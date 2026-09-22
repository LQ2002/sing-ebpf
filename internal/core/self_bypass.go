//go:build with_ebpf && (linux || android)

package core

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	selfBypassSocketCapacity        = 65536
	CompactSelfBypassSocketCapacity = 16384
)

// SelfBypass owns the socket-cookie map used by the local TC classifier. The
// map is populated by cgroup hooks when the process has an exclusive cgroup,
// or by the socket control callback when cgroup attachment is unavailable.
type SelfBypass struct {
	access   sync.RWMutex
	sockets  *CiliumEBPF.Map
	programs []*CiliumEBPF.Program
	links    []cgroupProgramLink
	mode     atomic.Uint32
}

type SelfBypassCgroupConfig struct {
	EnableTCP  bool
	EnableUDP  bool
	EnableIPv6 bool
}

type SelfBypassMode uint32

const (
	SelfBypassUserspace SelfBypassMode = iota
	SelfBypassCgroupSocket
	SelfBypassCgroupSocketAddr
	// SelfBypassUserspaceRelease keeps userspace socket registration while
	// using a cgroup sock_release hook for lifecycle cleanup. This is useful
	// when socket-create/connect hooks are unavailable, including TC-only
	// deployments where the cgroup data plane is not loaded.
	SelfBypassUserspaceRelease
)

func (m SelfBypassMode) String() string {
	switch m {
	case SelfBypassCgroupSocket:
		return "cgroup_socket_cookie"
	case SelfBypassCgroupSocketAddr:
		return "cgroup_socket_addr"
	case SelfBypassUserspaceRelease:
		return "userspace_socket_cookie_release"
	default:
		return "userspace_socket_cookie"
	}
}

// CleanupMode reports how entries in the self-bypass map are removed. The map
// is socket local storage, so the kernel frees every entry with its socket in
// all modes; a release hook, where one is attached, only brings that forward.
// There is no LRU and so no eviction of a live socket's entry.
func (m SelfBypassMode) CleanupMode() string {
	return "socket_storage"
}

func NewSelfBypass() (*SelfBypass, error) {
	return NewSelfBypassWithCapacity(selfBypassSocketCapacity)
}

// selfBypassStorageValue describes the map key and value to the kernel. Local
// storage maps are BTF-only: the kernel refuses to create one without type
// information, and the compiled objects have their .BTF section stripped by the
// build (see the generate target in Makefile), so the types are supplied here
// instead of being read back from the object.
func selfBypassStorageValue() btf.Type {
	return &btf.Int{Name: "__u32", Size: 4, Encoding: btf.Unsigned}
}

// requireSocketStorage reports whether this kernel can back the self-bypass map
// with socket local storage. Both halves are needed: the map type itself, and
// the lookup helper inside the TC classifier that reads it on every locally
// originated packet.
func requireSocketStorage() error {
	if err := features.HaveMapType(CiliumEBPF.SkStorage); err != nil {
		return E.Cause(err, "kernel does not provide BPF socket local storage")
	}
	if err := features.HaveProgramHelper(CiliumEBPF.SchedCLS, asm.FnSkStorageGet); err != nil {
		return E.Cause(err, "kernel does not allow bpf_sk_storage_get in TC classifiers")
	}
	return nil
}

// NewSelfBypassWithCapacity creates the map that marks sing-box's own sockets.
//
// The capacity argument is kept for callers but no longer bounds anything: the
// map is socket local storage, which has no entry limit because every entry is
// owned by one socket and freed with it. That ownership is the whole point of
// the type. The previous LRU hash was keyed by socket cookie and had nothing
// deleting from it on the userspace registration path, so entries accumulated
// until the LRU evicted them -- and an eviction could drop a cookie whose
// socket was still alive and carrying a long-lived connection, which then
// stopped being recognised as ours on its very next packet.
//
// Requires Linux 5.2 or newer. There is deliberately no fallback to the old
// cookie map: this fork targets kernels well past that, and carrying two
// on-wire layouts for the same map would mean two compiled object variants and
// a runtime branch through every path that touches it.
func NewSelfBypassWithCapacity(capacity uint32) (*SelfBypass, error) {
	if capacity == 0 || capacity > MaxConfigurableMapCapacity {
		return nil, E.New("invalid eBPF self-bypass socket map capacity: ", capacity)
	}
	if err := requireSocketStorage(); err != nil {
		return nil, err
	}
	_ = raiseMemlockLimit()
	sockets, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_self_sockets",
		Type:       CiliumEBPF.SkStorage,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 0,
		Flags:      bpfFlagNoPrealloc,
		Key:        selfBypassStorageValue(),
		Value:      selfBypassStorageValue(),
	})
	if err != nil {
		return nil, E.Cause(err, "create eBPF self-bypass socket map")
	}
	return &SelfBypass{sockets: sockets}, nil
}

// Map returns the map that must be shared with the local TC programs. The map
// is borrowed: callers must not close or retain it beyond SelfBypass.Close.
func (b *SelfBypass) Map() *CiliumEBPF.Map {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.sockets
}

// AttachCgroup enables automatic socket-cookie registration when the current
// cgroup is exclusive to this process. It first tries socket create/release
// hooks, then connect/sendmsg hooks for kernels that expose only the latter.
// When those hooks cannot be used, it still attempts a release-only hook so
// userspace registration does not leave entries behind on pure TC systems.
// A failure leaves the map usable by the userspace registration fallback.
func (b *SelfBypass) AttachCgroup(config SelfBypassCgroupConfig) error {
	if b == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.sockets == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	if b.mode.Load() != uint32(SelfBypassUserspace) {
		return nil
	}
	if lenOpenCgroupProgramLinks(b.links) > 0 {
		if err := b.closeHooks(); err != nil {
			return E.Cause(err, "finish previous eBPF self-bypass cleanup")
		}
	}
	cgroupPath, err := DetectProcessCgroup2Path()
	if err != nil {
		return E.Cause(err, "detect process cgroup v2")
	}
	exclusive, exclusiveErr := processCgroupExclusive(cgroupPath)
	var attachErrors []error
	if exclusiveErr != nil {
		attachErrors = append(attachErrors, exclusiveErr)
	}
	if exclusive {
		createReleaseErr := b.attachCgroupSocket(cgroupPath)
		if createReleaseErr == nil {
			b.mode.Store(uint32(SelfBypassCgroupSocket))
			return nil
		}
		attachErrors = append(attachErrors, createReleaseErr)
		if lenOpenCgroupProgramLinks(b.links) > 0 {
			return E.Errors(attachErrors...)
		}
		socketAddrErr := b.attachCgroupSocketAddr(cgroupPath, config)
		if socketAddrErr == nil {
			b.mode.Store(uint32(SelfBypassCgroupSocketAddr))
			return nil
		}
		attachErrors = append(attachErrors, socketAddrErr)
		if lenOpenCgroupProgramLinks(b.links) > 0 {
			return E.Errors(attachErrors...)
		}
	} else if exclusiveErr == nil {
		attachErrors = append(attachErrors, E.New("process cgroup contains other processes"))
	}

	// A release-only hook is safe on a shared cgroup: it only deletes the
	// releasing socket's own entry in our map, which sockets of other
	// processes never have, and never marks sockets.
	if releaseErr := b.attachCgroupRelease(cgroupPath); releaseErr == nil {
		b.mode.Store(uint32(SelfBypassUserspaceRelease))
		return nil
	} else {
		attachErrors = append(attachErrors, releaseErr)
	}
	return E.Errors(attachErrors...)
}

func (b *SelfBypass) CgroupAttached() bool {
	if b == nil {
		return false
	}
	mode := SelfBypassMode(b.mode.Load())
	return mode == SelfBypassCgroupSocket || mode == SelfBypassCgroupSocketAddr
}

func (b *SelfBypass) Mode() SelfBypassMode {
	if b == nil {
		return SelfBypassUserspace
	}
	return SelfBypassMode(b.mode.Load())
}

func (b *SelfBypass) attachCgroupSocket(path string) error {
	createProgram, err := newSelfBypassCreateProgram(b.sockets.FD())
	if err != nil {
		return err
	}
	releaseProgram, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		_ = createProgram.Close()
		return err
	}
	createLink, err := attachCgroupProgram(path, createProgram, CiliumEBPF.AttachCGroupInetSockCreate)
	if err != nil {
		_ = releaseProgram.Close()
		_ = createProgram.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-create hook")
	}
	releaseLink, err := attachCgroupProgram(path, releaseProgram, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		_ = releaseProgram.Close()
		b.programs = []*CiliumEBPF.Program{createProgram}
		b.links = []cgroupProgramLink{createLink}
		return E.Errors(
			E.Cause(err, "attach eBPF self-bypass socket-release hook"),
			b.closeHooks(),
		)
	}
	b.programs = []*CiliumEBPF.Program{createProgram, releaseProgram}
	b.links = []cgroupProgramLink{createLink, releaseLink}
	return nil
}

func (b *SelfBypass) attachCgroupRelease(path string) error {
	program, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		return err
	}
	programLink, err := attachCgroupProgram(path, program, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		_ = program.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-release cleanup hook")
	}
	b.programs = []*CiliumEBPF.Program{program}
	b.links = []cgroupProgramLink{programLink}
	return nil
}

func (b *SelfBypass) attachCgroupSocketAddr(path string, config SelfBypassCgroupConfig) error {
	hooks := selfBypassSocketAddrHooks(config)
	programs := make([]*CiliumEBPF.Program, 0, len(hooks))
	links := make([]cgroupProgramLink, 0, len(hooks))
	closeAttached := func() error {
		b.programs = programs
		b.links = links
		return b.closeHooks()
	}
	for _, hook := range hooks {
		program, err := newSelfBypassSocketAddrProgram(b.sockets.FD(), hook)
		if err != nil {
			return E.Errors(err, closeAttached())
		}
		programs = append(programs, program)
		programLink, err := attachCgroupProgram(path, program, hook.attachType)
		if err != nil {
			return E.Errors(E.Cause(err, "attach eBPF self-bypass ", hook.hookName, " hook"), closeAttached())
		}
		links = append(links, programLink)
	}
	b.programs = programs
	b.links = links
	return nil
}

type selfBypassSocketAddrHook struct {
	hookName          string
	kernelProgramName string
	attachType        CiliumEBPF.AttachType
}

func selfBypassSocketAddrHooks(config SelfBypassCgroupConfig) []selfBypassSocketAddrHook {
	hooks := make([]selfBypassSocketAddrHook, 0, 4)
	if config.EnableTCP {
		hooks = append(hooks, selfBypassSocketAddrHook{"connect4", kernelProgramNameSelfConnect4, CiliumEBPF.AttachCGroupInet4Connect})
		if config.EnableIPv6 {
			hooks = append(hooks, selfBypassSocketAddrHook{"connect6", kernelProgramNameSelfConnect6, CiliumEBPF.AttachCGroupInet6Connect})
		}
	}
	if config.EnableUDP {
		hooks = append(hooks, selfBypassSocketAddrHook{"sendmsg4", kernelProgramNameSelfSendmsg4, CiliumEBPF.AttachCGroupUDP4Sendmsg})
		if config.EnableIPv6 {
			hooks = append(hooks, selfBypassSocketAddrHook{"sendmsg6", kernelProgramNameSelfSendmsg6, CiliumEBPF.AttachCGroupUDP6Sendmsg})
		}
	}
	return hooks
}

func newSelfBypassCreateProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameSelfCreate,
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCGroupInetSockCreate,
		License:      "GPL",
		Instructions: selfBypassCreateInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-create hook")
	}
	return program, nil
}

func newSelfBypassReleaseProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameSelfRelease,
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCgroupInetSockRelease,
		License:      "GPL",
		Instructions: selfBypassReleaseInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-release hook")
	}
	return program, nil
}

func newSelfBypassSocketAddrProgram(mapFD int, hook selfBypassSocketAddrHook) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         hook.kernelProgramName,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   hook.attachType,
		License:      "GPL",
		Instructions: selfBypassSocketAddrInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass ", hook.hookName, " hook")
	}
	return program, nil
}

// bpfLocalStorageCreate is BPF_LOCAL_STORAGE_GET_F_CREATE: allocate the entry
// if this socket does not have one yet.
const bpfLocalStorageCreate = 1

// selfBypassCreateInstructions runs on cgroup/sock_create, where the context is
// the struct bpf_sock itself, so it can be handed to the helper directly.
func selfBypassCreateInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -4, SocketMetadataSelfBypass, asm.Word),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -4),
		asm.Mov.Imm(asm.R4, bpfLocalStorageCreate),
		asm.FnSkStorageGet.Call(),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
}

// selfBypassReleaseInstructions runs on cgroup/sock_release. Socket local
// storage is freed with the socket, so this only brings the release forward by
// the length of the teardown; it is kept because dropping the hook would change
// which attachment modes AttachCgroup can report (see attachCgroupSocket), and
// an explicit delete documents the lifetime at the place it ends.
//
// socketCookieDeleteInstructions is deliberately not reused here any more: it
// deletes by socket cookie, which is still right for the process-owner map in
// process_tracker.go but no longer matches this map's key.
func selfBypassReleaseInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.R6),
		asm.FnSkStorageDelete.Call(),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
}

func socketCookieDeleteInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

// sockAddrSocketOffset is offsetof(struct bpf_sock_addr, sk) from the kernel
// UAPI headers. It is part of the stable BPF context layout, not something the
// verifier will relocate, so it is written out rather than derived.
const sockAddrSocketOffset = 64

// selfBypassSocketAddrInstructions runs on the connect/sendmsg hooks, where the
// context is a struct bpf_sock_addr and the socket hangs off it. Creating the
// entry and setting the flag collapse into a single helper call: the value
// passed in is only used when the entry did not exist yet, so the read-modify
// -write that the cookie-keyed version needed is down to one OR on the pointer
// the helper returns.
func selfBypassSocketAddrInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, sockAddrSocketOffset, asm.DWord),
		asm.JEq.Imm(asm.R2, 0, "allow"),
		asm.StoreImm(asm.RFP, -4, SocketMetadataSelfBypass, asm.Word),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -4),
		asm.Mov.Imm(asm.R4, bpfLocalStorageCreate),
		asm.FnSkStorageGet.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.Or.Imm(asm.R1, SocketMetadataSelfBypass),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.Word),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

// RegisterSocket records a socket created by the consumer when cgroup hooks cannot
// be attached. It performs one map update per socket.
//
// The key is the socket file descriptor itself: that is how userspace addresses
// a socket local storage map. The SO_COOKIE read this used to need is gone with
// it, and so is the question of who deletes the entry -- the kernel frees it
// when the socket goes away.
func (b *SelfBypass) RegisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.sockets == nil {
		return nil
	}
	value := uint32(SocketMetadataSelfBypass)
	err := control.Raw(rawConn, func(fd uintptr) error {
		return b.sockets.Update(int32(fd), value, CiliumEBPF.UpdateAny)
	})
	if err != nil {
		return E.Cause(err, "register eBPF self-bypass socket")
	}
	return nil
}

// UnregisterSocket removes a socket previously registered by RegisterSocket.
// Call it before closing the socket when no kernel release hook is active.
//
// With socket local storage this is an optimisation, not a correctness
// requirement: the kernel frees the entry together with the socket either way.
// The map is addressed by the live socket's descriptor, so the delete cannot
// reach a different socket that later reuses the descriptor number. A socket
// that was never registered has no entry, which is not an error here.
func (b *SelfBypass) UnregisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.sockets == nil || b.CgroupAttached() {
		return nil
	}
	err := control.Raw(rawConn, func(fd uintptr) error {
		return b.sockets.Delete(int32(fd))
	})
	if err != nil && !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return E.Cause(err, "unregister eBPF self-bypass socket")
	}
	return nil
}

func processCgroupExclusive(path string) (bool, error) {
	pid := os.Getpid()
	found, exclusive, err := readExclusiveCgroupMembers(path, pid)
	if err != nil || !exclusive || !found {
		return found && exclusive, err
	}
	return inspectExclusiveCgroupDescendants(path)
}

func readExclusiveCgroupMembers(path string, pid int) (found bool, exclusive bool, err error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, false, E.Cause(err, "read process cgroup members")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		member, parseErr := strconv.Atoi(line)
		if parseErr != nil {
			return false, false, E.Cause(parseErr, "parse process cgroup member")
		}
		if member != pid {
			return found, false, nil
		}
		found = true
	}
	if err = scanner.Err(); err != nil {
		return false, false, E.Cause(err, "read process cgroup members")
	}
	return found, true, nil
}

func inspectExclusiveCgroupDescendants(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, E.Cause(err, "read process cgroup children")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		childPath := filepath.Join(path, entry.Name())
		populated, childErr := cgroupHasMembers(childPath)
		if childErr != nil {
			return false, childErr
		}
		if populated {
			return false, nil
		}
		childExclusive, childErr := inspectExclusiveCgroupDescendants(childPath)
		if childErr != nil || !childExclusive {
			return false, childErr
		}
	}
	return true, nil
}

func cgroupHasMembers(path string) (bool, error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, E.Cause(err, "read child cgroup members")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() != "" {
			return true, nil
		}
	}
	if err = scanner.Err(); err != nil {
		return false, E.Cause(err, "read child cgroup members")
	}
	return false, nil
}

func (b *SelfBypass) closeHooks() error {
	if b == nil {
		return nil
	}
	var closeErr error
	linksClosed := true
	for index := len(b.links) - 1; index >= 0; index-- {
		if b.links[index] != nil {
			linkErr := b.links[index].Close()
			closeErr = E.Errors(closeErr, linkErr)
			if cgroupProgramLinkCloseComplete(b.links[index], linkErr) {
				b.links[index] = nil
			} else {
				linksClosed = false
			}
		}
	}
	if !linksClosed {
		return closeErr
	}
	for index := len(b.programs) - 1; index >= 0; index-- {
		if b.programs[index] != nil {
			closeErr = E.Errors(closeErr, b.programs[index].Close())
			b.programs[index] = nil
		}
	}
	b.links = nil
	b.programs = nil
	b.mode.Store(uint32(SelfBypassUserspace))
	return closeErr
}

func (b *SelfBypass) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	closeErr := b.closeHooks()
	if lenOpenCgroupProgramLinks(b.links) > 0 {
		return closeErr
	}
	if b.sockets != nil {
		closeErr = E.Errors(closeErr, b.sockets.Close())
		b.sockets = nil
	}
	return closeErr
}

func (b *SelfBypass) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.sockets == nil && lenOpenCgroupProgramLinks(b.links) == 0
}
