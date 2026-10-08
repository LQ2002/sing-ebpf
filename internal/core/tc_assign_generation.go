//go:build with_ebpf && (linux || android)

package core

import (
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// tc_assign_generation (native/tc.bpf.c) counts writes to tc_assignment: the
// TC programs add one after every write, before the packet that caused the
// write reaches the listener socket. With BPF_F_MMAPABLE the counter is read
// through a shared read-only mapping, so a consumer can check per packet
// whether any assignment may have changed since it last looked one up, without
// a bpf(2) call.
//
// A kernel that cannot create or map the array (BPF_F_MMAPABLE needs Linux
// 5.5) still gets the counter map, created without the flag so the programs
// load unchanged; AssignmentGeneration then reports false and consumers keep
// looking assignments up per packet.

const bpfFlagMmapable = 1 << 10

var assignGenerationMmapable = sync.OnceValue(func() bool {
	probe, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_probe_mmap",
		Type:       CiliumEBPF.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
		Flags:      bpfFlagMmapable,
	})
	if err != nil {
		return false
	}
	defer probe.Close()
	memory, err := mapAssignGenerationFD(probe.FD())
	if err != nil {
		return false
	}
	_ = unix.Munmap(memory)
	return true
})

func assignGenerationOverride(mmapable bool) mapSpecOverride {
	override := mapSpecOverride{name: "sb_tc_assigngen", mapType: CiliumEBPF.Array, maxEntries: 1}
	if mmapable {
		override.flags = bpfFlagMmapable
	}
	return override
}

func mapAssignGenerationFD(fd int) ([]byte, error) {
	return unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
}

// mapAssignGeneration maps the counter of a freshly loaded TC backend. A nil
// result disables the fast path; it is never an error for the backend.
func mapAssignGeneration(generationMap *CiliumEBPF.Map, mmapable bool) []byte {
	if !mmapable || generationMap == nil {
		return nil
	}
	memory, err := mapAssignGenerationFD(generationMap.FD())
	if err != nil || len(memory) < 8 {
		if err == nil {
			_ = unix.Munmap(memory)
		}
		return nil
	}
	return memory
}

func unmapAssignGeneration(memory []byte) {
	if memory != nil {
		_ = unix.Munmap(memory)
	}
}

// AssignmentGeneration returns the number of tc_assignment writes so far,
// read from shared memory without a system call. It reports false when the
// counter could not be mapped or the backend is closed.
//
// A consumer that reads the generation, then looks an assignment up, may
// reuse that result for as long as the generation it read is still current:
// a write afterwards, including one for a socket that reused the same flow
// key, moves the generation before its packet can be received.
func (b *TCBackend) AssignmentGeneration() (uint64, bool) {
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.assignGeneration == nil {
		return 0, false
	}
	return atomic.LoadUint64((*uint64)(unsafe.Pointer(&b.assignGeneration[0]))), true
}
