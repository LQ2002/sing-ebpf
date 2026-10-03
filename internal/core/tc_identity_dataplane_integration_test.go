//go:build with_ebpf && linux && ebpf_integration

package core

// Real data-plane checks for UpdateUIDPolicy and the socket identity fields in
// tc_assignment. Unlike the BPF_PROG_TEST_RUN tests, packets here come from
// real sockets, so skb->sk is set and the verdict cache, bpf_get_socket_uid and
// bpf_skb_cgroup_id all run for real.
//
// Topology, built in private network namespaces:
//
//	[test ns] sbva 10.211.0.1 --veth-- sbvb 10.211.0.2 [peer ns, TCP echo :7000]
//	          sbdl (dummy): the delivery interface the local egress program
//	                        redirects selected packets to, where they are dropped
//
// The local egress program is attached to sbva egress. A selected flow
// therefore never reaches the peer; a bypassed one does. Socket UIDs are set
// with fchown on the socket, which is how sk_uid changes in the kernel
// (sockfs_setattr in net/socket.c) and how Android's netd hands DNS sockets to
// apps, so no extra processes or users are needed.
//
// Run (root, from internal/core):
//
//	go test -c -tags "with_ebpf ebpf_integration" -o core.test .
//	SING_EBPF_INTEGRATION=1 ./core.test -test.run 'TCUIDPolicy|TCSocketIdentity' -test.v

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type identityFixture struct {
	backend  *TCBackend
	delivery netlink.Link
	peer     netip.Addr
}

func newIdentityFixture(t *testing.T, recordIdentity bool, includeUIDs ...uint32) *identityFixture {
	t.Helper()
	return newIdentityFixtureWithCreator(t, recordIdentity, nil, includeUIDs...)
}

func newIdentityFixtureWithCreator(t *testing.T, recordIdentity bool, creatorMap *CiliumEBPF.Map, includeUIDs ...uint32) *identityFixture {
	t.Helper()
	requireEBPFIntegration(t, "run the TC local egress program on real sockets")
	local, delivery := buildTestTopology(t)

	var decisions []UIDDecision
	for _, uid := range includeUIDs {
		decisions = append(decisions, UIDDecision{Start: uid, End: uid, Action: DecisionIntercept})
	}
	policy, err := CompileActionPolicy(ActionPolicy{
		EnableTCP: true,
		EnableUDP: true,
		Local:     ActionScope{Default: DecisionPass, UID: decisions},
		Shared:    ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort:         65531,
		EnableLocal:          true,
		EnableIPv4:           true,
		EnableTCP:            true,
		EnableUDP:            true,
		Policy:               policy,
		RecordSocketIdentity: recordIdentity,
		SocketCreatorMap:     creatorMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	var mac MACAddress
	copy(mac[:], delivery.Attrs().HardwareAddr)
	if err = backend.SetDeliveryInterface(uint32(delivery.Attrs().Index), mac); err != nil {
		t.Fatal(err)
	}
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	attachLocalEgress(t, backend, local)
	return &identityFixture{backend: backend, delivery: delivery, peer: netip.MustParseAddr(identityPeerAddress)}
}

func (f *identityFixture) redirectedPackets(t *testing.T) uint64 {
	t.Helper()
	delivery, err := netlink.LinkByIndex(f.delivery.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	return delivery.Attrs().Statistics.TxPackets
}

// cgroupID returns the cgroup v2 id of a cgroup directory. On cgroup2 the id
// is the kernfs node id, which 64-bit kernels expose unchanged as the inode
// number (kernfs_ino in include/linux/kernfs.h); bpf_skb_cgroup_id returns
// the same value via cgroup_id().
func cgroupID(t *testing.T, path string) uint64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	return stat.Ino
}

func ownCgroupPath(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if relative, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", relative)
		}
	}
	t.Fatal("no cgroup v2 entry in /proc/self/cgroup")
	return ""
}

func (f *identityFixture) assignment(t *testing.T, protocol uint8, fd int, peerPort uint16) TCAssignment {
	t.Helper()
	assignment, err := f.backend.LookupAssignment(protocol, localAddrPort(t, fd), netip.AddrPortFrom(f.peer, peerPort), 0, false)
	if err != nil {
		t.Fatalf("lookup assignment: %v", err)
	}
	return assignment
}

func waitForRedirects(t *testing.T, f *identityFixture, baseline uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for f.redirectedPackets(t) == baseline {
		if time.Now().After(deadline) {
			dumpNetworkState(t)
			stats, statsErr := f.backend.Stats()
			entries := 0
			var key tcAssignKey
			var value TCAssignment
			iterator := f.backend.runtime.maps["tc_assignment"].Iterate()
			for iterator.Next(&key, &value) {
				entries++
				t.Logf("assignment %+v -> %+v", key, value)
			}
			t.Logf("baseline=%d stats=%+v (%v) assignments=%d control=%+v", baseline, stats, statsErr, entries, readTCControl(t, f.backend))
			t.Fatal("no packet reached the delivery interface")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTCUIDPolicyRefreshesCachedTCPVerdict: a TCP socket's verdict is cached
// on its first packet. After UpdateUIDPolicy the next packet of the same
// socket must be classified again -- otherwise the SYN retransmit would keep
// going to the delivery interface and the connection would never complete.
func TestTCUIDPolicyRefreshesCachedTCPVerdict(t *testing.T) {
	f := newIdentityFixture(t, true, uidIncluded)
	baseline := f.redirectedPackets(t)
	fd := startConnect(t, uidIncluded)
	if connectedWithin(t, fd, 300*time.Millisecond) {
		t.Fatal("an included UID connected directly")
	}
	waitForRedirects(t, f, baseline)

	changed, err := f.backend.UpdateUIDPolicy(nil, DecisionPass)
	if err != nil || !changed {
		t.Fatalf("UpdateUIDPolicy = %v, %v", changed, err)
	}
	// The SYN is retransmitted after the initial RTO of one second.
	if !connectedWithin(t, fd, 4*time.Second) {
		t.Fatal("the socket kept its cached verdict after the policy update")
	}
	if !echoWithin(t, fd, []byte("after update"), time.Second) {
		t.Fatal("no echo on the bypassed connection")
	}
}

// TestTCUIDPolicyLeavesUnaffectedConnections: an update that does not change
// a connection's UID decision does not disturb it, and one that does takes
// effect on that established connection's next packet; reverting lets the
// retransmissions through, so the connection was never torn down.
func TestTCUIDPolicyLeavesUnaffectedConnections(t *testing.T) {
	f := newIdentityFixture(t, true, uidIncluded)
	fd := startConnect(t, uidOther)
	if !connectedWithin(t, fd, 2*time.Second) {
		t.Fatal("a UID outside the include set did not connect directly")
	}
	if !echoWithin(t, fd, []byte("before"), time.Second) {
		t.Fatal("no echo before the update")
	}
	if changed, err := f.backend.UpdateUIDPolicy([]UIDDecision{
		{Start: uidIncluded, End: uidIncluded, Action: DecisionIntercept},
		{Start: 9070, End: 9070, Action: DecisionIntercept},
	}, DecisionPass); err != nil || !changed {
		t.Fatalf("UpdateUIDPolicy = %v, %v", changed, err)
	}
	if !echoWithin(t, fd, []byte("unaffected"), time.Second) {
		t.Fatal("an update that does not concern this UID disturbed the connection")
	}

	baseline := f.redirectedPackets(t)
	if _, err := f.backend.UpdateUIDPolicy([]UIDDecision{{Start: uidOther, End: uidOther, Action: DecisionIntercept}}, DecisionPass); err != nil {
		t.Fatal(err)
	}
	if echoWithin(t, fd, []byte("now intercepted"), 500*time.Millisecond) {
		t.Fatal("the established connection kept its old verdict after its UID was included")
	}
	waitForRedirects(t, f, baseline)
	if _, err := f.backend.UpdateUIDPolicy(nil, DecisionPass); err != nil {
		t.Fatal(err)
	}
	// The unacknowledged payload is retransmitted and now gets through.
	received := make([]byte, 0, 64)
	buffer := make([]byte, 64)
	deadline := time.Now().Add(5 * time.Second)
	for !bytes.Contains(received, []byte("now intercepted")) && time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, _ := unix.Poll(fds, 100); n <= 0 {
			continue
		}
		if n, err := unix.Read(fd, buffer); err == nil && n > 0 {
			received = append(received, buffer[:n]...)
		}
	}
	if !bytes.Contains(received, []byte("now intercepted")) {
		t.Fatalf("the connection did not recover after reverting the policy: %q", received)
	}
}

// TestTCUIDPolicyDefaultActionAndEmptySet covers the default action and the
// "include configured, nothing installed" case.
func TestTCUIDPolicyDefaultActionAndEmptySet(t *testing.T) {
	f := newIdentityFixture(t, true, uidIncluded)

	// Empty include set: policy on, every UID bypassed (not intercepted).
	if _, err := f.backend.UpdateUIDPolicy(nil, DecisionPass); err != nil {
		t.Fatal(err)
	}
	if f.backend.control.Flags&tcFlagUIDPolicy == 0 || f.backend.control.Flags&tcFlagUIDDefaultBypass == 0 {
		t.Fatalf("empty include set turned the UID policy off: flags %#x", f.backend.control.Flags)
	}
	for _, uid := range []uint32{uidIncluded, uidOther, 0} {
		if !connectedWithin(t, startConnect(t, uid), 2*time.Second) {
			t.Fatalf("UID %d was intercepted under an empty include set", uid)
		}
	}

	// Exclude mode: default intercept, one UID passes.
	if changed, err := f.backend.UpdateUIDPolicy([]UIDDecision{{Start: uidOther, End: uidOther, Action: DecisionPass}}, DecisionIntercept); err != nil || !changed {
		t.Fatalf("UpdateUIDPolicy = %v, %v", changed, err)
	}
	if !connectedWithin(t, startConnect(t, uidOther), 2*time.Second) {
		t.Fatal("the excluded UID was intercepted")
	}
	baseline := f.redirectedPackets(t)
	if connectedWithin(t, startConnect(t, uidIncluded), 300*time.Millisecond) {
		t.Fatal("a UID outside the exclusions bypassed under default intercept")
	}
	waitForRedirects(t, f, baseline)

	// Exclude mode with nothing excluded: the policy switches off entirely,
	// which is the same as intercepting everyone.
	if _, err := f.backend.UpdateUIDPolicy(nil, DecisionIntercept); err != nil {
		t.Fatal(err)
	}
	if f.backend.control.Flags&(tcFlagUIDPolicy|tcFlagUIDDefaultBypass) != 0 {
		t.Fatalf("flags %#x, want the UID policy off", f.backend.control.Flags)
	}
	if connectedWithin(t, startConnect(t, uidOther), 300*time.Millisecond) {
		t.Fatal("a UID bypassed with no UID policy")
	}

	// An identical update writes nothing.
	generation := f.backend.control.PolicyGeneration
	if changed, err := f.backend.UpdateUIDPolicy(nil, DecisionIntercept); err != nil || changed {
		t.Fatalf("identical update = %v, %v", changed, err)
	}
	if f.backend.control.PolicyGeneration != generation {
		t.Fatal("an identical update wrote the control")
	}
}

// TestTCSocketIdentityFields checks the new tc_assignment fields against the
// truth the test controls: the cookie from SO_COOKIE, the UID from fchown and
// the cgroup the socket was created in.
func TestTCSocketIdentityFields(t *testing.T) {
	f := newIdentityFixture(t, true, uidIncluded, uidIncluded+1)

	// TCP: identity of the connecting socket.
	baseline := f.redirectedPackets(t)
	tcp := startConnect(t, uidIncluded)
	waitForRedirects(t, f, baseline)
	assignment := f.assignment(t, ProtocolTCP, tcp, identityPeerTCPPort)
	if assignment.SocketCookie != socketCookie(t, tcp) || assignment.SocketUID != uidIncluded || !assignment.HasSocketIdentity() {
		t.Fatalf("TCP assignment %+v, want cookie %d uid %d", assignment, socketCookie(t, tcp), uidIncluded)
	}
	ownCgroup := cgroupID(t, ownCgroupPath(t))
	if assignment.SocketCgroupID != ownCgroup {
		t.Fatalf("TCP cgroup id %d, want %d", assignment.SocketCgroupID, ownCgroup)
	}

	// UDP created in another cgroup: the field is the creation cgroup, and it
	// stays that after the process has moved back.
	original := ownCgroupPath(t)
	scratch := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("sbtest-%d", os.Getpid()))
	if err := os.Mkdir(scratch, 0o755); err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(scratch) })
	writePID := func(path string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			t.Fatalf("move to %s: %v", path, err)
		}
	}
	writePID(scratch)
	udp, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	writePID(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(udp) })
	if err = unix.Fchown(udp, uidIncluded, -1); err != nil {
		t.Fatal(err)
	}
	// Bound to the address explicitly: an unbound, unconnected UDP socket
	// reports 0.0.0.0 from getsockname, not the source the packet carries.
	// It stays unconnected, the way a QUIC or DNS client socket often is.
	if err = unix.Bind(udp, &unix.SockaddrInet4{Addr: [4]byte{10, 211, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	peerUDP := &unix.SockaddrInet4{Port: identityPeerUDPPort, Addr: [4]byte{10, 211, 0, 2}}
	if err = unix.Sendto(udp, []byte("x"), 0, peerUDP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	assignment = f.assignment(t, ProtocolUDP, udp, identityPeerUDPPort)
	if want := cgroupID(t, scratch); assignment.SocketCgroupID != want || want == ownCgroup {
		t.Fatalf("UDP cgroup id %d, want the creation cgroup %d (process cgroup %d)", assignment.SocketCgroupID, want, ownCgroup)
	}
	if assignment.SocketUID != uidIncluded || assignment.SocketCookie != socketCookie(t, udp) {
		t.Fatalf("UDP assignment %+v", assignment)
	}

	// Same socket, UID changed with fchown: the next packet refreshes the UID
	// although the cookie is unchanged.
	if err = unix.Fchown(udp, uidIncluded+1, -1); err != nil {
		t.Fatal(err)
	}
	if err = unix.Sendto(udp, []byte("y"), 0, peerUDP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	assignment = f.assignment(t, ProtocolUDP, udp, identityPeerUDPPort)
	if assignment.SocketUID != uidIncluded+1 || assignment.SocketCgroupID != cgroupID(t, scratch) {
		t.Fatalf("after fchown: %+v, want uid %d", assignment, uidIncluded+1)
	}

	// The same five-tuple reused by a new socket: cookie and identity follow
	// the new socket.
	source := localAddrPort(t, udp)
	_ = unix.Close(udp)
	reused := ownedSocket(t, unix.SOCK_DGRAM, uidIncluded)
	_ = unix.SetsockoptInt(reused, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err = unix.Bind(reused, &unix.SockaddrInet4{Port: int(source.Port()), Addr: source.Addr().As4()}); err != nil {
		t.Fatal(err)
	}
	if err = unix.Sendto(reused, []byte("z"), 0, peerUDP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	assignment = f.assignment(t, ProtocolUDP, reused, identityPeerUDPPort)
	if assignment.SocketCookie != socketCookie(t, reused) || assignment.SocketUID != uidIncluded || assignment.SocketCgroupID != ownCgroup {
		t.Fatalf("reused tuple: %+v, want the new socket's cookie %d", assignment, socketCookie(t, reused))
	}
}

// TestTCSocketIdentityNotRecordedWithoutRequest: the light variant writes no
// assignment at all, so it calls none of the identity helpers.
func TestTCSocketIdentityNotRecordedWithoutRequest(t *testing.T) {
	f := newIdentityFixture(t, false, uidIncluded)
	baseline := f.redirectedPackets(t)
	tcp := startConnect(t, uidIncluded)
	waitForRedirects(t, f, baseline)
	if _, err := f.backend.LookupAssignment(ProtocolTCP, localAddrPort(t, tcp), netip.AddrPortFrom(f.peer, identityPeerTCPPort), 0, false); err == nil {
		t.Fatal("the light local egress variant recorded an assignment")
	}
}

func readTCControl(t *testing.T, backend *TCBackend) tcControl {
	t.Helper()
	var control tcControl
	key := uint32(0)
	if err := lookupMap(backend.controlMapFD, unsafe.Pointer(&key), unsafe.Pointer(&control)); err != nil {
		t.Fatal(err)
	}
	return control
}

func uidMapKeys(t *testing.T, backend *TCBackend) []uidLPMKey {
	t.Helper()
	var keys []uidLPMKey
	var key uidLPMKey
	var value uint8
	iterator := backend.runtime.maps["tc_uid_policy"].Iterate()
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iterator.Err(); err != nil {
		t.Fatal(err)
	}
	return keys
}

func newUIDPolicyBackend(t *testing.T) *TCBackend {
	t.Helper()
	requireEBPFIntegration(t, "update a real TC UID policy map")
	policy, err := CompileActionPolicy(ActionPolicy{
		EnableTCP: true,
		Local:     ActionScope{Default: DecisionPass, UID: []UIDDecision{{Start: 10001, End: 10001, Action: DecisionIntercept}}},
		Shared:    ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{ListenerPort: 65531, EnableLocal: true, EnableIPv4: true, EnableTCP: true, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// TestTCUIDPolicyFailureRecovery injects control-write failures into a real
// backend. A failure whose rollback succeeds leaves the previous policy in the
// map and in the kernel's control, with the generation advanced past the
// failed attempt; a failure that cannot be cleaned up marks the backend as
// requiring a rebuild.
func TestTCUIDPolicyFailureRecovery(t *testing.T) {
	backend := newUIDPolicyBackend(t)
	before := uidMapKeys(t, backend)
	generation := readTCControl(t, backend).PolicyGeneration

	writes := 0
	backend.controlWriteFault = func() error {
		writes++
		if writes == 1 {
			return unix.EIO
		}
		return nil
	}
	_, err := backend.UpdateUIDPolicy([]UIDDecision{{Start: 10050, End: 10060, Action: DecisionIntercept}}, DecisionPass)
	if err == nil || backend.RequiresRebuild() {
		t.Fatalf("err = %v, rebuild = %v; want a recovered failure", err, backend.RequiresRebuild())
	}
	if !sameKeys(uidMapKeys(t, backend), before) || !sameKeys(backend.uidEntries, before) {
		t.Fatalf("map %v / state %v after a failed update, want %v", uidMapKeys(t, backend), backend.uidEntries, before)
	}
	control := readTCControl(t, backend)
	if control.PolicyGeneration == generation {
		t.Fatal("the rollback did not advance the generation, so verdicts cached mid-update survive")
	}
	if control.Flags != backend.control.Flags {
		t.Fatalf("kernel flags %#x, backend flags %#x", control.Flags, backend.control.Flags)
	}

	// The backend is still usable.
	backend.controlWriteFault = nil
	if changed, err := backend.UpdateUIDPolicy([]UIDDecision{{Start: 10050, End: 10060, Action: DecisionIntercept}}, DecisionPass); err != nil || !changed {
		t.Fatalf("update after recovery = %v, %v", changed, err)
	}

	// Every control write fails: the rollback cannot invalidate the cache.
	backend.controlWriteFault = func() error { return unix.EIO }
	if _, err = backend.UpdateUIDPolicy(nil, DecisionPass); err == nil {
		t.Fatal("update succeeded with a failing control write")
	}
	if !backend.RequiresRebuild() {
		t.Fatal("a failure that could not invalidate cached verdicts left the backend usable")
	}
}

// TestTCUIDPolicyCapacity runs the capacity rules against the real trie.
func TestTCUIDPolicyCapacity(t *testing.T) {
	backend := newUIDPolicyBackend(t)
	// Old: a /32 every four UIDs. New: a /31 at each of the same places. Every
	// old block is reshaped and the blocks stay apart, so both policies are at
	// the capacity and adding first would need twice the room.
	var evens, pairs []UIDDecision
	for index := uint32(0); index < tcUIDPolicyCapacity; index++ {
		evens = append(evens, UIDDecision{Start: 20000 + 4*index, End: 20000 + 4*index, Action: DecisionIntercept})
		pairs = append(pairs, UIDDecision{Start: 20000 + 4*index, End: 20001 + 4*index, Action: DecisionIntercept})
	}
	if _, err := backend.UpdateUIDPolicy(evens, DecisionPass); err != nil {
		t.Fatalf("a policy at the capacity: %v", err)
	}
	if n := len(uidMapKeys(t, backend)); n != tcUIDPolicyCapacity {
		t.Fatalf("map holds %d entries, want %d", n, tcUIDPolicyCapacity)
	}
	if _, err := backend.UpdateUIDPolicy(pairs, DecisionPass); err != nil {
		t.Fatalf("a reshaping update at full capacity: %v", err)
	}
	if n := len(uidMapKeys(t, backend)); n != tcUIDPolicyCapacity {
		t.Fatalf("map holds %d entries after reshaping, want %d", n, tcUIDPolicyCapacity)
	}
	over := append(evens, UIDDecision{Start: 20000 + 4*tcUIDPolicyCapacity, End: 20000 + 4*tcUIDPolicyCapacity, Action: DecisionIntercept})
	keys := uidMapKeys(t, backend)
	if _, err := backend.UpdateUIDPolicy(over, DecisionPass); err == nil {
		t.Fatal("a policy over the capacity was accepted")
	}
	if !sameKeys(uidMapKeys(t, backend), keys) {
		t.Fatal("a refused policy changed the map")
	}
}

// attachDelivery replaces the dummy delivery target with the real delivery
// arrangement the runtime package builds (runtime/tc_delivery.go and
// runtime/tc_routing.go): a veth pair whose far end runs the delivery ingress
// program, rp_filter off and accept_local on there, a fwmark rule into a table
// that routes everything locally, and a transparent listener registered in the
// listener sockmap. It returns the listener.
func attachDelivery(t *testing.T, f *identityFixture) int {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sbdr"}, PeerName: "sbdi"}); err != nil {
		t.Fatalf("create delivery veth: %v", err)
	}
	redirect, err := netlink.LinkByName("sbdr")
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := netlink.LinkByName("sbdi")
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []netlink.Link{redirect, delivery} {
		if err = netlink.LinkSetUp(device); err != nil {
			t.Fatal(err)
		}
	}
	// /proc/sys/net resolves against the writing thread's namespace, which is
	// the locked test thread's private one.
	for path, value := range map[string]string{
		"/proc/sys/net/ipv4/conf/all/rp_filter":     "0",
		"/proc/sys/net/ipv4/conf/sbdi/rp_filter":    "0",
		"/proc/sys/net/ipv4/conf/sbdi/accept_local": "1",
	} {
		if err = os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatalf("sysctl %s: %v", path, err)
		}
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	const table = 211
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_, destination, _ := net.ParseCIDR(prefix)
		route := netlink.Route{
			LinkIndex: loopback.Attrs().Index, Dst: destination, Table: table,
			Type: unix.RTN_LOCAL, Scope: netlink.Scope(unix.RT_SCOPE_HOST),
		}
		if err = netlink.RouteAdd(&route); err != nil {
			t.Fatalf("local route: %v", err)
		}
	}
	rule := netlink.NewRule()
	rule.Priority, rule.Family, rule.Table = 100, unix.AF_INET, table
	rule.Mark, rule.MarkSet, rule.Mask = DefaultTCRoutingMark, true, int(DefaultTCRoutingMark)
	if err = netlink.RuleAdd(rule); err != nil {
		t.Fatalf("policy rule: %v", err)
	}
	attachment, err := link.AttachTCX(link.TCXOptions{
		Interface: delivery.Attrs().Index,
		Program:   f.backend.runtime.programs[tcProgramDeliveryIngress],
		Attach:    CiliumEBPF.AttachTCXIngress,
	})
	if err != nil {
		t.Fatalf("attach delivery ingress: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	var mac MACAddress
	copy(mac[:], delivery.Attrs().HardwareAddr)
	if err = f.backend.SetDeliveryInterface(uint32(redirect.Attrs().Index), mac); err != nil {
		t.Fatal(err)
	}
	f.delivery = redirect

	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(listener) })
	for _, option := range []struct{ level, name int }{{unix.SOL_IP, unix.IP_TRANSPARENT}, {unix.SOL_SOCKET, unix.SO_REUSEADDR}} {
		if err = unix.SetsockoptInt(listener, option.level, option.name, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.Bind(listener, &unix.SockaddrInet4{Port: 65531}); err != nil {
		t.Fatal(err)
	}
	if err = unix.Listen(listener, 16); err != nil {
		t.Fatal(err)
	}
	if err = f.backend.RegisterTCPListener(false, listener); err != nil {
		t.Fatal(err)
	}
	return listener
}

// TestTCSocketIdentitySurvivesDelivery: the local path records the identity,
// then the redirected packet passes the delivery ingress program, which
// rewrites the same assignment with path=delivery. The identity, and the
// cookie, must come through that rewrite unchanged.
func TestTCSocketIdentitySurvivesDelivery(t *testing.T) {
	f := newIdentityFixture(t, true, uidIncluded)
	listener := attachDelivery(t, f)
	client := startConnect(t, uidIncluded)
	if !connectedWithin(t, client, 2*time.Second) {
		t.Fatal("the redirected connection did not reach the transparent listener")
	}
	accepted, name, err := unix.Accept(listener)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer unix.Close(accepted)
	if source := name.(*unix.SockaddrInet4); netip.AddrFrom4(source.Addr) != netip.MustParseAddr(identityLocalAddress) {
		t.Fatalf("accepted a connection from %v", source.Addr)
	}
	assignment := f.assignment(t, ProtocolTCP, client, identityPeerTCPPort)
	if assignment.Path != TCPathDelivery {
		t.Fatalf("assignment %+v did not pass the delivery program", assignment)
	}
	if assignment.SocketCookie != socketCookie(t, client) || assignment.SocketUID != uidIncluded ||
		assignment.SocketCgroupID != cgroupID(t, ownCgroupPath(t)) || !assignment.HasSocketIdentity() {
		t.Fatalf("delivery lost the socket identity: %+v", assignment)
	}
}
