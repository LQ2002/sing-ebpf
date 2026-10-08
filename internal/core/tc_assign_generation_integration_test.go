//go:build with_ebpf && linux && ebpf_integration

package core

// Checks for tc_assign_generation (tc_assign_generation.go), on the identity
// data-plane fixture in tc_identity_dataplane_integration_test.go: real
// sockets, local egress program on sbva.
//
// Run (root, from internal/core):
//
//	go test -c -tags "with_ebpf ebpf_integration" -o core.test .
//	SING_EBPF_INTEGRATION=1 ./core.test -test.run 'AssignmentGeneration' -test.v

import (
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestAssignmentGenerationReadsMapping: the value read through the mapping is
// the map's element 0, including writes made after the mapping was set up.
func TestAssignmentGenerationReadsMapping(t *testing.T) {
	if !assignGenerationMmapable() {
		t.Skip("kernel cannot create or map a BPF_F_MMAPABLE array")
	}
	generationMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type: CiliumEBPF.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: bpfFlagMmapable,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = generationMap.Close() })
	backend := &TCBackend{runtime: &tcRuntime{}}
	backend.assignGeneration = mapAssignGeneration(generationMap, true)
	if backend.assignGeneration == nil {
		t.Fatal("mapping failed")
	}
	t.Cleanup(func() { unmapAssignGeneration(backend.assignGeneration) })
	for _, value := range []uint64{0, 1, 0x1_0000_0001} {
		if err = generationMap.Update(uint32(0), value, CiliumEBPF.UpdateAny); err != nil {
			t.Fatal(err)
		}
		got, ok := backend.AssignmentGeneration()
		if !ok || got != value {
			t.Fatalf("generation %d (%v), want %d", got, ok, value)
		}
	}
	backend.runtime = nil
	if _, ok := backend.AssignmentGeneration(); ok {
		t.Fatal("closed backend reported a generation")
	}
}

// TestAssignmentGenerationTracksWrites: the generation moves on every case in
// which a UDP flow's assignment changes (new flow, fchown, a new socket on the
// same five-tuple) and stays put for further packets of an unchanged socket.
// The second half is what makes caching worthwhile; the first is what makes it
// correct.
func TestAssignmentGenerationTracksWrites(t *testing.T) {
	f := newIdentityFixture(t, true, uidIncluded, uidIncluded+1)
	generation := func() uint64 {
		t.Helper()
		value, ok := f.backend.AssignmentGeneration()
		if !ok {
			t.Skip("kernel cannot map tc_assign_generation")
		}
		return value
	}
	peerUDP := &unix.SockaddrInet4{Port: identityPeerUDPPort, Addr: [4]byte{10, 211, 0, 2}}
	send := func(fd int, payload string) {
		t.Helper()
		if err := unix.Sendto(fd, []byte(payload), 0, peerUDP); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	start := generation()
	udp := ownedSocket(t, unix.SOCK_DGRAM, uidIncluded)
	if err := unix.Bind(udp, &unix.SockaddrInet4{Addr: [4]byte{10, 211, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	send(udp, "a")
	afterNew := generation()
	if afterNew == start {
		t.Fatal("new UDP flow did not move the generation")
	}
	if assignment := f.assignment(t, ProtocolUDP, udp, identityPeerUDPPort); assignment.SocketCookie != socketCookie(t, udp) {
		t.Fatalf("new flow assignment %+v", assignment)
	}

	for _, payload := range []string{"b", "c", "d"} {
		send(udp, payload)
	}
	if steady := generation(); steady != afterNew {
		t.Fatalf("unchanged socket moved the generation %d -> %d", afterNew, steady)
	}

	if err := unix.Fchown(udp, uidIncluded+1, -1); err != nil {
		t.Fatal(err)
	}
	send(udp, "e")
	afterChown := generation()
	if afterChown == afterNew {
		t.Fatal("fchown did not move the generation")
	}

	source := localAddrPort(t, udp)
	_ = unix.Close(udp)
	reused := ownedSocket(t, unix.SOCK_DGRAM, uidIncluded)
	_ = unix.SetsockoptInt(reused, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.Bind(reused, &unix.SockaddrInet4{Port: int(source.Port()), Addr: source.Addr().As4()}); err != nil {
		t.Fatal(err)
	}
	send(reused, "f")
	if generation() == afterChown {
		t.Fatal("a new socket on the same five-tuple did not move the generation")
	}
	if assignment := f.assignment(t, ProtocolUDP, reused, identityPeerUDPPort); assignment.SocketCookie != socketCookie(t, reused) {
		t.Fatalf("reused tuple assignment %+v, want cookie %d", assignment, socketCookie(t, reused))
	}
}
