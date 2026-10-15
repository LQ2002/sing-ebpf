//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"net/netip"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
)

// newTestAssignmentBackend builds a backend whose only runtime is a real
// assignment map, which is what the lookup path reads and writes.
func newTestAssignmentBackend(t *testing.T) *TCBackend {
	t.Helper()
	assignmentMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(tcAssignKey{})),
		ValueSize:  uint32(unsafe.Sizeof(TCAssignment{})),
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("cannot create an assignment map: %v", err)
	}
	t.Cleanup(func() { _ = assignmentMap.Close() })
	controlMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(tcControl{})),
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("cannot create a control map: %v", err)
	}
	t.Cleanup(func() { _ = controlMap.Close() })
	backend := &TCBackend{}
	backend.runtime = &tcRuntime{maps: map[string]*CiliumEBPF.Map{"tc_assignment": assignmentMap, "tc_control": controlMap}}
	backend.assignmentMapFD = assignmentMap.FD()
	backend.controlMapFD = controlMap.FD()
	return backend
}

// writeTestAssignment writes through the same raw map helper the programs and
// the lookup path use, so the value is laid out the way the map expects rather
// than the way a marshaller would pack it.
func writeTestAssignment(
	t *testing.T,
	backend *TCBackend,
	protocol uint8,
	source, destination netip.AddrPort,
	interfaceIndex uint32,
	value TCAssignment,
) {
	t.Helper()
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		t.Fatalf("build the assignment key: %v", err)
	}
	if err = updateMap(backend.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatalf("write the assignment: %v", err)
	}
}

// TestLookupAssignmentKeyIncludesInterfaceIndex covers what the interface index
// does in the lookup key: an entry is found under the index it was written for,
// and not under a different one.
//
// It says nothing about how long an entry lives or about what happens to entries
// when an interface goes away.
func TestLookupAssignmentKeyIncludesInterfaceIndex(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41000")
	destination := netip.MustParseAddrPort("10.0.0.1:53")
	const reusedIndex = 5

	// An entry written for one interface index.
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, reusedIndex, TCAssignment{
		SocketCookie:   0x1111,
		InterfaceIndex: reusedIndex,
		SourceMAC:      MACAddress{0xaa, 0, 0, 0, 0, 1},
		Path:           TCPathShared,
		SourceMACValid: 1,
	})

	// The same flow and the same index read the same key.
	assignment, err := backend.LookupAssignment(ProtocolUDP, source, destination, reusedIndex, false)
	if err != nil {
		t.Fatalf("lookup the assignment: %v", err)
	}
	if assignment.SocketCookie != 0x1111 {
		t.Fatalf("assignment = %+v, want the entry that was written", assignment)
	}

	// A different index is a different key.
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, reusedIndex+1, false); err == nil {
		t.Fatal("an assignment was found under an index it was not written for")
	}
}

// TestLookupAssignmentRemovesEntryOnRequest covers the removing form of the
// lookup, which is the one the TCP path uses: a successful read with remove set
// takes the entry with it, and a second read of the same key finds nothing.
//
// It covers that one call. It does not say what else may write the same key
// before or after.
func TestLookupAssignmentRemovesEntryOnRequest(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41001")
	destination := netip.MustParseAddrPort("10.0.0.1:443")

	writeTestAssignment(t, backend, ProtocolTCP, source, destination, 0, TCAssignment{
		SocketCookie: 0x2222,
		Path:         TCPathDelivery,
	})

	assignment, err := backend.LookupAssignment(ProtocolTCP, source, destination, 0, true)
	if err != nil {
		t.Fatalf("lookup the assignment: %v", err)
	}
	if assignment.SocketCookie != 0x2222 {
		t.Fatalf("assignment = %+v, want the entry that was written", assignment)
	}
	if _, err = backend.LookupAssignment(ProtocolTCP, source, destination, 0, false); err == nil {
		t.Fatal("the entry survived a lookup that was asked to remove it")
	}
}

// TestLookupAssignmentKeepsEntryWhenNotAsked covers the other form, which is the
// one the UDP path uses: reading without remove leaves the entry in place, so
// the same key can be read again.
//
// It covers the lookup only. Nothing here is a statement about when entries are
// otherwise removed.
func TestLookupAssignmentKeepsEntryWhenNotAsked(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41002")
	destination := netip.MustParseAddrPort("10.0.0.1:53")

	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 7, TCAssignment{
		SocketCookie: 0x3333,
		Path:         TCPathShared,
	})

	for range 3 {
		assignment, err := backend.LookupAssignment(ProtocolUDP, source, destination, 7, false)
		if err != nil {
			t.Fatalf("lookup the assignment: %v", err)
		}
		if assignment.SocketCookie != 0x3333 {
			t.Fatalf("assignment = %+v, want the entry that was written", assignment)
		}
	}
}

func TestRemoveAssignmentIfMatch(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	expected := TCAssignment{SocketCookie: 0x4444, InterfaceIndex: 17, Path: TCPathShared}
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, expected)

	if removed, err := backend.RemoveAssignmentIfMatch(ProtocolUDP, source, destination, 17, TCAssignment{SocketCookie: 0x9999}); err != nil {
		t.Fatalf("mismatched removal: %v", err)
	} else if removed {
		t.Fatal("mismatched assignment was removed")
	}
	if _, err := backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err != nil {
		t.Fatalf("mismatched removal deleted assignment: %v", err)
	}

	if removed, err := backend.RemoveAssignmentIfMatch(ProtocolUDP, source, destination, 17, expected); err != nil {
		t.Fatalf("matching removal: %v", err)
	} else if !removed {
		t.Fatal("matching assignment was not removed")
	}
	if _, err := backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err == nil {
		t.Fatal("matching removal left assignment in map")
	}
}

func TestSweepAssignmentsRemovesOnlyUnchangedStaleEntries(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	backend.assignmentCapacity = 64
	now := monotonicNowNS()
	// Period 1 began two minutes ago, period 2 one minute ago and is current.
	backend.activityEpochs.begin(1, now-uint64(2*time.Minute))
	backend.activityEpochs.begin(2, now-uint64(time.Minute))
	backend.control.ActivityEpoch = 2
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	write := func(port uint16, epoch uint32) netip.AddrPort {
		source := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port)
		writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17,
			TCAssignment{SocketCookie: uint64(port), InterfaceIndex: 17, Path: TCPathShared, ActivityEpoch: epoch})
		return source
	}
	stale := write(53000, 1)     // no packet since period 2 began, 60s ago
	current := write(53001, 2)   // seen in the current period
	unstamped := write(53002, 0) // only the local path wrote it

	result, err := backend.SweepAssignments(30*time.Second, 64)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 1 || !result.Complete || !result.UsageKnown || result.Failure != "" {
		t.Fatalf("unexpected sweep result: %+v", result)
	}
	if _, err = backend.LookupAssignment(ProtocolUDP, stale, destination, 17, false); err == nil {
		t.Fatal("stale assignment remains in map")
	}
	for _, source := range []netip.AddrPort{current, unstamped} {
		if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err != nil {
			t.Fatalf("assignment from %s was removed: %v", source, err)
		}
	}
	// The sweep started period 3 and published it without a policy bump.
	if backend.control.ActivityEpoch != 3 || backend.control.PolicyGeneration != 0 {
		t.Fatalf("control after sweep: epoch %d, policy generation %d",
			backend.control.ActivityEpoch, backend.control.PolicyGeneration)
	}
	var published tcControl
	key := uint32(0)
	if err = lookupMap(backend.controlMapFD, unsafe.Pointer(&key), unsafe.Pointer(&published)); err != nil {
		t.Fatal(err)
	}
	if published.ActivityEpoch != 3 {
		t.Fatalf("published activity epoch %d, want 3", published.ActivityEpoch)
	}
	// A second sweep within tcActivityEpochMinSpan keeps the period.
	if _, err = backend.SweepAssignments(30*time.Second, 64); err != nil {
		t.Fatal(err)
	}
	if backend.control.ActivityEpoch != 3 {
		t.Fatalf("period advanced within the minimum span: %d", backend.control.ActivityEpoch)
	}
}
