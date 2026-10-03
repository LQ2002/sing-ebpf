//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestTCABI(t *testing.T) {
	if size := unsafe.Sizeof(tcControl{}); size != 76 {
		t.Fatalf("unexpected TC control size: %d", size)
	}
	if offset := unsafe.Offsetof(tcControl{}.RoutingMark); offset != 12 {
		t.Fatalf("unexpected TC routing mark offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.DeliveryInterface); offset != 8 {
		t.Fatalf("unexpected TC delivery interface offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.ListenerPort); offset != 16 {
		t.Fatalf("unexpected TC listener port offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.ForceInterceptIPv6Mask); offset != 54 {
		t.Fatalf("unexpected TC IPv6 ForceIntercept mask offset: %d", offset)
	}
	if size := unsafe.Sizeof(tcAssignKey{}); size != 44 {
		t.Fatalf("unexpected TC assignment key size: %d", size)
	}
	// Mirrors the _Static_asserts on struct sb_tc_assign_value in
	// native/tc.bpf.c; TestEmbeddedTCObjectLayout checks the compiled map.
	if size := unsafe.Sizeof(TCAssignment{}); size != 88 {
		t.Fatalf("unexpected TC assignment value size: %d", size)
	}
	for name, offsets := range map[string][2]uintptr{
		"SocketCookie":   {unsafe.Offsetof(TCAssignment{}.SocketCookie), 0},
		"InterfaceIndex": {unsafe.Offsetof(TCAssignment{}.InterfaceIndex), 8},
		"SourceMAC":      {unsafe.Offsetof(TCAssignment{}.SourceMAC), 12},
		"Path":           {unsafe.Offsetof(TCAssignment{}.Path), 18},
		"SourceMACValid": {unsafe.Offsetof(TCAssignment{}.SourceMACValid), 19},
		"SocketUID":      {unsafe.Offsetof(TCAssignment{}.SocketUID), 20},
		"SocketCgroupID": {unsafe.Offsetof(TCAssignment{}.SocketCgroupID), 24},
		"IdentityFlags":  {unsafe.Offsetof(TCAssignment{}.IdentityFlags), 32},
		"Reserved":       {unsafe.Offsetof(TCAssignment{}.Reserved), 36},
		"Creator":        {unsafe.Offsetof(TCAssignment{}.Creator), 40},
	} {
		if offsets[0] != offsets[1] {
			t.Fatalf("unexpected TC assignment %s offset: %d, want %d", name, offsets[0], offsets[1])
		}
	}
	if flags := (policyVector{UIDPolicy: true, UIDDefaultBypass: true}).tcFlags(); flags != tcFlagUIDPolicy|tcFlagUIDDefaultBypass {
		t.Fatalf("UID flag constants disagree with the policy vector: %#x", flags)
	}
}

func TestTCIPv6PathFlags(t *testing.T) {
	localFlags := tcFlags(TCConfig{EnableLocalIPv6: true}, CompiledPolicy{})
	if localFlags&tcFlagLocalIPv6 == 0 || localFlags&tcFlagSharedIPv6 != 0 {
		t.Fatalf("unexpected local IPv6 flags: %#x", localFlags)
	}
	sharedFlags := tcFlags(TCConfig{EnableSharedIPv6: true}, CompiledPolicy{})
	if sharedFlags&tcFlagLocalIPv6 != 0 || sharedFlags&tcFlagSharedIPv6 == 0 {
		t.Fatalf("unexpected shared IPv6 flags: %#x", sharedFlags)
	}
	hybridFlags := tcFlags(TCConfig{EnableLocalIPv6: true, EnableSharedIPv6: true}, CompiledPolicy{})
	if hybridFlags&(tcFlagLocalIPv6|tcFlagSharedIPv6) != tcFlagLocalIPv6|tcFlagSharedIPv6 {
		t.Fatalf("unexpected hybrid IPv6 flags: %#x", hybridFlags)
	}
}

func TestMakeTCAssignKey(t *testing.T) {
	for _, test := range []struct {
		source      string
		destination string
		family      uint8
	}{
		{"192.0.2.10:12345", "1.1.1.1:443", addressFamilyIPv4},
		{"[2001:db8::10]:12345", "[2606:4700:4700::1111]:443", addressFamilyIPv6},
	} {
		source := netip.MustParseAddrPort(test.source)
		destination := netip.MustParseAddrPort(test.destination)
		key, err := makeTCAssignKey(ProtocolTCP, source, destination, 17)
		if err != nil {
			t.Fatal(err)
		}
		if key.Family != test.family || key.Protocol != ProtocolTCP ||
			key.SourcePort != source.Port() || key.DestinationPort != destination.Port() || key.InterfaceIndex != 17 {
			t.Fatalf("unexpected TC assignment key: %+v", key)
		}
		if got := tcKeyAddress(key.Family, key.SourceAddress); got != source.Addr() {
			t.Fatalf("unexpected source address: %s", got)
		}
		if got := tcKeyAddress(key.Family, key.DestinationAddress); got != destination.Addr() {
			t.Fatalf("unexpected destination address: %s", got)
		}
	}
	if _, err := makeTCAssignKey(
		ProtocolUDP,
		netip.MustParseAddrPort("192.0.2.1:1"),
		netip.MustParseAddrPort("[2001:db8::1]:2"),
		0,
	); err == nil {
		t.Fatal("mixed address families were accepted")
	}
}

func tcKeyAddress(family uint8, address [16]byte) netip.Addr {
	if family == addressFamilyIPv4 {
		return netip.AddrFrom4([4]byte(address[:4]))
	}
	return netip.AddrFrom16(address)
}
