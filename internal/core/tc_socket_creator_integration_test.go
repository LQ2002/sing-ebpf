//go:build with_ebpf && linux && ebpf_integration

package core

// These tests seed synthetic producer records through real socket FDs, then
// exercise the production TC programs with real packets. They validate the
// SK_STORAGE -> TC assignment boundary, not the creation hook or Android App
// registration. Run only in the existing opt-in private-network fixture.

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func newSocketCreatorTestMap(t *testing.T) *CiliumEBPF.Map {
	t.Helper()
	requireEBPFIntegration(t, "read creator SK_STORAGE from TC on real sockets")
	if err := raiseMemlockLimit(); err != nil {
		t.Fatal(err)
	}
	spec := &CiliumEBPF.MapSpec{
		Name: "sb_test_creator", Type: CiliumEBPF.SkStorage,
		KeySize: 4, ValueSize: uint32(unsafe.Sizeof(SocketCreator{})),
		Flags: bpfFlagNoPrealloc,
	}
	describeLocalStorageTypes(spec)
	creatorMap, err := CiliumEBPF.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = creatorMap.Close() })
	return creatorMap
}

func socketCreatorTestRecord(t *testing.T, fd int, generation uint32) SocketCreator {
	t.Helper()
	creator := SocketCreator{
		Cookie: socketCookie(t, fd), StartTimeNs: 1000000000 + uint64(generation),
		ProcessID: uint32(os.Getpid()), ThreadID: uint32(unix.Gettid()),
		UserID: 0, Flags: SocketCreatorValid,
	}
	copy(creator.Comm[:], fmt.Sprintf("creator-%d", generation))
	return creator
}

func setSocketCreatorTestRecord(t *testing.T, creatorMap *CiliumEBPF.Map, fd int, creator SocketCreator) {
	t.Helper()
	key := uint32(fd)
	if err := creatorMap.Update(&key, &creator, CiliumEBPF.UpdateAny); err != nil {
		t.Fatalf("seed socket creator: %v", err)
	}
}

// os.File makes early close plus test cleanup safe even when the next socket
// reuses the same descriptor number, as the tuple-reuse test intentionally does.
func newSocketCreatorTestSocket(t *testing.T, socketType int, uid uint32, source netip.AddrPort) *os.File {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, socketType|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(fd), "creator-test-socket")
	t.Cleanup(func() { _ = socket.Close() })
	if err = unix.Fchown(fd, int(uid), -1); err != nil {
		t.Fatal(err)
	}
	if socketType == unix.SOCK_DGRAM {
		address := &unix.SockaddrInet4{Addr: netip.MustParseAddr(identityLocalAddress).As4()}
		if source.IsValid() {
			address.Addr, address.Port = source.Addr().As4(), int(source.Port())
		}
		if err = unix.Bind(fd, address); err != nil {
			t.Fatal(err)
		}
	}
	return socket
}

func connectSocketCreatorTestTCP(t *testing.T, fd int) {
	t.Helper()
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	err := unix.Connect(fd, &unix.SockaddrInet4{Port: identityPeerTCPPort, Addr: netip.MustParseAddr(identityPeerAddress).As4()})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) {
		t.Fatal(err)
	}
}

func sendSocketCreatorTestUDP(t *testing.T, f *identityFixture, fd int) TCAssignment {
	t.Helper()
	baseline := f.redirectedPackets(t)
	if err := unix.Sendto(fd, []byte("creator"), 0, &unix.SockaddrInet4{Port: identityPeerUDPPort, Addr: f.peer.As4()}); err != nil {
		t.Fatal(err)
	}
	waitForRedirects(t, f, baseline)
	return f.assignment(t, ProtocolUDP, fd, identityPeerUDPPort)
}

func requireSocketCreatorAssignment(t *testing.T, assignment TCAssignment, creator SocketCreator) {
	t.Helper()
	if !assignment.HasSocketCreator() || assignment.Creator != creator || assignment.SocketCookie != creator.Cookie {
		t.Fatalf("assignment %+v, want creator %+v", assignment, creator)
	}
}

func TestTCSocketCreatorFirstPacket(t *testing.T) {
	for _, recordIdentity := range []bool{false, true} {
		for _, protocol := range []uint8{ProtocolTCP, ProtocolUDP} {
			t.Run(fmt.Sprintf("identity=%v/protocol=%d", recordIdentity, protocol), func(t *testing.T) {
				creatorMap := newSocketCreatorTestMap(t)
				f := newIdentityFixtureWithCreator(t, recordIdentity, creatorMap, uidIncluded)
				socketType := unix.SOCK_STREAM
				if protocol == ProtocolUDP {
					socketType = unix.SOCK_DGRAM
				}
				socket := newSocketCreatorTestSocket(t, socketType, uidIncluded, netip.AddrPort{})
				fd := int(socket.Fd())
				creator := socketCreatorTestRecord(t, fd, 1)
				setSocketCreatorTestRecord(t, creatorMap, fd, creator)
				var assignment TCAssignment
				if protocol == ProtocolTCP {
					baseline := f.redirectedPackets(t)
					connectSocketCreatorTestTCP(t, fd)
					waitForRedirects(t, f, baseline)
					assignment = f.assignment(t, protocol, fd, identityPeerTCPPort)
				} else {
					assignment = sendSocketCreatorTestUDP(t, f, fd)
				}
				requireSocketCreatorAssignment(t, assignment, creator)
				if recordIdentity && (!assignment.HasSocketIdentity() || assignment.SocketUID != uidIncluded) {
					t.Fatalf("creator collection lost socket identity: %+v", assignment)
				}
			})
		}
	}
}

func TestTCSocketCreatorKeepsFirstSnapshot(t *testing.T) {
	creatorMap := newSocketCreatorTestMap(t)
	f := newIdentityFixtureWithCreator(t, true, creatorMap, uidIncluded, uidIncluded+1)
	socket := newSocketCreatorTestSocket(t, unix.SOCK_DGRAM, uidIncluded, netip.AddrPort{})
	fd := int(socket.Fd())
	creator := socketCreatorTestRecord(t, fd, 1)
	setSocketCreatorTestRecord(t, creatorMap, fd, creator)
	requireSocketCreatorAssignment(t, sendSocketCreatorTestUDP(t, f, fd), creator)

	// Even an externally replaced producer value cannot relabel an assignment
	// whose cookie already has a valid creation snapshot.
	replacement := socketCreatorTestRecord(t, fd, 2)
	replacement.ProcessID++
	replacement.UserID = uidIncluded + 1
	setSocketCreatorTestRecord(t, creatorMap, fd, replacement)
	requireSocketCreatorAssignment(t, sendSocketCreatorTestUDP(t, f, fd), creator)
	if err := unix.Fchown(fd, int(uidIncluded+1), -1); err != nil {
		t.Fatal(err)
	}
	assignment := sendSocketCreatorTestUDP(t, f, fd)
	requireSocketCreatorAssignment(t, assignment, creator)
	if assignment.SocketUID != uidIncluded+1 || assignment.Creator.UserID != 0 {
		t.Fatalf("billing UID change overwrote creator UID: %+v", assignment)
	}
	key := uint32(fd)
	if err := creatorMap.Delete(&key); err != nil {
		t.Fatal(err)
	}
	requireSocketCreatorAssignment(t, sendSocketCreatorTestUDP(t, f, fd), creator)
}

func TestTCSocketCreatorConfirmsMissingSnapshot(t *testing.T) {
	creatorMap := newSocketCreatorTestMap(t)
	f := newIdentityFixtureWithCreator(t, true, creatorMap, uidIncluded, uidIncluded+1)
	socket := newSocketCreatorTestSocket(t, unix.SOCK_DGRAM, uidIncluded, netip.AddrPort{})
	fd := int(socket.Fd())
	assignment := sendSocketCreatorTestUDP(t, f, fd)
	if assignment.Creator != (SocketCreator{}) || assignment.HasSocketCreator() ||
		assignment.IdentityFlags&TCIdentityCreatorChecked == 0 {
		t.Fatalf("full socket with missing storage was not negatively cached: %+v", assignment)
	}
	creator := socketCreatorTestRecord(t, fd, 1)
	setSocketCreatorTestRecord(t, creatorMap, fd, creator)
	// The production hook captures synchronously at creation. A confirmed
	// missing record cannot become a creation record later on this socket.
	assignment = sendSocketCreatorTestUDP(t, f, fd)
	if assignment.Creator != (SocketCreator{}) || assignment.IdentityFlags&TCIdentityCreatorChecked == 0 {
		t.Fatalf("a late producer value relabeled a confirmed-missing socket: %+v", assignment)
	}
	if err := unix.Fchown(fd, int(uidIncluded+1), -1); err != nil {
		t.Fatal(err)
	}
	assignment = sendSocketCreatorTestUDP(t, f, fd)
	if assignment.Creator != (SocketCreator{}) || assignment.SocketUID != uidIncluded+1 ||
		assignment.IdentityFlags&TCIdentityCreatorChecked == 0 {
		t.Fatalf("billing UID change lost the negative creator snapshot: %+v", assignment)
	}
}
func TestTCSocketCreatorRejectsInvalidStorage(t *testing.T) {
	creatorMap := newSocketCreatorTestMap(t)
	f := newIdentityFixtureWithCreator(t, true, creatorMap, uidIncluded)
	for _, test := range []struct {
		name       string
		invalidate func(*SocketCreator)
	}{
		{"zero-cookie", func(c *SocketCreator) { c.Cookie = 0 }},
		{"other-cookie", func(c *SocketCreator) { c.Cookie++ }},
		{"missing-flag", func(c *SocketCreator) { c.Flags = 0 }},
		{"missing-birth", func(c *SocketCreator) { c.StartTimeNs = 0 }},
		{"missing-pid", func(c *SocketCreator) { c.ProcessID = 0 }},
		{"missing-tid", func(c *SocketCreator) { c.ThreadID = 0 }},
	} {
		// Stay on the fixture's locked OS thread. A nested t.Run would execute
		// its callback on another goroutine outside the private network namespace.
		socket := newSocketCreatorTestSocket(t, unix.SOCK_DGRAM, uidIncluded, netip.AddrPort{})
		fd := int(socket.Fd())
		creator := socketCreatorTestRecord(t, fd, 1)
		test.invalidate(&creator)
		setSocketCreatorTestRecord(t, creatorMap, fd, creator)
		assignment := sendSocketCreatorTestUDP(t, f, fd)
		if assignment.HasSocketCreator() || assignment.Creator != (SocketCreator{}) ||
			assignment.IdentityFlags&TCIdentityCreatorChecked != 0 {
			t.Fatalf("%s storage accepted or incorrectly cached as absent: %+v", test.name, assignment)
		}
		valid := socketCreatorTestRecord(t, fd, 2)
		setSocketCreatorTestRecord(t, creatorMap, fd, valid)
		requireSocketCreatorAssignment(t, sendSocketCreatorTestUDP(t, f, fd), valid)
		if err := socket.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTCSocketCreatorTupleReuse(t *testing.T) {
	creatorMap := newSocketCreatorTestMap(t)
	f := newIdentityFixtureWithCreator(t, true, creatorMap, uidIncluded)
	first := newSocketCreatorTestSocket(t, unix.SOCK_DGRAM, uidIncluded, netip.AddrPort{})
	firstFD := int(first.Fd())
	firstCreator := socketCreatorTestRecord(t, firstFD, 1)
	setSocketCreatorTestRecord(t, creatorMap, firstFD, firstCreator)
	requireSocketCreatorAssignment(t, sendSocketCreatorTestUDP(t, f, firstFD), firstCreator)
	source := localAddrPort(t, firstFD)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// A new socket on the exact tuple must clear the old creator, even though
	// socket UID and creation cgroup are unchanged and the old entry remains.
	second := newSocketCreatorTestSocket(t, unix.SOCK_DGRAM, uidIncluded, source)
	secondFD := int(second.Fd())
	secondCookie := socketCookie(t, secondFD)
	assignment := sendSocketCreatorTestUDP(t, f, secondFD)
	if secondCookie == firstCreator.Cookie || assignment.SocketCookie != secondCookie || assignment.Creator != (SocketCreator{}) {
		t.Fatalf("tuple reuse leaked old creator: %+v (old %+v)", assignment, firstCreator)
	}
	if assignment.IdentityFlags&TCIdentityCreatorChecked == 0 {
		t.Fatalf("reused full socket with no creator was not negatively cached: %+v", assignment)
	}
	secondCreator := socketCreatorTestRecord(t, secondFD, 2)
	setSocketCreatorTestRecord(t, creatorMap, secondFD, secondCreator)
	if assignment = sendSocketCreatorTestUDP(t, f, secondFD); assignment.Creator != (SocketCreator{}) {
		t.Fatalf("late storage replaced the new socket's confirmed-missing snapshot: %+v", assignment)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	third := newSocketCreatorTestSocket(t, unix.SOCK_DGRAM, uidIncluded, source)
	thirdFD := int(third.Fd())
	thirdCreator := socketCreatorTestRecord(t, thirdFD, 3)
	if thirdCreator.Cookie == firstCreator.Cookie || thirdCreator.Cookie == secondCookie {
		t.Fatal("new socket unexpectedly reused a live test cookie")
	}
	setSocketCreatorTestRecord(t, creatorMap, thirdFD, thirdCreator)
	requireSocketCreatorAssignment(t, sendSocketCreatorTestUDP(t, f, thirdFD), thirdCreator)
}

func TestTCSocketCreatorSurvivesDelivery(t *testing.T) {
	creatorMap := newSocketCreatorTestMap(t)
	f := newIdentityFixtureWithCreator(t, true, creatorMap, uidIncluded)
	listener := attachDelivery(t, f)
	socket := newSocketCreatorTestSocket(t, unix.SOCK_STREAM, uidIncluded, netip.AddrPort{})
	fd := int(socket.Fd())
	creator := socketCreatorTestRecord(t, fd, 1)
	setSocketCreatorTestRecord(t, creatorMap, fd, creator)
	connectSocketCreatorTestTCP(t, fd)
	if !connectedWithin(t, fd, 2*time.Second) {
		t.Fatal("redirected connection did not reach the transparent listener")
	}
	accepted, _, err := unix.Accept(listener)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(accepted)
	assignment := f.assignment(t, ProtocolTCP, fd, identityPeerTCPPort)
	requireSocketCreatorAssignment(t, assignment, creator)
	if assignment.Path != TCPathDelivery {
		t.Fatalf("assignment did not cross delivery ingress: %+v", assignment)
	}
}

func TestTCSocketCreatorBorrowedMapSurvivesBackend(t *testing.T) {
	creatorMap := newSocketCreatorTestMap(t)
	// No attachment or network changes are needed to test map ownership.
	fd := ownedSocket(t, unix.SOCK_DGRAM, 0)
	creator := socketCreatorTestRecord(t, fd, 1)
	setSocketCreatorTestRecord(t, creatorMap, fd, creator)
	config := TCConfig{
		ListenerPort: 65531, EnableLocal: true, EnableIPv4: true,
		EnableUDP: true, SocketCreatorMap: creatorMap,
	}
	backend, err := PrepareTC(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	checkBorrowedMap := func() {
		t.Helper()
		var got SocketCreator
		key := uint32(fd)
		if err := creatorMap.Lookup(&key, &got); err != nil || got != creator {
			t.Fatalf("borrowed creator map lost after backend cleanup: %+v, %v", got, err)
		}
	}
	checkBorrowedMap()

	// The second object read occurs after the external map is inserted into
	// the backend's map set. Fail that read to exercise the load-error cleanup.
	originalLoadTC := loadTC
	defer func() { loadTC = originalLoadTC }()
	loadCalls := 0
	injected := errors.New("injected creator program load failure")
	loadTC = func() (*CiliumEBPF.CollectionSpec, error) {
		loadCalls++
		if loadCalls == 2 {
			return nil, injected
		}
		return originalLoadTC()
	}
	failedBackend, err := PrepareTC(config)
	if failedBackend != nil {
		_ = failedBackend.Close()
		t.Fatal("program load failure returned a backend")
	}
	if !errors.Is(err, injected) || loadCalls != 2 {
		t.Fatalf("load failure = %v after %d reads", err, loadCalls)
	}
	checkBorrowedMap()
}

func TestTCSocketCreatorRejectsWrongMapBeforeLoading(t *testing.T) {
	requireEBPFIntegration(t, "reject incompatible real creator maps before loading TC")
	if err := raiseMemlockLimit(); err != nil {
		t.Fatal(err)
	}
	originalLoadTC := loadTC
	defer func() { loadTC = originalLoadTC }()
	loadCalls := 0
	loadTC = func() (*CiliumEBPF.CollectionSpec, error) {
		loadCalls++
		return nil, errors.New("unexpected TC object load for invalid creator map")
	}
	for _, spec := range []*CiliumEBPF.MapSpec{
		{Name: "sb_bad_hash", Type: CiliumEBPF.Hash, KeySize: 4, ValueSize: 48, MaxEntries: 1},
		{Name: "sb_bad_storage", Type: CiliumEBPF.SkStorage, KeySize: 4, ValueSize: 40, Flags: bpfFlagNoPrealloc},
	} {
		if spec.Type == CiliumEBPF.SkStorage {
			describeLocalStorageTypes(spec)
		}
		creatorMap, err := CiliumEBPF.NewMap(spec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = creatorMap.Close() })
		fd := ownedSocket(t, unix.SOCK_DGRAM, 0)
		key := uint32(fd)
		value := make([]byte, spec.ValueSize)
		value[0], value[len(value)-1] = 0x5a, 0xa5
		if err := creatorMap.Update(&key, value, CiliumEBPF.UpdateAny); err != nil {
			t.Fatal(err)
		}
		backend, err := PrepareTC(TCConfig{
			ListenerPort: 65531, EnableLocal: true, EnableIPv4: true,
			EnableTCP: true, EnableUDP: true, SocketCreatorMap: creatorMap,
		})
		if backend != nil {
			_ = backend.Close()
			t.Fatalf("%s accepted as creator storage", spec.Name)
		}
		if err == nil || loadCalls != 0 {
			t.Fatalf("%s rejection = %v after %d object loads", spec.Name, err, loadCalls)
		}
		got := make([]byte, spec.ValueSize)
		if err := creatorMap.Lookup(&key, &got); err != nil || !bytes.Equal(got, value) {
			t.Fatalf("%s rejection closed or modified caller map: %x, %v", spec.Name, got, err)
		}
	}
}
