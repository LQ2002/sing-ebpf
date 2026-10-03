//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestTCSocketCreatorLiveProducer uses the actual creation hook maintained by
// the parent collector. Unlike the synthetic producer tests, this test never
// writes socket storage. The parent must keep its collector open throughout
// this test and owns all pin cleanup. Only this test's read-only map FD closes.
//
// Set SING_EBPF_INTEGRATION=1 and SING_EBPF_CREATOR_MAP_PIN to the collector's
// creators map pin. All network changes use the existing private-netns fixture.
func TestTCSocketCreatorLiveProducer(t *testing.T) {
	pin := os.Getenv("SING_EBPF_CREATOR_MAP_PIN")
	if pin == "" {
		t.Skip("set SING_EBPF_CREATOR_MAP_PIN to a live collector's creators map")
	}
	requireEBPFIntegration(t, "run live creator producer -> existing TC assignments")
	creatorMap, err := CiliumEBPF.LoadPinnedMap(pin, &CiliumEBPF.LoadPinOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("open live creator map read-only: %v", err)
	}
	t.Cleanup(func() { _ = creatorMap.Close() })
	if err := validateSocketCreatorMap(creatorMap); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		socketType int
		protocol   uint8
		delivery   bool
	}{
		{"tcp-first-packet", unix.SOCK_STREAM, ProtocolTCP, false},
		{"udp-first-packet", unix.SOCK_DGRAM, ProtocolUDP, false},
		{"tcp-delivery", unix.SOCK_STREAM, ProtocolTCP, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The fixture locks this goroutine to its network-namespace thread.
			// Do not nest another t.Run after this point: TID must be measured
			// on the exact thread that performs socket(2).
			f := newIdentityFixtureWithCreator(t, true, creatorMap, uidIncluded)
			listener := -1
			if test.delivery {
				listener = attachDelivery(t, f)
			}
			processID, threadID, userID := uint32(os.Getpid()), uint32(unix.Gettid()), uint32(os.Getuid())
			commBytes, err := os.ReadFile("/proc/thread-self/comm")
			if err != nil {
				t.Fatalf("read creator thread comm: %v", err)
			}
			var comm [16]byte
			copy(comm[:], strings.TrimSuffix(string(commBytes), "\n"))
			// Fchown changes billing UID after the creation hook. The live
			// creator record must still carry the actual creating task's UID.
			socket := newSocketCreatorTestSocket(t, test.socketType, uidIncluded, netip.AddrPort{})
			fd := int(socket.Fd())
			cookie := socketCookie(t, fd)
			var creator SocketCreator
			key := uint32(fd)
			// This lookup is before the first send/connect. There is no retry
			// window that could hide a collector missing the creation event.
			if err := creatorMap.Lookup(&key, &creator); err != nil {
				t.Fatalf("live producer has no pre-send socket record: %v", err)
			}
			if !creator.IsValid() || creator.Cookie != cookie || creator.ProcessID != processID ||
				creator.ThreadID != threadID || creator.UserID != userID || creator.Comm != comm {
				t.Fatalf("live creator %+v, want cookie=%d tgid=%d tid=%d uid=%d comm=%x and nonzero birth",
					creator, cookie, processID, threadID, userID, comm)
			}
			t.Logf("LIVE_PRODUCER_CREATE case=%s cookie=%d birth_ns=%d tgid=%d tid=%d creator_uid=%d flags=%#x comm=%x",
				test.name, creator.Cookie, creator.StartTimeNs, creator.ProcessID, creator.ThreadID, creator.UserID, creator.Flags, creator.Comm)

			var assignment TCAssignment
			if test.protocol == ProtocolUDP {
				assignment = sendSocketCreatorTestUDP(t, f, fd)
			} else {
				baseline := f.redirectedPackets(t)
				connectSocketCreatorTestTCP(t, fd)
				if test.delivery {
					if !connectedWithin(t, fd, 2*time.Second) {
						t.Fatal("live creator connection did not reach the transparent listener")
					}
					accepted, _, err := unix.Accept(listener)
					if err != nil {
						t.Fatalf("accept live creator connection: %v", err)
					}
					defer unix.Close(accepted)
				} else {
					waitForRedirects(t, f, baseline)
				}
				assignment = f.assignment(t, ProtocolTCP, fd, identityPeerTCPPort)
			}
			requireSocketCreatorAssignment(t, assignment, creator)
			if !assignment.HasSocketIdentity() || assignment.SocketUID != uidIncluded {
				t.Fatalf("live creator assignment lost independent billing UID: %+v", assignment)
			}
			expectedPath := uint8(0)
			if test.delivery {
				expectedPath = TCPathDelivery
			}
			if assignment.Path != expectedPath {
				t.Fatalf("live creator assignment path=%d, want %d", assignment.Path, expectedPath)
			}
			t.Logf("LIVE_PRODUCER_ASSIGNMENT case=%s cookie=%d birth_ns=%d tgid=%d tid=%d creator_uid=%d socket_uid=%d path=%d flags=%#x comm=%x",
				test.name, assignment.SocketCookie, assignment.Creator.StartTimeNs, assignment.Creator.ProcessID,
				assignment.Creator.ThreadID, assignment.Creator.UserID, assignment.SocketUID, assignment.Path,
				assignment.Creator.Flags, assignment.Creator.Comm)
		})
	}
}
