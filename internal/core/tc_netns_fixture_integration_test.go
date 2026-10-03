//go:build with_ebpf && linux && ebpf_integration

package core

// Network-namespace fixture for TC data-plane tests that need packets from
// real sockets. It uses only APIs that predate the identity work, so the
// overhead harness (tc_overhead_integration_test.go) can be built against an
// older revision of this package with this file copied in.

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	goRuntime "runtime"
	"syscall"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

const (
	identityLocalAddress = "10.211.0.1"
	identityPeerAddress  = "10.211.0.2"
	identityPeerTCPPort  = 7000
	identityPeerUDPPort  = 7001
	// System-range UIDs on purpose. On Android, netd attaches cgroup-skb
	// programs at the root cgroup that apply its UID firewall chains (for
	// example the BACKGROUND_MATCH allowlist) to every app-range UID, in every
	// network namespace, at cgroup egress -- before TC. A test socket chowned
	// to an app UID such as 10050 has its SYN dropped there and never reaches
	// the program under test. netd exempts uid % 100000 < 10000
	// (is_system_uid in packages/modules/Connectivity bpf/progs/netd.h;
	// bpf_owner_match in bpf/progs/netd.c). Observed on the test phone:
	// TcpOutSegs incremented, yet neither interface transmitted the SYN.
	uidIncluded = 9050
	uidOther    = 9060
)

// buildTestTopology enters a private namespace and builds the topology
// below, returning the local veth end and the dummy delivery interface:
//
//	[test ns] sbva 10.211.0.1 --veth-- sbvb 10.211.0.2 [peer ns, TCP echo :7000]
//	          sbdl (dummy): a delivery target where redirected packets are dropped
func buildTestTopology(t *testing.T) (netlink.Link, netlink.Link) {
	t.Helper()
	enterPrivateNetns(t)
	if loopback, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(loopback)
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sbva"}, PeerName: "sbvb"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	local, err := netlink.LinkByName("sbva")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("sbvb")
	if err != nil {
		t.Fatal(err)
	}
	address, _ := netlink.ParseAddr(identityLocalAddress + "/24")
	if err = netlink.AddrAdd(local, address); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(local); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "sbdl"}}); err != nil {
		t.Fatalf("create dummy: %v", err)
	}
	delivery, err := netlink.LinkByName("sbdl")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(delivery); err != nil {
		t.Fatal(err)
	}
	startPeerNamespace(t, peer)
	return local, delivery
}

// attachLocalEgress attaches the backend's Ethernet local egress program to
// the egress hook of device, for the rest of the test.
func attachLocalEgress(t *testing.T, backend *TCBackend, device netlink.Link) {
	t.Helper()
	attachment, err := link.AttachTCX(link.TCXOptions{
		Interface: device.Attrs().Index,
		Program:   backend.runtime.programs[tcProgramLocalEgressEthernet],
		Attach:    CiliumEBPF.AttachTCXEgress,
	})
	if err != nil {
		t.Fatalf("attach local egress: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
}

// enterPrivateNetns moves the calling, now locked, thread into a fresh network
// namespace and returns it to the original one at cleanup.
func enterPrivateNetns(t *testing.T) {
	t.Helper()
	goRuntime.LockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		goRuntime.UnlockOSThread()
		t.Fatal(err)
	}
	if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = original.Close()
		goRuntime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer original.Close()
		if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
			// Leave the thread locked: the runtime discards it with the goroutine.
			t.Errorf("restore network namespace: %v", err)
			return
		}
		goRuntime.UnlockOSThread()
	})
}

// startPeerNamespace creates a second namespace on its own locked thread, moves
// peerLink into it, configures it and opens a TCP echo listener there. The
// listener socket belongs to that namespace for its lifetime no matter which
// thread later accepts on it.
func startPeerNamespace(t *testing.T, peerLink netlink.Link) {
	t.Helper()
	namespaceFD := make(chan int)
	moved := make(chan error)
	ready := make(chan error)
	release := make(chan struct{})
	var listener int
	t.Cleanup(func() { close(release) })
	go func() {
		goRuntime.LockOSThread()
		// Never unlocked: the thread ends with this goroutine, still in the
		// peer namespace, and the runtime discards it.
		err := unix.Unshare(unix.CLONE_NEWNET)
		var namespace *os.File
		if err == nil {
			namespace, err = os.Open("/proc/thread-self/ns/net")
		}
		if err != nil {
			namespaceFD <- -1
			ready <- err
			<-release
			return
		}
		defer namespace.Close()
		// Moving the link is a request made from the namespace it is in now,
		// so the test thread does it with this fd.
		namespaceFD <- int(namespace.Fd())
		if err = <-moved; err == nil {
			listener, err = configurePeer(peerLink.Attrs().Name)
		}
		ready <- err
		<-release
		if listener > 0 {
			_ = unix.Close(listener)
		}
	}()
	fd := <-namespaceFD
	if fd >= 0 {
		moved <- netlink.LinkSetNsFd(peerLink, fd)
	}
	if err := <-ready; err != nil {
		t.Fatalf("peer namespace: %v", err)
	}
	go echoAcceptLoop(listener)
}

// configurePeer runs on the peer namespace's thread.
func configurePeer(name string) (int, error) {
	peer, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	address, _ := netlink.ParseAddr(identityPeerAddress + "/24")
	if err = netlink.AddrAdd(peer, address); err != nil {
		return 0, err
	}
	if err = netlink.LinkSetUp(peer); err != nil {
		return 0, err
	}
	if loopback, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(loopback)
	}
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	_ = unix.SetsockoptInt(listener, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err = unix.Bind(listener, &unix.SockaddrInet4{Port: identityPeerTCPPort, Addr: [4]byte{10, 211, 0, 2}}); err != nil {
		_ = unix.Close(listener)
		return 0, err
	}
	if err = unix.Listen(listener, 64); err != nil {
		_ = unix.Close(listener)
		return 0, err
	}
	return listener, nil
}

func echoAcceptLoop(listener int) {
	for {
		connection, _, err := unix.Accept(listener)
		if err != nil {
			return
		}
		go func() {
			defer unix.Close(connection)
			buffer := make([]byte, 4096)
			for {
				n, err := unix.Read(connection, buffer)
				if err != nil || n <= 0 {
					return
				}
				if _, err = unix.Write(connection, buffer[:n]); err != nil {
					return
				}
			}
		}()
	}
}

// ownedSocket creates a socket and gives it the UID the policy matches on.
func ownedSocket(t *testing.T, socketType int, uid uint32) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, socketType|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err = unix.Fchown(fd, int(uid), -1); err != nil {
		t.Fatalf("fchown socket: %v", err)
	}
	return fd
}

// startConnect begins a non-blocking connect to the peer echo server.
func startConnect(t *testing.T, uid uint32) int {
	t.Helper()
	fd := ownedSocket(t, unix.SOCK_STREAM, uid)
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	err := unix.Connect(fd, &unix.SockaddrInet4{Port: identityPeerTCPPort, Addr: [4]byte{10, 211, 0, 2}})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) {
		t.Fatalf("connect: %v", err)
	}
	return fd
}

// connectedWithin reports whether the connect finished successfully in time.
func connectedWithin(t *testing.T, fd int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(fds, 50)
		if err != nil && !errors.Is(err, unix.EINTR) {
			t.Fatal(err)
		}
		if n > 0 {
			soError, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				t.Fatal(err)
			}
			if soError != 0 {
				t.Fatalf("connect failed: %v", syscall.Errno(soError))
			}
			return true
		}
	}
	return false
}

// echoWithin writes a payload and reports whether it came back in time.
func echoWithin(t *testing.T, fd int, payload []byte, timeout time.Duration) bool {
	t.Helper()
	if _, err := unix.Write(fd, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	received := make([]byte, 0, len(payload))
	buffer := make([]byte, len(payload))
	deadline := time.Now().Add(timeout)
	for len(received) < len(payload) && time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, _ := unix.Poll(fds, 50); n <= 0 {
			continue
		}
		n, err := unix.Read(fd, buffer)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil || n <= 0 {
			t.Fatalf("read: %v", err)
		}
		received = append(received, buffer[:n]...)
	}
	return bytes.Equal(received, payload)
}

func socketCookie(t *testing.T, fd int) uint64 {
	t.Helper()
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func localAddrPort(t *testing.T, fd int) netip.AddrPort {
	t.Helper()
	name, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	address := name.(*unix.SockaddrInet4)
	return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port))
}

// dumpNetworkState logs what the test namespace looks like, for diagnosing a
// topology that does not pass traffic on an unfamiliar kernel.
func dumpNetworkState(t *testing.T) {
	t.Helper()
	links, _ := netlink.LinkList()
	for _, device := range links {
		attrs := device.Attrs()
		statistics := attrs.Statistics
		if statistics == nil {
			statistics = &netlink.LinkStatistics{}
		}
		t.Logf("link %s idx=%d state=%s flags=%v tx=%d rx=%d txdrop=%d", attrs.Name, attrs.Index, attrs.OperState, attrs.Flags, statistics.TxPackets, statistics.RxPackets, statistics.TxDropped)
	}
	routes, _ := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	for _, route := range routes {
		t.Logf("route %+v", route)
	}
	rules, _ := netlink.RuleList(unix.AF_INET)
	for _, rule := range rules {
		t.Logf("rule prio=%d table=%d mark=%d", rule.Priority, rule.Table, rule.Mark)
	}
	neighbors, _ := netlink.NeighList(0, unix.AF_INET)
	for _, neighbor := range neighbors {
		t.Logf("neigh %v %v state=%d", neighbor.IP, neighbor.HardwareAddr, neighbor.State)
	}
	content, _ := os.ReadFile("/proc/thread-self/net/snmp")
	t.Logf("snmp:\n%s", content)
}
