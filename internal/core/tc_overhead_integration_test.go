//go:build with_ebpf && linux && ebpf_integration

package core

// Paired overhead harness for the local egress TC program. It measures what
// the kernel itself accounts to the program (BPF_ENABLE_STATS run time and run
// count, i.e. including every helper it calls) while real sockets push
// packets through it, so the number covers the whole changed code path rather
// than one helper in isolation.
//
// It deliberately uses only APIs that existed before the socket identity work
// (PrepareTC with TrackProcess, not RecordSocketIdentity), so the same file,
// together with tc_netns_fixture_integration_test.go, builds against the
// previous revision too. Comparing the two builds on the same device, run
// alternately, is the paired measurement:
//
//	git archive <old> | tar -x -C old && cp tc_netns_fixture_integration_test.go tc_overhead_integration_test.go old/internal/core/
//	SING_EBPF_INTEGRATION=1 SING_EBPF_OVERHEAD=1 ./core.test -test.run TCLocalEgressOverhead -test.v
//
// Each scenario prints one "OVERHEAD" line with nanoseconds per program run.

import (
	"errors"
	"os"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type overheadScenario struct {
	name         string
	trackProcess bool
	// drive sends traffic through the attached program.
	drive func(t *testing.T)
}

func TestTCLocalEgressOverhead(t *testing.T) {
	requireEBPFIntegration(t, "measure the local egress program")
	if os.Getenv("SING_EBPF_OVERHEAD") != "1" {
		t.Skip("set SING_EBPF_OVERHEAD=1 to run the overhead harness")
	}
	const datagrams = 200000
	sendUDP := func(t *testing.T, uid uint32) {
		fd := ownedSocket(t, unix.SOCK_DGRAM, uid)
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: identityPeerUDPPort, Addr: [4]byte{10, 211, 0, 2}}); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, 64)
		for range datagrams {
			// ECONNREFUSED: bypassed datagrams reach the peer, which has no UDP
			// listener, and its port-unreachable error lands on the next write.
			if _, err := unix.Write(fd, payload); err != nil && !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.ECONNREFUSED) {
				t.Fatal(err)
			}
		}
	}
	// A bypassed TCP connection: after the first packet every packet takes
	// the verdict-cache hit path, which is the hot path for long-lived flows
	// the proxy does not handle.
	sendTCP := func(t *testing.T) {
		fd := startConnect(t, uidOther)
		if !connectedWithin(t, fd, 3*time.Second) {
			t.Fatal("bypassed TCP connection did not connect")
		}
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		if err := unix.SetNonblock(fd, false); err != nil {
			t.Fatal(err)
		}
		chunk := make([]byte, 1024)
		buffer := make([]byte, 65536)
		for range 20000 {
			if _, err := unix.Write(fd, chunk); err != nil {
				t.Fatal(err)
			}
			// Drain the echo without blocking so the window never closes.
			for {
				n, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
				if n <= 0 || err != nil {
					break
				}
			}
		}
	}
	scenarios := []overheadScenario{
		{name: "udp-selected-light", trackProcess: false, drive: func(t *testing.T) { sendUDP(t, uidIncluded) }},
		{name: "udp-selected-tracked", trackProcess: true, drive: func(t *testing.T) { sendUDP(t, uidIncluded) }},
		{name: "udp-bypassed-tracked", trackProcess: true, drive: func(t *testing.T) { sendUDP(t, uidOther) }},
		{name: "tcp-bypassed-cached-light", trackProcess: false, drive: sendTCP},
		{name: "tcp-bypassed-cached-tracked", trackProcess: true, drive: sendTCP},
	}
	statsFD, err := CiliumEBPF.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Fatalf("enable BPF run-time stats: %v", err)
	}
	defer statsFD.Close()
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			local, delivery := buildTestTopology(t)
			policy, err := CompileActionPolicy(ActionPolicy{
				EnableTCP: true,
				EnableUDP: true,
				Local:     ActionScope{Default: DecisionPass, UID: []UIDDecision{{Start: uidIncluded, End: uidIncluded, Action: DecisionIntercept}}},
				Shared:    ActionScope{Default: DecisionIntercept},
			})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := PrepareTC(TCConfig{
				ListenerPort: 65531, EnableLocal: true, EnableIPv4: true, EnableTCP: true, EnableUDP: true,
				Policy: policy, TrackProcess: scenario.trackProcess,
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
			program := backend.runtime.programs[tcProgramLocalEgressEthernet]
			before := programRunStats(t, program)
			scenario.drive(t)
			after := programRunStats(t, program)
			runs := after.count - before.count
			if runs == 0 {
				t.Fatal("the program did not run")
			}
			txLocal, txDelivery := linkTX(t, local), linkTX(t, delivery)
			t.Logf("OVERHEAD scenario=%s runs=%d ns_per_run=%.1f local_tx=%d delivery_tx=%d",
				scenario.name, runs, float64(after.runtime-before.runtime)/float64(runs), txLocal, txDelivery)
		})
	}
}

type programRun struct{ runtime, count uint64 }

func programRunStats(t *testing.T, program *CiliumEBPF.Program) programRun {
	t.Helper()
	stats, err := program.Stats()
	if err != nil {
		t.Fatal(err)
	}
	return programRun{runtime: uint64(stats.Runtime), count: stats.RunCount}
}

func linkTX(t *testing.T, device netlink.Link) uint64 {
	t.Helper()
	current, err := netlink.LinkByIndex(device.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	return current.Attrs().Statistics.TxPackets
}
