//go:build with_ebpf && linux && ebpf_integration

package core

// Device acceptance: the identity recorded in tc_assignment against a real
// Android app's ground truth. Skipped unless SBO_APP_TRUTH=1; it is driven by
// a script that supplies the package, its UID (from `pm list packages -U`) and
// the routing table app traffic uses on the current default network.
//
// It works in the main network namespace but never touches an existing
// interface: it adds a test veth (idta, peer idtb moved into a private
// namespace), a dummy delivery target, and a single /32 route for an unused
// address into the default network's table, so only traffic to that address
// is affected. The program sees the app's real SYN, records the identity and
// redirects the packet to the dummy, where it is dropped (the app just fails to
// load the page). Everything is removed at cleanup.
//
// Truth checked per recorded flow: SocketUID equals the package UID; the
// cgroup id resolves (by inode under /sys/fs/cgroup) to apps/uid_<UID>/pid_<P>;
// process P runs with that UID and its cmdline names the package.

import (
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestAndroidAppSocketIdentityTruth(t *testing.T) {
	requireEBPFIntegration(t, "check recorded identity against a real app")
	if os.Getenv("SBO_APP_TRUTH") != "1" {
		t.Skip("set SBO_APP_TRUTH=1, SBO_APP_PACKAGE, SBO_APP_UID and SBO_ROUTE_TABLE")
	}
	packageName := os.Getenv("SBO_APP_PACKAGE")
	appUID64, err := strconv.ParseUint(os.Getenv("SBO_APP_UID"), 10, 32)
	if err != nil || packageName == "" {
		t.Fatal("SBO_APP_PACKAGE and SBO_APP_UID are required")
	}
	appUID := uint32(appUID64)
	table, err := strconv.Atoi(os.Getenv("SBO_ROUTE_TABLE"))
	if err != nil {
		t.Fatal("SBO_ROUTE_TABLE must be the numeric table of the default network")
	}

	// Test links in the main namespace, created on this thread.
	if err = netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "idta"}, PeerName: "idtb"}); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	t.Cleanup(func() {
		if device, err := netlink.LinkByName("idta"); err == nil {
			_ = netlink.LinkDel(device)
		}
	})
	local, err := netlink.LinkByName("idta")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("idtb")
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
	if err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "idtd"}}); err != nil {
		t.Fatalf("create dummy: %v", err)
	}
	t.Cleanup(func() {
		if device, err := netlink.LinkByName("idtd"); err == nil {
			_ = netlink.LinkDel(device)
		}
	})
	delivery, err := netlink.LinkByName("idtd")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(delivery); err != nil {
		t.Fatal(err)
	}
	startPeerNamespace(t, peer)

	_, destination, _ := net.ParseCIDR(identityPeerAddress + "/32")
	route := netlink.Route{LinkIndex: local.Attrs().Index, Dst: destination, Table: table}
	if err = netlink.RouteAdd(&route); err != nil {
		t.Fatalf("route %s via idta in table %d: %v", destination, table, err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(&route) })

	policy, err := CompileActionPolicy(ActionPolicy{
		EnableTCP: true,
		EnableUDP: true,
		Local:     ActionScope{Default: DecisionPass, UID: []UIDDecision{{Start: appUID, End: appUID, Action: DecisionIntercept}}},
		Shared:    ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65531, EnableLocal: true, EnableIPv4: true, EnableTCP: true, EnableUDP: true,
		Policy: policy, RecordSocketIdentity: true,
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
	statsFD, err := CiliumEBPF.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Fatalf("enable BPF run-time stats: %v", err)
	}
	defer statsFD.Close()
	program := backend.runtime.programs[tcProgramLocalEgressEthernet]
	runsBefore := programRunStats(t, program)

	url := "http://" + identityPeerAddress + ":" + strconv.Itoa(identityPeerTCPPort) + "/sbo-identity-truth"
	output, err := exec.Command("am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", url, "-p", packageName).CombinedOutput()
	t.Logf("am start: %v %s", err, strings.TrimSpace(string(output)))

	deadline := time.Now().Add(20 * time.Second)
	var found []TCAssignment
	for len(found) == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		var key tcAssignKey
		var value TCAssignment
		iterator := backend.runtime.maps["tc_assignment"].Iterate()
		for iterator.Next(&key, &value) {
			if key.DestinationPort == identityPeerTCPPort && [4]byte(key.DestinationAddress[:4]) == [4]byte{10, 211, 0, 2} {
				found = append(found, value)
			}
		}
	}
	runsAfter := programRunStats(t, program)
	t.Logf("local egress program runs during the test: %d", runsAfter.count-runsBefore.count)
	if len(found) == 0 {
		// /proc/net/tcp shows each socket's owner uid; 0200D30A is 10.211.0.2.
		tcp, _ := os.ReadFile("/proc/net/tcp")
		for _, line := range strings.Split(string(tcp), "\n") {
			if strings.Contains(line, ":0200D30A") || strings.Contains(line, "0200D30A:") {
				t.Logf("proc tcp: %s", strings.TrimSpace(line))
			}
		}
		dumpNetworkState(t)
		var key tcAssignKey
		var value TCAssignment
		iterator := backend.runtime.maps["tc_assignment"].Iterate()
		for iterator.Next(&key, &value) {
			t.Logf("assignment %+v -> %+v", key, value)
		}
		routeGet, _ := exec.Command("ip", "route", "get", identityPeerAddress, "uid", strconv.FormatUint(uint64(appUID), 10)).CombinedOutput()
		t.Logf("ip route get as app uid: %s", routeGet)
		t.Fatal("the app's connection was never recorded")
	}
	cgroupPaths := cgroupPathsByID(t)
	pathPattern := regexp.MustCompile(`/uid_(\d+)/pid_(\d+)$`)
	for _, assignment := range found {
		if !assignment.HasSocketIdentity() {
			t.Fatalf("recorded flow has no identity: %+v", assignment)
		}
		path := cgroupPaths[assignment.SocketCgroupID]
		match := pathPattern.FindStringSubmatch(path)
		if match == nil {
			t.Fatalf("cgroup id %d resolves to %q, not an app process cgroup", assignment.SocketCgroupID, path)
		}
		pid := match[2]
		status, _ := os.ReadFile("/proc/" + pid + "/status")
		cmdline, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		processUID := ""
		for _, line := range strings.Split(string(status), "\n") {
			if fields := strings.Fields(line); len(fields) > 1 && fields[0] == "Uid:" {
				processUID = fields[1]
			}
		}
		name := strings.TrimRight(strings.ReplaceAll(string(cmdline), "\x00", " "), " ")
		t.Logf("TRUTH cookie=%d socket_uid=%d cgroup_id=%d cgroup=%s pid=%s process_uid=%s cmdline=%q package_uid=%d",
			assignment.SocketCookie, assignment.SocketUID, assignment.SocketCgroupID, path, pid, processUID, name, appUID)
		if assignment.SocketUID != appUID || match[1] != strconv.FormatUint(uint64(appUID), 10) || processUID != match[1] {
			t.Fatalf("identity disagrees with the app's truth")
		}
		if !strings.HasPrefix(name, packageName) {
			t.Fatalf("process %s (%q) is not %s", pid, name, packageName)
		}
	}
}

// cgroupPathsByID maps cgroup v2 ids (inode numbers, see cgroupID) to paths.
func cgroupPathsByID(t *testing.T) map[uint64]string {
	t.Helper()
	paths := map[uint64]string{}
	_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		var stat unix.Stat_t
		if unix.Stat(path, &stat) == nil {
			paths[stat.Ino] = path
		}
		return nil
	})
	return paths
}
