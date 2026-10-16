//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"net"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// installLeftoverTCPolicyRouting leaves behind what a killed runtime leaves:
// its rule and its table's loopback routes.
func installLeftoverTCPolicyRouting(t *testing.T, loopbackIndex int, family int, mark uint32, table, priority int) {
	t.Helper()
	for _, route := range tcPolicyRoutesForTable(loopbackIndex, family, table) {
		if err := netlink.RouteAdd(&route); err != nil {
			t.Fatalf("add leftover route %v: %v", route.Dst, err)
		}
	}
	if err := netlink.RuleAdd(tcPolicyRuleFor(family, mark, table, priority)); err != nil {
		t.Fatalf("add leftover rule: %v", err)
	}
}

func tcTestRulePriorities(t *testing.T, family int) map[int]bool {
	t.Helper()
	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	priorities := make(map[int]bool)
	for _, rule := range rules {
		priorities[rule.Priority] = true
	}
	return priorities
}

// TestTCPolicyRoutingReclaimsLeftoversOfDeadRuntimes reproduces the
// 2026-10-17 phone state: two killed runtimes' rule sets (the first and the
// second identifiers the allocator hands out) plus a foreign rule of the same
// form whose table holds someone else's route. Startup must reclaim exactly
// the two leftovers, get the first identifiers again, and leave the foreign
// rule alone.
func TestTCPolicyRoutingReclaimsLeftoversOfDeadRuntimes(t *testing.T) {
	enterTestNetworkNamespace(t)
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	index := loopback.Attrs().Index
	families := []int{unix.AF_INET, unix.AF_INET6}
	for _, family := range families {
		installLeftoverTCPolicyRouting(t, index, family, 1<<30, tcPolicyRoutingTable, tcPolicyRoutingPriority)
		installLeftoverTCPolicyRouting(t, index, family, 1<<29, tcPolicyRoutingTable+1, tcPolicyRoutingPriority+1)
	}
	foreignTable := tcPolicyRoutingTable + 2
	foreignPriority := tcPolicyRoutingPriority + 2
	foreignRoute := netlink.Route{
		LinkIndex: index,
		Family:    unix.AF_INET,
		Dst:       &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		Scope:     netlink.Scope(unix.RT_SCOPE_LINK),
		Table:     foreignTable,
		Type:      unix.RTN_UNICAST,
	}
	if err = netlink.RouteAdd(&foreignRoute); err != nil {
		t.Fatalf("add foreign route: %v", err)
	}
	if err = netlink.RuleAdd(tcPolicyRuleFor(unix.AF_INET, 1<<28, foreignTable, foreignPriority)); err != nil {
		t.Fatalf("add foreign rule: %v", err)
	}

	routing, err := startTCPolicyRouting(true)
	if err != nil {
		t.Fatalf("start with leftovers: %v", err)
	}
	if routing.reclaimed != 4 {
		t.Fatalf("reclaimed %d leftover rule sets, want 4 (2 runtimes x 2 families)", routing.reclaimed)
	}
	if routing.mark != 1<<30 || routing.table != tcPolicyRoutingTable || routing.priority != tcPolicyRoutingPriority {
		t.Fatalf("got identifiers mark=%#x table=%d priority=%d, want the first set again", routing.mark, routing.table, routing.priority)
	}
	priorities := tcTestRulePriorities(t, unix.AF_INET)
	if priorities[tcPolicyRoutingPriority+1] {
		t.Fatal("the second leftover rule survived")
	}
	if !priorities[foreignPriority] {
		t.Fatal("the foreign rule was removed")
	}
	if routes, _ := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: tcPolicyRoutingTable + 1}, netlink.RT_FILTER_TABLE); len(routes) != 0 {
		t.Fatalf("the second leftover table kept %d routes", len(routes))
	}

	if err = routing.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	priorities = tcTestRulePriorities(t, unix.AF_INET)
	if priorities[tcPolicyRoutingPriority] || !priorities[foreignPriority] {
		t.Fatalf("after close: own rule present=%v foreign present=%v", priorities[tcPolicyRoutingPriority], priorities[foreignPriority])
	}
}
