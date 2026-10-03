//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"maps"
	"slices"
	"testing"
)

// fakeUIDPolicyMap behaves like the NO_PREALLOC LPM trie for what
// replaceUIDPolicyMap relies on: any insert into a full map fails,
// deleting a missing key is not an error (uidPolicyMap.delete maps ENOENT to
// nil). failAt fails the n-th write (1-based, 0 = never); after that, writes
// fail while failRollback is set, which is how a failed rollback is simulated.
type fakeUIDPolicyMap struct {
	t            *testing.T
	entries      map[uidLPMKey]struct{}
	capacity     int
	writes       int
	failAt       int
	failRollback bool
	failed       bool
	peak         int
	// observe runs after every successful write, with the map in its
	// intermediate state.
	observe func()
}

var errInjected = errors.New("injected map failure")

func newFakeUIDPolicyMap(t *testing.T, initial []uidLPMKey, capacity int) *fakeUIDPolicyMap {
	m := &fakeUIDPolicyMap{t: t, entries: map[uidLPMKey]struct{}{}, capacity: capacity}
	for _, key := range initial {
		m.entries[key] = struct{}{}
	}
	m.peak = len(m.entries)
	return m
}

func (m *fakeUIDPolicyMap) fail() bool {
	m.writes++
	if m.failed {
		return m.failRollback
	}
	if m.failAt != 0 && m.writes == m.failAt {
		m.failed = true
		return true
	}
	return false
}

func (m *fakeUIDPolicyMap) put(key uidLPMKey) error {
	if m.fail() {
		return errInjected
	}
	// Like trie_update_elem in kernel/bpf/lpm_trie.c (v6.12), which checks
	// n_entries == max_entries before looking for the key: a full trie refuses
	// even an in-place replacement.
	if len(m.entries) >= m.capacity {
		return errors.New("no space")
	}
	m.entries[key] = struct{}{}
	m.peak = max(m.peak, len(m.entries))
	if m.observe != nil {
		m.observe()
	}
	return nil
}

func (m *fakeUIDPolicyMap) delete(key uidLPMKey) error {
	if m.fail() {
		return errInjected
	}
	delete(m.entries, key)
	if m.observe != nil {
		m.observe()
	}
	return nil
}

func (m *fakeUIDPolicyMap) matches(uid uint32) bool {
	for key := range m.entries {
		interval := uidBlockInterval(key)
		if uint64(uid) >= interval.start && uint64(uid) <= interval.end {
			return true
		}
	}
	return false
}

func (m *fakeUIDPolicyMap) keys() []uidLPMKey {
	return slices.Collect(maps.Keys(m.entries))
}

func compileIntercepts(t *testing.T, ranges ...UIDRange) []uidLPMKey {
	t.Helper()
	decisions := make([]UIDDecision, 0, len(ranges))
	for _, r := range ranges {
		decisions = append(decisions, UIDDecision{Start: r.Start, End: r.End, Action: DecisionIntercept})
	}
	entries, defaultBypass, err := compileUIDActionPolicy(decisions, DecisionPass)
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass {
		t.Fatal("default pass must compile to default bypass")
	}
	return entries
}

func sameKeys(left, right []uidLPMKey) bool {
	a, b := slices.Clone(left), slices.Clone(right)
	less := func(x, y uidLPMKey) int {
		if x.PrefixLength != y.PrefixLength {
			return int(x.PrefixLength) - int(y.PrefixLength)
		}
		return slices.Compare(x.UID[:], y.UID[:])
	}
	slices.SortFunc(a, less)
	slices.SortFunc(b, less)
	return slices.Equal(a, b)
}

// sampleUIDs covers every UID the transition cases below touch, plus
// neighbours outside them.
func sampleUIDs() []uint32 {
	var uids []uint32
	for uid := uint32(9990); uid <= 10140; uid++ {
		uids = append(uids, uid)
	}
	return append(uids, 0, 1000, 1010001, 0xffffffff)
}

type uidTransitionCase struct {
	name          string
	current, next []UIDRange
}

func uidTransitionCases() []uidTransitionCase {
	return []uidTransitionCase{
		{"add to empty", nil, []UIDRange{{10050, 10050}}},
		{"remove to empty", []UIDRange{{10050, 10050}}, nil},
		{"add one", []UIDRange{{10001, 10001}}, []UIDRange{{10001, 10001}, {10050, 10050}}},
		{"remove one", []UIDRange{{10001, 10001}, {10050, 10050}}, []UIDRange{{10050, 10050}}},
		// 10000-10003 is one /30; dropping 10002 reshapes it into /31 + /32,
		// so 10000, 10001 and 10003 are matched before and after but by
		// different keys.
		{"reshape", []UIDRange{{10000, 10003}}, []UIDRange{{10000, 10001}, {10003, 10003}}},
		{"merge", []UIDRange{{10000, 10001}, {10002, 10003}, {10100, 10100}}, []UIDRange{{10000, 10003}}},
		{"package reinstalled with new UID", []UIDRange{{10001, 10001}, {10060, 10060}}, []UIDRange{{10060, 10060}, {10120, 10120}}},
		{"overlapping inputs", []UIDRange{{10000, 10010}, {10005, 10020}}, []UIDRange{{10008, 10030}, {10010, 10012}}},
	}
}

// TestReplaceUIDPolicyMapTransitions checks the end state and, after every
// single map write, the transition guarantee: each sample UID changes its
// match result at most once, and never leaves current∪next or drops out of
// current∩next.
func TestReplaceUIDPolicyMapTransitions(t *testing.T) {
	for _, testCase := range uidTransitionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			current := compileIntercepts(t, testCase.current...)
			next := compileIntercepts(t, testCase.next...)
			m := newFakeUIDPolicyMap(t, current, tcUIDPolicyCapacity)
			before := newFakeUIDPolicyMap(t, current, tcUIDPolicyCapacity)
			after := newFakeUIDPolicyMap(t, next, tcUIDPolicyCapacity)
			uids := sampleUIDs()
			last := make([]bool, len(uids))
			flips := make([]int, len(uids))
			for index, uid := range uids {
				last[index] = m.matches(uid)
			}
			m.observe = func() {
				for index, uid := range uids {
					matched := m.matches(uid)
					inOld, inNew := before.matches(uid), after.matches(uid)
					if inOld && inNew && !matched {
						t.Fatalf("UID %d matched before and after the update lost its match mid-way", uid)
					}
					if !inOld && !inNew && matched {
						t.Fatalf("UID %d matched by neither policy matched mid-way", uid)
					}
					if matched != last[index] {
						flips[index]++
						last[index] = matched
					}
				}
			}
			if err := replaceUIDPolicyMap(m, current, next, tcUIDPolicyCapacity); err != nil {
				t.Fatal(err)
			}
			if !sameKeys(m.keys(), next) {
				t.Fatalf("map = %v, want %v", m.keys(), next)
			}
			for index, uid := range uids {
				if flips[index] > 1 {
					t.Fatalf("UID %d changed its match result %d times", uid, flips[index])
				}
			}
		})
	}
}

// TestReplaceUIDPolicyMapRollsBackEveryFailure fails each write of each
// transition in turn and checks that the map is back to exactly the current
// policy, reported as an ordinary (not rollback) failure.
func TestReplaceUIDPolicyMapRollsBackEveryFailure(t *testing.T) {
	for _, testCase := range uidTransitionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			current := compileIntercepts(t, testCase.current...)
			next := compileIntercepts(t, testCase.next...)
			probe := newFakeUIDPolicyMap(t, current, tcUIDPolicyCapacity)
			if err := replaceUIDPolicyMap(probe, current, next, tcUIDPolicyCapacity); err != nil {
				t.Fatal(err)
			}
			for failAt := 1; failAt <= probe.writes; failAt++ {
				m := newFakeUIDPolicyMap(t, current, tcUIDPolicyCapacity)
				m.failAt = failAt
				err := replaceUIDPolicyMap(m, current, next, tcUIDPolicyCapacity)
				if !errors.Is(err, errInjected) {
					t.Fatalf("write %d: err = %v, want the injected failure", failAt, err)
				}
				if policyRollbackFailed(err) {
					t.Fatalf("write %d: a clean rollback was reported as failed: %v", failAt, err)
				}
				if !sameKeys(m.keys(), current) {
					t.Fatalf("write %d: map = %v after rollback, want %v", failAt, m.keys(), current)
				}
			}
		})
	}
}

func TestReplaceUIDPolicyMapReportsFailedRollback(t *testing.T) {
	current := compileIntercepts(t, UIDRange{10001, 10001})
	next := compileIntercepts(t, UIDRange{10050, 10050}, UIDRange{10060, 10060})
	m := newFakeUIDPolicyMap(t, current, tcUIDPolicyCapacity)
	// Write 1 removes 10001 (leaving), write 2 adds the first new key and
	// fails; undoing write 1 then fails as well.
	m.failAt = 2
	m.failRollback = true
	err := replaceUIDPolicyMap(m, current, next, tcUIDPolicyCapacity)
	if !policyRollbackFailed(err) {
		t.Fatalf("err = %v, want a rollback failure", err)
	}
}

// TestReplaceUIDPolicyMapCapacity: a policy at the compile limit can replace
// another one at the limit. With every block reshaped, adding first would need
// twice the capacity, so the reshaped removals have to go first.
func TestReplaceUIDPolicyMapCapacity(t *testing.T) {
	const blocks = tcUIDPolicyCapacity
	// Old: a /32 every four UIDs. New: a /31 at each of the same places. Every
	// old block is reshaped, the blocks never merge, and both sides are at the
	// capacity.
	var evens, pairs []UIDRange
	for index := uint32(0); index < blocks; index++ {
		evens = append(evens, UIDRange{Start: 20000 + 4*index, End: 20000 + 4*index})
		pairs = append(pairs, UIDRange{Start: 20000 + 4*index, End: 20001 + 4*index})
	}
	current := compileIntercepts(t, evens...)
	next := compileIntercepts(t, pairs...)
	if len(current) != blocks || len(next) != blocks {
		t.Fatalf("unexpected fixture sizes %d %d", len(current), len(next))
	}
	m := newFakeUIDPolicyMap(t, current, tcUIDPolicyCapacity)
	if err := replaceUIDPolicyMap(m, current, next, tcUIDPolicyCapacity); err != nil {
		t.Fatal(err)
	}
	if !sameKeys(m.keys(), next) {
		t.Fatal("map does not hold the next policy")
	}
	if m.peak > tcUIDPolicyCapacity {
		t.Fatalf("peak %d exceeded capacity %d", m.peak, tcUIDPolicyCapacity)
	}

	// One entry more than the compile limit is refused before any write.
	over := append(slices.Clone(evens), UIDRange{Start: 20000 + 4*blocks, End: 20000 + 4*blocks})
	decisions := make([]UIDDecision, 0, len(over))
	for _, r := range over {
		decisions = append(decisions, UIDDecision{Start: r.Start, End: r.End, Action: DecisionIntercept})
	}
	if _, _, err := compileUIDActionPolicy(decisions, DecisionPass); err == nil {
		t.Fatal("a policy over the map capacity compiled")
	}
}

// TestCompileUIDActionPolicyOverlap pins the overlap rule UpdateUIDPolicy
// inherits from startup compilation: where decisions disagree, the one that
// differs from the default wins. Callers subtract exclusions themselves.
func TestCompileUIDActionPolicyOverlap(t *testing.T) {
	entries, defaultBypass, err := compileUIDActionPolicy([]UIDDecision{
		{Start: 10000, End: 10003, Action: DecisionIntercept},
		{Start: 10002, End: 10002, Action: DecisionPass},
	}, DecisionPass)
	if err != nil {
		t.Fatal(err)
	}
	m := newFakeUIDPolicyMap(t, entries, tcUIDPolicyCapacity)
	if !defaultBypass || !m.matches(10002) {
		t.Fatalf("overlap rule changed: entries %v", entries)
	}
	// An empty include set compiles to no entries with default bypass: the
	// policy stays on and bypasses every UID (see UpdateUIDPolicy's flags).
	entries, defaultBypass, err = compileUIDActionPolicy(nil, DecisionPass)
	if err != nil || len(entries) != 0 || !defaultBypass {
		t.Fatalf("empty include set: %v %v %v", entries, defaultBypass, err)
	}
}

func TestUIDIntervalsOverlap(t *testing.T) {
	intervals := uidBlockIntervals(compileIntercepts(t, UIDRange{10, 13}, UIDRange{20, 20}))
	for _, testCase := range []struct {
		interval uidInterval
		want     bool
	}{
		{uidInterval{0, 9}, false},
		{uidInterval{9, 10}, true},
		{uidInterval{13, 19}, true},
		{uidInterval{14, 19}, false},
		{uidInterval{20, 20}, true},
		{uidInterval{21, 1 << 32}, false},
	} {
		if got := intervals.overlaps(testCase.interval); got != testCase.want {
			t.Fatalf("overlaps(%v) = %v, want %v", testCase.interval, got, testCase.want)
		}
	}
}
