//go:build with_ebpf && (linux || android)

package core

import (
	"encoding/binary"
	"errors"
	"slices"
	"sort"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	tcFlagUIDPolicy        uint32 = 1 << 4
	tcFlagUIDDefaultBypass uint32 = 1 << 5
)

// UpdateUIDPolicy replaces the local path's UID policy on a running backend.
// decisions and defaultAction mean exactly what they mean in ActionScope at
// startup, and are compiled by the same function, so an update equal to the
// startup policy is reported as unchanged. Where decisions overlap with
// different actions, the action that differs from defaultAction wins (also as
// at startup); callers that want exclusions inside an included range must
// subtract them before calling.
//
// It reports whether anything was written. An error leaves the previous
// policy in force; if restoring it fails too, the backend is marked as
// requiring a rebuild, as the other policy updates do.
//
// This is not one atomic switch. The map changes one entry at a time (the LPM
// trie guarantees single-element replacement, nothing more), so packets that
// arrive during the update can see a mix of the two policies, ordered so that
// every UID moves from its old action to its new one at most once -- see
// replaceUIDPolicyMap. Only a change of the default action has an intermediate
// state, and that state is "intercept everything", never "bypass everything".
// Established TCP connections are not torn down; their cached verdict is
// recomputed on their next packet, because the final control write advances
// the policy generation.
func (b *TCBackend) UpdateUIDPolicy(decisions []UIDDecision, defaultAction Decision) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	// Compiling enforces maxUIDPolicyEntries, which is also the map's
	// capacity, so an oversized policy is refused before any map write.
	entries, defaultBypass, err := compileUIDActionPolicy(decisions, defaultAction)
	if err != nil {
		return false, err
	}
	if err = checkLPMTriePolicyCompatibility("TC eBPF UID", len(entries)); err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.requireUsableLocked(); err != nil {
		return false, err
	}
	if slices.Equal(b.uidEntries, entries) && b.uidDefaultBypass == defaultBypass {
		return false, nil
	}
	uidMap := b.runtime.maps["tc_uid_policy"]
	previousEntries, previousFlags := b.uidEntries, b.control.Flags
	nextFlags := previousFlags &^ (tcFlagUIDPolicy | tcFlagUIDDefaultBypass)
	// The same rule tcFlags applies at startup. An include set that resolves to
	// nothing (no entries, default pass) keeps the policy on with every UID
	// bypassed; it does not turn the policy off, which would intercept all.
	if len(entries) > 0 || defaultBypass {
		nextFlags |= tcFlagUIDPolicy
	}
	if defaultBypass {
		nextFlags |= tcFlagUIDDefaultBypass
	}

	// A changed default action reverses what membership in the map means, so
	// no order of entry writes keeps per-UID transitions monotonic. Switch the
	// policy off first: with the flag clear the classifier skips the map and
	// intercepts, so the window fails toward the proxy rather than leaking.
	if b.uidDefaultBypass != defaultBypass && previousFlags&tcFlagUIDPolicy != 0 {
		b.control.Flags = previousFlags &^ (tcFlagUIDPolicy | tcFlagUIDDefaultBypass)
		if err = b.updateControlLocked(); err != nil {
			b.control.Flags = previousFlags
			return false, err
		}
	}
	if err = replaceUIDPolicyMap(uidPolicyMap{uidMap}, previousEntries, entries, tcUIDPolicyCapacity); err != nil {
		if policyRollbackFailed(err) {
			return false, b.invalidateLocked("UID policy", err)
		}
		return false, b.restoreControlAfterRollbackLocked("UID policy", previousFlags, err)
	}
	b.control.Flags = nextFlags
	if err = b.updateControlLocked(); err != nil {
		if restoreErr := replaceUIDPolicyMap(uidPolicyMap{uidMap}, entries, previousEntries, tcUIDPolicyCapacity); restoreErr != nil {
			return false, b.invalidateLocked("UID policy", policyUpdateError(err, restoreErr))
		}
		return false, b.restoreControlAfterRollbackLocked("UID policy", previousFlags, err)
	}
	b.uidEntries = slices.Clone(entries)
	b.uidDefaultBypass = defaultBypass
	return true, nil
}

// restoreControlAfterRollbackLocked is called once the policy maps are back to
// what previousFlags describes. Writing the control again is not redundant even
// when the flags never reached the kernel: it advances the policy generation,
// which discards TCP verdicts cached while the maps held the half-applied
// update. If that write fails there is no way left to invalidate them, so the
// backend is marked unusable rather than reported as merely unchanged.
func (b *TCBackend) restoreControlAfterRollbackLocked(operation string, previousFlags uint32, cause error) error {
	b.control.Flags = previousFlags
	if err := b.updateControlLocked(); err != nil {
		return b.invalidateLocked(operation, policyUpdateError(cause, E.Cause(err, "invalidate verdicts cached during the failed update")))
	}
	return cause
}

// uidPolicyWriter is the slice of map access replaceUIDPolicyMap needs; tests
// substitute one that fails or runs out of room on demand.
type uidPolicyWriter interface {
	put(key uidLPMKey) error
	delete(key uidLPMKey) error
}

type uidPolicyMap struct{ m *CiliumEBPF.Map }

func (w uidPolicyMap) put(key uidLPMKey) error {
	if w.m == nil {
		return errBackendClosed
	}
	value := uint8(1)
	return w.m.Update(&key, &value, CiliumEBPF.UpdateAny)
}

func (w uidPolicyMap) delete(key uidLPMKey) error {
	if w.m == nil {
		return errBackendClosed
	}
	err := w.m.Delete(&key)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return nil
	}
	return err
}

// replaceUIDPolicyMap moves the map from current to next, both as produced by
// compileUIDActionPolicy (sorted, duplicate-free, each a CIDR block of UIDs).
//
// The order keeps the set of matched UIDs between current∩next and
// current∪next at every instant, i.e. each UID changes its match result at
// most once:
//
//  1. remove blocks none of whose UIDs are matched by next ("leaving");
//  2. add next's new blocks;
//  3. remove the rest -- blocks whose UIDs stay matched but are now covered by
//     differently shaped blocks, which were added in step 2.
//
// Removing a reshaped block before its replacement exists would drop UIDs
// that are matched both before and after. The cost of adding first is
// transient capacity: the map peaks at len(current)-leaving+additions. When
// that exceeds capacity, the reshaped removals move ahead of the additions,
// and UIDs in reshaped blocks can briefly fall back to the default action.
//
// Capacity is counted the way the kernel counts it: trie_update_elem
// (kernel/bpf/lpm_trie.c, v6.12) refuses any update once n_entries reaches
// max_entries -- checked before it looks for the key, so even rewriting an
// existing key fails on a full trie -- and intermediate nodes are not counted.
// This function only ever puts keys that are absent, and counts only real
// entries, so the peak computed above is exactly what the kernel checks.
//
// On failure the completed steps are undone in reverse. If undoing fails too,
// the error is a policyRollbackError and the map matches neither policy.
func replaceUIDPolicyMap(writer uidPolicyWriter, current, next []uidLPMKey, capacity int) error {
	currentSet := make(map[uidLPMKey]struct{}, len(current))
	for _, key := range current {
		currentSet[key] = struct{}{}
	}
	nextSet := make(map[uidLPMKey]struct{}, len(next))
	var additions []uidLPMKey
	for _, key := range next {
		nextSet[key] = struct{}{}
		if _, loaded := currentSet[key]; !loaded {
			additions = append(additions, key)
		}
	}
	nextCoverage := uidBlockIntervals(next)
	var leaving, reshaped []uidLPMKey
	for _, key := range current {
		if _, loaded := nextSet[key]; loaded {
			continue
		}
		if nextCoverage.overlaps(uidBlockInterval(key)) {
			reshaped = append(reshaped, key)
		} else {
			leaving = append(leaving, key)
		}
	}
	steps := []uidPolicyStep{{true, leaving}, {false, additions}, {true, reshaped}}
	if len(current)-len(leaving)+len(additions) > capacity {
		steps = []uidPolicyStep{{true, leaving}, {true, reshaped}, {false, additions}}
	}
	var done []uidPolicyStep
	for _, step := range steps {
		for index, key := range step.keys {
			if err := step.apply(writer, key); err != nil {
				done = append(done, uidPolicyStep{step.remove, step.keys[:index]})
				return policyUpdateError(E.Cause(err, "update TC eBPF UID policy map"), undoUIDPolicySteps(writer, done))
			}
		}
		done = append(done, step)
	}
	return nil
}

type uidPolicyStep struct {
	remove bool
	keys   []uidLPMKey
}

func (s uidPolicyStep) apply(writer uidPolicyWriter, key uidLPMKey) error {
	if s.remove {
		return writer.delete(key)
	}
	return writer.put(key)
}

// undoUIDPolicySteps reverses completed steps, newest first, and keeps going
// past individual failures so as much as possible is restored.
func undoUIDPolicySteps(writer uidPolicyWriter, done []uidPolicyStep) error {
	var rollbackErr error
	for index := len(done) - 1; index >= 0; index-- {
		inverse := uidPolicyStep{remove: !done[index].remove}
		for _, key := range done[index].keys {
			rollbackErr = E.Errors(rollbackErr, inverse.apply(writer, key))
		}
	}
	if rollbackErr != nil {
		return E.Cause(rollbackErr, "rollback TC eBPF UID policy map")
	}
	return nil
}

type uidInterval struct{ start, end uint64 }

type uidIntervals []uidInterval

func uidBlockInterval(key uidLPMKey) uidInterval {
	start := uint64(binary.BigEndian.Uint32(key.UID[:]))
	size := uint64(1) << (32 - key.PrefixLength)
	return uidInterval{start: start, end: start + size - 1}
}

// uidBlockIntervals returns the blocks as intervals sorted by start. Blocks
// produced by compileUIDRanges never overlap each other.
func uidBlockIntervals(keys []uidLPMKey) uidIntervals {
	intervals := make(uidIntervals, 0, len(keys))
	for _, key := range keys {
		intervals = append(intervals, uidBlockInterval(key))
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start < intervals[j].start })
	return intervals
}

func (intervals uidIntervals) overlaps(target uidInterval) bool {
	// The first interval ending at or after target.start is the only candidate:
	// the intervals are disjoint and sorted, so their ends are sorted too.
	index := sort.Search(len(intervals), func(i int) bool { return intervals[i].end >= target.start })
	return index < len(intervals) && intervals[index].start <= target.end
}
