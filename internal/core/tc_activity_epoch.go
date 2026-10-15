//go:build with_ebpf && (linux || android)

package core

import "time"

// tcActivityEpochMinSpan is the shortest activity period. Sweeps closer
// together than this reuse the current period, which keeps the history below
// covering at least tcActivityEpochHistory * tcActivityEpochMinSpan.
const tcActivityEpochMinSpan = time.Second

// tcActivityEpochHistory is how many period start times are remembered. At one
// period per second at most, 256 entries cover over four minutes; the
// sing-box janitor's longest idle limit is two minutes.
const tcActivityEpochHistory = 256

type tcActivityEpochStart struct {
	epoch uint32
	start uint64
}

// tcActivityEpochs remembers when recent activity periods began, in
// CLOCK_MONOTONIC nanoseconds (the clock monotonicNowNS reads).
//
// The data path stamps the current period into every assignment it passes, at
// most once per period per entry. An entry stamped e therefore saw no packet
// after period e + 1 began, so it has been idle at least since start(e + 1).
// Entries stamped with the current period have no such bound and are never
// idle. Periods advance only from SweepAssignments, so the resolution of
// "idle since" is the sweep interval.
type tcActivityEpochs struct {
	starts [tcActivityEpochHistory]tcActivityEpochStart
	oldest uint64
}

func (e *tcActivityEpochs) begin(epoch uint32, now uint64) {
	e.starts[epoch%tcActivityEpochHistory] = tcActivityEpochStart{epoch: epoch, start: now}
	// At most once per tcActivityEpochMinSpan, so a full pass is cheap and
	// simpler than tracking the ring order.
	e.oldest = now
	for _, slot := range e.starts {
		if slot.epoch != 0 && slot.start < e.oldest {
			e.oldest = slot.start
		}
	}
}

// next returns the period to switch to, or false while the current one is
// younger than tcActivityEpochMinSpan. 0 is skipped: it marks unstamped entries.
func (e *tcActivityEpochs) next(current uint32, now uint64) (uint32, bool) {
	slot := e.starts[current%tcActivityEpochHistory]
	if slot.epoch == current && now-slot.start < uint64(tcActivityEpochMinSpan) {
		return current, false
	}
	next := current + 1
	if next == 0 {
		next = 1
	}
	return next, true
}

// idleSince reports whether an entry stamped with epoch has seen no packet
// since staleBefore. Unstamped entries (0) are never idle: nothing proves
// their age, and the LRU map remains their safety net, as upstream treats an
// entry without a timestamp.
func (e *tcActivityEpochs) idleSince(epoch uint32, staleBefore uint64) bool {
	if epoch == 0 {
		return false
	}
	following := epoch + 1
	if following == 0 {
		following = 1
	}
	slot := e.starts[following%tcActivityEpochHistory]
	if slot.epoch == following {
		return slot.start <= staleBefore
	}
	// The following period is not remembered. If the entry's own period is
	// still in the ring, the following one has not started: the entry is
	// current. Otherwise both fell out of the history, so the entry went idle
	// before the oldest remembered start.
	if own := e.starts[epoch%tcActivityEpochHistory]; own.epoch == epoch {
		return false
	}
	return e.oldest != 0 && e.oldest <= staleBefore
}
