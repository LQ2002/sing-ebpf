//go:build with_ebpf && (linux || android)

package core

import (
	"testing"
	"time"
)

func TestTCActivityEpochsIdleSince(t *testing.T) {
	var epochs tcActivityEpochs
	second := uint64(time.Second)
	base := 1000 * second
	epochs.begin(1, base)
	if epoch, advance := epochs.next(1, base+second/2); advance || epoch != 1 {
		t.Fatalf("advanced within the minimum span: %d %v", epoch, advance)
	}
	if epoch, advance := epochs.next(1, base+second); !advance || epoch != 2 {
		t.Fatalf("did not advance after the minimum span: %d %v", epoch, advance)
	}
	epochs.begin(2, base+60*second)
	epochs.begin(3, base+120*second)
	now := base + 125*second
	// Stamped in period 1: idle since period 2 began (base+60s).
	if !epochs.idleSince(1, now-60*second) {
		t.Fatal("period 1 entry should be idle for 60s")
	}
	if epochs.idleSince(1, now-70*second) {
		t.Fatal("period 1 entry cannot be proven idle for 70s")
	}
	// Stamped in period 2: idle since base+120s, i.e. 5s.
	if !epochs.idleSince(2, now-5*second) || epochs.idleSince(2, now-15*second) {
		t.Fatal("period 2 entry idle bound is wrong")
	}
	// The current period and unstamped entries are never idle.
	if epochs.idleSince(3, now) || epochs.idleSince(0, now) {
		t.Fatal("current or unstamped entry reported idle")
	}
}

func TestTCActivityEpochsForgottenPeriods(t *testing.T) {
	var epochs tcActivityEpochs
	second := uint64(time.Second)
	for epoch := uint32(1); epoch <= tcActivityEpochHistory+10; epoch++ {
		epochs.begin(epoch, uint64(epoch)*second)
	}
	// Periods 1..11 and their successors fell out of the ring. The oldest
	// remembered start is period 11's successor... i.e. epoch 11 at 11s.
	if epochs.oldest != 11*second {
		t.Fatalf("oldest = %d, want %d", epochs.oldest, 11*second)
	}
	if !epochs.idleSince(3, 11*second) || epochs.idleSince(3, 10*second) {
		t.Fatal("forgotten period idle bound is wrong")
	}
	// The newest period is current even though its successor slot is reused.
	if epochs.idleSince(tcActivityEpochHistory+10, 1<<60) {
		t.Fatal("current period reported idle")
	}
}

func TestTCActivityEpochSkipsZero(t *testing.T) {
	var epochs tcActivityEpochs
	epochs.begin(^uint32(0), 1)
	if epoch, advance := epochs.next(^uint32(0), uint64(2*time.Second)); !advance || epoch != 1 {
		t.Fatalf("wrap produced %d %v", epoch, advance)
	}
}
