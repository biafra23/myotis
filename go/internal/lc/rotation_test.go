package lc

import (
	"path/filepath"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
)

// TestCatchUpForceRotationThenACrossingUpdateRotatesOnce is the Go twin of
// the Rust catch_up_force_rotation_then_a_crossing_update_rotates_once
// (#737): catch-up with a wall clock ahead of the store. After the
// force-rotation into 1778, the 002 update, whose finalized header enters
// 1778, must not rotate the store again.
func TestCatchUpForceRotationThenACrossingUpdateRotatesOnce(t *testing.T) {
	s := freshStore(t)
	if err := s.ProcessUpdate(corpusUpdate001(t)); err != nil {
		t.Fatalf("001-update: %v", err)
	}
	if s.StorePeriod != 1777 || s.NextCommittee == nil {
		t.Fatalf("after 001: period %d, next held %v", s.StorePeriod, s.NextCommittee != nil)
	}
	s.ForceRotateIfPastPeriod(14_704_714)
	if s.StorePeriod != 1778 {
		t.Fatalf("force-rotation: period %d, want 1778", s.StorePeriod)
	}
	rotatedInto := s.CurrentCommittee

	dir := filepath.Join("..", "..", "..", "rust", "testdata", "lc", "mainnet")
	second, err := DecodeUpdate(readCorpus(t, filepath.Join(dir, "002-update.ssz")))
	if err != nil {
		t.Fatalf("decode 002-update: %v", err)
	}
	if p := chain.SyncCommitteePeriod(second.Finalized.Beacon.Slot); p != 1778 {
		t.Fatalf("002 finalized period %d, want 1778", p)
	}
	if err := s.ProcessUpdate(second); err != nil {
		t.Fatalf("002-update: %v", err)
	}
	if s.StorePeriod != 1778 {
		t.Fatalf("rotated twice into one period: store period %d", s.StorePeriod)
	}
	if p := chain.SyncCommitteePeriod(s.Finalized.Slot); p != s.StorePeriod {
		t.Fatalf("store period %d, finalized header's %d", s.StorePeriod, p)
	}
	if s.CurrentCommittee != rotatedInto {
		t.Fatal("the current committee changed after the force-rotation")
	}
	if s.NextCommittee == nil {
		t.Fatal("the P+2 committee 002 carries is not held as next")
	}
}
