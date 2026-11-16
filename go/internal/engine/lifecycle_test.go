package engine

// Lifecycle regression tests (PR #827 review): the sync.Once reset in
// StartNetwork used to be a PROCESS-FATAL `unlock of unlocked mutex`
// on any discovery.Start failure (UDP bind, nodedb lock), and nothing
// in the suite took the failure path — so nothing caught it. These
// pin the failure path itself.

import (
	"errors"
	"fmt"
	"github.com/biafra23/myotis/go/internal/clsync"
	"net"
	"testing"
)

func TestStartNetworkBusyPortRetries(t *testing.T) {
	// Occupy a UDP port, point the engine at it, and expect an ERROR
	// (not a fatal, not a panic) — twice, because the whole point of
	// the mutex rewrite is that a failed attempt leaves retryable
	// state; then success once the port frees.
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := sock.LocalAddr().(*net.UDPAddr).Port
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: port})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := range 2 {
		if err := e.StartNetwork(); err == nil {
			sock.Close()
			t.Fatalf("StartNetwork #%d onto busy :%d returned nil, want a bind error", i+1, port)
		}
	}
	if err := sock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.StartNetwork(); err != nil {
		t.Fatalf("StartNetwork after freeing the port: %v", err)
	}
	if e.networkService() == nil {
		t.Fatal("successful StartNetwork must publish the service through networkService()")
	}
}

func TestStartNetworkAfterCloseRefused(t *testing.T) {
	// StartNetwork behind Close would start a discovery service
	// nothing ever closes (StartLC guards the same case).
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if err := e.StartNetwork(); err == nil {
		t.Fatal("StartNetwork after Close must error, not leak a service")
	}
}

func TestSetStaleAnchorPolicyWithdrawalMirrorsRust(t *testing.T) {
	// The ABI-59 remembered-answer semantics (PR #877 review), tested at
	// the layer that owns them: CONTINUE arms the same sticky consent the
	// one-shot accept uses (read by the syncer at every weak-subjectivity
	// gate), and REPLACING a CONTINUE with ASK withdraws it — exactly
	// host.rs's `set_stale_anchor_policy`, so a Settings flip from
	// "continue anyway" back to "ask me" makes a later park ask instead of
	// silently continuing on a consent the user revoked.
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.StaleAccepted() {
		t.Fatal("fresh engine must not have the consent armed")
	}
	if !e.SetStaleAnchorPolicy(2) { // CONTINUE
		t.Fatal("CONTINUE (2) must apply")
	}
	if !e.StaleAccepted() {
		t.Fatal("CONTINUE must arm the consent the gates read")
	}
	if !e.SetStaleAnchorPolicy(0) { // ASK
		t.Fatal("ASK (0) must apply")
	}
	if e.StaleAccepted() {
		t.Error("replacing CONTINUE with ASK must withdraw the consent CONTINUE armed")
	}
	// CHECKPOINT (1) is refused at this door too (the fetch is the engine-
	// parity gap; capabilities anchorRefresh:false) and a refused policy
	// must not disturb an armed consent (a one-shot accept stays armed).
	if !e.AcceptStale() {
		t.Fatal("AcceptStale (one-shot) must arm")
	}
	if e.SetStaleAnchorPolicy(1) {
		t.Error("CHECKPOINT (1) must be refused, not applied")
	}
	if !e.StaleAccepted() {
		t.Error("a REFUSED policy write must not withdraw an armed consent (apply-or-refuse)")
	}
	// The consent GENERATION the waiver line follows (PR #877 round 8):
	// one bump per arming, none per refusal or refused write. Fresh
	// engine 0 → CONTINUE arms 1 → ASK withdraws, still 1 → one-shot
	// arms 2 → refused CHECKPOINT disturbs nothing, still 2.
	if g := e.StaleGeneration(); g != 2 {
		t.Errorf("staleGen = %d, want 2 (one bump per arming, none per withdrawal or refusal)", g)
	}
	// The 2 → 1 sequence specifically (PR #877 round-2): replacing a
	// remembered CONTINUE with CHECKPOINT withdraws the CONTINUE's consent
	// FIRST (host.rs swaps before it refuses), so the refused answer never
	// leaves a stale consent armed — ASK, the fail-closed posture, is what
	// the refused CHECKPOINT falls back to.
	if !e.SetStaleAnchorPolicy(2) {
		t.Fatal("CONTINUE must apply")
	}
	if e.SetStaleAnchorPolicy(1) {
		t.Error("CHECKPOINT still refuses")
	}
	if e.StaleAccepted() {
		t.Error("CONTINUE→CHECKPOINT must withdraw the consent (the host.rs rule, any replacement)")
	}
}

// TestStallWatcherReArmsOnAnyGatePass pins the round-6 fix: the stall
// WARN goes out once per refused streak, and EVERY outcome other than
// a stale refusal re-arms it — nil or not, because a non-stale
// RunCatchUp failure also came after a gate pass (the gate is reached
// at round 0). Re-arming only on nil had lost the re-warn exactly in
// the window where a re-consented node keeps ending in "catch-up
// stalled": stall #2 there emitted no line.
func TestStallWatcherReArmsOnAnyGatePass(t *testing.T) {
	var lines int
	w := &stallWatcher{warn: func(string, ...any) { lines++ }}
	stale := fmt.Errorf("wrapped: %w", clsync.ErrStaleAnchor)
	other := errors.New("clsync: catch-up stalled at period 1910 (wall 1930)")
	seq := []struct {
		err   error
		lines int // expected total after this note
		why   string
	}{
		{stale, 1, "first refusal of a streak warns"},
		{stale, 1, "per-slot repeats stay silent"},
		{other, 1, "a post-gate-pass failure re-arms silently"},
		{stale, 2, "stall #2 after that pass warns again"},
		{stale, 2, "and again stays silent"},
		{nil, 2, "a nil cycle re-arms silently"},
		{stale, 3, "stall #3 warns"},
	}
	for i, tc := range seq {
		w.note(tc.err)
		if lines != tc.lines {
			t.Fatalf("step %d (%s): lines = %d, want %d", i, tc.why, lines, tc.lines)
		}
	}
}
