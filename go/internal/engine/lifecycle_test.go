package engine

// Lifecycle regression tests (PR #827 review): the sync.Once reset in
// StartNetwork used to be a PROCESS-FATAL `unlock of unlocked mutex`
// on any discovery.Start failure (UDP bind, nodedb lock), and nothing
// in the suite took the failure path — so nothing caught it. These
// pin the failure path itself.

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/biafra23/myotis/go/internal/clsync"
	"log/slog"
	"net"
	"strings"
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
	// Then a one-shot arming, and CHECKPOINT (1) refused at this door too
	// (the fetch is the engine-parity gap; capabilities anchorRefresh:false)
	// — a refused policy must not disturb an armed consent (the one-shot
	// stays armed).
	if !e.AcceptStale() {
		t.Fatal("AcceptStale (one-shot) must arm")
	}
	if e.SetStaleAnchorPolicy(1) {
		t.Error("CHECKPOINT (1) must be refused, not applied")
	}
	if !e.StaleAccepted() {
		t.Error("a REFUSED policy write must not withdraw an armed consent (apply-or-refuse)")
	}
	// The APPLIED-ASK case the round-10 comment claimed was pinned but
	// was not: a bare one-shot must survive an ASK write (withdrawal
	// fires only when a remembered CONTINUE is replaced). Reachable on
	// every click of the Settings "Ask me" chip (NodeScreen re-sends
	// ASK unconditionally) — without this case, "ASK always withdraws"
	// passed the whole suite (round 11).
	if !e.SetStaleAnchorPolicy(0) {
		t.Fatal("ASK must apply")
	}
	if !e.StaleAccepted() {
		t.Error("ASK over a bare one-shot must not withdraw it (only a replaced CONTINUE does)")
	}
	// The consent GENERATION the waiver line follows (PR #877 round 8):
	// one bump per arming, none per refusal or refused write. Fresh
	// engine 0 → CONTINUE arms 1 → ASK withdraws, still 1 → one-shot
	// arms 2 → refused CHECKPOINT disturbs nothing, still 2 → applied
	// ASK over that one-shot disturbs nothing, still 2 (the three
	// writes above run in exactly this order).
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

// TestWireSyncerHooksTrackEngineState pins the wiring the round-8
// generation fix depends on and that no other test covers (PR #879
// round-9 review: deleting the StaleGeneration assignment left every
// test green while production took clsync's constant-generation
// fallback). The hooks must be live reads of engine state, not
// captures: mutate the engine, and the syncer's hooks answer
// differently on the next call. This pins the METHOD; the loop's call
// site is enforced by construction (lcLoop takes its Syncer only from
// newLoopSyncer, which builds and wires in one step — round 18).
func TestWireSyncerHooksTrackEngineState(t *testing.T) {
	var logBuf bytes.Buffer // must receive the WARN the hook promises (round 14)
	e, err := New(Config{DataDir: t.TempDir(), ListenPort: -1,
		Logger: slog.New(slog.NewTextHandler(&logBuf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := &clsync.Syncer{} // zero value: wireSyncerHooks only assigns hooks
	e.wireSyncerHooks(s)
	if s.Warnf == nil || s.WsBound == nil || s.StaleAccepted == nil || s.StaleGeneration == nil {
		t.Fatalf("wireSyncerHooks left a hook nil: warn=%v bound=%v consent=%v gen=%v",
			s.Warnf != nil, s.WsBound != nil, s.StaleAccepted != nil, s.StaleGeneration != nil)
	}
	// The WARN LEVEL of the Warnf hook is the last unpinned link of the
	// trail: clsync pins that the waiver routes through Warnf (not Logf),
	// capi pins how the ring renders level=WARN, GoLogDrainTest pins the
	// JVM normalization — only this test can pin that the engine's hook
	// LOGS at WARN. An e.log.Info here passes every other test while
	// dropping the waiver AND the stall line out of the hosts'
	// WARN-filtered view — the round-4 regression, one remove (round 14).
	s.Warnf("waiver probe %d", 7)
	if got := logBuf.String(); !strings.Contains(got, `level=WARN msg="waiver probe 7"`) {
		t.Fatalf("the Warnf hook must log at WARN, got %q", got)
	}
	if s.StaleAccepted() {
		t.Fatal("fresh engine: consent must start disarmed")
	}
	if g := s.StaleGeneration(); g != 0 {
		t.Fatalf("fresh engine: generation = %d, want 0", g)
	}
	b := s.WsBound()
	if b < 1 {
		t.Fatalf("WsBound hook returned %d, want the network default (>= 1)", b)
	}
	// The bound hook must be LIVE like the consent hooks, not a value
	// captured at wiring time (round 15). Nothing else can pin this:
	// StatusJSON reads Engine.EffectiveWsBound directly (capi.go:659),
	// so capi's setter test passes with a hook that stopped following
	// the setter, and no test asserts a gate after a bound change made
	// through this wiring. In production that mutant is the
	// accepted-and-ignored shape the Trust rules forbid — the setter
	// answers true and the status reports the new bound while the
	// running loop keeps judging by the bound captured when the loop
	// started — and it hides well, because releasing a PARKED loop
	// rebuilds the Syncer and captures afresh, so only the in-run path
	// goes wrong: raising the bound to end a stall (a way out the
	// stall WARN itself names), or lowering it.
	if !e.SetWsBoundPeriods(b + 7) {
		t.Fatal("SetWsBoundPeriods must apply on an open engine")
	}
	if got := s.WsBound(); got != b+7 {
		t.Fatalf("WsBound hook = %d after SetWsBoundPeriods(%d): a capture, not a live read", got, b+7)
	}
	// The override stays set: nothing below reads the bound, and
	// restartIfParked returns at !e.lcStarted, so it disturbs nothing.
	if !e.AcceptStale() {
		t.Fatal("AcceptStale failed")
	}
	if !s.StaleAccepted() {
		t.Fatal("hook captured a snapshot instead of reading live consent")
	}
	if g := s.StaleGeneration(); g != e.StaleGeneration() || g != 1 {
		t.Fatalf("hook generation = %d, engine = %d, want both 1", g, e.StaleGeneration())
	}
	// The round-7 shared-flag case, end to end through the hook: a
	// remembered CONTINUE after a one-shot, then ASK replacing it,
	// withdraws the one consent both armed. (A bare one-shot SURVIVES
	// an ASK write — withdrawal only fires when a remembered CONTINUE
	// is replaced; that case is pinned in
	// TestSetStaleAnchorPolicyWithdrawalMirrorsRust, which now writes
	// ASK over a bare one-shot too.)
	if !e.SetStaleAnchorPolicy(2) { // CONTINUE (already armed: no bump)
		t.Fatal("CONTINUE must apply")
	}
	if g := s.StaleGeneration(); g != 1 {
		t.Fatalf("re-arming an armed consent must not bump the generation (got %d)", g)
	}
	// The one-shot twin of the no-bump rule, in the order the park
	// dialog's "continue anyway" with "remember" ticked produces it
	// (NodeScreen.kt:587-591: onRemember then onContinue, i.e.
	// SetStaleAnchorPolicy(CONTINUE) then accept). Consent is armed
	// here and the generation is 1, so this accept must change
	// neither — an unconditional bump would turn that one click into
	// two generations, and the waiver log into two lines for one
	// user action (round 12; the CONTINUE guard above was pinned,
	// this twin was not).
	if !e.AcceptStale() {
		t.Fatal("AcceptStale on an armed consent must still answer true")
	}
	if g := s.StaleGeneration(); g != 1 {
		t.Fatalf("a one-shot accept on an armed consent must not bump the generation (got %d)", g)
	}
	if !e.SetStaleAnchorPolicy(0) { // ASK replaces CONTINUE -> withdrawal
		t.Fatal("ASK must apply")
	}
	if s.StaleAccepted() {
		t.Fatal("withdrawal did not reach the syncer's hook")
	}
	if g := s.StaleGeneration(); g != 1 {
		t.Fatalf("withdrawal must not bump the generation (got %d)", g)
	}
}
