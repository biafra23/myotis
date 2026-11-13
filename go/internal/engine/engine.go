// Package engine is the Go light engine as a library: discovery + RLPx
// dialing + the beacon light client + verified snap reads behind one
// type, so hosts (the CLI today; the c-shared C ABI and the desktop
// selector in the next parts) drive the same machinery instead of each
// re-hosting it. The code moved here from cmd/myotis-go unchanged —
// every guard comment came along — and the CLI is now a thin driver
// over it (desktop-embed step 1, part 1a).
//
// Trust model is unchanged and total: nothing a peer says is a value
// until a proof verified it against a light-client anchor that the BLS
// path accepted this cycle (docs/spec/02 §6.4).
package engine

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clsync"
	"github.com/biafra23/myotis/go/internal/discovery"
	"github.com/biafra23/myotis/go/internal/lc"
	"github.com/biafra23/myotis/go/internal/mpt"
	"github.com/biafra23/myotis/go/internal/nodekey"
	"github.com/biafra23/myotis/go/internal/snapread"
	"github.com/ethereum/go-ethereum/common"
)

// Config is what a host decides about an engine; everything else
// (network pins, LC geometry, budgets) is engine policy.
type Config struct {
	DataDir string // node key + peer database
	// ListenPort is the discv4 UDP port: 0 = network default,
	// -1 = ephemeral (and then nothing is advertised in our Hello).
	ListenPort int
	// DialPeers dials discovered candidates over RLPx; false is
	// discovery-only observation.
	DialPeers bool
	MaxDials  int // concurrent outbound dials
	MaxReady  int // cap on live READY sessions (backlog holds the rest)
	// RequireSnap closes READY sessions without the snap capability at
	// the door: set it when this process intends VERIFIED READS, unset
	// for dial-wall observation (where a non-snap READY peer is a
	// result, not a refusal).
	RequireSnap bool
	Logger      *slog.Logger
}

// Engine owns discovery, the dialer, the light-client loop and the
// verified-read orchestration. Construct with New; the zero value is not
// usable. Close releases everything (sockets, goroutines, the libp2p
// host).
type Engine struct {
	log  *slog.Logger
	dial *dialer
	key  *ecdsa.PrivateKey
	cfg  Config // kept for StartNetwork

	// Network start state. A mutex, not a sync.Once, because a failed
	// attempt must be retryable: a Once reset from inside its own Do
	// body is an unsynchronized write other StartNetwork callers race
	// on (PR #827 review) — with a mutex there is no state to reset,
	// a failed attempt simply leaves netStarted false. disc is written
	// and read only under netMu.
	netMu      sync.Mutex
	netStarted bool
	disc       *discovery.Service // set by StartNetwork, not by New

	// Weak-subjectivity overrides, the C ABI's live setters
	// (myotis_set_ws_bound_periods / myotis_accept_stale_anchor), read
	// by the LC loop through the syncer's WsBound/StaleAccepted hooks
	// on every gate, so a parked loop re-evaluates within its next
	// check rather than needing the process restarted.
	wsOverride  uint64 // 0 = the network default (the contract's 0)
	acceptStale bool

	// LC state. latest is the newest VERIFYING-poll anchor (nil until
	// the first one). dead closes whenever the loop goroutine ENDS —
	// gave up OR was cancelled — with the reason in lcErr under mu: a
	// host that stops the engine while a read is in flight must learn
	// that NOW, not after its own read budget (PR #827 review — the
	// old "only on gave-up" close left an ABI reader hanging the full
	// ReadBudget after myotis_stop; the reader's own ctx.Err() guard
	// in Account is what keeps a cancellation from being REPORTED as
	// a failure). Readers reload the channel under mu each loop, so a
	// restart (SetWsBoundPeriods/AcceptStale releasing a parked loop)
	// installs a fresh one they migrate to. anchorSig is a real
	// broadcast — publish() closes it and installs a fresh one under
	// mu, so EVERY blocked reader wakes (a 1-buffered signal would
	// wake one) — the payload lives in latest, not the channel, and
	// readers re-arm on the new channel each loop. lcDone closes when
	// the loop goroutine returns (its defer h.Close() released the
	// libp2p host), which is what lets Close honor the type doc for
	// an embedded stop-and-restart host; a restart installs a fresh
	// one so Close always waits on the CURRENT loop.
	lcStart   sync.Once
	lcCancel  context.CancelFunc
	lcCtx     context.Context // kept so a released park can re-spawn the loop
	lcStarted bool            // a loop was ever started; guards the lcDone wait
	lcRunning bool            // the CURRENT loop goroutine has not returned
	lcDone    chan struct{}
	mu        sync.Mutex
	latest    *Anchor
	lcErr     error
	dead      chan struct{}
	anchorSig chan struct{}
	closed    bool
	// bootstrapped is set once RunBootstrap passed (the Rust status'
	// "bootstrapped" key: the store exists, anchor or not). lcPeers is
	// the light-client peer count snapshotted by the loop each cycle
	// (the syncer itself is loop-local).
	bootstrapped bool
	lcPeers      int

	closeOnce sync.Once
}

// New loads the node identity and starts the dialer workers; it does
// NOT start discovery (that is StartNetwork's, so a C-ABI host can
// hold a created-but-quiet handle per myotis_engine.h) and not the
// light client (StartLC — a discovery-only host pays no libp2p).
func New(cfg Config) (*Engine, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	netCfg := chain.Mainnet() // the one network for now

	key, err := nodekey.Load(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	log.Info("node identity",
		"nodeId", fmt.Sprintf("%x", nodekey.NodeID(&key.PublicKey)),
		"datadir", cfg.DataDir)

	// What our Hello advertises as our TCP port: the operator's port when
	// it is a real one, 0 when the socket is ephemeral — never the
	// network's constant, which is wrong whenever the port moved.
	advertiseTCP := uint16(0)
	switch {
	case cfg.ListenPort < 0: // ephemeral: nothing to advertise
	case cfg.ListenPort == 0:
		advertiseTCP = uint16(netCfg.ListenPort)
	default:
		advertiseTCP = uint16(cfg.ListenPort)
	}

	e := &Engine{
		log:       log,
		dial:      newDialer(key, netCfg, cfg.MaxDials, cfg.MaxReady, advertiseTCP, cfg.RequireSnap, log),
		key:       key,
		cfg:       cfg,
		dead:      make(chan struct{}),
		lcDone:    make(chan struct{}),
		anchorSig: make(chan struct{}),
	}
	return e, nil
}

// StartNetwork begins EL discovery (and, through it, dialing). New does
// NOT start it: the C ABI's contract (myotis_engine.h) is that
// myotis_create allocates a NOT-YET-STARTED handle and myotis_start
// begins the sync loop, so the embedder — not the allocator — decides
// when the process starts sending packets. The CLI calls this right
// after New, which reproduces the old always-on behaviour exactly.
// Idempotent; a failed first attempt may be retried.
// After Close it is an error, not a silent success: a discovery
// service started behind a closed Engine would never be closed again
// (the same guard StartLC applies).
func (e *Engine) StartNetwork() error {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	if e.netStarted {
		return nil
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return fmt.Errorf("engine: closed")
	}
	disc, err := discovery.Start(discovery.Config{
		DataDir:    e.cfg.DataDir,
		Network:    chain.Mainnet(), // the same pin New derived from
		Key:        e.key,
		ListenPort: e.cfg.ListenPort,
		Logger:     e.log,
		OnDiscovered: func(c discovery.Candidate) {
			e.log.Info("peer discovered",
				"id", c.ID.String(),
				"addr", fmt.Sprintf("%s:%d", c.Node.IP(), c.Node.TCP()),
				"via", c.Source)
			if e.cfg.DialPeers {
				e.dial.enqueue(c.Node)
			}
		},
	})
	if err != nil {
		// Nothing recorded: the next call retries (the doc's promise,
		// now without a sync.Once reset racing its own Do).
		return err
	}
	e.disc = disc
	e.netStarted = true
	return nil
}

// networkService is the discv4 service under netMu (nil until
// StartNetwork succeeded) — the only way to read e.disc without
// racing StartNetwork's write.
func (e *Engine) networkService() *discovery.Service {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	return e.disc
}

// DiscoveryStats reports (routing-table size, live nodes) for the
// status surfaces; 0,0 before StartNetwork.
func (e *Engine) DiscoveryStats() (table, live int) {
	if disc := e.networkService(); disc != nil {
		table, live, _ = disc.Stats()
	}
	return table, live
}

// AttemptedDials is the count of candidates the dialer actually
// dialed (the status' "attemptedDials").
func (e *Engine) AttemptedDials() int { return e.dial.attemptedCount() }

// SnapServingPeers counts live snap sessions, and how many of them
// negotiated snap/2 (EIP-8189) — the status' "snapPeers"/
// "snapServingPeers"/"snap2ServingPeers". For this dial-only engine
// every snap session is a read candidate RIGHT NOW (there is no pool
// of still-syncing peers to discount, which is what the Rust field
// pair distinguishes over there), so serving == snap.
func (e *Engine) SnapServingPeers() (snap, snap2 int) { return e.dial.snapCounts() }

// StartLC starts the beacon light client once (later calls are no-ops):
// bootstrap over the static pins, committee catch-up, and the steady
// poll loop that keeps publishing verified anchors. ctx bounds the
// loop; cancelling it is shutdown, not failure.
func (e *Engine) StartLC(ctx context.Context) {
	e.lcStart.Do(func() {
		e.spawnLC(ctx)
	})
}

// spawnLC launches one LC loop goroutine under the current lcCtx/
// lcCancel. Called once by StartLC and again by releaseStalePark after
// a dead channel is replaced — the caller must hold e.mu when
// restarting (StartLC's fresh path may run it unlocked; it only ever
// wins the lcStart race once).
func (e *Engine) spawnLC(ctx context.Context) {
	lcCtx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	closed := e.closed
	if !closed {
		e.lcCancel = cancel
		e.lcCtx = lcCtx
		e.lcStarted = true
		e.lcRunning = true
	}
	e.mu.Unlock()
	if closed { // Close already ran (or is past its read): do not orphan a loop
		cancel()
		return
	}
	// Ownership of cancel transfers to Close (stored in e.lcCancel);
	// this is also what tells vet the value is not leaked here.
	_ = cancel
	go e.runLightClient(lcCtx)
}

// runLightClient ends the LC loop and ALWAYS wakes every waiting
// Account — gave-up or cancelled alike (PR #827 review: a C-ABI
// myotis_stop during an in-flight read left that reader blocked for
// its whole 90 s budget, because the cancelled exit published
// nothing; the reader's ctx.Err() guard is what turns the close into
// "aborted", never into a reported failure on shutdown). A cancelled
// exit still publishes no anchor: shutdown is the clean path, not a
// result.
func (e *Engine) runLightClient(ctx context.Context) {
	// Capture THIS loop's channels once, under mu: a park-release
	// (SetWsBoundPeriods/AcceptStale) may install fresh dead/lcDone
	// while this goroutine is between its lcRunning=false write and
	// these closes, and a late close of the NEW channels would fail
	// every reader against a loop that is running fine.
	e.mu.Lock()
	dead, done := e.dead, e.lcDone
	e.mu.Unlock()
	defer close(done)
	logf := func(f string, a ...any) { e.log.Info(fmt.Sprintf(f, a...)) }
	err := e.lcLoop(ctx, logf)
	e.mu.Lock()
	if err == nil {
		err = ctx.Err() // ctx-terminating loop already returns ctx.Err(); belt
	}
	e.lcErr = err
	e.lcRunning = false
	e.mu.Unlock()
	close(dead)
}

// SetWsBoundPeriods overrides the weak-subjectivity bound (0 restores
// the network default) — myotis_set_ws_bound_periods. The running
// loop reads it live at every gate; a loop that had ALREADY refused
// bootstrap as STALE_ANCHOR is restarted here, which is what makes
// the header's "a handle parked in the STALE_ANCHOR beaconState
// re-evaluates within a second" true for this engine too. Reports
// whether the value was applied (false only once the Engine is
// closed).
func (e *Engine) SetWsBoundPeriods(periods uint64) bool {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return false
	}
	e.wsOverride = periods
	e.mu.Unlock()
	e.restartIfParked()
	return true
}

// AcceptStale records the host's one-shot consent to the embedded
// anchor's age (myotis_accept_stale_anchor): suppresses both
// weak-subjectivity layers for the rest of this Engine's life, never
// persisted, and releases a bootstrap that had already parked.
func (e *Engine) AcceptStale() bool {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return false
	}
	e.acceptStale = true
	e.mu.Unlock()
	e.restartIfParked()
	return true
}

// restartIfParked re-spawns the LC loop when it died (and was not
// merely cancelled by shutdown): the stale/override setters promise a
// parked handle re-evaluates, and in this engine a park IS a loop
// that exited with ErrStaleAnchor. The fresh dead/lcDone channels are
// installed under the same lock hold that checks lcRunning, so a
// reader migrating between channels sees either the old closed pair
// (it reloads and retries) or the new open one — never a half state.
func (e *Engine) restartIfParked() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || !e.lcStarted || e.lcRunning {
		return // nothing to release: alive, not started yet, or gone
	}
	if e.lcCtx != nil && e.lcCtx.Err() != nil {
		return // cancelled for shutdown, not parked on staleness
	}
	if !errors.Is(e.lcErr, clsync.ErrStaleAnchor) {
		return // died for another reason; that failure stays reported
	}
	// lcErr is DELIBERATELY not cleared: a reader still armed on the
	// old dead channel wakes with the honest ErrStaleAnchor it was
	// about to report, and recognizes the restart by the channel swap
	// (Account's dead arm) rather than failing on a half state.
	e.dead = make(chan struct{})
	e.lcDone = make(chan struct{})
	e.lcRunning = true // we hold mu; runLightClient re-reads its channels under it
	go e.runLightClient(e.lcCtx)
}

// BeaconState maps the engine to the API's beaconState strings, with
// the same mapping the Rust engine's host applies (Starting and
// Bootstrapping both report "SYNCING"; a handle whose loop never ran
// reports "STARTING" like Rust's not-started shape). STALE_ANCHOR is
// this engine's honest equivalent of Rust's park: the LC loop exited
// refusing the anchor's age — and it survives SetWsBoundPeriods /
// AcceptStale only until the released loop's first outcome, after
// which the loop's new state takes over.
func (e *Engine) BeaconState(nowUnix int64) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case !e.lcStarted:
		return "STARTING"
	case !e.lcRunning && errors.Is(e.lcErr, clsync.ErrStaleAnchor):
		return "STALE_ANCHOR"
	case e.latest == nil:
		return "SYNCING"
	case beaconSynced(e.latest.BeaconSlot, nowUnix):
		return "SYNCED"
	default:
		return "CATCHING_UP"
	}
}

// Bootstrapped reports the Rust status' "bootstrapped": RunBootstrap
// passed once, store installed.
func (e *Engine) Bootstrapped() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bootstrapped
}

// LCPeerCount is the light-client peer count the loop last
// snapshotted (the status' "peerCount").
func (e *Engine) LCPeerCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lcPeers
}

// EffectiveWsBound is the weak-subjectivity bound in force (the
// override, or the network default) — reported as the status'
// "wsBoundPeriods", which the Rust side reports as ENFORCED, not as
// default.
func (e *Engine) EffectiveWsBound() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.wsOverride >= 1 {
		return e.wsOverride
	}
	return chain.WsBoundPeriods
}

// lcLoop bootstraps the LC over libp2p (static pins, the same
// set myotis-lc dials), walks the committee chain, and keeps the
// anchor fresh on the myotis-lc steady loop — every answer through
// the part-3 processor (checkpoint pin, period gate, BLS, Merkle
// branches). Anchors are published only after a VERIFYING finality
// poll (Advanced or Stale) — never the bootstrap/catch-up root, which
// is routinely outside every peer's state window (see the loop).
// This is the same loop as cmd/myotis-lc's; when a
// second consumer appeared the honest move is to say so in a comment
// and re-unify the two in 3c rather than contort the merged main.
func (e *Engine) lcLoop(ctx context.Context, logf func(string, ...any)) error {
	c := chain.ConsensusMainnet()
	h, err := clsync.NewHost()
	if err != nil {
		return fmt.Errorf("libp2p host: %w", err)
	}
	defer h.Close()
	syncer := clsync.NewSyncer(c, h, logf)
	// The C ABI's live setters reach the weak-subjectivity gates
	// through these hooks (read at every check, not captured):
	// myotis_set_ws_bound_periods and myotis_accept_stale_anchor.
	syncer.WsBound = e.EffectiveWsBound
	syncer.StaleAccepted = func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.acceptStale
	}
	clsync.InstallGossipSubHold(h)
	clsync.ServeInstall(h, syncer.LocalStatus)

	// Bootstrap RETRIES (PR #827 review): a laptop asleep at launch,
	// a pin rate-limiting us, a 4-minute window that just lapses —
	// none of those is "this handle is dead forever", which is what
	// returning made them behind a long-lived handle (the loop was
	// one-shot, so the zombie answered retryable forever). The Rust
	// twin likewise keeps working rather than parking; the ONE state
	// it parks in is STALE_ANCHOR, and that is the only bootstrap
	// failure this loop still exits on — the consent path
	// (AcceptStale / SetWsBoundPeriods) is what releases it.
	var st *lc.Store
	for {
		bootCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		var err error
		st, err = syncer.RunBootstrap(bootCtx)
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, clsync.ErrStaleAnchor) {
			return fmt.Errorf("bootstrap: %w", err) // park; beaconState reports it
		}
		e.log.Warn("bootstrap failed, retrying", "err", err, "retryIn", "30s")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
	e.mu.Lock()
	e.bootstrapped = true
	e.lcPeers = syncer.PeerCount()
	e.mu.Unlock()
	catchCtx, catchCancel := context.WithTimeout(ctx, 4*time.Minute)
	if err := syncer.RunCatchUp(catchCtx, st); err != nil {
		// NOT fatal (PR #773 review): a pin that is down or
		// rate-limiting us today is up in the next slot, and the
		// steady loop below re-runs catch-up every cycle exactly for
		// that. Killing the light client here instead would expire
		// the read window on one bad round — the failure the loop
		// right below already tolerates.
		logf("catch-up: %v (the steady loop retries it each slot)", err)
	}
	catchCancel()
	// NO publish yet: st.Finalized here is the embedded checkpoint (or
	// the previous period's best-update header) — hours old in the
	// ordinary case, and outside every peer's ~128-block state window,
	// so a read aimed at it would disclose the account key to up to
	// three peers that cannot answer it. An anchor becomes readable
	// only once a finality poll has VERIFIED it (below), which is also
	// what makes snapread's "the anchor is the fresh head" claim true.
	for ctx.Err() == nil {
		published := false
		e.mu.Lock()
		e.lcPeers = syncer.PeerCount()
		e.mu.Unlock()
		if err := syncer.RunCatchUp(ctx, st); err != nil {
			logf("re-catch-up: %v", err)
		} else if chain.SyncCommitteePeriod(syncer.Consensus.SlotAt(time.Now().Unix())) > st.Period() {
			logf("committee behind wall clock after re-catch-up; skipping finality poll this cycle")
		} else if outcome, err := syncer.PollFinality(ctx, st); err != nil {
			logf("finality poll: %v", err)
		} else {
			logf("finality poll: outcome %v, finalized slot %d", outcome, st.Finalized.Slot)
			// Advanced OR Stale both mean the store's finalized header
			// passed the full BLS path THIS cycle (Stale = verified,
			// just not newer); Rejected / poll errors publish nothing.
			published = outcome == lc.Advanced || outcome == lc.Stale
		}
		if published {
			e.publish(snapshot(st))
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(chain.SecondsPerSlot) * time.Second):
		}
	}
	return ctx.Err()
}

// publish keeps the freshest anchor as THE anchor and wakes EVERY
// waiting reader — close-and-replace, because a buffered nudge wakes
// one receiver and concurrent readers must not wait out their 2 s
// tick to learn the anchor moved. A reader that woke late reads the
// newest root by construction (latest is overwritten in place).
func (e *Engine) publish(a Anchor) {
	e.mu.Lock()
	e.latest = &a
	close(e.anchorSig)
	e.anchorSig = make(chan struct{})
	e.mu.Unlock()
}

// snapshot reads one trust position out of the verified store,
// including the PROVEN exec coordinates the result shapes report
// (lc.Store.FinalizedExecInfo / OptimisticExecInfo — fields of the
// attested execution payload headers, not peer claims).
func snapshot(st *lc.Store) Anchor {
	a := Anchor{
		BeaconSlot: st.Finalized.Slot,
		StateRoot:  st.FinalizedStateRoot(),
	}
	if n, t, h, ok := st.FinalizedExecInfo(); ok {
		a.ExecNumber, a.ExecTimestamp, a.ExecBlockHash = n, t, h
	}
	if n, _, _, ok := st.OptimisticExecInfo(); ok {
		a.OptimisticExecNo = n
	}
	if st.Optimistic != nil {
		a.OptimisticSlot = st.Optimistic.Slot
	}
	return a
}

// Anchor is the newest verified anchor the LC has published (ok=false
// before the first one).
func (e *Engine) Anchor() (Anchor, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.latest == nil {
		return Anchor{}, false
	}
	return *e.latest, true
}

// ReadyPeerCount is the number of live READY sessions (the same count
// the summary line reports; status surfaces use it).
func (e *Engine) ReadyPeerCount() int { return e.dial.readyCount() }

// SnapPeers are the live snap-capable sessions, sorted by node id —
// exposed for status surfaces; readers go through Account, which owns
// the disclosure budget.
func (e *Engine) SnapPeers() []snapread.Peer { return e.dial.snapPeers() }

// LCError reports that the light client gave up, so the read can never
// be VERIFIED. It is its own type (not just a wrapped error) because
// the LC's own budgets carry their own context deadline — a bootstrap
// timeout wraps context.DeadlineExceeded, and a caller classifying by
// that sentinel would report "the READ window expired" for a light
// client that died minutes earlier. The old main loop kept these arms
// separate (lcFailure vs deadline); the type keeps them separate
// across the library seam.
type LCError struct{ Err error }

func (e *LCError) Error() string { return "light client: " + e.Err.Error() }
func (e *LCError) Unwrap() error { return e.Err }

// ReadError says the wait for a verified read ended without one. Reason
// is why the wait ended (deadline or cancellation); LastAttempt is the
// last deferred per-anchor failure, so "the window expired" can name
// the cause instead of only the fact (the same honesty the CLI's
// timeout error carried).
type ReadError struct {
	Reason      error
	LastAttempt error
}

func (e *ReadError) Error() string {
	if e.LastAttempt != nil {
		return fmt.Sprintf("read did not complete: %v (last attempt: %v)", e.Reason, e.LastAttempt)
	}
	return fmt.Sprintf("read did not complete: %v", e.Reason)
}

// Unwrap exposes both halves to errors.Is (only the non-nil ones — a
// nil in the slice would make errors.Is match a nil target).
func (e *ReadError) Unwrap() []error {
	if e.LastAttempt != nil {
		return []error{e.Reason, e.LastAttempt}
	}
	return []error{e.Reason}
}

type readResult struct {
	read *AccountRead
	err  error
}

// Account performs one verified account read (plus the optional
// storage-slot hop) against the newest verified anchor, retrying as
// anchors advance and peers arrive, and returns only when a proof
// served the read, the light client gave up, or ctx ended. The result
// carries the proof outcome and the anchor it verified against — the
// caller decides what to print or marshal; nothing here logs the
// answer, because "answered" is the CALLER's event, not the engine's.
//
// Concurrency: each call is one logical read with its own disclosure
// memory. The bound is per ATTEMPT, not per call: every retry asks
// only peers not yet contacted AT THE CURRENT ANCHOR (up to
// snapread.MaxAttempts of them per attempt), so across a long call on
// one anchor the address can reach every snap peer that goes READY
// during the call — each exactly once, which is what the tried-set
// guarantees. Concurrent calls are independent replicas of that
// statement, each under its own memory.
//
// The address arrives as the caller's string and is echoed back in the
// result shapes EXACTLY as given (the cross-engine contract —
// host.rs passes the request's address_hex straight through); the
// engine parses it here and refuses a malformed one rather than
// accepting a parameter it cannot apply.
func (e *Engine) Account(ctx context.Context, address string, slot [32]byte, wantSlot bool) (*AccountRead, error) {
	if !common.IsHexAddress(address) {
		return nil, fmt.Errorf("engine: %q is not a hex address", address)
	}
	addr := common.HexToAddress(address)
	// Fail fast, honestly (the C ABI in part 1b would otherwise block
	// a host thread forever): without the light client there is no
	// anchor and never will be on this Engine (lcStart is once-only).
	e.mu.Lock()
	closed, started := e.closed, e.lcStarted
	sig := e.anchorSig
	e.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("engine: closed")
	}
	if !started {
		return nil, fmt.Errorf("engine: light client not started (StartLC)")
	}
	// tried maps anchor → peer ids already asked AT that anchor. The
	// 3-attempt cap bounds ONE snapread call; this ticker re-runs the
	// read, so without memory a failed read would reach a fresh random
	// three every 2 s (the ready map iterates arbitrarily) until the
	// whole ready set — and every replacement session — had seen
	// keccak(address). With it, one logical read (one anchor) discloses
	// the address to each peer at most once, and peers READYing later
	// are the only new ones the retries add.
	tried := map[[32]byte]map[string]bool{}
	var lastTriedRoot [32]byte
	haveTriedRoot := false
	var lastAttempt error
	// readRes carries the outcome of the in-flight attempt; reads run in
	// a goroutine because one can take maxAttempts × request-timeout per
	// hop, and neither Ctrl-C nor the deadline may wait that long (the
	// sessions take no context; the select does).
	readRes := make(chan readResult, 1)
	inFlight := false
	attempt := func(a *Anchor) {
		if inFlight {
			return
		}
		peers := e.dial.snapPeers()
		untried := make([]snapread.Peer, 0, len(peers))
		seen := tried[a.StateRoot]
		if seen == nil {
			// Finalized roots advance all the time; a long-running
			// read would otherwise accumulate a peer set per root
			// forever. Keep only the current root plus the previous
			// one (a read launched against it may still be in
			// flight) — older roots will never be read again.
			if haveTriedRoot && lastTriedRoot != a.StateRoot {
				for r := range tried {
					if r != a.StateRoot && r != lastTriedRoot {
						delete(tried, r)
					}
				}
			}
			seen = map[string]bool{}
			tried[a.StateRoot] = seen
			lastTriedRoot, haveTriedRoot = a.StateRoot, true
		}
		for _, p := range peers {
			if !seen[p.ID()] {
				untried = append(untried, p)
			}
		}
		if len(untried) == 0 {
			return // nothing new to ask at this anchor
		}
		if len(untried) > snapread.MaxAttempts {
			untried = untried[:snapread.MaxAttempts] // what usable() will contact
		}
		// Marking happens BEFORE the read runs: "contacts exactly
		// these" holds for every failure path except one — the
		// unmarked leaf-decode early return inside snapread can stop
		// at the first peer. That peer's later siblings go untried at
		// this root, and that is right: the failed leaf is COMMITTED
		// by a proof that verified against this root, so every honest
		// peer serving this root serves the same bytes and the same
		// verdict — asking the rest is the "repaying the round trip"
		// snapread's decode rule exists to skip. Every other failure
		// (transport, marked proof-invalid) walks all ≤3, so the
		// disclosure accounting stays exact.
		for _, p := range untried {
			seen[p.ID()] = true
		}
		inFlight = true
		go func() {
			r, err := attemptRead(a, untried, address, addr, slot, wantSlot)
			readRes <- readResult{r, err}
		}()
	}

	// Re-try with the ALREADY-held anchor when new peers arrive between
	// LC cycles: the anchor nudge only fires on LC cycles, and a snap
	// peer READYing right after one would otherwise wait a full slot.
	// attempt asks only peers not yet tried at this anchor and no-ops
	// when there are none, or when a read is still running.
	reads := time.NewTicker(2 * time.Second)
	defer reads.Stop()

	for {
		e.mu.Lock()
		a := e.latest
		sig = e.anchorSig // re-arm on the current broadcast channel
		dead := e.dead    // and on the current failure channel (a park-release swaps it)
		e.mu.Unlock()
		if a != nil {
			attempt(a)
		}
		select {
		case <-ctx.Done():
			return nil, &ReadError{Reason: ctx.Err(), LastAttempt: lastAttempt}
		case <-dead:
			e.mu.Lock()
			cur, err := e.dead, e.lcErr
			e.mu.Unlock()
			if cur != dead {
				// The loop was RESTARTED (stale-anchor release)
				// between arming and waking: this close belongs to
				// the retired loop — re-arm on the live channels.
				continue
			}
			// Ctrl-C closes both arms' race honestly (the old main
			// loop's rule): the LC loop ends with context.Canceled
			// exactly when ctx ends too, and select picks randomly —
			// shutdown is the clean path, never a failure, and library
			// consumers (StartLC's promise) must not have to re-check
			// ctx to know that. Same for a host STOP: myotis_stop
			// cancels the LC loop, which now closes dead immediately
			// (PR #827 review: it used to not, leaving this reader
			// waiting out its full read budget).
			if ctx.Err() != nil {
				return nil, &ReadError{Reason: ctx.Err(), LastAttempt: lastAttempt}
			}
			// The LC gave up (bootstrap/catch-up refused within the
			// budget): the read can never be VERIFIED, so the wait
			// fails too — a verified read is the only success this
			// engine knows.
			return nil, &LCError{err}
		case res := <-readRes:
			inFlight = false
			if res.err != nil {
				// Ordinary retry: the anchor may predate every peer's
				// state window, or every dial so far lacked snap. The
				// next poll cycle re-publishes and more peers arrive;
				// the tried map keeps the retries from re-asking peers
				// that already answered for this root.
				lastAttempt = res.err
				e.log.Debug("verified read deferred", "reason", res.err)
				continue
			}
			return res.read, nil
		case <-sig: // anchor already re-read at the top of the loop
		case <-reads.C:
		}
	}
}

// attemptRead is the two-hop read itself. Its result NEVER includes a
// peer's claim without a proof behind it — every field comes from a
// proof leaf verified against the anchor's root, or from the attested
// payload header that root was read at. The caller runs this in a
// goroutine — hops cost up to snapread.MaxAttempts × the request
// timeout each.
func attemptRead(a *Anchor, peers []snapread.Peer, address string, addr common.Address, slot [32]byte, wantSlot bool) (*AccountRead, error) {
	if len(peers) == 0 {
		return nil, fmt.Errorf("no snap-capable READY peers yet (anchor is ready: slot %d)", a.BeaconSlot)
	}
	servedBy, out, err := snapread.Account(peers, a.StateRoot, addr)
	if err != nil {
		return nil, err
	}
	rd := &AccountRead{
		Address:    addr,
		AddressHex: address, // echoed as supplied, as the Rust twin
		Anchor:     *a,
		Peers:      len(peers),
		Outcome:    out,
	}
	if wantSlot {
		if out.Absent() {
			// An absent account has no storage: the slot is provably
			// zero with no walk to do, and the JSON says so (exists
			// false, null value) rather than staying silent about it.
			// The root both engines report for it is the empty-trie
			// root (reader.rs:6996), not zeros.
			rd.Slot = &SlotRead{Key: slot, StorageRoot: mpt.EmptyTrieRoot}
		} else {
			// SlotAt, not Slot: the account was just proven above — the
			// storage hop must reuse that outcome and the SAME peer
			// slice (starting at the serving peer), so one logical read
			// never widens the disclosure cap to 3+3 peers, never pays
			// for the account request twice, and never re-pays a first
			// peer's timeout on the second hop.
			v, err := snapread.SlotAt(peers, a.StateRoot, addr, slot, out, servedBy)
			if err != nil {
				return nil, fmt.Errorf("slot read: %w", err)
			}
			rd.Slot = &SlotRead{Key: slot, Value: v, StorageRoot: out.Account.StorageRoot}
		}
	}
	return rd, nil
}

// Report logs the discovery/dial summary line — the same accounting the
// CLI's 30-second ticker and every exit path printed.
func (e *Engine) Report() {
	var (
		table, live int
		bySource    map[discovery.Source]int
	)
	if disc := e.networkService(); disc != nil { // StartNetwork may never have run
		table, live, bySource = disc.Stats()
	}
	peers := make([]any, 0, len(bySource))
	for src, n := range bySource {
		peers = append(peers, slog.Any(string(src), n))
	}
	ready, outcome, clients := e.dial.stats()
	e.log.Info("summary",
		"tableNodes", table, "liveNodes", live, "dialablePeers", peers,
		"readyPeers", ready, "dialOutcomes", outcome, "everReadyClients", clients)
}

// Close stops the light client, discovery and the dialer, idempotent.
// The order mirrors the CLI's old defers: discovery first (stop firing
// OnDiscovered), then the dialer (its closed-flag is the second belt).
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		cancel := e.lcCancel
		e.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if disc := e.networkService(); disc != nil { // New-then-Close without StartNetwork
			disc.Close()
		}
		e.dial.close()
		// Wait for the LC goroutine's defer (h.Close, the libp2p host)
		// before claiming release: an embedded host that restarts the
		// engine must not find the old host still listening. Bounded —
		// the loop's waits are all cancellable on this very ctx.
		// Read lcDone under mu — a park-release may have installed a
		// fresh one, and waiting on a stale closed channel would
		// return while the CURRENT loop's libp2p host is still up.
		e.mu.Lock()
		started, done := e.lcStarted, e.lcDone
		e.mu.Unlock()
		if started {
			<-done
		}
	})
}
