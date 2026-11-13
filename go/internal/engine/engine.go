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
	disc *discovery.Service // set by StartNetwork, not by New
	dial *dialer
	key  *ecdsa.PrivateKey
	cfg  Config // kept for StartNetwork

	netOnce sync.Once
	netErr  error

	// LC state. latest is the newest VERIFYING-poll anchor (nil until
	// the first one); dead closes exactly when the LC loop gave up for a
	// non-shutdown reason, with lcErr recorded under mu. anchorSig is a
	// real broadcast — publish() closes it and installs a fresh one
	// under mu, so EVERY blocked reader wakes (a 1-buffered signal
	// would wake one) — the payload lives in latest, not the channel,
	// and readers re-arm on the new channel each loop. lcDone closes
	// when the loop goroutine returns (its defer h.Close() released
	// the libp2p host), which is what lets Close honor the type doc
	// for an embedded stop-and-restart host.
	lcStart   sync.Once
	lcCancel  context.CancelFunc
	lcStarted bool // a loop goroutine exists; guards the lcDone wait
	lcDone    chan struct{}
	mu        sync.Mutex
	latest    *Anchor
	lcErr     error
	dead      chan struct{}
	anchorSig chan struct{}
	closed    bool

	closeOnce sync.Once
}

// New loads the node identity, starts the dialer and discovery, and
// returns a live engine. The light client runs only after StartLC — a
// discovery-only host pays no libp2p.
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
func (e *Engine) StartNetwork() error {
	e.netOnce.Do(func() {
		e.disc, e.netErr = discovery.Start(discovery.Config{
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
		if e.netErr != nil {
			e.netOnce = sync.Once{} // retryable, as the doc promises
		}
	})
	return e.netErr
}

// StartLC starts the beacon light client once (later calls are no-ops):
// bootstrap over the static pins, committee catch-up, and the steady
// poll loop that keeps publishing verified anchors. ctx bounds the
// loop; cancelling it is shutdown, not failure.
func (e *Engine) StartLC(ctx context.Context) {
	e.lcStart.Do(func() {
		lcCtx, cancel := context.WithCancel(ctx)
		e.mu.Lock()
		closed := e.closed
		if !closed {
			e.lcCancel = cancel
		}
		e.mu.Unlock()
		if closed { // Close already ran (or is past its read): do not orphan a loop
			cancel()
			return
		}
		// Ownership of cancel transfers to Close (stored in e.lcCancel);
		// this is also what tells vet the value is not leaked here.
		_ = cancel
		e.mu.Lock()
		e.lcStarted = true
		e.mu.Unlock()
		go e.runLightClient(lcCtx)
	})
}

// runLightClient ends the LC loop and, if it ended for a real reason,
// wakes every waiting Account with it. A ctx-cancelled exit publishes
// nothing: shutdown is the clean path, never a failure (the same
// honesty the CLI's lcFailure arm applied).
func (e *Engine) runLightClient(ctx context.Context) {
	defer close(e.lcDone)
	logf := func(f string, a ...any) { e.log.Info(fmt.Sprintf(f, a...)) }
	err := e.lcLoop(ctx, logf)
	if ctx.Err() != nil {
		return
	}
	e.mu.Lock()
	e.lcErr = err
	e.mu.Unlock()
	close(e.dead)
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
	clsync.InstallGossipSubHold(h)
	clsync.ServeInstall(h, syncer.LocalStatus)

	bootCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	st, err := syncer.RunBootstrap(bootCtx)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if err := syncer.RunCatchUp(bootCtx, st); err != nil {
		// NOT fatal (PR #773 review): a pin that is down or
		// rate-limiting us today is up in the next slot, and the
		// steady loop below re-runs catch-up every cycle exactly for
		// that. Killing the light client here instead would expire
		// the read window on one bad round — the failure the loop
		// right below already tolerates.
		logf("catch-up: %v (the steady loop retries it each slot)", err)
	}
	// NO publish yet: st.Finalized here is the embedded checkpoint (or
	// the previous period's best-update header) — hours old in the
	// ordinary case, and outside every peer's ~128-block state window,
	// so a read aimed at it would disclose the account key to up to
	// three peers that cannot answer it. An anchor becomes readable
	// only once a finality poll has VERIFIED it (below), which is also
	// what makes snapread's "the anchor is the fresh head" claim true.
	for ctx.Err() == nil {
		published := false
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
		e.mu.Unlock()
		if a != nil {
			attempt(a)
		}
		select {
		case <-ctx.Done():
			return nil, &ReadError{Reason: ctx.Err(), LastAttempt: lastAttempt}
		case <-e.dead:
			// Ctrl-C closes both arms' race honestly (the old main
			// loop's rule): the LC loop ends with context.Canceled
			// exactly when ctx ends too, and select picks randomly —
			// shutdown is the clean path, never a failure, and library
			// consumers (StartLC's promise) must not have to re-check
			// ctx to know that.
			if ctx.Err() != nil {
				return nil, &ReadError{Reason: ctx.Err(), LastAttempt: lastAttempt}
			}
			// The LC gave up (bootstrap/catch-up refused within the
			// budget): the read can never be VERIFIED, so the wait
			// fails too — a verified read is the only success this
			// engine knows.
			e.mu.Lock()
			err := e.lcErr
			e.mu.Unlock()
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
	if e.disc != nil { // StartNetwork may never have run
		table, live, bySource = e.disc.Stats()
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
		if e.disc != nil { // New-then-Close without StartNetwork
			e.disc.Close()
		}
		e.dial.close()
		// Wait for the LC goroutine's defer (h.Close, the libp2p host)
		// before claiming release: an embedded host that restarts the
		// engine must not find the old host still listening. Bounded —
		// the loop's waits are all cancellable on this very ctx.
		e.mu.Lock()
		started := e.lcStarted
		e.mu.Unlock()
		if started {
			<-e.lcDone
		}
	})
}
