package clsync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clwire"
	"github.com/biafra23/myotis/go/internal/lc"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ErrStaleAnchor is the weak-subjectivity start gate (docs/spec/01
// §9.6 layer 1): the embedded checkpoint is more than WsBoundPeriods
// periods behind the wall clock, so a cold start cannot bootstrap
// trustlessly. The Go engine refuses — no silent trust relaxation.
var ErrStaleAnchor = errors.New("clsync: checkpoint anchor is past the weak-subjectivity bound")

// maxCatchUpRounds bounds the catch-up loop so a starved engine exits
// with an error instead of spinning (the Rust loop has fan-out/strike
// machinery; the minimal Go loop bounds wall effort instead).
const maxCatchUpRounds = 24

type peerState struct {
	info peer.AddrInfo
	// earliest is the peer's earliest_available_slot from Status
	// (0 = unknown): a server that pruned older history. The catch-up
	// loop skips peers that provably cannot answer the asked range.
	earliest uint64
	// statused marks "Status exchanged on the CURRENT connection" —
	// cleared implicitly by tracking Connectedness (see ensureStatus).
	statused bool
	// singlePeriod marks a peer learned to answer
	// updates_by_range(count>1) with a truncated stream — Lighthouse
	// closes the stream after the first chunk (~30 ms), because a
	// count=N ask costs N request tokens against a 1-token/10 s rate
	// bucket (the same behavior the Rust twin documents in sync.rs,
	// which is why it asks Lighthouse one period at a time). Such a
	// peer is worth asking, just not with a batch: the catch-up loop
	// drops the count to 1 for it.
	singlePeriod bool
	// coolUntil is when the next ask to this peer may start (see
	// singlePeriodCooldown): the Rust twin's ~11 s between asks to a
	// single-period server, so a pool of rate-limited pins is walked
	// at their pace instead of re-hammering one server per round.
	coolUntil time.Time
}

// singlePeriodCooldown is the minimum spacing between asks to a peer
// learned to be a single-period server (see peerState.singlePeriod);
// the Rust twin's Lighthouse loop uses ~11 s for exactly the token
// bucket cited there.
const singlePeriodCooldown = 11 * time.Second

// Syncer runs the light-client loop over a peer pool. It owns the
// store: RunBootstrap installs it, the loops mutate it, and
// LocalStatus reads it — all through these methods, under procMu, so
// the inbound Status responder never sees a torn store (PR #769
// review: main used to write the store pointer unlocked).
type Syncer struct {
	Consensus *chain.Consensus
	H         host.Host
	Logf      func(string, ...any)
	// Now is the wall clock. Injectable (defaults to time.Now) because
	// the whole point of the corpus in rust/testdata/lc is that the
	// chain walk is reproducible: RunCatchUp's exit condition, the
	// force-rotate slot and the weak-subjectivity checks all read
	// wall time, and a test that replays the corpus must control it
	// (expected.txt's input.currentSlotEstimate is that input).
	Now func() time.Time

	// WsBound overrides the weak-subjectivity bound (periods), read
	// LIVE at every gate: myotis_set_ws_bound_periods promises that a
	// handle parked past the bound "re-evaluates within a second",
	// which needs the gate to consult the setter rather than a value
	// captured at construction. nil → chain.WsBoundPeriods (the
	// network default). Values < 1 fall back to the default too (a
	// bound of 0 periods would refuse every anchor including a fresh
	// one; the C ABI's 0 means "restore the default").
	WsBound func() uint64
	// StaleAccepted is the host's one-shot consent to the embedded
	// anchor's age (myotis_accept_stale_anchor). True suppresses the
	// ErrStaleAnchor refusals — the start gate and the in-run layer —
	// for the rest of the loop's life, exactly as the contract says
	// ("for the rest of this run; never persisted"). nil → never.
	StaleAccepted func() bool

	peersMu   sync.Mutex
	peers     map[peer.ID]*peerState
	order     []peer.ID
	pollRound int // rotates which peer is asked first

	procMu sync.Mutex
	store  *lc.Store
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// boundPeriods is the weak-subjectivity bound IN FORCE right now —
// the live override if one is set, the network default otherwise
// (0/negative means "no override" per the WsBound field's contract).
func (s *Syncer) boundPeriods() uint64 {
	if s.WsBound != nil {
		if b := s.WsBound(); b >= 1 {
			return b
		}
	}
	return chain.WsBoundPeriods
}

// staleAccepted reports the host's consent to anchor age, if any.
func (s *Syncer) staleAccepted() bool {
	return s.StaleAccepted != nil && s.StaleAccepted()
}

// staleGate is the ONE weak-subjectivity check both layers share
// (start gate + in-run layer): refused unless the host consented to
// the age, and judged against the bound in force at this instant.
func (s *Syncer) staleGate(anchorPeriod, wallPeriod uint64, what string) error {
	if s.staleAccepted() {
		return nil
	}
	if chain.WsAnchorStale(anchorPeriod, wallPeriod, s.boundPeriods()) {
		return fmt.Errorf("%w: %s period %d, wall period %d, bound %d",
			ErrStaleAnchor, what, anchorPeriod, wallPeriod, s.boundPeriods())
	}
	return nil
}

func NewSyncer(c *chain.Consensus, h host.Host, logf func(string, ...any)) *Syncer {
	s := &Syncer{Consensus: c, H: h, Logf: logf, peers: map[peer.ID]*peerState{}}
	if s.Logf == nil {
		s.Logf = func(string, ...any) {}
	}
	// A connection that dies silently (idle drop, peer close not yet
	// observed — nothing keep-alives us with identify off) must never
	// be treated as "already statused": the next Request would re-dial
	// internally and send light-client requests over a brand-new
	// connection without the mandatory Status. Clearing the flag on
	// Disconnected is the event-driven half of the Rust twin's
	// per-ConnectionEstablished Status (reqresp.rs:1680-1688); the
	// other half is ensureStatus re-exchanging whenever Connectedness
	// says not-connected.
	h.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(_ network.Network, conn network.Conn) {
			s.peersMu.Lock()
			if p, ok := s.peers[conn.RemotePeer()]; ok {
				p.statused = false
			}
			s.peersMu.Unlock()
		},
	})
	for _, m := range MainnetStaticPeers {
		a, err := parseMultiaddr(m)
		if err != nil {
			s.Logf("static peer %s: unparseable multiaddr: %v", m, err)
			continue
		}
		pi, err := peerAddrInfo(a)
		if err != nil {
			s.Logf("static peer %s: %v", m, err)
			continue
		}
		s.AddPeer(pi)
	}
	return s
}

// AddPeer admits a discovered or pinned peer (dedup by ID).
func (s *Syncer) AddPeer(info peer.AddrInfo) {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	if _, ok := s.peers[info.ID]; ok {
		return
	}
	s.peers[info.ID] = &peerState{info: info}
	s.order = append(s.order, info.ID)
}

// PeerCount is the admitted libp2p peer count, for status surfaces
// (the Rust status' "peerCount" is the light-client peer count, not
// the EL pool's).
func (s *Syncer) PeerCount() int {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	return len(s.peers)
}

// peerList returns a stable snapshot; callers must index THIS slice
// (the PR #769 review caught a double-snapshot that could panic when
// AddPeer grew the list between two calls).
func (s *Syncer) peerList() []*peerState {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	out := make([]*peerState, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.peers[id])
	}
	return out
}

// ourDigest recomputes the accepted fork digest from the wall clock:
// the ENR/Status filter follows the fork schedule without a restart.
func (s *Syncer) ourDigest() [4]byte {
	return clwire.CurrentForkDigest(s.Consensus, s.now().Unix())
}

// LocalStatus is the Status WE announce — inbound answer and outbound
// first-exchange alike. Pre-bootstrap it is the EMBEDDED CHECKPOINT
// for both roots at the checkpoint slot, exactly as the Rust twin
// initializes (sync.rs:1377-1387): Lighthouse's relevance check
// goodbyes peers announcing zero roots, and a wall-clock slot with a
// root nobody knows fails the same check. Post-bootstrap it is the
// store's verified finalized header (BLOCK root — the header hash, not
// its state root) with the head being the newer of finalized and
// optimistic (sync.rs:4183-4197).
func (s *Syncer) LocalStatus() *clwire.StatusMessage {
	c := s.Consensus
	s.procMu.Lock()
	st := s.store
	var fin, opt *lc.BeaconBlockHeader
	if st != nil {
		fin, opt = st.Finalized, st.Optimistic
	}
	s.procMu.Unlock()

	m := &clwire.StatusMessage{ForkDigest: s.ourDigest()}
	switch {
	case fin != nil && opt != nil && opt.Slot >= fin.Slot:
		m.FinalizedRoot = fin.Root()
		m.FinalizedEpoch = fin.Slot / chain.SlotsPerEpoch
		m.HeadRoot, m.HeadSlot = opt.Root(), opt.Slot
	case fin != nil:
		m.FinalizedRoot = fin.Root()
		m.FinalizedEpoch = fin.Slot / chain.SlotsPerEpoch
		m.HeadRoot, m.HeadSlot = fin.Root(), fin.Slot
	default:
		m.FinalizedRoot = [32]byte(c.CheckpointRoot)
		m.FinalizedEpoch = c.CheckpointSlot / chain.SlotsPerEpoch
		m.HeadRoot, m.HeadSlot = [32]byte(c.CheckpointRoot), c.CheckpointSlot
	}
	return m
}

// ensureStatus guarantees the mandatory Status exchange on the
// CURRENT connection before any other request. The Rust twin sends
// Status on every ConnectionEstablished (reqresp.rs:1680-1688,
// §13.6); a re-dialed connection that skipped it can be Goodbye'd by
// the same policy this repo's own servers apply. The exchange also
// refreshes the peer's earliest_available_slot.
func (s *Syncer) ensureStatus(ctx context.Context, p *peerState) error {
	s.peersMu.Lock()
	fresh := s.H.Network().Connectedness(p.info.ID) == network.Connected && p.statused
	s.peersMu.Unlock()
	if fresh {
		return nil
	}
	// The exchange runs OUTSIDE the lock (network I/O); the Disconnected
	// notifiee may fire across it and is idempotent with this writer.
	st, err := ExchangeStatus(ctx, s.H, p.info, s.LocalStatus())
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	if err != nil {
		p.statused = false
		return err
	}
	p.earliest = st.EarliestAvailableSlot
	p.statused = true
	return nil
}

// markNotStatused forces the next ensureStatus to re-exchange (used
// before bootstrap, where every peer is treated as fresh).
func (s *Syncer) markNotStatused(p *peerState) {
	s.peersMu.Lock()
	p.statused = false
	s.peersMu.Unlock()
}

// checkStartGate is weak-subjectivity layer 1: refuse a cold start
// whose anchor period is more than the bound behind the wall period.
func (s *Syncer) checkStartGate() error {
	wall := s.Consensus.SlotAt(s.now().Unix())
	// lc.CheckpointPeriod, not an inline SyncCommitteePeriod(CheckpointSlot):
	// the anchor of all three weak-subjectivity gates gets ONE definition
	// (verify.go), so no gate can drift from it by re-deriving.
	cp := lc.CheckpointPeriod(s.Consensus)
	return s.staleGate(cp, chain.SyncCommitteePeriod(wall), "checkpoint")
}

// RunBootstrap fetches the bootstrap for the EMBEDDED checkpoint root
// and installs it only if lc.NewFromBootstrap's full §9.1 chain passes:
// the checkpoint pin (header hash == CheckpointRoot), the committee
// branch and the execution branch. First valid answer wins; every
// failure moves to the next peer (the pin is exactly what makes a
// lying answer harmless rather than merely unlikely).
func (s *Syncer) RunBootstrap(ctx context.Context) (*lc.Store, error) {
	if err := s.checkStartGate(); err != nil {
		return nil, err
	}
	req := clwire.EncodeBootstrapRequest(s.Consensus.CheckpointRoot)
	var lastErr error
	// One-SHOT peer snapshots were the bug this loop shape fixes: at
	// entry the pool holds only the static pins, while discv5's first
	// lookup lands seconds later and keeps adding eth2-filtered peers.
	// Sweeping a dead snapshot and declaring "exhausted all peers"
	// made five down pins fatal while healthy peers were still
	// arriving. So: sweep, remember whom we swept, and re-sweep the
	// pool as it grows, sleeping between empty sweeps, until the
	// caller's bootstrap budget (ctx) runs out — THAT is the real
	// deadline the callers' log.Fatalf treats as fatal.
	tried := map[peer.ID]bool{}
	// Backoff between empty sweeps. A flat 2 s re-sweep (the first fix
	// for "a pin that failed once is never re-asked") retried every
	// pin ~95 times over the 4-minute budget — the same third-party
	// Lighthouse token buckets this file paces catch-up at 11 s to
	// respect, and these nodes answer sustained over-asking with 12 h
	// IP bans (CLAUDE.md: "that ban IS #422"). Doubling to a 30 s cap
	// keeps the retry (a restarting pin returns within the window) at
	// ~a dozen asks per pin; any non-empty sweep resets it, so a pool
	// that is still GROWING (discv5 adding) is never slowed.
	backoff := 2 * time.Second
	const backoffCap = 30 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("clsync: bootstrap window ended after every peer seen (%d): %w", len(tried), lastErr)
			}
			return nil, err
		}
		swept := 0
		for _, p := range s.peerList() {
			if tried[p.info.ID] {
				continue
			}
			tried[p.info.ID] = true
			swept++
			if err := ctx.Err(); err != nil {
				break
			}
			s.markNotStatused(p)
			if err := s.ensureStatus(ctx, p); err != nil {
				s.Logf("bootstrap: status with %s failed: %v", p.info.ID, err)
				lastErr = err
				continue
			}
			resp, err := RequestOnConn(ctx, s.H, p.info, clwire.Bootstrap, req, respTimeout)
			if err != nil {
				s.Logf("bootstrap: request to %s failed: %v", p.info.ID, err)
				lastErr = err
				continue
			}
			chunk, err := clwire.DecodeResponse(resp, true)
			if err != nil {
				s.Logf("bootstrap: %s answered an error: %v", p.info.ID, err)
				lastErr = err
				continue
			}
			if err := s.checkChunkDigest(chunk.ForkDigest, "bootstrap"); err != nil {
				s.Logf("bootstrap: %s: %v", p.info.ID, err)
				lastErr = err
				continue
			}
			boot, err := lc.DecodeBootstrap(chunk.Payload)
			if err != nil {
				s.Logf("bootstrap: %s sent undecodable bytes: %v", p.info.ID, err)
				lastErr = err
				continue
			}
			store, err := lc.NewFromBootstrap(boot, lc.NewForkSchedule(s.Consensus), s.Consensus,
				s.Consensus.CheckpointRoot)
			if err != nil {
				// The pin/rejection: a peer can answer a by-root request with
				// anything; only our embedded root makes it trusted.
				s.Logf("bootstrap: %s answer rejected: %v", p.info.ID, err)
				lastErr = err
				continue
			}
			s.procMu.Lock()
			s.store = store
			s.procMu.Unlock()
			s.Logf("bootstrap ok from %s: slot %d period %d", p.info.ID,
				boot.Header.Beacon.Slot, store.Period())
			return store, nil
		}
		if swept == 0 {
			// Every known peer swept, none answered: wait to see
			// whether discovery brings more before the budget ends.
			// Then FORGET whom we swept: myotis-go -get-account and
			// plain myotis-lc never start discv5, so for them the
			// pool stays the five static pins forever and a
			// permanent tried-set would turn this window into five
			// asks and a dead wait. Transient failures (a peer
			// restarting, a dial racing its own listen port) deserve
			// the retry; this pause IS the backoff (doubled, see
			// above).
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
				tried = map[peer.ID]bool{}
				if backoff *= 2; backoff > backoffCap {
					backoff = backoffCap
				}
			}
		} else {
			// Discovery brought new peers since the last sweep: the
			// pool is growing, stay at full re-sweep pace.
			backoff = 2 * time.Second
		}
	}
}

// checkChunkDigest applies a light-client response's 4 context bytes:
// they must name a fork this build's pinned schedule can produce
// (clwire.KnownForkDigests). The Status exchange already gated the
// peer's live digest (host.go), so an unknown digest here means the
// ANSWER came from a fork past every pinned one — a wire shape this
// parser would misread into wrong values. Refused, not ignored;
// recovery needs a build that pins the newer fork, so this is a
// per-answer rejection, not a peer fault.
func (s *Syncer) checkChunkDigest(digest []byte, what string) error {
	if len(digest) != 4 {
		return fmt.Errorf("clsync: %s response carries no fork-digest context bytes", what)
	}
	var d [4]byte
	copy(d[:], digest)
	if !clwire.KnownForkDigests(s.Consensus)[d] {
		return fmt.Errorf("clsync: %s response digest %x is not any fork this build pins (refused rather than misdecoded)", what, d)
	}
	return nil
}

// pickPeer round-robins through ONE snapshot (no double-snapshot race)
// and skips peers whose advertised earliest_available_slot proves they
// pruned the asked range (0-earliest semantics: earliest > the period
// range's start slot means "cannot answer"). A pool where everyone is
// skipped still serves the round-robin pick rather than stalling — the
// skip is a preference, as in the Rust candidate tiering (#291).
// pickPeer returns the peer to ask, whether one can provably serve the
// range (false = all are pruned below startPeriod, ask anyway), and the
// time its single-period cooldown expires (zero = ask now). The caller
// MUST wait out a non-zero third return before asking — the fallback
// that returns a cooling peer when every candidate is cooling keeps
// progress possible, but querying it immediately would defeat the whole
// point of the cooldown (PR #773 review round 2: in a pool of only
// Lighthouse pins, every ask landed ~2 s after the peer's last one,
// straight into the 1-token/10 s bucket the pacing exists for).
func (s *Syncer) pickPeer(round int, startPeriod uint64) (*peerState, bool, time.Time) {
	// One lock = one snapshot: indexing and the earliest reads all see
	// the same world (the pre-fix version took a snapshot, released the
	// lock, and could panic or read a torn list; the earliest reads also
	// race the Disconnected notifiee otherwise).
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	n := len(s.order)
	if n == 0 {
		return nil, false, time.Time{}
	}
	startSlot := startPeriod * chain.SlotsPerSyncCommitteePeriod
	now := s.now()
	var cooling *peerState
	for i := range n {
		p := s.peers[s.order[(round+i)%n]]
		if p.earliest == 0 || p.earliest <= startSlot {
			// A peer inside its single-period cooldown is still a
			// valid answer for the range — it is only deprioritized
			// while a peer at full pace is available (the caller
			// drops its batch to one period for it, see RunCatchUp).
			if now.Before(p.coolUntil) {
				if cooling == nil || p.coolUntil.Before(cooling.coolUntil) {
					cooling = p // the one whose cooldown clears soonest
				}
				continue
			}
			return p, true, time.Time{}
		}
	}
	if cooling != nil {
		return cooling, true, cooling.coolUntil
	}
	return s.peers[s.order[round%n]], false, time.Time{}
}

// RunCatchUp walks periods forward with updates_by_range until the
// store's committee period reaches the wall period. The ask starts at
// the store's OWN committee period — not +1 (PR #770 review): the
// first update the walk needs is the one for the store's own period,
// because it is the only thing that can deliver next_sync_committee
// for P+1, and a bootstrap never carries one. The Rust twin says it
// directly ("Start from the committee's own period, NOT the finalized
// slot's", sync.rs:3186-3199); docs/spec/01 §9.6 ("from the store's
// committee period") and the corpus itself agree (bootstrap at period
// 1777, the accepted chain 1777→1795, the Java golden request
// updates_by_range(1777,16)). Asking +1 could never apply anything:
// every answer is signed in a period whose committee the store does
// not hold, so it would period-gate forever.
//
// The batch is capped at MaxUpdatesByRange periods, multi-chunk reads
// get the 60 s updates budget, and a read that dies mid-batch keeps
// the prefix that arrived (each applied update advances the store on
// its own — a partial batch is progress). Every applied update goes
// through the SAME processor the corpus pins (period gate before BLS);
// force-rotation uses the wall-clock slot estimate.
func (s *Syncer) RunCatchUp(ctx context.Context, store *lc.Store) error {
	round := 0
	for {
		wallSlot := s.Consensus.SlotAt(s.now().Unix())
		wallPeriod := chain.SyncCommitteePeriod(wallSlot)
		if store.Period() >= wallPeriod {
			return nil
		}
		if round >= maxCatchUpRounds {
			return fmt.Errorf("clsync: catch-up stalled at period %d (wall %d)", store.Period(), wallPeriod)
		}
		// Weak subjectivity, in-run layer (§9.6 layer 3, sync.rs:2496-2523):
		// a committee held in memory ages exactly like one on disk, so a
		// long-running sync that fell WsBoundPeriods behind must stop
		// walking forward on it, not hand off through past-bound
		// committees when peers finally answer.
		if err := s.staleGate(store.Period(), wallPeriod, "held committee"); err != nil {
			return err
		}
		start := store.Period()
		count := min(wallPeriod-store.Period(), clwire.MaxUpdatesByRange)
		// `round` indexes the rotation and is incremented AFTER the
		// pick, so the first ask goes to order[0] — roost, the one
		// pin that serves real batches. Pre-incrementing started the
		// walk at order[1], asking roost only in the fifth round,
		// straight into the Lighthouse pins that truncate a
		// multi-period ask to one chunk.
		p, served, coolUntil := s.pickPeer(round, start)
		round++
		if p == nil {
			return errors.New("clsync: catch-up has no peers")
		}
		if !served {
			s.Logf("catch-up: all peers pruned before period %d; asking %s anyway", start, p.info.ID)
		}
		if p.singlePeriod {
			count = 1 // one period per ask — a batch it would truncate anyway
		}
		if wait := coolUntil.Sub(s.now()); wait > 0 {
			// Every candidate is mid-rate-limit: this is THE case the
			// cooldown exists for (a pool of nothing but Lighthouse
			// pins), so wait for the soonest one to clear instead of
			// asking it ~2 s after its last ask.
			s.Logf("catch-up: every candidate rate-spacing; waiting %s for %s",
				wait.Round(time.Second), p.info.ID)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if p.singlePeriod {
			// Re-space the NEXT ask to this peer from now (the pick
			// above only paced this one).
			s.markSinglePeriod(p)
		}
		if err := s.ensureStatus(ctx, p); err != nil {
			s.Logf("catch-up: status with %s failed: %v", p.info.ID, err)
			s.pause(ctx)
			continue
		}
		req := clwire.EncodeUpdatesByRangeRequest(start, uint64(count))
		resp, err := RequestOnConn(ctx, s.H, p.info, clwire.UpdatesByRange, req, updatesTimeout)
		if err != nil && len(resp) == 0 {
			s.Logf("catch-up: ask %s +%d×%d failed: %v", p.info.ID, start, count, err)
			s.pause(ctx)
			continue
		}
		chunks, derr := clwire.DecodeMultiChunk(resp, int(count))
		if derr != nil && len(chunks) == 0 {
			s.Logf("catch-up: %s batch undecodable: %v", p.info.ID, derr)
			s.pause(ctx)
			continue
		}
		if derr != nil || err != nil {
			s.Logf("catch-up: %s answer truncated (%v); salvaging %d whole chunks", p.info.ID, derr, len(chunks))
			if count > 1 {
				// The close-mid-batch IS the server class: a
				// Lighthouse node ends a multi-count stream after
				// the first chunk because count=N asks cost N
				// tokens against its 1-token/10 s bucket (the Rust
				// twin asks those pins one period at a time for
				// exactly this). Learn it once instead of paying a
				// truncation per batch, and space the asks.
				s.markSinglePeriod(p)
				s.Logf("catch-up: %s is a single-period server: one period per ask, %s apart",
					p.info.ID, singlePeriodCooldown)
			}
		}
		applied := 0
		s.procMu.Lock()
		for _, ch := range chunks {
			if err := s.checkChunkDigest(ch.ForkDigest[:], "updates-by-range"); err != nil {
				s.Logf("catch-up: %s: %v", p.info.ID, err)
				continue
			}
			u, err := lc.DecodeUpdate(ch.Payload)
			if err != nil {
				s.Logf("catch-up: %s update undecodable: %v", p.info.ID, err)
				continue
			}
			if err := store.ProcessUpdate(u); err != nil {
				// A rejected update is a peer problem, not a store
				// problem: the gates verified nothing false.
				s.Logf("catch-up: update (sig slot %d) rejected: %v", u.SignatureSlot, err)
				continue
			}
			applied++
			store.ForceRotateIfPastPeriod(wallSlot)
		}
		s.procMu.Unlock()
		s.Logf("catch-up: %s +%d×%d → %d/%d applied, store period %d, finalized slot %d",
			p.info.ID, start, count, applied, len(chunks), store.Period(), store.Finalized.Slot)
		if applied == 0 {
			s.pause(ctx) // pace the retry, don't hammer
		}
	}
}

// pause spaces the catch-up retries without ignoring cancellation —
// the loop's failure arms run against peers that may be down for the
// window, and a tight retry loop hammers them (and outlives the
// caller's budget) exactly when nothing is working.
func (s *Syncer) pause(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
}

// markSinglePeriod records that p is a single-period server (see
// peerState.singlePeriod) and re-spaces its next ask. Locks peersMu
// like every other peerState mutation.
func (s *Syncer) markSinglePeriod(p *peerState) {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	p.singlePeriod = true
	p.coolUntil = s.now().Add(singlePeriodCooldown)
}

// PollFinality reads the current finality update from the peer pool —
// one round over ALL of them, matching the Rust round's shape
// (sync.rs:3976-3988): `Advanced` from the first peer that moves the
// store ends the round; a `Stale` answer (verified, but behind what
// the store holds) is NOT a win — the round keeps reading, because a
// current server may still answer. Returning on the first verified
// answer was the stalled-relay trap the roost carve-out names
// ("Withholding is a liveness attack and this concentrates it"): the
// pool is walked in a fixed order, so one server serving an
// old-but-valid update would pin every poll to `Stale` while the
// healthy pins went unasked. The start index rotates per poll so no
// single pin carries every request. `Stale` is reported only when
// somebody verified and nobody advanced; `Rejected` + the last error
// when nothing verified.
func (s *Syncer) PollFinality(ctx context.Context, store *lc.Store) (lc.FinalityOutcome, error) {
	peers := s.peerList()
	if len(peers) == 0 {
		return lc.Rejected, errors.New("clsync: no peers to poll")
	}
	s.peersMu.Lock()
	rot := s.pollRound % len(peers)
	s.pollRound++
	s.peersMu.Unlock()

	var lastErr error
	verified := false
	for i := range peers {
		p := peers[(rot+i)%len(peers)]
		if err := ctx.Err(); err != nil {
			return lc.Rejected, err
		}
		if err := s.ensureStatus(ctx, p); err != nil {
			lastErr = err
			continue
		}
		// finality_update requests carry NO bytes (write nothing,
		// half-close) — nil request body.
		resp, err := RequestOnConn(ctx, s.H, p.info, clwire.FinalityUpdate, nil, respTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		chunk, err := clwire.DecodeResponse(resp, true)
		if err != nil {
			lastErr = err
			continue
		}
		if err := s.checkChunkDigest(chunk.ForkDigest, "finality-update"); err != nil {
			lastErr = err
			continue
		}
		u, err := lc.DecodeFinalityUpdate(chunk.Payload)
		if err != nil {
			lastErr = err
			continue
		}
		s.procMu.Lock()
		outcome, err := store.ProcessFinalityUpdate(u)
		s.procMu.Unlock()
		if err != nil {
			lastErr = err
			continue
		}
		if outcome == lc.Advanced {
			return lc.Advanced, nil
		}
		verified = true // Stale: not a win, not a strike — keep reading
	}
	if verified {
		return lc.Stale, nil
	}
	return lc.Rejected, lastErr
}

// ProbeUpdates asks every known peer for the last n periods of
// updates_by_range and reports, per peer, how many chunks arrived and
// what the processor did with them. Used by the -probe-range flag when
// catch-up has nothing to do: a fresh checkpoint lands inside the
// current period, so without a probe the multi-chunk wire path would
// never touch a live server in a smoke run. Rejections by the period
// gate are the EXPECTED outcome for pre-store periods — the probe
// counts them, it does not fail on them.
func (s *Syncer) ProbeUpdates(ctx context.Context, store *lc.Store, n uint64) {
	start := store.Period()
	if start >= n {
		start -= n
	} else {
		start = 0
	}
	req := clwire.EncodeUpdatesByRangeRequest(start, n)
	for _, p := range s.peerList() {
		if err := s.ensureStatus(ctx, p); err != nil {
			s.Logf("probe: %s status: %v", p.info.ID, err)
			continue
		}
		resp, err := RequestOnConn(ctx, s.H, p.info, clwire.UpdatesByRange, req, updatesTimeout)
		if err != nil && len(resp) == 0 {
			s.Logf("probe: %s: %v", p.info.ID, err)
			continue
		}
		chunks, derr := clwire.DecodeMultiChunk(resp, int(n))
		if derr != nil && len(chunks) == 0 {
			s.Logf("probe: %s: batch undecodable: %v", p.info.ID, derr)
			continue
		}
		var decoded, periodGated, otherRejects, applied int
		s.procMu.Lock()
		for _, ch := range chunks {
			if err := s.checkChunkDigest(ch.ForkDigest[:], "probe updates"); err != nil {
				continue
			}
			u, err := lc.DecodeUpdate(ch.Payload)
			if err != nil {
				s.Logf("probe: %s: update undecodable: %v", p.info.ID, err)
				continue
			}
			decoded++
			if err := store.ProcessUpdate(u); err != nil {
				if errors.Is(err, lc.ErrPeriodGate) {
					periodGated++
				} else {
					otherRejects++
					s.Logf("probe: %s: non-period-gate rejection: %v", p.info.ID, err)
				}
				continue
			}
			applied++
		}
		s.procMu.Unlock()
		s.Logf("probe: %s asked %d periods from %d: %d chunks, %d decoded, %d period-gated, %d other-rejects, %d applied",
			p.info.ID, n, start, len(chunks), decoded, periodGated, otherRejects, applied)
	}
}
