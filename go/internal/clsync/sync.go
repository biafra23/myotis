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
}

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
	if chain.WsAnchorStale(chain.SyncCommitteePeriod(s.Consensus.CheckpointSlot),
		chain.SyncCommitteePeriod(wall), chain.WsBoundPeriods) {
		return fmt.Errorf("%w: checkpoint period %d, wall period %d, bound %d",
			ErrStaleAnchor, chain.SyncCommitteePeriod(s.Consensus.CheckpointSlot),
			chain.SyncCommitteePeriod(wall), chain.WsBoundPeriods)
	}
	return nil
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
	for _, p := range s.peerList() {
		if err := ctx.Err(); err != nil {
			return nil, err
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
	return nil, fmt.Errorf("clsync: bootstrap exhausted all peers: %w", lastErr)
}

// pickPeer round-robins through ONE snapshot (no double-snapshot race)
// and skips peers whose advertised earliest_available_slot proves they
// pruned the asked range (0-earliest semantics: earliest > the period
// range's start slot means "cannot answer"). A pool where everyone is
// skipped still serves the round-robin pick rather than stalling — the
// skip is a preference, as in the Rust candidate tiering (#291).
func (s *Syncer) pickPeer(round int, startPeriod uint64) (*peerState, bool) {
	// One lock = one snapshot: indexing and the earliest reads all see
	// the same world (the pre-fix version took a snapshot, released the
	// lock, and could panic or read a torn list; the earliest reads also
	// race the Disconnected notifiee otherwise).
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	n := len(s.order)
	if n == 0 {
		return nil, false
	}
	startSlot := startPeriod * chain.SlotsPerSyncCommitteePeriod
	for i := range n {
		p := s.peers[s.order[(round+i)%n]]
		if p.earliest == 0 || p.earliest <= startSlot {
			return p, true
		}
	}
	return s.peers[s.order[round%n]], false
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
		if round++; round > maxCatchUpRounds {
			return fmt.Errorf("clsync: catch-up stalled at period %d (wall %d)", store.Period(), wallPeriod)
		}
		// Weak subjectivity, in-run layer (§9.6 layer 3, sync.rs:2496-2523):
		// a committee held in memory ages exactly like one on disk, so a
		// long-running sync that fell WsBoundPeriods behind must stop
		// walking forward on it, not hand off through past-bound
		// committees when peers finally answer.
		if chain.WsAnchorStale(store.Period(), wallPeriod, chain.WsBoundPeriods) {
			return fmt.Errorf("%w: held committee period %d, wall period %d, bound %d",
				ErrStaleAnchor, store.Period(), wallPeriod, chain.WsBoundPeriods)
		}
		start := store.Period()
		count := min(wallPeriod-store.Period(), clwire.MaxUpdatesByRange)
		p, served := s.pickPeer(round, start)
		if p == nil {
			return errors.New("clsync: catch-up has no peers")
		}
		if !served {
			s.Logf("catch-up: all peers pruned before period %d; asking %s anyway", start, p.info.ID)
		}
		if err := s.ensureStatus(ctx, p); err != nil {
			s.Logf("catch-up: status with %s failed: %v", p.info.ID, err)
			continue
		}
		req := clwire.EncodeUpdatesByRangeRequest(start, uint64(count))
		resp, err := RequestOnConn(ctx, s.H, p.info, clwire.UpdatesByRange, req, updatesTimeout)
		if err != nil && len(resp) == 0 {
			s.Logf("catch-up: ask %s +%d×%d failed: %v", p.info.ID, start, count, err)
			continue
		}
		chunks, derr := clwire.DecodeMultiChunk(resp, int(count))
		if derr != nil && len(chunks) == 0 {
			s.Logf("catch-up: %s batch undecodable: %v", p.info.ID, derr)
			continue
		}
		if derr != nil || err != nil {
			s.Logf("catch-up: %s answer truncated (%v); salvaging %d whole chunks", p.info.ID, derr, len(chunks))
		}
		applied := 0
		s.procMu.Lock()
		for _, ch := range chunks {
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
			time.Sleep(time.Second) // pace the retry, don't hammer
		}
	}
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
