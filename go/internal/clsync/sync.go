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
	ma "github.com/multiformats/go-multiaddr"
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

	peersMu sync.Mutex
	peers   map[peer.ID]*peerState
	order   []peer.ID

	procMu sync.Mutex
	store  *lc.Store
}

func NewSyncer(c *chain.Consensus, h host.Host, logf func(string, ...any)) *Syncer {
	s := &Syncer{Consensus: c, H: h, Logf: logf, peers: map[peer.ID]*peerState{}}
	if s.Logf == nil {
		s.Logf = func(string, ...any) {}
	}
	for _, m := range MainnetStaticPeers {
		pi, err := peer.AddrInfoFromP2pAddr(maMust(m))
		if err != nil {
			continue
		}
		s.AddPeer(*pi)
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
	return clwire.CurrentForkDigest(s.Consensus, time.Now().Unix())
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
	if s.H.Network().Connectedness(p.info.ID) == network.Connected && p.statused {
		return nil
	}
	st, err := ExchangeStatus(ctx, s.H, p.info, s.LocalStatus())
	if err != nil {
		p.statused = false
		return err
	}
	p.earliest = st.EarliestAvailableSlot
	p.statused = true
	return nil
}

// checkStartGate is weak-subjectivity layer 1: refuse a cold start
// whose anchor period is more than the bound behind the wall period.
func (s *Syncer) checkStartGate() error {
	wall := s.Consensus.SlotAt(time.Now().Unix())
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
		p.statused = false
		if err := s.ensureStatus(ctx, p); err != nil {
			s.Logf("bootstrap: status with %s failed: %v", p.info.ID, err)
			lastErr = err
			continue
		}
		resp, err := Request(ctx, s.H, p.info, clwire.Bootstrap, req, respTimeout)
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
	peers := s.peerList()
	if len(peers) == 0 {
		return nil, false
	}
	startSlot := startPeriod * chain.SlotsPerSyncCommitteePeriod
	for i := range peers {
		p := peers[(round+i)%len(peers)]
		if p.earliest == 0 || p.earliest <= startSlot {
			return p, true
		}
	}
	return peers[round%len(peers)], false
}

// RunCatchUp walks periods forward with updates_by_range until the
// store's committee period reaches the wall period. Per docs/spec/01
// §9.6 the ask starts at storePeriod+1 and is capped at 128 periods;
// multi-chunk timeouts use the 60 s updates budget. Every applied
// update goes through the SAME processor the corpus pins (period gate
// before BLS), and force-rotation uses the wall-clock slot estimate.
func (s *Syncer) RunCatchUp(ctx context.Context, store *lc.Store) error {
	round := 0
	for {
		wallSlot := s.Consensus.SlotAt(time.Now().Unix())
		wallPeriod := chain.SyncCommitteePeriod(wallSlot)
		if store.Period() >= wallPeriod {
			return nil
		}
		if round++; round > maxCatchUpRounds {
			return fmt.Errorf("clsync: catch-up stalled at period %d (wall %d)", store.Period(), wallPeriod)
		}
		start := store.Period() + 1
		count := min(wallPeriod-store.Period(), 128)
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
		resp, err := Request(ctx, s.H, p.info, clwire.UpdatesByRange, req, updatesTimeout)
		if err != nil {
			s.Logf("catch-up: ask %s +%d×%d failed: %v", p.info.ID, start, count, err)
			continue
		}
		chunks, err := clwire.DecodeMultiChunk(resp, int(count))
		if err != nil {
			s.Logf("catch-up: %s batch undecodable: %v", p.info.ID, err)
			continue
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

// PollFinality asks one peer for the current finality update and runs
// it through ProcessFinalityUpdate — which rotates committees on
// period crossings and reports Advanced only when the store moved
// (the stalled-server fix: a verified-but-stale answer must not count
// as the win). Returns the outcome for the caller's bookkeeping.
func (s *Syncer) PollFinality(ctx context.Context, store *lc.Store) (lc.FinalityOutcome, error) {
	var lastErr error
	for _, p := range s.peerList() {
		if err := s.ensureStatus(ctx, p); err != nil {
			lastErr = err
			continue
		}
		// finality_update requests carry NO bytes (write nothing,
		// half-close) — nil request body.
		resp, err := Request(ctx, s.H, p.info, clwire.FinalityUpdate, nil, respTimeout)
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
		return outcome, nil
	}
	return lc.Rejected, lastErr
}

// maMust parses a multiaddr literal (all ours are constants checked at
// package init by the tests).
func maMust(s string) ma.Multiaddr {
	a, err := ma.NewMultiaddr(s)
	if err != nil {
		panic(err)
	}
	return a
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
		resp, err := Request(ctx, s.H, p.info, clwire.UpdatesByRange, req, updatesTimeout)
		if err != nil {
			s.Logf("probe: %s: %v", p.info.ID, err)
			continue
		}
		chunks, err := clwire.DecodeMultiChunk(resp, int(n))
		if err != nil {
			s.Logf("probe: %s: batch undecodable: %v", p.info.ID, err)
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
