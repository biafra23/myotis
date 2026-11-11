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
	info     peer.AddrInfo
	earliest uint64 // from Status (0 = unknown)
	used     int
}

// Syncer runs the light-client loop over a peer pool. It owns no
// goroutines: callers drive RunBootstrap/RunCatchUp/PollFinality.
type Syncer struct {
	Consensus *chain.Consensus
	H         host.Host
	Logf      func(string, ...any)
	peersMu   sync.Mutex
	peers     map[peer.ID]*peerState
	order     []peer.ID
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

// ourStatus is what ExchangeStatus sends first. Head/finalized are the
// wall-clock view (the store's own finalized head is filled in by the
// caller once one exists); digest + slot is what peers actually gate on.
func (s *Syncer) ourStatus() *clwire.StatusMessage {
	wall := time.Now().Unix()
	return &clwire.StatusMessage{
		ForkDigest:     clwire.CurrentForkDigest(s.Consensus, wall),
		FinalizedEpoch: s.Consensus.SlotAt(wall) / chain.SlotsPerEpoch,
		HeadSlot:       s.Consensus.SlotAt(wall),
	}
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
		status, err := ExchangeStatus(ctx, s.H, p.info, s.ourStatus())
		if err != nil {
			s.Logf("bootstrap: status with %s failed: %v", p.info.ID, err)
			lastErr = err
			continue
		}
		p.earliest = status.EarliestAvailableSlot
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
		s.Logf("bootstrap ok from %s: slot %d period %d", p.info.ID,
			boot.Header.Beacon.Slot, store.Period())
		return store, nil
	}
	return nil, fmt.Errorf("clsync: bootstrap exhausted all peers: %w", lastErr)
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
		peer := s.peerList()[round%s.numPeers()]
		req := clwire.EncodeUpdatesByRangeRequest(start, uint64(count))
		resp, err := Request(ctx, s.H, peer.info, clwire.UpdatesByRange, req, updatesTimeout)
		if err != nil {
			s.Logf("catch-up: ask %s +%d×%d failed: %v", peer.info.ID, start, count, err)
			continue
		}
		chunks, err := clwire.DecodeMultiChunk(resp, int(count))
		if err != nil {
			s.Logf("catch-up: %s batch undecodable: %v", peer.info.ID, err)
			continue
		}
		applied := 0
		for _, ch := range chunks {
			u, err := lc.DecodeUpdate(ch.Payload)
			if err != nil {
				s.Logf("catch-up: %s update undecodable: %v", peer.info.ID, err)
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
		s.Logf("catch-up: %s +%d×%d → %d/%d applied, store period %d, finalized slot %d",
			peer.info.ID, start, count, applied, len(chunks), store.Period(), store.Finalized.Slot)
		if applied == 0 {
			time.Sleep(time.Second) // pace the retry, don't hammer
		}
	}
}

func (s *Syncer) numPeers() int {
	if n := len(s.peerList()); n > 0 {
		return n
	}
	return 1
}

// PollFinality asks one peer for the current finality update and runs
// it through ProcessFinalityUpdate — which rotates committees on
// period crossings and reports Advanced only when the store moved
// (the stalled-server fix: a verified-but-stale answer must not count
// as the win). Returns the outcome for the caller's bookkeeping.
func (s *Syncer) PollFinality(ctx context.Context, store *lc.Store) (lc.FinalityOutcome, error) {
	var lastErr error
	for _, p := range s.peerList() {
		if _, err := ExchangeStatus(ctx, s.H, p.info, s.ourStatus()); err != nil {
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
		outcome, err := store.ProcessFinalityUpdate(u)
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
		s.Logf("probe: %s asked %d periods from %d: %d chunks, %d decoded, %d period-gated, %d other-rejects, %d applied",
			p.info.ID, n, start, len(chunks), decoded, periodGated, otherRejects, applied)
	}
}
