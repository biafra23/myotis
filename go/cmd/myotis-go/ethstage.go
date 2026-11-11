package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/discovery"
	"github.com/biafra23/myotis/go/internal/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

const (
	targetEthPeers     = 2
	maxConcurrentDials = 5
	headerSample       = 16 // headers fetched to prove the read path
	// Public mainnet nodes reject random inbound as full (geth
	// DiscTooManyPeers, reason 0x04) as a matter of course — landing two
	// slots anywhere is a throughput game against the pool discovery keeps
	// growing.
	dialRetryEvery = 3 * time.Minute
	dialTick       = 2 * time.Second
	// The candidate pool's size cap. Pruning is by SIZE, not by age since
	// last dial: an age rule misfires exactly in the success case (ready
	// set full for an hour → every tried candidate is "stale" at once and
	// the peers known to work are the first forgotten).
	maxCandidates = 256
	// A just-disconnected ready peer is kept in the pool this long past
	// its last ready moment even when the pool is over the cap.
	keepReadyGrace = 10 * time.Minute
	// Dial backoff: a candidate that keeps failing is retried after
	// dialRetryEvery * 2^(attempts-1), capped here — otherwise an
	// unreachable top-priority node monopolises slots ahead of untried
	// ones forever (attempts was counted but never fed back).
	maxDialRetryEvery = 30 * time.Minute
)

type dialCandidate struct {
	node     *enode.Node
	priority int // lower dials first; refreshed when discovery re-offers from a better source
	lastDial time.Time
	attempts int
	// lastReady is when this peer last held a ready slot (0 never).
	// A peer that just worked is the most valuable entry in the pool —
	// pruning must not forget it first.
	lastReady time.Time
}

// ethStage keeps a small set of READY eth peers by dialing discovered
// candidates (evicting them when they die, which eth peers do routinely),
// and drives one verified backward header chain read from the first peer
// that stays up long enough (retried through later peers if one fails).
type ethStage struct {
	key  *ecdsa.PrivateKey
	netw *chain.Network
	log  *slog.Logger

	mu         sync.Mutex
	cands      map[enode.ID]*dialCandidate
	ready      map[enode.ID]*eth.Peer
	dialing    map[enode.ID]bool
	proving    bool
	chainDone  bool
	proofTried map[enode.ID]bool // peers already given (and failed) the proof
}

func newEthStage(key *ecdsa.PrivateKey, netw *chain.Network, log *slog.Logger) *ethStage {
	return &ethStage{
		key:        key,
		netw:       netw,
		log:        log.With("component", "eth"),
		cands:      map[enode.ID]*dialCandidate{},
		ready:      map[enode.ID]*eth.Peer{},
		dialing:    map[enode.ID]bool{},
		proofTried: map[enode.ID]bool{},
	}
}

// offer records a discovered candidate (cheap; called from discovery
// callbacks). A candidate that moved — or whose SOURCE was upgraded (the
// table proved an endpoint the DNS tree only sampled; discovery re-fires on
// a rank increase) — refreshes its record, including the dial priority:
// "proven before sampled" must win even when the sample arrived first.
func (e *ethStage) offer(c discovery.Candidate) {
	if c.Node.TCP() == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if old, ok := e.cands[c.ID]; ok {
		old.node = c.Node // endpoint may have been refreshed
		if p := -discovery.SourceRank(c.Source); p < old.priority {
			old.priority = p
		}
		return
	}
	// Same ordering the discovery pool uses for endpoint precedence
	// (liveness-proven discv4 > lookup-seen > DNS): negate its rank.
	e.cands[c.ID] = &dialCandidate{node: c.Node, priority: -discovery.SourceRank(c.Source)}
}

// run dials until ctx ends. Close must be called to release peers.
func (e *ethStage) run(ctx context.Context) {
	tick := time.NewTicker(dialTick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := time.Now()
			e.pruneCandidates(now)
			for _, c := range e.pickDials(now) {
				go e.dial(ctx, c)
			}
		}
	}
}

// pickDials fills the free dial slots best-first with not-recently-tried
// candidates and marks them dialed-now (so one tick cannot double-dial).
// The slot budget is the dial concurrency, not the ready target — with
// public peers rejecting most dials, several must be in flight while the
// ready set is still short.
func (e *ethStage) pickDials(now time.Time) []*enode.Node {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.ready) >= targetEthPeers {
		return nil
	}
	slots := maxConcurrentDials - len(e.dialing)
	if slots <= 0 {
		return nil
	}
	var pool []*dialCandidate
	for id, c := range e.cands {
		if e.ready[id] != nil || e.dialing[id] {
			continue
		}
		if !c.lastDial.IsZero() && now.Sub(c.lastDial) < retryAfter(c.attempts) {
			continue
		}
		pool = append(pool, c)
	}
	sort.SliceStable(pool, func(i, j int) bool {
		if pool[i].priority != pool[j].priority {
			return pool[i].priority < pool[j].priority
		}
		return pool[i].lastDial.Before(pool[j].lastDial)
	})
	var out []*enode.Node
	for _, c := range pool {
		if len(out) >= slots {
			break
		}
		c.lastDial = now
		c.attempts++
		e.dialing[c.node.ID()] = true
		out = append(out, c.node)
	}
	return out
}

// retryAfter is the exponential backoff for a candidate with `attempts`
// failed dials: dialRetryEvery * 2^(attempts-1), capped at
// maxDialRetryEvery. Fresh (never dialed) candidates are always due.
func retryAfter(attempts int) time.Duration {
	if attempts <= 0 {
		return 0
	}
	d := dialRetryEvery
	for i := 1; i < attempts && d < maxDialRetryEvery; i++ {
		d *= 2
	}
	if d > maxDialRetryEvery {
		return maxDialRetryEvery
	}
	return d
}

// pruneCandidates bounds the pool by SIZE. Over the cap it evicts
// evictable candidates worst-first — most dial attempts (a tried-and-
// unreliable node), then oldest last-dial — and never drops a live peer or
// one that held a ready slot within keepReadyGrace: a peer that just worked
// is the pool's most valuable entry, and discovery re-fires only on an
// endpoint change or a source upgrade, so an eviction here is otherwise
// permanent for that node.
func (e *ethStage) pruneCandidates(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.cands) <= maxCandidates {
		return
	}
	type evictable struct {
		id enode.ID
		c  *dialCandidate
	}
	var pool []evictable
	for id, c := range e.cands {
		if e.ready[id] != nil {
			continue
		}
		if !c.lastReady.IsZero() && now.Sub(c.lastReady) < keepReadyGrace {
			continue
		}
		pool = append(pool, evictable{id, c})
	}
	sort.SliceStable(pool, func(i, j int) bool {
		if pool[i].c.attempts != pool[j].c.attempts {
			return pool[i].c.attempts > pool[j].c.attempts
		}
		return pool[i].c.lastDial.Before(pool[j].c.lastDial)
	})
	for _, ev := range pool {
		if len(e.cands) <= maxCandidates {
			return
		}
		delete(e.cands, ev.id)
	}
}

func (e *ethStage) dial(ctx context.Context, node *enode.Node) {
	defer func() {
		e.mu.Lock()
		delete(e.dialing, node.ID())
		e.mu.Unlock()
	}()
	peer, err := eth.Dial(ctx, e.key, node, e.netw, e.log)
	if err != nil {
		e.log.Debug("dial failed", "peer", node.ID().TerminalString(), "attempts", e.attempts(node.ID()), "err", err)
		return
	}
	e.mu.Lock()
	if len(e.ready) >= targetEthPeers {
		e.mu.Unlock()
		peer.Close()
		return
	}
	e.ready[peer.ID] = peer
	if c := e.cands[peer.ID]; c != nil {
		c.lastReady = time.Now()
	}
	startProve := !e.chainDone && !e.proving && !e.proofTried[peer.ID]
	if startProve {
		e.proving = true
	}
	e.mu.Unlock()
	go e.watchPeer(peer)
	if startProve {
		go e.proveHeaderRead(peer)
	}
}

// watchPeer frees the ready slot when the peer dies so the dial loop can
// refill it — eth peers churn constantly.
func (e *ethStage) watchPeer(p *eth.Peer) {
	<-p.Dead()
	e.mu.Lock()
	wasReady := e.ready[p.ID] == p
	delete(e.ready, p.ID)
	if wasReady {
		if c := e.cands[p.ID]; c != nil {
			c.lastReady = time.Now() // keep it in the pool through the grace
		}
	}
	e.mu.Unlock()
	if wasReady {
		e.log.Debug("ready peer gone", "peer", p.ID.TerminalString(), "client", p.ClientID)
	}
}

func (e *ethStage) attempts(id enode.ID) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.cands[id]; c != nil {
		return c.attempts
	}
	return 0
}

// proveHeaderRead walks headerSample headers backward from the peer's Status
// head with full link verification, and logs the result. A part-3 anchor
// will replace "the peer's own head" as the trust root; until then this
// proves the read path end to end — the log line says UNANCHORED so nobody
// reads it as a canonically verified chain (the repo rule: unverified data
// never travels unnamed).
//
// A failure is genuinely handed to the NEXT READY PEER — including one that
// landed while this proof was running. Peers whose answer failed
// VERIFICATION (ErrBadAnswer: lied or broke) are closed; timeouts and
// connections that merely dropped mark the peer tried but keep it.
func (e *ethStage) proveHeaderRead(first *eth.Peer) {
	p := first
	for p != nil {
		headers, err := p.GetBlockHeaders(p.Status.BestHash, headerSample)
		if err == nil {
			oldest, newest := headers[len(headers)-1], headers[0]
			e.log.Info("header chain linked (UNANCHORED: peer-announced head)",
				"peer", p.ClientID, "count", len(headers),
				"head", newest.Hash, "headNumber", newest.Number,
				"foot", oldest.Number, "stateRoot", newest.StateRoot)
			e.mu.Lock()
			e.chainDone = true
			e.proving = false
			e.mu.Unlock()
			return
		}
		e.log.Warn("header read failed", "peer", p.ID.TerminalString(), "err", err)
		e.mu.Lock()
		e.proofTried[p.ID] = true
		next := e.pickProverLocked()
		if next == nil {
			e.proving = false
		}
		e.mu.Unlock()
		if errors.Is(err, eth.ErrBadAnswer) {
			// This peer served a bad answer; watchPeer frees its slot.
			go p.Close()
		}
		p = next
	}
	e.mu.Lock()
	e.proving = false
	e.mu.Unlock()
}

// pickProverLocked returns a ready peer that has not been given the proof
// yet. Caller holds e.mu.
func (e *ethStage) pickProverLocked() *eth.Peer {
	for id, p := range e.ready {
		if !e.proofTried[id] {
			return p
		}
	}
	return nil
}

func (e *ethStage) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.ready)
}

func (e *ethStage) Close() {
	e.mu.Lock()
	peers := make([]*eth.Peer, 0, len(e.ready))
	for id, p := range e.ready {
		peers = append(peers, p)
		delete(e.ready, id)
	}
	e.mu.Unlock()
	// Close outside the lock: it blocks on per-peer teardown and must not
	// stall discovery's offer() callbacks behind dying connections.
	for _, p := range peers {
		p.Close()
	}
}
