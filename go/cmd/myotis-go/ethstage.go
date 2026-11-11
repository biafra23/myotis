package main

import (
	"context"
	"crypto/ecdsa"
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
	// A tried candidate that has not been dialable-and-due for this long is
	// stale enough to drop; discovery keeps re-offering anyone still alive.
	candidateTTL = time.Hour
)

type dialCandidate struct {
	node     *enode.Node
	priority int // lower dials first
	lastDial time.Time
	attempts int
}

// ethStage keeps a small set of READY eth peers by dialing discovered
// candidates (evicting them when they die, which eth peers do routinely),
// and drives one verified backward header chain read from the first peer
// that stays up long enough (retried through later peers if one fails).
type ethStage struct {
	key  *ecdsa.PrivateKey
	netw *chain.Network
	log  *slog.Logger

	mu        sync.Mutex
	cands     map[enode.ID]*dialCandidate
	ready     map[enode.ID]*eth.Peer
	dialing   map[enode.ID]bool
	proving   bool
	chainDone bool
}

func newEthStage(key *ecdsa.PrivateKey, netw *chain.Network, log *slog.Logger) *ethStage {
	return &ethStage{
		key:     key,
		netw:    netw,
		log:     log.With("component", "eth"),
		cands:   map[enode.ID]*dialCandidate{},
		ready:   map[enode.ID]*eth.Peer{},
		dialing: map[enode.ID]bool{},
	}
}

// offer records a discovered candidate (cheap; called from discovery
// callbacks). A candidate that moved and re-fired replaces its record.
func (e *ethStage) offer(c discovery.Candidate) {
	if c.Node.TCP() == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if old, ok := e.cands[c.ID]; ok {
		old.node = c.Node // endpoint may have been refreshed
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
		if !c.lastDial.IsZero() && now.Sub(c.lastDial) < dialRetryEvery {
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

// pruneCandidates drops long-stale tried candidates so the pool cannot grow
// without bound; live peers return through discovery's re-fires.
func (e *ethStage) pruneCandidates(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, c := range e.cands {
		if c.attempts > 0 && now.Sub(c.lastDial) > candidateTTL && e.ready[id] == nil {
			delete(e.cands, id)
		}
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
	startProve := !e.chainDone && !e.proving
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
// proves the read path end to end. Only a SUCCESS retires the one-shot: a
// failed attempt hands the job to the next ready peer.
func (e *ethStage) proveHeaderRead(p *eth.Peer) {
	headers, err := p.GetBlockHeaders(p.Status.BestHash, headerSample)
	e.mu.Lock()
	e.proving = false
	if err == nil {
		e.chainDone = true
	}
	e.mu.Unlock()
	if err != nil {
		e.log.Warn("header read failed; a later peer will retry", "peer", p.ID.TerminalString(), "err", err)
		return
	}
	oldest, newest := headers[len(headers)-1], headers[0]
	e.log.Info("verified header chain",
		"peer", p.ClientID, "count", len(headers),
		"head", newest.Hash, "headNumber", newest.Number,
		"foot", oldest.Number, "stateRoot", newest.StateRoot)
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
