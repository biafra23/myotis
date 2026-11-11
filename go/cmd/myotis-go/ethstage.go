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
)

// dialPriority orders candidates: liveness-proven discv4 peers first (they
// answered a ping minutes ago), then lookup-seen, then DNS leaves (which may
// lag months behind). Public mainnet nodes reject inbound as full
// (disconnect 0x04) routinely — getting two ready peers is a retry loop, and
// the retry loop wants the best-first ordering.
func dialPriority(src discovery.Source) int {
	switch src {
	case discovery.SourceDiscv4:
		return 0
	case discovery.SourceLookup:
		return 1
	default:
		return 2
	}
}

type dialCandidate struct {
	node     *enode.Node
	priority int
	lastDial time.Time
	attempts int
}

// ethStage keeps a small set of READY eth peers by dialing discovered
// candidates, and once one is up fetches a verified backward header chain
// from its Status head (printed once).
type ethStage struct {
	key  *ecdsa.PrivateKey
	netw *chain.Network
	log  *slog.Logger

	mu        sync.Mutex
	cands     map[enode.ID]*dialCandidate
	ready     map[enode.ID]*eth.Peer
	dialing   map[enode.ID]bool
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
	e.cands[c.ID] = &dialCandidate{node: c.Node, priority: dialPriority(c.Source)}
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
			for _, c := range e.pickDials(time.Now()) {
				go e.dial(ctx, c)
			}
		}
	}
}

// pickDials chooses up to the free dial slots' worth of best-first,
// not-recently-tried candidates and marks them as dialed-now (so one tick
// cannot double-dial).
func (e *ethStage) pickDials(now time.Time) []*enode.Node {
	e.mu.Lock()
	defer e.mu.Unlock()
	slots := targetEthPeers - len(e.ready) - len(e.dialing)
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
		if len(out) >= min(slots, maxConcurrentDials) {
			break
		}
		c.lastDial = now
		c.attempts++
		e.dialing[c.node.ID()] = true
		out = append(out, c.node)
	}
	return out
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
	first := !e.chainDone
	e.chainDone = true
	e.mu.Unlock()

	if first {
		go e.proveHeaderRead(peer)
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
// head with full link verification, and logs the result. A part-3 anchor will
// replace "the peer's own head" as the trust root; until then this proves the
// read path end to end.
func (e *ethStage) proveHeaderRead(p *eth.Peer) {
	headers, err := p.GetBlockHeaders(p.Status.BestHash, headerSample)
	if err != nil {
		e.log.Warn("header read failed", "peer", p.ID.TerminalString(), "err", err)
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
	defer e.mu.Unlock()
	for id, p := range e.ready {
		p.Close()
		delete(e.ready, id)
	}
}
