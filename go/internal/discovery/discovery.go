// Package discovery finds execution-layer peers for one network: discv4 via
// go-ethereum's implementation (bonding, Kademlia table, iterative lookups all
// geth's) seeded with the pinned bootnodes, plus the EIP-1459 DNS tree as a
// discovery-independent candidate source (docs/spec/02 §2 and §4).
//
// The engine never accepts inbound TCP — candidates are reported upward for
// the (later) RLPx layer to dial. One deliberate departure from the spec's
// "client/dialer only" note (§2.3: the references do not respond to FindNode):
// reusing geth's discover.ListenV4 means this node DOES answer FINDNODE from
// bonded peers out of its table, and it advertises its UDP port so peers keep
// it in their tables. ListenV4 has no responder-side switch, and being a
// well-connected DHT participant is what makes our own lookups return good
// sets; the cost is inbound UDP discv4 traffic. The Rust twin is stricter
// (it never answers FindNode, though since #539 it does answer ENRRequest).
// No fork-id filtering of candidates here yet — the (later) RLPx layer
// rejects foreign chains at eth Status, like enrfilter.rs does upstream.
package discovery

import (
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/dnsdisc"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Source tells where a candidate came from.
type Source string

const (
	// SourceDiscv4 is a routing-table node that passed a revalidation ping —
	// the only liveness-proven source.
	SourceDiscv4 Source = "discv4"
	// SourceLookup is a node surfaced by an iterative lookup (geth's
	// RandomNodes feed): seen in a Neighbors response, not pinged yet. This
	// is also the pump that keeps geth's lookups running.
	SourceLookup Source = "discv4-lookup"
	SourceDNS    Source = "dns"
)

// sourceRank orders sources for endpoint precedence: a liveness-proven
// endpoint must never be replaced by a later unproven sample of the same
// node (the DNS tree lags; every source re-delivers what it already
// delivered). Same rank: last writer wins among unproven sources.
func sourceRank(src Source) int {
	if src == SourceDiscv4 {
		return 2
	}
	return 1
}

// Candidate is one discovered peer with a dialable TCP endpoint.
type Candidate struct {
	ID        enode.ID
	Node      *enode.Node
	Source    Source
	FirstSeen time.Time
}

// Config wires the service.
type Config struct {
	// DataDir backs the enode database (peer liveness bookkeeping).
	DataDir string
	// Network supplies bootnodes + DNS tree URL.
	Network *chain.Network
	// Key is the node's persistent identity (nodekey.Load).
	Key *ecdsa.PrivateKey
	// ListenPort is the UDP port discv4 binds; 0 selects the network's
	// default port, -1 binds an ephemeral one.
	ListenPort int
	// OnDiscovered, when set, is called from a service goroutine for each
	// newly seen candidate and again whenever a known candidate's TCP
	// endpoint changes. It must not block.
	OnDiscovered func(Candidate)
	Logger       *slog.Logger
}

// Service runs discovery until Close.
type Service struct {
	cfg    Config
	log    *slog.Logger
	tab    *discover.UDPv4
	nodeDB *enode.DB

	mu         sync.Mutex
	candidates map[enode.ID]Candidate
	// dnsIt / lookupIt are the live blocking iterators, if any. Close() must
	// call their Close: both iterators' Next() block inside the iterator and
	// only return false once the iterator itself is closed.
	dnsIt    enode.Iterator
	lookupIt enode.Iterator

	stopOnce sync.Once
	stop     chan struct{}
	done     sync.WaitGroup
}

// Start binds the UDP socket, seeds discv4 and starts the DNS-tree walk.
// The returned service must be Closed.
func Start(cfg Config) (*Service, error) {
	if cfg.Network == nil {
		return nil, fmt.Errorf("discovery: no network configured")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	port := cfg.ListenPort
	if port == 0 {
		port = cfg.Network.ListenPort
	}

	nodeDB, err := enode.OpenDB(filepath.Join(cfg.DataDir, "nodedb"))
	if err != nil {
		return nil, fmt.Errorf("open enode db: %w", err)
	}
	localNode := enode.NewLocalNode(nodeDB, cfg.Key)

	bindPort := port
	if bindPort < 0 {
		bindPort = 0 // ask the OS for a free port
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: bindPort})
	if err != nil {
		nodeDB.Close()
		return nil, fmt.Errorf("bind udp :%d: %w", bindPort, err)
	}
	// Advertise the real bound port in our ENR (the PING/PONG payload peers
	// put in their routing tables); without it they see an address-less
	// record and can't point lookups back at us.
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		localNode.SetFallbackUDP(udpAddr.Port)
	}

	seeds := make([]*enode.Node, 0, len(cfg.Network.Bootnodes))
	for _, raw := range cfg.Network.Bootnodes {
		n, err := chain.ParseBootnode(raw)
		if err != nil {
			conn.Close()
			nodeDB.Close()
			return nil, err
		}
		seeds = append(seeds, n)
	}

	tab, err := discover.ListenV4(conn, localNode, discover.Config{
		PrivateKey: cfg.Key,
		Bootnodes:  seeds,
	})
	if err != nil {
		conn.Close()
		nodeDB.Close()
		return nil, fmt.Errorf("start discv4: %w", err)
	}

	s := &Service{
		cfg:        cfg,
		log:        cfg.Logger.With("component", "discovery"),
		tab:        tab,
		nodeDB:     nodeDB,
		candidates: make(map[enode.ID]Candidate),
		stop:       make(chan struct{}),
	}
	s.done.Add(3)
	go s.watchTable()
	go s.pumpLookups()
	go s.walkDNSTree()
	s.log.Info("discovery started",
		"enr", tab.Self().String(),
		"udp", conn.LocalAddr().String(),
		"seeds", len(seeds),
		"tree", cfg.Network.ENRTreeURL)
	return s, nil
}

// Close stops the pumps and the discv4 listener.
func (s *Service) Close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		// Release pumps stuck inside a blocking iterator Next().
		s.mu.Lock()
		if s.dnsIt != nil {
			s.dnsIt.Close()
		}
		if s.lookupIt != nil {
			s.lookupIt.Close()
		}
		s.mu.Unlock()
		s.done.Wait()
		s.tab.Close()
		s.nodeDB.Close()
	})
}

// Stats reports table fill and candidate counts by source.
func (s *Service) Stats() (tableNodes, liveNodes int, bySource map[Source]int) {
	bySource = map[Source]int{}
	for _, c := range s.snapshot() {
		bySource[c.Source]++
	}
	for _, bucket := range s.tab.TableBuckets() {
		for _, bn := range bucket {
			tableNodes++
			if bn.Live {
				liveNodes++
			}
		}
	}
	return tableNodes, liveNodes, bySource
}

func (s *Service) snapshot() []Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Candidate, 0, len(s.candidates))
	for _, c := range s.candidates {
		out = append(out, c)
	}
	return out
}

// addCandidate records a peer with a dialable TCP endpoint (the RLPx layer
// can only dial those) and reports whether the pool changed. A known peer
// whose ENR moved is replaced — and OnDiscovered re-fired — only by a source
// at least as trustworthy as the one holding the record (see sourceRank), so
// a late DNS sample can never overwrite an endpoint discv4 proved.
func (s *Service) addCandidate(src Source, n *enode.Node) bool {
	if n.TCP() == 0 || n.IP() == nil || n.IP().IsUnspecified() {
		return false
	}
	c, fire := func() (Candidate, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		old, known := s.candidates[n.ID()]
		if known && (endpointOf(old.Node) == endpointOf(n) || sourceRank(src) < sourceRank(old.Source)) {
			return Candidate{}, false
		}
		c := Candidate{
			ID:        n.ID(),
			Node:      n,
			Source:    src,
			FirstSeen: time.Now(),
		}
		if known {
			c.FirstSeen = old.FirstSeen
		}
		s.candidates[n.ID()] = c
		return c, true
	}()
	if fire && s.cfg.OnDiscovered != nil {
		s.cfg.OnDiscovered(c)
	}
	return fire
}

func endpointOf(n *enode.Node) string {
	return net.JoinHostPort(n.IP().String(), strconv.Itoa(n.TCP()))
}

// watchTable polls the discv4 routing table for live nodes.
func (s *Service) watchTable() {
	defer s.done.Done()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			for _, bucket := range s.tab.TableBuckets() {
				for _, bn := range bucket {
					if bn.Live {
						s.addCandidate(SourceDiscv4, bn.Node)
					}
				}
			}
		}
	}
}

// pumpLookups consumes geth's RandomNodes feed — the dialer-grade discv4
// source and, like geth's own dialer, the thing that keeps iterative lookups
// running (the table alone only self-refreshes every ~RefreshInterval and
// caps at ~one table's worth). Nodes here come from Neighbors responses and
// are not yet pinged; watchTable upgrades them once a revalidation pong
// proves liveness.
func (s *Service) pumpLookups() {
	defer s.done.Done()
	it := s.tab.RandomNodes()
	if s.registerIt(&s.lookupIt, it) {
		it.Close()
		return
	}
	defer func() {
		s.clearIt(&s.lookupIt, it)
		it.Close()
	}()
	for it.Next() {
		s.addCandidate(SourceLookup, it.Node())
	}
}

// DNS-tree walk policy. geth's randomIterator is a continuous sampler, not a
// one-shot walk — sampled forever it is a permanent ~3/s background of DNS
// TXT queries long after every leaf is known. So the walk is bounded, like
// the references (docs/spec/02 §4): sample until a full sweep produced no
// new candidate (dnsIdleNoNew tells a sweep is over — at the client's rate
// limit, a quiet window covers a full pass of the EF list), then idle and
// re-walk only periodically, and only while the tree keeps offering new
// nodes. This engine has no Tor mode yet; when it lands, the DNS walk must
// go off under Tor like it does in the Rust engine.
const (
	dnsIdleNoNew   = 5 * time.Minute  // quiet window that counts a sweep as done
	dnsRewalkEvery = 30 * time.Minute // idle period between re-walks
	dnsRetryAfter  = time.Minute      // retry after a failed iterator start
)

func (s *Service) walkDNSTree() {
	defer s.done.Done()
	for {
		select {
		case <-s.stop:
			return
		default:
		}

		cl := dnsdisc.NewClient(dnsdisc.Config{})
		it, err := cl.NewIterator(s.cfg.Network.ENRTreeURL)
		if err != nil {
			s.log.Warn("dns tree walk failed to start", "err", err, "retryIn", dnsRetryAfter)
			if !s.sleep(dnsRetryAfter) {
				return
			}
			continue
		}
		if s.registerIt(&s.dnsIt, it) {
			// Close() already ran its iterator hook against the previous nil;
			// release this one ourselves.
			it.Close()
			return
		}

		sampled, fresh := 0, 0
		lastNew := time.Now()
		for it.Next() {
			sampled++
			if s.addCandidate(SourceDNS, it.Node()) {
				fresh++
				lastNew = time.Now()
			} else if time.Since(lastNew) > dnsIdleNoNew {
				break // a full sweep delivered nothing new: walk done
			}
		}
		s.clearIt(&s.dnsIt, it)
		it.Close()
		s.log.Info("dns tree sweep finished", "sampled", sampled, "newCandidates", fresh)

		retry := dnsRewalkEvery
		if fresh > 0 && sampled >= fresh {
			retry = dnsRetryAfter // the iterator ended early while the tree still fed us new nodes
		}
		if !s.sleep(retry) {
			return
		}
	}
}

// registerIt stores it as the service's live iterator and reports whether the
// service is already stopping (the caller must then Close it itself — Close()
// may already have looked at a nil field).
func (s *Service) registerIt(field *enode.Iterator, it enode.Iterator) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	*field = it
	return isClosed(s.stop)
}

func (s *Service) clearIt(field *enode.Iterator, it enode.Iterator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if *field == it {
		*field = nil
	}
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// sleep waits for d unless the service is stopping.
func (s *Service) sleep(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-s.stop:
		return false
	case <-timer.C:
		return true
	}
}
