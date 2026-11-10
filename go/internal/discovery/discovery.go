// Package discovery finds execution-layer peers for one network: discv4 via
// go-ethereum's implementation (bonding, Kademlia table, iterative lookups all
// geth's) seeded with the pinned bootnodes, plus the EIP-1459 DNS tree as a
// discovery-independent candidate source (docs/spec/02 §2 and §4).
//
// Like the rest of the engine this is a dialer only — candidates are reported
// upward for the (later) RLPx layer to dial; nothing here accepts inbound
// connections.
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
	SourceDiscv4 Source = "discv4"
	SourceDNS    Source = "dns"
)

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
	// dnsIt is the live DNS-tree iterator, if any. Close() must call its
	// Close: geth's randomIterator.Next() blocks inside the iterator and
	// only returns false once the iterator itself is closed.
	dnsIt enode.Iterator

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
	s.done.Add(2)
	go s.watchTable()
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
		// Release a walkDNSTree stuck inside the iterator's blocking Next().
		s.mu.Lock()
		if s.dnsIt != nil {
			s.dnsIt.Close()
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
// can only dial those). A known peer whose ENR moved (the DNS tree lags and
// carries stale endpoints; discv4 proves the live one) replaces the stored
// record and re-fires OnDiscovered.
func (s *Service) addCandidate(src Source, n *enode.Node) {
	if n.TCP() == 0 || n.IP() == nil || n.IP().IsUnspecified() {
		return
	}
	c, fire := func() (Candidate, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		old, known := s.candidates[n.ID()]
		if known && endpointOf(old.Node) == endpointOf(n) {
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

// walkDNSTree streams the EIP-1459 list into the candidate pool (geth's
// dnsdisc client verifies the tree root signature against the key in the URL).
// NewIterator returns a randomIterator, which is a continuous sampler, not a
// one-shot walk: it delivers randomly sampled leaves (duplicates included —
// addCandidate dedups by node id) at the client's rate limit, re-syncing the
// tree itself, and returns false only after Close(). Close() unblocks it via
// the iterator stored on the service; the outer loop only restarts after a
// failed start or an unexpected end.
func (s *Service) walkDNSTree() {
	defer s.done.Done()
	const backoff = time.Minute
	for {
		select {
		case <-s.stop:
			return
		default:
		}

		cl := dnsdisc.NewClient(dnsdisc.Config{})
		it, err := cl.NewIterator(s.cfg.Network.ENRTreeURL)
		if err != nil {
			s.log.Warn("dns tree walk failed to start", "err", err, "retryIn", backoff)
			if !s.sleep(backoff) {
				return
			}
			continue
		}

		s.mu.Lock()
		s.dnsIt = it
		stopping := isClosed(s.stop)
		s.mu.Unlock()
		if stopping {
			// Close() already ran its iterator hook against the previous nil;
			// release this one ourselves.
			it.Close()
			return
		}

		for it.Next() {
			s.addCandidate(SourceDNS, it.Node())
		}
		s.mu.Lock()
		if s.dnsIt == it {
			s.dnsIt = nil
		}
		s.mu.Unlock()
		it.Close() // idempotent; unblocks nothing if Next already returned

		if !s.sleep(backoff) {
			return
		}
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
