// Command myotis-go is the Go engine. As of this revision it discovers
// mainnet execution-layer peers (discv4 + EIP-1459), dials them over RLPx,
// and completes the eth handshake — then proves the framed channel works by
// asking one for the genesis header and checking it against the pinned
// genesis hash. The consensus light client and verified snap reads land as
// the following parts on feature/go-engine.
package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/discovery"
	"github.com/biafra23/myotis/go/internal/nodekey"
	"github.com/biafra23/myotis/go/internal/transport"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func main() {
	defaultDir := "myotis-go-data"
	if cd, err := os.UserConfigDir(); err == nil {
		defaultDir = cd + "/myotis-go"
	}
	var (
		dataDir    = flag.String("datadir", defaultDir, "directory for the node key and peer database")
		listenPort = flag.Int("port", chain.Mainnet().ListenPort, "discv4 UDP port (0 = network default, -1 = ephemeral)")
		runFor     = flag.Duration("run-for", 0, "exit after this duration (0 = run until interrupted)")
		dialPeers  = flag.Bool("dial", true, "dial discovered peers over RLPx (false = discovery only)")
		maxDials   = flag.Int("max-concurrent-dials", 4, "concurrent outbound dials (min 1)")
		maxReady   = flag.Int("max-ready", 8, "cap on live READY sessions; candidates wait until a slot frees")
		logLevel   = flag.String("loglevel", "info", "log level: info|debug (debug lists each dial failure)")
		quiet      = flag.Bool("quiet", false, "log only new peers, not the periodic summary")
	)
	flag.Parse()

	lvl := new(slog.LevelVar)
	if *logLevel == "debug" {
		lvl.Set(slog.LevelDebug)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	if err := run(*dataDir, *listenPort, *runFor, *dialPeers, *maxDials, *maxReady, *quiet, log); err != nil {
		log.Error("myotis-go: " + err.Error())
		os.Exit(1)
	}
}

func run(dataDir string, listenPort int, runFor time.Duration, dialPeers bool, maxDials, maxReady int, quiet bool, log *slog.Logger) error {
	netCfg := chain.Mainnet() // the one network for now

	key, err := nodekey.Load(dataDir)
	if err != nil {
		return err
	}
	log.Info("node identity",
		"nodeId", fmt.Sprintf("%x", nodekey.NodeID(&key.PublicKey)),
		"datadir", dataDir)

	// What our Hello advertises as our TCP port: the operator's port when
	// it is a real one, 0 when the socket is ephemeral — never the
	// network's constant, which is wrong whenever -port moved.
	advertiseTCP := uint16(0)
	switch {
	case listenPort < 0: // ephemeral: nothing to advertise
	case listenPort == 0:
		advertiseTCP = uint16(netCfg.ListenPort)
	default:
		advertiseTCP = uint16(listenPort)
	}

	dialer := newDialer(key, netCfg, maxDials, maxReady, advertiseTCP, log)
	// LIFO matters: register dialer.close BEFORE disc's defer so disc.Close
	// runs first — discovery must stop firing OnDiscovered before the dialer
	// queue closes (enqueue's closed-flag is the second belt on that).
	defer dialer.close()

	disc, err := discovery.Start(discovery.Config{
		DataDir:    dataDir,
		Network:    netCfg,
		Key:        key,
		ListenPort: listenPort,
		Logger:     log,
		OnDiscovered: func(c discovery.Candidate) {
			log.Info("peer discovered",
				"id", c.ID.String(),
				"addr", fmt.Sprintf("%s:%d", c.Node.IP(), c.Node.TCP()),
				"via", c.Source)
			if dialPeers {
				dialer.enqueue(c.Node)
			}
		},
	})
	if err != nil {
		return err
	}
	defer disc.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var deadline <-chan time.Time
	if runFor > 0 {
		t := time.NewTimer(runFor)
		defer t.Stop()
		deadline = t.C
	}

	summary := time.NewTicker(30 * time.Second)
	defer summary.Stop()
	for {
		select {
		case <-ctx.Done():
			report(disc, dialer, log)
			return nil
		case <-deadline:
			report(disc, dialer, log)
			return nil
		case <-summary.C:
			if !quiet {
				report(disc, dialer, log)
			}
		}
	}
}

func report(disc *discovery.Service, dialer *dialer, log *slog.Logger) {
	table, live, bySource := disc.Stats()
	peers := make([]any, 0, len(bySource))
	for src, n := range bySource {
		peers = append(peers, slog.Any(string(src), n))
	}
	ready, outcome, clients := dialer.stats()
	log.Info("summary",
		"tableNodes", table, "liveNodes", live, "dialablePeers", peers,
		"readyPeers", ready, "dialOutcomes", outcome, "everReadyClients", clients)
}

// dialer dials discovered candidates with bounded concurrency, keeps one
// session per node id, and verifies each new READY peer by pulling the
// genesis header and hashing it against the pin — the cheapest end-to-end
// proof that framing, codecs and the peer's chain all line up.
type dialer struct {
	key     *ecdsa.PrivateKey
	network *chain.Network
	log     *slog.Logger

	// tcpPort is advertised in our Hello (what a peer would dial to reach
	// us); 0 = ephemeral/no-listen, honest per finding (transport.Config).
	tcpPort  uint16
	maxReady int // cap live sessions; the CLI is a demo, not a peer pool

	queue chan *enode.Node

	mu        sync.Mutex
	closed    bool
	attempted map[enode.ID]bool
	ready     map[enode.ID]*transport.Session
	clients   map[string]int
	failures  map[string]int // dial-failure reason class → count
	dropped   int            // candidates discarded with a full queue (retryable)
	gone      int            // READY sessions evicted after the peer died

	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newDialer(key *ecdsa.PrivateKey, netCfg *chain.Network, workers, maxReady int, tcpPort uint16, log *slog.Logger) *dialer {
	if workers < 1 {
		log.Warn("max-concurrent-dials < 1 makes no dials; using 4", "requested", workers)
		workers = 4
	}
	if maxReady < 1 {
		maxReady = 1
	}
	d := &dialer{
		key:       key,
		network:   netCfg,
		log:       log.With("component", "dialer"),
		tcpPort:   tcpPort,
		maxReady:  maxReady,
		queue:     make(chan *enode.Node, 256),
		attempted: map[enode.ID]bool{},
		ready:     map[enode.ID]*transport.Session{},
		clients:   map[string]int{},
		failures:  map[string]int{},
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.work()
	}
	return d
}

func (d *dialer) enqueue(n *enode.Node) {
	// The non-blocking send runs UNDER d.mu, and close() closes the channel
	// under the same lock: a send can then never interleave between close's
	// flag and close(d.queue) — the race that panicked a
	// send-on-closed-channel at shutdown in the first smoke (defer
	// ordering is belt; this is braces).
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.attempted[n.ID()] {
		return
	}
	// At the live-session cap, hold the candidate un-attempted: a slot
	// frees when a peer dies, and discovery re-fires it.
	if len(d.ready) >= d.maxReady {
		return
	}
	select {
	case d.queue <- n:
		// Mark attempted only once the candidate is actually queued —
		// marking before a dropped send made queue-full candidates
		// permanently un-retryable while still counting as "attempted".
		d.attempted[n.ID()] = true
	default:
		d.dropped++ // queue full; the node stays un-attempted for re-fire
	}
}

func (d *dialer) work() {
	defer d.wg.Done()
	for node := range d.queue {
		d.dialOnce(node)
	}
}

func (d *dialer) dialOnce(node *enode.Node) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := transport.Dial(ctx, transport.Config{
		LocalKey:         d.key,
		Network:          d.network,
		Node:             node,
		AdvertiseTCPPort: d.tcpPort,
	})
	if err != nil {
		d.mu.Lock()
		d.failures[classifyDialError(err)]++
		d.mu.Unlock()
		d.log.Debug("dial failed", "id", node.ID().String(),
			"addr", net.JoinHostPort(node.IP().String(), fmt.Sprint(node.TCP())),
			"err", err)
		return
	}

	// Genesis probe: pull the header the pinned hash names and check
	// keccak256(rlp) == the pin (docs/spec/02 §6.4: peers are checked,
	// never trusted — this is the first instance of that in the Go engine).
	headers, err := sess.GetBlockHeadersByHash(d.network.GenesisHash, 1)
	switch {
	case err != nil:
		d.mu.Lock()
		d.failures["probe-error"]++
		d.mu.Unlock()
		d.log.Warn("ready peer failed the genesis probe", "id", node.ID().String(), "reason", err)
		sess.Close()
		return
	case len(headers) != 1 || crypto.Keccak256Hash(headers[0]) != d.network.GenesisHash:
		d.mu.Lock()
		d.failures["probe-wrong-header"]++
		d.mu.Unlock()
		d.log.Warn("ready peer failed the genesis probe", "id", node.ID().String(),
			"reason", fmt.Sprintf("got %d header(s), keccak(rlp) %s", len(headers), hashOf(headers)))
		sess.Close()
		return
	}

	d.mu.Lock()
	d.ready[node.ID()] = sess
	d.clients[sess.ClientID]++
	ready := len(d.ready)
	d.mu.Unlock()

	// Evict promptly when the peer dies (session reader reports it): a
	// readyPeers count must be live connections, not a census of everyone
	// who ever said hello (peers ping-timeout-disconnect silent clients,
	// and even honest ones move on).
	go func(id enode.ID, s *transport.Session) {
		<-s.Done()
		d.mu.Lock()
		if cur, ok := d.ready[id]; ok && cur == s {
			delete(d.ready, id)
			d.gone++
		}
		d.mu.Unlock()
		s.Close()
	}(node.ID(), sess)
	snap := "no"
	if sess.Snap != nil {
		snap = fmt.Sprintf("snap/%d", *sess.Snap)
	}
	d.log.Info("peer READY",
		"id", node.ID().String(),
		"client", sess.ClientID,
		"eth", fmt.Sprintf("eth/%d", sess.EthVersion),
		"snap", snap,
		"peerHeight", peerHeight(sess),
		"genesis", "verified",
		"readyPeers", ready)
}

func hashOf(headers [][]byte) string {
	if len(headers) == 0 {
		return "—"
	}
	h := crypto.Keccak256Hash(headers[0])
	return fmt.Sprintf("%x", h[:8])
}

func peerHeight(s *transport.Session) uint64 {
	if s.PeerStatus != nil && s.PeerStatus.LatestBlock != nil {
		return *s.PeerStatus.LatestBlock
	}
	return 0 // eth/67-68 Status carries no block number
}

func (d *dialer) stats() (ready int, outcome []string, clients []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for c, n := range d.clients {
		clients = append(clients, fmt.Sprintf("%s×%d", c, n))
	}
	// One accounting line: attempted dials split into live, died, failed,
	// plus the two non-dial outcomes (queue drops are retryable, so they
	// intentionally do NOT appear in dialsAttempted).
	outcome = append(outcome,
		fmt.Sprintf("attempted=%d", len(d.attempted)),
		fmt.Sprintf("failed=%d", sum(d.failures)),
		fmt.Sprintf("died=%d", d.gone),
		fmt.Sprintf("queueDropped=%d", d.dropped),
	)
	for f, n := range d.failures {
		outcome = append(outcome, "  "+f+"="+fmt.Sprint(n))
	}
	return len(d.ready), outcome, clients
}

func sum(m map[string]int) int {
	var t int
	for _, n := range m {
		t += n
	}
	return t
}

// classifyDialError buckets dial failures so the summary shows the shape of
// the dial wall instead of one Debug line per candidate.
func classifyDialError(err error) string {
	s := err.Error()
	switch {
	case containsAny(s, "connection refused"):
		return "refused"
	case containsAny(s, "i/o timeout", "context deadline"):
		return "timeout"
	case containsAny(s, "MAC mismatch"):
		return "frame-mac"
	case containsAny(s, "ECIES", "ecies"):
		return "ecies"
	case containsAny(s, "disconnected"):
		return "disconnect"
	case containsAny(s, "wrong chain"):
		return "wrong-chain"
	case containsAny(s, "no common eth"):
		return "no-eth-cap"
	case containsAny(s, "EOF"):
		return "eof"
	default:
		return "other"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func (d *dialer) close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.queue)
		d.mu.Unlock()
		d.wg.Wait()
		d.mu.Lock()
		defer d.mu.Unlock()
		for id, s := range d.ready {
			s.Close()
			delete(d.ready, id)
		}
	})
}
