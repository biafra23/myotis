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
		maxDials   = flag.Int("max-concurrent-dials", 4, "concurrent outbound dials")
		logLevel   = flag.String("loglevel", "info", "log level: info|debug (debug lists each dial failure)")
		quiet      = flag.Bool("quiet", false, "log only new peers, not the periodic summary")
	)
	flag.Parse()

	lvl := new(slog.LevelVar)
	if *logLevel == "debug" {
		lvl.Set(slog.LevelDebug)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	if err := run(*dataDir, *listenPort, *runFor, *dialPeers, *maxDials, *quiet, log); err != nil {
		log.Error("myotis-go: " + err.Error())
		os.Exit(1)
	}
}

func run(dataDir string, listenPort int, runFor time.Duration, dialPeers bool, maxDials int, quiet bool, log *slog.Logger) error {
	netCfg := chain.Mainnet() // the one network for now

	key, err := nodekey.Load(dataDir)
	if err != nil {
		return err
	}
	log.Info("node identity",
		"nodeId", fmt.Sprintf("%x", nodekey.NodeID(&key.PublicKey)),
		"datadir", dataDir)

	dialer := newDialer(key, netCfg, maxDials, log)
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
	ready, attempted, clients, failures := dialer.stats()
	log.Info("summary",
		"tableNodes", table, "liveNodes", live, "dialablePeers", peers,
		"readyPeers", ready, "dialsAttempted", attempted, "clients", clients,
		"dialFailures", failures)
}

// dialer dials discovered candidates with bounded concurrency, keeps one
// session per node id, and verifies each new READY peer by pulling the
// genesis header and hashing it against the pin — the cheapest end-to-end
// proof that framing, codecs and the peer's chain all line up.
type dialer struct {
	key     *ecdsa.PrivateKey
	network *chain.Network
	log     *slog.Logger

	queue chan *enode.Node

	mu        sync.Mutex
	closed    bool
	attempted map[enode.ID]bool
	ready     map[enode.ID]*transport.Session
	clients   map[string]int
	failures  map[string]int // dial-failure reason class → count

	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newDialer(key *ecdsa.PrivateKey, netCfg *chain.Network, workers int, log *slog.Logger) *dialer {
	d := &dialer{
		key:       key,
		network:   netCfg,
		log:       log.With("component", "dialer"),
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
	d.attempted[n.ID()] = true
	select {
	case d.queue <- n:
	default: // queue full: next candidates will come, discovery keeps firing
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
		LocalKey: d.key,
		Network:  d.network,
		Node:     node,
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
	if err != nil || len(headers) != 1 || crypto.Keccak256Hash(headers[0]) != d.network.GenesisHash {
		reason := "no header"
		if err != nil {
			reason = err.Error()
		}
		d.log.Warn("ready peer failed the genesis probe", "id", node.ID().String(), "reason", reason)
		sess.Close()
		return
	}

	d.mu.Lock()
	d.ready[node.ID()] = sess
	d.clients[sess.ClientID]++
	ready := len(d.ready)
	d.mu.Unlock()
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

func peerHeight(s *transport.Session) uint64 {
	if s.PeerStatus != nil && s.PeerStatus.LatestBlock != nil {
		return *s.PeerStatus.LatestBlock
	}
	return 0 // eth/67-68 Status carries no block number
}

func (d *dialer) stats() (ready, attempted int, clients, failures []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for c, n := range d.clients {
		clients = append(clients, fmt.Sprintf("%s×%d", c, n))
	}
	for f, n := range d.failures {
		failures = append(failures, fmt.Sprintf("%s=%d", f, n))
	}
	return len(d.ready), len(d.attempted), clients, failures
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
