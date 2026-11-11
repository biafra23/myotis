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
		maxReady   = flag.Int("max-ready", 8, "cap on live READY sessions; waiting candidates are held in a backlog and dialed when a slot frees")
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

	// ctx is cancelled by close(); workers and every dial derive from it,
	// so shutdown stops the dial wall instead of draining a queued 256
	// candidates through 30-second handshakes after the report printed.
	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{} // nudge: "backlog or slots moved, look again"

	mu        sync.Mutex
	closed    bool
	attempted map[string]bool // id‖endpoint — a moved node gets a fresh dial
	backlog   map[enode.ID]*enode.Node
	order     []enode.ID // FIFO over backlog
	ready     map[enode.ID]*transport.Session
	clients   map[string]int
	failures  map[string]int // dial-failure reason class → count
	dialed    int            // candidates actually dialed
	dropped   int            // candidates discarded with a full backlog
	gone      int            // READY sessions evicted after the peer died

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// backlogCap bounds the waiting list. Discovery fires OnDiscovered once per
// (id, endpoint) and never re-fires, so dropping a candidate at a full
// backlog or a full ready-set would lose it for the life of the process —
// the backlog is what makes "wait until a slot frees" true.
const backlogCap = 512

func newDialer(key *ecdsa.PrivateKey, netCfg *chain.Network, workers, maxReady int, tcpPort uint16, log *slog.Logger) *dialer {
	if workers < 1 {
		log.Warn("max-concurrent-dials < 1 makes no dials; using 4", "requested", workers)
		workers = 4
	}
	if maxReady < 1 {
		maxReady = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &dialer{
		key:       key,
		network:   netCfg,
		log:       log.With("component", "dialer"),
		tcpPort:   tcpPort,
		maxReady:  maxReady,
		ctx:       ctx,
		cancel:    cancel,
		wake:      make(chan struct{}, 1),
		attempted: map[string]bool{},
		backlog:   map[enode.ID]*enode.Node{},
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

func attemptKey(n *enode.Node) string {
	return n.ID().String() + "|" + net.JoinHostPort(n.IP().String(), fmt.Sprint(n.TCP()))
}

func (d *dialer) enqueue(n *enode.Node) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	if id := n.ID(); d.backlog[id] != nil {
		d.backlog[id] = n // a moved endpoint replaces the waiting one
	} else if len(d.order) >= backlogCap {
		d.dropped++
	} else if d.attempted[attemptKey(n)] {
		// already dialed at this exact endpoint
	} else {
		d.backlog[id] = n
		d.order = append(d.order, id)
	}
	d.mu.Unlock()
	d.signal()
}

func (d *dialer) signal() {
	select {
	case d.wake <- struct{}{}:
	default: // a pending nudge already promises a re-look
	}
}

func (d *dialer) work() {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.wake:
		}
		for {
			d.mu.Lock()
			if d.closed || len(d.order) == 0 || len(d.ready) >= d.maxReady {
				d.mu.Unlock()
				break
			}
			id := d.order[0]
			d.order = d.order[1:]
			node := d.backlog[id]
			delete(d.backlog, id)
			d.attempted[attemptKey(node)] = true
			d.dialed++
			d.mu.Unlock()
			d.dialOnce(node)
		}
	}
}

func (d *dialer) dialOnce(node *enode.Node) {
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
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

	// Hard cap at insert: workers may race past the dequeue-time check, so
	// a surplus READY session is closed rather than kept — -max-ready means
	// max-ready, not "max-ready plus whatever was in flight".
	d.mu.Lock()
	if len(d.ready) >= d.maxReady {
		d.mu.Unlock()
		d.log.Debug("ready set full, closing surplus session", "id", node.ID().String())
		sess.Close()
		d.signal() // a dial slot freed; another worker may proceed
		return
	}
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
		freed := false
		if cur, ok := d.ready[id]; ok && cur == s {
			delete(d.ready, id)
			d.gone++
			freed = true
		}
		d.mu.Unlock()
		s.Close()
		if freed {
			d.signal() // a ready slot freed: drain the backlog into it
		}
	}(node.ID(), sess)
	snap := "no"
	if sess.Snap != nil {
		snap = fmt.Sprintf("snap/%d", *sess.Snap)
	}
	attrs := []any{
		"id", node.ID().String(),
		"client", sess.ClientID,
		"eth", fmt.Sprintf("eth/%d", sess.EthVersion),
		"snap", snap,
		"genesis", "verified",
		"readyPeers", ready,
	}
	// The height is the peer's CLAIM, checked against nothing — name it so
	// it cannot read as verified next to genesis=verified, and omit it for
	// eth/67-68 Statuses, which carry no block number at all (0 there
	// would mean "unknown", not "height zero").
	if sess.PeerStatus != nil && sess.PeerStatus.LatestBlock != nil {
		attrs = append(attrs, "claimedHeight", *sess.PeerStatus.LatestBlock)
	}
	d.log.Info("peer READY", attrs...)
}

func hashOf(headers [][]byte) string {
	if len(headers) == 0 {
		return "—"
	}
	h := crypto.Keccak256Hash(headers[0])
	return fmt.Sprintf("%x", h[:8])
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
		fmt.Sprintf("dialed=%d", d.dialed),
		fmt.Sprintf("failed=%d", sum(d.failures)),
		fmt.Sprintf("died=%d", d.gone),
		fmt.Sprintf("backlog=%d", len(d.order)),
		fmt.Sprintf("backlogDropped=%d", d.dropped),
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
		// Cancel first: in-flight dials die with the context (transport
		// closes the socket on ctx), and workers stop pulling from the
		// backlog — no dial wall of queued candidates after the report.
		d.cancel()
		d.mu.Lock()
		d.closed = true
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
