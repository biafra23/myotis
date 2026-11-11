// Command myotis-go is the Go engine. It discovers mainnet execution-layer
// peers (discv4 + EIP-1459), dials them over RLPx, and completes the eth
// handshake — proving the framed channel by pulling the genesis header and
// hashing it against the pin. With -get-account it ALSO runs the beacon
// light client (the part-3/3b path, bootstrap → catch-up → finality poll,
// every header BLS-verified) in parallel, and once both halves are up it
// answers the account over snap — NONCE, BALANCE AND ROOTS PROVEN against
// the light client's anchored finalized execution state root, never taken
// from a peer's word.
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clsync"
	"github.com/biafra23/myotis/go/internal/discovery"
	"github.com/biafra23/myotis/go/internal/lc"
	"github.com/biafra23/myotis/go/internal/nodekey"
	"github.com/biafra23/myotis/go/internal/snapread"
	"github.com/biafra23/myotis/go/internal/transport"
	"github.com/ethereum/go-ethereum/common"
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
		getAccount = flag.String("get-account", "", "hex address: run the light client, wait for a snap peer, and print this account VERIFIED against the anchored finalized state root, then exit")
		slot       = flag.String("slot", "", "with -get-account: 32-byte hex storage slot to read too (two-hop, anchored at the PROVEN storageRoot)")
	)
	flag.Parse()
	if *slot != "" && *getAccount == "" {
		logFat := func(a ...any) { fmt.Fprintln(os.Stderr, a...); os.Exit(2) }
		logFat("-slot requires -get-account")
	}

	lvl := new(slog.LevelVar)
	if *logLevel == "debug" {
		lvl.Set(slog.LevelDebug)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	err := run(*dataDir, *listenPort, *runFor, *dialPeers, *maxDials, *maxReady, *quiet, log, *getAccount, *slot)
	if err != nil {
		log.Error("myotis-go: " + err.Error())
		os.Exit(1)
	}
}

func run(dataDir string, listenPort int, runFor time.Duration, dialPeers bool, maxDials, maxReady int, quiet bool, log *slog.Logger, getAccount, slotHex string) error {
	netCfg := chain.Mainnet() // the one network for now
	var wantAddr common.Address
	if getAccount != "" {
		if !common.IsHexAddress(getAccount) {
			return fmt.Errorf("-get-account: %q is not a hex address", getAccount)
		}
		wantAddr = common.HexToAddress(getAccount)
	}
	var wantSlot [32]byte
	if slotHex != "" {
		// A slot INDEX (short or odd hex, e.g. "0") is left-padded to
		// the 32-byte key the trie uses — the Java CLI's
		// "get-storage <addr> <index>" ergonomics; anything wider than
		// a word stays an error.
		h := strings.TrimPrefix(slotHex, "0x")
		if len(h)%2 == 1 {
			h = "0" + h
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) > 32 {
			return fmt.Errorf("-slot: want ≤32 hex bytes, got %q (%v)", slotHex, err)
		}
		copy(wantSlot[32-len(b):], b)
	}

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

	// -get-account mode: the beacon light client runs in parallel with
	// EL discovery/dialing; the read fires when BOTH are up. Without the
	// flag, no libp2p host is created at all — discovery/dial mode is
	// untouched.
	var (
		anchors   = make(chan lcAnchor, 1) // latest-wins (trySend below)
		lcFailure = make(chan error, 1)
	)
	if getAccount != "" {
		lcCtx, lcStop := context.WithCancel(ctx)
		defer lcStop()
		logf := func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }
		go func() { lcFailure <- runLightClient(lcCtx, logf, anchors) }()
	}
	var latest lcAnchor
	haveAnchor := false

	var deadline <-chan time.Time
	if runFor > 0 {
		t := time.NewTimer(runFor)
		defer t.Stop()
		deadline = t.C
	} else if getAccount != "" {
		// A bounded window for the read mode: an honest failure beats
		// hanging until interrupted when no anchor or snap peer ever
		// arrives (the same honesty as myotis-lc -once's exit code).
		t := time.NewTimer(10 * time.Minute)
		defer t.Stop()
		deadline = t.C
	}

	reads := time.NewTicker(2 * time.Second)
	defer reads.Stop()

	summary := time.NewTicker(30 * time.Second)
	defer summary.Stop()
	for {
		select {
		case <-ctx.Done():
			report(disc, dialer, log)
			return nil
		case <-deadline:
			report(disc, dialer, log)
			if getAccount != "" {
				return fmt.Errorf("read window expired before an anchor + snap peer could serve %s", wantAddr.Hex())
			}
			return nil
		case err := <-lcFailure:
			// The LC gave up (bootstrap/catch-up refused within the
			// budget): the read can never be VERIFIED, so neither can
			// the command quietly succeed.
			report(disc, dialer, log)
			return fmt.Errorf("light client: %w", err)
		case a := <-anchors:
			latest, haveAnchor = a, true
			if getAccount == "" {
				continue
			}
			if err := verifiedRead(dialer, log, a, wantAddr, wantSlot, slotHex != ""); err != nil {
				// Ordinary retry: the anchor may predate a peer's state
				// window, or every dial so far lacked snap. The next
				// poll cycle re-publishes and more peers arrive.
				log.Debug("verified read deferred", "reason", err)
				continue
			}
			return nil
		case <-reads.C:
			// Re-try with the ALREADY-held anchor when new peers arrive
			// between LC cycles: the anchor channel only fires on LC
			// cycles, and a snap peer READYing right after one would
			// otherwise wait a full slot.
			if getAccount != "" && haveAnchor {
				if err := verifiedRead(dialer, log, latest, wantAddr, wantSlot, slotHex != ""); err == nil {
					return nil
				}
			}
		case <-summary.C:
			if !quiet {
				report(disc, dialer, log)
			}
		}
	}
}

// lcAnchor is one snapshot of the light client's trust position: the
// finalized slot and the execution payload's OWN state_root field it
// commits to (lc.Store.FinalizedStateRoot — the only root a snap read
// may query).
type lcAnchor struct {
	slot      uint64
	stateRoot [32]byte
}

// publishAnchor keeps the buffered channel at exactly the newest
// anchor: drain-then-send, dropping a stale unconsumed snapshot — a
// reader that wakes late wants the FRESHEST root, not one queued
// behind it.
func publishAnchor(anchors chan lcAnchor, a lcAnchor) {
	select {
	case <-anchors:
	default:
	}
	select {
	case anchors <- a:
	default:
	}
}

// runLightClient bootstraps the LC over libp2p (static pins, the same
// set myotis-lc dials), walks the committee chain, and keeps the
// anchor fresh on the myotis-lc steady loop — every answer through
// the part-3 processor (checkpoint pin, period gate, BLS, Merkle
// branches). onAnchor fires after bootstrap/catch-up and after every
// steady cycle. This is the same loop as cmd/myotis-lc's; when a
// second consumer appeared the honest move is to say so in a comment
// and re-unify the two in 3c rather than contort the merged main.
func runLightClient(ctx context.Context, logf func(string, ...any), anchors chan lcAnchor) error {
	c := chain.ConsensusMainnet()
	h, err := clsync.NewHost()
	if err != nil {
		return fmt.Errorf("libp2p host: %w", err)
	}
	defer h.Close()
	syncer := clsync.NewSyncer(c, h, logf)
	clsync.InstallGossipSubHold(h)
	clsync.ServeInstall(h, syncer.LocalStatus)

	bootCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	st, err := syncer.RunBootstrap(bootCtx)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if err := syncer.RunCatchUp(bootCtx, st); err != nil {
		return fmt.Errorf("catch-up: %w", err)
	}
	publishAnchor(anchors, snapshot(st))

	for ctx.Err() == nil {
		if err := syncer.RunCatchUp(ctx, st); err != nil {
			logf("re-catch-up: %v", err)
		} else if chain.SyncCommitteePeriod(syncer.Consensus.SlotAt(time.Now().Unix())) > st.Period() {
			logf("committee behind wall clock after re-catch-up; skipping finality poll this cycle")
		} else if outcome, err := syncer.PollFinality(ctx, st); err != nil {
			logf("finality poll: %v", err)
		} else {
			logf("finality poll: outcome %v, finalized slot %d", outcome, st.Finalized.Slot)
		}
		publishAnchor(anchors, snapshot(st))
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(chain.SecondsPerSlot) * time.Second):
		}
	}
	return ctx.Err()
}

func snapshot(st *lc.Store) lcAnchor {
	return lcAnchor{slot: st.Finalized.Slot, stateRoot: st.FinalizedStateRoot()}
}

// snapPeers hands the reader the live snap-capable sessions
// (cap-bounded by snapread itself).
func (d *dialer) snapPeers() []snapread.Peer {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []snapread.Peer
	for _, s := range d.ready {
		if s.HasSnap() {
			out = append(out, s)
		}
	}
	return out
}

// verifiedRead fires once the read has both halves: an anchored state
// root and at least one snap session. Its output NEVER includes a
// peer's claim without saying so — every printed field comes from a
// proof leaf, verified against the snapshot's root.
func verifiedRead(d *dialer, log *slog.Logger, a lcAnchor, addr common.Address, slot [32]byte, wantSlot bool) error {
	peers := d.snapPeers()
	if len(peers) == 0 {
		return fmt.Errorf("no snap-capable READY peers yet (anchor is ready: slot %d)", a.slot)
	}
	out, err := snapread.Account(peers, a.stateRoot, addr)
	if err != nil {
		return err
	}
	attrs := []any{
		"account", addr.Hex(),
		"verifiedAt", fmt.Sprintf("0x%x", a.stateRoot),
		"lcFinalizedSlot", a.slot,
		"peers", len(peers),
	}
	if out.Absent() {
		attrs = append(attrs, "account", "PROVEN ABSENT (empty account)")
		log.Info("verified account read", attrs...)
		return nil
	}
	a2 := out.Account
	attrs = append(attrs,
		"nonce", a2.Nonce,
		"balanceWei", new(big.Int).SetBytes(a2.Balance).String(),
		"storageRoot", fmt.Sprintf("0x%x", a2.StorageRoot),
		"codeHash", fmt.Sprintf("0x%x", a2.CodeHash),
		"verifyMethod", "snapProof→lcAnchor",
	)
	log.Info("verified account read", attrs...)
	if wantSlot {
		v, err := snapread.Slot(peers, a.stateRoot, addr, slot)
		if err != nil {
			return fmt.Errorf("slot read: %w", err)
		}
		log.Info("verified storage read",
			"account", addr.Hex(), "slot", fmt.Sprintf("0x%x", slot),
			"value", fmt.Sprintf("0x%x", v),
			"anchoredAt", fmt.Sprintf("0x%x", a2.StorageRoot), // the PROVEN one
			"verifyMethod", "snapProof→provenStorageRoot")
	}
	return nil
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
