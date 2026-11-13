// Package capi is the Go engine's C-ABI surface (desktop-embed step 1,
// part 1b): the handle table, lifecycle, and JSON plumbing that
// cmd/myotis-capi exports as a c-shared library for JVM JNA consumers.
//
// The contract is rust/include/myotis_engine.h (ABI 57). The Go engine
// is the READ engine of that contract: the lifecycle functions, the
// account/storage verified reads, status, and the log drain are
// FUNCTIONAL; every other exported symbol exists (so the host's
// bindings are a library-name swap, not a symbol hunt) but returns an
// honest refusal — a permanent {"error":…,"code":-32602} JSON for the
// JSON getters, false for the setters, and the contract's own "not
// compiled in" codes where they exist (myotis_tor_status → 0 literally
// means "this build has no Tor support"). A host learns the split from
// myotis_go_capabilities_json, and from every status JSON's
// "capabilities" object.
//
// The status JSON keeps the Rust engine's KEY SET (host.rs's
// status_object): a consumer that parses the Rust shape reads a Go
// status with the same code — same names, same types, same
// not-started values — and the Go divergences are only (a) three
// clearly-named extra keys at the end (engine/myotisAbi/capabilities)
// and (b) honest zeros/false where the Go engine has no corresponding
// machinery (per-peer served-request counters, backoff/blacklist,
// hunt flags), each marked in the struct below.
//
// Values keep the engine's trust discipline all the way to the wire:
// what a peer says reaches a host only through a proof verified
// against a BLS-accepted anchor, and a block selector the engine
// cannot apply is REFUSED, never accepted and quietly reinterpreted
// (the #314 rule).
package capi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/biafra23/myotis/go/internal/chain"
	"github.com/biafra23/myotis/go/internal/clsync"
	"github.com/biafra23/myotis/go/internal/engine"
	"github.com/ethereum/go-ethereum/crypto"
)

// MyotisABIVersion is the myotis_engine.h ABI whose subset this library
// implements; myotis_init returns it so a host gated on the header's
// MYOTIS_ABI_VERSION macro gates identically on Go and Rust.
const MyotisABIVersion = 57

// ReadBudget is the wall-clock cap on one blocking verified read — the
// same ~90 s budget the Rust twin gives its reads, so a host's JNA
// thread never waits open-endedly on a stalled dial wall.
const ReadBudget = 90 * time.Second

var (
	mu    sync.Mutex
	table = map[int64]*entry{}
	next  int64

	initOnce sync.Once
	ring     = newRingHandler()

	// Process-global toggles, as the header marks them. dnsDiscovery is
	// FIXED in the Go engine (the DNS sweep is core discovery there),
	// which set_dns_discovery reports as the state actually in force;
	// metering is stored for the status figures the host reported even
	// though the Go engine does not yet count bytes against it.
	dnsDiscovery = true
	metering     int32
)

// entry is one handle's state. Every field except eng is guarded by
// the package mu — reads go through lookup, which snapshots them, so
// a status poll racing myotis_start never races a bool read (PR #827
// review: the started flag was read outside the lock and -race said
// so).
type entry struct {
	eng *engine.Engine
	// ctx is the handle's lifetime context, created by Start; every
	// READ derives from it (PR #827 review: reads derived from
	// context.Background() outlived myotis_stop by up to the whole
	// ReadBudget — the header asks Stop to "signal pending readers,
	// drain registered work", which needs both the derivation and
	// the reads waitgroup). cancel stops the LC loop too; set by
	// Start under mu, read by Stop after removing the entry (a
	// removed entry takes no more Start writes, so the handoff is
	// ordered by the map delete).
	ctx     context.Context
	cancel  context.CancelFunc
	reads   sync.WaitGroup // reads that began while the handle lived
	started bool
	// servedWindow is the myotis_set_served_block_window value in
	// force, clamped as the contract prescribes. This engine dials and
	// never serves blocks to peers, so the value is recorded, not
	// acted on — see SetServedBlockWindow.
	servedWindow int32
}

// lookup snapshots a handle's shared state under mu (non-blocking
// reads: status, setters, the nonce overlay).
func lookup(handle int64) (eng *engine.Engine, started bool, ok bool) {
	mu.Lock()
	defer mu.Unlock()
	e, found := table[handle]
	if !found {
		return nil, false, false
	}
	return e.eng, e.started, true
}

// beginRead registers a blocking read against a STARTED handle under
// mu, returning the handle's lifetime context; Stop's Wait is what
// makes "synchronous" true. The caller must defer e.reads.Done().
func beginRead(handle int64) (e *entry, started bool, exists bool) {
	mu.Lock()
	defer mu.Unlock()
	en, found := table[handle]
	if !found {
		return nil, false, false
	}
	if !en.started || en.ctx == nil {
		// ctx==nil with started==true only happens for a handle a
		// test forged; a real Start always sets both. Treating it as
		// "not started" keeps a nil-parent panic out of the reads.
		return nil, false, true
	}
	en.reads.Add(1)
	return en, true, true
}

// classifyReadErr maps an Engine.Account failure to the contract's
// two error shapes. The distinction is the host's retry rule, so it
// is typed, not prose-parsed (PR #827 review: a flat retryable made
// a state no retry on the handle can clear look retryable forever):
//   - stale-anchor park → retryable, because THIS handle can clear
//     it — myotis_accept_stale_anchor / myotis_set_ws_bound_periods
//     restart the loop (and status says STALE_ANCHOR meanwhile);
//   - any other LC death → PERMANENT -32602: the loop is gone and
//     only stop-and-recreate revives it;
//   - everything else (budget expiry, proof-side deferrals, unknown
//     handle) → retryable, as before.
func classifyReadErr(what string, err error) string {
	var lce *engine.LCError
	if errors.As(err, &lce) {
		if errors.Is(err, clsync.ErrStaleAnchor) {
			return retryableErr("go engine: " + what + ": " + err.Error() +
				" — consent to the anchor's age with myotis_accept_stale_anchor" +
				" or widen the bound with myotis_set_ws_bound_periods")
		}
		return permanentErr("go engine: " + what + ": " + err.Error() +
			" — this handle's light client stopped; myotis_stop it and myotis_create a new one")
	}
	return retryableErr("go engine: " + what + ": " + err.Error())
}

// Init installs the log ring and returns the ABI version — the
// handshake myotis_engine.h prescribes before any other call.
func Init() int32 {
	initOnce.Do(func() {})
	return MyotisABIVersion
}

// Logger is the slog logger a host should hand the engine: every line
// lands in the drain_logs ring (as well as wherever else the host
// points it).
func Logger() *slog.Logger { return slog.New(ring) }

func DrainLogs(max int) string { return ring.drain(max) }

// Unsupported builds the refusal for a functional-in-Rust, refused-
// here export. Exported because cmd/myotis-capi's stub bodies all
// route through it — one refusal wording for the whole library.
func Unsupported(name string) string {
	return permanentErr(fmt.Sprintf("go engine: %s is not supported by this read-only engine", name))
}

func retryableErr(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

// permanentErr: the -32602 shape, built by json.Marshal so a message
// carrying quotes or backslashes can never break the document (a
// hand-Sprintf'd one once emitted `"block selector "latest" needs…"`
// — valid-looking until parsed; the test caught it).
func permanentErr(msg string) string {
	b, _ := json.Marshal(map[string]any{"error": msg, "code": -32602})
	return string(b)
}

// networkInfo is the golden catalog shape: io.myotis.api.NetworkInfo /
// rust/myotis-engine/src/catalog.rs — the nine keys, exact camelCase.
// (The invented "supported" bool of the first draft is NOT part of
// that contract; what a build can RUN is told by myotis_create's
// return codes, not by the catalog.)
type networkInfo struct {
	Name              string `json:"name"`
	DisplayName       string `json:"displayName"`
	ChainID           uint64 `json:"chainId"`
	HasENS            bool   `json:"hasEns"`
	DefaultELPort     uint16 `json:"defaultElPort"`
	DefaultDiscv5Port uint16 `json:"defaultDiscv5Port"`
	DefaultRPCPort    uint16 `json:"defaultRpcPort"`
	CLGenesisTime     uint64 `json:"clGenesisTime"`
	SecondsPerSlot    uint32 `json:"secondsPerSlot"`
}

// mainnetInfo must equal the mainnet entry of
// rust/testdata/networks_catalog.json — pinned by TestCatalogMatchesGolden.
var mainnetInfo = networkInfo{
	Name: "mainnet", DisplayName: "Ethereum Mainnet", ChainID: 1, HasENS: true,
	DefaultELPort: 30303, DefaultDiscv5Port: 9000, DefaultRPCPort: 8545,
	CLGenesisTime: 1_606_824_023, SecondsPerSlot: 12,
}

// knownNetworks/aliases mirror rust/myotis-engine/src/catalog.rs
// canonical_network_name EXACTLY (it lowercases and matches these
// strings — nothing else, no "ethereum", no chain-id digits): the
// differential test of part 1c compares the two libraries' answers
// name for name, so the tables may not drift.
var knownNetworks = map[string]bool{
	"mainnet": true, "gnosis": true, "sepolia": true, "chiado": true,
}

var networkAliases = map[string]string{
	"gbc": "gnosis", "xdai": "gnosis",
}

func canonical(name string) (string, bool) {
	n := strings.ToLower(name) // Rust does to_ascii_lowercase, nothing more — no trim
	if knownNetworks[n] {
		return n, true
	}
	if c, ok := networkAliases[n]; ok {
		return c, true
	}
	return "", false
}

// CanonicalNetworkName is the catalog answer: every catalog network
// canonicalizes — including the ones THIS build cannot run (Create
// tells those apart with -2; the Rust twin canonicalizes all four the
// same way).
func CanonicalNetworkName(name string) (string, bool) {
	return canonical(name)
}

// AvailableNetworksJSON returns the catalog in the pinned NetworkInfo
// shape, listing the networks THIS library can run — mainnet alone,
// until multichain (step 4) lands; Rust answers all four there. A
// host treats a listed name as creatable, which is exactly true here.
func AvailableNetworksJSON() string {
	b, _ := json.Marshal([]networkInfo{mainnetInfo})
	return string(b)
}

// listenPortEnv lets a host (and the tests) move the discv4 UDP port
// without inventing a Go-only setter before myotis_set_listen_ports is
// functional: -1 ephemeral, 0 network default. The DEFAULT is
// ephemeral (PR #827 review): the header fixes OS-assigned as the
// port a handle uses when myotis_set_listen_ports was never called,
// and pinning :30303 by default collides with any local execution
// client, the daemon, or a second handle — and a bind failure fails
// myotis_start here, where Rust degrades instead. The bound port is
// still advertised in the ENR, so discovery is unaffected.
func listenPortEnv() int {
	if v := os.Getenv("MYOTIS_GO_LISTEN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return -1
}

// Create allocates a NOT-YET-STARTED handle (>= 1): discovery and the
// light client begin at Start, per the header's contract. Return
// codes mirror it: -1 unknown name / runtime-init failure (including
// a missing or empty data_dir — the Rust engine canonicalizes it and
// fails the same way), -2 canonical-but-unsupported network (this
// engine serves mainnet only — multichain is step 4 of the owner's
// program), and Go has no checkpoint-bootstrap path, so -3 never
// occurs.
func Create(network, dataDir string) int64 {
	c, ok := canonical(network)
	if !ok {
		return -1
	}
	if c != "mainnet" {
		return -2
	}
	if strings.TrimSpace(dataDir) == "" {
		// Refuse, don't guess: passing "" to Engine would write the
		// node key into the HOST PROCESS's cwd — the library's caller
		// never asked for that. Rust's canonicalize("") fails → -1.
		return -1
	}
	eng, err := engine.New(engine.Config{
		DataDir:     dataDir,
		ListenPort:  listenPortEnv(),
		DialPeers:   true,
		MaxDials:    4,
		MaxReady:    8,
		RequireSnap: true, // this is the read engine
		Logger:      Logger(),
	})
	if err != nil {
		return -1
	}
	mu.Lock()
	defer mu.Unlock()
	next++
	table[next] = &entry{eng: eng, servedWindow: defaultServedBlockWindow}
	return next
}

// defaultServedBlockWindow mirrors the Rust engine's shipped default
// (the eth/69 served-block window; see SetServedBlockWindow).
const defaultServedBlockWindow = 512

// CreateWithCheckpoint refuses rather than ignores: this engine
// bootstraps ONLY from its embedded checkpoint, so a caller-supplied
// root cannot be applied — and accepting it silently would answer at
// an anchor the caller did not choose. The contract's -1 ("cannot
// create") is the honest refusal; -3 (checkpoint-generation mismatch)
// never occurs because there is no checkpoint generation here.
func CreateWithCheckpoint(network, dataDir, root string) int64 {
	_ = root
	c, ok := canonical(network)
	if !ok {
		return -1
	}
	if c != "mainnet" {
		return -2
	}
	return -1
}

// Pause/Resume: the Go engine has no Paused state (idle-sleep is
// engine-internal in Go terms), so every pause is a no-transition and
// the contract's "true only on an actual transition" answers false.
func Pause(handle int64) bool  { return false }
func Resume(handle int64) bool { return false }

// SetTorEnabled answers the contract's own question — "true iff this
// build supports Tor" — and this build does not.
func SetTorEnabled(on bool) bool { return false }

// SetTorStorageDirs has no client to hand the directories to.
func SetTorStorageDirs(stateDir, cacheDir string) bool { return false }

// TorStatus is the contract's bitmask; 0 means "this build has no Tor
// support" — literally true of the Go engine, not a masked failure.
func TorStatus() int32 { return 0 }

// SetServedBlockWindow records the eth/69 served-block window,
// clamped to [1,4096] as the contract prescribes; the contract's
// "False only for an unknown handle" is honored exactly. Recorded,
// not acted on: this engine dials peers and never SERVES blocks to
// them, so no answer this library produces depends on the window —
// the honest capability disclosure is capabilities["servedBlockWindow"]
// in every status, which says "accepted and stored", while
// caps like blocks:false say nothing here is served at all.
func SetServedBlockWindow(handle int64, blocks int32) bool {
	mu.Lock()
	defer mu.Unlock()
	e, ok := table[handle]
	if !ok {
		return false
	}
	e.servedWindow = max(1, min(int32(4096), blocks))
	return true
}

// SetWsBoundPeriods overrides the weak-subjectivity bound (0 restores
// the network default), APPLIED live: the LC loop consults it at
// every gate, and a loop that had already refused bootstrap as
// STALE_ANCHOR is restarted — the contract's "a handle parked in the
// STALE_ANCHOR beaconState re-evaluates within a second". False for
// an unknown handle or a negative bound (a parameter that cannot be
// applied is refused, never accepted and dropped).
func SetWsBoundPeriods(handle int64, periods int64) bool {
	eng, _, ok := lookup(handle)
	if !ok || periods < 0 {
		return false
	}
	return eng.SetWsBoundPeriods(uint64(periods))
}

// AcceptStaleAnchor is the one-shot consent to the embedded anchor's
// age (myotis_accept_stale_anchor): suppresses both weak-subjectivity
// layers for the rest of this handle's life, never persisted, and
// releases a bootstrap that had already parked. False only for an
// unknown handle, as the contract says.
func AcceptStaleAnchor(handle int64) bool {
	eng, _, ok := lookup(handle)
	if !ok {
		return false
	}
	return eng.AcceptStale()
}

// PendingNonceOverlay reports the nonce a host should use for a new
// transaction. The Go engine has no local pending pool, so the mined
// nonce IS the effective nonce; -1 for an unknown handle (contract
// sentinel for "no answer").
func PendingNonceOverlay(handle int64, address string, minedNonce int64) int64 {
	_, _, ok := lookup(handle)
	if !ok || minedNonce < 0 {
		return -1
	}
	return minedNonce
}

// Start begins EL discovery/dialing and the light client. False for an
// unknown or already-running handle, or if the network could not
// start (retryable via another Start, per Engine.StartNetwork).
func Start(handle int64) bool {
	mu.Lock()
	e, ok := table[handle]
	if !ok || e.started {
		mu.Unlock()
		return false
	}
	e.started = true
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx, e.cancel = ctx, cancel
	mu.Unlock()
	if err := e.eng.StartNetwork(); err != nil {
		mu.Lock()
		e.started = false
		mu.Unlock()
		return false
	}
	e.eng.StartLC(ctx)
	return true
}

// Stop signals readers, closes the engine, and removes the handle.
// Synchronous, as the header demands (Engine.Close waits for the LC
// goroutine's libp2p release). No-op for an unknown id.
func Stop(handle int64) {
	mu.Lock()
	e, ok := table[handle]
	delete(table, handle)
	mu.Unlock()
	if !ok {
		return
	}
	if e.cancel != nil {
		e.cancel() // signals readers (their ctx derives from the handle's) AND the LC loop
	}
	e.reads.Wait() // "drain registered work" — synchronous means the JNA threads are out
	e.eng.Close()
}

// statusJSON carries EXACTLY the Rust status_object key set (host.rs),
// in that order, with the same types — including the string
// networkMetering (the Rust side serializes Metering::as_str, not the
// numeric code) and the 0x-less finalizedRootHex (host.rs hex32).
// Keys whose machinery the Go engine does not have carry honest
// zeros/false, marked per field; the three Go-only keys come last.
type statusJSON struct {
	Running        bool   `json:"running"`
	Paused         bool   `json:"paused"` // no Paused lifecycle in Go: always false
	Network        string `json:"network"`
	BeaconState    string `json:"beaconState"`
	Bootstrapped   bool   `json:"bootstrapped"`
	FinalizedSlot  uint64 `json:"finalizedSlot"`
	OptimisticSlot uint64 `json:"optimisticSlot"`
	CurrentPeriod  uint64 `json:"currentPeriod"`
	TargetPeriod   uint64 `json:"targetPeriod"`
	PeerCount      int    `json:"peerCount"` // LC peers, like Rust
	// Not tracked by the Go engine (it serves no peers): honest 0.
	ServedPeersLastMinute int `json:"servedPeersLastMinute"`
	// The Go engine discovers over discv4 (Rust: discv5); the Kademlia
	// routing-table size is the same-shaped number under the contract
	// key — the key names the discovery layer's table, and this is it.
	Discv5TableSize int    `json:"discv5TableSize"`
	SyncStartPeriod int64  `json:"syncStartPeriod"` // Go has no hunt phase: -1, like Rust's initial
	LcHunting       bool   `json:"lcHunting"`       // no hunt machinery: false
	WsBoundPeriods  uint64 `json:"wsBoundPeriods"`  // ENFORCED bound, incl. override
	// finalizedRootHex: 64 lowercase hex, NO 0x (host.rs hex32) —
	// unlike the read results, which use 0x-prefixed *Hash fields.
	FinalizedRootHex         string `json:"finalizedRootHex"`
	ElReaderAvailable        bool   `json:"elReaderAvailable"` // the reader is in-process: started == available
	SnapPeers                int    `json:"snapPeers"`
	SnapServingPeers         int    `json:"snapServingPeers"`  // == snapPeers (dial-only: every snap session can serve now)
	Snap2ServingPeers        int    `json:"snap2ServingPeers"` // the snap/2 subset (EIP-8189), informational
	ReadyPeers               int    `json:"readyPeers"`
	DiscoveredPeers          int    `json:"discoveredPeers"`
	AttemptedDials           int    `json:"attemptedDials"`
	BackedOffPeers           int    `json:"backedOffPeers"`   // no backoff machinery: 0
	BlacklistedPeers         int    `json:"blacklistedPeers"` // no blacklist: 0
	OptimisticBlockNumber    uint64 `json:"optimisticBlockNumber"`
	FinalizedBlockNumber     uint64 `json:"finalizedBlockNumber"`
	PeerHeaderRequests       int    `json:"peerHeaderRequests"` // Go serves no peers: 0
	PeerHeaderRequestsServed int    `json:"peerHeaderRequestsServed"`
	PeerBodyRequests         int    `json:"peerBodyRequests"`
	PeerBodyRequestsServed   int    `json:"peerBodyRequestsServed"`
	ExecutionBlockNumber     uint64 `json:"executionBlockNumber"` // == finalized, per the Rust field comment
	ElHunting                bool   `json:"elHunting"`            // no stall window: false
	UpgradeAdvisory          any    `json:"upgradeAdvisory"`      // no fork watch: null
	DataUsage                any    `json:"dataUsage"`            // no byte accounting: null
	NetworkMetering          string `json:"networkMetering"`      // UNKNOWN/UNMETERED/METERED (Metering::as_str)

	// Go additions (never Rust-parsed keys; new wrappers ignore
	// unknowns, exactly as the Rust comments promise for THEIR extras):
	Engine       string          `json:"engine"` // always "go" — the status badge reads this
	MyotisABI    int             `json:"myotisAbi"`
	Capabilities map[string]bool `json:"capabilities"`
}

func meteringString(code int32) string {
	switch code {
	case 1:
		return "UNMETERED"
	case 2:
		return "METERED"
	default:
		return "UNKNOWN"
	}
}

func StatusJSON(handle int64) string {
	eng, started, ok := lookup(handle)
	if !ok {
		return "{}" // the header's answer for an unknown handle
	}
	now := time.Now().Unix()
	c := chain.ConsensusMainnet()
	wallPeriod := chain.SyncCommitteePeriod(c.SlotAt(now))
	st := statusJSON{
		Running:          started,
		Paused:           false,
		Network:          "mainnet",
		BeaconState:      eng.BeaconState(now),
		SyncStartPeriod:  -1,
		WsBoundPeriods:   eng.EffectiveWsBound(),
		FinalizedRootHex: strings.Repeat("0", 64),
		NetworkMetering:  meteringString(readMetering()),
		Engine:           "go",
		MyotisABI:        MyotisABIVersion,
		Capabilities:     capabilities(),
	}
	st.Bootstrapped = eng.Bootstrapped()
	if started {
		st.ElReaderAvailable = true // the reader is this process; it is up
		st.PeerCount = eng.LCPeerCount()
		table, live := eng.DiscoveryStats()
		st.Discv5TableSize = table
		st.DiscoveredPeers = live
		st.AttemptedDials = eng.AttemptedDials()
		snap, snap2 := eng.SnapServingPeers()
		st.SnapPeers = snap
		st.SnapServingPeers = snap
		st.Snap2ServingPeers = snap2
		st.ReadyPeers = eng.ReadyPeerCount()
		if a, ok := eng.Anchor(); ok {
			st.FinalizedSlot = a.BeaconSlot
			st.OptimisticSlot = a.OptimisticSlot
			st.CurrentPeriod = chain.SyncCommitteePeriod(a.BeaconSlot)
			st.TargetPeriod = max(st.CurrentPeriod, wallPeriod)
			st.FinalizedRootHex = hex.EncodeToString(a.StateRoot[:]) // no 0x, like hex32
			st.OptimisticBlockNumber = a.OptimisticExecNo
			st.FinalizedBlockNumber = a.ExecNumber
			st.ExecutionBlockNumber = a.ExecNumber
		} else {
			st.TargetPeriod = wallPeriod
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func capabilities() map[string]bool {
	return map[string]bool{
		"reads": true, "status": true, "logDrain": true,
		"evm": false, "blocks": false, "receipts": false, "logs": false,
		"logIndex": false, "ens": false, "rawTx": false, "fees": false,
		"accessList": false, "activityWatch": false, "proofs": false,
		"tor": false, "pauseResume": false,
		// Applied live through Engine.SetWsBoundPeriods /
		// Engine.AcceptStale (gates read them per check, and a parked
		// loop restarts): these are true in the full sense.
		"wsBoundOverride": true, "staleAnchorConsent": true,
		// Recorded + contract-answered, but inert while this engine
		// never serves blocks to peers (it is the dial-only side of
		// the split that blocks:false already declares):
		"servedBlockWindow": true,
		"bootEnodes":        false, "listenPorts": false,
	}
}

func hexHash(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }

// blockPolicies: what the header's block-selector contract (v32) means
// for an engine that reads ONLY at the beacon-finalized anchor.
// "finalized" is applied; the head tags would need verified head state
// this engine does not read, so they are REFUSED permanently with the
// way forward named — never accepted and answered at a different
// block than asked (the #314 / CLAUDE.md rule in its purest form).
func accountBlockErr(block string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(block)) {
	case "finalized":
		return "", false
	case "":
		// The header maps NULL/"" to the verified HEAD — an engine that
		// cannot read head must refuse it, not silently finalize.
		return permanentErr("go engine: the empty block selector means the verified head (myotis_engine.h v32), which this engine does not read; pass \"finalized\""), true
	default:
		return permanentErr(fmt.Sprintf("go engine: block selector %q needs verified head state; this engine reads only \"finalized\"", block)), true
	}
}

// RequestAccountJSON runs one verified account read at the finalized
// anchor. Errors: retryable {"error":…} for unknown handle / not
// running / budget expiry / proof-side failures (the host may re-ask
// once the anchor or peers move), permanent -32602 for a block
// selector this engine cannot apply. A verification VERDICT (absent
// account) is a normal result shape with failReason, not an error —
// exactly as the header's comment prescribes.
func RequestAccountJSON(handle int64, address, block string) string {
	// Selector BEFORE the handle lookup, as the twin's
	// parse_read_block does: a request whose selector no retry can
	// serve is the REQUEST's fault and gets its permanent refusal
	// whatever state the handle is in (the old order handed a
	// retryable "not started" first to a request that would never
	// have been servable anyway).
	if msg, refused := accountBlockErr(block); refused {
		return msg
	}
	e, started, exists := beginRead(handle)
	if !exists {
		return retryableErr("go engine: unknown handle")
	}
	if !started {
		return retryableErr("go engine: handle not started (myotis_start)")
	}
	defer e.reads.Done()
	ctx, cancel := context.WithTimeout(e.ctx, ReadBudget)
	defer cancel()
	rd, err := e.eng.Account(ctx, address, [32]byte{}, false)
	if err != nil {
		return classifyReadErr("account read", err)
	}
	out, err := rd.AccountJSON(time.Now().Unix())
	if err != nil {
		return classifyReadErr("account read", err)
	}
	return out
}

// GetStorageProofJSON runs the two-hop account→slot read (the slot
// anchored at the PROVEN storageRoot of the same read). holder_hex is
// the ERC-20 MAPPING KEY, exactly as the twin applies it
// (reader.rs storage_key: keccak256(pad32(holder) ‖ pad32(slot)) —
// the shape that reads a balance at a token contract, the repo's own
// `get-storage <token> <slot> <holder>` integration). A slot index at
// or above 2^63 arrives as a negative int64 and is recovered by bit
// pattern, as host.rs documents — clamping it would silently query a
// different slot. Deliberate divergence from the twin, marked in the
// result: the twin proves this read at the verified HEAD; this engine
// has no head read, so it proves at the finalized anchor and the
// result says so ("anchor":"finalized").
// storageKey is the twin's storage_key(slot, Some(holder)) derivation
// (reader.rs): keccak256(pad32(holder) ‖ pad32(slot)). ok=false only
// for a holder that is neither a hex 20-byte address nor a hex
// 32-byte word — refused by name, never applied "close enough".
func storageKey(holder string, slotKey [32]byte) ([32]byte, bool) {
	hexStr := strings.TrimPrefix(holder, "0x")
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(hexStr)%2 != 0 || (len(b) != 20 && len(b) != 32) {
		return [32]byte{}, false
	}
	var word [32]byte
	copy(word[32-len(b):], b)
	var pre [64]byte
	copy(pre[:32], word[:])
	copy(pre[32:], slotKey[:])
	return [32]byte(crypto.Keccak256Hash(pre[:])), true
}

func GetStorageProofJSON(handle int64, address string, slot int64, holder string) string {
	var key [32]byte
	u := uint64(slot) // negative int64 → its top bit set: the twin's recovery
	key[24] = byte(u >> 56)
	key[25] = byte(u >> 48)
	key[26] = byte(u >> 40)
	key[27] = byte(u >> 32)
	key[28] = byte(u >> 24)
	key[29] = byte(u >> 16)
	key[30] = byte(u >> 8)
	key[31] = byte(u)
	if h := strings.TrimSpace(holder); h != "" {
		var ok bool
		if key, ok = storageKey(h, key); !ok {
			return permanentErr("go engine: holder_hex must be a 20-byte address or 32-byte word in hex, or null")
		}
	}
	// Request-shape faults are refused before the handle lookup (the
	// twin's ordering); handle-state faults stay retryable.
	e, started, exists := beginRead(handle)
	if !exists {
		return retryableErr("go engine: unknown handle")
	}
	if !started {
		return retryableErr("go engine: handle not started (myotis_start)")
	}
	defer e.reads.Done()
	ctx, cancel := context.WithTimeout(e.ctx, ReadBudget)
	defer cancel()
	rd, err := e.eng.Account(ctx, address, key, true)
	if err != nil {
		return classifyReadErr("storage read", err)
	}
	out, err := rd.StorageJSON(time.Now().Unix())
	if err != nil {
		return classifyReadErr("storage read", err)
	}
	return out
}

func SetDNSDiscovery(on bool) bool {
	// The Go engine's DNS sweep is core discovery and cannot be
	// toggled; the contract asks set_dns_discovery to "return the
	// state now in force", and the state in force is on — so a host
	// asking for off sees the refusal in the return value itself
	// (false ≠ its request), and asking for on is applied.
	_ = on
	return dnsDiscovery
}

func SetNetworkMetering(code int32) bool {
	if code < 0 || code > 2 {
		return false
	}
	mu.Lock()
	metering = code
	mu.Unlock()
	return true
}

func readMetering() int32 {
	mu.Lock()
	defer mu.Unlock()
	return metering
}

func NetworkMetering() int32 { return readMetering() }

// CapabilitiesJSON backs myotis_go_capabilities_json (a Go-only
// export, so hosts never confuse the split with ABI gating): what the
// library answers, what it refuses, and the version identity of both
// contracts.
func CapabilitiesJSON() string {
	b, _ := json.Marshal(map[string]any{
		"engine":       "go",
		"goAbi":        1,
		"myotisAbi":    MyotisABIVersion,
		"capabilities": capabilities(),
		"readBlock":    "finalized",
		"networks":     []string{"mainnet"},
	})
	return string(b)
}
