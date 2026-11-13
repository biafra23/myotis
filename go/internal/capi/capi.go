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
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/biafra23/myotis/go/internal/engine"
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
	ring     = &ringHandler{}

	// Process-global toggles, as the header marks them. dnsDiscovery is
	// FIXED in the Go engine (the DNS sweep is core discovery there),
	// which set_dns_discovery reports as the state actually in force;
	// metering is stored for the status figures the host reported even
	// though the Go engine does not yet count bytes against it.
	dnsDiscovery = true
	metering     int32
)

type entry struct {
	eng     *engine.Engine
	cancel  context.CancelFunc // stops the LC loop
	started bool
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

// unsupported builds the permanent-refusal JSON: -32602 is the
// contract's documented PERMANENT code (-32000 would invite host-side
// retries of something that will never succeed).
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

// knownNetworks is the catalog's canonical-name list — enough to honor
// the contract's -2 ("canonical but unsupported") versus -1 ("unknown
// name/alias") split even though this engine serves one network.
var knownNetworks = map[string]string{
	"mainnet": "mainnet",
	"gnosis":  "gnosis",
	"sepolia": "sepolia",
	"chiado":  "chiado",
}

var networkAliases = map[string]string{
	"mainnet": "mainnet", "ethereum": "mainnet", "eth": "mainnet", "1": "mainnet",
}

func canonical(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if c, ok := knownNetworks[n]; ok {
		return c, true
	}
	if c, ok := networkAliases[n]; ok {
		return c, true
	}
	return "", false
}

// CanonicalNetworkName is the catalog answer: known-and-servable names
// canonicalize; a known-but-unsupported network is NOT in this
// library's catalog (Create tells it apart with -2).
func CanonicalNetworkName(name string) (string, bool) {
	c, ok := canonical(name)
	if !ok || c != "mainnet" {
		return "", false
	}
	return c, true
}

func AvailableNetworksJSON() string {
	return `[{"name":"mainnet","chainId":1,"supported":true}]`
}

// listenPortEnv lets a host (and the tests) move the discv4 UDP port
// without inventing a Go-only setter before myotis_set_listen_ports is
// functional: -1 ephemeral, 0 network default.
func listenPortEnv() int {
	if v := os.Getenv("MYOTIS_GO_LISTEN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

// Create allocates a NOT-YET-STARTED handle (>= 1): discovery and the
// light client begin at Start, per the header's contract. Return
// codes mirror it: -1 unknown name / init failure, -2 canonical-but-
// unsupported network (this engine serves mainnet only — multichain is
// step 4 of the owner's program), and Go has no checkpoint-bootstrap
// path, so -3 never occurs.
func Create(network, dataDir string) int64 {
	c, ok := canonical(network)
	if !ok {
		return -1
	}
	if c != "mainnet" {
		return -2
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
	table[next] = &entry{eng: eng}
	return next
}

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

// PendingNonceOverlay reports the nonce a host should use for a new
// transaction. The Go engine has no local pending pool, so the mined
// nonce IS the effective nonce; -1 for an unknown handle (contract
// sentinel for "no answer").
func PendingNonceOverlay(handle int64, address string, minedNonce int64) int64 {
	mu.Lock()
	_, ok := table[handle]
	mu.Unlock()
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
	e.cancel = cancel
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
	if ok {
		if e.cancel != nil {
			e.cancel()
		}
		e.eng.Close()
	}
}

type statusJSON struct {
	Engine    string `json:"engine"`    // always "go" — the status badge reads this
	MyotisABI int    `json:"myotisAbi"` // the header ABI this subset implements
	Network   string `json:"network"`
	Running   bool   `json:"running"`
	// SnapPeers/ReadyPeers are live sessions (SnapPeers ⊆ ReadyPeers);
	// like the Rust status they count connections, not history.
	SnapPeers  int         `json:"snapPeers"`
	ReadyPeers int         `json:"readyPeers"`
	Anchor     *anchorJSON `json:"anchor"` // null before the first verified anchor
	// Capabilities is the machine-readable split of this library.
	Capabilities map[string]bool `json:"capabilities"`
	// NetworkMetering is the code the host last reported (0 until it
	// did), echoed per myotis_network_metering; the Go engine does not
	// yet attribute bytes, so no usage figures ride alongside it.
	NetworkMetering int32 `json:"networkMetering"`
}

type anchorJSON struct {
	Slot        uint64 `json:"slot"`
	StateRoot   string `json:"stateRoot"`
	BlockNumber uint64 `json:"blockNumber"`
	BlockHash   string `json:"blockHash"`
}

func StatusJSON(handle int64) string {
	mu.Lock()
	e, ok := table[handle]
	mu.Unlock()
	if !ok {
		return "{}" // the header's answer for an unknown handle
	}
	st := statusJSON{
		Engine:          "go",
		MyotisABI:       MyotisABIVersion,
		Network:         "mainnet",
		Running:         e.started,
		SnapPeers:       len(e.eng.SnapPeers()),
		ReadyPeers:      e.eng.ReadyPeerCount(),
		Capabilities:    capabilities(),
		NetworkMetering: readMetering(),
	}
	if a, ok := e.eng.Anchor(); ok {
		st.Anchor = &anchorJSON{
			Slot:        a.BeaconSlot,
			StateRoot:   hexHash(a.StateRoot),
			BlockNumber: a.ExecNumber,
			BlockHash:   hexHash(a.ExecBlockHash),
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
		"tor": false, "pauseResume": false, "wsBoundOverride": false,
		"staleAnchorConsent": false, "bootEnodes": false, "listenPorts": false,
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
	mu.Lock()
	e, ok := table[handle]
	mu.Unlock()
	if !ok {
		return retryableErr("go engine: unknown handle")
	}
	if !e.started {
		return retryableErr("go engine: handle not started (myotis_start)")
	}
	if msg, refused := accountBlockErr(block); refused {
		return msg
	}
	ctx, cancel := context.WithTimeout(context.Background(), ReadBudget)
	defer cancel()
	rd, err := e.eng.Account(ctx, address, [32]byte{}, false)
	if err != nil {
		return retryableErr("go engine: account read: " + err.Error())
	}
	out, err := rd.AccountJSON(time.Now().Unix())
	if err != nil {
		return retryableErr("go engine: account read: " + err.Error())
	}
	return out
}

// GetStorageProofJSON runs the two-hop account→slot read (the slot
// anchored at the PROVEN storageRoot of the same read). holder_hex is
// the ERC-20-delegation selector; the Go engine has no delegated-code
// resolution, so a non-empty holder is refused permanently rather than
// ignored.
func GetStorageProofJSON(handle int64, address string, slot int64, holder string) string {
	mu.Lock()
	e, ok := table[handle]
	mu.Unlock()
	if !ok {
		return retryableErr("go engine: unknown handle")
	}
	if !e.started {
		return retryableErr("go engine: handle not started (myotis_start)")
	}
	if strings.TrimSpace(holder) != "" {
		return permanentErr("go engine: holder_hex (delegated storage) is not supported; pass null")
	}
	if slot < 0 {
		return permanentErr("go engine: slot must be >= 0")
	}
	var key [32]byte
	u := uint64(slot)
	key[24] = byte(u >> 56)
	key[25] = byte(u >> 48)
	key[26] = byte(u >> 40)
	key[27] = byte(u >> 32)
	key[28] = byte(u >> 24)
	key[29] = byte(u >> 16)
	key[30] = byte(u >> 8)
	key[31] = byte(u)
	ctx, cancel := context.WithTimeout(context.Background(), ReadBudget)
	defer cancel()
	rd, err := e.eng.Account(ctx, address, key, true)
	if err != nil {
		return retryableErr("go engine: storage read: " + err.Error())
	}
	out, err := rd.StorageJSON(time.Now().Unix())
	if err != nil {
		return retryableErr("go engine: storage read: " + err.Error())
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
