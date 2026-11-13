package capi

// The C ABI contract, tested on the Go side of the seam (part 1b):
// return codes, refusal shapes, the apply-or-refuse discipline of
// the block selector, the status JSON's KEY SET pinned to the Rust
// engine's status_object, and the catalog pinned to the committed
// golden file. The reads themselves are the engine's tested path —
// what these tests pin is what a JNA host sees BEFORE a read can run
// (handle states, selector policy) and the exact shape of the
// refusals it sees instead.

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newStartedHandle makes a handle whose `started` is true WITHOUT a
// real Start (PR #827 review: the pure-policy tests need an entry in
// that state, not a mainnet join — discovery, dials and the libp2p
// host would put live network in every hermetic unit run). The
// engine behind it never began, so any read that got past the
// request-shape refusals fails fast ("light client not started")
// rather than reaching the network. TestLifecycleAndRefusals keeps
// the one real Start in the file.
func newStartedHandle(t *testing.T) int64 {
	t.Helper()
	h := Create("mainnet", t.TempDir())
	if h < 1 {
		t.Fatalf("Create(mainnet) = %d, want handle >= 1", h)
	}
	mu.Lock()
	table[h].started = true
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		e := table[h]
		delete(table, h)
		mu.Unlock()
		if e != nil {
			e.eng.Close()
		}
	})
	return h
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON (%v): %s", err, s)
	}
	return m
}

// rustStatusKeys is the key set of host.rs status_object /
// NOT_STARTED_FALLBACK — the keys the Java RustChainHandle parses.
// A Go status must answer every one of them with the same TYPE; the
// three Go additions (engine/myotisAbi/capabilities) are the only
// extras, and divergences in MEANING live in marked fields
// (honest zeros for machinery this engine lacks), never in missing
// or retyped keys (PR #827 review).
var rustStatusKeys = []string{
	"running", "paused", "network", "beaconState", "bootstrapped",
	"finalizedSlot", "optimisticSlot", "currentPeriod", "targetPeriod",
	"peerCount", "servedPeersLastMinute", "discv5TableSize",
	"syncStartPeriod", "lcHunting", "wsBoundPeriods", "finalizedRootHex",
	"elReaderAvailable", "snapPeers", "snapServingPeers",
	"snap2ServingPeers", "readyPeers", "discoveredPeers", "attemptedDials",
	"backedOffPeers", "blacklistedPeers", "optimisticBlockNumber",
	"finalizedBlockNumber", "peerHeaderRequests",
	"peerHeaderRequestsServed", "peerBodyRequests",
	"peerBodyRequestsServed", "executionBlockNumber", "elHunting",
	"upgradeAdvisory", "dataUsage", "networkMetering",
}

func TestStatusCarriesTheRustKeySet(t *testing.T) {
	h := newStartedHandle(t)
	st := decode(t, StatusJSON(h))
	got := map[string]bool{}
	for k := range st {
		got[k] = true
	}
	for _, k := range rustStatusKeys {
		if !got[k] {
			t.Errorf("status is missing Rust contract key %q", k)
		}
	}
	for k := range got {
		switch k {
		case "engine", "myotisAbi", "capabilities":
		default:
			found := false
			for _, r := range rustStatusKeys {
				if r == k {
					found = true
				}
			}
			if !found {
				t.Errorf("status carries unexplained extra key %q", k)
			}
		}
	}
	// Types the Rust side fixes (NOT_STARTED_FALLBACK shows the
	// shapes): beaconState/network/networkMetering are STRINGS —
	// networkMetering especially, it serializes Metering::as_str over
	// there, not the numeric code of myotis_set_network_metering.
	if _, ok := st["networkMetering"].(string); !ok {
		t.Errorf("networkMetering must be a string, got %T %v", st["networkMetering"], st["networkMetering"])
	}
	if root, ok := st["finalizedRootHex"].(string); !ok || len(root) != 64 || strings.HasPrefix(root, "0x") {
		t.Errorf("finalizedRootHex must be 64 hex chars WITHOUT 0x (host.rs hex32), got %v", st["finalizedRootHex"])
	}
	if st["syncStartPeriod"] != float64(-1) { // the Rust initial value; Go has no hunt phase
		t.Errorf("syncStartPeriod = %v, want -1", st["syncStartPeriod"])
	}
	if st["wsBoundPeriods"] != float64(13) {
		t.Errorf("wsBoundPeriods = %v, want the enforced bound 13", st["wsBoundPeriods"])
	}
	if st["engine"] != "go" || st["network"] != "mainnet" || st["running"] != true {
		t.Errorf("status identity wrong: %v", st)
	}
	caps, _ := st["capabilities"].(map[string]any)
	if caps["reads"] != true || caps["evm"] != false {
		t.Errorf("capabilities wrong: %v", caps)
	}

	// A reported metering shows up in the Rust STRING shape.
	if !SetNetworkMetering(2) {
		t.Fatal("metering 2 refused")
	}
	defer SetNetworkMetering(0)
	if got := decode(t, StatusJSON(h))["networkMetering"]; got != "METERED" {
		t.Errorf("networkMetering after code 2 = %v, want METERED", got)
	}
}

func TestLifecycleAndRefusals(t *testing.T) {
	h := newStartedHandle(t)

	if Start(h) {
		t.Error("second Start must be false (already-running handle)")
	}

	// (This loop runs against a never-created handle on purpose: the
	// selector is validated BEFORE the handle lookup, as the twin's
	// parse_read_block does, so the permanent refusal must not wait
	// for handle state.)
	for _, sel := range []string{"", "latest", "head", "safe", "pending", "123", "0x1c7c4"} {
		m := decode(t, RequestAccountJSON(424242, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", sel))
		if m["code"] != float64(-32602) {
			t.Errorf("selector %q on an UNKNOWN handle: want the permanent refusal first, got %v", sel, m)
		}
	}

	// Block-selector policy: everything but "finalized" is refused
	// permanently, the empty selector named as the head tag the
	// header says it is, and the refusal names the way forward.
	for _, sel := range []string{"", "latest", "head", "safe", "pending", "123", "0x1c7c4"} {
		m := decode(t, RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", sel))
		if m["code"] != float64(-32602) {
			t.Errorf("selector %q: want permanent -32602, got %v", sel, m)
		}
		if !strings.Contains(m["error"].(string), "finalized") {
			t.Errorf("selector %q: refusal must name \"finalized\": %v", sel, m["error"])
		}
	}

	Stop(h)
	if got := StatusJSON(h); got != "{}" {
		t.Errorf("status of a stopped handle = %q, want {}", got)
	}
	if Start(h) {
		t.Error("Start of a stopped (removed) handle must be false")
	}
	// Requests against the removed handle answer RETRYABLE (no code):
	// the host may start a new one and re-ask.
	m := decode(t, RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "finalized"))
	if _, has := m["code"]; has {
		t.Errorf("unknown-handle error must be retryable (no code), got %v", m)
	}
	if _, has := m["error"]; !has {
		t.Errorf("unknown-handle error must carry error: %v", m)
	}
}

func TestCreateReturnCodes(t *testing.T) {
	t.Setenv("MYOTIS_GO_LISTEN_PORT", "-1")
	if h := Create("dogecoin", t.TempDir()); h != -1 {
		t.Errorf("unknown network = %d, want -1", h)
	}
	if h := Create("gnosis", t.TempDir()); h != -2 {
		t.Errorf("canonical-but-unsupported network = %d, want -2 (multichain is step 4)", h)
	}
	// The alias table is catalog.rs's, NOT a Go invention: only
	// gbc/xdai alias gnosis — "ethereum"/"1" answer -1 HERE exactly
	// as canonical_network_name makes them unknown to Rust.
	if h := Create("1", t.TempDir()); h != -1 {
		t.Errorf("chain-id string \"1\" = %d, want -1 (not a Rust alias)", h)
	}
	if h := Create("Xdai", t.TempDir()); h != -2 {
		t.Errorf("alias \"Xdai\" = %d, want -2 (canonicalizes to gnosis)", h)
	}
	// An empty data_dir must be REFUSED (-1), not defaulted: passing
	// "" would otherwise write nodekey.key into the host process's
	// cwd (PR #827 review — Rust's canonicalize("") fails the same
	// way and answers -1).
	if h := Create("mainnet", ""); h != -1 {
		t.Errorf("empty data_dir = %d, want -1", h)
	}
	cwd, _ := os.Getwd()
	if _, err := os.Stat(cwd + "/nodekey.key"); err == nil {
		t.Errorf(`Create("") must not touch the cwd (found nodekey.key there)`)
	}
	// The Go engine reads only its embedded checkpoint: a
	// caller-supplied root cannot be applied, so it is refused rather
	// than silently ignored (the -3 generation never exists here).
	if h := CreateWithCheckpoint("mainnet", t.TempDir(), "0x11"+strings.Repeat("00", 31)); h != -1 {
		t.Errorf("CreateWithCheckpoint = %d, want -1 (refused)", h)
	}
	if h := CreateWithCheckpoint("gnosis", t.TempDir(), "0x11"); h != -2 {
		t.Errorf("CreateWithCheckpoint(gnosis) = %d, want -2", h)
	}
}

func TestStopWakesInFlightRead(t *testing.T) {
	// PR #827 review, CONFIRMED against the old code: myotis_stop
	// during a read left the JNA thread blocked for the whole 90 s
	// ReadBudget (the cancelled LC loop closed nothing). A Stop must
	// answer the pending read NOW — retryable, since a new handle
	// could serve a re-ask.
	t.Setenv("MYOTIS_GO_LISTEN_PORT", "-1")
	h := Create("mainnet", t.TempDir())
	if h < 1 {
		t.Fatalf("Create = %d", h)
	}
	if !Start(h) {
		t.Fatal("Start = false")
	}
	res := make(chan string, 1)
	go func() {
		res <- RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "finalized")
	}()
	time.Sleep(400 * time.Millisecond) // let the reader reach its wait
	stopDone := make(chan struct{})
	go func() { Stop(h); close(stopDone) }()
	select {
	case <-stopDone:
	case <-time.After(20 * time.Second):
		t.Fatal("Stop itself did not return")
	}
	select {
	case out := <-res:
		m := decode(t, out)
		if _, has := m["error"]; !has {
			t.Errorf("stopped read must answer an error, got %v", m)
		}
		if _, has := m["code"]; has {
			t.Errorf("stop-abort is retryable (host may re-ask on a new handle), got %v", m)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("in-flight read still blocked long after Stop (the 90 s budget bug)")
	}
}

func TestStorageRequestShapes(t *testing.T) {
	h := newStartedHandle(t)
	addr := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	// A malformed holder is refused permanently, BY NAME, before any
	// handle or network state (the mapping-key parameter is the
	// request's own fault when malformed).
	m := decode(t, GetStorageProofJSON(h, addr, 7, "0xdead"))
	if m["code"] != float64(-32602) || !strings.Contains(m["error"].(string), "holder_hex") {
		t.Errorf("malformed holder must be refused permanently by name: %v", m)
	}
	// A WELL-FORMED holder is APPLIED, not refused (it is the ERC-20
	// mapping key, reader.rs storage_key): the answer moves past the
	// request shape to the handle's state — here the fast
	// not-started retryable, since this test's engine never started.
	m = decode(t, GetStorageProofJSON(h, addr, 1, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
	if _, has := m["code"]; has {
		t.Errorf("a valid holder must not be refused as a request fault: %v", m)
	}
	// A slot ≥ 2^63 (negative int64) is a VALID slot recovered by
	// bit pattern, per host.rs — not malformed, not clamped.
	m = decode(t, GetStorageProofJSON(h, addr, -1, ""))
	if _, has := m["code"]; has {
		t.Errorf("negative int64 slot is a valid high slot, refused must be permanent-only: %v", m)
	}
	// The derivation itself, pinned: keccak(pad32(Vitalik) ‖ pad32(1))
	// — the exact shape the repo's integration test reads (its value
	// here is the pin, computed with the same keccak the read uses; a
	// derivation that stops matching reader.rs fails HERE, not in a
	// wallet balance read).
	var one [32]byte
	one[31] = 1
	got, ok := storageKey("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", one)
	if !ok || hex.EncodeToString(got[:]) != "b931be0b3d1fb06daf0d92e2b8dfe49ead9172e102b3af1e07a10cc29003beb2" {
		t.Errorf("storage_key derivation drifted from reader.rs: %x ok=%v", got, ok)
	}
	if _, ok := storageKey("0xd8dA6BF26964", one); ok { // 15 bytes: neither form
		t.Error("short holder must be refused")
	}
}

func TestUnsupportedShape(t *testing.T) {
	// The refusal every stub answers with: permanent -32602 (never the
	// retryable -32000 — hosts must not spin on a capability that
	// will never arrive), naming the exact function.
	m := decode(t, Unsupported("myotis_eth_call_json"))
	if m["code"] != float64(-32602) {
		t.Errorf("unsupported code = %v, want -32602", m["code"])
	}
	if !strings.Contains(m["error"].(string), "myotis_eth_call_json") {
		t.Errorf("refusal must name the function: %v", m["error"])
	}
}

func TestNotStartedHandleIsRetryable(t *testing.T) {
	t.Setenv("MYOTIS_GO_LISTEN_PORT", "-1")
	h := Create("mainnet", t.TempDir())
	if h < 1 {
		t.Fatalf("Create = %d", h)
	}
	t.Cleanup(func() { Stop(h) })
	m := decode(t, RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "finalized"))
	if _, has := m["code"]; has {
		t.Errorf("not-started must read retryable (start it and re-ask), got %v", m)
	}
	if !strings.Contains(m["error"].(string), "myotis_start") {
		t.Errorf("not-started error must name the fix: %v", m["error"])
	}
	s := decode(t, StatusJSON(h))
	if s["running"] != false {
		t.Errorf("created-but-unstarted status.running = %v, want false", s["running"])
	}
	// The Rust not-started shape's beaconState literal, same string.
	if s["beaconState"] != "STARTING" {
		t.Errorf("created-but-unstarted beaconState = %v, want STARTING", s["beaconState"])
	}
	if s["elReaderAvailable"] != false {
		t.Errorf("unstarted elReaderAvailable = %v, want false", s["elReaderAvailable"])
	}
}

func TestLogRingDrain(t *testing.T) {
	// drain: oldest first, newline-joined, removed on read, "" when
	// idle — the header's drain_logs semantics.
	r := newRingHandler()
	log := slog.New(r)
	log.Info("one")
	log.Warn("two")
	log.Info("three")
	if got := r.drain(2); got != "level=INFO msg=one\nlevel=WARN msg=two" {
		// TextHandler adds a time= prefix; assert order + membership
		// instead of the whole line.
		lines := strings.Split(got, "\n")
		if len(lines) != 2 || !strings.Contains(lines[0], "msg=one") || !strings.Contains(lines[1], "msg=two") {
			t.Fatalf("drain(2) = %q, want one then two", got)
		}
	}
	if got := r.drain(10); !strings.Contains(got, "msg=three") || strings.Contains(got, "msg=one") {
		t.Errorf("second drain must return only the remainder: %q", got)
	}
	if got := r.drain(10); got != "" {
		t.Errorf("drained ring must read empty, got %q", got)
	}
}

func TestRingKeepsDerivedLoggerAttrs(t *testing.T) {
	// A derived logger with a component attr (how the dialer logs:
	// log.With("component","dialer")) must land in the ring WITH the
	// attr — dropping it loses the marker hosts filter on (PR #827
	// review), and the view must still share the one buffer.
	r := newRingHandler()
	dial := slog.New(r.WithAttrs([]slog.Attr{slog.String("component", "dialer")}))
	dial.Info("dialed")
	if got := r.drain(10); !strings.Contains(got, "component=dialer") || !strings.Contains(got, "msg=dialed") {
		t.Errorf("derived attr dropped: drain = %q", got)
	}
	grouped := slog.New(r.WithGroup("el").WithAttrs([]slog.Attr{slog.String("kind", "pool")}))
	grouped.Info("pooled")
	if got := r.drain(10); !strings.Contains(got, "el.kind=pool") {
		t.Errorf("group must prefix attr names like the text handler: %q", got)
	}
}

func TestRingOverflowKeepsNewest(t *testing.T) {
	r := newRingHandler()
	for range ringCap + 10 {
		_ = r.Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "filler", 0))
	}
	if len(r.buf.lines) != ringCap {
		t.Fatalf("ring len = %d, want cap %d", len(r.buf.lines), ringCap)
	}
}

func TestProcessGlobals(t *testing.T) {
	// DNS discovery: the Go engine's sweep is core; set returns the
	// state IN FORCE, so a host asking for off sees the refusal in the
	// value it gets back.
	if !SetDNSDiscovery(false) || !SetDNSDiscovery(true) {
		t.Error("set_dns_discovery must report the in-force state (on)")
	}
	if SetNetworkMetering(5) {
		t.Error("metering code 5 must be refused")
	}
	if !SetNetworkMetering(2) || NetworkMetering() != 2 {
		t.Error("metering 2 must be recorded and readable")
	}
	SetNetworkMetering(0)
	// Tor: the contract's own codes — false / 0 mean "not in build".
	if SetTorEnabled(true) || TorStatus() != 0 || SetTorStorageDirs("/a", "/b") {
		t.Error("a Tor-less build must answer false/0 as the contract prescribes")
	}
}

func TestHandleStateSetters(t *testing.T) {
	// The three per-handle setters whose contract says "False only for
	// an unknown handle": a known handle gets true (the value is
	// APPLIED — ws-bound/stale-anchor through the engine's live gates;
	// the served window is recorded, inert in a dial-only engine and
	// disclosed as such via capabilities).
	t.Setenv("MYOTIS_GO_LISTEN_PORT", "-1")
	if SetServedBlockWindow(9999, 64) || SetWsBoundPeriods(9999, 20) || AcceptStaleAnchor(9999) {
		t.Error("unknown handle must answer false on all three")
	}
	h := newStartedHandle(t)
	if !SetServedBlockWindow(h, 100_000) { // clamped, still accepted
		t.Error("known handle must answer true (contract: false ONLY for unknown)")
	}
	if !SetWsBoundPeriods(h, 20) {
		t.Error("ws-bound 20 must be applied")
	}
	if got := decode(t, StatusJSON(h))["wsBoundPeriods"]; got != float64(20) {
		t.Errorf("status wsBoundPeriods must report the ENFORCED override, got %v", got)
	}
	if SetWsBoundPeriods(h, -1) {
		t.Error("a negative bound cannot be applied and must be refused")
	}
	if !SetWsBoundPeriods(h, 0) { // the contract's "restore the default"
		t.Error("0 must restore the default")
	}
	if got := decode(t, StatusJSON(h))["wsBoundPeriods"]; got != float64(13) {
		t.Errorf("after 0, bound must be back to 13, got %v", got)
	}
	if !AcceptStaleAnchor(h) {
		t.Error("stale-anchor consent must be recorded for a known handle")
	}
}

func TestPendingNonceOverlay(t *testing.T) {
	h := newStartedHandle(t)
	// No local pending pool: the mined nonce IS the effective nonce.
	if got := PendingNonceOverlay(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", 41); got != 41 {
		t.Errorf("overlay = %d, want 41", got)
	}
	if got := PendingNonceOverlay(9999, "0x0", 41); got != -1 {
		t.Errorf("unknown handle = %d, want -1", got)
	}
	if got := PendingNonceOverlay(h, "0x0", -1); got != -1 {
		t.Errorf("negative mined nonce = %d, want -1", got)
	}
}

func TestABIVersionMatchesHeader(t *testing.T) {
	// The header's own instruction ("Gate on this macro — do not copy
	// the number") applied to Go: a bump to MYOTIS_ABI_VERSION must
	// turn THIS test red on the PR that bumps it (the workflow's paths
	// now include rust/include/myotis_engine.h), not silently leave
	// the Go library answering the old handshake. Same discipline as
	// TestCheckpointMatchesRustEngine reading sync.rs.
	raw, err := os.ReadFile("../../../rust/include/myotis_engine.h")
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	m := abiDefine.FindSubmatch(raw)
	if m == nil {
		t.Fatal("no #define MYOTIS_ABI_VERSION in the header")
	}
	want, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("define not a number: %v", err)
	}
	if MyotisABIVersion != want {
		t.Errorf("MyotisABIVersion = %d, header says %d — bump the Go constant in this PR", MyotisABIVersion, want)
	}
	if got := Init(); got != int32(want) {
		t.Errorf("Init() = %d, want %d", got, want)
	}
}

var abiDefine = regexp.MustCompile("(?m)^#define MYOTIS_ABI_VERSION (\\d+)$")

func TestCapabilitiesJSON(t *testing.T) {
	m := decode(t, CapabilitiesJSON())
	if m["engine"] != "go" || m["myotisAbi"] != float64(MyotisABIVersion) || m["readBlock"] != "finalized" {
		t.Errorf("capabilities identity wrong: %v", m)
	}
	caps, _ := m["capabilities"].(map[string]any)
	if caps["wsBoundOverride"] != true || caps["staleAnchorConsent"] != true {
		t.Errorf("the live setters are applied now; capabilities must say so: %v", caps)
	}
}

func TestCatalogMatchesGolden(t *testing.T) {
	// The catalog SHAPE is a cross-language contract: the committed
	// golden (rust/testdata/networks_catalog.json, asserted
	// byte-for-byte by catalog.rs and parsed by Java's
	// NetworksJsonGoldenTest) defines the NetworkInfo objects. The Go
	// library lists only what it can RUN (mainnet), but every key and
	// value for that entry must equal the golden's.
	goldenRaw, err := os.ReadFile("../../../rust/testdata/networks_catalog.json")
	if err != nil {
		t.Fatalf("golden catalog: %v", err)
	}
	var golden []map[string]any
	if err := json.Unmarshal(goldenRaw, &golden); err != nil {
		t.Fatalf("golden not JSON: %v", err)
	}
	var want map[string]any
	for _, n := range golden {
		if n["name"] == "mainnet" {
			want = n
		}
	}
	if want == nil {
		t.Fatal("golden has no mainnet entry")
	}
	var gotList []map[string]any
	if err := json.Unmarshal([]byte(AvailableNetworksJSON()), &gotList); err != nil {
		t.Fatalf("catalog not a JSON array: %v", err)
	}
	if len(gotList) != 1 || gotList[0]["name"] != "mainnet" {
		t.Fatalf("catalog = %v, want exactly one mainnet entry", gotList)
	}
	got := gotList[0]
	if len(got) != len(want) {
		t.Errorf("key count diverges from golden: go=%v golden=%v", keys(got), keys(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("catalog key %q: go=%v golden=%v", k, got[k], v)
		}
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCanonicalNameMatchesRustTable(t *testing.T) {
	// catalog.rs canonical_network_name, entry by entry.
	cases := map[string]string{
		"mainnet": "mainnet", "MAINNET": "mainnet",
		"gnosis": "gnosis", "gbc": "gnosis", "xdai": "gnosis", "XDAI": "gnosis",
		"sepolia": "sepolia", "chiado": "chiado",
	}
	for in, want := range cases {
		if c, ok := CanonicalNetworkName(in); !ok || c != want {
			t.Errorf("canonical(%q) = %q %v, want %q", in, c, ok, want)
		}
	}
	// Unknowns — INCLUDING the Go draft's invented aliases, which the
	// Rust table does not carry and this library must not either.
	for _, in := range []string{"ethereum", "eth", "1", "holesky", "", " mainnet"} {
		if c, ok := CanonicalNetworkName(in); ok {
			t.Errorf("canonical(%q) = %q, want unknown (Rust table)", in, c)
		}
	}
	// A canonicalized-but-unsupported network still canonicalizes
	// (Create is what says -2); same as Rust.
	if c, ok := CanonicalNetworkName("gnosis"); !ok || c != "gnosis" {
		t.Errorf("gnosis must canonicalize even though Create refuses it: %q %v", c, ok)
	}
}
