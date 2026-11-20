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
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

	// Block-selector policy (twin parity, parse_call_block): selectors
	// the engine CAN apply pass the parse and only then meet handle
	// state; selectors no retry can serve are refused permanently,
	// BEFORE the handle lookup (a request that would never have been
	// servable must not get a retryable "not started" first). The
	// engine now reads both anchors, so the head vocabulary
	// (""/latest/pending), "finalized" and numbers all pass; only
	// safe/earliest (never tracked, #366), block hashes, numbers past
	// i64::MAX and garbage are refused.
	// (Unknown handle on purpose: the refusal must not wait for it.)
	for _, sel := range []string{"safe", "earliest", "head", "soon", "+7",
		"0x10000000000000000", // 2^64 — past the twin's i64::MAX bar
		// A block hash: 64 hex digits, too big to parse as a number (a
		// leading-zero 64-hex is a NUMBER to the twin too — both parse
		// before the hash arm).
		"0xabcfef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	} {
		m := decode(t, RequestAccountJSON(424242, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", sel))
		if m["code"] != float64(-32602) {
			t.Errorf("selector %q on an UNKNOWN handle: want the permanent refusal first, got %v", sel, m)
		}
	}
	for _, sel := range []string{"", "latest", "FINALIZED", "pending", "123", "0x1c7c4"} {
		m := decode(t, RequestAccountJSON(424242, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", sel))
		if _, has := m["code"]; has {
			t.Errorf("selector %q is servable and must reach handle state as a RETRYABLE error, got %v", sel, m)
		}
	}

	// The started handle answers the SAME way for the refused selectors
	// (permanent), and each refusal is the twin's text: SAFE_TAG_REFUSAL
	// names the tags that DO work, the earliest refusal names the two
	// anchors verified reads actually run at.
	for _, c := range []struct{ sel, names string }{
		{"safe", "ask for 'latest' or 'finalized'"},
		{"earliest", "or the finalized block's"},
	} {
		m := decode(t, RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", c.sel))
		if m["code"] != float64(-32602) {
			t.Errorf("selector %q: want permanent -32602, got %v", c.sel, m)
		}
		if !strings.Contains(m["error"].(string), c.names) {
			t.Errorf("selector %q: refusal must contain %q: %v", c.sel, c.names, m["error"])
		}
	}
	if m := decode(t, RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "safe")); !strings.Contains(m["error"].(string), "safe (justified) head") {
		t.Errorf("safe refusal must be the twin's SAFE_TAG_REFUSAL: %v", m["error"])
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
	// "" would otherwise write the node key into the host process's
	// cwd (PR #827 review — Rust's canonicalize("") fails the same
	// way and answers -1).
	if h := Create("mainnet", ""); h != -1 {
		t.Errorf("empty data_dir = %d, want -1", h)
	}
	// The guard is the KEY FILE NAME the engine actually writes —
	// nodekey.Load persists it as <dir>/nodekey (internal/nodekey
	// fileName = "nodekey"), NOT nodekey.key. An earlier draft statted
	// the wrong name, so this assertion could never fail: a regression
	// that let "" through would drop ./nodekey in this package dir and
	// the nodekey.key stat would still find nothing. The name is also
	// ignored repo-wide by .gitignore, so a stray key would not show in
	// git status either — this stat is the only thing that catches it
	// (final-PR review, finding 6).
	cwd, _ := os.Getwd()
	if _, err := os.Stat(cwd + "/nodekey"); err == nil {
		t.Errorf(`Create("") must not touch the cwd (found nodekey there)`)
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

func TestStartFailureRetryWithConcurrentRead(t *testing.T) {
	// PR #861 round-5 review: the Start FAILURE path (StartNetwork
	// bind error → started reset, ctx cancelled, retryable via
	// another Start) had never been executed — the lifecycle tests
	// forged a started handle or started successfully, and the
	// engine-level busy-port test never entered this function. One
	// intermediate state of that path could panic the host process
	// (a nil lifetime context reaching context.WithTimeout, which
	// nothing under go/ recovers from), and that was found by
	// reading. This test makes -race (go-engine.yml) the keeper of
	// the beginRead "hand the ctx out under mu" rule: a reader that
	// goes back to e.ctx after the lock shows up there.
	//
	// Pin the discv4 UDP port the way the engine test does, so
	// StartNetwork's bind fails:
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("pinning a UDP port: %v", err)
	}
	port := sock.LocalAddr().(*net.UDPAddr).Port
	t.Setenv("MYOTIS_GO_LISTEN_PORT", strconv.Itoa(port))
	h := Create("mainnet", t.TempDir())
	if h < 1 {
		t.Fatalf("Create = %d", h)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			Stop(h)
		}
	})

	// A reader hammering the handle across the WHOLE sequence —
	// fail / fail / free / succeed / Stop — so its beginRead and the
	// Start paths' mu-guarded writes genuinely overlap under -race
	// (a fixed-iteration loop can finish before the first Start even
	// runs, testing nothing). Every answer must stay retryable: an
	// error WITHOUT a code — "not started" while the bind fails,
	// "unknown handle" after the Stop; never a permanent code, never
	// a panic.
	stopReads := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopReads:
				return
			default:
			}
			out := RequestAccountJSON(h, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "finalized")
			// (no decode() here: it t.Fatalfes, and this is not the
			// test goroutine) every answer is an error envelope;
			// retryable = `{"error":…}` with NO code key.
			var m map[string]any
			if err := json.Unmarshal([]byte(out), &m); err != nil {
				t.Errorf("read answer not JSON (%v): %s", err, out)
				return
			}
			if _, has := m["error"]; !has {
				t.Errorf("read across the failed-Start window must answer a retryable error, got %s", out)
				return
			}
			if _, has := m["code"]; has {
				t.Errorf("read across the failed-Start window must stay retryable (no code), got %s", out)
				return
			}
		}
	}()
	if Start(h) {
		t.Fatal("Start onto the busy UDP port returned true, want false")
	}
	if Start(h) {
		t.Fatal("retry #1 onto the still-busy port returned true, want false (retryable per the header)")
	}
	if err := sock.Close(); err != nil { // free the port
		t.Fatalf("freeing the port: %v", err)
	}
	if !Start(h) {
		t.Fatal("Start after freeing the port returned false; the failed attempts must not poison the handle")
	}
	closeErr := make(chan struct{})
	go func() { Stop(h); stopped = true; close(closeErr) }()
	select {
	case <-closeErr:
	case <-time.After(20 * time.Second):
		t.Fatal("Stop after the retried Start did not return")
	}
	close(stopReads)
	<-done
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
	if m["engine"] != "go" || m["myotisAbi"] != float64(MyotisABIVersion) || m["readBlock"] != "head" {
		t.Errorf("capabilities identity wrong: %v", m)
	}
	caps, _ := m["capabilities"].(map[string]any)
	if caps["wsBoundOverride"] != true || caps["staleAnchorConsent"] != true {
		t.Errorf("the live setters are applied now; capabilities must say so: %v", caps)
	}
	// The ABI-58/59 stale-anchor additions: the checkpoint fetch is not
	// implemented, the remembered policy is honoured for the answers this
	// engine can act on. Both must be disclosed (PR #877 review).
	if caps["anchorRefresh"] != false || caps["staleAnchorPolicy"] != true {
		t.Errorf("capabilities must disclose the refresh refusal and the policy support: %v", caps)
	}
}

func TestStaleAnchorRefreshRefusalShape(t *testing.T) {
	// ABI-58 refusal in the contract's OWN key set (not the generic
	// permanentErr envelope): exactly applied/error/unconfirmed, applied
	// false, and the reason names the function so a host can tell "no
	// fetch" from a transient. Rust pins the same shape side.
	m := decode(t, AnchorRefreshUnsupported())
	if len(m) != 3 || m["applied"] != false || m["unconfirmed"] != false {
		t.Fatalf("refresh refusal must be {applied:false,error,unconfirmed:false}: %v", m)
	}
	if s, _ := m["error"].(string); !strings.Contains(s, "myotis_refresh_anchor_from_checkpointz") {
		t.Errorf("refusal must name the function: %v", m["error"])
	}
}

func TestStatusPeriodsCases(t *testing.T) {
	// The three period lines of the status JSON, pinned as a table (PR #877
	// round-2): dropping the parked case silently restores the "park is
	// ~1900 periods old" dialog with CI green, and parking a real loop in
	// tests needs engine internals a table does not.
	const cp, wall = uint64(1908), uint64(1922)
	anchorSlot := uint64(8192 * 1910) // period 1910 by the contract's own math
	for _, c := range []struct {
		name             string
		state            string
		slot             uint64
		have             bool
		cp, wall         uint64
		wantCur, wantTgt uint64
	}{
		{"anchor held", "SYNCED", anchorSlot, true, cp, wall, 1910, 1922},
		{"parked without anchor", "STALE_ANCHOR", 0, false, cp, wall, 1908, 1922},
		{"bootstrapping", "SYNCING", 0, false, cp, wall, 0, 1922},
		{"wall behind anchor", "SYNCED", anchorSlot, true, cp, 1900, 1910, 1910},
		{"wall behind park", "STALE_ANCHOR", 0, false, cp, 1900, 1908, 1908},
	} {
		gotCur, gotTgt := statusPeriods(c.state, c.slot, c.have, c.cp, c.wall)
		if gotCur != c.wantCur || gotTgt != c.wantTgt {
			t.Errorf("%s: statusPeriods = (%d,%d), want (%d,%d)", c.name, gotCur, gotTgt, c.wantCur, c.wantTgt)
		}
	}
}

func TestStaleAnchorPolicyApplyOrRefuse(t *testing.T) {
	// ABI-59 apply-or-refuse, pinned against the engine (mirrors host.rs):
	// ASK and CONTINUE are APPLIED (CONTINUE through the same sticky
	// consent the one-shot setter uses), CHECKPOINT is REFUSED (no fetch),
	// and unknown codes / a dead handle are refused — never accepted and
	// silently ignored.
	if SetStaleAnchorPolicy(9999, 0) {
		t.Error("unknown handle must answer false")
	}
	h := newStartedHandle(t)
	if !SetStaleAnchorPolicy(h, 0) {
		t.Error("ASK (0) must be applied")
	}
	if SetStaleAnchorPolicy(h, 1) {
		t.Error("CHECKPOINT (1) must be refused — no checkpoint fetch (anchorRefresh:false)")
	}
	if !SetStaleAnchorPolicy(h, 2) {
		t.Error("CONTINUE (2) must be applied (sticky consent)")
	}
	for _, p := range []int32{3, -1, 100} {
		if SetStaleAnchorPolicy(h, p) {
			t.Errorf("unknown policy code %d must be refused, not accepted and ignored", p)
		}
	}
	// Settable before start too, as the header says — a created, unstarted
	// handle applies ASK rather than refusing on "not running".
	u := Create("mainnet", t.TempDir())
	if u < 1 {
		t.Fatalf("Create = %d", u)
	}
	defer Stop(u)
	if !SetStaleAnchorPolicy(u, 0) {
		t.Error("ASK must apply on a created, not-yet-started handle")
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

// TestCapabilitiesGolden pins the shared golden the JVM fixture splices
// (testdata/capabilities.json) against the REAL map, byte-for-byte as
// json.Marshal emits it (sorted keys). This is the cross-check PR #879
// round 10 said was missing: capabilities() drifting from the golden
// fails HERE, the single point of enforcement — the JVM fixture
// splices this same file, so it can never be a stale hand-copy (the
// JVM reader interprets none of it: its test checks that the two
// ABI-58/59 disclosures are in the fixture, and that the snapshot is
// the same with them removed or an unknown key added).
// Cross-read pattern per GoAbiVersionMirrorTest.
func TestCapabilitiesGolden(t *testing.T) {
	golden, err := os.ReadFile("testdata/capabilities.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	got, err := json.Marshal(capabilities())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.TrimSpace(string(golden)) != string(got) {
		t.Errorf("capabilities() drifted from testdata/capabilities.json\n golden: %s\n    got: %s",
			strings.TrimSpace(string(golden)), got)
	}
}

// TestRingTruncatesLongLine pins the sink-side byte cap (maxLineBytes):
// a single line longer than the cap is cut to a bounded, valid-UTF-8
// prefix plus a marker, so one megabyte error-chunk line cannot sit in
// the ring and cross JNA whole into the host log. Fails if the cap is
// removed (line stored whole) or if the cut splits a multibyte rune.
func TestRingTruncatesLongLine(t *testing.T) {
	// (a) plain-ASCII overrun: cut lands on a byte boundary exactly at
	// maxLineBytes, marker appended, kept prefix is exactly that many q.
	b := &ringBuffer{}
	long := strings.Repeat("q", maxLineBytes+5000)
	if _, err := b.Write([]byte(long + "\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(b.lines) != 1 {
		t.Fatalf("want 1 stored line, got %d", len(b.lines))
	}
	line := b.lines[0]
	if !strings.Contains(line, "truncated") {
		t.Fatalf("long line not marked as truncated: %q…", line[:40])
	}
	if !strings.HasPrefix(line, strings.Repeat("q", maxLineBytes)) {
		t.Fatal("kept prefix shorter than maxLineBytes")
	}
	if strings.HasPrefix(line, strings.Repeat("q", maxLineBytes+1)) {
		t.Fatal("did not truncate — a full extra byte survived")
	}
	if !utf8.ValidString(line) {
		t.Fatal("truncated ASCII line is not valid UTF-8")
	}

	// (b) multibyte straddle: a 2-byte 'é' (0xC3 0xA9) sitting across
	// the maxLineBytes boundary must not be cut in half. Fill to
	// maxLineBytes-1 with 'q' then 'é' then more, so byte maxLineBytes
	// lands mid-'é'; the RuneStart backoff must drop the partial lead
	// byte and keep the whole rune.
	b2 := &ringBuffer{}
	straddle := strings.Repeat("q", maxLineBytes-1) + "é" + strings.Repeat("q", 3000)
	if _, err := b2.Write([]byte(straddle + "\n")); err != nil {
		t.Fatalf("Write straddle: %v", err)
	}
	got := b2.lines[0]
	if !utf8.ValidString(got) {
		t.Fatalf("rune-boundary cut produced invalid UTF-8: %x", got[maxLineBytes-4:maxLineBytes+4])
	}
	// The complete 'é' must be intact somewhere in the kept prefix (the
	// backoff drops the whole rune, never half of it).
	if strings.Count(got, "é") > 1 {
		t.Fatalf("straddle rune duplicated: %q", got)
	}
}

// --- the selector parser (parse_call_block twin) and the near-head window ---

func TestParseReadBlockTable(t *testing.T) {
	type want struct {
		head, pinnedSet bool
		pinned          uint64
		refused         bool
	}
	cases := []struct {
		in   string
		want want
	}{
		{"", want{head: true}}, // the header's verified HEAD
		{"latest", want{head: true}},
		{"LATEST", want{head: true}},    // tags in any case
		{" pending ", want{head: true}}, // trimmed
		{"finalized", want{}},           // the finalized anchor
		{"Finalized", want{}},
		{"123", want{head: true, pinnedSet: true, pinned: 123}},                           // bare digits DECIMAL (#366 item 6)
		{"0x1c7c4", want{head: true, pinnedSet: true, pinned: 0x1c7c4}},                   // 0x hex
		{"0X1C7C4", want{head: true, pinnedSet: true, pinned: 0x1c7c4}},                   // 0X too
		{"0", want{head: true, pinnedSet: true, pinned: 0}},                               // block zero parses as a number
		{"9223372036854775807", want{head: true, pinnedSet: true, pinned: math.MaxInt64}}, // i64::MAX is the bar
		{"9223372036854775808", want{refused: true}},                                      // past it: malformed
		{"safe", want{refused: true}},                                                     // #366
		{"earliest", want{refused: true}},
		{"head", want{refused: true}}, // NOT a tag in the vocabulary
		{"+7", want{refused: true}},   // ASCII digits only, no sign
		{"0x", want{refused: true}},   // no digits after the prefix
		{"0xzz", want{refused: true}},
		{"0x000000000000000000000000000000000000000000000000000000000000abcd", want{head: true, pinnedSet: true, pinned: 0xabcd}}, // leading-zero 64-hex parses as a number, twin's order
		{"0xabcfef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", want{refused: true}},                               // too big → hash arm
	}
	for _, c := range cases {
		sel, msg, refused := parseReadBlock(c.in)
		if refused != c.want.refused {
			t.Errorf("parseReadBlock(%q): refused=%v want %v (msg %q)", c.in, refused, c.want.refused, msg)
			continue
		}
		if c.want.refused {
			var probe map[string]any
			if err := json.Unmarshal([]byte(msg), &probe); err != nil || probe["code"] != float64(-32602) {
				t.Errorf("parseReadBlock(%q): refusal must be the -32602 envelope, got %q", c.in, msg)
			}
			continue
		}
		if sel.head != c.want.head || sel.pinnedSet != c.want.pinnedSet || sel.pinned != c.want.pinned {
			t.Errorf("parseReadBlock(%q) = {head:%v pinnedSet:%v pinned:%d}, want {head:%v pinnedSet:%v pinned:%d}",
				c.in, sel.head, sel.pinnedSet, sel.pinned, c.want.head, c.want.pinnedSet, c.want.pinned)
		}
	}
}

func TestCheckReadWindowTable(t *testing.T) {
	const head = 21_000_100
	num := func(n uint64) readSelector { return readSelector{head: true, pinned: n, pinnedSet: true} }
	// Inside the twin's [head-64, head+16]: served from head state, no refusal.
	for _, n := range []uint64{head, head - 64, head + 16, head - 1} {
		if _, _, bad := checkReadWindow(num(n), head, true); bad {
			t.Errorf("block %d inside the window of head %d must be served, got a refusal", n, head)
		}
	}
	// One outside, each direction, with the twin's code discipline:
	// behind PERMANENT (no retry clears it), ahead retryable (the head
	// advances into it — geth's future-block distinction).
	if _, perm, bad := checkReadWindow(num(head-65), head, true); !bad || !perm {
		t.Errorf("block head-65: want permanent refusal, got perm=%v bad=%v", perm, bad)
	}
	if _, perm, bad := checkReadWindow(num(head+17), head, true); !bad || perm {
		t.Errorf("block head+17: want RETRYABLE refusal, got perm=%v bad=%v", perm, bad)
	}
	// No anchor yet: retryable "no verified head" — clears as the LC syncs.
	if m, perm, bad := checkReadWindow(num(123), 0, false); !bad || perm || !strings.Contains(m, "no verified head") {
		t.Errorf("no anchor: want retryable NoHead, got perm=%v bad=%v msg=%q", perm, bad, m)
	}
	// Tiny head, saturating bound: nothing is "behind" a head of 10
	// (the twin's saturating_sub), including block 0.
	if _, _, bad := checkReadWindow(num(0), 10, true); bad {
		t.Error("block 0 at head 10 must be window-served (saturating_sub)")
	}
	// Non-pinned selectors need no window at all.
	if _, _, bad := checkReadWindow(readSelector{head: true}, head, true); bad {
		t.Error("the head tag needs no window check")
	}
	if _, _, bad := checkReadWindow(readSelector{}, head, true); bad {
		t.Error("finalized needs no window check")
	}
}

// TestReadWindowConstantsMatchRustEngine pins the near-head window to
// host.rs the way pins_drift_test.go pins the CL peers: a tolerance
// moved on one side and not the other means the two engines answer
// different questions for the same selector, and the wallet pinned the
// number for a reason (PR #366's window is a CROSS-engine contract).
func TestReadWindowConstantsMatchRustEngine(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rust", "myotis-engine", "src", "host.rs"))
	if err != nil {
		t.Fatalf("read rust/myotis-engine/src/host.rs: %v", err)
	}
	src := string(raw)
	pin := func(name string, goVal uint64) uint64 {
		m := regexp.MustCompile(`const ` + name + `: u64 = (\d+);`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("const %s not found in host.rs — renamed or restructured; update capi.go and this test together", name)
		}
		n, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			t.Fatalf("const %s unparseable: %v", name, err)
		}
		if n != goVal {
			t.Errorf("%s drifted: host.rs says %d, capi.go says %d — move both together (a wallet pinned one window, not two)", name, n, goVal)
		}
		return n
	}
	pin("CALL_BLOCK_LAG_TOLERANCE", callBlockLagTolerance)
	pin("CALL_BLOCK_AHEAD_TOLERANCE", callBlockAheadTolerance)
}

// --- myotis_get_storage_at_json: functional since the head-anchor
// change (it used to be a named refusal). Request-shape discipline is
// the twin's get_storage_at_json: address and position refusals are the
// twin's error_json (retryable), the selector's are parseReadBlock's
// permanent — all BEFORE the handle lookup. ---

func TestStorageAtJSONRefusalShapes(t *testing.T) {
	const addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	const pos = "0x0000000000000000000000000000000000000000000000000000000000000007"

	m := decode(t, GetStorageAtJSON(424242, "0xnope", pos, "latest"))
	if _, has := m["code"]; has {
		t.Errorf("malformed address is the twin's error_json (retryable), got %v", m)
	}
	if !strings.Contains(m["error"].(string), "invalid address") {
		t.Errorf("want the twin's address refusal: %v", m["error"])
	}
	m = decode(t, GetStorageAtJSON(424242, addr, "0xdeadbeef", "latest"))
	if _, has := m["code"]; has {
		t.Errorf("malformed position is the twin's error_json (retryable), got %v", m)
	}
	if !strings.Contains(m["error"].(string), "invalid storage position") {
		t.Errorf("want the twin's position refusal: %v", m["error"])
	}
	m = decode(t, GetStorageAtJSON(424242, addr, pos, "safe"))
	if m["code"] != float64(-32602) {
		t.Errorf("safe selector must be permanent, got %v", m)
	}
	// A fully-formed request passes every shape gate and meets handle
	// state (unknown handle → retryable): position 64-hex (upper too),
	// selector finalized.
	if w, ok := parseWord32("0X" + "AB" + strings.Repeat("0", 62)); !ok || w[0] != 0xAB {
		t.Errorf("parseWord32 must take 0X + mixed case: %x %v", w, ok)
	}
	// Only ONE prefix is stripped, like the twin (host.rs:4042): a second
	// prefix is data, so this is 66 payload chars and fails the length
	// check, not a 64-hex word with a doubled prefix (PR #889 review).
	bad := []string{"0x7", "7", "0x" + strings.Repeat("g", 64), pos + "00", "0x0X" + strings.Repeat("0", 64)}
	for _, bad := range bad {
		if _, ok := parseWord32(bad); ok {
			t.Errorf("parseWord32(%q) must refuse (no short forms, no width drift)", bad)
		}
	}
	m = decode(t, GetStorageAtJSON(424242, addr, pos, "finalized"))
	if _, has := m["code"]; has {
		t.Errorf("servable request on an unknown handle must be retryable, got %v", m)
	}
}

// The generic selector refusal echoes the selector truncated to 66
// CHARS like the twin (host.rs b.chars().take(66)) — rune-safe, so a
// multi-byte selector cannot leak a replacement rune into the message.
func TestSelectorRefusalEchoIsRuneSafe(t *testing.T) {
	m := decode(t, RequestAccountJSON(424242,
		"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", strings.Repeat("é", 100)))
	msg, _ := m["error"].(string)
	if strings.ContainsRune(msg, utf8.RuneError) {
		t.Errorf("truncation cut a rune in half: %q", msg)
	}
	// The twin formats `{shown:?}{more}`: the ellipsis sits AFTER the
	// closing quote, never inside the quoted selector (PR #889 review —
	// this test used to pin the inside form while claiming the twin's).
	if !strings.Contains(msg, `"…`) {
		t.Errorf("over-long selector must carry the twin's ellipsis after the closing quote: %q", msg)
	}
	if strings.Contains(msg, `…"`) {
		t.Errorf("ellipsis must not sit inside the quoted selector: %q", msg)
	}
}

// The tag vocabulary folds ASCII-only, like the twin's
// eq_ignore_ascii_case (host.rs:2250): Unicode case FOLDING would read
// "lateſt" (U+017F) as "latest" and serve it as the head tag.
func TestSelectorTagFoldIsASCIIOnly(t *testing.T) {
	if _, refusal, _ := parseReadBlock("lateſt"); refusal == "" {
		t.Errorf("lateſt (U+017F) must not fold to the head tag: %q", refusal)
	}
	if sel, refusal, _ := parseReadBlock("LATEST"); refusal != "" || !sel.head {
		t.Errorf("ASCII upper case must still be the head tag: %v %q", sel, refusal)
	}
}
