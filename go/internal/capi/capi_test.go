package capi

// The C ABI contract, tested on the Go side of the seam (part 1b):
// return codes, refusal shapes, and the apply-or-refuse discipline of
// the block selector. The reads themselves are the engine's tested
// path — what these tests pin is what a JNA host sees BEFORE a read
// can run (handle states, selector policy) and the exact shape of the
// refusals it sees instead.

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func newStartedHandle(t *testing.T) int64 {
	t.Helper()
	// Ephemeral UDP: tests must not fight a running daemon for :30303.
	t.Setenv("MYOTIS_GO_LISTEN_PORT", "-1")
	h := Create("mainnet", t.TempDir())
	if h < 1 {
		t.Fatalf("Create(mainnet) = %d, want handle >= 1", h)
	}
	if !Start(h) {
		t.Fatalf("Start(%d) = false", h)
	}
	t.Cleanup(func() { Stop(h) })
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

func TestLifecycleAndRefusals(t *testing.T) {
	h := newStartedHandle(t)

	if Start(h) {
		t.Error("second Start must be false (already-running handle)")
	}

	st := decode(t, StatusJSON(h))
	if st["engine"] != "go" || st["network"] != "mainnet" || st["running"] != true {
		t.Errorf("status identity wrong: %v", st)
	}
	if _, ok := st["anchor"]; !ok {
		t.Error("status must carry the anchor key (null until the first verified anchor)")
	}
	caps, _ := st["capabilities"].(map[string]any)
	if caps["reads"] != true || caps["evm"] != false {
		t.Errorf("capabilities wrong: %v", caps)
	}

	// Block-selector policy WITHOUT touching the network: everything
	// but "finalized" is refused permanently, the empty selector named
	// as the head tag the header says it is, and the refusal names the
	// way forward.
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
	if h := Create("1", t.TempDir()); h < 1 { // alias → mainnet
		t.Errorf("alias \"1\" = %d, want handle >= 1", h)
	} else {
		Stop(h)
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

func TestStorageRefusals(t *testing.T) {
	h := newStartedHandle(t)
	addr := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	m := decode(t, GetStorageProofJSON(h, addr, 7, "0xdead"))
	if m["code"] != float64(-32602) || !strings.Contains(m["error"].(string), "holder_hex") {
		t.Errorf("holder must be refused permanently by name: %v", m)
	}
	m = decode(t, GetStorageProofJSON(h, addr, -5, ""))
	if m["code"] != float64(-32602) {
		t.Errorf("negative slot must be refused: %v", m)
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
	if s := decode(t, StatusJSON(h)); s["running"] != false {
		t.Errorf("created-but-unstarted status.running = %v, want false", s["running"])
	}
}

func TestLogRingDrain(t *testing.T) {
	// drain: oldest first, newline-joined, removed on read, "" when
	// idle — the header's drain_logs semantics.
	r := &ringHandler{}
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

func TestRingOverflowKeepsNewest(t *testing.T) {
	r := &ringHandler{}
	for range ringCap + 10 {
		_ = r.Handle(t.Context(), slog.NewRecord(time.Time{}, slog.LevelInfo, "filler", 0))
	}
	if len(r.lines) != ringCap {
		t.Fatalf("ring len = %d, want cap %d", len(r.lines), ringCap)
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
	// Tor: the contract's own codes — false / 0 mean "not in build".
	if SetTorEnabled(true) || TorStatus() != 0 || SetTorStorageDirs("/a", "/b") {
		t.Error("a Tor-less build must answer false/0 as the contract prescribes")
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

func TestCapabilitiesJSONAndCatalog(t *testing.T) {
	m := decode(t, CapabilitiesJSON())
	if m["engine"] != "go" || m["myotisAbi"] != float64(MyotisABIVersion) || m["readBlock"] != "finalized" {
		t.Errorf("capabilities identity wrong: %v", m)
	}
	var nets []map[string]any
	if err := json.Unmarshal([]byte(AvailableNetworksJSON()), &nets); err != nil {
		t.Fatalf("catalog not a JSON array: %v", err)
	}
	if len(nets) != 1 || nets[0]["name"] != "mainnet" || nets[0]["supported"] != true {
		t.Errorf("catalog = %v, want exactly mainnet/supported", nets)
	}
	if c, ok := CanonicalNetworkName("Ethereum"); !ok || c != "mainnet" {
		t.Errorf("canonical(Ethereum) = %q %v", c, ok)
	}
	if _, ok := CanonicalNetworkName("gnosis"); ok {
		t.Error("gnosis is not in THIS library's catalog (Create says -2)")
	}
	if _, ok := CanonicalNetworkName("dogecoin"); ok {
		t.Error("dogecoin must be unknown")
	}
}
