package chain

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// seedEndpoint formats a seed node the way the engines' pin tests compare
// them: the discv4 endpoint — "ip:udp", falling back to TCP — because that is
// what discv4 pings and what the Rust ElConfig::mainnet comment pins ("each
// record's ip and udp fields").
func seedEndpoint(t *testing.T, raw string) string {
	t.Helper()
	n, err := ParseBootnode(raw)
	if err != nil {
		t.Fatalf("bootnode %q: %v", raw, err)
	}
	port := n.UDP()
	if port == 0 {
		port = n.TCP()
	}
	return net.JoinHostPort(n.IP().String(), strconv.Itoa(port))
}

// TestMainnetPins pins the mainnet constants as strings, the way the Rust
// engine's mainnet_config_pins_known_values and the Java
// NetworkConfigGnosisTest#elBootnodesMatchGoEthereum do: a partial re-sync of
// the bootnode list fails right here rather than silently in the field. The
// endpoints are the same nine the Rust ElConfig::mainnet pins (five EF NodeOps
// ip:udp, then the four legacy EF enodes).
func TestMainnetPins(t *testing.T) {
	m := Mainnet()

	if m.NetworkID != 1 {
		t.Errorf("NetworkID = %d, want 1", m.NetworkID)
	}
	if got := m.GenesisHash.Hex(); got != "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" {
		t.Errorf("GenesisHash = %s", got)
	}
	const wantTree = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"
	if m.ENRTreeURL != wantTree {
		t.Errorf("ENRTreeURL = %s, want %s", m.ENRTreeURL, wantTree)
	}

	want := []string{
		"212.99.218.66:20151",   // nodeops-bootnode-dcl1-01
		"129.212.166.61:30303",  // nodeops-bootnode-sfo3-01
		"144.126.252.24:30303",  // nodeops-bootnode-blr1-01
		"178.156.215.140:30303", // nodeops-bootnode-ash-01
		"5.223.94.81:30303",     // nodeops-bootnode-sin-01
		"18.138.108.67:30303",
		"3.209.45.79:30303",
		"65.108.70.101:30303",
		"157.90.35.166:30303",
	}
	if len(m.Bootnodes) != len(want) {
		t.Fatalf("got %d bootnodes, want %d", len(m.Bootnodes), len(want))
	}
	for i, raw := range m.Bootnodes {
		if got := seedEndpoint(t, raw); got != want[i] {
			t.Errorf("bootnode %d endpoint = %s, want %s", i, got, want[i])
		}
	}
}

// TestParseBootnodeIdentities checks the two wire forms land on distinct,
// pubkey-derived node IDs (the ENRs carry no id themselves; the id is the
// keccak of the record's secp256k1 key).
func TestParseBootnodeIdentities(t *testing.T) {
	m := Mainnet()
	seen := map[string]bool{}
	for _, raw := range m.Bootnodes {
		n, err := ParseBootnode(raw)
		if err != nil {
			t.Fatal(err)
		}
		id := n.ID().String()
		if id == "" || seen[id] {
			t.Errorf("duplicate or empty node id for %s: %q", seedEndpoint(t, raw), id)
		}
		seen[id] = true
	}
}

// corpusKeys reads the shared EL conformance corpus — the same key=value file
// that forces the Rust and Java engine pins together — from the repo root
// relative to this package.
func corpusKeys(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.FromSlash("../../../rust/testdata/el/core/expected.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %s: %v", path, err)
	}
	defer f.Close()
	keys := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			keys[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return keys
}

// TestMainnetForkIDMatchesCorpus binds the pinned fork id to the corpus
// instead of a second copy of itself: when mainnet's fork schedule moves, the
// corpus moves (it forces Rust and Java) and this test goes red with it,
// instead of the Go engine quietly announcing a superseded fork id and being
// disconnected by every peer.
func TestMainnetForkIDMatchesCorpus(t *testing.T) {
	m := Mainnet()
	keys := corpusKeys(t)

	wantHash, ok := keys["forkid.mainnet"]
	if !ok {
		t.Fatal("corpus has no forkid.mainnet key")
	}
	wantBytes, err := hex.DecodeString(wantHash)
	if err != nil || len(wantBytes) != 4 {
		t.Fatalf("corpus forkid.mainnet = %q, want 8 hex chars", wantHash)
	}
	if m.ForkIDHash != ([4]byte)(wantBytes) {
		t.Errorf("ForkIDHash = %x, corpus says %s", m.ForkIDHash, wantHash)
	}
	if wantNext, ok := keys["forkid.forkNext.mainnet"]; !ok || wantNext != "0" || m.ForkNext != 0 {
		t.Errorf("ForkNext = %d, corpus says %q", m.ForkNext, wantNext)
	}
}

// TestMainnetForkIDNotSuperseded is the forward tripwire: the corpus records
// the NEXT scheduled fork (forkid.afterNext.mainnet); "none" means the pinned
// id is current. The day a fork gets scheduled on mainnet, this test fails in
// the Go engine too, telling the author to move the pin (real CRC32 fork-id
// computation would retire it).
func TestMainnetForkIDNotSuperseded(t *testing.T) {
	keys := corpusKeys(t)
	after, ok := keys["forkid.afterNext.mainnet"]
	if !ok {
		t.Fatal("corpus has no forkid.afterNext.mainnet key")
	}
	if after != "none" {
		t.Errorf("mainnet has a fork scheduled (next fork id %s); the pinned ForkIDHash/ForkNext in chain.go must move", after)
	}
}
