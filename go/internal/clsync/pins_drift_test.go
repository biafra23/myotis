package clsync

// The static CL pins live in three places: NetworkConfig.java,
// rust/myotis-net/src/sync.rs, and here. TestCheckpointMatchesRustEngine
// (internal/chain) pins the CHECKPOINT across Go and Rust; nothing pinned
// the PEER lists, so a release that re-censuses the pins in the Rust
// engine (the release checklist's bootnode/pin steps) could leave this
// copy behind silently — the Go engine would keep dialing retired
// servers while both twins looked green (PR #773 review). Compare as
// SETS: the pinned order is a rotation strategy each engine picks for
// itself (both currently lead with roost), the membership is the fact.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func rustConstStrings(t *testing.T, src, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?s)const `+name+`:[^=]*= &\[(.*?)\];`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("const %s not found in rust/myotis-net/src/sync.rs — the pin list was renamed or restructured; update this test and peers.go together", name)
	}
	// Comments quote prose ("Unexpected peer ID", "connection closed")
	// that the naive literal scan would swallow — strip them first.
	body := regexp.MustCompile(`(?m)//[^\n]*`).ReplaceAllString(m[1], "")
	var out []string
	for _, lit := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(body, -1) {
		out = append(out, lit[1])
	}
	if len(out) == 0 {
		t.Fatalf("const %s parsed empty", name)
	}
	sort.Strings(out)
	return out
}

func checkSameSet(t *testing.T, name string, rust, goList []string) {
	t.Helper()
	goSorted := append([]string(nil), goList...)
	sort.Strings(goSorted)
	rustSet := make(map[string]bool, len(rust))
	for _, s := range rust {
		rustSet[s] = true
	}
	var onlyRust, onlyGo []string
	for _, s := range rust {
		if !contains(goSorted, s) {
			onlyRust = append(onlyRust, s)
		}
	}
	for _, s := range goSorted {
		if !rustSet[s] {
			onlyGo = append(onlyGo, s)
		}
	}
	if len(onlyRust) > 0 || len(onlyGo) > 0 {
		t.Errorf("%s drifted between rust/myotis-net/src/sync.rs and internal/clsync/peers.go — move both together (a re-census must not leave one engine dialing retired pins):\n  only in rust: %s\n  only in go:   %s",
			name, strings.Join(onlyRust, ", "), strings.Join(onlyGo, ", "))
	}
}

func contains(s []string, v string) bool {
	i := sort.SearchStrings(s, v)
	return i < len(s) && s[i] == v
}

func TestMainnetCLPinsMatchRustEngine(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rust", "myotis-net", "src", "sync.rs"))
	if err != nil {
		t.Fatalf("read rust sync.rs: %v", err)
	}
	src := string(raw)
	checkSameSet(t, "MAINNET_STATIC_PEERS",
		rustConstStrings(t, src, "MAINNET_STATIC_PEERS"), MainnetStaticPeers)
	checkSameSet(t, "MAINNET_BOOTSTRAP_ENRS",
		rustConstStrings(t, src, "MAINNET_BOOTSTRAP_ENRS"), MainnetBootstrapENRs)
}
