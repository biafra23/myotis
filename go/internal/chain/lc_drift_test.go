package chain

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestCheckpointMatchesRustEngine pins this package's checkpoint to the
// @checkpoint:mainnet region of rust/myotis-net/src/sync.rs — the
// release checklist's refreshCheckpoint rewrites the Java and Rust
// copies from one fetch and java_and_rust_checkpoints_agree fails on
// drift between THEM; nothing covered Go's copy, so a release could
// refresh past this file silently (PR #769 review). After this test, a
// refresh turns the Go build red until the pin here moves too — the same
// trick TestMainnetForkIDMatchesCorpus uses for the EL pins.
func TestCheckpointMatchesRustEngine(t *testing.T) {
	// go/internal/chain → go/internal → go → repo root.
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "rust", "myotis-net", "src", "sync.rs"))
	if err != nil {
		t.Fatalf("read rust sync.rs: %v", err)
	}
	begin := strings.Index(string(src), "@checkpoint:mainnet:begin")
	end := strings.Index(string(src), "@checkpoint:mainnet:end")
	if begin < 0 || end < 0 || end <= begin {
		t.Fatal("no @checkpoint:mainnet marker region in rust/myotis-net/src/sync.rs")
	}
	region := string(src)[begin:end]

	rootRe := regexp.MustCompile(`checkpoint_root:\s*hex32\(\s*"([0-9a-f]{64})"`)
	slotRe := regexp.MustCompile(`checkpoint_slot:\s*([0-9_]+),`)
	rm := rootRe.FindStringSubmatch(region)
	sm := slotRe.FindStringSubmatch(region)
	if rm == nil || sm == nil {
		t.Fatalf("cannot parse checkpoint_root/checkpoint_slot from the marker region:\n%s", region)
	}
	slot, err := strconv.ParseUint(strings.ReplaceAll(sm[1], "_", ""), 10, 64)
	if err != nil {
		t.Fatalf("parse slot %q: %v", sm[1], err)
	}

	c := ConsensusMainnet()
	if got := hexStrNo0x(c.CheckpointRoot[:]); got != rm[1] {
		t.Errorf("Go checkpoint root %s drifted from rust sync.rs %s — move the pin in chain/lc.go with the release refresh", got, rm[1])
	}
	if c.CheckpointSlot != slot {
		t.Errorf("Go checkpoint slot %d drifted from rust sync.rs %d", c.CheckpointSlot, slot)
	}
}

func hexStrNo0x(b []byte) string {
	const d = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(d[c>>4])
		sb.WriteByte(d[c&0xf])
	}
	return sb.String()
}
