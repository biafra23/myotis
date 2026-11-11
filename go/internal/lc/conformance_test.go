package lc

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
)

// TestLCCorpus replays the cross-language light-client corpus that the
// Rust engine pins (rust/testdata/lc/mainnet) — the same vectors
// LcVectorConformanceTest records for Rust and Java. Bootstrap plus the
// update chain 001..018 must advance the store to the recorded finalized
// header, the 099 stale replay and the 001-finality negative must be
// rejected, and the final execution state root (the anchor part 4 reads
// against) must match byte for byte. A moved corpus FAILS, never skips.
func TestLCCorpus(t *testing.T) {
	corpus := filepath.Join("..", "..", "..", "rust", "testdata", "lc", "mainnet")
	expected := parseExpectedCorpus(t, filepath.Join(corpus, "expected.txt"))
	consensus := chain.ConsensusMainnet()
	fork := NewForkSchedule(consensus)
	actual := map[string]string{}

	record := func(k, v string) { actual[k] = v }
	record("genesisValidatorsRoot", hexStr(consensus.GenesisValidatorsRoot[:]))
	fv := fork.VersionAtEpoch(^uint64(0))
	record("forkVersion", hexStr(fv[:]))

	bootBytes := readCorpus(t, filepath.Join(corpus, "bootstrap.ssz"))
	boot, err := DecodeBootstrap(bootBytes)
	if err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	root := boot.Header.Beacon.Root()
	record("bootstrap.headerRoot", hexStr(root[:]))
	record("bootstrap.slot", itoa(boot.Header.Beacon.Slot))
	store, err := NewFromBootstrap(boot, fork, consensus)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	slotEstimate := parseUint(t, expected["input.currentSlotEstimate"])
	record("input.currentSlotEstimate", expected["input.currentSlotEstimate"])

	updateFiles := corpusFiles(t, corpus, "-update.ssz")
	record("updates.count", itoa(uint64(len(updateFiles))))
	for i, f := range updateFiles {
		u, err := DecodeUpdate(readCorpus(t, f))
		if err != nil {
			t.Fatalf("decode %s: %v", filepath.Base(f), err)
		}
		applied := store.ProcessUpdate(u) == nil
		record("update."+itoa(uint64(i))+".applied", boolStr(applied))
		record("update."+itoa(uint64(i))+".finalizedSlot", itoa(store.Finalized.Slot))
		if applied {
			store.ForceRotateIfPastPeriod(slotEstimate)
		}
	}

	finalityFiles := corpusFiles(t, corpus, "-finality.ssz")
	record("finality.count", itoa(uint64(len(finalityFiles))))
	for i, f := range finalityFiles {
		fu, err := DecodeFinalityUpdate(readCorpus(t, f))
		if err != nil {
			t.Fatalf("decode %s: %v", filepath.Base(f), err)
		}
		outcome, err := store.ProcessFinalityUpdate(fu)
		applied := err == nil && outcome == Advanced
		record("finality."+itoa(uint64(i))+".applied", boolStr(applied))
	}

	record("final.finalizedSlot", itoa(store.Finalized.Slot))
	finalExec := store.FinalizedStateRoot()
	record("final.finalizedExecStateRoot", hexStr(finalExec[:]))

	for k, want := range expected {
		got, ok := actual[k]
		if !ok {
			t.Errorf("corpus key %s not produced by this replay", k)
			continue
		}
		if got != want {
			t.Errorf("corpus mismatch %s: got %s, want %s", k, got, want)
		}
	}
	for k := range actual {
		if _, ok := expected[k]; !ok {
			t.Errorf("replay produced key %s the corpus does not expect", k)
		}
	}
}

// ---- helpers ----

func parseExpectedCorpus(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed corpus line %q", line)
		}
		out[k] = v
	}
	if len(out) == 0 {
		t.Fatalf("corpus %s is empty", path)
	}
	return out
}

func corpusFiles(t *testing.T, dir, suffix string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*"+suffix))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no %s files in %s", suffix, dir)
	}
	// Corpus convention: exactly-3-digit prefixes, replayed in filename
	// order (expected.txt header); 4-digit captures are not ingested.
	var keep []string
	for _, m := range matches {
		base := filepath.Base(m)
		if len(base) == len(suffix)+3 && base[3] == '-' {
			keep = append(keep, m)
		}
	}
	sort.Strings(keep)
	return keep
}

func readCorpus(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}
	return b
}

func hexStr(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&0xf])
	}
	return sb.String()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func parseUint(t *testing.T, s string) uint64 {
	t.Helper()
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a number: %q", s)
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}
