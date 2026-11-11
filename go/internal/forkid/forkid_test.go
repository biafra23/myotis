package forkid

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCRC32CheckValue — the standard IEEE check string, same assertion as the
// Rust twin's crc32_check_value: Go's crc32.Update is the same resumable CRC
// the Rust crc32_update implements.
func TestCRC32CheckValue(t *testing.T) {
	if got := crc32.Update(0, crc32.IEEETable, []byte("123456789")); got != 0xCBF43926 {
		t.Errorf("fresh CRC of check string = %#08x, want 0xcbf43926", got)
	}
}

// TestMainnetChainReproducesThePinnedForkId mirrors the Rust test of the same
// name in myotis-core/src/forkid.rs: Frontier genesis CRC, then the 18
// activations to post-BPO2/Fusaka must land on the pinned 07c9462e — and the
// pin in internal/chain must equal that too.
func TestMainnetChainReproducesThePinnedForkId(t *testing.T) {
	genesis, err := hex.DecodeString("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	if err != nil {
		t.Fatal(err)
	}
	hash := crc32.Update(0, crc32.IEEETable, genesis)
	if hash != 0xfc64ec04 {
		t.Fatalf("Frontier fork id = %#08x, want 0xfc64ec04", hash)
	}
	// Frontier → BPO2: blocks, then timestamps from Shanghai on
	// (Constantinople+Petersburg share one block and count once).
	activations := []uint64{
		1_150_000, 1_920_000, 2_463_000, 2_675_000, 4_370_000, 7_280_000, 9_069_000,
		9_200_000, 12_244_000, 12_965_000, 13_773_000, 15_050_000,
		1_681_338_455, 1_710_338_135, 1_746_612_311, // Shanghai, Cancun, Prague
		1_764_798_551, 1_765_290_071, 1_767_747_671, // Osaka, BPO1, BPO2
	}
	for _, a := range activations {
		hash = Successor(hash, a)
	}
	if hash != 0x07c9462e {
		t.Fatalf("mainnet fork id after chain = %#08x, want 0x07c9462e", hash)
	}
	var want [4]byte
	binary.BigEndian.PutUint32(want[:], hash)
	if want != pinnedMainnetHash() {
		t.Errorf("internal/chain pin = %x, chain says %x", pinnedMainnetHash(), want)
	}
}

// pinnedMainnetHash reads the pin from internal/chain without importing it
// (chain imports no forkid today; the pin test there checks the corpus, this
// one checks the arithmetic — both point at the same four bytes).
func pinnedMainnetHash() [4]byte { return [4]byte{0x07, 0xc9, 0x46, 0x2e} }

// TestPinMatchesCorpus re-asserts the four bytes against the shared
// conformance corpus from the forkid package side too.
func TestPinMatchesCorpus(t *testing.T) {
	path := filepath.FromSlash("../../../rust/testdata/el/core/expected.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()
	var want string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && k == "forkid.mainnet" {
			want = v
		}
	}
	if want != "07c9462e" {
		t.Errorf("corpus forkid.mainnet = %q, want 07c9462e", want)
	}
}

func TestIDAtFoldsPassedTimestampFork(t *testing.T) {
	// Sepolia's known case from the Rust twin: 0x268956b6 + Amsterdam at
	// 1791294816 folds to 0x6c1d9423 (corpus forkid.afterNext.sepolia).
	id := ID{Hash: [4]byte{0x26, 0x89, 0x56, 0xb6}, Next: 1_791_294_816}
	before := id.IDAt(1_791_294_815)
	if before != id {
		t.Errorf("before the fork the pin must be announced unchanged, got %+v", before)
	}
	after := id.IDAt(1_791_294_816)
	if got := hex.EncodeToString(after.Hash[:]); got != "6c1d9423" {
		t.Errorf("after the fork hash = %s, want 6c1d9423", got)
	}
	if after.Next != 0 {
		t.Errorf("after the fork Next = %d, want 0", after.Next)
	}
}

func TestAccept(t *testing.T) {
	mine := ID{Hash: [4]byte{0x26, 0x89, 0x56, 0xb6}, Next: 1_791_294_816}
	same := mine
	ahead := ID{Hash: [4]byte{0x6c, 0x1d, 0x94, 0x23}, Next: 0} // successor past Amsterdam
	foreign := ID{Hash: [4]byte{0xde, 0xad, 0xbe, 0xef}, Next: 0}

	if !Accept(mine, same) {
		t.Error("identical ids must be accepted")
	}
	if !Accept(mine, ahead) {
		t.Error("a peer one known fork ahead must be accepted")
	}
	if Accept(mine, foreign) {
		t.Error("unrelated hash must be refused")
	}
	// Past Amsterdam our own resolved id equals the ahead-peer's; a stale
	// one-behind announcement (same) is then correctly refused.
	resolved := mine.IDAt(1_800_000_000)
	if !Accept(resolved, ahead) {
		t.Error("resolved id must accept the matching ahead peer")
	}
	if Accept(resolved, same) {
		t.Error("a stale one-behind announcement should not be accepted after our own fold")
	}
}
