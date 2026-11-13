package lc

import (
	"path/filepath"
	"testing"
)

// TestNormalizedBranchPads pins the rewritten verifyNormalizedMerkleBranch
// (PR #769 review: the old draft walked the leaf THROUGH the zero pad —
// accepting a proof one level deeper than the gindex names, and only ever
// one pad). Here: a genuine 3-node proof at gindex 10 (depth 3) in an
// 8-leaf tree; zero pads in FRONT of it must be accepted at any count and
// stripped, a nonzero pad or a truncated proof must not.
func TestNormalizedBranchPads(t *testing.T) {
	leaf := hash32{0xde, 0xad}
	z := zeroHashes[0]
	// 8-leaf tree, leaf at position 2, all else zero.
	l01 := sha256Pair(z, z) // H(l0,l1)
	l23 := sha256Pair(leaf, z)
	l45 := sha256Pair(z, z)
	l67 := sha256Pair(z, z)
	root := sha256Pair(sha256Pair(l01, l23), sha256Pair(l45, l67))
	// gindex for leaf 2 in a depth-3 tree: 8+2 = 10; branch = sibling
	// ladder bottom-up: l3(z), H(l0,l1), H(H(l4..),H(l6..)).
	branch := []hash32{z, l01, sha256Pair(l45, l67)}
	const gindex = 10

	if !verifyMerkleBranch(leaf, branch, gindex, root) {
		t.Fatal("the plain proof must verify (test fixture is wrong otherwise)")
	}
	if !verifyNormalizedMerkleBranch(leaf, branch, gindex, root) {
		t.Fatal("exact-depth branch must verify")
	}
	// Any number of ZERO leading pads: accepted (the Gloas case pads a
	// depth-9 proof inside an 11-node vector — two pads).
	for _, pads := range []int{1, 2, 3} {
		padded := append([]hash32{}, bytes_repeat(z, pads)...)
		padded = append(padded, branch...)
		if !verifyNormalizedMerkleBranch(leaf, padded, gindex, root) {
			t.Fatalf("%d zero pads must be accepted and stripped", pads)
		}
	}
	// A NONZERO leading pad must be refused…
	bad := append([]hash32{{0x01}}, branch...)
	if verifyNormalizedMerkleBranch(leaf, bad, gindex, root) {
		t.Fatal("nonzero pad accepted")
	}
	// …and so must a branch SHORTER than the gindex's depth.
	if verifyNormalizedMerkleBranch(leaf, branch[1:], gindex, root) {
		t.Fatal("truncated branch accepted")
	}
	// gindex < 2 names no leaf path.
	if verifyNormalizedMerkleBranch(leaf, branch, 1, root) {
		t.Fatal("gindex 1 (the root) accepted")
	}
}

func bytes_repeat(h hash32, n int) []hash32 {
	out := make([]hash32, n)
	for i := range out {
		out[i] = h
	}
	return out
}

// FuzzDecode* (PR #769 review): the three decoders eat peer bytes and
// MUST NOT panic — every sniffed length range-checked, every positioned
// read bounded. Seeds are the corpus files plus the shapes that used to
// break them: an oversized extra_data tail (+33 bytes past the
// ByteList[32] bound — the listRoot panic the review found), offsets
// ≥ 2³¹ (negative on 32-bit int), truncations.
func fuzzSeeds(t testing.TB, name string) [][]byte {
	dir := filepath.Join("..", "..", "..", "rust", "testdata", "lc", "mainnet")
	base := readCorpus(t, filepath.Join(dir, name))
	big := append(append([]byte{}, base...), make([]byte, 33)...)
	for i := 0; i < 4; i++ {
		big[len(base)+i] = 0xff // tail no longer all-zero
	}
	hi := append([]byte{}, base...)
	for i := 0; i < 4; i++ {
		hi[i] = 0xff // offset ≥ 2³¹: int(hi) negative on 32-bit
	}
	return [][]byte{base, big, hi, base[:len(base)/2], base[:8], {}}
}

func FuzzDecodeBootstrap(f *testing.F) {
	for _, s := range fuzzSeeds(f, "bootstrap.ssz") {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = DecodeBootstrap(b) })
}

func FuzzDecodeUpdate(f *testing.F) {
	for _, s := range fuzzSeeds(f, "001-update.ssz") {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = DecodeUpdate(b) })
}

func FuzzDecodeFinalityUpdate(f *testing.F) {
	for _, s := range fuzzSeeds(f, "002-finality.ssz") {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = DecodeFinalityUpdate(b) })
}
