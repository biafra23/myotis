package lc

import (
	"bytes"
	"testing"

	"github.com/biafra23/myotis/go/internal/chain"
	blst "github.com/supranational/blst/bindings/go"
)

// TestBlstReceiverIsTheSignature pins the binding trap that ate an hour:
// FastAggregateVerify verifies the RECEIVER's point — a fresh P2Affine is
// the identity and always fails. The signature must be uncompressed into
// the receiver first (and only then subgroup-checked per the Rust twin).
func TestBlstReceiverIsTheSignature(t *testing.T) {
	ikm := bytes.Repeat([]byte{3}, 32)
	sk := blst.KeyGen(ikm)
	pk := new(blst.P1Affine).From(sk)
	pks := []*blst.P1Affine{new(blst.P1Affine).Uncompress(pk.Compress())}
	if pks[0] == nil {
		t.Fatal("pubkey roundtrip")
	}
	msg := []byte("the signing root, 32 bytes long!!!.")
	sig := new(blst.P2Affine).Sign(sk, msg, BLS_DST)
	if sig == nil {
		t.Fatal("sign failed")
	}
	if new(blst.P2Affine).FastAggregateVerify(true, pks, msg, BLS_DST) {
		t.Fatal("an EMPTY receiver must not verify — it is the identity, not our signature")
	}
	if !sig.FastAggregateVerify(true, pks, msg, BLS_DST) {
		t.Fatal("the loaded signature must verify")
	}
}

// TestBLSDST pins the DST byte-for-byte: _POP_ (not _NUL_), no dash in
// BLS12381 — a one-byte drift changes hash-to-curve and silently fails
// every real signature.
func TestBLSDST(t *testing.T) {
	want := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
	if string(BLS_DST) != want {
		t.Fatalf("DST = %q, want %q", BLS_DST, want)
	}
}

// TestZeroLeafIsHeightZero pins the merkleize trap: a missing LEAF is
// zeroHashes[0] at any depth; the taller zero subtrees must emerge from
// pairing, not from indexing the fill table by recursion depth.
func TestZeroLeafIsHeightZero(t *testing.T) {
	// containerRoot of 5 fields = the BeaconBlockHeader shape: pad to 8
	// leaves. With the depth-indexed bug the root silently differs.
	if got, want := zeroHashes[0], sha256Pair(zeroHashes[0], zeroHashes[0]); got == want {
		t.Fatal("zero-hash table degenerate")
	}
	five := []hash32{{1}, {2}, {3}, {4}, {5}}
	r := containerRoot(five...)
	manual := merkleize([]hash32{{1}, {2}, {3}, {4}, {5}, zeroHashes[0], zeroHashes[0], zeroHashes[0]}, 8)
	if r != manual {
		t.Fatalf("containerRoot padded-to-8 mismatch: %x vs %x", r, manual)
	}
	// And the explicit three-level zero column:
	if zeroHashes[1] != sha256Pair(zeroHashes[0], zeroHashes[0]) ||
		zeroHashes[2] != sha256Pair(zeroHashes[1], zeroHashes[1]) {
		t.Fatal("zero-hash ladder")
	}
}

// TestWsAnchorStale pins the period-granular bound semantics both shipped
// engines share: age EQUAL to the bound is fresh (strictly-greater
// predicate), a backwards clock saturates to fresh, bound+1 is stale.
func TestWsAnchorStale(t *testing.T) {
	if chain.WsAnchorStale(100, 113, chain.WsBoundPeriods) {
		t.Fatal("age == bound must be fresh (strictly-greater predicate)")
	}
	if !chain.WsAnchorStale(100, 114, chain.WsBoundPeriods) {
		t.Fatal("bound+1 must be stale")
	}
	if chain.WsAnchorStale(100, 90, chain.WsBoundPeriods) {
		t.Fatal("a wall clock behind the anchor saturates to fresh")
	}
}

// TestSignatureSlotOffByOne pins the (slot-1) epoch rule (fork.rs:191):
// at a period/epoch boundary the domain follows the PRECEDING fork for
// signatures in the new epoch's first slot… i.e. version_for_signature_slot
// is version_at_epoch((max(slot,1)-1)/32), NOT version_at_epoch(slot/32).
func TestSignatureSlotOffByOne(t *testing.T) {
	c := chain.ConsensusMainnet()
	fork := NewForkSchedule(c)
	// Electra activates at epoch 364032 → slot 11649024. A signature AT
	// that slot signs under the version of epoch (slot-1)/32 = 364031 —
	// still Deneb. One slot later it flips.
	if v := fork.VersionForSignatureSlot(364032 * chain.SlotsPerEpoch); v != (c.Forks[4].Version) {
		t.Fatalf("boundary slot: got %x, want Deneb %x", v, c.Forks[4].Version)
	}
	// Adjacent slot, as the Rust twin tests it (fork.rs:227-228): an
	// epoch-later check would also pass under (slot-32)/32 and every
	// other wrong-but-similar rule.
	if v := fork.VersionForSignatureSlot(364032*chain.SlotsPerEpoch + 1); v != (c.Forks[5].Version) {
		t.Fatalf("one slot in: got %x, want Electra %x", v, c.Forks[5].Version)
	}
	// And slot 0 must not underflow.
	if v := fork.VersionForSignatureSlot(0); v != (c.Forks[0].Version) {
		t.Fatalf("slot 0: %x", v)
	}
}
