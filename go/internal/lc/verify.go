package lc

import (
	"errors"
	"fmt"

	"github.com/biafra23/myotis/go/internal/chain"
	blst "github.com/supranational/blst/bindings/go"
)

// BLS_DST is the proof-of-possession DST — byte-for-byte the string the
// Rust twin tests (myotis-bls lib.rs:27). A _NUL_ variant verifies
// different signatures; there is no negotiating this.
var BLS_DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// ComputeDomain: DOMAIN type ‖ truncate(ForkData root, 28) — spec
// compute_domain (verify.rs:13-26).
func ComputeDomain(domainType, forkVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	var padded [32]byte
	copy(padded[:4], forkVersion[:])
	forkDataRoot := containerRoot(padded, genesisValidatorsRoot)
	var d [32]byte
	copy(d[:4], domainType[:])
	copy(d[4:], forkDataRoot[:28])
	return d
}

// SigningRoot: 2-leaf container of object root and domain (verify.rs:29).
func SigningRoot(objectRoot, domain [32]byte) [32]byte {
	return containerRoot(objectRoot, domain)
}

// VerifySyncAggregate takes the same inputs as its Rust twin
// (verify.rs:36 — aggregate, committee, attested beacon header, fork
// version, genesis validators root) and derives the domain and signing
// root ITSELF: those parameters define what is signed, so accepting them
// and verifying a caller-computed root instead would be the Trust
// section's forbidden "accepted and silently ignored" — a caller could
// hand a root built under another fork version and get a verdict for it
// with no sign. The signed object is the BEACON header root, as the Rust
// processor passes attested_header.beacon into this function.
//
// The check is the spec's fast_aggregate_verify with the two myotis-bls
// asymmetries kept exact (lib.rs:69-86): committee pubkeys are
// Merkle-proven, so they get NO per-key subgroup check; the aggregate
// signature is peer-supplied and MUST be subgroup-checked. The
// participation gate (2/3 of 512, as *3 ≥ 512*2) runs before any curve
// arithmetic.
func VerifySyncAggregate(committee *SyncCommittee, agg *SyncAggregate, attested *BeaconBlockHeader, forkVersion [4]byte, genesisValidatorsRoot [32]byte) error {
	signingRoot := SigningRoot(attested.Root(),
		ComputeDomain(DomainSyncCommittee, forkVersion, genesisValidatorsRoot))
	n := agg.Participants()
	if n*3 < SyncCommitteeSize*2 {
		return fmt.Errorf("lc: participation %d below the 2/3 bar", n)
	}
	if n > MaxPubkeys {
		// Tripwire, not a live bound: a 64-byte participation bitvector
		// caps n at 512. It guards the curve arithmetic if the committee
		// or bitvector is ever widened past MAX_PUBKEYS without this
		// function following.
		return fmt.Errorf("lc: %d participants over MAX_PUBKEYS", n)
	}
	if len(committee.Pubkeys) != SyncCommitteeSize {
		return errors.New("lc: committee size")
	}
	pks := make([]*blst.P1Affine, 0, n)
	for i := 0; i < SyncCommitteeSize; i++ {
		if !agg.Active(i) {
			continue
		}
		pk := new(blst.P1Affine).Uncompress(committee.Pubkeys[i][:])
		if pk == nil {
			return fmt.Errorf("lc: pubkey %d uncompresses to nothing", i)
		}
		pks = append(pks, pk)
	}
	// Load the aggregate INTO the receiver first: FastAggregateVerify
	// verifies the RECEIVER's point (the binding's doc is easy to miss —
	// calling it on a fresh P2Affine verifies the identity and always
	// fails). Exactly the Rust twin's semantics (myotis-bls lib.rs:79-86):
	// uncompress WITH subgroup check (sigGroupcheck=true), hash input the
	// 32-byte signing root ALONE — the domain is already baked into the
	// signing root; blst's optional aug stays empty.
	sig := new(blst.P2Affine).Uncompress(agg.Signature[:])
	if sig == nil {
		return errors.New("lc: aggregate signature does not uncompress")
	}
	ok := sig.FastAggregateVerify(true, /* subgroup-check the signature */
		pks, signingRoot[:], BLS_DST)
	if !ok {
		return errors.New("lc: sync aggregate signature invalid")
	}
	return nil
}

// CheckpointPeriod is the period of the pinned checkpoint slot — anchor of
// all three weak-subjectivity gates (start, bootstrap re-check, in-run
// forward guard, sync.rs:2277).
func CheckpointPeriod(c *chain.Consensus) uint64 {
	return chain.SyncCommitteePeriod(c.CheckpointSlot)
}
