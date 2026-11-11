package snapwire

// Verify-on-fetch for snap state, the security-critical half of the
// snap oracle (docs/spec/03 §3.2, README §11.8-12). Go port of
// rust/myotis-wire/src/snap/fetch.rs.
//
// Every value is verified against a TRUSTED state root via the MPT
// proof verifier before it is returned; the peer's "slim" account body
// is NEVER trusted (a peer can keep nonce/balance honest while forging
// storageRoot/codeHash), so the account fields come only from the
// proof-verified leaf. Storage anchors at the account's proven
// storageRoot, not the world state root. Bytecode is accepted iff
// keccak256(code) == codeHash.

import (
	"fmt"
	"strings"

	"github.com/biafra23/myotis/go/internal/mpt"
)

// ProofInvalidMarker is shared by every proof-verification failure
// message. LOAD-BEARING: the read orchestration classifies
// "the peer answered but could not prove at that root" (pruned /
// trailing / malformed proof) by this substring, distinct from
// transport-shaped errors. Keep the formats below built from this
// constant, and IsUnservableRootError + its tests in sync.
const ProofInvalidMarker = "proof invalid"

// UnknownRootReason is the reason mpt.VerifyProof gives when a peer
// answers a range query with NO proof nodes for a non-empty root —
// the shape of "I do not hold that root": pruned, or never had (a
// trailing peer). Kept in sync with the verifier; it is the one miss
// a read at a root the peer is not obliged to hold (the finalized
// root, kept for a bounded window) EXCUSES as evidence about the ask
// rather than the peer.
const UnknownRootReason = "empty proof for non-empty root"

// IsUnservableRootError reports whether an error means "the peer
// responded, but the proof did not verify against the requested
// root" — a pruned/unknown root, a trailing peer, or a malformed/
// hostile proof, all cases where a retry against a DIFFERENT root can
// still succeed. False for transport-shaped failures (timeout/
// disconnect), where a second query against the same peer would just
// pay the same timeout again.
func IsUnservableRootError(err error) bool {
	return err != nil && strings.Contains(err.Error(), ProofInvalidMarker)
}

// IsUnknownRootError reports whether an error means "the peer does not
// hold the requested root" — the empty-proof answer, as opposed to a
// malformed or hostile proof (which stays a strike against the peer).
func IsUnknownRootError(err error) bool {
	return IsUnservableRootError(err) && strings.Contains(err.Error(), UnknownRootReason)
}

// AccountState is which verdict an AccountOutcome carries. Invalid is
// the ZERO value (the lc.FinalityOutcome rule from the #769 review):
// a "proven absent" account is a FACT handed to the caller, so a
// half-built outcome must never read as one.
type AccountState int

const (
	AccountInvalid      AccountState = iota // nothing proven
	AccountFound                            // proof-verified leaf in Account
	AccountProvenAbsent                     // proof shows the key is absent
)

// AccountOutcome is the verified outcome of an account lookup: State
// says which verdict it is, and Account carries the proof-verified
// fields when the account exists (nil otherwise — but STATE is what
// distinguishes "provably absent" from "nothing proven", not a nil
// that could mean either).
type AccountOutcome struct {
	State   AccountState
	Account *mpt.AccountLeaf
}

// Absent reports the provable-absence outcome.
func (o AccountOutcome) Absent() bool { return o.State == AccountProvenAbsent }

// VerifyAccount verifies an AccountRange response for address against
// the trusted stateRoot. A single-account query (starting =
// keccak(address)) yields a left-boundary proof that is exactly the
// Merkle proof for keccak(address).
func VerifyAccount(stateRoot [32]byte, address [20]byte, response *AccountRange) (AccountOutcome, error) {
	key := mpt.Keccak(address[:])
	return accountOutcome(mpt.VerifyProof(stateRoot, key[:], response.Proof))
}

func accountOutcome(r mpt.Result) (AccountOutcome, error) {
	switch r.Status {
	case mpt.Found:
		leaf, err := mpt.DecodeAccountLeaf(r.Value)
		if err != nil {
			return AccountOutcome{}, err
		}
		return AccountOutcome{State: AccountFound, Account: leaf}, nil
	case mpt.Absent:
		return AccountOutcome{State: AccountProvenAbsent}, nil
	default:
		return AccountOutcome{}, fmt.Errorf("account %s: %s", ProofInvalidMarker, r.Reason)
	}
}

// VerifyStorage verifies a StorageRanges response: the minimal
// big-endian slot value (nil = zero), anchored at the account's
// PROVEN storageRoot, not the state root.
func VerifyStorage(account *mpt.AccountLeaf, slot [32]byte, response *StorageRanges) ([]byte, error) {
	// An empty storage trie: the value is zero with no proof needed.
	if account.StorageRoot == mpt.EmptyTrieRoot {
		return nil, nil
	}
	key := mpt.Keccak(slot[:])
	switch r := mpt.VerifyProof(account.StorageRoot, key[:], response.Proof); r.Status {
	case mpt.Found:
		return mpt.DecodeStorageLeaf(r.Value)
	case mpt.Absent:
		return nil, nil
	default:
		return nil, fmt.Errorf("storage %s: %s", ProofInvalidMarker, r.Reason)
	}
}

// VerifyBytecode matches a returned bytecode against its requested
// codeHash (keccak256(code) == codeHash), returning the code if any
// returned entry matches. An empty-code-hash request short-circuits
// to "no code, verified" with no round trip.
func VerifyBytecode(codeHash [32]byte, returned [][]byte) ([]byte, bool) {
	if codeHash == mpt.EmptyCodeHash {
		return nil, true
	}
	for _, code := range returned {
		if mpt.Keccak(code) == codeHash {
			return code, true
		}
	}
	return nil, false
}
