// Package snapread turns READY snap sessions plus a BLS-anchored
// finalized exec state root into verified reads: account, storage
// (two-hop through the proof-verified account), and bytecode
// (keccak-checked against the proof-verified codeHash). Go twin of
// myotis-net's snap reader, stripped to the minimal-engine policy:
//
//   - FINALIZED reads only. Every read queries exactly the anchored
//     finalized exec state root, and there is NO fallback to a fresher
//     head (the Rust engine's handshake-head fallback, #355, is a
//     documented 3b-scope cut — the anchor is the fresh head here:
//     the LC finality poll advances it every round).
//   - Sequential peer attempts, capped at 3 — the address-disclosure
//     bound the Rust twin puts on hedged reads (MAX_HEDGED_ATTEMPTS)
//     applies the same way when one client IP would contact N peers
//     for one read. (Hedging itself — racing peers 3 s apart — is a
//     3c candidate, go/README.)
//   - The trust rule of the whole engine: values come ONLY from
//     proof-verified leaves (snapwire.Verify*), never from a peer's
//     slim body or a peer's word about roots.
package snapread

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/biafra23/myotis/go/internal/mpt"
	"github.com/biafra23/myotis/go/internal/snapwire"
)

// Peer is the slice of transport.Session the reader uses — an
// interface so the attempt/classification policy is testable without
// sockets.
type Peer interface {
	ID() string
	HasSnap() bool
	GetAccountRange(stateRoot, startingHash, limitHash [32]byte, responseBytes uint64) (*snapwire.AccountRange, error)
	GetStorageRanges(stateRoot, accountHash, startingHash, limitHash [32]byte, responseBytes uint64) (*snapwire.StorageRanges, error)
	GetByteCodes(hashes [][32]byte, responseBytes uint64) ([][]byte, error)
}

// maxAttempts bounds one read's contact with distinct peers: the
// address-disclosure bound, same constant and reason as the Rust
// twin's MAX_HEDGED_ATTEMPTS.
const maxAttempts = 3

const (
	// accountResponseBytes: a single account plus its boundary proof
	// fits with room; a bigger budget only invites a bigger page.
	accountResponseBytes = 4096
	// byteCodeResponseBytes mirrors the Rust reader's 256 KiB budget.
	byteCodeResponseBytes = 256 * 1024
)

// fullLimit is snapwire's documented no-upper-bound limit hash — one
// copy, exported there because the request encoders send exactly it.
var fullLimit = snapwire.FullLimitHash

// FaultKind classifies why one peer failed a read — the three-way
// taxonomy the Rust reader drives its pool policy from. The
// distinction pays off wherever peers are kept across reads (strike
// accounting): a PrunedRoot says something about the ASK (the peer
// is not obliged to hold that root yet — it pruned it or the finality
// moved under it), a BadProof or Transport fault says something about
// the PEER.
type FaultKind int

const (
	FaultTransport  FaultKind = iota // timeout / disconnect / protocol-shaped
	FaultPrunedRoot                  // answered, empty proof at that root (excused)
	FaultBadProof                    // answered, proof did not verify (strike)
)

func (k FaultKind) String() string {
	switch k {
	case FaultPrunedRoot:
		return "pruned-root"
	case FaultBadProof:
		return "bad-proof"
	default:
		return "transport"
	}
}

// Classify maps a read error to its fault kind through snapwire's
// load-bearing marker strings.
func Classify(err error) FaultKind {
	switch {
	case snapwire.IsUnknownRootError(err):
		return FaultPrunedRoot
	case snapwire.IsUnservableRootError(err):
		return FaultBadProof
	default:
		return FaultTransport
	}
}

// Attempt is one peer's turn at one read, kept for the aggregate
// error so the operator sees WHY the set failed.
type Attempt struct {
	Peer string
	Kind FaultKind
	Err  error
}

// Account reads address's account at the anchored finalized stateRoot,
// trying up to maxAttempts snap-capable peers in order. The returned
// fields are the proof-verified leaf's; outcome.Absent() is a
// PROVEN absence (an empty account), not a failure.
func Account(peers []Peer, stateRoot [32]byte, address [20]byte) (snapwire.AccountOutcome, error) {
	_, out, err := readAccount(peers, stateRoot, address)
	return out, err
}

// readAccount is the one account implementation all three reads share
// (Slot/Code need the proven leaf for their second hop); it also
// returns the serving peer for reporting.
func readAccount(peers []Peer, stateRoot [32]byte, address [20]byte) (Peer, snapwire.AccountOutcome, error) {
	accountHash := crypto.Keccak256Hash(address[:])
	var attempts []Attempt
	for _, p := range usable(peers) {
		ar, err := p.GetAccountRange(stateRoot, accountHash, fullLimit, accountResponseBytes)
		if err != nil {
			attempts = append(attempts, Attempt{p.ID(), Classify(err), err})
			continue
		}
		out, err := snapwire.VerifyAccount(stateRoot, address, ar)
		if err != nil {
			// VerifyAccount marks PROOF failures with "proof invalid"
			// (→ pruned-root / bad-proof, both "ask elsewhere"). A leaf
			// that HASHED but fails the strict leaf decode carries no
			// marker ON PURPOSE: its bytes are committed by the proven
			// path, so no other peer can answer differently — retrying
			// elsewhere would just repay the round trip. That is the
			// Rust twin's rule (fetch.rs lets decode_account_leaf's `?`
			// escape outside the marker), and Classify maps it to
			// transport-shaped propagation accordingly.
			attempts = append(attempts, Attempt{p.ID(), Classify(err), err})
			continue
		}
		return p, out, nil
	}
	return nil, snapwire.AccountOutcome{}, allFailed("account", attempts)
}

// Slot reads one storage slot: first the account (its storageRoot
// must be PROVEN before any slot is anchored at it), then the slot
// range at the same finalized root, verified against that storageRoot.
// An empty storage trie short-circuits to zero with no second round
// trip — the proof that every slot of an empty trie is zero.
func Slot(peers []Peer, stateRoot [32]byte, address [20]byte, slot [32]byte) ([]byte, error) {
	_, acct, err := readAccount(peers, stateRoot, address)
	if err != nil {
		return nil, err
	}
	return SlotAt(peers, stateRoot, address, slot, acct)
}

// SlotAt performs ONLY the storage hop, against an account outcome the
// caller already proved. A caller that reads account and slot for the
// same address must share the proven outcome (and the same peer
// slice, so the attempt cap sees one stable peer order) — otherwise
// the account hop runs twice and the address reaches up to 3+3
// distinct peers for what is one logical read, against the spirit of
// the disclosure bound maxAttempts exists for.
func SlotAt(peers []Peer, stateRoot [32]byte, address [20]byte, slot [32]byte, acct snapwire.AccountOutcome) ([]byte, error) {
	if acct.Absent() || acct.Account.StorageRoot == mpt.EmptyTrieRoot {
		return nil, nil // provably empty account / empty trie: every slot is zero
	}
	slotHash := crypto.Keccak256Hash(slot[:])
	accountHash := crypto.Keccak256Hash(address[:])
	var attempts []Attempt
	for _, p := range usable(peers) {
		sr, err := p.GetStorageRanges(stateRoot, accountHash, slotHash, fullLimit, accountResponseBytes)
		if err != nil {
			attempts = append(attempts, Attempt{p.ID(), Classify(err), err})
			continue
		}
		v, err := snapwire.VerifyStorage(acct.Account, slot, sr)
		if err != nil {
			attempts = append(attempts, Attempt{p.ID(), Classify(err), err})
			continue
		}
		return v, nil
	}
	return nil, allFailed("storage slot", attempts)
}

// Code reads an account's bytecode: the account read proves the
// codeHash, then GetByteCodes is asked for exactly that hash and
// every returned code is keccak-checked (VerifyBytecode) — an
// EOA's empty-code-hash short-circuits with no round trip.
func Code(peers []Peer, stateRoot [32]byte, address [20]byte) ([]byte, error) {
	_, acct, err := readAccount(peers, stateRoot, address)
	if err != nil {
		return nil, err
	}
	if acct.Absent() {
		return nil, errors.New("snapread: account is provably absent, it has no code")
	}
	codeHash := acct.Account.CodeHash
	if codeHash == mpt.EmptyCodeHash {
		return nil, nil // verified EOA: empty code, no request needed
	}
	var attempts []Attempt
	for _, p := range usable(peers) {
		codes, err := p.GetByteCodes([][32]byte{codeHash}, byteCodeResponseBytes)
		if err != nil {
			attempts = append(attempts, Attempt{p.ID(), Classify(err), err})
			continue
		}
		code, ok := snapwire.VerifyBytecode(codeHash, codes)
		if !ok {
			// No returned entry hashes to the proven codeHash: the peer
			// did not serve the ask — proof-shaped failure, retry next.
			err := fmt.Errorf("bytecodes %s: no served code hashes to the proven codeHash", ProofMismatchMarker)
			attempts = append(attempts, Attempt{p.ID(), FaultBadProof, err})
			continue
		}
		return code, nil
	}
	return nil, allFailed("bytecode", attempts)
}

// ProofMismatchMarker marks the "served, but nothing matched the
// proven hash" failure inside the unservable-root family (retrying
// elsewhere CAN succeed — the ask may be servable — but the miss is
// not excused: honest peers serve what a finalized read asks for).
const ProofMismatchMarker = "proof invalid: hash-mismatch"

// usable filters to snap-capable peers and applies the
// address-disclosure attempt cap.
func usable(peers []Peer) []Peer {
	var out []Peer
	for _, p := range peers {
		if p.HasSnap() {
			out = append(out, p)
		}
		if len(out) == maxAttempts {
			break
		}
	}
	return out
}

// allFailed is the pool-failure shape, twin of the Rust reader's
// "all N snap peer(s) failed to serve {what}: {last_err}" — with the
// per-attempt kinds inline so the operator can tell "the whole set
// pruned that root" from "the whole set is unreachable".
func allFailed(what string, attempts []Attempt) error {
	if len(attempts) == 0 {
		return errors.New("snapread: no snap-capable peers to serve " + what)
	}
	last := attempts[len(attempts)-1]
	return fmt.Errorf("snapread: all %d snap peer(s) failed to serve %s: %w [%s]",
		len(attempts), what, last.Err, summarize(attempts))
}

func summarize(attempts []Attempt) string {
	s := ""
	for _, a := range attempts {
		if s != "" {
			s += ", "
		}
		s += fmt.Sprintf("%s=%s", shortID(a.Peer), a.Kind)
	}
	return s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
