package lc

import (
	"errors"
	"fmt"

	"github.com/biafra23/myotis/go/internal/chain"
)

// ErrPeriodGate marks rejections by the weak-subjectivity period gate —
// the #423 ordering (store.rs:339-355): the signature's period is judged
// BEFORE any BLS runs, so a stale-but-well-formed update dies here, not
// at the curve. The conformance test asserts errors.Is on the corpus
// negatives to pin that no gate behind it fired instead.
var ErrPeriodGate = errors.New("lc: period gate")

// Store is the light client's verified state, a port of myotis-consensus
// store.rs. Everything in it was either bootstrapped from the pinned
// checkpoint or passed every gate of ProcessUpdate — the committee, the
// finalized header and its execution payload root are all proven, never
// assumed.
type Store struct {
	fork      *ForkSchedule
	consensus *chain.Consensus

	CurrentCommittee, NextCommittee *SyncCommittee
	// Period the CurrentCommittee serves (store.rs store_period).
	StorePeriod uint64

	Finalized      *BeaconBlockHeader
	FinalizedExec  hash32
	Optimistic     *BeaconBlockHeader
	OptimisticExec hash32
	// optimisticSigSlot is the SIGNATURE slot of the update that set the
	// optimistic header (#658, store.rs optimistic_slot) — the ledger
	// update_optimistic compares against, so like is compared with like.
	optimisticSigSlot uint64

	// finalizedLC keeps the finalized LightClientHeader so the payload's
	// own state_root field stays reachable (FinalizedStateRoot).
	finalizedLC *lcHeader
}

// NewFromBootstrap runs docs/spec/01 §9.1 in full before adopting
// anything (verify_bootstrap, store.rs:250-282):
//
//  1. the CHECKPOINT PIN — the header's own hash must equal trustedRoot.
//     Asking a peer BY root does not constrain what it answers with
//     (PR #769 review), so the comparison happens here, not in the
//     caller's conscience: production passes chain.CheckpointRoot, the
//     corpus test passes the recorded bootstrap header root.
//  2. the committee branch against the header's state root;
//  3. the EXECUTION branch against the header's own body root — without
//     it FinalizedStateRoot() would return a peer-chosen payload state
//     root under a genuine checkpoint header (BootstrapReject::
//     ExecutionBranch, store.rs:277).
//
// trustedRoot is compared, never trusted sight unseen.
func NewFromBootstrap(b *Bootstrap, fork *ForkSchedule, c *chain.Consensus, trustedRoot hash32) (*Store, error) {
	if got := b.Header.Beacon.Root(); got != trustedRoot {
		return nil, fmt.Errorf("lc: bootstrap header root %x is not the trusted checkpoint root %x", got, trustedRoot)
	}
	geom := fork.geomAtSlot(b.Header.Beacon.Slot)
	if uint64(len(b.CommitteeBranch)) != geom.SyncLen {
		return nil, fmt.Errorf("lc: bootstrap committee branch has %d elements, fork geometry wants %d",
			len(b.CommitteeBranch), geom.SyncLen)
	}
	if !verifyMerkleBranch(b.SyncCommittee.Root(), b.CommitteeBranch, geom.SyncGindex, b.Header.Beacon.StateRoot) {
		return nil, errors.New("lc: bootstrap committee branch does not verify against the header state root")
	}
	if uint64(len(b.Header.Branch)) != geom.ExecLen {
		return nil, fmt.Errorf("lc: bootstrap execution branch has %d elements, fork geometry wants %d",
			len(b.Header.Branch), geom.ExecLen)
	}
	if !verifyMerkleBranch(b.Header.Exec, b.Header.Branch, geom.ExecGindex, b.Header.Beacon.BodyRoot) {
		return nil, errors.New("lc: bootstrap execution branch does not verify against the header body root")
	}
	return &Store{
		fork: fork, consensus: c,
		CurrentCommittee: b.SyncCommittee,
		StorePeriod:      chain.SyncCommitteePeriod(b.Header.Beacon.Slot),
		Finalized:        b.Header.Beacon,
		FinalizedExec:    b.Header.Exec,
		finalizedLC:      b.Header,
		Optimistic:       b.Header.Beacon,
		OptimisticExec:   b.Header.Exec,
		// store.rs bootstrap init: optimistic_slot = header.beacon.slot
		// (store.rs:67) — there is no signature slot at bootstrap.
		optimisticSigSlot: b.Header.Beacon.Slot,
	}, nil
}

// Period is the store's current sync-committee period.
func (s *Store) Period() uint64 { return s.StorePeriod }

// FinalizedStateRoot is the execution payload's OWN state_root field under
// the finalized header — the anchor part 4's snap reads verify against
// (the EPH's htr, s.FinalizedExec, is the Merkle glue proving that field
// lives in the finalized body).
func (s *Store) FinalizedStateRoot() hash32 {
	if s.finalizedLC == nil {
		return hash32{}
	}
	return s.finalizedLC.ExecStateRoot
}

// committeeFor is Rust's committee_for (store.rs:460-470): the store's
// current committee for its own period, the held next committee for the
// period after, ErrPeriodGate otherwise. Every rejection here carries the
// sentinel so callers (and the conformance test) can tell the #423
// applicability gate from anything downstream of it.
func (s *Store) committeeFor(sigPeriod uint64) (*SyncCommittee, error) {
	switch sigPeriod {
	case s.StorePeriod:
		return s.CurrentCommittee, nil
	case s.StorePeriod + 1:
		if s.NextCommittee == nil {
			return nil, fmt.Errorf("%w: update signed for period %d but the store holds no next committee",
				ErrPeriodGate, sigPeriod)
		}
		return s.NextCommittee, nil
	default:
		// #423: the period gate runs BEFORE BLS. A committee can only
		// attest its own period and the next one; anything else is stale
		// or alien and cannot be judged by signature at all.
		return nil, fmt.Errorf("%w: signature period %d is neither the store's %d nor %d",
			ErrPeriodGate, sigPeriod, s.StorePeriod, s.StorePeriod+1)
	}
}

// ProcessUpdate runs the full gate order of the Rust processor
// (store.rs:314-455): period gate, attested-period precondition when no
// next committee is held, shape gate, BLS, finality branch, execution
// branches for BOTH headers, next-committee branch, then the store merge.
// An update that passes everything but advances nothing still returns
// nil error; whether the finalized header moved is visible in the store.
func (s *Store) ProcessUpdate(u *Update) error {
	sigPeriod := chain.SyncCommitteePeriod(u.SignatureSlot)
	attestedPeriod := chain.SyncCommitteePeriod(u.Attested.Beacon.Slot)

	committee, err := s.committeeFor(sigPeriod)
	if err != nil {
		return err
	}
	// Gate 2 (store.rs:357-370): with no next committee held yet, the
	// attested slot must still be inside the store's period — otherwise
	// its next-committee proof would vouch for a period nobody can check.
	if s.NextCommittee == nil && attestedPeriod != s.StorePeriod {
		return fmt.Errorf("lc: attested period %d while store period is %d and no next committee is held",
			attestedPeriod, s.StorePeriod)
	}
	// Gate 3: both headers' branch geometry must match the ATTESTED
	// slot's fork (headers_in_attested_forks_shape).
	geom := s.fork.geomAtSlot(u.Attested.Beacon.Slot)
	if !shapeOk(u.Attested, u.Finalized, geom, len(u.FinalityBranch), len(u.NextBranch)) {
		return fmt.Errorf("lc: update branch geometry (%d/%d) does not match fork geometry (%d/%d) at the attested slot",
			len(u.NextBranch), len(u.FinalityBranch), geom.NextLen, geom.FinalizedLen)
	}
	// Gate 4: BLS under the signature slot's fork domain; the verifier
	// derives domain and signing root from the attested BEACON header
	// itself (verify.rs:36 parity).
	if err := VerifySyncAggregate(committee, u.Aggregate, u.Attested.Beacon,
		s.fork.VersionForSignatureSlot(u.SignatureSlot), s.consensus.GenesisValidatorsRoot); err != nil {
		return err
	}
	// Gate 5: the finalized header must live in the attested state.
	if !verifyMerkleBranch(u.Finalized.Beacon.Root(), u.FinalityBranch, geom.FinalizedGindex, u.Attested.Beacon.StateRoot) {
		return errors.New("lc: finality branch does not verify")
	}
	// Gate 6: execution payload branches, each header against its OWN
	// body root (store.rs verify_execution_branch_at:611-636).
	if !verifyMerkleBranch(u.Attested.Exec, u.Attested.Branch, geom.ExecGindex, u.Attested.Beacon.BodyRoot) {
		return errors.New("lc: attested execution branch does not verify")
	}
	if !verifyMerkleBranch(u.Finalized.Exec, u.Finalized.Branch, geom.ExecGindex, u.Finalized.Beacon.BodyRoot) {
		return errors.New("lc: finalized execution branch does not verify")
	}
	// Gate 7 (store.rs:420-443): the next committee is verified and
	// adopted ONLY when the store holds none — an update never overwrites
	// a held next committee, and no contradiction check exists.
	if s.NextCommittee == nil {
		if !verifyMerkleBranch(u.NextCommittee.Root(), u.NextBranch, geom.NextGindex, u.Attested.Beacon.StateRoot) {
			return errors.New("lc: next-committee branch does not verify")
		}
		s.NextCommittee = u.NextCommittee
	}

	// Merge (store.rs:445-452): finalize, tip the optimistic head only if
	// this update's SIGNATURE slot beats the one that set it (#658), then
	// rotate once if the FINALIZED slot crossed a period.
	oldFinalized := s.Finalized.Slot
	if u.Finalized.Beacon.Slot > oldFinalized {
		s.Finalized, s.FinalizedExec, s.finalizedLC = u.Finalized.Beacon, u.Finalized.Exec, u.Finalized
	}
	if u.SignatureSlot > s.optimisticSigSlot {
		s.Optimistic, s.OptimisticExec, s.optimisticSigSlot = u.Attested.Beacon, u.Attested.Exec, u.SignatureSlot
	}
	s.applyNextWhenPeriodChanges(s.Finalized.Slot)
	return nil
}

// applyNextWhenPeriodChanges promotes the held next committee once the
// finalized slot lies in a period past the store's own — ONE period per
// call (store.rs apply_next_when_period_changes). Compared with
// StorePeriod, not with the previous finalized slot's period: in catch-up
// ForceRotateIfPastPeriod may already have rotated into the period this
// update finalizes, and a second rotation would put the store a period
// ahead of its finalized header (#737). Without a force-rotation
// StorePeriod is the previous finalized slot's period, so the verdict is
// the old crossing rule's.
func (s *Store) applyNextWhenPeriodChanges(newFinalized uint64) {
	if s.NextCommittee == nil {
		return
	}
	if chain.SyncCommitteePeriod(newFinalized) > s.StorePeriod {
		s.CurrentCommittee = s.NextCommittee
		s.NextCommittee = nil
		s.StorePeriod++
	}
}

// FinalityOutcome mirrors store.rs FinalityOutcome. Rejected is the zero
// value on purpose (PR #769 review): an error return that forgets to say
// otherwise then reports Rejected, not a false Advanced. Advanced means
// the update VERIFIED AND moved the store — finalized OR optimistic
// (store.rs:546-557); finality advances once per epoch while the
// attested header moves every slot, so counting only finalized moves
// would read a perfectly current server as Stale 31 times in 32, and
// the 3b poll (which marks a peer proven only on Advanced, sync.rs:3958-
// 3988) would inherit that inversion.
type FinalityOutcome int

const (
	Rejected FinalityOutcome = iota
	Advanced
	Stale
)

// ProcessFinalityUpdate is apply_finality_update (store.rs:545-557) over
// process_finality_update (store.rs:472-534): period gate, shape gate
// for BOTH headers against the attested fork, BLS, finality branch,
// execution branches — then the merge, which includes the period-crossing
// rotation the earlier draft omitted (without it, a finality update into
// period P+1 strands StorePeriod at P and the store only moves again via
// ForceRotateIfPastPeriod).
func (s *Store) ProcessFinalityUpdate(u *FinalityUpdate) (FinalityOutcome, error) {
	sigPeriod := chain.SyncCommitteePeriod(u.SignatureSlot)
	committee, err := s.committeeFor(sigPeriod)
	if err != nil {
		return Rejected, err
	}
	geom := s.fork.geomAtSlot(u.Attested.Beacon.Slot)
	if !finalityShapeOk(u.Attested, u.Finalized, geom, len(u.FinalityBranch)) {
		return Rejected, fmt.Errorf("lc: finality update shape (branch %d) does not match fork geometry (%d) at the attested slot",
			len(u.FinalityBranch), geom.FinalizedLen)
	}
	if err := VerifySyncAggregate(committee, u.Aggregate, u.Attested.Beacon,
		s.fork.VersionForSignatureSlot(u.SignatureSlot), s.consensus.GenesisValidatorsRoot); err != nil {
		return Rejected, err
	}
	if !verifyMerkleBranch(u.Finalized.Beacon.Root(), u.FinalityBranch, geom.FinalizedGindex, u.Attested.Beacon.StateRoot) {
		return Rejected, errors.New("lc: finality branch does not verify")
	}
	if !verifyMerkleBranch(u.Attested.Exec, u.Attested.Branch, geom.ExecGindex, u.Attested.Beacon.BodyRoot) {
		return Rejected, errors.New("lc: attested execution branch does not verify")
	}
	if !verifyMerkleBranch(u.Finalized.Exec, u.Finalized.Branch, geom.ExecGindex, u.Finalized.Beacon.BodyRoot) {
		return Rejected, errors.New("lc: finalized execution branch does not verify")
	}

	// Merge (store.rs:528-533): update_finalized, update_optimistic under
	// its own signature-slot guard, apply_next_when_period_changes — then
	// the outcome is decided by comparing store slots before/after, NOT
	// by the update's own numbers.
	//
	// NOTE on u.SignatureSlot here and in ProcessUpdate: it is only ever
	// used UNAUTHENTICATED, to SELECT the committee period (the gate) and
	// the signing fork domain (Gate 4) — the BLS signature itself is
	// verified against the ATTESTED beacon header (VerifySyncAggregate's
	// signing root), not against the signature slot. So the three-way
	// ordering the spec's validate_light_client_update implies between
	// signature_slot, attested.slot and finalized.slot, and the
	// signature_slot ≤ wall-slot bound, are NOT enforced here — they
	// would bind the signature to signature_slot, which the ported
	// signature scheme does not do. The practical consequence is bounded
	// (a peer cannot forge the finalized header either way — it is
	// Merkle-checked into the attested state, which is what the
	// committee signed): it is a stale-update-rejection sharp edge, not
	// a forgery path. This is deliberately IDENTICAL to the Rust twin
	// (store.rs notes the same) and the Java engine, so a fix is a
	// three-way coordinated change, not a Go-side patch — tracked as
	// issue #774, not silently diverged here (PR #773 review).
	oldFinalized, oldOptSig := s.Finalized.Slot, s.optimisticSigSlot
	if u.Finalized.Beacon.Slot > s.Finalized.Slot {
		s.Finalized, s.FinalizedExec, s.finalizedLC = u.Finalized.Beacon, u.Finalized.Exec, u.Finalized
	}
	if u.SignatureSlot > s.optimisticSigSlot {
		s.Optimistic, s.OptimisticExec, s.optimisticSigSlot = u.Attested.Beacon, u.Attested.Exec, u.SignatureSlot
	}
	s.applyNextWhenPeriodChanges(s.Finalized.Slot)
	if s.Finalized.Slot > oldFinalized || s.optimisticSigSlot > oldOptSig {
		return Advanced, nil
	}
	return Stale, nil
}

// ForceRotateIfPastPeriod is the catch-up rotation (store.rs:112-121):
// when the wall clock has left the store's period and no update rotated
// it, promote the held next committee — a liveness path, not a trust
// path (the next committee was proven when it arrived).
func (s *Store) ForceRotateIfPastPeriod(slotEstimate uint64) bool {
	if s.NextCommittee == nil {
		return false
	}
	if chain.SyncCommitteePeriod(slotEstimate) > s.StorePeriod {
		s.CurrentCommittee = s.NextCommittee
		s.NextCommittee = nil
		s.StorePeriod++ // ONE period per call, as the Rust twin
		return true
	}
	return false
}
