package lc

import (
	"errors"
	"fmt"

	"github.com/biafra23/myotis/go/internal/chain"
)

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

	// finalizedLC keeps the finalized LightClientHeader so the payload's
	// own state_root field stays reachable (FinalizedStateRoot).
	finalizedLC *lcHeader
}

// NewFromBootstrap verifies the bootstrap's committee proof against the
// header's state root (which the caller has pinned: the bootstrap was
// fetched BY the checkpoint root and its header hash must chain to the
// checkpoint's period) and adopts its committee. Like the Rust
// processor, the branch check is mandatory before anything is stored.
func NewFromBootstrap(b *Bootstrap, fork *ForkSchedule, c *chain.Consensus) (*Store, error) {
	geom := fork.geomAtSlot(b.Header.Beacon.Slot)
	if uint64(len(b.CommitteeBranch)) != geom.SyncLen {
		return nil, fmt.Errorf("lc: bootstrap committee branch has %d elements, fork geometry wants %d",
			len(b.CommitteeBranch), geom.SyncLen)
	}
	if !verifyMerkleBranch(b.SyncCommittee.Root(), b.CommitteeBranch, geom.SyncGindex, b.Header.Beacon.StateRoot) {
		return nil, errors.New("lc: bootstrap committee branch does not verify against the header state root")
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

func (s *Store) committeeFor(sigPeriod uint64) (*SyncCommittee, error) {
	switch sigPeriod {
	case s.StorePeriod:
		return s.CurrentCommittee, nil
	case s.StorePeriod + 1:
		if s.NextCommittee == nil {
			return nil, fmt.Errorf("lc: update signed for period %d but the store holds no next committee", sigPeriod)
		}
		return s.NextCommittee, nil
	default:
		// #423: the period gate runs BEFORE BLS. A committee can only
		// attest its own period and the next one; anything else is stale
		// or alien and cannot be judged by signature at all.
		return nil, fmt.Errorf("lc: signature period %d is neither the store's %d nor %d",
			sigPeriod, s.StorePeriod, s.StorePeriod+1)
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
	if uint64(len(u.NextBranch)) != geom.NextLen || uint64(len(u.FinalityBranch)) != geom.FinalizedLen {
		return fmt.Errorf("lc: update branch geometry (%d/%d) does not match fork geometry (%d/%d) at the attested slot",
			len(u.NextBranch), len(u.FinalityBranch), geom.NextLen, geom.FinalizedLen)
	}
	// Gate 4: BLS under the signature slot's fork domain.
	domain := ComputeDomain(DomainSyncCommittee, s.fork.VersionForSignatureSlot(u.SignatureSlot), s.consensus.GenesisValidatorsRoot)
	// The signed object is the BEACON header root (the Rust processor
	// passes attested_header.beacon into verify_sync_aggregate).
	signingRoot := SigningRoot(u.Attested.Beacon.Root(), domain)
	if err := VerifySyncAggregate(committee, u.Aggregate, signingRoot, s.consensus.GenesisValidatorsRoot,
		s.fork.VersionForSignatureSlot(u.SignatureSlot)); err != nil {
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

	// Merge (store.rs:445-452): finalize, tip the optimistic head by the
	// update's SIGNATURE slot (#658 — the slot the committee actually
	// signed), then rotate once if the FINALIZED slot crossed a period.
	oldFinalized := s.Finalized.Slot
	if u.Finalized.Beacon.Slot > oldFinalized {
		s.Finalized, s.FinalizedExec, s.finalizedLC = u.Finalized.Beacon, u.Finalized.Exec, u.Finalized
	}
	if u.SignatureSlot > s.Optimistic.Slot {
		s.Optimistic, s.OptimisticExec = u.Attested.Beacon, u.Attested.Exec
	}
	s.applyNextWhenPeriodChanges(oldFinalized, s.Finalized.Slot)
	return nil
}

// applyNextWhenPeriodChanges promotes the held next committee when the
// finalized slot crossed into a new period — ONE period per crossing
// (store.rs apply_next_when_period_changes).
func (s *Store) applyNextWhenPeriodChanges(oldFinalized, newFinalized uint64) {
	if s.NextCommittee == nil {
		return
	}
	if chain.SyncCommitteePeriod(newFinalized) > chain.SyncCommitteePeriod(oldFinalized) {
		s.CurrentCommittee = s.NextCommittee
		s.NextCommittee = nil
		s.StorePeriod++
	}
}

// FinalityOutcome distinguishes an advancing finality update from a
// verified-but-stale one (store.rs FinalityOutcome): only Advanced moves
// the anchor.
type FinalityOutcome int

const (
	Advanced FinalityOutcome = iota
	Stale
)

func (s *Store) ProcessFinalityUpdate(u *FinalityUpdate) (FinalityOutcome, error) {
	sigPeriod := chain.SyncCommitteePeriod(u.SignatureSlot)
	committee, err := s.committeeFor(sigPeriod)
	if err != nil {
		return Stale, err
	}
	geom := s.fork.geomAtSlot(u.Attested.Beacon.Slot)
	if uint64(len(u.FinalityBranch)) != geom.FinalizedLen {
		return Stale, fmt.Errorf("lc: finality branch length %d, fork geometry wants %d",
			len(u.FinalityBranch), geom.FinalizedLen)
	}
	forkVersion := s.fork.VersionForSignatureSlot(u.SignatureSlot)
	domain := ComputeDomain(DomainSyncCommittee, forkVersion, s.consensus.GenesisValidatorsRoot)
	// The signed object is the BEACON header root (the Rust processor
	// passes attested_header.beacon into verify_sync_aggregate).
	signingRoot := SigningRoot(u.Attested.Beacon.Root(), domain)
	if err := VerifySyncAggregate(committee, u.Aggregate, signingRoot, s.consensus.GenesisValidatorsRoot, forkVersion); err != nil {
		return Stale, err
	}
	if !verifyMerkleBranch(u.Finalized.Beacon.Root(), u.FinalityBranch, geom.FinalizedGindex, u.Attested.Beacon.StateRoot) {
		return Stale, errors.New("lc: finality branch does not verify")
	}
	if !verifyMerkleBranch(u.Attested.Exec, u.Attested.Branch, geom.ExecGindex, u.Attested.Beacon.BodyRoot) {
		return Stale, errors.New("lc: attested execution branch does not verify")
	}
	if !verifyMerkleBranch(u.Finalized.Exec, u.Finalized.Branch, geom.ExecGindex, u.Finalized.Beacon.BodyRoot) {
		return Stale, errors.New("lc: finalized execution branch does not verify")
	}
	if u.Finalized.Beacon.Slot > s.Finalized.Slot {
		s.Finalized, s.FinalizedExec, s.finalizedLC = u.Finalized.Beacon, u.Finalized.Exec, u.Finalized
		s.Optimistic, s.OptimisticExec = u.Attested.Beacon, u.Attested.Exec
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
