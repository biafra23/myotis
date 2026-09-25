//! Light-client store + processor — Rust twins of the Java `LightClientStore` /
//! `LightClientProcessor`. Wall-clock-free by construction: the one live-loop
//! clock input (the slot estimate behind `force_rotate_if_past_period`) is a
//! plain parameter, exactly as the conformance corpus records it.

use crate::fork::{ForkSchedule, LcFork};
use crate::spec;
use crate::ssz::{self, Root};
use crate::types::{
    HeaderExecution, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientUpdate, SyncCommittee,
};
use crate::verify;

#[derive(Default)]
pub struct LightClientStore {
    finalized_header: Option<LightClientHeader>,
    optimistic_header: Option<LightClientHeader>,
    current_sync_committee: Option<SyncCommittee>,
    next_sync_committee: Option<SyncCommittee>,
    finalized_slot: u64,
    optimistic_slot: u64,
    current_sync_committee_period: u64,
    /// Slots per sync-committee period FOR THIS CHAIN. Mainnet and sepolia pair
    /// 32-slot epochs with 256 epochs; gnosis pairs 16 with 512. Both reach
    /// 8192, so the old global constant was right by coincidence — see
    /// `spec::compute_sync_committee_period_with`.
    slots_per_period: u64,
}

impl LightClientStore {
    /// `slots_per_period` comes from the chain config, not from a peer: it
    /// selects the sync committee a signature is verified against.
    ///
    /// REFUSES zero rather than defaulting to the mainnet preset. Silently
    /// substituting one geometry for another would verify updates against a
    /// different committee than the caller configured, and the result would look
    /// entirely plausible — the failure CLAUDE.md singles out for any parameter
    /// that can change the answer. Zero only arises from a mis-built config, so
    /// failing at construction beats a wrong committee at runtime.
    pub fn new(slots_per_period: u64) -> Self {
        assert!(slots_per_period > 0, "slots_per_period must be non-zero");
        Self { slots_per_period, ..Self::default() }
    }

    /// Mainnet-preset store, for tests and for callers that genuinely mean it.
    pub fn new_mainnet_preset() -> Self {
        Self::new(spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD)
    }

    pub fn slots_per_period(&self) -> u64 {
        if self.slots_per_period == 0 {
            spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD
        } else {
            self.slots_per_period
        }
    }

    fn period_of(&self, slot: u64) -> u64 {
        spec::compute_sync_committee_period_with(slot, self.slots_per_period())
    }

    pub fn initialize(&mut self, header: LightClientHeader, committee: SyncCommittee) {
        self.finalized_slot = header.beacon.slot;
        self.optimistic_slot = header.beacon.slot;
        self.current_sync_committee_period =
            self.period_of(self.finalized_slot);
        self.finalized_header = Some(header.clone());
        self.optimistic_header = Some(header);
        self.current_sync_committee = Some(committee);
        self.next_sync_committee = None;
    }

    pub fn is_initialized(&self) -> bool {
        self.current_sync_committee.is_some()
    }

    pub fn update_finalized(&mut self, header: &LightClientHeader, slot: u64) {
        if slot > self.finalized_slot {
            self.finalized_header = Some(header.clone());
            self.finalized_slot = slot;
        }
    }

    pub fn update_optimistic(&mut self, header: &LightClientHeader, slot: u64) {
        if slot > self.optimistic_slot {
            self.optimistic_header = Some(header.clone());
            self.optimistic_slot = slot;
        }
    }

    pub fn update_next_sync_committee(&mut self, next: SyncCommittee) {
        self.next_sync_committee = Some(next);
    }

    pub fn apply_next_when_period_changes(&mut self, old_finalized_slot: u64, new_finalized_slot: u64) {
        if self.next_sync_committee.is_none() {
            return;
        }
        let old_period = self.period_of(old_finalized_slot);
        let new_period = self.period_of(new_finalized_slot);
        if new_period > old_period {
            self.current_sync_committee = self.next_sync_committee.take();
            self.current_sync_committee_period += 1;
        }
    }

    /// Mirrors `LightClientStore.forceRotateIfPastPeriod` (the live loop's — and the
    /// conformance corpus's — recorded-slot-estimate rotation between updates).
    pub fn force_rotate_if_past_period(&mut self, current_slot_estimate: u64) {
        if self.next_sync_committee.is_none() {
            return;
        }
        let wall_period = self.period_of(current_slot_estimate);
        if wall_period > self.current_sync_committee_period {
            self.current_sync_committee = self.next_sync_committee.take();
            self.current_sync_committee_period += 1;
        }
    }

    pub fn finalized_header(&self) -> Option<&LightClientHeader> {
        self.finalized_header.as_ref()
    }
    pub fn optimistic_header(&self) -> Option<&LightClientHeader> {
        self.optimistic_header.as_ref()
    }
    pub fn current_sync_committee(&self) -> Option<&SyncCommittee> {
        self.current_sync_committee.as_ref()
    }
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.next_sync_committee.as_ref()
    }
    pub fn finalized_slot(&self) -> u64 {
        self.finalized_slot
    }
    pub fn optimistic_slot(&self) -> u64 {
        self.optimistic_slot
    }
    pub fn current_period(&self) -> u64 {
        self.current_sync_committee_period
    }

    /// The persistable verified state, or `None` until the store is initialized
    /// (mirrors the Java `LightClientStore.snapshot()`). The optimistic header
    /// falls back to the finalized one so a just-bootstrapped store snapshots.
    pub fn snapshot(&self) -> Option<crate::snapshot::StoreSnapshot> {
        let finalized = self.finalized_header.as_ref()?;
        let current = self.current_sync_committee.as_ref()?;
        Some(crate::snapshot::StoreSnapshot {
            finalized_header: finalized.clone(),
            optimistic_header: self.optimistic_header.as_ref().unwrap_or(finalized).clone(),
            current_sync_committee: current.clone(),
            next_sync_committee: self.next_sync_committee.clone(),
            finalized_slot: self.finalized_slot,
            optimistic_slot: self.optimistic_slot,
            current_sync_committee_period: self.current_sync_committee_period,
        })
    }

    /// Restore a previously persisted (BLS-verified when written) state —
    /// the resume path that replaces bootstrap-from-checkpoint. Mirrors the
    /// Java `LightClientStore.restore(snapshot)`.
    pub fn restore(&mut self, s: crate::snapshot::StoreSnapshot) {
        self.finalized_header = Some(s.finalized_header);
        self.optimistic_header = Some(s.optimistic_header);
        self.current_sync_committee = Some(s.current_sync_committee);
        self.next_sync_committee = s.next_sync_committee;
        self.finalized_slot = s.finalized_slot;
        self.optimistic_slot = s.optimistic_slot;
        self.current_sync_committee_period = s.current_sync_committee_period;
    }
}

/// Processes updates against a store — Rust twin of `LightClientProcessor` (minus
/// the duplicate-signature fast path, which is a perf memo keyed on the applied
/// signature AND its slot, behind the period gate — not a verdict change:
/// re-verifying a duplicate reaches the same `true`, and a relabelled slot is
/// not a duplicate).
pub struct LightClientProcessor {
    pub store: LightClientStore,
    /// Per-slot signing-domain selector. Every update is verified under the
    /// fork active at its `signature_slot` (spec `validate_light_client_update`),
    /// so a store can walk updates across a fork boundary — a single fixed
    /// version rejects everything signed on the other side of it (#295).
    fork_schedule: ForkSchedule,
    genesis_validators_root: Root,
}

impl LightClientProcessor {
    pub fn new(
        store: LightClientStore,
        fork_schedule: ForkSchedule,
        genesis_validators_root: Root,
    ) -> Self {
        Self { store, fork_schedule, genesis_validators_root }
    }

    /// `is_valid_light_client_header` for a PRE-GLOAS-shaped header at a
    /// pre-Gloas slot (Capella..Fulu) — kept for callers that hold no fork
    /// schedule and only ever see that shape. A Gloas-shaped header is refused
    /// outright rather than checked under a guessed slot fork, so a call site
    /// that should have moved to [`Self::verify_header`] fails loudly.
    pub fn verify_execution_branch(header: &LightClientHeader) -> bool {
        header.shape() == LcFork::PreGloas && verify_execution_branch_at(header, LcFork::PreGloas)
    }

    /// `is_valid_light_client_header` against this chain's schedule: the proof is
    /// selected by the fork of the header's OWN slot.
    pub fn verify_header(&self, header: &LightClientHeader) -> bool {
        verify_execution_branch_at(
            header,
            self.fork_schedule.lc_fork_at_slot(header.beacon.slot),
        )
    }

    /// The fork whose wire format and proof indices an object with this attested
    /// (or bootstrap header) slot uses.
    pub fn lc_fork_at_slot(&self, slot: u64) -> LcFork {
        self.fork_schedule.lc_fork_at_slot(slot)
    }

    /// The checks a bootstrap must pass besides the checkpoint pin (which the
    /// caller owns — it chose the root): its shape matches its slot's fork, the
    /// current sync committee is in the header's state at that fork's gindex, and
    /// the execution branch binds the header's execution data to its body.
    pub fn verify_bootstrap(
        &self,
        bootstrap: &LightClientBootstrap,
    ) -> Result<(), BootstrapReject> {
        let fork = self.lc_fork_at_slot(bootstrap.header.beacon.slot);
        if bootstrap.header.shape() != fork {
            return Err(BootstrapReject::ShapeNotItsForks);
        }
        let (depth, gindex) = match fork {
            LcFork::Gloas => (
                spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
                spec::CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS,
            ),
            LcFork::PreGloas => {
                let depth = bootstrap.current_sync_committee_branch.len();
                (depth, spec::sync_committee_gindex(depth))
            }
        };
        if !ssz::verify_merkle_branch(
            &bootstrap.current_sync_committee.hash_tree_root(),
            &bootstrap.current_sync_committee_branch,
            depth,
            gindex,
            &bootstrap.header.beacon.state_root,
        ) {
            return Err(BootstrapReject::SyncCommitteeBranch);
        }
        if !self.verify_header(&bootstrap.header) {
            return Err(BootstrapReject::ExecutionBranch);
        }
        Ok(())
    }

    /// Cheap structural gate for an update, BEFORE any BLS work: every header in
    /// it must be in the shape of its ATTESTED slot's fork (a Gloas-format update
    /// carries even a pre-Gloas finalized header in the Gloas shape), since that
    /// fork also picks the state-proof indices below. A mismatch is a misrouted
    /// or forged object, never a genuine one.
    fn update_shape_ok(&self, attested: &LightClientHeader, finalized: &LightClientHeader) -> bool {
        let fork = self.lc_fork_at_slot(attested.beacon.slot);
        attested.shape() == fork && finalized.shape() == fork
    }

    /// Finality branch against the attested state root, at the attested slot's
    /// fork's gindex: fixed for Gloas (a progressive `BeaconState` — not
    /// derivable from the depth), depth-derived before it (6 → 105, 7 → 169).
    fn verify_finality_branch(
        &self,
        attested: &LightClientHeader,
        finalized: &LightClientHeader,
        branch: &[Root],
    ) -> bool {
        let (depth, gindex) = match self.lc_fork_at_slot(attested.beacon.slot) {
            LcFork::Gloas => (
                spec::GLOAS_FINALITY_BRANCH_LEN,
                spec::FINALIZED_ROOT_GINDEX_GLOAS,
            ),
            LcFork::PreGloas => (branch.len(), spec::finalized_root_gindex(branch.len())),
        };
        ssz::verify_merkle_branch(
            &finalized.beacon.hash_tree_root(),
            branch,
            depth,
            gindex,
            &attested.beacon.state_root,
        )
    }

    pub fn process_update(&mut self, update: &LightClientUpdate) -> bool {
        if self.store.current_sync_committee().is_none() {
            tracing::debug!("update rejected: store has no current sync committee");
            return false;
        }

        // Applicability gate BEFORE the expensive BLS verify (per spec
        // validate_light_client_update; mirrors the Java gate exactly).
        let store_period = self.store.current_period();
        let sig_period = self.store.period_of(update.signature_slot);
        // The aggregate is signed by the committee of signature_slot's PERIOD
        // (spec validate_light_client_update): our current committee for
        // store_period, the held next committee for store_period + 1, nothing
        // for anything else. Selecting the keys IS the gate. Verifying both
        // admitted periods with the current keys rejected genuine
        // next-committee updates before rotation and accepted a
        // current-committee signature whose unsigned signature_slot had been
        // relabelled into the next period (#423).
        let Some(committee) = self.committee_for(sig_period) else {
            tracing::debug!(store_period, sig_period,
                have_next = self.store.next_sync_committee().is_some(),
                signature_slot = update.signature_slot,
                attested_slot = update.attested_header.beacon.slot,
                "update rejected: not applicable to the store's period");
            return false;
        };

        // A store holding no next committee adopts the one this update carries
        // (below): the next committee of the ATTESTED state, i.e. of
        // period(attested) + 1. So only an update attested in the store's own
        // period can supply it (spec validate_light_client_update counts it
        // only when update_attested_period == store_period). The last block of
        // P−1 signed at the first slot of P passes the gate above and verifies,
        // and its genuine next committee is committee(P) — ours: the rotation
        // would install it for P+1, and every P+1 update would then fail BLS.
        // Honest servers send that update without a committee (spec
        // create_light_client_update), which the branch check below would
        // refuse anyway, so this changes no honest verdict. Not required: the
        // spec's apply_light_client_update also wants the FINALIZED header in
        // the store period. This client adopts from the attested state, as the
        // spec's force-update path does, having no best-valid-update timeout:
        // requiring finality would stall catch-up at a period that never
        // finalized. Java twin: LightClientProcessor.processUpdate.
        if self.store.next_sync_committee().is_none() {
            let attested_period = self.store.period_of(update.attested_header.beacon.slot);
            if attested_period != store_period {
                tracing::debug!(
                    store_period,
                    attested_period,
                    sig_period,
                    attested_slot = update.attested_header.beacon.slot,
                    "update rejected: attested outside the store's period, so its next \
                     committee is not the store's next"
                );
                return false;
            }
        }

        if !self.update_shape_ok(&update.attested_header, &update.finalized_header) {
            tracing::debug!(attested_slot = update.attested_header.beacon.slot,
                attested_shape = ?update.attested_header.shape(),
                finalized_shape = ?update.finalized_header.shape(),
                "update rejected: wire shape is not the attested slot's fork's");
            return false;
        }

        let fork_version = self.fork_schedule.version_for_signature_slot(update.signature_slot);
        if !verify::verify_sync_aggregate(
            &update.sync_aggregate,
            committee,
            &update.attested_header.beacon,
            &fork_version,
            &self.genesis_validators_root,
        ) {
            tracing::debug!(store_period, sig_period, used_next = sig_period != store_period,
                signature_slot = update.signature_slot,
                attested_slot = update.attested_header.beacon.slot,
                participants = update.sync_aggregate.count_participants(),
                fork_version = ?fork_version,
                "update rejected: sync-aggregate BLS verification failed");
            return false;
        }

        // Finality branch: finalizedHeader is finalized in the attested state.
        if !self.verify_finality_branch(
            &update.attested_header,
            &update.finalized_header,
            &update.finality_branch,
        ) {
            tracing::debug!(
                depth = update.finality_branch.len(),
                finalized_slot = update.finalized_header.beacon.slot,
                attested_slot = update.attested_header.beacon.slot,
                "update rejected: finality branch does not verify");
            return false;
        }

        if !self.verify_header(&update.attested_header)
            || !self.verify_header(&update.finalized_header)
        {
            tracing::debug!(
                attested_slot = update.attested_header.beacon.slot,
                finalized_slot = update.finalized_header.beacon.slot,
                "update rejected: execution branch does not verify");
            return false;
        }

        // Next sync committee: verify + store when we don't already hold one.
        if self.store.next_sync_committee().is_none() {
            let (depth, gindex) = match self.lc_fork_at_slot(update.attested_header.beacon.slot) {
                LcFork::Gloas => (
                    spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
                    spec::NEXT_SYNC_COMMITTEE_GINDEX_GLOAS,
                ),
                LcFork::PreGloas => {
                    let depth = update.next_sync_committee_branch.len();
                    (depth, spec::next_sync_committee_gindex(depth))
                }
            };
            if !ssz::verify_merkle_branch(
                &update.next_sync_committee.hash_tree_root(),
                &update.next_sync_committee_branch,
                depth,
                gindex,
                &update.attested_header.beacon.state_root,
            ) {
                tracing::debug!(depth,
                    attested_slot = update.attested_header.beacon.slot,
                    "update rejected: next-sync-committee branch does not verify");
                return false;
            }
            self.store
                .update_next_sync_committee(update.next_sync_committee.clone());
        }

        let old_finalized = self.store.finalized_slot();
        let finalized_slot = update.finalized_header.beacon.slot;
        self.store.update_finalized(&update.finalized_header, finalized_slot);
        self.store.update_optimistic(&update.attested_header, update.signature_slot);
        self.store.apply_next_when_period_changes(old_finalized, finalized_slot);
        true
    }

    /// The committee that signs `sig_period`: the store's current committee
    /// for its own period, the held next committee for the period after,
    /// `None` otherwise (spec validate_light_client_update's applicability +
    /// key selection in one place).
    fn committee_for(&self, sig_period: u64) -> Option<&SyncCommittee> {
        let store_period = self.store.current_period();
        if sig_period == store_period {
            self.store.current_sync_committee()
        } else if sig_period == store_period + 1 {
            self.store.next_sync_committee()
        } else {
            None
        }
    }

    pub fn process_finality_update(&mut self, update: &LightClientFinalityUpdate) -> bool {
        if self.store.current_sync_committee().is_none() {
            return false;
        }
        // Same period rule as process_update. This path had no gate at all and
        // always used the current keys, so with the store at P holding next
        // and a P+1-signed finality update in hand — the hunt path while
        // catch-up is starved, or a local clock lagging the chain — the update
        // was rejected until a catch-up round happened to force-rotate.
        let store_period = self.store.current_period();
        let sig_period = self.store.period_of(update.signature_slot);
        let Some(committee) = self.committee_for(sig_period) else {
            tracing::debug!(store_period, sig_period,
                signature_slot = update.signature_slot,
                "finality update rejected: not applicable to the store's period");
            return false;
        };

        if !self.update_shape_ok(&update.attested_header, &update.finalized_header) {
            tracing::debug!(attested_slot = update.attested_header.beacon.slot,
                attested_shape = ?update.attested_header.shape(),
                finalized_shape = ?update.finalized_header.shape(),
                "finality update rejected: wire shape is not the attested slot's fork's");
            return false;
        }

        let fork_version = self.fork_schedule.version_for_signature_slot(update.signature_slot);
        if !verify::verify_sync_aggregate(
            &update.sync_aggregate,
            committee,
            &update.attested_header.beacon,
            &fork_version,
            &self.genesis_validators_root,
        ) {
            tracing::debug!(store_period, sig_period, used_next = sig_period != store_period,
                signature_slot = update.signature_slot,
                attested_slot = update.attested_header.beacon.slot,
                fork_version = ?fork_version,
                "finality update rejected: sync-aggregate BLS verification failed");
            return false;
        }

        if !self.verify_finality_branch(
            &update.attested_header,
            &update.finalized_header,
            &update.finality_branch,
        ) {
            return false;
        }

        if !self.verify_header(&update.attested_header)
            || !self.verify_header(&update.finalized_header)
        {
            return false;
        }

        let old_finalized = self.store.finalized_slot();
        let finalized_slot = update.finalized_header.beacon.slot;
        self.store.update_finalized(&update.finalized_header, finalized_slot);
        self.store.update_optimistic(&update.attested_header, update.signature_slot);
        self.store.apply_next_when_period_changes(old_finalized, finalized_slot);
        true
    }
}

/// Why [`LightClientProcessor::verify_bootstrap`] refused a bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapReject {
    /// The header's wire shape is not its slot's fork's.
    ShapeNotItsForks,
    /// The current sync committee is not in the header's state.
    SyncCommitteeBranch,
    /// The header's execution data is not bound to its body.
    ExecutionBranch,
}

impl std::fmt::Display for BootstrapReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BootstrapReject::ShapeNotItsForks => "wire shape is not its slot's fork's",
            BootstrapReject::SyncCommitteeBranch => "sync committee branch invalid",
            BootstrapReject::ExecutionBranch => "execution branch invalid",
        })
    }
}

/// `is_valid_light_client_header` for a header whose OWN slot is in `slot_fork`.
///
/// This is the whole binding between the sync-committee-signed beacon header and
/// the execution layer: the signature covers only `beacon`, so without it a peer
/// could pair a genuine signed header with an execution payload or block hash of
/// its choosing, and every state proof downstream would verify against it.
///
/// - Pre-Gloas shape at a pre-Gloas slot: the payload header's root at gindex 25.
/// - Gloas shape at a Gloas slot: the block hash at 2856 — the payload bid's
///   `parent_block_hash`.
/// - Gloas shape at a pre-Gloas slot (a Gloas update's finalized header in the
///   first epochs after the fork): the payload's block hash at 812 (Deneb+),
///   normalized to 11 nodes with zero padding. Capella's 412 is not accepted: no
///   header this client meets is pre-Deneb (every network's checkpoint and every
///   Gloas update's finalized header are far past it), and a Capella header's
///   genuine proof simply fails here — a rejection, never an acceptance.
/// - A pre-Gloas shape at a Gloas slot is never genuine: rejected.
pub fn verify_execution_branch_at(header: &LightClientHeader, slot_fork: LcFork) -> bool {
    let body_root = &header.beacon.body_root;
    match (&header.execution, slot_fork) {
        (HeaderExecution::Payload(payload), LcFork::PreGloas) => ssz::verify_merkle_branch(
            &payload.hash_tree_root(),
            &header.execution_branch,
            spec::EXECUTION_PAYLOAD_DEPTH,
            spec::EXECUTION_PAYLOAD_GINDEX,
            body_root,
        ),
        (HeaderExecution::Payload(_), LcFork::Gloas) => false,
        (HeaderExecution::BlockHash(hash), fork) => {
            let gindex = match fork {
                LcFork::Gloas => spec::EXECUTION_BLOCK_HASH_GINDEX_GLOAS,
                LcFork::PreGloas => spec::EXECUTION_BLOCK_HASH_GINDEX_DENEB,
            };
            header.execution_branch.len() == spec::GLOAS_EXECUTION_BRANCH_LEN
                && ssz::verify_normalized_merkle_branch(
                    hash,
                    &header.execution_branch,
                    gindex,
                    body_root,
                )
        }
    }
}
