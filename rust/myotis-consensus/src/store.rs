//! Light-client store + processor — Rust twins of the Java `LightClientStore` /
//! `LightClientProcessor`. Wall-clock-free by construction: the one live-loop
//! clock input (the slot estimate behind `force_rotate_if_past_period`) is a
//! plain parameter, exactly as the conformance corpus records it.

use crate::spec;
use crate::ssz::{self, Root};
use crate::types::{
    LightClientFinalityUpdate, LightClientHeader, LightClientUpdate, SyncCommittee,
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
    pub fn new(slots_per_period: u64) -> Self {
        Self {
            slots_per_period: if slots_per_period == 0 {
                spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD
            } else {
                slots_per_period
            },
            ..Self::default()
        }
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
/// the duplicate-signature fast path, which is a perf memo, not a verdict change:
/// re-verifying a duplicate reaches the same `true`).
pub struct LightClientProcessor {
    pub store: LightClientStore,
    fork_version: [u8; 4],
    genesis_validators_root: Root,
}

impl LightClientProcessor {
    pub fn new(store: LightClientStore, fork_version: [u8; 4], genesis_validators_root: Root) -> Self {
        Self { store, fork_version, genesis_validators_root }
    }

    /// `is_valid_light_client_header` (Capella+): the execution payload header is
    /// bound to the beacon body solely through this branch — the sync-committee
    /// signature does NOT cover it.
    pub fn verify_execution_branch(header: &LightClientHeader) -> bool {
        ssz::verify_merkle_branch(
            &header.execution.hash_tree_root(),
            &header.execution_branch,
            spec::EXECUTION_PAYLOAD_DEPTH,
            spec::EXECUTION_PAYLOAD_GINDEX,
            &header.beacon.body_root,
        )
    }

    pub fn process_update(&mut self, update: &LightClientUpdate) -> bool {
        let Some(committee) = self.store.current_sync_committee() else {
            return false;
        };

        // Applicability gate BEFORE the expensive BLS verify (per spec
        // validate_light_client_update; mirrors the Java gate exactly).
        let store_period = self.store.current_period();
        let sig_period = self.store.period_of(update.signature_slot);
        let have_next = self.store.next_sync_committee().is_some();
        let applicable = if have_next {
            sig_period == store_period || sig_period == store_period + 1
        } else {
            sig_period == store_period
        };
        if !applicable {
            return false;
        }

        if !verify::verify_sync_aggregate(
            &update.sync_aggregate,
            committee,
            &update.attested_header.beacon,
            &self.fork_version,
            &self.genesis_validators_root,
        ) {
            return false;
        }

        // Finality branch: finalizedHeader is finalized in the attested state.
        let depth = update.finality_branch.len();
        if !ssz::verify_merkle_branch(
            &update.finalized_header.beacon.hash_tree_root(),
            &update.finality_branch,
            depth,
            spec::finalized_root_gindex(depth),
            &update.attested_header.beacon.state_root,
        ) {
            return false;
        }

        if !Self::verify_execution_branch(&update.attested_header)
            || !Self::verify_execution_branch(&update.finalized_header)
        {
            return false;
        }

        // Next sync committee: verify + store when we don't already hold one.
        if self.store.next_sync_committee().is_none() {
            let depth = update.next_sync_committee_branch.len();
            if !ssz::verify_merkle_branch(
                &update.next_sync_committee.hash_tree_root(),
                &update.next_sync_committee_branch,
                depth,
                spec::next_sync_committee_gindex(depth),
                &update.attested_header.beacon.state_root,
            ) {
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

    pub fn process_finality_update(&mut self, update: &LightClientFinalityUpdate) -> bool {
        let Some(committee) = self.store.current_sync_committee() else {
            return false;
        };

        if !verify::verify_sync_aggregate(
            &update.sync_aggregate,
            committee,
            &update.attested_header.beacon,
            &self.fork_version,
            &self.genesis_validators_root,
        ) {
            return false;
        }

        let depth = update.finality_branch.len();
        if !ssz::verify_merkle_branch(
            &update.finalized_header.beacon.hash_tree_root(),
            &update.finality_branch,
            depth,
            spec::finalized_root_gindex(depth),
            &update.attested_header.beacon.state_root,
        ) {
            return false;
        }

        if !Self::verify_execution_branch(&update.attested_header)
            || !Self::verify_execution_branch(&update.finalized_header)
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
