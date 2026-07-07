//! The CL→EL execution anchor (EL-A7), twin of the Java
//! `consensus.BeaconSyncState` — the SOLE trust hand-off from the beacon light
//! client to the execution layer (docs/reimplementation/04 §3, README §3).
//!
//! Holds the beacon-verified execution anchor: the finalized execution
//! `{block_number, block_hash, state_root, slot}`, the optimistic (attested)
//! equivalent, and a bounded window of BLS-attested `(slot, state_root)` pairs
//! for the `stateRootMatch` fast path. It is fed by the CL sync loop
//! (`sync.rs`, wired in EL-A7b) and read by the verified query ladder
//! ([`super::verify`]). Every field here is BLS-sync-committee-verified before
//! it lands — it is the only thing the EL trusts.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Window cap (twin of `BeaconSyncState.MAX_KNOWN_ROOTS`), matching
/// `MAX_HEADER_CHAIN_GAP` so the fast-path window and the header-chain bound
/// cover the same span.
pub const MAX_KNOWN_ROOTS: usize = 8192;

/// A BLS-attested `(slot, state_root)` pair in the fast-path window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlottedStateRoot {
    pub slot: u64,
    pub state_root: [u8; 32],
    pub bls_verified: bool,
}

/// The finalized execution anchor: the block number + its beacon-verified
/// execution state root, read together so a query never pairs a number with a
/// root from a different finalized payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedExecution {
    pub block_number: u64,
    pub state_root: [u8; 32],
}

#[derive(Default)]
struct Inner {
    finalized_slot: u64,
    execution_state_root: Option<[u8; 32]>,
    execution_block_number: u64,
    execution_block_hash: Option<[u8; 32]>,
    optimistic_slot: u64,
    optimistic_block_number: u64,
    optimistic_block_hash: Option<[u8; 32]>,
    optimistic_state_root: Option<[u8; 32]>,
    known_roots: VecDeque<SlottedStateRoot>,
}

/// Shared, mutable execution anchor. Cloneable handle over one `Mutex` — the
/// CL loop writes, the EL query path reads (both off their own threads).
pub struct ExecAnchor {
    inner: Mutex<Inner>,
}

impl Default for ExecAnchor {
    fn default() -> Self {
        ExecAnchor {
            inner: Mutex::new(Inner::default()),
        }
    }
}

impl ExecAnchor {
    pub fn new() -> ExecAnchor {
        ExecAnchor::default()
    }

    /// Record a finalized update (on every beacon finality step). Also appends
    /// the finalized `(slot, state_root)` to the fast-path window as
    /// BLS-verified.
    pub fn update_finalized(
        &self,
        finalized_slot: u64,
        execution_state_root: [u8; 32],
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
    ) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        inner.finalized_slot = finalized_slot;
        inner.execution_state_root = Some(execution_state_root);
        inner.execution_block_number = execution_block_number;
        inner.execution_block_hash = Some(execution_block_hash);
        push_root(&mut inner.known_roots, finalized_slot, execution_state_root, true);
    }

    /// Record the optimistic (attested) execution head (~1-2 slots behind wall
    /// clock, vs ~2 epochs for finalized). Also appends to the window.
    pub fn update_optimistic(
        &self,
        optimistic_slot: u64,
        optimistic_block_number: u64,
        optimistic_block_hash: [u8; 32],
        optimistic_state_root: [u8; 32],
    ) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        inner.optimistic_slot = optimistic_slot;
        inner.optimistic_block_number = optimistic_block_number;
        inner.optimistic_block_hash = Some(optimistic_block_hash);
        inner.optimistic_state_root = Some(optimistic_state_root);
        push_root(&mut inner.known_roots, optimistic_slot, optimistic_state_root, true);
    }

    /// Record a standalone BLS-attested `(slot, state_root)` into the window
    /// (the catch-up path records 40-80 per invocation).
    pub fn record_state_root(&self, slot: u64, state_root: [u8; 32], bls_verified: bool) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        push_root(&mut inner.known_roots, slot, state_root, bls_verified);
    }

    /// SYNCED once a finalized execution state root has landed — DERIVED, not a
    /// separate flag (twin of `BeaconSyncState.isSynced() == executionStateRoot
    /// != null`). This keeps `is_synced()` and `finalized_execution()` from ever
    /// disagreeing, which the verify ladder relies on.
    pub fn is_synced(&self) -> bool {
        self.inner
            .lock()
            .expect("anchor mutex")
            .execution_state_root
            .is_some()
    }

    /// The finalized execution `(block_number, state_root)` read atomically.
    /// `None` until the first finalized update lands.
    pub fn finalized_execution(&self) -> Option<FinalizedExecution> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner.execution_state_root.map(|state_root| FinalizedExecution {
            block_number: inner.execution_block_number,
            state_root,
        })
    }

    pub fn finalized_slot(&self) -> u64 {
        self.inner.lock().expect("anchor mutex").finalized_slot
    }

    /// The optimistic head block hash, for anchoring a header-chain walk at the
    /// beacon-attested block (`None` until an optimistic update lands).
    pub fn optimistic_block_hash(&self) -> Option<[u8; 32]> {
        self.inner.lock().expect("anchor mutex").optimistic_block_hash
    }

    pub fn optimistic_block_number(&self) -> u64 {
        self.inner.lock().expect("anchor mutex").optimistic_block_number
    }

    /// The `stateRootMatch` fast-path lookup: is `state_root` a root the beacon
    /// client already recorded? Searches NEWEST-first (twin of
    /// `findStateRoot`'s `descendingIterator`) so the freshest/best match wins.
    pub fn find_state_root(&self, state_root: &[u8; 32]) -> Option<SlottedStateRoot> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner
            .known_roots
            .iter()
            .rev()
            .find(|r| &r.state_root == state_root)
            .cloned()
    }

    pub fn known_root_count(&self) -> usize {
        self.inner.lock().expect("anchor mutex").known_roots.len()
    }
}

/// Append `(slot, state_root)`, then cap the window to `MAX_KNOWN_ROOTS`
/// (oldest dropped). Dedup keys on `(slot, state_root)` and only ever UPGRADES
/// `bls_verified` (unverified → verified), never downgrades — exact twin of
/// `BeaconSyncState.recordStateRoot` (a root at two slots stays two entries).
fn push_root(roots: &mut VecDeque<SlottedStateRoot>, slot: u64, state_root: [u8; 32], bls_verified: bool) {
    if let Some(pos) = roots
        .iter()
        .position(|r| r.slot == slot && r.state_root == state_root)
    {
        if bls_verified && !roots[pos].bls_verified {
            roots.remove(pos); // re-add as verified below
        } else {
            return; // already present with same or better verification
        }
    }
    roots.push_back(SlottedStateRoot {
        slot,
        state_root,
        bls_verified,
    });
    while roots.len() > MAX_KNOWN_ROOTS {
        roots.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(n: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = n;
        r
    }

    #[test]
    fn finalized_and_optimistic_updates() {
        let anchor = ExecAnchor::new();
        assert_eq!(anchor.finalized_execution(), None);
        assert!(!anchor.is_synced());

        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1));
        assert!(anchor.is_synced()); // derived: a finalized exec root landed
        let fin = anchor.finalized_execution().unwrap();
        assert_eq!(fin.block_number, 21_000_000);
        assert_eq!(fin.state_root, root(1));
        assert_eq!(anchor.finalized_slot(), 100);

        anchor.update_optimistic(102, 21_000_005, root(0xf2), root(2));
        assert_eq!(anchor.optimistic_block_hash(), Some(root(0xf2)));
        assert_eq!(anchor.optimistic_block_number(), 21_000_005);

        // Both roots are in the fast-path window.
        assert!(anchor.find_state_root(&root(1)).is_some());
        assert_eq!(anchor.find_state_root(&root(2)).unwrap().slot, 102);
        assert!(anchor.find_state_root(&root(9)).is_none());
    }

    #[test]
    fn window_dedup_is_slot_root_keyed_and_upgrade_only() {
        let anchor = ExecAnchor::new();
        // Same root at TWO slots → two entries (Java keeps both).
        anchor.record_state_root(1, root(5), true);
        anchor.record_state_root(2, root(5), true);
        assert_eq!(anchor.known_root_count(), 2);
        // find_state_root searches newest-first → the slot-2 entry.
        assert_eq!(anchor.find_state_root(&root(5)).unwrap().slot, 2);

        // Same (slot, root): unverified first, then verified → UPGRADE in place.
        anchor.record_state_root(3, root(6), false);
        anchor.record_state_root(3, root(6), true);
        assert_eq!(anchor.known_root_count(), 3);
        assert!(anchor.find_state_root(&root(6)).unwrap().bls_verified);
        // A subsequent unverified record must NOT downgrade it.
        anchor.record_state_root(3, root(6), false);
        assert!(anchor.find_state_root(&root(6)).unwrap().bls_verified);
        assert_eq!(anchor.known_root_count(), 3);
    }

    #[test]
    fn window_caps_at_max() {
        let anchor = ExecAnchor::new();
        for i in 0..(MAX_KNOWN_ROOTS as u64 + 10) {
            let mut r = [0u8; 32];
            r[..8].copy_from_slice(&i.to_be_bytes());
            anchor.record_state_root(i, r, true);
        }
        assert_eq!(anchor.known_root_count(), MAX_KNOWN_ROOTS);
    }
}
