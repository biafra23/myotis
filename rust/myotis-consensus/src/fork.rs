//! Fork schedule — the per-network, append-only list of `(activation epoch,
//! fork version)` pairs that selects the signing domain for every sync-committee
//! signature. Rust twin of the Java `ForkSchedule` (`:core`).
//!
//! # Why a schedule and not one version
//!
//! The spec's `validate_light_client_update` verifies a sync aggregate under
//! `compute_fork_version(compute_epoch_at_slot(max(signature_slot, 1) - 1))`
//! — the fork active when the signature was produced, NOT the network's
//! current fork. A store walking updates across a fork boundary therefore
//! needs both versions: a single configured value verifies one side of the
//! boundary and rejects every update on the other, which stalls sync at every
//! consensus fork on every install (#295). Before this type both engines held
//! one fixed version and were correct only because every checkpoint pin
//! happened to sit after its network's newest fork.
//!
//! # Shippable ahead of activation
//!
//! The schedule may (and should) carry the NEXT scheduled fork before it
//! activates: verification is keyed by the update's own slot, and the
//! digest-side "active" version is read with [`ForkSchedule::version_at_epoch`]
//! at the wall-clock epoch (`ChainConfig::current_fork_version`), so a future
//! entry changes nothing until its epoch arrives. Only the blob-parameter
//! (EIP-7892) digest fold remains a single configured value.
//!
//! # Trust posture
//!
//! Consensus-critical configuration with the same standing as the genesis
//! validators root: embedded, never fetched at runtime. The beacon API's
//! `/eth/v1/config/fork_schedule` exposes the same data and is the reference
//! for the pinned lists in `myotis-net`'s `ChainConfig` constructors.

use crate::spec;

/// Ordered fork schedule for one chain. Constructed once per network from
/// compile-time constants; invalid geometry is a build error surfacing, so the
/// constructor panics rather than returning a `Result` nobody would handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    /// Slots per epoch for THIS chain (32 on the mainnet preset, 16 on
    /// gnosis). Needed to map a signature slot to the epoch the schedule is
    /// keyed by. Bundled here — rather than passed alongside every lookup —
    /// so a schedule can never be read with another chain's geometry.
    slots_per_epoch: u64,
    /// `(activation_epoch, fork_version)`, strictly ascending by epoch, first
    /// entry at epoch 0 (the genesis fork).
    forks: Vec<(u64, [u8; 4])>,
}

impl ForkSchedule {
    /// Build a schedule. PANICS (in every build) on: zero `slots_per_epoch`, an
    /// empty list, a first entry not at epoch 0, or epochs that are not
    /// strictly ascending. Each of those would silently select a wrong signing
    /// domain for some slot — the "accepted and silently ignored" failure
    /// CLAUDE.md forbids for anything that can change the answer.
    pub fn new(slots_per_epoch: u64, forks: &[(u64, [u8; 4])]) -> Self {
        assert!(slots_per_epoch > 0, "fork schedule: slots_per_epoch must be non-zero");
        assert!(!forks.is_empty(), "fork schedule: at least the genesis fork is required");
        assert_eq!(forks[0].0, 0, "fork schedule: the first entry must activate at epoch 0");
        for w in forks.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "fork schedule: activation epochs must be strictly ascending ({} then {})",
                w[0].0,
                w[1].0
            );
        }
        Self { slots_per_epoch, forks: forks.to_vec() }
    }

    /// One version for every slot — a schedule with no boundary. For tests and
    /// for callers replaying a corpus recorded under a single version. The
    /// slot geometry is immaterial without a boundary; the mainnet preset is
    /// used so the value is at least a real one.
    pub fn single(version: [u8; 4]) -> Self {
        Self::new(spec::SLOTS_PER_EPOCH, &[(0, version)])
    }

    pub fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    /// The pinned `(activation_epoch, fork_version)` list, ascending.
    pub fn forks(&self) -> &[(u64, [u8; 4])] {
        &self.forks
    }

    /// The newest scheduled fork's version — possibly not yet active. Callers
    /// that need the fork active NOW (the digest, Status) must use
    /// [`version_at_epoch`](Self::version_at_epoch) with the wall-clock epoch;
    /// this is for pins and diagnostics.
    pub fn newest(&self) -> [u8; 4] {
        self.forks[self.forks.len() - 1].1
    }

    /// `compute_fork_version(epoch)`: the version of the latest fork whose
    /// activation epoch is `<= epoch`. Total — the genesis entry covers epoch 0.
    pub fn version_at_epoch(&self, epoch: u64) -> [u8; 4] {
        self.forks[self.index_at_epoch(epoch)].1
    }

    /// The version of the fork BEFORE the one active at `epoch`, or `None`
    /// when that is the genesis fork — the discv5 prior-digest fallback input.
    pub fn prior_version_at_epoch(&self, epoch: u64) -> Option<[u8; 4]> {
        let i = self.index_at_epoch(epoch);
        (i >= 1).then(|| self.forks[i - 1].1)
    }

    fn index_at_epoch(&self, epoch: u64) -> usize {
        // Ascending list; the last entry with activation <= epoch wins.
        let mut idx = 0;
        for (i, (activation, _)) in self.forks.iter().enumerate() {
            if *activation <= epoch {
                idx = i;
            } else {
                break;
            }
        }
        idx
    }

    /// The fork version a sync aggregate signed at `signature_slot` must be
    /// verified under — spec `validate_light_client_update`:
    /// `compute_fork_version(compute_epoch_at_slot(max(signature_slot, 1) - 1))`.
    ///
    /// The `- 1` is not a detail: the aggregate is over the block of the
    /// PREVIOUS slot, so a signature at the first slot of a fork's activation
    /// epoch still uses the old version, and only the next slot switches.
    pub fn version_for_signature_slot(&self, signature_slot: u64) -> [u8; 4] {
        // slots_per_epoch is non-zero by construction (see `new`).
        self.version_at_epoch((signature_slot.max(1) - 1) / self.slots_per_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 4] = [0x05, 0, 0, 0];
    const B: [u8; 4] = [0x06, 0, 0, 0];
    const C: [u8; 4] = [0x07, 0, 0, 0];

    fn three() -> ForkSchedule {
        ForkSchedule::new(32, &[(0, A), (10, B), (20, C)])
    }

    #[test]
    fn version_at_epoch_picks_latest_activated() {
        let s = three();
        assert_eq!(s.version_at_epoch(0), A);
        assert_eq!(s.version_at_epoch(9), A);
        assert_eq!(s.version_at_epoch(10), B);
        assert_eq!(s.version_at_epoch(19), B);
        assert_eq!(s.version_at_epoch(20), C);
        assert_eq!(s.version_at_epoch(u64::MAX), C);
    }

    /// The spec's `max(signature_slot, 1) - 1`: the FIRST slot of the
    /// activation epoch still signs under the old fork.
    #[test]
    fn signature_slot_boundary_is_off_by_one_per_spec() {
        let s = three();
        assert_eq!(s.version_for_signature_slot(0), A); // max(0,1)-1 = 0
        assert_eq!(s.version_for_signature_slot(1), A);
        assert_eq!(s.version_for_signature_slot(320), A); // slot 319 -> epoch 9
        assert_eq!(s.version_for_signature_slot(321), B); // slot 320 -> epoch 10
        assert_eq!(s.version_for_signature_slot(640), B); // slot 639 -> epoch 19
        assert_eq!(s.version_for_signature_slot(641), C); // slot 640 -> epoch 20
    }

    /// Gnosis geometry: 16-slot epochs move the same epoch boundary to a
    /// different slot — the schedule must carry its own slots_per_epoch.
    #[test]
    fn slots_per_epoch_is_part_of_the_schedule() {
        let s = ForkSchedule::new(16, &[(0, A), (10, B)]);
        assert_eq!(s.version_for_signature_slot(160), A); // slot 159 -> epoch 9
        assert_eq!(s.version_for_signature_slot(161), B); // slot 160 -> epoch 10
    }

    #[test]
    fn prior_version_is_the_one_before_the_active_fork() {
        let s = three();
        assert_eq!(s.prior_version_at_epoch(0), None);
        assert_eq!(s.prior_version_at_epoch(9), None);
        assert_eq!(s.prior_version_at_epoch(10), Some(A));
        assert_eq!(s.prior_version_at_epoch(20), Some(B));
        assert_eq!(s.prior_version_at_epoch(u64::MAX), Some(B));
    }

    #[test]
    fn newest_and_single() {
        assert_eq!(three().newest(), C);
        let one = ForkSchedule::single(A);
        assert_eq!(one.newest(), A);
        assert_eq!(one.prior_version_at_epoch(u64::MAX), None);
        assert_eq!(one.version_for_signature_slot(u64::MAX), A);
    }

    #[test]
    #[should_panic(expected = "epoch 0")]
    fn rejects_schedule_not_starting_at_genesis() {
        ForkSchedule::new(32, &[(5, A)]);
    }

    #[test]
    #[should_panic(expected = "strictly ascending")]
    fn rejects_unsorted_schedule() {
        ForkSchedule::new(32, &[(0, A), (20, B), (10, C)]);
    }

    #[test]
    #[should_panic(expected = "strictly ascending")]
    fn rejects_duplicate_epochs() {
        ForkSchedule::new(32, &[(0, A), (10, B), (10, C)]);
    }

    #[test]
    #[should_panic(expected = "genesis fork")]
    fn rejects_empty_schedule() {
        ForkSchedule::new(32, &[]);
    }

    #[test]
    #[should_panic(expected = "slots_per_epoch")]
    fn rejects_zero_slots_per_epoch() {
        ForkSchedule::new(0, &[(0, A)]);
    }
}
