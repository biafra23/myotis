//! Chain constants + gindex helpers — Rust twin of the Java `BeaconChainSpec`.

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
pub const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 =
    SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD; // 8192
pub const SYNC_COMMITTEE_SIZE: usize = 512;

pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;
pub const EXECUTION_PAYLOAD_DEPTH: usize = 4;

const CURRENT_SYNC_COMMITTEE_FIELD_INDEX: u64 = 22;
const NEXT_SYNC_COMMITTEE_FIELD_INDEX: u64 = 23;
const FINALIZED_CHECKPOINT_FIELD_INDEX: u64 = 20;

// Depths reaching these helpers come from decode-validated branch lengths (4..=7),
// but a shift-overflow panic on a wild depth would be a DoS foothold — guard and
// return gindex 0, which can never satisfy verify_merkle_branch (safe rejection).

/// Generalized index of current_sync_committee for a fork-dependent branch depth.
pub fn sync_committee_gindex(branch_depth: usize) -> u64 {
    if branch_depth >= 64 {
        return 0;
    }
    (1u64 << branch_depth) + CURRENT_SYNC_COMMITTEE_FIELD_INDEX
}

/// Generalized index of next_sync_committee for a fork-dependent branch depth.
pub fn next_sync_committee_gindex(branch_depth: usize) -> u64 {
    if branch_depth >= 64 {
        return 0;
    }
    (1u64 << branch_depth) + NEXT_SYNC_COMMITTEE_FIELD_INDEX
}

/// Generalized index of finalized_checkpoint.root — the branch depth includes the
/// extra level into the Checkpoint container (root = field 1).
pub fn finalized_root_gindex(branch_depth: usize) -> u64 {
    if branch_depth == 0 || branch_depth >= 64 {
        return 0;
    }
    let checkpoint_gindex = (1u64 << (branch_depth - 1)) + FINALIZED_CHECKPOINT_FIELD_INDEX;
    checkpoint_gindex * 2 + 1
}

/// Mainnet-preset period math. Prefer [`compute_sync_committee_period_with`]
/// wherever the chain is known — see its note.
pub fn compute_sync_committee_period(slot: u64) -> u64 {
    slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
}

/// The sync-committee period a slot falls in, for a chain whose period length
/// is `slots_per_period`.
///
/// # Why this is parameterised
///
/// The constants above are MAINNET's preset. Gnosis pairs 16-slot epochs with
/// 512 epochs per period — it reaches the same 8192, so the constant is right by
/// coincidence and its derivation is false for that chain. Nimbus makes the same
/// distinction at compile time: a mainnet-preset binary refuses to load gnosis
/// outright rather than mis-reading it.
///
/// This matters more here than in a cache. `LightClientStore` uses the period to
/// select the sync committee an update's signature is verified against, so a
/// wrong period would check a signature against the wrong committee. The
/// equivalent bug in `rust/roost` only mis-keyed an archive record.
///
/// Note the wallet must be TOLD this, never ask a node for it: it is a
/// verification input, and asking the thing being verified is not a check.
///
/// PANICS on a zero period length, in every build. `debug_assert!` plus
/// `.max(1)` would have silently treated an invalid configuration as one slot
/// per period in release — selecting a different committee than the caller
/// asked for, which is exactly the "accepted and silently ignored" failure
/// CLAUDE.md forbids for anything that can change the answer. A zero here is a
/// build-time configuration error, not a runtime condition to paper over.
pub fn compute_sync_committee_period_with(slot: u64, slots_per_period: u64) -> u64 {
    assert!(slots_per_period > 0, "slots_per_period must be non-zero");
    slot / slots_per_period
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same expectations the Java BeaconChainSpec constants encode.
    #[test]
    fn gindices_match_java_spec_constants() {
        assert_eq!(sync_committee_gindex(5), 54);
        assert_eq!(next_sync_committee_gindex(5), 55);
        assert_eq!(finalized_root_gindex(6), 105);
        // Electra depths
        assert_eq!(sync_committee_gindex(6), 86);
        assert_eq!(next_sync_committee_gindex(6), 87);
        assert_eq!(finalized_root_gindex(7), 169);
    }
}
