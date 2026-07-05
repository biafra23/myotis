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

/// Generalized index of current_sync_committee for a fork-dependent branch depth.
pub fn sync_committee_gindex(branch_depth: usize) -> u64 {
    (1u64 << branch_depth) + CURRENT_SYNC_COMMITTEE_FIELD_INDEX
}

/// Generalized index of next_sync_committee for a fork-dependent branch depth.
pub fn next_sync_committee_gindex(branch_depth: usize) -> u64 {
    (1u64 << branch_depth) + NEXT_SYNC_COMMITTEE_FIELD_INDEX
}

/// Generalized index of finalized_checkpoint.root — the branch depth includes the
/// extra level into the Checkpoint container (root = field 1).
pub fn finalized_root_gindex(branch_depth: usize) -> u64 {
    let checkpoint_gindex = (1u64 << (branch_depth - 1)) + FINALIZED_CHECKPOINT_FIELD_INDEX;
    checkpoint_gindex * 2 + 1
}

pub fn compute_sync_committee_period(slot: u64) -> u64 {
    slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
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
