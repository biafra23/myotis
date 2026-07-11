//! EIP-2124 fork-id constants, PINNED per network — twin of the pinned
//! values in `networking.NetworkConfig` (Java).
//!
//! The reference pins the 4-byte fork hash and refreshes it out-of-band
//! rather than computing the rolling `CRC32(genesisHash ‖ fork blocks/times…)`
//! (docs/reimplementation README §6). Same here; implementing the real CRC32
//! chain with `forkNext` is a recorded forward-compat TODO for the phase that
//! adds fork-constant rewrite tooling (07-el-implementation-plan.md decision
//! #5). Remote peers validate OUR fork id and disconnect on mismatch, so
//! these must track the live networks.
//!
//! Cross-language pin: the conformance corpus records these bytes and the
//! Java side asserts them against `NetworkConfig` — if either side drifts,
//! a golden test fails.

/// Mainnet fork-id hash (post-BPO2 / Fusaka head), forkNext = 0.
pub const MAINNET_FORK_ID_HASH: [u8; 4] = [0x07, 0xc9, 0x46, 0x2e];

/// Gnosis fork-id hash (Fulu/Osaka head), forkNext = 0.
pub const GNOSIS_FORK_ID_HASH: [u8; 4] = [0xcf, 0xca, 0x38, 0x7c];

/// Sepolia fork-id hash (post-BPO2 / Fusaka head), forkNext = 0.
pub const SEPOLIA_FORK_ID_HASH: [u8; 4] = [0x26, 0x89, 0x56, 0xb6];

/// `forkNext` is 0 on all three networks (no scheduled fork announced).
pub const FORK_NEXT: u64 = 0;

/// Pinned fork-id hash by canonical network name.
pub fn fork_id_hash(network: &str) -> Option<[u8; 4]> {
    match network {
        "mainnet" => Some(MAINNET_FORK_ID_HASH),
        "gnosis" => Some(GNOSIS_FORK_ID_HASH),
        "sepolia" => Some(SEPOLIA_FORK_ID_HASH),
        _ => None,
    }
}
