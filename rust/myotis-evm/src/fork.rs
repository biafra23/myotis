//! The mainnet fork table: `(block_number, timestamp) → revm SpecId`.
//!
//! Mirrors the Java `EvmFactory` cascade verbatim. Pre-merge forks activate by
//! block number, post-merge forks by timestamp, so the cascade checks timestamp
//! first (a post-merge block is always at/after the merge block) and falls back
//! to block number. Everything below London throws — the engine has no local
//! archive and does not model pre-London fork rules.
//!
//! revm applies the correct precompile set per `SpecId` automatically, so the
//! Java "Shanghai keeps Istanbul precompiles" nuance needs no special handling
//! here: revm's `SpecId::SHANGHAI` predates the Cancun KZG point-evaluation
//! precompile (0x0A), exactly as intended.

use revm::primitives::hardfork::SpecId;

use crate::error::EvmError;

/// London activation block (EIP-1559 base fee).
pub const LONDON_BLOCK: u64 = 12_965_000;
/// The Merge (Paris) activation block.
pub const PARIS_BLOCK: u64 = 15_537_394;
/// Shanghai activation timestamp (withdrawals, PUSH0).
pub const SHANGHAI_TIME: u64 = 1_681_338_455;
/// Cancun activation timestamp (blobs, transient storage, KZG precompile).
pub const CANCUN_TIME: u64 = 1_710_338_135;
/// Prague activation timestamp (EIP-7702, …).
pub const PRAGUE_TIME: u64 = 1_746_612_311;

/// Mainnet Osaka (Fusaka's EL fork: CLZ, P256VERIFY, ModExp repricing) —
/// go-ethereum MainnetChainConfig.OsakaTime (2025-12-03).
pub const OSAKA_TIME: u64 = 1_764_798_551;

/// Sepolia fork-activation timestamps (go-ethereum `SepoliaChainConfig`).
/// Sepolia launched with London active and merged in mid-2022, so anything the
/// beacon-anchored engine can serve is far past Shanghai; below Shanghai fails
/// closed as too old (no archive, and older sepolia forks aren't modelled).
pub const SEPOLIA_SHANGHAI_TIME: u64 = 1_677_557_088;
/// Sepolia Cancun activation timestamp.
pub const SEPOLIA_CANCUN_TIME: u64 = 1_706_655_072;
/// Sepolia Prague activation timestamp.
pub const SEPOLIA_PRAGUE_TIME: u64 = 1_741_159_776;
/// Sepolia Osaka — go-ethereum SepoliaChainConfig.OsakaTime (2025-10-14).
pub const SEPOLIA_OSAKA_TIME: u64 = 1_760_427_360;

/// The revm `SpecId` a `(chain_id, block_number, timestamp)` activates:
/// [`EvmError::UnsupportedChain`] for a chain with no table here,
/// [`EvmError::ForkTooOld`] below each chain's floor.
///
/// The Java `EvmFactory` mirrors this table PER CHAIN (its per-chain cascades
/// and the ChainAwareForkTest are the twins of this function and its tests) —
/// keep the two in lockstep whenever a fork constant is added.
pub fn spec_for(chain_id: u64, block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
    match chain_id {
        1 => mainnet_spec(block_number, timestamp),
        11_155_111 => sepolia_spec(block_number, timestamp),
        100 => gnosis_spec(block_number, timestamp),
        other => Err(EvmError::UnsupportedChain { chain_id: other }),
    }
}

/// The mainnet cascade: pre-merge forks by block number, post-merge by timestamp
/// (timestamp checked first — a post-merge block is always past the merge block).
fn mainnet_spec(block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
    if timestamp >= OSAKA_TIME {
        return Ok(SpecId::OSAKA);
    }
    if timestamp >= PRAGUE_TIME {
        Ok(SpecId::PRAGUE)
    } else if timestamp >= CANCUN_TIME {
        Ok(SpecId::CANCUN)
    } else if timestamp >= SHANGHAI_TIME {
        Ok(SpecId::SHANGHAI)
    } else if block_number >= PARIS_BLOCK {
        Ok(SpecId::MERGE)
    } else if block_number >= LONDON_BLOCK {
        Ok(SpecId::LONDON)
    } else {
        Err(EvmError::ForkTooOld {
            block_number,
            timestamp,
        })
    }
}

/// The sepolia cascade — all timestamp-gated (sepolia merged before Shanghai, and
/// nothing pre-Shanghai is servable by a beacon-anchored engine).
fn sepolia_spec(block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
    if timestamp >= SEPOLIA_OSAKA_TIME {
        return Ok(SpecId::OSAKA);
    }
    if timestamp >= SEPOLIA_PRAGUE_TIME {
        Ok(SpecId::PRAGUE)
    } else if timestamp >= SEPOLIA_CANCUN_TIME {
        Ok(SpecId::CANCUN)
    } else if timestamp >= SEPOLIA_SHANGHAI_TIME {
        Ok(SpecId::SHANGHAI)
    } else {
        Err(EvmError::ForkTooOld {
            block_number,
            timestamp,
        })
    }
}

/// Gnosis Shanghai activation timestamp (nethermind gnosis.json
/// eip3855TransitionTimestamp 0x64c8edbc = 2023-08-01). Gnosis merged before
/// Shanghai, so anything a beacon-anchored engine can serve is at/after it.
pub const GNOSIS_SHANGHAI_TIME: u64 = 1_690_889_660;
/// Gnosis Cancun activation timestamp (0x65ef4dbc = 2024-03-11).
pub const GNOSIS_CANCUN_TIME: u64 = 1_710_181_820;
/// Gnosis Prague activation timestamp (0x68122dbc = 2025-04-30).
pub const GNOSIS_PRAGUE_TIME: u64 = 1_746_021_820;
/// Gnosis Osaka activation timestamp (0x69de2dbc = 2026-04-14, nethermind
/// gnosis.json — hex-pinned like the other gnosis fork times).
pub const GNOSIS_OSAKA_TIME: u64 = 1_776_168_380;

/// The gnosis cascade — all timestamp-gated (gnosis merged before Shanghai).
fn gnosis_spec(block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
    if timestamp >= GNOSIS_OSAKA_TIME {
        return Ok(SpecId::OSAKA);
    }
    if timestamp >= GNOSIS_PRAGUE_TIME {
        Ok(SpecId::PRAGUE)
    } else if timestamp >= GNOSIS_CANCUN_TIME {
        Ok(SpecId::CANCUN)
    } else if timestamp >= GNOSIS_SHANGHAI_TIME {
        Ok(SpecId::SHANGHAI)
    } else {
        Err(EvmError::ForkTooOld {
            block_number,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_london_is_rejected() {
        assert!(matches!(
            spec_for(1, LONDON_BLOCK - 1, 0),
            Err(EvmError::ForkTooOld { .. })
        ));
        assert!(matches!(spec_for(1, 0, 0), Err(EvmError::ForkTooOld { .. })));
    }

    #[test]
    fn each_boundary_maps_to_its_spec() {
        // London/Paris are block-gated; timestamp below Shanghai so it doesn't win.
        assert_eq!(spec_for(1, LONDON_BLOCK, 0).unwrap(), SpecId::LONDON);
        assert_eq!(spec_for(1, PARIS_BLOCK - 1, 0).unwrap(), SpecId::LONDON);
        assert_eq!(spec_for(1, PARIS_BLOCK, 0).unwrap(), SpecId::MERGE);
        // Post-merge forks are timestamp-gated (block number well past Paris).
        assert_eq!(
            spec_for(1, 20_000_000, SHANGHAI_TIME).unwrap(),
            SpecId::SHANGHAI
        );
        assert_eq!(
            spec_for(1, 20_000_000, CANCUN_TIME - 1).unwrap(),
            SpecId::SHANGHAI
        );
        assert_eq!(spec_for(1, 20_000_000, CANCUN_TIME).unwrap(), SpecId::CANCUN);
        assert_eq!(
            spec_for(1, 20_000_000, PRAGUE_TIME - 1).unwrap(),
            SpecId::CANCUN
        );
        assert_eq!(spec_for(1, 20_000_000, PRAGUE_TIME).unwrap(), SpecId::PRAGUE);
    }

    #[test]
    fn sepolia_boundaries_map_to_their_specs() {
        let s = 11_155_111u64;
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_PRAGUE_TIME).unwrap(), SpecId::PRAGUE);
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_PRAGUE_TIME - 1).unwrap(), SpecId::CANCUN);
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_CANCUN_TIME).unwrap(), SpecId::CANCUN);
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_CANCUN_TIME - 1).unwrap(), SpecId::SHANGHAI);
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_SHANGHAI_TIME).unwrap(), SpecId::SHANGHAI);
        assert!(matches!(
            spec_for(s, 9_000_000, SEPOLIA_SHANGHAI_TIME - 1),
            Err(EvmError::ForkTooOld { .. })
        ));
    }

    #[test]
    fn osaka_boundaries_map_on_every_chain() {
        // Mainnet
        assert_eq!(spec_for(1, 21_000_000, OSAKA_TIME).unwrap(), SpecId::OSAKA);
        assert_eq!(spec_for(1, 21_000_000, OSAKA_TIME - 1).unwrap(), SpecId::PRAGUE);
        // Sepolia
        let s = 11_155_111u64;
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_OSAKA_TIME).unwrap(), SpecId::OSAKA);
        assert_eq!(spec_for(s, 9_000_000, SEPOLIA_OSAKA_TIME - 1).unwrap(), SpecId::PRAGUE);
        // Gnosis
        let g = 100u64;
        assert_eq!(spec_for(g, 30_000_000, GNOSIS_OSAKA_TIME).unwrap(), SpecId::OSAKA);
        assert_eq!(spec_for(g, 30_000_000, GNOSIS_OSAKA_TIME - 1).unwrap(), SpecId::PRAGUE);
    }

    #[test]
    fn osaka_wires_p256verify_and_prague_does_not() {
        // Twin of the Java OsakaBoundaryTest's registry assertions: don't just
        // trust revm's wiring across future bumps — pin that the OSAKA
        // precompile set serves 0x…0100 (EIP-7951) and PRAGUE's does not.
        use revm::precompile::{PrecompileSpecId, Precompiles};
        let mut p256 = [0u8; 20];
        p256[18] = 0x01;
        let addr = revm::primitives::Address::from(p256);
        assert!(
            Precompiles::new(PrecompileSpecId::OSAKA).get(&addr).is_some(),
            "P256VERIFY must be in the OSAKA set"
        );
        assert!(
            Precompiles::new(PrecompileSpecId::PRAGUE).get(&addr).is_none(),
            "P256VERIFY is Osaka-only"
        );
    }

    #[test]
    fn osaka_times_pin_their_sources() {
        // Cross-BASE pins (hex vs the decimal constants): a transposition typo
        // in either form can't survive both representations — the guard that
        // caught the gnosis decimal-slip bug, now applied to every chain.
        // Sources: go-ethereum MainnetChainConfig / SepoliaChainConfig
        // OsakaTime; nethermind gnosis.json eip*TransitionTimestamps.
        assert_eq!(OSAKA_TIME, 0x6930_b057); // 1_764_798_551, 2025-12-03
        assert_eq!(SEPOLIA_OSAKA_TIME, 0x68ed_fd60); // 1_760_427_360, 2025-10-14
        assert_eq!(GNOSIS_OSAKA_TIME, 0x69de_2dbc); // 1_776_168_380, 2026-04-14
    }

    #[test]
    fn gnosis_fork_times_pin_the_nethermind_hex() {
        // Guards against a decimal-conversion slip: these MUST equal the
        // nethermind gnosis.json hex activation timestamps, not a paraphrase.
        assert_eq!(GNOSIS_SHANGHAI_TIME, 0x64c8_edbc); // 1_690_889_660
        assert_eq!(GNOSIS_CANCUN_TIME, 0x65ef_4dbc); // 1_710_181_820
        assert_eq!(GNOSIS_PRAGUE_TIME, 0x6812_2dbc); // 1_746_021_820
    }

    #[test]
    fn gnosis_boundaries_map_to_their_specs() {
        let g = 100u64;
        assert_eq!(spec_for(g, 30_000_000, GNOSIS_PRAGUE_TIME).unwrap(), SpecId::PRAGUE);
        assert_eq!(spec_for(g, 30_000_000, GNOSIS_PRAGUE_TIME - 1).unwrap(), SpecId::CANCUN);
        assert_eq!(spec_for(g, 30_000_000, GNOSIS_CANCUN_TIME).unwrap(), SpecId::CANCUN);
        assert_eq!(spec_for(g, 30_000_000, GNOSIS_SHANGHAI_TIME).unwrap(), SpecId::SHANGHAI);
        assert!(matches!(
            spec_for(g, 30_000_000, GNOSIS_SHANGHAI_TIME - 1),
            Err(EvmError::ForkTooOld { .. })
        ));
    }

    #[test]
    fn unknown_chain_is_unsupported() {
        assert!(matches!(
            spec_for(137, 20_000_000, SEPOLIA_PRAGUE_TIME),
            Err(EvmError::UnsupportedChain { chain_id: 137 })
        ));
    }

    #[test]
    fn timestamp_takes_precedence_over_block_for_post_merge() {
        // A block at the merge height but with a Cancun timestamp is Cancun.
        assert_eq!(spec_for(1, PARIS_BLOCK, CANCUN_TIME).unwrap(), SpecId::CANCUN);
    }
}
