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

/// Sepolia fork-activation timestamps (go-ethereum `SepoliaChainConfig`).
/// Sepolia launched with London active and merged in mid-2022, so anything the
/// beacon-anchored engine can serve is far past Shanghai; below Shanghai fails
/// closed as too old (no archive, and older sepolia forks aren't modelled).
pub const SEPOLIA_SHANGHAI_TIME: u64 = 1_677_557_088;
/// Sepolia Cancun activation timestamp.
pub const SEPOLIA_CANCUN_TIME: u64 = 1_706_655_072;
/// Sepolia Prague activation timestamp.
pub const SEPOLIA_PRAGUE_TIME: u64 = 1_741_159_776;

/// The revm `SpecId` a `(chain_id, block_number, timestamp)` activates:
/// [`EvmError::UnsupportedChain`] for a chain with no table here (e.g. Gnosis
/// until its slice lands), [`EvmError::ForkTooOld`] below each chain's floor.
///
/// KNOWN GAPS vs the Java `EvmFactory` (cross-engine follow-ups):
/// * both tables cap at PRAGUE even though mainnet and sepolia have since
///   activated Osaka/Fusaka — Java stops at Prague too; add OSAKA to both.
/// * Java applies the MAINNET timestamps to every chain, so a historical sepolia
///   call in a window where the two schedules disagree (e.g. sepolia's
///   [Prague, mainnet-Prague) gap) picks a different spec there — this table is
///   the more correct side, and head-of-chain calls agree on both.
pub fn spec_for(chain_id: u64, block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
    match chain_id {
        1 => mainnet_spec(block_number, timestamp),
        11_155_111 => sepolia_spec(block_number, timestamp),
        other => Err(EvmError::UnsupportedChain { chain_id: other }),
    }
}

/// The mainnet cascade: pre-merge forks by block number, post-merge by timestamp
/// (timestamp checked first — a post-merge block is always past the merge block).
fn mainnet_spec(block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
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
    fn unknown_chain_is_unsupported() {
        assert!(matches!(
            spec_for(100, 20_000_000, SEPOLIA_PRAGUE_TIME),
            Err(EvmError::UnsupportedChain { chain_id: 100 })
        ));
    }

    #[test]
    fn timestamp_takes_precedence_over_block_for_post_merge() {
        // A block at the merge height but with a Cancun timestamp is Cancun.
        assert_eq!(spec_for(1, PARIS_BLOCK, CANCUN_TIME).unwrap(), SpecId::CANCUN);
    }
}
