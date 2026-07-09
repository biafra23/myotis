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

/// The revm `SpecId` a mainnet `(block_number, timestamp)` activates, or
/// [`EvmError::ForkTooOld`] below London.
pub fn spec_for(block_number: u64, timestamp: u64) -> Result<SpecId, EvmError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_london_is_rejected() {
        assert!(matches!(
            spec_for(LONDON_BLOCK - 1, 0),
            Err(EvmError::ForkTooOld { .. })
        ));
        assert!(matches!(spec_for(0, 0), Err(EvmError::ForkTooOld { .. })));
    }

    #[test]
    fn each_boundary_maps_to_its_spec() {
        // London/Paris are block-gated; timestamp below Shanghai so it doesn't win.
        assert_eq!(spec_for(LONDON_BLOCK, 0).unwrap(), SpecId::LONDON);
        assert_eq!(spec_for(PARIS_BLOCK - 1, 0).unwrap(), SpecId::LONDON);
        assert_eq!(spec_for(PARIS_BLOCK, 0).unwrap(), SpecId::MERGE);
        // Post-merge forks are timestamp-gated (block number well past Paris).
        assert_eq!(
            spec_for(20_000_000, SHANGHAI_TIME).unwrap(),
            SpecId::SHANGHAI
        );
        assert_eq!(
            spec_for(20_000_000, CANCUN_TIME - 1).unwrap(),
            SpecId::SHANGHAI
        );
        assert_eq!(spec_for(20_000_000, CANCUN_TIME).unwrap(), SpecId::CANCUN);
        assert_eq!(
            spec_for(20_000_000, PRAGUE_TIME - 1).unwrap(),
            SpecId::CANCUN
        );
        assert_eq!(spec_for(20_000_000, PRAGUE_TIME).unwrap(), SpecId::PRAGUE);
    }

    #[test]
    fn timestamp_takes_precedence_over_block_for_post_merge() {
        // A block at the merge height but with a Cancun timestamp is Cancun.
        assert_eq!(spec_for(PARIS_BLOCK, CANCUN_TIME).unwrap(), SpecId::CANCUN);
    }
}
