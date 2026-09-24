//! EIP-2124 fork-id constants, PINNED per network — twin of the pinned
//! values in `networking.NetworkConfig` (Java).
//!
//! The reference pins the 4-byte fork hash and refreshes it out-of-band
//! rather than computing the rolling `CRC32(genesisHash ‖ fork blocks/times…)`
//! (docs/reimplementation README §6). Same here: WHAT we announce stays pinned
//! (07-el-implementation-plan.md decision #5). Remote peers validate OUR fork
//! id and disconnect on mismatch, so these must track the live networks.
//!
//! The CRC32 chain arithmetic itself lives here too ([`crc32_update`],
//! [`successor`]) — not to compute our own id, but so the fork watch
//! (`myotis_net::el::fork_watch`, twin of Java `ForkIds`/`ForkWatch`) can prove
//! that a peer's unknown hash is the direct successor of our pin, and recover
//! the activation that produced it. CRC32 resumes from its own checksum, so the
//! hash after a fork follows from the hash before it plus the activation alone.
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

/// Activation values at or above this are unix timestamps, below it block
/// numbers (geth's threshold: the Frontier genesis timestamp). Every fork since
/// Shanghai is timestamp-activated.
pub const TIMESTAMP_THRESHOLD: u64 = 1_438_269_973;

/// IEEE CRC32 table (reflected polynomial 0xEDB88320), built at compile time.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

/// CRC32 of `data` continued from the checksum `crc` (0 = a fresh CRC) — the
/// resumable form `java.util.zip.CRC32` lacks (twin: Java `ForkIds.update`).
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = CRC32_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// The fork hash in effect once a fork activating at `activation` has passed,
/// given the hash `hash` in effect before it (EIP-2124: CRC32 continued over
/// the big-endian uint64 activation value).
pub fn successor(hash: u32, activation: u64) -> u32 {
    crc32_update(hash, &activation.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sepolia's Glamsterdam activation (ethereum/pm#2205: epoch 353024,
    /// 2026-10-06 13:53:36 UTC) and the fork id published with it.
    const SEPOLIA_GLAMSTERDAM: u64 = 1_791_294_816;
    const SEPOLIA_GLAMSTERDAM_FORK_ID: u32 = 0x6c1d_9423;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32_update(0, b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn mainnet_chain_reproduces_the_pinned_fork_id() {
        let genesis: [u8; 32] = [
            0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5,
            0xf5, 0x67, 0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d,
            0xb1, 0xcb, 0x8f, 0xa3,
        ];
        let mut hash = crc32_update(0, &genesis);
        assert_eq!(hash, 0xfc64_ec04, "Frontier fork id");
        // Frontier → BPO2: blocks, then timestamps from Shanghai on
        // (Constantinople+Petersburg share one block and count once).
        #[rustfmt::skip]
        let activations: [u64; 18] = [
            1_150_000, 1_920_000, 2_463_000, 2_675_000, 4_370_000, 7_280_000, 9_069_000,
            9_200_000, 12_244_000, 12_965_000, 13_773_000, 15_050_000,
            1_681_338_455, 1_710_338_135, 1_746_612_311, // Shanghai, Cancun, Prague
            1_764_798_551, 1_765_290_071, 1_767_747_671, // Osaka, BPO1, BPO2
        ];
        for a in activations {
            hash = successor(hash, a);
        }
        assert_eq!(hash, u32::from_be_bytes(MAINNET_FORK_ID_HASH));
    }

    #[test]
    fn sepolia_glamsterdam_is_the_successor_of_our_pin() {
        assert_eq!(
            successor(
                u32::from_be_bytes(SEPOLIA_FORK_ID_HASH),
                SEPOLIA_GLAMSTERDAM
            ),
            SEPOLIA_GLAMSTERDAM_FORK_ID
        );
    }
}
