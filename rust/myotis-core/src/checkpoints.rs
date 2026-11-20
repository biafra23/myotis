//! The bundled checkpoint table: the hash of every 1024th block, a trust anchor (D1).
//!
//! The rule is `.claude/agent/data-sources.md` (Trust, "The bundled checkpoint table"); the
//! design is `docs/ideas/deep-block-verification.md`. Entry `i` is the hash of block
//! `i * 1024`, from genesis up; the table also carries its **top**, the finalized block the
//! build walked down from, which is generally not a multiple of 1024. A block `n` at or below
//! the top is canonical when the headers from `n` up to [`CheckpointTable::anchor_at_or_above`]
//! hash-link to that anchor: at most [`CheckpointTable::K`] headers, one `GetBlockHeaders`.
//!
//! The table is committed as an asset (`rust/myotis-core/checkpoints/`), never produced by a
//! build, and pinned here by its keccak256: [`CheckpointTable::parse`] refuses bytes that do
//! not match, and [`mainnet`] parses the embedded copy against the pin. A running node never
//! writes into it.
//!
//! Why the pin covers every entry and the top: the build linked every header by `parentHash`
//! from the top down to the genesis hash, so all entries lie on one hash chain between those
//! two ends. An entry off that chain would break the walk. The top was cross-checked against
//! a second client, and the running node's gap walk checks it once more (the rule). The pin
//! then proves these are the bytes of that build.
//!
//! Sans-I/O like the rest of this crate: [`mainnet`] reads `include_bytes!` data only.
//! [`CheckpointTable::parse`] hashes the whole table (0.83 MB on mainnet), so a caller
//! parses once and keeps the table; it is `Copy` and borrows the static bytes.

use crate::keccak::keccak256;
use crate::{err, CoreError};
use alloc::format;

/// One table: its entries (32-byte hashes, entry `i` = block `i * K`) and its top.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointTable<'a> {
    entries: &'a [u8],
    top_number: u64,
    top_hash: [u8; 32],
}

/// What a table's build pins in the source: everything [`CheckpointTable::parse`] checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePin {
    /// keccak256 of the whole entries file.
    pub keccak256: [u8; 32],
    /// The number of entries (the file is `entries * 32` bytes).
    pub entries: u64,
    /// The network's genesis hash, which entry 0 must be.
    pub genesis_hash: [u8; 32],
    /// The finalized block the build walked down from.
    pub top_number: u64,
    /// Its hash.
    pub top_hash: [u8; 32],
}

impl<'a> CheckpointTable<'a> {
    /// The table's stride: one hash every 1024 blocks, geth's `GetBlockHeaders` limit, so
    /// every lookup is one request.
    pub const K: u64 = 1024;

    /// Parse `bytes` against `pin`: the keccak256, the length, entry 0 against the genesis
    /// hash, and the top at or above the last entry and below the next one (so the top is
    /// the only anchor above the last entry, and no anchor is more than `K` blocks above
    /// any block it serves).
    pub fn parse(bytes: &'a [u8], pin: &TablePin) -> Result<Self, CoreError> {
        if keccak256(bytes) != pin.keccak256 {
            return err("checkpoint table does not match its pinned keccak256");
        }
        if bytes.len() as u64 != pin.entries.saturating_mul(32) || pin.entries == 0 {
            return err(format!(
                "checkpoint table is {} bytes, the pin says {} entries",
                bytes.len(),
                pin.entries
            ));
        }
        if bytes[..32] != pin.genesis_hash {
            return err("checkpoint table entry 0 is not the genesis hash");
        }
        let last_entry = (pin.entries - 1) * Self::K;
        if pin.top_number < last_entry || pin.top_number >= last_entry + Self::K {
            return err(format!(
                "checkpoint table top {} is not within [{last_entry}, {}) of its last entry",
                pin.top_number,
                last_entry + Self::K
            ));
        }
        if pin.top_number == last_entry && bytes[bytes.len() - 32..] != pin.top_hash {
            return err("checkpoint table top is its last entry but the hashes differ");
        }
        Ok(Self { entries: bytes, top_number: pin.top_number, top_hash: pin.top_hash })
    }

    /// The top: the highest block the table anchors.
    pub fn top(&self) -> (u64, [u8; 32]) {
        (self.top_number, self.top_hash)
    }

    /// The number of entries.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64 / 32
    }

    /// Never true for a parsed table (entry 0 is genesis).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The hash of block `i * K`, if the table holds entry `i`.
    pub fn entry(&self, i: u64) -> Option<[u8; 32]> {
        let start = usize::try_from(i.checked_mul(32)?).ok()?;
        let bytes = self.entries.get(start..start.checked_add(32)?)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Some(out)
    }

    /// The anchor a block `n` verifies against: the first entry at or above `n`, or the top
    /// for a block above the last entry. `None` above the top (today's window from the
    /// attested finalized block serves those). The anchor is at most `K - 1` blocks above
    /// `n`, so the walk `[n ..= anchor]` is at most `K` headers.
    pub fn anchor_at_or_above(&self, n: u64) -> Option<(u64, [u8; 32])> {
        if n > self.top_number {
            return None;
        }
        let i = n.div_ceil(Self::K);
        match self.entry(i) {
            Some(hash) => Some((i * Self::K, hash)),
            None => Some((self.top_number, self.top_hash)),
        }
    }
}

/// The mainnet table's pin. Built 2026-11-20 by eth2swarm's `ethswarm checkpoint-table`
/// from Erigon 3.8.1: every header hashed and linked by `parentHash` down to the genesis
/// hash; the top is the source node's finalized block, cross-checked against Geth 1.17.7
/// (203 entries and the top equal). The sidecar `mainnet-1024.hashes.json` records the same.
pub const MAINNET_PIN: TablePin = TablePin {
    keccak256: hex32("ccf5ad8849bb513d7aef7b7bc732b264e2874c6b6e24cc4880753ceb68cc03d0"),
    entries: 25_838,
    genesis_hash: hex32("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
    top_number: 26_457_537,
    top_hash: hex32("229a7a2185b4a334b8c9e4f94f028974365698f2bc40b7ea418e276da9a485fc"),
};

/// The embedded mainnet table's bytes, as committed.
pub static MAINNET_BYTES: &[u8] = include_bytes!("../checkpoints/mainnet-1024.hashes");

/// The embedded mainnet table, parsed against [`MAINNET_PIN`].
pub fn mainnet() -> Result<CheckpointTable<'static>, CoreError> {
    CheckpointTable::parse(MAINNET_BYTES, &MAINNET_PIN)
}

/// The table for `chain_id`, if one is bundled: mainnet only so far.
pub fn for_chain(chain_id: u64) -> Option<Result<CheckpointTable<'static>, CoreError>> {
    match chain_id {
        1 => Some(mainnet()),
        _ => None,
    }
}

/// A 32-byte hex constant (64 lowercase hex digits, no prefix), at compile time.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "a 32-byte hash is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn mainnet_parses_against_its_pin() {
        let t = mainnet().expect("the committed table matches its pin");
        assert_eq!(t.len(), 25_838);
        assert_eq!(t.top(), (MAINNET_PIN.top_number, MAINNET_PIN.top_hash));
        assert_eq!(t.entry(0), Some(MAINNET_PIN.genesis_hash));
        assert!(for_chain(1).is_some());
        assert!(for_chain(100).is_none());
    }

    /// The sidecar's `last_entry_block` (26,457,088) is entry 25,837, the last one. The
    /// entries themselves are checked live, by the walks that verify against them.
    #[test]
    fn mainnet_last_entry() {
        let t = mainnet().unwrap();
        assert_eq!(
            t.entry(25_837),
            Some(hex32("f84279a9a1b4b7cb664c47bd0f21eb4ccc0f3bdc6ad4932063858de69eebf40b"))
        );
        assert_eq!(t.entry(25_838), None);
    }

    #[test]
    fn anchors() {
        let t = mainnet().unwrap();
        // An entry is its own anchor: a walk of one header.
        assert_eq!(t.anchor_at_or_above(0), Some((0, MAINNET_PIN.genesis_hash)));
        assert_eq!(t.anchor_at_or_above(2048).map(|a| a.0), Some(2048));
        // Otherwise the next multiple of 1024.
        assert_eq!(t.anchor_at_or_above(1).map(|a| a.0), Some(1024));
        assert_eq!(t.anchor_at_or_above(2049).map(|a| a.0), Some(3072));
        // Above the last entry, the top; above the top, none.
        assert_eq!(t.anchor_at_or_above(26_457_089), Some(t.top()));
        assert_eq!(t.anchor_at_or_above(26_457_537), Some(t.top()));
        assert_eq!(t.anchor_at_or_above(26_457_538), None);
        // The walk is never longer than K.
        for n in [1u64, 1023, 1025, 26_457_089, 26_457_537, 12_345_678] {
            let (a, _) = t.anchor_at_or_above(n).unwrap();
            assert!(a >= n && a - n < CheckpointTable::K, "{n} → {a}");
        }
    }

    fn pin_for(bytes: &[u8], top_number: u64, top_hash: [u8; 32]) -> TablePin {
        let mut genesis = [0u8; 32];
        genesis.copy_from_slice(&bytes[..32]);
        TablePin {
            keccak256: keccak256(bytes),
            entries: bytes.len() as u64 / 32,
            genesis_hash: genesis,
            top_number,
            top_hash,
        }
    }

    #[test]
    fn parse_refuses_what_does_not_match_the_pin() {
        let bytes: Vec<u8> = (0..3u8).flat_map(|i| [i; 32]).collect();
        let good = pin_for(&bytes, 2048 + 5, [9; 32]);
        assert!(CheckpointTable::parse(&bytes, &good).is_ok());

        let mut tampered = bytes.clone();
        tampered[40] ^= 1;
        assert!(CheckpointTable::parse(&tampered, &good).is_err(), "keccak");

        let short = &bytes[..64];
        assert!(CheckpointTable::parse(short, &pin_for(short, 2048, [9; 32])).is_err(), "top");
        let wrong_len = TablePin { entries: 3, ..pin_for(short, 1024, [1; 32]) };
        assert!(CheckpointTable::parse(short, &wrong_len).is_err(), "length");
        assert!(CheckpointTable::parse(&bytes, &TablePin { genesis_hash: [7; 32], ..good })
            .is_err(), "genesis");
        assert!(CheckpointTable::parse(&bytes, &TablePin { top_number: 3072, ..good }).is_err());
        assert!(CheckpointTable::parse(&bytes, &TablePin { top_number: 2047, ..good }).is_err());
        // A top that IS the last entry must carry that entry's hash.
        assert!(CheckpointTable::parse(&bytes, &TablePin { top_number: 2048, ..good }).is_err());
        assert!(CheckpointTable::parse(
            &bytes,
            &TablePin { top_number: 2048, top_hash: [2; 32], ..good }
        )
        .is_ok());
        assert!(CheckpointTable::parse(&[], &pin_for(&[0; 32], 0, [0; 32])).is_err(), "empty");
    }
}
