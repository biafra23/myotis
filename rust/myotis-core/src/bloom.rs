//! 2048-bit logs bloom (Yellow Paper M3:2048) — twin of the accrual in
//! `networking.eth.messages.ReceiptsMessage` (Java). Needed because eth/69
//! (EIP-7642) receipts arrive bloomless: the bloom is a pure function of the
//! logs, so it is recomputed before re-canonicalizing the receipt for the
//! `receiptsRoot` check (docs/reimplementation/02 §6.6, README §11.11).

use crate::keccak::keccak256;

/// A 2048-bit (256-byte) logs bloom filter.
pub type LogsBloom = [u8; 256];

/// All-zero bloom (a receipt with no logs).
pub const EMPTY_BLOOM: LogsBloom = [0u8; 256];

/// Accrue one item (a log address or topic) into the bloom: three bits,
/// each indexed by the low 11 bits of one of the first three byte-PAIRS of
/// `keccak256(item)`; bit `i` sets byte `255 - i/8`, bit `i % 8`.
pub fn accrue(bloom: &mut LogsBloom, item: &[u8]) {
    let h = keccak256(item);
    for i in (0..6).step_by(2) {
        let bit = ((usize::from(h[i]) << 8) | usize::from(h[i + 1])) & 0x7ff;
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accrue_sets_at_most_three_bits() {
        let mut bloom = EMPTY_BLOOM;
        accrue(&mut bloom, b"myotis");
        let bits: u32 = bloom.iter().map(|b| b.count_ones()).sum();
        assert!((1..=3).contains(&bits));
        // Idempotent: accruing the same item again changes nothing.
        let snapshot = bloom;
        accrue(&mut bloom, b"myotis");
        assert_eq!(bloom, snapshot);
    }

    #[test]
    fn distinct_items_accumulate() {
        let mut bloom = EMPTY_BLOOM;
        accrue(&mut bloom, b"a");
        let after_a = bloom;
        accrue(&mut bloom, b"b");
        assert_ne!(bloom, after_a);
        // Superset property: every bit of after_a is still set.
        for (x, y) in after_a.iter().zip(bloom.iter()) {
            assert_eq!(x & y, *x);
        }
    }
}
