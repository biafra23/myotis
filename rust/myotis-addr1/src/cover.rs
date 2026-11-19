//! Which slices a head makes a client read (eth2swarm `docs/address-index.md`, "Slices and
//! covers", "Starting at a later block").

use std::ops::Range;

use crate::records::{HeadRecord, L_MAX};

/// A slice `(level, index)`: units `[index·2^level, (index+1)·2^level)`.
pub type SliceId = (u8, u32);

/// Units of a slice on the grid from genesis.
pub fn units(slice: SliceId) -> Range<u64> {
    let (level, index) = slice;
    (index as u64) << level..(index as u64 + 1) << level
}

/// Units slice `slice` holds in an index from unit `first_unit`: empty for a slice that ends
/// at or before it (such a slice does not exist in that index).
pub fn held(slice: SliceId, first_unit: u64) -> Range<u64> {
    let r = units(slice);
    r.start.max(first_unit).min(r.end)..r.end
}

/// The cover of `[0, n)` units, oldest first: every complete top-level slice, then one slice
/// per set bit of `n` below `L_max`.
pub fn cover(n: u64) -> Vec<SliceId> {
    let mut out: Vec<SliceId> = (0..n >> L_MAX).map(|j| (L_MAX, j as u32)).collect();
    let mut start = (n >> L_MAX) << L_MAX;
    for level in (0..L_MAX).rev() {
        if n & (1 << level) != 0 {
            out.push((level, (start >> level) as u32));
            start += 1 << level;
        }
    }
    out
}

/// The slices a deferred merge replaces while it is pending: the cover of its units but the
/// last, then the last unit's level-0 slice.
pub fn expansion(slice: SliceId) -> Vec<SliceId> {
    let level = slice.0;
    if level == 0 {
        return vec![slice];
    }
    let mut out = Vec::with_capacity(level as usize + 1);
    let mut start = units(slice).start;
    for l in (0..level).rev() {
        out.push((l, (start >> l) as u32));
        start += 1 << l;
    }
    out.push((0, start as u32));
    out
}

/// The cover of `[0, n)` with every pending merge replaced by its expansion, recursively.
pub fn resolve(n: u64, pending: &[SliceId]) -> Vec<SliceId> {
    fn push(out: &mut Vec<SliceId>, s: SliceId, pending: &[SliceId]) {
        if s.0 > 0 && pending.contains(&s) {
            for e in expansion(s) {
                push(out, e, pending);
            }
        } else {
            out.push(s);
        }
    }
    let mut out = Vec::new();
    for s in cover(n) {
        push(&mut out, s, pending);
    }
    out
}

/// The slices of [`resolve`] that end after unit `m`. For an index from unit `S`,
/// `resolve_after(S, …)` is everything a client reads; for an incremental sync, `m` is the
/// last unit it has read (at least `S`).
pub fn resolve_after(m: u64, n: u64, pending: &[SliceId]) -> Vec<SliceId> {
    resolve(n, pending)
        .into_iter()
        .filter(|s| units(*s).end > m)
        .collect()
}

/// What a client reads for `head`, newest first: every slice from the index's start, or
/// only those after unit `since` for an incremental sync.
pub fn slices_to_read(head: &HeadRecord, since: Option<u64>) -> Vec<SliceId> {
    let from = since.unwrap_or(0).max(head.first_unit);
    let mut out = resolve_after(from, head.units, &head.pending);
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers() {
        // N = 13 = 0b1101: (3, 0), (2, 2), (0, 12).
        assert_eq!(cover(13), vec![(3, 0), (2, 2), (0, 12)]);
        assert!(cover(0).is_empty());
        // Mainnet at 412,950 units: 6 top slices and 7 lower ones.
        assert_eq!(cover(412_950).len(), 13);
        assert_eq!(expansion((2, 0)), vec![(1, 0), (0, 2), (0, 3)]);
        assert_eq!(
            resolve(16, &[(4, 0)]),
            vec![(3, 0), (2, 2), (1, 6), (0, 14), (0, 15)]
        );
    }

    #[test]
    fn late_start_and_incremental() {
        assert_eq!(held((3, 0), 5), 5..8);
        assert!(held((2, 0), 5).is_empty());
        assert_eq!(resolve_after(5, 13, &[]), vec![(3, 0), (2, 2), (0, 12)]);
        assert_eq!(resolve_after(8, 13, &[]), vec![(2, 2), (0, 12)]);
        let head = HeadRecord {
            first_unit: 9,
            units: 13,
            last_block_hash: [0; 32],
            last_block_timestamp: 0,
            pending: vec![],
        };
        // Newest first; the slice before the start is not read.
        assert_eq!(slices_to_read(&head, None), vec![(0, 12), (2, 2)]);
        assert_eq!(slices_to_read(&head, Some(12)), vec![(0, 12)]);
        // A `since` before the start reads from the start.
        assert_eq!(slices_to_read(&head, Some(2)), vec![(0, 12), (2, 2)]);
    }
}
