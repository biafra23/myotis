//! One address in one slice: which bucket to read, which of its records are the address's,
//! and their entries (eth2swarm `docs/address-index.md`, "Client lookup").
//!
//! A record carries only a 64-bit fingerprint of its address, so in rare cases the records of
//! another address with the same fingerprint come along; the per-entry check against chain
//! data (the caller's) finds such an entry not where its role says.

use myotis_core::keccak::keccak256;

use crate::records::{AddressRecord, BucketBody, BucketRecord, Entries, Entry, SliceRecord};
use crate::{ensure, Result};

/// `keccak256` of the address: the bucket from `h[0..4]`, the fingerprint `h[4..12]`.
pub fn address_hash(address: &[u8; 20]) -> [u8; 32] {
    keccak256(address)
}

/// Bucket of an address hash among `buckets` (multiply-shift on `h[0..4]`).
pub fn bucket_of(h: &[u8; 32], buckets: u32) -> u32 {
    let prefix = u32::from_be_bytes(h[..4].try_into().expect("4")) as u64;
    ((prefix * buckets as u64) >> 32) as u32
}

pub fn fingerprint(h: &[u8; 32]) -> [u8; 8] {
    h[4..12].try_into().expect("8")
}

/// The bucket of `address` in the slice `slice` describes.
pub fn bucket_for(address: &[u8; 20], slice: &SliceRecord) -> u32 {
    bucket_of(&address_hash(address), slice.bucket_count)
}

/// What one slice holds for an address, once its records are read: entries inline, and
/// spill files still to read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InSlice {
    /// Entries stored in the record itself.
    pub entries: Vec<Entry>,
    /// Spill files to read (reference, entry count): see `records::spill_entries`.
    pub spill_files: Vec<([u8; 32], u64)>,
}

/// What a bucket gives for an address: its records, or, for a paged bucket, the pages file
/// that holds them. A paged bucket has no entries of its own, so the two are separate cases
/// a caller cannot mistake for an empty answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InBucket {
    /// The address's records, from an inline bucket.
    Records(InSlice),
    /// A paged bucket: read its pages file with `records::bucket_pages_records(slice, file,
    /// pages, records)`, then [`select`] the address's records from it.
    Paged {
        pages_ref: [u8; 32],
        pages: u32,
        records: u32,
    },
}

/// The records of `address` in a decoded bucket, which must be the bucket
/// [`bucket_for`] names in `slice`.
pub fn in_bucket(
    address: &[u8; 20],
    slice: &SliceRecord,
    bucket: &BucketRecord,
) -> Result<InBucket> {
    let k = bucket_for(address, slice);
    ensure!(
        (bucket.level, bucket.index, bucket.bucket) == (slice.level, slice.index, k),
        "bucket {} of slice ({}, {}) read for bucket {k} of ({}, {})",
        bucket.bucket,
        bucket.level,
        bucket.index,
        slice.level,
        slice.index
    );
    Ok(match &bucket.body {
        BucketBody::Inline(records) => InBucket::Records(select(address, records)),
        BucketBody::Paged {
            count,
            pages,
            pages_ref,
        } => InBucket::Paged {
            pages_ref: *pages_ref,
            pages: *pages,
            records: *count,
        },
    })
}

/// The entries and spill files of the records whose fingerprint is `address`'s.
pub fn select(address: &[u8; 20], records: &[AddressRecord]) -> InSlice {
    let fp = fingerprint(&address_hash(address));
    let mut out = InSlice::default();
    for rec in records.iter().filter(|r| r.fp == fp) {
        match &rec.entries {
            Entries::Inline(e) => out.entries.extend_from_slice(e),
            Entries::Spilled { count, spill_ref } => out.spill_files.push((*spill_ref, *count)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_assignment_and_selection() {
        let a = [0x11u8; 20];
        let h = address_hash(&a);
        assert_eq!(bucket_of(&h, 1), 0);
        assert!(bucket_of(&h, 1000) < 1000);
        let mine = AddressRecord {
            fp: fingerprint(&h),
            entries: Entries::Inline(vec![Entry {
                block: 5,
                slot: 1,
                roles: 1,
            }]),
        };
        let other = AddressRecord {
            fp: [0; 8],
            entries: Entries::Spilled {
                count: 3,
                spill_ref: [9; 32],
            },
        };
        let got = select(&a, &[other, mine]);
        assert_eq!(got.entries.len(), 1);
        assert!(got.spill_files.is_empty());
    }
}
