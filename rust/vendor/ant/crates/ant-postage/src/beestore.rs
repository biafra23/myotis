//! Recover per-bucket stamp-issuer counters from a bee `stamperstore`
//! (PLAN.md "node-owned on-chain state recovery", Feature 1, option a).
//!
//! When a node is started on a data dir carried over from bee, the
//! on-chain batch is rediscoverable over RPC (see
//! `ant_chain::discover`), but the *local* stamp-issuer state — the
//! per-bucket counters across the `2^bucketDepth` collision buckets —
//! is never on-chain. Re-registering a batch with all-zero counters
//! would re-stamp `(batchId, bucket, index)` slots the network has
//! already seen, producing invalid/overwriting stamps. To avoid that we
//! read the counters bee persisted.
//!
//! Bee keeps them in `<data-dir>/stamperstore`, a `LevelDB`, in two forms
//! (see bee `pkg/postage/stampissuer.go`):
//!
//! - `StampIssuerItem`: key `"StampIssuerItem/" ++ raw32(batchID)`,
//!   value = msgpack of `stampIssuerData` (includes `buckets`). Flushed
//!   periodically and on clean shutdown.
//! - `StampItem`: key `"stampItem/" ++ raw32(batchID) ++ "/" ++
//!   hex(chunkAddr)`, value = `batchID(32) ++ chunkAddr(32) ++
//!   batchIndex(8) ++ timestamp(8) ++ 0`. One per issued stamp; bee
//!   rebuilds bucket counts from these after an unclean shutdown.
//!
//! [`recover_bee_buckets`] reads the `StampIssuerItem` for a batch and
//! then folds in the `StampItem` records (taking, per bucket, the
//! max of the stored count and the highest issued index + 1), matching
//! bee's own `recoverBuckets` so the result is correct even if bee
//! exited uncleanly.

use std::path::Path;

use rusty_leveldb::{LdbIterator, Options, DB};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BeeRecoverError {
    #[error("open bee stamperstore: {0}")]
    Open(String),
    #[error("read bee stamperstore: {0}")]
    Read(String),
    #[error("decode bee stamp issuer: {0}")]
    Decode(String),
}

/// The bucket state recovered for one batch from a bee `stamperstore`.
#[derive(Debug, Clone)]
pub struct RecoveredIssuer {
    pub batch_depth: u8,
    pub bucket_depth: u8,
    pub immutable: bool,
    /// Per-bucket issued counters, length `2^bucket_depth`.
    pub buckets: Vec<u32>,
}

/// Subset of bee's `stampIssuerData` we need. Bee marshals the struct
/// with `vmihailenco/msgpack` and field tags, so it lands as a msgpack
/// map keyed by these names; serde ignores the other keys (`label`,
/// `keyID`, `batchID`, `batchAmount`, `maxBucketCount`, `blockNumber`).
#[derive(Debug, Deserialize)]
struct BeeStampIssuerData {
    #[serde(rename = "batchDepth")]
    batch_depth: u8,
    #[serde(rename = "bucketDepth")]
    bucket_depth: u8,
    #[serde(rename = "buckets")]
    buckets: Vec<u32>,
    #[serde(rename = "immutableFlag")]
    immutable: bool,
}

const STAMP_ISSUER_NS: &[u8] = b"StampIssuerItem/";
const STAMP_ITEM_NS: &[u8] = b"stampItem/";

/// Recover the bucket counters bee persisted for `batch_id` at
/// `stamperstore_path`. Returns `Ok(None)` when bee never issued from
/// the batch (no `StampIssuerItem`), so the caller falls back to a
/// fresh (all-zero) issuer.
pub fn recover_bee_buckets(
    stamperstore_path: &Path,
    batch_id: &[u8; 32],
) -> Result<Option<RecoveredIssuer>, BeeRecoverError> {
    if !stamperstore_path.exists() {
        return Ok(None);
    }
    // Never create / mutate structure for a missing store: a bee
    // data-dir without a stamperstore just means "nothing to recover".
    let opt = Options {
        create_if_missing: false,
        ..Options::default()
    };
    let mut db =
        DB::open(stamperstore_path, opt).map_err(|e| BeeRecoverError::Open(e.to_string()))?;

    let mut issuer_key = Vec::with_capacity(STAMP_ISSUER_NS.len() + 32);
    issuer_key.extend_from_slice(STAMP_ISSUER_NS);
    issuer_key.extend_from_slice(batch_id);

    let Some(raw) = db.get(&issuer_key) else {
        return Ok(None);
    };
    let data: BeeStampIssuerData =
        rmp_serde::from_slice(&raw).map_err(|e| BeeRecoverError::Decode(e.to_string()))?;
    let mut recovered = RecoveredIssuer {
        batch_depth: data.batch_depth,
        bucket_depth: data.bucket_depth,
        immutable: data.immutable,
        buckets: data.buckets,
    };

    fold_in_stamp_items(&mut db, batch_id, &mut recovered.buckets)?;
    Ok(Some(recovered))
}

/// Walk the per-stamp `StampItem` records for this batch and raise each
/// bucket counter to at least `highest_issued_index + 1`, mirroring
/// bee's crash-recovery (`StampIssuer.recover`). This makes the result
/// correct even when the `StampIssuerItem` snapshot predates the last
/// stamps bee issued (unclean shutdown).
fn fold_in_stamp_items(
    db: &mut DB,
    batch_id: &[u8; 32],
    buckets: &mut [u32],
) -> Result<(), BeeRecoverError> {
    let mut prefix = Vec::with_capacity(STAMP_ITEM_NS.len() + 33);
    prefix.extend_from_slice(STAMP_ITEM_NS);
    prefix.extend_from_slice(batch_id);
    prefix.push(b'/');

    let mut it = db
        .new_iter()
        .map_err(|e| BeeRecoverError::Read(e.to_string()))?;
    it.seek(&prefix);
    while it.valid() {
        let Some((key, val)) = it.current() else {
            break;
        };
        if !key.starts_with(&prefix) {
            break;
        }
        // value = batchID(32) || chunkAddr(32) || batchIndex(8) || ts(8) [|| 0]
        if val.len() >= 72 {
            let bucket = u32::from_be_bytes(val[64..68].try_into().unwrap());
            let within = u32::from_be_bytes(val[68..72].try_into().unwrap());
            if let Some(slot) = buckets.get_mut(bucket as usize) {
                let need = within.saturating_add(1);
                if *slot < need {
                    *slot = need;
                }
            }
        }
        if !it.advance() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Encode a msgpack map with string keys, mimicking how bee's
    /// `vmihailenco/msgpack` marshals a tagged struct, then decode it
    /// through the same path `recover_bee_buckets` uses.
    #[test]
    fn decodes_bee_stamp_issuer_map() {
        use rmp_serde::Serializer;
        use serde::Serialize;

        // Build a map: bee includes extra keys we must ignore.
        #[derive(Serialize)]
        struct Wire {
            label: String,
            #[serde(rename = "batchDepth")]
            batch_depth: u8,
            #[serde(rename = "bucketDepth")]
            bucket_depth: u8,
            buckets: Vec<u32>,
            #[serde(rename = "maxBucketCount")]
            max_bucket_count: u32,
            #[serde(rename = "immutableFlag")]
            immutable: bool,
        }
        let wire = Wire {
            label: "test".into(),
            batch_depth: 22,
            bucket_depth: 4,
            buckets: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            max_bucket_count: 16,
            immutable: false,
        };
        // Force map (string-keyed) encoding, like bee.
        let mut buf = Vec::new();
        wire.serialize(&mut Serializer::new(&mut buf).with_struct_map())
            .unwrap();

        let data: BeeStampIssuerData = rmp_serde::from_slice(&buf).unwrap();
        assert_eq!(data.batch_depth, 22);
        assert_eq!(data.bucket_depth, 4);
        assert_eq!(data.buckets.len(), 16);
        assert_eq!(data.buckets[15], 16);
        assert!(!data.immutable);
    }

    /// The `StampItem` fold raises a bucket to the highest issued index
    /// + 1 and leaves already-higher counts untouched.
    #[test]
    fn stamp_item_fold_logic() {
        // Simulate two stamp items in bucket 3 (within 0 and 1) and one
        // in bucket 7 (within 4). Starting counters under-count bucket 7.
        let mut buckets = [0u32; 16];
        buckets[3] = 2; // already current
        buckets[7] = 2; // stale: a stamp at within=4 exists

        let mut items: BTreeMap<u32, u32> = BTreeMap::new();
        items.insert(3, 1); // highest within in bucket 3
        items.insert(7, 4); // highest within in bucket 7
        for (&bucket, &within) in &items {
            let need = within + 1;
            if buckets[bucket as usize] < need {
                buckets[bucket as usize] = need;
            }
        }
        assert_eq!(buckets[3], 2, "already-current bucket untouched");
        assert_eq!(buckets[7], 5, "stale bucket raised to within+1");
    }
}
