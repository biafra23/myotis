//! Postage stamp issuance — matches bee `pkg/postage/stamp.go` + `stampissuer.go`
//! serialization and signing (`signer.Sign` ⇒ EIP‑191 wrapping of digest).
//!
//! On-disk persistence
//! -------------------
//!
//! Bucket counters are issued strictly monotonically per (batch, bucket).
//! If the daemon restarts we **must not** re-issue an index already
//! handed to the network — bee peers would reject the second stamp as
//! a double-spend and quietly drop us (worse, they could downgrade their
//! reputation of our overlay).
//!
//! [`StampIssuer::open_or_new`] loads the counters from a small file at
//! a caller-supplied path; every successful [`StampIssuer::increment`]
//! writes the updated counters back atomically (`write tmp + fsync +
//! rename`) before the call returns. The on-disk state is therefore
//! always at-least-as-current as the most-recently-issued stamp, so a
//! crash anywhere after the persist call (including after pushsync has
//! shipped the chunk) is safe.
//!
//! File layout (little-endian throughout):
//!
//! ```text
//! [0..4]    magic  = b"ASBC"           (Ant Stamp Bucket Counters)
//! [4..6]    version = 0x0001
//! [6]       batch_depth
//! [7]       bucket_depth
//! [8]       immutable (0/1)
//! [9..16]   reserved (zeros)
//! [16..48]  batch_id
//! [48..N]   buckets: u32 LE * (1 << bucket_depth)
//! [N..N+32] keccak256 of bytes [0..N]   (corruption canary)
//! ```
//!
//! For depth=16 the file is 256 KiB; below the per-second IO budget of
//! any sane disk, and the typical upload-shaped workload only issues a
//! few hundred increments at a time interleaved with pushsync RTTs.

#[cfg(feature = "bee-recover")]
pub mod beestore;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ant_crypto::{
    ethereum_address_from_public_key, recover_public_key, sign_handshake_data, CryptoError,
    SECP256K1_SECRET_LEN,
};
use k256::ecdsa::VerifyingKey;
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub const INDEX_SIZE: usize = 8;
pub const TIMESTAMP_SIZE: usize = 8;
pub const SIGNATURE_LEN: usize = 65;
pub const STAMP_SIZE: usize = 32 + INDEX_SIZE + TIMESTAMP_SIZE + SIGNATURE_LEN;

#[derive(Debug, Error)]
pub enum PostageError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("{0}")]
    Msg(String),
    #[error("bucket full")]
    BucketFull,
    #[error("persist postage state: {0}")]
    Persist(String),
    #[error("load bucket counters: {0}")]
    Load(String),
    /// On-disk counters were written for a different batch / depth, so
    /// the file probably belongs to another batch and we must refuse to
    /// continue rather than silently re-issuing indices.
    #[error("bucket store mismatch: on-disk batch={on_disk}, expected={expected}")]
    StoreMismatch { on_disk: String, expected: String },
}

/// Magic bytes identifying an Ant stamp-bucket-counter file. Catches a
/// caller pointing the issuer at, e.g., a stale Bee `postage.db` blob
/// of the same name before we'd corrupt their state.
const STORE_MAGIC: &[u8; 4] = b"ASBC";
/// On-disk file format version. Bumped when the layout changes.
const STORE_VERSION: u16 = 1;
/// Length of the fixed header (magic + version + depths + batch id +
/// reserved). Followed by `4 * (1 << bucket_depth)` bytes of u32-LE
/// counters and a 32-byte keccak256 trailer.
const STORE_HEADER_LEN: usize = 48;

/// Bee `stampIssuerData`-shaped issuer with only the fields Ant needs locally.
///
/// Persistence is opt-in: instances built via [`StampIssuer::new`] keep
/// counters in memory only and lose them on restart. Production callers
/// should always use [`StampIssuer::open_or_new`] so a daemon restart
/// resumes the same counter sequence the network already saw.
#[derive(Debug)]
pub struct StampIssuer {
    batch_id: [u8; 32],
    batch_depth: u8,
    bucket_depth: u8,
    immutable: bool,
    buckets: Vec<u32>,
    /// Optional path the issuer flushes counters to after every
    /// [`StampIssuer::increment`]. `None` for in-memory-only test
    /// instances.
    persist_path: Option<PathBuf>,
    /// Per-chunk stamp cache: maps a chunk address to the latest stamp
    /// issued for it under this batch. Makes stamping **idempotent** —
    /// re-pushing a chunk (post-upload heal, a manual retry, an
    /// interrupted-upload resume) reuses the same bucket **slot** instead
    /// of burning a fresh index. Without this a chunk re-pushed N times
    /// consumes N slots in its collision bucket, so a few heal rounds can
    /// saturate an otherwise-roomy batch. Backed by the `.stamps` sidecar
    /// (see [`append_stamp_record`]): each stamp (fresh or refreshed) is
    /// **appended** with a checksum, so a torn write only ever damages
    /// the trailing record and the address's previous valid record still
    /// recovers its slot. The file is compacted (see [`rewrite_sidecar`])
    /// once it grows past a small multiple of the live entry count, so
    /// re-stamps don't grow it without bound.
    seen: HashMap<[u8; 32], [u8; STAMP_SIZE]>,
    /// Number of physical records currently in the sidecar (≥ `seen`
    /// when re-stamps have appended newer copies not yet compacted away).
    /// Drives the compaction trigger. `0` for in-memory issuers.
    stamp_record_count: usize,
    /// After a failed compaction, the physical record count at which the
    /// next attempt is made (`0`: no back-off). Compaction is
    /// housekeeping on a file that is already valid and appendable, so a
    /// failure (disk full, say) must not fail the stamp whose append
    /// already landed — and must not be re-attempted, a full-file
    /// rewrite, on every following stamp either.
    compact_retry_at: usize,
    /// The error of the most recent failed sidecar compaction (at load or
    /// after an append), `None` once a compaction succeeds. Compaction
    /// failing never fails a stamp, so without this a persistently
    /// failing rewrite (ENOSPC) would let the sidecar grow by one record
    /// per re-stamp with nothing telling the operator why — see
    /// [`Self::stamp_compaction_error`]. Each failure is also logged.
    compaction_error: Option<String>,
    /// Sidecar path the issued stamps are written to (sibling of
    /// `persist_path`, `.stamps` extension). `None` for in-memory issuers.
    stamps_path: Option<PathBuf>,
    /// `Some(reason)` when a *persistent* issuer's sidecar exists but
    /// could not be made safe to write to — an unreadable file, an
    /// un-removable foreign/corrupt or unknown-version header, a failed
    /// v1→v2 migration, or a failed trailing-partial truncation. It is
    /// distinct from an intentional in-memory issuer (`stamps_path`
    /// `None`, this `None`): here the caller **expected** durability, so
    /// [`sign_stamp_bytes`] refuses to issue and surfaces `reason` — a
    /// stamp we can't persist would push to the network and then lose
    /// its address→slot mapping on restart, burning a fresh index on
    /// re-push (and, at capacity, evicting another chunk or being
    /// rejected on an immutable batch).
    stamp_persistence_failed: Option<&'static str>,
    /// Advisory exclusive lock on `<persist_path>.lock`, held for the
    /// issuer's lifetime. Two issuers over one store — a second daemon,
    /// a stray CLI — would each hand out the same `(batch, bucket,
    /// index)` and double-issue toward the network, and a concurrent
    /// compaction `rename` could strand the other handle's `O_APPEND`
    /// write in an unlinked inode. `None` for in-memory issuers. A
    /// separate lock file (never renamed) so compaction can't detach
    /// the lock from its inode.
    _store_lock: Option<std::fs::File>,
}

/// Magic for the per-chunk stamp sidecar (Ant `STamp` Map).
const STAMP_STORE_MAGIC: &[u8; 4] = b"ASTM";
/// Sidecar format version. v2 appends checksummed records (v1 had no
/// checksum). A v1 file is **migrated** on load — its records are read
/// and rewritten as v2 — rather than discarded, so no reusable slot is
/// lost across the upgrade.
const STAMP_STORE_VERSION: u16 = 2;
/// The pre-checksum format: `addr(32) ‖ stamp(113)` records, no
/// per-record checksum. Read only to migrate forward.
const STAMP_STORE_VERSION_V1: u16 = 1;
/// v1 record length (no checksum).
const STAMP_RECORD_LEN_V1: usize = 32 + STAMP_SIZE;
/// Compact the sidecar once physical records exceed
/// `live × STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR`, bounding the
/// growth that append-on-re-stamp would otherwise cause to ~2× the live
/// entry count while keeping small files append-only (cheap).
const STAMP_COMPACT_FACTOR: usize = 2;
const STAMP_COMPACT_FLOOR: usize = 64;
/// Sidecar header: `magic(4) + version(2) + batch_id(32)`.
const STAMP_STORE_HEADER_LEN: usize = 38;
/// Trailing checksum on each record: first 4 bytes of
/// `keccak256(addr ‖ stamp)`. Detects a torn record from a
/// crash-interrupted write.
const STAMP_CHECKSUM_LEN: usize = 4;
/// One record: chunk address(32) + stamp([`STAMP_SIZE`]) + checksum(4).
const STAMP_RECORD_LEN: usize = 32 + STAMP_SIZE + STAMP_CHECKSUM_LEN;

/// Snapshot of a [`StampIssuer`]'s capacity and fill, suitable for
/// ops dashboards and pre-flight upload checks. Returned by
/// [`StampIssuer::stats`].
///
/// Field semantics:
///
/// - `total_capacity` = `bucket_count * bucket_capacity` = `2^batch_depth`.
///   The number of stamps the batch can issue *if every bucket fills
///   evenly*. Practical capacity is lower because chunk addresses
///   route to specific buckets.
/// - `worst_case_remaining` = `(bucket_capacity − bucket_fill_max) *
///   bucket_count`. The number of new chunks guaranteed to fit no
///   matter how the next file's chunk addresses route (assumes the
///   worst case where every new chunk hashes into the
///   currently-fullest bucket). This is the right number to use as
///   a pre-flight budget for an immutable batch.
/// - `remaining_total` is the sum of free indices across buckets;
///   the *optimistic* counterpart to `worst_case_remaining` (would
///   only be reachable with perfectly even bucket routing).
#[derive(Debug, Clone, Copy)]
pub struct BucketStats {
    pub batch_id: [u8; 32],
    pub batch_depth: u8,
    pub bucket_depth: u8,
    pub immutable: bool,
    /// Number of buckets in the batch (`2^bucket_depth`).
    pub bucket_count: u64,
    /// Per-bucket index ceiling (`2^(batch_depth − bucket_depth)`).
    pub bucket_capacity: u32,
    /// `bucket_count × bucket_capacity`.
    pub total_capacity: u64,
    /// Indices issued so far across every bucket.
    pub issued: u64,
    pub bucket_fill_min: u32,
    pub bucket_fill_max: u32,
    /// Sum of free indices across all buckets. Reachable only with
    /// perfectly-even chunk-address routing.
    pub remaining_total: u64,
    /// Conservative chunk budget: room left in the *currently
    /// fullest* bucket, scaled to a global count. Use this as the
    /// pre-flight ceiling for "will my next upload fit?" — see the
    /// type-level doc for the reasoning.
    pub worst_case_remaining: u64,
}

impl StampIssuer {
    /// Build an in-memory-only issuer. Useful for tests and one-shot
    /// CLI dry-runs; production callers should use
    /// [`StampIssuer::open_or_new`] so counters survive a restart.
    pub fn new(
        batch_id: [u8; 32],
        batch_depth: u8,
        bucket_depth: u8,
        immutable: bool,
    ) -> Result<Self, PostageError> {
        Self::build(batch_id, batch_depth, bucket_depth, immutable, None)
    }

    /// Open an existing on-disk store at `path` for this batch, or
    /// create a fresh zero-filled file if `path` doesn't exist.
    ///
    /// Refuses to load a file that was written for a different
    /// `(batch_id, batch_depth, bucket_depth)` triple — this catches
    /// `--data-dir` typos that would otherwise re-issue indices the
    /// network has already seen for a different batch.
    pub fn open_or_new(
        path: PathBuf,
        batch_id: [u8; 32],
        batch_depth: u8,
        bucket_depth: u8,
        immutable: bool,
    ) -> Result<Self, PostageError> {
        if path.exists() {
            let store_lock = acquire_store_lock(&path)?;
            let bytes = std::fs::read(&path)
                .map_err(|e| PostageError::Load(format!("{}: {e}", path.display())))?;
            let header = decode_header(&bytes)?;
            if header.batch_id != batch_id {
                return Err(PostageError::StoreMismatch {
                    on_disk: hex::encode(header.batch_id),
                    expected: hex::encode(batch_id),
                });
            }
            if header.batch_depth != batch_depth || header.bucket_depth != bucket_depth {
                return Err(PostageError::StoreMismatch {
                    on_disk: format!(
                        "depth={} bucket_depth={}",
                        header.batch_depth, header.bucket_depth
                    ),
                    expected: format!("depth={batch_depth} bucket_depth={bucket_depth}"),
                });
            }
            let buckets = decode_buckets(&bytes, bucket_depth)?;
            let mut issuer = Self {
                batch_id,
                batch_depth,
                bucket_depth,
                immutable,
                buckets,
                persist_path: Some(path),
                seen: HashMap::new(),
                stamp_record_count: 0,
                compact_retry_at: 0,
                compaction_error: None,
                stamps_path: None,
                stamp_persistence_failed: None,
                _store_lock: Some(store_lock),
            };
            issuer.attach_stamp_store();
            return Ok(issuer);
        }
        let issuer = Self::build(batch_id, batch_depth, bucket_depth, immutable, Some(path))?;
        issuer.persist()?;
        Ok(issuer)
    }

    /// Open (or create) an on-disk store at `path`, seeding the bucket
    /// counters from `buckets` **only when the file does not already
    /// exist**. Used by the on-chain recovery path
    /// (`antd` startup) to adopt a batch rediscovered from the node EOA,
    /// carrying over the per-bucket counters recovered from a bee
    /// `stamperstore` so the node never re-stamps a slot the network has
    /// already seen.
    ///
    /// If a store already exists at `path` its counters win (they are
    /// at-least-as-current as anything we could seed) and `buckets` is
    /// ignored — exactly [`Self::open_or_new`]. `buckets.len()` must
    /// equal `2^bucket_depth`.
    pub fn open_or_new_seeded(
        path: PathBuf,
        batch_id: [u8; 32],
        batch_depth: u8,
        bucket_depth: u8,
        immutable: bool,
        buckets: &[u32],
    ) -> Result<Self, PostageError> {
        if path.exists() {
            return Self::open_or_new(path, batch_id, batch_depth, bucket_depth, immutable);
        }
        let n = 1usize
            .checked_shl(u32::from(bucket_depth))
            .ok_or_else(|| PostageError::Msg("bucket bitmap too large".into()))?;
        if buckets.len() != n {
            return Err(PostageError::Msg(format!(
                "seed buckets len {} != 2^bucket_depth {n}",
                buckets.len(),
            )));
        }
        let mut issuer = Self::build(batch_id, batch_depth, bucket_depth, immutable, Some(path))?;
        issuer.buckets = buckets.to_vec();
        issuer.persist()?;
        Ok(issuer)
    }

    /// Reload a persisted issuer from `path`, taking every parameter
    /// (`batch_id`, depths, immutability) from the file header rather
    /// than the caller. Used at daemon startup to rescan
    /// `<data-dir>/postage/*.bin` and resurrect every batch the node
    /// previously bought without a sidecar registry — the filename is
    /// the batch id and the header carries the rest.
    pub fn open_existing(path: PathBuf) -> Result<Self, PostageError> {
        let store_lock = acquire_store_lock(&path)?;
        let bytes = std::fs::read(&path)
            .map_err(|e| PostageError::Load(format!("{}: {e}", path.display())))?;
        let header = decode_header(&bytes)?;
        let buckets = decode_buckets(&bytes, header.bucket_depth)?;
        let mut issuer = Self {
            batch_id: header.batch_id,
            batch_depth: header.batch_depth,
            bucket_depth: header.bucket_depth,
            immutable: header.immutable,
            buckets,
            persist_path: Some(path),
            seen: HashMap::new(),
            stamp_record_count: 0,
            compact_retry_at: 0,
            compaction_error: None,
            stamps_path: None,
            stamp_persistence_failed: None,
            _store_lock: Some(store_lock),
        };
        issuer.attach_stamp_store();
        Ok(issuer)
    }

    /// Raise the batch depth in place after an on-chain `increaseDepth`
    /// ("dilute"). The collision-bucket count is `2^bucket_depth`, which
    /// is unchanged by a dilute, so the bucket vector keeps its length;
    /// only each bucket's index ceiling (`2^(batch_depth − bucket_depth)`)
    /// grows. We therefore just update the header field and re-persist —
    /// no counter is touched, so no index is ever re-issued. Refuses to
    /// lower the depth (that would shrink capacity below already-issued
    /// indices and let the network reject our stamps).
    pub fn set_batch_depth(&mut self, new_depth: u8) -> Result<(), PostageError> {
        if new_depth <= self.bucket_depth {
            return Err(PostageError::Msg(format!(
                "new depth {new_depth} must exceed bucket_depth {}",
                self.bucket_depth
            )));
        }
        if new_depth - self.bucket_depth > MAX_BUCKET_SPAN {
            return Err(PostageError::Msg(format!(
                "new depth {new_depth} exceeds bucket_depth {} by more than {MAX_BUCKET_SPAN}",
                self.bucket_depth
            )));
        }
        if new_depth < self.batch_depth {
            return Err(PostageError::Msg(format!(
                "refusing to lower batch depth {} → {new_depth}",
                self.batch_depth
            )));
        }
        self.batch_depth = new_depth;
        self.persist()
    }

    fn build(
        batch_id: [u8; 32],
        batch_depth: u8,
        bucket_depth: u8,
        immutable: bool,
        persist_path: Option<PathBuf>,
    ) -> Result<Self, PostageError> {
        if bucket_depth == 0 || bucket_depth >= batch_depth {
            return Err(PostageError::Msg(
                "bucketDepth must be >0 and < batchDepth".into(),
            ));
        }
        if batch_depth - bucket_depth > MAX_BUCKET_SPAN {
            return Err(PostageError::Msg(format!(
                "batchDepth {batch_depth} exceeds bucketDepth {bucket_depth} \
                 by more than {MAX_BUCKET_SPAN}"
            )));
        }
        let n = 1usize
            .checked_shl(u32::from(bucket_depth))
            .ok_or_else(|| PostageError::Msg("bucket bitmap too large".into()))?;
        let store_lock = persist_path
            .as_deref()
            .map(acquire_store_lock)
            .transpose()?;
        let mut issuer = Self {
            batch_id,
            batch_depth,
            bucket_depth,
            immutable,
            buckets: vec![0u32; n],
            persist_path,
            seen: HashMap::new(),
            stamp_record_count: 0,
            compact_retry_at: 0,
            compaction_error: None,
            stamps_path: None,
            stamp_persistence_failed: None,
            _store_lock: store_lock,
        };
        issuer.attach_stamp_store();
        // Fresh counters (this branch only runs when the counter file
        // was absent) next to a sidecar that already records issued
        // stamps means the counter file was deleted or recreated: the
        // counters are behind what the network has seen, and issuing
        // would re-use `(batch, bucket, index)` tuples. Fail closed —
        // the recovered stamps stay readable, but no new stamp is
        // issued until the operator restores the counter file or
        // removes the sidecar with it.
        if issuer.persist_path.is_some()
            && !issuer.seen.is_empty()
            && issuer.stamp_persistence_failed.is_none()
        {
            issuer.stamp_persistence_failed = Some(
                "sidecar records issued stamps but the counter file was missing/recreated \
                 (counters behind the network)",
            );
        }
        Ok(issuer)
    }

    /// Wire the per-chunk stamp sidecar next to the counter file and
    /// load any previously-issued stamps into [`Self::seen`]. No-op for
    /// in-memory issuers (no `persist_path`). Best-effort: a missing or
    /// corrupt sidecar yields an empty cache — the worst case is that a
    /// future re-push re-stamps (the pre-fix behaviour), never a wrong
    /// stamp.
    fn attach_stamp_store(&mut self) {
        if let Some(p) = &self.persist_path {
            let sidecar = stamps_sidecar_path(p);
            let loaded = load_stamp_store(&sidecar, &self.batch_id);
            self.seen = loaded.map;
            match loaded.unusable_reason {
                None => {
                    self.stamp_record_count = loaded.physical_count;
                    self.compaction_error = loaded.compaction_error;
                    self.stamps_path = Some(sidecar);
                }
                Some(reason) => {
                    // The sidecar exists but can't be safely written
                    // (unreadable, an un-removable bad header, a failed
                    // migration, or a failed truncation). Appending under
                    // it would corrupt framing and lose the mapping on
                    // restart, so this issuer CANNOT persist new stamps.
                    // Record the reason so `sign_stamp_bytes` fails closed
                    // with an accurate operator message; a restart retries
                    // recovery. (Recovered stamps stay in memory so reads
                    // / `has_stamp` still reflect reality.)
                    self.stamp_record_count = 0;
                    self.stamps_path = None;
                    self.stamp_persistence_failed = Some(reason);
                }
            }
        }
    }

    #[must_use]
    pub const fn bucket_depth(&self) -> u8 {
        self.bucket_depth
    }

    #[must_use]
    pub const fn batch_depth(&self) -> u8 {
        self.batch_depth
    }

    #[must_use]
    pub const fn batch_id(&self) -> &[u8; 32] {
        &self.batch_id
    }

    #[must_use]
    pub const fn immutable(&self) -> bool {
        self.immutable
    }

    /// Total number of indices issued so far across every bucket. Used
    /// for ops dashboards / "batch is N% full" reporting; not on the
    /// critical path.
    #[must_use]
    pub fn issued_count(&self) -> u64 {
        self.buckets.iter().map(|&n| u64::from(n)).sum()
    }

    /// Per-bucket fill summary used by `antctl postage status` and the
    /// upload pre-flight check. Walks the in-memory bucket vector
    /// once: `O(2^bucket_depth)` — that's 65 536 elements at the bee
    /// default, ~50 µs in release. Cheap to call on every status
    /// tick.
    #[must_use]
    pub fn stats(&self) -> BucketStats {
        let bucket_count = self.buckets.len() as u64;
        let bucket_capacity = self.bucket_upper_bound();
        let total_capacity = bucket_count.saturating_mul(u64::from(bucket_capacity));
        let issued: u64 = self.buckets.iter().map(|&n| u64::from(n)).sum();
        let (bucket_fill_min, bucket_fill_max) = if self.buckets.is_empty() {
            (0u32, 0u32)
        } else {
            self.buckets
                .iter()
                .copied()
                .fold((u32::MAX, 0u32), |(mn, mx), v| (mn.min(v), mx.max(v)))
        };
        let remaining_total: u64 = self
            .buckets
            .iter()
            .map(|&n| u64::from(bucket_capacity.saturating_sub(n)))
            .sum();
        let worst_case_remaining =
            u64::from(bucket_capacity.saturating_sub(bucket_fill_max)) * bucket_count;
        BucketStats {
            batch_id: self.batch_id,
            batch_depth: self.batch_depth,
            bucket_depth: self.bucket_depth,
            immutable: self.immutable,
            bucket_count,
            bucket_capacity,
            total_capacity,
            issued,
            bucket_fill_min,
            bucket_fill_max,
            remaining_total,
            worst_case_remaining,
        }
    }

    /// Max collisions per bucket: `2^(batch_depth - bucket_depth)`.
    /// Public because bee's `GET /stamps/{id}/buckets` surfaces it as
    /// `bucketUpperBound`. Every path that sets the depths (`build`,
    /// `decode_header`, `set_batch_depth`) holds the span to
    /// `1..=MAX_BUCKET_SPAN`, so the shift always fits a `u32`.
    #[must_use]
    pub fn bucket_upper_bound(&self) -> u32 {
        bucket_capacity(self.batch_depth, self.bucket_depth)
            .expect("depth span is validated on every path that sets it")
    }

    /// Raw per-bucket collision counters, indexed by bucket id. Backs
    /// bee's `GET /stamps/{id}/buckets` (`issuer.Buckets()`).
    #[must_use]
    pub fn bucket_counts(&self) -> &[u32] {
        &self.buckets
    }

    /// True if the collision bucket the chunk at `addr` maps to is
    /// already at capacity. The next stamp for such a chunk would, on a
    /// mutable batch, wrap the bucket counter back to 0 and re-issue an
    /// already-used `(bucket, index)` slot with a newer timestamp — which
    /// bee storers resolve by keeping the newer chunk and **evicting**
    /// the older one. On a too-small batch (e.g. depth 17, only
    /// `2^(depth-bucket_depth)` slots per bucket) that silently drops
    /// chunks — including chunks of the *same* upload — leaving the
    /// content unretrievable network-wide. Callers that need durable
    /// storage should refuse to stamp when this returns `true` rather
    /// than evict. (An *immutable* batch already errors with
    /// [`PostageError::BucketFull`] in [`Self::increment`].)
    #[must_use]
    pub fn bucket_is_full(&self, addr: &[u8; 32]) -> bool {
        let b_idx = collision_bucket_from_addr(self.bucket_depth, addr);
        self.buckets.get(b_idx as usize).copied().unwrap_or(0) >= self.bucket_upper_bound()
    }

    /// True when the fullest bucket is already at capacity, so *some*
    /// chunk addresses can no longer be stamped without evicting an
    /// earlier chunk (see [`Self::bucket_is_full`]). Equivalent to
    /// `stats().worst_case_remaining == 0`, but without allocating /
    /// walking for the full [`BucketStats`]. Use as a cheap pre-flight
    /// "this batch is saturated" signal.
    #[must_use]
    pub fn is_saturated(&self) -> bool {
        let upper = self.bucket_upper_bound();
        self.buckets.iter().any(|&n| n >= upper)
    }

    /// The stamp already issued for `addr` under this batch, if any.
    /// A `Some` means a re-push can reuse it for free; callers should
    /// check this *before* the [`Self::bucket_is_full`] pre-flight so a
    /// re-push of an already-stamped chunk is never blocked by a now-full
    /// bucket (it consumes no new slot).
    #[must_use]
    pub fn cached_stamp(&self, addr: &[u8; 32]) -> Option<[u8; STAMP_SIZE]> {
        self.seen.get(addr).copied()
    }

    /// Whether a stamp has already been issued for `addr`. Cheap
    /// companion to [`Self::cached_stamp`] for guard conditions.
    #[must_use]
    pub fn has_stamp(&self, addr: &[u8; 32]) -> bool {
        self.seen.contains_key(addr)
    }

    /// `Some(reason)` when this persistent issuer's `.stamps` sidecar
    /// can't be safely written (the same state in which
    /// [`sign_stamp_bytes`] refuses to issue). In most of those states
    /// it also couldn't be fully read back — an unreadable file loads
    /// no records at all — so the per-chunk records
    /// ([`Self::cached_stamp`]) may be missing chunks this node did
    /// stamp. Readers that report "not stamped" from the records treat
    /// `Some` as "records may be incomplete" and refuse rather than
    /// read a miss as a confirmed absence. `None` does not prove the
    /// records cover every stamp the batch ever carried: stamps issued
    /// before the sidecar existed, by another node (counters seeded
    /// from bee), or into a data dir since lost or replaced, were never
    /// recorded here.
    #[must_use]
    pub fn stamp_records_unavailable(&self) -> Option<&'static str> {
        self.stamp_persistence_failed
    }

    /// `Some(error)` while the `.stamps` sidecar's compaction keeps
    /// failing (the last attempt's error), `None` when it has never
    /// failed or the latest attempt succeeded. Unlike
    /// [`Self::stamp_records_unavailable`] this does not stop issuance —
    /// appends still land and the records stay complete — but the file
    /// grows by one record per re-stamp until a rewrite succeeds, and on
    /// a full disk the appends themselves fail next.
    #[must_use]
    pub fn stamp_compaction_error(&self) -> Option<&str> {
        self.compaction_error.as_deref()
    }

    /// Remember the stamp issued for a **new** `addr` and, for persistent
    /// issuers, append its checksummed record to the `.stamps` sidecar
    /// (append + fsync) so a restart recovers it. `O(1)`. The in-memory
    /// record is only taken once the append succeeded: on an error the
    /// stamp is never returned to a caller, so `seen` must not claim it
    /// was issued (see [`Self::append_and_maybe_compact`]).
    fn record_stamp(
        &mut self,
        addr: [u8; 32],
        stamp: [u8; STAMP_SIZE],
    ) -> Result<(), PostageError> {
        self.append_and_maybe_compact(addr, stamp)
    }

    /// Refresh the stamp for an already-recorded address (a re-stamp that
    /// only changed the timestamp/signature — the bucket slot is
    /// unchanged). Same on-disk path as a fresh stamp: **append** a new
    /// checksummed record (never overwrite in place). Appending is what
    /// makes a torn write survivable — a crash mid-append can only damage
    /// the trailing record, and the address's previous valid record still
    /// recovers its slot on load — while [`Self::append_and_maybe_compact`]
    /// bounds growth so re-stamps don't grow the file without limit.
    fn refresh_cached_stamp(
        &mut self,
        addr: [u8; 32],
        stamp: [u8; STAMP_SIZE],
    ) -> Result<(), PostageError> {
        self.append_and_maybe_compact(addr, stamp)
    }

    /// Append one record to the sidecar, then compact if the physical
    /// record count has grown past a small multiple of the live entry
    /// count (re-stamps append newer copies that pile up until then).
    /// Compaction rewrites the file atomically (temp + rename) with one
    /// record per live address.
    fn append_and_maybe_compact(
        &mut self,
        addr: [u8; 32],
        stamp: [u8; STAMP_SIZE],
    ) -> Result<(), PostageError> {
        let Some(path) = self.stamps_path.clone() else {
            self.seen.insert(addr, stamp); // in-memory issuer
            return Ok(());
        };
        // Append first, remember second. A failed append returns `Err`,
        // so the caller never hands this stamp out; recording it in
        // `seen` anyway would make `cached_stamp` (and the stamp-record
        // endpoints built on it) report a stamp that was never issued
        // and that a restart doesn't reload. A refresh keeps the
        // address's previous stamp, which is also what the sidecar still
        // holds (a rolled-back or torn append leaves the old record as
        // the last valid one).
        if let Err(e) = append_stamp_record(&path, &self.batch_id, &addr, &stamp) {
            if !e.rolled_back {
                // A torn frame is stuck at EOF and a later successful
                // append would bury it mid-file, checksum-killing
                // everything after the tear on the next load. Poison the
                // issuer: no more appends this session, so the tear
                // stays at EOF where the loader heals it on restart —
                // trailing-partial truncation for a torn record, the
                // empty/header-prefix recovery for a torn FIRST append.
                self.stamp_persistence_failed =
                    Some("torn sidecar append could not be rolled back");
            }
            return Err(PostageError::Persist(e.msg));
        }
        self.seen.insert(addr, stamp);
        self.stamp_record_count += 1;
        self.maybe_compact(&path);
        Ok(())
    }

    /// Compact the sidecar once its physical record count has grown past
    /// `live × STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR`. Best-effort:
    /// it only runs after the record that triggered it was durably
    /// appended (and is already in `seen`), and a failed rewrite leaves
    /// the old, valid, appendable file in place (temp + rename), the
    /// same state [`load_stamp_store`] keeps appending to when its own
    /// compaction fails. So the failure is not the stamp's: returning
    /// `Err` here would refuse a stamp that is recorded in memory and on
    /// disk, and the stamp-record readers would then report a stamp the
    /// caller was told never happened. Instead the next attempt is put
    /// off until another `max(live, STAMP_COMPACT_FLOOR)` records have
    /// been appended, so a persistent failure costs one rewrite attempt
    /// per that many stamps rather than one per stamp.
    fn maybe_compact(&mut self, path: &Path) {
        let threshold = self.seen.len() * STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR;
        if self.stamp_record_count <= threshold || self.stamp_record_count < self.compact_retry_at {
            return;
        }
        match rewrite_sidecar(path, &self.batch_id, &self.seen) {
            Ok(()) => {
                if self.compaction_error.take().is_some() {
                    tracing::info!(
                        target: "ant_postage::stamps",
                        sidecar = %path.display(),
                        live = self.seen.len(),
                        "stamp sidecar compaction recovered",
                    );
                }
                self.stamp_record_count = self.seen.len();
                self.compact_retry_at = 0;
            }
            Err(e) => {
                self.compact_retry_at =
                    self.stamp_record_count + self.seen.len().max(STAMP_COMPACT_FLOOR);
                tracing::warn!(
                    target: "ant_postage::stamps",
                    sidecar = %path.display(),
                    records = self.stamp_record_count,
                    live = self.seen.len(),
                    retry_at = self.compact_retry_at,
                    error = %e,
                    "stamp sidecar compaction failed; stamps still recorded, file keeps growing until a retry succeeds",
                );
                self.compaction_error = Some(e.to_string());
            }
        }
    }

    /// [`Self::record_stamp`] for a batch: one sidecar append, one
    /// `fsync`. Same poisoning on a torn write as a single append.
    fn record_stamps(
        &mut self,
        records: &[([u8; 32], [u8; STAMP_SIZE])],
    ) -> Result<(), PostageError> {
        // Same order as `append_and_maybe_compact`: only a durable
        // append makes the stamps part of `seen`. On an error the whole
        // batch is failed and none of these stamps leaves the process.
        let path = self.stamps_path.clone();
        if let Some(path) = &path {
            if let Err(e) = append_stamp_records(path, &self.batch_id, records) {
                if !e.rolled_back {
                    self.stamp_persistence_failed =
                        Some("torn sidecar append could not be rolled back");
                }
                return Err(PostageError::Persist(e.msg));
            }
        }
        for (addr, stamp) in records {
            self.seen.insert(*addr, *stamp);
        }
        let Some(path) = path else {
            return Ok(()); // in-memory issuer
        };
        self.stamp_record_count += records.len();
        self.maybe_compact(&path);
        Ok(())
    }

    /// Reserve the next index for `addr` in memory only. The caller must
    /// [`Self::persist`] before any stamp built on it leaves the process.
    fn reserve_index(&mut self, addr: &[u8; 32]) -> Result<[u8; INDEX_SIZE], PostageError> {
        let b_idx = collision_bucket_from_addr(self.bucket_depth, addr);
        let mut cnt = self.buckets.get(b_idx as usize).copied().unwrap_or(0);
        if cnt == self.bucket_upper_bound() {
            if self.immutable {
                return Err(PostageError::BucketFull);
            }
            cnt = 0;
        }
        cnt += 1;
        self.buckets[b_idx as usize] = cnt;
        Ok(index_bytes(b_idx, cnt - 1))
    }

    /// Reserve the next index in the bucket the chunk address falls in.
    ///
    /// **Persistence**: when this issuer was built via
    /// [`StampIssuer::open_or_new`], the updated counters are flushed
    /// to disk before this call returns. A crash anywhere after this
    /// point is therefore safe; a crash *before* this point loses an
    /// in-flight stamp the network never saw.
    pub fn increment(
        &mut self,
        addr: &[u8; 32],
    ) -> Result<([u8; INDEX_SIZE], [u8; TIMESTAMP_SIZE]), PostageError> {
        let b_idx = collision_bucket_from_addr(self.bucket_depth, addr);
        let cnt = self.buckets.get(b_idx as usize).copied().unwrap_or(0);
        let upper = self.bucket_upper_bound();

        let mut cnt = cnt;
        if cnt == upper {
            if self.immutable {
                return Err(PostageError::BucketFull);
            }
            cnt = 0;
            self.buckets[b_idx as usize] = 0;
        }

        cnt += 1;
        self.buckets[b_idx as usize] = cnt;
        self.persist()?;

        Ok((index_bytes(b_idx, cnt - 1), unix_now_nanos_be()))
    }

    /// Write the current counter state to disk atomically: write to a
    /// `.tmp` sibling, fsync, rename over the canonical path. No-op for
    /// in-memory issuers (no `persist_path`). Surfaced in the public
    /// API so ops can force a flush on demand (e.g. before snapshotting
    /// the data dir for migration).
    pub fn persist(&self) -> Result<(), PostageError> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        let bytes = encode_store(
            &self.batch_id,
            self.batch_depth,
            self.bucket_depth,
            self.immutable,
            &self.buckets,
        );
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    PostageError::Persist(format!("create_dir_all {}: {e}", parent.display()))
                })?;
            }
        }
        let tmp = path.with_extension("tmp");
        atomic_write(&tmp, path, &bytes)
            .map_err(|e| PostageError::Persist(format!("{}: {e}", path.display())))?;
        Ok(())
    }
}

/// Decoded header (everything before the buckets blob) used to
/// validate that an on-disk store really belongs to the batch we're
/// about to use it with.
struct StoreHeader {
    batch_id: [u8; 32],
    batch_depth: u8,
    bucket_depth: u8,
    immutable: bool,
}

fn encode_store(
    batch_id: &[u8; 32],
    batch_depth: u8,
    bucket_depth: u8,
    immutable: bool,
    buckets: &[u32],
) -> Vec<u8> {
    let body_len = STORE_HEADER_LEN + 4 * buckets.len();
    let mut out = Vec::with_capacity(body_len + 32);
    out.extend_from_slice(STORE_MAGIC);
    out.extend_from_slice(&STORE_VERSION.to_le_bytes());
    out.push(batch_depth);
    out.push(bucket_depth);
    out.push(u8::from(immutable));
    out.extend_from_slice(&[0u8; 7]);
    out.extend_from_slice(batch_id);
    for &b in buckets {
        out.extend_from_slice(&b.to_le_bytes());
    }
    debug_assert_eq!(out.len(), body_len);
    let digest = Keccak256::digest(&out);
    out.extend_from_slice(&digest);
    out
}

fn decode_header(bytes: &[u8]) -> Result<StoreHeader, PostageError> {
    if bytes.len() < STORE_HEADER_LEN + 32 {
        return Err(PostageError::Load(format!(
            "file too short: {} bytes (need ≥ {})",
            bytes.len(),
            STORE_HEADER_LEN + 32
        )));
    }
    if &bytes[0..4] != STORE_MAGIC {
        return Err(PostageError::Load(format!(
            "bad magic: 0x{}",
            hex::encode(&bytes[0..4])
        )));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != STORE_VERSION {
        return Err(PostageError::Load(format!(
            "unsupported version {version} (expected {STORE_VERSION})"
        )));
    }
    let batch_depth = bytes[6];
    let bucket_depth = bytes[7];
    // Same bounds `build` enforces, plus a ceiling at 32 (bucket indices
    // are u32). Without this a corrupt or crafted header with a huge
    // `bucket_depth` reaches `decode_buckets` and its `1 << bucket_depth`
    // sizing, which aborts the process instead of failing the load. The
    // span `batch_depth - bucket_depth` is bounded too: it sizes each
    // bucket's `u32` capacity in `bucket_upper_bound`, where an
    // oversized span would overflow the shift (a panic in debug, a
    // silently masked bogus capacity in release).
    if bucket_depth == 0
        || bucket_depth >= batch_depth
        || bucket_depth > 32
        || batch_depth - bucket_depth > MAX_BUCKET_SPAN
    {
        return Err(PostageError::Load(format!(
            "invalid depths: bucket_depth {bucket_depth}, batch_depth {batch_depth} \
             (need 0 < bucket_depth < batch_depth, bucket_depth <= 32 and \
             batch_depth - bucket_depth <= {MAX_BUCKET_SPAN})"
        )));
    }
    let immutable = bytes[8] != 0;
    let mut batch_id = [0u8; 32];
    batch_id.copy_from_slice(&bytes[16..48]);
    Ok(StoreHeader {
        batch_id,
        batch_depth,
        bucket_depth,
        immutable,
    })
}

fn decode_buckets(bytes: &[u8], bucket_depth: u8) -> Result<Vec<u32>, PostageError> {
    let n = 1usize
        .checked_shl(u32::from(bucket_depth))
        .ok_or_else(|| PostageError::Load("bucket_depth overflow".into()))?;
    // Checked so an oversized depth can never wrap to a small length that
    // matches a short file; overflow is reported as a size mismatch.
    let body_len = n
        .checked_mul(4)
        .and_then(|b| b.checked_add(STORE_HEADER_LEN));
    let expected = body_len.and_then(|b| b.checked_add(32));
    let (Some(body_len), Some(expected)) = (body_len, expected) else {
        return Err(PostageError::Load(format!(
            "size mismatch: file is {} bytes, expected more than usize::MAX \
             for bucket_depth {bucket_depth}",
            bytes.len(),
        )));
    };
    if bytes.len() != expected {
        return Err(PostageError::Load(format!(
            "size mismatch: file is {} bytes, expected {expected}",
            bytes.len(),
        )));
    }
    let body = &bytes[..body_len];
    let trailer = &bytes[body_len..body_len + 32];
    let digest = Keccak256::digest(body);
    if trailer != digest.as_slice() {
        return Err(PostageError::Load(format!(
            "checksum mismatch (file: {}, computed: {})",
            hex::encode(trailer),
            hex::encode(digest)
        )));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = STORE_HEADER_LEN + 4 * i;
        out.push(u32::from_le_bytes([
            body[off],
            body[off + 1],
            body[off + 2],
            body[off + 3],
        ]));
    }
    Ok(out)
}

fn atomic_write(tmp: &Path, dest: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, dest)?;
    if let Some(parent) = dest.parent() {
        // Best-effort fsync of the directory so the rename is durable.
        // Platforms where opening a directory for fsync isn't supported
        // (Windows) just silently skip — we cap that here so a failure
        // doesn't bubble up as a fatal stamp issuance error.
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[must_use]
pub fn unix_now_nanos_be() -> [u8; TIMESTAMP_SIZE] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut b = [0u8; TIMESTAMP_SIZE];
    b.copy_from_slice(&now.to_be_bytes());
    b
}

/// Matches bee `pkg/postage/stampissuer.go::toBucket`: top `depth` bits of address as BE u32,
/// masked to collision bucket slots.
#[must_use]
pub fn collision_bucket_from_addr(bucket_depth: u8, addr: &[u8; 32]) -> u32 {
    let top = u32::from_be_bytes(addr[0..4].try_into().unwrap());
    top >> (32 - u32::from(bucket_depth))
}

fn index_bytes(bucket: u32, within_bucket: u32) -> [u8; INDEX_SIZE] {
    let mut out = [0u8; INDEX_SIZE];
    out[0..4].copy_from_slice(&bucket.to_be_bytes());
    out[4..8].copy_from_slice(&within_bucket.to_be_bytes());
    out
}

#[must_use]
pub fn postage_sign_digest(
    chunk_addr: &[u8; 32],
    batch_id: &[u8; 32],
    index: &[u8; 8],
    ts: &[u8; 8],
) -> [u8; 32] {
    let mut h = Keccak256::default();
    h.update(chunk_addr);
    h.update(batch_id);
    h.update(index);
    h.update(ts);
    let out = h.finalize();
    out.into()
}

/// Build a stamped full binary stamp — same layout as bee `Stamp.MarshalBinary`.
pub fn sign_stamp_bytes(
    secret: &[u8; SECP256K1_SECRET_LEN],
    issuer: &mut StampIssuer,
    chunk_address: &[u8; 32],
) -> Result<[u8; STAMP_SIZE], PostageError> {
    // Refuse to issue when a persistent issuer's sidecar is broken.
    // Failing closed here — before consuming a bucket index — is the
    // only safe choice: a stamp we can't persist would push to the
    // network and then vanish from our address→slot map on restart, so
    // a re-push burns a fresh index and, at capacity, evicts another
    // chunk (mutable) or is rejected (immutable). An *intentional*
    // in-memory issuer (`stamp_persistence_failed` None) is unaffected.
    if let Some(reason) = issuer.stamp_persistence_failed {
        // Keep the structured `Persist` classification (downstream
        // callers may match on it); its "persist postage state:" prefix
        // is accurate here — the sidecar is postage state we couldn't
        // persist, which is why we refuse to issue.
        return Err(PostageError::Persist(format!(
            "stamp sidecar unusable ({reason}); refusing to issue a non-durable \
             stamp — fix the data dir and restart to recover"
        )));
    }
    // Idempotent per chunk SLOT, not per stamp: an address we've stamped
    // before reuses its (bucket, index) — a re-push (heal / retry /
    // resume) costs no new bucket slot — but the timestamp is refreshed
    // and the stamp re-signed, mirroring bee's stamper
    // (`pkg/postage/stamper.go`: a known address gets
    // `BatchTimestamp = unixTime()` before signing). Returning the
    // byte-identical old stamp instead breaks single-owner-chunk
    // *updates*: bee's reserve treats a same-(batch, index) put whose
    // timestamp is not strictly newer as `ErrOverwriteNewerChunk` and
    // rejects it, so a GSOC update at its stable address would never
    // land on any storer (found live on mainnet, 2026-07-13: update #2
    // of a GSOC room was acked but silently dropped network-wide).
    if let Some(prev) = issuer.cached_stamp(chunk_address) {
        let index: [u8; INDEX_SIZE] = prev[32..40].try_into().expect("stamp layout");
        // Strictly-newer timestamp, guaranteed. bee's reserve rejects a
        // same-(batch, index) put whose timestamp isn't greater than the
        // stored one, so `now` alone is unsafe: coarse clock resolution
        // (two re-stamps in one tick) or a backward clock step would
        // re-create the very rejection this path fixes. Take
        // `max(now, prev + 1)`.
        let prev_ts = u64::from_be_bytes(prev[40..48].try_into().expect("stamp layout"));
        let now = u64::from_be_bytes(unix_now_nanos_be());
        let ts = now.max(prev_ts.saturating_add(1)).to_be_bytes();
        let digest = postage_sign_digest(chunk_address, &issuer.batch_id, &index, &ts);
        let sig = sign_handshake_data(secret, &digest)?;
        let mut fresh = [0u8; STAMP_SIZE];
        fresh[0..32].copy_from_slice(&issuer.batch_id);
        fresh[32..40].copy_from_slice(&index);
        fresh[40..48].copy_from_slice(&ts);
        fresh[48..113].copy_from_slice(&sig);
        // Persist the refreshed stamp by overwriting the address's
        // existing sidecar record in place: no file growth on re-push,
        // and the on-disk timestamp stays current so a restart can't
        // reload a stale one and re-emit a timestamp the network saw.
        issuer.refresh_cached_stamp(*chunk_address, fresh)?;
        return Ok(fresh);
    }

    let (index, ts) = issuer.increment(chunk_address)?;
    let digest = postage_sign_digest(chunk_address, &issuer.batch_id, &index, &ts);
    let sig = sign_handshake_data(secret, &digest)?;

    let mut stamp = [0u8; STAMP_SIZE];
    stamp[0..32].copy_from_slice(&issuer.batch_id);
    stamp[32..40].copy_from_slice(&index);
    stamp[40..48].copy_from_slice(&ts);
    stamp[48..113].copy_from_slice(&sig);
    issuer.record_stamp(*chunk_address, stamp)?;
    Ok(stamp)
}

/// Stamp many chunks with one durable write instead of one per chunk.
///
/// [`sign_stamp_bytes`] persists the bucket table (a full rewrite plus
/// `fsync`s) and appends a sidecar record (another `fsync`) for every new
/// chunk. On a phone a `fsync` costs milliseconds to tens of
/// milliseconds (`F_FULLFSYNC` on iOS), so a 100-chunk video segment
/// spent most of its time waiting on the disk. Here every new index is
/// reserved in memory, the table is persisted **once**, the stamps are
/// signed, and their sidecar records are appended **once**, all before
/// any stamp is returned. The crash rule is unchanged: no stamp leaves
/// before both its index and its record are durable, so an index is
/// never issued twice.
///
/// Results come back in input order, one per address, with the same
/// per-chunk semantics as [`sign_stamp_bytes`]: a known address (or one
/// repeated in the batch) keeps its slot and gets a strictly newer
/// timestamp; a full bucket on an immutable batch is
/// [`PostageError::BucketFull`] for that chunk alone. A persistence
/// failure fails every chunk that needed it.
pub fn sign_stamps_batch(
    secret: &[u8; SECP256K1_SECRET_LEN],
    issuer: &mut StampIssuer,
    addrs: &[[u8; 32]],
) -> Vec<Result<[u8; STAMP_SIZE], PostageError>> {
    if let Some(reason) = issuer.stamp_persistence_failed {
        return addrs
            .iter()
            .map(|_| {
                Err(PostageError::Persist(format!(
                    "stamp sidecar unusable ({reason}); refusing to issue a non-durable \
                     stamp — fix the data dir and restart to recover"
                )))
            })
            .collect();
    }
    // Slot + timestamp per address, decided before anything is written.
    enum Plan {
        Ready([u8; INDEX_SIZE], [u8; TIMESTAMP_SIZE]),
        Failed(PostageError),
    }
    let mut last_ts: HashMap<[u8; 32], ([u8; INDEX_SIZE], u64)> = HashMap::new();
    let mut fresh_indices = false;
    let now = u64::from_be_bytes(unix_now_nanos_be());
    let plans: Vec<Plan> = addrs
        .iter()
        .map(|addr| {
            let known = last_ts.get(addr).copied().or_else(|| {
                issuer.cached_stamp(addr).map(|prev| {
                    let index: [u8; INDEX_SIZE] = prev[32..40].try_into().expect("stamp layout");
                    (
                        index,
                        u64::from_be_bytes(prev[40..48].try_into().expect("stamp layout")),
                    )
                })
            });
            let (index, ts) = match known {
                // Strictly newer than the stamp it replaces (bee rejects a
                // same-index put that isn't), as in `sign_stamp_bytes`.
                Some((index, prev_ts)) => (index, now.max(prev_ts.saturating_add(1))),
                None => match issuer.reserve_index(addr) {
                    Ok(index) => {
                        fresh_indices = true;
                        (index, now)
                    }
                    Err(e) => return Plan::Failed(e),
                },
            };
            last_ts.insert(*addr, (index, ts));
            Plan::Ready(index, ts.to_be_bytes())
        })
        .collect();

    if fresh_indices {
        if let Err(e) = issuer.persist() {
            let msg = e.to_string();
            return addrs
                .iter()
                .map(|_| Err(PostageError::Persist(msg.clone())))
                .collect();
        }
    }

    let mut out = Vec::with_capacity(addrs.len());
    let mut records = Vec::with_capacity(addrs.len());
    for (addr, plan) in addrs.iter().zip(plans) {
        match plan {
            Plan::Failed(e) => out.push(Err(e)),
            Plan::Ready(index, ts) => {
                let digest = postage_sign_digest(addr, &issuer.batch_id, &index, &ts);
                match sign_handshake_data(secret, &digest) {
                    Ok(sig) => {
                        let mut stamp = [0u8; STAMP_SIZE];
                        stamp[0..32].copy_from_slice(&issuer.batch_id);
                        stamp[32..40].copy_from_slice(&index);
                        stamp[40..48].copy_from_slice(&ts);
                        stamp[48..113].copy_from_slice(&sig);
                        records.push((*addr, stamp));
                        out.push(Ok(stamp));
                    }
                    Err(e) => out.push(Err(e.into())),
                }
            }
        }
    }
    if let Err(e) = issuer.record_stamps(&records) {
        let msg = e.to_string();
        return addrs
            .iter()
            .map(|_| Err(PostageError::Persist(msg.clone())))
            .collect();
    }
    out
}

/// Sidecar path for the per-chunk stamp cache: the counter file's path
/// with its extension swapped to `.stamps` (e.g. `<batch>.bin` →
/// `<batch>.stamps`).
fn stamps_sidecar_path(persist: &Path) -> PathBuf {
    persist.with_extension("stamps")
}

/// Take the store's advisory exclusive lock (`<counter path>.lock`),
/// failing fast if another process (or another issuer in this one)
/// already holds it. See the `_store_lock` field docs for why the lock
/// lives on a dedicated never-renamed file.
fn acquire_store_lock(persist: &Path) -> Result<std::fs::File, PostageError> {
    let mut os = persist.as_os_str().to_owned();
    os.push(".lock");
    let lock_path = PathBuf::from(os);
    if let Some(parent) = lock_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PostageError::Persist(format!("{}: {e}", lock_path.display())))?;
        }
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| PostageError::Persist(format!("{}: {e}", lock_path.display())))?;
    // `fs4` (flock(2) via rustix on Unix, LockFileEx on Windows) rather
    // than std's `File::try_lock`: std (at least through Rust 1.94) reports
    // "try_lock() not supported" on Android, which failed every batch
    // registration there (#95). Our lock must not depend on which
    // toolchain an embedder builds with.
    // Called as `FileExt::try_lock` so the std inherent method doesn't win.
    match fs4::FileExt::try_lock(&f) {
        Ok(()) => Ok(f),
        Err(fs4::TryLockError::WouldBlock) => Err(PostageError::Persist(format!(
            "postage store {} is locked by another issuer/process — two issuers over one \
             store would double-issue (batch, bucket, index) tuples",
            persist.display()
        ))),
        Err(fs4::TryLockError::Error(e)) => Err(PostageError::Persist(format!(
            "{}: acquiring store lock: {e}",
            lock_path.display()
        ))),
    }
}

/// The 4-byte record checksum: first bytes of `keccak256(addr ‖ stamp)`.
fn stamp_record_checksum(addr: &[u8; 32], stamp: &[u8; STAMP_SIZE]) -> [u8; STAMP_CHECKSUM_LEN] {
    let mut h = Keccak256::default();
    h.update(addr);
    h.update(stamp);
    let digest = h.finalize();
    let mut c = [0u8; STAMP_CHECKSUM_LEN];
    c.copy_from_slice(&digest[..STAMP_CHECKSUM_LEN]);
    c
}

/// The 8-byte big-endian timestamp embedded in a stamp (`[40..48]`),
/// used to pick the newest record when an address has several.
fn stamp_timestamp(stamp: &[u8; STAMP_SIZE]) -> u64 {
    u64::from_be_bytes(stamp[40..48].try_into().expect("stamp layout"))
}

/// Result of loading a stamp sidecar.
struct LoadedSidecar {
    /// Latest valid stamp per address.
    map: HashMap<[u8; 32], [u8; STAMP_SIZE]>,
    /// Complete physical frames on disk (valid *and* checksum-invalid),
    /// so the compaction trigger accounts for torn frames too.
    physical_count: usize,
    /// `None` when the sidecar is safe to append to. `Some(reason)` when
    /// the on-disk file exists but couldn't be validated *or* made safe
    /// to write to — appending under it would corrupt framing and lose
    /// the mapping on restart, so the issuer fails closed and surfaces
    /// `reason` to the operator (the specific failure mode, not just
    /// "migration"). `map` still carries whatever valid records we
    /// parsed, for reads.
    unusable_reason: Option<&'static str>,
    /// The error of a load-time v2 compaction that failed (the file
    /// stays appendable); seeds [`StampIssuer::compaction_error`].
    compaction_error: Option<String>,
}

impl LoadedSidecar {
    /// No prior state, and it is safe to start a fresh append — the file
    /// is genuinely absent (or was cleanly removed).
    fn empty() -> Self {
        Self {
            map: HashMap::new(),
            physical_count: 0,
            unusable_reason: None,
            compaction_error: None,
        }
    }

    /// The sidecar exists but can't be safely written; `reason` names the
    /// specific failure mode for operator diagnostics.
    fn broken(map: HashMap<[u8; 32], [u8; STAMP_SIZE]>, reason: &'static str) -> Self {
        Self {
            map,
            physical_count: 0,
            unusable_reason: Some(reason),
            compaction_error: None,
        }
    }

    #[cfg(test)]
    fn appendable(&self) -> bool {
        self.unusable_reason.is_none()
    }
}

/// Load the per-chunk stamp sidecar into `(stamp map, physical record
/// count)`. Best-effort and self-healing:
///
/// - A genuinely **missing** file (`NotFound`) yields an empty,
///   appendable result. A file that exists but can't be validated —
///   unreadable, a corrupt/foreign/unknown-version header, a failed
///   migration, or a failed trailing-partial truncation — is marked
///   **non-appendable** and is **never deleted**: a bad header is
///   indistinguishable from our own file with a flipped bit, and
///   deleting it would trade one corrupt byte for the whole batch's
///   slot mappings. The issuer fails closed and the operator repairs
///   or removes the file explicitly.
/// - A **v1** file (no checksums) is *migrated*, not discarded: its
///   records are read and the file is rewritten as v2, so no reusable
///   slot is lost across the upgrade.
/// - For v2, each record's checksum is verified; a record that fails (a
///   torn append) is skipped. Records are append-only, so an address
///   may appear several times — the **highest-timestamp valid** record
///   wins, which means a torn *latest* write falls back to the previous
///   valid record (its slot survives). A trailing partial record (crash
///   mid-append) is truncated to the last whole-record boundary.
/// - If the file has grown well past the live entry count (re-stamps
///   piling up), it is compacted to one record per address.
///
/// A stale/dropped entry only ever costs a re-stamp, never a wrong
/// stamp, so issuer construction never hard-fails over the sidecar.
fn load_stamp_store(path: &Path, batch_id: &[u8; 32]) -> LoadedSidecar {
    let mut map: HashMap<[u8; 32], [u8; STAMP_SIZE]> = HashMap::new();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        // Genuinely absent → a fresh append is safe.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LoadedSidecar::empty(),
        // The file EXISTS but we can't read it (permissions, I/O error).
        // Appending under an unvalidated header would corrupt it, so fail
        // closed rather than treat it like a missing file.
        Err(_) => return LoadedSidecar::broken(map, "sidecar unreadable (permissions or I/O)"),
    };
    // An EXISTING but empty file provably contains zero records, so it is
    // exactly as safe as an absent one — the first append writes a fresh
    // header. Two real paths land here: a torn FIRST append rolled back
    // to length 0, and a crash between `open(create)` and the header
    // write. Classifying it as a corrupt header would wedge the store
    // permanently over a file with nothing in it.
    if bytes.is_empty() {
        return LoadedSidecar::empty();
    }
    // A file shorter than the header that is a byte-prefix of OUR
    // expected v2 header is a torn first append whose rollback also
    // failed (partial write stopped mid-header, nothing else can
    // produce this shape for this batch). Zero records existed, so
    // truncating to empty is provably safe and un-wedges the store; if
    // the truncate fails, fall through to the fail-closed rule below.
    if bytes.len() < STAMP_STORE_HEADER_LEN {
        let mut expect = Vec::with_capacity(STAMP_STORE_HEADER_LEN);
        expect.extend_from_slice(STAMP_STORE_MAGIC);
        expect.extend_from_slice(&STAMP_STORE_VERSION.to_le_bytes());
        expect.extend_from_slice(batch_id);
        if expect.starts_with(&bytes) {
            let truncated = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|f| f.set_len(0))
                .is_ok();
            if truncated {
                return LoadedSidecar::empty();
            }
        }
    }
    // Foreign / corrupt header: **fail closed, never delete.** A header
    // that doesn't parse is indistinguishable from OUR file with a
    // flipped bit — deleting it would silently discard every recorded
    // slot mapping (the whole batch's issued indices) over one byte of
    // corruption, and the network would then see re-issued indices.
    // Per-record corruption costs one record; header corruption must not
    // cost everything. The operator removes or restores the file and
    // restarts (the fail-closed issuance error says exactly that).
    if bytes.len() < STAMP_STORE_HEADER_LEN
        || &bytes[0..4] != STAMP_STORE_MAGIC
        || &bytes[6..38] != batch_id.as_slice()
    {
        return LoadedSidecar::broken(map, "corrupt or foreign sidecar header");
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    let (record_len, has_checksum) = match version {
        STAMP_STORE_VERSION => (STAMP_RECORD_LEN, true),
        STAMP_STORE_VERSION_V1 => (STAMP_RECORD_LEN_V1, false),
        // Unknown future/foreign version: same fail-closed rule — don't
        // guess at framing and don't destroy what a newer build wrote.
        _ => return LoadedSidecar::broken(map, "unknown sidecar version"),
    };

    // Newest-timestamp-wins per address, keeping only checksum-valid
    // records. Count *every complete physical frame* (valid or not)
    // separately: a checksum-invalid frame still occupies disk space, so
    // it must count toward the compaction trigger or repeated torn
    // writes could grow the file past the bound without ever compacting.
    let mut best_ts: HashMap<[u8; 32], u64> = HashMap::new();
    let mut off = STAMP_STORE_HEADER_LEN;
    let mut physical_frames = 0usize;
    while off + record_len <= bytes.len() {
        physical_frames += 1;
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes[off..off + 32]);
        let mut stamp = [0u8; STAMP_SIZE];
        stamp.copy_from_slice(&bytes[off + 32..off + 32 + STAMP_SIZE]);
        let ok = !has_checksum
            || bytes[off + 32 + STAMP_SIZE..off + record_len]
                == stamp_record_checksum(&addr, &stamp);
        if ok {
            let ts = stamp_timestamp(&stamp);
            if best_ts.get(&addr).is_none_or(|&prev| ts >= prev) {
                best_ts.insert(addr, ts);
                map.insert(addr, stamp);
            }
        }
        off += record_len;
    }

    // v1 files MUST be migrated before any append: appending a 149-byte
    // v2 record under a v1 (145-byte) header would misalign framing and
    // silently lose records on the next load. So if migration fails for a
    // v1 file, mark the sidecar non-appendable — the caller keeps the
    // in-memory map but does NOT append this session (a restart retries
    // migration), rather than corrupting the file. A v2 file whose
    // compaction fails is still safe to append to (same format), so it
    // stays appendable.
    let over_threshold = physical_frames > map.len() * STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR;
    let mut compaction_error = None;
    if !has_checksum || over_threshold {
        let rewritten = rewrite_sidecar(path, batch_id, &map);
        if rewritten.is_ok() {
            let live = map.len();
            return LoadedSidecar {
                map,
                physical_count: live,
                unusable_reason: None,
                compaction_error: None,
            };
        }
        if !has_checksum {
            // v1 migration failed: don't append to the v1 file (framing
            // mismatch), but keep the parsed records for reads.
            return LoadedSidecar::broken(map, "v1→v2 migration failed");
        }
        // v2 compaction failed: keep appending (same format is fine),
        // but say so — the file keeps growing until a retry succeeds.
        if let Err(e) = rewritten {
            tracing::warn!(
                target: "ant_postage::stamps",
                sidecar = %path.display(),
                records = physical_frames,
                live = map.len(),
                error = %e,
                "stamp sidecar compaction failed at load; still appendable",
            );
            compaction_error = Some(e.to_string());
        }
    }
    // Truncate a trailing partial record so the next append is aligned.
    // If the truncation itself fails, the next append would write at the
    // misaligned EOF and shift framing — so fail closed rather than
    // append onto an untruncated tail.
    if off < bytes.len() {
        let truncated = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.set_len(off as u64))
            .is_ok();
        if !truncated {
            return LoadedSidecar::broken(map, "trailing-partial truncation failed");
        }
    }
    LoadedSidecar {
        map,
        physical_count: physical_frames,
        unusable_reason: None,
        compaction_error,
    }
}

/// Rewrite the sidecar with exactly one v2 record per live address, via
/// the crash-durable [`atomic_write`] (temp write + fsync + rename +
/// **parent-dir fsync**, so the rename itself survives a crash). Used to
/// migrate a v1 file and to compact a v2 file whose re-stamp appends have
/// accumulated.
fn rewrite_sidecar(
    path: &Path,
    batch_id: &[u8; 32],
    live: &HashMap<[u8; 32], [u8; STAMP_SIZE]>,
) -> Result<(), PostageError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PostageError::Persist(format!("{}: {e}", path.display())))?;
        }
    }
    let mut buf = Vec::with_capacity(STAMP_STORE_HEADER_LEN + live.len() * STAMP_RECORD_LEN);
    buf.extend_from_slice(STAMP_STORE_MAGIC);
    buf.extend_from_slice(&STAMP_STORE_VERSION.to_le_bytes());
    buf.extend_from_slice(batch_id);
    for (addr, stamp) in live {
        buf.extend_from_slice(addr);
        buf.extend_from_slice(stamp);
        buf.extend_from_slice(&stamp_record_checksum(addr, stamp));
    }
    let tmp = path.with_extension("stamps.tmp");
    atomic_write(&tmp, path, &buf)
        .map_err(|e| PostageError::Persist(format!("{}: {e}", path.display())))
}

/// How an [`append_stamp_record`] failure left the file.
#[derive(Debug)]
struct AppendError {
    /// The file was truncated back to its pre-append length — framing
    /// is intact and future appends stay safe.
    rolled_back: bool,
    msg: String,
}

/// Append one checksummed `(addr, stamp)` record to the sidecar,
/// creating it with a header first if absent, and fsync before
/// returning so a restart recovers it. Append-only: a crash can only
/// damage the trailing record, which the loader truncates or (if a full
/// but torn record) rejects by checksum, leaving the address's earlier
/// record intact.
///
/// **Runtime torn writes are rolled back**, not just crash-time ones:
/// the loader's trailing-partial recovery only runs at startup, so a
/// partial `write_all` here (ENOSPC, I/O error) followed by a later
/// successful append would misalign framing mid-file and silently
/// checksum-kill every record after the tear on the next load. On any
/// write failure the file is truncated back to its pre-append length;
/// if that truncation itself fails, the error says so
/// (`rolled_back = false`) and the caller must poison the issuer.
/// [`append_stamp_record`] for several records with one write and one
/// `fsync`: the batch lands or (on a failed write) is truncated back off
/// as a whole.
fn append_stamp_records(
    path: &Path,
    batch_id: &[u8; 32],
    records: &[([u8; 32], [u8; STAMP_SIZE])],
) -> Result<(), AppendError> {
    use std::io::Write as _;

    let fail = |msg: String| AppendError {
        rolled_back: true, // nothing written yet
        msg,
    };
    if records.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| fail(format!("{}: {e}", path.display())))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| fail(format!("{}: {e}", path.display())))?;
    let pre_len = f
        .metadata()
        .map_err(|e| fail(format!("{}: {e}", path.display())))?
        .len();

    let mut buf = Vec::with_capacity(STAMP_STORE_HEADER_LEN + records.len() * STAMP_RECORD_LEN);
    if pre_len == 0 {
        buf.extend_from_slice(STAMP_STORE_MAGIC);
        buf.extend_from_slice(&STAMP_STORE_VERSION.to_le_bytes());
        buf.extend_from_slice(batch_id);
    }
    for (addr, stamp) in records {
        buf.extend_from_slice(addr);
        buf.extend_from_slice(stamp);
        buf.extend_from_slice(&stamp_record_checksum(addr, stamp));
    }

    let write_result = f.write_all(&buf).and_then(|()| f.sync_all());
    if let Err(e) = write_result {
        let rolled_back = f.set_len(pre_len).and_then(|()| f.sync_all()).is_ok();
        return Err(AppendError {
            rolled_back,
            msg: if rolled_back {
                format!("{}: batch append failed (rolled back): {e}", path.display())
            } else {
                format!(
                    "{}: batch append failed AND rollback truncate failed: {e}",
                    path.display()
                )
            },
        });
    }
    Ok(())
}

fn append_stamp_record(
    path: &Path,
    batch_id: &[u8; 32],
    addr: &[u8; 32],
    stamp: &[u8; STAMP_SIZE],
) -> Result<(), AppendError> {
    use std::io::Write as _;

    let fail = |msg: String| AppendError {
        rolled_back: true, // nothing written yet
        msg,
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| fail(format!("{}: {e}", path.display())))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| fail(format!("{}: {e}", path.display())))?;
    let pre_len = f
        .metadata()
        .map_err(|e| fail(format!("{}: {e}", path.display())))?
        .len();

    let mut buf = Vec::with_capacity(STAMP_STORE_HEADER_LEN + STAMP_RECORD_LEN);
    if pre_len == 0 {
        buf.extend_from_slice(STAMP_STORE_MAGIC);
        buf.extend_from_slice(&STAMP_STORE_VERSION.to_le_bytes());
        buf.extend_from_slice(batch_id);
    }
    buf.extend_from_slice(addr);
    buf.extend_from_slice(stamp);
    buf.extend_from_slice(&stamp_record_checksum(addr, stamp));

    let write_result = f.write_all(&buf).and_then(|()| f.sync_all());
    if let Err(e) = write_result {
        // Truncate the (possibly partial) frame back off so the next
        // append can't land after a tear and shift framing.
        let rolled_back = f.set_len(pre_len).and_then(|()| f.sync_all()).is_ok();
        return Err(AppendError {
            rolled_back,
            msg: if rolled_back {
                format!("{}: append failed (rolled back): {e}", path.display())
            } else {
                format!(
                    "{}: append failed AND rollback truncate failed: {e}",
                    path.display()
                )
            },
        });
    }
    Ok(())
}

pub fn stamp_batch_id(stamp: &[u8]) -> Result<&[u8; 32], PostageError> {
    if stamp.len() != STAMP_SIZE {
        return Err(PostageError::Msg("bad stamp size".into()));
    }
    Ok(stamp[0..32].try_into().unwrap())
}

/// Verify ECDSA signer is `expected_eth` — matches bee `RecoverBatchOwner`.
pub fn verify_stamp_owner(
    chunk_addr: &[u8; 32],
    stamp: &[u8; STAMP_SIZE],
    expected_eth: &[u8; 20],
    depth: u8,
    bucket_depth: u8,
) -> Result<(), PostageError> {
    let batch_id = stamp[0..32].try_into().unwrap();
    let index: &[u8; 8] = stamp[32..40].try_into().unwrap();
    let ts: &[u8; 8] = stamp[40..48].try_into().unwrap();
    let sig: &[u8; 65] = stamp[48..113].try_into().unwrap();

    let digest_arr = postage_sign_digest(chunk_addr, batch_id, index, ts);
    let digest_slice: &[u8] = digest_arr.as_ref();
    let vk = recover_public_key(sig, digest_slice)?;

    bucket_check(chunk_addr, *index, bucket_depth, depth)?;

    let eth = ethereum_address_from_public_key(&vk);
    if eth != *expected_eth {
        return Err(PostageError::Msg("stamp owner mismatch".into()));
    }
    Ok(())
}

fn bucket_check(
    chunk_addr: &[u8; 32],
    index: [u8; 8],
    bucket_depth: u8,
    depth: u8,
) -> Result<(), PostageError> {
    let bucket = collision_bucket_from_addr(bucket_depth, chunk_addr);
    let exp_bucket = read_u32_be(&index[0..4]);
    if bucket != exp_bucket {
        return Err(PostageError::Msg("bucket mismatch".into()));
    }

    let within = read_u32_be(&index[4..8]);
    // `depth`/`bucket_depth` come from the caller's batch record, not a
    // validated issuer, so the span is checked rather than shifted raw.
    let max_idx = bucket_capacity(depth, bucket_depth).ok_or_else(|| {
        PostageError::Msg(format!(
            "invalid depths: depth {depth}, bucket_depth {bucket_depth}"
        ))
    })?;
    if within >= max_idx {
        return Err(PostageError::Msg("invalid stamp index".into()));
    }
    Ok(())
}

/// Largest `batch_depth - bucket_depth` whose per-bucket capacity
/// `2^span` still fits the `u32` bucket counters and stamp indices.
const MAX_BUCKET_SPAN: u8 = 31;

/// Per-bucket capacity `2^(batch_depth - bucket_depth)`, or `None` when
/// `bucket_depth > batch_depth` or the span exceeds [`MAX_BUCKET_SPAN`].
/// (Issuers additionally require `bucket_depth < batch_depth`.)
fn bucket_capacity(batch_depth: u8, bucket_depth: u8) -> Option<u32> {
    batch_depth
        .checked_sub(bucket_depth)
        .filter(|span| *span <= MAX_BUCKET_SPAN)
        .map(|span| 1u32 << u32::from(span))
}

fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}

/// Optional signer identity check helper.
#[must_use]
pub fn eth_address_matches_key(pubkey_eth: &[u8; 20], vk: &VerifyingKey) -> bool {
    ethereum_address_from_public_key(vk) == *pubkey_eth
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::random_secp256k1_secret;
    use std::path::PathBuf;

    fn tmpdir() -> PathBuf {
        // A bare nanosecond timestamp collides when two tests start
        // within the same clock tick (coarse on some platforms), and
        // their per-test `remove_dir_all` then races — one test wipes
        // another's `batch.bin`. A per-call atomic counter guarantees a
        // distinct directory regardless of clock resolution.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "ant-postage-test-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n,
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn addr(i: u32) -> [u8; 32] {
        ant_crypto::keccak256(&i.to_be_bytes())
    }

    /// A sidecar append that fails and is rolled back returns `Err`, so
    /// the stamp never leaves the process; the in-memory records must
    /// not claim it either (they back `cached_stamp` and the stamp-record
    /// endpoints), and must agree with what a reopen loads. Covers a new
    /// stamp, a refresh of a known one, and a batch.
    #[cfg(unix)]
    #[test]
    fn a_failed_sidecar_append_records_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let secret = random_secp256k1_secret();
        let batch = [0x6bu8; 32];
        let dir = tmpdir();
        let path = dir.join("b.bin");
        let sidecar = stamps_sidecar_path(&path);
        let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 20, 16, false).unwrap();
        let known = sign_stamp_bytes(&secret, &mut issuer, &addr(7)).unwrap();

        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o400)).unwrap();
        if std::fs::OpenOptions::new()
            .append(true)
            .open(&sidecar)
            .is_ok()
        {
            // Running as root: permissions don't bite, nothing to test.
            eprintln!("skipped: sidecar stayed writable (root?)");
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
            return;
        }
        assert!(sign_stamp_bytes(&secret, &mut issuer, &addr(8)).is_err());
        assert!(sign_stamp_bytes(&secret, &mut issuer, &addr(7)).is_err());
        let batch_res = sign_stamps_batch(&secret, &mut issuer, &[addr(9), addr(10), addr(7)]);
        assert!(batch_res.iter().all(Result::is_err));
        // A cleanly rolled-back failure doesn't poison the issuer…
        assert_eq!(issuer.stamp_records_unavailable(), None);
        // …so the records have to be right on their own.
        for a in [8, 9, 10] {
            assert_eq!(issuer.cached_stamp(&addr(a)), None, "chunk {a}");
        }
        assert_eq!(
            issuer.cached_stamp(&addr(7)),
            Some(known),
            "refresh kept the old stamp"
        );

        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(issuer);
        let reopened = StampIssuer::open_existing(path).unwrap();
        for a in [8, 9, 10] {
            assert_eq!(reopened.cached_stamp(&addr(a)), None, "chunk {a}");
        }
        assert_eq!(reopened.cached_stamp(&addr(7)), Some(known));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A compaction that fails after the triggering record was durably
    /// appended doesn't fail that stamp: the record is in memory and on
    /// disk, so refusing it would make the records claim a stamp the
    /// caller was told never happened. The failed rewrite is retried
    /// only after a back-off, and runs again once the disk recovers.
    #[test]
    fn a_failed_compaction_does_not_fail_the_stamp() {
        let secret = random_secp256k1_secret();
        let batch = [0x6cu8; 32];
        let dir = tmpdir();
        let path = dir.join("b.bin");
        let sidecar = stamps_sidecar_path(&path);
        let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 20, 16, false).unwrap();
        sign_stamp_bytes(&secret, &mut issuer, &addr(7)).unwrap();
        // A directory where the rewrite's temp file goes blocks every
        // compaction (as root too), while appends keep working.
        let tmp = sidecar.with_extension("stamps.tmp");
        std::fs::create_dir(&tmp).unwrap();
        // Refreshes of one address pile up records until the count
        // passes `1 × FACTOR + FLOOR` and compaction is attempted.
        let mut last = None;
        for i in 0..(STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR + 4) {
            let s = sign_stamp_bytes(&secret, &mut issuer, &addr(7))
                .unwrap_or_else(|e| panic!("refresh {i} refused: {e}"));
            last = Some(s);
        }
        let new: Vec<[u8; 32]> = (20..23).map(addr).collect();
        let batch_out: Vec<_> = sign_stamps_batch(&secret, &mut issuer, &new)
            .into_iter()
            .map(|r| r.expect("batch stamp after a failed compaction"))
            .collect();
        assert!(issuer.compact_retry_at > 0, "compaction backed off");
        let err = issuer
            .stamp_compaction_error()
            .expect("a failed compaction is surfaced")
            .to_owned();
        assert!(err.contains("stamps"), "names the sidecar: {err}");
        assert!(
            issuer.stamp_record_count > issuer.seen.len(),
            "not compacted"
        );
        assert_eq!(issuer.stamp_records_unavailable(), None);
        assert_eq!(issuer.cached_stamp(&addr(7)), last);

        // Disk recovers: the next attempt after the back-off compacts.
        std::fs::remove_dir(&tmp).unwrap();
        while issuer.compact_retry_at != 0 {
            last = Some(sign_stamp_bytes(&secret, &mut issuer, &addr(7)).unwrap());
        }
        assert_eq!(issuer.stamp_record_count, issuer.seen.len(), "compacted");
        assert_eq!(issuer.stamp_compaction_error(), None, "cleared on success");

        drop(issuer);
        let reopened = StampIssuer::open_existing(path).unwrap();
        assert_eq!(reopened.cached_stamp(&addr(7)), last);
        for (a, s) in new.iter().zip(&batch_out) {
            assert_eq!(reopened.cached_stamp(a), Some(*s));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A compaction that fails while *loading* an oversized sidecar is
    /// surfaced the same way (the file stays appendable), and a reopen
    /// whose compaction succeeds reports nothing.
    #[test]
    fn a_failed_load_time_compaction_is_surfaced() {
        let secret = random_secp256k1_secret();
        let batch = [0x6du8; 32];
        let dir = tmpdir();
        let path = dir.join("b.bin");
        let sidecar = stamps_sidecar_path(&path);
        let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 20, 16, false).unwrap();
        let tmp = sidecar.with_extension("stamps.tmp");
        std::fs::create_dir(&tmp).unwrap();
        for _ in 0..(STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR + 4) {
            sign_stamp_bytes(&secret, &mut issuer, &addr(7)).unwrap();
        }
        drop(issuer);

        let mut reopened = StampIssuer::open_existing(path.clone()).unwrap();
        assert!(
            reopened.stamp_compaction_error().is_some(),
            "load-time failure surfaced"
        );
        assert_eq!(
            reopened.stamp_records_unavailable(),
            None,
            "still appendable"
        );
        sign_stamp_bytes(&secret, &mut reopened, &addr(8)).expect("append still works");
        drop(reopened);

        std::fs::remove_dir(&tmp).unwrap();
        let healed = StampIssuer::open_existing(path).unwrap();
        assert_eq!(healed.stamp_compaction_error(), None);
        assert_eq!(
            healed.stamp_record_count,
            healed.seen.len(),
            "compacted at load"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A batch reserves exactly the indices one-by-one stamping would,
    /// and everything it issued is on disk when it returns: a reopened
    /// issuer has the same counters and the same stamps.
    #[test]
    fn a_batch_issues_what_single_stamps_would_and_persists_it() {
        let secret = random_secp256k1_secret();
        let batch = [0x5au8; 32];
        let addrs: Vec<[u8; 32]> = (0..200).map(addr).collect();

        let dir_a = tmpdir();
        let mut batched =
            StampIssuer::open_or_new(dir_a.join("b.bin"), batch, 20, 16, false).unwrap();
        let stamps: Vec<_> = sign_stamps_batch(&secret, &mut batched, &addrs)
            .into_iter()
            .map(Result::unwrap)
            .collect();

        let dir_b = tmpdir();
        let mut single =
            StampIssuer::open_or_new(dir_b.join("b.bin"), batch, 20, 16, false).unwrap();
        for (a, s) in addrs.iter().zip(&stamps) {
            let one = sign_stamp_bytes(&secret, &mut single, a).unwrap();
            assert_eq!(one[32..40], s[32..40], "same bucket index");
        }
        assert_eq!(batched.buckets, single.buckets);

        drop(batched);
        let reopened = StampIssuer::open_or_new(dir_a.join("b.bin"), batch, 20, 16, false).unwrap();
        assert_eq!(reopened.buckets, single.buckets, "counters persisted");
        for (a, s) in addrs.iter().zip(&stamps) {
            assert_eq!(reopened.cached_stamp(a), Some(*s), "stamp recorded");
        }
        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    /// A chunk stamped before, or twice in one batch, keeps its slot and
    /// gets a strictly newer timestamp each time.
    #[test]
    fn a_batch_restamps_known_and_repeated_chunks_in_place() {
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let mut issuer =
            StampIssuer::open_or_new(dir.join("b.bin"), [1u8; 32], 20, 16, false).unwrap();
        let first = sign_stamp_bytes(&secret, &mut issuer, &addr(7)).unwrap();
        let counters = issuer.buckets.clone();
        let out: Vec<_> = sign_stamps_batch(&secret, &mut issuer, &[addr(7), addr(7)])
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(issuer.buckets, counters, "no new slot for a known chunk");
        let ts = |s: &[u8; STAMP_SIZE]| u64::from_be_bytes(s[40..48].try_into().unwrap());
        assert_eq!(out[0][32..40], first[32..40]);
        assert_eq!(out[1][32..40], first[32..40]);
        assert!(ts(&out[0]) > ts(&first) && ts(&out[1]) > ts(&out[0]));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// On an immutable batch a full bucket fails that chunk only.
    #[test]
    fn a_batch_fails_only_the_chunks_whose_bucket_is_full() {
        let secret = random_secp256k1_secret();
        // Depth one above the bucket depth: two slots per bucket.
        let mut issuer = StampIssuer::new([2u8; 32], 17, 16, true).unwrap();
        let a = addr(1);
        let bucket = collision_bucket_from_addr(16, &a);
        let mut same_bucket = (2..1_000_000)
            .map(addr)
            .filter(|c| collision_bucket_from_addr(16, c) == bucket);
        sign_stamp_bytes(&secret, &mut issuer, &a).unwrap();
        sign_stamp_bytes(&secret, &mut issuer, &same_bucket.next().unwrap()).unwrap();
        // A third chunk in the same (now full) bucket.
        let third = same_bucket.next().unwrap();
        let out = sign_stamps_batch(&secret, &mut issuer, &[third, addr(1_000_001)]);
        assert!(matches!(out[0], Err(PostageError::BucketFull)));
        assert!(out[1].is_ok());
    }

    /// Not an assertion, a figure: how much a batch saves on this disk.
    /// `cargo test -p ant-postage --release -- --ignored --nocapture batch_vs_single`
    #[test]
    #[ignore = "timing, run by hand"]
    fn batch_vs_single_stamping_cost() {
        let secret = random_secp256k1_secret();
        let addrs: Vec<[u8; 32]> = (0..110).map(addr).collect(); // one 720p segment
        let dir = tmpdir();
        let mut one =
            StampIssuer::open_or_new(dir.join("one.bin"), [3u8; 32], 22, 16, false).unwrap();
        let t = std::time::Instant::now();
        for a in &addrs {
            sign_stamp_bytes(&secret, &mut one, a).unwrap();
        }
        let single = t.elapsed();
        let mut many =
            StampIssuer::open_or_new(dir.join("many.bin"), [4u8; 32], 22, 16, false).unwrap();
        let t = std::time::Instant::now();
        for r in sign_stamps_batch(&secret, &mut many, &addrs) {
            r.unwrap();
        }
        let batched = t.elapsed();
        println!(
            "110 chunks: one by one {:?} ({:?}/chunk), batched {:?} ({:?}/chunk)",
            single,
            single / 110,
            batched,
            batched / 110
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The store lock must actually be taken — not error out as
    /// unsupported (std's `File::try_lock` does on Android, #95, which
    /// failed every `register_batch`) — must refuse a second issuer over
    /// the same store, and must be released when the holder drops.
    #[test]
    fn store_lock_is_exclusive_and_released_on_drop() {
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x95; 32];
        let first = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true)
            .expect("store lock must be supported on this platform");
        match StampIssuer::open_or_new(path.clone(), batch, 21, 16, true) {
            Err(PostageError::Persist(msg)) => {
                assert!(msg.contains("is locked by another"), "{msg}");
            }
            other => panic!(
                "second issuer over a held store must fail: {:?}",
                other.err()
            ),
        }
        drop(first);
        StampIssuer::open_or_new(path, batch, 21, 16, true)
            .expect("lock is released when the holder drops");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stamp_roundtrip_owner() {
        let secret = random_secp256k1_secret();
        let sk = k256::ecdsa::SigningKey::from_bytes(&secret.into()).unwrap();
        let vk = *sk.verifying_key();
        let owner = ethereum_address_from_public_key(&vk);
        let mut batch = [0u8; 32];
        batch[0] = 0xab;
        let mut issuer = StampIssuer::new(batch, 21, 16, false).unwrap();
        let chunk = [7u8; 32];

        let stamp = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
        verify_stamp_owner(
            &chunk,
            &stamp,
            &owner,
            issuer.batch_depth,
            issuer.bucket_depth,
        )
        .unwrap();
    }

    /// Re-stamping a known address must reuse its (bucket, index) slot
    /// but refresh the timestamp and re-sign — bee's stamper semantics.
    /// Returning the byte-identical cached stamp breaks SOC updates:
    /// bee's reserve rejects a same-(batch, index) put whose timestamp
    /// isn't strictly newer (`ErrOverwriteNewerChunk`), so a GSOC
    /// update at its stable address never lands anywhere (found live
    /// on mainnet 2026-07-13).
    #[test]
    fn restamp_reuses_slot_with_fresh_timestamp() {
        let secret = random_secp256k1_secret();
        let sk = k256::ecdsa::SigningKey::from_bytes(&secret.into()).unwrap();
        let owner = ethereum_address_from_public_key(sk.verifying_key());
        let mut issuer = StampIssuer::new([0xcd; 32], 21, 16, false).unwrap();
        let chunk = [3u8; 32];

        let ts = |s: &[u8; STAMP_SIZE]| u64::from_be_bytes(s[40..48].try_into().unwrap());
        let first = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
        // Rapid-fire re-stamps: each must be strictly newer than the
        // last even inside one clock tick — the monotonic guarantee, not
        // just "call unix_now again". A tight loop is the case coarse
        // resolution would break.
        let mut prev = first;
        for _ in 0..50 {
            let next = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            assert_eq!(&next[32..40], &first[32..40], "index must be reused");
            assert!(
                ts(&next) > ts(&prev),
                "timestamp must be strictly newer ({} vs {})",
                ts(&next),
                ts(&prev)
            );
            prev = next;
        }
        assert_eq!(issuer.issued_count(), 1, "re-stamp must not burn a slot");
        // The refreshed stamp still verifies against the owner.
        verify_stamp_owner(
            &chunk,
            &prev,
            &owner,
            issuer.batch_depth,
            issuer.bucket_depth,
        )
        .unwrap();
        // The cache now holds the latest refreshed stamp.
        assert_eq!(issuer.cached_stamp(&chunk).unwrap(), prev);
    }

    /// Re-stamps append (for crash-safety) but must not grow the sidecar
    /// without bound: compaction caps it at a small multiple of the live
    /// entry count. Hammering one address far past the compaction
    /// threshold must leave the file bounded, not linear in re-stamps.
    #[test]
    fn restamp_growth_is_bounded_by_compaction() {
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let mut issuer = StampIssuer::open_or_new(path.clone(), [0x44; 32], 21, 16, true).unwrap();
        let chunk = [0x5a; 32];
        let sidecar = path.with_extension("stamps");

        // Far more re-stamps than the compaction threshold for one live
        // address (2*1 + 64 = 66).
        for _ in 0..500 {
            sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
        }
        let records = (std::fs::metadata(&sidecar).unwrap().len() as usize
            - STAMP_STORE_HEADER_LEN)
            / STAMP_RECORD_LEN;
        assert!(
            records <= STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR + 1,
            "compaction must bound the file ({records} records after 500 re-stamps)"
        );
        // Only one bucket slot was ever consumed despite all the re-stamps.
        assert_eq!(issuer.issued_count(), 1, "re-stamp must not burn slots");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The refreshed re-stamp timestamp must survive a restart: if it
    /// weren't persisted, a restart (which reloads the sidecar) followed
    /// by a re-stamp under a rolled-back clock would re-emit a timestamp
    /// the network already saw, and peers would reject the chunk as
    /// not-strictly-newer. In place of a real clock rollback we assert
    /// the reloaded stamp equals the last one written (so the next
    /// re-stamp's `max(now, prev+1)` builds on the true high-water mark).
    #[test]
    fn restamp_timestamp_survives_restart() {
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x77; 32];
        let chunk = [0x9c; 32];
        let ts = |s: &[u8; STAMP_SIZE]| u64::from_be_bytes(s[40..48].try_into().unwrap());

        // Issue, then re-stamp several times so the persisted record
        // carries an advanced timestamp (not the original).
        let last = {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
            sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            let mut last = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            for _ in 0..5 {
                last = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            }
            last
        };

        // Restart: a fresh issuer reloads the sidecar. The reloaded stamp
        // must be the LATEST written, not the original — otherwise the
        // high-water mark is lost.
        let mut reopened = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
        let reloaded = reopened.cached_stamp(&chunk).expect("stamp recovered");
        assert_eq!(
            ts(&reloaded),
            ts(&last),
            "restart must reload the latest re-stamp timestamp, not a stale one"
        );

        // And the next re-stamp is still strictly newer than everything
        // the network has seen, even though a new issuer instance began.
        let after_restart = sign_stamp_bytes(&secret, &mut reopened, &chunk).unwrap();
        assert!(
            ts(&after_restart) > ts(&last),
            "post-restart re-stamp must exceed the persisted high-water mark"
        );
        // Append-based: at most a handful of records for one address
        // (compaction bounds it; well under the threshold here).
        let sidecar = path.with_extension("stamps");
        let records = (std::fs::metadata(&sidecar).unwrap().len() as usize
            - STAMP_STORE_HEADER_LEN)
            / STAMP_RECORD_LEN;
        assert!(
            records <= STAMP_COMPACT_FACTOR + STAMP_COMPACT_FLOOR + 1,
            "sidecar stays bounded for one address ({records} records)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A crash mid-append leaves a trailing partial record. The loader
    /// must truncate it so the *next* append writes at a valid boundary
    /// — otherwise framing shifts permanently and every later record
    /// fails to reload.
    #[test]
    fn sidecar_truncates_trailing_partial_record_on_load() {
        use std::io::Write as _;
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x33; 32];
        let sidecar = path.with_extension("stamps");

        let chunk_a = [0xa1; 32];
        {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
            sign_stamp_bytes(&secret, &mut issuer, &chunk_a).unwrap();
        }
        // Simulate a torn append: 20 stray bytes after the good record.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&sidecar)
                .unwrap();
            f.write_all(&[0x77u8; 20]).unwrap();
        }
        assert_eq!(
            std::fs::metadata(&sidecar).unwrap().len() as usize,
            STAMP_STORE_HEADER_LEN + STAMP_RECORD_LEN + 20
        );

        // Reopen: the partial is truncated and the good record recovered.
        let chunk_b = [0xb2; 32];
        let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
        assert!(issuer.has_stamp(&chunk_a), "intact record must survive");
        assert_eq!(
            std::fs::metadata(&sidecar).unwrap().len() as usize,
            STAMP_STORE_HEADER_LEN + STAMP_RECORD_LEN,
            "trailing partial must be truncated on load"
        );
        // A new append lands at the aligned boundary and reloads cleanly.
        sign_stamp_bytes(&secret, &mut issuer, &chunk_b).unwrap();
        drop(issuer);
        let reopened = StampIssuer::open_or_new(path, batch, 21, 16, true).unwrap();
        assert!(reopened.has_stamp(&chunk_a) && reopened.has_stamp(&chunk_b));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A torn in-place overwrite yields a record whose checksum no longer
    /// matches its stamp. The loader must discard that one record (its
    /// address just re-stamps later) while keeping the others — fixed
    /// framing means one corrupt record never shifts its neighbours.
    #[test]
    fn sidecar_discards_checksum_mismatched_record() {
        use std::io::{Seek as _, SeekFrom, Write as _};
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x44; 32];
        let sidecar = path.with_extension("stamps");

        let chunk_a = [0xaa; 32];
        let chunk_b = [0xbb; 32];
        {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
            sign_stamp_bytes(&secret, &mut issuer, &chunk_a).unwrap();
            sign_stamp_bytes(&secret, &mut issuer, &chunk_b).unwrap();
        }
        // Corrupt one byte inside the FIRST record's stamp region without
        // fixing its checksum → simulates a torn write.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&sidecar)
                .unwrap();
            // First record's stamp starts at header + 32 (past the addr).
            f.seek(SeekFrom::Start((STAMP_STORE_HEADER_LEN + 32 + 5) as u64))
                .unwrap();
            f.write_all(&[0xFF]).unwrap();
        }
        let reopened = StampIssuer::open_or_new(path, batch, 21, 16, true).unwrap();
        assert!(
            !reopened.has_stamp(&chunk_a),
            "checksum-mismatched record must be discarded"
        );
        assert!(
            reopened.has_stamp(&chunk_b),
            "the intact neighbour must still load (framing unshifted)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A torn *latest* append (its trailing record corrupt) must fall
    /// back to the address's previous valid record — its bucket slot is
    /// preserved, not lost. Losing it would let a re-stamp burn a fresh
    /// index and, on a full bucket, evict another chunk or (immutable)
    /// reject the existing one.
    #[test]
    fn sidecar_falls_back_to_previous_record_on_torn_latest_append() {
        use std::io::{Seek as _, SeekFrom, Write as _};
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x55; 32];
        let sidecar = path.with_extension("stamps");
        let chunk = [0xcc; 32];
        let ts = |s: &[u8; STAMP_SIZE]| u64::from_be_bytes(s[40..48].try_into().unwrap());

        // Stamp, then re-stamp once → two appended records (old + new).
        let first = {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
            let first = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            let second = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            assert!(ts(&second) > ts(&first));
            first
        };
        assert_eq!(
            (std::fs::metadata(&sidecar).unwrap().len() as usize - STAMP_STORE_HEADER_LEN)
                / STAMP_RECORD_LEN,
            2,
            "two records: the original and the re-stamp"
        );
        // Corrupt the SECOND (latest) record's stamp → torn latest write.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&sidecar)
                .unwrap();
            f.seek(SeekFrom::Start(
                (STAMP_STORE_HEADER_LEN + STAMP_RECORD_LEN + 32 + 7) as u64,
            ))
            .unwrap();
            f.write_all(&[0xFF]).unwrap();
        }
        // Reopen: the slot is recovered from the previous valid record.
        let reopened = StampIssuer::open_or_new(path, batch, 21, 16, true).unwrap();
        let recovered = reopened.cached_stamp(&chunk).expect("slot must survive");
        assert_eq!(
            ts(&recovered),
            ts(&first),
            "must fall back to the previous valid record, not lose the slot"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A v1 sidecar (no checksums) must be **migrated** on load — its
    /// records preserved and the file rewritten as v2 — not deleted.
    /// Deleting would drop reusable slots and, on a full bucket, cause
    /// eviction/rejection.
    #[test]
    fn sidecar_migrates_v1_records_forward() {
        use std::io::Write as _;
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x66; 32];
        let sidecar = path.with_extension("stamps");

        // Hand-write a v1 file: header (magic, version=1, batch) + two
        // v1 records (addr32 ‖ stamp113, no checksum).
        let v1_stamp = |addr: u8, index: u64| -> ([u8; 32], [u8; STAMP_SIZE]) {
            let a = [addr; 32];
            let mut s = [0u8; STAMP_SIZE];
            s[0..32].copy_from_slice(&batch);
            s[32..40].copy_from_slice(&index.to_be_bytes());
            s[40..48].copy_from_slice(&1000u64.to_be_bytes());
            (a, s)
        };
        let (a1, s1) = v1_stamp(0xa1, 1);
        let (a2, s2) = v1_stamp(0xb2, 2);
        {
            std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
            let mut f = std::fs::File::create(&sidecar).unwrap();
            f.write_all(STAMP_STORE_MAGIC).unwrap();
            f.write_all(&STAMP_STORE_VERSION_V1.to_le_bytes()).unwrap();
            f.write_all(&batch).unwrap();
            for (a, s) in [(a1, s1), (a2, s2)] {
                f.write_all(&a).unwrap();
                f.write_all(&s).unwrap();
            }
        }

        // Load migrates: both records preserved, file now v2 (with
        // checksums), one record per address.
        let issuer = StampIssuer::open_or_new(path, batch, 21, 16, true).unwrap();
        assert_eq!(issuer.cached_stamp(&a1), Some(s1), "v1 record 1 preserved");
        assert_eq!(issuer.cached_stamp(&a2), Some(s2), "v1 record 2 preserved");
        let bytes = std::fs::read(&sidecar).unwrap();
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            STAMP_STORE_VERSION,
            "file migrated to v2"
        );
        assert_eq!(
            (bytes.len() - STAMP_STORE_HEADER_LEN) / STAMP_RECORD_LEN,
            2,
            "two v2 records after migration"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// If v1 migration FAILS (e.g. the temp rewrite path can't be
    /// created), the loader must NOT append v2 records under the v1
    /// header — that would misalign framing and lose entries. Instead the
    /// v1 file is left untouched (a restart retries migration) and the
    /// issuer, and stamping must FAIL closed (not silently issue a
    /// non-durable stamp). Once migration can succeed again, the v1
    /// records recover intact — no successfully issued stamp ever
    /// disappears. Regression for the mixed-format-append + fail-open
    /// hazards.
    #[test]
    fn failed_v1_migration_fails_closed_then_recovers() {
        use std::io::Write as _;
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x88; 32];
        let sidecar = path.with_extension("stamps");

        // Hand-write a v1 file with one record.
        let a1 = [0xa1; 32];
        let mut s1 = [0u8; STAMP_SIZE];
        s1[0..32].copy_from_slice(&batch);
        s1[40..48].copy_from_slice(&1234u64.to_be_bytes());
        {
            std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
            let mut f = std::fs::File::create(&sidecar).unwrap();
            f.write_all(STAMP_STORE_MAGIC).unwrap();
            f.write_all(&STAMP_STORE_VERSION_V1.to_le_bytes()).unwrap();
            f.write_all(&batch).unwrap();
            f.write_all(&a1).unwrap();
            f.write_all(&s1).unwrap();
        }
        let v1_bytes_before = std::fs::read(&sidecar).unwrap();

        // Sabotage migration: occupy the exact temp rewrite path
        // (`rewrite_sidecar` uses `<sidecar>.with_extension("stamps.tmp")`)
        // with a directory so `atomic_write`'s File::create fails, while
        // the v1 file itself stays readable/writable.
        let tmp = sidecar.with_extension("stamps.tmp");
        std::fs::create_dir(&tmp).unwrap();

        {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
            // The v1 record is recovered into memory (reads work)…
            assert!(issuer.has_stamp(&a1), "records recovered in memory");
            // …but stamping FAILS CLOSED — no non-durable stamp is issued
            // (the old fail-open bug returned a pushable stamp here whose
            // mapping would vanish on restart).
            let a2 = [0xb2; 32];
            // The error must keep the structured `Persist` classification
            // (downstream callers may match on it) *and* name the
            // specific failure mode (migration here).
            let err = sign_stamp_bytes(&secret, &mut issuer, &a2).unwrap_err();
            assert!(
                matches!(err, PostageError::Persist(_)),
                "must stay classified as Persist, got: {err:?}"
            );
            assert!(
                err.to_string().contains("migration"),
                "error should name the migration failure, got: {err}"
            );
            assert!(
                sign_stamp_bytes(&secret, &mut issuer, &a2).is_err(),
                "must refuse to issue when persistence is broken"
            );
            // A re-stamp of a recovered address must also fail closed.
            assert!(
                sign_stamp_bytes(&secret, &mut issuer, &a1).is_err(),
                "re-stamp must also refuse when persistence is broken"
            );
            // The v1 file is byte-identical — nothing was appended.
            assert_eq!(
                std::fs::read(&sidecar).unwrap(),
                v1_bytes_before,
                "v1 file must be untouched when migration fails"
            );
        }

        // Clear the sabotage → a restart can now migrate. The v1 record
        // recovers intact and stamping works again.
        std::fs::remove_dir(&tmp).unwrap();
        let mut issuer = StampIssuer::open_or_new(path, batch, 21, 16, true).unwrap();
        assert_eq!(
            issuer.cached_stamp(&a1),
            Some(s1),
            "the recovered v1 stamp survives — no successfully issued stamp lost"
        );
        // File is now v2 and stamping succeeds again.
        assert_eq!(
            u16::from_le_bytes({
                let b = std::fs::read(&sidecar).unwrap();
                [b[4], b[5]]
            }),
            STAMP_STORE_VERSION,
            "migrated to v2 after the obstruction cleared"
        );
        sign_stamp_bytes(&secret, &mut issuer, &[0xc3; 32]).expect("stamping works post-migration");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Corrupt (checksum-invalid) full frames still occupy disk, so they
    /// must count toward the compaction trigger — otherwise a stream of
    /// torn full-record writes could grow the file past the bound without
    /// ever compacting. Here we stuff the file with garbage full-length
    /// frames and confirm the next load compacts them away.
    #[test]
    fn corrupt_frames_count_toward_compaction() {
        use std::io::Write as _;
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch = [0x99; 32];
        let sidecar = path.with_extension("stamps");
        let chunk = [0x5a; 32];

        // One real record, then a pile of full-length garbage frames
        // (valid framing, bad checksum) well past the compaction floor.
        {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 21, 16, true).unwrap();
            sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
        }
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&sidecar)
                .unwrap();
            for _ in 0..(STAMP_COMPACT_FLOOR + 5) {
                f.write_all(&[0x00u8; STAMP_RECORD_LEN]).unwrap(); // zero addr+stamp, checksum won't match
            }
        }
        let records_before = (std::fs::metadata(&sidecar).unwrap().len() as usize
            - STAMP_STORE_HEADER_LEN)
            / STAMP_RECORD_LEN;
        assert!(records_before > STAMP_COMPACT_FLOOR);

        // Reopen: the corrupt frames counted toward the trigger, so the
        // file is compacted down to just the one live record.
        let reopened = StampIssuer::open_or_new(path, batch, 21, 16, true).unwrap();
        assert!(reopened.has_stamp(&chunk));
        let records_after = (std::fs::metadata(&sidecar).unwrap().len() as usize
            - STAMP_STORE_HEADER_LEN)
            / STAMP_RECORD_LEN;
        assert_eq!(records_after, 1, "corrupt frames must be compacted away");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A sidecar that EXISTS but can't be read (a non-`NotFound` error)
    /// must fail closed, not be treated like a missing file — appending
    /// under an unvalidated header would corrupt it. Simulated with a
    /// directory at the sidecar path, which `std::fs::read` errors on
    /// (not `NotFound`) on every platform.
    #[test]
    fn unreadable_sidecar_fails_closed() {
        let dir = tmpdir();
        let sidecar = dir.join("x.stamps");
        std::fs::create_dir(&sidecar).unwrap();
        let loaded = load_stamp_store(&sidecar, &[0x22; 32]);
        assert!(
            !loaded.appendable(),
            "an unreadable existing sidecar must fail closed"
        );
        assert!(loaded.map.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A corrupt/foreign-header sidecar fails closed and is NEVER
    /// deleted: one flipped header bit is indistinguishable from a
    /// foreign file, and deleting would silently discard every recorded
    /// slot mapping (the loader used to unlink here — blocker-4
    /// regression).
    #[test]
    fn corrupt_header_fails_closed_and_survives() {
        let dir = tmpdir();
        let sidecar = dir.join("x.stamps");
        // Bad magic, long enough to pass the length check.
        std::fs::write(&sidecar, [0xEEu8; 64]).unwrap();

        let loaded = load_stamp_store(&sidecar, &[0x11; 32]);
        assert!(
            !loaded.appendable(),
            "a corrupt-header sidecar must fail closed"
        );
        assert!(
            sidecar.exists(),
            "the loader must never delete a sidecar it can't parse"
        );

        // Same rule for a well-formed header with an unknown version.
        let mut future = Vec::new();
        future.extend_from_slice(STAMP_STORE_MAGIC);
        future.extend_from_slice(&99u16.to_le_bytes());
        future.extend_from_slice(&[0x11; 32]);
        std::fs::write(&sidecar, &future).unwrap();
        let loaded = load_stamp_store(&sidecar, &[0x11; 32]);
        assert!(!loaded.appendable(), "unknown version must fail closed");
        assert!(sidecar.exists(), "unknown version must not be deleted");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Blocker-3 regression: a runtime append failure must not leave a
    /// torn frame mid-file. The rollback truncates back to the
    /// pre-append length so the next append can't shift framing and
    /// checksum-kill everything after the tear on the next load.
    #[test]
    fn failed_append_rolls_back_to_a_clean_boundary() {
        let dir = tmpdir();
        let sidecar = dir.join("x.stamps");
        let batch_id = [0x22u8; 32];

        // One good record.
        append_stamp_record(&sidecar, &batch_id, &[0xA1; 32], &[0x01; STAMP_SIZE]).unwrap();
        let clean_len = std::fs::metadata(&sidecar).unwrap().len();

        // Simulate the tear a partial write_all leaves behind, then the
        // rollback the fixed append performs.
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&sidecar)
                .unwrap();
            f.write_all(&[0xB2; 40]).unwrap(); // 40 of 149 bytes: torn
            f.set_len(clean_len).unwrap(); // the rollback path
        }

        // Frame boundary intact: the next append lands cleanly and BOTH
        // records survive a reload.
        append_stamp_record(&sidecar, &batch_id, &[0xC3; 32], &[0x02; STAMP_SIZE]).unwrap();
        let loaded = load_stamp_store(&sidecar, &batch_id);
        assert!(loaded.unusable_reason.is_none());
        assert_eq!(
            loaded.map.len(),
            2,
            "no record may be lost after a rollback"
        );
        assert_eq!(loaded.map[&[0xA1; 32]], [0x01; STAMP_SIZE]);
        assert_eq!(loaded.map[&[0xC3; 32]], [0x02; STAMP_SIZE]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The un-rollback-able variant must poison the issuer: with a torn
    /// frame stuck at EOF, any further append would bury the tear
    /// mid-file, so `sign_stamp_bytes` has to refuse until a restart
    /// lets the loader truncate it.
    #[test]
    fn unrolled_torn_append_poisons_the_issuer() {
        let dir = tmpdir();
        let path = dir.join("c.bin");
        let secret = [0x33u8; 32];
        let batch_id = [0x44u8; 32];
        let mut issuer = StampIssuer::open_or_new(path.clone(), batch_id, 17, 16, false).unwrap();
        let a1 = [0xD4u8; 32];
        sign_stamp_bytes(&secret, &mut issuer, &a1).unwrap();

        // Simulate append_stamp_record's worst case having happened.
        issuer.stamp_persistence_failed = Some("torn sidecar append could not be rolled back");
        let a2 = [0xE5u8; 32];
        let err = sign_stamp_bytes(&secret, &mut issuer, &a2).unwrap_err();
        assert!(
            matches!(err, PostageError::Persist(_)),
            "poisoned issuer must fail closed as Persist, got: {err:?}"
        );
        assert!(err.to_string().contains("torn sidecar append"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Round-14 residual #1: a torn FIRST append rolled back to length 0
    /// leaves an existing empty sidecar — which provably holds zero
    /// records and must load as empty/appendable, not wedge the store as
    /// "corrupt header" until an operator deletes an empty file. Same
    /// for the un-rolled-back variant: a partial write that stopped
    /// mid-header is a byte-prefix of our expected header and is
    /// truncated back to empty on load.
    #[test]
    fn zero_byte_and_torn_header_sidecars_recover_on_load() {
        let dir = tmpdir();
        let batch = [0x77u8; 32];

        // Case A: rollback left an existing 0-byte file.
        let empty = dir.join("a.stamps");
        std::fs::write(&empty, b"").unwrap();
        let loaded = load_stamp_store(&empty, &batch);
        assert!(loaded.appendable(), "an empty sidecar must load as fresh");
        assert!(loaded.map.is_empty());
        // …and a subsequent append works normally.
        append_stamp_record(&empty, &batch, &[0xA1; 32], &[0x01; STAMP_SIZE]).unwrap();
        assert_eq!(load_stamp_store(&empty, &batch).map.len(), 1);

        // Case B: rollback failed too — a partial write stopped
        // mid-header. The bytes are a prefix of OUR expected header, so
        // the loader truncates to empty instead of failing closed.
        let torn = dir.join("b.stamps");
        let mut expect = Vec::new();
        expect.extend_from_slice(STAMP_STORE_MAGIC);
        expect.extend_from_slice(&STAMP_STORE_VERSION.to_le_bytes());
        expect.extend_from_slice(&batch);
        std::fs::write(&torn, &expect[..10]).unwrap();
        let loaded = load_stamp_store(&torn, &batch);
        assert!(loaded.appendable(), "a torn first header must recover");
        assert_eq!(std::fs::metadata(&torn).unwrap().len(), 0);

        // Case C: a short file that is NOT a prefix of our header is
        // foreign/corrupt and still fails closed, untouched.
        let foreign = dir.join("c.stamps");
        std::fs::write(&foreign, [0xEE; 10]).unwrap();
        let loaded = load_stamp_store(&foreign, &batch);
        assert!(!loaded.appendable(), "foreign short file must fail closed");
        assert_eq!(std::fs::metadata(&foreign).unwrap().len(), 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two issuers over one store double-issue `(batch, bucket, index)`
    /// tuples, and a concurrent compaction rename can strand the other
    /// handle's append in an unlinked inode — the store lock refuses the
    /// second issuer outright.
    #[test]
    fn second_issuer_on_the_same_store_is_refused() {
        let dir = tmpdir();
        let path = dir.join("c.bin");
        let batch = [0x55u8; 32];
        let first = StampIssuer::open_or_new(path.clone(), batch, 17, 16, false).unwrap();
        let second = StampIssuer::open_or_new(path.clone(), batch, 17, 16, false);
        assert!(
            matches!(second, Err(PostageError::Persist(ref m)) if m.contains("locked")),
            "second issuer must be refused while the first holds the lock, got: {second:?}"
        );
        // Dropping the first releases the lock; a successor opens fine.
        drop(first);
        assert!(StampIssuer::open_or_new(path, batch, 17, 16, false).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A surviving `.stamps` sidecar next to a missing/recreated counter
    /// file means the counters are behind indices the network has seen —
    /// issuing would re-use them. Must fail closed, not silently accept.
    #[test]
    fn surviving_sidecar_with_fresh_counters_fails_closed() {
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("c.bin");
        let batch = [0x66u8; 32];
        let a1 = [0xAB; 32];
        {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 17, 16, false).unwrap();
            sign_stamp_bytes(&secret, &mut issuer, &a1).unwrap();
        }
        // Counter file vanishes (operator mistake, partial restore);
        // the sidecar survives.
        std::fs::remove_file(&path).unwrap();

        let mut issuer = StampIssuer::open_or_new(path.clone(), batch, 17, 16, false).unwrap();
        assert!(issuer.has_stamp(&a1), "recovered stamps stay readable");
        let err = sign_stamp_bytes(&secret, &mut issuer, &[0xCD; 32]).unwrap_err();
        assert!(
            matches!(err, PostageError::Persist(_)),
            "must fail closed as Persist, got: {err:?}"
        );
        assert!(
            err.to_string()
                .contains("counter file was missing/recreated"),
            "error should name the incoherence, got: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The headroom predicates must flag a collision bucket as full once
    /// it reaches capacity — the signal the upload path uses to refuse to
    /// stamp (and thus silently evict) on an under-sized batch.
    #[test]
    fn bucket_full_predicate_flags_saturation() {
        let batch_id = [0x5au8; 32];
        // depth 17, bucket_depth 16 => 2^(17-16) = 2 slots per bucket
        // (the postage minimum — exactly the batch that broke uploads).
        let mut issuer = StampIssuer::new(batch_id, 17, 16, false).unwrap();
        let chunk = [9u8; 32];

        assert!(!issuer.bucket_is_full(&chunk));
        assert!(!issuer.is_saturated());

        // First slot used — still room for one more.
        issuer.increment(&chunk).unwrap();
        assert!(!issuer.bucket_is_full(&chunk));

        // Second slot fills the bucket to capacity: a third stamp would
        // wrap and evict, so the predicate must now refuse it.
        issuer.increment(&chunk).unwrap();
        assert!(issuer.bucket_is_full(&chunk));
        assert!(issuer.is_saturated());

        // A chunk routing to an untouched bucket is still stampable.
        let mut other = [0u8; 32];
        other[0] = 0xff;
        other[1] = 0xff;
        assert!(!issuer.bucket_is_full(&other));
    }

    /// Writing then re-loading the store must preserve every counter
    /// exactly. Catches LE/BE mistakes and length-of-buckets drift.
    #[test]
    fn store_round_trips_counters() {
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch_id = [0xabu8; 32];

        // Use a small bucket_depth so the file stays test-friendly (8 → 256
        // counters → 1 KiB file). batch_depth must be > bucket_depth.
        let mut issuer = StampIssuer::open_or_new(path.clone(), batch_id, 12, 8, true).unwrap();
        // Issue indices on a few different addresses to populate
        // distinct buckets. The exact bucket choice depends on
        // collision_bucket_from_addr but we don't care which buckets
        // get hit — only that they round-trip.
        for i in 0..50u8 {
            let mut addr = [0u8; 32];
            addr[0] = i;
            issuer.increment(&addr).unwrap();
        }
        let total_before = issuer.issued_count();
        assert_eq!(total_before, 50);
        let buckets_before = issuer.buckets.clone();

        // Reload. Counters must match exactly.
        drop(issuer);
        let reloaded = StampIssuer::open_or_new(path, batch_id, 12, 8, true).unwrap();
        assert_eq!(reloaded.issued_count(), 50);
        assert_eq!(reloaded.buckets, buckets_before);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Crash recovery: the persisted state must reflect the most recent
    /// successful `increment`. We simulate the crash by issuing N
    /// stamps, dropping the issuer, and verifying the next instance
    /// keeps issuing from index N — never index 0.
    #[test]
    fn no_index_reissue_after_crash() {
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch_id = [0xcdu8; 32];

        // First run: issue 5 stamps on the same chunk address.
        let mut issuer1 = StampIssuer::open_or_new(path.clone(), batch_id, 14, 8, true).unwrap();
        let chunk = [0u8; 32]; // same bucket every time
        let mut issued: Vec<[u8; 8]> = Vec::new();
        for _ in 0..5 {
            let (idx, _) = issuer1.increment(&chunk).unwrap();
            issued.push(idx);
        }
        // Indices within the bucket should be 0..4.
        for (i, idx) in issued.iter().enumerate() {
            let within = u32::from_be_bytes(idx[4..8].try_into().unwrap());
            assert_eq!(within as usize, i);
        }

        // Simulated crash: drop, then re-open with no graceful shutdown.
        drop(issuer1);

        let mut issuer2 = StampIssuer::open_or_new(path, batch_id, 14, 8, true).unwrap();
        // Next index for the same bucket must be 5, not 0.
        let (idx, _) = issuer2.increment(&chunk).unwrap();
        let within = u32::from_be_bytes(idx[4..8].try_into().unwrap());
        assert_eq!(within, 5, "issuer must resume after crash, not reset");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pointing the issuer at a store from a *different* batch must
    /// fail with `StoreMismatch` so a `--data-dir` typo doesn't cause
    /// us to re-issue indices for the wrong batch.
    #[test]
    fn rejects_store_from_different_batch() {
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch_a = [0xaau8; 32];
        let batch_b = [0xbbu8; 32];

        // Create a store for batch A.
        let _ = StampIssuer::open_or_new(path.clone(), batch_a, 12, 8, true).unwrap();

        // Try to open the same file for batch B.
        let err = StampIssuer::open_or_new(path, batch_b, 12, 8, true).unwrap_err();
        assert!(
            matches!(err, PostageError::StoreMismatch { .. }),
            "expected StoreMismatch, got {err:?}",
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tampering with a single byte after the store was written must
    /// be caught by the checksum trailer.
    #[test]
    fn detects_corruption() {
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch_id = [0xeeu8; 32];
        {
            let mut issuer = StampIssuer::open_or_new(path.clone(), batch_id, 12, 8, true).unwrap();
            // Issue at least one stamp so the buckets blob is non-zero
            // somewhere.
            issuer.increment(&[0u8; 32]).unwrap();
        }
        // Flip a single byte midway through the buckets blob.
        let mut bytes = std::fs::read(&path).unwrap();
        let target = STORE_HEADER_LEN + 16;
        bytes[target] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let err = StampIssuer::open_or_new(path, batch_id, 12, 8, true).unwrap_err();
        assert!(
            matches!(err, PostageError::Load(_)),
            "expected Load error on checksum mismatch, got {err:?}",
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A header with out-of-range depths but a valid magic, version and
    /// checksum trailer must fail the load cleanly, never abort sizing the
    /// bucket vector (bee#5663 analog). `(64, 62)` is the case where
    /// `4 * (1 << 62)` used to wrap to 0 in release builds and let an
    /// 80-byte file through to `Vec::with_capacity(2^62)`.
    #[test]
    fn open_existing_rejects_invalid_depths() {
        let dir = tmpdir();
        for (batch_depth, bucket_depth) in [(64u8, 62u8), (20, 0), (12, 12), (255, 40)] {
            let path = dir.join(format!("{batch_depth}-{bucket_depth}.bin"));
            // Header only, no bucket counters: the length `4 * n` wraps
            // to 0 for depth 62 on 64-bit release builds.
            let bytes = encode_store(&[0x5au8; 32], batch_depth, bucket_depth, true, &[]);
            assert_eq!(bytes.len(), STORE_HEADER_LEN + 32);
            std::fs::write(&path, &bytes).unwrap();
            let err = StampIssuer::open_existing(path).unwrap_err();
            assert!(
                matches!(err, PostageError::Load(_)),
                "({batch_depth}, {bucket_depth}): expected Load, got {err:?}",
            );
            // The sizing in `decode_buckets` must hold on its own too,
            // even if a header check ever lets such a depth through.
            let err = decode_buckets(&bytes, bucket_depth).unwrap_err();
            assert!(
                matches!(err, PostageError::Load(_)),
                "decode_buckets({bucket_depth}): expected Load, got {err:?}",
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A header whose `bucket_depth` is fine but whose span
    /// `batch_depth - bucket_depth` overflows the `u32` per-bucket
    /// capacity must fail the load, even with a correctly sized body and
    /// a valid trailer. `(255, 16)` used to load and then panic in
    /// `bucket_upper_bound` (debug) or report a masked bogus capacity
    /// (release); `(48, 16)` is the first span (32) that no longer fits.
    #[test]
    fn open_existing_rejects_oversized_depth_span() {
        let dir = tmpdir();
        let buckets = vec![0u32; 1 << 16];
        for batch_depth in [255u8, 48] {
            let path = dir.join(format!("span-{batch_depth}.bin"));
            let bytes = encode_store(&[0x5au8; 32], batch_depth, 16, true, &buckets);
            std::fs::write(&path, &bytes).unwrap();
            let err = StampIssuer::open_existing(path).unwrap_err();
            assert!(
                matches!(err, PostageError::Load(_)),
                "({batch_depth}, 16): expected Load, got {err:?}",
            );
        }
        // The widest span that fits (31) still loads, with its true capacity.
        let path = dir.join("span-47.bin");
        std::fs::write(&path, encode_store(&[0x5au8; 32], 47, 16, true, &buckets)).unwrap();
        let issuer = StampIssuer::open_existing(path).unwrap();
        assert_eq!(issuer.bucket_upper_bound(), 1 << 31);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The span bound holds on every other path that sets depths: a fresh
    /// issuer, a dilute, and stamp verification against a batch record.
    #[test]
    fn oversized_depth_span_is_rejected_everywhere() {
        assert!(StampIssuer::new([1u8; 32], 48, 16, true).is_err());
        let mut issuer = StampIssuer::new([1u8; 32], 47, 16, true).unwrap();
        assert!(issuer.set_batch_depth(48).is_err());
        assert_eq!(issuer.batch_depth(), 47);
        assert_eq!(issuer.bucket_upper_bound(), 1 << 31);

        let addr = [0u8; 32];
        let index = [0u8; 8];
        assert!(bucket_check(&addr, index, 16, 47).is_ok());
        for depth in [48u8, 255, 10] {
            assert!(
                bucket_check(&addr, index, 16, depth).is_err(),
                "bucket_check(depth {depth}, bucket_depth 16) must error, not panic",
            );
        }
    }

    /// Re-stamping the same chunk must be idempotent: it returns the
    /// identical stamp and consumes **no** new bucket index. This is the
    /// fix for self-inflicted batch saturation — a heal/retry that
    /// re-pushes already-stamped chunks must not burn postage. We also
    /// prove the exemption: even after the bucket has filled, an
    /// already-stamped chunk still re-stamps (reuses) for free.
    #[test]
    fn restamp_is_idempotent_and_free() {
        let secret = random_secp256k1_secret();
        let batch_id = [0x11u8; 32];
        // depth 17, bucket_depth 16 => 2 slots per bucket.
        let mut issuer = StampIssuer::new(batch_id, 17, 16, true).unwrap();
        let chunk = [0x42u8; 32];

        let first = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
        let issued_after_first = issuer.issued_count();
        assert_eq!(issued_after_first, 1);
        assert!(issuer.has_stamp(&chunk));

        // Re-stamp the same chunk several times: the (bucket, index)
        // slot is reused — no new index — but each stamp carries a
        // fresh timestamp and signature (bee stamper semantics; a
        // byte-identical replay would make SOC updates undeliverable).
        for _ in 0..5 {
            let again = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            assert_eq!(&again[32..40], &first[32..40], "index slot is reused");
        }
        assert_eq!(
            issuer.issued_count(),
            issued_after_first,
            "re-stamping must not consume bucket slots",
        );

        // Fill the bucket with a *different* chunk in the same bucket so
        // it saturates, then prove the already-stamped chunk still
        // re-stamps for free despite the full bucket.
        let mut sibling = chunk;
        sibling[31] = 0x01; // same top bits => same collision bucket
        sign_stamp_bytes(&secret, &mut issuer, &sibling).unwrap();
        assert!(issuer.bucket_is_full(&chunk));
        let after_full = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
        assert_eq!(&after_full[32..40], &first[32..40]);
    }

    /// The `.stamps` sidecar must survive a restart so a later heal
    /// (manual "Push again") reuses stamps instead of re-issuing them.
    #[test]
    fn stamp_cache_persists_across_restart() {
        let secret = random_secp256k1_secret();
        let dir = tmpdir();
        let path = dir.join("batch.bin");
        let batch_id = [0x22u8; 32];

        let chunk = [0x99u8; 32];
        let original = {
            let mut issuer =
                StampIssuer::open_or_new(path.clone(), batch_id, 17, 16, true).unwrap();
            let s = sign_stamp_bytes(&secret, &mut issuer, &chunk).unwrap();
            assert_eq!(issuer.issued_count(), 1);
            s
        };
        assert!(path.with_extension("stamps").exists());

        // Reopen — the cache should rehydrate, so a re-stamp reuses the
        // original slot (same index, fresh timestamp) and issues no new
        // index.
        let mut reopened = StampIssuer::open_or_new(path, batch_id, 17, 16, true).unwrap();
        assert!(reopened.has_stamp(&chunk));
        let reused = sign_stamp_bytes(&secret, &mut reopened, &chunk).unwrap();
        assert_eq!(&reused[32..40], &original[32..40], "index slot is reused");
        assert_eq!(reopened.issued_count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
