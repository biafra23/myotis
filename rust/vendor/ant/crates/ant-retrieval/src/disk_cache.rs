//! Persistent (SQLite-backed) chunk cache — tier 2 of the cache stack
//! described in `PLAN.md` § 6.1.
//!
//! Network retrieval already validates every chunk on the wire (see
//! [`crate::retrieve_chunk`]) before any cache write. **Bee’s
//! `chunkstore.Get` trusts on-disk bytes the same way** — it reads the
//! retrieval index and sharky blob and returns `swarm.NewChunk` in Go
//! without re-proving the BMT against the address. This implementation matches
//! that contract: disk hits return stored wire bytes without
//! [`ant_crypto::cac_valid`] / [`ant_crypto::soc_valid`]. Bitrot or manual
//! edits can still poison a chunk until the next network refresh replaces
//! the row; that is the same durability model as bee’s localstore cache
//! path.
//!
//! One exception: a row stored at a dispersed-replica SOC address
//! (`keccak256(id ‖ REPLICAS_OWNER)`) is re-checked with
//! [`ant_crypto::soc_valid`] on every hit and read as a miss if it
//! fails. Builds before the replica id rule (bee#5640) accepted and
//! cached forged replicas signed with the public replicas key; without
//! this they would keep being served from disk after an upgrade and
//! block replica recovery. The filter is one keccak per hit; only the
//! rare replica rows pay the full SOC check. A miss sends the caller to
//! the network, and the validated replica it fetches overwrites the
//! row. See [`forged_replica_row`].
//!
//! Concurrency (bee-ish throughput goals):
//!
//! - **Dedicated read threads** — `get` is a prepared `SELECT` on a read-only
//!   WAL connection; jobs are routed round-robin over crossbeam channels (no
//!   `spawn_blocking` on the hot path). Pool size comes from
//!   [`DiskCacheTuning`] (2 by default on every platform), not the core count.
//! - **Dedicated writer thread** — all mutating work (batched `put`s,
//!   `last_access` touches past the freshness window, eviction) runs on
//!   one thread with **batched transactions** so bursts amortise fsync.
//! - **Pragmas** — `mmap_size` / `cache_size` on every connection, kept
//!   small so memory doesn't grow with the file ([`DiskCacheTuning`]).
//!
//! Async rule: `get` / `row_count` ship work to dedicated **read threads**
//! (each with a prepared `SELECT`) over a bounded channel — no
//! `spawn_blocking` hot path — so Tokio workers stay lightweight.

use crossbeam_channel::{
    bounded as cb_bounded, Receiver as CbReceiver, Sender as CbSender, TryRecvError,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

/// Default eviction "slack" — how far below the cap we drain on every
/// trigger. 95% means an over-cap insert deletes ~5% of the cap in
/// `last_access` order rather than one row at a time, keeping the
/// per-write eviction cost amortised. Mirrors the guidance in
/// `PLAN.md` § 6.1.
const EVICTION_SLACK_RATIO: f64 = 0.95;

/// How "fresh" `last_access` must already be for [`DiskChunkCache::get`]
/// to skip a touch write entirely. 60 s keeps hot reads as plain
/// `SELECT`s on the reader connections; rare `UPDATE`s go through the
/// writer queue.
const LAST_ACCESS_REFRESH_MS: i64 = 60_000;

/// Max `put` + `touch` rows coalesced into one writer transaction before commit.
/// Larger batches amortise WAL fsync against bursty write-through.
const WRITE_BATCH_MAX: usize = 256;

/// How much memory the cache's `SQLite` connections may use: the read
/// threads (one connection each, next to the writer's), and the file
/// mapping and page cache of every connection.
///
/// Both budgets are per connection, so they multiply by
/// `read_workers + 1`. `SQLite` maps up to `mmap_bytes` of the file
/// separately on each connection: iOS caps an app's address space
/// without the extended-virtual-addressing entitlement, and nine
/// 512 MiB mappings of a cache file larger than that reserved about
/// 4.5 GiB and crashed the app once anything else needed some. The
/// page cache is heap: iOS and Android count it against the app's
/// memory limit, and on desktop a per-core reader pool with 256 MiB
/// each let antd's memory grow by several GiB once the file passed the
/// mapped 512 MiB (issue #152).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskCacheTuning {
    /// Dedicated read threads, each with its own read-only connection
    /// and prepared statements.
    pub read_workers: usize,
    /// `PRAGMA mmap_size` per connection, in bytes. 0 reads every page
    /// into the page cache instead.
    pub mmap_bytes: u64,
    /// `PRAGMA cache_size` per connection, in bytes.
    pub page_cache_bytes: u64,
}

impl DiskCacheTuning {
    /// The tuning on every platform: two read threads, nothing mapped
    /// and 8 MiB of page cache per connection, so the three
    /// connections reserve no address space for the file and their
    /// page caches total at most 24 MiB of heap, however big the cache
    /// file grows. On top of that each connection maps the small WAL
    /// index (`-shm`, 32 KiB per 4,000 or so WAL frames), and a one-off
    /// legacy `VACUUM` builds its temp copy in memory (at most 64 MiB,
    /// only for a small pre-incremental-vacuum cache file).
    ///
    /// Measured on a 1.17 GiB cache file with random reads on a
    /// 14-core Mac (issue #152), this beat the old desktop profile (a
    /// reader per core, 512 MiB mapped and 256 MiB of page cache per
    /// connection) on memory and speed alike: +41 MiB footprint
    /// instead of +922 MiB and growing, 173k instead of 98k reads/s and
    /// a p99 of 0.9 ms instead of 8.8 ms at 64 concurrent reads. Four
    /// readers were no faster than two, and a 2 MiB page cache cut
    /// throughput by a quarter to a third.
    pub const DEFAULT: Self = Self {
        read_workers: 2,
        mmap_bytes: 0,
        page_cache_bytes: 8 * 1024 * 1024,
    };
}

impl Default for DiskCacheTuning {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Default size cap for the persistent chunk cache. 10 GB matches
/// `PLAN.md` § 6.1's desktop / Raspberry Pi default. Operators on
/// constrained boxes (mobile / embedded) should set a smaller cap;
/// power users should raise it.
pub const DEFAULT_DISK_CACHE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Error, Clone)]
pub enum DiskCacheError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("io: {0}")]
    Io(String),
    #[error("background worker panicked")]
    Panicked,
    #[error("disk cache writer stopped")]
    WriterStopped,
}

impl From<rusqlite::Error> for DiskCacheError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e.to_string())
    }
}

impl From<std::io::Error> for DiskCacheError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Pin membership rows: `(pinned root reference, member chunk
/// addresses)`.
pub type PinMembership = Vec<(Vec<u8>, Vec<[u8; 32]>)>;

/// SQLite-backed persistent chunk cache.
pub struct DiskChunkCache {
    inner: Arc<Inner>,
}

enum WriteMsg {
    Put {
        addr: [u8; 32],
        data: Vec<u8>,
        ack: oneshot::Sender<Result<(), DiskCacheError>>,
    },
    PutBatch {
        items: Vec<([u8; 32], Vec<u8>)>,
        ack: oneshot::Sender<Result<(), DiskCacheError>>,
    },
    Touch {
        addr: [u8; 32],
        last_access: i64,
    },
    /// Pin bookkeeping (see [`PinOp`]). Routed through the writer
    /// thread even for the read-shaped queries: pin traffic is rare
    /// (operator / bee-`/pins` actions, not the chunk hot path), and a
    /// single serialisation point keeps the pin tables and the
    /// `pin_count` budget accounting trivially consistent.
    Pin(PinOp),
    /// Change the byte cap at runtime; evicts (and reclaims the freed
    /// file space) at once when the new cap is below the current
    /// total. See [`DiskChunkCache::set_capacity`].
    SetCapacity {
        max_bytes: u64,
        ack: oneshot::Sender<Result<(), DiskCacheError>>,
    },
    /// Drop every unpinned row and give the space back to the OS. See
    /// [`DiskChunkCache::clear_unpinned`].
    ClearUnpinned {
        ack: oneshot::Sender<Result<ClearReport, DiskCacheError>>,
    },
    Shutdown,
}

/// Outcome of [`DiskChunkCache::clear_unpinned`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClearReport {
    /// Unpinned rows deleted.
    pub removed_chunks: u64,
    /// Chunk bytes those rows held (what [`DiskChunkCache::used_bytes`]
    /// dropped by).
    pub freed_bytes: u64,
    /// [`DiskChunkCache::file_bytes`] before the clear.
    pub file_bytes_before: u64,
    /// [`DiskChunkCache::file_bytes`] after the delete, the vacuum and
    /// the WAL checkpoint.
    pub file_bytes_after: u64,
}

/// Pinned-row totals, mirrored the same way as `total_bytes` /
/// `total_rows`: maintained by the writer thread inside every pin
/// transaction so a status read never runs a query.
#[derive(Default)]
struct PinTotals {
    /// Bytes of rows with `pin_count > 0` (outside the budget).
    bytes: AtomicU64,
    /// Rows with `pin_count > 0`.
    rows: AtomicU64,
    /// Rows in `pins` (pinned root references).
    collections: AtomicU64,
    /// Rows in `pin_members`: each collection's distinct members,
    /// summed — a chunk shared by two pins counts twice (bee's
    /// `/debugstore` `Pinning.TotalChunks`).
    member_refs: AtomicU64,
}

/// Pin mutations and queries handled by the writer thread.
///
/// **Eviction invariant** (documented once, here): a chunk row with
/// `pin_count > 0` is *outside the cache budget* — its bytes are not
/// part of `total_bytes` (which tracks evictable bytes only) and the
/// eviction sweep never visits it. Pinning a chunk (0→1) subtracts its
/// size from the budget; dropping the last pin (1→0) adds it back and
/// re-checks the cap. `pin_count` is a reference count because two
/// pinned roots may share chunks (bee's pinstore refcounts the same
/// way); a chunk becomes evictable again only when *every* pin
/// covering it is removed.
enum PinOp {
    /// Record a pin collection: the root `reference` (32-byte plain or
    /// 64-byte encrypted reference), plus every member chunk of its
    /// tree with the wire bytes (inserted if not already cached).
    /// Replies `Ok(false)` when the reference was already pinned
    /// (idempotent, nothing written), `Ok(true)` when freshly pinned.
    Collection {
        reference: Vec<u8>,
        members: Vec<([u8; 32], Vec<u8>)>,
        ack: oneshot::Sender<Result<bool, DiskCacheError>>,
    },
    /// Drop a pin: decrement `pin_count` on every recorded member and
    /// delete the membership rows. Replies `Ok(false)` when the
    /// reference wasn't pinned.
    Unpin {
        reference: Vec<u8>,
        ack: oneshot::Sender<Result<bool, DiskCacheError>>,
    },
    Has {
        reference: Vec<u8>,
        ack: oneshot::Sender<Result<bool, DiskCacheError>>,
    },
    /// Every pinned reference, in pin-creation order.
    List {
        ack: oneshot::Sender<Result<Vec<Vec<u8>>, DiskCacheError>>,
    },
    /// Recorded member addresses per pin (all pins, or just
    /// `reference`). Backs the `/pins/check` integrity walk.
    Members {
        reference: Option<Vec<u8>>,
        ack: oneshot::Sender<Result<PinMembership, DiskCacheError>>,
    },
}

enum ReadJob {
    Get {
        addr: [u8; 32],
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DiskCacheError>>,
    },
    Count {
        reply: oneshot::Sender<Result<u64, DiskCacheError>>,
    },
    Shutdown,
}

struct Inner {
    path: PathBuf,
    read_tx: Vec<CbSender<ReadJob>>,
    read_rr: AtomicUsize,
    read_joins: Mutex<Vec<JoinHandle<()>>>,
    write_tx: CbSender<WriteMsg>,
    writer_thread: Mutex<Option<JoinHandle<()>>>,
    /// Byte cap. Written only by the writer thread (on open and on
    /// [`WriteMsg::SetCapacity`]) so it always matches the cap the
    /// eviction sweep actually enforces.
    max_bytes: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    /// Live row count mirrored from `COUNT(*) FROM chunks`. Maintained
    /// by the writer thread alongside `total_bytes` so `antop` can show
    /// the chunk count without round-tripping a SQL query on every
    /// status tick. Reads `0` between `open()` returning and the
    /// initial `SELECT COUNT(*)` finishing (cosmetic; same trade-off as
    /// `total_bytes`).
    total_rows: Arc<AtomicU64>,
    /// Pinned rows / bytes (see [`PinTotals`]). Same backfill caveat as
    /// `total_rows`.
    pinned: Arc<PinTotals>,
    /// Read-worker pool size (`DiskCacheTuning::read_workers`, floored
    /// at 1), captured once at open time so the status snapshot can
    /// surface the size actually spawned.
    read_workers: usize,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for tx in &self.read_tx {
            let _ = tx.send(ReadJob::Shutdown);
        }
        if let Ok(mut joins) = self.read_joins.lock() {
            for h in joins.drain(..) {
                let _ = h.join();
            }
        }
        let _ = self.write_tx.send(WriteMsg::Shutdown);
        if let Ok(mut g) = self.writer_thread.lock() {
            if let Some(h) = g.take() {
                let _ = h.join();
            }
        }
    }
}

impl DiskChunkCache {
    /// Open (or create) a chunk cache database at `path` with a
    /// `max_bytes` byte cap and [`DiskCacheTuning::DEFAULT`].
    pub fn open(path: impl AsRef<Path>, max_bytes: u64) -> Result<Self, DiskCacheError> {
        Self::open_with_tuning(path, max_bytes, DiskCacheTuning::DEFAULT)
    }

    /// [`Self::open`] with explicit [`DiskCacheTuning`].
    pub fn open_with_tuning(
        path: impl AsRef<Path>,
        max_bytes: u64,
        tuning: DiskCacheTuning,
    ) -> Result<Self, DiskCacheError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let total_bytes = Arc::new(AtomicU64::new(0));
        let total_rows = Arc::new(AtomicU64::new(0));
        let pinned = Arc::new(PinTotals::default());
        let max_bytes_shared = Arc::new(AtomicU64::new(max_bytes));
        let tb = total_bytes.clone();
        let tr = total_rows.clone();
        let tp = pinned.clone();
        let tm = max_bytes_shared.clone();

        // The schema is in place once this returns; the writer thread
        // takes the connection over for everything after.
        let conn = open_write_connection(&path, tuning)?;
        let (write_tx, write_rx) = cb_bounded::<WriteMsg>(65_536);
        let path_thread = path.clone();
        let write_tx_main = write_tx.clone();

        let join = std::thread::Builder::new()
            .name("ant-disk-cache-writer".into())
            .spawn(move || {
                if let Err(e) = writer_main(conn, path_thread, write_rx, tb, tr, tp, tm) {
                    warn!(
                        target: "ant_retrieval::disk_cache",
                        "writer thread exited with error: {e}",
                    );
                }
            })
            .map_err(|e| DiskCacheError::Io(e.to_string()))?;

        let n_read = tuning.read_workers.max(1);
        let mut read_tx = Vec::with_capacity(n_read);
        let mut read_joins = Vec::with_capacity(n_read);
        for i in 0..n_read {
            let (job_tx, job_rx) = cb_bounded::<ReadJob>(4096);
            let path_r = path.clone();
            let wt = write_tx.clone();
            let j = std::thread::Builder::new()
                .name(format!("ant-disk-cache-read-{i}"))
                .spawn(move || read_worker_loop(path_r, tuning, job_rx, wt))
                .map_err(|e| DiskCacheError::Io(e.to_string()))?;
            read_tx.push(job_tx);
            read_joins.push(j);
        }

        debug!(
            target: "ant_retrieval::disk_cache",
            path = %path.display(),
            initial_total = total_bytes.load(Ordering::Relaxed),
            max_bytes,
            read_workers = n_read,
            mmap_bytes = tuning.mmap_bytes,
            page_cache_bytes = tuning.page_cache_bytes,
            "opened persistent chunk cache",
        );

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                read_tx,
                read_rr: AtomicUsize::new(0),
                read_joins: Mutex::new(read_joins),
                write_tx: write_tx_main,
                writer_thread: Mutex::new(Some(join)),
                max_bytes: max_bytes_shared,
                total_bytes,
                total_rows,
                pinned,
                read_workers: n_read,
            }),
        })
    }

    /// Live row count (mirrored from `COUNT(*)` and maintained in
    /// transactions on every write / eviction). Reads `0` until the
    /// initial backfill scan completes (~30 s on a cold 7 GB cache);
    /// see the rationale in `writer_main`.
    #[must_use]
    pub fn used_rows(&self) -> u64 {
        self.inner.total_rows.load(Ordering::Relaxed)
    }

    /// Number of dedicated read worker threads servicing `get`
    /// requests. Set at `open()` time and held constant for the
    /// lifetime of the cache.
    #[must_use]
    pub fn read_workers(&self) -> usize {
        self.inner.read_workers
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    #[must_use]
    pub fn capacity_bytes(&self) -> u64 {
        self.inner.max_bytes.load(Ordering::Relaxed)
    }

    /// Bytes of *unpinned* rows — the ones counted against
    /// [`Self::capacity_bytes`] and subject to eviction.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.inner.total_bytes.load(Ordering::Relaxed)
    }

    /// Bytes of pinned rows (`pin_count > 0`), held outside the budget.
    /// Mirrored counter, same backfill caveat as [`Self::used_rows`].
    #[must_use]
    pub fn pinned_bytes(&self) -> u64 {
        self.inner.pinned.bytes.load(Ordering::Relaxed)
    }

    /// Number of pinned rows. [`Self::used_rows`] includes these.
    #[must_use]
    pub fn pinned_rows(&self) -> u64 {
        self.inner.pinned.rows.load(Ordering::Relaxed)
    }

    /// Number of pinned root references (pin collections).
    #[must_use]
    pub fn pin_collections(&self) -> u64 {
        self.inner.pinned.collections.load(Ordering::Relaxed)
    }

    /// Members summed over every pin collection; a chunk two pins share
    /// counts twice. Bee reports this as `Pinning.TotalChunks`.
    #[must_use]
    pub fn pin_member_refs(&self) -> u64 {
        self.inner.pinned.member_refs.load(Ordering::Relaxed)
    }

    /// Size on disk of the database plus its `-wal` and `-shm` files
    /// (three `stat`s, no query). Missing files count as zero.
    #[must_use]
    pub fn file_bytes(&self) -> u64 {
        db_file_bytes(&self.inner.path)
    }

    /// Change the byte cap at runtime. When the new cap is below the
    /// current [`Self::used_bytes`], evicts oldest-by-`last_access`
    /// unpinned rows down to the usual slack (95% of the cap) before
    /// returning, then hands the freed pages back to the OS where it can
    /// (see [`Self::clear_unpinned`] and [`reclaim_space`]: a legacy
    /// database is only rebuilt when the remaining data is small and the
    /// disk has room). Pinned rows are never touched.
    ///
    /// The new cap is applied before the eviction runs. On `Err` (the
    /// eviction's SQL failed) it stays applied, part of the eviction may
    /// have committed, and the next `put` evicts down to it again.
    /// Runs on the writer thread, so it is ordered with every `put` and
    /// pin operation.
    pub async fn set_capacity(&self, max_bytes: u64) -> Result<(), DiskCacheError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .write_tx
            .send(WriteMsg::SetCapacity {
                max_bytes,
                ack: ack_tx,
            })
            .map_err(|_| DiskCacheError::WriterStopped)?;
        ack_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    /// Delete every unpinned row and return the space to the OS. Pinned
    /// rows and the `pins` / `pin_members` bookkeeping are left exactly
    /// as they were.
    ///
    /// Runs on the writer thread, so it is serialised with `put`s and
    /// pin operations (a `put` queued behind it lands after the clear;
    /// one ahead of it is cleared). Reads keep going on their own WAL
    /// connections throughout: a `get` racing the clear sees the row or
    /// a miss, never an error.
    ///
    /// Space: a database created by this version uses
    /// `auto_vacuum = INCREMENTAL`, so the freed pages are released with
    /// `PRAGMA incremental_vacuum`. An older database (created without
    /// auto-vacuum, which can only be switched on by rebuilding the
    /// file) is converted with one `VACUUM` on its first clear, but only
    /// if what's left (the pinned rows) is small enough and the volume
    /// has room for the rebuild; otherwise the file keeps its size and
    /// later writes reuse the freed pages. Either way a non-waiting
    /// `wal_checkpoint(TRUNCATE)` follows so the WAL the delete grew is
    /// cut back too. Giving space back is best-effort: once the delete
    /// has committed this returns `Ok`, and `file_bytes_after` shows
    /// what the file actually shrank to.
    pub async fn clear_unpinned(&self) -> Result<ClearReport, DiskCacheError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .write_tx
            .send(WriteMsg::ClearUnpinned { ack: ack_tx })
            .map_err(|_| DiskCacheError::WriterStopped)?;
        ack_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    /// Look up a chunk by address. Trusts stored bytes (bee `chunkstore`
    /// semantics), except that a dispersed-replica SOC failing
    /// [`ant_crypto::soc_valid`] reads as `None` (see the module docs). A stale `last_access` is refreshed via the writer
    /// queue (best-effort). Serviced by a dedicated read thread + prepared
    /// statement (no `spawn_blocking` on the hot path).
    pub async fn get(&self, addr: [u8; 32]) -> Result<Option<Vec<u8>>, DiskCacheError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let i = self.inner.read_rr.fetch_add(1, Ordering::Relaxed) % self.inner.read_tx.len();
        self.inner.read_tx[i]
            .send(ReadJob::Get {
                addr,
                reply: reply_tx,
            })
            .map_err(|_| DiskCacheError::WriterStopped)?;
        reply_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    /// Batched insert / upsert in a **single** writer transaction (amortises
    /// WAL fsync). Prefer this when filling the cache with many freshly
    /// validated chunks at once.
    pub async fn put_batch(&self, items: Vec<([u8; 32], Vec<u8>)>) -> Result<(), DiskCacheError> {
        if items.is_empty() {
            return Ok(());
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .write_tx
            .send(WriteMsg::PutBatch { items, ack: ack_tx })
            .map_err(|_| DiskCacheError::WriterStopped)?;
        ack_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    pub async fn put(&self, addr: [u8; 32], data: Vec<u8>) -> Result<(), DiskCacheError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .write_tx
            .send(WriteMsg::Put {
                addr,
                data,
                ack: ack_tx,
            })
            .map_err(|_| DiskCacheError::WriterStopped)?;
        ack_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    pub async fn row_count(&self) -> Result<u64, DiskCacheError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner.read_tx[0]
            .send(ReadJob::Count { reply: reply_tx })
            .map_err(|_| DiskCacheError::WriterStopped)?;
        reply_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    async fn pin_op<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, DiskCacheError>>) -> PinOp,
    ) -> Result<T, DiskCacheError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .write_tx
            .send(WriteMsg::Pin(build(ack_tx)))
            .map_err(|_| DiskCacheError::WriterStopped)?;
        ack_rx.await.map_err(|_| DiskCacheError::Panicked)?
    }

    /// Pin the collection rooted at `reference`: store every member
    /// chunk (upserting rows that aren't cached yet) and mark them all
    /// pin-protected. Idempotent — returns `Ok(false)` (writing
    /// nothing) when `reference` is already pinned, `Ok(true)` on a
    /// fresh pin. See [`PinOp`] for the eviction/budget invariant.
    pub async fn pin_collection(
        &self,
        reference: Vec<u8>,
        members: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<bool, DiskCacheError> {
        self.pin_op(|ack| PinOp::Collection {
            reference,
            members,
            ack,
        })
        .await
    }

    /// Drop the pin at `reference`; member chunks whose last pin is
    /// removed become evictable again (their `last_access` is
    /// refreshed so they age out like freshly-read rows rather than
    /// being first in line). Returns `Ok(false)` when `reference`
    /// wasn't pinned.
    pub async fn unpin(&self, reference: Vec<u8>) -> Result<bool, DiskCacheError> {
        self.pin_op(|ack| PinOp::Unpin { reference, ack }).await
    }

    /// Whether `reference` is a pinned root.
    pub async fn has_pin(&self, reference: Vec<u8>) -> Result<bool, DiskCacheError> {
        self.pin_op(|ack| PinOp::Has { reference, ack }).await
    }

    /// Every pinned root reference, in pin-creation order.
    pub async fn list_pins(&self) -> Result<Vec<Vec<u8>>, DiskCacheError> {
        self.pin_op(|ack| PinOp::List { ack }).await
    }

    /// Recorded member chunk addresses per pin — all pins when
    /// `reference` is `None`, else just that pin (empty result when it
    /// isn't pinned). Backs the `/pins/check` integrity walk.
    pub async fn pin_members(
        &self,
        reference: Option<Vec<u8>>,
    ) -> Result<PinMembership, DiskCacheError> {
        self.pin_op(|ack| PinOp::Members { reference, ack }).await
    }
}

fn apply_shared_pragmas(
    conn: &Connection,
    tuning: DiskCacheTuning,
    is_write: bool,
) -> Result<(), rusqlite::Error> {
    let mmap = i64::try_from(tuning.mmap_bytes).unwrap_or(i64::MAX);
    conn.pragma_update(None, "mmap_size", mmap)?;
    // A negative `cache_size` is KiB rather than pages.
    let cache_kib = i64::try_from(tuning.page_cache_bytes / 1024).unwrap_or(i64::MAX);
    conn.pragma_update(None, "cache_size", -cache_kib.max(1))?;
    if is_write {
        conn.pragma_update(None, "page_size", 8192)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Cap what a checkpoint leaves behind. Without it a WAL grown
        // by a big delete (a clear, a shrink, a legacy `VACUUM`) keeps
        // its high-water size on disk for the rest of the process when
        // the post-reclaim `wal_checkpoint(TRUNCATE)` loses to a reader:
        // SQLite reuses the file from the start but never shortens it.
        // With the limit, the first WAL reset after a later (automatic)
        // checkpoint cuts it back.
        conn.pragma_update(None, "journal_size_limit", WAL_SIZE_LIMIT_BYTES)?;
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
    }
    Ok(())
}

fn open_write_connection(
    path: &Path,
    tuning: DiskCacheTuning,
) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // A fresh database gets incremental auto-vacuum so a clear or a
    // capacity shrink can hand pages back to the OS without rebuilding
    // the file. It has to be set before the first write (the WAL switch
    // in `apply_shared_pragmas` included); on an existing database the
    // pragma would only queue a change for the next `VACUUM`, which
    // `reclaim_space` does explicitly instead.
    let fresh: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))?;
    if fresh == 0 {
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    }
    apply_shared_pragmas(&conn, tuning, true)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chunks (
                address     BLOB PRIMARY KEY,
                data        BLOB NOT NULL,
                size        INTEGER NOT NULL,
                last_access INTEGER NOT NULL,
                inserted_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS chunks_last_access_idx
                ON chunks(last_access);
            CREATE TABLE IF NOT EXISTS pins (
                reference  BLOB PRIMARY KEY,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pin_members (
                reference BLOB NOT NULL,
                address   BLOB NOT NULL,
                PRIMARY KEY (reference, address)
            );",
    )?;
    // Additive migration for pre-pin databases: the pin refcount rides
    // on the chunks table so the eviction sweep can filter on it
    // without a join. `DEFAULT 0` keeps every pre-existing row
    // evictable, exactly as it was.
    let has_pin_count: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('chunks') WHERE name = 'pin_count'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .is_ok_and(|n| n > 0);
    if !has_pin_count {
        conn.execute_batch("ALTER TABLE chunks ADD COLUMN pin_count INTEGER NOT NULL DEFAULT 0;")?;
    }
    Ok(conn)
}

fn open_read_connection(
    path: &Path,
    tuning: DiskCacheTuning,
) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    apply_shared_pragmas(&conn, tuning, false)?;
    Ok(conn)
}

fn read_worker_loop(
    path: PathBuf,
    tuning: DiskCacheTuning,
    rx: CbReceiver<ReadJob>,
    write_tx: CbSender<WriteMsg>,
) {
    let Ok(conn) = open_read_connection(&path, tuning) else {
        return;
    };
    let Ok(mut sel_stmt) =
        conn.prepare_cached("SELECT data, last_access FROM chunks WHERE address = ?1")
    else {
        return;
    };
    let Ok(mut count_stmt) = conn.prepare_cached("SELECT COUNT(*) FROM chunks") else {
        return;
    };

    while let Ok(job) = rx.recv() {
        match job {
            ReadJob::Shutdown => break,
            ReadJob::Get { addr, reply } => {
                let res = (|| -> Result<Option<Vec<u8>>, DiskCacheError> {
                    let row: Option<(Vec<u8>, i64)> = sel_stmt
                        .query_row(params![&addr[..]], |row| {
                            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                        })
                        .optional()
                        .map_err(DiskCacheError::from)?;
                    let Some((data, last_access)) = row else {
                        return Ok(None);
                    };
                    if forged_replica_row(&addr, &data) {
                        debug!(
                            target: "ant_retrieval::disk_cache",
                            "ignoring cached replica SOC {} that fails soc_valid",
                            hex::encode(addr),
                        );
                        return Ok(None);
                    }
                    let now = unix_now() as i64;
                    if now.saturating_sub(last_access) > LAST_ACCESS_REFRESH_MS {
                        let _ = write_tx.send(WriteMsg::Touch {
                            addr,
                            last_access: now,
                        });
                    }
                    Ok(Some(data))
                })();
                let _ = reply.send(res);
            }
            ReadJob::Count { reply } => {
                let res = (|| -> Result<u64, DiskCacheError> {
                    let n: i64 = count_stmt
                        .query_row([], |row| row.get(0))
                        .map_err(DiskCacheError::from)?;
                    Ok(n as u64)
                })();
                let _ = reply.send(res);
            }
        }
    }
}

/// Whether a cached row is a dispersed-replica SOC that fails
/// [`ant_crypto::soc_valid`]: a forgery signed with the public replicas
/// key, cached by a build that predates the replica id rule. Rows that
/// don't sit at `keccak256(id ‖ REPLICAS_OWNER)` (every CAC, every
/// other owner's SOC) return `false` after one keccak, so ordinary hits
/// keep bee's trust-the-disk contract.
fn forged_replica_row(addr: &[u8; 32], data: &[u8]) -> bool {
    if data.len() < ant_crypto::SOC_MIN_CHUNK_SIZE {
        return false;
    }
    let mut input = [0u8; ant_crypto::SOC_ID_SIZE + 20];
    input[..ant_crypto::SOC_ID_SIZE].copy_from_slice(&data[..ant_crypto::SOC_ID_SIZE]);
    input[ant_crypto::SOC_ID_SIZE..].copy_from_slice(&ant_crypto::soc::REPLICAS_OWNER);
    if &ant_crypto::keccak256(&input) != addr {
        return false;
    }
    !ant_crypto::soc_valid(addr, data)
}

fn process_put_batch_transaction(
    conn: &mut Connection,
    items: &[([u8; 32], Vec<u8>)],
    total_bytes: &Arc<AtomicU64>,
    total_rows: &Arc<AtomicU64>,
    pinned: &PinTotals,
    max_bytes: u64,
    slack_bytes: u64,
) -> Result<(), DiskCacheError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (addr, data) in items {
        put_upsert_tx(&tx, *addr, data.as_slice(), total_bytes, total_rows, pinned)?;
    }
    tx.commit()?;
    let current = total_bytes.load(Ordering::Relaxed);
    if current > max_bytes {
        evict_to_slack(conn, total_bytes, total_rows, slack_bytes)?;
    }
    Ok(())
}

/// Pending put: chunk address, wire bytes, and the ack channel back
/// to the caller. Sized as a separate type alias to keep
/// `consume_put_touch_batch` readable.
type PutOp = (
    [u8; 32],
    Vec<u8>,
    oneshot::Sender<Result<(), DiskCacheError>>,
);

fn consume_put_touch_batch(
    conn: &mut Connection,
    batch: Vec<WriteMsg>,
    total_bytes: &Arc<AtomicU64>,
    total_rows: &Arc<AtomicU64>,
    pinned: &PinTotals,
    max_bytes: u64,
    slack_bytes: u64,
) -> Result<bool, DiskCacheError> {
    let mut shutdown = false;
    let mut put_ops: Vec<PutOp> = Vec::new();
    let mut touches: Vec<([u8; 32], i64)> = Vec::new();

    for m in batch {
        match m {
            WriteMsg::Put { addr, data, ack } => put_ops.push((addr, data, ack)),
            WriteMsg::Touch { addr, last_access } => touches.push((addr, last_access)),
            WriteMsg::Shutdown => shutdown = true,
            // Everything else never enters the coalescing buffer — the
            // writer loop flushes and handles it out-of-band.
            WriteMsg::PutBatch { .. }
            | WriteMsg::Pin(_)
            | WriteMsg::SetCapacity { .. }
            | WriteMsg::ClearUnpinned { .. } => {}
        }
    }

    if put_ops.is_empty() && touches.is_empty() {
        return Ok(shutdown);
    }

    let batch_res: Result<(), DiskCacheError> = (|| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (addr, data, _) in &put_ops {
            put_upsert_tx(&tx, *addr, data, total_bytes, total_rows, pinned)?;
        }
        for (addr, last) in &touches {
            if let Err(e) = tx.execute(
                "UPDATE chunks SET last_access = ?1 WHERE address = ?2",
                params![last, &addr[..]],
            ) {
                trace!(
                    target: "ant_retrieval::disk_cache",
                    "last_access touch failed (non-fatal): {e}",
                );
            }
        }
        tx.commit()?;
        Ok(())
    })();

    match batch_res {
        Ok(()) => {
            let current = total_bytes.load(Ordering::Relaxed);
            if current > max_bytes {
                if let Err(e) = evict_to_slack(conn, total_bytes, total_rows, slack_bytes) {
                    for (_, _, ack) in put_ops {
                        let _ = ack.send(Err(e.clone()));
                    }
                    return Err(e);
                }
            }
            for (_, _, ack) in put_ops {
                let _ = ack.send(Ok(()));
            }
            Ok(shutdown)
        }
        Err(e) => {
            for (_, _, ack) in put_ops {
                let _ = ack.send(Err(e.clone()));
            }
            Err(e)
        }
    }
}

/// Eviction target for a cap: how far below it a sweep drains.
fn slack_for(max_bytes: u64) -> u64 {
    ((max_bytes as f64) * EVICTION_SLACK_RATIO) as u64
}

/// The writer's mirrored totals, bundled so the out-of-band ops below
/// don't each take five counters.
struct WriterState<'a> {
    path: &'a Path,
    total_bytes: &'a Arc<AtomicU64>,
    total_rows: &'a Arc<AtomicU64>,
    pinned: &'a PinTotals,
    max_bytes: &'a AtomicU64,
}

impl WriterState<'_> {
    fn max(&self) -> u64 {
        self.max_bytes.load(Ordering::Relaxed)
    }

    /// Every message the coalescing loop doesn't batch: pin ops, a cap
    /// change, a clear.
    fn out_of_band(&self, conn: &mut Connection, msg: WriteMsg) {
        let max = self.max();
        match msg {
            WriteMsg::Pin(op) => process_pin_op(
                conn,
                op,
                self.total_bytes,
                self.total_rows,
                self.pinned,
                max,
                slack_for(max),
            ),
            WriteMsg::SetCapacity { max_bytes, ack } => {
                let _ = ack.send(self.set_capacity(conn, max_bytes));
            }
            WriteMsg::ClearUnpinned { ack } => {
                let _ = ack.send(self.clear_unpinned(conn));
            }
            // Batched kinds are routed by the caller.
            WriteMsg::Put { .. }
            | WriteMsg::PutBatch { .. }
            | WriteMsg::Touch { .. }
            | WriteMsg::Shutdown => {}
        }
    }

    fn set_capacity(&self, conn: &mut Connection, max_bytes: u64) -> Result<(), DiskCacheError> {
        self.max_bytes.store(max_bytes, Ordering::Relaxed);
        if self.total_bytes.load(Ordering::Relaxed) <= max_bytes {
            return Ok(());
        }
        let before = self.total_bytes.load(Ordering::Relaxed);
        evict_to_slack(
            conn,
            self.total_bytes,
            self.total_rows,
            slack_for(max_bytes),
        )?;
        debug!(
            target: "ant_retrieval::disk_cache",
            max_bytes,
            before,
            after = self.total_bytes.load(Ordering::Relaxed),
            "disk cache capacity lowered; evicted down to it",
        );
        reclaim_space(conn, self.path);
        Ok(())
    }

    fn clear_unpinned(&self, conn: &mut Connection) -> Result<ClearReport, DiskCacheError> {
        let file_bytes_before = db_file_bytes(self.path);
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (removed, freed): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM chunks WHERE pin_count = 0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        tx.execute("DELETE FROM chunks WHERE pin_count = 0", [])?;
        // What's left is exactly the pinned rows: re-derive every
        // mirrored total from them inside the same transaction, so the
        // counters are exact after a clear even if they had drifted.
        let (rows, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM chunks",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        tx.commit()?;
        self.total_bytes.store(0, Ordering::Relaxed);
        self.total_rows.store(rows as u64, Ordering::Relaxed);
        self.pinned.rows.store(rows as u64, Ordering::Relaxed);
        self.pinned.bytes.store(bytes as u64, Ordering::Relaxed);

        reclaim_space(conn, self.path);
        let report = ClearReport {
            removed_chunks: removed as u64,
            freed_bytes: freed as u64,
            file_bytes_before,
            file_bytes_after: db_file_bytes(self.path),
        };
        debug!(
            target: "ant_retrieval::disk_cache",
            ?report,
            pinned_rows = rows,
            "disk cache cleared (pinned rows kept)",
        );
        Ok(report)
    }
}

/// Busy timeout on the write connection: how long a write waits for a
/// lock another connection holds before giving up.
const BUSY_TIMEOUT_MS: u64 = 5000;

/// `journal_size_limit` on the write connection: the most WAL a reset
/// leaves on disk. About one auto-checkpoint's worth (1000 pages of
/// 8 KiB), the size the WAL grows back to in normal use anyway.
const WAL_SIZE_LIMIT_BYTES: i64 = 8 * 1024 * 1024;

/// Largest database (live pages, after the delete) [`reclaim_space`]
/// converts from `auto_vacuum = NONE` with a `VACUUM`. The rebuild runs
/// on the writer thread, so every `put` waits behind it, and its temp
/// copy is built in memory (see [`vacuum_free_pages`]), so this is also
/// the RAM it can take; past this size the file is left as it is (its
/// free pages are reused by later writes). After a clear the live data
/// is just the pinned rows, normally far below this.
const LEGACY_VACUUM_MAX_LIVE_BYTES: u64 = 64 * 1024 * 1024;

/// Free disk a legacy `VACUUM` must find on top of twice the live size.
/// In WAL mode the rebuild writes the whole new database into the WAL
/// (its temp copy is in memory) before the checkpoint copies it back;
/// asking for 2× live keeps headroom for the WAL's frame overhead and
/// the old file's pages, and the margin keeps the rest of the app (and
/// the OS) off a full disk.
const LEGACY_VACUUM_FREE_MARGIN: u64 = 64 * 1024 * 1024;

/// Whether a legacy (`auto_vacuum = NONE`) database with `live_bytes` of
/// live pages may be rebuilt now, given `available` free bytes on its
/// volume. A failed free-space read is not "plenty of room": skip.
fn legacy_vacuum_fits(live_bytes: u64, available: Option<u64>) -> bool {
    live_bytes <= LEGACY_VACUUM_MAX_LIVE_BYTES
        && available.is_some_and(|free| {
            free >= live_bytes
                .saturating_mul(2)
                .saturating_add(LEGACY_VACUUM_FREE_MARGIN)
        })
}

/// Free bytes on the volume holding `path`; `None` if it can't be read.
fn available_space(path: &Path) -> Option<u64> {
    #[cfg(test)]
    if let Some(free) = test_free_space::get(path) {
        return Some(free);
    }
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    fs4::available_space(dir.unwrap_or(path)).ok()
}

/// Hand free pages back to the OS and cut the WAL back to zero.
///
/// Best-effort and infallible on purpose: it runs after the delete or
/// eviction has committed, so a failure here must not turn a done clear
/// or shrink into an error (the rows are gone and the cap applied either
/// way). Anything that goes wrong is logged; the free pages stay on the
/// freelist, later writes reuse them, and the file is no bigger than
/// before.
///
/// `auto_vacuum = INCREMENTAL` (every database created since this
/// landed): `PRAGMA incremental_vacuum` moves the free pages to the end
/// and truncates. Needs no extra disk and no rebuild.
///
/// Anything else (an older `NONE` database) can only be converted by a
/// `VACUUM`, which rebuilds the file at its live size and needs up to
/// about twice that in free disk while it runs, with every `put` queued
/// behind it. It runs only when [`legacy_vacuum_fits`]: the live data is
/// at most [`LEGACY_VACUUM_MAX_LIVE_BYTES`] and the volume has room for
/// it. Its temp copy is built in memory (`temp_store = MEMORY`), not in
/// SQLite's temp directory, which an Android app usually can't write.
/// After a clear the live data is just the pinned rows; after a
/// capacity shrink it is ~95% of the new cap plus the pinned rows, so a
/// large cap stays unconverted (and unshrunk) until a clear. Once
/// converted, later calls take the incremental path.
///
/// The checkpoint doesn't wait: the busy timeout is dropped to zero for
/// it, so a reader holding an old snapshot (a stream in progress) makes
/// it give up at once instead of stalling the writer for the full busy
/// timeout. The WAL then shrinks at a later checkpoint: the write
/// connection's `journal_size_limit` cuts it back to
/// [`WAL_SIZE_LIMIT_BYTES`] the first time it resets after one.
fn reclaim_space(conn: &mut Connection, path: &Path) {
    if let Err(e) = vacuum_free_pages(conn, path) {
        warn!(
            target: "ant_retrieval::disk_cache",
            error = %e,
            "giving disk space back failed; free pages stay in the file for reuse",
        );
    }
    if let Err(e) = conn.busy_timeout(std::time::Duration::ZERO) {
        warn!(target: "ant_retrieval::disk_cache", error = %e, "busy_timeout(0) failed");
        return;
    }
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(0) => {}
        Ok(_) => debug!(
            target: "ant_retrieval::disk_cache",
            "WAL checkpoint after reclaim was blocked by a reader; file shrinks at a later one",
        ),
        Err(e) => warn!(
            target: "ant_retrieval::disk_cache",
            error = %e,
            "WAL checkpoint after reclaim failed",
        ),
    }
    if let Err(e) = conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS)) {
        warn!(target: "ant_retrieval::disk_cache", error = %e, "restoring busy_timeout failed");
    }
}

fn vacuum_free_pages(conn: &mut Connection, path: &Path) -> Result<(), rusqlite::Error> {
    let mode: i64 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if mode == 2 {
        // Frees one page per step: drain the statement, don't
        // `execute` it once.
        let mut stmt = conn.prepare("PRAGMA incremental_vacuum")?;
        let mut rows = stmt.query([])?;
        while rows.next()?.is_some() {}
        return Ok(());
    }
    let (pages, free, page_size): (i64, i64, i64) = conn.query_row(
        "SELECT p.page_count, f.freelist_count, s.page_size \
         FROM pragma_page_count p, pragma_freelist_count f, pragma_page_size s",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let live_bytes = (pages - free).max(0) as u64 * page_size.max(0) as u64;
    let available = available_space(path);
    if !legacy_vacuum_fits(live_bytes, available) {
        debug!(
            target: "ant_retrieval::disk_cache",
            live_bytes,
            ?available,
            "legacy database (no auto-vacuum) left unconverted: too large or not enough free disk to rebuild it now",
        );
        return Ok(());
    }
    // `VACUUM` builds its copy in a temp database. On file, SQLite puts
    // that in `sqlite3_temp_directory`/`SQLITE_TMPDIR`/`TMPDIR`, else
    // `/var/tmp`, `/usr/tmp`, `/tmp` or the cwd: none of which an
    // Android app can write unless the host set one, and none of which
    // is the volume `available_space` measured. So build it in memory
    // instead (bounded by `LEGACY_VACUUM_MAX_LIVE_BYTES`); the process-
    // wide temp-directory knob is left alone, it isn't safe to change
    // while other connections may be opening temp files.
    conn.execute_batch("PRAGMA temp_store = MEMORY;")?;
    let res = conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;");
    if let Err(e) = conn.execute_batch("PRAGMA temp_store = DEFAULT;") {
        warn!(target: "ant_retrieval::disk_cache", error = %e, "restoring temp_store failed");
    }
    if let Err(e) = res {
        // Rolled back; leave the mode as the file has it so nothing
        // else on this connection picks the pending switch up.
        let _ = conn.execute_batch("PRAGMA auto_vacuum = NONE;");
        return Err(e);
    }
    Ok(())
}

/// Test-only override for [`available_space`], keyed by database path
/// so parallel tests don't see each other's value.
#[cfg(test)]
mod test_free_space {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static OVERRIDES: Mutex<Option<HashMap<PathBuf, u64>>> = Mutex::new(None);

    pub(super) fn set(path: &Path, free: Option<u64>) {
        let mut g = OVERRIDES.lock().unwrap();
        let map = g.get_or_insert_with(HashMap::new);
        match free {
            Some(f) => map.insert(path.to_path_buf(), f),
            None => map.remove(path),
        };
    }

    pub(super) fn get(path: &Path) -> Option<u64> {
        OVERRIDES.lock().unwrap().as_ref()?.get(path).copied()
    }
}

/// `path` + `-wal` + `-shm` sizes. A missing file is zero bytes.
fn db_file_bytes(path: &Path) -> u64 {
    let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let sidecar = |suffix: &str| {
        let mut s = path.as_os_str().to_owned();
        s.push(suffix);
        PathBuf::from(s)
    };
    size(path) + size(&sidecar("-wal")) + size(&sidecar("-shm"))
}

fn writer_main(
    mut conn: Connection,
    path: PathBuf,
    rx: CbReceiver<WriteMsg>,
    total_bytes: Arc<AtomicU64>,
    total_rows: Arc<AtomicU64>,
    pinned: Arc<PinTotals>,
    max_bytes: Arc<AtomicU64>,
) -> Result<(), DiskCacheError> {
    // `open()` doesn't wait for this thread: it opened `conn`, and the
    // schema with it, itself. The initial backfill scan below
    // (SUM(size) + COUNT(*)) touches every row in the chunks table
    // (sequential disk read on a cold page cache: ~28 s on a 7 GB DB),
    // and `antd` must be free to start its libp2p listener + bootstrap
    // dial before we finish that —
    // `time_to_first_peer_s` is otherwise dominated by this scan on
    // every cold start. Until backfill finishes, `total_bytes` and
    // `total_rows` stay at zero; that just means the eviction trigger
    // won't fire (no harm, we re-check inside every write batch via
    // `process_put_batch_transaction`), and `used_bytes()` /
    // `used_rows()` under-report for the first few seconds. Both are
    // acceptable; a frozen daemon is not.

    // Single combined backfill query: SQLite serves every aggregate
    // from the same sequential scan, so we pay the cold-cache scan cost
    // once. Pinned rows are outside the budget (see [`PinOp`]), so the
    // byte total only sums evictable rows; the row count covers
    // everything, and the pinned totals are mirrored separately.
    let (initial_total, initial_rows, initial_pinned_bytes, initial_pinned_rows): (
        u64,
        u64,
        u64,
        u64,
    ) = conn
        .query_row(
            "SELECT COALESCE(SUM(CASE WHEN pin_count = 0 THEN size ELSE 0 END), 0), COUNT(*), \
                    COALESCE(SUM(CASE WHEN pin_count > 0 THEN size ELSE 0 END), 0), \
                    COALESCE(SUM(CASE WHEN pin_count > 0 THEN 1 ELSE 0 END), 0) \
             FROM chunks",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                ))
            },
        )
        .unwrap_or((0, 0, 0, 0));
    total_bytes.store(initial_total, Ordering::Relaxed);
    total_rows.store(initial_rows, Ordering::Relaxed);
    pinned.bytes.store(initial_pinned_bytes, Ordering::Relaxed);
    pinned.rows.store(initial_pinned_rows, Ordering::Relaxed);
    // Pin tables are small (one row per pin / pin member), unlike the
    // chunks scan above.
    let count = |table: &str| -> u64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get::<_, i64>(0)
        })
        .map_or(0, |n| n as u64)
    };
    pinned.collections.store(count("pins"), Ordering::Relaxed);
    pinned
        .member_refs
        .store(count("pin_members"), Ordering::Relaxed);

    let ws = WriterState {
        path: &path,
        total_bytes: &total_bytes,
        total_rows: &total_rows,
        pinned: &pinned,
        max_bytes: &max_bytes,
    };

    'outer: loop {
        let max = ws.max();
        let slack = slack_for(max);
        match rx.recv() {
            Err(_) | Ok(WriteMsg::Shutdown) => break,
            Ok(WriteMsg::PutBatch { items, ack }) => {
                let r = process_put_batch_transaction(
                    &mut conn,
                    &items,
                    &total_bytes,
                    &total_rows,
                    &pinned,
                    max,
                    slack,
                );
                let _ = ack.send(r);
            }
            Ok(
                m @ (WriteMsg::Pin(_)
                | WriteMsg::SetCapacity { .. }
                | WriteMsg::ClearUnpinned { .. }),
            ) => {
                ws.out_of_band(&mut conn, m);
            }
            Ok(first) => {
                let mut batch = vec![first];
                while batch.len() < WRITE_BATCH_MAX {
                    match rx.try_recv() {
                        Ok(WriteMsg::Shutdown) => {
                            batch.push(WriteMsg::Shutdown);
                            break;
                        }
                        Ok(
                            m @ (WriteMsg::Pin(_)
                            | WriteMsg::SetCapacity { .. }
                            | WriteMsg::ClearUnpinned { .. }),
                        ) => {
                            let shutdown_after = match consume_put_touch_batch(
                                &mut conn,
                                std::mem::take(&mut batch),
                                &total_bytes,
                                &total_rows,
                                &pinned,
                                max,
                                slack,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(
                                        target: "ant_retrieval::disk_cache",
                                        "write batch ahead of out-of-band op failed: {e}",
                                    );
                                    false
                                }
                            };
                            ws.out_of_band(&mut conn, m);
                            if shutdown_after {
                                break 'outer;
                            }
                            continue 'outer;
                        }
                        Ok(WriteMsg::PutBatch { items, ack }) => {
                            let shutdown_after = match consume_put_touch_batch(
                                &mut conn,
                                batch,
                                &total_bytes,
                                &total_rows,
                                &pinned,
                                max,
                                slack,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    let _ = ack.send(Err(e));
                                    continue 'outer;
                                }
                            };
                            let r = process_put_batch_transaction(
                                &mut conn,
                                &items,
                                &total_bytes,
                                &total_rows,
                                &pinned,
                                max,
                                slack,
                            );
                            let _ = ack.send(r);
                            if shutdown_after {
                                break 'outer;
                            }
                            continue 'outer;
                        }
                        Ok(m) => batch.push(m),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => break 'outer,
                    }
                }

                let shutdown_after = consume_put_touch_batch(
                    &mut conn,
                    batch,
                    &total_bytes,
                    &total_rows,
                    &pinned,
                    max,
                    slack,
                )?;
                if shutdown_after {
                    break 'outer;
                }
            }
        }
    }

    Ok(())
}

fn put_upsert_tx(
    tx: &rusqlite::Transaction<'_>,
    addr: [u8; 32],
    data: &[u8],
    total_bytes: &AtomicU64,
    total_rows: &AtomicU64,
    pinned: &PinTotals,
) -> Result<(), DiskCacheError> {
    let size = data.len() as u64;
    let now = unix_now();
    let existing: Option<(u64, i64)> = tx
        .query_row(
            "SELECT size, pin_count FROM chunks WHERE address = ?1",
            params![&addr[..]],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)?)),
        )
        .optional()?;

    tx.execute(
        "INSERT INTO chunks (address, data, size, last_access, inserted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(address) DO UPDATE SET
                   data = excluded.data,
                   size = excluded.size,
                   last_access = excluded.last_access",
        params![&addr[..], data, size as i64, now as i64, now as i64],
    )?;

    // Pinned rows live outside the byte budget (see [`PinOp`]): an
    // upsert over one must not (re-)count its bytes.
    if let Some((old, pin_count)) = existing {
        if pin_count == 0 {
            update_total(total_bytes, size as i64 - old as i64);
        } else {
            update_total(&pinned.bytes, size as i64 - old as i64);
        }
    } else {
        update_total(total_bytes, size as i64);
        total_rows.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn update_total(total: &AtomicU64, delta: i64) -> u64 {
    if delta >= 0 {
        total.fetch_add(delta as u64, Ordering::Relaxed) + delta as u64
    } else {
        let abs = (-delta) as u64;
        match total.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(abs))
        }) {
            Ok(prev) => prev.saturating_sub(abs),
            Err(_) => total.load(Ordering::Relaxed),
        }
    }
}

fn evict_to_slack(
    conn: &mut Connection,
    total_bytes: &AtomicU64,
    total_rows: &AtomicU64,
    slack_bytes: u64,
) -> Result<(), DiskCacheError> {
    let current = total_bytes.load(Ordering::Relaxed);
    if current <= slack_bytes {
        return Ok(());
    }
    let need_to_free = current.saturating_sub(slack_bytes);

    // Pinned rows are exempt: the sweep only ever sees `pin_count = 0`
    // rows, and their bytes are the only ones in `total_bytes`, so the
    // slack target is reachable without touching pins (see [`PinOp`]).
    let mut stmt = conn
        .prepare(
            "SELECT address, size FROM chunks WHERE pin_count = 0 \
             ORDER BY last_access ASC, address ASC",
        )
        .map_err(DiskCacheError::from)?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut victim_addrs: Vec<Vec<u8>> = Vec::new();
    let mut freed: u64 = 0;
    for row in rows {
        let (addr, size) = row.map_err(DiskCacheError::from)?;
        victim_addrs.push(addr);
        freed += size;
        if freed >= need_to_free {
            break;
        }
    }
    drop(stmt);

    if victim_addrs.is_empty() {
        return Ok(());
    }

    let tx = conn.unchecked_transaction().map_err(DiskCacheError::from)?;
    {
        let mut del = tx
            .prepare("DELETE FROM chunks WHERE address = ?1")
            .map_err(DiskCacheError::from)?;
        for addr in &victim_addrs {
            del.execute(params![addr]).map_err(DiskCacheError::from)?;
        }
    }
    tx.commit().map_err(DiskCacheError::from)?;

    update_total(total_bytes, -(freed as i64));
    // Decrement row count by the eviction batch size. Saturating
    // because total_rows is observably zero between open() returning
    // and the initial COUNT(*) backfill finishing — a write+eviction
    // racing the backfill must not underflow.
    let evicted = victim_addrs.len() as u64;
    let _ = total_rows.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(evicted))
    });
    debug!(
        target: "ant_retrieval::disk_cache",
        evicted_rows = evicted,
        freed_bytes = freed,
        new_total = total_bytes.load(Ordering::Relaxed),
        new_rows = total_rows.load(Ordering::Relaxed),
        slack = slack_bytes,
        "disk cache eviction sweep complete",
    );
    Ok(())
}

/// Dispatch one [`PinOp`] on the writer connection. Failures are
/// reported to the caller through the op's ack channel; the writer
/// thread itself never dies over a pin error.
fn process_pin_op(
    conn: &mut Connection,
    op: PinOp,
    total_bytes: &Arc<AtomicU64>,
    total_rows: &Arc<AtomicU64>,
    pinned: &PinTotals,
    max_bytes: u64,
    slack_bytes: u64,
) {
    match op {
        PinOp::Collection {
            reference,
            members,
            ack,
        } => {
            let r = pin_collection_tx(conn, &reference, &members, total_bytes, total_rows, pinned);
            let _ = ack.send(r);
        }
        PinOp::Unpin { reference, ack } => {
            let r = unpin_tx(conn, &reference, total_bytes, pinned);
            // Bytes returned to the budget may push it over the cap.
            if matches!(r, Ok(true)) && total_bytes.load(Ordering::Relaxed) > max_bytes {
                if let Err(e) = evict_to_slack(conn, total_bytes, total_rows, slack_bytes) {
                    warn!(
                        target: "ant_retrieval::disk_cache",
                        "post-unpin eviction sweep failed: {e}",
                    );
                }
            }
            let _ = ack.send(r);
        }
        PinOp::Has { reference, ack } => {
            let r = conn
                .query_row(
                    "SELECT COUNT(*) FROM pins WHERE reference = ?1",
                    params![&reference[..]],
                    |row| row.get::<_, i64>(0),
                )
                .map(|n| n > 0)
                .map_err(DiskCacheError::from);
            let _ = ack.send(r);
        }
        PinOp::List { ack } => {
            let r = (|| -> Result<Vec<Vec<u8>>, DiskCacheError> {
                let mut stmt =
                    conn.prepare("SELECT reference FROM pins ORDER BY created_at ASC, rowid ASC")?;
                let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                Ok(out)
            })();
            let _ = ack.send(r);
        }
        PinOp::Members { reference, ack } => {
            let r = (|| -> Result<PinMembership, DiskCacheError> {
                let refs: Vec<Vec<u8>> = if let Some(r) = reference {
                    let pinned: i64 = conn.query_row(
                        "SELECT COUNT(*) FROM pins WHERE reference = ?1",
                        params![&r[..]],
                        |row| row.get(0),
                    )?;
                    if pinned > 0 {
                        vec![r]
                    } else {
                        Vec::new()
                    }
                } else {
                    let mut stmt = conn
                        .prepare("SELECT reference FROM pins ORDER BY created_at ASC, rowid ASC")?;
                    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
                    rows.collect::<Result<_, _>>()?
                };
                let mut out = Vec::with_capacity(refs.len());
                let mut stmt = conn.prepare(
                    "SELECT address FROM pin_members WHERE reference = ?1 ORDER BY rowid ASC",
                )?;
                for r in refs {
                    let rows = stmt.query_map(params![&r[..]], |row| row.get::<_, Vec<u8>>(0))?;
                    let mut members = Vec::new();
                    for row in rows {
                        let raw = row?;
                        if let Ok(addr) = <[u8; 32]>::try_from(raw.as_slice()) {
                            members.push(addr);
                        }
                    }
                    out.push((r, members));
                }
                Ok(out)
            })();
            let _ = ack.send(r);
        }
    }
}

/// Record a pin collection in one transaction. Returns `Ok(false)`
/// without writing anything when `reference` is already pinned.
fn pin_collection_tx(
    conn: &mut Connection,
    reference: &[u8],
    members: &[([u8; 32], Vec<u8>)],
    total_bytes: &Arc<AtomicU64>,
    total_rows: &Arc<AtomicU64>,
    pinned: &PinTotals,
) -> Result<bool, DiskCacheError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let already: i64 = tx.query_row(
        "SELECT COUNT(*) FROM pins WHERE reference = ?1",
        params![reference],
        |row| row.get(0),
    )?;
    if already > 0 {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO pins (reference, created_at) VALUES (?1, ?2)",
        params![reference, unix_now() as i64],
    )?;

    let mut seen = std::collections::HashSet::with_capacity(members.len());
    let mut new_rows = 0u64;
    let mut bytes_leaving_budget = 0u64;
    // Rows going from unpinned/absent to pinned, and their bytes.
    let mut newly_pinned_rows = 0u64;
    let mut newly_pinned_bytes = 0u64;
    let now = unix_now() as i64;
    for (addr, wire) in members {
        if !seen.insert(*addr) {
            continue;
        }
        tx.execute(
            "INSERT INTO pin_members (reference, address) VALUES (?1, ?2)",
            params![reference, &addr[..]],
        )?;
        let existing: Option<(u64, i64)> = tx
            .query_row(
                "SELECT size, pin_count FROM chunks WHERE address = ?1",
                params![&addr[..]],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        match existing {
            None => {
                // Fresh row, pinned from birth: never enters the budget.
                tx.execute(
                    "INSERT INTO chunks (address, data, size, last_access, inserted_at, pin_count)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                    params![&addr[..], wire, wire.len() as i64, now, now],
                )?;
                new_rows += 1;
                newly_pinned_rows += 1;
                newly_pinned_bytes += wire.len() as u64;
            }
            Some((size, 0)) => {
                // First pin over a cached row: bytes leave the budget.
                tx.execute(
                    "UPDATE chunks SET pin_count = 1 WHERE address = ?1",
                    params![&addr[..]],
                )?;
                bytes_leaving_budget += size;
                newly_pinned_rows += 1;
                newly_pinned_bytes += size;
            }
            Some((_, n)) => {
                tx.execute(
                    "UPDATE chunks SET pin_count = ?1 WHERE address = ?2",
                    params![n + 1, &addr[..]],
                )?;
            }
        }
    }
    tx.commit()?;
    total_rows.fetch_add(new_rows, Ordering::Relaxed);
    update_total(total_bytes, -(bytes_leaving_budget as i64));
    pinned.rows.fetch_add(newly_pinned_rows, Ordering::Relaxed);
    pinned
        .bytes
        .fetch_add(newly_pinned_bytes, Ordering::Relaxed);
    pinned.collections.fetch_add(1, Ordering::Relaxed);
    pinned
        .member_refs
        .fetch_add(seen.len() as u64, Ordering::Relaxed);
    Ok(true)
}

/// Remove a pin in one transaction. Returns `Ok(false)` when
/// `reference` wasn't pinned. Chunks whose last pin drops re-enter the
/// byte budget (the caller re-checks the cap afterwards).
fn unpin_tx(
    conn: &mut Connection,
    reference: &[u8],
    total_bytes: &Arc<AtomicU64>,
    pinned: &PinTotals,
) -> Result<bool, DiskCacheError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let is_pinned: i64 = tx.query_row(
        "SELECT COUNT(*) FROM pins WHERE reference = ?1",
        params![reference],
        |row| row.get(0),
    )?;
    if is_pinned == 0 {
        return Ok(false);
    }
    let members: Vec<Vec<u8>> = {
        let mut stmt = tx.prepare("SELECT address FROM pin_members WHERE reference = ?1")?;
        let rows = stmt.query_map(params![reference], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut bytes_returning = 0u64;
    let mut rows_returning = 0u64;
    for addr in &members {
        let existing: Option<(u64, i64)> = tx
            .query_row(
                "SELECT size, pin_count FROM chunks WHERE address = ?1",
                params![&addr[..]],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        match existing {
            Some((size, n)) if n <= 1 => {
                tx.execute(
                    "UPDATE chunks SET pin_count = 0, last_access = ?1 WHERE address = ?2",
                    params![unix_now() as i64, &addr[..]],
                )?;
                if n == 1 {
                    bytes_returning += size;
                    rows_returning += 1;
                }
            }
            Some((_, n)) => {
                tx.execute(
                    "UPDATE chunks SET pin_count = ?1 WHERE address = ?2",
                    params![n - 1, &addr[..]],
                )?;
            }
            None => {}
        }
    }
    tx.execute(
        "DELETE FROM pin_members WHERE reference = ?1",
        params![reference],
    )?;
    tx.execute("DELETE FROM pins WHERE reference = ?1", params![reference])?;
    tx.commit()?;
    update_total(total_bytes, bytes_returning as i64);
    update_total(&pinned.bytes, -(bytes_returning as i64));
    let _ = pinned
        .rows
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(rows_returning))
        });
    update_total(&pinned.collections, -1);
    update_total(&pinned.member_refs, -(members.len() as i64));
    Ok(true)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::cac_new;
    use rusqlite::params as rparams;
    use tempfile::tempdir;

    fn make_chunk(payload: &[u8]) -> ([u8; 32], Vec<u8>) {
        cac_new(payload).expect("cac_new")
    }

    #[tokio::test]
    async fn put_batch_round_trips() {
        let dir = tempdir().unwrap();
        let cache = DiskChunkCache::open(dir.path().join("batch.sqlite"), 1 << 20).unwrap();
        let a = make_chunk(b"a");
        let b = make_chunk(b"b");
        cache
            .put_batch(vec![(a.0, a.1.clone()), (b.0, b.1.clone())])
            .await
            .unwrap();
        assert_eq!(cache.get(a.0).await.unwrap(), Some(a.1));
        assert_eq!(cache.get(b.0).await.unwrap(), Some(b.1));
        assert_eq!(cache.row_count().await.unwrap(), 2);
    }

    #[test]
    fn tuning_sets_each_connections_mapping_and_page_cache() {
        let dir = tempdir().unwrap();
        let conn = Connection::open(dir.path().join("t.sqlite")).unwrap();
        let pragma = |name: &str| -> i64 {
            conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
                .unwrap()
        };
        apply_shared_pragmas(&conn, DiskCacheTuning::DEFAULT, false).unwrap();
        assert_eq!(pragma("mmap_size"), 0);
        assert_eq!(pragma("cache_size"), -8 * 1024, "8 MiB, in KiB");
        let mapped = DiskCacheTuning {
            mmap_bytes: 64 * 1024 * 1024,
            page_cache_bytes: 2 * 1024 * 1024,
            ..DiskCacheTuning::DEFAULT
        };
        apply_shared_pragmas(&conn, mapped, false).unwrap();
        assert_eq!(pragma("mmap_size"), 64 * 1024 * 1024);
        assert_eq!(pragma("cache_size"), -2 * 1024);
    }

    #[test]
    fn default_tuning_memory_does_not_grow_with_the_file_or_cores() {
        // Both budgets are per connection, times the connections. The
        // mapping crashed iOS (address space); a 256 MiB page cache per
        // per-core reader grew antd by GiBs on desktop (#152). Neither
        // may depend on the core count or the cache file's size.
        let t = DiskCacheTuning::DEFAULT;
        assert_eq!(DiskCacheTuning::default(), t);
        assert!((2..=4).contains(&t.read_workers), "{t:?}");
        let connections = t.read_workers as u64 + 1;
        assert_eq!(connections * t.mmap_bytes, 0);
        assert!(connections * t.page_cache_bytes <= 32 * 1024 * 1024);
    }

    #[tokio::test]
    async fn default_open_uses_default_tuning() {
        let dir = tempdir().unwrap();
        let cache = DiskChunkCache::open(dir.path().join("m.sqlite"), 1 << 20).unwrap();
        assert_eq!(cache.read_workers(), DiskCacheTuning::DEFAULT.read_workers);
        let chunks: Vec<_> = (0u8..8).map(|i| make_chunk(&[i; 64])).collect();
        cache
            .put_batch(chunks.iter().map(|(a, w)| (*a, w.clone())).collect())
            .await
            .unwrap();
        for (addr, wire) in &chunks {
            assert_eq!(cache.get(*addr).await.unwrap().as_ref(), Some(wire));
        }
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let dir = tempdir().unwrap();
        let cache = DiskChunkCache::open(dir.path().join("c.sqlite"), 1 << 20).unwrap();
        let (addr, wire) = make_chunk(b"hello disk");

        cache.put(addr, wire.clone()).await.unwrap();
        let got = cache.get(addr).await.unwrap();
        assert_eq!(got, Some(wire.clone()));
        assert_eq!(cache.used_bytes(), wire.len() as u64);
        assert_eq!(cache.row_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn rows_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("persist.sqlite");
        let (addr, wire) = make_chunk(b"persistence test");

        {
            let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
            cache.put(addr, wire.clone()).await.unwrap();
            assert_eq!(cache.used_bytes(), wire.len() as u64);
        }

        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        // `open()` returns before the writer's backfill scan fills
        // `total_bytes`; any writer round-trip is queued behind that scan,
        // so awaiting one makes the `used_bytes()` read below race-free.
        cache.list_pins().await.unwrap();
        assert_eq!(cache.used_bytes(), wire.len() as u64);
        let got = cache.get(addr).await.unwrap();
        assert_eq!(got, Some(wire));
    }

    #[tokio::test]
    async fn evicts_oldest_by_last_access() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evict.sqlite");
        let cache = DiskChunkCache::open(&path, 12 * 1024).unwrap();

        let chunks: Vec<([u8; 32], Vec<u8>)> =
            (0..3u8).map(|i| make_chunk(&vec![i; 4096])).collect();

        cache.put(chunks[0].0, chunks[0].1.clone()).await.unwrap();
        cache.put(chunks[1].0, chunks[1].1.clone()).await.unwrap();

        let now = unix_now() as i64;
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE chunks SET last_access = ?1 WHERE address = ?2",
                rparams![now - 20 * 60_000, &chunks[0].0[..]],
            )
            .unwrap();
            conn.execute(
                "UPDATE chunks SET last_access = ?1 WHERE address = ?2",
                rparams![now - 10 * 60_000, &chunks[1].0[..]],
            )
            .unwrap();
        }

        assert!(cache.get(chunks[0].0).await.unwrap().is_some());

        cache.put(chunks[2].0, chunks[2].1.clone()).await.unwrap();

        assert!(
            cache.used_bytes() <= 12 * 1024,
            "post-eviction total {} bytes must fit the cap (12 KiB)",
            cache.used_bytes(),
        );
        assert!(cache.get(chunks[0].0).await.unwrap().is_some());
        assert!(cache.get(chunks[1].0).await.unwrap().is_none());
        assert!(cache.get(chunks[2].0).await.unwrap().is_some());
        // The fast-path row counter must stay in lock-step with the
        // SQL COUNT(*). One eviction victim → counter goes 3 → 2.
        assert_eq!(cache.used_rows(), 2);
        assert_eq!(cache.row_count().await.unwrap(), 2);
    }

    /// Bee-style trust: a hand-corrupted row is still returned on read
    /// (same as bee chunkstore returning sharky bytes for a retrieval key).
    #[tokio::test]
    async fn corrupt_disk_row_is_trusted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.sqlite");
        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        let (addr, wire) = make_chunk(b"trust me");
        drop(cache);

        let mut bad = wire.clone();
        bad[8] ^= 0x01;
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO chunks (address, data, size, last_access, inserted_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                rparams![&addr[..], &bad, bad.len() as i64, 0i64, 0i64],
            )
            .unwrap();
        }
        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        assert_eq!(cache.row_count().await.unwrap(), 1);

        let got = cache.get(addr).await.unwrap();
        assert_eq!(got, Some(bad));
    }

    /// Wire bytes and address of a SOC signed by `secret` at `id`
    /// wrapping `payload`.
    fn signed_soc(secret: &[u8; 32], id: &[u8; 32], payload: &[u8]) -> ([u8; 32], Vec<u8>) {
        let (inner_addr, inner_wire) = cac_new(payload).unwrap();
        let mut digest_input = [0u8; 64];
        digest_input[..32].copy_from_slice(id);
        digest_input[32..].copy_from_slice(&inner_addr);
        let sig =
            ant_crypto::sign_handshake_data(secret, &ant_crypto::keccak256(&digest_input)).unwrap();
        let sk = k256::ecdsa::SigningKey::from_bytes(secret.into()).unwrap();
        let owner =
            ant_crypto::ethereum_address_from_public_key(&k256::ecdsa::VerifyingKey::from(&sk));
        let mut addr_input = [0u8; 52];
        addr_input[..32].copy_from_slice(id);
        addr_input[32..].copy_from_slice(&owner);
        let mut wire = id.to_vec();
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&inner_wire);
        (ant_crypto::keccak256(&addr_input), wire)
    }

    /// A forged replica SOC cached by a build that predates the replica
    /// id rule (bee#5640) reads as a miss, so retrieval goes to the
    /// network; the genuine replica it fetches overwrites the row and
    /// is served from disk from then on. Other SOCs keep the
    /// trust-the-disk contract.
    #[tokio::test]
    async fn forged_replica_row_reads_as_miss() {
        use ant_crypto::soc::REPLICAS_OWNER_SECRET;
        let dir = tempdir().unwrap();
        let path = dir.path().join("replica.sqlite");

        let payload = b"genuine replicated root";
        let (root, _) = cac_new(payload).unwrap();
        let mut id = root;
        id[0] = 0x80;
        let (addr, genuine) = signed_soc(&REPLICAS_OWNER_SECRET, &id, payload);
        let (forged_addr, forged) = signed_soc(&REPLICAS_OWNER_SECRET, &id, b"attacker content");
        assert_eq!(forged_addr, addr);

        // What an older build left behind: the forgery at the replica
        // address, written straight to the table.
        drop(DiskChunkCache::open(&path, 1 << 20).unwrap());
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT INTO chunks (address, data, size, last_access, inserted_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                rparams![&addr[..], &forged, forged.len() as i64, 0i64, 0i64],
            )
            .unwrap();
        }
        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        assert_eq!(cache.row_count().await.unwrap(), 1);
        assert_eq!(cache.get(addr).await.unwrap(), None);

        cache.put(addr, genuine.clone()).await.unwrap();
        assert_eq!(cache.get(addr).await.unwrap(), Some(genuine));
        assert_eq!(cache.row_count().await.unwrap(), 1);

        // A non-replica owner's SOC is still trusted from disk.
        let (other_addr, other) = signed_soc(&[7u8; 32], &[0x80u8; 32], b"anything");
        cache.put(other_addr, other.clone()).await.unwrap();
        assert_eq!(cache.get(other_addr).await.unwrap(), Some(other));
    }

    #[tokio::test]
    async fn upsert_does_not_double_count() {
        let dir = tempdir().unwrap();
        let cache = DiskChunkCache::open(dir.path().join("upsert.sqlite"), 1 << 20).unwrap();
        let (addr, wire) = make_chunk(b"upsert");

        cache.put(addr, wire.clone()).await.unwrap();
        cache.put(addr, wire.clone()).await.unwrap();
        cache.put(addr, wire.clone()).await.unwrap();
        assert_eq!(cache.row_count().await.unwrap(), 1);
        // Fast-path row counter must agree with the SQL truth.
        assert_eq!(cache.used_rows(), 1);
        assert_eq!(cache.used_bytes(), wire.len() as u64);
    }

    async fn read_last_access(cache: &DiskChunkCache, addr: [u8; 32]) -> i64 {
        let path = cache.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.query_row(
                "SELECT last_access FROM chunks WHERE address = ?1",
                rparams![&addr[..]],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn fresh_last_access_is_not_rewritten() {
        let dir = tempdir().unwrap();
        let cache = DiskChunkCache::open(dir.path().join("touch-skip.sqlite"), 1 << 20).unwrap();
        let (addr, wire) = make_chunk(b"hot read");

        cache.put(addr, wire.clone()).await.unwrap();
        let after_put = read_last_access(&cache, addr).await;

        for _ in 0..10 {
            assert_eq!(cache.get(addr).await.unwrap().as_deref(), Some(&wire[..]));
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }

        let after_reads = read_last_access(&cache, addr).await;
        assert_eq!(
            after_put, after_reads,
            "ten consecutive hot reads inside the refresh window must leave \
             last_access untouched (was {after_put}, now {after_reads})",
        );
    }

    /// The core pin invariant: pinned rows are exempt from the
    /// eviction sweep (and outside the byte budget), and unpinning
    /// restores evictability.
    #[tokio::test]
    async fn eviction_skips_pinned_rows_and_unpin_restores_evictability() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pin-evict.sqlite");
        // Cap fits ~2 chunks of unpinned bytes.
        let cache = DiskChunkCache::open(&path, 9 * 1024).unwrap();

        let pinned = make_chunk(&vec![0xaau8; 4096]);
        cache.put(pinned.0, pinned.1.clone()).await.unwrap();
        let newly = cache
            .pin_collection(pinned.0.to_vec(), vec![(pinned.0, pinned.1.clone())])
            .await
            .unwrap();
        assert!(newly, "first pin is fresh");
        assert!(
            !cache
                .pin_collection(pinned.0.to_vec(), vec![(pinned.0, pinned.1.clone())])
                .await
                .unwrap(),
            "second pin of the same root is a no-op"
        );
        // Pinned bytes left the budget entirely.
        assert_eq!(cache.used_bytes(), 0, "pinned bytes are outside the budget");

        // Backdate the pinned row so LRU order would evict it first if
        // the sweep could see it.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE chunks SET last_access = 0 WHERE address = ?1",
                rparams![&pinned.0[..]],
            )
            .unwrap();
        }

        // Fill past the cap with unpinned chunks → eviction fires.
        let fillers: Vec<([u8; 32], Vec<u8>)> =
            (1..=3u8).map(|i| make_chunk(&vec![i; 4096])).collect();
        for (addr, wire) in &fillers {
            cache.put(*addr, wire.clone()).await.unwrap();
        }
        assert!(
            cache.get(pinned.0).await.unwrap().is_some(),
            "pinned chunk survives an eviction sweep even as the LRU-oldest row"
        );
        assert!(
            cache.used_bytes() <= 9 * 1024,
            "unpinned bytes still respect the cap"
        );

        // Pin bookkeeping is queryable.
        assert!(cache.has_pin(pinned.0.to_vec()).await.unwrap());
        assert_eq!(cache.list_pins().await.unwrap(), vec![pinned.0.to_vec()]);
        let members = cache.pin_members(None).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].1, vec![pinned.0]);

        // Unpin → evictable again: keep it LRU-oldest and overflow.
        assert!(cache.unpin(pinned.0.to_vec()).await.unwrap());
        assert!(!cache.unpin(pinned.0.to_vec()).await.unwrap(), "idempotent");
        assert!(!cache.has_pin(pinned.0.to_vec()).await.unwrap());
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE chunks SET last_access = 0 WHERE address = ?1",
                rparams![&pinned.0[..]],
            )
            .unwrap();
        }
        let more: Vec<([u8; 32], Vec<u8>)> =
            (10..=12u8).map(|i| make_chunk(&vec![i; 4096])).collect();
        for (addr, wire) in &more {
            cache.put(*addr, wire.clone()).await.unwrap();
        }
        assert!(
            cache.get(pinned.0).await.unwrap().is_none(),
            "after unpin the (backdated) chunk is evicted like any other row"
        );
    }

    /// Pins are `SQLite` rows: they survive a close + reopen, and the
    /// budget backfill keeps treating pinned bytes as out-of-budget.
    #[tokio::test]
    async fn pins_survive_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pin-persist.sqlite");
        let (addr, wire) = make_chunk(b"pinned across restarts");
        {
            let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
            cache
                .pin_collection(addr.to_vec(), vec![(addr, wire.clone())])
                .await
                .unwrap();
        }
        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        assert!(cache.has_pin(addr.to_vec()).await.unwrap());
        assert_eq!(cache.list_pins().await.unwrap(), vec![addr.to_vec()]);
        assert_eq!(cache.get(addr).await.unwrap(), Some(wire));
        assert_eq!(
            cache.used_bytes(),
            0,
            "backfill keeps pinned bytes out of the budget"
        );
    }

    /// Two pins sharing a chunk: the shared chunk stays pin-protected
    /// until the *last* covering pin is removed (refcount semantics,
    /// like bee's pinstore).
    #[tokio::test]
    async fn shared_chunk_stays_pinned_until_last_pin_drops() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pin-shared.sqlite");
        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        let shared = make_chunk(b"shared leaf");
        let root_a = make_chunk(b"root a");
        let root_b = make_chunk(b"root b");
        cache
            .pin_collection(
                root_a.0.to_vec(),
                vec![(root_a.0, root_a.1.clone()), (shared.0, shared.1.clone())],
            )
            .await
            .unwrap();
        cache
            .pin_collection(
                root_b.0.to_vec(),
                vec![(root_b.0, root_b.1.clone()), (shared.0, shared.1.clone())],
            )
            .await
            .unwrap();
        cache.unpin(root_a.0.to_vec()).await.unwrap();

        let pin_count: i64 = {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.query_row(
                "SELECT pin_count FROM chunks WHERE address = ?1",
                rparams![&shared.0[..]],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(pin_count, 1, "one covering pin left");
        cache.unpin(root_b.0.to_vec()).await.unwrap();
        let pin_count: i64 = {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.query_row(
                "SELECT pin_count FROM chunks WHERE address = ?1",
                rparams![&shared.0[..]],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(pin_count, 0, "evictable again after the last unpin");
    }

    #[tokio::test]
    async fn stale_last_access_is_refreshed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("touch-stale.sqlite");
        let cache = DiskChunkCache::open(&path, 1 << 20).unwrap();
        let (addr, wire) = make_chunk(b"cool read");
        cache.put(addr, wire.clone()).await.unwrap();

        let backdated = unix_now() as i64 - 10 * 60_000;
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE chunks SET last_access = ?1 WHERE address = ?2",
                rparams![backdated, &addr[..]],
            )
            .unwrap();
        }

        assert!(cache.get(addr).await.unwrap().is_some());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let after = read_last_access(&cache, addr).await;
        assert!(
            after > backdated,
            "stale last_access must be refreshed on read \
             (was {backdated}, now {after})",
        );
    }

    /// Ground truth for the mirrored counters, straight from SQL:
    /// `(unpinned bytes, unpinned rows, pinned bytes, pinned rows)`.
    fn sql_totals(path: &Path) -> (u64, u64, u64, u64) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(CASE WHEN pin_count = 0 THEN size ELSE 0 END), 0), \
                    COALESCE(SUM(CASE WHEN pin_count = 0 THEN 1 ELSE 0 END), 0), \
                    COALESCE(SUM(CASE WHEN pin_count > 0 THEN size ELSE 0 END), 0), \
                    COALESCE(SUM(CASE WHEN pin_count > 0 THEN 1 ELSE 0 END), 0) \
             FROM chunks",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                ))
            },
        )
        .unwrap()
    }

    /// The mirrored counters agree with SQL.
    fn assert_counters_match(cache: &DiskChunkCache, ctx: &str) {
        let (ub, ur, pb, pr) = sql_totals(cache.path());
        assert_eq!(cache.used_bytes(), ub, "{ctx}: used_bytes");
        assert_eq!(cache.used_rows(), ur + pr, "{ctx}: used_rows (all rows)");
        assert_eq!(cache.pinned_bytes(), pb, "{ctx}: pinned_bytes");
        assert_eq!(cache.pinned_rows(), pr, "{ctx}: pinned_rows");
        let conn = rusqlite::Connection::open(cache.path()).unwrap();
        let count = |t: &str| -> u64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap() as u64
        };
        assert_eq!(
            cache.pin_collections(),
            count("pins"),
            "{ctx}: pin_collections"
        );
        assert_eq!(
            cache.pin_member_refs(),
            count("pin_members"),
            "{ctx}: pin_member_refs"
        );
    }

    fn auto_vacuum_mode(path: &Path) -> i64 {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap()
    }

    /// `n` distinct ~4 KiB chunks keyed by `tag`.
    fn chunks(tag: u8, n: u32) -> Vec<([u8; 32], Vec<u8>)> {
        (0..n)
            .map(|i| {
                let mut payload = vec![tag; 4096];
                payload[..4].copy_from_slice(&i.to_le_bytes());
                make_chunk(&payload)
            })
            .collect()
    }

    /// Fill `cache` with `n` unpinned chunks and one pinned collection
    /// of `pinned_n` chunks (one of which is also first cached
    /// unpinned, so both pin paths — fresh row and existing row — run).
    async fn fill_with_pin(
        cache: &DiskChunkCache,
        n: u32,
        pinned_n: u32,
    ) -> (Vec<([u8; 32], Vec<u8>)>, Vec<([u8; 32], Vec<u8>)>, Vec<u8>) {
        let unpinned = chunks(0x11, n);
        for batch in unpinned.chunks(256) {
            cache.put_batch(batch.to_vec()).await.unwrap();
        }
        let pinned = chunks(0x22, pinned_n);
        cache.put(pinned[0].0, pinned[0].1.clone()).await.unwrap();
        let root = pinned[0].0.to_vec();
        assert!(cache
            .pin_collection(root.clone(), pinned.clone())
            .await
            .unwrap());
        (unpinned, pinned, root)
    }

    async fn clear_keeps_pins_and_shrinks(cache: &DiskChunkCache) {
        let (unpinned, pinned, root) = fill_with_pin(cache, 3000, 8).await;
        assert_counters_match(cache, "before clear");
        assert_eq!(cache.pinned_rows(), 8);
        assert_eq!(cache.used_rows(), 3000 + 8);
        let used_before = cache.used_bytes();
        let file_before = cache.file_bytes();
        assert!(
            file_before > 3000 * 4096,
            "file holds the chunks: {file_before}"
        );

        let report = cache.clear_unpinned().await.unwrap();
        assert_eq!(report.removed_chunks, 3000);
        assert_eq!(report.freed_bytes, used_before);
        assert_eq!(report.file_bytes_before, file_before);
        assert_eq!(report.file_bytes_after, cache.file_bytes());
        // Eight pinned 4 KiB chunks plus schema: well under 1 MiB, from
        // over 12 MiB.
        assert!(
            report.file_bytes_after < 1024 * 1024,
            "file shrank on disk: {} -> {}",
            report.file_bytes_before,
            report.file_bytes_after,
        );

        assert_eq!(cache.used_bytes(), 0);
        assert_eq!(cache.used_rows(), 8);
        assert_counters_match(cache, "after clear");
        for (addr, wire) in &pinned {
            assert_eq!(
                cache.get(*addr).await.unwrap().as_deref(),
                Some(wire.as_slice()),
                "pinned chunk still retrievable",
            );
        }
        for (addr, _) in unpinned.iter().step_by(97) {
            assert!(cache.get(*addr).await.unwrap().is_none(), "unpinned gone");
        }
        // Pin bookkeeping untouched: still listed, members intact, and
        // the unpin still returns every member to the budget.
        assert_eq!(cache.list_pins().await.unwrap(), vec![root.clone()]);
        let members = cache.pin_members(Some(root.clone())).await.unwrap();
        assert_eq!(members[0].1.len(), 8);
        assert_eq!(auto_vacuum_mode(cache.path()), 2, "incremental from now on");

        // The cache keeps working after the clear.
        let fresh = chunks(0x33, 10);
        cache.put_batch(fresh.clone()).await.unwrap();
        assert!(cache.get(fresh[3].0).await.unwrap().is_some());
        assert!(cache.unpin(root).await.unwrap());
        assert_eq!(cache.pinned_rows(), 0);
        assert_eq!(cache.pinned_bytes(), 0);
        assert_counters_match(cache, "after unpin");
    }

    /// Fresh database: created with incremental auto-vacuum, cleared
    /// with `incremental_vacuum`.
    #[tokio::test]
    async fn clear_keeps_pins_removes_unpinned_and_shrinks_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clear.sqlite");
        let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
        assert_eq!(
            auto_vacuum_mode(&path),
            2,
            "fresh DB gets incremental auto_vacuum"
        );
        clear_keeps_pins_and_shrinks(&cache).await;
        // A second clear (the refill plus the eight just unpinned) still works.
        let r = cache.clear_unpinned().await.unwrap();
        assert_eq!(r.removed_chunks, 18);
        assert_counters_match(&cache, "second clear");
    }

    /// A database from before auto-vacuum (mode NONE) is converted by
    /// one `VACUUM` on its first clear and still shrinks.
    #[tokio::test]
    async fn clear_shrinks_a_legacy_database_without_auto_vacuum() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        {
            // The pre-pin schema, as an old build left it.
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA page_size = 8192; PRAGMA journal_mode = WAL;
                 CREATE TABLE chunks (
                    address BLOB PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL,
                    last_access INTEGER NOT NULL, inserted_at INTEGER NOT NULL);",
            )
            .unwrap();
        }
        assert_eq!(auto_vacuum_mode(&path), 0);
        let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
        assert_eq!(
            auto_vacuum_mode(&path),
            0,
            "open never rebuilds an existing file"
        );
        clear_keeps_pins_and_shrinks(&cache).await;
    }

    /// The pre-pin, pre-auto-vacuum schema an old build left behind.
    fn make_legacy_db(path: &Path) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "PRAGMA page_size = 8192; PRAGMA journal_mode = WAL;
             CREATE TABLE chunks (
                address BLOB PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL,
                last_access INTEGER NOT NULL, inserted_at INTEGER NOT NULL);",
        )
        .unwrap();
    }

    #[test]
    fn legacy_vacuum_needs_room_and_a_bounded_size() {
        let mib = 1024 * 1024;
        assert!(legacy_vacuum_fits(10 * mib, Some(84 * mib)));
        assert!(
            !legacy_vacuum_fits(10 * mib, Some(83 * mib)),
            "2x live + margin"
        );
        assert!(
            !legacy_vacuum_fits(10 * mib, None),
            "unreadable free space is no room"
        );
        assert!(!legacy_vacuum_fits(
            LEGACY_VACUUM_MAX_LIVE_BYTES + 1,
            Some(u64::MAX)
        ));
        assert!(legacy_vacuum_fits(0, Some(LEGACY_VACUUM_FREE_MARGIN)));
    }

    /// A legacy database on a disk without room for the rebuild: the
    /// clear (and a shrink) still succeed with the rows gone, nothing is
    /// rebuilt, and the freed pages are reused. Once there's room, the
    /// next clear converts and shrinks the file.
    #[tokio::test]
    async fn legacy_clear_without_room_succeeds_and_skips_the_vacuum() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy-full.sqlite");
        make_legacy_db(&path);
        let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
        test_free_space::set(cache.path(), Some(1024));

        let (_unpinned, pinned, _root) = fill_with_pin(&cache, 2000, 8).await;
        let used = cache.used_bytes();
        let report = cache.clear_unpinned().await.expect("clear is not an error");
        assert_eq!(report.removed_chunks, 2000);
        assert_eq!(report.freed_bytes, used);
        assert_eq!(cache.used_bytes(), 0);
        assert_counters_match(&cache, "after clear without room");
        assert_eq!(auto_vacuum_mode(&path), 0, "not rebuilt");
        assert!(
            report.file_bytes_after > 2000 * 4096,
            "file kept its pages: {}",
            report.file_bytes_after
        );
        for (addr, wire) in &pinned {
            assert_eq!(
                cache.get(*addr).await.unwrap().as_deref(),
                Some(wire.as_slice())
            );
        }

        // A shrink without room: applied, evicted, no error, no rebuild.
        let refill = chunks(0x44, 2000);
        for batch in refill.chunks(256) {
            cache.put_batch(batch.to_vec()).await.unwrap();
        }
        let file_full = cache.file_bytes();
        cache
            .set_capacity(400 * 1024)
            .await
            .expect("shrink is not an error");
        assert_eq!(cache.capacity_bytes(), 400 * 1024);
        assert!(cache.used_bytes() <= 400 * 1024);
        assert_counters_match(&cache, "after shrink without room");
        assert_eq!(auto_vacuum_mode(&path), 0);
        // Freed pages are reused: refilling doesn't grow the file.
        cache.set_capacity(1 << 30).await.unwrap();
        for batch in chunks(0x55, 1500).chunks(256) {
            cache.put_batch(batch.to_vec()).await.unwrap();
        }
        assert!(
            cache.file_bytes() <= file_full + 1024 * 1024,
            "refill reused the freelist: {} vs {file_full}",
            cache.file_bytes()
        );

        // Room again: the next clear converts and shrinks.
        test_free_space::set(cache.path(), None);
        let report = cache.clear_unpinned().await.unwrap();
        assert_eq!(auto_vacuum_mode(&path), 2, "converted once there was room");
        assert!(
            report.file_bytes_after < 1024 * 1024,
            "file shrank: {}",
            report.file_bytes_after
        );
        assert_counters_match(&cache, "after converting clear");
    }

    /// A reader holding a snapshot (a stream mid-read) makes the WAL
    /// checkpoint busy; the clear must give up on it at once rather than
    /// wait out the write connection's busy timeout.
    #[tokio::test]
    async fn clear_does_not_wait_for_a_reader_to_checkpoint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reader.sqlite");
        let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
        fill_with_pin(&cache, 500, 4).await;

        let reader = rusqlite::Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let n: i64 = reader
            .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        assert!(n > 0);

        let t = std::time::Instant::now();
        let report = cache.clear_unpinned().await.unwrap();
        let took = t.elapsed();
        assert_eq!(report.removed_chunks, 500);
        assert!(
            took < std::time::Duration::from_millis(BUSY_TIMEOUT_MS / 2),
            "clear stalled on the reader: {took:?}"
        );
        // The writer still waits normally for real locks afterwards.
        cache.put_batch(chunks(0x66, 4)).await.unwrap();
        reader.execute_batch("COMMIT").unwrap();
        assert_counters_match(&cache, "after clear with a reader");
    }

    fn wal_bytes(path: &Path) -> u64 {
        let mut s = path.as_os_str().to_owned();
        s.push("-wal");
        std::fs::metadata(PathBuf::from(s)).map_or(0, |m| m.len())
    }

    /// When a reader blocks the post-clear `wal_checkpoint(TRUNCATE)`,
    /// the WAL the delete grew must not stay at its high-water size for
    /// the rest of the process: once the reader is gone, later writes
    /// checkpoint and reset it, and `journal_size_limit` cuts it back.
    #[tokio::test]
    async fn wal_shrinks_after_a_reader_blocked_the_clear_checkpoint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("walcap.sqlite");
        let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
        cache.put_batch(chunks(0x6f, 4)).await.unwrap();

        // A long stream holds its snapshot across the fill and the
        // clear, so no checkpoint can reset the WAL in between.
        let reader = rusqlite::Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))
            .unwrap();
        fill_with_pin(&cache, 5000, 4).await;
        cache.clear_unpinned().await.unwrap();
        let high = wal_bytes(&path);
        assert!(
            high > 2 * WAL_SIZE_LIMIT_BYTES as u64,
            "the blocked checkpoint left a big WAL: {high}"
        );
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);

        for i in 0..4u8 {
            cache.put_batch(chunks(0x70 + i, 4)).await.unwrap();
        }
        let after = wal_bytes(&path);
        assert!(
            after <= WAL_SIZE_LIMIT_BYTES as u64,
            "WAL cut back after the reader left: {high} -> {after}"
        );
        assert_counters_match(&cache, "after WAL reset");
    }

    /// Paths of this process's open-but-unlinked SQLite temp files.
    #[cfg(target_os = "linux")]
    fn open_sqlite_temp_files() -> Vec<String> {
        std::fs::read_dir("/proc/self/fd")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|p| p.contains("etilqs_"))
            .collect()
    }

    /// The legacy conversion's `VACUUM` must not need SQLite's temp
    /// directory (`/tmp`, `TMPDIR`, ...), which an Android app usually
    /// can't write: its copy is built in memory. Watches this process's
    /// fds for SQLite's `etilqs_*` temp file while the rebuild runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_vacuum_builds_its_copy_in_memory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy-mem.sqlite");
        make_legacy_db(&path);
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        {
            let tx = conn.transaction().unwrap();
            for (i, (addr, wire)) in chunks(0x44, 6000).into_iter().enumerate() {
                tx.execute(
                    "INSERT INTO chunks VALUES (?1, ?2, ?3, ?4, ?4)",
                    rusqlite::params![addr.to_vec(), wire, 4096, i as i64],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        test_free_space::set(&path, Some(u64::MAX / 4));

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut seen = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    seen.extend(open_sqlite_temp_files());
                }
                seen
            })
        };
        vacuum_free_pages(&mut conn, &path).unwrap();
        stop.store(true, Ordering::Relaxed);
        let mut seen = watcher.join().unwrap();
        seen.sort();
        seen.dedup();
        test_free_space::set(&path, None);

        assert_eq!(auto_vacuum_mode(&path), 2, "converted");
        assert!(
            seen.is_empty(),
            "VACUUM used an on-disk temp file: {seen:?}"
        );
        let ts: i64 = conn
            .query_row("PRAGMA temp_store", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ts, 0, "temp_store restored to the default");
    }

    /// Lowering the cap evicts down to it at once (unpinned rows only)
    /// and gives the file space back; raising it evicts nothing.
    #[tokio::test]
    async fn set_capacity_evicts_down_to_the_new_cap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cap.sqlite");
        let cache = DiskChunkCache::open(&path, 64 * 1024 * 1024).unwrap();
        let (_unpinned, pinned, _root) = fill_with_pin(&cache, 1000, 4).await;
        assert_counters_match(&cache, "filled");
        let used = cache.used_bytes();
        assert!(used > 1000 * 4096);
        let file_before = cache.file_bytes();

        // Raising (or keeping) the cap: nothing moves.
        cache.set_capacity(128 * 1024 * 1024).await.unwrap();
        assert_eq!(cache.capacity_bytes(), 128 * 1024 * 1024);
        assert_eq!(cache.used_bytes(), used);

        let cap = 400 * 1024;
        cache.set_capacity(cap).await.unwrap();
        assert_eq!(cache.capacity_bytes(), cap);
        assert!(
            cache.used_bytes() <= cap,
            "evicted to the cap: {}",
            cache.used_bytes()
        );
        assert!(cache.used_bytes() > 0, "evicts to the slack, not to empty");
        assert_counters_match(&cache, "after shrink");
        assert_eq!(cache.pinned_rows(), 4, "pins untouched");
        for (addr, _) in &pinned {
            assert!(cache.get(*addr).await.unwrap().is_some());
        }
        assert!(
            cache.file_bytes() < file_before / 4,
            "space returned: {file_before} -> {}",
            cache.file_bytes(),
        );

        // The new cap holds for later writes too.
        for batch in chunks(0x44, 300).chunks(100) {
            cache.put_batch(batch.to_vec()).await.unwrap();
        }
        assert!(cache.used_bytes() <= cap);
        assert_counters_match(&cache, "after refill");
    }

    /// Reopen backfills the pinned totals from disk.
    #[tokio::test]
    async fn pinned_totals_backfill_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("reopen.sqlite");
        {
            let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
            let (_, pinned, _) = fill_with_pin(&cache, 50, 6).await;
            // A second pin sharing two members: rows stay distinct,
            // member refs count per collection.
            let second = vec![pinned[1].clone(), pinned[2].clone()];
            assert!(cache.pin_collection(vec![0xee; 32], second).await.unwrap());
            assert_eq!(cache.pinned_rows(), 6);
            assert_eq!(cache.pin_collections(), 2);
            assert_eq!(cache.pin_member_refs(), 8);
            assert_counters_match(&cache, "first open");
        }
        let cache = DiskChunkCache::open(&path, 1 << 30).unwrap();
        // The backfill runs on the writer thread before it serves any
        // message, so one round trip through it is enough to wait for it.
        cache.put_batch(chunks(0x55, 1)).await.unwrap();
        assert_counters_match(&cache, "reopened");
        assert_eq!(cache.pinned_rows(), 6);
        assert_eq!(cache.pin_collections(), 2);
        assert!(cache.unpin(vec![0xee; 32]).await.unwrap());
        assert_eq!(
            cache.pinned_rows(),
            6,
            "shared members still pinned by the first"
        );
        assert_eq!(cache.pin_member_refs(), 6);
        assert_counters_match(&cache, "after unpinning the overlap");
    }

    /// Clears racing `put_batch` / `get` traffic: no request errors, no
    /// corruption, pins survive, counters stay exact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clear_is_safe_during_concurrent_put_batch_and_get() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("race.sqlite");
        let cache = Arc::new(DiskChunkCache::open(&path, 1 << 30).unwrap());
        let (seed, pinned, root) = fill_with_pin(&cache, 1500, 5).await;
        let seed = Arc::new(seed);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut tasks = Vec::new();
        for w in 0..3u8 {
            let cache = cache.clone();
            let stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                let mut round = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    let batch: Vec<_> = (0..32u32)
                        .map(|i| {
                            let mut p = vec![0x60 + w; 4096];
                            p[..4].copy_from_slice(&round.to_le_bytes());
                            p[4..8].copy_from_slice(&i.to_le_bytes());
                            make_chunk(&p)
                        })
                        .collect();
                    cache
                        .put_batch(batch)
                        .await
                        .expect("put_batch during clear");
                    round += 1;
                }
                round
            }));
        }
        let mut readers = Vec::new();
        for r in 0..4usize {
            let cache = cache.clone();
            let stop = stop.clone();
            let seed = seed.clone();
            let pinned = pinned.clone();
            readers.push(tokio::spawn(async move {
                let (mut hits, mut misses) = (0u64, 0u64);
                let mut i = r;
                while !stop.load(Ordering::Relaxed) {
                    let (addr, wire) = &seed[i % seed.len()];
                    match cache.get(*addr).await.expect("get during clear") {
                        Some(got) => {
                            assert_eq!(&got, wire, "a hit is never torn");
                            hits += 1;
                        }
                        None => misses += 1,
                    }
                    let (paddr, pwire) = &pinned[i % pinned.len()];
                    assert_eq!(
                        cache.get(*paddr).await.expect("pinned get").as_deref(),
                        Some(pwire.as_slice()),
                        "pinned chunk never misses",
                    );
                    i += 7;
                }
                (hits, misses)
            }));
        }

        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            cache.clear_unpinned().await.expect("clear under load");
        }
        stop.store(true, Ordering::Relaxed);
        let mut rounds = 0;
        for t in tasks {
            rounds += t.await.unwrap();
        }
        let (mut hits, mut misses) = (0, 0);
        for t in readers {
            let (h, m) = t.await.unwrap();
            hits += h;
            misses += m;
        }
        assert!(
            rounds > 0 && hits > 0 && misses > 0,
            "rounds={rounds} hits={hits} misses={misses}"
        );

        assert_counters_match(&cache, "after racing clears");
        assert_eq!(cache.pinned_rows(), 5);
        assert_eq!(cache.list_pins().await.unwrap(), vec![root]);
        let conn = rusqlite::Connection::open(&path).unwrap();
        let ok: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok");
    }
}
