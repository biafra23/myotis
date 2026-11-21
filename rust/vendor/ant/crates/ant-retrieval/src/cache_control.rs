//! See, clear and size the node's chunk caches at runtime.
//!
//! The node keeps two chunk caches: the persistent `SQLite` one
//! ([`DiskChunkCache`], byte-capped) and an in-memory LRU
//! ([`InMemoryChunkCache`], slot-capped). Pinned chunks live in the same
//! database but outside the byte cap, so a host can't just delete the
//! file; [`ChunkCaches`] clears and resizes the cache while leaving pins
//! alone.
//!
//! Both entry points sequence these: ant-ffi's `ant_cache_status` /
//! `ant_cache_clear` / `ant_cache_set_capacity`, and the gateway's
//! `/v0/cache` routes (which `antd` serves). The JSON shapes are the
//! same on both.

use std::sync::Arc;

use crate::{ClearReport, DiskCacheError, DiskChunkCache, InMemoryChunkCache};

/// Smallest disk cap a host can set at runtime: 64 MiB. Below that the
/// cache holds too little of a manifest + media tree to save a refetch.
pub const CACHE_CAPACITY_MIN_BYTES: u64 = 64 * 1024 * 1024;

/// Largest disk cap a host can set at runtime: 16 GiB.
pub const CACHE_CAPACITY_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Clamp a host-requested cap into
/// [`CACHE_CAPACITY_MIN_BYTES`]..=[`CACHE_CAPACITY_MAX_BYTES`].
#[must_use]
pub fn clamp_capacity(bytes: u64) -> u64 {
    bytes.clamp(CACHE_CAPACITY_MIN_BYTES, CACHE_CAPACITY_MAX_BYTES)
}

/// Why [`ChunkCaches::set_capacity`] failed.
#[derive(Debug, thiserror::Error)]
pub enum SetCapacityError {
    /// No disk cache: disabled by config, or it failed to open at start.
    #[error("disk chunk cache is not available")]
    Unavailable,
    /// The eviction down to the new cap failed. The cap is still
    /// applied, part of the eviction may have committed, and the next
    /// cache write evicts down to it again.
    #[error("set cache capacity: {0}")]
    Evict(#[from] DiskCacheError),
}

/// The caches the node loop reads and writes. Shared `Arc`s, not
/// copies: clearing or resizing through this acts on the live caches.
#[derive(Clone)]
pub struct ChunkCaches {
    /// `None` when the disk cache is disabled or failed to open.
    pub disk: Option<Arc<DiskChunkCache>>,
    /// The node loop's process-wide in-memory cache (handed to it with
    /// `NodeConfig::with_memory_cache`).
    pub memory: Arc<InMemoryChunkCache>,
}

impl ChunkCaches {
    /// Chunk cache figures, as JSON:
    ///
    /// ```json
    /// {"disk_enabled":true,"used_bytes":0,"capacity_bytes":0,"pinned_bytes":0,
    ///  "chunks":0,"pinned_chunks":0,"file_bytes":0,
    ///  "memory_chunks":0,"memory_capacity_chunks":8192}
    /// ```
    ///
    /// * `used_bytes` / `chunks`: unpinned cached chunks, the ones
    ///   counted against `capacity_bytes` and evicted oldest-first past it.
    /// * `pinned_bytes` / `pinned_chunks`: pinned chunks, outside the cap.
    /// * `file_bytes`: the database plus its `-wal` / `-shm` on disk.
    /// * `memory_chunks` / `memory_capacity_chunks`: the in-memory cache.
    /// * `disk_enabled`: `false` when there is no disk cache; every disk
    ///   figure is then `0`.
    ///
    /// Reads counters and three `stat`s, never the database: cheap
    /// enough to poll every few seconds. Right after start on a large
    /// cache the disk counters read `0` until a background count
    /// finishes (seconds).
    #[must_use]
    pub fn status_json(&self) -> serde_json::Value {
        let (used_bytes, capacity_bytes, pinned_bytes, chunks, pinned_chunks, file_bytes) =
            self.disk.as_deref().map_or((0, 0, 0, 0, 0, 0), |d| {
                let pinned_chunks = d.pinned_rows();
                (
                    d.used_bytes(),
                    d.capacity_bytes(),
                    d.pinned_bytes(),
                    d.used_rows().saturating_sub(pinned_chunks),
                    pinned_chunks,
                    d.file_bytes(),
                )
            });
        serde_json::json!({
            "disk_enabled": self.disk.is_some(),
            "used_bytes": used_bytes,
            "capacity_bytes": capacity_bytes,
            "pinned_bytes": pinned_bytes,
            "chunks": chunks,
            "pinned_chunks": pinned_chunks,
            "file_bytes": file_bytes,
            "memory_chunks": self.memory.len(),
            "memory_capacity_chunks": self.memory.capacity(),
        })
    }

    /// Remove every unpinned chunk from the disk cache, empty the
    /// in-memory cache, and give the space back to the OS. Never touches
    /// pinned chunks or pin bookkeeping. With no disk cache only the
    /// in-memory cache is emptied (`status.disk_enabled` is `false`).
    ///
    /// Safe while downloads and uploads run: a read racing the clear
    /// gets the chunk or a cache miss (and then fetches it from the
    /// network); cache writes queue behind the clear and land after it.
    ///
    /// Returns JSON:
    ///
    /// ```json
    /// {"freed_bytes":0,"removed_chunks":0,"file_bytes_before":0,
    ///  "file_bytes_after":0,"memory_chunks_removed":0,"status":{...}}
    /// ```
    ///
    /// `freed_bytes` is the chunk bytes removed (what `used_bytes`
    /// dropped by); `file_bytes_before - file_bytes_after` is what the
    /// files on disk shrank by. Giving space back is best-effort: a
    /// database from an older build is only rebuilt (once) when the
    /// pinned data left is small and the disk has room, so the shrink can
    /// be 0 on a successful clear (see [`DiskChunkCache::clear_unpinned`]).
    /// `status` is [`Self::status_json`] after the clear.
    pub async fn clear(&self) -> Result<serde_json::Value, DiskCacheError> {
        let report = match &self.disk {
            Some(disk) => disk.clear_unpinned().await?,
            None => ClearReport::default(),
        };
        let memory_chunks_removed = self.memory.len();
        self.memory.clear();
        tracing::info!(
            target: "ant_retrieval::cache",
            ?report,
            memory_chunks_removed,
            "chunk cache cleared (pins kept)",
        );
        Ok(serde_json::json!({
            "freed_bytes": report.freed_bytes,
            "removed_chunks": report.removed_chunks,
            "file_bytes_before": report.file_bytes_before,
            "file_bytes_after": report.file_bytes_after,
            "memory_chunks_removed": memory_chunks_removed,
            "status": self.status_json(),
        }))
    }

    /// Set the disk cache cap, clamped with [`clamp_capacity`], and
    /// return the cap applied. Lowering it below `used_bytes` evicts
    /// oldest-first down to ~95% of the new cap before returning and
    /// gives the space back to the OS; pinned chunks are never evicted
    /// and don't count. Not persisted.
    pub async fn set_capacity(&self, bytes: u64) -> Result<u64, SetCapacityError> {
        let disk = self.disk.as_ref().ok_or(SetCapacityError::Unavailable)?;
        let applied = clamp_capacity(bytes);
        disk.set_capacity(applied).await?;
        tracing::info!(
            target: "ant_retrieval::cache",
            requested = bytes,
            applied,
            used_bytes = disk.used_bytes(),
            "disk chunk cache capacity set",
        );
        Ok(applied)
    }
}
