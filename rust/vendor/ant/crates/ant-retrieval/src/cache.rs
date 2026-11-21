//! In-memory LRU chunk cache shared across retrieval requests.
//!
//! The retrieval pipeline already CAC-validates every chunk on the
//! way out of [`crate::retrieve_chunk`], so cached entries are trusted
//! without re-hashing on the read path. The cache is read on every
//! [`crate::ChunkFetcher::fetch`] before we ask the network and
//! written on every successful network fetch, so:
//!
//! * Re-fetches inside a single retry attempt (e.g. a transient peer
//!   disconnect mid-walk) skip the network for chunks we've already
//!   pulled in this request — turning what was a full round-trip
//!   for the second retry into a memcpy.
//! * The whole-fetch retry wrapper in `ant-p2p` benefits transparently:
//!   attempt N+1 finds every chunk attempt N already pulled and only
//!   the dropped ones go back over the wire.
//! * A second `antctl get` of the same reference (or any reference
//!   that shares manifest / data nodes) on the same daemon process
//!   skips the network entirely.
//!
//! This is the in-memory tier described in `PLAN.md` § "chunk store".
//! A persistent tier backed by `SQLite` will sit underneath later;
//! the [`crate::ChunkFetcher`] integration in [`crate::RoutingFetcher`]
//! is unchanged when that lands — it just becomes a write-through
//! to the persistent layer below.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// Default cache size in chunk slots. 8192 chunks × ~4.1 KiB
/// (span + payload) ≈ 32 MiB resident, which is comfortable headroom
/// for the largest single file we'd realistically retrieve in one
/// go (a 30 MB blob is ≈7400 leaves) while still fitting the
/// "small daemon on a low-RAM box" target in `PLAN.md`.
pub const DEFAULT_CAPACITY: usize = 8 * 1024;

/// Thread-safe LRU cache from chunk address to wire bytes
/// (`span (8 LE) || payload`). Operations are O(1); the lock is held
/// only across the in-memory map op itself, never across an `.await`,
/// so concurrent fetchers don't serialise on it.
pub struct InMemoryChunkCache {
    inner: Mutex<LruCache<[u8; 32], Vec<u8>>>,
}

impl InMemoryChunkCache {
    /// Build a cache with `capacity` slots. Capacity is clamped to at
    /// least 1 — `LruCache::new` panics on zero, but a daemon misconfig
    /// shouldn't take the process down.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity clamped to >= 1 above");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Convenience: a cache sized at [`DEFAULT_CAPACITY`].
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Cache lookup. `Some(wire_bytes)` on a hit (also bumps the entry
    /// to most-recently-used); `None` on a miss.
    pub fn get(&self, addr: &[u8; 32]) -> Option<Vec<u8>> {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        guard.get(addr).cloned()
    }

    /// Insert. Overwrites any existing entry for `addr`; bumps to MRU.
    /// Cloning the value at insert is cheap (4 KiB memcpy) and keeps
    /// the public API working with owned `Vec<u8>` on both sides.
    pub fn put(&self, addr: [u8; 32], data: Vec<u8>) {
        let mut guard = self.inner.lock().expect("cache mutex poisoned");
        guard.put(addr, data);
    }

    /// Number of slots currently used. Mostly for diagnostics / tests.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("cache mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Slot capacity (the LRU bound), as built.
    pub fn capacity(&self) -> usize {
        self.inner.lock().expect("cache mutex poisoned").cap().get()
    }

    /// Drop every entry. A fetch racing this simply misses and goes to
    /// the next tier; nothing else depends on an entry staying put.
    pub fn clear(&self) {
        self.inner.lock().expect("cache mutex poisoned").clear();
    }
}

impl Default for InMemoryChunkCache {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips() {
        let cache = InMemoryChunkCache::new(4);
        let addr = [0xAB; 32];
        let bytes = vec![1, 2, 3, 4];
        cache.put(addr, bytes.clone());
        assert_eq!(cache.get(&addr), Some(bytes));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn miss_returns_none() {
        let cache = InMemoryChunkCache::new(4);
        assert!(cache.get(&[0u8; 32]).is_none());
        assert!(cache.is_empty());
    }

    /// Inserting past `capacity` evicts the least-recently-used entry.
    /// Critical correctness property: a runaway request shouldn't
    /// leak unbounded memory through a "cache".
    #[test]
    fn lru_eviction_drops_oldest() {
        let cache = InMemoryChunkCache::new(2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        cache.put(a, vec![10]);
        cache.put(b, vec![20]);
        // Touch `a` so it becomes MRU and `b` becomes LRU.
        let _ = cache.get(&a);
        cache.put(c, vec![30]);
        assert_eq!(cache.get(&a), Some(vec![10]));
        assert!(cache.get(&b).is_none(), "b should have been evicted");
        assert_eq!(cache.get(&c), Some(vec![30]));
    }

    #[test]
    fn clear_empties_and_keeps_capacity() {
        let cache = InMemoryChunkCache::new(4);
        cache.put([1u8; 32], vec![1]);
        cache.put([2u8; 32], vec![2]);
        assert_eq!(cache.capacity(), 4);
        cache.clear();
        assert!(cache.is_empty());
        assert!(cache.get(&[1u8; 32]).is_none());
        assert_eq!(cache.capacity(), 4);
    }

    /// Zero-capacity construction shouldn't panic; we clamp to 1.
    #[test]
    fn zero_capacity_clamps_to_one() {
        let cache = InMemoryChunkCache::new(0);
        cache.put([0u8; 32], vec![1]);
        assert_eq!(cache.len(), 1);
    }
}
