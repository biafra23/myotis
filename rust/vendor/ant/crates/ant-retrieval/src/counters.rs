//! Process-wide retrieval counters.
//!
//! [`RetrievalCounters`] is a tiny `AtomicU64` bag the daemon clones
//! into every [`crate::RoutingFetcher`] it builds. Each successful
//! chunk delivery (network or cache) bumps the counters once, and the
//! status publisher reads cumulative totals from them when populating
//! [`StatusSnapshot::retrieval`] for `antop`.
//!
//! Only the *winning* fetch is counted toward `bytes_fetched_total` —
//! losing hedge dispatches that the drain task pulls to completion
//! consume real bytes on the wire, but counting them would inflate
//! the user-facing bandwidth gauge with bytes nobody asked for. The
//! winner-only accounting keeps the gauge aligned with the work the
//! daemon actually delivered.
//!
//! Cumulative-counter design (rather than a windowed average kept in
//! the daemon) is deliberate: the consumer (`antop`) already polls
//! at a known cadence, so it can derive instantaneous throughput by
//! diff'ing two consecutive snapshots and apply whatever smoothing /
//! peak-tracking it wants without burning daemon CPU on a sliding
//! window we'd then have to wire through the wire format.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Where a chunk delivery came from — fed into
/// [`RetrievalCounters::record_chunk`] so the snapshot can split the
/// "cache hits" gauge into per-tier counts.
///
/// Splitting tier 1 (in-memory LRU) from tier 2 (`SQLite`) matters for
/// `antop`'s diagnostic value: a hot daemon with a large warm
/// disk cache should show non-zero `disk` even right after restart,
/// while the same daemon serving repeat requests should drive `mem`
/// up and leave `disk` flat. Surfacing the two together makes a
/// disk-cache regression (e.g. validation failing every read so
/// nothing ever lifts into memory) visible to operators without
/// needing to enable trace logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkSource {
    /// Delivered by [`super::retrieve_chunk`] over the wire (or by a
    /// drained losing hedge that happened to win the race for a
    /// sibling fetch).
    Network,
    /// Served from the in-memory LRU
    /// ([`super::InMemoryChunkCache`]).
    Memory,
    /// Served from the persistent `SQLite` cache
    /// ([`super::DiskChunkCache`]). The chunk is also lifted into
    /// the in-memory tier on a tier-2 hit, but only one source is
    /// recorded per delivery — the one that actually saved the
    /// network round-trip.
    Disk,
}

/// Cumulative chunk / byte counters shared across every fetcher in
/// one daemon process.
#[derive(Debug, Default)]
pub struct RetrievalCounters {
    chunks_fetched: AtomicU64,
    bytes_fetched: AtomicU64,
    /// Tier-1 (in-memory LRU) hits. `mem_hits + disk_hits + network`
    /// always equals `chunks_fetched`.
    mem_hits: AtomicU64,
    /// Tier-2 (persistent `SQLite`) hits. Bumps the in-memory tier as
    /// a side effect of [`super::ChunkFetcher::fetch`], so a chunk
    /// that lands here lifts to memory and the *next* request for
    /// the same chunk will increment `mem_hits`.
    disk_hits: AtomicU64,
    /// Retrieval attempts that failed on the link (timeout, stream
    /// couldn't be opened) since the last chunk the network delivered.
    /// The swarm loop reads it to notice a wedged peer set (issue #83);
    /// see [`Self::record_link_failure`].
    link_failure_streak: AtomicU32,
}

/// Plain-old-data snapshot of [`RetrievalCounters`]. Cheaper to
/// thread into `StatusSnapshot` than locking each atomic individually
/// at the read site.
#[derive(Debug, Clone, Copy, Default)]
pub struct RetrievalCountersSnapshot {
    pub chunks_fetched: u64,
    pub bytes_fetched: u64,
    /// In-memory LRU hits.
    pub mem_hits: u64,
    /// Persistent `SQLite` cache hits.
    pub disk_hits: u64,
}

impl RetrievalCountersSnapshot {
    /// Total cache hits (memory + disk). Convenience for the
    /// `antop` "x cache hits" overall summary so the renderer
    /// doesn't have to add the two fields itself everywhere.
    #[must_use]
    pub const fn cache_hits(&self) -> u64 {
        self.mem_hits.saturating_add(self.disk_hits)
    }
}

impl RetrievalCounters {
    /// Build a fresh zero-initialised counter set. The daemon constructs
    /// exactly one of these and clones the `Arc` into every fetcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one chunk delivered to the joiner. `bytes` is the wire
    /// size (`span (8) || payload`); `source` tags which tier (or the
    /// network) actually produced the bytes for this delivery. Bytes
    /// are counted for every source so the cumulative `bytes_fetched`
    /// gauge stays aligned with what the joiner saw — callers that
    /// want network-only throughput can subtract `cache_hits *
    /// avg_size`.
    pub fn record_chunk(&self, bytes: u64, source: ChunkSource) {
        self.chunks_fetched.fetch_add(1, Ordering::Relaxed);
        self.bytes_fetched.fetch_add(bytes, Ordering::Relaxed);
        match source {
            ChunkSource::Memory => {
                self.mem_hits.fetch_add(1, Ordering::Relaxed);
            }
            ChunkSource::Disk => {
                self.disk_hits.fetch_add(1, Ordering::Relaxed);
            }
            ChunkSource::Network => {
                self.link_failure_streak.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Record one retrieval attempt that failed on the link to its peer
    /// (`RetrievalError::Timeout` / `OpenStream`): the kind of failure a
    /// dead socket produces, unlike a peer answering "not found". Any
    /// chunk delivered from the network resets the streak.
    pub fn record_link_failure(&self) {
        self.link_failure_streak.fetch_add(1, Ordering::Relaxed);
    }

    /// Link failures since the last chunk delivered from the network.
    pub fn link_failure_streak(&self) -> u32 {
        self.link_failure_streak.load(Ordering::Relaxed)
    }

    /// Start a new streak (the swarm loop calls this once it has acted on
    /// one).
    pub fn reset_link_failure_streak(&self) {
        self.link_failure_streak.store(0, Ordering::Relaxed);
    }

    /// Read all counters in one shot. Called by the status publisher
    /// on its periodic tick.
    pub fn snapshot(&self) -> RetrievalCountersSnapshot {
        RetrievalCountersSnapshot {
            chunks_fetched: self.chunks_fetched.load(Ordering::Relaxed),
            bytes_fetched: self.bytes_fetched.load(Ordering::Relaxed),
            mem_hits: self.mem_hits.load(Ordering::Relaxed),
            disk_hits: self.disk_hits.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_chunk_distinguishes_sources() {
        let c = RetrievalCounters::new();
        c.record_chunk(4104, ChunkSource::Network);
        c.record_chunk(4104, ChunkSource::Memory);
        c.record_chunk(4104, ChunkSource::Disk);
        c.record_chunk(4104, ChunkSource::Network);
        let s = c.snapshot();
        assert_eq!(s.chunks_fetched, 4);
        assert_eq!(s.bytes_fetched, 4 * 4104);
        assert_eq!(s.mem_hits, 1);
        assert_eq!(s.disk_hits, 1);
        assert_eq!(s.cache_hits(), 2);
    }

    #[test]
    fn link_failure_streak_resets_on_network_delivery_only() {
        let c = RetrievalCounters::new();
        c.record_link_failure();
        c.record_link_failure();
        c.record_chunk(4104, ChunkSource::Memory);
        c.record_chunk(4104, ChunkSource::Disk);
        assert_eq!(
            c.link_failure_streak(),
            2,
            "cache hits say nothing about links"
        );
        c.record_chunk(4104, ChunkSource::Network);
        assert_eq!(c.link_failure_streak(), 0);
        c.record_link_failure();
        c.reset_link_failure_streak();
        assert_eq!(c.link_failure_streak(), 0);
    }
}
