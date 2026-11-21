//! Short-TTL "this peer just bounced a pushsync — leave it alone for a
//! few seconds" cache.
//!
//! # Why this exists
//!
//! The retrieval-side `RoutingFetcher` blacklist is scoped to one
//! retrieval attempt. The pushsync-side skip list inside
//! [`crate::fetcher::RoutingFetcher::push_stamped_chunk`] is scoped to
//! **one chunk**: once we move on to chunk N+1 we pick the next-closest
//! peer afresh, and on a small mainnet bee 2.7→2.8 cutover the closest
//! candidates for adjacent chunks are almost always the same handful of
//! peers. So a peer that just RST'd us on chunk N gets picked again for
//! chunk N+1 a few milliseconds later, RSTs us again, and the cycle
//! eats through the per-chunk skip-list quota one chunk at a time.
//!
//! Observed in a 1 MiB B2 baseline (3 runs, 260 + 2 chunks each):
//! 412 `pushsync attempt failed; skipping peer for this chunk` log
//! lines, with the top 5 offenders responsible for 77 of those —
//! every one a "Connection is closed" mid-pushsync from the same
//! repeat-offender bee 2.7.1 storer. Those 5 peers were dialed by
//! adjacent chunks dozens of times in a row, never given a chance to
//! recover.
//!
//! The cache here is a process-wide `(PeerId → Instant_until)` map.
//! Pushsync consults it before ranking the candidate set and filters
//! out any peer whose entry hasn't expired yet. The fetcher writes
//! entries on every transient error. TTL is short (5 s by default) so
//! a peer that recovers quickly only sits out a handful of chunks.
//!
//! Crucially this is a **soft** filter: if literally every closest
//! peer is in the cache we still try them — better to push to a
//! flapping peer than to fail the chunk. See [`PushSkipCache::filter`]
//! for that fall-through.
//!
//! # Sizing
//!
//! At the observed worst-case rate (a 1 MiB upload generates ~260
//! chunks in a few seconds and may touch ~50 distinct peers across
//! its lifetime) the cache holds tens of entries at peak. We GC
//! expired entries on every write so it never grows unbounded.

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default cool-down for a peer that just failed a pushsync.
///
/// Tuned for the bee 2.7→2.8 cutover: bee 2.7.x storers under
/// receipt-batching load take 10-25 s to recover from a load-shedding
/// `Disconnect`, but a faulty 2.7.1 with a flapping yamux session
/// recovers in well under a second. 5 s splits the difference: long
/// enough to give a real load-shed peer time to settle, short enough
/// that a transient yamux blip doesn't park them out of an upload's
/// entire critical path. Operators on a faster local fleet can drop
/// this; on a public mainnet under cutover stress, 5 s is a sweet
/// spot in our B2/B5 measurements.
pub const DEFAULT_SKIP_TTL: Duration = Duration::from_secs(5);

/// Hard ceiling on the entry count. Past this we fail closed (drop
/// new writes silently) rather than letting the map grow unbounded
/// under a pathological gossip storm. In practice the GC sweep on
/// every write keeps the live size well below this.
const MAX_ENTRIES: usize = 4096;

/// Cheaply-cloneable handle to a shared skip cache. The daemon
/// constructs one and clones it into every `RoutingFetcher` built
/// for `PushChunk` / `PushSoc` so the per-peer cool-down persists
/// across chunks within an upload (and across uploads while the
/// daemon is up).
#[derive(Clone, Default)]
pub struct PushSkipCache {
    inner: std::sync::Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<PeerId, Instant>,
}

impl PushSkipCache {
    /// Empty cache, ready to share.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Note that `peer` just failed a pushsync. Caller stays
    /// responsible for whether the failure was transient or fatal —
    /// this method always records the entry. Re-noting an already-
    /// skipped peer pushes its expiry forward (so a peer that
    /// keeps failing stays skipped continuously).
    pub fn note_failure(&self, peer: PeerId, ttl: Duration) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        // GC opportunistically on every write so the map never
        // accumulates past its working set.
        g.entries.retain(|_, until| *until > now);
        if g.entries.len() >= MAX_ENTRIES {
            return;
        }
        let until = now + ttl;
        g.entries.insert(peer, until);
    }

    /// `true` iff `peer` is currently in the skip set. Cheap O(1).
    /// Pushsync uses this in its ranking loop after sorting by XOR
    /// distance, so the call cost is paid once per chunk + once per
    /// skip-retry, not once per peer in the routing table.
    #[must_use]
    pub fn is_skipped(&self, peer: PeerId) -> bool {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.entries
            .get(&peer)
            .is_some_and(|until| *until > Instant::now())
    }

    /// Drop `peer` from the skip set immediately. Used when a
    /// pushsync against the peer subsequently succeeds — clearing
    /// the cool-down lets the peer re-enter the ranked candidate
    /// list for the next chunk instead of waiting out the TTL.
    pub fn clear(&self, peer: PeerId) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.entries.remove(&peer);
    }

    /// Test / debug: current live entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        g.entries.values().filter(|u| **u > now).count()
    }

    /// `true` when no live entries remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PeerId {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        PeerId::from(kp.public())
    }

    #[test]
    fn empty_cache_skips_nothing() {
        let cache = PushSkipCache::new();
        assert!(!cache.is_skipped(pid()));
        assert!(cache.is_empty());
    }

    #[test]
    fn noted_peer_is_skipped() {
        let cache = PushSkipCache::new();
        let p1 = pid();
        let p2 = pid();
        cache.note_failure(p1, Duration::from_mins(1));
        assert!(cache.is_skipped(p1));
        assert!(!cache.is_skipped(p2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ttl_expiry_releases_peer() {
        let cache = PushSkipCache::new();
        let p1 = pid();
        cache.note_failure(p1, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(!cache.is_skipped(p1));
    }

    #[test]
    fn clear_removes_entry_immediately() {
        let cache = PushSkipCache::new();
        let p1 = pid();
        cache.note_failure(p1, Duration::from_mins(1));
        assert!(cache.is_skipped(p1));
        cache.clear(p1);
        assert!(!cache.is_skipped(p1));
    }

    #[test]
    fn renote_extends_ttl() {
        let cache = PushSkipCache::new();
        let p1 = pid();
        cache.note_failure(p1, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(30));
        cache.note_failure(p1, Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(50));
        // First TTL would have expired by now (80 ms total elapsed
        // vs. 50 ms TTL), but the re-note extended it. We're at
        // 80 ms into a 30+100 = 130 ms total window.
        assert!(cache.is_skipped(p1));
    }
}
