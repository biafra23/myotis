//! The in-memory light-client store — what the serving path reads.
//!
//! # Pre-encoded, deliberately
//!
//! Everything here is held as the **fully encoded libp2p response**
//! (`result byte || fork digest || varint || snappy frames`), not raw SSZ.
//! Serving is then a memcpy and a write, with no per-peer computation — which
//! is precisely what §Capacity in docs/lc-server-design.md rests on. Every
//! client receives identical bytes, so the snappy work happens once at ingest
//! rather than once per wallet.
//!
//! # Synchronous by requirement, not by preference
//!
//! `respond_inbound` in `myotis-net` is **synchronous**, called inline from
//! `on_rr_event` on the single swarm task — there is no `await` point. So this
//! is a `std::sync::RwLock`, never a `tokio::sync::RwLock`: an async lock could
//! not be taken there, and an on-demand fetch inside the handler would either
//! stall every other connection's handshakes for an HTTP round trip or
//! `block_on` inside a tokio worker and panic.
//!
//! The consequence is the design's item 4: **the handler is a pure cache read,
//! and a miss stays `ResourceUnavailable`**, with a background task filling it.
//! That is correct behaviour — a wallet retries against another peer and the
//! second attempt hits — and it preserves the broadcast-cache property.
//!
//! # Bounds
//!
//! This is a public responder and `updates_by_range` carries caller-controlled
//! `u64` start and count, so a connection cap alone does not bound the work
//! (design item 5). Enforced here: the spec's
//! `MAX_REQUEST_LIGHT_CLIENT_UPDATES`, a total response byte cap, refusal of
//! ranges outside the servable window rather than scanning them, and a hard cap
//! on cached bootstraps — which are keyed by arbitrary block root and therefore
//! the one genuinely unbounded key space.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use myotis_net::codec::{decode_multi_chunk_response, encode_success_response};

use crate::rest::MAX_REQUEST_LIGHT_CLIENT_UPDATES;

/// Cap on a single `updates_by_range` response body.
///
/// 128 updates × ~27 KB is ~3.4 MB, so this is the count cap's natural
/// companion rather than a tighter constraint — it exists so a future fork
/// growing `LightClientUpdate` cannot silently turn a legal request into a
/// multi-hundred-megabyte write.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Cap on cached bootstraps.
///
/// Bootstraps are keyed by an arbitrary block root, so this is the only part of
/// the store an unco-operative caller could otherwise grow without limit.
///
/// The cap is enforced by FIFO **eviction**, not refusal — see
/// [`LcStore::insert_bootstrap`] for why that distinction is load-bearing. What
/// bounds the *upstream* cost of arbitrary roots is
/// [`MAX_BOOTSTRAP_MISSES`] plus the once-only attempt rule, not this number.
pub const MAX_BOOTSTRAPS: usize = 64;

/// Cap on roots queued for a background bootstrap fetch.
///
/// The queue is the other half of "ResourceUnavailable is the miss path": a
/// wallet's FIRST bootstrap request is for its own pinned checkpoint root,
/// which no amount of pre-population can guess, so a server that only ever
/// caches the current finalized root refuses every cold wallet forever. Bounded
/// and coalesced so one caller cannot turn misses into a burst of upstream
/// fetches.
pub const MAX_BOOTSTRAP_MISSES: usize = 32;

#[derive(Debug, Default)]
struct Inner {
    /// period → pre-encoded single chunk.
    updates: BTreeMap<u64, Arc<[u8]>>,
    /// block root → pre-encoded response.
    bootstraps: HashMap<[u8; 32], Arc<[u8]>>,
    finality: Option<Arc<[u8]>>,
    optimistic: Option<Arc<[u8]>>,
    /// Insertion order for `bootstraps`, so eviction is FIFO rather than
    /// whatever order the map happens to iterate in.
    bootstrap_order: VecDeque<[u8; 32]>,
    /// Roots a caller asked for and we did not have — drained by the background
    /// filler, in ARRIVAL order.
    ///
    /// A queue plus a membership set rather than an ordered set: draining a
    /// `BTreeSet` in key order would let a caller starve a legitimate checkpoint
    /// indefinitely by enqueueing lexicographically smaller roots before every
    /// tick, and the whole point of the queue is that a cold wallet's pinned
    /// root gets fetched.
    bootstrap_misses: VecDeque<[u8; 32]>,
    bootstrap_miss_set: BTreeSet<[u8; 32]>,
    /// Roots already attempted, so a root the upstream cannot serve is fetched
    /// once rather than on every retry of a wallet that will keep asking.
    /// The set answers "seen?"; the queue fixes the eviction order.
    bootstrap_attempted: BTreeSet<[u8; 32]>,
    bootstrap_attempted_order: VecDeque<[u8; 32]>,
    /// Digest of the highest period inserted so far.
    newest_fork_digest: Option<[u8; 4]>,
}

/// Shared, cheap to clone, safe to read from the swarm task.
#[derive(Debug, Default)]
pub struct LcStore {
    inner: RwLock<Inner>,
}

/// A snapshot of what the store can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub lowest_period: Option<u64>,
    pub highest_period: Option<u64>,
    pub periods: usize,
    pub bootstraps: usize,
    pub has_finality: bool,
    pub has_optimistic: bool,
    pub update_bytes: usize,
}

impl LcStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock accessors that IGNORE poisoning.
    ///
    /// A panic while one of these locks is held would otherwise poison it and
    /// make every later `unwrap()` panic too — so a single panic anywhere on
    /// the swarm task would convert this store into one that refuses forever.
    /// Nothing here has an invariant a torn write can break in a way a reader
    /// would misinterpret: the maps hold immutable pre-encoded byte blobs, and
    /// the worst case is a bootstrap present in the map but missing from the
    /// eviction queue, which costs one extra entry. Serving stale-but-valid
    /// bytes beats serving nothing.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    // --- ingestion (background tasks only; never the request path) --------

    /// Encode once, at ingest. `fork_digest` is the digest the source framed,
    /// re-emitted verbatim — not derived from a fork name, which since EIP-7892
    /// would not determine it.
    /// Raw SSZ of the held update for `period` (wire framing stripped), for the
    /// ingest-refresh decision — see `fill_periods` / the CLI ingest fill loop.
    /// `None` when the period is not held (or, defensively, when our own wire
    /// encoding fails to round-trip).
    pub fn update_ssz(&self, period: u64) -> Option<Vec<u8>> {
        let wire = self.read().updates.get(&period).cloned()?;
        decode_multi_chunk_response(&wire, 1)
            .ok()?
            .into_iter()
            .next()
    }

    pub fn insert_update(&self, period: u64, fork_digest: [u8; 4], ssz: &[u8]) {
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        let mut inner = self.write();
        let newest = inner.updates.keys().next_back().copied();
        if newest.is_none_or(|n| period >= n) {
            inner.newest_fork_digest = Some(fork_digest);
        }
        inner.updates.insert(period, wire);
    }

    pub fn set_finality(&self, fork_digest: [u8; 4], ssz: &[u8]) {
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        self.write().finality = Some(wire);
    }

    pub fn set_optimistic(&self, fork_digest: [u8; 4], ssz: &[u8]) {
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        self.write().optimistic = Some(wire);
    }

    /// Cache a bootstrap, evicting the least recently inserted root when full.
    /// Returns the evicted root, if any.
    ///
    /// Eviction rather than refusal, and the difference is not cosmetic: the
    /// finalized checkpoint advances every epoch, so a cache that refuses when
    /// full would stop accepting new finalized roots after
    /// `MAX_BOOTSTRAPS` epochs — a few hours — and from then on serve no
    /// bootstrap any live wallet could use, while looking perfectly healthy.
    pub fn insert_bootstrap(
        &self,
        block_root: [u8; 32],
        fork_digest: [u8; 4],
        ssz: &[u8],
    ) -> Option<[u8; 32]> {
        let mut inner = self.write();
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();

        // Refreshing an existing root must not re-queue it for eviction, or a
        // repeatedly refreshed root would push everything else out.
        if inner.bootstraps.insert(block_root, wire).is_some() {
            return None;
        }
        inner.bootstrap_order.push_back(block_root);

        let mut evicted = None;
        while inner.bootstrap_order.len() > MAX_BOOTSTRAPS {
            if let Some(oldest) = inner.bootstrap_order.pop_front() {
                inner.bootstraps.remove(&oldest);
                // Clearing the attempted marker with it is what keeps the
                // invariant "never attempted-without-cached" true by
                // construction rather than by arithmetic accident. Both sets are
                // capped at MAX_BOOTSTRAPS but fill at different rates —
                // `refresh_live` inserts the finalized root into `bootstraps`
                // without touching `attempted` — so an evicted root could
                // otherwise sit marked-attempted and uncached, and be refused
                // with no re-fetch until the marker aged out.
                //
                // Roots the upstream CANNOT serve are unaffected: they never
                // entered `bootstraps`, so nothing here evicts them and their
                // marker keeps doing its job.
                inner.bootstrap_attempted.remove(&oldest);
                inner.bootstrap_attempted_order.retain(|r| r != &oldest);
                evicted = Some(oldest);
            }
        }
        evicted
    }

    /// Drop every cached bootstrap, so they are refetched and re-stamped.
    ///
    /// Called when the fork schedule changes. Bootstraps are the only objects
    /// encoded ONCE and then kept: the per-slot objects are refetched every
    /// tick and periods carry the digest their source framed, but a bootstrap
    /// cached under an old schedule would keep its stale context bytes until
    /// FIFO eviction pushed it out — potentially hours, for the pinned
    /// checkpoint a cold wallet actually asks for.
    ///
    /// Clears the attempted markers with them, for the same reason eviction
    /// does: a root that is uncached but still marked attempted is refused with
    /// no re-fetch.
    pub fn clear_bootstraps(&self) -> usize {
        let mut inner = self.write();
        let dropped = inner.bootstraps.len();
        for root in inner.bootstrap_order.clone() {
            inner.bootstrap_attempted.remove(&root);
            inner.bootstrap_attempted_order.retain(|r| r != &root);
        }
        inner.bootstraps.clear();
        inner.bootstrap_order.clear();
        dropped
    }

    /// Queue a root for the background filler. Returns false when the queue is
    /// full or the root was already attempted — both mean "do not fetch".
    pub fn record_bootstrap_miss(&self, root: [u8; 32]) -> bool {
        // Read-lock first. This runs on the swarm task for EVERY miss, so a
        // caller spamming unknown roots must not be able to serialise the
        // responder behind a write lock it will not end up needing.
        {
            let inner = self.read();
            if inner.bootstrap_attempted.contains(&root)
                || inner.bootstrap_miss_set.contains(&root)
                || inner.bootstrap_misses.len() >= MAX_BOOTSTRAP_MISSES
            {
                return false;
            }
        }
        let mut inner = self.write();
        // Re-check: the lock was released in between.
        if inner.bootstrap_attempted.contains(&root)
            || inner.bootstrap_miss_set.contains(&root)
            || inner.bootstrap_misses.len() >= MAX_BOOTSTRAP_MISSES
        {
            return false;
        }
        inner.bootstrap_misses.push_back(root);
        inner.bootstrap_miss_set.insert(root);
        true
    }

    /// Put a root back at the FRONT of the queue and clear its attempted marker.
    ///
    /// For TRANSIENT upstream failures only. Without this, one Nimbus timeout
    /// would permanently poison a wallet's pinned checkpoint: the root is marked
    /// attempted before the fetch, so every later request for it is refused with
    /// no re-fetch, forever.
    pub fn requeue_bootstrap_miss(&self, root: [u8; 32]) {
        let mut inner = self.write();
        inner.bootstrap_attempted.remove(&root);
        inner.bootstrap_attempted_order.retain(|r| r != &root);
        if inner.bootstrap_miss_set.insert(root) {
            inner.bootstrap_misses.push_front(root);
        }
    }

    /// Drain at most `max` queued roots, marking them attempted.
    pub fn take_bootstrap_misses(&self, max: usize) -> Vec<[u8; 32]> {
        let mut inner = self.write();
        let mut taken: Vec<[u8; 32]> = Vec::new();
        while taken.len() < max {
            match inner.bootstrap_misses.pop_front() {
                Some(root) => taken.push(root),
                None => break,
            }
        }
        for root in &taken {
            inner.bootstrap_miss_set.remove(root);
            if inner.bootstrap_attempted.insert(*root) {
                inner.bootstrap_attempted_order.push_back(*root);
            }
        }
        // The attempted set is a negative cache, not a log: bound it, evicting
        // in INSERTION order. A BTreeSet iterates by key, so trimming from its
        // front would drop whichever root happens to sort lowest — arbitrary,
        // and it would keep re-attempting roots we just gave up on.
        while inner.bootstrap_attempted_order.len() > MAX_BOOTSTRAPS {
            if let Some(oldest) = inner.bootstrap_attempted_order.pop_front() {
                inner.bootstrap_attempted.remove(&oldest);
            }
        }
        taken
    }

    // --- serving (pure reads; safe from the synchronous handler) ----------

    /// The contiguous run of updates starting at `start_period`.
    ///
    /// `None` means miss — the caller answers `ResourceUnavailable` and schedules
    /// a background fill. A *partial* run is a legitimate answer: the spec allows
    /// responding with fewer updates than requested, and a wallet walks forward
    /// from what it gets.
    pub fn updates_range(&self, start_period: u64, count: u64) -> Option<Vec<u8>> {
        if count == 0 || count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
            return None;
        }
        let inner = self.read();

        // Refuse out-of-window rather than scanning for it.
        let (&lowest, _) = inner.updates.iter().next()?;
        let (&highest, _) = inner.updates.iter().next_back()?;
        if start_period < lowest || start_period > highest {
            return None;
        }

        let mut out = Vec::new();
        let mut served = 0u64;
        // Walked with a checked increment rather than `start..start+count`:
        // `saturating_add` would make the range EMPTY at `u64::MAX` instead of
        // one element long, silently turning a servable period into a miss.
        let mut period = start_period;
        for _ in 0..count {
            let Some(chunk) = inner.updates.get(&period) else {
                break; // contiguity ends; answer with what we have
            };
            if out.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                break;
            }
            out.extend_from_slice(chunk);
            served += 1;
            match period.checked_add(1) {
                Some(next) => period = next,
                None => break, // end of the number line, not an error
            }
        }
        if served == 0 {
            return None;
        }
        Some(out)
    }

    pub fn finality(&self) -> Option<Arc<[u8]>> {
        self.read().finality.clone()
    }

    pub fn optimistic(&self) -> Option<Arc<[u8]>> {
        self.read().optimistic.clone()
    }

    pub fn bootstrap(&self, block_root: &[u8; 32]) -> Option<Arc<[u8]>> {
        self.read().bootstraps.get(block_root).cloned()
    }

    /// The fork digest of the newest stored period — the last-resort fallback
    /// when upstream cannot supply one at startup.
    pub fn newest_fork_digest(&self) -> Option<[u8; 4]> {
        self.read().newest_fork_digest
    }

    pub fn has_period(&self, period: u64) -> bool {
        self.read().updates.contains_key(&period)
    }

    pub fn coverage(&self) -> Coverage {
        let inner = self.read();
        Coverage {
            lowest_period: inner.updates.keys().next().copied(),
            highest_period: inner.updates.keys().next_back().copied(),
            periods: inner.updates.len(),
            bootstraps: inner.bootstraps.len(),
            has_finality: inner.finality.is_some(),
            has_optimistic: inner.optimistic.is_some(),
            update_bytes: inner.updates.values().map(|v| v.len()).sum(),
        }
    }

    /// Periods missing from `[from, to]` — what a background filler works from.
    pub fn gaps(&self, from: u64, to: u64) -> Vec<u64> {
        let inner = self.read();
        (from..=to).filter(|p| !inner.updates.contains_key(p)).collect()
    }
}

/// The seam `myotis-net`'s swarm calls into.
///
/// Every method is a pure read of what ingestion already encoded — no I/O, no
/// allocation beyond the response copy, no await. That is a hard requirement,
/// not a style choice: this runs inline on the single swarm task, so anything
/// blocking here stalls every other connection's handshakes and responses.
impl myotis_net::reqresp::LcResponder for LcStore {
    fn bootstrap(&self, block_root: &[u8; 32]) -> Option<Vec<u8>> {
        match LcStore::bootstrap(self, block_root) {
            Some(b) => Some(b.to_vec()),
            None => {
                // Miss: queue it and answer ResourceUnavailable. The wallet
                // retries, and the retry hits. Still no I/O on this task.
                if self.record_bootstrap_miss(*block_root) {
                    tracing::info!(root = %hex::encode(&block_root[..8]),
                        "bootstrap miss queued for background fetch");
                }
                None
            }
        }
    }

    fn updates_by_range(&self, start_period: u64, count: u64) -> Option<Vec<u8>> {
        self.updates_range(start_period, count)
    }

    fn finality_update(&self) -> Option<Vec<u8>> {
        self.finality().map(|b| b.to_vec())
    }

    fn optimistic_update(&self) -> Option<Vec<u8>> {
        self.optimistic().map(|b| b.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_net::codec::decode_multi_chunk_response;

    const D: [u8; 4] = [0x74, 0xd0, 0x14, 0x59];

    fn store_with(periods: &[u64]) -> LcStore {
        let s = LcStore::new();
        for (i, p) in periods.iter().enumerate() {
            s.insert_update(*p, D, &[i as u8 + 1; 64]);
        }
        s
    }

    #[test]
    fn served_bytes_decode_as_a_multi_chunk_response() {
        // The property the whole store exists for: what a wallet reads off the
        // wire is what myotis' own decoder already handles.
        let s = store_with(&[1323, 1324, 1325]);
        let body = s.updates_range(1323, 3).unwrap();
        let decoded = decode_multi_chunk_response(&body, 3).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], vec![1u8; 64]);
        assert_eq!(decoded[2], vec![3u8; 64]);
    }

    #[test]
    fn miss_is_none_so_the_handler_can_answer_resource_unavailable() {
        let s = store_with(&[1323, 1324]);
        assert!(s.updates_range(1322, 1).is_none(), "below the window");
        assert!(s.updates_range(1400, 1).is_none(), "above the window");
        assert!(LcStore::new().updates_range(1323, 1).is_none(), "empty store");
    }

    #[test]
    fn a_hole_truncates_the_run_rather_than_failing_it() {
        let s = store_with(&[1323, 1324, 1327]);
        let body = s.updates_range(1323, 5).unwrap();
        // Stops at the hole: 1325 is missing, so 1327 is not served either.
        assert_eq!(decode_multi_chunk_response(&body, 5).unwrap().len(), 2);
    }

    #[test]
    fn refuses_an_unbounded_count() {
        let s = store_with(&[1323]);
        assert!(s.updates_range(1323, 0).is_none());
        assert!(s
            .updates_range(1323, MAX_REQUEST_LIGHT_CLIENT_UPDATES + 1)
            .is_none());
        assert!(s.updates_range(1323, MAX_REQUEST_LIGHT_CLIENT_UPDATES).is_some());
    }

    #[test]
    fn a_huge_start_period_cannot_overflow_the_range_walk() {
        let s = store_with(&[u64::MAX]);
        // start + count would overflow. The walk uses checked_add precisely
        // because `start..start.saturating_add(count)` would be EMPTY here
        // rather than one element long — see updates_range's own note.
        let body = s.updates_range(u64::MAX, 128).unwrap();
        assert_eq!(decode_multi_chunk_response(&body, 1).unwrap().len(), 1);
    }

    fn root_n(i: u64) -> [u8; 32] {
        let mut root = [0u8; 32];
        root[0..8].copy_from_slice(&i.to_le_bytes());
        root
    }

    #[test]
    fn bootstraps_evict_fifo_rather_than_refusing() {
        let s = LcStore::new();
        for i in 0..MAX_BOOTSTRAPS as u64 {
            assert_eq!(s.insert_bootstrap(root_n(i), D, &[1u8; 32]), None);
        }
        assert_eq!(s.coverage().bootstraps, MAX_BOOTSTRAPS);

        // One past the cap evicts the OLDEST, and — the point of the fix — the
        // new root is actually cached. Refusing here would mean that after
        // MAX_BOOTSTRAPS epochs the server stops caching the current finalized
        // root and serves no bootstrap any live wallet can use.
        assert_eq!(s.insert_bootstrap([0xff; 32], D, &[1u8; 32]), Some(root_n(0)));
        assert!(s.bootstrap(&[0xff; 32]).is_some(), "the new root must be cached");
        assert!(s.bootstrap(&root_n(0)).is_none(), "the oldest must be gone");
        assert_eq!(s.coverage().bootstraps, MAX_BOOTSTRAPS);
    }

    #[test]
    fn refreshing_a_cached_bootstrap_does_not_reorder_eviction() {
        let s = LcStore::new();
        for i in 0..MAX_BOOTSTRAPS as u64 {
            s.insert_bootstrap(root_n(i), D, &[1u8; 32]);
        }
        // Refresh the oldest: it must NOT move to the back, or a repeatedly
        // refreshed root would push everything else out.
        assert_eq!(s.insert_bootstrap(root_n(0), D, &[2u8; 32]), None);
        assert_eq!(s.insert_bootstrap([0xff; 32], D, &[1u8; 32]), Some(root_n(0)));
        assert_eq!(s.coverage().bootstraps, MAX_BOOTSTRAPS);
    }

    #[test]
    fn a_miss_is_queued_once_and_never_re_attempted() {
        let s = LcStore::new();
        let root = root_n(7);
        assert!(s.record_bootstrap_miss(root), "first miss queues");
        assert!(!s.record_bootstrap_miss(root), "already queued");
        assert_eq!(s.take_bootstrap_misses(10), vec![root]);
        assert!(
            !s.record_bootstrap_miss(root),
            "already attempted — a wallet that keeps asking must not keep costing us fetches"
        );
    }

    #[test]
    fn evicting_a_bootstrap_clears_its_attempted_marker() {
        // Otherwise a root can be simultaneously uncached and already-attempted,
        // and every request for it is refused with no re-fetch.
        let s = LcStore::new();
        let root = root_n(1);
        assert!(s.record_bootstrap_miss(root));
        assert_eq!(s.take_bootstrap_misses(1), vec![root]);
        s.insert_bootstrap(root, D, &[1u8; 32]);
        assert!(!s.record_bootstrap_miss(root), "cached, so nothing to fetch");

        // Push it out of the cache.
        for i in 100..(100 + MAX_BOOTSTRAPS as u64) {
            s.insert_bootstrap(root_n(i), D, &[1u8; 32]);
        }
        assert!(s.bootstrap(&root).is_none(), "evicted");
        assert!(
            s.record_bootstrap_miss(root),
            "an evicted root must become re-fetchable, not stay marked attempted"
        );
    }

    #[test]
    fn a_root_upstream_cannot_serve_stays_blocked() {
        // The other half: a root that never made it into the cache keeps its
        // marker, so a wallet retrying forever costs one upstream fetch.
        let s = LcStore::new();
        let root = root_n(42);
        assert!(s.record_bootstrap_miss(root));
        assert_eq!(s.take_bootstrap_misses(1), vec![root]);
        for i in 200..(200 + MAX_BOOTSTRAPS as u64) {
            s.insert_bootstrap(root_n(i), D, &[1u8; 32]);
        }
        assert!(!s.record_bootstrap_miss(root), "never cached, so still blocked");
    }

    #[test]
    fn clearing_bootstraps_makes_them_refetchable() {
        let s = LcStore::new();
        let root = root_n(3);
        assert!(s.record_bootstrap_miss(root));
        s.take_bootstrap_misses(1);
        s.insert_bootstrap(root, D, &[1u8; 32]);

        assert_eq!(s.clear_bootstraps(), 1);
        assert!(s.bootstrap(&root).is_none());
        assert!(
            s.record_bootstrap_miss(root),
            "a cleared root must be re-queued, or it is refused forever with no re-fetch"
        );
    }

    #[test]
    fn misses_drain_in_arrival_order_not_key_order() {
        // Otherwise a caller can starve a legitimate checkpoint forever by
        // enqueueing lexicographically smaller roots before each drain.
        let s = LcStore::new();
        let first = root_n(9_000);
        assert!(s.record_bootstrap_miss(first));
        assert!(s.record_bootstrap_miss(root_n(1))); // sorts lower, arrived later
        assert_eq!(s.take_bootstrap_misses(1), vec![first]);
    }

    #[test]
    fn a_transient_failure_can_be_requeued() {
        let s = LcStore::new();
        let root = root_n(5);
        assert!(s.record_bootstrap_miss(root));
        assert_eq!(s.take_bootstrap_misses(1), vec![root]);
        assert!(!s.record_bootstrap_miss(root), "marked attempted by the drain");

        s.requeue_bootstrap_miss(root);
        assert_eq!(
            s.take_bootstrap_misses(1),
            vec![root],
            "a transient upstream failure must not permanently poison a pinned checkpoint"
        );
    }

    #[test]
    fn the_miss_queue_is_bounded() {
        let s = LcStore::new();
        for i in 0..MAX_BOOTSTRAP_MISSES as u64 {
            assert!(s.record_bootstrap_miss(root_n(i)));
        }
        assert!(!s.record_bootstrap_miss(root_n(9999)), "queue cap must hold");
        assert_eq!(s.take_bootstrap_misses(usize::MAX).len(), MAX_BOOTSTRAP_MISSES);
    }

    #[test]
    fn single_objects_round_trip() {
        let s = LcStore::new();
        assert!(s.finality().is_none());
        assert!(s.optimistic().is_none());
        s.set_finality(D, &[5u8; 100]);
        s.set_optimistic(D, &[6u8; 50]);
        let f = s.finality().unwrap();
        assert_eq!(decode_multi_chunk_response(&f, 1).unwrap()[0], vec![5u8; 100]);
        let o = s.optimistic().unwrap();
        assert_eq!(decode_multi_chunk_response(&o, 1).unwrap()[0], vec![6u8; 50]);
    }

    #[test]
    fn coverage_and_gaps_describe_what_a_filler_must_do() {
        let s = store_with(&[1323, 1325, 1326]);
        let c = s.coverage();
        assert_eq!(c.lowest_period, Some(1323));
        assert_eq!(c.highest_period, Some(1326));
        assert_eq!(c.periods, 3);
        assert!(c.update_bytes > 0);
        assert_eq!(s.gaps(1323, 1327), vec![1324, 1327]);
    }
}
