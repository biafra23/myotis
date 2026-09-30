//! Per-head memo for the verified fee reads — `eth_gasPrice` /
//! `eth_maxPriorityFeePerGas` ([`FeeEstimate`]) and `eth_feeHistory`
//! ([`FeeHistory`]) — so a wallet's fee poll is answered from memory instead of
//! re-downloading and re-verifying blocks on the request path (#510).
//!
//! Soundness: every cached value is a pure function of the anchored window top
//! `(number, hash)` it was computed against (plus the request shape for a
//! history), so re-serving it while that top is unchanged is exactly the answer
//! a fresh compute would give. Past a head advance a value is only STALE: it is
//! re-served for at most [`STALE_MAX_BLOCKS`] blocks and [`STALE_MAX_AGE`] while
//! the reader's fee follower refreshes it off the request path — a fee from one
//! block ago is a far better wallet answer than a 15 s wait or a -32000. A
//! reorg (same number, other hash) or a head that moved backwards is a miss,
//! never stale.
//!
//! This module is pure state (no I/O, no clocks of its own — callers pass
//! `now`), so the freshness rules are unit-tested here; the reader owns the
//! locks, the single-flight computes and the follower task.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::el::reader::{FeeEstimate, FeeHistory};

/// A window top: `(block number, block hash)`.
pub(crate) type Head = (u64, [u8; 32]);

/// How many blocks behind the current head a cached fee may still be served.
pub(crate) const STALE_MAX_BLOCKS: u64 = 2;
/// How old (since it was computed) a cached fee may still be served stale.
pub(crate) const STALE_MAX_AGE: Duration = Duration::from_secs(30);
/// The follower keeps refreshing a fee read on every new head for this long
/// after the last request for it, then goes quiet (a wallet that stopped
/// polling costs nothing).
pub(crate) const FOLLOW_IDLE: Duration = Duration::from_secs(120);
/// After a failed compute for a head, the follower waits this long before
/// retrying the SAME head (a failing pool is not hammered once per tick).
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(3);
/// Per-block tip lists kept for the rolling estimate window: the estimate
/// samples 3 blocks, so this covers a few heads of slack for a lagging peer.
const TIPS_KEEP: usize = 8;
/// Distinct `eth_feeHistory` request shapes remembered (wallets use one or
/// two); the least recently requested is evicted past this.
const HISTORY_SHAPES_MAX: usize = 16;

/// What a lookup found for the current top.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Lookup<T> {
    /// Computed against exactly this top: the answer a fresh compute gives.
    Fresh(T),
    /// Computed against an older top within the stale bounds.
    Stale(T),
    Miss,
}

/// One cached value and the bookkeeping to refresh it.
#[derive(Debug)]
pub(crate) struct Slot<T> {
    cached: Option<(Head, T, Instant)>,
    /// The last FAILED compute: which top, and when.
    failed: Option<(Head, Instant)>,
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Slot { cached: None, failed: None }
    }
}

impl<T: Clone> Slot<T> {
    pub(crate) fn lookup(&self, head: Head, now: Instant, allow_stale: bool) -> Lookup<T> {
        let Some((at_head, value, at)) = &self.cached else {
            return Lookup::Miss;
        };
        if *at_head == head {
            return Lookup::Fresh(value.clone());
        }
        // Strictly older, and within both bounds. Same number with another
        // hash is a reorg; a HIGHER cached number means the head went
        // backwards — both are misses, never stale.
        let behind = head.0.checked_sub(at_head.0).filter(|&b| b > 0);
        if allow_stale
            && behind.is_some_and(|b| b <= STALE_MAX_BLOCKS)
            && now.saturating_duration_since(*at) <= STALE_MAX_AGE
        {
            return Lookup::Stale(value.clone());
        }
        Lookup::Miss
    }

    /// Store a value computed against `head` — unless a value for a NEWER top
    /// is already there and `head` is no longer the `current` one (a slow
    /// compute finishing late must not regress it). A head that really moved
    /// backwards (re-anchor, reorg to a shorter chain) IS current and replaces
    /// it; refusing it would leave the follower recomputing it every tick. Nor
    /// may a late compute for a reorged-away sibling displace the value for the
    /// top that IS current.
    pub(crate) fn store(&mut self, head: Head, value: T, now: Instant, current: Option<Head>) {
        if current != Some(head)
            && self
                .cached
                .as_ref()
                .is_some_and(|(h, _, _)| h.0 > head.0 || Some(*h) == current)
        {
            return;
        }
        self.cached = Some((head, value, now));
        self.failed = None;
    }

    pub(crate) fn record_failure(&mut self, head: Head, now: Instant) {
        self.failed = Some((head, now));
    }

    /// Whether the follower should compute for `head` now: nothing cached for
    /// it yet, and no failure for this same head within [`RETRY_AFTER`].
    pub(crate) fn wants_refresh(&self, head: Head, now: Instant) -> bool {
        if self.cached.as_ref().is_some_and(|(h, _, _)| *h == head) {
            return false;
        }
        !self
            .failed
            .is_some_and(|(h, at)| h == head && now.saturating_duration_since(at) < RETRY_AFTER)
    }
}

/// An `eth_feeHistory` request shape — everything but the anchored top the
/// result depends on. Percentiles are keyed by their bit patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct HistoryShape {
    pub block_count: u64,
    /// `None` = the latest tag (head-relative: followed and served stale).
    pub newest: Option<u64>,
    pub percentiles: Option<Vec<u64>>,
}

impl HistoryShape {
    pub(crate) fn new(block_count: u64, newest: Option<u64>, percentiles: Option<&[f64]>) -> Self {
        HistoryShape {
            block_count,
            newest,
            percentiles: percentiles.map(|p| p.iter().map(|f| f.to_bits()).collect()),
        }
    }

    pub(crate) fn percentiles(&self) -> Option<Vec<f64>> {
        self.percentiles.as_ref().map(|p| p.iter().map(|b| f64::from_bits(*b)).collect())
    }

    /// Only head-relative shapes are followed and may be served stale: an
    /// explicit block number asked for THAT block.
    pub(crate) fn follows_head(&self) -> bool {
        self.newest.is_none()
    }
}

struct HistoryEntry {
    slot: Slot<FeeHistory>,
    /// Single-flight for this shape's compute (held across the network build).
    lock: Arc<tokio::sync::Mutex<()>>,
    last_demand: Instant,
}

/// The reader's fee memo. Held under one brief-hold std mutex; never across
/// an await.
#[derive(Default)]
pub(crate) struct FeeCache {
    pub(crate) estimate: Slot<FeeEstimate>,
    estimate_demand: Option<Instant>,
    /// Per-block effective tips, verified against the block's
    /// `transactionsRoot`, keyed by `(number, hash)` — so a new head needs
    /// ONE new body for the rolling estimate window, not all of them.
    tips: VecDeque<(Head, Arc<Vec<u128>>)>,
    histories: HashMap<HistoryShape, HistoryEntry>,
}

impl FeeCache {
    pub(crate) fn note_estimate_demand(&mut self, now: Instant) {
        self.estimate_demand = Some(now);
    }

    pub(crate) fn estimate_followed(&self, now: Instant) -> bool {
        recent(self.estimate_demand, now)
    }

    pub(crate) fn tips(&self, head: Head) -> Option<Arc<Vec<u128>>> {
        self.tips.iter().find(|(h, _)| *h == head).map(|(_, t)| Arc::clone(t))
    }

    pub(crate) fn put_tips(&mut self, head: Head, tips: Arc<Vec<u128>>) {
        if self.tips.iter().any(|(h, _)| *h == head) {
            return;
        }
        self.tips.push_back((head, tips));
        while self.tips.len() > TIPS_KEEP {
            // Drop the LOWEST block number (a reorg can append out of order).
            let Some(lowest) = self
                .tips
                .iter()
                .enumerate()
                .min_by_key(|(_, (h, _))| h.0)
                .map(|(i, _)| i)
            else {
                break;
            };
            self.tips.remove(lowest);
        }
    }

    /// Look up a history for `shape` at `top`, noting the demand and handing
    /// back the shape's single-flight lock for a miss.
    pub(crate) fn history_lookup(
        &mut self,
        shape: &HistoryShape,
        top: Head,
        now: Instant,
    ) -> (Lookup<FeeHistory>, Arc<tokio::sync::Mutex<()>>) {
        if !self.histories.contains_key(shape) && self.histories.len() >= HISTORY_SHAPES_MAX {
            // Victim preference: a shape with no build in flight (evicting one
            // drops its result and splits its single-flight), then a pinned
            // shape over a followed `latest` one (whose demand only moves on
            // wallet polls), then the least recently requested.
            if let Some(victim) = self
                .histories
                .iter()
                .min_by_key(|(s, e)| (e.lock.try_lock().is_err(), s.follows_head(), e.last_demand))
                .map(|(k, _)| k.clone())
            {
                self.histories.remove(&victim);
            }
        }
        let entry = self.histories.entry(shape.clone()).or_insert_with(|| HistoryEntry {
            slot: Slot::default(),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            last_demand: now,
        });
        entry.last_demand = now;
        (entry.slot.lookup(top, now, shape.follows_head()), Arc::clone(&entry.lock))
    }

    /// A fresh-only re-check after winning the shape's lock (another caller
    /// may have finished the compute while this one waited).
    pub(crate) fn history_fresh(&self, shape: &HistoryShape, top: Head, now: Instant) -> Option<FeeHistory> {
        match self.histories.get(shape)?.slot.lookup(top, now, false) {
            Lookup::Fresh(h) => Some(h),
            _ => None,
        }
    }

    pub(crate) fn store_history(
        &mut self,
        shape: &HistoryShape,
        top: Head,
        value: FeeHistory,
        now: Instant,
        current: Option<Head>,
    ) {
        if let Some(e) = self.histories.get_mut(shape) {
            e.slot.store(top, value, now, current);
        }
    }

    pub(crate) fn record_history_failure(&mut self, shape: &HistoryShape, top: Head, now: Instant) {
        if let Some(e) = self.histories.get_mut(shape) {
            e.slot.record_failure(top, now);
        }
    }

    /// Head-relative shapes requested within [`FOLLOW_IDLE`], with their locks.
    pub(crate) fn followed_histories(&self, now: Instant) -> Vec<(HistoryShape, Arc<tokio::sync::Mutex<()>>)> {
        self.histories
            .iter()
            .filter(|(s, e)| s.follows_head() && recent(Some(e.last_demand), now))
            .map(|(s, e)| (s.clone(), Arc::clone(&e.lock)))
            .collect()
    }

    pub(crate) fn history_wants_refresh(&self, shape: &HistoryShape, top: Head, now: Instant) -> bool {
        self.histories.get(shape).is_some_and(|e| e.slot.wants_refresh(top, now))
    }

    /// Anything left for the follower to do?
    pub(crate) fn any_followed(&self, now: Instant) -> bool {
        self.estimate_followed(now)
            || self.histories.iter().any(|(s, e)| s.follows_head() && recent(Some(e.last_demand), now))
    }
}

fn recent(at: Option<Instant>, now: Instant) -> bool {
    at.is_some_and(|at| now.saturating_duration_since(at) < FOLLOW_IDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u64, tag: u8) -> Head {
        (n, [tag; 32])
    }

    fn est(tip: u128) -> FeeEstimate {
        FeeEstimate { max_priority_fee_wei: tip, gas_price_wei: tip + 1 }
    }

    fn tip_of(l: Lookup<FeeEstimate>) -> Option<(bool, u128)> {
        match l {
            Lookup::Fresh(e) => Some((true, e.max_priority_fee_wei)),
            Lookup::Stale(e) => Some((false, e.max_priority_fee_wei)),
            Lookup::Miss => None,
        }
    }

    #[test]
    fn fresh_for_the_same_head_for_as_long_as_it_stays_the_head() {
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(100, 1), est(7), t0, None);
        // Well past the stale age: the head did not move, so it is still exact.
        let later = t0 + Duration::from_secs(600);
        assert_eq!(tip_of(s.lookup(h(100, 1), later, true)), Some((true, 7)));
        assert_eq!(tip_of(s.lookup(h(100, 1), later, false)), Some((true, 7)));
    }

    #[test]
    fn stale_within_both_bounds_only() {
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(100, 1), est(7), t0, None);
        let t = t0 + Duration::from_secs(12);
        assert_eq!(tip_of(s.lookup(h(101, 2), t, true)), Some((false, 7)));
        assert_eq!(tip_of(s.lookup(h(102, 3), t, true)), Some((false, 7)));
        // Too many blocks behind.
        assert_eq!(tip_of(s.lookup(h(103, 4), t, true)), None);
        // Too old.
        assert_eq!(tip_of(s.lookup(h(101, 2), t0 + STALE_MAX_AGE + Duration::from_secs(1), true)), None);
        // Stale not allowed for this caller.
        assert_eq!(tip_of(s.lookup(h(101, 2), t, false)), None);
    }

    #[test]
    fn reorg_or_backwards_head_is_a_miss_never_stale() {
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(100, 1), est(7), t0, None);
        assert_eq!(tip_of(s.lookup(h(100, 9), t0, true)), None);
        assert_eq!(tip_of(s.lookup(h(99, 9), t0, true)), None);
    }

    #[test]
    fn a_late_older_compute_never_regresses_a_newer_value() {
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(101, 2), est(8), t0, None);
        s.store(h(100, 1), est(7), t0, None);
        assert_eq!(tip_of(s.lookup(h(101, 2), t0, false)), Some((true, 8)));
        // A reorg at the same height does replace it.
        s.store(h(101, 3), est(9), t0, None);
        assert_eq!(tip_of(s.lookup(h(101, 3), t0, false)), Some((true, 9)));
    }

    #[test]
    fn a_late_compute_for_a_reorged_sibling_never_displaces_the_current_top() {
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(100, 0xb), est(9), t0, Some(h(100, 0xb)));
        s.store(h(100, 0xa), est(7), t0, Some(h(100, 0xb)));
        assert_eq!(tip_of(s.lookup(h(100, 0xb), t0, false)), Some((true, 9)));
        assert!(!s.wants_refresh(h(100, 0xb), t0));
    }

    #[test]
    fn a_head_that_really_moved_backwards_is_stored_and_not_refreshed_again() {
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(101, 2), est(8), t0, None);
        // The anchored head is now 100: the value for it is current, so it lands.
        s.store(h(100, 9), est(7), t0, Some(h(100, 9)));
        assert_eq!(tip_of(s.lookup(h(100, 9), t0, false)), Some((true, 7)));
        assert!(!s.wants_refresh(h(100, 9), t0));
    }

    #[test]
    fn refresh_is_wanted_once_per_head_and_failures_back_off() {
        let t0 = Instant::now();
        let mut s: Slot<FeeEstimate> = Slot::default();
        assert!(s.wants_refresh(h(100, 1), t0));
        s.record_failure(h(100, 1), t0);
        assert!(!s.wants_refresh(h(100, 1), t0 + Duration::from_secs(1)));
        assert!(s.wants_refresh(h(100, 1), t0 + RETRY_AFTER));
        // A new head is tried at once, whatever the last head's failure.
        assert!(s.wants_refresh(h(101, 2), t0 + Duration::from_secs(1)));
        s.store(h(101, 2), est(7), t0, None);
        assert!(!s.wants_refresh(h(101, 2), t0 + Duration::from_secs(60)));
        assert!(s.wants_refresh(h(102, 3), t0));
    }

    #[test]
    fn tips_window_keeps_the_newest_blocks() {
        let mut c = FeeCache::default();
        for n in 0..(TIPS_KEEP as u64 + 3) {
            c.put_tips(h(n, n as u8), Arc::new(vec![n as u128]));
        }
        assert!(c.tips(h(0, 0)).is_none());
        assert!(c.tips(h(2, 2)).is_none());
        let top = TIPS_KEEP as u64 + 2;
        assert_eq!(c.tips(h(top, top as u8)).as_deref(), Some(&vec![top as u128]));
        // Keyed by hash too: a reorged block is not served another's tips.
        assert!(c.tips(h(top, 0xee)).is_none());
    }

    fn hist(oldest: u64) -> FeeHistory {
        FeeHistory { oldest_block: oldest, base_fee_per_gas: vec![1, 2], gas_used_ratio: vec![0.5], reward: None }
    }

    #[test]
    fn history_stale_only_for_head_relative_shapes() {
        let t0 = Instant::now();
        let mut c = FeeCache::default();
        let latest = HistoryShape::new(5, None, Some(&[25.0, 75.0]));
        let pinned = HistoryShape::new(5, Some(100), Some(&[25.0, 75.0]));
        for shape in [&latest, &pinned] {
            let (l, _) = c.history_lookup(shape, h(100, 1), t0);
            assert!(matches!(l, Lookup::Miss));
            c.store_history(shape, h(100, 1), hist(96), t0, None);
        }
        let t = t0 + Duration::from_secs(12);
        assert!(matches!(c.history_lookup(&latest, h(100, 1), t).0, Lookup::Fresh(_)));
        assert!(matches!(c.history_lookup(&latest, h(101, 2), t).0, Lookup::Stale(_)));
        assert!(matches!(c.history_lookup(&pinned, h(101, 2), t).0, Lookup::Miss));
        assert!(c.history_fresh(&latest, h(101, 2), t).is_none());
        // Other percentiles are another shape.
        let other = HistoryShape::new(5, None, Some(&[50.0]));
        assert!(matches!(c.history_lookup(&other, h(101, 2), t).0, Lookup::Miss));
        // Only head-relative shapes are followed.
        let followed: Vec<_> = c.followed_histories(t).into_iter().map(|(s, _)| s).collect();
        assert!(followed.contains(&latest) && followed.contains(&other) && !followed.contains(&pinned));
        assert!(c.followed_histories(t + FOLLOW_IDLE).is_empty());
    }

    #[test]
    fn history_shapes_are_bounded() {
        let t0 = Instant::now();
        let mut c = FeeCache::default();
        for i in 0..(HISTORY_SHAPES_MAX as u64 + 4) {
            let _ = c.history_lookup(&HistoryShape::new(i + 1, None, None), h(1, 1), t0 + Duration::from_millis(i));
        }
        assert_eq!(c.histories.len(), HISTORY_SHAPES_MAX);
        // The least recently requested went first.
        assert!(!c.histories.contains_key(&HistoryShape::new(1, None, None)));
    }

    #[test]
    fn eviction_spares_the_followed_shape_and_builds_in_flight() {
        let t0 = Instant::now();
        let mut c = FeeCache::default();
        let latest = HistoryShape::new(5, None, None);
        let _ = c.history_lookup(&latest, h(1, 1), t0);
        // The oldest pinned shape has a build in flight.
        let busy = HistoryShape::new(5, Some(1), None);
        let (_, busy_lock) = c.history_lookup(&busy, h(1, 1), t0 + Duration::from_millis(1));
        let _guard = busy_lock.try_lock().expect("uncontended");
        for i in 0..(HISTORY_SHAPES_MAX as u64 + 4) {
            let later = t0 + Duration::from_millis(10 + i);
            let _ = c.history_lookup(&HistoryShape::new(5, Some(100 + i), None), h(1, 1), later);
        }
        assert_eq!(c.histories.len(), HISTORY_SHAPES_MAX);
        assert!(c.histories.contains_key(&latest));
        assert!(c.histories.contains_key(&busy));
    }

    #[test]
    fn follower_goes_quiet_without_demand() {
        let t0 = Instant::now();
        let mut c = FeeCache::default();
        assert!(!c.any_followed(t0));
        c.note_estimate_demand(t0);
        assert!(c.any_followed(t0 + Duration::from_secs(60)));
        assert!(!c.any_followed(t0 + FOLLOW_IDLE));
    }
}
