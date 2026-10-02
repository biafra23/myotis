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
//! the reader's fee follower refreshes it off the request path, and keeps
//! retrying a refresh that fails or runs long. The base fee moves at most 12.5%
//! per block, so a fee a few blocks old is a far better wallet answer than a
//! timeout or a -32000 (#532). A reorg (same number, other hash) or a head that
//! moved backwards is a miss, never stale.
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

/// One block's `(effective tip, gas used)` per transaction, in transaction
/// order: the `eth_feeHistory` reward rows' input.
pub(crate) type BlockRewards = Arc<Vec<(u128, u64)>>;

/// How many blocks behind the current head a cached fee may still be served.
/// Wide enough to ride out a refresh that fails or runs long (a slow peer, a
/// 15 s request timeout, the [`RETRY_AFTER`] back-off): with two blocks a
/// polling wallet fell through to a request-path compute and waited on the
/// peer ladder, 10–90 s (#532).
pub(crate) const STALE_MAX_BLOCKS: u64 = 5;
/// How old (since it was computed) a cached fee may still be served stale.
pub(crate) const STALE_MAX_AGE: Duration = Duration::from_secs(75);
/// The follower keeps refreshing a fee read on every new head for this long
/// after the last request for it, then goes quiet (a wallet that stopped
/// polling costs nothing).
pub(crate) const FOLLOW_IDLE: Duration = Duration::from_secs(120);
/// After a failed compute for a head, the follower waits this long before
/// retrying the SAME head (a failing pool is not hammered once per tick).
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(3);
/// Per-block fee facts kept for the rolling windows: the `eth_feeHistory`
/// reward rows read up to 10 blocks (`FEE_HISTORY_MAX_BLOCKS`) and may be
/// refreshed up to [`STALE_MAX_BLOCKS`] behind, so this covers a refresh after
/// a full stale window with a block of slack (#532).
const BLOCKS_KEEP: usize = 16;
/// How often the reader logs the [`FeeStats`] summary while fee reads flow.
pub(crate) const SUMMARY_EVERY: Duration = Duration::from_secs(300);
/// Distinct `eth_feeHistory` request shapes remembered (wallets use one or
/// two); the least recently requested is evicted past this.
const HISTORY_SHAPES_MAX: usize = 16;

/// What a lookup found for the current top.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Lookup<T> {
    /// Computed against exactly this top: the answer a fresh compute gives.
    Fresh(T),
    /// Computed against an older top within the stale bounds, this long ago.
    Stale(T, Duration),
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
        let age = now.saturating_duration_since(*at);
        if allow_stale && behind.is_some_and(|b| b <= STALE_MAX_BLOCKS) && age <= STALE_MAX_AGE {
            return Lookup::Stale(value.clone(), age);
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

/// One block's fee facts, verified against its anchored header and keyed by
/// `(number, hash)`: shared by the estimate and every `eth_feeHistory` shape,
/// so a new head costs one body (and, for reward rows, one receipts) fetch
/// whatever the request shapes (#510, #532).
#[derive(Debug, Clone)]
struct BlockFees {
    /// The transactions' effective tips — the estimate's sample (the body).
    tips: Arc<Vec<u128>>,
    /// Each tip with the gas its transaction used, in transaction order — the
    /// reward rows' input (the body and the receipts). Its tips are `tips`.
    weighted: Option<BlockRewards>,
}

/// The reader's fee memo. Held under one brief-hold std mutex; never across
/// an await.
#[derive(Default)]
pub(crate) struct FeeCache {
    pub(crate) estimate: Slot<FeeEstimate>,
    estimate_demand: Option<Instant>,
    /// Per-block fee facts for the newest [`BLOCKS_KEEP`] blocks seen.
    blocks: VecDeque<(Head, BlockFees)>,
    histories: HashMap<HistoryShape, HistoryEntry>,
    /// What the fee reads served, for the periodic summary.
    pub(crate) stats: FeeStats,
}

impl FeeCache {
    pub(crate) fn note_estimate_demand(&mut self, now: Instant) {
        self.estimate_demand = Some(now);
    }

    pub(crate) fn estimate_followed(&self, now: Instant) -> bool {
        recent(self.estimate_demand, now)
    }

    fn block(&self, head: Head) -> Option<&BlockFees> {
        self.blocks.iter().find(|(h, _)| *h == head).map(|(_, b)| b)
    }

    /// The block's effective tips, from either kind of fetch.
    pub(crate) fn tips(&self, head: Head) -> Option<Arc<Vec<u128>>> {
        self.block(head).map(|b| Arc::clone(&b.tips))
    }

    /// The block's `(tip, gas used)` list, once its receipts were fetched.
    pub(crate) fn weighted(&self, head: Head) -> Option<BlockRewards> {
        self.block(head).and_then(|b| b.weighted.clone())
    }

    /// Remember a block's tips from its verified body. A block already known
    /// keeps what it has.
    pub(crate) fn put_tips(&mut self, head: Head, tips: Arc<Vec<u128>>) {
        if self.block(head).is_none() {
            self.push_block(head, BlockFees { tips, weighted: None });
        }
    }

    /// Remember a block's `(tip, gas used)` list from its verified body and
    /// receipts. Its tips serve the estimate too, so a block both kinds of
    /// read want is fetched once.
    pub(crate) fn put_weighted(&mut self, head: Head, weighted: BlockRewards) {
        if let Some((_, b)) = self.blocks.iter_mut().find(|(h, _)| *h == head) {
            b.weighted = Some(weighted);
            return;
        }
        let tips = Arc::new(weighted.iter().map(|&(tip, _)| tip).collect());
        self.push_block(head, BlockFees { tips, weighted: Some(weighted) });
    }

    fn push_block(&mut self, head: Head, fees: BlockFees) {
        self.blocks.push_back((head, fees));
        while self.blocks.len() > BLOCKS_KEEP {
            // Drop the LOWEST block number (a reorg can append out of order).
            let Some(lowest) = self
                .blocks
                .iter()
                .enumerate()
                .min_by_key(|(_, (h, _))| h.0)
                .map(|(i, _)| i)
            else {
                break;
            };
            self.blocks.remove(lowest);
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

/// How one kind of fee read was served (#532).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServeCounts {
    /// Exact for the current top.
    pub fresh: u64,
    /// A previous top's value, within the stale bounds.
    pub stale: u64,
    /// The oldest stale value served.
    pub stale_oldest: Duration,
    /// Nothing usable: answered by a compute within the wait bound.
    pub miss_served: u64,
    /// Nothing usable, and no answer within the bound: a retryable error.
    pub miss_failed: u64,
}

impl ServeCounts {
    /// Count a served lookup (a miss is counted when the wait settles).
    pub(crate) fn served<T>(&mut self, lookup: &Lookup<T>) {
        match lookup {
            Lookup::Fresh(_) => self.fresh += 1,
            Lookup::Stale(_, age) => {
                self.stale += 1;
                self.stale_oldest = self.stale_oldest.max(*age);
            }
            Lookup::Miss => {}
        }
    }

    /// Count a miss once its bounded wait settled: answered, or not.
    pub(crate) fn missed(&mut self, served: bool) {
        if served {
            self.miss_served += 1;
        } else {
            self.miss_failed += 1;
        }
    }

    fn any(&self) -> bool {
        self.fresh + self.stale + self.miss_served + self.miss_failed > 0
    }
}

/// What the fee reads served and how the follower's refreshes went, since the
/// last summary (#532: the tail could not be attributed without it).
#[derive(Debug, Default)]
pub(crate) struct FeeStats {
    pub estimate: ServeCounts,
    pub history: ServeCounts,
    pub refreshes_ok: u64,
    pub refreshes_failed: u64,
    pub refresh_slowest: Duration,
    /// When this window began (the first event after the last summary).
    since: Option<Instant>,
}

impl FeeStats {
    /// Note that something was counted at `now` (opens a window).
    pub(crate) fn touch(&mut self, now: Instant) {
        self.since.get_or_insert(now);
    }

    pub(crate) fn refreshed(&mut self, ok: bool, took: Duration) {
        if ok {
            self.refreshes_ok += 1;
        } else {
            self.refreshes_failed += 1;
        }
        self.refresh_slowest = self.refresh_slowest.max(took);
    }

    /// The summary line once [`SUMMARY_EVERY`] has passed since the window
    /// opened, resetting the counts; `None` before that or with nothing
    /// counted.
    pub(crate) fn take_summary(&mut self, now: Instant) -> Option<String> {
        let since = self.since?;
        let span = now.saturating_duration_since(since);
        if span < SUMMARY_EVERY {
            return None;
        }
        let active = self.estimate.any() || self.history.any() || self.refreshes_ok + self.refreshes_failed > 0;
        let line = active.then(|| {
            let kind = |name: &str, c: &ServeCounts| {
                format!(
                    "{name} fresh={} stale={} (oldest {}s) miss served={} failed={}",
                    c.fresh,
                    c.stale,
                    c.stale_oldest.as_secs(),
                    c.miss_served,
                    c.miss_failed
                )
            };
            format!(
                "[fee-reads] last {}s: {} | {} | refreshes ok={} failed={} slowest={}ms",
                span.as_secs(),
                kind("gasPrice", &self.estimate),
                kind("feeHistory", &self.history),
                self.refreshes_ok,
                self.refreshes_failed,
                self.refresh_slowest.as_millis()
            )
        });
        *self = FeeStats::default();
        line
    }
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
            Lookup::Stale(e, _) => Some((false, e.max_priority_fee_wei)),
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
        assert_eq!(tip_of(s.lookup(h(100 + STALE_MAX_BLOCKS, 3), t, true)), Some((false, 7)));
        // Too many blocks behind.
        assert_eq!(tip_of(s.lookup(h(101 + STALE_MAX_BLOCKS, 4), t, true)), None);
        // Too old.
        assert_eq!(tip_of(s.lookup(h(101, 2), t0 + STALE_MAX_AGE + Duration::from_secs(1), true)), None);
        // Stale not allowed for this caller.
        assert_eq!(tip_of(s.lookup(h(101, 2), t, false)), None);
    }

    #[test]
    fn stale_rides_out_a_slow_refresh_and_reports_its_age() {
        // #532: a refresh that failed or ran long let a 2-block, 30 s value
        // expire under a polling wallet, which then waited on the peer ladder.
        let t0 = Instant::now();
        let mut s = Slot::default();
        s.store(h(100, 1), est(7), t0, None);
        let t = t0 + Duration::from_secs(41);
        assert_eq!(s.lookup(h(104, 4), t, true), Lookup::Stale(est(7), Duration::from_secs(41)));
        assert_eq!(STALE_MAX_BLOCKS, 5);
        assert_eq!(STALE_MAX_AGE, Duration::from_secs(75));
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
        for n in 0..(BLOCKS_KEEP as u64 + 3) {
            c.put_tips(h(n, n as u8), Arc::new(vec![n as u128]));
        }
        assert!(c.tips(h(0, 0)).is_none());
        assert!(c.tips(h(2, 2)).is_none());
        let top = BLOCKS_KEEP as u64 + 2;
        assert_eq!(c.tips(h(top, top as u8)).as_deref(), Some(&vec![top as u128]));
        // Keyed by hash too: a reorged block is not served another's tips.
        assert!(c.tips(h(top, 0xee)).is_none());
    }

    #[test]
    fn a_block_fetched_with_its_receipts_serves_the_estimate_too() {
        // #532: one body + receipts fetch per new head serves every read.
        let mut c = FeeCache::default();
        c.put_weighted(h(5, 5), Arc::new(vec![(10, 21_000), (20, 50_000)]));
        assert_eq!(c.tips(h(5, 5)).as_deref(), Some(&vec![10, 20]));
        assert_eq!(c.weighted(h(5, 5)).as_deref(), Some(&vec![(10, 21_000), (20, 50_000)]));
        // A body-only block serves the estimate, not the reward rows…
        c.put_tips(h(6, 6), Arc::new(vec![7]));
        assert!(c.weighted(h(6, 6)).is_none());
        // …until its receipts are fetched; its tips stay as they were.
        c.put_weighted(h(6, 6), Arc::new(vec![(7, 21_000)]));
        assert_eq!(c.weighted(h(6, 6)).as_deref(), Some(&vec![(7, 21_000)]));
        assert_eq!(c.tips(h(6, 6)).as_deref(), Some(&vec![7]));
        // A known block keeps its facts.
        c.put_tips(h(5, 5), Arc::new(vec![99]));
        assert_eq!(c.tips(h(5, 5)).as_deref(), Some(&vec![10, 20]));
        // The window covers a feeHistory's 10 blocks across a full stale window.
        assert!(BLOCKS_KEEP as u64 > 10 + STALE_MAX_BLOCKS);
    }

    #[test]
    fn fee_stats_summarize_a_window_then_reset() {
        let t0 = Instant::now();
        let mut st = FeeStats::default();
        // Nothing counted: no line, however long.
        assert!(st.take_summary(t0 + SUMMARY_EVERY * 2).is_none());
        st.touch(t0);
        st.estimate.served(&Lookup::Fresh(est(1)));
        st.estimate.served(&Lookup::Fresh(est(1)));
        st.estimate.served(&Lookup::Stale(est(1), Duration::from_secs(41)));
        st.estimate.served(&Lookup::Stale(est(1), Duration::from_secs(9)));
        st.estimate.missed(true);
        st.history.missed(false);
        st.refreshed(true, Duration::from_millis(800));
        st.refreshed(false, Duration::from_millis(2_500));
        assert!(st.take_summary(t0 + Duration::from_secs(10)).is_none(), "not before the window ends");
        let line = st.take_summary(t0 + SUMMARY_EVERY).expect("a line once the window ends");
        assert!(line.contains("gasPrice fresh=2 stale=2 (oldest 41s) miss served=1 failed=0"), "{line}");
        assert!(line.contains("feeHistory fresh=0 stale=0 (oldest 0s) miss served=0 failed=1"), "{line}");
        assert!(line.contains("refreshes ok=1 failed=1 slowest=2500ms"), "{line}");
        // Reset: the next window starts empty.
        assert!(st.take_summary(t0 + SUMMARY_EVERY * 3).is_none());
        assert_eq!(st.estimate, ServeCounts::default());
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
        assert!(matches!(c.history_lookup(&latest, h(101, 2), t).0, Lookup::Stale(..)));
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
