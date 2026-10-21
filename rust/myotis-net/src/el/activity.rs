//! Address activity (#691): which watched addresses each verified block
//! touched, so a host re-proves an address's state only when a block touched
//! it, instead of at every new head.
//!
//! The follower (`ElReader::ensure_activity_follower`) keeps the last
//! [`WINDOW`] verified headers as one contiguous, parent-linked run ending at
//! the anchored head. This module is its state and the report built from it,
//! pure and unit-tested; the reader owns the I/O.
//!
//! Two kinds of coverage, reported separately:
//!
//! - **`log`**: the header's `logsBloom`, probed for each watched address both
//!   as a log's emitter (20 bytes) and as an indexed topic (the address
//!   left-padded to 32 bytes, as `Transfer(from, to, …)` carries it). A miss is
//!   definitive; a hit only says the block MAY have touched the address.
//! - **`account`**: the account itself (balance, nonce, code), which needs the
//!   block access list (EIP-7928). Not followed yet: every block is an account
//!   gap.
//!
//! Coverage honesty is the contract: every block of a report's range is either
//! covered or listed in its gaps, per kind. A block the follower did not see —
//! before it started, past its window, skipped by a head jump or a failed
//! fetch — is a gap, never a silence.

use std::collections::{BTreeMap, BTreeSet};

use myotis_core::bloom::{may_contain, LogsBloom};

/// Blocks of activity kept below the anchored head: ~51 min on Sepolia and
/// mainnet (12 s slots), ~21 min on Gnosis (5 s). A host back within that
/// learns what it missed without re-proving; further back is a gap.
pub const WINDOW: u64 = 256;

/// Upper bound on the watch list. Every watched address costs two bloom probes
/// per block, and the report lists every bloom hit, so an unbounded list
/// would make a no-I/O poll arbitrarily large. A push past it is refused.
pub const MAX_WATCHED: usize = 1024;

/// One verified block, as the follower keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub bloom: Box<LogsBloom>,
}

/// One touch in a report: `address` may have been touched by block `number`
/// (`hash`), seen through `via`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Touch {
    pub address: [u8; 20],
    pub block: u64,
    pub block_hash: [u8; 32],
    pub via: Via,
}

/// What a touch was seen through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The header's logs bloom matched.
    Log,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Log => "log",
        }
    }
}

/// The answer to "what touched the watched addresses after block `after`".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityReport {
    /// First block of the range (`after + 1`).
    pub from: u64,
    /// Last block of the range: the anchored head. `from > to` is an empty range.
    pub to: u64,
    /// The block `after` itself, with its hash when the follower holds it: a
    /// host whose proof anchors there can check it is still canonical.
    pub base: (u64, Option<[u8; 32]>),
    /// Inclusive ranges of `[from, to]` with no account coverage.
    pub account_gaps: Vec<(u64, u64)>,
    /// Inclusive ranges of `[from, to]` with no log coverage.
    pub log_gaps: Vec<(u64, u64)>,
    /// Ascending by block, then address.
    pub touched: Vec<Touch>,
    /// The watch list the report was made against, ascending.
    pub watching: Vec<[u8; 20]>,
}

/// The watch list and the follower's run of verified blocks.
#[derive(Debug, Default)]
pub struct ActivityState {
    watched: BTreeSet<[u8; 20]>,
    /// Contiguous by number and parent-linked: `records[n].parent_hash ==
    /// records[n - 1].hash` for every kept pair.
    records: BTreeMap<u64, BlockRecord>,
}

impl ActivityState {
    /// Apply a push: drop `unwatch`, then add `watch`. Additive like the log
    /// index's config: an address left out of `watch` stays watched.
    /// Refused as a whole, changing nothing, when the result would exceed
    /// [`MAX_WATCHED`].
    ///
    /// The records are blooms, not per-address results, so an address added
    /// here is covered over every block already kept.
    pub fn apply(&mut self, watch: &[[u8; 20]], unwatch: &[[u8; 20]]) -> Result<(), String> {
        let mut next = self.watched.clone();
        for a in unwatch {
            next.remove(a);
        }
        next.extend(watch.iter().copied());
        if next.len() > MAX_WATCHED {
            return Err(format!("watch list would hold {} addresses, more than {MAX_WATCHED}", next.len()));
        }
        self.watched = next;
        if self.watched.is_empty() {
            // Nothing to follow: what is kept would go stale while nobody
            // follows, and a later list must not read it as coverage.
            self.records.clear();
        }
        Ok(())
    }

    /// Whether the follower should run.
    pub fn is_active(&self) -> bool {
        !self.watched.is_empty()
    }

    /// The highest kept block, `(number, hash)`.
    pub fn top(&self) -> Option<(u64, [u8; 32])> {
        self.records.values().next_back().map(|r| (r.number, r.hash))
    }

    /// Install a verified, ascending, parent-linked run of blocks ending at
    /// `head`. A run that links to a kept block replaces everything above
    /// that block (a reorg above it, or simply new blocks); one that does not
    /// starts over, since the kept blocks can no longer be linked to the
    /// head. Then trims to [`WINDOW`] blocks ending at `head`.
    ///
    /// `segment` must be non-empty, ascending and parent-linked, ending at the
    /// anchored head: the reader's header-window gate establishes that, and a
    /// segment that breaks it here is dropped whole rather than kept in part.
    pub fn install(&mut self, segment: Vec<BlockRecord>, head: u64) {
        let Some(first) = segment.first() else { return };
        let linked_run = segment
            .windows(2)
            .all(|w| w[1].number == w[0].number.wrapping_add(1) && w[1].parent_hash == w[0].hash);
        if !linked_run || segment.last().map(|r| r.number) != Some(head) {
            return;
        }
        let links_below = first
            .number
            .checked_sub(1)
            .and_then(|below| self.records.get(&below))
            .is_some_and(|r| r.hash == first.parent_hash);
        if links_below {
            let _ = self.records.split_off(&first.number);
        } else {
            self.records.clear();
        }
        for r in segment {
            self.records.insert(r.number, r);
        }
        let floor = head.saturating_sub(WINDOW - 1);
        self.records = self.records.split_off(&floor);
    }

    /// Forget every kept block (the follower stopped following).
    pub fn clear_records(&mut self) {
        self.records.clear();
    }

    /// The activity of the watched addresses in `(after, head]`. No I/O.
    pub fn report(&self, after: u64, head: u64) -> ActivityReport {
        let from = after.saturating_add(1);
        let to = head;
        let base = (after, self.records.get(&after).map(|r| r.hash));
        let watching: Vec<[u8; 20]> = self.watched.iter().copied().collect();
        if from > to {
            return ActivityReport {
                from,
                to,
                base,
                account_gaps: Vec::new(),
                log_gaps: Vec::new(),
                touched: Vec::new(),
                watching,
            };
        }
        // Kept blocks above the head (it moved back) are not in the range.
        let kept: Vec<&BlockRecord> = self.records.range(from..=to).map(|(_, r)| r).collect();
        let log_gaps = match (kept.first(), kept.last()) {
            (Some(lo), Some(hi)) => {
                let mut gaps = Vec::new();
                if lo.number > from {
                    gaps.push((from, lo.number - 1));
                }
                if hi.number < to {
                    gaps.push((hi.number + 1, to));
                }
                gaps
            }
            _ => vec![(from, to)],
        };
        let mut touched = Vec::new();
        for r in &kept {
            for address in &self.watched {
                if bloom_may_touch(&r.bloom, address) {
                    touched.push(Touch { address: *address, block: r.number, block_hash: r.hash, via: Via::Log });
                }
            }
        }
        ActivityReport {
            from,
            to,
            base,
            account_gaps: vec![(from, to)],
            log_gaps,
            touched,
            watching,
        }
    }
}

/// Could a log in a block with this bloom name `address`, as its emitter or as
/// an indexed topic? `false` is definitive.
pub fn bloom_may_touch(bloom: &LogsBloom, address: &[u8; 20]) -> bool {
    let mut topic = [0u8; 32];
    topic[12..].copy_from_slice(address);
    may_contain(bloom, address) || may_contain(bloom, &topic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::bloom::{accrue, EMPTY_BLOOM};

    fn hash(n: u64, fork: u8) -> [u8; 32] {
        let mut h = [fork; 32];
        h[..8].copy_from_slice(&n.to_be_bytes());
        h
    }

    /// A linked run `lo..=hi` on fork `fork`, whose block `lo` links to `parent`.
    fn run(lo: u64, hi: u64, fork: u8, parent: [u8; 32]) -> Vec<BlockRecord> {
        let mut out = Vec::new();
        let mut parent_hash = parent;
        for n in lo..=hi {
            let h = hash(n, fork);
            out.push(BlockRecord { number: n, hash: h, parent_hash, bloom: Box::new(EMPTY_BLOOM) });
            parent_hash = h;
        }
        out
    }

    const A: [u8; 20] = [0xaa; 20];
    const B: [u8; 20] = [0xbb; 20];

    fn watching(addresses: &[[u8; 20]]) -> ActivityState {
        let mut s = ActivityState::default();
        s.apply(addresses, &[]).unwrap();
        s
    }

    #[test]
    fn bloom_matches_an_address_as_emitter_or_as_topic() {
        let mut as_emitter = EMPTY_BLOOM;
        accrue(&mut as_emitter, &A);
        assert!(bloom_may_touch(&as_emitter, &A));

        let mut as_topic = EMPTY_BLOOM;
        let mut topic = [0u8; 32];
        topic[12..].copy_from_slice(&A);
        accrue(&mut as_topic, &topic);
        assert!(bloom_may_touch(&as_topic, &A));

        assert!(!bloom_may_touch(&EMPTY_BLOOM, &A));
    }

    #[test]
    fn nothing_followed_is_one_gap_of_each_kind() {
        let r = watching(&[A]).report(99, 110);
        assert_eq!((r.from, r.to), (100, 110));
        assert_eq!(r.log_gaps, vec![(100, 110)]);
        assert_eq!(r.account_gaps, vec![(100, 110)]);
        assert!(r.touched.is_empty());
        assert_eq!(r.base, (99, None));
    }

    #[test]
    fn covered_blocks_leave_gaps_only_outside_the_run() {
        let mut s = watching(&[A]);
        s.install(run(105, 110, 0, hash(104, 0)), 110);
        let r = s.report(99, 110);
        assert_eq!(r.log_gaps, vec![(100, 104)]);
        // Account activity is not followed: the whole range stays a gap.
        assert_eq!(r.account_gaps, vec![(100, 110)]);
        assert_eq!(r.base, (99, None));
        assert_eq!(s.report(106, 110).base, (106, Some(hash(106, 0))));
        // A head past the run is a gap at the top.
        assert_eq!(s.report(104, 112).log_gaps, vec![(111, 112)]);
    }

    #[test]
    fn a_bloom_hit_is_a_touch_of_that_address_only() {
        let mut s = watching(&[A, B]);
        let mut seg = run(100, 102, 0, hash(99, 0));
        accrue(&mut seg[1].bloom, &B);
        s.install(seg, 102);
        let r = s.report(99, 102);
        assert_eq!(
            r.touched,
            vec![Touch { address: B, block: 101, block_hash: hash(101, 0), via: Via::Log }]
        );
        assert!(r.log_gaps.is_empty());
        assert_eq!(r.watching, vec![A, B]);
    }

    #[test]
    fn an_address_added_later_is_covered_over_blocks_already_kept() {
        let mut s = watching(&[A]);
        let mut seg = run(100, 101, 0, hash(99, 0));
        accrue(&mut seg[0].bloom, &B);
        s.install(seg, 101);
        s.apply(&[B], &[]).unwrap();
        let r = s.report(99, 101);
        assert!(r.log_gaps.is_empty());
        assert_eq!(r.touched.len(), 1);
        assert_eq!(r.touched[0].address, B);
    }

    #[test]
    fn new_blocks_that_link_extend_the_run() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        s.install(run(106, 107, 0, hash(105, 0)), 107);
        assert_eq!(s.top(), Some((107, hash(107, 0))));
        assert!(s.report(99, 107).log_gaps.is_empty());
    }

    #[test]
    fn a_reorg_above_a_kept_block_replaces_only_what_is_above_it() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        // Fork 1 branches off after block 102 and is now the canonical head.
        s.install(run(103, 106, 1, hash(102, 0)), 106);
        let r = s.report(99, 106);
        assert!(r.log_gaps.is_empty());
        assert_eq!(s.report(102, 106).base.1, Some(hash(102, 0)));
        assert_eq!(s.report(104, 106).base.1, Some(hash(104, 1)));
        assert_eq!(s.top(), Some((106, hash(106, 1))));
    }

    #[test]
    fn a_run_that_links_to_nothing_kept_starts_over() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        // A head jump: the new run's parent is not a kept block.
        s.install(run(400, 402, 0, hash(399, 0)), 402);
        assert_eq!(s.report(99, 402).log_gaps, vec![(100, 399)]);
        // A run whose parent at a kept height is on another fork starts over too.
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        s.install(run(104, 106, 1, hash(103, 1)), 106);
        assert_eq!(s.report(99, 106).log_gaps, vec![(100, 103)]);
    }

    #[test]
    fn the_run_is_trimmed_to_the_window_below_the_head() {
        let mut s = watching(&[A]);
        s.install(run(1, 300, 0, hash(0, 0)), 300);
        let lowest = 300 - WINDOW + 1;
        assert_eq!(s.report(0, 300).log_gaps, vec![(1, lowest - 1)]);
    }

    #[test]
    fn a_broken_or_misplaced_segment_changes_nothing() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        let mut broken = run(106, 108, 0, hash(105, 0));
        broken[2].parent_hash = [0xee; 32];
        s.install(broken, 108);
        // Not ending at the head it claims.
        s.install(run(106, 107, 0, hash(105, 0)), 108);
        assert_eq!(s.top(), Some((105, hash(105, 0))));
    }

    #[test]
    fn kept_blocks_above_a_head_that_moved_back_are_out_of_range() {
        let mut s = watching(&[A]);
        let mut seg = run(100, 105, 0, hash(99, 0));
        accrue(&mut seg[5].bloom, &A);
        s.install(seg, 105);
        let r = s.report(99, 103);
        assert!(r.log_gaps.is_empty());
        assert!(r.touched.is_empty());
    }

    #[test]
    fn an_empty_range_reports_nothing() {
        let r = watching(&[A]).report(110, 110);
        assert_eq!((r.from, r.to), (111, 110));
        assert!(r.log_gaps.is_empty() && r.account_gaps.is_empty() && r.touched.is_empty());
    }

    #[test]
    fn the_watch_list_is_additive_bounded_and_clears_the_run_when_emptied() {
        let mut s = watching(&[A]);
        s.apply(&[B], &[]).unwrap();
        assert_eq!(s.report(0, 0).watching, vec![A, B]);
        s.apply(&[], &[A]).unwrap();
        assert_eq!(s.report(0, 0).watching, vec![B]);

        let too_many: Vec<[u8; 20]> = (0..=MAX_WATCHED as u32)
            .map(|i| {
                let mut a = [0u8; 20];
                a[..4].copy_from_slice(&i.to_be_bytes());
                a
            })
            .collect();
        assert!(s.apply(&too_many, &[]).is_err());
        assert_eq!(s.report(0, 0).watching, vec![B], "a refused push changes nothing");

        s.install(run(100, 101, 0, hash(99, 0)), 101);
        s.apply(&[], &[B]).unwrap();
        assert!(!s.is_active());
        assert_eq!(s.top(), None);
    }
}
