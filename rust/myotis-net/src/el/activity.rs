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
//!   definitive for exactly that: no log of the block names the address as its
//!   emitter or in an indexed topic. It says nothing of a change no such log
//!   names (a rebasing token's balance, an address only in a log's data). A
//!   hit only says the block MAY have such a log.
//! - **`account`**: the account's own state — a balance, nonce or code change,
//!   or a storage write — from the block's access list (EIP-7928), fetched over
//!   eth/71 (EIP-8159) or snap/2 (EIP-8189) and verified against the header's
//!   `blockAccessListHash`. A block
//!   whose BAL no peer served, or a block before Amsterdam (no commitment to
//!   check one against), is an account gap.
//!
//! Coverage honesty is the contract: every block of a report's range is either
//! covered or listed in its gaps, per kind. A block the follower did not see —
//! before it started, past its window, skipped by a head jump or a failed
//! fetch — is a gap, never a silence. So is a kept block nothing proves to be
//! an ancestor of the CURRENT head: between a reorg and the tick that follows
//! it, the kept run may be on the losing fork.

use std::collections::BTreeMap;

use myotis_core::bloom::{BloomProbe, LogsBloom};

/// Blocks of activity kept below the anchored head: ~51 min on Sepolia and
/// mainnet (12 s slots), ~21 min on Gnosis (5 s). A host back within that
/// learns what it missed without re-proving; further back is a gap.
pub const WINDOW: u64 = 256;

/// Upper bound on the watch list: far more than a wallet's accounts. Every
/// watched address costs two bloom probes per kept block at each poll, and
/// the report lists every bloom hit — on mainnet, whose blooms run full, a
/// fair share of all of them — so an unbounded list would make a no-I/O poll
/// arbitrarily large. A push past it is refused.
pub const MAX_WATCHED: usize = 256;

/// One verified block, as the follower keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub bloom: Box<LogsBloom>,
    /// The header's `blockAccessListHash`: none before Amsterdam.
    pub bal_hash: Option<[u8; 32]>,
    /// The accounts the block's verified BAL changed, ascending; `None` until
    /// one is fetched and verified (an account gap until then).
    pub account: Option<Box<[[u8; 20]]>>,
    /// Its BAL verified but did not decode. The commitment pins the bytes, so
    /// no peer can serve one that does: never asked for again, an account gap.
    pub bal_undecodable: bool,
}

/// One touch in a report: `address` may have been touched by block `number`
/// (`hash`), seen through `via`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Touch {
    pub address: [u8; 20],
    pub block: u64,
    pub block_hash: [u8; 32],
    /// Ascending ([`Via::Account`] first), never empty.
    pub via: Vec<Via>,
}

/// What a touch was seen through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The block's verified access list records a change to the account.
    Account,
    /// The header's logs bloom matched.
    Log,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Account => "account",
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
    /// Each watched address with its two bloom probes (as emitter, as topic).
    watched: BTreeMap<[u8; 20], [BloomProbe; 2]>,
    /// Contiguous by number and parent-linked: `records[n].parent_hash ==
    /// records[n - 1].hash` for every kept pair.
    records: BTreeMap<u64, BlockRecord>,
    /// The lowest block whose BAL is worth fetching: the head the run last
    /// started over at (a start, a resume, a head jump past the window, a run
    /// that links to nothing kept). A host's proofs from then on anchor at
    /// that head or later, and one from before it meets a gap anyway, so the
    /// kept blocks below it would cost a BAL each (~54 KB on Sepolia) that
    /// can never vouch for a proof.
    bal_floor: u64,
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
        for a in watch {
            next.entry(*a).or_insert_with(|| probes(a));
        }
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

    /// The watch list, ascending.
    pub fn watching(&self) -> Vec<[u8; 20]> {
        self.watched.keys().copied().collect()
    }

    /// Whether the kept top commits to a block access list: the chain is past
    /// Amsterdam, so fetching BALs can cover the account side.
    pub fn top_commits_to_bal(&self) -> bool {
        self.records.values().next_back().is_some_and(|r| r.bal_hash.is_some())
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
        // Replaced records hand a verified BAL on to the same block re-fetched
        // (the shallow window always repeats the kept top).
        let mut replaced = if links_below {
            self.records.split_off(&first.number)
        } else {
            self.bal_floor = head;
            std::mem::take(&mut self.records)
        };
        for mut r in segment {
            if let Some(old) = replaced.remove(&r.number).filter(|old| old.hash == r.hash) {
                r.account = r.account.or(old.account);
                r.bal_undecodable |= old.bal_undecodable;
            }
            self.records.insert(r.number, r);
        }
        let floor = head.saturating_sub(WINDOW - 1);
        self.records = self.records.split_off(&floor);
    }

    /// The kept blocks whose BAL is still wanted — at or above the BAL floor
    /// (the head the run last started over at), committing to one, none
    /// verified yet — newest
    /// first, at most `max`: `(number, block hash, blockAccessListHash)`.
    pub fn bals_wanted(&self, max: usize) -> Vec<(u64, [u8; 32], [u8; 32])> {
        self.records
            .range(self.bal_floor..)
            .map(|(_, r)| r)
            .rev()
            .filter(|r| r.account.is_none() && !r.bal_undecodable)
            .filter_map(|r| r.bal_hash.map(|bal| (r.number, r.hash, bal)))
            .take(max)
            .collect()
    }

    /// Record the accounts block `number` (`hash`) changed, from its verified
    /// BAL. Ignored when that block is no longer kept under that hash (a reorg
    /// or a trim while the BAL was fetched).
    pub fn set_account(&mut self, number: u64, hash: &[u8; 32], mut changed: Vec<[u8; 20]>) {
        if let Some(r) = self.records.get_mut(&number).filter(|r| &r.hash == hash) {
            changed.sort_unstable();
            changed.dedup();
            r.account = Some(changed.into_boxed_slice());
        }
    }

    /// Mark block `number` (`hash`) as one whose verified BAL does not decode
    /// ([`BlockRecord::bal_undecodable`]). Ignored as [`Self::set_account`] is.
    pub fn set_bal_undecodable(&mut self, number: u64, hash: &[u8; 32]) {
        if let Some(r) = self.records.get_mut(&number).filter(|r| &r.hash == hash) {
            r.bal_undecodable = true;
        }
    }

    /// Forget every kept block (the follower stopped following).
    pub fn clear_records(&mut self) {
        self.records.clear();
    }

    /// The activity of the watched addresses in `(after, head]`. No I/O.
    ///
    /// `is_ancestor(number, hash)` says whether a block is known to be the
    /// head or one of its ancestors. A kept block counts as covered only up
    /// to the highest one it vouches for: the run is parent-linked, so every
    /// kept block below that one is an ancestor too, and every one above it
    /// may be on a fork the head has left, which is a gap until the follower
    /// re-links the run.
    pub fn report(&self, after: u64, head: u64, is_ancestor: impl Fn(u64, &[u8; 32]) -> bool) -> ActivityReport {
        let from = after.saturating_add(1);
        let to = head;
        let vouched_top = self
            .records
            .range(..=head)
            .rev()
            .find(|(_, r)| is_ancestor(r.number, &r.hash))
            .map(|(n, _)| *n);
        let base = (after, self.records.get(&after).filter(|_| vouched_top.is_some_and(|t| after <= t)).map(|r| r.hash));
        let watching = self.watching();
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
        // Kept blocks above the head (it moved back), or above the highest one
        // known to lead to it, are not covered.
        let kept: Vec<&BlockRecord> = match vouched_top {
            Some(top) if top >= from => self.records.range(from..=top).map(|(_, r)| r).collect(),
            _ => Vec::new(),
        };
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
        // Account coverage: the kept blocks whose BAL was verified.
        let account_gaps = gaps_of(from, to, kept.iter().filter(|r| r.account.is_some()).map(|r| r.number));
        let mut touched = Vec::new();
        for r in &kept {
            for (address, [emitter, topic]) in &self.watched {
                let mut via = Vec::new();
                if r.account.as_ref().is_some_and(|changed| changed.binary_search(address).is_ok()) {
                    via.push(Via::Account);
                }
                if emitter.may_match(&r.bloom) || topic.may_match(&r.bloom) {
                    via.push(Via::Log);
                }
                if !via.is_empty() {
                    touched.push(Touch { address: *address, block: r.number, block_hash: r.hash, via });
                }
            }
        }
        ActivityReport { from, to, base, account_gaps, log_gaps, touched, watching }
    }
}

/// The inclusive ranges of `[from, to]` not in `covered` (ascending).
fn gaps_of(from: u64, to: u64, covered: impl Iterator<Item = u64>) -> Vec<(u64, u64)> {
    let mut gaps = Vec::new();
    let mut next = from;
    for n in covered {
        if n > next {
            gaps.push((next, n - 1));
        }
        next = n + 1;
    }
    if next <= to {
        gaps.push((next, to));
    }
    gaps
}

/// The bloom probes of `address`: as a log's emitter, and as an indexed topic
/// (left-padded to 32 bytes).
fn probes(address: &[u8; 20]) -> [BloomProbe; 2] {
    let mut topic = [0u8; 32];
    topic[12..].copy_from_slice(address);
    [BloomProbe::of(address), BloomProbe::of(&topic)]
}

/// Could a log in a block with this bloom name `address`, as its emitter or as
/// an indexed topic? `false` is definitive.
pub fn bloom_may_touch(bloom: &LogsBloom, address: &[u8; 20]) -> bool {
    let [emitter, topic] = probes(address);
    emitter.may_match(bloom) || topic.may_match(bloom)
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
            out.push(BlockRecord {
                number: n,
                hash: h,
                parent_hash,
                bloom: Box::new(EMPTY_BLOOM),
                bal_hash: Some([n as u8; 32]),
                account: None,
                bal_undecodable: false,
            });
            parent_hash = h;
        }
        out
    }

    /// Every kept block leads to the head (no reorg since the last tick).
    fn every(_: u64, _: &[u8; 32]) -> bool {
        true
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
        let r = watching(&[A]).report(99, 110, every);
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
        let r = s.report(99, 110, every);
        assert_eq!(r.log_gaps, vec![(100, 104)]);
        // Account activity is not followed: the whole range stays a gap.
        assert_eq!(r.account_gaps, vec![(100, 110)]);
        assert_eq!(r.base, (99, None));
        assert_eq!(s.report(106, 110, every).base, (106, Some(hash(106, 0))));
        // A head past the run is a gap at the top.
        assert_eq!(s.report(104, 112, every).log_gaps, vec![(111, 112)]);
    }

    #[test]
    fn a_bloom_hit_is_a_touch_of_that_address_only() {
        let mut s = watching(&[A, B]);
        let mut seg = run(100, 102, 0, hash(99, 0));
        accrue(&mut seg[1].bloom, &B);
        s.install(seg, 102);
        let r = s.report(99, 102, every);
        assert_eq!(
            r.touched,
            vec![Touch { address: B, block: 101, block_hash: hash(101, 0), via: vec![Via::Log] }]
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
        let r = s.report(99, 101, every);
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
        assert!(s.report(99, 107, every).log_gaps.is_empty());
    }

    #[test]
    fn a_reorg_above_a_kept_block_replaces_only_what_is_above_it() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        // Fork 1 branches off after block 102 and is now the canonical head.
        s.install(run(103, 106, 1, hash(102, 0)), 106);
        let r = s.report(99, 106, every);
        assert!(r.log_gaps.is_empty());
        assert_eq!(s.report(102, 106, every).base.1, Some(hash(102, 0)));
        assert_eq!(s.report(104, 106, every).base.1, Some(hash(104, 1)));
        assert_eq!(s.top(), Some((106, hash(106, 1))));
    }

    #[test]
    fn a_run_that_links_to_nothing_kept_starts_over() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        // A head jump: the new run's parent is not a kept block.
        s.install(run(400, 402, 0, hash(399, 0)), 402);
        assert_eq!(s.report(99, 402, every).log_gaps, vec![(100, 399)]);
        // A run whose parent at a kept height is on another fork starts over too.
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        s.install(run(104, 106, 1, hash(103, 1)), 106);
        assert_eq!(s.report(99, 106, every).log_gaps, vec![(100, 103)]);
    }

    #[test]
    fn the_run_is_trimmed_to_the_window_below_the_head() {
        let mut s = watching(&[A]);
        s.install(run(1, 300, 0, hash(0, 0)), 300);
        let lowest = 300 - WINDOW + 1;
        assert_eq!(s.report(0, 300, every).log_gaps, vec![(1, lowest - 1)]);
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
        let r = s.report(99, 103, every);
        assert!(r.log_gaps.is_empty());
        assert!(r.touched.is_empty());
    }

    #[test]
    fn kept_blocks_not_known_to_lead_to_the_head_are_a_gap() {
        let mut s = watching(&[A]);
        let mut seg = run(100, 105, 0, hash(99, 0));
        accrue(&mut seg[4].bloom, &A);
        s.install(seg, 105);
        // The head moved to fork 1, which branched after 102, before the next tick:
        // only 100..=102 are known to lead to it.
        let on_fork_1 = |n: u64, h: &[u8; 32]| n <= 102 && *h == hash(n, 0);
        let r = s.report(99, 106, on_fork_1);
        assert_eq!(r.log_gaps, vec![(103, 106)]);
        assert!(r.touched.is_empty(), "a touch on the abandoned fork is not reported as coverage either");
        assert_eq!(s.report(102, 106, on_fork_1).base, (102, Some(hash(102, 0))));
        assert_eq!(s.report(104, 106, on_fork_1).base, (104, None));
        // Nothing known to lead to the head: the whole range is a gap.
        assert_eq!(s.report(99, 105, |_, _| false).log_gaps, vec![(100, 105)]);
    }

    #[test]
    fn a_kept_run_that_lags_the_head_still_covers_up_to_its_top() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        // A new head 106 the follower has not fetched yet, whose ancestry vouches for 105.
        let r = s.report(99, 106, |n, h| *h == hash(n, 0));
        assert_eq!(r.log_gaps, vec![(106, 106)]);
    }

    #[test]
    fn a_verified_bal_covers_the_account_side_and_names_what_it_changed() {
        let mut s = watching(&[A, B]);
        let mut seg = run(100, 103, 0, hash(99, 0));
        accrue(&mut seg[1].bloom, &A);
        s.install(seg, 103);
        // A run that starts over wants the BAL of its head only: nothing below it
        // can vouch for a proof made from now on.
        assert_eq!(s.bals_wanted(8), vec![(103, hash(103, 0), [103; 32])]);
        s.set_account(101, &hash(101, 0), vec![B, A]);
        s.set_account(102, &hash(102, 0), vec![]);
        // A BAL for a block no longer kept under that hash changes nothing.
        s.set_account(103, &hash(103, 1), vec![A]);
        let r = s.report(99, 103, every);
        assert_eq!(r.account_gaps, vec![(100, 100), (103, 103)]);
        assert_eq!(
            r.touched,
            vec![
                Touch { address: A, block: 101, block_hash: hash(101, 0), via: vec![Via::Account, Via::Log] },
                Touch { address: B, block: 101, block_hash: hash(101, 0), via: vec![Via::Account] },
            ]
        );
        assert_eq!(s.bals_wanted(8), vec![(103, hash(103, 0), [103; 32])]);
    }

    #[test]
    fn bals_are_wanted_from_the_head_the_run_started_over_at() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        assert_eq!(s.bals_wanted(8).iter().map(|w| w.0).collect::<Vec<_>>(), vec![105]);
        // New blocks that link: each is wanted, the backlog below the start never.
        s.install(run(105, 107, 0, hash(104, 0)), 107);
        assert_eq!(s.bals_wanted(8).iter().map(|w| w.0).collect::<Vec<_>>(), vec![107, 106, 105]);
        // A reorg above a kept block does not move the floor.
        s.install(run(107, 108, 1, hash(106, 0)), 108);
        assert_eq!(s.bals_wanted(8).iter().map(|w| w.0).collect::<Vec<_>>(), vec![108, 107, 106, 105]);
        // A head jump past the window starts over: the floor moves to the new head.
        s.install(run(400, 402, 0, hash(399, 0)), 402);
        assert_eq!(s.bals_wanted(8).iter().map(|w| w.0).collect::<Vec<_>>(), vec![402]);
    }

    #[test]
    fn a_block_fetched_again_keeps_its_verified_bal_and_a_reorged_one_loses_it() {
        let mut s = watching(&[A]);
        s.install(run(100, 102, 0, hash(99, 0)), 102);
        s.set_account(102, &hash(102, 0), vec![A]);
        s.set_account(101, &hash(101, 0), vec![]);
        // The next shallow window repeats the kept top.
        s.install(run(102, 103, 0, hash(101, 0)), 103);
        assert_eq!(s.report(101, 103, every).account_gaps, vec![(103, 103)]);
        // A reorg replaces 102 with another block: its BAL is gone with it.
        s.install(run(102, 104, 1, hash(101, 0)), 104);
        assert_eq!(s.report(100, 104, every).account_gaps, vec![(102, 104)]);
    }

    #[test]
    fn an_undecodable_bal_is_not_wanted_again_and_stays_a_gap() {
        let mut s = watching(&[A]);
        s.install(run(100, 101, 0, hash(99, 0)), 101);
        s.set_bal_undecodable(101, &hash(101, 0));
        assert!(s.bals_wanted(8).is_empty());
        // Kept across a reinstall of the same block, like a verified BAL.
        s.install(run(101, 102, 0, hash(100, 0)), 102);
        assert_eq!(s.bals_wanted(8), vec![(102, hash(102, 0), [102; 32])]);
        assert_eq!(s.report(99, 102, every).account_gaps, vec![(100, 102)]);
    }

    #[test]
    fn a_block_without_a_bal_commitment_is_never_wanted_and_stays_a_gap() {
        let mut s = watching(&[A]);
        let mut seg = run(100, 101, 0, hash(99, 0));
        for r in &mut seg {
            r.bal_hash = None; // before Amsterdam
        }
        s.install(seg, 101);
        assert!(s.bals_wanted(8).is_empty());
        assert_eq!(s.report(99, 101, every).account_gaps, vec![(100, 101)]);
    }

    #[test]
    fn account_coverage_ends_where_ancestry_does() {
        let mut s = watching(&[A]);
        s.install(run(100, 102, 0, hash(99, 0)), 102);
        for n in 100..=102 {
            s.set_account(n, &hash(n, 0), vec![]);
        }
        assert!(s.report(99, 102, every).account_gaps.is_empty());
        assert_eq!(s.report(99, 102, |n, _| n <= 100).account_gaps, vec![(101, 102)]);
    }

    #[test]
    fn gaps_of_fills_around_covered_blocks() {
        assert_eq!(gaps_of(1, 5, [].into_iter()), vec![(1, 5)]);
        assert_eq!(gaps_of(1, 5, [1, 2, 3, 4, 5].into_iter()), vec![]);
        assert_eq!(gaps_of(1, 5, [2, 4].into_iter()), vec![(1, 1), (3, 3), (5, 5)]);
        assert_eq!(gaps_of(1, 5, [1, 5].into_iter()), vec![(2, 4)]);
    }

    #[test]
    fn an_empty_range_reports_nothing() {
        let r = watching(&[A]).report(110, 110, every);
        assert_eq!((r.from, r.to), (111, 110));
        assert!(r.log_gaps.is_empty() && r.account_gaps.is_empty() && r.touched.is_empty());
    }

    #[test]
    fn the_watch_list_is_additive_bounded_and_clears_the_run_when_emptied() {
        let mut s = watching(&[A]);
        s.apply(&[B], &[]).unwrap();
        assert_eq!(s.report(0, 0, every).watching, vec![A, B]);
        s.apply(&[], &[A]).unwrap();
        assert_eq!(s.report(0, 0, every).watching, vec![B]);

        let too_many: Vec<[u8; 20]> = (0..=MAX_WATCHED as u32)
            .map(|i| {
                let mut a = [0u8; 20];
                a[..4].copy_from_slice(&i.to_be_bytes());
                a
            })
            .collect();
        assert!(s.apply(&too_many, &[]).is_err());
        assert_eq!(s.report(0, 0, every).watching, vec![B], "a refused push changes nothing");

        s.install(run(100, 101, 0, hash(99, 0)), 101);
        s.apply(&[], &[B]).unwrap();
        assert!(!s.is_active());
        assert_eq!(s.top(), None);
    }
}
