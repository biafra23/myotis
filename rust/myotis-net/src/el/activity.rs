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
use myotis_core::trie::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

use crate::el::snap::messages::BalAccountChange;

/// Blocks of activity kept below the anchored head: ~51 min on Sepolia and
/// mainnet (12 s slots), ~21 min on Gnosis (5 s). A host back within that
/// learns what it missed without re-proving; further back is a gap.
pub const WINDOW: u64 = 256;

/// How far below the kept top a followed account's stored state advances.
/// The blocks above it are applied at each answer instead, so a reorg of the
/// newest blocks replaces them without losing the account: only one that
/// reaches deeper than this drops it, and the next read proves it again.
pub const FOLLOW_MARGIN: u64 = 8;

/// How many blocks below the anchored head a followed account may be
/// answered at: the head's BAL arrives a few seconds after the head, and a
/// read in between is answered at the block before rather than proven over
/// snap. Past this the read is proven, so a follower that stopped getting
/// BALs never serves state that falls further behind.
pub const FOLLOW_MAX_LAG: u64 = 2;

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
    /// The header's `stateRoot` and `timestamp`: what a read answered at this
    /// block reports.
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub bloom: Box<LogsBloom>,
    /// The header's `blockAccessListHash`: none before Amsterdam.
    pub bal_hash: Option<[u8; 32]>,
    /// The accounts the block's verified BAL changed, ascending; `None` until
    /// one is fetched and verified (an account gap until then).
    pub account: Option<Box<[[u8; 20]]>>,
    /// The post-block values the verified BAL names for the accounts that
    /// were watched when it arrived, ascending by address. A changed account
    /// missing here (watched only since) cannot be followed through this
    /// block.
    pub watched_changes: Box<[BalAccountChange]>,
    /// Its BAL verified but did not decode. The commitment pins the bytes, so
    /// no peer can serve one that does: never asked for again, an account gap.
    pub bal_undecodable: bool,
}

/// An account's state as a proof names it: what a followed account carries
/// from block to block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountValues {
    pub exists: bool,
    pub nonce: u64,
    /// Big-endian and minimal, empty for zero (and when `!exists`).
    pub balance: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// A watched account whose state is known at one kept block: proven there by
/// a read, or carried there from such a proof through the verified BAL of
/// every block in between.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Followed {
    number: u64,
    hash: [u8; 32],
    values: AccountValues,
}

/// A followed account's state at a block that leads to the head: the read
/// [`ActivityState::followed_answer`] serves without asking a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FollowedAnswer {
    pub number: u64,
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub values: AccountValues,
}

/// Why a followed account could not be carried through a block.
#[derive(Debug, PartialEq, Eq)]
enum Carry {
    /// Its BAL is not verified yet: a later pass may bring it.
    NotYet,
    /// It never can be: the block wrote the account's storage (its new
    /// storage root is not in the BAL), its BAL does not decode or does not
    /// exist (before Amsterdam), or its values for this account were not
    /// kept (the account was not watched when the BAL arrived).
    Never,
}

/// Carry `values` through block `r`, by its verified BAL.
fn carry(values: &mut AccountValues, address: &[u8; 20], r: &BlockRecord) -> Result<(), Carry> {
    let Some(changed) = &r.account else {
        return Err(if r.bal_undecodable || r.bal_hash.is_none() { Carry::Never } else { Carry::NotYet });
    };
    if changed.binary_search(address).is_err() {
        return Ok(());
    }
    let i = r.watched_changes.binary_search_by(|c| c.address.cmp(address)).map_err(|_| Carry::Never)?;
    let change = &r.watched_changes[i];
    if change.storage_written {
        return Err(Carry::Never);
    }
    if let Some(balance) = &change.balance {
        values.balance = balance.clone();
    }
    if let Some(nonce) = change.nonce {
        values.nonce = nonce;
    }
    if let Some(code_hash) = change.code_hash {
        values.code_hash = code_hash;
    }
    // EIP-161: an account left empty is not in the state, and a proof says
    // it does not exist. A credit to one that did not makes it exist.
    values.exists = !(values.nonce == 0
        && values.balance.is_empty()
        && values.code_hash == EMPTY_CODE_HASH
        && values.storage_root == EMPTY_TRIE_ROOT);
    Ok(())
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
    /// The watched accounts whose state is known at a kept block
    /// ([`Self::seed`]), carried forward by each verified BAL.
    followed: BTreeMap<[u8; 20], Followed>,
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
        let watched = &self.watched;
        self.followed.retain(|a, _| watched.contains_key(a));
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
                if r.account.is_none() && old.account.is_some() {
                    r.account = old.account;
                    r.watched_changes = old.watched_changes;
                }
                r.bal_undecodable |= old.bal_undecodable;
            }
            self.records.insert(r.number, r);
        }
        let floor = head.saturating_sub(WINDOW - 1);
        self.records = self.records.split_off(&floor);
        self.advance_followed();
    }

    /// The kept blocks whose BAL is still wanted — at or above the BAL floor
    /// (the head the run last started over at), committing to one, none
    /// verified yet — newest
    /// first, at most `max`: `(number, block hash, blockAccessListHash)`.
    ///
    /// The floor reaches down to the block above a followed account's proof
    /// when that is lower (a proof made at a head just before the run last
    /// started over): carrying the account needs every BAL above it, and
    /// without them its next read would be proven again.
    pub fn bals_wanted(&self, max: usize) -> Vec<(u64, [u8; 32], [u8; 32])> {
        let floor = self.followed.values().map(|f| f.number + 1).min().map_or(self.bal_floor, |f| f.min(self.bal_floor));
        self.records
            .range(floor..)
            .map(|(_, r)| r)
            .rev()
            .filter(|r| r.account.is_none() && !r.bal_undecodable)
            .filter_map(|r| r.bal_hash.map(|bal| (r.number, r.hash, bal)))
            .take(max)
            .collect()
    }

    /// Record what block `number` (`hash`) changed, from its verified BAL:
    /// the accounts (`changed`), and the post-block values (`changes`) of
    /// those watched now. A changed account `changes` does not name cannot be
    /// carried through the block. Ignored when that block is no longer kept
    /// under that hash (a reorg or a trim while the BAL was fetched).
    pub fn set_account(
        &mut self,
        number: u64,
        hash: &[u8; 32],
        mut changed: Vec<[u8; 20]>,
        mut changes: Vec<BalAccountChange>,
    ) {
        let Some(r) = self.records.get_mut(&number).filter(|r| &r.hash == hash) else {
            return;
        };
        changed.sort_unstable();
        changed.dedup();
        r.account = Some(changed.into_boxed_slice());
        changes.sort_unstable_by_key(|c| c.address);
        changes.dedup_by(|a, b| a.address == b.address);
        changes.retain(|c| self.watched.contains_key(&c.address));
        r.watched_changes = changes.into_boxed_slice();
        self.advance_followed();
    }

    /// A watched account proven at block `number` (`hash`): from now on its
    /// state is carried forward by the BAL of every block above it, and a
    /// read at the head can be answered without a proof
    /// ([`Self::followed_answer`]). Ignored for an address not watched, and
    /// for a proof older than the one held.
    ///
    /// `hash` must be the block whose state root the proof was verified
    /// against. The block need not be kept yet (the follower may trail the
    /// read); the account is carried only once it is, under that hash.
    pub fn seed(&mut self, address: [u8; 20], number: u64, hash: [u8; 32], values: AccountValues) {
        if !self.watched.contains_key(&address) || self.followed.get(&address).is_some_and(|f| f.number > number) {
            return;
        }
        self.followed.insert(address, Followed { number, hash, values });
        self.advance_followed();
    }

    /// Carry every followed account forward through the kept blocks whose
    /// BAL is verified, up to [`FOLLOW_MARGIN`] below the kept top. Drop one
    /// that can never be carried on: its block was replaced or trimmed, or
    /// the next block is one it cannot be carried through ([`Carry::Never`]).
    fn advance_followed(&mut self) {
        // Nothing kept yet (the follower's first window is still on its way):
        // a proof made meanwhile waits for it.
        let Some((&lowest, _)) = self.records.first_key_value() else {
            return;
        };
        let top = self.records.last_key_value().map_or(0, |(n, _)| *n);
        let target = top.saturating_sub(FOLLOW_MARGIN);
        let records = &self.records;
        self.followed.retain(|address, f| {
            match records.get(&f.number) {
                Some(r) if r.hash == f.hash => {}
                // Proven above the kept top: the follower has not fetched that
                // block yet.
                None if f.number > top => return true,
                _ => return false,
            }
            debug_assert!(f.number >= lowest);
            while f.number < target {
                let Some(r) = records.get(&(f.number + 1)) else { break };
                let mut next = f.values.clone();
                match carry(&mut next, address, r) {
                    Ok(()) => {
                        *f = Followed { number: r.number, hash: r.hash, values: next };
                    }
                    Err(Carry::NotYet) => break,
                    Err(Carry::Never) => return false,
                }
            }
            true
        });
    }

    /// The state of the followed account `address` at the highest kept block
    /// it can be carried to that leads to the anchored head (`is_ancestor`, as
    /// in [`Self::report`]), when that block is at most `max_lag` below
    /// `head`. `None` sends the read to a proof.
    ///
    /// Sound by induction on the kept run: the account was proven at a block
    /// the run holds under the proof's hash, the run is parent-linked up to a
    /// block the beacon anchor vouches for, and every block in between has a
    /// BAL that hashes to its header's commitment. A BAL lists every account a
    /// block touched with its post-block values, so an account it does not
    /// list is unchanged.
    pub fn followed_answer(
        &self,
        address: &[u8; 20],
        head: u64,
        max_lag: u64,
        is_ancestor: impl Fn(u64, &[u8; 32]) -> bool,
    ) -> Option<FollowedAnswer> {
        let f = self.followed.get(address)?;
        let vouched_top = self
            .records
            .range(..=head)
            .rev()
            .find(|(_, r)| is_ancestor(r.number, &r.hash))
            .map(|(n, _)| *n)?;
        // A chain whose blocks commit to no BAL (before Amsterdam) carries
        // nothing: its reads stay proofs, as before following existed.
        let start = self
            .records
            .get(&f.number)
            .filter(|r| r.hash == f.hash && r.number <= vouched_top && r.bal_hash.is_some())?;
        let mut at = start;
        let mut values = f.values.clone();
        // `start` is at or below `vouched_top`, so the range is never inverted
        // (an empty one when the proof is at the top).
        for (_, r) in self.records.range(f.number + 1..vouched_top.saturating_add(1)) {
            let mut next = values.clone();
            match carry(&mut next, address, r) {
                Ok(()) => {}
                // A BAL still on its way: the state below it is the newest
                // known, answered within the lag.
                Err(Carry::NotYet) => break,
                // A block the account cannot be carried through: the state
                // below it is known to be superseded (or, with no BAL, not
                // known to be current), so the read is proven.
                Err(Carry::Never) => return None,
            }
            values = next;
            at = r;
        }
        (at.number.saturating_add(max_lag) >= head).then_some(FollowedAnswer {
            number: at.number,
            hash: at.hash,
            state_root: at.state_root,
            timestamp: at.timestamp,
            values,
        })
    }

    /// Mark block `number` (`hash`) as one whose verified BAL does not decode
    /// ([`BlockRecord::bal_undecodable`]). Ignored as [`Self::set_account`] is.
    pub fn set_bal_undecodable(&mut self, number: u64, hash: &[u8; 32]) {
        if let Some(r) = self.records.get_mut(&number).filter(|r| &r.hash == hash) {
            r.bal_undecodable = true;
        }
    }

    /// Forget every kept block (the follower stopped following), and with
    /// them every followed account: nothing links them to a later head.
    pub fn clear_records(&mut self) {
        self.records.clear();
        self.followed.clear();
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
                state_root: [n as u8 ^ fork; 32],
                timestamp: n * 12,
                bloom: Box::new(EMPTY_BLOOM),
                bal_hash: Some([n as u8; 32]),
                account: None,
                watched_changes: Box::new([]),
                bal_undecodable: false,
            });
            parent_hash = h;
        }
        out
    }

    /// Record a verified BAL that changed exactly the accounts `changes` names.
    fn set_bal(s: &mut ActivityState, number: u64, hash: &[u8; 32], changes: Vec<BalAccountChange>) {
        let changed = changes.iter().map(|c| c.address).collect();
        s.set_account(number, hash, changed, changes);
    }

    /// A BAL's changes to `addresses`: a balance change each.
    fn touched(addresses: &[[u8; 20]]) -> Vec<BalAccountChange> {
        addresses
            .iter()
            .map(|a| BalAccountChange { address: *a, balance: Some(vec![1]), nonce: None, code_hash: None, storage_written: false })
            .collect()
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
        set_bal(&mut s, 101, &hash(101, 0), touched(&[B, A]));
        set_bal(&mut s, 102, &hash(102, 0), touched(&[]));
        // A BAL for a block no longer kept under that hash changes nothing.
        set_bal(&mut s, 103, &hash(103, 1), touched(&[A]));
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
    fn bals_are_wanted_from_above_a_followed_proof_below_the_floor() {
        let mut s = watching(&[A]);
        // A proof at 104, just before the run started over at 107.
        s.seed(A, 104, hash(104, 0), proven(1, &[5]));
        s.install(run(100, 107, 0, hash(99, 0)), 107);
        assert_eq!(s.bals_wanted(8).iter().map(|w| w.0).collect::<Vec<_>>(), vec![107, 106, 105]);
        bals(&mut s, 105, 107, 0, none);
        assert_eq!(s.followed_answer(&A, 107, 0, every).map(|a| a.number), Some(107));
        // Unwatched, the floor is the run's own again.
        s.apply(&[B], &[A]).unwrap();
        s.install(run(108, 108, 0, hash(107, 0)), 108);
        assert_eq!(s.bals_wanted(8).iter().map(|w| w.0).collect::<Vec<_>>(), vec![108]);
    }

    #[test]
    fn a_block_fetched_again_keeps_its_verified_bal_and_a_reorged_one_loses_it() {
        let mut s = watching(&[A]);
        s.install(run(100, 102, 0, hash(99, 0)), 102);
        set_bal(&mut s, 102, &hash(102, 0), touched(&[A]));
        set_bal(&mut s, 101, &hash(101, 0), touched(&[]));
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
            set_bal(&mut s, n, &hash(n, 0), touched(&[]));
        }
        assert!(s.report(99, 102, every).account_gaps.is_empty());
        assert_eq!(s.report(99, 102, |n, _| n <= 100).account_gaps, vec![(101, 102)]);
    }

    fn proven(nonce: u64, balance: &[u8]) -> AccountValues {
        AccountValues {
            exists: true,
            nonce,
            balance: balance.to_vec(),
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: EMPTY_CODE_HASH,
        }
    }

    fn change(address: [u8; 20], balance: Option<&[u8]>, nonce: Option<u64>) -> BalAccountChange {
        BalAccountChange { address, balance: balance.map(<[u8]>::to_vec), nonce, code_hash: None, storage_written: false }
    }

    /// Verify the BAL of every kept block `lo..=hi` on `fork`, with `at(n)`'s changes.
    fn bals(s: &mut ActivityState, lo: u64, hi: u64, fork: u8, at: impl Fn(u64) -> Vec<BalAccountChange>) {
        for n in lo..=hi {
            set_bal(s, n, &hash(n, fork), at(n));
        }
    }

    fn none(_: u64) -> Vec<BalAccountChange> {
        Vec::new()
    }

    #[test]
    fn a_proven_account_is_carried_to_the_head_by_each_verified_bal() {
        let mut s = watching(&[A, B]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        s.seed(A, 100, hash(100, 0), proven(2, &[9]));
        // Nothing verified above the proof yet: answered at the proof's block
        // only while that is within the lag.
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, every), None);
        assert_eq!(s.followed_answer(&A, 100, FOLLOW_MAX_LAG, every).map(|a| a.number), Some(100));
        // Block 102 spends from A (and touches B, the second account changed);
        // 101, 103 and 104 leave A alone.
        bals(&mut s, 101, 105, 0, |n| match n {
            102 => vec![change(A, Some(&[4]), Some(3)), change(B, Some(&[1]), None)],
            105 => vec![change(A, Some(&[]), None)],
            _ => Vec::new(),
        });
        let at_104 = s.followed_answer(&A, 104, 0, every).unwrap();
        assert_eq!((at_104.number, at_104.hash, at_104.state_root), (104, hash(104, 0), [104; 32]));
        assert_eq!(at_104.timestamp, 104 * 12);
        assert_eq!(at_104.values, proven(3, &[4]));
        // Block 105 empties the balance; the nonce keeps it in the state.
        assert_eq!(s.followed_answer(&A, 105, 0, every).unwrap().values, proven(3, &[]));
        // B was never proven: nothing to carry.
        assert_eq!(s.followed_answer(&B, 105, FOLLOW_MAX_LAG, every), None);
    }

    #[test]
    fn a_head_whose_bal_is_missing_is_answered_just_below_it_or_proven() {
        let mut s = watching(&[A]);
        s.install(run(100, 110, 0, hash(99, 0)), 110);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 108, 0, none);
        // 109 and 110 have no BAL yet: 108 is two below the head.
        assert_eq!(s.followed_answer(&A, 110, 2, every).map(|a| a.number), Some(108));
        assert_eq!(s.followed_answer(&A, 110, 1, every), None);
        // A missing BAL in the middle stops the carry there, for good if it never comes.
        let mut s = watching(&[A]);
        s.install(run(100, 110, 0, hash(99, 0)), 110);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 104, 0, none);
        bals(&mut s, 106, 110, 0, none);
        assert_eq!(s.followed_answer(&A, 110, FOLLOW_MAX_LAG, every), None);
        set_bal(&mut s, 105, &hash(105, 0), none(105));
        assert_eq!(s.followed_answer(&A, 110, 0, every).map(|a| a.number), Some(110));
    }

    #[test]
    fn what_a_bal_cannot_say_sends_the_account_back_to_a_proof() {
        // A storage write: the new storage root is not in the BAL.
        let mut s = watching(&[A]);
        s.install(run(100, 120, 0, hash(99, 0)), 120);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 120, 0, |n| {
            if n == 103 {
                vec![BalAccountChange { storage_written: true, ..change(A, None, None) }]
            } else {
                Vec::new()
            }
        });
        assert_eq!(s.followed_answer(&A, 120, FOLLOW_MAX_LAG, every), None);
        // A proof after the write follows again.
        s.seed(A, 118, hash(118, 0), proven(1, &[5]));
        assert_eq!(s.followed_answer(&A, 120, 0, every).map(|a| a.number), Some(120));

        // A changed account whose values were not kept: it was not watched
        // when its BAL arrived.
        let mut s = watching(&[B]);
        s.install(run(100, 103, 0, hash(99, 0)), 103);
        set_bal(&mut s, 102, &hash(102, 0), vec![change(A, Some(&[7]), None)]);
        s.apply(&[A], &[]).unwrap();
        s.seed(A, 101, hash(101, 0), proven(1, &[5]));
        set_bal(&mut s, 103, &hash(103, 0), none(103));
        // Not even within the lag: the state below 102 is known to be superseded.
        assert_eq!(s.followed_answer(&A, 103, FOLLOW_MAX_LAG, every), None);

        // A BAL whose values did not decode: its changed accounts are known,
        // their values are not.
        let mut s = watching(&[A]);
        s.install(run(100, 102, 0, hash(99, 0)), 102);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        s.set_account(101, &hash(101, 0), vec![A], Vec::new());
        s.set_account(102, &hash(102, 0), vec![B], Vec::new());
        assert_eq!(s.followed_answer(&A, 102, FOLLOW_MAX_LAG, every), None);
        assert!(s.report(99, 102, every).touched.iter().any(|t| t.address == A && t.via == vec![Via::Account]));

        // A block before Amsterdam commits to no BAL.
        let mut s = watching(&[A]);
        let mut seg = run(100, 102, 0, hash(99, 0));
        seg[2].bal_hash = None;
        s.install(seg, 102);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        set_bal(&mut s, 101, &hash(101, 0), none(101));
        assert_eq!(s.followed_answer(&A, 102, 0, every), None);
        assert_eq!(s.followed_answer(&A, 102, FOLLOW_MAX_LAG, every), None, "never served from below a block with no BAL");

        // A storage write at the head itself: the pre-write state is not
        // served within the lag either.
        let mut s = watching(&[A]);
        s.install(run(100, 103, 0, hash(99, 0)), 103);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 103, 0, |n| {
            if n == 103 {
                vec![BalAccountChange { storage_written: true, ..change(A, None, None) }]
            } else {
                Vec::new()
            }
        });
        assert_eq!(s.followed_answer(&A, 103, FOLLOW_MAX_LAG, every), None);
        assert_eq!(s.followed_answer(&A, 102, 0, every).map(|a| a.number), Some(102));

        // A chain with no BALs at all (mainnet and Gnosis before Amsterdam):
        // a proof is never replayed, not even at its own block.
        let mut s = watching(&[A]);
        let mut seg = run(100, 101, 0, hash(99, 0));
        for r in &mut seg {
            r.bal_hash = None;
        }
        s.install(seg, 101);
        s.seed(A, 101, hash(101, 0), proven(1, &[5]));
        assert_eq!(s.followed_answer(&A, 101, FOLLOW_MAX_LAG, every), None);
    }

    #[test]
    fn an_account_comes_into_the_state_and_leaves_it_as_a_proof_would_say() {
        let mut s = watching(&[A]);
        s.install(run(100, 102, 0, hash(99, 0)), 102);
        let absent = AccountValues { exists: false, nonce: 0, balance: Vec::new(), storage_root: EMPTY_TRIE_ROOT, code_hash: EMPTY_CODE_HASH };
        s.seed(A, 100, hash(100, 0), absent.clone());
        bals(&mut s, 101, 102, 0, |n| match n {
            101 => vec![change(A, Some(&[3]), None)],
            _ => vec![change(A, Some(&[]), None)],
        });
        assert_eq!(s.followed_answer(&A, 101, 0, every).unwrap().values, AccountValues { exists: true, balance: vec![3], ..absent.clone() });
        assert_eq!(s.followed_answer(&A, 102, 0, every).unwrap().values, absent);
    }

    #[test]
    fn a_shallow_reorg_is_followed_on_the_new_fork() {
        let mut s = watching(&[A]);
        s.install(run(100, 120, 0, hash(99, 0)), 120);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 120, 0, |n| if n == 118 { vec![change(A, Some(&[1]), Some(2))] } else { Vec::new() });
        assert_eq!(s.followed_answer(&A, 120, 0, every).unwrap().values, proven(2, &[1]));
        // Fork 1 replaces 117..: its 118 does not spend from A, its 119 credits it.
        s.install(run(117, 121, 1, hash(116, 0)), 121);
        // Its BALs are not in yet: answered below the fork point only, within the lag.
        assert_eq!(s.followed_answer(&A, 121, 5, every).map(|a| a.number), Some(116));
        assert_eq!(s.followed_answer(&A, 121, FOLLOW_MAX_LAG, every), None);
        bals(&mut s, 117, 121, 1, |n| if n == 119 { vec![change(A, Some(&[8]), None)] } else { Vec::new() });
        let a = s.followed_answer(&A, 121, 0, every).unwrap();
        assert_eq!((a.number, a.hash), (121, hash(121, 1)));
        assert_eq!(a.values, proven(1, &[8]), "fork 0's spend is gone with its block");
    }

    #[test]
    fn a_reorg_below_the_stored_state_drops_the_account() {
        let mut s = watching(&[A]);
        s.install(run(100, 130, 0, hash(99, 0)), 130);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 130, 0, none);
        // Stored FOLLOW_MARGIN below the top, at 122: a reorg from 110 reaches it.
        s.install(run(110, 131, 1, hash(109, 0)), 131);
        bals(&mut s, 110, 131, 1, none);
        assert_eq!(s.followed_answer(&A, 131, FOLLOW_MAX_LAG, every), None);
    }

    #[test]
    fn a_proof_on_a_block_the_run_does_not_hold_is_never_carried() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        bals(&mut s, 101, 105, 0, none);
        // A proof at a sibling of 103.
        s.seed(A, 103, hash(103, 1), proven(1, &[5]));
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, every), None);
        // One above the kept top waits for the follower to fetch its block.
        s.seed(A, 106, hash(106, 0), proven(1, &[5]));
        assert_eq!(s.followed_answer(&A, 106, FOLLOW_MAX_LAG, every), None);
        s.install(run(106, 106, 0, hash(105, 0)), 106);
        assert_eq!(s.followed_answer(&A, 106, 0, every).map(|a| a.number), Some(106));
        // A head that moved back below the proof gets no answer.
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, every), None);
    }

    #[test]
    fn only_blocks_that_lead_to_the_head_answer() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        s.seed(A, 100, hash(100, 0), proven(1, &[5]));
        bals(&mut s, 101, 105, 0, none);
        // The head moved to a fork branching after 103 before the next tick.
        let on_fork = |n: u64, h: &[u8; 32]| n <= 103 && *h == hash(n, 0);
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, on_fork).map(|a| a.number), Some(103));
        assert_eq!(s.followed_answer(&A, 105, 1, on_fork), None);
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, |_, _| false), None);
    }

    #[test]
    fn seeds_are_for_watched_accounts_and_never_step_back() {
        let mut s = watching(&[A]);
        s.install(run(100, 105, 0, hash(99, 0)), 105);
        bals(&mut s, 101, 105, 0, none);
        s.seed(B, 104, hash(104, 0), proven(1, &[5]));
        assert_eq!(s.followed_answer(&B, 105, FOLLOW_MAX_LAG, every), None);
        s.seed(A, 104, hash(104, 0), proven(1, &[5]));
        s.seed(A, 102, hash(102, 0), proven(9, &[9]));
        assert_eq!(s.followed_answer(&A, 105, 0, every).unwrap().values, proven(1, &[5]));
        // An unwatched account is forgotten; watched again, it needs a new proof.
        s.apply(&[], &[A]).unwrap();
        s.apply(&[A], &[]).unwrap();
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, every), None);
        s.seed(A, 105, hash(105, 0), proven(1, &[5]));
        s.clear_records();
        assert_eq!(s.followed_answer(&A, 105, FOLLOW_MAX_LAG, every), None);
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
