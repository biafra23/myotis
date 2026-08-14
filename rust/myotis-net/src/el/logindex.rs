//! Scoped, verified log index behind `eth_getLogs` (docs/eth-getlogs-design.md).
//!
//! This module is the pure state half of the feature: watch-list config,
//! the in-memory index, coverage bookkeeping, filter matching, and the
//! atomic on-disk snapshot. It does no networking and no verification —
//! callers (the head-follow appender and the backfill walker) only feed it
//! logs that already passed the anchored-header + receiptsRoot gates, the
//! same contract as `receipt::DecodedReceipt` ("callers must have already
//! verified").
//!
//! The one load-bearing rule lives in [`LogIndex::query`]: a request outside
//! indexed coverage is an error, never an empty answer. Wallets read `[]` as
//! "no events exist"; serving it for an unindexed range would corrupt
//! event-sourced state (commitment trees) silently and permanently.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One watched contract: index every log this address emits from
/// `from_block` onward. `topic0s`, when non-empty, restricts indexing to
/// those event signatures — and correspondingly restricts which queries are
/// answerable (see [`LogIndex::query`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEntry {
    pub address: [u8; 20],
    pub from_block: u64,
    pub topic0s: Vec<[u8; 32]>,
    /// Human-readable label (ENS reverse name or a host-supplied one), purely
    /// cosmetic: displayed by hosts, carried by the portable v2 snapshot, and
    /// deliberately EXCLUDED from [`LogIndexConfig::fingerprint`] — renaming
    /// an entry must never invalidate accumulated coverage. Empty = unnamed.
    pub name: String,
}

/// The network a snapshot belongs to. Persisted in every v2 file and checked
/// on load: logs are keyed by block-global `(block_number, log_index)`, so
/// merging or loading a file from another chain would silently collide keys
/// and fabricate coverage for blocks nobody verified on THIS chain. The
/// filename suffix (`logindex-sepolia.db`) is a convention, not a guarantee —
/// the bytes carry their own identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTag {
    /// EL network id (1 mainnet, 11155111 sepolia, 100 gnosis).
    pub network_id: u64,
    /// EL genesis block hash — distinguishes forks sharing a network id.
    pub genesis_hash: [u8; 32],
}

/// The host-supplied index configuration (crosses the FFI as JSON, parsed
/// engine-side into this typed form).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogIndexConfig {
    pub enabled: bool,
    /// Backfill pacing: `true` = the walker works a multi-batch time budget
    /// per tick (max download speed); `false` = one batch per tick (nice,
    /// background). Deliberately NOT part of the fingerprint — flipping it
    /// must never invalidate accumulated coverage.
    pub max_speed: bool,
    pub watch: Vec<WatchEntry>,
}

impl LogIndexConfig {
    /// Would any watch entry store this log? (Address match at/past the
    /// entry's from_block, honoring topic0 restrictions.) Exposed so batch
    /// fetchers can pre-filter against a captured config snapshot instead of
    /// buffering every log of every candidate block.
    pub fn watches(&self, log: &StoredLog) -> bool {
        self.watch.iter().any(|w| {
            w.address == log.address
                && log.block_number >= w.from_block
                && (w.topic0s.is_empty()
                    || log.topics.first().is_some_and(|t| w.topic0s.contains(t)))
        })
    }

    /// Union this (pushed) config with an already-subscribed watch-list —
    /// what keeps an imported subscription alive across host preset pushes:
    /// a host re-applying its shipped preset must EXTEND the stored set, not
    /// replace it, or every restart would fingerprint-mismatch the imported
    /// index into a full re-index. Same-address entries take the MIN
    /// `from_block` (undershooting cannot lie) and the pushed name when
    /// non-empty (the host is authoritative for cosmetics); addresses only
    /// in `stored` are appended behind the pushed ones. `enabled`/`max_speed`
    /// come from `self` — they are the push's whole point. None on a topic0
    /// conflict (the caller falls back to replace semantics).
    pub fn union_with(&self, stored: &[WatchEntry]) -> Option<LogIndexConfig> {
        let mut watch = self.watch.clone();
        for s in stored {
            match watch.iter_mut().find(|w| w.address == s.address) {
                Some(w) => {
                    let mut ta = w.topic0s.clone();
                    let mut tb = s.topic0s.clone();
                    ta.sort_unstable();
                    tb.sort_unstable();
                    if ta != tb {
                        return None;
                    }
                    w.from_block = w.from_block.min(s.from_block);
                    if w.name.is_empty() && !s.name.is_empty() {
                        w.name = s.name.clone();
                    }
                }
                None => watch.push(s.clone()),
            }
        }
        Some(LogIndexConfig { enabled: self.enabled, max_speed: self.max_speed, watch })
    }

    /// Order-insensitive fingerprint of the watch-list. A changed fingerprint
    /// on load invalidates the persisted index (derived data — re-index
    /// rather than risk serving under a stale subscription set).
    /// `name` is deliberately not encoded: it is cosmetic (see [`WatchEntry`])
    /// and renaming must not cost a re-index.
    pub fn fingerprint(&self) -> u64 {
        // FNV-1a over sorted entry encodings: stable, dependency-free, and
        // this is a cache-invalidation tag, not a security boundary.
        let mut encoded: Vec<Vec<u8>> = self
            .watch
            .iter()
            .map(|w| {
                let mut e = Vec::with_capacity(28 + 32 * w.topic0s.len());
                e.extend_from_slice(&w.address);
                e.extend_from_slice(&w.from_block.to_le_bytes());
                let mut ts = w.topic0s.clone();
                ts.sort_unstable();
                for t in ts {
                    e.extend_from_slice(&t);
                }
                e
            })
            .collect();
        encoded.sort_unstable();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for e in encoded {
            for b in e {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            // Entry separator so [AB],[C] != [A],[BC].
            h ^= 0xff;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

/// A stored, verified log — the exact tuple the `eth_getLogs` response needs
/// (field set mirrors the per-log JSON of `eljson::receipt_json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLog {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub tx_index: u32,
    /// Block-global log position (`log_index_base` + offset within the tx).
    pub log_index: u32,
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Contiguous indexed span, inclusive on both ends. `None` = nothing indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub span: Option<(u64, u64)>,
}

impl Coverage {
    pub fn contains(&self, from: u64, to: u64) -> bool {
        matches!(self.span, Some((low, high)) if low <= from && to <= high)
    }

    /// Extend upward — only contiguously. A gap would make `contains` claim
    /// blocks nobody processed, the exact lie this module exists to prevent.
    fn extend_up(&mut self, block: u64) -> Result<(), CoverageGap> {
        match self.span {
            None => self.span = Some((block, block)),
            Some((low, high)) => {
                if block > high.saturating_add(1) {
                    return Err(CoverageGap { edge: high, block });
                }
                self.span = Some((low, high.max(block)));
            }
        }
        Ok(())
    }

    /// Extend downward — only contiguously (see [`Self::extend_up`]).
    fn extend_down(&mut self, block: u64) -> Result<(), CoverageGap> {
        match self.span {
            None => self.span = Some((block, block)),
            Some((low, high)) => {
                if block.saturating_add(1) < low {
                    return Err(CoverageGap { edge: low, block });
                }
                self.span = Some((low.min(block), high));
            }
        }
        Ok(())
    }
}

/// The config lists the same address twice (see [`LogIndex::new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateWatchAddress(pub [u8; 20]);

/// A non-contiguous extend was rejected: the caller tried to record `block`
/// against a span whose nearest edge is `edge` — the blocks between were
/// never processed, so bridging them would fabricate coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageGap {
    pub edge: u64,
    pub block: u64,
}

/// A parsed `eth_getLogs` filter (JSON parsing happens engine-side).
/// `topics` is positional; an empty inner vec is a wildcard position; a
/// non-empty inner vec is an OR-list, per the RPC spec.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub from_block: u64,
    pub to_block: u64,
    pub addresses: Vec<[u8; 20]>,
    pub topics: Vec<Vec<[u8; 32]>>,
}

impl LogFilter {
    /// Spec matching: every positional constraint must hold; positions beyond
    /// the log's topic count fail unless the position is a wildcard.
    pub fn matches(&self, log: &StoredLog) -> bool {
        if log.block_number < self.from_block || log.block_number > self.to_block {
            return false;
        }
        if !self.addresses.is_empty() && !self.addresses.contains(&log.address) {
            return false;
        }
        for (i, alts) in self.topics.iter().enumerate() {
            if alts.is_empty() {
                continue; // wildcard position
            }
            match log.topics.get(i) {
                Some(t) if alts.contains(t) => {}
                _ => return false,
            }
        }
        true
    }
}

/// Why a query cannot be answered. Every variant maps to a strict
/// "cannot serve verified right now" error at the RPC layer — retryable
/// while the index is still catching up, permanent when the filter asks for
/// something the watch-list will never contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The index is switched off for this network.
    Disabled,
    /// An address in the filter is not on the watch-list at all.
    UnwatchedAddress([u8; 20]),
    /// The watch entry is topic0-restricted and the filter's topic0 position
    /// is a wildcard or asks for an unindexed signature.
    UnindexedTopic([u8; 20]),
    /// The address is watched but the requested range is not (fully) indexed
    /// yet. Carries what IS covered so status/errors can say how far along
    /// the backfill is.
    OutOfCoverage { address: [u8; 20], covered: Coverage },
    /// Filter is structurally unanswerable (from > to, or no address — a
    /// scoped index cannot serve address-less queries).
    Unanswerable,
}

/// The index proper: watch-list, per-entry coverage, and the log store keyed
/// by (block_number, log_index) so range queries are ordered scans.
#[derive(Debug, Default)]
pub struct LogIndex {
    config: LogIndexConfig,
    coverage: Vec<Coverage>, // parallel to config.watch
    logs: BTreeMap<(u64, u32), StoredLog>,
    /// Backfill cursor: the lowest header verified by the descending walk
    /// (number, hash) — the trust edge future batches must chain into.
    pub cursor: Option<(u64, [u8; 32])>,
}

impl LogIndex {
    /// Build an empty index. Rejects configs with duplicate watch addresses:
    /// query resolution is per-address, and two entries for one address can
    /// desynchronize storage from coverage (a coverage-honesty hole).
    pub fn new(config: LogIndexConfig) -> Result<Self, DuplicateWatchAddress> {
        for (i, w) in config.watch.iter().enumerate() {
            if config.watch.iter().skip(i + 1).any(|o| o.address == w.address) {
                return Err(DuplicateWatchAddress(w.address));
            }
        }
        let n = config.watch.len();
        Ok(Self { config, coverage: vec![Coverage::default(); n], logs: BTreeMap::new(), cursor: None })
    }

    /// Flip the enabled bit without touching accumulated state (used when a
    /// host re-applies a config whose watch-list fingerprint is unchanged).
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Swap in `config` while keeping ALL accumulated state — the additive
    /// re-apply path. Adoptable iff it subscribes exactly this index's
    /// address set under the same topic0 restrictions: then coverage still
    /// describes every entry (re-paired by address, since order may differ).
    /// Names and runtime bits ride along. A LOWERED `from_block` adopts too:
    /// while the walk is mid-descent that is just a deeper target, and when
    /// it drops below an already-complete span's low (a hole the descending
    /// walk could never reach — see [`walk_resumable`]) the cursor is
    /// DROPPED so the appender re-seeds at the top and the walker
    /// re-descends: coverage survives, the hole closes, nothing wedges.
    /// False (and untouched state) for a new/removed address or a changed
    /// topic set — those need a re-index (or a merge).
    pub fn adopt_config(&mut self, config: LogIndexConfig) -> bool {
        if config.watch.len() != self.config.watch.len() {
            return false;
        }
        let mut coverage = Vec::with_capacity(config.watch.len());
        for w in &config.watch {
            let Some(i) = self.config.watch.iter().position(|o| o.address == w.address) else {
                return false;
            };
            let mut ta = w.topic0s.clone();
            let mut tb = self.config.watch[i].topic0s.clone();
            ta.sort_unstable();
            tb.sort_unstable();
            if ta != tb {
                return false;
            }
            coverage.push(self.coverage[i]);
        }
        if !walk_resumable(&config.watch, &coverage, self.cursor) {
            self.cursor = None;
        }
        self.config = config;
        self.coverage = coverage;
        true
    }

    /// Flip the backfill pacing bit without touching accumulated state (same
    /// fingerprint-unchanged re-apply path as [`Self::set_enabled`]).
    pub fn set_max_speed(&mut self, max_speed: bool) {
        self.config.max_speed = max_speed;
    }

    pub fn config(&self) -> &LogIndexConfig {
        &self.config
    }

    /// Fill in a display name for a watched address IF it is still unnamed —
    /// the post-import naming pass. Never overwrites: a name baked into a
    /// snapshot (or pushed by a host) outranks a late lookup. Cosmetic only
    /// (names are fingerprint-neutral); persists with the next checkpoint.
    /// Returns whether anything changed.
    pub fn set_name(&mut self, address: &[u8; 20], name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        match self.config.watch.iter_mut().find(|w| &w.address == address) {
            Some(w) if w.name.is_empty() => {
                w.name = name.to_string();
                true
            }
            _ => false,
        }
    }

    pub fn coverage_of(&self, address: &[u8; 20]) -> Option<Coverage> {
        self.config
            .watch
            .iter()
            .zip(self.coverage.iter())
            .find(|(w, _)| &w.address == address)
            .map(|(_, c)| *c)
    }

    fn watched(&self, log: &StoredLog) -> bool {
        self.config.watches(log)
    }

    /// Record a fully processed block adjoining the high edge (the head-follow
    /// path). `logs` may be empty — coverage still advances, which is what
    /// makes "no events in this range" a servable answer. All-or-nothing: a
    /// gap against ANY affected entry rejects the whole call and stores
    /// nothing — the caller must process the missing blocks first.
    pub fn append_block(
        &mut self,
        block_number: u64,
        block_hash: [u8; 32],
        logs: Vec<StoredLog>,
    ) -> Result<(), CoverageGap> {
        for (w, c) in self.config.watch.iter().zip(self.coverage.iter()) {
            if block_number >= w.from_block {
                if let Some((low, high)) = c.span {
                    if block_number > high.saturating_add(1) || block_number < low {
                        return Err(CoverageGap { edge: high, block: block_number });
                    }
                }
            }
        }
        for log in logs {
            // Unconditional (not debug_assert): a mislabeled log would be
            // keyed by its own number, possibly inside covered range it was
            // never verified for. Drop it instead.
            if log.block_number != block_number {
                continue;
            }
            if self.watched(&log) {
                self.logs.insert((log.block_number, log.log_index), log);
            }
        }
        for (w, c) in self.config.watch.iter().zip(self.coverage.iter_mut()) {
            if block_number >= w.from_block {
                // Pre-checked above; a gap here is unreachable.
                let _ = c.extend_up(block_number);
            }
        }
        // Seed the backfill trust edge at the first-ever appended block: the
        // walker chains DOWNWARD from here (backfill_block then advances it).
        if self.cursor.is_none() {
            self.cursor = Some((block_number, block_hash));
        }
        Ok(())
    }

    /// Record a fully processed block adjoining the low edge (the backfill
    /// walk). Caller supplies the verified (number, hash) so the cursor tracks
    /// the trust edge. Same all-or-nothing gap rule as [`Self::append_block`].
    pub fn backfill_block(
        &mut self,
        block_number: u64,
        block_hash: [u8; 32],
        logs: Vec<StoredLog>,
    ) -> Result<(), CoverageGap> {
        for (w, c) in self.config.watch.iter().zip(self.coverage.iter()) {
            if block_number >= w.from_block {
                if let Some((low, high)) = c.span {
                    if block_number.saturating_add(1) < low || block_number > high {
                        return Err(CoverageGap { edge: low, block: block_number });
                    }
                }
            }
        }
        for log in logs {
            if log.block_number != block_number {
                continue; // see append_block: unconditional mislabel guard
            }
            if self.watched(&log) {
                self.logs.insert((log.block_number, log.log_index), log);
            }
        }
        for (w, c) in self.config.watch.iter().zip(self.coverage.iter_mut()) {
            if block_number >= w.from_block {
                let _ = c.extend_down(block_number);
            }
        }
        self.cursor = Some((block_number, block_hash));
        Ok(())
    }

    /// Drop everything above `fork_point` (exclusive) after a reorg above
    /// finalized. Coverage highs pull back; logs of orphaned blocks go away.
    pub fn rewind_above(&mut self, fork_point: u64) {
        // The backfill trust edge is a HASH; if the reorg reaches below it,
        // that hash may name an orphaned block — a resuming walker would
        // parent-chain into the dead branch. Drop it; the caller re-anchors.
        if self.cursor.is_some_and(|(n, _)| n > fork_point) {
            self.cursor = None;
        }
        self.logs.retain(|(bn, _), _| *bn <= fork_point);
        for c in &mut self.coverage {
            if let Some((low, high)) = c.span {
                if high > fork_point {
                    c.span = if low > fork_point { None } else { Some((low, fork_point)) };
                }
            }
        }
    }

    /// Answer `eth_getLogs`, enforcing coverage honesty (see module docs).
    pub fn query(&self, filter: &LogFilter) -> Result<Vec<StoredLog>, QueryError> {
        if !self.config.enabled {
            return Err(QueryError::Disabled);
        }
        if filter.from_block > filter.to_block || filter.addresses.is_empty() {
            return Err(QueryError::Unanswerable);
        }
        for addr in &filter.addresses {
            let Some((w, cov)) = self
                .config
                .watch
                .iter()
                .zip(self.coverage.iter())
                .find(|(w, _)| &w.address == addr)
            else {
                return Err(QueryError::UnwatchedAddress(*addr));
            };
            if !w.topic0s.is_empty() {
                // Topic-restricted entry: only queries pinned to a subset of
                // the indexed topic0s are answerable — a wildcard would
                // deserve logs we never stored.
                let ok = filter
                    .topics
                    .first()
                    .is_some_and(|alts| !alts.is_empty() && alts.iter().all(|t| w.topic0s.contains(t)));
                if !ok {
                    return Err(QueryError::UnindexedTopic(*addr));
                }
            }
            // Only the part of the range at/after the entry's from_block must
            // be covered — below it the contract cannot have logs by config,
            // which the config itself asserts (deployment block).
            let need_from = filter.from_block.max(w.from_block);
            if need_from <= filter.to_block && !cov.contains(need_from, filter.to_block) {
                return Err(QueryError::OutOfCoverage { address: *addr, covered: *cov });
            }
        }
        Ok(self
            .logs
            .range((filter.from_block, 0)..=(filter.to_block, u32::MAX))
            .map(|(_, l)| l)
            .filter(|l| filter.matches(l))
            .cloned()
            .collect())
    }

    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    /// The next block the head-follow appender should record: one past the
    /// highest covered block across entries, or None when nothing is indexed
    /// yet (the appender then starts fresh at the current head).
    /// Invariant making `max` safe here: append_block extends every
    /// at-or-past-from_block entry together and rewind_above pulls highs to
    /// a common fork point, so all `Some` highs are equal at rest; an entry
    /// below the max is either pre-from_block or `None` (backfill's job).
    pub fn append_edge(&self) -> Option<u64> {
        self.coverage
            .iter()
            .filter_map(|c| c.span.map(|(_, high)| high))
            .max()
            .map(|h| h.saturating_add(1))
    }

    /// Bloom pre-filter for one block: could its header bloom contain a log
    /// any watch entry would store? `false` is a definitive skip (blooms
    /// have no false negatives); `true` still requires verified receipts.
    /// Entries whose `from_block` is above `block_number` are ignored, and
    /// a topic0-restricted entry requires address AND one of its topic0s.
    pub fn bloom_may_match(&self, block_number: u64, bloom: &myotis_core::bloom::LogsBloom) -> bool {
        self.config.watch.iter().any(|w| {
            block_number >= w.from_block
                && myotis_core::bloom::may_contain(bloom, &w.address)
                && (w.topic0s.is_empty()
                    || w.topic0s.iter().any(|t| myotis_core::bloom::may_contain(bloom, t)))
        })
    }

    /// Watch entries paired with their coverage — the status surface.
    pub fn coverage_entries(&self) -> Vec<(WatchEntry, Coverage)> {
        self.config.watch.iter().cloned().zip(self.coverage.iter().copied()).collect()
    }
}

// ---------------------------------------------------------------------------
// Persistence: a versioned framed blob, written atomically (temp + rename,
// the sync-state snapshot pattern). The index is derived data: any load
// problem — bad magic, unknown version, truncation, fingerprint mismatch —
// yields None and the caller re-indexes. Never correctness-critical.
// ---------------------------------------------------------------------------

const MAGIC: &[u8; 4] = b"MLIX";
/// v1: config-keyed blob (fingerprint only — unreadable without the exact
///     watch-list that produced it; still LOADED for upgrade, never written).
/// v2: self-describing — adds the chain tag and the full watch-table
///     (address, from_block, topic0s, name), so a file can be imported on a
///     host that has never seen its config, and cannot cross networks.
const VERSION: u32 = 2;
const VERSION_LEGACY: u32 = 1;

/// Byte offset of the v2 checksum field: magic(4) + version(4) +
/// network_id(8) + genesis_hash(32) + fingerprint(8). The checksum covers
/// everything AFTER itself.
const V2_CHECKSUM_AT: usize = 56;
/// v1 layout: magic(4) + version(4) + fingerprint(8).
const V1_CHECKSUM_AT: usize = 16;

/// FNV-1a (same primitive as the config fingerprint): integrity tag for the
/// snapshot payload — bit-rot detection, not a security boundary.
fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

struct Cursor<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.d.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).and_then(|b| b.try_into().ok())
    }
}

impl LogIndex {
    /// Serialize with coverage and logs CLAMPED at `max_block`: everything
    /// above it is left out of the file entirely. Used to keep optimistic
    /// (above-finality) coverage out of checkpoints — that coverage is only
    /// verifiable against the in-memory tail record, which does not survive a
    /// restart, so persisting it would leave a later run holding coverage it
    /// can never re-check.
    pub fn serialize_clamped(&self, tag: &ChainTag, max_block: u64) -> Vec<u8> {
        self.serialize_with_clamp(tag, Some(max_block))
    }

    /// [`Self::persist`] with the same clamp as [`Self::serialize_clamped`].
    pub fn persist_clamped(&self, tag: &ChainTag, path: &Path, max_block: u64) -> std::io::Result<()> {
        let tmp: PathBuf = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&self.serialize_clamped(tag, max_block))?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    pub fn serialize(&self, tag: &ChainTag) -> Vec<u8> {
        self.serialize_with_clamp(tag, None)
    }

    /// The one serializer (always writes VERSION 2). `clamp` bounds what is
    /// written (see [`Self::serialize_clamped`]) and filters DURING the
    /// write: the tail keeps coverage above finality at all times, so a clamp
    /// that cloned the index would deep-copy the whole log store on every
    /// checkpoint, under the index lock, on a 10s cadence.
    fn serialize_with_clamp(&self, tag: &ChainTag, clamp: Option<u64>) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.logs.len() * 200);
        out.extend_from_slice(MAGIC);
        put_u32(&mut out, VERSION);
        put_u64(&mut out, tag.network_id);
        out.extend_from_slice(&tag.genesis_hash);
        put_u64(&mut out, self.config.fingerprint());
        put_u64(&mut out, 0); // checksum placeholder, patched below
        // The watch-table, in config order (coverage below is parallel to
        // it): what makes the file self-describing — an importer reconstructs
        // the subscription set from the bytes instead of needing the exact
        // config that produced them.
        put_u32(&mut out, self.config.watch.len() as u32);
        for w in &self.config.watch {
            out.extend_from_slice(&w.address);
            put_u64(&mut out, w.from_block);
            put_u32(&mut out, w.topic0s.len() as u32);
            for t in &w.topic0s {
                out.extend_from_slice(t);
            }
            put_bytes(&mut out, w.name.as_bytes());
        }
        // Coverage spans + cursor.
        put_u32(&mut out, self.coverage.len() as u32);
        for c in &self.coverage {
            // A span whose LOW is above the clamp disappears entirely; one
            // that straddles it is written with the clamped high.
            let span = match (c.span, clamp) {
                (Some((low, _)), Some(max)) if low > max => None,
                (Some((low, high)), Some(max)) => Some((low, high.min(max))),
                (span, _) => span,
            };
            match span {
                None => out.push(0),
                Some((low, high)) => {
                    out.push(1);
                    put_u64(&mut out, low);
                    put_u64(&mut out, high);
                }
            }
        }
        // The cursor is a HASH: above the clamp it may name a block that was
        // never re-checked (or was orphaned), and a reloading walker would
        // parent-chain into it. Drop it rather than persist it — the appender
        // re-seeds the trust edge on its first append.
        let cursor = match (self.cursor, clamp) {
            (Some((n, _)), Some(max)) if n > max => None,
            (cursor, _) => cursor,
        };
        match cursor {
            None => out.push(0),
            Some((n, h)) => {
                out.push(1);
                put_u64(&mut out, n);
                out.extend_from_slice(&h);
            }
        }
        // Logs (the clamped range is a prefix of the key order, so this is a
        // bounded scan rather than a filtered copy).
        let clamped_logs: Vec<&StoredLog> = match clamp {
            None => self.logs.values().collect(),
            Some(max) => self.logs.range(..=(max, u32::MAX)).map(|(_, l)| l).collect(),
        };
        put_u64(&mut out, clamped_logs.len() as u64);
        for log in clamped_logs {
            put_u64(&mut out, log.block_number);
            out.extend_from_slice(&log.block_hash);
            out.extend_from_slice(&log.tx_hash);
            put_u32(&mut out, log.tx_index);
            put_u32(&mut out, log.log_index);
            out.extend_from_slice(&log.address);
            put_u32(&mut out, log.topics.len() as u32);
            for t in &log.topics {
                out.extend_from_slice(t);
            }
            put_bytes(&mut out, &log.data);
        }
        // Payload checksum over everything after the checksum field itself:
        // structural framing catches truncation, this catches bit-rot inside
        // otherwise-valid frames — either way a bad load means re-index, never
        // serving corrupted logs as verified.
        let sum = fnv64(&out[V2_CHECKSUM_AT + 8..]);
        if let Some(slot) = out.get_mut(V2_CHECKSUM_AT..V2_CHECKSUM_AT + 8) {
            slot.copy_from_slice(&sum.to_le_bytes());
        }
        out
    }

    /// Rebuild from bytes for the given config. Any mismatch or corruption
    /// → None (re-index). Accepts the current v2 layout (tag-checked) and the
    /// legacy v1 layout (pre-tag files written by earlier builds — loading
    /// them preserves accumulated coverage across the upgrade; the next
    /// checkpoint rewrites the file as v2).
    pub fn deserialize(config: &LogIndexConfig, tag: &ChainTag, data: &[u8]) -> Option<Self> {
        let mut c = Cursor { d: data, pos: 0 };
        if c.take(4)? != MAGIC {
            return None;
        }
        match c.u32()? {
            VERSION_LEGACY => Self::deserialize_v1(config, data, c),
            VERSION => {
                let parsed = parse_v2(data, c)?;
                if parsed.tag != *tag || parsed.fingerprint != config.fingerprint() {
                    return None;
                }
                // The file's coverage vec parallels the file's watch order;
                // the given config may list the same set in another order
                // (the fingerprint is order-insensitive). Re-pair coverage by
                // ADDRESS so a reordered-but-equal config cannot attach a
                // span to the wrong entry. The config (not the file) supplies
                // the names — the host is authoritative for cosmetics.
                let mut coverage = Vec::with_capacity(config.watch.len());
                for w in &config.watch {
                    let j = parsed.watch.iter().position(|f| f.address == w.address)?;
                    coverage.push(parsed.coverage[j]);
                }
                Some(Self { config: config.clone(), coverage, logs: parsed.logs, cursor: parsed.cursor })
            }
            _ => None,
        }
    }

    /// The legacy (v1) layout: fingerprint-keyed, no chain tag, no
    /// watch-table, coverage parallel to the SUPPLIED config's order.
    fn deserialize_v1(config: &LogIndexConfig, data: &[u8], mut c: Cursor) -> Option<Self> {
        if c.u64()? != config.fingerprint() {
            return None;
        }
        let stored_sum = c.u64()?;
        if fnv64(data.get(V1_CHECKSUM_AT + 8..)?) != stored_sum {
            return None;
        }
        let n_cov = c.u32()? as usize;
        if n_cov != config.watch.len() {
            return None;
        }
        let (coverage, cursor, logs) = parse_body(&mut c, n_cov)?;
        if c.pos != data.len() {
            return None; // trailing garbage → treat as corrupt
        }
        Some(Self { config: config.clone(), coverage, logs, cursor })
    }

    /// Self-describing read (v2 only): reconstruct the subscription set from
    /// the file's own watch-table instead of requiring the config that wrote
    /// it — the import path. Returns the file's chain tag so the importer can
    /// refuse a file from another network, and the index carrying the file's
    /// watch entries (names included) with `enabled`/`max_speed` false: those
    /// are runtime bits the receiving host decides, never file content.
    pub fn deserialize_portable(data: &[u8]) -> Option<(ChainTag, Self)> {
        let mut c = Cursor { d: data, pos: 0 };
        if c.take(4)? != MAGIC || c.u32()? != VERSION {
            return None; // v1 files are not self-describing — not importable
        }
        let parsed = parse_v2(data, c)?;
        let config =
            LogIndexConfig { enabled: false, max_speed: false, watch: parsed.watch };
        // The stored fingerprint must actually match the stored watch-table —
        // a mismatch means the frame is inconsistent with itself.
        if parsed.fingerprint != config.fingerprint() {
            return None;
        }
        let ix = Self::new(config).ok()?;
        Some((
            parsed.tag,
            Self { coverage: parsed.coverage, logs: parsed.logs, cursor: parsed.cursor, ..ix },
        ))
    }

    /// [`Self::deserialize_portable`] from a file.
    pub fn load_portable(path: &Path) -> Option<(ChainTag, Self)> {
        let data = std::fs::read(path).ok()?;
        Self::deserialize_portable(&data)
    }

    /// Atomic best-effort persist: temp file (pid-suffixed) + rename, the
    /// `persist_snapshot` pattern. A failed write costs a re-index on the
    /// affected range, never correctness.
    pub fn persist(&self, tag: &ChainTag, path: &Path) -> std::io::Result<()> {
        let tmp: PathBuf = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&self.serialize(tag))?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Load a persisted index for `config`; None on absence or any mismatch.
    pub fn load(config: &LogIndexConfig, tag: &ChainTag, path: &Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        Self::deserialize(config, tag, &data)
    }
}

// ---------------------------------------------------------------------------
// Merge: combine self-describing snapshots (import). The output is CANONICAL —
// every present span shares one global high and the cursor sits at the global
// low — because that is the only shape the appender/walker pair can resume:
// `append_block` demands each new block adjoin EVERY live entry's span, so
// per-entry frontiers at different heights would wedge the appender on its
// first tick. Canonicalization is what turns "import then catch up" into the
// machinery that already exists (walker descends to the new lows, bridge +
// appender close the top) instead of new per-entry reconciliation code.
// ---------------------------------------------------------------------------

/// Why a set of snapshots cannot be merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// No sources given.
    Empty,
    /// A source belongs to another network. Merging it would key logs of a
    /// foreign chain into this chain's block numbers — fabricated coverage.
    ChainMismatch { expected: ChainTag, got: ChainTag },
    /// Two sources watch the same address under DIFFERENT topic0 sets. A
    /// coverage span's meaning includes the topic restriction it was indexed
    /// under; unioning restrictions would claim logs nobody stored. Refused
    /// rather than resolved — re-generate one source with matching topics.
    TopicConflict([u8; 20]),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::Empty => write!(f, "nothing to merge"),
            MergeError::ChainMismatch { expected, got } => write!(
                f,
                "snapshot belongs to another chain (network id {}, expected {})",
                got.network_id, expected.network_id
            ),
            MergeError::TopicConflict(a) => {
                write!(f, "0x")?;
                for b in a {
                    write!(f, "{b:02x}")?;
                }
                write!(f, " is watched under conflicting topic restrictions")
            }
        }
    }
}

impl LogIndex {
    /// Merge portable snapshots (all of one chain) into a single canonical
    /// index. Rules:
    ///
    /// - watch union — same address requires equal topic0 sets
    ///   ([`MergeError::TopicConflict`]); `from_block` = min (undershooting
    ///   cannot lie); name = first non-empty in input order.
    /// - sources that contribute nothing (no new address, no lower
    ///   `from_block`, no coverage extension) are dropped FIRST, so a stale
    ///   re-import cannot drag the global high back in time.
    /// - coverage: global high `H` = min over contributing sources' own
    ///   highs; every span is clamped to `H` (one whose low is above `H`
    ///   vanishes — its blocks re-index later) and unioned per address. With
    ///   canonical inputs every surviving span contains `H`, so the union is
    ///   contiguous and single-span coverage suffices. The band above `H` is
    ///   re-covered by the existing bridge/appender — re-fetched, never
    ///   trusted from the staler file.
    /// - logs: kept iff inside the merged span of their address's entry —
    ///   anything else is unreachable by the coverage-honest query anyway.
    /// - cursor: the lowest source cursor (the deepest verified trust edge).
    ///
    /// Non-canonical inputs (hand-crafted files) degrade safely: a span that
    /// cannot share `H` goes dormant (None — re-indexed), a cursor above some
    /// span's low is dropped (the appender re-seeds it).
    ///
    /// The output's `enabled`/`max_speed` are false: runtime bits the
    /// installing host decides, never file content.
    pub fn merge(sources: Vec<(ChainTag, LogIndex)>) -> Result<(ChainTag, LogIndex), MergeError> {
        let Some(expected) = sources.first().map(|(t, _)| *t) else {
            return Err(MergeError::Empty);
        };
        if let Some((got, _)) = sources.iter().find(|(t, _)| *t != expected) {
            return Err(MergeError::ChainMismatch { expected, got: *got });
        }
        let mut sources: Vec<LogIndex> = sources.into_iter().map(|(_, ix)| ix).collect();
        // Topic conflicts are structural — check before any pruning so a
        // conflicting pair is refused even when one side would be pruned.
        for (i, a) in sources.iter().enumerate() {
            for b in sources.iter().skip(i + 1) {
                for wa in &a.config.watch {
                    if let Some(wb) = b.config.watch.iter().find(|w| w.address == wa.address) {
                        let mut ta = wa.topic0s.clone();
                        let mut tb = wb.topic0s.clone();
                        ta.sort_unstable();
                        tb.sort_unstable();
                        if ta != tb {
                            return Err(MergeError::TopicConflict(wa.address));
                        }
                    }
                }
            }
        }
        // Drop redundant sources: everything they declare and cover is
        // already declared and covered (at least as deeply) by the rest.
        loop {
            let redundant = (0..sources.len()).find(|&i| {
                sources.len() > 1 && {
                    let rest: Vec<&LogIndex> = sources
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, s)| s)
                        .collect();
                    sources[i].config.watch.iter().all(|w| {
                        rest.iter().any(|r| {
                            r.config.watch.iter().zip(r.coverage.iter()).any(|(rw, rc)| {
                                rw.address == w.address
                                    && rw.from_block <= w.from_block
                                    && match sources[i].coverage_of(&w.address).and_then(|c| c.span) {
                                        None => true,
                                        Some((low, high)) => matches!(
                                            rc.span,
                                            Some((rl, rh)) if rl <= low && high <= rh
                                        ),
                                    }
                            })
                        })
                    })
                }
            });
            match redundant {
                Some(i) => {
                    sources.remove(i);
                }
                None => break,
            }
        }
        // Union the watch-lists (config order: first source first).
        let mut watch: Vec<WatchEntry> = Vec::new();
        for s in &sources {
            for w in &s.config.watch {
                match watch.iter_mut().find(|m| m.address == w.address) {
                    Some(m) => {
                        m.from_block = m.from_block.min(w.from_block);
                        if m.name.is_empty() && !w.name.is_empty() {
                            m.name = w.name.clone();
                        }
                    }
                    None => watch.push(w.clone()),
                }
            }
        }
        // Global high H: the minimum of the contributing sources' own highs.
        // A source without any coverage contributes config only and does not
        // constrain H.
        let h = sources
            .iter()
            .filter_map(|s| s.coverage.iter().filter_map(|c| c.span.map(|(_, hi)| hi)).max())
            .min();
        // Per entry: clamp every source span to H, union what overlaps or
        // adjoins, and if disjoint pieces survive (non-canonical inputs only)
        // keep the lowest — deployment-anchored history is the part a
        // cold-syncing wallet cannot rebuild from the head.
        let coverage: Vec<Coverage> = watch
            .iter()
            .map(|w| {
                let mut pieces: Vec<(u64, u64)> = sources
                    .iter()
                    .filter_map(|s| s.coverage_of(&w.address).and_then(|c| c.span))
                    .filter_map(|(low, high)| {
                        let h = h.expect("a span exists, so H exists");
                        (low <= h).then_some((low, high.min(h)))
                    })
                    .collect();
                pieces.sort_unstable();
                let merged = pieces.into_iter().fold(Vec::<(u64, u64)>::new(), |mut acc, p| {
                    match acc.last_mut() {
                        Some(last) if p.0 <= last.1.saturating_add(1) => last.1 = last.1.max(p.1),
                        _ => acc.push(p),
                    }
                    acc
                });
                Coverage { span: merged.first().copied() }
            })
            .collect();
        // Canonical output invariant: every present span ends at the same
        // high. A piece that cannot (non-canonical input) goes dormant.
        let out_high = coverage.iter().filter_map(|c| c.span.map(|(_, hi)| hi)).max();
        let coverage: Vec<Coverage> = coverage
            .into_iter()
            .map(|c| Coverage { span: c.span.filter(|(_, hi)| Some(*hi) == out_high) })
            .collect();
        // Cursor: the DEEPEST source trust edge the walk can actually resume
        // from (see [`walk_resumable`] — every incomplete span must sit at or
        // below it; the walk re-descends THROUGH deeper spans, it can never
        // reach a hole above itself). When no source cursor qualifies, no
        // cursor at all: the appender re-seeds at the top and the walker
        // re-descends through the merged spans — headers-only where the
        // bloom misses, and every hole closes on the way down.
        let mut candidates: Vec<(u64, [u8; 32])> = sources.iter().filter_map(|s| s.cursor).collect();
        candidates.sort_unstable_by_key(|(n, _)| *n);
        let cursor = candidates
            .into_iter()
            .find(|c| walk_resumable(&watch, &coverage, Some(*c)));
        // Logs: only what the merged coverage can actually serve.
        let mut logs = BTreeMap::new();
        for s in &mut sources {
            let taken = std::mem::take(&mut s.logs);
            for (key, log) in taken {
                let served = watch
                    .iter()
                    .zip(coverage.iter())
                    .find(|(w, _)| w.address == log.address)
                    .is_some_and(|(_, c)| c.contains(log.block_number, log.block_number));
                if served {
                    logs.insert(key, log);
                }
            }
        }
        let config = LogIndexConfig { enabled: false, max_speed: false, watch };
        // Duplicates are impossible post-union; new() also re-validates.
        let ix = Self::new(config).expect("union has unique addresses");
        Ok((expected, Self { coverage, logs, cursor, ..ix }))
    }
}

/// Can the single-cursor walk, resuming from `cursor`, eventually complete
/// every entry? The walker only DESCENDS: from `cursor - 1` down to the
/// lowest `from_block`, extending each entry it passes. So a hole that sits
/// ABOVE the cursor is unreachable forever, and `backfill_block`'s gap check
/// wedges outright on an incomplete span whose low is above the walk. The
/// resumable states are exactly:
///
/// - `cursor == None`: always resumable — the appender seeds the cursor at
///   the top on its next append (extending every present span and every
///   absent one together, so the all-highs-equal invariant holds) and the
///   walker re-descends through everything; costly, never wrong.
/// - `cursor == Some(n)`: every present span is either complete
///   (`low <= from_block` — the walker skips it below its from_block) or
///   reachable (`low <= n` — the walk passes through it on the way down),
///   AND every ABSENT span belongs to an entry starting above the frontier
///   (`from_block > H` — the appender's job); an absent span with
///   `from_block <= H` has its whole range above the descending walk.
///
/// This is the invariant [`LogIndex::merge`] and [`LogIndex::adopt_config`]
/// preserve; getting it backwards (cursor at/below every low) was a
/// walk-wedging bug — the walker demands the OPPOSITE half.
fn walk_resumable(
    watch: &[WatchEntry],
    coverage: &[Coverage],
    cursor: Option<(u64, [u8; 32])>,
) -> bool {
    let Some((n, _)) = cursor else {
        return true;
    };
    let Some(h) = coverage.iter().filter_map(|c| c.span.map(|(_, hi)| hi)).max() else {
        return false; // a cursor with nothing covered: nothing seeded it
    };
    watch.iter().zip(coverage.iter()).all(|(w, c)| match c.span {
        Some((low, _)) => low <= w.from_block || low <= n,
        None => w.from_block > h,
    })
}

/// A fully parsed v2 frame (tag + fingerprint + watch-table + body), before
/// any policy decision about configs or tags.
struct ParsedV2 {
    tag: ChainTag,
    fingerprint: u64,
    watch: Vec<WatchEntry>,
    coverage: Vec<Coverage>,
    cursor: Option<(u64, [u8; 32])>,
    logs: BTreeMap<(u64, u32), StoredLog>,
}

/// Parse a v2 frame from just past the version field. Verifies the checksum
/// and structural framing; policy checks (tag, fingerprint-vs-config) are the
/// caller's.
fn parse_v2(data: &[u8], mut c: Cursor) -> Option<ParsedV2> {
    let network_id = c.u64()?;
    let genesis_hash = c.arr::<32>()?;
    let fingerprint = c.u64()?;
    let stored_sum = c.u64()?;
    if fnv64(data.get(V2_CHECKSUM_AT + 8..)?) != stored_sum {
        return None;
    }
    let n_watch = c.u32()? as usize;
    let mut watch = Vec::with_capacity(n_watch.min(1024));
    for _ in 0..n_watch {
        let address = c.arr::<20>()?;
        let from_block = c.u64()?;
        let n_topics = c.u32()? as usize;
        let mut topic0s = Vec::with_capacity(n_topics.min(64));
        for _ in 0..n_topics {
            topic0s.push(c.arr::<32>()?);
        }
        let name = String::from_utf8(c.bytes()?.to_vec()).ok()?;
        watch.push(WatchEntry { address, from_block, topic0s, name });
    }
    // Coverage is parallel to the watch-table by construction of the writer —
    // a count disagreeing with the table is an inconsistent frame.
    let n_cov = c.u32()? as usize;
    if n_cov != n_watch {
        return None;
    }
    let (coverage, cursor, logs) = parse_body(&mut c, n_cov)?;
    if c.pos != data.len() {
        return None; // trailing garbage → treat as corrupt
    }
    Some(ParsedV2 { tag: ChainTag { network_id, genesis_hash }, fingerprint, watch, coverage, cursor, logs })
}

/// Parse the coverage + cursor + log body shared by v1 and v2 frames.
#[allow(clippy::type_complexity)]
fn parse_body(
    c: &mut Cursor,
    n_cov: usize,
) -> Option<(Vec<Coverage>, Option<(u64, [u8; 32])>, BTreeMap<(u64, u32), StoredLog>)> {
    let mut coverage = Vec::with_capacity(n_cov.min(1024));
    for _ in 0..n_cov {
        coverage.push(match c.take(1)?.first().copied()? {
            0 => Coverage::default(),
            1 => Coverage { span: Some((c.u64()?, c.u64()?)) },
            _ => return None,
        });
    }
    let cursor = match c.take(1)?.first().copied()? {
        0 => None,
        1 => Some((c.u64()?, c.arr::<32>()?)),
        _ => return None,
    };
    let n_logs = c.u64()?;
    let mut logs = BTreeMap::new();
    for _ in 0..n_logs {
        let block_number = c.u64()?;
        let block_hash = c.arr::<32>()?;
        let tx_hash = c.arr::<32>()?;
        let tx_index = c.u32()?;
        let log_index = c.u32()?;
        let address = c.arr::<20>()?;
        let n_topics = c.u32()? as usize;
        if n_topics > 4 {
            return None;
        }
        let mut topics = Vec::with_capacity(n_topics);
        for _ in 0..n_topics {
            topics.push(c.arr::<32>()?);
        }
        let data = c.bytes()?.to_vec();
        logs.insert(
            (block_number, log_index),
            StoredLog { block_number, block_hash, tx_hash, tx_index, log_index, address, topics, data },
        );
    }
    Some((coverage, cursor, logs))
}

#[cfg(test)]
mod tests {

    #[test]
    fn max_speed_is_fingerprint_neutral_and_flippable() {
        let w = WatchEntry { address: [7u8; 20], from_block: 5, topic0s: vec![], name: String::new() };
        let a = LogIndexConfig { enabled: true, max_speed: false, watch: vec![w.clone()] };
        let b = LogIndexConfig { enabled: true, max_speed: true, watch: vec![w] };
        // Flipping pacing must never invalidate accumulated coverage.
        assert_eq!(a.fingerprint(), b.fingerprint());
        let mut ix = LogIndex::new(a).unwrap();
        assert!(!ix.config().max_speed);
        ix.set_max_speed(true);
        assert!(ix.config().max_speed);
    }

    use super::*;

    fn addr(b: u8) -> [u8; 20] {
        [b; 20]
    }

    fn topic(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn log(bn: u64, li: u32, a: [u8; 20], topics: Vec<[u8; 32]>) -> StoredLog {
        StoredLog {
            block_number: bn,
            block_hash: [0xbb; 32],
            tx_hash: [0xcc; 32],
            tx_index: 0,
            log_index: li,
            address: a,
            topics,
            data: vec![1, 2, 3],
        }
    }

    fn watch_all(a: [u8; 20], from: u64) -> WatchEntry {
        WatchEntry { address: a, from_block: from, topic0s: vec![], name: String::new() }
    }

    /// The chain tag every test persists under (arbitrary but fixed).
    fn tag() -> ChainTag {
        ChainTag { network_id: 1, genesis_hash: [0xd4; 32] }
    }

    fn config(entries: Vec<WatchEntry>) -> LogIndexConfig {
        LogIndexConfig { enabled: true, max_speed: false, watch: entries }
    }

    /// `LogIndex::new(config(...)).unwrap()` shorthand for valid configs.
    fn config_ok(entries: Vec<WatchEntry>) -> LogIndexConfig {
        config(entries)
    }

    fn filter(from: u64, to: u64, a: [u8; 20]) -> LogFilter {
        LogFilter { from_block: from, to_block: to, addresses: vec![a], topics: vec![] }
    }

    #[test]
    fn query_outside_coverage_errors_never_empty() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 100)])).unwrap();
        ix.append_block(200, [0xbb; 32], vec![]).unwrap();
        ix.append_block(201, [0xbb; 32], vec![log(201, 0, addr(1), vec![topic(9)])]).unwrap();
        // Covered range answers (including the empty block).
        assert_eq!(ix.query(&filter(200, 200, addr(1))).unwrap(), vec![]);
        assert_eq!(ix.query(&filter(200, 201, addr(1))).unwrap().len(), 1);
        // Range dipping below coverage errors instead of answering empt-ish.
        match ix.query(&filter(150, 201, addr(1))) {
            Err(QueryError::OutOfCoverage { address, covered }) => {
                assert_eq!(address, addr(1));
                assert_eq!(covered.span, Some((200, 201)));
            }
            other => panic!("expected OutOfCoverage, got {other:?}"),
        }
    }

    #[test]
    fn range_below_from_block_needs_no_coverage() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 500)])).unwrap();
        ix.append_block(500, [0xbb; 32], vec![]).unwrap();
        // 100..=500 is fine: below from_block the contract can't have logs.
        assert_eq!(ix.query(&filter(100, 500, addr(1))).unwrap(), vec![]);
        // Entirely below from_block: nothing to cover, empty is honest.
        assert_eq!(ix.query(&filter(100, 400, addr(1))).unwrap(), vec![]);
    }

    #[test]
    fn unwatched_address_and_disabled_error() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        ix.append_block(10, [0xbb; 32], vec![]).unwrap();
        assert_eq!(ix.query(&filter(0, 10, addr(2))), Err(QueryError::UnwatchedAddress(addr(2))));
        let off = LogIndex::new(LogIndexConfig { enabled: false, max_speed: false, watch: vec![watch_all(addr(1), 0)] }).unwrap();
        assert_eq!(off.query(&filter(0, 0, addr(1))), Err(QueryError::Disabled));
        assert_eq!(ix.query(&LogFilter { from_block: 0, to_block: 10, addresses: vec![], topics: vec![] }), Err(QueryError::Unanswerable));
    }

    #[test]
    fn topic_restricted_watch_rejects_wildcard_queries() {
        let w = WatchEntry { address: addr(1), from_block: 0, topic0s: vec![topic(7)], name: String::new() };
        let mut ix = LogIndex::new(config_ok(vec![w])).unwrap();
        ix.append_block(5, [0xbb; 32], vec![log(5, 0, addr(1), vec![topic(7)])]).unwrap();
        // Wildcard topic0 would deserve unindexed signatures → error.
        assert_eq!(ix.query(&filter(5, 5, addr(1))), Err(QueryError::UnindexedTopic(addr(1))));
        // Pinned to the indexed signature → answers.
        let mut f = filter(5, 5, addr(1));
        f.topics = vec![vec![topic(7)]];
        assert_eq!(ix.query(&f).unwrap().len(), 1);
        // Pinned to a different signature → error, not empty.
        f.topics = vec![vec![topic(8)]];
        assert_eq!(ix.query(&f), Err(QueryError::UnindexedTopic(addr(1))));
    }

    #[test]
    fn positional_topic_matching() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        ix.append_block(1, [0xbb; 32], vec![log(1, 0, addr(1), vec![topic(7), topic(8)])]).unwrap();
        let mut f = filter(1, 1, addr(1));
        f.topics = vec![vec![], vec![topic(8), topic(9)]]; // wildcard t0, OR at t1
        assert_eq!(ix.query(&f).unwrap().len(), 1);
        f.topics = vec![vec![], vec![topic(9)]];
        assert_eq!(ix.query(&f).unwrap().len(), 0); // covered range, honest empty
        f.topics = vec![vec![], vec![], vec![topic(1)]]; // position beyond log's topics
        assert_eq!(ix.query(&f).unwrap().len(), 0);
    }

    #[test]
    fn backfill_extends_down_and_tracks_cursor() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 100)])).unwrap();
        ix.append_block(300, [0xbb; 32], vec![]).unwrap();
        ix.backfill_block(299, [9; 32], vec![log(299, 2, addr(1), vec![])]).unwrap();
        ix.backfill_block(298, [8; 32], vec![]).unwrap();
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((298, 300)));
        assert_eq!(ix.cursor, Some((298, [8; 32])));
        assert_eq!(ix.query(&filter(298, 300, addr(1))).unwrap().len(), 1);
    }

    #[test]
    fn clamped_persist_leaves_optimistic_coverage_out_of_the_file() {
        let dir = std::env::temp_dir().join(format!("logindex-clamp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clamped.db");
        let cfg = config_ok(vec![watch_all(addr(1), 0)]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        for b in 10..=14 {
            ix.append_block(b, [b as u8; 32], vec![log(b, 0, addr(1), vec![])]).unwrap();
        }
        // Finality at 12: blocks 13-14 are optimistic and must not persist —
        // a later run has no way to re-check them, and once finality moves
        // past them nothing would ever rewind them.
        ix.persist_clamped(&tag(), &path, 12).unwrap();
        let loaded = LogIndex::load(&cfg, &tag(), &path).unwrap();
        assert_eq!(loaded.coverage_of(&addr(1)).unwrap().span, Some((10, 12)));
        assert_eq!(loaded.log_count(), 3);
        // The live index is untouched — the clamp is a serialization concern.
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((10, 14)));
        assert_eq!(ix.log_count(), 5);
        // Nothing above the clamp → byte-identical to a plain serialize.
        assert_eq!(ix.serialize_clamped(&tag(), 14), ix.serialize(&tag()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn clamping_writes_a_prefix_without_touching_the_live_index() {
        let cfg = config_ok(vec![watch_all(addr(1), 0)]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        for b in 10..=14 {
            ix.append_block(b, [b as u8; 32], vec![log(b, 0, addr(1), vec![])]).unwrap();
        }
        // A span entirely above the clamp disappears; one that straddles it is
        // written with the clamped high; the live index is untouched either way.
        let bytes = ix.serialize_clamped(&tag(), 12);
        let loaded = LogIndex::deserialize(&cfg, &tag(), &bytes).unwrap();
        assert_eq!(loaded.coverage_of(&addr(1)).unwrap().span, Some((10, 12)));
        assert_eq!(loaded.log_count(), 3);
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((10, 14)));
        assert_eq!(ix.log_count(), 5);
        let below = LogIndex::deserialize(&cfg, &tag(), &ix.serialize_clamped(&tag(), 9)).unwrap();
        assert_eq!(below.coverage_of(&addr(1)).unwrap().span, None);
        assert_eq!(below.log_count(), 0);
    }

    #[test]
    fn clamping_drops_a_cursor_above_the_clamp() {
        let cfg = config_ok(vec![watch_all(addr(1), 0)]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        // append_block seeds the cursor at the first appended block.
        ix.append_block(20, [20; 32], vec![]).unwrap();
        assert_eq!(ix.cursor, Some((20, [20; 32])));
        // Clamped below it, the cursor must NOT persist: it is a hash, and
        // above the clamp it may name a block that was never re-checked — a
        // reloading walker would parent-chain into it.
        let below = LogIndex::deserialize(&cfg, &tag(), &ix.serialize_clamped(&tag(), 15)).unwrap();
        assert_eq!(below.cursor, None);
        // At or above the cursor, it survives.
        let at = LogIndex::deserialize(&cfg, &tag(), &ix.serialize_clamped(&tag(), 20)).unwrap();
        assert_eq!(at.cursor, Some((20, [20; 32])));
    }

    #[test]
    fn rewind_above_drops_logs_and_pulls_coverage_back() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        for b in 10..=14 {
            ix.append_block(b, [0xbb; 32], vec![log(b, 0, addr(1), vec![])]).unwrap();
        }
        ix.rewind_above(12);
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((10, 12)));
        assert_eq!(ix.log_count(), 3);
        // Above the fork point is out of coverage again.
        assert!(matches!(ix.query(&filter(10, 14, addr(1))), Err(QueryError::OutOfCoverage { .. })));
    }

    #[test]
    fn unwatched_logs_are_not_stored() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 100)])).unwrap();
        // Wrong address, and right address but below from_block: both dropped.
        ix.append_block(200, [0xbb; 32], vec![log(200, 0, addr(2), vec![])]).unwrap();
        ix.backfill_block(99, [1; 32], vec![log(99, 0, addr(1), vec![])]).unwrap();
        assert_eq!(ix.log_count(), 0);
    }

    #[test]
    fn persist_load_roundtrip_and_invalidation() {
        let dir = std::env::temp_dir().join(format!("logindex-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("logindex-test.db");
        let cfg = config(vec![watch_all(addr(1), 100), WatchEntry { address: addr(2), from_block: 0, topic0s: vec![topic(7)], name: String::new() }]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        ix.append_block(200, [0xbb; 32], vec![log(200, 3, addr(1), vec![topic(7), topic(8)])]).unwrap();
        ix.backfill_block(199, [7; 32], vec![]).unwrap();
        ix.persist(&tag(), &path).unwrap();

        let back = LogIndex::load(&cfg, &tag(), &path).expect("roundtrip");
        assert_eq!(back.coverage_of(&addr(1)).unwrap().span, Some((199, 200)));
        assert_eq!(back.cursor, Some((199, [7; 32])));
        assert_eq!(back.query(&filter(199, 200, addr(1))).unwrap(), ix.query(&filter(199, 200, addr(1))).unwrap());

        // Changed watch-list → fingerprint mismatch → None (re-index).
        let changed = config(vec![watch_all(addr(1), 101)]);
        assert!(LogIndex::load(&changed, &tag(), &path).is_none());
        // Another network's tag → None, even for the very config that wrote
        // the file: the bytes carry their own chain identity.
        let other = ChainTag { network_id: 11_155_111, genesis_hash: [0x25; 32] };
        assert!(LogIndex::load(&cfg, &other, &path).is_none());
        // Truncated file → None.
        let data = std::fs::read(&path).unwrap();
        std::fs::write(&path, &data[..data.len() - 1]).unwrap();
        assert!(LogIndex::load(&cfg, &tag(), &path).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gaps_are_rejected_not_bridged() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        ix.append_block(200, [0xbb; 32], vec![]).unwrap();
        // Skipping 201 must fail and store nothing.
        assert_eq!(ix.append_block(205, [0xbb; 32], vec![log(205, 0, addr(1), vec![])]), Err(CoverageGap { edge: 200, block: 205 }));
        assert_eq!(ix.log_count(), 0);
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((200, 200)));
        // Contiguous append still works; downward gap equally rejected.
        ix.append_block(201, [0xbb; 32], vec![]).unwrap();
        assert_eq!(ix.backfill_block(150, [1; 32], vec![]), Err(CoverageGap { edge: 200, block: 150 }));
        ix.backfill_block(199, [2; 32], vec![]).unwrap();
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((199, 201)));
        // The gap blocks never answer as empty.
        assert!(matches!(ix.query(&filter(199, 205, addr(1))), Err(QueryError::OutOfCoverage { .. })));
    }

    #[test]
    fn deserialize_survives_arbitrary_corruption() {
        let cfg = config(vec![watch_all(addr(1), 0)]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        ix.append_block(7, [0xbb; 32], vec![log(7, 0, addr(1), vec![topic(1), topic(2)])]).unwrap();
        let good = ix.serialize(&tag());
        assert!(LogIndex::deserialize(&cfg, &tag(), &good).is_some());
        // Every single-byte mutation must yield Some-or-None, never panic,
        // and structural fields must not produce a bogus accepted index —
        // on the config-keyed AND the self-describing path.
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = LogIndex::deserialize(&cfg, &tag(), &bad);
            let _ = LogIndex::deserialize_portable(&bad);
        }
        // Every truncation length likewise.
        for n in 0..good.len() {
            assert!(LogIndex::deserialize(&cfg, &tag(), &good[..n]).is_none());
            assert!(LogIndex::deserialize_portable(&good[..n]).is_none());
        }
        // Huge length prefixes must fail cleanly (no allocation bomb).
        let mut huge = good.clone();
        let tail = huge.len() - 4;
        huge[tail..].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = LogIndex::deserialize(&cfg, &tag(), &huge);
        let _ = LogIndex::deserialize_portable(&huge);
    }

    #[test]
    fn duplicate_watch_addresses_are_rejected() {
        let dup = config(vec![watch_all(addr(1), 0), WatchEntry { address: addr(1), from_block: 50, topic0s: vec![], name: String::new() }]);
        assert!(matches!(LogIndex::new(dup), Err(DuplicateWatchAddress(a)) if a == addr(1)));
    }

    #[test]
    fn rewind_below_backfill_edge_drops_cursor() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        ix.append_block(200, [0xbb; 32], vec![]).unwrap();
        ix.backfill_block(199, [9; 32], vec![]).unwrap();
        // Fork below the walk's edge: the cursor hash may be orphaned.
        ix.rewind_above(150);
        assert_eq!(ix.cursor, None);
        // Fork above the edge leaves the cursor intact.
        let mut ix2 = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        ix2.append_block(200, [0xbb; 32], vec![]).unwrap();
        ix2.backfill_block(199, [9; 32], vec![]).unwrap();
        ix2.rewind_above(199);
        assert_eq!(ix2.cursor, Some((199, [9; 32])));
    }

    #[test]
    fn append_below_low_and_backfill_above_high_are_rejected() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        ix.append_block(200, [0xbb; 32], vec![]).unwrap();
        ix.backfill_block(199, [1; 32], vec![]).unwrap();
        assert!(ix.append_block(150, [0xbb; 32], vec![log(150, 0, addr(1), vec![])]).is_err());
        assert_eq!(ix.log_count(), 0); // nothing stored outside coverage
        assert!(ix.backfill_block(300, [2; 32], vec![]).is_err());
        // Re-processing inside the span stays allowed on both paths.
        ix.append_block(200, [0xbb; 32], vec![]).unwrap();
        ix.backfill_block(199, [1; 32], vec![]).unwrap();
    }

    #[test]
    fn payload_bitflip_is_detected() {
        let cfg = config(vec![watch_all(addr(1), 0)]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        ix.append_block(7, [0xbb; 32], vec![log(7, 0, addr(1), vec![topic(1)])]).unwrap();
        let good = ix.serialize(&tag());
        // Flip one bit inside every payload byte (past the checksum field):
        // the checksum must reject each one.
        for i in V2_CHECKSUM_AT + 8..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(LogIndex::deserialize(&cfg, &tag(), &bad).is_none(), "bitflip at {i} accepted");
            assert!(LogIndex::deserialize_portable(&bad).is_none(), "portable bitflip at {i} accepted");
        }
    }

    #[test]
    fn first_append_seeds_the_backfill_cursor() {
        let mut ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        assert_eq!(ix.cursor, None);
        ix.append_block(500, [5; 32], vec![]).unwrap();
        assert_eq!(ix.cursor, Some((500, [5; 32])));
        // Later appends leave the walk edge alone; backfill moves it down.
        ix.append_block(501, [6; 32], vec![]).unwrap();
        assert_eq!(ix.cursor, Some((500, [5; 32])));
        ix.backfill_block(499, [4; 32], vec![]).unwrap();
        assert_eq!(ix.cursor, Some((499, [4; 32])));
    }

    #[test]
    fn fingerprint_is_order_insensitive_but_content_sensitive() {
        let a = watch_all(addr(1), 5);
        let b = WatchEntry { address: addr(2), from_block: 9, topic0s: vec![topic(3), topic(4)], name: String::new() };
        let mut b_rev = b.clone();
        b_rev.topic0s.reverse();
        let c1 = config(vec![a.clone(), b.clone()]);
        let c2 = config(vec![b_rev, a.clone()]);
        assert_eq!(c1.fingerprint(), c2.fingerprint());
        let c3 = config(vec![a, WatchEntry { address: addr(2), from_block: 10, topic0s: vec![topic(3), topic(4)], name: String::new() }]);
        assert_ne!(c1.fingerprint(), c3.fingerprint());
    }

    #[test]
    fn names_are_fingerprint_neutral_and_never_cost_a_reindex() {
        let unnamed = config(vec![watch_all(addr(1), 100)]);
        let mut named_entry = watch_all(addr(1), 100);
        named_entry.name = "tornado.registry.eth".to_string();
        let named = config(vec![named_entry]);
        assert_eq!(unnamed.fingerprint(), named.fingerprint());
        // A file written unnamed loads under a renamed config (and the
        // config's name wins — the host is authoritative for cosmetics).
        let mut ix = LogIndex::new(unnamed).unwrap();
        ix.append_block(200, [0xbb; 32], vec![]).unwrap();
        let back = LogIndex::deserialize(&named, &tag(), &ix.serialize(&tag())).unwrap();
        assert_eq!(back.config().watch[0].name, "tornado.registry.eth");
        assert_eq!(back.coverage_of(&addr(1)).unwrap().span, Some((200, 200)));
    }

    #[test]
    fn portable_roundtrip_reconstructs_config_from_the_bytes() {
        let mut w1 = watch_all(addr(1), 100);
        w1.name = "tornado.registry.eth".to_string();
        let w2 = WatchEntry { address: addr(2), from_block: 50, topic0s: vec![topic(7)], name: String::new() };
        let mut ix = LogIndex::new(config(vec![w1.clone(), w2.clone()])).unwrap();
        ix.append_block(200, [0xbb; 32], vec![log(200, 0, addr(1), vec![topic(7)])]).unwrap();
        ix.backfill_block(199, [9; 32], vec![]).unwrap();

        let (got_tag, back) = LogIndex::deserialize_portable(&ix.serialize(&tag())).expect("portable");
        assert_eq!(got_tag, tag());
        // The watch-list — names included — comes from the FILE, no config
        // supplied. Runtime bits are the receiving host's decision.
        assert_eq!(back.config().watch, vec![w1, w2]);
        assert!(!back.config().enabled);
        assert!(!back.config().max_speed);
        // Coverage, cursor, and logs all survive.
        assert_eq!(back.coverage_of(&addr(1)).unwrap().span, Some((199, 200)));
        assert_eq!(back.cursor, Some((199, [9; 32])));
        assert_eq!(back.log_count(), 1);
    }

    #[test]
    fn v1_files_are_not_portable() {
        let ix = LogIndex::new(config_ok(vec![watch_all(addr(1), 0)])).unwrap();
        let mut v1 = ix.serialize(&tag());
        v1[4..8].copy_from_slice(&1u32.to_le_bytes());
        // (Bogus v1 framing after the version field — the point is only that
        // the version gate itself refuses before parsing anything.)
        assert!(LogIndex::deserialize_portable(&v1).is_none());
    }

    /// Serialize `ix` in the LEGACY v1 layout (what pre-v2 builds wrote):
    /// magic, version 1, fingerprint, checksum over the rest, coverage,
    /// cursor, logs — no chain tag, no watch-table.
    fn serialize_v1(ix: &LogIndex) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_u32(&mut out, VERSION_LEGACY);
        put_u64(&mut out, ix.config().fingerprint());
        put_u64(&mut out, 0); // checksum placeholder
        put_u32(&mut out, ix.coverage.len() as u32);
        for c in &ix.coverage {
            match c.span {
                None => out.push(0),
                Some((low, high)) => {
                    out.push(1);
                    put_u64(&mut out, low);
                    put_u64(&mut out, high);
                }
            }
        }
        match ix.cursor {
            None => out.push(0),
            Some((n, h)) => {
                out.push(1);
                put_u64(&mut out, n);
                out.extend_from_slice(&h);
            }
        }
        put_u64(&mut out, ix.logs.len() as u64);
        for log in ix.logs.values() {
            put_u64(&mut out, log.block_number);
            out.extend_from_slice(&log.block_hash);
            out.extend_from_slice(&log.tx_hash);
            put_u32(&mut out, log.tx_index);
            put_u32(&mut out, log.log_index);
            out.extend_from_slice(&log.address);
            put_u32(&mut out, log.topics.len() as u32);
            for t in &log.topics {
                out.extend_from_slice(t);
            }
            put_bytes(&mut out, &log.data);
        }
        let sum = fnv64(&out[V1_CHECKSUM_AT + 8..]);
        out[V1_CHECKSUM_AT..V1_CHECKSUM_AT + 8].copy_from_slice(&sum.to_le_bytes());
        out
    }

    #[test]
    fn legacy_v1_files_still_load_preserving_coverage() {
        // The upgrade path: a file written by a pre-v2 build must load (months
        // of phone backfill must not re-index just because the code updated).
        let cfg = config(vec![watch_all(addr(1), 100)]);
        let mut ix = LogIndex::new(cfg.clone()).unwrap();
        ix.append_block(200, [0xbb; 32], vec![log(200, 0, addr(1), vec![topic(7)])]).unwrap();
        ix.backfill_block(199, [9; 32], vec![]).unwrap();
        let v1 = serialize_v1(&ix);
        let back = LogIndex::deserialize(&cfg, &tag(), &v1).expect("v1 upgrade load");
        assert_eq!(back.coverage_of(&addr(1)).unwrap().span, Some((199, 200)));
        assert_eq!(back.cursor, Some((199, [9; 32])));
        assert_eq!(back.log_count(), 1);
        // Same guards as ever: wrong fingerprint or truncation → None.
        assert!(LogIndex::deserialize(&config(vec![watch_all(addr(1), 101)]), &tag(), &v1).is_none());
        assert!(LogIndex::deserialize(&cfg, &tag(), &v1[..v1.len() - 1]).is_none());
    }

    #[test]
    fn set_name_fills_only_unnamed_entries() {
        let mut named = watch_all(addr(1), 0);
        named.name = "baked.eth".to_string();
        let mut ix = LogIndex::new(config(vec![named, watch_all(addr(2), 0)])).unwrap();
        // A baked-in name outranks a late lookup; empty names never install.
        assert!(!ix.set_name(&addr(1), "late.eth"));
        assert_eq!(ix.config().watch[0].name, "baked.eth");
        assert!(!ix.set_name(&addr(2), ""));
        assert!(ix.set_name(&addr(2), "resolved.eth"));
        assert_eq!(ix.config().watch[1].name, "resolved.eth");
        // Unknown address: no-op.
        assert!(!ix.set_name(&addr(9), "nobody.eth"));
    }

    #[test]
    fn union_with_extends_stored_and_keeps_pushed_bits() {
        // The additive re-apply: a preset push must extend an imported
        // subscription, never replace it.
        let mut stored_extra = watch_all(addr(2), 300);
        stored_extra.name = "imported.eth".to_string();
        let stored = vec![watch_all(addr(1), 200), stored_extra.clone()];
        let pushed = LogIndexConfig {
            enabled: true,
            max_speed: true,
            watch: vec![{
                let mut w = watch_all(addr(1), 100); // lower from_block
                w.name = "preset name".to_string();
                w
            }],
        };
        let eff = pushed.union_with(&stored).unwrap();
        assert!(eff.enabled && eff.max_speed);
        assert_eq!(eff.watch.len(), 2);
        assert_eq!(eff.watch[0].from_block, 100); // min wins
        assert_eq!(eff.watch[0].name, "preset name"); // push is authoritative
        assert_eq!(eff.watch[1], stored_extra); // imported entry survives
        // Topic conflict → None (caller replaces instead).
        let restricted = vec![WatchEntry { address: addr(1), from_block: 100, topic0s: vec![topic(7)], name: String::new() }];
        assert!(pushed.union_with(&restricted).is_none());
    }

    #[test]
    fn adopt_config_keeps_state_only_for_the_same_subscription_set() {
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 200), watch_all(addr(2), 200)])).unwrap();
        ix.append_block(500, [5; 32], vec![log(500, 0, addr(1), vec![])]).unwrap();
        // Reordered + renamed + lowered from_block + flipped bits: adoptable,
        // and coverage re-pairs by address.
        let mut renamed = watch_all(addr(2), 150);
        renamed.name = "renamed.eth".to_string();
        let eff = LogIndexConfig { enabled: true, max_speed: true, watch: vec![renamed, watch_all(addr(1), 200)] };
        assert!(ix.adopt_config(eff));
        assert!(ix.config().enabled && ix.config().max_speed);
        assert_eq!(ix.config().watch[0].from_block, 150);
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((500, 500)));
        assert_eq!(ix.log_count(), 1);
        // A new address is NOT adoptable (needs a re-index), and the failed
        // attempt leaves everything untouched.
        let wider = config(vec![watch_all(addr(1), 200), watch_all(addr(2), 150), watch_all(addr(3), 0)]);
        assert!(!ix.adopt_config(wider));
        assert_eq!(ix.config().watch.len(), 2);
        // A changed topic set is NOT adoptable either.
        let retopiced = config(vec![
            WatchEntry { address: addr(1), from_block: 200, topic0s: vec![topic(9)], name: String::new() },
            watch_all(addr(2), 150),
        ]);
        assert!(!ix.adopt_config(retopiced));
    }

    /// Drive the (simulated) appender + walker over `ix` to completion,
    /// panicking if either wedges: one append at the edge (which also
    /// re-seeds a dropped cursor — exactly what the real appender does),
    /// then the walker's descent to the lowest from_block. Hashes are
    /// synthetic — the coverage state machine is what's under test. Ends by
    /// asserting every entry is COMPLETE (low <= from_block): the branch's
    /// promise that catch-up finishes every imported address.
    fn assert_catch_up_completes(ix: &mut LogIndex) {
        let top = ix.append_edge().unwrap_or(10_000);
        ix.append_block(top, [1; 32], vec![])
            .unwrap_or_else(|g| panic!("appender wedged at {top}: {g:?}"));
        let target = ix.config().watch.iter().map(|w| w.from_block).min().expect("entries");
        let mut steps = 0u32;
        while let Some((n, _)) = ix.cursor {
            if n <= target {
                break;
            }
            let b = n - 1;
            ix.backfill_block(b, [2; 32], vec![])
                .unwrap_or_else(|g| panic!("walker wedged at {b}: {g:?}"));
            steps += 1;
            assert!(steps < 100_000, "walk did not terminate");
        }
        for (w, c) in ix.coverage_entries() {
            let (low, _) = c.span.unwrap_or_else(|| {
                panic!("entry 0x{:02x}.. never covered", w.address[0])
            });
            assert!(low <= w.from_block, "entry incomplete: low {low} > from {}", w.from_block);
        }
    }

    /// Build a canonical index over `cfg` covering `low..=high` (appender
    /// seed at the top, walker descent to the bottom — cursor ends at `low`),
    /// with `logs` inserted at their blocks along the way.
    fn span_ix(cfg: LogIndexConfig, low: u64, high: u64, logs: Vec<StoredLog>) -> LogIndex {
        let mut ix = LogIndex::new(cfg).unwrap();
        let at = |b: u64| logs.iter().filter(|l| l.block_number == b).cloned().collect::<Vec<_>>();
        ix.append_block(high, [high as u8; 32], at(high)).unwrap();
        for b in (low..high).rev() {
            ix.backfill_block(b, [b as u8; 32], at(b)).unwrap();
        }
        ix
    }

    #[test]
    fn merge_unions_addresses_and_clamps_to_the_min_high() {
        // A: tornado history, generated earlier (high 300). B: railgun,
        // generated later (high 500). The union must not claim (300, 500]
        // for A's address — that band re-indexes via the bridge.
        let a = span_ix(config(vec![watch_all(addr(1), 100)]), 100, 300, vec![log(200, 0, addr(1), vec![])]);
        let b = span_ix(config(vec![watch_all(addr(2), 400)]), 400, 500, vec![log(450, 0, addr(2), vec![])]);
        let (t, m) = LogIndex::merge(vec![(tag(), a), (tag(), b)]).unwrap();
        assert_eq!(t, tag());
        assert_eq!(m.coverage_of(&addr(1)).unwrap().span, Some((100, 300)));
        // B's span lies entirely above H=300 → dormant, its log dropped
        // (unreachable by the coverage-honest query anyway).
        assert_eq!(m.coverage_of(&addr(2)).unwrap().span, None);
        assert_eq!(m.log_count(), 1);
        // Config is the union; runtime bits are the installer's.
        assert_eq!(m.config().watch.len(), 2);
        assert!(!m.config().enabled);
        // Cursor: the deepest trust edge.
        assert_eq!(m.cursor, Some((100, [100; 32])));
    }

    #[test]
    fn merge_same_address_unions_overlapping_spans() {
        let a = span_ix(config(vec![watch_all(addr(1), 50)]), 50, 200, vec![log(60, 0, addr(1), vec![])]);
        let b = span_ix(config(vec![watch_all(addr(1), 50)]), 150, 260, vec![log(250, 0, addr(1), vec![])]);
        let (_, mut m) = LogIndex::merge(vec![(tag(), a), (tag(), b)]).unwrap();
        // H = min(200, 260) = 200; spans [50,200] ∪ [150,200] = [50,200].
        assert_eq!(m.coverage_of(&addr(1)).unwrap().span, Some((50, 200)));
        // B's log at 250 is above the merged span → dropped; A's at 60 kept.
        assert_eq!(m.log_count(), 1);
        m.set_enabled(true); // the installer's decision, made here for the query
        assert_eq!(m.query(&filter(50, 200, addr(1))).unwrap().len(), 1);
    }

    #[test]
    fn merge_same_address_disjoint_spans_keep_the_lower() {
        // A reaches only [50,120]; B covers [300,400]. H = 120 makes B's
        // piece vanish — the deployment-anchored lower history survives and
        // catch-up re-indexes upward from 120.
        let a = span_ix(config(vec![watch_all(addr(1), 50)]), 50, 120, vec![log(70, 0, addr(1), vec![])]);
        let b = span_ix(config(vec![watch_all(addr(1), 50)]), 300, 400, vec![log(350, 0, addr(1), vec![])]);
        let (_, mut m) = LogIndex::merge(vec![(tag(), a), (tag(), b)]).unwrap();
        assert_eq!(m.coverage_of(&addr(1)).unwrap().span, Some((50, 120)));
        assert_eq!(m.log_count(), 1);
        m.set_enabled(true); // the installer's decision, made here for the query
        assert!(matches!(m.query(&filter(300, 400, addr(1))), Err(QueryError::OutOfCoverage { .. })));
    }

    #[test]
    fn merge_refuses_other_chains_and_topic_conflicts() {
        let a = span_ix(config(vec![watch_all(addr(1), 50)]), 50, 100, vec![]);
        let b = span_ix(config(vec![watch_all(addr(2), 50)]), 50, 100, vec![]);
        let sepolia = ChainTag { network_id: 11_155_111, genesis_hash: [0x25; 32] };
        assert!(matches!(
            LogIndex::merge(vec![(tag(), a), (sepolia, b)]),
            Err(MergeError::ChainMismatch { .. })
        ));
        assert!(matches!(LogIndex::merge(vec![]), Err(MergeError::Empty)));
        // Same address under different topic restrictions: a span's meaning
        // includes what it indexed — refuse, never widen.
        let all = span_ix(config(vec![watch_all(addr(1), 50)]), 50, 100, vec![]);
        let restricted = span_ix(
            config(vec![WatchEntry { address: addr(1), from_block: 50, topic0s: vec![topic(7)], name: String::new() }]),
            50,
            100,
            vec![],
        );
        assert!(matches!(
            LogIndex::merge(vec![(tag(), all), (tag(), restricted)]),
            Err(MergeError::TopicConflict(a)) if a == addr(1)
        ));
    }

    #[test]
    fn merge_takes_min_from_block_and_first_nonempty_name() {
        let mut named = watch_all(addr(1), 200);
        named.name = "tornado.registry.eth".to_string();
        let a = span_ix(config(vec![watch_all(addr(1), 400)]), 400, 500, vec![]);
        let b = span_ix(config(vec![named]), 400, 500, vec![]);
        let (_, m) = LogIndex::merge(vec![(tag(), a), (tag(), b)]).unwrap();
        let w = &m.config().watch[0];
        assert_eq!(w.from_block, 200);
        assert_eq!(w.name, "tornado.registry.eth");
    }

    #[test]
    fn merge_prunes_a_stale_source_instead_of_rewinding_the_fresh_one() {
        // Re-importing an old file whose coverage is a subset must NOT drag
        // the merged high back to the old file's high.
        let fresh = span_ix(config(vec![watch_all(addr(1), 100)]), 100, 500, vec![log(450, 0, addr(1), vec![])]);
        let stale = span_ix(config(vec![watch_all(addr(1), 100)]), 100, 300, vec![]);
        let (_, m) = LogIndex::merge(vec![(tag(), stale), (tag(), fresh)]).unwrap();
        assert_eq!(m.coverage_of(&addr(1)).unwrap().span, Some((100, 500)));
        assert_eq!(m.log_count(), 1);
    }

    #[test]
    fn merge_into_a_mid_backfill_index_resumes_and_completes() {
        // The flagship import case that once wedged: own index mid-backfill
        // (X from 20, covered [1000,1100], cursor at 1000) + a deep imported
        // snapshot (Y from 50, covered [50,1100], cursor at 50). The naive
        // "deepest cursor" (50) leaves X's hole [20,1000) ABOVE the walk —
        // backfill_block gap-errors every tick, forever. The resumable
        // choice is the cursor at the MAX incomplete low (X's 1000): the
        // walk re-descends through Y's covered span and closes both holes.
        let own = span_ix(config(vec![watch_all(addr(1), 20)]), 1000, 1100, vec![]);
        let imported = span_ix(config(vec![watch_all(addr(2), 50)]), 50, 1100, vec![]);
        let (_, mut m) = LogIndex::merge(vec![(tag(), own), (tag(), imported)]).unwrap();
        assert_eq!(m.cursor.map(|(n, _)| n), Some(1000), "must resume at the max incomplete low");
        assert_catch_up_completes(&mut m);
    }

    #[test]
    fn merge_with_a_config_only_source_drops_the_cursor_and_completes() {
        // A config-only source (new address, no coverage — the preset-grew
        // case): its whole range sits above any source cursor, so NO cursor
        // is resumable; the merge must drop it (appender re-seeds at the
        // top, walker re-descends) rather than strand the new entry.
        let covered = span_ix(config(vec![watch_all(addr(1), 50)]), 50, 300, vec![]);
        let config_only = LogIndex::new(config(vec![watch_all(addr(2), 100)])).unwrap();
        let (_, mut m) = LogIndex::merge(vec![(tag(), config_only), (tag(), covered)]).unwrap();
        assert_eq!(m.cursor, None, "no cursor can reach the new entry's hole");
        // Coverage survived the union.
        assert_eq!(m.coverage_of(&addr(1)).unwrap().span, Some((50, 300)));
        assert_catch_up_completes(&mut m);
    }

    #[test]
    fn adopt_lowering_from_block_below_a_complete_span_drops_the_cursor() {
        // Regression: pre-import builds re-indexed on any from_block change;
        // the additive path must not instead wedge. Two entries, walk at
        // 150: X1 (from 200) is COMPLETE at low 200, X2 (from 100) is
        // mid-descent at the cursor. Lowering X1's from_block to 50 opens
        // the hole [50,200) ABOVE the cursor — unreachable by the descent —
        // so the adopt keeps all coverage but drops the cursor and the walk
        // re-descends.
        let mut ix = span_ix(
            config(vec![watch_all(addr(1), 200), watch_all(addr(2), 100)]),
            150,
            300,
            vec![],
        );
        assert_eq!(ix.cursor.map(|(n, _)| n), Some(150));
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((200, 300)));
        let lowered = config(vec![watch_all(addr(1), 50), watch_all(addr(2), 100)]);
        assert!(ix.adopt_config(lowered));
        assert_eq!(ix.cursor, None, "X1's hole [50,200) sits above the old cursor");
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((200, 300)), "coverage kept");
        assert_catch_up_completes(&mut ix);
        // Mid-descent lowering (span low == cursor) keeps the cursor: the
        // walk just runs deeper.
        let mut mid = span_ix(config(vec![watch_all(addr(3), 150)]), 200, 300, vec![]);
        assert!(mid.adopt_config(config(vec![watch_all(addr(3), 100)])));
        assert_eq!(mid.cursor.map(|(n, _)| n), Some(200));
        assert_catch_up_completes(&mut mid);
    }

    #[test]
    fn merge_output_is_canonical_and_never_fabricates_coverage() {
        // Pseudo-random source shapes (fixed LCG seed — deterministic): the
        // merged result must (a) never claim a block for an address that no
        // source covered for that address, and (b) stay canonical: all
        // present spans share one high, the cursor sits at/below every low.
        let mut state: u64 = 0x5eed;
        let mut rng = move |bound: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % bound
        };
        for _ in 0..50 {
            let n_sources = 1 + rng(3);
            let mut sources = Vec::new();
            for _ in 0..n_sources {
                let n_watch = 1 + rng(3) as u8;
                let entries: Vec<WatchEntry> = (1..=n_watch).map(|k| watch_all(addr(k), 10)).collect();
                let low = 10 + rng(50);
                let high = low + rng(60);
                sources.push(span_ix(config(entries), low, high, vec![]));
            }
            let originals: Vec<LogIndex> = sources
                .iter()
                .map(|s| {
                    let cfg = s.config().clone();
                    let mut c = LogIndex::new(cfg).unwrap();
                    c.coverage = s.coverage.clone();
                    c
                })
                .collect();
            let (_, mut m) = LogIndex::merge(sources.into_iter().map(|s| (tag(), s)).collect()).unwrap();
            let highs: Vec<u64> =
                m.coverage_entries().iter().filter_map(|(_, c)| c.span.map(|(_, h)| h)).collect();
            assert!(highs.windows(2).all(|w| w[0] == w[1]), "unequal highs: {highs:?}");
            // The RESUMABILITY invariant — the walker demands every
            // incomplete low at/below the cursor (asserting the inverted
            // "cursor at/below every low" here is exactly the bug this
            // branch once had).
            let (watch, coverage): (Vec<_>, Vec<_>) = m.coverage_entries().into_iter().unzip();
            assert!(walk_resumable(&watch, &coverage, m.cursor), "merge emitted a non-resumable state");
            for (w, c) in m.coverage_entries() {
                if let Some((low, high)) = c.span {
                    for b in low..=high {
                        let covered_somewhere = originals.iter().any(|s| {
                            s.coverage_of(&w.address).is_some_and(|sc| sc.contains(b, b))
                        });
                        assert!(covered_somewhere, "merged claims block {b} for an address no source covered");
                    }
                }
            }
            // And the invariant is not just declared — the pipeline actually
            // runs to completion from the merged state.
            assert_catch_up_completes(&mut m);
        }
    }

    #[test]
    fn reordered_config_pairs_coverage_by_address() {
        // The fingerprint is order-insensitive, so a host may re-apply the
        // same watch-set in a different order. v2 stores the watch-table and
        // re-pairs coverage by ADDRESS — entry order must not migrate a span
        // to the wrong contract.
        let w1 = watch_all(addr(1), 100);
        let w2 = watch_all(addr(2), 300);
        let mut ix = LogIndex::new(config(vec![w1.clone(), w2.clone()])).unwrap();
        // Blocks 200..=210: only addr(1)'s entry is live (addr(2) starts at 300).
        for b in 200..=210 {
            ix.append_block(b, [0xbb; 32], vec![]).unwrap();
        }
        let bytes = ix.serialize(&tag());
        let reordered = config(vec![w2, w1]);
        assert_eq!(reordered.fingerprint(), ix.config().fingerprint());
        let back = LogIndex::deserialize(&reordered, &tag(), &bytes).unwrap();
        assert_eq!(back.coverage_of(&addr(1)).unwrap().span, Some((200, 210)));
        assert_eq!(back.coverage_of(&addr(2)).unwrap().span, None);
    }
}

#[cfg(test)]
mod bloom_match_tests {
    use super::*;
    use myotis_core::bloom::{accrue, EMPTY_BLOOM};

    #[test]
    fn bloom_prefilter_respects_from_block_and_topics() {
        fn addr(b: u8) -> [u8; 20] {
            [b; 20]
        }
        let watch = WatchEntry { address: addr(1), from_block: 100, topic0s: vec![[7; 32]], name: String::new() };
        let ix = LogIndex::new(LogIndexConfig { enabled: true, max_speed: false, watch: vec![watch] }).unwrap();
        let mut hit = EMPTY_BLOOM;
        accrue(&mut hit, &addr(1));
        accrue(&mut hit, &[7u8; 32]);
        assert!(ix.bloom_may_match(100, &hit));
        assert!(!ix.bloom_may_match(99, &hit)); // below from_block
        let mut addr_only = EMPTY_BLOOM;
        accrue(&mut addr_only, &addr(1));
        assert!(!ix.bloom_may_match(100, &addr_only)); // topic0-restricted entry needs a topic hit
        assert!(!ix.bloom_may_match(100, &EMPTY_BLOOM));
    }
}
