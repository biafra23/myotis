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
}

/// The host-supplied index configuration (crosses the FFI as JSON, parsed
/// engine-side into this typed form).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogIndexConfig {
    pub enabled: bool,
    pub watch: Vec<WatchEntry>,
}

impl LogIndexConfig {
    /// Order-insensitive fingerprint of the watch-list. A changed fingerprint
    /// on load invalidates the persisted index (derived data — re-index
    /// rather than risk serving under a stale subscription set).
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

    fn extend_up(&mut self, block: u64) {
        self.span = Some(match self.span {
            None => (block, block),
            Some((low, high)) => (low, high.max(block)),
        });
    }

    fn extend_down(&mut self, block: u64) {
        self.span = Some(match self.span {
            None => (block, block),
            Some((low, high)) => (low.min(block), high),
        });
    }
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
    pub fn new(config: LogIndexConfig) -> Self {
        let n = config.watch.len();
        Self { config, coverage: vec![Coverage::default(); n], logs: BTreeMap::new(), cursor: None }
    }

    pub fn config(&self) -> &LogIndexConfig {
        &self.config
    }

    pub fn coverage_of(&self, address: &[u8; 20]) -> Option<Coverage> {
        self.config
            .watch
            .iter()
            .position(|w| &w.address == address)
            .map(|i| self.coverage[i])
    }

    fn watched(&self, log: &StoredLog) -> bool {
        self.config.watch.iter().any(|w| {
            w.address == log.address
                && log.block_number >= w.from_block
                && (w.topic0s.is_empty()
                    || log.topics.first().is_some_and(|t| w.topic0s.contains(t)))
        })
    }

    /// Record a fully processed block at or above the current high edge (the
    /// head-follow path). `logs` may be empty — coverage still advances,
    /// which is what makes "no events in this range" a servable answer.
    pub fn append_block(&mut self, block_number: u64, logs: Vec<StoredLog>) {
        for log in logs {
            debug_assert_eq!(log.block_number, block_number);
            if self.watched(&log) {
                self.logs.insert((log.block_number, log.log_index), log);
            }
        }
        for (i, w) in self.config.watch.iter().enumerate() {
            if block_number >= w.from_block {
                self.coverage[i].extend_up(block_number);
            }
        }
    }

    /// Record a fully processed block below the current low edge (the
    /// backfill walk). Caller supplies the verified (number, hash) so the
    /// cursor tracks the trust edge.
    pub fn backfill_block(&mut self, block_number: u64, block_hash: [u8; 32], logs: Vec<StoredLog>) {
        for log in logs {
            debug_assert_eq!(log.block_number, block_number);
            if self.watched(&log) {
                self.logs.insert((log.block_number, log.log_index), log);
            }
        }
        for (i, w) in self.config.watch.iter().enumerate() {
            if block_number >= w.from_block {
                self.coverage[i].extend_down(block_number);
            }
        }
        self.cursor = Some((block_number, block_hash));
    }

    /// Drop everything above `fork_point` (exclusive) after a reorg above
    /// finalized. Coverage highs pull back; logs of orphaned blocks go away.
    pub fn rewind_above(&mut self, fork_point: u64) {
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
            let Some(i) = self.config.watch.iter().position(|w| &w.address == addr) else {
                return Err(QueryError::UnwatchedAddress(*addr));
            };
            let w = &self.config.watch[i];
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
            if need_from <= filter.to_block && !self.coverage[i].contains(need_from, filter.to_block) {
                return Err(QueryError::OutOfCoverage { address: *addr, covered: self.coverage[i] });
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
}

// ---------------------------------------------------------------------------
// Persistence: a versioned framed blob, written atomically (temp + rename,
// the sync-state snapshot pattern). The index is derived data: any load
// problem — bad magic, unknown version, truncation, fingerprint mismatch —
// yields None and the caller re-indexes. Never correctness-critical.
// ---------------------------------------------------------------------------

const MAGIC: &[u8; 4] = b"MLIX";
const VERSION: u32 = 1;

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
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
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
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.logs.len() * 200);
        out.extend_from_slice(MAGIC);
        put_u32(&mut out, VERSION);
        put_u64(&mut out, self.config.fingerprint());
        // Coverage spans + cursor.
        put_u32(&mut out, self.coverage.len() as u32);
        for c in &self.coverage {
            match c.span {
                None => out.push(0),
                Some((low, high)) => {
                    out.push(1);
                    put_u64(&mut out, low);
                    put_u64(&mut out, high);
                }
            }
        }
        match self.cursor {
            None => out.push(0),
            Some((n, h)) => {
                out.push(1);
                put_u64(&mut out, n);
                out.extend_from_slice(&h);
            }
        }
        // Logs.
        put_u64(&mut out, self.logs.len() as u64);
        for log in self.logs.values() {
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
        out
    }

    /// Rebuild from bytes for the given config. Any mismatch or corruption
    /// → None (re-index).
    pub fn deserialize(config: &LogIndexConfig, data: &[u8]) -> Option<Self> {
        let mut c = Cursor { d: data, pos: 0 };
        if c.take(4)? != MAGIC || c.u32()? != VERSION || c.u64()? != config.fingerprint() {
            return None;
        }
        let n_cov = c.u32()? as usize;
        if n_cov != config.watch.len() {
            return None;
        }
        let mut coverage = Vec::with_capacity(n_cov);
        for _ in 0..n_cov {
            coverage.push(match c.take(1)?[0] {
                0 => Coverage::default(),
                1 => Coverage { span: Some((c.u64()?, c.u64()?)) },
                _ => return None,
            });
        }
        let cursor = match c.take(1)?[0] {
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
        if c.pos != data.len() {
            return None; // trailing garbage → treat as corrupt
        }
        Some(Self { config: config.clone(), coverage, logs, cursor })
    }

    /// Atomic best-effort persist: temp file (pid-suffixed) + rename, the
    /// `persist_snapshot` pattern. A failed write costs a re-index on the
    /// affected range, never correctness.
    pub fn persist(&self, path: &Path) -> std::io::Result<()> {
        let tmp: PathBuf = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&self.serialize())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Load a persisted index for `config`; None on absence or any mismatch.
    pub fn load(config: &LogIndexConfig, path: &Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        Self::deserialize(config, &data)
    }
}

#[cfg(test)]
mod tests {
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
        WatchEntry { address: a, from_block: from, topic0s: vec![] }
    }

    fn config(entries: Vec<WatchEntry>) -> LogIndexConfig {
        LogIndexConfig { enabled: true, watch: entries }
    }

    fn filter(from: u64, to: u64, a: [u8; 20]) -> LogFilter {
        LogFilter { from_block: from, to_block: to, addresses: vec![a], topics: vec![] }
    }

    #[test]
    fn query_outside_coverage_errors_never_empty() {
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 100)]));
        ix.append_block(200, vec![]);
        ix.append_block(201, vec![log(201, 0, addr(1), vec![topic(9)])]);
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
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 500)]));
        ix.append_block(500, vec![]);
        // 100..=500 is fine: below from_block the contract can't have logs.
        assert_eq!(ix.query(&filter(100, 500, addr(1))).unwrap(), vec![]);
        // Entirely below from_block: nothing to cover, empty is honest.
        assert_eq!(ix.query(&filter(100, 400, addr(1))).unwrap(), vec![]);
    }

    #[test]
    fn unwatched_address_and_disabled_error() {
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 0)]));
        ix.append_block(10, vec![]);
        assert_eq!(ix.query(&filter(0, 10, addr(2))), Err(QueryError::UnwatchedAddress(addr(2))));
        let off = LogIndex::new(LogIndexConfig { enabled: false, watch: vec![watch_all(addr(1), 0)] });
        assert_eq!(off.query(&filter(0, 0, addr(1))), Err(QueryError::Disabled));
        assert_eq!(ix.query(&LogFilter { from_block: 0, to_block: 10, addresses: vec![], topics: vec![] }), Err(QueryError::Unanswerable));
    }

    #[test]
    fn topic_restricted_watch_rejects_wildcard_queries() {
        let w = WatchEntry { address: addr(1), from_block: 0, topic0s: vec![topic(7)] };
        let mut ix = LogIndex::new(config(vec![w]));
        ix.append_block(5, vec![log(5, 0, addr(1), vec![topic(7)])]);
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
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 0)]));
        ix.append_block(1, vec![log(1, 0, addr(1), vec![topic(7), topic(8)])]);
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
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 100)]));
        ix.append_block(300, vec![]);
        ix.backfill_block(299, [9; 32], vec![log(299, 2, addr(1), vec![])]);
        ix.backfill_block(298, [8; 32], vec![]);
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((298, 300)));
        assert_eq!(ix.cursor, Some((298, [8; 32])));
        assert_eq!(ix.query(&filter(298, 300, addr(1))).unwrap().len(), 1);
    }

    #[test]
    fn rewind_above_drops_logs_and_pulls_coverage_back() {
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 0)]));
        for b in 10..=14 {
            ix.append_block(b, vec![log(b, 0, addr(1), vec![])]);
        }
        ix.rewind_above(12);
        assert_eq!(ix.coverage_of(&addr(1)).unwrap().span, Some((10, 12)));
        assert_eq!(ix.log_count(), 3);
        // Above the fork point is out of coverage again.
        assert!(matches!(ix.query(&filter(10, 14, addr(1))), Err(QueryError::OutOfCoverage { .. })));
    }

    #[test]
    fn unwatched_logs_are_not_stored() {
        let mut ix = LogIndex::new(config(vec![watch_all(addr(1), 100)]));
        // Wrong address, and right address but below from_block: both dropped.
        ix.append_block(200, vec![log(200, 0, addr(2), vec![])]);
        ix.backfill_block(99, [1; 32], vec![log(99, 0, addr(1), vec![])]);
        assert_eq!(ix.log_count(), 0);
    }

    #[test]
    fn persist_load_roundtrip_and_invalidation() {
        let dir = std::env::temp_dir().join(format!("logindex-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("logindex-test.db");
        let cfg = config(vec![watch_all(addr(1), 100), WatchEntry { address: addr(2), from_block: 0, topic0s: vec![topic(7)] }]);
        let mut ix = LogIndex::new(cfg.clone());
        ix.append_block(200, vec![log(200, 3, addr(1), vec![topic(7), topic(8)])]);
        ix.backfill_block(199, [7; 32], vec![]);
        ix.persist(&path).unwrap();

        let back = LogIndex::load(&cfg, &path).expect("roundtrip");
        assert_eq!(back.coverage_of(&addr(1)).unwrap().span, Some((199, 200)));
        assert_eq!(back.cursor, Some((199, [7; 32])));
        assert_eq!(back.query(&filter(199, 200, addr(1))).unwrap(), ix.query(&filter(199, 200, addr(1))).unwrap());

        // Changed watch-list → fingerprint mismatch → None (re-index).
        let changed = config(vec![watch_all(addr(1), 101)]);
        assert!(LogIndex::load(&changed, &path).is_none());
        // Truncated file → None.
        let data = std::fs::read(&path).unwrap();
        std::fs::write(&path, &data[..data.len() - 1]).unwrap();
        assert!(LogIndex::load(&cfg, &path).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_is_order_insensitive_but_content_sensitive() {
        let a = watch_all(addr(1), 5);
        let b = WatchEntry { address: addr(2), from_block: 9, topic0s: vec![topic(3), topic(4)] };
        let mut b_rev = b.clone();
        b_rev.topic0s.reverse();
        let c1 = config(vec![a.clone(), b.clone()]);
        let c2 = config(vec![b_rev, a.clone()]);
        assert_eq!(c1.fingerprint(), c2.fingerprint());
        let c3 = config(vec![a, WatchEntry { address: addr(2), from_block: 10, topic0s: vec![topic(3), topic(4)] }]);
        assert_ne!(c1.fingerprint(), c3.fingerprint());
    }
}
