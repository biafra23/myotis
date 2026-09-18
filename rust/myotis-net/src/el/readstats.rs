//! Read-fetch statistics — a SHADOW CACHE that caches nothing and instead
//! measures how much of the verified state-read traffic a cache *could* have
//! served, and under which keying.
//!
//! Every verified fetch that actually crossed the network (an account proof, a
//! storage-slot proof, a bytecode blob) is reported here AFTER it verified,
//! with the anchors it verified against. The observer remembers the last
//! verified fact per key (bounded, most-recently-observed wins) and classifies
//! each repeat:
//!
//! * **`sameStateRoot`** — the world state root is unchanged since the previous
//!   fetch of this key, i.e. the read happened within the same block. A
//!   per-root cache (what the EVM path already has, and what the direct
//!   `eth_getStorageAt` / `eth_getBalance` path does NOT consult) would have
//!   served it with zero round-trips.
//! * **`sameStorageRoot`** (storage only) — the contract's storage trie root is
//!   unchanged, so the slot value is provably the same: a cache keyed by
//!   `(storageRoot, slot)` would have served it at the cost of the account
//!   proof alone. This is the SOUND cross-block scheme — the account proof is
//!   the freshness check — and it is what the Java engine's `StateProofCache`
//!   already does while this engine's twin still keys by world root.
//! * **`unchanged` / `sameValue`** — the value itself is identical although the
//!   root moved. No sound cache can exploit this without a proof; it is the
//!   CEILING, reported so "serve a minute-old value" can be judged against
//!   how often such a value would have been right.
//! * **`byAge`** — repeats bucketed by how long ago the key was last fetched,
//!   each with how many were value-unchanged: the direct answer to "if we had
//!   served the value from ≤ N seconds ago, how often would it have been
//!   correct?".
//!
//! Costs are wall-clock milliseconds of the snap round-trip(s) that produced
//! the observation — never the beacon-anchoring ladder that may follow a
//! direct read — so `sameStorageRootFetchMs` is literally the time a
//! storage-root-keyed cache would have saved.
//!
//! Trust posture: this module never returns a value to anyone; it only counts.
//! It is deliberately *not* a cache so the measurement can land — and be
//! judged — before any serving behaviour changes.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use myotis_core::trie::{AccountLeaf, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

/// Distinct addresses whose last verified account is remembered.
const TRACKED_ACCOUNTS: usize = 4096;
/// Distinct `(address, storage key)` pairs remembered.
const TRACKED_SLOTS: usize = 16_384;
/// Distinct code hashes remembered.
const TRACKED_CODES: usize = 4096;
/// A one-line summary goes to the tracing ring this often (while reads flow),
/// so hosts without the JSON surface (Android/iOS log views) still see it.
const SUMMARY_EVERY: Duration = Duration::from_secs(300);

/// Age-bucket upper bounds in seconds; the last bucket is open-ended.
const AGE_BOUNDS_SECS: [u64; 3] = [12, 60, 300];
const AGE_LABELS: [&str; 4] = ["le12s", "le60s", "le5m", "gt5m"];

/// The proof-verified account fields a repeat is compared against. A verified
/// EXCLUSION proof is the empty account (nonce 0, zero balance, empty trie
/// root, empty code hash) — post-EIP-161 an existing account cannot be empty,
/// so no `present` flag is needed to tell the two apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountFact {
    pub nonce: u64,
    /// Left-padded big-endian wei.
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

impl AccountFact {
    /// From a verified leaf, or the empty account for a verified absence.
    pub fn from_leaf(leaf: Option<&AccountLeaf>) -> AccountFact {
        match leaf {
            Some(l) => AccountFact {
                nonce: l.nonce,
                balance: pad32(&l.balance),
                storage_root: l.storage_root,
                code_hash: l.code_hash,
            },
            None => AccountFact::absent(),
        }
    }

    pub fn absent() -> AccountFact {
        AccountFact {
            nonce: 0,
            balance: [0; 32],
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: EMPTY_CODE_HASH,
        }
    }
}

/// Left-pad a minimal big-endian scalar to 32 bytes; a longer input (which a
/// verified leaf cannot carry) pads to zero rather than panicking.
pub fn pad32(minimal_be: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if minimal_be.len() <= 32 {
        out[32 - minimal_be.len()..].copy_from_slice(minimal_be);
    }
    out
}

/// A bounded "last seen" map: every observation re-puts its key, so evicting
/// the oldest PUT is exactly evicting the least-recently-observed key — and a
/// FIFO of puts gives that in O(1), where a scan-to-evict LRU costs O(cap) per
/// fresh key (tens of µs at 16 k entries, on the EVM's blocking thread, once
/// per slot of a prefetch wave). Re-puts leave a stale queue entry behind;
/// entries are tagged with a sequence number so eviction skips stale ones,
/// and the queue is compacted when it grows past twice the capacity.
struct RecentMap<K, V> {
    cap: usize,
    seq: u64,
    map: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
}

impl<K: Hash + Eq + Clone, V> RecentMap<K, V> {
    fn new(cap: usize) -> RecentMap<K, V> {
        RecentMap {
            cap,
            seq: 0,
            map: HashMap::with_capacity(cap.min(1024)),
            order: VecDeque::with_capacity(cap.min(1024)),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(v, _)| v)
    }

    fn put(&mut self, key: K, value: V) {
        if self.cap == 0 {
            return;
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let fresh = self.map.insert(key.clone(), (value, seq)).is_none();
        self.order.push_back((key, seq));
        if fresh {
            while self.map.len() > self.cap {
                match self.order.pop_front() {
                    Some((k, s)) => {
                        // Only the queue entry that matches the key's CURRENT
                        // sequence evicts it; older entries are stale re-puts.
                        if self.map.get(&k).is_some_and(|(_, cur)| *cur == s) {
                            self.map.remove(&k);
                        }
                    }
                    None => break,
                }
            }
        }
        if self.order.len() > self.cap.saturating_mul(2).max(16) {
            let map = &self.map;
            self.order
                .retain(|(k, s)| map.get(k).is_some_and(|(_, cur)| cur == s));
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

struct AccountSeen {
    state_root: [u8; 32],
    fact: AccountFact,
    at: Instant,
}

struct SlotSeen {
    state_root: [u8; 32],
    storage_root: [u8; 32],
    value: [u8; 32],
    at: Instant,
}

#[derive(Clone, Copy, Default)]
struct AgeBucket {
    reads: u64,
    unchanged: u64,
}

#[derive(Clone, Copy, Default)]
struct ByAge([AgeBucket; 4]);

impl ByAge {
    fn record(&mut self, age: Duration, unchanged: bool) {
        let secs = age.as_secs();
        let idx = AGE_BOUNDS_SECS
            .iter()
            .position(|bound| secs <= *bound)
            .unwrap_or(AGE_BOUNDS_SECS.len());
        let b = &mut self.0[idx];
        b.reads += 1;
        if unchanged {
            b.unchanged += 1;
        }
    }

    fn write_json(&self, out: &mut String) {
        out.push('{');
        for (i, (label, b)) in AGE_LABELS.iter().zip(self.0.iter()).enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(label);
            out.push_str("\":{");
            num(out, "reads", b.reads);
            out.push(',');
            num(out, "unchanged", b.unchanged);
            out.push('}');
        }
        out.push('}');
    }
}

#[derive(Clone, Copy, Default)]
struct AccountCounters {
    fetches: u64,
    repeats: u64,
    same_state_root: u64,
    unchanged: u64,
    fetch_ms: u64,
    same_state_root_ms: u64,
    by_age: ByAge,
}

#[derive(Clone, Copy, Default)]
struct StorageCounters {
    fetches: u64,
    repeats: u64,
    same_state_root: u64,
    same_storage_root: u64,
    same_value: u64,
    fetch_ms: u64,
    same_storage_root_ms: u64,
    by_age: ByAge,
}

#[derive(Clone, Copy, Default)]
struct CodeCounters {
    fetches: u64,
    repeats: u64,
    fetch_ms: u64,
    repeat_ms: u64,
}

/// The `Copy` part of the state: taken out under the lock, formatted outside
/// it, so neither the JSON build nor the tracing summary holds up observers.
#[derive(Clone, Copy, Default)]
struct Counters {
    account: AccountCounters,
    storage: StorageCounters,
    code: CodeCounters,
    tracked_accounts: usize,
    tracked_slots: usize,
    tracked_codes: usize,
}

struct Inner {
    counters: Counters,
    accounts: RecentMap<[u8; 20], AccountSeen>,
    slots: RecentMap<([u8; 20], [u8; 32]), SlotSeen>,
    codes: RecentMap<[u8; 32], ()>,
    last_summary: Instant,
}

impl Inner {
    fn snapshot(&self) -> Counters {
        Counters {
            tracked_accounts: self.accounts.len(),
            tracked_slots: self.slots.len(),
            tracked_codes: self.codes.len(),
            ..self.counters
        }
    }

    /// Whether a summary is due; flips the clock so exactly one caller emits.
    fn summary_due(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.last_summary) < SUMMARY_EVERY {
            return false;
        }
        self.last_summary = now;
        true
    }
}

/// The observer. One per chain handle — shared by the
/// [`ElReader`](crate::el::reader::ElReader) and every
/// [`PoolOracle`](crate::el::evm::PoolOracle) it creates, and handed across a
/// pause/resume so the counters outlive the reader.
pub struct ReadStats {
    inner: Mutex<Inner>,
    started: Instant,
}

impl Default for ReadStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadStats {
    pub fn new() -> ReadStats {
        let now = Instant::now();
        ReadStats {
            inner: Mutex::new(Inner {
                counters: Counters::default(),
                accounts: RecentMap::new(TRACKED_ACCOUNTS),
                slots: RecentMap::new(TRACKED_SLOTS),
                codes: RecentMap::new(TRACKED_CODES),
                last_summary: now,
            }),
            started: now,
        }
    }

    /// A verified account proof for `address` at world root `state_root` that
    /// cost `elapsed` of wall-clock to fetch.
    pub fn observe_account(
        &self,
        address: [u8; 20],
        state_root: [u8; 32],
        fact: AccountFact,
        elapsed: Duration,
    ) {
        self.observe_account_at(address, state_root, fact, elapsed, Instant::now());
    }

    fn observe_account_at(
        &self,
        address: [u8; 20],
        state_root: [u8; 32],
        fact: AccountFact,
        elapsed: Duration,
        now: Instant,
    ) {
        let ms = elapsed.as_millis() as u64;
        let summary = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let inner = &mut *g;
            let c = &mut inner.counters.account;
            c.fetches += 1;
            c.fetch_ms += ms;
            if let Some(prev) = inner.accounts.get(&address) {
                c.repeats += 1;
                let unchanged = prev.fact == fact;
                if prev.state_root == state_root {
                    c.same_state_root += 1;
                    c.same_state_root_ms += ms;
                } else if unchanged {
                    c.unchanged += 1;
                }
                c.by_age.record(now.saturating_duration_since(prev.at), unchanged);
            }
            inner.accounts.put(address, AccountSeen { state_root, fact, at: now });
            inner.summary_due(now).then(|| inner.snapshot())
        };
        if let Some(s) = summary {
            log_summary(&s);
        }
    }

    /// A verified storage-slot proof for `(address, storage_key)` anchored at
    /// the account's `storage_root` under world root `state_root`.
    pub fn observe_storage(
        &self,
        address: [u8; 20],
        storage_key: [u8; 32],
        state_root: [u8; 32],
        storage_root: [u8; 32],
        value: [u8; 32],
        elapsed: Duration,
    ) {
        self.observe_storage_at(
            address,
            storage_key,
            state_root,
            storage_root,
            value,
            elapsed,
            Instant::now(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_storage_at(
        &self,
        address: [u8; 20],
        storage_key: [u8; 32],
        state_root: [u8; 32],
        storage_root: [u8; 32],
        value: [u8; 32],
        elapsed: Duration,
        now: Instant,
    ) {
        let ms = elapsed.as_millis() as u64;
        let key = (address, storage_key);
        let summary = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let inner = &mut *g;
            let c = &mut inner.counters.storage;
            c.fetches += 1;
            c.fetch_ms += ms;
            if let Some(prev) = inner.slots.get(&key) {
                c.repeats += 1;
                let unchanged = prev.value == value;
                if prev.state_root == state_root {
                    c.same_state_root += 1;
                }
                if prev.storage_root == storage_root {
                    // Includes the same-world-root case: the storage root cannot
                    // move while the world root stands still.
                    c.same_storage_root += 1;
                    c.same_storage_root_ms += ms;
                } else if unchanged {
                    c.same_value += 1;
                }
                c.by_age.record(now.saturating_duration_since(prev.at), unchanged);
            }
            inner
                .slots
                .put(key, SlotSeen { state_root, storage_root, value, at: now });
            inner.summary_due(now).then(|| inner.snapshot())
        };
        if let Some(s) = summary {
            log_summary(&s);
        }
    }

    /// A bytecode blob fetched for `code_hash` (content-addressed: every
    /// repeat is avoidable by construction).
    pub fn observe_code(&self, code_hash: [u8; 32], elapsed: Duration) {
        self.observe_code_at(code_hash, elapsed, Instant::now());
    }

    fn observe_code_at(&self, code_hash: [u8; 32], elapsed: Duration, now: Instant) {
        let ms = elapsed.as_millis() as u64;
        let summary = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let inner = &mut *g;
            let c = &mut inner.counters.code;
            c.fetches += 1;
            c.fetch_ms += ms;
            if inner.codes.get(&code_hash).is_some() {
                c.repeats += 1;
                c.repeat_ms += ms;
            }
            inner.codes.put(code_hash, ());
            inner.summary_due(now).then(|| inner.snapshot())
        };
        if let Some(s) = summary {
            log_summary(&s);
        }
    }

    /// The counters as JSON: fixed key order, no whitespace. The Java engine's
    /// `ReadStats.toJson()` produces the identical shape (pinned on both sides)
    /// so a host reads one schema whichever engine answers.
    pub fn to_json(&self) -> String {
        self.to_json_at(Instant::now())
    }

    fn to_json_at(&self, now: Instant) -> String {
        let c = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot();
        let mut s = String::with_capacity(768);
        s.push('{');
        num(&mut s, "schema", 1);
        s.push(',');
        num(
            &mut s,
            "windowSeconds",
            now.saturating_duration_since(self.started).as_secs(),
        );
        let a = &c.account;
        s.push_str(",\"account\":{");
        num(&mut s, "fetches", a.fetches);
        s.push(',');
        num(&mut s, "repeats", a.repeats);
        s.push(',');
        num(&mut s, "sameStateRoot", a.same_state_root);
        s.push(',');
        num(&mut s, "unchanged", a.unchanged);
        s.push(',');
        num(&mut s, "fetchMs", a.fetch_ms);
        s.push(',');
        num(&mut s, "sameStateRootFetchMs", a.same_state_root_ms);
        s.push_str(",\"byAge\":");
        a.by_age.write_json(&mut s);
        let st = &c.storage;
        s.push_str("},\"storage\":{");
        num(&mut s, "fetches", st.fetches);
        s.push(',');
        num(&mut s, "repeats", st.repeats);
        s.push(',');
        num(&mut s, "sameStateRoot", st.same_state_root);
        s.push(',');
        num(&mut s, "sameStorageRoot", st.same_storage_root);
        s.push(',');
        num(&mut s, "sameValue", st.same_value);
        s.push(',');
        num(&mut s, "fetchMs", st.fetch_ms);
        s.push(',');
        num(&mut s, "sameStorageRootFetchMs", st.same_storage_root_ms);
        s.push_str(",\"byAge\":");
        st.by_age.write_json(&mut s);
        let co = &c.code;
        s.push_str("},\"code\":{");
        num(&mut s, "fetches", co.fetches);
        s.push(',');
        num(&mut s, "repeats", co.repeats);
        s.push(',');
        num(&mut s, "fetchMs", co.fetch_ms);
        s.push(',');
        num(&mut s, "repeatFetchMs", co.repeat_ms);
        s.push_str("},\"tracked\":{");
        num(&mut s, "accounts", c.tracked_accounts as u64);
        s.push(',');
        num(&mut s, "slots", c.tracked_slots as u64);
        s.push(',');
        num(&mut s, "codes", c.tracked_codes as u64);
        s.push_str("}}");
        s
    }
}

fn num(out: &mut String, key: &str, value: u64) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

fn log_summary(c: &Counters) {
    tracing::info!(
        "[read-stats] account fetches={} repeats={} sameStateRoot={} unchanged={} | \
         storage fetches={} repeats={} sameStateRoot={} sameStorageRoot={} sameValue={} \
         avoidableMs={} | code fetches={} repeats={} avoidableMs={}",
        c.account.fetches,
        c.account.repeats,
        c.account.same_state_root,
        c.account.unchanged,
        c.storage.fetches,
        c.storage.repeats,
        c.storage.same_state_root,
        c.storage.same_storage_root,
        c.storage.same_value,
        c.storage.same_storage_root_ms,
        c.code.fetches,
        c.code.repeats,
        c.code.repeat_ms,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(nonce: u64, storage_root: u8) -> AccountFact {
        AccountFact {
            nonce,
            balance: pad32(&[1, 2]),
            storage_root: [storage_root; 32],
            code_hash: [7; 32],
        }
    }

    fn parse(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("valid json")
    }

    #[test]
    fn empty_shape_is_stable() {
        let s = ReadStats::new();
        let t0 = s.started;
        // The Java twin's ReadStatsTest pins this exact literal.
        assert_eq!(
            s.to_json_at(t0),
            "{\"schema\":1,\"windowSeconds\":0,\
             \"account\":{\"fetches\":0,\"repeats\":0,\"sameStateRoot\":0,\"unchanged\":0,\
             \"fetchMs\":0,\"sameStateRootFetchMs\":0,\"byAge\":{\"le12s\":{\"reads\":0,\"unchanged\":0},\
             \"le60s\":{\"reads\":0,\"unchanged\":0},\"le5m\":{\"reads\":0,\"unchanged\":0},\
             \"gt5m\":{\"reads\":0,\"unchanged\":0}}},\
             \"storage\":{\"fetches\":0,\"repeats\":0,\"sameStateRoot\":0,\"sameStorageRoot\":0,\
             \"sameValue\":0,\"fetchMs\":0,\"sameStorageRootFetchMs\":0,\"byAge\":{\
             \"le12s\":{\"reads\":0,\"unchanged\":0},\"le60s\":{\"reads\":0,\"unchanged\":0},\
             \"le5m\":{\"reads\":0,\"unchanged\":0},\"gt5m\":{\"reads\":0,\"unchanged\":0}}},\
             \"code\":{\"fetches\":0,\"repeats\":0,\"fetchMs\":0,\"repeatFetchMs\":0},\
             \"tracked\":{\"accounts\":0,\"slots\":0,\"codes\":0}}"
        );
    }

    #[test]
    fn storage_repeats_classify_by_root_and_age() {
        let s = ReadStats::new();
        let t0 = s.started;
        let addr = [0xAA; 20];
        let key = [0x01; 32];
        let ms = Duration::from_millis(100);
        // First fetch: nothing to compare against.
        s.observe_storage_at(addr, key, [1; 32], [9; 32], [5; 32], ms, t0);
        // Same block (same world root) 5 s later: a per-root cache would hit.
        s.observe_storage_at(addr, key, [1; 32], [9; 32], [5; 32], ms, t0 + Duration::from_secs(5));
        // New block, storage root unchanged, 30 s later: storageRoot cache hits.
        s.observe_storage_at(addr, key, [2; 32], [9; 32], [5; 32], ms, t0 + Duration::from_secs(35));
        // New block, storage root moved, value unchanged, 4 min later: ceiling only.
        s.observe_storage_at(addr, key, [3; 32], [8; 32], [5; 32], ms, t0 + Duration::from_secs(275));
        // Storage root moved and the value changed, > 5 min later.
        s.observe_storage_at(addr, key, [4; 32], [7; 32], [6; 32], ms, t0 + Duration::from_secs(700));
        let j = parse(&s.to_json_at(t0 + Duration::from_secs(700)));
        assert_eq!(j["windowSeconds"], 700);
        let st = &j["storage"];
        assert_eq!(st["fetches"], 5);
        assert_eq!(st["repeats"], 4);
        assert_eq!(st["sameStateRoot"], 1);
        assert_eq!(st["sameStorageRoot"], 2);
        assert_eq!(st["sameValue"], 1);
        assert_eq!(st["fetchMs"], 500);
        assert_eq!(st["sameStorageRootFetchMs"], 200);
        assert_eq!(st["byAge"]["le12s"]["reads"], 1);
        assert_eq!(st["byAge"]["le12s"]["unchanged"], 1);
        assert_eq!(st["byAge"]["le60s"]["reads"], 1);
        assert_eq!(st["byAge"]["le5m"]["reads"], 1);
        assert_eq!(st["byAge"]["le5m"]["unchanged"], 1);
        assert_eq!(st["byAge"]["gt5m"]["reads"], 1);
        assert_eq!(st["byAge"]["gt5m"]["unchanged"], 0);
        assert_eq!(j["tracked"]["slots"], 1);
    }

    #[test]
    fn account_repeats_count_same_root_and_unchanged_separately() {
        let s = ReadStats::new();
        let t0 = s.started;
        let addr = [0xBB; 20];
        let ms = Duration::from_millis(40);
        s.observe_account_at(addr, [1; 32], fact(1, 9), ms, t0);
        // Duplicate within the block.
        s.observe_account_at(addr, [1; 32], fact(1, 9), ms, t0 + Duration::from_secs(1));
        // Next block, account untouched: the ceiling case, not sameStateRoot.
        s.observe_account_at(addr, [2; 32], fact(1, 9), ms, t0 + Duration::from_secs(20));
        // Next block, nonce bumped.
        s.observe_account_at(addr, [3; 32], fact(2, 9), ms, t0 + Duration::from_secs(40));
        let j = parse(&s.to_json_at(t0));
        let a = &j["account"];
        assert_eq!(a["fetches"], 4);
        assert_eq!(a["repeats"], 3);
        assert_eq!(a["sameStateRoot"], 1);
        assert_eq!(a["unchanged"], 1);
        assert_eq!(a["sameStateRootFetchMs"], 40);
        assert_eq!(a["byAge"]["le12s"]["reads"], 1);
        assert_eq!(a["byAge"]["le60s"]["reads"], 2);
        assert_eq!(a["byAge"]["le60s"]["unchanged"], 1);
        assert_eq!(j["tracked"]["accounts"], 1);
    }

    #[test]
    fn absent_account_is_the_empty_account() {
        assert_eq!(AccountFact::from_leaf(None), AccountFact::absent());
        let leaf = AccountLeaf {
            nonce: 0,
            balance: Vec::new(),
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: EMPTY_CODE_HASH,
        };
        // A present-but-empty leaf compares equal to an absence: the same fact
        // for every caching question, whichever proof shape the peer served.
        assert_eq!(AccountFact::from_leaf(Some(&leaf)), AccountFact::absent());
        assert_eq!(pad32(&[0xab, 0xcd])[30..], [0xab, 0xcd]);
        assert_eq!(pad32(&[1; 33]), [0; 32], "oversized scalar pads to zero, no panic");
    }

    #[test]
    fn code_repeats_are_all_avoidable() {
        let s = ReadStats::new();
        let t0 = s.started;
        s.observe_code_at([1; 32], Duration::from_millis(30), t0);
        s.observe_code_at([2; 32], Duration::from_millis(30), t0);
        s.observe_code_at([1; 32], Duration::from_millis(50), t0);
        let j = parse(&s.to_json_at(t0));
        assert_eq!(j["code"]["fetches"], 3);
        assert_eq!(j["code"]["repeats"], 1);
        assert_eq!(j["code"]["fetchMs"], 110);
        assert_eq!(j["code"]["repeatFetchMs"], 50);
        assert_eq!(j["tracked"]["codes"], 2);
    }

    #[test]
    fn tracking_is_bounded_and_evicts_least_recently_observed() {
        let mut m: RecentMap<u32, u32> = RecentMap::new(3);
        m.put(1, 10);
        m.put(2, 20);
        m.put(3, 30);
        // Re-observing 1 makes 2 the least recently observed.
        m.put(1, 11);
        m.put(4, 40);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(&2), None, "least recently observed evicted");
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.get(&3), Some(&30));
        assert_eq!(m.get(&4), Some(&40));
        // Many re-puts of one key must not grow the queue without bound.
        for i in 0..1000 {
            m.put(1, i);
        }
        assert!(m.order.len() <= 16, "stale queue entries compacted");
        assert_eq!(m.len(), 3);

        let s = ReadStats::new();
        let t0 = s.started;
        for i in 0..(TRACKED_CODES as u32 + 10) {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            s.observe_code_at(h, Duration::ZERO, t0);
        }
        let j = parse(&s.to_json_at(t0));
        assert_eq!(j["tracked"]["codes"], TRACKED_CODES);
        assert_eq!(j["code"]["repeats"], 0);
    }
}
