//! What we can serve OTHER peers, and how often they ask.
//!
//! Twin of the Java side's `ServedHeaderWindow` + `ServeStats` (PRs #221/#226):
//! a bounded, shared store of recent block headers backing the eth/69 (EIP-7642)
//! advertised block range, plus counters for inbound peer demand.
//!
//! The eth/69 Status range is a promise — a peer that asks inside
//! `[earliestBlock, latestBlock]` and gets an empty response scores us down. So
//! [`ServedHeaders::advertise`] never names a block we do not hold: both ends of
//! the returned range are held headers, and an empty window advertises nothing
//! (the session then falls back to a minimal genesis-only `[0, 0]` — itself a
//! small residual over-claim, since unlike Java no genesis header RLP is
//! embedded to serve; see the handshake comment in `eth::session`).
//!
//! One instance per network, owned by the peer pool and shared with every
//! managed peer, so a header fetched on one connection is servable on all of
//! them. Headers are stored as the raw RLP received on the wire with the hash
//! recomputed at decode (same integrity level as the Java window). Plain
//! `std::sync::Mutex`: critical sections are tiny map operations with no awaits.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Default window size — how many blocks below the newest held header we retain
/// and advertise. Matches the Java `EthHandler.DEFAULT_SERVED_BLOCK_WINDOW`.
pub const DEFAULT_SERVED_BLOCK_WINDOW: u64 = 32;

/// Cap on headers served per response, mirroring the Java serve path's bound.
pub const MAX_SERVED_HEADERS: u64 = 1024;

/// Reject absurd "headers" at the door: real ones are ~600 B; 16 KiB leaves
/// generous room (clique-style extraData) while capping a hostile peer's
/// worst-case window memory at ~512 KiB instead of ~320 MiB (32 × the 10 MiB
/// RLPx frame bound).
pub const MAX_SERVED_HEADER_BYTES: usize = 16 * 1024;

/// The mainnet genesis header RLP (535 bytes), byte-identical to the Java
/// `NetworkConfig.MAINNET_GENESIS_HEADER_RLP` (dumped from it; the test below
/// pins `keccak256(rlp) == the mainnet genesis hash`). Seeded into the served
/// window so genesis fork-probes get a real answer — the last residual
/// over-claim of the `[0, 0]` empty-window advertisement.
pub const MAINNET_GENESIS_HEADER_RLP_HEX: &str = concat!(
    "f90214a000000000000000000000000000000000000000000000000000000000",
    "00000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142",
    "fd40d49347940000000000000000000000000000000000000000a0d7f8974fb5",
    "ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544a056e81f17",
    "1bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f",
    "171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "850400000000808213888080a011bbe8db4e347b4e8c937c1c8370e4b5ed33ad",
    "b3db69cbdb7a38e1e50b1b82faa0000000000000000000000000000000000000",
    "0000000000000000000000000000880000000000000042"
);


/// Decode the embedded genesis constant and self-check `keccak256(rlp)` against
/// the mainnet genesis hash. Returns `None` (no seeding, fail-safe) rather than
/// panicking on any mismatch — the test below asserts it is `Some`.
pub fn mainnet_genesis() -> Option<([u8; 32], Vec<u8>)> {
    let rlp = decode_hex(MAINNET_GENESIS_HEADER_RLP_HEX)?;
    let hash = myotis_core::keccak::keccak256(&rlp);
    let expected: [u8; 32] = decode_hex(
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
    )?
    .try_into()
    .ok()?;
    if hash != expected {
        return None;
    }
    Some((hash, rlp))
}

/// Panic-free lowercase-hex decode (even length only).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push(nib(pair[0])? << 4 | nib(pair[1])?);
    }
    Some(out)
}

#[derive(Default)]
struct Inner {
    /// number → (hash, parentHash, raw header RLP), bounded to the newest window.
    /// The parent hash lets the backfill anchor a downward batch to the held run
    /// without re-decoding the stored RLP.
    by_number: BTreeMap<u64, ([u8; 32], [u8; 32], Vec<u8>)>,
    /// hash → number, kept in lockstep with `by_number` (fork probes ask by hash).
    by_hash: BTreeMap<[u8; 32], u64>,
}

/// Bounded shared store of recent servable headers.
pub struct ServedHeaders {
    inner: Mutex<Inner>,
    /// Live-settable window size (the Settings knob adjusts it, mirroring the
    /// Java `ServedHeaderWindow.setMaxWindow`). Read on every put.
    window: AtomicU64,
    /// Genesis header (hash, raw RLP) — always servable for fork probes, held
    /// OUTSIDE the sliding window and never part of the advertised range
    /// (mirrors the Java window's genesis seeding). None where we embed no
    /// genesis bytes (non-mainnet, tests).
    genesis: Option<([u8; 32], Vec<u8>)>,
}

impl Default for ServedHeaders {
    fn default() -> Self {
        Self::new(DEFAULT_SERVED_BLOCK_WINDOW)
    }
}

impl ServedHeaders {
    pub fn new(window: u64) -> ServedHeaders {
        Self::with_genesis(window, None)
    }

    /// As [`new`](Self::new), seeding an always-servable genesis header
    /// (hash + raw RLP). The caller vouches for the pair; production wiring
    /// verifies `keccak256(rlp) == hash` before seeding (see the pool).
    pub fn with_genesis(window: u64, genesis: Option<([u8; 32], Vec<u8>)>) -> ServedHeaders {
        ServedHeaders {
            inner: Mutex::new(Inner::default()),
            window: AtomicU64::new(window.max(1)),
            genesis,
        }
    }

    /// The current window cap.
    pub fn window(&self) -> u64 {
        self.window.load(Ordering::Relaxed)
    }

    /// Live-adjust the window (Settings). Clamped ≥ 1; shrinking evicts the tail
    /// immediately so the advertised range can never exceed the new cap.
    pub fn set_window(&self, window: u64) {
        let clamped = window.max(1);
        self.window.store(clamped, Ordering::Relaxed);
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::evict_locked(&mut g, clamped);
    }

    /// Evict everything below the newest-window band. Caller holds the lock.
    fn evict_locked(g: &mut Inner, window: u64) {
        let top = match g.by_number.keys().next_back() {
            Some(&t) => t,
            None => return,
        };
        let floor = top.saturating_sub(window - 1);
        while let Some((&n, _)) = g.by_number.first_key_value() {
            if n >= floor {
                break;
            }
            if let Some((h, _, _)) = g.by_number.remove(&n) {
                g.by_hash.remove(&h);
            }
        }
    }

    /// Record a header we hold (raw wire RLP, hash recomputed at decode).
    /// Genesis (number 0) is not tracked — the range never claims it and the
    /// Rust EL has no embedded genesis header to serve.
    pub fn put(&self, number: u64, hash: [u8; 32], parent_hash: [u8; 32], raw_rlp: Vec<u8>) {
        if number == 0 || raw_rlp.len() > MAX_SERVED_HEADER_BYTES {
            return;
        }
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((old_hash, _, _)) = g.by_number.insert(number, (hash, parent_hash, raw_rlp)) {
            if old_hash != hash {
                g.by_hash.remove(&old_hash); // reorg: drop the stale hash key
            }
        }
        g.by_hash.insert(hash, number);
        Self::evict_locked(&mut g, self.window.load(Ordering::Relaxed));
    }

    /// The contiguous run of held headers starting at `start` (ascending, no
    /// skip), capped at `count` — the simple GetBlockHeaders shape peers use.
    pub fn run_from(&self, start: u64, count: u64) -> Vec<Vec<u8>> {
        // Genesis is servable by number but deliberately not part of the sliding
        // window: a run STARTING at 0 serves just the genesis header (the fork
        // probe shape — count is typically 1, and the window can never be
        // contiguous with block 0 anyway).
        if start == 0 {
            return match &self.genesis {
                Some((_, rlp)) if count >= 1 => vec![rlp.clone()],
                _ => Vec::new(),
            };
        }
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut out = Vec::new();
        let cap = count.min(MAX_SERVED_HEADERS);
        for i in 0..cap {
            // checked_add: panic-freedom here must not depend on decode-side
            // number bounds in another crate (peer-supplied start can be u64::MAX).
            let Some(n) = start.checked_add(i) else { break };
            match g.by_number.get(&n) {
                Some((_, _, raw)) => out.push(raw.clone()),
                None => break,
            }
        }
        out
    }

    /// The stored parent hash of a held header (the backfill's downward anchor).
    pub fn parent_hash_of(&self, number: u64) -> Option<[u8; 32]> {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        g.by_number.get(&number).map(|(_, p, _)| *p)
    }

    /// One header by hash, if held.
    pub fn by_hash(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some((gh, rlp)) = &self.genesis {
            if gh == hash {
                return Some(rlp.clone());
            }
        }
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let n = g.by_hash.get(hash)?;
        g.by_number.get(n).map(|(_, _, raw)| raw.clone())
    }

    /// The eth/69 range to advertise: the contiguous run of held headers ending
    /// at the newest one — `(earliest, latest, latest_hash)`. `None` when the
    /// window is empty (callers advertise the honest genesis-only `[0, 0]`).
    /// Never names a block we do not hold.
    pub fn advertise(&self) -> Option<(u64, u64, [u8; 32])> {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (&top, (top_hash, _, _)) = g.by_number.last_key_value()?;
        let mut earliest = top;
        while earliest > 0 && g.by_number.contains_key(&(earliest - 1)) {
            earliest -= 1;
        }
        Some((earliest, top, *top_hash))
    }
}

/// Everything a managed peer needs to serve and count inbound requests:
/// the shared window + the shared counters, both pool-owned.
#[derive(Clone)]
pub struct ServeContext {
    pub window: std::sync::Arc<ServedHeaders>,
    pub stats: std::sync::Arc<ServeStats>,
}

/// Counters of inbound peer demand — asked before parsing/answering (malformed
/// requests and failed sends still register), served only for a non-empty
/// response. Same semantics as the Java `ServeStats`.
#[derive(Default)]
pub struct ServeStats {
    header_requests: AtomicU64,
    header_requests_served: AtomicU64,
    body_requests: AtomicU64,
    body_requests_served: AtomicU64,
}

impl ServeStats {
    pub fn header_asked(&self) {
        self.header_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn header_served(&self) {
        self.header_requests_served.fetch_add(1, Ordering::Relaxed);
    }
    pub fn body_asked(&self) {
        self.body_requests.fetch_add(1, Ordering::Relaxed);
    }
    /// Never called today — a light client holds no bodies — but the counter
    /// exists so the surface matches Java's and lights up if that ever changes.
    #[allow(dead_code)]
    pub fn body_served(&self) {
        self.body_requests_served.fetch_add(1, Ordering::Relaxed);
    }

    /// `(header_asked, header_served, body_asked, body_served)`.
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.header_requests.load(Ordering::Relaxed),
            self.header_requests_served.load(Ordering::Relaxed),
            self.body_requests.load(Ordering::Relaxed),
            self.body_requests_served.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_be_bytes());
        h
    }

    fn raw(n: u64) -> Vec<u8> {
        format!("header-{n}").into_bytes()
    }

    #[test]
    fn advertises_only_the_contiguous_held_run() {
        let w = ServedHeaders::new(32);
        for n in 100..=110 {
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        assert_eq!(w.advertise(), Some((100, 110, hash(110))));
        // A hole breaks the run at the top.
        let w = ServedHeaders::new(32);
        for n in 100..=110 {
            if n == 107 {
                continue;
            }
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        assert_eq!(w.advertise(), Some((108, 110, hash(110))));
    }

    #[test]
    fn empty_window_advertises_nothing() {
        assert_eq!(ServedHeaders::new(32).advertise(), None);
    }

    #[test]
    fn window_cap_evicts_and_bounds_the_claim() {
        let w = ServedHeaders::new(5);
        for n in 100..=120 {
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        assert_eq!(w.advertise(), Some((116, 120, hash(120))));
        assert!(w.run_from(115, 1).is_empty(), "evicted below the cap");
        assert_eq!(w.by_hash(&hash(115)), None, "hash index evicted in lockstep");
    }

    #[test]
    fn serves_runs_and_by_hash_and_stops_at_holes() {
        let w = ServedHeaders::new(32);
        for n in [5u64, 6, 7, 9] {
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        assert_eq!(w.run_from(5, 10), vec![raw(5), raw(6), raw(7)]); // stops at the 8 hole
        assert_eq!(w.run_from(8, 2), Vec::<Vec<u8>>::new());
        assert_eq!(w.by_hash(&hash(6)), Some(raw(6)));
        assert_eq!(w.by_hash(&hash(8)), None);
    }

    #[test]
    fn reorg_replaces_the_hash_index() {
        let w = ServedHeaders::new(32);
        w.put(50, hash(1), hash(1 - 1), raw(1));
        w.put(50, hash(2), hash(2 - 1), raw(2)); // same number, new hash
        assert_eq!(w.by_hash(&hash(1)), None, "stale hash dropped");
        assert_eq!(w.by_hash(&hash(2)), Some(raw(2)));
        assert_eq!(w.advertise(), Some((50, 50, hash(2))));
    }

    #[test]
    fn set_window_shrinks_and_grows_live() {
        let w = ServedHeaders::new(10);
        for n in 100..=109 {
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        w.set_window(3);
        assert_eq!(w.advertise(), Some((107, 109, hash(109))));
        assert!(w.run_from(106, 1).is_empty(), "shrink evicts below the new cap");
        w.set_window(5);
        for n in 110..=111 {
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        // survivors (107..109) + new (110,111) all within the 5-cap band [107,111]
        assert_eq!(w.advertise(), Some((107, 111, hash(111))));
    }

    #[test]
    fn embedded_mainnet_genesis_hashes_correctly_and_serves() {
        let (hash, rlp) = mainnet_genesis().expect("embedded genesis must self-verify");
        assert_eq!(rlp.len(), 535, "byte-identical to the Java constant");
        let w = ServedHeaders::with_genesis(32, Some((hash, rlp.clone())));
        // Servable by number-0 run and by hash; never advertised.
        assert_eq!(w.run_from(0, 1), vec![rlp.clone()]);
        assert_eq!(w.by_hash(&hash), Some(rlp));
        assert_eq!(w.advertise(), None, "genesis never enters the advertised range");
        // Without seeding, block 0 stays unservable.
        assert!(ServedHeaders::new(32).run_from(0, 1).is_empty());
    }

    #[test]
    fn stats_snapshot_counts() {
        let s = ServeStats::default();
        s.header_asked();
        s.header_asked();
        s.header_served();
        s.body_asked();
        assert_eq!(s.snapshot(), (2, 1, 1, 0));
    }
}
