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

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use myotis_net::codec::encode_success_response;

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
/// the store an unco-operative caller could otherwise grow without limit. The
/// design's answer is to pre-populate checkpoint-aligned roots and refuse the
/// rest; this cap is the backstop that makes "refuse the rest" true even if a
/// future ingestion path gets sloppy.
pub const MAX_BOOTSTRAPS: usize = 64;

#[derive(Debug, Default)]
struct Inner {
    /// period → pre-encoded single chunk.
    updates: BTreeMap<u64, Arc<[u8]>>,
    /// block root → pre-encoded response.
    bootstraps: HashMap<[u8; 32], Arc<[u8]>>,
    finality: Option<Arc<[u8]>>,
    optimistic: Option<Arc<[u8]>>,
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

    // --- ingestion (background tasks only; never the request path) --------

    /// Encode once, at ingest. `fork_digest` is the digest the source framed,
    /// re-emitted verbatim — not derived from a fork name, which since EIP-7892
    /// would not determine it.
    pub fn insert_update(&self, period: u64, fork_digest: [u8; 4], ssz: &[u8]) {
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        self.inner.write().unwrap().updates.insert(period, wire);
    }

    pub fn set_finality(&self, fork_digest: [u8; 4], ssz: &[u8]) {
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        self.inner.write().unwrap().finality = Some(wire);
    }

    pub fn set_optimistic(&self, fork_digest: [u8; 4], ssz: &[u8]) {
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        self.inner.write().unwrap().optimistic = Some(wire);
    }

    /// Returns false if the bootstrap cache is full — the caller should treat
    /// that as "this root is not one we pre-populate", not as an error.
    pub fn insert_bootstrap(&self, block_root: [u8; 32], fork_digest: [u8; 4], ssz: &[u8]) -> bool {
        let mut inner = self.inner.write().unwrap();
        if !inner.bootstraps.contains_key(&block_root) && inner.bootstraps.len() >= MAX_BOOTSTRAPS {
            return false;
        }
        let wire: Arc<[u8]> = encode_success_response(ssz, Some(fork_digest)).into();
        inner.bootstraps.insert(block_root, wire);
        true
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
        let inner = self.inner.read().unwrap();

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
        self.inner.read().unwrap().finality.clone()
    }

    pub fn optimistic(&self) -> Option<Arc<[u8]>> {
        self.inner.read().unwrap().optimistic.clone()
    }

    pub fn bootstrap(&self, block_root: &[u8; 32]) -> Option<Arc<[u8]>> {
        self.inner.read().unwrap().bootstraps.get(block_root).cloned()
    }

    pub fn has_period(&self, period: u64) -> bool {
        self.inner.read().unwrap().updates.contains_key(&period)
    }

    pub fn coverage(&self) -> Coverage {
        let inner = self.inner.read().unwrap();
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
        let inner = self.inner.read().unwrap();
        (from..=to).filter(|p| !inner.updates.contains_key(p)).collect()
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
            s.insert_update(*p, D, &vec![i as u8 + 1; 64]);
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
        // start + count would overflow; saturating_add keeps the walk sane.
        let body = s.updates_range(u64::MAX, 128).unwrap();
        assert_eq!(decode_multi_chunk_response(&body, 1).unwrap().len(), 1);
    }

    #[test]
    fn bootstraps_are_capped() {
        let s = LcStore::new();
        for i in 0..MAX_BOOTSTRAPS {
            let mut root = [0u8; 32];
            root[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(s.insert_bootstrap(root, D, &[1u8; 32]));
        }
        assert!(!s.insert_bootstrap([0xff; 32], D, &[1u8; 32]), "cap must hold");
        // …but refreshing one already cached is always allowed.
        let mut existing = [0u8; 32];
        existing[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(s.insert_bootstrap(existing, D, &[2u8; 32]));
        assert_eq!(s.coverage().bootstraps, MAX_BOOTSTRAPS);
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
