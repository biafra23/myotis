//! The sent-tx watch and the pending-nonce overlay — the Rust twins of the
//! Java engine's `SentTxTracker` and `PendingNonceTracker` (rpc-backend),
//! constants and boundary semantics identical.
//!
//! Both are PURE state machines: the caller supplies `now` (the reader's
//! monotonic clock), so unit tests are deterministic and nothing here touches
//! I/O or a real clock. Neither locks internally — the reader wraps them in
//! its own `Mutex`, like the receipt-scan map.
//!
//! Trust posture (the Java doc's rationale, kept verbatim in spirit): none of
//! this is proof-backed and none of it needs to be. The watch only gates a
//! REBROADCAST of bytes the wallet itself signed; the nonce overlay only ever
//! RAISES a "pending" answer above the proof-verified mined floor, is derived
//! from our own ECDSA-authenticated broadcast, and self-heals via TTL. It must
//! never be consulted for settled tags (latest/safe/finalized).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The watch as shared between the reader (broadcast/rebroadcast/confirm) and
/// every peer's read loop (gossip sightings). A std Mutex — every access is a
/// brief map poke, never held across I/O.
pub type SharedSentTxWatch = std::sync::Arc<std::sync::Mutex<SentTxTracker>>;

/// How long a broadcast tx stays watched (rebroadcast candidates + the
/// broadcast-head reachback) before the watch gives up. Java
/// `SENT_TX_WATCH_TTL_MS = 180_000`.
pub const SENT_TX_WATCH_TTL: Duration = Duration::from_secs(180);

/// How long a recorded pending nonce may raise `getTransactionCount("pending")`
/// before it expires unmined. Java `PENDING_NONCE_TTL_MS = 90_000`.
pub const PENDING_NONCE_TTL: Duration = Duration::from_secs(90);

/// One watched broadcast: when it left us, when the network first echoed it
/// back (`None` until then), and the head number recorded at broadcast time
/// (`None` when the anchor had no head yet) — the receipt scan's reachback
/// floor for our own txs.
struct Watch {
    broadcast_at: Instant,
    seen_at: Option<Instant>,
    broadcast_head: Option<u64>,
}

/// Watches the wallet's own broadcast txs until the network visibly has them:
/// a tx is rebroadcast (bounded, deduped by peers) while it is neither seen in
/// gossip nor mined nor expired. Java `SentTxTracker` twin.
#[derive(Default)]
pub struct SentTxTracker {
    watched: HashMap<[u8; 32], Watch>,
}

impl SentTxTracker {
    pub fn new() -> SentTxTracker {
        SentTxTracker { watched: HashMap::new() }
    }

    /// Start (or restart — a re-send overwrites) watching a broadcast tx.
    pub fn watch(&mut self, hash: [u8; 32], now: Instant, broadcast_head: Option<u64>) {
        self.watched.insert(hash, Watch { broadcast_at: now, seen_at: None, broadcast_head });
    }

    /// The head number recorded when WE broadcast this tx, or `None` for a tx
    /// that isn't ours / had no head at broadcast time. The receipt scan
    /// reaches its first-scan window back to this floor.
    pub fn broadcast_head(&self, hash: &[u8; 32]) -> Option<u64> {
        self.watched.get(hash).and_then(|w| w.broadcast_head)
    }

    /// O(1) hot-path guard so gossip decoding is skipped entirely while
    /// nothing is watched (the common state).
    pub fn watching_any(&self) -> bool {
        !self.watched.is_empty()
    }

    /// Note a gossip sighting. Returns the broadcast→first-sighting latency
    /// ONCE (the first sighting of one of ours); `None` when the hash isn't
    /// ours or was already counted — so the caller logs each tx once.
    pub fn mark_seen(&mut self, hash: &[u8; 32], now: Instant) -> Option<Duration> {
        let w = self.watched.get_mut(hash)?;
        if w.seen_at.is_some() {
            return None;
        }
        w.seen_at = Some(now);
        Some(now.saturating_duration_since(w.broadcast_at))
    }

    /// Verified inclusion (a receipt was served) — stop watching.
    pub fn confirm_mined(&mut self, hash: &[u8; 32]) {
        self.watched.remove(hash);
    }

    /// The rebroadcast candidates: watched txs never yet seen in gossip.
    pub fn unseen(&self) -> Vec<[u8; 32]> {
        self.watched.iter().filter(|(_, w)| w.seen_at.is_none()).map(|(h, _)| *h).collect()
    }

    /// Drop watches older than [`SENT_TX_WATCH_TTL`] (strictly older — at
    /// exactly the boundary a watch is still live, the Java `>` mirrored).
    /// Returns how many were evicted.
    pub fn evict_expired(&mut self, now: Instant) -> usize {
        let before = self.watched.len();
        self.watched
            .retain(|_, w| now.saturating_duration_since(w.broadcast_at) <= SENT_TX_WATCH_TTL);
        before - self.watched.len()
    }

    pub fn len(&self) -> usize {
        self.watched.len()
    }

    pub fn is_empty(&self) -> bool {
        self.watched.is_empty()
    }
}

/// A sender's highest broadcast-but-unmined nonce, with its record time.
struct PendingEntry {
    nonce: u64,
    at: Instant,
}

/// The "pending" nonce overlay: after the wallet broadcasts a tx, the pending
/// tag answers `max(verified mined count, our nonce + 1)` until the chain
/// catches up or the entry expires unmined. Java `PendingNonceTracker` twin.
#[derive(Default)]
pub struct PendingNonceTracker {
    by_sender: HashMap<[u8; 20], PendingEntry>,
}

impl PendingNonceTracker {
    pub fn new() -> PendingNonceTracker {
        PendingNonceTracker { by_sender: HashMap::new() }
    }

    /// Record a broadcast tx's sender nonce. Keeps the HIGHEST nonce per
    /// sender — an out-of-order lower record never lowers it; an EQUAL nonce
    /// refreshes the timestamp (the Java `merge` with `>=`, mirrored).
    pub fn record(&mut self, sender: [u8; 20], nonce: u64, now: Instant) {
        match self.by_sender.get_mut(&sender) {
            Some(e) if nonce >= e.nonce => {
                e.nonce = nonce;
                e.at = now;
            }
            Some(_) => {}
            None => {
                self.by_sender.insert(sender, PendingEntry { nonce, at: now });
            }
        }
    }

    /// The pending-tag answer: `mined_count` untouched when there's no live
    /// entry; `max(mined_count, nonce + 1)` while our broadcast is unmined and
    /// unexpired. An entry the chain has caught up with (`mined_count >
    /// nonce`) or one older than [`PENDING_NONCE_TTL`] (strictly — the exact
    /// boundary still holds, the Java `>` mirrored) is dropped. Never returns
    /// below the verified mined floor.
    pub fn overlay(&mut self, sender: &[u8; 20], mined_count: u64, now: Instant) -> u64 {
        let Some(e) = self.by_sender.get(sender) else {
            return mined_count;
        };
        let mined = mined_count > e.nonce;
        let expired = now.saturating_duration_since(e.at) > PENDING_NONCE_TTL;
        if mined || expired {
            self.by_sender.remove(sender);
            return mined_count;
        }
        // saturating: a u64::MAX nonce in a (self-signed) recorded tx must not
        // wrap the +1 (panic-free workspace; the value is absurd, not unsafe).
        mined_count.max(e.nonce.saturating_add(1))
    }

    /// Whether a live entry exists for this sender (logging helper).
    pub fn has(&self, sender: &[u8; 20]) -> bool {
        self.by_sender.contains_key(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    // ---- SentTxTracker (SentTxTrackerTest twin) ----

    #[test]
    fn mark_seen_counts_first_sighting_once() {
        let mut w = SentTxTracker::new();
        let start = t0();
        w.watch([1; 32], start, Some(100));
        // Not ours → None.
        assert_eq!(w.mark_seen(&[9; 32], start), None);
        // First sighting → the latency; second → None (already counted).
        let seen = start + Duration::from_millis(250);
        assert_eq!(w.mark_seen(&[1; 32], seen), Some(Duration::from_millis(250)));
        assert_eq!(w.mark_seen(&[1; 32], seen + Duration::from_secs(1)), None);
        // Seen txs leave the rebroadcast candidate list but stay watched.
        assert!(w.unseen().is_empty());
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn unseen_lists_only_never_seen() {
        let mut w = SentTxTracker::new();
        let start = t0();
        w.watch([1; 32], start, None);
        w.watch([2; 32], start, None);
        w.mark_seen(&[1; 32], start + Duration::from_millis(1));
        assert_eq!(w.unseen(), vec![[2; 32]]);
    }

    #[test]
    fn confirm_mined_stops_watching() {
        let mut w = SentTxTracker::new();
        w.watch([1; 32], t0(), Some(7));
        assert_eq!(w.broadcast_head(&[1; 32]), Some(7));
        w.confirm_mined(&[1; 32]);
        assert!(!w.watching_any());
        assert_eq!(w.broadcast_head(&[1; 32]), None);
    }

    #[test]
    fn evict_expired_is_strictly_after_ttl() {
        let mut w = SentTxTracker::new();
        let start = t0();
        w.watch([1; 32], start, None);
        // Exactly at the boundary: still live (Java `>` semantics).
        assert_eq!(w.evict_expired(start + SENT_TX_WATCH_TTL), 0);
        assert_eq!(w.len(), 1);
        // One millisecond past: evicted.
        assert_eq!(w.evict_expired(start + SENT_TX_WATCH_TTL + Duration::from_millis(1)), 1);
        assert!(w.is_empty());
    }

    // ---- PendingNonceTracker (PendingNonceTrackerTest twin) ----

    #[test]
    fn overlay_raises_to_nonce_plus_one_until_mined() {
        let mut p = PendingNonceTracker::new();
        let start = t0();
        let sender = [0xd8; 20];
        p.record(sender, 5, start);
        // Unmined: raises above the mined floor.
        assert_eq!(p.overlay(&sender, 5, start + Duration::from_secs(1)), 6);
        // Never lowers below a HIGHER verified floor... (equal-nonce case below)
        // Chain caught up (mined count passed our nonce): entry drops, floor wins.
        assert_eq!(p.overlay(&sender, 7, start + Duration::from_secs(2)), 7);
        assert!(!p.has(&sender));
    }

    #[test]
    fn overlay_never_lowers_the_mined_floor() {
        let mut p = PendingNonceTracker::new();
        let start = t0();
        let sender = [1; 20];
        p.record(sender, 5, start);
        // mined_count == nonce + 1 exactly: not `mined_count > nonce`... it IS.
        // mined 6 > nonce 5 → mined, drop, return 6 (== nonce+1, no raise needed).
        assert_eq!(p.overlay(&sender, 6, start), 6);
        assert!(!p.has(&sender));
    }

    #[test]
    fn record_keeps_highest_nonce_per_sender() {
        let mut p = PendingNonceTracker::new();
        let start = t0();
        let sender = [2; 20];
        p.record(sender, 5, start);
        p.record(sender, 3, start + Duration::from_secs(1)); // out-of-order: ignored
        assert_eq!(p.overlay(&sender, 0, start + Duration::from_secs(2)), 6);
        p.record(sender, 8, start + Duration::from_secs(3));
        assert_eq!(p.overlay(&sender, 0, start + Duration::from_secs(4)), 9);
    }

    #[test]
    fn overlay_expires_strictly_after_ttl() {
        let mut p = PendingNonceTracker::new();
        let start = t0();
        let sender = [3; 20];
        p.record(sender, 5, start);
        // Exactly at the boundary: still holds (Java `>` semantics).
        assert_eq!(p.overlay(&sender, 5, start + PENDING_NONCE_TTL), 6);
        // Past it: expired, plain mined count, entry gone.
        assert_eq!(
            p.overlay(&sender, 5, start + PENDING_NONCE_TTL + Duration::from_millis(1)),
            5
        );
        assert!(!p.has(&sender));
    }

    #[test]
    fn equal_nonce_record_refreshes_timestamp() {
        let mut p = PendingNonceTracker::new();
        let start = t0();
        let sender = [4; 20];
        p.record(sender, 5, start);
        // Re-record the same nonce later (a rebroadcast) — TTL restarts.
        p.record(sender, 5, start + Duration::from_secs(60));
        let past_first_ttl = start + PENDING_NONCE_TTL + Duration::from_secs(1);
        assert_eq!(p.overlay(&sender, 5, past_first_ttl), 6); // still live
    }

    #[test]
    fn senders_are_independent() {
        let mut p = PendingNonceTracker::new();
        let start = t0();
        p.record([1; 20], 5, start);
        assert_eq!(p.overlay(&[9; 20], 3, start), 3); // untouched stranger
        assert!(p.has(&[1; 20]));
    }
}
