//! Forwarding-Kademlia routing table for Swarm overlays.
//!
//! Bee uses a 32-bin routing table keyed on the **proximity order** (PO) of
//! a peer's overlay address relative to ours. PO is the count of leading
//! XOR-zero bits of `our_overlay ^ their_overlay`, capped at 31. A peer with
//! every bit different lands in bin 0; a peer that shares 30 leading bits
//! lands in bin 30; we never store ourselves (PO 32+).
//!
//! For the minimum-viable read path we only need the *forwarding* side:
//! given a target overlay (the address of a chunk we want to retrieve),
//! find the connected peer whose overlay XORs with the target to the
//! smallest big-endian numeric value. That's `closest_peer`. Bee additionally
//! tracks neighborhood depth, replication targets, healthy/reachable flags,
//! etc.; all of that is overkill for "fetch one chunk", so it's deliberately
//! omitted here and can be layered on later without changing the public
//! `RoutingTable` surface.
//!
//! # Why a separate module
//!
//! Routing logic is pure (overlay bytes in, peer-id out). Keeping it out of
//! `behaviour.rs` means it can be tested with synthetic peer ids and known
//! XOR distances, and the swarm event loop just calls
//! `RoutingTable::admit` / `forget` / `closest_peer` at the right places.
//!
//! [`Proximity`]: https://github.com/ethersphere/bee/blob/v2.7.1/pkg/swarm/proximity.go

use libp2p::PeerId;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Number of XOR bins we partition peers into. Matches `swarm.MaxBins =
/// MaxPO + 1 = 32`.
pub const NUM_BINS: usize = 32;
/// Length of a Swarm overlay address in bytes.
pub const OVERLAY_LEN: usize = 32;

/// 32-byte Swarm overlay address.
pub type Overlay = [u8; OVERLAY_LEN];

/// Proximity order of `a` relative to `b`: number of common leading
/// XOR-zero bits, saturating at `NUM_BINS - 1`. Two equal addresses XOR to
/// all-zeros and hit the saturation cap.
///
/// Mirrors `bee` `swarm.Proximity` byte-for-byte for any input where both
/// sides are 32-byte overlays.
#[must_use]
pub fn proximity(a: &Overlay, b: &Overlay) -> u8 {
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        let xor = x ^ y;
        if xor != 0 {
            // Count leading zeros within this byte: `leading_zeros` on `u8`
            // counts zeros from the MSB end, which is exactly the bit-order
            // bee uses for proximity (`oxo >> (7 - j) & 1`).
            let bit = xor.leading_zeros() as u8;
            let po = (i as u8) * 8 + bit;
            return po.min((NUM_BINS - 1) as u8);
        }
    }
    (NUM_BINS - 1) as u8
}

/// `Ordering` of two overlays' XOR distance to a target. `Less` means `a`
/// is closer (smaller XOR) than `b`. Equivalent to `bee` `DistanceCmp` with
/// inverted return values (Go uses `+1` for closer; Rust uses `Less`).
#[must_use]
pub fn distance_cmp(target: &Overlay, a: &Overlay, b: &Overlay) -> Ordering {
    for i in 0..OVERLAY_LEN {
        let da = a[i] ^ target[i];
        let db = b[i] ^ target[i];
        let ord = da.cmp(&db);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Per-peer routing entry. We only need the overlay for distance compares;
/// PO is recomputed once at admission and cached for cheap bin lookups.
#[derive(Debug, Clone, Copy)]
struct Entry {
    overlay: Overlay,
    po: u8,
}

/// In-memory forwarding-Kademlia routing table.
///
/// Indexed both by `PeerId` (for O(1) admit / forget on libp2p events) and
/// by `po` (for fast bin enumeration). Both indexes are kept in sync;
/// neither is the canonical state, the underlying `entries` map is.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    base: Overlay,
    entries: HashMap<PeerId, Entry>,
    /// `bins[po]` = peers currently classified at proximity order `po`.
    /// `Vec` because admission order is not meaningful and we always do
    /// linear scans of the whole bin (it's bounded by `target_peers`).
    bins: Vec<Vec<PeerId>>,
}

impl RoutingTable {
    #[must_use]
    pub fn new(base: Overlay) -> Self {
        Self {
            base,
            entries: HashMap::new(),
            bins: vec![Vec::new(); NUM_BINS],
        }
    }

    /// Local overlay (our base address). Useful for diagnostics and for
    /// the ant-control snapshot.
    #[must_use]
    pub const fn base(&self) -> &Overlay {
        &self.base
    }

    /// Number of peers currently in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Admit a peer with its (verified) overlay. Idempotent: re-admitting
    /// the same peer-id is a no-op if the overlay matches, and a "move"
    /// (forget then re-admit) if it doesn't. The latter shouldn't happen
    /// in practice — overlays are permanent — but we don't want a stale
    /// entry to silently shadow a fresh handshake.
    pub fn admit(&mut self, peer: PeerId, overlay: Overlay) {
        if let Some(existing) = self.entries.get(&peer) {
            if existing.overlay == overlay {
                return;
            }
            self.forget(&peer);
        }
        let po = proximity(&self.base, &overlay);
        self.entries.insert(peer, Entry { overlay, po });
        self.bins[po as usize].push(peer);
    }

    /// Remove a peer (e.g. on `ConnectionClosed`). No-op if unknown.
    pub fn forget(&mut self, peer: &PeerId) {
        let Some(entry) = self.entries.remove(peer) else {
            return;
        };
        let bin = &mut self.bins[entry.po as usize];
        if let Some(pos) = bin.iter().position(|p| p == peer) {
            bin.swap_remove(pos);
        }
    }

    /// Number of peers per bin — used by `antop` to visualise the
    /// routing table fan-out at a glance. Length is always `NUM_BINS`.
    #[must_use]
    pub fn bin_counts(&self) -> [u8; NUM_BINS] {
        let mut out = [0u8; NUM_BINS];
        for (i, b) in self.bins.iter().enumerate() {
            out[i] = b.len().min(u8::MAX as usize) as u8;
        }
        out
    }

    /// Forwarding-Kademlia `closest_peer`: the peer in our table whose
    /// overlay XORs with `target` to the smallest big-endian value, ignoring
    /// any peer in `skip`.
    ///
    /// Bee additionally allows / requires the result to be strictly closer
    /// than ourselves when `allow_upstream = false`; we deliberately don't
    /// enforce that here. As an origin-only retrieval client we *want* to
    /// fall back to "the closest connected peer, even if we're closer than
    /// it" — bee's retrieval handler will then either serve from cache or
    /// itself forward toward the chunk.
    /// Snapshot all current `(peer, overlay)` entries. Used by the node
    /// loop to hand a stable peer list to a spawned fetch task without
    /// holding a borrow of the live table for the whole tree walk.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(PeerId, Overlay)> {
        self.entries.iter().map(|(p, e)| (*p, e.overlay)).collect()
    }

    #[must_use]
    pub fn closest_peer(&self, target: &Overlay, skip: &[PeerId]) -> Option<(PeerId, Overlay)> {
        let mut best: Option<(PeerId, Overlay)> = None;
        for (peer, entry) in &self.entries {
            if skip.contains(peer) {
                continue;
            }
            match &best {
                None => best = Some((*peer, entry.overlay)),
                Some((_, current)) => {
                    if distance_cmp(target, &entry.overlay, current) == Ordering::Less {
                        best = Some((*peer, entry.overlay));
                    }
                }
            }
        }
        best
    }
}

/// Default time-to-live for a known-but-unconnected peer entry. After
/// this long without a fresh hive advert / handshake, the entry is
/// pruned so a peer that left the network eventually stops counting
/// toward "visible peers". 45 min sits in the middle of bee's
/// kademlia retention window.
pub const DEFAULT_KNOWN_TTL: Duration = Duration::from_mins(45);

/// Default per-bin cap on the known-peer book. Bounds memory and
/// stops gateway-style churn (a firehose of distinct overlays in the
/// far bins) from growing the book without limit. 32 bins × 512 ≈ 16K
/// overlays max (~1 MB), comfortably in the "thousands of visible
/// peers" range bee reports while staying bounded.
pub const DEFAULT_KNOWN_PER_BIN_CAP: u32 = 512;

/// One entry in the [`KnownPeers`] book. Keyed by overlay (not
/// `PeerId`) because hive can re-advertise the same overlay under a
/// fresh `PeerId`; the overlay is the stable network identity and the
/// thing bee counts.
#[derive(Debug, Clone, Copy)]
struct KnownEntry {
    po: u8,
    last_seen: Instant,
}

/// Bounded book of peers we *know about* — connected peers plus those
/// discovered via hive gossip but not (yet / currently) connected.
///
/// This is the "known" side of bee's kademlia, distinct from the
/// "connected" [`RoutingTable`]: bee-shaped clients read **visible
/// peers** as `sum(bins[*].population)`, which is the size of this book
/// per PO bin, while **connected peers** stay the smaller working set.
/// Entries are deduped by overlay, bounded by a per-bin cap, and pruned
/// on TTL so the book tracks the live population without growing
/// unbounded.
#[derive(Debug, Clone)]
pub struct KnownPeers {
    base: Overlay,
    entries: HashMap<Overlay, KnownEntry>,
    bins: [u32; NUM_BINS],
    ttl: Duration,
    per_bin_cap: u32,
}

impl KnownPeers {
    #[must_use]
    pub fn new(base: Overlay) -> Self {
        Self::with_limits(base, DEFAULT_KNOWN_TTL, DEFAULT_KNOWN_PER_BIN_CAP)
    }

    #[must_use]
    pub fn with_limits(base: Overlay, ttl: Duration, per_bin_cap: u32) -> Self {
        Self {
            base,
            entries: HashMap::new(),
            bins: [0u32; NUM_BINS],
            ttl,
            per_bin_cap,
        }
    }

    /// Note that we've seen `overlay` (from a hive hint or a successful
    /// handshake). Idempotent: a repeat refreshes `last_seen` without
    /// double-counting; a first insert bumps `bins[po]` unless the bin
    /// is already at the per-bin cap (in which case the overlay is
    /// dropped to keep the book bounded). Returns `true` on first
    /// insert.
    pub fn note(&mut self, overlay: Overlay) -> bool {
        let now = Instant::now();
        if let Some(e) = self.entries.get_mut(&overlay) {
            e.last_seen = now;
            return false;
        }
        let po = proximity(&self.base, &overlay);
        if self.bins[po as usize] >= self.per_bin_cap {
            return false;
        }
        self.entries
            .insert(overlay, KnownEntry { po, last_seen: now });
        self.bins[po as usize] += 1;
        true
    }

    /// Drop entries not seen within the TTL, decrementing their bins.
    /// `now` is taken as a parameter so the caller can drive it off the
    /// existing periodic tick (and tests can simulate elapsed time).
    pub fn prune(&mut self, now: Instant) {
        let ttl = self.ttl;
        let bins = &mut self.bins;
        self.entries.retain(|_, e| {
            let keep = now.saturating_duration_since(e.last_seen) <= ttl;
            if !keep {
                bins[e.po as usize] = bins[e.po as usize].saturating_sub(1);
            }
            keep
        });
    }

    /// Per-bin known-peer counts. Length is always `NUM_BINS`.
    #[must_use]
    pub fn bin_counts(&self) -> [u32; NUM_BINS] {
        self.bins
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn pid() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    /// Identical overlays → max PO (saturated). Diverging at the very first
    /// bit → PO 0. Sanity check that we follow bee's `swarm.Proximity`.
    #[test]
    fn proximity_matches_bee() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert_eq!(proximity(&a, &b), (NUM_BINS - 1) as u8);

        b[0] = 0x80;
        assert_eq!(proximity(&a, &b), 0, "diverges at MSB → bin 0");

        b[0] = 0x40;
        assert_eq!(proximity(&a, &b), 1, "first bit equal → bin 1");

        a[0] = 0xff;
        b[0] = 0xff;
        b[1] = 0x80;
        assert_eq!(proximity(&a, &b), 8, "byte boundary, MSB of byte 1 differs");

        a = [0xff; 32];
        b = [0xff; 32];
        b[3] = 0xfe;
        assert_eq!(
            proximity(&a, &b),
            31,
            "saturated at MaxPO=31 even when more bits agree",
        );
    }

    /// Distance compare orders by big-endian XOR magnitude — closer = smaller.
    #[test]
    fn distance_cmp_orders_by_xor() {
        let target = [0u8; 32];
        let mut closer = [0u8; 32];
        closer[31] = 0x01;
        let mut farther = [0u8; 32];
        farther[0] = 0x01;
        assert_eq!(distance_cmp(&target, &closer, &farther), Ordering::Less);
        assert_eq!(distance_cmp(&target, &farther, &closer), Ordering::Greater);
        assert_eq!(distance_cmp(&target, &closer, &closer), Ordering::Equal);
    }

    /// Admit / forget keeps the bin index in sync with the entry map.
    #[test]
    fn admit_and_forget_round_trip() {
        let base = [0u8; 32];
        let mut table = RoutingTable::new(base);
        let p1 = pid();
        let p2 = pid();
        let mut o1 = [0u8; 32];
        o1[0] = 0x80;
        let mut o2 = [0u8; 32];
        o2[0] = 0x01;

        table.admit(p1, o1);
        table.admit(p2, o2);
        assert_eq!(table.len(), 2);
        let bins = table.bin_counts();
        assert_eq!(bins[0], 1, "p1 (PO 0) lands in bin 0");
        assert_eq!(bins[7], 1, "p2 (PO 7) lands in bin 7");

        table.forget(&p1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.bin_counts()[0], 0);

        // Forgetting an unknown peer is a no-op.
        table.forget(&p1);
        assert_eq!(table.len(), 1);
    }

    /// Re-admit with the same overlay is idempotent; with a different
    /// overlay moves the peer to the right bin (no shadow entry left
    /// behind).
    #[test]
    fn admit_idempotent_and_repinning() {
        let mut table = RoutingTable::new([0u8; 32]);
        let p = pid();
        let mut o1 = [0u8; 32];
        o1[0] = 0x80;
        let mut o2 = [0u8; 32];
        o2[0] = 0x01;

        table.admit(p, o1);
        table.admit(p, o1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.bin_counts()[0], 1);

        table.admit(p, o2);
        assert_eq!(table.len(), 1);
        assert_eq!(table.bin_counts()[0], 0, "old bin cleared");
        assert_eq!(table.bin_counts()[7], 1, "new bin populated");
    }

    /// `closest_peer` picks the peer with the smallest XOR distance and
    /// honors `skip` so a forwarder can rotate through candidates.
    #[test]
    fn closest_peer_picks_smallest_xor_and_skips() {
        let mut table = RoutingTable::new([0u8; 32]);
        let mut target = [0u8; 32];
        target[0] = 0x80;
        target[1] = 0x40;

        let near = pid();
        let far = pid();
        let mut o_near = target;
        o_near[31] = 0x01;
        let mut o_far = [0u8; 32];
        o_far[0] = 0x01;

        table.admit(near, o_near);
        table.admit(far, o_far);

        let (chosen, _) = table.closest_peer(&target, &[]).unwrap();
        assert_eq!(chosen, near);

        let (skipped, _) = table.closest_peer(&target, &[near]).unwrap();
        assert_eq!(skipped, far);

        assert!(table.closest_peer(&target, &[near, far]).is_none());
    }

    /// Empty table returns `None` rather than panicking — the caller is
    /// expected to handle this as "no peers to ask, retry later".
    #[test]
    fn closest_peer_empty_table_is_none() {
        let table = RoutingTable::new([0u8; 32]);
        assert!(table.closest_peer(&[0u8; 32], &[]).is_none());
    }

    /// `note` dedups by overlay (a re-advert refreshes, doesn't
    /// double-count) and places overlays into the right PO bin.
    #[test]
    fn known_peers_note_dedups_and_bins() {
        let mut known = KnownPeers::new([0u8; 32]);
        let mut o1 = [0u8; 32];
        o1[0] = 0x80; // PO 0
        let mut o2 = [0u8; 32];
        o2[0] = 0x01; // PO 7

        assert!(known.note(o1), "first insert returns true");
        assert!(!known.note(o1), "re-note is a refresh, not a new entry");
        assert!(known.note(o2));
        assert_eq!(known.len(), 2);
        let bins = known.bin_counts();
        assert_eq!(bins[0], 1);
        assert_eq!(bins[7], 1);
    }

    /// The per-bin cap bounds the book: once a bin is full, further
    /// distinct overlays in that bin are dropped.
    #[test]
    fn known_peers_per_bin_cap_bounds_growth() {
        let mut known = KnownPeers::with_limits([0u8; 32], DEFAULT_KNOWN_TTL, 2);
        // All these overlays start with 0x80 → PO 0, but differ in
        // later bytes so they're distinct entries.
        for i in 0u8..5 {
            let mut o = [0u8; 32];
            o[0] = 0x80;
            o[31] = i;
            known.note(o);
        }
        assert_eq!(known.bin_counts()[0], 2, "bin 0 capped at 2");
        assert_eq!(known.len(), 2);
    }

    /// Pruning drops entries older than the TTL and decrements bins.
    #[test]
    fn known_peers_prune_expires_by_ttl() {
        let ttl = Duration::from_mins(1);
        let mut known = KnownPeers::with_limits([0u8; 32], ttl, DEFAULT_KNOWN_PER_BIN_CAP);
        let mut o = [0u8; 32];
        o[0] = 0x80;
        known.note(o);
        assert_eq!(known.len(), 1);

        // Not yet expired.
        known.prune(Instant::now());
        assert_eq!(known.len(), 1);

        // Well past the TTL → pruned, bin decremented.
        known.prune(Instant::now() + ttl + Duration::from_secs(1));
        assert_eq!(known.len(), 0);
        assert_eq!(known.bin_counts()[0], 0);
    }
}
