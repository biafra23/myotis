//! The Tor reserve (docs/privacy-and-tor.md §5): verified peers set aside for
//! Tor reads and sends, persisted next to the peer cache as
//! `peers-tor[-net].cache` — the Tor-only sidecar §5 calls for.
//!
//! A node moves in from the peer cache (a past session proved it serves snap)
//! and from then on the pool never dials it directly — with Tor mode on or
//! off, across restarts. Only Tor reaches it, so a peer in the reserve has no
//! direct session of ours to pair a Tor session with. Its last direct contact
//! is saved with it, so a node that moved in right after a direct session waits
//! out [`TOR_DIRECT_SEPARATION`] even across a restart. Tor results keep it:
//! a read it serves confirms it; `TOR_RESERVE_EVICT_AT` Tor dials in a row
//! that it refuses send it back to the peer cache (a peer that refuses Tor
//! exits is still a fine direct peer), and this process does not take it again.
//!
//! Rust only: the Java engine has no Tor mode and never reads this file. It
//! shares `peers[-net].cache` but not the reserve, so a node it dials directly
//! while reserved comes back in both files; the pool then drops it from the
//! reserve on its next start (see `PeerPool::start`).
//!
//! **Record format** (tab-separated, UTF-8), one node per line, the peer
//! cache's columns (spelled by its helpers) plus two:
//! `ip \t port \t publicKeyHex \t {1|0} [\t snapok|snapbad] [\t torfails=N] [\t direct=UNIX_MS]`.
//! Malformed lines are skipped; a node appears once (keyed by node id).

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::el::peercache::{addr_key, key, parse_key, parse_pubkey, pubkey_hex, CachedElPeer, SnapQuality};
use crate::el::pool::TOR_DIRECT_SEPARATION;

/// The most nodes the reserve holds: enough for several Tor reads and a
/// five-peer broadcast to find fresh peers, while the direct pool keeps the
/// rest of a large cache.
pub(crate) const TOR_RESERVE_CAP: usize = 24;

/// Consecutive Tor dials a reserved node refuses before it goes back to the
/// peer cache. Many peers refuse Tor-exit inbound; one bad exit is not enough
/// to give a node up, three in a row is.
#[cfg(any(test, feature = "tor"))]
pub(crate) const TOR_RESERVE_EVICT_AT: u32 = 3;

/// How many of `verified` peers (the peer cache's snap servers plus the
/// reserve) the reserve should hold: about a third, at most
/// [`TOR_RESERVE_CAP`], and none while fewer than two are known — the direct
/// pool keeps at least one.
pub(crate) fn tor_reserve_target(verified: usize) -> usize {
    if verified < 2 {
        0
    } else {
        ((verified + 1) / 3).clamp(1, TOR_RESERVE_CAP)
    }
}

/// One reserved node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reserved {
    pub addr: SocketAddr,
    pub snap: bool,
    pub quality: SnapQuality,
    /// Consecutive Tor dials it refused (persisted).
    pub tor_fails: u32,
    /// Its last direct contact, unix millis (persisted): Tor may use it from
    /// [`TOR_DIRECT_SEPARATION`] after that.
    pub last_direct_ms: u64,
}

impl Reserved {
    fn as_peer(&self, node: &[u8; 64]) -> CachedElPeer {
        CachedElPeer { addr: self.addr, pubkey: *node, snap: self.snap, quality: self.quality }
    }
}

/// The reserve. In-memory map authoritative; [`flush`](Self::flush) rewrites
/// the file. One with no path (`disabled`) holds nothing: every insert is a
/// no-op, so a host without a data directory has no reserve and Tor fails
/// closed there, as before.
pub(crate) struct TorReserve {
    path: Option<PathBuf>,
    entries: BTreeMap<[u8; 64], Reserved>,
    /// Nodes released for refusing Tor: this process does not take them again
    /// (in memory only — a restart gives each one more try).
    released: HashSet<[u8; 64]>,
    dirty: bool,
}

impl TorReserve {
    pub(crate) fn disabled() -> TorReserve {
        TorReserve { path: None, entries: BTreeMap::new(), released: HashSet::new(), dirty: false }
    }

    /// The reserve that goes with the peer cache at `cache_path`
    /// (`peers.cache` → `peers-tor.cache`, `peers-gnosis.cache` →
    /// `peers-tor-gnosis.cache`, same directory); disabled when the cache is.
    pub(crate) fn beside(cache_path: Option<&Path>) -> TorReserve {
        let path = cache_path.and_then(|p| {
            let name = p.file_name()?.to_str()?;
            let sidecar = match name.strip_prefix("peers") {
                Some(rest) => format!("peers-tor{rest}"),
                None => format!("tor-{name}"),
            };
            Some(p.with_file_name(sidecar))
        });
        match path {
            Some(path) => TorReserve::load(path),
            None => TorReserve::disabled(),
        }
    }

    /// Load the reserve at `path` (missing file → empty).
    pub(crate) fn load(path: PathBuf) -> TorReserve {
        let mut reserve = TorReserve { path: Some(path.clone()), ..TorReserve::disabled() };
        if let Ok(text) = fs::read_to_string(&path) {
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if let Some((node, entry)) = parse_line(line) {
                    reserve.entries.insert(node, entry);
                }
            }
        }
        reserve
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.path.is_some()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn contains(&self, node: &[u8; 64]) -> bool {
        self.entries.contains_key(node)
    }

    /// Whether this process released `node` for refusing Tor.
    pub(crate) fn was_released(&self, node: &[u8; 64]) -> bool {
        self.released.contains(node)
    }

    /// Reserve `node` (replacing an entry it had). A no-op when disabled.
    pub(crate) fn insert(&mut self, node: [u8; 64], entry: Reserved) {
        if self.is_enabled() {
            self.entries.insert(node, entry);
            self.dirty = true;
        }
    }

    /// Release `node` from the reserve, as the peer it was.
    pub(crate) fn remove(&mut self, node: &[u8; 64]) -> Option<CachedElPeer> {
        let entry = self.entries.remove(node)?;
        self.dirty = true;
        Some(entry.as_peer(node))
    }

    /// The nodes in the reserve.
    pub(crate) fn nodes(&self) -> Vec<[u8; 64]> {
        self.entries.keys().copied().collect()
    }

    /// Record a direct contact with `node` at `ms` (unix millis), if later than
    /// the one stored: the pool stamps reserved nodes from its contact log
    /// before every flush, so a session that formed while a node moved in is
    /// what the file remembers.
    pub(crate) fn note_direct(&mut self, node: &[u8; 64], ms: u64) {
        if let Some(e) = self.entries.get_mut(node) {
            if ms > e.last_direct_ms {
                e.last_direct_ms = ms;
                self.dirty = true;
            }
        }
    }

    /// The nodes Tor may use at `now_ms` (unix millis): those whose last direct
    /// contact is [`TOR_DIRECT_SEPARATION`] behind, snap-serving quality first
    /// (Confirmed → Unknown → Denied), then the fewest Tor failures, then in an
    /// order `draw` picks — a fresh one per call, so successive reads spread
    /// over the reserve rather than all going to the same first few nodes.
    pub(crate) fn ready(&self, now_ms: u64, draw: impl Fn(&[u8; 64]) -> u64) -> Vec<CachedElPeer> {
        let window = TOR_DIRECT_SEPARATION.as_millis() as u64;
        let mut ready: Vec<(&[u8; 64], &Reserved)> = self
            .entries
            .iter()
            .filter(|(_, e)| now_ms >= e.last_direct_ms.saturating_add(window))
            .collect();
        ready.sort_by_cached_key(|(node, e)| (e.quality.dial_rank(), e.tor_fails, draw(node)));
        ready.into_iter().map(|(node, e)| e.as_peer(node)).collect()
    }

    /// The `n` nodes to hand back when the reserve holds more than its share
    /// (the verified cache shrank): the most Tor failures first, then the
    /// weakest quality.
    pub(crate) fn surplus(&self, n: usize) -> Vec<[u8; 64]> {
        let mut nodes: Vec<(&[u8; 64], &Reserved)> = self.entries.iter().collect();
        nodes.sort_by_key(|(_, e)| (std::cmp::Reverse(e.tor_fails), std::cmp::Reverse(e.quality.dial_rank())));
        nodes.into_iter().take(n).map(|(node, _)| *node).collect()
    }

    #[cfg(any(test, feature = "tor"))]
    /// A Tor read or push reached `node` and it answered: its Tor failures
    /// start over. `snap_served` — it answered a snap read with a proof that
    /// verified — also confirms its snap quality; a confirmed push or an
    /// answer that proved nothing does not.
    pub(crate) fn record_served(&mut self, node: &[u8; 64], snap_served: bool) {
        if let Some(e) = self.entries.get_mut(node) {
            if e.tor_fails != 0 || (snap_served && e.quality != SnapQuality::Confirmed) {
                e.tor_fails = 0;
                if snap_served {
                    e.quality = SnapQuality::Confirmed;
                }
                self.dirty = true;
            }
        }
    }

    #[cfg(any(test, feature = "tor"))]
    /// A Tor dial to `node` was refused on its side. The
    /// [`TOR_RESERVE_EVICT_AT`]th in a row releases it, returned for the peer
    /// cache, and this process does not take it again.
    pub(crate) fn record_unreachable(&mut self, node: &[u8; 64]) -> Option<CachedElPeer> {
        let e = self.entries.get_mut(node)?;
        e.tor_fails += 1;
        self.dirty = true;
        if e.tor_fails >= TOR_RESERVE_EVICT_AT {
            self.released.insert(*node);
            self.remove(node)
        } else {
            None
        }
    }

    /// Rewrite the file if anything changed.
    pub(crate) fn flush(&mut self) {
        let Some(path) = &self.path else { return };
        if !self.dirty {
            return;
        }
        let mut body = String::with_capacity(self.entries.len() * 180);
        for (node, e) in &self.entries {
            body.push_str(&addr_key(e.addr));
            body.push('\t');
            body.push_str(&pubkey_hex(node));
            body.push('\t');
            body.push(if e.snap { '1' } else { '0' });
            match e.quality {
                SnapQuality::Confirmed => body.push_str("\tsnapok"),
                SnapQuality::Denied => body.push_str("\tsnapbad"),
                SnapQuality::Unknown => {}
            }
            if e.tor_fails > 0 {
                body.push_str(&format!("\ttorfails={}", e.tor_fails));
            }
            body.push_str(&format!("\tdirect={}\n", e.last_direct_ms));
        }
        if fs::write(path, body).is_ok() {
            self.dirty = false;
        } else {
            tracing::warn!(path = %path.display(), "could not write the Tor reserve");
        }
    }
}

fn parse_line(line: &str) -> Option<([u8; 64], Reserved)> {
    let parts: Vec<&str> = line.split('\t').collect();
    // The peer cache's key rule: the address in its canonical spelling.
    let ip = parts.first()?.parse::<IpAddr>().ok()?;
    let port = parts.get(1)?.parse::<u16>().ok()?;
    let addr = parse_key(&key(ip, port))?;
    let node = parse_pubkey(parts.get(2)?)?;
    let snap = parts.get(3).is_some_and(|f| *f == "1");
    let (mut quality, mut tor_fails, mut last_direct_ms) = (SnapQuality::Unknown, 0, None);
    for token in parts.iter().skip(4) {
        match *token {
            "snapok" => quality = SnapQuality::Confirmed,
            "snapbad" => quality = SnapQuality::Denied,
            t => {
                if let Some(n) = t.strip_prefix("torfails=") {
                    tor_fails = n.parse().unwrap_or(0);
                } else if let Some(ms) = t.strip_prefix("direct=") {
                    last_direct_ms = ms.parse().ok();
                }
            }
        }
    }
    let entry = Reserved {
        addr,
        snap,
        quality,
        tor_fails,
        // A line without its stamp counts as contacted when this process
        // started: the run before may have just dialed it.
        last_direct_ms: last_direct_ms.unwrap_or_else(crate::el::pool::process_start_unix_ms),
    };
    Some((node, entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("myotis-torreserve-{name}-{}.cache", std::process::id()))
    }

    fn entry(last_direct_ms: u64) -> Reserved {
        Reserved {
            addr: SocketAddr::from(([10, 0, 0, 1], 30303)),
            snap: true,
            quality: SnapQuality::Unknown,
            tor_fails: 0,
            last_direct_ms,
        }
    }

    #[test]
    fn the_target_is_about_a_third_capped_and_leaves_the_direct_pool_one() {
        assert_eq!(tor_reserve_target(0), 0);
        assert_eq!(tor_reserve_target(1), 0);
        assert_eq!(tor_reserve_target(2), 1);
        assert_eq!(tor_reserve_target(4), 1);
        assert_eq!(tor_reserve_target(5), 2);
        assert_eq!(tor_reserve_target(30), 10);
        assert_eq!(tor_reserve_target(72), 24);
        assert_eq!(tor_reserve_target(1_000), TOR_RESERVE_CAP);
    }

    #[test]
    fn it_sits_beside_the_peer_cache_and_is_off_without_one() {
        let r = TorReserve::beside(Some(Path::new("/data/peers-gnosis.cache")));
        assert_eq!(r.path.as_deref(), Some(Path::new("/data/peers-tor-gnosis.cache")));
        let r = TorReserve::beside(Some(Path::new("/data/peers.cache")));
        assert_eq!(r.path.as_deref(), Some(Path::new("/data/peers-tor.cache")));
        assert!(!TorReserve::beside(None).is_enabled());
        let mut off = TorReserve::disabled();
        off.insert([1; 64], entry(0));
        assert_eq!(off.len(), 0, "a disabled reserve holds nothing");
    }

    #[test]
    fn a_round_trip_keeps_quality_failures_and_the_direct_stamp() {
        let p = path("roundtrip");
        let mut r = TorReserve::load(p.clone());
        let mut a = entry(1_700_000_000_000);
        a.quality = SnapQuality::Confirmed;
        a.tor_fails = 2;
        let mut b = entry(42);
        b.addr = "[::ffff:192.0.2.7]:30304".parse().unwrap(); // stored as the v4 form
        r.insert([0xaa; 64], a.clone());
        r.insert([0xbb; 64], b.clone());
        r.flush();
        let loaded = TorReserve::load(p.clone());
        assert_eq!(loaded.entries.get(&[0xaa; 64]), Some(&a));
        b.addr = "192.0.2.7:30304".parse().unwrap();
        assert_eq!(loaded.entries.get(&[0xbb; 64]), Some(&b));
        let _ = fs::remove_file(p);
    }

    #[test]
    fn a_node_is_ready_ten_minutes_after_its_last_direct_contact() {
        let mut r = TorReserve::load(path("ready"));
        let t = 1_700_000_000_000u64;
        r.insert([1; 64], entry(t));
        let window = TOR_DIRECT_SEPARATION.as_millis() as u64;
        let by_id = |n: &[u8; 64]| u64::from(n[0]);
        assert!(r.ready(t + window - 1, by_id).is_empty());
        assert_eq!(r.ready(t + window, by_id).len(), 1);
        // A later direct contact moves it out again; an earlier one never does.
        r.note_direct(&[1; 64], t + 5);
        assert!(r.ready(t + window, by_id).is_empty());
        r.note_direct(&[1; 64], t);
        assert_eq!(r.ready(t + window + 5, by_id).len(), 1);
    }

    #[test]
    fn ready_nodes_rank_by_quality_then_failures_then_the_draw() {
        let mut r = TorReserve::load(path("rank"));
        let mut c = entry(0);
        c.quality = SnapQuality::Confirmed;
        let mut f = entry(0);
        f.tor_fails = 1;
        r.insert([1; 64], entry(0));
        r.insert([2; 64], f);
        r.insert([3; 64], c);
        r.insert([4; 64], entry(0));
        let order = |draw: fn(&[u8; 64]) -> u64| -> Vec<u8> {
            r.ready(u64::MAX, draw).iter().map(|p| p.pubkey[0]).collect()
        };
        assert_eq!(order(|n| u64::from(n[0])), vec![3, 1, 4, 2]);
        // Among equals, the draw decides: another draw, another order.
        assert_eq!(order(|n| u64::from(u8::MAX - n[0])), vec![3, 4, 1, 2]);
    }

    #[test]
    fn three_refused_dials_in_a_row_release_a_node_for_good_and_a_serve_resets_them() {
        let mut r = TorReserve::load(path("evict"));
        r.insert([1; 64], entry(0));
        assert!(r.record_unreachable(&[1; 64]).is_none());
        assert!(r.record_unreachable(&[1; 64]).is_none());
        // A confirmed push resets the failures without vouching for snap...
        r.record_served(&[1; 64], false);
        assert_eq!((r.entries[&[1; 64]].tor_fails, r.entries[&[1; 64]].quality), (0, SnapQuality::Unknown));
        // ...a verified snap read confirms it.
        r.record_served(&[1; 64], true);
        assert_eq!(r.entries[&[1; 64]].quality, SnapQuality::Confirmed);
        assert!(r.record_unreachable(&[1; 64]).is_none());
        assert!(r.record_unreachable(&[1; 64]).is_none());
        let released = r.record_unreachable(&[1; 64]).expect("the third in a row releases it");
        assert_eq!((released.pubkey, released.quality), ([1; 64], SnapQuality::Confirmed));
        assert!(!r.contains(&[1; 64]));
        assert!(r.was_released(&[1; 64]), "not taken again by this process");
    }

    #[test]
    fn the_surplus_is_the_most_failed_then_the_weakest() {
        let mut r = TorReserve::load(path("surplus"));
        let mut good = entry(0);
        good.quality = SnapQuality::Confirmed;
        let mut failing = entry(0);
        failing.tor_fails = 2;
        r.insert([1; 64], good);
        r.insert([2; 64], entry(0));
        r.insert([3; 64], failing);
        assert_eq!(r.surplus(2), vec![[3; 64], [2; 64]]);
    }

    #[test]
    fn malformed_lines_are_skipped_and_an_unstamped_one_waits_from_the_process_start() {
        let p = path("malformed");
        let node = format!("0x{}", "ab".repeat(64));
        fs::write(
            &p,
            format!("not a line\n10.0.0.1\t30303\t0xdead\t1\n10.0.0.2\t30303\t{node}\t1\tsnapok\n"),
        )
        .unwrap();
        let r = TorReserve::load(p.clone());
        assert_eq!(r.len(), 1);
        let e = &r.entries[&[0xab; 64]];
        assert_eq!(e.quality, SnapQuality::Confirmed);
        assert_eq!(e.last_direct_ms, crate::el::pool::process_start_unix_ms());
        let _ = fs::remove_file(p);
    }
}
