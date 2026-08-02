//! The EL peer cache (EL-A8): persists peers that reached a READY snap session so
//! a restart warm-starts from proven snap servers instead of re-discovering them
//! one discv4 timeout at a time. The Rust twin of the Java `app/PeerCache`
//! (and `AndroidPeerCache`), reading and writing the SAME `peers[-net].cache`
//! file + format so verified EL peers survive restarts AND engine switches
//! (the same cross-engine sharing the CL [`crate::clcache`] gives).
//!
//! **Record format** (tab-separated, UTF-8), one peer per line:
//! `ip \t port \t publicKeyHex \t {1|0} [\t snapok|snapbad] [\t fails=N]`
//! — the trailing `{1|0}` is snap/1 CAPABILITY; the optional `snapok`/`snapbad`
//! token records learned snap-serving QUALITY. `publicKeyHex` is the peer's
//! 64-byte node id as `0x`-prefixed hex (Java `Bytes.toHexString()`). Tabs
//! can't appear in an IP literal, so IPv6 stays unambiguous. Lines in the
//! legacy colon format (`ip:port:publicKeyHex[:snap]`, IPv4 only) still parse,
//! so an existing daemon cache migrates in place on the first rewrite.
//!
//! **Capability vs quality** (Java parity): the snap flag means the peer
//! negotiated snap/1 in Hello; it says nothing about whether it actually serves
//! the state trie. [`record_snap_served`](ElPeerCache::record_snap_served) /
//! [`record_snap_failure`](ElPeerCache::record_snap_failure) layer a learned
//! verdict on top — a peer needs [`FAILURE_THRESHOLD`] consecutive failures (no
//! intervening serve) to be marked DENIED, and any serve re-confirms it. Denied
//! peers are DEPRIORITIZED, not evicted (a peer that couldn't serve an old
//! pivot may serve the current one, and is a fine plain-eth peer regardless).
//!
//! **Reachability** (Java parity): [`record_connect_failure`](ElPeerCache::record_connect_failure)
//! tracks consecutive TCP-level dial failures as a persisted `fails=N` token.
//! Past [`CONNECT_FAILURE_DEMOTE`] the peer reports DENIED from
//! [`peers`](ElPeerCache::peers); past [`CONNECT_FAILURE_EVICT`] it is dropped
//! from the cache — the only eviction path. Any successful connect or serve
//! resets the streak.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Consecutive snap-serve failures before a peer is marked DENIED (Java
/// `PeerCache.SNAP_FAILURE_THRESHOLD`).
const FAILURE_THRESHOLD: u32 = 3;

/// Consecutive TCP connect failures before a peer reports DENIED from
/// [`ElPeerCache::peers`] — a currently-unreachable CONFIRMED peer must not
/// outrank reachable candidates (Java `PeerCache.CONNECT_FAILURE_DEMOTE`).
const CONNECT_FAILURE_DEMOTE: u32 = 5;

/// Consecutive TCP connect failures before a peer is evicted from the cache —
/// the only eviction path; re-discovery re-adds a peer that comes back (Java
/// `PeerCache.CONNECT_FAILURE_EVICT`).
const CONNECT_FAILURE_EVICT: u32 = 50;

/// Learned snap-serving quality — the dial-priority verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapQuality {
    /// Proven to serve usable proofs — dial first.
    Confirmed,
    /// Advertised snap but not yet proven either way.
    Unknown,
    /// Failed to serve `FAILURE_THRESHOLD` times running — dial last.
    Denied,
}

impl SnapQuality {
    /// Dial rank for a snap-capable peer of this quality (lower = dial sooner):
    /// Confirmed(0) → Unknown(1) → Denied(2). The pool ranks a non-snap peer
    /// after all of these.
    pub fn dial_rank(self) -> u8 {
        match self {
            SnapQuality::Confirmed => 0,
            SnapQuality::Unknown => 1,
            SnapQuality::Denied => 2,
        }
    }
}

/// A cached peer, ready to re-dial.
#[derive(Debug, Clone)]
pub struct CachedElPeer {
    pub addr: SocketAddr,
    pub pubkey: [u8; 64],
    pub snap: bool,
    pub quality: SnapQuality,
}

/// One in-memory cache entry (keyed by `ip\tport`).
#[derive(Debug, Clone)]
struct Entry {
    /// The peer's node id as stored (`0x`-prefixed hex — kept verbatim so a
    /// rewrite is byte-stable with what Java wrote).
    pubkey_hex: String,
    snap: bool,
    quality: SnapQuality,
    /// Consecutive TCP connect failures (persisted as `fails=N`, shared with
    /// the Java caches). Reset by any successful connect or serve.
    fails: u32,
}

/// The EL peer cache. In-memory maps are authoritative; [`flush`](Self::flush)
/// rewrites the whole file (truncating). A cache with no path (`disabled`)
/// accepts all mutations as no-ops — the pool can hold one unconditionally.
pub struct ElPeerCache {
    path: Option<PathBuf>,
    /// `ip\tport` → entry. `BTreeMap` for deterministic rewrite order (line
    /// order doesn't affect compatibility — parsing is order-independent).
    entries: BTreeMap<String, Entry>,
    /// Consecutive-failure streaks — in-memory only (Java parity: the streak is
    /// not persisted; only the resulting DENIED verdict is).
    failures: HashMap<String, u32>,
    dirty: bool,
}

impl ElPeerCache {
    /// A cache with no backing file: loads nothing, persists nothing.
    pub fn disabled() -> ElPeerCache {
        ElPeerCache {
            path: None,
            entries: BTreeMap::new(),
            failures: HashMap::new(),
            dirty: false,
        }
    }

    /// Load the cache at `path` (missing file → empty). Malformed lines are
    /// skipped, never fatal.
    pub fn load(path: PathBuf) -> ElPeerCache {
        let mut cache = ElPeerCache {
            path: Some(path.clone()),
            entries: BTreeMap::new(),
            failures: HashMap::new(),
            dirty: false,
        };
        let Ok(text) = fs::read_to_string(&path) else {
            return cache; // missing/unreadable → empty
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            cache.parse_line(line);
        }
        cache
    }

    /// Parse one cache line into `entries` (tab format, or the legacy colon
    /// format as a fallback). Silently skips a line it can't understand.
    fn parse_line(&mut self, line: &str) {
        let parts: Vec<&str> = line.split(SEP_CH).collect();
        if parts.len() < 3 {
            self.parse_legacy_line(line);
            return;
        }
        // Canonicalize the IP so the key matches the one `addr_key` computes on
        // a later mutate — otherwise a non-canonical literal in the file (e.g.
        // uppercase/expanded IPv6) would make quality updates miss and `add`
        // duplicate the entry. An unparseable IP drops the line.
        let Ok(ip) = parts[0].parse::<std::net::IpAddr>() else {
            return;
        };
        let Ok(port) = parts[1].parse::<u16>() else {
            return;
        };
        let pubkey_hex = parts[2];
        if parse_pubkey(pubkey_hex).is_none() {
            return; // unusable node id → drop the line
        }
        let snap = parts.get(3).map_or(false, |f| *f == "1");
        let mut quality = SnapQuality::Unknown;
        let mut fails = 0u32;
        for token in &parts[4.min(parts.len())..] {
            match *token {
                "snapok" => quality = SnapQuality::Confirmed,
                "snapbad" => quality = SnapQuality::Denied,
                t => {
                    if let Some(n) = t.strip_prefix("fails=") {
                        // Unreadable count → streak starts over at 0 (Java parity).
                        fails = n.parse().unwrap_or(0);
                    }
                }
            }
        }
        self.entries.insert(
            key(&ip.to_string(), port),
            Entry { pubkey_hex: pubkey_hex.to_string(), snap, quality, fails },
        );
    }

    /// Parse a legacy colon line `ip:port:pubkeyHex[:{0|1}]` (IPv4 only — the
    /// legacy writer used colons, so v6 literals were never representable).
    fn parse_legacy_line(&mut self, line: &str) {
        let Some(first) = line.find(':') else { return };
        let Some(second_rel) = line[first + 1..].find(':') else { return };
        let second = first + 1 + second_rel;
        let Ok(ip) = line[..first].parse::<std::net::IpAddr>() else {
            return;
        };
        let Ok(port) = line[first + 1..second].parse::<u16>() else {
            return;
        };
        let rest = &line[second + 1..];
        let (pubkey_hex, snap) = match rest.rfind(':') {
            Some(colon) if matches!(&rest[colon + 1..], "0" | "1") => {
                (&rest[..colon], &rest[colon + 1..] == "1")
            }
            _ => (rest, false),
        };
        if pubkey_hex.is_empty() || pubkey_hex.contains(':') || parse_pubkey(pubkey_hex).is_none() {
            return;
        }
        self.entries.insert(
            key(&ip.to_string(), port),
            Entry {
                pubkey_hex: pubkey_hex.to_string(),
                snap,
                quality: SnapQuality::Unknown,
                fails: 0,
            },
        );
    }

    /// All cached peers, snap-serving quality first (Confirmed → Unknown →
    /// Denied), then non-snap. Entries whose stored address/pubkey no longer
    /// parse are skipped.
    pub fn peers(&self) -> Vec<CachedElPeer> {
        let mut out: Vec<CachedElPeer> = self
            .entries
            .iter()
            .filter_map(|(k, e)| {
                let addr = parse_key(k)?;
                let pubkey = parse_pubkey(&e.pubkey_hex)?;
                // A peer past the connect-failure demote threshold reports
                // Denied regardless of its learned serve quality: a
                // currently-unreachable Confirmed peer must not outrank
                // reachable candidates (or get the hunt's eager backoff
                // bypass). The stored verdict is kept — one successful
                // connect clears the streak and restores it (Java parity).
                let quality = if e.fails >= CONNECT_FAILURE_DEMOTE {
                    SnapQuality::Denied
                } else {
                    e.quality
                };
                Some(CachedElPeer { addr, pubkey, snap: e.snap, quality })
            })
            .collect();
        // Snap peers first (by quality), then non-snap. Stable within a rank.
        out.sort_by_key(|p| if p.snap { p.quality.dial_rank() } else { 3 });
        out
    }

    /// Record a peer that reached a READY session with capability `snap`. New
    /// peers enter as [`SnapQuality::Unknown`]; a re-add only updates the snap
    /// flag (quality is driven by the serve/failure signals).
    pub fn add(&mut self, addr: SocketAddr, pubkey: &[u8; 64], snap: bool) {
        if self.path.is_none() {
            return;
        }
        let k = addr_key(addr);
        match self.entries.get_mut(&k) {
            Some(e) => {
                if e.snap != snap {
                    e.snap = snap;
                    self.dirty = true;
                }
                // Reachable again — clear the connect-failure streak (persisted
                // lazily, on the next dirty flush; Java parity).
                e.fails = 0;
            }
            None => {
                self.entries.insert(
                    k,
                    Entry {
                        pubkey_hex: pubkey_hex(pubkey),
                        snap,
                        quality: SnapQuality::Unknown,
                        fails: 0,
                    },
                );
                self.dirty = true;
            }
        }
    }

    /// A dial to this peer completed a session without snap — still proof the
    /// address is alive, so clear its connect-failure streak (persisted lazily).
    pub fn record_connect_success(&mut self, addr: SocketAddr) {
        if self.path.is_none() {
            return;
        }
        if let Some(e) = self.entries.get_mut(&addr_key(addr)) {
            e.fails = 0;
        }
    }

    /// A TCP-level dial failure (refused/timeout/unreachable) against a cached
    /// peer. No-op for unknown addresses. Crossing [`CONNECT_FAILURE_DEMOTE`]
    /// persists the streak and demotes the peer's reported quality; crossing
    /// [`CONNECT_FAILURE_EVICT`] evicts it — callers must only report while
    /// demonstrably online (e.g. some other pooled peer is live), so an offline
    /// device can't decimate its own cache.
    pub fn record_connect_failure(&mut self, addr: SocketAddr) {
        if self.path.is_none() {
            return;
        }
        let k = addr_key(addr);
        let Some(e) = self.entries.get_mut(&k) else {
            return;
        };
        e.fails = e.fails.saturating_add(1);
        if e.fails >= CONNECT_FAILURE_EVICT {
            let fails = e.fails;
            self.entries.remove(&k);
            self.failures.remove(&k);
            self.dirty = true;
            tracing::info!(%addr, fails, "evicted unreachable peer from EL cache");
        } else if e.fails % CONNECT_FAILURE_DEMOTE == 0 {
            // Persist every 5th failure (not just the demote crossing) so a
            // restart resumes the streak with at most 4 counts lost — keeping
            // eviction genuinely cumulative across restarts (Java parity).
            self.dirty = true;
            if e.fails == CONNECT_FAILURE_DEMOTE {
                tracing::info!(%addr, fails = e.fails, "deprioritized unreachable EL cache peer");
            }
        }
    }

    /// A snap fetch against this peer returned usable proof material: mark it
    /// CONFIRMED (dial-first on restart) and clear its failure streak.
    pub fn record_snap_served(&mut self, addr: SocketAddr) {
        if self.path.is_none() {
            return;
        }
        let k = addr_key(addr);
        self.failures.remove(&k);
        if let Some(e) = self.entries.get_mut(&k) {
            e.fails = 0;
            if e.quality != SnapQuality::Confirmed {
                e.quality = SnapQuality::Confirmed;
                self.dirty = true;
            }
        }
    }

    /// A snap fetch failed (timeout / empty / bad proof). After
    /// [`FAILURE_THRESHOLD`] consecutive failures with no intervening serve, the
    /// peer is marked DENIED (deprioritized, not evicted).
    pub fn record_snap_failure(&mut self, addr: SocketAddr) {
        if self.path.is_none() {
            return;
        }
        let k = addr_key(addr);
        // Java parity (`if (!entries.containsKey(key)) return;`): only track
        // failures for peers we actually cached, so the streak map can't grow
        // for never-added addresses.
        if !self.entries.contains_key(&k) {
            return;
        }
        let count = self.failures.entry(k.clone()).or_insert(0);
        *count += 1;
        if *count >= FAILURE_THRESHOLD {
            if let Some(e) = self.entries.get_mut(&k) {
                if e.quality != SnapQuality::Denied {
                    e.quality = SnapQuality::Denied;
                    self.dirty = true;
                }
            }
        }
    }

    /// Rewrite the file from the in-memory state (truncating) if anything
    /// changed since the last flush. Best-effort: a write error is dropped
    /// (persistence must never take the engine down).
    pub fn flush(&mut self) {
        let Some(path) = &self.path else { return };
        if !self.dirty {
            return;
        }
        let mut body = String::with_capacity(self.entries.len() * 96);
        for (k, e) in &self.entries {
            body.push_str(k); // ip\tport
            body.push(SEP_CH);
            body.push_str(&e.pubkey_hex);
            body.push(SEP_CH);
            body.push(if e.snap { '1' } else { '0' });
            match e.quality {
                SnapQuality::Confirmed => {
                    body.push(SEP_CH);
                    body.push_str("snapok");
                }
                SnapQuality::Denied => {
                    body.push(SEP_CH);
                    body.push_str("snapbad");
                }
                SnapQuality::Unknown => {}
            }
            if e.fails > 0 {
                body.push(SEP_CH);
                body.push_str(&format!("fails={}", e.fails));
            }
            body.push('\n');
        }
        if fs::write(path, body).is_ok() {
            self.dirty = false;
        }
    }

    /// Count of cached entries (for host status / tests).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

const SEP_CH: char = '\t';

/// `ip\tport` key from string parts (used on the parse path).
fn key(ip: &str, port: u16) -> String {
    format!("{ip}{SEP_CH}{port}")
}

/// `ip\tport` key from a socket address (used on the mutate path). The IP
/// renders the same way the parser reads it back ([`parse_key`]).
fn addr_key(addr: SocketAddr) -> String {
    format!("{}{SEP_CH}{}", addr.ip(), addr.port())
}

/// Recover a socket address from an `ip\tport` key. `None` if either side is
/// unparseable (a corrupt entry is skipped rather than crashing).
fn parse_key(k: &str) -> Option<SocketAddr> {
    let (ip, port) = k.split_once(SEP_CH)?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// A 64-byte node id as `0x`-prefixed lowercase hex (Java `Bytes.toHexString`).
fn pubkey_hex(pubkey: &[u8; 64]) -> String {
    let mut s = String::with_capacity(2 + 128);
    s.push_str("0x");
    for b in pubkey {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse a `0x`-prefixed-or-bare 128-hex node id into 64 bytes. Panic-free —
/// `None` on any malformed input (cache files are semi-trusted on disk).
fn parse_pubkey(hex: &str) -> Option<[u8; 64]> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    if hex.len() != 128 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> [u8; 64] {
        [n; 64]
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = std::env::temp_dir().join(format!("myotis-elcache-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("peers.cache");
        let _ = fs::remove_file(&path);

        let mut c = ElPeerCache::load(path.clone());
        let a: SocketAddr = "1.2.3.4:30303".parse().unwrap();
        let b: SocketAddr = "5.6.7.8:30304".parse().unwrap();
        c.add(a, &pk(0x11), true);
        c.add(b, &pk(0x22), false);
        c.record_snap_served(a); // a → Confirmed
        c.flush();

        let reloaded = ElPeerCache::load(path.clone());
        let peers = reloaded.peers();
        assert_eq!(peers.len(), 2);
        // Confirmed snap peer sorts first.
        assert_eq!(peers[0].addr, a);
        assert_eq!(peers[0].pubkey, pk(0x11));
        assert!(peers[0].snap);
        assert_eq!(peers[0].quality, SnapQuality::Confirmed);
        // Non-snap peer sorts last.
        assert_eq!(peers[1].addr, b);
        assert!(!peers[1].snap);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn denies_after_three_failures_and_reconfirms_on_serve() {
        let mut c = ElPeerCache::load(std::env::temp_dir().join("myotis-elcache-deny.cache"));
        let a: SocketAddr = "9.9.9.9:30303".parse().unwrap();
        c.add(a, &pk(1), true);
        c.record_snap_failure(a);
        c.record_snap_failure(a);
        assert_eq!(c.peers()[0].quality, SnapQuality::Unknown); // < threshold
        c.record_snap_failure(a);
        assert_eq!(c.peers()[0].quality, SnapQuality::Denied); // 3rd → denied
        c.record_snap_served(a);
        assert_eq!(c.peers()[0].quality, SnapQuality::Confirmed); // serve reconfirms
    }

    #[test]
    fn connect_failures_demote_evict_and_reset() {
        let path = std::env::temp_dir().join("myotis-elcache-connfail.cache");
        let _ = fs::remove_file(&path);
        let mut c = ElPeerCache::load(path.clone());
        let a: SocketAddr = "1.2.3.4:30303".parse().unwrap();
        c.add(a, &pk(1), true);
        c.record_snap_served(a); // Confirmed

        // Below the demote threshold the learned verdict shows through.
        for _ in 0..CONNECT_FAILURE_DEMOTE - 1 {
            c.record_connect_failure(a);
        }
        assert_eq!(c.peers()[0].quality, SnapQuality::Confirmed);
        // Crossing it reports Denied — and persists.
        c.record_connect_failure(a);
        assert_eq!(c.peers()[0].quality, SnapQuality::Denied);
        c.flush();
        let reloaded = ElPeerCache::load(path.clone());
        assert_eq!(reloaded.peers()[0].quality, SnapQuality::Denied);

        // A successful re-connect clears the streak and restores the verdict.
        c.add(a, &pk(1), true);
        assert_eq!(c.peers()[0].quality, SnapQuality::Confirmed);

        // Sustained unreachability evicts.
        for _ in 0..CONNECT_FAILURE_EVICT {
            c.record_connect_failure(a);
        }
        assert!(c.is_empty());
        // Unknown addresses never create entries.
        c.record_connect_failure("9.9.9.9:1".parse().unwrap());
        assert!(c.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn parses_and_rewrites_fails_token() {
        let hex = format!("0x{}", "ab".repeat(64));
        // A streak resumed from disk: 4 = one below the demote threshold.
        let text = format!("1.2.3.4\t30303\t{hex}\t1\tsnapok\tfails=4\n");
        let path = std::env::temp_dir().join("myotis-elcache-failstok.cache");
        fs::write(&path, text).unwrap();
        let mut c = ElPeerCache::load(path.clone());
        // Below the threshold the learned verdict still shows through.
        assert_eq!(c.peers()[0].quality, SnapQuality::Confirmed);
        // One more failure crosses the demote threshold → persisted, and the
        // stored snapok verdict is kept alongside the streak.
        c.record_connect_failure("1.2.3.4:30303".parse().unwrap());
        c.flush();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("\tsnapok\tfails=5\n"), "got: {body}");
        assert_eq!(c.peers()[0].quality, SnapQuality::Denied);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn parses_java_tab_format_including_quality_and_snap_flag() {
        let hex = format!("0x{}", "ab".repeat(64));
        let text = format!(
            "1.2.3.4\t30303\t{hex}\t1\tsnapok\n\
             5.6.7.8\t30304\t{hex}\t0\n\
             9.9.9.9\t30305\t{hex}\t1\tsnapbad\n"
        );
        let path = std::env::temp_dir().join("myotis-elcache-java.cache");
        fs::write(&path, text).unwrap();
        let c = ElPeerCache::load(path.clone());
        let peers = c.peers();
        assert_eq!(peers.len(), 3);
        // Confirmed first, then non-snap ranks last (after the denied snap peer).
        assert_eq!(peers[0].quality, SnapQuality::Confirmed);
        assert!(peers[0].snap);
        assert_eq!(peers[1].quality, SnapQuality::Denied);
        assert!(peers[1].snap);
        assert!(!peers[2].snap);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn migrates_legacy_colon_format() {
        let hex = "cd".repeat(64); // bare, no 0x
        let text = format!("1.2.3.4:30303:{hex}:1\n5.6.7.8:30304:{hex}\n");
        let path = std::env::temp_dir().join("myotis-elcache-legacy.cache");
        fs::write(&path, text).unwrap();
        let c = ElPeerCache::load(path.clone());
        let peers = c.peers();
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().any(|p| p.snap));
        assert!(peers.iter().any(|p| !p.snap));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn skips_malformed_lines() {
        let path = std::env::temp_dir().join("myotis-elcache-bad.cache");
        fs::write(
            &path,
            "garbage\n1.2.3.4\tnotaport\t0xdead\n1.2.3.4\t30303\tnothex\n",
        )
        .unwrap();
        let c = ElPeerCache::load(path.clone());
        assert!(c.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn disabled_cache_is_inert() {
        let mut c = ElPeerCache::disabled();
        c.add("1.2.3.4:30303".parse().unwrap(), &pk(1), true);
        c.record_snap_served("1.2.3.4:30303".parse().unwrap());
        c.flush();
        assert!(c.is_empty());
    }

    #[test]
    fn non_canonical_ip_is_matched_after_canonicalization() {
        // A non-canonical IPv6 literal in the file (uppercase + expanded) must
        // load under the SAME key a later mutate computes, so quality updates
        // land and `add` doesn't duplicate.
        let hex = format!("0x{}", "ab".repeat(64));
        let text = format!("2001:0DB8:0000:0000:0000:0000:0000:0001\t30303\t{hex}\t1\n");
        let path = std::env::temp_dir().join("myotis-elcache-canon.cache");
        fs::write(&path, text).unwrap();
        let mut c = ElPeerCache::load(path.clone());
        assert_eq!(c.len(), 1);
        // The canonical form of that address.
        let canonical: SocketAddr = "[2001:db8::1]:30303".parse().unwrap();
        c.record_snap_served(canonical);
        assert_eq!(c.peers()[0].quality, SnapQuality::Confirmed);
        // Re-adding the canonical address must NOT create a duplicate.
        c.add(canonical, &pk(0xab), true);
        assert_eq!(c.len(), 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn failure_for_unknown_peer_is_ignored() {
        // Java parity: recording a failure for a peer that was never added is a
        // no-op (doesn't create an untracked streak entry).
        let mut c = ElPeerCache::load(std::env::temp_dir().join("myotis-elcache-unknown.cache"));
        c.record_snap_failure("7.7.7.7:30303".parse().unwrap());
        c.record_snap_failure("7.7.7.7:30303".parse().unwrap());
        c.record_snap_failure("7.7.7.7:30303".parse().unwrap());
        assert!(c.is_empty());
        // Adding it now starts a fresh streak — one failure must NOT deny it.
        let a: SocketAddr = "7.7.7.7:30303".parse().unwrap();
        c.add(a, &pk(1), true);
        c.record_snap_failure(a);
        assert_eq!(c.peers()[0].quality, SnapQuality::Unknown);
    }

    #[test]
    fn written_bytes_match_the_java_line_format() {
        // Pin the exact on-disk bytes so cross-engine (Java <-> Rust) sharing
        // can't silently regress: `ip\tport\t0x<128hex>\t{1|0}[\tsnapok|snapbad]`.
        let path = std::env::temp_dir().join("myotis-elcache-bytes.cache");
        let _ = fs::remove_file(&path);
        let mut c = ElPeerCache::load(path.clone());
        c.add("1.2.3.4:30303".parse().unwrap(), &pk(0xab), true);
        c.record_snap_served("1.2.3.4:30303".parse().unwrap());
        c.add("5.6.7.8:30304".parse().unwrap(), &pk(0xcd), false);
        c.flush();
        let written = fs::read_to_string(&path).unwrap();
        let hex_ab = format!("0x{}", "ab".repeat(64));
        let hex_cd = format!("0x{}", "cd".repeat(64));
        // BTreeMap order: "1.2.3.4\t30303" < "5.6.7.8\t30304".
        assert_eq!(
            written,
            format!("1.2.3.4\t30303\t{hex_ab}\t1\tsnapok\n5.6.7.8\t30304\t{hex_cd}\t0\n")
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pubkey_hex_round_trip() {
        let p = pk(0x5a);
        assert_eq!(parse_pubkey(&pubkey_hex(&p)), Some(p));
        assert_eq!(parse_pubkey(&"5a".repeat(64)), Some(p)); // bare accepted
        assert!(parse_pubkey("0x1234").is_none());
        assert!(parse_pubkey(&"zz".repeat(64)).is_none());
    }
}
