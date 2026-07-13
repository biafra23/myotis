//! CL peer cache — the Rust reader/writer of the SAME `cl-peers[-net].cache`
//! file the Java hosts maintain (`AndroidCLPeerCache` / `app CLPeerCache`), so
//! proven light-client servers survive restarts AND engine switches.
//!
//! Format (tab-separated UTF-8 lines, one peer per line, only lines starting
//! with `/` are peers):
//!
//! ```text
//! multiaddr[\t<token>]...
//! ```
//!
//! Tokens (order-independent):
//!   - `<low>-<high>`  proven catch-up served sync-committee period range
//!   - `b<period>`     LightClientBootstrap period served (deepest kept)
//!   - `lc` / `nolc`   light-client protocol support confirmed / denied
//!   - bare integer    legacy floor — loaded as the degenerate range `[p, p]`
//!
//! Ranges WIDEN on merge (union), never overwrite — matching the Java parser.
//! Peers are evicted after 3 consecutive failures (Java FAILURE_THRESHOLD).
//! Writes are full rewrites of sorted lines via temp-file + rename; best-effort
//! (a lost cache costs a slower next catch-up, never correctness).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const FAILURE_THRESHOLD: u32 = 3;

#[derive(Default)]
pub struct ClPeerCache {
    path: Option<PathBuf>,
    peers: Vec<String>, // insertion order; rewrite sorts (Java parity)
    served: HashMap<String, (u64, u64)>,
    bootstrap: HashMap<String, u64>,
    lc: HashSet<String>,
    nolc: HashSet<String>,
    failures: HashMap<String, u32>,
    /// Unflushed changes. Mutators only mark; [`Self::flush`] writes — so the
    /// sync loop batches one write per round instead of one per peer event.
    dirty: bool,
}

impl ClPeerCache {
    /// An inert cache (no file) — every mutator is a cheap no-op persist-wise.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Load the cache file; missing/unreadable → an empty cache bound to `path`
    /// (first save creates it). Parse is tolerant: bad lines/tokens are skipped.
    pub fn load(path: PathBuf) -> Self {
        let mut cache = Self { path: Some(path), ..Self::default() };
        let Some(p) = cache.path.clone() else { return cache };
        let Ok(text) = std::fs::read_to_string(&p) else { return cache };
        for line in text.lines() {
            let mut fields = line.trim().split('\t');
            let Some(addr) = fields.next() else { continue };
            if !addr.starts_with('/') {
                continue;
            }
            let addr = addr.to_string();
            if !cache.peers.contains(&addr) {
                cache.peers.push(addr.clone());
            }
            for tok in fields {
                if tok == "lc" {
                    cache.lc.insert(addr.clone());
                } else if tok == "nolc" {
                    cache.nolc.insert(addr.clone());
                } else if let Some(b) = tok.strip_prefix('b') {
                    if let Ok(period) = b.parse::<u64>() {
                        // Deepest kept = HIGHEST period (Java Math::max merge).
                        cache
                            .bootstrap
                            .entry(addr.clone())
                            .and_modify(|cur| *cur = (*cur).max(period))
                            .or_insert(period);
                    }
                } else if let Some((lo, hi)) = tok.split_once('-') {
                    if let (Ok(lo), Ok(hi)) = (lo.parse::<u64>(), hi.parse::<u64>()) {
                        cache.widen(&addr, lo.min(hi), lo.max(hi));
                    }
                } else if let Ok(p) = tok.parse::<u64>() {
                    cache.widen(&addr, p, p); // legacy bare floor
                }
            }
        }
        tracing::info!(
            peers = cache.peers.len(),
            catch_up_servers = cache.served.len(),
            bootstrap_peers = cache.bootstrap.len(),
            lc = cache.lc.len(),
            nolc = cache.nolc.len(),
            "loaded CL peer cache"
        );
        cache
    }

    fn widen(&mut self, addr: &str, low: u64, high: u64) {
        self.served
            .entry(addr.to_string())
            .and_modify(|r| *r = (r.0.min(low), r.1.max(high)))
            .or_insert((low, high));
    }

    /// All cached peers, best first: proven catch-up servers (WIDEST served
    /// range first), then bootstrap servers / lc-confirmed, then the rest.
    /// The served range is the accumulated UNION across responses, so width
    /// does NOT single out "generous" multi-chunk servers — a truncating
    /// server that stuck around for a whole catch-up carries a wide range too.
    /// What it does mark is the peers that demonstrably carried the most
    /// verified periods, which is the best available dial-first signal until
    /// per-response serve size is recorded. `nolc` peers are still returned
    /// (the pool tracks them separately) — the caller seeds its own sets. The
    /// pool preserves this seeding order within its tiers.
    pub fn peers(&self) -> Vec<String> {
        use std::cmp::Reverse;
        let mut out: Vec<String> = self.peers.clone();
        out.sort_by_key(|a| {
            match self.served.get(a) {
                // Tier 0, widest range first. checked_sub, not `hi - lo`: the
                // stored order is normally lo ≤ hi, but a corrupt/hand-edited
                // cache line could reverse it, and a bare subtraction would
                // underflow-panic under overflow-checks — fatal with
                // panic="abort". (Reverse, not i64 negation, likewise avoids
                // the ≥ 2^63 negation-overflow panic.)
                Some(&(lo, hi)) => (0, Reverse(hi.checked_sub(lo).unwrap_or(0))),
                None if self.bootstrap.contains_key(a) || self.lc.contains(a) => (1, Reverse(0)),
                None => (2, Reverse(0)),
            }
        });
        out
    }

    pub fn served_range(&self, addr: &str) -> Option<(u64, u64)> {
        self.served.get(addr).copied()
    }

    pub fn is_nolc(&self, addr: &str) -> bool {
        self.nolc.contains(addr)
    }

    /// A peer served VERIFIED catch-up updates for `[low, high]` (callers must
    /// only invoke this after the updates BLS/Merkle-verified and applied —
    /// the cache is shared cross-engine, so an unverified entry would poison
    /// the Java engine's peer selection too): widen its range, confirm lc,
    /// clear failures. Persists only when something actually changed, so the
    /// steady drip of repeat serves doesn't rewrite the file every round.
    pub fn record_served(&mut self, addr: &str, low: u64, high: u64) {
        let mut changed = self.ensure(addr);
        let before = self.served.get(addr).copied();
        self.widen(addr, low, high);
        changed |= self.served.get(addr).copied() != before;
        changed |= self.lc.insert(addr.to_string());
        changed |= self.nolc.remove(addr);
        self.failures.remove(addr); // in-memory streak only — not persisted
        if changed {
            self.dirty = true;
        }
    }

    /// A finality/other serve succeeded: reset the failure streak (Java resets
    /// on any successful interaction). In-memory only — no file write.
    pub fn note_success(&mut self, addr: &str) {
        self.failures.remove(addr);
    }

    /// LC-hunt confirmation: the peer answered a light-client request with a
    /// DECODABLE response (dial-priority signal only — trust still requires a
    /// verified apply, same rule as the Java fan-out harvest). Persists the
    /// `lc` token so the next start dials this peer in the lc-confirmed
    /// bucket, and clears any nolc mark/failure streak.
    pub fn mark_lc(&mut self, addr: &str) {
        let mut changed = self.ensure(addr);
        changed |= self.lc.insert(addr.to_string());
        changed |= self.nolc.remove(addr);
        self.failures.remove(addr);
        if changed {
            self.dirty = true;
        }
    }

    /// A peer served the bootstrap for `period` — deepest kept, where deepest
    /// means HIGHEST (Java `recordBootstrap` keeps the max).
    pub fn record_bootstrap(&mut self, addr: &str, period: u64) {
        let mut changed = self.ensure(addr);
        // Java parity: `if (prev != null && prev >= period) return` — keep max.
        if self.bootstrap.get(addr).is_none_or(|prev| period > *prev) {
            self.bootstrap.insert(addr.to_string(), period);
            changed = true;
        }
        self.failures.remove(addr);
        if changed {
            self.dirty = true;
        }
    }

    /// Protocol negotiation proved the peer does NOT serve LC updates. A
    /// denial NEVER demotes an lc-confirmed peer (Java parity: one transient
    /// UnsupportedProtocol must not bench a proven server); uncached peers
    /// ARE recorded, so known non-LC full nodes aren't re-probed every start.
    pub fn mark_nolc(&mut self, addr: &str) {
        if self.lc.contains(addr) {
            return;
        }
        let mut changed = self.ensure(addr);
        changed |= self.nolc.insert(addr.to_string());
        if changed {
            self.dirty = true;
        }
    }

    /// Consecutive terminal failure; evicts the peer from the cache at the
    /// threshold so the file can't fill with dead servers.
    pub fn mark_failure(&mut self, addr: &str) {
        if !self.peers.contains(&addr.to_string()) {
            return;
        }
        let n = self.failures.entry(addr.to_string()).or_insert(0);
        *n += 1;
        if *n >= FAILURE_THRESHOLD {
            let a = addr.to_string();
            self.peers.retain(|p| p != &a);
            self.served.remove(&a);
            self.bootstrap.remove(&a);
            self.lc.remove(&a);
            self.nolc.remove(&a);
            self.failures.remove(&a);
            self.dirty = true;
        }
    }

    /// Write out unflushed changes, if any. The sync loop calls this once per
    /// round (post-bootstrap / post-catch-up / post-finality-poll), so a burst
    /// of per-peer verdicts inside a round costs at most ONE synchronous
    /// few-KiB write — never one per peer event (review: no blocking I/O
    /// inside the parallel peer processing loop).
    pub fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        self.save();
        self.dirty = false;
    }

    /// Add the peer if absent; true when it was newly added.
    fn ensure(&mut self, addr: &str) -> bool {
        if self.peers.contains(&addr.to_string()) {
            return false;
        }
        self.peers.push(addr.to_string());
        true
    }

    /// Full sorted rewrite via pid-suffixed temp + rename (atomic publish; an
    /// overlapping writer from another process can't tear the temp file).
    /// Reached only through [`Self::flush`]. Best-effort: failures are logged
    /// at debug and ignored (performance cache).
    fn save(&self) {
        let Some(path) = &self.path else { return };
        let mut peers = self.peers.clone();
        peers.sort();
        let mut out = String::new();
        for p in &peers {
            out.push_str(p);
            if let Some((lo, hi)) = self.served.get(p) {
                out.push('\t');
                out.push_str(&format!("{lo}-{hi}"));
            }
            if let Some(bp) = self.bootstrap.get(p) {
                out.push('\t');
                out.push_str(&format!("b{bp}"));
            }
            if self.lc.contains(p) {
                out.push_str("\tlc");
            } else if self.nolc.contains(p) {
                out.push_str("\tnolc");
            }
            out.push('\n');
        }
        let tmp = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
        let ok = std::fs::write(&tmp, out.as_bytes())
            .and_then(|_| std::fs::rename(&tmp, path));
        if let Err(e) = ok {
            tracing::debug!(error = %e, "CL peer cache write failed (ignored)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("myotis-clcache-test-{name}-{}.cache", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn parses_java_written_tokens_and_round_trips() {
        let p = tmp_path("roundtrip");
        std::fs::write(
            &p,
            "/ip4/1.2.3.4/tcp/9000/p2p/16Uabc\t1770-1795\tb1480\tlc\n\
             /ip4/5.6.7.8/tcp/9000/p2p/16Udef\tnolc\n\
             /ip4/9.9.9.9/tcp/9000/p2p/16Ughi\t1777\n\
             # not a peer line\n",
        )
        .unwrap();
        let mut c = ClPeerCache::load(p.clone());
        assert_eq!(c.peers.len(), 3);
        assert_eq!(c.served_range("/ip4/1.2.3.4/tcp/9000/p2p/16Uabc"), Some((1770, 1795)));
        // legacy bare int → degenerate range
        assert_eq!(c.served_range("/ip4/9.9.9.9/tcp/9000/p2p/16Ughi"), Some((1777, 1777)));
        assert!(c.is_nolc("/ip4/5.6.7.8/tcp/9000/p2p/16Udef"));

        // Widen (union), persist, reload: still widened, still tokenized.
        c.record_served("/ip4/1.2.3.4/tcp/9000/p2p/16Uabc", 1760, 1780);
        c.flush();
        let c2 = ClPeerCache::load(p.clone());
        assert_eq!(c2.served_range("/ip4/1.2.3.4/tcp/9000/p2p/16Uabc"), Some((1760, 1795)));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("1760-1795"), "widened range persisted: {text}");
        assert!(text.contains("\tb1480"), "bootstrap token persisted: {text}");
        assert!(text.contains("\tnolc"), "nolc persisted: {text}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn evicts_after_three_consecutive_failures_and_resets_on_serve() {
        let p = tmp_path("evict");
        let mut c = ClPeerCache::load(p.clone());
        c.record_served("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa", 1700, 1701);
        c.mark_failure("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa");
        c.mark_failure("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa");
        // A serve resets the streak…
        c.record_served("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa", 1700, 1702);
        c.mark_failure("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa");
        c.mark_failure("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa");
        assert!(c.served_range("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa").is_some(), "2 failures survive");
        // …the third consecutive failure evicts.
        c.mark_failure("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa");
        assert!(c.served_range("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa").is_none());
        c.flush();
        assert!(ClPeerCache::load(p.clone()).peers.is_empty(), "eviction persisted");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn nolc_never_demotes_confirmed_but_is_recorded_for_uncached() {
        let p = tmp_path("nolc");
        let mut c = ClPeerCache::load(p.clone());
        // Proven server: one transient UnsupportedProtocol must not demote.
        c.record_served("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa", 1700, 1710);
        c.mark_nolc("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa");
        assert!(!c.is_nolc("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa"), "denial must not demote lc");
        // Uncached full node: the denial IS persisted so restarts skip it.
        c.mark_nolc("/ip4/2.2.2.2/tcp/9000/p2p/16Ubbb");
        assert!(c.is_nolc("/ip4/2.2.2.2/tcp/9000/p2p/16Ubbb"));
        c.flush();
        let c2 = ClPeerCache::load(p.clone());
        assert!(c2.is_nolc("/ip4/2.2.2.2/tcp/9000/p2p/16Ubbb"), "nolc persisted for new peer");
        assert!(!c2.is_nolc("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn bootstrap_keeps_deepest_meaning_highest_period() {
        let p = tmp_path("bmax");
        let mut c = ClPeerCache::load(p.clone());
        c.record_bootstrap("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa", 1480);
        c.record_bootstrap("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa", 1795);
        c.record_bootstrap("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa", 1600); // ignored: shallower
        c.flush();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\tb1795"), "max kept (Java parity): {text}");
        // Load-time merge of duplicate lines also keeps the max.
        std::fs::write(&p, "/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa\tb1480\n/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa\tb1795\n").unwrap();
        let c2 = ClPeerCache::load(p.clone());
        assert_eq!(c2.bootstrap.get("/ip4/1.1.1.1/tcp/9000/p2p/16Uaaa"), Some(&1795));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn ordering_prefers_proven_then_bootstrap() {
        let p = tmp_path("order");
        std::fs::write(
            &p,
            "/ip4/3.3.3.3/tcp/9000/p2p/16Uc\n\
             /ip4/2.2.2.2/tcp/9000/p2p/16Ub\tb1480\n\
             /ip4/1.1.1.1/tcp/9000/p2p/16Ua\t1794-1795\tlc\n\
             /ip4/4.4.4.4/tcp/9000/p2p/16Ud\t1777-1795\tlc\n",
        )
        .unwrap();
        let c = ClPeerCache::load(p.clone());
        let order = c.peers();
        // Within the proven tier, the WIDEST served range leads — that's the
        // generous multi-chunk server that can cover a catch-up in one round.
        assert!(order[0].contains("4.4.4.4"), "widest proven first: {order:?}");
        assert!(order[1].contains("1.1.1.1"), "narrow proven second: {order:?}");
        assert!(order[2].contains("2.2.2.2"), "bootstrap third: {order:?}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn mark_lc_persists_confirms_and_clears_nolc() {
        let p = tmp_path("marklc");
        let mut c = ClPeerCache::load(p.clone());
        // A hunt confirm on a peer previously marked nolc flips it to lc.
        c.mark_nolc("/ip4/3.3.3.3/tcp/9000/p2p/16Uccc");
        c.mark_lc("/ip4/3.3.3.3/tcp/9000/p2p/16Uccc");
        assert!(!c.is_nolc("/ip4/3.3.3.3/tcp/9000/p2p/16Uccc"));
        // A brand-new hunt confirm is cached at all.
        c.mark_lc("/ip4/4.4.4.4/tcp/9000/p2p/16Uddd");
        c.flush();
        let c2 = ClPeerCache::load(p.clone());
        assert!(c2.peers().iter().any(|a| a.contains("4.4.4.4")), "hunt confirm persisted");
        assert!(!c2.is_nolc("/ip4/3.3.3.3/tcp/9000/p2p/16Uccc"), "lc flip persisted");
        // The lc token survives the round-trip: a later nolc must not demote.
        let mut c3 = c2;
        c3.mark_nolc("/ip4/4.4.4.4/tcp/9000/p2p/16Uddd");
        assert!(!c3.is_nolc("/ip4/4.4.4.4/tcp/9000/p2p/16Uddd"));
        let _ = std::fs::remove_file(&p);
    }
}
