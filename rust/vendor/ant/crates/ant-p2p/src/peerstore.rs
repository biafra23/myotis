//! On-disk peer snapshot: a JSON file at `<data-dir>/peers.json` updated
//! incrementally as peers complete the BZZ handshake, flushed every 30 s and
//! again on shutdown. Loaded at startup so the next run skips the multi-hop
//! hive bootstrap when our previous neighbourhood is still alive.
//!
//! # Why JSON, not `SQLite`
//!
//! `ant-plan.md` ultimately puts the peer table inside `SQLite` (§6, M1.1) once
//! `ant-store` exists. Until then a JSON snapshot is sufficient: writes are
//! incremental in-memory and flushed in one shot, the data is small (a few
//! hundred entries × a few hundred bytes), and atomicity is one `rename`
//! away. When the `SQLite` layer lands, this module gets replaced wholesale —
//! the public API is small enough that the swap is cheap.
//!
//! # Eviction policy
//!
//! Entries that fail to redial [`MAX_FAIL_COUNT`] consecutive times are
//! dropped. On a soft cap of [`MAX_ENTRIES`] entries we evict by oldest
//! `last_seen_unix` first. Successful handshakes reset the failure counter.

use crate::sinks::PeerHint;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Drop entries after this many consecutive redial failures. Five is a
/// trade-off: enough to ride out a flaky NAT or short outage, few enough that
/// yesterday's bootnodes don't accumulate across restarts.
const MAX_FAIL_COUNT: u32 = 5;
/// Soft cap on persisted entries. 1000 × ~250 B/entry ≈ 250 KB on disk; well
/// under any reasonable per-process budget. With `DEFAULT_TARGET_PEERS = 100`
/// this gives ~10× headroom for churn between restarts.
const MAX_ENTRIES: usize = 1000;
/// Bumped on incompatible schema changes; older / newer files are rejected
/// rather than silently mis-parsed.
const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerEntry {
    peer_id: String,
    addrs: Vec<String>,
    /// `0x`-prefixed hex of the 32-byte BZZ overlay; empty string if unknown.
    overlay: String,
    last_seen_unix: u64,
    fail_count: u32,
    /// Bee 2.8+: peer-declared unix timestamp on the signed
    /// `BzzAddress` we accepted during the last successful handshake.
    /// Zero when unknown (V14 peer or first-seen entry from a
    /// hint-only path). `#[serde(default)]` so older snapshots
    /// (written by `0.4.x`) decode cleanly into the same struct.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    bzz_timestamp: u64,
    /// Bee 2.8+: peer-declared chequebook contract address, `0x`-prefixed
    /// 20-byte hex. Empty string when the peer advertised no chequebook
    /// or we learned about them under V14. Kept as a string for forward
    /// compatibility with operator-edited snapshots.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    chequebook: String,
    /// We dialed this peer as a bootnode (`/dnsaddr/` resolution or a
    /// configured `/p2p/` multiaddr). Persisted so the next start knows
    /// it is a bootnode before (or without) resolving the bootnode list:
    /// the warm-hint pipeline dials stored peers first, and an untagged
    /// bootnode would count toward `/readiness` at once (#78).
    /// `#[serde(default)]` so older snapshots decode as "not a bootnode".
    #[serde(default, skip_serializing_if = "is_false")]
    bootnode: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    peers: Vec<PeerEntry>,
}

#[derive(Default)]
pub struct PeerStore {
    path: Option<PathBuf>,
    entries: HashMap<PeerId, EntryState>,
    dirty: bool,
}

struct EntryState {
    addrs: Vec<Multiaddr>,
    overlay: [u8; 32],
    last_seen_unix: u64,
    fail_count: u32,
    /// Bee 2.8+ signed timestamp from the last successful handshake.
    /// Zero when not yet seen on a V15 handshake.
    bzz_timestamp: u64,
    /// Bee 2.8+ chequebook address from the last successful handshake.
    /// `None` for V14 peers and for V15 peers with an empty
    /// chequebook field.
    chequebook: Option<[u8; 20]>,
    /// See [`PeerEntry::bootnode`].
    bootnode: bool,
}

impl PeerStore {
    /// A no-op store, returned when the operator passes `--no-peerstore`.
    /// All mutations are silently dropped; `warm_hints` returns empty.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Load `path` if it exists. On read / decode / version mismatch we start
    /// with an empty in-memory state and mark the store dirty so the next
    /// flush overwrites the bad file. Running without a peerstore is a
    /// degraded-but-safe mode: we never propagate I/O failures from here.
    pub fn load(path: PathBuf) -> Self {
        let raw = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self {
                    path: Some(path),
                    entries: HashMap::new(),
                    dirty: false,
                };
            }
            Err(e) => {
                warn!(target: "ant_p2p::peerstore", "read {path:?}: {e}");
                return Self {
                    path: Some(path),
                    entries: HashMap::new(),
                    dirty: false,
                };
            }
        };
        let snap: Snapshot = match serde_json::from_slice(&raw) {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "ant_p2p::peerstore", "decode {path:?}: {e}; starting fresh");
                return Self {
                    path: Some(path),
                    entries: HashMap::new(),
                    dirty: true,
                };
            }
        };
        if snap.version != SNAPSHOT_VERSION {
            warn!(
                target: "ant_p2p::peerstore",
                "{path:?} version {} != {SNAPSHOT_VERSION}; starting fresh",
                snap.version,
            );
            return Self {
                path: Some(path),
                entries: HashMap::new(),
                dirty: true,
            };
        }
        let mut entries = HashMap::with_capacity(snap.peers.len());
        for p in snap.peers {
            let Ok(peer_id) = p.peer_id.parse::<PeerId>() else {
                continue;
            };
            let addrs: Vec<Multiaddr> = p.addrs.iter().filter_map(|s| s.parse().ok()).collect();
            if addrs.is_empty() {
                continue;
            }
            let mut overlay = [0u8; 32];
            if !p.overlay.is_empty() {
                let hex_str = p.overlay.strip_prefix("0x").unwrap_or(&p.overlay);
                if hex::decode_to_slice(hex_str, &mut overlay).is_err() {
                    overlay = [0u8; 32];
                }
            }
            let chequebook = if p.chequebook.is_empty() {
                None
            } else {
                let mut buf = [0u8; 20];
                let hex_str = p.chequebook.strip_prefix("0x").unwrap_or(&p.chequebook);
                match hex::decode_to_slice(hex_str, &mut buf) {
                    Ok(()) => Some(buf),
                    Err(_) => None,
                }
            };
            entries.insert(
                peer_id,
                EntryState {
                    addrs,
                    overlay,
                    last_seen_unix: p.last_seen_unix,
                    fail_count: p.fail_count,
                    bzz_timestamp: p.bzz_timestamp,
                    chequebook,
                    bootnode: p.bootnode,
                },
            );
        }
        debug!(
            target: "ant_p2p::peerstore",
            "loaded {} entries from {path:?}",
            entries.len(),
        );
        Self {
            path: Some(path),
            entries,
            dirty: false,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn contains(&self, peer_id: &PeerId) -> bool {
        self.entries.contains_key(peer_id)
    }

    /// Convert loaded entries into hints for the dial pipeline, ordered by
    /// most-recent-success first. Most-recently-seen peers are most likely to
    /// still be reachable, so dial them ahead of cold bootnodes.
    pub fn warm_hints(&self) -> Vec<PeerHint> {
        let mut entries: Vec<(&PeerId, &EntryState)> = self.entries.iter().collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.1.last_seen_unix));
        entries
            .into_iter()
            .map(|(peer_id, e)| PeerHint {
                peer_id: *peer_id,
                addrs: e.addrs.clone(),
                overlay: e.overlay,
            })
            .collect()
    }

    /// Stamp `peer_id` as healthy after a successful BZZ handshake.
    /// `bzz_timestamp` and `chequebook` come from the V15 handshake
    /// fields; pass `0` and `None` for V14 peers (the snapshot keeps
    /// them at their existing values so a V15 handshake earlier in
    /// the session isn't downgraded by a subsequent V14 reconnect).
    pub fn record_success(
        &mut self,
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
        overlay: [u8; 32],
        bzz_timestamp: u64,
        chequebook: Option<[u8; 20]>,
    ) {
        if self.path.is_none() {
            return;
        }
        let entry = self.entries.entry(peer_id).or_insert_with(|| EntryState {
            addrs: Vec::new(),
            overlay,
            last_seen_unix: 0,
            fail_count: 0,
            bzz_timestamp: 0,
            chequebook: None,
            bootnode: false,
        });
        if !addrs.is_empty() {
            entry.addrs = addrs;
        }
        entry.overlay = overlay;
        entry.last_seen_unix = unix_now();
        entry.fail_count = 0;
        // Don't downgrade V15 info to V14. If the new handshake brought
        // fresh fields, take them; if it was V14 (`0` / `None`), keep
        // whatever we previously knew.
        if bzz_timestamp != 0 {
            entry.bzz_timestamp = bzz_timestamp;
        }
        if chequebook.is_some() {
            entry.chequebook = chequebook;
        }
        self.dirty = true;
    }

    /// Peers a previous run dialed as bootnodes ([`Self::mark_bootnode`]).
    /// Seeded into the swarm's bootnode set at startup, so a warm-dialed
    /// bootnode is known as one even when this run's `/dnsaddr/`
    /// resolution is slow or fails.
    pub fn bootnodes(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.entries
            .iter()
            .filter(|(_, e)| e.bootnode)
            .map(|(peer_id, _)| *peer_id)
    }

    /// Flag a stored peer as a bootnode. No-op for peers without an entry
    /// (the flag is set again when its handshake records one) and for a
    /// `disabled()` store.
    pub fn mark_bootnode(&mut self, peer_id: &PeerId) {
        if let Some(entry) = self.entries.get_mut(peer_id) {
            if !entry.bootnode {
                entry.bootnode = true;
                self.dirty = true;
            }
        }
    }

    /// Record a redial / handshake failure for an entry. No-op for peers we
    /// don't know about: hint-only peers don't earn an entry until they
    /// complete a handshake at least once.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        if self.path.is_none() {
            return;
        }
        let Some(entry) = self.entries.get_mut(peer_id) else {
            return;
        };
        entry.fail_count = entry.fail_count.saturating_add(1);
        self.dirty = true;
        if entry.fail_count >= MAX_FAIL_COUNT {
            self.entries.remove(peer_id);
            debug!(
                target: "ant_p2p::peerstore",
                %peer_id,
                "evicted after {MAX_FAIL_COUNT} consecutive failures",
            );
        }
    }

    /// Drop every entry, remove the on-disk file if any, and mark the store
    /// clean. Used by the live `antctl peers reset` control command and by
    /// `antd --reset-peerstore` at startup.
    ///
    /// Returns the number of entries that were evicted so the caller can log
    /// a human-meaningful summary. No-op for a `disabled()` store.
    pub fn clear(&mut self) -> usize {
        let evicted = self.entries.len();
        self.entries.clear();
        self.dirty = false;
        if let Some(path) = self.path.as_ref() {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    debug!(
                        target: "ant_p2p::peerstore",
                        "cleared peerstore at {path:?} ({evicted} entries dropped)",
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    warn!(
                        target: "ant_p2p::peerstore",
                        "unlink {path:?} during clear: {e}",
                    );
                }
            }
        }
        evicted
    }

    /// Persist the snapshot if anything has changed since the last flush.
    /// Errors are logged and swallowed: a transient disk-full on the snapshot
    /// is not worth tearing the node down for.
    pub fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        match self.write_atomic(&path) {
            Ok(()) => {
                self.dirty = false;
            }
            Err(e) => warn!(target: "ant_p2p::peerstore", "flush {path:?}: {e}"),
        }
    }

    fn write_atomic(&mut self, path: &Path) -> std::io::Result<()> {
        if self.entries.len() > MAX_ENTRIES {
            let excess = self.entries.len() - MAX_ENTRIES;
            let mut by_age: Vec<(PeerId, u64)> = self
                .entries
                .iter()
                .map(|(p, e)| (*p, e.last_seen_unix))
                .collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (p, _) in by_age.into_iter().take(excess) {
                self.entries.remove(&p);
            }
        }

        let snap = Snapshot {
            version: SNAPSHOT_VERSION,
            peers: self
                .entries
                .iter()
                .map(|(peer_id, e)| PeerEntry {
                    peer_id: peer_id.to_string(),
                    addrs: e
                        .addrs
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect(),
                    overlay: format!("0x{}", hex::encode(e.overlay)),
                    last_seen_unix: e.last_seen_unix,
                    fail_count: e.fail_count,
                    bzz_timestamp: e.bzz_timestamp,
                    chequebook: e
                        .chequebook
                        .map(|c| format!("0x{}", hex::encode(c)))
                        .unwrap_or_default(),
                    bootnode: e.bootnode,
                })
                .collect(),
        };
        let body = serde_json::to_vec(&snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic publish: write to a sibling tempfile, then rename. Rename is
        // atomic on the same filesystem, so a crash mid-flush leaves either
        // the previous good snapshot or no file at all — never a torn one.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &body)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Final flush when the store goes away. The swarm loop owns the store,
/// and neither shutdown path returns through the loop: `antd` on
/// SIGTERM returns from `main` and drops the runtime, and `ant_shutdown`
/// cancels the runtime's tasks. Both drop the loop's future, and with it
/// the store, so this is the one point both reach. Without it, up to a
/// flush interval (30 s) of peer state was lost on every shutdown.
/// It runs wherever the loop's future is dropped: `ant-ffi`'s shutdown
/// paths (C and JNI) join the runtime, so the write lands before they
/// return and can't overwrite the `peers.json` of a node re-initialised
/// on the same data dir afterwards.
/// A no-op when nothing changed or the store is disabled.
impl Drop for PeerStore {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fake_peer(seed: u8) -> PeerId {
        let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        kp.public().to_peer_id()
    }

    fn fake_addr(port: u16) -> Multiaddr {
        format!("/ip4/192.0.2.1/tcp/{port}").parse().unwrap()
    }

    #[test]
    fn load_missing_returns_empty_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::load(path.clone());
        assert_eq!(store.len(), 0);
        assert!(!path.exists(), "load must not create the file");
    }

    #[test]
    fn round_trip_via_atomic_rename() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let mut store = PeerStore::load(path.clone());
        let peer = fake_peer(7);
        store.record_success(peer, vec![fake_addr(1634)], [0xab; 32], 0, None);
        store.flush();
        assert!(path.exists());
        // Tempfile must be cleaned up by the rename.
        assert!(!path.with_extension("json.tmp").exists());

        let reloaded = PeerStore::load(path);
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.contains(&peer));
        let hints = reloaded.warm_hints();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].peer_id, peer);
        assert_eq!(hints[0].addrs, vec![fake_addr(1634)]);
        assert_eq!(hints[0].overlay, [0xab; 32]);
    }

    #[test]
    fn record_failure_evicts_after_threshold() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path);
        let peer = fake_peer(9);
        store.record_success(peer, vec![fake_addr(1634)], [0; 32], 0, None);
        for _ in 0..(MAX_FAIL_COUNT - 1) {
            store.record_failure(&peer);
            assert!(store.contains(&peer));
        }
        store.record_failure(&peer);
        assert!(!store.contains(&peer));
    }

    #[test]
    fn success_resets_failure_counter() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path);
        let peer = fake_peer(11);
        store.record_success(peer, vec![fake_addr(1634)], [0; 32], 0, None);
        for _ in 0..(MAX_FAIL_COUNT - 1) {
            store.record_failure(&peer);
        }
        store.record_success(peer, vec![fake_addr(1634)], [0; 32], 0, None);
        for _ in 0..(MAX_FAIL_COUNT - 1) {
            store.record_failure(&peer);
        }
        assert!(store.contains(&peer));
    }

    #[test]
    fn warm_hints_orders_newest_first() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path);
        let older = fake_peer(1);
        let newer = fake_peer(2);
        store.record_success(older, vec![fake_addr(1)], [0; 32], 0, None);
        // Force divergent timestamps without sleeping the whole test.
        store.entries.get_mut(&older).unwrap().last_seen_unix = 1_000;
        store.record_success(newer, vec![fake_addr(2)], [0; 32], 0, None);
        store.entries.get_mut(&newer).unwrap().last_seen_unix = 2_000;
        let hints = store.warm_hints();
        assert_eq!(hints[0].peer_id, newer);
        assert_eq!(hints[1].peer_id, older);
    }

    #[test]
    fn corrupted_file_starts_fresh_and_overwrites() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        std::fs::write(&path, b"not json").unwrap();
        let mut store = PeerStore::load(path.clone());
        assert_eq!(store.len(), 0);
        store.record_success(fake_peer(3), vec![fake_addr(1)], [0; 32], 0, None);
        store.flush();
        // The corrupted file should have been replaced with a valid snapshot.
        let raw = std::fs::read(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["version"], SNAPSHOT_VERSION);
    }

    #[test]
    fn clear_drops_entries_and_unlinks_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path.clone());
        store.record_success(fake_peer(5), vec![fake_addr(1)], [0xcd; 32], 0, None);
        store.record_success(fake_peer(6), vec![fake_addr(2)], [0xef; 32], 0, None);
        store.flush();
        assert!(path.exists());

        let evicted = store.clear();
        assert_eq!(evicted, 2);
        assert_eq!(store.len(), 0);
        assert!(!path.exists(), "clear() must unlink the snapshot");

        // A follow-up `record_success` after `clear()` re-establishes the
        // file on the next flush — the store isn't permanently disabled.
        store.record_success(fake_peer(7), vec![fake_addr(3)], [0xab; 32], 0, None);
        store.flush();
        assert!(path.exists());
        assert_eq!(PeerStore::load(path).len(), 1);
    }

    #[test]
    fn drop_flushes_unsaved_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let peer = fake_peer(9);
        {
            let mut store = PeerStore::load(path.clone());
            store.record_success(peer, vec![fake_addr(1635)], [0x12; 32], 0, None);
            // No explicit flush: the loop's timer hasn't fired yet when
            // the node shuts down.
        }
        assert!(
            PeerStore::load(path).contains(&peer),
            "dropping the store must persist it"
        );
    }

    #[test]
    fn drop_after_clear_does_not_resurrect_the_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        {
            let mut store = PeerStore::load(path.clone());
            store.record_success(fake_peer(4), vec![fake_addr(1)], [0x34; 32], 0, None);
            store.flush();
            store.clear();
        }
        assert!(!path.exists(), "a reset must survive the final flush");
    }

    #[test]
    fn clear_on_disabled_store_is_noop() {
        let mut store = PeerStore::disabled();
        assert_eq!(store.clear(), 0);
    }

    #[test]
    fn loads_legacy_snapshot_without_v15_fields() {
        // Simulate a snapshot written by ant 0.4.x — no bzz_timestamp,
        // no chequebook. `serde(default)` must let it parse cleanly.
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let legacy = format!(
            "{{\"version\":{SNAPSHOT_VERSION},\"peers\":[{{\
\"peer_id\":\"{}\",\"addrs\":[\"/ip4/192.0.2.1/tcp/1\"],\
\"overlay\":\"0xab0000000000000000000000000000000000000000000000000000000000ab00\",\
\"last_seen_unix\":1234,\"fail_count\":0}}]}}",
            fake_peer(42)
        );
        std::fs::write(&path, legacy).unwrap();
        let store = PeerStore::load(path);
        assert_eq!(store.len(), 1);
        // Defaults: timestamp 0, chequebook None.
        let e = store.entries.values().next().unwrap();
        assert_eq!(e.bzz_timestamp, 0);
        assert!(e.chequebook.is_none());
    }

    #[test]
    fn round_trip_persists_v15_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path.clone());
        let peer = fake_peer(50);
        let cb = [0xcd; 20];
        store.record_success(
            peer,
            vec![fake_addr(1)],
            [0xab; 32],
            1_715_000_000,
            Some(cb),
        );
        store.flush();

        let reloaded = PeerStore::load(path);
        let e = reloaded.entries.get(&peer).unwrap();
        assert_eq!(e.bzz_timestamp, 1_715_000_000);
        assert_eq!(e.chequebook, Some(cb));
    }

    #[test]
    fn bootnode_flag_round_trips_and_survives_record_success() {
        // A bootnode tagged in one run must still be known as one on the
        // next start, before (or without) `/dnsaddr/` resolution (#78).
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path.clone());
        let boot = fake_peer(60);
        let other = fake_peer(61);
        store.mark_bootnode(&boot); // no entry yet: no-op
        assert_eq!(store.bootnodes().count(), 0);
        store.record_success(boot, vec![fake_addr(1)], [0; 32], 0, None);
        store.record_success(other, vec![fake_addr(2)], [0; 32], 0, None);
        store.mark_bootnode(&boot);
        // A later handshake doesn't clear the flag.
        store.record_success(boot, vec![fake_addr(1)], [0; 32], 0, None);
        store.flush();

        let reloaded = PeerStore::load(path);
        assert_eq!(reloaded.bootnodes().collect::<Vec<_>>(), vec![boot]);
    }

    #[test]
    fn v14_handshake_after_v15_keeps_chequebook() {
        // Once we've learned a peer's chequebook over a V15 handshake,
        // a subsequent V14 reconnect (passing `None`) must not erase it.
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::load(path);
        let peer = fake_peer(51);
        let cb = [0xef; 20];
        store.record_success(peer, vec![fake_addr(1)], [0; 32], 1_715_000_000, Some(cb));
        store.record_success(peer, vec![fake_addr(1)], [0; 32], 0, None);
        let e = store.entries.get(&peer).unwrap();
        assert_eq!(e.bzz_timestamp, 1_715_000_000);
        assert_eq!(e.chequebook, Some(cb));
    }

    #[test]
    fn disabled_store_is_silent() {
        let mut store = PeerStore::disabled();
        store.record_success(fake_peer(0), vec![fake_addr(1)], [0; 32], 0, None);
        store.record_failure(&fake_peer(0));
        store.flush();
        assert_eq!(store.len(), 0);
        assert!(store.warm_hints().is_empty());
    }
}
