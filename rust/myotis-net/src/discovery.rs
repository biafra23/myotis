//! discv5 peer discovery for the consensus layer — mirrors the Java
//! `ChainStack` wiring of `DiscV5Service`: seed the routing table from the
//! network's bootstrap ENRs, run iterative FINDNODE lookups, filter discovered
//! ENRs by their `eth2` field's fork digest against our accepted set (current
//! digest plus the prior fork's, when configured), and emit libp2p dial
//! candidates (TCP multiaddr + PeerId derived from the ENR's secp256k1 key).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use discv5::enr::{CombinedKey, CombinedPublicKey, EnrPublicKey, NodeId};
use discv5::{ConfigBuilder, Discv5, Enr, ListenConfig};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;

/// Consecutive lookup rounds with zero live table entries before the
/// bootstrap ENRs are re-added — the Rust twin of the Java DiscV5Service
/// empty-table re-seed (PR #135): the sigp crate seeds bootnodes exactly once
/// at spawn; if its bucket maintenance evicts them and the table drains,
/// find_node has nobody to query and nothing ever re-adds the bootnodes —
/// a terminal wedge without this. ~60 s at the 15 s lookup cadence, repeating
/// while the table stays empty (throttled for bootnode politeness, matching
/// the Java constant).
const RESEED_EMPTY_ROUNDS: u32 = 4;

/// A dialable CL peer candidate emitted by discovery.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    /// `/ip4/<ip>/tcp/<port>` (no `/p2p` suffix; the peer id travels separately).
    pub addr: Multiaddr,
}

#[derive(Clone)]
pub struct DiscoveryConfig {
    pub bootstrap_enrs: Vec<String>,
    /// Accepted `eth2` fork digests: current first, then the prior fork's when
    /// the chain configures one (`NetworkConfig.acceptedForkDigests`).
    pub accepted_fork_digests: Vec<[u8; 4]>,
    /// UDP port to bind. 0 lets the OS pick.
    pub listen_port: u16,
    /// LC-hunt escalation flag, shared with the sync loop: while `true`,
    /// lookup rounds run back-to-back (short sleep) instead of the polite
    /// steady-state cadence, so the pool fills with fresh candidates fast when
    /// the chain is starved of light-client servers. Cleared by the sync loop
    /// the moment finality flows again.
    pub hunt_boost: Arc<AtomicBool>,
}

/// Spawn the discovery task. Discovered, fork-matched peers stream out on the
/// returned channel until the receiver closes or the caller calls
/// `JoinHandle::abort()` — note that merely DROPPING the handle detaches the
/// task (it keeps running); the sync loop holds it in an abort-on-drop guard
/// for prompt UDP-socket release on shutdown. Failure to start is returned,
/// not panicked — the Java treats discv5 as non-essential the same way. The
/// returned counter tracks the TOTAL routing-table entry count (including
/// Disconnected entries), refreshed each lookup round — the status surface
/// behind the UI's "Discv5 peers" row (previously hardcoded 0 for Rust
/// chains).
pub async fn spawn(
    config: DiscoveryConfig,
    tx: mpsc::Sender<DiscoveredPeer>,
) -> Result<(tokio::task::JoinHandle<()>, Arc<AtomicUsize>), String> {
    let enr_key = CombinedKey::generate_secp256k1();
    let local_enr = Enr::builder()
        .build(&enr_key)
        .map_err(|e| format!("local ENR build failed: {e}"))?;

    let listen = ListenConfig::Ipv4 { ip: std::net::Ipv4Addr::UNSPECIFIED, port: config.listen_port };
    let discv5_config = ConfigBuilder::new(listen).build();
    let mut discv5 = Discv5::new(local_enr, enr_key, discv5_config)
        .map_err(|e| format!("discv5 init failed: {e}"))?;

    // Keep every successfully PARSED bootstrap ENR for the empty-table
    // re-seed — including ones whose initial add_enr fails (a full bucket at
    // spawn must not permanently exclude a bootnode from recovery; only
    // malformed ENRs are dropped, with a warn).
    let mut bootnodes: Vec<Enr> = Vec::with_capacity(config.bootstrap_enrs.len());
    for enr_str in &config.bootstrap_enrs {
        match enr_str.parse::<Enr>() {
            Ok(enr) => {
                if let Err(e) = discv5.add_enr(enr.clone()) {
                    tracing::warn!(error = e, "bootstrap ENR not added to table (kept for re-seed)");
                }
                bootnodes.push(enr);
            }
            Err(e) => tracing::warn!(error = %e, "skipping malformed bootstrap ENR"),
        }
    }

    discv5
        .start()
        .await
        .map_err(|e| format!("discv5 start failed: {e}"))?;
    tracing::info!(bootnodes = bootnodes.len(), port = config.listen_port, "discv5 started");

    let table_size = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_lookups(
        discv5,
        config.accepted_fork_digests,
        bootnodes,
        Arc::clone(&table_size),
        config.hunt_boost,
        tx,
    ));
    Ok((task, table_size))
}

async fn run_lookups(
    discv5: Discv5,
    accepted_digests: Vec<[u8; 4]>,
    bootnodes: Vec<Enr>,
    table_size: Arc<AtomicUsize>,
    hunt_boost: Arc<AtomicBool>,
    tx: mpsc::Sender<DiscoveredPeer>,
) {
    let mut seen: HashSet<NodeId> = HashSet::new();
    let mut empty_rounds = 0u32;
    loop {
        match discv5.find_node(NodeId::random()).await {
            Ok(enrs) => {
                let mut emitted = 0usize;
                for enr in enrs {
                    if !seen.insert(enr.node_id()) {
                        continue;
                    }
                    if let Some(peer) = filter_candidate(&enr, &accepted_digests) {
                        emitted += 1;
                        if tx.send(peer).await.is_err() {
                            return; // receiver gone — sync loop shut down
                        }
                    }
                }
                tracing::debug!(emitted, known = seen.len(), "discv5 lookup round complete");
            }
            Err(e) => tracing::debug!(error = %e, "discv5 lookup failed"),
        }

        // Status metric: TOTAL routing-table entries (never a misleading 0
        // during a connectivity blip that flips entries Disconnected-in-place).
        // The re-seed trigger below deliberately uses the stricter
        // connected_peers() == 0 — the Java twin keys on live==0 the same way.
        table_size.store(discv5.table_entries_id().len(), Ordering::Relaxed);
        let live = discv5.connected_peers();
        if reseed_due(&mut empty_rounds, live, bootnodes.len()) {
            // add_enr alone is PASSIVE and rejected outright when the target
            // bucket is full of dead Disconnected entries (sigp only evicts on
            // a Connected-status insert) — so also PING every bootnode, the
            // active path the Java re-seed uses: one Pong drives the
            // Connected insert that evicts a dead entry and refills a bucket.
            let mut readded = 0usize;
            for enr in &bootnodes {
                if discv5.add_enr(enr.clone()).is_ok() {
                    readded += 1;
                }
                let ping = discv5.send_ping(enr.clone());
                tokio::spawn(async move {
                    let _ = ping.await; // fire-and-forget; failure is expected noise
                });
            }
            // A recovered table must also REFILL the sync pool: without this,
            // every re-found peer fails the seen-dedup and is never re-emitted
            // (emission is once-ever per NodeId), leaving the pool starved
            // even after a successful re-seed.
            seen.clear();
            tracing::info!(pinged = bootnodes.len(), readded, rounds = RESEED_EMPTY_ROUNDS,
                "discv5 live table empty — pinged bootnodes and cleared the dedup set");
        }

        if tx.is_closed() {
            return;
        }
        // LC hunt: when the sync loop is starved of light-client servers it
        // flips hunt_boost and lookups run near back-to-back — each random-
        // target FINDNODE walks a different DHT region, so cadence is the
        // enumeration throttle. 15 s is the polite steady-state.
        let pause = if hunt_boost.load(Ordering::Relaxed) { 2 } else { 15 };
        tokio::time::sleep(std::time::Duration::from_secs(pause)).await;
        // Bound the dedup set: discovery on mainnet finds thousands of nodes.
        if seen.len() > 16_384 {
            seen.clear();
        }
    }
}

/// The stateful counter step behind the empty-table re-seed — the Rust twin
/// of the Java `DiscV5Service.reseedDue` and pinned by the same test shape:
/// any live node resets the streak; with no bootnodes a re-seed is never due
/// (nothing to add); otherwise due on every `RESEED_EMPTY_ROUNDS`-th
/// consecutive empty round, resetting when due so a persistent wedge keeps
/// re-seeding instead of firing once.
fn reseed_due(empty_rounds: &mut u32, live_nodes: usize, bootnode_count: usize) -> bool {
    if live_nodes > 0 || bootnode_count == 0 {
        *empty_rounds = 0;
        return false;
    }
    *empty_rounds += 1;
    if *empty_rounds < RESEED_EMPTY_ROUNDS {
        return false;
    }
    *empty_rounds = 0;
    true
}

/// ENR → dial candidate, applying the same gates the Java discv5 callback does:
/// must carry an `eth2` field whose fork digest is in our accepted set, a TCP
/// endpoint, and a secp256k1 key we can turn into a libp2p PeerId.
fn filter_candidate(enr: &Enr, accepted_digests: &[[u8; 4]]) -> Option<DiscoveredPeer> {
    let digest = enr_eth2_fork_digest(enr)?;
    let match_idx = accepted_digests.iter().position(|d| *d == digest)?;

    let (ip, tcp_port): (IpAddr, u16) = if let (Some(ip4), Some(tcp4)) = (enr.ip4(), enr.tcp4()) {
        (IpAddr::V4(ip4), tcp4)
    } else if let (Some(ip6), Some(tcp6)) = (enr.ip6(), enr.tcp6()) {
        (IpAddr::V6(ip6), tcp6)
    } else {
        return None;
    };

    let peer_id = enr_to_peer_id(enr)?;
    let addr = Multiaddr::empty()
        .with(ip.into())
        .with(libp2p::multiaddr::Protocol::Tcp(tcp_port));
    tracing::debug!(peer = %peer_id, %addr, prior_fork = match_idx > 0, "CL peer discovered");
    Some(DiscoveredPeer { peer_id, addr })
}

/// First 4 bytes of the ENR `eth2` field (SSZ `ENRForkID`: fork_digest(4) ||
/// next_fork_version(4) || next_fork_epoch(8)). The field value is an
/// RLP-encoded byte string inside the record; strip the string header by hand
/// (a 16-byte payload is `0x90 || bytes`, but tolerate any short-string form).
fn enr_eth2_fork_digest(enr: &Enr) -> Option<[u8; 4]> {
    let raw = enr.get_raw_rlp(b"eth2")?;
    let payload = rlp_short_string_payload(raw)?;
    if payload.len() < 4 {
        return None;
    }
    Some(payload[..4].try_into().expect("length checked"))
}

/// Decode a single RLP short string (the only shape an `eth2` field takes).
fn rlp_short_string_payload(raw: &[u8]) -> Option<&[u8]> {
    let first = *raw.first()?;
    match first {
        0x00..=0x7F => Some(&raw[..1]),
        0x80..=0xB7 => {
            let len = (first - 0x80) as usize;
            raw.get(1..1 + len)
        }
        _ => None, // long string / list — not a valid eth2 field
    }
}

/// Derive the libp2p PeerId from the ENR's secp256k1 public key (compressed
/// SEC1 bytes → libp2p secp256k1 public key → PeerId).
fn enr_to_peer_id(enr: &Enr) -> Option<PeerId> {
    match enr.public_key() {
        CombinedPublicKey::Secp256k1(pk) => {
            let compressed = pk.encode(); // 33 bytes compressed
            let pk = libp2p::identity::secp256k1::PublicKey::try_from_bytes(&compressed).ok()?;
            Some(PeerId::from(libp2p::identity::PublicKey::from(pk)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live Gnosis bootnode ENR from NetworkConfig — known to carry an eth2
    /// field (digest 0x824be431), ip4+tcp, and a secp256k1 key.
    const GNOSIS_BOOT_ENR: &str = "enr:-Ly4QIAhiTHk6JdVhCdiLwT83wAolUFo5J4nI5HrF7-zJO_QEw3cmEGxC1jvqNNUN64Vu-xxqDKSM528vKRNCehZAfEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhEFtZ5SJc2VjcDI1NmsxoQJwgL5C-30E8RJmW8gCb7sfwWvvfre7wGcCeV4X1G2wJYhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA";

    #[test]
    fn parses_eth2_field_and_peer_id_from_real_enr() {
        let enr: Enr = GNOSIS_BOOT_ENR.parse().unwrap();
        let digest = enr_eth2_fork_digest(&enr).unwrap();
        assert_eq!(digest, [0x82, 0x4B, 0xE4, 0x31]);
        assert!(enr_to_peer_id(&enr).is_some());
        // Accepted-digest filter: matches its own digest, rejects others.
        assert!(filter_candidate(&enr, &[[0x82, 0x4B, 0xE4, 0x31]]).is_some());
        assert!(filter_candidate(&enr, &[[0xDE, 0xAD, 0xBE, 0xEF]]).is_none());
        // Prior-fork fallback position also matches (index 1).
        assert!(filter_candidate(&enr, &[[0; 4], [0x82, 0x4B, 0xE4, 0x31]]).is_some());
    }

    #[test]
    fn reseed_counter_mirrors_java_discv5_reseed_test() {
        let mut c = 0u32;
        // Due on the 4th consecutive empty round.
        assert!(!reseed_due(&mut c, 0, 8));
        assert!(!reseed_due(&mut c, 0, 8));
        assert!(!reseed_due(&mut c, 0, 8));
        assert!(reseed_due(&mut c, 0, 8), "4th consecutive empty round must be due");
        // Repeats while the table stays empty (counter resets when due).
        for _ in 0..3 {
            assert!(!reseed_due(&mut c, 0, 8));
        }
        assert!(reseed_due(&mut c, 0, 8));
        // Any live node resets the streak.
        reseed_due(&mut c, 0, 8);
        reseed_due(&mut c, 0, 8);
        assert!(!reseed_due(&mut c, 5, 8), "a live table must reset the streak");
        for _ in 0..3 {
            assert!(!reseed_due(&mut c, 0, 8));
        }
        assert!(reseed_due(&mut c, 0, 8));
        // No bootnodes: never due (nothing to add — the sepolia analog).
        let mut n = 0u32;
        for i in 0..10 {
            assert!(!reseed_due(&mut n, 0, 0), "no bootnodes: never due (round {i})");
        }
    }

    #[test]
    fn rlp_short_string_forms() {
        assert_eq!(rlp_short_string_payload(&[0x42]), Some(&[0x42u8][..]));
        let mut buf = vec![0x90u8];
        buf.extend_from_slice(&[7u8; 16]);
        assert_eq!(rlp_short_string_payload(&buf), Some(&[7u8; 16][..]));
        assert_eq!(rlp_short_string_payload(&[0x90, 1, 2]), None); // truncated
        assert_eq!(rlp_short_string_payload(&[0xC1, 0x01]), None); // list
        assert_eq!(rlp_short_string_payload(&[]), None);
    }
}

// -------------------------------------------------------------------------
// Server-mode ENR: a record other nodes can find
// -------------------------------------------------------------------------

/// Load a persisted discv5 identity, or create one with owner-only permissions.
///
/// SEPARATE from the libp2p host key: discv5 and libp2p have different node
/// identities, and conflating them would publish a record whose node id does not
/// match the peer id wallets dial.
///
/// Persistence is the whole point. A fresh key per start means a new node ID, so
/// the published ENR becomes a new DHT entry with no accumulated reachability
/// and every cached record points at an identity that no longer exists. A
/// routine deploy would repeatedly un-learn the server from the network.
pub fn load_or_create_discv5_key(path: &std::path::Path) -> Result<CombinedKey, String> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating {parent:?}: {e}"))?;
        }
    }

    // create_new + 0600 in ONE call: `exists()` then write is both a race (two
    // starts each see "missing", the second clobbers a published identity) and a
    // permissions hole, since plain writes use the process umask.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            let key = CombinedKey::generate_secp256k1();
            let bytes = match &key {
                CombinedKey::Secp256k1(k) => k.to_bytes().to_vec(),
                _ => return Err("generated a non-secp256k1 discv5 key".into()),
            };
            f.write_all(&bytes)
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
            f.sync_all().map_err(|e| format!("syncing {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), "generated a new discv5 identity (0600)");
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut bytes =
                std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            CombinedKey::secp256k1_from_bytes(&mut bytes)
                .map_err(|e| format!("decoding the discv5 key in {}: {e}", path.display()))
        }
        Err(e) => Err(format!("creating {}: {e}", path.display())),
    }
}

/// Build the ENR a SERVER publishes: reachable endpoint plus the `eth2` field.
///
/// The endpoint is what makes the record listable at all — the client-side
/// record is built with no endpoint, which is why a wallet is unlistable by
/// omission rather than by configuration.
///
/// `eth2` MUST be the complete 16-byte SSZ `ENRForkID`
/// (`fork_digest || next_fork_version || next_fork_epoch`). A truncated field
/// carrying only the 4-byte digest is malformed, and standard clients reject the
/// record — so a half-filled field is worse than none.
///
/// `seq` must be persisted and monotonic across restarts. The DHT keeps the
/// highest-sequence record it has seen, so a record that does not out-rank the
/// cached one is ignored — which would make an address update silently
/// ineffective, the failure mode that matters most on a connection whose IP can
/// change.
pub fn build_server_enr(
    key: &CombinedKey,
    seq: u64,
    ip: std::net::IpAddr,
    tcp_port: u16,
    udp_port: u16,
    eth2: [u8; 16],
) -> Result<Enr, String> {
    let mut builder = Enr::builder();
    match ip {
        std::net::IpAddr::V4(v4) => {
            builder.ip4(v4).tcp4(tcp_port).udp4(udp_port);
        }
        std::net::IpAddr::V6(v6) => {
            builder.ip6(v6).tcp6(tcp_port).udp6(udp_port);
        }
    }
    builder.add_value(b"eth2".as_slice(), &eth2.as_slice());
    builder.seq(seq);
    builder.build(key).map_err(|e| format!("building the server ENR: {e}"))
}

#[cfg(test)]
mod server_enr_tests {
    use super::*;

    fn eth2_field() -> [u8; 16] {
        let mut f = [0u8; 16];
        f[..4].copy_from_slice(&[0x74, 0xd0, 0x14, 0x59]);
        f[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x00]);
        f[8..].copy_from_slice(&u64::MAX.to_le_bytes());
        f
    }

    #[test]
    fn a_server_record_carries_an_endpoint_and_the_full_eth2_field() {
        let key = CombinedKey::generate_secp256k1();
        let enr = build_server_enr(
            &key,
            7,
            "87.154.209.161".parse().unwrap(),
            9105,
            9105,
            eth2_field(),
        )
        .unwrap();

        assert_eq!(enr.seq(), 7);
        assert_eq!(enr.ip4().map(|i| i.to_string()).as_deref(), Some("87.154.209.161"));
        assert_eq!(enr.tcp4(), Some(9105));
        assert_eq!(enr.udp4(), Some(9105), "no udp means unlistable for discv5");

        // The field must round-trip through the SAME reader the client side uses
        // to filter candidates — a record we cannot read ourselves is one no
        // wallet will match either.
        assert_eq!(enr_eth2_fork_digest(&enr), Some([0x74, 0xd0, 0x14, 0x59]));

        let raw = enr.get_raw_rlp(b"eth2").expect("eth2 present");
        let payload = rlp_short_string_payload(raw).expect("rlp string");
        assert_eq!(payload.len(), 16, "a truncated eth2 field is malformed");
        assert_eq!(u64::from_le_bytes(payload[8..].try_into().unwrap()), u64::MAX);
    }

    #[test]
    fn the_persisted_key_survives_a_reload_and_keeps_the_node_id() {
        let mut path = std::env::temp_dir();
        path.push(format!("roost-discv5-key-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // Compare NODE IDs, which is the thing the DHT indexes on and the thing
        // a restart must not change.
        let node_id = |k: &CombinedKey| {
            build_server_enr(k, 1, "1.2.3.4".parse().unwrap(), 1, 1, eth2_field())
                .unwrap()
                .node_id()
        };
        let first = node_id(&load_or_create_discv5_key(&path).unwrap());
        let second = node_id(&load_or_create_discv5_key(&path).unwrap());
        assert_eq!(
            first, second,
            "a restart that changes the node id un-learns the server from every peer"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a world-readable identity can be impersonated");
        }
        std::fs::remove_file(&path).ok();
    }
}
