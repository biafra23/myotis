//! discv5 peer discovery for the consensus layer — mirrors the Java
//! `ChainStack` wiring of `DiscV5Service`: seed the routing table from the
//! network's bootstrap ENRs, run iterative FINDNODE lookups, filter discovered
//! ENRs by their `eth2` field's fork digest against our accepted set (current
//! digest plus the prior fork's, when configured), and emit libp2p dial
//! candidates (TCP multiaddr + PeerId derived from the ENR's secp256k1 key).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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
        tx,
    ));
    Ok((task, table_size))
}

async fn run_lookups(
    discv5: Discv5,
    accepted_digests: Vec<[u8; 4]>,
    bootnodes: Vec<Enr>,
    table_size: Arc<AtomicUsize>,
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
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
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
