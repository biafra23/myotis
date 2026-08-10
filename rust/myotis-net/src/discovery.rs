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
    /// libp2p ids of the chain's PINNED peers (the static-peer list). Lookups
    /// walk TOWARD these ids first — O(log n) convergence — instead of hoping a
    /// random walk lands in their bucket, which on the mainnet DHT it rarely
    /// does. This is what lets a STALE static-peer address heal in seconds: the
    /// server (roost) signs its current endpoint into its ENR under the same
    /// secp256k1 key its libp2p peer id encodes, so its discv5 node id is
    /// DERIVABLE from the pin (`node_id_for_peer`) and the record third-party
    /// tables return is verifiable — a wrong key cannot produce this peer id.
    pub pinned_peer_ids: Vec<PeerId>,
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

    let bootnodes = seed_bootnodes(&discv5, &config.bootstrap_enrs);

    discv5
        .start()
        .await
        .map_err(|e| format!("discv5 start failed: {e}"))?;
    // Pinned ids whose discv5 node id is derivable get TARGETED lookups; the
    // rest (non-secp256k1 ids, if any ever appear) silently fall back to being
    // findable only by the random walk, which is what they were before.
    let pinned_targets: Vec<NodeId> = config
        .pinned_peer_ids
        .iter()
        .filter_map(node_id_for_peer)
        .collect();
    tracing::info!(
        bootnodes = bootnodes.len(),
        pinned_targets = pinned_targets.len(),
        port = config.listen_port,
        "discv5 started"
    );

    let table_size = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_lookups(
        discv5,
        config.accepted_fork_digests,
        bootnodes,
        pinned_targets,
        Arc::clone(&table_size),
        config.hunt_boost,
        tx,
    ));
    Ok((task, table_size))
}

/// Parse the bootstrap ENRs and add them to the routing table, keeping every
/// successfully PARSED one for the empty-table re-seed — including ones whose
/// initial `add_enr` fails (a full bucket at spawn must not permanently exclude
/// a bootnode from recovery; only malformed ENRs are dropped, with a warn).
/// The discv5 node id a pinned libp2p peer will present, derived from the peer
/// id alone.
///
/// Works because secp256k1 libp2p peer ids are IDENTITY-multihashed protobuf
/// public keys (33 compressed bytes inline), and roost deliberately signs its
/// ENR with its libp2p host key — one key, two identities, so the discv5 id is
/// keccak256 of the same point. `None` for peer ids that don't inline a
/// secp256k1 key (sha256-multihashed RSA/ed25519 ids can't be reversed).
pub fn node_id_for_peer(peer_id: &PeerId) -> Option<NodeId> {
    let mh = libp2p::multihash::Multihash::from(*peer_id);
    if mh.code() != 0x00 {
        return None; // not identity-hashed: the key is not recoverable
    }
    let key = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    let secp = key.try_into_secp256k1().ok()?;
    let vk = discv5::enr::k256::ecdsa::VerifyingKey::from_sec1_bytes(&secp.to_bytes()).ok()?;
    Some(NodeId::from(vk))
}

fn seed_bootnodes(discv5: &Discv5, bootstrap_enrs: &[String]) -> Vec<Enr> {
    let mut bootnodes: Vec<Enr> = Vec::with_capacity(bootstrap_enrs.len());
    for enr_str in bootstrap_enrs {
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
    bootnodes
}

/// Every Nth steady-state round revisits one pinned target (after the opening
/// rounds visited each once). Between visits the random walk enumerates the
/// wider DHT exactly as before — pinned targets ride alongside, they don't
/// displace enumeration.
const PINNED_ROUND_EVERY: usize = 4;

async fn run_lookups(
    discv5: Discv5,
    accepted_digests: Vec<[u8; 4]>,
    bootnodes: Vec<Enr>,
    pinned_targets: Vec<NodeId>,
    table_size: Arc<AtomicUsize>,
    hunt_boost: Arc<AtomicBool>,
    tx: mpsc::Sender<DiscoveredPeer>,
) {
    let mut seen: HashSet<NodeId> = HashSet::new();
    // Last emitted ENR sequence number per PINNED id. A pinned server may be
    // re-found on every targeted round, but only a STRICTLY newer record — a
    // genuine republication, e.g. after an address change — re-emits. Gating on
    // seq (not on "address differs") also means a laggard or adversarial table
    // serving an OLDER record can never flap a pinned peer's pooled address
    // backward (#348 review).
    let mut pinned_seq: std::collections::HashMap<NodeId, u64> = std::collections::HashMap::new();
    let mut empty_rounds = 0u32;
    let mut round: usize = 0;
    loop {
        // The FIRST rounds walk toward each pinned server id in turn — that is
        // the startup fast path (O(log n) hops instead of random-walk luck) —
        // then every PINNED_ROUND_EVERY-th round revisits one, which is what
        // heals a stale pinned ADDRESS: third-party tables return the server's
        // current signed ENR and, when its seq has advanced, the emission
        // below re-feeds the pool.
        let target = if pinned_targets.is_empty() {
            NodeId::random()
        } else if round < pinned_targets.len() {
            pinned_targets[round]
        } else if round % PINNED_ROUND_EVERY == 0 {
            pinned_targets[(round / PINNED_ROUND_EVERY) % pinned_targets.len()]
        } else {
            NodeId::random()
        };
        round = round.wrapping_add(1);
        match discv5.find_node(target).await {
            Ok(enrs) => {
                let mut emitted = 0usize;
                for enr in enrs {
                    if pinned_targets.contains(&enr.node_id()) {
                        // Pinned ids bypass the once-ever dedup, but only on a
                        // record NEWER than the last one emitted.
                        match pinned_seq.get(&enr.node_id()) {
                            Some(&last) if enr.seq() <= last => continue,
                            _ => {
                                pinned_seq.insert(enr.node_id(), enr.seq());
                                seen.insert(enr.node_id());
                            }
                        }
                    } else if !seen.insert(enr.node_id()) {
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
            let readded = reseed(&discv5, &bootnodes);
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

/// Re-seed the routing table from the bootnodes, returning how many `add_enr`
/// calls took. Shared by the client and server loops so a fix to the re-seed
/// mechanics lands in both.
///
/// add_enr alone is PASSIVE and rejected outright when the target bucket is
/// full of dead Disconnected entries (sigp only evicts on a Connected-status
/// insert) — so also PING every bootnode, the active path the Java re-seed
/// uses: one Pong drives the Connected insert that evicts a dead entry and
/// refills a bucket.
fn reseed(discv5: &Discv5, bootnodes: &[Enr]) -> usize {
    let mut readded = 0usize;
    for enr in bootnodes {
        if discv5.add_enr(enr.clone()).is_ok() {
            readded += 1;
        }
        let ping = discv5.send_ping(enr.clone());
        tokio::spawn(async move {
            let _ = ping.await; // fire-and-forget; failure is expected noise
        });
    }
    readded
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

/// Derive the discv5 identity from the libp2p host key.
///
/// They MUST be the same key. In the eth2 network a node's libp2p peer id is
/// derived from the secp256k1 public key in its ENR — this crate's own
/// `enr_to_peer_id` does exactly that when turning a discovered record into a
/// dial target. Publishing a record signed by a different key would therefore
/// advertise a peer id we cannot authenticate as: every wallet that discovered
/// us would dial, fail the Noise handshake, and charge us a strike.
///
/// (An earlier version of this module generated and persisted a SEPARATE discv5
/// key, on the reasoning that conflating the two identities would be a mistake.
/// That was backwards, and roost's own client code is the proof.)
pub fn discv5_key_from_libp2p(
    keypair: &libp2p::identity::Keypair,
) -> Result<CombinedKey, String> {
    let secp = keypair
        .clone()
        .try_into_secp256k1()
        .map_err(|_| "the libp2p host key is not secp256k1 — the CL spec requires it".to_string())?;
    let mut bytes = secp.secret().to_bytes();
    CombinedKey::secp256k1_from_bytes(&mut bytes)
        .map_err(|e| format!("converting the libp2p key to a discv5 key: {e}"))
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

    /// THE property: a wallet that discovers our record must derive the peer id
    /// it will actually be able to authenticate against.
    #[test]
    fn the_enr_yields_the_libp2p_peer_id_the_host_authenticates_as() {
        let host_key = libp2p::identity::Keypair::generate_secp256k1();
        let host_peer_id = PeerId::from(host_key.public());

        let enr_key = discv5_key_from_libp2p(&host_key).unwrap();
        let record = build_server_enr(
            &enr_key,
            1,
            "87.154.209.161".parse().unwrap(),
            9105,
            9105,
            eth2_field(),
        )
        .unwrap();

        assert_eq!(
            enr_to_peer_id(&record),
            Some(host_peer_id),
            "a record signed by any other key advertises a peer id we cannot authenticate as: \
             every wallet that discovers us dials, fails the Noise handshake, and charges a strike"
        );
    }

    #[test]
    fn a_non_secp256k1_host_key_is_refused_rather_than_silently_wrong() {
        let ed = libp2p::identity::Keypair::generate_ed25519();
        assert!(discv5_key_from_libp2p(&ed).is_err());
    }
}

// -------------------------------------------------------------------------
// Server-mode discv5: join the DHT, then publish the server record (#335)
// -------------------------------------------------------------------------

/// Steady-state pause between server lookup rounds.
///
/// Slower than the client's 15 s: a wallet enumerates the DHT hunting for
/// servers, while a server runs lookups only to keep its own table healthy and
/// to keep showing up in other nodes' tables — each query we send is also the
/// traffic that gets us inserted (and endpoint-proven) on the remote side.
const SERVER_LOOKUP_PAUSE: std::time::Duration = std::time::Duration::from_secs(60);

pub struct ServerDiscoveryConfig {
    /// The libp2p HOST key. The discv5 identity is derived from it so the peer
    /// id a wallet computes from the published record is the one the libp2p
    /// listener authenticates as — see [`discv5_key_from_libp2p`].
    pub keypair: libp2p::identity::Keypair,
    /// Sequence number for the initial, endpoint-less record: the caller's
    /// persisted high-water mark. NOT bumped here — nothing is published until
    /// [`ServerDiscovery::publish`], and every publish must arrive with a
    /// freshly persisted, out-ranking number.
    pub initial_seq: u64,
    /// UDP port to bind — the deployment forwards it under the same number as
    /// the TCP listener, so a single port per instance covers both.
    pub udp_port: u16,
    pub bootstrap_enrs: Vec<String>,
}

/// A running server-side discv5 node.
///
/// Starts in the JOIN-ONLY state (issue #335 step 1): the local record carries
/// no endpoint, so the node can query the DHT and populate its table but no
/// remote can insert it into theirs — unlistable by omission, exactly like the
/// wallet's client record. [`Self::publish`] is the separate, deliberate step
/// that makes the node findable.
///
/// `enr_update` is DISABLED on the underlying service: sigp's IP-voting would
/// otherwise rewrite the record's socket (and bump its sequence number) from
/// inside the service, invisibly to the caller whose persisted sequence file is
/// supposed to be the source of truth. Every mutation of the record goes
/// through `publish`, which takes a caller-persisted sequence number.
pub struct ServerDiscovery {
    discv5: Arc<Discv5>,
    /// A second derivation of the same host key, kept for building records at
    /// publish time (the first copy is consumed by `Discv5::new`).
    record_key: CombinedKey,
    maintenance: tokio::task::JoinHandle<()>,
}

impl Drop for ServerDiscovery {
    fn drop(&mut self) {
        // The maintenance task holds an Arc<Discv5>; aborting it releases the
        // last clone so the service (and its UDP socket) shuts down promptly.
        self.maintenance.abort();
    }
}

/// Start the server discv5 node: bind UDP, seed the table, begin maintenance
/// lookups. Publishes nothing (see [`ServerDiscovery`]).
pub async fn spawn_server(config: ServerDiscoveryConfig) -> Result<ServerDiscovery, String> {
    let enr_key = discv5_key_from_libp2p(&config.keypair)?;
    let record_key = discv5_key_from_libp2p(&config.keypair)?;

    // Endpoint-less on purpose — join-only until `publish`.
    let local_enr = {
        let mut builder = Enr::builder();
        builder.seq(config.initial_seq);
        builder
            .build(&enr_key)
            .map_err(|e| format!("building the initial (endpoint-less) ENR: {e}"))?
    };

    let listen = ListenConfig::Ipv4 {
        ip: std::net::Ipv4Addr::UNSPECIFIED,
        port: config.udp_port,
    };
    let discv5_config = ConfigBuilder::new(listen).disable_enr_update().build();
    let mut discv5 = Discv5::new(local_enr, enr_key, discv5_config)
        .map_err(|e| format!("discv5 init failed: {e}"))?;

    let bootnodes = seed_bootnodes(&discv5, &config.bootstrap_enrs);

    discv5
        .start()
        .await
        .map_err(|e| format!("discv5 start failed: {e}"))?;
    tracing::info!(
        bootnodes = bootnodes.len(),
        port = config.udp_port,
        node_id = %discv5.local_enr().node_id(),
        "server discv5 started (join-only until the record is published)"
    );

    let discv5 = Arc::new(discv5);
    let maintenance = tokio::spawn(run_server_maintenance(Arc::clone(&discv5), bootnodes));
    Ok(ServerDiscovery { discv5, record_key, maintenance })
}

/// Keep the table alive and the node visible: periodic random-target lookups,
/// plus the same empty-table bootnode re-seed the client runs ([`reseed_due`]).
async fn run_server_maintenance(discv5: Arc<Discv5>, bootnodes: Vec<Enr>) {
    let mut empty_rounds = 0u32;
    loop {
        match discv5.find_node(NodeId::random()).await {
            Ok(found) => tracing::debug!(
                found = found.len(),
                table = discv5.table_entries_id().len(),
                live = discv5.connected_peers(),
                "server discv5 lookup round complete"
            ),
            Err(e) => tracing::debug!(error = %e, "server discv5 lookup failed"),
        }

        if reseed_due(&mut empty_rounds, discv5.connected_peers(), bootnodes.len()) {
            let readded = reseed(&discv5, &bootnodes);
            tracing::info!(pinged = bootnodes.len(), readded, rounds = RESEED_EMPTY_ROUNDS,
                "server discv5 live table empty — pinged bootnodes");
        }

        tokio::time::sleep(SERVER_LOOKUP_PAUSE).await;
    }
}

impl ServerDiscovery {
    /// Replace the local record with a complete server ENR — endpoint plus the
    /// full 16-byte `eth2` ENRForkID — built via [`build_server_enr`] and
    /// signed with the host key. From this moment the node is listable: every
    /// peer that talks to us learns the record and can hand it to wallets.
    ///
    /// `seq` MUST be persisted by the caller BEFORE this call (the `EnrSeq`
    /// discipline): a crash between publishing and persisting would re-issue a
    /// number the network has already seen, and the DHT ignores a record that
    /// does not out-rank the cached one. The same-rule is enforced here against
    /// the CURRENT record — a non-out-ranking sequence number is refused rather
    /// than published into silence.
    ///
    /// Returns the published record's base64 form, for the operator's log.
    pub fn publish(
        &self,
        seq: u64,
        ip: IpAddr,
        tcp_port: u16,
        udp_port: u16,
        eth2: [u8; 16],
    ) -> Result<String, String> {
        let record = build_server_enr(&self.record_key, seq, ip, tcp_port, udp_port, eth2)?;
        // The shared handle is the SAME Arc the running service answers
        // handshakes and NODES responses from (`Discv5::external_enr` — "useful
        // for synchronising views of the local ENR outside of Discv5"), so the
        // swap is visible to peers on their next exchange. Safe to replace
        // wholesale because `disable_enr_update` above makes this the only
        // writer, and the key (therefore the node id) never changes.
        let shared = self.discv5.external_enr();
        let mut current = shared.write();
        if record.node_id() != current.node_id() {
            return Err("record node id changed — the signing key must be the host key".into());
        }
        if record.seq() <= current.seq() {
            return Err(format!(
                "sequence {} does not out-rank the current record's {} — peers would silently \
                 ignore it; the persisted sequence file has gone backwards",
                record.seq(),
                current.seq()
            ));
        }
        *current = record.clone();
        Ok(record.to_base64())
    }

    /// The current local record.
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Total routing-table entries (including Disconnected ones) — the "did the
    /// table populate?" number issue #335 step 1 asks operators to verify.
    pub fn table_entries(&self) -> usize {
        self.discv5.table_entries_id().len()
    }

    /// Peers with live sessions.
    pub fn connected_peers(&self) -> usize {
        self.discv5.connected_peers()
    }
}

#[cfg(test)]
mod server_discovery_tests {
    use super::*;

    fn eth2_field() -> [u8; 16] {
        let mut f = [0u8; 16];
        f[..4].copy_from_slice(&[0x74, 0xd0, 0x14, 0x59]);
        f[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x00]);
        f[8..].copy_from_slice(&u64::MAX.to_le_bytes());
        f
    }

    /// The full lifecycle the design describes: start join-only (endpoint-less,
    /// at the persisted sequence number), then publish a complete record, and
    /// refuse a sequence number that does not out-rank it.
    #[tokio::test]
    async fn joins_unpublished_then_publishes_only_with_an_outranking_seq() {
        let keypair = libp2p::identity::Keypair::generate_secp256k1();
        let host_peer_id = PeerId::from(keypair.public());
        let sd = spawn_server(ServerDiscoveryConfig {
            keypair,
            initial_seq: 41,
            udp_port: 0, // OS-assigned: tests must not fight over a port
            bootstrap_enrs: vec![],
        })
        .await
        .expect("server discv5 starts");

        // Join-only: no endpoint, so no remote can list us — and the sequence
        // number is the caller's persisted value, not a restart at 1.
        let initial = sd.local_enr();
        assert_eq!(initial.seq(), 41);
        assert!(initial.ip4().is_none() && initial.udp4().is_none(), "join-only means endpoint-less");

        // A stale (equal) sequence number must be refused, not published into
        // silence: the DHT keeps the highest-sequence record it has seen.
        let ip: IpAddr = "87.154.209.161".parse().unwrap();
        assert!(sd.publish(41, ip, 9105, 9105, eth2_field()).is_err());

        let b64 = sd.publish(42, ip, 9105, 9105, eth2_field()).expect("out-ranking seq publishes");
        assert!(b64.starts_with("enr:"));

        let published = sd.local_enr();
        assert_eq!(published.seq(), 42);
        assert_eq!(published.ip4().map(|i| i.to_string()).as_deref(), Some("87.154.209.161"));
        assert_eq!(published.tcp4(), Some(9105));
        assert_eq!(published.udp4(), Some(9105));
        // The record a wallet discovers must filter and dial exactly as the
        // client side does — same digest reader, same peer-id derivation.
        assert_eq!(enr_eth2_fork_digest(&published), Some([0x74, 0xd0, 0x14, 0x59]));
        assert_eq!(enr_to_peer_id(&published), Some(host_peer_id));

        // Re-publication (address change) keeps working: bump again, new IP.
        let moved: IpAddr = "87.154.210.7".parse().unwrap();
        sd.publish(43, moved, 9105, 9105, eth2_field()).expect("address change re-publishes");
        assert_eq!(sd.local_enr().ip4().map(|i| i.to_string()).as_deref(), Some("87.154.210.7"));
    }
}
