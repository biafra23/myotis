//! Live-network integration tests for EL-A3 discv4: bond with a network's
//! real bootnodes and learn nodes beyond them, and a per-bootnode census of
//! the shipped seed list.
//!
//! Ignored by default (needs outbound UDP to the bootnodes). Run with:
//!
//! ```bash
//! NET=sepolia cargo test -p myotis-net --test live_discv4 -- --ignored --nocapture
//! ```
//!
//! `NET` is `mainnet` (the default), `sepolia` or `gnosis`. The census is the
//! one whose OUTPUT you read when re-syncing a list from go-ethereum's
//! `params/bootnodes.go`: it says which entries answered from this host. A
//! silent entry is a statement about this host's path to it as much as about
//! the node — confirm from a second network before pruning one.
//!
//! What the census cannot see: discv4 carries no network id, so an entry
//! pinned with ANOTHER network's port (the EF NodeOps hosts run one bootnode
//! per network, on neighbouring ports) answers and hands out neighbours all
//! the same. Only decoding the upstream ENR catches that; the pin tests in
//! `el/reader.rs` hold the decoded values.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{Discv4Config, Discv4Service, TableEntry};
use myotis_net::el::reader::ElConfig;

/// How long one bootnode gets to answer the cold ping and hand out Neighbors.
/// A healthy one bonds in well under a second; Neighbors can only follow the
/// first refresh (10 s after start), which is when the FindNode goes out, and
/// the second (25 s) covers a lost datagram.
const CENSUS_WINDOW: Duration = Duration::from_secs(30);

/// Bootnodes that must SEED — bond and hand out at least one neighbour — for
/// discovery to count as seedable. A floor, not a clean sweep: these are
/// third-party hosts, and geth itself keeps entries it is phasing out.
const MIN_SEEDING: usize = 2;

/// The network under test and its shipped discv4 seed list — the engine
/// config, one source of truth (pinned by `mainnet_config_pins_known_values`
/// and `sepolia_config_pins_known_values`).
fn bootnodes_from_env() -> (String, Vec<SocketAddr>) {
    let net = std::env::var("NET").unwrap_or_else(|_| "mainnet".into());
    let config = match net.as_str() {
        "mainnet" => ElConfig::mainnet(),
        "sepolia" => ElConfig::sepolia(),
        "gnosis" => ElConfig::gnosis(),
        other => panic!("NET={other}: expected mainnet, sepolia or gnosis"),
    };
    (net, config.bootnodes)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: pings the network's discv4 bootnodes over UDP"]
async fn bonds_and_discovers_on_live_network() {
    init_tracing();

    let key = Arc::new(NodeKey::from_secret_bytes(&keccak256(b"myotis-live-discv4")).unwrap());
    let (net, bootnodes) = bootnodes_from_env();

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let service = Discv4Service::start(
        Arc::clone(&key),
        Discv4Config {
            bind_port: 0, // ephemeral
            bootnodes: bootnodes.clone(),
        },
        tx,
    )
    .await
    .expect("discv4 start");

    // Neighbors arrive only after the endpoint proof completes (they PING us
    // back, we PONG, they answer FindNode) — allow a couple of refresh cycles.
    // A bootnode's own bond is an event too (its Pong, then its return Ping),
    // and a list of five answering seeds would reach the count on those alone
    // before any FindNode went out: only nodes BEYOND the seed list count.
    // Nor does our own record: the refresh asks each bootnode for the nodes
    // closest to US, and a bootnode that just bonded with us tends to answer
    // with us, which `handle_neighbors` passes through unfiltered. Distinct
    // node ids, so a re-bond re-emitting the same peer is not a second find.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut discovered: HashSet<Vec<u8>> = HashSet::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(peer)) if is_bootnode(&bootnodes, &peer) => {
                eprintln!("[live_discv4] bonded with bootnode {:?}:{}", peer.ip, peer.udp_port);
            }
            Ok(Some(peer)) if is_self(&key, &peer) => {
                eprintln!("[live_discv4] a bootnode echoed our own record");
            }
            Ok(Some(peer)) => {
                if !discovered.insert(peer.node_id.clone()) {
                    continue;
                }
                let discovered = discovered.len();
                eprintln!(
                    "[live_discv4] peer #{discovered}: {:?}:{} table={}",
                    peer.ip,
                    peer.udp_port,
                    service.table_size()
                );
                if discovered >= 5 {
                    break;
                }
            }
            _ => eprintln!("[live_discv4] waiting… table={}", service.table_size()),
        }
    }

    service.stop().await;
    assert!(
        !discovered.is_empty(),
        "learned no node beyond the {net} bootnodes (and ourselves) within 60s"
    );
}

/// Whether a discovery event is this probe's own record, echoed back by a
/// bootnode answering FindNode(self).
fn is_self(key: &NodeKey, entry: &TableEntry) -> bool {
    entry.node_id == key.public_key_bytes()
}

/// Whether a discovery event is one of the configured seeds itself (matched on
/// its UDP endpoint) rather than a node learned through them.
fn is_bootnode(bootnodes: &[SocketAddr], entry: &TableEntry) -> bool {
    let ip = match entry.ip.len() {
        4 => <[u8; 4]>::try_from(&entry.ip[..]).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(&entry.ip[..]).ok().map(IpAddr::from),
        _ => None,
    };
    ip.is_some_and(|ip| bootnodes.contains(&SocketAddr::new(ip.to_canonical(), entry.udp_port)))
}

/// One bootnode's census row: when it first answered (the bond's Pong) and how
/// many OTHER nodes a service seeded from it alone learned within the window.
struct Census {
    addr: SocketAddr,
    answered_after: Option<Duration>,
    neighbours: usize,
}

/// Seed a discv4 service from a single bootnode. What it learns then starts
/// from that node's Neighbors alone; within the window the refresh also asks
/// up to ten of those for theirs, so the count is "reachable through this
/// seed", not "handed out by it". Counted as distinct node ids from the
/// events, minus the bootnode itself and minus our own record (a bootnode
/// answering FindNode(self) tends to include the asker) — not from the table,
/// whose size also moves with bucket eviction.
async fn census_one(index: usize, addr: SocketAddr) -> Census {
    // A key per probe: every service is its own node, so one bootnode's bond
    // says nothing about another's.
    let seed = keccak256(format!("myotis-live-discv4-census-{index}").as_bytes());
    let key = Arc::new(NodeKey::from_secret_bytes(&seed).unwrap());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let service = Discv4Service::start(
        Arc::clone(&key),
        Discv4Config { bind_port: 0, bootnodes: vec![addr] },
        tx,
    )
    .await
    .expect("discv4 start");

    let start = tokio::time::Instant::now();
    let mut answered_after = None;
    let mut others: HashSet<Vec<u8>> = HashSet::new();
    while start.elapsed() < CENSUS_WINDOW {
        // Keep draining for the whole window: the first event is the bond
        // (the bootnode's return Ping is a second one for the same node), the
        // later ones are the Neighbors.
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(entry)) if is_bootnode(&[addr], &entry) => {
                answered_after.get_or_insert(start.elapsed());
            }
            Ok(Some(entry)) if is_self(&key, &entry) => {}
            Ok(Some(entry)) => {
                others.insert(entry.node_id);
            }
            Ok(None) => break, // service gone: nothing more can arrive
            Err(_) => {}
        }
    }
    service.stop().await;
    Census { addr, answered_after, neighbours: others.len() }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: pings each of the network's discv4 bootnodes over UDP"]
async fn each_bootnode_census() {
    init_tracing();
    let (net, bootnodes) = bootnodes_from_env();
    assert!(!bootnodes.is_empty(), "{net} configures no discv4 bootnodes");

    let probes: Vec<_> = bootnodes
        .iter()
        .enumerate()
        .map(|(i, addr)| tokio::spawn(census_one(i, *addr)))
        .collect();
    let (mut answering, mut seeding) = (0usize, 0usize);
    for probe in probes {
        let row = probe.await.expect("census task");
        match row.answered_after {
            Some(after) => {
                answering += 1;
                seeding += usize::from(row.neighbours > 0);
                eprintln!(
                    "[census {net}] {} ANSWERED after {after:.0?}, other nodes learned through \
                     it alone: {}",
                    row.addr, row.neighbours
                );
            }
            None => eprintln!("[census {net}] {} SILENT for {CENSUS_WINDOW:?}", row.addr),
        }
    }
    eprintln!(
        "[census {net}] {answering} of {} bootnodes answered, {seeding} handed out neighbours",
        bootnodes.len()
    );
    assert!(
        seeding >= MIN_SEEDING,
        "only {seeding} of {} {net} discv4 bootnodes handed out neighbours ({answering} \
         answered; want >= {MIN_SEEDING} seeding) — a fresh profile cannot seed EL discovery; \
         re-sync the list from go-ethereum's params/bootnodes.go, or check whether this host \
         is the outlier",
        bootnodes.len()
    );
}
