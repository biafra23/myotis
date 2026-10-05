//! Live-network integration tests for EL-A3 discv4: bond with a network's
//! real bootnodes and receive Neighbors, and a per-bootnode census of the
//! shipped seed list.
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{Discv4Config, Discv4Service};
use myotis_net::el::reader::ElConfig;

/// How long one bootnode gets to answer the cold ping and hand out Neighbors.
/// A healthy one bonds in well under a second; the rest of the window covers
/// the endpoint proof and the first refresh (10 s after start).
const CENSUS_WINDOW: Duration = Duration::from_secs(30);

/// Bootnodes that must answer for discovery to count as seedable. A floor, not
/// a clean sweep: these are third-party hosts, and geth itself keeps entries
/// it is phasing out.
const MIN_ANSWERING: usize = 2;

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
        key,
        Discv4Config {
            bind_port: 0, // ephemeral
            bootnodes,
        },
        tx,
    )
    .await
    .expect("discv4 start");

    // Neighbors arrive only after the endpoint proof completes (they PING us
    // back, we PONG, they answer FindNode) — allow a couple of refresh cycles.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut discovered = 0usize;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(peer)) => {
                discovered += 1;
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
        discovered > 0,
        "discovered no peers from the {net} bootnodes within 60s"
    );
}

/// One bootnode's census row: when it first answered (the bond's Pong) and how
/// far a table seeded from it ALONE got within the window.
struct Census {
    addr: SocketAddr,
    answered_after: Option<Duration>,
    table: usize,
}

/// Seed a discv4 service from a single bootnode, so whatever lands in its
/// table can only have come from that node.
async fn census_one(index: usize, addr: SocketAddr) -> Census {
    // A key per probe: every service is its own node, so one bootnode's bond
    // says nothing about another's.
    let seed = keccak256(format!("myotis-live-discv4-census-{index}").as_bytes());
    let key = Arc::new(NodeKey::from_secret_bytes(&seed).unwrap());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let service = Discv4Service::start(key, Discv4Config { bind_port: 0, bootnodes: vec![addr] }, tx)
        .await
        .expect("discv4 start");

    let start = tokio::time::Instant::now();
    let mut answered_after = None;
    while start.elapsed() < CENSUS_WINDOW {
        // Keep draining for the whole window: the first event is the bond,
        // the later ones are the Neighbors that fill the table.
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            answered_after.get_or_insert(start.elapsed());
        }
    }
    let table = service.table_size();
    service.stop().await;
    Census { addr, answered_after, table }
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
    let mut answering = 0usize;
    for probe in probes {
        let row = probe.await.expect("census task");
        match row.answered_after {
            Some(after) => {
                answering += 1;
                eprintln!(
                    "[census {net}] {} ANSWERED after {after:.0?}, table seeded from it alone: {}",
                    row.addr, row.table
                );
            }
            None => eprintln!("[census {net}] {} SILENT for {CENSUS_WINDOW:?}", row.addr),
        }
    }
    eprintln!("[census {net}] {answering} of {} bootnodes answered", bootnodes.len());
    assert!(
        answering >= MIN_ANSWERING,
        "only {answering} of {} {net} discv4 bootnodes answered (want >= {MIN_ANSWERING}) — a \
         fresh profile cannot seed EL discovery; re-sync the list from go-ethereum's \
         params/bootnodes.go, or check whether this host is the outlier",
        bootnodes.len()
    );
}
