//! Live-network test for the discv4 ENR fork-id filter (#539): run against a
//! network's bootnodes for a minute and report how the nodes it met were
//! judged — handed over on a matching `eth` entry, kept from the pool as
//! another chain's, or handed over unjudged. The filter is the one the reader
//! ships (`fork_filter_for`), the network's epoch grid included.
//!
//! Ignored by default (outbound UDP to the network's bootnodes). Run with:
//!
//! ```bash
//! NET=sepolia cargo test -p myotis-net --test live_enr_filter -- --ignored --nocapture
//! # the same walk without the filter, for comparison:
//! NET=sepolia FILTER=off cargo test -p myotis-net --test live_enr_filter -- --ignored --nocapture
//! ```
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{Discv4Config, Discv4Service};
use myotis_net::el::reader::{fork_filter_for, ElConfig};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: pings a network's discv4 bootnodes over UDP"]
async fn the_filter_judges_live_nodes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net::el::discv4=debug".into()),
        )
        .try_init();
    let net = std::env::var("NET").unwrap_or_else(|_| "sepolia".to_string());
    let cfg = match net.as_str() {
        "mainnet" => ElConfig::mainnet(),
        "gnosis" => ElConfig::gnosis(),
        _ => ElConfig::sepolia(),
    };
    let filter_on = std::env::var("FILTER").map_or(true, |v| v != "off");
    let key = Arc::new(NodeKey::from_secret_bytes(&keccak256(b"myotis-live-enr-filter")).unwrap());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let service = Discv4Service::start(
        key,
        Discv4Config {
            bind_port: 0,
            bootnodes: cfg.bootnodes.clone(),
            fork_filter: filter_on.then(|| fork_filter_for(&cfg)),
            pool_below_target: None,
        },
        tx,
    )
    .await
    .expect("discv4 start");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut emitted = 0usize;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(_)) => emitted += 1,
            Ok(None) => break,
            Err(_) => {}
        }
        let (compatible, foreign, unjudged) = service.enr_counts().snapshot();
        let table = service.table_size();
        eprintln!("[live_enr_filter {net}] emitted={emitted} compatible={compatible} foreign={foreign} unjudged={unjudged} table={table}");
    }
    let (compatible, foreign, unjudged) = service.enr_counts().snapshot();
    service.stop().await;
    let filter = if filter_on { "on" } else { "off" };
    eprintln!("[live_enr_filter {net} filter={filter}] FINAL emitted={emitted} compatible={compatible} foreign={foreign} unjudged={unjudged}");
    // An environment verdict, not an engine one (#372): Sepolia's bootnodes
    // answered nothing from a dev host within 60 s, filter or no filter.
    assert!(
        emitted as u64 + compatible + foreign + unjudged > 0,
        "discovery produced no candidates from {net}'s bootnodes within 60 s — the \
         environment, not the filter; try again or NET=mainnet"
    );
    if !filter_on {
        return;
    }
    // A node re-learned from NEIGHBORS is handed over again on its stored
    // verdict without a new count, so emissions can exceed the verdicts — but
    // never fall short of them.
    assert!(
        emitted as u64 >= compatible + unjudged,
        "every compatible or unjudged verdict reached the pool"
    );
}
