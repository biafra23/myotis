//! Live-network integration test for EL-A3 discv4: bond with a real mainnet
//! bootnode and receive Neighbors.
//!
//! Ignored by default (needs outbound UDP to mainnet bootnodes). Run with:
//!
//! ```bash
//! cargo test -p myotis-net --test live_discv4 -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{Discv4Config, Discv4Service};

/// Mainnet discv4 bootnodes (ip:port), mirroring `NetworkConfig.MAINNET`.
const MAINNET_BOOTNODES: &[&str] = &[
    "18.138.108.67:30303",
    "3.209.45.79:30303",
    "65.108.70.101:30303",
    "157.90.35.166:30303",
];

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: pings mainnet discv4 bootnodes over UDP"]
async fn bonds_and_discovers_on_live_mainnet() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();

    let key = Arc::new(NodeKey::from_secret_bytes(&keccak256(b"myotis-live-discv4")).unwrap());
    let bootnodes: Vec<SocketAddr> = MAINNET_BOOTNODES
        .iter()
        .map(|s| s.parse().expect("valid bootnode addr"))
        .collect();

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
        "discovered no peers from mainnet bootnodes within 60s"
    );
}
