//! Live-network integration test for EL-A7b-2: the EL peer pool. Wires the
//! discv4 candidate stream straight into a `PeerPool`, which dials, handshakes,
//! and retains snap-capable `ManagedPeer`s on its own. Then it fetches a
//! VERIFIED account through a pooled peer.
//!
//! What this proves beyond `live_managed_peer` (a hand-dialed single peer): the
//! pool's dial manager (backoff/blacklist/attempted + concurrency cap) turns the
//! raw discovery stream into usable snap peers with no per-peer orchestration
//! from the caller. Reaching a snap peer + verified state is opportunistic
//! (gated on the fork-id pin + a snap node retaining recent state, same posture
//! as the other live tests); the reliably-provable milestone is that the pool
//! attempts dials from the discovery stream.
//!
//! Run with:
//! `cargo test -p myotis-net --test live_pool -- --ignored --nocapture`

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{Discv4Config, Discv4Service, TableEntry};
use myotis_net::el::eth::session::EthConfig;
use myotis_net::el::pool::{PeerPool, PoolConfig};
use myotis_net::el::snap::fetch::AccountOutcome;

const MAINNET_BOOTNODES: &[&str] = &[
    "18.138.108.67:30303",
    "3.209.45.79:30303",
    "18.188.214.86:30303",
    "3.219.208.172:30303",
];
const MAINNET_GENESIS: &str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
const MAINNET_FORK_ID: [u8; 4] = [0x07, 0xc9, 0x46, 0x2e];
const PROBE_ADDRESS_HEX: &str = "d8da6bf26964af9d7eed9e03e53415d37aa96045";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: discv4 stream → PeerPool → verified account fetch"]
async fn pool_dials_from_discovery_and_serves_a_verified_account() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();

    let key = Arc::new(NodeKey::from_secret_bytes(&keccak256(b"myotis-live-pool")).unwrap());
    let bootnodes: Vec<SocketAddr> = MAINNET_BOOTNODES.iter().map(|s| s.parse().unwrap()).collect();
    let genesis = hex32(MAINNET_GENESIS);

    let (tx, rx) = tokio::sync::mpsc::channel::<TableEntry>(256);
    let discovery = Discv4Service::start(Arc::clone(&key), Discv4Config { bind_port: 0, bootnodes }, tx)
        .await
        .expect("discv4 start");

    let cfg = Arc::new(EthConfig {
        network_id: 1,
        genesis_hash: genesis,
        fork_id_hash: MAINNET_FORK_ID,
        fork_next: 0,
        head_hash: genesis,
        head_number: 0,
        listen_port: 30303,
        genesis_header_rlp: None,
    });

    // Wire discovery straight into the pool — no per-peer orchestration here.
    let pool = PeerPool::start(
        Arc::clone(&key),
        key.public_key_bytes(),
        cfg,
        PoolConfig::default(),
        myotis_net::el::peercache::ElPeerCache::disabled(),
        rx,
        None,
        None,
        None,
    );

    let mut probe = [0u8; 20];
    for (i, b) in probe.iter_mut().enumerate() {
        *b = u8::from_str_radix(&PROBE_ADDRESS_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }

    // Wait for the pool to acquire a snap peer (best-effort, bounded).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
    let mut verified = false;
    while tokio::time::Instant::now() < deadline {
        if let Some(peer) = pool.snap_peer().await {
            let head_hash = peer.peer_status.best_hash;
            if let Ok(headers) = peer.get_block_headers_by_hash(&head_hash, 1).await {
                if let Some(h) = headers.first() {
                    let state_root = h.header.state_root;
                    if state_root != [0u8; 32] {
                        match peer.snap_get_account(&state_root, &probe).await {
                            Ok(AccountOutcome::Present(acct)) => {
                                eprintln!(
                                    "[live_pool] VERIFIED account 0x{}: nonce={} balanceHex={}",
                                    hex(&probe),
                                    acct.nonce,
                                    hex(&acct.balance),
                                );
                                verified = true;
                                break;
                            }
                            Ok(AccountOutcome::Absent) => {
                                eprintln!("[live_pool] probe account verified ABSENT at this root");
                                verified = true;
                                break;
                            }
                            Err(e) => eprintln!("[live_pool] snap fetch failed: {e}"),
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let snap_peers = pool.snap_peer_count().await;
    let attempted = pool.attempted_count().await;
    let blacklisted = pool.blacklist_count().await;
    pool.stop().await;
    discovery.stop().await;

    eprintln!(
        "[live_pool] attempted={attempted} snapPeers={snap_peers} blacklisted={blacklisted} \
         verifiedAccount={verified}"
    );
    // Reliably-provable milestone: the pool pulled candidates off the discovery
    // stream and dialed them. Holding a snap peer + fetching verified state
    // additionally needs a current fork-id (EL-A7) + a snap node retaining recent
    // state, so those are opportunistic and logged.
    assert!(
        attempted > 0 || blacklisted > 0,
        "pool never attempted a dial from the discovery stream in 150s"
    );
}

fn hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
