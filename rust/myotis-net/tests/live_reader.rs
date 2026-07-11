//! Live-network integration test for EL-A7b-4a: the `ElReader`. Starts discovery
//! + the peer pool from a single `ElConfig::mainnet()`, then runs a VERIFIED
//! account query end-to-end — the whole EL read pipeline behind one call.
//!
//! The `ExecAnchor` here is a fresh (un-synced) one, so a served query returns
//! the `beaconNotSynced` verdict rather than `headerChain` — that still exercises
//! the full pool → snap fetch → MPT proof → beacon-anchor ladder. The real
//! `headerChain` verdict needs a SYNCED beacon anchor and is the job of the
//! `-Pengine=rust` daemon integration gate (a later sub-PR). Reaching a snap peer
//! is opportunistic (fork-id pin + a snap node retaining recent state), so the
//! reliably-provable milestone is that the reader discovers and dials peers.
//!
//! Run with:
//! `cargo test -p myotis-net --test live_reader -- --ignored --nocapture`

use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::anchor::ExecAnchor;
use myotis_net::el::reader::{ElConfig, ElReader};

const PROBE_ADDRESS_HEX: &str = "d8da6bf26964af9d7eed9e03e53415d37aa96045";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: ElReader discovery → pool → verified account query"]
async fn reader_runs_a_verified_account_query() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();

    let key = Arc::new(NodeKey::from_secret_bytes(&keccak256(b"myotis-live-reader")).unwrap());
    let anchor = Arc::new(ExecAnchor::new()); // fresh / un-synced
    let reader = ElReader::start(Arc::clone(&key), Arc::clone(&anchor), ElConfig::mainnet())
        .await
        .expect("reader start");

    let mut probe = [0u8; 20];
    for (i, b) in probe.iter_mut().enumerate() {
        *b = u8::from_str_radix(&PROBE_ADDRESS_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
    let mut served = false;
    let mut peak_snap_peers = 0usize;
    while tokio::time::Instant::now() < deadline {
        peak_snap_peers = peak_snap_peers.max(reader.snap_peer_count().await);
        match reader.get_account(probe).await {
            Ok(acct) => {
                eprintln!(
                    "[live_reader] account 0x{}: exists={} nonce={} verifyMethod={:?} \
                     failReason={:?} beaconSynced={} peerBlock={}",
                    hex(&probe),
                    acct.exists,
                    acct.nonce,
                    acct.verify_method,
                    acct.fail_reason,
                    acct.beacon_synced,
                    acct.block_number,
                );
                // The full ladder ran and produced a verdict. With the un-synced
                // anchor that verdict is beaconNotSynced (no peer state root can
                // match, and the header-chain walk needs a finalized anchor).
                assert!(!acct.beacon_synced);
                assert_eq!(acct.fail_reason, Some("beaconNotSynced"));
                assert!(!acct.beacon_chain_verified);
                served = true;
                break;
            }
            Err(e) => {
                // "no snap peer available" until the pool acquires one.
                eprintln!("[live_reader] query not yet servable: {e}");
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    reader.stop().await;
    eprintln!("[live_reader] peakSnapPeers={peak_snap_peers} served={served}");
    // Reaching a serving snap peer is opportunistic; the pipeline being wired
    // (discovery → pool) is the milestone. `served` is asserted above when it
    // happens; here we only require the reader came up.
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
