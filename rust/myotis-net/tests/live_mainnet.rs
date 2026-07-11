//! Live-network integration test: sync to SYNCED against real mainnet peers.
//!
//! Ignored by default (network + up to 15 minutes). Run with:
//!
//! ```bash
//! cargo test -p myotis-net --test live_mainnet -- --ignored --nocapture
//! ```

use std::time::Duration;

use myotis_net::{ChainConfig, SyncHandle, SyncState};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: dials mainnet CL peers, takes minutes"]
async fn syncs_to_head_on_live_mainnet() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();

    let config = ChainConfig::mainnet();
    let checkpoint_root = config.checkpoint_root;
    let handle = SyncHandle::start(config).expect("sync start");

    // 15 min: measured live (2026-07-06), an 18-period-stale checkpoint takes
    // ~8-12 min — LC servers cap updates_by_range at ~1 update per 10 s per
    // peer, so deep catch-up is peer-quota-bound.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(900);
    let mut synced = None;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = handle.status();
        eprintln!(
            "[live_mainnet] state={} finalized_slot={} period={} peers={}",
            s.state, s.finalized_slot, s.period, s.peer_count
        );
        if s.state == SyncState::Synced {
            synced = Some(s);
            break;
        }
    }

    let status = synced.expect("did not reach SYNCED within the 15-minute cap");
    // The finalized chain must have ADVANCED beyond the embedded checkpoint:
    // a fresh root at a later slot, i.e. bootstrap + verified updates applied.
    assert!(status.finalized_slot > 14_560_000, "finalized slot did not advance");
    assert_ne!(status.finalized_root, checkpoint_root, "finalized root did not advance");
    assert_ne!(status.finalized_root, [0u8; 32]);

    handle.stop().await;
}
