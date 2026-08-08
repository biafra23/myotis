//! Run the Rust light client against live mainnet until SYNCED, then keep
//! polling finality.
//!
//! ```bash
//! RUST_LOG=info cargo run --release -p myotis-net --example live_sync
//! RUST_LOG=info cargo run --release -p myotis-net --example live_sync -- --once
//! ```
//!
//! `--once` exits 0 as soon as the store is SYNCED (finalized within a couple
//! of epochs of wall clock), non-zero after 25 minutes. Catch-up is peer-bound:
//! live LC servers pace update chunks (~10 s apart under rate limiting), so the
//! sync staggers disjoint sub-ranges across the fan-out and budgets generous
//! per-request deadlines; a ~18-period-stale checkpoint measured 2026-07-06 in
//! the low minutes with cooperative peers, longer under churn.

use std::time::Duration;

use myotis_net::{ChainConfig, SyncHandle, SyncState};

#[tokio::main]
async fn main() {
    // The binary installs a subscriber; the library itself only emits tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=info".into()),
        )
        .init();

    let once = std::env::args().any(|a| a == "--once");

    // NET selects the chain (default mainnet), so this example can drive a
    // sepolia wallet against a candidate LC server — see rust/roost.
    let net = std::env::var("NET").unwrap_or_else(|_| "mainnet".into());
    let config = match net.as_str() {
        "sepolia" => ChainConfig::sepolia(),
        "gnosis" => ChainConfig::gnosis(),
        "mainnet" => ChainConfig::mainnet(),
        other => {
            tracing::error!(net = other, "unknown NET (want mainnet|sepolia|gnosis)");
            std::process::exit(2);
        }
    };
    tracing::info!(net = %net, peers = config.static_peers.len(), "starting light client");

    let handle = match SyncHandle::start(config) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to start sync");
            std::process::exit(2);
        }
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1500);
    let mut last_status = None;
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let s = handle.status();
        if last_status.as_ref() != Some(&s) {
            tracing::info!(state = %s.state, finalized_slot = s.finalized_slot,
                optimistic_slot = s.optimistic_slot, period = s.period,
                peers = s.peer_count, "status");
            last_status = Some(s.clone());
        }
        if s.state == SyncState::Synced && once {
            tracing::info!("SYNCED — exiting (--once)");
            handle.stop().await;
            std::process::exit(0);
        }
        if once && tokio::time::Instant::now() > deadline {
            tracing::error!("not SYNCED within 15 minutes");
            handle.stop().await;
            std::process::exit(1);
        }
    }
}
