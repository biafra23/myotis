//! Ground-truth probe for updates_by_range chunking: ask each static mainnet
//! peer for a full 16-update range and report EXACTLY what comes back (wire
//! bytes, chunk count, per-chunk sizes, wall time). Diagnostic tool for the
//! "why do we see one chunk per response?" question — not part of the sync.
//!
//! ```bash
//! RUST_LOG=info cargo run --release -p myotis-net --example probe_updates
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use myotis_net::codec;
use myotis_net::protocols;
use myotis_net::reqresp::{self, LocalStatus};
use myotis_net::status::StatusMessage;
use myotis_net::sync::ChainConfig;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = ChainConfig::mainnet();
    let from_period = config.checkpoint_slot / 8192; // 1777
    let span: u64 = 16;

    // Same pre-bootstrap Status SyncHandle::start serves (checkpoint anchors).
    let local = LocalStatus::new(StatusMessage {
        fork_digest: config.current_fork_digest(),
        finalized_root: config.checkpoint_root,
        finalized_epoch: config.checkpoint_slot / config.slots_per_epoch.max(1),
        head_root: config.checkpoint_root,
        head_slot: config.checkpoint_slot,
        earliest_available_slot: 0,
    });
    let client = reqresp::start_host(Arc::clone(&local)).expect("host");

    let mut ssz_request = Vec::with_capacity(16);
    ssz_request.extend_from_slice(&from_period.to_le_bytes());
    ssz_request.extend_from_slice(&span.to_le_bytes());
    let wire = codec::encode_request(&ssz_request);

    for peer_str in &config.static_peers {
        // Split /p2p/<id> off the multiaddr (same as sync's parse_static_peer).
        let Ok(full) = peer_str.parse::<Multiaddr>() else { continue };
        let mut addr = Multiaddr::empty();
        let mut peer = None;
        for proto in full.iter() {
            if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                peer = Some(id);
            } else {
                addr.push(proto);
            }
        }
        let Some(peer) = peer else { continue };
        let t0 = Instant::now();
        match tokio::time::timeout(
            Duration::from_secs(60),
            client.request_raw(peer, addr, protocols::UPDATES_BY_RANGE, wire.clone()),
        )
        .await
        {
            Ok(Ok(raw)) => {
                let elapsed = t0.elapsed();
                match codec::decode_multi_chunk_response(&raw, span as usize) {
                    Ok(chunks) => {
                        let sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
                        tracing::info!(peer = %peer, wire_bytes = raw.len(),
                            chunks = chunks.len(), ?sizes, ms = elapsed.as_millis() as u64,
                            "response");
                    }
                    Err(e) => tracing::warn!(peer = %peer, wire_bytes = raw.len(),
                        ms = elapsed.as_millis() as u64, error = %e, "undecodable"),
                }
            }
            Ok(Err(e)) => tracing::warn!(peer = %peer, error = %e, "request failed"),
            Err(_) => tracing::warn!(peer = %peer, "timed out (60s)"),
        }
    }
    client.shutdown().await;
}
