//! Live-network integration test for EL-A4 RLPx: discover a mainnet peer via
//! discv4, dial it over RLPx to FRAMED, exchange Hello, and read the peer's
//! Hello (its advertised eth/snap capabilities).
//!
//! Ignored by default. Run with:
//!
//! ```bash
//! cargo test -p myotis-net --test live_rlpx -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{Discv4Config, Discv4Service, TableEntry};
use myotis_net::el::rlpx::transport::{decode_hello, encode_hello, RlpxConnection, P2P_HELLO};
use myotis_net::el::reader::ElConfig;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: discovers a mainnet peer and RLPx-dials it to FRAMED"]
async fn dials_a_mainnet_peer_to_framed() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();

    let key = Arc::new(NodeKey::from_secret_bytes(&keccak256(b"myotis-live-rlpx")).unwrap());
    let bootnodes: Vec<SocketAddr> = ElConfig::mainnet().bootnodes; // one source of truth

    let (tx, mut rx) = tokio::sync::mpsc::channel::<TableEntry>(256);
    let discovery = Discv4Service::start(
        Arc::clone(&key),
        Discv4Config { bind_port: 0, bootnodes },
        tx,
    )
    .await
    .expect("discv4 start");

    // Collect peers that advertise a TCP port + a 64-byte node id, then try to
    // RLPx-dial each until one reaches FRAMED and sends a valid Hello.
    let overall = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut attempts = 0usize;
    let mut framed = false;
    while tokio::time::Instant::now() < overall && !framed {
        let entry = match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(Some(e)) => e,
            _ => continue,
        };
        if entry.node_id.len() != 64 || entry.ip.len() != 4 || entry.tcp_port == 0 {
            continue;
        }
        let Some(tcp_addr) = to_v4(&entry.ip, entry.tcp_port) else {
            continue;
        };
        let mut peer_pubkey = [0u8; 64];
        peer_pubkey.copy_from_slice(&entry.node_id);

        attempts += 1;
        match RlpxConnection::dial(Arc::clone(&key), tcp_addr, peer_pubkey).await {
            Ok(mut conn) => {
                // Send our Hello, then read the peer's first framed message.
                let hello = encode_hello(&key.public_key_bytes(), 30303);
                if conn.send(P2P_HELLO, &hello).await.is_err() {
                    continue;
                }
                match conn.recv().await {
                    Ok(frame) if frame.message_code == P2P_HELLO => {
                        let h = decode_hello(&frame.payload).expect("valid Hello");
                        eprintln!(
                            "[live_rlpx] FRAMED with {tcp_addr}: client={:?} caps={:?}",
                            h.client_id, h.capabilities
                        );
                        framed = true;
                    }
                    Ok(frame) => eprintln!(
                        "[live_rlpx] framed {tcp_addr} but first msg code=0x{:02x}",
                        frame.message_code
                    ),
                    Err(e) => eprintln!("[live_rlpx] {tcp_addr} recv after handshake: {e}"),
                }
            }
            Err(e) => eprintln!("[live_rlpx] dial {tcp_addr} failed: {e}"),
        }
    }

    discovery.stop().await;
    assert!(
        framed,
        "did not reach FRAMED with any of {attempts} dialed mainnet peers in 90s"
    );
}

fn to_v4(ip: &[u8], port: u32) -> Option<SocketAddr> {
    if ip.len() != 4 || port == 0 || port > u32::from(u16::MAX) {
        return None;
    }
    let mut o = [0u8; 4];
    o.copy_from_slice(ip);
    Some(SocketAddr::from((std::net::Ipv4Addr::from(o), port as u16)))
}
