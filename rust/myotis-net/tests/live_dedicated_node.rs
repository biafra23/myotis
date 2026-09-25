//! Live diagnostic against the dedicated sepolia node (docs/dedicated-sepolia-node.md):
//! dial it directly and run the exact request shapes the log-index backfill
//! walker uses — reverse header window from a recent block, then bodies +
//! receipts for a chunk — printing where (if anywhere) the node stops serving.
//!
//! Run with:
//! `cargo test -p myotis-net --test live_dedicated_node -- --ignored --nocapture`

use std::sync::Arc;

use myotis_core::nodekey::NodeKey;
use myotis_net::el::eth::session::{EthConfig, EthSession};
use myotis_net::el::peer::ManagedPeer;
use myotis_net::el::rlpx::transport::RlpxConnection;

const NODE_ADDR: &str = "188.68.32.16:30405";
const NODE_PUBKEY_HEX: &str =
    "cfd3572bd7691fe03baf52106b873e01d9b5dca1714a74b316cb94151127dfd2\
     0adae3be559e3e6b44b78a5af1ed6f92ecc8676a2555fc7cdb2d29a0c37e1b2c";
const SEPOLIA_GENESIS: &str = "25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9";
// Post-BPO2 (Fusaka) fork id — keep in lockstep with NetworkConfig.java.
const SEPOLIA_FORK_ID: [u8; 4] = [0x26, 0x89, 0x56, 0xb6];

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: exercises the dedicated node with backfill-shaped requests"]
async fn dedicated_node_serves_backfill_shapes() {
    let key = Arc::new(
        NodeKey::from_secret_bytes(&myotis_core::keccak::keccak256(b"live-dedicated")).unwrap(),
    );
    let genesis = hex32(SEPOLIA_GENESIS);
    let cfg = Arc::new(EthConfig {
        network_id: 11155111,
        genesis_hash: genesis,
        fork_id_hash: SEPOLIA_FORK_ID,
        fork_next: 0,
        head_hash: genesis,
        head_number: 0,
        listen_port: 30303,
        genesis_header_rlp: None,
    });

    let addr: std::net::SocketAddr = NODE_ADDR.parse().unwrap();
    let mut pubkey = [0u8; 64];
    for (i, b) in pubkey.iter_mut().enumerate() {
        *b = u8::from_str_radix(&NODE_PUBKEY_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }

    let conn = RlpxConnection::dial(Arc::clone(&key), addr, pubkey)
        .await
        .expect("rlpx dial+handshake");
    let session = EthSession::handshake(conn, &key.public_key_bytes(), &cfg, None)
        .await
        .expect("eth handshake (status/forkid gate)");
    eprintln!(
        "[dedicated] handshake OK: eth/{} snap={} client={}",
        session.eth_version, session.snap, session.peer_hello.client_id
    );
    let best_hash = session.peer_status.best_hash;
    let peer = ManagedPeer::spawn(session, addr);

    // Step 0: resolve the peer's own head to a (number, hash) cursor.
    let head = peer
        .get_block_headers_by_hash(&best_hash, 1)
        .await
        .expect("head header by hash");
    let head = head.first().expect("head header present");
    let cur_n = head.header.number;
    let cur_hash = head.hash;
    eprintln!("[dedicated] head #{cur_n}");

    // Step 1: the walker's reverse window — 1024 headers descending from the cursor.
    let window = peer
        .get_block_headers_by_number(cur_n, 1024, 0, true)
        .await
        .expect("reverse header window");
    eprintln!("[dedicated] reverse window: {} headers", window.len());
    assert!(!window.is_empty(), "node served no headers for the reverse window");
    let top = window.first().unwrap();
    assert_eq!(top.header.number, cur_n, "window must start at the cursor");
    assert_eq!(top.hash, cur_hash, "cursor hash mismatch");
    let mut verified = 0usize;
    for pair in window.windows(2) {
        let [upper, lower] = pair else { break };
        if upper.header.parent_hash != lower.hash
            || lower.header.number != upper.header.number.wrapping_sub(1)
        {
            break;
        }
        verified += 1;
    }
    eprintln!("[dedicated] parent-hash-chained prefix: {verified} blocks");
    assert!(verified > 0, "response does not chain to the cursor");

    // Step 2: bodies + receipts for a walker-sized chunk (64 blocks).
    let chunk: Vec<[u8; 32]> = window[1..].iter().take(64).map(|h| h.hash).collect();
    let (bodies, receipts) = futures::future::join(
        peer.get_block_bodies(&chunk),
        peer.get_receipts(&chunk),
    )
    .await;
    let bodies = bodies.expect("bodies response");
    let receipts = receipts.expect("receipts response");
    // Byte-budget truncation is the EXPECTED honest shape (this is exactly
    // what the walker must tolerate — see log_index_backfill_batch): assert a
    // non-empty, internally-consistent prefix rather than exact lengths.
    let usable = bodies.len().min(receipts.len()).min(chunk.len());
    eprintln!(
        "[dedicated] chunk of {}: {} bodies, {} receipt sets -> usable prefix {}",
        chunk.len(),
        bodies.len(),
        receipts.len(),
        usable
    );
    assert!(usable > 0, "node served no bodies/receipts at all");
    for (i, (body, rs)) in bodies[..usable].iter().zip(&receipts[..usable]).enumerate() {
        assert_eq!(
            rs.len(),
            body.transactions.len(),
            "block {} ({}th in chunk): receipts/txs mismatch",
            window[1 + i].header.number,
            i
        );
    }
    eprintln!("[dedicated] prefix count-consistent — node serves the backfill shapes \
         (counts only; the walker itself verifies tx/receipt roots)");
    drop(peer);
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
