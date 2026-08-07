//! Live A/B benchmark for the backfill chunk pipeline (#298): fetch the SAME
//! bodies+receipts chunks from the dedicated sepolia node sequentially (the
//! pre-pipeline shape, depth 1) and pipelined (`buffered(4)`, the PR shape),
//! and print wall times per pass. Two regions:
//!
//! - a full-serve region (small early blocks — chunks come back complete;
//!   this is where the pipeline should collapse the sequential RTT chain),
//! - the bloom-saturated spam region near the current walk cursor (first
//!   chunk truncates; the walker's adaptive depth stays at 1 there BY DESIGN,
//!   so the pipelined pass here only quantifies what adaptivity avoids
//!   wasting).
//!
//! MEASUREMENT ONLY: headers are fetched by number and nothing is verified —
//! no trust claims are made; the real walker verifies every root.
//!
//! Run with:
//! `cargo test -p myotis-net --test live_pipeline_bench -- --ignored --nocapture`

use std::sync::Arc;
use std::time::Instant;

use myotis_core::nodekey::NodeKey;
use myotis_net::el::eth::session::{EthConfig, EthSession};
use myotis_net::el::peer::ManagedPeer;
use myotis_net::el::rlpx::transport::RlpxConnection;

const NODE_ADDR: &str = "87.154.209.161:30405";
const NODE_PUBKEY_HEX: &str =
    "cfd3572bd7691fe03baf52106b873e01d9b5dca1714a74b316cb94151127dfd2\
     0adae3be559e3e6b44b78a5af1ed6f92ecc8676a2555fc7cdb2d29a0c37e1b2c";
const SEPOLIA_GENESIS: &str = "25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9";
const SEPOLIA_FORK_ID: [u8; 4] = [0x26, 0x89, 0x56, 0xb6];

/// Matches the walker (`reader.rs`).
const CHUNK_LEN: usize = 64;
const DEPTH: usize = 4;
/// Chunks per pass: 8 × 64 = 512 blocks, i.e. a half-batch of walker work.
const CHUNKS: usize = 8;
/// Alternating rounds per region, to control for drift/warm-up bias.
const ROUNDS: usize = 2;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: benchmarks chunk fetch pipelining against the dedicated node"]
async fn pipeline_vs_sequential_chunk_fetches() {
    let peer = dial().await;

    // Probe first: how much does the node actually serve per chunk across the
    // walk corpus? (bodies vs receipts separately — the budget binds on one.)
    for top in [5_700_000u64, 7_000_000, 8_500_000, 10_000_000, 11_170_000] {
        probe_chunk(&peer, top).await;
    }

    // Region A: early small blocks — full-serve regime (the walk floor is
    // 5,594,611; this sits just above it, in range the walker will reach).
    bench_region(&peer, "full-serve @6.0M", 6_000_000).await;
    // Region B: the bloom-saturated spam era near the current walk cursor —
    // truncating regime.
    bench_region(&peer, "truncating @11.17M", 11_170_000).await;

    drop(peer);
}

/// One 64-hash chunk at `top_block`, reporting bodies and receipts serve
/// counts separately — shows which side of the byte budget binds.
async fn probe_chunk(peer: &ManagedPeer, top_block: u64) {
    let window = peer
        .get_block_headers_by_number(top_block, CHUNK_LEN as u64, 0, true)
        .await
        .expect("probe header window");
    let hashes: Vec<[u8; 32]> = window.iter().take(CHUNK_LEN).map(|h| h.hash).collect();
    let started = Instant::now();
    let (bodies, receipts) = futures::future::join(
        peer.get_block_bodies(&hashes),
        peer.get_receipts(&hashes),
    )
    .await;
    eprintln!(
        "[probe @{top_block}] chunk of {}: {} bodies, {} receipt sets in {} ms",
        hashes.len(),
        bodies.map(|b| b.len()).unwrap_or(0),
        receipts.map(|r| r.len()).unwrap_or(0),
        started.elapsed().as_millis()
    );
}

async fn bench_region(peer: &ManagedPeer, label: &str, top_block: u64) {
    // Headers by number, descending — bench-only, unverified.
    let window = peer
        .get_block_headers_by_number(top_block, (CHUNKS * CHUNK_LEN) as u64, 0, true)
        .await
        .expect("header window");
    assert!(
        window.len() >= CHUNKS * CHUNK_LEN,
        "[{label}] node served only {} headers",
        window.len()
    );
    let chunks: Vec<Vec<[u8; 32]>> = window[..CHUNKS * CHUNK_LEN]
        .chunks(CHUNK_LEN)
        .map(|c| c.iter().map(|h| h.hash).collect())
        .collect();

    // Warm-up: one chunk, discarded (TCP window growth, peer-side cache).
    let _ = futures::future::join(
        peer.get_block_bodies(&chunks[0]),
        peer.get_receipts(&chunks[0]),
    )
    .await;

    for round in 0..ROUNDS {
        // Alternate order across rounds so neither shape always runs first.
        if round % 2 == 0 {
            run_sequential(peer, label, &chunks).await;
            run_pipelined(peer, label, &chunks).await;
        } else {
            run_pipelined(peer, label, &chunks).await;
            run_sequential(peer, label, &chunks).await;
        }
    }
}

async fn run_sequential(peer: &ManagedPeer, label: &str, chunks: &[Vec<[u8; 32]>]) {
    let started = Instant::now();
    let mut served = 0usize;
    let mut truncated = false;
    for hashes in chunks {
        let (bodies, receipts) = futures::future::join(
            peer.get_block_bodies(hashes),
            peer.get_receipts(hashes),
        )
        .await;
        let (bodies, receipts) = (bodies.expect("bodies"), receipts.expect("receipts"));
        let usable = bodies.len().min(receipts.len()).min(hashes.len());
        served += usable;
        if usable < hashes.len() {
            truncated = true;
            break; // the walker stops the batch at the first short chunk
        }
    }
    report(label, "sequential", served, truncated, started.elapsed());
}

async fn run_pipelined(peer: &ManagedPeer, label: &str, chunks: &[Vec<[u8; 32]>]) {
    let started = Instant::now();
    let mut served = 0usize;
    let mut truncated = false;
    let mut fetches = futures::StreamExt::buffered(
        futures::stream::iter(chunks.iter().map(|hashes| async move {
            futures::future::join(peer.get_block_bodies(hashes), peer.get_receipts(hashes)).await
        })),
        DEPTH,
    );
    while let Some((bodies, receipts)) = futures::StreamExt::next(&mut fetches).await {
        let (bodies, receipts) = (bodies.expect("bodies"), receipts.expect("receipts"));
        let usable = bodies.len().min(receipts.len()).min(CHUNK_LEN);
        served += usable;
        if usable < CHUNK_LEN {
            truncated = true;
            break; // drops in-flight fetches, like the walker
        }
    }
    report(label, &format!("pipelined(x{DEPTH})"), served, truncated, started.elapsed());
}

fn report(label: &str, shape: &str, served: usize, truncated: bool, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    eprintln!(
        "[{label}] {shape:<14} {served:>3} blocks in {:>7.0} ms  ({:>5.1} blk/s chunk-phase{})",
        secs * 1000.0,
        served as f64 / secs,
        if truncated { ", TRUNCATED" } else { "" }
    );
}

async fn dial() -> ManagedPeer {
    let key = Arc::new(
        NodeKey::from_secret_bytes(&myotis_core::keccak::keccak256(b"live-pipeline-bench"))
            .unwrap(),
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
        .expect("eth handshake");
    eprintln!(
        "[bench] handshake OK: eth/{} snap={} client={}",
        session.eth_version, session.snap, session.peer_hello.client_id
    );
    ManagedPeer::spawn(session, addr)
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
