//! One-shot snap/1 census for foreign EVM chains (Polygon PoS / Bor, Scroll,
//! Mantle): crawl discv4 from each chain's published bootnodes plus the
//! Ethereum mainnet DHT, RLPx-dial every discovered node, read its Hello and
//! Status, and — for a peer of a target chain — mirror its own Status back
//! (so no per-chain fork-id table is needed), fetch its head header and ask
//! one `GetAccountRange` at that header's state root. A non-empty proof that
//! verifies against the root (present OR absent) counts as "serves snap".
//!
//! Diagnostic tool, not part of the sync. The verdict "serves snap" proves the
//! peer answers snap proofs for its own head; it says nothing about whether
//! that head is canonical (no anchor is involved).
//!
//! ```bash
//! CRAWL_SECS=300 cargo run --release -p myotis-net --example snap_probe
//! ```

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_core::rlp;
use myotis_net::el::discv4::{Discv4Config, Discv4Service, TableEntry};
use myotis_net::el::eth::messages as eth;
use myotis_net::el::rlpx::transport::RlpxConnection;
use myotis_net::el::snap::fetch::{verify_account, AccountOutcome};
use myotis_net::el::snap::messages::{decode_account_range, encode_get_account, SnapCodes};
use myotis_wire::rlpx::hello::{decode_hello, encode_hello, P2P_DISCONNECT, P2P_HELLO};
use tokio::sync::{Mutex, Semaphore};

#[path = "probe_common/mod.rs"]
mod probe_common;
use probe_common::{
    caps_line, disconnect_reason, fresh_node_key, negotiate, read_status, recv_frame, truncate,
};

/// Target chains: (network id, name, probe address with known state).
const TARGETS: &[(u64, &str, &str)] = &[
    (
        137,
        "polygon-pos",
        "0000000000000000000000000000000000001010",
    ), // MRC20 native-token contract
    (534352, "scroll", "5300000000000000000000000000000000000004"), // WETH predeploy
    (5000, "mantle", "4200000000000000000000000000000000000016"),   // L2ToL1MessagePasser predeploy
];

/// Bor `params/bootnodes.go` BorMainnetBootnodes (0xPolygon/bor master, fetched 2026-11-05).
const BOR_BOOT: &[&str] = &[
    "enode://e4fb013061eba9a2c6fb0a41bbd4149f4808f0fb7e88ec55d7163f19a6f02d64d0ce5ecc81528b769ba552a7068057432d44ab5e9e42842aff5b4709aa2c3f3b@34.89.75.187:30303",
    "enode://a49da6300403cf9b31e30502eb22c142ba4f77c9dda44990bccce9f2121c3152487ee95ee55c6b92d4cdce77845e40f59fd927da70ea91cf935b23e262236d75@34.142.43.249:30303",
];
/// scroll-geth `params/bootnodes.go` ScrollMainnetBootnodes (scroll-tech/go-ethereum develop, fetched 2026-11-05).
const SCROLL_BOOT: &[&str] = &[
    "enode://c6ac91f43df3d63916ac1ae411cdd5ba249d55d48a7bec7f8cd5bb351a31aba437e5a69e8a1de74d73fdfeba8af1cfe9caf9846ecd3abf60d1ffdf4925b55b23@54.186.123.248:30303",
    "enode://fdcc807b5d1353f3a1e98b90208ce6ef1b7d446136e51eaa8ad657b55518a2f8b37655e42375d61622e6ea18f3faf9d070c9bbdf012cf5484bcbad33b7a15fb1@44.227.91.206:30303",
    "enode://6beb5a3efbb39be73d17630b6da48e94c0ce7ec665172111463cb470197b20c12faa1fa6f835b81c28571277d1017e65c4e426cc92a46141cf69118ecf28ac03@44.237.194.52:30303",
    "enode://7cf893d444eb8e129dca0f6485b3df579911606e7c728be4fa55fcc5f155a37c3ce07d217ccec5447798bde465ac2bdba2cb8763d107e9f3257e787579e9f27e@52.35.203.107:30303",
    "enode://c7b2d94e95da343db6e667a01cef90376a592f2d277fbcbf6e9c9186734ed8003d01389571bd10cdbab7a6e5adfa6f0c7b55644d0db24e0b9deb4ec80f842075@54.70.236.187:30303",
];
// Mantle publishes no execution-layer bootnodes; its op-geth defaults to the
// Ethereum mainnet bootnodes, so Mantle nodes with discovery on sit in the
// mainnet DHT (`ElConfig::mainnet().bootnodes` below).

#[derive(Debug, Clone, Default)]
struct PeerReport {
    addr: String,
    stage: &'static str,
    client: String,
    caps: String,
    network_id: Option<u64>,
    eth: Option<u64>,
    snap: Option<u64>,
    head: Option<u64>,
    verdict: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let crawl_secs: u64 = std::env::var("CRAWL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    let key = fresh_node_key();
    let mut boot_enodes: Vec<(SocketAddr, [u8; 64])> = Vec::new();
    for e in BOR_BOOT.iter().chain(SCROLL_BOOT) {
        let enode = myotis_net::el::reader::parse_enode(e).expect("bootnode enode");
        boot_enodes.push(enode);
    }
    let mut bootnodes: Vec<SocketAddr> = boot_enodes.iter().map(|(a, _)| *a).collect();
    bootnodes.extend(myotis_net::el::reader::ElConfig::mainnet().bootnodes);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<TableEntry>(1024);
    let discovery = Discv4Service::start(
        Arc::clone(&key),
        Discv4Config {
            bind_port: 0,
            bootnodes,
            ..Default::default()
        },
        tx,
    )
    .await
    .expect("discv4 start");

    let reports: Arc<Mutex<Vec<PeerReport>>> = Arc::default();
    let sem = Arc::new(Semaphore::new(96));
    let mut tried: HashSet<SocketAddr> = HashSet::new();
    let mut handles = Vec::new();

    let spawn_dial = |addr: SocketAddr, pubkey: [u8; 64], handles: &mut Vec<_>| {
        let key = Arc::clone(&key);
        let reports = Arc::clone(&reports);
        let sem = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let r = probe_peer(key, addr, pubkey).await;
            if r.network_id
                .is_some_and(|n| TARGETS.iter().any(|t| t.0 == n))
            {
                eprintln!("[snap_probe] {r:?}");
            }
            reports.lock().await.push(r);
        }));
    };

    for (addr, pk) in &boot_enodes {
        tried.insert(*addr);
        spawn_dial(*addr, *pk, &mut handles);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(crawl_secs);
    let mut discovered = 0usize;
    while tokio::time::Instant::now() < deadline {
        let entry = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                eprintln!("[snap_probe] discv4 channel closed; ending the crawl early");
                break;
            }
            Err(_) => continue,
        };
        discovered += 1;
        if entry.node_id.len() != 64
            || entry.ip.len() != 4
            || entry.tcp_port == 0
            || entry.tcp_port > 65535
        {
            continue;
        }
        let ip = std::net::Ipv4Addr::new(entry.ip[0], entry.ip[1], entry.ip[2], entry.ip[3]);
        let addr = SocketAddr::from((ip, entry.tcp_port as u16));
        if !tried.insert(addr) {
            continue;
        }
        let mut pk = [0u8; 64];
        pk.copy_from_slice(&entry.node_id);
        spawn_dial(addr, pk, &mut handles);
    }
    discovery.stop().await;
    // Wait for EVERY queued probe: each is bounded by its own 45 s timeout, so
    // this terminates, and the totals below cover every dialled address.
    eprintln!(
        "[snap_probe] crawl over; waiting for {} queued probes",
        handles.len()
    );
    // The drain can take tens of minutes after a large crawl (96 probes at a
    // time, up to 45 s each), so report progress rather than sit silent.
    let total = handles.len();
    for (i, h) in handles.into_iter().enumerate() {
        let _ = h.await;
        if (i + 1) % 100 == 0 {
            eprintln!("[snap_probe] {}/{total} probes finished", i + 1);
        }
    }

    let reports = reports.lock().await;
    let mut by_net: BTreeMap<u64, usize> = BTreeMap::new();
    let mut stages: BTreeMap<&str, usize> = BTreeMap::new();
    for r in reports.iter() {
        *stages.entry(r.stage).or_default() += 1;
        if let Some(n) = r.network_id {
            *by_net.entry(n).or_default() += 1;
        }
    }
    println!("\n=== snap_probe summary ({crawl_secs}s crawl) ===");
    println!(
        "discv4 entries seen: {discovered}, distinct dials: {}, reports: {}",
        tried.len(),
        reports.len()
    );
    println!("furthest stage reached: {stages:?}");
    let mut errs: BTreeMap<String, usize> = BTreeMap::new();
    for r in reports.iter() {
        let short: String = r.verdict.chars().take(60).collect();
        *errs.entry(short).or_default() += 1;
    }
    println!("verdicts (first 60 chars): {errs:#?}");
    println!("Status by networkId (top 15):");
    let mut nets: Vec<_> = by_net.iter().collect();
    nets.sort_by(|a, b| b.1.cmp(a.1));
    for (n, c) in nets.iter().take(15) {
        println!("  {n:>10}: {c}");
    }
    for (nid, name, _) in TARGETS {
        let peers: Vec<_> = reports
            .iter()
            .filter(|r| r.network_id == Some(*nid))
            .collect();
        let adv = peers.iter().filter(|r| r.snap.is_some()).count();
        let served = peers
            .iter()
            .filter(|r| r.verdict.starts_with("SERVES"))
            .count();
        println!("\n--- {name} (networkId {nid}): {} peers, {adv} advertise snap, {served} served a verified proof", peers.len());
        for r in peers {
            println!(
                "  {:<22} eth/{:<3} snap/{:<4} head={:<10} {:<40} caps=[{}] -> {}",
                r.addr,
                r.eth.map_or("-".into(), |v| v.to_string()),
                r.snap.map_or("-".into(), |v| v.to_string()),
                r.head.map_or("?".into(), |v| v.to_string()),
                truncate(&r.client, 40),
                r.caps,
                r.verdict
            );
        }
    }
}

async fn probe_peer(key: Arc<NodeKey>, addr: SocketAddr, pubkey: [u8; 64]) -> PeerReport {
    let mut r = PeerReport {
        addr: addr.to_string(),
        stage: "dial",
        ..Default::default()
    };
    match tokio::time::timeout(
        Duration::from_secs(45),
        probe_inner(key, addr, pubkey, &mut r),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            if r.verdict.is_empty() {
                r.verdict = e;
            }
        }
        Err(_) => {
            if r.verdict.is_empty() {
                r.verdict = "timeout".into();
            }
        }
    }
    r
}

async fn probe_inner(
    key: Arc<NodeKey>,
    addr: SocketAddr,
    pubkey: [u8; 64],
    r: &mut PeerReport,
) -> Result<(), String> {
    let mut conn = RlpxConnection::dial(Arc::clone(&key), addr, pubkey).await?;
    r.stage = "rlpx";
    let our_hello = encode_hello(&key.public_key_bytes(), 30303);
    conn.send(P2P_HELLO, &our_hello).await?;
    let (code, payload) = recv_frame(&mut conn, 10).await?;
    if code == P2P_DISCONNECT {
        return Err(format!(
            "disconnect at hello: {}",
            disconnect_reason(&payload)
        ));
    }
    if code != P2P_HELLO {
        return Err(format!("expected hello, got 0x{code:02x}"));
    }
    let hello = decode_hello(&payload)?;
    r.stage = "hello";
    r.client = hello.client_id.clone();
    r.caps = caps_line(&hello);
    let (eth_v, snap_v) = negotiate(&decode_hello(&our_hello)?, &hello);
    r.eth = eth_v;
    r.snap = snap_v;
    let eth_v = eth_v.ok_or("no common eth version")?;

    // Their Status arrives without waiting for ours (geth/bor/reth send first).
    let (code, status_payload) = recv_frame(&mut conn, 8).await?;
    if code == P2P_DISCONNECT {
        return Err(format!(
            "disconnect at status: {}",
            disconnect_reason(&status_payload)
        ));
    }
    if code != eth::STATUS {
        return Err(format!("expected status, got 0x{code:02x}"));
    }
    let (nid, head_hash, latest) = read_status(&status_payload, eth_v)?;
    r.stage = "status";
    r.network_id = Some(nid);
    r.head = latest;
    let Some(target) = TARGETS.iter().find(|t| t.0 == nid) else {
        r.verdict = "other chain".into();
        return Ok(());
    };
    // Mirror the peer's own Status: same network, genesis and fork id, so its
    // EIP-2124 check passes without us knowing the chain's fork schedule.
    conn.send(eth::STATUS, &status_payload).await?;

    // Head header (by the hash the peer announced), hash-checked.
    conn.send(
        eth::GET_BLOCK_HEADERS,
        &eth::encode_get_block_headers_by_hash(1, &head_hash, 1, 0, false),
    )
    .await?;
    let state_root = loop {
        let (code, p) = recv_frame(&mut conn, 12).await?;
        if code == P2P_DISCONNECT {
            return Err(format!(
                "disconnect after status: {}",
                disconnect_reason(&p)
            ));
        }
        if code != eth::BLOCK_HEADERS {
            continue;
        }
        // Hash the header's RAW bytes as received, never a re-encode. Read it
        // with the generic RLP view rather than `eth::decode_block_headers`:
        // that one runs Myotis's own `BlockHeader` decoder, which knows only
        // the layouts of the chains Myotis ships, and would turn a foreign
        // chain's header shape into a false "does not serve" verdict.
        let mut items = rlp::View::new(&p)
            .and_then(|v| v.as_list())
            .map_err(|e| e.0)?;
        let headers = items.nth(1).ok_or("headers: short")?;
        let h = headers
            .as_list()
            .map_err(|e| e.0)?
            .next()
            .ok_or("headers: empty response")?;
        if keccak256(h.raw()) != head_hash {
            return Err("header hash mismatch".into());
        }
        let fields: Vec<_> = h.as_list().map_err(|e| e.0)?.collect();
        if let Some(n) = fields.get(8).and_then(|i| i.as_u64().ok()) {
            r.head = Some(n);
        }
        let sr = fields
            .get(3)
            .ok_or("header: short")?
            .as_bytes()
            .map_err(|e| e.0)?;
        let root: [u8; 32] = sr
            .try_into()
            .map_err(|_| format!("header: stateRoot is {} bytes", sr.len()))?;
        break root;
    };
    r.stage = "header";

    let Some(snap_v) = snap_v else {
        r.verdict = "no snap capability".into();
        return Ok(());
    };
    let codes = SnapCodes::negotiated(eth_v, snap_v);
    let mut probe = [0u8; 20];
    for (i, b) in probe.iter_mut().enumerate() {
        *b = u8::from_str_radix(&target.2[i * 2..i * 2 + 2], 16).unwrap();
    }
    conn.send(
        codes.get_account_range,
        &encode_get_account(7, &state_root, &keccak256(&probe), 4096),
    )
    .await?;
    loop {
        let (code, p) = recv_frame(&mut conn, 15).await?;
        if code == P2P_DISCONNECT {
            return Err(format!(
                "disconnect after GetAccountRange: {}",
                disconnect_reason(&p)
            ));
        }
        if code != codes.account_range {
            continue;
        }
        let resp = decode_account_range(&p).map_err(|e| format!("AccountRange decode: {}", e.0))?;
        if resp.proof.is_empty() {
            r.verdict = "snap advertised, EMPTY proof (root not served)".into();
            return Ok(());
        }
        r.stage = "snap";
        r.verdict = match verify_account(&state_root, &probe, &resp) {
            Ok(AccountOutcome::Present(a)) => format!(
                "SERVES snap: account present, nonce={} ({} proof nodes)",
                a.nonce,
                resp.proof.len()
            ),
            Ok(AccountOutcome::Absent) => format!(
                "SERVES snap: absence proven ({} proof nodes)",
                resp.proof.len()
            ),
            Err(e) => format!("snap proof INVALID: {}", e.0),
        };
        return Ok(());
    }
}
