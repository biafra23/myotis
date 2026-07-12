//! One-shot LC-server census: crawl a chain's discv5 DHT and probe every
//! fork-matched peer for `light_client_finality_update` support. Answers
//! "how many reachable light-client servers does this network actually have
//! right now?" — the number that decides whether an in-engine LC hunt mode
//! is worth building. Diagnostic tool, not part of the sync.
//!
//! ```bash
//! NET=sepolia CRAWL_SECS=420 RUST_LOG=info \
//!   cargo run --release -p myotis-net --example lc_crawl
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use myotis_consensus::types::LightClientFinalityUpdate;
use myotis_net::codec;
use myotis_net::discovery::{self, DiscoveryConfig};
use myotis_net::protocols;
use myotis_net::reqresp::{self, LocalStatus, RequestError};
use myotis_net::status::StatusMessage;
use myotis_net::sync::ChainConfig;
use tokio::sync::{mpsc, Semaphore};

/// One probed peer's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Verdict {
    /// Served a decodable finality update (finalized slot inside).
    ServesFinality(u64),
    /// Responded, but the frame/SSZ didn't decode (error response or garbage).
    RespondedUndecodable,
    /// Connected, but doesn't speak the LC protocol.
    Unsupported,
    DialFail,
    Timeout,
    ConnectionClosed,
    Io,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let net = std::env::var("NET").unwrap_or_else(|_| "sepolia".into());
    let config = match net.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "gnosis" => ChainConfig::gnosis(),
        _ => ChainConfig::sepolia(),
    };
    let crawl_secs: u64 = std::env::var("CRAWL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(420);
    let concurrency: usize = std::env::var("PROBES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);

    let wall_slot = |cfg: &ChainConfig| -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(cfg.genesis_time) / cfg.seconds_per_slot.max(1)
    };

    println!(
        "== LC census: net={} crawl={}s probes={} wall_slot={} ==",
        config.name,
        crawl_secs,
        concurrency,
        wall_slot(&config)
    );

    // Same pre-bootstrap Status the sync loop serves (checkpoint anchors).
    let local = LocalStatus::new(StatusMessage {
        fork_digest: config.current_fork_digest(),
        finalized_root: config.checkpoint_root,
        finalized_epoch: config.checkpoint_slot / config.slots_per_epoch.max(1),
        head_root: config.checkpoint_root,
        head_slot: config.checkpoint_slot,
        earliest_available_slot: 0,
    });
    let client = reqresp::start_host(Arc::clone(&local)).expect("libp2p host");

    let (disc_tx, mut disc_rx) = mpsc::channel(1024);
    let (disc_task, table_size) = discovery::spawn(
        DiscoveryConfig {
            bootstrap_enrs: config.bootstrap_enrs.clone(),
            accepted_fork_digests: config.accepted_fork_digests(),
            listen_port: 0,
            // The census is a hunt by definition: crawl at the boosted cadence.
            hunt_boost: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        },
        disc_tx,
    )
    .await
    .expect("discv5");

    // Seed the probe queue with the chain's static peers too.
    let (res_tx, mut res_rx) = mpsc::channel::<(String, String, Verdict, f64)>(1024);
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut seen: HashSet<String> = HashSet::new();
    let mut spawned = 0usize;

    let deadline = Instant::now() + Duration::from_secs(crawl_secs);
    // finality_update carries NO request content — send truly empty wire
    // bytes, exactly like the production poll (sync.rs poll_finality). An
    // encode_request(&[]) would prepend a stray length byte that strict
    // servers reject, skewing the census toward responded-undecodable.
    let finality_wire: Vec<u8> = Vec::new();

    let mut results: Vec<(String, String, Verdict, f64)> = Vec::new();
    let spawn_probe = |peer_id: libp2p::PeerId,
                           addr: libp2p::Multiaddr,
                           seen: &mut HashSet<String>,
                           spawned: &mut usize| {
        let key = peer_id.to_string();
        if !seen.insert(key) {
            return;
        }
        *spawned += 1;
        let client = client.clone();
        let sem = Arc::clone(&sem);
        let res_tx = res_tx.clone();
        let wire = finality_wire.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore");
            let started = Instant::now();
            let res = tokio::time::timeout(
                Duration::from_secs(25),
                client.request_raw(peer_id, addr.clone(), protocols::FINALITY_UPDATE, wire),
            )
            .await;
            let verdict = match res {
                Err(_) => Verdict::Timeout,
                Ok(Err(RequestError::UnsupportedProtocol)) => Verdict::Unsupported,
                Ok(Err(RequestError::DialFailure)) => Verdict::DialFail,
                Ok(Err(RequestError::Timeout)) => Verdict::Timeout,
                Ok(Err(RequestError::ConnectionClosed)) => Verdict::ConnectionClosed,
                Ok(Err(_)) => Verdict::Io,
                Ok(Ok(raw)) => match codec::decode_response(&raw, true) {
                    Ok(d) => match LightClientFinalityUpdate::decode(&d.ssz_payload) {
                        Ok(u) => Verdict::ServesFinality(u.finalized_header.beacon.slot),
                        Err(_) => Verdict::RespondedUndecodable,
                    },
                    Err(_) => Verdict::RespondedUndecodable,
                },
            };
            let _ = res_tx
                .send((
                    peer_id.to_string(),
                    addr.to_string(),
                    verdict,
                    started.elapsed().as_secs_f64(),
                ))
                .await;
        });
    };

    // Static peers first (multiaddr with trailing /p2p/<id>).
    for peer_str in &config.static_peers {
        let Ok(full) = peer_str.parse::<libp2p::Multiaddr>() else { continue };
        let mut addr = libp2p::Multiaddr::empty();
        let mut peer = None;
        for proto in full.iter() {
            if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                peer = Some(id);
            } else {
                addr.push(proto);
            }
        }
        if let Some(p) = peer {
            spawn_probe(p, addr, &mut seen, &mut spawned);
        }
    }

    // Crawl loop: consume discoveries + collect verdicts until the deadline.
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => break,
            maybe = disc_rx.recv() => {
                match maybe {
                    Some(p) => spawn_probe(p.peer_id, p.addr, &mut seen, &mut spawned),
                    None => break, // discovery died
                }
            }
            Some(r) = res_rx.recv() => {
                if results.len() % 25 == 0 {
                    println!("  … {} probed / {} discovered (table {})",
                        results.len(), spawned,
                        table_size.load(std::sync::atomic::Ordering::Relaxed));
                }
                results.push(r);
            }
        }
    }
    // Drain in-flight probes (up to 30 s more).
    let drain_until = Instant::now() + Duration::from_secs(30);
    while results.len() < spawned && Instant::now() < drain_until {
        match tokio::time::timeout(Duration::from_secs(1), res_rx.recv()).await {
            Ok(Some(r)) => results.push(r),
            _ => {}
        }
    }
    disc_task.abort();

    // Identify-advertised LC servers (protocol list), independent of probe outcome.
    let identify_lc = client.lc_update_servers().await;

    let ws = wall_slot(&config);
    let mut histogram: HashMap<&'static str, usize> = HashMap::new();
    let mut servers: Vec<(String, String, u64, f64)> = Vec::new();
    for (peer, addr, verdict, secs) in &results {
        let bucket = match verdict {
            Verdict::ServesFinality(slot) => {
                servers.push((peer.clone(), addr.clone(), *slot, *secs));
                "SERVES_FINALITY"
            }
            Verdict::RespondedUndecodable => "responded-undecodable",
            Verdict::Unsupported => "no-lc-protocol",
            Verdict::DialFail => "dial-fail",
            Verdict::Timeout => "timeout",
            Verdict::ConnectionClosed => "conn-closed",
            Verdict::Io => "io-error",
        };
        *histogram.entry(bucket).or_insert(0) += 1;
    }

    println!("\n== census: net={} ==", config.name);
    println!(
        "discovered fork-matched: {} (discv5 table {}), probed: {}",
        spawned,
        table_size.load(std::sync::atomic::Ordering::Relaxed),
        results.len()
    );
    let mut buckets: Vec<_> = histogram.into_iter().collect();
    buckets.sort_by(|a, b| b.1.cmp(&a.1));
    for (bucket, n) in buckets {
        println!("  {bucket:>22}: {n}");
    }
    println!("identify-advertised LC protocol: {}", identify_lc.len());
    println!("\nLC SERVERS ({}):", servers.len());
    servers.sort_by(|a, b| b.2.cmp(&a.2));
    for (peer, addr, slot, secs) in &servers {
        let age_slots = ws.saturating_sub(*slot);
        println!(
            "  {addr}/p2p/{peer}  finalized_slot={slot} (age {age_slots} slots) rtt={secs:.1}s"
        );
    }
}
