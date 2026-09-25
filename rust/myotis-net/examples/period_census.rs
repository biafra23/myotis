//! Period census: crawl a chain's discv5 DHT and ask EVERY fork-matched peer
//! for `light_client_updates_by_range` at ONE period, then report the
//! sync-committee participation of each answer. Answers the operational
//! question "does anybody on this network serve a plausible update for
//! period N?" — a light client needs >= 2/3 participation to accept one, so a
//! peer below that bar can never satisfy it.
//!
//! SCOPE: this counts participation BITS. It does not verify the BLS aggregate,
//! applicability, or the Merkle branches — `LightClientProcessor::process_update`
//! does that against a trusted committee, which a one-shot crawler has no anchor
//! for. A forged update with 512 bits set would be reported as claiming a
//! supermajority. Use this to answer "is the data out there at all", not "is
//! this peer honest".
//!
//! Written for the mainnet period-1840 stall (2026-09-01), where one server's
//! stored update had 113/512 and wallets could not advance past it.
//!
//! The PINNED peers (`ChainConfig::static_peers`) are asked first, ONE AT A
//! TIME, before any crawl probe is in flight, and each gets its own line: its
//! verdict, the client its Identify named, and whether that Identify
//! advertises `light_client_updates_by_range`. A pin-list re-census — what
//! `live_pins_alive` tells you to run when a pin stops answering — decides
//! about each entry, so a pin's line must not depend on what else is in
//! flight: probed concurrently, healthy pins came back as timeouts and
//! undecodable answers (2026-09-13; reqresp keys its outbound bookkeeping by
//! request id alone, and libp2p issues those ids per protocol). The crawl
//! itself stays concurrent, so read its negative buckets with that in mind.
//! A pin that fails its first ask gets one more, 11 s later: a busy public
//! node closes on a full peer table and answers the next ask, so a single
//! failure is not grounds to prune. Only `updates_by_range` is asked, so a
//! `no-updates-protocol` peer may still serve bootstraps and finality updates.
//!
//! ```bash
//! NET=mainnet PERIOD=1840 CRAWL_SECS=300 RUST_LOG=info \
//!   cargo run --release -p myotis-net --example period_census
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use myotis_consensus::types::LightClientUpdate;
use myotis_net::codec;
use myotis_net::discovery::{self, DiscoveryConfig};
use myotis_net::protocols;
use myotis_net::reqresp::{self, LocalStatus, RequestError};
use myotis_net::status::StatusMessage;
use myotis_net::sync::ChainConfig;
use tokio::sync::{mpsc, Semaphore};

/// Wait before a pin's second ask. A Lighthouse server grants one
/// updates_by_range request per 10 s per peer, so a retry any sooner can be
/// refused for quota rather than capability — the same window
/// `live_pins_alive` waits before re-asking.
const PIN_RETRY_BACKOFF: Duration = Duration::from_secs(11);

/// One probed peer's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Verdict {
    /// Served a decodable update: (participants, attested slot).
    Serves(u64, u64),
    /// Responded, but the frame/SSZ didn't decode (error response or garbage).
    RespondedUndecodable,
    /// Connected, but doesn't speak `light_client_updates_by_range`. It may
    /// still serve the other light-client protocols (bootstrap, finality).
    Unsupported,
    DialFail,
    Timeout,
    ConnectionClosed,
    Io,
}

/// The histogram bucket a verdict lands in; `need` is the 2/3 participation bar.
fn bucket(verdict: &Verdict, need: u64) -> &'static str {
    match verdict {
        Verdict::Serves(bits, _) if *bits >= need => "claims-supermajority",
        Verdict::Serves(..) => "below-2/3-bar",
        Verdict::RespondedUndecodable => "responded-undecodable",
        Verdict::Unsupported => "no-updates-protocol",
        Verdict::DialFail => "dial-fail",
        Verdict::Timeout => "timeout",
        Verdict::ConnectionClosed => "conn-closed",
        Verdict::Io => "io-error",
    }
}

/// Ask one peer for `updates_by_range(period, 1)` — `wire` is that request —
/// and classify the answer. Returns the verdict and how long it took.
async fn probe(
    config: &ChainConfig,
    client: &reqresp::ReqRespClient,
    peer_id: libp2p::PeerId,
    addr: libp2p::Multiaddr,
    wire: Vec<u8>,
) -> (Verdict, f64) {
    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(25),
        client.request_raw(peer_id, addr, protocols::UPDATES_BY_RANGE, wire),
    )
    .await;
    let verdict = match res {
        Err(_) => Verdict::Timeout,
        Ok(Err(RequestError::UnsupportedProtocol)) => Verdict::Unsupported,
        Ok(Err(RequestError::DialFailure)) => Verdict::DialFail,
        Ok(Err(RequestError::Timeout)) => Verdict::Timeout,
        Ok(Err(RequestError::ConnectionClosed)) => Verdict::ConnectionClosed,
        Ok(Err(_)) => Verdict::Io,
        Ok(Ok(raw)) => match codec::decode_multi_chunk_response_with_digests(&raw, 1) {
            Ok(chunks) => match chunks.into_iter().next() {
                // Decoded by its context bytes, as the wallet does (Gloas).
                Some((digest, c)) if !c.is_empty() => {
                    match LightClientUpdate::decode_for(config.lc_fork_of_digest(&digest), &c) {
                        Ok(u) => {
                            let bits: u64 = u
                                .sync_aggregate
                                .sync_committee_bits
                                .iter()
                                .map(|b| b.count_ones() as u64)
                                .sum();
                            Verdict::Serves(bits, u.attested_header.beacon.slot)
                        }
                        Err(_) => Verdict::RespondedUndecodable,
                    }
                }
                _ => Verdict::RespondedUndecodable,
            },
            Err(_) => Verdict::RespondedUndecodable,
        },
    };
    (verdict, started.elapsed().as_secs_f64())
}

/// Split a pinned `…/p2p/<id>` multiaddr into its peer id and dial address.
fn split_pin(pin: &str) -> Option<(libp2p::PeerId, libp2p::Multiaddr)> {
    let full = pin.parse::<libp2p::Multiaddr>().ok()?;
    let mut addr = libp2p::Multiaddr::empty();
    let mut peer = None;
    for proto in full.iter() {
        if let libp2p::multiaddr::Protocol::P2p(id) = proto {
            peer = Some(id);
        } else {
            addr.push(proto);
        }
    }
    Some((peer?, addr))
}

/// Record `peer`'s Identify agent and whether it advertises updates_by_range.
/// Identify can land just after a fast failure, and a closing connection takes
/// its metadata with it, so poll briefly right after the probe.
async fn note_pin_agent(
    client: &reqresp::ReqRespClient,
    peer: libp2p::PeerId,
    agents: &mut HashMap<String, (String, bool)>,
) {
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        let meta = client.catchup_peer_meta().await;
        if let Some(agent) = meta.agents.get(&peer) {
            agents.insert(peer.to_string(), (agent.clone(), meta.lc_servers.contains(&peer)));
            return;
        }
    }
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
    let period: u64 = std::env::var("PERIOD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1840);
    // A light client requires a 2/3 supermajority of the 512-member committee.
    let need = 512u64 * 2 / 3 + 1;

    let wall_slot = |cfg: &ChainConfig| -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(cfg.genesis_time) / cfg.seconds_per_slot.max(1)
    };

    println!(
        "== period census: net={} period={} need>={}/512 crawl={}s probes={} wall_slot={} ==",
        config.name,
        period,
        need,
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
            accepted_fork_digests: config.accepted_fork_digests().into(),
            listen_port: 0,
            // The census is a hunt by definition: crawl at the boosted cadence.
            hunt_boost: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            // A census enumerates the whole DHT; targeted rounds toward the
            // pinned servers would only skew the sample toward nodes we run.
            pinned_peer_ids: vec![],
        },
        disc_tx,
    )
    .await
    .expect("discv5");

    let (res_tx, mut res_rx) = mpsc::channel::<(String, String, Verdict, f64)>(1024);
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut seen: HashSet<String> = HashSet::new();
    let mut spawned = 0usize;

    // updates_by_range request body: SSZ (start_period u64 LE, count u64 LE).
    let finality_wire: Vec<u8> = codec::encode_updates_by_range_request(period, 1);

    let mut results: Vec<(String, String, Verdict, f64)> = Vec::new();

    // The pinned peers first, one at a time, before any crawl probe is in
    // flight (see the header). Remembered in config order for the per-pin
    // report; an empty id marks a pin that did not parse. Discovery fills its
    // channel meanwhile, and the crawl's clock starts only after this.
    let mut pins: Vec<(String, String)> = Vec::new();
    // Pin peer id -> (Identify agent, advertises updates_by_range).
    let mut pin_agents: HashMap<String, (String, bool)> = HashMap::new();
    // Pin peer id -> the verdict of its first ask, when a second one followed.
    let mut pin_first_asks: HashMap<String, Verdict> = HashMap::new();
    for pin in &config.static_peers {
        let Some((peer_id, addr)) = split_pin(pin) else {
            pins.push((String::new(), pin.clone()));
            continue;
        };
        let key = peer_id.to_string();
        pins.push((key.clone(), pin.clone()));
        if !seen.insert(key.clone()) {
            continue; // the same id pinned twice: its first answer stands
        }
        spawned += 1;
        let mut ask = probe(
            &config,
            &client,
            peer_id,
            addr.clone(),
            finality_wire.clone(),
        )
        .await;
        if ask.0 != Verdict::DialFail {
            note_pin_agent(&client, peer_id, &mut pin_agents).await;
        }
        if matches!(ask.0, Verdict::Serves(..)) {
            println!("  pin {addr}: {}", bucket(&ask.0, need));
        } else {
            tokio::time::sleep(PIN_RETRY_BACKOFF).await;
            let retry = probe(
                &config,
                &client,
                peer_id,
                addr.clone(),
                finality_wire.clone(),
            )
            .await;
            let first = std::mem::replace(&mut ask, retry);
            if ask.0 != Verdict::DialFail && !pin_agents.contains_key(&key) {
                note_pin_agent(&client, peer_id, &mut pin_agents).await;
            }
            println!("  pin {addr}: {}, then {}", bucket(&first.0, need), bucket(&ask.0, need));
            pin_first_asks.insert(key.clone(), first.0);
        }
        let (verdict, secs) = ask;
        results.push((key, addr.to_string(), verdict, secs));
    }

    let deadline = Instant::now() + Duration::from_secs(crawl_secs);
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
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore");
            let (verdict, secs) = probe(&config, &client, peer_id, addr.clone(), wire).await;
            let _ = res_tx.send((peer_id.to_string(), addr.to_string(), verdict, secs)).await;
        });
    };

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
    let mut servers: Vec<(String, String, u64, u64, f64)> = Vec::new();
    for (peer, addr, verdict, secs) in &results {
        if let Verdict::Serves(bits, slot) = verdict {
            servers.push((peer.clone(), addr.clone(), *bits, *slot, *secs));
        }
        *histogram.entry(bucket(verdict, need)).or_insert(0) += 1;
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
    let _ = ws;
    let supermajority = servers.iter().filter(|s| s.2 >= need).count();
    println!(
        "\nANSWERS FOR PERIOD {} ({} total, {} claim >= 2/3, {} below the bar):",
        period,
        servers.len(),
        supermajority,
        servers.len() - supermajority
    );
    servers.sort_by(|a, b| b.2.cmp(&a.2));
    for (peer, addr, bits, slot, secs) in &servers {
        let offset = slot.saturating_sub(period * 8192);
        let mark = if *bits >= need { ">=2/3" } else { "WEAK " };
        println!(
            "  [{mark}] {bits:>3}/512  attested slot {slot} (offset {offset})  rtt={secs:.1}s  {addr}/p2p/{peer}"
        );
    }
    println!(
        "\nPINNED PEERS ({} configured, in config order, each probed alone and asked again \
         after a failure; client and updates_by_range advertisement from Identify, '-' when \
         it never arrived):",
        pins.len()
    );
    for (id, pin) in &pins {
        let what = if id.is_empty() {
            "unparseable".to_string()
        } else {
            match results.iter().find(|r| r.0 == *id).map(|r| &r.2) {
                Some(v @ Verdict::Serves(bits, slot)) => {
                    format!("{} {bits}/512 @slot {slot}", bucket(v, need))
                }
                Some(v) => bucket(v, need).to_string(),
                None => "no verdict".to_string(),
            }
        };
        let (agent, advertises) = match pin_agents.get(id) {
            Some((agent, lc)) => (agent.as_str(), if *lc { "yes" } else { "no" }),
            None => ("-", "-"),
        };
        // A second ask is shown with the first answer it overrode.
        let first = pin_first_asks
            .get(id)
            .map(|v| format!("  (first ask: {})", bucket(v, need)))
            .unwrap_or_default();
        println!("  {what:<44} lc-updates={advertises:<3} agent={agent}{first}\n      {pin}");
    }
    println!(
        "\nVERDICT: {} peer(s) on {} serve a period-{} update whose sync aggregate\n\
         CLAIMS a >=2/3 supermajority. This census counts participation bits ONLY —\n\
         it does NOT verify the BLS aggregate, applicability, or Merkle branches\n\
         (that needs a processor anchored to a trusted committee). Read it as\n\
         'the data exists and is not obviously too weak', not as 'proven good'.",
        supermajority, config.name, period
    );
}
