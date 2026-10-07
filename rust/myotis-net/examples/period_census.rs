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
//! What it does check is what the catch-up refuses before any BLS work, so an
//! answer a wallet throws away on sight never counts as serving: an update
//! attested outside the asked period is `wrong-period`, and one whose headers
//! are not in the wire shape of its attested slot's fork
//! (`LightClientProcessor::update_shape_ok` — a pre-Gloas-shaped update for a
//! Gloas slot, say) is `wrong-fork-shape`. An error answer is filed by its
//! result code (`server-error`, `resource-unavailable`, `invalid-request`) and
//! its message listed under ERROR ANSWERS; an answer with no chunk at all —
//! what a server without the update is supposed to send — is `answered-empty`;
//! only bytes that do not decode are `undecodable`. Every answer is also
//! counted under the client its Identify named (BY CLIENT), which is what tells
//! a client-wide failure — one release refusing a fork's periods — from
//! scattered sick nodes.
//!
//! Written for the mainnet period-1840 stall (2026-09-01), where one server's
//! stored update had 113/512 and wallets could not advance past it; the
//! error/shape/client split for Sepolia's Gloas fork (2026-10-06), where the
//! Lighthouse v8.3.0-rc.0 servers answered Gloas periods with
//! `ServerError: Database error` and an "undecodable" bucket hid that.
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
//! `PERIOD` defaults to the current wall-clock period. Like `live_pins_alive`,
//! the result is only as good as the host it runs from (CLAUDE.md, release step
//! 3): the `cold-start regression` workflow's `census` scope runs this from a
//! GitHub-hosted runner.
//!
//! ```bash
//! NET=mainnet PERIOD=1840 CRAWL_SECS=300 RUST_LOG=info \
//!   cargo run --release -p myotis-net --example period_census
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Served an update for the asked period, in its attested slot's wire
    /// shape: (participants, attested slot).
    Serves(u64, u64),
    /// Served a decodable update attested OUTSIDE the asked period (its
    /// attested slot) — a server whose light-client data stopped at an earlier
    /// period, say, answering with the last update it has.
    WrongPeriod(u64),
    /// Served an update for the asked period whose headers are not in the wire
    /// shape of its attested slot's fork (its attested slot); the processor
    /// refuses it before any BLS work.
    WrongShape(u64),
    /// Answered with an error chunk: (result code, the server's message).
    Error(u8, String),
    /// Answered with no chunk at all — what a server without the update is
    /// supposed to send.
    Empty,
    /// Answered with a success code, but the frame/SSZ didn't decode.
    Undecodable,
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
        Verdict::WrongPeriod(_) => "wrong-period",
        Verdict::WrongShape(_) => "wrong-fork-shape",
        Verdict::Error(codec::RESULT_INVALID_REQUEST, _) => "invalid-request",
        Verdict::Error(codec::RESULT_SERVER_ERROR, _) => "server-error",
        Verdict::Error(codec::RESULT_RESOURCE_UNAVAILABLE, _) => "resource-unavailable",
        Verdict::Error(..) => "unknown-error-code",
        Verdict::Empty => "answered-empty",
        Verdict::Undecodable => "undecodable",
        Verdict::Unsupported => "no-updates-protocol",
        Verdict::DialFail => "dial-fail",
        Verdict::Timeout => "timeout",
        Verdict::ConnectionClosed => "conn-closed",
        Verdict::Io => "io-error",
    }
}

/// A verdict with its particulars, for the per-peer lines.
fn describe(verdict: &Verdict, need: u64, slots_per_period: u64) -> String {
    let name = bucket(verdict, need);
    match verdict {
        Verdict::Serves(bits, slot) => format!("{name} {bits}/512 @slot {slot}"),
        Verdict::WrongPeriod(slot) | Verdict::WrongShape(slot) => {
            format!("{name} (attested slot {slot}, period {})", slot / slots_per_period)
        }
        Verdict::Error(code, msg) if msg.is_empty() => format!("{name} (code {code})"),
        Verdict::Error(_, msg) => format!("{name} {msg:?}"),
        _ => name.to_string(),
    }
}

/// Read an `updates_by_range(period, 1)` answer the way the catch-up does, up
/// to its BLS check (see SCOPE).
fn classify(config: &ChainConfig, period: u64, raw: &[u8]) -> Verdict {
    if raw.is_empty() {
        return Verdict::Empty;
    }
    if let Some((code, msg)) = codec::leading_error(raw) {
        return Verdict::Error(code, msg);
    }
    let Ok(chunks) = codec::decode_multi_chunk_response_with_digests(raw, 1) else {
        return Verdict::Undecodable;
    };
    let Some((digest, chunk)) = chunks.into_iter().next().filter(|(_, c)| !c.is_empty()) else {
        return Verdict::Undecodable;
    };
    // Decoded by its context bytes and size, as the wallet does (Gloas).
    let fork = config.lc_fork_of_chunk(&digest, chunk.len(), LightClientUpdate::GLOAS_SIZE);
    let Ok(update) = LightClientUpdate::decode_for(fork, &chunk) else {
        return Verdict::Undecodable;
    };
    let slot = update.attested_header.beacon.slot;
    if slot / config.slots_per_period() != period {
        return Verdict::WrongPeriod(slot);
    }
    // The processor's first gate: both headers in the shape of the ATTESTED
    // slot's fork (a Gloas update carries even a pre-Gloas finalized header in
    // the Gloas shape).
    let slot_fork = config.fork_schedule.lc_fork_at_slot(slot);
    if update.attested_header.shape() != slot_fork || update.finalized_header.shape() != slot_fork
    {
        return Verdict::WrongShape(slot);
    }
    Verdict::Serves(update.sync_aggregate.count_participants() as u64, slot)
}

/// Ask one peer for `updates_by_range(period, 1)` — `wire` is that request —
/// and classify the answer. Returns the verdict and how long it took.
async fn probe(
    config: &ChainConfig,
    client: &reqresp::ReqRespClient,
    period: u64,
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
        Ok(Ok(raw)) => classify(config, period, &raw),
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

/// `peer`'s Identify agent and whether it advertises updates_by_range; `None`
/// when Identify never arrived. Identify can land just after a fast failure,
/// and a closing connection takes its metadata with it, so poll briefly right
/// after the probe.
async fn identify(
    client: &reqresp::ReqRespClient,
    peer: libp2p::PeerId,
) -> Option<(String, bool)> {
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        let meta = client.catchup_peer_meta().await;
        if let Some(agent) = meta.agents.get(&peer) {
            return Some((agent.clone(), meta.lc_servers.contains(&peer)));
        }
    }
    None
}

/// The client and version an Identify agent names
/// (`Lighthouse/v8.3.0-rc.0-4920af7/x86_64-linux` -> `Lighthouse/v8.3.0-rc.0-4920af7`),
/// `-` when Identify never arrived.
fn client_of(identify: &Option<(String, bool)>) -> String {
    match identify {
        Some((agent, _)) => agent.splitn(3, '/').take(2).collect::<Vec<_>>().join("/"),
        None => "-".to_string(),
    }
}

/// Error answers: (bucket, the server's message) -> (count, client -> count).
type ErrorTally = HashMap<(&'static str, String), (usize, HashMap<String, usize>)>;

/// One probed peer.
struct Probed {
    peer: String,
    addr: String,
    verdict: Verdict,
    secs: f64,
    /// Identify agent and whether it advertises updates_by_range.
    identify: Option<(String, bool)>,
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
    let wall_period = config.wall_clock_period();
    let period: u64 = std::env::var("PERIOD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(wall_period);
    let spp = config.slots_per_period();
    // A light client requires a 2/3 supermajority of the 512-member committee.
    let need = 512u64 * 2 / 3 + 1;

    println!(
        "== period census: net={} period={} (slots {}..{}, {:?} wire shape; wall period {}) \
         need>={}/512 crawl={}s probes={} wall_slot={} ==",
        config.name,
        period,
        period * spp,
        (period + 1) * spp - 1,
        config.fork_schedule.lc_fork_at_slot(period * spp),
        wall_period,
        need,
        crawl_secs,
        concurrency,
        config.wall_clock_slot()
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
            cl_fork_watch: None,
        },
        disc_tx,
    )
    .await
    .expect("discv5");

    let (res_tx, mut res_rx) = mpsc::channel::<Probed>(1024);
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut seen: HashSet<String> = HashSet::new();
    let mut spawned = 0usize;

    // updates_by_range request body: SSZ (start_period u64 LE, count u64 LE).
    let finality_wire: Vec<u8> = codec::encode_updates_by_range_request(period, 1);

    let mut results: Vec<Probed> = Vec::new();

    // The pinned peers first, one at a time, before any crawl probe is in
    // flight (see the header). Remembered in config order for the per-pin
    // report; an empty id marks a pin that did not parse. Discovery fills its
    // channel meanwhile, and the crawl's clock starts only after this.
    let mut pins: Vec<(String, String)> = Vec::new();
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
        let mut ask = probe(&config, &client, period, peer_id, addr.clone(), finality_wire.clone())
            .await;
        let mut agent = None;
        if ask.0 != Verdict::DialFail {
            agent = identify(&client, peer_id).await;
        }
        if matches!(ask.0, Verdict::Serves(..)) {
            println!("  pin {addr}: {}", describe(&ask.0, need, spp));
        } else {
            tokio::time::sleep(PIN_RETRY_BACKOFF).await;
            let retry =
                probe(&config, &client, period, peer_id, addr.clone(), finality_wire.clone())
                    .await;
            let first = std::mem::replace(&mut ask, retry);
            if ask.0 != Verdict::DialFail && agent.is_none() {
                agent = identify(&client, peer_id).await;
            }
            println!(
                "  pin {addr}: {}, then {}",
                describe(&first.0, need, spp),
                describe(&ask.0, need, spp)
            );
            pin_first_asks.insert(key.clone(), first.0);
        }
        let (verdict, secs) = ask;
        results.push(Probed { peer: key, addr: addr.to_string(), verdict, secs, identify: agent });
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
            let permit = sem.acquire_owned().await.expect("semaphore");
            let (verdict, secs) =
                probe(&config, &client, period, peer_id, addr.clone(), wire).await;
            // The probe slot is free again; Identify only needs the swarm.
            drop(permit);
            let agent = if verdict == Verdict::DialFail {
                None
            } else {
                identify(&client, peer_id).await
            };
            let _ = res_tx
                .send(Probed {
                    peer: peer_id.to_string(),
                    addr: addr.to_string(),
                    verdict,
                    secs,
                    identify: agent,
                })
                .await;
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
        if let Ok(Some(r)) = tokio::time::timeout(Duration::from_secs(1), res_rx.recv()).await {
            results.push(r);
        }
    }
    disc_task.abort();

    // Identify-advertised LC servers (protocol list), independent of probe outcome.
    let identify_lc = client.lc_update_servers().await;

    let mut histogram: HashMap<&'static str, usize> = HashMap::new();
    // Client -> (answers, bucket -> count).
    let mut by_client: HashMap<String, (usize, HashMap<&'static str, usize>)> = HashMap::new();
    let mut errors: ErrorTally = HashMap::new();
    let mut servers: Vec<&Probed> = Vec::new();
    let mut refused: Vec<&Probed> = Vec::new();
    for r in &results {
        let b = bucket(&r.verdict, need);
        *histogram.entry(b).or_insert(0) += 1;
        let client_name = client_of(&r.identify);
        let entry = by_client.entry(client_name.clone()).or_default();
        entry.0 += 1;
        *entry.1.entry(b).or_insert(0) += 1;
        match &r.verdict {
            Verdict::Serves(..) => servers.push(r),
            Verdict::WrongPeriod(_) | Verdict::WrongShape(_) => refused.push(r),
            Verdict::Error(_, msg) => {
                let e = errors.entry((b, msg.clone())).or_default();
                e.0 += 1;
                *e.1.entry(client_name).or_insert(0) += 1;
            }
            _ => {}
        }
    }
    // "count  name: a, b" lines, largest first.
    let tally = |counts: &HashMap<String, usize>| -> String {
        let mut v: Vec<_> = counts.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        v.iter().map(|(k, n)| format!("{k} x{n}")).collect::<Vec<_>>().join(", ")
    };

    println!("\n== census: net={} period={} ==", config.name, period);
    println!(
        "discovered fork-matched: {} (discv5 table {}), probed: {}",
        spawned,
        table_size.load(std::sync::atomic::Ordering::Relaxed),
        results.len()
    );
    let mut buckets: Vec<_> = histogram.into_iter().collect();
    buckets.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (bucket, n) in buckets {
        println!("  {bucket:>22}: {n}");
    }
    println!("identify-advertised LC protocol: {}", identify_lc.len());

    println!("\nBY CLIENT (Identify agent; '-' = Identify never arrived):");
    let mut clients: Vec<_> = by_client.into_iter().collect();
    clients.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
    for (name, (n, verdicts)) in &clients {
        let verdicts: HashMap<String, usize> =
            verdicts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        println!("  {n:>4}  {name}: {}", tally(&verdicts));
    }

    if !errors.is_empty() {
        println!("\nERROR ANSWERS (result code, the server's message, count, clients):");
        let mut errors: Vec<_> = errors.into_iter().collect();
        errors.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
        for ((bucket, msg), (n, clients)) in &errors {
            println!("  {n:>4}  {bucket} {msg:?}  [{}]", tally(clients));
        }
    }

    let supermajority = servers
        .iter()
        .filter(|s| matches!(s.verdict, Verdict::Serves(bits, _) if bits >= need))
        .count();
    println!(
        "\nANSWERS FOR PERIOD {} ({} total, {} claim >= 2/3, {} below the bar):",
        period,
        servers.len(),
        supermajority,
        servers.len() - supermajority
    );
    let participants = |p: &Probed| match p.verdict {
        Verdict::Serves(bits, _) => bits,
        _ => 0,
    };
    servers.sort_by_key(|s| std::cmp::Reverse(participants(s)));
    for s in &servers {
        let Verdict::Serves(bits, slot) = s.verdict else { continue };
        let offset = slot.saturating_sub(period * spp);
        let mark = if bits >= need { ">=2/3" } else { "WEAK " };
        println!(
            "  [{mark}] {bits:>3}/512  attested slot {slot} (offset {offset})  rtt={:.1}s  \
             client={}  {}/p2p/{}",
            s.secs,
            client_of(&s.identify),
            s.addr,
            s.peer
        );
    }
    if !refused.is_empty() {
        println!(
            "\nREFUSED ON SIGHT ({} — the catch-up drops these before any BLS work):",
            refused.len()
        );
        for r in &refused {
            println!(
                "  {}  client={}  {}/p2p/{}",
                describe(&r.verdict, need, spp),
                client_of(&r.identify),
                r.addr,
                r.peer
            );
        }
    }
    println!(
        "\nPINNED PEERS ({} configured, in config order, each probed alone and asked again \
         after a failure; client and updates_by_range advertisement from Identify, '-' when \
         it never arrived):",
        pins.len()
    );
    for (id, pin) in &pins {
        let probed = results.iter().find(|r| r.peer == *id);
        let what = if id.is_empty() {
            "unparseable".to_string()
        } else {
            match probed {
                Some(r) => describe(&r.verdict, need, spp),
                None => "no verdict".to_string(),
            }
        };
        let (agent, advertises) = match probed.and_then(|r| r.identify.as_ref()) {
            Some((agent, lc)) => (agent.as_str(), if *lc { "yes" } else { "no" }),
            None => ("-", "-"),
        };
        // A second ask is shown with the first answer it overrode.
        let first = pin_first_asks
            .get(id)
            .map(|v| format!("  (first ask: {})", describe(v, need, spp)))
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
