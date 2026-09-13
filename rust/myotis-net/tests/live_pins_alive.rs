//! Are this build's configured CL peers and bootnodes actually alive?
//!
//! This is NOT a cold-start test and does not overlap `live_cold_start.rs`,
//! which deliberately blackholes every pin to prove discovery survives without
//! them. That test is blind to whether the real pins answer. This one asks
//! exactly that, because a silently rotted pin list is what #422 turned out to
//! be: the shipped build's servers had moved or gone, every automated check was
//! green, and a fresh install could not catch up at all.
//!
//! Seconds when the pins are healthy; a sick one costs up to its retries
//! (`3 x PIN_TIMEOUT`), and the bootnode test has its own 60 s budget, so a bad
//! list of a couple of dozen pins is minutes, not seconds.
//!
//! ```bash
//! NET=gnosis cargo test -p myotis-net --test live_pins_alive -- --ignored --nocapture
//! ```
//!
//! **Read the census, do not just read the exit code.** These are third-party
//! servers, so some are always down, and the run is only as trustworthy as the
//! host it runs from: a machine whose IP a Lighthouse node has banned sees that
//! node as `dial failed` even though it is healthy for everyone else (that ban
//! is what #422 was about, and a developer box that ran a pre-gossipsub build
//! carries it for 12 h). The reverse happens too: mainnet pin 57.129.130.18
//! closed the connection on GitHub-hosted runner IPs on 2026-09-12 and
//! 2026-09-13 while serving a residential address in full, so confirm a pin
//! only one host calls dead from a second address before dropping it. So the
//! gate is a FLOOR — enough pins alive to actually bootstrap a fresh install —
//! and the per-pin lines above it are the part a human acts on.
//!
//! What each line means:
//!
//! * a pin that does not answer — decommissioned, firewalled, or its address
//!   moved. Re-census it (`examples/period_census.rs`) or drop it.
//! * a pin that answers but does NOT advertise the light-client protocols —
//!   it is a beacon node that stopped serving light clients, so it occupies an
//!   un-evictable pool slot for nothing.
//! * a pin whose peer ID does not match — the server minted a new key (Nimbus
//!   does this per restart without `--netkey-file`); the pin is dead even
//!   though the host is up, and the dial fails with `Unexpected peer ID <new
//!   id>` (in reqresp's debug log; the line here only says `dial failed`) or a
//!   failed handshake rather than a clean refusal.
//! * bootnodes below the floor — discovery cannot seed, which strands a fresh
//!   install even when the pins are fine.

use std::sync::Arc;
use std::time::Duration;

use libp2p::Multiaddr;
use myotis_consensus::store::LightClientProcessor;
use myotis_consensus::types::{LightClientBootstrap, LightClientUpdate};
use myotis_consensus::{spec, ssz};
use myotis_net::codec;
use myotis_net::reqresp::{self, LocalStatus};
use myotis_net::status::StatusMessage;
use myotis_net::{protocols, ChainConfig, SyncHandle, SyncState};

/// Per-peer dial + identify budget. Generous: a healthy server answers in well
/// under a second, and a slow-but-alive one must not be reported as dead.
const PIN_TIMEOUT: Duration = Duration::from_secs(20);

/// A first bootstrap request may legitimately MISS. roost's handler is a pure
/// cache read — the design forbids I/O on the swarm task — so an uncached root
/// answers `ResourceUnavailable` and queues a background fetch, expecting the
/// wallet to retry (`rust/roost/src/store.rs`, "a miss stays
/// ResourceUnavailable, with a background task filling it"). roost drops its
/// cached bootstraps whenever the fork/blob schedule changes, and starts empty
/// after a restart, so a single-shot check reports the project's own primary
/// server as dead on a cold cache. Retry the way a wallet does.
/// One full roost REFRESH tick (12 s, `roost/src/serve.rs`) plus fetch
/// headroom: `fill_bootstrap_misses` runs once per tick, so a shorter backoff
/// retries BEFORE the fill it is waiting for and reports a cold-but-healthy
/// server as dead — the false reading this retry exists to remove.
const MISS_RETRIES: usize = 2;
const MISS_BACKOFF: Duration = Duration::from_secs(15);

/// Gap before re-asking for updates. Light-client servers rate-limit each
/// protocol separately (Lighthouse: one request per 10 s), so a request issued
/// immediately after the bootstrap can be closed for quota rather than for
/// capability — one probe must not condemn a pin.
const UPDATES_RETRY_BACKOFF: Duration = Duration::from_secs(11);

/// How long discovery gets to seed its routing table from the bootnodes.
const DISCOVERY_BUDGET: Duration = Duration::from_secs(60);

/// A routing table this size proves the bootnodes answered and the walk began.
/// Deliberately low: this asserts "discovery can seed", not "discovery is fast"
/// — and not "this network's peers are findable" either, since the eth2 DHT is
/// shared and table membership is not fork-filtered (the fork gate applies to
/// what reaches the pool). The no-pins cold start is what proves findability.
const MIN_TABLE_ENTRIES: usize = 8;

/// How many pinned peers must serve the anchor for the list to be doing its
/// job. A floor, not "all of them": pins are third-party hosts that come and
/// go, and requiring a clean sweep would fail for reasons that are not the
/// pin list's fault — which is how a release check becomes one people skip.
/// Two is the smallest number that is not a single point of failure.
const MIN_ALIVE_PINS: usize = 2;

fn config_for_env() -> ChainConfig {
    match std::env::var("NET").unwrap_or_else(|_| "gnosis".into()).as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "sepolia" => ChainConfig::sepolia(),
        "gnosis" => ChainConfig::gnosis(),
        other => panic!("unknown NET {other:?} (want mainnet, sepolia or gnosis)"),
    }
}

/// The CL source-selection overrides are applied inside the `ChainConfig`
/// constructors, so `MYOTIS_CL_STATIC_PEERS` REPLACES the shipped pin list —
/// a census run with it set is green about peers this build does not ship.
/// `MYOTIS_CL_DISABLE_DISCV5` likewise empties the bootnodes and makes the
/// second test panic with the wrong diagnosis.
fn assert_no_cl_env_overrides() {
    for var in ["MYOTIS_CL_STATIC_PEERS", "MYOTIS_CL_DISABLE_DISCV5"] {
        assert!(
            std::env::var_os(var).is_none(),
            "{var} is set — it replaces the shipped configuration, so this census would \
             not be about the peers this build ships. Unset it."
        );
    }
}

/// Did this `updates_by_range` response actually carry an update a wallet
/// could apply? A success byte is not enough — a truncated or malformed frame
/// (even a bare `[0]`) would otherwise count as "serves catch-up", letting the
/// census meet its floor on peers that cannot advance a stale install. Mirrors
/// the real catch-up path: split the chunks, then decode one.
fn served_an_update(raw: &[u8]) -> bool {
    if raw.first() != Some(&codec::RESULT_SUCCESS) {
        return false;
    }
    match codec::decode_multi_chunk_response(raw, 1) {
        Ok(chunks) => chunks
            .first()
            .is_some_and(|c| !c.is_empty() && LightClientUpdate::decode(c).is_ok()),
        Err(_) => false,
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,myotis_net=info".into()),
        )
        .try_init();
}

/// Every pinned CL peer must answer a `light_client_bootstrap` for this build's
/// own embedded checkpoint root. That is the strongest cheap check: it proves
/// the host is up, the peer ID still matches, the fork digest agrees, it serves
/// light clients, AND it still holds the anchor a fresh install starts from.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: dials this build's pinned CL servers"]
async fn every_pinned_cl_peer_serves_this_builds_anchor() {
    init_tracing();
    assert_no_cl_env_overrides();
    let config = config_for_env();
    assert!(!config.static_peers.is_empty(), "this network pins no CL peers");

    let local = LocalStatus::new(StatusMessage {
        fork_digest: config.current_fork_digest(),
        finalized_root: config.checkpoint_root,
        finalized_epoch: config.checkpoint_slot / config.slots_per_epoch.max(1),
        head_root: config.checkpoint_root,
        head_slot: config.checkpoint_slot,
        earliest_available_slot: 0,
    });
    let client = reqresp::start_host(Arc::clone(&local)).expect("host");

    let mut dead = Vec::new();
    let mut alive = 0usize;
    for pin in &config.static_peers {
        // A malformed pin is a finding, not a reason to lose the rest —
        // `run_sync` itself only warns and skips one.
        let Ok(full) = pin.parse::<Multiaddr>() else {
            dead.push(format!("{pin} — unparseable multiaddr"));
            eprintln!("[pins] BAD  {pin} — unparseable");
            continue;
        };
        let mut addr = Multiaddr::empty();
        let mut peer = None;
        for proto in full.iter() {
            if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                peer = Some(id);
            } else {
                addr.push(proto);
            }
        }
        let Some(peer) = peer else {
            dead.push(format!("{pin} — no /p2p/ peer id"));
            eprintln!("[pins] BAD  {pin} — no peer id");
            continue;
        };
        // `None` until the first attempt runs; the loop below always sets it.
        let mut outcome = None;
        for attempt in 0..=MISS_RETRIES {
            if attempt > 0 {
                eprintln!("[pins] .... {addr} retrying after a miss ({attempt}/{MISS_RETRIES})");
                tokio::time::sleep(MISS_BACKOFF).await;
            }
            let req = myotis_net::codec::encode_request(&config.checkpoint_root);
            outcome = Some(
                tokio::time::timeout(
                    PIN_TIMEOUT,
                    client.request_raw(peer, addr.clone(), protocols::BOOTSTRAP, req),
                )
                .await,
            );
            // Only a cache MISS is worth retrying. Decide that on the eth2
            // RESULT CODE, never on the response's length: an error chunk is
            // `code || varint || snappy(msg)`, about 20 B of framing plus the
            // message, so a 45-character error outweighs any length threshold
            // — myotis-net's own responder answers
            // "InvalidRequest: bootstrap root must be 32 bytes" in 65 B.
            // InvalidRequest and ServerError are final answers; only
            // ResourceUnavailable is the miss roost fills in the background.
            // Byte 0 of an eth2 response frame IS the result code, so read it
            // rather than measuring the frame: an error chunk is
            // `code || varint || snappy(msg)`, roughly 20 B of framing plus the
            // message, so a 45-character error outweighs any length threshold
            // — myotis-net's own responder answers
            // "InvalidRequest: bootstrap root must be 32 bytes" in 65 B.
            // InvalidRequest and ServerError are final; only
            // ResourceUnavailable is the miss roost fills in the background.
            match &outcome {
                Some(Ok(Ok(raw))) if raw.first() == Some(&codec::RESULT_RESOURCE_UNAVAILABLE) => {
                    continue
                }
                _ => break,
            }
        }
        match outcome.expect("the retry loop always runs at least once") {
            Ok(Ok(raw)) => match codec::decode_response(&raw, true) {
                Ok(d) if !d.ssz_payload.is_empty() => {
                    // Framing alone is not evidence. Apply the SAME acceptance
                    // the production bootstrap path does (sync.rs): the
                    // checkpoint pin — we chose the root, the peer chose the
                    // payload — plus both Merkle branches. Without it a
                    // bootstrap for some other anchor, or bytes that merely
                    // decompress, would count as a healthy pin that a fresh
                    // install then rejects.
                    // Deliberately NOT compared against current_fork_digest():
                    // a bootstrap's context bytes follow the slot of the block
                    // it anchors to, not the wall clock, and a still-valid
                    // checkpoint can sit behind a fork boundary — roost stamps
                    // them that way on purpose (`roost/src/serve.rs`, "stamping
                    // it with head's digest would be wrong for exactly the
                    // wallets that are furthest behind"). The production
                    // bootstrap path does not check it either; the checkpoint
                    // pin and the two branches below are the real proof.
                    let verdict = {
                        match LightClientBootstrap::decode(&d.ssz_payload) {
                            Err(e) => Err(format!("bootstrap did not decode: {e}")),
                            Ok(b) if b.header.beacon.hash_tree_root() != config.checkpoint_root => {
                                Err(format!(
                                    "served a bootstrap for root {}, not our anchor",
                                    b.header.beacon.hash_tree_root()[..8]
                                        .iter()
                                        .map(|x| format!("{x:02x}"))
                                        .collect::<String>()
                                ))
                            }
                            Ok(b) => {
                                let depth = b.current_sync_committee_branch.len();
                                if !ssz::verify_merkle_branch(
                                    &b.current_sync_committee.hash_tree_root(),
                                    &b.current_sync_committee_branch,
                                    depth,
                                    spec::sync_committee_gindex(depth),
                                    &b.header.beacon.state_root,
                                ) {
                                    Err("sync-committee branch does not verify".to_string())
                                } else if !LightClientProcessor::verify_execution_branch(&b.header) {
                                    Err("execution branch does not verify".to_string())
                                } else {
                                    Ok(())
                                }
                            }
                        }
                    };
                    if let Err(why) = verdict {
                        dead.push(format!("{pin} — {why}"));
                        eprintln!("[pins] BAD  {addr} — {why}");
                    } else {
                        // #422 was "cannot CATCH UP", which needs
                        // updates_by_range — a server that bootstraps and then
                        // refuses updates strands a stale install just as
                        // thoroughly, so ask for one period before calling it
                        // alive. count=1: Lighthouse's quota refuses more.
                        let period = config.checkpoint_slot / config.slots_per_period();
                        let mut req = Vec::with_capacity(16);
                        req.extend_from_slice(&period.to_le_bytes());
                        req.extend_from_slice(&1u64.to_le_bytes());
                        // Retry once: these servers rate-limit per protocol
                        // and a request issued straight after the bootstrap can
                        // be closed for quota rather than capability. One
                        // probe must not condemn a pin.
                        // `Ok(bytes)` once a server answered, `Err(reason)`
                        // otherwise; the loop always sets it.
                        let mut updates: Option<Result<Vec<u8>, String>> = None;
                        for attempt in 0..2 {
                            if attempt > 0 {
                                tokio::time::sleep(UPDATES_RETRY_BACKOFF).await;
                            }
                            updates = Some(
                                match tokio::time::timeout(
                                    PIN_TIMEOUT,
                                    client.request_raw(
                                        peer,
                                        addr.clone(),
                                        protocols::UPDATES_BY_RANGE,
                                        codec::encode_request(&req),
                                    ),
                                )
                                .await
                                {
                                    Ok(Ok(raw)) => Ok(raw),
                                    Ok(Err(e)) => Err(e.to_string()),
                                    Err(_) => Err("timeout".to_string()),
                                },
                            );
                            if matches!(&updates, Some(Ok(raw)) if served_an_update(raw)) {
                                break;
                            }
                        }
                        match updates.expect("the loop always sets it") {
                            Ok(raw) if served_an_update(&raw) => {
                                alive += 1;
                                eprintln!(
                                    "[pins] OK   {addr} (bootstrap {} B, serves period {period})",
                                    d.ssz_payload.len()
                                );
                            }
                            other => {
                                let why = match other {
                                    Ok(raw) => format!(
                                        "result code {}, {} B, no decodable update",
                                        raw.first().copied().unwrap_or(255),
                                        raw.len()
                                    ),
                                    Err(e) => e,
                                };
                                dead.push(format!(
                                    "{pin} — bootstraps, but refused updates_by_range({period}): {why}"
                                ));
                                eprintln!("[pins] HALF {addr} — bootstrap ok, no updates ({why})");
                            }
                        }
                    }
                }
                Ok(_) => {
                    dead.push(format!("{pin} — success code with an empty payload"));
                    eprintln!("[pins] THIN {addr} — empty payload");
                }
                Err(e) => {
                    // Includes ResourceUnavailable that the retries did not
                    // outlast: roost's background fill is not keeping up.
                    dead.push(format!("{pin} — {e}"));
                    eprintln!("[pins] THIN {addr} — {e}");
                }
            },
            Ok(Err(e)) => {
                dead.push(format!("{pin} — {e}"));
                eprintln!("[pins] DEAD {addr} — {e}");
            }
            Err(_) => {
                dead.push(format!("{pin} — no answer in {PIN_TIMEOUT:?}"));
                eprintln!("[pins] DEAD {addr} — timeout");
            }
        }
    }
    client.shutdown().await;

    let total = config.static_peers.len();
    eprintln!("[pins] {alive} of {total} pinned {} peers served the anchor", config.name);
    if !dead.is_empty() {
        // Not a failure by itself — see the header — but always worth a human
        // look, because a dead pin is not free: it is exempt from eviction, so
        // it holds a pool slot and a targeted discovery lookup for the life of
        // the process.
        eprintln!(
            "[pins] {} did not serve it; re-census (examples/period_census.rs) or drop them:\n  {}",
            dead.len(),
            dead.join("\n  ")
        );
    }
    assert!(
        alive >= MIN_ALIVE_PINS,
        "only {alive} of {total} pinned CL peers on {} served this build's anchor (want at \
         least {MIN_ALIVE_PINS}) — a fresh install would depend entirely on discovery. \
         Before treating this as a pin-list problem, check whether THIS host is the \
         outlier: a Lighthouse node that has banned your IP reports as `dial failed` while \
         being healthy for everyone else. Dead pins:\n  {}",
        config.name,
        dead.join("\n  ")
    );
}

/// The bootnodes must be able to seed discovery. Without this a fresh install
/// has no way into the DHT, which no amount of working pins would fix.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: seeds discv5 from this build's bootnodes"]
async fn the_bootnodes_can_seed_discovery() {
    init_tracing();
    assert_no_cl_env_overrides();
    let mut config = config_for_env();
    let bootnodes = config.bootstrap_enrs.len();
    assert!(bootnodes > 0, "this network configures no CL bootnodes");
    // Remove the pins so the routing table can only have come from bootnodes:
    // a pinned server's targeted lookup would otherwise mask a dead bootnode
    // list entirely.
    config.static_peers.clear();

    let handle = SyncHandle::start(config).expect("sync start");
    let deadline = tokio::time::Instant::now() + DISCOVERY_BUDGET;
    let mut best = 0usize;
    let mut parked = false;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = handle.status();
        // A stale-anchor park publishes a fresh status whose table size is 0,
        // so without this the run would report healthy discovery as dead —
        // and this test is run beside the release's checkpoint question,
        // which is exactly when the anchor may be past the bound.
        parked |= s.state == SyncState::StaleAnchor;
        best = best.max(s.discv5_table_size);
        eprintln!("[bootnodes] state={} discv5 table: {best}", s.state);
        if best >= MIN_TABLE_ENTRIES {
            break;
        }
    }
    handle.stop().await;

    assert!(
        !parked || best >= MIN_TABLE_ENTRIES,
        "parked in STALE_ANCHOR, which publishes an empty table, so discovery was never \
         measured — refresh this network's checkpoint (release question 1) and re-run"
    );
    assert!(
        best >= MIN_TABLE_ENTRIES,
        "discv5 reached only {best} routing-table entries in {:?} from {bootnodes} configured \
         bootnodes (want >= {MIN_TABLE_ENTRIES}) — a fresh install cannot seed discovery, so it \
         depends entirely on the pins being alive",
        DISCOVERY_BUDGET
    );
}
