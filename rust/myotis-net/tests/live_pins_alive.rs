//! Are this build's configured CL peers and bootnodes actually alive?
//!
//! This is NOT a cold-start test and does not overlap `live_cold_start.rs`,
//! which deliberately blackholes every pin to prove discovery survives without
//! them. That test is blind to whether the real pins answer. This one asks
//! exactly that, because a silently rotted pin list is what #422 turned out to
//! be: the shipped build's servers had moved or gone, every automated check was
//! green, and a fresh install could not catch up at all.
//!
//! Seconds when the pins are healthy — about 12 s more per pin once the chain
//! has left the anchor's period, since the second updates ask waits out the
//! server's quota window; a sick one costs up to its retries
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
//! * a pin that serves the anchor but not the CURRENT period — its
//!   light-client server stopped somewhere between the two, as Sepolia's
//!   Lighthouse servers did at the Gloas fork (2026-10-06: ServerError
//!   "Database error" for every Gloas period). A fresh install bootstraps from
//!   it and then cannot follow the chain. It is asked separately because an
//!   anchor embedded before the stop says nothing about it: run on 2026-10-07
//!   with v0.1.13's pre-fork anchor, the old check still passed a Lighthouse
//!   pin that serves nothing after the fork, while only roost could carry a
//!   wallet past it. The current period is read two epochs back: in a
//!   period's first slots no server has a supermajority update attested in
//!   it yet — every pin at once, which reads like a dead list. A red
//!   current-period ask right after a period boundary means re-run first.
//! * a pin whose peer ID does not match — the server minted a new key (Nimbus
//!   does this per restart without `--netkey-file`); the pin is dead even
//!   though the host is up, and the dial fails with `Unexpected peer ID <new
//!   id>` (in reqresp's debug log; the line here only says `dial failed`) or a
//!   failed handshake rather than a clean refusal.
//! * bootnodes below the floor — discovery cannot seed, which strands a fresh
//!   install even when the pins are fine.

use std::sync::Arc;
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use myotis_consensus::spec::SYNC_COMMITTEE_SIZE;
use myotis_consensus::store::{
    headers_in_attested_forks_shape, LightClientProcessor, LightClientStore,
};
use myotis_consensus::types::{LightClientBootstrap, LightClientUpdate};
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

/// How many pinned peers must serve the anchor, and the catch-up from it, for
/// the list to be doing its job. A floor, not "all of them": pins are
/// third-party hosts that come and go, and requiring a clean sweep would fail
/// for reasons that are not the pin list's fault — which is how a release
/// check becomes one people skip.
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

/// The update an `updates_by_range` answer carries, decoded the way the
/// catch-up decodes it, or why there is none. A success byte is not enough — a
/// truncated or malformed frame (even a bare `[0]`) must not count as serving
/// catch-up, or the census meets its floor on peers that cannot advance a
/// stale install. An error answer keeps its result code and the server's
/// message: "result code 2" alone hid Lighthouse's "Database error".
fn decode_update(config: &ChainConfig, raw: &[u8]) -> Result<LightClientUpdate, String> {
    if raw.is_empty() {
        return Err("an empty answer (no update)".to_string());
    }
    if let Some((code, msg)) = codec::leading_error(raw) {
        return Err(format!("result code {code} {msg:?}"));
    }
    let chunks = codec::decode_multi_chunk_response_with_digests(raw, 1)
        .map_err(|e| format!("{} B that do not frame: {e}", raw.len()))?;
    let (digest, chunk) = chunks
        .into_iter()
        .next()
        .filter(|(_, c)| !c.is_empty())
        .ok_or_else(|| format!("{} B carrying no update", raw.len()))?;
    let fork = config.lc_fork_of_chunk(&digest, chunk.len(), LightClientUpdate::GLOAS_SIZE);
    LightClientUpdate::decode_for(fork, &chunk)
        .map_err(|e| format!("an update that does not decode: {e}"))
}

/// Ask `peer` for `updates_by_range(period, 1)` — count 1: Lighthouse's quota
/// refuses more — and decode the answer. Asked again once when no update came
/// back: these servers rate-limit each protocol separately and a request
/// issued straight after the previous one can be closed for quota rather than
/// capability, so one probe must not condemn a pin. `after_quota` waits out
/// that window before the FIRST ask too, for a peer that was just asked for
/// updates.
async fn ask_update(
    client: &reqresp::ReqRespClient,
    config: &ChainConfig,
    peer: PeerId,
    addr: &Multiaddr,
    period: u64,
    after_quota: bool,
) -> Result<LightClientUpdate, String> {
    let mut why = String::new();
    for attempt in 0..2 {
        if attempt > 0 || after_quota {
            tokio::time::sleep(UPDATES_RETRY_BACKOFF).await;
        }
        why = match tokio::time::timeout(
            PIN_TIMEOUT,
            client.request_raw(
                peer,
                addr.clone(),
                protocols::UPDATES_BY_RANGE,
                codec::encode_updates_by_range_request(period, 1),
            ),
        )
        .await
        {
            Ok(Ok(raw)) => match decode_update(config, &raw) {
                Ok(update) => return Ok(update),
                Err(why) => why,
            },
            Ok(Err(e)) => e.to_string(),
            Err(_) => "timeout".to_string(),
        };
    }
    Err(why)
}

/// Would a wallet take this current-period update? Everything the catch-up
/// checks short of the BLS aggregate: attested in `period`, both headers in the
/// wire shape of the attested slot's fork, and the 2/3 participation the BLS
/// check demands first. The aggregate itself would need period `period`'s
/// committee, i.e. a walk from the anchor through every period in between —
/// minutes per pin once an anchor has aged, against a server whose data the
/// anchor-period ask has just verified in full. What this ask has to show is
/// that the server still produces the head's updates, in the head's format.
fn head_update_ok(
    config: &ChainConfig,
    update: &LightClientUpdate,
    period: u64,
) -> Result<usize, String> {
    let slot = update.attested_header.beacon.slot;
    let attested_period = slot / config.slots_per_period();
    if attested_period != period {
        return Err(format!("an update attested in period {attested_period} (slot {slot})"));
    }
    // The processor's own shape gate, not a copy of it.
    if !headers_in_attested_forks_shape(
        &config.fork_schedule,
        &update.attested_header,
        &update.finalized_header,
    ) {
        let fork = config.fork_schedule.lc_fork_at_slot(slot);
        return Err(format!("an update for slot {slot} not in its fork's ({fork:?}) wire shape"));
    }
    let participants = update.sync_aggregate.count_participants();
    if participants * 3 < SYNC_COMMITTEE_SIZE * 2 {
        return Err(format!(
            "{participants}/{SYNC_COMMITTEE_SIZE} participants, below the 2/3 a wallet needs \
             (a period only minutes old may not have a better one yet)"
        ));
    }
    Ok(participants)
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
/// Then the catch-up from there: the anchor period's update, run through the
/// production processor started from that very bootstrap, and — once the chain
/// has left the anchor's period — the current period's, where a fresh install
/// has to arrive.
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

    // Where a fresh install's catch-up starts, and where it has to arrive —
    // read two epochs back, so a run in a period's first slots asks for the
    // period before it instead of failing every pin at once (see the header).
    let anchor_period = config.checkpoint_slot / config.slots_per_period();
    let head_period = config
        .wall_clock_slot()
        .saturating_sub(2 * config.slots_per_epoch)
        / config.slots_per_period();

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
            // RESULT CODE — byte 0 of the response frame — never on the
            // response's length: an error chunk is `code || varint ||
            // snappy(msg)`, about 20 B of framing plus the message, so a
            // 45-character error outweighs any length threshold — myotis-net's
            // own responder answers "InvalidRequest: bootstrap root must be 32
            // bytes" in 65 B. InvalidRequest and ServerError are final answers;
            // only ResourceUnavailable is the miss roost fills in the background.
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
                    let mut processor = LightClientProcessor::new(
                        LightClientStore::new(config.slots_per_period()),
                        config.fork_schedule.clone(),
                        config.genesis_validators_root,
                    );
                    let verdict = {
                        let fork = config.lc_fork_of_chunk(
                            &d.fork_digest,
                            d.ssz_payload.len(),
                            LightClientBootstrap::GLOAS_SIZE,
                        );
                        match LightClientBootstrap::decode_for(fork, &d.ssz_payload) {
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
                            // The production checks, at the proof indices of the
                            // header's fork (sync.rs bootstrap path).
                            Ok(b) => processor
                                .verify_bootstrap(&b)
                                .map(|()| b)
                                .map_err(|reason| reason.to_string()),
                        }
                    };
                    match verdict {
                        Err(why) => {
                            dead.push(format!("{pin} — {why}"));
                            eprintln!("[pins] BAD  {addr} — {why}");
                        }
                        Ok(bootstrap) => {
                            // #422 was "cannot CATCH UP", which needs
                            // updates_by_range — a server that bootstraps and
                            // then refuses updates strands a stale install just
                            // as thoroughly. So: the anchor period's update,
                            // through the production processor started from
                            // this very bootstrap — committee, the 2/3 bar, the
                            // BLS aggregate and every branch, exactly what a
                            // fresh install does with it.
                            processor.store.initialize(
                                bootstrap.header.clone(),
                                bootstrap.current_sync_committee.clone(),
                            );
                            let at_anchor =
                                ask_update(&client, &config, peer, &addr, anchor_period, false)
                                    .await;
                            let catch_up = match at_anchor {
                                Ok(update) if processor.process_update(&update) => {
                                    if head_period <= anchor_period {
                                        Ok(String::new())
                                    } else {
                                        // Same peer and protocol again: wait
                                        // out its quota window first.
                                        ask_update(&client, &config, peer, &addr, head_period, true)
                                            .await
                                            .and_then(|update| {
                                                head_update_ok(&config, &update, head_period)
                                            })
                                            .map(|participants| {
                                                format!(
                                                    ", current period {head_period} at \
                                                     {participants}/{SYNC_COMMITTEE_SIZE}"
                                                )
                                            })
                                            .map_err(|why| {
                                                format!(
                                                    "updates_by_range({head_period}), the current \
                                                     period, gave {why}"
                                                )
                                            })
                                    }
                                }
                                Ok(update) => Err(format!(
                                    "updates_by_range({anchor_period}) gave an update \
                                     (attested slot {}, {}/{SYNC_COMMITTEE_SIZE}) the \
                                     production processor refused — RUST_LOG=debug names \
                                     the gate",
                                    update.attested_header.beacon.slot,
                                    update.sync_aggregate.count_participants()
                                )),
                                Err(why) => {
                                    Err(format!("updates_by_range({anchor_period}) gave {why}"))
                                }
                            };
                            match catch_up {
                                Ok(head) => {
                                    alive += 1;
                                    eprintln!(
                                        "[pins] OK   {addr} (bootstrap {} B, period \
                                         {anchor_period} update verified{head})",
                                        d.ssz_payload.len()
                                    );
                                }
                                Err(why) => {
                                    dead.push(format!("{pin} — bootstraps, but {why}"));
                                    eprintln!("[pins] HALF {addr} — bootstrap ok, but {why}");
                                }
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
                    // outlast: roost's background fill is not keeping up. An
                    // error answer's message is snappy-framed, which
                    // `decode_response` prints raw; `leading_error` reads it.
                    let why = match codec::leading_error(&raw) {
                        Some((code, msg)) => format!("result code {code} {msg:?}"),
                        None => e.to_string(),
                    };
                    dead.push(format!("{pin} — {why}"));
                    eprintln!("[pins] THIN {addr} — {why}");
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
    let served = if head_period > anchor_period {
        format!("the anchor (period {anchor_period}) and the current period ({head_period})")
    } else {
        format!("the anchor (period {anchor_period})")
    };
    eprintln!("[pins] {alive} of {total} pinned {} peers served {served}", config.name);
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
        "only {alive} of {total} pinned CL peers on {} served {served} (want at \
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
