//! roost — a dedicated light-client server (docs/lc-server-design.md).
//!
//! Status: **in progress.** `serve` runs the server — the libp2p responder over
//! the light-client store, the chain-view poller behind `status`, ingestion in
//! background tasks, and discv5: it joins the DHT and publishes the ENR once
//! the external address is confirmed (#335; `--no-publish` joins without
//! publishing). `probe` verifies the upstream path and `ingest` fills the
//! archive without listening. The back-archive below the upstream light-client
//! floor is what remains. Context bytes are computed from the chain's fork and
//! blob schedule (`forks.rs`), not approximated.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

mod archive;
mod enr;
mod forks;
mod framing;
mod rest;
mod serve;
mod store;

use archive::Archive;
use framing::{split_updates, updates_to_wire};
use rest::NimbusRest;
use store::LcStore;

const DEFAULT_REST: &str = "http://127.0.0.1:5052";
const DEFAULT_ARCHIVE: &str = "roost-archive.db";
const DEFAULT_PORT: u16 = 9105;

fn usage() -> String {
    format!(
        "roost — dedicated light-client server\n\
         \n\
         USAGE:\n    \
         roost <COMMAND> [OPTIONS]\n\
         \n\
         COMMANDS:\n    \
         probe     Fetch every light-client endpoint from Nimbus, check the\n              \
         framing, and round-trip the updates through myotis' own decoder.\n    \
         ingest    Load the archive, fill it from Nimbus, and report coverage.\n    \
         serve     Run the light-client server: libp2p responder + ingestion +\n              \
         discv5 (joins the DHT; publishes the ENR once the address is\n              \
         confirmed — see --no-publish).\n    \
         enr       Print the ENR roost would publish. Publishes nothing.\n\
         \n\
         OPTIONS:\n    \
         --rest URL       Nimbus REST base (default {DEFAULT_REST})\n    \
         --archive PATH   Archive file (default {DEFAULT_ARCHIVE})\n    \
         --port N         libp2p TCP listen port for `serve`; discv5 binds the\n                     \
         same number on UDP (default {DEFAULT_PORT})\n    \
         --key PATH       libp2p identity file (default: archive path with .key)\n    \
         --advertise IP   address to build the ENR for (`enr` command)\n    \
         --no-publish     `serve`: join the discv5 DHT but never publish the\n                     \
         record — the deliberate first deployment step (#335)\n"
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut rest_base = DEFAULT_REST.to_string();
    let mut archive_path = PathBuf::from(DEFAULT_ARCHIVE);
    let mut key_path: Option<PathBuf> = None;
    let mut advertise: Option<String> = None;
    let mut port = DEFAULT_PORT;
    let mut publish_enr = true;
    let mut command = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rest" => {
                i += 1;
                rest_base = args
                    .get(i)
                    .ok_or_else(|| anyhow!("--rest needs a URL\n\n{}", usage()))?
                    .clone();
            }
            "--archive" => {
                i += 1;
                archive_path = PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| anyhow!("--archive needs a path\n\n{}", usage()))?,
                );
            }
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or_else(|| anyhow!("--port needs a number\n\n{}", usage()))?
                    .parse::<u16>()
                    .ok()
                    // Zero is a valid u16 but not a valid listen port here: it
                    // asks the OS for an ephemeral one, and the daemon would
                    // then advertise `/tcp/0`, which nothing can dial. Reject it
                    // rather than print an unusable multiaddr.
                    .filter(|p| *p != 0)
                    .ok_or_else(|| anyhow!("--port must be a number 1-65535\n\n{}", usage()))?;
            }
            "--key" => {
                i += 1;
                key_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| anyhow!("--key needs a path\n\n{}", usage()))?,
                ));
            }
            "--advertise" => {
                i += 1;
                advertise = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow!("--advertise needs an IP\n\n{}", usage()))?
                        .clone(),
                );
            }
            "--no-publish" => publish_enr = false,
            "-h" | "--help" => {
                print!("{}", usage());
                return Ok(());
            }
            other if command.is_none() => command = Some(other.to_string()),
            other => return Err(anyhow!("unexpected argument '{other}'\n\n{}", usage())),
        }
        i += 1;
    }

    match command.as_deref() {
        Some("probe") => probe(&rest_base).await,
        Some("ingest") => ingest(&rest_base, &archive_path).await,
        Some("serve") => serve::serve(&rest_base, &archive_path, key_path, port, publish_enr).await,
        Some("enr") => show_enr(&rest_base, &archive_path, key_path, advertise, port).await,
        Some(other) => Err(anyhow!("unknown command '{other}'\n\n{}", usage())),
        None => {
            print!("{}", usage());
            Ok(())
        }
    }
}

/// Exercise every upstream path and report what a serving daemon would have to
/// work with. Read-only: it fetches, parses and re-encodes, and stores nothing.
async fn probe(rest_base: &str) -> Result<()> {
    let client = NimbusRest::new(rest_base, Duration::from_secs(30))?;

    println!("== upstream ==");
    println!("  rest      {rest_base}");
    println!("  version   {}", client.node_version().await?);
    let (head_slot, syncing) = client.syncing().await?;
    println!("  head      slot {head_slot}, syncing={syncing}");

    println!("\n== single-object endpoints ==");
    for (name, resp) in [
        ("finality_update", client.finality_update().await?),
        ("optimistic_update", client.optimistic_update().await?),
    ] {
        println!(
            "  {name:<18} {:>7} bytes   fork={}",
            resp.bytes.len(),
            resp.consensus_version.as_deref().unwrap_or("-"),
        );
    }

    let finalized = client.finalized_root().await?;
    let bootstrap = client.bootstrap(&finalized).await?;
    println!(
        "  {:<18} {:>7} bytes   fork={}   root=0x{}",
        "bootstrap",
        bootstrap.bytes.len(),
        bootstrap.consensus_version.as_deref().unwrap_or("-"),
        hex::encode(&finalized[..8]),
    );

    // Geometry LAST of the things that can fail, and non-fatally. probe writes
    // nothing, so unlike `serve` it should still report what it managed to
    // learn: a failure here is exactly the run an operator makes when the
    // upstream is already misbehaving, and aborting before the report is the
    // least useful moment to abort.
    println!("\n== geometry ==");
    let params = match client.chain_params().await {
        Ok(p) => {
            println!(
                "  {} slots/epoch x {} epochs/period = {} slots per period",
                p.slots_per_epoch(),
                p.epochs_per_sync_committee_period(),
                p.slots_per_period()
            );
            p
        }
        Err(e) => {
            println!("  unavailable — {e:#}");
            println!("\n  skipping the period-dependent sections (updates framing, fork digest,");
            println!("  servable window): every one of them is keyed by period.");
            return Ok(());
        }
    };
    let head_period = params.period_of_slot(head_slot);
    println!("  head slot {head_slot} is in period {head_period}");

    println!("\n== updates: framing and re-encode ==");
    let resp = client.updates(head_period, 1).await?;
    let chunks = split_updates(&resp.bytes)?;
    if chunks.is_empty() {
        return Err(anyhow!(
            "period {head_period} returned no update — the node's window may lag its head"
        ));
    }
    for c in &chunks {
        println!(
            "  period {head_period}: {:>7} SSZ bytes   digest=0x{}",
            c.ssz.len(),
            hex::encode(c.fork_digest),
        );
    }

    let wire = updates_to_wire(&chunks);
    let decoded = myotis_net::codec::decode_multi_chunk_response(&wire, chunks.len())
        .map_err(|e| anyhow!("re-encoded updates failed myotis' own decoder: {e:?}"))?;
    if decoded.len() != chunks.len() {
        return Err(anyhow!(
            "decoder returned {} chunk(s), framed {}",
            decoded.len(),
            chunks.len()
        ));
    }
    for (i, (orig, back)) in chunks.iter().zip(decoded.iter()).enumerate() {
        if &orig.ssz != back {
            return Err(anyhow!("chunk {i} did not survive the round trip"));
        }
    }
    println!(
        "  round trip  OK  ({} chunk(s), {} wire bytes -> myotis decoder)",
        chunks.len(),
        wire.len()
    );

    // The check that keeps context bytes honest: what we COMPUTE from the
    // chain's fork and blob schedule must equal what the upstream actually
    // framed. Only the `updates` protocol carries a digest on the wire, so this
    // is the one place the computation can be checked against ground truth —
    // and it is what every other endpoint's context bytes now rest on.
    println!("\n== fork digest ==");
    let gvr = client.genesis_validators_root().await?;
    match forks::ForkSchedule::fetch(&client, gvr).await {
        Ok(schedule) => {
            let computed = schedule.digest_for_slot(head_slot);
            let observed = chunks[0].fork_digest;
            let fork = schedule.fork_at_epoch(head_slot / schedule.slots_per_epoch());
            println!(
                "  fork      version 0x{} active from epoch {}",
                hex::encode(fork.version),
                fork.epoch
            );
            match schedule.blob_params_at_epoch(head_slot / schedule.slots_per_epoch()) {
                Some(bp) => println!(
                    "  blobs     BPO epoch {}, max {} per block",
                    bp.epoch, bp.max_blobs
                ),
                None => println!("  blobs     no BPO active (pre-Fulu formula)"),
            }
            println!("  computed  0x{}", hex::encode(computed));
            println!("  on wire   0x{}", hex::encode(observed));
            if computed == observed {
                println!("  MATCH     context bytes can be computed for any slot");
            } else {
                // NOT an error. The wire digest belongs to the update's attested
                // header, which can predate a fork or BPO boundary that head is
                // already past — a period spans 256 epochs, so the two SHOULD
                // differ during a transition. Failing here would make `probe`
                // report a schedule fault precisely when the schedule is doing
                // its job. `serve` treats the same signal the same way.
                println!(
                    "  DIFFER    expected across a fork/BPO boundary inside this period\n\
                     \x20           (the wire digest is the update's attested header, not head);\n\
                     \x20           otherwise it means the schedule and the chain disagree."
                );
            }
        }
        Err(e) => println!("  unavailable — {e:#}"),
    }

    let span = 3u64.min(head_period + 1);
    let multi = client.updates(head_period + 1 - span, span).await?;
    let multi_chunks = split_updates(&multi.bytes)?;
    println!(
        "  multi       {} period(s) from {} -> {} chunk(s), {} bytes",
        span,
        head_period + 1 - span,
        multi_chunks.len(),
        multi.bytes.len()
    );

    println!("\n== servable window ==");
    match find_window_floor(&client, head_period).await? {
        Some(f) => {
            println!(
                "  nimbus serves periods {f}..={head_period} ({} periods)",
                head_period - f + 1
            );
            println!(
                "  archive gap  periods 0..{} are NOT available upstream — roost's own\n\
                 \x20              archive is what closes this, and nothing we operate can\n\
                 \x20              regenerate it once collected.",
                f.saturating_sub(1)
            );
        }
        None => println!("  no servable period found (is --light-client-data-serve set?)"),
    }

    Ok(())
}

/// Load the archive, fill every period Nimbus can still serve, and report.
///
/// One request per period rather than batching with `count>1`: the endpoint
/// returns a bare concatenation with no period labels, so a batch's chunks can
/// only be mapped back positionally. That is fine when the window is dense and
/// silently wrong when it is not — and mis-keying an *archive* record is a
/// durable error. Over loopback the extra round trips cost nothing.
async fn ingest(rest_base: &str, archive_path: &Path) -> Result<()> {
    let client = NimbusRest::new(rest_base, Duration::from_secs(30))?;
    let gvr = client.genesis_validators_root().await?;
    // Before Archive::open, matching `serve`. Archive::open is not read-only —
    // it repairs a torn tail with an in-place set_len — so "a chain roost cannot
    // measure is one it never touches records for" should hold on both write
    // paths, not just the one where it was written down.
    let params = client.chain_params().await?;

    println!("== archive ==");
    let (mut archive, records, report) = Archive::open(archive_path, &gvr)?;
    println!("  path      {}", archive.path().display());
    println!("  chain     genesis_validators_root 0x{}…", hex::encode(&gvr[..8]));
    println!(
        "  loaded    {} record(s){}{}",
        report.loaded,
        if report.torn_tail_bytes > 0 {
            format!(", repaired a {}-byte torn tail", report.torn_tail_bytes)
        } else {
            String::new()
        },
        if report.corrupt_regions > 0 {
            format!(", {} CORRUPT region(s) — see the log", report.corrupt_regions)
        } else {
            String::new()
        },
    );

    // Memory is an accelerator in front of the archive, so the store is rebuilt
    // from it on every start. Re-encoding 1327 periods is milliseconds.
    // Participation is decoded alongside: the fill loop below uses it to decide
    // whether a stored update is provisional. Last record per period wins, the
    // same last-wins rule insert_update applies.
    let store = LcStore::new();
    let mut participation: std::collections::BTreeMap<u64, usize> =
        std::collections::BTreeMap::new();
    let mut held_periods: std::collections::BTreeSet<u64> =
        std::collections::BTreeSet::new();
    for (period, rec) in &records {
        store.insert_update(*period, rec.fork_digest, &rec.ssz);
        held_periods.insert(*period);
        match participation_of(&rec.ssz) {
            Some(p) => {
                participation.insert(*period, p);
            }
            None => {
                participation.remove(period);
            }
        }
    }

    let (head_slot, syncing) = client.syncing().await?;
    let head_period = params.period_of_slot(head_slot);
    println!("\n== upstream ==");
    println!("  head      slot {head_slot} (period {head_period}), syncing={syncing}");
    println!(
        "  geometry  {} slots/epoch x {} epochs/period = {} slots per period",
        params.slots_per_epoch(),
        params.epochs_per_sync_committee_period(),
        params.slots_per_period()
    );

    let floor = match find_window_floor(&client, head_period).await? {
        Some(f) => f,
        None => return Err(anyhow!("nimbus serves no light-client periods")),
    };
    println!("  window    periods {floor}..={head_period}");

    println!("\n== fill ==");
    // A stored update is PROVISIONAL — refetched, not frozen — when its
    // sync-aggregate participation is below the light-client supermajority
    // (participants*3 < SYNC_COMMITTEE_SIZE*2) or its period is still in
    // progress. Upstream's by-range answer is its best update SEEN SO FAR, so
    // an ingest that runs early in a period can capture the period's first
    // slots' update carrying a fraction of the committee (observed: 113/512 at
    // mainnet period 1840, attested at the period's slot 0) — and a wallet
    // REFUSES < 2/3, so a frozen weak update stalls every catch-up through
    // that period, silently, forever. `has_period` used to be that freezer.
    // Replacement is strictly-better-only (more participants), so a repeated
    // ingest never grows the archive with equal copies; the append-only
    // archive + last-wins insert_update/rebuild make the better record
    // supersede on this run and on every later start.
    let mut fetched = 0usize;
    let mut newest_digest = None;
    // Below the upstream window nothing can be refetched from this node — and
    // below-floor periods are exactly roost's unique serving value — so a weak
    // or undecodable record there is an UNHEALABLE stall for every wallet that
    // walks it. Nothing to fix automatically; say it loudly instead of the
    // silence that hid period 1840 (restore from a back-archive or a node with
    // deeper light-client retention).
    for (&period, &p) in participation.range(..floor) {
        if below_supermajority(p) {
            println!(
                "  period {period}: WEAK ({p} participants) and below the \
                 upstream window — unhealable from this node"
            );
        }
    }
    for &period in held_periods.range(..floor) {
        if !participation.contains_key(&period) {
            println!(
                "  period {period}: UNDECODABLE and below the upstream window — \
                 unhealable from this node"
            );
        }
    }

    for period in floor..=head_period {
        let held = store.has_period(period);
        let stored = participation.get(&period).copied();
        if !needs_refetch(held, stored, period == head_period) {
            continue;
        }
        let resp = client.updates(period, 1).await?;
        let chunks = split_updates(&resp.bytes)?;
        if chunks.is_empty() {
            println!("  period {period}: upstream returned no data, skipping");
            continue;
        }
        let mut stored_now = 0usize;
        for c in &chunks {
            if held {
                let fresh = participation_of(&c.ssz);
                if !should_replace(stored, fresh) {
                    if let (Some(old), Some(new)) = (stored, fresh) {
                        println!(
                            "  period {period}: upstream no better \
                             ({new} <= {old} participants), keeping"
                        );
                    }
                    continue;
                }
                match (stored, fresh) {
                    (Some(old), Some(new)) => println!(
                        "  period {period}: replacing a provisional update \
                         ({old} -> {new} participants)"
                    ),
                    (None, Some(new)) => println!(
                        "  period {period}: replacing an undecodable stored \
                         update ({new} participants)"
                    ),
                    (_, None) => unreachable!("should_replace is false for an undecodable fresh chunk"),
                }
            }
            archive.append(period, c.fork_digest, &c.ssz)?;
            store.insert_update(period, c.fork_digest, &c.ssz);
            fetched += 1;
            stored_now += 1;
        }
        if stored_now > 0 && !held {
            println!("  period {period}: stored {stored_now} chunk(s)");
        }
    }
    archive.flush()?;
    println!("  fetched   {fetched} update(s) (new or replaced)");

    // The newest period's digest, used as the interim context bytes for the
    // single-object endpoints below.
    if let Ok(resp) = client.updates(head_period, 1).await {
        if let Some(c) = split_updates(&resp.bytes)?.first() {
            newest_digest = Some(c.fork_digest);
        }
    }

    println!("\n== live objects ==");
    let mut bootstrap_root = None;
    match newest_digest {
        Some(digest) => {
            let fin = client.finality_update().await?;
            let opt = client.optimistic_update().await?;
            store.set_finality(digest, &fin.bytes);
            store.set_optimistic(digest, &opt.bytes);

            let finalized = client.finalized_root().await?;
            let bs = client.bootstrap(&finalized).await?;
            store.insert_bootstrap(finalized, digest, &bs.bytes);
            bootstrap_root = Some(finalized);

            println!("  finality    {:>7} bytes", fin.bytes.len());
            println!("  optimistic  {:>7} bytes", opt.bytes.len());
            println!(
                "  bootstrap   {:>7} bytes  root=0x{}",
                bs.bytes.len(),
                hex::encode(&finalized[..8]),
            );
            println!(
                "  context     0x{} — INTERIM: copied from the newest update chunk.\n\
                 \x20             Correct except across a fork or BPO boundary, where the\n\
                 \x20             head object's digest differs from the newest period's.\n\
                 \x20             myotis' own decoder ignores context bytes, so this is safe\n\
                 \x20             for our clients; other CLs dispatch on it. Computing it via\n\
                 \x20             fork_digest_bpo for the object's slot is the next task.",
                hex::encode(digest)
            );
        }
        None => println!("  skipped — no update available to take interim context bytes from"),
    }

    let c = store.coverage();
    println!("\n== coverage ==");
    println!(
        "  periods   {} ({}..={})",
        c.periods,
        c.lowest_period.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        c.highest_period.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
    );
    println!("  encoded   {} KB of pre-encoded update responses", c.update_bytes / 1024);
    println!("  bootstraps {}", c.bootstraps);
    println!(
        "  live      finality={} optimistic={}",
        c.has_finality, c.has_optimistic
    );
    if let Some(lowest) = c.lowest_period {
        if lowest > 0 {
            println!(
                "  gap       periods 0..{} are absent and cannot be sourced from this node —\n\
                 \x20           that is what the back-archive is for.",
                lowest - 1
            );
        }
    }

    serving_self_check(&store, &c, bootstrap_root)?;
    Ok(())
}

/// Sync-aggregate participant count of an SSZ-encoded `LightClientUpdate`, or
/// `None` when it does not decode with this build's (fork-polymorphic) decoder.
/// Used by ingest to judge whether a stored update is provisional.
fn participation_of(ssz: &[u8]) -> Option<usize> {
    myotis_consensus::types::LightClientUpdate::decode(ssz)
        .ok()
        .map(|u| u.sync_aggregate.count_participants())
}

/// Below the light-client supermajority bar — a wallet REFUSES such an update,
/// so serving one stalls every catch-up through its period.
fn below_supermajority(participants: usize) -> bool {
    participants * 3 < myotis_consensus::spec::SYNC_COMMITTEE_SIZE * 2
}

/// Whether ingest must refetch a period from upstream instead of freezing what
/// it holds: not held at all; still in progress (upstream's by-range answer is
/// its best update SEEN SO FAR, improving as the period ages); stored below
/// the supermajority; or stored undecodable by this build (`stored == None`
/// while held — a record nobody with this decoder can use). Pure — every
/// promised ingest property is pinned by the table tests below.
fn needs_refetch(held: bool, stored: Option<usize>, in_progress: bool) -> bool {
    !held || in_progress || stored.is_none_or(below_supermajority)
}

/// Whether a fresh chunk replaces a held record: strictly more participants;
/// a decodable update beats an undecodable stored one; an undecodable fresh
/// chunk never replaces anything (it cannot be judged). Strictly-better-only
/// is what makes repeated ingests idempotent — equal copies are never
/// re-appended. Pure — pinned by the table tests below.
fn should_replace(stored: Option<usize>, fresh: Option<usize>) -> bool {
    match (stored, fresh) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(old), Some(new)) => new > old,
    }
}

/// Serve from the store exactly as the libp2p responder will, and decode the
/// result with myotis' own decoder.
///
/// This is the last check that does not need a socket: it exercises the real
/// read paths, the real pre-encoded bytes and the real miss behaviour, so a
/// failure here is a store bug rather than a networking one. Once the responder
/// lands, the only thing added on top is the swarm.
fn serving_self_check(
    store: &LcStore,
    coverage: &store::Coverage,
    bootstrap_root: Option<[u8; 32]>,
) -> Result<()> {
    println!("\n== serving self-check ==");

    let (Some(lo), Some(hi)) = (coverage.lowest_period, coverage.highest_period) else {
        println!("  store is empty — nothing to serve");
        return Ok(());
    };

    let inner_gaps = store.gaps(lo, hi);
    if inner_gaps.is_empty() {
        println!("  contiguity  {lo}..={hi}, no holes");
    } else {
        println!("  contiguity  HOLES at {inner_gaps:?} — a range request stops at the first one");
    }

    // The request a cold wallet actually makes, clamped to the spec's cap.
    let count = (hi - lo + 1).min(rest::MAX_REQUEST_LIGHT_CLIENT_UPDATES);
    let body = store
        .updates_range(lo, count)
        .ok_or_else(|| anyhow!("store refused to serve its own range {lo}..={hi}"))?;
    let decoded = myotis_net::codec::decode_multi_chunk_response(&body, count as usize)
        .map_err(|e| anyhow!("served updates_by_range failed myotis' own decoder: {e:?}"))?;
    println!(
        "  by_range    {lo}..={} -> {} chunk(s), {} wire bytes, decodes OK",
        lo + count - 1,
        decoded.len(),
        body.len()
    );

    // The miss path matters as much as the hit path: it is what makes
    // `ResourceUnavailable` correct rather than a bug.
    if lo > 0 && store.updates_range(lo - 1, 1).is_some() {
        return Err(anyhow!("store served period {} which it does not have", lo - 1));
    }
    if store.updates_range(hi + 1, 1).is_some() {
        return Err(anyhow!("store served period {} which it does not have", hi + 1));
    }
    println!("  miss        below and above the window -> None (ResourceUnavailable)");

    for (name, bytes) in [
        ("finality", store.finality()),
        ("optimistic", store.optimistic()),
    ] {
        match bytes {
            Some(b) => {
                myotis_net::codec::decode_multi_chunk_response(&b, 1)
                    .map_err(|e| anyhow!("served {name} failed myotis' own decoder: {e:?}"))?;
                println!("  {name:<11} {} wire bytes, decodes OK", b.len());
            }
            None => println!("  {name:<11} absent"),
        }
    }

    // Bootstraps are keyed by an arbitrary root, so "we have the one we
    // pre-populated, and nothing else" is the property worth asserting.
    match bootstrap_root {
        Some(root) => {
            let b = store
                .bootstrap(&root)
                .ok_or_else(|| anyhow!("store lost the bootstrap it just ingested"))?;
            myotis_net::codec::decode_multi_chunk_response(&b, 1)
                .map_err(|e| anyhow!("served bootstrap failed myotis' own decoder: {e:?}"))?;
            println!("  bootstrap   {} wire bytes, decodes OK", b.len());
            if store.bootstrap(&[0xab; 32]).is_some() {
                return Err(anyhow!("store served a bootstrap root it never ingested"));
            }
            println!("  bootstrap   unknown root -> None (ResourceUnavailable)");
        }
        None => println!("  bootstrap   absent"),
    }

    Ok(())
}

/// Print the ENR roost would publish, and publish nothing.
///
/// Separating "build the record" from "put it in the DHT" is deliberate: a
/// published record is cached by wallets and a wrong one is worse than none —
/// they discover it, dial, fail, and spend their three strikes to eviction on a
/// node that is healthy. This makes the record inspectable first.
async fn show_enr(
    rest_base: &str,
    archive_path: &Path,
    key_path: Option<PathBuf>,
    advertise: Option<String>,
    port: u16,
) -> Result<()> {
    let ip: std::net::IpAddr = advertise
        .ok_or_else(|| {
            anyhow!(
                "--advertise <ip> is required.\n\n\
                 There is deliberately no default: the address must come from \
                 somewhere that knows it — an operator who checked, or the running \
                 daemon's quorum of Identify reports. Guessing it is how a record \
                 ends up pointing at an address nothing answers on."
            )
        })?
        .parse()
        .context("parsing --advertise")?;

    if !myotis_net::reqresp::is_routable(ip) {
        println!("WARNING: {ip} is not reachable from the public internet.\n");
    }
    // `serve` listens on /ip4/0.0.0.0 only, so a v6 record would advertise an
    // endpoint nothing is listening on — undialable in the one place that must
    // not be.
    if ip.is_ipv6() {
        return Err(anyhow!(
            "IPv6 is not supported yet: `serve` listens on /ip4/0.0.0.0/tcp/{port} only, so a \
             v6 record would advertise an endpoint this server is not listening on"
        ));
    }

    let client = NimbusRest::new(rest_base, Duration::from_secs(30))?;
    let gvr = client.genesis_validators_root().await?;
    // ONE fetch of /config/spec feeding both, so the epoch the ENR is built for
    // cannot come from a different reading than the digest it carries.
    let (params, schedule) = forks::ForkSchedule::fetch_with_params(&client, gvr).await?;
    let schedule = schedule?;
    let (head_slot, syncing) = client.syncing().await?;
    // A syncing upstream reports a head behind the real one, and if it is behind
    // the most recent fork or BPO boundary the digest computed from it is the
    // PREVIOUS one. In a log that self-corrects on the next tick; in a published
    // record it is cached by wallets and only displaced by a higher-sequence
    // record — so refuse rather than bake a stale digest into an artifact whose
    // whole purpose is to be found.
    if syncing {
        return Err(anyhow!(
            "upstream is still syncing (head slot {head_slot}) — the head epoch, and therefore \
             the fork digest, would be stale. A published record with a stale digest is \
             invisible to exactly the clients it is for."
        ));
    }
    // One source for slot->epoch, so the ENR's fork id cannot disagree with the
    // period math the rest of the daemon uses.
    let epoch = params.epoch_of_slot(head_slot);
    let eth2 = schedule.enr_fork_id(epoch);

    // The SAME key the libp2p host authenticates with — including a --key
    // override, which this command previously accepted and silently ignored
    // while auto-creating a different identity next to the archive.
    let key_path = key_path.unwrap_or_else(|| archive_path.with_extension("key"));
    let host_key = serve::load_or_create_key(&key_path)?;
    let key = myotis_net::discovery::discv5_key_from_libp2p(&host_key).map_err(|e| anyhow!("{e}"))?;
    let mut seq = enr::EnrSeq::load(archive_path.with_extension("enrseq"))?;

    // Persist BEFORE use, which is the discipline EnrSeq documents: a crash
    // between publishing and persisting would re-issue a number the network has
    // already seen, and the DHT ignores a record that does not out-rank the
    // cached one.
    let seq_for_record = seq.bump()?;
    let record = myotis_net::discovery::build_server_enr(&key, seq_for_record, ip, port, port, eth2)
        .map_err(|e| anyhow!("{e}"))?;

    println!("== enr ==");
    println!("  identity  {} (the libp2p host key)", key_path.display());
    println!("  node id   {}", record.node_id());
    println!(
        "  peer id   {} (derived from the ENR key — must match what `serve` announces)",
        myotis_net::PeerId::from(host_key.public())
    );
    println!("  seq       {seq_for_record} (persisted before use)");
    println!("  endpoint  {ip} tcp/{port} udp/{port}");
    println!("  eth2      0x{}", hex::encode(eth2));
    println!("    digest      0x{}", hex::encode(&eth2[..4]));
    println!("    next fork   0x{}", hex::encode(&eth2[4..8]));
    let next_epoch = u64::from_le_bytes(eth2[8..].try_into().expect("16-byte field"));
    println!(
        "    next epoch  {}",
        if next_epoch == u64::MAX { "far future (none scheduled)".to_string() } else { next_epoch.to_string() }
    );
    // to_base64() explicitly rather than Display. They are the same today
    // (enr 0.13's Display forwards to it), but this is a WIRE format and
    // depending on a Display impl for one lets an upstream cosmetic change
    // silently alter what an operator pastes into a bootnode list.
    println!("\n  {}", record.to_base64());
    println!(
        "\n  NOT published by this command — `serve` publishes automatically once the\n  \
         external address is confirmed (or joins without publishing under --no-publish).\n  \
         Note this run consumed a sequence number from the shared .enrseq file; that is\n  \
         harmless (gaps are fine, reuse is not), but a `serve` running on the same data\n  \
         directory holds its own count in memory, so inspect a LIVE deployment's record\n  \
         from its log rather than by running `enr` beside it."
    );
    Ok(())
}

/// Lowest period the node still serves.
///
/// Binary search rather than a linear walk: availability is contiguous (Nimbus
/// never prunes light-client data — `maxPeriods` unset means retain everything —
/// so the floor is "never had the states", not "threw it away"), and a linear
/// walk from 0 would be a thousand requests.
async fn find_window_floor(client: &NimbusRest, head_period: u64) -> Result<Option<u64>> {
    let has = |p: u64| async move {
        Ok::<bool, anyhow::Error>(!client.updates(p, 1).await?.bytes.is_empty())
    };

    if !has(head_period).await? {
        return Ok(None);
    }
    let (mut lo, mut hi) = (0u64, head_period); // hi always has data
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if has(mid).await? {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(Some(lo))
}

#[cfg(test)]
mod ingest_decision_tests {
    use super::{below_supermajority, needs_refetch, participation_of, should_replace};

    // 2/3 of 512 = 341.33…, so 342 participants is the lowest acceptable count.
    #[test]
    fn supermajority_bar_sits_at_two_thirds_of_512() {
        assert!(below_supermajority(0));
        assert!(below_supermajority(113)); // the frozen period-1840 record
        assert!(below_supermajority(341));
        assert!(!below_supermajority(342));
        assert!(!below_supermajority(512));
    }

    #[test]
    fn missing_periods_are_always_fetched() {
        assert!(needs_refetch(false, None, false));
        assert!(needs_refetch(false, None, true));
    }

    #[test]
    fn the_in_progress_period_is_always_provisional() {
        assert!(needs_refetch(true, Some(512), true));
    }

    #[test]
    fn a_weak_stored_update_is_provisional() {
        assert!(needs_refetch(true, Some(113), false));
        assert!(needs_refetch(true, Some(341), false));
    }

    #[test]
    fn an_undecodable_stored_update_is_provisional() {
        assert!(needs_refetch(true, None, false));
    }

    #[test]
    fn a_strong_complete_period_is_frozen() {
        assert!(!needs_refetch(true, Some(342), false));
        assert!(!needs_refetch(true, Some(512), false));
    }

    #[test]
    fn replacement_is_strictly_better_only() {
        assert!(should_replace(Some(113), Some(114)));
        assert!(should_replace(Some(113), Some(512)));
        assert!(!should_replace(Some(113), Some(113))); // idempotent re-ingest
        assert!(!should_replace(Some(512), Some(342)));
    }

    #[test]
    fn a_decodable_update_beats_an_undecodable_stored_one() {
        assert!(should_replace(None, Some(1)));
        assert!(should_replace(None, Some(512)));
    }

    #[test]
    fn an_undecodable_fresh_chunk_never_replaces_anything() {
        assert!(!should_replace(Some(113), None));
        assert!(!should_replace(None, None));
    }

    #[test]
    fn participation_of_rejects_undecodable_bytes() {
        assert_eq!(participation_of(&[]), None);
        assert_eq!(participation_of(&[0u8; 64]), None);
        assert_eq!(participation_of(b"not an ssz light client update"), None);
    }
}
