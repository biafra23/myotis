//! roost — a dedicated light-client server (docs/lc-server-design.md).
//!
//! Status: **in progress.** `serve` runs the server — the libp2p responder over
//! the light-client store, the chain-view poller behind `status`, and ingestion
//! in background tasks. `probe` verifies the upstream path and `ingest` fills
//! the archive without listening. ENR publication and the back-archive below the
//! upstream light-client floor are what remain. Context bytes are computed from
//! the chain's fork and blob schedule (`forks.rs`), not approximated.

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
         serve     Run the light-client server: libp2p responder + ingestion.\n    \
         enr       Print the ENR roost WOULD publish. Publishes nothing.\n\
         \n\
         OPTIONS:\n    \
         --rest URL       Nimbus REST base (default {DEFAULT_REST})\n    \
         --archive PATH   Archive file (default {DEFAULT_ARCHIVE})\n    \
         --port N         libp2p listen port for `serve` (default {DEFAULT_PORT})\n    \
         --key PATH       libp2p identity file (default: archive path with .key)\n    \
         --advertise IP   address to build the ENR for (`enr` command)\n"
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
        Some("serve") => serve::serve(&rest_base, &archive_path, key_path, port).await,
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
    let params = client.chain_params().await?;
    let (head_slot, syncing) = client.syncing().await?;
    let head_period = params.period_of_slot(head_slot);
    println!("  head      slot {head_slot} (period {head_period}), syncing={syncing}");
    println!(
        "  geometry  {} slots/epoch x {} epochs/period = {} slots per period",
        params.slots_per_epoch,
        params.epochs_per_sync_committee_period,
        params.slots_per_period()
    );

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
    let store = LcStore::new();
    for (period, rec) in &records {
        store.insert_update(*period, rec.fork_digest, &rec.ssz);
    }

    let params = client.chain_params().await?;
    let (head_slot, syncing) = client.syncing().await?;
    let head_period = params.period_of_slot(head_slot);
    println!("\n== upstream ==");
    println!("  head      slot {head_slot} (period {head_period}), syncing={syncing}");
    println!(
        "  geometry  {} slots/epoch x {} epochs/period = {} slots per period",
        params.slots_per_epoch,
        params.epochs_per_sync_committee_period,
        params.slots_per_period()
    );

    let floor = match find_window_floor(&client, head_period).await? {
        Some(f) => f,
        None => return Err(anyhow!("nimbus serves no light-client periods")),
    };
    println!("  window    periods {floor}..={head_period}");

    println!("\n== fill ==");
    let mut fetched = 0usize;
    let mut newest_digest = None;
    for period in floor..=head_period {
        if store.has_period(period) {
            continue;
        }
        let resp = client.updates(period, 1).await?;
        let chunks = split_updates(&resp.bytes)?;
        if chunks.is_empty() {
            println!("  period {period}: upstream returned no data, skipping");
            continue;
        }
        for c in &chunks {
            archive.append(period, c.fork_digest, &c.ssz)?;
            store.insert_update(period, c.fork_digest, &c.ssz);
            fetched += 1;
        }
        println!("  period {period}: stored {} chunk(s)", chunks.len());
    }
    archive.flush()?;
    println!("  fetched   {fetched} new period(s)");

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
    let schedule = forks::ForkSchedule::fetch(&client, gvr).await?;
    let params = client.chain_params().await?;
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
    println!("\n  NOT published. This command only builds the record.");
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
