//! roost — a dedicated light-client server (docs/lc-server-design.md).
//!
//! Status: **in progress.** `probe` verifies the upstream path; `ingest` fills
//! the durable archive and the in-memory serving store from Nimbus. The libp2p
//! responder, the chain-view poller behind `status`, and ENR publication come
//! next.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};

mod archive;
mod framing;
mod rest;
mod store;

use archive::Archive;
use framing::{split_updates, updates_to_wire};
use rest::{period_of_slot, NimbusRest};
use store::LcStore;

const DEFAULT_REST: &str = "http://127.0.0.1:5052";
const DEFAULT_ARCHIVE: &str = "roost-archive.db";

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
         ingest    Load the archive, fill it from Nimbus, and report coverage.\n\
         \n\
         OPTIONS:\n    \
         --rest URL       Nimbus REST base (default {DEFAULT_REST})\n    \
         --archive PATH   Archive file (default {DEFAULT_ARCHIVE})\n"
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
    let head_period = period_of_slot(head_slot);
    println!("  head      slot {head_slot} (period {head_period}), syncing={syncing}");

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

    let (head_slot, syncing) = client.syncing().await?;
    let head_period = period_of_slot(head_slot);
    println!("\n== upstream ==");
    println!("  head      slot {head_slot} (period {head_period}), syncing={syncing}");

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
            let accepted = store.insert_bootstrap(finalized, digest, &bs.bytes);
            bootstrap_root = Some(finalized);

            println!("  finality    {:>7} bytes", fin.bytes.len());
            println!("  optimistic  {:>7} bytes", opt.bytes.len());
            println!(
                "  bootstrap   {:>7} bytes  root=0x{}{}",
                bs.bytes.len(),
                hex::encode(&finalized[..8]),
                if accepted { "" } else { "  (REFUSED: cache full)" }
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
