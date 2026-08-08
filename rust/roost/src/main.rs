//! roost — a dedicated light-client server (docs/lc-server-design.md).
//!
//! Status: **in progress.** Today this binary is the verification tool the rest
//! of the build leans on — `roost probe` exercises the whole upstream path
//! against a live Nimbus and closes the loop through myotis' own wire decoder.
//! The serving daemon (LC store, ingestion tasks, ENR publication) comes next.

use std::time::Duration;

use anyhow::{anyhow, Result};

mod framing;
mod rest;

use framing::{split_updates, updates_to_wire};
use rest::{period_of_slot, NimbusRest};

const DEFAULT_REST: &str = "http://127.0.0.1:5052";

fn usage() -> String {
    format!(
        "roost — dedicated light-client server\n\
         \n\
         USAGE:\n    \
         roost probe [--rest URL]\n\
         \n\
         COMMANDS:\n    \
         probe    Fetch every light-client endpoint from Nimbus, check the\n             \
         framing, and round-trip the updates through myotis' own decoder.\n\
         \n\
         OPTIONS:\n    \
         --rest URL    Nimbus REST base (default {DEFAULT_REST})\n"
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

    // A bootstrap is keyed by an arbitrary block root, so the only sane
    // pre-population key is a checkpoint-aligned one.
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

    // The loop that matters: what we frame for the wire is what our own wallets
    // already decode. Any divergence here is a bug we would otherwise only find
    // against a live client.
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

    // Multi-chunk is the shape `updates_by_range` actually answers in, so probe
    // it separately rather than inferring it from the single-period case.
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
    let floor = find_window_floor(&client, head_period).await?;
    match floor {
        Some(f) => {
            println!("  nimbus serves periods {f}..={head_period} ({} periods)", head_period - f + 1);
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
