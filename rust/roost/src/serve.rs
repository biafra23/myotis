//! The serving daemon: libp2p host + ingestion, wired to the store.
//!
//! Structurally this is the design's items 2, 3 and 4 together, because they
//! only make sense as a set:
//!
//! - **Ingestion runs entirely in background tasks** (item 2). Nothing here
//!   fetches from the request path.
//! - **A chain-view poller keeps `status` honest** (item 3). Easy to miss and
//!   the daemon is dead without it: `respond_inbound` answers `status` from
//!   `LocalStatus`, which in a wallet stays current only as a side effect of the
//!   sync loop decoding light-client headers. A byte-only cache that skipped
//!   this would serve its **initial checkpoint status forever**, and peers judge
//!   us on it.
//! - **Serving is a pure cache read** (item 4), which is what
//!   [`crate::store::LcStore`]'s `LcResponder` impl provides.
//!
//! The libp2p host itself is `myotis-net`'s, unmodified — one protocol stack,
//! not two. The only thing this crate adds is a responder to plug into it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use myotis_net::libp2p::identity::Keypair;
use myotis_net::reqresp::{start_host_with, HostConfig, LocalStatus};
use myotis_net::status::StatusMessage;

use crate::archive::Archive;
use crate::framing::split_updates;
use crate::rest::{period_of_slot, NimbusRest, SLOTS_PER_PERIOD};
use crate::store::LcStore;

/// How often to refresh the chain view and the per-slot objects. One slot.
const REFRESH: Duration = Duration::from_secs(12);

/// Inbound connection cap.
///
/// This is the number the whole design exists to be able to choose: a beacon
/// node's limit is sized for gossip peers and shared with its outbound dials,
/// and inheriting it is what starved wallets in the first place. Per-connection
/// cost here is a Noise session and a yamux stream — tens of KB — with no
/// gossipsub mesh, no peer scoring and no per-peer computation.
const MAX_INBOUND: u32 = 1024;

/// Bootstrap misses fetched per tick. The rate limit the design asks for: a
/// caller inventing roots costs us at most this many upstream requests per
/// slot, no matter how fast it asks.
const MISS_FETCHES_PER_TICK: usize = 4;

/// Load a persisted identity, or create and persist one.
///
/// Persistence is not an optimisation. A fresh key on every start means a new
/// node ID, so the published ENR becomes a new DHT entry with no accumulated
/// reachability, and every wallet's cached `/p2p/<peer-id>` points at an
/// identity that no longer exists — burning the three strikes to eviction and
/// taking the tokens that made the peer worth keeping with it. A routine deploy
/// would repeatedly un-learn this server from every wallet that had proven it.
/// The same lesson `--netkey-file` taught us on the Nimbus side.
fn load_or_create_key(path: &Path) -> Result<Keypair> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        return Keypair::from_protobuf_encoding(&bytes)
            .with_context(|| format!("decoding the identity key in {}", path.display()));
    }
    // The CL spec requires secp256k1 identities.
    let kp = Keypair::generate_secp256k1();
    let bytes = kp
        .to_protobuf_encoding()
        .map_err(|e| anyhow!("encoding a new identity key: {e}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, &bytes).with_context(|| format!("writing {}", path.display()))?;
    tracing::info!(path = %path.display(), "generated a new libp2p identity");
    Ok(kp)
}

/// Build the chain view a `status` answer is made of.
///
/// `earliest_available_slot` is derived from what we actually hold, not from
/// what Nimbus holds: it is the promise a peer judges us on, and over-claiming
/// it earns a goodbye the first time someone takes us up on it.
async fn chain_view(
    client: &NimbusRest,
    store: &LcStore,
    fork_digest: [u8; 4],
) -> Result<StatusMessage> {
    let (head_slot, head_root) = client.head_header().await?;
    let (finalized_root, finalized_epoch) = client.finalized_checkpoint().await?;
    let earliest_available_slot = store
        .coverage()
        .lowest_period
        .map(|p| p.saturating_mul(SLOTS_PER_PERIOD))
        .unwrap_or(0);
    Ok(StatusMessage {
        fork_digest,
        finalized_root,
        finalized_epoch,
        head_root,
        head_slot,
        earliest_available_slot,
    })
}

/// The fork digest to stamp on responses, taken from the newest update chunk.
///
/// INTERIM, and the one place roost is knowingly not spec-perfect: since
/// EIP-7892 the digest is not a function of the fork name, so it cannot be
/// derived from `Eth-Consensus-Version`; it has to be computed for the object's
/// slot via `fork_digest_bpo`. Re-using the newest period's digest is correct
/// except across a fork or BPO boundary. myotis' own decoder ignores context
/// bytes, so our wallets are unaffected; other CLs dispatch on them, which is
/// why this must be fixed before the ENR is published.
async fn interim_fork_digest(client: &NimbusRest, head_period: u64) -> Result<[u8; 4]> {
    let resp = client.updates(head_period, 1).await?;
    split_updates(&resp.bytes)?
        .first()
        .map(|c| c.fork_digest)
        .ok_or_else(|| anyhow!("no update at period {head_period} to take a fork digest from"))
}

/// The digest, trying the head period, then the one below it, then the newest
/// period already archived.
///
/// The middle case is the period rollover; the last is "upstream is briefly
/// unreachable but we hold an archive", where serving the last known digest
/// beats not serving.
async fn resolve_fork_digest(
    client: &NimbusRest,
    store: &LcStore,
    head_period: u64,
) -> Option<[u8; 4]> {
    for candidate in [Some(head_period), head_period.checked_sub(1)].into_iter().flatten() {
        if let Ok(d) = interim_fork_digest(client, candidate).await {
            return Some(d);
        }
    }
    let archived = store.newest_fork_digest();
    if archived.is_some() {
        tracing::warn!("upstream gave no fork digest — falling back to the newest archived one");
    }
    archived
}

/// Fill every period the upstream still serves that we do not already hold.
async fn fill_periods(
    client: &NimbusRest,
    store: &LcStore,
    archive: &mut Archive,
    floor: u64,
    head_period: u64,
) -> Result<usize> {
    let mut fetched = 0;
    for period in floor..=head_period {
        if store.has_period(period) {
            continue;
        }
        // One flaky request out of ~1300 must not abort a whole backfill; the
        // gap is simply retried on the next pass.
        let resp = match client.updates(period, 1).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(period, error = %e, "fetching a period failed; will retry");
                continue;
            }
        };
        let chunks = match split_updates(&resp.bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(period, error = %e, "unparseable updates body; skipping");
                continue;
            }
        };
        for c in &chunks {
            archive.append(period, c.fork_digest, &c.ssz)?;
            store.insert_update(period, c.fork_digest, &c.ssz);
            fetched += 1;
        }
    }
    if fetched > 0 {
        archive.flush()?;
    }
    Ok(fetched)
}

/// Run the daemon until Ctrl-C.
pub async fn serve(
    rest_base: &str,
    archive_path: &Path,
    key_path: Option<PathBuf>,
    port: u16,
) -> Result<()> {
    let client = NimbusRest::new(rest_base, Duration::from_secs(30))?;
    let gvr = client.genesis_validators_root().await?;

    let (mut archive, records, report) = Archive::open(archive_path, &gvr)?;
    let store = Arc::new(LcStore::new());
    for (period, rec) in &records {
        store.insert_update(*period, rec.fork_digest, &rec.ssz);
    }
    println!("== archive ==");
    println!("  path      {}", archive.path().display());
    println!("  loaded    {} record(s)", report.loaded);
    if report.corrupt_regions > 0 {
        println!("  WARNING   {} corrupt region(s) — see the log", report.corrupt_regions);
    }

    // Initial fill, so the server is useful the moment it starts listening.
    let (head_slot, _) = client.syncing().await?;
    let head_period = period_of_slot(head_slot);
    // Everything from here to `start_host_with` is BEST EFFORT. Startup must not
    // be able to fail on a transient upstream condition: at a period rollover
    // the head slot is already in period P while the newest servable update is
    // still P-1, so `find_window_floor` legitimately answers None — and a daemon
    // that exits there is one that cannot be restarted during a window which
    // recurs every ~27 hours. Whatever the archive already holds is servable, so
    // serve it and fill the rest in the background.
    match crate::find_window_floor(&client, head_period).await {
        Ok(Some(floor)) => {
            match fill_periods(&client, &store, &mut archive, floor, head_period).await {
                Ok(fetched) => {
                    println!("  filled    {fetched} new period(s), window {floor}..={head_period}")
                }
                Err(e) => println!("  filled    PARTIAL — {e}; the ticker will retry"),
            }
        }
        Ok(None) => println!(
            "  filled    upstream has no servable period yet (period rollover?) — serving the archive"
        ),
        Err(e) => println!("  filled    upstream probe failed: {e}; serving the archive"),
    }

    let fork_digest = match resolve_fork_digest(&client, &store, head_period).await {
        Some(d) => d,
        None => {
            return Err(anyhow!(
                "no fork digest available from upstream or the archive — refusing to serve, \
                 because a wrong digest in `status` makes every peer drop us"
            ))
        }
    };
    if let Err(e) = refresh_live(&client, &store, fork_digest).await {
        tracing::warn!(error = %e, "initial live-object fetch failed; the ticker will retry");
    }

    let status = LocalStatus::new(chain_view(&client, &store, fork_digest).await?);
    let key_path = key_path.unwrap_or_else(|| archive_path.with_extension("key"));
    let keypair = load_or_create_key(&key_path)?;

    let listen = format!("/ip4/0.0.0.0/tcp/{port}")
        .parse()
        .map_err(|e| anyhow!("bad listen address: {e}"))?;
    let (_client, peer_id, swarm_task) = start_host_with(
        status.clone(),
        HostConfig {
            listen,
            max_established_incoming: Some(MAX_INBOUND),
            keypair: Some(keypair),
            lc_responder: Some(store.clone()),
        },
    )
    .map_err(|e| anyhow!("starting the libp2p host: {e}"))?;

    let c = store.coverage();
    println!("\n== serving ==");
    println!("  identity  {} (persisted in {})", peer_id, key_path.display());
    println!("  multiaddr /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}");
    println!("  periods   {} ({:?}..={:?})", c.periods, c.lowest_period, c.highest_period);
    println!("  digest    0x{} (interim)", hex::encode(fork_digest));
    println!("  inbound   cap {MAX_INBOUND}");
    println!("\n  point a wallet at the multiaddr above; Ctrl-C to stop.\n");

    let mut swarm_task = swarm_task;
    let mut fork_digest = fork_digest;
    let mut ticker = tokio::time::interval(REFRESH);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nshutting down");
                return Ok(());
            }
            // The swarm task owns the listener and every connection. If it ends
            // we are no longer serving anything, but the process would happily
            // keep polling Nimbus forever — a silent outage no supervisor can
            // see, because `Restart=` only acts on a process that exits. So
            // exit, loudly, and let the unit restart us.
            joined = &mut swarm_task => {
                let how = match joined {
                    Ok(()) => "returned".to_string(),
                    Err(e) if e.is_panic() => "PANICKED".to_string(),
                    Err(e) => format!("failed: {e}"),
                };
                tracing::error!(outcome = %how, "libp2p swarm task ended — no longer serving");
                return Err(anyhow!("libp2p swarm task ended ({how}) — exiting so the supervisor can restart us"));
            }
            _ = ticker.tick() => {
                // Every failure here is logged and swallowed: a REST hiccup must
                // degrade what we serve, never take the responder down. A stale
                // relay surfaces to wallets as "not ready", which is the
                // detectable failure the design accepts.
                // Re-resolve the digest EVERY tick. It is not only context
                // bytes: it is also `status.fork_digest`, which every peer's
                // relevance check reads on the mandatory handshake. Held
                // constant, a process that stays up across a fork or BPO
                // boundary advertises the pre-fork digest indefinitely — other
                // clients answer with Goodbye(IrrelevantNetwork), and myotis
                // wallets filter us out on `accepted_fork_digests`, so we go
                // invisible to exactly the clients we exist for.
                match client.syncing().await {
                    Ok((slot, _)) => {
                        if let Some(d) = resolve_fork_digest(&client, &store, period_of_slot(slot)).await {
                            if d != fork_digest {
                                tracing::warn!(old = %hex::encode(fork_digest), new = %hex::encode(d),
                                    "fork digest changed — fork or BPO boundary crossed");
                                fork_digest = d;
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "polling head slot for the digest failed"),
                }
                if let Err(e) = refresh_live(&client, &store, fork_digest).await {
                    tracing::warn!(error = %e, "refreshing live objects failed");
                }
                if let Err(e) = fill_bootstrap_misses(&client, &store, fork_digest).await {
                    tracing::warn!(error = %e, "filling bootstrap misses failed");
                }
                match chain_view(&client, &store, fork_digest).await {
                    Ok(view) => status.set(view),
                    Err(e) => tracing::warn!(error = %e, "refreshing the chain view failed"),
                }
                // A new period turns over every ~27 hours; checking each slot is
                // free next to the HTTP calls above.
                match client.syncing().await {
                    Ok((slot, _)) => {
                        let p = period_of_slot(slot);
                        if !store.has_period(p) {
                            match fill_periods(&client, &store, &mut archive, p, p).await {
                                Ok(n) if n > 0 => tracing::info!(period = p, "archived a new period"),
                                Ok(_) => {}
                                Err(e) => tracing::warn!(error = %e, "filling the new period failed"),
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "polling head slot failed"),
                }
            }
        }
    }
}

/// Refresh the per-slot objects and the checkpoint bootstrap.
async fn refresh_live(client: &NimbusRest, store: &LcStore, fork_digest: [u8; 4]) -> Result<()> {
    let fin = client.finality_update().await?;
    store.set_finality(fork_digest, &fin.bytes);
    let opt = client.optimistic_update().await?;
    store.set_optimistic(fork_digest, &opt.bytes);

    // The current finalized root is pre-populated; anything else arrives through
    // the miss queue below, which is what keeps this key space bounded.
    let finalized = client.finalized_root().await?;
    if store.bootstrap(&finalized).is_none() {
        let bs = client.bootstrap(&finalized).await?;
        store.insert_bootstrap(finalized, fork_digest, &bs.bytes);
    }
    Ok(())
}

/// Fetch bootstraps that callers asked for and we did not have.
///
/// A wallet's first request is always for its OWN pinned checkpoint root, which
/// no pre-population can guess — so without this a cold wallet is refused
/// forever. Each root is attempted once and the batch is capped, so a caller
/// inventing roots cannot fan out into a burst of upstream fetches.
async fn fill_bootstrap_misses(
    client: &NimbusRest,
    store: &LcStore,
    fork_digest: [u8; 4],
) -> Result<usize> {
    let mut filled = 0;
    for root in store.take_bootstrap_misses(MISS_FETCHES_PER_TICK) {
        match client.bootstrap(&root).await {
            Ok(bs) => {
                store.insert_bootstrap(root, fork_digest, &bs.bytes);
                filled += 1;
                tracing::info!(root = %hex::encode(&root[..8]), bytes = bs.bytes.len(),
                    "filled a requested bootstrap");
            }
            // Upstream cannot serve it (typically below its window). Already
            // marked attempted, so we will not ask again.
            Err(e) => tracing::info!(root = %hex::encode(&root[..8]), error = %e,
                "upstream cannot serve this bootstrap"),
        }
    }
    Ok(filled)
}
