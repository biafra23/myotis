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
use myotis_net::identity::Keypair;
use myotis_net::multiaddr::Protocol;
use myotis_net::reqresp::{
    start_host_with, ExternalAddress, HostConfig, LocalStatus, EXTERNAL_ADDR_QUORUM,
};
use myotis_net::Multiaddr;
use myotis_net::status::StatusMessage;

use crate::archive::Archive;
use crate::framing::split_updates;
use crate::forks::ForkSchedule;
use crate::rest::{period_of_slot, FetchError, NimbusRest, SLOTS_PER_PERIOD};
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

/// How often to re-read the chain's fork/blob schedule, in ticks.
///
/// It is configuration and changes only when the upstream is upgraded — but it
/// DOES change then (a client release can add a BPO entry), and a roost that
/// cached it at startup would keep stamping the old digest. ~5 minutes.
const SCHEDULE_REFRESH_TICKS: u32 = 25;

/// Bootstrap misses fetched per tick — the rate limit the design asks for.
///
/// A caller inventing roots costs us at most this many upstream fetches per
/// slot, no matter how fast it asks. Note each SUCCESSFUL fill is up to two
/// loopback requests — the bootstrap itself plus the `header_slot` lookup that
/// resolves its epoch — so the ceiling is 2x this number. Invented roots 404 on
/// the bootstrap and never reach the header lookup, so the ABUSE ceiling is
/// unchanged at one request each.
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // The CL spec requires secp256k1 identities.
    let kp = Keypair::generate_secp256k1();
    let bytes = kp
        .to_protobuf_encoding()
        .map_err(|e| anyhow!("encoding a new identity key: {e}"))?;

    // create_new + mode 0600 in ONE call. `exists()` then `write()` is both a
    // race (two starts can each see "missing" and the second clobbers the
    // identity the first published) and a permissions hole: plain `fs::write`
    // creates with the process umask, typically 0644, so any local user could
    // copy this key and impersonate the published server.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(&bytes)
                .with_context(|| format!("writing {}", path.display()))?;
            f.sync_all()?;
            tracing::info!(path = %path.display(), "generated a new libp2p identity (0600)");
            Ok(kp)
        }
        // Already there — the normal path on every restart after the first.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let kp = Keypair::from_protobuf_encoding(&existing)
                .with_context(|| format!("decoding the identity key in {}", path.display()))?;
            warn_if_group_or_world_readable(path);
            Ok(kp)
        }
        Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
    }
}

/// A key written by an older build (or copied in by hand) may be 0644. Say so
/// rather than silently serving with an identity anyone on the box can steal.
fn warn_if_group_or_world_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", meta.permissions().mode() & 0o777),
                    "identity key is readable beyond its owner — chmod 600 it; \
                     anyone who copies it can impersonate this server"
                );
            }
        }
    }
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

/// Where a response's context bytes come from.
///
/// Computed from the chain's schedule when it is available, which is the
/// correct answer for any slot. The observed fallback exists only so an
/// upstream that cannot serve `/config/spec` degrades to the previous
/// behaviour instead of taking the daemon down — it is the newest `updates`
/// chunk's digest, which is right for the current fork and stale across a
/// boundary.
struct Digests {
    schedule: Option<ForkSchedule>,
    observed: [u8; 4],
}

impl Digests {
    fn for_slot(&self, slot: u64) -> [u8; 4] {
        match &self.schedule {
            Some(s) => s.digest_for_slot(slot),
            None => self.observed,
        }
    }

    fn source(&self) -> &'static str {
        if self.schedule.is_some() { "computed" } else { "observed (interim)" }
    }
}

/// Log — loudly — when the digest we compute disagrees with one the upstream
/// actually framed on the wire.
///
/// Deliberately does NOT fall back to the observed value. A disagreement has two
/// causes and they pull in opposite directions:
///
/// - The schedule or the selection is wrong, in which case computed is wrong.
/// - A fork or BPO boundary falls inside the current sync-committee period, in
///   which case the two SHOULD differ: `observed` is the digest of that period's
///   update, whose attested header may predate the boundary, while `computed` is
///   for head. A period spans 256 epochs, so this is entirely possible.
///
/// Falling back would mean serving the stale digest during exactly the fork
/// transition this whole module exists to handle. `computed` is derived from the
/// chain's own configuration and is authoritative for a known slot, so it wins;
/// the mismatch is surfaced for a human instead.
fn report_digest_disagreement(digests: &Digests, observed: [u8; 4], head_slot: u64) {
    if digests.schedule.is_none() {
        return;
    }
    let computed = digests.for_slot(head_slot);
    if computed != observed {
        tracing::error!(
            computed = %hex::encode(computed),
            observed = %hex::encode(observed),
            head_slot,
            "computed fork digest disagrees with the newest digest seen on the wire — \
             expected across a fork/BPO boundary inside the current period, otherwise a \
             schedule bug. Serving the COMPUTED value."
        );
    }
}

/// Build the multiaddr an operator would dial.
///
/// Constructed from `Protocol::from(ip)` rather than formatted with a hardcoded
/// `/ip4/`, which would emit an unparseable `/ip4/2001:db8::1/...` the moment an
/// observation is IPv6 — in the one line someone would copy to test reachability.
/// Not reachable today (the listener is v4-only and roost never dials), which is
/// exactly why it is cheap to make impossible now.
fn dialable(seen: &ExternalAddress, listen_port: u16, peer_id: myotis_net::PeerId) -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::from(seen.ip))
        // The observed port when reporters supplied one (inbound connections
        // see our externally mapped port); otherwise what we asked to listen on.
        .with(Protocol::Tcp(seen.port.unwrap_or(listen_port)))
        .with(Protocol::P2p(peer_id))
}

/// Read the fork and blob schedule from the upstream.
async fn fetch_schedule(client: &NimbusRest, gvr: [u8; 32]) -> Result<ForkSchedule> {
    ForkSchedule::fetch(client, gvr).await
}

/// The digest observed on the wire, from the newest update chunk.
///
/// This is now the FALLBACK, used only when the chain's schedule cannot be read
/// (see [`Digests`]); [`crate::forks::ForkSchedule`] computes the primary value
/// for an object's own slot. It remains useful because it is ground truth for
/// the current fork — the upstream framed it — and it is what the computed value
/// is checked against. It is stale across a fork or BPO boundary, which is
/// exactly why it is no longer the primary.
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

    let observed = match resolve_fork_digest(&client, &store, head_period).await {
        Some(d) => d,
        None => {
            return Err(anyhow!(
                "no fork digest available from upstream or the archive — refusing to serve, \
                 because a wrong digest in `status` makes every peer drop us"
            ))
        }
    };
    let schedule = match fetch_schedule(&client, gvr).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e,
                "could not read the fork/blob schedule — falling back to the observed digest, \
                 which goes stale across a fork boundary; will retry");
            None
        }
    };
    let digests = Digests { schedule, observed };

    report_digest_disagreement(&digests, observed, head_slot);

    if let Err(e) = refresh_live(&client, &store, &digests, head_slot).await {
        tracing::warn!(error = %e, "initial live-object fetch failed; the ticker will retry");
    }

    let status = LocalStatus::new(chain_view(&client, &store, digests.for_slot(head_slot)).await?);
    let key_path = key_path.unwrap_or_else(|| archive_path.with_extension("key"));
    let keypair = load_or_create_key(&key_path)?;

    let listen = format!("/ip4/0.0.0.0/tcp/{port}")
        .parse()
        .map_err(|e| anyhow!("bad listen address: {e}"))?;
    let (net, peer_id, swarm_task) = start_host_with(
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
    println!("  loopback  /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}");
    println!(
        "  public    unknown — needs {EXTERNAL_ADDR_QUORUM} peers to agree on what they see \
         (logged when it settles)"
    );
    println!("  periods   {} ({:?}..={:?})", c.periods, c.lowest_period, c.highest_period);
    println!(
        "  digest    0x{} ({})",
        hex::encode(digests.for_slot(head_slot)),
        digests.source()
    );
    println!("  inbound   cap {MAX_INBOUND}");
    println!("\n  point a wallet at the loopback address above; Ctrl-C to stop.\n");

    let mut digests = digests;
    let mut external: Option<ExternalAddress> = None;
    let mut swarm_task = swarm_task;
    let mut ticks: u32 = 0;
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
                ticks = ticks.wrapping_add(1);
                let head_slot_hint = status.get().head_slot;

                // Re-read the schedule periodically, and keep retrying while we
                // are on the observed fallback. A client upgrade can add a BPO
                // entry, and a roost that cached the schedule at startup would
                // keep stamping the pre-BPO digest indefinitely.
                if digests.schedule.is_none() || ticks.is_multiple_of(SCHEDULE_REFRESH_TICKS) {
                    match fetch_schedule(&client, gvr).await {
                        Ok(s) => {
                            if digests.schedule.as_ref() != Some(&s) {
                                tracing::info!("fork/blob schedule updated");
                                digests.schedule = Some(s);
                                // Bootstraps are encoded once and then kept, so
                                // any cached under the previous schedule carry
                                // stale context bytes. The per-slot objects
                                // refetch every tick and periods carry the
                                // digest their source framed, so only these need
                                // invalidating.
                                let dropped = store.clear_bootstraps();
                                if dropped > 0 {
                                    tracing::info!(dropped,
                                        "dropped cached bootstraps so they are re-stamped");
                                }
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "re-reading the schedule failed"),
                    }
                    if let Some(observed) = store.newest_fork_digest() {
                        // Re-check after every refresh, not only at boot, so a
                        // schedule that STARTS disagreeing with the wire keeps
                        // being reported rather than being noticed once and
                        // never again.
                        report_digest_disagreement(&digests, observed, head_slot_hint);
                    }
                }

                // A failed head poll must not skip the rest of the tick: the
                // live objects are still worth refreshing, and the last known
                // head is good enough to pick a digest with (it only changes at
                // an epoch boundary). Skipping was a behaviour change against
                // the code this replaced, where a failed poll warned and carried
                // on.
                let head_slot = match client.syncing().await {
                    Ok((slot, _)) => slot,
                    Err(e) => {
                        tracing::warn!(error = %e,
                            "polling head slot failed — continuing with the last known head");
                        head_slot_hint
                    }
                };

                // While we are on the fallback, the observed digest must keep
                // tracking the chain. It is assigned at startup, so leaving it
                // alone would freeze `status.fork_digest` at the boot value —
                // and after a fork or BPO boundary every peer would drop us,
                // which is the exact failure this module exists to prevent,
                // reintroduced through the degraded path.
                if digests.schedule.is_none() {
                    if let Some(d) =
                        resolve_fork_digest(&client, &store, period_of_slot(head_slot)).await
                    {
                        if d != digests.observed {
                            tracing::warn!(old = %hex::encode(digests.observed), new = %hex::encode(d),
                                "observed fork digest changed (no schedule available)");
                            digests.observed = d;
                        }
                    }
                }

                // status.fork_digest is not merely context bytes: it is what
                // every peer's relevance check reads on the mandatory handshake.
                // Computing it per tick from the head slot is what carries us
                // across a fork or BPO boundary — held constant, other clients
                // answer Goodbye(IrrelevantNetwork) and myotis wallets filter us
                // out on `accepted_fork_digests`, making us invisible to exactly
                // the clients we exist for.
                let head_digest = digests.for_slot(head_slot);

                if let Err(e) = refresh_live(&client, &store, &digests, head_slot).await {
                    tracing::warn!(error = %e, "refreshing live objects failed");
                }
                if let Err(e) = fill_bootstrap_misses(&client, &store, &digests, head_slot).await {
                    tracing::warn!(error = %e, "filling bootstrap misses failed");
                }
                match chain_view(&client, &store, head_digest).await {
                    Ok(view) => status.set(view),
                    Err(e) => tracing::warn!(error = %e, "refreshing the chain view failed"),
                }
                // Track the address peers say they see us on.
                //
                // The PORT here is our configured listen port, not something
                // observed: Identify reports the remote address of the
                // connection, which for a connection we dialed carries an
                // ephemeral source port. That is correct for the pinned
                // deployment, where the router forwards the same port — but a
                // NAT rewriting the port would make the advertised multiaddr
                // wrong in a way this cannot detect. Worth revisiting when the
                // ENR lands, where the port is published rather than logged.
                //
                // The deployment sits on a residential line whose public IP is
                // not guaranteed stable, so this is not a startup question that
                // gets answered once. It matters most for the ENR that is not
                // published yet: a record carrying a dead IP is WORSE than no
                // record, because wallets discover it, dial, fail, and spend
                // their three strikes to eviction on a node that is actually
                // healthy — taking the tokens that made it worth keeping. Until
                // the ENR exists, this reports the dialable address and makes a
                // change visible rather than silent.
                // A `None` here is not an error and deliberately does nothing:
                // below quorum simply means too few peers have reported yet, and
                // keeping the last known answer beats oscillating to "unknown"
                // every time a peer disconnects.
                if let Some(seen) = net.external_address().await {
                    let advertised = dialable(&seen, port, peer_id);
                    let changed = external.map(|p: ExternalAddress| p.ip != seen.ip);
                    match changed {
                        None => {
                            // First settle. Say plainly whether this is an
                            // address anything outside could dial: a couple of
                            // wallets on the same LAN can reach quorum before a
                            // single internet peer does, and an ENR carrying an
                            // RFC1918 address fails exactly the way publishing
                            // an address is meant to prevent.
                            if seen.routable && !seen.is_contested() {
                                tracing::info!(
                                    ip = %seen.ip, port = ?seen.port,
                                    confirmations = seen.confirmations, reporters = seen.reporters,
                                    multiaddr = %advertised, "external address established"
                                );
                            } else {
                                tracing::warn!(
                                    ip = %seen.ip, routable = seen.routable,
                                    contested = seen.is_contested(),
                                    confirmations = seen.confirmations, reporters = seen.reporters,
                                    multiaddr = %advertised,
                                    "external address seen but NOT usable for publication — \
                                     non-routable and/or contested; treating it as provisional"
                                );
                            }
                            external = Some(seen);
                        }
                        Some(true) => {
                            tracing::warn!(
                                old = %external.map(|p| p.ip.to_string()).unwrap_or_default(),
                                new = %seen.ip, routable = seen.routable,
                                contested = seen.is_contested(),
                                confirmations = seen.confirmations, reporters = seen.reporters,
                                multiaddr = %advertised,
                                "EXTERNAL ADDRESS CHANGED — anything pinning the old one is now \
                                 dialling a dead address; the ENR will need re-publishing with a \
                                 bumped sequence number once it exists"
                            );
                            external = Some(seen);
                        }
                        Some(false) => external = Some(seen),
                    }
                }

                // A new period turns over every ~27 hours; checking each slot is
                // free next to the HTTP calls above.
                let p = period_of_slot(head_slot);
                if !store.has_period(p) {
                    match fill_periods(&client, &store, &mut archive, p, p).await {
                        Ok(n) if n > 0 => tracing::info!(period = p, "archived a new period"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "filling the new period failed"),
                    }
                }
            }
        }
    }
}

/// Refresh the per-slot objects and the checkpoint bootstrap.
///
/// The per-slot objects are stamped with the digest for the HEAD slot at fetch
/// time. roost is a byte cache and does not decode SSZ, so it cannot read the
/// object's own attested-header slot without the light-client type modelling
/// this design exists to avoid — and head is what these objects track, to
/// within a slot or two. The residual error is confined to the handful of slots
/// straddling a fork or BPO boundary, and self-corrects on the next tick because
/// both objects are refetched every slot.
///
/// A BOOTSTRAP is different: it is keyed by an arbitrary root that may be far
/// from head, so its epoch is looked up exactly.
async fn refresh_live(
    client: &NimbusRest,
    store: &LcStore,
    digests: &Digests,
    head_slot: u64,
) -> Result<()> {
    let head_digest = digests.for_slot(head_slot);

    let fin = client.finality_update().await?;
    store.set_finality(head_digest, &fin.bytes);
    let opt = client.optimistic_update().await?;
    store.set_optimistic(head_digest, &opt.bytes);

    let finalized = client.finalized_root().await?;
    if store.bootstrap(&finalized).is_none() {
        let bs = client.bootstrap(&finalized).await?;
        let digest = bootstrap_digest(client, digests, &finalized, head_slot).await;
        store.insert_bootstrap(finalized, digest, &bs.bytes);
    }
    Ok(())
}

/// The digest for a bootstrap, from the slot of the block it anchors to.
///
/// A pinned checkpoint can sit many epochs behind head — potentially across a
/// fork boundary — so stamping it with head's digest would be wrong for exactly
/// the wallets that are furthest behind. Falls back to head only if the header
/// lookup fails, which is strictly better than refusing to serve.
async fn bootstrap_digest(
    client: &NimbusRest,
    digests: &Digests,
    root: &[u8; 32],
    head_slot: u64,
) -> [u8; 4] {
    match client.header_slot(root).await {
        Ok(slot) => digests.for_slot(slot),
        Err(e) => {
            tracing::warn!(root = %hex::encode(&root[..8]), error = %e,
                "could not resolve a bootstrap's slot — stamping it with head's digest");
            digests.for_slot(head_slot)
        }
    }
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
    digests: &Digests,
    head_slot: u64,
) -> Result<usize> {
    let mut filled = 0;
    for root in store.take_bootstrap_misses(MISS_FETCHES_PER_TICK) {
        match client.bootstrap_classified(&root).await {
            Ok(bs) => {
                let digest = bootstrap_digest(client, digests, &root, head_slot).await;
                store.insert_bootstrap(root, digest, &bs.bytes);
                filled += 1;
                tracing::info!(root = %hex::encode(&root[..8]), bytes = bs.bytes.len(),
                    "filled a requested bootstrap");
            }
            // Definitive: the upstream answered and does not have it (typically
            // below its light-client window). The attempted marker set by the
            // drain is correct — asking again would cost a fetch per retry of a
            // wallet that will keep asking forever.
            Err(FetchError::Unavailable(code)) => {
                tracing::info!(root = %hex::encode(&root[..8]), code,
                    "upstream does not have this bootstrap — not retrying");
            }
            // Transient: a timeout, a connection failure, a 5xx. The drain
            // already marked it attempted, so leaving it there would make ONE
            // Nimbus hiccup permanently poison a wallet's pinned checkpoint —
            // every later request refused with ResourceUnavailable and no
            // re-fetch. Put it back at the front of the queue instead.
            Err(FetchError::Transient(e)) => {
                tracing::warn!(root = %hex::encode(&root[..8]), error = %e,
                    "transient failure fetching a bootstrap — requeued");
                store.requeue_bootstrap_miss(root);
            }
        }
    }
    Ok(filled)
}
