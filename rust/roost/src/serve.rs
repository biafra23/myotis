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

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use myotis_net::identity::Keypair;
use myotis_net::multiaddr::Protocol;
use myotis_net::reqresp::{
    is_routable, start_host_with, ExternalAddress, HostConfig, LocalStatus, ReqRespClient,
    EXTERNAL_ADDR_QUORUM,
};
use myotis_net::{Multiaddr, PeerId};
use myotis_net::status::StatusMessage;

use crate::archive::Archive;
use crate::framing::split_updates;
use crate::forks::ForkSchedule;
use crate::rest::{ChainParams, FetchError, NimbusRest};
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

/// How often to dial peers for an external-address reading, in ticks. ~60s.
///
/// Deliberately shorter than the swarm's 120s idle-connection timeout. An
/// observation is dropped when its connection closes, so probing slower than
/// the timeout would make the quorum blink in and out; probing inside it keeps
/// a healthy probe set connected and the reading effectively continuous.
const OBSERVE_TICKS: u32 = 5;

/// Peers dialed per observation round.
///
/// Twice [`EXTERNAL_ADDR_QUORUM`], because the tally dedupes by SOURCE IP and
/// dials fail: three reachable peers on three distinct addresses is the
/// minimum for an answer at all, and asking for exactly the minimum means one
/// unreachable peer costs the whole round.
const OBSERVE_PEERS: usize = EXTERNAL_ADDR_QUORUM * 2;

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
pub(crate) fn load_or_create_key(path: &Path) -> Result<Keypair> {
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
    params: ChainParams,
    fork_digest: [u8; 4],
) -> Result<StatusMessage> {
    let (head_slot, head_root) = client.head_header().await?;
    let (finalized_root, finalized_epoch) = client.finalized_checkpoint().await?;
    let earliest_available_slot = store
        .coverage()
        .lowest_period
        .map(|p| p.saturating_mul(params.slots_per_period()))
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
/// correct answer for any slot.
///
/// The observed fallback covers a NARROWER set than it once did. An upstream
/// that cannot serve `/eth/v1/config/spec` at all now takes the daemon down
/// before this is consulted, because the chain geometry is read from the same
/// document and is required — a chain roost cannot measure is one it must not
/// write archive records for. What still degrades here is a schedule that fails
/// for its own reasons: an unpaired `*_FORK_VERSION`, an unparseable
/// `BLOB_SCHEDULE`, or a spec with no fork versions at all. The fallback value
/// is the newest `updates` chunk's digest — right for the current fork, stale
/// across a boundary.
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
    // REQUIRED, and fetched before the archive is opened: every period number
    // below — including the keys archive records are written under — depends on
    // it, and a wrong value mis-keys durable data rather than failing.
    let (params, initial_schedule) = ForkSchedule::fetch_with_params(&client, gvr).await?;

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
    let head_period = params.period_of_slot(head_slot);
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
    let schedule = match initial_schedule {
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

    let status = LocalStatus::new(chain_view(&client, &store, params, digests.for_slot(head_slot)).await?);
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
    match client.external_ips().await.ok().as_deref().and_then(upstream_external_ip) {
        Some(ip) => println!("  public    /ip4/{ip}/tcp/{port}/p2p/{peer_id} (upstream's discv5 view)"),
        None => println!(
            "  public    unknown — the upstream advertises no routable address yet"
        ),
    }
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
    let mut upstream_ip: Option<IpAddr> = None;
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
                        resolve_fork_digest(&client, &store, params.period_of_slot(head_slot)).await
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
                match chain_view(&client, &store, params, head_digest).await {
                    Ok(view) => status.set(view),
                    Err(e) => tracing::warn!(error = %e, "refreshing the chain view failed"),
                }
                // PRIMARY external-address source: the upstream's own discv5
                // view. roost cannot determine this for itself — it is a pure
                // server, and the peers it dials to try close the connection
                // before Identify completes (measured: 2 establishes, 0
                // identify, in 150s). The upstream shares roost's host and
                // therefore its public IP, and already runs the discovery that
                // answers the question.
                upstream_ip = track_upstream_ip(&client, upstream_ip, port, peer_id).await;

                // FALLBACK ONLY, and deliberately not a second opinion.
                //
                // Dialing peers to harvest Identify observations was measured in
                // this deployment and does not work: over 150s, 10 dials failed
                // and the 2 connections that established were closed by the
                // remote in ~20ms, before Identify completed. Beacon nodes trim
                // a peer that does not gossip — the same behaviour roost exists
                // to escape, met from the other side.
                //
                // Running it anyway while the primary answers would mean ~360
                // dial-and-abandon connections an hour to peers we have no other
                // reason to talk to, to recompute a value already in hand. That
                // is precisely the behaviour that gets a node scored down, and
                // roost of all things should not be doing it.
                //
                // So it runs only when the upstream cannot answer — a Nimbus
                // that has not yet discovered its own address, or is down.
                if upstream_ip.is_none() && ticks.is_multiple_of(OBSERVE_TICKS) {
                    probe_external(&client, &net).await;
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
                let p = params.period_of_slot(head_slot);
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

/// Dial a handful of the upstream's peers so somebody tells us our own address.
///
/// roost is a pure server: it answers connections and never opens one. Identify
/// only reports what a REMOTE observes about us, so with no outbound traffic
/// the external-address tally stays at zero reporters forever — the mechanism
/// was built and then deployed somewhere it could never fire. The fix is to
/// make the outbound traffic deliberately rather than to wait for traffic that
/// by construction never comes.
///
/// Peers come from the upstream's own connected set, which is live and
/// chain-appropriate by construction. The alternative — a second hardcoded
/// bootnode list inside roost — would rot on its own schedule and be wrong on
/// exactly the chains we add later.
///
/// Selection dedupes by IP because the tally does: six peers behind one NAT are
/// one vote, so dialing them would burn the round. Non-routable peers are
/// dropped for the same reason a non-routable answer is unusable — a reading
/// backed by LAN peers is how you publish an RFC1918 address.
///
/// Best effort throughout. A failed probe round is logged at debug and the next
/// tick tries again; it must never disturb serving.
async fn probe_external(client: &NimbusRest, net: &ReqRespClient) {
    let addrs = match client.connected_peer_addrs().await {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(error = %e, "listing upstream peers for address probing failed");
            return;
        }
    };
    let picked = select_probe_peers(&addrs);
    if picked.len() < EXTERNAL_ADDR_QUORUM {
        // Not an error: an upstream still finding its feet legitimately has too
        // few distinct peers. Say so rather than failing silently, because
        // "never reaches quorum" is precisely the bug this exists to fix and it
        // should not be able to come back quietly.
        tracing::debug!(
            candidates = addrs.len(), usable = picked.len(), need = EXTERNAL_ADDR_QUORUM,
            "too few distinct routable upstream peers to establish an address this round"
        );
    }
    net.observe_via(picked).await;
}

/// The upstream's externally-visible IP, from its advertised multiaddrs.
///
/// IPv4 is preferred over IPv6 because the pinned wallet entries and any ENR we
/// publish are v4, and answering with a v6 address roost is not reachable on
/// would be worse than answering nothing.
fn upstream_external_ip(addrs: &[String]) -> Option<IpAddr> {
    let mut v6 = None;
    for raw in addrs {
        let Ok(addr) = raw.parse::<Multiaddr>() else { continue };
        for proto in addr.iter() {
            match proto {
                Protocol::Ip4(a) if is_routable(IpAddr::V4(a)) => return Some(IpAddr::V4(a)),
                Protocol::Ip6(a) if is_routable(IpAddr::V6(a)) && v6.is_none() => {
                    v6 = Some(IpAddr::V6(a));
                }
                _ => {}
            }
        }
    }
    v6
}

/// Read the upstream's view of our public address and report any change.
///
/// Returns the current IP so the caller can carry it to the next tick.
async fn track_upstream_ip(
    client: &NimbusRest,
    last: Option<IpAddr>,
    port: u16,
    peer_id: PeerId,
) -> Option<IpAddr> {
    let addrs = match client.external_ips().await {
        Ok(a) => a,
        Err(e) => {
            // Keep the last known value: a failed poll is not evidence the
            // address changed, and treating it as one would fire the alarm
            // every time the upstream restarts.
            tracing::debug!(error = %e, "reading the upstream's external address failed");
            return last;
        }
    };
    let Some(ip) = upstream_external_ip(&addrs) else {
        tracing::debug!(candidates = addrs.len(),
            "upstream advertises no routable address yet (discv5 may still be settling)");
        return last;
    };
    match last {
        None => {
            tracing::info!(%ip, multiaddr = %format!("/ip4/{ip}/tcp/{port}/p2p/{peer_id}"),
                "external address established (from the upstream's discv5 view)");
        }
        Some(prev) if prev != ip => {
            // The event this whole mechanism exists for. WARN, not info: on a
            // residential line this invalidates the multiaddrs pinned in
            // NetworkConfig and would invalidate a published ENR, and it is
            // silent everywhere else.
            tracing::warn!(old = %prev, new = %ip,
                multiaddr = %format!("/ip4/{ip}/tcp/{port}/p2p/{peer_id}"),
                "EXTERNAL ADDRESS CHANGED — anything pinning the old address can no longer \
                 reach this server; update NetworkConfig (and re-publish the ENR once that exists)");
        }
        Some(_) => {}
    }
    Some(ip)
}

/// Pick up to [`OBSERVE_PEERS`] dialable peers with DISTINCT routable IPs.
///
/// Split out from [`probe_external`] because the filtering is the part with the
/// failure modes and the I/O is not: dedupe-by-IP mirrors the tally's own
/// dedupe (six peers behind one NAT are one vote, so dialing them burns the
/// round), and dropping non-routable peers keeps a LAN-backed reading — the
/// exact way one publishes an RFC1918 address — from ever forming.
fn select_probe_peers(addrs: &[String]) -> Vec<(PeerId, Multiaddr)> {
    let mut seen_ips = HashSet::new();
    let mut picked: Vec<(PeerId, Multiaddr)> = Vec::new();
    for raw in addrs {
        if picked.len() >= OBSERVE_PEERS {
            break;
        }
        let Ok(addr) = raw.parse::<Multiaddr>() else { continue };
        let mut peer = None;
        let mut ip = None;
        for proto in addr.iter() {
            match proto {
                Protocol::P2p(p) => peer = Some(p),
                Protocol::Ip4(a) => ip = Some(IpAddr::V4(a)),
                Protocol::Ip6(a) => ip = Some(IpAddr::V6(a)),
                _ => {}
            }
        }
        let (Some(peer), Some(ip)) = (peer, ip) else { continue };
        if !is_routable(ip) || !seen_ips.insert(ip) {
            continue;
        }
        picked.push((peer, addr));
    }
    picked
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

#[cfg(test)]
mod probe_tests {
    use super::*;

    const P1: &str = "16Uiu2HAmLBZgzF4QKAjjERDh2wWaxtCkLBktEDxKsBmnNhjfcdyR";
    const P2: &str = "16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC";
    const P3: &str = "16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5";

    fn addr(ip: &str, port: u16, peer: &str) -> String {
        format!("/ip4/{ip}/tcp/{port}/p2p/{peer}")
    }

    #[test]
    fn picks_distinct_routable_peers() {
        let addrs = vec![
            addr("45.139.159.102", 9010, P1),
            addr("54.157.213.0", 9000, P2),
            addr("176.229.58.1", 9001, P3),
        ];
        assert_eq!(select_probe_peers(&addrs).len(), 3);
    }

    #[test]
    fn dedupes_by_ip_not_by_peer_id() {
        // Three DIFFERENT peer ids behind one address. The tally counts one
        // vote for them between it, so dialing all three would spend the round
        // and still leave us below quorum — the selection has to mirror that
        // rule, not merely avoid dialing the same peer id twice.
        let addrs = vec![
            addr("45.139.159.102", 9010, P1),
            addr("45.139.159.102", 9011, P2),
            addr("45.139.159.102", 9012, P3),
        ];
        assert_eq!(select_probe_peers(&addrs).len(), 1, "one address is one vote");
    }

    #[test]
    fn drops_non_routable_peers() {
        // A reading backed by LAN peers is how an RFC1918 address gets
        // published. These must never become probe targets.
        let addrs = vec![
            addr("127.0.0.1", 9000, P1),
            addr("192.168.178.74", 9000, P2),
            addr("10.0.0.5", 9000, P3),
        ];
        assert!(select_probe_peers(&addrs).is_empty());
    }

    #[test]
    fn caps_the_round() {
        let addrs: Vec<String> =
            (1..40).map(|i| addr(&format!("45.139.159.{i}"), 9000, P1)).collect();
        assert_eq!(select_probe_peers(&addrs).len(), OBSERVE_PEERS);
    }

    #[test]
    fn skips_entries_without_a_peer_id_or_ip() {
        let addrs = vec![
            "/ip4/45.139.159.102/tcp/9010".to_string(), // no /p2p
            format!("/dns4/example.com/tcp/9000/p2p/{P1}"), // no ip
            "not a multiaddr".to_string(),
            addr("54.157.213.0", 9000, P2),
        ];
        let picked = select_probe_peers(&addrs);
        assert_eq!(picked.len(), 1, "only the one dialable entry survives");
    }

    /// Both invariants are over constants, so they are checked at COMPILE time —
    /// a bad edit fails the build rather than a test run.
    ///
    /// The swarm closes idle connections after 120s and DROPS the observation
    /// with them, so a probe interval above that makes the quorum blink instead
    /// of hold, and IP-change detection silently degrades.
    #[test]
    fn probe_cadence_stays_inside_the_idle_timeout() {
        const {
            assert!(
                REFRESH.as_secs() * (OBSERVE_TICKS as u64) < 120,
                "probe interval must stay under the swarm's 120s idle timeout"
            );
            assert!(
                OBSERVE_PEERS >= EXTERNAL_ADDR_QUORUM,
                "a round must be able to reach quorum"
            );
        }
    }
}

#[cfg(test)]
mod upstream_ip_tests {
    use super::*;

    #[test]
    fn prefers_routable_v4() {
        // Nimbus lists the public v4 first but surrounds it with loopback, ULA,
        // link-local and LAN entries — this is the real shape of the endpoint.
        let addrs: Vec<String> = [
            "/ip4/87.154.209.161/tcp/9107/p2p/16Uiu2HAmSNPCPWg1nysEdBVpTTg3kw7mvEbjrxXW3tQ84td1yax5",
            "/ip6/::1/tcp/9107",
            "/ip6/fd5b:65e6:3b39::eaef:7f15:9f02:c5eb/tcp/9107",
            "/ip4/127.0.0.1/tcp/9107",
            "/ip4/192.168.178.74/tcp/9107",
        ]
        .iter().map(|s| s.to_string()).collect();
        assert_eq!(
            upstream_external_ip(&addrs),
            Some("87.154.209.161".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn v4_wins_over_v6_regardless_of_order() {
        // A published v6 roost is not reachable on the v4 multiaddrs wallets
        // pin, so order in the upstream's list must not decide this.
        let addrs: Vec<String> = [
            "/ip6/2003:fb:ef3a:2300:788a:d7bf:513e:223/tcp/9107",
            "/ip4/87.154.209.161/tcp/9107",
        ]
        .iter().map(|s| s.to_string()).collect();
        assert_eq!(
            upstream_external_ip(&addrs),
            Some("87.154.209.161".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn falls_back_to_v6_when_there_is_no_v4() {
        let addrs = vec![
            "/ip4/127.0.0.1/tcp/9107".to_string(),
            "/ip6/2003:fb:ef3a:2300:788a:d7bf:513e:223/tcp/9107".to_string(),
        ];
        assert_eq!(
            upstream_external_ip(&addrs),
            Some("2003:fb:ef3a:2300:788a:d7bf:513e:223".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn none_when_only_private_addresses() {
        // A node that has not yet discovered itself advertises only local
        // addresses. Answering with one of those is how an RFC1918 address ends
        // up pinned or published, so this must be None rather than a best guess.
        let addrs = vec![
            "/ip4/127.0.0.1/tcp/9107".to_string(),
            "/ip4/192.168.178.74/tcp/9107".to_string(),
            "/ip6/fe80::1/tcp/9107".to_string(),
            "/ip6/fd5b:65e6:3b39::1/tcp/9107".to_string(),
        ];
        assert_eq!(upstream_external_ip(&addrs), None);
    }

    #[test]
    fn ignores_unparseable_entries() {
        let addrs = vec![
            "not a multiaddr".to_string(),
            "/ip4/87.154.209.161/tcp/9107".to_string(),
        ];
        assert_eq!(
            upstream_external_ip(&addrs),
            Some("87.154.209.161".parse::<IpAddr>().unwrap())
        );
    }
}
