//! The EL peer pool (EL-A7b): consume the discv4 candidate stream, dial peers
//! (bounded concurrency), run the eth+snap handshake, and keep a live set of
//! snap-capable [`ManagedPeer`]s for verified reads. Twin of the Java
//! `ChainStack` dial bookkeeping (`attempted` / `backoff` / `blacklist`), minus
//! the cache- and DNS-seeded dials, which arrive with the engine-owned peer
//! cache in EL-A8.
//!
//! Dial outcomes drive the bookkeeping the same way `ChainStack` does:
//! * an **incompatible** peer (wrong network id / genesis) → blacklist its node
//!   id + a long (10 min) address backoff,
//! * any other failure, or a compatible peer that doesn't offer snap/1 → a short
//!   (30 s) address backoff,
//! * a snap-capable peer → spawned as a `ManagedPeer` and held in the pool.
//!
//! A candidate is skipped while its node id is blacklisted, its address is in
//! backoff, or it's already `attempted` (in-flight or connected). Once the pool
//! holds `target_snap_peers`, further candidates are ignored until a peer drops.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::Instant;

use myotis_core::nodekey::NodeKey;

use crate::el::discv4::TableEntry;
use crate::el::eth::session::{EthConfig, EthSession};
use crate::el::peer::{refusing_lag, AnchorSource, Coverage, ManagedPeer};
use crate::el::served::{ServeContext, ServeStats, ServedHeaders};
use crate::el::peercache::{ElPeerCache, SnapQuality};
use crate::el::rlpx::transport::RlpxConnection;

/// Wrong-chain peers: don't retry the address for a long while (Java's
/// `BACKOFF_INCOMPATIBLE_MS`).
const BACKOFF_INCOMPATIBLE: Duration = Duration::from_secs(10 * 60);
/// Transient failures / not-snap peers: a short cool-off (Java's
/// `BACKOFF_TRANSIENT_MS`).
const BACKOFF_TRANSIENT: Duration = Duration::from_secs(30);
/// TooManyPeers (Disconnect 0x04) rejections: the peer is ALIVE, just full —
/// retry patiently enough to halve the dial burn, often enough to keep
/// farming freed slots (Java's `BACKOFF_BUSY_MS`). While the EL hunt is
/// engaged the transient window applies instead (see the dial Err arm).
const BACKOFF_BUSY: Duration = Duration::from_secs(60);

/// True when a dial error is a TooManyPeers rejection. The session's
/// disconnect errors all start with the literal "peer disconnected" and end
/// with `describe_disconnect`'s "reason=N"; the Status-stage variant embeds
/// the peer's client id MID-string, but the prefix is producer-literal and
/// the suffix is always appended last, so neither end can be steered by
/// peer-controlled content. 0x04 says nothing
/// about the peer's CHAIN (full wrong-chain nodes send it too), so busy only
/// selects a backoff class — never a verified/known-good promotion.
///
/// Known divergences from the Java twin (deliberate, scope): (1) Java also
/// flags 0x04 on a READY peer's disconnect; here a serving peer's close
/// reason isn't plumbed through `ManagedPeer`, so its address is simply
/// freed by `prune_closed` with no backoff. (2) The Java hunt log reports a
/// rolling distinct-busy-peer count; the Rust hunt log doesn't (the per-dial
/// `busy` debug field is the Rust-side signal).
fn is_busy_disconnect(e: &str) -> bool {
    e.starts_with("peer disconnected") && e.ends_with("reason=4")
}
/// How often the maintainer checks the pool and tops it back up to target
/// (Java's `maintainSnapPeers` fixed delay).
const MAINTAINER_INTERVAL: Duration = Duration::from_secs(10);

/// EL hunt: the serving pool has been EMPTY this long → emergency mode. Not
/// "below target" — on snap-scarce chains (gnosis) the target is simply
/// unreachable and hunting forever would burn network for nothing; zero
/// serving is the state where verified reads are actually impossible. The
/// hunt bypasses TRANSIENT backoffs for cache-CONFIRMED snap servers (they
/// served chain-verified snap data — wrong-chain is impossible, so an eager
/// re-dial is safe). Blacklist and incompatible entries stay respected.
const EL_HUNT_STALL: Duration = Duration::from_secs(60);

/// How recent an online signal (discv4 delivery / completed session) still
/// gates connect-failure counting. Short on purpose: a device that drops
/// offline must stop counting before it can demote healthy cached peers
/// (Java `ChainStack.ONLINE_SIGNAL_MAX_AGE_MS`).
const ONLINE_SIGNAL_MAX_AGE: Duration = Duration::from_secs(2 * 60);

/// Which pinned boot enodes to (re-)dial this maintainer tick — pure, so the
/// policy is unit-tested rather than buried in the loop.
///
/// - BELOW target: all of them. The incident this fixes (#311): a pin that had
///   been serving dropped, the pool refilled to `target` with discovered full
///   nodes that had pruned the finalized-root state, and the pin was never
///   re-dialed — account proofs failed until a restart. A dropped pin must
///   reconnect even while the pool is "full" of peers that cannot serve.
/// - AT/ABOVE target: only pins ALREADY PROVEN to serve snap data (cache
///   `Confirmed`). Otherwise a healthy pool would perpetually re-handshake a
///   pin that has never served — background radio + flash churn every backoff
///   window for the process lifetime, which scales with the pin count (Gnosis
///   ships 16 static EL enodes) and hits the Android/iOS paths CLAUDE.md keeps
///   first-class. `try_dial` dedups a still-connected pin, so a proven pin that
///   is up costs nothing; only a proven pin that has DROPPED is re-dialed.
fn pins_to_dial(
    live: usize,
    target: usize,
    pins: &[(SocketAddr, [u8; 64])],
    confirmed: &std::collections::HashSet<SocketAddr>,
) -> Vec<(SocketAddr, [u8; 64])> {
    pins.iter()
        .filter(|(addr, _)| live < target || confirmed.contains(addr))
        .copied()
        .collect()
}

/// Pure trigger: pool empty AND it has been empty past the stall window.
fn el_hunt_due(live: usize, zero_since: Option<Instant>, now: Instant) -> bool {
    live == 0
        && zero_since.is_some_and(|t| now.saturating_duration_since(t) >= EL_HUNT_STALL)
}

/// Pool tunables.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Stop dialing once the pool holds this many snap-capable peers.
    pub target_snap_peers: usize,
    /// Cap on concurrent in-flight dials.
    pub max_concurrent_dials: usize,
    /// Cap on the `attempted` set (matches Java's 2000 guard) — a backstop
    /// against unbounded growth if peers never resolve.
    pub max_attempted: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        // A wallet needs only a handful of snap servers; keep the fan-out modest.
        PoolConfig { target_snap_peers: 8, max_concurrent_dials: 16, max_attempted: 2000 }
    }
}

/// Bench window after a verified-read failure: the peer is moved BEHIND
/// unbenched peers in the read ladder (never excluded outright — the sole
/// server must stay reachable) so the next read tries somebody else first.
/// Java's transient 30 s bench twin (`benchUnlessLastServing`); before this
/// the live pool had NO reaction to read failures at all, and 8 lagging
/// cached peers held every slot through days of failing reads (2026-09-02).
const READ_FAIL_BENCH: Duration = Duration::from_secs(30);

/// Consecutive verified-read failures that EVICT a live peer, freeing its
/// slot for the maintainer to refill with a fresh candidate. Reset on any
/// successful serve. A repeated outpace counts as a failure too (see
/// [`OUTPACES_BEFORE_STRIKE`]). Never applied to the sole remaining peer — a failure
/// against the only server is ambiguous (it may be our own stale ask), the
/// same rationale as record_quality's persisted-verdict guard.
///
/// Kept EQUAL to peercache's snap FAILURE_THRESHOLD on purpose: when other
/// peers exist the live strike here and the persisted cache strike increment
/// in lockstep, so an evicted laggard flips to `Denied` in the same beat and
/// the hunt's confirmed-peer backoff bypass won't instantly re-dial it. Drift
/// between the two constants would silently reopen that re-admit churn.
///
/// Since #465 the lockstep holds for WITNESSED failures only (see
/// [`QualityOutcome`]): a failure no other peer contradicted still counts
/// here, so the live pool rotates, but persists nothing — the peer it evicts
/// is not flipped to `Denied`, and a hunt may re-dial it after one transient
/// window. That re-dial costs one handshake and, while the hunt stays
/// engaged, the few failed reads it takes to evict it again — the price of
/// never poisoning the cache with a verdict nobody witnessed (14 of 27
/// entries in #465's cold-start cache were such verdicts).
const READ_FAILS_EVICT: u32 = 3;

/// Enforce the equality the doc above calls load-bearing at COMPILE time, not
/// just in prose: tuning peercache's threshold without moving this one now
/// fails the build instead of silently reopening the re-admit churn.
const _: () = assert!(READ_FAILS_EVICT == crate::el::peercache::FAILURE_THRESHOLD);

/// Times a peer may be OUTPACED (see `PeerPool::record_snap_outpaced`) since it
/// last served before each further outpace also counts as a verified-read
/// failure. A hedged read drops a silent attempt once another peer answers, so
/// without this a dead connection that stays open (a request timeout does not
/// close it, and nothing pings an idle one) would never be struck: it would sit
/// out 30 s benches forever, costing a hedge delay after each, and never free
/// its slot. The first outpace stays free so one stall is not held against a
/// peer; with [`READ_FAILS_EVICT`] a peer that never serves is evicted on its
/// fourth consecutive outpace.
const OUTPACES_BEFORE_STRIKE: u32 = 1;

/// Live verdict after an outpace — pure. Returns `(new_streak, strike)`, where
/// `strike` means the outpace also counts as a verified-read failure.
fn outpace_verdict(streak_before: u32) -> (u32, bool) {
    let streak = streak_before.saturating_add(1);
    (streak, streak > OUTPACES_BEFORE_STRIKE)
}

/// A live pooled peer plus the address it was dialed at (so pruning a dropped
/// peer can free its address for a future re-dial).
struct PooledPeer {
    addr: SocketAddr,
    peer: Arc<ManagedPeer>,
    /// Sidelined until this instant after a verified-read failure (see
    /// [`READ_FAIL_BENCH`]); `None`/past = in the front of the read ladder.
    benched_until: Option<Instant>,
    /// Consecutive verified-read failures (see [`READ_FAILS_EVICT`]).
    read_fails: u32,
    /// Outpaces since the last successful serve (see [`OUTPACES_BEFORE_STRIKE`]).
    outpaced: u32,
    /// Verified reads this peer has served this session.
    served: u32,
    /// The peer was cache-Confirmed (`snapok`) when dialed: a prior from an
    /// earlier run, kept apart from `served` so a warm-start peer is not
    /// ranked as unproven before its first read of this session.
    cache_confirmed: bool,
    /// When `probe_unknown_heads` last asked this peer for the anchored head;
    /// `None` = never.
    last_probe: Option<Instant>,
    /// Consecutive head probes this peer ANSWERED without the anchored head
    /// (see `probe_unknown_heads`); reset by any serve.
    probe_misses: u32,
}

impl PooledPeer {
    fn is_benched(&self, now: Instant) -> bool {
        self.benched_until.is_some_and(|t| t > now)
    }

    /// Neither served this session nor cache-Confirmed when dialed.
    fn unproven(&self) -> bool {
        self.served == 0 && !self.cache_confirmed
    }
}

/// One peer's read-ladder sort key. FIELD ORDER IS THE POLICY — the derived
/// `Ord` sorts lexicographically:
///  1. `behind`: a peer whose fresh word says it lacks the anchored head goes
///     last, whatever else is true of it — its "0 headers" is the answer it
///     predicted (#465), and asking it first is what made a cold pool fail
///     every read;
///  2. `benched`: a peer that just failed a read trails those that did not —
///     a preference, never a veto, so the sole server stays reachable;
///  3. `coverage`: its own word or a served proof put it at our anchor
///     (Covers), near it (Near), or said nothing usable (Unknown) —
///     `peer::Coverage`'s variant order;
///  4. `unproven`: a peer that has neither served this session nor was
///     cache-Confirmed when dialed trails one that has — the persisted cache
///     now pays off on the READ path, not just the dial path (before #465 a
///     warm start dialed its proven servers first, which made them the OLDEST
///     connections and put them at the bottom of a newest-first ladder).
///
/// Ties keep the pool's newest-connection-first order — the pre-#465 ladder —
/// because `ladder_order` sorts stably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LadderKey {
    behind: bool,
    benched: bool,
    coverage: Coverage,
    unproven: bool,
}

impl LadderKey {
    fn new(benched: bool, coverage: Coverage, unproven: bool) -> LadderKey {
        LadderKey { behind: coverage == Coverage::Behind, benched, coverage, unproven }
    }
}

/// Read-ladder order over the pool's per-peer keys (newest connection first):
/// the positions STABLY sorted by [`LadderKey`]. Pure — the ordering IS the
/// rotation, so it is pinned by tests.
fn ladder_order(keys: &[LadderKey]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|&i| keys[i]);
    order
}

/// Live verdict after a verified-read failure — pure. Returns
/// `(new_fail_count, evict)`: evict once the count reaches
/// [`READ_FAILS_EVICT`], except for the sole remaining peer.
///
/// A sole peer's failures are NOT banked (`read_fails` stays 0): a failure
/// against the only server is ambiguous — likely our own stale ask, the same
/// reason the persisted-verdict guard shields it — so banking strikes there
/// would evict it on its very next failure the instant the pool grows, before
/// it has actually failed as a NON-sole peer. It is still benched by the
/// caller (30 s) so a second peer, once found, leads the ladder.
fn read_failure_verdict(fails_before: u32, pool_len: usize) -> (u32, bool) {
    if pool_len <= 1 {
        return (0, false);
    }
    let fails = fails_before.saturating_add(1);
    (fails, fails >= READ_FAILS_EVICT)
}

/// Cool-off for a peer refused or evicted as lagging (see `peer::refusing_lag`
/// and `evict_lagging_peers`). A syncing node needs hours, but ten minutes
/// re-checks often enough to re-admit one that caught up. Deliberately LONGER
/// than `BACKOFF_TRANSIENT`: the EL hunt's backoff bypass (`maintainer_loop`)
/// clears only transient-length entries, so a hunt never re-dials a known
/// laggard — it cannot serve, and the dial budget is better spent on discovery.
const BACKOFF_LAGGING: Duration = Duration::from_secs(10 * 60);

/// Pure: may a verified-read FAILURE be persisted as a snap verdict against
/// the peer? Generalises the sole-peer shield in `record_quality`: a failure
/// nobody contradicted is evidence about OUR ask (a head no peer has yet, a
/// root every peer pruned), not about the peer. `witnessed` = another peer
/// served the same read; `other_live_peer` = the pool holds a peer at a
/// different address. Both must hold. #465 watched a cold pool's whole-batch
/// tip-lag failures flip 14 of 27 cache entries to `snapbad`, so the next
/// cold start dialed its proven servers last.
fn persist_verdict(witnessed: bool, other_live_peer: bool) -> bool {
    witnessed && other_live_peer
}

/// Pure: does a pooled peer count as SERVING — on the evidence, able to answer
/// a read at the anchored head — for the count the hosts' readiness is meant
/// to gate on (`snapServingPeers`; the status plumbing is a follow-up)? Its
/// own word or a served proof put it at or near our anchor (see
/// `peer::Coverage`), and it is not read-benched. Evidence, not a guarantee: a
/// `Near` peer, or one whose word is minutes old, can still miss a read at the
/// very tip. A pool of eth/68 peers therefore serves once one of them proves
/// itself (`probe_unknown_heads`), not the moment it connects — which is the
/// point: #465's hosts gated on a count that was true while every read failed.
fn is_serving(benched: bool, cov: Coverage) -> bool {
    !benched && matches!(cov, Coverage::Covers | Coverage::Near)
}

/// Pure: does a pooled peer count toward the EL hunt's "somebody could
/// serve" tally? Looser than `is_serving`: `Unknown` counts (no evidence is
/// not evidence of absence, and before the anchor lands every peer is
/// Unknown — the hunt must not engage on a pool that is merely waiting for
/// the beacon side). Only a read-benched peer or one whose fresh word says it
/// lacks the head is excluded — a pool of nothing but those is a serving
/// outage, exactly like an empty one.
fn counts_for_hunt(benched: bool, cov: Coverage) -> bool {
    !benched && cov != Coverage::Behind
}

/// A verified-read outcome against one peer, as the pool's quality accounting
/// records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualityOutcome {
    /// Usable, verified data came back.
    Served,
    /// The read failed and another peer served the same read: WITNESSED —
    /// evidence about this peer, banked live and persisted (under the
    /// sole-peer shield).
    Failed,
    /// The read failed and no peer served it: benched and counted toward
    /// eviction, so the live pool still rotates, but persisted NOWHERE (see
    /// `persist_verdict`).
    FailedUnwitnessed,
}

impl QualityOutcome {
    fn failed(witnessed: bool) -> QualityOutcome {
        if witnessed {
            QualityOutcome::Failed
        } else {
            QualityOutcome::FailedUnwitnessed
        }
    }
}

struct PoolInner {
    tasks: super::tasks::Tasks,
    key: Arc<NodeKey>,
    local_pubkey: [u8; 64],
    cfg: Arc<EthConfig>,
    pool_cfg: PoolConfig,
    peers: Mutex<Vec<PooledPeer>>,
    /// Addresses dialed and not yet failed — in-flight OR connected. Prevents
    /// re-dialing a live peer or racing two dials to the same address.
    attempted: Mutex<HashSet<SocketAddr>>,
    /// Address → earliest instant it may be dialed again.
    backoff: Mutex<HashMap<SocketAddr, Instant>>,
    /// Node ids of wrong-chain peers, never dialed again this run.
    blacklist: Mutex<HashSet<[u8; 64]>>,
    /// Proven snap-capable peers, persisted for warm-start on the next run.
    cache: Mutex<ElPeerCache>,
    /// The network's pinned EL peers, `(addr, 64-byte pubkey)` — Java
    /// `NetworkConfig.elBootEnodes()`. Dialed directly (warm start; and on a
    /// maintainer tick when below target, or when a PROVEN snap server has
    /// dropped even with a full pool — see `pins_to_dial`), NOT seeded into the
    /// cache: see the warm-start comment in `dialer_loop`.
    boot_enodes: Vec<(SocketAddr, [u8; 64])>,
    /// Recent headers we can serve to peers + the eth/69 advertised range source.
    served: Arc<ServedHeaders>,
    /// The beacon-anchored head (number, hash) to backfill toward — the batch
    /// anchor — and the yardstick every peer's head observation is stamped
    /// with (shared with each pooled peer's read loop, see `peer::KnownHead`).
    /// None (or a None result) → no backfill, no judgement (fixtures;
    /// pre-sync). A closure, not the anchor itself — the pool stays
    /// anchor-free.
    head_source: Option<AnchorSource>,
    /// Round-robin cursor for backfill peer selection.
    backfill_rr: std::sync::atomic::AtomicUsize,
    /// True while a spawned backfill fetch is in flight: the 10 s tick is
    /// shorter than the 15 s request timeout, so without this a slow peer's
    /// batch would be re-requested from the next peer while still pending
    /// (harmless but wasteful — Java avoids it by construction, 15 s tick
    /// > 10 s timeout).
    backfill_inflight: std::sync::atomic::AtomicBool,
    /// Last (earliest, latest, latestHash) broadcast via BlockRangeUpdate and
    /// WHEN, to suppress duplicate sends and rate-limit changed ones: the spec
    /// recommends an update "about once every two minutes", and the backfill
    /// makes the triple track the head, changing on nearly every tick.
    /// The hash is part of the key so a same-height reorg re-broadcasts (when due).
    last_broadcast_range: Mutex<Option<((u64, u64, [u8; 32]), Instant)>>,
    /// Inbound peer-demand counters for the status page.
    serve_stats: Arc<ServeStats>,
    /// EL hunt engaged (serving pool empty past the stall window) — drives the
    /// hosts' status banner and the maintainer's backoff bypass.
    hunting: AtomicBool,
    /// Last proof we're online: a discv4 candidate arrived or a dial completed
    /// a session. Gates connect-failure counting (with the live-peer check) so
    /// a warm start whose cached peers are ALL dead can still clean them up,
    /// while an offline device (no discovery, no sessions) counts nothing.
    online_signal: Mutex<Option<Instant>>,
    /// The reader's sent-tx watch, handed to every spawned peer's read loop so
    /// gossip sightings of our own broadcasts register (None for pools whose
    /// host never sends).
    tx_watch: Option<crate::el::sent_tx::SharedSentTxWatch>,
    /// Probe requests toward discovery: when a snap peer connects, its address
    /// is nudged into the discv4 walk so its neighbourhood gets explored (a
    /// cache-/warm-start peer may never enter the table on its own). Best-effort
    /// `try_send`; `None` for pools without discovery (tests).
    probe: Option<mpsc::Sender<SocketAddr>>,
}

impl PoolInner {
    /// Bench an outpaced peer, and strike a repeat — see `record_snap_outpaced`.
    async fn record_outpaced(&self, addr: SocketAddr) {
        self.prune_closed().await;
        let strike = {
            let mut peers = self.peers.lock().await;
            let Some(p) = peers.iter_mut().find(|p| p.addr == addr) else {
                return;
            };
            let (streak, strike) = outpace_verdict(p.outpaced);
            p.outpaced = streak;
            p.benched_until = Some(Instant::now() + READ_FAIL_BENCH);
            strike
        };
        // Outside the lock: record_quality takes it again (tokio's Mutex is
        // not reentrant). It benches too, banks the strike under the sole-peer
        // shield, may evict, and feeds the persisted verdict, exactly as a
        // failed read does.
        if strike {
            // Witnessed by construction: outpaced means another peer answered.
            self.record_quality(addr, QualityOutcome::Failed).await;
        }
    }

    /// The single quality-recording path (dirty-gated flush inside) — shared by
    /// the pool's public sinks and [`SnapQualitySink`] so behavior can't drift.
    async fn record_quality(&self, addr: SocketAddr, outcome: QualityOutcome) {
        let served = outcome == QualityOutcome::Served;
        // LIVE-POOL accounting first (this is the rotation the 2026-09-02
        // stale-pool wedge was missing — 8 lagging cached peers held every
        // slot because a failed read cost them nothing here): a success
        // clears the bench and the strike count; a failure benches the peer
        // (the read ladder tries others first, see snap_peers) and, at
        // READ_FAILS_EVICT consecutive failures, evicts it so the maintainer
        // refills the slot with a fresh candidate. The evicted address gets
        // the transient backoff so the dialer doesn't immediately re-dial
        // the same laggard; its Arc drop closes the session once the ladder
        // lets go of its clone.
        // Prune first so `len` counts only LIVE peers: a corpse left in the vec
        // would let the sole-peer shield be pierced (evicting the one real
        // server while a dead entry made len look like 2). prune_closed locks
        // `peers` on its own, so it must run BEFORE we take the lock below.
        self.prune_closed().await;
        {
            let mut peers = self.peers.lock().await;
            let len = peers.len();
            if let Some(p) = peers.iter_mut().find(|p| p.addr == addr) {
                if served {
                    p.benched_until = None;
                    p.read_fails = 0;
                    p.outpaced = 0;
                    p.probe_misses = 0;
                    p.served = p.served.saturating_add(1);
                } else {
                    let (fails, evict) = read_failure_verdict(p.read_fails, len);
                    if evict {
                        tracing::info!(%addr, fails,
                            "evicting snap peer after repeated verified-read failures — \
                             freeing the slot for a fresh candidate");
                        peers.retain(|p| p.addr != addr);
                        // NOTE the order across the next awaits: the address stays
                        // claimed in `attempted` until AFTER its backoff is
                        // recorded, so a concurrent try_dial (which checks backoff
                        // first, then the attempted claim) can never see this
                        // laggard as both un-backed-off AND un-claimed and re-dial
                        // it in the gap.
                        drop(peers);
                        self.record_backoff(addr, BACKOFF_TRANSIENT, Instant::now()).await;
                        self.attempted.lock().await.remove(&addr);
                        // fall through to the persisted verdict below
                        return self.persist_quality(addr, outcome).await;
                    }
                    // Not evicting: bank the strike and bench the peer so the
                    // read ladder tries others first. (On the evict branch the
                    // entry is retained away, so writing these would be dead.)
                    p.read_fails = fails;
                    p.benched_until = Some(Instant::now() + READ_FAIL_BENCH);
                }
            }
        }
        self.persist_quality(addr, outcome).await;
    }

    /// The persisted half of [`record_quality`](Self::record_quality). A serve
    /// always confirms. A failure reaches the cache only under
    /// [`persist_verdict`]: witnessed by another peer serving the same read,
    /// AND with another peer live. The second half is the older sole-peer
    /// shield — never demote the LAST live snap peer: an empty/failed fetch
    /// against the sole server usually means WE asked for a root outside its
    /// snapshot window (stale local head), not that the peer is bad, and three
    /// such strikes would persist a snapbad verdict against the one peer still
    /// serving us. Twin of the Java benchUnlessLastServing scan (`h != failed`):
    /// it keys on whether any OTHER peer is live, not on pool size — a lone
    /// pooled peer at a DIFFERENT address means the failing one isn't our last
    /// resort. (Deliberate asymmetry with Java: this skips a PERSISTED verdict,
    /// Java skips a transient 30 s bench — the transient bench exists here too,
    /// in the live half.) The first half is #465's generalisation of it to a
    /// whole batch nobody served.
    async fn persist_quality(&self, addr: SocketAddr, outcome: QualityOutcome) {
        let served = match outcome {
            QualityOutcome::Served => true,
            // Nobody served: nothing to persist, no lock to take.
            QualityOutcome::FailedUnwitnessed => return,
            QualityOutcome::Failed => {
                let other_live = self.peers.lock().await.iter().any(|p| p.addr != addr);
                if !persist_verdict(true, other_live) {
                    tracing::debug!(%addr, "skipping the persisted snap-failure verdict — no other peer live");
                    return;
                }
                false
            }
        };
        let mut cache = self.cache.lock().await;
        if served {
            cache.record_snap_served(addr);
        } else {
            cache.record_snap_failure(addr);
        }
        cache.flush();
    }

    /// Stamp the online signal (see `online_signal` field docs).
    async fn note_online(&self) {
        *self.online_signal.lock().await = Some(Instant::now());
    }

    /// True if we have live proof of connectivity: a pooled peer, or an online
    /// signal within [`ONLINE_SIGNAL_MAX_AGE`].
    async fn likely_online(&self) -> bool {
        if !self.peers.lock().await.is_empty() {
            return true;
        }
        self.online_signal
            .lock()
            .await
            .is_some_and(|t| t.elapsed() < ONLINE_SIGNAL_MAX_AGE)
    }

    /// Drop closed peers, freeing their addresses for a future re-dial. Returns
    /// the number of remaining live peers (so callers avoid a second `peers`
    /// lock just to read the count).
    async fn prune_closed(&self) -> usize {
        let mut peers = self.peers.lock().await;
        let mut freed = Vec::new();
        peers.retain(|p| {
            if p.peer.is_closed() {
                freed.push(p.addr);
                false
            } else {
                true
            }
        });
        if !freed.is_empty() {
            let mut attempted = self.attempted.lock().await;
            for addr in freed {
                attempted.remove(&addr);
            }
        }
        peers.len()
    }

    /// The beacon-anchored head `(number, hash)`, or `None` before the anchor
    /// has one (fixtures; pre-sync). A sync closure over the anchor's std
    /// mutex: call it BEFORE taking any pool lock, never inside.
    fn anchored_head(&self) -> Option<(u64, [u8; 32])> {
        self.head_source.as_ref().and_then(|f| f()).filter(|&(n, _)| n > 0)
    }

    fn anchored_head_number(&self) -> Option<u64> {
        self.anchored_head().map(|(n, _)| n)
    }

    /// Live peers satisfying `pred(benched, coverage)` — `is_serving` for the
    /// hosts' count, `counts_for_hunt` for the EL hunt.
    async fn count_where(&self, pred: fn(bool, Coverage) -> bool) -> usize {
        let now = Instant::now();
        self.peers.lock().await.iter().filter(|p| pred(p.is_benched(now), p.peer.coverage())).count()
    }

    /// Evict a pooled peer as LAGGING — its own word, or its answers to the
    /// head probe, put it behind the anchored head — with the long backoff and
    /// no cache verdict (lagging is not a snap-quality judgement). Never the
    /// sole peer, the asymmetry `read_failure_verdict` keeps: a Behind sole
    /// peer serves nothing now, but evicting it with the long backoff
    /// guarantees nothing serves for ten minutes (a lagging pin, the only peer
    /// on sepolia, would be out of the hunt's reach), while a pooled one serves
    /// the moment its next word says it caught up — it still ranks last and
    /// does not count for the hunt. The address stays claimed until the
    /// backoff is recorded, the ordering the read-failure eviction in
    /// `record_quality` documents, so a concurrent dial cannot re-dial it in
    /// the gap.
    async fn evict_lagging(&self, addr: SocketAddr, why: &str) {
        let was_pooled = {
            let mut peers = self.peers.lock().await;
            if peers.len() <= 1 {
                return;
            }
            let before = peers.len();
            peers.retain(|p| p.addr != addr);
            peers.len() != before
        };
        if !was_pooled {
            return;
        }
        tracing::info!(%addr, "evicting snap peer as lagging: {why}");
        self.record_backoff(addr, BACKOFF_LAGGING, Instant::now()).await;
        self.attempted.lock().await.remove(&addr);
    }

    /// A head probe the peer ANSWERED without the anchored head (see
    /// `probe_unknown_heads`): count it, and at [`PROBE_MISSES_EVICT`] in a
    /// row evict the peer as lagging.
    async fn note_probe_miss(&self, addr: SocketAddr) {
        let misses = {
            let mut peers = self.peers.lock().await;
            let Some(p) = peers.iter_mut().find(|p| p.addr == addr) else { return };
            p.probe_misses = p.probe_misses.saturating_add(1);
            p.probe_misses
        };
        if misses >= PROBE_MISSES_EVICT {
            self.evict_lagging(addr, &format!("it answered {misses} head probes without the anchored head"))
                .await;
        }
    }

    /// Record an address backoff for `window` (one of the BACKOFF_* consts).
    async fn record_backoff(&self, addr: SocketAddr, window: Duration, now: Instant) {
        let mut backoff = self.backoff.lock().await;
        // Entries are normally dropped when their address resurfaces as a
        // candidate, but an address that never comes back would linger forever.
        // Sweep expired entries when the map grows large so it stays bounded.
        if backoff.len() >= self.pool_cfg.max_attempted {
            backoff.retain(|_, expiry| *expiry > now);
        }
        backoff.insert(addr, now + window);
    }

    /// Dial one candidate through the full eth+snap handshake, updating the
    /// bookkeeping by outcome. `addr` is already in `attempted`.
    async fn dial_one(self: &Arc<PoolInner>, addr: SocketAddr, pubkey: [u8; 64]) {
        let conn = match RlpxConnection::dial(Arc::clone(&self.key), addr, pubkey).await {
            Ok(conn) => conn,
            Err(e) => {
                // Transport-level failure (refused/timeout/ECIES) — the peer is
                // GONE, not incompatible. Streaks of these demote and eventually
                // evict it from the warm-start cache. (Deliberately broader than
                // the Java twin, which only sees pre-handshake TCP failures: an
                // ECIES failure against a cached entry means its stored node key
                // is stale — the entry can never handshake again and deserves
                // the same eviction path.) Gated on an online signal so an
                // offline device can't count a failure against every cached
                // peer per cycle and decimate its own cache.
                tracing::debug!(%addr, error = %e, "el dial: transport failed");
                if self.likely_online().await {
                    let mut cache = self.cache.lock().await;
                    cache.record_connect_failure(addr);
                    cache.flush();
                }
                self.record_backoff(addr, BACKOFF_TRANSIENT, Instant::now()).await;
                self.attempted.lock().await.remove(&addr);
                return;
            }
        };
        // TCP + ECIES succeeded — proof of connectivity regardless of how the
        // eth handshake goes.
        self.note_online().await;
        // eth/69 Status advertises only the window's held range (None → the
        // honest genesis-only [0, 0]); see ServedHeaders::advertise.
        let result =
            EthSession::handshake(conn, &self.local_pubkey, &self.cfg, self.served.advertise())
                .await;

        let now = Instant::now();
        // Any COMPATIBLE completed session (snap or not) proves the peer is on
        // our network — nudge discovery toward its neighbourhood (UDP port
        // guessed = TCP port, the devp2p default; a wrong guess just means no
        // pong). The service dedups per endpoint. Same semantics as the Java
        // twin, which probes on every eth-READY peer: a fork-verified plain-eth
        // peer's neighbours may well serve snap.
        if result.is_ok() {
            if let Some(probe) = &self.probe {
                let _ = probe.try_send(addr);
            }
        }
        match result {
            Ok(session) if session.snap => {
                // Admission by announced head (#465): a peer whose fresh Status
                // puts its head far below our anchored one is syncing or
                // stalled — it would answer "0 headers" to every tip read and
                // hold a slot for hours. Not a verdict on its snap quality (no
                // cache strike): a lagging backoff, and discovery moves on. The
                // address stays claimed until the backoff is recorded — the
                // ordering the eviction path in record_quality documents.
                let anchored = self.anchored_head_number();
                if let Some(lag) = refusing_lag(session.peer_status.latest_block, anchored) {
                    tracing::info!(%addr, lag, eth = session.eth_version,
                        "el dial: peer announces a head far behind the anchored one — not pooling");
                    {
                        // Reachable — clear any connect-failure streak, as the
                        // no-snap arm does. Not `add`ed: it proved nothing
                        // worth dialing first next run.
                        let mut cache = self.cache.lock().await;
                        cache.record_connect_success(addr);
                        cache.flush();
                    }
                    self.record_backoff(addr, BACKOFF_LAGGING, now).await;
                    self.attempted.lock().await.remove(&addr);
                    return;
                }
                // INFO: the operator-visible signal that the EL found a usable
                // snap peer (bounded to ~target occurrences per run). Per-peer
                // failures/non-snap stay at debug to avoid the discv4 cross-chain
                // noise (most discovered peers are other networks or full).
                tracing::info!(%addr, eth = session.eth_version, "el dial: snap peer connected");
                // The cache's verdict on this peer from earlier runs, read in
                // its own statement BEFORE the peers lock (never two pool locks
                // at once — the maintainer takes them in the other order).
                let cache_confirmed =
                    self.cache.lock().await.quality_of(addr) == Some(SnapQuality::Confirmed);
                let peer = Arc::new(ManagedPeer::spawn_serving(
                    session,
                    addr,
                    ServeContext {
                        window: Arc::clone(&self.served),
                        stats: Arc::clone(&self.serve_stats),
                    },
                    self.tx_watch.clone(),
                    self.head_source.clone(),
                ));
                // Keep `addr` in `attempted` while connected — dropped by
                // prune_closed when the peer later closes.
                self.peers.lock().await.push(PooledPeer {
                    addr,
                    peer,
                    benched_until: None,
                    read_fails: 0,
                    outpaced: 0,
                    served: 0,
                    cache_confirmed,
                    last_probe: None,
                    probe_misses: 0,
                });
                // Persist this proven snap-capable peer for warm-start next run.
                // `add` only marks the cache dirty for a genuinely new peer, so
                // `flush` no-ops on a re-connect.
                let mut cache = self.cache.lock().await;
                cache.add(addr, &pubkey, true);
                cache.flush();
            }
            Ok(session) => {
                // Compatible but no snap/1 — useless for verified reads. Cool the
                // address off and free it from `attempted`. Still proof the
                // address is alive: clear any connect-failure streak.
                tracing::debug!(%addr, eth = session.eth_version, "el dial: connected but no snap/1");
                {
                    // Flush so a cleared persisted streak lands on disk now —
                    // this path may be the only cache event the peer ever gets.
                    let mut cache = self.cache.lock().await;
                    cache.record_connect_success(addr);
                    cache.flush();
                }
                self.record_backoff(addr, BACKOFF_TRANSIENT, now).await;
                self.attempted.lock().await.remove(&addr);
            }
            Err(e) => {
                // Only the network-id/genesis mismatch and Status-decode errors
                // start with these prefixes (see EthSession::handshake). An
                // undecodable Status is a foreign-chain client with a divergent
                // Status shape (e.g. Polygon's bor keeps the TD field eth/69
                // removed) — treat it as incompatible so it gets the long
                // backoff + blacklist instead of a re-dial every transient
                // window. Match the PREFIX, not a substring: a peer's client id
                // is echoed into other error strings, so `contains` could be
                // steered by a hostile peer.
                let incompatible =
                    e.starts_with("incompatible peer") || e.starts_with("peer Status decode");
                let busy = is_busy_disconnect(&e);
                tracing::debug!(%addr, incompatible, busy, error = %e, "el dial: failed");
                if incompatible {
                    self.blacklist.lock().await.insert(pubkey);
                }
                let window = if incompatible {
                    BACKOFF_INCOMPATIBLE
                } else if busy {
                    // While the EL hunt is engaged, busy peers retry on the
                    // transient cadence: with the serving pool empty they are
                    // the only realistic source of a freed slot, and slots
                    // are won by fast retries (Java busyBackoffMs twin).
                    if self.hunting.load(Ordering::Relaxed) {
                        BACKOFF_TRANSIENT
                    } else {
                        BACKOFF_BUSY
                    }
                } else {
                    BACKOFF_TRANSIENT
                };
                self.record_backoff(addr, window, now).await;
                self.attempted.lock().await.remove(&addr);
            }
        }
    }
}

/// A running peer pool. Drop or [`stop`](PeerPool::stop) to tear it down (the
/// dialer task is aborted; held peers close as their `Arc`s drop).
pub struct PeerPool {
    inner: Arc<PoolInner>,
}

impl PeerPool {
    /// Start the pool, consuming the discv4 candidate stream `rx`. `local_pubkey`
    /// is our node id (64-byte); `cfg` is our eth handshake parameters.
    pub fn start(
        key: Arc<NodeKey>,
        local_pubkey: [u8; 64],
        cfg: Arc<EthConfig>,
        pool_cfg: PoolConfig,
        cache: ElPeerCache,
        boot_enodes: Vec<(SocketAddr, [u8; 64])>,
        rx: mpsc::Receiver<TableEntry>,
        tx_watch: Option<crate::el::sent_tx::SharedSentTxWatch>,
        probe: Option<mpsc::Sender<SocketAddr>>,
        head_source: Option<Box<dyn Fn() -> Option<(u64, [u8; 32])> + Send + Sync>>,
    ) -> PeerPool {
        // Built before the struct literal (cfg is moved into it below).
        let served = Arc::new(ServedHeaders::with_genesis(
            crate::el::served::DEFAULT_SERVED_BLOCK_WINDOW,
            // Belt-and-braces: re-verify the RLP against the network's genesis
            // hash before seeding (the config path already did — see reader).
            cfg.genesis_header_rlp.as_ref().and_then(|rlp| {
                let h = myotis_core::keccak::keccak256(rlp);
                (h == cfg.genesis_hash).then(|| (h, rlp.clone()))
            }),
        ));
        let inner = Arc::new(PoolInner {
            tasks: super::tasks::Tasks::default(),
            key,
            local_pubkey,
            cfg,
            pool_cfg,
            peers: Mutex::new(Vec::new()),
            attempted: Mutex::new(HashSet::new()),
            backoff: Mutex::new(HashMap::new()),
            blacklist: Mutex::new(HashSet::new()),
            cache: Mutex::new(cache),
            boot_enodes,
            served,
            head_source: head_source.map(|f| -> AnchorSource { Arc::from(f) }),
            backfill_rr: std::sync::atomic::AtomicUsize::new(0),
            backfill_inflight: std::sync::atomic::AtomicBool::new(false),
            last_broadcast_range: Mutex::new(None),
            serve_stats: Arc::new(ServeStats::default()),
            hunting: AtomicBool::new(false),
            online_signal: Mutex::new(None),
            tx_watch,
            probe,
        });
        // Both the discv4 dialer and the maintainer dial through one shared
        // concurrency budget.
        let dial_slots = Arc::new(Semaphore::new(inner.pool_cfg.max_concurrent_dials));
        inner.tasks.spawn(dialer_loop(Arc::clone(&inner), rx, Arc::clone(&dial_slots)));
        inner.tasks.spawn(maintainer_loop(Arc::clone(&inner), dial_slots));
        PeerPool { inner }
    }

    /// The read ladder's first peer (see [`snap_peers`](Self::snap_peers)), or
    /// `None` if the pool has none yet.
    pub async fn snap_peer(&self) -> Option<Arc<ManagedPeer>> {
        self.snap_peers().await.into_iter().next()
    }

    /// All live snap peers in READ-LADDER order (see [`LadderKey`]): peers
    /// whose fresh word says they lack the anchored head last, read-benched
    /// peers (see [`READ_FAIL_BENCH`]) behind unbenched ones, then by how well
    /// their known head covers the anchored one, proven servers before
    /// unproven ones, newest connection first. Every peer stays reachable as
    /// the last resort. The verified-read ladder tries them in order, moving
    /// to the next on a failure — twin of the Java `RLPxConnector.trySnapPeer`
    /// retry loop with its transient bench, plus the head and proof keys #465
    /// added. Prunes closed peers first.
    pub async fn snap_peers(&self) -> Vec<Arc<ManagedPeer>> {
        self.inner.prune_closed().await;
        let now = Instant::now();
        let peers = self.inner.peers.lock().await;
        let newest_first: Vec<&PooledPeer> = peers.iter().rev().collect();
        let keys: Vec<LadderKey> = newest_first
            .iter()
            .map(|p| LadderKey::new(p.is_benched(now), p.peer.coverage(), p.unproven()))
            .collect();
        ladder_order(&keys)
            .into_iter()
            .map(|i| Arc::clone(&newest_first[i].peer))
            .collect()
    }

    /// Count of live snap peers (prunes closed peers first).
    pub async fn snap_peer_count(&self) -> usize {
        self.inner.prune_closed().await
    }

    /// Count of live snap peers that can answer a read at the anchored head
    /// right now (see `is_serving`) — the hosts' `snapServingPeers`. 0 while
    /// the anchor has no head. Prunes closed peers first.
    pub async fn snap_serving_count(&self) -> usize {
        self.inner.prune_closed().await;
        self.inner.count_where(is_serving).await
    }

    /// Addresses dialed and not yet failed (in-flight or connected).
    pub async fn attempted_count(&self) -> usize {
        self.inner.attempted.lock().await.len()
    }

    /// Inbound-serve counters `(header_asked, header_served, body_asked,
    /// body_served)` for the status page. Lock-free.
    pub fn serve_stats(&self) -> (u64, u64, u64, u64) {
        self.inner.serve_stats.snapshot()
    }

    /// Live-adjust the eth/69 served-block window (Settings knob). Shrinking
    /// evicts immediately; the next maintainer tick broadcasts the new range.
    pub fn set_served_block_window(&self, blocks: u64) {
        self.inner.served.set_window(blocks);
    }

    /// Node ids blacklisted as wrong-chain this run.
    pub async fn blacklist_count(&self) -> usize {
        self.inner.blacklist.lock().await.len()
    }

    /// Count of ACTIVE (non-expired) backoffs, pruning expired entries as a
    /// side effect — matching the `StatusSnapshot.backedOffPeers` "active,
    /// pruned on read" semantics (and the Java `activeBackoffCount`). Pruning
    /// here also keeps the map from lingering with dead entries.
    pub async fn backoff_count(&self) -> usize {
        let now = Instant::now();
        let mut backoff = self.inner.backoff.lock().await;
        backoff.retain(|_, expiry| *expiry > now);
        backoff.len()
    }

    /// A snap fetch against `addr` returned usable proof material — mark the
    /// cached peer CONFIRMED (dial-first next run). Persists only on a quality
    /// transition (dirty-gated flush), so repeated serves don't re-write.
    pub async fn record_snap_served(&self, addr: SocketAddr) {
        self.inner.record_quality(addr, QualityOutcome::Served).await;
    }

    /// A snap fetch against `addr` failed. `witnessed` = another peer served
    /// the same read: then, after the failure threshold, the cached peer is
    /// marked DENIED (deprioritized next run; dirty-gated flush). Unwitnessed
    /// — no peer served — it is benched and counted toward eviction like any
    /// failure, but never persisted (see [`QualityOutcome::FailedUnwitnessed`]).
    pub async fn record_snap_failure(&self, addr: SocketAddr, witnessed: bool) {
        self.inner.record_quality(addr, QualityOutcome::failed(witnessed)).await;
    }

    /// A hedged read was answered by a peer whose request went out no earlier
    /// than this one's, while this peer had had its request for at least the
    /// hedge delay (see `reader::RaceOutcome::outpaced`). Bench it for
    /// [`READ_FAIL_BENCH`] so the next reads start with someone else. The first
    /// outpace since the peer last served costs nothing more; each further one
    /// is also a verified-read failure (see [`OUTPACES_BEFORE_STRIKE`]).
    ///
    /// Only a peer whose request went out no later than the winner's can be
    /// outpaced, so a uniformly slow link does not strike anyone: there the
    /// first peer asked usually answers first, and the hedges sent after it are
    /// not counted. A request still waiting for the connection's writer never
    /// reached the peer and is not counted either.
    ///
    /// Without this, a silent peer was never struck once reads were hedged: the
    /// winner returns and the silent attempt is simply dropped, so the peer
    /// stayed at the front of the ladder and every read paid the hedge delay
    /// for as long as its dead connection lasted (a request timeout does not
    /// close the connection, and nothing pings it).
    pub async fn record_snap_outpaced(&self, addr: SocketAddr) {
        self.inner.record_outpaced(addr).await;
    }

    /// A cloneable, task-safe handle onto the snap-quality sinks — hands the
    /// EVM oracle's fetch loops the same reputation recording the block path
    /// uses, without holding the whole pool (the pool owns task handles and is
    /// deliberately not Clone).
    pub fn quality_sink(&self) -> SnapQualitySink {
        SnapQualitySink { inner: Arc::clone(&self.inner) }
    }

    /// EL hunt engaged: the serving pool has been empty past the stall window
    /// and the maintainer is in emergency mode (see EL_HUNT_STALL).
    pub fn el_hunting(&self) -> bool {
        self.inner.hunting.load(Ordering::Relaxed)
    }

    /// Stop the pool: flush the peer cache, abort the background tasks, and drop
    /// all held peers (closing them).
    pub async fn stop(&self) {
        // Close admission and join parent loops AND their dial/backfill/send
        // jobs before flushing caches or clearing peers. No late dial can
        // publish a fresh peer after stop has cleared the set.
        self.inner.tasks.stop().await;
        self.inner.cache.lock().await.flush();
        let mut peers = self.inner.peers.lock().await;
        for peer in peers.iter() { peer.peer.close().await; }
        peers.clear();
    }
}

impl Drop for PeerPool {
    fn drop(&mut self) {
        self.inner.tasks.abort();
    }
}

/// Dial cached snap peers first (warm start), then consume the discv4 candidate
/// stream — both through the same eligibility + concurrency-capped dial path.
async fn dialer_loop(
    inner: Arc<PoolInner>,
    mut rx: mpsc::Receiver<TableEntry>,
    dial_slots: Arc<Semaphore>,
) {
    // Warm start: the network's PINNED boot enodes first, then proven snap peers
    // from the cache, snap-quality first (Confirmed → Unknown → Denied).
    //
    // The pins are dialed directly rather than seeded into the cache. Seeding
    // would (a) be swallowed entirely by a disabled cache — a host with no
    // dataDir runs `ElPeerCache::disabled()`, whose `add` early-returns, so the
    // pin would silently never be dialed — and (b) force a snap flag onto the
    // entry: `add` overwrites it, so re-seeding "known but unproven" on each
    // start would DOWNGRADE the snap=true the peer earned in an earlier run and
    // sort it dead last (non-snap = rank 3). Dialing directly keeps the earned
    // quality intact and matches the Java twin, which dials
    // `NetworkConfig.elBootEnodes()` unconditionally (ChainStack
    // .directDialStaticEnodes). Once a pin connects, the normal path caches it
    // with the snap flag it actually proved.
    if !inner.boot_enodes.is_empty() {
        tracing::info!(count = inner.boot_enodes.len(), "EL pool dialing pinned boot enodes");
    }
    for (addr, pubkey) in inner.boot_enodes.clone() {
        if !try_dial(&inner, &dial_slots, addr, pubkey).await {
            return; // pool shutting down (dial semaphore closed)
        }
    }
    // Snapshot the list so the cache lock isn't held across the dials.
    let cached = inner.cache.lock().await.peers();
    if !cached.is_empty() {
        tracing::info!(count = cached.len(), "EL pool warm-starting from peer cache");
    }
    for c in cached {
        if inner.prune_closed().await >= inner.pool_cfg.target_snap_peers {
            break;
        }
        if !try_dial(&inner, &dial_slots, c.addr, c.pubkey).await {
            return; // pool shutting down (dial semaphore closed)
        }
    }

    // Then top up from live discovery.
    while let Some(entry) = rx.recv().await {
        // A candidate arriving proves discv4 round-trips are working — that's
        // the online signal that lets connect-failure counting clean up a
        // warm-started cache whose peers are ALL dead.
        inner.note_online().await;
        if inner.prune_closed().await >= inner.pool_cfg.target_snap_peers {
            continue;
        }
        let Some(addr) = to_socket_addr(&entry.ip, entry.tcp_port) else { continue };
        let Some(pubkey) = to_pubkey(&entry.node_id) else { continue };
        if !try_dial(&inner, &dial_slots, addr, pubkey).await {
            return; // pool shutting down (dial semaphore closed)
        }
    }
}

/// Eligibility-check a candidate and, if it passes, dial it in a permit-bounded
/// task. Silently skips a blacklisted node id, an address in backoff, one
/// already attempted/connected, or the attempted cap. Returns `false` only when
/// the dial semaphore is closed (the pool is shutting down) so the caller can
/// stop iterating; `true` otherwise (skipped or dialed).
async fn try_dial(
    inner: &Arc<PoolInner>,
    dial_slots: &Arc<Semaphore>,
    addr: SocketAddr,
    pubkey: [u8; 64],
) -> bool {
    if inner.blacklist.lock().await.contains(&pubkey) {
        return true;
    }
    // Backoff: skip while cooling off; drop the entry once expired so the map
    // doesn't grow unbounded.
    {
        let mut backoff = inner.backoff.lock().await;
        if let Some(&expiry) = backoff.get(&addr) {
            if Instant::now() < expiry {
                return true;
            }
            backoff.remove(&addr);
        }
    }
    // Claim the address (bounded), or skip if in-flight/connected already.
    {
        let mut attempted = inner.attempted.lock().await;
        if attempted.len() >= inner.pool_cfg.max_attempted || !attempted.insert(addr) {
            return true;
        }
    }
    // Bound concurrency: acquire a dial permit (waits when saturated), then dial
    // in a task that releases it when done.
    let Ok(permit) = Arc::clone(dial_slots).acquire_owned().await else {
        inner.attempted.lock().await.remove(&addr);
        return false;
    };
    let inner2 = Arc::clone(inner);
    inner.tasks.spawn(async move {
        inner2.dial_one(addr, pubkey).await;
        drop(permit);
    });
    true
}

/// Max headers requested per backfill tick — converges a full 4096-cap window
/// in a few minutes without hammering any one peer. Twin of the Java
/// `ChainStack.BACKFILL_BATCH`.
const BACKFILL_BATCH: u64 = 192;

/// What a backfill batch must anchor its TOP header's hash against before any
/// of it may enter the window. Every batch is chained: internally by parent
/// hashes, and at the top either to the beacon-anchored head hash or to the
/// parent hash of the held header just above it — so only content
/// cryptographically linked to the verified head is ever served.
#[derive(Debug, PartialEq, Eq)]
enum BatchAnchor {
    /// The batch ends at the anchored head: top hash must equal this.
    Head([u8; 32]),
    /// The batch fills below the held run: top hash must equal the held run's
    /// earliest header's parent hash.
    ChildParent([u8; 32]),
}

/// The pure per-tick backfill plan. `run` is the window's contiguous newest run
/// (earliest, latest); `earliest_parent` its earliest header's stored parent
/// hash. Two shapes, both fully anchored:
///  - the run doesn't include the anchored head → fetch up to and INCLUDING the
///    head (in one batch; too-far-behind runs restart near the head), anchored
///    by the beacon head hash;
///  - the run includes the head but not the floor → fill downward below the
///    run, anchored by the run's earliest parent hash. This also repairs the
///    "organic put ahead of the run strands the gap" case: filling is always
///    relative to the newest run.
fn backfill_plan(
    anchored: (u64, [u8; 32]),
    cap: u64,
    run: Option<(u64, u64, [u8; 32])>,
    earliest_parent: Option<[u8; 32]>,
) -> Option<(u64, u64, BatchAnchor)> {
    let (head, head_hash) = anchored;
    if head == 0 {
        return None;
    }
    let floor = head.saturating_sub(cap.saturating_sub(1)).max(1);
    match run {
        // Run reaches the anchored head AND its top is the beacon-verified head
        // hash: fill DOWN below it. The hash equality is load-bearing — without
        // it, one spoofed organic entry at/above the head number would become
        // the down-fill anchor and "verify" whole fabricated batches against
        // itself. A mismatched (or head-passing) top falls through to the
        // head-anchored restart arm, which overwrites the junk.
        Some((earliest, latest, latest_hash)) if latest == head && latest_hash == head_hash => {
            if earliest <= floor {
                return None; // window full
            }
            let from = earliest.saturating_sub(BACKFILL_BATCH).max(floor);
            Some((from, earliest - from, BatchAnchor::ChildParent(earliest_parent?)))
        }
        // Run below the head and adjacent-reachable in one batch: extend UP to
        // the head (top anchored by the beacon hash; the internal chain check
        // plus the top anchor transitively pins every element).
        Some((_, latest, _)) if latest < head && head - latest <= BACKFILL_BATCH => {
            let from = (latest + 1).max(floor);
            Some((from, head - from + 1, BatchAnchor::Head(head_hash)))
        }
        // Too far behind (or empty): restart at the head window.
        _ => {
            let from = head.saturating_sub(BACKFILL_BATCH - 1).max(floor);
            Some((from, head - from + 1, BatchAnchor::Head(head_hash)))
        }
    }
}

/// Validate an ascending backfill batch before admission: exact numbering
/// `[from..from+len)`, internal parent-hash chain, and the top anchored per
/// [`BatchAnchor`]. Any failure rejects the WHOLE batch.
fn batch_anchored(
    headers: &[crate::el::eth::messages::VerifiedHeader],
    from: u64,
    anchor: &BatchAnchor,
) -> bool {
    let Some(top) = headers.last() else { return false };
    for (i, h) in headers.iter().enumerate() {
        if h.header.number != from + i as u64 {
            return false;
        }
        if i > 0 && h.header.parent_hash != headers[i - 1].hash {
            return false;
        }
    }
    match anchor {
        BatchAnchor::Head(h) => top.hash == *h,
        BatchAnchor::ChildParent(p) => top.hash == *p,
    }
}

/// One bounded, ANCHORED backfill request per tick: plan the next missing chunk
/// of `[head-cap+1 ..= head]`, fetch it raw (no side-channel admission), verify
/// the batch parent-chains to the beacon anchor, and only then admit it into
/// the window. Runs in a spawned task so a hung peer (15 s request timeout >
/// the 10 s tick) can never stall the maintainer. Failures drop the batch; the
/// next tick retries.
async fn backfill_served_headers(inner: &Arc<PoolInner>) {
    let Some(head_source) = &inner.head_source else { return };
    let Some(anchored) = head_source() else { return };
    let cap = inner.served.window();
    let run = inner.served.advertise();
    let earliest_parent = run.and_then(|(e, _, _)| inner.served.parent_hash_of(e));
    let Some((from, count, anchor)) = backfill_plan(anchored, cap, run, earliest_parent) else {
        return;
    };
    // Rotate across the pool so one peer neither monopolizes nor poisons the
    // fill; snapshot the pick outside the lock.
    let peer = {
        let peers = inner.peers.lock().await;
        if peers.is_empty() {
            return;
        }
        let i = inner.backfill_rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Arc::clone(&peers[i % peers.len()].peer)
    };
    // One fetch at a time (see backfill_inflight).
    if inner
        .backfill_inflight
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let inner2 = Arc::clone(inner);
    inner.tasks.spawn(async move {
        tracing::debug!(from, count, head = anchored.0, "header backfill: anchored fetch");
        let result = peer.get_block_headers_by_number_raw(from, count).await;
        inner2.backfill_inflight.store(false, std::sync::atomic::Ordering::Release);
        let headers = match result {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(from, count, error = %e, "header backfill: fetch failed");
                return;
            }
        };
        if headers.len() as u64 != count || !batch_anchored(&headers, from, &anchor) {
            tracing::debug!(
                from,
                count,
                got = headers.len(),
                "header backfill: batch failed anchoring — dropped"
            );
            return;
        }
        // Reorg splice repair: if the held entry just below this verified batch
        // isn't the batch's parent, everything below is a stale fork — evict it
        // so the window never serves a spliced non-chain.
        if let (Some(first), Some(below_hash)) =
            (headers.first(), inner2.served.hash_of(from.saturating_sub(1)))
        {
            if first.header.parent_hash != below_hash {
                inner2.served.evict_below(from);
            }
        }
        // A batch that anchored at the beacon head is proof this peer holds
        // it — the same evidence a served read gives (peer::KnownHead).
        if let BatchAnchor::Head(_) = anchor {
            peer.note_head_served(anchored.0);
        }
        for vh in &headers {
            inner2.served.put(vh.header.number, vh.hash, vh.header.parent_hash, vh.raw_rlp.clone());
        }
    });
}

/// Evict pooled peers whose FRESH word says they have fallen behind the
/// anchored head (`peer::Coverage::Behind` — the same bar that refuses a peer
/// at the handshake), at most [`MAX_LAG_EVICTIONS_PER_TICK`] per tick, so a
/// runaway local anchor cannot churn the whole pool in one beat. Only the
/// peer's own announcement can say so: a served proof is at par by
/// construction, and an aging observation is Unknown, never Behind. Since
/// #465 a peer is no longer struck for lacking a head it SAID it lacks, so
/// this — with the admission check in `dial_one` — is what keeps a lagging
/// peer from holding a slot (the 2026-09-02 stale-pool wedge, by another
/// route: eight lagging peers held every slot through days of failing reads).
/// Corroborating the anchor against the served window before evicting was
/// considered and rejected: on a cold pool of syncing peers the backfill never
/// succeeds, so corroboration never arrives and the pool wedges — the very bug.
const MAX_LAG_EVICTIONS_PER_TICK: usize = 2;

async fn evict_lagging_peers(inner: &Arc<PoolInner>) {
    let victims: Vec<(SocketAddr, u64)> = inner
        .peers
        .lock()
        .await
        .iter()
        .filter(|p| !p.peer.is_closed() && p.peer.coverage() == Coverage::Behind)
        .map(|p| (p.addr, p.peer.known_head().and_then(|h| h.lag()).unwrap_or(0)))
        .take(MAX_LAG_EVICTIONS_PER_TICK)
        .collect();
    for (addr, lag) in victims {
        inner
            .evict_lagging(addr, &format!("its announced head is {lag} blocks behind the anchored one"))
            .await;
    }
}

/// The cheapest possible proof that a peer can serve reads at the anchored
/// head: one header, admitted through the same `batch_anchored` gate the
/// backfill uses. For peers with no usable head observation
/// (`peer::Coverage::Unknown`): eth/68 announces none, a word spoken before
/// the anchor had a head cannot be judged, and any observation goes stale
/// after `HEAD_SIGNAL_FRESH`. A hit counts as a served read for the peer's
/// standing; a miss the peer ANSWERED (no header, or not the anchored one) is
/// a lagging signal — [`PROBE_MISSES_EVICT`] in a row evict it as lagging (the
/// long backoff, no cache verdict), not one, because a single miss can be the
/// one-slot race between the optimistic head and the peer's import; a
/// transport failure is an ordinary unwitnessed read failure. Bounded per tick
/// and per peer; spawned through `tasks` so a stopping pool never has a probe
/// writing to a peer it is closing. A probe carries no address, so it widens
/// no disclosure (docs/privacy-and-tor.md).
const HEAD_PROBE_MIN_INTERVAL: Duration = Duration::from_secs(30);
const HEAD_PROBE_PER_TICK: usize = 2;
const PROBE_MISSES_EVICT: u32 = 3;

async fn probe_unknown_heads(inner: &Arc<PoolInner>) {
    let Some((head, head_hash)) = inner.anchored_head() else { return };
    let now = Instant::now();
    let candidates: Vec<(SocketAddr, Arc<ManagedPeer>)> = inner
        .peers
        .lock()
        .await
        .iter_mut()
        .filter(|p| {
            let recently =
                p.last_probe.is_some_and(|t| now.duration_since(t) < HEAD_PROBE_MIN_INTERVAL);
            !recently
                && !p.is_benched(now)
                && !p.peer.is_closed()
                && p.peer.coverage() == Coverage::Unknown
        })
        .take(HEAD_PROBE_PER_TICK)
        .map(|p| {
            // Stamped under the SAME lock that picked it: two ticks (or a tick
            // overlapping a slow probe) cannot double-ask a peer.
            p.last_probe = Some(now);
            (p.addr, Arc::clone(&p.peer))
        })
        .collect();
    for (addr, peer) in candidates {
        let inner2 = Arc::clone(inner);
        inner.tasks.spawn(async move {
            match peer.get_block_headers_by_number_raw(head, 1).await {
                Ok(h) if batch_anchored(&h, head, &BatchAnchor::Head(head_hash)) => {
                    tracing::debug!(%addr, head, "head probe: peer serves the anchored head");
                    peer.note_head_served(head);
                    inner2.record_quality(addr, QualityOutcome::Served).await;
                }
                Ok(_) => {
                    tracing::debug!(%addr, head, "head probe: peer answered without the anchored head");
                    inner2.note_probe_miss(addr).await;
                }
                Err(e) => {
                    tracing::debug!(%addr, head, error = %e, "head probe: request failed");
                    inner2.record_quality(addr, QualityOutcome::FailedUnwitnessed).await;
                }
            }
        });
    }
}

/// Send BlockRangeUpdate to all live eth/69 peers when our servable range has
/// changed since the last broadcast (deduped on the (earliest, latest, hash)
/// triple — a same-height reorg re-broadcasts too). Peers are snapshotted, then
/// sent to outside the peers lock; each send is bounded by the frame-write
/// timeout, and a failed write closes that peer (see send_block_range_update).
async fn broadcast_range_if_changed(inner: &Arc<PoolInner>) {
    let Some((earliest, latest, latest_hash)) = inner.served.advertise() else {
        return; // empty window — nothing new to promise
    };
    if !range_broadcast_due(
        &mut *inner.last_broadcast_range.lock().await,
        (earliest, latest, latest_hash),
        Instant::now(),
    ) {
        return;
    }
    let peers: Vec<Arc<ManagedPeer>> =
        inner.peers.lock().await.iter().map(|p| Arc::clone(&p.peer)).collect();
    // Concurrent sends: each is bounded by the frame-write timeout, but awaited
    // SEQUENTIALLY a few stalled peers would sum to minutes and starve the
    // maintainer's prune/re-dial work. Spawned, the tick is bounded by nothing —
    // a failed write closes its own peer (send_block_range_update fail_alls).
    for peer in peers {
        inner.tasks.spawn(async move {
            peer.send_block_range_update(earliest, latest, latest_hash).await;
        });
    }
}

/// Spec guidance: "It is recommended to send an update about once every two
/// minutes" (devp2p eth.md, BlockRangeUpdate).
const MIN_REBROADCAST_INTERVAL: Duration = Duration::from_secs(120);

/// The pure dedup + rate-limit decision for BlockRangeUpdate: broadcast (and
/// record) only when the (earliest, latest, latestHash) triple changed AND the
/// spec's recommended interval has passed since the last broadcast. The very
/// first broadcast is immediate — new peers get the range in their handshake
/// Status anyway, so nothing depends on it.
fn range_broadcast_due(
    last: &mut Option<((u64, u64, [u8; 32]), Instant)>,
    range: (u64, u64, [u8; 32]),
    now: Instant,
) -> bool {
    match last {
        Some((prev, at)) if *prev == range || now.duration_since(*at) < MIN_REBROADCAST_INTERVAL => {
            false
        }
        _ => {
            *last = Some((range, now));
            true
        }
    }
}

/// The snap-peer maintainer: on a timer, re-dial pinned boot enodes
/// (`pins_to_dial` — always below target, proven-servers-only above it) and,
/// while below `target_snap_peers`, top the pool back up from the cache
/// (snap-quality first). Twin of the Java `ChainStack.maintainSnapPeers` loop — the
/// discv4 dialer alone can starve on a long-running daemon once its stream goes
/// quiet and pooled peers die, so this keeps the pool healed from the cache.
async fn maintainer_loop(inner: Arc<PoolInner>, dial_slots: Arc<Semaphore>) {
    // EL-hunt stall clock: Some(t) while the pool has been continuously empty
    // since t. Maintainer-task-local — nothing else needs it.
    let mut zero_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(MAINTAINER_INTERVAL).await;
        // Serving is only real if we HOLD the recent headers peers ask for — a
        // light client fetches almost none organically. Top the window up toward
        // the anchored head (one bounded request per tick), then broadcast the
        // (possibly grown) range.
        backfill_served_headers(&inner).await;
        // #465: drop peers whose fresh word says they fell far behind the
        // head, and learn the heads of peers that announce none.
        evict_lagging_peers(&inner).await;
        probe_unknown_heads(&inner).await;
        // Keep the eth/69 advertised range honest over a connection's lifetime:
        // a peer told a narrow range at handshake would otherwise get empty
        // answers once the window slides forward. Broadcast on change (deduped).
        broadcast_range_if_changed(&inner).await;
        // prune_closed frees dead peers' addresses so try_dial can re-dial them.
        let live = inner.prune_closed().await;
        // The HUNT keys on peers that could actually serve reads right now:
        // read-benched peers don't count, and neither (since #465) does a
        // peer whose fresh announcement says it lacks the anchored head —
        // such a peer is no longer struck for the "0 headers" it predicted,
        // so it is never benched, and counting it would hide a pool of
        // laggards from the hunt. A pool whose every slot is held by laggards
        // is a serving outage exactly like an empty one — before this, 8 such
        // peers suppressed the hunt through days of failing reads
        // (2026-09-02) because "live" looked healthy. Fill and pin decisions
        // below keep using the TOTAL live count: eviction (see record_quality
        // and evict_lagging_peers) frees the slots quickly, so the two counts
        // converge.
        let serving = inner.count_where(counts_for_hunt).await;
        // target == 0 = maintainer deliberately idle: an empty pool is the
        // EXPECTED state — never engage the hunt (Java maintainSnapPeers twin).
        if inner.pool_cfg.target_snap_peers == 0 {
            zero_since = None;
            inner.hunting.store(false, Ordering::Relaxed);
            continue;
        }
        if serving > 0 {
            zero_since = None;
            if inner.hunting.swap(false, Ordering::Relaxed) {
                tracing::info!(serving, live, "EL hunt disengaged — snap peer serving again");
            }
        } else {
            zero_since.get_or_insert_with(Instant::now);
        }
        let hunting = el_hunt_due(serving, zero_since, Instant::now());
        if hunting && !inner.hunting.swap(true, Ordering::Relaxed) {
            tracing::info!(stall_secs = EL_HUNT_STALL.as_secs(),
                "EL hunt engaged — serving pool empty past the stall window \
                 (bypassing transient backoffs for cache-confirmed snap servers)");
        }
        // PINNED BOOT ENODES: maintained ABOVE the count gate (see
        // `pins_to_dial`). Below target, dial all — a dropped pin must reconnect
        // even when the pool is "full" of peers that cannot serve state. At/above
        // target, dial only proven snap servers, so a healthy pool doesn't
        // perpetually re-handshake a never-serving pin.
        let cached = inner.cache.lock().await.peers();
        let confirmed: std::collections::HashSet<SocketAddr> = cached
            .iter()
            .filter(|c| c.quality == SnapQuality::Confirmed)
            .map(|c| c.addr)
            .collect();
        for (addr, pubkey) in
            pins_to_dial(live, inner.pool_cfg.target_snap_peers, &inner.boot_enodes, &confirmed)
        {
            if !try_dial(&inner, &dial_slots, addr, pubkey).await {
                return; // pool shutting down
            }
        }
        // Discovered/cached peers are fungible — only fill UP TO the count target.
        if live >= inner.pool_cfg.target_snap_peers {
            continue;
        }
        if cached.is_empty() {
            continue;
        }
        if hunting {
            // Emergency: free the TRANSIENT backoffs of CONFIRMED snap servers
            // so the dial loop below reaches them NOW instead of after the
            // standard cool-off. Confirmed = served us chain-verified snap
            // data. Entries whose remaining window exceeds the transient
            // length are INCOMPATIBLE (10 min) or a not-yet-elapsed 60s busy
            // entry — keep those: the timer must stay honest (and for
            // incompatible, try_dial's blacklist would block the dial anyway).
            // Hunt-time BUSY entries are written at the transient window, so a
            // confirmed-but-busy server is clearable immediately and re-dials
            // roughly every maintainer tick while the pool is empty —
            // intentional, bounded slot-farming (Java maintainSnapPeers twin
            // documents the same trade-off). Non-confirmed peers keep timers.
            let now = Instant::now();
            let mut backoff = inner.backoff.lock().await;
            for c in cached.iter().filter(|c| c.quality == SnapQuality::Confirmed) {
                if backoff
                    .get(&c.addr)
                    .is_some_and(|exp| exp.saturating_duration_since(now) <= BACKOFF_TRANSIENT)
                {
                    backoff.remove(&c.addr);
                }
            }
        }
        tracing::debug!(
            live,
            target = inner.pool_cfg.target_snap_peers,
            cached = cached.len(),
            hunting,
            "EL pool below target — maintainer re-dialing cached snap peers"
        );
        for c in cached {
            // Cheap live-count check: the guard above already pruned, and this
            // tight loop rarely spans a peer closing, so read `peers` length
            // directly (freshly-connected dials show up here) rather than
            // re-pruning both maps every iteration.
            if inner.peers.lock().await.len() >= inner.pool_cfg.target_snap_peers {
                break;
            }
            if !try_dial(&inner, &dial_slots, c.addr, c.pubkey).await {
                return; // pool shutting down
            }
        }
    }
}

/// A discv4 entry's TCP socket, IPv4 or IPv6, or `None` if the address is
/// unusable. (discv4 endpoints carry 4- or 16-byte IPs; the pool's bookkeeping
/// is IP-version-agnostic, so both are dialed.)
fn to_socket_addr(ip: &[u8], tcp_port: u32) -> Option<SocketAddr> {
    if tcp_port == 0 || tcp_port > u32::from(u16::MAX) {
        return None;
    }
    let port = tcp_port as u16;
    match ip.len() {
        4 => {
            let octets: [u8; 4] = ip.try_into().ok()?;
            Some(SocketAddr::from((Ipv4Addr::from(octets), port)))
        }
        16 => {
            let octets: [u8; 16] = ip.try_into().ok()?;
            Some(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        _ => None,
    }
}

/// A discv4 entry's 64-byte node id, or `None` if malformed.
fn to_pubkey(node_id: &[u8]) -> Option<[u8; 64]> {
    node_id.try_into().ok()
}

/// See [`PeerPool::quality_sink`]. The Java `SnapQualitySink` twin: serves
/// confirm a peer (dial-first next run), failures count toward DENIED after
/// the cache's consecutive-failure threshold. Dirty-gated flush inside.
#[derive(Clone)]
pub struct SnapQualitySink {
    inner: Arc<PoolInner>,
}

impl SnapQualitySink {
    /// A snap fetch against `addr` returned usable proof material.
    pub async fn served(&self, addr: SocketAddr) {
        self.inner.record_quality(addr, QualityOutcome::Served).await;
    }

    /// A snap fetch against `addr` failed (bad proof / transport / timeout);
    /// `witnessed` = another peer served the same read (see
    /// [`PeerPool::record_snap_failure`]).
    pub async fn failed(&self, addr: SocketAddr, witnessed: bool) {
        self.inner.record_quality(addr, QualityOutcome::failed(witnessed)).await;
    }

    /// A hedged snap fetch against `addr` was outpaced by a peer whose request
    /// went out no earlier: bench it, and count a repeat as a failure (see
    /// `PeerPool::record_snap_outpaced`).
    pub async fn outpaced(&self, addr: SocketAddr) {
        self.inner.record_outpaced(addr).await;
    }
}

#[cfg(test)]
mod tests {
    /// The read-ladder rotation (2026-09-02 stale-pool wedge): benched peers
    /// go behind unbenched ones but are never dropped from the ladder, and
    /// repeated read failures evict — except the sole peer.
    mod read_rotation {
        use super::super::{
            ladder_order, outpace_verdict, read_failure_verdict, Coverage, LadderKey,
            OUTPACES_BEFORE_STRIKE, READ_FAILS_EVICT,
        };

        /// Keys with no head evidence and no proof — the pre-#465 ladder,
        /// which the bench flag alone ordered.
        fn bench_only(benched: &[bool]) -> Vec<LadderKey> {
            benched.iter().map(|&b| LadderKey::new(b, Coverage::Unknown, true)).collect()
        }

        #[test]
        fn unbenched_lead_benched_trail_newest_first_within_each() {
            //                          n     n-1    n-2    n-3
            let benched = [false, true, false, true];
            assert_eq!(ladder_order(&bench_only(&benched)), vec![0, 2, 1, 3]);
        }

        #[test]
        fn an_all_benched_pool_still_serves_the_full_ladder() {
            // The sole-server semantics: benched is a preference, not a veto —
            // a wallet with only failing peers must still ask them rather
            // than answer nothing while the maintainer refills.
            assert_eq!(ladder_order(&bench_only(&[true, true, true])), vec![0, 1, 2]);
        }

        #[test]
        fn nothing_benched_keeps_the_newest_first_order() {
            // Stable sort: equal keys stay newest first.
            assert_eq!(ladder_order(&bench_only(&[false, false])), vec![0, 1]);
        }

        #[test]
        fn a_covering_peer_leads_a_behind_one_even_when_benched() {
            // #465: the peer whose own word says it lacks the head goes last,
            // whatever else is true — one transient failure by a peer that
            // HAS the head must not drop it below peers that provably do not.
            let keys = [
                LadderKey::new(false, Coverage::Behind, false),
                LadderKey::new(true, Coverage::Covers, false),
                LadderKey::new(false, Coverage::Unknown, true),
            ];
            assert_eq!(ladder_order(&keys), vec![2, 1, 0]);
        }

        #[test]
        fn head_evidence_orders_the_unbenched_covers_near_unknown() {
            let keys = [
                LadderKey::new(false, Coverage::Unknown, false),
                LadderKey::new(false, Coverage::Near, false),
                LadderKey::new(false, Coverage::Covers, false),
            ];
            assert_eq!(ladder_order(&keys), vec![2, 1, 0]);
        }

        #[test]
        fn never_proven_peers_trail_proven_ones_within_a_bucket() {
            // The warm-start case: the cache-Confirmed peer is the OLDEST
            // connection (dialed first) and used to sit at the bottom.
            let keys = [
                LadderKey::new(false, Coverage::Unknown, true),
                LadderKey::new(false, Coverage::Unknown, true),
                LadderKey::new(false, Coverage::Unknown, false),
            ];
            assert_eq!(ladder_order(&keys), vec![2, 0, 1]);
        }

        #[test]
        fn a_pool_that_is_entirely_behind_still_serves_the_full_ladder() {
            // Behind is a ranking, never an exclusion: the read still asks
            // everyone, and the retry loop rides out a genuine tip-lag race.
            let keys = [
                LadderKey::new(true, Coverage::Behind, true),
                LadderKey::new(false, Coverage::Behind, true),
            ];
            assert_eq!(ladder_order(&keys), vec![1, 0]);
        }

        #[test]
        fn eviction_at_the_threshold_but_never_the_sole_peer() {
            assert_eq!(read_failure_verdict(0, 8), (1, false));
            assert_eq!(read_failure_verdict(READ_FAILS_EVICT - 1, 8), (READ_FAILS_EVICT, true));
            // The sole remaining peer is benched but never evicted, and its
            // strike is NOT banked — a failure against the only server may be
            // our own stale ask, so the count stays 0 rather than arming an
            // eviction the instant a second peer appears.
            assert_eq!(read_failure_verdict(0, 1), (0, false));
            assert_eq!(read_failure_verdict(READ_FAILS_EVICT - 1, 1), (0, false));
            // ...so after the pool grows the ex-sole peer starts from 0, not
            // one failure from eviction.
            assert_eq!(read_failure_verdict(0, 2), (1, false));
        }

        #[test]
        fn a_peer_that_never_serves_is_evicted_by_repeated_outpaces() {
            // A hedged read drops a silent attempt once another peer answers,
            // so an open-but-dead connection only ever shows up as outpaced.
            // The first outpace is free, each further one is a strike, and the
            // strikes evict at the usual threshold: gone on the fourth
            // outpace, not never.
            assert_eq!(outpace_verdict(0), (1, false));
            assert_eq!(outpace_verdict(1), (2, true));
            assert_eq!(outpace_verdict(u32::MAX), (u32::MAX, true));
            let (mut streak, mut fails) = (0, 0);
            let mut evicted_at = None;
            for n in 1..=10u32 {
                let (next, strike) = outpace_verdict(streak);
                streak = next;
                if strike {
                    let (f, evict) = read_failure_verdict(fails, 8);
                    fails = f;
                    if evict {
                        evicted_at = Some(n);
                        break;
                    }
                }
            }
            assert_eq!(evicted_at, Some(OUTPACES_BEFORE_STRIKE + READ_FAILS_EVICT));
            assert_eq!(evicted_at, Some(4));
        }
    }

    /// The pure head policies #465 added: the witness rule for persisted
    /// verdicts and the two serving tallies (the admission/eviction bar lives
    /// with `peer::coverage`).
    mod head_policy {
        use super::super::{counts_for_hunt, is_serving, persist_verdict, Coverage};

        #[test]
        fn a_whole_pool_failure_persists_nothing_against_anyone() {
            assert!(!persist_verdict(false, true));
            assert!(!persist_verdict(false, false));
        }

        #[test]
        fn the_sole_peer_shield_still_holds() {
            assert!(!persist_verdict(true, false));
        }

        #[test]
        fn a_witnessed_failure_with_another_live_peer_persists() {
            assert!(persist_verdict(true, true));
        }

        #[test]
        fn serving_needs_evidence_but_the_hunt_only_needs_hope() {
            for cov in [Coverage::Covers, Coverage::Near] {
                assert!(is_serving(false, cov));
                assert!(counts_for_hunt(false, cov));
                assert!(!is_serving(true, cov));
                assert!(!counts_for_hunt(true, cov));
            }
            // No evidence: not serving for the hosts, but the hunt must not
            // engage on it (before the anchor lands EVERY peer is Unknown).
            assert!(!is_serving(false, Coverage::Unknown));
            assert!(counts_for_hunt(false, Coverage::Unknown));
            // Said it lacks the head: neither.
            assert!(!is_serving(false, Coverage::Behind));
            assert!(!counts_for_hunt(false, Coverage::Behind));
        }
    }

    #[test]
    fn backfill_plan_is_always_anchored() {
        use super::{backfill_plan, BatchAnchor, BACKFILL_BATCH};
        let hh = [7u8; 32]; // anchored head hash
        let pp = [9u8; 32]; // held run's earliest parent hash
        // No head yet → nothing.
        assert_eq!(backfill_plan((0, hh), 32, None, None), None);
        // Empty window: restart at the head window, anchored by the head hash.
        assert_eq!(
            backfill_plan((1_000_000, hh), 32, None, None),
            Some((999_969, 32, BatchAnchor::Head(hh)))
        );
        assert_eq!(
            backfill_plan((1_000_000, hh), 4096, None, None),
            Some((999_809, BACKFILL_BATCH, BatchAnchor::Head(hh)))
        );
        // Run below the head within one batch: extend UP to and including the head.
        assert_eq!(
            backfill_plan((1_000_000, hh), 4096, Some((999_000, 999_980, hh)), Some(pp)),
            Some((999_981, 20, BatchAnchor::Head(hh)))
        );
        // Run too far behind: restart near the head (still head-anchored).
        assert_eq!(
            backfill_plan((1_000_000, hh), 4096, Some((900_000, 900_010, hh)), Some(pp)),
            Some((999_809, BACKFILL_BATCH, BatchAnchor::Head(hh)))
        );
        // Run includes the head WITH the beacon-verified top hash: fill DOWN,
        // anchored by the held run's earliest parent hash.
        assert_eq!(
            backfill_plan((1_000_000, hh), 4096, Some((999_900, 1_000_000, hh)), Some(pp)),
            Some((999_708, 192, BatchAnchor::ChildParent(pp)))
        );
        // N1 guard: a run top at the head number whose hash is NOT the beacon
        // hash (spoofed organic entry) must NOT become the down-fill anchor —
        // the plan restarts head-anchored, overwriting the junk.
        assert_eq!(
            backfill_plan((1_000_000, hh), 4096, Some((999_900, 1_000_000, [0xbb; 32])), Some(pp)),
            Some((999_809, BACKFILL_BATCH, BatchAnchor::Head(hh)))
        );
        // Down-fill without a known earliest parent (shouldn't happen) → no plan.
        assert_eq!(backfill_plan((1_000_000, hh), 4096, Some((999_900, 1_000_000, hh)), None), None);
        // Window full → done.
        assert_eq!(
            backfill_plan((1_000_000, hh), 32, Some((999_969, 1_000_000, hh)), Some(pp)),
            None
        );
        // cap=1: only the head itself.
        assert_eq!(
            backfill_plan((1_000_000, hh), 1, None, None),
            Some((1_000_000, 1, BatchAnchor::Head(hh)))
        );
    }

    #[test]
    fn batch_anchoring_rejects_unchained_and_misnumbered() {
        use super::{batch_anchored, BatchAnchor};
        use crate::el::eth::messages::VerifiedHeader;
        use myotis_core::header::BlockHeader;
        // Build a 3-header parent-chained batch [100..102] from real RLP.
        fn mk(number: u64, parent: [u8; 32]) -> VerifiedHeader {
            // A minimal-but-decodable header: reuse the pinned genesis fields via
            // decode of a synthetic header is heavy — instead fabricate the struct
            // directly (batch_anchored only reads number/parent_hash/hash).
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&number.to_be_bytes());
            VerifiedHeader {
                hash,
                raw_rlp: vec![0xc0],
                header: BlockHeader { number, parent_hash: parent, ..synthetic_header() },
            }
        }
        fn synthetic_header() -> BlockHeader {
            // decode the embedded genesis for a fully-populated template
            let (_, rlp) = crate::el::served::mainnet_genesis().unwrap();
            BlockHeader::decode(&rlp).unwrap()
        }
        let h100 = mk(100, [1u8; 32]);
        let h101 = mk(101, h100.hash);
        let h102 = mk(102, h101.hash);
        let top_hash = h102.hash;
        let batch = vec![h100.clone(), h101.clone(), h102.clone()];
        assert!(batch_anchored(&batch, 100, &BatchAnchor::Head(top_hash)));
        assert!(batch_anchored(&batch, 100, &BatchAnchor::ChildParent(top_hash)));
        // Wrong anchor hash → rejected.
        assert!(!batch_anchored(&batch, 100, &BatchAnchor::Head([0xee; 32])));
        // Broken internal chain → rejected.
        let broken = vec![h100.clone(), mk(101, [0xdd; 32]), h102.clone()];
        assert!(!batch_anchored(&broken, 100, &BatchAnchor::Head(top_hash)));
        // Misnumbered → rejected.
        assert!(!batch_anchored(&batch, 99, &BatchAnchor::Head(top_hash)));
        // Empty → rejected.
        assert!(!batch_anchored(&[], 100, &BatchAnchor::Head(top_hash)));
    }

    #[test]
    fn range_broadcast_dedup_and_rate_limit() {
        use super::{range_broadcast_due, MIN_REBROADCAST_INTERVAL};
        use tokio::time::Instant; // pool.rs's Instant is tokio's re-export
        let mut last = None;
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let t0 = Instant::now();
        assert!(range_broadcast_due(&mut last, (10, 20, h1), t0), "first range broadcasts");
        assert!(!range_broadcast_due(&mut last, (10, 20, h1), t0), "unchanged is deduped");
        // Changed but inside the spec interval: suppressed (and NOT recorded).
        let early = t0 + MIN_REBROADCAST_INTERVAL / 2;
        assert!(!range_broadcast_due(&mut last, (11, 21, h1), early), "rate-limited");
        // Past the interval, the latest change fires.
        let due = t0 + MIN_REBROADCAST_INTERVAL;
        assert!(range_broadcast_due(&mut last, (11, 21, h1), due), "due change fires");
        // Same-height reorg (hash-only change) also fires once due.
        let due2 = due + MIN_REBROADCAST_INTERVAL;
        assert!(range_broadcast_due(&mut last, (11, 21, h2), due2), "reorg hash fires");
    }

    use super::*;

    #[test]
    fn to_socket_addr_validation() {
        assert!(to_socket_addr(&[1, 2, 3, 4], 30303).is_some());
        assert!(to_socket_addr(&[0; 16], 30303).is_some()); // IPv6
        assert!(to_socket_addr(&[1, 2, 3], 30303).is_none()); // wrong length
        assert!(to_socket_addr(&[0; 15], 30303).is_none()); // wrong length
        assert!(to_socket_addr(&[1, 2, 3, 4], 0).is_none()); // no TCP port
        assert!(to_socket_addr(&[1, 2, 3, 4], 70000).is_none()); // port out of range
    }

    #[test]
    fn to_pubkey_requires_64_bytes() {
        assert_eq!(to_pubkey(&[7u8; 64]), Some([7u8; 64]));
        assert!(to_pubkey(&[7u8; 63]).is_none());
        assert!(to_pubkey(&[]).is_none());
    }

    #[tokio::test]
    async fn empty_pool_has_no_snap_peer() {
        let key = Arc::new(
            NodeKey::from_secret_bytes(&myotis_core::keccak::keccak256(b"pool-test")).unwrap(),
        );
        let cfg = Arc::new(EthConfig {
            network_id: 1,
            genesis_hash: [0u8; 32],
            fork_id_hash: [0u8; 4],
            fork_next: 0,
            head_hash: [0u8; 32],
            head_number: 0,
            listen_port: 30303,
            genesis_header_rlp: None,
        });
        let (_tx, rx) = mpsc::channel(4);
        let pool = PeerPool::start(
            Arc::clone(&key),
            key.public_key_bytes(),
            cfg,
            PoolConfig::default(),
            ElPeerCache::disabled(),
            Vec::new(), // no pinned boot enodes in fixtures
            rx,
            None,
            None,
            None,
        );
        assert_eq!(pool.snap_peer_count().await, 0);
        assert!(pool.snap_peer().await.is_none());
        assert_eq!(pool.attempted_count().await, 0);
        pool.stop().await;
    }

    #[tokio::test]
    async fn warm_start_dials_cached_peers_and_survives_a_flush() {
        // Seed the cache with a snap peer at a LOCAL listener that accepts TCP but
        // never speaks, using a VALID secp256k1 pubkey. Both halves are load-bearing:
        // the dial does TCP connect first (loopback: instant success), then ECIES
        // auth — where an off-curve key like the old [9u8; 64] fails ecdh_x in ~1 ms
        // BEFORE the auth write, unclaiming the address before the first poll. With
        // a real key the auth write lands in the kernel buffer and the ack read
        // parks against the 10 s HANDSHAKE_TIMEOUT (far beyond this test), so the
        // address stays claimed in `attempted` while we poll. (The old version used
        // TEST-NET-1 as a "blackhole", which is routing-dependent: hosts returning
        // ENETUNREACH failed the connect instantly — flaky by machine.)
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let remote = NodeKey::from_secret_bytes(&myotis_core::keccak::keccak256(b"warm-remote")).unwrap();
        let path = std::env::temp_dir().join(format!("myotis-pool-warm-{}.cache", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut seed = ElPeerCache::load(path.clone());
            seed.add(addr, &remote.public_key_bytes(), true);
            seed.flush();
        }

        let key = Arc::new(
            NodeKey::from_secret_bytes(&myotis_core::keccak::keccak256(b"warm-test")).unwrap(),
        );
        let cfg = Arc::new(EthConfig {
            network_id: 1,
            genesis_hash: [0u8; 32],
            fork_id_hash: [0u8; 4],
            fork_next: 0,
            head_hash: [0u8; 32],
            head_number: 0,
            listen_port: 30303,
            genesis_header_rlp: None,
        });
        let (_tx, rx) = mpsc::channel(4);
        let pool = PeerPool::start(
            Arc::clone(&key),
            key.public_key_bytes(),
            cfg,
            PoolConfig::default(),
            ElPeerCache::load(path.clone()),
            Vec::new(), // no pinned boot enodes in fixtures
            rx,
            None,
            None,
            None,
        );
        // The warm-start branch dials the cached peer, claiming its address.
        // Poll briefly (the silent listener parks the handshake, so the address
        // stays claimed).
        let mut attempted = 0;
        for _ in 0..40 {
            attempted = pool.attempted_count().await;
            if attempted >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(attempted, 1, "warm start should have dialed the cached peer");

        pool.stop().await;
        drop(listener); // kept alive so the pending dial stayed claimed while polling
        // The cached peer survived load → warm-start → flush-on-stop.
        assert_eq!(ElPeerCache::load(path.clone()).len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn snap_quality_outcomes_persist_to_the_cache() {
        use crate::el::peercache::SnapQuality;
        let path =
            std::env::temp_dir().join(format!("myotis-pool-quality-{}.cache", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let addr: SocketAddr = "192.0.2.5:30303".parse().unwrap();
        {
            let mut seed = ElPeerCache::load(path.clone());
            seed.add(addr, &[7u8; 64], true); // enters as Unknown
            seed.flush();
        }

        let key = Arc::new(
            NodeKey::from_secret_bytes(&myotis_core::keccak::keccak256(b"quality-test")).unwrap(),
        );
        let cfg = Arc::new(EthConfig {
            network_id: 1,
            genesis_hash: [0u8; 32],
            fork_id_hash: [0u8; 4],
            fork_next: 0,
            head_hash: [0u8; 32],
            head_number: 0,
            listen_port: 30303,
            genesis_header_rlp: None,
        });
        let (_tx, rx) = mpsc::channel(4);
        let pool = PeerPool::start(
            Arc::clone(&key),
            key.public_key_bytes(),
            cfg,
            PoolConfig::default(),
            ElPeerCache::load(path.clone()),
            Vec::new(), // no pinned boot enodes in fixtures
            rx,
            None,
            None,
            None,
        );

        // No verdict is persisted without another live peer to compare
        // against, witnessed or not — the sole-peer shield. (The witness rule
        // itself is pinned by the pure `persist_verdict` tests: telling the two
        // apart through the pool takes a live second peer.)
        for witnessed in [false, true, false, true, false, true] {
            pool.record_snap_failure(addr, witnessed).await;
        }
        assert_eq!(ElPeerCache::load(path.clone()).peers()[0].quality, SnapQuality::Unknown);

        // A served outcome promotes the cached peer to Confirmed and persists it.
        pool.record_snap_served(addr).await;
        assert_eq!(
            ElPeerCache::load(path.clone()).peers()[0].quality,
            SnapQuality::Confirmed
        );

        pool.stop().await;
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn busy_disconnect_classification_is_prefix_and_suffix_bound() {
        assert!(is_busy_disconnect("peer disconnected: reason=4"));
        assert!(is_busy_disconnect("peer disconnected during handshake: reason=4"));
        // Other reasons and other error shapes are NOT busy.
        assert!(!is_busy_disconnect("peer disconnected: reason=3"));
        assert!(!is_busy_disconnect("peer disconnected: reason=42"));
        assert!(!is_busy_disconnect("incompatible peer: networkId=137 genesis=..."));
        // A peer-controlled client id echoed mid-string can't fake the prefix.
        assert!(!is_busy_disconnect("expected Status, got code 0x04 from peer disconnected: reason=4x"));
        // The Status-stage variant classifies by the same ends. Built through
        // the REAL producer so a rewording that drops the "peer disconnected"
        // prefix breaks here instead of silently degrading busy to transient —
        // and a hostile client id mid-string can't steer either end.
        let status_busy = crate::el::eth::session::status_disconnect_error(
            "Nethermind/v1.36.2",
            69,
            &[0xc1, 0x04],
        );
        assert!(is_busy_disconnect(&status_busy), "producer drifted: {status_busy}");
        let status_hostile = crate::el::eth::session::status_disconnect_error(
            "reason=4\nforged line",
            69,
            &[0xc1, 0x10],
        );
        assert!(!is_busy_disconnect(&status_hostile));
        assert!(!status_hostile.contains('\n'), "client id must be Debug-escaped");
        // Producer-coupled: build the string through the REAL session
        // formatter (RLP [0x04] = TooManyPeers) so a future format change in
        // describe_disconnect breaks this test instead of silently degrading
        // busy classification to transient.
        let produced = format!(
            "peer disconnected: {}",
            crate::el::eth::session::describe_disconnect(&[0xc1, 0x04])
        );
        assert!(is_busy_disconnect(&produced), "producer drifted: {produced}");
        let produced_other = format!(
            "peer disconnected: {}",
            crate::el::eth::session::describe_disconnect(&[0xc1, 0x03])
        );
        assert!(!is_busy_disconnect(&produced_other));
    }

    #[test]
    fn pins_dial_below_target_and_only_confirmed_above() {
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let pins = vec![(a, [1u8; 64]), (b, [2u8; 64])];
        let none: std::collections::HashSet<SocketAddr> = Default::default();
        let confirmed_a: std::collections::HashSet<SocketAddr> = [a].into_iter().collect();

        // Below target: every pin, proven or not — a dropped pin must reconnect
        // even when the pool is "full" of peers that cannot serve state.
        assert_eq!(pins_to_dial(3, 8, &pins, &none).len(), 2);
        assert_eq!(pins_to_dial(0, 8, &pins, &none).len(), 2);

        // At/above target: only pins already proven to serve snap data, so a
        // healthy pool doesn't perpetually re-handshake a never-serving pin.
        assert_eq!(pins_to_dial(8, 8, &pins, &none).len(), 0);
        let only = pins_to_dial(9, 8, &pins, &confirmed_a);
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].0, a); // the confirmed one, not b

        // The incident shape: a proven pin (the dedicated node) dropped while the
        // pool is at target with non-serving peers — it is still dialed.
        assert_eq!(pins_to_dial(8, 8, &pins, &confirmed_a).len(), 1);
    }

    #[test]
    fn el_hunt_due_triggers_only_on_sustained_empty_pool() {
        let now = Instant::now();
        // Any live peer → never hunt, regardless of how long the pool WAS empty.
        assert!(!el_hunt_due(1, Some(now - EL_HUNT_STALL * 2), now));
        // Empty but not yet past the stall window → no hunt (fresh starts and
        // brief blips must not trip emergency mode).
        assert!(!el_hunt_due(0, Some(now - Duration::from_secs(5)), now));
        assert!(!el_hunt_due(0, None, now));
        // Empty past the window → hunt.
        assert!(el_hunt_due(0, Some(now - EL_HUNT_STALL), now));
    }
}


