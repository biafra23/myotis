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
use tokio::task::JoinHandle;
use tokio::time::Instant;

use myotis_core::nodekey::NodeKey;

use crate::el::discv4::TableEntry;
use crate::el::eth::session::{EthConfig, EthSession};
use crate::el::peer::ManagedPeer;
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
/// farming freed slots (Java's `BACKOFF_BUSY_MS`).
const BACKOFF_BUSY: Duration = Duration::from_secs(60);

/// True when a dial error is a TooManyPeers rejection. The session's
/// disconnect errors are fixed-format ("peer disconnected[ during
/// handshake]: reason=N" — see `describe_disconnect`), so prefix+suffix
/// matching cannot be steered by peer-controlled content. 0x04 says nothing
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

/// A live pooled peer plus the address it was dialed at (so pruning a dropped
/// peer can free its address for a future re-dial).
struct PooledPeer {
    addr: SocketAddr,
    peer: Arc<ManagedPeer>,
}

struct PoolInner {
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
    /// Recent headers we can serve to peers + the eth/69 advertised range source.
    served: Arc<ServedHeaders>,
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
}

impl PoolInner {
    /// The single quality-recording path (dirty-gated flush inside) — shared by
    /// the pool's public sinks and [`SnapQualitySink`] so behavior can't drift.
    async fn record_quality(&self, addr: SocketAddr, served: bool) {
        // Never demote the LAST live snap peer: an empty/failed fetch against
        // the sole server usually means WE asked for a root outside its
        // snapshot window (stale local head), not that the peer is bad — and
        // three such strikes would persist a snapbad verdict against the one
        // peer still serving us. Twin of the Java benchUnlessLastServing scan
        // (`h != failed`): the guard keys on whether any OTHER peer is live,
        // not on pool size — a lone pooled peer at a DIFFERENT address means
        // the failing one isn't our last resort and the strike must count.
        // (Deliberate asymmetry with Java: this skips a PERSISTED verdict
        // step, Java skips a transient 30s bench — same trigger, harsher
        // consequence here, hence the same protection.)
        if !served && !self.peers.lock().await.iter().any(|p| p.addr != addr) {
            tracing::debug!(%addr, "skipping snap-failure verdict — no other serving peer");
            return;
        }
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
        match result {
            Ok(session) if session.snap => {
                // INFO: the operator-visible signal that the EL found a usable
                // snap peer (bounded to ~target occurrences per run). Per-peer
                // failures/non-snap stay at debug to avoid the discv4 cross-chain
                // noise (most discovered peers are other networks or full).
                tracing::info!(%addr, eth = session.eth_version, "el dial: snap peer connected");
                let peer = Arc::new(ManagedPeer::spawn_serving(
                    session,
                    addr,
                    ServeContext {
                        window: Arc::clone(&self.served),
                        stats: Arc::clone(&self.serve_stats),
                    },
                    self.tx_watch.clone(),
                ));
                // Keep `addr` in `attempted` while connected — dropped by
                // prune_closed when the peer later closes.
                self.peers.lock().await.push(PooledPeer { addr, peer });
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
                    BACKOFF_BUSY
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
    dialer_task: JoinHandle<()>,
    /// Keeps the live snap-peer count at target by re-dialing cached peers when
    /// they die (twin of the Java `ChainStack.maintainSnapPeers` loop).
    maintainer_task: JoinHandle<()>,
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
        rx: mpsc::Receiver<TableEntry>,
        tx_watch: Option<crate::el::sent_tx::SharedSentTxWatch>,
    ) -> PeerPool {
        let inner = Arc::new(PoolInner {
            key,
            local_pubkey,
            cfg,
            pool_cfg,
            peers: Mutex::new(Vec::new()),
            attempted: Mutex::new(HashSet::new()),
            backoff: Mutex::new(HashMap::new()),
            blacklist: Mutex::new(HashSet::new()),
            cache: Mutex::new(cache),
            served: Arc::new(ServedHeaders::default()),
            serve_stats: Arc::new(ServeStats::default()),
            hunting: AtomicBool::new(false),
            online_signal: Mutex::new(None),
            tx_watch,
        });
        // Both the discv4 dialer and the maintainer dial through one shared
        // concurrency budget.
        let dial_slots = Arc::new(Semaphore::new(inner.pool_cfg.max_concurrent_dials));
        let dialer_task = tokio::spawn(dialer_loop(Arc::clone(&inner), rx, Arc::clone(&dial_slots)));
        let maintainer_task = tokio::spawn(maintainer_loop(Arc::clone(&inner), dial_slots));
        PeerPool { inner, dialer_task, maintainer_task }
    }

    /// A live snap-capable peer for a verified read, or `None` if the pool has
    /// none yet. Prunes closed peers first; returns the newest live peer (most
    /// likely to still retain recent state).
    pub async fn snap_peer(&self) -> Option<Arc<ManagedPeer>> {
        self.inner.prune_closed().await;
        self.inner.peers.lock().await.last().map(|p| Arc::clone(&p.peer))
    }

    /// All live snap peers, NEWEST first (freshest head → most likely to still
    /// retain the state a query needs). The verified-read ladder tries them in
    /// order, moving to the next on a failure — twin of the Java
    /// `RLPxConnector.trySnapPeer` retry loop. Prunes closed peers first.
    pub async fn snap_peers(&self) -> Vec<Arc<ManagedPeer>> {
        self.inner.prune_closed().await;
        self.inner
            .peers
            .lock()
            .await
            .iter()
            .rev()
            .map(|p| Arc::clone(&p.peer))
            .collect()
    }

    /// Count of live snap peers (prunes closed peers first).
    pub async fn snap_peer_count(&self) -> usize {
        self.inner.prune_closed().await
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
        self.inner.record_quality(addr, true).await;
    }

    /// A snap fetch against `addr` failed — after the failure threshold the
    /// cached peer is marked DENIED (deprioritized next run). Dirty-gated flush.
    pub async fn record_snap_failure(&self, addr: SocketAddr) {
        self.inner.record_quality(addr, false).await;
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
    pub async fn stop(self) {
        self.inner.cache.lock().await.flush();
        self.dialer_task.abort();
        self.maintainer_task.abort();
        self.inner.peers.lock().await.clear();
    }
}

impl Drop for PeerPool {
    fn drop(&mut self) {
        self.dialer_task.abort();
        self.maintainer_task.abort();
    }
}

/// Dial cached snap peers first (warm start), then consume the discv4 candidate
/// stream — both through the same eligibility + concurrency-capped dial path.
async fn dialer_loop(
    inner: Arc<PoolInner>,
    mut rx: mpsc::Receiver<TableEntry>,
    dial_slots: Arc<Semaphore>,
) {
    // Warm start: re-dial proven snap peers from the cache, snap-quality first
    // (Confirmed → Unknown → Denied). Snapshot the list so the cache lock isn't
    // held across the dials.
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
    tokio::spawn(async move {
        inner2.dial_one(addr, pubkey).await;
        drop(permit);
    });
    true
}

/// The snap-peer maintainer: on a timer, if the live snap count has dropped
/// below `target_snap_peers`, re-dial cached snap peers (snap-quality first) to
/// top back up. Twin of the Java `ChainStack.maintainSnapPeers` loop — the
/// discv4 dialer alone can starve on a long-running daemon once its stream goes
/// quiet and pooled peers die, so this keeps the pool healed from the cache.
async fn maintainer_loop(inner: Arc<PoolInner>, dial_slots: Arc<Semaphore>) {
    // EL-hunt stall clock: Some(t) while the pool has been continuously empty
    // since t. Maintainer-task-local — nothing else needs it.
    let mut zero_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(MAINTAINER_INTERVAL).await;
        // prune_closed frees dead peers' addresses so try_dial can re-dial them.
        let live = inner.prune_closed().await;
        // target == 0 = maintainer deliberately idle: an empty pool is the
        // EXPECTED state — never engage the hunt (Java maintainSnapPeers twin).
        if inner.pool_cfg.target_snap_peers == 0 {
            zero_since = None;
            inner.hunting.store(false, Ordering::Relaxed);
            continue;
        }
        if live > 0 {
            zero_since = None;
            if inner.hunting.swap(false, Ordering::Relaxed) {
                tracing::info!(live, "EL hunt disengaged — snap peer serving again");
            }
        } else {
            zero_since.get_or_insert_with(Instant::now);
        }
        let hunting = el_hunt_due(live, zero_since, Instant::now());
        if hunting && !inner.hunting.swap(true, Ordering::Relaxed) {
            tracing::info!(stall_secs = EL_HUNT_STALL.as_secs(),
                "EL hunt engaged — serving pool empty past the stall window \
                 (bypassing transient backoffs for cache-confirmed snap servers)");
        }
        if live >= inner.pool_cfg.target_snap_peers {
            continue;
        }
        // Snapshot the cache (snap-quality-sorted) without holding its lock
        // across the dials.
        let cached = inner.cache.lock().await.peers();
        if cached.is_empty() {
            continue;
        }
        if hunting {
            // Emergency: free the TRANSIENT backoffs of CONFIRMED snap servers
            // so the dial loop below reaches them NOW instead of after the
            // standard cool-off. Confirmed = served us chain-verified snap
            // data. Entries whose remaining window exceeds the transient
            // length are INCOMPATIBLE (10 min) — keep those: try_dial's
            // blacklist check would block the dial anyway, but the timer
            // must stay honest too. Non-confirmed peers keep their timers.
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
        self.inner.record_quality(addr, true).await;
    }

    /// A snap fetch against `addr` failed (bad proof / transport / timeout).
    pub async fn failed(&self, addr: SocketAddr) {
        self.inner.record_quality(addr, false).await;
    }
}

#[cfg(test)]
mod tests {
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
        });
        let (_tx, rx) = mpsc::channel(4);
        let pool = PeerPool::start(
            Arc::clone(&key),
            key.public_key_bytes(),
            cfg,
            PoolConfig::default(),
            ElPeerCache::disabled(),
            rx,
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
        });
        let (_tx, rx) = mpsc::channel(4);
        let pool = PeerPool::start(
            Arc::clone(&key),
            key.public_key_bytes(),
            cfg,
            PoolConfig::default(),
            ElPeerCache::load(path.clone()),
            rx,
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
        });
        let (_tx, rx) = mpsc::channel(4);
        let pool = PeerPool::start(
            Arc::clone(&key),
            key.public_key_bytes(),
            cfg,
            PoolConfig::default(),
            ElPeerCache::load(path.clone()),
            rx,
            None,
        );

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


