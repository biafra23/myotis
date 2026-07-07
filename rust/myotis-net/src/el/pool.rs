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
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use myotis_core::nodekey::NodeKey;

use crate::el::discv4::TableEntry;
use crate::el::eth::session::{EthConfig, EthSession};
use crate::el::peer::ManagedPeer;
use crate::el::rlpx::transport::RlpxConnection;

/// Wrong-chain peers: don't retry the address for a long while (Java's
/// `BACKOFF_INCOMPATIBLE_MS`).
const BACKOFF_INCOMPATIBLE: Duration = Duration::from_secs(10 * 60);
/// Transient failures / not-snap peers: a short cool-off (Java's
/// `BACKOFF_TRANSIENT_MS`).
const BACKOFF_TRANSIENT: Duration = Duration::from_secs(30);

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
}

impl PoolInner {
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

    /// Record an address backoff. `long` selects the wrong-chain (10 min) vs the
    /// transient (30 s) window.
    async fn record_backoff(&self, addr: SocketAddr, long: bool, now: Instant) {
        let window = if long { BACKOFF_INCOMPATIBLE } else { BACKOFF_TRANSIENT };
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
        let result = async {
            let conn = RlpxConnection::dial(Arc::clone(&self.key), addr, pubkey).await?;
            EthSession::handshake(conn, &self.local_pubkey, &self.cfg).await
        }
        .await;

        let now = Instant::now();
        match result {
            Ok(session) if session.snap => {
                let peer = Arc::new(ManagedPeer::spawn(session));
                // Keep `addr` in `attempted` while connected — dropped by
                // prune_closed when the peer later closes.
                self.peers.lock().await.push(PooledPeer { addr, peer });
            }
            Ok(_) => {
                // Compatible but no snap/1 — useless for verified reads. Cool the
                // address off and free it from `attempted`.
                self.record_backoff(addr, false, now).await;
                self.attempted.lock().await.remove(&addr);
            }
            Err(e) => {
                // Only the network-id/genesis mismatch error starts with this
                // prefix (see EthSession::handshake). Match the PREFIX, not a
                // substring: a peer's client id is echoed into other error
                // strings, so `contains` could be steered by a hostile peer.
                let incompatible = e.starts_with("incompatible peer");
                if incompatible {
                    self.blacklist.lock().await.insert(pubkey);
                }
                self.record_backoff(addr, incompatible, now).await;
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
}

impl PeerPool {
    /// Start the pool, consuming the discv4 candidate stream `rx`. `local_pubkey`
    /// is our node id (64-byte); `cfg` is our eth handshake parameters.
    pub fn start(
        key: Arc<NodeKey>,
        local_pubkey: [u8; 64],
        cfg: Arc<EthConfig>,
        pool_cfg: PoolConfig,
        rx: mpsc::Receiver<TableEntry>,
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
        });
        let dialer_task = tokio::spawn(dialer_loop(Arc::clone(&inner), rx));
        PeerPool { inner, dialer_task }
    }

    /// A live snap-capable peer for a verified read, or `None` if the pool has
    /// none yet. Prunes closed peers first; returns the newest live peer (most
    /// likely to still retain recent state).
    pub async fn snap_peer(&self) -> Option<Arc<ManagedPeer>> {
        self.inner.prune_closed().await;
        self.inner.peers.lock().await.last().map(|p| Arc::clone(&p.peer))
    }

    /// Count of live snap peers (prunes closed peers first).
    pub async fn snap_peer_count(&self) -> usize {
        self.inner.prune_closed().await
    }

    /// Addresses dialed and not yet failed (in-flight or connected).
    pub async fn attempted_count(&self) -> usize {
        self.inner.attempted.lock().await.len()
    }

    /// Node ids blacklisted as wrong-chain this run.
    pub async fn blacklist_count(&self) -> usize {
        self.inner.blacklist.lock().await.len()
    }

    /// Stop the pool: abort the dialer and drop all held peers (closing them).
    pub async fn stop(self) {
        self.dialer_task.abort();
        self.inner.peers.lock().await.clear();
    }
}

impl Drop for PeerPool {
    fn drop(&mut self) {
        self.dialer_task.abort();
    }
}

/// Consume the candidate stream, dialing eligible peers under a concurrency cap.
async fn dialer_loop(inner: Arc<PoolInner>, mut rx: mpsc::Receiver<TableEntry>) {
    let dial_slots = Arc::new(Semaphore::new(inner.pool_cfg.max_concurrent_dials));

    while let Some(entry) = rx.recv().await {
        // Prune + read the live count in one `peers` lock.
        if inner.prune_closed().await >= inner.pool_cfg.target_snap_peers {
            continue;
        }
        let Some(addr) = to_socket_addr(&entry.ip, entry.tcp_port) else { continue };
        let Some(pubkey) = to_pubkey(&entry.node_id) else { continue };

        if inner.blacklist.lock().await.contains(&pubkey) {
            continue;
        }

        // Backoff: skip while cooling off; drop the entry once it has expired so
        // the map doesn't grow unbounded.
        {
            let mut backoff = inner.backoff.lock().await;
            if let Some(&expiry) = backoff.get(&addr) {
                if Instant::now() < expiry {
                    continue;
                }
                backoff.remove(&addr);
            }
        }

        // Claim the address (bounded), or skip if in-flight/connected already.
        {
            let mut attempted = inner.attempted.lock().await;
            if attempted.len() >= inner.pool_cfg.max_attempted || !attempted.insert(addr) {
                continue;
            }
        }

        // Bound concurrency: acquire a dial permit (waits when saturated), then
        // dial in a task that releases it when done.
        let Ok(permit) = Arc::clone(&dial_slots).acquire_owned().await else {
            // Semaphore closed — pool shutting down.
            inner.attempted.lock().await.remove(&addr);
            break;
        };
        let inner2 = Arc::clone(&inner);
        tokio::spawn(async move {
            inner2.dial_one(addr, pubkey).await;
            drop(permit);
        });
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
            rx,
        );
        assert_eq!(pool.snap_peer_count().await, 0);
        assert!(pool.snap_peer().await.is_none());
        assert_eq!(pool.attempted_count().await, 0);
        pool.stop().await;
    }
}
