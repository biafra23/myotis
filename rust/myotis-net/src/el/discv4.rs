//! discv4 — UDP Kademlia peer discovery (EL-A3), twin of the Java
//! `networking.discv4` package (docs/reimplementation/02 §2).
//!
//! Wire format:
//! ```text
//! packet    = hash(32) ‖ signature(65) ‖ packet-type(1) ‖ packet-data(RLP)
//! sigHash   = keccak256(packet-type ‖ packet-data)      — signed DIRECTLY, no re-hash
//! signature = r(32) ‖ s(32) ‖ v(1)                       — v = recovery id 0/1
//! hash      = keccak256(signature ‖ packet-type ‖ packet-data)
//! ```
//!
//! Client-only, like the Java reference: we ping / find-node and consume
//! Neighbors, we never answer FindNode and never send Neighbors (inbound
//! Pings get a Pong so bonds form). Two deliberate departures from the Java
//! twin since #539: we ping back a node that pings us while we hold no pong
//! from it, and we answer ENRRequest (EIP-868) from a node whose pong we hold,
//! under the same per-IP rate limit as Pings — both so the fork-id pre-filter
//! (`enrfilter.rs`) can read a node's ENR before the pool dials it. The packet
//! codec, Kademlia table, and rate limiter are pure (clock values are
//! parameters) and pinned by the `rust/testdata/el/discv4/` cross-language
//! corpus; only [`Discv4Service`] touches sockets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use myotis_core::keccak::{keccak256, keccak256_concat};
use myotis_core::nodekey::{recover_public_key, NodeKey};
use myotis_core::rlp::{self, Item};
use myotis_core::CoreError;

use crate::el::enrfilter::{decode_enr, local_enr_rlp, ForkFilter, Verdict};

pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_FIND_NODE: u8 = 0x03;
pub const TYPE_NEIGHBORS: u8 = 0x04;
/// EIP-868: ask a bonded node for its ENR; the reply echoes the request hash.
pub const TYPE_ENR_REQUEST: u8 = 0x05;
pub const TYPE_ENR_RESPONSE: u8 = 0x06;

/// Ping/Pong protocol version.
const VERSION: u64 = 4;

/// Expiry horizon for outgoing packets (seconds past `now`).
pub const EXPIRY_SECONDS: u64 = 20;

// ---------------------------------------------------------------------------
// Packet codec (pure — expiry is a parameter, entropy comes from the caller).
// ---------------------------------------------------------------------------

/// A parsed and signature-verified inbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The packet hash (echoed in Pong as the ping reference).
    pub hash: [u8; 32],
    pub packet_type: u8,
    /// The RLP packet-data (after the type byte).
    pub data: Vec<u8>,
    /// Recovered 64-byte sender public key (the enode id / RLPx dial key).
    pub sender_pubkey: [u8; 64],
}

/// Encode `Ping: [version, from, to, expiry]`. The `from` endpoint carries
/// our UDP port as the TCP port too (Java parity); `to.tcp` is 0.
pub fn encode_ping(
    key: &NodeKey,
    from_ip: &[u8],
    from_udp_port: u16,
    to_ip: &[u8],
    to_udp_port: u16,
    expiry: u64,
) -> Result<Vec<u8>, CoreError> {
    let mut payload = rlp::encode_u64(VERSION);
    payload.extend_from_slice(&encode_endpoint(from_ip, from_udp_port, from_udp_port));
    payload.extend_from_slice(&encode_endpoint(to_ip, to_udp_port, 0));
    payload.extend_from_slice(&rlp::encode_u64(expiry));
    encode_packet(key, TYPE_PING, &rlp::encode_list_payload(&payload))
}

/// Encode `Pong: [to, ping-hash, expiry]`.
pub fn encode_pong(
    key: &NodeKey,
    to_ip: &[u8],
    to_udp_port: u16,
    ping_hash: &[u8; 32],
    expiry: u64,
) -> Result<Vec<u8>, CoreError> {
    let mut payload = encode_endpoint(to_ip, to_udp_port, 0);
    payload.extend_from_slice(&rlp::encode_bytes(ping_hash));
    payload.extend_from_slice(&rlp::encode_u64(expiry));
    encode_packet(key, TYPE_PONG, &rlp::encode_list_payload(&payload))
}

/// Encode `FindNode: [target(64-byte pubkey), expiry]`.
pub fn encode_find_node(key: &NodeKey, target: &[u8], expiry: u64) -> Result<Vec<u8>, CoreError> {
    let mut payload = rlp::encode_bytes(target);
    payload.extend_from_slice(&rlp::encode_u64(expiry));
    encode_packet(key, TYPE_FIND_NODE, &rlp::encode_list_payload(&payload))
}

/// EIP-868 ENRRequest: `[expiration]`.
pub fn encode_enr_request(key: &NodeKey, expiry: u64) -> Result<Vec<u8>, CoreError> {
    let payload = rlp::encode_u64(expiry);
    encode_packet(key, TYPE_ENR_REQUEST, &rlp::encode_list_payload(&payload))
}

/// The expiration of an ENRRequest.
pub fn decode_enr_request_expiry(data: &[u8]) -> Result<u64, CoreError> {
    decode_lenient(data)?
        .as_list()?
        .first()
        .ok_or_else(|| CoreError("ENRRequest: missing expiration".into()))?
        .as_u64()
}

/// EIP-868 ENRResponse: `[request-hash, ENR]`, the ENR spliced in as the RLP
/// list it already is.
pub fn encode_enr_response(
    key: &NodeKey,
    request_hash: &[u8; 32],
    enr_rlp: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut payload = rlp::encode_bytes(request_hash);
    payload.extend_from_slice(enr_rlp);
    encode_packet(key, TYPE_ENR_RESPONSE, &rlp::encode_list_payload(&payload))
}

/// The request hash and the ENR (re-encoded from the parsed list — canonical
/// RLP, which is what an ENR signature covers) of an ENRResponse.
pub fn decode_enr_response(data: &[u8]) -> Result<([u8; 32], Vec<u8>), CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    let hash_item = items
        .first()
        .ok_or_else(|| CoreError("ENRResponse: missing request hash".into()))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hash_item.as_fixed_bytes(32)?);
    let enr = items
        .get(1)
        .filter(|e| e.is_list())
        .ok_or_else(|| CoreError("ENRResponse: missing ENR".into()))?;
    Ok((hash, rlp::encode(enr)))
}

/// Endpoint: `[ip(4|16), udpPort, tcpPort]`.
fn encode_endpoint(ip: &[u8], udp_port: u16, tcp_port: u16) -> Vec<u8> {
    let mut payload = rlp::encode_bytes(ip);
    payload.extend_from_slice(&rlp::encode_u64(u64::from(udp_port)));
    payload.extend_from_slice(&rlp::encode_u64(u64::from(tcp_port)));
    rlp::encode_list_payload(&payload)
}

fn encode_packet(key: &NodeKey, packet_type: u8, data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let sig_hash = keccak256_concat(&[packet_type], data);
    let sig = key.sign_hash(&sig_hash)?;
    // hash = keccak256(sig ‖ type ‖ data)
    let mut tail = Vec::with_capacity(65 + 1 + data.len());
    tail.extend_from_slice(&sig);
    tail.push(packet_type);
    tail.extend_from_slice(data);
    let hash = keccak256(&tail);
    let mut out = Vec::with_capacity(32 + tail.len());
    out.extend_from_slice(&hash);
    out.extend_from_slice(&tail);
    Ok(out)
}

/// Parse and verify an inbound packet: hash check, then sender recovery.
pub fn parse(packet: &[u8]) -> Result<Parsed, CoreError> {
    if packet.len() < 98 {
        return Err(CoreError(format!("Packet too short: {}", packet.len())));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&packet[..32]);
    if keccak256(&packet[32..]) != hash {
        return Err(CoreError("Packet hash mismatch".into()));
    }
    let mut sig = [0u8; 65];
    sig.copy_from_slice(&packet[32..97]);
    let msg_hash = keccak256(&packet[97..]); // type ‖ data
    let sender_pubkey = recover_public_key(&msg_hash, &sig)?;
    Ok(Parsed {
        hash,
        packet_type: packet[97],
        data: packet[98..].to_vec(),
        sender_pubkey,
    })
}

/// Decode one RLP value from a discv4 packet-data field, TOLERATING trailing
/// bytes (EIP-8: discovery packets may carry extra data after the RLP value,
/// and the Java twin's Tuweni `decodeList` never checks for completeness).
fn decode_lenient(data: &[u8]) -> Result<Item, CoreError> {
    let (item, _used) = rlp::decode_at(data, 0)?;
    Ok(item)
}

/// The `(udp, tcp)` ports from a Ping's self-reported FROM endpoint.
pub fn decode_ping_from_ports(data: &[u8]) -> Result<(u32, u32), CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    // [version, from, to, expiry] — from = [ip, udp, tcp].
    let from = items
        .get(1)
        .ok_or_else(|| CoreError("Ping: missing from endpoint".into()))?
        .as_list()?;
    if from.len() < 3 {
        return Err(CoreError("Ping: short from endpoint".into()));
    }
    Ok((read_u32(&from[1])?, read_u32(&from[2])?))
}

/// The echoed ping hash from a Pong: `[to, ping-hash, expiry]`.
pub fn decode_pong_ping_hash(data: &[u8]) -> Result<[u8; 32], CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    let hash_item = items
        .get(1)
        .ok_or_else(|| CoreError("Pong: missing ping hash".into()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(hash_item.as_fixed_bytes(32)?);
    Ok(out)
}

/// A node from a Neighbors packet: `[ip, udp, tcp, nodeId(64-byte pubkey)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// 4 (v4) or 16 (v6) bytes — anything else is skipped at decode.
    pub ip: Vec<u8>,
    pub udp_port: u16,
    /// Kept as the wire integer (Java parity: not range-checked).
    pub tcp_port: u32,
    /// The node's public key bytes as sent (64 expected, not enforced).
    pub node_id: Vec<u8>,
}

/// Decode `Neighbors: [[node, …], expiry]` with the Java decoder's exact
/// leniency: a structurally malformed node entry STOPS the walk (keeping
/// nodes decoded so far); a node with a bad ip length or an out-of-range
/// UDP port is SKIPPED individually.
pub fn decode_neighbors(data: &[u8]) -> Result<Vec<DiscoveredPeer>, CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    let nodes = items
        .first()
        .ok_or_else(|| CoreError("Neighbors: missing node list".into()))?
        .as_list()?;
    let mut peers = Vec::new();
    for node in nodes {
        let fields = match node.as_list() {
            Ok(f) if f.len() >= 4 => f,
            _ => break, // malformed entry → stop, keep what we have (Java parity)
        };
        let (Ok(ip), Ok(udp), Ok(tcp), Ok(node_id)) = (
            fields[0].as_bytes(),
            read_u32(&fields[1]),
            read_u32(&fields[2]),
            fields[3].as_bytes(),
        ) else {
            break; // field-level RLP type errors also stop the walk
        };
        // Java skips a node whose InetAddress/InetSocketAddress construction
        // throws: wrong ip length or udp port > 65535.
        if !(ip.len() == 4 || ip.len() == 16) || udp > 65535 {
            continue;
        }
        peers.push(DiscoveredPeer {
            ip: ip.to_vec(),
            udp_port: udp as u16,
            tcp_port: tcp,
            node_id: node_id.to_vec(),
        });
    }
    Ok(peers)
}

/// Canonical unsigned integer ≤ 4 bytes (Tuweni `readInt` shape).
fn read_u32(item: &Item) -> Result<u32, CoreError> {
    let v = item.as_u64()?;
    if v > u64::from(u32::MAX) {
        return Err(CoreError("integer exceeds 32 bits".into()));
    }
    Ok(v as u32)
}

// ---------------------------------------------------------------------------
// Kademlia table (pure — last-seen timestamps are caller-supplied millis).
// ---------------------------------------------------------------------------

const BUCKET_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableEntry {
    pub ip: Vec<u8>,
    pub udp_port: u16,
    pub tcp_port: u32,
    /// Node public key bytes as discovered (64-byte pubkey; 32-byte ids from
    /// crafted packets are hashed as-is, matching Java).
    pub node_id: Vec<u8>,
    pub last_seen_ms: u64,
}

/// 256 buckets (one per distance bit), K=16, XOR distance over
/// `keccak256(pubkey)` node IDs. Twin of the Java `KademliaTable`
/// (including its noted simplification: full buckets drop the oldest entry
/// instead of ping-before-evict).
pub struct KademliaTable {
    local_id: [u8; 32],
    buckets: Vec<Vec<TableEntry>>,
}

impl KademliaTable {
    pub fn new(local_id: [u8; 32]) -> KademliaTable {
        KademliaTable {
            local_id,
            buckets: vec![Vec::new(); 256],
        }
    }

    /// Add or refresh a peer (dedup by nodeId; oldest dropped when full).
    pub fn add(&mut self, entry: TableEntry) {
        let idx = self.bucket_index(&entry.node_id);
        let bucket = &mut self.buckets[idx];
        bucket.retain(|e| e.node_id != entry.node_id);
        if bucket.len() >= BUCKET_SIZE {
            bucket.remove(0);
        }
        bucket.push(entry);
    }

    /// Forget a node — the fork-id filter placed it on another chain (#539),
    /// and the pool's below-target walk reads this table.
    pub fn remove(&mut self, node_id: &[u8]) {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].retain(|e| e.node_id != node_id);
    }

    /// The entry under `node_id`, if the table holds one.
    pub fn get(&self, node_id: &[u8]) -> Option<&TableEntry> {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].iter().find(|e| e.node_id == node_id)
    }

    /// The k entries closest (XOR) to `target` (64-byte pubkey or 32-byte id).
    pub fn closest_peers(&self, target: &[u8], k: usize) -> Vec<TableEntry> {
        let target_id = to_node_id(target);
        let mut all: Vec<&TableEntry> = self.buckets.iter().flatten().collect();
        // Cached-key sort: to_node_id (a keccak over the 64-byte pubkey) runs
        // once per entry, not O(N log N) times inside the comparator.
        all.sort_by_cached_key(|e| xor_distance(&to_node_id(&e.node_id), &target_id));
        all.into_iter().take(k).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(Vec::is_empty)
    }

    pub fn all_peers(&self) -> Vec<TableEntry> {
        self.buckets.iter().flatten().cloned().collect()
    }

    fn bucket_index(&self, node_id: &[u8]) -> usize {
        let id = to_node_id(node_id);
        let lz = leading_zeros(&xor_distance(&self.local_id, &id));
        lz.min(255)
    }
}

fn to_node_id(key_or_id: &[u8]) -> [u8; 32] {
    if key_or_id.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(key_or_id);
        out
    } else {
        keccak256(key_or_id)
    }
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn leading_zeros(b: &[u8; 32]) -> usize {
    for (i, &byte) in b.iter().enumerate() {
        if byte != 0 {
            return i * 8 + byte.leading_zeros() as usize;
        }
    }
    256
}

// ---------------------------------------------------------------------------
// Per-IP ping rate limiter (pure — `now_ms` is a parameter).
// ---------------------------------------------------------------------------

const PING_RATE_LIMIT: usize = 5;
const PING_RATE_WINDOW_MS: u64 = 10_000;
/// Source IPs remembered at once. Beyond it, the rings no packet touched within
/// the window go — they count nothing, so nothing is lost — and if every ring is
/// live, all of them (fail open): a flood of spoofed sources, which costs the
/// flooder one address per packet, must not grow the map.
const RATE_LIMIT_IPS_MAX: usize = 4096;

/// Sliding-window ring of the last [`PING_RATE_LIMIT`] packet timestamps per
/// IP (twin of the Java handler's limiter), bounded by [`RATE_LIMIT_IPS_MAX`].
#[derive(Default)]
pub struct PingRateLimiter {
    rings: HashMap<IpAddr, [u64; PING_RATE_LIMIT]>,
}

impl PingRateLimiter {
    /// True when `addr` has exceeded the limit; records the packet otherwise.
    pub fn is_limited(&mut self, addr: IpAddr, now_ms: u64) -> bool {
        if self.rings.len() >= RATE_LIMIT_IPS_MAX && !self.rings.contains_key(&addr) {
            self.rings.retain(|_, ring| {
                ring.iter()
                    .any(|&t| now_ms.saturating_sub(t) < PING_RATE_WINDOW_MS)
            });
            if self.rings.len() >= RATE_LIMIT_IPS_MAX {
                self.rings.clear();
            }
        }
        let ring = self.rings.entry(addr).or_insert([0; PING_RATE_LIMIT]);
        let mut recent = 0usize;
        let mut oldest = 0usize;
        for (i, &t) in ring.iter().enumerate() {
            if now_ms.saturating_sub(t) < PING_RATE_WINDOW_MS {
                recent += 1;
            } else if t < ring[oldest] {
                oldest = i;
            }
        }
        if recent >= PING_RATE_LIMIT {
            return true;
        }
        ring[oldest] = now_ms;
        false
    }
}

// ---------------------------------------------------------------------------
// The tokio UDP service.
// ---------------------------------------------------------------------------

/// Configuration for [`Discv4Service::start`].
#[derive(Default)]
pub struct Discv4Config {
    /// UDP bind port (0 = ephemeral, for tests).
    pub bind_port: u16,
    /// Bootnode `ip:port` addresses (bare, no keys — discv4 pings them cold).
    pub bootnodes: Vec<SocketAddr>,
    /// EIP-2124 fork-id pre-filter (#539): a node whose ENR places it on
    /// another chain is never handed to the pool, and a node whose ENR is
    /// still unknown waits for it (at most [`ENR_TIMEOUT`]) before it is.
    /// `None` = every discovered node is handed over at once, as before.
    pub fork_filter: Option<ForkFilter>,
    /// The pool's "below target" flag, set each maintainer tick. While it is
    /// set, every discovered node is judged before it is handed over and the
    /// first refreshes ask three times as many table peers for neighbours
    /// ([`WIDE_REFRESHES_MAX`]). While the pool is at target — it dials
    /// nothing then — only nodes already bonding with us are judged (one
    /// request and response each); nodes learned second-hand from NEIGHBORS go
    /// over unjudged, as before, rather than be pinged for a verdict nobody
    /// needs yet. `None` = always judge (tests).
    pub pool_below_target: Option<Arc<AtomicBool>>,
}

/// How the fork-id filter (#539) judged the nodes it saw this run.
#[derive(Debug, Default)]
pub struct EnrCounts {
    /// Handed to the pool on a matching `eth` entry.
    pub compatible: AtomicU64,
    /// Kept from the pool: another chain's fork hash. Counted per skip, so a
    /// node re-learned from NEIGHBORS counts again.
    pub foreign: AtomicU64,
    /// Handed to the pool unjudged: no `eth` entry, or no ENR within the
    /// timeout.
    pub unjudged: AtomicU64,
}

impl EnrCounts {
    /// A plain snapshot `(compatible, foreign, unjudged)`.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.compatible.load(Ordering::Relaxed),
            self.foreign.load(Ordering::Relaxed),
            self.unjudged.load(Ordering::Relaxed),
        )
    }
}

/// Handle to a running discv4 service. Dropping it does NOT stop the task;
/// call [`Discv4Service::stop`].
pub struct Discv4Service {
    table: Arc<Mutex<KademliaTable>>,
    /// The fork-id filter's tallies (#539), for the hosts' logs and tests.
    enr_counts: Arc<EnrCounts>,
    local_port: u16,
    stop_tx: tokio::sync::watch::Sender<bool>,
    /// Probe requests into the service loop (see [`Discv4Service::probe_sender`]).
    probe_tx: tokio::sync::mpsc::Sender<SocketAddr>,
    /// Shared-borrow shutdown still owns and joins the service task exactly once.
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Discv4Service {
    /// Bind the socket and spawn the service loop. Discovered peers (from
    /// Pong bonds and Neighbors) are emitted on `events`.
    pub async fn start(
        key: Arc<NodeKey>,
        cfg: Discv4Config,
        events: tokio::sync::mpsc::Sender<TableEntry>,
    ) -> Result<Discv4Service, String> {
        let (socket, dual_stack) =
            bind_udp(cfg.bind_port).map_err(|e| format!("discv4 bind: {e}"))?;
        let local_port = socket
            .local_addr()
            .map_err(|e| format!("discv4 local_addr: {e}"))?
            .port();
        let table = Arc::new(Mutex::new(KademliaTable::new(key.node_id())));
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (probe_tx, probe_rx) = tokio::sync::mpsc::channel(64);
        let enr_counts = Arc::new(EnrCounts::default());
        let enr = match cfg.fork_filter {
            Some(filter) => Some(EnrExchange::new(&key, filter, Arc::clone(&enr_counts))?),
            None => None,
        };
        let loop_state = ServiceLoop {
            key,
            socket,
            dual_stack,
            local_port,
            bootnodes: cfg.bootnodes,
            table: Arc::clone(&table),
            events,
            pending_pings: HashMap::new(),
            limiter: PingRateLimiter::default(),
            enr_limiter: PingRateLimiter::default(),
            probe_rx,
            probed: HashMap::new(),
            enr,
            pool_below_target: cfg.pool_below_target,
            wide: WideState::default(),
        };
        let task = tokio::spawn(loop_state.run(stop_rx));
        Ok(Discv4Service {
            table,
            enr_counts,
            local_port,
            stop_tx,
            probe_tx,
            task: tokio::sync::Mutex::new(Some(task)),
        })
    }

    /// A clonable sender for probe requests: bond with a specific UDP endpoint
    /// (the UDP-port guess for a peer PROVEN over TCP) so its neighbourhood
    /// enters the walk — the refresh loop only FindNodes peers already in the
    /// table, so a cache-/DNS-sourced peer's neighbours are otherwise never
    /// asked for. Sends are best-effort (`try_send`; a full queue drops the
    /// probe — it's a nudge, not bookkeeping).
    pub fn probe_sender(&self) -> tokio::sync::mpsc::Sender<SocketAddr> {
        self.probe_tx.clone()
    }

    /// The routing table itself, shared with the EL pool's below-target
    /// re-dial (#539), which walks it for peers to re-offer.
    pub fn table_handle(&self) -> Arc<Mutex<KademliaTable>> {
        Arc::clone(&self.table)
    }

    /// Sightings of nodes the fork-id filter placed on another chain and kept
    /// from the pool, this run (#539): a node re-learned from NEIGHBORS counts
    /// again. The five-minute summary's `known_foreign` is the node count.
    pub fn foreign_skipped(&self) -> u64 {
        self.enr_counts.foreign.load(Ordering::Relaxed)
    }

    /// Every verdict the fork-id filter reached this run (#539).
    pub fn enr_counts(&self) -> &EnrCounts {
        &self.enr_counts
    }

    pub fn table_size(&self) -> usize {
        self.table.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// The k closest known peers to a target (for the dial manager, EL-A7).
    pub fn closest_peers(&self, target: &[u8], k: usize) -> Vec<TableEntry> {
        self.table
            .lock()
            .map(|t| t.closest_peers(target, k))
            .unwrap_or_default()
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub async fn stop(&self) {
        let _ = self.stop_tx.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Discv4Service {
    fn drop(&mut self) {
        // Signal the loop to exit even if the owner forgot to `stop().await`
        // (EL-A4's restart flows drop-and-recreate). The task detaches; the
        // socket closes when it winds down.
        let _ = self.stop_tx.send(true);
    }
}

/// discv4 NEIGHBORS packets run to the 1280-byte spec cap; a fixed 4096-byte
/// read buffer keeps any allocator from truncating them, and a 1 MiB
/// SO_RCVBUF absorbs reply bursts (docs/reimplementation/02 §2.3 — the
/// Android/ART truncation trap).
const RECV_BUF: usize = 4096;

/// Bind the UDP socket. Returns `(socket, dual_stack)` — `dual_stack` is true
/// for a v6 socket with `IPV6_V6ONLY` off, which reaches IPv4 peers via the
/// v4-mapped form (so outgoing v4 targets must be mapped, see [`send_addr`]).
/// Java's Netty `NioDatagramChannel` is dual-stack by default; falling back to
/// a v4-only socket keeps the common (v4 bootnodes) path working everywhere.
fn bind_udp(port: u16) -> std::io::Result<(tokio::net::UdpSocket, bool)> {
    let bind_v6 = || -> std::io::Result<tokio::net::UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(false)?;
        set_recv_buffer_best_effort(&socket);
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
        tokio::net::UdpSocket::from_std(socket.into())
    };
    match bind_v6() {
        Ok(s) => Ok((s, true)),
        Err(_) => {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            set_recv_buffer_best_effort(&socket);
            socket.set_nonblocking(true)?;
            socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            Ok((tokio::net::UdpSocket::from_std(socket.into())?, false))
        }
    }
}

/// Enlarge SO_RCVBUF to 1 MiB, but don't fail the bind if the platform
/// refuses (strict `net.core.rmem_max`, containers): the fixed 4096-byte read
/// buffer already prevents NEIGHBORS truncation; the larger kernel buffer only
/// absorbs reply bursts, so the default is a fine fallback.
fn set_recv_buffer_best_effort(socket: &socket2::Socket) {
    if let Err(e) = socket.set_recv_buffer_size(1 << 20) {
        tracing::debug!("discv4 SO_RCVBUF 1 MiB not granted, using default: {e}");
    }
}

struct ServiceLoop {
    key: Arc<NodeKey>,
    socket: tokio::net::UdpSocket,
    /// True when `socket` is a dual-stack v6 socket (outgoing v4 targets need
    /// the v4-mapped form).
    dual_stack: bool,
    local_port: u16,
    bootnodes: Vec<SocketAddr>,
    table: Arc<Mutex<KademliaTable>>,
    events: tokio::sync::mpsc::Sender<TableEntry>,
    /// ping target → the bond in flight: the expected echo hash and when it
    /// was sent. An entry older than [`PING_PENDING_TTL`] is stale — the pong
    /// is not coming — and is pinged over, not waited on; the sweep prunes
    /// them and the map is capped ([`PING_PENDING_MAX`]).
    pending_pings: HashMap<SocketAddr, PendingPing>,
    limiter: PingRateLimiter,
    /// The same limit on the ENRRequests we answer: each answer is a signature
    /// and a reflected record, so a bonded node gets a Ping's budget, not line
    /// rate for its bond's hour.
    enr_limiter: PingRateLimiter,
    /// Probe requests from the pool (proven-peer UDP endpoints to bond with).
    probe_rx: tokio::sync::mpsc::Receiver<SocketAddr>,
    /// Endpoint → last probe instant (1 h per-endpoint dedup, bounded).
    probed: HashMap<SocketAddr, tokio::time::Instant>,
    /// The EIP-868 exchange behind the fork-id filter (#539); `None` = no
    /// filter, every node is handed to the pool at once.
    enr: Option<EnrExchange>,
    /// The pool's below-target hint (see `Discv4Config::pool_below_target`).
    pool_below_target: Option<Arc<AtomicBool>>,
    /// The wide fan-out's per-episode budget.
    wide: WideState,
}

/// A ping awaiting its pong.
struct PendingPing {
    hash: [u8; 32],
    since: tokio::time::Instant,
}

/// How long a ping's pong is waited for before the entry is stale: the
/// packet's own expiry horizon.
const PING_PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(EXPIRY_SECONDS);
/// Pings in flight at most; beyond it the stale entries go, then all of them.
const PING_PENDING_MAX: usize = 4096;

/// Refreshes per below-target episode that get the wide fan-out: a chain whose
/// target is unreachable (gnosis, PR #553's note) would otherwise keep three
/// times the FindNode traffic — and three times the ENR exchanges the replies
/// start — for the life of the process. Eight refreshes are two minutes.
pub const WIDE_REFRESHES_MAX: u8 = 8;
/// A new episode's budget is granted at most this often: a pool flapping
/// around its target every few minutes must not re-earn two wide minutes per
/// dip.
pub const WIDE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// The wide fan-out's state: a budget granted when the pool drops below
/// target — once per [`WIDE_COOLDOWN`] — and spent one refresh at a time.
#[derive(Debug, Default)]
struct WideState {
    was_below: bool,
    budget: u8,
    last_grant: Option<tokio::time::Instant>,
}

/// Pure: table peers to ask for neighbours this refresh, given the pool's
/// below-target flag (`None` = no pool hint: the narrow fan-out).
fn fan_out(state: &mut WideState, below_target: Option<bool>, now: tokio::time::Instant) -> usize {
    let below = below_target.unwrap_or(false);
    if below && !state.was_below {
        let cooled = state
            .last_grant
            .is_none_or(|t| now.duration_since(t) >= WIDE_COOLDOWN);
        if cooled {
            state.budget = WIDE_REFRESHES_MAX;
            state.last_grant = Some(now);
        }
    }
    state.was_below = below;
    if below && state.budget > 0 {
        state.budget -= 1;
        REFRESH_SAMPLE_WIDE
    } else {
        REFRESH_SAMPLE
    }
}

/// How long a node may stay unjudged before it is handed to the pool anyway:
/// a node that never answers an ENRRequest (an old client, a lost datagram)
/// costs this much delay once and is then dialed as before — the filter fails
/// open.
pub const ENR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// ENRRequests per pending node: one when its pong arrives, one more when its
/// ping does (whichever of the two the remote counts as our bond).
const ENR_REQUESTS_MAX: u8 = 2;
/// Nodes awaiting an ENR at once; beyond it a node is handed over unjudged.
/// A wide refresh can surface up to 30 × 16 neighbours in one tick.
const ENR_PENDING_MAX: usize = 1024;
/// Remembered verdicts (by node id); cleared wholesale when full.
const ENR_VERDICTS_MAX: usize = 4096;
/// How long an `Unknown` verdict stands before the node is judged again. A
/// lost datagram, a response a shade past the timeout or an old client must
/// not mean blind dials for the rest of the run — only until the next sighting
/// after this; `Compatible` and `Foreign` stand for the run.
const UNKNOWN_VERDICT_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// How long a verified pong counts as a bond for answering ENRRequests, and
/// the cap on remembered bonds.
const BOND_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
const BONDED_MAX: usize = 4096;
/// How often the exchange says how many foreign nodes it kept from the pool.
const FILTER_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// Table peers asked for neighbours per refresh, and the wider fan-out while
/// the pool is below target.
const REFRESH_SAMPLE: usize = 10;
const REFRESH_SAMPLE_WIDE: usize = 30;

/// A verified pong: who signed it, and when.
struct Bond {
    pubkey: [u8; 64],
    since: tokio::time::Instant,
}

/// A discovered node waiting for its ENR before it is handed to the pool.
struct PendingEnr {
    entry: TableEntry,
    /// Hashes of the ENRRequests sent, newest last (at most ENR_REQUESTS_MAX).
    hashes: Vec<[u8; 32]>,
    since: tokio::time::Instant,
    /// `entry.tcp_port` is the node's own claim (a Ping's FROM endpoint), not
    /// a relayer's hearsay or a guess: hearsay arriving while the record is
    /// awaited must not displace it, and it is pinned if the record names no
    /// address.
    claimed: bool,
}

/// What the exchange concluded about a node, kept by node id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Judgement {
    verdict: Verdict,
    /// The TCP port by the node's own word: its record's (`0`: an address but
    /// no TCP port — never dialed), updated by a later Ping's FROM endpoint,
    /// which the node signed too and is fresher; `None` when the record named
    /// no address or never came. It outlives the sighting: a relayer's hearsay
    /// must not put a discovery-only node back on the dial list, or a known
    /// port back to a guess — only the node itself moves its port here.
    tcp_port: Option<u32>,
    at: tokio::time::Instant,
}

impl Judgement {
    /// An `Unknown` that holds no record — a lost datagram, a response a shade
    /// past the timeout — no longer stands past [`UNKNOWN_VERDICT_TTL`]; one
    /// with a record in hand (an address but no `eth` entry: the EF NodeOps
    /// bootnodes) stands for the run, as every verdict with a record does, so
    /// the port it pinned is never forgotten with it.
    fn expired(&self, now: tokio::time::Instant) -> bool {
        self.verdict == Verdict::Unknown
            && self.tcp_port.is_none()
            && now.duration_since(self.at) >= UNKNOWN_VERDICT_TTL
    }
}

/// What `consider` finds on file for a sighted node.
enum Seen {
    Foreign,
    /// Judged, with the port its record named (if any): handed over as is.
    Judged(Option<u32>),
    /// An expired `Unknown`: judged again.
    Stale,
    New,
}

/// The EIP-868 ENR exchange that feeds the fork-id filter (#539).
struct EnrExchange {
    filter: ForkFilter,
    /// Our own record, as RLP, and the fork id it carries.
    local: Vec<u8>,
    local_seq: u64,
    local_eth: Vec<u8>,
    pending: HashMap<SocketAddr, PendingEnr>,
    /// node id → what the exchange concluded about it (bounded).
    verdicts: HashMap<Vec<u8>, Judgement>,
    /// Endpoints whose pong we verified — with the key that signed it and
    /// when: the bond that lets THAT node ask for our ENR. Keyed by address
    /// and checked against the signer, as geth's `checkBond(id, ip)`: a bond
    /// by address alone would let a spoofed source borrow a bootnode's.
    bonded: HashMap<SocketAddr, Bond>,
    counts: Arc<EnrCounts>,
    logged_skipped: u64,
    last_log: tokio::time::Instant,
}

impl EnrExchange {
    fn new(
        key: &NodeKey,
        filter: ForkFilter,
        counts: Arc<EnrCounts>,
    ) -> Result<EnrExchange, String> {
        let local_eth = filter.local_eth_entry(now_secs());
        let local = local_enr_rlp(key, 1, &local_eth)?;
        Ok(EnrExchange {
            filter,
            local,
            local_seq: 1,
            local_eth,
            pending: HashMap::new(),
            verdicts: HashMap::new(),
            bonded: HashMap::new(),
            counts,
            logged_skipped: 0,
            last_log: tokio::time::Instant::now(),
        })
    }

    /// Re-sign our record when the fork schedule moved its `eth` entry.
    fn refresh_local(&mut self, key: &NodeKey) {
        let eth = self.filter.local_eth_entry(now_secs());
        if eth == self.local_eth {
            return;
        }
        match local_enr_rlp(key, self.local_seq + 1, &eth) {
            Ok(local) => {
                self.local = local;
                self.local_seq += 1;
                self.local_eth = eth;
                tracing::info!(
                    seq = self.local_seq,
                    "discv4: our ENR follows the fork schedule"
                );
            }
            Err(e) => tracing::debug!("discv4: could not re-sign our ENR: {e}"),
        }
    }

    /// Whether `signer` at `addr` holds a fresh bond with us: its pong, signed
    /// by that key, arrived within [`BOND_TTL`].
    fn is_bonded(&self, addr: SocketAddr, signer: &[u8; 64], now: tokio::time::Instant) -> bool {
        self.bonded
            .get(&addr)
            .is_some_and(|b| b.pubkey == *signer && now.duration_since(b.since) < BOND_TTL)
    }

    fn mark_bonded(&mut self, addr: SocketAddr, pubkey: [u8; 64], now: tokio::time::Instant) {
        if self.bonded.len() >= BONDED_MAX {
            self.bonded
                .retain(|_, b| now.duration_since(b.since) < BOND_TTL);
            if self.bonded.len() >= BONDED_MAX {
                self.bonded.clear();
            }
        }
        self.bonded.insert(addr, Bond { pubkey, since: now });
    }

    fn record(
        &mut self,
        node_id: Vec<u8>,
        verdict: Verdict,
        tcp_port: Option<u32>,
        now: tokio::time::Instant,
    ) {
        if self.verdicts.len() >= ENR_VERDICTS_MAX {
            self.verdicts.clear();
        }
        self.verdicts.insert(
            node_id,
            Judgement {
                verdict,
                tcp_port,
                at: now,
            },
        );
    }

    fn skip_foreign(&self) {
        self.counts.foreign.fetch_add(1, Ordering::Relaxed);
    }

    /// The periodic summary line, when there is something new to say.
    fn maybe_log(&mut self, now: tokio::time::Instant) {
        if now.duration_since(self.last_log) < FILTER_LOG_INTERVAL {
            return;
        }
        let (compatible, total, unjudged) = self.counts.snapshot();
        if total > self.logged_skipped {
            let known_foreign = self
                .verdicts
                .values()
                .filter(|j| j.verdict == Verdict::Foreign)
                .count();
            tracing::info!(
                skipped = total - self.logged_skipped,
                total,
                known_foreign,
                compatible,
                unjudged,
                "discv4: nodes on other chains kept from the pool before any dial (ENR fork id)"
            );
            self.logged_skipped = total;
        }
        self.last_log = now;
    }
}

impl ServiceLoop {
    async fn run(mut self, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
        tracing::info!(port = self.local_port, "discv4 listening");
        // Bootstrap: ping all bootnodes; then refresh every 15 s (first at 10 s).
        let now = tokio::time::Instant::now();
        for bootnode in self.bootnodes.clone() {
            if !self.fresh_ping_pending(bootnode, now) {
                self.send_ping(bootnode).await;
            }
        }
        let mut refresh = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(15),
        );
        // After a stall/sleep, catch up with ONE tick, not a burst of them —
        // otherwise we'd flood peers with a storm of FindNodes on wakeup.
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The ENR exchange's timeout sweep (a no-op without a filter).
        let mut sweep = tokio::time::interval(std::time::Duration::from_secs(1));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    tracing::info!("discv4 stopped");
                    return;
                }
                _ = refresh.tick() => self.refresh().await,
                _ = sweep.tick() => self.sweep_enr().await,
                // `Some(addr) =` disables this branch once all senders drop
                // (recv() → None fails the pattern) — no busy-loop at shutdown.
                Some(addr) = self.probe_rx.recv() => self.probe(addr).await,
                recv = self.socket.recv_from(&mut buf) => {
                    let (n, sender) = match recv {
                        Ok(v) => v,
                        Err(e) => {
                            // ICMP port-unreachable surfaces here on some
                            // stacks (Windows WSAECONNRESET). Log and continue;
                            // the next recv proceeds normally.
                            tracing::debug!("discv4 recv error: {e}");
                            continue;
                        }
                    };
                    // Un-map v4-mapped v6 senders back to canonical v4 so the
                    // pending-ping key and the recorded IP bytes match what we
                    // sent to and what peers advertise.
                    let sender = canonical_addr(sender);
                    match parse(&buf[..n]) {
                        Ok(parsed) => self.handle(parsed, sender).await,
                        Err(e) => tracing::debug!(bytes = n, %sender, "discv4 unparseable: {}", e.0),
                    }
                }
            }
        }
    }

    async fn handle(&mut self, p: Parsed, sender: SocketAddr) {
        match p.packet_type {
            TYPE_PING => self.handle_ping(p, sender).await,
            TYPE_PONG => self.handle_pong(p, sender).await,
            TYPE_NEIGHBORS => self.handle_neighbors(p, sender).await,
            TYPE_ENR_REQUEST => self.handle_enr_request(p, sender).await,
            TYPE_ENR_RESPONSE => self.handle_enr_response(p, sender).await,
            // FindNode inbound: deliberately unanswered (client-only stack).
            other => tracing::trace!(?other, %sender, "discv4 ignoring packet type"),
        }
    }

    async fn handle_ping(&mut self, p: Parsed, sender: SocketAddr) {
        if self.limiter.is_limited(sender.ip(), now_ms()) {
            tracing::debug!(%sender, "discv4 rate-limited ping");
            return;
        }
        // Respond with Pong (echoing the ping's packet hash) so bonds form.
        if let Ok(pong) = encode_pong(
            &self.key,
            &ip_bytes(sender.ip()),
            sender.port(),
            &p.hash,
            expiry_now(),
        ) {
            let _ = self.send_to(&pong, sender).await;
        }
        // The sender's advertised TCP port rides the Ping's FROM endpoint.
        // Java's Tuweni readInt is SIGNED: a 4-byte port with the high bit set
        // reads negative there and fails its `> 0` check, falling back to the
        // UDP port — mirror that by accepting only 1..=i32::MAX; otherwise the
        // packet claims no port and `admit` falls back the same way.
        let tcp_port = match decode_ping_from_ports(&p.data) {
            Ok((_, tcp)) if (1..=i32::MAX as u32).contains(&tcp) => Some(tcp),
            _ => None,
        };
        // Bond back when we have not (geth does): a node answers an
        // ENRRequest only from a node whose pong it holds — and so do we — so
        // the exchange needs the bond in both directions.
        let now = tokio::time::Instant::now();
        let bond_back = self
            .enr
            .as_ref()
            .is_some_and(|e| !e.is_bonded(sender, &p.sender_pubkey, now))
            && !self.fresh_ping_pending(sender, now);
        if bond_back {
            self.send_ping(sender).await;
        }
        // Its ping is in hand, so our pong is on its way: an ENRRequest now
        // meets a node that counts us as bonded.
        self.admit(sender, tcp_port, p.sender_pubkey.to_vec(), true)
            .await;
    }

    async fn handle_pong(&mut self, p: Parsed, sender: SocketAddr) {
        let Ok(ping_hash) = decode_pong_ping_hash(&p.data) else {
            return;
        };
        // Compare before removing: a pong for a ping this entry no longer
        // records (a refresh or probe ping overwrote it) must not discard the
        // bond in flight for the newer one.
        let verified = self
            .pending_pings
            .get(&sender)
            .is_some_and(|p| p.hash == ping_hash);
        match verified
            .then(|| self.pending_pings.remove(&sender))
            .flatten()
        {
            Some(_) => {
                tracing::debug!(%sender, "discv4 pong verified");
                // NOTE (Java parity): no FindNode here — go-ethereum requires
                // OUR pong to the bootnode's return Ping before it answers
                // FindNode; the refresh loop issues FindNodes later.
                if let Some(enr) = self.enr.as_mut() {
                    enr.mark_bonded(sender, p.sender_pubkey, tokio::time::Instant::now());
                }
                // A pong carries no TCP port: `admit` uses the one on file.
                self.admit(sender, None, p.sender_pubkey.to_vec(), true)
                    .await;
            }
            _ => tracing::debug!(%sender, "discv4 unsolicited/mismatched pong"),
        }
    }

    async fn handle_neighbors(&mut self, p: Parsed, sender: SocketAddr) {
        let Ok(peers) = decode_neighbors(&p.data) else {
            return;
        };
        tracing::debug!(count = peers.len(), %sender, "discv4 neighbors");
        for peer in peers {
            let Some(addr) = to_socket_addr(&peer.ip, peer.udp_port) else {
                continue;
            };
            let entry = TableEntry {
                ip: peer.ip,
                udp_port: addr.port(),
                tcp_port: peer.tcp_port,
                node_id: peer.node_id,
                last_seen_ms: now_ms(),
            };
            // Learned second-hand: no bond yet, so the exchange pings first.
            self.consider(entry, false, None).await;
        }
    }

    /// Table-add + discovered-peer event for a directly-bonded sender.
    /// `tcp_port`: the port the packet itself claims (a Ping's FROM endpoint),
    /// or `None` when it claims nothing (a Pong): then the port on file for the
    /// node — its NEIGHBORS entry's or its record's — and the UDP port only as
    /// the last resort (Java parity). Before #539 a Pong's guess was one more
    /// event beside the advertised one; with the exchange the pool sees one
    /// entry per node, so a guess would replace the advertised port for good.
    /// `bonded`: the remote holds our pong (see `consider`).
    async fn admit(
        &mut self,
        sender: SocketAddr,
        tcp_port: Option<u32>,
        node_id: Vec<u8>,
        bonded: bool,
    ) {
        let claim = tcp_port;
        let tcp_port = tcp_port
            .or_else(|| self.known_tcp_port(sender, &node_id))
            .unwrap_or_else(|| u32::from(sender.port()));
        let entry = TableEntry {
            ip: ip_bytes(sender.ip()),
            udp_port: sender.port(),
            tcp_port,
            node_id,
            last_seen_ms: now_ms(),
        };
        self.consider(entry, bonded, claim).await;
    }

    /// The TCP port on file for the node at `addr`: its pending entry's (a
    /// NEIGHBORS port or its own Ping's), else its routing-table entry's.
    fn known_tcp_port(&self, addr: SocketAddr, node_id: &[u8]) -> Option<u32> {
        if let Some(p) = self.enr.as_ref().and_then(|e| e.pending.get(&addr)) {
            return Some(p.entry.tcp_port);
        }
        self.table
            .lock()
            .ok()
            .and_then(|t| t.get(node_id).map(|e| e.tcp_port))
    }

    /// Hand a discovered node to the pool — at once without a filter or with a
    /// verdict in hand; otherwise after its ENR (or [`ENR_TIMEOUT`]).
    /// `bonded`: the remote has our pong (its ping or pong just arrived), so an
    /// ENRRequest goes out now; else we ping first and ask when it answers.
    /// `claim`: the TCP port the packet itself claimed — a Ping's FROM
    /// endpoint, the node's own signed word — or `None` for a Pong (claims
    /// nothing) or a NEIGHBORS entry (a relayer's hearsay).
    async fn consider(&mut self, entry: TableEntry, bonded: bool, claim: Option<u32>) {
        let Some(enr) = self.enr.as_mut() else {
            return self.emit(entry).await;
        };
        let now = tokio::time::Instant::now();
        let seen = match enr.verdicts.get(&entry.node_id) {
            Some(j) if j.verdict == Verdict::Foreign => Seen::Foreign,
            Some(j) if j.expired(now) => Seen::Stale,
            Some(j) => Seen::Judged(j.tcp_port),
            None => Seen::New,
        };
        match seen {
            Seen::Foreign => {
                enr.skip_foreign();
                // It may have entered the table unjudged earlier (see the gate
                // below); the pool's below-target walk reads the table.
                return self.forget(&entry.node_id);
            }
            Seen::Judged(record_port) => {
                // The node's own word on its port outlives the sighting (see
                // `Judgement::tcp_port`): a relayer's hearsay yields to it, a
                // Ping's own claim — fresher, and signed by the node — updates
                // it, so a node that moved its port is followed and a relayer
                // cannot move it.
                let mut entry = entry;
                match claim {
                    Some(port) => {
                        if let Some(j) = enr.verdicts.get_mut(&entry.node_id) {
                            j.tcp_port = Some(port);
                        }
                    }
                    None => {
                        if let Some(port) = record_port {
                            entry.tcp_port = port;
                        }
                    }
                }
                return self.emit(entry).await;
            }
            Seen::Stale => {
                enr.verdicts.remove(&entry.node_id); // judged again below
            }
            Seen::New => {}
        }
        // At target the pool dials nothing. A node already bonding with us is
        // judged anyway — one request and one response — but a node learned
        // second-hand from NEIGHBORS is not pinged for a verdict nobody needs
        // yet: it goes over as before, and is judged when it is next seen
        // while the pool wants candidates.
        let pool_wants = self
            .pool_below_target
            .as_ref()
            .is_none_or(|f| f.load(Ordering::Relaxed));
        if !pool_wants && !bonded {
            return self.emit(entry).await;
        }
        let Some(addr) = to_socket_addr(&entry.ip, entry.udp_port) else {
            return;
        };
        let ask = match enr.pending.get_mut(&addr) {
            Some(p) => {
                // The newest sighting, with the port by precedence: the node's
                // own claim (a Ping's FROM endpoint) stands over any later
                // hearsay — a relayer's NEIGHBORS inside the judging window
                // must not displace it — while hearsay may replace a port that
                // was itself hearsay or a guess.
                let port = match claim {
                    Some(port) => {
                        p.claimed = true;
                        port
                    }
                    None if p.claimed => p.entry.tcp_port,
                    None => entry.tcp_port,
                };
                p.entry = entry;
                p.entry.tcp_port = port;
                bonded && p.hashes.len() < usize::from(ENR_REQUESTS_MAX)
            }
            None => {
                if enr.pending.len() >= ENR_PENDING_MAX {
                    // Fail open under load: the pool's Status check still rules.
                    enr.counts.unjudged.fetch_add(1, Ordering::Relaxed);
                    return self.emit(entry).await;
                }
                enr.pending.insert(
                    addr,
                    PendingEnr {
                        entry,
                        hashes: Vec::new(),
                        since: tokio::time::Instant::now(),
                        claimed: claim.is_some(),
                    },
                );
                if !bonded && !self.fresh_ping_pending(addr, tokio::time::Instant::now()) {
                    self.send_ping(addr).await;
                }
                bonded
            }
        };
        if ask {
            self.send_enr_request(addr).await;
        }
    }

    async fn send_enr_request(&mut self, to: SocketAddr) {
        let Ok(packet) = encode_enr_request(&self.key, expiry_now()) else {
            return;
        };
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&packet[..32]);
        if let Some(p) = self.enr.as_mut().and_then(|e| e.pending.get_mut(&to)) {
            if p.hashes.len() >= usize::from(ENR_REQUESTS_MAX) {
                p.hashes.remove(0);
            }
            p.hashes.push(hash);
        }
        let _ = self.send_to(&packet, to).await;
    }

    /// Answer with our record, to a node whose pong we hold — without the bond
    /// check we would amplify a spoofed source's traffic (geth `checkBond`) —
    /// and no more often than we answer its Pings.
    async fn handle_enr_request(&mut self, p: Parsed, sender: SocketAddr) {
        // Expired requests are ignored (geth `errExpired`): a captured one must
        // not be replayable for the bond's whole hour.
        match decode_enr_request_expiry(&p.data) {
            Ok(expiry) if expiry >= now_secs() => {}
            _ => return,
        }
        let now = tokio::time::Instant::now();
        let Some(local) = self
            .enr
            .as_ref()
            .filter(|e| e.is_bonded(sender, &p.sender_pubkey, now))
            .map(|e| e.local.clone())
        else {
            tracing::trace!(%sender, "discv4 ENRRequest from an unbonded node, ignored");
            return;
        };
        // Each answer is a signature and a reflected record: a bonded node gets
        // the Ping budget (5 per 10 s per IP), not line rate for its bond's
        // hour. After the bond check, so unbonded noise from an address cannot
        // spend the budget of the node bonded there.
        if self.enr_limiter.is_limited(sender.ip(), now_ms()) {
            tracing::debug!(%sender, "discv4 rate-limited ENRRequest");
            return;
        }
        if let Ok(packet) = encode_enr_response(&self.key, &p.hash, &local) {
            let _ = self.send_to(&packet, sender).await;
        }
    }

    async fn handle_enr_response(&mut self, p: Parsed, sender: SocketAddr) {
        let Some(enr) = self.enr.as_mut() else {
            return;
        };
        // Is anyone waiting on this sender at all? Before any parsing, so an
        // unsolicited packet costs nothing more than the signature check.
        let Some(pending) = enr.pending.get(&sender) else {
            tracing::trace!(%sender, "discv4 unsolicited ENRResponse");
            return;
        };
        let Ok((request_hash, raw)) = decode_enr_response(&p.data) else {
            return;
        };
        if !pending.hashes.contains(&request_hash) {
            tracing::trace!(%sender, "discv4 ENRResponse to an unknown request");
            return;
        }
        let remote = match decode_enr(&raw, &p.sender_pubkey) {
            Ok(r) => r,
            Err(e) => {
                // Not ours to judge: the node stays pending and times out into
                // the pool unjudged.
                tracing::debug!(%sender, "discv4 ENRResponse not usable: {e}");
                return;
            }
        };
        let Some(mut pending) = enr.pending.remove(&sender) else {
            return;
        };
        // The record's identity is the packet's signer (decode_enr). A
        // NEIGHBORS entry may have carried a stale key for this address: the
        // signer is the node that is actually there, so the verdict is recorded
        // under it and the pool dials it by it.
        if pending.entry.node_id != p.sender_pubkey {
            tracing::debug!(%sender, "discv4: ENR signer differs from the advertised node id; using the signer");
            pending.entry.node_id = p.sender_pubkey.to_vec();
        }
        // The record is the node's own word on where it listens: it beats the
        // NEIGHBORS entry's hearsay and any port `admit` fell back to. An
        // address without a TCP port is a discovery-only node (the EF NodeOps
        // bootnodes): it stays in the table as a source of neighbours and is
        // never dialed — the pool refuses port 0, as geth refuses such a node
        // (`errNoPort`). A record naming no address says nothing.
        let record_port = match remote.tcp_port_for(&pending.entry.ip) {
            Some(tcp) => Some(u32::from(tcp)),
            None if remote.has_ip => Some(0),
            None => None,
        };
        if let Some(port) = record_port {
            pending.entry.tcp_port = port;
        }
        // What the judgement pins: the record's word; else the node's own
        // Ping claim, when the record named no address; never hearsay.
        let pin = record_port.or_else(|| pending.claimed.then_some(pending.entry.tcp_port));
        let verdict = enr.filter.verdict(remote.eth.as_deref(), now_secs());
        enr.record(
            pending.entry.node_id.clone(),
            verdict,
            pin,
            tokio::time::Instant::now(),
        );
        match verdict {
            Verdict::Foreign => {
                tracing::debug!(
                    %sender,
                    seq = remote.seq,
                    "discv4: node on another chain (ENR fork id), not handed to the pool"
                );
                enr.skip_foreign();
                self.forget(&pending.entry.node_id);
            }
            Verdict::Compatible => {
                enr.counts.compatible.fetch_add(1, Ordering::Relaxed);
                self.emit(pending.entry).await;
            }
            Verdict::Unknown => {
                enr.counts.unjudged.fetch_add(1, Ordering::Relaxed);
                self.emit(pending.entry).await;
            }
        }
    }

    /// Hand over nodes whose ENR never came (fail open), forget stale bonds,
    /// and say how many foreign nodes were kept from the pool.
    async fn sweep_enr(&mut self) {
        let now = tokio::time::Instant::now();
        // Filter or no filter: pings whose pong is not coming must not pile up.
        self.prune_pending_pings(now);
        let Some(enr) = self.enr.as_mut() else {
            return;
        };
        let expired: Vec<SocketAddr> = enr
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.since) >= ENR_TIMEOUT)
            .map(|(a, _)| *a)
            .collect();
        let mut unjudged = Vec::with_capacity(expired.len());
        for addr in expired {
            if let Some(p) = enr.pending.remove(&addr) {
                // Unjudged, until UNKNOWN_VERDICT_TTL has passed: the node is
                // asked again at its first sighting after that.
                enr.record(p.entry.node_id.clone(), Verdict::Unknown, None, now);
                enr.counts.unjudged.fetch_add(1, Ordering::Relaxed);
                unjudged.push(p.entry);
            }
        }
        if enr.bonded.len() > BONDED_MAX / 2 {
            enr.bonded
                .retain(|_, b| now.duration_since(b.since) < BOND_TTL);
        }
        enr.maybe_log(now);
        for entry in unjudged {
            self.emit(entry).await;
        }
    }

    /// Drop a node the filter placed on another chain from the routing table.
    fn forget(&self, node_id: &[u8]) {
        if let Ok(mut table) = self.table.lock() {
            table.remove(node_id);
        }
    }

    /// A ping to `addr` is in flight and may still be answered.
    fn fresh_ping_pending(&self, addr: SocketAddr, now: tokio::time::Instant) -> bool {
        self.pending_pings
            .get(&addr)
            .is_some_and(|p| now.duration_since(p.since) < PING_PENDING_TTL)
    }

    /// Drop pings whose pong is not coming; a map at its cap loses them all
    /// rather than growing (a NEIGHBORS list is mostly nodes that never answer).
    fn prune_pending_pings(&mut self, now: tokio::time::Instant) {
        self.pending_pings
            .retain(|_, p| now.duration_since(p.since) < PING_PENDING_TTL);
        if self.pending_pings.len() >= PING_PENDING_MAX {
            self.pending_pings.clear();
        }
    }

    async fn emit(&mut self, entry: TableEntry) {
        if let Ok(mut table) = self.table.lock() {
            table.add(entry.clone());
        }
        // NON-blocking: discovery events are advisory (the table is already
        // updated). Blocking here on a full channel would freeze the whole
        // select loop — recv AND refresh AND stop would all stall.
        match self.events.try_send(entry) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tracing::trace!("discv4 events channel full, dropping peer event");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Bond with a proven peer's UDP endpoint (see [`Discv4Service::probe_sender`]):
    /// ping (the pong lands it in the table, where `refresh` samples it) plus a
    /// best-effort FindNode-self head start — the same ping-then-FindNode shape
    /// `refresh` uses (Java `DiscV4Service.probeEndpoint` twin). Deduped per
    /// endpoint (1 h) and bounded.
    async fn probe(&mut self, addr: SocketAddr) {
        // Bonded endpoints (in the table — pong verified) re-probe hourly; an
        // endpoint whose earlier probe never bonded retries sooner, so one
        // lost datagram can't black out a proven peer's neighbourhood for an
        // hour (Java `shouldProbe` twin).
        const PROBE_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
        const PROBE_RETRY_UNBONDED: std::time::Duration = std::time::Duration::from_secs(10 * 60);
        const PROBE_MAP_MAX: usize = 1024;
        let now = tokio::time::Instant::now();
        // Coarse bound: losing history just allows a re-probe.
        if self.probed.len() > PROBE_MAP_MAX {
            self.probed.clear();
        }
        let bonded = self
            .table
            .lock()
            .map(|t| {
                t.all_peers().iter().any(|e| {
                    e.udp_port == addr.port()
                        && match addr.ip() {
                            IpAddr::V4(v4) => e.ip == v4.octets(),
                            IpAddr::V6(v6) => e.ip == v6.octets(),
                        }
                })
            })
            .unwrap_or(false);
        let window = if bonded { PROBE_MIN_INTERVAL } else { PROBE_RETRY_UNBONDED };
        if let Some(last) = self.probed.get(&addr) {
            if now.duration_since(*last) < window {
                return;
            }
        }
        self.probed.insert(addr, now);
        tracing::debug!(%addr, "probing proven peer endpoint");
        if !self.fresh_ping_pending(addr, now) {
            self.send_ping(addr).await;
        }
        let self_target = self.key.public_key_bytes().to_vec();
        self.send_find_node(addr, &self_target).await;
    }

    /// 15 s refresh: empty table → re-ping bootnodes; else FindNode-self to
    /// bootnodes + ping-then-FindNode(random target) to 10 random peers — 30
    /// while the pool is below target, for a bounded run (`fan_out`).
    async fn refresh(&mut self) {
        let peers = self
            .table
            .lock()
            .map(|t| t.all_peers())
            .unwrap_or_default();
        tracing::debug!(table = peers.len(), "discv4 refresh");
        if peers.is_empty() {
            let now = tokio::time::Instant::now();
            for bootnode in self.bootnodes.clone() {
                // Not over a bond in flight (the previous refresh's ping is
                // inside its 20 s expiry when the next one fires).
                if !self.fresh_ping_pending(bootnode, now) {
                    self.send_ping(bootnode).await;
                }
            }
            return;
        }
        let self_target = self.key.public_key_bytes().to_vec();
        for bootnode in self.bootnodes.clone() {
            self.send_find_node(bootnode, &self_target).await;
        }
        if let Some(enr) = self.enr.as_mut() {
            enr.refresh_local(&self.key);
        }
        // Below target the pool wants candidates faster than ten peers' worth
        // of neighbours per 15 s (#539) — for a bounded while (`fan_out`).
        let below = self
            .pool_below_target
            .as_ref()
            .map(|f| f.load(Ordering::Relaxed));
        let fan_out = fan_out(&mut self.wide, below, tokio::time::Instant::now());
        let mut random_target = [0u8; 64];
        let _ = getrandom::getrandom(&mut random_target);
        let now = tokio::time::Instant::now();
        for entry in sample(&peers, fan_out) {
            let Some(addr) = to_socket_addr(&entry.ip, entry.udp_port) else {
                continue;
            };
            // Never over a bond in flight: a second ping would make the first
            // pong unverifiable.
            if !self.fresh_ping_pending(addr, now) {
                self.send_ping(addr).await;
            }
            self.send_find_node(addr, &random_target).await;
        }
    }

    async fn send_ping(&mut self, to: SocketAddr) {
        let from_ip = [0u8; 4]; // 0.0.0.0 — Java sends its wildcard bind addr
        let Ok(packet) = encode_ping(
            &self.key,
            &from_ip,
            self.local_port,
            &ip_bytes(to.ip()),
            to.port(),
            expiry_now(),
        ) else {
            return;
        };
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&packet[..32]);
        self.pending_pings.insert(
            to,
            PendingPing {
                hash,
                since: tokio::time::Instant::now(),
            },
        );
        let _ = self.send_to(&packet, to).await;
    }

    async fn send_find_node(&mut self, to: SocketAddr, target: &[u8]) {
        if let Ok(packet) = encode_find_node(&self.key, target, expiry_now()) {
            let _ = self.send_to(&packet, to).await;
        }
    }

    /// Send, mapping IPv4 targets to the v4-mapped form on a dual-stack v6
    /// socket (a v6 socket rejects a plain `SocketAddr::V4`).
    async fn send_to(&self, packet: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        let dest = match (self.dual_stack, to) {
            (true, SocketAddr::V4(v4)) => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            _ => to,
        };
        self.socket.send_to(packet, dest).await
    }
}

fn expiry_now() -> u64 {
    now_secs() + EXPIRY_SECONDS
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Canonicalize a socket address: a v4-mapped v6 (`::ffff:a.b.c.d`, how a
/// dual-stack socket reports v4 senders) becomes a plain v4 address.
fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        _ => addr,
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn to_socket_addr(ip: &[u8], port: u16) -> Option<SocketAddr> {
    match ip.len() {
        4 => {
            let mut o = [0u8; 4];
            o.copy_from_slice(ip);
            Some(SocketAddr::from((Ipv4Addr::from(o), port)))
        }
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(ip);
            Some(SocketAddr::from((Ipv6Addr::from(o), port)))
        }
        _ => None,
    }
}

/// Up to `k` distinct random picks (PARTIAL Fisher-Yates — only the first
/// `min(k, n)` positions are resolved, so at most `k` entropy draws rather
/// than one per table entry; the table can hold thousands).
fn sample(peers: &[TableEntry], k: usize) -> Vec<TableEntry> {
    let n = peers.len();
    let take = k.min(n);
    let mut indices: Vec<usize> = (0..n).collect();
    let mut rnd = [0u8; 8];
    for i in 0..take {
        let _ = getrandom::getrandom(&mut rnd);
        let j = i + (u64::from_le_bytes(rnd) as usize) % (n - i);
        indices.swap(i, j);
    }
    indices[..take].iter().map(|&i| peers[i].clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> NodeKey {
        let mut secret = [0u8; 32];
        secret[31] = n;
        NodeKey::from_secret_bytes(&secret).unwrap()
    }

    #[test]
    fn ping_round_trip() {
        let k = key(1);
        let packet = encode_ping(&k, &[0, 0, 0, 0], 30303, &[1, 2, 3, 4], 30304, 1_700_000_020)
            .unwrap();
        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.packet_type, TYPE_PING);
        assert_eq!(parsed.sender_pubkey, k.public_key_bytes());
        assert_eq!(decode_ping_from_ports(&parsed.data).unwrap(), (30303, 30303));
    }

    #[test]
    fn pong_echoes_ping_hash() {
        let k = key(2);
        let ping = encode_ping(&k, &[0; 4], 1, &[1, 2, 3, 4], 2, 100).unwrap();
        let mut ping_hash = [0u8; 32];
        ping_hash.copy_from_slice(&ping[..32]);
        let pong = encode_pong(&k, &[1, 2, 3, 4], 2, &ping_hash, 100).unwrap();
        let parsed = parse(&pong).unwrap();
        assert_eq!(parsed.packet_type, TYPE_PONG);
        assert_eq!(decode_pong_ping_hash(&parsed.data).unwrap(), ping_hash);
    }

    #[test]
    fn enr_request_and_response_round_trip() {
        use crate::el::enrfilter::{eth_entry_rlp, local_enr_rlp};
        let k = key(5);
        let request = encode_enr_request(&k, 100).unwrap();
        let parsed = parse(&request).unwrap();
        assert_eq!(parsed.packet_type, TYPE_ENR_REQUEST);
        assert_eq!(parsed.sender_pubkey, k.public_key_bytes());
        let enr = local_enr_rlp(&k, 3, &eth_entry_rlp([1, 2, 3, 4], 0)).unwrap();
        let response = encode_enr_response(&k, &parsed.hash, &enr).unwrap();
        let parsed_response = parse(&response).unwrap();
        assert_eq!(parsed_response.packet_type, TYPE_ENR_RESPONSE);
        let (hash, raw) = decode_enr_response(&parsed_response.data).unwrap();
        assert_eq!(hash, parsed.hash);
        // The ENR comes back byte for byte: an ENR is canonical RLP.
        assert_eq!(raw, enr);
        assert!(decode_enr(&raw, &k.public_key_bytes()).is_ok());
        // A response whose second item is not a list carries no ENR.
        let bogus = rlp::encode(&Item::List(vec![
            Item::Bytes(vec![0u8; 32]),
            Item::Bytes(vec![1, 2, 3]),
        ]));
        assert!(decode_enr_response(&bogus).is_err());
    }

    #[test]
    fn the_wide_fan_out_is_granted_per_below_target_episode_and_runs_out() {
        let mut state = WideState::default();
        let t0 = tokio::time::Instant::now();
        // No pool hint: narrow.
        assert_eq!(fan_out(&mut state, None, t0), REFRESH_SAMPLE);
        // Below target: wide for WIDE_REFRESHES_MAX refreshes, then narrow.
        for _ in 0..WIDE_REFRESHES_MAX {
            assert_eq!(fan_out(&mut state, Some(true), t0), REFRESH_SAMPLE_WIDE);
        }
        assert_eq!(fan_out(&mut state, Some(true), t0), REFRESH_SAMPLE);
        assert_eq!(fan_out(&mut state, Some(true), t0), REFRESH_SAMPLE);
        // Back at target, then below again within the cooldown: no new budget.
        let soon = t0 + std::time::Duration::from_secs(5 * 60);
        assert_eq!(fan_out(&mut state, Some(false), soon), REFRESH_SAMPLE);
        assert_eq!(fan_out(&mut state, Some(true), soon), REFRESH_SAMPLE);
        // After the cooldown, a dip earns a fresh budget.
        let later = t0 + WIDE_COOLDOWN;
        assert_eq!(fan_out(&mut state, Some(false), later), REFRESH_SAMPLE);
        assert_eq!(fan_out(&mut state, Some(true), later), REFRESH_SAMPLE_WIDE);
    }

    #[test]
    fn the_table_forgets_a_node() {
        let local = key(6);
        let mut table = KademliaTable::new(local.node_id());
        let entry = |n: u8| TableEntry {
            ip: vec![10, 0, 0, n],
            udp_port: 30303,
            tcp_port: 30303,
            node_id: vec![n; 64],
            last_seen_ms: 0,
        };
        table.add(entry(1));
        table.add(entry(2));
        assert_eq!(table.get(&[1u8; 64]).map(|e| e.tcp_port), Some(30303));
        table.remove(&[1u8; 64]);
        assert_eq!(table.len(), 1);
        assert_eq!(table.all_peers()[0].node_id, vec![2u8; 64]);
        assert!(table.get(&[1u8; 64]).is_none());
        table.remove(&[9u8; 64]); // unknown: a no-op
        assert_eq!(table.len(), 1);
    }

    /// Two services on loopback: the one that bootstraps from the other is
    /// handed over only once its ENR says it is on the same chain. `None` for
    /// B's filter = a node that neither asks for nor answers ENRs.
    async fn loopback_pair(
        a_filter: ForkFilter,
        b_filter: Option<ForkFilter>,
    ) -> (
        Discv4Service,
        Discv4Service,
        tokio::sync::mpsc::Receiver<TableEntry>,
        [u8; 64],
    ) {
        let a_key = Arc::new(key(11));
        let b_key = Arc::new(key(12));
        let (a_tx, a_rx) = tokio::sync::mpsc::channel(16);
        let a = Discv4Service::start(
            Arc::clone(&a_key),
            Discv4Config {
                bind_port: 0,
                bootnodes: Vec::new(),
                fork_filter: Some(a_filter),
                pool_below_target: None,
            },
            a_tx,
        )
        .await
        .unwrap();
        let (b_tx, _b_rx) = tokio::sync::mpsc::channel(16);
        let b = Discv4Service::start(
            Arc::clone(&b_key),
            Discv4Config {
                bind_port: 0,
                bootnodes: vec![SocketAddr::from(([127, 0, 0, 1], a.local_port()))],
                fork_filter: b_filter,
                pool_below_target: None,
            },
            b_tx,
        )
        .await
        .unwrap();
        (a, b, a_rx, b_key.public_key_bytes())
    }

    #[tokio::test]
    async fn a_node_on_our_chain_is_handed_over_after_its_enr() {
        let same = || ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0);
        let (a, b, mut a_rx, b_id) = loopback_pair(same(), Some(same())).await;
        // B pings A at start; A pongs, bonds back and asks for B's ENR; B
        // answers once A's pong has bonded it; A judges B compatible and emits.
        let entry = tokio::time::timeout(std::time::Duration::from_secs(5), a_rx.recv())
            .await
            .expect("A should hand B over within the ENR timeout")
            .unwrap();
        assert_eq!(entry.node_id, b_id.to_vec());
        assert_eq!(a.foreign_skipped(), 0);
        a.stop().await;
        b.stop().await;
    }

    #[tokio::test]
    async fn a_node_on_another_chain_is_kept_from_the_pool() {
        let (a, b, mut a_rx, _) = loopback_pair(
            ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0),
            Some(ForkFilter::for_chain([0x01, 0x02, 0x03, 0x04], 0)),
        )
        .await;
        // Past the fail-open timeout and then some: nothing was emitted, and
        // the skip was counted.
        let got =
            tokio::time::timeout(ENR_TIMEOUT + std::time::Duration::from_secs(2), a_rx.recv())
                .await;
        assert!(
            got.is_err(),
            "a foreign node must not reach the pool: {got:?}"
        );
        assert!(a.foreign_skipped() >= 1, "the skip is counted");
        a.stop().await;
        b.stop().await;
    }

    #[tokio::test]
    async fn a_node_that_never_answers_is_handed_over_unjudged_after_the_timeout() {
        // B runs no exchange at all (no filter): it never answers A's
        // ENRRequests. A must hand it over anyway, once the timeout passes —
        // the fail-open the design's "dialed as before" rests on.
        let (a, b, mut a_rx, b_id) =
            loopback_pair(ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0), None).await;
        let started = tokio::time::Instant::now();
        let entry =
            tokio::time::timeout(ENR_TIMEOUT + std::time::Duration::from_secs(3), a_rx.recv())
                .await
                .expect("A should hand B over after the ENR timeout")
                .unwrap();
        assert_eq!(entry.node_id, b_id.to_vec());
        assert!(
            started.elapsed() >= ENR_TIMEOUT - std::time::Duration::from_millis(200),
            "handed over only after the timeout: {:?}",
            started.elapsed()
        );
        let (compatible, foreign, unjudged) = a.enr_counts().snapshot();
        assert_eq!((compatible, foreign), (0, 0));
        assert!(unjudged >= 1, "the timeout is counted as unjudged");
        a.stop().await;
        b.stop().await;
    }

    #[tokio::test]
    async fn enr_requests_are_answered_for_the_bonded_signer_only() {
        let a_key = Arc::new(key(14));
        let (a_tx, _a_rx) = tokio::sync::mpsc::channel(16);
        let a = Discv4Service::start(
            Arc::clone(&a_key),
            Discv4Config {
                bind_port: 0,
                bootnodes: Vec::new(),
                fork_filter: Some(ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0)),
                pool_below_target: None,
            },
            a_tx,
        )
        .await
        .unwrap();
        let a_addr = SocketAddr::from(([127, 0, 0, 1], a.local_port()));
        let stranger = key(15);
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 2048];
        // 1. Never bonded: a valid, unexpired request gets no answer.
        let request = encode_enr_request(&stranger, expiry_now()).unwrap();
        sock.send_to(&request, a_addr).await.unwrap();
        let answered = tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            sock.recv_from(&mut buf),
        )
        .await;
        assert!(
            answered.is_err(),
            "an unbonded ENRRequest must get no answer (amplification)"
        );
        // 2. Bond: ping A; A pongs and pings back; pong that ping. A now holds
        //    our pong under the stranger's key, and answers our request.
        let ping = encode_ping(
            &stranger,
            &[0, 0, 0, 0],
            30303,
            &[127, 0, 0, 1],
            a.local_port(),
            expiry_now(),
        )
        .unwrap();
        sock.send_to(&ping, a_addr).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut bonded = false;
        let mut answered_enr = false;
        while tokio::time::Instant::now() < deadline && !answered_enr {
            let Ok(Ok((n, from))) =
                tokio::time::timeout(std::time::Duration::from_secs(1), sock.recv_from(&mut buf))
                    .await
            else {
                continue;
            };
            let Ok(p) = parse(&buf[..n]) else { continue };
            match p.packet_type {
                TYPE_PING => {
                    let pong = encode_pong(
                        &stranger,
                        &[127, 0, 0, 1],
                        from.port(),
                        &p.hash,
                        expiry_now(),
                    )
                    .unwrap();
                    sock.send_to(&pong, from).await.unwrap();
                    bonded = true;
                    let request = encode_enr_request(&stranger, expiry_now()).unwrap();
                    sock.send_to(&request, from).await.unwrap();
                }
                TYPE_ENR_RESPONSE => {
                    let (_, raw) = decode_enr_response(&p.data).unwrap();
                    assert!(
                        decode_enr(&raw, &a_key.public_key_bytes()).is_ok(),
                        "A's own record"
                    );
                    answered_enr = true;
                }
                _ => {} // A's pong, and its ENRRequest to us
            }
        }
        assert!(bonded, "A should ping back a node that pinged it");
        assert!(
            answered_enr,
            "A should answer the bonded signer's ENRRequest"
        );
        // 3. The same address, another key: a spoofed source cannot borrow the
        //    bond (geth checkBond(id, ip)).
        let impostor = key(16);
        let request = encode_enr_request(&impostor, expiry_now()).unwrap();
        sock.send_to(&request, a_addr).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1500);
        while tokio::time::Instant::now() < deadline {
            let Ok(Ok((n, _))) = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                sock.recv_from(&mut buf),
            )
            .await
            else {
                continue;
            };
            if let Ok(p) = parse(&buf[..n]) {
                assert_ne!(
                    p.packet_type, TYPE_ENR_RESPONSE,
                    "another key must not borrow the bond"
                );
            }
        }
        a.stop().await;
    }

    /// The record a raw node answers A's ENRRequest with — on A's chain
    /// unless said otherwise.
    #[derive(Clone, Copy)]
    enum RawRecord {
        /// No address, no port: the record says nothing about its endpoint.
        Bare,
        /// Listening on this TCP port.
        Tcp(u16),
        /// An address and a UDP port, no TCP port — the discovery-only shape;
        /// with or without an `eth` entry (the EF NodeOps bootnodes have none).
        DiscoveryOnly { eth: bool },
    }

    /// Play a node for `a` over a raw socket: announce ourselves to A in a
    /// NEIGHBORS packet as listening on `advertised_tcp`, pong A's ping, and
    /// answer A's ENRRequest with `record`. Returns the entry A hands to its
    /// pool.
    async fn raw_node_round(
        a: &Discv4Service,
        a_rx: &mut tokio::sync::mpsc::Receiver<TableEntry>,
        node: &NodeKey,
        advertised_tcp: u32,
        record: RawRecord,
    ) -> TableEntry {
        use crate::el::enrfilter::eth_entry_rlp;
        use discv5::enr::{CombinedKey, Enr};
        let a_addr = SocketAddr::from(([127, 0, 0, 1], a.local_port()));
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let our_udp = sock.local_addr().unwrap().port();
        let mut secret = node.secret_bytes();
        let signing = CombinedKey::secp256k1_from_bytes(&mut secret).unwrap();
        let mut builder = Enr::<CombinedKey>::builder();
        builder.seq(1);
        if !matches!(record, RawRecord::DiscoveryOnly { eth: false }) {
            builder.add_value_rlp(
                "eth",
                alloy_rlp::Bytes::from(eth_entry_rlp([0xaa, 0xbb, 0xcc, 0xdd], 0)),
            );
        }
        match record {
            RawRecord::DiscoveryOnly { .. } => {
                builder.ip4([127, 0, 0, 1].into()).udp4(our_udp);
            }
            RawRecord::Tcp(tcp) => {
                builder.tcp4(tcp);
            }
            RawRecord::Bare => {}
        }
        let record = alloy_rlp::encode(builder.build(&signing).unwrap());
        // 1. NEIGHBORS, unsolicited (A takes any): "this node, at our UDP
        //    port, listens on advertised_tcp".
        let data = rlp::encode(&Item::List(vec![
            Item::List(vec![Item::List(vec![
                Item::Bytes(vec![127, 0, 0, 1]),
                Item::Bytes(rlp::u64_to_minimal_be(u64::from(our_udp))),
                Item::Bytes(rlp::u64_to_minimal_be(u64::from(advertised_tcp))),
                Item::Bytes(node.public_key_bytes().to_vec()),
            ])]),
            Item::Bytes(rlp::u64_to_minimal_be(expiry_now())),
        ]));
        let neighbors = encode_packet(node, TYPE_NEIGHBORS, &data).unwrap();
        sock.send_to(&neighbors, a_addr).await.unwrap();
        // 2. A pings first (we are second-hand); pong it. Bonded, A asks for
        //    our record; answer it. A judges us compatible and hands us over.
        let mut buf = [0u8; 2048];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            tokio::select! {
                got = a_rx.recv() => return got.expect("A's event channel"),
                recv = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)) => {
                    let (n, from) = recv.expect("A handed nothing over within 5 s").unwrap();
                    let Ok(p) = parse(&buf[..n]) else { continue };
                    match p.packet_type {
                        TYPE_PING => {
                            let pong = encode_pong(
                                node,
                                &[127, 0, 0, 1],
                                from.port(),
                                &p.hash,
                                expiry_now(),
                            )
                            .unwrap();
                            sock.send_to(&pong, from).await.unwrap();
                        }
                        TYPE_ENR_REQUEST => {
                            let response = encode_enr_response(node, &p.hash, &record).unwrap();
                            sock.send_to(&response, from).await.unwrap();
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn a_pong_keeps_the_advertised_tcp_port_and_the_record_overrides_it() {
        let a_key = Arc::new(key(17));
        let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(16);
        let a = Discv4Service::start(
            Arc::clone(&a_key),
            Discv4Config {
                bind_port: 0,
                bootnodes: Vec::new(),
                fork_filter: Some(ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0)),
                pool_below_target: None,
            },
            a_tx,
        )
        .await
        .unwrap();
        // A node whose record names no port: the port its NEIGHBORS entry
        // advertised survives its pong — which carries none — to the pool.
        let quiet = key(18);
        let entry = raw_node_round(&a, &mut a_rx, &quiet, 40404, RawRecord::Bare).await;
        assert_eq!(entry.node_id, quiet.public_key_bytes().to_vec());
        assert_eq!(
            entry.tcp_port, 40404,
            "a pong must not replace the advertised TCP port with the UDP port"
        );
        // A node whose record names its port: the signed record beats the
        // NEIGHBORS hearsay.
        let outspoken = key(19);
        let entry = raw_node_round(&a, &mut a_rx, &outspoken, 40404, RawRecord::Tcp(50505)).await;
        assert_eq!(entry.node_id, outspoken.public_key_bytes().to_vec());
        assert_eq!(
            entry.tcp_port, 50505,
            "the node's own record names the port to dial"
        );
        // A node whose record names an address and a UDP port but no TCP port
        // is discovery-only: handed over at port 0, which the pool refuses,
        // whatever NEIGHBORS claimed.
        let discovery_only = key(20);
        let entry = raw_node_round(&a, &mut a_rx, &discovery_only, 40404, RawRecord::DiscoveryOnly { eth: true }).await;
        assert_eq!(entry.node_id, discovery_only.public_key_bytes().to_vec());
        assert_eq!(entry.tcp_port, 0, "a record with an address and no TCP port is never dialed");
        // Re-learned from a relayer's NEIGHBORS with other ports: the record's
        // word outlives the sighting — the discovery-only node stays at port
        // 0, the outspoken one at its record's port; only the node whose
        // record named no address takes the hearsay.
        let entry = reannounce(&a, &mut a_rx, &discovery_only, 30303).await;
        assert_eq!(entry.tcp_port, 0, "hearsay must not put a discovery-only node back on the dial list");
        let entry = reannounce(&a, &mut a_rx, &outspoken, 30303).await;
        assert_eq!(entry.tcp_port, 50505, "hearsay must not replace the port the record named");
        let entry = reannounce(&a, &mut a_rx, &quiet, 41414).await;
        assert_eq!(entry.tcp_port, 41414, "a record that named no address leaves the port to the sighting");
        // The EF NodeOps bootnodes' exact shape: an address, no TCP port, no
        // `eth` entry — unjudged, handed over at port 0, and the pin holds on
        // a relayer's re-announcement (an Unknown with a record in hand does
        // not expire).
        let (compatible_before, _, unjudged_before) = a.enr_counts().snapshot();
        let bootnode_like = key(24);
        let entry = raw_node_round(&a, &mut a_rx, &bootnode_like, 30303, RawRecord::DiscoveryOnly { eth: false }).await;
        assert_eq!(entry.tcp_port, 0);
        let (compatible, _, unjudged) = a.enr_counts().snapshot();
        assert_eq!((compatible, unjudged), (compatible_before, unjudged_before + 1), "no eth entry: unjudged");
        let entry = reannounce(&a, &mut a_rx, &bootnode_like, 30303).await;
        assert_eq!(entry.tcp_port, 0, "the pin holds for an unjudged record too");
        // The node's own Ping claims a new port: fresher than its record and
        // signed by it, so it wins — and a relayer still cannot move it.
        let entry = ping_claiming(&a, &mut a_rx, &outspoken, 50506).await;
        assert_eq!(entry.tcp_port, 50506, "a Ping's own claim follows a moved port");
        let entry = reannounce(&a, &mut a_rx, &outspoken, 30303).await;
        assert_eq!(entry.tcp_port, 50506, "the claim is kept against later hearsay");
        a.stop().await;
    }

    /// `node` pings `a` from a fresh socket, its FROM endpoint claiming
    /// `claimed_tcp`; returns what A hands over for it.
    async fn ping_claiming(
        a: &Discv4Service,
        a_rx: &mut tokio::sync::mpsc::Receiver<TableEntry>,
        node: &NodeKey,
        claimed_tcp: u16,
    ) -> TableEntry {
        let a_addr = SocketAddr::from(([127, 0, 0, 1], a.local_port()));
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // `encode_ping` writes the FROM endpoint's UDP port as its TCP port too.
        let ping = encode_ping(node, &[0, 0, 0, 0], claimed_tcp, &[127, 0, 0, 1], a.local_port(), expiry_now()).unwrap();
        sock.send_to(&ping, a_addr).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), a_rx.recv())
            .await
            .expect("A hands a pinging judged node over at once")
            .unwrap()
    }

    /// A relayer's NEIGHBORS to `a`, from a fresh socket: `node` at
    /// 127.0.0.1:`udp_port`, claiming `advertised_tcp`.
    async fn relay_neighbors(a: &Discv4Service, node: &NodeKey, udp_port: u16, advertised_tcp: u32) {
        let a_addr = SocketAddr::from(([127, 0, 0, 1], a.local_port()));
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let data = rlp::encode(&Item::List(vec![
            Item::List(vec![Item::List(vec![
                Item::Bytes(vec![127, 0, 0, 1]),
                Item::Bytes(rlp::u64_to_minimal_be(u64::from(udp_port))),
                Item::Bytes(rlp::u64_to_minimal_be(u64::from(advertised_tcp))),
                Item::Bytes(node.public_key_bytes().to_vec()),
            ])]),
            Item::Bytes(rlp::u64_to_minimal_be(expiry_now())),
        ]));
        let relayer = key(99);
        let packet = encode_packet(&relayer, TYPE_NEIGHBORS, &data).unwrap();
        sock.send_to(&packet, a_addr).await.unwrap();
    }

    /// Announce `node` to `a` again — a relayer's NEIGHBORS naming a fresh UDP
    /// port and `advertised_tcp` — and return what A hands over.
    async fn reannounce(
        a: &Discv4Service,
        a_rx: &mut tokio::sync::mpsc::Receiver<TableEntry>,
        node: &NodeKey,
        advertised_tcp: u32,
    ) -> TableEntry {
        let fresh = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay_neighbors(a, node, fresh.local_addr().unwrap().port(), advertised_tcp).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), a_rx.recv())
            .await
            .expect("A hands a judged node over at once")
            .unwrap()
    }

    #[tokio::test]
    async fn a_pings_own_port_claim_survives_hearsay_inside_the_judging_window() {
        use crate::el::enrfilter::eth_entry_rlp;
        use discv5::enr::{CombinedKey, Enr};
        // Node X pings A claiming port 50507; before X answers A's ENRRequest,
        // a relayer's NEIGHBORS lists X with 30303. X's record names no
        // address, so the claim is all A has on X's port: it must survive the
        // hearsay, and be pinned against later hearsay.
        let a_key = Arc::new(key(25));
        let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(16);
        let a = Discv4Service::start(
            Arc::clone(&a_key),
            Discv4Config {
                bind_port: 0,
                bootnodes: Vec::new(),
                fork_filter: Some(ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0)),
                pool_below_target: None,
            },
            a_tx,
        )
        .await
        .unwrap();
        let a_addr = SocketAddr::from(([127, 0, 0, 1], a.local_port()));
        let x = key(26);
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let our_udp = sock.local_addr().unwrap().port();
        let record = {
            let mut secret = x.secret_bytes();
            let signing = CombinedKey::secp256k1_from_bytes(&mut secret).unwrap();
            let mut b = Enr::<CombinedKey>::builder();
            b.seq(1).add_value_rlp(
                "eth",
                alloy_rlp::Bytes::from(eth_entry_rlp([0xaa, 0xbb, 0xcc, 0xdd], 0)),
            );
            alloy_rlp::encode(b.build(&signing).unwrap())
        };
        // 1. X pings A, its FROM endpoint claiming TCP 50507.
        let ping = encode_ping(&x, &[0, 0, 0, 0], 50507, &[127, 0, 0, 1], a.local_port(), expiry_now()).unwrap();
        sock.send_to(&ping, a_addr).await.unwrap();
        // 2. A's ENRRequest arrives: A holds the claim and awaits the record.
        let mut buf = [0u8; 2048];
        let request = loop {
            let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
                .await
                .expect("A asks X for its record")
                .unwrap();
            if let Ok(p) = parse(&buf[..n]) {
                if p.packet_type == TYPE_ENR_REQUEST {
                    break p;
                }
            }
        };
        // 3. Hearsay inside the window: a relayer lists X with another port.
        relay_neighbors(&a, &x, our_udp, 30303).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // 4. X answers with a record that names no address.
        let response = encode_enr_response(&x, &request.hash, &record).unwrap();
        sock.send_to(&response, a_addr).await.unwrap();
        let entry = tokio::time::timeout(std::time::Duration::from_secs(5), a_rx.recv())
            .await
            .expect("A hands X over")
            .unwrap();
        assert_eq!(entry.node_id, x.public_key_bytes().to_vec());
        assert_eq!(
            entry.tcp_port, 50507,
            "the node's own claim survives a relayer's hearsay inside the judging window"
        );
        // 5. And it is pinned: later hearsay does not move it.
        let entry = reannounce(&a, &mut a_rx, &x, 30303).await;
        assert_eq!(entry.tcp_port, 50507, "the claim is pinned against later hearsay");
        a.stop().await;
    }

    #[tokio::test]
    async fn the_pool_gate_judges_second_hand_nodes_below_target_only() {
        // The pool's flag (part 1's maintainer sets it each tick): at target a
        // node learned from NEIGHBORS goes over unjudged, without a ping;
        // below target it is judged first.
        let below_target = Arc::new(AtomicBool::new(false));
        let a_key = Arc::new(key(21));
        let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(16);
        let a = Discv4Service::start(
            Arc::clone(&a_key),
            Discv4Config {
                bind_port: 0,
                bootnodes: Vec::new(),
                fork_filter: Some(ForkFilter::for_chain([0xaa, 0xbb, 0xcc, 0xdd], 0)),
                pool_below_target: Some(Arc::clone(&below_target)),
            },
            a_tx,
        )
        .await
        .unwrap();
        // At target: handed over at once with the hearsay port, nothing judged.
        let at_target = key(22);
        let entry = raw_node_round(&a, &mut a_rx, &at_target, 40404, RawRecord::Tcp(50505)).await;
        assert_eq!(entry.node_id, at_target.public_key_bytes().to_vec());
        assert_eq!(entry.tcp_port, 40404, "at target the sighting goes over as it came");
        assert_eq!(a.enr_counts().snapshot(), (0, 0, 0), "nothing was judged at target");
        // Below target: pinged, asked, judged — the record's port arrives.
        below_target.store(true, Ordering::Relaxed);
        let wanted = key(23);
        let entry = raw_node_round(&a, &mut a_rx, &wanted, 40404, RawRecord::Tcp(50505)).await;
        assert_eq!(entry.node_id, wanted.public_key_bytes().to_vec());
        assert_eq!(entry.tcp_port, 50505, "below target the record is asked for first");
        assert_eq!(a.enr_counts().snapshot(), (1, 0, 0));
        a.stop().await;
    }

    #[test]
    fn an_unknown_verdict_expires_but_the_others_stand() {
        let t0 = tokio::time::Instant::now();
        let j = |verdict: Verdict| Judgement {
            verdict,
            tcp_port: None,
            at: t0,
        };
        let later = t0 + UNKNOWN_VERDICT_TTL;
        assert!(!j(Verdict::Unknown).expired(t0 + UNKNOWN_VERDICT_TTL / 2));
        assert!(j(Verdict::Unknown).expired(later));
        assert!(!j(Verdict::Compatible).expired(later));
        assert!(!j(Verdict::Foreign).expired(later));
        // An Unknown with a record in hand — an address but no `eth` entry,
        // the discovery-only bootnodes' shape — keeps its port pin for the run.
        let with_record = Judgement {
            verdict: Verdict::Unknown,
            tcp_port: Some(0),
            at: t0,
        };
        assert!(!with_record.expired(later + UNKNOWN_VERDICT_TTL));
    }

    #[test]
    fn parse_rejects_tampering() {
        let k = key(3);
        let mut packet = encode_find_node(&k, &k.public_key_bytes(), 100).unwrap();
        assert!(parse(&packet[..97]).is_err()); // too short
        packet[40] ^= 0x01; // corrupt the signature → hash mismatch
        assert!(parse(&packet).is_err());
    }

    #[test]
    fn neighbors_leniency_matches_java() {
        // [[good, bad-ip(3 bytes), good2], expiry] — bad ip SKIPS the node;
        // then a structurally-broken 4th entry STOPS the walk.
        use myotis_core::rlp::{encode, Item};
        let node = |ip: &[u8], udp: u64, id: u8| {
            Item::List(vec![
                Item::Bytes(ip.to_vec()),
                Item::Bytes(rlp::u64_to_minimal_be(udp)),
                Item::Bytes(rlp::u64_to_minimal_be(30303)),
                Item::Bytes(vec![id; 64]),
            ])
        };
        let data = encode(&Item::List(vec![
            Item::List(vec![
                node(&[1, 1, 1, 1], 100, 0xaa),
                node(&[9, 9, 9], 100, 0xbb),      // bad ip length → skipped
                node(&[2, 2, 2, 2], 70000, 0xcc), // udp out of range → skipped
                node(&[3, 3, 3, 3], 300, 0xdd),
                Item::Bytes(vec![0x01]),          // not a list → walk stops
                node(&[4, 4, 4, 4], 400, 0xee),   // never reached
            ]),
            Item::Bytes(rlp::u64_to_minimal_be(1_700_000_000)),
        ]));
        let peers = decode_neighbors(&data).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].node_id, vec![0xaa; 64]);
        assert_eq!(peers[1].node_id, vec![0xdd; 64]);
    }

    #[test]
    fn kademlia_dedup_eviction_and_ordering() {
        let local = key(4);
        let mut table = KademliaTable::new(local.node_id());
        let entry = |n: u8| TableEntry {
            ip: vec![10, 0, 0, n],
            udp_port: 30303,
            tcp_port: 30303,
            node_id: key(n).public_key_bytes().to_vec(),
            last_seen_ms: u64::from(n),
        };
        for n in 10..30 {
            table.add(entry(n));
        }
        let before = table.len();
        table.add(entry(10)); // dedup, not growth
        assert_eq!(table.len(), before);
        // Closest to node 11's own key must be node 11 itself.
        let closest = table.closest_peers(&key(11).public_key_bytes(), 3);
        assert_eq!(closest[0].node_id, key(11).public_key_bytes().to_vec());
    }

    #[test]
    fn rate_limiter_window() {
        // Realistic epoch millis: the zero-initialized ring must read as
        // "ancient", exactly as in Java where now ≫ window.
        const T0: u64 = 1_700_000_000_000;
        let mut limiter = PingRateLimiter::default();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        for i in 0..5 {
            assert!(!limiter.is_limited(ip, T0 + i));
        }
        assert!(limiter.is_limited(ip, T0 + 10)); // 6th within the window
        assert!(!limiter.is_limited(ip, T0 + 11_000)); // window expired
        let other: IpAddr = "10.1.2.4".parse().unwrap();
        assert!(!limiter.is_limited(other, T0 + 10)); // per-IP isolation
    }

    #[test]
    fn rate_limiter_is_bounded() {
        const T0: u64 = 1_700_000_000_000;
        let mut limiter = PingRateLimiter::default();
        let ip = |n: u32| IpAddr::from(Ipv4Addr::from(n));
        for n in 0..RATE_LIMIT_IPS_MAX as u32 {
            assert!(!limiter.is_limited(ip(n), T0));
        }
        assert_eq!(limiter.rings.len(), RATE_LIMIT_IPS_MAX);
        // A known source at the cap is still judged, not evicted around.
        assert!(!limiter.is_limited(ip(0), T0 + 1));
        assert_eq!(limiter.rings.len(), RATE_LIMIT_IPS_MAX);
        // Once the window has passed every ring, a new source evicts the idle
        // rings — which count nothing any more — rather than growing the map.
        let later = T0 + PING_RATE_WINDOW_MS + 1;
        assert!(!limiter.is_limited(ip(u32::MAX), later));
        assert_eq!(limiter.rings.len(), 1);
        // A flood of sources all live within the window is forgotten
        // wholesale (fail open) instead of growing it.
        for n in 0..RATE_LIMIT_IPS_MAX as u32 {
            limiter.is_limited(ip(n), later);
        }
        assert!(limiter.rings.len() <= RATE_LIMIT_IPS_MAX);
        assert!(!limiter.is_limited(ip(u32::MAX - 1), later));
        assert!(limiter.rings.len() <= RATE_LIMIT_IPS_MAX);
    }
}
