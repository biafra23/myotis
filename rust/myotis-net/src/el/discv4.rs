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
//! Pings get a Pong so bonds form). The packet codec, Kademlia table, and
//! rate limiter are pure (clock values are parameters) and pinned by the
//! `rust/testdata/el/discv4/` cross-language corpus; only [`Discv4Service`]
//! touches sockets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use myotis_core::keccak::{keccak256, keccak256_concat};
use myotis_core::nodekey::{recover_public_key, NodeKey};
use myotis_core::rlp::{self, Item};
use myotis_core::CoreError;

pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_FIND_NODE: u8 = 0x03;
pub const TYPE_NEIGHBORS: u8 = 0x04;

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

/// Sliding-window ring of the last [`PING_RATE_LIMIT`] ping timestamps per IP
/// (twin of the Java handler's limiter).
#[derive(Default)]
pub struct PingRateLimiter {
    rings: HashMap<IpAddr, [u64; PING_RATE_LIMIT]>,
}

impl PingRateLimiter {
    /// True when `addr` has exceeded the limit; records the ping otherwise.
    pub fn is_limited(&mut self, addr: IpAddr, now_ms: u64) -> bool {
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
pub struct Discv4Config {
    /// UDP bind port (0 = ephemeral, for tests).
    pub bind_port: u16,
    /// Bootnode `ip:port` addresses (bare, no keys — discv4 pings them cold).
    pub bootnodes: Vec<SocketAddr>,
}

/// Handle to a running discv4 service. Dropping it does NOT stop the task;
/// call [`Discv4Service::stop`].
pub struct Discv4Service {
    table: Arc<Mutex<KademliaTable>>,
    local_port: u16,
    stop_tx: tokio::sync::watch::Sender<bool>,
    /// Probe requests into the service loop (see [`Discv4Service::probe_sender`]).
    probe_tx: tokio::sync::mpsc::Sender<SocketAddr>,
    /// `Option` so `stop(self)` can take the handle while `Drop` (the
    /// forgot-to-stop path) leaves it `None`.
    task: Option<tokio::task::JoinHandle<()>>,
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
            probe_rx,
            probed: HashMap::new(),
        };
        let task = tokio::spawn(loop_state.run(stop_rx));
        Ok(Discv4Service {
            table,
            local_port,
            stop_tx,
            probe_tx,
            task: Some(task),
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

    pub async fn stop(mut self) {
        let _ = self.stop_tx.send(true);
        if let Some(task) = self.task.take() {
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
    /// ping target → expected echo hash (the bond in flight).
    pending_pings: HashMap<SocketAddr, [u8; 32]>,
    limiter: PingRateLimiter,
    /// Probe requests from the pool (proven-peer UDP endpoints to bond with).
    probe_rx: tokio::sync::mpsc::Receiver<SocketAddr>,
    /// Endpoint → last probe instant (1 h per-endpoint dedup, bounded).
    probed: HashMap<SocketAddr, tokio::time::Instant>,
}

impl ServiceLoop {
    async fn run(mut self, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
        tracing::info!(port = self.local_port, "discv4 listening");
        // Bootstrap: ping all bootnodes; then refresh every 15 s (first at 10 s).
        for bootnode in self.bootnodes.clone() {
            self.send_ping(bootnode).await;
        }
        let mut refresh = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(15),
        );
        // After a stall/sleep, catch up with ONE tick, not a burst of them —
        // otherwise we'd flood peers with a storm of FindNodes on wakeup.
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    tracing::info!("discv4 stopped");
                    return;
                }
                _ = refresh.tick() => self.refresh().await,
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
        // UDP port — mirror that by accepting only 1..=i32::MAX.
        let tcp_port = match decode_ping_from_ports(&p.data) {
            Ok((_, tcp)) if (1..=i32::MAX as u32).contains(&tcp) => tcp,
            _ => u32::from(sender.port()),
        };
        self.admit(sender, tcp_port, p.sender_pubkey.to_vec()).await;
    }

    async fn handle_pong(&mut self, p: Parsed, sender: SocketAddr) {
        let Ok(ping_hash) = decode_pong_ping_hash(&p.data) else {
            return;
        };
        match self.pending_pings.remove(&sender) {
            Some(expected) if expected == ping_hash => {
                tracing::debug!(%sender, "discv4 pong verified");
                // NOTE (Java parity): no FindNode here — go-ethereum requires
                // OUR pong to the bootnode's return Ping before it answers
                // FindNode; the refresh loop issues FindNodes later.
                self.admit(sender, u32::from(sender.port()), p.sender_pubkey.to_vec())
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
            self.emit(entry).await;
        }
    }

    /// Table-add + discovered-peer event for a directly-bonded sender.
    async fn admit(&mut self, sender: SocketAddr, tcp_port: u32, node_id: Vec<u8>) {
        let entry = TableEntry {
            ip: ip_bytes(sender.ip()),
            udp_port: sender.port(),
            tcp_port,
            node_id,
            last_seen_ms: now_ms(),
        };
        self.emit(entry).await;
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
        self.send_ping(addr).await;
        let self_target = self.key.public_key_bytes().to_vec();
        self.send_find_node(addr, &self_target).await;
    }

    /// 15 s refresh: empty table → re-ping bootnodes; else FindNode-self to
    /// bootnodes + ping-then-FindNode(random target) to ≤ 10 random peers.
    async fn refresh(&mut self) {
        let peers = self
            .table
            .lock()
            .map(|t| t.all_peers())
            .unwrap_or_default();
        tracing::debug!(table = peers.len(), "discv4 refresh");
        if peers.is_empty() {
            for bootnode in self.bootnodes.clone() {
                self.send_ping(bootnode).await;
            }
            return;
        }
        let self_target = self.key.public_key_bytes().to_vec();
        for bootnode in self.bootnodes.clone() {
            self.send_find_node(bootnode, &self_target).await;
        }
        let mut random_target = [0u8; 64];
        let _ = getrandom::getrandom(&mut random_target);
        for entry in sample(&peers, 10) {
            let Some(addr) = to_socket_addr(&entry.ip, entry.udp_port) else {
                continue;
            };
            self.send_ping(addr).await;
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
        self.pending_pings.insert(to, hash);
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
}
