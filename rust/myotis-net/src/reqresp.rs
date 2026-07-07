//! libp2p transport + eth2 req/resp dialer/responder.
//!
//! Mirrors the behavior (not the structure) of the Java `BeaconP2PService`:
//! TCP + noise XX + yamux with a secp256k1 identity (the CL spec requirement),
//! per-protocol req/resp streams where the dialer writes the request, half-closes,
//! and buffers the response until the responder closes, and minimal responder
//! roles for status/ping/metadata/goodbye (peers drop clients that don't answer
//! those). The `light_client_*` read protocols answer `ResourceUnavailable` —
//! the Java relays from a response cache when warm; empty-cache behavior is the
//! same result code.
//!
//! Requests and responses cross this module as RAW WIRE BYTES ([`crate::codec`]
//! frames); parsing/validation happens in the sync layer. An empty request means
//! "write nothing, just half-close" (finality/optimistic — see `requestFinalityUpdate`).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::identify;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm};
use tokio::sync::{mpsc, oneshot};

use crate::codec;
use crate::protocols;
use crate::status::{self, StatusMessage};

/// Response deadline mirroring the Java RESP_TIMEOUT (~10 s) for single-chunk
/// protocols; updates_by_range gets the Java catch-up deadline (15 s) — live
/// peers cap those responses at one chunk per request anyway (Lighthouse's
/// one_every(10s) quota), so waiting longer buys nothing.
pub const RESP_TIMEOUT: Duration = Duration::from_secs(10);
/// Live servers PACE multi-chunk responses (observed: single chunks arriving
/// ~10 s apart under Lighthouse's rate limiter) — a short deadline turns a
/// multi-chunk response into a 1-chunk one. This is the libp2p behaviour-level
/// deadline: when IT fires, everything the codec buffered is dropped and the
/// peer is charged a failure. A full 128-update batch cannot fit here for a
/// paced or slow-link server, which is why the codec completes the read at
/// UPDATES_READ_BUDGET with whatever whole chunks arrived — this timeout only
/// fires when a peer sent NOTHING for the whole window. Sized so the budget
/// below can cover a full 128-chunk batch (~3.5 MiB) on a ~65 KB/s link; the
/// extra 15 s over the old 45 s only lengthens rounds where NO peer serves.
pub const UPDATES_TIMEOUT: Duration = Duration::from_secs(60);
/// Total read budget for an updates_by_range response, deliberately under
/// UPDATES_TIMEOUT: when it expires with data buffered, the read completes and
/// the complete chunks are used (a paced ~10 s/chunk server yields ~5 periods
/// per round instead of a behaviour timeout that loses all of them AND
/// strike-marks the serving peer toward cache eviction). The clock starts at
/// request time, NOT at the first byte — it shadows the behaviour timeout,
/// so server think time before the first chunk spends the same budget.
const UPDATES_READ_BUDGET: Duration = Duration::from_secs(55);

/// Complete a response once the stream has gone quiet for this long with data
/// buffered — the Rust twin of the Java controller's safety/drain timers.
/// Responders SHOULD close after the last chunk, but some stall the close;
/// waiting only for EOF would burn the whole request timeout instead.
const RESPONSE_QUIET_WINDOW: Duration = Duration::from_secs(3);
/// Multi-chunk (updates_by_range) quiet window: healthy responders stream
/// chunks back-to-back; observed live behavior is one chunk per request from
/// rate-limited peers, where waiting longer buys nothing — the sync loop
/// rotates peers instead.
/// Must comfortably exceed the observed inter-chunk pacing (~10 s) or the
/// quiet window truncates paced batches to their first chunk.
const UPDATES_QUIET_WINDOW: Duration = Duration::from_secs(12);

const MAX_REQUEST_WIRE_BYTES: usize = 1024;
/// A full 128-update batch is ~3.5 MiB on the wire (~128 x ~60 KB SSZ
/// uncompressed). 16 MiB is a generous DoS ceiling, not a target.
const MAX_RESPONSE_WIRE_BYTES: usize = 16 * 1024 * 1024;

// -------------------------------------------------------------------------
// Codec: raw wire bytes in, raw wire bytes out
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Eth2Protocol(pub StreamProtocol);

impl AsRef<str> for Eth2Protocol {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Clone, Default)]
pub struct Eth2Codec;

async fn read_capped<T>(io: &mut T, cap: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    io.take(cap as u64 + 1).read_to_end(&mut buf).await?;
    if buf.len() > cap {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response exceeds size cap"));
    }
    Ok(buf)
}

/// Read to EOF, but once at least one byte is buffered treat `quiet` of
/// silence as end-of-response; also salvage buffered data when the peer
/// resets the stream instead of half-closing. `budget`, when set, bounds the
/// TOTAL read time measured from entry (mirroring the behaviour timeout it
/// runs under — pre-first-byte server think time spends it too): when it
/// expires with data buffered, the read completes with what arrived instead
/// of running into the behaviour-level request timeout, which would discard
/// the buffer and charge the peer a failure. With nothing buffered the read
/// keeps waiting — a wholly unresponsive peer is left to the behaviour
/// timeout, which is the failure signal eviction accounting keys off.
async fn read_until_quiet<T>(
    io: &mut T,
    cap: usize,
    quiet: Duration,
    budget: Option<Duration>,
) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let deadline = budget.map(|b| tokio::time::Instant::now() + b);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        // The quiet window only means anything once bytes are buffered (it
        // detects "peer finished a paced response without closing"). Before the
        // first byte, await the read with NO per-iteration timer — the
        // behaviour-level request timeout is the deadline — instead of respawning
        // a `quiet`-length timer every window while a slow peer spins up.
        let read = if buf.is_empty() {
            io.read(&mut chunk).await.map(Some)
        } else {
            let mut wake_at = tokio::time::Instant::now() + quiet;
            if let Some(d) = deadline {
                wake_at = wake_at.min(d);
            }
            match tokio::time::timeout_at(wake_at, io.read(&mut chunk)).await {
                Ok(r) => r.map(Some),
                // Quiet with data buffered — or total budget spent — → complete.
                Err(_elapsed) => Ok(None),
            }
        };
        match read {
            Ok(Some(0)) => break,
            Ok(Some(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "response exceeds size cap",
                    ));
                }
            }
            Ok(None) => break, // quiet window elapsed with data buffered
            Err(e) => {
                if buf.is_empty() {
                    return Err(e);
                }
                tracing::debug!(buffered = buf.len(), error = %e,
                    "stream errored after data — salvaging buffered response");
                break;
            }
        }
    }
    Ok(buf)
}

#[async_trait]
impl request_response::Codec for Eth2Codec {
    type Protocol = Eth2Protocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _p: &Eth2Protocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        // The requester half-closes after writing, so EOF delimits the request.
        read_capped(io, MAX_REQUEST_WIRE_BYTES).await
    }

    async fn read_response<T>(&mut self, p: &Eth2Protocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        // eth2 responders write their chunk(s) then close. Buffer until EOF,
        // completing early when the stream goes quiet with data on hand —
        // mirroring the Java controller's drain timers (and salvaging complete
        // chunks when a peer resets instead of closing; the codec validates
        // everything downstream).
        let (quiet, budget) = if p.as_ref() == protocols::UPDATES_BY_RANGE {
            // Budgeted: a full 128-update batch from a paced or slow-link
            // server can outlast UPDATES_TIMEOUT; completing at the budget
            // keeps the chunks that DID arrive (single-chunk protocols fit
            // their behaviour timeout trivially and need no budget).
            (UPDATES_QUIET_WINDOW, Some(UPDATES_READ_BUDGET))
        } else {
            (RESPONSE_QUIET_WINDOW, None)
        };
        read_until_quiet(io, MAX_RESPONSE_WIRE_BYTES, quiet, budget).await
    }

    async fn write_request<T>(&mut self, _p: &Eth2Protocol, io: &mut T, req: Vec<u8>) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Empty request = write NOTHING (finality/optimistic), then the handler
        // half-closes — mirroring the Java doReqResp empty-payload path.
        if !req.is_empty() {
            io.write_all(&req).await?;
        }
        Ok(())
    }

    async fn write_response<T>(&mut self, _p: &Eth2Protocol, io: &mut T, res: Vec<u8>) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&res).await
    }
}

// -------------------------------------------------------------------------
// Behaviour: one request_response instance per protocol (each eth2 protocol
// negotiates independently; a single multi-protocol instance would offer every
// protocol on every outbound stream)
// -------------------------------------------------------------------------

type RR = request_response::Behaviour<Eth2Codec>;

fn rr(protocol: &'static str, support: ProtocolSupport, timeout: Duration) -> RR {
    request_response::Behaviour::with_codec(
        Eth2Codec,
        [(Eth2Protocol(StreamProtocol::new(protocol)), support)],
        request_response::Config::default()
            .with_request_timeout(timeout)
            .with_max_concurrent_streams(64),
    )
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    // Defense-in-depth: this client dials but also accepts inbound, and each
    // protocol behaviour independently permits concurrent streams. Cap total
    // established connections so a peer flood can't exhaust fds/memory.
    pub limits: connection_limits::Behaviour,
    pub identify: identify::Behaviour,
    pub status_v2: RR,
    pub status_v1: RR,
    pub ping: RR,
    pub metadata: RR,
    pub goodbye: RR,
    pub bootstrap: RR,
    pub updates: RR,
    pub finality: RR,
    pub optimistic: RR,
}

impl Behaviour {
    fn new(local_public_key: libp2p::identity::PublicKey) -> Self {
        Self {
            limits: connection_limits::Behaviour::new(
                ConnectionLimits::default()
                    .with_max_established_incoming(Some(64))
                    .with_max_established_per_peer(Some(2))
                    .with_max_pending_incoming(Some(16)),
            ),
            identify: identify::Behaviour::new(
                identify::Config::new("eth2/1.0.0".into(), local_public_key)
                    .with_agent_version("myotis/0.1.0-rs".into()),
            ),
            status_v2: rr(protocols::STATUS_V2, ProtocolSupport::Full, RESP_TIMEOUT),
            status_v1: rr(protocols::STATUS_V1, ProtocolSupport::Full, RESP_TIMEOUT),
            ping: rr(protocols::PING, ProtocolSupport::Full, RESP_TIMEOUT),
            metadata: rr(protocols::METADATA_V2, ProtocolSupport::Full, RESP_TIMEOUT),
            goodbye: rr(protocols::GOODBYE, ProtocolSupport::Full, RESP_TIMEOUT),
            bootstrap: rr(protocols::BOOTSTRAP, ProtocolSupport::Full, RESP_TIMEOUT),
            // Never advertised inbound: we can't serve catch-up history, and the
            // Java learned that advertising unservable protocols gets us
            // goodbye'd ("durationMs=1 closes in the wild").
            updates: rr(protocols::UPDATES_BY_RANGE, ProtocolSupport::Outbound, UPDATES_TIMEOUT),
            finality: rr(protocols::FINALITY_UPDATE, ProtocolSupport::Full, RESP_TIMEOUT),
            optimistic: rr(protocols::OPTIMISTIC_UPDATE, ProtocolSupport::Full, RESP_TIMEOUT),
        }
    }
}

// -------------------------------------------------------------------------
// Service handle
// -------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// Peer doesn't speak the protocol (negotiation failed) — the signal the
    /// Java uses to blacklist a peer for updates_by_range.
    UnsupportedProtocol,
    Timeout,
    DialFailure,
    ConnectionClosed,
    Io(String),
    /// The service shut down before the request completed.
    Shutdown,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProtocol => write!(f, "protocol negotiation failed"),
            Self::Timeout => write!(f, "request timed out"),
            Self::DialFailure => write!(f, "dial failed"),
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Shutdown => write!(f, "service shut down"),
        }
    }
}
impl std::error::Error for RequestError {}

enum Command {
    Request {
        peer: PeerId,
        addr: Multiaddr,
        protocol: &'static str,
        wire: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, RequestError>>,
    },
    PeerCount {
        reply: oneshot::Sender<usize>,
    },
    /// Peers whose Identify advertised light_client_updates_by_range.
    LcServers {
        reply: oneshot::Sender<HashSet<PeerId>>,
    },
    Shutdown,
}

/// Cheap-to-clone client for issuing eth2 req/resp calls against the running
/// swarm task. Independent instances of the whole stack are independent — no
/// globals anywhere in this crate.
#[derive(Clone)]
pub struct ReqRespClient {
    tx: mpsc::Sender<Command>,
}

impl ReqRespClient {
    /// One request against `peer` (dialing `addr` if not connected): sends the
    /// pre-encoded wire bytes, returns the raw wire response.
    pub async fn request_raw(
        &self,
        peer: PeerId,
        addr: Multiaddr,
        protocol: &'static str,
        wire: Vec<u8>,
    ) -> Result<Vec<u8>, RequestError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Request { peer, addr, protocol, wire, reply })
            .await
            .map_err(|_| RequestError::Shutdown)?;
        rx.await.map_err(|_| RequestError::Shutdown)?
    }

    pub async fn connected_peer_count(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::PeerCount { reply }).await.is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Peers whose Identify response advertised `light_client_updates_by_range`.
    pub async fn lc_update_servers(&self) -> HashSet<PeerId> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::LcServers { reply }).await.is_err() {
            return HashSet::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn shutdown(&self) {
        let _ = self.tx.send(Command::Shutdown).await;
    }
}

/// Shared local view the responder answers from. The sync loop refreshes it as
/// the store advances so our Status stays honest (Lighthouse's relevance check
/// requires a real block root — see the Java `buildLocalStatusFor` doc).
pub struct LocalStatus {
    inner: Mutex<StatusMessage>,
}

impl LocalStatus {
    pub fn new(initial: StatusMessage) -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(initial) })
    }
    pub fn set(&self, s: StatusMessage) {
        *self.inner.lock().expect("status lock") = s;
    }
    pub fn get(&self) -> StatusMessage {
        self.inner.lock().expect("status lock").clone()
    }
}

/// Start the libp2p host and its event-loop task. Returns the request client;
/// the task exits on [`ReqRespClient::shutdown`] (or when every client is dropped).
pub fn start_host(local_status: Arc<LocalStatus>) -> Result<ReqRespClient, String> {
    // Ethereum CL spec requires secp256k1 identity keys (same as the Java
    // HostBuilder's KeyType.SECP256K1) — the default ed25519 would make some
    // peers reject the noise handshake payload.
    let keypair = libp2p::identity::Keypair::generate_secp256k1();
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| format!("tcp/noise/yamux setup failed: {e}"))?
        .with_behaviour(|key| Behaviour::new(key.public()))
        .map_err(|e| format!("behaviour setup failed: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    // Listen on an ephemeral port: some peers reject dial-only hosts (same
    // reason the Java host listens on /ip4/0.0.0.0/tcp/0).
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("static multiaddr"))
        .map_err(|e| format!("listen failed: {e}"))?;

    tracing::info!(peer_id = %swarm.local_peer_id(), "libp2p host starting");

    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(run_swarm(swarm, rx, local_status));
    Ok(ReqRespClient { tx })
}

/// What a pending outbound request id maps back to.
enum Pending {
    External(oneshot::Sender<Result<Vec<u8>, RequestError>>),
    /// Fire-and-forget auto-Status (v2, falls back to v1 on unsupported protocol).
    AutoStatusV2(PeerId),
    AutoStatusV1(PeerId),
}

/// A request parked until the peer's Status handshake completes.
struct QueuedRequest {
    addr: Multiaddr,
    protocol: &'static str,
    wire: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, RequestError>>,
}

struct SwarmCtx {
    pending: HashMap<OutboundRequestId, Pending>,
    connected: HashSet<PeerId>,
    /// Peers whose spec-required first Status exchange has completed (either
    /// way). Requests to peers not in this set are parked in `queued` —
    /// opening a light_client stream before Status completes gets the whole
    /// connection dropped by Lighthouse/Teku (see the Java autoStatus doc).
    status_done: HashSet<PeerId>,
    queued: HashMap<PeerId, Vec<QueuedRequest>>,
    lc_servers: HashSet<PeerId>,
    local_status: Arc<LocalStatus>,
}

async fn run_swarm(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Command>,
    local_status: Arc<LocalStatus>,
) {
    let mut ctx = SwarmCtx {
        pending: HashMap::new(),
        connected: HashSet::new(),
        status_done: HashSet::new(),
        queued: HashMap::new(),
        lc_servers: HashSet::new(),
        local_status,
    };
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None | Some(Command::Shutdown) => {
                    for (_, p) in ctx.pending.drain() {
                        if let Pending::External(reply) = p {
                            let _ = reply.send(Err(RequestError::Shutdown));
                        }
                    }
                    for (_, queue) in ctx.queued.drain() {
                        for q in queue {
                            let _ = q.reply.send(Err(RequestError::Shutdown));
                        }
                    }
                    tracing::info!("libp2p host stopping");
                    return;
                }
                Some(Command::Request { peer, addr, protocol, wire, reply }) => {
                    submit_request(&mut swarm, &mut ctx, peer, addr, protocol, wire, reply);
                }
                Some(Command::PeerCount { reply }) => {
                    let _ = reply.send(ctx.connected.len());
                }
                Some(Command::LcServers { reply }) => {
                    let _ = reply.send(ctx.lc_servers.clone());
                }
            },
            event = swarm.select_next_some() => handle_swarm_event(&mut swarm, &mut ctx, event),
        }
    }
}

/// Dispatch an external request. Peers that haven't completed the
/// spec-required first Status exchange get the request PARKED until the
/// auto-Status settles — Lighthouse/Teku drop connections whose first inbound
/// stream isn't Status, which is exactly what a raced dial+request produces.
fn submit_request(
    swarm: &mut Swarm<Behaviour>,
    ctx: &mut SwarmCtx,
    peer: PeerId,
    addr: Multiaddr,
    protocol: &'static str,
    wire: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, RequestError>>,
) {
    if ctx.status_done.contains(&peer) {
        let Some(rr) = behaviour_for(swarm, protocol) else {
            let _ = reply.send(Err(RequestError::Io(format!("unknown protocol {protocol}"))));
            return;
        };
        let id = rr.send_request_with_addresses(&peer, wire, vec![addr]);
        ctx.pending.insert(id, Pending::External(reply));
        return;
    }

    ctx.queued
        .entry(peer)
        .or_default()
        .push(QueuedRequest { addr: addr.clone(), protocol, wire, reply });
    if !ctx.connected.contains(&peer) {
        use libp2p::swarm::dial_opts::DialOpts;
        let opts = DialOpts::peer_id(peer).addresses(vec![addr]).build();
        match swarm.dial(opts) {
            Ok(()) => {}
            // Already dialing / connecting — the queued request rides along.
            Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {}
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "dial failed");
                fail_queued(ctx, &peer, RequestError::DialFailure);
            }
        }
    }
}

fn behaviour_for<'a>(swarm: &'a mut Swarm<Behaviour>, protocol: &str) -> Option<&'a mut RR> {
    let behaviour = swarm.behaviour_mut();
    Some(match protocol {
        protocols::STATUS_V2 => &mut behaviour.status_v2,
        protocols::STATUS_V1 => &mut behaviour.status_v1,
        protocols::PING => &mut behaviour.ping,
        protocols::METADATA_V2 => &mut behaviour.metadata,
        protocols::GOODBYE => &mut behaviour.goodbye,
        protocols::BOOTSTRAP => &mut behaviour.bootstrap,
        protocols::UPDATES_BY_RANGE => &mut behaviour.updates,
        protocols::FINALITY_UPDATE => &mut behaviour.finality,
        protocols::OPTIMISTIC_UPDATE => &mut behaviour.optimistic,
        _ => return None,
    })
}

fn fail_queued(ctx: &mut SwarmCtx, peer: &PeerId, error: RequestError) {
    if let Some(queue) = ctx.queued.remove(peer) {
        for q in queue {
            let _ = q.reply.send(Err(error.clone()));
        }
    }
}

/// The peer's Status handshake settled (either way): release its parked requests.
fn mark_status_done(swarm: &mut Swarm<Behaviour>, ctx: &mut SwarmCtx, peer: PeerId) {
    ctx.status_done.insert(peer);
    let Some(queue) = ctx.queued.remove(&peer) else { return };
    for q in queue {
        let Some(rr) = behaviour_for(swarm, q.protocol) else {
            let _ = q.reply.send(Err(RequestError::Io(format!("unknown protocol {}", q.protocol))));
            continue;
        };
        let id = rr.send_request_with_addresses(&peer, q.wire, vec![q.addr]);
        ctx.pending.insert(id, Pending::External(q.reply));
    }
}

fn handle_swarm_event(swarm: &mut Swarm<Behaviour>, ctx: &mut SwarmCtx, event: SwarmEvent<BehaviourEvent>) {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            let newly = ctx.connected.insert(peer_id);
            tracing::debug!(peer = %peer_id, remote = %endpoint.get_remote_address(),
                "connection established");
            if newly {
                // CL p2p spec: Status MUST be the first req/resp on a new
                // connection; clients drop peers that skip it (see autoStatus
                // in the Java service). v2 first, v1 fallback on negotiation
                // failure. Parked requests flush when it settles.
                let wire = codec::encode_request(&ctx.local_status.get().encode());
                let id = swarm.behaviour_mut().status_v2.send_request(&peer_id, wire);
                ctx.pending.insert(id, Pending::AutoStatusV2(peer_id));
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            if num_established == 0 {
                ctx.connected.remove(&peer_id);
                // Next connection must redo the Status handshake.
                ctx.status_done.remove(&peer_id);
                fail_queued(ctx, &peer_id, RequestError::ConnectionClosed);
                tracing::debug!(peer = %peer_id, "connection closed");
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
            tracing::debug!(peer = %peer_id, error = %error, "outgoing connection failed");
            fail_queued(ctx, &peer_id, RequestError::DialFailure);
        }
        SwarmEvent::Behaviour(be) => handle_behaviour_event(swarm, ctx, be),
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::debug!(%address, "listening");
        }
        _ => {}
    }
}

fn handle_behaviour_event(swarm: &mut Swarm<Behaviour>, ctx: &mut SwarmCtx, event: BehaviourEvent) {
    use BehaviourEvent as E;
    match event {
        E::Identify(identify::Event::Received { peer_id, info, .. }) => {
            let lc = info
                .protocols
                .iter()
                .any(|p| p.as_ref().contains("light_client_updates_by_range"));
            if lc {
                ctx.lc_servers.insert(peer_id);
            }
            tracing::debug!(peer = %peer_id, agent = %info.agent_version,
                protocols = info.protocols.len(), lc_updates = lc, "identify received");
        }
        E::Identify(_) => {}
        E::StatusV2(ev) => on_rr_event(swarm, ctx, protocols::STATUS_V2, ev),
        E::StatusV1(ev) => on_rr_event(swarm, ctx, protocols::STATUS_V1, ev),
        E::Ping(ev) => on_rr_event(swarm, ctx, protocols::PING, ev),
        E::Metadata(ev) => on_rr_event(swarm, ctx, protocols::METADATA_V2, ev),
        E::Goodbye(ev) => on_rr_event(swarm, ctx, protocols::GOODBYE, ev),
        E::Bootstrap(ev) => on_rr_event(swarm, ctx, protocols::BOOTSTRAP, ev),
        E::Updates(ev) => on_rr_event(swarm, ctx, protocols::UPDATES_BY_RANGE, ev),
        E::Finality(ev) => on_rr_event(swarm, ctx, protocols::FINALITY_UPDATE, ev),
        E::Optimistic(ev) => on_rr_event(swarm, ctx, protocols::OPTIMISTIC_UPDATE, ev),
    }
}

type RrEvent = request_response::Event<Vec<u8>, Vec<u8>>;

fn on_rr_event(swarm: &mut Swarm<Behaviour>, ctx: &mut SwarmCtx, protocol: &'static str, event: RrEvent) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Response { request_id, response } => {
                complete(ctx, swarm, request_id, peer, Ok(response));
            }
            request_response::Message::Request { request, channel, .. } => {
                let response = respond_inbound(ctx, protocol, peer, &request);
                let behaviour = swarm.behaviour_mut();
                let rr = match protocol {
                    protocols::STATUS_V2 => &mut behaviour.status_v2,
                    protocols::STATUS_V1 => &mut behaviour.status_v1,
                    protocols::PING => &mut behaviour.ping,
                    protocols::METADATA_V2 => &mut behaviour.metadata,
                    protocols::GOODBYE => &mut behaviour.goodbye,
                    protocols::BOOTSTRAP => &mut behaviour.bootstrap,
                    protocols::FINALITY_UPDATE => &mut behaviour.finality,
                    protocols::OPTIMISTIC_UPDATE => &mut behaviour.optimistic,
                    _ => return, // updates_by_range is outbound-only
                };
                if rr.send_response(channel, response).is_err() {
                    tracing::debug!(peer = %peer, protocol, "inbound response channel closed");
                }
            }
        },
        request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
            let mapped = match &error {
                request_response::OutboundFailure::Timeout => RequestError::Timeout,
                request_response::OutboundFailure::UnsupportedProtocols => {
                    RequestError::UnsupportedProtocol
                }
                request_response::OutboundFailure::DialFailure => RequestError::DialFailure,
                request_response::OutboundFailure::ConnectionClosed => {
                    RequestError::ConnectionClosed
                }
                other => RequestError::Io(other.to_string()),
            };
            tracing::debug!(peer = %peer, protocol, error = %error, "outbound failure");
            complete(ctx, swarm, request_id, peer, Err(mapped));
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            tracing::debug!(peer = %peer, protocol, error = %error, "inbound failure");
        }
        request_response::Event::ResponseSent { .. } => {}
    }
}

fn complete(
    ctx: &mut SwarmCtx,
    swarm: &mut Swarm<Behaviour>,
    request_id: OutboundRequestId,
    _peer: PeerId,
    result: Result<Vec<u8>, RequestError>,
) {
    match ctx.pending.remove(&request_id) {
        Some(Pending::External(reply)) => {
            let _ = reply.send(result);
        }
        Some(Pending::AutoStatusV2(peer_id)) => match result {
            Ok(raw) => {
                log_peer_status("v2", peer_id, &raw);
                mark_status_done(swarm, ctx, peer_id);
            }
            Err(RequestError::UnsupportedProtocol) => {
                // v1-only peer (Nimbus bucket in the Java notes) — fall back.
                let local = ctx.local_status.get();
                let wire = codec::encode_request(&local.encode_v1());
                let id = swarm.behaviour_mut().status_v1.send_request(&peer_id, wire);
                ctx.pending.insert(id, Pending::AutoStatusV1(peer_id));
            }
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "auto-status v2 failed");
                // Settled (failed) — release parked requests rather than
                // starving them; the peer may still serve other protocols.
                mark_status_done(swarm, ctx, peer_id);
            }
        },
        Some(Pending::AutoStatusV1(peer_id)) => {
            match result {
                Ok(raw) => log_peer_status("v1", peer_id, &raw),
                Err(e) => tracing::debug!(peer = %peer_id, error = %e, "auto-status v1 failed"),
            }
            mark_status_done(swarm, ctx, peer_id);
        }
        None => {}
    }
}

fn log_peer_status(version: &str, peer: PeerId, raw: &[u8]) {
    match codec::decode_response(raw, false) {
        Ok(d) => {
            let decoded = if version == "v2" {
                StatusMessage::decode(&d.ssz_payload)
            } else {
                StatusMessage::decode_v1(&d.ssz_payload)
            };
            match decoded {
                Ok(s) => tracing::debug!(peer = %peer, version,
                    fork_digest = %hex4(&s.fork_digest),
                    finalized_epoch = s.finalized_epoch, head_slot = s.head_slot,
                    earliest = s.earliest_available_slot, "auto-status ok"),
                Err(e) => tracing::debug!(peer = %peer, version, error = %e,
                    "auto-status decode failed"),
            }
        }
        Err(e) => tracing::debug!(peer = %peer, version, error = %e, "auto-status frame invalid"),
    }
}

fn hex4(b: &[u8; 4]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
}

/// Serve a peer-initiated request, mirroring the Java responder handlers:
/// status → our current Status; ping/goodbye → echo; metadata → light-client
/// zeros; light_client_* → ResourceUnavailable (no relay cache in this stage).
fn respond_inbound(ctx: &SwarmCtx, protocol: &'static str, peer: PeerId, raw: &[u8]) -> Vec<u8> {
    let expected = protocols::expected_request_size(protocol);
    let req_ssz: Vec<u8> = if expected == 0 {
        Vec::new()
    } else {
        match codec::parse_request_ssz(raw) {
            Some(ssz) => ssz,
            None => {
                return codec::encode_error_response(
                    codec::RESULT_INVALID_REQUEST,
                    "InvalidRequest: unparseable body",
                )
            }
        }
    };

    match protocol {
        protocols::STATUS_V2 => {
            let local = ctx.local_status.get();
            codec::encode_success_response(&local.encode(), None)
        }
        protocols::STATUS_V1 => {
            let local = ctx.local_status.get();
            codec::encode_success_response(&local.encode_v1(), None)
        }
        protocols::PING => {
            let body: &[u8] = if req_ssz.len() == 8 { &req_ssz } else { &[0u8; 8] };
            codec::encode_success_response(body, None)
        }
        protocols::METADATA_V2 => {
            codec::encode_success_response(&status::metadata_v2_light_client(), None)
        }
        protocols::GOODBYE => {
            let reason = if req_ssz.len() == 8 {
                u64::from_le_bytes(req_ssz[..8].try_into().expect("length checked"))
            } else {
                0
            };
            tracing::info!(peer = %peer, reason, "peer sent goodbye");
            let body: &[u8] = if req_ssz.len() == 8 { &req_ssz } else { &[0u8; 8] };
            codec::encode_success_response(body, None)
        }
        // No relay cache yet: same observable result as the Java handlers on a
        // cold cache — ResourceUnavailable, "ask someone else".
        _ => codec::encode_error_response(codec::RESULT_RESOURCE_UNAVAILABLE, "ResourceUnavailable"),
    }
}
