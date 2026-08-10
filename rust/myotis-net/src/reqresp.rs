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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::identify;
use libp2p::request_response::{self, InboundRequestId, OutboundRequestId, ProtocolSupport};
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

/// Ceiling on response bytes queued but not yet written, across ALL inbound
/// connections.
///
/// Per-request bounds (`MAX_REQUEST_LIGHT_CLIENT_UPDATES`, response byte caps)
/// say nothing about how many responses can be in flight at once, and the two
/// are very different numbers on a public responder: a full updates_by_range
/// body is ~3.4 MiB built from a 16-byte request, held until written or until
/// UPDATES_TIMEOUT (60 s) expires. One peer opening its permitted connections,
/// filling its concurrent streams and then not reading would otherwise pin
/// hundreds of MiB for a minute at a cost to itself of a couple of KiB.
///
/// Over budget we answer ResourceUnavailable, which is already the correct
/// "ask someone else" answer and costs the caller nothing to retry.
const MAX_IN_FLIGHT_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Concurrent inbound streams per connection for `updates_by_range` when
/// serving. A wallet catching up needs one at a time; 64 (the default for the
/// cheap protocols) only multiplies the in-flight ceiling above.
const SERVING_UPDATES_MAX_STREAMS: usize = 4;

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
    rr_with_streams(protocol, support, timeout, 64)
}

fn rr_with_streams(
    protocol: &'static str,
    support: ProtocolSupport,
    timeout: Duration,
    max_streams: usize,
) -> RR {
    request_response::Behaviour::with_codec(
        Eth2Codec,
        [(Eth2Protocol(StreamProtocol::new(protocol)), support)],
        request_response::Config::default()
            .with_request_timeout(timeout)
            .with_max_concurrent_streams(max_streams),
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
    /// `serving` ⇒ this host answers the light-client protocols, so
    /// `updates_by_range` is advertised inbound as well as outbound.
    fn new(
        local_public_key: libp2p::identity::PublicKey,
        serving: bool,
        max_established_incoming: Option<u32>,
    ) -> Self {
        Self {
            limits: connection_limits::Behaviour::new(
                ConnectionLimits::default()
                    .with_max_established_incoming(max_established_incoming)
                    // A server sees many wallets behind one NAT, and a wallet
                    // opening a second connection is normal; the per-peer cap
                    // is about a single peer monopolising us, not about volume.
                    .with_max_established_per_peer(Some(2))
                    .with_max_pending_incoming(Some(if serving { 256 } else { 16 })),
            ),
            identify: identify::Behaviour::new(
                identify::Config::new("eth2/1.0.0".into(), local_public_key)
                    .with_agent_version("myotis/0.1.5-rs".into()),
            ),
            status_v2: rr(protocols::STATUS_V2, ProtocolSupport::Full, RESP_TIMEOUT),
            status_v1: rr(protocols::STATUS_V1, ProtocolSupport::Full, RESP_TIMEOUT),
            ping: rr(protocols::PING, ProtocolSupport::Full, RESP_TIMEOUT),
            metadata: rr(protocols::METADATA_V2, ProtocolSupport::Full, RESP_TIMEOUT),
            goodbye: rr(protocols::GOODBYE, ProtocolSupport::Full, RESP_TIMEOUT),
            bootstrap: rr(protocols::BOOTSTRAP, ProtocolSupport::Full, RESP_TIMEOUT),
            // Outbound-only for a WALLET: it can't serve catch-up history, and
            // the Java learned that advertising unservable protocols gets us
            // goodbye'd ("durationMs=1 closes in the wild"). A serving host has
            // the archive that makes the advertisement honest, so it goes Full.
            updates: rr_with_streams(
                protocols::UPDATES_BY_RANGE,
                if serving {
                    ProtocolSupport::Full
                } else {
                    ProtocolSupport::Outbound
                },
                UPDATES_TIMEOUT,
                if serving { SERVING_UPDATES_MAX_STREAMS } else { 64 },
            ),
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
        /// The DNS name these candidates came from, if any — logging only.
        dns_name: Option<String>,
        /// Dial candidates in RESOLVER ORDER — a DNS name expands to every
        /// address it resolves to, and order is load-bearing (see
        /// [`resolve_dial_addrs`]).
        addrs: Vec<Multiaddr>,
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
    /// The externally observed address, once EXTERNAL_ADDR_QUORUM peers agree.
    ExternalAddress {
        reply: oneshot::Sender<Option<ExternalAddress>>,
    },
    /// Dial peers purely to collect Identify observations of our own address.
    /// Fire-and-forget: nothing is requested and no reply is sent, because the
    /// answer arrives asynchronously as `observed_ips` and is read later via
    /// [`Command::ExternalAddress`].
    Observe {
        peers: Vec<(PeerId, Multiaddr)>,
    },
    /// One snapshot of both catch-up peer-selection inputs — the LC-server set
    /// and the per-peer `earliest_available_slot` map — so a round fetches them
    /// in a single swarm round-trip instead of two.
    CatchupMeta {
        reply: oneshot::Sender<(HashSet<PeerId>, HashMap<PeerId, u64>)>,
    },
    Shutdown,
}

/// Cheap-to-clone client for issuing eth2 req/resp calls against the running
/// swarm task. Independent instances of the whole stack are independent — no
/// globals anywhere in this crate.
#[derive(Clone)]
pub struct ReqRespClient {
    tx: mpsc::Sender<Command>,
    /// Last answer seen per DNS name, so repeat resolutions can log at DEBUG
    /// while a CHANGE still logs at INFO.
    ///
    /// Per-instance, not a global: independent stacks stay independent, which is
    /// this crate's standing rule. Bounded by the number of distinct pinned
    /// names, which is a handful.
    last_resolved: Arc<std::sync::Mutex<HashMap<String, Vec<IpAddr>>>>,
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
        // Resolve HERE, per request, in async context. The swarm task's dial
        // path is synchronous, so it cannot await a lookup — and libp2p's own
        // DNS transport is not always present (Android has no /etc/resolv.conf,
        // so `build_swarm` falls back to plain TCP and a /dns4/ address is
        // rejected outright with "Multiaddr is not supported").
        let dns_name = multiaddr_dns_name(&addr).map(|n| n.to_string());
        // Never empty: a resolver failure yields the original address, so an
        // already-connected peer is unaffected by a transient DNS blip.
        let addrs = resolve_dial_addrs(&addr, &self.last_resolved).await;
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Request { peer, dns_name, addrs, protocol, wire, reply })
            .await
            .map_err(|_| RequestError::Shutdown)?;
        rx.await.map_err(|_| RequestError::Shutdown)?
    }

    /// The address peers say they see us on, once at least
    /// [`EXTERNAL_ADDR_QUORUM`] distinct peers agree on it.
    ///
    /// `None` until enough peers have reported — which is the honest answer, not
    /// a failure: a server with too few connections genuinely does not know its
    /// own address, and acting on a guess is how a published record ends up
    /// pointing somewhere dead.
    /// Dial `peers` for the sole purpose of learning our own external address.
    ///
    /// A host that only ever ACCEPTS connections never learns this. Identify
    /// reports what the remote observes about us, so it takes a connection to
    /// produce one — and [`external_address`](Self::external_address) needs
    /// [`EXTERNAL_ADDR_QUORUM`] of them from distinct source IPs. A wallet gets
    /// these for free from the peers it syncs against; a pure server
    /// (`rust/roost`) has no such traffic and would sit below quorum forever.
    ///
    /// The observations are BOUNDED BY THE CONNECTION: they are dropped when it
    /// closes, and idle connections close after 120s. So this establishes a
    /// quorum that is momentary by design, not a standing one. Callers should
    /// re-probe on a cadence and treat a `None` from `external_address` as "no
    /// fresh reading", not as "the address is gone".
    ///
    /// Fire-and-forget: dial failures are logged, not returned. Probing is a
    /// best-effort background concern and must never fail a caller's real work.
    pub async fn observe_via(&self, peers: Vec<(PeerId, Multiaddr)>) {
        if peers.is_empty() {
            return;
        }
        let _ = self.tx.send(Command::Observe { peers }).await;
    }

    pub async fn external_address(&self) -> Option<ExternalAddress> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::ExternalAddress { reply }).await.is_err() {
            return None;
        }
        rx.await.ok().flatten()
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

    /// Both catch-up peer-selection inputs in one round-trip: the set of
    /// Identify-confirmed LC servers, and `earliest_available_slot` per peer
    /// (from the auto-Status exchange). Peers absent from the earliest map
    /// haven't completed Status yet (unknown — never skipped); a v1 peer
    /// reports 0 (history from genesis).
    pub async fn catchup_peer_meta(&self) -> (HashSet<PeerId>, HashMap<PeerId, u64>) {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::CatchupMeta { reply }).await.is_err() {
            return (HashSet::new(), HashMap::new());
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

/// How many DISTINCT peers must report the same address before it is believed.
///
/// One peer's `observed_addr` is not evidence: it can lie, and a peer behind the
/// same NAT can be honestly wrong. This is the same reasoning discv5's endpoint
/// prediction uses, and the reason Geth's `--nat stun` and Nimbus's
/// `--enr-auto-update` do not act on a single report.
///
/// # What this is not
///
/// A floor against accident, **not** a defence against a determined Sybil. The
/// answer is a plurality among connected peers, so an attacker who can hold more
/// simultaneous connections than the honest peers reporting the true address can
/// move it. That is tolerable while the result is only logged; before it drives
/// a PUBLISHED ENR it wants at least one of:
///
/// - a majority of currently connected peers rather than a fixed floor,
/// - cross-checking against discv5's own endpoint prediction, which is a
///   different peer set reached over a different transport, or
/// - refusing to act on a change until it survives several rounds.
///
/// The cost of getting it wrong is reachability, not correctness: a wrong
/// address makes us undialable, it cannot make a wallet accept bad data.
pub const EXTERNAL_ADDR_QUORUM: usize = 3;

/// The address other peers say they see us on, once enough of them agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAddress {
    pub ip: IpAddr,
    /// The port reporters see, when it is meaningful — see
    /// [`ExternalAddress::port`]'s note below.
    ///
    /// Populated ONLY from inbound connections, where the reporter dialed us and
    /// their view of our port is the externally mapped one. On an outbound
    /// connection the port they see is our ephemeral source port and says
    /// nothing about where we listen, so it is discarded. A server that never
    /// dials therefore gets a real answer here, which is what makes a NAT
    /// rewriting the port detectable rather than invisible.
    pub port: Option<u16>,
    /// Distinct reporters behind the winning address.
    pub confirmations: usize,
    /// Total distinct reporters. The denominator `confirmations` is out of —
    /// without it a consumer cannot tell 3-of-3 from 3-of-200, nor implement a
    /// majority rule without a second, racing round-trip.
    pub reporters: usize,
    /// Whether the winner is an address that could actually be reached from the
    /// public internet. See [`is_routable`].
    pub routable: bool,
}

impl ExternalAddress {
    /// Whether the winner failed to clear half the reporters.
    ///
    /// A near-even split is the shape both a Sybil and a genuine mid-flight
    /// address change produce, and the tie-break makes each CALL deterministic
    /// without making the SEQUENCE stable — one more reporter can flip the
    /// winner. A consumer that publishes a record should wait rather than act on
    /// a contested answer.
    pub fn is_contested(&self) -> bool {
        self.confirmations * 2 <= self.reporters
    }
}

/// Whether an address could be reached from the public internet.
///
/// `IpAddr::is_global()` is still unstable on the pinned toolchain, so the
/// classes are spelled out. This exists because the mechanism will happily
/// establish `127.0.0.1` or `192.168.x.x` — a couple of wallets on the same LAN
/// can reach quorum before any internet peer does — and a record carrying a
/// non-routable IP fails in exactly the way publishing an address is meant to
/// prevent.
pub fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT — routable-looking, not reachable.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local
                || (v6.octets()[0] & 0xfe) == 0xfc
                // fe80::/10 link-local
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80))
        }
    }
}

/// Extract the IP from a libp2p multiaddr.
///
/// Only the IP is meaningful. Identify reports the remote address of the
/// connection as the reporter sees it, so for a connection WE dialed that is our
/// source IP with an ephemeral port — the port says nothing about where we
/// listen. Callers pair the IP with their own configured listen port.
fn multiaddr_ip(addr: &Multiaddr) -> Option<IpAddr> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(v4) => Some(IpAddr::V4(v4)),
        Protocol::Ip6(v6) => Some(IpAddr::V6(v6)),
        _ => None,
    })
}

fn multiaddr_port(addr: &Multiaddr) -> Option<u16> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

/// The DNS name in a multiaddr, if it is dialed by name rather than by address.
///
/// Used only for logging: libp2p resolves the name inside the transport, so
/// without this the operator sees a connection to an IP with no indication that
/// a name was involved, or which one — and on a dynamic address the whole point
/// is being able to see what the name currently points at.
fn multiaddr_dns_name(addr: &Multiaddr) -> Option<String> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|p| match p {
        Protocol::Dns(n) | Protocol::Dns4(n) | Protocol::Dns6(n) | Protocol::Dnsaddr(n) => {
            Some(n.to_string())
        }
        _ => None,
    })
}

/// Expand a dial address into concrete candidates, resolving any DNS component.
///
/// Returns the input unchanged when there is no name to resolve.
///
/// **Why we resolve rather than letting libp2p do it.** `build_swarm` layers in
/// libp2p's DNS transport when a system resolver is configured, but that reads
/// `/etc/resolv.conf`, which Android has not had since Oreo. There the swarm
/// falls back to plain TCP and rejects a `/dns4/` address outright — "Multiaddr
/// is not supported" — before any connection is attempted. `getaddrinfo`, which
/// `lookup_host` uses, works on every platform we ship.
///
/// **Order is load-bearing.** `getaddrinfo` already sorts by RFC 6724
/// destination-address selection, and every candidate is passed on in that
/// order. On an IPv6-only mobile network with DNS64/NAT64 the synthesized
/// `64:ff9b::/96` address sorts first and is the one that works, while the raw
/// A record is unroutable there — so preferring IPv4 by hand would break
/// exactly the networks this exists to support.
///
/// Substituting the address is safe: Noise still authenticates the remote
/// against the `/p2p/` peer id, so a wrong or hostile answer cannot impersonate
/// the pinned server — it can only fail to connect.
async fn resolve_dial_addrs(
    addr: &Multiaddr,
    last: &std::sync::Mutex<HashMap<String, Vec<IpAddr>>>,
) -> Vec<Multiaddr> {
    use libp2p::multiaddr::Protocol;
    let Some(name) = multiaddr_dns_name(addr).map(|n| n.to_string()) else {
        return vec![addr.clone()];
    };
    // Without a /tcp/ component there is nothing to rebuild around: `skip_while`
    // would consume the whole iterator and every candidate would come out a bare
    // /ip4/A — no port, no transport, no /p2p/ id — while `unwrap_or(0)` looked
    // the name up on port 0. Hand the address back untouched instead and let the
    // transport reject it on its own terms. Reaches here via /dnsaddr/ (which
    // resolves to TXT records, not A/AAAA) and via a name with no transport.
    let Some(port) = multiaddr_port(addr) else {
        return vec![addr.clone()];
    };
    let tail: Vec<Protocol> = addr
        .iter()
        .skip_while(|p| !matches!(p, Protocol::Tcp(_)))
        .map(|p| p.acquire())
        .collect();
    match tokio::net::lookup_host(format!("{name}:{port}")).await {
        Ok(found) => {
            let mut out = Vec::new();
            let mut seen = HashSet::new();
            for sa in found {
                if !seen.insert(sa.ip()) {
                    continue;
                }
                let mut m = Multiaddr::empty();
                m.push(match sa.ip() {
                    IpAddr::V4(a) => Protocol::Ip4(a),
                    IpAddr::V6(a) => Protocol::Ip6(a),
                });
                for p in &tail {
                    m.push(p.clone());
                }
                out.push(m);
            }
            if out.is_empty() {
                tracing::warn!(%name, "DNS-PIN resolve EMPTY — name exists but has no A/AAAA record");
                return vec![addr.clone()];
            } else {
                // INFO on the FIRST answer and on any CHANGE; DEBUG for a repeat
                // of what we already saw. Resolution runs per request, so a
                // flat INFO here repeated every few seconds forever and buried
                // the two events that actually matter — the first answer, and
                // the address moving — in the noise, on a phone especially.
                let ips: Vec<IpAddr> = out.iter().filter_map(multiaddr_ip).collect();
                let previous = last
                    .lock()
                    .ok()
                    .and_then(|mut m| m.insert(name.clone(), ips.clone()));
                let shown = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
                match previous {
                    Some(prev) if prev == ips => {
                        tracing::debug!(%name, resolved = %shown, "DNS-PIN resolved (unchanged)");
                    }
                    Some(prev) => {
                        let was = prev.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
                        tracing::info!(%name, was = %was, resolved = %shown,
                            "DNS-PIN resolved — ADDRESS CHANGED");
                    }
                    None => tracing::info!(%name, resolved = %shown, "DNS-PIN resolved"),
                }
            }
            out
        }
        Err(e) => {
            // Hand back the ORIGINAL rather than nothing. `request_raw` resolves
            // before it can know whether a dial is even needed — connection state
            // lives on the swarm task — so returning empty made a transient
            // resolver blip fail requests on peers we were already connected to,
            // where the candidates would never have been used. The failure is
            // logged; if a dial really is required it fails on its own.
            tracing::warn!(%name, error = %e, "DNS-PIN resolve FAILED");
            vec![addr.clone()]
        }
    }
}

/// One peer's report: where they reached us from, and what they see us as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    source: IpAddr,
    ip: IpAddr,
    /// Only set for inbound connections — see [`ExternalAddress::port`].
    port: Option<u16>,
}

/// A source of pre-encoded light-client responses.
///
/// This is the seam that lets a SERVER (`rust/roost`) reuse this host verbatim
/// instead of standing up a second libp2p stack — the design's "one protocol
/// stack, not two". The wallet passes `None` and keeps behaving exactly as
/// before: the four light-client protocols fall through to
/// `ResourceUnavailable`.
///
/// Every method returns the **fully encoded response body** (`result byte ||
/// fork digest || varint || snappy frames`), because these are called from
/// [`respond_inbound`], which is **synchronous** and runs inline on the swarm
/// task. There is no await point here: an implementation must be a pure cache
/// read, never an I/O fetch. `None` means miss, and the caller answers
/// `ResourceUnavailable` — correct behaviour, since a wallet simply retries
/// against another peer.
pub trait LcResponder: Send + Sync {
    fn bootstrap(&self, block_root: &[u8; 32]) -> Option<Vec<u8>>;
    fn updates_by_range(&self, start_period: u64, count: u64) -> Option<Vec<u8>>;
    fn finality_update(&self) -> Option<Vec<u8>>;
    fn optimistic_update(&self) -> Option<Vec<u8>>;
}

/// How to build the host. [`HostConfig::default`] is the wallet's shape.
pub struct HostConfig {
    /// Where to listen. The wallet uses an ephemeral port because some peers
    /// reject dial-only hosts; a server pins one so its ENR stays valid.
    pub listen: Multiaddr,
    /// Cap on established inbound connections. The wallet's 64 is
    /// defense-in-depth; a server sets its own, which is the entire point of
    /// splitting it out of a beacon node whose limit it would otherwise inherit.
    pub max_established_incoming: Option<u32>,
    /// Identity key. `None` generates a fresh one — right for a wallet, fatal
    /// for a published server, where every restart would mint a new node ID and
    /// invalidate every cached `/p2p/<peer-id>`.
    pub keypair: Option<libp2p::identity::Keypair>,
    /// Present ⇒ serve the light-client protocols, and advertise
    /// `updates_by_range` inbound.
    pub lc_responder: Option<Arc<dyn LcResponder>>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            listen: "/ip4/0.0.0.0/tcp/0".parse().expect("static multiaddr"),
            max_established_incoming: Some(64),
            keypair: None,
            lc_responder: None,
        }
    }
}

/// Start the libp2p host and its event-loop task. Returns the request client;
/// the task exits on [`ReqRespClient::shutdown`] (or when every client is dropped).
pub fn start_host(local_status: Arc<LocalStatus>) -> Result<ReqRespClient, String> {
    // The wallet drops the JoinHandle: dropping it does not abort the task, and
    // a wallet that loses its host recovers by its own reconnect paths rather
    // than by exiting the process.
    start_host_with(local_status, HostConfig::default()).map(|(client, _, _)| client)
}

/// [`start_host`] with explicit configuration. Also returns the local peer id
/// (a server needs it to publish a dialable multiaddr) and the swarm task's
/// `JoinHandle`.
///
/// **A server must watch that handle.** The swarm task owns the listener and
/// every connection, so if it ends — panic or otherwise — the host stops
/// accepting while the process keeps running perfectly happily. Nothing else
/// notices: the caller's `ReqRespClient` still exists and background pollers
/// keep polling. A supervisor cannot help with a process that never exits, so
/// detecting it is the owner's job. See `roost::serve`, which exits non-zero.
/// Build the swarm, optionally with the DNS resolution layer.
///
/// Two near-identical chains rather than one with a branch: `with_dns()`
/// consumes the builder and does not hand it back on failure, so recovering
/// from a failed DNS setup means building again from the identity.
fn build_swarm(
    keypair: libp2p::identity::Keypair,
    serving: bool,
    max_incoming: Option<u32>,
    dns: bool,
) -> Result<Swarm<Behaviour>, String> {
    let base = libp2p::SwarmBuilder::with_existing_identity(keypair).with_tokio();
    let idle = |c: libp2p::swarm::Config| c.with_idle_connection_timeout(Duration::from_secs(120));
    let behaviour = |key: &libp2p::identity::Keypair| {
        Behaviour::new(key.public(), serving, max_incoming)
    };
    if dns {
        Ok(base
            .with_tcp(
                libp2p::tcp::Config::default().nodelay(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| format!("tcp/noise/yamux setup failed: {e}"))?
            .with_dns()
            .map_err(|e| format!("dns transport setup failed: {e}"))?
            .with_behaviour(behaviour)
            .map_err(|e| format!("behaviour setup failed: {e}"))?
            .with_swarm_config(idle)
            .build())
    } else {
        Ok(base
            .with_tcp(
                libp2p::tcp::Config::default().nodelay(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| format!("tcp/noise/yamux setup failed: {e}"))?
            .with_behaviour(behaviour)
            .map_err(|e| format!("behaviour setup failed: {e}"))?
            .with_swarm_config(idle)
            .build())
    }
}

pub fn start_host_with(
    local_status: Arc<LocalStatus>,
    config: HostConfig,
) -> Result<(ReqRespClient, PeerId, tokio::task::JoinHandle<()>), String> {
    // Ethereum CL spec requires secp256k1 identity keys (same as the Java
    // HostBuilder's KeyType.SECP256K1) — the default ed25519 would make some
    // peers reject the noise handshake payload.
    let keypair = config
        .keypair
        .unwrap_or_else(libp2p::identity::Keypair::generate_secp256k1);
    let serving = config.lc_responder.is_some();
    let max_incoming = config.max_established_incoming;
    // DNS is layered in so `/dns4/host/tcp/port/p2p/<id>` peers resolve AT DIAL
    // TIME, every dial, honouring the record's TTL. That is what lets a server
    // on a dynamic residential address be pinned by NAME instead of by a literal
    // IP that goes stale (rust/roost).
    //
    // It must not be load-bearing, because it CANNOT be relied on everywhere:
    // the system resolver is configured from /etc/resolv.conf, which Android has
    // not had since Oreo (DNS goes through netd), so this legitimately fails
    // there. Android is a first-class consumer (CLAUDE.md, Platform & language
    // direction), and failing the whole host over an optional transport layer
    // would take out `/ip4/` peers — every peer we pin today — on the default
    // Android path.
    //
    // So: try with DNS, fall back to plain TCP with a warning. The degraded mode
    // is exactly today's behaviour, and the warning names what stops working.
    let mut swarm = match build_swarm(keypair.clone(), serving, max_incoming, true) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e,
                "no system DNS resolver — continuing WITHOUT the DNS transport; \
                 /ip4/ peers are unaffected but /dns4/ peers cannot be dialed");
            build_swarm(keypair, serving, max_incoming, false)?
        }
    };

    swarm
        .listen_on(config.listen)
        .map_err(|e| format!("listen failed: {e}"))?;

    let peer_id = *swarm.local_peer_id();
    tracing::info!(peer_id = %peer_id, serving, "libp2p host starting");

    let (tx, rx) = mpsc::channel(256);
    let task = tokio::spawn(run_swarm(swarm, rx, local_status, config.lc_responder));
    Ok((ReqRespClient { tx, last_resolved: Arc::default() }, peer_id, task))
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
    addrs: Vec<Multiaddr>,
    protocol: &'static str,
    wire: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, RequestError>>,
}

struct SwarmCtx {
    pending: HashMap<OutboundRequestId, Pending>,
    connected: HashSet<PeerId>,
    /// Peers we dialed BY NAME, and the name used. Logging only — cleared when
    /// the dial resolves one way or the other.
    dns_dials: HashMap<PeerId, String>,
    /// Peers whose spec-required first Status exchange has completed (either
    /// way). Requests to peers not in this set are parked in `queued` —
    /// opening a light_client stream before Status completes gets the whole
    /// connection dropped by Lighthouse/Teku (see the Java autoStatus doc).
    status_done: HashSet<PeerId>,
    queued: HashMap<PeerId, Vec<QueuedRequest>>,
    lc_servers: HashSet<PeerId>,
    /// `earliest_available_slot` learned from each peer's auto-Status reply.
    peer_earliest: HashMap<PeerId, u64>,
    local_status: Arc<LocalStatus>,
    /// Present only on a serving host; `None` on a wallet, where the
    /// light-client protocols answer `ResourceUnavailable` as before.
    lc: Option<Arc<dyn LcResponder>>,
    /// Response bytes handed to `send_response` but not yet written, plus their
    /// running total. Bounded by [`MAX_IN_FLIGHT_RESPONSE_BYTES`].
    ///
    /// Keyed by (protocol, id) because `InboundRequestId` is issued PER
    /// `request_response::Behaviour`, and this host runs one behaviour per
    /// protocol — so two protocols can each mint id 1. Keyed on the id alone,
    /// the second insert would overwrite the first while both lengths stayed in
    /// the total, and whichever terminal event arrived first would release the
    /// wrong entry: the budget leaks until everything is refused.
    in_flight: HashMap<(&'static str, InboundRequestId), usize>,
    in_flight_bytes: usize,
    /// Per connected peer: (the address WE see them coming from, the address
    /// THEY report seeing us on).
    ///
    /// The tally dedupes on the first element, not on the peer id — see
    /// [`external_address`]. Dropped with the connection, so this is bounded by
    /// the connected set.
    observed_ips: HashMap<PeerId, Observation>,
    /// Source address per peer plus whether THEY dialed US, learned at
    /// connection time and needed before their Identify arrives.
    peer_source_ips: HashMap<PeerId, (IpAddr, bool)>,
}

async fn run_swarm(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Command>,
    local_status: Arc<LocalStatus>,
    lc: Option<Arc<dyn LcResponder>>,
) {
    let mut ctx = SwarmCtx {
        pending: HashMap::new(),
        connected: HashSet::new(),
        dns_dials: HashMap::new(),
        status_done: HashSet::new(),
        queued: HashMap::new(),
        lc_servers: HashSet::new(),
        peer_earliest: HashMap::new(),
        local_status,
        lc,
        in_flight: HashMap::new(),
        in_flight_bytes: 0,
        observed_ips: HashMap::new(),
        peer_source_ips: HashMap::new(),
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
                Some(Command::Request { peer, dns_name, addrs, protocol, wire, reply }) => {
                    submit_request(
                        &mut swarm, &mut ctx, peer, dns_name, addrs, protocol, wire, reply,
                    );
                }
                Some(Command::PeerCount { reply }) => {
                    let _ = reply.send(ctx.connected.len());
                }
                Some(Command::LcServers { reply }) => {
                    let _ = reply.send(ctx.lc_servers.clone());
                }
                Some(Command::ExternalAddress { reply }) => {
                    let _ = reply.send(external_address(&ctx.observed_ips));
                }
                Some(Command::Observe { peers }) => {
                    for (peer, addr) in peers {
                        // Skip peers we already hold a connection to: their
                        // Identify has already been recorded, and a redundant
                        // dial would only churn the connection.
                        if ctx.connected.contains(&peer) {
                            continue;
                        }
                        if let Some(name) = multiaddr_dns_name(&addr) {
                            ctx.dns_dials.insert(peer, name);
                        }
                        use libp2p::swarm::dial_opts::DialOpts;
                        let opts = DialOpts::peer_id(peer).addresses(vec![addr]).build();
                        match swarm.dial(opts) {
                            Ok(()) => {}
                            Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {}
                            Err(e) => {
                                tracing::debug!(peer = %peer, error = %e, "observation dial failed");
                            }
                        }
                    }
                }
                Some(Command::CatchupMeta { reply }) => {
                    let _ = reply.send((ctx.lc_servers.clone(), ctx.peer_earliest.clone()));
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
    dns_name: Option<String>,
    // Candidates in resolver order — see `resolve_dial_addrs`.
    addrs: Vec<Multiaddr>,
    protocol: &'static str,
    wire: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, RequestError>>,
) {
    if ctx.status_done.contains(&peer) {
        let Some(rr) = behaviour_for(swarm, protocol) else {
            let _ = reply.send(Err(RequestError::Io(format!("unknown protocol {protocol}"))));
            return;
        };
        let id = rr.send_request_with_addresses(&peer, wire, addrs);
        ctx.pending.insert(id, Pending::External(reply));
        return;
    }

    ctx.queued
        .entry(peer)
        .or_default()
        .push(QueuedRequest { addrs: addrs.clone(), protocol, wire, reply });
    if !ctx.connected.contains(&peer) {
        // The name is carried through rather than re-derived: by this point the
        // candidates are concrete /ip4//ip6/ addresses, so the name only exists
        // because the caller resolved it. Kept so a connection or dial failure
        // can still be attributed to the pin that produced it.
        if let Some(name) = dns_name {
            ctx.dns_dials.insert(peer, name);
        }
        use libp2p::swarm::dial_opts::DialOpts;
        // EVERY candidate, in resolver order: libp2p tries them in turn, which
        // is what makes a NAT64 network work without special-casing it.
        let opts = DialOpts::peer_id(peer).addresses(addrs).build();
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
        let id = rr.send_request_with_addresses(&peer, q.wire, q.addrs);
        ctx.pending.insert(id, Pending::External(q.reply));
    }
}

fn handle_swarm_event(swarm: &mut Swarm<Behaviour>, ctx: &mut SwarmCtx, event: SwarmEvent<BehaviourEvent>) {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            // Remember where this peer reached us from: the external-address
            // tally dedupes on it, so a host cannot vote more than once by
            // minting extra peer ids.
            if let Some(ip) = multiaddr_ip(endpoint.get_remote_address()) {
                ctx.peer_source_ips.insert(peer_id, (ip, endpoint.is_listener()));
            }
            let newly = ctx.connected.insert(peer_id);
            // The name's CURRENT answer. libp2p resolves inside the transport,
            // so this is the only place the mapping is observable — and on a
            // dynamic address it is the thing an operator actually wants to
            // see: which IP the name points at right now, confirmed by a
            // connection that succeeded rather than by a lookup done elsewhere.
            if let Some(name) = ctx.dns_dials.remove(&peer_id) {
                // NOTE: not `endpoint.get_remote_address()` — for a dial by name
                // that returns the /dns4/ address we asked for, not the address
                // it resolved to, which makes it useless for exactly this. The
                // answer is logged by `resolve_dial_addrs` at dial time instead.
                tracing::info!(peer = %peer_id, %name, "DNS-PIN connected");
            }
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
                // Next connection must redo the Status handshake — and drop the
                // per-peer metadata it produced so these maps stay bounded by
                // the CONNECTED set, not by every peer ever seen (a reconnect
                // re-runs Identify + auto-Status and repopulates both).
                ctx.status_done.remove(&peer_id);
                ctx.lc_servers.remove(&peer_id);
                ctx.peer_earliest.remove(&peer_id);
                ctx.observed_ips.remove(&peer_id);
                ctx.peer_source_ips.remove(&peer_id);
                fail_queued(ctx, &peer_id, RequestError::ConnectionClosed);
                tracing::debug!(peer = %peer_id, "connection closed");
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
            if let Some(name) = ctx.dns_dials.remove(&peer_id) {
                // WARN, not debug: a pinned name that stops resolving makes the
                // server unreachable to every wallet at once, and it is
                // otherwise indistinguishable from the server being down.
                tracing::warn!(peer = %peer_id, %name, error = %error,
                    "DNS-PIN dial FAILED — the name did not resolve, or resolved to \
                     an address that refused the connection");
            }
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
            if let (Some(ip), Some((source, inbound))) = (
                multiaddr_ip(&info.observed_addr),
                ctx.peer_source_ips.get(&peer_id).copied(),
            ) {
                // The port is only meaningful when THEY dialed US: then what
                // they see is our externally mapped port. On a connection we
                // dialed it is our ephemeral source port.
                let port = inbound.then(|| multiaddr_port(&info.observed_addr)).flatten();
                ctx.observed_ips.insert(peer_id, Observation { source, ip, port });
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
            request_response::Message::Request { request, channel, request_id, .. } => {
                let mut response = respond_inbound(ctx, protocol, peer, &request);
                // Refuse rather than queue when the in-flight budget is spent.
                // ResourceUnavailable is the answer a wallet already knows how
                // to handle, and it costs us nothing to hold.
                if ctx.in_flight_bytes.saturating_add(response.len()) > MAX_IN_FLIGHT_RESPONSE_BYTES
                {
                    tracing::warn!(peer = %peer, protocol, queued = ctx.in_flight_bytes,
                        want = response.len(),
                        "in-flight response budget exhausted — answering ResourceUnavailable");
                    response = codec::encode_error_response(
                        codec::RESULT_RESOURCE_UNAVAILABLE,
                        "ResourceUnavailable",
                    );
                }
                let response_len = response.len();
                let behaviour = swarm.behaviour_mut();
                let rr = match protocol {
                    protocols::STATUS_V2 => &mut behaviour.status_v2,
                    protocols::STATUS_V1 => &mut behaviour.status_v1,
                    protocols::PING => &mut behaviour.ping,
                    protocols::METADATA_V2 => &mut behaviour.metadata,
                    protocols::GOODBYE => &mut behaviour.goodbye,
                    protocols::BOOTSTRAP => &mut behaviour.bootstrap,
                    protocols::UPDATES_BY_RANGE => &mut behaviour.updates,
                    protocols::FINALITY_UPDATE => &mut behaviour.finality,
                    protocols::OPTIMISTIC_UPDATE => &mut behaviour.optimistic,
                    _ => return,
                };
                if rr.send_response(channel, response).is_err() {
                    tracing::debug!(peer = %peer, protocol, "inbound response channel closed");
                } else {
                    ctx.in_flight.insert((protocol, request_id), response_len);
                    ctx.in_flight_bytes = ctx.in_flight_bytes.saturating_add(response_len);
                }
                // Goodbye means the peer is leaving. Answering without closing
                // leaves us holding a connection its owner considers gone —
                // which on a public responder is how the connection table fills
                // with peers that will never talk again.
                if protocol == protocols::GOODBYE {
                    let _ = swarm.disconnect_peer_id(peer);
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
        // Both terminal outcomes release the budget; missing either would leak it
        // and converge on a responder that refuses everything.
        request_response::Event::InboundFailure { peer, error, request_id, .. } => {
            release_in_flight(ctx, protocol, request_id);
            tracing::debug!(peer = %peer, protocol, error = %error, "inbound failure");
        }
        request_response::Event::ResponseSent { request_id, .. } => {
            release_in_flight(ctx, protocol, request_id);
        }
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
                if let Some(earliest) = log_peer_status("v2", peer_id, &raw) {
                    ctx.peer_earliest.insert(peer_id, earliest);
                }
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
                Ok(raw) => {
                    if let Some(earliest) = log_peer_status("v1", peer_id, &raw) {
                        ctx.peer_earliest.insert(peer_id, earliest);
                    }
                }
                Err(e) => tracing::debug!(peer = %peer_id, error = %e, "auto-status v1 failed"),
            }
            mark_status_done(swarm, ctx, peer_id);
        }
        None => {}
    }
}

/// Logs a peer's auto-Status reply and returns its `earliest_available_slot`
/// (None on a decode/frame error). v1 peers report 0 — genesis history.
fn log_peer_status(version: &str, peer: PeerId, raw: &[u8]) -> Option<u64> {
    match codec::decode_response(raw, false) {
        Ok(d) => {
            let decoded = if version == "v2" {
                StatusMessage::decode(&d.ssz_payload)
            } else {
                StatusMessage::decode_v1(&d.ssz_payload)
            };
            match decoded {
                Ok(s) => {
                    tracing::debug!(peer = %peer, version,
                        fork_digest = %hex4(&s.fork_digest),
                        finalized_epoch = s.finalized_epoch, head_slot = s.head_slot,
                        earliest = s.earliest_available_slot, "auto-status ok");
                    Some(s.earliest_available_slot)
                }
                Err(e) => {
                    tracing::debug!(peer = %peer, version, error = %e,
                        "auto-status decode failed");
                    None
                }
            }
        }
        Err(e) => {
            tracing::debug!(peer = %peer, version, error = %e, "auto-status frame invalid");
            None
        }
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
        // `expected` is exact for every protocol we answer, so the declared
        // length is checked before the allocation it would otherwise cause.
        match codec::parse_request_ssz_expecting(raw, Some(expected)) {
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
        // Ping answers with OUR metadata sequence number, never an echo of the
        // caller's. Echoing is harmless for a client that dials out and closes,
        // but a public responder that echoes tells every peer its metadata
        // changes in lockstep with theirs — so they never refetch our real
        // metadata, and never learn what we actually serve.
        protocols::PING => {
            codec::encode_success_response(&status::metadata_seq_number().to_le_bytes(), None)
        }
        protocols::METADATA_V2 => {
            codec::encode_success_response(&status::metadata_v2_light_client(), None)
        }
        // Goodbye is a one-way notification: the spec has no response for it,
        // and the caller does not wait. We answer to keep the request_response
        // machinery happy, and the CALLER of this function disconnects the peer
        // — retaining someone who asked to leave is how a responder accumulates
        // dead connections.
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

        // --- light client -------------------------------------------------
        // A serving host reads its cache; a wallet has no responder and falls
        // through to ResourceUnavailable, exactly as before. Note there is no
        // await point in here by construction: a miss is answered, not filled.
        protocols::BOOTSTRAP => match (&ctx.lc, req_ssz.as_slice().try_into()) {
            (Some(lc), Ok(root)) => {
                let root: [u8; 32] = root;
                lc.bootstrap(&root).unwrap_or_else(resource_unavailable)
            }
            (Some(_), Err(_)) => codec::encode_error_response(
                codec::RESULT_INVALID_REQUEST,
                "InvalidRequest: bootstrap root must be 32 bytes",
            ),
            (None, _) => resource_unavailable(),
        },
        protocols::UPDATES_BY_RANGE => match &ctx.lc {
            Some(lc) => {
                if req_ssz.len() != 16 {
                    return codec::encode_error_response(
                        codec::RESULT_INVALID_REQUEST,
                        "InvalidRequest: updates_by_range request must be 16 bytes",
                    );
                }
                let start = u64::from_le_bytes(req_ssz[..8].try_into().expect("checked"));
                let count = u64::from_le_bytes(req_ssz[8..16].try_into().expect("checked"));
                lc.updates_by_range(start, count)
                    .unwrap_or_else(resource_unavailable)
            }
            None => resource_unavailable(),
        },
        protocols::FINALITY_UPDATE => match &ctx.lc {
            Some(lc) => lc.finality_update().unwrap_or_else(resource_unavailable),
            None => resource_unavailable(),
        },
        protocols::OPTIMISTIC_UPDATE => match &ctx.lc {
            Some(lc) => lc.optimistic_update().unwrap_or_else(resource_unavailable),
            None => resource_unavailable(),
        },

        _ => resource_unavailable(),
    }
}

/// The address a quorum of distinct SOURCES agrees on.
///
/// Plurality among reports, then a floor: the winner must have at least
/// [`EXTERNAL_ADDR_QUORUM`] distinct reporters behind it. Below that we return
/// `None` rather than the leading candidate — "I do not know yet" is the honest
/// answer for a server with few connections, and publishing a guess is how a
/// record ends up pointing at an address nothing answers on.
///
/// # Reporters are counted by source address, not by peer id
///
/// A peer id is a self-minted keypair that costs nothing, so counting distinct
/// ids would let ONE host reach quorum alone with three fresh identities —
/// out-voting every honest reporter whenever the honest set is small, which is
/// precisely the state just after a restart, when the answer first settles.
/// Deduping on the address the reporter reached us from raises that cost from
/// "generate three keypairs" to "hold three distinct addresses".
///
/// Honest peers behind one NAT now count once between them. That makes quorum
/// HARDER to reach, which is the safe direction for a value that will drive a
/// published record: the failure mode becomes "we decline to claim an address",
/// not "we claim the wrong one".
fn external_address(observed: &HashMap<PeerId, Observation>) -> Option<ExternalAddress> {
    // One vote per source address. A source reporting different values across
    // its own connections collapses to one of them, which is the point.
    let mut by_source: HashMap<IpAddr, (IpAddr, Option<u16>)> = HashMap::new();
    for o in observed.values() {
        by_source.insert(o.source, (o.ip, o.port));
    }
    let reporters = by_source.len();
    let mut counts: HashMap<IpAddr, usize> = HashMap::new();
    for (ip, _) in by_source.values() {
        *counts.entry(*ip).or_insert(0) += 1;
    }
    // Ties break on the IP itself, so the answer is deterministic rather than
    // dependent on hash iteration order — a flapping answer would look exactly
    // like a flapping address.
    let (ip, confirmations) = counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))?;
    // The port MOST reporters who back the winning IP agree on — by frequency,
    // ties broken on the value, exactly as the IP above.
    //
    // `find_map` over a HashMap took whichever backer hash order happened to
    // visit first, so when reporters disagreed (a NAT rewriting the port for
    // some peers, or a mix of listen-port and mapped-port views) the answer
    // flipped between calls with no change in the underlying data. That is the
    // same failure the IP tie-break exists to prevent, and it matters more here
    // because `dialable()` publishes this port.
    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    for (seen, port) in by_source.values() {
        if *seen == ip {
            if let Some(p) = port {
                *port_counts.entry(*p).or_insert(0) += 1;
            }
        }
    }
    let port = port_counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|(p, _)| p);

    (confirmations >= EXTERNAL_ADDR_QUORUM).then_some(ExternalAddress {
        ip,
        port,
        confirmations,
        reporters,
        routable: is_routable(ip),
    })
}

fn release_in_flight(ctx: &mut SwarmCtx, protocol: &'static str, request_id: InboundRequestId) {
    if let Some(bytes) = ctx.in_flight.remove(&(protocol, request_id)) {
        ctx.in_flight_bytes = ctx.in_flight_bytes.saturating_sub(bytes);
    }
}

/// The miss answer — "ask someone else", which is what makes a pure-cache-read
/// handler correct rather than a shortcut.
fn resource_unavailable() -> Vec<u8> {
    codec::encode_error_response(codec::RESULT_RESOURCE_UNAVAILABLE, "ResourceUnavailable")
}

#[cfg(test)]
mod external_address_tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Deterministic distinct peer ids — a seeded key, not a random one, so a
    /// failure reproduces.
    fn peer(n: u8) -> PeerId {
        let mut seed = [0u8; 32];
        seed[0] = n;
        let kp = libp2p::identity::Keypair::ed25519_from_bytes(seed).expect("seeded key");
        PeerId::from(kp.public())
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(87, 154, 209, last))
    }

    /// A report from a distinct host: source address `src`, seeing us as `seen`.
    fn obs(src: u8, seen: IpAddr) -> Observation {
        Observation {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, src)),
            ip: seen,
            port: None,
        }
    }

    #[test]
    fn below_quorum_is_none_not_a_best_guess() {
        let mut observed = HashMap::new();
        for i in 0..(EXTERNAL_ADDR_QUORUM - 1) as u8 {
            observed.insert(peer(i), obs(i, ip(161)));
        }
        assert_eq!(
            external_address(&observed),
            None,
            "a server with too few reports genuinely does not know its own address"
        );
    }

    #[test]
    fn quorum_is_believed() {
        let mut observed = HashMap::new();
        for i in 0..EXTERNAL_ADDR_QUORUM as u8 {
            observed.insert(peer(i), obs(i, ip(161)));
        }
        let got = external_address(&observed).unwrap();
        assert_eq!(got.ip, ip(161));
        assert_eq!(got.confirmations, EXTERNAL_ADDR_QUORUM);
        assert_eq!(got.reporters, EXTERNAL_ADDR_QUORUM);
        assert!(got.routable);
        assert!(!got.is_contested());
    }

    #[test]
    fn a_minority_cannot_move_the_answer() {
        // The point of the quorum: peers claiming something else — lying, or
        // honestly wrong behind the same NAT — must not win.
        let mut observed = HashMap::new();
        for i in 0..5u8 {
            observed.insert(peer(i), obs(i, ip(161)));
        }
        for i in 5..7u8 {
            observed.insert(peer(i), obs(i, ip(99)));
        }
        let got = external_address(&observed).unwrap();
        assert_eq!(got.ip, ip(161));
        assert_eq!(got.reporters, 7, "the denominator must be visible");
        assert!(!got.is_contested(), "5 of 7 is not contested");
    }

    #[test]
    fn one_peer_cannot_stuff_the_ballot() {
        // Keyed by peer, so repeated reports from one peer replace rather than
        // accumulate.
        let mut observed = HashMap::new();
        let loud = peer(1);
        for _ in 0..10 {
            observed.insert(loud, obs(1, ip(99)));
        }
        assert_eq!(external_address(&observed), None, "one peer is not a quorum");
    }

    #[test]
    fn the_answer_is_deterministic_under_a_tie() {
        // A tie resolved by hash iteration order would look exactly like a
        // flapping address — the thing this mechanism exists to detect.
        let mut observed = HashMap::new();
        for i in 0..EXTERNAL_ADDR_QUORUM as u8 {
            observed.insert(peer(i), obs(i, ip(1)));
        }
        for i in 0..EXTERNAL_ADDR_QUORUM as u8 {
            observed.insert(peer(i + 50), obs(i + 50, ip(2)));
        }
        let first = external_address(&observed).unwrap().ip;
        for _ in 0..20 {
            assert_eq!(external_address(&observed).unwrap().ip, first);
        }
    }

    #[test]
    fn one_host_cannot_stuff_the_ballot_with_free_keypairs() {
        // The property the ENR actually needs. A peer id is a self-minted
        // keypair costing nothing, so counting distinct IDS would let one
        // machine reach quorum alone — most easily right after a restart, when
        // the honest set is smallest and the answer first settles.
        let mut observed = HashMap::new();
        for i in 0..10u8 {
            // Ten identities, ONE source address.
            observed.insert(peer(i), obs(7, ip(99)));
        }
        assert_eq!(
            external_address(&observed),
            None,
            "ten identities behind one address are one reporter"
        );
    }

    #[test]
    fn a_contested_plurality_is_flagged() {
        // 3-vs-3 must not read as an established address: one more reporter
        // flips the winner, and that is the shape both a Sybil and a genuine
        // mid-flight address change produce.
        let mut observed = HashMap::new();
        for i in 0..3u8 {
            observed.insert(peer(i), obs(i, ip(1)));
        }
        for i in 3..6u8 {
            observed.insert(peer(i), obs(i, ip(2)));
        }
        let got = external_address(&observed).unwrap();
        assert_eq!(got.reporters, 6);
        assert_eq!(got.confirmations, 3);
        assert!(got.is_contested(), "3 of 6 is contested");
    }

    #[test]
    fn non_routable_winners_are_labelled() {
        // The PR's own verification established 127.0.0.1 from three loopback
        // wallets. The realistic version is RFC1918: LAN wallets reach quorum
        // before internet peers do.
        for addr in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), // carrier-grade NAT
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        ] {
            assert!(!is_routable(addr), "{addr} must not read as routable");
        }
        assert!(is_routable(ip(161)), "the pinned deployment's address is routable");
        assert!(!is_routable("fd00::1".parse().unwrap()), "ULA");
        assert!(!is_routable("fe80::1".parse().unwrap()), "link-local");
        assert!(!is_routable("::1".parse().unwrap()), "v6 loopback");
        assert!(is_routable("2001:db8::1".parse().unwrap()));

        let mut observed = HashMap::new();
        for i in 0..EXTERNAL_ADDR_QUORUM as u8 {
            observed.insert(peer(i), obs(i, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));
        }
        assert!(!external_address(&observed).unwrap().routable);
    }

    #[test]
    fn the_port_is_carried_only_from_inbound_reports() {
        // Inbound: the reporter dialed us, so what they see IS our externally
        // mapped port — the fact that makes a NAT rewriting it detectable.
        let mut observed = HashMap::new();
        for i in 0..EXTERNAL_ADDR_QUORUM as u8 {
            observed.insert(
                peer(i),
                Observation {
                    source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                    ip: ip(161),
                    port: Some(9105),
                },
            );
        }
        assert_eq!(external_address(&observed).unwrap().port, Some(9105));

        // Outbound-only reports carry no port rather than an ephemeral one.
        let mut outbound = HashMap::new();
        for i in 0..EXTERNAL_ADDR_QUORUM as u8 {
            outbound.insert(peer(i), obs(i, ip(161)));
        }
        assert_eq!(external_address(&outbound).unwrap().port, None);
    }

    #[test]
    fn extracts_the_ip_and_ignores_the_port() {
        // Identify reports the connection's remote address, so for a connection
        // WE dialed the port is our ephemeral source port and says nothing about
        // where we listen.
        let addr: Multiaddr = "/ip4/87.154.209.161/tcp/54321".parse().unwrap();
        assert_eq!(multiaddr_ip(&addr), Some(ip(161)));
        let addr6: Multiaddr = "/ip6/::1/tcp/9105".parse().unwrap();
        assert!(multiaddr_ip(&addr6).is_some());
        let no_ip: Multiaddr = "/dns4/example.com/tcp/9105".parse().unwrap();
        assert_eq!(multiaddr_ip(&no_ip), None);
        assert_eq!(multiaddr_port(&addr), Some(54321));
    }
}

#[cfg(test)]
mod dial_resolution_tests {
    use super::*;

    fn memo() -> std::sync::Mutex<HashMap<String, Vec<IpAddr>>> {
        std::sync::Mutex::new(HashMap::new())
    }

    #[tokio::test]
    async fn a_plain_ip_address_passes_through_untouched() {
        let a: Multiaddr = "/ip4/87.154.209.161/tcp/9105/p2p/\
            16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5"
            .parse()
            .unwrap();
        assert_eq!(resolve_dial_addrs(&a, &memo()).await, vec![a.clone()]);
    }

    #[tokio::test]
    async fn a_name_becomes_concrete_candidates_keeping_port_and_peer_id() {
        // localhost is the one name guaranteed resolvable in CI and offline.
        let a: Multiaddr = "/dns4/localhost/tcp/9105/p2p/\
            16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5"
            .parse()
            .unwrap();
        let out = resolve_dial_addrs(&a, &memo()).await;
        assert!(!out.is_empty(), "localhost must resolve");
        for m in &out {
            // No DNS component survives — that is the whole point: the swarm's
            // transport may have no DNS layer at all (Android), where a /dns4/
            // address is rejected with "Multiaddr is not supported".
            assert!(multiaddr_dns_name(m).is_none(), "{m} still carries a name");
            assert!(multiaddr_ip(m).is_some(), "{m} has no IP");
            assert_eq!(multiaddr_port(m), Some(9105), "port must survive");
            assert!(
                m.to_string().ends_with("16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5"),
                "peer id must survive: {m}"
            );
        }
    }

    #[tokio::test]
    async fn an_unresolvable_name_falls_back_to_the_original() {
        // NOT empty. `request_raw` resolves before it can know whether a dial is
        // even needed, so returning nothing would fail requests on peers we are
        // already connected to over a transient resolver blip. The failure is
        // logged; a dial that genuinely needs the address fails on its own.
        let a: Multiaddr = "/dns4/no-such-host.invalid/tcp/9105/p2p/\
            16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5"
            .parse()
            .unwrap();
        assert_eq!(resolve_dial_addrs(&a, &memo()).await, vec![a.clone()]);
    }

    #[tokio::test]
    async fn an_address_without_tcp_is_returned_untouched() {
        // No /tcp/ means nothing to rebuild around: rewriting would drop the
        // port, the transport and the /p2p/ id, leaving a bare /ip4/A.
        for raw in ["/dnsaddr/example.com", "/dns4/localhost"] {
            let a: Multiaddr = raw.parse().unwrap();
            assert_eq!(resolve_dial_addrs(&a, &memo()).await, vec![a.clone()], "{raw}");
        }
    }

    /// The first answer is INFO, a repeat is DEBUG — the memo is what decides,
    /// so it must actually be written on the first pass.
    #[tokio::test]
    async fn the_answer_is_remembered_so_repeats_can_be_quiet() {
        let a: Multiaddr = "/dns4/localhost/tcp/9105".parse().unwrap();
        let m = memo();
        let first = resolve_dial_addrs(&a, &m).await;
        assert!(!first.is_empty());
        assert_eq!(m.lock().unwrap().len(), 1, "first resolution must be recorded");
        let again = resolve_dial_addrs(&a, &m).await;
        assert_eq!(first, again, "a repeat must return the same candidates");
        assert_eq!(m.lock().unwrap().len(), 1, "and must not grow the memo");
    }

    #[tokio::test]
    async fn duplicate_addresses_are_collapsed() {
        // localhost commonly resolves to 127.0.0.1 twice (once per socket type);
        // dialing the same address twice buys nothing.
        let a: Multiaddr = "/dns4/localhost/tcp/9105".parse().unwrap();
        let out = resolve_dial_addrs(&a, &memo()).await;
        let ips: HashSet<_> = out.iter().filter_map(multiaddr_ip).collect();
        assert_eq!(ips.len(), out.len(), "candidates must be unique by IP");
    }
}
