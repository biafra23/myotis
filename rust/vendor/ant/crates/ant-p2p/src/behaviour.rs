//! Tokio libp2p swarm: dial bootnodes, open `/swarm/handshake/14.0.0/handshake` via `libp2p_stream`, Identify + Ping.

use crate::bounded_close::BoundedClose;
use crate::dial::endpoint_host;
use crate::dnsaddr;
use crate::handshake::{
    handshake_outbound, HandshakeError, HandshakeInfo, PROTOCOL_HANDSHAKE_V14,
    PROTOCOL_HANDSHAKE_V15,
};
use crate::liveness::{Liveness, LivenessConfig};
use crate::peerstore::PeerStore;
use crate::routing::{KnownPeers, Overlay, RoutingTable};
use crate::sinks;
use ant_control::{
    AccountingSnapshotView, CacheInfo, ControlAck, ControlCommand, DiskCacheInfo,
    ExternalAddressInfo, GatewayActivity, GetProgress, HandshakeReport, LastChequeView,
    PeerAccountingView, PeerConnectionInfo, PeerConnectionState, PeerInfo, PeerPipelineEntry,
    RetrievalInfo, RoutingInfo, StatusSnapshot, StreamRange,
};
use ant_crypto::HandshakeWireVersion;
use ant_crypto::{
    ethereum_address_from_public_key, overlay_from_ethereum_address, OVERLAY_NONCE_LEN,
    SECP256K1_SECRET_LEN,
};
use ant_retrieval::{ChunkFetcher, ProgressTracker, RetrievalCounters, DEFAULT_CACHE_CAPACITY};
use futures::StreamExt;
use k256::ecdsa::{SigningKey, VerifyingKey};
use libp2p::core::connection::ConnectedPoint;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::Transport as _;
use libp2p::identify;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Multiaddr;
use libp2p::ping;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{dns, noise, tcp, yamux, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use libp2p_stream::Control;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tracing::{debug, info, trace, warn};

const LISTEN: &str = "/ip4/0.0.0.0/tcp/0";
const AGENT: &str = concat!("antd/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Error)]
pub enum RunError {
    #[error("transport: {0}")]
    Transport(#[from] std::io::Error),
    #[error("handshake: {0}")]
    Handshake(#[from] crate::handshake::HandshakeError),
    #[error("behaviour: {0}")]
    Behaviour(#[from] libp2p::BehaviourBuilderError),
}

/// Postage stamping + signing key wired at daemon startup for pushsync uploads.
///
/// The node wallet owns every batch it buys on-chain, so a single
/// `stamp_key` (the node's signing secret) signs stamps for *all*
/// batches; we keep one [`ant_postage::StampIssuer`] per batch in
/// `issuers`, keyed by 32-byte batch id. New batches are added at
/// runtime via [`ControlCommand::RegisterBatch`] (after a
/// `POST /stamps/{amount}/{depth}` buy) so Freedom can buy a batch and
/// immediately upload against it with no restart.
///
/// The map lives behind a `Mutex` because each chunk push needs to
/// atomically pick the next slot in its collision bucket and increment
/// the counter; bee `stampissuer.go::increment` does the same. `Arc`
/// lets the runtime be cloned into per-`PushChunk` spawned tasks.
pub struct UploadRuntime {
    pub issuers: std::sync::Mutex<HashMap<[u8; 32], ant_postage::StampIssuer>>,
    pub stamp_key: [u8; SECP256K1_SECRET_LEN],
    pub batch_owner: [u8; 20],
    /// Directory holding each batch's persistent counter file
    /// (`<batch_id>.bin`). Used to open issuers for batches registered
    /// at runtime.
    pub postage_dir: PathBuf,
}

/// Map a [`ant_postage::BucketStats`] snapshot to the control-plane
/// [`ant_control::PostageStatusView`] reported over `PostageStatus` /
/// `PostageList`.
fn postage_status_view(
    stats: &ant_postage::BucketStats,
    usable: bool,
    propagating: bool,
    registered_at: Option<Instant>,
    block_number: Option<u64>,
) -> ant_control::PostageStatusView {
    ant_control::PostageStatusView {
        usable,
        propagating,
        registered_secs_ago: registered_at.map(|t| t.elapsed().as_secs()),
        block_number,
        enabled: true,
        batch_id: format!("0x{}", hex::encode(stats.batch_id)),
        batch_depth: stats.batch_depth,
        bucket_depth: stats.bucket_depth,
        immutable: stats.immutable,
        bucket_count: stats.bucket_count,
        bucket_capacity: stats.bucket_capacity,
        total_capacity_chunks: stats.total_capacity,
        issued_chunks: stats.issued,
        bucket_fill_min: stats.bucket_fill_min,
        bucket_fill_max: stats.bucket_fill_max,
        remaining_total_chunks: stats.remaining_total,
        worst_case_remaining_chunks: stats.worst_case_remaining,
    }
}

/// One registered batch's view. It isn't usable while peers reject it
/// as not-on-chain, nor while a just-bought batch is still propagating
/// to the storers.
fn batch_view(
    state: &SwarmState,
    issuer: &ant_postage::StampIssuer,
) -> ant_control::PostageStatusView {
    let id = issuer.batch_id();
    let rejected = state
        .rejected_batches
        .lock()
        .is_ok_and(|s| s.contains_key(id));
    let bought = state.bought_batches.get(id);
    let propagating = bought.is_some_and(|b| b.propagating(Instant::now()));
    postage_status_view(
        &issuer.stats(),
        !rejected && !propagating,
        !rejected && propagating,
        state.runtime_registered.get(id).copied(),
        bought.map(|b| b.block),
    )
}

/// The `enabled: false` view returned when no batch is registered.
fn postage_status_disabled() -> ant_control::PostageStatusView {
    ant_control::PostageStatusView {
        enabled: false,
        ..Default::default()
    }
}

pub struct RunConfig {
    pub signing_secret: [u8; SECP256K1_SECRET_LEN],
    pub overlay_nonce: [u8; OVERLAY_NONCE_LEN],
    pub network_id: u64,
    pub bootnodes: Vec<Multiaddr>,
    pub libp2p_keypair: Keypair,
    /// Addresses to advertise via identify as externally reachable. Bee's
    /// inbound handshake stalls for 10 s if its peerstore has no public
    /// multiaddr for us, so operators behind NAT should set at least one
    /// dialable address here.
    pub external_addrs: Vec<Multiaddr>,
    /// Dial peers' private / loopback / link-local underlays even when
    /// this host isn't on the same subnet. Off by default: hive gossip is
    /// full of Docker/Kubernetes pod addresses, and dialing them from a
    /// hosted server trips provider netscan detection (issue #88). Only
    /// for dev/test networks that live entirely on one private network or
    /// on loopback. Same-LAN private peers are dialed regardless.
    pub allow_private_dials: bool,
    /// Live status view maintained by the swarm loop; read by the control
    /// socket server.
    pub status: Option<watch::Sender<StatusSnapshot>>,
    /// Peer-set target. The swarm loop will keep dialing hive-discovered
    /// peers until this many BZZ-handshake-complete peers are online.
    pub target_peers: usize,
    /// Path to the on-disk peer snapshot. Loaded at startup to warm the
    /// dial pipeline and avoid the bootnode hop on every restart, then
    /// flushed periodically and on shutdown. `None` disables persistence.
    pub peerstore_path: Option<PathBuf>,
    /// Live mutation channel fed by the control-socket server. `None` means
    /// commands like `antctl peers reset` will fail with
    /// `"daemon has no control-command channel wired up"`.
    pub commands: Option<mpsc::Receiver<ControlCommand>>,
    /// Baseline for cold-start elapsed metrics (`time_to_first_peer_s`, etc.).
    pub process_start: std::time::Instant,
    /// When true, scope the in-memory chunk cache to a single
    /// `antctl get` invocation: a fresh `InMemoryChunkCache` is built
    /// for each request and dropped when the request finishes. Intra-
    /// request retries still benefit from the cache (they share the
    /// per-request `Arc`), but a second `antctl get` starts cold.
    /// Useful for reproducing transient retrieval failures and
    /// timing the cold path; off in production.
    pub per_request_chunk_cache: bool,
    /// When set, every chunk fetched by a `GetBytes` / `GetBzz`
    /// request is dumped to `<dir>/<hex_addr>.bin` (raw wire bytes:
    /// 8-byte LE span || payload). Combined with the integration-test
    /// helper that loads a directory of such chunks into a
    /// `MapFetcher`, this lets us snapshot a successful mainnet
    /// retrieval and replay it offline as a regression fixture. The
    /// daemon only honours the flag in debug builds (the `antd` CLI
    /// hides it otherwise); the directory must already exist.
    pub chunk_record_dir: Option<PathBuf>,
    /// Live registry of currently-active gateway HTTP requests,
    /// shared with `ant-gateway`. The swarm loop reads a snapshot
    /// from it on every status tick to populate
    /// `StatusSnapshot::retrieval.gateway_requests` so `antop`
    /// can render the Retrieval tab. `None` when the gateway is
    /// disabled (e.g. `antd --no-http-api`).
    pub gateway_activity: Option<Arc<GatewayActivity>>,
    /// Optional persistent (SQLite-backed) chunk cache shared with
    /// every `RoutingFetcher` we build. `Some(cache)` makes the
    /// retrieval lookup order `memory -> disk -> network`; `None`
    /// keeps the legacy `memory -> network` behaviour. The disk
    /// cache is opened in `antd::main` (so the path/cap come from
    /// CLI config) and threaded through here. Request-level
    /// `bypass_cache` skips both the memory and disk tiers; see
    /// `cache_for_request` for the wiring.
    pub disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    /// Embedder-owned process-wide in-memory chunk cache. `Some` makes
    /// the swarm loop share this `Arc` instead of building its own, so
    /// the embedder can read and clear it (ant-ffi's `ant_cache_*`).
    /// Ignored when `per_request_chunk_cache` is set.
    pub memory_cache: Option<Arc<ant_retrieval::InMemoryChunkCache>>,
    /// Optional postage stamping + signing runtime for `POST /chunks`
    /// (gateway → control socket → swarm). `None` keeps the upload
    /// command path disabled and `PushChunk` returns a clear "uploads
    /// not configured" error instead of silently doing nothing.
    pub upload: Option<Arc<UploadRuntime>>,
    /// Optional SWAP / chequebook configuration. When `Some`, the
    /// `/swarm/swap/1.0.0/swap` listener is wired to a credit ledger
    /// pinned at `our_beneficiary` (typically the same EOA that
    /// signs the BZZ handshake) and inbound cheques are
    /// signature-verified, monotonicity-checked, and persisted to
    /// `ledger_path`. When `None`, the protocol is still registered
    /// — so peers don't see a libp2p disconnect when they emit a
    /// cheque — but every received cheque is silently dropped.
    pub swap: Option<SwapConfig>,
    /// Optional outbound SWAP settlement configuration (Phase 7b).
    /// When `Some`, the node builds a [`crate::PushsyncSwap`] on the
    /// chequebook: the cheque payer of the shared accounting mirror,
    /// which settles retrieval and pushsync debt alike (bee's one
    /// balance per peer) — the free pseudosettle refresh first, then a
    /// cheque priced like bee's once the debt reaches the early-payment
    /// threshold, while `swap-enable` is on and the chequebook has funds
    /// (issues #121, #127).
    pub pushsync_swap: Option<crate::PushsyncSwapConfig>,
    /// Shared `peer_id -> ethereum_address` registry. The swarm
    /// loop populates this in the BZZ-handshake-success branch
    /// (with `HandshakeInfo::remote_eth_address`) so the pushsync
    /// settlement subsystem can recover the cheque beneficiary EOA
    /// for any peer it just pushed to. Always present so the
    /// daemon can install a record without a runtime check; the
    /// pushsync settlement code only consults it when
    /// `pushsync_swap` is configured.
    pub peer_eth: crate::PeerEthMap,
    /// One-shot delivery of the chain-derived inputs (`upload`,
    /// `pushsync_swap`) resolved *after* the swarm loop has started.
    /// `antd` spends seconds on Gnosis RPC at startup (postage batch
    /// validation / rediscovery, chequebook resolution); serializing
    /// those reads before the swarm start put their full latency into
    /// `time_to_first_peer_s`. With this channel set, the daemon
    /// starts the loop immediately and sends the resolved values once
    /// — until then `upload` behaves as `None` ("uploads not
    /// configured") and pushsync runs without outbound settlement,
    /// which is fine because the daemon only opens its API surfaces
    /// (gateway, control socket) after chain init completes anyway.
    /// `None` keeps the constructor-provided `upload` /
    /// `pushsync_swap` as the final word, exactly as before.
    pub late_chain_rx: Option<mpsc::Receiver<LateChainInit>>,
    /// Bee's node-wide `swap-enable` switch, which governs retrieval
    /// payments (issue #121); see `ant_node::NodeConfig::swap_enabled`.
    pub swap_enabled: bool,
}

/// Chain-derived swarm inputs delivered through
/// [`RunConfig::late_chain_rx`] once the daemon's startup Gnosis RPC
/// reads complete. Fields mirror [`RunConfig::upload`] and
/// [`RunConfig::pushsync_swap`].
pub struct LateChainInit {
    /// Postage stamping + signing runtime; see [`RunConfig::upload`].
    pub upload: Option<Arc<UploadRuntime>>,
    /// Outbound SWAP settlement config; see
    /// [`RunConfig::pushsync_swap`]. `peer_eth` is patched to the
    /// loop's live registry on arrival, so the sender may leave it
    /// defaulted.
    pub pushsync_swap: Option<crate::PushsyncSwapConfig>,
}

/// Inputs needed to spin up the SWAP inbound listener.
#[derive(Clone)]
pub struct SwapConfig {
    /// Our node's EOA (20 bytes) — the address every accepted cheque
    /// must list as its `Beneficiary`.
    pub our_beneficiary: [u8; 20],
    /// Chain id used for EIP-712 cheque digest reconstruction (100
    /// for Gnosis mainnet).
    pub chain_id: u64,
    /// Where the ledger snapshot lives on disk; e.g. `<data_dir>/swap_credits.json`.
    pub ledger_path: PathBuf,
    /// Channel that accepted cheques will be published to. `None`
    /// keeps the listener self-contained (operator just reads the
    /// ledger snapshot when they want to inspect inbound payments).
    pub events_tx: Option<mpsc::Sender<crate::swap::InboundCheque>>,
}

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
pub struct AntBehaviour {
    stream: libp2p_stream::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    /// UPnP/IGD-based external-port discovery. Watches `NewListenAddr`
    /// events, talks to the local home router via SSDP, and (on success)
    /// emits [`libp2p::upnp::Event::NewExternalAddr`] with our public
    /// `/ip4/<wan>/tcp/<port>` multiaddr. Treated as opportunistic: on
    /// hosts without an IGD-capable router (cloud VMs, corporate NAT,
    /// CGNAT) the behaviour just emits `GatewayNotFound` /
    /// `NonRoutableGateway` and stays quiet, so leaving it always-on is
    /// safe — handlers in `apply_event` only ever *add* addresses, never
    /// reject existing ones.
    upnp: libp2p::upnp::tokio::Behaviour,
}

/// How often the swarm loop runs its connection liveness pass
/// ([`maintain_liveness`]). The loop wakes at least every 250 ms.
const LIVENESS_PASS_INTERVAL: Duration = Duration::from_millis(500);
const MIN_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_mins(1);
/// Bee's inbound handshake handler waits for the peerstore to be populated
/// via libp2p-identify (a 10 s timeout). Opening our BZZ stream before
/// identify has round-tripped makes bee stall for the full 10 s, then disconnect.
/// This cap is the longest we'll wait before opening the BZZ stream anyway.
const HANDSHAKE_IDENTIFY_WAIT: Duration = Duration::from_secs(3);
/// How far below the peer's bin cursor a default `PullsyncProbe` starts:
/// a historical page the server answers immediately, sized to show a
/// handful of real chunks.
const PROBE_BACKLOG: u64 = 8;
/// Overall bound on the probe's sync page — strictly below the control
/// server's 20 s `NETWORK_COMMAND_TIMEOUT` so the probe always acks
/// before the dispatcher gives up (no orphaned probe tasks).
const PROBE_SYNC_TIMEOUT: Duration = Duration::from_secs(15);
/// Grace window we give libp2p-identify auto-promotion and the `UPnP` behaviour
/// to settle before warning the operator that no globally-routable external
/// address has been registered. `UPnP`'s SSDP search round-trip is typically
/// ~1 s on a cooperative router and up to a few seconds on slower ones; 10 s
/// is enough for both `UPnP` and the first inbound `NewExternalAddrCandidate`
/// from a bootnode without being so long that the warning misses the operator.
const EXTERNAL_ADDRESS_CHECK_DELAY: Duration = Duration::from_secs(10);
/// Hive sinks → swarm-loop channel depth. Bee sends Peers messages with up to
/// 30 entries per stream, and multiple bootnodes gossip concurrently; a few
/// hundred slots is enough to avoid backpressure without being wasteful.
const HINT_CHAN_CAP: usize = 512;
/// Per-loop iteration cap on how many hint dials we fan out. Keeps the
/// `ConnectionEstablished` → handshake pipeline from being drowned in parallel
/// dials when a fresh bootnode dumps its full neighbourhood at once.
const HINT_DIAL_BATCH: usize = 4;
/// Maximum number of known-but-unconnected peers we retain (with dial
/// addresses) for on-demand neighbourhood dialing. Hive gossip refreshes
/// constantly, so a generous cap gives broad keyspace coverage for routing
/// uploads toward arbitrary chunk neighbourhoods while staying bounded in
/// memory (each entry is a `PeerId` + a few multiaddrs + 32-byte overlay).
const KNOWN_DIALABLE_CAP: usize = 16_384;
/// How many of the closest known peers we dial toward a chunk address on a
/// single neighbourhood-dial request. A larger fan-out lands more peers
/// genuinely inside the chunk's neighbourhood per request, so a light node's
/// push reaches a deep storer (deep receipt) instead of drawing a shallow
/// one — the dominant cause of uploads that the uploader can read back but
/// the wider network can't.
///
/// Raised from 8: each newly-connected near-target peer broadcasts its own
/// neighbourhood over hive, so dialing several per round both improves
/// immediate coverage *and* multiplies the inbound gossip that seeds the
/// next, deeper round of the gossip-deepening cycle (a light node's only
/// route to an arbitrary neighbourhood — hive has no `pull`/`FIND_NODE` path).
/// Bounded by [`NEIGHBORHOOD_DIAL_MARGIN`] headroom, and `dial_toward_target`
/// only dials peers strictly deeper than our current best, so this can't
/// balloon the steady-state peer set.
const NEIGHBORHOOD_DIAL_FANOUT: usize = 24;
/// How far over `target_peers` the connection pipeline may grow to admit
/// on-demand neighbourhood dials. Uploads need transient connections into
/// many different chunk neighbourhoods across the keyspace; this headroom
/// lets us reach them without the count-based `target_peers` cap (tuned for
/// steady-state forwarding) starving the upload. Excess peers churn back
/// out naturally once the upload is done.
const NEIGHBORHOOD_DIAL_MARGIN: usize = 128;
/// Minimum gap between two consecutive peer top-ups. Sustained connection
/// churn (bee-side load shedding under pushsync pressure being the canonical
/// trigger) drops the peer set below the floor; the top-up clears the
/// `seen_hints` dedup, re-warms from the on-disk peerstore, and re-bootstraps
/// to pull fresh hive gossip. 15 s is short enough to recover within a single
/// scripted upload's retry budget yet long enough that a flapping bootnode
/// region can't turn the recovery path into a hot loop.
const PEER_TOP_UP_INTERVAL: Duration = Duration::from_secs(15);
/// Default target peer count if `RunConfig::target_peers` is left at zero.
///
/// Bee's mainnet neighbourhood typically fans out to a few hundred peers
/// once kademlia stabilises; 100 keeps us connected to a useful slice of
/// that fan-out while staying cheap on CPU/FDs and well under the raised
/// `RLIMIT_NOFILE` we bump to at `antd` startup.
pub const DEFAULT_TARGET_PEERS: usize = 100;
/// Wall-clock cadence for flushing the peerstore snapshot to disk. Trades
/// off "how much state can we lose on a SIGKILL" against IO churn under
/// peer churn. 30 s strikes a balance: a fresh restart still warms within
/// seconds even if the last 30 s of additions are gone.
const PEERSTORE_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
/// Shallow bins `0..BIN_BALANCE_MAX_BIN` are kept populated by the periodic
/// bin-balance pass. Bin `b` covers a `2^-(b+1)` slice of the keyspace, so
/// the first 8 bins together cover all chunks outside our own `/256`
/// neighbourhood — exactly the part of the address space a collapsed peer
/// set can no longer route retrievals into. Deeper bins fill themselves:
/// hive gossip is biased toward the receiver's own neighbourhood.
const BIN_BALANCE_MAX_BIN: usize = 8;
/// Minimum connected peers per shallow bin before the balance pass starts
/// dialing replacements. Matches bee's kademlia `saturationPeers = 4` —
/// enough fan-out for retrieval forwarding with a candidate to spare when
/// one peer flaps, without inflating the steady-state connection count.
const BIN_BALANCE_MIN_PEERS: usize = 4;
/// Cadence of the bin-balance pass. Collapse is a slow process (hours of
/// churn replacing far peers with gossip-biased near ones), so a 30 s
/// re-check is more than fast enough while keeping the pass — a scan of
/// `known_dialable` — off the hot path.
const BIN_BALANCE_INTERVAL: Duration = Duration::from_secs(30);
/// Cap on dials a single balance pass may fire. A node that just lost a
/// whole region (e.g. resumed from sleep) can be short in every shallow
/// bin at once; bounding the fan-out keeps the handshake pipeline from
/// being drowned, and the next pass (30 s later) finishes the job.
const BIN_BALANCE_DIAL_CAP: usize = 16;

/// Build the [`sinks::SwapWiring`] from `RunConfig::swap` (if set).
/// Returns `None` when SWAP is unconfigured — `sinks::spawn` then
/// installs a drain-only handler so the protocol is still
/// negotiated.
fn build_swap_wiring(cfg: &RunConfig) -> Option<sinks::SwapWiring> {
    let swap = cfg.swap.as_ref()?;
    let ledger = std::sync::Arc::new(crate::swap::CreditLedger::open(
        Some(swap.ledger_path.clone()),
        swap.chain_id,
        swap.our_beneficiary,
    ));
    Some(sinks::SwapWiring {
        ledger,
        events: swap.events_tx.clone(),
    })
}

fn is_loopback_multiaddr(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// Bee's libp2p-go peerstore filters out unroutable addresses (loopback,
/// RFC1918, CGNAT, link-local, IPv6 ULA) when the peer is connected over a
/// public transport. Before we promote an observed address to external we
/// need it to pass the same filter, otherwise we just re-publish what bee
/// will throw away. The IP classification is shared with the peer-underlay
/// dial filter ([`crate::underlay::ip_scope`]).
///
/// Also used as the ground truth for "would our libp2p-identify push help
/// bee's peerstore" — see [`our_identify_useful_for_bee`].
fn is_globally_routable_multiaddr(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    let mut has_ip = false;
    let ok = addr.iter().all(|p| match p {
        Protocol::Ip4(ip) => {
            has_ip = true;
            crate::underlay::is_globally_routable_ip(ip.into())
        }
        Protocol::Ip6(ip) => {
            has_ip = true;
            crate::underlay::is_globally_routable_ip(ip.into())
        }
        _ => true,
    });
    has_ip && ok
}

/// Where we learned an externally-advertised multiaddr from. Kept tiny
/// and `Copy` so it can be passed around without ceremony; rendered as a
/// stable lower-case ASCII tag via [`Self::as_str`] for log lines and the
/// `StatusSnapshot::external_addresses` field. Adding a new source means
/// (a) adding a variant here, (b) wiring the variant through
/// [`record_external_address`] at the relevant call site, and (c)
/// optionally teaching `antop` to render it differently — but
/// unknown sources already round-trip fine since the on-the-wire type
/// is `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalAddrSource {
    /// User-supplied via `--external-address` (i.e. `RunConfig::external_addrs`).
    Manual,
    /// Auto-promoted from a non-loopback `NewListenAddr`. Useful on
    /// public-IP hosts where the listener address is itself dialable.
    Listener,
    /// Promoted from a remote peer's libp2p-identify `observed_addr`.
    /// Catches NAT-punched IPv6 / full-cone IPv4 cases where outside
    /// peers see us at a routable address even without `UPnP`.
    Observed,
    /// Mapped via `libp2p-upnp` talking to a local IGD gateway. Most
    /// common on home routers.
    Upnp,
}

impl ExternalAddrSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Listener => "listener",
            Self::Observed => "observed",
            Self::Upnp => "upnp",
        }
    }
}

/// Centralized add: registers `addr` as an external on the swarm, tracks
/// the source + insertion time in `state`, emits a single attributed
/// `info!` line, and pushes the new set into the status snapshot. No-op
/// when the address is already known — `UPnP` renews mappings every 30 min
/// and we don't want flapping log lines, and re-promoting an address
/// should not silently change its recorded source.
fn record_external_address(
    state: &mut SwarmState,
    swarm: &mut Swarm<AntBehaviour>,
    status: Option<&watch::Sender<StatusSnapshot>>,
    addr: Multiaddr,
    source: ExternalAddrSource,
) {
    if state.external_addresses.contains_key(&addr) {
        return;
    }
    info!(
        target: "ant_p2p",
        %addr,
        source = source.as_str(),
        "advertising external address",
    );
    swarm.add_external_address(addr.clone());
    let added_at_unix = unix_now();
    state
        .external_addresses
        .insert(addr.clone(), (source, added_at_unix));
    state.external_addresses_order.push(addr);
    sync_external_addresses_status(status, state);
}

/// Centralized remove: drops `addr` from the swarm + the tracker, emits
/// a single `info!` line, and pushes the new set into the status
/// snapshot. No-op when the address isn't tracked (e.g. a `UPnP` expiry
/// for a mapping we never accepted because it failed the public-IP filter).
fn forget_external_address(
    state: &mut SwarmState,
    swarm: &mut Swarm<AntBehaviour>,
    status: Option<&watch::Sender<StatusSnapshot>>,
    addr: &Multiaddr,
) {
    if state.external_addresses.remove(addr).is_none() {
        return;
    }
    state.external_addresses_order.retain(|a| a != addr);
    info!(
        target: "ant_p2p",
        %addr,
        "retracting external address",
    );
    swarm.remove_external_address(addr);
    sync_external_addresses_status(status, state);
}

/// Mirror the live external-address set into the status snapshot. Cheap
/// (a handful of entries even on long-running daemons) so we recompute
/// from scratch on every change rather than try to track deltas.
fn sync_external_addresses_status(
    status: Option<&watch::Sender<StatusSnapshot>>,
    state: &SwarmState,
) {
    let Some(tx) = status else { return };
    let snapshot: Vec<ExternalAddressInfo> = state
        .external_addresses_order
        .iter()
        .filter_map(|addr| {
            state
                .external_addresses
                .get(addr)
                .map(|(source, added_at_unix)| ExternalAddressInfo {
                    addr: addr.to_string(),
                    source: source.as_str().to_string(),
                    added_at_unix: *added_at_unix,
                })
        })
        .collect();
    tx.send_modify(|st| st.external_addresses = snapshot);
}

/// Heuristic: will our next libp2p-identify push give bee anything its
/// peerstore will accept? Bee's libp2p-go filters inbound addresses with
/// the same public-IP rules [`is_globally_routable_multiaddr`] enforces, so
/// if none of our advertised externals pass that filter, waiting on
/// `IdentifySent` before opening the BZZ stream is pointless — bee's
/// `peerMultiaddrs` will sit out its 10 s window regardless. We use this
/// to gate [`HANDSHAKE_IDENTIFY_WAIT`] inside [`spawn_handshake_driver`]:
/// when it returns `false` we open the stream immediately and let bee
/// burn the 10 s on its own clock instead of stacking another 3 s of our
/// own on top.
fn our_identify_useful_for_bee(swarm: &Swarm<AntBehaviour>) -> bool {
    swarm
        .external_addresses()
        .any(is_globally_routable_multiaddr)
}

/// One-shot operator nudge: ~10 s into the run, if neither
/// `cfg.external_addrs`, `NewListenAddr` auto-promotion, nor `UPnP` have
/// produced a globally-routable external address, warn that bee will burn
/// its 10 s `peerMultiaddrs` window on every handshake. We wait the grace
/// period rather than warning eagerly because `UPnP`'s SSDP search and
/// listener auto-promotion both happen asynchronously after `run` starts
/// — an eager check would always fire on home networks where things work
/// out a moment later.
fn maybe_warn_no_external_address(swarm: &Swarm<AntBehaviour>, configured: &[Multiaddr]) {
    if our_identify_useful_for_bee(swarm) {
        return;
    }
    if configured.is_empty() {
        warn!(
            target: "ant_p2p",
            "no globally-routable external address after \
             {EXTERNAL_ADDRESS_CHECK_DELAY:?}: UPnP found no IGD gateway and \
             no listener auto-promoted. If this node is behind NAT, bee \
             bootnodes will stall the BZZ handshake by ~10 s waiting for \
             our public multiaddr via libp2p-identify. Pass \
             --external-address /ip4/<public-ip>/tcp/<public-port> to fix.",
        );
    } else {
        // The operator did set `--external-address`, but the values we
        // were given don't pass the public-IP filter (e.g. they typo'd a
        // private IP). Bee will silently drop them on its side; flag it
        // here so the operator notices.
        warn!(
            target: "ant_p2p",
            configured = ?configured,
            "configured --external-address values are not globally \
             routable; bee will reject them via its identify-go filter \
             and the BZZ handshake will still stall ~10 s. Use a public \
             IP and the dialable port that maps to this node.",
        );
    }
}

/// React to events from the bundled `UPnP` behaviour. Successful mappings
/// get promoted to confirmed external addresses (subject to the same
/// public-IP filter bee uses), so the very first outbound identify push
/// after bootstrap already carries our public multiaddr. Renewal failures
/// retract the address. Gateway-search failures are routine on hosts
/// without `UPnP` (most cloud VMs, corporate NAT, CGNAT) and we log them at
/// `debug` rather than nagging the operator.
fn handle_upnp_event(
    state: &mut SwarmState,
    swarm: &mut Swarm<AntBehaviour>,
    status: Option<&watch::Sender<StatusSnapshot>>,
    ev: libp2p::upnp::Event,
) {
    use libp2p::upnp::Event;
    match ev {
        Event::NewExternalAddr(addr) => {
            if is_globally_routable_multiaddr(&addr) {
                record_external_address(state, swarm, status, addr, ExternalAddrSource::Upnp);
            } else {
                debug!(
                    target: "ant_p2p",
                    %addr,
                    "upnp returned a non-globally-routable address; \
                     bee's identify-go would filter it, ignoring",
                );
            }
        }
        Event::ExpiredExternalAddr(addr) => {
            forget_external_address(state, swarm, status, &addr);
        }
        Event::GatewayNotFound => {
            debug!(
                target: "ant_p2p",
                "upnp: no IGD gateway found on this network. \
                 Set --external-address or rely on inbound identify if \
                 this node is behind NAT.",
            );
        }
        Event::NonRoutableGateway => {
            warn!(
                target: "ant_p2p",
                "upnp: gateway is itself behind NAT (likely carrier-grade \
                 NAT). UPnP cannot help here; you'll need a relay or a \
                 routable external address to be reachable from bee peers.",
            );
        }
    }
}

/// Everything `drive_handshake` needs, lifted out of `RunConfig` so it can be
/// cloned into spawned per-peer tasks without touching the main loop's `cfg`.
#[derive(Clone)]
struct HandshakeParams {
    local_peer_id: PeerId,
    signing_secret: [u8; SECP256K1_SECRET_LEN],
    overlay_nonce: [u8; OVERLAY_NONCE_LEN],
    network_id: u64,
}

/// Result of the full per-peer pipeline: wait-for-identify → open BZZ stream
/// → run handshake. Emitted to the main loop over an mpsc channel.
enum DriveOutcome {
    Ok(HandshakeInfo),
    OpenFailed(String),
    HandshakeFailed(HandshakeError),
}

/// Per-peer state tracked while they're moving through the pipeline. The
/// dialed `Multiaddr` is carried through both phases so we can persist it to
/// the peerstore on a successful handshake without going back to libp2p for
/// connection metadata after the fact.
enum PendingPhase {
    /// Dialed or accepted; waiting for libp2p-identify to round-trip so bee's
    /// inbound handshake handler finds us in its peerstore.
    AwaitingIdentify {
        sig: oneshot::Sender<()>,
        addr: Multiaddr,
        identify_started: Instant,
        /// `Some` when we were the dialer and recorded a start in `dial_started`.
        dial_ms: Option<u64>,
    },
    /// Identify sent; the spawned task is opening the BZZ stream and running
    /// the handshake. Kept for cleanup on disconnect plus the dialed addr we
    /// hand to the peerstore on success.
    Handshaking {
        addr: Multiaddr,
        handshake_started: Instant,
        dial_ms: Option<u64>,
        identifying_ms: u64,
    },
}

impl PendingPhase {
    fn dialed_addr(&self) -> Multiaddr {
        match self {
            Self::AwaitingIdentify { addr, .. } | Self::Handshaking { addr, .. } => addr.clone(),
        }
    }
}

/// Swarm-loop accounting: which peers we're mid-handshake with, which have
/// completed, and the dial backlog from hive gossip.
struct PeerFailure {
    peer: PeerId,
    at: Instant,
}

/// First retry delay after an outbound dial to a hinted peer fails at the
/// transport level (no route / refused / timed out on every underlay).
const DIAL_BACKOFF_BASE: Duration = Duration::from_secs(30);
/// Ceiling for the doubling dial backoff.
const DIAL_BACKOFF_MAX: Duration = Duration::from_mins(30);
/// How long a [`LocalSubnets`](crate::underlay::LocalSubnets) snapshot is
/// trusted before the interfaces are re-read (phone switching Wi-Fi ↔
/// cellular changes which private underlays are same-LAN).
const LOCAL_SUBNETS_TTL: Duration = Duration::from_secs(30);

/// Per-peer backoff for dials we drive from hints (hive gossip, peerstore
/// warm-up, neighbourhood / bin-balance dials). Without it a peer whose
/// underlays are all dead is re-dialed on every top-up, every
/// neighbourhood request and every bin-balance pass — a stream of
/// unanswered SYNs that looks like scanning from the outside (issue #88).
struct DialBackoff {
    failures: u32,
    until: Instant,
}

struct SwarmState {
    /// Peers we've dialed but haven't yet seen a `ConnectionEstablished` or
    /// `OutgoingConnectionError` for. Counting these against `target_peers`
    /// is what stops us from firing 4 dials per event-loop iteration and
    /// ballooning the peer set past the cap on fast connections.
    dialing: HashSet<PeerId>,
    /// Wall time when `dialing.insert` happened (outbound dials only).
    dial_started: HashMap<PeerId, Instant>,
    /// Tracked dials (subset of `dial_started`'s keys) that started while
    /// our own connectivity was down ([`SwarmState::own_connectivity_down`]).
    /// Their failure is never charged to the peer, even when it only
    /// arrives (OS SYN timeout, ~75-127 s) after the link is proven again.
    dial_started_unproven: HashSet<PeerId>,
    /// A representative dial address for `antctl` (first hint / bootnode multiaddr).
    dial_hint_addr: HashMap<PeerId, Multiaddr>,
    /// `disconnect_peer_id` was called; connection not fully torn down yet.
    closing: HashSet<PeerId>,
    /// Recent dial or handshake failures (pruned in [`sync_peer_pipeline`]).
    failed: Vec<PeerFailure>,
    pending: HashMap<PeerId, PendingPhase>,
    bzz_peers: HashSet<PeerId>,
    /// Peer ids we dialed as bootnodes ([`handle_bootnode_dial`]). They
    /// count toward `RoutingInfo::serving` (`/readiness`) only after
    /// [`BOOTNODE_SERVING_GRACE`] in the routing table — see
    /// [`serving_peer_count`].
    bootnode_peers: HashSet<PeerId>,
    /// When each routing-table entry was admitted. Removed with the entry
    /// on `ConnectionClosed`.
    routing_admitted_at: HashMap<PeerId, Instant>,
    /// Total cold-start time (dial + identify + handshake, in ms) for each
    /// peer that has reached `Ready`. Surfaced as `ready_in_ms` on the
    /// pipeline rows so `antop` can show the column and rank slow
    /// peers. Reset on `ConnectionClosed` together with `bzz_peers`, so a
    /// reconnect always reports the new pipeline's timing rather than a
    /// stale one.
    ready_in_ms: HashMap<PeerId, u64>,
    /// Forwarding-Kademlia routing table populated as each outbound BZZ
    /// handshake completes; consumed by the retrieval client to pick which
    /// peer to ask for a given chunk. Mirrors `bzz_peers` but carries the
    /// overlay alongside the peer-id and indexes by proximity order.
    routing: RoutingTable,
    /// Bounded book of *known* peers — connected peers plus those
    /// discovered via hive gossip but not currently connected, deduped
    /// by overlay. Fed in [`SwarmState::enqueue_hint`] and on handshake
    /// success, pruned on the periodic tick, and never cleared on
    /// disconnect (a known peer persists until its TTL lapses). bee
    /// reports `sum(bins[*].population)` from this as "visible peers",
    /// distinct from the smaller connected `routing` working set.
    known: KnownPeers,
    /// All peer ids we've ever had a hint for, whether enqueued or already
    /// dialed. Stops hive's Peers broadcasts from queueing the same peer
    /// repeatedly as every bootnode gossips its neighbourhood to us.
    /// Rebuilt from `hint_queue` once it passes twice
    /// [`KNOWN_DIALABLE_CAP`] (see `enqueue_hint`).
    seen_hints: HashSet<PeerId>,
    /// FIFO of hints waiting to be dialed, at most [`KNOWN_DIALABLE_CAP`]
    /// long (the oldest is evicted).
    hint_queue: VecDeque<sinks::PeerHint>,
    /// [`RunConfig::allow_private_dials`]: skip the peer-underlay filter.
    allow_private_dials: bool,
    /// Cached snapshot of this host's subnets for the same-LAN exception
    /// of the underlay filter, with the time it was taken.
    local_subnets: Option<(Instant, crate::underlay::LocalSubnets)>,
    /// Hint-dial backoff for peers whose dials failed; cleared when a
    /// connection to the peer is established. See [`DialBackoff`].
    dial_backoff: HashMap<PeerId, DialBackoff>,
    target_peers: usize,
    /// Order in which peers first appeared in the pipeline. Used as the sort
    /// key in [`build_peer_pipeline_entries`] so new peers are appended to
    /// the bottom of the rendered table instead of jumping around as their
    /// state advances. Pruned to whatever's currently in the pipeline on
    /// every rebuild so it can't grow unbounded across long sessions.
    peer_order: HashMap<PeerId, u64>,
    next_peer_order: u64,
    /// Process-wide chunk cache, when enabled. `Some(cache)` means
    /// every `GetBytes` / `GetBzz` clones this single `Arc`, so chunks
    /// fetched on request N are reusable for request N+1. `None`
    /// means each request builds its own fresh `InMemoryChunkCache`
    /// (intra-request retries still cache-hit; consecutive
    /// `antctl get` calls start cold). Toggled by
    /// `RunConfig::per_request_chunk_cache`.
    chunk_cache: Option<Arc<ant_retrieval::InMemoryChunkCache>>,
    /// Process-wide persistent chunk cache. `Some` when the daemon
    /// has been configured with `--disk-cache-path`; cloned into
    /// every `RoutingFetcher` we build (modulo `bypass_cache`).
    /// Lifetime matches the daemon process; the underlying `SQLite`
    /// connection is shared via `Arc` so we don't pay a new open
    /// per request.
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    /// Optional fixture-capture directory; cloned into every
    /// `RoutingFetcher` we build for a `GetBytes` / `GetBzz` request,
    /// so each chunk fetched (or served from the cache) gets dumped
    /// to disk. Set from `RunConfig::chunk_record_dir`.
    chunk_record_dir: Option<PathBuf>,
    /// Live `(PeerId, Overlay)` snapshot of the routing table, refreshed
    /// every time we admit or forget a peer. Spawned `GetBytes` /
    /// `GetBzz` tasks subscribe to this watch and re-read it at the
    /// start of every retry attempt — that's how we avoid pinning a
    /// minute-stale peer list across a 3+ minute multi-chunk fetch.
    /// Bee peers churn aggressively (libp2p connections regularly
    /// open and close within a few seconds during normal swarm
    /// activity), and a snapshot frozen at command time would leave
    /// the fetcher trying to open streams on long-dead connections —
    /// which surfaces in the logs as `io: <peer>/N: connection is closed`
    /// or `oneshot canceled` from the libp2p stream-open path. The
    /// retry loop's whole point is to re-roll against the *current*
    /// network state, not the network state from before the fetch
    /// started.
    peers_watch: watch::Sender<Vec<(PeerId, Overlay)>>,
    /// Shared lurker registry: one GSOC/PSS pull pipeline per target
    /// neighborhood, fanned out to every WS subscriber on it (see
    /// [`crate::lurker_registry`]). Per-node, not process-wide — tests
    /// run several nodes in one process.
    lurkers: crate::lurker_registry::Registry,
    /// Process-wide cap on concurrent `retrieve_chunk` calls. Cloned
    /// into every `RoutingFetcher` we build for any `GetBytes` /
    /// `GetBzz` request, so the cap applies across concurrent
    /// requests rather than per-request. The cap is deliberately below
    /// the unbounded browser stampede (~60 simultaneous retrieval
    /// streams in the four-WAV repro), but high enough that several
    /// large gateway downloads can make progress at once.
    retrieval_inflight: Arc<Semaphore>,
    /// One-permit gate serialising deep verification passes
    /// (`VerifyPropagation` and the deep arm of `VerifyChunksPresent`)
    /// process-wide. The probe stage of a verification fans out dozens
    /// of raw `retrieve_chunk` streams; two verifications racing (the
    /// Drive app fires one per completed file at once) saturate the
    /// peer set and fail each other's probes — the same file that
    /// verifies clean alone reported ~30% of its chunks missing when
    /// checked alongside a sibling. Serialised, each verification gets
    /// the node's full bandwidth and verdicts stay reproducible.
    verify_gate: Arc<Semaphore>,
    /// Notification channel into the pseudosettle driver. Cloned into
    /// every `RoutingFetcher` so successful chunk fetches feed the
    /// driver's per-peer activity tracker. Set lazily by the run loop
    /// after `mpsc::channel` is created (the channel sender doesn't
    /// outlive the driver task, and the run loop owns both).
    payment_notify: Option<mpsc::Sender<PeerId>>,
    /// Shared client-side accounting mirror. Built once and cloned
    /// into every fetcher and into the pseudosettle driver. The
    /// fetcher uses it for admission control on dispatch
    /// (`Accounting::try_reserve`); the driver uses it to credit
    /// peers back on every accepted refresh
    /// (`Accounting::credit`); the swarm calls
    /// `Accounting::forget` from `ConnectionClosed` so peer state
    /// matches bee's `notifyPeerConnect` reset on the remote end.
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    /// Process-wide retrieval counters. Cloned into every
    /// `RoutingFetcher` we build; read on every status tick to
    /// populate the cumulative `bytes_fetched_total` /
    /// `chunks_fetched_total` fields in `StatusSnapshot::retrieval`.
    retrieval_counters: Arc<RetrievalCounters>,
    /// Optional live registry of in-flight gateway HTTP requests.
    /// `None` when `--no-http-api` was passed; `Some` when the
    /// gateway is wired up. Read by the status publisher for the
    /// Retrieval tab in `antop`.
    gateway_activity: Option<Arc<GatewayActivity>>,
    /// One-shot guard for the "slow handshake = bee peerstore stall"
    /// `warn!` we emit on the first handshake whose timing matches the
    /// pattern (`handshake_ms` ≥ 5 s, `identifying_ms` < 200 ms). Without
    /// the guard the warning would fire on every slow peer until the
    /// operator fixes the cause. The flag is intentionally not reset on
    /// `RunConfig` reload — once an operator has been told, we don't keep
    /// nagging.
    bee_peerstore_stall_warning_emitted: bool,
    /// Live set of externally-advertised multiaddrs and how each was
    /// learned. Maintained in lockstep with `swarm.external_addresses()`
    /// via [`record_external_address`] / [`forget_external_address`] so
    /// the status snapshot can attribute each address to a source.
    /// Indexed by multiaddr for O(1) duplicate suppression; insertion
    /// order is tracked separately in [`Self::external_addresses_order`]
    /// so the on-wire snapshot stays deterministic.
    external_addresses: HashMap<Multiaddr, (ExternalAddrSource, u64)>,
    /// Insertion order for `external_addresses` so renders are stable.
    /// Wide enough to keep one slot per address ever advertised in this
    /// process; `UPnP` / listener churn keeps this very small in practice.
    external_addresses_order: Vec<Multiaddr>,
    /// Shared `peer_id -> ethereum_address` map. Populated in the
    /// BZZ-handshake-success branch of `apply_drive_outcome`; consumed
    /// by [`crate::PushsyncSwap`] to look up the cheque beneficiary
    /// for a libp2p peer. Cloned from `RunConfig::peer_eth` so the
    /// owner outside the swarm loop (e.g. a future `antctl swap
    /// snapshot` HTTP handler) can read the same registry.
    peer_eth: crate::PeerEthMap,
    /// Outbound SWAP settlement service. Built once at swarm startup
    /// from `RunConfig::pushsync_swap` (if set) using the swarm's
    /// `libp2p_stream::Control`, then cloned into every
    /// `RoutingFetcher` for `PushChunk` requests so the per-peer
    /// debt counter is shared across uploads. `None` keeps the
    /// legacy "push without settlement" behaviour for ultra-light
    /// reads + tests.
    pushsync_swap: Option<Arc<crate::PushsyncSwap>>,
    /// Outbound ledger of the last service `DisablePushsyncSwap` turned
    /// off. Its cheques are still outstanding, so while no service runs
    /// the accounting snapshot keeps reporting them (for the chequebook
    /// it names) instead of claiming nothing was issued.
    retired_outbound: Option<crate::swap::OutboundLedger>,
    /// Inbound SWAP credit ledger (cheques peers paid us), shared with
    /// the swap sink task spawned by `sinks::spawn`. Retained here so
    /// [`ControlCommand::AccountingSnapshot`] can render the
    /// `swap_received` / `cheque_received` side of the gateway's
    /// `/settlements` and `/chequebook/cheque` endpoints. `None` when
    /// the operator didn't configure inbound SWAP (no beneficiary),
    /// in which case every received-side field is absent — honest:
    /// without a ledger we accept no cheques.
    credit_ledger: Option<Arc<crate::swap::CreditLedger>>,
    /// `swap-enable` (issues #121, #127): `false` keeps downloads and
    /// uploads on the free tier whatever the chequebook holds.
    swap_enabled: bool,
    /// The node's status channel, so settlement changes made from a
    /// control command reach `StatusSnapshot::settlement` (see
    /// [`publish_settlement`]). `None` in tests and embeddings without
    /// one.
    status: Option<watch::Sender<StatusSnapshot>>,
    /// Latest `SetRetrievalFunds` and the chequebook it's for. Applied to
    /// the outbound SWAP service whenever it runs on that chequebook, so
    /// funds read before the service starts (antd's late chain init) are
    /// not lost.
    retrieval_funds: Option<([u8; 20], crate::RetrievalSwapPolicy)>,
    /// Process-wide push-side peer skip cache. Cloned into every
    /// `RoutingFetcher` built for `PushChunk` / `PushSoc` so a peer
    /// that just bounced a pushsync on chunk N is excluded from
    /// chunk N+1's candidate list for the cache's TTL (5 s). The
    /// per-chunk skip list inside `push_stamped_chunk` is still in
    /// effect and gives same-chunk retries their own scope; the
    /// cache adds the missing cross-chunk dimension so a single
    /// flapping bee 2.7.1 storer can't get re-picked dozens of
    /// times across a multi-chunk upload. See
    /// [`ant_retrieval::PushSkipCache`] for the design rationale.
    push_skip: ant_retrieval::PushSkipCache,
    /// Per-peer pushsync load tracker (perf-lab Experiment 2). `Some`
    /// only when `ANT_PUSH_INFLIGHT_CAP` is set — one build serves
    /// both A/B benchmark arms.
    push_load: Option<Arc<ant_retrieval::PushLoadTracker>>,
    /// Batches storer peers have rejected as not-on-chain (peer-
    /// attested phantom batches). Fed by the push paths on
    /// `StampRejected`; consulted by `PostageStatus`/`PostageList` so
    /// `/stamps` stops reporting a dead batch as usable after the
    /// first failed push. Each entry carries a **self-probe schedule**
    /// (issue #52): clients filter on `usable`, so nothing external
    /// ever pushes with a rejected batch again — the node re-validates
    /// it itself with backoff and clears the mark when peers accept.
    rejected_batches: RejectedBatches,
    /// Pushes answered at "stored" whose deep-storer hunt is still
    /// running (`ack_when_stored`, issue #212); see
    /// [`MAX_BACKGROUND_HUNTS`].
    background_hunts: Arc<Semaphore>,
    /// When each batch was registered at runtime via
    /// `ControlCommand::RegisterBatch` (a buy or connect). Surfaced as
    /// `PostageStatusView::registered_secs_ago` so the gateway's
    /// `/stamps` doesn't declare a just-bought batch "not on chain"
    /// because a lagging RPC backend hasn't seen its `BatchCreated`
    /// block yet. Batches reloaded from disk at startup have no entry.
    runtime_registered: HashMap<[u8; 32], Instant>,
    /// Batches registered right after this node bought them
    /// (`RegisterBatch::bought_at_block`). Until [`BATCH_PROPAGATION`]
    /// has passed, such a batch is reported not usable, and a peer's
    /// "not found on-chain" is propagation lag rather than a phantom
    /// batch.
    bought_batches: HashMap<[u8; 32], BoughtBatch>,
    /// Last successfully-resolved sequence-feed index per
    /// `(owner, topic)` (perf-lab Experiment 6b). Sequence feeds are
    /// append-only, so a previously-resolved index is always a valid
    /// anchor: warm re-polls gallop from it instead of re-walking the
    /// whole sequence (measured: warm == cold at up to 4.3 s without
    /// this). In-memory only — a restart just pays one cold walk.
    /// Shared by `GET /feeds` (`GetFeed`) and the `/bzz` feed-manifest
    /// dereference (`StreamBzz`, `GetBzz`; issue #159), so either one
    /// warms the other.
    feed_hints: ant_retrieval::FeedHints,
    /// Neighbourhoods where a push recently couldn't reach a deep storer
    /// (shared by every push fetcher; see
    /// [`ant_retrieval::ShallowNeighbourhoods`]).
    shallow_neighbourhoods: Arc<ant_retrieval::ShallowNeighbourhoods>,
    /// Pushes in flight and recently stored, so a duplicate waits for or
    /// reuses an earlier push (see [`crate::push_dedup`]).
    push_dedup: Arc<crate::push_dedup::PushDedup>,
    /// Overlay-indexed dial book: every peer we've learned about via hive
    /// gossip (or the on-disk peerstore) that we are *not* currently
    /// connected to, retained with its dial multiaddrs + overlay. Unlike
    /// `hint_queue` (FIFO, drained once) and `known` (overlay counts only,
    /// no addresses), this lets us dial *toward an arbitrary target
    /// address* on demand — the building block for reaching a chunk's deep
    /// neighbourhood during an upload, the way a full bee node's saturated
    /// Kademlia always has a peer close to any chunk. Bounded by
    /// [`KNOWN_DIALABLE_CAP`]; entries are removed once the peer connects.
    known_dialable: HashMap<PeerId, sinks::PeerHint>,
    /// Sender half of the on-demand neighbourhood-dial channel. Cloned into
    /// every upload-side `RoutingFetcher`; when a push can't find a
    /// connected peer inside a chunk's neighbourhood, the fetcher sends the
    /// chunk address here and the swarm loop dials the closest peers it
    /// knows about (from `known_dialable`) toward that address. `None`
    /// until `run` wires the channel (and in tests).
    neighborhood_dial_tx: Option<mpsc::Sender<[u8; 32]>>,
    /// Hands chunks to be stamped to the stamper task (see
    /// [`run_stamper`]), which stamps them in batches off this loop.
    /// `None` until `run` wires it (and in tests): `PushChunk` then
    /// stamps inline, one chunk at a time.
    stamp_tx: Option<mpsc::UnboundedSender<StampJob>>,
    /// Per-connection ping liveness (issue #83): which connections still
    /// answer, which to close as dead, and what `peers.connected` counts.
    liveness: Liveness,
}

impl SwarmState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        target_peers: usize,
        base_overlay: Overlay,
        per_request_chunk_cache: bool,
        chunk_record_dir: Option<PathBuf>,
        gateway_activity: Option<Arc<GatewayActivity>>,
        disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
        peer_eth: crate::PeerEthMap,
    ) -> Self {
        let chunk_cache = if per_request_chunk_cache {
            None
        } else {
            Some(Arc::new(
                ant_retrieval::InMemoryChunkCache::with_default_capacity(),
            ))
        };
        Self {
            dialing: HashSet::new(),
            dial_started: HashMap::new(),
            dial_started_unproven: HashSet::new(),
            dial_hint_addr: HashMap::new(),
            closing: HashSet::new(),
            failed: Vec::new(),
            pending: HashMap::new(),
            bzz_peers: HashSet::new(),
            bootnode_peers: HashSet::new(),
            routing_admitted_at: HashMap::new(),
            ready_in_ms: HashMap::new(),
            routing: RoutingTable::new(base_overlay),
            known: KnownPeers::new(base_overlay),
            seen_hints: HashSet::new(),
            hint_queue: VecDeque::new(),
            allow_private_dials: false,
            local_subnets: None,
            dial_backoff: HashMap::new(),
            target_peers,
            peer_order: HashMap::new(),
            next_peer_order: 0,
            chunk_cache,
            disk_cache,
            chunk_record_dir,
            peers_watch: watch::channel(Vec::new()).0,
            lurkers: crate::lurker_registry::Registry::new(),
            retrieval_inflight: Arc::new(Semaphore::new(RETRIEVAL_INFLIGHT_CAP)),
            verify_gate: Arc::new(Semaphore::new(1)),
            payment_notify: None,
            accounting: None,
            retrieval_counters: Arc::new(RetrievalCounters::new()),
            gateway_activity,
            bee_peerstore_stall_warning_emitted: false,
            external_addresses: HashMap::new(),
            external_addresses_order: Vec::new(),
            peer_eth,
            pushsync_swap: None,
            retired_outbound: None,
            credit_ledger: None,
            swap_enabled: true,
            status: None,
            retrieval_funds: None,
            push_skip: ant_retrieval::PushSkipCache::new(),
            push_load: ant_retrieval::PushLoadTracker::from_env().map(Arc::new),
            rejected_batches: Arc::new(std::sync::Mutex::new(HashMap::new())),
            background_hunts: Arc::new(Semaphore::new(MAX_BACKGROUND_HUNTS)),
            runtime_registered: HashMap::new(),
            bought_batches: HashMap::new(),
            feed_hints: ant_retrieval::FeedHints::new(),
            shallow_neighbourhoods: Arc::default(),
            push_dedup: Arc::default(),
            known_dialable: HashMap::new(),
            neighborhood_dial_tx: None,
            stamp_tx: None,
            liveness: Liveness::new(LivenessConfig::DEFAULT, Instant::now()),
        }
    }

    /// Republish the current routing-table snapshot on `peers_watch`.
    /// Call after every `routing.admit` / `routing.forget`. Cheap: the
    /// snapshot is at most a few hundred `(PeerId, [u8; 32])` pairs and
    /// `watch::Sender::send_replace` does a single move + wake of any
    /// borrow-blocked readers (there aren't any during normal operation
    /// — the spawned retry tasks read on attempt boundaries, not
    /// continuously).
    fn publish_peers(&self) {
        let snapshot = self.routing.snapshot();
        self.peers_watch.send_replace(snapshot);
    }

    /// Resolve the chunk cache for one user-visible `GetBytes` / `GetBzz`
    /// command: clone the shared daemon cache if it's enabled, or
    /// mint a brand-new cache for this request only. Either way the
    /// returned `Arc` is what the request's retry loop hands to every
    /// `RoutingFetcher` it builds, so intra-request retries always
    /// share a cache and only inter-request reuse depends on the flag.
    ///
    /// `bypass_cache` overrides the daemon-wide setting for this one
    /// request: a fresh `InMemoryChunkCache` is always returned, so
    /// no chunk hits or writes touch the long-lived cache.
    fn cache_for_request(&self, bypass_cache: bool) -> Arc<ant_retrieval::InMemoryChunkCache> {
        if bypass_cache {
            return Arc::new(ant_retrieval::InMemoryChunkCache::with_default_capacity());
        }
        match &self.chunk_cache {
            Some(c) => c.clone(),
            None => Arc::new(ant_retrieval::InMemoryChunkCache::with_default_capacity()),
        }
    }

    /// Resolve the *persistent* chunk cache for one user-visible
    /// request. `bypass_cache` returns `None` so the request neither
    /// reads from nor writes to the long-lived disk cache — exactly
    /// the contract `PLAN.md` § 6.1 calls out: "Request-level cache
    /// bypass must skip both disk reads and disk writes". When the
    /// daemon was started without a disk cache, this is always
    /// `None`.
    fn disk_cache_for_request(
        &self,
        bypass_cache: bool,
    ) -> Option<Arc<ant_retrieval::DiskChunkCache>> {
        if bypass_cache {
            return None;
        }
        self.disk_cache.clone()
    }

    fn peer_set_size(&self) -> usize {
        self.bzz_peers.len()
    }

    /// Everything we're counting against `target_peers`: live dials, peers
    /// mid-handshake, and completed peers.
    fn pipeline_size(&self) -> usize {
        self.dialing.len() + self.pending.len() + self.bzz_peers.len()
    }

    /// Filter a peer's advertised underlays down to the ones worth dialing
    /// from here — see [`crate::underlay::filter_dialable_underlays`].
    ///
    /// Called both when a hint is enqueued *and* again right before every
    /// hint-driven dial: a same-LAN private underlay admitted on the home
    /// Wi-Fi must not be dialed after the host moved to cellular.
    fn dialable_underlays(&mut self, addrs: &[Multiaddr]) -> Vec<Multiaddr> {
        if self.allow_private_dials {
            return addrs.to_vec();
        }
        self.refresh_local_subnets();
        let local = self
            .local_subnets
            .as_ref()
            .map(|(_, l)| l)
            .expect("refreshed above");
        crate::underlay::filter_dialable_underlays(addrs, local, false)
    }

    /// Re-read the host's subnets once the cached snapshot is older than
    /// [`LOCAL_SUBNETS_TTL`]. When they changed (Wi-Fi ↔ cellular, a new
    /// LAN, a DHCP lease with a different address), every private underlay
    /// cached in `known_dialable` / `hint_queue` was admitted against the
    /// *old* network — possibly a different LAN that happens to use the
    /// same `192.168.1.0/24` numbering — so drop them all. Hive gossip
    /// re-teaches the ones that are same-LAN on the new network, and they
    /// get filtered against the new snapshot on the way in.
    ///
    /// Residual gap: hopping between two LANs with identical numbering
    /// *and* an identical local address within one TTL is not detectable
    /// from interface data alone.
    fn refresh_local_subnets(&mut self) {
        let stale = self
            .local_subnets
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= LOCAL_SUBNETS_TTL);
        if !stale {
            return;
        }
        match crate::underlay::LocalSubnets::from_interfaces() {
            Some(fresh) => self.set_local_subnets(fresh),
            // A failed interface read is not "no networks": keep trusting
            // the previous snapshot for another TTL rather than purging the
            // caches and rejecting every same-LAN underlay (then purging
            // again once the next read succeeds).
            None => self.interfaces_unreadable(),
        }
    }

    /// Enumerating the host's interfaces failed. With a previous snapshot,
    /// keep it (re-stamped, so the read is retried after another TTL rather
    /// than on every dial). With none yet, fall back to an empty set — no
    /// private underlay is admitted, the safe direction — and since nothing
    /// private was cached against it, the change on the next good read
    /// purges nothing.
    fn interfaces_unreadable(&mut self) {
        match self.local_subnets.as_mut() {
            Some((at, _)) => *at = Instant::now(),
            None => {
                self.local_subnets =
                    Some((Instant::now(), crate::underlay::LocalSubnets::default()));
            }
        }
    }

    /// Install a new subnet snapshot, purging cached private underlays if
    /// it differs from the previous one. See [`Self::refresh_local_subnets`].
    fn set_local_subnets(&mut self, fresh: crate::underlay::LocalSubnets) {
        let changed = self
            .local_subnets
            .as_ref()
            .is_some_and(|(_, old)| !old.same_networks(&fresh));
        self.local_subnets = Some((Instant::now(), fresh));
        if changed {
            self.purge_private_underlays();
        }
    }

    /// Strip every private-scope underlay from the cached dial book and
    /// queue, dropping hints left with nothing to dial. A queued hint that
    /// is dropped also leaves `seen_hints`, so gossip can re-queue the peer
    /// once it is reachable again (e.g. back on the same LAN) — otherwise
    /// the dedup would keep it out of `fill_pipeline_from_hints` until a
    /// `force_resume` / re-warm clears the whole set.
    fn purge_private_underlays(&mut self) {
        let strip = |hint: &mut sinks::PeerHint| {
            hint.addrs.retain(|a| !crate::underlay::has_private_ip(a));
            !hint.addrs.is_empty()
        };
        let before = self.known_dialable.len() + self.hint_queue.len();
        self.known_dialable.retain(|_, hint| strip(hint));
        let seen_hints = &mut self.seen_hints;
        self.hint_queue.retain_mut(|hint| {
            let keep = strip(hint);
            if !keep {
                seen_hints.remove(&hint.peer_id);
            }
            keep
        });
        let dropped = before - (self.known_dialable.len() + self.hint_queue.len());
        debug!(
            target: "ant_p2p",
            dropped,
            "local networks changed; dropped cached private underlays",
        );
    }

    /// Re-filter a cached hint's underlays against the *current* networks
    /// right before dialing it. Returns `None` (and forgets the peer's
    /// cached dial info) when nothing dialable is left.
    fn addrs_for_dial(&mut self, hint: &sinks::PeerHint) -> Option<Vec<Multiaddr>> {
        let addrs = self.dialable_underlays(&hint.addrs);
        if addrs.is_empty() {
            self.known_dialable.remove(&hint.peer_id);
            return None;
        }
        Some(addrs)
    }

    /// Is a hint-driven dial to `peer` currently suppressed by
    /// [`DialBackoff`]?
    fn dial_backed_off(&self, peer: &PeerId) -> bool {
        self.dial_backoff
            .get(peer)
            .is_some_and(|b| b.until > Instant::now())
    }

    /// Record an outbound dial failure: double the peer's backoff (from
    /// [`DIAL_BACKOFF_BASE`] up to [`DIAL_BACKOFF_MAX`]).
    fn note_dial_failure(&mut self, peer: PeerId) {
        let entry = self.dial_backoff.entry(peer).or_insert(DialBackoff {
            failures: 0,
            until: Instant::now(),
        });
        entry.failures = entry.failures.saturating_add(1);
        let delay = DIAL_BACKOFF_BASE
            .saturating_mul(1u32 << entry.failures.saturating_sub(1).min(16))
            .min(DIAL_BACKOFF_MAX);
        entry.until = Instant::now() + delay;
    }

    /// Are we cut off ourselves? Then an outbound dial failure says more
    /// about our own link (no network, Wi-Fi ↔ cellular handover, the OS
    /// suspending sockets) than about the remote peer, so it must not be
    /// charged to that peer.
    ///
    /// An empty peer set is the obvious case. A full one proves nothing
    /// (issue #90): after a suspend or a handover `bzz_peers` stays
    /// populated with zombie sockets until the liveness pass closes them
    /// (~30 s), and every dial in that window fails. So the link also
    /// counts as down while no connection has answered a ping lately, or
    /// none has since a stall / `Resume` / self-heal
    /// ([`Liveness::network_unproven`]).
    fn own_connectivity_down(&self) -> bool {
        self.bzz_peers.is_empty() || self.liveness.network_unproven(Instant::now())
    }

    /// Record that we just started a tracked outbound dial to `peer`, and
    /// whether our own link was down at that moment (see
    /// [`note_outgoing_dial_error`]).
    fn note_dial_started(&mut self, peer: PeerId) {
        self.dial_started.insert(peer, Instant::now());
        if self.own_connectivity_down() {
            self.dial_started_unproven.insert(peer);
        } else {
            self.dial_started_unproven.remove(&peer);
        }
    }

    /// Clear the hint dedup and re-queue every peerstore entry. With
    /// `clear_backoff`, also forget those peers' [`DialBackoff`] so the
    /// re-warm actually redials them now instead of skipping every
    /// known-good peer until its (up to [`DIAL_BACKOFF_MAX`]) window
    /// expires. Returns the number of hints re-queued.
    fn rewarm_from_peerstore(
        &mut self,
        peerstore: &PeerStore,
        local_peer_id: PeerId,
        clear_backoff: bool,
    ) -> usize {
        // Clear the dedup so peers we've connected to before can re-enter
        // the queue; `enqueue_hint` still filters currently-live peers, so
        // a wholesale clear doesn't disturb surviving connections.
        self.seen_hints.clear();
        let warm = peerstore.warm_hints();
        let warmed = warm.len();
        for hint in warm {
            if clear_backoff {
                self.dial_backoff.remove(&hint.peer_id);
            }
            self.enqueue_hint(hint, local_peer_id);
        }
        warmed
    }

    /// Pop the next queued hint worth dialing, skipping peers that are
    /// already live / mid-pipeline / backed off. A backed-off peer is
    /// dropped from the queue *and* from `seen_hints`: keeping it queued
    /// would either spin the fill loop on it or need a second, time-ordered
    /// queue, whereas forgetting the dedup lets the next hive gossip (or a
    /// re-warm) re-queue it, and `enqueue_hint` → this check simply drops it
    /// again until the backoff has expired. The peer's dial info stays in
    /// `known_dialable` either way.
    fn pop_dialable_hint(&mut self) -> Option<sinks::PeerHint> {
        while let Some(hint) = self.hint_queue.pop_front() {
            if self.bzz_peers.contains(&hint.peer_id)
                || self.pending.contains_key(&hint.peer_id)
                || self.dialing.contains(&hint.peer_id)
            {
                continue;
            }
            if self.dial_backed_off(&hint.peer_id) {
                self.seen_hints.remove(&hint.peer_id);
                continue;
            }
            return Some(hint);
        }
        None
    }

    fn enqueue_hint(&mut self, mut hint: sinks::PeerHint, local_peer_id: PeerId) {
        // Record the overlay in the known-peer book *before* the
        // dial-dedup early-returns below: every hive advert counts
        // toward "visible peers" even when we never dial it (the peer
        // set is already full, or we've seen its peer-id before). Skip
        // our own overlay.
        if hint.peer_id != local_peer_id {
            self.known.note(hint.overlay);
        }
        // Drop the underlays that only mean something inside the peer's
        // own network (Docker/Kubernetes pod IPs, RFC1918, loopback, …)
        // before the hint can reach any dial path — `fill_pipeline_from_hints`,
        // `dial_toward_target` and bin balancing all dial `hint.addrs`
        // (each re-filters against the current networks right before
        // dialing, see `addrs_for_dial`). A peer with nothing dialable left
        // is not queued at all: `DialOpts::peer_id(..).addresses(vec![])`
        // does not extend the list through the behaviour, so the dial would
        // only fail with `NoAddresses` and burn a pipeline slot.
        let advertised = hint.addrs.len();
        hint.addrs = self.dialable_underlays(&hint.addrs);
        if hint.addrs.is_empty() {
            if advertised > 0 {
                trace!(
                    target: "ant_p2p",
                    peer = %hint.peer_id,
                    advertised,
                    "hint has no dialable underlay; skipping",
                );
            }
            return;
        }
        if hint.peer_id != local_peer_id {
            // Retain the full dial info (addrs + overlay) so we can dial
            // *toward a chunk's neighbourhood* on demand later — even for
            // peers we don't dial now (peer set full / already seen).
            // Skip peers that carry no overlay (older hive adverts) since
            // we can't rank those by proximity to a target.
            if hint.overlay != [0u8; 32] && !self.bzz_peers.contains(&hint.peer_id) {
                if self.known_dialable.len() >= KNOWN_DIALABLE_CAP
                    && !self.known_dialable.contains_key(&hint.peer_id)
                {
                    // Bound the book: drop one arbitrary stale entry. The
                    // hive stream constantly refreshes, so a dropped entry
                    // that's still live will be re-learned shortly.
                    if let Some(victim) = self.known_dialable.keys().next().copied() {
                        self.known_dialable.remove(&victim);
                    }
                }
                self.known_dialable.insert(hint.peer_id, hint.clone());
            }
        }
        if hint.peer_id == local_peer_id
            || self.bzz_peers.contains(&hint.peer_id)
            || self.pending.contains_key(&hint.peer_id)
            || self.dialing.contains(&hint.peer_id)
            || !self.seen_hints.insert(hint.peer_id)
        {
            return;
        }
        // Issue #202: bound the queue and its dedup set. With a full peer
        // set `fill_pipeline_from_hints` drains nothing, so a peer
        // streaming fabricated hive adverts would otherwise grow both
        // without limit. Evict the oldest queued hint and forget its
        // dedup entry, so fresh gossip can re-queue it later.
        if self.hint_queue.len() >= KNOWN_DIALABLE_CAP {
            if let Some(evicted) = self.hint_queue.pop_front() {
                if evicted.peer_id != hint.peer_id {
                    self.seen_hints.remove(&evicted.peer_id);
                }
            }
        }
        // `seen_hints` also keeps every peer already popped and dialed.
        // Past twice the cap, rebuild it from what is still queued: the
        // dialed peers are forgotten, as the churn re-warm in
        // `maybe_top_up_peers` already does wholesale, and live / mid-dial
        // peers stay filtered by the checks above.
        if self.seen_hints.len() > 2 * KNOWN_DIALABLE_CAP {
            self.seen_hints = self
                .hint_queue
                .iter()
                .map(|h| h.peer_id)
                .chain(std::iter::once(hint.peer_id))
                .collect();
        }
        self.hint_queue.push_back(hint);
    }
}

/// Book-keeping for an `OutgoingConnectionError` on `peer`.
///
/// While our own connectivity is down (no connected bzz peer, or none of
/// our connections answering lately, see
/// [`SwarmState::own_connectivity_down`]) the failure is not charged to the
/// peer at all: neither the in-memory [`DialBackoff`] nor the peerstore's
/// consecutive-failure count moves. Both would otherwise punish every peer
/// we try during a local outage — the backoff by keeping known-good peers
/// undialed for up to [`DIAL_BACKOFF_MAX`] once the link is back, and the
/// peerstore (worse, and permanent) by evicting them after `MAX_FAIL_COUNT`
/// failures, which empties exactly the list the post-outage re-warm dials
/// from. The cost is that a genuinely dead peer isn't charged for the
/// attempts that fail during a cold start, or after a `Resume` before any
/// connection has answered again.
///
/// A tracked dial is judged by the link's state when it *started* as well:
/// one begun while connectivity was down, or before a later suspected
/// network change (`Resume`, self-heal, loop stall), isn't charged even if
/// its failure arrives after the link is proven again.
fn note_outgoing_dial_error(state: &mut SwarmState, peerstore: &mut PeerStore, p: PeerId) {
    // `dial_started` is set by the two paths that *we* drive
    // (bootstrap_dial, fill_pipeline_from_hints). Any other
    // outbound dial — e.g. a libp2p-internal redial or a stray
    // address book attempt — would otherwise pollute the
    // pipeline with `Failed` rows the operator never asked for.
    let started = state.dial_started.remove(&p);
    let started_unproven = state.dial_started_unproven.remove(&p);
    let was_tracked = started.is_some();
    state.dialing.remove(&p);
    state.dial_hint_addr.remove(&p);
    if was_tracked {
        record_swarm_failure(state, p);
    }
    // Judge the link both now and as it was when the dial started: a SYN
    // sent during the zombie / post-`Resume` window (or before a later
    // suspected network change) only fails after the OS SYN timeout
    // (~75 s iOS, ~127 s Linux; the swarm sets no dial timeout), by which
    // time a new link may already have answered a ping. That failure is
    // still about our old link, not the peer.
    if state.own_connectivity_down()
        || started_unproven
        || started.is_some_and(|t| state.liveness.suspected_since(t))
    {
        return;
    }
    if was_tracked {
        state.note_dial_failure(p);
    }
    // Stored entries that go dud get evicted after
    // [`MAX_FAIL_COUNT`] consecutive failures; the peerstore
    // already noops for unknown peers.
    peerstore.record_failure(&p);
}

fn record_swarm_failure(state: &mut SwarmState, peer: PeerId) {
    state.failed.retain(|f| f.peer != peer);
    state.failed.push(PeerFailure {
        peer,
        at: Instant::now(),
    });
    const MAX_FAIL: usize = 64;
    if state.failed.len() > MAX_FAIL {
        let drain = state.failed.len() - MAX_FAIL;
        state.failed.drain(0..drain);
    }
}

fn classify_pipeline_state(
    peer: PeerId,
    state: &SwarmState,
    conn: Option<&PeerConnectionInfo>,
) -> PeerConnectionState {
    if state.closing.contains(&peer) {
        return PeerConnectionState::Closing;
    }
    if state.bzz_peers.contains(&peer) {
        return PeerConnectionState::Ready;
    }
    if let Some(phase) = state.pending.get(&peer) {
        return match phase {
            PendingPhase::AwaitingIdentify { .. } => PeerConnectionState::Identifying,
            PendingPhase::Handshaking { .. } => PeerConnectionState::Handshaking,
        };
    }
    if state.dialing.contains(&peer) {
        return PeerConnectionState::Dialing;
    }
    if let Some(c) = conn {
        return if c.bzz_overlay.is_some() {
            PeerConnectionState::Ready
        } else {
            PeerConnectionState::Handshaking
        };
    }
    if state.failed.iter().any(|f| f.peer == peer) {
        return PeerConnectionState::Failed;
    }
    PeerConnectionState::Ready
}

fn ip_for_pipeline_row(
    peer: PeerId,
    state: &SwarmState,
    conn: Option<&PeerConnectionInfo>,
) -> String {
    if let Some(c) = conn {
        if let Ok(ma) = c.address.parse::<Multiaddr>() {
            let h = endpoint_host(&ma);
            if !h.is_empty() {
                return h;
            }
        }
    }
    if let Some(phase) = state.pending.get(&peer) {
        return endpoint_host(&phase.dialed_addr());
    }
    if let Some(ma) = state.dial_hint_addr.get(&peer) {
        return endpoint_host(ma);
    }
    String::new()
}

fn build_peer_pipeline_entries(
    state: &mut SwarmState,
    connected: &[PeerConnectionInfo],
) -> Vec<PeerPipelineEntry> {
    let mut by_id: HashMap<PeerId, &PeerConnectionInfo> = HashMap::new();
    for c in connected {
        if let Ok(p) = c.peer_id.parse::<PeerId>() {
            by_id.insert(p, c);
        }
    }
    let mut all: HashSet<PeerId> = HashSet::new();
    for p in &state.closing {
        all.insert(*p);
    }
    for f in &state.failed {
        all.insert(f.peer);
    }
    for p in &state.dialing {
        all.insert(*p);
    }
    for p in state.pending.keys() {
        all.insert(*p);
    }
    for p in &state.bzz_peers {
        all.insert(*p);
    }
    for p in by_id.keys() {
        all.insert(*p);
    }

    // Drop ordering for peers that have left the pipeline so the map can't
    // grow unbounded over a long-running daemon. Done before assigning new
    // sequence numbers so a peer that disappears and reappears gets sent to
    // the bottom of the list (treated as a new peer).
    state.peer_order.retain(|p, _| all.contains(p));

    let mut rows: Vec<(u64, PeerPipelineEntry)> = Vec::with_capacity(all.len());
    for peer in all {
        let order = *state.peer_order.entry(peer).or_insert_with(|| {
            let n = state.next_peer_order;
            state.next_peer_order = state.next_peer_order.wrapping_add(1);
            n
        });
        let conn = by_id.get(&peer).copied();
        let st = classify_pipeline_state(peer, state, conn);
        let ip = ip_for_pipeline_row(peer, state, conn);
        let ready_in_ms = state.ready_in_ms.get(&peer).copied();
        rows.push((
            order,
            PeerPipelineEntry {
                peer_id: peer.to_string(),
                state: st,
                ip,
                ready_in_ms,
            },
        ));
    }
    rows.sort_by_key(|(order, _)| *order);
    rows.into_iter().map(|(_, e)| e).collect()
}

/// Time between full peer-pipeline rebuilds. Bootstrap fires hundreds of
/// swarm events per second; without a floor here we'd rebuild + serialize a
/// 200+ row pipeline (and grab the watch's write lock) on every event,
/// starving `ant_control::serve` enough that `antop` reads time out.
const PIPELINE_SYNC_INTERVAL: Duration = Duration::from_millis(100);

fn sync_peer_pipeline(status: Option<&watch::Sender<StatusSnapshot>>, state: &mut SwarmState) {
    const FAIL_TTL: Duration = Duration::from_mins(1);
    state.failed.retain(|f| f.at.elapsed() < FAIL_TTL);
    // Forget backoffs that expired long ago so the map stays bounded; a
    // peer failing again after that starts over at `DIAL_BACKOFF_BASE`.
    let now = Instant::now();
    state
        .dial_backoff
        .retain(|_, b| now.saturating_duration_since(b.until) < DIAL_BACKOFF_MAX);
    let Some(tx) = status else { return };
    let routing = routing_snapshot(state, Instant::now());
    let retrieval = build_retrieval_info(state);
    tx.send_modify(|st| {
        st.peers.peer_pipeline = build_peer_pipeline_entries(state, &st.peers.connected_peers);
        st.peers.routing = routing.clone();
        st.retrieval = retrieval.clone();
    });
}

/// Read the live data-plane snapshot for `StatusSnapshot::retrieval`.
/// Cheap: each load is a single relaxed atomic; the gateway-activity
/// snapshot grabs one Mutex per call but the entry count is small
/// (typically ≤ a few dozen) so it never shows up in profiles.
fn build_retrieval_info(state: &SwarmState) -> RetrievalInfo {
    let cache_used = state.chunk_cache.as_ref().map_or(0, |c| c.len() as u32);
    let in_flight = (RETRIEVAL_INFLIGHT_CAP - state.retrieval_inflight.available_permits()) as u32;
    let counters = state.retrieval_counters.snapshot();
    let gateway_requests = state
        .gateway_activity
        .as_ref()
        .map(|a| a.snapshot())
        .unwrap_or_default();
    // Disk cache snapshot. When the daemon was started with
    // `--no-disk-cache` (or no disk cache at all),
    // `state.disk_cache` is `None` and `enabled` stays false so
    // `antop` can render a clean `disabled` label. The byte
    // totals are read directly from the cache's `AtomicU64` mirror,
    // so we never block the status tick on a SQLite query.
    let disk = match state.disk_cache.as_ref() {
        Some(c) => DiskCacheInfo {
            enabled: true,
            used_bytes: c.used_bytes(),
            capacity_bytes: c.capacity_bytes(),
            hits_total: counters.disk_hits,
            chunks: c.used_rows(),
            path: c.path().display().to_string(),
            read_workers: c.read_workers() as u32,
            pinned_bytes: c.pinned_bytes(),
            pinned_chunks: c.pinned_rows(),
            pin_collections: c.pin_collections(),
            pin_member_chunks: c.pin_member_refs(),
        },
        None => DiskCacheInfo::default(),
    };
    RetrievalInfo {
        cache: CacheInfo {
            used: cache_used,
            capacity: DEFAULT_CACHE_CAPACITY as u32,
        },
        in_flight,
        in_flight_capacity: RETRIEVAL_INFLIGHT_CAP as u32,
        chunks_fetched_total: counters.chunks_fetched,
        bytes_fetched_total: counters.bytes_fetched,
        cache_hits_total: counters.cache_hits(),
        mem_hits_total: counters.mem_hits,
        disk,
        gateway_requests,
    }
}

/// Build a `RoutingInfo` that mirrors the live routing table for the
/// control snapshot. Cheap (32 entries plus one pass over the table) so
/// we recompute on every pipeline sync rather than try to track deltas.
fn routing_snapshot(state: &SwarmState, now: Instant) -> RoutingInfo {
    let table = &state.routing;
    let known = &state.known;
    let counts = table.bin_counts();
    let known_counts = known.bin_counts();
    RoutingInfo {
        base_overlay: format!("0x{}", hex::encode(table.base())),
        size: table.len() as u32,
        bins: counts.iter().map(|c| u32::from(*c)).collect(),
        serving: serving_peer_count(state, now),
        known_size: known.len() as u32,
        known_bins: known_counts.to_vec(),
    }
}

/// How long a bootnode must stay in the routing table before it counts as
/// a serving peer (`RoutingInfo::serving`, `/readiness`). Mainnet
/// bootnodes run bee's bootnode mode: they hand out peers and reset the
/// connection 3–600 ms after the handshake (#78), so they never get
/// here. A bootnode that does stay — a private network's only node,
/// which ant does route through — makes the node ready after this.
const BOOTNODE_SERVING_GRACE: Duration = Duration::from_secs(5);

/// Routing-table peers the node can serve retrievals through at `now`:
/// every entry except one whose connections stopped answering pings
/// ([`Liveness::stale_peers`], #83) and a bootnode admitted less than
/// [`BOOTNODE_SERVING_GRACE`] ago. The pipeline sync (every
/// [`PIPELINE_SYNC_INTERVAL`]) republishes it, so a peer going stale, or
/// a bootnode that stays, is reflected within one tick.
fn serving_peer_count(state: &SwarmState, now: Instant) -> u32 {
    let stale = state.liveness.stale_peers(now);
    state
        .routing
        .snapshot()
        .iter()
        .filter(|(peer, _)| !stale.contains(peer))
        .filter(|(peer, _)| {
            !state.bootnode_peers.contains(peer)
                || state
                    .routing_admitted_at
                    .get(peer)
                    .is_some_and(|at| now.saturating_duration_since(*at) >= BOOTNODE_SERVING_GRACE)
        })
        .count() as u32
}

/// Push a routing-only update to the status snapshot. Used right after
/// `routing.admit` and `routing.forget` so `antop` and the gateway's
/// `/readiness` (`PeerInfo::can_retrieve`) reflect the table without
/// waiting for the next pipeline-sync tick.
fn sync_routing_snapshot(status: Option<&watch::Sender<StatusSnapshot>>, state: &SwarmState) {
    let Some(tx) = status else { return };
    let routing = routing_snapshot(state, Instant::now());
    tx.send_modify(|st| st.peers.routing = routing);
}

/// Compute our own Swarm overlay from the BZZ signing secret + nonce. This
/// is the same derivation the BZZ handshake uses, just lifted out so the
/// routing table can pin its base address before the first peer connects.
fn local_overlay_from_secret(
    signing_secret: &[u8; SECP256K1_SECRET_LEN],
    overlay_nonce: &[u8; OVERLAY_NONCE_LEN],
    network_id: u64,
) -> Overlay {
    let sk = SigningKey::from_bytes(signing_secret.into())
        .expect("signing_secret was validated at startup");
    let vk = VerifyingKey::from(&sk);
    let eth = ethereum_address_from_public_key(&vk);
    overlay_from_ethereum_address(&eth, network_id, overlay_nonce)
}

/// Run forever. Keeps a running handshake pipeline (capacity =
/// `target_peers`) fed by two sources: the static bootnode list (bootstrap
/// only) and live `/swarm/hive/1.1.0/peers` gossip from every connected
/// bee. Each successful BZZ handshake usually triggers a hive stream in
/// response, so the peer set fans out geometrically until we hit
/// `target_peers` and the dialer stops pulling from the hint queue.
pub async fn run(mut cfg: RunConfig) -> Result<(), RunError> {
    let local_peer_id = cfg.libp2p_keypair.public().to_peer_id();
    let mut swarm = build_swarm(cfg.libp2p_keypair.clone(), &LivenessConfig::DEFAULT)?;
    let mut commands = cfg.commands.take();
    let listen: Multiaddr = LISTEN.parse().unwrap();
    swarm
        .listen_on(listen)
        .map_err(|e| std::io::Error::other(format!("listen_on: {e}")))?;

    // Deferred operator warning: if neither user-supplied externals, listener
    // auto-promotion, nor UPnP have produced a globally-routable address by
    // this deadline, surface a `warn!` pointing at `--external-address`.
    // We can't run the check eagerly because UPnP's SSDP search takes a few
    // seconds and listener-address auto-promotion happens in the run loop —
    // an eager check would always fire on home routers where UPnP would have
    // succeeded a moment later. The deadline is checked from the main loop
    // after every event so we don't need a separate timer.
    let mut external_address_check_deadline = Some(Instant::now() + EXTERNAL_ADDRESS_CHECK_DELAY);

    let mut control = swarm.behaviour().stream.new_control();
    let mut peer_agents: HashMap<PeerId, String> = HashMap::new();

    // Must register the post-handshake sinks BEFORE the first bootnode
    // handshake completes. bee's `ConnectIn` opens
    // `/swarm/pricing/1.0.0/pricing` and kademlia's `Announce` opens
    // `/swarm/hive/1.1.0/peers` immediately after BZZ handshake; rejecting
    // either triggers an instant `Disconnect`.
    let (hint_tx, mut hint_rx) = mpsc::channel::<sinks::PeerHint>(HINT_CHAN_CAP);
    let registrations = sinks::register(&mut control, hint_tx);
    // Hook the swap listener to a credit ledger if the operator
    // configured both a chequebook beneficiary and a persistence
    // directory; otherwise we register the protocol but throw away
    // every cheque we receive (no on-chain identity to credit
    // against).
    let swap_wiring = build_swap_wiring(&cfg);
    // Keep a handle on the inbound credit ledger for the accounting
    // snapshot (gateway `/settlements` received side) before the
    // wiring moves into the sink task.
    let credit_ledger = swap_wiring.as_ref().map(|w| w.ledger.clone());
    sinks::spawn(registrations, swap_wiring);

    let target_peers = if cfg.target_peers == 0 {
        DEFAULT_TARGET_PEERS
    } else {
        cfg.target_peers
    };
    if let Some(s) = &cfg.status {
        s.send_modify(|st| st.peers.node_limit = target_peers as u32);
    }
    let base_overlay =
        local_overlay_from_secret(&cfg.signing_secret, &cfg.overlay_nonce, cfg.network_id);
    let mut state = SwarmState::new(
        target_peers,
        base_overlay,
        cfg.per_request_chunk_cache,
        cfg.chunk_record_dir.clone(),
        cfg.gateway_activity.clone(),
        cfg.disk_cache.clone(),
        cfg.peer_eth.clone(),
    );
    if state.chunk_cache.is_some() {
        if let Some(shared) = cfg.memory_cache.clone() {
            state.chunk_cache = Some(shared);
        }
    }
    state.credit_ledger = credit_ledger;
    state.allow_private_dials = cfg.allow_private_dials;
    state.swap_enabled = cfg.swap_enabled;
    state.status = cfg.status.clone();
    publish_settlement(&state);

    // Advertise any user-supplied external addresses so bee's peerstore sees
    // a public multiaddr for us. Without this bee's inbound handshake handler
    // waits 10 s in `peerMultiaddrs` because libp2p-go filters out the RFC1918
    // listener addresses we'd otherwise publish via identify. We route this
    // through `record_external_address` (rather than calling
    // `swarm.add_external_address` directly) so the operator-supplied set
    // shows up in `StatusSnapshot::external_addresses` with `source = manual`
    // and an `info!` log on each registration, matching how listener
    // auto-promotion / observed / UPnP sources are surfaced.
    for addr in cfg.external_addrs.clone() {
        record_external_address(
            &mut state,
            &mut swarm,
            cfg.status.as_ref(),
            addr,
            ExternalAddrSource::Manual,
        );
    }

    // Pseudosettle driver: keeps our per-peer debt below bee's
    // light-mode `disconnectLimit` by opening
    // `/swarm/pseudosettle/1.0.0/pseudosettle` and asking bee to clear
    // the time-based allowance worth. Refreshes are scheduled off the
    // accounting mirror below (`Accounting::refresh_due`, bee's settle
    // trigger): a peer is refreshed only once its mirrored debt is due.
    // The fetcher's `payment_notify` (see
    // [`RoutingFetcher::with_payment_notify`]) and the hot hints only
    // register peers with the driver; neither schedules a refresh.
    // The driver also subscribes to `peers_watch` so it skips
    // refreshes for peers we no longer have a direct connection to —
    // critical for gateway loads where the routing set churns through
    // thousands of peers per hour.
    //
    // The shared `Accounting` mirror is the same one we hand to every
    // `RoutingFetcher` we build below; it gives the fetcher's hot path
    // admission control (refuse to dispatch to peers near
    // `lightDisconnectLimit`) and the driver both its refresh trigger
    // and a way to credit peers back as bee accepts our refresh
    // attempts.
    let (payment_notify_for_state, payment_notify_rx) =
        mpsc::channel::<PeerId>(crate::pseudosettle::NOTIFY_CHANNEL_CAP);
    let (hot_hint_tx, hot_hint_rx) = mpsc::channel::<ant_retrieval::accounting::HotHint>(
        crate::pseudosettle::HOT_HINT_CHANNEL_CAP,
    );
    // The accounting mirror feeds the driver's hot hints for retrieval
    // and pushsync debt alike (pushsync debits land in it through
    // `PushPseudosettle`, see `push_settlement`).
    let accounting =
        Arc::new(ant_retrieval::accounting::Accounting::new().with_hot_hint(hot_hint_tx));
    tokio::spawn(crate::pseudosettle::run_driver(
        control.clone(),
        payment_notify_rx,
        hot_hint_rx,
        state.peers_watch.subscribe(),
        Some(accounting.clone()),
    ));
    state.payment_notify = Some(payment_notify_for_state);
    state.accounting = Some(accounting);
    // Phase 7b: outbound SWAP settlement. Built once we have a `Control`
    // for opening swap streams and the shared peer-EOA registry. When
    // `cfg.pushsync_swap` is `None` (operator hasn't configured a
    // chequebook), we leave `state.pushsync_swap` as `None` and the
    // fetcher silently falls back to the legacy "push without
    // settlement" behaviour — fine for ultra-light read-only builds,
    // and in failure-mode for upload-heavy ones (uploads run for ~20K
    // chunks then stall, surfacing the obvious error). The
    // `OutboundLedger` snapshot lives at the configured path so
    // cumulative cheque amounts survive restarts.
    if let Some(swap_cfg) = cfg.pushsync_swap.clone() {
        let svc = Arc::new(crate::PushsyncSwap::new(swap_cfg, control.clone()));
        info!(
            target: "ant_p2p::pushsync_swap",
            chequebook = %hex::encode(svc.chequebook()),
            "outbound SWAP settlement enabled",
        );
        state.pushsync_swap = Some(svc);
        sync_retrieval_payment(&state);
    } else if cfg.late_chain_rx.is_some() {
        // Chain init is still resolving concurrently with bootstrap;
        // the DISABLED/enabled verdict is logged when the
        // `LateChainInit` arrives so operators don't see a scary
        // warning that flips to "enabled" two seconds later.
        info!(
            target: "ant_p2p::pushsync_swap",
            "outbound SWAP settlement pending chain init (resolving concurrently with bootstrap)",
        );
    } else {
        info!(
            target: "ant_p2p::pushsync_swap",
            "outbound SWAP settlement DISABLED — uploads will stall \
             after ~20K chunks across the peer set; configure \
             --chequebook + --swap-key to enable",
        );
    }
    let mut peerstore = match cfg.peerstore_path.clone() {
        Some(p) => PeerStore::load(p),
        None => PeerStore::disabled(),
    };
    // Know the bootnodes before the first warm dial: a stored bootnode is
    // dialed from the hint queue long before `/dnsaddr/` resolution (if
    // it succeeds at all) tags it in `handle_bootnode_dial`.
    seed_bootnode_tags(&mut state, &peerstore, &cfg.bootnodes);
    // Warm the dial pipeline from the on-disk snapshot before the bootnode
    // dial fires. The bootnode dial still runs as a fallback — if every
    // stored peer is dead, the bootnodes carry us back into the network.
    let warm = peerstore.warm_hints();
    if !warm.is_empty() {
        info!(
            target: "ant_p2p",
            "warming pipeline from peerstore ({} entries)",
            warm.len(),
        );
        for hint in warm {
            state.enqueue_hint(hint, local_peer_id);
        }
    }
    let hs_params = HandshakeParams {
        local_peer_id,
        signing_secret: cfg.signing_secret,
        overlay_nonce: cfg.overlay_nonce,
        network_id: cfg.network_id,
    };
    let (result_tx, mut result_rx) = mpsc::channel::<(PeerId, DriveOutcome)>(64);
    // Channel that resolved bootnode multiaddrs flow through. A spawned
    // task does the DNS work and sends each leaf as it's resolved; the
    // main `select!` below dials them from the swarm-event-loop task
    // (which is where `swarm.dial()` must be called from). Sized to
    // comfortably fit one full resolution round (8 regions × ~3 leaves
    // each) without blocking the resolver.
    let (bootnode_dial_tx, mut bootnode_dial_rx) = mpsc::channel::<Multiaddr>(64);

    // On-demand neighbourhood dialing: upload-side fetchers send chunk
    // addresses here when they lack a connected peer close to the chunk;
    // the loop dials known peers toward that address. Bounded + best-effort
    // (the fetcher drops on a full channel) so a large upload can't flood
    // the dial pipeline.
    let (neighborhood_dial_tx, mut neighborhood_dial_rx) = mpsc::channel::<[u8; 32]>(256);
    state.neighborhood_dial_tx = Some(neighborhood_dial_tx);
    let (stamp_tx, stamp_rx) = mpsc::unbounded_channel::<StampJob>();
    let (stamped_tx, mut stamped_rx) = mpsc::unbounded_channel::<StampedPush>();
    state.stamp_tx = Some(stamp_tx);
    tokio::spawn(run_stamper(stamp_rx, stamped_tx));

    let mut backoff = MIN_BACKOFF;
    let mut last_bootstrap_at = Instant::now();
    // Last time the partial-drain top-up fired. Initialised so the very first
    // loop iteration is allowed to top up — useful when the daemon resumes
    // with a peerstore but no connected BZZ peers yet.
    let mut last_top_up_at = Instant::now()
        .checked_sub(PEER_TOP_UP_INTERVAL)
        .unwrap_or_else(Instant::now);
    // First bin-balance pass only after a full interval: at startup the
    // bootstrap wave is still handshaking, so the bins are legitimately
    // empty and an immediate pass would burn dial slots on noise.
    let mut last_bin_balance_at = Instant::now();
    spawn_bootstrap_dial(&cfg.bootnodes, bootnode_dial_tx.clone());

    let mut flush_timer = tokio::time::interval(PEERSTORE_FLUSH_INTERVAL);
    flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick — we have nothing to flush at startup.
    flush_timer.tick().await;
    // Floor on how often the status snapshot is republished even when
    // the swarm is fully idle. `sync_peer_pipeline` already runs from
    // the loop top on every wakeup, gated by `PIPELINE_SYNC_INTERVAL`;
    // this timer just guarantees `antop` keeps seeing a live
    // `RetrievalInfo` (cache fill, in-flight count, gateway-request
    // list) even when no swarm events fire. Cadence chosen to match
    // `antop --interval`'s 1 s default while still letting
    // operators run with sub-second polling without seeing stale data.
    let mut status_pulse = tokio::time::interval(Duration::from_millis(250));
    status_pulse.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    status_pulse.tick().await;
    // Self-probe scan for peer-rejected batches (issue #52): a cheap
    // no-op while nothing is rejected.
    let mut batch_probe_pulse = tokio::time::interval(BATCH_PROBE_TICK);
    batch_probe_pulse.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    batch_probe_pulse.tick().await;
    // Upload runtime slot: starts as the constructor-provided value and
    // may be filled once by a `LateChainInit` (see the select arm
    // below). Loop-local rather than read from `cfg` so the late init
    // can replace it without `cfg` being mutable everywhere.
    let mut upload_rt = cfg.upload.clone();
    // Taken out of `cfg` so the select arm below can hold it `&mut`;
    // dropped to `None` after the single delivery (or on a closed
    // sender) so the arm goes inert instead of busy-polling.
    let mut late_chain_rx = cfg.late_chain_rx.take();
    // Publish chain-init readiness: constructor-provided inputs mean
    // the embedder resolved chain state before starting the loop (or
    // has none to resolve); a pending late channel means `antctl`
    // clients should treat upload-affecting answers as transient
    // until this flips (see `StatusSnapshot::chain_ready`).
    if let Some(s) = cfg.status.as_ref() {
        let ready = late_chain_rx.is_none();
        s.send_modify(|st| st.chain_ready = ready);
    }
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut last_pipeline_sync = Instant::now()
        .checked_sub(PIPELINE_SYNC_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut last_liveness_pass = Instant::now();

    loop {
        fill_pipeline_from_hints(&mut swarm, &mut state);
        maybe_top_up_peers(
            &cfg.bootnodes,
            &mut state,
            &peerstore,
            &mut last_top_up_at,
            local_peer_id,
            &bootnode_dial_tx,
        );
        maybe_rebootstrap(
            &cfg.bootnodes,
            &state,
            &mut backoff,
            &mut last_bootstrap_at,
            &bootnode_dial_tx,
        );
        maybe_balance_bins(&mut swarm, &mut state, &mut last_bin_balance_at);
        if last_liveness_pass.elapsed() >= LIVENESS_PASS_INTERVAL {
            maintain_liveness(
                &mut swarm,
                &mut state,
                cfg.status.as_ref(),
                &cfg.bootnodes,
                &peerstore,
                &mut backoff,
                &mut last_bootstrap_at,
                &mut last_top_up_at,
                local_peer_id,
                &bootnode_dial_tx,
            );
            last_liveness_pass = Instant::now();
        }
        if last_pipeline_sync.elapsed() >= PIPELINE_SYNC_INTERVAL {
            sync_peer_pipeline(cfg.status.as_ref(), &mut state);
            last_pipeline_sync = Instant::now();
        }
        if let Some(deadline) = external_address_check_deadline {
            if Instant::now() >= deadline {
                maybe_warn_no_external_address(&swarm, &cfg.external_addrs);
                external_address_check_deadline = None;
            }
        }

        tokio::select! {
            ev = swarm.select_next_some() => {
                observe_event(cfg.status.as_ref(), &mut peer_agents, &ev);
                handle_swarm_event(
                    &mut swarm,
                    &mut state,
                    cfg.status.as_ref(),
                    &mut control,
                    &hs_params,
                    &result_tx,
                    &mut peerstore,
                    ev,
                );
            }
            Some(hint) = hint_rx.recv() => {
                state.enqueue_hint(hint, local_peer_id);
            }
            Some(addr) = bootnode_dial_rx.recv() => {
                if let Some(peer) = crate::dial::extract_peer_id(&addr) {
                    // Already handshaked from a warm hint: flag the stored
                    // entry now, the handshake that would flag it is past.
                    peerstore.mark_bootnode(&peer);
                }
                handle_bootnode_dial(&mut swarm, &mut state, addr);
            }
            Some(target) = neighborhood_dial_rx.recv() => {
                dial_toward_target(&mut swarm, &mut state, target);
            }
            Some((peer, outcome)) = result_rx.recv() => {
                handle_drive_outcome(
                    &cfg,
                    &mut swarm,
                    &mut state,
                    &peer_agents,
                    &mut backoff,
                    &mut peerstore,
                    peer,
                    outcome,
                );
            }
            _ = flush_timer.tick() => {
                peerstore.flush();
                // Age out known-but-unconnected peers so a peer that
                // left the network eventually stops counting toward
                // "visible peers". Cheap (one retain over a bounded
                // book); 30 s cadence is well below the 45 min TTL.
                state.known.prune(Instant::now());
            }
            _ = status_pulse.tick() => {
                // The loop-top `sync_peer_pipeline` call does most of
                // the work: this arm wakes the select up regularly so
                // the snapshot stays live during gateway-only /
                // fully-idle periods. Cheques are issued off this loop,
                // so the settlement figures are refreshed here.
                publish_settlement(&state);
            }
            _ = batch_probe_pulse.tick() => {
                spawn_due_batch_probes(&state, &control, upload_rt.as_ref(), cfg.network_id);
            }
            Some(p) = stamped_rx.recv() => {
                push_with_stamp(&state, &control, cfg.network_id, p.addr, p.wire, p.stamp, p.require_deep, p.ack_when_stored, p.ack);
            }
            Some(cmd) = recv_command(commands.as_mut()) => {
                match cmd {
                    // Recovery after an OS suspension needs the loop-local
                    // dial machinery (bootnodes + the bootstrap dial channel
                    // + the backoff/interval clocks), none of which
                    // `handle_control_command` has, so it's handled inline
                    // here rather than threaded through that signature.
                    ControlCommand::Resume { ack } => {
                        let warmed = force_resume(
                            &cfg.bootnodes,
                            &mut state,
                            &peerstore,
                            &mut backoff,
                            &mut last_bootstrap_at,
                            &mut last_top_up_at,
                            local_peer_id,
                            &bootnode_dial_tx,
                        );
                        let _ = ack.send(ControlAck::Ok {
                            message: format!(
                                "resume: re-warmed {warmed} peer hints; bootstrap re-dial fired",
                            ),
                        });
                    }
                    other => handle_control_command(&mut state, &mut peerstore, &control, upload_rt.clone(), cfg.network_id, other),
                }
            }
            init = recv_late_chain(late_chain_rx.as_mut()), if late_chain_rx.is_some() => {
                // Single-shot: drop the receiver whether we got a value
                // or the sender went away, so this arm never fires again.
                late_chain_rx = None;
                if let Some(init) = init {
                    apply_late_chain_init(&mut state, &mut upload_rt, &control, init);
                    // A dropped sender (init = None) means chain init
                    // failed and the daemon is exiting — leave
                    // `chain_ready` false rather than lie on the way down.
                    if let Some(s) = cfg.status.as_ref() {
                        s.send_modify(|st| st.chain_ready = true);
                    }
                }
            }
            _ = &mut shutdown => {
                info!(target: "ant_p2p", "shutdown signal; flushing peerstore");
                peerstore.flush();
                return Ok(());
            }
        }
    }
}

/// `tokio::select!` wrapper that makes the command channel inert when the
/// daemon was launched without one (`cfg.commands = None`). Returning a
/// `Future<Output = Option<_>>` that never yields in the `None` case lets the
/// select arm compile under the same shape as the other arms.
async fn recv_command(
    commands: Option<&mut mpsc::Receiver<ControlCommand>>,
) -> Option<ControlCommand> {
    match commands {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// [`recv_command`]'s twin for the late chain-init channel; the select
/// arm additionally guards on `late_chain_rx.is_some()` and drops the
/// receiver after the first resolution, so the `None` branch here only
/// covers the same-poll race.
async fn recv_late_chain(rx: Option<&mut mpsc::Receiver<LateChainInit>>) -> Option<LateChainInit> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Bring SWAP payments (issues #121, #127) in line with the node's state:
/// the outbound SWAP service gets the payment policy for its chequebook
/// (the latest `SetRetrievalFunds` for it, unless the switch is off), and
/// the accounting mirror — retrieval and pushsync debt alike — pays
/// through that service only while it has funds under that policy.
/// Otherwise accounting has no payer and debt is settled by the
/// pseudosettle refresh alone, exactly as without a chequebook. Called
/// after every change to any of those inputs; also publishes the result
/// ([`publish_settlement`]).
fn sync_retrieval_payment(state: &SwarmState) {
    sync_payer(state);
    publish_settlement(state);
}

/// [`sync_retrieval_payment`]'s payer half.
fn sync_payer(state: &SwarmState) {
    let Some(accounting) = state.accounting.as_ref() else {
        return;
    };
    let payer = state.pushsync_swap.as_ref().and_then(|svc| {
        let policy = state
            .retrieval_funds
            .filter(|(chequebook, _)| state.swap_enabled && *chequebook == svc.chequebook())
            .map(|(_, policy)| policy);
        svc.set_retrieval_policy(policy);
        svc.pays_retrieval()
            .then(|| svc.clone() as Arc<dyn ant_retrieval::accounting::RetrievalPayment>)
    });
    let paying = payer.is_some();
    if paying != accounting.pays_with_swap() {
        info!(
            target: "ant_p2p::pushsync_swap",
            paying,
            "SWAP settlement: {}",
            if paying {
                "downloads and uploads pay peers with SWAP cheques past the early-payment threshold"
            } else {
                "downloads and uploads use the free pseudosettle tier"
            },
        );
        if !paying {
            if let Some(why) = state
                .pushsync_swap
                .as_ref()
                .and_then(|svc| svc.outbound_ledger().lost_figures())
            {
                warn!(target: "ant_p2p::pushsync_swap", "{why}");
            }
        }
    }
    accounting.set_payment(payer);
}

/// Publish the node's settlement state (the `swap-enable` switch, the
/// chequebook, whether cheques are paid now, its funds and what cheques
/// have taken from them) into `StatusSnapshot::settlement`, for `GET
/// /node`, `GET /v0/settlement/swap` and `ant_swap_status`. Only sends
/// on a change; the status pulse calls it so the figures follow each
/// cheque.
fn publish_settlement(state: &SwarmState) {
    let Some(status) = state.status.as_ref() else {
        return;
    };
    let svc = state.pushsync_swap.as_ref();
    let issued = svc.map(|svc| svc.outbound_ledger().total_issued());
    let deposited = svc.and_then(|svc| {
        state
            .retrieval_funds
            .filter(|(chequebook, _)| *chequebook == svc.chequebook())
            .map(|(_, policy)| policy.deposited_plur)
    });
    let info = ant_control::SettlementInfo {
        swap_enabled: state.swap_enabled,
        chequebook: svc.map(|svc| format!("0x{}", hex::encode(svc.chequebook()))),
        paying: state
            .accounting
            .as_ref()
            .is_some_and(|a| a.pays_with_swap()),
        deposited_plur: deposited.map(|d| d.to_string()),
        issued_plur: issued.map(|i| i.to_string()),
        available_plur: deposited
            .zip(issued)
            .map(|(d, i)| d.saturating_sub(i).to_string()),
    };
    status.send_if_modified(|snap| {
        if snap.settlement == info {
            false
        } else {
            snap.settlement = info;
            true
        }
    });
}

/// Install the chain-derived inputs once `antd`'s startup Gnosis reads
/// complete: fill the upload-runtime slot consulted by
/// `handle_control_command` (`PushChunk`, postage commands) and build
/// the outbound SWAP service. Mirrors the startup path at the top of
/// [`run`] and the runtime [`ControlCommand::EnablePushsyncSwap`]
/// handler — and defers to either if they got there first: the FFI
/// first-buy flow can legitimately race this delivery.
fn apply_late_chain_init(
    state: &mut SwarmState,
    upload_rt: &mut Option<Arc<UploadRuntime>>,
    control: &Control,
    init: LateChainInit,
) {
    if upload_rt.is_none() {
        *upload_rt = init.upload;
    }
    if state.pushsync_swap.is_some() {
        // A runtime `EnablePushsyncSwap` (FFI first-buy) raced this
        // delivery and won; its service — and its ledger state — stay.
        return;
    }
    match init.pushsync_swap {
        Some(mut swap_cfg) => {
            // The daemon-side config was built before the loop existed;
            // patch in the live handshake-EOA registry the same way
            // `run_node` does for the startup path.
            swap_cfg.peer_eth = state.peer_eth.clone();
            let svc = crate::PushsyncSwap::new(swap_cfg, control.clone());
            info!(
                target: "ant_p2p::pushsync_swap",
                chequebook = %hex::encode(svc.chequebook()),
                "outbound SWAP settlement enabled",
            );
            state.pushsync_swap = Some(Arc::new(svc));
            sync_retrieval_payment(state);
        }
        None => {
            info!(
                target: "ant_p2p::pushsync_swap",
                "outbound SWAP settlement DISABLED — uploads will stall \
                 after ~20K chunks across the peer set; configure \
                 --chequebook + --swap-key to enable",
            );
        }
    }
}

/// Apply a control-socket command against the node loop's single-writer
/// state. Keep the match exhaustive so a newly-added variant on the wire is
/// noisily rejected instead of silently dropped.
fn handle_control_command(
    state: &mut SwarmState,
    peerstore: &mut PeerStore,
    control: &Control,
    upload: Option<Arc<UploadRuntime>>,
    network_id: u64,
    cmd: ControlCommand,
) {
    match cmd {
        ControlCommand::ResetPeerstore { ack } => {
            let evicted = peerstore.clear();
            // Also drop the dedup set so any peer we previously discarded as
            // "already seen" can re-enter the hint queue next time a bee
            // gossips us its table.
            state.seen_hints.clear();
            state.hint_queue.clear();
            let msg = format!(
                "peerstore reset: dropped {evicted} on-disk entries; current connections unchanged",
            );
            info!(target: "ant_p2p", "{msg}");
            let _ = ack.send(ControlAck::Ok { message: msg });
        }
        ControlCommand::GetChunk { reference, ack } => {
            // Serve from the node's local caches first, then fall back to a
            // hedged network retrieve. The upload path stashes every
            // chunk/SOC into the mem + disk cache *before* pushsync (see the
            // `PushChunk`/`PushSoc` handlers) precisely so the node can read
            // back its own writes without waiting for network propagation —
            // but only if the read path consults those caches. Routing the
            // fetch through a cache-aware `RoutingFetcher` makes a local hit
            // short-circuit before any peer round-trip, so we deliberately
            // do *not* early-return on an empty peer set: a cached copy must
            // still be returned. The fetcher subscribes to the live peer
            // snapshot so network fallback tracks the current BZZ set.
            let peers_rx = state.peers_watch.subscribe();
            let retry_peers = state.peers_watch.subscribe();
            let cache = state.cache_for_request(false);
            let disk_cache = state.disk_cache_for_request(false);
            let neighborhood_dial = state.neighborhood_dial_tx.clone();
            let control = control.clone();
            tokio::spawn(async move {
                let mut builder =
                    ant_retrieval::RoutingFetcher::new(control, peers_rx).with_cache(cache);
                if let Some(disk) = disk_cache {
                    builder = builder.with_disk_cache(disk);
                }
                if let Some(tx) = neighborhood_dial {
                    builder = builder.with_neighborhood_dialer(tx);
                }
                let fetcher = builder;
                let reply = match fetch_with_retry(&fetcher, retry_peers, reference).await {
                    Ok(wire) if wire.len() >= ant_crypto::SPAN_SIZE => {
                        // `fetch` returns the chunk's wire bytes
                        // (`span || payload`); `GetChunk` acks the payload.
                        let payload = wire[ant_crypto::SPAN_SIZE..].to_vec();
                        debug!(
                            target: "ant_p2p",
                            payload_bytes = payload.len(),
                            "retrieval ok",
                        );
                        ControlAck::Bytes { data: payload }
                    }
                    Ok(wire) => ControlAck::Error {
                        message: format!("retrieval: short chunk ({} bytes)", wire.len()),
                    },
                    Err(e) => {
                        debug!(target: "ant_p2p", "retrieval failed: {e}");
                        ControlAck::Error {
                            message: format!("retrieval: {e}"),
                        }
                    }
                };
                let _ = ack.send(reply);
            });
        }
        ControlCommand::VerifyPropagation {
            reference,
            samples,
            probes,
            progress,
            cancel,
            ack,
        } => {
            // Deep read-back propagation check. Resolve the manifest,
            // enumerate the file's chunk tree, and check the *actual data
            // leaves* across distinct closest peers — all network-only so a
            // store-then-push local copy can't mask a failed push. The heavy
            // lifting runs in a spawned task (`verify_propagation_deep`); here
            // we only snapshot the peer pool synchronously so we don't borrow
            // `state` into the task.
            //
            // `samples == 0` is the thorough default: every data leaf,
            // uncapped, however large the file. A non-zero value probes only
            // that many evenly-spread leaves — a weaker, faster signal we keep
            // for callers that explicitly want a quick spot-check.
            let samples = samples as usize;
            let probes = if probes == 0 { 2 } else { probes.min(8) } as usize;
            let peers: Vec<(PeerId, Overlay)> = state.peers_watch.subscribe().borrow().clone();
            if peers.is_empty() {
                let _ = ack.send(ControlAck::NotReady {
                    message: "no peers available; wait for handshakes to complete".into(),
                });
                return;
            }
            let peers_rx = state.peers_watch.subscribe();
            let control = control.clone();
            let net = VerifyNet::from_state(state);
            tokio::spawn(async move {
                let body = verify_propagation_deep(
                    control, peers_rx, peers, reference, samples, probes, net, progress, cancel,
                )
                .await;
                let _ = ack.send(ControlAck::Ok {
                    message: body.to_string(),
                });
            });
        }
        ControlCommand::VerifyChunksPresent {
            addresses,
            probes,
            include_shallow,
            ack,
        } => {
            // Read-back presence check for a specific address set (upload
            // self-heal). `probes == 0` is the any-route fetch (cache-free
            // `RoutingFetcher`, the real download path); `probes > 0` is the
            // deep neighbourhood check that flags shallow placements. Either
            // way we report which addresses didn't come back so the caller
            // can re-push exactly those.
            let peers: Vec<(PeerId, Overlay)> = state.peers_watch.subscribe().borrow().clone();
            if peers.is_empty() {
                let _ = ack.send(ControlAck::NotReady {
                    message: "no peers available; wait for handshakes to complete".into(),
                });
                return;
            }
            let peers_rx = state.peers_watch.subscribe();
            let control = control.clone();
            let net = VerifyNet::from_state(state);
            tokio::spawn(async move {
                // Serialise with any other in-flight verification (see
                // `SwarmState::verify_gate`).
                let _gate = net
                    .verify_gate
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("verify gate semaphore closed");
                let fetcher = net.fetcher(control.clone(), peers_rx);
                let missing = if probes == 0 {
                    verify_chunks_present(&fetcher, &addresses).await
                } else {
                    // Heal path: no UI to drive, so no progress sink and no
                    // cancellation. The automatic heals (`include_shallow ==
                    // false`) re-push only what no route can serve
                    // (`confirmed_missing`); the explicit "Push again"
                    // (`include_shallow == true`) also re-pushes
                    // merely-shallow chunks so it actually repairs a file
                    // that loads but isn't durably placed (see
                    // [`DeepPresence`]).
                    let presence = verify_chunks_present_deep(
                        &control, &peers, &fetcher, &addresses, probes, &net, None, 0, None,
                    )
                    .await;
                    if include_shallow {
                        presence.probe_missing
                    } else {
                        presence.confirmed_missing
                    }
                };
                let body = serde_json::json!({
                    "checked": addresses.len(),
                    "missing": missing
                        .iter()
                        .map(|a| format!("0x{}", hex::encode(a)))
                        .collect::<Vec<_>>(),
                });
                let _ = ack.send(ControlAck::Ok {
                    message: body.to_string(),
                });
            });
        }
        ControlCommand::PushChunk {
            wire,
            batch_id,
            stamp,
            require_deep,
            ack_when_stored,
            ack,
        } => {
            // Validate wire bytes locally before paying for a stamp,
            // so a malformed `POST /chunks` body is rejected up-front
            // instead of burning a postage slot and then being told to
            // retry by every neighbourhood peer.
            if wire.len() < 8 || wire.len() > 8 + 4096 {
                let _ = ack.send(ControlAck::Error {
                    message: format!("chunk wire size out of range: {} bytes", wire.len()),
                });
                return;
            }
            let mut span = [0u8; 8];
            span.copy_from_slice(&wire[..8]);
            let payload = wire[8..].to_vec();
            let Some(addr) = ant_crypto::bmt::bmt_hash_with_span(&span, &payload) else {
                let _ = ack.send(ControlAck::Error {
                    message: "failed to BMT-hash chunk".into(),
                });
                return;
            };
            // A duplicate of a push in flight, or of a chunk stored a
            // moment ago, needs no stamp and no push of its own (see
            // `push_dedup`). Strict pushes (repairs) and caller-stamped
            // ones always go out.
            let ack = if stamp.is_none() && !require_deep {
                match state.push_dedup.begin(
                    crate::push_dedup::push_key(&addr, &batch_id, &wire),
                    addr,
                    ack,
                ) {
                    crate::push_dedup::Begin::Push(ack) => ack,
                    crate::push_dedup::Begin::Handled => return,
                }
            } else {
                ack
            };

            // Pre-signed stamp (bee's `swarm-postage-stamp` header):
            // push with the caller's stamp instead of issuing one. No
            // upload runtime is needed — the stamp's own signature is
            // the postage proof, mirroring bee's presigned-stamper path
            // where any node can forward a foreign-batch chunk.
            if let Some(pre) = stamp {
                let stamp = match validate_presigned_stamp(&pre, &addr) {
                    Ok(s) => s,
                    Err(message) => {
                        let _ = ack.send(ControlAck::Error { message });
                        return;
                    }
                };
                push_with_stamp(
                    state,
                    control,
                    network_id,
                    addr,
                    wire,
                    stamp,
                    require_deep,
                    ack_when_stored,
                    ack,
                );
                return;
            }

            let Some(upload) = upload.clone() else {
                let _ = ack.send(ControlAck::Error {
                    message: "uploads not configured: node cannot stamp (set a blockchain-rpc-endpoint or pass --postage-batch at startup)".into(),
                });
                return;
            };

            // Stamp under the issuer-registry mutex so concurrent pushes
            // can't collide on the same bucket index — bee's `stampissuer`
            // does exactly this. The batch must be registered (bought or
            // pre-configured); an unknown id is rejected up-front so we
            // don't pushsync an unstamped chunk.
            let stamp = {
                let mut issuers = match upload.issuers.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let Some(issuer) = issuers.get_mut(&batch_id) else {
                    let _ = ack.send(ControlAck::Error {
                        message: format!("batch 0x{} not usable", hex::encode(batch_id)),
                    });
                    return;
                };
                // Headroom guard for a *full* collision bucket. Behaviour
                // depends on the batch's mutability:
                //
                // * **Immutable** batch ⇒ hard-refuse. The issuer can't
                //   evict, so a full bucket is a genuine dead end; failing
                //   loudly surfaces an under-sized batch instead of a
                //   phantom "uploaded" file.
                // * **Mutable** batch ⇒ proceed and let `increment` wrap
                //   the bucket, which is exactly bee's documented mutable
                //   semantics (evict the oldest stamp in that one bucket).
                //   Hard-refusing here would brick an otherwise-roomy
                //   mutable batch over a single hot bucket — the very
                //   failure that left 98%-empty batches unable to upload.
                //   The real cause of premature bucket fill (re-stamping
                //   the same chunk on every re-push) is fixed by the
                //   per-chunk stamp cache, so a mutable wrap now only
                //   happens when one bucket genuinely sees >capacity
                //   *distinct* chunks — vanishingly rare on a sane depth,
                //   and the pre-upload capacity check warns before then.
                //
                // A chunk we've *already* stamped is exempt either way: a
                // re-push (heal / retry / resume) reuses its original
                // stamp and consumes no new slot.
                if !issuer.has_stamp(&addr) && issuer.bucket_is_full(&addr) {
                    if issuer.immutable() {
                        warn!(
                            target: "ant_p2p",
                            batch = %hex::encode(batch_id),
                            depth = issuer.batch_depth(),
                            addr = %hex::encode(addr),
                            "refusing to stamp: collision bucket full on immutable batch — stamping would evict an existing chunk (buy/dilute a larger batch)",
                        );
                        let _ = ack.send(ControlAck::Error {
                            message: format!(
                                "batch 0x{} saturated: collision bucket full at depth {} on an immutable batch — stamping would evict an existing chunk; buy or dilute to a larger batch",
                                hex::encode(batch_id),
                                issuer.batch_depth(),
                            ),
                        });
                        return;
                    }
                    warn!(
                        target: "ant_p2p",
                        batch = %hex::encode(batch_id),
                        depth = issuer.batch_depth(),
                        addr = %hex::encode(addr),
                        "collision bucket full on mutable batch — wrapping (evicting the oldest stamp in this bucket); consider diluting to a larger batch",
                    );
                }
                match ant_postage::sign_stamp_bytes(&upload.stamp_key, issuer, &addr) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ack.send(ControlAck::Error {
                            message: format!("stamp issue failed: {e}"),
                        });
                        return;
                    }
                }
            };

            push_with_stamp(
                state,
                control,
                network_id,
                addr,
                wire,
                stamp,
                require_deep,
                ack_when_stored,
                ack,
            );
        }
        ControlCommand::PushSoc {
            address,
            wire,
            batch_id,
            stamp,
            ack_when_stored,
            ack,
        } => {
            // Re-check the wire layout locally even though the gateway
            // has already validated `soc_valid(&address, &wire)`: a
            // misbehaving gateway must not be able to coerce us into
            // stamping a malformed chunk. SOC wire layout: id(32) +
            // sig(65) + span(8) + payload(≤4096).
            const SOC_HEADER: usize = 32 + 65;
            if wire.len() < SOC_HEADER + 8 || wire.len() > SOC_HEADER + 8 + 4096 {
                let _ = ack.send(ControlAck::Error {
                    message: format!("soc wire size out of range: {} bytes", wire.len()),
                });
                return;
            }
            // Same SOC (address, bytes *and* batch) in flight or just stored:
            // reuse that push (see `push_dedup`). Redundancy replicas of
            // an unchanged manifest node repeat with every upload.
            let ack = if stamp.is_none() {
                match state.push_dedup.begin(
                    crate::push_dedup::push_key(&address, &batch_id, &wire),
                    address,
                    ack,
                ) {
                    crate::push_dedup::Begin::Push(ack) => ack,
                    crate::push_dedup::Begin::Handled => return,
                }
            } else {
                ack
            };

            // Pre-signed stamp: push with the caller's stamp — no local
            // issuer needed. See the matching branch in `PushChunk`.
            if let Some(pre) = stamp {
                let stamp = match validate_presigned_stamp(&pre, &address) {
                    Ok(s) => s,
                    Err(message) => {
                        let _ = ack.send(ControlAck::Error { message });
                        return;
                    }
                };
                push_soc_with_stamp(
                    state,
                    control,
                    network_id,
                    address,
                    wire,
                    stamp,
                    ack_when_stored,
                    ack,
                );
                return;
            }

            let Some(upload) = upload.clone() else {
                let _ = ack.send(ControlAck::NotReady {
                    message: "uploads not configured: node cannot stamp (set a blockchain-rpc-endpoint or pass --postage-batch at startup)".into(),
                });
                return;
            };

            // Stamp under the issuer mutex so concurrent pushes can't
            // collide on the same bucket index, matching the PushChunk
            // path. The address is owner-bound (`keccak256(id || owner)`),
            // so the stamp signs the SOC's content address rather than
            // a BMT hash. Bee stamps SOCs the same way: see
            // `bee/pkg/api/soc.go` (the `chunk.NewChunk(addr, ...)` is
            // handed to the postage stamper as-is) and
            // `bee/pkg/postage/stampissuer.go::Issue` which signs over
            // the chunk's address bytes regardless of CAC vs SOC.
            let stamp = {
                let mut issuers = match upload.issuers.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let Some(issuer) = issuers.get_mut(&batch_id) else {
                    let _ = ack.send(ControlAck::Error {
                        message: format!("batch 0x{} not usable", hex::encode(batch_id)),
                    });
                    return;
                };
                // Same collision-bucket guard `PushChunk` applies, and
                // for the same reason. SOCs are not a rare write: every
                // redundant upload mints dispersed replicas as SOCs, and
                // a live feed writes one per playlist update (#67
                // stage 2), so a long broadcast walks a batch's buckets
                // exactly like a bulk file upload does. Without this the
                // immutable case surfaced as a bare `stamp issue failed:
                // bucket full` and the mutable case wrapped a bucket —
                // evicting somebody's chunk — with no log at all.
                if !issuer.has_stamp(&address) && issuer.bucket_is_full(&address) {
                    if issuer.immutable() {
                        warn!(
                            target: "ant_p2p",
                            batch = %hex::encode(batch_id),
                            depth = issuer.batch_depth(),
                            addr = %hex::encode(address),
                            "refusing to stamp soc: collision bucket full on immutable batch — stamping would evict an existing chunk (buy/dilute a larger batch)",
                        );
                        let _ = ack.send(ControlAck::Error {
                            message: format!(
                                "batch 0x{} saturated: collision bucket full at depth {} on an immutable batch — stamping would evict an existing chunk; buy or dilute to a larger batch",
                                hex::encode(batch_id),
                                issuer.batch_depth(),
                            ),
                        });
                        return;
                    }
                    warn!(
                        target: "ant_p2p",
                        batch = %hex::encode(batch_id),
                        depth = issuer.batch_depth(),
                        addr = %hex::encode(address),
                        "collision bucket full on mutable batch — wrapping (evicting the oldest stamp in this bucket); consider diluting to a larger batch",
                    );
                }
                match ant_postage::sign_stamp_bytes(&upload.stamp_key, issuer, &address) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ack.send(ControlAck::Error {
                            message: format!("stamp issue failed: {e}"),
                        });
                        return;
                    }
                }
            };

            push_soc_with_stamp(
                state,
                control,
                network_id,
                address,
                wire,
                stamp,
                ack_when_stored,
                ack,
            );
        }
        ControlCommand::Envelope {
            address,
            batch_id,
            ack,
        } => {
            // Bee's `envelopePostHandler`: issue (and persist) a stamp
            // for a chunk address the caller will upload later, via
            // `stamper.Stamp(address, address)`. Consumes a bucket slot
            // exactly like stamping an upload; re-requesting the same
            // address reuses the cached stamp (issuer idempotence).
            let Some(upload) = upload.clone() else {
                let _ = ack.send(ControlAck::Error {
                    message: "uploads not configured: node cannot stamp (set a blockchain-rpc-endpoint or pass --postage-batch at startup)".into(),
                });
                return;
            };
            let reply = {
                let mut issuers = match upload.issuers.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                match issuers.get_mut(&batch_id) {
                    None => ControlAck::Error {
                        message: format!("batch 0x{} not usable", hex::encode(batch_id)),
                    },
                    Some(issuer) => {
                        match ant_postage::sign_stamp_bytes(&upload.stamp_key, issuer, &address) {
                            Ok(stamp) => ControlAck::Envelope {
                                issuer: upload.batch_owner,
                                stamp,
                            },
                            Err(ant_postage::PostageError::BucketFull) => ControlAck::Error {
                                // Keyword the gateway maps to bee's
                                // `402 "batch is overissued"`.
                                message: "batch is overissued".into(),
                            },
                            Err(e) => ControlAck::Error {
                                message: format!("stamp issue failed: {e}"),
                            },
                        }
                    }
                }
            };
            let _ = ack.send(reply);
        }
        ControlCommand::StewardshipGet { reference, ack } => {
            // Bee's `steward.IsRetrievable`: traverse the whole content
            // tree (span trees + mantaray manifests) and probe every
            // chunk. Any failure — missing root, unreachable interior
            // node, unreachable leaf — reports `retrievable: false`
            // rather than an error, matching bee's not-found mapping.
            // The fetcher is the normal cache-aware one: a light node's
            // own uploads are held locally, and a cached copy is by
            // definition retrievable through this node's gateway.
            let peers_rx = state.peers_watch.subscribe();
            let cache = state.cache_for_request(false);
            let disk_cache = state.disk_cache_for_request(false);
            let control = control.clone();
            tokio::spawn(async move {
                let mut fetcher =
                    ant_retrieval::RoutingFetcher::new(control, peers_rx).with_cache(cache);
                if let Some(disk) = disk_cache {
                    fetcher = fetcher.with_disk_cache(disk);
                }
                let retrievable = stewardship_is_retrievable(&fetcher, reference).await;
                let _ = ack.send(ControlAck::Retrievable { retrievable });
            });
        }
        ControlCommand::StampedChunk {
            batch_id,
            address,
            ack,
        } => {
            // ethersphere/bee#5682 (1): one lookup in the batch issuer's
            // per-chunk stamp records. No network, no slot consumed.
            let reply = match upload {
                // No upload runtime yet (antd before late chain init):
                // not "this batch didn't stamp it" — the gateway maps
                // the `uploads not configured` prefix to 503.
                None => ControlAck::Error {
                    message: "uploads not configured: node has no stamp issuers (set a blockchain-rpc-endpoint or pass --postage-batch at startup)".into(),
                },
                Some(ref upload) => {
                    let issuers = match upload.issuers.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    stamped_chunk_reply(&issuers, batch_id, &address)
                }
            };
            let _ = ack.send(reply);
        }
        ControlCommand::StewardshipStamps { reference, ack } => {
            // ethersphere/bee#5682 (2): walk the tree like
            // `StewardshipGet`, then count each batch's records. Without
            // an upload runtime there are no issuers to ask yet (antd
            // before late chain init); say so instead of reporting every
            // chunk as unstamped.
            let Some(upload) = upload.clone() else {
                let _ = ack.send(ControlAck::Error {
                    message: "uploads not configured: node has no stamp issuers (set a blockchain-rpc-endpoint or pass --postage-batch at startup)".into(),
                });
                return;
            };
            let peers_rx = state.peers_watch.subscribe();
            let cache = state.cache_for_request(false);
            let disk_cache = state.disk_cache_for_request(false);
            let control = control.clone();
            tokio::spawn(async move {
                let mut fetcher =
                    ant_retrieval::RoutingFetcher::new(control, peers_rx).with_cache(cache);
                if let Some(disk) = disk_cache {
                    fetcher = fetcher.with_disk_cache(disk);
                }
                // Only interior and manifest nodes are fetched; data
                // leaves are listed from their parents, so the counts
                // don't prove the leaves retrievable (that is
                // `GET /stewardship/{reference}`'s job).
                let reply = match ant_retrieval::traverse_chunk_addresses(
                    &fetcher,
                    reference,
                    STEWARDSHIP_MAX_FILE_BYTES,
                )
                .await
                {
                    Ok(addrs) => {
                        match count_tree_stamps_sliced(&upload.issuers, &addrs, STAMP_COUNT_SLICE)
                            .await
                        {
                            Ok(view) => ControlAck::StewardshipStamps(view),
                            Err(message) => ControlAck::Error { message },
                        }
                    }
                    Err(e) => ControlAck::Error {
                        message: format!("stamps check traversal failed: {e}"),
                    },
                };
                let _ = ack.send(reply);
            });
        }
        ControlCommand::StewardshipPut {
            reference,
            batch_id,
            ack,
        } => {
            // Bee's `steward.Reupload`: traverse the tree, fetch every
            // chunk (cache-first — a light node holds its own uploads
            // locally), stamp each against `batch_id`, pushsync all.
            let Some(upload) = upload.clone() else {
                let _ = ack.send(ControlAck::Error {
                    message: "uploads not configured: node cannot stamp (set a blockchain-rpc-endpoint or pass --postage-batch at startup)".into(),
                });
                return;
            };
            {
                // Cheap up-front registry check so an unknown batch is
                // rejected before any traversal work, mirroring bee's
                // `getStamper` failing before `Reupload` starts.
                let issuers = match upload.issuers.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if !issuers.contains_key(&batch_id) {
                    let _ = ack.send(ControlAck::Error {
                        message: format!("batch 0x{} not usable", hex::encode(batch_id)),
                    });
                    return;
                }
            }
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                let _ = ack.send(ControlAck::Error {
                    message: "no peers available; wait for handshakes to complete".into(),
                });
                return;
            }
            let cache = state.cache_for_request(false);
            let disk_cache = state.disk_cache_for_request(false);
            let control = control.clone();
            let push_settlement = push_settlement(
                state.accounting.clone(),
                state.pushsync_swap.is_some(),
                crate::push_pseudosettle::PushPseudosettle::enabled_by_env(),
            );
            let push_skip = state.push_skip.clone();
            let neighborhood_dial = state.neighborhood_dial_tx.clone();
            tokio::spawn(async move {
                let mut read_fetcher =
                    ant_retrieval::RoutingFetcher::new(control.clone(), peers_rx.clone())
                        .with_cache(cache);
                if let Some(disk) = disk_cache {
                    read_fetcher = read_fetcher.with_disk_cache(disk);
                }
                let mut push_fetcher = ant_retrieval::RoutingFetcher::new(control, peers_rx)
                    .with_push_skip(push_skip)
                    .with_network_id(network_id);
                if let Some(tx) = neighborhood_dial {
                    push_fetcher = push_fetcher.with_neighborhood_dialer(tx);
                }
                if let Some(s) = push_settlement {
                    push_fetcher = push_fetcher.with_pushsync_settlement(s);
                }
                let reply = stewardship_reupload(
                    &read_fetcher,
                    &push_fetcher,
                    &upload,
                    batch_id,
                    reference,
                )
                .await;
                let _ = ack.send(reply);
            });
        }
        ControlCommand::GetChunkRaw {
            reference,
            fast_miss,
            bypass_cache,
            ack,
        } => {
            // Same cache-then-network fetch path as `GetChunk`, but the ack
            // carries the full wire bytes (`span || payload` for a CAC, or
            // `id || sig || span || payload` for a SOC) so `ant-gateway` can
            // serve `/chunks/{addr}` byte-for-byte the way bee does. This is
            // the read path behind SOC-read-by-address and exact-index feed
            // reads, so it must consult the local upload cache to satisfy
            // read-after-own-write; a cached hit short-circuits before any
            // peer round-trip, hence no early-return on an empty peer set.
            //
            // For `/chunks` and `/soc` a miss is an answer, not a failure:
            // a live-stream player polls the next feed slot through it
            // until the slot is written, so those callers set `fast_miss`
            // and the lookup ends once enough peers said "not found"
            // (issue #146). Either way a confirmed miss is typed as
            // `ControlAck::NotFound` so the gateway answers 404 whichever
            // tail (`storage: not found` or `no peer found`) the last
            // answer had.
            //
            // `bypass_cache` (`/chunks` with `swarm-cache: false`, issue
            // #80) gives up that read-after-own-write: the lookup neither
            // reads nor writes the shared caches and always asks peers.
            let peers_rx = state.peers_watch.subscribe();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let control = control.clone();
            tokio::spawn(async move {
                let mut builder = ant_retrieval::RoutingFetcher::new(control, peers_rx)
                    .with_cache(cache)
                    .with_fast_miss(fast_miss);
                if let Some(disk) = disk_cache {
                    builder = builder.with_disk_cache(disk);
                }
                let fetcher = builder;
                let reply = match fetcher.fetch(reference).await {
                    Ok(wire) => {
                        debug!(
                            target: "ant_p2p",
                            wire_bytes = wire.len(),
                            "retrieval ok (raw)",
                        );
                        ControlAck::Bytes { data: wire }
                    }
                    Err(e) => {
                        debug!(target: "ant_p2p", "retrieval failed: {e}");
                        pre_stream_failure_ack(format!("retrieval: {e}"), e.as_ref())
                    }
                };
                let _ = ack.send(reply);
            });
        }
        ControlCommand::PullsyncProbe {
            target,
            bin,
            start,
            max_deliver,
            ack,
        } => {
            use crate::pullsync;
            use std::sync::atomic::{AtomicUsize, Ordering};

            // Pick the connected peer closest to the target overlay — the
            // one whose reserve most likely holds the neighborhood's
            // chunks. Fall back to any peer if routing is empty but the
            // peer snapshot isn't.
            let peer = state
                .routing
                .closest_peer(&target, &[])
                .or_else(|| state.peers_watch.subscribe().borrow().first().copied());
            let Some((peer_id, peer_overlay)) = peer else {
                let _ = ack.send(ControlAck::PullsyncProbe(ant_control::PullsyncProbeView {
                    error: "no connected peer to probe (wait for handshakes)".into(),
                    ..Default::default()
                }));
                return;
            };
            // The chunks near `target` sit in the server's proximity-order
            // bin to that address, unless the caller pinned a bin.
            let probe_bin =
                bin.unwrap_or_else(|| crate::routing::proximity(&peer_overlay, &target));
            let control = control.clone();
            tokio::spawn(async move {
                let mut view = ant_control::PullsyncProbeView {
                    peer_overlay: hex::encode(peer_overlay),
                    peer_id: peer_id.to_string(),
                    bin: probe_bin,
                    ..Default::default()
                };

                let t0 = std::time::Instant::now();
                let cursors = pullsync::get_cursors(&mut control.clone(), peer_id).await;
                view.cursors_ms = t0.elapsed().as_millis() as u64;
                let cursor_for_bin = match cursors {
                    Ok(c) => {
                        view.cursors_ok = true;
                        view.epoch = c.epoch;
                        let cur = c.cursors.get(probe_bin as usize).copied().unwrap_or(0);
                        view.bin_cursor = cur;
                        cur
                    }
                    Err(e) => {
                        view.error = format!("cursors: {e}");
                        let _ = ack.send(ControlAck::PullsyncProbe(view));
                        return;
                    }
                };

                // Default to a *historical* page (start ≤ cursor): the
                // server answers immediately with what it has. The old
                // default (cursor+1) opened a live request that blocks
                // until the next chunk arrives — on a quiet bin that
                // meant every probe "timed out" and orphaned its task,
                // making the probe useless as a diagnostic. Callers who
                // really want the live-block behavior pass `start`.
                let sync_start =
                    start.unwrap_or_else(|| cursor_for_bin.saturating_sub(PROBE_BACKLOG));
                view.start = sync_start;
                let wanted = AtomicUsize::new(0);
                let t1 = std::time::Instant::now();
                // Self-bound below the control server's 20 s dispatch
                // timeout so the probe always acks a view (with an error
                // string if need be) instead of orphaning the task after
                // the server has already given up on it.
                let page = match tokio::time::timeout(
                    PROBE_SYNC_TIMEOUT,
                    pullsync::sync_once(
                        &mut control.clone(),
                        peer_id,
                        probe_bin,
                        sync_start,
                        |_offered| wanted.fetch_add(1, Ordering::Relaxed) < max_deliver,
                        || {}, // probe is one-shot; no readiness signal needed
                    ),
                )
                .await
                {
                    Ok(page) => page,
                    Err(_) => Err(crate::pullsync::PullsyncError::Protocol(format!(
                        "probe sync timed out after {}s (live bin? pass an explicit start)",
                        PROBE_SYNC_TIMEOUT.as_secs()
                    ))),
                };
                view.sync_ms = t1.elapsed().as_millis() as u64;
                match page {
                    Ok(p) => {
                        view.sync_ok = true;
                        view.topmost = p.topmost;
                        view.offered = wanted.load(Ordering::Relaxed);
                        view.delivered = p.chunks.len();
                    }
                    Err(e) => {
                        view.error = format!("sync: {e}");
                    }
                }
                let _ = ack.send(ControlAck::PullsyncProbe(view));
            });
        }
        ControlCommand::LurkerSubscribe {
            target,
            gsoc_addresses,
            pss_topics,
            history,
            ack,
        } => {
            use crate::lurker::{self, LurkerConfig};
            use crate::messaging::WatchState;

            let watch = WatchState {
                gsoc_addresses: gsoc_addresses.into_iter().collect(),
                pss_topics,
                // No persisted node PSS key yet: topic-broadcast reception
                // only (the topic-derived key handles it). Directed PSS to
                // the node's key lands when a pss.key is persisted.
                pss_secret: None,
                history,
                // Mailbox ticket: stamped by the registry on subscribe.
                history_seq: 0,
                history_held: std::collections::BTreeSet::new(),
            };
            if watch.is_empty() {
                // Nothing to watch — tell the subscriber why before the
                // stream closes (a bare drop looks like a node failure
                // and invites a blind retry loop).
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: "lurker subscription rejected: nothing to watch".to_string(),
                    },
                );
                return;
            }
            // All-zeros target → the node's own neighborhood (where PSS
            // messages addressed to us land).
            let target = if target == [0u8; 32] {
                *state.routing.base()
            } else {
                target
            };

            // One lurker per neighborhood, shared: the registry attaches
            // this subscriber to an existing pull pipeline for `target`
            // (union watch, per-subscriber fan-out) or spawns one, and
            // refuses when the distinct-neighborhood cap is reached —
            // dropping `ack` then closes the subscriber's stream right
            // away instead of silently queueing unbounded lurkers.
            let control = control.clone();
            let peers = state.peers_watch.subscribe();
            let neighborhood_dial = state.neighborhood_dial_tx.clone();
            let subscribed = state
                .lurkers
                .subscribe(target, watch, |shared_watch, out_tx| {
                    tokio::spawn(lurker::run(
                        control,
                        peers,
                        neighborhood_dial,
                        LurkerConfig {
                            target,
                            watch: shared_watch,
                        },
                        out_tx,
                    ))
                });
            let Some(out_rx) = subscribed else {
                tracing::warn!(
                    target: "ant_p2p::lurker",
                    limit = crate::lurker_registry::MAX_LURKER_NEIGHBORHOODS,
                    "lurker subscription rejected: neighborhood limit reached",
                );
                // Surface the rejection so the gateway can close the
                // WebSocket with a reason instead of a bare drop.
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: format!(
                            "lurker subscription rejected: neighborhood limit reached ({})",
                            crate::lurker_registry::MAX_LURKER_NEIGHBORHOODS
                        ),
                    },
                );
                return;
            };

            // Forward decoded messages to the caller's ack stream; when
            // the subscriber goes away — even silently, with no message
            // ever arriving — the forwarder returns and drops `out_rx`,
            // and the registry prunes the subscriber (tearing down the
            // shared lurker once the last one leaves).
            tokio::spawn(forward_lurker_messages(out_rx, ack));
        }
        ControlCommand::GetBytes {
            reference,
            bypass_cache,
            progress,
            max_bytes,
            ack,
        } => {
            // Multi-chunk raw bytes: subscribe to the live peer-snapshot
            // watch, build a routing-aware fetcher per attempt against
            // the *current* set of BZZ peers, and drive the joiner
            // inside a spawned task. The joiner does its own per-chunk
            // fetch + CAC verify; we only need to feed it the root
            // chunk. Subscribing (rather than snapshotting at command
            // time) is what keeps the retry loop honest across long
            // multi-MiB fetches: by attempt N our original peer list
            // would be 30+ seconds stale and full of disconnected
            // peers.
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: "no peers available; wait for handshakes to complete".to_string(),
                    },
                );
                return;
            }
            let control = control.clone();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let record_dir = state.chunk_record_dir.clone();
            let inflight_limit = state.retrieval_inflight.clone();
            let payment_notify = state.payment_notify.clone();
            let accounting = state.accounting.clone();
            let counters = state.retrieval_counters.clone();
            let tracker = Arc::new(ProgressTracker::new(bypass_cache));
            let started = Instant::now();
            let emitter = if progress {
                Some(spawn_progress_emitter(
                    tracker.clone(),
                    ack.clone(),
                    started,
                ))
            } else {
                None
            };
            let tracker_for_run = tracker;
            tokio::spawn(async move {
                let reply = unless_client_gone(
                    &ack,
                    run_get_bytes(
                        control,
                        peers_rx,
                        cache,
                        disk_cache,
                        record_dir,
                        inflight_limit,
                        payment_notify,
                        accounting,
                        counters,
                        tracker_for_run,
                        reference,
                        max_bytes,
                    ),
                )
                .await;
                if let Some(handle) = emitter {
                    handle.abort();
                }
                if let Some(reply) = reply {
                    let _ = ack.send(reply).await;
                }
            });
        }
        ControlCommand::GetBytesEncrypted {
            reference,
            key,
            bypass_cache,
            max_bytes,
            ack,
        } => {
            // Encrypted content (feed v1 80-byte payload): same routing /
            // retry machinery as `GetBytes`, but the joiner decrypts each
            // chunk with the per-chunk keys carried in the 64-byte
            // references. Buffered, no progress stream — the volume is a
            // feed payload, and the gateway slices the result for Range.
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: "no peers available; wait for handshakes to complete".to_string(),
                    },
                );
                return;
            }
            let control = control.clone();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let record_dir = state.chunk_record_dir.clone();
            let inflight_limit = state.retrieval_inflight.clone();
            let payment_notify = state.payment_notify.clone();
            let accounting = state.accounting.clone();
            let counters = state.retrieval_counters.clone();
            let tracker = Arc::new(ProgressTracker::new(bypass_cache));
            tokio::spawn(async move {
                let reply = unless_client_gone(
                    &ack,
                    run_get_bytes_encrypted(
                        control,
                        peers_rx,
                        cache,
                        disk_cache,
                        record_dir,
                        inflight_limit,
                        payment_notify,
                        accounting,
                        counters,
                        tracker,
                        reference,
                        key,
                        max_bytes,
                    ),
                )
                .await;
                if let Some(reply) = reply {
                    let _ = ack.send(reply).await;
                }
            });
        }
        ControlCommand::StreamBytes {
            reference,
            bypass_cache,
            max_bytes,
            range,
            head_only,
            ack,
        } => {
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: "no peers available; wait for handshakes to complete".to_string(),
                    },
                );
                return;
            }
            let control = control.clone();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let record_dir = state.chunk_record_dir.clone();
            let inflight_limit = state.retrieval_inflight.clone();
            let payment_notify = state.payment_notify.clone();
            let accounting = state.accounting.clone();
            let counters = state.retrieval_counters.clone();
            let tracker = Arc::new(ProgressTracker::new(bypass_cache));
            // Always spawn the progress emitter for streaming requests:
            // the gateway uses the periodic `Progress` acks to update
            // its `GatewayActivity` entry so `antop`'s Retrieval
            // tab reflects live per-request chunks/bytes/in-flight
            // counts. Unlike `GetBytes` (where the client opts in via
            // the `progress` flag), streaming has no "consumer doesn't
            // care" mode — the gateway always wants the updates and a
            // 150 ms tick is well below the rate at which `BytesChunk`
            // acks already flow.
            let started = Instant::now();
            let emitter = spawn_progress_emitter(tracker.clone(), ack.clone(), started);
            let tracker_for_run = tracker;
            let client = ack.clone();
            tokio::spawn(async move {
                unless_client_gone(
                    &client,
                    run_stream_bytes(
                        control,
                        peers_rx,
                        cache,
                        disk_cache,
                        record_dir,
                        inflight_limit,
                        payment_notify,
                        accounting,
                        counters,
                        tracker_for_run,
                        reference,
                        max_bytes,
                        range,
                        head_only,
                        ack,
                    ),
                )
                .await;
                emitter.abort();
            });
        }
        ControlCommand::StreamBzz {
            reference,
            path,
            allow_degraded_redundancy,
            bypass_cache,
            max_bytes,
            range,
            head_only,
            ack,
        } => {
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: "no peers available; wait for handshakes to complete".to_string(),
                    },
                );
                return;
            }
            let control = control.clone();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let record_dir = state.chunk_record_dir.clone();
            let inflight_limit = state.retrieval_inflight.clone();
            let payment_notify = state.payment_notify.clone();
            let accounting = state.accounting.clone();
            let counters = state.retrieval_counters.clone();
            let feed_hints = state.feed_hints.clone();
            let tracker = Arc::new(ProgressTracker::new(bypass_cache));
            // Same rationale as the StreamBytes arm above: gateway-side
            // activity rendering depends on the periodic `Progress`
            // acks, so the streaming path always runs the emitter.
            let started = Instant::now();
            let emitter = spawn_progress_emitter(tracker.clone(), ack.clone(), started);
            let tracker_for_run = tracker;
            let client = ack.clone();
            tokio::spawn(async move {
                unless_client_gone(
                    &client,
                    run_stream_bzz(
                        control,
                        peers_rx,
                        cache,
                        disk_cache,
                        record_dir,
                        inflight_limit,
                        payment_notify,
                        accounting,
                        counters,
                        feed_hints,
                        tracker_for_run,
                        reference,
                        path,
                        allow_degraded_redundancy,
                        max_bytes,
                        range,
                        head_only,
                        ack,
                    ),
                )
                .await;
                emitter.abort();
            });
        }
        ControlCommand::GetBzz {
            reference,
            path,
            allow_degraded_redundancy,
            bypass_cache,
            progress,
            max_bytes,
            ack,
        } => {
            // Same live-snapshot reasoning as `GetBytes` above.
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                send_terminal_ack(
                    &ack,
                    ControlAck::Error {
                        message: "no peers available; wait for handshakes to complete".to_string(),
                    },
                );
                return;
            }
            let control = control.clone();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let record_dir = state.chunk_record_dir.clone();
            let inflight_limit = state.retrieval_inflight.clone();
            let payment_notify = state.payment_notify.clone();
            let accounting = state.accounting.clone();
            let counters = state.retrieval_counters.clone();
            let tracker = Arc::new(ProgressTracker::new(bypass_cache));
            let started = Instant::now();
            let emitter = if progress {
                Some(spawn_progress_emitter(
                    tracker.clone(),
                    ack.clone(),
                    started,
                ))
            } else {
                None
            };
            let tracker_for_run = tracker;
            let feed_hints = state.feed_hints.clone();
            tokio::spawn(async move {
                let reply = unless_client_gone(
                    &ack,
                    run_get_bzz(
                        control,
                        peers_rx,
                        cache,
                        disk_cache,
                        record_dir,
                        inflight_limit,
                        payment_notify,
                        accounting,
                        counters,
                        feed_hints,
                        tracker_for_run,
                        reference,
                        path,
                        allow_degraded_redundancy,
                        max_bytes,
                    ),
                )
                .await;
                if let Some(handle) = emitter {
                    handle.abort();
                }
                if let Some(reply) = reply {
                    let _ = ack.send(reply).await;
                }
            });
        }
        ControlCommand::ListBzz {
            reference,
            bypass_cache,
            page,
            ack,
        } => {
            let peers_rx = state.peers_watch.subscribe();
            if peers_rx.borrow().is_empty() {
                let message = "no peers available; wait for handshakes to complete".to_string();
                // The paged listing types this as a 503; the legacy one
                // keeps the `Error` whose text `ant_list_bzz` retries on.
                send_terminal_ack(
                    &ack,
                    if page.is_some() {
                        ControlAck::NotReady { message }
                    } else {
                        ControlAck::Error { message }
                    },
                );
                return;
            }
            let control = control.clone();
            let cache = state.cache_for_request(bypass_cache);
            let disk_cache = state.disk_cache_for_request(bypass_cache);
            let record_dir = state.chunk_record_dir.clone();
            let inflight_limit = state.retrieval_inflight.clone();
            let payment_notify = state.payment_notify.clone();
            let accounting = state.accounting.clone();
            let counters = state.retrieval_counters.clone();
            tokio::spawn(async move {
                let reply = run_list_bzz(
                    control,
                    peers_rx,
                    cache,
                    disk_cache,
                    record_dir,
                    inflight_limit,
                    payment_notify,
                    accounting,
                    counters,
                    reference,
                    page,
                )
                .await;
                let _ = ack.send(reply).await;
            });
        }
        // Upload* commands are handled by `ant_node::run_node`'s
        // command interceptor before they ever reach this loop, so
        // these arms exist for defense in depth: they keep the match
        // exhaustive (so adding a new ControlCommand variant fails
        // the build until we wire it) and they error loudly if a
        // future caller ever bypasses the interceptor. Not reached
        // in production daemons; not exercised by tests beyond a
        // build check.
        ControlCommand::UploadStart { ack, .. }
        | ControlCommand::UploadList { ack }
        | ControlCommand::UploadStatus { ack, .. }
        | ControlCommand::UploadPause { ack, .. }
        | ControlCommand::UploadResume { ack, .. }
        | ControlCommand::UploadRepush { ack, .. }
        | ControlCommand::UploadCancel { ack, .. }
        | ControlCommand::UploadSuspendAll { ack }
        | ControlCommand::UploadWakeAll { ack } => {
            let _ = ack.send(ControlAck::Error {
                message: "upload manager not wired into the swarm loop".into(),
            });
        }
        ControlCommand::UploadFollow { ack, .. } => {
            // `ack` is an mpsc sender — drop after one error frame.
            let _ = ack.try_send(ControlAck::Error {
                message: "upload manager not wired into the swarm loop".into(),
            });
        }
        // Intercepted by the run loop's command arm (it owns the bootnode
        // dial channel + backoff clocks `force_resume` needs). This arm is
        // defense in depth: it keeps the match exhaustive and errors loudly
        // if a future caller ever bypasses the loop. Not reached in practice.
        ControlCommand::Resume { ack } => {
            let _ = ack.send(ControlAck::Error {
                message: "resume must be handled by the swarm loop".into(),
            });
        }
        ControlCommand::PostageStatus { ack } => {
            // The stamp issuer's stats are pure local state — no
            // network, no chain. Synchronous read under the same
            // mutex `PushChunk` uses, so a status request can't
            // race a stamp increment to a half-updated bucket
            // count. `2^bucket_depth` is 65 536 entries at the bee
            // default, so the walk completes in microseconds. With
            // multiple batches we report the first registered one for
            // back-compat with `antctl postage status`.
            let view = match upload {
                Some(rt) => {
                    let issuers = match rt.issuers.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    issuers
                        .values()
                        .next()
                        .map_or_else(postage_status_disabled, |iss| batch_view(state, iss))
                }
                None => postage_status_disabled(),
            };
            let _ = ack.send(ControlAck::PostageStatus(view));
        }
        ControlCommand::PostageList { ack } => {
            // Every registered batch, one view each — backs the
            // gateway's `GET /stamps`.
            let views = match upload {
                Some(rt) => {
                    let issuers = match rt.issuers.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    issuers.values().map(|iss| batch_view(state, iss)).collect()
                }
                None => Vec::new(),
            };
            let _ = ack.send(ControlAck::PostageList(views));
        }
        ControlCommand::RegisterBatch {
            batch_id,
            depth,
            bucket_depth,
            immutable,
            bought_at_block,
            ack,
        } => {
            let Some(rt) = upload.as_ref() else {
                let _ = ack.send(ControlAck::Error {
                    message: "cannot register batch: node has no upload runtime (configure a blockchain-rpc-endpoint)".into(),
                });
                return;
            };
            let mut issuers = match rt.issuers.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            // Idempotent: if the batch is already live, a dilute may have
            // raised its depth — bump it in place. Otherwise open (or
            // create) its persistent counter file and insert it.
            if let Some(existing) = issuers.get_mut(&batch_id) {
                if depth > existing.batch_depth() {
                    if let Err(e) = existing.set_batch_depth(depth) {
                        let _ = ack.send(ControlAck::Error {
                            message: format!("update batch depth: {e}"),
                        });
                        return;
                    }
                }
                if let Some(block) = bought_at_block {
                    note_bought_batch(state, batch_id, block);
                }
                let _ = ack.send(ControlAck::Ok {
                    message: format!("batch 0x{} refreshed", hex::encode(batch_id)),
                });
                return;
            }
            let path = rt
                .postage_dir
                .join(format!("{}.bin", hex::encode(batch_id)));
            match ant_postage::StampIssuer::open_or_new(
                path,
                batch_id,
                depth,
                bucket_depth,
                immutable,
            ) {
                Ok(issuer) => {
                    issuers.insert(batch_id, issuer);
                    state.runtime_registered.insert(batch_id, Instant::now());
                    if let Some(block) = bought_at_block {
                        note_bought_batch(state, batch_id, block);
                    }
                    info!(
                        target: "ant_p2p",
                        batch = %format!("0x{}", hex::encode(batch_id)),
                        depth,
                        bucket_depth,
                        immutable,
                        "registered postage batch for runtime stamping",
                    );
                    let _ = ack.send(ControlAck::Ok {
                        message: format!("batch 0x{} registered", hex::encode(batch_id)),
                    });
                }
                Err(e) => {
                    let _ = ack.send(ControlAck::Error {
                        message: format!("register batch: {e}"),
                    });
                }
            }
        }
        ControlCommand::EnablePushsyncSwap {
            chequebook,
            swap_secret,
            chain_id,
            outbound_ledger_path,
            ack,
        } => {
            // Idempotent: a chequebook is deployed once and reused
            // forever, so a repeat install (e.g. a second storage buy
            // in the same session) must not rebuild the ledger / lose
            // the in-flight per-peer debt counters.
            if let Some(existing) = state.pushsync_swap.as_ref() {
                if existing.chequebook() == chequebook {
                    let _ = ack.send(ControlAck::Ok {
                        message: format!(
                            "outbound SWAP settlement already enabled (chequebook 0x{})",
                            hex::encode(chequebook),
                        ),
                    });
                    return;
                }
            }
            let cfg = crate::PushsyncSwapConfig::new(
                chequebook,
                swap_secret,
                chain_id,
                PathBuf::from(outbound_ledger_path),
                state.peer_eth.clone(),
            );
            let svc = crate::PushsyncSwap::new(cfg, control.clone());
            state.pushsync_swap = Some(Arc::new(svc));
            sync_retrieval_payment(state);
            info!(
                target: "ant_p2p::pushsync_swap",
                chequebook = %hex::encode(chequebook),
                "outbound SWAP settlement enabled at runtime",
            );
            let _ = ack.send(ControlAck::Ok {
                message: format!(
                    "outbound SWAP settlement enabled (chequebook 0x{})",
                    hex::encode(chequebook),
                ),
            });
        }
        ControlCommand::SetRetrievalFunds {
            chequebook,
            deposited_plur,
            exchange_rate_plur,
            deduction_plur,
            ack,
        } => {
            state.retrieval_funds = Some((
                chequebook,
                crate::RetrievalSwapPolicy {
                    deposited_plur: deposited_plur.into(),
                    max_exchange_rate: exchange_rate_plur.into(),
                    max_deduction: deduction_plur.into(),
                },
            ));
            sync_retrieval_payment(state);
            let _ = ack.send(ControlAck::Ok {
                message: format!(
                    "retrieval funds for chequebook 0x{}: {deposited_plur} PLUR deposited",
                    hex::encode(chequebook),
                ),
            });
        }
        ControlCommand::SetSwapEnabled { enabled, ack } => {
            state.swap_enabled = enabled;
            sync_retrieval_payment(state);
            let _ = ack.send(ControlAck::Ok {
                message: format!(
                    "swap settlement {} (downloads and uploads)",
                    if enabled { "on" } else { "off" }
                ),
            });
        }
        ControlCommand::DisablePushsyncSwap { chequebook, ack } => {
            let running = state
                .pushsync_swap
                .as_ref()
                .is_some_and(|s| s.chequebook() == chequebook);
            let message = if running {
                state.retired_outbound = state
                    .pushsync_swap
                    .take()
                    .map(|s| s.outbound_ledger().clone());
                sync_retrieval_payment(state);
                warn!(
                    target: "ant_p2p::pushsync_swap",
                    chequebook = %hex::encode(chequebook),
                    "outbound SWAP settlement disabled at runtime — chequebook failed its chain checks",
                );
                format!(
                    "outbound SWAP settlement disabled (chequebook 0x{})",
                    hex::encode(chequebook),
                )
            } else {
                format!(
                    "outbound SWAP settlement was not running on chequebook 0x{}",
                    hex::encode(chequebook),
                )
            };
            let _ = ack.send(ControlAck::Ok { message });
        }
        ControlCommand::PutChunkLocal { wire, ack } => {
            handle_put_chunk_local(state, wire, ack);
        }
        ControlCommand::GetFeed {
            owner,
            topic,
            after,
            exact,
            ack,
        } => {
            // Feed reads share their fetch path with `GetBytes`: spin up a
            // routing-aware fetcher backed by the live peer-snapshot
            // watch and let `resolve_sequence_feed_after` walk the
            // sequence indices. Wire in the node's mem + disk caches so a
            // just-signed update we stashed before pushsync (see `PushSoc`)
            // is visible to "latest" resolution immediately — without the
            // cache, read-after-own-write on a feed returns `feed_empty`
            // until pushsync propagates. A local hit on index 0 also lets
            // the latest resolve with an empty peer set, so we no longer
            // early-return on no peers.
            let peers_rx = state.peers_watch.subscribe();
            let cache = state.cache_for_request(false);
            let disk_cache = state.disk_cache_for_request(false);
            let control = control.clone();
            let hints = state.feed_hints.clone();
            tokio::spawn(async move {
                // An exact read ends on a miss it needs corroborated
                // (the slot after the head), so it stops at a handful
                // of peers' "not found" like `/soc` does rather than
                // walking the whole error budget (issue #146).
                let mut builder = ant_retrieval::RoutingFetcher::new(control, peers_rx)
                    .with_cache(cache)
                    .with_fast_miss(exact);
                if let Some(disk) = disk_cache {
                    builder = builder.with_disk_cache(disk);
                }
                let fetcher = builder;
                let feed = ant_retrieval::Feed {
                    owner,
                    topic,
                    kind: ant_retrieval::FeedType::Sequence,
                };
                // Experiment 6b: anchor at the best of the caller's
                // `after` and the daemon's last-resolved index for this
                // feed. Append-only sequence feeds can't regress, so a
                // previously-resolved index is always present; if the
                // hinted walk still errors the helper retries once
                // without it rather than surfacing a hint-induced
                // failure for a feed that plain resolution could read.
                // Only an anchor miss more than a couple of peers agree
                // on (a reset feed) drops the hint; a transient failure
                // or one cold peer's "not found" keeps it, as before.
                // The `/bzz` feed-manifest dereference shares the same
                // map and helper (issue #159).
                // `exact` (a writer's head read) also confirms the slot
                // after the head is empty, rather than trusting the
                // look-ahead's bounded probes (issue #173).
                let result = if exact {
                    ant_retrieval::resolve_sequence_feed_exact(&fetcher, &feed, after, Some(&hints))
                        .await
                } else {
                    ant_retrieval::resolve_sequence_feed_hinted(
                        &fetcher,
                        &feed,
                        after,
                        Some(&hints),
                    )
                    .await
                };
                let _ = ack.send(feed_lookup_ack(result));
            });
        }
        ControlCommand::AccountingSnapshot { ack } => {
            let _ = ack.send(ControlAck::Accounting(build_accounting_snapshot(state)));
        }
        // Bee `/pins` parity ("pin-light"): the pin store rides on the
        // persistent disk chunk cache, so every pin command requires it.
        ControlCommand::PinAdd { reference, ack } => {
            let Some(disk_cache) = state.disk_cache.clone() else {
                let _ = ack.send(pin_cache_disabled());
                return;
            };
            // Fetch-then-pin through the normal cache-first /
            // network-fallback fetcher: pinning cold content pulls it
            // in, exactly like bee's pin handler traversing via
            // `storer.Download(true)`.
            let peers_rx = state.peers_watch.subscribe();
            let cache = state.cache_for_request(false);
            let control = control.clone();
            tokio::spawn(async move {
                let fetcher = ant_retrieval::RoutingFetcher::new(control, peers_rx)
                    .with_cache(cache)
                    .with_disk_cache(disk_cache.clone());
                let reply = pin_add(&fetcher, &disk_cache, &reference).await;
                let _ = ack.send(reply);
            });
        }
        ControlCommand::PinRemove { reference, ack } => {
            let Some(disk_cache) = state.disk_cache.clone() else {
                let _ = ack.send(pin_cache_disabled());
                return;
            };
            tokio::spawn(async move {
                let reply = match disk_cache.unpin(reference).await {
                    Ok(was_pinned) => ControlAck::PinRemoved { was_pinned },
                    Err(e) => ControlAck::Error {
                        message: format!("unpin failed: {e}"),
                    },
                };
                let _ = ack.send(reply);
            });
        }
        ControlCommand::PinHas { reference, ack } => {
            let Some(disk_cache) = state.disk_cache.clone() else {
                let _ = ack.send(pin_cache_disabled());
                return;
            };
            tokio::spawn(async move {
                let reply = match disk_cache.has_pin(reference).await {
                    Ok(pinned) => ControlAck::PinPresent { pinned },
                    Err(e) => ControlAck::Error {
                        message: format!("pin lookup failed: {e}"),
                    },
                };
                let _ = ack.send(reply);
            });
        }
        ControlCommand::PinList { ack } => {
            let Some(disk_cache) = state.disk_cache.clone() else {
                let _ = ack.send(pin_cache_disabled());
                return;
            };
            tokio::spawn(async move {
                let reply = match disk_cache.list_pins().await {
                    Ok(references) => ControlAck::PinList { references },
                    Err(e) => ControlAck::Error {
                        message: format!("pin listing failed: {e}"),
                    },
                };
                let _ = ack.send(reply);
            });
        }
        ControlCommand::PinCheck { reference, ack } => {
            let Some(disk_cache) = state.disk_cache.clone() else {
                let _ = ack.send(pin_cache_disabled());
                return;
            };
            tokio::spawn(async move {
                let reply = pin_check(&disk_cache, reference).await;
                let _ = ack.send(reply);
            });
        }
        ControlCommand::PostageBuckets { batch_id, ack } => {
            // Bee `postageGetStampBucketsHandler`: per-bucket collision
            // counters of a *registered* issuer. An unknown batch (or a
            // node without an upload runtime) is bee's 404 "issuer does
            // not exist"; the gateway substring-matches the message.
            let Some(upload) = upload else {
                let _ = ack.send(ControlAck::Error {
                    message: "issuer does not exist (uploads not configured)".into(),
                });
                return;
            };
            let issuers = match upload.issuers.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let reply = match issuers.get(&batch_id) {
                Some(issuer) => ControlAck::PostageBuckets(ant_control::PostageBucketsView {
                    depth: issuer.batch_depth(),
                    bucket_depth: issuer.bucket_depth(),
                    bucket_upper_bound: issuer.bucket_upper_bound(),
                    collisions: issuer.bucket_counts().to_vec(),
                }),
                None => ControlAck::Error {
                    message: format!("issuer does not exist: 0x{}", hex::encode(batch_id)),
                },
            };
            let _ = ack.send(reply);
        }
    }
}

/// Shared "no disk cache" pin error — pin state persists in the `SQLite`
/// cache, so a daemon started without one cannot pin.
fn pin_cache_disabled() -> ControlAck {
    ControlAck::Error {
        message: "pinning requires the disk chunk cache; pass --disk-cache-bytes > 0 at startup"
            .into(),
    }
}

/// Traverse the (plain or encrypted) content tree at `reference`,
/// fetch every chunk via `fetcher` (cache-first, network fallback),
/// and record the pin collection in the disk cache.
async fn pin_add(
    fetcher: &ant_retrieval::RoutingFetcher,
    disk_cache: &Arc<ant_retrieval::DiskChunkCache>,
    reference: &[u8],
) -> ControlAck {
    // Idempotence first, like bee's HasPin check: an already-pinned
    // root replies without re-traversing.
    match disk_cache.has_pin(reference.to_vec()).await {
        Ok(true) => {
            return ControlAck::PinAdded {
                already_pinned: true,
            }
        }
        Ok(false) => {}
        Err(e) => {
            return ControlAck::Error {
                message: format!("pin lookup failed: {e}"),
            }
        }
    }
    let addrs = match reference.len() {
        32 => {
            let root: [u8; 32] = reference.try_into().expect("length checked");
            ant_retrieval::traverse_chunk_addresses(fetcher, root, STEWARDSHIP_MAX_FILE_BYTES).await
        }
        len if len == ant_retrieval::ENC_REF_SIZE => {
            let root: [u8; ant_retrieval::ENC_REF_SIZE] =
                reference.try_into().expect("length checked");
            ant_retrieval::traverse_encrypted_chunk_addresses(
                fetcher,
                root,
                STEWARDSHIP_MAX_FILE_BYTES,
            )
            .await
        }
        len => {
            return ControlAck::Error {
                message: format!("invalid pin reference length: {len} bytes"),
            }
        }
    };
    let addrs = match addrs {
        Ok(a) => a,
        Err(e) => {
            return ControlAck::Error {
                message: format!("pin traversal failed: {e}"),
            }
        }
    };
    // Fetch every member (interiors are cache-hot from the traversal;
    // leaves may come from the network — that's the fetch-then-pin).
    type Fetched = Result<Vec<([u8; 32], Vec<u8>)>, String>;
    let fetched: Fetched = futures::stream::iter(addrs)
        .map(|addr| async move {
            fetcher
                .fetch(addr)
                .await
                .map(|wire| (addr, wire))
                .map_err(|e| format!("fetch {}: {e}", hex::encode(addr)))
        })
        .buffer_unordered(STEWARDSHIP_CONCURRENCY)
        .fold(Ok(Vec::new()), |acc, item| async move {
            match (acc, item) {
                (Ok(mut v), Ok(pair)) => {
                    v.push(pair);
                    Ok(v)
                }
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        })
        .await;
    let members = match fetched {
        Ok(m) => m,
        Err(message) => return ControlAck::Error { message },
    };
    match disk_cache.pin_collection(reference.to_vec(), members).await {
        Ok(newly) => ControlAck::PinAdded {
            already_pinned: !newly,
        },
        Err(e) => ControlAck::Error {
            message: format!("pin store failed: {e}"),
        },
    }
}

/// Pin-integrity check (bee `PinIntegrity.Check`): for each pin (or
/// just `reference`), count recorded members, members missing from the
/// local store, and members whose stored bytes fail CAC/SOC
/// validation.
async fn pin_check(
    disk_cache: &Arc<ant_retrieval::DiskChunkCache>,
    reference: Option<Vec<u8>>,
) -> ControlAck {
    let per_pin = match disk_cache.pin_members(reference).await {
        Ok(m) => m,
        Err(e) => {
            return ControlAck::Error {
                message: format!("pin members read failed: {e}"),
            }
        }
    };
    let mut stats = Vec::with_capacity(per_pin.len());
    for (reference, members) in per_pin {
        let mut stat = ant_control::PinCheckStat {
            reference,
            total: members.len() as u64,
            ..Default::default()
        };
        for addr in members {
            match disk_cache.get(addr).await {
                Ok(Some(wire)) => {
                    if !(ant_crypto::cac_valid(&addr, &wire) || ant_crypto::soc_valid(&addr, &wire))
                    {
                        stat.invalid += 1;
                    }
                }
                Ok(None) | Err(_) => stat.missing += 1,
            }
        }
        stats.push(stat);
    }
    ControlAck::PinCheck { stats }
}

/// Assemble the per-peer settlement/balance snapshot for
/// [`ControlCommand::AccountingSnapshot`]. Purely synchronous reads of
/// swarm-loop state (each source takes its own short-lived lock).
///
/// Rows are keyed by the peer's overlay (bee's peer identifier), so
/// only currently-connected peers — the routing table's snapshot — can
/// be rendered. That matches the lifetime of the accounting mirror
/// itself (reset per connection, like bee's `notifyPeerConnect`), but
/// it does mean persisted outbound-cheque cumulative amounts for peers
/// that are *not* connected right now are omitted: without the peer's
/// handshake we no longer know which overlay/EOA they belong to.
fn build_accounting_snapshot(state: &SwarmState) -> AccountingSnapshotView {
    let balances: HashMap<PeerId, (u64, u64)> = state
        .accounting
        .as_ref()
        .map(|a| {
            a.settlement_snapshot()
                .into_iter()
                .map(|(peer, balance, time_settled)| (peer, (balance, time_settled)))
                .collect()
        })
        .unwrap_or_default();
    let credits = state
        .credit_ledger
        .as_ref()
        .map(|l| (l.beneficiary(), l.snapshot()));

    let mut rows = Vec::new();
    for (peer, overlay) in state.routing.snapshot() {
        let (debt, time_settled) = match balances.get(&peer) {
            Some(&(balance, time_settled)) => (Some(balance), time_settled),
            None => (None, 0),
        };
        let eth = state.peer_eth.get(&peer);
        // Outbound: cumulative cheque payout to the peer's beneficiary.
        let swap_sent = match (eth, state.pushsync_swap.as_ref()) {
            (Some(e), Some(svc)) => svc.outbound_ledger().recorded_for(&e),
            _ => None,
        };
        let cheque_sent = match (eth, swap_sent, state.pushsync_swap.as_ref()) {
            (Some(e), Some(cumulative), Some(svc)) => Some(LastChequeView {
                beneficiary: hex::encode(e),
                chequebook: hex::encode(svc.chequebook()),
                payout: cumulative.to_string(),
            }),
            _ => None,
        };
        // Inbound: the credit-ledger record whose pinned issuer EOA is
        // this peer's handshake EOA (cheques are signed by the same
        // key the overlay is derived from).
        let cheque_received = match (&credits, eth) {
            (Some((our_beneficiary, records)), Some(e)) => {
                let eth_hex = hex::encode(e);
                records
                    .iter()
                    .find(|(_, credit)| credit.issuer_eoa_hex == eth_hex)
                    .map(|(chequebook_hex, credit)| LastChequeView {
                        beneficiary: hex::encode(our_beneficiary),
                        chequebook: chequebook_hex.clone(),
                        payout: credit.cumulative_payout_dec.clone(),
                    })
            }
            _ => None,
        };
        let swap_received = cheque_received.as_ref().map(|c| c.payout.clone());

        let row = PeerAccountingView {
            peer: hex::encode(overlay),
            debt_to_peer: debt.map(|b| b.to_string()),
            swap_sent: swap_sent.map(|u| u.to_string()),
            swap_received,
            time_sent: (time_settled > 0).then(|| time_settled.to_string()),
            cheque_sent,
            cheque_received,
        };
        // Peers with no record anywhere are omitted — bee's stores
        // have no entry for them either (its per-peer endpoints 404).
        if row.debt_to_peer.is_some()
            || row.swap_sent.is_some()
            || row.swap_received.is_some()
            || row.time_sent.is_some()
        {
            rows.push(row);
        }
    }
    // Stable order so repeated snapshots render identically.
    rows.sort_by(|a, b| a.peer.cmp(&b.peer));
    let outbound = state
        .pushsync_swap
        .as_ref()
        .map(|svc| svc.outbound_ledger())
        .or(state.retired_outbound.as_ref());
    AccountingSnapshotView {
        peers: rows,
        cheques_issued_plur: outbound.and_then(|l| {
            // An unreadable ledger doesn't know the total: report none
            // rather than a short one.
            l.ensure_readable()
                .ok()
                .map(|()| l.total_issued().to_string())
        }),
        cheques_issued_chequebook: outbound.map(|l| hex::encode(l.chequebook())),
        cheques_ledger_lost: outbound.and_then(crate::swap::OutboundLedger::lost_figures),
    }
}

/// Cap on how many bytes any single file span inside a stewardship
/// traversal may declare. Matches the gateway's serving ceiling rather
/// than the conservative CLI joiner default, so stewardship works on
/// real multi-GiB bzz content.
const STEWARDSHIP_MAX_FILE_BYTES: usize = 16 * 1024 * 1024 * 1024;

/// Concurrent chunk probes / pushes during a stewardship check or
/// re-upload. Same bound the upload pipeline uses for `PushChunk`
/// fan-out (`MAX_PUSH_CONCURRENCY` in `ant-node`/`ant-gateway`).
const STEWARDSHIP_CONCURRENCY: usize = 32;

/// Validate a caller-supplied pre-signed 113-byte postage stamp against
/// the chunk address it claims to cover: shape, then signature recovery
/// over bee's stamp digest (`keccak256(addr ‖ batch ‖ index ‖ ts)`).
/// Recovery succeeding means the stamp was really signed over *this*
/// chunk by *some* batch owner — the strongest check a light node
/// without a batchstore can make (bee additionally compares the
/// recovered owner against the on-chain batch owner).
fn validate_presigned_stamp(
    pre: &[u8],
    addr: &[u8; 32],
) -> Result<[u8; ant_postage::STAMP_SIZE], String> {
    let stamp: [u8; ant_postage::STAMP_SIZE] = pre.try_into().map_err(|_| {
        format!(
            "presigned stamp must be {} bytes, got {}",
            ant_postage::STAMP_SIZE,
            pre.len()
        )
    })?;
    let batch: &[u8; 32] = stamp[0..32].try_into().expect("slice length");
    let index: &[u8; 8] = stamp[32..40].try_into().expect("slice length");
    let ts: &[u8; 8] = stamp[40..48].try_into().expect("slice length");
    let sig: &[u8; 65] = stamp[48..113].try_into().expect("slice length");
    let digest = ant_postage::postage_sign_digest(addr, batch, index, ts);
    ant_crypto::recover_public_key(sig, digest.as_ref())
        .map_err(|e| format!("presigned stamp signature invalid: {e}"))?;
    Ok(stamp)
}

/// Bug-hunt Fix C: one bounded retry of a failed network read after
/// the peer set changes. Retrieval failures on a light node cluster in
/// churn troughs — the walk exhausts against a momentarily-thin/flappy
/// pool and the SAME read succeeds seconds later (the field report's
/// self-healing read 502s). Instead of surfacing the first exhaustion,
/// nudge the swarm to dial toward the target's neighbourhood, wait
/// (≤ `ANT_READ_RETRY_WAIT_MS`, default 2500, 0 disables) for the peer
/// set to actually change, and re-run the fetch once. The local-cache
/// fast path is unaffected — this only runs after a full network walk
/// already failed.
async fn fetch_with_retry(
    fetcher: &ant_retrieval::RoutingFetcher,
    mut peers_rx: watch::Receiver<Vec<(PeerId, [u8; 32])>>,
    reference: [u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let first = fetcher.fetch(reference).await;
    let wait = read_retry_wait();
    if wait.is_zero() {
        return first;
    }
    match first {
        Ok(wire) => Ok(wire),
        Err(e) => {
            debug!(
                target: "ant_p2p",
                addr = %hex::encode(reference),
                err = %e,
                "read walk exhausted; dialing toward the neighbourhood and retrying once",
            );
            fetcher.request_neighborhood_dial_pub(&reference);
            let _ = tokio::time::timeout(wait, peers_rx.changed()).await;
            fetcher.fetch(reference).await
        }
    }
}

/// `ANT_READ_RETRY_WAIT_MS` — bounded wait for a peer-set change before
/// the single read re-walk. Default 2500 ms; `0` disables (pre-fix
/// behaviour, the A/B control arm).
fn read_retry_wait() -> Duration {
    static MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    Duration::from_millis(*MS.get_or_init(|| {
        std::env::var("ANT_READ_RETRY_WAIT_MS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(2500)
    }))
}

/// Perf-lab bug-hunt Fix A: outer patience for the gateway's ONE-SHOT
/// push paths (`POST /soc`, `POST /chunks`, `/bytes`, `/bzz`).
///
/// Unlike the `antctl upload` job manager — which re-queues failed
/// chunks forever with escalating backoff — the gateway endpoints get
/// a single `push_stamped_chunk` walk over the currently-connected
/// peers, and its exhaustion surfaces as a client-visible 502. The
/// field signature (2026-07 reliability report): a fresh SOC address
/// lands in a never-dialed neighbourhood, the walk exhausts before the
/// gossip-deepening cycle connects deeper peers, and the CLIENT's
/// retry succeeds a second later because deepening kept working in the
/// background. This loop is that retry, server-side: re-walk on
/// transient exhaustion until `ANT_GATEWAY_PUSH_PATIENCE_SECS`
/// (default 12 s, `0` disables) elapses, waiting ≤1.5 s for the peer
/// set to CHANGE between walks so a re-walk only runs against a
/// genuinely different candidate pool.
///
/// Fix B rides the same loop for SOCs: the walk runs strict-receipt
/// (`require_deep`) during patience — a shallow receipt re-walks after
/// deepening instead of being accepted immediately — and only at the
/// patience ceiling falls back to one final shallow-accepting walk, so
/// a hostile neighbourhood degrades to today's behaviour instead of a
/// new failure mode. (The upload job manager got strict receipts in
/// v0.5.37; the SOC path had kept unconditional shallow-accept, which
/// the 16-worker soak measured as 0.35 % of SOCs never becoming
/// retrievable from an independent node — a 201'd write the network
/// cannot see.)
///
/// `rejections_are_lag_until` is set for a batch this node just bought
/// ([`rejection_lag_deadline`]). Until then a "not found on-chain"
/// rejection means the storers haven't synced the batch's creation
/// block yet, so the push waits a block and re-walks instead of
/// failing, however long the patience budget is. Only those waits run
/// past the budget: every other failure still gets the ordinary
/// patience budget, counted from the last propagation wait (so a
/// transient exhaustion right after the storers accept the batch gets
/// its re-walks too) — see [`Patience`].
async fn push_with_patience(
    fetcher: &ant_retrieval::RoutingFetcher,
    mut peers_rx: watch::Receiver<Vec<(PeerId, [u8; 32])>>,
    addr: [u8; 32],
    wire: Vec<u8>,
    stamp: [u8; ant_postage::STAMP_SIZE],
    strict_first: bool,
    rejections_are_lag_until: Option<Instant>,
) -> Result<(), ant_retrieval::pushsync::PushSyncError> {
    // The patience budget runs on tokio's clock (as the fetcher's credit
    // deadline does), so tests can drive it with a paused clock; the
    // batch-propagation window below stays on `std::time::Instant`, the
    // clock its registration stamp was taken on.
    let started = tokio::time::Instant::now();
    let mut patience = Patience::new(gateway_push_patience(), started);
    let mut last_err = None;
    let mut walk = 0u32;
    loop {
        walk += 1;
        // A neighbourhood a recent push already found without a reachable
        // deep storer: hunting the whole patience again (~30 s) ends
        // shallow anyway, so go straight to the shallow-accepting walk.
        let strict = strict_first
            && !patience.exhausted(tokio::time::Instant::now())
            && !fetcher.in_shallow_neighbourhood(&addr);
        let res = fetcher
            .push_stamped_chunk_with_policy(addr, wire.clone(), stamp, strict)
            .await;
        match res {
            Ok(()) => {
                if walk > 1 {
                    debug!(
                        target: "ant_p2p",
                        addr = %hex::encode(addr),
                        walk,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "gateway push landed after outer re-walk",
                    );
                }
                return Ok(());
            }
            Err(e) => {
                // A stamp rejection is deterministic across honest
                // storers — re-walking or falling back to shallow can
                // never help, and burning the patience budget turns an
                // instant clear failure into a slow opaque one
                // (phantom-batch report). Except for a just-bought
                // batch: storers learn of it only once their postage
                // listeners sync its creation block.
                if let Some(wait) = propagation_wait(&e, rejections_are_lag_until, Instant::now()) {
                    debug!(
                        target: "ant_p2p",
                        addr = %hex::encode(addr),
                        walk,
                        err = %e,
                        "batch not yet known to the storers (just bought); waiting a block to re-walk",
                    );
                    last_err = Some(e);
                    tokio::time::sleep(wait).await;
                    patience.restart(tokio::time::Instant::now());
                    continue;
                }
                if matches!(
                    e,
                    ant_retrieval::pushsync::PushSyncError::StampRejected { .. }
                ) {
                    return Err(e);
                }
                if patience.exhausted(tokio::time::Instant::now()) {
                    // Strict SOCs get one final bee-aligned
                    // shallow-accepting walk before we give up: stored
                    // shallow beats a 502 with nothing stored.
                    if strict {
                        if let Ok(()) = fetcher
                            .push_stamped_chunk_with_policy(addr, wire.clone(), stamp, false)
                            .await
                        {
                            if let Some(ant_retrieval::pushsync::PushSyncError::ShallowReceipt {
                                storage_radius,
                                ..
                            }) = last_err.as_ref().or(Some(&e))
                            {
                                fetcher.mark_shallow_neighbourhood(&addr, *storage_radius);
                            }
                            warn!(
                                target: "ant_p2p",
                                addr = %hex::encode(addr),
                                "gateway push: deep placement not achieved within patience; accepted shallow",
                            );
                            return Ok(());
                        }
                    }
                    return Err(last_err.unwrap_or(e));
                }
                warn!(
                    target: "ant_p2p",
                    addr = %hex::encode(addr),
                    walk,
                    err = %e,
                    "gateway push walk failed; waiting for peer-set change before re-walk",
                );
                last_err = Some(e);
                // Ride the deepening cycle: re-walk when the peer set
                // actually changes (a dial landed / gossip arrived),
                // with a nap floor so a hot flapping set can't spin us.
                let _ = tokio::time::timeout(Duration::from_millis(1500), peers_rx.changed()).await;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

/// The re-walk budget of [`push_with_patience`]. It runs from the
/// push's start, and restarts after each wait for a just-bought batch
/// to reach the storers: those waits are bounded by the batch's own
/// window ([`propagation_wait`]), and must not stretch the budget for
/// other failures (a transient "exhausted peers" is given up on after
/// `budget`, not after the batch's whole propagation window).
#[derive(Debug, Clone, Copy)]
struct Patience {
    budget: Duration,
    from: tokio::time::Instant,
}

impl Patience {
    fn new(budget: Duration, now: tokio::time::Instant) -> Self {
        Self { budget, from: now }
    }

    /// Start the budget over, after a propagation wait.
    fn restart(&mut self, now: tokio::time::Instant) {
        self.from = now;
    }

    fn exhausted(&self, now: tokio::time::Instant) -> bool {
        now.saturating_duration_since(self.from) >= self.budget
    }
}

/// `ANT_GATEWAY_PUSH_PATIENCE_SECS` — outer re-walk budget for gateway
/// one-shot pushes. Default 12 s; `0` disables (single-walk, the
/// pre-fix behaviour, kept as the A/B control arm).
fn gateway_push_patience() -> Duration {
    static SECS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    Duration::from_secs(*SECS.get_or_init(|| {
        std::env::var("ANT_GATEWAY_PUSH_PATIENCE_SECS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(12)
    }))
}

/// How long a just-bought batch takes to reach the storers: bee's
/// `blockThreshold` of 10 blocks past the creation block
/// (`pkg/postage/service.go`, `IssuerUsable`), plus the 4 blocks bee's
/// postage listener trails the chain head (`tailSize`,
/// `pkg/postage/listener/listener.go`), at Gnosis's 5 s blocks. Storers
/// reject a batch's stamps as "not found on-chain" until their
/// batchstores have synced its creation block, and bee doesn't stamp
/// with a batch before then either. Counted from registration, which
/// follows the buy receipt, so it never starts early.
const BATCH_PROPAGATION: Duration = Duration::from_secs((10 + 4) * 5);

/// How long past [`BATCH_PROPAGATION`] a push still reads a "not found
/// on-chain" rejection as propagation lag, for storers whose listener
/// polls late. Short enough that the *waiting* — the whole window, then
/// one default patience budget, 112 s — stays inside the upload
/// manager's 2-minute push timeout (and the gateway's
/// `CHUNK_PUSH_TIMEOUT`). The walks themselves come on top: deadlines
/// are only checked between walks, and one walk can spend up to one
/// `PUSHSYNC_TIMEOUT` (45 s, `ant-retrieval`) per candidate peer. So a
/// push whose last walk starts near the end of the wait and runs slow
/// can still ack past 2 minutes: the caller then sees a timeout (504
/// on the gateway routes, a re-dispatch in the upload manager) while
/// the push finishes in the background. Nothing is lost; the same
/// overshoot existed before the propagation wait (budget + walk time
/// against the old 60 s cap).
const PROPAGATION_REJECTION_GRACE: Duration = Duration::from_secs(30);

/// Pause between re-walks while a push waits for its batch to reach
/// the storers: one Gnosis block.
const PROPAGATION_RETRY: Duration = Duration::from_secs(5);

/// A batch this node registered right after buying it.
#[derive(Debug, Clone, Copy)]
struct BoughtBatch {
    /// The `createBatch` receipt's block, reported as `blockNumber`.
    block: u64,
    registered: Instant,
}

impl BoughtBatch {
    /// Whether the storers may not know the batch yet, so it isn't
    /// usable.
    fn propagating(&self, now: Instant) -> bool {
        now < self.registered + BATCH_PROPAGATION
    }

    /// Until when a "not found on-chain" rejection is propagation lag.
    fn rejections_are_lag_until(&self) -> Instant {
        self.registered + BATCH_PROPAGATION + PROPAGATION_REJECTION_GRACE
    }
}

/// Record a batch registered right after its buy. A second
/// registration (a retried buy flow) keeps the first record.
fn note_bought_batch(state: &mut SwarmState, batch_id: [u8; 32], block: u64) {
    state
        .bought_batches
        .entry(batch_id)
        .or_insert_with(|| BoughtBatch {
            block,
            registered: Instant::now(),
        });
}

/// How long a push waits before re-walking after `err`: `Some` only
/// for a "not found on-chain" rejection while the batch is still
/// propagating (`lag_until` in the future), at most one block.
fn propagation_wait(
    err: &ant_retrieval::pushsync::PushSyncError,
    lag_until: Option<Instant>,
    now: Instant,
) -> Option<Duration> {
    if !matches!(
        err,
        ant_retrieval::pushsync::PushSyncError::StampRejected { .. }
    ) {
        return None;
    }
    let left = lag_until?.saturating_duration_since(now);
    (!left.is_zero()).then(|| PROPAGATION_RETRY.min(left))
}

/// Until when a push stamped with `stamp` may treat "not found on-chain"
/// as propagation lag: set only for a batch this node just bought.
fn rejection_lag_deadline(
    state: &SwarmState,
    stamp: &[u8; ant_postage::STAMP_SIZE],
) -> Option<Instant> {
    let mut batch_id = [0u8; 32];
    batch_id.copy_from_slice(&stamp[..32]);
    state
        .bought_batches
        .get(&batch_id)
        .map(BoughtBatch::rejections_are_lag_until)
}

/// First self-probe delay after a batch is peer-rejected. Rejections
/// with "batchstore … not found" are usually a propagation race — the
/// on-chain creation event hasn't reached the storers' batchstores yet
/// — and peers typically sync within seconds to a couple of minutes.
const BATCH_PROBE_BACKOFF_INITIAL: Duration = Duration::from_secs(15);
/// Backoff ceiling for repeated probe rejections. A batch still
/// rejected at this cadence is plausibly a genuine phantom (creation tx
/// reorged away / wrong chain), but "not found" is never a *durable*
/// verdict, so we keep probing cheaply rather than give up.
const BATCH_PROBE_BACKOFF_MAX: Duration = Duration::from_mins(10);
/// How often the node loop scans for due batch probes. Cheap no-op
/// when nothing is marked rejected.
const BATCH_PROBE_TICK: Duration = Duration::from_secs(5);
/// Flight lease on an in-flight probe: while a probe is running, no
/// second probe fires for the same batch — a pushsync walk can outlast
/// the early backoffs (per-peer timeouts × error budget), and without
/// the guard two overlapping rejections would double the backoff twice
/// per schedule. If the outcome never lands within the lease (a lost
/// task), the flight is considered dead and probing resumes — a stuck
/// `in_flight` must not quietly reinstate the very deadlock this
/// machinery exists to break.
const BATCH_PROBE_FLIGHT_LEASE: Duration = Duration::from_mins(2);

/// Self-probe schedule for one peer-rejected batch (issue #52).
///
/// "Unusable until a push succeeds" used to be the whole recovery
/// story — but every well-behaved client filters on `usable`, so the
/// rejected batch was never selected, never pushed with, and never
/// recovered. The node now re-validates rejected batches *itself*: a
/// tiny deterministic probe chunk is re-pushed with backoff until
/// peers accept it, at which point the mark clears and `/stamps`
/// reports the batch usable again with no client action.
struct RejectedBatch {
    /// Delay before the probe after next; doubles on each probe the
    /// peers still reject, capped at [`BATCH_PROBE_BACKOFF_MAX`].
    backoff: Duration,
    /// When the next probe becomes due.
    next_probe: Instant,
    /// Probes attempted so far (diagnostics only).
    probes: u32,
    /// A probe is currently running (strict one-in-flight per batch).
    /// Set when the probe is popped, cleared by
    /// [`record_batch_probe_outcome`]; bounded by
    /// [`BATCH_PROBE_FLIGHT_LEASE`] so a lost task can't wedge probing.
    in_flight: bool,
}

/// Peer-rejected batches keyed by batch id, with their probe schedules.
type RejectedBatches = Arc<std::sync::Mutex<HashMap<[u8; 32], RejectedBatch>>>;

/// Maintain the peer-attested phantom-batch set: a `StampRejected`
/// outcome marks the stamp's batch rejected (so `/stamps` turns
/// `usable:false` after the first failed push) and schedules the
/// self-probe; any successful push with the batch clears it.
fn note_stamp_outcome(
    rejected: &RejectedBatches,
    stamp: &[u8; ant_postage::STAMP_SIZE],
    err: Option<&ant_retrieval::pushsync::PushSyncError>,
) {
    let mut batch_id = [0u8; 32];
    batch_id.copy_from_slice(&stamp[..32]);
    let Ok(mut set) = rejected.lock() else {
        return;
    };
    match err {
        Some(ant_retrieval::pushsync::PushSyncError::StampRejected { .. }) => {
            // Repeated organic rejections don't reset an existing probe
            // schedule — the prober owns the backoff.
            set.entry(batch_id).or_insert_with(|| {
                warn!(
                    target: "ant_p2p",
                    batch = %hex::encode(batch_id),
                    "batch marked peer-rejected — /stamps reports it unusable; \
                     self-probing with backoff until peers accept it",
                );
                RejectedBatch {
                    backoff: BATCH_PROBE_BACKOFF_INITIAL,
                    next_probe: Instant::now() + BATCH_PROBE_BACKOFF_INITIAL,
                    probes: 0,
                    in_flight: false,
                }
            });
        }
        Some(_) => {}
        None => {
            if set.remove(&batch_id).is_some() {
                info!(
                    target: "ant_p2p",
                    batch = %hex::encode(batch_id),
                    "peer-rejected batch recovered — a push succeeded; /stamps reports it usable again",
                );
            }
        }
    }
}

/// Pop the batches whose probe is due. Popping marks the batch
/// `in_flight` and leases the slot for [`BATCH_PROBE_FLIGHT_LEASE`]:
/// exactly one probe runs per batch at a time, however long the walk
/// takes relative to the backoff. A batch still `in_flight` past its
/// lease is a lost task — probing resumes (with a warning) rather than
/// staying wedged forever.
fn due_batch_probes(rejected: &RejectedBatches, now: Instant) -> Vec<[u8; 32]> {
    let Ok(mut set) = rejected.lock() else {
        return Vec::new();
    };
    let mut due = Vec::new();
    for (batch_id, entry) in set.iter_mut() {
        if entry.next_probe > now {
            continue;
        }
        if entry.in_flight {
            warn!(
                target: "ant_p2p",
                batch = %hex::encode(batch_id),
                "batch probe outlived its flight lease (lost task?); re-probing",
            );
        }
        entry.in_flight = true;
        entry.next_probe = now + BATCH_PROBE_FLIGHT_LEASE;
        entry.probes += 1;
        due.push(*batch_id);
    }
    due
}

/// Record one probe's outcome. Success clears the mark (via
/// [`note_stamp_outcome`]'s semantics); a fresh `StampRejected` doubles
/// the backoff toward the cap; any other failure (no peers, timeouts)
/// keeps the current cadence — it isn't a verdict about the batch.
fn record_batch_probe_outcome(
    rejected: &RejectedBatches,
    batch_id: [u8; 32],
    err: Option<&ant_retrieval::pushsync::PushSyncError>,
) {
    let Ok(mut set) = rejected.lock() else {
        return;
    };
    match err {
        None => {
            if let Some(e) = set.remove(&batch_id) {
                info!(
                    target: "ant_p2p",
                    batch = %hex::encode(batch_id),
                    probes = e.probes,
                    "peer-rejected batch recovered by self-probe — /stamps reports it usable again",
                );
            }
        }
        Some(ant_retrieval::pushsync::PushSyncError::StampRejected { .. }) => {
            if let Some(e) = set.get_mut(&batch_id) {
                e.in_flight = false;
                e.backoff = (e.backoff * 2).min(BATCH_PROBE_BACKOFF_MAX);
                e.next_probe = Instant::now() + e.backoff;
                debug!(
                    target: "ant_p2p",
                    batch = %hex::encode(batch_id),
                    probes = e.probes,
                    next_backoff_secs = e.backoff.as_secs(),
                    "batch self-probe still peer-rejected; backing off",
                );
            }
        }
        // Transient (no peers / timeout): release the flight and keep
        // the cadence — this outcome says nothing about the batch.
        Some(_) => {
            if let Some(e) = set.get_mut(&batch_id) {
                e.in_flight = false;
                e.next_probe = Instant::now() + e.backoff;
            }
        }
    }
}

/// The deterministic probe chunk for a batch: a tiny CAC whose address
/// is a pure function of the batch id. Re-probing therefore re-stamps
/// the *same* address every time, and the issuer's per-chunk stamp
/// cache reuses the original bucket slot (with a fresh timestamp) — so
/// self-probing a batch costs exactly ONE `(bucket, index)` slot total,
/// no matter how many probes it takes.
fn batch_probe_chunk(batch_id: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let payload = format!("ant postage batch probe 0x{}", hex::encode(batch_id));
    ant_crypto::cac_new(payload.as_bytes()).expect("probe payload is far below the chunk cap")
}

/// Build the routing fetcher every push path shares, with the full
/// wiring: push-skip cache, network id, load tracker, neighborhood
/// dialer, and SWAP (or env-gated pseudosettle) settlement. ONE place —
/// `push_with_stamp`, `push_soc_with_stamp`, and the batch self-probe
/// all call this, so a future settlement change cannot silently miss a
/// path (the probe being the one nobody would remember to update).
/// Callers layer path-specific options (`with_require_deep`) on top.
fn build_push_fetcher(
    state: &SwarmState,
    control: Control,
    network_id: u64,
) -> ant_retrieval::RoutingFetcher {
    let mut fetcher = ant_retrieval::RoutingFetcher::new(control, state.peers_watch.subscribe())
        .with_push_skip(state.push_skip.clone())
        .with_shallow_memory(state.shallow_neighbourhoods.clone())
        .with_network_id(network_id);
    if let Some(load) = state.push_load.clone() {
        fetcher = fetcher.with_push_load(load);
    }
    if let Some(tx) = state.neighborhood_dial_tx.clone() {
        fetcher = fetcher.with_neighborhood_dialer(tx);
    }
    if let Some(s) = push_settlement(
        state.accounting.clone(),
        state.pushsync_swap.is_some(),
        crate::push_pseudosettle::PushPseudosettle::enabled_by_env(),
    ) {
        fetcher = fetcher.with_pushsync_settlement(s);
    }
    fetcher
}

/// How pushsync debt is settled: like bee, in the same per-peer balance
/// as retrieval debt. Each accepted push is debited to the shared
/// accounting mirror ([`crate::push_pseudosettle::PushPseudosettle`]),
/// which settles it the way it settles downloads — the free pseudosettle
/// refresh first, then, while the node has a payer installed (a funded
/// chequebook with `swap-enable` on, see [`sync_retrieval_payment`]), a
/// cheque priced `units × exchange + deduction` once the debt reaches the
/// early-payment threshold, lowering the mirror only by the units bee
/// credits for a delivered cheque (issue #127).
///
/// Without a chequebook the debit is still mirrored so the refresh covers
/// uploads (perf-lab experiment 1), unless `ANT_PUSH_PSEUDOSETTLE=0`
/// opts out (`pseudosettle_by_env`, the A/B control arm). With a
/// chequebook it always is: the mirror is what pays.
fn push_settlement(
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    has_chequebook: bool,
    pseudosettle_by_env: bool,
) -> Option<Arc<dyn ant_retrieval::PushsyncSettlement>> {
    let acc = accounting.filter(|_| has_chequebook || pseudosettle_by_env)?;
    Some(Arc::new(crate::push_pseudosettle::PushPseudosettle::new(
        acc,
    )))
}

/// Fire one self-probe push per due rejected batch (issue #52). Called
/// from the node loop on [`BATCH_PROBE_TICK`]; a fast no-op while
/// nothing is marked rejected. Each probe is a real single-walk
/// pushsync of the batch's deterministic probe chunk: success clears
/// the rejection (and `/stamps` flips back to `usable:true`), a fresh
/// peer rejection doubles the backoff, and transient failures keep the
/// cadence.
fn spawn_due_batch_probes(
    state: &SwarmState,
    control: &Control,
    upload: Option<&Arc<UploadRuntime>>,
    network_id: u64,
) {
    // Cheap emptiness gate before any other work.
    if state.rejected_batches.lock().map_or(true, |s| s.is_empty()) {
        return;
    }
    let Some(upload) = upload else { return };
    for batch_id in due_batch_probes(&state.rejected_batches, Instant::now()) {
        let (addr, wire) = batch_probe_chunk(&batch_id);
        // Stamp under the issuer mutex like every push. The probe
        // address is fixed per batch, so this reuses the same bucket
        // slot on every probe (fresh timestamp) — one slot total.
        let stamp = {
            let mut issuers = match upload.issuers.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let Some(issuer) = issuers.get_mut(&batch_id) else {
                // Batch was deregistered since the rejection: nothing
                // left to recover — drop the mark.
                if let Ok(mut set) = state.rejected_batches.lock() {
                    set.remove(&batch_id);
                }
                continue;
            };
            match ant_postage::sign_stamp_bytes(&upload.stamp_key, issuer, &addr) {
                Ok(s) => s,
                Err(e) => {
                    // Issuer can't stamp (e.g. sidecar poisoned):
                    // probing is pointless until that's resolved. Keep
                    // the mark, release the flight, retry at the
                    // current cadence.
                    debug!(
                        target: "ant_p2p",
                        batch = %hex::encode(batch_id),
                        "batch self-probe could not stamp: {e}",
                    );
                    if let Ok(mut set) = state.rejected_batches.lock() {
                        if let Some(entry) = set.get_mut(&batch_id) {
                            entry.in_flight = false;
                            entry.next_probe = Instant::now() + entry.backoff;
                        }
                    }
                    continue;
                }
            }
        };
        let fetcher = build_push_fetcher(state, control.clone(), network_id);
        let rejected = state.rejected_batches.clone();
        tokio::spawn(async move {
            debug!(
                target: "ant_p2p",
                batch = %hex::encode(batch_id),
                probe_chunk = %hex::encode(addr),
                "self-probing peer-rejected batch",
            );
            match fetcher.push_stamped_chunk(addr, wire, stamp).await {
                Ok(()) => record_batch_probe_outcome(&rejected, batch_id, None),
                Err(e) => record_batch_probe_outcome(&rejected, batch_id, Some(&e)),
            }
        });
    }
}

/// A chunk waiting for its postage stamp (see [`run_stamper`]).
struct StampJob {
    upload: Arc<UploadRuntime>,
    batch_id: [u8; 32],
    addr: [u8; 32],
    wire: Vec<u8>,
    require_deep: bool,
    ack_when_stored: bool,
    ack: oneshot::Sender<ControlAck>,
}

/// A stamped chunk on its way back to the swarm loop to be pushed.
struct StampedPush {
    addr: [u8; 32],
    wire: Vec<u8>,
    stamp: [u8; ant_postage::STAMP_SIZE],
    require_deep: bool,
    ack_when_stored: bool,
    ack: oneshot::Sender<ControlAck>,
}

/// Most chunks stamped under one durable write.
const STAMP_BATCH_MAX: usize = 512;

/// Stamp chunks in batches, off the swarm loop.
///
/// Stamping a new chunk persists the batch's bucket table and its stamp
/// record before the stamp may leave (an index must never be issued
/// twice, crash or not). Done per chunk on the swarm loop, that was a
/// 256 KiB rewrite and several `fsync`s per chunk, stalling every other
/// protocol meanwhile: ~1 ms a chunk on a server SSD, far more on a
/// phone (`F_FULLFSYNC` on iOS). Here whatever is queued when a batch
/// starts is stamped with one write of each
/// ([`ant_postage::sign_stamps_batch`]); while it runs the next batch
/// queues up, so batches grow with the load (a video segment's chunks
/// arrive together). Stamps go back to the loop in arrival order.
async fn run_stamper(
    mut jobs: mpsc::UnboundedReceiver<StampJob>,
    stamped: mpsc::UnboundedSender<StampedPush>,
) {
    while let Some(first) = jobs.recv().await {
        let mut batch = vec![first];
        while batch.len() < STAMP_BATCH_MAX {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        let Ok(results) = tokio::task::spawn_blocking(move || stamp_jobs(batch)).await else {
            // The blocking task panicked: its jobs' acks were dropped,
            // which their callers see as an error.
            continue;
        };
        for (job, result) in results {
            match result {
                Ok(stamp) => {
                    let push = StampedPush {
                        addr: job.addr,
                        wire: job.wire,
                        stamp,
                        require_deep: job.require_deep,
                        ack_when_stored: job.ack_when_stored,
                        ack: job.ack,
                    };
                    if let Err(mpsc::error::SendError(push)) = stamped.send(push) {
                        let _ = push.ack.send(ControlAck::Error {
                            message: "node stopped".into(),
                        });
                    }
                }
                Err(message) => {
                    let _ = job.ack.send(ControlAck::Error { message });
                }
            }
        }
    }
}

/// Stamp `jobs`, one durable write per batch they belong to, in order.
fn stamp_jobs(
    jobs: Vec<StampJob>,
) -> Vec<(StampJob, Result<[u8; ant_postage::STAMP_SIZE], String>)> {
    let mut results: Vec<Option<Result<[u8; ant_postage::STAMP_SIZE], String>>> =
        (0..jobs.len()).map(|_| None).collect();
    // Group by (upload runtime, batch), keeping arrival order within each.
    let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
    for (i, job) in jobs.iter().enumerate() {
        match groups.iter_mut().find(|(first, _)| {
            Arc::ptr_eq(&jobs[*first].upload, &job.upload) && jobs[*first].batch_id == job.batch_id
        }) {
            Some((_, members)) => members.push(i),
            None => groups.push((i, vec![i])),
        }
    }
    for (first, members) in groups {
        let upload = &jobs[first].upload;
        let batch_id = jobs[first].batch_id;
        let mut issuers = match upload.issuers.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(issuer) = issuers.get_mut(&batch_id) else {
            for i in members {
                results[i] = Some(Err(format!("batch 0x{} not usable", hex::encode(batch_id))));
            }
            continue;
        };
        let mut to_stamp = Vec::with_capacity(members.len());
        for i in members {
            let addr = jobs[i].addr;
            if !issuer.has_stamp(&addr) && issuer.bucket_is_full(&addr) {
                if issuer.immutable() {
                    warn!(
                        target: "ant_p2p",
                        batch = %hex::encode(batch_id),
                        depth = issuer.batch_depth(),
                        addr = %hex::encode(addr),
                        "refusing to stamp: collision bucket full on immutable batch — stamping would evict an existing chunk (buy/dilute a larger batch)",
                    );
                    results[i] = Some(Err(format!(
                        "batch 0x{} saturated: collision bucket full at depth {} on an immutable batch — stamping would evict an existing chunk; buy or dilute to a larger batch",
                        hex::encode(batch_id),
                        issuer.batch_depth(),
                    )));
                    continue;
                }
                warn!(
                    target: "ant_p2p",
                    batch = %hex::encode(batch_id),
                    depth = issuer.batch_depth(),
                    addr = %hex::encode(addr),
                    "collision bucket full on mutable batch — wrapping (evicting the oldest stamp in this bucket); consider diluting to a larger batch",
                );
            }
            to_stamp.push(i);
        }
        let addrs: Vec<[u8; 32]> = to_stamp.iter().map(|&i| jobs[i].addr).collect();
        let stamps = ant_postage::sign_stamps_batch(&upload.stamp_key, issuer, &addrs);
        for (i, stamp) in to_stamp.into_iter().zip(stamps) {
            results[i] = Some(stamp.map_err(|e| format!("stamp issue failed: {e}")));
        }
    }
    jobs.into_iter()
        .zip(results)
        .map(|(job, r)| (job, r.unwrap_or_else(|| Err("not stamped".into()))))
        .collect()
}

/// Node-wide cap on deep-storer hunts that go on after their push was
/// answered as stored (`ack_when_stored`, issue #212). An answered push
/// leaves its request's `MAX_PUSH_CONCURRENCY` window (32 per request in
/// `ant-gateway`/`ant-node`), so without this the hunts left behind by
/// one request after another would add up with nothing bounding them,
/// and per-peer stream pressure is what collapses a push run (PR #72).
/// Once every slot is taken, a push that gets its first receipt is not
/// answered early: its caller waits for placement as without the
/// header, which keeps it inside its request's window and slows the
/// request down instead of adding more pushes. That wait also hedges as
/// without the header, every 5 s: the fetcher's 1 s hedge ends at the
/// stored signal, whether or not a slot was free to answer on it. 64 is
/// two requests' worth of data pushes; at about one shallow first
/// receipt in ten (issue #212's measurement) a 2 s live cadence leaves
/// a handful of hunts running at a time.
const MAX_BACKGROUND_HUNTS: usize = 64;

/// How a push that may answer early ended its first wait.
enum PushStep {
    Done(Result<(), ant_retrieval::pushsync::PushSyncError>),
    /// A storer receipted it (shallow): answered, the hunt goes on,
    /// holding one of the [`MAX_BACKGROUND_HUNTS`] slots until it ends.
    Stored(tokio::sync::OwnedSemaphorePermit),
    Abandoned,
}

/// Wait for the first of: the push ending, its stored signal (answered
/// early only if a [`MAX_BACKGROUND_HUNTS`] slot is free, otherwise it
/// keeps waiting for the push to end), or, when `abandonable`, its
/// requester going away.
async fn next_push_step<F>(
    mut push: std::pin::Pin<&mut F>,
    stored: oneshot::Receiver<()>,
    ack: &mut oneshot::Sender<ControlAck>,
    abandonable: bool,
    background_hunts: &Arc<Semaphore>,
) -> PushStep
where
    F: std::future::Future<Output = Result<(), ant_retrieval::pushsync::PushSyncError>>,
{
    let abandoned = async {
        if abandonable {
            ack.closed().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(abandoned);
    tokio::select! {
        outcome = &mut push => return PushStep::Done(outcome),
        Ok(()) = stored => {}
        () = &mut abandoned => return PushStep::Abandoned,
    }
    if let Ok(slot) = background_hunts.clone().try_acquire_owned() {
        return PushStep::Stored(slot);
    }
    tokio::select! {
        outcome = &mut push => PushStep::Done(outcome),
        () = &mut abandoned => PushStep::Abandoned,
    }
}

/// `fetcher` with a stored signal when `enabled` (`ack_when_stored`,
/// issue #212), and the receiver to wait on. Without it the receiver
/// errors at once, which disables its `select!` arm.
fn with_stored_signal(
    fetcher: ant_retrieval::RoutingFetcher,
    enabled: bool,
) -> (ant_retrieval::RoutingFetcher, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    let fetcher = if enabled {
        fetcher.with_stored_signal(tx)
    } else {
        fetcher
    };
    (fetcher, rx)
}

/// The end of a hunt for a deep storer that went on after the push was
/// answered as stored (`ack_when_stored`): the chunk is held by the
/// storer that receipted it whatever this says, so a failure is only
/// logged (and fed to the batch's rejection memory, as any push is).
fn finish_hunt_in_background(
    outcome: Result<(), ant_retrieval::pushsync::PushSyncError>,
    rejected_batches: &RejectedBatches,
    stamp: &[u8; ant_postage::STAMP_SIZE],
    addr: &[u8; 32],
) {
    note_stamp_outcome(rejected_batches, stamp, outcome.as_ref().err());
    if let Err(e) = outcome {
        debug!(
            target: "ant_p2p",
            addr = %hex::encode(addr),
            err = %e,
            "push answered as stored; its hunt for a deeper storer ended without one",
        );
    }
}

/// Shared `PushChunk` tail: cache the chunk locally (store-then-push),
/// then pushsync it with `stamp` and ack. Used by both the local-issuer
/// and the presigned-stamp paths.
#[allow(clippy::too_many_arguments)]
fn push_with_stamp(
    state: &SwarmState,
    control: &Control,
    network_id: u64,
    addr: [u8; 32],
    wire: Vec<u8>,
    stamp: [u8; ant_postage::STAMP_SIZE],
    require_deep: bool,
    ack_when_stored: bool,
    ack: oneshot::Sender<ControlAck>,
) {
    let rejected_batches = state.rejected_batches.clone();
    let background_hunts = state.background_hunts.clone();
    let lag_until = rejection_lag_deadline(state, &stamp);
    let patience_peers = state.peers_watch.subscribe();
    if state.peers_watch.subscribe().borrow().is_empty() {
        let _ = ack.send(ControlAck::Error {
            message: "no peers available; wait for handshakes to complete".into(),
        });
        return;
    }
    // One credit-wait budget for the whole push, shared by all of
    // `push_with_patience`'s re-walks (issue #128): each walk waits only
    // for what is left of it, so the waits can't add up per walk.
    let fetcher = build_push_fetcher(state, control.clone(), network_id)
        .with_require_deep(require_deep)
        .with_credit_deadline(
            tokio::time::Instant::now() + ant_retrieval::accounting::CREDIT_WAIT_BUDGET,
        );
    // A strict push's answer is the deep receipt itself.
    let (fetcher, stored) = with_stored_signal(fetcher, ack_when_stored && !require_deep);
    let disk_cache = state.disk_cache.clone();
    let mem_cache = state.chunk_cache.clone();
    tokio::spawn(async move {
        // Land the chunk in our own local store *before* pushsync,
        // mirroring bee's store-then-push upload model. Without
        // this a node can't retrieve content it just uploaded:
        // the chunk only exists on whatever neighbourhood storer
        // accepted the push, and fresh content is not reliably
        // retrievable from the network for the first few seconds
        // (the gateway / AntDrive then "hits an unretrievable
        // chunk" and the read truncates). Keeping a local copy
        // makes our own uploads retrievable immediately and
        // survives a slow/partial network push.
        if let Some(mem) = &mem_cache {
            mem.put(addr, wire.clone());
        }
        if let Some(disk) = &disk_cache {
            if let Err(e) = disk.put(addr, wire.clone()).await {
                warn!(
                    target: "ant_p2p",
                    addr = %hex::encode(addr),
                    "failed to cache uploaded chunk locally: {e}",
                );
            }
        }
        // Nobody waiting for this push any more (the gateway request it
        // belongs to failed on another chunk, or its HTTP client gave
        // up): stop instead of spending peer credit, re-walks and paid
        // hedges on a chunk no one will use. Without this a segment that
        // failed once kept its other pushes going for up to the push
        // patience, competing with the segments after it.
        let mut ack = ack;
        let push = push_with_patience(
            &fetcher,
            patience_peers,
            addr,
            wire,
            stamp,
            false,
            lag_until,
        );
        tokio::pin!(push);
        let step = next_push_step(push.as_mut(), stored, &mut ack, true, &background_hunts).await;
        let outcome = match step {
            PushStep::Done(outcome) => outcome,
            PushStep::Stored(slot) => {
                let _ = ack.send(ControlAck::ChunkUploaded {
                    reference: format!("0x{}", hex::encode(addr)),
                });
                finish_hunt_in_background(push.await, &rejected_batches, &stamp, &addr);
                drop(slot);
                return;
            }
            PushStep::Abandoned => {
                debug!(
                    target: "ant_p2p",
                    addr = %hex::encode(addr),
                    "push abandoned: its requester went away",
                );
                return;
            }
        };
        let reply = match outcome {
            Ok(()) => {
                note_stamp_outcome(&rejected_batches, &stamp, None);
                ControlAck::ChunkUploaded {
                    reference: format!("0x{}", hex::encode(addr)),
                }
            }
            Err(e) => {
                note_stamp_outcome(&rejected_batches, &stamp, Some(&e));
                ControlAck::Error {
                    message: format!("pushsync: {e}"),
                }
            }
        };
        let _ = ack.send(reply);
    });
}

/// Shared `PushSoc` tail: cache the SOC (and its wrapped CAC) locally,
/// then pushsync with `stamp` and ack. Used by both the local-issuer
/// and the presigned-stamp paths.
#[allow(clippy::too_many_arguments)]
fn push_soc_with_stamp(
    state: &SwarmState,
    control: &Control,
    network_id: u64,
    address: [u8; 32],
    wire: Vec<u8>,
    stamp: [u8; ant_postage::STAMP_SIZE],
    ack_when_stored: bool,
    ack: oneshot::Sender<ControlAck>,
) {
    const SOC_HEADER: usize = 32 + 65;
    let rejected_batches = state.rejected_batches.clone();
    let background_hunts = state.background_hunts.clone();
    let lag_until = rejection_lag_deadline(state, &stamp);
    let patience_peers = state.peers_watch.subscribe();
    if state.peers_watch.subscribe().borrow().is_empty() {
        let _ = ack.send(ControlAck::NotReady {
            message: "no peers available; wait for handshakes to complete".into(),
        });
        return;
    }
    // One credit-wait budget for all re-walks, as in `push_with_stamp`.
    let fetcher = build_push_fetcher(state, control.clone(), network_id).with_credit_deadline(
        tokio::time::Instant::now() + ant_retrieval::accounting::CREDIT_WAIT_BUDGET,
    );
    let (fetcher, stored) = with_stored_signal(fetcher, ack_when_stored);
    let disk_cache = state.disk_cache.clone();
    let mem_cache = state.chunk_cache.clone();
    tokio::spawn(async move {
        // Keep a local copy of our own upload before pushsync, so
        // the node can serve the SOC it just stamped without
        // waiting for network propagation. See the matching note
        // in `push_with_stamp`.
        if let Some(mem) = &mem_cache {
            mem.put(address, wire.clone());
        }
        if let Some(disk) = &disk_cache {
            if let Err(e) = disk.put(address, wire.clone()).await {
                warn!(
                    target: "ant_p2p",
                    addr = %hex::encode(address),
                    "failed to cache uploaded soc locally: {e}",
                );
            }
        }
        // Also cache the wrapped CAC carried inside the SOC. The SOC
        // wire is `id(32) ‖ sig(65) ‖ span(8) ‖ payload`; everything
        // after the 97-byte header is a content-addressed chunk
        // (`span ‖ payload`). For a single-chunk (v2) feed update that
        // wrapped CAC *is* the content root the feed points at, and
        // bee-js never uploads it as a standalone chunk — so without
        // this a feed `latest` read (GetFeed resolves the SOC, then
        // GetBytes the resolved reference) can't serve our own write
        // until pushsync propagates, and read-after-own-write returns
        // `feed_empty`. Caching it under its own CAC address closes
        // that gap, mirroring the SOC cache above (content-addressed,
        // so it's a no-op-correct extra entry for non-feed SOCs too).
        let inner = &wire[SOC_HEADER..];
        if let Ok(inner_span) = <[u8; 8]>::try_from(&inner[..8]) {
            if let Some(inner_addr) = ant_crypto::bmt::bmt_hash_with_span(&inner_span, &inner[8..])
            {
                if let Some(mem) = &mem_cache {
                    mem.put(inner_addr, inner.to_vec());
                }
                if let Some(disk) = &disk_cache {
                    if let Err(e) = disk.put(inner_addr, inner.to_vec()).await {
                        warn!(
                            target: "ant_p2p",
                            addr = %hex::encode(inner_addr),
                            "failed to cache wrapped feed CAC locally: {e}",
                        );
                    }
                }
            }
        }
        // Fix B: SOCs run strict-receipt during the patience budget —
        // the walk hunts a DEEP placement (re-walking after deepening)
        // and only degrades to shallow-accept at the ceiling.
        let push = push_with_patience(
            &fetcher,
            patience_peers,
            address,
            wire,
            stamp,
            true,
            lag_until,
        );
        tokio::pin!(push);
        let mut ack = ack;
        let outcome =
            match next_push_step(push.as_mut(), stored, &mut ack, false, &background_hunts).await {
                PushStep::Done(outcome) => outcome,
                PushStep::Stored(slot) => {
                    let _ = ack.send(ControlAck::ChunkUploaded {
                        reference: format!("0x{}", hex::encode(address)),
                    });
                    finish_hunt_in_background(push.await, &rejected_batches, &stamp, &address);
                    drop(slot);
                    return;
                }
                PushStep::Abandoned => unreachable!("a SOC push is not abandonable"),
            };
        let reply = match outcome {
            Ok(()) => {
                note_stamp_outcome(&rejected_batches, &stamp, None);
                ControlAck::ChunkUploaded {
                    reference: format!("0x{}", hex::encode(address)),
                }
            }
            Err(e) => {
                note_stamp_outcome(&rejected_batches, &stamp, Some(&e));
                ControlAck::Error {
                    message: format!("pushsync: {e}"),
                }
            }
        };
        let _ = ack.send(reply);
    });
}

/// Traverse the content tree at `reference` and probe every chunk.
/// `false` on any traversal or fetch failure — bee's `IsRetrievable`
/// maps a not-found anywhere in the tree to `{"isRetrievable": false}`.
async fn stewardship_is_retrievable(
    fetcher: &ant_retrieval::RoutingFetcher,
    reference: [u8; 32],
) -> bool {
    let addrs = match ant_retrieval::traverse_chunk_addresses(
        fetcher,
        reference,
        STEWARDSHIP_MAX_FILE_BYTES,
    )
    .await
    {
        Ok(addrs) => addrs,
        Err(e) => {
            debug!(target: "ant_p2p", reference = %hex::encode(reference), "stewardship traversal failed: {e}");
            return false;
        }
    };
    // The traversal already proved interior/manifest nodes retrievable
    // (it had to fetch them — now cache-hot); this pass covers the data
    // leaves. Short-circuits on the first miss.
    futures::stream::iter(addrs)
        .map(|addr| async move { fetcher.fetch(addr).await.is_ok() })
        .buffer_unordered(STEWARDSHIP_CONCURRENCY)
        .all(|ok| async move { ok })
        .await
}

/// Answer `StampedChunk` from the registered issuers: the stamp the
/// batch's issuer recorded for `address`, `None` when it has no record,
/// an error for an unregistered batch or an issuer whose records could
/// not be read back (where a missing record proves nothing).
fn stamped_chunk_reply(
    issuers: &HashMap<[u8; 32], ant_postage::StampIssuer>,
    batch_id: [u8; 32],
    address: &[u8; 32],
) -> ControlAck {
    let Some(issuer) = issuers.get(&batch_id) else {
        return ControlAck::Error {
            message: format!("issuer does not exist: 0x{}", hex::encode(batch_id)),
        };
    };
    if let Some(stamp) = issuer.cached_stamp(address) {
        // A record found is a record, even if later records were lost.
        return ControlAck::StampedChunk { stamp: Some(stamp) };
    }
    if let Some(reason) = issuer.stamp_records_unavailable() {
        return ControlAck::Error {
            message: format!(
                "stamp records unavailable for batch 0x{}: {reason}",
                hex::encode(batch_id)
            ),
        };
    }
    ControlAck::StampedChunk { stamp: None }
}

/// Addresses counted per hold of the issuer lock in
/// [`count_tree_stamps_sliced`]. The lock is the one every stamping path
/// takes (uploads, `Envelope`, `PostageBuckets` on the node loop
/// itself), so one hold is kept to `16_384 × batches` hash lookups
/// (about a millisecond per batch) instead of the whole tree's: a
/// 16 GiB file is ~4.2 M chunks.
const STAMP_COUNT_SLICE: usize = 16_384;

/// How many times [`count_tree_stamps_sliced`] starts over because the
/// set of registered batches changed between two of its slices before it
/// gives up. Batches are registered or dropped on a buy, a chain sync or
/// an expiry, minutes apart, so one restart nearly always suffices.
const STAMP_COUNT_RESTARTS: usize = 3;

/// [`count_tree_stamps`] over `addrs` in slices of `slice`, releasing the
/// issuer lock and yielding between slices so stamping isn't held up by a
/// large tree. Every slice must see the same set of batches as the
/// first: a batch registered or dropped between slices would otherwise
/// be counted for only part of the tree (and its chunks read as
/// `unstamped` in the slices before it appeared), with no error. On such
/// a change the count starts over, up to [`STAMP_COUNT_RESTARTS`] times,
/// then fails rather than return a mixed view. Stamps issued between
/// slices on an unchanged batch set are counted where their slice sees
/// them, as with any read racing a concurrent upload.
async fn count_tree_stamps_sliced(
    issuers: &std::sync::Mutex<HashMap<[u8; 32], ant_postage::StampIssuer>>,
    addrs: &[[u8; 32]],
    slice: usize,
) -> Result<ant_control::StewardshipStampsView, String> {
    for _ in 0..=STAMP_COUNT_RESTARTS {
        if let Some(view) = count_tree_stamps_sliced_once(issuers, addrs, slice).await? {
            return Ok(view);
        }
    }
    Err(format!(
        "the set of postage batches kept changing during the count \
         ({} attempts); retry",
        STAMP_COUNT_RESTARTS + 1
    ))
}

/// One pass of [`count_tree_stamps_sliced`]: `Ok(None)` when the batch
/// set changed between slices.
async fn count_tree_stamps_sliced_once(
    issuers: &std::sync::Mutex<HashMap<[u8; 32], ant_postage::StampIssuer>>,
    addrs: &[[u8; 32]],
    slice: usize,
) -> Result<Option<ant_control::StewardshipStampsView>, String> {
    let mut total: Option<ant_control::StewardshipStampsView> = None;
    let mut parts = addrs.chunks(slice.max(1)).peekable();
    // An empty tree still lists the batches.
    let empty: [[u8; 32]; 0] = [];
    loop {
        let part = parts.next().unwrap_or(&empty);
        let view = {
            let guard = match issuers.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            count_tree_stamps(&guard, part)?
        };
        match &mut total {
            None => total = Some(view),
            Some(total) => {
                // Both lists are sorted by id, so equal ids pair up.
                if total.batches.len() != view.batches.len()
                    || total
                        .batches
                        .iter()
                        .zip(&view.batches)
                        .any(|(a, b)| a.batch_id != b.batch_id)
                {
                    return Ok(None);
                }
                total.chunks += view.chunks;
                total.unstamped += view.unstamped;
                for (a, b) in total.batches.iter_mut().zip(view.batches) {
                    a.chunks += b.chunks;
                }
            }
        }
        if parts.peek().is_none() {
            return Ok(total);
        }
        tokio::task::yield_now().await;
    }
}

/// Count, for every registered batch, how many of `addrs` its issuer's
/// records say it stamped, and how many no batch stamped. Batches come
/// out sorted by id, zero counts included, so the caller sees every
/// batch it could be relying on. Refuses (rather than undercounting)
/// when any issuer's records could not be read back.
fn count_tree_stamps(
    issuers: &HashMap<[u8; 32], ant_postage::StampIssuer>,
    addrs: &[[u8; 32]],
) -> Result<ant_control::StewardshipStampsView, String> {
    let mut ids: Vec<&[u8; 32]> = issuers.keys().collect();
    ids.sort();
    if let Some((id, reason)) = ids.iter().find_map(|id| {
        issuers[*id]
            .stamp_records_unavailable()
            .map(|reason| (*id, reason))
    }) {
        return Err(format!(
            "stamp records unavailable for batch 0x{}: {reason}",
            hex::encode(id)
        ));
    }
    let mut batches: Vec<ant_control::BatchChunkCount> = ids
        .iter()
        .map(|id| ant_control::BatchChunkCount {
            batch_id: **id,
            chunks: 0,
        })
        .collect();
    let mut unstamped = 0u64;
    for addr in addrs {
        let mut any = false;
        for row in &mut batches {
            if issuers[&row.batch_id].has_stamp(addr) {
                row.chunks += 1;
                any = true;
            }
        }
        if !any {
            unstamped += 1;
        }
    }
    Ok(ant_control::StewardshipStampsView {
        chunks: addrs.len() as u64,
        batches,
        unstamped,
    })
}

/// Traverse the content tree at `reference`, then fetch + stamp +
/// pushsync every chunk (bee's `steward.Reupload`). Fails on the first
/// chunk that can't be fetched or pushed.
async fn stewardship_reupload(
    read_fetcher: &ant_retrieval::RoutingFetcher,
    push_fetcher: &ant_retrieval::RoutingFetcher,
    upload: &Arc<UploadRuntime>,
    batch_id: [u8; 32],
    reference: [u8; 32],
) -> ControlAck {
    let addrs = match ant_retrieval::traverse_chunk_addresses(
        read_fetcher,
        reference,
        STEWARDSHIP_MAX_FILE_BYTES,
    )
    .await
    {
        Ok(addrs) => addrs,
        Err(e) => {
            return ControlAck::Error {
                message: format!("re-upload traversal failed: {e}"),
            };
        }
    };
    let total = addrs.len();
    let result: Result<(), String> = futures::stream::iter(addrs)
        .map(|addr| async move {
            let wire = read_fetcher
                .fetch(addr)
                .await
                .map_err(|e| format!("fetch {}: {e}", hex::encode(addr)))?;
            // Stamp under the issuer mutex like `PushChunk`; the
            // per-chunk stamp cache makes a re-upload of chunks this
            // node already stamped free of new bucket slots.
            let stamp = {
                let mut issuers = match upload.issuers.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let issuer = issuers
                    .get_mut(&batch_id)
                    .ok_or_else(|| format!("batch 0x{} not usable", hex::encode(batch_id)))?;
                ant_postage::sign_stamp_bytes(&upload.stamp_key, issuer, &addr)
                    .map_err(|e| format!("stamp issue failed: {e}"))?
            };
            push_fetcher
                .push_stamped_chunk(addr, wire, stamp)
                .await
                .map_err(|e| format!("pushsync {}: {e}", hex::encode(addr)))
        })
        .buffer_unordered(STEWARDSHIP_CONCURRENCY)
        .fold(Ok(()), |acc, item| async move { acc.and(item) })
        .await;
    match result {
        Ok(()) => ControlAck::Ok {
            message: format!("re-uploaded {total} chunks"),
        },
        Err(message) => ControlAck::Error { message },
    }
}

fn handle_put_chunk_local(state: &mut SwarmState, wire: Vec<u8>, ack: oneshot::Sender<ControlAck>) {
    let Some(disk_cache) = state.disk_cache.clone() else {
        let _ = ack.send(ControlAck::Error {
            message: "disk chunk cache disabled; pass --disk-cache-bytes > 0 at startup".into(),
        });
        return;
    };
    if wire.len() < 8 || wire.len() > 8 + ant_crypto::CHUNK_SIZE {
        let _ = ack.send(ControlAck::Error {
            message: format!("chunk wire size out of range: {} bytes", wire.len()),
        });
        return;
    }
    let mut span = [0u8; 8];
    span.copy_from_slice(&wire[..8]);
    let payload = &wire[8..];
    let Some(addr) = ant_crypto::bmt::bmt_hash_with_span(&span, payload) else {
        let _ = ack.send(ControlAck::Error {
            message: "failed to BMT-hash chunk".into(),
        });
        return;
    };
    tokio::spawn(async move {
        let reply = match disk_cache.put(addr, wire).await {
            Ok(()) => ControlAck::Ok {
                message: format!("0x{}", hex::encode(addr)),
            },
            Err(e) => ControlAck::Error {
                message: format!("disk cache write failed: {e}"),
            },
        };
        let _ = ack.send(reply);
    });
}

#[allow(clippy::too_many_arguments)]
async fn run_stream_bytes(
    control: Control,
    peers_rx: watch::Receiver<Vec<(libp2p::PeerId, [u8; 32])>>,
    cache: Arc<ant_retrieval::InMemoryChunkCache>,
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    inflight_limit: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    counters: Arc<RetrievalCounters>,
    tracker: Arc<ProgressTracker>,
    reference: [u8; 32],
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    head_only: bool,
    ack: mpsc::Sender<ControlAck>,
) {
    let mut builder = ant_retrieval::RoutingFetcher::new(control, peers_rx.clone())
        .with_cache(cache)
        .with_record_dir(record_dir)
        .with_progress(tracker.clone())
        .with_inflight_limit(inflight_limit)
        .with_counters(counters)
        .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP);
    if let Some(disk) = disk_cache {
        builder = builder.with_disk_cache(disk);
    }
    if let Some(tx) = payment_notify {
        builder = builder.with_payment_notify(tx);
    }
    if let Some(acc) = accounting {
        builder = builder.with_accounting(acc);
    }
    let fetcher = builder;

    // Root fetch with dispersed-replica fallback: files uploaded with a
    // swarm-redundancy-level carry 2^level SOC replicas of their root at
    // addresses derivable from the root address alone.
    //
    // Retried within `RESOLUTION_RETRY_BUDGET`, like `/bzz`'s
    // pre-stream phase, so a `/bytes` request that lands while the
    // peer pool is still cold doesn't answer a fast 502 (issue #117).
    // A peer set that is empty *at dispatch* never gets here: the
    // `ControlCommand::StreamBytes` arm answers `no peers available` at
    // once, as `/bzz` does. The empty-set branch below covers a pool
    // that empties after dispatch (its only peer just dropped): `/bytes`
    // waits that out and only then reports `no peers available`. A
    // miss more than a couple of peers confirmed (`is_final_miss`) is
    // final and 404s at once. A miss only one or two peers answered (a
    // cold node with a thin peer table) is *not* final: it is retried
    // with fresh peer snapshots and only answers the 404 when the loop
    // gives up — after `MAX_FETCH_ATTEMPTS` attempts or the
    // `RESOLUTION_RETRY_BUDGET`, whichever comes first (the linear
    // backoff alone is ~22 s over ten attempts). So on such a node a
    // missing reference takes up to ~30 s to 404, not the sub-second
    // answer it got before R1-M2 on PR #124; that is intended, since
    // one or two cold peers' miss is not the network's answer.
    //
    // The direct root fetch waits for peer credit, but never past the
    // resolution budget (`credit_window`), so the attempts' waits can't
    // stack (issue #117).
    let resolution_started = Instant::now();
    let credit_window = ant_retrieval::accounting::CreditWindow::new(RESOLUTION_RETRY_BUDGET);
    let mut attempt = 0usize;
    let root = loop {
        attempt += 1;
        let failure = if peers_rx.borrow().is_empty() {
            None
        } else {
            match ant_retrieval::fetch_root_with_replicas(
                &fetcher,
                reference,
                credit_window.budget(),
            )
            .await
            {
                Ok(root) => break root,
                Err(e) => Some(e),
            }
        };
        let retry = failure
            .as_ref()
            .is_none_or(|e| is_bytes_root_transient(e.as_ref()))
            && attempt < MAX_FETCH_ATTEMPTS
            && resolution_started.elapsed() < RESOLUTION_RETRY_BUDGET;
        let message = failure.as_ref().map_or_else(
            || "no peers available; wait for handshakes to complete".to_string(),
            |e| format!("fetch root chunk {}: {e}", hex::encode(reference)),
        );
        if !retry {
            let terminal = match failure {
                Some(e) => pre_stream_failure_ack(message, e.as_ref()),
                None => ControlAck::Error { message },
            };
            let _ = ack.send(terminal).await;
            return;
        }
        let backoff = RETRY_BACKOFF_BASE * attempt as u32;
        warn!(
            target: "ant_p2p",
            attempt,
            next_in_ms = backoff.as_millis() as u64,
            "stream_bytes root fetch failed, retrying: {message}",
        );
        tokio::time::sleep(backoff).await;
    };
    // Mask the RS level byte off the span before reporting
    // `total_bytes` so the gateway's `Content-Length` reflects the real
    // file size; the joiner itself decodes the level per node and
    // recovers missing data chunks from parities.
    let Some(total_bytes) = root_span_to_u64_masked(&root) else {
        let _ = ack
            .send(ControlAck::Error {
                message: format!("root chunk {} shorter than span", hex::encode(reference)),
            })
            .await;
        return;
    };
    tracker.set_total_bytes(total_bytes);
    if ack
        .send(ControlAck::BytesStreamStart { total_bytes })
        .await
        .is_err()
    {
        return;
    }

    if head_only {
        let _ = ack.send(ControlAck::StreamDone).await;
        return;
    }

    stream_root_chunk_with_range(
        &fetcher,
        root,
        total_bytes,
        max_bytes,
        range,
        reference,
        ack,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_stream_bzz(
    control: Control,
    peers_rx: watch::Receiver<Vec<(libp2p::PeerId, [u8; 32])>>,
    cache: Arc<ant_retrieval::InMemoryChunkCache>,
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    inflight_limit: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    counters: Arc<RetrievalCounters>,
    feed_hints: ant_retrieval::FeedHints,
    tracker: Arc<ProgressTracker>,
    reference: Vec<u8>,
    path: String,
    allow_degraded_redundancy: bool,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    head_only: bool,
    ack: mpsc::Sender<ControlAck>,
) {
    use ant_retrieval::{lookup_path_with_credit, ManifestError};

    // Reuse the same retry envelope as `run_get_bzz` for the manifest
    // walk. Once the data root has landed and we've emitted
    // `BzzStreamStart`, we cannot restart the response — `join_to_sender`
    // (and its range-aware sibling) handle in-place subtree retries
    // themselves, so the consumer sees a continuous stream.
    let mut last_error = None;
    let resolution_started = Instant::now();
    // The bare-root and data-root fetches wait for peer credit, but never
    // past the resolution budget, so the attempts' waits can't stack
    // (issue #117). So do the manifest walk's node loads (issue #130) and
    // a bare root's raw-bytes sniff fetches (issue #122), one at a time,
    // from the same window. Feed probes, and the fallback join of a
    // multi-chunk node, never wait.
    let credit_window = ant_retrieval::accounting::CreditWindow::new(RESOLUTION_RETRY_BUDGET);
    // One replica-sweep memo across all attempts: a manifest node whose
    // direct fetch fails is swept for dispersed replicas (#154) at most
    // once per attempt, however many times the directory-redirect check
    // and index-document retry load it, and never again in this request
    // once a sweep confirms its replicas missing. A sweep that failed
    // transiently (starved pool, uncorroborated miss) is retried on the
    // next attempt, like the direct fetch: a replica-only node is
    // reachable through nothing else (R2-F1 on PR #155). Such a sweep
    // keeps the request retrying even when the node's direct miss is
    // corroborated, which every replica-only node's is
    // (`is_bzz_lookup_retryable`, R3-M1 on PR #155), and, once retries
    // run out, ends it in a 503 rather than the direct miss's 404
    // (`bzz_lookup_failure_ack`, R4-M1 on PR #155).
    let replica_sweeps = ant_retrieval::ReplicaSweeps::new();
    let bare_root = is_bare_root_path(&path);
    for attempt in 1..=MAX_FETCH_ATTEMPTS {
        replica_sweeps.next_attempt();
        if peers_rx.borrow().is_empty() {
            let _ = ack
                .send(ControlAck::Error {
                    message: "no peers available; wait for handshakes to complete".to_string(),
                })
                .await;
            return;
        }
        let mut builder = ant_retrieval::RoutingFetcher::new(control.clone(), peers_rx.clone())
            .with_cache(cache.clone())
            .with_record_dir(record_dir.clone())
            .with_progress(tracker.clone())
            .with_inflight_limit(inflight_limit.clone())
            .with_counters(counters.clone())
            .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP);
        if let Some(disk) = disk_cache.clone() {
            builder = builder.with_disk_cache(disk);
        }
        if let Some(tx) = payment_notify.clone() {
            builder = builder.with_payment_notify(tx);
        }
        if let Some(acc) = accounting.clone() {
            builder = builder.with_accounting(acc);
        }
        let fetcher = builder;

        // Bare `/bzz/<ref>/` may name raw bytes (#112), so its root gets
        // the same dispersed-replica fallback `/bytes` gives it before
        // the manifest walk; the walk then reads the root from the
        // request cache. Its root → leftmost-leaf sniff waits for credit
        // too (#122), so a raw ref is recognised and streamed like
        // `/bytes` instead of falling into the sniff's full, non-waiting
        // fallback join on a starved pool. Every request's walk loads its
        // nodes waiting for credit (#130), so a site lookup queues for
        // credit behind concurrent body fetches instead of failing and
        // backing off.
        let looked_up = match (bare_root, <[u8; 32]>::try_from(reference.as_slice())) {
            (true, Ok(root)) => match ant_retrieval::fetch_root_with_replicas(
                &fetcher,
                root,
                credit_window.budget(),
            )
            .await
            {
                Ok(_) => {
                    lookup_path_with_credit(
                        &fetcher,
                        &reference,
                        &path,
                        &credit_window,
                        &replica_sweeps,
                        Some(&feed_hints),
                    )
                    .await
                }
                Err(source) => Err(ManifestError::Fetch(ant_retrieval::JoinError::FetchChunk {
                    addr: hex::encode(root),
                    source,
                })),
            },
            _ => {
                lookup_path_with_credit(
                    &fetcher,
                    &reference,
                    &path,
                    &credit_window,
                    &replica_sweeps,
                    Some(&feed_hints),
                )
                .await
            }
        };
        let lookup = match looked_up {
            Ok(r) => r,
            Err(ManifestError::NotAManifest) => {
                if let Some(raw) = raw_bytes_lookup(&reference, &path) {
                    raw
                } else {
                    let _ = ack
                        .send(ControlAck::Error {
                            message: path_below_raw_bytes_message(&reference, &path),
                        })
                        .await;
                    return;
                }
            }
            Err(e)
                if is_bzz_lookup_retryable(&e, bare_root, &replica_sweeps)
                    && attempt < MAX_FETCH_ATTEMPTS
                    && resolution_started.elapsed() < RESOLUTION_RETRY_BUDGET =>
            {
                last_error = Some(format!("manifest lookup '{path}': {e}"));
                let backoff = RETRY_BACKOFF_BASE * attempt as u32;
                warn!(
                    target: "ant_p2p",
                    attempt,
                    next_in_ms = backoff.as_millis() as u64,
                    "stream_bzz manifest lookup failed, retrying: {e}",
                );
                tokio::time::sleep(backoff).await;
                continue;
            }
            Err(e) => {
                let _ = ack
                    .send(bzz_lookup_failure_ack(
                        format!("manifest lookup '{path}': {e}"),
                        &e,
                        replica_sweeps.swept_transiently(&e),
                    ))
                    .await;
                return;
            }
        };

        debug!(
            target: "ant_p2p",
            manifest = %hex::encode(&reference),
            path = %path,
            data_ref = %hex::encode(&lookup.data_ref),
            content_type = ?lookup.content_type,
            "stream_bzz manifest resolved",
        );

        // Encrypted manifest entry (64-byte `address ‖ key`): the body
        // can't be streamed chunkwise (each chunk needs its parent's
        // key), so decrypt-join buffered and emit the same stream shape
        // from memory — mirroring the gateway's encrypted-feed path.
        if let Ok(enc_ref) =
            <[u8; ant_retrieval::ENCRYPTED_REF_SIZE]>::try_from(lookup.data_ref.as_slice())
        {
            let filename = lookup
                .metadata
                .get("Filename")
                .cloned()
                .or_else(|| derive_filename_from_path(&path));
            stream_encrypted_body(
                &fetcher,
                enc_ref,
                lookup.content_type.clone(),
                filename,
                bzz_feed(lookup.feed),
                max_bytes,
                range,
                head_only,
                ack,
            )
            .await;
            return;
        }
        let Ok(data_ref) = <[u8; 32]>::try_from(lookup.data_ref.as_slice()) else {
            let _ = ack
                .send(ControlAck::Error {
                    message: "manifest entry has invalid width".to_string(),
                })
                .await;
            return;
        };

        // Data-root fetch with dispersed-replica fallback (see
        // `run_stream_bytes`).
        let root = match ant_retrieval::fetch_root_with_replicas(
            &fetcher,
            data_ref,
            credit_window.budget(),
        )
        .await
        {
            Ok(r) => r,
            Err(e)
                if is_bytes_root_transient(e.as_ref())
                    && attempt < MAX_FETCH_ATTEMPTS
                    && resolution_started.elapsed() < RESOLUTION_RETRY_BUDGET =>
            {
                last_error = Some(format!("fetch data root {}: {e}", hex::encode(data_ref)));
                let backoff = RETRY_BACKOFF_BASE * attempt as u32;
                warn!(
                    target: "ant_p2p",
                    attempt,
                    next_in_ms = backoff.as_millis() as u64,
                    "stream_bzz data root fetch failed, retrying: {e}",
                );
                tokio::time::sleep(backoff).await;
                continue;
            }
            Err(e) => {
                let message = format!("fetch data root {}: {e}", hex::encode(data_ref));
                let _ = ack.send(pre_stream_failure_ack(message, e.as_ref())).await;
                return;
            }
        };

        let Some(total_bytes) = root_span_to_u64_masked(&root) else {
            let _ = ack
                .send(ControlAck::Error {
                    message: format!("data root {} shorter than span", hex::encode(data_ref)),
                })
                .await;
            return;
        };
        tracker.set_total_bytes(total_bytes);

        let filename = lookup
            .metadata
            .get("Filename")
            .cloned()
            .or_else(|| derive_filename_from_path(&path));
        if ack
            .send(ControlAck::BzzStreamStart {
                total_bytes,
                reference: data_ref.to_vec(),
                content_type: lookup.content_type,
                filename,
                feed: bzz_feed(lookup.feed),
            })
            .await
            .is_err()
        {
            return;
        }

        if head_only {
            let _ = ack.send(ControlAck::StreamDone).await;
            return;
        }

        // Once `BzzStreamStart` has been emitted we own the stream;
        // any further failure terminates with `Error` on the same
        // body channel. The joiner already wraps each subtree in its
        // own retry loop, so transient chunk misses don't leak out.
        let join_options = ant_retrieval::JoinOptions {
            allow_degraded_redundancy,
        };
        stream_root_chunk_inner(
            &fetcher,
            root,
            total_bytes,
            max_bytes,
            range,
            data_ref,
            join_options,
            ack,
        )
        .await;
        return;
    }
    let _ = ack
        .send(ControlAck::Error {
            message: last_error.unwrap_or_else(|| "stream_bzz exhausted retries".to_string()),
        })
        .await;
}

/// Serve an **encrypted** bzz body (64-byte `address ‖ key` data
/// reference) over the streaming ack protocol. Encrypted trees can't be
/// streamed chunkwise — every chunk's key arrives with its parent — so
/// the body is decrypt-joined into memory (bounded by `max_bytes`) and
/// emitted as one `BytesChunk`, with any range applied by slicing.
/// `HEAD` requests only decrypt the root chunk's span.
#[allow(clippy::too_many_arguments)]
async fn stream_encrypted_body(
    fetcher: &ant_retrieval::RoutingFetcher,
    enc_ref: [u8; ant_retrieval::ENCRYPTED_REF_SIZE],
    content_type: Option<String>,
    filename: Option<String>,
    feed: Option<ant_control::BzzFeed>,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    head_only: bool,
    ack: mpsc::Sender<ControlAck>,
) {
    let addr: [u8; 32] = enc_ref[..32].try_into().expect("64-byte ref");
    let key: [u8; 32] = enc_ref[32..].try_into().expect("64-byte ref");

    // Total size from the (decrypted) root span — needed for the stream
    // prologue and for HEAD without joining the whole tree. The root
    // fetch falls back to the root's dispersed replicas (keyed on the
    // 32-byte address half; the replica wraps the *encrypted* root
    // chunk), like the buffered `join_encrypted` path.
    let root_wire =
        match ant_retrieval::fetch_root_with_replicas(fetcher, addr, Duration::ZERO).await {
            Ok(w) => w,
            Err(e) => {
                let _ = ack
                    .send(ControlAck::Error {
                        message: format!("fetch encrypted data root {}: {e}", hex::encode(addr)),
                    })
                    .await;
                return;
            }
        };
    let total_bytes = match ant_crypto::decrypt_chunk_parts(&root_wire, &key) {
        Ok((span, _)) => {
            let (_, plain) = ant_retrieval::rs::decode_span(span);
            u64::from_le_bytes(plain)
        }
        Err(e) => {
            let _ = ack
                .send(ControlAck::Error {
                    message: format!("decrypt data root {}: {e}", hex::encode(addr)),
                })
                .await;
            return;
        }
    };

    if ack
        .send(ControlAck::BzzStreamStart {
            total_bytes,
            reference: enc_ref.to_vec(),
            content_type,
            filename,
            feed,
        })
        .await
        .is_err()
    {
        return;
    }
    if head_only {
        let _ = ack.send(ControlAck::StreamDone).await;
        return;
    }

    let body_range =
        range.and_then(|r| ant_retrieval::ByteRange::clamp(r.start, r.end_inclusive, total_bytes));
    if range.is_some() && body_range.is_none() {
        let _ = ack
            .send(ControlAck::Error {
                message: "range not satisfiable for resource".to_string(),
            })
            .await;
        return;
    }

    let cap = clamp_max_bytes(max_bytes);
    let body = match ant_retrieval::join_encrypted(fetcher, enc_ref, cap).await {
        Ok(b) => b,
        Err(e) => {
            // `BzzStreamStart` is already out, so this fails a `200`.
            warn!(
                target: "ant_p2p",
                reference = %hex::encode(addr),
                "encrypted join failed after stream start, response truncated: {e}",
            );
            let _ = ack
                .send(ControlAck::Error {
                    message: format!("join encrypted {}: {e}", hex::encode(enc_ref)),
                })
                .await;
            return;
        }
    };
    let data = match body_range {
        Some(r) => {
            let start = usize::try_from(r.start)
                .unwrap_or(usize::MAX)
                .min(body.len());
            let end = usize::try_from(r.end_inclusive)
                .unwrap_or(usize::MAX)
                .saturating_add(1)
                .min(body.len());
            body[start..end].to_vec()
        }
        None => body,
    };
    if !data.is_empty() && ack.send(ControlAck::BytesChunk { data }).await.is_err() {
        return;
    }
    let _ = ack.send(ControlAck::StreamDone).await;
}

/// Drive a streaming joiner from an already-fetched root chunk and emit
/// `BytesChunk` acks until completion. Used by both `StreamBytes` (which
/// has already sent its `BytesStreamStart`) and `StreamBzz` (which has
/// already sent its `BzzStreamStart`).
async fn stream_root_chunk_with_range(
    fetcher: &ant_retrieval::RoutingFetcher,
    root: Vec<u8>,
    total_bytes: u64,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    reference: [u8; 32],
    ack: mpsc::Sender<ControlAck>,
) {
    stream_root_chunk_inner(
        fetcher,
        root,
        total_bytes,
        max_bytes,
        range,
        reference,
        ant_retrieval::JoinOptions::default(),
        ack,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn stream_root_chunk_inner(
    fetcher: &ant_retrieval::RoutingFetcher,
    root: Vec<u8>,
    total_bytes: u64,
    max_bytes: Option<u64>,
    range: Option<StreamRange>,
    reference: [u8; 32],
    options: ant_retrieval::JoinOptions,
    ack: mpsc::Sender<ControlAck>,
) {
    // 64 × ~4 KiB ≈ 256 KiB of decoded body buffered between the
    // joiner and the control reply pump. This matches bee's small-file
    // lookahead window (`langos` with `smallFileBufferSize` = 8 ×
    // 32 KiB) so a slow-draining HTTP consumer doesn't immediately
    // back-pressure into the joiner's per-child pipes. Combined with
    // the joiner's `STREAM_PIPE_DEPTH` per-child buffers, a healthy
    // download keeps roughly 2-3 MiB of decoded body ahead of the
    // gateway at any given moment.
    let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(64);
    let cap = clamp_max_bytes(max_bytes);
    let body_range =
        range.and_then(|r| ant_retrieval::ByteRange::clamp(r.start, r.end_inclusive, total_bytes));
    if range.is_some() && body_range.is_none() {
        let _ = ack
            .send(ControlAck::Error {
                message: "range not satisfiable for resource".to_string(),
            })
            .await;
        return;
    }
    let mut join_fut = Box::pin(ant_retrieval::join_to_sender_range(
        fetcher, &root, cap, options, body_range, chunk_tx,
    ));
    let mut join_result = None;
    loop {
        tokio::select! {
            result = &mut join_fut, if join_result.is_none() => {
                join_result = Some(result);
            }
            maybe_chunk = chunk_rx.recv() => {
                if let Some(data) = maybe_chunk {
                    if ack.send(ControlAck::BytesChunk { data }).await.is_err() {
                        return;
                    }
                } else {
                    match join_result.unwrap_or(Ok(())) {
                        Ok(()) => {
                            let _ = ack.send(ControlAck::StreamDone).await;
                        }
                        Err(e) => {
                            // The stream-start ack (and the gateway's
                            // `200` + Content-Length) went out before the
                            // join began, so this error truncates the
                            // body. The client only sees a short read;
                            // make it visible here (issue #114).
                            warn!(
                                target: "ant_p2p",
                                reference = %hex::encode(reference),
                                "streaming join failed mid-body, response truncated: {e}",
                            );
                            let _ = ack
                                .send(ControlAck::Error {
                                    message: format!("join {}: {e}", hex::encode(reference)),
                                })
                                .await;
                        }
                    }
                    return;
                }
            }
        }
    }
}

/// Run a retrieval task for a control client until it finishes or the
/// client goes away, whichever comes first; `None` means the client left.
///
/// The gateway reads a request's acks from the receiving end of `ack` and
/// drops it when the HTTP client disconnects, e.g. a video player that
/// seeks away from a segment it was loading. The task only learned that
/// on its next `ack.send`, which for a stream is its next in-order chunk:
/// a head chunk waiting for credit or a retry could put that seconds away,
/// and until then the look-ahead kept fetching, and debiting, chunks nobody
/// would read, in competition with the requests that replaced it. Racing
/// the task against `ack.closed()` drops it at the disconnect. Everything
/// it owns is cancel-safe (the joiner's fetches, credit waits and permit
/// waits); retrievals already on the wire still drain on their own, so the
/// debit for chunks peers are already sending is applied as before.
async fn unless_client_gone<T>(
    ack: &mpsc::Sender<ControlAck>,
    task: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        out = task => Some(out),
        () = ack.closed() => {
            debug!(target: "ant_p2p", "control client went away; dropping its retrieval");
            None
        }
    }
}

/// How often the progress emitter wakes up and pushes a sample over
/// the ack channel. 150 ms is fast enough to drive a smoothly-updating
/// stderr status line on the client without flooding the wire (or
/// blocking the joiner on a stalled writer).
const PROGRESS_TICK: Duration = Duration::from_millis(150);

/// Convert a tracker snapshot + the request's start instant into the
/// wire-shape `GetProgress`. The tracker itself doesn't track
/// elapsed time (it's a pure counter struct), so we mix it in here.
fn build_progress(tracker: &ProgressTracker, started: Instant) -> GetProgress {
    let sample = tracker.snapshot();
    GetProgress {
        elapsed_ms: started.elapsed().as_millis() as u64,
        chunks_done: sample.chunks_done,
        total_chunks_estimate: sample.total_chunks_estimate,
        bytes_done: sample.bytes_done,
        total_bytes_estimate: sample.total_bytes_estimate,
        cache_hits: sample.cache_hits,
        peers_used: sample.peers_used,
        bypass_cache: sample.bypass_cache,
        in_flight: sample.in_flight,
    }
}

/// Spawn a background ticker that emits one `ControlAck::Progress`
/// per `PROGRESS_TICK` until either the ack channel closes (the
/// connection went away) or the parent task aborts the handle. The
/// emitter exits on the first failed send so a disconnected client
/// doesn't keep us spinning forever.
fn spawn_progress_emitter(
    tracker: Arc<ProgressTracker>,
    ack: mpsc::Sender<ControlAck>,
    started: Instant,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PROGRESS_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first fire — counters are all zero so
        // there's nothing useful to send before the first chunk lands.
        interval.tick().await;
        loop {
            interval.tick().await;
            let progress = build_progress(&tracker, started);
            if ack.send(ControlAck::Progress(progress)).await.is_err() {
                return;
            }
        }
    })
}

/// Best-effort terminal ack send for the rare cases where we know
/// we're going to error out before spawning the worker task (e.g.
/// no peers available). The mpsc channel was minted with capacity
/// 16 so this never actually blocks; spawning a tiny task keeps
/// `handle_control_command` itself synchronous.
fn send_terminal_ack(ack: &mpsc::Sender<ControlAck>, reply: ControlAck) {
    let ack = ack.clone();
    tokio::spawn(async move {
        let _ = ack.send(reply).await;
    });
}

/// Max number of full pipeline attempts (`lookup_path` + fetch + join)
/// per user-visible `get` command. Successful chunks are written through
/// to the daemon cache, so later attempts usually skip straight to the
/// sparse tail chunks that still need a working peer. Live gateway
/// verification against four concurrent 44 MiB WAVs still saw late
/// single-chunk misses after five attempts; ten attempts gives those
/// tail chunks more peer-set churn windows without re-downloading the
/// already joined prefix.
const MAX_FETCH_ATTEMPTS: usize = 10;

/// Wall-clock ceiling on **retrying a failed manifest/feed resolution**
/// (the `/bzz/{ref}/` pre-stream phase: manifest chunk → mantaray walk →
/// feed latest-lookup → data-root chunk). `MAX_FETCH_ATTEMPTS` alone
/// bounds the *count* of retries but not their *duration*: a single
/// attempt can spend ~30 s hedging across an unhelpful peer set, so ten
/// attempts plus back-off could hold an HTTP request open for minutes —
/// e.g. an SPA polling a feed every 5 s would see the tab spin forever
/// instead of getting a prompt error it can retry. This caps that
/// pre-stream phase so the gateway returns a `502`/`504` quickly and the
/// client can degrade gracefully. It does **not** bound content
/// streaming: once `BzzStreamStart` is emitted the resolution loop has
/// already returned, and the joiner does its own in-place subtree retries
/// for the body. Generous enough (vs. a healthy sub-second resolution)
/// that it only trips on a genuinely unreachable chunk.
const RESOLUTION_RETRY_BUDGET: Duration = Duration::from_secs(30);

/// How long a buffered `GetBytes` / `GetBzz` request (`antctl get`, FFI
/// `ant_get`) may wait for peer credit in total, across all its
/// whole-join attempts (`RoutingFetcher::with_credit_deadline`). After
/// it, a starved fetch fails at once as it did before issue #117.
const BUFFERED_REQUEST_CREDIT_WINDOW: Duration = RESOLUTION_RETRY_BUDGET;

/// Process-wide cap on concurrent `retrieve_chunk` calls (see
/// `SwarmState::retrieval_inflight`). Bee's retrieval has no
/// equivalent — it spawns one goroutine per chunk fetch and lets the
/// Go runtime sort it out. We keep a soft cap so a stuck network
/// can't chew through unbounded yamux streams; 256 is well above
/// what 4–8 concurrent media downloads ever drive at once but caps
/// pathological loops. The per-request cap is what does the actual
/// fairness work between requests.
const RETRIEVAL_INFLIGHT_CAP: usize = 256;

/// Per-user-request cap layered in front of the process-wide semaphore.
/// Sized to roughly match bee's effective chunk-level parallelism for
/// a single file (one langos lookahead window of ~256 KiB ≈ 64 chunks)
/// while keeping per-peer chunk rate inside the headroom that the
/// pseudosettle driver can clear. Going higher (e.g. 128) makes a
/// fresh peer set drain faster on a single file but punches through
/// the per-peer debt allowance for sustained multi-file streaming —
/// the hottest peers see ≥10× their share when chunk addresses cluster
/// around a small neighbourhood, and the pseudosettle refresh budget
/// per peer (`450k units/s × MIN_REFRESH_INTERVAL` = 900k units / 2 s)
/// caps the steady-state per-peer fetch rate at ~12 chunks / 2 s.
/// The chunks at the head of a streaming download's window skip this
/// cap (issue #46, `ant_retrieval::priority`), so a large file's
/// look-ahead can't queue the chunk its consumer is waiting for.
const RETRIEVAL_REQUEST_INFLIGHT_CAP: usize = 64;

/// Multiplier base for inter-attempt backoff. Attempt N waits
/// `RETRY_BACKOFF_BASE * N` before retrying — small enough not to
/// noticeably stretch the user's wait, large enough that we don't
/// re-flood the same overloaded forwarders the moment they shed us.
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Should a failed `/bytes` root fetch (`run_stream_bytes`, and `/bzz`'s
/// data root) be retried? Yes unless the miss is final
/// ([`is_final_miss`]): an empty or overdraft-starved pool (`no BZZ
/// peers available`, a starved `not found` tail), timeouts, dropped
/// streams and a cold node's one or two `not found` answers can all
/// clear up within the resolution budget, a real miss can't (issues
/// #117, #123). Errors from other fetchers fall back to the message
/// ([`ant_retrieval::rs::shard_confirmed_missing`]).
fn is_bytes_root_transient(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    match ant_retrieval::fetcher::FetchExhausted::find(e) {
        Some(x) => !x.corroborated_missing(),
        None => !ant_retrieval::rs::shard_confirmed_missing(e),
    }
}

/// Did the fetcher behind `e` (found through any wrapping, e.g. a
/// manifest walk's `ManifestError::Fetch`) end with more than a couple
/// of peers confirming the chunk missing
/// ([`ant_retrieval::fetcher::FetchExhausted::corroborated_missing`])?
/// Such a miss is final: no retry within the resolution budget will
/// change the network's answer. A merely confirmed miss — every ranked
/// peer asked, but only one or two of them, as on a node that has just
/// started — is retried with fresh peer snapshots, and only reported
/// (as a 404, [`pre_stream_failure_ack`]) once the budget runs out
/// (R1-M2 on PR #124).
fn is_final_miss(e: &(dyn std::error::Error + 'static)) -> bool {
    ant_retrieval::fetcher::FetchExhausted::find(e)
        .is_some_and(ant_retrieval::fetcher::FetchExhausted::corroborated_missing)
}

/// Terminal ack for a `/bytes` or `/bzz` retrieval that failed before
/// its stream started, or for a single-chunk `GetChunkRaw` read (issue
/// #146), typed off the fetcher's error behind `e` rather than its
/// message (issue #123):
///
/// - peers confirmed the chunk missing → [`ControlAck::NotFound`], which
///   the gateway answers with bee's 404. That includes a fetch whose
///   last answer was `no peer found`, which used to fall through to a
///   502 that Freedom retries for ~50 s;
/// - the last answer was a miss but the peer pool was starved →
///   [`ControlAck::NotReady`] (503): one cold peer's "not found" is not
///   the network's answer (#114), so it must not read as a 404 either.
///   `GetChunkRaw` never reaches this arm: its fetcher has no accounting
///   attached, so no peer is overdraft-skipped and the pool is never
///   reported starved;
/// - anything else → [`ControlAck::Error`], as before.
fn pre_stream_failure_ack(message: String, e: &(dyn std::error::Error + 'static)) -> ControlAck {
    match ant_retrieval::fetcher::FetchExhausted::find(e) {
        Some(x) if x.confirmed_missing() => ControlAck::NotFound { message },
        Some(x) if x.last_not_found => ControlAck::NotReady { message },
        _ => ControlAck::Error { message },
    }
}

/// One pipeline attempt's outcome on failure. `Transient` failures
/// (chunk fetch errors from peer / network flakes) should trigger a
/// retry; `Permanent` failures (corrupt data, "not a manifest", path
/// not found, file-too-large, …) won't get better with another try
/// and surface to the user immediately.
enum AttemptError {
    Transient(String),
    Permanent(String),
}

/// Did this `JoinError` come from a chunk-fetch failure? The other
/// variants (oversize span, malformed intermediate, RS / encryption)
/// describe data-shape problems that would re-fail identically on a
/// retry, so we mark them permanent.
const fn is_join_transient(e: &ant_retrieval::JoinError) -> bool {
    matches!(e, ant_retrieval::JoinError::FetchChunk { .. })
}

/// The terminal ack for a `GetFeed` lookup's result.
///
/// Only a miss the network corroborated is an empty feed
/// ([`ControlAck::FeedNotFound`], bee's `404 "no update found"`). A cold
/// node's one or two peers answer `no peer found` for an index that may
/// well exist, so an uncorroborated anchor miss is
/// [`ControlAck::NotReady`], a 503 to retry: a host that reads the 404
/// as "empty" starts writing at index 0 over the feed (the live
/// publisher's head read, issue #173). An exact read's head whose next
/// slot isn't confirmed empty ([`ant_retrieval::FeedError::EndUnconfirmed`])
/// is a `NotReady` too: the head may be below the real one.
///
/// Corroborating takes more than two peers' "not found", so a node with
/// at most two peers can't tell a brand-new feed is empty, or that the
/// slot after a head is: every such read stays a 503 until it has three
/// or more (the iOS app gates **Go Live** on that).
#[must_use]
pub fn feed_lookup_ack(
    result: Result<ant_retrieval::FeedResolution, ant_retrieval::FeedError>,
) -> ControlAck {
    match result {
        Ok(resolution) => ControlAck::FeedResolved {
            reference: resolution.reference,
            index: resolution.index,
            signature: resolution.signature,
            v2: resolution.v2,
            decrypt_key: resolution.decrypt_key,
        },
        Err(ant_retrieval::FeedError::NoUpdates {
            corroborated: true, ..
        }) => ControlAck::FeedNotFound,
        Err(e @ ant_retrieval::FeedError::NoUpdates { .. }) => ControlAck::NotReady {
            message: format!(
                "feed lookup: {e}; too few peers answered to tell an empty feed \
                 from one this node can't reach yet"
            ),
        },
        Err(e @ ant_retrieval::FeedError::EndUnconfirmed { .. }) => ControlAck::NotReady {
            message: format!("feed lookup: {e}"),
        },
        Err(e) => ControlAck::Error {
            message: format!("feed lookup: {e}"),
        },
    }
}

/// Did this `ManifestError` ultimately come from a chunk-fetch failure
/// during the trie walk? The wire/encoding variants (bad version hash,
/// invalid metadata, descend-past-leaf, …) and the lookup-miss are all
/// terminal.
///
/// `Feed(FeedError::Fetch(_))` is treated as transient for the same
/// reason `Fetch(JoinError::FetchChunk { .. })` is: the underlying
/// failure is a chunk lookup that the [`run_get_bytes`] / [`run_get_bzz`]
/// retry loop can re-drive against a fresh peer snapshot. Without this,
/// a momentary empty peer pool during the feed walk (e.g. `RoutingFetcher`
/// returning "no BZZ peers available") would escape the loop and surface
/// as a hard 404 to the user — even though the same shortage on a
/// non-feed manifest node retries cleanly.
const fn is_manifest_transient(e: &ant_retrieval::ManifestError) -> bool {
    match e {
        ant_retrieval::ManifestError::Fetch(inner) => is_join_transient(inner),
        ant_retrieval::ManifestError::Feed(ant_retrieval::FeedError::Fetch(_)) => true,
        _ => false,
    }
}

/// Spawned task body for `Request::GetBytes`. Fetches the root chunk via
/// `RoutingFetcher`, then hands it to `ant_retrieval::join`. Pulled out
/// of `handle_control_command` so the latter stays small and the async
/// pieces are exercise-able without spinning up a swarm.
///
/// Wraps the actual pipeline in a retry loop: a fresh `RoutingFetcher`
/// per attempt with a **clean blacklist** *and* a fresh peer snapshot
/// pulled from `peers_rx` at attempt-start. So peers that were
/// transiently unreachable on attempt N (dropped libp2p connection,
/// tail-slow forward, momentarily no dial address) drop out of the
/// candidate list automatically once `ConnectionClosed` fires —
/// instead of sitting in a frozen list and giving us "connection is
/// closed" / "oneshot canceled" errors over and over until we exhaust
/// `MAX_FETCH_ATTEMPTS`. Bee's retrieval works the same way: skip-lists
/// are scoped to a single retrieval, never to the whole client session,
/// and the candidate set comes from the live forwarding-Kademlia table.
///
/// This is the core of the fix for "browser stalls on a multi-MiB media
/// file": both the blacklist carry-forward *and* the frozen peer snapshot
/// pushed us into "no BZZ peers available" or "connection is closed"
/// by attempt 2 — every peer we'd ever flubbed got banned permanently
/// for the rest of the request, and even un-flubbed-but-disconnected
/// peers stayed in the rotation forever.
// Eight args is over clippy's preferred ceiling, but bundling shared
// retrieval plumbing with request-scoped knobs into a struct just for
// one call site hides more than it helps.
#[allow(clippy::too_many_arguments)]
async fn run_get_bytes(
    control: Control,
    peers_rx: watch::Receiver<Vec<(libp2p::PeerId, [u8; 32])>>,
    cache: Arc<ant_retrieval::InMemoryChunkCache>,
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    inflight_limit: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    counters: Arc<RetrievalCounters>,
    tracker: Arc<ProgressTracker>,
    reference: [u8; 32],
    max_bytes: Option<u64>,
) -> ControlAck {
    // Every attempt re-joins the whole file, so the attempts' credit
    // waits share one deadline instead of stacking (issue #117).
    let credit_deadline = tokio::time::Instant::now() + BUFFERED_REQUEST_CREDIT_WINDOW;
    for attempt in 1..=MAX_FETCH_ATTEMPTS {
        if peers_rx.borrow().is_empty() {
            return ControlAck::Error {
                message: "no peers available; wait for handshakes to complete".to_string(),
            };
        }
        // Pass the watch receiver itself, not a snapshot: the fetcher's
        // per-chunk `ranked()` call rereads it so peers that disconnect
        // during the attempt drop out of subsequent chunks' candidate
        // pools immediately.
        let mut builder = ant_retrieval::RoutingFetcher::new(control.clone(), peers_rx.clone())
            .with_cache(cache.clone())
            .with_record_dir(record_dir.clone())
            .with_progress(tracker.clone())
            .with_inflight_limit(inflight_limit.clone())
            .with_counters(counters.clone())
            .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP)
            .with_credit_deadline(credit_deadline);
        if let Some(disk) = disk_cache.clone() {
            builder = builder.with_disk_cache(disk);
        }
        if let Some(tx) = payment_notify.clone() {
            builder = builder.with_payment_notify(tx);
        }
        if let Some(acc) = accounting.clone() {
            builder = builder.with_accounting(acc);
        }
        let fetcher = builder;
        match try_get_bytes(&fetcher, &tracker, reference, max_bytes).await {
            Ok(data) => {
                debug!(
                    target: "ant_p2p",
                    root = %hex::encode(reference),
                    bytes = data.len(),
                    attempt,
                    "joiner produced file",
                );
                return ControlAck::Bytes { data };
            }
            Err(AttemptError::Transient(message)) if attempt < MAX_FETCH_ATTEMPTS => {
                let backoff = RETRY_BACKOFF_BASE * attempt as u32;
                warn!(
                    target: "ant_p2p",
                    attempt,
                    next_in_ms = backoff.as_millis() as u64,
                    "get_bytes failed, retrying: {message}",
                );
                tokio::time::sleep(backoff).await;
            }
            Err(AttemptError::Permanent(message) | AttemptError::Transient(message)) => {
                return ControlAck::Error { message };
            }
        }
    }
    unreachable!("retry loop exits via return on the final attempt");
}

/// One attempt at the get-bytes pipeline. Splits per-error-site
/// classification away from the retry policy in `run_get_bytes`.
async fn try_get_bytes(
    fetcher: &ant_retrieval::RoutingFetcher,
    tracker: &ProgressTracker,
    reference: [u8; 32],
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, AttemptError> {
    use ant_retrieval::join;

    let root = ant_retrieval::fetch_root_with_replicas(
        fetcher,
        reference,
        ant_retrieval::accounting::CREDIT_WAIT_BUDGET,
    )
    .await
    .map_err(|e| {
        AttemptError::Transient(format!("fetch root chunk {}: {e}", hex::encode(reference)))
    })?;
    // The root chunk's span is the total file size (in bytes) of the
    // BMT-built tree below it, so we can finalize the progress totals
    // as soon as the root lands and the rest of the joiner can drive
    // the chunks_done counter against a real denominator.
    if let Some(total) = root_span_to_u64(&root) {
        tracker.set_total_bytes(total);
    }
    let cap = clamp_max_bytes(max_bytes);
    join(fetcher, &root, cap).await.map_err(|e| {
        let message = format!("join {}: {e}", hex::encode(reference));
        if is_join_transient(&e) {
            AttemptError::Transient(message)
        } else {
            AttemptError::Permanent(message)
        }
    })
}

/// Encrypted counterpart of [`run_get_bytes`]: same per-attempt
/// `RoutingFetcher` + retry loop, but the decrypting joiner
/// ([`ant_retrieval::join_encrypted`]) walks the 64-byte encrypted
/// reference `reference ‖ key`. Returns [`ControlAck::Bytes`] with the
/// decrypted file on success.
#[allow(clippy::too_many_arguments)]
async fn run_get_bytes_encrypted(
    control: Control,
    peers_rx: watch::Receiver<Vec<(libp2p::PeerId, [u8; 32])>>,
    cache: Arc<ant_retrieval::InMemoryChunkCache>,
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    inflight_limit: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    counters: Arc<RetrievalCounters>,
    tracker: Arc<ProgressTracker>,
    reference: [u8; 32],
    key: [u8; 32],
    max_bytes: Option<u64>,
) -> ControlAck {
    for attempt in 1..=MAX_FETCH_ATTEMPTS {
        if peers_rx.borrow().is_empty() {
            return ControlAck::Error {
                message: "no peers available; wait for handshakes to complete".to_string(),
            };
        }
        let mut builder = ant_retrieval::RoutingFetcher::new(control.clone(), peers_rx.clone())
            .with_cache(cache.clone())
            .with_record_dir(record_dir.clone())
            .with_progress(tracker.clone())
            .with_inflight_limit(inflight_limit.clone())
            .with_counters(counters.clone())
            .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP);
        if let Some(disk) = disk_cache.clone() {
            builder = builder.with_disk_cache(disk);
        }
        if let Some(tx) = payment_notify.clone() {
            builder = builder.with_payment_notify(tx);
        }
        if let Some(acc) = accounting.clone() {
            builder = builder.with_accounting(acc);
        }
        let fetcher = builder;
        match try_get_bytes_encrypted(&fetcher, reference, key, max_bytes).await {
            Ok(data) => {
                debug!(
                    target: "ant_p2p",
                    root = %hex::encode(reference),
                    bytes = data.len(),
                    attempt,
                    "encrypted joiner produced file",
                );
                return ControlAck::Bytes { data };
            }
            Err(AttemptError::Transient(message)) if attempt < MAX_FETCH_ATTEMPTS => {
                let backoff = RETRY_BACKOFF_BASE * attempt as u32;
                warn!(
                    target: "ant_p2p",
                    attempt,
                    next_in_ms = backoff.as_millis() as u64,
                    "get_bytes_encrypted failed, retrying: {message}",
                );
                tokio::time::sleep(backoff).await;
            }
            Err(AttemptError::Permanent(message) | AttemptError::Transient(message)) => {
                return ControlAck::Error { message };
            }
        }
    }
    unreachable!("retry loop exits via return on the final attempt");
}

/// One attempt at the encrypted get-bytes pipeline.
async fn try_get_bytes_encrypted(
    fetcher: &ant_retrieval::RoutingFetcher,
    reference: [u8; 32],
    key: [u8; 32],
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, AttemptError> {
    use ant_retrieval::{join_encrypted, ENCRYPTED_REF_SIZE};

    let mut root_ref = [0u8; ENCRYPTED_REF_SIZE];
    root_ref[..32].copy_from_slice(&reference);
    root_ref[32..].copy_from_slice(&key);

    let cap = clamp_max_bytes(max_bytes);
    join_encrypted(fetcher, root_ref, cap).await.map_err(|e| {
        let message = format!("join encrypted {}: {e}", hex::encode(reference));
        if is_join_transient(&e) {
            AttemptError::Transient(message)
        } else {
            AttemptError::Permanent(message)
        }
    })
}

/// Decode the 8-byte little-endian BMT span prefix from a wire-format
/// CAC chunk (`span || payload`) into a `u64` byte length. For an
/// intermediate chunk this is the total span its subtree covers; for
/// the root it's the final file size. Returns `None` if `wire` is
/// somehow shorter than the span prefix (shouldn't happen with
/// CAC-verified output, but cheap to guard).
fn root_span_to_u64(wire: &[u8]) -> Option<u64> {
    let span: [u8; 8] = wire.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(span))
}

/// Like [`root_span_to_u64`] but masks the redundancy level byte off the
/// span before decoding. Bee stores the RS level in the high byte of the
/// chunk's 8-byte span (top of the range, since a real file's span fits
/// in 56 bits / 72 PB). Reads that go through the joiner already decode
/// and mask the level per node, but the streaming path
/// also reports the file's total span over the wire (`BytesStreamStart`,
/// `BzzStreamStart`), so we need the masked value there too — otherwise
/// the gateway emits a `Content-Length` of `0x82_<...>` instead of the
/// real file size, and HEAD / Content-Range responses look like the
/// file is 9 exabytes long.
fn root_span_to_u64_masked(wire: &[u8]) -> Option<u64> {
    let mut span: [u8; 8] = wire.get(..8)?.try_into().ok()?;
    span[7] = 0;
    Some(u64::from_le_bytes(span))
}

#[allow(clippy::too_many_arguments)]
async fn run_list_bzz(
    control: Control,
    peers_rx: watch::Receiver<Vec<(libp2p::PeerId, [u8; 32])>>,
    cache: Arc<ant_retrieval::InMemoryChunkCache>,
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    inflight_limit: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    counters: Arc<RetrievalCounters>,
    reference: [u8; 32],
    page: Option<ant_control::ManifestListQuery>,
) -> ControlAck {
    if peers_rx.borrow().is_empty() {
        let message = "no peers available; wait for handshakes to complete".to_string();
        return if page.is_some() {
            ControlAck::NotReady { message }
        } else {
            ControlAck::Error { message }
        };
    }

    let mut builder = ant_retrieval::RoutingFetcher::new(control, peers_rx)
        .with_cache(cache)
        .with_record_dir(record_dir)
        .with_inflight_limit(inflight_limit)
        .with_counters(counters)
        .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP);
    if let Some(disk) = disk_cache {
        builder = builder.with_disk_cache(disk);
    }
    if let Some(tx) = payment_notify {
        builder = builder.with_payment_notify(tx);
    }
    if let Some(acc) = accounting {
        builder = builder.with_accounting(acc);
    }
    let fetcher = builder;

    if let Some(query) = page {
        let sweeps = ant_retrieval::ReplicaSweeps::for_listing();
        let query = manifest_page_query(query);
        let result = ant_retrieval::list_manifest_page(&fetcher, &reference, &query, &sweeps).await;
        return manifest_page_ack(&reference, result, &sweeps);
    }

    match ant_retrieval::list_manifest(&fetcher, &reference).await {
        Ok(entries) => ControlAck::Manifest {
            entries: entries
                .into_iter()
                .map(|entry| ant_control::ManifestEntryInfo {
                    path: entry.path,
                    reference: entry.reference.map(hex::encode),
                    metadata: entry.metadata,
                    size: entry.size,
                })
                .collect(),
        },
        Err(e) => ControlAck::Error {
            message: format!("list manifest {}: {e}", hex::encode(reference)),
        },
    }
}

fn manifest_page_query(q: ant_control::ManifestListQuery) -> ant_retrieval::ManifestPageQuery {
    ant_retrieval::ManifestPageQuery {
        prefix: q.prefix,
        delimiter: q.delimiter,
        after: q.after,
        limit: q.limit,
        sizes: q.sizes,
    }
}

/// Terminal ack for one page of a manifest listing
/// ([`ControlCommand::ListBzz`] with `page: Some(..)`, issue #61), typed
/// off the [`ant_retrieval::ManifestError`] rather than its message:
///
/// - a page → [`ControlAck::ManifestPage`], `immutable` unless the
///   reference was a feed manifest, a size asked for couldn't be read,
///   or the walk ran out of time ([`ant_retrieval::MANIFEST_PAGE_WALK_BUDGET`])
///   and ended `truncated` early, or the page ended `truncated` on a
///   failed lookahead load ([`ant_retrieval::ManifestPage::lookahead_failed`]);
/// - the prefix names nothing, or the reference (or a trie node) is not
///   a decodable manifest → [`ControlAck::NotFound`], bee#5537's 404;
/// - a path on the page is not valid UTF-8 (it can't be returned as a
///   JSON string and passed back as `after` without paging wrongly) →
///   [`ControlAck::NotFound`]: a property of the content, which a retry
///   would only repeat;
/// - the walk ran out of time before finding a single item →
///   [`ControlAck::NotReady`]: the nodes it loaded are cached, so a
///   retry gets further;
/// - a trie node that couldn't be fetched → [`ControlAck::NotFound`] if
///   peers confirmed it missing, [`ControlAck::NotReady`] if the miss
///   came from a starved pool or the node's replica sweep failed only
///   transiently (`sweeps`; the same split as `/bzz`'s
///   [`bzz_lookup_failure_ack`]), else [`ControlAck::Error`]. A listing
///   is never answered with a subtree silently left out.
///
/// Public so the gateway's test node loop answers with this exact
/// mapping instead of a copy of it.
#[must_use]
pub fn manifest_page_ack(
    reference: &[u8],
    result: Result<ant_retrieval::ManifestPage, ant_retrieval::ManifestError>,
    sweeps: &ant_retrieval::ReplicaSweeps,
) -> ControlAck {
    use ant_retrieval::ManifestError as E;
    match result {
        Ok(page) => ControlAck::ManifestPage(ant_control::ManifestListPage {
            immutable: !page.feed
                && !page.sizes_incomplete
                && !page.timed_out
                && !page.lookahead_failed,
            entries: page
                .entries
                .into_iter()
                .map(|entry| ant_control::ManifestEntryInfo {
                    path: entry.path,
                    reference: entry.reference.map(hex::encode),
                    metadata: entry.metadata,
                    size: entry.size,
                })
                .collect(),
            common_prefixes: page.common_prefixes,
            truncated: page.truncated,
            next_marker: page.next_marker,
        }),
        Err(
            e @ (E::NotFound { .. }
            | E::NotAManifest
            | E::TooShort(_)
            | E::UnsupportedVersion(_)
            | E::InvalidRefLength(_)
            | E::InvalidMetadata(_)
            | E::ListNonUtf8Path { .. }),
        ) => ControlAck::NotFound {
            message: format!("list manifest {}: {e}", hex::encode(reference)),
        },
        Err(e @ E::ListTimedOut) => ControlAck::NotReady {
            message: format!("list manifest {}: {e}", hex::encode(reference)),
        },
        Err(e) => bzz_lookup_failure_ack(
            format!("list manifest {}: {e}", hex::encode(reference)),
            &e,
            sweeps.swept_transiently(&e),
        ),
    }
}

/// Resolve the optional per-request `max_bytes` override into the
/// `usize` the joiner expects. `None` falls back to the conservative
/// `DEFAULT_MAX_FILE_BYTES` (32 MiB), keeping `antctl get` safe by
/// default. The HTTP gateway raises this so real bzz sites with media
/// payloads don't 502 at the joiner step. Saturating cast keeps a
/// hypothetical `u64` value larger than `usize::MAX` — only possible on
/// 32-bit targets — from wrapping to a tiny cap silently.
fn clamp_max_bytes(max_bytes: Option<u64>) -> usize {
    use ant_retrieval::DEFAULT_MAX_FILE_BYTES;
    match max_bytes {
        Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
        None => DEFAULT_MAX_FILE_BYTES,
    }
}

/// Spread `max` sample indices evenly across `[0, len)`. Returns every
/// index when `len <= max`, otherwise a strided subset so the sample
/// covers the file front-to-back rather than clustering at the start.
fn sample_indices(len: usize, max: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    if len <= max {
        return (0..len).collect();
    }
    (0..max).map(|k| k * len / max).collect()
}

/// Probe a single chunk address across the `probes` closest distinct
/// peers, network-only, and return how many returned it (a per-chunk
/// route-diversity / replication count). Peers are ranked by XOR
/// distance to `addr` — the same ordering [`RoutingFetcher`] uses — so
/// we hit the chunk's natural neighbourhood first.
///
/// Each probe is a real, billable retrieval on the serving peer's
/// accounting, so it goes through the same admission control
/// (`Accounting::try_reserve`) and pseudosettle heartbeat as the
/// production fetch path.
///
/// Crucially, a peer we *couldn't even ask* because our accounting with
/// it is saturated is **not** counted as a "no" — it's left out of both
/// `hits` and `answered`. Treating an admission-control skip as evidence
/// the chunk is absent is what made shallow counts *grow* round over
/// round: re-pushing and probing spend budget, more peers saturate, and
/// each saturated peer used to drag a chunk into the "missing" set even
/// though we never reached anyone who could answer. Callers must treat
/// `answered == 0` as "unknown", never as "missing".
struct LeafProbe {
    /// Closest peers that returned the chunk.
    hits: u32,
    /// Closest peers we actually reached (admission control let us pay and
    /// dispatch the fetch), whether they had it or not. Saturated/skipped
    /// peers are excluded.
    answered: u32,
}

async fn probe_leaf_sources(
    control: &Control,
    peers: &[(PeerId, Overlay)],
    addr: [u8; 32],
    probes: usize,
    probe_timeout: std::time::Duration,
    net: &VerifyNet,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> LeafProbe {
    use ant_retrieval::accounting::Accounting;

    let mut ranked: Vec<(PeerId, Overlay)> = peers.to_vec();
    ranked.sort_by(|(_, a), (_, b)| {
        for i in 0..32 {
            let da = a[i] ^ addr[i];
            let db = b[i] ^ addr[i];
            if da != db {
                return da.cmp(&db);
            }
        }
        std::cmp::Ordering::Equal
    });
    let candidates: Vec<(PeerId, Overlay)> = ranked.into_iter().take(probes).collect();
    let probes_iter = candidates.into_iter().map(|(peer, overlay)| {
        let mut control = control.clone();
        let accounting = net.accounting.clone();
        let payment_notify = net.payment_notify.clone();
        let cancel = cancel.clone();
        async move {
            let guard = match accounting.as_ref() {
                Some(acc) => {
                    let price = Accounting::peer_price(&overlay, &addr);
                    match acc.try_reserve(peer, price) {
                        Some(g) => Some(g),
                        // Saturated peer: skip and report "unknown"
                        // (neither answered nor hit), never a miss.
                        None => return (false, false),
                    }
                }
                None => None,
            };
            let fetch = async move {
                ant_retrieval::retrieve_chunk(&mut control, peer, addr)
                    .await
                    .is_ok()
            };
            // On a delivery, in time or late, bee has applied the debit:
            // record it in the mirror, which is what schedules the
            // pseudosettle refresh that clears it.
            let on_delivered = move || {
                if let Some(g) = guard {
                    g.apply();
                }
                if let Some(tx) = payment_notify.as_ref() {
                    let _ = tx.try_send(peer);
                }
            };
            let hit =
                probe_draining_late_delivery(fetch, probe_timeout, cancel, on_delivered).await;
            // We reached the peer (reservation succeeded), so this is a
            // definitive answer regardless of hit/miss.
            (hit, true)
        }
    });
    let results = futures::future::join_all(probes_iter).await;
    LeafProbe {
        hits: results.iter().filter(|(hit, _)| *hit).count() as u32,
        answered: results.iter().filter(|(_, answered)| *answered).count() as u32,
    }
}

/// Run one billable probe fetch with a `timeout` on the *answer* but not
/// on the request: if `fetch` hasn't resolved by then the probe counts as
/// a miss, but the request is not dropped, and `on_delivered` still runs
/// if bee delivers late. Dropping the request at the timeout would lose a
/// debit bee may already have applied (`creditAction.Apply` runs when it
/// writes the delivery), and since pseudosettle refreshes are scheduled
/// only off the accounting mirror (`Accounting::refresh_due`), debt the
/// mirror never sees is cleared only incidentally.
///
/// The late request is waited for *in place*, bounded by
/// `retrieve_chunk`'s own `RETRIEVE_TIMEOUT` (30 s), so it keeps holding
/// its caller's slot: a verify's per-leaf `CONCURRENCY` stays the real
/// bound on its open retrieval streams and on the reservations those
/// hold, and a timed-out probe can't pile up behind later leaves (where
/// its held reservation would make `try_reserve` refuse the same peer and
/// turn their probes into "unknown"). The cost is wall-clock: a leaf with
/// a slow closest peer finishes when that request does — up to 30 s
/// instead of `timeout` — though its verdict is still fixed at `timeout`.
///
/// Once `cancel` is set (the user cancelled the verify), the caller is
/// released at once and the request is handed to a detached task instead
/// (the fetcher's loser drain, `spawn_drain_losers`, for the probe path).
/// That is the one case where a request outlives the verify: it still
/// has to be read to the end to record its debit, and it ends within
/// `RETRIEVE_TIMEOUT` of having been sent. `cancel` is polled every
/// [`PROBE_CANCEL_POLL`].
///
/// Returns whether `fetch` delivered within `timeout`. `on_delivered`
/// runs at most once, on an in-time or late delivery, never on a failure.
async fn probe_draining_late_delivery<F, D>(
    fetch: F,
    timeout: std::time::Duration,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    on_delivered: D,
) -> bool
where
    F: std::future::Future<Output = bool> + Send + 'static,
    D: FnOnce() + Send + 'static,
{
    let mut fetch = Box::pin(fetch);
    match tokio::time::timeout(timeout, &mut fetch).await {
        Ok(true) => {
            on_delivered();
            true
        }
        Ok(false) => false,
        Err(_) => {
            let cancelled = async {
                loop {
                    if cancel
                        .as_ref()
                        .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                    {
                        return;
                    }
                    tokio::time::sleep(PROBE_CANCEL_POLL).await;
                }
            };
            tokio::select! {
                delivered = &mut fetch => {
                    if delivered {
                        on_delivered();
                    }
                }
                () = cancelled => {
                    tokio::spawn(async move {
                        if fetch.await {
                            on_delivered();
                        }
                    });
                }
            }
            false
        }
    }
}

/// How often a probe waiting out a late request checks the verify's
/// cancel flag ([`probe_draining_late_delivery`]).
const PROBE_CANCEL_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Read back a specific set of chunk addresses network-only and return
/// the subset that could not be retrieved. Uses the cache-free
/// `RoutingFetcher` (the real download path: closest-first through
/// forwarder peers, hedged, with error backfill) and a bounded
/// concurrency window so a large file's heal check doesn't open
/// thousands of simultaneous streams. Backs the upload self-heal loop.
async fn verify_chunks_present(
    fetcher: &ant_retrieval::RoutingFetcher,
    addresses: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    use futures::stream::StreamExt;

    const CONCURRENCY: usize = 16;
    // A chunk that hits this cap is reported unreachable, but the
    // fetcher's in-flight requests are not dropped with it: they finish
    // in the fetcher's loser drain (within `RETRIEVE_TIMEOUT`) so a late
    // delivery's debit still reaches the accounting mirror. They keep
    // their process-wide retrieval permits (`VerifyNet::inflight`) until
    // then, which is what bounds them once outside `CONCURRENCY`.
    const PER_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

    futures::stream::iter(addresses.iter().copied().map(|addr| async move {
        let reachable = matches!(
            tokio::time::timeout(PER_CHUNK_TIMEOUT, fetcher.fetch(addr)).await,
            Ok(Ok(_))
        );
        (addr, reachable)
    }))
    .buffer_unordered(CONCURRENCY)
    .filter_map(|(addr, reachable)| async move { (!reachable).then_some(addr) })
    .collect()
    .await
}

/// Outcome of the two-stage deep presence check
/// ([`verify_chunks_present_deep`]). The two sets answer two different
/// questions and must not be conflated:
///
/// - `probe_missing` is the **third-party reachability** signal: a leaf
///   here was not returned by any of its *own* closest peers, which is
///   exactly the vantage a gateway has when it routes closest-first. A
///   chunk that only landed shallow (held by a peer the uploader is
///   directly linked to, but not in the chunk's neighbourhood) shows up
///   here even though the uploader itself can still fetch it.
/// - `confirmed_missing` is the **genuinely-gone** signal: the subset of
///   `probe_missing` that *also* failed the privileged routed download,
///   i.e. no route serves it at all. This is the only safe basis for a
///   re-push (re-pushing a merely-shallow chunk from probe noise was the
///   regression that motivated the routed confirmation pass).
struct DeepPresence {
    probe_missing: Vec<[u8; 32]>,
    confirmed_missing: Vec<[u8; 32]>,
}

/// Deep read-back: for each address, first probe its `probes` closest
/// known peers (the chunk's neighbourhood vantage), then — for every
/// address those one-shot probes failed to find — confirm with the real
/// routed download path. Returns both sets (see [`DeepPresence`]): the
/// probe misses (gateway-reachability) and the routed-confirmed misses
/// (genuinely gone). The heal re-push keys on `confirmed_missing`; the
/// user-facing "fully available" verdict keys on `probe_missing`, so a
/// shallow placement the uploader can still privilege-fetch no longer
/// reads as durably replicated.
///
/// Why two stages: the closest-peer probes are single-attempt fetches
/// with no hedging, no retry and no error backfill, so on a light node
/// they have a substantial per-chunk false-failure rate (peer churn, a
/// slow forwarding hop, an overdraft skip). Run alone they flagged ~25%
/// of a file "missing" while the public gateway streamed the very same
/// file byte-exact — and the heal then re-pushed hundreds of perfectly
/// healthy chunks on every launch. The routed confirmation pass
/// ([`verify_chunks_present`], the production fetch path: closest-first
/// through forwarder peers, hedged, with error backfill) clears those
/// false alarms, so "missing" again means "a third party can't get it".
///
/// The probe stage is kept (rather than going routed-only) because it is
/// what surfaces shallow placements: the routed pass run from the
/// uploader can be privileged — it may still be directly linked to a far
/// storer that signed a shallow receipt — but a chunk that *no* probe
/// finds and only the privileged route serves is rare now that uploads
/// dial the neighbourhood and land deep at push time; we accept that
/// residual in exchange for verdicts that match gateway reality.
/// Bounded concurrency so a large file's check doesn't open thousands
/// of simultaneous streams.
#[allow(clippy::too_many_arguments)]
async fn verify_chunks_present_deep(
    control: &Control,
    peers: &[(PeerId, Overlay)],
    fetcher: &ant_retrieval::RoutingFetcher,
    addresses: &[[u8; 32]],
    probes: usize,
    net: &VerifyNet,
    // Optional progress sink + denominator: each item is a JSON line
    // `{"phase":"checking","checked":n,"total":total}`, emitted as each
    // leaf's neighbourhood probe completes. `None` opts out (the heal
    // caller). The routed-confirmation second pass below isn't counted —
    // it only runs for the misses and would make the bar jump backwards.
    progress: Option<mpsc::UnboundedSender<String>>,
    total: usize,
    // Optional cooperative cancel: once set, in-flight per-leaf futures
    // short-circuit (returning the leaf as "present" so it isn't flagged),
    // so the stream drains near-instantly. The caller
    // (`verify_propagation_deep`) re-checks the flag afterwards and reports
    // cancellation instead of using this (now-partial) result.
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> DeepPresence {
    use futures::stream::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CONCURRENCY: usize = 16;
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    let checked = Arc::new(AtomicUsize::new(0));
    let probe_missing: Vec<[u8; 32]> =
        futures::stream::iter(addresses.iter().copied().map(|addr| {
            let checked = checked.clone();
            let progress = progress.clone();
            let cancel = cancel.clone();
            async move {
                if cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                    // Skip remaining work; not flagged so the partial set stays
                    // clean (discarded by the caller on cancel anyway).
                    return (addr, true);
                }
                let probe = probe_leaf_sources(
                    control,
                    peers,
                    addr,
                    probes,
                    PROBE_TIMEOUT,
                    net,
                    cancel.clone(),
                )
                .await;
                if let Some(tx) = &progress {
                    let done = checked.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = tx.send(
                        serde_json::json!({ "phase": "checking", "checked": done, "total": total })
                            .to_string(),
                    );
                }
                // Flag as a probe miss only when we actually reached at
                // least one of its closest peers and none had it. If every
                // candidate was admission-control-saturated (`answered ==
                // 0`) we learned nothing — treat it as present (unknown) so
                // our own spent budget can't manufacture shallow chunks.
                let present = probe.hits > 0 || probe.answered == 0;
                (addr, present)
            }
        }))
        .buffer_unordered(CONCURRENCY)
        .filter_map(|(addr, present)| async move { (!present).then_some(addr) })
        .collect()
        .await;

    if probe_missing.is_empty() {
        return DeepPresence {
            probe_missing,
            confirmed_missing: Vec::new(),
        };
    }
    debug!(
        target: "ant_p2p",
        flagged = probe_missing.len(),
        checked = addresses.len(),
        "deep probes missed some chunks; confirming via routed fetch before declaring genuinely missing",
    );
    let confirmed_missing = verify_chunks_present(fetcher, &probe_missing).await;
    DeepPresence {
        probe_missing,
        confirmed_missing,
    }
}

/// Settlement + admission plumbing for every network-only verification
/// fetch (the deep neighbourhood probes and the routed confirmation
/// pass). Verification used to run *without* this — raw `retrieve_chunk`
/// calls with no accounting mirror and no pseudosettle heartbeat — so a
/// few hundred probed leaves racked up unpaid debt on the serving peers
/// (each chunk is ~240–320 k units against bee's ≈1.69 M-unit light-mode
/// disconnect limit, i.e. ~6 free chunks per peer) and the closest peers
/// started refusing us mid-verify. The result was mass false-"missing"
/// verdicts on files the public gateway streamed perfectly well, and
/// heal rounds whose missing count *grew* round-over-round as the debt
/// piled up. Cloned out of [`SwarmState`] at command time.
#[derive(Clone)]
struct VerifyNet {
    inflight: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    /// See [`SwarmState::verify_gate`]: serialises verification passes
    /// so concurrent per-file verifies can't fail each other's probes.
    verify_gate: Arc<Semaphore>,
}

impl VerifyNet {
    fn from_state(state: &SwarmState) -> Self {
        Self {
            inflight: state.retrieval_inflight.clone(),
            payment_notify: state.payment_notify.clone(),
            accounting: state.accounting.clone(),
            verify_gate: state.verify_gate.clone(),
        }
    }

    /// Cache-free fetcher for verification: network-only (the local
    /// store-then-push copy must never mask a failed push) but a full
    /// network citizen — process-wide inflight cap, overdraft admission
    /// control, and pseudosettle heartbeat, exactly like the real
    /// download path.
    fn fetcher(
        &self,
        control: Control,
        peers_rx: watch::Receiver<Vec<(PeerId, Overlay)>>,
    ) -> ant_retrieval::RoutingFetcher {
        let mut f = ant_retrieval::RoutingFetcher::new(control, peers_rx)
            .with_inflight_limit(self.inflight.clone())
            .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP);
        if let Some(tx) = self.payment_notify.clone() {
            f = f.with_payment_notify(tx);
        }
        if let Some(acc) = self.accounting.clone() {
            f = f.with_accounting(acc);
        }
        f
    }
}

/// How many leaves a verification additionally probes for the
/// informational distinct-route ("sources") floor. Bounded because each
/// probe is a second per-leaf round-trip on top of the reachability check.
const SOURCE_PROBE_SAMPLE: usize = 24;

/// Floor on how many of a leaf's closest peers the first-pass
/// reachability probes ask (the "does its neighbourhood hold it"
/// question, distinct from the `sources` route-diversity floor). A leaf
/// passes the probe stage if *any* of its closest `VERIFY_DEEP_PROBES`
/// peers returns it; probe misses are then confirmed via the routed
/// download path before counting as missing (see
/// [`verify_chunks_present_deep`]). Matched to the heal's `HEAL_PROBES`
/// so the UI verdict and the post-upload heal agree on what "reachable"
/// means.
const VERIFY_DEEP_PROBES: usize = 4;

/// Deep propagation check: resolve the manifest at `reference` to its
/// data root, enumerate the file's chunk tree (fetching every interior
/// node network-only, which proves the skeleton is retrievable), then
/// check the data leaves network-only — every leaf when `samples == 0`
/// (a full, uncapped verification), otherwise an evenly-spread
/// sample of `samples` leaves — and probe a bounded subset across up to
/// `probes` distinct closest peers for the replication floor. Returns the
/// JSON body described on [`ControlCommand::VerifyPropagation`].
#[allow(clippy::too_many_arguments)]
async fn verify_propagation_deep(
    control: Control,
    peers_rx: watch::Receiver<Vec<(PeerId, Overlay)>>,
    peers: Vec<(PeerId, Overlay)>,
    reference: [u8; 32],
    samples: usize,
    probes: usize,
    net: VerifyNet,
    progress: Option<mpsc::UnboundedSender<String>>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> serde_json::Value {
    use ant_retrieval::{
        enumerate_chunk_tree, lookup_path, ChunkFetcher, JoinOptions, ManifestError,
        DURABILITY_MAX_FILE_BYTES,
    };

    // True once the caller (the app's Cancel button) has requested abort.
    let cancelled = || {
        cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    };

    // Best-effort progress emitter; a dropped receiver (caller gone) just
    // makes this a no-op, so emission never blocks or fails the pass.
    let emit = |phase: &str, checked: Option<usize>, total: Option<usize>| {
        if let Some(tx) = &progress {
            let mut v = serde_json::json!({ "phase": phase });
            if let Some(c) = checked {
                v["checked"] = c.into();
            }
            if let Some(t) = total {
                v["total"] = t.into();
            }
            let _ = tx.send(v.to_string());
        }
    };

    // Serialise with any other in-flight verification (see
    // `SwarmState::verify_gate`); the permit is held for the whole pass.
    emit("resolving", None, None);
    let _gate = net
        .verify_gate
        .clone()
        .acquire_owned()
        .await
        .expect("verify gate semaphore closed");

    let ref_hex = format!("0x{}", hex::encode(reference));
    let err_body = |msg: String| {
        serde_json::json!({
            "reference": ref_hex,
            "retrievable": false,
            "fully_replicated": false,
            "total_chunks": 0,
            "leaf_chunks": 0,
            "intermediate_chunks": 0,
            "checked_chunks": 0,
            "retrievable_chunks": 0,
            "sampled_leaves": 0,
            "shallow_leaves": 0,
            "sources": 0,
            "error": msg,
        })
    };
    // Distinct from an error: a user-cancelled check carries `cancelled:true`
    // and `error:"cancelled"` so the app clears the in-flight state without
    // recording a (misleading) "not retrievable" verdict.
    let cancelled_body = || {
        let mut b = err_body("cancelled".to_string());
        b["cancelled"] = true.into();
        b
    };

    if cancelled() {
        return cancelled_body();
    }

    // Cache-free fetcher: manifest resolution and interior-node fetches
    // must hit the network, never the daemon's local store-then-push
    // copy. Fully wired (inflight cap, admission control, pseudosettle
    // heartbeat) so the verification's own traffic gets paid for instead
    // of blocklisting us with the peers we're about to probe.
    let fetcher = net.fetcher(control.clone(), peers_rx);

    // Resolve the manifest to its data root; a non-manifest reference is
    // treated as a raw `/bytes/` data root. Encrypted entries are not
    // verifiable here (their chunk tree needs the decryption keys to
    // enumerate) — report that instead of a bogus verdict.
    let data_ref: [u8; 32] = match lookup_path(&fetcher, &reference, "").await {
        Ok(r) => match r.data_ref.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                return err_body("encrypted manifest entries are not supported here".to_string())
            }
        },
        Err(ManifestError::NotAManifest) => reference,
        Err(e) => return err_body(format!("manifest resolve: {e}")),
    };

    let root = match fetcher.fetch(data_ref).await {
        Ok(r) => r,
        Err(e) => return err_body(format!("fetch data root: {e}")),
    };

    if cancelled() {
        return cancelled_body();
    }
    emit("enumerating", None, None);
    // Durability verify must cover any file the gateway will serve (up to
    // ~16 GiB), not the 32 MiB interactive cap — otherwise a large-but-
    // healthy upload fails enumeration ("file too large: span … cap
    // 33554432") and is reported "not fully stored". Saturate the u64 cap
    // into usize so 32-bit targets clamp instead of overflowing.
    let max_bytes = usize::try_from(DURABILITY_MAX_FILE_BYTES).unwrap_or(usize::MAX);
    let inv = match enumerate_chunk_tree(
        &fetcher,
        data_ref,
        &root,
        max_bytes,
        JoinOptions {
            allow_degraded_redundancy: true,
        },
    )
    .await
    {
        Ok(i) => i,
        Err(e) => return err_body(format!("enumerate chunk tree: {e}")),
    };

    let leaf_chunks = inv.leaves.len();
    let intermediate_chunks = inv.intermediates.len();
    let total_chunks = inv.total();

    // Every interior node (and the data root) was fetched network-only
    // above, so the skeleton is retrievable. Now check the data leaves.
    //
    // `samples == 0` checks *every* data leaf — no cap. This is a full,
    // end-to-end verification: the authoritative verdict the UI shows as
    // "Verified". (There used to be a `MAX_FULL_VERIFY_LEAVES` ceiling that
    // sampled large files; it was removed so a big file is verified in full
    // rather than sampled, at the cost of more per-leaf network probes.)
    // The check is still bounded in *concurrency* (see
    // `verify_chunks_present_deep`), just not in coverage. A non-zero
    // `samples` probes an evenly-spread subset only.
    let check_idx = if samples == 0 {
        sample_indices(leaf_chunks, leaf_chunks)
    } else {
        sample_indices(leaf_chunks, samples)
    };
    let sampled_leaves = check_idx.len();
    let leaf_addrs: Vec<[u8; 32]> = check_idx.iter().map(|&i| inv.leaves[i]).collect();

    // Reachability verdict: two-stage. First the deep neighbourhood
    // probe — each chunk's *own* closest peers, the vantage a gateway
    // reaches by routing closest-first, so a chunk that only landed
    // shallow is flagged exactly as a gateway would experience it. Then
    // every probe miss is confirmed via the routed download path before
    // counting as missing, because the one-shot probes have a material
    // false-failure rate on a light node (see
    // [`verify_chunks_present_deep`]). Same signal as the post-upload
    // heal, so the UI verdict and the heal can't disagree.
    if cancelled() {
        return cancelled_body();
    }
    let deep_probes = probes.max(VERIFY_DEEP_PROBES);
    emit("checking", Some(0), Some(sampled_leaves));
    let presence = verify_chunks_present_deep(
        &control,
        &peers,
        &fetcher,
        &leaf_addrs,
        deep_probes,
        &net,
        progress.clone(),
        sampled_leaves,
        cancel.clone(),
    )
    .await;
    // Cancelled mid-leaf-check: the result is partial and meaningless,
    // so report cancellation rather than a verdict.
    if cancelled() {
        return cancelled_body();
    }
    // Leaves no neighbourhood probe returned — the gateway-reachability
    // signal. A non-empty set means at least one leaf only landed shallow
    // (or is gone), so a third party routing closest-first can't get it.
    let neighbourhood_missing = presence.probe_missing.len();
    // Leaves genuinely unreachable from any route (the hard "not
    // retrievable" basis); a subset of `neighbourhood_missing`.
    let missing = presence.confirmed_missing;
    // Leaves that exist but only via the uploader's privileged routed
    // link, not their own closest peers — present yet not durably placed.
    let shallow_leaves = neighbourhood_missing.saturating_sub(missing.len());
    let leaves_retrievable = sampled_leaves - missing.len();

    // Informational replication floor: how many of a chunk's own closest
    // peers hold it directly (route diversity), separate from whether it's
    // reachable at all. A bounded, evenly-spread sample — but probed
    // *concurrently* and reported as its own "sources" progress phase, so
    // the UI shows movement (replications checked X/Y) instead of a stalled
    // 100% bar between the leaf check and the verdict.
    let probe_timeout = std::time::Duration::from_secs(10);
    let source_idx = sample_indices(leaf_addrs.len(), SOURCE_PROBE_SAMPLE.min(leaf_addrs.len()));
    let source_total = source_idx.len();
    let min_sources = if source_total == 0 {
        0
    } else {
        use futures::stream::StreamExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        const SOURCE_PROBE_CONCURRENCY: usize = 16;

        emit("sources", Some(0), Some(source_total));
        let control_ref = &control;
        let peers_ref = &peers;
        let net_ref = &net;
        let progress_ref = &progress;
        let cancel_ref = &cancel;
        let done = AtomicUsize::new(0);
        let done_ref = &done;

        let min = futures::stream::iter(source_idx.into_iter().map(|i| {
            let addr = leaf_addrs[i];
            async move {
                if cancel_ref
                    .as_ref()
                    .is_some_and(|c| c.load(Ordering::Relaxed))
                {
                    return u32::MAX;
                }
                let probe = probe_leaf_sources(
                    control_ref,
                    peers_ref,
                    addr,
                    probes,
                    probe_timeout,
                    net_ref,
                    cancel_ref.clone(),
                )
                .await;
                if let Some(tx) = progress_ref {
                    let n = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = tx.send(
                        serde_json::json!({ "phase": "sources", "checked": n, "total": source_total })
                            .to_string(),
                    );
                }
                // A leaf whose closest peers were all admission-control
                // saturated couldn't be measured — return MAX so it's
                // excluded from the min rather than collapsing the floor to
                // zero on our own spent budget.
                if probe.answered == 0 {
                    u32::MAX
                } else {
                    probe.hits
                }
            }
        }))
        .buffer_unordered(SOURCE_PROBE_CONCURRENCY)
        .fold(u32::MAX, |acc, s| async move { acc.min(s) })
        .await;
        if min == u32::MAX {
            0
        } else {
            min
        }
    };
    // Cancelled during the replication probe → report cancellation, not a
    // verdict computed from a partial sample.
    if cancelled() {
        return cancelled_body();
    }

    let checked_chunks = intermediate_chunks + sampled_leaves;
    let retrievable_chunks = intermediate_chunks + leaves_retrievable;
    // Intermediates are retrievable by construction (enumeration fetched
    // them). `retrievable` means "exists somewhere" — every checked leaf
    // came back on at least one route, possibly the uploader's privileged
    // link.
    let retrievable = total_chunks > 0 && missing.is_empty();
    // `fully_replicated` is the stronger, third-party verdict the UI shows
    // as the confident "Verified": every checked leaf is reachable from
    // its *own* closest peers (the gateway vantage, not the uploader's
    // privileged route) AND the sampled replication floor is at least one.
    // Either a shallow placement (`neighbourhood_missing > 0`) or a
    // zero-source sample is enough to withhold it — those are exactly the
    // files that verify "ok" here yet won't load from a public gateway.
    let fully_replicated = retrievable && neighbourhood_missing == 0 && min_sources >= 1;

    serde_json::json!({
        "reference": ref_hex,
        "retrievable": retrievable,
        "fully_replicated": fully_replicated,
        "total_chunks": total_chunks,
        "leaf_chunks": leaf_chunks,
        "intermediate_chunks": intermediate_chunks,
        "checked_chunks": checked_chunks,
        "retrievable_chunks": retrievable_chunks,
        "sampled_leaves": sampled_leaves,
        "shallow_leaves": shallow_leaves,
        "sources": min_sources,
    })
}

/// Spawned task body for `Request::GetBzz`. Walks the manifest at
/// `reference`, resolves `path`, then runs the joiner against the
/// resolved data ref. Wrapped in the same retry loop as
/// [`run_get_bytes`].
// Nine args is over clippy's preferred ceiling, but the alternative
// (bundling shared retrieval plumbing with request-scoped knobs into a
// struct just for one call site) hides more than it helps.
#[allow(clippy::too_many_arguments)]
async fn run_get_bzz(
    control: Control,
    peers_rx: watch::Receiver<Vec<(libp2p::PeerId, [u8; 32])>>,
    cache: Arc<ant_retrieval::InMemoryChunkCache>,
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    inflight_limit: Arc<Semaphore>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
    accounting: Option<Arc<ant_retrieval::accounting::Accounting>>,
    counters: Arc<RetrievalCounters>,
    feed_hints: ant_retrieval::FeedHints,
    tracker: Arc<ProgressTracker>,
    reference: [u8; 32],
    path: String,
    allow_degraded_redundancy: bool,
    max_bytes: Option<u64>,
) -> ControlAck {
    // Every attempt re-joins the whole file, so the attempts' credit
    // waits share one deadline instead of stacking (issue #117).
    let credit_deadline = tokio::time::Instant::now() + BUFFERED_REQUEST_CREDIT_WINDOW;
    for attempt in 1..=MAX_FETCH_ATTEMPTS {
        if peers_rx.borrow().is_empty() {
            return ControlAck::Error {
                message: "no peers available; wait for handshakes to complete".to_string(),
            };
        }
        // Pass the watch receiver itself: see `run_get_bytes` for
        // rationale on per-chunk peer freshness.
        let mut builder = ant_retrieval::RoutingFetcher::new(control.clone(), peers_rx.clone())
            .with_cache(cache.clone())
            .with_record_dir(record_dir.clone())
            .with_progress(tracker.clone())
            .with_inflight_limit(inflight_limit.clone())
            .with_counters(counters.clone())
            .with_request_inflight_limit(RETRIEVAL_REQUEST_INFLIGHT_CAP)
            .with_credit_deadline(credit_deadline);
        if let Some(disk) = disk_cache.clone() {
            builder = builder.with_disk_cache(disk);
        }
        if let Some(tx) = payment_notify.clone() {
            builder = builder.with_payment_notify(tx);
        }
        if let Some(acc) = accounting.clone() {
            builder = builder.with_accounting(acc);
        }
        let fetcher = builder;
        match try_get_bzz(
            &fetcher,
            &feed_hints,
            &tracker,
            reference,
            &path,
            allow_degraded_redundancy,
            max_bytes,
        )
        .await
        {
            Ok((data, content_type, filename)) => {
                return ControlAck::BzzBytes {
                    data,
                    content_type,
                    filename,
                };
            }
            Err(AttemptError::Transient(message)) if attempt < MAX_FETCH_ATTEMPTS => {
                let backoff = RETRY_BACKOFF_BASE * attempt as u32;
                warn!(
                    target: "ant_p2p",
                    attempt,
                    next_in_ms = backoff.as_millis() as u64,
                    "get_bzz failed, retrying: {message}",
                );
                tokio::time::sleep(backoff).await;
            }
            Err(AttemptError::Permanent(message) | AttemptError::Transient(message)) => {
                return ControlAck::Error { message };
            }
        }
    }
    unreachable!("retry loop exits via return on the final attempt");
}

/// One attempt at the get-bzz pipeline. Returns the resolved
/// `(data, content_type, filename)` tuple on success.
#[allow(clippy::too_many_arguments)]
async fn try_get_bzz(
    fetcher: &ant_retrieval::RoutingFetcher,
    feed_hints: &ant_retrieval::FeedHints,
    tracker: &ProgressTracker,
    reference: [u8; 32],
    path: &str,
    allow_degraded_redundancy: bool,
    max_bytes: Option<u64>,
) -> Result<(Vec<u8>, Option<String>, Option<String>), AttemptError> {
    use ant_retrieval::{join_with_options, lookup_path_with_hints, JoinOptions, ManifestError};

    let lookup = match lookup_path_with_hints(fetcher, &reference, path, feed_hints).await {
        Ok(r) => r,
        Err(ManifestError::NotAManifest) => {
            return Err(AttemptError::Permanent(format!(
                "{} is not a mantaray manifest; try `antctl get` (raw chunk) or fetch via /bytes",
                hex::encode(reference)
            )));
        }
        Err(e) => {
            let message = format!("manifest lookup '{path}': {e}");
            return Err(if is_manifest_transient(&e) {
                AttemptError::Transient(message)
            } else {
                AttemptError::Permanent(message)
            });
        }
    };
    debug!(
        target: "ant_p2p",
        manifest = %hex::encode(reference),
        path = %path,
        data_ref = %hex::encode(&lookup.data_ref),
        content_type = ?lookup.content_type,
        "manifest resolved",
    );
    let filename = lookup
        .metadata
        .get("Filename")
        .cloned()
        .or_else(|| derive_filename_from_path(path));
    let cap = clamp_max_bytes(max_bytes);

    // Encrypted manifest entry (64-byte `address ‖ key`): the body is
    // decrypt-joined in one buffered pass.
    if let Ok(enc_ref) =
        <[u8; ant_retrieval::ENCRYPTED_REF_SIZE]>::try_from(lookup.data_ref.as_slice())
    {
        let data = ant_retrieval::join_encrypted(fetcher, enc_ref, cap)
            .await
            .map_err(|e| {
                let message = format!("join encrypted data {}: {e}", hex::encode(enc_ref));
                if is_join_transient(&e) {
                    AttemptError::Transient(message)
                } else {
                    AttemptError::Permanent(message)
                }
            })?;
        return Ok((data, lookup.content_type, filename));
    }
    let data_ref: [u8; 32] = lookup
        .data_ref
        .as_slice()
        .try_into()
        .map_err(|_| AttemptError::Permanent("manifest entry has invalid width".to_string()))?;

    // Reuse the same fetcher so the blacklist / peer ordering carries
    // over from the manifest walk into the file-body fetch. Data-root
    // fetch falls back to the dispersed replicas of redundant uploads.
    let root = ant_retrieval::fetch_root_with_replicas(
        fetcher,
        data_ref,
        ant_retrieval::accounting::CREDIT_WAIT_BUDGET,
    )
    .await
    .map_err(|e| {
        AttemptError::Transient(format!("fetch data root {}: {e}", hex::encode(data_ref)))
    })?;
    // Manifest chunks already showed up in the tracker as raw bytes;
    // we only learn the *file*'s size once the data root lands. Set
    // it now so the client's progress bar gets a real denominator
    // for the second half of the request.
    if let Some(total) = root_span_to_u64(&root) {
        tracker.set_total_bytes(total);
    }
    let join_options = JoinOptions {
        allow_degraded_redundancy,
    };
    let data = join_with_options(fetcher, &root, cap, join_options)
        .await
        .map_err(|e| {
            let message = format!("join data {}: {e}", hex::encode(data_ref));
            if is_join_transient(&e) {
                AttemptError::Transient(message)
            } else {
                AttemptError::Permanent(message)
            }
        })?;
    Ok((data, lookup.content_type, filename))
}

/// `/bzz/<ref>` or `/bzz/<ref>/`: no path below the reference.
fn is_bare_root_path(path: &str) -> bool {
    path.trim_matches('/').is_empty()
}

/// Should `run_stream_bzz` retry this `lookup_path` failure?
///
/// Everything [`is_manifest_transient`] retries, plus — for a bare
/// root only — an erasure-recovery failure. On a bare root that error
/// comes from the walk still deciding whether the reference is a
/// manifest at all, and a recovery that ran out of reachable shards
/// (typically "no BZZ peers available" on a cold or thin peer set) is a
/// fetch problem the next attempt can clear, not a property of the
/// content. Answering it with an immediate 404 is what made Freedom's
/// first `bzz://<raw-ref>/` load fail where `/bytes/<ref>` succeeded
/// (#113). With a path, the reference must be a manifest and the
/// existing classification (recovery failures are terminal) stands.
fn is_bzz_lookup_transient(e: &ant_retrieval::ManifestError, bare_root: bool) -> bool {
    is_manifest_transient(e)
        || (bare_root
            && matches!(
                e,
                ant_retrieval::ManifestError::Fetch(ant_retrieval::JoinError::Recovery { .. })
            ))
}

/// Should `run_stream_bzz` retry a failed manifest lookup (budget and
/// attempt count aside)? A transient fetch failure is retried unless its
/// miss is final ([`is_final_miss`]), or unless the failing node's
/// dispersed-replica sweep missed only transiently in this attempt
/// ([`ant_retrieval::ReplicaSweeps::swept_transiently`]): a replica-only
/// node (#154) is a corroborated direct miss by construction, so the
/// direct error alone would end the request with a 404 although the
/// next attempt's sweep can still recover it (R3-M1 on PR #155).
fn is_bzz_lookup_retryable(
    e: &ant_retrieval::ManifestError,
    bare_root: bool,
    sweeps: &ant_retrieval::ReplicaSweeps,
) -> bool {
    is_bzz_lookup_transient(e, bare_root) && (!is_final_miss(e) || sweeps.swept_transiently(e))
}

/// Terminal ack for a manifest lookup `run_stream_bzz` gives up on.
/// [`pre_stream_failure_ack`], except that a failure on a node whose
/// dispersed-replica sweep missed only transiently in the last attempt
/// (`swept_transiently`, [`ant_retrieval::ReplicaSweeps::swept_transiently`])
/// is `NotReady` (503), not `NotFound` (404): a replica-only node (#154)
/// is a corroborated direct miss by construction, so the direct error
/// alone would read as final although [`is_bzz_lookup_retryable`] just
/// classed the same miss as recoverable, and the content may well be
/// retrievable once the sweep's pool clears (R4-M1 on PR #155).
fn bzz_lookup_failure_ack(
    message: String,
    e: &ant_retrieval::ManifestError,
    swept_transiently: bool,
) -> ControlAck {
    match pre_stream_failure_ack(message, e) {
        ControlAck::NotFound { message } if swept_transiently => ControlAck::NotReady { message },
        ack => ack,
    }
}

/// Error for `/bzz/<raw-bytes-ref>/<path>`: raw bytes have no paths, so
/// the path is not found. Phrased as a manifest path miss so the gateway
/// answers bee's `404 "path address not found"` (`map_retrieval_error`)
/// rather than a 502, which hosts like Freedom treat as retryable and
/// retry for most of a minute (#113).
fn path_below_raw_bytes_message(reference: &[u8], path: &str) -> String {
    format!(
        "path '{}' not found: {} is raw bytes, not a mantaray manifest",
        path.trim_start_matches('/'),
        hex::encode(reference)
    )
}

/// Lookup for a `/bzz/<ref>` whose root is not a manifest: the
/// reference itself is the data, served as `/bytes/<ref>` would serve
/// it. Lets `bzz://<ref>/` load raw uploads in hosts that only proxy
/// `/bzz/` (Freedom, #111). Only the bare reference qualifies; a path
/// below raw bytes names nothing.
fn raw_bytes_lookup(reference: &[u8], path: &str) -> Option<ant_retrieval::LookupResult> {
    if !is_bare_root_path(path) {
        return None;
    }
    Some(ant_retrieval::LookupResult {
        data_ref: reference.to_vec(),
        content_type: None,
        metadata: HashMap::new(),
        feed: None,
    })
}

/// The feed update a `/bzz` lookup resolved through, in the shape
/// [`ControlAck::BzzStreamStart`] carries to the gateway (#161).
fn bzz_feed(feed: Option<ant_retrieval::ResolvedFeed>) -> Option<ant_control::BzzFeed> {
    feed.map(|f| ant_control::BzzFeed {
        index: f.index,
        v2: f.v2,
    })
}

/// Heuristic fallback: if mantaray didn't carry a `Filename` metadata
/// key (some uploaders skip it), use the last segment of the request
/// path so `antctl get -o` can still pick a sensible default.
fn derive_filename_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .rsplit('/')
        .next()
        .map(std::string::ToString::to_string)
}

/// Drain the hint queue into live libp2p dials until we hit either the peer
/// target or the per-iteration batch cap. Bounded dial fan-out keeps us from
/// swamping the local TCP stack when a bootnode gossips 30 peers at once.
fn fill_pipeline_from_hints(swarm: &mut Swarm<AntBehaviour>, state: &mut SwarmState) {
    let mut dialed = 0usize;
    while dialed < HINT_DIAL_BATCH && state.pipeline_size() < state.target_peers {
        let Some(hint) = state.pop_dialable_hint() else {
            break;
        };
        if swarm.is_connected(&hint.peer_id) {
            continue;
        }
        let Some(addrs) = state.addrs_for_dial(&hint) else {
            // Nothing dialable on the current networks (e.g. a same-LAN
            // hint after moving to cellular, before the snapshot purge
            // ran): forget the dedup so gossip can re-queue the peer once
            // it is reachable again.
            state.seen_hints.remove(&hint.peer_id);
            continue;
        };
        let opts = DialOpts::peer_id(hint.peer_id)
            .addresses(addrs.clone())
            .build();
        let peer_id = hint.peer_id;
        match swarm.dial(opts) {
            Ok(()) => {
                state.dialing.insert(peer_id);
                state.note_dial_started(peer_id);
                state.failed.retain(|f| f.peer != peer_id);
                if let Some(a) = addrs.first() {
                    state.dial_hint_addr.insert(peer_id, a.clone());
                }
                dialed += 1;
                debug!(
                    target: "ant_p2p",
                    peer = %peer_id,
                    addrs = addrs.len(),
                    "dialing hive hint",
                );
            }
            Err(DialError::DialPeerConditionFalse(_)) => {}
            Err(e) => {
                debug!(target: "ant_p2p", peer = %peer_id, "hint dial error: {e}");
            }
        }
    }
}

/// Dial the closest known-but-unconnected peers toward `target` (a chunk
/// address), so a subsequent pushsync lands inside the chunk's
/// neighbourhood instead of relying on a possibly-shallow forwarding chain.
///
/// This is the on-demand counterpart to a full bee node's saturated
/// Kademlia: a light node connects to ~100 roughly-random peers, so for
/// most chunks its closest *connected* peer is shallow and pushes draw
/// shallow receipts (the chunk lands on the wrong neighbourhood and an
/// independent gateway can't retrieve it). When the upload path detects it
/// has no connected peer close enough to a chunk, it asks us to dial
/// peers we've learned about via hive whose overlay *is* close to that
/// chunk. We only dial peers strictly deeper than our current best
/// connected peer (so we always improve coverage), capped at
/// [`NEIGHBORHOOD_DIAL_FANOUT`] per request, and only while the pipeline
/// has [`NEIGHBORHOOD_DIAL_MARGIN`] headroom over `target_peers`.
fn dial_toward_target(swarm: &mut Swarm<AntBehaviour>, state: &mut SwarmState, target: Overlay) {
    if state.pipeline_size() >= state.target_peers + NEIGHBORHOOD_DIAL_MARGIN {
        return;
    }
    // Proximity of our current best *connected* peer to the target. We only
    // bother dialing peers that would sit strictly deeper than this.
    let best_connected_po = state
        .routing
        .closest_peer(&target, &[])
        .map_or(0, |(_, overlay)| {
            crate::routing::proximity(&target, &overlay)
        });

    // Rank known-but-unconnected peers by proximity to the target, deepest
    // first, keeping only those that improve on what we already have.
    let mut candidates: Vec<(PeerId, u8)> = state
        .known_dialable
        .iter()
        .filter(|(pid, _)| {
            !state.bzz_peers.contains(*pid)
                && !state.dialing.contains(*pid)
                && !state.pending.contains_key(*pid)
                && !state.dial_backed_off(pid)
        })
        .map(|(pid, hint)| (*pid, crate::routing::proximity(&target, &hint.overlay)))
        .filter(|(_, po)| *po > best_connected_po)
        .collect();
    if candidates.is_empty() {
        return;
    }
    candidates.sort_by_key(|c| std::cmp::Reverse(c.1));
    debug!(
        target: "ant_p2p",
        target = %hex::encode(target),
        known_dialable = state.known_dialable.len(),
        best_connected_po,
        candidates = candidates.len(),
        deepest = candidates.first().map_or(0, |c| c.1),
        "neighbourhood dial request",
    );
    candidates.truncate(NEIGHBORHOOD_DIAL_FANOUT);

    for (peer_id, po) in candidates {
        let Some(hint) = state.known_dialable.get(&peer_id).cloned() else {
            continue;
        };
        if swarm.is_connected(&peer_id) {
            continue;
        }
        let Some(addrs) = state.addrs_for_dial(&hint) else {
            continue;
        };
        let opts = DialOpts::peer_id(peer_id).addresses(addrs.clone()).build();
        match swarm.dial(opts) {
            Ok(()) => {
                state.dialing.insert(peer_id);
                state.note_dial_started(peer_id);
                state.failed.retain(|f| f.peer != peer_id);
                if let Some(a) = addrs.first() {
                    state.dial_hint_addr.insert(peer_id, a.clone());
                }
                debug!(
                    target: "ant_p2p",
                    peer = %peer_id,
                    po,
                    target = %hex::encode(target),
                    "dialing toward chunk neighbourhood",
                );
            }
            Err(DialError::DialPeerConditionFalse(_)) => {}
            Err(e) => {
                debug!(target: "ant_p2p", peer = %peer_id, "neighbourhood dial error: {e}");
            }
        }
    }
}

/// Re-warm the dial pipeline + re-bootstrap when sustained connection churn
/// drops the peer set below half of `target_peers`. Without this, peers
/// disconnected by remote-side close (bee's "load shedding" under sustained
/// pushsync pressure being the canonical trigger) are never re-dialed:
///
/// * `seen_hints` permanently dedups every peer we've ever queued, so the
///   same peer cannot re-enter the queue via fresh hive gossip,
/// * the hint queue drains naturally (every entry is consumed by
///   `fill_pipeline_from_hints`),
/// * `maybe_rebootstrap` only fires when the entire pipeline is empty —
///   one surviving BZZ peer keeps it parked.
///
/// Observable failure mode before this guard: the peer set slid from 100 →
/// ~15 mid-upload, never recovered without a daemon restart, and the upload
/// died with `pushsync: no peers`.
fn maybe_top_up_peers(
    bootnodes: &[Multiaddr],
    state: &mut SwarmState,
    peerstore: &PeerStore,
    last_top_up_at: &mut Instant,
    local_peer_id: PeerId,
    bootnode_dial_tx: &mpsc::Sender<Multiaddr>,
) {
    let floor = state.target_peers / 2;
    let before = state.peer_set_size();
    if floor == 0 || before >= floor {
        return;
    }
    if last_top_up_at.elapsed() < PEER_TOP_UP_INTERVAL {
        return;
    }
    *last_top_up_at = Instant::now();
    // Clear the dedup so peers we've previously connected to (and lost) can
    // re-enter the queue. `enqueue_hint` still filters out peers that are
    // currently `bzz_peers` / `pending` / `dialing`, so a wholesale clear is
    // safe — surviving connections aren't disturbed. After a full collapse
    // (no bzz peer left) the backoffs were most likely earned while our own
    // link was failing, so forget them for the peers being re-warmed.
    let collapsed = state.bzz_peers.is_empty();
    let warmed = state.rewarm_from_peerstore(peerstore, local_peer_id, collapsed);
    info!(
        target: "ant_p2p",
        peer_set_size = before,
        target = state.target_peers,
        floor,
        warmed,
        "peer set below floor; re-warming dial queue + re-bootstrapping",
    );
    if !bootnodes.is_empty() {
        spawn_bootstrap_dial(bootnodes, bootnode_dial_tx.clone());
    }
}

/// Force a post-suspension recovery, driven by an explicit
/// [`ControlCommand::Resume`] or by the liveness pass's self-heal on a
/// streak of retrieval link failures ([`maintain_liveness`]). Re-warms the dial queue from the on-disk
/// peerstore and fires a fresh bootstrap dial **unconditionally** — unlike
/// [`maybe_top_up_peers`] / [`maybe_rebootstrap`], which only fire once the
/// peer *count* has visibly collapsed.
///
/// The count gate is exactly what wedges an embedded node after a long OS
/// suspension (iOS background reap): the kernel sockets are dead but libp2p
/// hasn't seen the FIN, so `bzz_peers` still looks full and neither
/// automatic guard fires — the node sits on a swarm of zombies and the next
/// retrieval hangs. Bypassing the gate re-opens live sockets to the
/// bootnodes (and, through their hive gossip, the wider set) in parallel,
/// so retrieval has working routes again; the liveness pass closes the
/// dead connections once they miss their pongs.
///
/// Returns the number of warm peer hints re-queued. Surviving connections
/// are left untouched: re-warming only enqueues hints (`enqueue_hint` skips
/// peers that are already `bzz` / `pending` / `dialing`), and the bootnode
/// dial path skips peers we're already connected to — so a healthy
/// short-background resume is close to a no-op rather than a full
/// re-handshake.
#[allow(clippy::too_many_arguments)]
fn force_resume(
    bootnodes: &[Multiaddr],
    state: &mut SwarmState,
    peerstore: &PeerStore,
    backoff: &mut Duration,
    last_bootstrap_at: &mut Instant,
    last_top_up_at: &mut Instant,
    local_peer_id: PeerId,
    bootnode_dial_tx: &mpsc::Sender<Multiaddr>,
) -> usize {
    // Re-queue the peerstore and forget those peers' dial backoff: an
    // explicit resume after an outage must redial known-good peers now,
    // not after backoffs earned while our own link was down expire.
    let warmed = state.rewarm_from_peerstore(peerstore, local_peer_id, true);
    // Our link may have changed under the connections we still hold:
    // don't charge the dials this fires to the peers until some
    // connection answers again (issue #90).
    state.liveness.suspect_network(Instant::now());
    // Unpark the automatic guards: reset the bootstrap backoff and rewind
    // both cadence clocks so the loop-top maintenance can re-fire
    // immediately if this resume doesn't fully recover the set on its own.
    *backoff = MIN_BACKOFF;
    *last_bootstrap_at = Instant::now()
        .checked_sub(MIN_BACKOFF)
        .unwrap_or_else(Instant::now);
    *last_top_up_at = Instant::now()
        .checked_sub(PEER_TOP_UP_INTERVAL)
        .unwrap_or_else(Instant::now);
    if !bootnodes.is_empty() {
        spawn_bootstrap_dial(bootnodes, bootnode_dial_tx.clone());
    }
    info!(
        target: "ant_p2p",
        warmed,
        peer_set_size = state.peer_set_size(),
        "resume: re-warmed dial queue + fired bootstrap re-dial",
    );
    warmed
}

/// Pick known-but-unconnected peers to dial into under-populated shallow
/// bins. Pure selection (no swarm access) so the policy is unit-testable:
/// for each bin `0..BIN_BALANCE_MAX_BIN` whose *connected* count is below
/// [`BIN_BALANCE_MIN_PEERS`], pick up to the deficit from `known_dialable`
/// entries that land in that bin relative to `base`, skipping anything
/// `exclude` rejects (connected / mid-pipeline / recently failed). Total
/// output is capped at [`BIN_BALANCE_DIAL_CAP`].
fn bin_balance_candidates(
    base: &Overlay,
    bin_counts: &[u8; crate::routing::NUM_BINS],
    known_dialable: &HashMap<PeerId, sinks::PeerHint>,
    exclude: impl Fn(&PeerId) -> bool,
) -> Vec<(PeerId, u8)> {
    let mut deficits = [0usize; BIN_BALANCE_MAX_BIN];
    let mut total_deficit = 0usize;
    for (bin, deficit) in deficits.iter_mut().enumerate() {
        *deficit = BIN_BALANCE_MIN_PEERS.saturating_sub(bin_counts[bin] as usize);
        total_deficit += *deficit;
    }
    if total_deficit == 0 {
        return Vec::new();
    }
    let mut out: Vec<(PeerId, u8)> = Vec::new();
    for (peer_id, hint) in known_dialable {
        if out.len() >= BIN_BALANCE_DIAL_CAP {
            break;
        }
        let po = crate::routing::proximity(base, &hint.overlay) as usize;
        if po >= BIN_BALANCE_MAX_BIN || deficits[po] == 0 || exclude(peer_id) {
            continue;
        }
        deficits[po] -= 1;
        out.push((*peer_id, po as u8));
    }
    out
}

/// Periodic bin-balance pass: keep every shallow Kademlia bin minimally
/// populated so retrieval can route into *any* neighbourhood.
///
/// Without this, a long-running node's peer set slowly collapses into its
/// own neighbourhood: bee's hive gossip advertises peers close to the
/// *receiver*, so every churn-driven replacement dial is drawn from a
/// near-biased pool, and far peers that disconnect are never re-dialed.
/// Observable end state (vibing.at gateway after days of uptime): all ~180
/// connected overlays shared the node's own first nibble, retrieval of any
/// chunk outside that /16 fast-failed, and the public gateway 404'd content
/// that the rest of the network served fine. Count-based maintenance
/// ([`maybe_top_up_peers`]) can't see this — the peer *count* stays healthy
/// while the *distribution* degenerates.
fn maybe_balance_bins(
    swarm: &mut Swarm<AntBehaviour>,
    state: &mut SwarmState,
    last_balance_at: &mut Instant,
) {
    if last_balance_at.elapsed() < BIN_BALANCE_INTERVAL {
        return;
    }
    // Below the floor the count-based top-up + re-bootstrap own recovery;
    // balancing a near-empty table would just race them for dial slots.
    if state.peer_set_size() < state.target_peers / 2 {
        return;
    }
    if state.pipeline_size() >= state.target_peers + NEIGHBORHOOD_DIAL_MARGIN {
        return;
    }
    *last_balance_at = Instant::now();
    let bin_counts = state.routing.bin_counts();
    let candidates = bin_balance_candidates(
        state.routing.base(),
        &bin_counts,
        &state.known_dialable,
        |peer_id| {
            state.bzz_peers.contains(peer_id)
                || state.pending.contains_key(peer_id)
                || state.dialing.contains(peer_id)
                || state.closing.contains(peer_id)
                || state.failed.iter().any(|f| f.peer == *peer_id)
                || state.dial_backed_off(peer_id)
        },
    );
    if candidates.is_empty() {
        return;
    }
    info!(
        target: "ant_p2p",
        dials = candidates.len(),
        bins = ?candidates.iter().map(|(_, b)| *b).collect::<Vec<_>>(),
        "bin balance: dialing peers into under-populated shallow bins",
    );
    for (peer_id, bin) in candidates {
        let Some(hint) = state.known_dialable.get(&peer_id).cloned() else {
            continue;
        };
        if swarm.is_connected(&peer_id) {
            continue;
        }
        let Some(addrs) = state.addrs_for_dial(&hint) else {
            continue;
        };
        let opts = DialOpts::peer_id(peer_id).addresses(addrs.clone()).build();
        match swarm.dial(opts) {
            Ok(()) => {
                state.dialing.insert(peer_id);
                state.note_dial_started(peer_id);
                if let Some(a) = addrs.first() {
                    state.dial_hint_addr.insert(peer_id, a.clone());
                }
                debug!(target: "ant_p2p", peer = %peer_id, bin, "dialing for bin balance");
            }
            Err(DialError::DialPeerConditionFalse(_)) => {}
            Err(e) => {
                debug!(target: "ant_p2p", peer = %peer_id, "bin-balance dial error: {e}");
            }
        }
    }
}

/// Fire a fresh bootstrap dial when we've fully drained: no BZZ-handshaked
/// peers, nothing mid-pipeline, nothing queued. Uses exponential backoff so a
/// cold DNS + dead bootnode region doesn't turn into a tight retry loop.
fn maybe_rebootstrap(
    bootnodes: &[Multiaddr],
    state: &SwarmState,
    backoff: &mut Duration,
    last_at: &mut Instant,
    bootnode_dial_tx: &mpsc::Sender<Multiaddr>,
) {
    if bootnodes.is_empty()
        || !state.bzz_peers.is_empty()
        || !state.pending.is_empty()
        || !state.dialing.is_empty()
        || !state.hint_queue.is_empty()
    {
        return;
    }
    if last_at.elapsed() < *backoff {
        return;
    }
    *last_at = Instant::now();
    spawn_bootstrap_dial(bootnodes, bootnode_dial_tx.clone());
    *backoff = bump_backoff(*backoff);
}

fn bump_backoff(backoff: Duration) -> Duration {
    (backoff * 2).min(MAX_BACKOFF)
}

/// Route a `SwarmEvent` into the pipeline. Everything that mutates state
/// lives here; the status snapshot has already been updated via
/// `observe_event` by the time we're called.
#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    swarm: &mut Swarm<AntBehaviour>,
    state: &mut SwarmState,
    status: Option<&watch::Sender<StatusSnapshot>>,
    control: &mut Control,
    hs_params: &HandshakeParams,
    result_tx: &mpsc::Sender<(PeerId, DriveOutcome)>,
    peerstore: &mut PeerStore,
    ev: SwarmEvent<AntBehaviourEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } if !is_loopback_multiaddr(&address) => {
            // Advertise non-loopback listeners as external addresses so that
            // our identify message carries usable `listen_addrs`. Without this
            // bee's inbound handshake handler waits 10 s in `peerMultiaddrs`
            // for our peerstore entry to populate.
            record_external_address(state, swarm, status, address, ExternalAddrSource::Listener);
        }
        // rust-libp2p's identify surfaces each remote's `observed_addr` as
        // a candidate here. Promote globally-routable ones to confirmed
        // external addresses so the next outbound identify carries our
        // NAT-punched public multiaddr and bee's peerstore accepts it.
        SwarmEvent::NewExternalAddrCandidate { address }
            if is_globally_routable_multiaddr(&address) =>
        {
            record_external_address(state, swarm, status, address, ExternalAddrSource::Observed);
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            state
                .liveness
                .on_established(connection_id, peer_id, Instant::now());
            state.dialing.remove(&peer_id);
            state.dial_hint_addr.remove(&peer_id);
            state.failed.retain(|f| f.peer != peer_id);
            state.dial_backoff.remove(&peer_id);
            // Only dialer connections need our outbound BZZ handshake — bee
            // initiates the handshake over the listener direction itself.
            // An inbound connection leaves `dial_started` alone: a tracked
            // dial of ours still in flight resolves with its own
            // `ConnectionEstablished { Dialer }` or `OutgoingConnectionError`,
            // and that event clears it.
            let ConnectedPoint::Dialer { address, .. } = endpoint else {
                return;
            };
            // Our dial resolved: drop its start markers before any early
            // return, so a stale `dial_started_unproven` / start time can't
            // later exempt an unrelated (untracked) dial failure to this peer.
            let dial_ms = state
                .dial_started
                .remove(&peer_id)
                .map(|t| t.elapsed().as_millis() as u64);
            state.dial_started_unproven.remove(&peer_id);
            if state.bzz_peers.contains(&peer_id) || state.pending.contains_key(&peer_id) {
                // Duplicate connection (race with a hint or a bootnode retry);
                // keep the existing pipeline entry and let the new connection
                // get GC'd by libp2p's inactivity timeout if nothing uses it.
                return;
            }
            let (tx, rx) = oneshot::channel();
            state.pending.insert(
                peer_id,
                PendingPhase::AwaitingIdentify {
                    sig: tx,
                    addr: address.clone(),
                    identify_started: Instant::now(),
                    dial_ms,
                },
            );
            let listen_addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
            let our_identify_useful = our_identify_useful_for_bee(swarm);
            spawn_handshake_driver(
                peer_id,
                address,
                listen_addrs,
                control.clone(),
                hs_params.clone(),
                rx,
                result_tx.clone(),
                our_identify_useful,
            );
        }
        SwarmEvent::Behaviour(AntBehaviourEvent::Identify(identify::Event::Sent {
            peer_id,
            ..
        })) => {
            // Bee's inbound handshake calls `peerMultiaddrs` and blocks up to
            // 10 s on the peerstore being populated. `Event::Sent` is our
            // signal that we've pushed our identify to the remote, so it's
            // now safe to open the BZZ stream.
            if let Some(PendingPhase::AwaitingIdentify {
                sig,
                addr,
                identify_started,
                dial_ms,
            }) = state.pending.remove(&peer_id)
            {
                let identifying_ms = identify_started.elapsed().as_millis() as u64;
                state.pending.insert(
                    peer_id,
                    PendingPhase::Handshaking {
                        addr,
                        handshake_started: Instant::now(),
                        dial_ms,
                        identifying_ms,
                    },
                );
                let _ = sig.send(());
                trace!(target: "ant_p2p", %peer_id, "identify sent; unblocking handshake");
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            num_established,
            cause,
            ..
        } => {
            state.liveness.on_closed(connection_id);
            if num_established > 0 {
                // Another connection to this peer is still open (a dial
                // race left a duplicate, or liveness closed a dead one
                // next to a live one): the peer, its BZZ session and its
                // routing entry stay. The closed connection may have
                // carried a SWAP cheque stream, though, so its payment
                // must not count as delivered: a new session for the
                // peer makes `PushsyncSwap`'s delivery check fail for
                // any cheque in flight (the EOA stays).
                state.peer_eth.renew_session(&peer_id);
                debug!(
                    target: "ant_p2p",
                    %peer_id,
                    num_established,
                    "one of the peer's connections closed; peer stays connected",
                );
                return;
            }
            state.closing.remove(&peer_id);
            state.dial_hint_addr.remove(&peer_id);
            let was_pending = state.pending.remove(&peer_id).is_some();
            let was_bzz = state.bzz_peers.remove(&peer_id);
            state.ready_in_ms.remove(&peer_id);
            // Drop the routing entry alongside `bzz_peers`; otherwise the
            // forwarder would keep picking a peer we have no live
            // connection to.
            state.routing.forget(&peer_id);
            state.routing_admitted_at.remove(&peer_id);
            // Drop the accounting mirror for this peer too: bee's
            // `notifyPeerConnect` resets the `accountingPeer` on
            // reconnect, so our balance must reset alongside.
            // Without this, a peer that flapped the connection would
            // come back in our peerstore with stale debt and we'd
            // refuse to dispatch to it for ~1 s for no reason.
            if let Some(acc) = state.accounting.as_ref() {
                acc.forget(&peer_id);
            }
            // (Pushsync debt lives in that same mirror since #127.)
            // Drop the EOA registry entry too — a reconnected peer
            // re-runs the BZZ handshake and re-records its beneficiary,
            // so a stale entry can only mislead — and with it the
            // connection's session, which tells a SWAP payment in flight
            // that its connection is gone (`PushsyncSwap`'s delivery
            // check). Idempotent on peers we never had a handshake for.
            state.peer_eth.forget(&peer_id);
            state.publish_peers();
            // Keep the status snapshot's routing size in step with the
            // table: `/readiness` reads it, and must go back to 503 as
            // soon as the last peer drops, not at the next pipeline tick.
            sync_routing_snapshot(status, state);
            if was_bzz {
                info!(
                    target: "ant_p2p",
                    %peer_id,
                    cause = ?cause,
                    "peer disconnected; peer set size={}",
                    state.peer_set_size(),
                );
            } else if was_pending {
                if let Some(err) = cause {
                    debug!(
                        target: "ant_p2p",
                        %peer_id,
                        "connection closed during handshake: {err}",
                    );
                } else {
                    debug!(
                        target: "ant_p2p",
                        %peer_id,
                        "connection closed during handshake",
                    );
                }
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            if let Some(p) = peer_id {
                note_outgoing_dial_error(state, peerstore, p);
            }
            // Bootnode dial failures are noisy during rotation; demote to
            // debug once we're past the cold start (peer set > 0).
            if state.bzz_peers.is_empty() && state.pending.is_empty() {
                warn!(target: "ant_p2p", peer = ?peer_id, "dial error: {error}");
            } else {
                debug!(target: "ant_p2p", peer = ?peer_id, "dial error: {error}");
            }
        }
        SwarmEvent::Behaviour(AntBehaviourEvent::Upnp(ev)) => {
            handle_upnp_event(state, swarm, status, ev);
        }
        SwarmEvent::Behaviour(AntBehaviourEvent::Ping(ev)) => {
            handle_ping_event(swarm, state, ev);
        }
        _ => {}
    }
}

/// Feed one ping result into [`SwarmState::liveness`] (issue #83). A
/// pong refreshes the connection. A reported failure closes it: the
/// ping handler stays quiet about a single failed ping and reports only
/// the second in a row, so this is a connection that stopped answering
/// rather than one slow pong. A peer that doesn't speak ping is left
/// alone.
fn handle_ping_event(swarm: &mut Swarm<AntBehaviour>, state: &mut SwarmState, ev: ping::Event) {
    match ev.result {
        Ok(rtt) => {
            trace!(target: "ant_p2p", peer = %ev.peer, ?rtt, "pong");
            state.liveness.on_pong(ev.connection, Instant::now());
        }
        Err(ping::Failure::Unsupported) => {
            debug!(target: "ant_p2p", peer = %ev.peer, "peer doesn't support ping; not judging its liveness");
            state.liveness.on_ping_unsupported(ev.connection);
        }
        Err(e) => {
            info!(
                target: "ant_p2p",
                peer = %ev.peer,
                "closing dead connection: two pings in a row failed ({e})",
            );
            if swarm.close_connection(ev.connection) {
                state.liveness.on_closing(ev.connection);
            }
        }
    }
}

/// Connection liveness pass (issue #83), run from the loop top at most
/// every [`LIVENESS_PASS_INTERVAL`]:
///
/// 1. notice a frozen process (see [`Liveness::tick`]);
/// 2. close connections that stopped answering pings, so their peers
///    leave routing and the top-up guards redial;
/// 3. self-heal on a streak of retrieval link failures: close every
///    connection that hasn't answered within the liveness window and do
///    what `ControlCommand::Resume` does ([`force_resume`]), at most once
///    per [`LivenessConfig::self_heal_cooldown`];
/// 4. publish which connected peers are stale, so `peers.connected`
///    (`ant_peer_count`) counts only live ones. `/readiness` reads
///    `RoutingInfo::serving`, which skips stale peers itself
///    ([`serving_peer_count`]).
#[allow(clippy::too_many_arguments)]
fn maintain_liveness(
    swarm: &mut Swarm<AntBehaviour>,
    state: &mut SwarmState,
    status: Option<&watch::Sender<StatusSnapshot>>,
    bootnodes: &[Multiaddr],
    peerstore: &PeerStore,
    backoff: &mut Duration,
    last_bootstrap_at: &mut Instant,
    last_top_up_at: &mut Instant,
    local_peer_id: PeerId,
    bootnode_dial_tx: &mpsc::Sender<Multiaddr>,
) {
    let now = Instant::now();
    if state.liveness.tick(now) {
        info!(
            target: "ant_p2p",
            "swarm loop resumed after a stall; re-verifying every connection by ping",
        );
    }
    close_dead_connections(swarm, state, now);
    let streak = state.retrieval_counters.link_failure_streak();
    if state.liveness.take_self_heal(streak, now) {
        state.retrieval_counters.reset_link_failure_streak();
        let stale = state.liveness.stale_connections(now);
        for (conn, _) in &stale {
            if swarm.close_connection(*conn) {
                state.liveness.on_closing(*conn);
            }
        }
        info!(
            target: "ant_p2p",
            streak,
            closed = stale.len(),
            "retrievals failing on the link; closed unanswering connections, redialing",
        );
        force_resume(
            bootnodes,
            state,
            peerstore,
            backoff,
            last_bootstrap_at,
            last_top_up_at,
            local_peer_id,
            bootnode_dial_tx,
        );
    }
    publish_liveness(status, &state.liveness, now);
}

/// Close every connection [`Liveness::dead_connections`] names.
///
/// Each is closed once: `close_connection` only *starts* the close, and
/// the connection stays in the swarm until the muxer's close finishes
/// (bounded by [`crate::bounded_close::CLOSE_TIMEOUT`]), so the
/// connection is marked closing rather than named again next pass.
fn close_dead_connections(swarm: &mut Swarm<AntBehaviour>, state: &mut SwarmState, now: Instant) {
    for (conn, peer) in state.liveness.dead_connections(now) {
        if swarm.close_connection(conn) {
            state.liveness.on_closing(conn);
            info!(
                target: "ant_p2p",
                %peer,
                "closing dead connection: no pong within the liveness window",
            );
        }
    }
}

/// Mark the stale rows of `connected_peers` and recount
/// `peers.connected` from the rest. Publishes only on a change.
fn publish_liveness(
    status: Option<&watch::Sender<StatusSnapshot>>,
    liveness: &Liveness,
    now: Instant,
) {
    let Some(s) = status else {
        return;
    };
    let stale: HashSet<String> = liveness
        .stale_peers(now)
        .iter()
        .map(ToString::to_string)
        .collect();
    s.send_if_modified(|st| {
        let mut changed = false;
        for p in &mut st.peers.connected_peers {
            let is_stale = stale.contains(&p.peer_id);
            if p.stale != is_stale {
                p.stale = is_stale;
                changed = true;
            }
        }
        let connected = PeerInfo::live_connected_count(&st.peers.connected_peers);
        if st.peers.connected != connected {
            st.peers.connected = connected;
            changed = true;
        }
        changed
    });
}

/// Finalize the per-peer pipeline result. `Ok` promotes the peer to
/// `bzz_peers`; anything else disconnects, which in turn drives
/// `ConnectionClosed` cleanup.
#[allow(clippy::too_many_arguments)]
fn handle_drive_outcome(
    cfg: &RunConfig,
    swarm: &mut Swarm<AntBehaviour>,
    state: &mut SwarmState,
    peer_agents: &HashMap<PeerId, String>,
    backoff: &mut Duration,
    peerstore: &mut PeerStore,
    peer: PeerId,
    outcome: DriveOutcome,
) {
    // Pull the dialed addr out of pending before we drop the entry: it's the
    // multiaddr we want to persist for redial. Entry may already be gone if
    // ConnectionClosed beat us here (e.g. bee dropped us mid-handshake).
    let pending_removed = state.pending.remove(&peer);
    let dialed_addr = pending_removed.as_ref().map(PendingPhase::dialed_addr);
    let pipeline_ms = match &pending_removed {
        Some(PendingPhase::Handshaking {
            handshake_started,
            dial_ms,
            identifying_ms,
            ..
        }) => Some(OutboundPipelineMs {
            dial_ms: *dial_ms,
            identifying_ms: *identifying_ms,
            handshake_ms: handshake_started.elapsed().as_millis() as u64,
        }),
        _ => None,
    };
    match outcome {
        DriveOutcome::Ok(info) => {
            let first_bzz_in_session = state.bzz_peers.is_empty();
            state.bzz_peers.insert(peer);
            // Now connected: drop it from the dial book so neighbourhood
            // dials don't re-target an already-connected peer.
            state.known_dialable.remove(&peer);
            if let Some(p) = pipeline_ms.as_ref() {
                let total = p.dial_ms.unwrap_or(0) + p.identifying_ms + p.handshake_ms;
                state.ready_in_ms.insert(peer, total);
                maybe_warn_bee_peerstore_stall(state, peer, p);
            }
            // The remote_overlay was just verified by `handshake_outbound`
            // (signature recovers to an Ethereum address whose overlay
            // matches the declared one), so admitting it is safe.
            state.routing.admit(peer, info.remote_overlay);
            state
                .routing_admitted_at
                .entry(peer)
                .or_insert_with(Instant::now);
            // A connected peer is also a known peer (so population is
            // always >= connected). Idempotent if hive already noted it.
            state.known.note(info.remote_overlay);
            // Record the peer's beneficiary EOA in the shared registry
            // so the pushsync-side SWAP settlement (Phase 7b) can look
            // it up later when emitting cheques. Cheap (one HashMap
            // insert behind RwLock); harmless on builds where SWAP is
            // unconfigured (registry has no consumers in that case).
            state.peer_eth.record(peer, info.remote_eth_address);
            state.publish_peers();
            let peer_set_size = state.peer_set_size();
            state.failed.retain(|f| f.peer != peer);
            *backoff = MIN_BACKOFF;
            log_handshake_ok(&info, peer_set_size, pipeline_ms);
            record_peer_session_milestones(
                cfg.status.as_ref(),
                cfg.process_start,
                first_bzz_in_session,
                peer_set_size,
                state.target_peers,
            );
            record_handshake(
                cfg.status.as_ref(),
                peer,
                &info,
                peer_agents.get(&peer).cloned(),
            );
            sync_routing_snapshot(cfg.status.as_ref(), state);
            // Persist the working dial address. We only ever record outbound
            // peers — for inbound connections we don't yet have a guaranteed-
            // reachable multiaddr, so we let those become hints via hive
            // gossip on the next start instead.
            let addrs = dialed_addr.map(|a| vec![a]).unwrap_or_default();
            // Pass the V15 fields through to the peerstore so peers.json
            // carries the signed timestamp + chequebook forward across
            // restarts. `record_success` won't downgrade V15 → V14 on a
            // subsequent V14 reconnect (see peerstore unit tests).
            let bzz_ts: u64 = u64::try_from(info.remote_timestamp).unwrap_or(0);
            peerstore.record_success(
                peer,
                addrs,
                info.remote_overlay,
                bzz_ts,
                info.remote_chequebook,
            );
            if state.bootnode_peers.contains(&peer) {
                peerstore.mark_bootnode(&peer);
            }
        }
        DriveOutcome::OpenFailed(e) => {
            debug!(target: "ant_p2p", %peer, "open handshake stream: {e}");
            mark_for_disconnect(state, swarm, peer);
            record_swarm_failure(state, peer);
            peerstore.record_failure(&peer);
        }
        DriveOutcome::HandshakeFailed(e) => {
            warn!(target: "ant_p2p", %peer, "bzz handshake failed: {e}");
            mark_for_disconnect(state, swarm, peer);
            record_swarm_failure(state, peer);
            peerstore.record_failure(&peer);
        }
    }
}

/// Tear down a peer and mark it `Closing` for the duration of the wind-down.
/// `disconnect_peer_id` returns `Err` if there is no live connection (e.g.
/// remote already closed); in that case `ConnectionClosed` won't fire and we
/// must clear `closing` ourselves to avoid a sticky pipeline row.
fn mark_for_disconnect(state: &mut SwarmState, swarm: &mut Swarm<AntBehaviour>, peer: PeerId) {
    state.closing.insert(peer);
    if swarm.disconnect_peer_id(peer).is_err() {
        state.closing.remove(&peer);
    }
}

/// Drive one peer end-to-end on a spawned tokio task. Keeping this out of
/// the main loop lets us handshake `target_peers` in parallel while the loop
/// is free to accept new events, hive hints, and result messages.
///
/// `our_identify_useful` toggles whether the identify round-trip is worth
/// waiting for: see [`our_identify_useful_for_bee`]. When `false` we still
/// poll the signal once (so we capture `identifying_ms` if `IdentifySent`
/// already fired before the spawn), but we don't block on it — bee's
/// peerstore stall is going to fire either way and adding our 3 s wait on
/// top would just stack another 3 s on every cold-start handshake.
#[allow(clippy::too_many_arguments)]
fn spawn_handshake_driver(
    peer_id: PeerId,
    dial_addr: Multiaddr,
    listen_addrs: Vec<Multiaddr>,
    mut control: Control,
    params: HandshakeParams,
    identify_signal: oneshot::Receiver<()>,
    result_tx: mpsc::Sender<(PeerId, DriveOutcome)>,
    our_identify_useful: bool,
) {
    tokio::spawn(async move {
        let wait_budget = if our_identify_useful {
            HANDSHAKE_IDENTIFY_WAIT
        } else {
            Duration::ZERO
        };
        let _ = tokio::time::timeout(wait_budget, identify_signal).await;

        // Bee 2.8.0 ships handshake `15.0.0`; 2.7.x ships `14.0.0`.
        // The mainnet is rolling through the cutover, so try V15 first
        // and fall back to V14 when the remote refuses the protocol
        // id (libp2p-stream surfaces that as an `OpenStreamError`).
        // Once a peer answers under one version we stick with that
        // version's wire schema for the rest of the handshake — the
        // sender / receiver in `handshake.rs` is parameterised on the
        // chosen version.
        let dial_addrs = vec![dial_addr];
        let attempts: [(HandshakeWireVersion, &'static str); 2] = [
            (HandshakeWireVersion::V15, PROTOCOL_HANDSHAKE_V15),
            (HandshakeWireVersion::V14, PROTOCOL_HANDSHAKE_V14),
        ];
        let mut last_open_err: Option<String> = None;
        for (version, proto_id) in attempts {
            let proto = StreamProtocol::new(proto_id);
            let stream = match control.open_stream(peer_id, proto).await {
                Ok(s) => s,
                Err(e) => {
                    last_open_err = Some(e.to_string());
                    continue;
                }
            };

            match handshake_outbound(
                stream,
                params.local_peer_id,
                peer_id,
                &params.signing_secret,
                &params.overlay_nonce,
                params.network_id,
                &dial_addrs,
                listen_addrs.clone(),
                version,
            )
            .await
            {
                Ok(info) => {
                    let _ = result_tx.send((peer_id, DriveOutcome::Ok(info))).await;
                    return;
                }
                Err(e) => {
                    // A handshake-level failure (network id, signature,
                    // timestamp gate, …) is a peer rejection, not a
                    // version mismatch — surface it and don't retry the
                    // other wire version.
                    let _ = result_tx
                        .send((peer_id, DriveOutcome::HandshakeFailed(e)))
                        .await;
                    return;
                }
            }
        }

        let _ = result_tx
            .send((
                peer_id,
                DriveOutcome::OpenFailed(
                    last_open_err.unwrap_or_else(|| "no handshake version accepted".into()),
                ),
            ))
            .await;
    });
}

/// Side-channel: keep the status snapshot and the `peer_agents` map in sync
/// without changing the flow of the main event loop.
fn observe_event(
    status: Option<&watch::Sender<StatusSnapshot>>,
    peer_agents: &mut HashMap<PeerId, String>,
    ev: &SwarmEvent<AntBehaviourEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(target: "ant_p2p", "listening on {address}");
            if let Some(s) = status {
                let ma = address.to_string();
                s.send_modify(|st| {
                    if !st.listeners.iter().any(|l| l == &ma) {
                        st.listeners.push(ma);
                    }
                });
            }
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            if let Some(s) = status {
                let ma = address.to_string();
                s.send_modify(|st| st.listeners.retain(|l| l != &ma));
            }
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            num_established,
            ..
        } => {
            if let Some(s) = status {
                let pid = *peer_id;
                let peer_id = pid.to_string();
                let (direction, address) = peer_endpoint(endpoint);
                let connected_at_unix = unix_now();
                s.send_modify(|st| {
                    let already_listed = st
                        .peers
                        .connected_peers
                        .iter()
                        .any(|p| p.peer_id == peer_id);
                    if !already_listed {
                        st.peers.connected_peers.insert(
                            0,
                            PeerConnectionInfo {
                                peer_id,
                                direction,
                                address,
                                connected_at_unix,
                                agent_version: String::new(),
                                bzz_overlay: None,
                                full_node: None,
                                last_bzz_at_unix: None,
                                stale: false,
                            },
                        );
                    } else if num_established.get() == 1 {
                        if let Some(peer) = st
                            .peers
                            .connected_peers
                            .iter_mut()
                            .find(|p| p.peer_id == peer_id)
                        {
                            peer.direction = direction;
                            peer.address = address;
                            peer.connected_at_unix = connected_at_unix;
                        }
                    }
                    st.peers.connected = PeerInfo::live_connected_count(&st.peers.connected_peers);
                });
                tracing::trace!(target: "ant_p2p", %pid, "status: connection opened");
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            if *num_established == 0 {
                peer_agents.remove(peer_id);
            }
            if let Some(s) = status {
                let pid = peer_id.to_string();
                s.send_modify(|st| {
                    if *num_established == 0 {
                        st.peers.connected_peers.retain(|p| p.peer_id != pid);
                    }
                    st.peers.connected = PeerInfo::live_connected_count(&st.peers.connected_peers);
                });
            }
        }
        SwarmEvent::Behaviour(AntBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            let agent = info.agent_version.clone();
            info!(target: "ant_p2p", %peer_id, "libp2p connected agent={agent:?}");
            peer_agents.insert(*peer_id, agent);
            if let Some(s) = status {
                let pid = peer_id.to_string();
                let agent = info.agent_version.clone();
                s.send_modify(|st| {
                    if let Some(peer) = st
                        .peers
                        .connected_peers
                        .iter_mut()
                        .find(|p| p.peer_id == pid)
                    {
                        peer.agent_version = agent;
                    }
                });
            }
        }
        SwarmEvent::Behaviour(AntBehaviourEvent::Ping(e)) => {
            tracing::trace!(target: "ant_p2p", "ping: {e:?}");
        }
        _ => {}
    }
}

fn peer_endpoint(endpoint: &ConnectedPoint) -> (String, String) {
    match endpoint {
        ConnectedPoint::Dialer { address, .. } => ("outbound".to_string(), address.to_string()),
        ConnectedPoint::Listener { send_back_addr, .. } => {
            ("inbound".to_string(), send_back_addr.to_string())
        }
    }
}

/// Record one-shot session timings for UIs (e.g. `antop`).
fn record_peer_session_milestones(
    status: Option<&watch::Sender<StatusSnapshot>>,
    process_start: std::time::Instant,
    first_bzz_in_session: bool,
    peer_set_size: usize,
    target_peers: usize,
) {
    let Some(s) = status else { return };
    let elapsed = process_start.elapsed().as_secs_f64();
    s.send_modify(|st| {
        if first_bzz_in_session {
            st.peers.time_to_first_peer_s.get_or_insert(elapsed);
        }
        // Guard against the (currently unreachable but cheap to defend against)
        // case where a future caller wires `RunConfig::target_peers = 0`
        // directly without going through `state.target_peers` normalisation.
        if target_peers > 0 && peer_set_size >= target_peers {
            st.peers.time_to_node_limit_s.get_or_insert(elapsed);
        }
    });
}

fn record_handshake(
    status: Option<&watch::Sender<StatusSnapshot>>,
    remote: PeerId,
    info: &HandshakeInfo,
    agent: Option<String>,
) {
    let Some(s) = status else { return };
    let now = unix_now();
    let report = HandshakeReport {
        remote_overlay: format!("0x{}", hex::encode(info.remote_overlay)),
        remote_peer_id: remote.to_string(),
        agent_version: agent.unwrap_or_default(),
        full_node: info.remote_full_node,
        at_unix: now,
    };
    s.send_modify(|st| {
        if let Some(peer) = st
            .peers
            .connected_peers
            .iter_mut()
            .find(|p| p.peer_id == report.remote_peer_id)
        {
            peer.bzz_overlay = Some(report.remote_overlay.clone());
            peer.full_node = Some(report.full_node);
            peer.last_bzz_at_unix = Some(report.at_unix);
            if peer.agent_version.is_empty() {
                peer.agent_version.clone_from(&report.agent_version);
            }
        }
        st.peers.last_handshake = Some(report);
    });
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Sub-second breakdown for a completed **outbound** (dialer) pipeline.
// Every field is a millisecond duration; `_ms` is the unit, not redundant naming.
#[allow(clippy::struct_field_names)]
struct OutboundPipelineMs {
    dial_ms: Option<u64>,
    identifying_ms: u64,
    handshake_ms: u64,
}

/// `handshake_ms` and `identifying_ms` thresholds that together identify the
/// "bee burned its `peerMultiaddrs` window" case. We send identify quickly
/// (`identifying_ms < FAST_IDENTIFY_MS`) but the BZZ exchange itself drags
/// on past `SLOW_HANDSHAKE_MS`, which on bee can only happen if its inbound
/// handshake handler sat out its 10 s peerstore wait. The numbers are
/// deliberately conservative on both ends so we don't fire on the occasional
/// fast-identify-slow-link peer.
const SLOW_HANDSHAKE_MS: u64 = 5000;
const FAST_IDENTIFY_MS: u64 = 200;

/// Surface a one-shot `warn!` the first time we see a handshake whose
/// timing matches bee's peerstore-stall pattern (see `SLOW_HANDSHAKE_MS` /
/// `FAST_IDENTIFY_MS`). The cure is almost always `--external-address`,
/// but operators don't necessarily know that, so we point at it directly.
/// Only fires once per process — repeated nags are noise.
fn maybe_warn_bee_peerstore_stall(state: &mut SwarmState, peer: PeerId, p: &OutboundPipelineMs) {
    if state.bee_peerstore_stall_warning_emitted {
        return;
    }
    if p.handshake_ms < SLOW_HANDSHAKE_MS || p.identifying_ms >= FAST_IDENTIFY_MS {
        return;
    }
    warn!(
        target: "ant_p2p",
        %peer,
        handshake_ms = p.handshake_ms,
        identifying_ms = p.identifying_ms,
        "slow BZZ handshake suggests the remote bee waited ~10 s for our \
         public multiaddr via libp2p-identify. If this node is behind NAT, \
         pass --external-address /ip4/<public-ip>/tcp/<public-port> to \
         shorten future handshakes.",
    );
    state.bee_peerstore_stall_warning_emitted = true;
}

fn log_handshake_ok(
    info: &HandshakeInfo,
    peer_set_size: usize,
    pipeline_ms: Option<OutboundPipelineMs>,
) {
    let ov = hex::encode(info.remote_overlay);
    let prefix = ov.chars().take(6).collect::<String>();
    let suffix = ov.chars().rev().take(2).collect::<String>();
    info!(
        target: "ant_p2p",
        "bzz handshake ok overlay={prefix}…{suffix} full_node={} peer_set_size={peer_set_size}",
        info.remote_full_node,
    );
    if let Some(p) = pipeline_ms {
        let dial = p
            .dial_ms
            .map_or_else(|| "n/a".to_string(), |d| d.to_string());
        let total_ms = p.dial_ms.map_or(p.identifying_ms + p.handshake_ms, |d| {
            d + p.identifying_ms + p.handshake_ms
        });
        debug!(
            target: "ant_p2p",
            "outbound peer_pipeline_ms peer_set_size={peer_set_size} dial_ms={dial} \
             identifying_ms={} handshake_ms={} total_ms={total_ms}",
            p.identifying_ms,
            p.handshake_ms,
        );
    }
}

/// Expand every `/dnsaddr/` entry into concrete peer multiaddrs, group by
/// `PeerId`, then hand each group to libp2p as a single [`DialOpts`] with
/// IPv6-first ordering and a concurrency factor sized to the address count.
/// Swarm's `mainnet.ethswarm.org` TXT tree fans out into several regional
/// bootnodes; dialing them concurrently makes bootstrap tolerant of any
/// single region being unreachable.
///
/// DNS resolution for `/dnsaddr/` entries can take seconds on slow / partly-
/// failing system DNS (we've seen the macOS resolver burn ~5 s walking the
/// regional TXT chain on first run), and awaiting it from the main loop
/// freezes everything else: the listener `NewListenAddr` events sit
/// undelivered in the swarm queue, identify can't fire, warm-peerstore
/// hints don't get dialed. So we resolve in a spawned task and feed each
/// resolved bootnode multiaddr through `dial_tx`. The main `select!` reads
/// the receiver and calls `swarm.dial()` from the event-loop task, which
/// is what `swarm.dial()` requires anyway.
fn spawn_bootstrap_dial(bootnodes: &[Multiaddr], dial_tx: mpsc::Sender<Multiaddr>) {
    if bootnodes.is_empty() {
        return;
    }
    let bootnodes = bootnodes.to_vec();
    tokio::spawn(async move {
        let start = Instant::now();
        let resolved = dnsaddr::resolve_all(bootnodes.iter().cloned()).await;
        let total = resolved.len();
        if total == 0 {
            warn!(
                target: "ant_p2p",
                "no dialable bootnode addresses after /dnsaddr/ resolution"
            );
            return;
        }
        info!(
            target: "ant_p2p",
            count = total,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "bootnode /dnsaddr/ resolution complete",
        );
        for addr in resolved {
            if dial_tx.send(addr).await.is_err() {
                // Receiver closed — daemon is shutting down.
                return;
            }
        }
    });
}

/// Tag every peer known to be a bootnode before any dial goes out: the
/// configured bootnode multiaddrs that carry a `/p2p/` id, and the stored
/// peers a previous run dialed as bootnodes ([`PeerStore::bootnodes`]).
/// `/dnsaddr/` entries are tagged later, as their leaves resolve
/// ([`handle_bootnode_dial`]); without this a warm-started node dials a
/// stored bootnode from the hint queue first and, if resolution is slow or
/// fails, counts it as a serving peer for `/readiness` at once (#78).
fn seed_bootnode_tags(state: &mut SwarmState, peerstore: &PeerStore, bootnodes: &[Multiaddr]) {
    state
        .bootnode_peers
        .extend(bootnodes.iter().filter_map(crate::dial::extract_peer_id));
    state.bootnode_peers.extend(peerstore.bootnodes());
}

/// Drain one bootnode multiaddr from the channel and dial it from the
/// swarm-event-loop task. Mirrors the bookkeeping `bootstrap_dial` used
/// to do inline: skips peers we're already connected to (or already
/// dialing), records `dial_started` for the cold-start metric, and
/// pins a `dial_hint_addr` so the handshake driver knows which underlay
/// to advertise in `BzzAddress.underlays`.
fn handle_bootnode_dial(swarm: &mut Swarm<AntBehaviour>, state: &mut SwarmState, addr: Multiaddr) {
    let Some(peer) = crate::dial::extract_peer_id(&addr) else {
        return;
    };
    state.bootnode_peers.insert(peer);
    if swarm.is_connected(&peer) || state.dialing.contains(&peer) {
        return;
    }
    let opts = DialOpts::peer_id(peer)
        .addresses(vec![addr.clone()])
        .build();
    match swarm.dial(opts) {
        Ok(()) => {
            state.dialing.insert(peer);
            state.note_dial_started(peer);
            state.failed.retain(|f| f.peer != peer);
            state.dial_hint_addr.insert(peer, addr);
            info!(target: "ant_p2p", peer=%peer, "dialing bootnode");
        }
        Err(DialError::DialPeerConditionFalse(_)) => {
            tracing::debug!(
                target: "ant_p2p",
                %peer,
                "dial skipped: already connected or dial in progress",
            );
        }
        Err(e) => warn!(target: "ant_p2p", "dial error: {e}"),
    }
}

/// Build a DNS resolver config from `/etc/resolv.conf` (system) but strip any
/// local search domains. `/dnsaddr/*.ethswarm.org` must resolve globally; a
/// captive-portal search suffix would turn it into a name that only exists on
/// the local network. System nameservers are always followed by Cloudflare's
/// anycast as a public fallback — see `dnsaddr::build_resolver` for the
/// detailed rationale (in short: the iOS simulator's sandbox cannot reach
/// the host's `/etc/resolv.conf` entries, so DNSADDR resolution fails on cold
/// start without a backup). On hosts with `/etc/resolv.conf` unreadable
/// (Android / minimal containers) we fall through to Cloudflare-only.
fn resolver_config() -> dns::ResolverConfig {
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((cfg, _)) => {
            let mut servers = cfg.name_servers().to_vec();
            servers.extend(
                dns::ResolverConfig::cloudflare()
                    .name_servers()
                    .iter()
                    .cloned(),
            );
            dns::ResolverConfig::from_parts(None, Vec::new(), servers)
        }
        Err(_) => dns::ResolverConfig::cloudflare(),
    }
}

fn build_swarm(
    keypair: Keypair,
    liveness: &LivenessConfig,
) -> Result<Swarm<AntBehaviour>, RunError> {
    // `push_listen_addr_updates` triggers an identify-push whenever our
    // listener set changes. That matters for bee: if a later listener arrives
    // (e.g. port reopens after network change) bee learns it mid-connection
    // rather than on the next 5-minute identify interval. External address
    // additions don't trigger push in libp2p-identify 0.47, so the first
    // connection to a fresh bee still eats the 10 s `peerMultiaddrs` wait.
    let id_cfg = identify::Config::new(AGENT.to_string(), keypair.public())
        .with_agent_version(AGENT.to_string())
        .with_push_listen_addr_updates(true);
    let behaviour = AntBehaviour {
        stream: libp2p_stream::Behaviour::default(),
        identify: identify::Behaviour::new(id_cfg),
        ping: ping::Behaviour::new(
            ping::Config::new()
                .with_interval(liveness.ping_interval)
                .with_timeout(liveness.ping_timeout),
        ),
        upnp: libp2p::upnp::tokio::Behaviour::default(),
    };

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        // What `.with_tcp(tcp::Config::default(), noise::Config::new,
        // yamux::Config::default)` builds, plus `BoundedClose` around the
        // muxer: a close on a dead link must not wait ~15 min for the
        // kernel before `ConnectionClosed` fires (issue #83).
        .with_other_transport(|key| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                tcp::tokio::Transport::new(tcp::Config::default())
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key)?)
                    .multiplex(yamux::Config::default())
                    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(BoundedClose::new(muxer)))),
            )
        })
        .map_err(|e| std::io::Error::other(format!("tcp/noise/yamux: {e}")))?
        .with_dns_config(resolver_config(), dns::ResolverOpts::default())
        .with_behaviour(|_| behaviour)
        .expect("infallible behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();
    Ok(swarm)
}

/// Forward decoded lurker messages to a subscriber's ack channel.
///
/// Returns — dropping `out_rx`, which is what stops the lurker and its
/// pull streams — as soon as the subscriber goes away, **even if no
/// message ever arrives**: `ack.closed()` is selected alongside `recv()`.
/// Without that, a quiet subscription whose WebSocket closed would block
/// on `recv()` forever and leak the whole lurker.
async fn forward_lurker_messages(
    mut out_rx: tokio::sync::mpsc::Receiver<crate::messaging::DecodedMessage>,
    ack: mpsc::Sender<ControlAck>,
) {
    use crate::messaging::DecodedMessage;
    loop {
        let msg = tokio::select! {
            m = out_rx.recv() => m,
            () = ack.closed() => None,
        };
        let Some(msg) = msg else { return };
        let frame = match msg {
            DecodedMessage::Gsoc { address, payload } => ControlAck::LurkerMessage {
                kind: ant_control::LurkerMessageKind::Gsoc,
                key: hex::encode(address),
                payload,
            },
            DecodedMessage::Pss { topic, message } => ControlAck::LurkerMessage {
                kind: ant_control::LurkerMessageKind::Pss,
                key: hex::encode(topic),
                payload: message,
            },
        };
        if ack.send(frame).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use libp2p::swarm::ConnectionId;

    fn pid() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    /// Liveness timings shrunk so a real-socket test runs in seconds.
    const FAST_LIVENESS: LivenessConfig = LivenessConfig {
        ping_interval: Duration::from_millis(100),
        ping_timeout: Duration::from_millis(300),
        live_window: Duration::from_millis(600),
        resume_verify: Duration::from_millis(600),
        close_grace: Duration::from_millis(600),
        stall_gap: Duration::from_secs(10),
        ..LivenessConfig::DEFAULT
    };

    fn test_state() -> SwarmState {
        SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        )
    }

    /// Relay one TCP connection to `target` (a `/ip4/../tcp/..` multiaddr).
    /// Returns the relay's multiaddr and its freeze switch: once set, the
    /// relay stops forwarding in both directions but holds both sockets.
    async fn freezable_tcp_relay(
        target: &Multiaddr,
    ) -> (Multiaddr, Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let port = target
            .iter()
            .find_map(|p| match p {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            })
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: Multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let frozen = Arc::new(AtomicBool::new(false));
        let f = frozen.clone();
        tokio::spawn(async move {
            let (down, _) = listener.accept().await.unwrap();
            let up = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (dr, dw) = down.into_split();
            let (ur, uw) = up.into_split();
            let pump = |mut r: tokio::net::tcp::OwnedReadHalf,
                        mut w: tokio::net::tcp::OwnedWriteHalf,
                        f: Arc<AtomicBool>| async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    if f.load(Ordering::SeqCst) {
                        // Hold both halves forever.
                        std::future::pending::<()>().await;
                    }
                    match tokio::time::timeout(Duration::from_millis(20), r.read(&mut buf)).await {
                        Err(_) => {}
                        Ok(Ok(0) | Err(_)) => return,
                        Ok(Ok(n)) => {
                            if f.load(Ordering::SeqCst) {
                                std::future::pending::<()>().await;
                            }
                            if w.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            };
            let a = tokio::spawn(pump(dr, uw, f.clone()));
            let b = tokio::spawn(pump(ur, dw, f));
            let _ = tokio::join!(a, b);
        });
        (addr, frozen)
    }

    /// Issue #83, end to end over real TCP: a peer that stops answering
    /// (its process frozen, its socket still open — the half-open state
    /// a reaped mobile socket leaves) stops being counted in
    /// `peers.connected` and then has its connection closed by the swarm
    /// loop's liveness pass. While it answered, the same pass left the
    /// connection alone. On `main` nothing closed it: the test runs into
    /// its timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frozen_peer_is_uncounted_then_disconnected() {
        frozen_peer_scenario(0, Duration::ZERO).await;
    }

    /// Issue #83, PR #133 R1-F1: the same, with uploads in flight when
    /// the link dies — enough of them to fill the TCP send buffer. A
    /// graceful yamux close then can't flush, and without
    /// `BoundedClose` `ConnectionClosed` (and the peer teardown hanging
    /// off it) waited for the kernel's ETIMEDOUT (~15 min); the liveness
    /// pass re-issued the close every pass meanwhile. Now the close gives
    /// up after `CLOSE_TIMEOUT`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn frozen_peer_with_a_full_send_buffer_is_still_disconnected() {
        frozen_peer_scenario(64, crate::bounded_close::CLOSE_TIMEOUT).await;
    }

    /// Drive [`frozen_peer_is_uncounted_then_disconnected`]'s scenario.
    /// With `streams > 0`, that many streams to the remote are opened
    /// while it answers and each writes 1 MiB once the link is frozen;
    /// `extra_close` is the extra time the close may then take.
    async fn frozen_peer_scenario(streams: usize, extra_close: Duration) {
        use futures::AsyncWriteExt as _;
        let cfg = FAST_LIVENESS;
        let proto = StreamProtocol::new("/ant/test/sink/1.0.0");
        // Remote: a plain node of ours on loopback, frozen on demand.
        let mut remote = build_swarm(Keypair::generate_ed25519(), &cfg).unwrap();
        remote
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let remote_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = remote.select_next_some().await {
                break address;
            }
        };
        // The remote drains every stream it is offered (until the freeze
        // stops anything reaching it).
        let mut incoming = remote
            .behaviour()
            .stream
            .new_control()
            .accept(proto.clone())
            .unwrap();
        tokio::spawn(async move {
            while let Some((_, mut s)) = incoming.next().await {
                tokio::spawn(async move {
                    let _ = futures::io::copy(&mut s, &mut futures::io::sink()).await;
                });
            }
        });
        tokio::spawn(async move {
            loop {
                remote.select_next_some().await;
            }
        });
        // Between us and the remote: a TCP relay that, once frozen, stops
        // forwarding but keeps both sockets open. Nothing reaches either
        // side any more and nobody sees a FIN or RST: a half-open link.
        let (proxy_addr, freeze) = freezable_tcp_relay(&remote_addr).await;
        let mut ours = build_swarm(Keypair::generate_ed25519(), &cfg).unwrap();
        let mut state = test_state();
        state.liveness = Liveness::new(cfg, Instant::now());
        let (status_tx, status_rx) = watch::channel(StatusSnapshot::default());
        let mut control = ours.behaviour().stream.new_control();
        let hs = HandshakeParams {
            local_peer_id: *ours.local_peer_id(),
            signing_secret: [7u8; SECP256K1_SECRET_LEN],
            overlay_nonce: [0u8; OVERLAY_NONCE_LEN],
            network_id: 1,
        };
        let (result_tx, _result_rx) = mpsc::channel(8);
        let mut peerstore = PeerStore::disabled();
        let (dial_tx, _dial_rx) = mpsc::channel::<Multiaddr>(8);
        let mut agents = HashMap::new();
        let (mut backoff, mut last_boot, mut last_top_up) =
            (MIN_BACKOFF, Instant::now(), Instant::now());
        ours.dial(proxy_addr).unwrap();

        let started = Instant::now();
        let mut established_at = None;
        let mut remote_peer = None;
        let mut opened = Vec::new();
        let mut frozen_at = None;
        let mut uncounted_at = None;
        let mut pass = tokio::time::interval(Duration::from_millis(50));
        let closed_at = loop {
            assert!(
                started.elapsed() < Duration::from_secs(20) + extra_close,
                "frozen peer never disconnected (frozen {:?} ago)",
                frozen_at.map(|t: Instant| t.elapsed()),
            );
            tokio::select! {
                ev = ours.select_next_some() => {
                    let established = matches!(ev, SwarmEvent::ConnectionEstablished { .. });
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = &ev {
                        remote_peer = Some(*peer_id);
                    }
                    let closed = matches!(ev, SwarmEvent::ConnectionClosed { .. });
                    observe_event(Some(&status_tx), &mut agents, &ev);
                    handle_swarm_event(
                        &mut ours, &mut state, Some(&status_tx), &mut control, &hs,
                        &result_tx, &mut peerstore, ev,
                    );
                    if established {
                        established_at = Some(Instant::now());
                        let peer = remote_peer.unwrap();
                        for _ in 0..streams {
                            let mut c = control.clone();
                            let proto = proto.clone();
                            opened.push(tokio::spawn(async move {
                                c.open_stream(peer, proto).await.unwrap()
                            }));
                        }
                    }
                    if closed {
                        break Instant::now();
                    }
                }
                _ = pass.tick() => {
                    maintain_liveness(
                        &mut ours, &mut state, Some(&status_tx), &[], &PeerStore::disabled(),
                        &mut backoff, &mut last_boot, &mut last_top_up, hs.local_peer_id,
                        &dial_tx,
                    );
                    let (listed, counted) = {
                        let s = status_rx.borrow();
                        (s.peers.connected_peers.len(), s.peers.connected)
                    };
                    if frozen_at.is_none() {
                        if let Some(t) = established_at {
                            assert_eq!((listed, counted), (1, 1), "a live peer is counted");
                            // Answering for 3 whole windows: kept open.
                            if t.elapsed() > 3 * (cfg.live_window + cfg.close_grace) {
                                let mut ready = Vec::new();
                                for o in opened.drain(..) {
                                    ready.push(o.await.unwrap());
                                }
                                freeze.store(true, std::sync::atomic::Ordering::SeqCst);
                                frozen_at = Some(Instant::now());
                                // Uploads in flight on the dead link.
                                for mut st in ready {
                                    tokio::spawn(async move {
                                        let _ = st.write_all(&vec![0u8; 1 << 20]).await;
                                        std::future::pending::<()>().await;
                                    });
                                }
                            }
                        }
                    } else if listed == 1 && counted == 0 && uncounted_at.is_none() {
                        uncounted_at = Some(Instant::now());
                    }
                }
            }
        };
        let frozen_at = frozen_at.expect("closed while the peer still answered pings");
        let uncounted_at = uncounted_at.expect("the silent peer was still counted until it closed");
        assert!(uncounted_at < closed_at);
        // Uncounted within one window of its last pong, closed within
        // `close_grace` after that (+ slack for the 50 ms pass cadence).
        let slack = Duration::from_millis(400);
        assert!(
            uncounted_at - frozen_at <= cfg.live_window + slack,
            "{:?}",
            uncounted_at - frozen_at
        );
        assert!(
            closed_at - frozen_at <= cfg.live_window + cfg.close_grace + extra_close + slack,
            "{:?}",
            closed_at - frozen_at,
        );
        let s = status_rx.borrow();
        assert!(s.peers.connected_peers.is_empty());
        assert_eq!(s.peers.connected, 0);
    }

    /// Issue #83: a streak of retrieval link failures makes the liveness
    /// pass do what `ControlCommand::Resume` does (re-warm + redial, here
    /// visible as the cleared hint dedup), once per cooldown window.
    #[tokio::test]
    async fn link_failure_streak_triggers_one_self_heal_per_window() {
        let mut swarm = build_swarm(Keypair::generate_ed25519(), &LivenessConfig::DEFAULT).unwrap();
        let mut state = test_state();
        let (dial_tx, _dial_rx) = mpsc::channel::<Multiaddr>(8);
        let (mut backoff, mut last_boot, mut last_top_up) =
            (MAX_BACKOFF, Instant::now(), Instant::now());
        let mut pass = |state: &mut SwarmState, backoff: &mut Duration| {
            maintain_liveness(
                &mut swarm,
                state,
                None,
                &[],
                &PeerStore::disabled(),
                backoff,
                &mut last_boot,
                &mut last_top_up,
                pid(),
                &dial_tx,
            );
        };
        // Below the threshold: nothing.
        for _ in 1..LivenessConfig::DEFAULT.self_heal_streak {
            state.retrieval_counters.record_link_failure();
        }
        state.seen_hints.insert(pid());
        pass(&mut state, &mut backoff);
        assert_eq!(state.seen_hints.len(), 1);
        assert_eq!(backoff, MAX_BACKOFF);
        // At the threshold: self-heal, streak restarted.
        state.retrieval_counters.record_link_failure();
        pass(&mut state, &mut backoff);
        assert!(
            state.seen_hints.is_empty(),
            "self-heal re-warmed the dial queue"
        );
        assert_eq!(
            backoff, MIN_BACKOFF,
            "self-heal unparked the bootstrap guard"
        );
        assert_eq!(state.retrieval_counters.link_failure_streak(), 0);
        // A second streak inside the cooldown: no redial storm.
        for _ in 0..LivenessConfig::DEFAULT.self_heal_streak {
            state.retrieval_counters.record_link_failure();
        }
        state.seen_hints.insert(pid());
        backoff = MAX_BACKOFF;
        pass(&mut state, &mut backoff);
        assert_eq!(state.seen_hints.len(), 1);
        assert_eq!(backoff, MAX_BACKOFF);
    }

    /// A peer with a duplicate connection keeps its BZZ session, routing
    /// entry and status row when one of the two closes (liveness may close
    /// a dead duplicate next to a live one).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closing_one_of_two_connections_keeps_the_peer() {
        let cfg = FAST_LIVENESS;
        let mut remote = build_swarm(Keypair::generate_ed25519(), &cfg).unwrap();
        remote
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let remote_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = remote.select_next_some().await {
                break address;
            }
        };
        let remote_id = *remote.local_peer_id();
        tokio::spawn(async move {
            loop {
                remote.select_next_some().await;
            }
        });
        let mut ours = build_swarm(Keypair::generate_ed25519(), &cfg).unwrap();
        let mut state = test_state();
        let (status_tx, status_rx) = watch::channel(StatusSnapshot::default());
        let mut control = ours.behaviour().stream.new_control();
        let hs = HandshakeParams {
            local_peer_id: *ours.local_peer_id(),
            signing_secret: [7u8; SECP256K1_SECRET_LEN],
            overlay_nonce: [0u8; OVERLAY_NONCE_LEN],
            network_id: 1,
        };
        let (result_tx, _result_rx) = mpsc::channel(8);
        let mut peerstore = PeerStore::disabled();
        let mut agents = HashMap::new();
        for _ in 0..2 {
            ours.dial(
                DialOpts::peer_id(remote_id)
                    .addresses(vec![remote_addr.clone()])
                    .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                    .build(),
            )
            .unwrap();
        }
        let mut conns = Vec::new();
        while conns.len() < 2 {
            let ev = tokio::time::timeout(Duration::from_secs(10), ours.select_next_some())
                .await
                .expect("two connections");
            if let SwarmEvent::ConnectionEstablished { connection_id, .. } = &ev {
                conns.push(*connection_id);
            }
            observe_event(Some(&status_tx), &mut agents, &ev);
            handle_swarm_event(
                &mut ours,
                &mut state,
                Some(&status_tx),
                &mut control,
                &hs,
                &result_tx,
                &mut peerstore,
                ev,
            );
        }
        // Pretend the BZZ handshake finished on this peer.
        state.bzz_peers.insert(remote_id);
        assert!(ours.close_connection(conns[0]));
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(10), ours.select_next_some())
                .await
                .expect("close event");
            let closed = matches!(ev, SwarmEvent::ConnectionClosed { .. });
            observe_event(Some(&status_tx), &mut agents, &ev);
            handle_swarm_event(
                &mut ours,
                &mut state,
                Some(&status_tx),
                &mut control,
                &hs,
                &result_tx,
                &mut peerstore,
                ev,
            );
            if closed {
                break;
            }
        }
        assert!(ours.is_connected(&remote_id));
        assert!(state.bzz_peers.contains(&remote_id), "BZZ session kept");
        assert_eq!(status_rx.borrow().peers.connected, 1);
    }

    /// A tracked dial that resolves as a *duplicate* connection (the peer
    /// is already in the pipeline) still clears its dial-start markers.
    /// A stale `dial_started_unproven` would otherwise exempt a later,
    /// unrelated dial failure to that peer on a proven link.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_dialer_connection_clears_dial_start_markers() {
        let cfg = FAST_LIVENESS;
        let mut remote = build_swarm(Keypair::generate_ed25519(), &cfg).unwrap();
        remote
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let remote_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = remote.select_next_some().await {
                break address;
            }
        };
        let remote_id = *remote.local_peer_id();
        tokio::spawn(async move {
            loop {
                remote.select_next_some().await;
            }
        });
        let mut ours = build_swarm(Keypair::generate_ed25519(), &cfg).unwrap();
        let mut state = test_state();
        let mut control = ours.behaviour().stream.new_control();
        let hs = HandshakeParams {
            local_peer_id: *ours.local_peer_id(),
            signing_secret: [7u8; SECP256K1_SECRET_LEN],
            overlay_nonce: [0u8; OVERLAY_NONCE_LEN],
            network_id: 1,
        };
        let (result_tx, _result_rx) = mpsc::channel(8);
        let mut peerstore = PeerStore::disabled();
        for round in 0..2 {
            // No bzz peers yet: our connectivity counts as down, so the
            // dial is marked unproven.
            state.dialing.insert(remote_id);
            state.note_dial_started(remote_id);
            assert!(state.dial_started_unproven.contains(&remote_id));
            ours.dial(
                DialOpts::peer_id(remote_id)
                    .addresses(vec![remote_addr.clone()])
                    .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                    .build(),
            )
            .unwrap();
            loop {
                let ev = tokio::time::timeout(Duration::from_secs(10), ours.select_next_some())
                    .await
                    .expect("connection");
                let established = matches!(ev, SwarmEvent::ConnectionEstablished { .. });
                handle_swarm_event(
                    &mut ours,
                    &mut state,
                    None,
                    &mut control,
                    &hs,
                    &result_tx,
                    &mut peerstore,
                    ev,
                );
                if established {
                    break;
                }
            }
            // Round 0 enters the pipeline; round 1 is the duplicate early return.
            assert!(state.pending.contains_key(&remote_id), "round {round}");
            assert!(
                !state.dial_started.contains_key(&remote_id),
                "round {round}: dial_started left behind"
            );
            assert!(
                !state.dial_started_unproven.contains(&remote_id),
                "round {round}: dial_started_unproven left behind"
            );
        }
    }

    fn stamp_for(batch_id: [u8; 32]) -> [u8; ant_postage::STAMP_SIZE] {
        let mut s = [0u8; ant_postage::STAMP_SIZE];
        s[..32].copy_from_slice(&batch_id);
        s
    }

    fn rejected_err() -> ant_retrieval::pushsync::PushSyncError {
        ant_retrieval::pushsync::PushSyncError::StampRejected {
            batch_id: [0u8; 32],
            rejections: 1,
            sample: "batchstore get: not found".into(),
        }
    }

    /// PR #134 R1-M2: a probe that times out must not lose the debit of a
    /// delivery bee makes after the timeout — the mirror is what schedules
    /// the pseudosettle refresh, so unmirrored debt would go uncleared.
    /// R2-M2: the late request is waited for in place, so it keeps the
    /// caller's concurrency slot (and its reservation) instead of running
    /// on outside the verify's bound.
    #[tokio::test(start_paused = true)]
    async fn probe_records_late_delivery_debit_in_mirror() {
        use ant_retrieval::accounting::Accounting;
        use std::time::Duration;
        let acc = Arc::new(Accounting::new());
        let peer = pid();
        let guard = acc.try_reserve(peer, 1_000).expect("reserve");
        let fetch = async {
            tokio::time::sleep(Duration::from_secs(20)).await;
            true
        };
        let started = tokio::time::Instant::now();
        let probe = tokio::spawn(probe_draining_late_delivery(
            fetch,
            Duration::from_secs(10),
            None,
            move || guard.apply(),
        ));
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert!(
            !probe.is_finished(),
            "a timed-out probe holds its slot until the request ends",
        );
        // Still in flight: reserved, not yet applied.
        assert_eq!(acc.debug_snapshot(&peer), Some((0, 1_000)));
        let hit = probe.await.unwrap();
        assert!(!hit, "a late delivery is still a probe miss");
        assert_eq!(started.elapsed(), Duration::from_secs(20));
        assert_eq!(
            acc.debug_snapshot(&peer),
            Some((1_000, 0)),
            "late delivery's debit must land in the mirror",
        );
    }

    /// PR #134 R2-M2: cancelling the verify releases a probe that is
    /// waiting out a late request at once; the request is detached so its
    /// debit still lands in the mirror.
    #[tokio::test(start_paused = true)]
    async fn cancelled_probe_detaches_its_late_request() {
        use ant_retrieval::accounting::Accounting;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        let acc = Arc::new(Accounting::new());
        let peer = pid();
        let guard = acc.try_reserve(peer, 1_000).expect("reserve");
        let cancel = Arc::new(AtomicBool::new(false));
        let fetch = async {
            tokio::time::sleep(Duration::from_secs(20)).await;
            true
        };
        let started = tokio::time::Instant::now();
        let probe = tokio::spawn(probe_draining_late_delivery(
            fetch,
            Duration::from_secs(10),
            Some(cancel.clone()),
            move || guard.apply(),
        ));
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert!(!probe.is_finished());
        cancel.store(true, Ordering::Relaxed);
        let hit = probe.await.unwrap();
        assert!(!hit);
        assert!(
            started.elapsed() <= Duration::from_secs(12) + PROBE_CANCEL_POLL,
            "cancel must release the probe within one poll, took {:?}",
            started.elapsed(),
        );
        assert_eq!(acc.debug_snapshot(&peer), Some((0, 1_000)));
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            acc.debug_snapshot(&peer),
            Some((1_000, 0)),
            "the detached request's debit must still land in the mirror",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_releases_reservation_when_late_fetch_fails() {
        use ant_retrieval::accounting::Accounting;
        use std::time::Duration;
        let acc = Arc::new(Accounting::new());
        let peer = pid();
        let guard = acc.try_reserve(peer, 1_000).expect("reserve");
        let fetch = async {
            tokio::time::sleep(Duration::from_secs(20)).await;
            false
        };
        let hit = probe_draining_late_delivery(fetch, Duration::from_secs(10), None, move || {
            guard.apply();
        })
        .await;
        assert!(!hit);
        assert_eq!(acc.debug_snapshot(&peer), Some((0, 0)));
    }

    #[tokio::test(start_paused = true)]
    async fn probe_applies_in_time_delivery_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let hit = probe_draining_late_delivery(
            async { true },
            Duration::from_secs(10),
            None,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(hit);
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Issue #52 regression: a peer-rejected batch must carry a probe
    /// schedule that becomes due — not sit in the set waiting for an
    /// external push that usable-filtering clients will never make.
    #[test]
    fn rejected_batch_schedules_a_probe_and_recovers_on_success() {
        let rejected: RejectedBatches = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let batch = [0xAB; 32];
        note_stamp_outcome(&rejected, &stamp_for(batch), Some(&rejected_err()));

        // Marked unusable, probe scheduled but not yet due.
        assert!(rejected.lock().unwrap().contains_key(&batch));
        assert_eq!(
            due_batch_probes(&rejected, Instant::now()),
            [] as [[u8; 32]; 0]
        );

        // After the initial backoff the probe is due — and popping it
        // marks the flight so the next tick can't double-fire it.
        let later = Instant::now() + BATCH_PROBE_BACKOFF_INITIAL + Duration::from_millis(10);
        assert_eq!(due_batch_probes(&rejected, later), vec![batch]);
        assert_eq!(due_batch_probes(&rejected, later), [] as [[u8; 32]; 0]);

        // A successful probe clears the mark → /stamps flips usable.
        record_batch_probe_outcome(&rejected, batch, None);
        assert!(!rejected.lock().unwrap().contains_key(&batch));
    }

    /// Reviewer change-request regression: a walk that outlasts the
    /// early backoffs must NOT overlap a second probe for the same
    /// batch — strictly one in flight, released by the outcome. And a
    /// flight that never reports (lost task) expires with the lease so
    /// probing can't wedge.
    #[test]
    fn only_one_probe_in_flight_per_batch() {
        let rejected: RejectedBatches = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let batch = [0x77; 32];
        note_stamp_outcome(&rejected, &stamp_for(batch), Some(&rejected_err()));

        let t0 = Instant::now() + BATCH_PROBE_BACKOFF_INITIAL + Duration::from_millis(10);
        assert_eq!(due_batch_probes(&rejected, t0), vec![batch]);

        // The walk runs long: several backoff periods pass, still
        // within the flight lease → NO second probe fires.
        let mid_flight = t0 + 4 * BATCH_PROBE_BACKOFF_INITIAL;
        assert!(mid_flight < t0 + BATCH_PROBE_FLIGHT_LEASE);
        assert_eq!(due_batch_probes(&rejected, mid_flight), [] as [[u8; 32]; 0]);

        // The outcome lands (still rejected): flight released, backoff
        // doubled exactly ONCE, and the next probe fires on the new
        // schedule.
        record_batch_probe_outcome(&rejected, batch, Some(&rejected_err()));
        {
            let set = rejected.lock().unwrap();
            assert!(!set[&batch].in_flight);
            assert_eq!(set[&batch].backoff, 2 * BATCH_PROBE_BACKOFF_INITIAL);
        }
        let next = Instant::now() + 2 * BATCH_PROBE_BACKOFF_INITIAL + Duration::from_millis(10);
        assert_eq!(due_batch_probes(&rejected, next), vec![batch]);

        // Lost-task backstop: no outcome ever lands; once the lease
        // expires the flight is considered dead and probing resumes.
        let past_lease = next + BATCH_PROBE_FLIGHT_LEASE + Duration::from_millis(10);
        assert_eq!(due_batch_probes(&rejected, past_lease), vec![batch]);
    }

    /// Still-rejected probes back off exponentially toward the cap;
    /// transient failures (no peers, timeouts) keep the cadence — they
    /// are not verdicts about the batch.
    #[test]
    fn probe_backoff_doubles_on_rejection_and_caps() {
        let rejected: RejectedBatches = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let batch = [0xCD; 32];
        note_stamp_outcome(&rejected, &stamp_for(batch), Some(&rejected_err()));

        for _ in 0..12 {
            record_batch_probe_outcome(&rejected, batch, Some(&rejected_err()));
        }
        let backoff = rejected.lock().unwrap()[&batch].backoff;
        assert_eq!(backoff, BATCH_PROBE_BACKOFF_MAX, "backoff must cap");

        // A transient error must not grow the backoff further… or
        // remove the mark.
        let transient = ant_retrieval::pushsync::PushSyncError::ReceiptMismatch;
        record_batch_probe_outcome(&rejected, batch, Some(&transient));
        let set = rejected.lock().unwrap();
        assert_eq!(set[&batch].backoff, BATCH_PROBE_BACKOFF_MAX);
        assert!(set.contains_key(&batch));
    }

    /// Repeated organic rejections must not reset the probe schedule
    /// (the prober owns the backoff), and an organic success clears the
    /// mark exactly like a probe success.
    #[test]
    fn organic_pushes_interact_correctly_with_the_probe_schedule() {
        let rejected: RejectedBatches = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let batch = [0xEF; 32];
        note_stamp_outcome(&rejected, &stamp_for(batch), Some(&rejected_err()));
        record_batch_probe_outcome(&rejected, batch, Some(&rejected_err()));
        let backoff_before = rejected.lock().unwrap()[&batch].backoff;

        // Another organic rejection arrives: schedule untouched.
        note_stamp_outcome(&rejected, &stamp_for(batch), Some(&rejected_err()));
        assert_eq!(rejected.lock().unwrap()[&batch].backoff, backoff_before);

        // An organic success (e.g. a manual pinned-batch upload, or
        // any client that doesn't filter) clears the mark.
        note_stamp_outcome(&rejected, &stamp_for(batch), None);
        assert!(!rejected.lock().unwrap().contains_key(&batch));
    }

    /// The probe chunk is a pure function of the batch id: same address
    /// every probe (so the stamp cache reuses one bucket slot), distinct
    /// across batches, and a well-formed CAC.
    #[test]
    fn probe_chunk_is_deterministic_per_batch() {
        let (a1, w1) = batch_probe_chunk(&[0x11; 32]);
        let (a2, _) = batch_probe_chunk(&[0x11; 32]);
        let (b1, _) = batch_probe_chunk(&[0x22; 32]);
        assert_eq!(a1, a2);
        assert_ne!(a1, b1);
        assert!(ant_crypto::cac_valid(&a1, &w1));
    }

    /// Regression for the quiet-subscription leak: closing the
    /// subscriber's ack stream must stop the forwarder (and thereby the
    /// lurker, which watches `out_rx`'s closure) even when no message
    /// ever flows.
    #[tokio::test]
    async fn lurker_forwarder_stops_when_quiet_subscriber_leaves() {
        let (out_tx, out_rx) = mpsc::channel::<crate::messaging::DecodedMessage>(4);
        let (ack_tx, ack_rx) = mpsc::channel::<ControlAck>(4);
        let forwarder = tokio::spawn(forward_lurker_messages(out_rx, ack_tx));

        // Subscriber goes away without a single message having arrived.
        drop(ack_rx);

        tokio::time::timeout(std::time::Duration::from_secs(2), forwarder)
            .await
            .expect("forwarder must return once the subscriber is gone")
            .expect("forwarder must not panic");
        // The lurker's sender now observes closure and shuts down.
        assert!(out_tx.is_closed());
    }

    /// Build a hive hint whose overlay's first byte is `first` (zeros
    /// elsewhere, except a discriminator in the last byte so distinct
    /// peers in the same bin stay distinct overlays). Against a zero
    /// base overlay, `first = 0x80 >> bin` puts the hint in `bin`.
    fn hint_in_bin(peer_id: PeerId, first: u8, discriminator: u8) -> sinks::PeerHint {
        let mut overlay = [0u8; 32];
        overlay[0] = first;
        overlay[31] = discriminator;
        sinks::PeerHint {
            peer_id,
            addrs: vec!["/ip4/1.2.3.4/tcp/1634".parse().unwrap()],
            overlay,
        }
    }

    /// Issue #202: a peer streaming fabricated public hints must not grow
    /// `hint_queue` / `seen_hints` without bound. The queue holds at most
    /// `KNOWN_DIALABLE_CAP` (oldest evicted, and forgotten by the dedup so
    /// gossip can re-queue it), and `seen_hints` is rebuilt from the queue
    /// once dialed peers push it past twice the cap.
    #[tokio::test]
    async fn enqueue_hint_bounds_queue_and_dedup() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        state.local_subnets = Some((Instant::now(), crate::underlay::LocalSubnets::default()));
        let local = PeerId::random();

        let peers: Vec<PeerId> = (0..KNOWN_DIALABLE_CAP + 10)
            .map(|_| PeerId::random())
            .collect();
        for (i, peer) in peers.iter().enumerate() {
            state.enqueue_hint(hint_in_bin(*peer, 0x80, i as u8), local);
        }
        assert_eq!(state.hint_queue.len(), KNOWN_DIALABLE_CAP);
        assert!(state.seen_hints.len() <= 2 * KNOWN_DIALABLE_CAP);
        for evicted in &peers[..10] {
            assert!(!state.seen_hints.contains(evicted));
            assert!(state.hint_queue.iter().all(|h| h.peer_id != *evicted));
        }
        assert_eq!(state.hint_queue[0].peer_id, peers[10]);
        assert_eq!(
            state.hint_queue.back().unwrap().peer_id,
            *peers.last().unwrap()
        );

        // An evicted peer can be re-queued by fresh gossip.
        state.enqueue_hint(hint_in_bin(peers[0], 0x80, 0), local);
        assert_eq!(state.hint_queue.back().unwrap().peer_id, peers[0]);
        assert_eq!(state.hint_queue.len(), KNOWN_DIALABLE_CAP);

        // Dialed peers (popped from the queue, still deduped) pile up in
        // `seen_hints`; past twice the cap it is rebuilt from the queue.
        state
            .seen_hints
            .extend((0..=KNOWN_DIALABLE_CAP).map(|_| PeerId::random()));
        assert_eq!(state.seen_hints.len(), 2 * KNOWN_DIALABLE_CAP + 1);
        let fresh = PeerId::random();
        state.enqueue_hint(hint_in_bin(fresh, 0x80, 1), local);
        assert_eq!(state.hint_queue.len(), KNOWN_DIALABLE_CAP);
        assert_eq!(state.seen_hints.len(), KNOWN_DIALABLE_CAP);
        assert!(state.seen_hints.contains(&fresh));
        assert!(state
            .hint_queue
            .iter()
            .all(|h| state.seen_hints.contains(&h.peer_id)));
    }

    /// Issue #88: a hive hint's pod/RFC1918/loopback underlays must never
    /// reach a dial path, and a hint left with nothing dialable is not
    /// queued (nor kept for neighbourhood / bin-balance dials) — an empty
    /// address list would let libp2p fall back to identify's cached,
    /// unfiltered listen addrs.
    #[tokio::test]
    async fn enqueue_hint_filters_unroutable_underlays() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        // Pin an empty "local subnets" snapshot so the host's real
        // interfaces can't make a private address look same-LAN.
        state.local_subnets = Some((Instant::now(), crate::underlay::LocalSubnets::default()));
        let local = PeerId::random();

        let mixed = PeerId::random();
        let mut hint = hint_in_bin(mixed, 0x80, 1);
        hint.addrs = vec![
            "/ip4/10.233.64.12/tcp/1634".parse().unwrap(),
            "/ip4/172.17.0.3/tcp/1634".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/1634".parse().unwrap(),
            "/ip4/1.2.3.4/tcp/1634".parse().unwrap(),
        ];
        state.enqueue_hint(hint, local);

        let private_only = PeerId::random();
        let mut hint = hint_in_bin(private_only, 0x40, 2);
        hint.addrs = vec![
            "/ip4/10.42.0.7/tcp/1634".parse().unwrap(),
            "/ip6/fd00::7/tcp/1634".parse().unwrap(),
        ];
        state.enqueue_hint(hint, local);

        assert_eq!(state.hint_queue.len(), 1);
        let queued = &state.hint_queue[0];
        assert_eq!(queued.peer_id, mixed);
        assert_eq!(
            queued.addrs,
            vec!["/ip4/1.2.3.4/tcp/1634".parse::<Multiaddr>().unwrap()],
        );
        assert_eq!(state.known_dialable[&mixed].addrs, queued.addrs);
        assert!(!state.known_dialable.contains_key(&private_only));

        // Same peer again, now "on its LAN": the private underlay is kept.
        state.seen_hints.clear();
        state.hint_queue.clear();
        state.local_subnets = Some((
            Instant::now(),
            crate::underlay::LocalSubnets::from_nets(vec![("10.42.0.1".parse().unwrap(), 16)]),
        ));
        let mut hint = hint_in_bin(private_only, 0x40, 2);
        hint.addrs = vec![
            "/ip4/10.42.0.7/tcp/1634".parse().unwrap(),
            "/ip6/fd00::7/tcp/1634".parse().unwrap(),
        ];
        state.enqueue_hint(hint, local);
        assert_eq!(state.hint_queue.len(), 1);
        assert_eq!(
            state.hint_queue[0].addrs,
            vec!["/ip4/10.42.0.7/tcp/1634".parse::<Multiaddr>().unwrap()],
        );

        // The escape hatch keeps every advertised underlay.
        state.allow_private_dials = true;
        state.seen_hints.clear();
        state.hint_queue.clear();
        let mut hint = hint_in_bin(private_only, 0x40, 2);
        hint.addrs = vec!["/ip4/127.0.0.1/tcp/1634".parse().unwrap()];
        state.enqueue_hint(hint, local);
        assert_eq!(state.hint_queue.len(), 1);
    }

    /// A same-LAN private underlay admitted on one network must not be
    /// dialed after the host's networks change (Wi-Fi → cellular, or a
    /// different LAN reusing the same numbering): the dial-time re-filter
    /// drops it, and a changed subnet snapshot purges it from the caches.
    #[tokio::test]
    async fn network_change_drops_cached_private_underlays() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let home =
            crate::underlay::LocalSubnets::from_nets(vec![("192.168.1.7".parse().unwrap(), 24)]);
        state.local_subnets = Some((Instant::now(), home.clone()));
        let local = PeerId::random();

        let lan_only = PeerId::random();
        let mut hint = hint_in_bin(lan_only, 0x80, 1);
        hint.addrs = vec!["/ip4/192.168.1.20/tcp/1634".parse().unwrap()];
        state.enqueue_hint(hint, local);
        let mixed = PeerId::random();
        let mut hint = hint_in_bin(mixed, 0x40, 2);
        hint.addrs = vec![
            "/ip4/192.168.1.21/tcp/1634".parse().unwrap(),
            "/ip4/1.2.3.4/tcp/1634".parse().unwrap(),
        ];
        state.enqueue_hint(hint, local);
        assert_eq!(state.hint_queue.len(), 2);
        assert!(state.known_dialable.contains_key(&lan_only));

        // Dial-time re-filter: moved to cellular (no private subnet), the
        // cached LAN address is no longer offered to the dialer, even
        // before any purge ran.
        state.local_subnets = Some((Instant::now(), crate::underlay::LocalSubnets::default()));
        let cached = state.known_dialable[&lan_only].clone();
        assert_eq!(state.addrs_for_dial(&cached), None);
        assert!(!state.known_dialable.contains_key(&lan_only));
        let cached = state.known_dialable[&mixed].clone();
        assert_eq!(
            state.addrs_for_dial(&cached),
            Some(vec!["/ip4/1.2.3.4/tcp/1634".parse().unwrap()]),
        );

        // Snapshot change purges the caches: a different LAN with the
        // same 192.168.1.0/24 numbering (new lease) must not inherit the
        // old LAN's addresses.
        state.local_subnets = Some((Instant::now(), home));
        state.set_local_subnets(crate::underlay::LocalSubnets::from_nets(vec![(
            "192.168.1.33".parse().unwrap(),
            24,
        )]));
        assert_eq!(state.hint_queue.len(), 1);
        assert_eq!(state.hint_queue[0].peer_id, mixed);
        assert_eq!(
            state.hint_queue[0].addrs,
            vec!["/ip4/1.2.3.4/tcp/1634".parse::<Multiaddr>().unwrap()],
        );
        assert_eq!(
            state.known_dialable[&mixed].addrs,
            vec!["/ip4/1.2.3.4/tcp/1634".parse::<Multiaddr>().unwrap()],
        );
        // R3-M1: the purged private-only hint left `seen_hints` with the
        // queue, so gossip re-queues it once it is same-LAN again; the
        // surviving mixed hint keeps its dedup entry.
        assert!(!state.seen_hints.contains(&lan_only));
        assert!(state.seen_hints.contains(&mixed));

        // An unchanged snapshot purges nothing.
        let mut hint = hint_in_bin(lan_only, 0x80, 1);
        hint.addrs = vec!["/ip4/192.168.1.20/tcp/1634".parse().unwrap()];
        state.enqueue_hint(hint, local);
        assert_eq!(state.hint_queue.len(), 2);
        assert_eq!(state.hint_queue[1].peer_id, lan_only);
        let same = state.local_subnets.as_ref().unwrap().1.clone();
        state.set_local_subnets(same);
        assert!(state.known_dialable.contains_key(&lan_only));

        // R2-M1: a rotated temporary IPv6 address is not a network move.
        let mut rotated = vec![("192.168.1.33".parse().unwrap(), 24)];
        rotated.push(("2a01:4f8:1:2:cafe::1".parse().unwrap(), 64));
        state.set_local_subnets(crate::underlay::LocalSubnets::from_nets(rotated));
        assert!(state.known_dialable.contains_key(&lan_only));

        // PR #93 R2-M1: a carrier drop on the LAN interface that keeps its
        // address (Wi-Fi reassociation clearing IFF_RUNNING) stops same-LAN
        // matching but is not a move — nothing is purged, and once the
        // carrier is back the cached LAN underlay dials again.
        let queued = state.hint_queue.len();
        let iface = |up| {
            crate::underlay::LocalSubnets::from_interface_list(vec![(
                "wlan0".to_string(),
                up,
                "192.168.1.33".parse().unwrap(),
                24,
            )])
        };
        state.set_local_subnets(iface(false));
        assert!(!state
            .local_subnets
            .as_ref()
            .unwrap()
            .1
            .contains("192.168.1.20".parse().unwrap()));
        assert!(state.known_dialable.contains_key(&lan_only));
        assert_eq!(state.hint_queue.len(), queued);
        assert!(state.seen_hints.contains(&lan_only));
        state.set_local_subnets(iface(true));
        let cached = state.known_dialable[&lan_only].clone();
        assert_eq!(
            state.addrs_for_dial(&cached),
            Some(vec!["/ip4/192.168.1.20/tcp/1634".parse().unwrap()]),
        );

        // R2-M2: a failed interface read keeps the previous snapshot (and
        // the cached same-LAN underlays) instead of acting as "no networks".
        let before = state.local_subnets.as_ref().unwrap().1.clone();
        state.local_subnets.as_mut().unwrap().0 =
            Instant::now().checked_sub(LOCAL_SUBNETS_TTL).unwrap();
        state.interfaces_unreadable();
        let (at, kept) = state.local_subnets.as_ref().unwrap();
        assert!(kept.same_networks(&before));
        assert!(at.elapsed() < LOCAL_SUBNETS_TTL);
        assert!(state.known_dialable.contains_key(&lan_only));
        let cached = state.known_dialable[&lan_only].clone();
        assert_eq!(
            state.addrs_for_dial(&cached),
            Some(vec!["/ip4/192.168.1.20/tcp/1634".parse().unwrap()]),
        );
        // … and with no snapshot yet it falls back to the safe empty set.
        state.local_subnets = None;
        state.interfaces_unreadable();
        assert!(state
            .local_subnets
            .as_ref()
            .unwrap()
            .1
            .same_networks(&crate::underlay::LocalSubnets::default()));
    }

    /// Dead-underlay backoff (issue #88): repeated dial failures double the
    /// suppression window up to the cap; a connection clears it.
    #[test]
    fn dial_backoff_doubles_and_caps() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let peer = PeerId::random();
        assert!(!state.dial_backed_off(&peer));
        state.note_dial_failure(peer);
        assert!(state.dial_backed_off(&peer));
        let first = state.dial_backoff[&peer].until - Instant::now();
        assert!(first <= DIAL_BACKOFF_BASE && first > DIAL_BACKOFF_BASE / 2);
        state.note_dial_failure(peer);
        let second = state.dial_backoff[&peer].until - Instant::now();
        assert!(second > DIAL_BACKOFF_BASE && second <= DIAL_BACKOFF_BASE * 2);
        for _ in 0..40 {
            state.note_dial_failure(peer);
        }
        let capped = state.dial_backoff[&peer].until - Instant::now();
        assert!(capped <= DIAL_BACKOFF_MAX && capped > DIAL_BACKOFF_MAX / 2);
        // An expired backoff no longer suppresses dials.
        state.dial_backoff.get_mut(&peer).unwrap().until = Instant::now();
        assert!(!state.dial_backed_off(&peer));
    }

    fn backoff_test_state() -> SwarmState {
        SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        )
    }

    /// A real on-disk peerstore holding `peers` as known-good entries.
    fn peerstore_with(dir: &std::path::Path, peers: &[PeerId]) -> PeerStore {
        let mut store = PeerStore::load(dir.join("peers.json"));
        for (i, p) in peers.iter().enumerate() {
            store.record_success(
                *p,
                vec!["/ip4/1.2.3.4/tcp/1634".parse().unwrap()],
                [i as u8 + 1; 32],
                0,
                None,
            );
        }
        store
    }

    /// A connected bzz peer whose connection just answered a ping, as the
    /// swarm loop records it (`ConnectionEstablished` + a pong). Returns
    /// the connection so a test can pong on it again.
    fn connect_answering(state: &mut SwarmState, peer: PeerId) -> ConnectionId {
        let conn = ConnectionId::new_unchecked(state.bzz_peers.len() + 1000);
        state.bzz_peers.insert(peer);
        state.liveness.on_established(conn, peer, Instant::now());
        state.liveness.on_pong(conn, Instant::now());
        conn
    }

    /// Drive a tracked dial to `peer` failing through the same handler the
    /// `OutgoingConnectionError` arm calls (backoff + peerstore).
    fn fail_tracked_dial(state: &mut SwarmState, peerstore: &mut PeerStore, peer: PeerId) {
        state.dialing.insert(peer);
        state.note_dial_started(peer);
        note_outgoing_dial_error(state, peerstore, peer);
    }

    /// An explicit Resume after an outage must redial the peerstore's
    /// known-good peers now, not skip them until backoffs earned during
    /// the outage expire; the automatic top-up does the same only after a
    /// full collapse. Backoffs of peers not being re-warmed are untouched.
    #[tokio::test]
    async fn rewarm_clears_backoff_for_rewarmed_peers() {
        let dir = tempfile::tempdir().unwrap();
        let (known, stranger, live) = (pid(), pid(), pid());
        let mut peerstore = peerstore_with(dir.path(), &[known]);
        let local = pid();
        let (tx, _rx) = mpsc::channel::<Multiaddr>(8);

        // Backoff earned while connected (so the handler does charge it).
        let mut state = backoff_test_state();
        let live_conn = connect_answering(&mut state, live);
        fail_tracked_dial(&mut state, &mut peerstore, known);
        fail_tracked_dial(&mut state, &mut peerstore, stranger);
        assert!(state.dial_backed_off(&known) && state.dial_backed_off(&stranger));

        // force_resume: known-good peer redialable and first out of the queue.
        let mut backoff = MAX_BACKOFF;
        let (mut last_bootstrap_at, mut last_top_up_at) = (Instant::now(), Instant::now());
        let warmed = force_resume(
            &[],
            &mut state,
            &peerstore,
            &mut backoff,
            &mut last_bootstrap_at,
            &mut last_top_up_at,
            local,
            &tx,
        );
        assert_eq!(warmed, 1);
        assert!(!state.dial_backed_off(&known));
        assert!(
            state.dial_backed_off(&stranger),
            "only re-warmed peers are cleared"
        );
        assert_eq!(state.pop_dialable_hint().map(|h| h.peer_id), Some(known));

        // maybe_top_up_peers below the floor but with a surviving peer:
        // not a collapse, so backoffs stand and the hint is not dialed.
        // (The surviving connection answers after the resume, so the
        // failure is charged again.)
        state.liveness.on_pong(live_conn, Instant::now());
        fail_tracked_dial(&mut state, &mut peerstore, known);
        assert!(state.dial_backed_off(&known));
        let mut last_top_up_at = Instant::now().checked_sub(PEER_TOP_UP_INTERVAL).unwrap();
        maybe_top_up_peers(&[], &mut state, &peerstore, &mut last_top_up_at, local, &tx);
        assert!(state.dial_backed_off(&known));
        assert_eq!(state.pop_dialable_hint().map(|h| h.peer_id), None);

        // Full collapse: the re-warm clears the known-good peer's backoff.
        state.bzz_peers.clear();
        let mut last_top_up_at = Instant::now().checked_sub(PEER_TOP_UP_INTERVAL).unwrap();
        maybe_top_up_peers(&[], &mut state, &peerstore, &mut last_top_up_at, local, &tx);
        assert!(!state.dial_backed_off(&known));
        assert!(state.dial_backed_off(&stranger));
        assert_eq!(state.pop_dialable_hint().map(|h| h.peer_id), Some(known));
    }

    /// With no connected bzz peer our own link is the likely culprit, so a
    /// dial failure must neither back the peer off nor count toward its
    /// peerstore eviction — otherwise a local outage (no network, handover,
    /// suspend) would back off, and eventually evict, every known-good peer.
    #[test]
    fn dial_failures_not_charged_while_own_connectivity_down() {
        let dir = tempfile::tempdir().unwrap();
        let peer = pid();
        let mut peerstore = peerstore_with(dir.path(), &[peer]);
        let mut state = backoff_test_state();

        for _ in 0..10 {
            fail_tracked_dial(&mut state, &mut peerstore, peer);
        }
        assert!(!state.dial_backed_off(&peer));
        assert!(
            peerstore.contains(&peer),
            "outage must not evict known-good peers"
        );
        assert!(state.dialing.is_empty() && state.dial_started.is_empty());
        assert!(
            state.failed.iter().any(|f| f.peer == peer),
            "the failed dial still shows in the pipeline"
        );

        // Connected again: failures are charged to the peer as before.
        connect_answering(&mut state, pid());
        fail_tracked_dial(&mut state, &mut peerstore, peer);
        assert!(state.dial_backed_off(&peer));
        for _ in 0..10 {
            fail_tracked_dial(&mut state, &mut peerstore, peer);
        }
        assert!(
            !peerstore.contains(&peer),
            "a genuinely dead peer is still evicted"
        );
    }

    /// Issue #90: after a suspend or a network handover `bzz_peers` stays
    /// full of zombie sockets until the liveness pass closes them, and
    /// every dial in that window fails because *our* link is gone. Those
    /// failures must not back the peers off or evict them from the
    /// peerstore — the list the post-outage re-warm dials from. Same for
    /// the dials a `Resume` / self-heal fires before any connection has
    /// answered again.
    #[tokio::test]
    async fn dial_failures_not_charged_on_zombie_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let (peer, other) = (pid(), pid());
        let mut peerstore = peerstore_with(dir.path(), &[peer, other]);
        let mut state = backoff_test_state();
        let local = pid();
        let (tx, _rx) = mpsc::channel::<Multiaddr>(8);

        // Zombies: connected, but nothing has answered for longer than
        // the proof window (no pong since the link died).
        let silent_since = Instant::now()
            .checked_sub(LivenessConfig::DEFAULT.proof_window + Duration::from_secs(1))
            .unwrap();
        for n in 0..3 {
            let zombie = pid();
            state.bzz_peers.insert(zombie);
            state
                .liveness
                .on_established(ConnectionId::new_unchecked(n), zombie, silent_since);
        }
        assert!(state.liveness.stale_peers(Instant::now()).is_empty());
        for _ in 0..10 {
            fail_tracked_dial(&mut state, &mut peerstore, peer);
        }
        assert!(!state.dial_backed_off(&peer), "not backed off");
        assert!(
            peerstore.contains(&peer),
            "zombie-window failures must not evict a known-good peer"
        );

        // A connection that still answers proves the link: charged again.
        let live = connect_answering(&mut state, pid());
        fail_tracked_dial(&mut state, &mut peerstore, peer);
        assert!(state.dial_backed_off(&peer));

        // `Resume` (or a self-heal) after a handover: the redials it
        // fires fail while the old connections haven't answered again.
        let mut backoff = MAX_BACKOFF;
        let (mut last_bootstrap_at, mut last_top_up_at) = (Instant::now(), Instant::now());
        force_resume(
            &[],
            &mut state,
            &peerstore,
            &mut backoff,
            &mut last_bootstrap_at,
            &mut last_top_up_at,
            local,
            &tx,
        );
        for _ in 0..10 {
            fail_tracked_dial(&mut state, &mut peerstore, other);
        }
        assert!(!state.dial_backed_off(&other));
        assert!(
            peerstore.contains(&other),
            "dials before the first answer after a resume must not evict"
        );

        // The first answer after the resume: a dead peer is charged and,
        // eventually, evicted as before.
        state.liveness.on_pong(live, Instant::now());
        for _ in 0..10 {
            fail_tracked_dial(&mut state, &mut peerstore, other);
        }
        assert!(state.dial_backed_off(&other));
        assert!(!peerstore.contains(&other), "a dead peer is still evicted");
    }

    /// A dial fired during the zombie / post-`Resume` window often fails
    /// only after the OS SYN timeout (~75-127 s), by which time the new
    /// link has long answered a ping. Its failure is still about our old
    /// link: no backoff, no peerstore strike. Same for a dial started on a
    /// proven link just before a `Resume`. Dials started once the link is
    /// proven again are charged as usual.
    #[tokio::test]
    async fn late_dial_failures_judged_by_link_state_at_dial_start() {
        let dir = tempfile::tempdir().unwrap();
        let (early, before_resume, after_proof) = (pid(), pid(), pid());
        let mut peerstore = peerstore_with(dir.path(), &[early, before_resume, after_proof]);
        let mut state = backoff_test_state();
        let local = pid();
        let (tx, _rx) = mpsc::channel::<Multiaddr>(8);

        // Proven link; a dial starts, then the host resumes after a
        // handover before that dial resolves.
        let live = connect_answering(&mut state, pid());
        state.dialing.insert(before_resume);
        state.note_dial_started(before_resume);
        tokio::time::sleep(Duration::from_millis(2)).await;
        let mut backoff = MAX_BACKOFF;
        let (mut last_bootstrap_at, mut last_top_up_at) = (Instant::now(), Instant::now());
        force_resume(
            &[],
            &mut state,
            &peerstore,
            &mut backoff,
            &mut last_bootstrap_at,
            &mut last_top_up_at,
            local,
            &tx,
        );
        // Re-warm dial fired while the link is unproven.
        state.dialing.insert(early);
        state.note_dial_started(early);

        // The new link answers; only afterwards do the stale SYNs time out.
        tokio::time::sleep(Duration::from_millis(2)).await;
        state.liveness.on_pong(live, Instant::now());
        assert!(!state.own_connectivity_down());
        for p in [early, before_resume] {
            note_outgoing_dial_error(&mut state, &mut peerstore, p);
            assert!(!state.dial_backed_off(&p), "late failure not backed off");
        }
        assert!(state.dial_started_unproven.is_empty());
        // No strikes either: four more charged failures would evict after
        // MAX_FAIL_COUNT (5) only if the stale one had counted.
        for _ in 0..4 {
            fail_tracked_dial(&mut state, &mut peerstore, early);
        }
        assert!(
            peerstore.contains(&early),
            "the stale failure must not count toward eviction"
        );

        // A dial started on the proven link is charged as before.
        fail_tracked_dial(&mut state, &mut peerstore, after_proof);
        assert!(state.dial_backed_off(&after_proof));
    }

    /// A backed-off hint popped by the fill loop must not be discarded
    /// while its peer stays in `seen_hints` (which would keep gossip from
    /// ever re-queueing it): it leaves the dedup, gossip re-queues it, and
    /// it is dialed once the backoff has expired.
    #[test]
    fn backed_off_hint_leaves_dedup_for_requeue() {
        let mut state = backoff_test_state();
        connect_answering(&mut state, pid());
        let mut peerstore = PeerStore::disabled();
        let local = pid();
        let (dead, good) = (pid(), pid());
        fail_tracked_dial(&mut state, &mut peerstore, dead);
        assert!(state.dial_backed_off(&dead));

        state.enqueue_hint(hint_in_bin(dead, 0x80, 1), local);
        state.enqueue_hint(hint_in_bin(good, 0x40, 2), local);
        assert_eq!(state.pop_dialable_hint().map(|h| h.peer_id), Some(good));
        assert!(state.hint_queue.is_empty());
        assert!(!state.seen_hints.contains(&dead));
        assert!(state.seen_hints.contains(&good));

        // Gossip re-queues it; still backed off, so dropped again.
        state.enqueue_hint(hint_in_bin(dead, 0x80, 1), local);
        assert_eq!(state.hint_queue.len(), 1);
        assert_eq!(state.pop_dialable_hint().map(|h| h.peer_id), None);

        // Backoff expired: the next gossip round gets it dialed.
        state.dial_backoff.get_mut(&dead).unwrap().until = Instant::now();
        state.enqueue_hint(hint_in_bin(dead, 0x80, 1), local);
        assert_eq!(state.pop_dialable_hint().map(|h| h.peer_id), Some(dead));
    }

    /// `force_resume` is the post-suspension recovery lever, so its whole
    /// job is to act **even when the automatic guards would stay parked**:
    /// a swarm full of half-open zombies still looks healthy
    /// (`bzz_peers` non-empty, backoff far from elapsing), which is exactly
    /// when `maybe_top_up_peers` / `maybe_rebootstrap` do nothing. The
    /// resume must unconditionally clear the hint dedup and rewind the
    /// backoff + cadence clocks so the loop-top maintenance is free to
    /// re-fire immediately.
    #[tokio::test]
    async fn force_resume_unparks_guards_despite_healthy_looking_swarm() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        // Make the swarm *look* healthy: a connected peer and a peer we've
        // already deduped. This is the half-open state — the count gates
        // see no reason to act.
        state.bzz_peers.insert(pid());
        state.seen_hints.insert(pid());

        // Backoff maxed out and clocks "just fired": the automatic guards
        // are parked behind their cadence.
        let mut backoff = MAX_BACKOFF;
        let mut last_bootstrap_at = Instant::now();
        let mut last_top_up_at = Instant::now();

        // Empty bootnodes → no real DNS / dial spawned, so the test stays
        // hermetic; the gate-bypass bookkeeping is what we're asserting.
        let (tx, _rx) = mpsc::channel::<Multiaddr>(8);
        let warmed = force_resume(
            &[],
            &mut state,
            &PeerStore::disabled(),
            &mut backoff,
            &mut last_bootstrap_at,
            &mut last_top_up_at,
            pid(),
            &tx,
        );

        assert_eq!(warmed, 0, "a disabled peerstore re-queues no warm hints");
        assert!(
            state.seen_hints.is_empty(),
            "resume must clear the dedup so previously-seen peers can re-enter",
        );
        assert_eq!(
            backoff, MIN_BACKOFF,
            "resume must reset the bootstrap backoff"
        );
        assert!(
            last_bootstrap_at.elapsed() >= MIN_BACKOFF,
            "resume must rewind the bootstrap clock so maybe_rebootstrap is free to fire",
        );
        assert!(
            last_top_up_at.elapsed() >= PEER_TOP_UP_INTERVAL,
            "resume must rewind the top-up clock so maybe_top_up_peers is free to fire",
        );
        assert!(
            state.bzz_peers.len() == 1,
            "resume must not disturb surviving connections",
        );
    }

    /// The balance pass must dial only into bins below the minimum, take
    /// no more than each bin's deficit, skip excluded peers, and ignore
    /// bins at or beyond [`BIN_BALANCE_MAX_BIN`] (those fill themselves
    /// via gossip bias). This is the policy that stops a long-running
    /// node's peer set from collapsing into its own neighbourhood.
    #[test]
    fn bin_balance_candidates_fill_deficient_bins_only() {
        let base = [0u8; 32];
        // Bin 0 is empty, bin 1 needs one more peer, bin 2 is saturated.
        let mut bin_counts = [0u8; crate::routing::NUM_BINS];
        bin_counts[1] = (BIN_BALANCE_MIN_PEERS - 1) as u8;
        bin_counts[2] = BIN_BALANCE_MIN_PEERS as u8;

        let mut known = HashMap::new();
        // More bin-0 candidates than the deficit (4) — selection must cap.
        for i in 0..6u8 {
            let p = pid();
            known.insert(p, hint_in_bin(p, 0x80, i));
        }
        // Two bin-1 candidates for a deficit of one.
        let b1a = pid();
        let b1b = pid();
        known.insert(b1a, hint_in_bin(b1a, 0x40, 0));
        known.insert(b1b, hint_in_bin(b1b, 0x40, 1));
        // A bin-2 candidate (saturated) and a deep-bin candidate (>= max).
        let b2 = pid();
        known.insert(b2, hint_in_bin(b2, 0x20, 0));
        let deep = pid();
        known.insert(deep, hint_in_bin(deep, 0x00, 1));

        let picked = bin_balance_candidates(&base, &bin_counts, &known, |_| false);
        let bin0 = picked.iter().filter(|(_, b)| *b == 0).count();
        let bin1 = picked.iter().filter(|(_, b)| *b == 1).count();
        assert_eq!(
            bin0, BIN_BALANCE_MIN_PEERS,
            "bin 0 fills exactly its deficit"
        );
        assert_eq!(bin1, 1, "bin 1 takes one peer, not both candidates");
        assert_eq!(picked.len(), bin0 + bin1, "saturated / deep bins untouched");
        assert!(picked.iter().all(|(p, _)| *p != b2 && *p != deep));
    }

    /// Excluded peers (connected, mid-pipeline, recently failed) must not
    /// be selected, and a fully-balanced table yields no candidates at all
    /// — the pass is a no-op in steady state.
    #[test]
    fn bin_balance_candidates_respect_exclusion_and_saturation() {
        let base = [0u8; 32];
        let bin_counts = [0u8; crate::routing::NUM_BINS];
        let excluded = pid();
        let allowed = pid();
        let mut known = HashMap::new();
        known.insert(excluded, hint_in_bin(excluded, 0x80, 0));
        known.insert(allowed, hint_in_bin(allowed, 0x80, 1));

        let picked = bin_balance_candidates(&base, &bin_counts, &known, |p| *p == excluded);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].0, allowed);

        let saturated = [BIN_BALANCE_MIN_PEERS as u8; crate::routing::NUM_BINS];
        assert!(
            bin_balance_candidates(&base, &saturated, &known, |_| false).is_empty(),
            "balanced table must produce no dials",
        );
    }

    /// `/readiness` (#78) counts routing peers that can serve: a bootnode
    /// counts only after `BOOTNODE_SERVING_GRACE` in the table (mainnet
    /// bootnodes reset the connection milliseconds after the handshake),
    /// any other routing peer at once, and never a forgotten peer. Stale
    /// peers: `serving_peer_count_skips_stale_peers`.
    #[test]
    fn serving_peer_count_skips_fresh_bootnodes() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let t0 = Instant::now();
        let boot = pid();
        state.bootnode_peers.insert(boot);
        state.routing.admit(boot, [1u8; 32]);
        state.routing_admitted_at.insert(boot, t0);
        assert_eq!(serving_peer_count(&state, t0), 0, "fresh bootnode");
        let snap = routing_snapshot(&state, t0);
        assert_eq!((snap.size, snap.serving), (1, 0));
        assert_eq!(
            serving_peer_count(
                &state,
                t0 + BOOTNODE_SERVING_GRACE.saturating_sub(Duration::from_millis(1))
            ),
            0,
        );
        assert_eq!(
            serving_peer_count(&state, t0 + BOOTNODE_SERVING_GRACE),
            1,
            "a bootnode that stays (private network) counts after the grace",
        );

        let peer = pid();
        state.routing.admit(peer, [2u8; 32]);
        state.routing_admitted_at.insert(peer, t0);
        assert_eq!(serving_peer_count(&state, t0), 1, "gossiped peer at once");

        state.routing.forget(&peer);
        state.routing_admitted_at.remove(&peer);
        assert_eq!(serving_peer_count(&state, t0), 0);
    }

    /// A routing peer whose connection stopped answering pings (#83)
    /// doesn't count toward `RoutingInfo::serving` while it waits to be
    /// closed as dead — the staleness half of `/readiness`. The gateway
    /// only reads the published `serving` figure, so this is the one test
    /// that catches `serving_peer_count` counting a stale peer.
    #[test]
    fn serving_peer_count_skips_stale_peers() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let t0 = Instant::now();
        let quiet = pid();
        state.routing.admit(quiet, [3u8; 32]);
        state.routing_admitted_at.insert(quiet, t0);
        state
            .liveness
            .on_established(libp2p::swarm::ConnectionId::new_unchecked(1), quiet, t0);
        assert_eq!(serving_peer_count(&state, t0), 1, "answering pings");
        let silent = t0 + LivenessConfig::DEFAULT.live_window + Duration::from_secs(1);
        assert!(state.liveness.stale_peers(silent).contains(&quiet));
        assert_eq!(serving_peer_count(&state, silent), 0, "stale-only table");
        let snap = routing_snapshot(&state, silent);
        assert_eq!(
            (snap.size, snap.serving),
            (1, 0),
            "in the table, not serving"
        );

        // A live peer alongside it still serves; the stale one stays out.
        let live = pid();
        state.routing.admit(live, [4u8; 32]);
        state.routing_admitted_at.insert(live, silent);
        assert_eq!(serving_peer_count(&state, silent), 1);
    }

    /// A warm start dials stored peers from the hint queue before the
    /// `/dnsaddr/` bootnode list resolves (or when it never does). A
    /// bootnode the previous run persisted must still be tagged, so it
    /// doesn't make `/readiness` 200 on its own (#78): `seed_bootnode_tags`
    /// reads the flag back from `peers.json` and the configured `/p2p/`
    /// ids, with this run's resolution failing outright.
    #[test]
    fn warm_start_tags_stored_bootnodes_without_dnsaddr_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let boot = pid();
        let gossiped = pid();
        {
            // Previous run: both handshaked, `boot` dialed as a bootnode.
            let mut store = PeerStore::load(path.clone());
            let addr: Multiaddr = "/ip4/192.0.2.1/tcp/1634".parse().unwrap();
            store.record_success(boot, vec![addr.clone()], [1u8; 32], 0, None);
            store.record_success(gossiped, vec![addr], [2u8; 32], 0, None);
            store.mark_bootnode(&boot);
            store.flush();
        }
        let peerstore = PeerStore::load(path);
        let static_boot = pid();
        let bootnodes: Vec<Multiaddr> = vec![
            "/dnsaddr/nonexistent.invalid".parse().unwrap(),
            format!("/ip4/192.0.2.2/tcp/1634/p2p/{static_boot}")
                .parse()
                .unwrap(),
        ];
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        seed_bootnode_tags(&mut state, &peerstore, &bootnodes);
        assert!(state.bootnode_peers.contains(&boot), "stored bootnode");
        assert!(
            state.bootnode_peers.contains(&static_boot),
            "configured /p2p/ id"
        );
        assert!(!state.bootnode_peers.contains(&gossiped));

        let t0 = Instant::now();
        state.routing.admit(boot, [1u8; 32]);
        state.routing_admitted_at.insert(boot, t0);
        assert_eq!(
            serving_peer_count(&state, t0),
            0,
            "a warm-dialed stored bootnode alone is not ready",
        );
        state.routing.admit(gossiped, [2u8; 32]);
        state.routing_admitted_at.insert(gossiped, t0);
        assert_eq!(serving_peer_count(&state, t0), 1);
    }

    /// Pin the contract that `publish_peers` actually republishes the
    /// current routing-table snapshot on `peers_watch`. The retry loop
    /// in `run_get_bytes` / `run_get_bzz` reads from this watch on every
    /// attempt, so silently breaking publication (e.g. by forgetting to
    /// call it after an admit / forget) reverts us to the frozen-snapshot
    /// regression that produced the "io: <peer>/N: connection is closed"
    /// 502s on multi-MiB media files.
    #[test]
    fn publish_peers_reflects_admit_and_forget() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let mut rx = state.peers_watch.subscribe();
        // Initial state: empty.
        assert!(rx.borrow_and_update().is_empty());

        let p1 = pid();
        let o1 = [1u8; 32];
        state.routing.admit(p1, o1);
        state.publish_peers();
        let v = rx.borrow_and_update().clone();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], (p1, o1));

        let p2 = pid();
        let o2 = [2u8; 32];
        state.routing.admit(p2, o2);
        state.publish_peers();
        let v = rx.borrow_and_update().clone();
        assert_eq!(v.len(), 2, "two peers visible after second admit");
        assert!(v.contains(&(p1, o1)));
        assert!(v.contains(&(p2, o2)));

        state.routing.forget(&p1);
        state.publish_peers();
        let v = rx.borrow_and_update().clone();
        assert_eq!(v.len(), 1, "only the un-forgotten peer remains");
        assert_eq!(v[0], (p2, o2));
    }

    /// Pin the contract that the "bee peerstore stall" warning fires
    /// exactly once for the first matching handshake and never again,
    /// regardless of how many slow peers follow. Operators get told,
    /// then we shut up.
    #[test]
    fn bee_peerstore_stall_warning_is_one_shot() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let stall = OutboundPipelineMs {
            dial_ms: Some(50),
            identifying_ms: 50,
            handshake_ms: 8_000,
        };
        assert!(!state.bee_peerstore_stall_warning_emitted);
        maybe_warn_bee_peerstore_stall(&mut state, pid(), &stall);
        assert!(
            state.bee_peerstore_stall_warning_emitted,
            "first matching handshake must arm the flag",
        );
        // Reset the flag manually to verify it only flips on a match;
        // a second call shouldn't flip it back without the threshold.
        state.bee_peerstore_stall_warning_emitted = false;
        let healthy = OutboundPipelineMs {
            dial_ms: Some(50),
            identifying_ms: 50,
            handshake_ms: 200,
        };
        maybe_warn_bee_peerstore_stall(&mut state, pid(), &healthy);
        assert!(
            !state.bee_peerstore_stall_warning_emitted,
            "fast handshake must not arm the flag",
        );
    }

    /// `/bytes` retries its root fetch through a cold or flaky pool but
    /// not through a corroborated miss, so a missing reference that more
    /// than a couple of peers confirmed 404s promptly (issue #117); a
    /// thin miss is retried until the resolution budget runs out.
    #[test]
    fn bytes_root_retries_all_but_a_confirmed_miss() {
        let err = |m: &str| -> Box<dyn std::error::Error + Send + Sync> { m.into() };
        for transient in [
            "no BZZ peers available",
            "all peers failed for chunk ab after 3 attempts (last: open retrieval stream: \
             failed to open stream: io error: oneshot canceled)",
        ] {
            assert!(
                is_bytes_root_transient(err(transient).as_ref()),
                "{transient}"
            );
        }
        for miss in [
            "all peers failed for chunk ab after 5 attempts (last: remote: retrieve chunk: \
             storage: not found)",
            "all peers failed for chunk ab after 5 attempts (last: remote: retrieve chunk: \
             no peer found)",
        ] {
            assert!(!is_bytes_root_transient(err(miss).as_ref()), "{miss}");
        }
    }

    /// A listing page's own outcomes (PR #260, R1-F1/R1-M1): out of time
    /// before any item is a 503 (a warm retry gets further), a page cut
    /// short by the clock is not cached immutably, and a non-UTF-8 path
    /// is a 404 (the content's answer, not the network's).
    #[test]
    fn manifest_page_ack_types_time_and_utf8_outcomes() {
        use ant_retrieval::{ManifestError, ManifestPage, ReplicaSweeps};
        let sweeps = ReplicaSweeps::for_listing();
        let ack = manifest_page_ack(&[0; 32], Err(ManifestError::ListTimedOut), &sweeps);
        assert!(matches!(ack, ControlAck::NotReady { .. }), "{ack:?}");
        let ack = manifest_page_ack(
            &[0; 32],
            Err(ManifestError::ListNonUtf8Path {
                path_lossy: "caf\u{FFFD}".into(),
            }),
            &sweeps,
        );
        assert!(matches!(ack, ControlAck::NotFound { .. }), "{ack:?}");
        let ack = manifest_page_ack(&[0; 32], Err(ManifestError::ListBudgetExceeded), &sweeps);
        assert!(matches!(ack, ControlAck::Error { .. }), "{ack:?}");
        let page = |timed_out| ManifestPage {
            truncated: true,
            next_marker: Some("a".into()),
            timed_out,
            ..ManifestPage::default()
        };
        let ControlAck::ManifestPage(full) = manifest_page_ack(&[0; 32], Ok(page(false)), &sweeps)
        else {
            panic!("not a page");
        };
        assert!(full.immutable);
        let ControlAck::ManifestPage(cut) = manifest_page_ack(&[0; 32], Ok(page(true)), &sweeps)
        else {
            panic!("not a page");
        };
        assert!(!cut.immutable);
        assert!(cut.truncated);
        let ControlAck::ManifestPage(blind) = manifest_page_ack(
            &[0; 32],
            Ok(ManifestPage {
                lookahead_failed: true,
                ..page(false)
            }),
            &sweeps,
        ) else {
            panic!("not a page");
        };
        assert!(!blind.immutable);
        assert!(blind.truncated);
    }

    /// Issue #123: a `/bytes` or `/bzz` root that peers confirmed missing
    /// ends in a typed `NotFound` (the gateway's 404) for *both* of bee's
    /// miss tails, `storage: not found` and `no peer found` — the latter
    /// used to end in a plain `Error`, i.e. a 502. The fetcher's error is
    /// found bare (`/bytes`, `/bzz` data root) and wrapped in the manifest
    /// walk's `ManifestError::Fetch` (`/bzz` root), and the miss is final
    /// there too. A miss from a starved pool is never a 404 (#114).
    #[test]
    fn pre_stream_failure_ack_types_each_miss_tail() {
        use ant_retrieval::fetcher::FetchExhausted;
        use ant_retrieval::{JoinError, ManifestError};
        let message = |tail: &str| {
            format!("all peers failed for chunk ab after 34 attempts (last: remote: retrieve chunk: {tail})")
        };
        // `answers`: how many peers said "not found" (34 = every one asked).
        let bare_n =
            |tail: &str, starved, not_found, answers| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(
                    FetchExhausted::new(message(tail), starved, not_found)
                        .with_not_found_answers(answers),
                )
            };
        let bare = |tail: &str, starved, not_found: bool| {
            bare_n(tail, starved, not_found, if not_found { 34 } else { 0 })
        };
        let wrapped_n = |tail: &str, starved, not_found, answers| {
            ManifestError::Fetch(JoinError::FetchChunk {
                addr: "ab".into(),
                source: bare_n(tail, starved, not_found, answers),
            })
        };
        let wrapped = |tail: &str, starved, not_found: bool| {
            wrapped_n(tail, starved, not_found, if not_found { 34 } else { 0 })
        };
        let kind = |ack: &ControlAck| match ack {
            ControlAck::NotFound { .. } => "NotFound",
            ControlAck::NotReady { .. } => "NotReady",
            ControlAck::Error { .. } => "Error",
            other => panic!("unexpected {other:?}"),
        };
        for tail in ["no peer found", "storage: not found"] {
            let ack = pre_stream_failure_ack("m".into(), bare(tail, false, true).as_ref());
            assert_eq!(kind(&ack), "NotFound", "bare {tail}");
            let e = wrapped(tail, false, true);
            assert_eq!(
                kind(&pre_stream_failure_ack("m".into(), &e)),
                "NotFound",
                "{tail}"
            );
            // Final: neither `/bytes` nor the `/bzz` lookup retries it.
            assert!(
                !is_bytes_root_transient(bare(tail, false, true).as_ref()),
                "{tail}"
            );
            assert!(is_final_miss(&e), "{tail}");
            // R3-M1 on PR #155: without a transient replica sweep of the
            // node in this attempt, a corroborated miss ends the lookup.
            let sweeps = ant_retrieval::ReplicaSweeps::new();
            assert!(!is_bzz_lookup_retryable(&e, false, &sweeps), "{tail}");
            // R4-M1 on PR #155: once retries run out, the same
            // corroborated miss is a 404 only if the node's replica sweep
            // didn't just miss transiently; otherwise it's a 503.
            assert_eq!(
                kind(&bzz_lookup_failure_ack("m".into(), &e, false)),
                "NotFound",
                "{tail}"
            );
            assert_eq!(
                kind(&bzz_lookup_failure_ack("m".into(), &e, true)),
                "NotReady",
                "swept transiently {tail}"
            );

            // R1-M2 on PR #124: a cold node's only peer answering the
            // miss (every ranked peer asked, so not starved) is still the
            // 404 to give once retries run out, but neither `/bytes` nor
            // the `/bzz` lookup stops retrying on it at once.
            let ack = pre_stream_failure_ack("m".into(), bare_n(tail, false, true, 1).as_ref());
            assert_eq!(kind(&ack), "NotFound", "thin {tail}");
            assert!(
                is_bytes_root_transient(bare_n(tail, false, true, 1).as_ref()),
                "thin {tail}"
            );
            let e = wrapped_n(tail, false, true, 2);
            assert_eq!(kind(&pre_stream_failure_ack("m".into(), &e)), "NotFound");
            assert!(!is_final_miss(&e), "thin {tail}");
            assert!(is_bzz_lookup_retryable(&e, false, &sweeps), "thin {tail}");

            // Starved: one cold peer's answer, retried and never a 404.
            let ack = pre_stream_failure_ack("m".into(), bare(tail, true, true).as_ref());
            assert_eq!(kind(&ack), "NotReady", "starved {tail}");
            let e = wrapped(tail, true, true);
            assert_eq!(kind(&pre_stream_failure_ack("m".into(), &e)), "NotReady");
            assert!(
                is_bytes_root_transient(bare(tail, true, true).as_ref()),
                "{tail}"
            );
            assert!(!is_final_miss(&e), "{tail}");
        }
        // Not a miss: unchanged, a plain error (502) that is retried.
        let e = bare("timeout", false, false);
        assert_eq!(
            kind(&pre_stream_failure_ack("m".into(), e.as_ref())),
            "Error"
        );
        assert!(is_bytes_root_transient(e.as_ref()));
        let e: Box<dyn std::error::Error + Send + Sync> = "no BZZ peers available".into();
        assert_eq!(
            kind(&pre_stream_failure_ack("m".into(), e.as_ref())),
            "Error"
        );
        assert!(!is_final_miss(&ManifestError::NotAManifest));
    }

    /// Issue #173 / R1-F1 on PR #183: only an anchor miss the network
    /// corroborated is bee's `404 "no update found"`. One or two cold
    /// peers' miss is a `NotReady` (503), so a publisher reading its
    /// feed head never takes a cold node's miss for an empty feed and
    /// rewrites the channel from index 0.
    #[test]
    fn feed_lookup_ack_needs_a_corroborated_miss_for_not_found() {
        let ack = feed_lookup_ack(Err(ant_retrieval::FeedError::NoUpdates {
            probed: 1,
            corroborated: true,
        }));
        assert!(matches!(ack, ControlAck::FeedNotFound), "{ack:?}");
        let ack = feed_lookup_ack(Err(ant_retrieval::FeedError::NoUpdates {
            probed: 1,
            corroborated: false,
        }));
        assert!(matches!(ack, ControlAck::NotReady { .. }), "{ack:?}");
        // R2-F1: an exact read whose next slot isn't confirmed empty
        // may sit below the real head, so it is a 503 too.
        let ack = feed_lookup_ack(Err(ant_retrieval::FeedError::EndUnconfirmed {
            index: 9,
            reason: "index 10: feed probe for index 10 exceeded 800 ms deadline".into(),
        }));
        assert!(matches!(ack, ControlAck::NotReady { .. }), "{ack:?}");
        let ack = feed_lookup_ack(Err(ant_retrieval::FeedError::OwnerMismatch));
        assert!(matches!(ack, ControlAck::Error { .. }), "{ack:?}");
    }

    /// Pin the contract that `is_manifest_transient` treats a feed
    /// dereference whose underlying chunk fetch failed as transient.
    /// This is the read-path equivalent of marking a normal manifest
    /// node fetch failure transient: without it, "no BZZ peers
    /// available" raised inside `resolve_sequence_feed` escapes the
    /// `run_get_bzz` retry loop and surfaces to the gateway as a 404
    /// — even though the very next attempt could have a fresh peer
    /// snapshot that resolves the feed cleanly.
    #[test]
    fn is_manifest_transient_classifies_feed_fetch_as_transient() {
        let inner: Box<dyn std::error::Error + Send + Sync> = "no BZZ peers available".into();
        let e = ant_retrieval::ManifestError::Feed(ant_retrieval::FeedError::Fetch(inner));
        assert!(
            is_manifest_transient(&e),
            "feed dereference chunk-fetch failures must retry",
        );

        // Terminal feed errors (no updates published, owner mismatch,
        // malformed metadata, …) must NOT retry — they would re-fail
        // the same way every time and just stretch out the user's
        // wait before the inevitable error.
        let terminal = [
            ant_retrieval::ManifestError::Feed(ant_retrieval::FeedError::NoUpdates {
                probed: 4096,
                corroborated: true,
            }),
            ant_retrieval::ManifestError::Feed(ant_retrieval::FeedError::OwnerMismatch),
            ant_retrieval::ManifestError::Feed(ant_retrieval::FeedError::InvalidMetadata(
                "bad hex".into(),
            )),
        ];
        for e in &terminal {
            assert!(
                !is_manifest_transient(e),
                "terminal feed error must not retry: {e}",
            );
        }
    }

    /// Pin the contract that `sync_external_addresses_status` projects
    /// `state.external_addresses` into the snapshot in insertion order
    /// and tags each entry with the right source string. Older clients
    /// match on the `source` field literally (no enum on the wire), so
    /// changing one of these strings is a breaking-API event.
    #[test]
    fn external_addresses_status_attributes_source_in_order() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let (tx, rx) = watch::channel(StatusSnapshot::default());

        let manual: Multiaddr = "/ip4/203.0.113.10/tcp/1634".parse().unwrap();
        let upnp: Multiaddr = "/ip4/203.0.113.20/tcp/1634".parse().unwrap();
        let listener: Multiaddr = "/ip4/198.51.100.30/tcp/1634".parse().unwrap();
        let observed: Multiaddr = "/ip4/198.51.100.40/tcp/1634".parse().unwrap();

        for (addr, src, ts) in [
            (manual.clone(), ExternalAddrSource::Manual, 1000),
            (upnp.clone(), ExternalAddrSource::Upnp, 1100),
            (listener.clone(), ExternalAddrSource::Listener, 1200),
            (observed.clone(), ExternalAddrSource::Observed, 1300),
        ] {
            state.external_addresses.insert(addr.clone(), (src, ts));
            state.external_addresses_order.push(addr);
        }

        sync_external_addresses_status(Some(&tx), &state);

        let snap = rx.borrow().external_addresses.clone();
        let actual: Vec<(String, String, u64)> = snap
            .into_iter()
            .map(|e| (e.addr, e.source, e.added_at_unix))
            .collect();
        assert_eq!(
            actual,
            vec![
                (manual.to_string(), "manual".into(), 1000),
                (upnp.to_string(), "upnp".into(), 1100),
                (listener.to_string(), "listener".into(), 1200),
                (observed.to_string(), "observed".into(), 1300),
            ],
        );
    }

    /// Drop one entry and verify the snapshot reflects it without disturbing
    /// the ordering of the remaining ones. This is the path `UPnP` renewal
    /// failures take (`Event::ExpiredExternalAddr` →
    /// `forget_external_address`); regressing it would silently keep stale
    /// addresses on display long after the mapping is gone.
    #[test]
    fn external_addresses_status_drops_retracted_entry() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let (tx, rx) = watch::channel(StatusSnapshot::default());

        let a: Multiaddr = "/ip4/203.0.113.10/tcp/1634".parse().unwrap();
        let b: Multiaddr = "/ip4/203.0.113.20/tcp/1634".parse().unwrap();
        let c: Multiaddr = "/ip4/203.0.113.30/tcp/1634".parse().unwrap();
        for addr in [&a, &b, &c] {
            state
                .external_addresses
                .insert(addr.clone(), (ExternalAddrSource::Upnp, 1));
            state.external_addresses_order.push(addr.clone());
        }

        state.external_addresses.remove(&b);
        state.external_addresses_order.retain(|x| x != &b);
        sync_external_addresses_status(Some(&tx), &state);

        let snap_addrs: Vec<String> = rx
            .borrow()
            .external_addresses
            .iter()
            .map(|e| e.addr.clone())
            .collect();
        assert_eq!(snap_addrs, vec![a.to_string(), c.to_string()]);
    }

    /// Pin the wire-stable source strings. Operators (and `antop`)
    /// match these literally; renaming a variant is a breaking change to
    /// the on-the-wire `StatusSnapshot::external_addresses[i].source`
    /// field.
    #[test]
    fn external_addr_source_strings_are_stable() {
        assert_eq!(ExternalAddrSource::Manual.as_str(), "manual");
        assert_eq!(ExternalAddrSource::Listener.as_str(), "listener");
        assert_eq!(ExternalAddrSource::Observed.as_str(), "observed");
        assert_eq!(ExternalAddrSource::Upnp.as_str(), "upnp");
    }

    /// A handshake that's slow because *our* identify itself was slow
    /// (e.g. local event-loop pressure) is not the bee-peerstore case
    /// and the warning would point at the wrong fix. Pin that we don't
    /// fire when `identifying_ms` itself is past the threshold.
    #[test]
    fn bee_peerstore_stall_warning_skips_slow_identify() {
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let p = OutboundPipelineMs {
            dial_ms: Some(50),
            identifying_ms: 3_000,
            handshake_ms: 8_000,
        };
        maybe_warn_bee_peerstore_stall(&mut state, pid(), &p);
        assert!(
            !state.bee_peerstore_stall_warning_emitted,
            "slow identify means our side, not bee's peerstore — don't \
             nag the operator about --external-address",
        );
    }

    /// Build a `SwarmState` whose disk cache holds the planted chunks but
    /// whose peer set is empty — the read-after-own-write fixture. The
    /// upload path stashes uploads into this same disk cache before
    /// pushsync, so a read served from here without any peers proves the
    /// handler consults the local cache rather than going straight to the
    /// (here, non-existent) network.
    fn state_with_disk_cache(disk: Arc<ant_retrieval::DiskChunkCache>) -> SwarmState {
        SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            Some(disk),
            crate::PeerEthMap::new(),
        )
    }

    /// A bare libp2p stream control, good enough to construct the fetcher
    /// in the spawned read tasks. With an empty peer set no stream is ever
    /// opened on it, so the cache hit must answer first.
    fn test_control() -> Control {
        libp2p_stream::Behaviour::default().new_control()
    }

    /// Read-after-own-write for `GetChunkRaw`: a chunk present only in the
    /// node's local disk cache (where the upload path stashes it before
    /// pushsync) must be served verbatim with no peers available. This is
    /// the path behind SOC-read-by-address and exact-index feed reads
    /// (#6 / #7).
    #[tokio::test]
    async fn get_chunk_raw_serves_local_cache_without_peers() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        let (addr, wire) = ant_crypto::cac_new(b"read-after-own-write raw").unwrap();
        disk.put(addr, wire.clone()).await.unwrap();

        let mut state = state_with_disk_cache(disk);
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            None,
            0,
            ControlCommand::GetChunkRaw {
                reference: addr,
                fast_miss: true,
                bypass_cache: false,
                ack: ack_tx,
            },
        );
        match ack_rx.await.unwrap() {
            ControlAck::Bytes { data } => {
                assert_eq!(data, wire, "GetChunkRaw must return the full wire bytes");
            }
            other => panic!("expected cached wire bytes, got {other:?}"),
        }
    }

    /// `swarm-cache: false` on `/chunks` (issue #80): with `bypass_cache`
    /// the lookup must not be answered from the local caches. The chunk
    /// sits in both the shared memory and the disk cache, there are no
    /// peers, so a bypassed read can only fail; the same read without
    /// the flag is served locally.
    #[tokio::test]
    async fn get_chunk_raw_bypass_cache_skips_local_caches() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        let (addr, wire) = ant_crypto::cac_new(b"swarm-cache false").unwrap();
        disk.put(addr, wire.clone()).await.unwrap();
        let mut state = state_with_disk_cache(disk);
        state
            .chunk_cache
            .as_ref()
            .expect("shared memory cache")
            .put(addr, wire.clone());
        let mut peerstore = PeerStore::disabled();
        let control = test_control();

        for (bypass_cache, served) in [(true, false), (false, true)] {
            let (ack_tx, ack_rx) = oneshot::channel();
            handle_control_command(
                &mut state,
                &mut peerstore,
                &control,
                None,
                0,
                ControlCommand::GetChunkRaw {
                    reference: addr,
                    fast_miss: true,
                    bypass_cache,
                    ack: ack_tx,
                },
            );
            let ack = tokio::time::timeout(Duration::from_secs(30), ack_rx)
                .await
                .expect("lookup with no peers must end")
                .unwrap();
            match ack {
                ControlAck::Bytes { data } => {
                    assert!(served, "bypass_cache read was served locally");
                    assert_eq!(data, wire);
                }
                other => assert!(!served, "expected a cache hit, got {other:?}"),
            }
        }
    }

    /// The per-request cache routing behind every `bypass_cache` flag:
    /// bypassed requests get a private memory cache and no disk cache,
    /// so nothing they fetch is read from or written to the shared
    /// tiers; other requests share the daemon's caches.
    #[test]
    fn bypass_cache_routes_requests_away_from_shared_caches() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        let state = state_with_disk_cache(disk.clone());
        let shared = state.chunk_cache.clone().expect("shared memory cache");

        assert!(Arc::ptr_eq(&state.cache_for_request(false), &shared));
        assert!(Arc::ptr_eq(
            &state.disk_cache_for_request(false).expect("disk cache"),
            &disk
        ));
        assert!(!Arc::ptr_eq(&state.cache_for_request(true), &shared));
        assert!(state.disk_cache_for_request(true).is_none());
    }

    /// Read-after-own-write for `GetChunk`: the same local-cache hit, but
    /// this handler acks the payload (wire minus the 8-byte span).
    #[tokio::test]
    async fn get_chunk_serves_local_cache_payload_without_peers() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        let payload = b"read-after-own-write payload";
        let (addr, wire) = ant_crypto::cac_new(payload).unwrap();
        disk.put(addr, wire.clone()).await.unwrap();

        let mut state = state_with_disk_cache(disk);
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            None,
            0,
            ControlCommand::GetChunk {
                reference: addr,
                ack: ack_tx,
            },
        );
        match ack_rx.await.unwrap() {
            ControlAck::Bytes { data } => {
                assert_eq!(
                    data, payload,
                    "GetChunk must return the span-stripped payload"
                );
            }
            other => panic!("expected cached payload bytes, got {other:?}"),
        }
    }

    /// Read-after-own-write for `GetFeed`: a freshly-signed sequence
    /// update at index 0 stashed in the local disk cache must let "latest"
    /// resolution find it with no peers — the exact case the old "feed
    /// updates rarely repeat" opt-out broke (#6 / #7).
    #[tokio::test]
    async fn get_feed_resolves_latest_from_local_cache_without_peers() {
        use k256::ecdsa::{SigningKey, VerifyingKey};

        let secret: [u8; 32] = [7u8; 32];
        let sk = SigningKey::from_bytes((&secret).into()).unwrap();
        let owner = ant_crypto::ethereum_address_from_public_key(&VerifyingKey::from(&sk));
        let topic: [u8; 32] = [0xaau8; 32];

        let (soc_addr, wire) = feed_update_v1(&secret, &owner, &topic, 0, &[0xbbu8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        disk.put(soc_addr, wire).await.unwrap();

        let mut state = state_with_disk_cache(disk);
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            None,
            0,
            ControlCommand::GetFeed {
                owner,
                topic,
                after: 0,
                exact: false,
                ack: ack_tx,
            },
        );
        match ack_rx.await.unwrap() {
            ControlAck::FeedResolved { index, .. } => {
                assert_eq!(index, 0, "the cached index-0 update must resolve as latest");
            }
            other => panic!("expected the cached feed update to resolve, got {other:?}"),
        }
    }

    /// A **v2** feed resolution must leave the update's wrapped CAC in
    /// the node's mem cache under its own address: bee serves the
    /// wrapped chunk straight from the SOC, and for v2 updates that CAC
    /// exists nowhere else on the network — without the seed, the
    /// gateway's follow-up content fetch 404s on every node that didn't
    /// author the update (perf-lab baseline: 0/45 cold resolutions).
    #[tokio::test]
    async fn get_feed_seeds_wrapped_v2_cac_into_cache() {
        use k256::ecdsa::{SigningKey, VerifyingKey};

        let secret: [u8; 32] = [9u8; 32];
        let sk = SigningKey::from_bytes((&secret).into()).unwrap();
        let owner = ant_crypto::ethereum_address_from_public_key(&VerifyingKey::from(&sk));
        let topic: [u8; 32] = [0xccu8; 32];

        // v2: the wrapped CAC is the content itself (length ≠ 48/80).
        let content = b"wrapped v2 feed content, served from the SOC";
        let (inner_addr, inner_wire) = ant_crypto::cac_new(content).unwrap();
        let (soc_addr, wire) = feed_update_wrapping(&secret, &owner, &topic, 0, &inner_wire);

        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        disk.put(soc_addr, wire).await.unwrap();

        let mut state = state_with_disk_cache(disk);
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            None,
            0,
            ControlCommand::GetFeed {
                owner,
                topic,
                after: 0,
                exact: false,
                ack: ack_tx,
            },
        );
        match ack_rx.await.unwrap() {
            ControlAck::FeedResolved { reference, v2, .. } => {
                assert!(v2, "wrapped-content update must classify as v2");
                assert_eq!(reference, inner_addr);
            }
            other => panic!("expected v2 resolution, got {other:?}"),
        }
        let cached = state
            .chunk_cache
            .as_ref()
            .expect("shared mem cache")
            .get(&inner_addr);
        assert_eq!(
            cached.as_deref(),
            Some(inner_wire.as_slice()),
            "resolution must seed the wrapped CAC so the content fetch never hits the network"
        );
    }

    /// Like [`feed_update_v1`] but wraps caller-supplied CAC wire (v2
    /// updates wrap the content chunk itself).
    fn feed_update_wrapping(
        secret: &[u8; 32],
        owner: &[u8; 20],
        topic: &[u8; 32],
        index: u64,
        inner_cac_wire: &[u8],
    ) -> ([u8; 32], Vec<u8>) {
        let mut id_input = Vec::with_capacity(40);
        id_input.extend_from_slice(topic);
        id_input.extend_from_slice(&index.to_be_bytes());
        let id = ant_crypto::keccak256(&id_input);

        let inner_span: &[u8; 8] = inner_cac_wire[..8].try_into().unwrap();
        let inner_cac_addr =
            ant_crypto::bmt_hash_with_span(inner_span, &inner_cac_wire[8..]).unwrap();

        let mut sig_input = Vec::with_capacity(64);
        sig_input.extend_from_slice(&id);
        sig_input.extend_from_slice(&inner_cac_addr);
        let prehash = ant_crypto::keccak256(&sig_input);
        let sig = ant_crypto::sign_handshake_data(secret, &prehash).unwrap();

        let mut soc_addr_input = Vec::with_capacity(52);
        soc_addr_input.extend_from_slice(&id);
        soc_addr_input.extend_from_slice(owner);
        let soc_addr = ant_crypto::keccak256(&soc_addr_input);

        let mut wire = Vec::with_capacity(ant_crypto::SOC_HEADER_SIZE + inner_cac_wire.len());
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(inner_cac_wire);
        (soc_addr, wire)
    }

    /// Build a v1 sequence feed-update SOC exactly the way a bee-compatible
    /// client (and the gateway's `upload_soc` → `PushSoc` path) addresses
    /// it: `id = keccak256(topic ‖ index_be8)`, SOC address =
    /// `keccak256(id ‖ owner)` — the same address
    /// `ant_retrieval::sequence_update_address` recomputes when `GetFeed`
    /// walks the sequence. Returns `(soc_address, wire)` where wire is
    /// `id ‖ sig ‖ inner_cac`.
    fn feed_update_v1(
        secret: &[u8; 32],
        owner: &[u8; 20],
        topic: &[u8; 32],
        index: u64,
        wrapped_ref: &[u8; 32],
    ) -> ([u8; 32], Vec<u8>) {
        let mut id_input = Vec::with_capacity(40);
        id_input.extend_from_slice(topic);
        id_input.extend_from_slice(&index.to_be_bytes());
        let id = ant_crypto::keccak256(&id_input);

        let mut update_payload = Vec::with_capacity(40);
        update_payload.extend_from_slice(&[0u8; 8]);
        update_payload.extend_from_slice(wrapped_ref);
        let (inner_cac_addr, inner_cac_wire) = ant_crypto::cac_new(&update_payload).unwrap();

        let mut sig_input = Vec::with_capacity(64);
        sig_input.extend_from_slice(&id);
        sig_input.extend_from_slice(&inner_cac_addr);
        let prehash = ant_crypto::keccak256(&sig_input);
        let sig = ant_crypto::sign_handshake_data(secret, &prehash).unwrap();

        let mut soc_addr_input = Vec::with_capacity(52);
        soc_addr_input.extend_from_slice(&id);
        soc_addr_input.extend_from_slice(owner);
        let soc_addr = ant_crypto::keccak256(&soc_addr_input);

        let mut wire = Vec::with_capacity(ant_crypto::SOC_HEADER_SIZE + inner_cac_wire.len());
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&inner_cac_wire);
        (soc_addr, wire)
    }

    /// The auto-index regression from #8: two consecutive feed updates
    /// (indices 0 then 1) stashed in the node's local cache the way two
    /// `POST /soc` writes would, then `GetFeed` must resolve **index 1**
    /// (the latest) — not `feed_empty` and not the stale index 0. This is
    /// the node-side guarantee that makes the client's auto-index
    /// (`writeFeedEntry({name})` returns 0 then 1) and
    /// `readFeedEntry({name})`-after-write deterministic with no network.
    #[tokio::test]
    async fn get_feed_resolves_latest_across_two_cached_updates() {
        use k256::ecdsa::{SigningKey, VerifyingKey};

        let secret: [u8; 32] = [9u8; 32];
        let sk = SigningKey::from_bytes((&secret).into()).unwrap();
        let owner = ant_crypto::ethereum_address_from_public_key(&VerifyingKey::from(&sk));
        let topic: [u8; 32] = [0xccu8; 32];

        let dir = tempfile::tempdir().unwrap();
        let disk = Arc::new(
            ant_retrieval::DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap(),
        );
        // Two sequential updates pointing at distinct references.
        for (index, wrapped) in [(0u64, [0x01u8; 32]), (1u64, [0x02u8; 32])] {
            let (addr, wire) = feed_update_v1(&secret, &owner, &topic, index, &wrapped);
            disk.put(addr, wire).await.unwrap();
        }

        let mut state = state_with_disk_cache(disk);
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            None,
            0,
            ControlCommand::GetFeed {
                owner,
                topic,
                after: 0,
                exact: false,
                ack: ack_tx,
            },
        );
        match ack_rx.await.unwrap() {
            ControlAck::FeedResolved { index, .. } => {
                assert_eq!(index, 1, "latest of two cached updates must be index 1");
            }
            other => panic!("expected the latest cached update to resolve, got {other:?}"),
        }
    }

    /// `DisablePushsyncSwap` switches off settlement running on the named
    /// chequebook — the path `ant-ffi` takes when the chain disqualifies
    /// the chequebook `ant_init` enabled unchecked — and leaves a service
    /// on any other chequebook alone.
    /// Issue #121 wiring: retrieval accounting pays through the outbound
    /// SWAP service only with funds known for the chequebook that
    /// service runs on, while the switch is on; funds that arrive before
    /// the service starts are applied once it does. Everything else
    /// (no chequebook, unknown or zero funds, another chequebook's funds,
    /// switch off, settlement disabled) leaves downloads on the free tier.
    #[tokio::test]
    async fn retrieval_pays_only_with_funds_for_the_running_chequebook() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let accounting = Arc::new(ant_retrieval::accounting::Accounting::new());
        state.accounting = Some(accounting.clone());
        let (status_tx, status_rx) = watch::channel(StatusSnapshot::default());
        state.status = Some(status_tx);
        let settlement = || status_rx.borrow().settlement.clone();
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (cb, other) = ([0xcbu8; 20], [0x0cu8; 20]);
        let mut send = |state: &mut SwarmState, cmd| {
            handle_control_command(state, &mut peerstore, &control, None, 0, cmd);
        };
        let funds = |state: &mut SwarmState,
                     send: &mut dyn FnMut(&mut SwarmState, ControlCommand),
                     chequebook,
                     deposited| {
            let (ack, _rx) = oneshot::channel();
            send(
                state,
                ControlCommand::SetRetrievalFunds {
                    chequebook,
                    deposited_plur: deposited,
                    exchange_rate_plur: 100_000,
                    deduction_plur: 100,
                    ack,
                },
            );
        };

        // Funds before settlement runs: kept, nothing to pay with yet.
        funds(&mut state, &mut send, cb, 10_000_000_000_000);
        assert!(!accounting.pays_with_swap());

        let (ack, _rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::EnablePushsyncSwap {
                chequebook: cb,
                swap_secret: [3u8; 32],
                chain_id: 100,
                outbound_ledger_path: dir.path().join("out.json").to_string_lossy().into(),
                ack,
            },
        );
        assert!(accounting.pays_with_swap(), "earlier funds apply on enable");
        // ... and the status hosts read says so (`GET /node`,
        // `/v0/settlement/swap`, `ant_swap_status`).
        assert_eq!(
            settlement(),
            ant_control::SettlementInfo {
                swap_enabled: true,
                chequebook: Some(format!("0x{}", hex::encode(cb))),
                paying: true,
                // The funds read before settlement started, nothing
                // issued yet: all of it is still available.
                deposited_plur: Some("10000000000000".into()),
                issued_plur: Some("0".into()),
                available_plur: Some("10000000000000".into()),
            }
        );

        let (ack, _rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::SetSwapEnabled {
                enabled: false,
                ack,
            },
        );
        assert!(!accounting.pays_with_swap(), "switch off: free tier");
        assert!(!settlement().swap_enabled);
        assert!(!settlement().paying);
        let (ack, _rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::SetSwapEnabled { enabled: true, ack },
        );
        assert!(accounting.pays_with_swap());

        funds(&mut state, &mut send, other, 10_000_000_000_000);
        assert!(!accounting.pays_with_swap(), "another chequebook's funds");
        funds(&mut state, &mut send, cb, 0);
        assert!(!accounting.pays_with_swap(), "an empty chequebook");
        funds(&mut state, &mut send, cb, 10_000_000_000_000);
        assert!(accounting.pays_with_swap());

        let (ack, _rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::DisablePushsyncSwap {
                chequebook: cb,
                ack,
            },
        );
        assert!(!accounting.pays_with_swap(), "settlement off");
    }

    /// Uploads settle like bee (issue #127): with a chequebook, every
    /// accepted push reserves its credit (issue #128) and is debited to the one accounting mirror retrieval
    /// uses — even with `ANT_PUSH_PSEUDOSETTLE=0`, which only opts a
    /// chequebook-less node out — so the payer installed there pays push
    /// debt with the same cheques, at the early-payment threshold, and
    /// the debt drops only by what a delivered cheque covers. Before #127
    /// the chequebook's pushsync service kept its own counter instead and
    /// paid `debt` PLUR, which the mirror never saw.
    #[tokio::test]
    async fn uploads_settle_through_the_shared_payer() {
        #[derive(Default)]
        struct Payer {
            calls: std::sync::Mutex<Vec<(PeerId, u64)>>,
            refuse: std::sync::atomic::AtomicBool,
        }
        #[async_trait::async_trait]
        impl ant_retrieval::accounting::RetrievalPayment for Payer {
            async fn pay(&self, peer: PeerId, amount: u64) -> Result<(), String> {
                self.calls.lock().unwrap().push((peer, amount));
                if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                    Err("connection closed as the cheque stream ended".into())
                } else {
                    Ok(())
                }
            }
        }
        let accounting = Arc::new(ant_retrieval::accounting::Accounting::new());
        assert!(push_settlement(Some(accounting.clone()), false, false).is_none());
        assert!(push_settlement(Some(accounting.clone()), false, true).is_some());
        let push = push_settlement(Some(accounting.clone()), true, false)
            .expect("a chequebook settles pushsync through the mirror");

        let payer = Arc::new(Payer::default());
        accounting.set_payment(Some(payer.clone()));
        let settle = || tokio::time::sleep(Duration::from_millis(20));
        // One push with a receipt: credit reserved first (issue #128),
        // then applied.
        let push_receipt = |peer: PeerId| {
            push.prepare_credit(peer, 300_000)
                .expect("inside the peer's credit limit")
                .apply();
        };
        let peer = PeerId::random();
        accounting.credit(peer, 0); // a refresh was accepted just now
        push_receipt(peer);
        push_receipt(peer);
        settle().await;
        assert!(payer.calls.lock().unwrap().is_empty(), "600 k < 675 k");
        assert_eq!(accounting.debug_snapshot(&peer), Some((600_000, 0)));
        push_receipt(peer);
        settle().await;
        assert_eq!(*payer.calls.lock().unwrap(), vec![(peer, 600_000)]);
        assert_eq!(accounting.debug_snapshot(&peer), Some((300_000, 0)));
        assert_eq!(accounting.swap_settled(&peer), 600_000);

        // An undelivered cheque (reset with the connection, timeout)
        // lowers nothing.
        payer
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let other = PeerId::random();
        accounting.credit(other, 0);
        for _ in 0..3 {
            push_receipt(other);
        }
        settle().await;
        assert_eq!(payer.calls.lock().unwrap().len(), 2);
        assert_eq!(accounting.debug_snapshot(&other), Some((900_000, 0)));
        assert_eq!(accounting.swap_settled(&other), 0);

        // `swap-enable` off removes the payer: push debt waits for the
        // refresh, as on a node without a chequebook.
        accounting.set_payment(None);
        let third = PeerId::random();
        accounting.credit(third, 0);
        for _ in 0..3 {
            push_receipt(third);
        }
        settle().await;
        assert_eq!(payer.calls.lock().unwrap().len(), 2);
        assert_eq!(accounting.debug_snapshot(&third), Some((900_000, 0)));
    }

    /// Issue #128: a push through the gateway / upload-job path
    /// (`push_with_stamp`) never pushes to a peer at its credit limit,
    /// and all of `push_with_patience`'s re-walks share one credit-wait
    /// budget, so a pool that stays at its limit costs one
    /// `CREDIT_WAIT_BUDGET` of waiting, not one per re-walk, before the
    /// push is handed back (the upload job re-queues it).
    #[tokio::test(start_paused = true)]
    async fn push_credit_waits_share_one_budget_across_rewalks() {
        use ant_retrieval::accounting::{Accounting, CREDIT_WAIT_BUDGET, OVERDRAFT_LIMIT};
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let accounting = Arc::new(Accounting::new());
        state.accounting = Some(accounting.clone());
        let peer = PeerId::random();
        state.peers_watch.send_replace(vec![(peer, [0x80u8; 32])]);
        let _held = accounting
            .try_reserve(peer, OVERDRAFT_LIMIT)
            .expect("a fresh peer has its whole limit");
        let behaviour = libp2p_stream::Behaviour::default();
        let (ack, rx) = oneshot::channel();
        let started = tokio::time::Instant::now();
        push_with_stamp(
            &state,
            &behaviour.new_control(),
            1,
            [0u8; 32],
            vec![0u8; 16],
            [0u8; ant_postage::STAMP_SIZE],
            false,
            false,
            ack,
        );
        let reply = rx.await.expect("acked");
        let took = started.elapsed();
        let ControlAck::Error { message } = reply else {
            panic!("expected an error, got {reply:?}");
        };
        assert!(message.contains("no pushsync peer has credit"), "{message}");
        assert_eq!(
            accounting.debug_snapshot(&peer),
            Some((0, OVERDRAFT_LIMIT)),
            "nothing was pushed to the peer",
        );
        // One budget of waiting, then re-walks that don't wait until the
        // patience runs out (≤ 1.75 s between walks).
        assert!(
            took >= CREDIT_WAIT_BUDGET
                && took <= gateway_push_patience().max(CREDIT_WAIT_BUDGET) + Duration::from_secs(2),
            "push took {took:?}",
        );
    }

    #[tokio::test]
    async fn disable_pushsync_swap_only_stops_the_named_chequebook() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let (bad, other) = ([0xbau8; 20], [0x0cu8; 20]);
        let mut send = |state: &mut SwarmState, cmd| {
            handle_control_command(state, &mut peerstore, &control, None, 0, cmd);
        };

        let (ack, rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::EnablePushsyncSwap {
                chequebook: bad,
                swap_secret: [3u8; 32],
                chain_id: 100,
                outbound_ledger_path: dir.path().join("out.json").to_string_lossy().into(),
                ack,
            },
        );
        assert!(matches!(rx.await.unwrap(), ControlAck::Ok { .. }));
        assert_eq!(
            state.pushsync_swap.as_ref().map(|s| s.chequebook()),
            Some(bad)
        );

        // A disable naming another chequebook is a no-op.
        let (ack, rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::DisablePushsyncSwap {
                chequebook: other,
                ack,
            },
        );
        assert!(matches!(rx.await.unwrap(), ControlAck::Ok { .. }));
        assert_eq!(
            state.pushsync_swap.as_ref().map(|s| s.chequebook()),
            Some(bad)
        );

        let (ack, rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::DisablePushsyncSwap {
                chequebook: bad,
                ack,
            },
        );
        assert!(matches!(rx.await.unwrap(), ControlAck::Ok { .. }));
        assert!(state.pushsync_swap.is_none(), "settlement is off again");
    }

    /// Switching settlement off doesn't make its cheques vanish from the
    /// accounting snapshot (PR #126 R2-M1): the total keeps coming, and
    /// it names the chequebook it counts.
    #[tokio::test]
    async fn accounting_snapshot_names_the_chequebook_its_issued_total_counts() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        let cb = [0xcbu8; 20];
        let mut send = |state: &mut SwarmState, cmd| {
            handle_control_command(state, &mut peerstore, &control, None, 0, cmd);
        };
        assert!(build_accounting_snapshot(&state)
            .cheques_issued_chequebook
            .is_none());

        let (ack, rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::EnablePushsyncSwap {
                chequebook: cb,
                swap_secret: [3u8; 32],
                chain_id: 100,
                outbound_ledger_path: dir.path().join("out.json").to_string_lossy().into(),
                ack,
            },
        );
        assert!(matches!(rx.await.unwrap(), ControlAck::Ok { .. }));
        state
            .pushsync_swap
            .as_ref()
            .unwrap()
            .outbound_ledger()
            .record_issued(&[0x11; 20], primitive_types::U256::from(700u64))
            .unwrap();
        let snap = build_accounting_snapshot(&state);
        assert_eq!(snap.cheques_issued_plur.as_deref(), Some("700"));
        let cb_hex = hex::encode(cb);
        assert_eq!(
            snap.cheques_issued_chequebook.as_deref(),
            Some(cb_hex.as_str())
        );

        let (ack, rx) = oneshot::channel();
        send(
            &mut state,
            ControlCommand::DisablePushsyncSwap {
                chequebook: cb,
                ack,
            },
        );
        assert!(matches!(rx.await.unwrap(), ControlAck::Ok { .. }));
        let snap = build_accounting_snapshot(&state);
        assert_eq!(snap.cheques_issued_plur.as_deref(), Some("700"));
        assert_eq!(
            snap.cheques_issued_chequebook.as_deref(),
            Some(cb_hex.as_str())
        );
    }

    /// The stamper stamps a batch of queued chunks with one write per
    /// postage batch, answers each chunk in order, and fails only the
    /// chunks of a batch it doesn't know.
    #[test]
    fn the_stamper_stamps_queued_chunks_per_batch_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let known = [0x0cu8; 32];
        let issuer = ant_postage::StampIssuer::open_or_new(
            dir.path().join(format!("{}.bin", hex::encode(known))),
            known,
            20,
            16,
            false,
        )
        .unwrap();
        let rt = Arc::new(UploadRuntime {
            issuers: std::sync::Mutex::new(HashMap::from([(known, issuer)])),
            stamp_key: [1u8; SECP256K1_SECRET_LEN],
            batch_owner: [0u8; 20],
            postage_dir: dir.path().to_path_buf(),
        });
        let job = |batch_id: [u8; 32], n: u8| StampJob {
            upload: rt.clone(),
            batch_id,
            addr: [n; 32],
            wire: vec![n],
            require_deep: false,
            ack_when_stored: false,
            ack: oneshot::channel().0,
        };
        let jobs = vec![
            job(known, 1),
            job([0xeeu8; 32], 2),
            job(known, 3),
            job(known, 1),
        ];
        let out = stamp_jobs(jobs);
        assert_eq!(
            out.iter().map(|(j, _)| j.wire[0]).collect::<Vec<_>>(),
            vec![1, 2, 3, 1]
        );
        let stamp = |k: usize| *out[k].1.as_ref().unwrap();
        assert_eq!(stamp(0)[..32], known, "stamped with its batch");
        assert!(out[1].1.as_ref().unwrap_err().contains("not usable"));
        assert_ne!(
            stamp(0)[32..40],
            stamp(2)[32..40],
            "distinct chunks, distinct slots"
        );
        assert_eq!(
            stamp(0)[32..40],
            stamp(3)[32..40],
            "a repeated chunk keeps its slot"
        );
        let issuers = rt.issuers.lock().unwrap();
        assert!(
            issuers[&known].has_stamp(&[3u8; 32]),
            "recorded before release"
        );
    }

    /// `PostageList` reports a registration age only for batches the node
    /// registered at runtime (`RegisterBatch`, i.e. a buy / connect) — the
    /// gateway uses it to give a just-bought batch a grace window against
    /// a lagging RPC backend. A batch reloaded from disk carries none, so
    /// its on-chain check applies immediately.
    #[tokio::test]
    async fn postage_list_reports_registration_age_only_for_runtime_batches() {
        let dir = tempfile::tempdir().unwrap();
        let reloaded_id = [0x0au8; 32];
        let bought_id = [0x0bu8; 32];
        let reloaded = ant_postage::StampIssuer::open_or_new(
            dir.path().join(format!("{}.bin", hex::encode(reloaded_id))),
            reloaded_id,
            20,
            16,
            true,
        )
        .unwrap();
        let rt = Arc::new(UploadRuntime {
            issuers: std::sync::Mutex::new(HashMap::from([(reloaded_id, reloaded)])),
            stamp_key: [1u8; SECP256K1_SECRET_LEN],
            batch_owner: [0u8; 20],
            postage_dir: dir.path().to_path_buf(),
        });

        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let mut peerstore = PeerStore::disabled();
        let control = test_control();

        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            Some(rt.clone()),
            0,
            ControlCommand::RegisterBatch {
                batch_id: bought_id,
                depth: 20,
                bucket_depth: 16,
                immutable: true,
                bought_at_block: None,
                ack: ack_tx,
            },
        );
        assert!(matches!(ack_rx.await.unwrap(), ControlAck::Ok { .. }));

        let (ack_tx, ack_rx) = oneshot::channel();
        handle_control_command(
            &mut state,
            &mut peerstore,
            &control,
            Some(rt),
            0,
            ControlCommand::PostageList { ack: ack_tx },
        );
        let ControlAck::PostageList(views) = ack_rx.await.unwrap() else {
            panic!("expected a postage list");
        };
        let age = |id: [u8; 32]| {
            views
                .iter()
                .find(|v| v.batch_id == format!("0x{}", hex::encode(id)))
                .expect("batch listed")
                .registered_secs_ago
        };
        assert_eq!(
            age(reloaded_id),
            None,
            "reloaded batch has no registration age"
        );
        assert!(
            age(bought_id).is_some_and(|a| a < 60),
            "runtime-registered batch reports a fresh age"
        );
    }

    /// A batch registered right after its buy isn't usable until the
    /// storers can have synced its creation block (bee's confirmation
    /// window), and reports that block. A batch registered by id
    /// (connect, rediscovery) is usable at once.
    #[tokio::test]
    async fn a_just_bought_batch_is_not_usable_until_it_has_propagated() {
        let dir = tempfile::tempdir().unwrap();
        let bought_id = [0x0bu8; 32];
        let connected_id = [0x0cu8; 32];
        let rt = Arc::new(UploadRuntime {
            issuers: std::sync::Mutex::new(HashMap::new()),
            stamp_key: [1u8; SECP256K1_SECRET_LEN],
            batch_owner: [0u8; 20],
            postage_dir: dir.path().to_path_buf(),
        });
        let mut state = SwarmState::new(
            32,
            [0u8; 32],
            false,
            None,
            None,
            None,
            crate::PeerEthMap::new(),
        );
        let mut peerstore = PeerStore::disabled();
        let control = test_control();
        for (batch_id, bought_at_block) in [(bought_id, Some(48_500_000)), (connected_id, None)] {
            let (ack_tx, ack_rx) = oneshot::channel();
            handle_control_command(
                &mut state,
                &mut peerstore,
                &control,
                Some(rt.clone()),
                0,
                ControlCommand::RegisterBatch {
                    batch_id,
                    depth: 20,
                    bucket_depth: 16,
                    immutable: true,
                    bought_at_block,
                    ack: ack_tx,
                },
            );
            assert!(matches!(ack_rx.await.unwrap(), ControlAck::Ok { .. }));
        }
        let list = |state: &mut SwarmState, peerstore: &mut PeerStore| {
            let (ack_tx, mut ack_rx) = oneshot::channel();
            handle_control_command(
                state,
                peerstore,
                &control,
                Some(rt.clone()),
                0,
                ControlCommand::PostageList { ack: ack_tx },
            );
            let Ok(ControlAck::PostageList(views)) = ack_rx.try_recv() else {
                panic!("expected a postage list");
            };
            views
        };
        let find = |views: &[ant_control::PostageStatusView], id: [u8; 32]| {
            let v = views
                .iter()
                .find(|v| v.batch_id == format!("0x{}", hex::encode(id)))
                .expect("batch listed")
                .clone();
            (v.usable, v.block_number)
        };

        let views = list(&mut state, &mut peerstore);
        assert_eq!(
            find(&views, bought_id),
            (false, Some(48_500_000)),
            "just bought: not usable yet, with its creation block"
        );
        let propagating = |views: &[ant_control::PostageStatusView], id: [u8; 32]| {
            views
                .iter()
                .find(|v| v.batch_id == format!("0x{}", hex::encode(id)))
                .expect("batch listed")
                .propagating
        };
        assert!(propagating(&views, bought_id), "held back as propagating");
        assert!(!propagating(&views, connected_id));
        assert_eq!(
            find(&views, connected_id),
            (true, None),
            "connected by id: usable at once"
        );

        // Once the window has passed, the bought batch is usable.
        state.bought_batches.get_mut(&bought_id).unwrap().registered -=
            BATCH_PROPAGATION + Duration::from_secs(1);
        let views = list(&mut state, &mut peerstore);
        assert_eq!(find(&views, bought_id), (true, Some(48_500_000)));
        assert!(!propagating(&views, bought_id));
    }

    /// Bee's window: 10 blocks past creation, plus the 4 its listener
    /// trails the head, at 5 s blocks.
    #[test]
    fn the_propagation_window_is_bees_confirmation_window() {
        assert_eq!(BATCH_PROPAGATION, Duration::from_secs(70));
        // The *waiting* — the whole window, then one default patience
        // budget for a transient failure — must fit the upload
        // manager's 2-minute push timeout (and the gateway's
        // `CHUNK_PUSH_TIMEOUT` for the one-shot routes). Walk time is
        // not bounded by this: a walk in flight at the deadline runs to
        // completion (up to one 45 s pushsync timeout per candidate),
        // so the ack itself can overshoot; see
        // `PROPAGATION_REJECTION_GRACE`.
        assert!(
            BATCH_PROPAGATION + PROPAGATION_REJECTION_GRACE + Duration::from_secs(12)
                < Duration::from_mins(2)
        );
    }

    /// The patience budget doesn't stretch to a just-bought batch's
    /// propagation window: a non-rejection failure gives up after the
    /// budget from the push's start, and after a propagation wait the
    /// budget starts over from that wait.
    #[test]
    fn patience_restarts_after_a_propagation_wait_but_is_never_stretched() {
        let budget = Duration::from_secs(12);
        let t0 = tokio::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);

        // No propagation wait (e.g. only "exhausted pushsync peers"
        // failures for a just-bought batch): the plain budget, however
        // far off the batch's lag deadline is.
        let plain = Patience::new(budget, t0);
        assert!(!plain.exhausted(at(11)));
        assert!(plain.exhausted(at(12)));
        assert!(plain.exhausted(at(13)), "not held open until lag_until");

        // Storers rejected the batch until t=60, then a transient
        // failure: it still gets its re-walks for one budget.
        let mut waited = Patience::new(budget, t0);
        waited.restart(at(60));
        assert!(!waited.exhausted(at(61)));
        assert!(!waited.exhausted(at(71)));
        assert!(waited.exhausted(at(72)));
    }

    /// A "not found on-chain" rejection is waited out, a block at a
    /// time, only while the batch is still propagating; any other
    /// failure, or a rejection after the window, isn't.
    #[test]
    fn only_a_propagating_batch_waits_out_a_rejection() {
        use ant_retrieval::pushsync::PushSyncError;
        let rejected = PushSyncError::StampRejected {
            batch_id: [1; 32],
            rejections: 2,
            sample: "invalid stamp: batchstore get: storage: not found".into(),
        };
        let other = PushSyncError::ReceiptMismatch;
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        assert_eq!(
            propagation_wait(&rejected, Some(later), now),
            Some(PROPAGATION_RETRY)
        );
        assert_eq!(
            propagation_wait(&rejected, Some(now + Duration::from_secs(2)), now),
            Some(Duration::from_secs(2)),
            "never waits past the window"
        );
        assert_eq!(propagation_wait(&rejected, Some(now), now), None);
        assert_eq!(propagation_wait(&rejected, None, now), None);
        assert_eq!(propagation_wait(&other, Some(later), now), None);
    }

    #[test]
    fn raw_bytes_lookup_serves_the_bare_reference() {
        let reference = vec![0xab; 32];
        for path in ["", "/"] {
            let lookup = raw_bytes_lookup(&reference, path).expect("bare reference");
            assert_eq!(lookup.data_ref, reference);
            assert_eq!(lookup.content_type, None);
            assert!(lookup.metadata.is_empty());
            assert!(!lookup.is_feed());
        }
        // Encrypted `address ‖ key` references pass through whole.
        let encrypted = vec![0xcd; 64];
        let lookup = raw_bytes_lookup(&encrypted, "").expect("bare reference");
        assert_eq!(lookup.data_ref, encrypted);
    }

    /// #113: on a bare `/bzz/<ref>/` an erasure-recovery failure during
    /// the manifest walk is retried like a chunk-fetch failure — it is
    /// what a cold or thin peer set produces while the walk is still
    /// deciding whether the reference is a manifest. With a path the
    /// classification is unchanged: recovery failures and path misses
    /// stay terminal, so a missing path in a real manifest 404s fast.
    #[test]
    fn bzz_lookup_retries_recovery_failures_on_a_bare_root_only() {
        use ant_retrieval::{JoinError, ManifestError};
        let recovery = || {
            ManifestError::Fetch(JoinError::Recovery {
                detail: "erasure recovery impossible: 95 of 128 shards retrievable, need 119 \
                         (119 data + 9 parity refs); trigger: no BZZ peers available"
                    .into(),
            })
        };
        let fetch = || {
            ManifestError::Fetch(JoinError::FetchChunk {
                addr: "00".into(),
                source: "no BZZ peers available".into(),
            })
        };
        let path_miss = || ManifestError::NotFound {
            path: "missing.html".into(),
        };

        assert!(is_bzz_lookup_transient(&recovery(), true));
        assert!(!is_bzz_lookup_transient(&recovery(), false));
        assert!(is_bzz_lookup_transient(&fetch(), true));
        assert!(is_bzz_lookup_transient(&fetch(), false));
        assert!(!is_bzz_lookup_transient(&path_miss(), false));
        assert!(!is_bzz_lookup_transient(&path_miss(), true));
        assert!(!is_bzz_lookup_transient(&ManifestError::NotAManifest, true));

        for path in ["", "/", "//"] {
            assert!(is_bare_root_path(path), "{path:?}");
        }
        for path in ["foo", "/foo", "a/b/"] {
            assert!(!is_bare_root_path(path), "{path:?}");
        }
    }

    /// #113: `/bzz/<raw-bytes-ref>/foo` is a path miss, worded so the
    /// gateway's `map_retrieval_error` answers 404 "path address not
    /// found" (its `"path '"` arm) instead of a retryable 502.
    #[test]
    fn path_below_raw_bytes_reads_as_a_path_miss() {
        let message = path_below_raw_bytes_message(&[0xab; 32], "/seg/0.ts");
        assert!(
            message.starts_with("path 'seg/0.ts' not found"),
            "{message}"
        );
        assert!(!message.contains("(root)"), "{message}");
        assert!(message.contains(&"ab".repeat(32)), "{message}");
    }

    #[test]
    fn raw_bytes_lookup_refuses_a_path_below_raw_bytes() {
        let reference = [0xab; 32];
        assert!(raw_bytes_lookup(&reference, "index.html").is_none());
        assert!(raw_bytes_lookup(&reference, "/a/b").is_none());
    }

    /// A retrieval whose control client went away (the gateway dropped
    /// the ack receiver because the HTTP client disconnected) is dropped
    /// at once, with everything it owns, instead of running on until it
    /// next tries to send an ack.
    #[tokio::test]
    async fn retrieval_is_dropped_when_its_client_goes_away() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        let (ack, rx) = mpsc::channel::<ControlAck>(1);
        let task = tokio::spawn(async move {
            unless_client_gone(&ack, async move {
                let _flag = flag;
                std::future::pending::<()>().await;
            })
            .await
        });
        drop(rx);
        let out = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the retrieval is dropped when its client goes away")
            .unwrap();
        assert!(out.is_none());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn retrieval_that_finishes_hands_back_its_reply() {
        let (ack, _rx) = mpsc::channel::<ControlAck>(1);
        assert_eq!(unless_client_gone(&ack, async { 7 }).await, Some(7));
    }

    /// Issue #212 (PR #213 R1-M4): a push answered at "stored" holds a
    /// node-wide background-hunt slot until its hunt ends; with every
    /// slot taken, the stored signal answers nothing early and the
    /// caller waits for the push itself, as without the header.
    #[tokio::test]
    async fn background_hunts_are_capped_node_wide() {
        let hunts = Arc::new(Semaphore::new(1));

        // A free slot: answered at stored, the slot held by the hunt.
        let (stored_tx, stored) = oneshot::channel();
        let (mut ack, _ack_rx) = oneshot::channel();
        let push = std::future::pending::<Result<(), ant_retrieval::pushsync::PushSyncError>>();
        tokio::pin!(push);
        stored_tx.send(()).unwrap();
        let step = next_push_step(push.as_mut(), stored, &mut ack, true, &hunts).await;
        let PushStep::Stored(slot) = step else {
            panic!("a free slot should answer at stored");
        };
        assert_eq!(hunts.available_permits(), 0);

        // Every slot taken: the stored signal is ignored and the step
        // waits for the push to end.
        let (stored_tx, stored) = oneshot::channel();
        let (mut ack2, _ack2_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        let push = async move {
            done_rx.await.unwrap();
            Ok::<(), ant_retrieval::pushsync::PushSyncError>(())
        };
        tokio::pin!(push);
        stored_tx.send(()).unwrap();
        let step = next_push_step(push.as_mut(), stored, &mut ack2, true, &hunts);
        tokio::pin!(step);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut step)
                .await
                .is_err(),
            "answered early with no slot free",
        );
        done_tx.send(()).unwrap();
        assert!(matches!(step.await, PushStep::Done(Ok(()))));

        // The first hunt ends: its slot is free again.
        drop(slot);
        assert_eq!(hunts.available_permits(), 1);
    }

    /// With every slot taken, a push still ends as abandoned when its
    /// requester goes away, rather than hunting on for nobody.
    #[tokio::test]
    async fn a_capped_push_is_still_abandoned_with_its_requester() {
        let hunts = Arc::new(Semaphore::new(0));
        let (stored_tx, stored) = oneshot::channel();
        let (mut ack, ack_rx) = oneshot::channel();
        let push = std::future::pending::<Result<(), ant_retrieval::pushsync::PushSyncError>>();
        tokio::pin!(push);
        stored_tx.send(()).unwrap();
        drop(ack_rx);
        let step = next_push_step(push.as_mut(), stored, &mut ack, true, &hunts).await;
        assert!(matches!(step, PushStep::Abandoned));
    }

    fn persistent_issuer(dir: &std::path::Path, id: [u8; 32]) -> ant_postage::StampIssuer {
        ant_postage::StampIssuer::open_or_new(
            dir.join(format!("{}.bin", hex::encode(id))),
            id,
            20,
            16,
            true,
        )
        .unwrap()
    }

    /// `GET /stamps/{id}/chunks/{address}` answers from the issuer's
    /// records, and those records survive a restart (the `.stamps`
    /// sidecar), not just the in-memory map of the process that stamped.
    #[test]
    fn stamped_chunk_reads_the_persisted_records() {
        let dir = tempfile::tempdir().unwrap();
        let id = [0x0cu8; 32];
        let key = [1u8; SECP256K1_SECRET_LEN];
        let issued = {
            let mut issuer = persistent_issuer(dir.path(), id);
            ant_postage::sign_stamp_bytes(&key, &mut issuer, &[7u8; 32]).unwrap()
        };
        let issuers = HashMap::from([(id, persistent_issuer(dir.path(), id))]);
        match stamped_chunk_reply(&issuers, id, &[7u8; 32]) {
            ControlAck::StampedChunk { stamp: Some(s) } => assert_eq!(s, issued),
            other => panic!("expected the issued stamp, got {other:?}"),
        }
        assert!(matches!(
            stamped_chunk_reply(&issuers, id, &[8u8; 32]),
            ControlAck::StampedChunk { stamp: None }
        ));
        match stamped_chunk_reply(&issuers, [0x0du8; 32], &[7u8; 32]) {
            ControlAck::Error { message } => assert!(message.contains("issuer does not exist")),
            other => panic!("expected unknown issuer, got {other:?}"),
        }
    }

    /// An issuer whose sidecar can't be read back has incomplete records:
    /// a missing record must surface as an error, never as "not stamped"
    /// or as an unstamped count.
    #[cfg(unix)]
    #[test]
    fn unreadable_records_refuse_instead_of_reading_as_unstamped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = [0x0cu8; 32];
        let key = [1u8; SECP256K1_SECRET_LEN];
        {
            let mut issuer = persistent_issuer(dir.path(), id);
            ant_postage::sign_stamp_bytes(&key, &mut issuer, &[7u8; 32]).unwrap();
        }
        let sidecar = dir.path().join(format!("{}.stamps", hex::encode(id)));
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o000)).unwrap();
        let issuer = persistent_issuer(dir.path(), id);
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        if issuer.stamp_records_unavailable().is_none() {
            // Running as root: permissions don't bite, nothing to test.
            eprintln!("skipped: sidecar stayed readable (root?)");
            return;
        }
        let issuers = HashMap::from([(id, issuer)]);
        // Chunk 7 really was stamped; its record is what got lost.
        for addr in [[7u8; 32], [8u8; 32]] {
            match stamped_chunk_reply(&issuers, id, &addr) {
                ControlAck::Error { message } => {
                    assert!(message.contains("stamp records unavailable"), "{message}");
                }
                other => panic!("expected an error, got {other:?}"),
            }
        }
        let err = count_tree_stamps(&issuers, &[[7u8; 32], [8u8; 32]]).unwrap_err();
        assert!(err.contains("stamp records unavailable"), "{err}");
    }

    /// Every registered batch is listed (sorted, zero counts kept), a
    /// chunk stamped by two batches counts in each, and `unstamped`
    /// counts only chunks no batch stamped.
    #[test]
    fn count_tree_stamps_counts_per_batch_and_unstamped() {
        let dir = tempfile::tempdir().unwrap();
        let key = [1u8; SECP256K1_SECRET_LEN];
        let (old, new, idle) = ([0x0bu8; 32], [0x0au8; 32], [0x0fu8; 32]);
        let mut issuers = HashMap::new();
        for id in [old, new, idle] {
            issuers.insert(id, persistent_issuer(dir.path(), id));
        }
        // Tree of chunks 1..=4: 1 and 2 on the old batch, 2 and 3 moved
        // to the new one, 4 on neither. Chunk 9 (not in the tree) is on
        // the idle batch.
        for (id, addrs) in [(old, vec![1u8, 2]), (new, vec![2, 3]), (idle, vec![9])] {
            let issuer = issuers.get_mut(&id).unwrap();
            for a in addrs {
                ant_postage::sign_stamp_bytes(&key, issuer, &[a; 32]).unwrap();
            }
        }
        let tree: Vec<[u8; 32]> = (1u8..=4).map(|a| [a; 32]).collect();
        let view = count_tree_stamps(&issuers, &tree).unwrap();
        assert_eq!(view.chunks, 4);
        assert_eq!(view.unstamped, 1);
        assert_eq!(
            view.batches,
            vec![
                ant_control::BatchChunkCount {
                    batch_id: new,
                    chunks: 2
                },
                ant_control::BatchChunkCount {
                    batch_id: old,
                    chunks: 2
                },
                ant_control::BatchChunkCount {
                    batch_id: idle,
                    chunks: 0
                },
            ]
        );
        // No batches at all: everything is unstamped, nothing listed.
        let none = count_tree_stamps(&HashMap::new(), &tree).unwrap();
        assert_eq!((none.chunks, none.unstamped, none.batches.len()), (4, 4, 0));

        // Counting in slices (lock released between them) adds up to
        // the same view, for every slice size including an empty tree.
        let locked = std::sync::Mutex::new(issuers);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for slice in [1, 2, 3, 4, 100] {
            let sliced = rt
                .block_on(count_tree_stamps_sliced(&locked, &tree, slice))
                .unwrap();
            assert_eq!(sliced, view, "slice {slice}");
        }
        let empty = rt
            .block_on(count_tree_stamps_sliced(&locked, &[], 2))
            .unwrap();
        assert_eq!(
            (empty.chunks, empty.unstamped, empty.batches.len()),
            (0, 0, 3)
        );
    }

    /// A batch registered or dropped between two slices of a count must
    /// not show up in only some of them: the count starts over and the
    /// view is the one a single pass over the new set gives.
    #[test]
    fn sliced_count_restarts_when_the_batch_set_changes() {
        let dir = tempfile::tempdir().unwrap();
        let key = [1u8; SECP256K1_SECRET_LEN];
        let (old, new) = ([0x0bu8; 32], [0x0au8; 32]);
        let mut old_issuer = persistent_issuer(dir.path(), old);
        let mut new_issuer = persistent_issuer(dir.path(), new);
        for a in 1u8..=4 {
            ant_postage::sign_stamp_bytes(&key, &mut old_issuer, &[a; 32]).unwrap();
            ant_postage::sign_stamp_bytes(&key, &mut new_issuer, &[a; 32]).unwrap();
        }
        let tree: Vec<[u8; 32]> = (1u8..=4).map(|a| [a; 32]).collect();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // `biased` polls the count first every round, so `change` runs
        // exactly once per slice the count yields after, deterministically.
        async fn racing(
            locked: &std::sync::Mutex<HashMap<[u8; 32], ant_postage::StampIssuer>>,
            tree: &[[u8; 32]],
            change: impl std::future::Future<Output = ()>,
        ) -> Result<ant_control::StewardshipStampsView, String> {
            let change = async {
                change.await;
                std::future::pending::<()>().await;
            };
            tokio::select! {
                biased;
                r = count_tree_stamps_sliced(locked, tree, 1) => r,
                () = change => unreachable!(),
            }
        }

        // Registered after the first of four slices.
        let locked = std::sync::Mutex::new(HashMap::from([(old, old_issuer)]));
        let view = rt
            .block_on(racing(&locked, &tree, async {
                locked.lock().unwrap().insert(new, new_issuer);
            }))
            .unwrap();
        assert_eq!((view.chunks, view.unstamped), (4, 0));
        assert_eq!(
            view.batches,
            vec![
                ant_control::BatchChunkCount {
                    batch_id: new,
                    chunks: 4
                },
                ant_control::BatchChunkCount {
                    batch_id: old,
                    chunks: 4
                },
            ]
        );

        // Dropped after the first slice: not listed with a partial count.
        let view = rt
            .block_on(racing(&locked, &tree, async {
                locked.lock().unwrap().remove(&new);
            }))
            .unwrap();
        assert_eq!((view.chunks, view.unstamped), (4, 0));
        assert_eq!(
            view.batches,
            vec![ant_control::BatchChunkCount {
                batch_id: old,
                chunks: 4
            }]
        );

        // A set that changes on every slice ends in an error, never in
        // a mixed view.
        let res = rt.block_on(racing(&locked, &tree, async {
            for i in 0..=STAMP_COUNT_RESTARTS as u8 {
                let id = [0x40 + i; 32];
                let issuer = persistent_issuer(dir.path(), id);
                locked.lock().unwrap().insert(id, issuer);
                tokio::task::yield_now().await;
            }
        }));
        assert!(res.unwrap_err().contains("kept changing"));
    }
}
