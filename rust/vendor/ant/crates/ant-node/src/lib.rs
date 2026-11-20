//! Minimal node orchestration for M1.0 (p2p dial + handshake loop).

pub mod uploads;

use ant_control::{ControlCommand, GatewayActivity, StatusSnapshot};
use ant_crypto::{OVERLAY_NONCE_LEN, SECP256K1_SECRET_LEN};
pub use ant_p2p::LateChainInit;
use ant_p2p::{run, PeerEthMap, PushsyncSwapConfig, RunConfig, SwapConfig, UploadRuntime};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Multiaddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

pub use uploads::{estimate_chunk_count, UploadError, UploadJobInfo, UploadManager, UploadStatus};

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("p2p: {0}")]
    P2p(#[from] ant_p2p::RunError),
}

pub struct NodeConfig {
    pub signing_secret: [u8; SECP256K1_SECRET_LEN],
    pub overlay_nonce: [u8; OVERLAY_NONCE_LEN],
    pub network_id: u64,
    pub bootnodes: Vec<Multiaddr>,
    pub libp2p_keypair: Keypair,
    /// Public multiaddrs advertised via identify. Required for bee bootnodes
    /// to complete the BZZ handshake without a 10 s peerstore timeout.
    pub external_addrs: Vec<Multiaddr>,
    /// Forwarded to `ant_p2p::RunConfig::allow_private_dials`: dial peers'
    /// private/loopback underlays even off-LAN. Dev/test networks only.
    pub allow_private_dials: bool,
    /// Optional live status sink written to by the node loop.
    pub status: Option<watch::Sender<StatusSnapshot>>,
    /// Where to persist the warm-restart peer snapshot. `None` disables it.
    pub peerstore_path: Option<PathBuf>,
    /// Live control-socket commands consumed by the node loop. `None` means
    /// mutating `antctl` subcommands (`peers reset`, …) will fail with a
    /// "channel not wired up" error.
    pub commands: Option<mpsc::Receiver<ControlCommand>>,
    /// Peer-set target — how many BZZ-handshake-complete peers the swarm
    /// loop tries to keep online. `None` falls back to
    /// `ant_p2p::DEFAULT_TARGET_PEERS` (100), which is the right size
    /// for cheap-CPU light-mode operation. Raise it for wider
    /// connectivity and routing-table coverage, redundancy, or more
    /// parallelism on a node that settles over SWAP with a funded
    /// chequebook. Each bee peer extends its own small pseudosettle
    /// (free-tier) allowance, so a larger peer set also draws more unpaid
    /// bandwidth in total; that allowance is for light use, not a
    /// throughput lever — a node hitting the free-tier wall should pay
    /// (fund its chequebook) rather than add peers.
    pub target_peers: Option<usize>,
    /// Baseline for `PeerInfo` cold-start timings (`antop` milestones).
    pub process_start: Instant,
    /// Scope the in-memory chunk cache to a single request. Default
    /// (`false`) keeps one process-wide cache so consecutive
    /// `antctl get` calls share fetched chunks; setting this makes
    /// every command start with an empty cache, which is the right
    /// shape for reproducing transient retrieval failures or for
    /// timing the cold path.
    pub per_request_chunk_cache: bool,
    /// When set, every chunk fetched by a `GetBytes` / `GetBzz`
    /// request is dumped to `<dir>/<hex_addr>.bin` (raw wire bytes:
    /// 8-byte LE span || payload). Used by `antd --record-chunks`
    /// (debug builds only) to capture an offline fixture of every
    /// chunk a successful `antctl get` touched. The directory must
    /// already exist; `None` (the default) disables recording.
    pub chunk_record_dir: Option<PathBuf>,
    /// Live registry of in-flight gateway HTTP requests, shared with
    /// `ant-gateway`. Wired up by `antd::main` when the HTTP API is
    /// enabled; `None` for headless deployments
    /// (`antd --no-http-api`). Surfaces in `antop`'s Retrieval
    /// tab.
    pub gateway_activity: Option<Arc<GatewayActivity>>,
    /// Persistent (SQLite-backed) chunk cache, opened by the daemon
    /// at startup and shared across every retrieval request.
    /// `Some(cache)` makes the lookup order `memory -> disk ->
    /// network`; `None` keeps the legacy `memory -> network`
    /// behaviour. `antd` opens it from `--disk-cache-path` (or the
    /// computed default in `<data-dir>/chunks.sqlite`); embedders can
    /// disable it by passing `None`.
    pub disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    /// Embedder-owned process-wide in-memory chunk cache. `Some` makes
    /// the swarm loop share this `Arc` instead of building its own, so
    /// the embedder can read and clear it (ant-ffi's `ant_cache_*`).
    /// Ignored when `per_request_chunk_cache` is set.
    pub memory_cache: Option<Arc<ant_retrieval::InMemoryChunkCache>>,
    /// Postage stamping + signing runtime for `POST /chunks`. `Some`
    /// enables uploads; `None` returns "uploads not configured".
    pub upload: Option<Arc<UploadRuntime>>,
    /// SWAP / chequebook configuration. When `Some`, the node
    /// participates in `/swarm/swap/1.0.0/swap` exchanges with peers
    /// — accepting their cheques (signature-verified, monotonic,
    /// pinned to chequebook) into a persistent ledger. When `None`,
    /// the protocol is still negotiated but every received cheque is
    /// dropped silently.
    pub swap: Option<SwapConfig>,
    /// Outbound SWAP settlement (Phase 7b). When `Some`, every
    /// successful pushsync push reports into a per-peer cumulative
    /// debit mirror, and an EIP-712 cheque is emitted automatically
    /// once the per-peer debt crosses the configured trigger. Required
    /// for sustained uploads to Bee mainnet — without it pushsync
    /// stalls after a few hundred chunks per peer (bee
    /// `paymentTolerance`). See PLAN.md § Phase 7b.
    pub pushsync_swap: Option<PushsyncSwapConfig>,
    /// `antctl upload` job manager. When `Some`, `run_node` installs
    /// a command interceptor in front of `ant-p2p` that catches
    /// `ControlCommand::Upload*` variants and dispatches them to
    /// the manager, leaving everything else (peer ops, retrieval,
    /// `PushChunk`) to flow through to the swarm event loop
    /// unchanged. The manager itself issues `PushChunk` commands
    /// through the same outer channel, so the bounded postage
    /// stamping path (`ant_p2p::UploadRuntime`) handles every
    /// uploaded chunk uniformly. `None` keeps the upload commands
    /// disabled — the interceptor is bypassed and the stub arms in
    /// `ant_p2p::handle_control_command` reject `Upload*` with a
    /// clear error.
    pub upload_manager: Option<UploadManager>,
    /// One-shot channel delivering the chain-derived inputs (`upload`,
    /// `pushsync_swap`) after the swarm loop is already running, so
    /// the daemon's startup Gnosis RPC reads don't serialize in front
    /// of the bootstrap dial (they were costing ~3 s of
    /// `time_to_first_peer_s`). See [`ant_p2p::RunConfig::late_chain_rx`].
    pub late_chain: Option<mpsc::Receiver<LateChainInit>>,
    /// Bee's `swap-enable`: SWAP settlement on or off for the node. On
    /// (`true`, the default), downloads (issue #121) and uploads (issue
    /// #127) pay peers with SWAP cheques once a funded chequebook backs
    /// outbound settlement, as bee does; `false` keeps both on the free
    /// pseudosettle tier. Switchable at runtime with
    /// `ControlCommand::SetSwapEnabled`.
    pub swap_enabled: bool,
}

impl NodeConfig {
    #[must_use]
    pub fn mainnet_default(
        signing_secret: [u8; SECP256K1_SECRET_LEN],
        overlay_nonce: [u8; OVERLAY_NONCE_LEN],
        bootnodes: Vec<Multiaddr>,
        libp2p_keypair: Keypair,
    ) -> Self {
        Self {
            signing_secret,
            overlay_nonce,
            network_id: 1,
            bootnodes,
            libp2p_keypair,
            external_addrs: Vec::new(),
            allow_private_dials: false,
            status: None,
            peerstore_path: None,
            commands: None,
            target_peers: None,
            process_start: Instant::now(),
            per_request_chunk_cache: false,
            chunk_record_dir: None,
            gateway_activity: None,
            disk_cache: None,
            memory_cache: None,
            upload: None,
            swap: None,
            pushsync_swap: None,
            upload_manager: None,
            late_chain: None,
            swap_enabled: true,
        }
    }

    #[must_use]
    pub fn with_status(mut self, status: watch::Sender<StatusSnapshot>) -> Self {
        self.status = Some(status);
        self
    }

    /// Swarm network id (`1` = mainnet, the `mainnet_default`). It feeds
    /// both the overlay address and the BZZ handshake, so it must be the
    /// same value the caller derived its displayed overlay from.
    #[must_use]
    pub const fn with_network_id(mut self, network_id: u64) -> Self {
        self.network_id = network_id;
        self
    }

    #[must_use]
    pub fn with_external_addrs(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.external_addrs = addrs;
        self
    }

    #[must_use]
    pub const fn with_allow_private_dials(mut self, allow: bool) -> Self {
        self.allow_private_dials = allow;
        self
    }

    #[must_use]
    pub fn with_peerstore_path(mut self, path: Option<PathBuf>) -> Self {
        self.peerstore_path = path;
        self
    }

    #[must_use]
    pub fn with_commands(mut self, commands: mpsc::Receiver<ControlCommand>) -> Self {
        self.commands = Some(commands);
        self
    }

    #[must_use]
    pub const fn with_target_peers(mut self, target_peers: Option<usize>) -> Self {
        self.target_peers = target_peers;
        self
    }

    #[must_use]
    pub const fn with_process_start(mut self, t: Instant) -> Self {
        self.process_start = t;
        self
    }

    #[must_use]
    pub const fn with_per_request_chunk_cache(mut self, per_request: bool) -> Self {
        self.per_request_chunk_cache = per_request;
        self
    }

    #[must_use]
    pub fn with_chunk_record_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.chunk_record_dir = dir;
        self
    }

    #[must_use]
    pub fn with_gateway_activity(mut self, activity: Option<Arc<GatewayActivity>>) -> Self {
        self.gateway_activity = activity;
        self
    }

    #[must_use]
    pub fn with_disk_cache(
        mut self,
        disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    ) -> Self {
        self.disk_cache = disk_cache;
        self
    }

    /// Share `cache` as the process-wide in-memory chunk cache (see
    /// [`Self::memory_cache`]).
    #[must_use]
    pub fn with_memory_cache(
        mut self,
        cache: Option<Arc<ant_retrieval::InMemoryChunkCache>>,
    ) -> Self {
        self.memory_cache = cache;
        self
    }

    #[must_use]
    pub fn with_upload(mut self, upload: Option<Arc<UploadRuntime>>) -> Self {
        self.upload = upload;
        self
    }

    #[must_use]
    pub fn with_swap(mut self, swap: Option<SwapConfig>) -> Self {
        self.swap = swap;
        self
    }

    #[must_use]
    pub fn with_pushsync_swap(mut self, cfg: Option<PushsyncSwapConfig>) -> Self {
        self.pushsync_swap = cfg;
        self
    }

    #[must_use]
    pub fn with_upload_manager(mut self, mgr: Option<UploadManager>) -> Self {
        self.upload_manager = mgr;
        self
    }

    #[must_use]
    pub const fn with_swap_enabled(mut self, enabled: bool) -> Self {
        self.swap_enabled = enabled;
        self
    }

    #[must_use]
    pub fn with_late_chain(mut self, rx: Option<mpsc::Receiver<LateChainInit>>) -> Self {
        self.late_chain = rx;
        self
    }
}

/// Run the M1.0 node loop until the process is interrupted.
///
/// When [`NodeConfig::upload_manager`] is `Some`, this fn installs a
/// command interceptor in front of `ant-p2p` that pulls
/// [`ControlCommand`]s off the operator-supplied channel, routes
/// `Upload*` variants to the manager, and forwards everything else to
/// the swarm event loop. The manager itself issues `PushChunk` through
/// a clone of that same outer channel — so manager-driven chunks land
/// in `ant-p2p` exactly the way a `POST /chunks` call from `bee-js`
/// does today.
pub async fn run_node(cfg: NodeConfig) -> Result<(), NodeError> {
    let (forward_rx, _interceptor) = match (cfg.commands, cfg.upload_manager.clone()) {
        (Some(outer_rx), Some(mgr)) => {
            let (inner_tx, inner_rx) = mpsc::channel::<ControlCommand>(64);
            let task = tokio::spawn(intercept_commands(outer_rx, inner_tx, mgr));
            (Some(inner_rx), Some(task))
        }
        (commands, _) => (commands, None),
    };

    let peer_eth = PeerEthMap::new();
    run(RunConfig {
        signing_secret: cfg.signing_secret,
        overlay_nonce: cfg.overlay_nonce,
        network_id: cfg.network_id,
        bootnodes: cfg.bootnodes,
        libp2p_keypair: cfg.libp2p_keypair,
        external_addrs: cfg.external_addrs,
        allow_private_dials: cfg.allow_private_dials,
        status: cfg.status,
        // `None` → 0 → `ant_p2p` falls back to `DEFAULT_TARGET_PEERS = 100`.
        // `Some(n)` is forwarded literally; values above bee's typical
        // neighbourhood fan-out (~few hundred) just plateau at the
        // achievable peer count without harm.
        target_peers: cfg.target_peers.unwrap_or(0),
        peerstore_path: cfg.peerstore_path,
        commands: forward_rx,
        process_start: cfg.process_start,
        per_request_chunk_cache: cfg.per_request_chunk_cache,
        chunk_record_dir: cfg.chunk_record_dir,
        gateway_activity: cfg.gateway_activity,
        disk_cache: cfg.disk_cache,
        memory_cache: cfg.memory_cache,
        upload: cfg.upload,
        swap: cfg.swap,
        pushsync_swap: cfg.pushsync_swap.map(|mut c| {
            c.peer_eth = peer_eth.clone();
            c
        }),
        peer_eth,
        late_chain_rx: cfg.late_chain,
        swap_enabled: cfg.swap_enabled,
    })
    .await?;
    Ok(())
}

/// Pull commands off `outer_rx`. Dispatch `Upload*` to `mgr`; forward
/// everything else to `inner_tx` (which feeds `ant-p2p`'s swarm event
/// loop). Exits when `outer_rx` closes.
///
/// This is intentionally synchronous-per-command on the upload path:
/// `UploadStart` returns as soon as the manager registers the job
/// (the actual splitter / pushsync work happens on the manager's
/// own background task). `UploadFollow` keeps the interceptor task
/// busy for the duration of the follow because it pumps a watch
/// receiver into the per-request `mpsc::Sender<ControlAck>` — but
/// that's fine, follows are spawned on their own tokio task per
/// connection, so multiple followers don't bottleneck each other.
async fn intercept_commands(
    mut outer_rx: mpsc::Receiver<ControlCommand>,
    inner_tx: mpsc::Sender<ControlCommand>,
    mgr: uploads::UploadManager,
) {
    use ant_control::ControlAck;
    while let Some(cmd) = outer_rx.recv().await {
        match cmd {
            ControlCommand::UploadStart {
                source_path,
                batch_id,
                name,
                content_type,
                raw,
                ack,
            } => {
                let mgr = mgr.clone();
                tokio::spawn(async move {
                    let reply = match mgr.start(source_path, batch_id, name, content_type, raw) {
                        Ok(job_id) => ControlAck::UploadStarted { job_id },
                        Err(e) => ControlAck::Error {
                            message: e.to_string(),
                        },
                    };
                    let _ = ack.send(reply);
                });
            }
            ControlCommand::UploadList { ack } => {
                let mut views: Vec<_> = mgr.list().into_iter().map(uploads::to_view).collect();
                views.sort_by_key(|v| v.created_at_unix);
                let _ = ack.send(ControlAck::UploadList(views));
            }
            ControlCommand::UploadStatus { job_id, ack } => {
                let reply = match mgr.status(&job_id) {
                    Ok(info) => ControlAck::UploadJob(uploads::to_view(info)),
                    Err(e) => ControlAck::Error {
                        message: e.to_string(),
                    },
                };
                let _ = ack.send(reply);
            }
            ControlCommand::UploadPause { job_id, ack } => {
                let reply = match mgr.pause(&job_id) {
                    Ok(info) => ControlAck::UploadJob(uploads::to_view(info)),
                    Err(e) => ControlAck::Error {
                        message: e.to_string(),
                    },
                };
                let _ = ack.send(reply);
            }
            ControlCommand::UploadResume { job_id, ack } => {
                let reply = match mgr.resume(&job_id) {
                    Ok(info) => ControlAck::UploadJob(uploads::to_view(info)),
                    Err(e) => ControlAck::Error {
                        message: e.to_string(),
                    },
                };
                let _ = ack.send(reply);
            }
            ControlCommand::UploadCancel { job_id, ack } => {
                let reply = match mgr.cancel(&job_id) {
                    Ok(info) => ControlAck::UploadJob(uploads::to_view(info)),
                    Err(e) => ControlAck::Error {
                        message: e.to_string(),
                    },
                };
                let _ = ack.send(reply);
            }
            ControlCommand::UploadFollow { job_id, ack } => {
                let mgr = mgr.clone();
                tokio::spawn(async move { uploads::run_follow(mgr, job_id, ack).await });
            }
            ControlCommand::UploadSuspendAll { ack } => {
                // Spawned so the (bounded) drain wait never blocks the
                // interceptor; the ack fires only once the paused
                // drivers have checkpointed, which is what lets a host
                // with a short background grace window block on it.
                let mgr = mgr.clone();
                tokio::spawn(async move {
                    let suspended = mgr.suspend_all().await;
                    let _ = ack.send(ControlAck::Ok {
                        message: format!("suspended {suspended} upload job(s)"),
                    });
                });
            }
            ControlCommand::UploadWakeAll { ack } => {
                let woken = mgr.wake_all();
                let _ = ack.send(ControlAck::Ok {
                    message: format!("resumed {woken} auto-paused upload job(s)"),
                });
            }
            ControlCommand::UploadRepush {
                job_id,
                progress,
                ack,
            } => {
                let mgr = mgr.clone();
                tokio::spawn(async move {
                    let reply = match mgr.repush_with_progress(&job_id, progress).await {
                        Ok(info) => ControlAck::UploadJob(uploads::to_view(info)),
                        Err(e) => ControlAck::Error {
                            message: e.to_string(),
                        },
                    };
                    let _ = ack.send(reply);
                });
            }
            other => {
                if inner_tx.send(other).await.is_err() {
                    break;
                }
            }
        }
    }
}
