//! Myotis's embedded Swarm reader: an [`ant`](https://github.com/freedom-hq/ant) light node,
//! meant to be linked into the engine, which reaches Swarm over libp2p
//! (`.claude/agent/data-sources.md`, the carve-out for Swarm reads of the address index).
//!
//! This crate only fetches single chunks. It hands back what Swarm delivered, in wire form;
//! ant checks a content-addressed chunk against its address, and the caller checks every
//! chunk against what it expects (a SOC's address and owner signature, a CAC's address) before
//! using it, and joins files itself from chunks it has checked. It never serves HTTP and never
//! uploads.
//!
//! The node runs on a tokio runtime of its own, so that starting it needs no ambient runtime
//! (the engine's FFI entry points run on threads without one) and stopping it is certain:
//! [`SwarmNode::shutdown`] (or dropping the node) shuts that runtime down, which ends every
//! task ant spawned, its listener and its connections. It is driven through ant's command
//! channel ([`ant_control::ControlCommand`]), the in-process interface `antd`'s own control
//! socket uses.
//!
//! **Linked into the engine only behind its off-by-default `swarm` feature, for dev builds:
//! not ready for a release build** (owner, 2026-11-20: settled before any release that turns
//! `swarm` on), for reasons inside
//! ant that this crate cannot switch off:
//! - ant listens on `0.0.0.0` and runs libp2p's UPnP behaviour, which asks the local router
//!   for a port mapping and announces the public address to peers: more than a fetch-only
//!   reader should expose. (So the tests that start a node are `#[ignore]`d.)
//! - ant resolves `/dnsaddr` bootnodes with hickory-resolver 0.25.2, the version with known
//!   advisories that `myotis-net` keeps out of every build on purpose.
//! - ant would run inside the engine under the workspace's `panic = "abort"`: a panic anywhere
//!   in its networking code, on input from any Swarm peer, would end the host process.
//!
//! Each needs a change in ant (an option for no listener and no UPnP, DNS behind a feature or
//! through the host's resolver, a panic contract) or an owner's decision. ant itself is
//! vendored (`rust/vendor/ant`, its `VENDORED.md`): no build fetches it from GitHub. Being on
//! no registry, it has no advisory coverage: nothing reports a security fix in ant, which
//! reaches Myotis only when the copy is moved (`VENDORED.md`, "Watching upstream").

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ant_control::{ControlAck, ControlCommand, StatusSnapshot};
use ant_node::{run_node, NodeConfig};
use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use tokio::sync::{mpsc, oneshot, watch};

/// Swarm mainnet's network id.
pub const MAINNET_NETWORK_ID: u64 = 1;

/// Peers a reader keeps by default. A reader needs few; ant's own default (100) suits a node
/// that serves.
pub const READER_PEERS: usize = 24;

/// Errors of the reader.
#[derive(Debug)]
pub enum SwarmError {
    /// The node is not running (its runtime could not start, or the node stopped).
    Stopped,
    /// The node has no usable peers yet (a cold start); worth a retry.
    NotReady(String),
    /// Anything else ant reported, or an answer of an unexpected kind.
    Failed(String),
    /// No answer in time.
    Timeout,
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "the Swarm node is not running"),
            Self::NotReady(m) => write!(f, "the Swarm node has no usable peers yet: {m}"),
            Self::Failed(m) => write!(f, "Swarm read failed: {m}"),
            Self::Timeout => write!(f, "Swarm read timed out"),
        }
    }
}

impl std::error::Error for SwarmError {}

/// Where and how the node joins Swarm.
#[derive(Clone, Debug)]
pub struct SwarmConfig {
    pub network_id: u64,
    pub bootnodes: Vec<Multiaddr>,
    /// Dial peers' private and loopback addresses: a local dev network only.
    pub allow_private_dials: bool,
    /// File for the warm-restart peer snapshot (`None`: start cold every time).
    pub peerstore_path: Option<PathBuf>,
    /// Peers the node keeps connected.
    pub target_peers: usize,
    /// How long one chunk read may take, queueing included.
    pub chunk_timeout: Duration,
}

impl SwarmConfig {
    /// Swarm mainnet through its published bootnodes.
    pub fn mainnet() -> Self {
        Self {
            network_id: MAINNET_NETWORK_ID,
            bootnodes: ant_p2p::default_mainnet_bootnodes(),
            allow_private_dials: false,
            peerstore_path: None,
            target_peers: READER_PEERS,
            chunk_timeout: Duration::from_secs(60),
        }
    }

    /// A local network (bee-factory): its network id and the multiaddrs of its nodes.
    pub fn dev(network_id: u64, bootnodes: Vec<Multiaddr>) -> Self {
        Self {
            network_id,
            bootnodes,
            allow_private_dials: true,
            peerstore_path: None,
            target_peers: READER_PEERS,
            chunk_timeout: Duration::from_secs(30),
        }
    }
}

/// A running embedded node, on its own runtime.
pub struct SwarmNode {
    commands: mpsc::Sender<ControlCommand>,
    status: watch::Receiver<StatusSnapshot>,
    chunk_timeout: Duration,
    runtime: Option<tokio::runtime::Runtime>,
}

impl SwarmNode {
    /// Starts a node on a runtime of its own (two worker threads). Callable from any thread,
    /// with or without a runtime. Its identity (the BZZ signing key, the overlay nonce and the
    /// libp2p key, unrelated to each other) is fresh for every start: a reader needs no stable
    /// identity, and a fresh one links fewer sessions together.
    pub fn start(cfg: SwarmConfig) -> Result<Self, SwarmError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("myotis-swarm")
            .enable_all()
            .build()
            .map_err(|e| SwarmError::Failed(format!("starting the Swarm runtime: {e}")))?;
        let (commands, rx) = mpsc::channel(64);
        let (status_tx, status) = watch::channel(StatusSnapshot::default());
        // A reader settles nothing on chain and pays nobody: free-tier retrieval only.
        let node = NodeConfig::mainnet_default(
            ant_crypto::random_secp256k1_secret(),
            ant_crypto::random_overlay_nonce(),
            cfg.bootnodes,
            Keypair::generate_secp256k1(),
        )
        .with_network_id(cfg.network_id)
        .with_allow_private_dials(cfg.allow_private_dials)
        .with_status(status_tx)
        .with_commands(rx)
        .with_peerstore_path(cfg.peerstore_path)
        .with_target_peers(Some(cfg.target_peers))
        .with_process_start(Instant::now())
        .with_swap_enabled(false);
        runtime.spawn(async move {
            if let Err(e) = run_node(node).await {
                tracing::warn!(target: "myotis_swarm", "Swarm node stopped: {e}");
            }
        });
        Ok(Self {
            commands,
            status,
            chunk_timeout: cfg.chunk_timeout,
            runtime: Some(runtime),
        })
    }

    /// Peers with a completed Swarm handshake.
    pub fn connected_peers(&self) -> u32 {
        self.status.borrow().peers.connected
    }

    /// Whether the node is still running (its command channel is open).
    pub fn is_running(&self) -> bool {
        !self.commands.is_closed()
    }

    /// The chunk at `address` in wire form (`span ‖ payload` for a content-addressed chunk,
    /// `identifier ‖ signature ‖ span ‖ payload` for a SOC), or `Ok(None)` when it is
    /// unavailable from the peers asked: at most [`SwarmConfig::target_peers`], fewer with
    /// `expect_missing`, and any of them can withhold it. So `None` is "not delivered", never
    /// proof that the chunk does not exist. `expect_missing` asks fewer peers: for a read
    /// whose miss is an expected answer (a head update not published yet).
    ///
    /// Callable from any tokio runtime (the timeout uses the caller's).
    pub async fn chunk(
        &self,
        address: [u8; 32],
        expect_missing: bool,
    ) -> Result<Option<Vec<u8>>, SwarmError> {
        let read = async {
            let (ack, rx) = oneshot::channel();
            self.commands
                .send(ControlCommand::GetChunkRaw {
                    reference: address,
                    fast_miss: expect_missing,
                    bypass_cache: false,
                    ack,
                })
                .await
                .map_err(|_| SwarmError::Stopped)?;
            match rx.await {
                Err(_) => Err(SwarmError::Stopped),
                Ok(ControlAck::Bytes { data }) => Ok(Some(data)),
                Ok(other) => match classify(other) {
                    Miss::Unavailable => Ok(None),
                    Miss::Error(e) => Err(e),
                },
            }
        };
        tokio::time::timeout(self.chunk_timeout, read)
            .await
            .unwrap_or(Err(SwarmError::Timeout))
    }

    /// [`Self::chunk`] with the error as text: what the addr1 reader's
    /// [`ChunkSource`](myotis_addr1::client::ChunkSource) takes.
    async fn chunk_text(&self, address: [u8; 32], expect_missing: bool) -> Result<Option<Vec<u8>>, String> {
        self.chunk(address, expect_missing).await.map_err(|e| e.to_string())
    }

    /// Stops the node: shuts its runtime down, which ends every task ant spawned (its swarm
    /// loop, listener and connections), waiting up to `timeout` for them. Blocking: call it
    /// from a thread that may block (not from inside an async task).
    pub fn shutdown(mut self, timeout: Duration) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_timeout(timeout);
        }
    }
}

/// The addr1 reader reads through the node: every chunk it gets is checked there before use.
impl myotis_addr1::client::ChunkSource for SwarmNode {
    fn chunk(
        &self,
        address: [u8; 32],
        expect_missing: bool,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, String>> + Send {
        self.chunk_text(address, expect_missing)
    }
}

impl Drop for SwarmNode {
    /// Dropping the node stops it too, without waiting (safe inside an async context).
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

/// How a read that delivered nothing ended.
enum Miss {
    /// The chunk was not delivered (peers answered "not found", or ant said so in words).
    Unavailable,
    Error(SwarmError),
}

/// What an answer other than the chunk means. ant reports a missing chunk as `NotFound` on
/// some paths and inside a plain error message on others ("storage: not found"), and a node
/// without peers as `NotReady` or as "no BZZ peers available".
fn classify(ack: ControlAck) -> Miss {
    match ack {
        ControlAck::NotFound { .. } => Miss::Unavailable,
        ControlAck::NotReady { message } => Miss::Error(SwarmError::NotReady(message)),
        ControlAck::Error { message } => {
            let m = message.to_ascii_lowercase();
            if m.contains("no bzz peers") || m.contains("no peers available") {
                Miss::Error(SwarmError::NotReady(message))
            } else if m.contains("not found") {
                Miss::Unavailable
            } else {
                Miss::Error(SwarmError::Failed(message))
            }
        }
        other => Miss::Error(SwarmError::Failed(format!("unexpected answer {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misses_and_errors_are_classified() {
        let err = |m: &str| {
            classify(ControlAck::Error {
                message: m.to_string(),
            })
        };
        assert!(matches!(
            err("retrieval: no BZZ peers available"),
            Miss::Error(SwarmError::NotReady(_))
        ));
        assert!(matches!(
            err("no peers available"),
            Miss::Error(SwarmError::NotReady(_))
        ));
        assert!(matches!(
            err("chunk abc: storage: not found"),
            Miss::Unavailable
        ));
        assert!(matches!(
            err("bad span"),
            Miss::Error(SwarmError::Failed(_))
        ));
        assert!(matches!(
            classify(ControlAck::NotFound {
                message: String::new()
            }),
            Miss::Unavailable
        ));
    }

    /// A node with nowhere to connect starts from a thread without a runtime, says it has no
    /// peers instead of hanging, and is gone after `shutdown`: its status sender (owned by
    /// ant's node loop) is dropped. Not run by default: ant listens on 0.0.0.0 and asks the
    /// router for a UPnP mapping (`cargo test --manifest-path rust/swarm/Cargo.toml --
    /// --ignored`).
    #[test]
    #[ignore]
    fn a_node_without_peers_starts_answers_and_stops() {
        let mut cfg = SwarmConfig::dev(4020, Vec::new());
        cfg.chunk_timeout = Duration::from_secs(10);
        let node = SwarmNode::start(cfg).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut status = node.status.clone();
        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(node.is_running(), "the node did not come up");
            assert_eq!(node.connected_peers(), 0);
            let got = node.chunk([7u8; 32], false).await;
            assert!(
                matches!(got, Err(SwarmError::NotReady(_)) | Ok(None)),
                "a peerless node answered {got:?}"
            );
        });
        node.shutdown(Duration::from_secs(5));
        rt.block_on(async {
            let gone = tokio::time::timeout(Duration::from_secs(5), async {
                while status.changed().await.is_ok() {}
            })
            .await;
            assert!(gone.is_ok(), "the node's status sender outlived shutdown");
        });
    }

    /// Against a running bee-factory (not run by default):
    /// `SWARM_DEV_BOOTNODE=/ip4/127.0.0.1/tcp/1734/p2p/<queen peer id> SWARM_DEV_NETWORK=1337
    /// SWARM_DEV_CHUNK=<hex address> cargo test --manifest-path rust/swarm/Cargo.toml --
    /// --ignored --nocapture`.
    #[test]
    #[ignore]
    fn reads_a_chunk_from_a_dev_network() {
        let bootnode: Multiaddr = std::env::var("SWARM_DEV_BOOTNODE")
            .unwrap()
            .parse()
            .unwrap();
        let network: u64 = std::env::var("SWARM_DEV_NETWORK").unwrap().parse().unwrap();
        let address: [u8; 32] = hex_32(&std::env::var("SWARM_DEV_CHUNK").unwrap());
        let node = SwarmNode::start(SwarmConfig::dev(network, vec![bootnode])).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..60 {
                if node.connected_peers() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            println!("{} peers", node.connected_peers());
            let chunk = node
                .chunk(address, false)
                .await
                .unwrap()
                .expect("chunk exists");
            println!("chunk of {} bytes", chunk.len());
        });
        node.shutdown(Duration::from_secs(5));
    }

    fn hex_32(s: &str) -> [u8; 32] {
        let s = s.trim_start_matches("0x");
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
