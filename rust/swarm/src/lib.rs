//! Myotis's embedded Swarm reader: an [`ant`](https://github.com/freedom-hq/ant) light node
//! linked into the engine, which reaches Swarm over libp2p (`.claude/agent/data-sources.md`,
//! the carve-out for Swarm reads of the address index).
//!
//! This crate only fetches. It hands back what Swarm delivered, a chunk in wire form or the
//! bytes of a file; ant checks a content-addressed chunk against its address, and every caller
//! checks what it reads against what it expects (a SOC's owner signature, a file's reference,
//! the record's canonical encoding) before using it. It never serves HTTP and never uploads.
//!
//! The node runs as a task on the caller's tokio runtime and is driven through ant's command
//! channel ([`ant_control::ControlCommand`]), the in-process interface `antd`'s own control
//! socket uses.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ant_control::{ControlAck, ControlCommand, StatusSnapshot};
use ant_node::{run_node, NodeConfig};
use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use tokio::sync::{mpsc, oneshot, watch};

/// Swarm mainnet's network id.
pub const MAINNET_NETWORK_ID: u64 = 1;

/// Largest file this reader joins (the addr1 index's spill and pages files stay below the
/// 256 MiB its importer refuses to exceed).
pub const MAX_FILE_BYTES: u64 = 256 << 20;

/// Errors of the reader.
#[derive(Debug)]
pub enum SwarmError {
    /// The node is not running (never started, or its task ended).
    Stopped,
    /// Peers answered that the chunk or file does not exist.
    NotFound(String),
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
            Self::NotFound(m) => write!(f, "not found on Swarm: {m}"),
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
    /// How long one read may take.
    pub timeout: Duration,
}

impl SwarmConfig {
    /// Swarm mainnet through its published bootnodes.
    pub fn mainnet() -> Self {
        Self {
            network_id: MAINNET_NETWORK_ID,
            bootnodes: ant_p2p::default_mainnet_bootnodes(),
            allow_private_dials: false,
            peerstore_path: None,
            timeout: Duration::from_secs(60),
        }
    }

    /// A local network (bee-factory): its network id and the multiaddrs of its nodes.
    pub fn dev(network_id: u64, bootnodes: Vec<Multiaddr>) -> Self {
        Self {
            network_id,
            bootnodes,
            allow_private_dials: true,
            peerstore_path: None,
            timeout: Duration::from_secs(30),
        }
    }
}

/// A running embedded node.
pub struct SwarmNode {
    commands: mpsc::Sender<ControlCommand>,
    status: watch::Receiver<StatusSnapshot>,
    timeout: Duration,
    task: tokio::task::JoinHandle<()>,
}

impl SwarmNode {
    /// Starts a node on the current tokio runtime. Its identity (the BZZ signing key, the
    /// overlay nonce and the libp2p key) is fresh for every start: a reader needs no stable
    /// identity, and a fresh one links fewer sessions together.
    pub fn start(cfg: SwarmConfig) -> Self {
        let signing_secret = ant_crypto::random_secp256k1_secret();
        let overlay_nonce = ant_crypto::random_overlay_nonce();
        let mut secret = signing_secret;
        let keypair = libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut secret)
            .map(|sk| Keypair::from(libp2p::identity::secp256k1::Keypair::from(sk)))
            .unwrap_or_else(|_| Keypair::generate_secp256k1());
        let (commands, rx) = mpsc::channel(64);
        let (status_tx, status) = watch::channel(StatusSnapshot::default());
        let mut node =
            NodeConfig::mainnet_default(signing_secret, overlay_nonce, cfg.bootnodes, keypair)
                .with_network_id(cfg.network_id)
                .with_allow_private_dials(cfg.allow_private_dials)
                .with_status(status_tx);
        node.commands = Some(rx);
        node.peerstore_path = cfg.peerstore_path;
        node.process_start = Instant::now();
        // A reader settles nothing on chain and pays nobody: free-tier retrieval only.
        node.swap_enabled = false;
        let task = tokio::spawn(async move {
            if let Err(e) = run_node(node).await {
                tracing::warn!(target: "myotis_swarm", "Swarm node stopped: {e}");
            }
        });
        Self {
            commands,
            status,
            timeout: cfg.timeout,
            task,
        }
    }

    /// Peers with a completed Swarm handshake.
    pub fn connected_peers(&self) -> u32 {
        self.status.borrow().peers.connected
    }

    /// Whether the node's task is still running.
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }

    /// The chunk at `address` in wire form (`span ‖ payload` for a content-addressed chunk,
    /// `identifier ‖ signature ‖ span ‖ payload` for a SOC), or `Ok(None)` when peers
    /// answered that it does not exist. `expect_missing` asks fewer peers before concluding
    /// it is missing: for a read whose miss is an expected answer (a head update not
    /// published yet).
    pub async fn chunk(
        &self,
        address: [u8; 32],
        expect_missing: bool,
    ) -> Result<Option<Vec<u8>>, SwarmError> {
        let (ack, rx) = oneshot::channel();
        self.send(ControlCommand::GetChunkRaw {
            reference: address,
            fast_miss: expect_missing,
            bypass_cache: false,
            ack,
        })
        .await?;
        match tokio::time::timeout(self.timeout, rx).await {
            Err(_) => Err(SwarmError::Timeout),
            Ok(Err(_)) => Err(SwarmError::Stopped),
            Ok(Ok(ControlAck::Bytes { data })) => Ok(Some(data)),
            Ok(Ok(ControlAck::NotFound { .. })) => Ok(None),
            Ok(Ok(other)) => Err(unexpected(other)),
        }
    }

    /// The file (an unencrypted chunk tree, Bee's `/bytes`) rooted at `reference`, joined, at
    /// most [`MAX_FILE_BYTES`].
    pub async fn file(&self, reference: [u8; 32]) -> Result<Vec<u8>, SwarmError> {
        let (ack, mut rx) = mpsc::channel(16);
        self.send(ControlCommand::GetBytes {
            reference,
            bypass_cache: false,
            progress: false,
            max_bytes: Some(MAX_FILE_BYTES),
            ack,
        })
        .await?;
        let read = async {
            let mut out: Option<Vec<u8>> = None;
            while let Some(a) = rx.recv().await {
                match a {
                    ControlAck::Bytes { data } => return Ok(data),
                    ControlAck::BytesStreamStart { total_bytes } => {
                        if total_bytes > MAX_FILE_BYTES {
                            return Err(SwarmError::Failed(format!(
                                "file of {total_bytes} bytes, above {MAX_FILE_BYTES}"
                            )));
                        }
                        out = Some(Vec::with_capacity(total_bytes as usize));
                    }
                    ControlAck::BytesChunk { data } => {
                        out.get_or_insert_with(Vec::new).extend_from_slice(&data)
                    }
                    ControlAck::StreamDone => return Ok(out.unwrap_or_default()),
                    ControlAck::Progress(_) => {}
                    other => return Err(unexpected(other)),
                }
            }
            Err(SwarmError::Stopped)
        };
        tokio::time::timeout(self.timeout, read)
            .await
            .unwrap_or(Err(SwarmError::Timeout))
    }

    async fn send(&self, cmd: ControlCommand) -> Result<(), SwarmError> {
        self.commands
            .send(cmd)
            .await
            .map_err(|_| SwarmError::Stopped)
    }
}

impl Drop for SwarmNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn unexpected(ack: ControlAck) -> SwarmError {
    match ack {
        ControlAck::NotFound { message } => SwarmError::NotFound(message),
        ControlAck::NotReady { message } => SwarmError::NotReady(message),
        ControlAck::Error { message } => SwarmError::Failed(message),
        other => SwarmError::Failed(format!("unexpected answer {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node with nowhere to connect still starts, answers "not ready" or times out instead
    /// of hanging, and stops when dropped.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_without_peers_answers_and_stops() {
        let mut cfg = SwarmConfig::dev(4020, Vec::new());
        cfg.timeout = Duration::from_secs(5);
        let node = SwarmNode::start(cfg);
        assert_eq!(node.connected_peers(), 0);
        let got = node.chunk([7u8; 32], true).await;
        assert!(!matches!(got, Ok(Some(_))), "a chunk from nowhere");
        drop(node);
    }

    /// Against a running bee-factory (not run by default):
    /// `SWARM_DEV_BOOTNODE=/ip4/127.0.0.1/tcp/1634/p2p/<queen peer id> SWARM_DEV_NETWORK=4020
    /// SWARM_DEV_CHUNK=<hex address> cargo test -p myotis-swarm -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn reads_a_chunk_from_a_dev_network() {
        let bootnode: Multiaddr = std::env::var("SWARM_DEV_BOOTNODE")
            .unwrap()
            .parse()
            .unwrap();
        let network: u64 = std::env::var("SWARM_DEV_NETWORK").unwrap().parse().unwrap();
        let address: [u8; 32] = hex_32(&std::env::var("SWARM_DEV_CHUNK").unwrap());
        let node = SwarmNode::start(SwarmConfig::dev(network, vec![bootnode]));
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
