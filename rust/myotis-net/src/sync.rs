//! The light-client sync loop — drives `myotis_consensus` (store + processor)
//! over the req/resp transport, mirroring the behavior of the Java
//! `BeaconLightClient.syncLoop`: bootstrap from the embedded checkpoint,
//! catch the sync committee up to the wall-clock period via
//! `light_client_updates_by_range`, then poll `light_client_finality_update`
//! every slot.
//!
//! CLOCK POLICY: this module is the only place wall-clock time is read. Slot
//! estimates are computed here and passed into the consensus crate as plain
//! values (`force_rotate_if_past_period(slot_estimate)`), keeping
//! `myotis-consensus` clock-free.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::stream::{FuturesUnordered, StreamExt};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, watch};

use myotis_consensus::spec;
use myotis_consensus::store::{LightClientProcessor, LightClientStore};
use myotis_consensus::types::{LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate};
use myotis_consensus::ssz;

use crate::codec;
use crate::discovery::{self, DiscoveryConfig};
use crate::protocols;
use crate::reqresp::{self, LocalStatus, ReqRespClient, RequestError};
use crate::status::{fork_digest, fork_digest_bpo, StatusMessage};

// -------------------------------------------------------------------------
// Chain configuration
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub name: &'static str,
    pub fork_version: [u8; 4],
    /// Prior fork version, accepted as a discv5 fork-digest fallback (the Java
    /// `NetworkConfig.acceptedForkDigests`). None for mainnet (on Fulu; stale
    /// digests wouldn't help us sync).
    pub prior_fork_version: Option<[u8; 4]>,
    pub genesis_validators_root: [u8; 32],
    /// Beacon chain genesis time (seconds since epoch) for wall-clock slot estimates.
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    /// EIP-7892 active BPO entry folded into the fork digest (0 epoch = none).
    pub blob_params_epoch: u64,
    pub blob_params_max_blobs: u64,
    /// Trusted weak-subjectivity checkpoint (block root + slot).
    pub checkpoint_root: [u8; 32],
    pub checkpoint_slot: u64,
    /// Pinned light-client-serving peer multiaddrs (`/ip4/../tcp/../p2p/..`).
    pub static_peers: Vec<String>,
    /// discv5 bootstrap ENRs.
    pub bootstrap_enrs: Vec<String>,
    /// discv5 UDP listen port (0 = OS-assigned; use when running next to a Java daemon).
    pub discv5_port: u16,
    /// Persisted verified-store snapshot path (`sync-state[-net].snapshot`) —
    /// the SAME file, SAME format ("LCSS" v1) as the Java engine, so state
    /// survives restarts and engine switches. None = no persistence.
    pub snapshot_path: Option<std::path::PathBuf>,
    /// CL peer cache path (`cl-peers[-net].cache`) — same file/format as the
    /// Java hosts' caches. None = no persistence.
    pub cl_peer_cache_path: Option<std::path::PathBuf>,
}

impl ChainConfig {
    /// Mainnet — values duplicated verbatim from the Java
    /// `NetworkConfig.MAINNET` (networking/src/main/java/.../NetworkConfig.java).
    pub fn mainnet() -> Self {
        Self {
            name: "mainnet",
            // Fulu, activated at slot 13164544 (2025-12-03).
            fork_version: [0x06, 0x00, 0x00, 0x00],
            prior_fork_version: None,
            genesis_validators_root: hex32(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
            genesis_time: 1_606_824_023, // 2020-12-01 12:00:23 UTC
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            // BPO2 (Fusaka) blob schedule entry: epoch 419072, MAX_BLOBS=21.
            blob_params_epoch: 419_072,
            blob_params_max_blobs: 21,
            // Copied verbatim from the @checkpoint:mainnet:begin/end region of
            // NetworkConfig.java (slot 14560000, 2026-06-15, period 1777).
            // NOTE: `./gradlew refreshMainnetCheckpoint` rewrites only the Java
            // region today — it does NOT rewrite this constant yet (plan PR7);
            // until then a checkpoint refresh must be mirrored here by hand.
            checkpoint_root: hex32(
                "58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e",
            ),
            checkpoint_slot: 14_560_000,
            static_peers: MAINNET_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
            bootstrap_enrs: MAINNET_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
            discv5_port: 0,
            snapshot_path: None,
            cl_peer_cache_path: None,
        }
    }

    /// Fork digests accepted when filtering discv5 ENRs — current first, then
    /// the prior fork's when configured (`NetworkConfig.acceptedForkDigests`).
    pub fn accepted_fork_digests(&self) -> Vec<[u8; 4]> {
        let mut out = vec![self.current_fork_digest()];
        if let Some(prior) = self.prior_fork_version {
            out.push(fork_digest(prior, self.genesis_validators_root));
        }
        out
    }

    pub fn current_fork_digest(&self) -> [u8; 4] {
        fork_digest_bpo(
            self.fork_version,
            self.genesis_validators_root,
            self.blob_params_epoch,
            self.blob_params_max_blobs,
        )
    }

    /// Wall-clock sync-committee period — the catch-up target the store's period
    /// climbs to. Public so the engine crate can stamp it into the status JSON at
    /// read time (deriving it per read keeps it fresh across bootstrap stalls and
    /// correct for created-but-not-started handles, instead of snapshot-carrying
    /// a value that goes stale).
    pub fn wall_clock_period(&self) -> u64 {
        spec::compute_sync_committee_period(self.current_slot_estimate())
    }

    /// Wall-clock slot estimate — THE clock read of this crate.
    fn current_slot_estimate(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now.saturating_sub(self.genesis_time) / self.seconds_per_slot.max(1)
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex constant");
    }
    out
}

/// Known light-client-serving mainnet peers — the Java `NetworkConfig.MAINNET`
/// clPeerMultiaddrs list (nimbus/lodestar/lighthouse, discovered 2026-03-11).
const MAINNET_STATIC_PEERS: &[&str] = &[
    "/ip4/176.229.58.1/tcp/9001/p2p/16Uiu2HAmHu1BxzrSWg7sN9JyJenC5unK5ntdk5QFYqQdQyyD7x3a",
    "/ip4/81.172.166.237/tcp/9001/p2p/16Uiu2HAmRogw5aqM4ZuVEmZoQvFp25sUnnQ9wpGuWXRLFMmXc88j",
    "/ip4/54.157.213.0/tcp/9000/p2p/16Uiu2HAmQz83bNmMaBFCafuxDasiNdPYZF1B4zhgo3DckByU8bo3",
    "/ip4/84.229.246.214/tcp/9001/p2p/16Uiu2HAm1UtRynVpuvWUgn3bfNooSUKYSUrbW8oeuBBcwVxbC1c9",
    "/ip4/73.205.184.197/tcp/9000/p2p/16Uiu2HAm9CKG1x5rJk6sgEnCh9TKRagNEVVJfjR1jC3ruzPQfwzb",
    "/ip4/172.92.13.157/tcp/9000/p2p/16Uiu2HAm7TEx4DP8iVj1RedeDNK59pw9AskGRwV7x9vgexTQi8CM",
    "/ip4/77.12.100.127/tcp/9012/p2p/16Uiu2HAmA5VXnNKGu9jmV5yhL3tGy5seiNMnaBMTaV1vBesz84iJ",
    "/ip4/52.200.203.85/tcp/9000/p2p/16Uiu2HAm6JKuoWTSKP7uTbe1PESUcejo4ffcaADoRMuKmMJQKBeP",
    "/ip4/82.139.21.242/tcp/9802/p2p/16Uiu2HAm5LSnoe8EdTDhrPEm4M1fnYw34zSo2SYbXLLH4FtfcfnL",
    "/ip4/217.67.221.74/tcp/9037/p2p/16Uiu2HAmExQubp4XC5KoQwvYxNWJP2M5rpX3VKdtEYgwPnMb5Kn4",
    "/ip4/135.181.210.123/tcp/9000/p2p/16Uiu2HAmBWXZS9H2ncxgEcVi77GvYtmGUEGpHNyJxsF3Ct25Uidc",
    "/ip4/195.201.160.183/tcp/9000/p2p/16Uiu2HAm79xzMY5FNnXGo6xcBRxCzYvMNE7CM6NZytrjXoDB5yRQ",
    "/ip4/45.10.55.78/tcp/9000/p2p/16Uiu2HAmCpe6iMDvcXFmjLVpJ98u1fqNehpDLS2dmMRgxQ8mgMKu",
    "/ip4/185.107.68.131/tcp/9000/p2p/16Uiu2HAm3sGDmyV3m4tju3SzekGt2EBSnALQNdn9QebPSiQP5NA2",
    "/ip4/51.161.218.70/tcp/9000/p2p/16Uiu2HAmE6fJp7ZZVMUFxZGgfxAvfVyX3GDU6Wh88GvWv5U6SriT",
    "/ip4/216.105.170.30/tcp/9000/p2p/16Uiu2HAm86YwyECbBiHTo2imwQJ4UXGgR1NLY2W6dPUfEFDony6d",
    "/ip4/54.201.148.177/tcp/9000/p2p/16Uiu2HAmNwEsdBC2phX7qU7camNe9Gs21WyrpV5AZDYyjZBMYjWZ",
    "/ip4/16.63.94.117/tcp/9000/p2p/16Uiu2HAmSd7qzG5joNgvEYYcgVvg1y9MiYjpMHMvzRzaWYqXxkCM",
];

/// Mainnet CL discv5 bootnodes — the Java `NetworkConfig.MAINNET`
/// clDiscv5Bootnodes list (sigp/lighthouse bootstrap_nodes.yaml mirror).
const MAINNET_BOOTSTRAP_ENRS: &[&str] = &[
    // Teku
    "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
    "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",
    // Prylabs
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
    // Sigma Prime (Lighthouse)
    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",
    // Ethereum Foundation
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
    // Nimbus
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
    // Lodestar
    "enr:-IS4QPi-onjNsT5xAIAenhCGTDl4z-4UOR25Uq-3TmG4V3kwB9ljLTb_Kp1wdjHNj-H8VVLRBSSWVZo3GUe3z6k0E-IBgmlkgnY0gmlwhKB3_qGJc2VjcDI1NmsxoQMvAfgB4cJXvvXeM6WbCG86CstbSxbQBSGx31FAwVtOTYN1ZHCCIyg",
    "enr:-KG4QPUf8-g_jU-KrwzG42AGt0wWM1BTnQxgZXlvCEIfTQ5hSmptkmgmMbRkpOqv6kzb33SlhPHJp7x4rLWWiVq5lSECgmlkgnY0gmlwhFPlR9KDaXA2kCoGxcAJAAAVAAAAAAAAABCJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA",
];

// -------------------------------------------------------------------------
// Status snapshot
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Starting,
    Bootstrapping,
    CatchingUp,
    Synced,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Starting => "STARTING",
            Self::Bootstrapping => "BOOTSTRAPPING",
            Self::CatchingUp => "CATCHING_UP",
            Self::Synced => "SYNCED",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub state: SyncState,
    pub finalized_slot: u64,
    /// hash_tree_root of the finalized beacon header.
    pub finalized_root: [u8; 32],
    pub optimistic_slot: u64,
    /// Sync-committee period the store currently holds a committee for.
    pub period: u64,
    pub peer_count: usize,
    /// Distinct peers that successfully served a light-client response
    /// (bootstrap / updates / finality) in the last 60 s — the UI's "CL peers
    /// served N/min" health signal (Java `BeaconStatus.servedPeersLastMinute`).
    pub served_peers_last_min: usize,
    /// TOTAL entries in the discv5 routing table, including Disconnected
    /// ones (the UI's "Discv5 peers" row) — deliberately not the connected
    /// count, which reads a misleading 0 during connectivity blips.
    pub discv5_table_size: usize,
}

impl SyncStatus {
    /// The pre-start snapshot (all zero, `Starting`). Public so the engine crate
    /// can render a not-yet-started handle's status without a live `SyncHandle`.
    pub fn initial() -> Self {
        Self {
            state: SyncState::Starting,
            finalized_slot: 0,
            finalized_root: [0u8; 32],
            optimistic_slot: 0,
            period: 0,
            peer_count: 0,
            served_peers_last_min: 0,
            discv5_table_size: 0,
        }
    }
}

// -------------------------------------------------------------------------
// SyncHandle
// -------------------------------------------------------------------------

/// A running light-client sync. Independent instances are fully independent
/// (each owns its libp2p host, discv5 service, and store — no globals).
pub struct SyncHandle {
    status_rx: watch::Receiver<SyncStatus>,
    client: ReqRespClient,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SyncHandle {
    /// Start syncing. Must be called from within a tokio runtime.
    pub fn start(config: ChainConfig) -> Result<SyncHandle, String> {
        let (status_tx, status_rx) = watch::channel(SyncStatus::initial());

        // Local Status the responder serves pre-bootstrap: the trusted
        // checkpoint (a real block root — Lighthouse's relevance check
        // goodbyes zero roots; see the Java buildLocalStatusFor).
        let local_status = LocalStatus::new(StatusMessage {
            fork_digest: config.current_fork_digest(),
            finalized_root: config.checkpoint_root,
            finalized_epoch: config.checkpoint_slot / config.slots_per_epoch.max(1),
            head_root: config.checkpoint_root,
            head_slot: config.checkpoint_slot,
            earliest_available_slot: 0,
        });

        let client = reqresp::start_host(Arc::clone(&local_status))?;

        let discovery_cfg = DiscoveryConfig {
            bootstrap_enrs: config.bootstrap_enrs.clone(),
            accepted_fork_digests: config.accepted_fork_digests(),
            listen_port: config.discv5_port,
        };

        let sync_task = tokio::spawn(run_sync(
            config,
            client.clone(),
            local_status,
            status_tx,
            discovery_cfg,
        ));

        Ok(SyncHandle { status_rx, client, tasks: vec![sync_task] })
    }

    pub fn status(&self) -> SyncStatus {
        self.status_rx.borrow().clone()
    }

    /// A watch receiver for callers that want to await state changes.
    pub fn watch(&self) -> watch::Receiver<SyncStatus> {
        self.status_rx.clone()
    }

    /// Stop the sync loop, discovery, and the libp2p host.
    pub async fn stop(self) {
        self.client.shutdown().await;
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

// -------------------------------------------------------------------------
// Peer pool
// -------------------------------------------------------------------------

#[derive(Clone)]
struct Peer {
    id: PeerId,
    addr: Multiaddr,
}

struct PeerPool {
    peers: Vec<Peer>,
    known: HashSet<PeerId>,
    /// Peers proven NOT to serve light_client_updates_by_range (protocol
    /// negotiation failed) — mirrors the Java `peersNoLcUpdates`.
    no_lc_updates: HashSet<PeerId>,
    /// Peers that actually SERVED light-client data (bootstrap or an applied
    /// update) — mirrors the Java proven-server tracking; preferred first.
    proven: HashSet<PeerId>,
    /// Per-peer "don't re-ask updates_by_range until" marks. Live CL peers
    /// rate-limit that protocol to ~one served update per request window; an
    /// immediate re-ask returns an empty stream, so rotate away for a while.
    cooldown_until: HashMap<PeerId, Instant>,
    /// Last successful serve per peer, for the served-last-minute health
    /// metric. Deliberately NOT cleared by evict(): "served in the last 60 s"
    /// stays true of an evicted peer; entries prune inside note_served (the
    /// &mut site), so the map stays bounded by serve activity.
    recent_serves: HashMap<PeerId, Instant>,
    /// Total discv5 routing-table entry count (incl. Disconnected), written
    /// by the discovery task each lookup round. Lives here (not a
    /// publish_status param) because the pool already travels everywhere
    /// status is published.
    discv5_table_size: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Consecutive terminal-failure count per peer, for eviction. Reset on any
    /// success. Without eviction the MAX_POOL cap fills with dead peers and
    /// `add` starts rejecting fresh ones — a permanent catch-up wedge.
    fail_counts: HashMap<PeerId, u32>,
    /// Rotating offset so retries sweep different peers each cycle.
    sweep: usize,
}

/// How long to leave a peer alone after it served (or empty-replied) an
/// updates_by_range request. Lighthouse's default inbound quota for this
/// protocol is `Quota::one_every(10s)` (rpc/config.rs) — one update per 10 s
/// per peer; asking again just after the window refills is both polite and
/// the fastest legal cadence.
const UPDATES_SERVE_COOLDOWN: Duration = Duration::from_secs(11);

/// Cap on the discovered pool (Java MAX_CL_PEERS is 1024; we keep it smaller —
/// the sync loop fans out to a handful at a time anyway).
const MAX_POOL: usize = 512;

/// Consecutive terminal failures before eviction. Un-proven peers go on the
/// first (cheap, endlessly rediscoverable); a peer that has actually served
/// gets slack so one transient blip doesn't drop a scarce LC server.
const UNPROVEN_EVICT_AT: u32 = 1;
const PROVEN_EVICT_AT: u32 = 3;
/// Window for the served-peers health metric (BeaconStatus.servedPeersLastMinute).
const SERVED_WINDOW: Duration = Duration::from_secs(60);

impl PeerPool {
    fn new() -> Self {
        Self {
            peers: Vec::new(),
            known: HashSet::new(),
            no_lc_updates: HashSet::new(),
            proven: HashSet::new(),
            cooldown_until: HashMap::new(),
            fail_counts: HashMap::new(),
            recent_serves: HashMap::new(),
            discv5_table_size: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            sweep: 0,
        }
    }

    fn mark_proven(&mut self, id: PeerId) {
        self.proven.insert(id);
        self.fail_counts.remove(&id); // a served peer is demonstrably alive
    }

    /// Stamp a VERIFIED serve (bootstrap applied / catch-up update applied /
    /// finality update applied) for the served-last-minute health metric.
    /// Deliberately NOT part of mark_proven: decode-only responses and the
    /// startup cache warm-load must not read as live serving — the metric
    /// exists to expose exactly those stalls. Prunes here (the &mut site),
    /// keeping the map bounded by serve activity.
    fn note_served(&mut self, id: PeerId) {
        let now = Instant::now();
        // checked_sub: within 60 s of device boot the monotonic clock is
        // younger than the window and a plain subtraction would PANIC
        // (= abort the app under panic=abort) — keep everything instead.
        if let Some(cutoff) = now.checked_sub(SERVED_WINDOW) {
            self.recent_serves.retain(|_, t| *t >= cutoff);
        }
        self.recent_serves.insert(id, now);
    }

    /// Distinct peers with a verified serve within the last 60 s.
    fn served_last_minute(&self) -> usize {
        match Instant::now().checked_sub(SERVED_WINDOW) {
            Some(cutoff) => self.recent_serves.values().filter(|t| **t >= cutoff).count(),
            None => self.recent_serves.len(), // clock younger than the window
        }
    }

    /// Record a terminal request failure (dial/timeout/connection-closed — NOT
    /// UnsupportedProtocol, which means the peer is alive but doesn't serve LC).
    /// Evicts once the peer crosses its threshold, freeing a MAX_POOL slot.
    fn note_failure(&mut self, id: PeerId) {
        let n = self.fail_counts.entry(id).or_insert(0);
        *n += 1;
        let threshold = if self.proven.contains(&id) {
            PROVEN_EVICT_AT
        } else {
            UNPROVEN_EVICT_AT
        };
        if *n >= threshold {
            self.evict(&id);
        }
    }

    /// Remove a peer everywhere, including from `known` so discovery may re-add
    /// it if it comes back (mirrors the Java addPeer/knownPeerAddrs eviction —
    /// re-discoverable rather than permanently tombstoned; `fail_counts` resets
    /// with it, so a recovered peer starts clean).
    fn evict(&mut self, id: &PeerId) {
        self.peers.retain(|p| &p.id != id);
        self.known.remove(id);
        self.no_lc_updates.remove(id);
        self.proven.remove(id);
        self.cooldown_until.remove(id);
        self.fail_counts.remove(id);
    }

    fn set_updates_cooldown(&mut self, id: PeerId) {
        self.cooldown_until.insert(id, Instant::now() + UPDATES_SERVE_COOLDOWN);
    }

    fn cooled_down(&self, id: &PeerId) -> bool {
        self.cooldown_until.get(id).is_none_or(|until| *until <= Instant::now())
    }

    fn add(&mut self, id: PeerId, addr: Multiaddr) {
        if self.peers.len() >= MAX_POOL || !self.known.insert(id) {
            return;
        }
        self.peers.push(Peer { id, addr });
    }

    fn mark_no_lc_updates(&mut self, id: PeerId) {
        self.no_lc_updates.insert(id);
    }

    fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    fn len(&self) -> usize {
        self.peers.len()
    }

    /// Up to `n` candidates starting at a rotating offset. `skip_no_lc`
    /// filters the proven non-servers; `respect_cooldown` skips peers inside
    /// their updates-serve cooldown. Never starves: falls back to everyone.
    fn candidates(
        &mut self,
        n: usize,
        skip_no_lc: bool,
        respect_cooldown: bool,
        prefer: &HashSet<PeerId>,
    ) -> Vec<Peer> {
        if self.peers.is_empty() {
            return Vec::new();
        }
        let ok = |pool: &Self, id: &PeerId| {
            (!skip_no_lc || !pool.no_lc_updates.contains(id))
                && (!respect_cooldown || pool.cooled_down(id))
        };
        let mut out: Vec<Peer> = Vec::with_capacity(n);
        // Tier 1: peers that actually served light-client data before.
        // Tier 2: positive-signal peers (Identify-confirmed LC servers).
        for tier in [&self.proven, prefer] {
            for p in &self.peers {
                if out.len() >= n {
                    break;
                }
                if tier.contains(&p.id) && ok(self, &p.id) && !out.iter().any(|q| q.id == p.id) {
                    out.push(p.clone());
                }
            }
        }
        // Fill from a rotating window of the rest.
        let start = self.sweep % self.peers.len();
        self.sweep = self.sweep.wrapping_add(n);
        for i in 0..self.peers.len() {
            if out.len() >= n {
                break;
            }
            let p = &self.peers[(start + i) % self.peers.len()];
            if out.iter().any(|q| q.id == p.id) || !ok(self, &p.id) {
                continue;
            }
            out.push(p.clone());
        }
        if out.is_empty() {
            // Never starve the batch (Java: `if (capable.isEmpty()) capable = peers`).
            out.extend(self.peers.iter().take(n).cloned());
        }
        out
    }
}

fn parse_static_peer(multiaddr: &str) -> Option<Peer> {
    let addr: Multiaddr = multiaddr.parse().ok()?;
    let mut base = Multiaddr::empty();
    let mut peer_id = None;
    for proto in addr.iter() {
        if let libp2p::multiaddr::Protocol::P2p(id) = proto {
            peer_id = Some(id);
        } else {
            base.push(proto);
        }
    }
    Some(Peer { id: peer_id?, addr: base })
}

// -------------------------------------------------------------------------
// The sync loop
// -------------------------------------------------------------------------

async fn run_sync(
    config: ChainConfig,
    client: ReqRespClient,
    local_status: Arc<LocalStatus>,
    status_tx: watch::Sender<SyncStatus>,
    discovery_cfg: DiscoveryConfig,
) {
    let mut pool = PeerPool::new();
    for s in &config.static_peers {
        match parse_static_peer(s) {
            Some(p) => pool.add(p.id, p.addr),
            None => tracing::warn!(peer = s, "skipping unparseable static peer multiaddr"),
        }
    }
    tracing::info!(chain = config.name, static_peers = pool.len(),
        fork_digest = %hex_str(&config.current_fork_digest()),
        "sync starting");

    // Discovery feeds the pool continuously; failure is non-fatal (Java treats
    // discv5 the same way). The guard aborts the discovery task the moment
    // run_sync's future is dropped (SyncHandle::stop): without it the lookup
    // loop only notices the closed channel at its next 15 s tick, keeping the
    // UDP port bound and failing a fast stop→start on a fixed discv5_port
    // (tokio cancellation drops the future's locals without unwinding, so the
    // guard is panic=abort-safe and Discv5's socket closes immediately).
    struct DiscoveryGuard(Option<tokio::task::JoinHandle<()>>);
    impl Drop for DiscoveryGuard {
        fn drop(&mut self) {
            if let Some(task) = self.0.as_ref() {
                task.abort();
            }
        }
    }
    let mut discovery_guard = DiscoveryGuard(None);

    let (peer_tx, mut peer_rx) = mpsc::channel::<discovery::DiscoveredPeer>(64);
    let mut discovery_up = match discovery::spawn(discovery_cfg.clone(), peer_tx.clone()).await {
        Ok((task, table_size)) => {
            pool.discv5_table_size = table_size;
            discovery_guard.0 = Some(task);
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "discv5 unavailable — will retry (static peers meanwhile)");
            false
        }
    };
    // Respawn countdown, in outer-loop iterations (~12 s each → retry ~1/min).
    // A failed spawn is often transient (the predecessor instance's port still
    // bound during a fast restart) — without the retry, discv5TableSize would
    // report 0 for the process lifetime, indistinguishable from an empty
    // table, and the empty-table re-seed could never run at all.
    let mut discovery_retry_in = 0u32;

    let mut processor = LightClientProcessor::new(
        LightClientStore::new(),
        config.fork_version,
        config.genesis_validators_root,
    );

    // CL peer cache — the SAME file the Java hosts maintain, so proven LC
    // servers survive restarts and engine switches.
    let mut clcache = config
        .cl_peer_cache_path
        .clone()
        .map(crate::clcache::ClPeerCache::load)
        .unwrap_or_else(crate::clcache::ClPeerCache::disabled);
    for cached in clcache.peers() {
        if let Some(p) = parse_static_peer(&cached) {
            let (id, addr) = (p.id, p.addr.clone());
            pool.add(id, addr);
            if clcache.is_nolc(&cached) {
                pool.mark_no_lc_updates(id);
            }
            if clcache.served_range(&cached).is_some() {
                pool.mark_proven(id);
            }
        }
    }

    let mut status = SyncStatus::initial();
    status.state = SyncState::Bootstrapping;
    let _ = status_tx.send(status.clone());

    // Catch-up pipeline buffer (see catch_up) — lives here so staged periods
    // survive catch_up returning empty-handed between poll cycles.
    let mut staged_updates: std::collections::BTreeMap<u64, Vec<u8>> =
        std::collections::BTreeMap::new();

    // Resume from the persisted snapshot when it is bound to this chain AND
    // strictly newer than the embedded checkpoint (the snapshot was produced
    // from our own BLS-verified store, so resuming is strictly less long-range
    // exposure than re-bootstrapping — same rule as the Java engine, which
    // reads/writes the identical file). Anything else → fresh bootstrap. A
    // restored store stays on probation (ResumeGuard) until one update
    // BLS-verifies against it; see RESUME_REJECTS_MAX.
    let checkpoint_period = spec::compute_sync_committee_period(config.checkpoint_slot);
    // Floor the persist throttle at the CHECKPOINT period: a snapshot at (or
    // below) the checkpoint period can never be resumed (the strictly-newer
    // rule rejects it), so writing one could only OVERWRITE a possibly-newer
    // snapshot on disk with useless bytes — a fresh bootstrap must never
    // clobber resumable state (this exact overwrite was observed on-device:
    // a non-resuming boot's bootstrap-persist destroyed a period-1795
    // snapshot with a dead 1777 one). Only periods verified PAST the
    // checkpoint are worth writing.
    let mut last_persisted_period = checkpoint_period;
    let mut resume = ResumeGuard::fresh();
    if let Some(path) = &config.snapshot_path {
        if let Ok(bytes) = std::fs::read(path) {
            match myotis_consensus::snapshot::deserialize(&bytes, &config.genesis_validators_root) {
                Some(snap) if snap.current_sync_committee_period > checkpoint_period => {
                    last_persisted_period = snap.current_sync_committee_period;
                    tracing::info!(period = snap.current_sync_committee_period,
                        finalized_slot = snap.finalized_slot,
                        "resumed from persisted snapshot — skipping bootstrap");
                    processor.store.restore(snap);
                    resume = ResumeGuard::resumed();
                    // Publish the restored state IMMEDIATELY: without this the
                    // status watch holds SyncStatus::initial() (period 0 — 
                    // indistinguishable from a fresh bootstrap) until the first
                    // catch-up apply, hiding the resume from the UI and from
                    // on-device forensics.
                    refresh_local_status(&config, &processor, &local_status);
                    publish_status(&config, &client, &processor, &pool, &status_tx).await;
                }
                Some(_) => tracing::info!(
                    "persisted snapshot not newer than the embedded checkpoint — bootstrapping fresh"),
                None => tracing::warn!(
                    "persisted snapshot unreadable/foreign — bootstrapping fresh"),
            }
        }
    }

    // One loop for all phases: bootstrap (when the store isn't initialized —
    // fresh start OR after a poisoned resume was discarded), catch-up when
    // behind, finality polling in steady state.
    loop {
        drain_discovered(&mut peer_rx, &mut pool);

        if !discovery_up {
            if discovery_retry_in == 0 {
                discovery_retry_in = 5;
                match discovery::spawn(discovery_cfg.clone(), peer_tx.clone()).await {
                    Ok((task, table_size)) => {
                        pool.discv5_table_size = table_size;
                        discovery_guard.0 = Some(task);
                        discovery_up = true;
                        tracing::info!("discv5 recovered on retry");
                    }
                    Err(e) => tracing::debug!(error = %e, "discv5 respawn failed — will retry"),
                }
            } else {
                discovery_retry_in -= 1;
            }
        }

        if !processor.store.is_initialized() {
            let bootstrapped =
                try_bootstrap(&config, &client, &mut pool, &mut processor, &mut clcache).await;
            clcache.flush(); // one write per attempt round, win or lose
            if bootstrapped {
                persist_snapshot(&config, &processor, &mut last_persisted_period);
                refresh_local_status(&config, &processor, &local_status);
                publish_status(&config, &client, &processor, &pool, &status_tx).await;
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        let wall_period = spec::compute_sync_committee_period(config.current_slot_estimate());
        if wall_period > processor.store.current_period() {
            let poisoned = catch_up(&config, &client, &mut pool, &mut processor, &status_tx,
                &mut peer_rx, &mut staged_updates, &mut clcache, &mut resume)
                .await;
            // Batch-persist every cache verdict from the catch-up rounds in
            // one write, OFF the per-peer hot path (review: no blocking I/O
            // inside the parallel peer loop).
            clcache.flush();
            if poisoned {
                // The restored snapshot can't verify anything (corrupt on
                // disk, framing-valid): discard it and the store, and fall
                // back to the embedded checkpoint — the trust anchor path.
                tracing::warn!(rejects = RESUME_REJECTS_MAX,
                    "restored snapshot failed verification repeatedly — discarding; \
                     re-bootstrapping from the embedded checkpoint");
                if let Some(path) = &config.snapshot_path {
                    let _ = std::fs::remove_file(path);
                }
                processor.store = LightClientStore::new();
                staged_updates.clear();
                last_persisted_period = checkpoint_period; // keep the never-persist-checkpoint floor
                resume = ResumeGuard::fresh();
                continue;
            }
            // Persist on period advance only (Java parity): the ~50 KiB
            // committee snapshot is worth rewriting exactly when the committee
            // moved, not on every finality tick.
            persist_snapshot(&config, &processor, &mut last_persisted_period);
            refresh_local_status(&config, &processor, &local_status);
            publish_status(&config, &client, &processor, &pool, &status_tx).await;
            if spec::compute_sync_committee_period(config.current_slot_estimate())
                > processor.store.current_period()
            {
                // Still behind: skip the finality poll — while the committee is
                // stale every finality update fails BLS verify (Java does the
                // same to avoid burning the whole cycle).
                tokio::time::sleep(Duration::from_secs(config.seconds_per_slot)).await;
                continue;
            }
        }

        if poll_finality(&client, &mut pool, &mut processor, &mut clcache).await {
            // A finality update verified against the (possibly restored)
            // committee — the snapshot is genuine.
            resume.confirm();
        }
        clcache.flush(); // batch any finality-round evictions into one write
        // No-op unless the period advanced (force-rotate can move it here too).
        persist_snapshot(&config, &processor, &mut last_persisted_period);
        refresh_local_status(&config, &processor, &local_status);
        publish_status(&config, &client, &processor, &pool, &status_tx).await;

        tokio::time::sleep(Duration::from_secs(config.seconds_per_slot)).await;
    }
    // No code after the loop: the task ends via SyncHandle::stop (abort).
}

/// Persist the verified store when its committee period advanced past the last
/// write (Java `persistSnapshot` throttle — so this synchronous ~50 KiB write
/// runs at most once per ~27 h period, not per poll). Atomic temp+rename with
/// a pid-suffixed temp name so an overlapping writer from another process
/// (e.g. an engine switch mid-teardown) can't tear the temp file — renames
/// stay atomic either way, last writer wins. Best-effort: a failed write
/// costs a slower next start, never correctness. The Java `.roots` sidecar is
/// deliberately left in place: stale entries are harmless (the Java client
/// imports them before updateSyncState and simply ages them out), while a
/// deleted sidecar would cost Java FILL_THRESHOLD extra finality polls to
/// reach SYNCED after an engine switch back.
fn persist_snapshot(
    config: &ChainConfig,
    processor: &LightClientProcessor,
    last_persisted_period: &mut u64,
) {
    let Some(path) = &config.snapshot_path else { return };
    let period = processor.store.current_period();
    if period <= *last_persisted_period {
        return;
    }
    let Some(snap) = processor.store.snapshot() else { return };
    let bytes = myotis_consensus::snapshot::serialize(&snap, &config.genesis_validators_root);
    let tmp = std::path::PathBuf::from(format!(
        "{}.tmp.{}",
        path.display(),
        std::process::id()
    ));
    let ok = std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, path));
    match ok {
        Ok(()) => {
            tracing::info!(period, bytes = bytes.len(), "persisted sync-state snapshot");
        }
        // Give up until the NEXT period advance either way: a failing disk
        // (full/read-only) would otherwise be retried every ~12 s poll cycle
        // — repeated blocking I/O plus log spam — for a best-effort cache.
        Err(e) => tracing::warn!(error = %e,
            "snapshot write failed — retrying on the next period advance"),
    }
    *last_persisted_period = period;
}

fn drain_discovered(rx: &mut mpsc::Receiver<discovery::DiscoveredPeer>, pool: &mut PeerPool) {
    while let Ok(p) = rx.try_recv() {
        pool.add(p.peer_id, p.addr);
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fan a bootstrap request out to a few peers; first VALID response wins.
/// Validation mirrors the Java `bootstrap()`: checkpoint pin (header
/// hash_tree_root == checkpoint root), current-sync-committee branch, and
/// execution branch — all before `store.initialize`.
async fn try_bootstrap(
    config: &ChainConfig,
    client: &ReqRespClient,
    pool: &mut PeerPool,
    processor: &mut LightClientProcessor,
    clcache: &mut crate::clcache::ClPeerCache,
) -> bool {
    if pool.is_empty() {
        tracing::info!("bootstrap: no peers yet (waiting on discovery)");
        return false;
    }
    let peers = pool.candidates(8, false, false, &HashSet::new());
    tracing::info!(peers = peers.len(), root = %hex_str(&config.checkpoint_root),
        slot = config.checkpoint_slot, "bootstrap: requesting by checkpoint root");

    let wire = codec::encode_request(&config.checkpoint_root);
    let mut futures = Vec::new();
    for peer in &peers {
        let client = client.clone();
        let wire = wire.clone();
        let (id, addr) = (peer.id, peer.addr.clone());
        futures.push(async move {
            let res = client.request_raw(id, addr, protocols::BOOTSTRAP, wire).await;
            (id, res)
        });
    }
    let results = futures::future::join_all(futures).await;

    for (peer, res) in results {
        let raw = match res {
            Ok(raw) => raw,
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "bootstrap request failed");
                continue;
            }
        };
        let ssz_payload = match codec::decode_response(&raw, true) {
            Ok(d) => d.ssz_payload,
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "bootstrap frame invalid");
                continue;
            }
        };
        let bootstrap = match LightClientBootstrap::decode(&ssz_payload) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "bootstrap decode failed");
                continue;
            }
        };

        // Checkpoint pin: the peer chose the payload, WE chose the root.
        let header_root = bootstrap.header.beacon.hash_tree_root();
        if header_root != config.checkpoint_root {
            tracing::warn!(peer = %peer, got = %hex_str(&header_root),
                "bootstrap rejected: header root does not match checkpoint");
            continue;
        }
        let depth = bootstrap.current_sync_committee_branch.len();
        if !ssz::verify_merkle_branch(
            &bootstrap.current_sync_committee.hash_tree_root(),
            &bootstrap.current_sync_committee_branch,
            depth,
            spec::sync_committee_gindex(depth),
            &bootstrap.header.beacon.state_root,
        ) {
            tracing::warn!(peer = %peer, depth, "bootstrap rejected: sync committee branch invalid");
            continue;
        }
        if !LightClientProcessor::verify_execution_branch(&bootstrap.header) {
            tracing::warn!(peer = %peer, "bootstrap rejected: execution branch invalid");
            continue;
        }

        processor
            .store
            .initialize(bootstrap.header.clone(), bootstrap.current_sync_committee.clone());
        pool.mark_proven(peer);
        pool.note_served(peer); // verified: checkpoint pin + both branches checked
        if let Some(p) = peers.iter().find(|p| p.id == peer) {
            clcache.record_bootstrap(
                &format!("{}/p2p/{}", p.addr, p.id),
                processor.store.current_period(),
            );
        }
        tracing::info!(peer = %peer, slot = bootstrap.header.beacon.slot,
            period = processor.store.current_period(), "bootstrap verified and applied");
        return true;
    }
    false
}

/// Consecutive verify-rejects after a snapshot resume before the restored
/// state is declared poisoned and the store falls back to the embedded
/// checkpoint. LCSS has no integrity checksum, so a bit-flipped-but-framing-
/// valid snapshot (e.g. inside the ~49 KiB committee pubkeys) deserializes
/// fine and then fails BLS on EVERY update; without this guard that wedges
/// sync permanently (the period never advances, so the bad file is never
/// overwritten and every restart re-resumes it). Only catch-up VERIFY rejects
/// count — well-formed updates that failed BLS/Merkle against the restored
/// committee (decode failures are excluded: malformed frames indict the peer,
/// not our store). A bad peer serving valid-but-wrong updates can contribute
/// rejects too, so the threshold trades a rare unnecessary re-bootstrap
/// (self-correcting: the checkpoint path re-verifies everything) against a
/// permanent wedge; any successful apply confirms the resume for good.
const RESUME_REJECTS_MAX: u32 = 4;

/// Tracks whether a snapshot-restored store has verified anything yet.
/// Inert (never poisons) when the store bootstrapped fresh.
struct ResumeGuard {
    unconfirmed: bool,
    rejects: u32,
}

impl ResumeGuard {
    fn fresh() -> Self {
        Self { unconfirmed: false, rejects: 0 }
    }
    fn resumed() -> Self {
        Self { unconfirmed: true, rejects: 0 }
    }
    /// An update BLS-verified against the restored committee — the snapshot
    /// is genuine; the guard goes inert.
    fn confirm(&mut self) {
        self.unconfirmed = false;
        self.rejects = 0;
    }
    /// Count verify-rejects; true once the restored state is deemed poisoned.
    fn poisoned(&mut self, rejects: u32) -> bool {
        if !self.unconfirmed {
            return false;
        }
        self.rejects += rejects;
        self.rejects >= RESUME_REJECTS_MAX
    }
}

/// Periods fetched per catch-up round (≤16 per the plan; the spec request cap
/// is 128).
const UPDATES_BATCH_MAX: u64 = 16;
/// Peer candidates asked per round — all in parallel, first useful response
/// wins (Java CATCHUP_FANOUT_MAX is 48; the discovered pool is failure-heavy,
/// so a wide fan-out is what makes rounds land).
const CATCHUP_FANOUT: usize = 32;

/// Consecutive no-progress rounds before returning to the outer loop (which
/// refreshes the discovered-peer pool and republishes status). Rounds inside
/// retry after a short pause — the Java equivalent is MAX_CATCHUP_BATCHES
/// per call with a 12 s outer cycle.
const CATCHUP_MAX_IDLE_ROUNDS: u32 = 6;

/// Catch the store's committee period up to wall clock — the behavioral twin
/// of the Java `catchUpSyncCommittee`/`attemptCatchUpBatch`/
/// `applyCatchUpResponses`: every fan-out peer gets the SAME
/// `(current_period, count ≤ 16)` range request in parallel, so any single
/// successful response starts with the EARLIEST missing period (the whole
/// pipeline's bottleneck — the committee chain admits no gaps). Response
/// chunks are staged at consecutive periods (a mislabeled chunk just fails
/// verification at apply time and gets refetched) and the contiguous prefix
/// is verified+applied as it forms, `force_rotate_if_past_period` after each
/// applied update, exactly like the Java.
async fn catch_up(
    config: &ChainConfig,
    client: &ReqRespClient,
    pool: &mut PeerPool,
    processor: &mut LightClientProcessor,
    status_tx: &watch::Sender<SyncStatus>,
    peer_rx: &mut mpsc::Receiver<discovery::DiscoveredPeer>,
    // Fetched-but-not-yet-applied updates keyed by target period, owned by the
    // caller so partial pipeline progress survives across catch_up calls.
    // Raw SSZ — everything is BLS/Merkle-verified at apply time, in order.
    staged: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    clcache: &mut crate::clcache::ClPeerCache,
    resume: &mut ResumeGuard,
) -> bool {
    let mut idle_rounds = 0u32;
    // Exponential pause after fruitless rounds: hammering the whole pool every
    // ~13 s is exactly what CL peer scoring penalizes, and it burns request
    // quota on servers that will serve happily a minute later.
    let mut empty_backoff = Duration::from_secs(0);
    loop {
        if !empty_backoff.is_zero() {
            tracing::info!(backoff_s = empty_backoff.as_secs(),
                "catch-up: no progress last round — backing off before retrying");
            tokio::time::sleep(empty_backoff).await;
        }
        drain_discovered(peer_rx, pool);
        let slot_estimate = config.current_slot_estimate();
        let wall_period = spec::compute_sync_committee_period(slot_estimate);
        // Start from the committee's own period, NOT the finalized slot's:
        // after a force-rotate the two diverge by one period (see the Java
        // comment in catchUpSyncCommittee).
        let committee_period = processor.store.current_period();
        if wall_period <= committee_period {
            tracing::info!(period = committee_period, "sync committee is current");
            return false;
        }
        *staged = staged.split_off(&committee_period); // drop already-passed periods
        let span = (wall_period - committee_period).min(UPDATES_BATCH_MAX);
        tracing::info!(from_period = committee_period, wall_period, span,
            staged = staged.len(), "catch-up: requesting updates_by_range");

        let lc_servers = client.lc_update_servers().await;
        let peers = pool.candidates(CATCHUP_FANOUT, true, true, &lc_servers);
        if peers.is_empty() {
            tracing::warn!("catch-up: no peers available — retrying after discovery");
            return false;
        }

        // Every peer gets the SAME (committee_period, span) request — the Java
        // attemptCatchUpBatch fan-out, kept deliberately: the prefix period is
        // the whole pipeline's bottleneck, so it must be redundantly requested;
        // any single good response advances it. (A staggered disjoint-range
        // variant was tried live 2026-07-06 and performed WORSE — it made the
        // prefix a single point of failure among mostly-unserving peers.)
        let mut ssz_request = Vec::with_capacity(16);
        ssz_request.extend_from_slice(&committee_period.to_le_bytes());
        ssz_request.extend_from_slice(&span.to_le_bytes());
        let wire = codec::encode_request(&ssz_request);

        let staged_before = staged.len();
        let mut in_flight: FuturesUnordered<_> = peers
            .into_iter()
            .map(|peer| {
                let wire = wire.clone();
                let client = client.clone();
                // Same (period, span) for every peer — see the fan-out comment
                // above. Kept as per-future bindings so the response handler can
                // stay range-agnostic if staggering is ever reintroduced.
                let (sub_from, sub_count) = (committee_period, span);
                async move {
                    let res = client
                        .request_raw(peer.id, peer.addr.clone(), protocols::UPDATES_BY_RANGE, wire)
                        .await;
                    (peer, sub_from, sub_count, res)
                }
            })
            .collect();

        // Collect responses into the staging buffer: chunk i of a response is
        // staged at its request's sub_from + i (responses are consecutive per
        // spec; a peer that violates that just fails verify at apply time).
        // The contiguous prefix is applied AS RESPONSES ARRIVE; the round runs
        // until every sub-range answered or the span is fully staged — with
        // disjoint ranges, stragglers carry periods nobody else was asked for.
        let mut applied = 0usize;
        while let Some((peer, sub_from, sub_count, res)) = in_flight.next().await {
            let raw = match res {
                Ok(raw) => raw,
                Err(e) => {
                    if e == RequestError::UnsupportedProtocol {
                        // Doesn't serve updates_by_range at all — skip in future
                        // batches (Java peersNoLcUpdates). Peer is alive, keep it.
                        pool.mark_no_lc_updates(peer.id);
                        clcache.mark_nolc(&format!("{}/p2p/{}", peer.addr, peer.id));
                    } else if e != RequestError::Shutdown {
                        // Dial/timeout/connection-closed — count toward eviction
                        // so dead peers stop occupying MAX_POOL slots.
                        pool.note_failure(peer.id);
                        clcache.mark_failure(&format!("{}/p2p/{}", peer.addr, peer.id));
                    }
                    tracing::debug!(peer = %peer.id, error = %e, "updates_by_range failed");
                    continue;
                }
            };
            if raw.len() < 64 {
                // Tiny frames are peers closing without serving (0 B) or sending
                // near-empty chunks; dumped verbatim at debug for peer forensics.
                tracing::debug!(peer = %peer.id, raw_len = raw.len(),
                    hex = %raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "small updates_by_range frame");
            }
            let chunks = match codec::decode_multi_chunk_response(&raw, sub_count as usize) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(peer = %peer.id, raw_len = raw.len(), error = %e,
                        "updates_by_range frame invalid");
                    continue;
                }
            };
            let mut served = 0usize;
            for (i, chunk) in chunks.into_iter().enumerate() {
                if chunk.is_empty() {
                    break; // truncated/empty chunk — nothing after it is trustworthy
                }
                served += 1;
                staged.entry(sub_from + i as u64).or_insert(chunk);
            }
            if served > 0 {
                tracing::info!(peer = %peer.id, sub_from, sub_count, served,
                    raw_len = raw.len(), "updates_by_range served");
                pool.mark_proven(peer.id);
                // Deliberately NO cooldown for a peer that just served: it is
                // often the only willing server in the pool, and the ~13 s
                // round cadence sits at Lighthouse's ~1-per-10s quota anyway —
                // the Java client re-asks its serving peer the same way.
                let before_period = processor.store.current_period();
                let (applied_now, verify_rejects) =
                    apply_staged_prefix(processor, staged, slot_estimate);
                if verify_rejects > 0 && resume.poisoned(verify_rejects as u32) {
                    return true; // restored snapshot can't verify anything — re-bootstrap
                }
                if applied_now > 0 {
                    resume.confirm();
                    pool.note_served(peer.id); // BLS-verified and applied
                    // Only VERIFIED periods reach the shared cross-engine
                    // cache: this range just BLS-verified and applied, and
                    // this peer's response is what unblocked it (Java
                    // applyCatchUpResponses records AFTER processUpdate the
                    // same way — never before verification).
                    clcache.record_served(
                        &format!("{}/p2p/{}", peer.addr, peer.id),
                        before_period,
                        before_period + applied_now as u64 - 1,
                    );
                    applied += applied_now;
                    empty_backoff = Duration::from_secs(0);
                    // The fastest serving peer won this round — abandon the
                    // stragglers (identical requests make them redundant) and
                    // start the next round from the advanced period.
                    break;
                }
            } else {
                // Unserving answer — NOW the cooldown applies, so the next
                // round rotates toward peers that might actually serve.
                pool.set_updates_cooldown(peer.id);
                tracing::debug!(peer = %peer.id, sub_from, sub_count, raw_len = raw.len(),
                    "updates_by_range returned no chunks");
            }
        }
        drop(in_flight);

        if applied > 0 {
            tracing::info!(applied, staged = staged.len(),
                period = processor.store.current_period(),
                finalized_slot = processor.store.finalized_slot(),
                "catch-up round applied");
            publish_status(config, client, processor, &*pool, status_tx).await;
            idle_rounds = 0;
        } else if staged.len() > staged_before {
            // No prefix advance yet, but the buffer grew — that's progress
            // toward unblocking the earliest period; keep going.
            tracing::debug!(staged = staged.len(), "catch-up staged new periods");
            idle_rounds = 0;
            empty_backoff = Duration::from_secs(0);
        } else {
            idle_rounds += 1;
            if idle_rounds >= CATCHUP_MAX_IDLE_ROUNDS {
                tracing::warn!(period = processor.store.current_period(), idle_rounds,
                    "catch-up made no progress — returning to the poll loop");
                return false;
            }
            // Grow the pre-round pause 5s → 60s: rapid-fire empty rounds burn
            // server quota and our own peer score; a quiet minute lets rate
            // limiters refill and discovery deliver fresh candidates.
            empty_backoff = if empty_backoff.is_zero() {
                Duration::from_secs(5)
            } else {
                (empty_backoff * 2).min(Duration::from_secs(60))
            };
            tracing::debug!(period = processor.store.current_period(), idle_rounds,
                "catch-up round made no progress — retrying after backoff");
        }
    }
}

/// Verify+apply the contiguous staged prefix: each staged update is decoded
/// and processed in period order, advancing the store's committee period by
/// one per applied update (`force_rotate_if_past_period` on the recorded
/// wall-clock estimate after each — Java `applyCatchUpResponses`). A chunk
/// that fails decode/verify is dropped from the buffer so the next round
/// refetches that period from a different peer.
/// Returns `(applied, verify_rejects)` — verify_rejects counts ONLY updates
/// that decoded fine but failed BLS/Merkle verification (`process_update` →
/// false): that is the resume guard's poison signal, since a corrupt restored
/// committee rejects every well-formed update. Decode failures are NOT
/// counted — a peer sending malformed frames says nothing about our store.
fn apply_staged_prefix(
    processor: &mut LightClientProcessor,
    staged: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    slot_estimate: u64,
) -> (usize, usize) {
    let mut applied = 0usize;
    let mut verify_rejects = 0usize;
    while let Some(chunk) = staged.remove(&processor.store.current_period()) {
        let target_period = processor.store.current_period();
        match LightClientUpdate::decode(&chunk) {
            Ok(update) => {
                if processor.process_update(&update) {
                    applied += 1;
                    processor.store.force_rotate_if_past_period(slot_estimate);
                    tracing::debug!(target_period,
                        finalized_slot = update.finalized_header.beacon.slot,
                        period = processor.store.current_period(),
                        "catch-up update applied");
                } else {
                    verify_rejects += 1;
                    tracing::debug!(target_period,
                        finalized_slot = update.finalized_header.beacon.slot,
                        "catch-up update rejected");
                    break;
                }
            }
            Err(e) => {
                tracing::debug!(target_period, error = %e, "catch-up update decode failed");
                break;
            }
        }
    }
    (applied, verify_rejects)
}

/// One finality-poll pass: try peers until one update verifies and applies —
/// the Java `pollFinalityUpdate` steady-state branch (POLL_FINALITY_PEER_LIMIT=16).
/// Returns true when an update verified AND applied (the resume guard's
/// confirmation signal).
async fn poll_finality(
    client: &ReqRespClient,
    pool: &mut PeerPool,
    processor: &mut LightClientProcessor,
    clcache: &mut crate::clcache::ClPeerCache,
) -> bool {
    let lc_servers = client.lc_update_servers().await;
    let peers = pool.candidates(16, false, false, &lc_servers);
    // Parallel fan-out; first update that verifies AND advances wins.
    let mut in_flight: FuturesUnordered<_> = peers
        .into_iter()
        .map(|peer| {
            let client = client.clone();
            async move {
                // Finality/optimistic requests carry NO body: write nothing,
                // half-close (the empty Vec is the reqresp layer's "write
                // nothing" contract).
                let res = client
                    .request_raw(peer.id, peer.addr.clone(), protocols::FINALITY_UPDATE, Vec::new())
                    .await;
                (peer, res)
            }
        })
        .collect();
    while let Some((peer, res)) = in_flight.next().await {
        let raw = match res {
            Ok(raw) => raw,
            Err(e) => {
                if e != RequestError::Shutdown && e != RequestError::UnsupportedProtocol {
                    pool.note_failure(peer.id);
                    clcache.mark_failure(&format!("{}/p2p/{}", peer.addr, peer.id));
                }
                tracing::debug!(peer = %peer.id, error = %e, "finality_update request failed");
                continue;
            }
        };
        let ssz_payload = match codec::decode_response(&raw, true) {
            Ok(d) => d.ssz_payload,
            Err(e) => {
                tracing::debug!(peer = %peer.id, error = %e, "finality_update frame invalid");
                continue;
            }
        };
        match LightClientFinalityUpdate::decode(&ssz_payload) {
            Ok(update) => {
                // Answered a finality request → alive and useful: clear its
                // failure count so a later blip doesn't drop it prematurely
                // (cache streak too — Java resets on any successful serve).
                pool.mark_proven(peer.id);
                clcache.note_success(&format!("{}/p2p/{}", peer.addr, peer.id));
                if processor.process_finality_update(&update) {
                    pool.note_served(peer.id); // verified against our committee
                    tracing::info!(peer = %peer.id,
                        finalized_slot = processor.store.finalized_slot(),
                        optimistic_slot = processor.store.optimistic_slot(),
                        period = processor.store.current_period(),
                        "finality update applied");
                    return true;
                }
                tracing::debug!(peer = %peer.id,
                    finalized_slot = update.finalized_header.beacon.slot,
                    "finality update did not advance state");
            }
            Err(e) => tracing::debug!(peer = %peer.id, error = %e, "finality update decode failed"),
        }
    }
    false
}

/// Keep the Status we serve to peers in step with verified store state
/// (Java `buildLocalStatusFor` post-bootstrap branch).
fn refresh_local_status(
    config: &ChainConfig,
    processor: &LightClientProcessor,
    local_status: &LocalStatus,
) {
    let store = &processor.store;
    let (Some(finalized), Some(optimistic)) = (store.finalized_header(), store.optimistic_header())
    else {
        return;
    };
    let finalized_root = finalized.beacon.hash_tree_root();
    let (head_slot, head_root) = if optimistic.beacon.slot >= finalized.beacon.slot {
        (optimistic.beacon.slot, optimistic.beacon.hash_tree_root())
    } else {
        (finalized.beacon.slot, finalized_root)
    };
    local_status.set(StatusMessage {
        fork_digest: config.current_fork_digest(),
        finalized_root,
        finalized_epoch: finalized.beacon.slot / config.slots_per_epoch.max(1),
        head_root,
        head_slot,
        earliest_available_slot: 0,
    });
}

/// SYNCED gate: committee period current AND the finalized header within ~5
/// epochs of wall clock (finality itself trails the head by ~2 epochs).
const SYNCED_SLOT_SLACK_EPOCHS: u64 = 5;

async fn publish_status(
    config: &ChainConfig,
    client: &ReqRespClient,
    processor: &LightClientProcessor,
    pool: &PeerPool,
    status_tx: &watch::Sender<SyncStatus>,
) {
    let store = &processor.store;
    let wall_slot = config.current_slot_estimate();
    let wall_period = spec::compute_sync_committee_period(wall_slot);
    let state = if !store.is_initialized() {
        SyncState::Bootstrapping
    } else if wall_period == store.current_period()
        && store.finalized_slot() + SYNCED_SLOT_SLACK_EPOCHS * config.slots_per_epoch >= wall_slot
    {
        SyncState::Synced
    } else {
        SyncState::CatchingUp
    };
    let finalized_root = store
        .finalized_header()
        .map(|h| h.beacon.hash_tree_root())
        .unwrap_or([0u8; 32]);
    let status = SyncStatus {
        state,
        finalized_slot: store.finalized_slot(),
        finalized_root,
        optimistic_slot: store.optimistic_slot(),
        period: store.current_period(),
        peer_count: client.connected_peer_count().await,
        served_peers_last_min: pool.served_last_minute(),
        discv5_table_size: pool
            .discv5_table_size
            .load(std::sync::atomic::Ordering::Relaxed),
    };
    let _ = status_tx.send(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_config_matches_networkconfig_java() {
        let c = ChainConfig::mainnet();
        assert_eq!(c.fork_version, [6, 0, 0, 0]);
        assert_eq!(c.checkpoint_slot, 14_560_000);
        assert_eq!(
            hex_str(&c.checkpoint_root),
            "58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e"
        );
        assert_eq!(
            hex_str(&c.genesis_validators_root),
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
        assert_eq!(c.genesis_time, 1_606_824_023);
        // Checkpoint period 1777 (slot / 8192).
        assert_eq!(spec::compute_sync_committee_period(c.checkpoint_slot), 1777);
        // The live digest the Java computes (verified against jshell).
        assert_eq!(c.current_fork_digest(), [0x8C, 0x9F, 0x62, 0xFE]);
        assert_eq!(c.accepted_fork_digests(), vec![[0x8C, 0x9F, 0x62, 0xFE]]);
        assert_eq!(c.static_peers.len(), 18);
        assert_eq!(c.bootstrap_enrs.len(), 17);
    }

    #[test]
    fn static_peer_parsing() {
        let p = parse_static_peer(
            "/ip4/176.229.58.1/tcp/9001/p2p/16Uiu2HAmHu1BxzrSWg7sN9JyJenC5unK5ntdk5QFYqQdQyyD7x3a",
        )
        .unwrap();
        assert_eq!(p.addr.to_string(), "/ip4/176.229.58.1/tcp/9001");
        assert!(parse_static_peer("/ip4/1.2.3.4/tcp/9000").is_none()); // no peer id
        assert!(parse_static_peer("nonsense").is_none());
    }

    #[test]
    fn peer_pool_rotates_and_respects_no_lc() {
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..4u8 {
            let kp = libp2p::identity::Keypair::generate_secp256k1();
            let id = kp.public().to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.0.{i}/tcp/9000").parse().unwrap());
        }
        assert_eq!(pool.len(), 4);
        // Duplicate add is ignored.
        pool.add(ids[0], "/ip4/10.0.0.9/tcp/9000".parse().unwrap());
        assert_eq!(pool.len(), 4);

        pool.mark_no_lc_updates(ids[1]);
        let c = pool.candidates(4, true, false, &HashSet::new());
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|p| p.id != ids[1]));

        // Preferred peers come first.
        let mut prefer = HashSet::new();
        prefer.insert(ids[3]);
        let c = pool.candidates(2, false, false, &prefer);
        assert_eq!(c[0].id, ids[3]);

        // Never starve: everything marked no-lc still returns candidates.
        for id in &ids {
            pool.mark_no_lc_updates(*id);
        }
        assert!(!pool.candidates(2, true, false, &HashSet::new()).is_empty());
    }

    #[test]
    fn dead_peers_are_evicted_and_slots_freed() {
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let id = libp2p::identity::Keypair::generate_secp256k1()
                .public()
                .to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.0.{i}/tcp/9000").parse().unwrap());
        }
        assert_eq!(pool.len(), 3);

        // Un-proven peer: one terminal failure evicts it and frees its slot +
        // its `known` entry (so discovery may re-add a recovered peer).
        pool.note_failure(ids[0]);
        assert_eq!(pool.len(), 2);
        assert!(!pool.known.contains(&ids[0]));

        // Proven peer: survives transient blips, evicted only past the threshold.
        pool.mark_proven(ids[1]);
        pool.note_failure(ids[1]);
        pool.note_failure(ids[1]);
        assert_eq!(pool.len(), 2, "proven peer kept below threshold");
        pool.note_failure(ids[1]);
        assert_eq!(pool.len(), 1, "proven peer evicted at threshold");

        // A serve resets the failure count: a proven server that blips twice,
        // serves (reset), then blips twice more is still alive — the resets
        // keep it under the threshold.
        pool.mark_proven(ids[2]);
        pool.note_failure(ids[2]);
        pool.note_failure(ids[2]);
        pool.mark_proven(ids[2]); // serve resets the count
        pool.note_failure(ids[2]);
        pool.note_failure(ids[2]);
        assert_eq!(pool.len(), 1, "serve-reset keeps a blippy proven server alive");
    }
}
