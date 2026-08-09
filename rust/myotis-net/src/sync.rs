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
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::el::anchor::ExecAnchor;
use crate::protocols;
use crate::reqresp::{self, LocalStatus, ReqRespClient, RequestError};
use crate::status::{fork_digest, fork_digest_bpo, StatusMessage};

// -------------------------------------------------------------------------
// Chain configuration
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub name: &'static str,
    /// The EL chain id (EIP-155) — threaded into the EVM reads (eth_call /
    /// estimateGas / ENS) so nothing downstream hardcodes a network.
    pub chain_id: u64,
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
    /// Epochs per sync-committee period. 256 everywhere except gnosis (512),
    /// whose 16-slot epochs make `slots_per_epoch * this` land on 8192 anyway —
    /// which is exactly why hardcoding 8192 survived this long. It is a
    /// VERIFICATION input (it picks the committee an update is checked
    /// against), so the wallet is told it and never asks a node for it.
    pub epochs_per_sync_committee_period: u64,
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
    /// Slots per sync-committee period — the geometry every period division uses.
    pub fn slots_per_period(&self) -> u64 {
        self.slots_per_epoch
            .saturating_mul(self.epochs_per_sync_committee_period)
    }

    /// Mainnet — values duplicated verbatim from the Java
    /// `NetworkConfig.MAINNET` (networking/src/main/java/.../NetworkConfig.java).
    /// `MYOTIS_CL_STATIC_PEERS` — REPLACE the pinned light-client-serving peers
    /// for this run, comma-separated `/ip4/../tcp/../p2p/..` multiaddrs.
    ///
    /// The CL twin of `MYOTIS_EL_BOOT_ENODES`, and it exists for the same two
    /// reasons: dialing a serving node that lives on this machine over loopback
    /// instead of hairpinning through the router's NAT, and pointing a wallet at
    /// a *candidate* server — `rust/roost` — before its address is pinned in
    /// this file or published in an ENR. An empty or unset value changes
    /// nothing.
    fn env_static_peers() -> Option<Vec<String>> {
        let raw = std::env::var("MYOTIS_CL_STATIC_PEERS").ok()?;
        let peers: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if peers.is_empty() {
            return None;
        }
        tracing::info!(count = peers.len(), "MYOTIS_CL_STATIC_PEERS overrides the pinned CL peers");
        Some(peers)
    }

    /// Apply any environment overrides. Called by every constructor, so a
    /// network added later cannot silently miss them.
    fn with_env_overrides(mut self) -> Self {
        if let Some(peers) = Self::env_static_peers() {
            self.static_peers = peers;
        }
        // `MYOTIS_CL_DISABLE_DISCV5=1` — drop the discv5 bootstrap ENRs, leaving
        // the static peers as the ONLY way to find a CL peer. This is what makes
        // "can a wallet sync from this one server alone?" an honest question:
        // with discovery on, a wallet that silently syncs from a random public
        // peer looks exactly like one the server is serving properly.
        //
        // Note this pair is strictly stronger than MYOTIS_EL_BOOT_ENODES on its
        // own: pinning peers still leaves discovery as a fallback, while pinning
        // AND disabling discovery lets whoever controls the environment decide
        // the wallet's only source. That is a LIVENESS exposure, not a
        // correctness one — every byte is still verified against the wallet's
        // own anchor, so the worst case is withholding, which surfaces as
        // `beaconNotSynced` rather than a wrong answer. Intended for testing a
        // candidate server; do not set it in a shipped configuration.
        if matches!(std::env::var("MYOTIS_CL_DISABLE_DISCV5").as_deref(), Ok("1") | Ok("true")) {
            tracing::info!("MYOTIS_CL_DISABLE_DISCV5 set — discv5 bootstrap ENRs cleared");
            self.bootstrap_enrs.clear();
        }
        self
    }

    pub fn mainnet() -> Self {
        Self {
            name: "mainnet",
            chain_id: 1,
            // Fulu, activated at slot 13164544 (2025-12-03).
            fork_version: [0x06, 0x00, 0x00, 0x00],
            prior_fork_version: None,
            genesis_validators_root: hex32(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
            genesis_time: 1_606_824_023, // 2020-12-01 12:00:23 UTC
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
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
        .with_env_overrides()
    }

    /// Sepolia — values duplicated verbatim from the Java
    /// `NetworkConfig.SEPOLIA` (networking/src/main/java/.../NetworkConfig.java),
    /// whose sepolia CL wiring landed in PR #192.
    pub fn sepolia() -> Self {
        Self {
            name: "sepolia",
            chain_id: 11_155_111,
            // Fulu on sepolia (0x90000075) — activated at epoch 272640 (2025-10-14).
            fork_version: [0x90, 0x00, 0x00, 0x75],
            // No prior-fork fallback (same rationale as mainnet: stale digests
            // wouldn't help us sync to the current head anyway).
            prior_fork_version: None,
            genesis_validators_root: hex32(
                "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
            ),
            genesis_time: 1_655_733_600, // 2022-06-20 14:00:00 UTC
            seconds_per_slot: 12, // mainnet preset
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            // EIP-7892 BLOB_SCHEDULE — latest active entry on sepolia: BPO2 at
            // epoch 275712, MAX_BLOBS_PER_BLOCK=21 (2025-10-28).
            blob_params_epoch: 275_712,
            blob_params_max_blobs: 21,
            // Copied verbatim from the @checkpoint:sepolia:begin/end region of
            // NetworkConfig.java (slot 10851360, 2026-08-05, period 1324). Like
            // mainnet, `./gradlew refreshSepoliaCheckpoint` rewrites only the Java
            // region — a refresh must be mirrored here by hand until plan PR7.
            //
            // This pin must also stay NEWER than the dedicated serving node's
            // trustedNodeSync point, or that node cannot answer the bootstrap for
            // it (docs/dedicated-sepolia-node.md §5).
            checkpoint_root: hex32(
                "a064b99bb711d152efbc88674dcba50d4e6c1b9151dae0a2e5bfbb7c40bc7cb9",
            ),
            checkpoint_slot: 10_851_360,
            static_peers: SEPOLIA_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
            bootstrap_enrs: SEPOLIA_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
            discv5_port: 0,
            snapshot_path: None,
            cl_peer_cache_path: None,
        }
        .with_env_overrides()
    }

    /// Gnosis Chain — values duplicated verbatim from the Java
    /// `NetworkConfig.GNOSIS`. Its own beacon chain: 5 s slots, 16-slot epochs
    /// (still 8192 slots per sync-committee period: 512 epochs × 16), and a
    /// prior-fork digest fallback (Electra) accepted alongside the Fulu digest.
    pub fn gnosis() -> Self {
        Self {
            name: "gnosis",
            chain_id: 100,
            // Fulu on Gnosis (0x06000064), active since 2026-04-14.
            fork_version: [0x06, 0x00, 0x00, 0x64],
            // Electra — accepted as a discv5 fork-digest fallback.
            prior_fork_version: Some([0x05, 0x00, 0x00, 0x64]),
            genesis_validators_root: hex32(
                "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47",
            ),
            genesis_time: 1_638_993_340, // 2021-12-08 19:55:40 UTC
            seconds_per_slot: 5,
            slots_per_epoch: 16,
            epochs_per_sync_committee_period: 512,
            // EIP-7892: Gnosis has no explicit BLOB_SCHEDULE — clients fold the
            // Electra-baseline params (ELECTRA_FORK_EPOCH=1337856, MAX_BLOBS=2)
            // into the Fulu digest. Yields the live-verified digest 0x3237dab6.
            blob_params_epoch: 1_337_856,
            blob_params_max_blobs: 2,
            // Copied verbatim from the @checkpoint:gnosis:begin/end region of
            // NetworkConfig.java (slot 29460368, 2026-08-09, period 3596).
            // A refresh must be mirrored here by hand until plan PR7.
            //
            // Refreshed so the anchor sits INSIDE the period roost@gnosis can
            // serve. The previous anchor (period 3480) was 116 periods behind,
            // and roost's archive only grows forward from where it started, so
            // no amount of waiting would have closed that gap — a wallet
            // bootstrapping from it got ResourceUnavailable forever.
            //
            // Cross-validated: refreshGnosisCheckpoint could only reach ONE of
            // its three providers (the other two 404), so this root was checked
            // against the local gnosis beacon node, which reached the same slot
            // independently over p2p, and against its finalized checkpoint.
            checkpoint_root: hex32(
                "84f127f4bbb1e733c5607910c2df1d2c0e726e2fab0a4690b66cd07a5c2455bf",
            ),
            checkpoint_slot: 29_460_368,
            static_peers: GNOSIS_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
            bootstrap_enrs: GNOSIS_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
            discv5_port: 0,
            snapshot_path: None,
            cl_peer_cache_path: None,
        }
        .with_env_overrides()
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
        spec::compute_sync_committee_period_with(
            self.current_slot_estimate(),
            self.slots_per_period(),
        )
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

///
/// ORDER LOOKS BACKWARDS AND IS NOT. The literal comes FIRST and the name LAST
/// because the two engines consume the pair differently, and the engine that
/// cannot recover is the one that must end up on the name:
///
///   Rust  — `PeerPool::add` REFRESHES a static peer's address in place (the
///           #322 fix), so for one peer id the LAST entry wins. Statics are
///           un-evictable and roost publishes no ENR, so a stale literal here
///           could never self-heal: no eviction, no rediscovery, undialable
///           until a release. Ending on the name is what makes an address
///           change survivable.
///   Java  — dedupes by multiaddr string and walks the list in order, so it
///           tries the literal first and falls through to the name. A stale
///           literal costs one failed dial, then the name resolves. That is why
///           the "worse" order is harmless there.
///
/// Putting the name first inverts both: Rust would keep the literal (the case
/// that cannot recover) and gain nothing.

/// Pinned sepolia LC-serving peer multiaddrs (Java `NetworkConfig.SEPOLIA.clPeerMultiaddrs`
/// — keep the two lists, their ORDER and their addresses in step;
/// `sepolia_config_matches_networkconfig_java` pins this side, and the Java
/// `NetworkConfigGnosisTest` pins that one).
///
/// First is roost, the dedicated light-client server. The per-entry comments below
/// carry the reasoning and each entry's own stability caveat.
const SEPOLIA_STATIC_PEERS: &[&str] = &[
    // roost, the dedicated light-client server (rust/roost, docs/lc-server-design.md).
    // FIRST on purpose: it exists because a general-purpose beacon node is
    // structurally bad at serving wallets — one connection semaphore shared
    // between inbound and outbound, and a trimmer that drops light clients
    // first. Nimbus stays below it, so a roost fault degrades to exactly
    // today's behaviour rather than to nothing.
    //
    // Its peer id comes from /data/roost/sepolia.key and is stable across
    // restarts by construction; unlike the Nimbus entry there is no flag to
    // forget, because roost has no mode in which it mints a fresh one.
    //
    // Pinning a literal IP has the same exposure as the entries below: the line
    // is residential and the address is not guaranteed stable. ENR publication
    // (design §7) is what removes it. See ROOST_PIN_ORDER above for why the
    // literal precedes the name.
    // roost BY NAME, ahead of its own literal IP.
    //
    // The line is residential and the address is not guaranteed stable; the
    // name is DynDNS with a ~30s TTL and libp2p resolves it AT DIAL TIME, every
    // dial, so an address change costs one failed dial instead of a release.
    //
    // The literal below is kept deliberately as the next entry: DNS resolution
    // is verified working on the RUST engine (live sync from roost over this
    // name) but NOT on the Java one, which is the default — jvm-libp2p parses
    // the multiaddr and extracts the peer id, but its transport's DNS handling
    // is unverified. If it cannot dial a name it falls through to the IP and
    // behaves exactly as before. Drop the literal once Java is confirmed.
    "/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5",
    "/ip4/87.154.209.161/tcp/9104/p2p/16Uiu2HAkvYx58piGw1oxz34CUoeTv8nNQwTwE2cZZh4jR4wVMYy6",
    "/ip4/18.185.193.198/tcp/9000/p2p/16Uiu2HAm3mfkjmLPtqnSJzNtKxbDuVjVRXidz5UinaZNpjCCKAkS",
];

/// Sepolia CL discv5 bootstrap ENRs (Java `NetworkConfig.SEPOLIA.clDiscv5Bootnodes` —
/// mirrors eth-clients/sepolia metadata/bootstrap_nodes.yaml: EF, Teku, Lodestar).
const SEPOLIA_BOOTSTRAP_ENRS: &[&str] = &[
    // EF
    "enr:-Ku4QDZ_rCowZFsozeWr60WwLgOfHzv1Fz2cuMvJqN5iJzLxKtVjoIURY42X_YTokMi3IGstW5v32uSYZyGUXj9Q_IECh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIpEe5iJc2VjcDI1NmsxoQNHTpFdaNSCEWiN_QqT396nb0PzcUpLe3OVtLph-AciBYN1ZHCCIy0",
    "enr:-Ku4QHRyRwEPT7s0XLYzJ_EeeWvZTXBQb4UCGy1F_3m-YtCNTtDlGsCMr4UTgo4uR89pv11uM-xq4w6GKfKhqU31hTgCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIrFM7WJc2VjcDI1NmsxoQI4diTwChN3zAAkarf7smOHCdFb1q3DSwdiQ_Lc_FdzFIN1ZHCCIy0",
    "enr:-Ku4QOkvvf0u5Hg4-HhY-SJmEyft77G5h3rUM8VF_e-Hag5cAma3jtmFoX4WElLAqdILCA-UWFRN1ZCDJJVuEHrFeLkDh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhJK-AWeJc2VjcDI1NmsxoQLFcT5VE_NMiIC8Ll7GypWDnQ4UEmuzD7hF_Hf4veDJwIN1ZHCCIy0",
    "enr:-Ku4QH6tYsHKITYeHUu5kdfXgEZWI18EWk_2RtGOn1jBPlx2UlS_uF3Pm5Dx7tnjOvla_zs-wwlPgjnEOcQDWXey51QCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIs7Mc6Jc2VjcDI1NmsxoQIET4Mlv9YzhrYhX_H9D7aWMemUrvki6W4J2Qo0YmFMp4N1ZHCCIy0",
    "enr:-Ku4QDmz-4c1InchGitsgNk4qzorWMiFUoaPJT4G0IiF8r2UaevrekND1o7fdoftNucirj7sFFTTn2-JdC2Ej0p1Mn8Ch2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhKpA-liJc2VjcDI1NmsxoQMpHP5U1DK8O_JQU6FadmWbE42qEdcGlllR8HcSkkfWq4N1ZHCCIy0",
    // Teku
    "enr:-Iu4QKvMF7Ne_RSQoZGvavTuZ1QA5_Pgeb0nq_hrjhU8s0UDV3KhcMXJkGwOWhsDGZL3ISjL0CTP-hfoTjZtEtCEwR4BgmlkgnY0gmlwhAOAaySJc2VjcDI1NmsxoQNta5b_bexSSwwrGW2Re24MjfMntzFd0f2SAxQtMj3ueYN0Y3CCIyiDdWRwgiMo",
    // Lodestar
    "enr:-KG4QJejf8KVtMeAPWFhN_P0c4efuwu1pZHELTveiXUeim6nKYcYcMIQpGxxdgT2Xp9h-M5pr9gn2NbbwEAtxzu50Y8BgmlkgnY0gmlwhEEVkQCDaXA2kCoBBPnAEJg4AAAAAAAAAAGJc2VjcDI1NmsxoQLEh_eVvk07AQABvLkTGBQTrrIOQkzouMgSBtNHIRUxOIN1ZHCCIyiEdWRwNoIjKA",
    // remaining bootstrap_nodes.yaml entries (unattributed)
    "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
    "enr:-L64QC9Hhov4DhQ7mRukTOz4_jHm4DHlGL726NWH4ojH1wFgEwSin_6H95Gs6nW2fktTWbPachHJ6rUFu0iJNgA0SB2CARqHYXR0bmV0c4j__________4RldGgykDb6UBOQAABx__________-CaWSCdjSCaXCEA-2vzolzZWNwMjU2azGhA17lsUg60R776rauYMdrAz383UUgESoaHEzMkvm4K6k6iHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo",
];

/// Pinned Gnosis LC-serving peer multiaddrs (Java `NetworkConfig.GNOSIS.clPeerMultiaddrs`
/// — keep the two lists and their ORDER in step). Identify-confirmed LC servers
/// harvested from a long-running desktop profile's cl-peers-gnosis.cache
/// (2026-08-06, issue #291): a cold Gnosis pool starves catch-up because so few
/// nodes serve light-client data, so a fresh install gets a serving head start.
/// One address per peer id: `PeerPool::add` dedupes by peer id, so a second
/// address for an already-known id would be silently dropped here (Java dedupes
/// by multiaddr string and would dial both) — keeping the lists identical means
/// keeping them one-per-id.
const GNOSIS_STATIC_PEERS: &[&str] = &[
    // roost gnosis. Same reasoning as the other two chains; see
    // MAINNET_STATIC_PEERS. 9108/tcp verified forwarded before pinning (hairpin
    // connect showing the public IP as the source address).
    //
    // Gnosis is the chain where roost's fork digest had to be FIXED before this
    // pin was safe: BLOB_SCHEDULE is empty here, so roost stamped the bare Fulu
    // digest and every peer answered Goodbye(IrrelevantNetwork). Pinning a
    // server in that state would have cost every gnosis wallet its
    // strikes-to-eviction on a peer that could never answer.
    "/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9108/p2p/16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh",
    "/ip4/104.37.190.86/tcp/15974/p2p/16Uiu2HAky9pZH5QBGwtPgXm3A58ahKLSuuUJbZpreBMZrmksUW59",
    "/ip4/134.65.194.144/tcp/9500/p2p/16Uiu2HAmLZasEWSgafRb5hqW5M2jSN7YcERyVQ81AeCGCFZmynsQ",
    "/ip4/135.129.103.34/tcp/9006/p2p/16Uiu2HAmA5FYL7dQftsHktHvuVTRyPdc1sH6qcWiXaVEPM6FMyN2",
    "/ip4/135.148.35.18/tcp/9000/p2p/16Uiu2HAm5g8koS1AgicyMZKekLoyh5rK3eBGoZJP5KUsoK5wcehs",
    "/ip4/136.243.146.247/tcp/9000/p2p/16Uiu2HAmEFCgE5gLHQRHNMv1P1R673849q7cgH7S3WJBXTkg5698",
    "/ip4/138.201.196.44/tcp/4001/p2p/16Uiu2HAmFXPBdWLwQQSLpXhvSAzUfRErcH1whnq3SuPE5dRmojAT",
    "/ip4/141.94.46.9/tcp/4001/p2p/16Uiu2HAmBCpdwswdk1wdzZH4gkhPtytx1Jt8GfSjgNsgPdPHUW67",
    "/ip4/144.76.106.139/tcp/9200/p2p/16Uiu2HAm4B91Fn21jnSPKw58R46THxhp1ZTHmTWU1TDWvNpJySRB",
    "/ip4/144.76.118.19/tcp/9000/p2p/16Uiu2HAmEJpzjSyajPJzzrN8TnV1VaNMaEecQo1v4Mkedwb6UYwE",
    "/ip4/144.76.163.174/tcp/9000/p2p/16Uiu2HAkxLFxkn7MbAPH17VdwEvXytqgteNAr52AaqKYuEmsw2bt",
    "/ip4/144.76.164.21/tcp/9016/p2p/16Uiu2HAm2UAjrJax6SAtu53VykpbmPrzDDdfB3G79ypQeiXnjj3u",
    "/ip4/144.76.196.184/tcp/13000/p2p/16Uiu2HAm6wUQPL4FYKHqmGfZQBPYbDd8GNHxNYeH5DZGLunPAw4J",
    "/ip4/146.103.38.79/tcp/4101/p2p/16Uiu2HAmKnRLFoU3QMX3zkTZLRv5mG8FBp4qfZpGJYuT3LAErt11",
    "/ip4/146.70.243.142/tcp/9000/p2p/16Uiu2HAm6uE18CuSgCEi5LyjxvbEXdZFQHv1HJCad3WpqerJfDrE",
    "/ip4/148.251.181.49/tcp/9000/p2p/16Uiu2HAmAWrwxf2murYQp1tdbwKbFwqUiVofwJ3xgJP5T7BLSpRa",
    "/ip4/148.251.184.20/tcp/15974/p2p/16Uiu2HAmQYoJ6Gn5caze4BAZXMQ5CJX5qZbdkY3o7S23vvSAPLu9",
    "/ip4/148.251.235.60/tcp/9001/p2p/16Uiu2HAmTeAHEG2tCFgC5RmrjZcw6zGeCgnE5svqM4528R5inSjA",
    "/ip4/148.251.237.209/tcp/9000/p2p/16Uiu2HAmSLirTFzTcPE9wsHE6UhbXXmDxFkunHDVhPtrBfuPMq5U",
    "/ip4/148.56.243.210/tcp/9000/p2p/16Uiu2HAkyQr5e7gobYTAutAoCDR6ZKEMrgmsChUztDkw2fQTiYL4",
    "/ip4/159.195.138.9/tcp/9000/p2p/16Uiu2HAmUimXaHiCvWhx2YuvwTkDLtca6oq1bCH85Eb6JcEYiaGi",
    "/ip4/159.195.30.80/tcp/9100/p2p/16Uiu2HAmDMWLqML5zdVVVuptjpfKAZi1qEb784HFtrqyJZGPFL3X",
    "/ip4/164.152.161.131/tcp/9500/p2p/16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw",
];

/// Gnosis CL discv5 bootstrap ENRs (Java `NetworkConfig.GNOSIS.clDiscv5Bootnodes`
/// — gnosischain/configs bootstrap_nodes.txt).
const GNOSIS_BOOTSTRAP_ENRS: &[&str] = &[
    "enr:-Ly4QIAhiTHk6JdVhCdiLwT83wAolUFo5J4nI5HrF7-zJO_QEw3cmEGxC1jvqNNUN64Vu-xxqDKSM528vKRNCehZAfEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhEFtZ5SJc2VjcDI1NmsxoQJwgL5C-30E8RJmW8gCb7sfwWvvfre7wGcCeV4X1G2wJYhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    "enr:-Ly4QDhEjlkf8fwO5uWAadexy88GXZneTuUCIPHhv98v8ZfXMtC0S1S_8soiT0CMEgoeLe9Db01dtkFQUnA9YcnYC_8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhEFtZ5WJc2VjcDI1NmsxoQMRSho89q2GKx_l2FZhR1RmnSiQr6o_9hfXfQUuW6bjMohzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    "enr:-Ly4QLKgv5M2D4DYJgo6s4NG_K4zu4sk5HOLCfGCdtgoezsbfRbfGpQ4iSd31M88ec3DHA5FWVbkgIas9EaJeXia0nwBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhI1eYRaJc2VjcDI1NmsxoQLpK_A47iNBkVjka9Mde1F-Kie-R0sq97MCNKCxt2HwOIhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    "enr:-Ly4QF_0qvji6xqXrhQEhwJR1W9h5dXV7ZjVCN_NlosKxcgZW6emAfB_KXxEiPgKr_-CZG8CWvTiojEohG1ewF7P368Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhI1eYUqJc2VjcDI1NmsxoQIpNRUT6llrXqEbjkAodsZOyWv8fxQkyQtSvH4sg2D7n4hzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    "enr:-Ly4QCD5D99p36WafgTSxB6kY7D2V1ca71C49J4VWI2c8UZCCPYBvNRWiv0-HxOcbpuUdwPVhyWQCYm1yq2ZH0ukCbQBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhI1eYVSJc2VjcDI1NmsxoQJJMSV8iSZ8zvkgbi8cjIGEUVJeekLqT0LQha_co-siT4hzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    "enr:-KK4QKXJq1QOVWuJAGige4uaT8LRPQGCVRf3lH3pxjaVScMRUfFW1eiiaz8RwOAYvw33D4EX-uASGJ5QVqVCqwccxa-Bi4RldGgykCGm-DYDAABk__________-CaWSCdjSCaXCEM0QnzolzZWNwMjU2azGhAhNvrRkpuK4MWTf3WqiOXSOePL8Zc-wKVpZ9FQx_BDadg3RjcIIjKIN1ZHCCIyg",
    "enr:-LO4QO87Rn2ejN3SZdXkx7kv8m11EZ3KWWqoIN5oXwQ7iXR9CVGd1dmSyWxOL1PGsdIqeMf66OZj4QGEJckSi6okCdWBpIdhdHRuZXRziAAAAABgAAAAhGV0aDKQPr_UhAQAAGT__________4JpZIJ2NIJpcIQj0iX1iXNlY3AyNTZrMaEDd-_eqFlWWJrUfEp8RhKT9NxdYaZoLHvsp3bbejPyOoeDdGNwgiMog3VkcIIjKA",
    "enr:-LK4QIJUAxX9uNgW4ACkq8AixjnSTcs9sClbEtWRq9F8Uy9OEExsr4ecpBTYpxX66cMk6pUHejCSX3wZkK2pOCCHWHEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpA-v9SEBAAAZP__________gmlkgnY0gmlwhCPSnDuJc2VjcDI1NmsxoQNuaAjFE-ANkH3pbeBdPiEIwjR5kxFuKaBWxHkqFuPz5IN0Y3CCIyiDdWRwgiMo",
];

/// Known light-client-serving mainnet peers — the Java `NetworkConfig.MAINNET`
/// clPeerMultiaddrs list (nimbus/lodestar/lighthouse, discovered 2026-03-11).
const MAINNET_STATIC_PEERS: &[&str] = &[
    // roost mainnet (rust/roost). FIRST for the same reason as sepolia: a
    // general-purpose beacon node shares one connection semaphore between
    // inbound and outbound and trims light clients first, so the peers below
    // are structurally unreliable for us in a way roost is not. Identity comes
    // from /data/roost/mainnet.key and is stable by construction.
    //
    // 9109/tcp was confirmed forwarded before this was pinned (hairpin connect
    // showing the public IP as the source address, plus 145 inbound peers on
    // the neighbouring 9107). Pinning an unreachable address is not free — a
    // wallet spends its strikes-to-eviction on a node that is actually fine.
    //
    // Same residential-IP exposure as every literal here; ENR publication
    // (docs/lc-server-design.md §7) is what removes it. NOTE that roost cannot
    // currently notice its own IP changing — its Identify quorum never settles
    // because it makes no outbound connections — so this line is the thing that
    // breaks if the address moves.
    "/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9109/p2p/16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
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
    /// Period this run's catch-up started from; -1 until bootstrap/resume.
    pub sync_start_period: i64,
    /// LC hunt engaged (starved of light-client servers — see hunt_due).
    pub hunting: bool,
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
            sync_start_period: -1,
            hunting: false,
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
    /// The CL→EL bridge: the verified beacon loop feeds finalized/optimistic
    /// execution into this, and the EL verified-read ladder reads it.
    exec_anchor: Arc<ExecAnchor>,
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
            // Shared with run_sync's hunt trigger; discovery re-spawns reuse
            // the same flag, so a boost survives a discv5 restart.
            hunt_boost: Arc::new(AtomicBool::new(false)),
        };

        let exec_anchor = Arc::new(ExecAnchor::new());
        let sync_task = tokio::spawn(run_sync(
            config,
            client.clone(),
            local_status,
            status_tx,
            discovery_cfg,
            Arc::clone(&exec_anchor),
        ));

        Ok(SyncHandle { status_rx, client, tasks: vec![sync_task], exec_anchor })
    }

    /// The EL execution anchor fed by this beacon sync loop — the CL→EL trust
    /// bridge the verified-read ladder anchors against (finalized/optimistic
    /// execution + the BLS-attested state-root window).
    pub fn exec_anchor(&self) -> Arc<ExecAnchor> {
        Arc::clone(&self.exec_anchor)
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
    /// Pinned static (config) peers — the curated LC-serving set
    /// (`ChainConfig::static_peers`, e.g. the #302 Gnosis list). Loaded once at
    /// startup and NEVER re-added from any other source, so they must never be
    /// permanently evicted: a single transient failure used to drop them for
    /// the whole process lifetime, draining the scarce LC pool on Gnosis with
    /// nothing to bring them back (issue #291). The Java engine keeps
    /// re-seeding its pinned list; we keep these entries un-evictable instead
    /// (the set is a handful of ids — bounded either way).
    static_ids: HashSet<PeerId>,
    /// Peers proven NOT to serve light_client_updates_by_range (protocol
    /// negotiation failed) — mirrors the Java `peersNoLcUpdates`. REVERSIBLE:
    /// an authoritative positive signal (Identify advertising the protocol, or
    /// a fresh verified serve) clears the flag via `clear_no_lc`/`mark_proven`,
    /// exactly like the Java classification sweep's `peersNoLcUpdates.remove`
    /// (BeaconLightClient.java). Without that reversal a peer that returned
    /// `UnsupportedProtocol` once — which a busy Lighthouse/Nimbus emits
    /// transiently when it throttles or resets a new substream — was condemned
    /// to nolc for the process lifetime, excluded from every catch-up tier AND
    /// from hunt re-probing, and never dialed again so never evicted: the
    /// #291 "previously-LC nodes went nolc and stayed there" zero-peer stall.
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
    /// Period this run's catch-up started from (bootstrap checkpoint or
    /// resumed snapshot); -1 until known. Drives the UI's determinate
    /// progress bar ((current-start)/(target-start)) — without it the bar
    /// spins forever even though current/target are displayed. Same
    /// travels-with-the-pool rationale as discv5_table_size.
    sync_start_period: i64,
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
            static_ids: HashSet::new(),
            no_lc_updates: HashSet::new(),
            proven: HashSet::new(),
            cooldown_until: HashMap::new(),
            fail_counts: HashMap::new(),
            recent_serves: HashMap::new(),
            discv5_table_size: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            sync_start_period: -1,
            sweep: 0,
        }
    }

    fn mark_proven(&mut self, id: PeerId) {
        self.proven.insert(id);
        self.fail_counts.remove(&id); // a served peer is demonstrably alive
        // A peer that just served light-client data is, by definition, not a
        // non-server: clear any stale nolc verdict so it rejoins the normal
        // catch-up tiers (issue #291 — the deny set must be reversible, or one
        // transient UnsupportedProtocol permanently blacklists an LC server
        // that is now demonstrably serving us). Mirrors Java line
        // `peersNoLcUpdates.remove(ma) | provenLightClient.add(ma)`.
        self.no_lc_updates.remove(&id);
    }

    /// Reconcile the LIVE Identify LC-capability signal into the deny set: any
    /// peer whose Identify currently advertises `light_client_updates_by_range`
    /// has its nolc flag cleared. Returns the ids actually cleared so the caller
    /// can persist the same reversal to the shared cache (keeping pool and cache
    /// from disagreeing — PR #322 review). The Java classification sweep does
    /// exactly this every cycle (BeaconLightClient.java); without it the Rust
    /// engine's Identify verdict fed a SEPARATE prefer set that never un-did an
    /// earlier request-time nolc strike, so an Identify-confirmed server could
    /// sit in `no_lc_updates` forever, filtered out of every catch-up tier
    /// (issue #291).
    ///
    /// Callers reconcile against the Identify set ONLY — deliberately not the
    /// hunt-confirmed set. Hunt confirmation attests to `light_client_finality_
    /// update`, a DIFFERENT protocol from the one nolc tracks, and that set is
    /// never pruned for the process lifetime; reconciling against it would make
    /// one decodable finality response permanently immune a peer to the
    /// updates_by_range denial it may genuinely deserve (PR #322 review).
    fn clear_no_lc(&mut self, servers: &HashSet<PeerId>) -> Vec<PeerId> {
        if self.no_lc_updates.is_empty() || servers.is_empty() {
            return Vec::new();
        }
        let cleared: Vec<PeerId> = self.no_lc_updates.intersection(servers).copied().collect();
        for id in &cleared {
            self.no_lc_updates.remove(id);
        }
        cleared
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
        if self.static_ids.contains(id) {
            // A pinned LC server is never dropped (issue #291): nothing would
            // re-add it, so evicting it on a transient blip permanently loses a
            // curated server. Clear only its transient FAILURE state so a later
            // recovery starts clean, and keep it in the pool. Deliberately does
            // NOT touch cooldown_until: that is the UPDATES_SERVE_COOLDOWN
            // rotation mark (the LC serve quota), not failure state — wiping it
            // on a failure would re-admit the peer to the next respect_cooldown
            // batch inside its quota window and risk a rate-limit/peer-score
            // penalty from the very servers we want to keep (PR #322 review).
            self.fail_counts.remove(id);
            return;
        }
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
        if self.known.contains(&id) {
            // Already pooled. Refresh a pinned static peer's address in place:
            // it is un-evictable, so removal-then-rediscovery (the path an
            // ordinary peer self-heals an IP change through) never runs for it.
            // The 22 Gnosis statics are hardcoded /ip4/…; when an operator moves
            // (same node key, new address) discovery re-reports the same PeerId
            // at the current address, and without this refresh the entry would
            // be dialed at the stale address for the process lifetime (PR #322
            // review). `add()` used to keep the first multiaddr and drop later
            // ones — that still holds for ordinary peers, which self-heal via
            // evict→rediscover.
            if self.static_ids.contains(&id) {
                if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
                    p.addr = addr;
                }
            }
            return;
        }
        if self.peers.len() >= MAX_POOL {
            return;
        }
        self.known.insert(id);
        self.peers.push(Peer { id, addr });
    }

    /// Whether `id` is a pinned static (config) peer.
    fn is_static(&self, id: &PeerId) -> bool {
        self.static_ids.contains(id)
    }

    /// The shared-cache key (`{addr}/p2p/{id}`) for a pooled peer, if present —
    /// so a caller reversing an in-memory denial can persist the same reversal
    /// to the cross-engine cache under the exact key it was written with.
    fn cache_key(&self, id: &PeerId) -> Option<String> {
        self.peers.iter().find(|p| &p.id == id).map(|p| format!("{}/p2p/{}", p.addr, p.id))
    }

    /// Add a pinned static (config) peer and record its id as un-evictable
    /// (see `static_ids`). Same dedup/cap semantics as `add`.
    fn add_static(&mut self, id: PeerId, addr: Multiaddr) {
        self.add(id, addr);
        // Mark un-evictable ONLY once the peer is actually pooled, so the
        // invariant static_ids ⊆ peers holds: `add` is a no-op past MAX_POOL,
        // and marking an unpooled id un-evictable would make it permanently
        // un-evictable while absent. `known` is exactly the set of pooled ids.
        if self.known.contains(&id) {
            self.static_ids.insert(id);
        }
    }

    fn mark_no_lc_updates(&mut self, id: PeerId) {
        // Never deny a curated static peer (issue #291). They are pinned
        // precisely because they serve light-client data, AND they are
        // un-evictable — but eviction is the path that clears the deny flag for
        // an ordinary peer. So a nolc strike on a static peer (a transient
        // `UnsupportedProtocol` under load, or a stale nolc flag replayed from
        // the peer cache at startup) would be STICKY, recreating the very "went
        // nolc and stayed there" wedge this change removes — scoped to the
        // scarce curated set that matters most. Skipping the mark keeps them in
        // every catch-up/finality tier; capability is still reconciled live
        // from Identify via the prefer set.
        if self.static_ids.contains(&id) {
            return;
        }
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
        skip: &HashSet<PeerId>,
    ) -> Vec<Peer> {
        if self.peers.is_empty() {
            return Vec::new();
        }
        let ok = |pool: &Self, id: &PeerId| {
            !skip.contains(id)
                && (!skip_no_lc || !pool.no_lc_updates.contains(id))
                && (!respect_cooldown || pool.cooled_down(id))
        };
        let mut out: Vec<Peer> = Vec::with_capacity(n);
        // Tier 1: peers that actually served light-client data before —
        // most-recently-served first (recent_serves already backs the
        // served-last-minute metric). A server that answered seconds ago is
        // almost certainly still good, so a bounded batch always contains it
        // even when the proven set outgrows `n` and carries servers that are
        // flagged capable but currently at capacity. Never-served proven
        // peers keep their pool order after the recent ones (stable sort).
        let mut tier1: Vec<&Peer> = self
            .peers
            .iter()
            .filter(|p| self.proven.contains(&p.id) && ok(self, &p.id))
            .collect();
        tier1.sort_by_key(|p| std::cmp::Reverse(self.recent_serves.get(&p.id).copied()));
        for p in tier1 {
            if out.len() >= n {
                break;
            }
            if !out.iter().any(|q| q.id == p.id) {
                out.push(p.clone());
            }
        }
        // Tier 2: positive-signal peers (Identify-confirmed LC servers).
        for p in &self.peers {
            if out.len() >= n {
                break;
            }
            if prefer.contains(&p.id) && ok(self, &p.id) && !out.iter().any(|q| q.id == p.id) {
                out.push(p.clone());
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
            // Never starve the batch on the SOFT filters (Java: `if
            // (capable.isEmpty()) capable = peers`) — a no-lc/cooled peer may
            // still serve. Sweep the fallback too, so consecutive drought
            // rounds spread the retries across the pool instead of
            // re-hammering the first few.
            let start = self.sweep % self.peers.len();
            self.sweep = self.sweep.wrapping_add(n);
            for i in 0..self.peers.len() {
                if out.len() >= n {
                    break;
                }
                let p = &self.peers[(start + i) % self.peers.len()];
                if !skip.contains(&p.id) {
                    out.push(p.clone());
                }
            }
        }
        if out.is_empty() {
            // LAST RESORT: `skip` too. It used to be honored even here, on the
            // theory that a too-shallow peer is "provably incapable" of the
            // needed period — but the evidence behind it is weaker than that
            // (issue #291). `skip` is built from `earliest_available_slot`,
            // which is the peer's BLOCK/data-availability floor, not its
            // light-client-update floor: LC updates are a separate, tiny store
            // (one best update per period), and a checkpoint-synced node that
            // pruned blocks below its checkpoint still answers
            // `light_client_updates_by_range` well beneath that floor. On a
            // pool where nearly every node is checkpoint-synced (Gnosis), the
            // filter condemned the WHOLE pool once the auto-Status replies had
            // landed — including Tier-1 peers that had just served us — and
            // catch_up bounced to rediscovery forever while the data was
            // plainly available network-wide. Java never had this failure mode
            // because its guard drops every filter. Asking a maybe-incapable
            // peer costs one round; returning [] costs the whole sync.
            let start = self.sweep % self.peers.len();
            self.sweep = self.sweep.wrapping_add(n);
            for i in 0..self.peers.len() {
                if out.len() >= n {
                    break;
                }
                out.push(self.peers[(start + i) % self.peers.len()].clone());
            }
        }
        out
    }

    /// Up to `n` LC-hunt candidates from the UNPROVEN pool tail: skips the
    /// proven tier (the regular finality fan-out already covers it), proven
    /// non-servers, and peers probed within the re-probe window. Rotates via
    /// the same sweep offset as [`Self::candidates`], so consecutive hunt
    /// rounds walk different pool regions instead of re-hammering the head.
    fn explore_candidates(
        &mut self,
        n: usize,
        probed: &HashMap<PeerId, Instant>,
        reprobe: Duration,
    ) -> Vec<Peer> {
        if self.peers.is_empty() {
            return Vec::new();
        }
        let now = Instant::now();
        let fresh = |id: &PeerId| {
            probed.get(id).is_none_or(|t| now.saturating_duration_since(*t) >= reprobe)
        };
        let mut out: Vec<Peer> = Vec::with_capacity(n);
        let start = self.sweep % self.peers.len();
        self.sweep = self.sweep.wrapping_add(n);
        for i in 0..self.peers.len() {
            if out.len() >= n {
                break;
            }
            let p = &self.peers[(start + i) % self.peers.len()];
            if self.proven.contains(&p.id)
                || self.no_lc_updates.contains(&p.id)
                || !fresh(&p.id)
            {
                continue;
            }
            out.push(p.clone());
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
    anchor: Arc<ExecAnchor>,
) {
    let mut pool = PeerPool::new();
    for s in &config.static_peers {
        match parse_static_peer(s) {
            Some(p) => pool.add_static(p.id, p.addr),
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
        LightClientStore::new(config.slots_per_period()),
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
    let mut staged_updates: std::collections::BTreeMap<u64, StagedChunk> =
        std::collections::BTreeMap::new();

    // Resume from the persisted snapshot when it is bound to this chain AND
    // strictly newer than the embedded checkpoint (the snapshot was produced
    // from our own BLS-verified store, so resuming is strictly less long-range
    // exposure than re-bootstrapping — same rule as the Java engine, which
    // reads/writes the identical file). Anything else → fresh bootstrap. A
    // restored store stays on probation (ResumeGuard) until one update
    // BLS-verifies against it; see RESUME_REJECTS_MAX.
    let checkpoint_period =
        spec::compute_sync_committee_period_with(config.checkpoint_slot, config.slots_per_period());
    let mut in_catchup = false;
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
                    publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, false).await;
                }
                Some(_) => tracing::info!(
                    "persisted snapshot not newer than the embedded checkpoint — bootstrapping fresh"),
                None => tracing::warn!(
                    "persisted snapshot unreadable/foreign — bootstrapping fresh"),
            }
        }
    }

    // LC hunt state: engaged whenever the chain is starved of light-client
    // servers (bootstrap stall, starved catch-up, or finality starvation —
    // see hunt_due). While engaged, discovery lookups run boosted and each
    // cycle burst-probes the unproven pool tail; confirmations persist into
    // the CL peer cache so the next start dials them first.
    let sync_started = Instant::now();
    let mut hunt_probed: HashMap<PeerId, Instant> = HashMap::new();
    let mut hunt_confirmed: HashSet<PeerId> = HashSet::new();
    let mut hunting = false;
    // Store-progress tracking for the starved-catch-up trigger: any advance
    // of (period, finalized slot) resets the stall clock.
    let mut last_progress = Instant::now();
    let mut last_seen_progress = (0u64, 0u64);

    // One loop for all phases: bootstrap (when the store isn't initialized —
    // fresh start OR after a poisoned resume was discarded), catch-up when
    // behind, finality polling in steady state.
    loop {
        drain_discovered(&mut peer_rx, &mut pool);

        let seen = (processor.store.current_period(), processor.store.finalized_slot());
        if seen != last_seen_progress {
            last_seen_progress = seen;
            last_progress = Instant::now();
        }
        let hunt_now = hunt_due(
            hunting,
            processor.store.is_initialized(),
            sync_started.elapsed(),
            last_progress.elapsed(),
            config.current_slot_estimate(),
            processor.store.current_period(),
            processor.store.finalized_slot(),
            config.slots_per_epoch,
            config.slots_per_period(),
        );
        if hunt_now != hunting {
            hunting = hunt_now;
            discovery_cfg.hunt_boost.store(hunting, Ordering::Relaxed);
            if hunting {
                tracing::info!(pool = pool.len(),
                    "LC hunt engaged — starved of light-client servers \
                     (boosted discovery + unproven-tail probing)");
            } else {
                tracing::info!(confirmed = hunt_confirmed.len(), "LC hunt disengaged");
            }
        }

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
            // Hunting widens the bootstrap fan-out and prefers hunt-confirmed
            // LC servers (a peer that answered ANY light-client request is the
            // best bootstrap bet in a starved pool).
            let fanout = if hunting { 16 } else { 8 };
            let bootstrapped = try_bootstrap(&config, &client, &mut pool, &mut processor,
                &mut clcache, fanout, &hunt_confirmed)
                .await;
            clcache.flush(); // one write per attempt round, win or lose
            if bootstrapped {
                persist_snapshot(&config, &processor, &mut last_persisted_period);
                refresh_local_status(&config, &processor, &local_status);
                publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunting).await;
            } else {
                if hunting {
                    // Pre-bootstrap the finality probe still classifies: a
                    // decodable response marks the peer lc-confirmed (it can't
                    // APPLY without a committee, and that's fine — the confirm
                    // feeds the next bootstrap round's prefer tier).
                    hunt_round(&client, &mut pool, &mut processor, &mut clcache,
                        &mut hunt_probed, &mut hunt_confirmed)
                        .await;
                    clcache.flush();
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        let wall_period = config.wall_clock_period();
        if wall_period > processor.store.current_period() {
            // Baseline the progress bar at every catch-up ENTRY (not just
            // bootstrap/resume): a process that reached SYNCED and re-enters
            // catch-up after a doze must start its bar at 0%, not at the
            // fraction left over from the previous run's baseline.
            if !in_catchup {
                in_catchup = true;
                pool.sync_start_period = processor.store.current_period() as i64;
            }
            let poisoned = catch_up(&config, &client, &mut pool, &mut processor, &status_tx,
                &mut peer_rx, &mut staged_updates, &mut clcache, &mut resume,
                &mut last_persisted_period, &anchor, &hunt_confirmed, hunting)
                .await;
            // Batch-persist every cache verdict from the catch-up rounds in
            // one write, OFF the per-peer hot path (review: no blocking I/O
            // inside the parallel peer loop).
            clcache.flush();
            if hunting && processor.store.current_period() == last_seen_progress.0 {
                // catch_up returned with no period progress while starved —
                // probe for new servers before the next round (lc-confirms
                // feed both the cache and catch-up's prefer tier).
                hunt_round(&client, &mut pool, &mut processor, &mut clcache,
                    &mut hunt_probed, &mut hunt_confirmed)
                    .await;
                clcache.flush();
            }
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
                processor.store = LightClientStore::new(config.slots_per_period());
                staged_updates.clear();
                last_persisted_period = checkpoint_period; // keep the never-persist-checkpoint floor
                resume = ResumeGuard::fresh();
                in_catchup = false;
                pool.sync_start_period = -1;
                // Publish the reset immediately: without this the status watch
                // keeps the DISCARDED snapshot's CATCHING_UP periods frozen on
                // screen for the whole re-bootstrap.
                publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunting).await;
                continue;
            }
            // Backstop only: catch_up persists each applied period itself,
            // so this is a no-op unless a future change makes catch_up return
            // with an unpersisted advance.
            persist_snapshot(&config, &processor, &mut last_persisted_period);
            refresh_local_status(&config, &processor, &local_status);
            publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunting).await;
            if config.wall_clock_period()
                > processor.store.current_period()
            {
                // Still behind: skip the finality poll — while the committee is
                // stale every finality update fails BLS verify (Java does the
                // same to avoid burning the whole cycle).
                tokio::time::sleep(Duration::from_secs(config.seconds_per_slot)).await;
                continue;
            }
        }

        in_catchup = false; // reaching here means the committee is current
        let applied =
            poll_finality(&client, &mut pool, &mut processor, &mut clcache, &hunt_confirmed)
                .await;
        if applied {
            // A finality update verified against the (possibly restored)
            // committee — the snapshot is genuine.
            resume.confirm();
        } else if hunting {
            // Starved and the proven/preferred tiers came up dry — burst-probe
            // the unproven pool tail for new LC servers.
            hunt_round(&client, &mut pool, &mut processor, &mut clcache,
                &mut hunt_probed, &mut hunt_confirmed)
                .await;
        }
        clcache.flush(); // batch any finality-round evictions into one write
        // No-op unless the period advanced (force-rotate can move it here too).
        persist_snapshot(&config, &processor, &mut last_persisted_period);
        refresh_local_status(&config, &processor, &local_status);
        publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunting).await;

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
    fanout: usize,
    prefer: &HashSet<PeerId>,
) -> bool {
    if pool.is_empty() {
        tracing::info!("bootstrap: no peers yet (waiting on discovery)");
        return false;
    }
    let peers = pool.candidates(fanout, false, false, prefer, &HashSet::new());
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

    // Same round-scoped cache accounting as poll_finality: strikes are
    // buffered and applied ONLY when the whole round fails — a round with a
    // verified winner spares its speculative losers, while a fully-failed
    // round strikes each failed peer once. Without any bootstrap-side strikes
    // (the previous state), dead proven servers could accumulate in the shared
    // cache unboundedly and — once they filled the 8-candidate proven tier —
    // wedge a fresh bootstrap forever on the same dead dials every round.
    let mut round_failures: Vec<String> = Vec::new();
    let fail = |pool: &mut PeerPool, buf: &mut Vec<String>, id: PeerId| {
        pool.note_failure(id);
        if let Some(p) = peers.iter().find(|p| p.id == id) {
            buf.push(format!("{}/p2p/{}", p.addr, p.id));
        }
    };

    for (peer, res) in results {
        let raw = match res {
            Ok(raw) => raw,
            Err(e) => {
                if e != RequestError::Shutdown && e != RequestError::UnsupportedProtocol {
                    fail(pool, &mut round_failures, peer);
                }
                tracing::debug!(peer = %peer, error = %e, "bootstrap request failed");
                continue;
            }
        };
        let ssz_payload = match codec::decode_response(&raw, true) {
            Ok(d) => d.ssz_payload,
            Err(e) => {
                fail(pool, &mut round_failures, peer);
                tracing::debug!(peer = %peer, error = %e, "bootstrap frame invalid");
                continue;
            }
        };
        let bootstrap = match LightClientBootstrap::decode(&ssz_payload) {
            Ok(b) => b,
            Err(e) => {
                fail(pool, &mut round_failures, peer);
                tracing::debug!(peer = %peer, error = %e, "bootstrap decode failed");
                continue;
            }
        };

        // Checkpoint pin: the peer chose the payload, WE chose the root.
        let header_root = bootstrap.header.beacon.hash_tree_root();
        if header_root != config.checkpoint_root {
            fail(pool, &mut round_failures, peer);
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
            fail(pool, &mut round_failures, peer);
            tracing::warn!(peer = %peer, depth, "bootstrap rejected: sync committee branch invalid");
            continue;
        }
        if !LightClientProcessor::verify_execution_branch(&bootstrap.header) {
            fail(pool, &mut round_failures, peer);
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
        return true; // round has a winner — buffered strikes are discarded
    }
    for addr in &round_failures {
        clcache.mark_failure(addr);
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
/// not our store), and ONLY from batches with zero applies: an apply in the
/// same batch proves the restored committee, so confirm() wins over poison
/// accounting. A lone bad peer replaying unverifiable updates can still trip
/// this before any honest serve — ACCEPTED: the outcome is a self-correcting
/// re-bootstrap from the embedded checkpoint (a cold-start cost, ~15 min),
/// which strictly beats the alternatives — any distinct-peer requirement is
/// Sybil-cheap (peer identities are free; counts are not cryptographic
/// evidence, per the repo trust rule) AND permanently wedges the genuinely-
/// corrupt-snapshot case when only one server answers (the scarce-server
/// reality). The threshold is 8 (~2 min of reject rounds) to make the
/// false positive rare while keeping the corrupt-snapshot escape prompt.
const RESUME_REJECTS_MAX: u32 = 8;

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
    /// Callers must only report rejects from batches WITHOUT an apply — an
    /// apply proves the snapshot and confirm() takes precedence (rejects in
    /// such a batch are stale/bad chunks from other peers, not evidence
    /// against the restored committee).
    fn poisoned(&mut self, rejects: u32) -> bool {
        if !self.unconfirmed {
            return false;
        }
        self.rejects += rejects;
        self.rejects >= RESUME_REJECTS_MAX
    }
}

/// A fetched-but-unapplied catch-up update plus the shared-cache key
/// (`multiaddr/p2p/peerid`) of the peer whose response staged it — the apply
/// path credits `record_served` to the actual stager, which is not always the
/// round's responding peer (chunks linger across rounds and responses).
struct StagedChunk {
    ssz: Vec<u8>,
    from: String,
}

/// Periods requested per catch-up round — the full spec cap, matching the
/// Java client's `min(periodsToFetch, 128)`. This is THE cold-sync lever:
/// "generous" servers exist that stream the whole requested range back-to-back
/// (measured on the same Pixel 7 with the same cached peers: Java engine
/// synced 19 periods in 140 s off one such server, while this engine's old
/// 16-cap plus per-round costs — serve latency, the 12 s quiet window, the
/// 11 s pace, backoff on empty rounds — took 972 s at ~1 period per round
/// from quota-truncating servers). One generous response now covers the whole
/// catch-up in a single staged apply; truncating (Lighthouse-style) servers
/// still return 1 chunk per round exactly as before. Wire-size check: 128
/// chunks × ~27 KiB ≈ 3.5 MiB, well under the 16 MiB response cap. Time
/// check: a paced or slow-link server can't stream 128 chunks inside the
/// 45 s request timeout — the codec's UPDATES_READ_BUDGET completes such a
/// read early with the chunks that DID arrive, so a partial batch applies
/// instead of timing out and strike-marking the server.
const UPDATES_BATCH_MAX: u64 = 128;
/// Peer candidates asked per round — all in parallel, first useful response
/// wins (Java CATCHUP_FANOUT_MAX is 48; the discovered pool is failure-heavy,
/// so a wide fan-out is what makes rounds land).
const CATCHUP_FANOUT: usize = 32;

// ---------------------------------------------------------------------------
// LC hunt mode — aggressive server discovery when the chain is starved.
// ---------------------------------------------------------------------------

/// Still un-bootstrapped this long after sync start → hunt. A healthy network
/// bootstraps in seconds; a minute of failure means the candidate pool holds
/// no reachable LC server and waiting on the polite lookup cadence won't fix
/// it (the sepolia starvation incident: 4 fresh servers were discoverable
/// within minutes once lookups and probing ran aggressively).
const HUNT_BOOTSTRAP_STALL: Duration = Duration::from_secs(60);

/// Peers probed per hunt round, drawn from the UNPROVEN pool tail — the tier
/// the regular finality fan-out reaches last. Bounded per ~12 s round so hunt
/// mode stays a burst, not a flood.
const HUNT_FANOUT: usize = 24;

/// Don't re-probe the same peer within this window — hunts run every poll
/// cycle while starved, and a peer that just failed won't recover in 12 s.
const HUNT_REPROBE: Duration = Duration::from_secs(600);

/// Catch-up (committee period behind wall clock) with ZERO store progress for
/// this long → the catch-up fan-out itself is starved of servers → hunt. A
/// healthy catch-up applies a period every few seconds; two minutes of
/// nothing means nobody in the pool serves `updates_by_range`, and only the
/// hunt (boosted discovery + probing) can break that chicken-and-egg. Also
/// keeps a hunt ENGAGED when finality starvation crosses a period boundary
/// (the store period falls behind but the starvation is the same).
const HUNT_CATCHUP_STALL: Duration = Duration::from_secs(120);

/// Should the LC hunt run this cycle? Three triggers, all meaning "we are
/// starved of light-client servers":
/// - **Bootstrap stall**: the store never initialized and we've been trying
///   longer than [`HUNT_BOOTSTRAP_STALL`] — bootstrap itself can't find a
///   server.
/// - **Starved catch-up**: the committee period is behind wall clock AND the
///   store hasn't advanced for [`HUNT_CATCHUP_STALL`]. A *progressing*
///   catch-up never hunts — its own wide fan-out covers the pool, and
///   hunting there would just double-dial it.
/// - **Finality starvation**: the committee period is current but the
///   finalized head has aged past the SYNCED freshness slack — catch-up is
///   done, yet nobody serves us finality updates (the state the status
///   surface shows as CATCHING_UP at `period X / X`).
///
/// `engaged` adds hysteresis to the finality trigger: engage at the full
/// slack, disengage only once finality is a full epoch fresher — a pool
/// whose lone server applies right at the boundary must not flap the
/// discovery boost on/off every cycle.
///
/// Pure function of its inputs so the triggers are unit-testable.
#[allow(clippy::too_many_arguments)]
fn hunt_due(
    engaged: bool,
    store_initialized: bool,
    since_sync_start: Duration,
    since_progress: Duration,
    wall_slot: u64,
    store_period: u64,
    finalized_slot: u64,
    slots_per_epoch: u64,
    slots_per_period: u64,
) -> bool {
    if !store_initialized {
        return since_sync_start >= HUNT_BOOTSTRAP_STALL;
    }
    let wall_period = spec::compute_sync_committee_period_with(wall_slot, slots_per_period);
    if wall_period > store_period {
        return since_progress >= HUNT_CATCHUP_STALL;
    }
    let slack_epochs =
        if engaged { SYNCED_SLOT_SLACK_EPOCHS - 1 } else { SYNCED_SLOT_SLACK_EPOCHS };
    finalized_slot + slack_epochs * slots_per_epoch < wall_slot
}

/// Consecutive no-progress rounds before returning to the outer loop (which
/// refreshes the discovered-peer pool and republishes status). Rounds inside
/// retry after a short pause — the Java equivalent is MAX_CATCHUP_BATCHES
/// per call with a 12 s outer cycle.
const CATCHUP_MAX_IDLE_ROUNDS: u32 = 6;

/// Catch the store's committee period up to wall clock — the behavioral twin
/// of the Java `catchUpSyncCommittee`/`attemptCatchUpBatch`/
/// `applyCatchUpResponses`: every fan-out peer gets the SAME
/// `(current_period, count ≤ 128)` range request in parallel, so any single
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
    staged: &mut std::collections::BTreeMap<u64, StagedChunk>,
    clcache: &mut crate::clcache::ClPeerCache,
    resume: &mut ResumeGuard,
    last_persisted_period: &mut u64,
    anchor: &ExecAnchor,
    hunt_confirmed: &HashSet<PeerId>,
    hunting: bool,
) -> bool {
    let mut idle_rounds = 0u32;
    // Exponential pause after fruitless rounds: hammering the whole pool every
    // ~13 s is exactly what CL peer scoring penalizes, and it burns request
    // quota on servers that will serve happily a minute later.
    let mut empty_backoff = Duration::from_secs(0);
    // Pace after a SUCCESSFUL round instead of re-asking instantly: LC servers
    // (Lighthouse) serve ~one update per ~10 s quota window, so the instant
    // re-ask always came back empty — which put the just-serving peer on
    // cooldown, rotated the fan-out to non-servers, and climbed the 5→40 s
    // empty-round backoff ladder. Observed on-device: 20–95 s per period
    // where the quota allows ~11 s. Sleeping one quota window keeps the
    // serving peer in the next round's fan-out with its quota refilled.
    let mut pace_after_apply = false;
    loop {
        drain_discovered(peer_rx, pool);
        let slot_estimate = config.current_slot_estimate();
        let wall_period =
        spec::compute_sync_committee_period_with(slot_estimate, config.slots_per_period());
        // Start from the committee's own period, NOT the finalized slot's:
        // after a force-rotate the two diverge by one period (see the Java
        // comment in catchUpSyncCommittee).
        let committee_period = processor.store.current_period();
        if wall_period <= committee_period {
            tracing::info!(period = committee_period, "sync committee is current");
            return false;
        }
        // Sleeps AFTER the done-check: the final applied round must not pay
        // an 11 s pace (or a backoff) just to discover there is no next
        // request to protect — SYNCED publishes immediately.
        if pace_after_apply {
            pace_after_apply = false;
            tracing::info!(pace_s = UPDATES_SERVE_COOLDOWN.as_secs(),
                "catch-up: pacing to the LC serve quota before the next round");
            tokio::time::sleep(UPDATES_SERVE_COOLDOWN).await;
        } else if !empty_backoff.is_zero() {
            tracing::info!(backoff_s = empty_backoff.as_secs(),
                "catch-up: no progress last round — backing off before retrying");
            tokio::time::sleep(empty_backoff).await;
        }
        *staged = staged.split_off(&committee_period); // drop already-passed periods
        let span = (wall_period - committee_period).min(UPDATES_BATCH_MAX);
        tracing::info!(from_period = committee_period, wall_period, span,
            staged = staged.len(), "catch-up: requesting updates_by_range");

        let (mut lc_servers, earliest_slots) = client.catchup_peer_meta().await;
        // Reconcile the deny set against the LIVE Identify signal (same protocol
        // nolc tracks, self-expiring on disconnect) BEFORE folding in
        // hunt_confirmed — see clear_no_lc for why the finality-attesting hunt
        // set must not un-deny updates_by_range. Persist each reversal to the
        // shared cache so pool and cache never disagree across a restart or an
        // engine switch (issue #291, PR #322 review).
        for id in pool.clear_no_lc(&lc_servers) {
            if let Some(key) = pool.cache_key(&id) {
                clcache.clear_nolc(&key);
            }
        }
        // Hunt-confirmed servers join the Identify-confirmed prefer tier —
        // same dial-priority-only trust level (see poll_finality).
        lc_servers.extend(hunt_confirmed.iter().copied());
        // Skip peers whose advertised earliest_available_slot proves their
        // light-client history begins in a LATER period than the one we need —
        // they'd only return far-future updates the period gate discards (Java
        // attemptCatchUpBatch's earliestAvailableSlot filter). Compare at
        // PERIOD granularity: a peer whose earliest slot lands anywhere inside
        // committee_period can still serve that period's update, so only skip
        // when its earliest period is strictly greater. Peers not yet
        // status-exchanged (absent from the map) are unknown and kept; v1 peers
        // report 0 (genesis history) and are never skipped. This is a STRONG
        // PREFERENCE, not a veto: candidates() falls back to the shallow peers
        // when they are all that is left, because earliest_available_slot is a
        // block floor rather than an LC-update floor and an all-shallow pool is
        // not proof that nobody serves the period (issue #291). Only a
        // genuinely empty pool bounces to rediscovery.
        let too_shallow: HashSet<PeerId> = earliest_slots
            .into_iter()
            .filter(|&(_, earliest)| {
                spec::compute_sync_committee_period_with(earliest, config.slots_per_period())
                    > committee_period
            })
            .map(|(id, _)| id)
            .collect();
        let peers = pool.candidates(CATCHUP_FANOUT, true, true, &lc_servers, &too_shallow);
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
        let mut poisoned_this_round = false;
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
                        // Both are no-ops for a static peer: the pool exempts it,
                        // and the shared cache is read by the Java engine, which
                        // would otherwise inherit the denial for a curated peer
                        // (PR #322 review) — so gate the persist on it too.
                        pool.mark_no_lc_updates(peer.id);
                        if !pool.is_static(&peer.id) {
                            clcache.mark_nolc(&format!("{}/p2p/{}", peer.addr, peer.id));
                        }
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
            let peer_key = format!("{}/p2p/{}", peer.addr, peer.id);
            let chunks = match codec::decode_multi_chunk_response(&raw, sub_count as usize) {
                Ok(c) => c,
                Err(e) => {
                    // Undecodable response — with the codec's read budget this
                    // is also where a byte-dribbling peer lands (it used to hit
                    // the behaviour timeout instead). Charge it the same way so
                    // 3-strike eviction still prunes peers that never produce
                    // a usable chunk.
                    pool.note_failure(peer.id);
                    clcache.mark_failure(&peer_key);
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
                staged.entry(sub_from + i as u64).or_insert_with(|| StagedChunk {
                    ssz: chunk,
                    from: peer_key.clone(),
                });
            }
            if served > 0 {
                tracing::info!(peer = %peer.id, sub_from, sub_count, served,
                    raw_len = raw.len(), "updates_by_range served");
                pool.mark_proven(peer.id);
                // Deliberately NO cooldown for a peer that just served: it is
                // often the only willing server in the pool, and the ~13 s
                // round cadence sits at Lighthouse's ~1-per-10s quota anyway —
                // the Java client re-asks its serving peer the same way.
                // Apply at most ONE staged update here — just enough BLS to
                // decide this response is the round's winner. The rest of the
                // staged prefix (up to 128 periods from a generous server) is
                // drained AFTER the fan-out is dropped, so the stragglers'
                // redundant multi-MiB streams are cancelled behind one
                // signature verification instead of a full batch of them.
                let before_period = processor.store.current_period();
                let (applied_now, verify_rejects, applied_from) =
                    apply_staged_step(processor, staged, slot_estimate);
                // ORDER MATTERS: an apply in this batch BLS-verified against
                // the restored committee and proves the snapshot genuine —
                // confirm() must win over poison accounting (a reject in the
                // same batch is a stale/bad chunk another peer staged, not
                // evidence against the snapshot; counting it first was
                // exactly how one bad peer could get a good snapshot
                // deleted despite an honest serve landing in the same round).
                if applied_now == 0
                    && verify_rejects > 0
                    && resume.poisoned(verify_rejects as u32)
                {
                    // Defer the verdict to round end: a slower HONEST response
                    // in this same round can still apply and confirm the
                    // snapshot — a fast bad peer must not win the race. If an
                    // apply lands, confirm() resets the guard and the pending
                    // flag below is ignored.
                    poisoned_this_round = true;
                    continue;
                }
                if applied_now > 0 {
                    resume.confirm();
                    pool.note_served(peer.id); // BLS-verified and applied
                    // Only VERIFIED periods reach the shared cross-engine
                    // cache, credited to the peer whose response STAGED the
                    // applied chunk — usually this responder, but a chunk
                    // lingering from an earlier response can be the one that
                    // applies (Java applyCatchUpResponses records AFTER
                    // processUpdate the same way — never before verification).
                    if let Some(key) = applied_from {
                        clcache.record_served(&key, before_period, before_period);
                    }
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

        if poisoned_this_round && applied == 0 {
            return true; // whole round rejected — restored snapshot can't verify anything
        }

        if applied > 0 {
            // Drain the rest of the contiguous staged prefix — a generous
            // response stages up to the whole remaining span. One update per
            // iteration: persist after EVERY period so an Android kill
            // mid-drain loses at most one period's BLS work, not the whole
            // batch (the ~50 KiB write+rename is milliseconds next to the
            // ~100 ms BLS verify it checkpoints), publish so the progress bar
            // tracks the drain instead of jumping at round end, and yield so
            // back-to-back BLS verifications don't pin this worker while the
            // swarm task needs it. A verify-reject here is a stale chunk some
            // other peer staged earlier — the winner already confirmed the
            // store, so it is dropped for refetch without poison accounting.
            // Each period is credited to the peer whose response staged it.
            let mut drained = 0usize;
            loop {
                let before_period = processor.store.current_period();
                let (applied_now, _verify_rejects, applied_from) =
                    apply_staged_step(processor, staged, slot_estimate);
                if applied_now == 0 {
                    break;
                }
                applied += applied_now;
                drained += 1;
                if let Some(key) = applied_from {
                    clcache.record_served(&key, before_period, before_period);
                }
                persist_snapshot(config, processor, last_persisted_period);
                publish_status(config, client, processor, &*pool, status_tx, anchor, hunting).await;
                tokio::task::yield_now().await;
            }
            tracing::info!(applied, staged = staged.len(),
                period = processor.store.current_period(),
                finalized_slot = processor.store.finalized_slot(),
                "catch-up round applied");
            if drained == 0 {
                // Single-period round (truncating server): the drain didn't
                // run, so this is the round's one publish+persist. Persisting
                // every applied period — not just when catch_up returns —
                // is what keeps an Android kill (reinstall, OOM, user swipe)
                // from losing every verified period since bootstrap
                // (observed: 4 periods re-verified after a reinstall).
                publish_status(config, client, processor, &*pool, status_tx, anchor, hunting).await;
                persist_snapshot(config, processor, last_persisted_period);
            }
            idle_rounds = 0;
            pace_after_apply = true;
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
            // Grow the pre-round pause 5s → 25s: rapid-fire empty rounds burn
            // server quota and our own peer score, but with the post-apply
            // pacing preventing self-inflicted empties, the rounds that reach
            // here are genuine server droughts — and a 60 s ceiling meant up
            // to a minute of blindness after a server RETURNED (droughts
            // dominated measured cold syncs). 25 s samples recovery twice as
            // fast at bounded quota cost: CATCHUP_MAX_IDLE_ROUNDS exits to
            // the outer poll loop after 6 fruitless rounds either way, so a
            // sustained drought cycles at most ~35% more request bursts than
            // the 60 s ceiling did — it cannot hammer indefinitely faster.
            empty_backoff = if empty_backoff.is_zero() {
                Duration::from_secs(5)
            } else {
                (empty_backoff * 2).min(Duration::from_secs(25))
            };
            tracing::debug!(period = processor.store.current_period(), idle_rounds,
                "catch-up round made no progress — retrying after backoff");
        }
    }
}

/// Verify+apply AT MOST ONE staged update — the one at the store's current
/// period (the contiguous prefix advances one period per call; callers loop:
/// the fan-out handler calls once to pick a winner, the post-fan-out drain
/// loops with a persist+yield between calls). The update is decoded and
/// processed, advancing the committee period on success
/// (`force_rotate_if_past_period` on the recorded wall-clock estimate — Java
/// `applyCatchUpResponses`). A chunk that fails decode/verify is dropped from
/// the buffer so the next round refetches that period from a different peer.
/// Returns `(applied, verify_rejects, applied_from)` — applied and
/// verify_rejects are each 0 or 1, and applied_from is the shared-cache key
/// of the peer whose response staged the applied chunk (None unless applied).
/// verify_rejects counts ONLY an update that decoded fine but failed
/// BLS/Merkle verification (`process_update` → false): that is the resume
/// guard's poison signal, since a corrupt restored committee rejects every
/// well-formed update. Decode failures are NOT counted — a peer sending
/// malformed frames says nothing about our store.
fn apply_staged_step(
    processor: &mut LightClientProcessor,
    staged: &mut std::collections::BTreeMap<u64, StagedChunk>,
    slot_estimate: u64,
) -> (usize, usize, Option<String>) {
    let target_period = processor.store.current_period();
    let Some(chunk) = staged.remove(&target_period) else {
        return (0, 0, None);
    };
    match LightClientUpdate::decode(&chunk.ssz) {
        Ok(update) => {
            if processor.process_update(&update) {
                processor.store.force_rotate_if_past_period(slot_estimate);
                tracing::debug!(target_period,
                    finalized_slot = update.finalized_header.beacon.slot,
                    period = processor.store.current_period(),
                    "catch-up update applied");
                (1, 0, Some(chunk.from))
            } else {
                tracing::debug!(target_period,
                    finalized_slot = update.finalized_header.beacon.slot,
                    "catch-up update rejected");
                (0, 1, None)
            }
        }
        Err(e) => {
            tracing::debug!(target_period, error = %e, "catch-up update decode failed");
            (0, 0, None)
        }
    }
}

/// One finality-poll pass: try peers until one update verifies and applies —
/// the Java `pollFinalityUpdate` steady-state branch (POLL_FINALITY_FANOUT=16,
/// which now mirrors this fan-out shape and round accounting).
/// Returns true when an update verified AND applied (the resume guard's
/// confirmation signal).
async fn poll_finality(
    client: &ReqRespClient,
    pool: &mut PeerPool,
    processor: &mut LightClientProcessor,
    clcache: &mut crate::clcache::ClPeerCache,
    hunt_confirmed: &HashSet<PeerId>,
) -> bool {
    let mut lc_servers = client.lc_update_servers().await;
    // Reverse any stale nolc verdict for peers whose LIVE Identify now advertises
    // updates_by_range, and persist the reversal to the shared cache — before
    // folding in hunt_confirmed, which attests to a different protocol (see
    // clear_no_lc, issue #291, PR #322 review).
    for id in pool.clear_no_lc(&lc_servers) {
        if let Some(key) = pool.cache_key(&id) {
            clcache.clear_nolc(&key);
        }
    }
    // Hunt-confirmed servers (decodable LC response this run) join the
    // Identify-confirmed prefer tier — same dial-priority-only trust level.
    lc_servers.extend(hunt_confirmed.iter().copied());
    // No earliest-slot skip here: finality polling asks for the LATEST update,
    // which every synced peer holds regardless of how far its history is pruned.
    let peers = pool.candidates(16, false, false, &lc_servers, &HashSet::new());
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
    // Round-scoped cache accounting (the Java poll now fans out with the same
    // rule). Dialing 16 at once mints up to 15 speculative losses per 12 s
    // round, and feeding each into the cache's 3-strike eviction emptied it of
    // every proven server on-device (peers=209, catch_up_servers=0). So:
    // failures are buffered per round; a round WITH a winner discards them
    // (the losers raced a success); a fully-failed round strikes every failed
    // peer once. Dead proven servers thus still evict in ~3 fully-failed
    // encounters, and the cache can't accumulate them unboundedly.
    // Session-pool note_failure stays per-dial: it exists precisely to rotate
    // the live fan-out.
    let mut round_failures: Vec<String> = Vec::new();
    let mut applied = false;
    while let Some((peer, res)) = in_flight.next().await {
        let raw = match res {
            Ok(raw) => raw,
            Err(e) => {
                if e != RequestError::Shutdown && e != RequestError::UnsupportedProtocol {
                    pool.note_failure(peer.id);
                    round_failures.push(format!("{}/p2p/{}", peer.addr, peer.id));
                }
                tracing::debug!(peer = %peer.id, error = %e, "finality_update request failed");
                continue;
            }
        };
        let ssz_payload = match codec::decode_response(&raw, true) {
            Ok(d) => d.ssz_payload,
            Err(e) => {
                // Garbage frames are failures too (bootstrap-round parity):
                // strikable when the whole round fails, spared by a winner.
                pool.note_failure(peer.id);
                round_failures.push(format!("{}/p2p/{}", peer.addr, peer.id));
                tracing::debug!(peer = %peer.id, error = %e, "finality_update frame invalid");
                continue;
            }
        };
        match LightClientFinalityUpdate::decode(&ssz_payload) {
            Ok(update) => {
                if processor.process_finality_update(&update) {
                    // Success is a VERIFIED apply (Java notifies its cache
                    // only after processUpdate succeeds, never on mere decode
                    // — a peer serving decodable-but-unverifiable updates
                    // must not earn tier-1 status or cache streak resets).
                    pool.mark_proven(peer.id);
                    pool.note_served(peer.id);
                    clcache.note_success(&format!("{}/p2p/{}", peer.addr, peer.id));
                    tracing::info!(peer = %peer.id,
                        finalized_slot = processor.store.finalized_slot(),
                        optimistic_slot = processor.store.optimistic_slot(),
                        period = processor.store.current_period(),
                        "finality update applied");
                    applied = true;
                    break; // stragglers are speculative losers — spare them
                }
                tracing::debug!(peer = %peer.id,
                    finalized_slot = update.finalized_header.beacon.slot,
                    "finality update did not advance state");
            }
            Err(e) => {
                pool.note_failure(peer.id);
                round_failures.push(format!("{}/p2p/{}", peer.addr, peer.id));
                tracing::debug!(peer = %peer.id, error = %e, "finality update decode failed");
            }
        }
    }
    if !applied {
        for addr in &round_failures {
            clcache.mark_failure(addr);
        }
    }
    applied
}

/// One LC-hunt burst: probe up to [`HUNT_FANOUT`] UNPROVEN pool peers with a
/// `light_client_finality_update` request and harvest every verdict:
/// - verified apply → full win: proven tier + cache success + `lc` token
///   (ends the starvation this round);
/// - decodable but not applied/advancing → `lc`-confirmed: persisted to the
///   cache and preferred by subsequent poll/bootstrap rounds (dial-priority
///   only — trust still requires a verified apply, PR #217's rule);
/// - `UnsupportedProtocol` → `nolc` in pool + cache, never re-probed;
/// - dial/timeout/garbage → pool failure only. Deliberately NOT a cache
///   strike: hunt targets are mostly fresh discoveries the cache has never
///   vouched for, and striking them would churn the file with dead entries.
///
/// Returns true when an update verified AND applied.
async fn hunt_round(
    client: &ReqRespClient,
    pool: &mut PeerPool,
    processor: &mut LightClientProcessor,
    clcache: &mut crate::clcache::ClPeerCache,
    probed: &mut HashMap<PeerId, Instant>,
    confirmed: &mut HashSet<PeerId>,
) -> bool {
    let peers = pool.explore_candidates(HUNT_FANOUT, probed, HUNT_REPROBE);
    if peers.is_empty() {
        tracing::debug!("LC hunt: no unprobed candidates (waiting on discovery)");
        return false;
    }
    let now = Instant::now();
    for p in &peers {
        probed.insert(p.id, now);
    }
    // Bound the map: starved runs hunt every cycle and discovery keeps
    // feeding; entries past the re-probe window are dead weight.
    if probed.len() > 4096 {
        probed.retain(|_, t| now.saturating_duration_since(*t) < HUNT_REPROBE);
    }
    let attempted = peers.len();
    let mut in_flight: FuturesUnordered<_> = peers
        .into_iter()
        .map(|peer| {
            let client = client.clone();
            async move {
                let res = client
                    .request_raw(peer.id, peer.addr.clone(), protocols::FINALITY_UPDATE, Vec::new())
                    .await;
                (peer, res)
            }
        })
        .collect();
    let mut applied = false;
    let mut newly_confirmed = 0usize;
    let mut nolc = 0usize;
    while let Some((peer, res)) = in_flight.next().await {
        let raw = match res {
            Ok(raw) => raw,
            Err(RequestError::UnsupportedProtocol) => {
                nolc += 1;
                pool.mark_no_lc_updates(peer.id);
                // Never persist a static peer's transient strike (PR #322
                // review) — the Java engine seeds its deny set from this cache.
                if !pool.is_static(&peer.id) {
                    clcache.mark_nolc(&format!("{}/p2p/{}", peer.addr, peer.id));
                }
                continue;
            }
            Err(e) => {
                if e != RequestError::Shutdown {
                    pool.note_failure(peer.id);
                }
                continue;
            }
        };
        let ssz_payload = match codec::decode_response(&raw, true) {
            Ok(d) => d.ssz_payload,
            Err(_) => {
                pool.note_failure(peer.id);
                continue;
            }
        };
        match LightClientFinalityUpdate::decode(&ssz_payload) {
            Ok(update) => {
                let addr = format!("{}/p2p/{}", peer.addr, peer.id);
                if confirmed.insert(peer.id) {
                    newly_confirmed += 1;
                }
                clcache.mark_lc(&addr);
                // Skip the BLS verify once a winner applied this round — it's
                // the expensive step (~17s/update on Android/ART) and the
                // starvation is already over; a decodable response was enough
                // to harvest the lc confirm above. Stragglers stay
                // lc-confirmed, not proven — the same speculative-loser rule
                // as poll_finality's early break.
                if !applied && processor.process_finality_update(&update) {
                    // Verified apply — the same full-win treatment as a
                    // poll_finality winner.
                    pool.mark_proven(peer.id);
                    pool.note_served(peer.id);
                    clcache.note_success(&addr);
                    applied = true;
                    tracing::info!(peer = %peer.id,
                        finalized_slot = processor.store.finalized_slot(),
                        "LC hunt: finality update applied from new server");
                }
            }
            Err(_) => {
                pool.note_failure(peer.id);
            }
        }
    }
    tracing::info!(attempted, newly_confirmed, nolc, applied,
        "LC hunt round complete");
    applied
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

/// Feed the EL execution anchor from the verified beacon store — the CL→EL
/// trust bridge (twin of the Java `BeaconSyncState.updateFinalizedExecution` /
/// `updateOptimisticExecution`). The finalized payload is what `is_synced()`
/// derives from and what the header-chain walk anchors against; the optimistic
/// payload gives the freshest attested head. Both also seed the `stateRootMatch`
/// window. Guarded on a non-zero block hash so a pre-merge / absent execution
/// header never registers a zero state root as "synced".
fn update_exec_anchor(store: &LightClientStore, anchor: &ExecAnchor) {
    // Label each execution payload with ITS block's slot (`beacon.slot`), read
    // straight from the header — not the store's tracked slots. `finalized_slot`
    // happens to equal `finalized_header.beacon.slot`, but `optimistic_slot` is
    // the SIGNATURE slot (~beacon.slot + 1), whereas the optimistic execution
    // payload belongs to the attested block at `beacon.slot`. Using the block
    // slot keeps the stateRootMatch window's (slot, root) keys correct.
    if let Some(finalized) = store.finalized_header() {
        let e = &finalized.execution;
        if e.block_hash != [0u8; 32] {
            anchor.update_finalized(
                finalized.beacon.slot,
                e.state_root,
                e.block_number,
                e.block_hash,
            );
        }
    }
    if let Some(optimistic) = store.optimistic_header() {
        let e = &optimistic.execution;
        if e.block_hash != [0u8; 32] {
            anchor.update_optimistic(
                optimistic.beacon.slot,
                e.block_number,
                e.block_hash,
                e.state_root,
            );
        }
    }
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
    anchor: &ExecAnchor,
    hunting: bool,
) {
    let store = &processor.store;
    update_exec_anchor(store, anchor);
    let wall_slot = config.current_slot_estimate();
    let wall_period =
        spec::compute_sync_committee_period_with(wall_slot, config.slots_per_period());
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
        sync_start_period: pool.sync_start_period,
        hunting,
    };
    let _ = status_tx.send(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A LightClientHeader with a real (post-merge) execution payload for the
    /// anchor-wiring tests.
    fn header_with_exec(
        slot: u64,
        state_root: [u8; 32],
        block_number: u64,
        block_hash: [u8; 32],
    ) -> myotis_consensus::types::LightClientHeader {
        use myotis_consensus::types::{
            BeaconBlockHeader, ExecutionPayloadHeader, LightClientHeader,
        };
        LightClientHeader {
            beacon: BeaconBlockHeader { slot, ..Default::default() },
            execution: ExecutionPayloadHeader {
                state_root,
                block_number,
                block_hash,
                ..Default::default()
            },
            execution_branch: Vec::new(),
        }
    }

    #[test]
    fn exec_anchor_fed_from_store_headers() {
        let anchor = ExecAnchor::new();
        let mut store = LightClientStore::new_mainnet_preset();
        store.update_finalized(&header_with_exec(1000, [0x11; 32], 21_000_000, [0x22; 32]), 1000);
        // Mirror the processor: the optimistic header is tracked at the SIGNATURE
        // slot (1003), one past the attested block's beacon.slot (1002).
        store.update_optimistic(&header_with_exec(1002, [0x33; 32], 21_000_002, [0x44; 32]), 1003);

        update_exec_anchor(&store, &anchor);

        // is_synced() derives from the finalized execution state root landing.
        assert!(anchor.is_synced());
        let fin = anchor.finalized_execution().expect("finalized execution");
        assert_eq!(fin.block_number, 21_000_000);
        assert_eq!(fin.state_root, [0x11; 32]);
        assert_eq!(fin.block_hash, [0x22; 32]);
        assert_eq!(anchor.finalized_slot(), 1000);
        assert_eq!(anchor.optimistic_block_number(), 21_000_002);
        assert_eq!(anchor.optimistic_block_hash(), Some([0x44; 32]));
        // Both roots seed the stateRootMatch window, each keyed by ITS block's
        // slot — the optimistic root at the attested block slot 1002, NOT the
        // store's signature slot 1003.
        assert_eq!(anchor.find_state_root(&[0x11; 32]).map(|r| r.slot), Some(1000));
        assert_eq!(anchor.find_state_root(&[0x33; 32]).map(|r| r.slot), Some(1002));
    }

    #[test]
    fn exec_anchor_skips_zero_block_hash() {
        // A pre-merge / absent execution header (zero block hash) must NOT
        // register a zero state root as the finalized anchor — that would make
        // is_synced() true against a bogus root.
        let anchor = ExecAnchor::new();
        let mut store = LightClientStore::new_mainnet_preset();
        store.update_finalized(&header_with_exec(5, [0u8; 32], 0, [0u8; 32]), 5);

        update_exec_anchor(&store, &anchor);

        assert!(!anchor.is_synced());
        assert!(anchor.finalized_execution().is_none());
    }

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
        // 18 discovered peers + roost mainnet, pinned by NAME only.
        assert_eq!(c.static_peers.len(), 19);
        // roost is FIRST — the ordering is the point, not an accident of the
        // list. The Java twin prepends it with prependLocal(); if these two ever
        // disagree on position, the default engine and the Rust engine pick
        // different first-choice peers and only one of them is the dedicated one.
        assert_eq!(
            c.static_peers[0],
            "/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9109/p2p/16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC"
        );
        assert_eq!(c.bootstrap_enrs.len(), 17);
        assert_eq!(c.chain_id, 1);
    }

    #[test]
    fn sepolia_config_matches_networkconfig_java() {
        let c = ChainConfig::sepolia();
        assert_eq!(c.chain_id, 11_155_111);
        assert_eq!(c.fork_version, [0x90, 0x00, 0x00, 0x75]); // Fulu on sepolia
        assert_eq!(c.checkpoint_slot, 10_851_360);
        assert_eq!(
            hex_str(&c.checkpoint_root),
            "a064b99bb711d152efbc88674dcba50d4e6c1b9151dae0a2e5bfbb7c40bc7cb9"
        );
        assert_eq!(
            hex_str(&c.genesis_validators_root),
            "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
        );
        assert_eq!(c.genesis_time, 1_655_733_600);
        assert_eq!(c.seconds_per_slot, 12);
        assert_eq!(c.slots_per_epoch, 32);
        assert_eq!((c.blob_params_epoch, c.blob_params_max_blobs), (275_712, 21));
        // Checkpoint period 1324 (slot / 8192) — matches the Java region comment.
        assert_eq!(spec::compute_sync_committee_period(c.checkpoint_slot), 1324);
        // The live digest the Java computes (verified by running
        // NetworkConfig.SEPOLIA.currentForkDigest() — BPO2 folded in).
        assert_eq!(c.current_fork_digest(), [0x74, 0xD0, 0x14, 0x59]);
        assert_eq!(c.accepted_fork_digests(), vec![[0x74, 0xD0, 0x14, 0x59]]);
        // The full list, in order, addresses included — NOT a suffix match.
        //
        // This does NOT read the Java config: the two are hand-maintained copies
        // and nothing mechanically compares them. What it does is fail whenever
        // THIS side changes, which pairs with the Java `NetworkConfigGnosisTest`
        // failing whenever THAT side changes — so an edit to one is caught by
        // the other's test only if the editor runs both suites. Treat it as a
        // tripwire, not an enforced invariant.
        //
        // The addresses matter as much as the order. The Java twin asserts full
        // strings; matching only the `/tcp/<port>/p2p/<peer-id>` suffix here
        // would let an IP rotation be fixed on the Java side while this list
        // kept a dead address — and this list is the ONLY one iOS has, since
        // :app-ios runs the Rust engine exclusively.
        assert_eq!(
            c.static_peers,
            vec![
                "/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5",
                "/ip4/87.154.209.161/tcp/9104/p2p/16Uiu2HAkvYx58piGw1oxz34CUoeTv8nNQwTwE2cZZh4jR4wVMYy6",
                "/ip4/18.185.193.198/tcp/9000/p2p/16Uiu2HAm3mfkjmLPtqnSJzNtKxbDuVjVRXidz5UinaZNpjCCKAkS",
            ],
            "roost first (the dedicated LC server), the dedicated Nimbus second as \
             fallback — same list, order AND addresses as the Java \
             NetworkConfig.SEPOLIA.clPeerMultiaddrs"
        );
        // A malformed pin would otherwise reach run_sync and surface only as a
        // "skipping unparseable static peer multiaddr" warn.
        assert!(c.static_peers.iter().all(|p| parse_static_peer(p).is_some()));
        assert_eq!(c.bootstrap_enrs.len(), 9);
    }

    #[test]
    fn gnosis_config_matches_networkconfig_java() {
        let c = ChainConfig::gnosis();
        assert_eq!(c.chain_id, 100);
        assert_eq!(c.fork_version, [0x06, 0x00, 0x00, 0x64]); // Fulu on Gnosis
        assert_eq!(c.prior_fork_version, Some([0x05, 0x00, 0x00, 0x64])); // Electra
        assert_eq!(c.checkpoint_slot, 29_460_368);
        assert_eq!(
            hex_str(&c.checkpoint_root),
            "84f127f4bbb1e733c5607910c2df1d2c0e726e2fab0a4690b66cd07a5c2455bf"
        );
        assert_eq!(
            hex_str(&c.genesis_validators_root),
            "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"
        );
        assert_eq!(c.genesis_time, 1_638_993_340);
        assert_eq!((c.seconds_per_slot, c.slots_per_epoch), (5, 16));
        // 16 x 512 = 8192, the SAME product as mainnet's 32 x 256. That equality
        // is why a hardcoded 8192 worked on gnosis by accident; pin both factors
        // so a chain that breaks the coincidence fails here rather than in
        // committee selection.
        assert_eq!(c.epochs_per_sync_committee_period, 512);
        assert_eq!(c.slots_per_period(), 8192);
        assert_eq!(ChainConfig::mainnet().slots_per_period(), 8192);
        assert_eq!(ChainConfig::mainnet().epochs_per_sync_committee_period, 256);
        assert_eq!((c.blob_params_epoch, c.blob_params_max_blobs), (1_337_856, 2));
        // 512 epochs x 16 slots = the same 8192-slot period as mainnet-preset.
        // 3596 — the SAME period roost@gnosis serves. That is not incidental:
        // the previous anchor sat at 3480, 116 periods below roost's floor, and
        // roost's archive only grows forward, so a wallet could never have
        // bootstrapped from it.
        assert_eq!(spec::compute_sync_committee_period(c.checkpoint_slot), 3596);
        // Live-verified digests the Java computes (NetworkConfig.GNOSIS
        // currentForkDigest / acceptedForkDigests): Fulu first, Electra fallback.
        assert_eq!(c.current_fork_digest(), [0x32, 0x37, 0xDA, 0xB6]);
        assert_eq!(
            c.accepted_fork_digests(),
            vec![[0x32, 0x37, 0xDA, 0xB6], [0x7D, 0x5A, 0xAB, 0x40]]
        );
        // 22 pinned LC peers — same list and order as the Java
        // NetworkConfig.GNOSIS.clPeerMultiaddrs, ONE ADDRESS PER PEER ID
        // (`PeerPool::add` dedupes by peer id, so a second address for a known
        // id would never be dialed here while Java dialed both).
        // 22 discovered gnosis peers + roost, pinned by NAME only.
        assert_eq!(c.static_peers.len(), 23);
        // POSITION, like the other two chains: both engines must agree on which
        // peer the light client tries FIRST, not merely that roost is present.
        assert_eq!(c.static_peers[0], "/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9108/p2p/16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh");
        // The discovered list is unchanged, just shifted by the one roost entry.
        assert!(c.static_peers[1].ends_with(
            "/tcp/15974/p2p/16Uiu2HAky9pZH5QBGwtPgXm3A58ahKLSuuUJbZpreBMZrmksUW59"
        ));
        assert!(c.static_peers[22].ends_with(
            "/tcp/9500/p2p/16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw"
        ));
        let unique: std::collections::HashSet<_> = c.static_peers.iter().collect();
        assert_eq!(unique.len(), 23);
        let ids: std::collections::HashSet<_> =
            c.static_peers.iter().map(|a| a.rsplit('/').next().unwrap()).collect();
        assert_eq!(ids.len(), 23, "one address per peer id (the pool dedupes by id)");
        assert!(c.static_peers.iter().all(|p| parse_static_peer(p).is_some()));
        assert_eq!(c.bootstrap_enrs.len(), 8);
    }

    /// A chain whose geometry does NOT multiply to 8192, which is the case every
    /// period division must survive and the one no real chain exercises today.
    ///
    /// The config-parity tests pin both factors, but they assert the CONFIG —
    /// they cannot catch a consumer that ignores it. This asserts the consumer:
    /// `wall_clock_period` must follow the config, not the mainnet preset.
    #[test]
    fn period_consumers_follow_the_config_not_the_preset() {
        let mut c = ChainConfig::mainnet();
        c.slots_per_epoch = 32;
        c.epochs_per_sync_committee_period = 128; // 4096, deliberately not 8192
        assert_eq!(c.slots_per_period(), 4096);
        // Same slot, two geometries, two answers — if this ever equals the
        // mainnet-preset value the consumer has stopped reading the config.
        let slot = 4096 * 7 + 5;
        assert_eq!(
            spec::compute_sync_committee_period_with(slot, c.slots_per_period()),
            7
        );
        assert_eq!(spec::compute_sync_committee_period(slot), 3);
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
        let c = pool.candidates(4, true, false, &HashSet::new(), &HashSet::new());
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|p| p.id != ids[1]));

        // Preferred peers come first.
        let mut prefer = HashSet::new();
        prefer.insert(ids[3]);
        let c = pool.candidates(2, false, false, &prefer, &HashSet::new());
        assert_eq!(c[0].id, ids[3]);

        // A skipped (too-shallow) peer is excluded even when preferred.
        let mut skip = HashSet::new();
        skip.insert(ids[3]);
        let c = pool.candidates(4, false, false, &prefer, &skip);
        assert!(c.iter().all(|p| p.id != ids[3]));

        // Never starve on the SOFT filters: everything marked no-lc still
        // returns candidates (a no-lc peer may serve; better than nobody).
        for id in &ids {
            pool.mark_no_lc_updates(*id);
        }
        assert!(!pool.candidates(2, true, false, &HashSet::new(), &HashSet::new()).is_empty());

        // `skip` is preferred-against but NOT fatal: a fully-skipped pool
        // still returns candidates (issue #291 — earliest_available_slot is a
        // block floor, not an LC-update floor, so a fully-skipped pool is not
        // proof that nobody can serve; returning [] stalled catch-up forever).
        let all_skip: HashSet<PeerId> = ids.iter().copied().collect();
        assert!(!pool.candidates(4, true, false, &HashSet::new(), &all_skip).is_empty());

        // The preference still holds while ANY non-skipped peer remains: with
        // only ids[3] skipped, it must not be chosen over the other three.
        let mut one_skip = HashSet::new();
        one_skip.insert(ids[3]);
        let c = pool.candidates(3, true, false, &HashSet::new(), &one_skip);
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|p| p.id != ids[3]));
    }

    #[test]
    fn explore_candidates_targets_the_unproven_unprobed_tail() {
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..5u8 {
            let kp = libp2p::identity::Keypair::generate_secp256k1();
            let id = kp.public().to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.1.{i}/tcp/9000").parse().unwrap());
        }
        pool.mark_proven(ids[0]); // regular poll's tier 1 — hunt skips it
        pool.mark_no_lc_updates(ids[1]); // proven non-server — hunt skips it
        let mut probed: HashMap<PeerId, Instant> = HashMap::new();
        probed.insert(ids[2], Instant::now()); // probed seconds ago — inside window

        let c = pool.explore_candidates(5, &probed, HUNT_REPROBE);
        let got: HashSet<PeerId> = c.iter().map(|p| p.id).collect();
        assert!(!got.contains(&ids[0]), "proven excluded");
        assert!(!got.contains(&ids[1]), "nolc excluded");
        assert!(!got.contains(&ids[2]), "recently probed excluded");
        assert!(got.contains(&ids[3]) && got.contains(&ids[4]), "unproven tail included");

        // A peer probed LONGER than the window ago becomes eligible again.
        probed.insert(ids[2], Instant::now() - HUNT_REPROBE - Duration::from_secs(1));
        let c = pool.explore_candidates(5, &probed, HUNT_REPROBE);
        assert!(c.iter().any(|p| p.id == ids[2]), "window expiry re-admits");

        // Exhausted pool (everything probed) returns empty, not a repeat.
        let now = Instant::now();
        for id in &ids {
            probed.insert(*id, now);
        }
        assert!(pool.explore_candidates(5, &probed, HUNT_REPROBE).is_empty());
    }

    #[test]
    fn hunt_due_triggers() {
        let epoch = 32u64;
        let slack = SYNCED_SLOT_SLACK_EPOCHS * epoch; // 160 slots
        let wall = 10_000_000u64;
        let period = spec::compute_sync_committee_period(wall);
        let z = Duration::ZERO;

        // Bootstrap stall: only after the stall window.
        assert!(!hunt_due(false, false, Duration::from_secs(10), z, wall, 0, 0, epoch, 8192));
        assert!(hunt_due(false, false, HUNT_BOOTSTRAP_STALL, z, wall, 0, 0, epoch, 8192));

        // Finality starvation: period current + finalized older than slack.
        assert!(hunt_due(false, true, z, z, wall, period, wall - slack - 1, epoch, 8192));
        // Fresh finality → no hunt.
        assert!(!hunt_due(false, true, z, z, wall, period, wall - 64, epoch, 8192));

        // PROGRESSING catch-up (period behind, store advancing) → no hunt:
        // catch-up's own wide fan-out covers the pool; hunting double-dials.
        assert!(!hunt_due(false, true, z, z, wall, period - 1, wall - slack - 1, epoch, 8192));
        // STARVED catch-up (no store progress past the stall window) → hunt.
        assert!(hunt_due(false, true, z, HUNT_CATCHUP_STALL, wall, period - 1,
            wall - slack - 1, epoch, 8192));
        // ...and an ENGAGED hunt survives the period boundary the same way
        // (finality starvation rotating into catch-up must not disengage).
        assert!(hunt_due(true, true, z, HUNT_CATCHUP_STALL, wall, period - 1,
            wall - slack - 1, epoch, 8192));

        // Hysteresis on the finality trigger: at staleness between the
        // engaged and disengaged thresholds, an engaged hunt stays on and a
        // disengaged one stays off (no flapping at the boundary).
        let between = wall - slack + epoch - 1; // stale by SLACK-1 epochs + 1 slot
        assert!(hunt_due(true, true, z, z, wall, period, between, epoch, 8192));
        assert!(!hunt_due(false, true, z, z, wall, period, between, epoch, 8192));
    }

    #[test]
    fn proven_tier_orders_by_serve_recency() {
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..4u8 {
            let kp = libp2p::identity::Keypair::generate_secp256k1();
            let id = kp.public().to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.1.{i}/tcp/9000").parse().unwrap());
        }
        // Three proven servers; ids[1] served longest ago, ids[3] most recently,
        // ids[0] is proven but never served (Identify-confirmed only via
        // mark_proven from an earlier session's cache seed, say).
        for id in [ids[0], ids[1], ids[3]] {
            pool.mark_proven(id);
        }
        pool.note_served(ids[1]);
        // Instant::now() can be coarse (Windows ~15ms ticks); equal timestamps
        // would stable-sort back to pool order and flake the assertion below.
        let t0 = std::time::Instant::now();
        while std::time::Instant::now() == t0 {
            std::hint::spin_loop();
        }
        pool.note_served(ids[3]); // strictly later ⇒ more recent

        let c = pool.candidates(4, false, false, &HashSet::new(), &HashSet::new());
        // Most-recently-served proven first, then older serves, then the
        // never-served proven peer, then the unproven rest.
        assert_eq!(c[0].id, ids[3], "most recent server leads the batch");
        assert_eq!(c[1].id, ids[1], "older server second");
        assert_eq!(c[2].id, ids[0], "never-served proven after recent servers");
        assert_eq!(c[3].id, ids[2], "unproven peer last");
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

    #[test]
    fn static_peers_are_never_evicted() {
        // Issue #291: a pinned LC server must survive transient failures — it
        // is loaded once and nothing re-adds it, so eviction is permanent loss.
        let mut pool = PeerPool::new();
        let stat = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        let disc = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        pool.add_static(stat, "/ip4/10.0.0.1/tcp/9000".parse().unwrap());
        pool.add(disc, "/ip4/10.0.0.2/tcp/9000".parse().unwrap());
        assert_eq!(pool.len(), 2);

        // Far more failures than any threshold: the static peer stays put (and
        // stays `known`, so it is not treated as re-discoverable-only), while
        // the ordinary discovered peer is evicted on its first strike.
        for _ in 0..10 {
            pool.note_failure(stat);
        }
        pool.note_failure(disc);
        assert!(pool.known.contains(&stat), "static peer stays known");
        assert!(pool.peers.iter().any(|p| p.id == stat), "static peer stays pooled");
        assert!(!pool.peers.iter().any(|p| p.id == disc), "discovered peer evicted");
        assert_eq!(pool.len(), 1);

        // It is still handed out as a candidate after all those failures.
        let c = pool.candidates(4, true, false, &HashSet::new(), &HashSet::new());
        assert!(c.iter().any(|p| p.id == stat), "static peer still a candidate");
    }

    #[test]
    fn static_peers_are_never_denied_nolc() {
        // Issue #291 follow-up: static peers are un-evictable, and eviction is
        // what clears the nolc deny flag for ordinary peers — so a static peer
        // must never enter the deny set at all, or a transient strike (or a
        // stale cache flag replayed at startup) would be permanently sticky and
        // drop the curated server out of the skip_no_lc tiers.
        let mut pool = PeerPool::new();
        let stat = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        let disc = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        pool.add_static(stat, "/ip4/10.0.3.1/tcp/9000".parse().unwrap());
        pool.add(disc, "/ip4/10.0.3.2/tcp/9000".parse().unwrap());

        // The mark is a no-op for the static peer, effective for the ordinary one.
        pool.mark_no_lc_updates(stat);
        pool.mark_no_lc_updates(disc);
        assert!(!pool.no_lc_updates.contains(&stat), "static peer never denied");
        assert!(pool.no_lc_updates.contains(&disc), "ordinary peer denied");

        // With skip_no_lc on, the static peer survives the filter; the denied
        // ordinary peer only comes back via the soft-filter fallback.
        let c = pool.candidates(1, true, false, &HashSet::new(), &HashSet::new());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].id, stat, "static peer preferred over the denied peer");
    }

    #[test]
    fn static_peer_address_refreshes_on_rediscovery() {
        // PR #322 review: a static peer is un-evictable, so an operator IP
        // change can only reach the pool through add()'s in-place refresh —
        // otherwise the entry is dialed at the stale address forever.
        let mut pool = PeerPool::new();
        let stat = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        let disc = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        pool.add_static(stat, "/ip4/10.0.4.1/tcp/9000".parse().unwrap());
        pool.add(disc, "/ip4/10.0.4.2/tcp/9000".parse().unwrap());

        // Discovery re-reports both at a new address (same PeerId, new /ip4/…).
        pool.add(stat, "/ip4/198.51.100.7/tcp/9000".parse().unwrap());
        pool.add(disc, "/ip4/198.51.100.8/tcp/9000".parse().unwrap());

        let addr_of = |pool: &PeerPool, id| {
            pool.peers.iter().find(|p| p.id == id).map(|p| p.addr.to_string()).unwrap()
        };
        assert_eq!(addr_of(&pool, stat), "/ip4/198.51.100.7/tcp/9000",
            "static peer address refreshed in place");
        assert_eq!(addr_of(&pool, disc), "/ip4/10.0.4.2/tcp/9000",
            "ordinary peer keeps its first address (self-heals via evict instead)");
        assert_eq!(pool.len(), 2, "no duplicate entries");
    }

    #[test]
    fn clear_no_lc_returns_the_ids_it_cleared() {
        // The reconcile call sites persist the reversal to the shared cache
        // using exactly the ids clear_no_lc reports as cleared.
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let id = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.5.{i}/tcp/9000").parse().unwrap());
            pool.mark_no_lc_updates(id);
        }
        let servers: HashSet<PeerId> = [ids[0], ids[2]].into_iter().collect();
        let mut cleared = pool.clear_no_lc(&servers);
        cleared.sort();
        let mut want = vec![ids[0], ids[2]];
        want.sort();
        assert_eq!(cleared, want, "returns exactly the cleared ids");
        assert!(pool.cache_key(&ids[0]).is_some(), "cleared id maps to a cache key");
        // Idempotent: nothing left to clear for the same set.
        assert!(pool.clear_no_lc(&servers).is_empty());
    }

    #[test]
    fn nolc_verdict_is_reversible() {
        // Issue #291: an authoritative positive LC signal (Identify / a fresh
        // serve) must clear a stale nolc strike, or a transiently-mismarked
        // server is filtered out of every catch-up tier for the process life.
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let id = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.2.{i}/tcp/9000").parse().unwrap());
        }
        // All three transiently mark nolc.
        for id in &ids {
            pool.mark_no_lc_updates(*id);
        }
        assert!(pool.no_lc_updates.contains(&ids[0]));

        // Identify (via clear_no_lc) re-confirms ids[0] and ids[1] as servers.
        let confirmed: HashSet<PeerId> = [ids[0], ids[1]].into_iter().collect();
        pool.clear_no_lc(&confirmed);
        assert!(!pool.no_lc_updates.contains(&ids[0]), "confirmed server un-denied");
        assert!(!pool.no_lc_updates.contains(&ids[1]), "confirmed server un-denied");
        assert!(pool.no_lc_updates.contains(&ids[2]), "unconfirmed peer still denied");

        // A verified serve on ids[2] clears its flag too (mark_proven path).
        pool.mark_proven(ids[2]);
        assert!(!pool.no_lc_updates.contains(&ids[2]), "served peer un-denied");

        // With the deny set empty, the skip_no_lc filter no longer drops them.
        let c = pool.candidates(3, true, false, &HashSet::new(), &HashSet::new());
        assert_eq!(c.len(), 3, "all three rejoin the fan-out once un-denied");
    }
}
