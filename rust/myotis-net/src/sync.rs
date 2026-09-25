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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::stream::{FuturesUnordered, StreamExt};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, watch};

use myotis_consensus::fork::ForkSchedule;
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

/// Whether an anchor is past the weak-subjectivity bound. Saturating: a wall
/// clock BEHIND the anchor (skew) reads as fresh — a backwards clock can only
/// make the check more permissive, and the device clock is outside this
/// threat model.
pub fn ws_anchor_stale(anchor_period: u64, wall_clock_period: u64, bound_periods: u64) -> bool {
    wall_clock_period.saturating_sub(anchor_period) > bound_periods
}

/// Live weak-subjectivity knobs, shared between the host FFI and the running
/// sync loop: `ChainConfig` is deep-cloned into the loop at start, but this
/// sits behind an `Arc`, so a host-side write reaches a loop already parked in
/// `StaleAnchor` (the park re-reads both every second). Mirrors the Java
/// engine's `BeaconLightClient` volatiles.
#[derive(Debug, Default)]
pub struct WsPolicy {
    /// Host override for the anchor-age bound (periods); 0 = use the network
    /// default (`ChainConfig::ws_bound_periods`).
    pub bound_override_periods: AtomicU64,
    /// One-shot consent to sync forward from a stale anchor. Per-run: never
    /// persisted, so a restart with a still-stale anchor parks again.
    pub accept_stale_anchor: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub name: &'static str,
    /// The EL chain id (EIP-155) — threaded into the EVM reads (eth_call /
    /// estimateGas / ENS) so nothing downstream hardcodes a network.
    pub chain_id: u64,
    /// The chain's full fork schedule — `(activation epoch, fork version)`,
    /// ascending, genesis first. Every sync-committee signature is verified
    /// under the version active at its `signature_slot`, so the store can walk
    /// updates across a fork boundary (#295); the entry active at the
    /// wall-clock epoch feeds the fork digest, so the NEXT fork may be pinned
    /// ahead of activation. Append-only, consensus-critical, same trust standing as
    /// `genesis_validators_root`: pinned from the network's published config
    /// (`/eth/v1/config/fork_schedule`), never fetched at runtime. Keep in
    /// lockstep with the Java `NetworkConfig.forkSchedule` — both sides pin
    /// the same lists in their config tests.
    pub fork_schedule: ForkSchedule,
    /// Whether the PRIOR fork's digest is accepted as a discv5 fork-digest
    /// fallback next to the current one (the Java
    /// `NetworkConfig.acceptedForkDigests`). Off for mainnet and sepolia (stale
    /// digests wouldn't help us sync); on for gnosis. A policy knob, not a
    /// fork version — the version itself comes from the schedule.
    pub accept_prior_fork_digest: bool,
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
    /// Default weak-subjectivity bound (sync-committee periods): how old the
    /// sync anchor (embedded checkpoint or persisted snapshot, whichever is
    /// newer) may be before the sync loop refuses it and parks in
    /// `SyncState::StaleAnchor` awaiting explicit consent. Keep in lockstep
    /// with the Java `NetworkConfig.wsBoundPeriods()` (the derivations are
    /// documented there).
    pub ws_bound_periods: u64,
    /// Live host overrides for the bound + the stale-anchor consent (see
    /// [`WsPolicy`]). Shared across config clones.
    pub ws_policy: Arc<WsPolicy>,
}

impl ChainConfig {
    /// Slots per sync-committee period — the geometry every period division uses.
    pub fn slots_per_period(&self) -> u64 {
        // CHECKED, not saturating. Saturating would turn an overflowing config
        // into u64::MAX, which puts every real slot in period 0 — a wrong
        // committee for every update, silently. Both factors are compile-time
        // constants in every shipped config, so a panic here is a build error
        // surfacing, never a runtime condition.
        // The fork schedule carries its own copy of slots_per_epoch (it maps
        // signature slots to epochs); the Java NetworkConfig refuses a
        // mismatch in its constructor and this is the Rust twin of that check,
        // on the accessor every period division goes through.
        assert_eq!(
            self.fork_schedule.slots_per_epoch(),
            self.slots_per_epoch,
            "{}: fork_schedule geometry must match the chain's slots_per_epoch",
            self.name
        );
        self.slots_per_epoch
            .checked_mul(self.epochs_per_sync_committee_period)
            .filter(|p| *p > 0)
            .expect("chain geometry must be non-zero and must not overflow")
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
        // One binding for both the period math and the schedule's slot->epoch map.
        let slots_per_epoch: u64 = 32;
        Self {
            name: "mainnet",
            chain_id: 1,
            // consensus-specs configs/mainnet.yaml *_FORK_EPOCH / *_FORK_VERSION.
            // Fulu activated at epoch 411392 = slot 13164544 (2025-12-03).
            fork_schedule: ForkSchedule::new(slots_per_epoch, &[
                (0, [0x00, 0x00, 0x00, 0x00]),       // phase0 (genesis)
                (74_240, [0x01, 0x00, 0x00, 0x00]),  // altair
                (144_896, [0x02, 0x00, 0x00, 0x00]), // bellatrix
                (194_048, [0x03, 0x00, 0x00, 0x00]), // capella
                (269_568, [0x04, 0x00, 0x00, 0x00]), // deneb
                (364_032, [0x05, 0x00, 0x00, 0x00]), // electra
                (411_392, [0x06, 0x00, 0x00, 0x00]), // fulu
            ]),
            accept_prior_fork_digest: false,
            genesis_validators_root: hex32(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
            genesis_time: 1_606_824_023, // 2020-12-01 12:00:23 UTC
            seconds_per_slot: 12,
            slots_per_epoch,
            epochs_per_sync_committee_period: 256,
            // BPO2 (Fusaka) blob schedule entry: epoch 419072, MAX_BLOBS=21.
            blob_params_epoch: 419_072,
            blob_params_max_blobs: 21,
            // Mirrors the @checkpoint:mainnet region of NetworkConfig.java;
            // `./gradlew refreshCheckpoint` rewrites both from one fetch, and
            // `java_and_rust_checkpoints_agree` fails if they ever diverge.
            // @checkpoint:mainnet:begin — managed by `./gradlew refreshCheckpoint`
            // trusted checkpoint: recent finalized mainnet block root (slot 15285056, 2026-09-24, period 1865)
            checkpoint_root: hex32(
                "4f4b89524600b09292365d29f2e9266e7a004b27bccf7ed31655b88851045028",
            ),
            checkpoint_slot: 15_285_056,
            // @checkpoint:mainnet:end
            static_peers: MAINNET_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
            bootstrap_enrs: MAINNET_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
            discv5_port: 0,
            snapshot_path: None,
            cl_peer_cache_path: None,
            ws_bound_periods: 13, // spec WS plateau 3532 epochs / 256 = 13.8 -> floor 13 (~14.7 days)
            ws_policy: Arc::new(WsPolicy::default()),
        }
        .with_env_overrides()
    }

    /// Sepolia — values duplicated verbatim from the Java
    /// `NetworkConfig.SEPOLIA` (networking/src/main/java/.../NetworkConfig.java),
    /// whose sepolia CL wiring landed in PR #192.
    pub fn sepolia() -> Self {
        // One binding for both the period math and the schedule's slot->epoch map.
        let slots_per_epoch: u64 = 32;
        Self {
            name: "sepolia",
            chain_id: 11_155_111,
            // eth-clients/sepolia metadata/config.yaml *_FORK_EPOCH / *_FORK_VERSION.
            // Fulu (0x90000075) activated at epoch 272640 (2025-10-14).
            fork_schedule: ForkSchedule::new(slots_per_epoch, &[
                (0, [0x90, 0x00, 0x00, 0x69]),       // phase0 (genesis)
                (50, [0x90, 0x00, 0x00, 0x70]),      // altair
                (100, [0x90, 0x00, 0x00, 0x71]),     // bellatrix
                (56_832, [0x90, 0x00, 0x00, 0x72]),  // capella
                (132_608, [0x90, 0x00, 0x00, 0x73]), // deneb
                (222_464, [0x90, 0x00, 0x00, 0x74]), // electra
                (272_640, [0x90, 0x00, 0x00, 0x75]), // fulu
            ]),
            // No prior-fork fallback (same rationale as mainnet: stale digests
            // wouldn't help us sync to the current head anyway).
            accept_prior_fork_digest: false,
            genesis_validators_root: hex32(
                "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
            ),
            genesis_time: 1_655_733_600, // 2022-06-20 14:00:00 UTC
            seconds_per_slot: 12, // mainnet preset
            slots_per_epoch,
            epochs_per_sync_committee_period: 256,
            // EIP-7892 BLOB_SCHEDULE — latest active entry on sepolia: BPO2 at
            // epoch 275712, MAX_BLOBS_PER_BLOCK=21 (2025-10-28).
            blob_params_epoch: 275_712,
            blob_params_max_blobs: 21,
            // Mirrors the @checkpoint:sepolia region of NetworkConfig.java;
            // `./gradlew refreshCheckpoint` rewrites both from one fetch, and
            // `java_and_rust_checkpoints_agree` fails if they ever diverge.
            //
            // DURABLE CONSTRAINT (survives every refresh, so it lives outside the
            // rewritten region): this pin must stay NEWER than the dedicated
            // serving node's trustedNodeSync point, or that node cannot answer
            // the bootstrap for it (docs/dedicated-sepolia-node.md §5).
            // @checkpoint:sepolia:begin — managed by `./gradlew refreshCheckpoint`
            // trusted checkpoint: recent finalized sepolia block root (slot 11209280, 2026-09-24, period 1368)
            checkpoint_root: hex32(
                "d9d8f57adb4ad2053a191dd566f5fb75722c09c531fb833a27cee23f077d3b36",
            ),
            checkpoint_slot: 11_209_280,
            // @checkpoint:sepolia:end
            static_peers: SEPOLIA_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
            bootstrap_enrs: SEPOLIA_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
            discv5_port: 0,
            snapshot_path: None,
            cl_peer_cache_path: None,
            ws_bound_periods: 13, // permissioned validator set; mainnet-preset bound kept as hygiene
            ws_policy: Arc::new(WsPolicy::default()),
        }
        .with_env_overrides()
    }

    /// Gnosis Chain — values duplicated verbatim from the Java
    /// `NetworkConfig.GNOSIS`. Its own beacon chain: 5 s slots, 16-slot epochs
    /// (still 8192 slots per sync-committee period: 512 epochs × 16), and a
    /// prior-fork digest fallback (Electra) accepted alongside the Fulu digest.
    pub fn gnosis() -> Self {
        // One binding for both the period math and the schedule's slot->epoch map.
        let slots_per_epoch: u64 = 16;
        Self {
            name: "gnosis",
            chain_id: 100,
            // gnosischain/configs mainnet/config.yaml *_FORK_EPOCH / *_FORK_VERSION
            // (16-slot epochs). Fulu (0x06000064) active since epoch 1714688
            // (2026-04-14); Electra's epoch is also the blob_params_epoch below.
            fork_schedule: ForkSchedule::new(slots_per_epoch, &[
                (0, [0x00, 0x00, 0x00, 0x64]),         // phase0 (genesis)
                (512, [0x01, 0x00, 0x00, 0x64]),       // altair
                (385_536, [0x02, 0x00, 0x00, 0x64]),   // bellatrix
                (648_704, [0x03, 0x00, 0x00, 0x64]),   // capella
                (889_856, [0x04, 0x00, 0x00, 0x64]),   // deneb
                (1_337_856, [0x05, 0x00, 0x00, 0x64]), // electra
                (1_714_688, [0x06, 0x00, 0x00, 0x64]), // fulu
            ]),
            // Electra's digest is accepted as a discv5 fork-digest fallback.
            accept_prior_fork_digest: true,
            genesis_validators_root: hex32(
                "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47",
            ),
            genesis_time: 1_638_993_340, // 2021-12-08 19:55:40 UTC
            seconds_per_slot: 5,
            slots_per_epoch,
            epochs_per_sync_committee_period: 512,
            // EIP-7892: Gnosis has no explicit BLOB_SCHEDULE — clients fold the
            // Electra-baseline params (ELECTRA_FORK_EPOCH=1337856, MAX_BLOBS=2)
            // into the Fulu digest. Yields the live-verified digest 0x3237dab6.
            blob_params_epoch: 1_337_856,
            blob_params_max_blobs: 2,
            // Mirrors the @checkpoint:gnosis region of NetworkConfig.java;
            // `./gradlew refreshCheckpoint` rewrites both from one fetch, and
            // `java_and_rust_checkpoints_agree` fails if they ever diverge.
            //
            // DURABLE CONSTRAINT (survives every refresh, so it lives outside the
            // rewritten region): the anchor must sit INSIDE the period window
            // roost@gnosis can serve. An earlier anchor sat 116 periods below
            // roost's floor, and roost's archive only grows FORWARD from where it
            // started, so no amount of waiting closes such a gap — a wallet
            // bootstrapping from it gets ResourceUnavailable forever. The window
            // is [floor, head]: anchor at head (the task's default) for a release —
            // roost fetches an unseen head root on demand, and the weak-
            // subjectivity gate (`ws_bound_periods` below, 3 here) refuses
            // anything older than a few periods anyway — and use `-Pperiod=<n>`
            // only to pin a retained state for testing, never one below the floor.
            // @checkpoint:gnosis:begin — managed by `./gradlew refreshCheckpoint`
            // trusted checkpoint: recent finalized gnosis block root (slot 30250464, 2026-09-24, period 3692)
            checkpoint_root: hex32(
                "8cf978da4e896b02351fe9669d0ac82b601174bd6a413c7c975ae1a611bc29f9",
            ),
            checkpoint_slot: 30_250_464,
            // @checkpoint:gnosis:end
            static_peers: GNOSIS_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
            bootstrap_enrs: GNOSIS_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
            discv5_port: 0,
            snapshot_path: None,
            cl_peer_cache_path: None,
            ws_bound_periods: 3, // short churn window (see NetworkConfig.wsBoundPeriods) — pragmatic floor
            ws_policy: Arc::new(WsPolicy::default()),
        }
        .with_env_overrides()
    }

    /// The shipped config whose chain matches this `genesis_validators_root`,
    /// or None for a chain this build does not know.
    ///
    /// For consumers that learn their chain from a live source instead of
    /// being configured with one — `rust/roost` reads the root from its
    /// upstream and needs the matching discv5 bootstrap ENRs to join the DHT
    /// (#335). Keying by the root rather than by a name keeps it ONE list per
    /// network (this file's), not a second one rotting on roost's schedule.
    ///
    /// Note the constructors apply the usual env overrides, so
    /// `MYOTIS_CL_DISABLE_DISCV5=1` empties `bootstrap_enrs` here too — the
    /// consistent reading of "disable discv5" for any process honoring it.
    pub fn for_genesis(genesis_validators_root: &[u8; 32]) -> Option<Self> {
        [Self::mainnet(), Self::sepolia(), Self::gnosis()]
            .into_iter()
            .find(|c| &c.genesis_validators_root == genesis_validators_root)
    }

    /// Fork digests accepted when filtering discv5 ENRs — current first, then
    /// the prior fork's when configured (`NetworkConfig.acceptedForkDigests`).
    pub fn accepted_fork_digests(&self) -> Vec<[u8; 4]> {
        let mut out = vec![self.current_fork_digest()];
        // KNOWN LIMIT (Java twin `NetworkConfig.acceptedForkDigests` carries the
        // same note): the prior digest is the plain pre-EIP-7892 form, which is
        // what Electra-era peers advertise (gnosis today: 0x7D5AAB40). Once the
        // prior fork is Fulu or later, stale peers advertise the BPO-FOLDED
        // digest of their era, so this fallback matches nobody (fail-safe, never
        // a wrong acceptance). Folding it needs the blob-params entry active in
        // the prior fork's era — the blob-schedule follow-up deferred in PR #430.
        if let Some(prior) = self.prior_fork_version() {
            out.push(fork_digest(prior, self.genesis_validators_root));
        }
        out
    }

    /// The fork version active NOW — the digest input (discv5 filter, Status).
    /// Read from the schedule at the wall-clock epoch, so the next fork can be
    /// pinned ahead of its activation without flipping the digest early (a
    /// not-yet-active digest matches no peer). NOT a signing-domain input:
    /// verification reads the schedule per update
    /// (`ForkSchedule::version_for_signature_slot`).
    pub fn current_fork_version(&self) -> [u8; 4] {
        self.fork_schedule.version_at_epoch(self.wall_clock_epoch())
    }

    /// The version of the fork before the active one when its digest is
    /// accepted (`accept_prior_fork_digest`), else `None`.
    pub fn prior_fork_version(&self) -> Option<[u8; 4]> {
        if self.accept_prior_fork_digest {
            self.fork_schedule.prior_version_at_epoch(self.wall_clock_epoch())
        } else {
            None
        }
    }

    /// Wall-clock beacon epoch (Java twin: `NetworkConfig.wallClockEpoch`).
    pub fn wall_clock_epoch(&self) -> u64 {
        self.current_slot_estimate() / self.slots_per_epoch.max(1)
    }

    pub fn current_fork_digest(&self) -> [u8; 4] {
        fork_digest_bpo(
            self.current_fork_version(),
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

    /// The weak-subjectivity bound actually enforced: the live host override
    /// when set (> 0), else this network's default.
    pub fn effective_ws_bound_periods(&self) -> u64 {
        let overridden = self.ws_policy.bound_override_periods.load(Ordering::Relaxed);
        if overridden > 0 {
            overridden
        } else {
            self.ws_bound_periods
        }
    }

    /// Wall-clock slot estimate, for callers outside this crate that must judge
    /// a slot against "now" (the host refuses a caller-supplied checkpoint from
    /// the future). Same clock read as everything else here.
    pub fn wall_clock_slot(&self) -> u64 {
        self.current_slot_estimate()
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
/// ADDRESS: every roost/zbox literal below is the netcup relay (188.68.32.16, a
/// static VPS). zbox itself sits behind mobile CGNAT and is reachable only via
/// a WireGuard tunnel that DNATs the serving ports to it, so its own uplink
/// rotating no longer moves these pins. The earlier "DynDNS name last, literal
/// first" pair (name for self-healing, literal for the unverified Java DNS
/// path) went with it: one literal per peer id, identical on both engines.

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
    // first. The census-verified public servers below it are the fallback,
    // so a roost fault degrades to working peers rather than to nothing.
    //
    // Its peer id comes from /data/roost/sepolia.key and is stable across
    // restarts by construction — roost has no mode in which it mints a
    // fresh one.
    //
    // The address is the netcup relay (see the ADDRESS note above); ENR
    // publication (design §7) is what removes the need to pin at all.
    "/ip4/188.68.32.16/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5",
    // Public sepolia LC servers, census-verified 2026-09-11: each answered
    // light_client_bootstrap for the THEN-pinned root AND
    // updates_by_range(1356,1) from a fresh peer id, all Lighthouse v8.2.2 (so
    // the catch-up asks them for one period at a time — see
    // agent_serves_one_period).
    //
    // Re-verified 2026-09-12 at period 1357, the anchor then embedded, by the
    // release's live_pins_alive run on a clean CI host: 4 of 4 pins, roost
    // included, served a bootstrap for that root and a period of updates.
    // Re-verified 2026-09-13 against the then-shipped period-1358 anchor:
    // live_pins_alive run 34776027257, 4 of 4 again.
    // Re-verified 2026-09-16 against the then-shipped period-1361 anchor:
    // live_pins_alive run 35065049320 on a GitHub-hosted runner, 4 of 4
    // again; the bootnodes seeded discv5 (20 entries, SYNCED), and a cold start
    // from the recorded period-1323 anchor reached SYNCED in 55 s.
    // Re-verified 2026-09-21 against the then-shipped period-1365 anchor:
    // live_pins_alive run 35616060242 on a GitHub-hosted runner, 4 of 4
    // again; the bootnodes seeded discv5 (20 entries, SYNCED), and a cold start
    // from the recorded period-1323 anchor (42 periods behind) reached SYNCED
    // in 21 s.
    // Re-verified 2026-09-24 against the anchor this build ships (period
    // 1368): live_pins_alive run 35989152817 on a GitHub-hosted runner, 4 of 4
    // again; the bootnodes seeded discv5 (23 entries, SYNCED), and a cold start
    // from the recorded period-1323 anchor (45 periods behind) reached SYNCED
    // in 55 s.
    // Re-run it after every checkpoint refresh — a census against
    // a superseded root says nothing about the anchor a fresh install actually
    // starts from, which is the #422 shape: every check green while no pinned
    // server can answer for the root being shipped.
    //
    // They replace
    // two dead pins: the zbox Nimbus behind the relay (9104: TCP accepts, the
    // libp2p handshake times out — the tunnel's far end is not answering) and
    // 18.185.193.198 (TCP timeout for days). A dead pin is not free: with
    // roost sepolia switched off as well, the bootstrap fan-out spent 82
    // rounds on three unreachable pins while a wallet sat in SYNCING.
    "/ip4/65.109.144.95/tcp/9000/p2p/16Uiu2HAkwKbnJCnfFsNGjGd5TURbXyNBdTWoVZjw8jqiCEf47gc2",
    "/ip4/138.201.192.180/tcp/9000/p2p/16Uiu2HAmNHPaVrDFi7zVnEd9vhSHy9e4a5eF5a3aBxNXPPAucWbE",
    "/ip4/198.13.138.237/tcp/9000/p2p/16Uiu2HAmMb2mLN12B5vnJGv2LMuXxKsAiKQ8yTdy5gSJY1zKgE5f",
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
    // roost sepolia (this project's dedicated LC server) — a SNAPSHOT of its
    // published record (2026-09-06, from behind the netcup relay): seeding it
    // makes roost dialable from the first table without waiting for any walk.
    // The relay address is static, so the only way the embedded IP goes stale
    // is an operator-driven relay move; the targeted-lookup path (node_id
    // derived from the position-0 static peer pin,
    // `discovery::node_id_for_peer`) is what recovers the CURRENT record then.
    "enr:-KG4QOZNbpU9w2wGBTa5tMaJKfLFOBvygYCYCtSewcQcXnWnNLbuZFar-gCtb70gJTLrAki7efXD5yBj1tSXOEBgul4HhGV0aDKQdNAUWZAAAHX__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaECOGinXjNuey5xwLNiO0Cd-MB7I3zLqCC5rbLWG6Bo9rqDdGNwgiORg3VkcIIjkQ",
];

/// Pinned Gnosis LC-serving peer multiaddrs (Java `NetworkConfig.GNOSIS.clPeerMultiaddrs`
/// — keep the two lists and their ORDER in step; both parity tests pin the full
/// strings). Identify-confirmed LC servers harvested from a long-running desktop
/// profile's cl-peers-gnosis.cache (2026-08-06, issue #291): a cold Gnosis pool
/// starves catch-up because so few nodes serve light-client data, so a fresh
/// install gets a serving head start. Re-censused 2026-09-13 and cut from 22
/// harvested entries to the 7 that still serve catch-up (evidence below).
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
    "/ip4/188.68.32.16/tcp/9108/p2p/16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh",
    // Re-censused 2026-09-13 like mainnet, against period 3666 (v0.1.9's anchor
    // until the rebase re-anchored it to 3670) and period 3663: live_pins_alive on
    // GitHub-hosted runners (run 34660358795 on 2026-09-12 at 3666, run
    // 34764525187 on 2026-09-13 at 3663) and, from a residential address, a
    // one-pin-at-a-time probe plus period_census. The seven kept are
    // Lighthouse v8.2.x whose Identify advertises light_client_updates_by_range;
    // each served the 2026-09-12 runner run and the residential probe in full,
    // the period-3666 bootstrap and a 507/512 updates_by_range(3666,1)
    // included. The two on :9500 (134.65.194.144, 164.152.161.131) timed out on
    // the 2026-09-13 runner run, then served the residential probe in full; one
    // slow run is not grounds to prune.
    // Re-verified 2026-09-13 against the then-shipped period-3670 anchor:
    // live_pins_alive run 34776024335 on a GitHub-hosted runner, 8 of 8
    // served it, both :9500 pins included.
    // Re-verified 2026-09-16 against the then-shipped period-3675 anchor:
    // live_pins_alive run 35065032444 on a GitHub-hosted runner, 8 of 8
    // again, both :9500 pins included; the bootnodes seeded discv5 (21
    // entries, SYNCED), and a cold start from the recorded period-3596 anchor
    // (79 periods behind) reached SYNCED in 85 s.
    // Re-verified 2026-09-21 against the then-shipped period-3686 anchor:
    // live_pins_alive run 35616052466 on a GitHub-hosted runner, 8 of 8
    // again, both :9500 pins included; the bootnodes seeded discv5 (21
    // entries, SYNCED), and a cold start from the recorded period-3596 anchor
    // (90 periods behind) reached SYNCED in 76 s.
    // Re-verified 2026-09-24 against the anchor this build ships (period
    // 3692): live_pins_alive run 35988128286 on a GitHub-hosted runner, 6 of 8
    // — both :9500 pins (134.65.194.144, 164.152.161.131) failed to dial from
    // the runner. One run from one vantage point, and the pair has timed out
    // on a runner before (2026-09-13) and served every run since, so this is
    // a re-census signal, not grounds to prune; the floor is two pins. The
    // bootnodes seeded discv5 (25 entries), and a cold start from the
    // recorded period-3596 anchor (96 periods behind) reached SYNCED in 55 s.
    "/ip4/134.65.194.144/tcp/9500/p2p/16Uiu2HAmLZasEWSgafRb5hqW5M2jSN7YcERyVQ81AeCGCFZmynsQ",
    "/ip4/144.76.118.19/tcp/9000/p2p/16Uiu2HAmEJpzjSyajPJzzrN8TnV1VaNMaEecQo1v4Mkedwb6UYwE",
    "/ip4/144.76.163.174/tcp/9000/p2p/16Uiu2HAkxLFxkn7MbAPH17VdwEvXytqgteNAr52AaqKYuEmsw2bt",
    "/ip4/148.251.181.49/tcp/9000/p2p/16Uiu2HAmAWrwxf2murYQp1tdbwKbFwqUiVofwJ3xgJP5T7BLSpRa",
    "/ip4/148.251.235.60/tcp/9001/p2p/16Uiu2HAmTeAHEG2tCFgC5RmrjZcw6zGeCgnE5svqM4528R5inSjA",
    "/ip4/159.195.138.9/tcp/9000/p2p/16Uiu2HAmUimXaHiCvWhx2YuvwTkDLtca6oq1bCH85Eb6JcEYiaGi",
    "/ip4/164.152.161.131/tcp/9500/p2p/16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw",
    // Pruned 2026-09-13 (15 of the 22):
    //  - Ten that serve nothing: refusing TCP (104.37.190.86, 136.243.146.247,
    //    146.70.243.142), unreachable (148.56.243.210, and 144.76.106.139, whose
    //    TCP connect times out), accepting TCP but closing or stalling before
    //    the handshake completes (146.103.38.79, 159.195.30.80), a different
    //    peer id at the pinned address (138.201.196.44), or closing the
    //    connection before answering from BOTH vantage points (141.94.46.9, and
    //    148.251.184.20, an Erigon/Caplin v3.6.0 node).
    //  - Five Lighthouse v8.1.3 nodes (135.129.103.34, 135.148.35.18,
    //    144.76.164.21, 148.251.237.209, 144.76.196.184) that serve bootstrap,
    //    finality and optimistic updates but NOT updates_by_range: Identify
    //    does not advertise it and negotiating it fails. They can anchor a
    //    fresh install but never advance it — catch-up is what a gnosis pin is
    //    for, and live_pins_alive counts each of them as not alive. Pinned,
    //    they also cost the Rust catch-up a little: pins are exempt from the
    //    no-LC denial (`PeerPool::mark_no_lc_updates` skips static ids, on the
    //    premise that pins serve light-client data), so catch-up re-asks each
    //    one whenever its 11 s cooldown lapses, from the top tier once it has
    //    served a bootstrap or a finality update (`mark_proven`). Each ask
    //    fails fast at negotiation. Unpinned, one failure denies such a peer
    //    for catch-up while bootstrap and finality rounds, which ignore the
    //    denial, keep using it; the Java engine skips it for catch-up whenever
    //    its Identify is known (`servesLightClientUpdates`), pinned or not.
    //    What dropping them costs is redundancy: 8 bootstrap- and
    //    finality-serving pins where there were 13. Pinning such a server at
    //    no catch-up cost would take the pool denying a pin whose live Identify
    //    lacks updates_by_range, as the Java engine effectively does.
    //    (144.76.196.184 also closed the connection on both runner runs, yet
    //    answered the residential probe's bootstrap, finality and optimistic
    //    requests.)
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
    // roost gnosis (this project's dedicated LC server) — a SNAPSHOT of its
    // published record (2026-09-06, from behind the netcup relay): seeding it
    // makes roost dialable from the first table without waiting for any walk.
    // The relay address is static, so the only way the embedded IP goes stale
    // is an operator-driven relay move; the targeted-lookup path (node_id
    // derived from the position-0 static peer pin,
    // `discovery::node_id_for_peer`) is what recovers the CURRENT record then.
    "enr:-KG4QCjwDSRCD6CysnECiWR9i6LBDoETDWI-0zU9bHBbFvgwKHZBGM4LBOBLl15zPJdgPePLlUNJrcbO8l9CGY6aagQHhGV0aDKQMjfatgYAAGT__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaEDM0NY9iNV9hZMrtkoRrPEKj7tm2TLriwZv-m1ctszvvKDdGNwgiOUg3VkcIIjlA",
];

/// Known light-client-serving mainnet peers — mirrored with the Java
/// `NetworkConfig.MAINNET` clPeerMultiaddrs list (same entries, same order;
/// both parity tests pin the full strings). Provenance: originally discovered
/// via the Lighthouse peer API 2026-03-11, re-censused via period_census
/// 2026-09-01 (#410), re-verified and pruned 2026-09-02 (#411), re-censused and
/// pruned again 2026-09-13 (per-entry evidence in the comments below).
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
    // The address is the netcup relay (see the ADDRESS note above); ENR
    // publication (docs/lc-server-design.md §7) is what removes the need to
    // pin at all. Recovery from a RELAY move is operator-driven, not automatic:
    // behind the tunnel the address is configuration on both ends (this pin
    // and the upstream Nimbus's --nat=extip), and roost takes its external
    // address from that upstream's ENR (rust/roost/src/serve.rs,
    // track_upstream_ip) — so repoint Nimbus, roost republishes with a bumped
    // seq, then refresh this pin and the bootstrap ENR below.
    "/ip4/188.68.32.16/tcp/9109/p2p/16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
    // Re-censused 2026-09-13 against period 1854 (v0.1.9's anchor until the
    // rebase re-anchored it to 1856) and period 1853, from two vantage points:
    // live_pins_alive on GitHub-hosted runners (run 34660361028 on 2026-09-12
    // at 1854, run 34764523424 on 2026-09-13 at 1853) and, from a residential
    // address, a one-pin-at-a-time probe of bootstrap, finality, optimistic and
    // updates_by_range plus examples/period_census.rs. Each entry below served
    // that probe everything, the period-1854 bootstrap and a 511/512
    // updates_by_range(1854,1) included. All four are Lighthouse by Identify,
    // so the catch-up asks each for one period at a time
    // (`agent_serves_one_period`; the one_every(10s) updates quota was
    // verified live against 57.129.130.18 on 2026-09-02).
    //  - 57.129.130.18 (v8.2.2): closed the connection on BOTH runner runs
    //    before answering anything, then served the residential probe in full.
    //    That is the vantage point, not the pin — wallets dial from residential
    //    and mobile addresses, not from cloud runners — so a runner-only
    //    "connection closed" is not grounds to prune.
    //  - 84.112.35.112 (v8.2.1), 91.189.182.90 (v8.2.2), 54.201.148.177 (v8.2.1):
    //    served both runner runs as well. (The 2026-09-02 note called
    //    91.189.182.90 a Nimbus-fleet node; its Identify says Lighthouse.)
    //
    // Re-verified 2026-09-13 against the then-shipped period-1856 anchor:
    // live_pins_alive run 34776025758 on a GitHub-hosted runner, 4 of 5
    // served it. 57.129.130.18 served it in full this time and 91.189.182.90
    // closed the connection instead; each has now closed on one runner run and
    // served on another, so the closes look like intermittent load on a busy
    // public node rather than anything about runner IPs. Not grounds to prune.
    // Re-verified 2026-09-16 against the then-shipped period-1858 anchor:
    // live_pins_alive run 35065042347 on a GitHub-hosted runner, 4 of 5
    // again — 91.189.182.90 closed the connection a second time while
    // 57.129.130.18 served in full; still one vantage point, so still not
    // grounds to prune, but a third close in a row should be. The bootnodes
    // seeded discv5 (23 entries), and a cold start from the recorded
    // period-1825 anchor reached SYNCED in 45 s.
    // Re-verified 2026-09-21 against the then-shipped period-1863 anchor:
    // live_pins_alive run 35616056243 on a GitHub-hosted runner, 5 of 5
    // — 91.189.182.90 served in full this time, so there is no third close in
    // a row. The bootnodes seeded discv5 (23 entries, SYNCED), and a cold start
    // from the recorded period-1825 anchor (38 periods behind) reached SYNCED
    // in 26 s.
    // Re-verified 2026-09-24 against the anchor this build ships (period
    // 1865): live_pins_alive run 35988133216 on a GitHub-hosted runner, 5 of 5
    // again; the bootnodes seeded discv5 (32 entries), and a cold start from
    // the recorded period-1825 anchor (40 periods behind) reached SYNCED in
    // 10 s.
    "/ip4/57.129.130.18/tcp/9000/p2p/16Uiu2HAkwmBd7zSRAiBkGar6ghHYfKCKTpGbGL1igrD6mC4W99T9",
    "/ip4/84.112.35.112/tcp/9000/p2p/16Uiu2HAm6YkLaGLMH1Q9caGi4A2WctHPhENumfQMJXVCMVpc7GQY",
    "/ip4/91.189.182.90/tcp/9000/p2p/16Uiu2HAmJJUAs17wxW1i4HM5Fce1zYPCvvavxsYorWr4EQVx1Ui8",
    "/ip4/54.201.148.177/tcp/9000/p2p/16Uiu2HAmNwEsdBC2phX7qU7camNe9Gs21WyrpV5AZDYyjZBMYjWZ",
    // Pruned 2026-09-13, having failed every run above from both vantage
    // points: six addresses now present a DIFFERENT peer id than the one
    // pinned whenever the handshake completes ("Unexpected peer ID": the key
    // rotated or the address changed hands — 52.200.203.85, 82.139.21.242,
    // 135.181.210.123, 45.10.55.78, 185.107.68.131, 51.161.218.70), and
    // 217.67.221.74 accepts TCP but never completes the handshake. A dead pin
    // is not free: pins are never evicted, so it keeps a place in the
    // bootstrap fan-out, and a bootstrap round waits for its slowest dial —
    // ten seconds for a handshake that never completes.
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
    // roost mainnet (this project's dedicated LC server) — a SNAPSHOT of its
    // published record (2026-09-06, from behind the netcup relay): seeding it
    // makes roost dialable from the first table without waiting for any walk.
    // The relay address is static, so the only way the embedded IP goes stale
    // is an operator-driven relay move; the targeted-lookup path (node_id
    // derived from the position-0 static peer pin,
    // `discovery::node_id_for_peer`) is what recovers the CURRENT record then.
    "enr:-KG4QKUnChEU8InNkAxOj6e_KZzebsvUQYJ850DJaEQAygKJb_8Y2Mv5IxDEOacUs0pkVctDN1f8CjrCfG7Vf2leulkIhGV0aDKQjJ9i_gYAAAD__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaEC41NP_bzrL7-rq6KmsQIeTl2Nw9yvIlgEvz-Pjz2dwTmDdGNwgiOVg3VkcIIjlQ",
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
    /// Syncing is REFUSED: the best available trust anchor (embedded checkpoint
    /// or persisted snapshot, whichever is newer) is older than the
    /// weak-subjectivity bound, so a forged continuation signed by since-exited
    /// committee members would verify. Parked awaiting a raised bound or
    /// explicit consent (`WsPolicy`); fail-closed meanwhile.
    StaleAnchor,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Starting => "STARTING",
            Self::Bootstrapping => "BOOTSTRAPPING",
            Self::CatchingUp => "CATCHING_UP",
            Self::Synced => "SYNCED",
            Self::StaleAnchor => "STALE_ANCHOR",
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
    /// LC hunt engaged: starved of light-client servers, or catching up
    /// throughput-bound on a few quota-limited ones — see hunt_due.
    pub hunting: bool,
    /// The weak-subjectivity bound (periods) currently enforced — host override
    /// if set, else the network default. While `state == StaleAnchor`, `period`
    /// is the refused anchor's period, so the wall-clock target minus `period`
    /// is the anchor age the bound was compared against.
    pub ws_bound_periods: u64,
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
            ws_bound_periods: 0,
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
            // Re-read per candidate ENR so the filter follows the fork schedule
            // at the wall clock (a fork pinned ahead rotates it at its epoch
            // without a restart) — see `AcceptedForkDigests`.
            accepted_fork_digests: {
                let chain = config.clone();
                discovery::AcceptedForkDigests::Dynamic(Arc::new(move || chain.accepted_fork_digests()))
            },
            listen_port: config.discv5_port,
            // Shared with run_sync's hunt trigger; discovery re-spawns reuse
            // the same flag, so a boost survives a discv5 restart.
            hunt_boost: Arc::new(AtomicBool::new(false)),
            // The pinned CL peers, for targeted lookups: discovery walks toward
            // their derived discv5 ids so a stale pinned address (roost behind
            // a rotated residential IP) heals from third-party tables in
            // seconds instead of waiting on random-walk luck.
            pinned_peer_ids: config
                .static_peers
                .iter()
                .filter_map(|s| parse_static_peer(s))
                .map(|p| p.id)
                .collect(),
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
    /// Peers that closed the connection on a MULTI-period updates_by_range and
    /// must therefore be asked for exactly one period at a time.
    ///
    /// Lighthouse enforces `light_client_updates_by_range = one_every(10s)`
    /// (rpc/config.rs) by CLOSING the stream ~30 ms into any multi-count
    /// request, while answering count=1 from the same peer normally — verified
    /// live against 57.129.130.18 (Lighthouse v8.2.2). Without this, every
    /// span>1 round charges such a peer a failure and the 3-strike rule evicts
    /// the whole Lighthouse-class population — precisely the servers the
    /// verify-reject rotation steers toward. Nimbus-class servers stay on the
    /// big span.
    single_period_peers: HashSet<PeerId>,
    /// Peers whose ONE multi-count response applied two or more periods
    /// (verified) — Nimbus/Lodestar/roost-class servers with no per-request
    /// quota. They lead the proven tier in `candidates` so a
    /// month-long walk rides the batch server instead of the Lighthouse peer
    /// that happens to have served most recently: the proven tier used to
    /// rank by recency alone, and a count=1 chunk lands first almost every
    /// round, so the single-period server kept winning and kept ranking
    /// first — a stable one-period-per-11-s walk with a batch server sitting
    /// unused in the same pool.
    batch_servers: HashSet<PeerId>,
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
/// Verify-rejects tolerated before a peer is evicted.
///
/// Deliberately NOT the unproven threshold (1): `process_update` also returns
/// false for INAPPLICABLE updates — a future-period chunk from an honest,
/// generous server is the common case in the drain loop — so evicting on the
/// first reject would cull exactly the well-behaved servers the rotation steers
/// toward. The cooldown is what rotates away immediately; eviction is reserved
/// for a peer that keeps failing verification (PR #410 review).
const REJECT_EVICT_AT: u32 = 3;
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
            single_period_peers: HashSet::new(),
            batch_servers: HashSet::new(),
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

    /// The factual half of `mark_proven`: this peer answered an
    /// updates_by_range request, so it demonstrably serves the protocol and any
    /// stale nolc verdict is wrong. Deliberately does NOT grant the proven tier
    /// or clear fail_counts — DELIVERING a chunk says nothing about whether the
    /// chunk verifies, and conflating the two is what let one peer serving an
    /// unverifiable update hold the catch-up walk indefinitely (mainnet 1840).
    fn clear_no_lc_for(&mut self, id: PeerId) {
        self.no_lc_updates.remove(&id);
    }

    /// Charge a peer for serving a chunk that FAILED BLS verification: a strike
    /// toward eviction plus a cooldown, so the next round asks somebody else.
    /// Without this the fan-out re-asked the same fast bad server every round.
    ///
    /// The strike IS measured against a threshold (`REJECT_EVICT_AT`) and does
    /// evict — incrementing `fail_counts` without ever comparing it would let a
    /// peer serving unverifiable updates sit in the capped pool forever, retried
    /// each time its cooldown lapsed (PR #410 review). The cooldown is the part
    /// that rotates the walk away *this round*; eviction only fires for a peer
    /// that keeps doing it, because an inapplicable-update reject is not proof
    /// of a bad server.
    fn note_verify_reject(&mut self, id: PeerId) {
        self.proven.remove(&id);
        self.set_updates_cooldown(id);
        let n = self.fail_counts.entry(id).or_insert(0);
        *n += 1;
        if *n >= REJECT_EVICT_AT {
            self.evict(&id);
        }
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
        self.batch_servers.remove(id);
        self.single_period_peers.remove(id);
        self.cooldown_until.remove(id);
        self.fail_counts.remove(id);
    }

    /// Remember that this peer closed on a multi-period ask (see
    /// `single_period_peers`); future rounds request one period from it.
    fn mark_single_period(&mut self, id: PeerId) {
        self.single_period_peers.insert(id);
    }

    fn wants_single_period(&self, id: &PeerId) -> bool {
        self.single_period_peers.contains(id)
    }

    /// Record a VERIFIED multi-period serve (two or more of one response's
    /// periods applied in one round). Delivery alone does not qualify — a
    /// peer that streams many unverifiable chunks must not be promoted, the
    /// same rule `mark_proven` follows.
    fn mark_batch_server(&mut self, id: PeerId) -> bool {
        self.batch_servers.insert(id)
    }

    /// Any batch-capable server currently in the pool (evicted ones don't
    /// count — they cannot be asked).
    fn has_batch_server(&self) -> bool {
        self.peers.iter().any(|p| self.batch_servers.contains(&p.id))
    }

    /// Any pool peer that could be asked right now: not excluded by `pred`
    /// (the caller's busy set) and outside its cooldown window. The cheap
    /// pre-check before a top-up pays for the swarm meta round-trip.
    fn has_free_peer(&self, pred: impl Fn(&PeerId) -> bool) -> bool {
        self.peers.iter().any(|p| pred(&p.id) && self.cooled_down(&p.id))
    }

    /// The shared-cache key of a peer — the same `addr/p2p/id` shape
    /// `cache_key` derives from the pool, for a `Peer` already in hand.
    fn key_for(&self, peer: &Peer) -> String {
        format!("{}/p2p/{}", peer.addr, peer.id)
    }

    /// When the soonest serve-quota / rotation cooldown among pool peers
    /// expires — the pipeline's wake-up when every server is inside its
    /// window. None when nobody is cooling down.
    fn earliest_cooldown_expiry(&self) -> Option<Instant> {
        let now = Instant::now();
        self.peers
            .iter()
            .filter_map(|p| self.cooldown_until.get(&p.id))
            .filter(|until| **until > now)
            .min()
            .copied()
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
            // The Gnosis statics are hardcoded /ip4/…; when an operator moves
            // (same node key, new address) discovery re-reports the same PeerId
            // at the current address, and without this refresh the entry would
            // be dialed at the stale address for the process lifetime (PR #322
            // review). `add()` used to keep the first multiaddr and drop later
            // ones — that still holds for ordinary peers, which self-heal via
            // evict→rediscover.
            // …but NEVER replace a DNS-NAME pin with a numeric snapshot. A
            // /dns4 pin re-resolves at every dial (#338), so it heals through
            // the operator's dyndns within a TTL — faster than any DHT record,
            // whose IP only updates after the server notices the change and
            // republishes. Overwriting the name with the ENR's /ip4 would trade
            // the self-healing path for a snapshot that goes stale with the
            // next rotation, and targeted discovery re-imposing it would keep
            // the pool pointed at the dead address (#348 review). The #322
            // refresh stays for numeric pins, which have no such path.
            if self.static_ids.contains(&id) {
                if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
                    let name_pinned = p.addr.iter().any(|proto| {
                        matches!(
                            proto,
                            libp2p::multiaddr::Protocol::Dns(_)
                                | libp2p::multiaddr::Protocol::Dns4(_)
                                | libp2p::multiaddr::Protocol::Dns6(_)
                                | libp2p::multiaddr::Protocol::Dnsaddr(_)
                        )
                    });
                    if !name_pinned {
                        p.addr = addr;
                    }
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

    /// Inverse of `cache_key`: the pooled peer id behind a `<multiaddr>/p2p/<id>`
    /// key. Used to charge a verify-reject to the peer that actually STAGED the
    /// bad chunk — the responder handling the round is often someone else.
    fn id_for_key(&self, key: &str) -> Option<PeerId> {
        self.peers
            .iter()
            .find(|p| format!("{}/p2p/{}", p.addr, p.id) == key)
            .map(|p| p.id)
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
        // Proven BATCH servers lead the tier regardless of recency (see
        // `batch_servers`): a bounded batch must always carry the peer that
        // can answer the whole span in one response.
        let mut tier1: Vec<&Peer> = self
            .peers
            .iter()
            .filter(|p| self.proven.contains(&p.id) && ok(self, &p.id))
            .collect();
        tier1.sort_by_key(|p| {
            (!self.batch_servers.contains(&p.id),
             std::cmp::Reverse(self.recent_serves.get(&p.id).copied()))
        });
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
        config.fork_schedule.clone(),
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
    // Deserialize the snapshot ONCE, up front: the weak-subjectivity gate below
    // must judge the BEST available anchor (embedded checkpoint vs persisted
    // snapshot) BEFORE anything is restored from it, and the strictly-newer
    // resume rule further down reuses the same parse.
    let mut persisted_snap = None;
    if let Some(path) = &config.snapshot_path {
        if let Ok(bytes) = std::fs::read(path) {
            persisted_snap =
                myotis_consensus::snapshot::deserialize(&bytes, &config.genesis_validators_root);
            if persisted_snap.is_none() {
                tracing::warn!("persisted snapshot unreadable/foreign — bootstrapping fresh");
            }
        }
    }

    // Weak-subjectivity gate (mirrors the Java BeaconLightClient.awaitAnchorFreshness).
    // The forward walk is only as trustworthy as the anchor it starts from: past the
    // bound, a forged continuation signed by since-exited committee members would
    // BLS-verify. So judge the best anchor's age and, when it's past the bound, park
    // in StaleAnchor — fail closed, publishing status once per second — until the
    // bound covers it (host raised it live), consent arrives
    // (WsPolicy::accept_stale_anchor), or the task is aborted (stop/pause).
    {
        let snap_period = persisted_snap
            .as_ref()
            .map(|s| s.current_sync_committee_period)
            .unwrap_or(0);
        let anchor_period = checkpoint_period.max(snap_period);
        let mut parked = false;
        loop {
            let bound = config.effective_ws_bound_periods();
            let wall_period = config.wall_clock_period();
            let stale = ws_anchor_stale(anchor_period, wall_period, bound);
            if !stale || config.ws_policy.accept_stale_anchor.load(Ordering::Relaxed) {
                break;
            }
            if !parked {
                parked = true;
                tracing::warn!(anchor_period, wall_period, bound,
                    age = wall_period - anchor_period,
                    "STALE ANCHOR: best trust anchor is past the weak-subjectivity bound — \
                     refusing to sync (a forged chain signed by since-exited committee members \
                     would be indistinguishable) until the bound is raised or the risk is \
                     explicitly accepted");
            }
            publish_stale_anchor(&status_tx, &anchor, anchor_period, bound);
            // Parked across a fork activation, the served Status digest must
            // still follow the schedule (see refresh_local_status).
            refresh_local_status(&config, &processor, &local_status);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if parked {
            tracing::warn!(anchor_period,
                "stale anchor released (bound raised or risk accepted) — syncing forward");
            // Replace the lingering StaleAnchor on the status watch IMMEDIATELY:
            // bootstrap can take a while (or keep failing peer-starved), and until
            // the next publish the UI would keep saying "awaiting your consent"
            // about a consent that was just given.
            publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, false).await;
        }
    }

    if let Some(snap) = persisted_snap {
        if snap.current_sync_committee_period > checkpoint_period {
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
        } else {
            tracing::info!(
                "persisted snapshot not newer than the configured checkpoint — bootstrapping fresh");
        }
    }

    // LC hunt state: engaged whenever the chain is starved of light-client
    // servers (bootstrap stall, starved catch-up, or finality starvation —
    // see hunt_due). While engaged, discovery lookups run boosted and each
    // cycle burst-probes the unproven pool tail; confirmations persist into
    // the CL peer cache so the next start dials them first.
    let sync_started = Instant::now();
    let mut hunt = HuntState::new(Arc::clone(&discovery_cfg.hunt_boost));
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
            hunt.hunting,
            processor.store.is_initialized(),
            sync_started.elapsed(),
            last_progress.elapsed(),
            hunt.throughput_bound,
            config.current_slot_estimate(),
            processor.store.current_period(),
            processor.store.finalized_slot(),
            config.slots_per_epoch,
            config.slots_per_period(),
        );
        if hunt_now != hunt.hunting {
            hunt.set_hunting(hunt_now);
            if hunt.hunting {
                tracing::info!(pool = pool.len(),
                    "LC hunt engaged — starved of light-client servers \
                     (boosted discovery + unproven-tail probing)");
            } else {
                tracing::info!(confirmed = hunt.confirmed.len(), "LC hunt disengaged");
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
            // Weak-subjectivity re-check for THIS bootstrap's anchor, the embedded
            // checkpoint. Reachable when a vetted-but-poisoned snapshot resume was
            // discarded mid-run: the checkpoint can be older than the anchor the
            // start-time gate approved, so falling back to it silently would dodge
            // the gate. Same fail-closed park, released by the same knobs.
            let ws_bound = config.effective_ws_bound_periods();
            let wall_period = config.wall_clock_period();
            if ws_anchor_stale(checkpoint_period, wall_period, ws_bound)
                && !config.ws_policy.accept_stale_anchor.load(Ordering::Relaxed)
            {
                publish_stale_anchor(&status_tx, &anchor, checkpoint_period, ws_bound);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            // Hunting widens the bootstrap fan-out and prefers hunt-confirmed
            // LC servers (a peer that answered ANY light-client request is the
            // best bootstrap bet in a starved pool).
            let fanout = if hunt.hunting { 16 } else { 8 };
            let bootstrapped = try_bootstrap(&config, &client, &mut pool, &mut processor,
                &mut clcache, fanout, &hunt.confirmed)
                .await;
            clcache.flush(); // one write per attempt round, win or lose
            if bootstrapped {
                persist_snapshot(&config, &processor, &mut last_persisted_period);
                refresh_local_status(&config, &processor, &local_status);
                publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunt.hunting).await;
            } else {
                if hunt.hunting {
                    // Pre-bootstrap the finality probe still classifies: a
                    // decodable response marks the peer lc-confirmed (it can't
                    // APPLY without a committee, and that's fine — the confirm
                    // feeds the next bootstrap round's prefer tier).
                    hunt_round(&client, &mut pool, &mut processor, &mut clcache,
                        &mut hunt.probed, &mut hunt.confirmed)
                        .await;
                    clcache.flush();
                }
                // Publish on FAILED rounds too: this is what replaces a lingering
                // StaleAnchor after the in-loop guard is released (consent given /
                // bound raised) — without it the watch keeps the park on display
                // until the first SUCCESSFUL bootstrap, however long that takes —
                // and it keeps peer/discovery counts moving during long stalls.
                // The served Status digest follows the schedule here too — a
                // peer-starved process can otherwise never bootstrap from
                // post-fork peers (refresh_local_status's pre-bootstrap path).
                refresh_local_status(&config, &processor, &local_status);
                publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunt.hunting).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        // In-run weak-subjectivity re-check, the awake twin of the entry gate: an
        // initialized store's committee ages in memory exactly like a snapshot of
        // the same vintage ages on disk, so a node that stays running while
        // peer-starved (or eclipsed — starvation is inducible) for longer than
        // the bound must NOT hand off through past-bound committees when peers
        // return, when the identical vintage arriving via restart would require
        // consent. Park the cycle — no catch-up, no finality poll — publishing
        // the held committee as the refused anchor; a raised bound or consent
        // releases within one 5 s cycle. Mirrors the Java wsGateAllowsForwardSync.
        if processor.store.is_initialized() {
            let held_period = processor.store.current_period();
            let ws_bound = config.effective_ws_bound_periods();
            let wall = config.wall_clock_period();
            if ws_anchor_stale(held_period, wall, ws_bound)
                && !config.ws_policy.accept_stale_anchor.load(Ordering::Relaxed)
            {
                if status_tx.borrow().state != SyncState::StaleAnchor {
                    tracing::warn!(held_period, wall_period = wall, bound = ws_bound,
                        age = wall - held_period,
                        "STALE ANCHOR: held committee aged past the weak-subjectivity \
                         bound while running — refusing to sync forward until the bound \
                         is raised or the risk is explicitly accepted");
                }
                publish_stale_anchor(&status_tx, &anchor, held_period, ws_bound);
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
                &mut last_persisted_period, &anchor, &mut hunt)
                .await;
            // Batch-persist every cache verdict from the catch-up rounds in
            // one write, OFF the per-peer hot path (review: no blocking I/O
            // inside the parallel peer loop).
            clcache.flush();
            if hunt.hunting && processor.store.current_period() == last_seen_progress.0 {
                // catch_up returned with no period progress while starved —
                // probe for new servers before the next round (lc-confirms
                // feed both the cache and catch-up's prefer tier).
                hunt_round(&client, &mut pool, &mut processor, &mut clcache,
                    &mut hunt.probed, &mut hunt.confirmed)
                    .await;
                clcache.flush();
            }
            if poisoned {
                // The restored snapshot can't verify anything (corrupt on
                // disk, framing-valid): discard it and the store, and fall
                // back to the embedded checkpoint — the trust anchor path.
                tracing::warn!(rejects = RESUME_REJECTS_MAX,
                    "restored snapshot failed verification repeatedly — discarding; \
                     re-bootstrapping from the configured checkpoint");
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
                publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunt.hunting).await;
                continue;
            }
            // Backstop only: catch_up persists each applied period itself,
            // so this is a no-op unless a future change makes catch_up return
            // with an unpersisted advance.
            persist_snapshot(&config, &processor, &mut last_persisted_period);
            refresh_local_status(&config, &processor, &local_status);
            publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunt.hunting).await;
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
            poll_finality(&client, &mut pool, &mut processor, &mut clcache, &hunt.confirmed)
                .await;
        if applied {
            // A finality update verified against the (possibly restored)
            // committee — the snapshot is genuine.
            resume.confirm();
        } else if hunt.hunting {
            // Starved and the proven/preferred tiers came up dry — burst-probe
            // the unproven pool tail for new LC servers.
            hunt_round(&client, &mut pool, &mut processor, &mut clcache,
                &mut hunt.probed, &mut hunt.confirmed)
                .await;
        }
        clcache.flush(); // batch any finality-round evictions into one write
        // No-op unless the period advanced (force-rotate can move it here too).
        persist_snapshot(&config, &processor, &mut last_persisted_period);
        refresh_local_status(&config, &processor, &local_status);
        publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunt.hunting).await;

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
        // Slot reconciliation: the root is what we verify against; the
        // configured slot only feeds the anchor PERIOD (persist floor, resume
        // rule, weak-subjectivity age). The embedded checkpoints record the
        // epoch-boundary slot the root finalizes, and a host-supplied one
        // (createWithCheckpoint) should be the header's own slot — either way
        // the period must agree. Log loudly rather than reject: a header a few
        // skipped slots behind its boundary is normal, a period off is a host
        // error whose cost is persistence (nothing is written until the store
        // passes the claimed period), never verification.
        let header_slot = bootstrap.header.beacon.slot;
        if header_slot != config.checkpoint_slot {
            let spp = config.slots_per_period();
            if spec::compute_sync_committee_period_with(header_slot, spp)
                != spec::compute_sync_committee_period_with(config.checkpoint_slot, spp)
            {
                tracing::warn!(peer = %peer, header_slot, configured = config.checkpoint_slot,
                    "bootstrap: verified header lies in a DIFFERENT sync-committee period than \
                     the configured checkpoint slot — the anchor period is wrong; persistence \
                     and snapshot resume will be off until the store passes the claimed period");
            } else {
                tracing::info!(header_slot, configured = config.checkpoint_slot,
                    "bootstrap: verified header slot differs from the configured checkpoint \
                     slot (same period — fine)");
            }
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
    /// Other peers' chunks for the SAME period, kept as fallbacks.
    ///
    /// The fan-out asks every peer for the same range, so several answer with
    /// the same period — and before this, the FIRST responder's chunk took the
    /// slot and every other copy was dropped. A fast peer serving an
    /// unverifiable update therefore wedged the whole walk: its chunk lost BLS
    /// verification, the honest copies had already been discarded, and the next
    /// round raced the same way (mainnet period 1840, ~4.6k identical requests
    /// to one server; issue seen live 2026-09-01). Alternates make a
    /// verify-reject fall through to the next peer's copy instead.
    alternates: Vec<(Vec<u8>, String)>,
}

/// Cap on alternates per period — enough to route around a few bad or stale
/// servers without holding a full fan-out's multi-MiB responses in memory.
const MAX_STAGED_ALTERNATES: usize = 3;

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
/// Outstanding `updates_by_range` asks the catch-up pipeline keeps at once
/// (its in-flight cap, single look-ahead asks and batch asks together).
/// Nothing is cancelled behind a winner any more: a batch ask streams to
/// completion while single-period servers fill the periods around it. (Java
/// CATCHUP_FANOUT_MAX is 48; the discovered pool is failure-heavy, so a wide
/// set is what makes progress land.)
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

/// Should the LC hunt run this cycle? Four triggers, all meaning "we are
/// starved of light-client servers" (or of the RIGHT servers):
/// - **Throughput-bound catch-up** (`throughput_bound`, raised by
///   `catch_up` itself): the walk is progressing, but off a handful of
///   quota-limited single-period servers with a long span still ahead. Not
///   a stall, so the progress clock never fires — yet only MORE servers
///   (ideally a batch-capable one) can speed it up, and only discovery +
///   probing can find them.
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
    throughput_bound: bool,
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
        return throughput_bound || since_progress >= HUNT_CATCHUP_STALL;
    }
    let slack_epochs =
        if engaged { SYNCED_SLOT_SLACK_EPOCHS - 1 } else { SYNCED_SLOT_SLACK_EPOCHS };
    finalized_slot + slack_epochs * slots_per_epoch < wall_slot
}

/// Consecutive no-progress rounds before returning to the outer loop (which
/// refreshes the discovered-peer pool and republishes status). Rounds inside
/// retry after a short pause — the Java equivalent is MAX_CATCHUP_BATCHES
/// per call with a 12 s outer cycle.
const CATCHUP_MAX_IDLE_WAVES: u32 = 6;

/// Outstanding single-period asks the PREFIX period is allowed at once.
/// The prefix is the pipeline's bottleneck (the committee chain admits no
/// gaps), so it is never left to one server: the 2026-07-06 disjoint-range
/// experiment did exactly that and stalled on mostly-unserving peers. Every
/// batch-capable peer asks for it as well; look-ahead periods get one ask.
const PREFIX_REDUNDANCY: usize = 2;

/// Outstanding multi-count (batch) asks at once. Every batch-capable peer
/// is asked for the same prefix-anchored span, so beyond a few copies the
/// extra streams only duplicate data — at up to ~3.5 MiB per 128-period
/// response, an uncapped fan-out of unknown-agent peers could pull tens of
/// MiB for one copy's worth. Proven batch servers rank first, so the cap is
/// spent on them once one is known.
const CATCHUP_MULTI_MAX: usize = 4;

/// Fewer distinct peers than this serving in the last minute — with no
/// batch-capable server known and `THROUGHPUT_HUNT_MIN_SPAN` periods still
/// ahead — means the walk is throughput-bound on a handful of quota-limited
/// servers, and the LC hunt engages to find more (see
/// `throughput_bound_verdict`). Four single-period servers give ~4 periods
/// per quota window, a month of mainnet in ~1 minute.
const THROUGHPUT_HUNT_MIN_SERVERS: usize = 4;

/// Extra servers above `THROUGHPUT_HUNT_MIN_SERVERS` before an engaged
/// throughput hunt releases — hysteresis, so one intermittent server at the
/// threshold does not flap the discovery boost every serve window.
const THROUGHPUT_HUNT_HYSTERESIS: usize = 2;

/// Periods still ahead below which a throughput-bound walk is left alone:
/// with two or three periods left, a hunt cannot pay for itself.
const THROUGHPUT_HUNT_MIN_SPAN: u64 = 3;

/// Floor on the probe budget of a hunt round run inside a quota wait: a
/// sub-second refill still gets one dial + round-trip's worth of probing.
const HUNT_PROBE_MIN: Duration = Duration::from_secs(3);

/// Catch the store's committee period up to wall clock.
///
/// A PIPELINE, not a round: one long-lived set of in-flight `updates_by_range`
/// asks is topped up whenever a response lands or a serve quota refills, so
/// the walk runs at the POOL's aggregate serve rate instead of one server's.
/// Two ask shapes coexist:
///
/// - **Batch-capable peers** (anything not known to truncate) are asked for
///   the PREFIX period with the full remaining span — the Java
///   `attemptCatchUpBatch` shape, kept because the prefix is the pipeline's
///   bottleneck (the committee chain admits no gaps) and must be redundantly
///   requested. At most `CATCHUP_MULTI_MAX` such asks are outstanding (each
///   can be a multi-MiB stream), and a multi-count ask is never cancelled
///   behind a faster single-period answer: it stays in flight across top-ups,
///   so a Nimbus/roost batch lands whenever it finishes and is drained in
///   order.
/// - **Single-period servers** (Lighthouse enforces one `updates_by_range`
///   per ~10 s per peer, `agent_serves_one_period` / `single_period_peers`)
///   each get a DISTINCT look-ahead period: the prefix up to
///   `PREFIX_REDUNDANCY` times, then the lowest period nobody has staged or
///   asked for (`next_single_target`). After serving they sit out one
///   `UPDATES_SERVE_COOLDOWN` — a PER-PEER quota mark, which replaces the old
///   global pace: ten such servers now deliver ten periods per quota window
///   where the round-and-sleep loop delivered one, and with a single server
///   the cadence is unchanged (the quota wait below is that server's refill).
///
/// Response chunks are staged at consecutive periods (a mislabeled chunk just
/// fails verification at apply time and gets refetched) and the contiguous
/// prefix is verified+applied as it forms, `force_rotate_if_past_period`
/// after each applied update, exactly like the Java apply path.
///
/// DIVERGENCE from the Java engine (`BeaconLightClient.catchUpSyncCommittee`):
/// the Java engine still asks every peer for the same range and paces the
/// whole call by `CATCHUP_QUOTA_PACE_MS`; only the apply/credit rules are
/// mirrored (#342, #410). Expect the Rust engine to catch up faster whenever
/// the pool holds more than one serving peer.
///
/// The disjoint-range experiment of 2026-07-06 performed worse because it
/// handed the prefix to ONE mostly-unserving peer. Here the prefix keeps every
/// batch-capable peer plus `PREFIX_REDUNDANCY` single servers; only the
/// look-ahead is spread, and a look-ahead ask that fails simply frees its
/// period for the next top-up.
#[allow(clippy::too_many_arguments)]
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
    // Hunt state, shared with the outer loop: `catch_up` runs for many cycles
    // before returning, so a walk that turns out to be THROUGHPUT-bound (a
    // handful of quota-limited servers, none batch-capable, a long span
    // ahead) engages the hunt from IN HERE — boost flag plus tail probing in
    // the quota-wait window — and `hunt.throughput_bound` tells the outer
    // loop's `hunt_due` so its next pass keeps it engaged.
    hunt: &mut HuntState,
) -> bool {
    /// One outstanding ask: what was asked of a busy peer.
    struct Ask {
        from: u64,
        /// count=1 ask to a quota-limited server (vs a batch ask) — decided
        /// at top-up, carried here so the response path never has to infer
        /// it from `count` (a batch ask with span 1 also has count 1).
        single: bool,
    }
    type Answer = (Peer, bool, u64, u64, Result<Vec<u8>, RequestError>);
    // The pipeline: every outstanding ask, across top-ups. Boxed because each
    // top-up's async block is its own anonymous type.
    let mut in_flight: FuturesUnordered<futures::future::BoxFuture<'static, Answer>> =
        FuturesUnordered::new();
    // Peers with an ask outstanding — never asked twice concurrently. The
    // only bookkeeping: `in_flight` and the per-period coverage the top-up
    // needs are both derived from it.
    let mut outstanding: HashMap<PeerId, Ask> = HashMap::new();
    // A "wave" is the life of the pipeline from empty to empty again: the
    // unit of idle/backoff accounting (the old round). Top-ups inside a wave
    // keep it alive; it ends only when nothing is outstanding AND nobody
    // free is left to ask (see `can_ask`).
    let mut wave_active = false;
    let mut wave_progress = false; // net staged growth or a period applied
    let mut wave_rejects = 0usize;
    let mut last_reject_participants: Option<usize> = None;
    let mut idle_waves = 0u32;
    // Exponential pause after fruitless waves: hammering the whole pool every
    // few seconds is exactly what CL peer scoring penalizes, and it burns
    // request quota on servers that will serve happily a minute later.
    let mut empty_backoff = Duration::from_secs(0);

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
            // The walk is over; the outer loop's hunt_due re-evaluates the
            // hunt on its own triggers from here. Outstanding asks are
            // dropped with `in_flight` — their periods are all applied.
            hunt.release_throughput(pool, wall_period, committee_period);
            return false;
        }
        *staged = staged.split_off(&committee_period); // drop already-passed periods
        let span = (wall_period - committee_period).min(UPDATES_BATCH_MAX);

        // Can the top-up below hand out an ask at all? Computed first so the
        // wave verdict is taken only when the pipeline is empty AND nobody
        // free is left — a transient drain with a free peer (a first-contact
        // batch ask closed and the peer marked single-period at no cost) is
        // re-asked at once, not backed off. Skipped outright when every peer
        // is busy or inside its window, or the pipeline is full — the meta
        // round-trip and candidate ranking are not free, and a burst of
        // responses would otherwise pay them once each for nothing. Also
        // skipped once the restored snapshot is poisoned and no apply has
        // confirmed it: the pipeline then drains within one request timeout
        // and the wave-end verdict fires — the old per-round deadline, not a
        // pool-sized one.
        let can_ask = in_flight.len() < CATCHUP_FANOUT
            && pool.has_free_peer(|id| !outstanding.contains_key(id))
            && !resume.poisoned(0);

        // ── Wave accounting: the pipeline drained and nothing can refill it.
        if wave_active && in_flight.is_empty() && !can_ask {
            wave_active = false;
            if resume.poisoned(0) {
                // Restored snapshot can't verify anything (no apply confirmed
                // it, RESUME_REJECTS_MAX rejects did the opposite).
                return true;
            }
            if wave_progress {
                idle_waves = 0;
                empty_backoff = Duration::from_secs(0);
            } else {
                idle_waves += 1;
                if wave_rejects > 0 {
                    // Loud on purpose (hosts keep info+ only in their log
                    // rings): a wave whose staged update for the target period
                    // keeps failing verification is how a serving peer holding
                    // a weak update stalls catch-up INDEFINITELY — exactly this
                    // shape hid a server-side weak-participation update
                    // (113/512 signers at mainnet period 1840) behind
                    // debug-only logs for days. The per-check reason logs at
                    // debug in myotis_consensus::store. (Counts verify-rejects
                    // only; a chunk that fails DECODE stays debug —
                    // apply_staged_step reports it as neither applied nor
                    // rejected, because malformed frames say nothing about our
                    // store or the period's data.)
                    tracing::warn!(period = committee_period, rejects = wave_rejects,
                        idle_waves, participants = ?last_reject_participants,
                        "catch-up: staged update for the target period failed verification — \
                         below-2/3 participants means the serving peer holds a weak update");
                }
                if idle_waves >= CATCHUP_MAX_IDLE_WAVES {
                    tracing::warn!(period = committee_period, idle_waves,
                        "catch-up made no progress — returning to the poll loop");
                    return false;
                }
                // Grow the pre-wave pause 5s → 25s: rapid-fire empty waves
                // burn server quota and our own peer score, but with per-peer
                // quota marks preventing self-inflicted empties, the waves
                // that reach here are genuine server droughts — and a 60 s
                // ceiling meant up to a minute of blindness after a server
                // RETURNED (droughts dominated measured cold syncs). 25 s
                // samples recovery twice as fast at bounded quota cost:
                // CATCHUP_MAX_IDLE_WAVES exits to the outer poll loop after
                // 6 fruitless waves either way.
                empty_backoff = if empty_backoff.is_zero() {
                    Duration::from_secs(5)
                } else {
                    (empty_backoff * 2).min(Duration::from_secs(25))
                };
                tracing::info!(backoff_s = empty_backoff.as_secs(), idle_waves,
                    "catch-up: no progress last wave — backing off before retrying");
                tokio::time::sleep(empty_backoff).await;
                continue; // re-read the clock and discovery before asking again
            }
        }

        // ── Top-up: hand every free, quota-refilled candidate an ask.
        if can_ask {
            let reqresp::CatchupPeerMeta { mut lc_servers, earliest_slots, agents } =
                client.catchup_peer_meta().await;
            // Reconcile the deny set against the LIVE Identify signal (same
            // protocol nolc tracks, self-expiring on disconnect) BEFORE folding
            // in hunt_confirmed — see clear_no_lc for why the finality-attesting
            // hunt set must not un-deny updates_by_range. Persist each reversal
            // to the shared cache so pool and cache never disagree across a
            // restart or an engine switch (issue #291, PR #322 review).
            for id in pool.clear_no_lc(&lc_servers) {
                if let Some(key) = pool.cache_key(&id) {
                    clcache.clear_nolc(&key);
                }
            }
            // Hunt-confirmed servers join the Identify-confirmed prefer tier —
            // same dial-priority-only trust level (see poll_finality).
            lc_servers.extend(hunt.confirmed.iter().copied());
            // Skip peers whose advertised earliest_available_slot proves their
            // light-client history begins in a LATER period than the one we
            // need — they'd only return far-future updates the period gate
            // discards (Java attemptCatchUpBatch's earliestAvailableSlot
            // filter). Compare at PERIOD granularity: a peer whose earliest
            // slot lands anywhere inside committee_period can still serve that
            // period's update, so only skip when its earliest period is
            // strictly greater. Peers not yet status-exchanged (absent from the
            // map) are unknown and kept; v1 peers report 0 (genesis history)
            // and are never skipped. This is a STRONG PREFERENCE, not a veto:
            // candidates() falls back to the shallow peers when they are all
            // that is left, because earliest_available_slot is a block floor
            // rather than an LC-update floor and an all-shallow pool is not
            // proof that nobody serves the period (issue #291). Only a
            // genuinely empty pool bounces to rediscovery.
            let too_shallow: HashSet<PeerId> = earliest_slots
                .into_iter()
                .filter(|&(_, earliest)| {
                    spec::compute_sync_committee_period_with(earliest, config.slots_per_period())
                        > committee_period
                })
                .map(|(id, _)| id)
                .collect();
            // candidates() honours the busy set as `skip` in its main tiers,
            // but its LAST-RESORT tier ignores `skip` (issue #291) and its
            // never-starve tier ignores cooldowns, so both are re-checked
            // here: a peer with an ask outstanding is never asked twice, and
            // asking a peer inside its quota window just earns an empty
            // answer and another cooldown — the self-inflicted drought the
            // old global pace existed to avoid. The too-shallow filter is
            // the STRONG PREFERENCE the comment above describes: shallow
            // peers are asked only when no deeper free peer exists (the #291
            // fallback the old code got from candidates() itself — a hard
            // veto here left a pool of checkpoint-synced peers with zero
            // asks and no exit).
            let busy: HashSet<PeerId> = outstanding.keys().copied().collect();
            let candidates = pool.candidates(CATCHUP_FANOUT, true, true, &lc_servers, &busy);
            if candidates.is_empty() && in_flight.is_empty() {
                tracing::warn!("catch-up: no peers available — retrying after discovery");
                return false;
            }
            let (deep, shallow): (Vec<Peer>, Vec<Peer>) = candidates
                .into_iter()
                .filter(|p| !busy.contains(&p.id) && pool.cooled_down(&p.id))
                .partition(|p| !too_shallow.contains(&p.id));
            let free: Vec<Peer> = if deep.is_empty() { shallow } else { deep }
                .into_iter()
                .take(CATCHUP_FANOUT - in_flight.len())
                .collect();
            // Coverage of the span by outstanding single asks, for the
            // look-ahead assignment (multi asks all start at the prefix).
            let mut covered: HashMap<u64, usize> = HashMap::new();
            for ask in outstanding.values().filter(|a| a.single) {
                *covered.entry(ask.from).or_insert(0) += 1;
            }
            let mut multi_outstanding = outstanding.values().filter(|a| !a.single).count();
            let (mut asked_single, mut asked_multi, mut look_ahead_to) =
                (0usize, 0usize, committee_period);
            for peer in free {
                // The COUNT is per-peer: a server that closed on a multi-period
                // ask (Lighthouse's quota) is asked for exactly one, so it can
                // serve instead of being struck out. Lighthouse gets count=1
                // from the FIRST ask (its quota makes a multi-count request
                // yield one chunk then a closed stream); the reactive
                // single_period_peers mark covers clients we don't know.
                let single = pool.wants_single_period(&peer.id)
                    || agent_serves_one_period(agents.get(&peer.id).map(String::as_str));
                let (from, count) = if single {
                    match next_single_target(committee_period, span, staged, &covered) {
                        Some(target) => (target, 1u64),
                        None => continue, // every period is staged or already asked
                    }
                } else {
                    if multi_outstanding >= CATCHUP_MULTI_MAX {
                        continue; // enough batch asks streaming for the same data
                    }
                    (committee_period, span)
                };
                if single {
                    *covered.entry(from).or_insert(0) += 1;
                    asked_single += 1;
                    look_ahead_to = look_ahead_to.max(from);
                } else {
                    multi_outstanding += 1;
                    asked_multi += 1;
                }
                outstanding.insert(peer.id, Ask { from, single });
                tracing::debug!(peer = %peer.id, from, count,
                    agent = agents.get(&peer.id).map(String::as_str).unwrap_or("?"),
                    "catch-up: updates_by_range request");
                let wire = codec::encode_updates_by_range_request(from, count);
                let client = client.clone();
                in_flight.push(Box::pin(async move {
                    let res = client
                        .request_raw(peer.id, peer.addr.clone(), protocols::UPDATES_BY_RANGE, wire)
                        .await;
                    (peer, single, from, count, res)
                }));
            }
            if asked_single + asked_multi > 0 {
                tracing::info!(from_period = committee_period, wall_period, span,
                    staged = staged.len(), in_flight = in_flight.len(),
                    asked_single, asked_multi, look_ahead_to,
                    "catch-up: requesting updates_by_range");
            }
        }

        // The pipeline's next wake-up while a server is inside its quota
        // window: the earliest refill. With asks outstanding it races the
        // next response (a refilled server must not idle behind a slow
        // batch stream); with none outstanding it is the whole wait.
        let refill = pool.earliest_cooldown_expiry();

        if in_flight.is_empty() {
            // Nobody free to ask and nothing outstanding — but servers exist:
            // they are all inside their serve-quota window. Wait for the
            // earliest refill (the single-server cadence of the old pace), and
            // — when the walk is throughput-bound — spend the wait probing the
            // unproven tail for MORE servers. Not idle: progress is
            // quota-bound, not server-bound.
            if resume.poisoned(0) {
                continue; // wave accounting above returns the verdict
            }
            let now = Instant::now();
            let wait = refill
                .map(|until| until.saturating_duration_since(now))
                .unwrap_or(Duration::ZERO)
                .clamp(Duration::from_millis(250), UPDATES_SERVE_COOLDOWN);
            // The quota wait IS the throughput-bound signal: the pipeline ran
            // dry because every server is cooling, not because a batch is
            // still streaming (that keeps in_flight non-empty).
            hunt.engage_throughput(pool, wall_period, committee_period);
            if hunt.throughput_bound {
                tracing::info!(wait_ms = wait.as_millis() as u64,
                    "catch-up: every server is inside its serve quota — probing for more servers meanwhile");
                // The probe is bounded by the wait itself (plus a floor so a
                // sub-second wait still gets one round-trip): a slow tail must
                // not idle a refilled server, which is the very thing the hunt
                // is meant to prevent. Confirms harvested before the deadline
                // are kept; cut-off probes stay marked probed.
                let probe_budget = wait.max(HUNT_PROBE_MIN);
                let (_, _) = tokio::join!(
                    tokio::time::sleep(wait),
                    tokio::time::timeout(
                        probe_budget,
                        hunt_round(client, pool, processor, clcache, &mut hunt.probed,
                            &mut hunt.confirmed),
                    ),
                );
            } else {
                tracing::info!(wait_ms = wait.as_millis() as u64,
                    "catch-up: every server is inside its serve quota — waiting for a refill");
                tokio::time::sleep(wait).await;
            }
            continue;
        }
        if !wave_active {
            wave_active = true;
            wave_progress = false;
            wave_rejects = 0;
            last_reject_participants = None;
        }

        // ── One response — or a quota refill, which goes straight back to
        // the top-up so the refilled server is asked while others stream.
        let next = match refill {
            Some(until) => tokio::select! {
                answer = in_flight.next() => answer,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(until)) => continue,
            },
            None => in_flight.next().await,
        };
        let Some((peer, single, sub_from, sub_count, res)) = next else {
            continue;
        };
        outstanding.remove(&peer.id);
        let peer_key = pool.key_for(&peer);
        let raw = match res {
            Ok(raw) => raw,
            Err(e) => {
                if e == RequestError::UnsupportedProtocol {
                    // Doesn't serve updates_by_range at all — skip in future
                    // asks (Java peersNoLcUpdates). Peer is alive, keep it.
                    // Both are no-ops for a static peer: the pool exempts it,
                    // and the shared cache is read by the Java engine, which
                    // would otherwise inherit the denial for a curated peer
                    // (PR #322 review) — so gate the persist on it too. The
                    // cooldown is what keeps an exempt static peer from being
                    // re-asked on every top-up.
                    pool.mark_no_lc_updates(peer.id);
                    pool.set_updates_cooldown(peer.id);
                    if !pool.is_static(&peer.id) {
                        clcache.mark_nolc(&peer_key);
                    }
                } else if e == RequestError::ConnectionClosed && !single && sub_count > 1 {
                    // NOT a dead peer: Lighthouse enforces its updates_by_range
                    // quota by closing the stream on any multi-count request
                    // while answering count=1 fine (verified live, v8.2.2).
                    // Charging a failure here would three-strike the entire
                    // Lighthouse-class population — and the verify-reject
                    // rotation steers traffic straight at them. Remember to
                    // ask this peer one period at a time instead, and cost it
                    // nothing: the next top-up hands it a look-ahead period.
                    // The signature is a MULTI-count ask being closed — a
                    // span-1 batch ask has count 1 and its close is an
                    // ordinary failure (a batch server that blips at a period
                    // rollover must not be degraded to count=1 for good).
                    pool.mark_single_period(peer.id);
                    tracing::debug!(peer = %peer.id, sub_count,
                        "closed on a multi-period ask — will request one period at a time");
                } else if e != RequestError::Shutdown {
                    // Dial/timeout/connection-closed — count toward eviction
                    // so dead peers stop occupying MAX_POOL slots. The
                    // cooldown spaces the strikes one quota window apart: with
                    // top-ups running per response, a restarting server would
                    // otherwise collect its three strikes in well under a
                    // second and be evicted for a two-second blip.
                    pool.note_failure(peer.id);
                    pool.set_updates_cooldown(peer.id);
                    clcache.mark_failure(&peer_key);
                }
                tracing::debug!(peer = %peer.id, error = %e, "updates_by_range failed");
                continue;
            }
        };
        if raw.len() < 64 {
            // Tiny frames are peers closing without serving (0 B) or sending
            // near-empty chunks; dumped verbatim at debug for peer forensics.
            tracing::debug!(peer = %peer.id, raw_len = raw.len(), hex = %hex_str(&raw),
                "small updates_by_range frame");
        }
        let chunks = match codec::decode_multi_chunk_response(&raw, sub_count as usize) {
            Ok(c) => c,
            Err(e) => {
                // Undecodable response — with the codec's read budget this is
                // also where a byte-dribbling peer lands (it used to hit the
                // behaviour timeout instead). Charge it the same way so
                // 3-strike eviction still prunes peers that never produce a
                // usable chunk.
                pool.note_failure(peer.id);
                pool.set_updates_cooldown(peer.id);
                clcache.mark_failure(&peer_key);
                tracing::debug!(peer = %peer.id, raw_len = raw.len(), error = %e,
                    "updates_by_range frame invalid");
                continue;
            }
        };
        let staged_before = staged.len();
        let mut served = 0usize;
        for (i, chunk) in chunks.into_iter().enumerate() {
            if chunk.is_empty() {
                break; // truncated/empty chunk — nothing after it is trustworthy
            }
            served += 1;
            match staged.entry(sub_from + i as u64) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(StagedChunk {
                        ssz: chunk,
                        from: peer_key.clone(),
                        alternates: Vec::new(),
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut o) => {
                    // Another peer already staged this period: keep this copy
                    // as a FALLBACK rather than dropping it, so a verify-reject
                    // on the leader can try someone else's (see
                    // StagedChunk::alternates). Skip byte-identical copies —
                    // they would fail verification identically.
                    let slot = o.get_mut();
                    if slot.alternates.len() < MAX_STAGED_ALTERNATES
                        && slot.ssz != chunk
                        && !slot.alternates.iter().any(|(ssz, _)| *ssz == chunk)
                    {
                        slot.alternates.push((chunk, peer_key.clone()));
                    }
                }
            }
        }
        if served == 0 {
            // Unserving answer — NOW the cooldown applies, so the next top-up
            // rotates toward peers that might actually serve.
            pool.set_updates_cooldown(peer.id);
            tracing::debug!(peer = %peer.id, sub_from, sub_count, raw_len = raw.len(),
                "updates_by_range returned no chunks");
            continue;
        }
        tracing::info!(peer = %peer.id, sub_from, sub_count, served, raw_len = raw.len(),
            "updates_by_range served");
        // A peer that answered DOES serve the protocol, so reverse any stale
        // nolc verdict — that part is factual. But it is NOT yet "proven":
        // mark_proven also grants the preferred tier and wipes fail_counts,
        // and granting that for mere DELIVERY is what let a fast peer serving
        // an unverifiable update keep winning selection forever (mainnet
        // 1840). Promotion happens only where the update actually VERIFIES,
        // below.
        //
        // PARITY (#342): this mirrors the Java reference, which records a
        // catch-up server ONLY inside `if (applied > 0)` after processUpdate
        // returned true (BeaconLightClient.applyCatchUpResponses). The Java
        // engine never had this stall precisely because it credits
        // verification, not delivery — keep the two in step.
        pool.clear_no_lc_for(peer.id);
        if single {
            // Per-peer serve quota: a single-period server that just served
            // answers empty for the next ~10 s (Lighthouse one_every(10s)),
            // so sit it out for one window instead of pacing the WHOLE walk
            // — the other servers' quotas are what the look-ahead spends
            // meanwhile. Batch servers carry no such mark.
            pool.set_updates_cooldown(peer.id);
        }

        // ── Apply the contiguous prefix as far as it now reaches. One update
        // per iteration: persist after EVERY period so an Android kill
        // mid-drain loses at most one period's BLS work, publish so the
        // progress bar tracks the drain, and yield so back-to-back BLS
        // verifications don't pin this worker while the swarm task needs it.
        // Each period is credited to the peer whose response staged it (not
        // necessarily this responder: alternates and look-ahead chunks from
        // earlier responses apply here too — `applied_from` names the source,
        // and a source that has since left the pool gets no credit at all;
        // crediting the responder instead would wipe strikes and grant
        // priority to a peer that merely delivered bytes, PR #410 review).
        let mut applied_now_total = 0usize;
        let mut from_this_response = 0usize;
        loop {
            let before_period = processor.store.current_period();
            let step = apply_staged_step(processor, staged, slot_estimate);
            wave_rejects += step.verify_rejects;
            if let Some(p) = step.reject_participants {
                last_reject_participants = Some(p);
            }
            // Charge every peer whose chunk failed verification — by peer KEY,
            // so the strike lands on whoever actually served the bad copy
            // rather than on whoever happened to respond last.
            for bad in &step.rejected_from {
                if let Some(id) = pool.id_for_key(bad) {
                    pool.note_verify_reject(id);
                    clcache.mark_failure(bad);
                    tracing::warn!(peer = %bad, period = before_period,
                        "catch-up: update failed verification — peer penalised, \
                         will try another next ask");
                }
            }
            if step.applied == 0 {
                // ORDER MATTERS: an apply BLS-verified against the restored
                // committee proves the snapshot genuine — confirm() (below, on
                // the first apply) resets the guard, so rejects only count
                // while nothing has verified yet. The verdict is read at wave
                // end (`resume.poisoned(0)`), so a slower HONEST response can
                // still confirm the snapshot — a fast bad peer must not win.
                let _ = resume.poisoned(step.verify_rejects as u32);
                break;
            }
            if applied_now_total == 0 {
                resume.confirm();
            }
            applied_now_total += step.applied;
            let Some(key) = step.applied_from.as_deref() else { break };
            if key == peer_key {
                from_this_response += 1;
            }
            if let Some(id) = pool.id_for_key(key) {
                pool.mark_proven(id);
                pool.note_served(id); // BLS-verified and applied
            }
            // Only VERIFIED periods reach the shared cross-engine cache (Java
            // applyCatchUpResponses records AFTER processUpdate the same way).
            clcache.record_served(key, before_period, before_period);
            persist_snapshot(config, processor, last_persisted_period);
            publish_status(config, client, processor, &*pool, status_tx, anchor, hunt.hunting)
                .await;
            tokio::task::yield_now().await;
        }
        // Progress is NET buffer growth after the apply pass (a served-then-
        // rejected prefix chunk is removed again and does not count — the
        // weak-update WARN above depends on that) or an applied period.
        if applied_now_total > 0 || staged.len() > staged_before {
            wave_progress = true;
        }
        if applied_now_total == 0 {
            continue; // staged a look-ahead period; the prefix is still outstanding
        }
        tracing::info!(applied = applied_now_total, staged = staged.len(),
            in_flight = in_flight.len(),
            period = processor.store.current_period(),
            finalized_slot = processor.store.finalized_slot(),
            "catch-up applied");
        // A verified batch server: two or more periods of THIS multi-count
        // response applied. Look-ahead chunks from other peers that drained
        // behind it do not count — a single-period peer must never be
        // promoted to the batch tier (it would lead selection and silence
        // the throughput hunt).
        if !single && from_this_response >= 2 && pool.mark_batch_server(peer.id) {
            tracing::info!(peer = %peer.id, periods = from_this_response,
                "catch-up: batch-capable LC server confirmed — preferred from now on");
        }
        hunt.release_throughput(pool, wall_period, processor.store.current_period());
    }
}

/// The LC hunt's state, owned by the sync loop and lent to `catch_up`: probe
/// bookkeeping for `hunt_round`, the engaged flag every status publish
/// carries, the discovery boost it mirrors, and the throughput-bound verdict
/// `catch_up` raises for `hunt_due`.
struct HuntState {
    probed: HashMap<PeerId, Instant>,
    confirmed: HashSet<PeerId>,
    hunting: bool,
    boost: Arc<AtomicBool>,
    /// Raised by `catch_up` when the walk is throughput-bound on a few
    /// quota-limited servers with a long span ahead; keeps `hunt_due` from
    /// disengaging the hunt that `catch_up` raised for it.
    throughput_bound: bool,
}

impl HuntState {
    fn new(boost: Arc<AtomicBool>) -> Self {
        Self {
            probed: HashMap::new(),
            confirmed: HashSet::new(),
            hunting: false,
            boost,
            throughput_bound: false,
        }
    }

    /// The one writer of the engaged flag and its discovery-boost mirror.
    fn set_hunting(&mut self, on: bool) {
        self.hunting = on;
        self.boost.store(on, Ordering::Relaxed);
    }

    /// Called from the quota wait — the moment the pipeline provably ran dry
    /// on quotas: engage the hunt if the walk is throughput-bound.
    fn engage_throughput(&mut self, pool: &PeerPool, wall_period: u64, store_period: u64) {
        let remaining = wall_period.saturating_sub(store_period);
        let servers = pool.served_last_minute();
        if !self.throughput_bound
            && throughput_bound_verdict(false, remaining, pool.has_batch_server(), servers)
        {
            self.throughput_bound = true;
            self.set_hunting(true);
            tracing::info!(remaining, servers, pool = pool.len(),
                "LC hunt engaged — catch-up is throughput-bound on a few single-period \
                 servers; searching for more (batch-capable) servers");
        }
    }

    /// Called after every applied period and at the end of the walk: release
    /// the throughput hunt once any of its conditions stops holding
    /// (hysteresis on the server count — see `throughput_bound_verdict`).
    fn release_throughput(&mut self, pool: &PeerPool, wall_period: u64, store_period: u64) {
        if !self.throughput_bound {
            return;
        }
        let remaining = wall_period.saturating_sub(store_period);
        let servers = pool.served_last_minute();
        if !throughput_bound_verdict(true, remaining, pool.has_batch_server(), servers) {
            self.throughput_bound = false;
            self.set_hunting(false);
            tracing::info!(remaining, servers, batch = pool.has_batch_server(),
                "LC hunt disengaged — catch-up is no longer throughput-bound");
        }
    }
}

/// Is a progressing walk throughput-bound? A long span ahead, no
/// batch-capable server in the pool, and fewer than
/// `THROUGHPUT_HUNT_MIN_SERVERS` peers serving — then only MORE servers can
/// speed it up. `engaged` adds hysteresis on the server count: engage below
/// the threshold, release only at threshold + `THROUGHPUT_HUNT_HYSTERESIS`,
/// so a pool flickering around the threshold does not flap the discovery
/// boost every serve window. Pure so the trigger is unit-testable.
fn throughput_bound_verdict(engaged: bool, remaining: u64, has_batch: bool, servers: usize) -> bool {
    let release_at = THROUGHPUT_HUNT_MIN_SERVERS + THROUGHPUT_HUNT_HYSTERESIS;
    remaining >= THROUGHPUT_HUNT_MIN_SPAN
        && !has_batch
        && servers < if engaged { release_at } else { THROUGHPUT_HUNT_MIN_SERVERS }
}

/// The period a free single-period server should be asked for: the lowest in
/// `[from, from + span)` that is neither staged nor already covered by enough
/// outstanding single asks — `PREFIX_REDUNDANCY` for the prefix (the
/// bottleneck period stays redundantly requested, the lesson of the
/// 2026-07-06 disjoint-range experiment), one for every look-ahead period.
/// None when the whole span is staged or asked.
fn next_single_target(
    from: u64,
    span: u64,
    staged: &std::collections::BTreeMap<u64, StagedChunk>,
    covered: &HashMap<u64, usize>,
) -> Option<u64> {
    (from..from.saturating_add(span)).find(|p| {
        let want = if *p == from { PREFIX_REDUNDANCY } else { 1 };
        !staged.contains_key(p) && covered.get(p).copied().unwrap_or(0) < want
    })
}

/// Verify+apply AT MOST ONE staged update — the one at the store's current
/// period (the contiguous prefix advances one period per call; the catch-up
/// pipeline loops it after every served response, with a persist+yield
/// between calls). The update is decoded and
/// processed, advancing the committee period on success
/// (`force_rotate_if_past_period` on the recorded wall-clock estimate — Java
/// `applyCatchUpResponses`). A chunk that fails decode/verify is dropped from
/// the buffer so the next round refetches that period from a different peer.
/// Returns `(applied, verify_rejects, applied_from, reject_participants)` —
/// applied and verify_rejects are each 0 or 1, applied_from is the
/// shared-cache key of the peer whose response staged the applied chunk (None
/// unless applied), and reject_participants is the rejected update's
/// sync-aggregate participant count (None unless a verify-reject), carried so
/// the round's WARN can name a weak-server stall at info level.
/// verify_rejects counts ONLY an update that decoded fine but failed
/// BLS/Merkle verification (`process_update` → false): that is the resume
/// guard's poison signal, since a corrupt restored committee rejects every
/// well-formed update. Decode failures are NOT counted — a peer sending
/// malformed frames says nothing about our store.
fn apply_staged_step(
    processor: &mut LightClientProcessor,
    staged: &mut std::collections::BTreeMap<u64, StagedChunk>,
    slot_estimate: u64,
) -> StepOutcome {
    let target_period = processor.store.current_period();
    let Some(chunk) = staged.remove(&target_period) else {
        return StepOutcome::default();
    };
    let mut out = StepOutcome::default();
    // The leader first, then every alternate: one bad copy of a period must not
    // block the walk when another peer served a good one in the same round.
    let candidates = std::iter::once((chunk.ssz, chunk.from)).chain(chunk.alternates.into_iter());
    for (ssz, from) in candidates {
        match LightClientUpdate::decode(&ssz) {
            Ok(update) => {
                if processor.process_update(&update) {
                    processor.store.force_rotate_if_past_period(slot_estimate);
                    tracing::debug!(target_period,
                        finalized_slot = update.finalized_header.beacon.slot,
                        period = processor.store.current_period(),
                        "catch-up update applied");
                    out.applied = 1;
                    out.applied_from = Some(from);
                    return out;
                }
                // Verify-reject: name the peer so the caller can charge it —
                // rewarding a peer for merely DELIVERING an unverifiable update
                // is what let one bad server hold the walk indefinitely.
                //
                // The participant count rides back too (PR #409): the round's
                // WARN can then say WHY without a debug session — a weak-server
                // stall (below the 2/3 bar) reads directly off the warn.
                tracing::debug!(target_period, %from,
                    finalized_slot = update.finalized_header.beacon.slot,
                    "catch-up update rejected");
                out.verify_rejects += 1;
                out.reject_participants = Some(update.sync_aggregate.count_participants());
                out.rejected_from.push(from);
            }
            Err(e) => {
                tracing::debug!(target_period, %from, error = %e,
                    "catch-up update decode failed");
                out.decode_failures += 1;
            }
        }
    }
    out
}

/// Whether a client family should be asked for ONE period per request.
///
/// Lighthouse rate-limits `light_client_updates_by_range` at `one_every(10s)`
/// (`lighthouse_network/src/rpc/config.rs`): a count=N request costs N tokens
/// against a one-token bucket, so it serves the first chunk and closes the
/// stream. Asking it for one period up front turns every first contact into
/// a served update instead of a truncated one. Nimbus and roost answer whole
/// spans, and unknown agents keep the span until the reactive
/// `single_period_peers` mark fires.
pub(crate) fn agent_serves_one_period(agent: Option<&str>) -> bool {
    agent.is_some_and(|a| a.starts_with("Lighthouse"))
}

/// What one `apply_staged_step` pass did — richer than the old tuple so the
/// caller can charge verify-rejects to the peers that actually served them.
#[derive(Default)]
struct StepOutcome {
    applied: usize,
    verify_rejects: usize,
    decode_failures: usize,
    /// Peer key of the response whose chunk APPLIED (verified), if any.
    applied_from: Option<String>,
    /// Peer keys whose chunks failed BLS verification this pass.
    rejected_from: Vec<String>,
    /// Participant count of the LAST rejected update (PR #409) — surfaced in
    /// the round WARN so a below-2/3 stall is legible without a debug session.
    reject_participants: Option<usize>,
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
        // Not bootstrapped yet: the checkpoint fields stay, but the digest must
        // still follow the fork schedule at the wall clock. A process parked or
        // peer-starved across a fork activation otherwise keeps offering the
        // old digest on every new connection and can never bootstrap from
        // post-fork peers (PR #430 review).
        let mut s = local_status.get();
        let digest = config.current_fork_digest();
        if s.fork_digest != digest {
            tracing::info!(from = %hex_str(&s.fork_digest), to = %hex_str(&digest),
                "pre-bootstrap Status fork digest follows the schedule");
            s.fork_digest = digest;
            local_status.set(s);
        }
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
/// Crate-visible because the EL log index sizes a bound from it
/// (`RESTART_CLAIM_MAX_LEAD` in el/reader.rs, pinned by a test there).
pub(crate) const SYNCED_SLOT_SLACK_EPOCHS: u64 = 5;

/// The published state of `store` at `wall_slot` — the SYNCED gate above.
/// Pure, so the status and the execution anchor's currency flag (which the EL
/// log index trusts to tell a restored finality from a current one) cannot
/// drift apart.
fn sync_state_at(
    store: &LightClientStore,
    wall_slot: u64,
    slots_per_epoch: u64,
    slots_per_period: u64,
) -> SyncState {
    let wall_period = spec::compute_sync_committee_period_with(wall_slot, slots_per_period);
    if !store.is_initialized() {
        SyncState::Bootstrapping
    } else if wall_period == store.current_period()
        && store.finalized_slot() + SYNCED_SLOT_SLACK_EPOCHS * slots_per_epoch >= wall_slot
    {
        SyncState::Synced
    } else {
        SyncState::CatchingUp
    }
}

/// Feed the EL anchor from `store` at `wall_slot` — its headers
/// ([`update_exec_anchor`]) and whether their finality is current — and return
/// the state that decided the latter. A resumed store hands the anchor the
/// finality it was persisted with, up to a whole period old, so the number
/// alone cannot say whether it is current; the EL log index needs to know (a
/// restart must not rewind coverage that only LOOKS optimistic against it).
fn feed_exec_anchor(
    store: &LightClientStore,
    anchor: &ExecAnchor,
    wall_slot: u64,
    slots_per_epoch: u64,
    slots_per_period: u64,
) -> SyncState {
    update_exec_anchor(store, anchor);
    let state = sync_state_at(store, wall_slot, slots_per_epoch, slots_per_period);
    anchor.set_finality_current(state == SyncState::Synced);
    state
}

/// Publish the fail-closed STALE_ANCHOR park for `period` (every
/// weak-subjectivity gate parks the same way). Parked, finality stops moving,
/// so the EL anchor also hears that it is no longer current — whatever the
/// last publish said.
fn publish_stale_anchor(
    status_tx: &watch::Sender<SyncStatus>,
    anchor: &ExecAnchor,
    period: u64,
    ws_bound_periods: u64,
) {
    let mut status = SyncStatus::initial();
    status.state = SyncState::StaleAnchor;
    status.period = period;
    status.ws_bound_periods = ws_bound_periods;
    let _ = status_tx.send(status);
    anchor.set_finality_current(false);
}

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
    let state = feed_exec_anchor(
        store,
        anchor,
        config.current_slot_estimate(),
        config.slots_per_epoch,
        config.slots_per_period(),
    );
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
        ws_bound_periods: config.effective_ws_bound_periods(),
    };
    let _ = status_tx.send(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lighthouse_agents_get_single_period_requests() {
        assert!(agent_serves_one_period(Some("Lighthouse/v8.2.2-e423a66/x86_64-linux")));
        assert!(agent_serves_one_period(Some("Lighthouse/v8.1.3-176cce5/x86_64-linux")));
        assert!(!agent_serves_one_period(Some("nimbus-eth2/v26.4.0")));
        assert!(!agent_serves_one_period(Some("lodestar/v1.47.0/2aff495")));
        // Built the way the engine builds it (reqresp.rs), so this sample
        // cannot drift to a previous release's version at the next sweep.
        assert!(!agent_serves_one_period(Some(concat!(
            "myotis/",
            env!("CARGO_PKG_VERSION"),
            "-rs"
        ))));
        // Case-sensitive on purpose: Lighthouse always capitalises its agent.
        assert!(!agent_serves_one_period(Some("lighthouse/v8.2.2")));
        assert!(!agent_serves_one_period(None));
    }

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
    fn ws_gate_staleness_and_bound_precedence() {
        // Fresh: age == bound is NOT stale (the bound is inclusive headroom).
        assert!(!ws_anchor_stale(1800, 1813, 13));
        // Stale: one period past the bound.
        assert!(ws_anchor_stale(1800, 1814, 13));
        // Clock skew (wall behind anchor) reads as fresh, never underflows.
        assert!(!ws_anchor_stale(1800, 1700, 13));

        // Effective bound: network default until the host override is set (> 0),
        // then the override wins; 0 restores the default. Judged through the
        // SHARED WsPolicy so a clone of the config sees the same live values.
        let config = ChainConfig::mainnet();
        assert_eq!(config.effective_ws_bound_periods(), 13);
        let clone = config.clone();
        config.ws_policy.bound_override_periods.store(40, Ordering::Relaxed);
        assert_eq!(config.effective_ws_bound_periods(), 40);
        assert_eq!(clone.effective_ws_bound_periods(), 40, "clones share the policy");
        config.ws_policy.bound_override_periods.store(0, Ordering::Relaxed);
        assert_eq!(config.effective_ws_bound_periods(), 13);

        // Per-network defaults stay in lockstep with NetworkConfig.wsBoundPeriods().
        assert_eq!(ChainConfig::sepolia().effective_ws_bound_periods(), 13);
        assert_eq!(ChainConfig::gnosis().effective_ws_bound_periods(), 3);
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
    fn sync_state_marks_only_a_current_finality_as_synced() {
        use myotis_consensus::types::SyncCommittee;
        let (epoch, period_slots) = (32u64, 8192u64);
        let wall = 10_000_000u64; // mid-period: period 1220 spans 9_994_240..
        let committee = || SyncCommittee { pubkeys: Vec::new(), aggregate_pubkey: [0u8; 48] };
        let mut store = LightClientStore::new_mainnet_preset();
        assert_eq!(sync_state_at(&store, wall, epoch, period_slots), SyncState::Bootstrapping);

        // Resumed from a snapshot written at this period's start: the committee
        // is current, the finality is hours old. That is catch-up, not SYNCED —
        // and it is exactly the state a restart hands the EL anchor.
        let period_start = wall - wall % period_slots;
        store.initialize(header_with_exec(period_start, [1; 32], 21_000_000, [2; 32]), committee());
        assert_eq!(sync_state_at(&store, wall, epoch, period_slots), SyncState::CatchingUp);

        // Finality within the slack of the wall clock: SYNCED.
        store.update_finalized(&header_with_exec(wall - 64, [3; 32], 21_004_000, [4; 32]), wall - 64);
        assert_eq!(sync_state_at(&store, wall, epoch, period_slots), SyncState::Synced);
        let slack = SYNCED_SLOT_SLACK_EPOCHS * epoch;
        assert_eq!(sync_state_at(&store, wall - 64 + slack, epoch, period_slots), SyncState::Synced);
        assert_eq!(sync_state_at(&store, wall - 64 + slack + 1, epoch, period_slots), SyncState::CatchingUp);
        // A later period on the wall clock: the committee is stale.
        assert_eq!(
            sync_state_at(&store, period_start + period_slots, epoch, period_slots),
            SyncState::CatchingUp
        );
    }

    #[test]
    fn the_anchor_hears_whether_its_finality_is_current() {
        use myotis_consensus::types::SyncCommittee;
        let (epoch, period_slots) = (32u64, 8192u64);
        let wall = 10_000_000u64;
        let anchor = ExecAnchor::new();
        let mut store = LightClientStore::new_mainnet_preset();
        let committee = SyncCommittee { pubkeys: Vec::new(), aggregate_pubkey: [0u8; 48] };

        // A resumed store: its finality reaches the anchor, flagged stale.
        let period_start = wall - wall % period_slots;
        store.initialize(header_with_exec(period_start, [1; 32], 21_000_000, [2; 32]), committee);
        anchor.set_finality_current(true); // whatever an earlier publish said
        assert_eq!(feed_exec_anchor(&store, &anchor, wall, epoch, period_slots), SyncState::CatchingUp);
        assert_eq!(anchor.finalized_execution().map(|f| f.block_number), Some(21_000_000));
        assert!(!anchor.finality_is_current());

        // Caught up: current.
        store.update_finalized(&header_with_exec(wall - 64, [3; 32], 21_004_000, [4; 32]), wall - 64);
        assert_eq!(feed_exec_anchor(&store, &anchor, wall, epoch, period_slots), SyncState::Synced);
        assert_eq!(anchor.finalized_execution().map(|f| f.block_number), Some(21_004_000));
        assert!(anchor.finality_is_current());

        // A weak-subjectivity park says otherwise, whatever came before.
        let (status_tx, status_rx) = watch::channel(SyncStatus::initial());
        publish_stale_anchor(&status_tx, &anchor, 1_220, 13);
        assert!(!anchor.finality_is_current());
        let parked = status_rx.borrow().clone();
        assert_eq!(parked.state, SyncState::StaleAnchor);
        assert_eq!((parked.period, parked.ws_bound_periods), (1_220, 13));
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
        assert_eq!(c.current_fork_version(), [6, 0, 0, 0]);
        assert_eq!(c.prior_fork_version(), None); // fallback digest off
        // The FULL schedule (consensus-specs configs/mainnet.yaml) — the Java
        // twin (NetworkConfigForkScheduleTest) pins the same list.
        assert_eq!(c.fork_schedule.slots_per_epoch(), c.slots_per_epoch);
        assert_eq!(
            c.fork_schedule.forks(),
            &[
                (0, [0x00, 0x00, 0x00, 0x00]),
                (74_240, [0x01, 0x00, 0x00, 0x00]),
                (144_896, [0x02, 0x00, 0x00, 0x00]),
                (194_048, [0x03, 0x00, 0x00, 0x00]),
                (269_568, [0x04, 0x00, 0x00, 0x00]),
                (364_032, [0x05, 0x00, 0x00, 0x00]),
                (411_392, [0x06, 0x00, 0x00, 0x00]),
            ]
        );
        // Fulu's first slot (13164544) still verifies under Electra; the next
        // slot switches — the spec's max(signature_slot,1)-1.
        assert_eq!(c.fork_schedule.version_for_signature_slot(13_164_544), [5, 0, 0, 0]);
        assert_eq!(c.fork_schedule.version_for_signature_slot(13_164_545), [6, 0, 0, 0]);
        // @checkpoint:mainnet:test:begin — managed by `./gradlew refreshCheckpoint`
        assert_eq!(c.checkpoint_slot, 15_285_056);
        assert_eq!(
            hex_str(&c.checkpoint_root),
            "4f4b89524600b09292365d29f2e9266e7a004b27bccf7ed31655b88851045028"
        );
        // @checkpoint:mainnet:test:end
        assert_eq!(
            hex_str(&c.genesis_validators_root),
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
        assert_eq!(c.genesis_time, 1_606_824_023);
        // Structural, not a pinned period number: the anchor moves every time
        // `./gradlew refreshCheckpoint` runs, so a literal here would make the
        // refresh tool break this test. What must hold is that the default
        // helper and the config-aware one agree for this chain.
        assert_eq!(
            spec::compute_sync_committee_period(c.checkpoint_slot),
            spec::compute_sync_committee_period_with(c.checkpoint_slot, c.slots_per_period())
        );
        // The live digest the Java computes (verified against jshell).
        assert_eq!(c.current_fork_digest(), [0x8C, 0x9F, 0x62, 0xFE]);
        assert_eq!(c.accepted_fork_digests(), vec![[0x8C, 0x9F, 0x62, 0xFE]]);
        // The FULL list, order and addresses — same discipline as the sepolia
        // test below, and the Java twin (NetworkConfigGnosisTest
        // .mainnetPinsRoostFirst) pins the same strings, so a one-sided edit
        // fails a test on whichever side diverges; pinning only count +
        // element 0 (as both tests once did) let every later element drift
        // machine-unchecked. roost is FIRST — the ordering is the point, not an
        // accident of the list; the Java twin prepends it with prependLocal().
        assert_eq!(
            c.static_peers,
            vec![
                "/ip4/188.68.32.16/tcp/9109/p2p/16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
                "/ip4/57.129.130.18/tcp/9000/p2p/16Uiu2HAkwmBd7zSRAiBkGar6ghHYfKCKTpGbGL1igrD6mC4W99T9",
                "/ip4/84.112.35.112/tcp/9000/p2p/16Uiu2HAm6YkLaGLMH1Q9caGi4A2WctHPhENumfQMJXVCMVpc7GQY",
                "/ip4/91.189.182.90/tcp/9000/p2p/16Uiu2HAmJJUAs17wxW1i4HM5Fce1zYPCvvavxsYorWr4EQVx1Ui8",
                "/ip4/54.201.148.177/tcp/9000/p2p/16Uiu2HAmNwEsdBC2phX7qU7camNe9Gs21WyrpV5AZDYyjZBMYjWZ",
            ],
            "same list, order AND addresses as the Java NetworkConfig.MAINNET.clPeerMultiaddrs"
        );
        // A malformed pin would otherwise reach run_sync and surface only as a
        // "skipping unparseable static peer multiaddr" warn.
        assert!(c.static_peers.iter().all(|p| parse_static_peer(p).is_some()));
        // Every pin must also derive a discv5 node id: that is what lets the
        // targeted lookup recover a pinned server's CURRENT record when its
        // address rotates, and a re-census that pinned an Ed25519 (12D3KooW…)
        // id would silently lose that safety net.
        assert!(c.static_peers.iter().all(|p| crate::discovery::node_id_for_peer(
            &parse_static_peer(p).expect("parseable pin").id
        )
        .is_some()));
        assert_eq!(c.bootstrap_enrs.len(), 18);
        assert_eq!(c.chain_id, 1);
    }

    /// Pre-bootstrap, `refresh_local_status` still moves the Status digest to
    /// the schedule's wall-clock value (everything else untouched).
    /// Copilot on PR #430: a parked process kept the start-time digest forever.
    #[test]
    fn pre_bootstrap_status_digest_follows_the_schedule() {
        let config = ChainConfig::mainnet();
        let stale = StatusMessage {
            fork_digest: [0xDE, 0xAD, 0xBE, 0xEF],
            finalized_root: config.checkpoint_root,
            finalized_epoch: 7,
            head_root: config.checkpoint_root,
            head_slot: 8,
            earliest_available_slot: 0,
        };
        let local = LocalStatus::new(stale.clone());
        let processor = LightClientProcessor::new(
            LightClientStore::new(config.slots_per_period()),
            config.fork_schedule.clone(),
            config.genesis_validators_root,
        );
        assert!(!processor.store.is_initialized());
        refresh_local_status(&config, &processor, &local);
        let got = local.get();
        assert_eq!(got.fork_digest, config.current_fork_digest());
        assert_eq!(
            (got.finalized_root, got.finalized_epoch, got.head_root, got.head_slot),
            (stale.finalized_root, stale.finalized_epoch, stale.head_root, stale.head_slot),
            "only the digest moves before bootstrap"
        );
    }

    /// The digest-side "current" version is the schedule entry active at the
    /// WALL CLOCK, so the next fork can be pinned before it activates without
    /// flipping the digest early. Pinned with a far-future entry appended to
    /// each real schedule: every digest and version must be what it is today.
    /// Java twin: NetworkConfigForkScheduleTest.aFutureForkPinnedAheadDoesNotChangeTodaysDigest.
    #[test]
    fn a_future_fork_pinned_ahead_does_not_change_todays_digest() {
        for c in [ChainConfig::mainnet(), ChainConfig::sepolia(), ChainConfig::gnosis()] {
            assert_eq!(c.current_fork_version(), c.fork_schedule.newest(),
                "{}: every pinned fork is active today", c.name);
            let mut forks = c.fork_schedule.forks().to_vec();
            forks.push((u64::MAX / 64, [0x7F, 0, 0, 0])); // never activates in this test's lifetime
            let ahead = ChainConfig {
                fork_schedule: ForkSchedule::new(c.fork_schedule.slots_per_epoch(), &forks),
                ..c.clone()
            };
            assert_eq!(ahead.current_fork_version(), c.current_fork_version(), "{}", c.name);
            assert_eq!(ahead.current_fork_digest(), c.current_fork_digest(), "{}", c.name);
            assert_eq!(ahead.accepted_fork_digests(), c.accepted_fork_digests(), "{}", c.name);
            // ...while signatures from that far future would already verify under it.
            assert_eq!(ahead.fork_schedule.version_for_signature_slot(u64::MAX), [0x7F, 0, 0, 0]);
            // The geometry twin-check fires on the shared accessor.
            let _ = ahead.slots_per_period();
        }
    }

    #[test]
    #[should_panic(expected = "geometry must match")]
    fn mismatched_schedule_geometry_is_refused() {
        let c = ChainConfig::gnosis();
        let wrong = ChainConfig {
            fork_schedule: ForkSchedule::new(32, c.fork_schedule.forks()),
            ..c
        };
        let _ = wrong.slots_per_period();
    }

    #[test]
    fn sepolia_config_matches_networkconfig_java() {
        let c = ChainConfig::sepolia();
        assert_eq!(c.chain_id, 11_155_111);
        assert_eq!(c.current_fork_version(), [0x90, 0x00, 0x00, 0x75]); // Fulu on sepolia
        assert_eq!(c.prior_fork_version(), None); // fallback digest off
        // eth-clients/sepolia metadata/config.yaml — Java twin pins the same.
        assert_eq!(c.fork_schedule.slots_per_epoch(), c.slots_per_epoch);
        assert_eq!(
            c.fork_schedule.forks(),
            &[
                (0, [0x90, 0x00, 0x00, 0x69]),
                (50, [0x90, 0x00, 0x00, 0x70]),
                (100, [0x90, 0x00, 0x00, 0x71]),
                (56_832, [0x90, 0x00, 0x00, 0x72]),
                (132_608, [0x90, 0x00, 0x00, 0x73]),
                (222_464, [0x90, 0x00, 0x00, 0x74]),
                (272_640, [0x90, 0x00, 0x00, 0x75]),
            ]
        );
        // @checkpoint:sepolia:test:begin — managed by `./gradlew refreshCheckpoint`
        assert_eq!(c.checkpoint_slot, 11_209_280);
        assert_eq!(
            hex_str(&c.checkpoint_root),
            "d9d8f57adb4ad2053a191dd566f5fb75722c09c531fb833a27cee23f077d3b36"
        );
        // @checkpoint:sepolia:test:end
        assert_eq!(
            hex_str(&c.genesis_validators_root),
            "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
        );
        assert_eq!(c.genesis_time, 1_655_733_600);
        assert_eq!(c.seconds_per_slot, 12);
        assert_eq!(c.slots_per_epoch, 32);
        assert_eq!((c.blob_params_epoch, c.blob_params_max_blobs), (275_712, 21));
        // Structural rather than a pinned period — see the mainnet twin.
        assert_eq!(
            spec::compute_sync_committee_period(c.checkpoint_slot),
            spec::compute_sync_committee_period_with(c.checkpoint_slot, c.slots_per_period())
        );
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
                "/ip4/188.68.32.16/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5",
                "/ip4/65.109.144.95/tcp/9000/p2p/16Uiu2HAkwKbnJCnfFsNGjGd5TURbXyNBdTWoVZjw8jqiCEf47gc2",
                "/ip4/138.201.192.180/tcp/9000/p2p/16Uiu2HAmNHPaVrDFi7zVnEd9vhSHy9e4a5eF5a3aBxNXPPAucWbE",
                "/ip4/198.13.138.237/tcp/9000/p2p/16Uiu2HAmMb2mLN12B5vnJGv2LMuXxKsAiKQ8yTdy5gSJY1zKgE5f",
            ],
            "roost first (the dedicated LC server), then the census-verified public \
             servers — same list, order AND addresses as the Java \
             NetworkConfig.SEPOLIA.clPeerMultiaddrs"
        );
        // A malformed pin would otherwise reach run_sync and surface only as a
        // "skipping unparseable static peer multiaddr" warn.
        assert!(c.static_peers.iter().all(|p| parse_static_peer(p).is_some()));
        // Every pin must also derive a discv5 node id: that is what lets the
        // targeted lookup recover a pinned server's CURRENT record when its
        // address rotates, and a re-census that pinned an Ed25519 (12D3KooW…)
        // id would silently lose that safety net.
        assert!(c.static_peers.iter().all(|p| crate::discovery::node_id_for_peer(
            &parse_static_peer(p).expect("parseable pin").id
        )
        .is_some()));
        assert_eq!(c.bootstrap_enrs.len(), 10);
    }

    #[test]
    fn gnosis_config_matches_networkconfig_java() {
        let c = ChainConfig::gnosis();
        assert_eq!(c.chain_id, 100);
        assert_eq!(c.current_fork_version(), [0x06, 0x00, 0x00, 0x64]); // Fulu on Gnosis
        assert_eq!(c.prior_fork_version(), Some([0x05, 0x00, 0x00, 0x64])); // Electra
        // gnosischain/configs mainnet/config.yaml — Java twin pins the same.
        // 16-slot epochs: the schedule carries its own geometry.
        assert_eq!((c.fork_schedule.slots_per_epoch(), c.slots_per_epoch), (16, 16));
        assert_eq!(
            c.fork_schedule.forks(),
            &[
                (0, [0x00, 0x00, 0x00, 0x64]),
                (512, [0x01, 0x00, 0x00, 0x64]),
                (385_536, [0x02, 0x00, 0x00, 0x64]),
                (648_704, [0x03, 0x00, 0x00, 0x64]),
                (889_856, [0x04, 0x00, 0x00, 0x64]),
                (1_337_856, [0x05, 0x00, 0x00, 0x64]),
                (1_714_688, [0x06, 0x00, 0x00, 0x64]),
            ]
        );
        // Fulu epoch 1714688 x 16 = slot 27435008: first slot still Electra.
        assert_eq!(c.fork_schedule.version_for_signature_slot(27_435_008), [0x05, 0, 0, 0x64]);
        assert_eq!(c.fork_schedule.version_for_signature_slot(27_435_009), [0x06, 0, 0, 0x64]);
        // @checkpoint:gnosis:test:begin — managed by `./gradlew refreshCheckpoint`
        assert_eq!(c.checkpoint_slot, 30_250_464);
        assert_eq!(
            hex_str(&c.checkpoint_root),
            "8cf978da4e896b02351fe9669d0ac82b601174bd6a413c7c975ae1a611bc29f9"
        );
        // @checkpoint:gnosis:test:end
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
        // 512 epochs x 16 slots = the same 8192-slot period as mainnet-preset,
        // which is why the default helper may be used on gnosis at all. Pinned
        // structurally rather than as a period number: the anchor must track
        // roost@gnosis's servable window, so it moves on every refresh — see the
        // mainnet twin.
        assert_eq!(
            spec::compute_sync_committee_period(c.checkpoint_slot),
            spec::compute_sync_committee_period_with(c.checkpoint_slot, c.slots_per_period())
        );
        // Live-verified digests the Java computes (NetworkConfig.GNOSIS
        // currentForkDigest / acceptedForkDigests): Fulu first, Electra fallback.
        assert_eq!(c.current_fork_digest(), [0x32, 0x37, 0xDA, 0xB6]);
        assert_eq!(
            c.accepted_fork_digests(),
            vec![[0x32, 0x37, 0xDA, 0xB6], [0x7D, 0x5A, 0xAB, 0x40]]
        );
        // The FULL list, order and addresses, like the other two chains — the
        // Java twin (NetworkConfigGnosisTest.gnosisPinsHarvestedLcServers) pins
        // the same strings, so a one-sided edit fails on whichever side
        // diverges. This used to pin only the count and three positions, the
        // same gap #411 closed for mainnet. roost FIRST: both engines must agree
        // on which peer the light client tries first, not merely that roost is
        // present.
        assert_eq!(
            c.static_peers,
            vec![
                "/ip4/188.68.32.16/tcp/9108/p2p/16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh",
                "/ip4/134.65.194.144/tcp/9500/p2p/16Uiu2HAmLZasEWSgafRb5hqW5M2jSN7YcERyVQ81AeCGCFZmynsQ",
                "/ip4/144.76.118.19/tcp/9000/p2p/16Uiu2HAmEJpzjSyajPJzzrN8TnV1VaNMaEecQo1v4Mkedwb6UYwE",
                "/ip4/144.76.163.174/tcp/9000/p2p/16Uiu2HAkxLFxkn7MbAPH17VdwEvXytqgteNAr52AaqKYuEmsw2bt",
                "/ip4/148.251.181.49/tcp/9000/p2p/16Uiu2HAmAWrwxf2murYQp1tdbwKbFwqUiVofwJ3xgJP5T7BLSpRa",
                "/ip4/148.251.235.60/tcp/9001/p2p/16Uiu2HAmTeAHEG2tCFgC5RmrjZcw6zGeCgnE5svqM4528R5inSjA",
                "/ip4/159.195.138.9/tcp/9000/p2p/16Uiu2HAmUimXaHiCvWhx2YuvwTkDLtca6oq1bCH85Eb6JcEYiaGi",
                "/ip4/164.152.161.131/tcp/9500/p2p/16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw",
            ],
            "same list, order AND addresses as the Java NetworkConfig.GNOSIS.clPeerMultiaddrs"
        );
        // ONE ADDRESS PER PEER ID: `PeerPool::add` dedupes by peer id, so a
        // second address for a known id would never be dialed here while Java,
        // which dedupes by multiaddr string, dialed both.
        let ids: std::collections::HashSet<_> =
            c.static_peers.iter().map(|a| a.rsplit('/').next().unwrap()).collect();
        assert_eq!(ids.len(), c.static_peers.len(), "one address per peer id (the pool dedupes by id)");
        assert!(c.static_peers.iter().all(|p| parse_static_peer(p).is_some()));
        // Every pin must also derive a discv5 node id: that is what lets the
        // targeted lookup recover a pinned server's CURRENT record when its
        // address rotates, and a re-census that pinned an Ed25519 (12D3KooW…)
        // id would silently lose that safety net.
        assert!(c.static_peers.iter().all(|p| crate::discovery::node_id_for_peer(
            &parse_static_peer(p).expect("parseable pin").id
        )
        .is_some()));
        assert_eq!(c.bootstrap_enrs.len(), 9);
    }

    /// The Java anchor and the Rust one, compared directly.
    ///
    /// The `*_config_matches_networkconfig_java` tests above are ONE-SIDED: they
    /// pin the Rust config against literals copied into this file, so they fail
    /// when someone edits Rust and stay green when the two engines drift apart.
    /// A split trust anchor is precisely a drift, so it slipped through — this
    /// reads `NetworkConfig.java` itself and asserts the two agree.
    ///
    /// `./gradlew refreshCheckpoint` writes both from one fetch and so keeps this
    /// green by construction; the test is what makes that a checked property
    /// rather than a claim in a KDoc.
    #[test]
    fn java_and_rust_checkpoints_agree() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let java = repo_root
            .join("networking/src/main/java/com/jaeckel/ethp2p/networking/NetworkConfig.java");
        let src = match std::fs::read_to_string(&java) {
            Ok(s) => s,
            Err(e) => {
                // Skipping is legitimate ONLY outside a repo checkout (a vendored
                // crate has no Java engine to disagree with). Inside one, an
                // unreadable path means the Java file MOVED — and skipping there
                // would silently disarm this guard forever, degrading the parity
                // guarantee back to a claim in a comment. Distinguish the two by
                // a repo landmark.
                if repo_root.join("settings.gradle.kts").exists() {
                    panic!(
                        "this is a repo checkout (settings.gradle.kts present) but {} is \
                         unreadable ({e}) — NetworkConfig.java moved; update this test's path \
                         and the refreshCheckpoint task in build.gradle.kts",
                        java.display()
                    );
                }
                eprintln!("skipping: not a repo checkout ({} unreadable: {e})", java.display());
                return;
            }
        };

        for (net, c) in [
            ("mainnet", ChainConfig::mainnet()),
            ("sepolia", ChainConfig::sepolia()),
            ("gnosis", ChainConfig::gnosis()),
        ] {
            let begin = format!("// @checkpoint:{net}:begin");
            let end = format!("// @checkpoint:{net}:end");
            let from = src
                .find(&begin)
                .unwrap_or_else(|| panic!("no {begin} marker in NetworkConfig.java"));
            let to = src[from..]
                .find(&end)
                .unwrap_or_else(|| panic!("no {end} marker in NetworkConfig.java"))
                + from;
            let region = &src[from..to];

            // Bytes.fromHexString("<64 hex>")
            let root_at = region
                .find("fromHexString(\"")
                .unwrap_or_else(|| panic!("no root literal in the {net} region"))
                + "fromHexString(\"".len();
            let java_root = region[root_at..root_at + 64].to_ascii_lowercase();
            assert_eq!(
                java_root,
                hex_str(&c.checkpoint_root),
                "{net}: checkpoint_root differs between NetworkConfig.java and ChainConfig::{net}() \
                 — the two engines are anchored to different blocks. Run `./gradlew refreshCheckpoint`."
            );

            // <digits>L, on its own line
            let java_slot: u64 = region
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_suffix("L,")
                        .or_else(|| l.trim().split_once("L, //").map(|p| p.0))
                })
                .and_then(|d| d.trim().parse().ok())
                .unwrap_or_else(|| panic!("no slot literal in the {net} region"));
            assert_eq!(
                java_slot, c.checkpoint_slot,
                "{net}: checkpoint_slot differs between NetworkConfig.java and ChainConfig::{net}()"
            );
        }
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

    /// The position-0 static peer (roost, pinned by libp2p peer id) and the
    /// last bootstrap ENR (roost's published record, seeded as a snapshot)
    /// must be the SAME node, per network — and the discv5 node id derived
    /// from the pinned peer id must equal the ENR's.
    ///
    /// This is the invariant the targeted-lookup fast path stands on: roost
    /// signs its ENR with its libp2p host key, so a wallet can walk the DHT
    /// toward `node_id_for_peer(pinned id)` and trust what comes back. If
    /// roost ever splits the keys — or someone reorders either list — the
    /// stale-pin recovery silently degrades to random-walk luck; this test
    /// makes that a red build instead.
    #[test]
    fn pinned_roost_identity_matches_its_seeded_enr() {
        for c in [
            ChainConfig::mainnet(),
            ChainConfig::sepolia(),
            ChainConfig::gnosis(),
        ] {
            let pinned = parse_static_peer(&c.static_peers[0])
                .unwrap_or_else(|| panic!("{}: unparseable position-0 static peer", c.name));
            let derived = crate::discovery::node_id_for_peer(&pinned.id).unwrap_or_else(|| {
                panic!("{}: pinned peer id does not inline a secp256k1 key", c.name)
            });
            let enr: discv5::Enr = c
                .bootstrap_enrs
                .last()
                .expect("bootstrap list is never empty")
                .parse()
                .unwrap_or_else(|e| panic!("{}: last bootstrap ENR unparseable: {e}", c.name));
            assert_eq!(
                derived,
                enr.node_id(),
                "{}: the pinned roost peer id and the seeded roost ENR disagree — \
                 either a list was reordered or roost's libp2p and discv5 keys split",
                c.name
            );
            // The snapshot must also advertise the same TCP port the pin dials.
            let pinned_port = c.static_peers[0]
                .split("/tcp/")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse::<u16>().ok())
                .expect("pinned peer has a tcp port");
            assert_eq!(
                enr.tcp4(),
                Some(pinned_port),
                "{}: ENR tcp port != pinned port",
                c.name
            );
        }
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
        assert!(!hunt_due(false, false, Duration::from_secs(10), z, false, wall, 0, 0, epoch, 8192));
        assert!(hunt_due(false, false, HUNT_BOOTSTRAP_STALL, z, false, wall, 0, 0, epoch, 8192));

        // Finality starvation: period current + finalized older than slack.
        assert!(hunt_due(false, true, z, z, false, wall, period, wall - slack - 1, epoch, 8192));
        // Fresh finality → no hunt.
        assert!(!hunt_due(false, true, z, z, false, wall, period, wall - 64, epoch, 8192));

        // PROGRESSING catch-up (period behind, store advancing) → no hunt:
        // catch-up's own wide fan-out covers the pool; hunting double-dials.
        assert!(!hunt_due(false, true, z, z, false, wall, period - 1, wall - slack - 1,
            epoch, 8192));
        // THROUGHPUT-BOUND catch-up (progressing, but catch_up says the walk
        // is limited to a few quota-bound servers) → hunt, even with fresh
        // progress; and the flag means nothing once the period is current.
        assert!(hunt_due(false, true, z, z, true, wall, period - 1, wall - slack - 1,
            epoch, 8192));
        assert!(!hunt_due(false, true, z, z, true, wall, period, wall - 64, epoch, 8192));
        // STARVED catch-up (no store progress past the stall window) → hunt.
        assert!(hunt_due(false, true, z, HUNT_CATCHUP_STALL, false, wall, period - 1,
            wall - slack - 1, epoch, 8192));
        // ...and an ENGAGED hunt survives the period boundary the same way
        // (finality starvation rotating into catch-up must not disengage).
        assert!(hunt_due(true, true, z, HUNT_CATCHUP_STALL, false, wall, period - 1,
            wall - slack - 1, epoch, 8192));

        // Hysteresis on the finality trigger: at staleness between the
        // engaged and disengaged thresholds, an engaged hunt stays on and a
        // disengaged one stays off (no flapping at the boundary).
        let between = wall - slack + epoch - 1; // stale by SLACK-1 epochs + 1 slot
        assert!(hunt_due(true, true, z, z, false, wall, period, between, epoch, 8192));
        assert!(!hunt_due(false, true, z, z, false, wall, period, between, epoch, 8192));
    }

    #[test]
    fn batch_servers_lead_the_proven_tier() {
        let mut pool = PeerPool::new();
        let mut ids = Vec::new();
        for i in 0..3u8 {
            let kp = libp2p::identity::Keypair::generate_secp256k1();
            let id = kp.public().to_peer_id();
            ids.push(id);
            pool.add(id, format!("/ip4/10.0.2.{i}/tcp/9000").parse().unwrap());
        }
        for id in &ids {
            pool.mark_proven(*id);
        }
        // ids[2] served most recently (a Lighthouse count=1 winner); ids[0]
        // is the batch server that served earlier.
        pool.note_served(ids[0]);
        std::thread::sleep(Duration::from_millis(5));
        pool.note_served(ids[2]);
        assert!(pool.mark_batch_server(ids[0]));
        assert!(!pool.mark_batch_server(ids[0]), "idempotent: second mark reports nothing new");
        assert!(pool.has_batch_server());
        let got: Vec<PeerId> = pool
            .candidates(3, true, true, &HashSet::new(), &HashSet::new())
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(got[0], ids[0], "batch server first regardless of serve recency");
        assert_eq!(got[1], ids[2], "then most-recently-served");
        assert_eq!(got[2], ids[1]);
    }

    #[test]
    fn next_single_target_spreads_lookahead_and_keeps_prefix_redundant() {
        let mut staged = std::collections::BTreeMap::new();
        let mut covered: HashMap<u64, usize> = HashMap::new();
        let chunk = || StagedChunk { ssz: vec![1], from: String::new(), alternates: Vec::new() };
        // Empty pipeline: the prefix first, PREFIX_REDUNDANCY times.
        assert_eq!(next_single_target(100, 5, &staged, &covered), Some(100));
        for _ in 0..PREFIX_REDUNDANCY {
            *covered.entry(100).or_insert(0) += 1;
        }
        // Prefix saturated: look-ahead periods, one ask each, in order.
        assert_eq!(next_single_target(100, 5, &staged, &covered), Some(101));
        covered.insert(101, 1);
        assert_eq!(next_single_target(100, 5, &staged, &covered), Some(102));
        // A staged period is skipped (a look-ahead chunk already landed).
        staged.insert(102, chunk());
        assert_eq!(next_single_target(100, 5, &staged, &covered), Some(103));
        // Whole span covered or staged → nothing to ask.
        covered.insert(103, 1);
        staged.insert(104, chunk());
        assert_eq!(next_single_target(100, 5, &staged, &covered), None);
        // An ask that came back frees its period again.
        covered.remove(&101);
        assert_eq!(next_single_target(100, 5, &staged, &covered), Some(101));
        // Zero span never asks.
        assert_eq!(next_single_target(100, 0, &staged, &covered), None);
    }

    #[test]
    fn earliest_cooldown_expiry_is_the_pipelines_wakeup() {
        let mut pool = PeerPool::new();
        let kp = libp2p::identity::Keypair::generate_secp256k1();
        let id = kp.public().to_peer_id();
        pool.add(id, "/ip4/10.0.3.1/tcp/9000".parse().unwrap());
        assert!(pool.earliest_cooldown_expiry().is_none());
        pool.set_updates_cooldown(id);
        let until = pool.earliest_cooldown_expiry().expect("a cooling peer");
        let left = until.saturating_duration_since(Instant::now());
        assert!(left <= UPDATES_SERVE_COOLDOWN && left > UPDATES_SERVE_COOLDOWN / 2);
        assert!(!pool.cooled_down(&id));
    }

    #[test]
    fn throughput_bound_verdict_has_hysteresis() {
        let min = THROUGHPUT_HUNT_MIN_SERVERS;
        // Long span, no batch server, few servers → bound.
        assert!(throughput_bound_verdict(false, 30, false, min - 1));
        // At the threshold a disengaged hunt stays off…
        assert!(!throughput_bound_verdict(false, 30, false, min));
        // …but an engaged one stays on until threshold + hysteresis.
        assert!(throughput_bound_verdict(true, 30, false, min));
        assert!(throughput_bound_verdict(true, 30, false, min + THROUGHPUT_HUNT_HYSTERESIS - 1));
        assert!(!throughput_bound_verdict(true, 30, false, min + THROUGHPUT_HUNT_HYSTERESIS));
        // A batch server or a short span ends it regardless of server count.
        assert!(!throughput_bound_verdict(true, 30, true, 0));
        assert!(!throughput_bound_verdict(false, THROUGHPUT_HUNT_MIN_SPAN - 1, false, 0));
    }

    #[test]
    fn evict_clears_batch_and_single_period_marks() {
        let mut pool = PeerPool::new();
        let kp = libp2p::identity::Keypair::generate_secp256k1();
        let id = kp.public().to_peer_id();
        pool.add(id, "/ip4/10.0.4.1/tcp/9000".parse().unwrap());
        pool.mark_proven(id);
        pool.mark_batch_server(id);
        pool.mark_single_period(id);
        assert!(pool.has_batch_server());
        pool.evict(&id);
        assert!(!pool.has_batch_server());
        assert!(!pool.wants_single_period(&id));
        assert!(pool.mark_batch_server(id), "a re-discovered peer starts unmarked");
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

    /// A DNS-NAME pin must survive rediscovery. The /dns4 pin re-resolves at
    /// every dial, so it heals through the operator's dyndns within a TTL —
    /// faster than any DHT record, whose IP updates only after the server
    /// notices the change and republishes. Overwriting the name with a
    /// discovered /ip4 snapshot (which targeted lookups would re-impose every
    /// revisit) traded the self-healing path for a stale address (#348 review).
    #[test]
    fn dns_pinned_static_is_never_downgraded_to_a_numeric_address() {
        let mut pool = PeerPool::new();
        let roost = libp2p::identity::Keypair::generate_secp256k1()
            .public()
            .to_peer_id();
        pool.add_static(roost, "/dns4/roost.example.org/tcp/9109".parse().unwrap());

        // Discovery re-reports it at its ENR's numeric address.
        pool.add(roost, "/ip4/198.51.100.7/tcp/9109".parse().unwrap());

        let addr = pool.peers.iter().find(|p| p.id == roost).map(|p| p.addr.to_string()).unwrap();
        assert_eq!(addr, "/dns4/roost.example.org/tcp/9109",
            "the name is the healing path; a numeric snapshot must not replace it");
    }

    /// The mainnet period-1840 wedge, as a unit test.
    ///
    /// One fast peer served an update that failed BLS verification (113/512
    /// participants). Before the fix it was `mark_proven`'d for merely
    /// DELIVERING the chunk — which also wiped its fail_counts — so it stayed
    /// in the preferred tier and won the next round's race too. ~4.6k identical
    /// requests later the walk had not advanced a single period.
    #[test]
    fn a_peer_serving_an_unverifiable_update_loses_priority() {
        let mut pool = PeerPool::new();
        let bad = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        pool.add(bad, "/ip4/10.0.0.1/tcp/9000".parse().unwrap());

        // It answers the protocol, so the nolc verdict is (correctly) reversed…
        pool.clear_no_lc_for(bad);
        assert!(
            !pool.proven.contains(&bad),
            "delivering bytes must NOT grant the proven tier — verification does"
        );

        // …and when its chunk fails verification it is charged, not rewarded.
        pool.note_verify_reject(bad);
        assert!(
            !pool.proven.contains(&bad),
            "a verify-reject must not leave a peer proven"
        );
        assert_eq!(
            pool.fail_counts.get(&bad).copied(),
            Some(1),
            "reject counts toward eviction"
        );
        assert!(
            pool.peers.iter().any(|p| p.id == bad),
            "ONE reject must not evict: process_update also rejects merely \
             inapplicable updates from honest servers"
        );
        assert!(
            !pool.cooled_down(&bad),
            "rejecting peer is cooled down so the next round asks someone else"
        );

        // …but a peer that keeps failing verification is eventually evicted.
        pool.note_verify_reject(bad);
        pool.note_verify_reject(bad);
        assert!(
            !pool.peers.iter().any(|p| p.id == bad),
            "repeated verify-rejects must evict, not loop forever behind a cooldown"
        );

        // A peer whose update actually verifies still gets promoted.
        let good = libp2p::identity::Keypair::generate_secp256k1().public().to_peer_id();
        pool.add(good, "/ip4/10.0.0.2/tcp/9000".parse().unwrap());
        pool.mark_proven(good);
        assert!(pool.proven.contains(&good));
    }

    /// A rejected leader must fall through to ANOTHER PEER'S copy of the same
    /// period — exercised through the real `apply_staged_step`, with the real
    /// corpus bootstrap and update, so it fails if the fallback iteration or
    /// the attribution is removed (PR #410 review: the first version of this
    /// test only inspected the Vec and would have stayed green).
    #[test]
    fn a_rejected_leader_falls_through_to_another_peers_copy() {
        use myotis_consensus::types::LightClientBootstrap;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/lc/mainnet");
        let Ok(bootstrap_ssz) = std::fs::read(dir.join("bootstrap.ssz")) else {
            eprintln!("skipping: LC corpus not present");
            return;
        };
        let bootstrap = LightClientBootstrap::decode(&bootstrap_ssz).expect("bootstrap decodes");
        // The corpus' first update is the one that applies against this anchor.
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with("-update.ssz") && n.len() == "000-update.ssz".len())
            .collect();
        names.sort();
        let good_ssz = std::fs::read(dir.join(&names[0])).expect("first update");

        let mut store = myotis_consensus::store::LightClientStore::new_mainnet_preset();
        store.initialize(bootstrap.header.clone(), bootstrap.current_sync_committee.clone());
        let expected_period = store.current_period();
        let mut processor = LightClientProcessor::new(
            store,
            crate::sync::ChainConfig::mainnet().fork_schedule,
            crate::sync::ChainConfig::mainnet().genesis_validators_root,
        );

        // A fast peer stages a chunk that cannot verify; a slower peer's HONEST
        // copy of the same period lands as an alternate.
        let mut staged: std::collections::BTreeMap<u64, StagedChunk> =
            std::collections::BTreeMap::new();
        staged.insert(
            expected_period,
            StagedChunk {
                ssz: good_ssz.iter().map(|b| b ^ 0xff).collect(), // same length, garbage
                from: "/ip4/10.0.0.1/tcp/9000/p2p/bad".into(),
                alternates: vec![(good_ssz, "/ip4/10.0.0.2/tcp/9000/p2p/good".into())],
            },
        );

        let out = apply_staged_step(&mut processor, &mut staged, u64::MAX);
        assert_eq!(out.applied, 1, "the alternate must apply after the leader is rejected");
        assert_eq!(
            out.applied_from.as_deref(),
            Some("/ip4/10.0.0.2/tcp/9000/p2p/good"),
            "credit must name the peer whose copy VERIFIED, not the responder or the leader"
        );
        assert!(
            out.rejected_from.iter().any(|f| f.contains("bad"))
                || out.decode_failures > 0,
            "the bad leader must be reported as rejected (or undecodable), never silently dropped"
        );
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
