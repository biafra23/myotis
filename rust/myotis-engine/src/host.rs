//! The hosting surface: a process-global engine that OWNS a multi-thread tokio
//! runtime and runs `myotis_net::SyncHandle`s inside it. The JNI natives
//! (lib.rs) are called from JVM threads with no tokio runtime of their own, so
//! all async work is entered via `rt.block_on` / `rt.spawn` on the runtime this
//! module owns.
//!
//! LIFECYCLE (mirrors the Java engine's create/start split):
//!   - `create` allocates an id and stores a `Created(ChainConfig)` entry —
//!     nothing runs yet.
//!   - `start` calls `SyncHandle::start` inside the runtime and swaps the entry
//!     to `Running(ChainConfig, SyncHandle)`.
//!   - `pause`/`resume` are the idle-sleep pair (the ChainHandle contract's
//!     PAUSED): pause tears the networking down but keeps the handle (and its
//!     last status) as `Paused`; resume re-runs the start path, warm-starting
//!     from the persisted snapshot / peer caches.
//!   - `status_json` reads the live `SyncStatus` (or the not-started / frozen
//!     paused shape).
//!   - `stop` removes the entry and awaits the handle's shutdown.
//!
//! PANIC POLICY: the workspace builds with `panic = "abort"`, so `catch_unwind`
//! cannot unwind — a panic here would abort the JVM. Every function in this
//! module is therefore panic-free BY CONSTRUCTION: no `unwrap`/`expect`/indexing
//! on runtime state, all lookups go through `Option`/`Result`, and the one
//! `Runtime::new` failure at startup is surfaced as an unavailable engine rather
//! than a panic. The JNI shim never dereferences a raw pointer it didn't just
//! create from a valid Rust value.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use myotis_net::el::evm::{CallAnchor, EnsQuery, EnsRootMode};
use myotis_net::el::pool::Enode;
use myotis_net::el::reader::{parse_enode, ElReader};
use myotis_net::el::readstats::ReadStats;
use myotis_net::{ChainConfig, SyncHandle, SyncState, SyncStatus};
use myotis_evm::U256;

use crate::eljson;

/// Slots per sync-committee period (for the finalized-slot → period diagnostics
/// the verified-read results carry).
const SLOTS_PER_PERIOD: u64 = 8192;

// Distinct negative sentinels from `create` (all `< 0` = failure to the Java side,
// but distinguishable for tests / future callers):
/// Unknown network name, or the tokio runtime never came up.
const CREATE_FAILED: i64 = -1;
/// A canonical catalog network this engine has no `ChainConfig` for (none today:
/// mainnet, gnosis and sepolia are all hosted; kept for the contract).
const UNSUPPORTED_NETWORK: i64 = -2;
/// The dataDir already holds sync state from a DIFFERENT trust anchor than the
/// one this call names: a caller-supplied checkpoint that does not match the
/// directory's recorded anchor, a caller-supplied checkpoint for a directory
/// whose snapshot came from the embedded checkpoint, or a plain `create` on a
/// directory bootstrapped from a caller-supplied checkpoint. Never silently
/// resolved — the host owns its directories and must pick a fresh one (or the
/// matching anchor) itself.
const ANCHOR_MISMATCH: i64 = -3;

/// One hosted chain: created-but-not-started, or running. Running keeps the
/// config so status reads can derive wall-clock values (targetPeriod) fresh.
/// `Arc` because the config is cloned out of the map on every such read (and
/// in `start`) — the deep `ChainConfig` clone happens only once, into
/// `SyncHandle::start`.
enum ChainEntry {
    Created(Arc<ChainConfig>),
    /// A running chain: the CL sync loop plus (optionally) the EL verified-read
    /// reader. The reader is `None` if its discovery/pool failed to start — the
    /// CL still runs, but EL queries report the reader unavailable. `Arc` so a
    /// query can clone it out and run OUTSIDE the handle-map lock (a verified
    /// read can take up to ~60 s for a header-chain walk).
    Running(Arc<ChainConfig>, SyncHandle, Option<Arc<ElReader>>),
    /// An idle-slept chain (the ChainHandle contract's PAUSED): networking is
    /// fully torn down (zero sockets, zero timers — the radio can sleep) but the
    /// handle stays valid and `resume` re-runs the start path, which warm-starts
    /// from the persisted snapshot / peer caches under the host's dataDir (no
    /// checkpoint re-bootstrap). Carries the last `SyncStatus` observed at pause
    /// time so status reads keep reporting the warm beacon fields while asleep,
    /// and the read-fetch shadow cache so its counters outlive the torn-down
    /// reader (they are per handle, like the Java stack's — resume hands them
    /// to the new reader).
    Paused(Arc<ChainConfig>, SyncStatus, Arc<ReadStats>),
}

/// The single legitimate engine singleton. Owns the runtime + the handle map;
/// multiple handles/networks coexist in `handles`.
struct EngineState {
    rt: tokio::runtime::Runtime,
    handles: Mutex<HashMap<i64, ChainEntry>>,
    next_id: AtomicI64,
    /// Per-handle LAST-REQUESTED served-block window (the Settings knob). Hosts
    /// set it between create() and start(), and Saves update it live too; every
    /// spin_up (start AND resume) re-applies it after building the EL reader,
    /// mirroring the Java ChainStack's pre-start buffer. Dies with the handle.
    pending_served_window: Mutex<HashMap<i64, u64>>,
    /// Per-handle LAST-PUSHED host seed pins (`set_boot_enodes_json`, #465):
    /// stashed for every spin_up (start AND resume — a resume rebuilds the
    /// pool from scratch) and applied live to a running reader, exactly like
    /// [`EngineState::pending_served_window`]. Dies with the handle.
    pending_boot_enodes: Mutex<HashMap<i64, Vec<Enode>>>,
    /// Per-handle LAST-PUSHED log-index runtime bits, as
    /// `(enabled, max_speed, backfill_paused)`. None of the three is in the
    /// portable snapshot, and a pause drops the EL reader with the index in it,
    /// so a resume re-activates from disk at the ACTIVATION defaults — enabled,
    /// walk paused — no matter what the host last said, and no host re-pushes on
    /// resume. Without this, one Android idle pause strands a walk a host asked
    /// for, and re-enables an index a host turned off. Re-applied by every
    /// spin_up (start AND resume) after activation, exactly like
    /// [`Engine::pending_served_window`]. Dies with the handle.
    log_index_runtime_bits: Mutex<HashMap<i64, (bool, bool, bool)>>,
    /// Per-handle last-good `eth_feeHistory`: the EMITTED JSON plus the raw
    /// request signature it answered, re-servable within
    /// [`FEE_HISTORY_STALE_MAX`] when a fresh build fails for the SAME
    /// signature (the Java `lastGoodFeeHistory` twin — identical params ⇒
    /// identical verified data, just older; fees drift slowly and the wallet
    /// re-polls). Kept at the JSON layer so a hit costs a String clone, never
    /// a result rebuild. Entries die with their handle (see `stop`).
    fee_history_cache: Mutex<HashMap<i64, (String, String, std::time::Instant)>>,
    /// Serializes `create` / `create_with_checkpoint` end to end (in-use guard,
    /// anchor-marker read/write, registration). Every guard in those paths is
    /// check-then-act against the filesystem and the handle map; without one
    /// lock across all of it, two racing creates on the same dataDir could both
    /// pass and persist different generations into one snapshot. Creates are
    /// cold, so a coarse lock costs nothing (the JVM's `RustMyotisEngine.create`
    /// is `synchronized` for the same reason). Never held while `handles` is
    /// taken by anything that could wait on a create.
    create_lock: Mutex<()>,
    /// Snapshot paths whose handle has been removed from `handles` but whose
    /// sync loop is still being awaited by `stop` (teardown runs OUTSIDE the
    /// map lock). A loop in that window can still persist a snapshot, so the
    /// directory stays "in use" for the create guards until the await returns
    /// — otherwise a `createWithCheckpoint` slipping in between would label a
    /// late embedded-anchor snapshot as the caller's generation.
    tearing_down: Mutex<std::collections::HashSet<std::path::PathBuf>>,
}

/// How long a last-good `eth_feeHistory` result may be re-served (the Java
/// `RPC_HEAD_SERVE_STALE_MAX_MS`).
const FEE_HISTORY_STALE_MAX: std::time::Duration = std::time::Duration::from_secs(64 * 12);

static ENGINE: OnceLock<Option<EngineState>> = OnceLock::new();

/// Lazily build (or return) the engine. `None` means the tokio runtime could not
/// be created — the whole hosting surface is then unavailable, but no panic.
fn engine() -> Option<&'static EngineState> {
    ENGINE
        .get_or_init(|| {
            match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("myotis-engine")
                .build()
            {
                Ok(rt) => Some(EngineState {
                    rt,
                    handles: Mutex::new(HashMap::new()),
                    // Start at 1 so a valid id is never confused with the -1 sentinel.
                    next_id: AtomicI64::new(1),
                    pending_served_window: Mutex::new(HashMap::new()),
                    pending_boot_enodes: Mutex::new(HashMap::new()),
                    log_index_runtime_bits: Mutex::new(HashMap::new()),
                    fee_history_cache: Mutex::new(HashMap::new()),
            create_lock: Mutex::new(()),
            tearing_down: Mutex::new(std::collections::HashSet::new()),
                }),
                Err(_) => None,
            }
        })
        .as_ref()
}

/// Resolve a config for a canonical/alias network name. Hosted: mainnet +
/// sepolia (gnosis is the remaining catalog network — its own beacon-chain
/// parameters land with the gnosis slice).
fn config_for(network_name: &str) -> Option<ChainConfig> {
    match crate::catalog::canonical_network_name(network_name) {
        Some("mainnet") => Some(ChainConfig::mainnet()),
        Some("sepolia") => Some(ChainConfig::sepolia()),
        Some("gnosis") => Some(ChainConfig::gnosis()),
        _ => None,
    }
}

/// `nativeSetTorEnabled`: turn Tor verified-read routing on/off
/// (docs/privacy-and-tor.md). Returns `true` when this engine build actually
/// supports Tor (`--features tor`), `false` when it doesn't — so a host can grey
/// out the toggle rather than pretend it works. A no-op when Tor isn't compiled.
pub fn set_tor_enabled(on: bool) -> bool {
    #[cfg(feature = "tor")]
    {
        myotis_net::el::tor::set_enabled(on);
        true
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = on;
        false
    }
}

/// `nativeTorStatus`: a small bitmask for the host's Status view —
/// bit0 compiled-in, bit1 enabled, bit2 bootstrapped (circuit ready). `0` means
/// this build has no Tor support at all.
pub fn tor_status() -> i32 {
    #[cfg(feature = "tor")]
    {
        let mut s = 1; // compiled in
        if myotis_net::el::tor::is_enabled() {
            s |= 2;
        }
        if myotis_net::el::tor::is_bootstrapped() {
            s |= 4;
        }
        s
    }
    #[cfg(not(feature = "tor"))]
    {
        0
    }
}

/// `nativeCreate`: allocate a handle for a hosted network (mainnet, gnosis,
/// sepolia). Returns the id (`>= 1`), `UNSUPPORTED_NETWORK` (-2) for a canonical
/// network this engine doesn't host yet, `CREATE_FAILED` (-1) for an unknown
/// name, an unavailable runtime, or an uncreatable dataDir, and
/// `ANCHOR_MISMATCH` (-3) when the dataDir was bootstrapped from a
/// caller-supplied checkpoint (see [`create_with_checkpoint`]) — resuming such
/// a directory from the embedded anchor would silently swap trust anchors.
pub fn create(network_name: &str, data_dir: &str) -> i64 {
    let Some(engine) = engine() else {
        return CREATE_FAILED;
    };
    let mut config = match resolve_config(network_name) {
        Ok(c) => c,
        Err(sentinel) => return sentinel,
    };
    // Guard + register under one lock (see `EngineState::create_lock`).
    let Ok(_serial) = engine.create_lock.lock() else {
        return CREATE_FAILED;
    };
    if !data_dir.is_empty() {
        let dir = match bind_persistence(&mut config, data_dir) {
            Ok(d) => d,
            Err(sentinel) => return sentinel,
        };
        // A directory carrying a caller-supplied anchor belongs to that
        // generation: the embedded checkpoint is a different trust anchor, and
        // the snapshot-resume rule would happily continue from the caller's
        // verified state as if it descended from ours. Fail closed: only a
        // marker entry that is DEFINITELY absent lets the embedded anchor in —
        // a file, a dangling symlink, an unreadable entry, or one that cannot
        // even be stat'ed all refuse (same rule as create_with_checkpoint).
        if !marker_entry_absent(&anchor_marker_path(&dir, &config)) {
            tracing::warn!(data_dir, "dataDir was bootstrapped from a caller-supplied \
                checkpoint — refusing to create it from the embedded anchor");
            return ANCHOR_MISMATCH;
        }
    }
    register(engine, config)
}

/// Like [`create`], but the light client bootstraps from the CALLER's beacon
/// block root and slot instead of the embedded checkpoint. Reached through the
/// plain C ABI (`myotis_create_with_checkpoint`) and the Node addon; the
/// UniFFI/JVM and iOS hosts have no wrapper for it (they refuse a directory it
/// has bound — see `ANCHOR_MISMATCH`). This is the recovery path for a host whose install is
/// past the weak-subjectivity bound (`STALE_ANCHOR`) and that has obtained a
/// fresher checkpoint through its own means (#441).
///
/// **Trust boundary.** The engine does not — cannot — authenticate the root.
/// It treats it exactly as it treats the embedded checkpoint: the bootstrap is
/// pinned to it (a peer can only return the committee that Merkle-proves
/// against it), every later update is BLS-verified against the committee
/// chain that follows from it, the persisted snapshot stays on probation until
/// an update verifies against it, and the weak-subjectivity gate judges the
/// supplied slot's age like any other anchor: a root that is itself past the
/// bound still parks in `STALE_ANCHOR`. That last guarantee is enforced by the
/// IN-RUN re-check in the sync loop (the one that re-judges the store's period
/// right after bootstrap, before catch-up — `run_sync`'s held-gate in
/// myotis-net's sync.rs), which reads the period the store derived from the
/// VERIFIED header, not from the slot the caller claimed; the start-time gate
/// only sees the claim, so an overstated slot buys exactly one bootstrap
/// (pinned to the caller's own root) and no forward sync. Keep that re-check
/// when refactoring the loop. Supplying a checkpoint therefore never
/// marks the client synced or unlocks verified reads early; it only moves the
/// anchor. Whether the root is the honest chain's is the caller's
/// responsibility and must be described as such to users.
///
/// **Slot.** The slot of the checkpoint BLOCK HEADER (the header whose
/// hash_tree_root equals `root`), not the epoch boundary it finalizes: with
/// skipped slots the two differ. Only the sync-committee PERIOD derived from
/// it is load-bearing (it floors what gets persisted and what a later restart
/// may resume from); the bootstrap logs a warning when the verified header's
/// slot disagrees, and a slot in a LATER period than the header degrades
/// persistence (nothing is written until the store passes the claimed period)
/// without weakening verification. `>= 1` and not in the future; the Node
/// binding additionally bounds it to a JS safe integer.
///
/// **Generations.** The first successful call on a directory records the
/// anchor in `sync-anchor[-net].json` next to the snapshot, before any sync
/// state exists. From then on the directory belongs to that anchor:
/// - the same root and slot on a later call RESUMES it — the engine's normal
///   rule applies (a persisted snapshot strictly newer than the checkpoint is
///   restored and re-verified; otherwise it bootstraps from the checkpoint
///   again), so a restart never reverts to the embedded anchor;
/// - a different root or slot, a directory whose snapshot predates the marker
///   (state from the embedded anchor), an unreadable marker, or a plain
///   [`create`] on a marked directory returns `ANCHOR_MISMATCH` (-3). Nothing
///   is deleted or rewritten; the host picks a fresh directory or the matching
///   anchor. A directory another live handle of this process already uses —
///   or one whose stopped handle is still tearing down — is refused with
///   `CREATE_FAILED` before the marker is touched: two writers into one
///   snapshot would mix generations, and a loop mid-shutdown is still a
///   writer.
///
/// Invalid inputs — unknown/unsupported network, malformed or all-zero root,
/// slot 0 or ahead of the wall clock, empty dataDir — return
/// `CREATE_FAILED` (-1) / `UNSUPPORTED_NETWORK` (-2) before the directory is
/// created or touched. A non-empty dataDir is required: a caller-supplied
/// anchor without a home for its marker could not be told apart on restart.
pub fn create_with_checkpoint(
    network_name: &str,
    data_dir: &str,
    checkpoint_root_hex: &str,
    checkpoint_slot: u64,
) -> i64 {
    let Some(engine) = engine() else {
        return CREATE_FAILED;
    };
    let mut config = match resolve_config(network_name) {
        Ok(c) => c,
        Err(sentinel) => return sentinel,
    };
    if data_dir.is_empty() {
        tracing::warn!("createWithCheckpoint needs a dataDir to record its anchor in");
        return CREATE_FAILED;
    }
    let Some(root) = parse_hex_fixed::<32>(checkpoint_root_hex) else {
        tracing::warn!("createWithCheckpoint: checkpoint root is not 32 bytes of hex");
        return CREATE_FAILED;
    };
    if root == [0u8; 32] {
        tracing::warn!("createWithCheckpoint: checkpoint root is all zeros");
        return CREATE_FAILED;
    }
    let wall_slot = config.wall_clock_slot();
    if checkpoint_slot == 0 || checkpoint_slot > wall_slot {
        tracing::warn!(slot = checkpoint_slot, wall_slot,
            "createWithCheckpoint: checkpoint slot is zero or in the future");
        return CREATE_FAILED;
    }
    // Guard, marker I/O and registration under one lock (see
    // `EngineState::create_lock`): every check below is check-then-act.
    let Ok(_serial) = engine.create_lock.lock() else {
        return CREATE_FAILED;
    };
    let dir = match bind_persistence(&mut config, data_dir) {
        Ok(d) => d,
        Err(sentinel) => return sentinel,
    };
    // A live handle already persisting into this directory (typically a plain
    // create() that has not written its first snapshot yet) would later drop
    // embedded-anchor state into the caller's generation. Host error, refused
    // before any marker is written.
    if let Some(other) = handle_using(engine, config.snapshot_path.as_deref()) {
        tracing::warn!(data_dir, other_handle = other,
            "createWithCheckpoint: dataDir is in use by another handle — refusing");
        return CREATE_FAILED;
    }
    let marker = anchor_marker_path(&dir, &config);
    match read_anchor_marker(&marker) {
        Err(()) => {
            tracing::warn!(data_dir,
                "createWithCheckpoint: existing anchor marker is unreadable — refusing \
                 (it never unlocks a resume; restore it or use a fresh directory)");
            return ANCHOR_MISMATCH;
        }
        Ok(Some((recorded_root, recorded_slot))) => {
            if recorded_root != root || recorded_slot != checkpoint_slot {
                tracing::warn!(data_dir, recorded_slot, requested_slot = checkpoint_slot,
                    "createWithCheckpoint: dataDir belongs to a different checkpoint \
                     generation — refusing");
                return ANCHOR_MISMATCH;
            }
            tracing::info!(data_dir, slot = checkpoint_slot,
                "createWithCheckpoint: resuming the recorded checkpoint generation");
        }
        Ok(None) => {
            // No marker: either a fresh directory or one that already holds a
            // snapshot from the EMBEDDED anchor. The latter must not be
            // silently adopted — its state descends from a different root.
            let has_foreign_state = config
                .snapshot_path
                .as_ref()
                .is_some_and(|p| std::fs::symlink_metadata(p).is_ok());
            if has_foreign_state {
                tracing::warn!(data_dir,
                    "createWithCheckpoint: dataDir holds a snapshot from the embedded \
                     anchor and no checkpoint marker — refusing (use a fresh directory)");
                return ANCHOR_MISMATCH;
            }
            if let Err(e) = write_anchor_marker(&marker, &root, checkpoint_slot) {
                tracing::warn!(data_dir, error = %e,
                    "createWithCheckpoint: could not record the checkpoint anchor");
                return CREATE_FAILED;
            }
            tracing::info!(data_dir, slot = checkpoint_slot,
                "createWithCheckpoint: fresh directory bound to the caller's checkpoint");
        }
    }
    config.checkpoint_root = root;
    config.checkpoint_slot = checkpoint_slot;
    register(engine, config)
}

/// Unknown network → `CREATE_FAILED`; canonical-but-not-hosted → `UNSUPPORTED`.
fn resolve_config(network_name: &str) -> Result<ChainConfig, i64> {
    match crate::catalog::canonical_network_name(network_name) {
        None => Err(CREATE_FAILED),
        Some(_) => config_for(network_name).ok_or(UNSUPPORTED_NETWORK),
    }
}

/// Point the config's persistence at the host's (non-empty) dataDir, creating
/// it, and return the directory.
///
/// Persistence lives under the host's dataDir, in the SAME files (names and
/// formats) the Java hosts/engine maintain — `sync-state[-net].snapshot` and
/// `cl-peers[-net].cache`, mainnet keeping the bare name — so verified sync
/// state and proven LC servers survive restarts AND engine switches.
fn bind_persistence(config: &mut ChainConfig, data_dir: &str) -> Result<std::path::PathBuf, i64> {
    // The dir may not exist yet (fresh host profile) — create it now.
    // Without this, sync runs fine but every snapshot/cache write fails
    // with ENOENT ("retrying on the next period advance", forever), so
    // persistence is silently lost and every restart bootstraps cold.
    // An uncreatable dataDir is a runtime-init failure the caller must
    // see (honest error over silent degradation), hence CREATE_FAILED
    // rather than warn-and-continue.
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        tracing::warn!(data_dir, error = %e, "dataDir cannot be created");
        return Err(CREATE_FAILED);
    }
    // Resolve the directory's IDENTITY, not its spelling: symlinks, `..`, and
    // relative paths all alias the same inode, and every guard below (the
    // in-use check, the anchor marker) must see one directory as one
    // directory — `create('x', real)` then `createWithCheckpoint('x', alias)`
    // used to slip past the in-use check and drop a marker into the first
    // handle's directory (reported from freedom-browser#353).
    let dir = match std::fs::canonicalize(data_dir) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(data_dir, error = %e, "dataDir cannot be resolved");
            return Err(CREATE_FAILED);
        }
    };
    let suffix = persistence_suffix(config);
    config.snapshot_path = Some(dir.join(format!("sync-state{suffix}.snapshot")));
    config.cl_peer_cache_path = Some(dir.join(format!("cl-peers{suffix}.cache")));
    Ok(dir)
}

/// The id of a live handle (created, running, or paused) whose persistence is
/// bound to `snapshot_path`, if any — or `Some(0)` when no handle owns it any
/// more but a stopped loop is still tearing down there (see `tearing_down`).
fn handle_using(engine: &EngineState, snapshot_path: Option<&std::path::Path>) -> Option<i64> {
    let target = snapshot_path?;
    // Lock order everywhere: handles, then tearing_down (stop() takes them the
    // same way), so the two views cannot interleave into a gap.
    let map = engine.handles.lock().ok()?;
    if engine.tearing_down.lock().ok()?.contains(target) {
        return Some(0);
    }
    map.iter()
        .find(|(_, entry)| {
            let cfg = match entry {
                ChainEntry::Created(c) => c,
                ChainEntry::Running(c, _, _) => c,
                ChainEntry::Paused(c, ..) => c,
            };
            cfg.snapshot_path.as_deref() == Some(target)
        })
        .map(|(id, _)| *id)
}

/// `""` for mainnet, `-<net>` otherwise — the per-network file-name suffix
/// shared with the Java hosts.
fn persistence_suffix(config: &ChainConfig) -> String {
    if config.name == "mainnet" {
        String::new()
    } else {
        format!("-{}", config.name)
    }
}

/// The caller-supplied-checkpoint marker for this network under `dir`
/// (`sync-anchor[-net].json`, next to the snapshot it governs).
fn anchor_marker_path(dir: &std::path::Path, config: &ChainConfig) -> std::path::PathBuf {
    dir.join(format!("sync-anchor{}.json", persistence_suffix(config)))
}

/// Whether the marker ENTRY is definitely absent. Judged on the directory entry
/// itself (`symlink_metadata`, never following links): a dangling symlink at
/// the marker path is an entry, not absence — following it would read ENOENT
/// and let a caller rebind the directory and overwrite the link
/// (freedom-browser#353). Any error other than NotFound also counts as
/// present (fail closed).
fn marker_entry_absent(path: &std::path::Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// Read a marker written by [`write_anchor_marker`]: `Ok(None)` when the entry
/// is absent, `Err(())` when an entry exists but cannot be read as a marker
/// (garbage, wrong shape, dangling symlink, permissions) — which both entry
/// points treat as a foreign generation (a marker we cannot read never unlocks
/// a resume).
fn read_anchor_marker(path: &std::path::Path) -> Result<Option<([u8; 32], u64)>, ()> {
    if marker_entry_absent(path) {
        return Ok(None);
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Err(());
    };
    let parse = || -> Option<([u8; 32], u64)> {
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        let root = parse_hex_fixed::<32>(v.get("checkpointRoot")?.as_str()?)?;
        let slot = v.get("checkpointSlot")?.as_u64()?;
        Some((root, slot))
    };
    parse().map(Some).ok_or(())
}

/// Record the caller's anchor DURABLY: the tree's atomic writer (unique temp,
/// fsync, rename) followed by an fsync of the parent directory that is
/// required to succeed. `write_atomic`'s own directory sync is best-effort —
/// right for a cache, where a lost rename just means the previous checkpoint —
/// but wrong here: if the rename were not durable, a power loss after the
/// engine persisted a caller-anchored snapshot could leave that snapshot
/// WITHOUT its marker, and a later plain `create()` would classify the
/// directory as embedded-anchor state and resume it under the wrong anchor.
/// So a create is registered only once the marker's directory entry is on
/// disk; any failure here surfaces as `CREATE_FAILED`, never as a handle.
fn write_anchor_marker(path: &std::path::Path, root: &[u8; 32], slot: u64) -> std::io::Result<()> {
    let body = serde_json::json!({
        "checkpointRoot": format!("0x{}", hex32(root)),
        "checkpointSlot": slot,
        "note": "trust anchor supplied by the host at createWithCheckpoint; the engine \
                 verifies forward from it but did not authenticate it",
    });
    myotis_net::el::logindex::write_atomic(path, &serde_json::to_vec_pretty(&body)?)?;
    sync_parent_dir(path)
}

/// Make a rename in `path`'s directory durable. On Unix that is an fsync of
/// the directory itself, and it must succeed. Windows has no directory fsync
/// (opening a directory as a file is refused) and NTFS journals directory
/// metadata itself, so nothing is required there.
fn sync_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let dir = path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "marker path has no parent")
        })?;
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Insert a not-yet-started handle for `config` and hand out its id.
fn register(engine: &EngineState, config: ChainConfig) -> i64 {
    let id = engine.next_id.fetch_add(1, Ordering::Relaxed);
    match engine.handles.lock() {
        Ok(mut map) => {
            map.insert(id, ChainEntry::Created(Arc::new(config)));
            id
        }
        // A poisoned lock means another native panicked mid-critical-section —
        // shouldn't happen (panic-free by construction), but never panic here.
        Err(_) => CREATE_FAILED,
    }
}

/// Which not-running entry a spin-up expects to transition from: `start` runs a
/// `Created` handle, `resume` a `Paused` one. The publish step re-checks the SAME
/// variant, so a racing stop/start/pause can never be silently overwritten.
#[derive(Clone, Copy, PartialEq)]
enum SpinUpFrom {
    Created,
    Paused,
}

/// `nativeStart`: start the sync loop for a created handle. Returns true on
/// success; false for an unknown id, an already-running/paused handle, or a
/// start error.
pub fn start(handle: i64) -> bool {
    spin_up(handle, SpinUpFrom::Created)
}

/// `nativeResume`: rebuild networking for a paused handle (the ChainHandle
/// contract's resume). Same fault isolation as `start`: on failure the entry
/// stays `Paused` (retryable). Returns true only when this call moved the
/// handle Paused → Running; the idempotent already-running semantics live on
/// the Java side, which owns the sleep accounting.
pub fn resume(handle: i64) -> bool {
    spin_up(handle, SpinUpFrom::Paused)
}

/// The shared start/resume path: build the sync loop + EL reader for a handle
/// currently in the `from` state and publish it as `Running`. Resume is a real
/// warm start — `SyncHandle::start` resumes from the persisted snapshot and the
/// EL pool from its peer cache, so no checkpoint re-bootstrap / cold discovery.
fn spin_up(handle: i64, from: SpinUpFrom) -> bool {
    let Some(engine) = engine() else {
        return false;
    };
    // Take the config under the lock, then RELEASE it before entering the runtime.
    // Holding the map lock across block_on would serialize every other native
    // (status/stop/create) behind a potentially-slow start and invites deadlock on
    // future changes — even though SyncHandle::start is fast today (spawn + return).
    let (config, read_stats) = {
        let map = match engine.handles.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        match (from, map.get(&handle)) {
            (SpinUpFrom::Created, Some(ChainEntry::Created(c))) => {
                (Arc::clone(c), Arc::new(ReadStats::new()))
            }
            // Resume keeps the shadow cache the paused reader accumulated.
            (SpinUpFrom::Paused, Some(ChainEntry::Paused(c, _, stats))) => {
                (Arc::clone(c), Arc::clone(stats))
            }
            _ => return false, // unknown id, or not in the expected state
        }
    };
    // SyncHandle::start must run inside the tokio runtime (it spawns tasks).
    // The one deep ChainConfig clone: SyncHandle::start takes it by value.
    let sync = match engine.rt.block_on(async { SyncHandle::start((*config).clone()) }) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Start the EL reader against the sync loop's execution anchor (the CL→EL
    // bridge). A failure (e.g. a discv4 UDP bind error) is non-fatal: the CL
    // still runs and EL queries report the reader unavailable, rather than
    // failing the whole start. The EL peer cache sits alongside the CL snapshot
    // under the host's dataDir, suffixed like the CL files (`peers.cache` bare
    // on mainnet — the same file the Java daemon writes — `peers-sepolia.cache`
    // etc. otherwise), so verified snap peers warm-start across restarts and
    // engine switches without cross-network contamination.
    let el_suffix = persistence_suffix(&config);
    let el_cache_path = config
        .snapshot_path
        .as_deref()
        .and_then(|p| p.parent())
        .map(|dir| dir.join(format!("peers{el_suffix}.cache")));
    // The eth_getLogs watch-list index, same dataDir + suffix convention
    // (docs/eth-getlogs-design.md). None (no dataDir) → memory-only index.
    let log_index_path = config
        .snapshot_path
        .as_deref()
        .and_then(|p| p.parent())
        .map(|dir| dir.join(format!("logindex{el_suffix}.db")));
    // Explicit per-network match: a network without an EL config here runs
    // CL-ONLY (EL queries report the reader unavailable, matching the non-fatal
    // EL philosophy) — it must never silently inherit another chain's EL config.
    let el_config = match config.name {
        "mainnet" => Some(myotis_net::el::reader::ElConfig::mainnet()),
        "sepolia" => Some(myotis_net::el::reader::ElConfig::sepolia()),
        "gnosis" => Some(myotis_net::el::reader::ElConfig::gnosis()),
        other => {
            tracing::warn!(handle, network = other, "no EL config for this network; CL runs without EL");
            None
        }
    };
    let reader = match el_config {
        Some(cfg) => match engine.rt.block_on(async {
            let cfg = myotis_net::el::reader::ElConfig { log_index_path, ..cfg };
            ElReader::start_for(sync.exec_anchor(), el_cache_path, cfg, read_stats).await
        }) {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!(handle, error = %e, "EL reader failed to start; CL runs without EL");
                None
            }
        },
        None => None,
    };
    // Apply a served-block-window set before this start (the Settings knob is
    // applied between create() and start() by the hosts) so the very first
    // eth/69 Status advertises the configured size. The stash survives
    // pause/resume cycles too; it only dies with the handle (see stop()).
    if let Some(reader) = &reader {
        if let Ok(pending) = engine.pending_served_window.lock() {
            if let Some(&w) = pending.get(&handle) {
                reader.set_served_block_window(w);
            }
        }
        // Activate a portable log-index snapshot found on disk (the drop-in
        // path): its presence in the engine's own data dir is the opt-in —
        // the daemon has no settings surface at all, and hosts that do have
        // one push their config right after start, which unions with (and
        // can disable) what this activated.
        reader.activate_log_index_from_disk(engine.rt.handle());
        // Then re-apply the host's last push. Activation sets its own defaults —
        // enabled, walk paused — which are right on a cold start, where the
        // host's push decides what happens next. A RESUME has no push behind it:
        // pause dropped the reader, the index came back off disk, and no host
        // re-pushes on resume (Android's idle pause is the common case). Without
        // this, one idle pause strands a walk the host asked for, and re-enables
        // an index the host turned off — the latter silently, since a disabled
        // index leaves its file in place for activation to find.
        if let Ok(bits) = engine.log_index_runtime_bits.lock() {
            if let Some(&(enabled, max_speed, backfill_paused)) = bits.get(&handle) {
                reader.apply_log_index_runtime_bits(enabled, max_speed, backfill_paused);
            }
        }
    }
    // Re-lock and publish ONLY if the entry is still the same Created/Paused one
    // we spun up from: a concurrent stop() may have removed it, or a racing
    // start()/resume() may have already published a Running one, while we were
    // starting. Either way, shut the handle we just started down rather than
    // orphan its tokio/libp2p host.
    let pins_reader = reader.clone();
    let mut map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => {
            shutdown(engine, sync, reader);
            return false;
        }
    };
    match (from, map.get(&handle)) {
        (SpinUpFrom::Created, Some(ChainEntry::Created(_)))
        | (SpinUpFrom::Paused, Some(ChainEntry::Paused(..))) => {
            map.insert(handle, ChainEntry::Running(config, sync, reader));
            drop(map);
            // The host's seed pins, applied AFTER the entry is Running (#465):
            // the pool was rebuilt from scratch, and the pins are the host's
            // answer to a starving pool. After, not before, the publish: a
            // push that lands while the reader is being built sees a
            // Created/Paused entry and only stashes, so reading the stash
            // here catches it, and a push from now on applies itself live.
            // Applying twice is idle (set semantics; `try_dial` dedups).
            apply_pending_boot_enodes(engine, handle, pins_reader.as_ref());
            true
        }
        _ => {
            drop(map);
            shutdown(engine, sync, reader);
            false
        }
    }
}

/// Hand the handle's stashed host seed pins (`set_boot_enodes_json`) to its EL
/// reader: read under the stash lock, applied outside it (the pool call
/// takes its own locks). No reader (the CL-only degraded mode) or no pins:
/// nothing to do — the stash stays for the next spin_up.
fn apply_pending_boot_enodes(engine: &EngineState, handle: i64, reader: Option<&Arc<ElReader>>) {
    let Some(reader) = reader else { return };
    let pins = engine
        .pending_boot_enodes
        .lock()
        .ok()
        .and_then(|pending| pending.get(&handle).cloned())
        .filter(|pins| !pins.is_empty());
    if let Some(pins) = pins {
        let reader = Arc::clone(reader);
        engine.rt.block_on(async move { reader.set_boot_enodes(pins).await });
    }
}

/// `nativePause`: idle-sleep a RUNNING handle (the ChainHandle contract's pause):
/// swap the entry to `Paused` — freezing the last observed `SyncStatus` for the
/// status reads — then tear the sync loop + EL reader down OUTSIDE the lock.
/// Warm state survives on disk (the sync loop persists its snapshot as it
/// verifies; the EL pool persists its peer cache), so `resume` warm-starts.
/// Returns true only when this call moved the handle Running → Paused (the
/// idempotent already-paused semantics live on the Java side, which owns the
/// sleep accounting).
///
/// CALLER CONTRACT: pause/resume/start/stop on one handle must not run
/// concurrently — the `Paused` entry is published BEFORE the async teardown
/// below finishes, so a resume racing into that window would spin a second
/// sync loop up against the same snapshot/peer-cache files while the first is
/// still shutting down. The Java `RustChainHandle` serializes all four on its
/// lifecycle monitor (they are `synchronized`), which is the only caller.
pub fn pause(handle: i64) -> bool {
    let Some(engine) = engine() else {
        return false;
    };
    let (sync, reader) = {
        let mut map = match engine.handles.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        // remove-then-reinsert (not get) because the teardown needs OWNERSHIP of
        // the SyncHandle; a non-Running entry is put back untouched.
        match map.remove(&handle) {
            Some(ChainEntry::Running(config, sync, reader)) => {
                let mut frozen = sync.status();
                // The frozen status keeps the warm STORE facts (state, slots,
                // periods) but must not keep live-CONNECTION facts: the libp2p
                // host and discovery are about to go down, and a paused status
                // reporting pause-time peer counts would read as live ones.
                frozen.peer_count = 0;
                frozen.served_peers_last_min = 0;
                frozen.discv5_table_size = 0;
                // The shadow cache outlives the reader; a CL-only chain
                // (no reader) parks an empty one so resume has something to
                // hand the reader it may then manage to start.
                let stats = reader
                    .as_ref()
                    .map(|r| r.read_stats())
                    .unwrap_or_else(|| Arc::new(ReadStats::new()));
                map.insert(handle, ChainEntry::Paused(config, frozen, stats));
                (sync, reader)
            }
            Some(other) => {
                map.insert(handle, other);
                return false; // created-but-not-started, or already paused
            }
            None => return false, // unknown id
        }
    };
    // Await the async teardown outside the map lock, like stop().
    engine.rt.block_on(async move {
        if let Some(reader) = &reader { reader.cancel_requests(); }
        sync.stop().await;
        if let Some(reader) = reader {
            reader.stop().await;
        }
    });
    tracing::info!(handle, "paused (networking torn down; warm state persisted)");
    true
}

/// Shut down a started-but-not-published sync handle + reader (the lost-race
/// path). Runs the async stops on the engine runtime.
fn shutdown(engine: &EngineState, sync: SyncHandle, reader: Option<Arc<ElReader>>) {
    engine.rt.block_on(async move {
        if let Some(reader) = &reader { reader.cancel_requests(); }
        sync.stop().await;
        if let Some(reader) = reader {
            reader.stop().await;
        }
    });
}

/// `nativeStatusJson`: the status of one handle as a JSON object (see
/// `status_object` for the exact keys). `"{}"` for an unknown handle.
pub fn status_json(handle: i64) -> String {
    let Some(engine) = engine() else {
        return "{}".to_string();
    };
    // Snapshot what we need under the map lock — the EL count reads are async
    // and must not run while the lock is held.
    enum Snap {
        // targetPeriod is derived from the config AT READ TIME (not carried in
        // the sync snapshot): fresh across bootstrap stalls, and real (not 0)
        // for a created-but-not-started handle — matching the Java engine.
        // Each arm carries the handle's network name so the status object can
        // report the handle's OWN network (see `status_object`).
        Created(&'static str, u64),
        Running(&'static str, SyncStatus, u64, Option<Arc<ElReader>>),
        // The status frozen at pause time (warm beacon fields keep showing).
        Paused(&'static str, SyncStatus, u64),
        Unknown,
    }
    let snap = {
        let map = match engine.handles.lock() {
            Ok(m) => m,
            Err(_) => return "{}".to_string(),
        };
        match map.get(&handle) {
            Some(ChainEntry::Created(config)) => {
                Snap::Created(config.name, config.wall_clock_period())
            }
            Some(ChainEntry::Running(config, sync, reader)) => Snap::Running(
                config.name,
                sync.status(),
                config.wall_clock_period(),
                reader.clone(),
            ),
            Some(ChainEntry::Paused(config, frozen, _)) => {
                Snap::Paused(config.name, frozen.clone(), config.wall_clock_period())
            }
            None => Snap::Unknown,
        }
    };
    match snap {
        Snap::Created(network, wall) => {
            status_object(Lifecycle::NotStarted, network, None, wall, ElCounts::default())
        }
        Snap::Running(network, status, wall, reader) => {
            let el = match reader {
                Some(r) => engine.rt.block_on(async {
                    {
                        let (h_asked, h_served, b_asked, b_served) = r.serve_stats();
                        ElCounts {
                            reader_available: true,
                            snap_peers: r.snap_peer_count().await,
                            snap_serving: r.snap_serving_count().await,
                            discovered: r.discovered_count(),
                            attempted: r.attempted_count().await,
                            backed_off: r.backoff_count().await,
                            blacklisted: r.blacklist_count().await,
                            optimistic_block: r.optimistic_block_number(),
                            finalized_block: r.finalized_block_number(),
                            header_requests: h_asked,
                            header_requests_served: h_served,
                            body_requests: b_asked,
                            body_requests_served: b_served,
                            el_hunting: r.el_hunting(),
                        }
                    }
                }),
                None => ElCounts::default(),
            };
            status_object(Lifecycle::Running, network, Some(status), wall, el)
        }
        // EL counts are zero while paused: the pool/discovery are torn down.
        Snap::Paused(network, frozen, wall) => {
            status_object(Lifecycle::Paused, network, Some(frozen), wall, ElCounts::default())
        }
        Snap::Unknown => "{}".to_string(),
    }
}

/// EL pool/discovery counts for the status snapshot (all zero for a
/// not-started handle or when the EL reader failed to start).
#[derive(Default)]
struct ElCounts {
    /// Whether the EL reader is up on this RUNNING handle. False = the reader
    /// failed to start (the documented CL-only degraded mode): EL queries can
    /// NEVER succeed until a pause/resume rebuilds it, so the Java wake gate
    /// fast-fails instead of holding the full wake cap.
    reader_available: bool,
    snap_peers: usize,
    /// The subset of `snap_peers` that can answer a read at the anchored head
    /// NOW (`ElReader::snap_serving_count`: their own word or a served proof
    /// puts them at or near it, and they are not read-benched). What the hosts
    /// gate readiness on since ABI 31 — a pool of peers still syncing keeps
    /// `snap_peers` positive for hours while every read fails (#465).
    snap_serving: usize,
    discovered: usize,
    attempted: usize,
    backed_off: usize,
    blacklisted: usize,
    /// Beacon optimistic-head execution block number (0 before the anchor has one).
    optimistic_block: u64,
    /// Finalized execution block number (0 before the anchor has one).
    finalized_block: u64,
    /// Inbound peer demand: GetBlockHeaders asked / answered non-empty, and
    /// GetBlockBodies asked / answered non-empty (the latter always 0 today).
    header_requests: u64,
    header_requests_served: u64,
    body_requests: u64,
    body_requests_served: u64,
    /// EL hunt engaged: the snap serving pool has been empty past the stall
    /// window and the pool maintainer is in emergency re-dial mode.
    el_hunting: bool,
}

/// `nativeStop`: remove + shut down a handle's sync loop. No-op for unknown id.
pub fn stop(handle: i64) {
    let Some(engine) = engine() else {
        return;
    };
    // Remove under the lock, then await shutdown OUTSIDE it (shutdown is async
    // and can take a moment; holding the map lock across it would serialize all
    // other natives needlessly).
    let entry = match engine.handles.lock() {
        Ok(mut m) => {
            let entry = m.remove(&handle);
            // Still under the map lock: the directory must never be observable
            // as free while the loop below may still write to it.
            if let Some(ChainEntry::Running(cfg, _, _)) = &entry {
                if let (Some(p), Ok(mut td)) = (cfg.snapshot_path.clone(), engine.tearing_down.lock()) {
                    td.insert(p);
                }
            }
            entry
        }
        Err(_) => return,
    };
    // The handle's cached feeHistory dies with it.
    if let Ok(mut cache) = engine.fee_history_cache.lock() {
        cache.remove(&handle);
    }
    if let Ok(mut pending) = engine.pending_served_window.lock() {
        pending.remove(&handle);
    }
    if let Ok(mut pending) = engine.pending_boot_enodes.lock() {
        pending.remove(&handle);
    }
    if let Ok(mut bits) = engine.log_index_runtime_bits.lock() {
        bits.remove(&handle);
    }
    if let Some(ChainEntry::Running(cfg, sync, reader)) = entry {
        engine.rt.block_on(async move {
            if let Some(reader) = &reader { reader.cancel_requests(); }
            sync.stop().await;
            if let Some(reader) = reader {
                reader.stop().await;
            }
        });
        // Teardown complete: no writer is left for this directory.
        if let (Some(p), Ok(mut td)) = (cfg.snapshot_path.as_ref(), engine.tearing_down.lock()) {
            td.remove(p);
        }
    }
}

/// Live-set the eth/69 served-block window (ChainHandle.setServedBlockWindow).
/// Clamped to [1, 4096] per the API contract (0 would disable serving; an
/// unbounded window is an archive-node promise a light client cannot keep).
/// Applied immediately on a RUNNING handle's EL reader; for a known handle in
/// any other state (Created/Paused/EL-less) the value is STASHED and applied at
/// the next spin_up — hosts set the knob between create() and start(), so
/// without the stash the pref would silently revert to the default every boot.
/// False only for an unknown handle.
pub fn set_served_block_window(handle: i64, blocks: i32) -> bool {
    let Some(engine) = engine() else { return false };
    let clamped = blocks.clamp(1, 4096) as u64;
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    match map.get(&handle) {
        Some(ChainEntry::Running(_, _, Some(reader))) => {
            reader.set_served_block_window(clamped);
            // Keep the stash in sync: spin_up re-applies it on resume, and a
            // stale pre-start value must not revert a newer live set.
            if let Ok(mut pending) = engine.pending_served_window.lock() {
                pending.insert(handle, clamped);
            }
            true
        }
        Some(_) => {
            // Not running yet (or EL-less right now): remember for spin_up.
            if let Ok(mut pending) = engine.pending_served_window.lock() {
                pending.insert(handle, clamped);
            }
            true
        }
        None => false,
    }
}

/// Cap on host-supplied seed pins per handle: a seed list is a handful of
/// servers the host knows to be up, not a peer database (the cache is that).
const MAX_HOST_ENODES: usize = 64;

/// Pure: a host's seed-pin push (`myotis_set_boot_enodes`) → dialable pins,
/// APPLIED OR REFUSED AS A WHOLE (CLAUDE.md §Trust — a push the engine
/// half-applied is one the host cannot reason about): a non-array, any entry
/// that is not a string or not a strict `enode://<128 hex>@ip:port` URL
/// (`parse_enode` — a DNS name is refused, not resolved), a duplicate
/// address, or more than [`MAX_HOST_ENODES`] entries refuses the push with
/// every reason named. An empty array is a valid "clear".
fn parse_boot_enodes_json(json: &str) -> Result<Vec<Enode>, String> {
    let entries = match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Array(entries)) => entries,
        Ok(_) => return Err("not a JSON array of enode:// strings".to_string()),
        Err(e) => return Err(format!("not valid JSON: {e}")),
    };
    if entries.len() > MAX_HOST_ENODES {
        return Err(format!(
            "{} entries; at most {MAX_HOST_ENODES} seed pins are accepted",
            entries.len()
        ));
    }
    let mut pins: Vec<Enode> = Vec::with_capacity(entries.len());
    let mut reasons = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let Some(url) = entry.as_str() else {
            reasons.push(format!("entry {i}: not a string"));
            continue;
        };
        match parse_enode(url) {
            Ok((addr, _)) if pins.iter().any(|(seen, _)| *seen == addr) => {
                reasons.push(format!("entry {i}: duplicate address {addr}"));
            }
            Ok(pin) => pins.push(pin),
            Err(why) => reasons.push(format!("entry {i}: {why}")),
        }
    }
    if reasons.is_empty() {
        Ok(pins)
    } else {
        Err(reasons.join("; "))
    }
}

/// `myotis_set_boot_enodes` (ABI ≥ 31, #465): replace the handle's
/// HOST-SUPPLIED EL seed pins with a JSON array of `enode://` URLs. Strict —
/// the whole push is applied or refused ([`parse_boot_enodes_json`]; `false`
/// with one WARN naming every reason, nothing applied). Applied immediately
/// on a RUNNING handle's EL reader and STASHED for every spin_up (start AND
/// resume), exactly like [`set_served_block_window`]: hosts push between
/// create() and start(), and a resume rebuilds the pool. A RUNNING handle
/// whose EL reader failed to start (`elReaderAvailable` false, the CL-only
/// degraded mode) stashes only, for the resume that rebuilds it — as the
/// served window does. Set semantics — a later push replaces an earlier one;
/// an empty array clears. `false` for an unknown handle (nothing stashed).
pub fn set_boot_enodes_json(handle: i64, enodes_json: &str) -> bool {
    let pins = match parse_boot_enodes_json(enodes_json) {
        Ok(pins) => pins,
        Err(reason) => {
            tracing::warn!(handle, %reason, "boot enodes refused; nothing applied");
            return false;
        }
    };
    let Some(engine) = engine() else { return false };
    // Stash under the handles lock — stop() removes the entry under this same
    // lock and clears the stash after, so an entry stashed for a known handle
    // cannot outlive it (set_served_block_window's discipline) — and apply to
    // the snapshotted reader OUTSIDE it (the pool call takes its own locks).
    let reader = {
        let Ok(map) = engine.handles.lock() else { return false };
        let reader = match map.get(&handle) {
            Some(ChainEntry::Running(_, _, Some(reader))) => Some(Arc::clone(reader)),
            Some(_) => None, // Created / Paused / EL-less: applied at the next spin_up
            None => return false,
        };
        if let Ok(mut pending) = engine.pending_boot_enodes.lock() {
            pending.insert(handle, pins.clone());
        }
        reader
    };
    if let Some(reader) = reader {
        engine.rt.block_on(async move { reader.set_boot_enodes(pins).await });
    }
    true
}

/// `nativeSetWsBoundPeriods`: override the weak-subjectivity anchor-age bound
/// (periods); 0 restores the network default. No stash map needed: the knob
/// lives in the config's shared `Arc<WsPolicy>`, which every entry state
/// (Created/Running/Paused) and the running sync loop's config clone all point
/// at — a loop parked in STALE_ANCHOR re-reads it within a second. False only
/// for an unknown handle.
pub fn set_ws_bound_periods(handle: i64, periods: i64) -> bool {
    let Some(engine) = engine() else { return false };
    let sane = periods.max(0) as u64;
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    match map.get(&handle) {
        Some(ChainEntry::Created(c)) | Some(ChainEntry::Running(c, _, _))
        | Some(ChainEntry::Paused(c, ..)) => {
            c.ws_policy
                .bound_override_periods
                .store(sane, std::sync::atomic::Ordering::Relaxed);
            true
        }
        None => false,
    }
}

/// `nativeAcceptStaleAnchor`: one-shot consent to sync forward from an anchor
/// older than the weak-subjectivity bound — releases a STALE_ANCHOR park for
/// the rest of this run (same shared-`WsPolicy` reach as the bound setter).
/// Never persisted. False only for an unknown handle.
pub fn accept_stale_anchor(handle: i64) -> bool {
    let Some(engine) = engine() else { return false };
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    match map.get(&handle) {
        Some(ChainEntry::Created(c)) | Some(ChainEntry::Running(c, _, _))
        | Some(ChainEntry::Paused(c, ..)) => {
            c.ws_policy
                .accept_stale_anchor
                .store(true, std::sync::atomic::Ordering::Relaxed);
            true
        }
        None => false,
    }
}

/// Verified account query as JSON (`AccountProofResult` shape / an
/// `{"error": ...}` object) — `nativeRequestAccountJson`.
pub fn request_account_json(handle: i64, address_hex: &str) -> String {
    let Some(address) = parse_address(address_hex) else {
        return eljson::error_json("invalid address (expected 20-byte hex)");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    // Snapshot the reader + the CL status/config under the lock, then release it
    // before the (potentially slow) query — never hold the map lock across a
    // verified read.
    let (reader, finalized_period, wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.get_account(address).await })) {
        Ok(account) => eljson::account_json(address_hex, &account, finalized_period, wall_period),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetStorageProofJson`: run a verified storage-slot query for a running
/// handle. `holder_hex` (if present) selects the ERC-20 mapping key.
pub fn get_storage_proof_json(
    handle: i64,
    address_hex: &str,
    slot: i64,
    holder_hex: Option<&str>,
) -> String {
    let Some(address) = parse_address(address_hex) else {
        return eljson::error_json("invalid address (expected 20-byte hex)");
    };
    let holder = match holder_hex {
        Some(h) => match parse_address(h) {
            Some(a) => Some(a),
            None => return eljson::error_json("invalid holder (expected 20-byte hex)"),
        },
        None => None,
    };
    // Preserve the bit pattern: a slot index >= 2^63 arrives as a negative
    // Java long; `as u64` recovers the intended unsigned slot (clamping to 0
    // would silently query slot 0 instead).
    let slot = slot as u64;
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, finalized_slot, optimistic_slot) = match snapshot_reader_slots(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.get_storage(address, slot, holder).await })) {
        Ok(storage) => eljson::storage_json(
            address_hex,
            holder_hex,
            &storage,
            finalized_slot,
            optimistic_slot,
        ),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetCodeJson`: run a verified contract-code query (`eth_getCode`) for a
/// running handle, returning the code result JSON, or `{"error": "..."}` for a
/// transport / not-running / bad-input failure.
pub fn get_code_json(handle: i64, address_hex: &str) -> String {
    let Some(address) = parse_address(address_hex) else {
        return eljson::error_json("invalid address (expected 20-byte hex)");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, finalized_period, wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.get_code(address).await })) {
        Ok(code) => eljson::code_json(address_hex, &code, finalized_period, wall_period),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetStorageAtJson`: run a verified RAW-32-byte-position storage query
/// (`eth_getStorageAt`) for a running handle. `position_hex` is the 32-byte
/// storage position (0x-hex); the trie key is that position itself — no ERC-20
/// mapping, unlike `get_storage_proof_json`'s `(slot, holder)`.
pub fn get_storage_at_json(handle: i64, address_hex: &str, position_hex: &str) -> String {
    let Some(address) = parse_address(address_hex) else {
        return eljson::error_json("invalid address (expected 20-byte hex)");
    };
    let Some(position) = parse_word32(position_hex) else {
        return eljson::error_json("invalid storage position (expected 32-byte hex)");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, finalized_slot, optimistic_slot) = match snapshot_reader_slots(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.get_storage_at(address, position).await })) {
        Ok(storage) => {
            eljson::storage_json(address_hex, None, &storage, finalized_slot, optimistic_slot)
        }
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeEthCallJson`: run a verified `eth_call` for a running handle. `from` is
/// empty for an anonymous call; an EMPTY `to` means CONTRACT CREATION (the
/// calldata is init code and the constructor's return data is the answer);
/// `data_hex` is the calldata;
/// `value_dec` is the wei value as a decimal string (FFI-neutral); `block` is the
/// RPC block selector, checked HERE, once for every host (#452): a head tag (or
/// empty) runs against the VERIFIED HEAD's state, `finalized` against the
/// beacon-finalized block (ABI ≥ 30, #465), a block number runs only inside the
/// window around the head ([`check_call_block`]) and still against head state,
/// and anything else is refused rather than answered from the head. Returns
/// the call JSON (`ok`/`revert`/`unavailable`, each naming the block it ran
/// against, see
/// [`eljson::call_json`]), `{"error": "..."}`, or
/// [`eljson::invalid_params_json`] for a request this node can never serve (a
/// malformed argument, or a block it will never reach).
pub fn eth_call_json(
    handle: i64,
    from_hex: &str,
    to_hex: &str,
    data_hex: &str,
    value_dec: &str,
    block: &str,
) -> String {
    eth_call_overrides_json(handle, from_hex, to_hex, data_hex, value_dec, block, "")
}

/// [`eth_call_json`] with an `eth_call` STATE OVERRIDE object (the JSON-RPC
/// third parameter) as JSON; empty means none. The overrides are the caller's
/// hypothesis layered over verified state for this call only — the answer is
/// not a chain fact, which is why hosts log it under a distinct label.
pub fn eth_call_overrides_json(
    handle: i64,
    from_hex: &str,
    to_hex: &str,
    data_hex: &str,
    value_dec: &str,
    block: &str,
    overrides_json: &str,
) -> String {
    // Every refusal of the request's own arguments is permanent (-32602): no
    // retry changes them. The block first, as the host adapters check it.
    let call_block = match parse_call_block(block) {
        Ok(b) => b,
        Err(msg) => return eljson::invalid_params_json(&msg),
    };
    let overrides = match parse_state_overrides(overrides_json) {
        Ok(o) => o,
        Err(msg) => return eljson::invalid_params_json(&msg),
    };
    let target = match call_target(to_hex) {
        Ok(t) => t,
        Err(msg) => return eljson::invalid_params_json(msg),
    };
    let creation = target.is_none();
    let to = target.unwrap_or([0u8; 20]);
    // 'from' is optional: empty → an anonymous zero-address sender.
    let from = if from_hex.trim().is_empty() {
        None
    } else {
        match parse_address(from_hex) {
            Some(a) => Some(a),
            None => {
                return eljson::invalid_params_json("invalid 'from' address (expected 20-byte hex)")
            }
        }
    };
    // Calldata may be empty (a bare value transfer / fallback call).
    let data = if data_hex.trim().is_empty() {
        Vec::new()
    } else {
        match parse_hex_bytes(data_hex) {
            Some(d) => d,
            None => return eljson::invalid_params_json("invalid call data (expected hex)"),
        }
    };
    let value = if value_dec.trim().is_empty() {
        U256::ZERO
    } else {
        match U256::from_str_radix(value_dec.trim(), 10) {
            Ok(v) => v,
            Err(_) => return eljson::invalid_params_json("invalid value (expected decimal wei)"),
        }
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, chain_id) = match snapshot_reader_evm(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    // Against the head as of dispatch, like the host adapters' own check.
    if let Err(refusal) = check_call_block(call_block, reader.optimistic_block_number()) {
        return refusal.to_json();
    }
    // `finalized` runs against the beacon-finalized block; a head tag or a
    // number inside the window runs against the head (the near-head trade-off
    // documented on check_call_block).
    let anchor = match call_block {
        BlockSelector::Finalized => CallAnchor::Finalized,
        BlockSelector::Head | BlockSelector::Number(_) => CallAnchor::Head,
    };
    match engine
        .rt
        .block_on(async {
            if creation {
                reader.eth_call_create(anchor, from, data, value, chain_id, overrides).await
            } else {
                reader
                    .eth_call_overridden(anchor, from, to, data, value, chain_id, overrides)
                    .await
            }
        })
    {
        Ok(answer) => eljson::call_json(&answer),
        Err(e) => eljson::error_json(&e),
    }
}

/// Which call the `to` argument selects. This is where the FFI convention lives
/// now that the signature is unchanged, so it is a pure function with tests:
///
/// - EMPTY ⇒ `Ok(None)` = CONTRACT CREATION (the calldata is init code and the
///   constructor's return data is the answer, as geth answers a `to`-less call).
/// - a 20-byte hex address ⇒ `Ok(Some(addr))` = an ordinary call.
/// - anything else ⇒ `Err` — NOT creation. Running init code the caller never
///   asked to run would be worse than refusing, and a malformed argument must
///   never silently change which question is answered.
fn call_target(to_hex: &str) -> Result<Option<[u8; 20]>, &'static str> {
    if to_hex.trim().is_empty() {
        return Ok(None);
    }
    match parse_address(to_hex) {
        Some(a) => Ok(Some(a)),
        None => Err("invalid 'to' address (expected 20-byte hex)"),
    }
}

/// How far BELOW the verified head a numbered `eth_call` block still runs
/// against head state. Mirrors `RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE`
/// (jsonrpc-server), the check the JVM and iOS hosts run before calling in;
/// `RustBlockWindowTest` reads this file and pins the two together.
const CALL_BLOCK_LAG_TOLERANCE: u64 = 64;

/// How far ABOVE the verified head a numbered `eth_call` block still runs
/// against head state. Mirrors `RpcBlockWindow.BLOCK_NUM_TOLERANCE`.
const CALL_BLOCK_AHEAD_TOLERANCE: u64 = 16;

/// A parsed eth block selector — for `eth_call` ([`parse_call_block`]) and the
/// block reads ([`parse_block_target`]), whose accepted syntax differs but
/// whose meaning is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockSelector {
    /// A head tag (`latest`/`pending`/`safe`), or empty — the JSON-RPC
    /// default. `safe` and `pending` still mean the head (#366).
    Head,
    /// The `finalized` tag: the beacon-FINALIZED block (ABI ≥ 30, #465) —
    /// applied, not silently mapped to the head; for a block read resolved
    /// against the anchor by [`resolve_block_target`].
    Finalized,
    /// A block number: for `eth_call` still to be checked against the verified
    /// head ([`check_call_block`]); for a block read served as is.
    Number(u64),
}

/// Parse an `eth_call` block selector with the acceptance of the hosts'
/// `RpcBlockWindow.blockInWindow`, so the engine does not refuse a pin they
/// admit: head tags in any case, `0x`/`0X` hex, and bare digits read as
/// DECIMAL (unlike [`parse_block_target`], which reads them as hex; #366 item
/// 6). Deliberately stricter in one respect: ASCII digits only and no sign,
/// where Kotlin's `toLongOrNull` also takes a sign and non-ASCII digits. No
/// JSON-RPC quantity carries either.
///
/// `Err` is a selector no retry can make servable (`earliest`, a block hash,
/// garbage), so the caller refuses it as invalid params.
fn parse_call_block(block: &str) -> Result<BlockSelector, String> {
    let b = block.trim();
    let is_tag = |t: &str| b.eq_ignore_ascii_case(t);
    if b.is_empty() || ["latest", "pending", "safe"].into_iter().any(is_tag) {
        return Ok(BlockSelector::Head);
    }
    if is_tag("finalized") {
        return Ok(BlockSelector::Finalized);
    }
    if is_tag("earliest") {
        return Err("earliest (genesis) is not served: eth_call runs against the verified \
                    head's state"
            .to_string());
    }
    let (digits, radix) = match b.strip_prefix("0x").or_else(|| b.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (b, 10),
    };
    let well_formed = !digits.is_empty() && digits.chars().all(|c| c.is_digit(radix));
    // Digits only, so the parse fails only on overflow: a number past i64::MAX
    // is malformed, as the hosts' Long parse has it.
    let number = if well_formed { i64::from_str_radix(digits, radix).ok() } else { None };
    if let Some(n) = number.and_then(|n| u64::try_from(n).ok()) {
        return Ok(BlockSelector::Number(n));
    }
    if well_formed && radix == 16 && digits.len() == 64 {
        return Err("eth_call by block hash is not supported: pass a block number or a head tag"
            .to_string());
    }
    let shown: String = b.chars().take(66).collect();
    let more = if shown.len() < b.len() { "…" } else { "" };
    Err(format!(
        "invalid block selector {shown:?}{more} (expected latest, pending, safe, finalized or a \
         block number)"
    ))
}

/// Why a numbered `eth_call` block cannot run against the verified head.
#[derive(Debug, PartialEq, Eq)]
enum CallBlockRefusal {
    /// More than [`CALL_BLOCK_LAG_TOLERANCE`] below the head. Head state would
    /// answer a different question, and the head never moves back that far:
    /// PERMANENT (-32602).
    Behind { block: u64, head: u64 },
    /// More than [`CALL_BLOCK_AHEAD_TOLERANCE`] above the head: a block this
    /// node has not verified YET. That clears as the head advances, so it is
    /// retryable, like geth's "header not found" for a future block. Calling
    /// it permanent would tell a client to stop asking a node that is only
    /// lagging.
    Ahead { block: u64, head: u64 },
    /// No verified head yet to check the number against: not synced, retryable.
    NoHead { block: u64 },
}

impl CallBlockRefusal {
    fn to_json(&self) -> String {
        match *self {
            Self::Behind { block, head } => eljson::invalid_params_json(&format!(
                "block {block:#x} ({block}) is more than {CALL_BLOCK_LAG_TOLERANCE} blocks \
                 behind the verified head ({head}); eth_call runs against head state, so this \
                 node cannot answer for that block"
            )),
            Self::Ahead { block, head } => eljson::error_json(&format!(
                "block {block:#x} ({block}) is more than {CALL_BLOCK_AHEAD_TOLERANCE} blocks \
                 ahead of the verified head ({head})"
            )),
            Self::NoHead { block } => eljson::error_json(&format!(
                "beacon not synced: no verified head to check block {block:#x} against"
            )),
        }
    }
}

/// Whether a call for `block` may run against the verified head `head` (0 =
/// none yet). A number must lie in `[head - 64, head + 16]`, the hosts'
/// window: wallets pin reads to the number `eth_blockNumber` just returned,
/// which is at or near the head. Inside the window the call still runs against
/// HEAD state, the documented near-head trade-off (exact-block execution is
/// #382). A tag needs no check here: `Head` runs at the head, `Finalized` at
/// the beacon-finalized block, whose own not-synced refusal comes from the
/// reader.
fn check_call_block(block: BlockSelector, head: u64) -> Result<(), CallBlockRefusal> {
    let BlockSelector::Number(block) = block else {
        return Ok(());
    };
    if head == 0 {
        return Err(CallBlockRefusal::NoHead { block });
    }
    if block < head.saturating_sub(CALL_BLOCK_LAG_TOLERANCE) {
        return Err(CallBlockRefusal::Behind { block, head });
    }
    if block > head.saturating_add(CALL_BLOCK_AHEAD_TOLERANCE) {
        return Err(CallBlockRefusal::Ahead { block, head });
    }
    Ok(())
}

/// Parse an `eth_call` state-override object (the JSON-RPC third parameter).
/// Empty/absent ⇒ no overrides. Pure and unit-tested: this decides what state a
/// call runs against, so a silently mis-parsed field would answer a different
/// question than the caller asked — the exact failure mode issue #314 is about.
///
/// Accepts geth's shape per address: `code`, `balance`, `nonce`, `state`
/// (full storage replacement) and `stateDiff` (per-slot overlay). An
/// unrecognised key is an ERROR rather than a silent skip, for the same
/// reason.
fn parse_state_overrides(json: &str) -> Result<myotis_evm::overrides::StateOverrides, String> {
    use myotis_evm::overrides::{AccountOverride, StateOverrides};
    let mut out = StateOverrides::new();
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(out);
    }
    let v: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|_| "malformed state override object".to_string())?;
    let Some(map) = v.as_object() else {
        return Err("state overrides must be an object keyed by address".to_string());
    };
    for (addr_str, entry) in map {
        let address =
            parse_address(addr_str).ok_or_else(|| format!("invalid override address {addr_str}"))?;
        let obj = entry
            .as_object()
            .ok_or_else(|| format!("override for {addr_str} must be an object"))?;
        let mut over = AccountOverride::default();
        for (k, val) in obj {
            match k.as_str() {
                "code" => {
                    let hex = val.as_str().ok_or("override 'code' must be a hex string")?;
                    over.code =
                        Some(parse_hex_bytes(hex).ok_or("override 'code' is not valid hex")?);
                }
                "balance" => {
                    over.balance = Some(parse_u256_hex_or_dec(val)?);
                }
                "nonce" => {
                    let n = parse_u256_hex_or_dec(val)?;
                    over.nonce = Some(u64::try_from(n).map_err(|_| "override 'nonce' too large")?);
                }
                "state" | "stateDiff" => {
                    let slots = val
                        .as_object()
                        .ok_or_else(|| format!("override '{k}' must be an object"))?;
                    let mut parsed = std::collections::HashMap::new();
                    for (slot, sv) in slots {
                        let key = parse_word32(slot).ok_or("override slot is not a 32-byte hex")?;
                        let sval = parse_word32(
                            sv.as_str().ok_or("override slot value must be a hex string")?,
                        )
                        .ok_or("override slot value is not a 32-byte hex")?;
                        parsed.insert(U256::from_be_bytes(key), U256::from_be_bytes(sval));
                    }
                    if k == "state" {
                        over.state = Some(parsed);
                    } else {
                        over.state_diff = parsed;
                    }
                }
                other => return Err(format!("unsupported state override field '{other}'")),
            }
        }
        out.insert(address, over);
    }
    Ok(out)
}

/// A quantity that may arrive as `0x`-hex or a decimal string (wallets send
/// both for `balance`/`nonce`).
fn parse_u256_hex_or_dec(v: &serde_json::Value) -> Result<U256, String> {
    let s = v.as_str().ok_or("override quantity must be a string")?.trim();
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16)
    } else {
        U256::from_str_radix(s, 10)
    };
    parsed.map_err(|_| format!("invalid override quantity '{s}'"))
}

/// `nativeResolveEnsJson`: verified ENS forward resolution for a running handle.
/// `name` is the ENS name (e.g. "vitalik.eth"); resolution runs the registry
/// resolver-walk + addr/ENSIP-10 dispatch over verified eth_calls against the
/// current head. Returns the ENS JSON (`ok`/`noRecord`/`offchain`, see
/// [`eljson::ens_json`]) or `{"error": "..."}`.
pub fn resolve_ens_json(handle: i64, name: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        return eljson::error_json("empty ENS name");
    }
    // Bound the native input: real names are short; DNS-encoding caps labels at
    // 63 bytes anyway, and an unbounded string shouldn't cross into the walk.
    if name.len() > 512 {
        return eljson::error_json("ENS name too long");
    }
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, chain_id) = match snapshot_reader_evm(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let owned = name.to_string();
    match engine
        .rt
        .block_on(async { reader.resolve_ens(owned, chain_id).await })
    {
        Ok(outcome) => eljson::ens_json(&outcome),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeEnsRecordJson`: one generic dispatch for every ENS record query
/// (EL-C-5-2) — the "one RPC dispatch layer" shape, so record types don't
/// multiply natives. `params_json` carries the method and its args:
///
/// ```json
/// {"method":"text","name":"a.eth","key":"url","root":"auto"}
/// {"method":"addr"|"contenthash"|"pubkey","name":"a.eth","root":"finalized"}
/// {"method":"multicoin","name":"a.eth","coinType":0}
/// {"method":"abi","name":"a.eth","contentTypes":15}
/// {"method":"dnsRecord","name":"a.eth","dnsName":"a.eth","resource":1}
/// {"method":"interfaceImplementer","name":"a.eth","interfaceIdHex":"0x5b5e139f"}
/// {"method":"reverse","addressHex":"0x…40-hex"}
/// ```
///
/// `root` is optional: `"auto"` (default — finalized first, optimistic
/// fallback), `"finalized"` (fails closed), or `"optimistic"` (the Java
/// PEER_HEAD twin). Returns [`eljson::ens_record_json`] shapes or
/// `{"error":"…"}`.
pub fn ens_record_json(handle: i64, params_json: &str) -> String {
    // Bound the native input like the other JSON natives. ccipCallback carries
    // gateway response payloads (L2-proof gateways return tens of KB), so it
    // gets a wide bound sized to parse_hex_bytes' own 2 MiB-hex/field cap; all
    // other methods keep the tight name-sized cap, enforced AFTER the method is
    // known (an exact check — a "ccipCallback" substring in some unrelated
    // field can't widen a record query's cap). Parsing up to the wide bound
    // first is bounded work.
    if params_json.len() > 5 * 1024 * 1024 {
        return eljson::error_json("ens params too long");
    }
    let params: serde_json::Value = match serde_json::from_str(params_json) {
        Ok(v) => v,
        Err(e) => return eljson::error_json(&format!("bad ens params JSON: {e}")),
    };
    let str_field = |key: &str| -> Option<String> {
        params.get(key).and_then(|v| v.as_str()).map(str::to_string)
    };

    let Some(method) = str_field("method") else {
        return eljson::error_json("missing method");
    };
    if method != "ccipCallback" && params_json.len() > 4096 {
        return eljson::error_json("ens params too long");
    }
    // method:"ccipCallback" re-enters after a host-driven gateway round: the
    // ORIGINAL query travels as queryMethod + its usual fields (drives the
    // decode semantics + reverse forward-verify), plus the callback tuple.
    let is_ccip = method == "ccipCallback";
    let query_method = if is_ccip {
        match str_field("queryMethod") {
            Some(m) => m,
            None => return eljson::error_json("missing queryMethod"),
        }
    } else {
        method.clone()
    };
    // Strict: a PRESENT root that isn't one of the known strings is an error
    // (a non-string value must not silently read as the default).
    let root = match params.get("root") {
        None => EnsRootMode::Auto,
        Some(v) => match v.as_str() {
            Some("auto") => EnsRootMode::Auto,
            Some("finalized") => EnsRootMode::Finalized,
            // The Java EnsRoot.PEER_HEAD twin: don't wait for finality (here
            // still beacon-anchored — no peer-claimed-head mode).
            Some("optimistic") => EnsRootMode::Optimistic,
            _ => return eljson::error_json(&format!("unknown root mode: {v}")),
        },
    };

    let query = match parse_ens_query(&query_method, &params) {
        Ok(q) => q,
        Err(e) => return eljson::error_json(&e),
    };

    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, chain_id) = match snapshot_reader_evm(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    if is_ccip {
        let Some(sender) = str_field("senderHex").and_then(|h| parse_hex_fixed::<20>(&h)) else {
            return eljson::error_json("missing/malformed senderHex");
        };
        let Some(callback) =
            str_field("callbackFunctionHex").and_then(|h| parse_hex_fixed::<4>(&h))
        else {
            return eljson::error_json("missing/malformed callbackFunctionHex");
        };
        let Some(response) = str_field("responseHex").and_then(|h| parse_hex_bytes(&h)) else {
            return eljson::error_json("missing/malformed responseHex");
        };
        let Some(extra) = str_field("extraDataHex").and_then(|h| parse_hex_bytes(&h)) else {
            return eljson::error_json("missing/malformed extraDataHex");
        };
        let Some(wrapped) = params.get("wrapped").and_then(|v| v.as_bool()) else {
            return eljson::error_json("missing wrapped");
        };
        let Some(finalized) = params.get("finalized").and_then(|v| v.as_bool()) else {
            return eljson::error_json("missing finalized");
        };
        return match engine.rt.block_on(async {
            reader
                .ens_ccip_callback(
                    query, chain_id, finalized, sender, callback, response, extra, wrapped,
                )
                .await
        }) {
            Ok(outcome) => eljson::ens_record_json(&outcome),
            Err(e) => eljson::error_json(&e),
        };
    }
    match engine
        .rt
        .block_on(async { reader.resolve_ens_query(query, chain_id, root).await })
    {
        Ok(outcome) => eljson::ens_record_json(&outcome),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeEstimateGasJson`: verified `eth_estimateGas` for a call (`to` set) over the
/// revm executor. Args as for [`eth_call_json`] minus the block (estimate always runs
/// against the verified head). Returns the estimate JSON (`ok`/`revert`/`unavailable`, see
/// [`eljson::estimate_json`]) or `{"error": "..."}`.
pub fn estimate_gas_json(
    handle: i64,
    from_hex: &str,
    to_hex: &str,
    data_hex: &str,
    value_dec: &str,
) -> String {
    let Some(to) = parse_address(to_hex) else {
        return eljson::error_json("invalid 'to' address (expected 20-byte hex)");
    };
    let from = if from_hex.trim().is_empty() {
        None
    } else {
        match parse_address(from_hex) {
            Some(a) => Some(a),
            None => return eljson::error_json("invalid 'from' address (expected 20-byte hex)"),
        }
    };
    let data = if data_hex.trim().is_empty() {
        Vec::new()
    } else {
        match parse_hex_bytes(data_hex) {
            Some(d) => d,
            None => return eljson::error_json("invalid call data (expected hex)"),
        }
    };
    let value = if value_dec.trim().is_empty() {
        U256::ZERO
    } else {
        match U256::from_str_radix(value_dec.trim(), 10) {
            Ok(v) => v,
            Err(_) => return eljson::error_json("invalid value (expected decimal wei)"),
        }
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, chain_id) = match snapshot_reader_evm(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine
        .rt
        .block_on(async { reader.estimate_gas(from, to, data, value, chain_id).await })
    {
        Ok(outcome) => eljson::estimate_json(&outcome),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetBlockByNumberJson`: verified `eth_getBlockByNumber` for a running
/// handle. `full_transactions` selects fully decoded tx objects instead of
/// hashes. Returns the block JSON when found+verified, the literal `"null"` for
/// a future/unknown block (eth's null — above the verified head and not
/// covered by finality), or `{"error": "..."}` when it can't
/// verify right now (which the Java side maps to a null → -32000).
pub fn get_block_by_number_json(handle: i64, block_tag: &str, full_transactions: bool) -> String {
    let target = match parse_block_target(block_tag) {
        Ok(t) => t,
        Err(msg) => return eljson::error_json(msg),
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let target = match resolve_block_target(target, reader.finalized_block_number()) {
        Ok(t) => t,
        Err(msg) => return eljson::error_json(&msg),
    };
    match engine
        .rt
        .block_on(reader.request(async { reader.get_block_by_number(target, full_transactions).await }))
    {
        Ok(Some(block)) => eljson::block_json(&block),
        Ok(None) => "null".to_string(), // verified future/unknown block → eth null
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetTransactionReceiptJson`: verified `eth_getTransactionReceipt` for a
/// running handle. `tx_hash_hex` is the 0x-hex 32-byte tx hash. Returns the
/// receipt JSON when the tx is found+verified in the scanned window, the literal
/// `"null"` for a verified "not seen" (pending/unknown — the wallet keeps
/// polling), or `{"error": "..."}` when it can't verify right now (the Java side
/// maps it to a null → -32000).
/// `nativePendingNonceOverlay`: the "pending" nonce overlay for
/// `eth_getTransactionCount(addr, "pending")` — `max(minedNonce, our broadcast
/// nonce + 1)` while the wallet's own tx is unmined and unexpired, identity
/// otherwise. Returns a NEGATIVE value only for a malformed address / missing
/// handle (the Java adapter then serves the plain mined nonce). A dedicated
/// native (not a field bolted onto the golden-pinned account JSON) because
/// only the pending tag ever consults it.
pub fn pending_nonce_overlay(handle: i64, address_hex: &str, mined_nonce: i64) -> i64 {
    if mined_nonce < 0 {
        return -1;
    }
    let Some(address) = parse_address(address_hex) else {
        return -1;
    };
    let Some(engine) = engine() else {
        return -1;
    };
    let Ok((reader, _finalized_period, _wall_period)) = snapshot_reader(engine, handle) else {
        return -1;
    };
    let overlaid = reader.pending_nonce_overlay(&address, mined_nonce as u64);
    i64::try_from(overlaid).unwrap_or(-1)
}

pub fn get_transaction_receipt_json(handle: i64, tx_hash_hex: &str) -> String {
    let Some(tx_hash) = parse_word32(tx_hash_hex) else {
        return eljson::error_json("invalid transaction hash (expected 32-byte hex)");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.get_transaction_receipt(tx_hash).await })) {
        Ok(Some(receipt)) => eljson::receipt_json(&receipt),
        Ok(None) => "null".to_string(), // verified "not seen" → eth null
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetTransactionByHashJson`: verified `eth_getTransactionByHash` for a
/// running handle. `tx_hash_hex` is the 0x-hex 32-byte tx hash. Returns the tx
/// JSON when found+verified — the MINED shape for a located tx, or the PENDING
/// shape (block fields explicitly null) for the wallet's own just-broadcast tx
/// from the sent-tx cache — the literal `"null"` for a verified "not seen"
/// (unknown tx), or `{"error": "..."}` when it can't verify right now.
pub fn get_transaction_by_hash_json(handle: i64, tx_hash_hex: &str) -> String {
    let Some(tx_hash) = parse_word32(tx_hash_hex) else {
        return eljson::error_json("invalid transaction hash (expected 32-byte hex)");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.get_transaction_by_hash(tx_hash).await })) {
        Ok(myotis_net::el::reader::TxLookup::Mined(tx)) => eljson::tx_json(&tx),
        Ok(myotis_net::el::reader::TxLookup::Pending { tx_hash, tx }) => {
            eljson::pending_tx_json(&tx_hash, &tx)
        }
        Ok(myotis_net::el::reader::TxLookup::NotSeen) => "null".to_string(), // eth null
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetBlockByHashJson`: verified `eth_getBlockByHash` for a running
/// handle. `block_hash_hex` is the 0x-hex 32-byte block hash;
/// `full_transactions` selects fully decoded tx objects instead of hashes.
/// Returns the block JSON, the literal `"null"` for a hash this engine has
/// never verified (eth's unknown-block null), or `{"error": "..."}`.
pub fn get_block_by_hash_json(
    handle: i64,
    block_hash_hex: &str,
    full_transactions: bool,
) -> String {
    let Some(block_hash) = parse_word32(block_hash_hex) else {
        return eljson::error_json("invalid block hash (expected 32-byte hex)");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine
        .rt
        .block_on(reader.request(async { reader.get_block_by_hash(block_hash, full_transactions).await }))
    {
        Ok(Some(block)) => eljson::block_json(&block),
        Ok(None) => "null".to_string(), // never-verified/reorged-away hash → eth null
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeSendRawTransactionJson`: gossip a signed raw transaction to peers and
/// return `{"txHash":"0x…"}` (keccak256 of the raw tx), or `{"error": "..."}` when
/// no peer could be reached / the input isn't a plausible tx. A WRITE — nothing is
/// beacon-verified; the engine never signs. `raw_hex` is the 0x-hex raw tx.
pub fn send_raw_transaction_json(handle: i64, raw_hex: &str) -> String {
    let Some(raw) = parse_hex_bytes(raw_hex) else {
        return eljson::error_json("invalid raw transaction hex");
    };
    if raw.is_empty() {
        return eljson::error_json("empty raw transaction");
    }
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.send_raw_transaction(&raw).await })) {
        Ok(hash) => eljson::tx_hash_json(&hash),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeFeeEstimateJson`: verified fee suggestion (`eth_gasPrice` +
/// `eth_maxPriorityFeePerGas`) for a running handle. Returns
/// `{"gasPriceWei":"…","maxPriorityFeePerGasWei":"…"}` (decimal wei), or
/// `{"error": "..."}` when it can't verify right now. Both RPC methods read this
/// one payload, so a paired gasPrice+maxPriorityFee poll shares a single compute.
pub fn fee_estimate_json(handle: i64) -> String {
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    match engine.rt.block_on(reader.request(async { reader.fee_estimate().await })) {
        Ok(est) => eljson::fee_json(&est),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeGetBlockReceiptsJson`: verified `eth_getBlockReceipts` for a running
/// handle. `selector` is a tag, a 0x-hex block number, or a 0x-32-byte block
/// hash (unambiguous at 66 chars — a block number is at most 18); a BARE
/// numeric is rejected — the engines' bare conventions differ (the Java engine
/// reads decimal, [`parse_block_target`] hex), so the contract is 0x-only for
/// callers that bypass the router's identical gate. Returns the receipts array
/// JSON, the literal `"null"` (verified unknown/future block, or a hash this
/// engine never verified), or `{"error": "..."}`.
pub fn get_block_receipts_json(handle: i64, selector: &str) -> String {
    let selector = selector.trim();
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let outcome = if selector.len() == 66
        && (selector.starts_with("0x") || selector.starts_with("0X"))
    {
        let Some(hash) = parse_word32(selector) else {
            return eljson::error_json("invalid block hash (expected 32-byte hex)");
        };
        engine.rt.block_on(reader.request(async { reader.get_block_receipts_by_hash(hash).await }))
    } else {
        let tag = if selector.is_empty() { "latest" } else { selector };
        let is_tag = matches!(tag, "latest" | "pending" | "safe" | "finalized" | "earliest");
        if !is_tag && !(tag.starts_with("0x") || tag.starts_with("0X")) {
            return eljson::error_json(
                "invalid block selector (expected a tag, 0x-number, or 0x-hash)",
            );
        }
        let target = match parse_block_target(tag) {
            Ok(t) => t,
            Err(msg) => return eljson::error_json(msg),
        };
        let target = match resolve_block_target(target, reader.finalized_block_number()) {
            Ok(t) => t,
            Err(msg) => return eljson::error_json(&msg),
        };
        engine.rt.block_on(reader.request(async { reader.get_block_receipts(target).await }))
    };
    match outcome {
        Ok(Some(receipts)) => eljson::block_receipts_json(&receipts),
        Ok(None) => "null".to_string(),
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeFeeHistoryJson`: verified `eth_feeHistory` for a running handle.
/// `newest_block_tag` is the RPC block selector; `percentiles_json` is a JSON
/// array of reward percentiles (e.g. `[25.0,75.0]`), or empty/`"null"` to omit
/// the reward matrix. Returns the feeHistory JSON
/// (`{"oldestBlock","baseFeePerGas","gasUsedRatio"[,"reward"]}`) or
/// `{"error": "..."}` — the Java engine's null/JSON two-state, no `"null"`
/// literal case.
pub fn fee_history_json(
    handle: i64,
    block_count: i64,
    newest_block_tag: &str,
    percentiles_json: &str,
) -> String {
    if block_count < 1 {
        return eljson::error_json("blockCount must be at least 1");
    }
    // The feeHistory newest-block selector: head tags → latest (None); a number
    // must be servable AT ALL (existence is re-checked against the head inside
    // the reader); earliest/malformed are not served — mirrors rpcFeeHistory.
    let newest = match parse_block_target(newest_block_tag.trim()) {
        Ok(t) => t,
        Err(msg) => return eljson::error_json(msg),
    };
    let percentiles = match parse_percentiles(percentiles_json) {
        Ok(p) => p,
        Err(msg) => return eljson::error_json(msg),
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let (reader, _finalized_period, _wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let newest = match resolve_block_target(newest, reader.finalized_block_number()) {
        Ok(t) => t,
        Err(msg) => return eljson::error_json(&msg),
    };
    // The raw request strings ARE the stale-serve signature (the Java
    // `blockCount + "|" + newestBlock + "|" + Arrays.toString(percentiles)`).
    let key = format!("{block_count}|{}|{}", newest_block_tag.trim(), percentiles_json.trim());
    let result = engine.rt.block_on(reader.request(async {
        Ok(reader.fee_history(block_count as u64, newest, percentiles.as_deref()).await)
    }));
    fee_history_response(result, &engine.fee_history_cache, handle, key)
}

// Keep host result/cache policy independent of the live engine for finite tests.
fn fee_history_response(
    result: Result<
        Result<myotis_net::el::reader::FeeHistory, myotis_net::el::reader::FeeHistoryError>,
        String,
    >,
    cache: &Mutex<HashMap<i64, (String, String, std::time::Instant)>>,
    handle: i64,
    key: String,
) -> String {
    // An outer operation failure is a build/availability failure, just like
    // an inner peer timeout. Explicit request Rejects retain their meaning.
    match result.unwrap_or_else(|msg| Err(myotis_net::el::reader::FeeHistoryError::Build(msg))) {
        Ok(history) => {
            let json = eljson::fee_history_json(&history);
            if let Ok(mut cache) = cache.lock() {
                cache.insert(handle, (key, json.clone(), std::time::Instant::now()));
            }
            json
        }
        // A Reject is a bad request against the CURRENT head — answered as the
        // error (→ -32000), never from a stale snapshot (Java parity: only
        // BUILD failures reach serveStaleFeeHistory).
        Err(myotis_net::el::reader::FeeHistoryError::Reject(msg)) => eljson::error_json(&msg),
        Err(myotis_net::el::reader::FeeHistoryError::Build(msg)) => {
            if let Ok(cache) = cache.lock() {
                if let Some((last_key, json, at)) = cache.get(&handle) {
                    // saturating + read once: explicit panic-free style (the
                    // workspace convention under panic="abort"), and the gate
                    // and the log line report the same age.
                    let age = std::time::Instant::now().saturating_duration_since(*at);
                    if *last_key == key && age < FEE_HISTORY_STALE_MAX {
                        tracing::info!(
                            age_secs = age.as_secs(),
                            "eth_feeHistory serving STALE result"
                        );
                        return json.clone();
                    }
                }
            }
            eljson::error_json(&msg)
        }
    }
}

/// Parse the reward-percentiles JSON: absent (empty / `"null"`) → `None` (no
/// reward matrix); else a JSON array of numbers. Bounded like the other JSON
/// natives; the VALUES are not range-checked (the router owns RPC validation —
/// this is the same pass-through the Java backend gets).
fn parse_percentiles(json: &str) -> Result<Option<Vec<f64>>, &'static str> {
    let json = json.trim();
    if json.is_empty() || json == "null" {
        return Ok(None);
    }
    if json.len() > 4096 {
        return Err("percentiles JSON too long");
    }
    let parsed: serde_json::Value =
        serde_json::from_str(json).map_err(|_| "malformed percentiles JSON")?;
    let arr = parsed.as_array().ok_or("percentiles must be a JSON array")?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        out.push(v.as_f64().ok_or("percentiles must be numbers")?);
    }
    Ok(Some(out))
}


/// Parse an eth block selector. Pure — `finalized` resolves against the anchor
/// in [`resolve_block_target`]. Earliest (genesis) and malformed/negative are
/// not served verified (`Err`, surfaced as an error the router turns into
/// -32000).
fn parse_block_target(tag: &str) -> Result<BlockSelector, &'static str> {
    match tag {
        "latest" | "pending" | "safe" => Ok(BlockSelector::Head),
        "finalized" => Ok(BlockSelector::Finalized),
        "earliest" => Err("earliest (genesis) is not served verified"),
        hex => {
            let h = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
            if h.is_empty() || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid block number");
            }
            match u64::from_str_radix(h, 16) {
                // Block 0 (any hex form) is genesis — reject it up front, same as the
                // "earliest" tag, rather than letting it fail deep in the lookback cap.
                Ok(0) => Err("earliest (genesis) is not served verified"),
                Ok(n) => Ok(BlockSelector::Number(n)),
                Err(_) => Err("block number out of range"),
            }
        }
    }
}

/// Resolve a parsed selector to the reader's target: `None` = the head,
/// `Some(n)` = a block number. `finalized` takes the anchor's finalized block
/// (`finalized_block_number`, 0 before one has landed) and is then refused with
/// a plain, RETRYABLE error — it clears when the beacon syncs, and `-32602`
/// would tell a client to stop asking a node that is merely unsynced. (The
/// `eth_call` path lets the reader refuse the same state itself, with the same
/// words.)
fn resolve_block_target(
    target: BlockSelector,
    finalized_block_number: u64,
) -> Result<Option<u64>, String> {
    match target {
        BlockSelector::Head => Ok(None),
        BlockSelector::Number(n) => Ok(Some(n)),
        BlockSelector::Finalized => match finalized_block_number {
            0 => Err("no beacon-finalized execution block yet".to_string()),
            n => Ok(Some(n)),
        },
    }
}

/// Snapshot `(reader, chain_id)` for a running handle — the EVM reads
/// (eth_call / estimateGas / resolve-ens) thread the handle's REAL chain id, so
/// nothing downstream hardcodes a network.
fn snapshot_reader_evm(
    engine: &EngineState,
    handle: i64,
) -> Result<(Arc<ElReader>, u64), &'static str> {
    let map = engine.handles.lock().map_err(|_| "engine lock poisoned")?;
    match map.get(&handle) {
        Some(ChainEntry::Running(config, _, Some(reader))) => {
            Ok((Arc::clone(reader), config.chain_id))
        }
        Some(ChainEntry::Running(_, _, None)) => Err("EL reader unavailable on this handle"),
        Some(ChainEntry::Paused(..)) => Err("handle is paused"),
        Some(ChainEntry::Created(_)) => Err("handle not started"),
        None => Err("unknown handle"),
    }
}

/// Snapshot `(reader, finalizedPeriod, wallClockPeriod)` for a running handle,
/// or an error message. Holds the map lock only for the clone.
fn snapshot_reader(
    engine: &EngineState,
    handle: i64,
) -> Result<(Arc<ElReader>, u64, u64), &'static str> {
    let map = engine.handles.lock().map_err(|_| "engine lock poisoned")?;
    match map.get(&handle) {
        Some(ChainEntry::Running(config, sync, Some(reader))) => Ok((
            Arc::clone(reader),
            sync.status().finalized_slot / SLOTS_PER_PERIOD,
            config.wall_clock_period(),
        )),
        Some(ChainEntry::Running(_, _, None)) => Err("EL reader unavailable on this handle"),
        Some(ChainEntry::Paused(..)) => Err("handle is paused"),
        Some(ChainEntry::Created(_)) => Err("handle not started"),
        None => Err("unknown handle"),
    }
}

/// Snapshot `(reader, finalizedSlot, optimisticSlot)` for a running handle.
fn snapshot_reader_slots(
    engine: &EngineState,
    handle: i64,
) -> Result<(Arc<ElReader>, u64, u64), &'static str> {
    let map = engine.handles.lock().map_err(|_| "engine lock poisoned")?;
    match map.get(&handle) {
        Some(ChainEntry::Running(_, sync, Some(reader))) => {
            let s = sync.status();
            Ok((Arc::clone(reader), s.finalized_slot, s.optimistic_slot))
        }
        Some(ChainEntry::Running(_, _, None)) => Err("EL reader unavailable on this handle"),
        Some(ChainEntry::Paused(..)) => Err("handle is paused"),
        Some(ChainEntry::Created(_)) => Err("handle not started"),
        None => Err("unknown handle"),
    }
}

/// Build the [`EnsQuery`] for one record method from the params JSON — shared
/// by the direct dispatch AND the ccipCallback re-entry (which passes the
/// ORIGINAL query's method as `queryMethod`), so the two paths can never
/// disagree on decode semantics. `Err` is the user-facing message.
fn parse_ens_query(query_method: &str, params: &serde_json::Value) -> Result<EnsQuery, String> {
    let str_field = |key: &str| -> Option<String> {
        params.get(key).and_then(|v| v.as_str()).map(str::to_string)
    };
    let u64_field = |key: &str| -> Option<u64> { params.get(key).and_then(|v| v.as_u64()) };
    let name_field = |key: &str| -> Result<String, String> {
        let Some(name) = str_field(key) else {
            return Err(format!("missing {key}"));
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(format!("empty {key}"));
        }
        if name.len() > 512 {
            return Err(format!("{key} too long"));
        }
        Ok(name)
    };

    Ok(match query_method {
        "addr" => EnsQuery::Addr { name: name_field("name")? },
        "contenthash" => EnsQuery::Contenthash { name: name_field("name")? },
        "pubkey" => EnsQuery::Pubkey { name: name_field("name")? },
        "text" => {
            let name = name_field("name")?;
            let Some(key) = str_field("key").filter(|k| !k.is_empty()) else {
                return Err("missing key".to_string());
            };
            if key.len() > 512 {
                return Err("key too long".to_string());
            }
            EnsQuery::Text { name, key }
        }
        "multicoin" => {
            let name = name_field("name")?;
            let Some(coin_type) = u64_field("coinType") else {
                return Err("missing coinType".to_string());
            };
            EnsQuery::Multicoin { name, coin_type }
        }
        "abi" => {
            let name = name_field("name")?;
            let Some(content_types) = u64_field("contentTypes") else {
                return Err("missing contentTypes".to_string());
            };
            EnsQuery::Abi { name, content_types }
        }
        "dnsRecord" => {
            let name = name_field("name")?;
            let dns_name = name_field("dnsName")?;
            let resource = match u64_field("resource") {
                Some(r) if r <= u64::from(u16::MAX) => r as u16,
                Some(_) => return Err("resource out of range (uint16)".to_string()),
                None => return Err("missing resource".to_string()),
            };
            EnsQuery::DnsRecord { name, dns_name, resource }
        }
        "interfaceImplementer" => {
            let name = name_field("name")?;
            let Some(id_hex) = str_field("interfaceIdHex") else {
                return Err("missing interfaceIdHex".to_string());
            };
            let Some(id) = parse_hex_fixed::<4>(&id_hex) else {
                return Err("interfaceIdHex must be 4 bytes of hex".to_string());
            };
            EnsQuery::Interface { name, interface_id: id }
        }
        "reverse" => {
            let Some(addr_hex) = str_field("addressHex") else {
                return Err("missing addressHex".to_string());
            };
            let Some(address) = parse_hex_fixed::<20>(&addr_hex) else {
                // The Java EnsApi contract's message for a malformed reverse input.
                return Err("address must be a 20-byte hex string (40 hex chars)".to_string());
            };
            EnsQuery::Reverse { address }
        }
        other => return Err(format!("unknown ens method: {other}")),
    })
}

/// Parse a `0x`-prefixed-or-bare hex string into exactly `N` bytes. Panic-free:
/// `None` for any malformed input (JNI callers pass untrusted strings).
fn parse_hex_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    if hex.len() != 2 * N || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse a `0x`-prefixed-or-bare 40-char hex address into 20 bytes. Panic-free:
/// returns `None` for any malformed input (JNI callers pass untrusted strings).
fn parse_address(hex: &str) -> Option<[u8; 20]> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    // Require exactly 40 hex digits — reject the sign/whitespace that
    // `u8::from_str_radix` would otherwise accept (e.g. a "+f" byte-pair).
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse a variable-length 0x-hex byte string (a raw transaction). `None` for odd
/// length or a non-hex digit.
fn parse_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    // Cap before allocating: a real tx is well under this (~1 MB), and the workspace
    // builds with panic=abort, so an unbounded `with_capacity` on a hostile giant
    // input could OOM-abort the JVM. Reject rather than allocate.
    if hex.len() > 2 * 1024 * 1024 || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        out.push(u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()?);
        i += 2;
    }
    Some(out)
}

/// Parse a 32-byte storage position (`eth_getStorageAt`) from 0x-hex. The Java
/// side normalizes to a full 64-hex-digit word before the call, so require
/// exactly that — same strictness as `parse_address`.
fn parse_word32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Map a `SyncState` to the API `beaconState` string.
fn beacon_state(state: SyncState) -> &'static str {
    match state {
        SyncState::Starting => "SYNCING",
        SyncState::Bootstrapping => "SYNCING",
        SyncState::CatchingUp => "CATCHING_UP",
        SyncState::Synced => "SYNCED",
        SyncState::StaleAnchor => "STALE_ANCHOR",
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Coarse lifecycle of one handle for the status JSON — the native half of the
/// API's `LifecycleState` (a Created handle reports NotStarted; the map has no
/// entry at all for a stopped/unknown one, which reads as `"{}"`).
#[derive(Clone, Copy, PartialEq)]
enum Lifecycle {
    NotStarted,
    Running,
    Paused,
}

/// Serialize the status object with EXACTLY the keys the Java `RustChainHandle`
/// parses (camelCase). `NotStarted` / `status=None` → the not-started shape;
/// `Paused` carries the SyncStatus frozen at pause time (warm beacon fields).
/// Built by hand (not serde) so the key set + ordering is the golden contract
/// both `status_json_shape` tests pin.
fn status_object(
    lifecycle: Lifecycle,
    network: &str,
    status: Option<SyncStatus>,
    target_period: u64,
    el: ElCounts,
) -> String {
    let s = status.unwrap_or_else(SyncStatus::initial);
    // A not-started handle reports STARTING; a running/paused one maps its
    // live/frozen state.
    let beacon = if lifecycle == Lifecycle::NotStarted {
        "STARTING"
    } else {
        beacon_state(s.state)
    };
    let bootstrapped = lifecycle != Lifecycle::NotStarted
        && matches!(s.state, SyncState::CatchingUp | SyncState::Synced);
    let mut obj = serde_json::Map::new();
    obj.insert("running".into(), (lifecycle == Lifecycle::Running).into());
    // The PAUSED discriminator (running=false, paused=true → the API's PAUSED;
    // both false → STOPPED). Older Java wrappers ignore the unknown key.
    obj.insert("paused".into(), (lifecycle == Lifecycle::Paused).into());
    // The handle's OWN network (`ChainConfig::name`), not a constant: the JVM
    // hosts pass `networkName` in beside the JSON and ignore this key, but the
    // napi/Node consumer reads the raw object and has nothing else to go on —
    // a hardcoded "mainnet" made every gnosis/sepolia handle self-report as
    // mainnet (issue #291).
    obj.insert("network".into(), network.into());
    obj.insert("beaconState".into(), beacon.into());
    obj.insert("bootstrapped".into(), bootstrapped.into());
    obj.insert("finalizedSlot".into(), s.finalized_slot.into());
    obj.insert("optimisticSlot".into(), s.optimistic_slot.into());
    obj.insert("currentPeriod".into(), s.period.into());
    // Floor at the store's period: a device clock set in the past must not
    // publish a target below current (the target >= current invariant).
    obj.insert("targetPeriod".into(), target_period.max(s.period).into());
    obj.insert("peerCount".into(), s.peer_count.into());
    obj.insert("servedPeersLastMinute".into(), s.served_peers_last_min.into());
    obj.insert("discv5TableSize".into(), s.discv5_table_size.into());
    obj.insert("syncStartPeriod".into(), s.sync_start_period.into());
    // LC hunt engaged (starved of light-client servers) — drives the hosts'
    // hunt banner on the Status screen.
    obj.insert("lcHunting".into(), s.hunting.into());
    // Weak-subjectivity bound (periods) the engine enforces. While beaconState
    // is STALE_ANCHOR, currentPeriod is the refused anchor's period, so
    // targetPeriod - currentPeriod is the anchor age judged against this.
    obj.insert("wsBoundPeriods".into(), s.ws_bound_periods.into());
    obj.insert("finalizedRootHex".into(), hex32(&s.finalized_root).into());
    // EL pool/discovery counts (the Rust engine's execution-layer side). The
    // pool keeps only snap-capable READY peers, so readyPeers == snapPeers —
    // both count POOLED peers. snapServingPeers (ABI >= 31) is the subset that
    // can answer a read at the anchored head now; it is what the hosts gate
    // on (#465). elReaderAvailable distinguishes "EL warming up" from "EL
    // reader failed to start" (the CL-only degraded mode) — the wake gate
    // fast-fails the latter.
    obj.insert("elReaderAvailable".into(), el.reader_available.into());
    obj.insert("snapPeers".into(), el.snap_peers.into());
    obj.insert("snapServingPeers".into(), el.snap_serving.into());
    obj.insert("readyPeers".into(), el.snap_peers.into());
    obj.insert("discoveredPeers".into(), el.discovered.into());
    obj.insert("attemptedDials".into(), el.attempted.into());
    obj.insert("backedOffPeers".into(), el.backed_off.into());
    obj.insert("blacklistedPeers".into(), el.blacklisted.into());
    // Execution head/finalized block numbers from the beacon anchor. optimistic
    // drives eth_blockNumber; executionBlockNumber == finalized (the finalized
    // payload's block), matching the StatusSnapshot field semantics.
    obj.insert("optimisticBlockNumber".into(), el.optimistic_block.into());
    obj.insert("finalizedBlockNumber".into(), el.finalized_block.into());
    obj.insert("peerHeaderRequests".into(), el.header_requests.into());
    obj.insert("peerHeaderRequestsServed".into(), el.header_requests_served.into());
    obj.insert("peerBodyRequests".into(), el.body_requests.into());
    obj.insert("peerBodyRequestsServed".into(), el.body_requests_served.into());
    obj.insert("executionBlockNumber".into(), el.finalized_block.into());
    // EL hunt flag (snap serving pool empty past the stall window).
    obj.insert("elHunting".into(), el.el_hunting.into());
    // A hand-built object of primitives always serializes; fall back to the
    // literal not-started shape rather than panic on the (impossible) error.
    serde_json::to_string(&serde_json::Value::Object(obj))
        .unwrap_or_else(|_| NOT_STARTED_FALLBACK.to_string())
}

/// The exact not-started shape, used only if serde ever failed (it can't for a
/// primitive object) — keeps this function total. Its `network` is necessarily
/// a literal; every reachable path builds the object above with the handle's
/// real network name.
const NOT_STARTED_FALLBACK: &str = concat!(
    r#"{"running":false,"paused":false,"network":"mainnet","beaconState":"STARTING","#,
    r#""bootstrapped":false,"finalizedSlot":0,"optimisticSlot":0,"#,
    r#""currentPeriod":0,"targetPeriod":0,"peerCount":0,"servedPeersLastMinute":0,"#,
    r#""discv5TableSize":0,"syncStartPeriod":-1,"lcHunting":false,"wsBoundPeriods":0,"#,
    r#""finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000","#,
    r#""elReaderAvailable":false,"#,
    r#""snapPeers":0,"snapServingPeers":0,"readyPeers":0,"discoveredPeers":0,"attemptedDials":0,"#,
    r#""backedOffPeers":0,"blacklistedPeers":0,"optimisticBlockNumber":0,"#,
    r#""finalizedBlockNumber":0,"executionBlockNumber":0,"elHunting":false,"#,
    r#""peerHeaderRequests":0,"peerHeaderRequestsServed":0,"#,
    r#""peerBodyRequests":0,"peerBodyRequestsServed":0}"#,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_history_outer_failure_preserves_stale_cache_policy() {
        use myotis_net::el::reader::FeeHistoryError;
        let key = "2|latest|null".to_string();
        let json = r#"{"oldestBlock":"0x1","baseFeePerGas":["0x1"]}"#.to_string();
        let cache = Mutex::new(HashMap::from([(
            7,
            (key.clone(), json.clone(), std::time::Instant::now()),
        )]));
        for message in ["request deadline exceeded", "request cancelled"] {
            assert_eq!(
                fee_history_response(Err(message.into()), &cache, 7, key.clone()),
                json
            );
            assert_eq!(
                fee_history_response(
                    Ok(Err(FeeHistoryError::Build(message.into()))),
                    &cache,
                    7,
                    key.clone()
                ),
                json
            );
        }
        let reject = "newest block is beyond the verified head";
        assert_eq!(
            fee_history_response(
                Ok(Err(FeeHistoryError::Reject(reject.into()))),
                &cache,
                7,
                key.clone()
            ),
            eljson::error_json(reject)
        );
        assert_eq!(
            fee_history_response(
                Err("request cancelled".into()),
                &cache,
                7,
                "different request".into()
            ),
            eljson::error_json("request cancelled")
        );
        assert_eq!(
            fee_history_response(Err("request cancelled".into()), &cache, 8, key),
            eljson::error_json("request cancelled")
        );
    }

    #[test]
    fn fee_history_outer_failure_does_not_serve_expired_cache() {
        let key = "2|latest|null".to_string();
        let expired = std::time::Instant::now()
            .checked_sub(FEE_HISTORY_STALE_MAX)
            .unwrap();
        let cache = Mutex::new(HashMap::from([(7, (key.clone(), "stale".into(), expired))]));
        assert_eq!(
            fee_history_response(Err("request deadline exceeded".into()), &cache, 7, key),
            eljson::error_json("request deadline exceeded")
        );
    }

    #[test]
    fn create_makes_the_data_dir() {
        // A nested, not-yet-existing dataDir (fresh host profile) must exist
        // after create — otherwise the sync loop's snapshot/cache writes fail
        // with ENOENT forever and persistence is silently lost.
        let dir = std::env::temp_dir()
            .join(format!("myotis-create-dir-test-{}", std::process::id()))
            .join("nested");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        let id = create("mainnet", dir.to_str().unwrap());
        assert!(id >= 1, "create failed: {id}");
        assert!(dir.is_dir(), "dataDir was not created");
        stop(id);
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn create_with_checkpoint_rejects_bad_input_before_touching_the_disk() {
        let dir = std::env::temp_dir()
            .join(format!("myotis-cwc-reject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        let root = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let future = ChainConfig::mainnet().wall_clock_slot() + 10_000;
        for (label, id) in [
            ("unknown network", create_with_checkpoint("nope", d, root, 100)),
            ("short root", create_with_checkpoint("mainnet", d, "0x1234", 100)),
            ("non-hex root", create_with_checkpoint("mainnet", d, &"zz".repeat(32), 100)),
            ("zero root", create_with_checkpoint("mainnet", d, &"00".repeat(32), 100)),
            ("slot 0", create_with_checkpoint("mainnet", d, root, 0)),
            ("future slot", create_with_checkpoint("mainnet", d, root, future)),
            ("empty data_dir", create_with_checkpoint("mainnet", "", root, 100)),
        ] {
            assert_eq!(id, CREATE_FAILED, "{label} must be refused with CREATE_FAILED");
        }
        // Refusals happen BEFORE any state mutation: no directory, no marker.
        assert!(!dir.exists(), "a refused createWithCheckpoint must not create the dataDir");
    }

    #[test]
    fn create_with_checkpoint_binds_a_fresh_dir_and_resumes_only_the_same_anchor() {
        let dir = std::env::temp_dir()
            .join(format!("myotis-cwc-gen-{}", std::process::id()))
            .join("fresh");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        let d = dir.to_str().unwrap();
        let root = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let other = "0x3333333333333333333333333333333333333333333333333333333333333333";
        let slot = 8_192 * 3 + 5; // not an epoch boundary on purpose

        // Fresh directory: bound to the caller's anchor, config carries it.
        let id = create_with_checkpoint("mainnet", d, root, slot);
        assert!(id >= 1, "fresh createWithCheckpoint failed: {id}");
        let marker = dir.join("sync-anchor.json");
        assert!(marker.is_file(), "the anchor marker must be written on first use");
        assert_eq!(read_anchor_marker(&marker), Ok(Some((parse_hex_fixed::<32>(root).unwrap(), slot))));
        {
            let map = engine().unwrap().handles.lock().unwrap();
            let ChainEntry::Created(cfg) = map.get(&id).expect("handle registered") else {
                panic!("fresh handle must be Created");
            };
            assert_eq!(cfg.checkpoint_root, parse_hex_fixed::<32>(root).unwrap());
            assert_eq!(cfg.checkpoint_slot, slot);
            assert_eq!(cfg.snapshot_path.as_deref(), Some(dir.join("sync-state.snapshot").as_path()));
        }
        // While that handle is alive the directory is in use: a second binding —
        // even the same anchor — is refused before any marker work.
        assert_eq!(create_with_checkpoint("mainnet", d, root, slot), CREATE_FAILED);
        stop(id);

        // Same anchor again: resume (a second handle, same generation).
        let again = create_with_checkpoint("mainnet", d, root, slot);
        assert!(again >= 1, "same-anchor restart must resume: {again}");
        stop(again);

        // A different root, or the same root at another slot: refused, marker untouched.
        assert_eq!(create_with_checkpoint("mainnet", d, other, slot), ANCHOR_MISMATCH);
        assert_eq!(create_with_checkpoint("mainnet", d, root, slot + 1), ANCHOR_MISMATCH);
        assert_eq!(read_anchor_marker(&marker), Ok(Some((parse_hex_fixed::<32>(root).unwrap(), slot))));

        // The embedded anchor must not be able to adopt this generation either.
        assert_eq!(create("mainnet", d), ANCHOR_MISMATCH);

        // Another network in the same dir is a separate generation (own suffix).
        let g = create_with_checkpoint("gnosis", d, other, slot);
        assert!(g >= 1, "per-network markers are independent: {g}");
        assert!(dir.join("sync-anchor-gnosis.json").is_file());
        stop(g);

        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn create_with_checkpoint_refuses_a_dir_holding_embedded_anchor_state() {
        // A snapshot without a marker is state that descends from the EMBEDDED
        // checkpoint: adopting it would let the snapshot-resume rule continue
        // from a different trust anchor than the caller named.
        let dir = std::env::temp_dir()
            .join(format!("myotis-cwc-foreign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sync-state.snapshot"), b"whatever").unwrap();
        let root = "0x4444444444444444444444444444444444444444444444444444444444444444";
        assert_eq!(create_with_checkpoint("mainnet", dir.to_str().unwrap(), root, 100), ANCHOR_MISMATCH);
        assert!(!dir.join("sync-anchor.json").exists(), "no marker may be written on refusal");
        // The plain path still works on such a directory (no marker → not ours to refuse).
        let id = create("mainnet", dir.to_str().unwrap());
        assert!(id >= 1);
        stop(id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn directory_aliases_share_one_identity_for_the_guards() {
        // freedom-browser#353 repro: create(real) then createWithCheckpoint(alias)
        // used to yield two live handles and a marker in the first handle's dir.
        let base = std::env::temp_dir().join(format!("myotis-cwc-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        let alias = base.join("alias");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let root = "0x8888888888888888888888888888888888888888888888888888888888888888";

        let id = create("mainnet", real.to_str().unwrap());
        assert!(id >= 1);
        // The alias is the same directory: in use, refused, and no marker written.
        assert_eq!(create_with_checkpoint("mainnet", alias.to_str().unwrap(), root, 100), CREATE_FAILED);
        assert!(!real.join("sync-anchor.json").exists(), "no marker may land in a live handle's dir");
        stop(id);

        // Bind through the alias; the real path must then see the marker.
        let g = create_with_checkpoint("mainnet", alias.to_str().unwrap(), root, 100);
        assert!(g >= 1, "{g}");
        assert!(real.join("sync-anchor.json").is_file());
        // Plain create sees the marker through the real path (its refusal is the
        // marker, not the in-use guard, which is createWithCheckpoint's).
        assert_eq!(create("mainnet", real.to_str().unwrap()), ANCHOR_MISMATCH, "bound via alias");
        stop(g);
        assert_eq!(create("mainnet", real.to_str().unwrap()), ANCHOR_MISMATCH);
        // And resuming through either spelling is the same generation.
        let r = create_with_checkpoint("mainnet", real.to_str().unwrap(), root, 100);
        assert!(r >= 1, "{r}");
        stop(r);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_the_marker_path_is_an_entry_not_absence() {
        // freedom-browser#353 repro: a dangling `sync-anchor.json` symlink used to read
        // as "no marker" (ENOENT through the link), so createWithCheckpoint bound the
        // directory and replaced the link. Both constructors must refuse it.
        let dir = std::env::temp_dir().join(format!("myotis-cwc-dangling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("sync-anchor.json");
        std::os::unix::fs::symlink(dir.join("does-not-exist"), &marker).unwrap();
        assert!(!marker_entry_absent(&marker));
        assert_eq!(read_anchor_marker(&marker), Err(()));
        let root = "0x9999999999999999999999999999999999999999999999999999999999999999";
        assert_eq!(create_with_checkpoint("mainnet", dir.to_str().unwrap(), root, 100), ANCHOR_MISMATCH);
        assert_eq!(create("mainnet", dir.to_str().unwrap()), ANCHOR_MISMATCH);
        assert!(std::fs::symlink_metadata(&marker).unwrap().file_type().is_symlink(),
            "the dangling link must be left untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_still_tearing_down_counts_as_in_use() {
        // stop() removes the handle from the map before awaiting its loop, which
        // may still persist a snapshot; the directory must stay "in use" for the
        // create guards until teardown returns (Copilot on #442).
        let dir = std::env::temp_dir().join(format!("myotis-cwc-teardown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let canonical = std::fs::canonicalize(&dir).unwrap();
        let snap = canonical.join("sync-state.snapshot");
        let engine = engine().unwrap();
        engine.tearing_down.lock().unwrap().insert(snap.clone());
        let root = "0xabababababababababababababababababababababababababababababababab";
        assert_eq!(create_with_checkpoint("mainnet", dir.to_str().unwrap(), root, 100), CREATE_FAILED);
        assert!(!canonical.join("sync-anchor.json").exists(), "no marker while a writer may remain");
        engine.tearing_down.lock().unwrap().remove(&snap);
        let id = create_with_checkpoint("mainnet", dir.to_str().unwrap(), root, 100);
        assert!(id >= 1, "{id}");
        stop(id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn anchor_marker_round_trips_and_rejects_garbage() {
        let dir = std::env::temp_dir()
            .join(format!("myotis-cwc-marker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("sync-anchor.json");
        let root = [0xabu8; 32];
        assert_eq!(read_anchor_marker(&p), Ok(None), "absent marker reads as None");
        write_anchor_marker(&p, &root, 12_345).unwrap();
        assert_eq!(read_anchor_marker(&p), Ok(Some((root, 12_345))));
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n != "sync-anchor.json").collect();
        assert!(leftovers.is_empty(), "temp files must be renamed away: {leftovers:?}");
        // Garbage is Err, never None: a marker we cannot read must never unlock a
        // resume (createWithCheckpoint answers ANCHOR_MISMATCH on it).
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(read_anchor_marker(&p), Err(()));
        std::fs::write(&p, br#"{"checkpointRoot":"0x12","checkpointSlot":1}"#).unwrap();
        assert_eq!(read_anchor_marker(&p), Err(()));
        let other = "0x7777777777777777777777777777777777777777777777777777777777777777";
        assert_eq!(create_with_checkpoint("mainnet", dir.to_str().unwrap(), other, 100), ANCHOR_MISMATCH);
        assert_eq!(create("mainnet", dir.to_str().unwrap()), ANCHOR_MISMATCH);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_fails_loudly_on_uncreatable_data_dir() {
        // A dataDir that cannot exist (path through a regular file) is a
        // runtime-init failure the caller must see, not a warn-and-continue.
        let file = std::env::temp_dir()
            .join(format!("myotis-create-file-test-{}", std::process::id()));
        std::fs::write(&file, b"not a dir").unwrap();
        let id = create("mainnet", file.join("sub").to_str().unwrap());
        assert_eq!(id, CREATE_FAILED);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn parse_ens_query_maps_every_method_correctly() {
        use myotis_net::el::evm::EnsQuery;
        let q = |method: &str, extra: &str| {
            let json: serde_json::Value =
                serde_json::from_str(&format!(r#"{{"name":"a.eth"{extra}}}"#)).unwrap();
            parse_ens_query(method, &json)
        };
        // The addr/contenthash/pubkey trio must NEVER collapse into one arm —
        // the ccipCallback re-entry passes these as queryMethod, and a mis-map
        // decodes an address answer with pubkey semantics (a real regression).
        assert!(matches!(q("addr", "").unwrap(), EnsQuery::Addr { .. }));
        assert!(matches!(q("contenthash", "").unwrap(), EnsQuery::Contenthash { .. }));
        assert!(matches!(q("pubkey", "").unwrap(), EnsQuery::Pubkey { .. }));
        assert!(matches!(q("text", r#","key":"url""#).unwrap(), EnsQuery::Text { .. }));
        assert!(matches!(q("multicoin", r#","coinType":60"#).unwrap(), EnsQuery::Multicoin { coin_type: 60, .. }));
        assert!(matches!(q("abi", r#","contentTypes":15"#).unwrap(), EnsQuery::Abi { .. }));
        assert!(matches!(
            q("dnsRecord", r#","dnsName":"a.eth","resource":1"#).unwrap(),
            EnsQuery::DnsRecord { resource: 1, .. }
        ));
        assert!(matches!(
            q("interfaceImplementer", r#","interfaceIdHex":"0x9061b923""#).unwrap(),
            EnsQuery::Interface { interface_id: [0x90, 0x61, 0xb9, 0x23], .. }
        ));
        let rev: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"addressHex":"0x{}"}}"#, "d8".repeat(20))).unwrap();
        assert!(matches!(parse_ens_query("reverse", &rev).unwrap(), EnsQuery::Reverse { .. }));
        // ccipCallback can never be a queryMethod (no native recursion).
        assert!(parse_ens_query("ccipCallback", &rev).is_err());
        assert!(parse_ens_query("bogus", &rev).is_err());
    }

    #[test]
    fn not_started_status_shape_is_stable() {
        // The golden not-started object (parsed by the Java RustChainHandle test).
        let json = status_object(Lifecycle::NotStarted, "mainnet", None, 0, ElCounts::default());
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["running"], false);
        assert_eq!(v["paused"], false);
        assert_eq!(v["network"], "mainnet");
        assert_eq!(v["beaconState"], "STARTING");
        assert_eq!(v["bootstrapped"], false);
        assert_eq!(v["finalizedSlot"], 0);
        assert_eq!(v["optimisticSlot"], 0);
        assert_eq!(v["currentPeriod"], 0);
        assert_eq!(v["targetPeriod"], 0);
        assert_eq!(v["peerCount"], 0);
        assert_eq!(v["servedPeersLastMinute"], 0);
        assert_eq!(v["discv5TableSize"], 0);
        assert_eq!(v["syncStartPeriod"], -1);
        assert_eq!(
            v["finalizedRootHex"],
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(v["elReaderAvailable"], false);
        // EL counts are zero for a not-started handle.
        for k in ["snapPeers", "snapServingPeers", "readyPeers", "discoveredPeers",
                  "attemptedDials", "backedOffPeers", "blacklistedPeers",
                  "optimisticBlockNumber", "finalizedBlockNumber", "executionBlockNumber"] {
            assert_eq!(v[k], 0, "{k} should be 0 when not started");
        }
        // Round-trips through the fallback constant too.
        let fb: serde_json::Value =
            serde_json::from_str(NOT_STARTED_FALLBACK).expect("fallback valid json");
        assert_eq!(v, fb);
    }

    #[test]
    fn status_reports_the_handles_own_network() {
        // Issue #291: a gnosis handle self-reported "mainnet" because the key
        // was a constant. The napi/Node consumer reads this raw object, so the
        // label is the only network identity it has.
        for network in ["mainnet", "gnosis", "sepolia"] {
            let json =
                status_object(Lifecycle::NotStarted, network, None, 0, ElCounts::default());
            let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
            assert_eq!(v["network"], network, "not-started handle on {network}");

            let running = status_object(
                Lifecycle::Running,
                network,
                Some(SyncStatus::initial()),
                0,
                ElCounts::default(),
            );
            let v: serde_json::Value = serde_json::from_str(&running).expect("valid json");
            assert_eq!(v["network"], network, "running handle on {network}");
        }
    }

    #[test]
    fn running_state_maps_to_beacon_state() {
        let mk = |state: SyncState| SyncStatus {
            state,
            finalized_slot: 100,
            finalized_root: [0xab; 32],
            optimistic_slot: 132,
            period: 1777,
            peer_count: 7,
            served_peers_last_min: 3,
            discv5_table_size: 12,
            sync_start_period: 1777,
            hunting: false,
            ws_bound_periods: 13,
        };
        let el = ElCounts {
            reader_available: true,
            snap_peers: 5,
            snap_serving: 3,
            discovered: 240,
            attempted: 14,
            backed_off: 30,
            blacklisted: 66,
            optimistic_block: 21_000_010,
            finalized_block: 20_999_000,
            header_requests: 6,
            header_requests_served: 2,
            body_requests: 1,
            body_requests_served: 0,
            el_hunting: false,
        };
        let synced: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Running,
            "mainnet",
            Some(mk(SyncState::Synced)),
            1795,
            el,
        ))
        .unwrap();
        assert_eq!(synced["running"], true);
        assert_eq!(synced["paused"], false);
        assert_eq!(synced["beaconState"], "SYNCED");
        assert_eq!(synced["bootstrapped"], true);
        assert_eq!(synced["finalizedSlot"], 100);
        assert_eq!(synced["peerHeaderRequests"], 6);
        assert_eq!(synced["peerHeaderRequestsServed"], 2);
        assert_eq!(synced["peerBodyRequests"], 1);
        assert_eq!(synced["peerBodyRequestsServed"], 0);
        assert_eq!(synced["optimisticSlot"], 132);
        assert_eq!(synced["currentPeriod"], 1777);
        assert_eq!(synced["targetPeriod"], 1795);
        assert_eq!(synced["peerCount"], 7);
        assert_eq!(synced["servedPeersLastMinute"], 3);
        assert_eq!(synced["discv5TableSize"], 12);
        assert_eq!(synced["syncStartPeriod"], 1777);
        assert_eq!(synced["wsBoundPeriods"], 13);
        assert_eq!(synced["finalizedRootHex"], hex32(&[0xab; 32]));
        // EL counts reflect the pool/discovery snapshot (snapPeers drives
        // readyPeers, since the pool holds only snap-capable READY peers;
        // snapServingPeers is its own count — the peers that can answer now).
        assert_eq!(synced["elReaderAvailable"], true);
        assert_eq!(synced["snapPeers"], 5);
        assert_eq!(synced["snapServingPeers"], 3);
        assert_eq!(synced["readyPeers"], 5);
        assert_eq!(synced["discoveredPeers"], 240);
        assert_eq!(synced["attemptedDials"], 14);
        assert_eq!(synced["backedOffPeers"], 30);
        assert_eq!(synced["blacklistedPeers"], 66);
        assert_eq!(synced["optimisticBlockNumber"], 21_000_010);
        assert_eq!(synced["finalizedBlockNumber"], 20_999_000);
        assert_eq!(synced["executionBlockNumber"], 20_999_000);

        for (st, expect, boot) in [
            (SyncState::Starting, "SYNCING", false),
            (SyncState::Bootstrapping, "SYNCING", false),
            (SyncState::CatchingUp, "CATCHING_UP", true),
        ] {
            let v: serde_json::Value = serde_json::from_str(&status_object(
                Lifecycle::Running,
                "mainnet",
                Some(mk(st)),
                1795,
                ElCounts::default(),
            ))
            .unwrap();
            assert_eq!(v["beaconState"], expect);
            assert_eq!(v["bootstrapped"], boot);
        }
    }

    #[test]
    fn paused_status_keeps_frozen_beacon_fields() {
        // A paused handle: running=false + paused=true (the Java side's PAUSED),
        // the beacon fields frozen at pause time, and all EL counts zero (the
        // pool/discovery are torn down while asleep).
        let frozen = SyncStatus {
            state: SyncState::Synced,
            finalized_slot: 14_560_000,
            finalized_root: [0xab; 32],
            optimistic_slot: 14_560_032,
            period: 1777,
            peer_count: 7,
            served_peers_last_min: 3,
            discv5_table_size: 12,
            sync_start_period: 1777,
            hunting: false,
            ws_bound_periods: 13,
        };
        let v: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Paused,
            "mainnet",
            Some(frozen),
            1795,
            ElCounts::default(),
        ))
        .unwrap();
        assert_eq!(v["running"], false);
        assert_eq!(v["paused"], true);
        assert_eq!(v["elReaderAvailable"], false);
        assert_eq!(v["beaconState"], "SYNCED");
        assert_eq!(v["bootstrapped"], true);
        assert_eq!(v["finalizedSlot"], 14_560_000);
        assert_eq!(v["currentPeriod"], 1777);
        assert_eq!(v["targetPeriod"], 1795);
        for k in ["snapPeers", "snapServingPeers", "readyPeers", "discoveredPeers",
                  "attemptedDials", "backedOffPeers", "blacklistedPeers",
                  "optimisticBlockNumber", "finalizedBlockNumber", "executionBlockNumber"] {
            assert_eq!(v[k], 0, "{k} should be 0 while paused");
        }
    }

    #[test]
    fn served_block_window_stashes_pre_start_and_rejects_unknown() {
        // Unknown handle → false (the Java wrapper logs the drop).
        assert!(!set_served_block_window(999_999, 64));
        // A Created (not-started) handle stashes the clamped value for spin_up.
        let handle = create("mainnet", std::env::temp_dir().to_str().unwrap());
        assert!(handle > 0);
        assert!(set_served_block_window(handle, 999_999)); // clamps to 4096
        let engine = engine().unwrap();
        assert_eq!(
            engine.pending_served_window.lock().unwrap().get(&handle),
            Some(&4096)
        );
        assert!(set_served_block_window(handle, 0)); // clamps to 1
        assert_eq!(
            engine.pending_served_window.lock().unwrap().get(&handle),
            Some(&1)
        );
        // The stash dies with the handle.
        stop(handle);
        assert!(engine.pending_served_window.lock().unwrap().get(&handle).is_none());
    }

    #[test]
    fn boot_enodes_json_is_applied_or_refused_as_a_whole() {
        let key = "ab".repeat(64);
        let pin = |host: &str| format!("enode://{key}@{host}");
        // The empty "clear", and a valid list.
        assert_eq!(parse_boot_enodes_json("[]").unwrap(), vec![]);
        let two = parse_boot_enodes_json(&format!(
            r#"["{}","{}"]"#,
            pin("1.2.3.4:30303"),
            pin("[2001:db8::1]:30303")
        ))
        .unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].1, [0xab; 64]);
        // Refused as a whole, every reason named — a good entry beside a bad
        // one is not applied.
        let mixed = parse_boot_enodes_json(&format!(r#"["{}","nope",7]"#, pin("1.2.3.4:30303")))
            .unwrap_err();
        assert!(mixed.contains("entry 1: missing the enode:// prefix"), "{mixed}");
        assert!(mixed.contains("entry 2: not a string"), "{mixed}");
        let dup = parse_boot_enodes_json(&format!(
            r#"["{}","{}"]"#,
            pin("1.2.3.4:30303"),
            pin("1.2.3.4:30303")
        ))
        .unwrap_err();
        assert!(dup.contains("entry 1: duplicate address 1.2.3.4:30303"), "{dup}");
        assert!(parse_boot_enodes_json("{}").unwrap_err().contains("not a JSON array"));
        assert!(parse_boot_enodes_json("[").unwrap_err().contains("not valid JSON"));
        let dns = parse_boot_enodes_json(&format!(r#"["{}"]"#, pin("node.example.org:30303")))
            .unwrap_err();
        assert!(dns.contains("numeric ip:port"), "{dns}");
        let many = format!(
            "[{}]",
            (0..=MAX_HOST_ENODES)
                .map(|i| format!("\"{}\"", pin(&format!("10.0.0.{i}:1"))))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(parse_boot_enodes_json(&many).unwrap_err().contains("at most 64"));
    }

    #[test]
    fn boot_enodes_stash_pre_start_refuse_malformed_and_clear_on_stop() {
        let key = "ab".repeat(64);
        let list = format!(r#"["enode://{key}@1.2.3.4:30303"]"#);
        // Unknown handle → false, nothing stashed.
        assert!(!set_boot_enodes_json(999_999, &list));
        let dir = std::env::temp_dir().join("myotis-host-boot-enodes-test");
        let handle = create("mainnet", dir.to_str().unwrap());
        assert!(handle > 0);
        let engine = engine().unwrap();
        let stashed = |h: i64| engine.pending_boot_enodes.lock().unwrap().get(&h).map(|p| p.len());
        assert!(stashed(999_999).is_none());
        // A Created (not-started) handle stashes the pins for spin_up.
        assert!(set_boot_enodes_json(handle, &list));
        assert_eq!(stashed(handle), Some(1));
        // A malformed push is refused and leaves the earlier one in place.
        assert!(!set_boot_enodes_json(handle, r#"["nope"]"#));
        assert_eq!(stashed(handle), Some(1));
        // An empty array is a valid clear.
        assert!(set_boot_enodes_json(handle, "[]"));
        assert_eq!(stashed(handle), Some(0));
        // The stash dies with the handle.
        stop(handle);
        assert!(stashed(handle).is_none());
    }

    #[test]
    fn pause_and_resume_reject_unknown_and_not_started_handles() {
        // Unknown ids: neither transition applies (and nothing panics).
        assert!(!pause(i64::MIN));
        assert!(!resume(i64::MIN));
        // A created-but-never-started handle can't pause (it isn't RUNNING) and
        // can't resume (it isn't PAUSED) — and stays intact/startable after both.
        let id = create("mainnet", "");
        assert!(id >= 1, "create failed: {id}");
        assert!(!pause(id));
        assert!(!resume(id));
        let v: serde_json::Value = serde_json::from_str(&status_json(id)).unwrap();
        assert_eq!(v["running"], false);
        assert_eq!(v["paused"], false);
        stop(id);
    }

    #[test]
    fn target_period_is_floored_at_current_period() {
        // A device clock behind the store's committee period (wall period 1770 <
        // store period 1777) must not publish an inverted target.
        let s = SyncStatus {
            state: SyncState::CatchingUp,
            finalized_slot: 100,
            finalized_root: [0u8; 32],
            optimistic_slot: 132,
            period: 1777,
            peer_count: 7,
            served_peers_last_min: 3,
            discv5_table_size: 12,
            sync_start_period: 1777,
            hunting: false,
            ws_bound_periods: 13,
        };
        let v: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Running,
            "mainnet",
            Some(s),
            1770,
            ElCounts::default(),
        ))
        .unwrap();
        assert_eq!(v["currentPeriod"], 1777);
        assert_eq!(v["targetPeriod"], 1777);
    }

    #[test]
    fn stale_anchor_state_maps_and_carries_the_bound() {
        // A parked handle: beaconState STALE_ANCHOR (NOT bootstrapped), period =
        // the refused anchor's period, wsBoundPeriods = the enforced bound — so a
        // host can render "anchor is (target - current) periods old, bound N".
        let s = SyncStatus {
            state: SyncState::StaleAnchor,
            finalized_slot: 0,
            finalized_root: [0u8; 32],
            optimistic_slot: 0,
            period: 1825,
            peer_count: 0,
            served_peers_last_min: 0,
            discv5_table_size: 0,
            sync_start_period: -1,
            hunting: false,
            ws_bound_periods: 13,
        };
        let v: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Running,
            "mainnet",
            Some(s),
            1845,
            ElCounts::default(),
        ))
        .unwrap();
        assert_eq!(v["beaconState"], "STALE_ANCHOR");
        assert_eq!(v["bootstrapped"], false);
        assert_eq!(v["currentPeriod"], 1825);
        assert_eq!(v["targetPeriod"], 1845);
        assert_eq!(v["wsBoundPeriods"], 13);
    }

    #[test]
    fn unknown_handle_returns_empty_object() {
        // No engine calls here — just the contract for a missing handle, which
        // status_json returns directly.
        assert_eq!(status_json(i64::MIN), "{}");
    }

    #[test]
    fn parse_block_target_cases() {
        assert_eq!(parse_block_target("latest"), Ok(BlockSelector::Head));
        assert_eq!(parse_block_target("pending"), Ok(BlockSelector::Head));
        assert_eq!(parse_block_target("safe"), Ok(BlockSelector::Head));
        assert_eq!(parse_block_target("finalized"), Ok(BlockSelector::Finalized));
        assert_eq!(parse_block_target("0x1406f40"), Ok(BlockSelector::Number(21_000_000)));
        // `finalized` resolves to the anchor's finalized block — applied — and
        // is refused, retryably, before one has landed.
        assert_eq!(resolve_block_target(BlockSelector::Head, 20_999_936), Ok(None));
        assert_eq!(resolve_block_target(BlockSelector::Number(7), 20_999_936), Ok(Some(7)));
        assert_eq!(
            resolve_block_target(BlockSelector::Finalized, 20_999_936),
            Ok(Some(20_999_936))
        );
        assert!(resolve_block_target(BlockSelector::Finalized, 0).is_err());
        assert!(parse_block_target("earliest").is_err());
        // Block 0 (genesis) is rejected up front in any hex form, like "earliest".
        assert!(parse_block_target("0x0").is_err());
        assert!(parse_block_target("0x00").is_err());
        assert!(parse_block_target("0").is_err());
        // Malformed selectors.
        assert!(parse_block_target("0xzz").is_err());
        assert!(parse_block_target("0x").is_err());
    }

    #[test]
    fn parse_address_accepts_valid_and_rejects_malformed() {
        assert_eq!(parse_address(&"11".repeat(20)), Some([0x11; 20]));
        assert_eq!(parse_address(&format!("0x{}", "22".repeat(20))), Some([0x22; 20]));
        assert_eq!(parse_address(&format!("0X{}", "22".repeat(20))), Some([0x22; 20]));
        assert!(parse_address("0x1234").is_none()); // too short
        assert!(parse_address(&"zz".repeat(20)).is_none()); // non-hex
        assert!(parse_address(&"+f".repeat(20)).is_none()); // sign rejected
        assert!(parse_address("").is_none());
    }

    #[test]
    fn account_query_rejects_bad_address_and_unknown_handle() {
        // Bad address → error before any handle lookup.
        let v: serde_json::Value =
            serde_json::from_str(&request_account_json(1, "0xnothex")).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid address"));

        // Valid address, unknown handle → "unknown handle" error.
        let addr = format!("0x{}", "ab".repeat(20));
        let v: serde_json::Value =
            serde_json::from_str(&request_account_json(i64::MIN, &addr)).unwrap();
        assert_eq!(v["error"], "unknown handle");
    }

    #[test]
    fn storage_query_rejects_bad_holder() {
        let addr = format!("0x{}", "ab".repeat(20));
        let v: serde_json::Value =
            serde_json::from_str(&get_storage_proof_json(i64::MIN, &addr, 1, Some("0xbad"))).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid holder"));
    }
}

// ---------------------------------------------------------------------------
// eth_getLogs (docs/eth-getlogs-design.md): watch-list config install, index
// status, and the coverage-honest query. All JSON in / JSON out, panic-free.
// ---------------------------------------------------------------------------

/// Install the watch-list config: `{"enabled":bool,"watch":[{"address":"0x..",
/// "fromBlock":n,"topic0s":["0x..",..]?,"name":"..."?}]}`. False on malformed
/// input, duplicate addresses, or an unavailable reader.
pub fn set_log_index_config_json(handle: i64, config_json: &str) -> bool {
    // Both refusals below were silent: the caller got a bare `false` with
    // nothing in the engine log to say why, and since the parser screens
    // duplicate addresses the reader's own warning never fires for a JSON
    // caller either. Say it once, here, at the boundary that decides.
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
        tracing::warn!("log-index config is not valid JSON; ignoring the push");
        return false;
    };
    let Some(config) = parse_log_index_config(&v) else {
        tracing::warn!(
            "log-index config refused: a watch entry is missing `address` or `fromBlock`, \
             a field has the wrong type or is not valid hex, or the watch list names \
             one address twice; ignoring the push"
        );
        return false;
    };
    let enabled = config.enabled;
    let bits = (config.enabled, config.max_speed, config.backfill_paused);
    let Some(engine) = engine() else {
        return false;
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return false;
    };
    let installed = reader.set_log_index_config(config);
    if installed {
        // Remember what the host asked for, so a resume re-applies it instead of
        // the activation defaults (see `Engine::log_index_runtime_bits`). Written
        // under the handles lock, and only while the handle is still Running, so a
        // push racing `stop()` cannot leave a stash entry behind a removed handle
        // — the same discipline `set_served_block_window` keeps.
        if let Ok(map) = engine.handles.lock() {
            if matches!(map.get(&handle), Some(ChainEntry::Running(..))) {
                if let Ok(mut stash) = engine.log_index_runtime_bits.lock() {
                    stash.insert(handle, bits);
                }
            }
        }
    }
    if installed && enabled {
        // Spawn (or keep) the head-follow appender on the engine runtime.
        reader.ensure_log_index_appender(engine.rt.handle());
    }
    installed
}

/// A JSON boolean field that must be a boolean if it is there at all.
///
/// Absent (or `null`, which every host's "field omitted" encodes as) yields
/// `default`; a real boolean yields itself; anything else yields `None`, which
/// makes the caller refuse the config instead of applying a default the caller
/// never asked for.
fn strict_bool(v: &serde_json::Value, key: &str, default: bool) -> Option<bool> {
    match v.get(key) {
        None | Some(serde_json::Value::Null) => Some(default),
        Some(other) => other.as_bool(),
    }
}

/// Pure config-JSON → typed config (unit-tested; the FFI wrapper above only
/// adds engine plumbing). `None` = malformed — a watch entry missing the
/// required `address` or `fromBlock`, a field of the wrong type, an address
/// or topic that is not valid hex of the right width, or a watch-list that
/// names one address twice. Unknown keys are ignored for forward
/// compatibility.
fn parse_log_index_config(
    v: &serde_json::Value,
) -> Option<myotis_net::el::logindex::LogIndexConfig> {
    // Every scalar here decides what the index DOES, so a present-but-malformed
    // value refuses the whole config rather than falling back to a default: a
    // caller that wrote `"enabled":"true"` would otherwise get a running index
    // silently switched off, with no way to tell (CLAUDE.md §Trust — applied or
    // refused, never silently replaced). Absent stays the documented default.
    let enabled = strict_bool(v, "enabled", false)?;
    // Backfill pacing (optional; absent = nice/background). Fingerprint-neutral:
    // flipping it re-applies onto the live index without resetting coverage.
    let max_speed = strict_bool(v, "maxSpeed", false)?;
    // Absent means "not paused": a host that predates this key keeps walking,
    // which is the behaviour it already had.
    let backfill_paused = strict_bool(v, "backfillPaused", false)?;
    let mut watch = Vec::new();
    if v.get("watch").is_some_and(|w| !w.is_array() && !w.is_null()) {
        return None;
    }
    if let Some(entries) = v.get("watch").and_then(|w| w.as_array()) {
        for e in entries {
            let address = e.get("address").and_then(|a| a.as_str()).and_then(parse_address)?;
            let from_block = e.get("fromBlock").and_then(|b| b.as_u64())?;
            let mut topic0s = Vec::new();
            if e.get("topic0s").is_some_and(|t| !t.is_array() && !t.is_null()) {
                return None;
            }
            if let Some(ts) = e.get("topic0s").and_then(|t| t.as_array()) {
                for t in ts {
                    topic0s.push(t.as_str().and_then(parse_word32)?);
                }
            }
            // Optional cosmetic label (empty = unnamed). A non-string name is
            // malformed like any other wrong type — never silently coerced.
            if e.get("name").is_some_and(|n| !n.is_string() && !n.is_null()) {
                return None;
            }
            let name = e.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            watch.push(myotis_net::el::logindex::WatchEntry { address, from_block, topic0s, name });
        }
    }
    let config =
        myotis_net::el::logindex::LogIndexConfig { enabled, max_speed, backfill_paused, watch };
    // The one config the index layer refuses outright. The reader refuses it
    // too (and leaves its installed index alone doing so), but catching it
    // here keeps a malformed push off the checkpoint lock entirely — that lock
    // can be held for as long as an import takes to merge GBs, and a caller
    // that is going to get `false` either way should not wait behind it.
    if config.duplicate_address().is_some() {
        return None;
    }
    Some(config)
}

/// Import portable log-index snapshots: `paths_json` is a JSON array of
/// absolute file paths (each a v2 self-describing snapshot of THIS handle's
/// chain). They merge with the node's current index (all-or-nothing), the
/// result is persisted + installed, and — since importing IS the opt-in —
/// the appender is spawned so catch-up starts immediately.
/// Returns `{"ok":true,"status":<status json>}` or `{"error":"..."}`.
pub fn import_log_index_files(handle: i64, paths_json: &str) -> String {
    let paths = match serde_json::from_str::<Vec<String>>(paths_json) {
        Ok(p) if !p.is_empty() && p.iter().all(|s| !s.trim().is_empty()) => {
            p.into_iter().map(std::path::PathBuf::from).collect::<Vec<_>>()
        }
        _ => return eljson::error_json("expected a non-empty JSON array of file paths"),
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return eljson::error_json("node is not running");
    };
    match reader.import_log_index(&paths) {
        Ok(()) => {
            reader.ensure_log_index_appender(engine.rt.handle());
            format!("{{\"ok\":true,\"status\":{}}}", log_index_status_json(handle))
        }
        Err(e) => eljson::error_json(&e),
    }
}

/// Export the current index as a portable snapshot at `path` (the
/// generator's output; finality-clamped, self-describing v2 — importable
/// anywhere on the same chain). `{"ok":true}` or `{"error":"..."}`.
pub fn export_log_index(handle: i64, path: &str) -> String {
    if path.trim().is_empty() {
        return eljson::error_json("empty export path");
    }
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return eljson::error_json("node is not running");
    };
    match reader.export_log_index(std::path::Path::new(path)) {
        Ok(()) => "{\"ok\":true}".to_string(),
        Err(e) => eljson::error_json(&e),
    }
}

/// Index status for hosts/UI: enabled, log count, backfill cursor, and per
/// watch entry the covered span (absent while nothing is indexed).
pub fn log_index_status_json(handle: i64) -> String {
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    // Propagate snapshot_reader's reason like the verified-read natives do:
    // with the host-side wake gate gone from this probe, a paused chain's
    // status is the first thing a caller sees — "handle is paused" points at
    // `resume`, where a collapsed "node is not running" pointed at start.
    let (reader, _, _) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let rate_bps = reader.log_index_rate_bps();
    // Measured against the ANCHORED HEAD, which is what `latest` resolves to
    // and therefore what decides whether a query is refused — reporting the
    // gap to finality instead would show "caught up" through the whole band
    // where queries still fail.
    let head = reader.head_block_number().unwrap_or(0);
    let status = reader.with_log_index(|ix| build_log_index_status(ix, rate_bps, head));
    status.unwrap_or_else(|| "{\"enabled\":false,\"logCount\":0,\"entries\":[]}".to_string())
}

/// The read-fetch shadow cache's counters (`myotis_net::el::readstats`): how
/// much of this handle's verified account / storage / bytecode fetch traffic
/// a cache — and which keying — would have served. A diagnostic, not gated on
/// readiness: like the log-index status it answers on any running handle.
pub fn read_stats_json(handle: i64) -> String {
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    // Not `snapshot_reader`: a PAUSED handle still answers, from the shadow
    // cache parked in its entry — the counters are per handle, not per reader.
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return eljson::error_json("engine lock poisoned"),
    };
    match map.get(&handle) {
        Some(ChainEntry::Running(_, _, Some(reader))) => reader.read_stats_json(),
        Some(ChainEntry::Running(_, _, None)) => {
            eljson::error_json("EL reader unavailable on this handle")
        }
        Some(ChainEntry::Paused(_, _, stats)) => stats.to_json(),
        Some(ChainEntry::Created(_)) => eljson::error_json("handle not started"),
        None => eljson::error_json("unknown handle"),
    }
}

/// Pure status serializer (unit-tested): fixed key order, no whitespace —
/// the Kotlin LogIndexStatus parser and its golden test pin this shape.
fn build_log_index_status(
    ix: &myotis_net::el::logindex::LogIndex,
    rate_bps: Option<f64>,
    head: u64,
) -> String {
    {
        let mut s = String::from("{\"enabled\":");
        s.push_str(if ix.config().enabled { "true" } else { "false" });
        s.push_str(",\"logCount\":");
        s.push_str(&ix.log_count().to_string());
        if let Some((n, _)) = ix.cursor {
            s.push_str(",\"backfillCursor\":");
            s.push_str(&n.to_string());
        }
        s.push_str(",\"maxSpeed\":");
        s.push_str(if ix.config().max_speed { "true" } else { "false" });
        s.push_str(",\"backfillPaused\":");
        s.push_str(if ix.config().backfill_paused { "true" } else { "false" });
        // Backfill progress for the hosts' Index tab: the walk target, blocks
        // remaining to it, and — once the walker has a measured rate — an ETA.
        // All optional-by-context so the shape stays honest: no cursor yet →
        // no remaining; no rate yet → no ETA (hosts then show x/y instead).
        if let Some(target_low) = ix.config().watch.iter().map(|w| w.from_block).min() {
            s.push_str(",\"targetLow\":");
            s.push_str(&target_low.to_string());
            if let Some((n, _)) = ix.cursor {
                let remaining = n.saturating_sub(target_low);
                s.push_str(",\"blocksRemaining\":");
                s.push_str(&remaining.to_string());
                if let Some(bps) = rate_bps {
                    if bps > 0.05 {
                        s.push_str(",\"blocksPerSec\":");
                        s.push_str(&format!("{:.1}", bps));
                        let eta = (remaining as f64 / bps).round() as u64;
                        s.push_str(",\"etaSeconds\":");
                        s.push_str(&eta.to_string());
                    }
                }
            }
        }
        // How far the TOP of coverage trails the head `latest` resolves to.
        // Beyond LOG_INDEX_LATEST_SLACK, head-reaching queries are refused, so
        // this is the number that explains a refusal even on a fully
        // backfilled index — the bridge and tail close it after downtime.
        if head > 0 {
            if let Some(edge) = ix.append_edge() {
                let covered_high = edge.saturating_sub(1);
                s.push_str(",\"headGap\":");
                s.push_str(&head.saturating_sub(covered_high).to_string());
            }
        }
        s.push_str(",\"entries\":[");
        for (k, (w, c)) in ix.coverage_entries().iter().enumerate() {
            if k > 0 {
                s.push(',');
            }
            s.push_str("{\"address\":\"0x");
            for b in &w.address {
                let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
            }
            s.push_str("\",\"fromBlock\":");
            s.push_str(&w.from_block.to_string());
            if !w.name.is_empty() {
                // serde_json handles the escaping (names come from hosts or
                // ENS reverse records — arbitrary strings).
                if let Ok(quoted) = serde_json::to_string(&w.name) {
                    s.push_str(",\"name\":");
                    s.push_str(&quoted);
                }
            }
            if let Some((low, high)) = c.span {
                s.push_str(",\"coveredLow\":");
                s.push_str(&low.to_string());
                s.push_str(",\"coveredHigh\":");
                s.push_str(&high.to_string());
            }
            s.push('}');
        }
        s.push_str("]}");
        s
    }
}

/// Parse an eth_getLogs filter into a typed [`LogFilter`], resolving tags
/// against the supplied head/finalized numbers. Pure (testable): every
/// malformed shape is a specific error string; nothing is silently ignored.
fn parse_get_logs_filter(
    v: &serde_json::Value,
    head: u64,
    finalized: u64,
) -> Result<myotis_net::el::logindex::LogFilter, String> {
    if v.get("blockHash").is_some_and(|b| !b.is_null()) {
        // EIP-234: silently resolving the tags instead would answer with the
        // HEAD block's logs for a question about a specific other block.
        return Err("blockHash filters are not supported by this scoped index".to_string());
    }
    fn tag(v: Option<&serde_json::Value>, head: u64, finalized: u64) -> Result<u64, String> {
        match v {
            None | Some(serde_json::Value::Null) => Ok(head),
            Some(serde_json::Value::String(s)) => match s.as_str() {
                "latest" | "pending" | "safe" => Ok(head),
                "finalized" => Ok(finalized),
                "earliest" => Ok(0),
                hex => hex
                    .strip_prefix("0x")
                    .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|d| u64::from_str_radix(d, 16).ok())
                    .ok_or_else(|| "unresolvable block tag".to_string()),
            },
            Some(_) => Err("block tag must be a string".to_string()),
        }
    }
    let from_block = tag(v.get("fromBlock"), head, finalized)?;
    let to_block = tag(v.get("toBlock"), head, finalized)?;
    let mut addresses = Vec::new();
    match v.get("address") {
        Some(serde_json::Value::String(a)) => {
            addresses.push(parse_address(a).ok_or("malformed address")?);
        }
        Some(serde_json::Value::Array(items)) if !items.is_empty() => {
            for a in items {
                addresses.push(a.as_str().and_then(parse_address).ok_or("malformed address")?);
            }
        }
        _ => return Err("eth_getLogs without an address is not served by this scoped index".to_string()),
    }
    let mut topics: Vec<Vec<[u8; 32]>> = Vec::new();
    match v.get("topics") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(ts)) => {
            for t in ts {
                match t {
                    serde_json::Value::Null => topics.push(Vec::new()),
                    serde_json::Value::String(one) => {
                        topics.push(vec![parse_word32(one).ok_or("malformed topic")?]);
                    }
                    serde_json::Value::Array(alts) => {
                        let mut ors = Vec::new();
                        for a in alts {
                            ors.push(a.as_str().and_then(parse_word32).ok_or("malformed topic")?);
                        }
                        topics.push(ors);
                    }
                    _ => return Err("malformed topics".to_string()),
                }
            }
        }
        Some(_) => return Err("malformed topics".to_string()),
    }
    Ok(myotis_net::el::logindex::LogFilter { from_block, to_block, addresses, topics })
}

/// The eth_getLogs query. Returns the log array ONLY when the requested
/// range is inside indexed coverage; every other case is `{"error": ...}`
/// (the router maps it to strict -32000) — never an empty array for an
/// unindexed range.
pub fn get_logs_json(handle: i64, filter_json: &str) -> String {
    let out = get_logs_json_impl(handle, filter_json);
    // Observability for wallet integration (requested during the Kohaku
    // bring-up): refusals log the exact filter at info so hosts can see what
    // the wallet asked for without a proxy; successes stay at debug. A
    // polling wallet repeats the identical refused filter every few seconds
    // for the whole backfill, so identical refusals are debounced to one
    // line per minute. (Filter content is addresses/topics/ranges — the
    // watched contract set — no secrets, but it IS the wallet's query
    // surface, hence info not warn.)
    if let Some(reason) = out.strip_prefix("{\"error\":") {
        // Strip the JSON wrapping (trailing brace and the value's quotes) so
        // the log line reads as prose, not nested JSON.
        let reason = reason
            .strip_suffix('}')
            .unwrap_or(reason)
            .trim_matches('"');
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        handle.hash(&mut h); // distinct networks debounce independently
        filter_json.hash(&mut h);
        reason.hash(&mut h);
        let key = h.finish();
        // Per-key debounce map, NOT a single slot: wallets poll several
        // distinct filters (one per watched contract), and alternating
        // refusals would evict a single slot every call — logging everything
        // during exactly the catch-up window the debounce targets. Bounded:
        // swept of expired entries whenever it grows past a handful.
        static RECENT_REFUSALS: std::sync::Mutex<
            Option<std::collections::HashMap<u64, std::time::Instant>>,
        > = std::sync::Mutex::new(None);
        const DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(60);
        let log_it = match RECENT_REFUSALS.lock() {
            Ok(mut slot) => {
                let map = slot.get_or_insert_with(std::collections::HashMap::new);
                if map.len() > 64 {
                    map.retain(|_, at| at.elapsed() < DEBOUNCE);
                }
                match map.get(&key) {
                    Some(at) if at.elapsed() < DEBOUNCE => false,
                    _ => {
                        map.insert(key, std::time::Instant::now());
                        true
                    }
                }
            }
            Err(_) => true,
        };
        if log_it {
            tracing::info!(filter = %filter_json, refusal = %reason, "eth_getLogs refused");
        }
    } else {
        tracing::debug!(filter = %filter_json, "eth_getLogs served");
    }
    out
}

/// How far the index's covered top may trail the anchored head and still be
/// used to resolve `latest`. Sized to absorb TICK CADENCE only — the tail
/// appender runs every 6s while blocks arrive every ~12s, so it is normally
/// 0-1 blocks behind. Anything beyond this is a real lag, and the query is
/// refused rather than answered against a narrower range the caller never
/// asked for and cannot see (a wallet advancing its cursor from
/// `eth_blockNumber` would silently lose those blocks' logs).
const LOG_INDEX_LATEST_SLACK: u64 = 4;

fn get_logs_json_impl(handle: i64, filter_json: &str) -> String {
    use myotis_net::el::logindex::QueryError;
    let Ok(v) = serde_json::from_str::<serde_json::Value>(filter_json) else {
        return eljson::error_json("malformed filter");
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return eljson::error_json("node is not running");
    };
    let Some(head) = reader.head_block_number() else {
        return eljson::error_json("no verified head yet");
    };
    // `latest` resolves to the top of the index's coverage when that is within
    // a block or two of the anchored head. The tail appender runs on a 6s tick
    // while blocks arrive faster than it, so a literal `head` would put every
    // other poll one block outside coverage and refuse it — a flapping refusal
    // that reads as "broken" to a wallet. The clamp is deliberately TIGHT: a
    // coverage top further behind than the appender's own window means the
    // index is genuinely not current, and the query is refused (never silently
    // answered against a stale range).
    let servable = reader
        .log_index_covered_high()
        .filter(|top| head.saturating_sub(*top) <= LOG_INDEX_LATEST_SLACK)
        .map_or(head, |top| top.min(head));
    let filter = match parse_get_logs_filter(&v, servable, reader.finalized_block_number()) {
        Ok(f) => f,
        Err(msg) => return eljson::error_json(&msg),
    };
    let mut result = reader.with_log_index(|ix| ix.query(&filter));
    // On-demand tail fill. An explicit `toBlock` at the very head can land one
    // block past the covered top while the 6s appender tick hasn't recorded it
    // yet — a wallet takes `toBlock` from `eth_blockNumber`, which follows the
    // anchored head the log index trails by up to a tick. That block IS verified
    // and moments from indexed, so rather than refuse the query, drive one
    // catch-up tick and retry once. Fire ONLY when the missing part is the HIGH
    // edge of the erroring address's coverage — `toBlock` at most
    // `LOG_INDEX_LATEST_SLACK` above the covered top and never above the head. A
    // shortfall on the LOW side (fromBlock below the index floor) cannot be
    // helped by advancing the tail, and a deeper high-side lag is the bridge's
    // job; neither should spend a synchronous network tick here.
    let needs_fill = matches!(
        &result,
        Some(Err(QueryError::OutOfCoverage { covered, .. }))
            if covered.span.is_some_and(|(low, high)| {
                // The fill helps ONLY when the high edge is the sole shortfall.
                // A fromBlock below the covered low (the classic full-history
                // scan while backfill is still running) cannot be served by
                // advancing the tail — firing there would spend a synchronous
                // network tick per poll for nothing.
                filter.from_block >= low
                    && filter.to_block <= head
                    && filter.to_block > high
                    && filter.to_block - high <= LOG_INDEX_LATEST_SLACK
            })
    );
    if needs_fill {
        if let Err(error) = engine.rt.block_on(reader.request(async {
            reader.advance_log_index_tail_now(filter.to_block).await;
            Ok(())
        })) {
            return eljson::error_json(&error);
        }
        result = reader.with_log_index(|ix| ix.query(&filter));
    }
    // What the caller should DO about a coverage shortfall depends on which side
    // fell short, and on whether anything is still working on it.
    //
    // A HIGH-side shortfall is head-follow's job — the appender and the bridge
    // are closing it right now, and the backfill OFF switch touches neither —
    // so "retry" stays right even on a paused node, and telling that caller to
    // resume the walk would point at the one action that makes it slower. Only
    // a LOW-side shortfall is the walk's job, and a paused node never fills it.
    //
    // Which side fell short is decided against the EFFECTIVE floor, not the raw
    // filter: `LogIndex::query` requires coverage only from
    // `max(filter.from_block, entry.from_block)`, because below a watch entry's
    // from_block the config asserts the contract has no logs. So a routine
    // `0..head` sweep of a contract deployed at 31,305,656 whose coverage starts
    // exactly there has NO low-side gap — only the head side is missing, and
    // that caller must be told to retry however the walk is set.
    // Host-neutral wording: this reaches every eth_getLogs consumer, and the
    // daemon's `logindex-backfill on` does not exist on desktop, Android or iOS,
    // whose lever is the Index tab's pause switch.
    let paused = reader.with_log_index(|ix| ix.config().backfill_paused) == Some(true);
    let effective_from = |address: [u8; 20]| -> u64 {
        let entry_from = reader
            .with_log_index(|ix| {
                ix.config().watch.iter().find(|w| w.address == address).map(|w| w.from_block)
            })
            .flatten()
            .unwrap_or(0);
        filter.from_block.max(entry_from)
    };
    let advice = |address: [u8; 20], low: u64| -> &'static str {
        if paused && effective_from(address) < low {
            "the backfill is paused on this node, so this range will not be filled in; resume it (Index tab switch, or logindex-backfill on in the daemon) or query within the covered range"
        } else {
            "retry as the index catches up"
        }
    };
    match result {
        None => eljson::error_json("log index is not configured on this network"),
        Some(Ok(logs)) => eljson::get_logs_json(&logs),
        Some(Err(QueryError::Disabled)) => eljson::error_json("log index is disabled on this network"),
        Some(Err(QueryError::UnwatchedAddress(_))) => {
            eljson::error_json("address is not on this node's log watch-list")
        }
        Some(Err(QueryError::UnindexedTopic(_))) => {
            eljson::error_json("topic is outside this node's indexed signatures for that address")
        }
        Some(Err(QueryError::OutOfCoverage { address, covered })) => match covered.span {
            Some((low, high)) => eljson::error_json(&format!(
                "requested range is not indexed yet (covered: {low}-{high}); {}",
                advice(address, low)
            )),
            // No coverage at all yet, so there is no side to compare against.
            // Head-follow still starts covering from the head as blocks arrive,
            // which a retrying caller near the tip will see; anything further
            // down waits on the walk, and on a paused node waits forever.
            None if paused => eljson::error_json(
                "log index has no coverage yet, and the backfill is paused on this node, so only \
                 blocks indexed from here on become answerable; resume it (Index tab switch, or \
                 logindex-backfill on in the daemon)",
            ),
            None => eljson::error_json("log index has not indexed any blocks yet; retry"),
        },
        Some(Err(QueryError::Unanswerable)) => eljson::error_json("unanswerable filter (fromBlock > toBlock)"),
    }
}

#[cfg(test)]
mod log_index_json_tests {
    use super::{build_log_index_status, parse_log_index_config};

    fn cfg(json: &str) -> Option<myotis_net::el::logindex::LogIndexConfig> {
        parse_log_index_config(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn a_present_but_non_boolean_scalar_refuses_the_whole_config() {
        // Applied or refused, never silently replaced: `"enabled":"true"` used to
        // parse as enabled=false, which would switch a running index off while the
        // caller believed it had turned one on.
        assert!(cfg(r#"{"enabled":"true","watch":[]}"#).is_none());
        assert!(cfg(r#"{"enabled":true,"maxSpeed":1,"watch":[]}"#).is_none());
        assert!(cfg(r#"{"enabled":true,"backfillPaused":"true","watch":[]}"#).is_none());
        // Absent and explicit null both keep the documented default.
        assert!(cfg(r#"{"enabled":true,"backfillPaused":null,"watch":[]}"#).is_some());
        assert!(!cfg(r#"{"enabled":true,"backfillPaused":null,"watch":[]}"#).unwrap().backfill_paused);
    }

    #[test]
    fn a_watch_list_naming_one_address_twice_is_refused_at_the_parser() {
        // The index layer refuses this config anyway; refusing it here keeps a
        // push that cannot be applied from queueing behind the checkpoint lock.
        let a = "0x4e69fD587118dFb64957d18654E3894118E9b1BF";
        let dup = format!(
            r#"{{"enabled":true,"watch":[{{"address":"{a}","fromBlock":5}},{{"address":"{a}","fromBlock":9}}]}}"#
        );
        assert!(cfg(&dup).is_none(), "a duplicate watch address parsed");
        // Case is not identity here — the parser normalizes, so the same
        // address in two spellings is still the same address.
        let mixed = format!(
            r#"{{"enabled":true,"watch":[{{"address":"{a}","fromBlock":5}},{{"address":"{}","fromBlock":9}}]}}"#,
            a.to_lowercase()
        );
        assert!(cfg(&mixed).is_none(), "a duplicate watch address parsed in another case");
        // Two genuinely different addresses still parse.
        let two = format!(
            r#"{{"enabled":true,"watch":[{{"address":"{a}","fromBlock":5}},{{"address":"0x{}","fromBlock":9}}]}}"#,
            "ab".repeat(20)
        );
        assert_eq!(cfg(&two).unwrap().watch.len(), 2);
    }

    #[test]
    fn parses_backfill_paused_default_and_explicit() {
        // Absent means "keep walking": a host that predates the key must not
        // silently stop its backfill on upgrade.
        let base = r#"{"enabled":true,"watch":[{"address":"0x4e69fD587118dFb64957d18654E3894118E9b1BF","fromBlock":5}]}"#;
        assert!(!cfg(base).unwrap().backfill_paused, "absent backfillPaused must keep the walk running");
        assert!(cfg(r#"{"enabled":true,"backfillPaused":true,"watch":[]}"#).unwrap().backfill_paused);
        assert!(!cfg(r#"{"enabled":true,"backfillPaused":false,"watch":[]}"#).unwrap().backfill_paused);
    }

    #[test]
    fn parses_max_speed_default_and_explicit() {
        let base = r#"{"enabled":true,"watch":[{"address":"0x4e69fD587118dFb64957d18654E3894118E9b1BF","fromBlock":5}]}"#;
        let c = cfg(base).unwrap();
        assert!(c.enabled);
        assert!(!c.max_speed, "absent maxSpeed must default to nice");
        let fast = cfg(r#"{"enabled":true,"maxSpeed":true,"watch":[]}"#).unwrap();
        assert!(fast.max_speed);
        // Wrong type on watch is malformed, unknown keys are tolerated.
        assert!(cfg(r#"{"enabled":true,"watch":7}"#).is_none());
        assert!(cfg(r#"{"enabled":true,"futureKey":1,"watch":[]}"#).is_some());
    }

    #[test]
    fn parses_optional_names_and_reflects_them_in_status() {
        let addr = format!("0x{}", "11".repeat(20));
        let named = cfg(&format!(
            r#"{{"enabled":true,"watch":[{{"address":"{addr}","fromBlock":5,"name":"tornado.registry.eth"}}]}}"#
        ))
        .unwrap();
        assert_eq!(named.watch[0].name, "tornado.registry.eth");
        // Absent name → empty (unnamed); a non-string name is malformed.
        let unnamed = cfg(&format!(r#"{{"enabled":true,"watch":[{{"address":"{addr}","fromBlock":5}}]}}"#)).unwrap();
        assert!(unnamed.watch[0].name.is_empty());
        assert!(cfg(&format!(r#"{{"enabled":true,"watch":[{{"address":"{addr}","fromBlock":5,"name":7}}]}}"#)).is_none());
        // Status carries the name for named entries and omits the key for
        // unnamed ones (shape-stable for pre-name hosts).
        let ix = myotis_net::el::logindex::LogIndex::new(named).unwrap();
        let s = build_log_index_status(&ix, None, 0);
        assert!(s.contains("\"name\":\"tornado.registry.eth\""), "{s}");
        let ix = myotis_net::el::logindex::LogIndex::new(unnamed).unwrap();
        assert!(!build_log_index_status(&ix, None, 0).contains("\"name\""));
    }

    #[test]
    fn status_json_carries_progress_keys() {
        let w = myotis_net::el::logindex::WatchEntry {
            address: [0x11; 20],
            from_block: 100,
            topic0s: vec![],
            name: String::new(),
        };
        let cfg = myotis_net::el::logindex::LogIndexConfig {
            enabled: true,
            max_speed: true,
            backfill_paused: false,
            watch: vec![w],
        };
        let mut ix = myotis_net::el::logindex::LogIndex::new(cfg).unwrap();
        ix.cursor = Some((600, [0u8; 32]));
        let s = build_log_index_status(&ix, Some(9.44), 0);
        assert!(s.contains("\"maxSpeed\":true"), "{s}");
        // The pause bit rides next to maxSpeed in the fixed key order the
        // Kotlin parser and its golden test pin.
        assert!(s.contains("\"backfillPaused\":false"), "{s}");
        assert!(s.contains("\"targetLow\":100"), "{s}");
        assert!(s.contains("\"blocksRemaining\":500"), "{s}");
        assert!(s.contains("\"blocksPerSec\":9.4"), "{s}");
        // eta = 500 / 9.44 = 52.966 -> 53
        assert!(s.contains("\"etaSeconds\":53"), "{s}");
        // No rate -> no ETA keys, remaining still present.
        let s2 = build_log_index_status(&ix, None, 0);
        assert!(s2.contains("\"blocksRemaining\":500"), "{s2}");
        assert!(!s2.contains("etaSeconds"), "{s2}");
    }
}

#[cfg(test)]
mod call_target_tests {
    use super::call_target;

    #[test]
    fn empty_to_selects_contract_creation() {
        // The load-bearing half of the design: the Java/iOS adapters map a null
        // `to` to "" across the FFI, and THIS is what turns that into a create.
        assert_eq!(call_target(""), Ok(None));
        assert_eq!(call_target("   "), Ok(None));
    }

    #[test]
    fn an_address_selects_an_ordinary_call() {
        let a = call_target("0x00000000219ab540356cBB839Cbe05303d7705Fa").unwrap();
        assert_eq!(a.map(|x| x[0]), Some(0x00));
        assert_eq!(a.map(|x| x[19]), Some(0xFa));
    }

    #[test]
    fn a_malformed_to_is_an_error_not_a_creation() {
        // Serving this as a creation would run init code nobody asked to run.
        assert!(call_target("0xZZ").is_err());
        assert!(call_target("0x1234").is_err());          // too short
        assert!(call_target("not-hex-at-all").is_err());
    }
}

#[cfg(test)]
mod call_block_tests {
    use super::{
        check_call_block, eth_call_json, eth_call_overrides_json, parse_call_block, BlockSelector,
        CallBlockRefusal, CALL_BLOCK_AHEAD_TOLERANCE, CALL_BLOCK_LAG_TOLERANCE,
    };

    /// The JVM twin's head (`RustBlockWindowTest`), so the two tables line up.
    const HEAD: u64 = 25_000_000;

    /// The hosts' `blockInWindow` verdict, as the engine reaches it.
    fn servable(block: &str, head: u64) -> bool {
        parse_call_block(block).is_ok_and(|b| check_call_block(b, head).is_ok())
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn head_tags_and_default_are_servable() {
        for tag in ["latest", "pending", "safe", "", "  ", "LATEST", "Pending"] {
            assert_eq!(parse_call_block(tag), Ok(BlockSelector::Head), "{tag:?}");
        }
        // A tag needs no head to be checked against; without one, the executor
        // fails with its own not-synced error.
        assert_eq!(check_call_block(BlockSelector::Head, 0), Ok(()));
    }

    #[test]
    fn finalized_is_its_own_anchor() {
        // Applied, not mapped to the head (#465, #366): the call runs against
        // the beacon-finalized block.
        for tag in ["finalized", "FINALIZED", " finalized "] {
            assert_eq!(parse_call_block(tag), Ok(BlockSelector::Finalized), "{tag:?}");
        }
        // Like a head tag it needs no window check; the reader refuses it
        // itself while there is no finalized block.
        assert_eq!(check_call_block(BlockSelector::Finalized, 0), Ok(()));
        assert!(servable("finalized", HEAD));
    }

    #[test]
    fn a_number_at_or_near_the_head_is_servable() {
        assert!(servable("0x17d7840", HEAD)); // == HEAD
        assert!(servable("0X17D7840", HEAD));
        assert!(servable(&HEAD.to_string(), HEAD)); // bare digits are decimal, as for the hosts
        assert!(servable(&format!("{:#x}", HEAD - CALL_BLOCK_LAG_TOLERANCE), HEAD));
        assert!(servable(&format!("{:#x}", HEAD + CALL_BLOCK_AHEAD_TOLERANCE), HEAD));
        // Zero-padded to hash length, it is still a number.
        assert!(servable(&format!("0x{HEAD:064x}"), HEAD));
    }

    #[test]
    fn an_older_number_is_refused_for_good() {
        let behind = HEAD - CALL_BLOCK_LAG_TOLERANCE - 1;
        let refusal = check_call_block(BlockSelector::Number(behind), HEAD).unwrap_err();
        assert_eq!(refusal, CallBlockRefusal::Behind { block: behind, head: HEAD });
        assert_eq!(json(&refusal.to_json())["code"], -32602);
        assert!(!servable("0x1", HEAD));
    }

    #[test]
    fn a_number_past_the_head_is_refused_but_retryable() {
        let ahead = HEAD + CALL_BLOCK_AHEAD_TOLERANCE + 1;
        let refusal = check_call_block(BlockSelector::Number(ahead), HEAD).unwrap_err();
        assert_eq!(refusal, CallBlockRefusal::Ahead { block: ahead, head: HEAD });
        let v = json(&refusal.to_json());
        assert!(v["error"].is_string() && v.get("code").is_none(), "{v}");
    }

    #[test]
    fn a_number_without_a_verified_head_is_refused_but_retryable() {
        let refusal = check_call_block(BlockSelector::Number(HEAD), 0).unwrap_err();
        assert_eq!(refusal, CallBlockRefusal::NoHead { block: HEAD });
        let v = json(&refusal.to_json());
        assert!(v["error"].is_string() && v.get("code").is_none(), "{v}");
    }

    #[test]
    fn a_young_chain_clamps_the_window_at_genesis() {
        assert!(servable("0x0", 10)); // head - 64 saturates to 0
        assert!(servable("0x1a", 10)); // 26 == head + 16
        assert!(!servable("0x1b", 10));
    }

    #[test]
    fn unservable_selectors_are_refused_as_malformed() {
        for bad in [
            "earliest",
            "EARLIEST",
            "0xzz",
            "garbage",
            "0x",
            "0x+5",
            "+5",
            "-5",
            "0x-1",
            "1.5",
            "0x8000000000000000", // past i64::MAX
            r#"{"blockHash":"0x00"}"#,
        ] {
            assert!(parse_call_block(bad).is_err(), "{bad:?} should be refused");
        }
        let hash = format!("0x{}", "ab".repeat(32));
        assert!(parse_call_block(&hash).unwrap_err().contains("block hash"));
        // The echo of the caller's input is bounded.
        assert!(parse_call_block(&"z".repeat(10_000)).unwrap_err().len() < 200);
    }

    #[test]
    fn eth_call_refuses_a_malformed_block_before_anything_else() {
        // No engine or handle needed: both entry points refuse the selector
        // first, as invalid params.
        let to = format!("0x{}", "11".repeat(20));
        for out in [
            eth_call_json(i64::MIN, "", &to, "", "", "earliest"),
            eth_call_overrides_json(i64::MIN, "", &to, "", "", "0xzz", ""),
        ] {
            assert_eq!(json(&out)["code"], -32602, "{out}");
        }
        // A well-formed number gets past the parse to the handle lookup.
        let v = json(&eth_call_json(i64::MIN, "", &to, "", "", "0x1"));
        assert_eq!(v["error"], "unknown handle");
        assert!(v.get("code").is_none(), "{v}");
    }

    #[test]
    fn eth_call_refuses_every_malformed_argument_as_invalid_params() {
        let to = format!("0x{}", "11".repeat(20));
        for (what, out) in [
            ("from", eth_call_json(i64::MIN, "0xnope", &to, "", "", "latest")),
            ("to", eth_call_json(i64::MIN, "", "0x1234", "", "", "latest")),
            ("data", eth_call_json(i64::MIN, "", &to, "0xzz", "", "latest")),
            ("value", eth_call_json(i64::MIN, "", &to, "", "ten", "latest")),
            ("overrides", eth_call_overrides_json(i64::MIN, "", &to, "", "", "latest", "[]")),
        ] {
            assert_eq!(json(&out)["code"], -32602, "{what}: {out}");
        }
    }
}

#[cfg(test)]
mod get_logs_filter_tests {
    use super::parse_get_logs_filter;

    fn f(json: &str) -> Result<myotis_net::el::logindex::LogFilter, String> {
        parse_get_logs_filter(&serde_json::from_str(json).unwrap(), 1000, 900)
    }

    #[test]
    fn tags_resolve_and_malformed_tags_error() {
        let addr = format!("\"address\":\"0x{}\"", "11".repeat(20));
        let ok = f(&format!("{{{addr}}}")).unwrap();
        assert_eq!((ok.from_block, ok.to_block), (1000, 1000)); // absent → head
        let ok = f(&format!("{{{addr},\"fromBlock\":\"earliest\",\"toBlock\":\"finalized\"}}")).unwrap();
        assert_eq!((ok.from_block, ok.to_block), (0, 900));
        let ok = f(&format!("{{{addr},\"fromBlock\":\"0x64\"}}")).unwrap();
        assert_eq!(ok.from_block, 100);
        for bad in ["\"0x\"", "\"0x+5\"", "\"nope\"", "5", "{}"] {
            assert!(f(&format!("{{{addr},\"fromBlock\":{bad}}}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn block_hash_filters_are_rejected() {
        let addr = format!("\"address\":\"0x{}\"", "11".repeat(20));
        let bh = format!("\"blockHash\":\"0x{}\"", "cc".repeat(32));
        assert!(f(&format!("{{{addr},{bh}}}")).unwrap_err().contains("blockHash"));
        // Explicit null blockHash is treated as absent, per JSON-RPC habits.
        assert!(f(&format!("{{{addr},\"blockHash\":null}}")).is_ok());
    }

    #[test]
    fn address_forms_and_empty_array_error() {
        assert!(f("{}").is_err());
        assert!(f("{\"address\":[]}").unwrap_err().contains("without an address"));
        assert!(f(&format!("{{\"address\":[\"0x{}\",\"0x{}\"]}}", "11".repeat(20), "22".repeat(20))).unwrap().addresses.len() == 2);
        assert!(f("{\"address\":\"0xzz\"}").is_err());
    }

    #[test]
    fn topics_forms_and_malformed_topics_error() {
        let addr = format!("\"address\":\"0x{}\"", "11".repeat(20));
        let t = format!("0x{}", "aa".repeat(32));
        let ok = f(&format!("{{{addr},\"topics\":[null,\"{t}\",[\"{t}\"]]}}")).unwrap();
        assert_eq!(ok.topics.len(), 3);
        assert!(ok.topics.first().is_some_and(|w| w.is_empty()));
        // A non-array topics value must ERROR, not silently widen the query.
        assert!(f(&format!("{{{addr},\"topics\":\"{t}\"}}")).unwrap_err().contains("malformed topics"));
        assert!(f(&format!("{{{addr},\"topics\":[5]}}")).is_err());
    }
}
