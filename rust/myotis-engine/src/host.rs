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

use myotis_net::el::evm::{EnsQuery, EnsRootMode};
use myotis_net::el::reader::ElReader;
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
/// A canonical network that R1 does not host yet (anything but mainnet).
const UNSUPPORTED_NETWORK: i64 = -2;

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
    /// time so status reads keep reporting the warm beacon fields while asleep.
    Paused(Arc<ChainConfig>, SyncStatus),
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
    /// Per-handle last-good `eth_feeHistory`: the EMITTED JSON plus the raw
    /// request signature it answered, re-servable within
    /// [`FEE_HISTORY_STALE_MAX`] when a fresh build fails for the SAME
    /// signature (the Java `lastGoodFeeHistory` twin — identical params ⇒
    /// identical verified data, just older; fees drift slowly and the wallet
    /// re-polls). Kept at the JSON layer so a hit costs a String clone, never
    /// a result rebuild. Entries die with their handle (see `stop`).
    fee_history_cache: Mutex<HashMap<i64, (String, String, std::time::Instant)>>,
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
                    fee_history_cache: Mutex::new(HashMap::new()),
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

/// `nativeCreate`: allocate an id for a not-yet-started hosted chain (mainnet or
/// sepolia). Returns the id (`>= 1`), `UNSUPPORTED_NETWORK` (-2) for a canonical
/// network this engine doesn't host yet (gnosis), or `CREATE_FAILED` (-1) for an
/// unknown name, an unavailable runtime, or an uncreatable dataDir.
pub fn create(network_name: &str, data_dir: &str) -> i64 {
    let Some(engine) = engine() else {
        return CREATE_FAILED;
    };
    // Unknown network → CREATE_FAILED; canonical-but-not-hosted → UNSUPPORTED.
    let mut config = match crate::catalog::canonical_network_name(network_name) {
        None => return CREATE_FAILED,
        Some(_) => match config_for(network_name) {
            Some(c) => c,
            None => return UNSUPPORTED_NETWORK,
        },
    };
    // Persistence lives under the host's dataDir, in the SAME files (names and
    // formats) the Java hosts/engine maintain — `sync-state[-net].snapshot` and
    // `cl-peers[-net].cache`, mainnet keeping the bare name — so verified sync
    // state and proven LC servers survive restarts AND engine switches.
    if !data_dir.is_empty() {
        // The dir may not exist yet (fresh host profile) — create it now.
        // Without this, sync runs fine but every snapshot/cache write fails
        // with ENOENT ("retrying on the next period advance", forever), so
        // persistence is silently lost and every restart bootstraps cold.
        // An uncreatable dataDir is a runtime-init failure the caller must
        // see (honest error over silent degradation), hence CREATE_FAILED
        // rather than warn-and-continue.
        if let Err(e) = std::fs::create_dir_all(data_dir) {
            tracing::warn!(data_dir, error = %e, "dataDir cannot be created");
            return CREATE_FAILED;
        }
        let suffix = if config.name == "mainnet" {
            String::new()
        } else {
            format!("-{}", config.name)
        };
        let dir = std::path::Path::new(data_dir);
        config.snapshot_path = Some(dir.join(format!("sync-state{suffix}.snapshot")));
        config.cl_peer_cache_path = Some(dir.join(format!("cl-peers{suffix}.cache")));
    }
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
    let config = {
        let map = match engine.handles.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        match (from, map.get(&handle)) {
            (SpinUpFrom::Created, Some(ChainEntry::Created(c))) => Arc::clone(c),
            (SpinUpFrom::Paused, Some(ChainEntry::Paused(c, _))) => Arc::clone(c),
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
    let el_suffix = if config.name == "mainnet" {
        String::new()
    } else {
        format!("-{}", config.name)
    };
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
            ElReader::start_for(sync.exec_anchor(), el_cache_path, cfg).await
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
    }
    // Re-lock and publish ONLY if the entry is still the same Created/Paused one
    // we spun up from: a concurrent stop() may have removed it, or a racing
    // start()/resume() may have already published a Running one, while we were
    // starting. Either way, shut the handle we just started down rather than
    // orphan its tokio/libp2p host.
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
            true
        }
        _ => {
            drop(map);
            shutdown(engine, sync, reader);
            false
        }
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
                map.insert(handle, ChainEntry::Paused(config, frozen));
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
        sync.stop().await;
        if let Some(reader) = reader {
            reader.stop_log_index_appender().await;
            if let Ok(reader) = Arc::try_unwrap(reader) {
                reader.stop().await;
            }
            // An in-flight verified read still holds a clone: its Drop aborts
            // the reader's tasks when the last Arc goes (same as stop()).
        }
    });
    tracing::info!(handle, "paused (networking torn down; warm state persisted)");
    true
}

/// Shut down a started-but-not-published sync handle + reader (the lost-race
/// path). Runs the async stops on the engine runtime.
fn shutdown(engine: &EngineState, sync: SyncHandle, reader: Option<Arc<ElReader>>) {
    engine.rt.block_on(async move {
        sync.stop().await;
        if let Some(reader) = reader {
            // Only our just-started reader holds an Arc here, so unwrapping the
            // Arc to consume `stop(self)` succeeds; if it somehow doesn't, the
            // reader's Drop still aborts its tasks. The appender is stopped
            // (abort + await) FIRST so its per-tick strong Arc can't defeat
            // the unwrap.
            reader.stop_log_index_appender().await;
            if let Ok(reader) = Arc::try_unwrap(reader) {
                reader.stop().await;
            }
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
            Some(ChainEntry::Paused(config, frozen)) => {
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
        Ok(mut m) => m.remove(&handle),
        Err(_) => return,
    };
    // The handle's cached feeHistory dies with it.
    if let Ok(mut cache) = engine.fee_history_cache.lock() {
        cache.remove(&handle);
    }
    if let Ok(mut pending) = engine.pending_served_window.lock() {
        pending.remove(&handle);
    }
    if let Some(ChainEntry::Running(_, sync, reader)) = entry {
        engine.rt.block_on(async move {
            sync.stop().await;
            if let Some(reader) = reader {
                reader.stop_log_index_appender().await;
                if let Ok(reader) = Arc::try_unwrap(reader) {
                    reader.stop().await;
                }
            }
        });
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
    match engine.rt.block_on(async { reader.get_account(address).await }) {
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
    match engine.rt.block_on(async { reader.get_storage(address, slot, holder).await }) {
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
    match engine.rt.block_on(async { reader.get_code(address).await }) {
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
    match engine.rt.block_on(async { reader.get_storage_at(address, position).await }) {
        Ok(storage) => {
            eljson::storage_json(address_hex, None, &storage, finalized_slot, optimistic_slot)
        }
        Err(e) => eljson::error_json(&e),
    }
}

/// `nativeEthCallJson`: run a verified `eth_call` for a running handle. `from` is
/// empty for an anonymous call; `to` is required; `data_hex` is the calldata;
/// `value_dec` is the wei value as a decimal string (FFI-neutral); `block` is the
/// RPC block tag (the Java side has already gated it to the servable window, so
/// the call runs against the verified head). Returns the call JSON
/// (`ok`/`revert`/`unavailable`, see [`eljson::call_json`]) or `{"error": "..."}`.
pub fn eth_call_json(
    handle: i64,
    from_hex: &str,
    to_hex: &str,
    data_hex: &str,
    value_dec: &str,
    _block: &str,
) -> String {
    let Some(to) = parse_address(to_hex) else {
        return eljson::error_json("invalid 'to' address (expected 20-byte hex)");
    };
    // 'from' is optional: empty → an anonymous zero-address sender.
    let from = if from_hex.trim().is_empty() {
        None
    } else {
        match parse_address(from_hex) {
            Some(a) => Some(a),
            None => return eljson::error_json("invalid 'from' address (expected 20-byte hex)"),
        }
    };
    // Calldata may be empty (a bare value transfer / fallback call).
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
        .block_on(async { reader.eth_call(from, to, data, value, chain_id).await })
    {
        Ok(outcome) => eljson::call_json(&outcome),
        Err(e) => eljson::error_json(&e),
    }
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
/// against the verified head). Returns the estimate JSON (`ok`/`unavailable`, see
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
/// a future/unknown block (eth's null), or `{"error": "..."}` when it can't
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
    match engine
        .rt
        .block_on(async { reader.get_block_by_number(target, full_transactions).await })
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
    match engine.rt.block_on(async { reader.get_transaction_receipt(tx_hash).await }) {
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
    match engine.rt.block_on(async { reader.get_transaction_by_hash(tx_hash).await }) {
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
        .block_on(async { reader.get_block_by_hash(block_hash, full_transactions).await })
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
    match engine.rt.block_on(async { reader.send_raw_transaction(&raw).await }) {
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
    match engine.rt.block_on(async { reader.fee_estimate().await }) {
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
        engine.rt.block_on(async { reader.get_block_receipts_by_hash(hash).await })
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
        engine.rt.block_on(async { reader.get_block_receipts(target).await })
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
    // The raw request strings ARE the stale-serve signature (the Java
    // `blockCount + "|" + newestBlock + "|" + Arrays.toString(percentiles)`).
    let key = format!("{block_count}|{}|{}", newest_block_tag.trim(), percentiles_json.trim());
    match engine.rt.block_on(async {
        reader.fee_history(block_count as u64, newest, percentiles.as_deref()).await
    }) {
        Ok(history) => {
            let json = eljson::fee_history_json(&history);
            if let Ok(mut cache) = engine.fee_history_cache.lock() {
                cache.insert(handle, (key, json.clone(), std::time::Instant::now()));
            }
            json
        }
        // A Reject is a bad request against the CURRENT head — answered as the
        // error (→ -32000), never from a stale snapshot (Java parity: only
        // BUILD failures reach serveStaleFeeHistory).
        Err(myotis_net::el::reader::FeeHistoryError::Reject(msg)) => eljson::error_json(&msg),
        Err(myotis_net::el::reader::FeeHistoryError::Build(msg)) => {
            if let Ok(cache) = engine.fee_history_cache.lock() {
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

/// Parse an eth block selector to a target number: `None` = latest (the head).
/// Mirrors the Java backend — latest/pending/safe/finalized all resolve to the
/// optimistic head; earliest (genesis) and malformed/negative are not served
/// verified (`Err`, surfaced as an error the router turns into -32000).
fn parse_block_target(tag: &str) -> Result<Option<u64>, &'static str> {
    match tag {
        "latest" | "pending" | "safe" | "finalized" => Ok(None),
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
                Ok(n) => Ok(Some(n)),
                Err(_) => Err("block number out of range"),
            }
        }
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
    obj.insert("finalizedRootHex".into(), hex32(&s.finalized_root).into());
    // EL pool/discovery counts (the Rust engine's execution-layer side). The
    // pool keeps only snap-capable READY peers, so readyPeers == snapPeers.
    // elReaderAvailable distinguishes "EL warming up" from "EL reader failed to
    // start" (the CL-only degraded mode) — the wake gate fast-fails the latter.
    obj.insert("elReaderAvailable".into(), el.reader_available.into());
    obj.insert("snapPeers".into(), el.snap_peers.into());
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
    r#""discv5TableSize":0,"syncStartPeriod":-1,"lcHunting":false,"#,
    r#""finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000","#,
    r#""elReaderAvailable":false,"#,
    r#""snapPeers":0,"readyPeers":0,"discoveredPeers":0,"attemptedDials":0,"#,
    r#""backedOffPeers":0,"blacklistedPeers":0,"optimisticBlockNumber":0,"#,
    r#""finalizedBlockNumber":0,"executionBlockNumber":0,"elHunting":false,"#,
    r#""peerHeaderRequests":0,"peerHeaderRequestsServed":0,"#,
    r#""peerBodyRequests":0,"peerBodyRequestsServed":0}"#,
);

#[cfg(test)]
mod tests {
    use super::*;

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
        for k in ["snapPeers", "readyPeers", "discoveredPeers", "attemptedDials",
                  "backedOffPeers", "blacklistedPeers", "optimisticBlockNumber",
                  "finalizedBlockNumber", "executionBlockNumber"] {
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
        };
        let el = ElCounts {
            reader_available: true,
            snap_peers: 5,
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
        assert_eq!(synced["finalizedRootHex"], hex32(&[0xab; 32]));
        // EL counts reflect the pool/discovery snapshot (snapPeers drives
        // readyPeers, since the pool holds only snap-capable READY peers).
        assert_eq!(synced["elReaderAvailable"], true);
        assert_eq!(synced["snapPeers"], 5);
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
        for k in ["snapPeers", "readyPeers", "discoveredPeers", "attemptedDials",
                  "backedOffPeers", "blacklistedPeers", "optimisticBlockNumber",
                  "finalizedBlockNumber", "executionBlockNumber"] {
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
    fn unknown_handle_returns_empty_object() {
        // No engine calls here — just the contract for a missing handle, which
        // status_json returns directly.
        assert_eq!(status_json(i64::MIN), "{}");
    }

    #[test]
    fn parse_block_target_cases() {
        assert_eq!(parse_block_target("latest"), Ok(None));
        assert_eq!(parse_block_target("pending"), Ok(None));
        assert_eq!(parse_block_target("finalized"), Ok(None));
        assert_eq!(parse_block_target("0x1406f40"), Ok(Some(21_000_000)));
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
/// "fromBlock":n,"topic0s":["0x..",..]?}]}`. False on malformed input,
/// duplicate addresses, or an unavailable reader.
pub fn set_log_index_config_json(handle: i64, config_json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return false;
    };
    let Some(config) = parse_log_index_config(&v) else {
        return false;
    };
    let enabled = config.enabled;
    let Some(engine) = engine() else {
        return false;
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return false;
    };
    let installed = reader.set_log_index_config(config);
    if installed && enabled {
        // Spawn (or keep) the head-follow appender on the engine runtime.
        reader.ensure_log_index_appender(engine.rt.handle());
    }
    installed
}

/// Pure config-JSON → typed config (unit-tested; the FFI wrapper above only
/// adds engine plumbing). `None` = malformed (wrong types); unknown keys are
/// ignored for forward compatibility.
fn parse_log_index_config(
    v: &serde_json::Value,
) -> Option<myotis_net::el::logindex::LogIndexConfig> {
    let enabled = v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
    // Backfill pacing (optional; absent = nice/background). Fingerprint-neutral:
    // flipping it re-applies onto the live index without resetting coverage.
    let max_speed = v.get("maxSpeed").and_then(|e| e.as_bool()).unwrap_or(false);
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
            watch.push(myotis_net::el::logindex::WatchEntry { address, from_block, topic0s });
        }
    }
    Some(myotis_net::el::logindex::LogIndexConfig { enabled, max_speed, watch })
}

/// Index status for hosts/UI: enabled, log count, backfill cursor, and per
/// watch entry the covered span (absent while nothing is indexed).
pub fn log_index_status_json(handle: i64) -> String {
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    let Ok((reader, _, _)) = snapshot_reader(engine, handle) else {
        return eljson::error_json("node is not running");
    };
    let rate_bps = reader.log_index_rate_bps();
    let finalized = reader.finalized_block_number();
    let status = reader.with_log_index(|ix| build_log_index_status(ix, rate_bps, finalized));
    status.unwrap_or_else(|| "{\"enabled\":false,\"logCount\":0,\"entries\":[]}".to_string())
}

/// Pure status serializer (unit-tested): fixed key order, no whitespace —
/// the Kotlin LogIndexStatus parser and its golden test pin this shape.
fn build_log_index_status(
    ix: &myotis_net::el::logindex::LogIndex,
    rate_bps: Option<f64>,
    finalized: u64,
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
        // How far the TOP of coverage trails the finalized head. Queries with
        // `toBlock: "latest"` are refused while this is non-zero, so it is the
        // number that explains a refusal even on a fully backfilled index —
        // the head bridge closes it after downtime.
        if finalized > 0 {
            if let Some(edge) = ix.append_edge() {
                // edge = covered high + 1, so the gap is measured from the
                // covered TOP: zero exactly when coverage reaches finality.
                let covered_high = edge.saturating_sub(1);
                s.push_str(",\"headGap\":");
                s.push_str(&finalized.saturating_sub(covered_high).to_string());
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
/// used to resolve `latest` (the engine's own append window).
const LOG_INDEX_LATEST_SLACK: u64 = 128;

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
    let result = reader.with_log_index(|ix| ix.query(&filter));
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
        Some(Err(QueryError::OutOfCoverage { covered, .. })) => match covered.span {
            Some((low, high)) => eljson::error_json(&format!(
                "requested range is not indexed yet (covered: {low}-{high}); retry as the index catches up"
            )),
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
    fn status_json_carries_progress_keys() {
        let w = myotis_net::el::logindex::WatchEntry {
            address: [0x11; 20],
            from_block: 100,
            topic0s: vec![],
        };
        let cfg = myotis_net::el::logindex::LogIndexConfig {
            enabled: true,
            max_speed: true,
            watch: vec![w],
        };
        let mut ix = myotis_net::el::logindex::LogIndex::new(cfg).unwrap();
        ix.cursor = Some((600, [0u8; 32]));
        let s = build_log_index_status(&ix, Some(9.44), 0);
        assert!(s.contains("\"maxSpeed\":true"), "{s}");
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
