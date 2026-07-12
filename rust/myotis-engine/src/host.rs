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
}

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

/// `nativeCreate`: allocate an id for a not-yet-started hosted chain (mainnet or
/// sepolia). Returns the id (`>= 1`), `UNSUPPORTED_NETWORK` (-2) for a canonical
/// network this engine doesn't host yet (gnosis), or `CREATE_FAILED` (-1) for an
/// unknown name / unavailable runtime.
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
            // reader's Drop still aborts its tasks.
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
        Created(u64),
        Running(SyncStatus, u64, Option<Arc<ElReader>>),
        // The status frozen at pause time (warm beacon fields keep showing).
        Paused(SyncStatus, u64),
        Unknown,
    }
    let snap = {
        let map = match engine.handles.lock() {
            Ok(m) => m,
            Err(_) => return "{}".to_string(),
        };
        match map.get(&handle) {
            Some(ChainEntry::Created(config)) => Snap::Created(config.wall_clock_period()),
            Some(ChainEntry::Running(config, sync, reader)) => {
                Snap::Running(sync.status(), config.wall_clock_period(), reader.clone())
            }
            Some(ChainEntry::Paused(config, frozen)) => {
                Snap::Paused(frozen.clone(), config.wall_clock_period())
            }
            None => Snap::Unknown,
        }
    };
    match snap {
        Snap::Created(wall) => {
            status_object(Lifecycle::NotStarted, None, wall, ElCounts::default())
        }
        Snap::Running(status, wall, reader) => {
            let el = match reader {
                Some(r) => engine.rt.block_on(async {
                    ElCounts {
                        snap_peers: r.snap_peer_count().await,
                        discovered: r.discovered_count(),
                        attempted: r.attempted_count().await,
                        backed_off: r.backoff_count().await,
                        blacklisted: r.blacklist_count().await,
                        optimistic_block: r.optimistic_block_number(),
                        finalized_block: r.finalized_block_number(),
                    }
                }),
                None => ElCounts::default(),
            };
            status_object(Lifecycle::Running, Some(status), wall, el)
        }
        // EL counts are zero while paused: the pool/discovery are torn down.
        Snap::Paused(frozen, wall) => {
            status_object(Lifecycle::Paused, Some(frozen), wall, ElCounts::default())
        }
        Snap::Unknown => "{}".to_string(),
    }
}

/// EL pool/discovery counts for the status snapshot (all zero for a
/// not-started handle or when the EL reader failed to start).
#[derive(Default)]
struct ElCounts {
    snap_peers: usize,
    discovered: usize,
    attempted: usize,
    backed_off: usize,
    blacklisted: usize,
    /// Beacon optimistic-head execution block number (0 before the anchor has one).
    optimistic_block: u64,
    /// Finalized execution block number (0 before the anchor has one).
    finalized_block: u64,
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
    if let Some(ChainEntry::Running(_, sync, reader)) = entry {
        engine.rt.block_on(async move {
            sync.stop().await;
            if let Some(reader) = reader {
                if let Ok(reader) = Arc::try_unwrap(reader) {
                    reader.stop().await;
                }
            }
        });
    }
}

/// `nativeRequestAccountJson`: run a verified account query for a running
/// handle, returning the `AccountProofResult` JSON, or `{"error": "..."}` for a
/// transport / not-running / bad-input failure.
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

/// `nativeGetBlockByNumberJson`: verified `eth_getBlockByNumber` (transactions as
/// hashes) for a running handle. Returns the block JSON when found+verified, the
/// literal `"null"` for a future/unknown block (eth's null), or `{"error": "..."}`
/// when it can't verify right now (which the Java side maps to a null → -32000).
/// `fullTransactions=true` is handled on the Java side (returns null before this
/// native runs), so this always serves the hashes-only shape.
pub fn get_block_by_number_json(handle: i64, block_tag: &str) -> String {
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
    match engine.rt.block_on(async { reader.get_block_by_number(target).await }) {
        Ok(Some(block)) => eljson::block_json(&block),
        Ok(None) => "null".to_string(), // verified future/unknown block → eth null
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
    obj.insert("network".into(), "mainnet".into());
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
    obj.insert("finalizedRootHex".into(), hex32(&s.finalized_root).into());
    // EL pool/discovery counts (the Rust engine's execution-layer side). The
    // pool keeps only snap-capable READY peers, so readyPeers == snapPeers.
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
    obj.insert("executionBlockNumber".into(), el.finalized_block.into());
    // A hand-built object of primitives always serializes; fall back to the
    // literal not-started shape rather than panic on the (impossible) error.
    serde_json::to_string(&serde_json::Value::Object(obj))
        .unwrap_or_else(|_| NOT_STARTED_FALLBACK.to_string())
}

/// The exact not-started shape, used only if serde ever failed (it can't for a
/// primitive object) — keeps this function total.
const NOT_STARTED_FALLBACK: &str = concat!(
    r#"{"running":false,"paused":false,"network":"mainnet","beaconState":"STARTING","#,
    r#""bootstrapped":false,"finalizedSlot":0,"optimisticSlot":0,"#,
    r#""currentPeriod":0,"targetPeriod":0,"peerCount":0,"servedPeersLastMinute":0,"#,
    r#""discv5TableSize":0,"syncStartPeriod":-1,"#,
    r#""finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000","#,
    r#""snapPeers":0,"readyPeers":0,"discoveredPeers":0,"attemptedDials":0,"#,
    r#""backedOffPeers":0,"blacklistedPeers":0,"optimisticBlockNumber":0,"#,
    r#""finalizedBlockNumber":0,"executionBlockNumber":0}"#,
);

#[cfg(test)]
mod tests {
    use super::*;

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
        let json = status_object(Lifecycle::NotStarted, None, 0, ElCounts::default());
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
        };
        let el = ElCounts {
            snap_peers: 5,
            discovered: 240,
            attempted: 14,
            backed_off: 30,
            blacklisted: 66,
            optimistic_block: 21_000_010,
            finalized_block: 20_999_000,
        };
        let synced: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Running,
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
        };
        let v: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Paused,
            Some(frozen),
            1795,
            ElCounts::default(),
        ))
        .unwrap();
        assert_eq!(v["running"], false);
        assert_eq!(v["paused"], true);
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
        };
        let v: serde_json::Value = serde_json::from_str(&status_object(
            Lifecycle::Running,
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
