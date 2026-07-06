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
//!     to `Running(SyncHandle)`.
//!   - `status_json` reads the live `SyncStatus` (or the not-started shape).
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
use std::sync::{Mutex, OnceLock};

use myotis_net::{ChainConfig, SyncHandle, SyncState, SyncStatus};

/// R1 hosts mainnet only (Gnosis lands later). Returned by `create` for any
/// other (still-canonical) network so the Java side can raise a named error.
const UNSUPPORTED_NETWORK: i64 = -1;
/// `create` failure (bad name, or the runtime never came up).
const CREATE_FAILED: i64 = -1;

/// One hosted chain: created-but-not-started, or running.
enum ChainEntry {
    Created(ChainConfig),
    Running(SyncHandle),
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

/// Resolve a config for a canonical/alias network name. R1: mainnet only.
fn config_for(network_name: &str) -> Option<ChainConfig> {
    match crate::catalog::canonical_network_name(network_name) {
        Some("mainnet") => Some(ChainConfig::mainnet()),
        _ => None,
    }
}

/// `nativeCreate`: allocate an id for a not-yet-started mainnet chain. Returns
/// the id, `UNSUPPORTED_NETWORK` for a non-mainnet (but canonical) network, or
/// `CREATE_FAILED` for an unknown name / unavailable runtime.
pub fn create(network_name: &str, _data_dir: &str) -> i64 {
    let Some(engine) = engine() else {
        return CREATE_FAILED;
    };
    // Unknown network → CREATE_FAILED; canonical-but-not-mainnet → UNSUPPORTED.
    let config = match crate::catalog::canonical_network_name(network_name) {
        None => return CREATE_FAILED,
        Some("mainnet") => match config_for(network_name) {
            Some(c) => c,
            None => return CREATE_FAILED,
        },
        Some(_) => return UNSUPPORTED_NETWORK,
    };
    let id = engine.next_id.fetch_add(1, Ordering::Relaxed);
    match engine.handles.lock() {
        Ok(mut map) => {
            map.insert(id, ChainEntry::Created(config));
            id
        }
        // A poisoned lock means another native panicked mid-critical-section —
        // shouldn't happen (panic-free by construction), but never panic here.
        Err(_) => CREATE_FAILED,
    }
}

/// `nativeStart`: start the sync loop for a created handle. Returns true on
/// success; false for an unknown id, an already-running handle, or a start error.
pub fn start(handle: i64) -> bool {
    let Some(engine) = engine() else {
        return false;
    };
    let mut map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return false,
    };
    // Take the config out only if the entry is Created; leave Running untouched.
    let config = match map.get(&handle) {
        Some(ChainEntry::Created(c)) => c.clone(),
        _ => return false,
    };
    // SyncHandle::start must run inside the tokio runtime (it spawns tasks).
    let started = engine.rt.block_on(async { SyncHandle::start(config) });
    match started {
        Ok(sync) => {
            map.insert(handle, ChainEntry::Running(sync));
            true
        }
        Err(_) => false,
    }
}

/// `nativeStatusJson`: the status of one handle as a JSON object (see
/// `status_object` for the exact keys). `"{}"` for an unknown handle.
pub fn status_json(handle: i64) -> String {
    let Some(engine) = engine() else {
        return "{}".to_string();
    };
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return "{}".to_string(),
    };
    match map.get(&handle) {
        Some(ChainEntry::Created(_)) => status_object(false, None),
        Some(ChainEntry::Running(sync)) => status_object(true, Some(sync.status())),
        None => "{}".to_string(),
    }
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
    if let Some(ChainEntry::Running(sync)) = entry {
        engine.rt.block_on(async move { sync.stop().await });
    }
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

/// Serialize the status object with EXACTLY the keys the Java `RustChainHandle`
/// parses (camelCase). `running=false` / `status=None` → the not-started shape.
/// Built by hand (not serde) so the key set + ordering is the golden contract
/// both `status_json_shape` tests pin.
fn status_object(running: bool, status: Option<SyncStatus>) -> String {
    let s = status.unwrap_or_else(SyncStatus::initial);
    // A not-started handle reports STARTING; a running one maps its live state.
    let beacon = if running {
        beacon_state(s.state)
    } else {
        "STARTING"
    };
    let bootstrapped = running
        && matches!(s.state, SyncState::CatchingUp | SyncState::Synced);
    let mut obj = serde_json::Map::new();
    obj.insert("running".into(), running.into());
    obj.insert("network".into(), "mainnet".into());
    obj.insert("beaconState".into(), beacon.into());
    obj.insert("bootstrapped".into(), bootstrapped.into());
    obj.insert("finalizedSlot".into(), s.finalized_slot.into());
    obj.insert("optimisticSlot".into(), s.optimistic_slot.into());
    obj.insert("currentPeriod".into(), s.period.into());
    obj.insert("peerCount".into(), s.peer_count.into());
    obj.insert("finalizedRootHex".into(), hex32(&s.finalized_root).into());
    // A hand-built object of primitives always serializes; fall back to the
    // literal not-started shape rather than panic on the (impossible) error.
    serde_json::to_string(&serde_json::Value::Object(obj))
        .unwrap_or_else(|_| NOT_STARTED_FALLBACK.to_string())
}

/// The exact not-started shape, used only if serde ever failed (it can't for a
/// primitive object) — keeps this function total.
const NOT_STARTED_FALLBACK: &str = concat!(
    r#"{"running":false,"network":"mainnet","beaconState":"STARTING","#,
    r#""bootstrapped":false,"finalizedSlot":0,"optimisticSlot":0,"#,
    r#""currentPeriod":0,"peerCount":0,"#,
    r#""finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_started_status_shape_is_stable() {
        // The golden not-started object (parsed by the Java RustChainHandle test).
        let json = status_object(false, None);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["running"], false);
        assert_eq!(v["network"], "mainnet");
        assert_eq!(v["beaconState"], "STARTING");
        assert_eq!(v["bootstrapped"], false);
        assert_eq!(v["finalizedSlot"], 0);
        assert_eq!(v["optimisticSlot"], 0);
        assert_eq!(v["currentPeriod"], 0);
        assert_eq!(v["peerCount"], 0);
        assert_eq!(
            v["finalizedRootHex"],
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
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
        };
        let synced: serde_json::Value =
            serde_json::from_str(&status_object(true, Some(mk(SyncState::Synced)))).unwrap();
        assert_eq!(synced["running"], true);
        assert_eq!(synced["beaconState"], "SYNCED");
        assert_eq!(synced["bootstrapped"], true);
        assert_eq!(synced["finalizedSlot"], 100);
        assert_eq!(synced["optimisticSlot"], 132);
        assert_eq!(synced["currentPeriod"], 1777);
        assert_eq!(synced["peerCount"], 7);
        assert_eq!(synced["finalizedRootHex"], hex32(&[0xab; 32]));

        for (st, expect, boot) in [
            (SyncState::Starting, "SYNCING", false),
            (SyncState::Bootstrapping, "SYNCING", false),
            (SyncState::CatchingUp, "CATCHING_UP", true),
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&status_object(true, Some(mk(st)))).unwrap();
            assert_eq!(v["beaconState"], expect);
            assert_eq!(v["bootstrapped"], boot);
        }
    }

    #[test]
    fn unknown_handle_returns_empty_object() {
        // No engine calls here — just the contract for a missing handle, which
        // status_json returns directly.
        assert_eq!(status_json(i64::MIN), "{}");
    }
}
