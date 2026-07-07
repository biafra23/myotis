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
use std::sync::{Arc, Mutex, OnceLock};

use myotis_net::el::reader::ElReader;
use myotis_net::{ChainConfig, SyncHandle, SyncState, SyncStatus};

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

/// `nativeCreate`: allocate an id for a not-yet-started mainnet chain. Returns the
/// id (`>= 1`), `UNSUPPORTED_NETWORK` (-2) for a canonical-but-not-mainnet network,
/// or `CREATE_FAILED` (-1) for an unknown name / unavailable runtime.
pub fn create(network_name: &str, data_dir: &str) -> i64 {
    let Some(engine) = engine() else {
        return CREATE_FAILED;
    };
    // Unknown network → CREATE_FAILED; canonical-but-not-mainnet → UNSUPPORTED.
    let mut config = match crate::catalog::canonical_network_name(network_name) {
        None => return CREATE_FAILED,
        Some("mainnet") => match config_for(network_name) {
            Some(c) => c,
            None => return CREATE_FAILED,
        },
        Some(_) => return UNSUPPORTED_NETWORK,
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

/// `nativeStart`: start the sync loop for a created handle. Returns true on
/// success; false for an unknown id, an already-running handle, or a start error.
pub fn start(handle: i64) -> bool {
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
        match map.get(&handle) {
            Some(ChainEntry::Created(c)) => Arc::clone(c),
            _ => return false, // unknown id, or already running
        }
    };
    // SyncHandle::start must run inside the tokio runtime (it spawns tasks).
    // The one deep ChainConfig clone: SyncHandle::start takes it by value.
    let sync = match engine.rt.block_on(async { SyncHandle::start((*config).clone()) }) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Start the EL reader against the sync loop's execution anchor (the CL→EL
    // bridge). Mainnet-only for now, matching the CL host scope. A failure
    // (e.g. a discv4 UDP bind error) is non-fatal: the CL still runs and EL
    // queries report the reader unavailable, rather than failing the whole start.
    let reader = match engine
        .rt
        .block_on(async { ElReader::start_mainnet(sync.exec_anchor()).await })
    {
        Ok(r) => Some(Arc::new(r)),
        Err(e) => {
            tracing::warn!(handle, error = %e, "EL reader failed to start; CL runs without EL");
            None
        }
    };
    // Re-lock and publish ONLY if the entry is still the same Created one: a
    // concurrent stop() may have removed it, or a racing start() may have already
    // published a Running one, while we were starting. Either way, shut the handle
    // we just started down rather than orphan its tokio/libp2p host.
    let mut map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => {
            shutdown(engine, sync, reader);
            return false;
        }
    };
    match map.get(&handle) {
        Some(ChainEntry::Created(_)) => {
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
    let map = match engine.handles.lock() {
        Ok(m) => m,
        Err(_) => return "{}".to_string(),
    };
    match map.get(&handle) {
        // targetPeriod is derived from the config AT READ TIME (not carried in
        // the sync snapshot): fresh across bootstrap stalls, and real (not 0)
        // for a created-but-not-started handle — matching the Java engine's
        // unconditional wall-clock computation behind the same API.
        Some(ChainEntry::Created(config)) => {
            status_object(false, None, config.wall_clock_period())
        }
        Some(ChainEntry::Running(config, sync, _reader)) => {
            status_object(true, Some(sync.status()), config.wall_clock_period())
        }
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
        Some(ChainEntry::Created(_)) => Err("handle not started"),
        None => Err("unknown handle"),
    }
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
fn status_object(running: bool, status: Option<SyncStatus>, target_period: u64) -> String {
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
    // Floor at the store's period: a device clock set in the past must not
    // publish a target below current (the target >= current invariant).
    obj.insert("targetPeriod".into(), target_period.max(s.period).into());
    obj.insert("peerCount".into(), s.peer_count.into());
    obj.insert("servedPeersLastMinute".into(), s.served_peers_last_min.into());
    obj.insert("discv5TableSize".into(), s.discv5_table_size.into());
    obj.insert("syncStartPeriod".into(), s.sync_start_period.into());
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
    r#""currentPeriod":0,"targetPeriod":0,"peerCount":0,"servedPeersLastMinute":0,"#,
    r#""discv5TableSize":0,"syncStartPeriod":-1,"#,
    r#""finalizedRootHex":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_started_status_shape_is_stable() {
        // The golden not-started object (parsed by the Java RustChainHandle test).
        let json = status_object(false, None, 0);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["running"], false);
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
        let synced: serde_json::Value =
            serde_json::from_str(&status_object(true, Some(mk(SyncState::Synced)), 1795)).unwrap();
        assert_eq!(synced["running"], true);
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

        for (st, expect, boot) in [
            (SyncState::Starting, "SYNCING", false),
            (SyncState::Bootstrapping, "SYNCING", false),
            (SyncState::CatchingUp, "CATCHING_UP", true),
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&status_object(true, Some(mk(st)), 1795)).unwrap();
            assert_eq!(v["beaconState"], expect);
            assert_eq!(v["bootstrapped"], boot);
        }
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
        let v: serde_json::Value =
            serde_json::from_str(&status_object(true, Some(s), 1770)).unwrap();
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
