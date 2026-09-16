//! Node.js binding over the myotis-engine **C ABI** (`capi.rs` /
//! `rust/include/myotis_engine.h`) via napi-rs — the Electron/desktop-host seam.
//!
//! Design notes, mirroring the other consumers of this seam (UniFFI for the
//! JVM hosts, Kotlin/Native cinterop for iOS):
//!
//! - We call the C-ABI entry points (`myotis_engine::capi`) rather than engine
//!   internals, so the binding stays pinned to the same JSON shapes the
//!   cross-engine golden tests enforce. The one engine change this required is
//!   `pub mod capi` — linking the rlib does not reliably resolve `extern "C"`
//!   imports of its `no_mangle` symbols, so the functions are called by Rust
//!   path instead (see the note on the module in myotis-engine's lib.rs).
//! - Compound values cross as JSON strings; parsing is the JS side's job.
//! - Verified reads run on bounded Myotis-owned workers, never libuv workers.
//!   Their Promise completion uses a referenced-while-busy Node-API TSFN.
//! - Stop/pause stay synchronous: cancel and drain native requests, then tear
//!   down the reader. They may block on indivisible native/filesystem work.
//! - Errors stay **in-band** (`{"error": ...}` objects, negative handles,
//!   `false`), exactly as the C header documents — no JS exceptions for
//!   engine-level failures, so all three seams behave identically.

#![allow(unused_unsafe)] // capi fns are a mix of safe/unsafe; calls are wrapped uniformly

use std::ffi::{c_char, CStr, CString};

use napi::bindgen_prelude::Object;
mod scheduler;
mod admission;
use napi::{Env, Result};
use napi_derive::napi;

// The C ABI of myotis-engine (capi.rs / rust/include/myotis_engine.h; the
// addon is built from the same tree, so init() reports the tree's current
// ABI_VERSION), called by Rust path — linking the rlib does not reliably
// resolve `extern "C"` imports of its no_mangle symbols.
use myotis_engine::capi::{
    myotis_accept_stale_anchor, myotis_available_networks_json, myotis_canonical_network_name,
    myotis_create, myotis_create_with_checkpoint, myotis_drain_logs, myotis_ens_record_json,
    myotis_estimate_gas_json,
    myotis_eth_call_json, myotis_fee_estimate_json, myotis_init, myotis_pause,
    myotis_request_account_json, myotis_resolve_ens_json, myotis_resume,
    myotis_send_raw_transaction_json, myotis_set_ws_bound_periods, myotis_start,
    myotis_status_json, myotis_stop, myotis_string_free,
};

/// Take ownership of an engine-allocated C string: copy to a Rust `String`,
/// release via `myotis_string_free` (never `free(3)` — the header's contract).
/// Null (the engine's OOM/interior-NUL sentinel) becomes an in-band error
/// object so JS never has to branch on empty strings.
fn take(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return r#"{"error":"engine returned null"}"#.to_string();
    }
    let s = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    unsafe { myotis_string_free(ptr) };
    s
}

/// A JS string crossing into C. Interior NULs can't appear in addresses/names/
/// JSON, but a hostile caller must get an in-band error, not a panic (the
/// workspace builds with `panic = "abort"`).
fn c_arg(s: &str) -> std::result::Result<CString, String> {
    CString::new(s).map_err(|_| r#"{"error":"argument contains NUL"}"#.to_string())
}

// ---------------------------------------------------------------------------
// Availability + catalog (synchronous, no engine handle involved)
// ---------------------------------------------------------------------------

/// ABI handshake; also installs the engine's log-ring subscriber (idempotent).
/// Returns the engine's `ABI_VERSION` — this addon is built from the same tree,
/// so it is always the tree's current value. A host loading a PREBUILT addon
/// must refuse to proceed unless this equals the version pinned in the notes of
/// the release it built against; the JSON shapes below are guaranteed only for
/// that version.
#[napi]
pub fn init() -> i32 {
    unsafe { myotis_init() }
}

/// Up to `max` buffered engine tracing lines, oldest first, newline-joined;
/// empty string when idle. Hosts pump this into their own log pipeline.
#[napi]
pub fn drain_logs(max: i32) -> String {
    take(unsafe { myotis_drain_logs(max) })
}

/// The embedded network catalog as a JSON array of NetworkInfo objects.
#[napi]
pub fn available_networks_json() -> String {
    take(unsafe { myotis_available_networks_json() })
}

/// Canonical network name, or null for an unknown network/alias.
#[napi]
pub fn canonical_network_name(name_or_alias: String) -> Option<String> {
    let c = match c_arg(&name_or_alias) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let ptr = unsafe { myotis_canonical_network_name(c.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    Some(take(ptr))
}

// ---------------------------------------------------------------------------
// Lifecycle (synchronous; stop/pause drain native work)
// ---------------------------------------------------------------------------

/// Allocate a not-yet-started handle (≥ 1); -1 unknown name / runtime-init
/// failure, -2 canonical-but-unsupported network, -3 `dataDir` was bound to a
/// caller-supplied checkpoint by `createWithCheckpoint` (resume it there, or
/// use a fresh directory). `data_dir` is where the engine persists sync
/// snapshots and peer caches.
#[napi]
pub fn create(env: &Env, network: String, data_dir: String) -> Result<i64> {
    scheduler::prepare(env)?;
    let (Ok(n), Ok(d)) = (c_arg(&network), c_arg(&data_dir)) else {
        return Ok(-1);
    };
    let handle = unsafe { myotis_create(n.as_ptr(), d.as_ptr()) };
    if handle > 0 { scheduler::created(env, handle)?; }
    Ok(handle)
}

/// Allocate a handle that bootstraps from the CALLER's checkpoint instead of
/// the embedded one (#441): the recovery path for an install parked in
/// `STALE_ANCHOR` after the host obtained a fresher checkpoint by its own
/// means. `checkpointRoot` is the beacon block root (32-byte hex, `0x`
/// optional); `checkpointSlot` is that block HEADER's slot as a plain JS
/// number (a safe integer, `1..=Number.MAX_SAFE_INTEGER`, not in the future).
///
/// Returns the handle (≥ 1) or an in-band sentinel: -1 invalid input (unknown
/// network, malformed/zero root, bad slot, empty dataDir, runtime failure),
/// -2 canonical-but-unsupported network, -3 the dataDir already belongs to a
/// different trust anchor. The engine does NOT authenticate the root — it
/// verifies forward from it exactly as from the embedded checkpoint (BLS on
/// every update, snapshot probation, weak-subjectivity gate on the supplied
/// slot's age), so supplying one never marks the client synced early. The
/// first call on a directory records the anchor in `sync-anchor[-net].json`;
/// later calls with the same root+slot resume that generation; any other
/// anchor, a directory holding embedded-anchor state, or a plain `create()` on
/// a marked directory is refused (-3) rather than silently switching anchors.
/// Requires `init() >= 26`.
#[napi]
pub fn create_with_checkpoint(
    env: &Env,
    network: String,
    data_dir: String,
    checkpoint_root: String,
    checkpoint_slot: f64,
) -> Result<i64> {
    // The documented JS representation is a safe integer; anything else is a
    // permanently malformed request, answered in-band like every other engine
    // refusal (never a JS exception).
    if !checkpoint_slot.is_finite()
        || checkpoint_slot.fract() != 0.0
        || checkpoint_slot < 1.0
        || checkpoint_slot > 9_007_199_254_740_991.0
    {
        return Ok(-1);
    }
    scheduler::prepare(env)?;
    let (Ok(n), Ok(d), Ok(r)) = (c_arg(&network), c_arg(&data_dir), c_arg(&checkpoint_root)) else {
        return Ok(-1);
    };
    let handle = unsafe {
        myotis_create_with_checkpoint(n.as_ptr(), d.as_ptr(), r.as_ptr(), checkpoint_slot as u64)
    };
    if handle > 0 { scheduler::created(env, handle)?; }
    Ok(handle)
}

/// Start the sync loop. False for an unknown/already-running handle.
#[napi]
pub fn start(env: &Env, handle: i64) -> bool {
    if !scheduler::owns(env, handle) { return false; }
    unsafe { myotis_start(handle) }
}

/// Status JSON object (camelCase keys), or "{}" for an unknown handle.
#[napi]
pub fn status_json(env: &Env, handle: i64) -> String {
    if !scheduler::owns(env, handle) { return "{}".into(); }
    take(unsafe { myotis_status_json(handle) })
}

/// Idle-sleep: Running→Paused (tear down networking, keep warm state).
#[napi]
pub fn pause(env: &Env, handle: i64) -> Result<bool> {
    let cancellation = scheduler::cancel_handle(env, handle, false)?;
    let result = cancellation.owned && unsafe { myotis_pause(handle) };
    cancellation.finish(env);
    Ok(result)
}

/// Paused→Running warm restart. False = rebuild failed (still PAUSED, retry).
#[napi]
pub fn resume(env: &Env, handle: i64) -> bool {
    if !scheduler::owns(env, handle) { return false; }
    unsafe { myotis_resume(handle) }
}

/// Cancel queued/active native work, drain it, then remove and shut down.
/// Promise callbacks deliver once JS regains control. Unknown id is a no-op.
#[napi]
pub fn stop(env: &Env, handle: i64) -> Result<()> {
    let cancellation = scheduler::cancel_handle(env, handle, true)?;
    if cancellation.owned { unsafe { myotis_stop(handle) }; }
    cancellation.finish(env);
    Ok(())
}

// ---------------------------------------------------------------------------
// Weak-subjectivity gate controls (synchronous — a host policy decision)
// ---------------------------------------------------------------------------
//
// When the anchor (embedded checkpoint or persisted snapshot, whichever is
// newer) is older than the network's WS bound, the engine refuses to walk
// forward from it — that anchor is old enough that its sync committee could
// have exited, so BLS verification alone cannot tell a forged continuation
// (a long-range attack) from the honest chain. It parks in `STALE_ANCHOR`
// (`statusJson().beaconState`) and verified reads fail closed. The bound is
// small on some networks (~34 h on gnosis), so an embedding must decide, on
// its users' behalf or by exposing the choice, how to handle a parked node.
// Both controls below are the host's decision; the engine never persists them.

/// Override the weak-subjectivity anchor-age bound, in sync-committee periods;
/// `0` restores the network default (`statusJson().wsBoundPeriods` reports the
/// effective value). Raising it widens the anchor age this node will accept.
/// Applied live over the shared policy, so a parked handle re-evaluates within
/// ~1 s. Per-host, never persisted. Returns `false` for an unknown handle.
#[napi]
pub fn set_ws_bound_periods(env: &Env, handle: i64, periods: i64) -> bool {
    if !scheduler::owns(env, handle) { return false; }
    unsafe { myotis_set_ws_bound_periods(handle, periods) }
}

/// Accept the current over-age anchor and let sync proceed past a
/// `STALE_ANCHOR` park — the informed-consent escape hatch a host puts behind
/// its own UI (or an experimental tier). Run-sticky: it releases the park
/// (current or subsequent) for the rest of THIS run and is never persisted, so
/// a fresh `create()` starts gated again. Returns `false` for an unknown
/// handle.
#[napi]
pub fn accept_stale_anchor(env: &Env, handle: i64) -> bool {
    if !scheduler::owns(env, handle) { return false; }
    unsafe { myotis_accept_stale_anchor(handle) }
}

// ---------------------------------------------------------------------------
// Verified reads (bounded owned workers → Promise<string>)
// ---------------------------------------------------------------------------

/// Verified account read (balance/nonce/code hash + Merkle proof + beacon
/// verification fields). Resolves to the AccountProofResult JSON.
#[napi(ts_return_type = "Promise<string>")]
pub fn request_account_json<'env>(env: &'env Env, handle: i64, address: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || match c_arg(&address) {
        Ok(a) => take(unsafe { myotis_request_account_json(handle, a.as_ptr()) }),
        Err(e) => e,
    })
}

/// Verified eth_call over the revm executor. `from` empty = anonymous sender;
/// `value` is wei as a decimal string; `block` is a tag or a block number.
/// The engine checks `block`: the call runs against the verified head, so a
/// number outside [head-64, head+16] is refused, never answered from the head
/// (`{"error","code":-32602}` when it can never be served; README "Notes").
#[napi(ts_return_type = "Promise<string>")]
pub fn eth_call_json<'env>(env: &'env Env,
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
    block: String,
) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        match (c_arg(&from), c_arg(&to), c_arg(&data), c_arg(&value), c_arg(&block)) {
            (Ok(f), Ok(t), Ok(d), Ok(v), Ok(b)) => take(unsafe {
                myotis_eth_call_json(handle, f.as_ptr(), t.as_ptr(), d.as_ptr(), v.as_ptr(), b.as_ptr())
            }),
            _ => r#"{"error":"argument contains NUL"}"#.to_string(),
        }
    })
}

/// Verified eth_estimateGas (local EVM metering + safety buffer).
#[napi(ts_return_type = "Promise<string>")]
pub fn estimate_gas_json<'env>(env: &'env Env,
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        match (c_arg(&from), c_arg(&to), c_arg(&data), c_arg(&value)) {
            (Ok(f), Ok(t), Ok(d), Ok(v)) => take(unsafe {
                myotis_estimate_gas_json(handle, f.as_ptr(), t.as_ptr(), d.as_ptr(), v.as_ptr())
            }),
            _ => r#"{"error":"argument contains NUL"}"#.to_string(),
        }
    })
}

/// Verified ENS forward resolution (name → address).
#[napi(ts_return_type = "Promise<string>")]
pub fn resolve_ens_json<'env>(env: &'env Env, handle: i64, name: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || match c_arg(&name) {
        Ok(n) => take(unsafe { myotis_resolve_ens_json(handle, n.as_ptr()) }),
        Err(e) => e,
    })
}

/// Generic ENS record dispatch — `params_json` carries the method + args, e.g.
/// `{"method":"contenthash","name":"vitalik.eth"}` (the record freedom-browser
/// navigation needs), `{"method":"text","name":"a.eth","key":"avatar"}`, …
#[napi(ts_return_type = "Promise<string>")]
pub fn ens_record_json<'env>(env: &'env Env, handle: i64, params_json: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || match c_arg(&params_json) {
        Ok(p) => take(unsafe { myotis_ens_record_json(handle, p.as_ptr()) }),
        Err(e) => e,
    })
}

/// Verified fee suggestions: `{"gasPriceWei","maxPriorityFeePerGasWei"}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn fee_estimate_json<'env>(env: &'env Env, handle: i64) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || take(unsafe { myotis_fee_estimate_json(handle) }))
}

/// Gossip a signed raw transaction to devp2p peers: `{"txHash":"0x…"}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn send_raw_transaction_json<'env>(env: &'env Env, handle: i64, raw_tx_hex: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || match c_arg(&raw_tx_hex) {
        Ok(r) => take(unsafe { myotis_send_raw_transaction_json(handle, r.as_ptr()) }),
        Err(e) => e,
    })
}
