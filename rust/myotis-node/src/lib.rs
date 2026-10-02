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
    myotis_estimate_gas_json, myotis_estimate_gas_tx_json, myotis_eth_call_overrides_json,
    myotis_eth_call_tx_json, myotis_eth_call_json, myotis_fee_estimate_json,
    myotis_fee_history_json, myotis_get_block_by_hash_json, myotis_get_block_by_number_json,
    myotis_get_block_receipts_json, myotis_get_code_json, myotis_get_logs_json,
    myotis_get_storage_at_json, myotis_get_transaction_by_hash_json,
    myotis_get_transaction_receipt_json, myotis_import_log_index_files, myotis_init,
    myotis_log_index_status_json, myotis_pause, myotis_pending_nonce_overlay,
    myotis_request_account_json, myotis_resolve_ens_json, myotis_resume,
    myotis_send_raw_transaction_json, myotis_set_boot_enodes, myotis_set_log_index_config,
    myotis_set_ws_bound_periods, myotis_start,
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
/// The in-band refusal of an argument with a NUL byte on the calls whose own
/// refusals are permanent (`eth_call`, the state reads): the same -32602 the
/// engine gives a malformed selector.
const NUL_INVALID_PARAMS: &str = r#"{"error":"argument contains NUL","code":-32602}"#;

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

/// Replace this handle's HOST-SUPPLIED EL seed pins (ABI >= 31, #465):
/// `enodes_json` is a JSON array of `enode://` URLs, applied or refused AS A
/// WHOLE — the contract is `myotis_set_boot_enodes` in `myotis_engine.h`
/// (README "Notes"). `false` for a refused push or an unknown handle; a NUL
/// byte is refused here, before the engine. Per-host, never persisted.
#[napi]
pub fn set_boot_enodes(env: &Env, handle: i64, enodes_json: String) -> bool {
    if !scheduler::owns(env, handle) { return false; }
    match c_arg(&enodes_json) {
        Ok(j) => unsafe { myotis_set_boot_enodes(handle, j.as_ptr()) },
        Err(_) => false,
    }
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
/// verification fields). Resolves to the AccountProofResult JSON. `block`
/// (ABI >= 32, optional) is the RPC block selector the engine applies or
/// refuses: omitted or a head tag proves at the verified head, `finalized` at
/// the beacon-finalized block, a number only inside [head-64, head+16]
/// (`{"error","code":-32602}` otherwise); the result names the block it
/// proved at (`anchor`). A malformed address is refused the same way (#503).
#[napi(ts_return_type = "Promise<string>")]
pub fn request_account_json<'env>(
    env: &'env Env,
    handle: i64,
    address: String,
    block: Option<String>,
) -> Result<Object<'env>> {
    let block = block.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(a), Ok(b)) = (c_arg(&address), c_arg(&block)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !hex_of_len(&address, 20) {
            return invalid_params("invalid address (expected 20-byte hex)");
        }
        take(unsafe { myotis_request_account_json(handle, a.as_ptr(), b.as_ptr()) })
    })
}

/// Verified eth_call over the revm executor. `from` empty = anonymous sender;
/// `value` is wei as a decimal string; `block` is a tag or a block number.
/// The engine checks `block`: a head tag runs against the verified head,
/// `finalized` (ABI >= 30) against the beacon-finalized block, and a number
/// outside [head-64, head+16] is refused, never answered from the head
/// (`{"error","code":-32602}` when it can never be served; README "Notes").
/// The result names the block it ran against (`blockNumber`, `verified`).
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
            // A malformed argument, refused here instead of in the engine:
            // permanent, like the engine's own refusals for this call (README).
            _ => NUL_INVALID_PARAMS.to_string(),
        }
    })
}

/// Verified eth_estimateGas (local EVM metering + safety buffer). `to` is
/// required; `from` empty = anonymous sender; `value` is wei as a decimal
/// string. A malformed argument is refused as the permanent
/// `{"error","code":-32602}` (#503), where the engine's own refusal of one
/// carries no code.
#[napi(ts_return_type = "Promise<string>")]
pub fn estimate_gas_json<'env>(env: &'env Env,
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        let (Ok(f), Ok(t), Ok(d), Ok(v)) = (c_arg(&from), c_arg(&to), c_arg(&data), c_arg(&value)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        // The engine's checks, in its order.
        if !hex_of_len(&to, 20) {
            return invalid_params("invalid 'to' address (expected 20-byte hex)");
        }
        if !from.trim().is_empty() && !hex_of_len(&from, 20) {
            return invalid_params("invalid 'from' address (expected 20-byte hex)");
        }
        if !data.trim().is_empty() && !hex_bytes(&data) {
            return invalid_params("invalid call data (expected hex)");
        }
        if !value.trim().is_empty() && !decimal_u256(value.trim()) {
            return invalid_params("invalid value (expected decimal wei)");
        }
        take(unsafe { myotis_estimate_gas_json(handle, f.as_ptr(), t.as_ptr(), d.as_ptr(), v.as_ptr()) })
    })
}

/// Verified eth_estimateGas for the FULL JSON-RPC transaction object (ABI >= 34):
/// `tx` is geth's TransactionArgs JSON — EIP-7702 `authorizationList`,
/// `accessList`, `gas`, fees, `nonce` and `type` are applied, never dropped —
/// `block` the block selector (checked as for ethCallJson), `stateOverrides` a
/// state override object ('' = none). A malformed or contradictory object is
/// the permanent `{"error","code":-32602}`; `{"status":"infeasible","reason"}`
/// is geth's "gas required exceeds allowance" / "insufficient funds for
/// transfer" answer (README "Notes").
#[napi(ts_return_type = "Promise<string>")]
pub fn estimate_gas_tx_json<'env>(env: &'env Env,
    handle: i64,
    tx: String,
    block: String,
    state_overrides: String,
) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        match (c_arg(&tx), c_arg(&block), c_arg(&state_overrides)) {
            (Ok(t), Ok(b), Ok(o)) => take(unsafe {
                myotis_estimate_gas_tx_json(handle, t.as_ptr(), b.as_ptr(), o.as_ptr())
            }),
            // A malformed argument, refused here instead of in the engine:
            // permanent, like the engine's own refusals for this call (README).
            _ => NUL_INVALID_PARAMS.to_string(),
        }
    })
}

/// Verified eth_call for the FULL JSON-RPC transaction object (ABI >= 35): the
/// arguments of estimateGasTxJson, every field applied as the estimate applies
/// it — `gas` as the call's limit, a fee checked and charged to the sender,
/// EIP-7702 `authorizationList`, `accessList`, `nonce` — never dropped. A
/// malformed or contradictory object is the permanent `{"error","code":-32602}`;
/// `{"status":"infeasible","reason"}` is geth's -32000 answer ("out of gas",
/// "intrinsic gas too low: …", "insufficient funds for gas * price + value: …",
/// README "Notes").
#[napi(ts_return_type = "Promise<string>")]
pub fn eth_call_tx_json<'env>(env: &'env Env,
    handle: i64,
    tx: String,
    block: String,
    state_overrides: String,
) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        match (c_arg(&tx), c_arg(&block), c_arg(&state_overrides)) {
            (Ok(t), Ok(b), Ok(o)) => take(unsafe {
                myotis_eth_call_tx_json(handle, t.as_ptr(), b.as_ptr(), o.as_ptr())
            }),
            // A malformed argument, refused here instead of in the engine:
            // permanent, like the engine's own refusals for this call (README).
            _ => NUL_INVALID_PARAMS.to_string(),
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

/// Gossip a signed raw transaction to devp2p peers: `{"txHash":"0x…"}`, `{"status":"rejected","reason"}` (ABI ≥ 36: refused before broadcast, nothing sent; the reason is geth's txpool verdict) or `{"error": ...}`.
/// Hex that is no transaction, or none, is refused as the permanent
/// `{"error","code":-32602}` (#503), where the engine's own refusal carries no
/// code.
#[napi(ts_return_type = "Promise<string>")]
pub fn send_raw_transaction_json<'env>(env: &'env Env, handle: i64, raw_tx_hex: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        let Ok(r) = c_arg(&raw_tx_hex) else { return NUL_INVALID_PARAMS.to_string() };
        if !hex_bytes(&raw_tx_hex) {
            return invalid_params("invalid raw transaction hex");
        }
        let h = raw_tx_hex.strip_prefix("0x").or_else(|| raw_tx_hex.strip_prefix("0X")).unwrap_or(&raw_tx_hex);
        if h.is_empty() {
            return invalid_params("empty raw transaction");
        }
        take(unsafe { myotis_send_raw_transaction_json(handle, r.as_ptr()) })
    })
}

/// `eth_call` with a STATE OVERRIDE object (`stateOverrides`, JSON; '' = none):
/// a simulation over verified state under the caller's hypothesis, not a chain
/// fact. Every other argument, and the result, are ethCallJson's; a malformed
/// override is refused as permanently as a malformed `block` (#503).
#[napi(ts_return_type = "Promise<string>")]
#[allow(clippy::too_many_arguments)]
pub fn eth_call_overrides_json<'env>(env: &'env Env,
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
    block: String,
    state_overrides: String,
) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        match (c_arg(&from), c_arg(&to), c_arg(&data), c_arg(&value), c_arg(&block), c_arg(&state_overrides)) {
            (Ok(f), Ok(t), Ok(d), Ok(v), Ok(b), Ok(o)) => take(unsafe {
                myotis_eth_call_overrides_json(
                    handle, f.as_ptr(), t.as_ptr(), d.as_ptr(), v.as_ptr(), b.as_ptr(), o.as_ptr(),
                )
            }),
            _ => NUL_INVALID_PARAMS.to_string(),
        }
    })
}

// ---------------------------------------------------------------------------
// The rest of a provider's verified reads (#503): blocks, receipts,
// transactions, fee history, code and storage, logs
// ---------------------------------------------------------------------------
//
// Wrapped as the reads above are, each resolves to the engine's JSON
// UNCHANGED: the result object or array, the literal `"null"` for a verified
// not-found, or an `{"error": …}` object — a refusal of the request itself
// carries `"code":-32602` and is permanent (README "Notes"). The state reads
// have a fourth outcome, a result without a verdict (`verifyMethod: null`),
// which is not to be served (README).
//
// The engine leaves part of a request's checking to the JSON-RPC routers that
// call it on the other hosts; this binding has no router in front of it, so it
// makes those checks here, before the engine, each refused as the permanent
// `-32602` the routers answer: a NUL byte in a string; a block number in bare
// digits for the block, receipts and fee-history selectors (the first and last
// would read them as HEX; the state reads and the calls read them as decimal,
// as ethCallJson always has, and keep doing so); a malformed address, hash,
// call data, value or raw transaction, which the engine refuses in a shape
// that looks retryable (here and in requestAccountJson, estimateGasJson and
// sendRawTransactionJson above); reward percentiles out of range or order; an
// empty import list; and a count or nonce that is not a safe integer. A short
// storage position (`0x0`, as dApps send it) is padded to its 32-byte word, as
// the routers pad it. Each check is the engine's own parse or a router's rule,
// so what this binding refuses, the other hosts refuse too.

/// A permanent refusal of the request: `{"error": why, "code": -32602}`.
fn invalid_params(why: &str) -> String {
    format!(r#"{{"error":{},"code":-32602}}"#, serde_json::Value::from(why))
}

/// Whether a JS number is an integer this binding can pass on exactly.
fn safe_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0
}

/// A block number in bare digits, which the block and fee-history selectors
/// would take as HEX — `"23500000"` a block far past the head, or a smaller
/// number silently the wrong block — while a JS caller means decimal. The
/// JSON-RPC routers refuse it, and so do those reads; the receipts selector
/// is refused up front too, which the engine refuses only once the handle
/// runs.
fn bare_digits(selector: &str) -> bool {
    let s = selector.trim();
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Hex of exactly `len` bytes, `0x` optional: the engine's own address and
/// 32-byte-word parsers, mirrored, so only what it would refuse is refused.
fn hex_of_len(s: &str, len: usize) -> bool {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    h.len() == 2 * len && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Hex bytes of any length up to 1 MiB, `0x` optional: the engine's parser
/// for call data and raw transactions, mirrored.
fn hex_bytes(s: &str) -> bool {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    h.len() <= 2 * 1024 * 1024 && h.len().is_multiple_of(2) && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A wei amount as the engine parses it (ruint's radix 10): decimal digits,
/// `_` ignored, at most `U256::MAX`.
fn decimal_u256(s: &str) -> bool {
    const U256_MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    if !s.bytes().all(|b| b.is_ascii_digit() || b == b'_') {
        return false;
    }
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).skip_while(|&c| c == '0').collect();
    digits.len() < U256_MAX.len() || (digits.len() == U256_MAX.len() && digits.as_str() <= U256_MAX)
}

/// A storage position as the engine reads it, `0x` and 64 hex digits; a shorter
/// quantity (`0x0`) is left-padded, as the routers pad it. `None` when it is no
/// hex or longer than 32 bytes.
fn storage_word(position: &str) -> Option<String> {
    let h = position.strip_prefix("0x").or_else(|| position.strip_prefix("0X")).unwrap_or(position);
    let hex = !h.is_empty() && h.len() <= 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
    hex.then(|| format!("0x{h:0>64}"))
}

/// eth_feeHistory's reward percentiles, checked as the routers check them (the
/// engine leaves range and order to its caller): `''`, `null` or `[]` ask for
/// no reward column — geth answers none for an empty list — and anything else
/// must be JSON numbers in [0, 100], non-decreasing, at most 100. What to hand
/// the engine — the numbers re-serialised, as the routers hand them over, so
/// long numerals cannot overrun its 4 KiB bound — or the refusal.
fn reward_percentiles(json: &str) -> std::result::Result<String, String> {
    let json = json.trim();
    if json.is_empty() || json == "null" {
        return Ok(String::new());
    }
    // A numeral past f64's range fails the parse itself, so the message names
    // the numbers too.
    let not_an_array = || invalid_params("reward percentiles must be a JSON array of numbers");
    let parsed: serde_json::Value = serde_json::from_str(json).map_err(|_| not_an_array())?;
    let list = parsed.as_array().ok_or_else(not_an_array)?;
    if list.is_empty() {
        return Ok(String::new());
    }
    if list.len() > 100 {
        return Err(invalid_params(&format!("at most 100 reward percentiles, got {}", list.len())));
    }
    let mut last = 0.0;
    for p in list {
        let Some(d) = p.as_f64() else {
            return Err(invalid_params("reward percentiles must be JSON numbers"));
        };
        if !(0.0..=100.0).contains(&d) {
            return Err(invalid_params(&format!("reward percentile {d} is outside [0, 100]")));
        }
        if d < last {
            return Err(invalid_params("reward percentiles must be non-decreasing"));
        }
        last = d;
    }
    Ok(parsed.to_string())
}

/// importLogIndexFiles' paths: a non-empty JSON array of non-empty strings.
fn import_paths_ok(json: &str) -> bool {
    serde_json::from_str::<Vec<String>>(json)
        .is_ok_and(|paths| !paths.is_empty() && paths.iter().all(|p| !p.trim().is_empty()))
}

/// pendingNonceOverlay's mined nonce: a non-negative safe integer.
fn nonce_arg(n: f64) -> Option<i64> {
    (safe_integer(n) && n >= 0.0).then_some(n as i64)
}

/// eth_getBlockByNumber: the block JSON, the literal `"null"`, or
/// `{"error"}`. `blockTag` is a tag or a 0x-number (bare digits are refused);
/// `fullTransactions` (default false) selects decoded transaction objects over
/// hashes.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_block_by_number_json<'env>(
    env: &'env Env,
    handle: i64,
    block_tag: String,
    full_transactions: Option<bool>,
) -> Result<Object<'env>> {
    let full = full_transactions.unwrap_or(false);
    scheduler::submit(env, handle, move || {
        let Ok(b) = c_arg(&block_tag) else { return NUL_INVALID_PARAMS.to_string() };
        if bare_digits(&block_tag) {
            return invalid_params("a block number must be 0x-hex");
        }
        take(unsafe { myotis_get_block_by_number_json(handle, b.as_ptr(), full) })
    })
}

/// eth_getBlockByHash: the block JSON, the literal `"null"` (a hash this node
/// never verified), or `{"error"}`. `fullTransactions` defaults to false.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_block_by_hash_json<'env>(
    env: &'env Env,
    handle: i64,
    block_hash: String,
    full_transactions: Option<bool>,
) -> Result<Object<'env>> {
    let full = full_transactions.unwrap_or(false);
    scheduler::submit(env, handle, move || {
        let Ok(h) = c_arg(&block_hash) else { return NUL_INVALID_PARAMS.to_string() };
        if !hex_of_len(&block_hash, 32) {
            return invalid_params("invalid block hash (expected 32-byte hex)");
        }
        take(unsafe { myotis_get_block_by_hash_json(handle, h.as_ptr(), full) })
    })
}

/// eth_feeHistory: `{"oldestBlock","baseFeePerGas","gasUsedRatio"[,"reward"]}`
/// or `{"error"}`. `blockCount` is a JS number, a safe integer (the engine
/// refuses one below 1 and clamps a large one to what it serves) — convert a
/// JSON-RPC quantity first; `newestBlock` a tag or a 0x-number;
/// `percentilesJson` a JSON number array, or omitted / '' / `[]` for no reward
/// column.
#[napi(ts_return_type = "Promise<string>")]
pub fn fee_history_json<'env>(
    env: &'env Env,
    handle: i64,
    block_count: f64,
    newest_block: String,
    percentiles_json: Option<String>,
) -> Result<Object<'env>> {
    let percentiles = percentiles_json.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(n), Ok(_)) = (c_arg(&newest_block), c_arg(&percentiles)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !safe_integer(block_count) {
            return invalid_params("blockCount must be an integer");
        }
        if bare_digits(&newest_block) {
            return invalid_params("a block number must be 0x-hex");
        }
        let p = match reward_percentiles(&percentiles).map(|p| c_arg(&p)) {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return NUL_INVALID_PARAMS.to_string(),
            Err(refusal) => return refusal,
        };
        take(unsafe { myotis_fee_history_json(handle, block_count as i64, n.as_ptr(), p.as_ptr()) })
    })
}

/// eth_getTransactionReceipt: the receipt JSON (verified against the block's
/// `receiptsRoot`), the literal `"null"` (verified not seen), or `{"error"}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_transaction_receipt_json<'env>(env: &'env Env, handle: i64, tx_hash: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        let Ok(h) = c_arg(&tx_hash) else { return NUL_INVALID_PARAMS.to_string() };
        if !hex_of_len(&tx_hash, 32) {
            return invalid_params("invalid transaction hash (expected 32-byte hex)");
        }
        take(unsafe { myotis_get_transaction_receipt_json(handle, h.as_ptr()) })
    })
}

/// eth_getBlockReceipts: the receipts ARRAY JSON, the literal `"null"` (an
/// unknown or future block, or a hash this node never verified), or
/// `{"error"}`. `selector` is a tag, a 0x-number or a 0x-hash; bare digits are
/// refused. The engine checks the rest of a selector only once the handle
/// runs, so on a paused handle a malformed one reports the pause first.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_block_receipts_json<'env>(env: &'env Env, handle: i64, selector: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        let Ok(s) = c_arg(&selector) else { return NUL_INVALID_PARAMS.to_string() };
        if bare_digits(&selector) {
            return invalid_params("a block number must be 0x-hex");
        }
        take(unsafe { myotis_get_block_receipts_json(handle, s.as_ptr()) })
    })
}

/// eth_getTransactionByHash: the transaction JSON (verified against the
/// block's `transactionsRoot`; this node's own unmined send reads as pending),
/// the literal `"null"` (verified not seen), or `{"error"}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_transaction_by_hash_json<'env>(env: &'env Env, handle: i64, tx_hash: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        let Ok(h) = c_arg(&tx_hash) else { return NUL_INVALID_PARAMS.to_string() };
        if !hex_of_len(&tx_hash, 32) {
            return invalid_params("invalid transaction hash (expected 32-byte hex)");
        }
        take(unsafe { myotis_get_transaction_by_hash_json(handle, h.as_ptr()) })
    })
}

/// eth_getCode: `{"codeHex", "verifyMethod", "failReason", …}`. Serve
/// `codeHex` only when `verifyMethod` is set: without a verdict it is no
/// answer (README). `block` (optional) is checked as for requestAccountJson:
/// omitted or a head tag proves at the verified head, `finalized` at the
/// beacon-finalized block, a number only inside [head-64, head+16].
#[napi(ts_return_type = "Promise<string>")]
pub fn get_code_json<'env>(env: &'env Env, handle: i64, address: String, block: Option<String>) -> Result<Object<'env>> {
    let block = block.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(a), Ok(b)) = (c_arg(&address), c_arg(&block)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !hex_of_len(&address, 20) {
            return invalid_params("invalid address (expected 20-byte hex)");
        }
        take(unsafe { myotis_get_code_json(handle, a.as_ptr(), b.as_ptr()) })
    })
}

/// eth_getStorageAt: `{"valueHex", "verifyMethod", "failReason", …}`, served
/// only with a verdict, as for getCodeJson. `position` is the slot as hex — a
/// short quantity such as `0x0` is padded to its 32-byte word; `block` is
/// checked as for getCodeJson.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_storage_at_json<'env>(
    env: &'env Env,
    handle: i64,
    address: String,
    position: String,
    block: Option<String>,
) -> Result<Object<'env>> {
    let block = block.unwrap_or_default();
    scheduler::submit(env, handle, move || {
        let (Ok(a), Ok(_), Ok(b)) = (c_arg(&address), c_arg(&position), c_arg(&block)) else {
            return NUL_INVALID_PARAMS.to_string();
        };
        if !hex_of_len(&address, 20) {
            return invalid_params("invalid address (expected 20-byte hex)");
        }
        let Some(Ok(p)) = storage_word(&position).map(|w| c_arg(&w)) else {
            return invalid_params("invalid storage position (expected hex of at most 32 bytes)");
        };
        take(unsafe { myotis_get_storage_at_json(handle, a.as_ptr(), p.as_ptr(), b.as_ptr()) })
    })
}

/// eth_getLogs over the opt-in log index (setLogIndexConfig,
/// importLogIndexFiles): the logs ARRAY JSON, served only inside the index's
/// verified coverage; anything else is an `{"error"}` that says how far
/// coverage reaches — never an empty array for a range the index has not
/// covered. A filter that cannot parse carries `"code":-32602`. The result is
/// not capped: a host serving untrusted pages bounds the range itself.
#[napi(ts_return_type = "Promise<string>")]
pub fn get_logs_json<'env>(env: &'env Env, handle: i64, filter_json: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || match c_arg(&filter_json) {
        Ok(f) => take(unsafe { myotis_get_logs_json(handle, f.as_ptr()) }),
        Err(_) => NUL_INVALID_PARAMS.to_string(),
    })
}

// ---------------------------------------------------------------------------
// The log index (#503): what eth_getLogs serves from
// ---------------------------------------------------------------------------
//
// These run on the request workers like the reads: installing a config or
// importing a snapshot takes the index's write lock, which its own appender or
// an import can hold for a while, and that must not block the JS thread. An
// import is neither bounded by the 90 s budget nor cancellable: it occupies its
// handle's one execution slot until it finishes, that handle's reads queue
// behind it, and `stop`/`pause` — synchronous on the JS thread — wait for it.

/// Install the watch-list config (docs/eth-getlogs-design.md; the JSON the
/// other hosts push). Resolves `{"ok":true}` when installed, `{"ok":false}`
/// when refused — invalid JSON, a watch entry without `address` or a numeric
/// `fromBlock`, an address listed twice, or a handle without a running EL
/// reader; the engine logs the config refusals (drainLogs).
#[napi(ts_return_type = "Promise<string>")]
pub fn set_log_index_config<'env>(env: &'env Env, handle: i64, config_json: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || match c_arg(&config_json) {
        Ok(c) => {
            let installed = unsafe { myotis_set_log_index_config(handle, c.as_ptr()) };
            format!(r#"{{"ok":{installed}}}"#)
        }
        Err(_) => NUL_INVALID_PARAMS.to_string(),
    })
}

/// The log index's status: whether it is on, its watch entries with their
/// verified coverage, the log count and the catch-up rate — what a host shows
/// and what decides whether an eth_getLogs range is served. It shares the
/// handle's execution slot with the reads, so a poll waits behind a slow one.
#[napi(ts_return_type = "Promise<string>")]
pub fn log_index_status_json<'env>(env: &'env Env, handle: i64) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || take(unsafe { myotis_log_index_status_json(handle) }))
}

/// Import portable log-index snapshots (`pathsJson`: a non-empty JSON array of
/// absolute file paths, each a self-describing snapshot of this handle's
/// chain), merged all or nothing; importing is the opt-in, and catch-up starts
/// at once. An imported file is its producer's claim, served as covered
/// without being re-verified (README). Resolves `{"ok":true,"status":…}` (the
/// status as logIndexStatusJson reports it) or `{"error"}`.
#[napi(ts_return_type = "Promise<string>")]
pub fn import_log_index_files<'env>(env: &'env Env, handle: i64, paths_json: String) -> Result<Object<'env>> {
    scheduler::submit(env, handle, move || {
        let Ok(p) = c_arg(&paths_json) else { return NUL_INVALID_PARAMS.to_string() };
        if !import_paths_ok(&paths_json) {
            return invalid_params("expected a non-empty JSON array of file paths");
        }
        take(unsafe { myotis_import_log_index_files(handle, p.as_ptr()) })
    })
}

// ---------------------------------------------------------------------------
// The pending nonce (#503; synchronous — an in-memory lookup)
// ---------------------------------------------------------------------------

/// eth_getTransactionCount at `"pending"`: `minedNonce` (the verified nonce at
/// the head, from requestAccountJson) raised to this node's own unmined
/// broadcast's nonce + 1 while that broadcast is unexpired, unchanged
/// otherwise. -1 for an unknown handle, a malformed address, or a `minedNonce`
/// that is not a non-negative safe integer: serve the plain mined nonce then.
#[napi]
pub fn pending_nonce_overlay(env: &Env, handle: i64, address_hex: String, mined_nonce: f64) -> i64 {
    let Some(mined) = nonce_arg(mined_nonce) else {
        return -1;
    };
    if !scheduler::owns(env, handle) {
        return -1;
    }
    match c_arg(&address_hex) {
        Ok(a) => unsafe { myotis_pending_nonce_overlay(handle, a.as_ptr(), mined) },
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_or_nonce_must_be_a_safe_integer() {
        for n in [1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 2f64.powi(53)] {
            assert!(!safe_integer(n), "{n}");
            assert_eq!(nonce_arg(n), None, "{n}");
        }
        assert!(safe_integer(4.0) && safe_integer(0.0) && safe_integer(-3.0));
        assert_eq!(nonce_arg(-1.0), None, "a nonce is never negative");
        assert_eq!(nonce_arg(7.0), Some(7));
        assert_eq!(nonce_arg(9_007_199_254_740_991.0), Some(9_007_199_254_740_991));
    }

    #[test]
    fn bare_digits_are_refused_and_tags_and_hex_are_not() {
        for s in ["23500000", " 42 ", "0"] {
            assert!(bare_digits(s), "{s}");
        }
        for s in ["0x166f9e0", "latest", "finalized", "", "  "] {
            assert!(!bare_digits(s), "{s}");
        }
    }

    #[test]
    fn hex_is_checked_as_the_engine_parses_it() {
        let addr = "11".repeat(20);
        for ok in [format!("0x{addr}"), format!("0X{addr}"), addr.clone()] {
            assert!(hex_of_len(&ok, 20), "{ok}");
        }
        assert!(!hex_of_len("0xdead", 20) && !hex_of_len(&format!("0x{addr}00"), 20));
        assert!(!hex_of_len(&format!("0x{}zz", "11".repeat(19)), 20), "a non-hex digit");
        assert!(!hex_of_len(&format!(" 0x{addr}"), 20), "no trimming, as the engine does none");
        assert!(hex_of_len(&format!("0x{}", "cd".repeat(32)), 32));
    }

    #[test]
    fn a_short_storage_position_is_padded_to_its_word() {
        assert_eq!(storage_word("0x0"), Some(format!("0x{}", "0".repeat(64))));
        assert_eq!(storage_word("0x1f"), Some(format!("0x{}1f", "0".repeat(62))));
        let full = "ab".repeat(32);
        assert_eq!(storage_word(&format!("0x{full}")), Some(format!("0x{full}")));
        for bad in ["0x", "", "0xzz", &format!("0x{full}00")] {
            assert_eq!(storage_word(bad), None, "{bad}");
        }
    }

    #[test]
    fn reward_percentiles_are_checked_as_the_routers_check_them() {
        assert_eq!(reward_percentiles("").as_deref(), Ok(""));
        assert_eq!(reward_percentiles("null").as_deref(), Ok(""));
        // geth answers no reward column for an empty list.
        assert_eq!(reward_percentiles(" [] ").as_deref(), Ok(""));
        assert_eq!(reward_percentiles("[25, 50, 50, 75]").as_deref(), Ok("[25,50,50,75]"));
        // Re-serialised, a list of long numerals fits the engine's 4 KiB bound.
        let long = format!("[{}]", vec!["50.000000000000000000000000000000000000001"; 100].join(","));
        assert!(long.len() > 4096);
        assert_eq!(reward_percentiles(&long).map(|p| p.len() <= 4096), Ok(true));
        for bad in ["[75, 25]", "[101]", "[-1]", "[\"50\"]", "{\"p\":1}", "not json", "[1e400]"] {
            let refusal = reward_percentiles(bad).expect_err(bad);
            assert!(refusal.contains("\"code\":-32602"), "{bad}: {refusal}");
        }
        let many = format!("[{}]", vec!["50"; 101].join(","));
        assert!(reward_percentiles(&many).is_err());
    }

    #[test]
    fn call_data_and_raw_transactions_are_checked_as_the_engine_parses_them() {
        for ok in ["0x", "", "0xdeadBEEF", "00ff"] {
            assert!(hex_bytes(ok), "{ok}");
        }
        for bad in ["0xabc", "0xzz", " 0x00", "0x0g"] {
            assert!(!hex_bytes(bad), "{bad}");
        }
        assert!(hex_bytes(&"ab".repeat(1024 * 1024)) && !hex_bytes(&"ab".repeat(1024 * 1024 + 1)));
    }

    #[test]
    fn a_value_is_decimal_wei_up_to_u256_max() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        for ok in ["0", "1000000000000000000", max, "1_000", "_", &format!("000{max}")] {
            assert!(decimal_u256(ok), "{ok}");
        }
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        for bad in [over, &format!("{max}0"), "0x10", "1e18", "-1", "+1", "1.5", " 1"] {
            assert!(!decimal_u256(bad), "{bad}");
        }
    }

    #[test]
    fn import_paths_must_be_a_non_empty_list_of_paths() {
        assert!(import_paths_ok(r#"["/a/logindex.db"]"#));
        for bad in ["[]", r#"[""]"#, r#"["  "]"#, "\"/a\"", "[1]", "nope"] {
            assert!(!import_paths_ok(bad), "{bad}");
        }
    }

    #[test]
    fn a_refusal_is_permanent_invalid_params_with_its_reason_escaped() {
        let why = "a \"quoted\" reason";
        let r: serde_json::Value = serde_json::from_str(&invalid_params(why)).unwrap();
        assert_eq!((r["error"].as_str(), r["code"].as_i64()), (Some(why), Some(-32602)));
    }
}
