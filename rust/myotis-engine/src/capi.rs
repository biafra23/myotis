//! Plain C ABI over the same `host` functions the JNI shim wraps — the iOS
//! (Kotlin/Native cinterop) seam. Mirrors the JVM FFI surface (`ffi`, UniFFI)
//! one-to-one: compound values
//! cross as JSON strings with the exact same shapes the golden tests pin, and the
//! sentinel conventions are identical (negative handle ids, `"{}"` status for an
//! unknown handle, `{"error": ...}` objects). The header consumed by cinterop is
//! `rust/include/myotis_engine.h` — keep both in sync and bump `ABI_VERSION` on
//! any shape change (`myotis_init` is the handshake, exactly like `nativeInit`).
//!
//! Memory contract: every `*mut c_char` this module returns is owned by the
//! caller and MUST be released via `myotis_string_free` (it is a `CString`
//! allocated by Rust — freeing it with `free(3)` is undefined behavior).
//!
//! Panic-freedom matters as much as in the JNI shim: the workspace builds with
//! `panic = "abort"`, so any panic kills the host app. Every failure path here
//! returns a sentinel (null / false / -1) instead of unwrapping.

use std::ffi::{c_char, CStr, CString};

/// Read a C string into an owned Rust `String`. Null → `None`; invalid UTF-8 is
/// replaced lossily (panic-free) rather than rejected — same spirit as the JNI
/// shim's `read_string`, which tolerates whatever the JVM hands it.
///
/// # Safety
/// `p` must be null or a valid null-terminated C string.
unsafe fn read_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    Some(CStr::from_ptr(p).to_string_lossy().into_owned())
}

/// Hand a Rust `String` to the caller as a `CString`. Interior NUL bytes cannot
/// occur in the engine's JSON/log output, but if one ever did, return null
/// instead of panicking (the caller already treats null as unavailable).
fn into_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The availability + ABI handshake (`nativeInit` twin). Installs the tracing
/// subscriber feeding the drainable ring (idempotent) and returns `ABI_VERSION`;
/// hosts must refuse to call anything else if the value doesn't match the header
/// they compiled against.
#[no_mangle]
pub extern "C" fn myotis_init() -> i32 {
    crate::ringlog::init();
    crate::ABI_VERSION
}

/// Up to `max` buffered tracing lines, oldest first, newline-joined; empty
/// string when idle (`nativeDrainLogs` twin). Free with `myotis_string_free`.
#[no_mangle]
pub extern "C" fn myotis_drain_logs(max: i32) -> *mut c_char {
    into_c(crate::ringlog::drain(max.max(0) as usize))
}

/// The embedded catalog as a JSON array of `NetworkInfo` objects
/// (`nativeAvailableNetworksJson` twin).
#[no_mangle]
pub extern "C" fn myotis_available_networks_json() -> *mut c_char {
    into_c(crate::catalog::networks_json())
}

/// Canonical network name, or null for an unknown network
/// (`nativeCanonicalNetworkName` twin).
///
/// # Safety
/// `name_or_alias` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_canonical_network_name(
    name_or_alias: *const c_char,
) -> *mut c_char {
    let Some(input) = read_string(name_or_alias) else {
        return std::ptr::null_mut();
    };
    match crate::catalog::canonical_network_name(&input) {
        Some(canonical) => into_c(canonical.to_owned()),
        None => std::ptr::null_mut(),
    }
}

/// Allocate a not-yet-started handle id (`nativeCreate` twin). Returns the id
/// (≥ 1), or a negative sentinel: -1 for an unknown name / runtime-init
/// failure, -2 for a canonical-but-unsupported network.
///
/// # Safety
/// Both pointers must be null or valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn myotis_create(
    network: *const c_char,
    data_dir: *const c_char,
) -> i64 {
    let Some(network) = read_string(network) else {
        return -1;
    };
    let data_dir = read_string(data_dir).unwrap_or_default();
    crate::host::create(&network, &data_dir)
}

/// Start the sync loop (`nativeStart` twin). True on success; false for an
/// unknown / already-running handle or a start error.
#[no_mangle]
pub extern "C" fn myotis_start(handle: i64) -> bool {
    crate::host::start(handle)
}

/// Toggle Tor verified-read routing (`set_tor_enabled` twin,
/// docs/privacy-and-tor.md). Returns true iff this build supports Tor
/// (`--features tor`); a Tor-less build returns false and no-ops.
#[no_mangle]
pub extern "C" fn myotis_set_tor_enabled(on: bool) -> bool {
    crate::host::set_tor_enabled(on)
}

/// Tor status bitmask (`tor_status` twin): bit0 compiled-in, bit1 enabled,
/// bit2 bootstrapped. `0` = this build has no Tor support.
#[no_mangle]
pub extern "C" fn myotis_tor_status() -> i32 {
    crate::host::tor_status()
}

/// One handle's status as a JSON object, or `"{}"` for an unknown handle
/// (`nativeStatusJson` twin).
#[no_mangle]
pub extern "C" fn myotis_status_json(handle: i64) -> *mut c_char {
    into_c(crate::host::status_json(handle))
}

/// Remove + shut down the sync loop; no-op for an unknown id (`nativeStop` twin).
#[no_mangle]
pub extern "C" fn myotis_stop(handle: i64) {
    crate::host::stop(handle);
}

/// Idle-sleep: tear down networking, keep the handle PAUSED (`nativePause` twin).
/// True ONLY on an actual Running→Paused transition.
#[no_mangle]
pub extern "C" fn myotis_pause(handle: i64) -> bool {
    crate::host::pause(handle)
}

/// Live-set the eth/69 served-block window (`nativeSetServedBlockWindow` twin).
/// Clamped to [1, 4096]; stashed for spin_up when the handle isn't running.
/// False only for an unknown handle.
#[no_mangle]
pub extern "C" fn myotis_set_served_block_window(handle: i64, blocks: i32) -> bool {
    crate::host::set_served_block_window(handle, blocks)
}

/// Rebuild networking for a paused handle (`nativeResume` twin). False when the
/// rebuild failed (handle stays PAUSED, retryable) or the handle isn't paused.
#[no_mangle]
pub extern "C" fn myotis_resume(handle: i64) -> bool {
    crate::host::resume(handle)
}

/// Verified account read (`nativeRequestAccountJson` twin). Blocking — may take
/// up to ~90 s for a header-chain walk; never call from the UI thread.
///
/// # Safety
/// `address` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_request_account_json(
    handle: i64,
    address: *const c_char,
) -> *mut c_char {
    let address = read_string(address).unwrap_or_default();
    into_c(crate::host::request_account_json(handle, &address))
}

/// Verified storage proof (`nativeGetStorageProofJson` twin). A null `holder`
/// is the plain-slot lookup. Blocking, same bound as the account read.
///
/// # Safety
/// `address` and `holder` must each be null or valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_storage_proof_json(
    handle: i64,
    address: *const c_char,
    slot: i64,
    holder: *const c_char,
) -> *mut c_char {
    let address = read_string(address).unwrap_or_default();
    let holder = read_string(holder);
    into_c(crate::host::get_storage_proof_json(
        handle,
        &address,
        slot,
        holder.as_deref(),
    ))
}

/// Verified `eth_getCode` (`nativeGetCodeJson` twin).
///
/// # Safety
/// `address` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_code_json(
    handle: i64,
    address: *const c_char,
) -> *mut c_char {
    let address = read_string(address).unwrap_or_default();
    into_c(crate::host::get_code_json(handle, &address))
}

/// Verified `eth_getStorageAt` with a RAW 32-byte position
/// (`nativeGetStorageAtJson` twin).
///
/// # Safety
/// `address` and `position` must each be null or valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_storage_at_json(
    handle: i64,
    address: *const c_char,
    position: *const c_char,
) -> *mut c_char {
    let address = read_string(address).unwrap_or_default();
    let position = read_string(position).unwrap_or_default();
    into_c(crate::host::get_storage_at_json(handle, &address, &position))
}

/// Verified `eth_call` over the revm executor (`nativeEthCallJson` twin).
/// `from` empty ⇒ anonymous sender; `value` is wei as a decimal string.
///
/// # Safety
/// All pointer params must be null or valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn myotis_eth_call_json(
    handle: i64,
    from: *const c_char,
    to: *const c_char,
    data: *const c_char,
    value: *const c_char,
    block: *const c_char,
) -> *mut c_char {
    let from = read_string(from).unwrap_or_default();
    let to = read_string(to).unwrap_or_default();
    let data = read_string(data).unwrap_or_default();
    let value = read_string(value).unwrap_or_default();
    let block = read_string(block).unwrap_or_default();
    into_c(crate::host::eth_call_json(
        handle, &from, &to, &data, &value, &block,
    ))
}

/// Verified `eth_estimateGas` over the revm executor (`nativeEstimateGasJson`
/// twin; runs against the verified head — no block arg).
///
/// # Safety
/// All pointer params must be null or valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn myotis_estimate_gas_json(
    handle: i64,
    from: *const c_char,
    to: *const c_char,
    data: *const c_char,
    value: *const c_char,
) -> *mut c_char {
    let from = read_string(from).unwrap_or_default();
    let to = read_string(to).unwrap_or_default();
    let data = read_string(data).unwrap_or_default();
    let value = read_string(value).unwrap_or_default();
    into_c(crate::host::estimate_gas_json(
        handle, &from, &to, &data, &value,
    ))
}

/// Verified ENS forward resolution (`nativeResolveEnsJson` twin).
///
/// # Safety
/// `name` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_resolve_ens_json(
    handle: i64,
    name: *const c_char,
) -> *mut c_char {
    let name = read_string(name).unwrap_or_default();
    into_c(crate::host::resolve_ens_json(handle, &name))
}

/// Generic ENS record dispatch — method + args travel in `params_json`
/// (`nativeEnsRecordJson` twin).
///
/// # Safety
/// `params_json` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_ens_record_json(
    handle: i64,
    params_json: *const c_char,
) -> *mut c_char {
    let params = read_string(params_json).unwrap_or_default();
    into_c(crate::host::ens_record_json(handle, &params))
}

/// Verified `eth_getBlockByNumber` (`nativeGetBlockByNumberJson` twin);
/// `full_transactions` selects decoded tx objects over hashes. Returns the
/// block JSON, the literal `"null"`, or `{"error": ...}`.
///
/// # Safety
/// `block_tag` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_block_by_number_json(
    handle: i64,
    block_tag: *const c_char,
    full_transactions: bool,
) -> *mut c_char {
    let block_tag = read_string(block_tag).unwrap_or_default();
    into_c(crate::host::get_block_by_number_json(
        handle,
        &block_tag,
        full_transactions,
    ))
}

/// The pending-tag nonce overlay (`nativePendingNonceOverlay` twin):
/// `max(mined_nonce, our broadcast nonce + 1)` while the wallet's own tx is
/// unmined+unexpired, identity otherwise; negative for malformed input (the
/// host serves the plain mined nonce).
///
/// # Safety
/// `address_hex` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_pending_nonce_overlay(
    handle: i64,
    address_hex: *const c_char,
    mined_nonce: i64,
) -> i64 {
    let address_hex = read_string(address_hex).unwrap_or_default();
    crate::host::pending_nonce_overlay(handle, &address_hex, mined_nonce)
}

/// Verified `eth_getTransactionReceipt` (`nativeGetTransactionReceiptJson`
/// twin). Returns the receipt JSON, the literal `"null"` (verified "not seen"
/// — pending/unknown), or `{"error": ...}`.
///
/// # Safety
/// `tx_hash_hex` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_transaction_receipt_json(
    handle: i64,
    tx_hash_hex: *const c_char,
) -> *mut c_char {
    let tx_hash_hex = read_string(tx_hash_hex).unwrap_or_default();
    into_c(crate::host::get_transaction_receipt_json(handle, &tx_hash_hex))
}

/// Verified `eth_getTransactionByHash` (`nativeGetTransactionByHashJson`
/// twin). Returns the tx JSON, the literal `"null"` (verified "not seen" —
/// unknown/pending), or `{"error": ...}`.
///
/// # Safety
/// `tx_hash_hex` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_transaction_by_hash_json(
    handle: i64,
    tx_hash_hex: *const c_char,
) -> *mut c_char {
    let tx_hash_hex = read_string(tx_hash_hex).unwrap_or_default();
    into_c(crate::host::get_transaction_by_hash_json(handle, &tx_hash_hex))
}

/// Verified `eth_getBlockByHash` (`nativeGetBlockByHashJson` twin);
/// `full_transactions` selects decoded tx objects over hashes. Returns the
/// block JSON, the literal `"null"` (a hash this engine never verified), or
/// `{"error": ...}`.
///
/// # Safety
/// `block_hash_hex` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_block_by_hash_json(
    handle: i64,
    block_hash_hex: *const c_char,
    full_transactions: bool,
) -> *mut c_char {
    let block_hash_hex = read_string(block_hash_hex).unwrap_or_default();
    into_c(crate::host::get_block_by_hash_json(
        handle,
        &block_hash_hex,
        full_transactions,
    ))
}

/// Verified fee estimate: `{"gasPriceWei","maxPriorityFeePerGasWei"}` or
/// `{"error": ...}` (`nativeFeeEstimateJson` twin).
#[no_mangle]
pub extern "C" fn myotis_fee_estimate_json(handle: i64) -> *mut c_char {
    into_c(crate::host::fee_estimate_json(handle))
}

/// Verified `eth_getBlockReceipts` (`nativeGetBlockReceiptsJson` twin).
/// `selector` is a tag, a 0x-hex block number, or a 0x-32-byte block hash.
/// Returns the receipts array JSON, the literal `"null"` (verified
/// unknown/future block or never-verified hash), or `{"error": ...}`.
///
/// # Safety
/// `selector` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_block_receipts_json(
    handle: i64,
    selector: *const c_char,
) -> *mut c_char {
    let selector = read_string(selector).unwrap_or_default();
    into_c(crate::host::get_block_receipts_json(handle, &selector))
}

/// Verified `eth_feeHistory` (`nativeFeeHistoryJson` twin). `percentiles_json`
/// is a JSON array of reward percentiles, or null/empty to omit the reward
/// matrix. Returns the feeHistory JSON or `{"error": ...}`.
///
/// # Safety
/// `newest_block_tag` and `percentiles_json` must each be null or valid
/// null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn myotis_fee_history_json(
    handle: i64,
    block_count: i64,
    newest_block_tag: *const c_char,
    percentiles_json: *const c_char,
) -> *mut c_char {
    let newest_block_tag = read_string(newest_block_tag).unwrap_or_default();
    let percentiles_json = read_string(percentiles_json).unwrap_or_default();
    into_c(crate::host::fee_history_json(
        handle,
        block_count,
        &newest_block_tag,
        &percentiles_json,
    ))
}

/// Gossip a signed raw tx: `{"txHash":"0x…"}` or `{"error": ...}`
/// (`nativeSendRawTransactionJson` twin).
///
/// # Safety
/// `raw_tx_hex` must be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_send_raw_transaction_json(
    handle: i64,
    raw_tx_hex: *const c_char,
) -> *mut c_char {
    let raw_tx_hex = read_string(raw_tx_hex).unwrap_or_default();
    into_c(crate::host::send_raw_transaction_json(handle, &raw_tx_hex))
}

/// Release a string previously returned by any `myotis_*` function. Null is a
/// no-op.
///
/// # Safety
/// `s` must be null or a pointer previously returned by this module and not yet
/// freed. Passing anything else (including a pointer freed twice) is undefined
/// behavior.
#[no_mangle]
pub unsafe extern "C" fn myotis_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip an owned C string back into Rust for assertions, freeing it
    /// through the public contract.
    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = CStr::from_ptr(p).to_string_lossy().into_owned();
        myotis_string_free(p);
        s
    }

    #[test]
    fn init_reports_the_shared_abi_version() {
        assert_eq!(myotis_init(), crate::ABI_VERSION);
    }

    /// The hand-maintained C header is the contract for the plain-ABI consumers
    /// (:app-ios via cinterop, the napi loader), and its version is what they
    /// gate on — so it has to name the same number as the crate constant. The
    /// `include_str!` makes the header a compile input of this test: bumping
    /// `ABI_VERSION` without touching the header fails `cargo test` (wired into
    /// the root Gradle `check`) instead of shipping a header that tells C
    /// consumers to refuse a perfectly good engine.
    #[test]
    fn header_pins_the_current_abi_version() {
        const HEADER: &str = include_str!("../../include/myotis_engine.h");
        let declared: i32 = HEADER
            .lines()
            .find_map(|l| l.trim().strip_prefix("#define MYOTIS_ABI_VERSION "))
            .expect("rust/include/myotis_engine.h must #define MYOTIS_ABI_VERSION")
            .trim()
            .parse()
            .expect("MYOTIS_ABI_VERSION must be a plain integer literal");
        assert_eq!(
            declared,
            crate::ABI_VERSION,
            "rust/include/myotis_engine.h declares MYOTIS_ABI_VERSION {declared} but \
             crate::ABI_VERSION is {}. Update the header, and check the host mirrors \
             too: RustEngineNative.EXPECTED_ABI_VERSION (myotis-engines) and \
             RustEngine.EXPECTED_ABI_VERSION (app-ios).",
            crate::ABI_VERSION
        );
    }

    #[test]
    fn catalog_crosses_the_c_boundary_verbatim() {
        let json = unsafe { take(myotis_available_networks_json()) };
        assert_eq!(json, crate::catalog::networks_json());
    }

    #[test]
    fn canonical_name_resolves_aliases_and_rejects_unknowns() {
        let mainnet = CString::new("Mainnet").unwrap();
        let got = unsafe { take(myotis_canonical_network_name(mainnet.as_ptr())) };
        assert_eq!(got, "mainnet");

        let bogus = CString::new("no-such-network").unwrap();
        assert!(unsafe { myotis_canonical_network_name(bogus.as_ptr()) }.is_null());
        assert!(unsafe { myotis_canonical_network_name(std::ptr::null()) }.is_null());
    }

    #[test]
    fn null_inputs_hit_sentinels_not_crashes() {
        assert_eq!(unsafe { myotis_create(std::ptr::null(), std::ptr::null()) }, -1);
        assert!(!myotis_start(0));
        assert_eq!(unsafe { take(myotis_status_json(0)) }, "{}");
        myotis_stop(0); // unknown id: must be a silent no-op
        unsafe { myotis_string_free(std::ptr::null_mut()) };
    }
}

/// eth_getLogs over the watch-list index (see ffi::get_logs_json).
/// Returned string must be freed with `myotis_string_free`.
#[no_mangle]
pub unsafe extern "C" fn myotis_get_logs_json(
    handle: i64,
    filter_json: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    match read_string(filter_json) {
        Some(f) => into_c(crate::host::get_logs_json(handle, &f)),
        None => std::ptr::null_mut(),
    }
}

/// Install the log-index watch-list config (see ffi::set_log_index_config).
#[no_mangle]
pub unsafe extern "C" fn myotis_set_log_index_config(
    handle: i64,
    config_json: *const std::os::raw::c_char,
) -> bool {
    match read_string(config_json) {
        Some(c) => crate::host::set_log_index_config_json(handle, &c),
        None => false,
    }
}

/// Log-index status JSON (see ffi::log_index_status_json).
/// Returned string must be freed with `myotis_string_free`.
#[no_mangle]
pub unsafe extern "C" fn myotis_log_index_status_json(handle: i64) -> *mut std::os::raw::c_char {
    into_c(crate::host::log_index_status_json(handle))
}
