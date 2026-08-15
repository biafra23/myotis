//! The UniFFI export surface for the JVM hosts (`:myotis-engines`' generated
//! Kotlin bindings + the `RustEngineNative` delegator).
//!
//! TRANSPORT SWAP ONLY: these functions mirror the old hand-JNI natives 1:1 —
//! compound values still cross as JSON strings with the exact shapes the golden
//! tests pin on both sides. What UniFFI replaces is the byte-shoveling layer:
//! no hand-written `JNIEnv` code, and the generated bindings verify a per-function
//! API checksum at load time, so a stale library fails loudly at initialization
//! instead of segfaulting on a reshaped symbol.
//!
//! Conventions carried over from the JNI shims:
//! - Panic-free by construction (the workspace builds `panic = "abort"`, so a
//!   panic aborts the host process — same contract as before). All fallible
//!   paths return sentinel values or `{"error": ...}` JSON.
//! - `Option<String>` where the old surface used null (unknown canonical name;
//!   the optional ERC-20 `holder`).
//! - The iOS plain C ABI in `capi.rs` shares the same `host`/`catalog`/`ringlog`
//!   internals and is deliberately NOT expressed through UniFFI.
//!
//! (`uniffi::setup_scaffolding!()` lives in lib.rs — the macro must run at the
//! crate root because `#[uniffi::export]` resolves its `UniFfiTag` there.)

/// ABI handshake: installs the ring-buffer tracing subscriber (idempotent) and
/// returns the compiled-in [`crate::ABI_VERSION`]. UniFFI's checksum validation
/// already guarantees signature compatibility; this coarse version remains for
/// the wrapper's log line and as a shared constant with the iOS C ABI.
#[uniffi::export]
pub fn engine_init() -> i32 {
    crate::ringlog::init();
    crate::ABI_VERSION
}

/// Up to `max` buffered engine tracing lines (oldest first, newline-joined;
/// empty when idle) — the drainable-ring end of the observability seam.
#[uniffi::export]
pub fn drain_logs(max: i32) -> String {
    crate::ringlog::drain(max.max(0) as usize)
}

/// The embedded network catalog as a JSON array of NetworkInfo objects
/// (camelCase keys, display order).
#[uniffi::export]
pub fn available_networks_json() -> String {
    crate::catalog::networks_json()
}

/// Canonical name for a name/alias, or None when unknown (the Java wrapper
/// raises `EngineException`).
#[uniffi::export]
pub fn canonical_network_name(name_or_alias: String) -> Option<String> {
    crate::catalog::canonical_network_name(&name_or_alias).map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Hosting surface. Sentinels unchanged: create returns the handle id (>= 1),
// -1 for unknown-name/runtime-init failure, -2 for canonical-but-unsupported.
// ---------------------------------------------------------------------------

/// Allocate a not-yet-started handle for `network` (R1: mainnet only).
#[uniffi::export]
pub fn create_handle(network: String, data_dir: String) -> i64 {
    crate::host::create(&network, &data_dir)
}

/// Start the sync loop for a created handle. True on success.
#[uniffi::export]
pub fn start_handle(handle: i64) -> bool {
    crate::host::start(handle)
}

/// Toggle Tor verified-read routing (docs/privacy-and-tor.md). Returns true iff
/// this build supports Tor (`--features tor`); a Tor-less build returns false and
/// no-ops. Process-global, not per-handle.
#[uniffi::export]
pub fn set_tor_enabled(on: bool) -> bool {
    crate::host::set_tor_enabled(on)
}

/// Tor status bitmask for the host Status view: bit0 compiled-in, bit1 enabled,
/// bit2 bootstrapped. `0` = this build has no Tor support.
#[uniffi::export]
pub fn tor_status() -> i32 {
    crate::host::tor_status()
}

/// One handle's status as a JSON object, or `"{}"` for an unknown handle.
#[uniffi::export]
pub fn status_json(handle: i64) -> String {
    crate::host::status_json(handle)
}

/// Remove and shut down a handle's sync loop. No-op for an unknown id.
#[uniffi::export]
pub fn stop_handle(handle: i64) {
    crate::host::stop(handle);
}

/// Idle-sleep a RUNNING handle. True ONLY on an actual RUNNING→PAUSED transition.
#[uniffi::export]
pub fn pause_handle(handle: i64) -> bool {
    crate::host::pause(handle)
}

/// Live-set the eth/69 served-block window (the Settings knob). Clamped to
/// [1, 4096]; applied immediately on a RUNNING handle's EL reader, stashed for
/// the next spin_up when the handle isn't running. False only for an unknown
/// handle.
#[uniffi::export]
pub fn set_served_block_window(handle: i64, blocks: i32) -> bool {
    crate::host::set_served_block_window(handle, blocks)
}

/// Rebuild networking for a PAUSED handle (warm start). True ONLY on an actual
/// PAUSED→RUNNING transition.
#[uniffi::export]
pub fn resume_handle(handle: i64) -> bool {
    crate::host::resume(handle)
}

// ---------------------------------------------------------------------------
// EL verified-read surface. Every function returns the same JSON payloads the
// JNI natives returned; `{"error": ...}` marks transport/not-running/bad-input
// failures the Java side raises as EngineException.
// ---------------------------------------------------------------------------

/// Verified account query (`AccountProofResult` shape). `address` is 0x-hex.
#[uniffi::export]
pub fn request_account_json(handle: i64, address: String) -> String {
    crate::host::request_account_json(handle, &address)
}

/// Verified storage-slot query (`StorageProofResult` shape). A non-None `holder`
/// selects the ERC-20 mapping key `keccak256(pad32(holder) ‖ uint256(slot))`.
#[uniffi::export]
pub fn get_storage_proof_json(
    handle: i64,
    address: String,
    slot: i64,
    holder: Option<String>,
) -> String {
    crate::host::get_storage_proof_json(handle, &address, slot, holder.as_deref())
}

/// Verified contract-code query (`eth_getCode`).
#[uniffi::export]
pub fn get_code_json(handle: i64, address: String) -> String {
    crate::host::get_code_json(handle, &address)
}

/// Verified RAW-32-byte-position storage query (`eth_getStorageAt`).
#[uniffi::export]
pub fn get_storage_at_json(handle: i64, address: String, position: String) -> String {
    crate::host::get_storage_at_json(handle, &address, &position)
}

/// Verified `eth_call` over the revm executor. `from` empty ⇒ anonymous call;
/// `to` EMPTY ⇒ contract creation (the calldata is init code, its return data
/// is the answer); `value` is wei as a decimal string; `block` is the RPC block
/// tag.
#[uniffi::export]
pub fn eth_call_json(
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
    block: String,
) -> String {
    crate::host::eth_call_json(handle, &from, &to, &data, &value, &block)
}

/// [`eth_call_json`] with an `eth_call` STATE OVERRIDE object (the JSON-RPC
/// third parameter) as a JSON string; empty ⇒ none. An empty `to` selects
/// contract creation here too. The overrides are the
/// caller's hypothesis layered over verified state for this call only, so the
/// answer is not a chain fact — hosts log it under a distinct label.
#[uniffi::export]
pub fn eth_call_overrides_json(
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
    block: String,
    state_overrides: String,
) -> String {
    crate::host::eth_call_overrides_json(handle, &from, &to, &data, &value, &block, &state_overrides)
}

/// Verified `eth_estimateGas` over the revm executor (verified head; no block arg).
#[uniffi::export]
pub fn estimate_gas_json(
    handle: i64,
    from: String,
    to: String,
    data: String,
    value: String,
) -> String {
    crate::host::estimate_gas_json(handle, &from, &to, &data, &value)
}

/// Verified ENS forward resolution (name → address record).
#[uniffi::export]
pub fn resolve_ens_json(handle: i64, name: String) -> String {
    crate::host::resolve_ens_json(handle, &name)
}

/// One generic ENS record dispatch; the method and its args travel in `params_json`.
#[uniffi::export]
pub fn ens_record_json(handle: i64, params_json: String) -> String {
    crate::host::ens_record_json(handle, &params_json)
}

/// Verified `eth_getBlockByNumber` (`full_transactions` selects decoded tx
/// objects over hashes). Returns the block JSON, the literal `"null"`, or
/// `{"error": ...}`.
#[uniffi::export]
pub fn get_block_by_number_json(handle: i64, block_tag: String, full_transactions: bool) -> String {
    crate::host::get_block_by_number_json(handle, &block_tag, full_transactions)
}

/// Verified fee suggestion (`eth_gasPrice` + `eth_maxPriorityFeePerGas`).
#[uniffi::export]
pub fn fee_estimate_json(handle: i64) -> String {
    crate::host::fee_estimate_json(handle)
}

/// Gossip a signed raw transaction; `{"txHash":"0x…"}` or `{"error": ...}`.
#[uniffi::export]
pub fn send_raw_transaction_json(handle: i64, raw_tx_hex: String) -> String {
    crate::host::send_raw_transaction_json(handle, &raw_tx_hex)
}

/// Verified `eth_getTransactionReceipt`. Returns the receipt JSON, the literal
/// `"null"` (verified "not seen"), or `{"error": ...}`.
#[uniffi::export]
pub fn get_transaction_receipt_json(handle: i64, tx_hash_hex: String) -> String {
    crate::host::get_transaction_receipt_json(handle, &tx_hash_hex)
}

/// The "pending" nonce overlay; negative only for malformed input / a missing
/// handle (the adapter then serves the plain mined nonce).
#[uniffi::export]
pub fn pending_nonce_overlay(handle: i64, address_hex: String, mined_nonce: i64) -> i64 {
    crate::host::pending_nonce_overlay(handle, &address_hex, mined_nonce)
}

/// Verified `eth_getTransactionByHash`. Returns the tx JSON, the literal
/// `"null"` (verified "not seen"), or `{"error": ...}`.
#[uniffi::export]
pub fn get_transaction_by_hash_json(handle: i64, tx_hash_hex: String) -> String {
    crate::host::get_transaction_by_hash_json(handle, &tx_hash_hex)
}

/// Verified `eth_getBlockByHash` (hashes this engine has already verified).
#[uniffi::export]
pub fn get_block_by_hash_json(handle: i64, block_hash_hex: String, full_transactions: bool) -> String {
    crate::host::get_block_by_hash_json(handle, &block_hash_hex, full_transactions)
}

/// Verified `eth_getBlockReceipts` for a tag / 0x-number / 0x-32-byte-hash selector.
#[uniffi::export]
pub fn get_block_receipts_json(handle: i64, selector: String) -> String {
    crate::host::get_block_receipts_json(handle, &selector)
}

/// Verified `eth_feeHistory`. `percentiles_json` is a JSON array of reward
/// percentiles, or empty to omit the reward matrix.
#[uniffi::export]
pub fn fee_history_json(
    handle: i64,
    block_count: i64,
    newest_block_tag: String,
    percentiles_json: String,
) -> String {
    crate::host::fee_history_json(handle, block_count, &newest_block_tag, &percentiles_json)
}

/// eth_getLogs over the opt-in watch-list index: the log array on success,
/// `{"error": ...}` otherwise — including for any range outside indexed
/// coverage (never an empty array for unindexed blocks).
#[uniffi::export]
pub fn get_logs_json(handle: i64, filter_json: String) -> String {
    crate::host::get_logs_json(handle, &filter_json)
}

/// Install the log-index watch-list config (JSON; see host docs). False on
/// malformed config, duplicate addresses, or an unavailable reader.
#[uniffi::export]
pub fn set_log_index_config(handle: i64, config_json: String) -> bool {
    crate::host::set_log_index_config_json(handle, &config_json)
}

/// Log-index status JSON: enabled flag, log count, backfill cursor, and per
/// watch entry its covered span.
#[uniffi::export]
pub fn log_index_status_json(handle: i64) -> String {
    crate::host::log_index_status_json(handle)
}

/// Import portable log-index snapshots (JSON array of absolute file paths;
/// each file must be a self-describing snapshot of this handle's chain).
/// All-or-nothing merge into the node's index; importing is the opt-in, so
/// catch-up starts immediately. `{"ok":true,"status":…}` or `{"error":…}`.
#[uniffi::export]
pub fn import_log_index_files(handle: i64, paths_json: String) -> String {
    crate::host::import_log_index_files(handle, &paths_json)
}

/// Export the current log index as a portable snapshot file (the generator's
/// output; finality-clamped, self-describing). `{"ok":true}` or `{"error":…}`.
#[uniffi::export]
pub fn export_log_index(handle: i64, path: String) -> String {
    crate::host::export_log_index(handle, &path)
}
