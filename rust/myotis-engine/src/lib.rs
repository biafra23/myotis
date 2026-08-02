//! The Rust implementation of the `io.myotis.api` engine contract, exposed to the
//! JVM via UniFFI (`ffi` — generated Kotlin bindings live in `:myotis-engines`;
//! compound records still cross as JSON, see the phase-1 plan and
//! docs/reimplementation/05). The old hand-JNI shims are gone; the iOS hosts keep
//! consuming the plain C ABI in `capi`.
//!
//! R1 (this stage): the network CATALOG is answered from Rust (`engine_init` ABI
//! handshake, `available_networks_json`, `canonical_network_name`) AND the
//! engine can HOST mainnet — `create_handle`/`start_handle`/`status_json`/
//! `stop_handle` drive a `myotis_net::SyncHandle` (the light-client sync loop) on a
//! tokio runtime this crate owns (see `host`). R1 is CL-only + mainnet-only; Gnosis
//! and the EL surface land later.

// Public: the plain C ABI doubles as the in-process seam for Rust hosts (the
// napi-rs Node binding in `myotis-node` calls these by Rust path — linking the
// rlib does not reliably resolve `extern "C"` imports of no_mangle symbols).
pub mod capi;
pub mod catalog;
mod eljson;
pub mod ffi;
mod host;
pub mod ringlog;

// UniFFI scaffolding (checksums, FFI glue) for the `ffi` exports; must be invoked
// at the crate root — `#[uniffi::export]` resolves its `UniFfiTag` here.
uniffi::setup_scaffolding!();

/// Bumped whenever the FFI surface changes shape. On the JVM this is now a
/// belt-and-braces guard: UniFFI's generated bindings verify a per-function API
/// checksum at load time (a stale .so fails initialization loudly), and the
/// wrapper's availability probe (`engine_init`) additionally compares this coarse
/// version for its log line. The iOS C ABI (`capi`) still relies on it directly.
///
/// (History below predates the UniFFI swap — the `nativeXxx` names refer to the
/// deleted hand-JNI natives; today's equivalents live in `ffi.rs`.)
///
/// v2: added the hosting surface (nativeCreate/Start/StatusJson/Stop).
/// v4: added the EL verified-read surface (nativeRequestAccountJson,
///     nativeGetStorageProofJson), wired into the Java RustEngineNative /
///     RustChainHandle at the same time so no .so ever reports an ABI the
///     running Java engine treats as stale.
/// v9: added nativeEthCallJson (eth_call over verified state via the revm executor).
/// v10: added nativeEstimateGasJson (eth_estimateGas over the revm executor).
/// v11: added nativeResolveEnsJson (ENS forward resolution over verified eth_calls).
/// v12: added nativeEnsRecordJson (all ENS record types + reverse + root modes,
///      one generic dispatch — EL-C-5-2).
/// v13: added the idle-sleep surface (nativePause/nativeResume) and the
///      `paused` key in the status JSON, wired into the Java RustEngineNative /
///      RustChainHandle at the same time.
/// v14: added nativeGetTransactionReceiptJson (verified eth_getTransactionReceipt
///      over the incremental beacon-anchored tx scan).
/// v15: added nativeGetTransactionByHashJson + nativeGetBlockByHashJson (the
///      wallet's post-receipt confirm loop; the same locate machinery + the
///      verified block-hash→number map).
/// v16: added nativeFeeHistoryJson (verified eth_feeHistory: anchored header
///      window + gas-used-weighted reward percentiles from verified bodies and
///      receipts).
/// v17: added nativeGetBlockReceiptsJson (verified eth_getBlockReceipts — one
///      anchored block's whole receipt list, body + receipts root-verified).
/// v18: nativeGetBlockByNumberJson + nativeGetBlockByHashJson gained a
///      `boolean fullTransactions` parameter (fullTransactions=true blocks now
///      served natively: decoded tx objects instead of hashes).
/// v19: added nativePendingNonceOverlay (the sent-tx slice: pending-tag nonce
///      overlay); nativeGetTransactionByHashJson may now return the PENDING
///      shape (block trio explicitly null) for the wallet's own broadcasts —
///      a payload extension, no signature change there.
/// v20: added the Tor toggle surface (set_tor_enabled/tor_status, UniFFI +
///      the iOS C ABI; docs/privacy-and-tor.md). The functions exist in every
///      build; a dylib compiled without `--features tor` reports "not supported"
///      (false / 0) rather than being absent.
/// v21: added get_logs_json / set_log_index_config / log_index_status_json
///      (the opt-in eth_getLogs watch-list index, docs/eth-getlogs-design.md).
pub const ABI_VERSION: i32 = 21;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;
