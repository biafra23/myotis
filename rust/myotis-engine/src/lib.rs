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
/// v22: added set_served_block_window (live per-handle eth/69 served-block
///      window — the Settings knob, previously a no-op on Rust chains).
/// v23: nativeEstimateGasJson may now return `{"status":"revert","dataHex"}`
///      for an estimated transaction that reverts (a verified answer the host
///      serves as JSON-RPC code 3) — a payload extension, no signature change.
/// v24: added import_log_index_files + export_log_index (portable log-index
///      snapshots: the generic import/export path, docs/eth-getlogs-design.md).
///      set_log_index_config became ADDITIVE (unions with the stored
///      subscription set) — a behavior change, no signature change.
/// v25: added set_ws_bound_periods + accept_stale_anchor (the weak-subjectivity
///      anchor-age gate: STALE_ANCHOR beaconState + wsBoundPeriods status key;
///      a too-old sync anchor now parks fail-closed awaiting consent).
/// v26: added create_with_checkpoint (bootstrap from a CALLER-supplied beacon
///      root + slot, #441; the dataDir records the anchor in
///      `sync-anchor[-net].json` and resumes only that generation). `create`
///      gained the -3 ANCHOR_MISMATCH sentinel for a marked dataDir.
/// v27: eth_call_json / eth_call_overrides_json now CHECK their `block`
///      argument (#452): a number outside [head-64, head+16] is refused, never
///      answered from the head — permanently (`{"error","code":-32602}`, a new
///      envelope key) when it is behind the window or not a servable selector
///      at all. A behavior change and a payload extension, no signature change.
/// v28: added read_stats_json (UniFFI + the iOS C ABI): the read-fetch shadow
///      cache's counters (docs/read-stats.md) — a measurement surface, no
///      serving change.
/// v29: myotis_eth_call_json refuses a NULL `to` instead of reading it as the
///      EMPTY `to` that means CONTRACT CREATION — running the caller's
///      calldata as init code was a different question than the one asked.
///      Its overrides twin already refused it, and both now name the null
///      pointer in the refusal message instead of an "undecodable string".
///      Plain-C callers only (the Node and iOS bindings never pass NULL); a
///      behavior change, no signature change.
/// v30: eth_call_json / eth_call_overrides_json and the block-read selectors
///      (get_block_by_number_json, get_block_receipts_json, fee_history_json)
///      now HONOUR `finalized` (#465, #366): the call runs against the
///      beacon-finalized block and the block reads serve it, instead of the
///      optimistic head. The call envelope gained `blockNumber` and
///      `verified` (= ran against the finalized block), naming the block that
///      answered (#382; `verified` is false on `unavailable`, which ran
///      nowhere). `safe` and `pending` still resolve to the head —
///      documented, not silent — and so does `finalized` on the JVM hosts'
///      state reads and on the Java engine (#366). A behavior change and a
///      payload extension, no signature change.
/// v31: added myotis_set_boot_enodes (C ABI + Node; no UniFFI export — the
///      JVM hosts have no seed-pin surface yet, so ffi.rs is untouched):
///      host-supplied EL seed pins, a JSON array of enode:// URLs applied or
///      refused AS A WHOLE (#465). The status JSON gained `snapServingPeers`,
///      the pooled peers that can answer a read at the anchored head now —
///      what the hosts' readiness gates use in place of `snapPeers`, which a
///      pool of still-syncing peers satisfies for hours while every read
///      fails. A key addition; older wrappers ignore it.
pub const ABI_VERSION: i32 = 31;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;
