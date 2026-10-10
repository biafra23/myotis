//! The Rust implementation of the `io.myotis.api` engine contract, exposed to the
//! JVM via UniFFI (`ffi` — generated Kotlin bindings live in `:myotis-engines`;
//! compound records still cross as JSON, see the phase-1 plan and
//! docs/reimplementation/05). The old hand-JNI shims are gone; the iOS hosts keep
//! consuming the plain C ABI in `capi`.
//!
//! The network CATALOG is answered from Rust (`engine_init` ABI handshake,
//! `available_networks_json`, `canonical_network_name`) and the engine HOSTS
//! mainnet, Sepolia and Gnosis — `create_handle`/`start_handle`/`status_json`/
//! `stop_handle` drive a `myotis_net::SyncHandle` (the light-client sync loop) and
//! the EL reader on a tokio runtime this crate owns (see `host`). The verified
//! reads, the EVM (`eth_call`/`eth_estimateGas`), ENS, the fee reads, transaction
//! broadcast, the log index, read-stats and Tor are exported beside them (`ffi`,
//! `capi`); the per-function history is the ABI table in `rust/include/myotis_engine.h`.

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
/// v32: request_account_json / get_code_json / get_storage_at_json (UniFFI and
///      the C ABI) take the RPC block selector and APPLY OR REFUSE it, as
///      eth_call has since v27 (#465, #366): `finalized` proves the snap proof
///      at the beacon-finalized state root (no fallback to any other root —
///      refused, retryably, while no finalized block has landed or no peer
///      still serves it), a number is served from head state only inside the
///      window around the head, anything else is -32602. The three result
///      shapes gained `anchor` ("head" | "finalized"). A signature change on
///      three functions; the JVM `RustEngineNative` wrappers, the Node addon
///      and the iOS wrapper moved with it. The `io.myotis.api` state reads
///      still have no block parameter, and the Java engine still maps
///      `finalized` to the head (#366).
/// v33: eth_call_json / eth_call_overrides_json / estimate_gas_json may return
///      the permanent `{"error","code":-32602}` envelope for an executor
///      REFUSAL — today a header and fork table that disagree about Amsterdam:
///      an Amsterdam block whose header lacks EIP-7843's `slot_number` (refused
///      rather than run with SLOTNUM = 0), or a `slot_number` on a block the
///      table puts before Amsterdam (refused rather than run under the older
///      fork's rules). And on a Gloas network the status JSON's beacon state
///      is SYNCED only once the finalized execution header has been fetched
///      and verified by hash (a Gloas light-client header proves only the
///      block hash). Behavior changes, no signature change.
/// v34: added estimate_gas_tx_json (UniFFI, the C ABI and Node, #509):
///      eth_estimateGas for the FULL JSON-RPC transaction object — EIP-7702
///      authorizations, access list, gas, fees, nonce, type — with the block
///      selector and a state override, every field applied or the request
///      refused (-32602). The estimate JSON gained
///      `{"status":"infeasible","reason"}` for a transaction that does not fit
///      the caller's gas or funds (geth's -32000 answer, served verbatim),
///      which estimate_gas_json can now return too, for an estimate that runs
///      out of gas at its 30 M ceiling (it used to be `unavailable`). The JVM
///      `RustEngineNative` wrappers, the Node addon and the iOS wrapper moved
///      with it.
/// v35: added eth_call_tx_json (UniFFI, the C ABI and Node, #509): eth_call
///      for the FULL JSON-RPC transaction object, every field applied as
///      estimate_gas_tx_json applies it — `gas` as the call's limit (capped at
///      the 30 M call budget, as geth caps at its RPC gas cap), a fee checked
///      against the base fee and charged to the sender, EIP-7702
///      authorizations, access list, nonce — or the request refused (-32602).
///      The call JSON gained `{"status":"infeasible","reason"}` for a call
///      that cannot succeed within the caller's gas, fee cap or funds (geth's
///      -32000 answer in geth's words — a check failed before the run as
///      "err: … (supplied gas N)"). eth_call_tx_json returns it; the plain
///      eth_call_json / eth_call_overrides_json only for calldata that alone
///      costs more than the 30 M budget (it used to be `unavailable`).
///      estimate_gas_tx_json now also answers a fee cap below the block's
///      base fee as `infeasible` ("failed with N gas: max fee per gas less
///      than block base fee: …"), where it used to estimate. The JVM
///      `RustEngineNative` wrappers, the Node addon and the iOS wrapper moved
///      with it.
/// v36: send_raw_transaction_json judges a transaction before it broadcasts it
///      (#531): one its sender cannot pay for (`value + gas × fee` above the
///      balance) or whose nonce is used — on the sender's account as proven at
///      a fresh head — is answered `{"status":"rejected","reason"}` with
///      geth's txpool verdict ("insufficient funds for gas * price + value: …",
///      "nonce too low: …"), which the hosts serve verbatim under geth's
///      -32000, and is never broadcast. Anything that keeps it from judging
///      sends as before. No signature change; the JVM `RustChainHandle` and
///      the iOS `IosRpcBackend` read the new shape, and the Node addon passes
///      it through.
/// v37: set_log_index_config's JSON gained `unwatch`, an array of addresses:
///      the explicit unsubscribe the additive union (v24) never had. Each
///      address it names leaves the index BEFORE the union — its watch entry,
///      its coverage and its stored logs — while every other entry keeps its
///      own; an address the index does not watch is ignored, and one the same
///      push also lists under `watch` refuses the push. A payload extension,
///      no signature change — bumped because an older engine would take the
///      key and silently ignore it, which is the one thing a host must not be
///      able to pair with. `true` now also means the unwatch is DURABLE:
///      a push whose unwatch could not write its checkpoint answers `false`
///      (the entries are dropped in memory, the rest of the push is not
///      applied, and repeating the push retries the write). The status JSON
///      marks an entry indexed under a topic0 restriction with a trailing
///      `"restricted":true` (other entries keep their shape). The hosts'
///      Index tab sends `unwatch` for a removed contract
///      (`LogIndexWatch.configJson`); the Node addon and the iOS wrapper pass
///      the JSON through unchanged.
/// v38: the status JSON gained `snap2ServingPeers`: the part of
///      `snapServingPeers` whose connection runs snap/2 (EIP-8189), which the
///      engine now speaks next to snap/1. Informational — the hosts show it in
///      parentheses after the serving count ("serving 8 (3)") and gate on nothing;
///      reads are the same on either version. A payload extension, no
///      signature change — bumped so a host showing the number is never
///      paired with an engine that cannot report it (an absent key would read
///      as "no snap/2 peers"). `RustChainHandle`, the iOS wrapper's status
///      reader and the Node addon's `statusJson()` carry it.
/// v39: added set_dns_discovery / myotis_set_dns_discovery (#539, part 3): a
///      process-global switch (not per-handle) allowing the EIP-1459 DNS tree
///      walk (`el/dnsdisco.rs`) on hosts that resolve through the system
///      resolver; off by default, never used while Tor is enabled, and the
///      last caller wins for every network in the process. An additive
///      function — bumped so a JVM host that switches it on is never paired
///      with an engine that silently lacks it. The JVM desktop and daemon
///      (`RustMyotisEngine.create`, when the host passes no DnsServers port)
///      and myotis-rpcd call it; iOS and the Node addon do not yet.
/// v40: added create_access_list_json (UniFFI, the C ABI and Node):
///      eth_createAccessList for the FULL JSON-RPC transaction object — the
///      EIP-2930 access list the transaction touches, built as geth builds it
///      (traced with geth's exclusions, then confirmed with the list applied
///      until it stops changing), with the gas the run made with it used and
///      that run's own revert or halt NEXT TO the list, as geth's result
///      carries it (`{"status":"ok","accessList","gasUsed"[,"vmError"
///      [,"revertDataHex"]]}` — `vmError`, since a top-level `error` is the
///      engine's failure envelope); the request checked as eth_call_tx_json checks
///      it, so `infeasible`, the permanent envelope and the block selector
///      behave as there. The JVM `RustEngineNative` wrappers, the Node addon
///      and the iOS wrapper moved with it.
/// v41: "blockTimestamp" (unix seconds) on the verified-read shapes that name
///      the block a wallet sees: the account read (`AccountProofResult`) carries
///      it only when PROVEN — the read ran against the beacon-attested
///      optimistic or finalized block (its payload header, or after Gloas the
///      header whose keccak is the attested hash, carries the timestamp) and
///      the verdict holds — else null; the ENS forward
///      and record shapes always carry it, from the verified header the
///      resolution ran against. A payload extension, no signature change —
///      bumped, as v38 was, so a host that shows the block's age is never
///      paired with an engine that cannot report it. `RustChainHandle`,
///      `RustEnsApi` and the iOS wrapper read it.
/// v42: ens_record_json gained the method "ownership" — the registry's owner and
///      resolver, and for a .eth second-level name the registrar's registrant,
///      expiry and grace period, seen through the NameWrapper (status ok carries
///      registrantHex / managerHex / wrapped / resolverHex / expiresAt /
///      gracePeriodSeconds, absent parts left out). A payload extension, no
///      signature change: an older engine answers "unknown ens method".
pub const ABI_VERSION: i32 = 42;

// Keep the workspace edge alive so `cargo build -p myotis-engine` type-checks the
// consensus crate too.
pub use myotis_consensus::bls_dst;
