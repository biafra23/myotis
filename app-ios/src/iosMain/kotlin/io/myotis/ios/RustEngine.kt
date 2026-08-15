package io.myotis.ios

import io.myotis.engine.capi.MYOTIS_ABI_VERSION
import io.myotis.engine.capi.myotis_available_networks_json
import io.myotis.engine.capi.myotis_canonical_network_name
import io.myotis.engine.capi.myotis_create
import io.myotis.engine.capi.myotis_drain_logs
import io.myotis.engine.capi.myotis_ens_record_json
import io.myotis.engine.capi.myotis_estimate_gas_json
import io.myotis.engine.capi.myotis_eth_call_json
import io.myotis.engine.capi.myotis_eth_call_overrides_json
import io.myotis.engine.capi.myotis_fee_estimate_json
import io.myotis.engine.capi.myotis_fee_history_json
import io.myotis.engine.capi.myotis_get_block_by_hash_json
import io.myotis.engine.capi.myotis_get_block_by_number_json
import io.myotis.engine.capi.myotis_get_block_receipts_json
import io.myotis.engine.capi.myotis_get_code_json
import io.myotis.engine.capi.myotis_get_storage_at_json
import io.myotis.engine.capi.myotis_get_transaction_by_hash_json
import io.myotis.engine.capi.myotis_get_transaction_receipt_json
import io.myotis.engine.capi.myotis_import_log_index_files
import io.myotis.engine.capi.myotis_log_index_status_json
import io.myotis.engine.capi.myotis_set_log_index_config
import io.myotis.engine.capi.myotis_send_raw_transaction_json
import io.myotis.engine.capi.myotis_init
import io.myotis.engine.capi.myotis_pause
import io.myotis.engine.capi.myotis_pending_nonce_overlay
import io.myotis.engine.capi.myotis_request_account_json
import io.myotis.engine.capi.myotis_resume
import io.myotis.engine.capi.myotis_start
import io.myotis.engine.capi.myotis_status_json
import io.myotis.engine.capi.myotis_stop
import io.myotis.engine.capi.myotis_string_free
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString

/**
 * Thin Kotlin face over the Rust engine's C ABI — the iOS twin of
 * `RustEngineNative` on the JVM side. Owns exactly two concerns: the
 * string-memory contract (every `char*` the engine returns is copied to a
 * Kotlin String and immediately released via `myotis_string_free`) and the
 * ABI handshake. Everything else (JSON parsing, lifecycle bookkeeping) lives
 * in [IosNodeController].
 *
 * All calls are BLOCKING (verified reads up to ~90 s) — callers stay off the
 * main thread, same rule as every other host.
 */
@OptIn(ExperimentalForeignApi::class)
object RustEngine {

    /** The ABI this host was built against, taken from the C header itself
     *  (`MYOTIS_ABI_VERSION` in rust/include/myotis_engine.h) rather than
     *  copied — the header instructs consumers to gate on the macro, and a
     *  capi.rs test pins it to `ABI_VERSION` in rust/myotis-engine/src/lib.rs.
     *  So there is no number to keep in sync here; cinterop reads it from the
     *  same header it generates these bindings from. The JVM twin
     *  `RustEngineNative.EXPECTED_ABI_VERSION` still mirrors by hand (UniFFI,
     *  no header in the loop). */
    const val EXPECTED_ABI_VERSION = MYOTIS_ABI_VERSION

    private val abiVersion: Int by lazy { myotis_init() }

    /**
     * Throws when the linked engine's ABI differs from what this host was built
     * against — fail loudly with a clear message instead of on drifted JSON or a
     * missing symbol. EVERY public entry point below calls this first (cheap
     * after the lazy first call), so no construction order can slip an FFI call
     * past the handshake — the header's contract is "refuse to call anything
     * else if the version differs".
     */
    fun requireAbi() {
        val v = abiVersion
        check(v == EXPECTED_ABI_VERSION) {
            "Rust engine ABI mismatch: expected $EXPECTED_ABI_VERSION, linked $v"
        }
    }

    /** Copy + free an engine-owned C string. Null stays null (the sentinel). */
    private fun take(p: CPointer<ByteVar>?): String? {
        if (p == null) return null
        return try {
            p.toKString()
        } finally {
            myotis_string_free(p)
        }
    }

    fun drainLogs(max: Int): String {
        requireAbi()
        return take(myotis_drain_logs(max)) ?: ""
    }

    fun availableNetworksJson(): String {
        requireAbi()
        return take(myotis_available_networks_json()) ?: "[]"
    }

    /** Canonical network name, or null for an unknown name/alias. */
    fun canonicalNetworkName(nameOrAlias: String): String? {
        requireAbi()
        return take(myotis_canonical_network_name(nameOrAlias))
    }

    /** Handle id (>= 1), or a negative sentinel (-1 create failed, -2 unsupported). */
    fun create(network: String, dataDir: String): Long {
        requireAbi()
        return myotis_create(network, dataDir)
    }

    fun start(handle: Long): Boolean {
        requireAbi()
        return myotis_start(handle)
    }

    fun stop(handle: Long) {
        requireAbi()
        myotis_stop(handle)
    }

    fun pause(handle: Long): Boolean {
        requireAbi()
        return myotis_pause(handle)
    }

    fun resume(handle: Long): Boolean {
        requireAbi()
        return myotis_resume(handle)
    }

    /** Status JSON object; `"{}"` for an unknown handle. */
    /** Install the eth_getLogs watch-list config; false = invalid/unavailable. */
    fun setLogIndexConfig(handle: Long, configJson: String): Boolean {
        requireAbi()
        return myotis_set_log_index_config(handle, configJson)
    }

    /** Log-index status JSON (enabled, counts, per-entry coverage). */
    fun logIndexStatusJson(handle: Long): String {
        requireAbi()
        return take(myotis_log_index_status_json(handle)) ?: """{"enabled":false}"""
    }

    /** Import portable log-index snapshots ({"ok":...} / {"error":...}). */
    fun importLogIndexFiles(handle: Long, pathsJson: String): String {
        requireAbi()
        return take(myotis_import_log_index_files(handle, pathsJson))
            ?: """{"error":"engine returned no result"}"""
    }

    fun statusJson(handle: Long): String {
        requireAbi()
        return take(myotis_status_json(handle)) ?: "{}"
    }

    /** AccountProofResult JSON, or `{"error": ...}`. */
    fun requestAccountJson(handle: Long, address: String): String {
        requireAbi()
        return take(myotis_request_account_json(handle, address))
            ?: """{"error":"engine returned no result"}"""
    }

    /** Generic ENS record dispatch (method + args in [paramsJson]). */
    fun ensRecordJson(handle: Long, paramsJson: String): String {
        requireAbi()
        return take(myotis_ens_record_json(handle, paramsJson))
            ?: """{"error":"engine returned no result"}"""
    }

    // ---- verified read surface behind the iOS JSON-RPC backend ----
    // Same envelopes as over JNI (golden-pinned): {"error"} for transport /
    // not-running, status-tagged objects for call/estimate, tri-state block/tx
    // JSON (object | the literal "null" | {"error"}).

    fun getCodeJson(handle: Long, address: String): String =
        jsonCall { myotis_get_code_json(handle, address) }

    fun getStorageAtJson(handle: Long, address: String, position32Hex: String): String =
        jsonCall { myotis_get_storage_at_json(handle, address, position32Hex) }

    fun ethCallJson(handle: Long, from: String, to: String, data: String, valueDecimal: String, block: String): String =
        jsonCall { myotis_eth_call_json(handle, from, to, data, valueDecimal, block) }

    /** [ethCallJson] with the `eth_call` state-override object as JSON (empty ⇒
     *  none). A SIMULATION over verified state — the caller's hypothesis, not a
     *  chain fact. */
    fun ethCallOverridesJson(
        handle: Long,
        from: String,
        to: String,
        data: String,
        valueDecimal: String,
        block: String,
        stateOverrides: String,
    ): String =
        jsonCall {
            myotis_eth_call_overrides_json(handle, from, to, data, valueDecimal, block, stateOverrides)
        }

    fun estimateGasJson(handle: Long, from: String, to: String, data: String, valueDecimal: String): String =
        jsonCall { myotis_estimate_gas_json(handle, from, to, data, valueDecimal) }

    fun getBlockByNumberJson(handle: Long, blockTag: String, fullTransactions: Boolean): String =
        jsonCall { myotis_get_block_by_number_json(handle, blockTag, fullTransactions) }

    fun getBlockByHashJson(handle: Long, blockHash32Hex: String, fullTransactions: Boolean): String =
        jsonCall { myotis_get_block_by_hash_json(handle, blockHash32Hex, fullTransactions) }

    fun getTransactionByHashJson(handle: Long, txHash32Hex: String): String =
        jsonCall { myotis_get_transaction_by_hash_json(handle, txHash32Hex) }

    fun getTransactionReceiptJson(handle: Long, txHash32Hex: String): String =
        jsonCall { myotis_get_transaction_receipt_json(handle, txHash32Hex) }

    fun getBlockReceiptsJson(handle: Long, selector: String): String =
        jsonCall { myotis_get_block_receipts_json(handle, selector) }

    /** Pending-tag nonce overlay; negative = malformed/not-running (serve the
     *  plain mined nonce). Plain long over the FFI — no JSON envelope. */
    fun pendingNonceOverlay(handle: Long, addressHex: String, minedNonce: Long): Long {
        requireAbi()
        return myotis_pending_nonce_overlay(handle, addressHex, minedNonce)
    }

    fun feeEstimateJson(handle: Long): String =
        jsonCall { myotis_fee_estimate_json(handle) }

    fun feeHistoryJson(handle: Long, blockCount: Long, newestBlockTag: String, percentilesJson: String): String =
        jsonCall { myotis_fee_history_json(handle, blockCount, newestBlockTag, percentilesJson) }

    fun sendRawTransactionJson(handle: Long, rawTxHex: String): String =
        jsonCall { myotis_send_raw_transaction_json(handle, rawTxHex) }

    private inline fun jsonCall(call: () -> CPointer<ByteVar>?): String {
        requireAbi()
        return take(call()) ?: """{"error":"engine returned no result"}"""
    }
}
