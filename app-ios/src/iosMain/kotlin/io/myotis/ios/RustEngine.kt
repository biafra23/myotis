package io.myotis.ios

import io.myotis.engine.capi.myotis_available_networks_json
import io.myotis.engine.capi.myotis_canonical_network_name
import io.myotis.engine.capi.myotis_create
import io.myotis.engine.capi.myotis_drain_logs
import io.myotis.engine.capi.myotis_ens_record_json
import io.myotis.engine.capi.myotis_init
import io.myotis.engine.capi.myotis_pause
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

    /** Must match `ABI_VERSION` in rust/myotis-engine/src/lib.rs — the same
     *  handshake `RustEngineNative.EXPECTED_ABI_VERSION` performs over JNI. */
    const val EXPECTED_ABI_VERSION = 18

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
}
