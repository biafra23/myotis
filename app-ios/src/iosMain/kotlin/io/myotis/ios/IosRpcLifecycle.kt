package io.myotis.ios

import io.myotis.jsonrpc.RpcLifecycle
import io.myotis.jsonrpc.RpcLifecycleResult
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * `myotis_pause` / `myotis_wakeup` for the iOS listener — the JSON-RPC
 * counterpart of the daemon's pause/resume IPC commands, over the Rust engine's
 * pause/resume FFI (`RustEngine.pause` / `RustEngine.resume`, i.e. the native
 * `myotis_pause` / `myotis_resume`). Called straight from the RPC dispatcher like
 * [IosRpcBackend] / [IosRpcStatusSource]: the native engine is internally
 * serialized, so these do not need the controller's lifecycle lane.
 *
 * The resulting lifecycle name is read back from the engine's status JSON AFTER
 * the transition so `{ok, lifecycle}` reflects the state actually reached, and
 * `ok` mirrors the JVM handle's rule (target state reached, idempotent when
 * already there) rather than the raw native boolean.
 */
class IosRpcLifecycle(
    private val handleProvider: () -> Long?,
) : RpcLifecycle {

    override fun pause(): RpcLifecycleResult {
        val handle = handleProvider() ?: return RpcLifecycleResult(false, "STOPPED")
        RustEngine.pause(handle)
        val lc = lifecycleName(handle)
        return RpcLifecycleResult(lc == "PAUSED", lc)
    }

    override fun wakeUp(): RpcLifecycleResult {
        val handle = handleProvider() ?: return RpcLifecycleResult(false, "STOPPED")
        RustEngine.resume(handle)
        val lc = lifecycleName(handle)
        return RpcLifecycleResult(lc == "RUNNING", lc)
    }

    /** Coarse lifecycle from the native status JSON (running/paused booleans),
     *  matching how [IosRpcStatusSource] derives the status "state" field. */
    private fun lifecycleName(handle: Long): String {
        val o = runCatching { engineJson.parseToJsonElement(RustEngine.statusJson(handle)).jsonObject }
            .getOrElse { JsonObject(emptyMap()) }
        return when {
            o.engineBoolean("running") -> "RUNNING"
            o.engineBoolean("paused") -> "PAUSED"
            else -> "STOPPED"
        }
    }
}
