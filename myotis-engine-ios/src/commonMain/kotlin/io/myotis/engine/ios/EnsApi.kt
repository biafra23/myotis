package io.myotis.engine.ios

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * ENS on one handle: the Kotlin twin of `io.myotis.api.EnsApi`'s forward resolution, as
 * the JVM side's `RustEnsApi` answers it. Every failure, not-running and bad arguments
 * included, is folded into the result's `error`, never thrown.
 *
 * This engine has no CCIP-Read gateway: a name that resolves off chain (ERC-3668) is an
 * error result, as on a JVM host that gives the engine none. An off-chain answer would
 * come from an HTTP gateway the resolver names and would tell it the name.
 */
class EnsApi internal constructor(private val handle: ChainHandle) {

    /** [name]'s address, resolved against [root]. */
    fun resolveAddress(name: String, root: EnsRoot): EnsResolutionResult {
        if (name.isBlank()) return EnsResolutionResult(name, null, -1, false, "empty ENS name")
        return try {
            val params = buildJsonObject {
                put("method", "addr")
                put("name", name)
                put("root", root.param())
            }
            EngineDecoding.ensAddress(name, handle.ensRecord(params.toString()))
        } catch (e: Exception) {
            EnsResolutionResult(name, null, -1, false, e.message ?: e::class.simpleName)
        }
    }

    private fun EnsRoot.param(): String = when (this) {
        EnsRoot.AUTO -> "auto"
        EnsRoot.FINALIZED -> "finalized"
        // No peer-claimed-head mode: the beacon-attested optimistic head, strictly stronger.
        EnsRoot.PEER_HEAD -> "optimistic"
    }
}
