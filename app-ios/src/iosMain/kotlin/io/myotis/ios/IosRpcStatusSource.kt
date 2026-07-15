package io.myotis.ios

import io.myotis.jsonrpc.RpcStatusSource
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlin.time.TimeMark

/**
 * `myotis_status` / `myotis_beaconStatus` for the iOS listener, shaped like the
 * JVM StatusJson output (whose exact field set the jsonrpc-server tests pin)
 * and populated the way `RustChainHandle` maps the native status JSON: CL
 * peerCount is connectedPeers, the EL pool holds only snap-ready peers, the
 * idle-sleep metrics are zero because iOS has no idle controller yet, and the
 * fields the Rust engine doesn't expose over the FFI (peer list, state-root
 * cache introspection) report their empty values.
 */
class IosRpcStatusSource(
    private val handleProvider: () -> Long?,
    private val startMarkProvider: () -> TimeMark?,
) : RpcStatusSource {

    override fun uptimeSeconds(): Long =
        startMarkProvider()?.elapsedNow()?.inWholeSeconds ?: 0L

    override fun statusJson(uptimeSeconds: Long): JsonObject {
        val o = nativeStatus()
        val running = o.boolean("running")
        val paused = o.boolean("paused")
        val snapPeers = o.long("snapPeers")
        return buildJsonObject {
            put("ok", true)
            put("state", if (running) "RUNNING" else if (paused) "PAUSED" else "STOPPED")
            put("uptimeSeconds", uptimeSeconds)
            put("discoveredPeers", o.long("discoveredPeers"))
            put("connectedPeers", o.long("peerCount"))
            put("readyPeers", snapPeers)
            put("snapPeers", snapPeers)
            put("backedOffPeers", o.long("backedOffPeers"))
            put("blacklistedPeers", o.long("blacklistedPeers"))
            // Idle-sleep isn't wired on iOS yet — metrics report the JVM shape's zeros.
            put("pauseCount", 0)
            put("totalPausedMs", 0)
            put("lastPauseEpochMs", 0)
            put("lastResumeEpochMs", 0)
            put("lastWakeReason", JsonNull)
        }
    }

    override fun beaconStatusJson(uptimeSeconds: Long): JsonObject {
        val o = nativeStatus()
        val state = o.string("beaconState") ?: "STARTING"
        val currentPeriod = o.long("currentPeriod")
        val targetPeriod = maxOf(o.long("targetPeriod"), currentPeriod)
        val syncing = state == "SYNCING" || state == "STARTING"
        return buildJsonObject {
            put("ok", true)
            put("state", state)
            put("currentPeriod", currentPeriod)
            put("targetPeriod", targetPeriod)
            put("uptimeSeconds", uptimeSeconds)
            put("discoveredPeers", o.long("discv5TableSize"))
            put("connectedPeers", o.long("peerCount"))
            put("lightClientPeers", o.long("peerCount"))
            put("servedPeersLastMinute", o.long("servedPeersLastMinute"))
            if (syncing) {
                put("finalizedSlot", 0)
                put("optimisticSlot", 0)
                put("executionStateRoot", JsonNull)
                put("knownStateRoots", 0)
            } else {
                put("finalizedSlot", o.long("finalizedSlot"))
                put("optimisticSlot", o.long("optimisticSlot"))
                put("finalizedPeriod", o.long("finalizedSlot") / 8192L)
                put("syncCommitteePeriod", currentPeriod)
                put("wallClockPeriod", targetPeriod)
                // The Rust engine doesn't expose the EL anchor / state-root cache
                // introspection over the FFI (JNI parity: RustChainHandle reports
                // the same empties).
                put("executionStateRoot", JsonNull)
                put("executionBlockNumber", 0)
                put("knownStateRoots", 0)
                put("fillThreshold", 0)
            }
            put("peers", buildJsonArray { })
        }
    }

    private fun nativeStatus(): JsonObject {
        val handle = handleProvider() ?: return JsonObject(emptyMap())
        return runCatching { engineJson.parseToJsonElement(RustEngine.statusJson(handle)).jsonObject }
            .getOrElse { JsonObject(emptyMap()) }
    }

    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content

    private fun JsonObject.boolean(key: String): Boolean =
        (this[key] as? JsonPrimitive)?.content == "true"

    private fun JsonObject.long(key: String): Long =
        (this[key] as? JsonPrimitive)?.longOrNull ?: 0L
}
