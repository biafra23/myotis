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
        val running = o.engineBoolean("running")
        val paused = o.engineBoolean("paused")
        val snapPeers = o.engineLong("snapPeers")
        return buildJsonObject {
            put("ok", true)
            put("state", if (running) "RUNNING" else if (paused) "PAUSED" else "STOPPED")
            put("uptimeSeconds", uptimeSeconds)
            put("discoveredPeers", o.engineLong("discoveredPeers"))
            // OMITTED (not zero) when the engine status is unreadable/not running:
            // net_peerCount answers from this field, and a fabricated 0 would tell
            // a health probe "node isolated" when the truth is "can't read status"
            // (→ the router's strict -32000 instead). The zeros below are fine —
            // nothing answers a JSON-RPC method from them.
            if (o.containsKey("peerCount")) put("connectedPeers", o.engineLong("peerCount"))
            put("readyPeers", snapPeers)
            put("snapPeers", snapPeers)
            put("backedOffPeers", o.engineLong("backedOffPeers"))
            put("blacklistedPeers", o.engineLong("blacklistedPeers"))
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
        val rawState = o.engineString("beaconState") ?: "STARTING"
        val currentPeriod = o.engineLong("currentPeriod")
        val targetPeriod = maxOf(o.engineLong("targetPeriod"), currentPeriod)
        val syncing = rawState == "SYNCING" || rawState == "STARTING"
        return buildJsonObject {
            put("ok", true)
            // The pinned JVM shape never emits STARTING — it normalizes to
            // SYNCING (StatusJson.beaconStatus does the same).
            put("state", if (syncing) "SYNCING" else rawState)
            put("currentPeriod", currentPeriod)
            put("targetPeriod", targetPeriod)
            put("uptimeSeconds", uptimeSeconds)
            put("discoveredPeers", o.engineLong("discv5TableSize"))
            put("connectedPeers", o.engineLong("peerCount"))
            put("lightClientPeers", o.engineLong("peerCount"))
            put("servedPeersLastMinute", o.engineLong("servedPeersLastMinute"))
            if (syncing) {
                put("finalizedSlot", 0)
                put("optimisticSlot", 0)
                put("executionStateRoot", JsonNull)
                put("knownStateRoots", 0)
            } else {
                put("finalizedSlot", o.engineLong("finalizedSlot"))
                put("optimisticSlot", o.engineLong("optimisticSlot"))
                put("finalizedPeriod", o.engineLong("finalizedSlot") / 8192L)
                put("syncCommitteePeriod", currentPeriod)
                put("wallClockPeriod", targetPeriod)
                // The Rust engine doesn't expose the EL state-root cache
                // introspection over the FFI, but its status does carry the
                // finalized payload's execution block number.
                put("executionStateRoot", JsonNull)
                put("executionBlockNumber", o.engineLong("finalizedBlockNumber"))
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

}
