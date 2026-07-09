package io.myotis.jsonrpc

import io.myotis.api.BeaconState
import io.myotis.api.BeaconStatus
import io.myotis.api.ClPeerInfo
import io.myotis.api.StatusSnapshot
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Serializers for the `myotis_status` / `myotis_beaconStatus` JSON-RPC results.
 *
 * The object shape (fields AND order) mirrors the daemon's `status` / `beacon-status`
 * IPC commands field-for-field — see [com.jaeckel.ethp2p.app.CommandHandler]'s
 * `handleStatus` / `handleBeaconStatus` — so a myotis-aware client can reuse a single
 * parser across the IPC and JSON-RPC transports. The IPC `"ok":true` field is kept for
 * exact parity; on the JSON-RPC side this object is the `result`, and success is already
 * implied by `result` being present.
 *
 * The two serializers can't share code with CommandHandler (different module, no build
 * edge), so [StatusJsonTest] pins the shape to catch drift.
 */
internal object StatusJson {

    /** Mirrors CommandHandler.handleStatus. [uptimeSeconds] is supplied by the host. */
    fun status(s: StatusSnapshot, uptimeSeconds: Long): JsonObject = buildJsonObject {
        put("ok", true)
        put("state", s.lifecycle().name)
        put("uptimeSeconds", uptimeSeconds)
        put("discoveredPeers", s.discoveredPeers())
        put("connectedPeers", s.connectedPeers())
        put("readyPeers", s.readyPeers())
        put("snapPeers", s.snapPeers())
        put("backedOffPeers", s.backedOffPeers())
        put("blacklistedPeers", s.blacklistedPeers())
        put("pauseCount", s.pauseCount())
        put("totalPausedMs", s.totalPausedMs())
        put("lastPauseEpochMs", s.lastPauseEpochMs())
        put("lastResumeEpochMs", s.lastResumeEpochMs())
        val reason = s.lastWakeReason()
        if (reason == null) put("lastWakeReason", JsonNull) else put("lastWakeReason", reason)
    }

    /** Mirrors CommandHandler.handleBeaconStatus, incl. its SYNCING-vs-synced branch. */
    fun beaconStatus(bs: BeaconStatus, uptimeSeconds: Long): JsonObject = buildJsonObject {
        val syncing = bs.state() == BeaconState.SYNCING || bs.state() == BeaconState.STARTING
        put("ok", true)
        put("state", if (syncing) "SYNCING" else bs.state().name)
        // periodProgress
        put("currentPeriod", bs.currentPeriod())
        put("targetPeriod", bs.targetPeriod())
        // peerStats
        put("uptimeSeconds", uptimeSeconds)
        put("discoveredPeers", bs.discv5TableSize())
        put("connectedPeers", bs.connectedPeers())
        put("lightClientPeers", bs.lightClientPeers())
        put("servedPeersLastMinute", bs.servedPeersLastMinute())
        if (syncing) {
            put("finalizedSlot", 0)
            put("optimisticSlot", 0)
            put("executionStateRoot", JsonNull)
            put("knownStateRoots", bs.knownStateRoots())
        } else {
            put("finalizedSlot", bs.finalizedSlot())
            put("optimisticSlot", bs.optimisticSlot())
            put("finalizedPeriod", bs.finalizedPeriod())
            put("syncCommitteePeriod", bs.currentPeriod())
            put("wallClockPeriod", bs.targetPeriod())
            val stateRoot = bs.executionStateRootHex()
            if (stateRoot == null) put("executionStateRoot", JsonNull) else put("executionStateRoot", stateRoot)
            put("executionBlockNumber", bs.executionBlockNumber())
            put("knownStateRoots", bs.knownStateRoots())
            put("fillThreshold", bs.fillThreshold())
        }
        put("peers", beaconPeers(bs.peers()))
    }

    private fun beaconPeers(peers: List<ClPeerInfo>): JsonArray = buildJsonArray {
        for (p in peers) {
            add(buildJsonObject {
                // Match the IPC command exactly: it renders these through escapeJson(), which
                // maps null -> "" (CommandHandler.escapeJson), so a null id/address is "", not null.
                put("peerId", truncatePeerId(p.peerId()) ?: "")
                put("remoteAddress", p.remoteAddress() ?: "")
                val clientId = p.clientId()
                if (clientId != null) put("clientId", clientId)
                put("lightClient", p.lightClient())
                put("protocols", p.protocols())
            })
        }
    }

    /** Same 16-char truncation the daemon's beacon-status uses. */
    private fun truncatePeerId(peerId: String?): String? =
        if (peerId != null && peerId.length > 16) peerId.substring(0, 16) + "..." else peerId
}
