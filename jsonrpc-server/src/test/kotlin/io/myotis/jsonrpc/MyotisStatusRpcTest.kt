package io.myotis.jsonrpc

import io.myotis.api.BeaconState
import io.myotis.api.BeaconStatus
import io.myotis.api.ClPeerInfo
import io.myotis.api.LifecycleState
import io.myotis.api.NodeStatusReads
import io.myotis.api.PeerInfo
import io.myotis.api.StatusSnapshot
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The `myotis_status` / `myotis_beaconStatus` JSON-RPC methods: their result shape must
 * mirror the daemon's `status` / `beacon-status` IPC commands
 * ([com.jaeckel.ethp2p.app.CommandHandler]) field-for-field, and — being local
 * introspection — they must answer without a verified backend. The exact-string asserts
 * pin the shape so it can't silently drift from the IPC command.
 */
class MyotisStatusRpcTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun statusSnapshot(
        lifecycle: LifecycleState = LifecycleState.RUNNING,
        lastWakeReason: String? = "REQUEST",
    ) = StatusSnapshot(
        /* running */ true,
        lifecycle,
        /* network */ "mainnet",
        /* beaconState */ BeaconState.SYNCED,
        /* connectedPeers */ 4,
        /* readyPeers */ 3,
        /* snapPeers */ 2,
        /* snapServingPeers */ 2,
        /* discoveredPeers */ 5,
        /* backedOffPeers */ 1,
        /* blacklistedPeers */ 0,
        /* attemptedDials */ 9,
        /* discv5TableSize */ 8,
        /* executionBlockNumber */ 123L,
        /* optimisticBlockNumber */ 124L,
        /* finalizedSlot */ 500L,
        /* finalizedBlockNumber */ 122L,
        /* syncStartPeriod */ -1L,
        /* syncCurrentPeriod */ 1000L,
        /* syncTargetPeriod */ 1000L,
        /* finalizedPeriod */ 15L,
        /* wallClockPeriod */ 1000L,
        /* verifiedHeadAgeMs */ 0L,
        /* readyPeerList */ listOf(PeerInfo("1.2.3.4:30303", true, "geth/v1")),
        /* pauseCount */ 7,
        /* totalPausedMs */ 1000L,
        /* lastPauseEpochMs */ 111L,
        /* lastResumeEpochMs */ 222L,
        lastWakeReason,
    )

    private fun beaconStatus(
        state: BeaconState,
        peers: List<ClPeerInfo> = emptyList(),
        stateRootHex: String? = "0xabc",
    ) = BeaconStatus(
        state,
        /* bootstrapped */ true,
        /* currentPeriod */ if (state == BeaconState.SYNCING) 10L else 1000L,
        /* targetPeriod */ if (state == BeaconState.SYNCING) 20L else 1000L,
        /* discv5TableSize */ 8,
        /* connectedPeers */ 6,
        /* lightClientPeers */ 2L,
        /* servedPeersLastMinute */ 3,
        /* finalizedSlot */ 500L,
        /* optimisticSlot */ 501L,
        /* finalizedPeriod */ 15L,
        /* executionStateRootHex */ stateRootHex,
        /* executionBlockHashHex */ "0xdef",
        /* executionBlockNumber */ 123L,
        /* knownStateRoots */ 10,
        /* fillThreshold */ 4,
        peers,
    )

    private fun encode(obj: JsonObject) = Json.encodeToString(JsonObject.serializer(), obj)

    // ---- serializer shape (pinned to the IPC command output) ------------------------

    @Test fun statusJson_mirrorsIpcStatusShape() {
        assertEquals(
            """{"ok":true,"state":"RUNNING","uptimeSeconds":42,"discoveredPeers":5,""" +
                """"connectedPeers":4,"readyPeers":3,"snapPeers":2,"backedOffPeers":1,""" +
                """"blacklistedPeers":0,"pauseCount":7,"totalPausedMs":1000,""" +
                """"lastPauseEpochMs":111,"lastResumeEpochMs":222,"lastWakeReason":"REQUEST"}""",
            encode(StatusJson.status(statusSnapshot(), 42L)),
        )
    }

    @Test fun statusJson_nullWakeReason_isJsonNull() {
        assertTrue(
            encode(StatusJson.status(statusSnapshot(lastWakeReason = null), 0L))
                .endsWith(""""lastWakeReason":null}"""),
        )
    }

    @Test fun beaconStatusJson_synced_mirrorsIpcShape() {
        assertEquals(
            """{"ok":true,"state":"SYNCED","currentPeriod":1000,"targetPeriod":1000,""" +
                """"uptimeSeconds":42,"discoveredPeers":8,"connectedPeers":6,""" +
                """"lightClientPeers":2,"servedPeersLastMinute":3,"finalizedSlot":500,""" +
                """"optimisticSlot":501,"finalizedPeriod":15,"syncCommitteePeriod":1000,""" +
                """"wallClockPeriod":1000,"executionStateRoot":"0xabc","executionBlockNumber":123,""" +
                """"knownStateRoots":10,"fillThreshold":4,"peers":[]}""",
            encode(StatusJson.beaconStatus(beaconStatus(BeaconState.SYNCED), 42L)),
        )
    }

    @Test fun beaconStatusJson_syncing_collapsesToSyncingBranch() {
        // STARTING/SYNCING both render as "SYNCING" with zeroed slots + null state root, and
        // OMIT the synced-only fields (finalizedPeriod, syncCommitteePeriod, …) — exactly the
        // daemon's SYNCING branch.
        assertEquals(
            """{"ok":true,"state":"SYNCING","currentPeriod":10,"targetPeriod":20,""" +
                """"uptimeSeconds":42,"discoveredPeers":8,"connectedPeers":6,""" +
                """"lightClientPeers":2,"servedPeersLastMinute":3,"finalizedSlot":0,""" +
                """"optimisticSlot":0,"executionStateRoot":null,"knownStateRoots":10,"peers":[]}""",
            encode(StatusJson.beaconStatus(beaconStatus(BeaconState.SYNCING, stateRootHex = null), 42L)),
        )
        // STARTING collapses to the same branch.
        assertTrue(
            encode(StatusJson.beaconStatus(beaconStatus(BeaconState.STARTING, stateRootHex = null), 0L))
                .contains(""""state":"SYNCING""""),
        )
    }

    @Test fun beaconPeers_truncateLongId_andOmitNullClientId() {
        val peers = listOf(
            ClPeerInfo("QmVeryLongPeerIdBeyondSixteen", "1.2.3.4:9000", "Lighthouse/v1", true, 3),
            ClPeerInfo("shortId", "5.6.7.8:9000", null, false, 1),
        )
        val arr = StatusJson.beaconStatus(beaconStatus(BeaconState.SYNCED, peers), 0L)["peers"]!!.jsonArray
        val p0 = arr[0].jsonObject
        assertEquals("QmVeryLongPeerId...", p0["peerId"]!!.jsonPrimitive.content) // first 16 + "..."
        assertEquals("Lighthouse/v1", p0["clientId"]!!.jsonPrimitive.content)
        assertEquals(true, p0["lightClient"]!!.jsonPrimitive.content.toBoolean())
        val p1 = arr[1].jsonObject
        assertEquals("shortId", p1["peerId"]!!.jsonPrimitive.content)             // no truncation
        assertFalse(p1.containsKey("clientId"))                                   // null clientId omitted
    }

    @Test fun beaconPeers_nullPeerIdAndAddress_renderEmptyString() {
        // The IPC command runs these through escapeJson(), which maps null -> "" — so parity
        // requires "" here too, not JSON null. (Fields are documented always-present; this
        // guards the parity claim regardless.)
        val peers = listOf(ClPeerInfo(null, null, null, false, 0))
        val p = StatusJson.beaconStatus(beaconStatus(BeaconState.SYNCED, peers), 0L)["peers"]!!
            .jsonArray[0].jsonObject
        assertEquals("", p["peerId"]!!.jsonPrimitive.content)
        assertEquals("", p["remoteAddress"]!!.jsonPrimitive.content)
        assertFalse(p.containsKey("clientId"))
    }

    // ---- router dispatch ------------------------------------------------------------

    private class StubStatus(
        private val s: StatusSnapshot,
        private val bs: BeaconStatus,
        private val up: Long,
    ) : NodeStatusReads {
        override fun status() = s
        override fun beaconStatus() = bs
        override fun uptimeSeconds() = up
    }

    private fun route(statusReads: NodeStatusReads?, body: String): String =
        runBlocking { RpcRouter(null, MethodLogger(), null, statusReads).handle(body) }

    @Test fun myotisStatus_returnsResult_withoutBackend() {
        val stub = StubStatus(statusSnapshot(), beaconStatus(BeaconState.SYNCED), 42L)
        val resp = route(stub, """{"jsonrpc":"2.0","id":1,"method":"myotis_status","params":[]}""")
        val obj = json.parseToJsonElement(resp).jsonObject
        assertFalse(obj.containsKey("error"))                                     // local method, no backend needed
        val result = obj["result"]!!.jsonObject
        assertEquals("RUNNING", result["state"]!!.jsonPrimitive.content)
        assertEquals(42, result["uptimeSeconds"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun myotisBeaconStatus_returnsResult_withoutBackend() {
        val stub = StubStatus(statusSnapshot(), beaconStatus(BeaconState.SYNCED), 7L)
        val resp = route(stub, """{"jsonrpc":"2.0","id":2,"method":"myotis_beaconStatus","params":[]}""")
        val result = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("SYNCED", result["state"]!!.jsonPrimitive.content)
        assertEquals(500, result["finalizedSlot"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun myotisStatus_readThrows_errorsInternal_notRaw500() {
        // A throwing status source must become a JSON-RPC error envelope (like the IPC path),
        // not an unhandled exception surfacing as a raw HTTP 500.
        val throwing = object : NodeStatusReads {
            override fun status(): StatusSnapshot = throw IllegalStateException("boom")
            override fun beaconStatus(): BeaconStatus = throw IllegalStateException("boom")
            override fun uptimeSeconds() = 0L
        }
        val resp = route(throwing, """{"jsonrpc":"2.0","id":1,"method":"myotis_status","params":[]}""")
        val err = json.parseToJsonElement(resp).jsonObject["error"]!!.jsonObject
        assertEquals(-32603, err["code"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun myotisStatus_unwired_errorsMethodNotSupported() {
        // No status source injected (e.g. an engine host that didn't wire it) → -32601, not a crash.
        for (m in listOf("myotis_status", "myotis_beaconStatus")) {
            val resp = route(null, """{"jsonrpc":"2.0","id":1,"method":"$m","params":[]}""")
            val err = json.parseToJsonElement(resp).jsonObject["error"]!!.jsonObject
            assertEquals(-32601, err["code"]!!.jsonPrimitive.content.toInt())
            assertNull(json.parseToJsonElement(resp).jsonObject["result"])
        }
    }
}
