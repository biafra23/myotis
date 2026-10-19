package io.myotis.engine.ios

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The typed API's own rules over a fake C ABI: creating handles, the reads' guards and
 *  arguments, the pending nonce, the send gate, ENS and the verified head's age. */
class TypedEngineTest {

    private val catalog =
        """[{"name":"sepolia","displayName":"Sepolia","chainId":11155111,"hasEns":true,""" +
            """"defaultElPort":30303,"defaultDiscv5Port":9000,"defaultRpcPort":8547,""" +
            """"clGenesisTime":1655733600,"secondsPerSlot":12},""" +
            """{"name":"gnosis","displayName":"Gnosis","chainId":100,"hasEns":false,""" +
            """"defaultElPort":30303,"defaultDiscv5Port":9000,"defaultRpcPort":8548,""" +
            """"clGenesisTime":1638993340,"secondsPerSlot":5}]"""

    /** Answers from its fields and records what it was asked. */
    private inner class FakeNative : NativeEngine {
        var nextHandle = 7L
        val stopped = mutableListOf<Long>()
        val calls = mutableListOf<String>()
        var status = "{}"
        var account = """{"exists":true,"nonce":4,"balanceWei":"10","verifyMethod":"headerChain"}"""
        var overlay = -1L
        var call = """{"status":"ok","resultHex":"0x2a","blockNumber":5}"""
        var gate = """{"ok":true}"""
        var send = """{"txHash":"0x${"ab".repeat(32)}"}"""
        var ens = """{"status":"noRecord","blockNumber":1,"verified":true}"""
        var receipt = "null"

        override fun availableNetworksJson() = catalog
        override fun canonicalNetworkName(nameOrAlias: String) =
            when (nameOrAlias) {
                "sepolia", "SEPOLIA" -> "sepolia"
                "gnosis" -> "gnosis"
                else -> null
            }
        override fun create(network: String, dataDir: String) = nextHandle
        override fun start(handle: Long) = true
        override fun stop(handle: Long) {
            stopped += handle
        }
        override fun pause(handle: Long) = true
        override fun resume(handle: Long) = true
        override fun setWsBoundPeriods(handle: Long, periods: Long) = true
        override fun acceptStaleAnchor(handle: Long) = true
        override fun statusJson(handle: Long) = status
        override fun requestAccountJson(handle: Long, address: String, block: String): String {
            calls += "account $address $block"
            return account
        }
        override fun getStorageProofJson(handle: Long, address: String, slot: Long, holder: String?): String {
            calls += "storageProof $address $slot $holder"
            return """{"error":"handle not started"}"""
        }
        override fun getCodeJson(handle: Long, address: String, block: String) = """{"error":"handle not started"}"""
        override fun getStorageAtJson(handle: Long, address: String, position32Hex: String, block: String): String {
            calls += "storageAt $address $position32Hex $block"
            return """{"valueHex":"0x01","verifyMethod":"headerChain"}"""
        }
        override fun ethCallJson(handle: Long, from: String, to: String, data: String, valueDecimal: String, block: String): String {
            calls += "call [$from] [$to] [$data] [$valueDecimal] $block"
            return call
        }
        override fun ethCallOverridesJson(
            handle: Long,
            from: String,
            to: String,
            data: String,
            valueDecimal: String,
            block: String,
            stateOverrides: String,
        ): String {
            calls += "callOverrides $stateOverrides"
            return call
        }
        override fun estimateGasJson(handle: Long, from: String, to: String, data: String, valueDecimal: String): String {
            calls += "estimate [$from] [$to] [$data] [$valueDecimal]"
            return """{"status":"ok","gas":21000}"""
        }
        override fun pendingNonceOverlay(handle: Long, address: String, minedNonce: Long): Long {
            calls += "overlay $address $minedNonce"
            return overlay
        }
        override fun feeHistoryJson(handle: Long, blockCount: Long, newestBlockTag: String, percentilesJson: String): String {
            calls += "feeHistory $blockCount $newestBlockTag $percentilesJson"
            return """{"oldestBlock":"0x1"}"""
        }
        override fun getTransactionReceiptJson(handle: Long, txHash32Hex: String) = receipt
        override fun checkRawTransactionJson(rawTxHex: String) = gate
        override fun sendRawTransactionJson(handle: Long, rawTxHex: String): String {
            calls += "send $rawTxHex"
            return send
        }
        override fun ensRecordJson(handle: Long, paramsJson: String): String {
            calls += "ens $paramsJson"
            return ens
        }
    }

    private val native = FakeNative()
    private val engine = MyotisEngine(native)
    private val address = ByteArray(20) { 0x11 }

    private fun sepolia(): ChainHandle = engine.create(EngineConfig("SEPOLIA", "/data"))

    // ---- creating ----

    @Test
    fun aHandleIsCreatedForTheCanonicalNetworkOnce() {
        val handle = sepolia()
        assertEquals("sepolia", handle.networkName)
        assertEquals(11155111L, handle.chainId)
        assertSame(handle, engine.get("sepolia"))
        assertEquals(listOf("sepolia"), engine.hostedNetworks())
        assertFailsWith<EngineException> { sepolia() }
        engine.stop("sepolia")
        assertEquals(listOf(7L), native.stopped)
        assertNull(engine.get("sepolia"))
        assertNotNull(sepolia())
    }

    @Test
    fun theCreateSentinelsAreRefusals() {
        assertFailsWith<EngineException> { engine.create(EngineConfig("holesky", "/data")) }
        for (sentinel in listOf(-1L, -2L, -3L)) {
            native.nextHandle = sentinel
            assertFailsWith<EngineException> { engine.create(EngineConfig("sepolia", "/data")) }
        }
        assertTrue(engine.hostedNetworks().isEmpty())
    }

    @Test
    fun ensIsThereOnlyWhereTheNetworkHasARegistry() {
        assertNotNull(sepolia().ens())
        native.nextHandle = 8
        assertNull(engine.create(EngineConfig("gnosis", "/data-gnosis")).ens())
    }

    @Test
    fun shutdownStopsEveryHostedNetwork() {
        sepolia()
        native.nextHandle = 8
        engine.create(EngineConfig("gnosis", "/data-gnosis"))
        engine.shutdownAll()
        assertEquals(setOf(7L, 8L), native.stopped.toSet())
        assertTrue(engine.hostedNetworks().isEmpty())
    }

    // ---- the reads ----

    @Test
    fun theBalanceAndTheNonceNeedAVerdict() {
        val reads = sepolia().reads()
        assertEquals("10", reads.getBalance(address, "latest"))
        assertEquals(4L, reads.getTransactionCount(address, "latest"))
        assertEquals("account 0x${"11".repeat(20)} latest", native.calls.first())
        // Proven absent: zero.
        native.account = """{"exists":false,"nonce":-1,"balanceWei":null,"verifyMethod":"headerChain"}"""
        assertEquals("0", reads.getBalance(address, "latest"))
        assertEquals(0L, reads.getTransactionCount(address, "latest"))
        // No verdict, an error, a wrong-sized address: no answer.
        native.account = """{"exists":true,"nonce":4,"balanceWei":"10","verifyMethod":null,"failReason":"x"}"""
        assertNull(reads.getBalance(address, "latest"))
        native.account = """{"error":"handle not started"}"""
        assertNull(reads.getTransactionCount(address, "latest"))
        assertNull(reads.getBalance(ByteArray(19), "latest"))
    }

    @Test
    fun thePendingNonceCountsThisNodesUnminedSends() {
        val reads = sepolia().reads()
        native.overlay = 6
        assertEquals(6L, reads.getTransactionCount(address, "pending"))
        assertEquals("overlay 0x${"11".repeat(20)} 4", native.calls.last())
        // No overlay to apply: the mined nonce.
        native.overlay = -1
        assertEquals(4L, reads.getTransactionCount(address, "pending"))
        native.calls.clear()
        assertEquals(4L, reads.getTransactionCount(address, "latest"))
        assertTrue(native.calls.none { it.startsWith("overlay") })
    }

    @Test
    fun aCallPassesItsArgumentsAndAFailureIsUnavailable() {
        val reads = sepolia().reads()
        val result = reads.callDetailed(null, address, byteArrayOf(1, 2), null, "latest", null)
        assertEquals(CallResult.Status.OK, result.status)
        assertContentEquals(byteArrayOf(0x2a), result.data)
        assertEquals(5L, result.blockNumber)
        assertEquals("call [] [0x${"11".repeat(20)}] [0x0102] [] latest", native.calls.last())
        reads.callDetailed(address, address, null, "7", "latest", """{"0x00":{}}""")
        assertEquals("""callOverrides {"0x00":{}}""", native.calls.last())
        native.call = """{"error":"handle not started"}"""
        assertEquals(CallResult.Status.UNAVAILABLE, reads.callDetailed(null, address, null, null, "latest", null).status)
        assertEquals(CallResult.Status.UNAVAILABLE, reads.callDetailed(null, ByteArray(3), null, null, "latest", null).status)
    }

    @Test
    fun anEstimateNeedsATarget() {
        val reads = sepolia().reads()
        assertEquals(21000L, reads.estimateGasDetailed(address, address, null, "1").gas)
        assertEquals("estimate [0x${"11".repeat(20)}] [0x${"11".repeat(20)}] [] [1]", native.calls.last())
        assertEquals(EstimateResult.Status.UNAVAILABLE, reads.estimateGasDetailed(address, null, null, null).status)
    }

    @Test
    fun aStorageWordAndAStorageProofTakeTheirWidths() {
        val handle = sepolia()
        val word = handle.reads().getStorageAt(address, ByteArray(32), "finalized")
        assertContentEquals(ByteArray(31) + byteArrayOf(1), word)
        assertEquals("storageAt 0x${"11".repeat(20)} 0x${"00".repeat(32)} finalized", native.calls.last())
        assertNull(handle.reads().getStorageAt(address, ByteArray(31), "latest"))
        // The proof read throws an engine error, as the JVM handle's does.
        assertFailsWith<EngineException> { handle.getStorageProof("0xC0", 3, null) }
    }

    @Test
    fun theFeeHistoryTakesItsPercentilesAsJson() {
        val reads = sepolia().reads()
        assertEquals("""{"oldestBlock":"0x1"}""", reads.feeHistory(4, "", doubleArrayOf(25.0, 75.0)))
        val asked = native.calls.last()
        assertTrue(asked.startsWith("feeHistory 4 latest ["), asked)
        assertEquals(listOf(25.0, 75.0), Json.parseToJsonElement(asked.substringAfter("latest ")).let { array ->
            (array as kotlinx.serialization.json.JsonArray).map { it.jsonPrimitive.content.toDouble() }
        })
        reads.feeHistory(4, "latest", null)
        assertEquals("feeHistory 4 latest ", native.calls.last())
        assertNull(reads.feeHistory(0, "latest", null))
        assertNull(reads.feeHistory(4, "latest", doubleArrayOf(Double.NaN)))
    }

    @Test
    fun aReceiptIsTheObjectTheNullLiteralOrNoAnswer() {
        val reads = sepolia().reads()
        assertEquals("null", reads.getTransactionReceipt(ByteArray(32)))
        native.receipt = """{"status":"0x1"}"""
        assertEquals("""{"status":"0x1"}""", reads.getTransactionReceipt(ByteArray(32)))
        native.receipt = """{"error":"no snap peer available"}"""
        assertNull(reads.getTransactionReceipt(ByteArray(32)))
        assertNull(reads.getTransactionReceipt(ByteArray(20)))
    }

    @Test
    fun bytesTheGateRefusesAreNeverSent() {
        val reads = sepolia().reads()
        native.gate = """{"error":"invalid raw transaction","code":-32602}"""
        assertEquals(SendResult.Status.REFUSED, reads.sendRawTransactionDetailed(byteArrayOf(1)).status)
        assertTrue(native.calls.none { it.startsWith("send") })
        native.gate = """{"ok":true}"""
        assertEquals(SendResult.Status.SENT, reads.sendRawTransactionDetailed(byteArrayOf(1)).status)
        assertEquals("send 0x01", native.calls.last())
        native.send = """{"error":"no peer available"}"""
        assertEquals(SendResult.Status.UNAVAILABLE, reads.sendRawTransactionDetailed(byteArrayOf(1)).status)
        assertEquals(SendResult.Status.UNAVAILABLE, reads.sendRawTransactionDetailed(ByteArray(0)).status)
    }

    // ---- ENS ----

    @Test
    fun aNameIsResolvedAgainstTheRootAskedFor() {
        val ens = assertNotNull(sepolia().ens())
        native.ens = """{"status":"ok","addressHex":"0x${"d8".repeat(20)}","blockNumber":9,"verified":true}"""
        val r = ens.resolveAddress("vitalik.eth", EnsRoot.FINALIZED)
        assertEquals("0x${"d8".repeat(20)}", r.addressHex)
        assertTrue(r.verified)
        val params = Json.parseToJsonElement(native.calls.last().removePrefix("ens ")).jsonObject
        assertEquals("addr", params.getValue("method").jsonPrimitive.content)
        assertEquals("vitalik.eth", params.getValue("name").jsonPrimitive.content)
        assertEquals("finalized", params.getValue("root").jsonPrimitive.content)
        ens.resolveAddress("vitalik.eth", EnsRoot.PEER_HEAD)
        assertTrue(native.calls.last().contains("\"optimistic\""))
        // Every failure is folded into the result.
        native.ens = """{"error":"handle not started"}"""
        assertEquals("handle not started", ens.resolveAddress("vitalik.eth", EnsRoot.AUTO).error)
        assertEquals("empty ENS name", ens.resolveAddress(" ", EnsRoot.AUTO).error)
    }

    // ---- the verified head's age ----

    private val synced =
        """{"running":true,"beaconState":"SYNCED","optimisticBlockNumber":100,"snapServingPeers":1}"""

    @Test
    fun theHeadIsAgedOnlyWhileAReadCanBeServed() {
        val handle = sepolia()
        native.status = synced.replace("SYNCED", "CATCHING_UP")
        assertEquals(Long.MAX_VALUE, handle.status().verifiedHeadAgeMs)
        native.status = synced
        val first = handle.status().verifiedHeadAgeMs
        assertTrue(first in 0..1_000, "a head just seen is fresh, was $first")
        assertEquals(LifecycleState.RUNNING, handle.lifecycle())
        native.status = synced.replace("\"snapServingPeers\":1", "\"snapServingPeers\":0")
        assertEquals(Long.MAX_VALUE, handle.status().verifiedHeadAgeMs)
        native.status = "{}"
        assertEquals(LifecycleState.STOPPED, handle.lifecycle())
    }
}
