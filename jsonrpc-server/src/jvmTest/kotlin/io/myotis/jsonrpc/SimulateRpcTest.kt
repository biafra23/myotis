package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * `eth_simulateV1` through the router (#716): the simulation object handed to the
 * engine as the request carried it, the block read as for `eth_call`, and the
 * backend's outcomes served as geth serves them — geth's own errors with geth's codes.
 */
class SimulateRpcTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** A backend recording what it was asked; it answers [answer]. */
    private class Backend(private val simulating: Boolean = true) : RpcBackend {
        var answer: RpcSimulateResult = RpcSimulateResult.ok("""[{"number":"0x65","hash":null,"calls":[]}]""")
        var asked: Pair<String, String>? = null

        override fun chainId(): Long = 1
        override fun headBlockNumber(): Long? = 100
        override fun syncState(): RpcSyncState = RpcSyncState.SYNCED
        override fun supportsSimulation(): Boolean = simulating
        override fun simulateV1(optsJson: String, block: String): RpcSimulateResult {
            asked = optsJson to block
            return answer
        }

        override fun call(from: ByteArray?, to: ByteArray?, data: ByteArray, valueWei: String?, block: String): ByteArray? = null
        override fun getBalance(address: ByteArray, block: String): String? = null
        override fun getTransactionCount(address: ByteArray, block: String): Long? = null
        override fun getCode(address: ByteArray, block: String): ByteArray? = null
        override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? = null
        override fun sendRawTransaction(rawTx: ByteArray): ByteArray? = null
        override fun getTransactionReceipt(txHash: ByteArray): String? = null
        override fun getTransactionByHash(txHash: ByteArray): String? = null
        override fun getBlockReceipts(blockSelector: String): String? = null
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? = null
        override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? = null
        override fun gasPrice(): String? = null
        override fun maxPriorityFeePerGas(): String? = null
        override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? = null
        override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long? = null
    }

    private val opts = """{"blockStateCalls":[{"calls":[{"from":"0x${"42".repeat(20)}","to":"0x${"11".repeat(20)}"}]}],"traceTransfers":true}"""

    private fun call(b: RpcBackend, params: String, logger: MethodLogger = MethodLogger()): JsonObject = runBlocking {
        json.parseToJsonElement(
            RpcRouter(null, logger, b).handle("""{"jsonrpc":"2.0","id":1,"method":"eth_simulateV1","params":$params}"""),
        ).jsonObject
    }

    private fun JsonObject.code(): Int = this["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt()
    private fun JsonObject.message(): String = this["error"]!!.jsonObject["message"]!!.jsonPrimitive.content

    @Test fun servesGethsResult_andHandsTheRequestToTheEngineWhole() {
        val b = Backend()
        val logger = MethodLogger()
        val resp = call(b, """[$opts,"latest"]""", logger)
        val blocks = resp["result"]!!.jsonArray
        assertEquals("0x65", blocks[0].jsonObject["number"]!!.jsonPrimitive.content)
        val (handed, block) = b.asked!!
        assertEquals("latest", block)
        assertEquals(json.parseToJsonElement(opts), json.parseToJsonElement(handed))
        // A simulated block is no chain fact.
        assertEquals(1, logger.coverage()["eth_simulateV1"]!!.jsonObject["simulated"]!!.jsonPrimitive.content.toInt())
        // Without a block: latest; a number is passed on as the engine reads it.
        call(b, """[$opts]""")
        assertEquals("latest", b.asked!!.second)
        call(b, """[$opts,"0x64"]""")
        assertEquals("0x64", b.asked!!.second)
        // A number past eth_call's 64-block window reaches the engine, which
        // judges it (the finalized block is that far back on mainnet).
        call(b, """[$opts,"0x14"]""")
        assertEquals("0x14", b.asked!!.second)
    }

    /** Refused before the engine is asked, for good. */
    @Test fun refusesWhatTheRouterCannotHandOn() {
        val b = Backend()
        for ((params, says) in listOf(
            """[]""" to "expected the simulation object",
            """["0x1"]""" to "expected the simulation object",
            """[$opts,"safe"]""" to "'safe' tag",
            """[$opts,"latest",{}]""" to "too many arguments",
        )) {
            val resp = call(b, params)
            assertEquals(-32602, resp.code(), params)
            assertTrue(resp.message().contains(says), "$params → ${resp.message()}")
        }
        assertNull(b.asked, "nothing refused reached the engine")
    }

    @Test fun anEngineWithoutSimulation_isRefusedForGood() {
        val resp = call(Backend(simulating = false), """[$opts]""")
        assertEquals(-32602, resp.code())
        assertTrue(resp.message().contains("simulates no blocks"), resp.message())
    }

    @Test fun theEnginesOutcomes_areServedAsGethServesThem() {
        val b = Backend()
        val params = """[$opts]"""
        b.answer = RpcSimulateResult.failed(-38020, "block numbers must be in order: 2 <= 2")
        val failed = call(b, params)
        assertEquals(-38020, failed.code())
        assertEquals("block numbers must be in order: 2 <= 2", failed.message())
        b.answer = RpcSimulateResult.refused("BLOBBASEFEE reads the simulated block's blob base fee")
        assertEquals(-32602, call(b, params).code())
        b.answer = RpcSimulateResult.unavailable("no snap peer")
        val unavailable = call(b, params)
        assertEquals(-32000, unavailable.code())
        assertTrue(unavailable.message().contains("no snap peer"))
        b.answer = RpcSimulateResult.ok("{not an array")
        assertEquals(-32000, call(b, params).code(), "a result the backend could not shape is no answer")
    }
}
