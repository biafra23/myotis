package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * `debug_traceCall` through the router (#716): the trace config read, the
 * state override applied, everything the node does not apply refused with
 * `-32602`, and the backend's outcomes served as geth serves them.
 */
class TraceCallRpcTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** A backend recording what it was asked; it answers [answer]. */
    private class Backend(private val tracing: Boolean = true) : RpcBackend {
        var answer: RpcTraceResult = RpcTraceResult.ok("""{"type":"CALL","from":"0x01","gas":"0x1","gasUsed":"0x1","input":"0x"}""")
        var asked: Triple<String, String?, String>? = null

        override fun chainId(): Long = 1
        override fun headBlockNumber(): Long? = 100
        override fun syncState(): RpcSyncState = RpcSyncState.SYNCED
        override fun supportsCallTracing(): Boolean = tracing
        override fun supportsStateOverrides(): Boolean = true
        override fun supportsContractCreation(): Boolean = true
        override fun traceCall(
            tx: RpcTransactionArgs,
            block: String,
            stateOverridesJson: String?,
            tracerJson: String,
        ): RpcTraceResult {
            asked = Triple(block, stateOverridesJson, tracerJson)
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

    private val tx = """{"from":"0x${"42".repeat(20)}","to":"0x${"11".repeat(20)}","data":"0xab"}"""

    private fun call(b: RpcBackend, params: String, logger: MethodLogger = MethodLogger()): JsonObject = runBlocking {
        json.parseToJsonElement(
            RpcRouter(null, logger, b).handle("""{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":$params}"""),
        ).jsonObject
    }

    private fun JsonObject.code(): Int = this["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt()
    private fun JsonObject.message(): String = this["error"]!!.jsonObject["message"]!!.jsonPrimitive.content

    @Test fun servesTheTrace_andHandsTheTracerAndOverridesToTheEngine() {
        val b = Backend()
        val logger = MethodLogger()
        val override = """{"0x${"11".repeat(20)}":{"code":"0x6000"}}"""
        val resp = call(
            b,
            """[$tx,"latest",{"tracer":"callTracer","tracerConfig":{"withLog":true},"stateOverrides":$override,"timeout":"5s"}]""",
            logger,
        )
        assertEquals("CALL", resp["result"]!!.jsonObject["type"]!!.jsonPrimitive.content)
        val (block, overrides, tracer) = b.asked!!
        assertEquals("latest", block)
        assertTrue(overrides!!.contains("0x6000"))
        assertEquals("""{"tracer":"callTracer","tracerConfig":{"withLog":true}}""", tracer)
        // A traced run under the caller's override is a simulation, not a chain fact.
        assertEquals(1, logger.coverage()["debug_traceCall"]!!.jsonObject["simulated"]!!.jsonPrimitive.content.toInt())
        // No config at all: the engine is handed none and names what it wants.
        call(b, """[$tx]""")
        assertEquals("{}", b.asked!!.third)
    }

    /** Applied or refused: every refusal is permanent, and none reaches the engine. */
    @Test fun refusesWhatTheNodeDoesNotApply() {
        val b = Backend()
        for ((params, says) in listOf(
            """[$tx,"latest",{"tracer":"callTracer","disableStack":true}]""" to "'disableStack' is not applied",
            """[$tx,"latest",{"tracer":"callTracer","blockOverrides":{"number":"0x1"}}]""" to "blockOverrides",
            """[$tx,"latest",{"tracer":"callTracer","stateOverrides":{"0x12":{}}}]""" to "invalid state override",
            """[$tx,"latest",{"tracer":"callTracer","timeout":5}]""" to "duration string",
            """[$tx,"latest",{"tracer":"callTracer","timeout":"banana"}]""" to "duration string",
            """[$tx,"latest","callTracer"]""" to "expected a trace config object",
            """[$tx,"safe",{"tracer":"callTracer"}]""" to "'safe' tag",
            """[{"from":"0x12"},"latest",{"tracer":"callTracer"}]""" to "invalid transaction object",
            """[$tx,"latest",{"tracer":"callTracer"},{}]""" to "too many arguments",
        )) {
            val resp = call(b, params)
            assertEquals(-32602, resp.code(), params)
            assertTrue(resp.message().contains(says), "$params → ${resp.message()}")
        }
        assertNull(b.asked, "nothing refused reached the engine")
        // An empty block override is no override.
        call(b, """[$tx,"latest",{"tracer":"callTracer","blockOverrides":{}}]""")
        assertTrue(b.asked != null)
    }

    @Test fun anEngineWithoutTracing_isRefusedForGood() {
        val resp = call(Backend(tracing = false), """[$tx,"latest",{"tracer":"callTracer"}]""")
        assertEquals(-32602, resp.code())
        assertTrue(resp.message().contains("traces no calls"), resp.message())
    }

    @Test fun theEnginesOutcomes_areServedAsGethServesThem() {
        val b = Backend()
        val params = """[$tx,"latest",{"tracer":"4byteTracer"}]"""
        b.answer = RpcTraceResult.refused("the tracer '4byteTracer' is not served by this node")
        assertEquals(-32602, call(b, params).code())
        b.answer = RpcTraceResult.infeasible("insufficient funds for gas * price + value")
        val infeasible = call(b, params)
        assertEquals(-32000, infeasible.code())
        assertEquals("insufficient funds for gas * price + value", infeasible.message())
        b.answer = RpcTraceResult.unavailable("no snap peer")
        val unavailable = call(b, params)
        assertEquals(-32000, unavailable.code())
        assertTrue(unavailable.message().contains("no snap peer"))
        b.answer = RpcTraceResult.ok("[not json")
        assertEquals(-32000, call(b, params).code(), "a trace the backend could not shape is no answer")
    }
}
