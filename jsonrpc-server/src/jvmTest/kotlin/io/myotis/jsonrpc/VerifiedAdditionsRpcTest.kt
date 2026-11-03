package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The small verified additions of #715 through the router: `eth_blobBaseFee`,
 * `eth_getAccount` and the three `eth_getRawTransaction*` methods — served from
 * the backend's verified reads, refused (`-32602`) where the engine lacks them.
 */
class VerifiedAdditionsRpcTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** A backend answering only what a test sets; everything else cannot answer. */
    private open class Backend(private val chain: Long = 1) : RpcBackend {
        var headBlock: String? = null
        var proofs = false
        var proof: String? = null
        var lastProof: Triple<String, String, String>? = null
        var raw = false
        var rawByHash: String? = null
        var rawByBlock: String? = null
        var lastRawBlock: Pair<String, Long>? = null
        var resolved: String? = """{"hash":"0x00","number":"0x63"}"""
        var resolvedHashes = 0

        override fun chainId(): Long = chain
        override fun headBlockNumber(): Long? = 100
        override fun syncState(): RpcSyncState = RpcSyncState.SYNCED
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? =
            headBlock.takeIf { block == "latest" }
        override fun supportsProofs(): Boolean = proofs
        override fun getProof(address: ByteArray, storageKeysJson: String, block: String): String? {
            lastProof = Triple(hex(address), storageKeysJson, block)
            return proof
        }
        override fun resolveBlockHash(blockHash32: ByteArray): String? {
            resolvedHashes++
            return resolved
        }
        override fun supportsRawTransactions(): Boolean = raw
        override fun getRawTransactionByHash(txHash: ByteArray): String? = rawByHash
        override fun getRawTransactionByBlock(blockSelector: String, index: Long): String? {
            lastRawBlock = blockSelector to index
            return rawByBlock
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
        override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? = null
        override fun gasPrice(): String? = null
        override fun maxPriorityFeePerGas(): String? = null
        override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? = null
        override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long? = null

        companion object {
            fun hex(b: ByteArray) = "0x" + b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        }
    }

    private fun call(b: RpcBackend, method: String, params: String = "[]"): JsonObject = runBlocking {
        json.parseToJsonElement(
            RpcRouter(null, MethodLogger(), b).handle("""{"jsonrpc":"2.0","id":1,"method":"$method","params":$params}"""),
        ).jsonObject
    }

    private fun JsonObject.code(): Int = this["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt()
    private fun JsonObject.message(): String = this["error"]!!.jsonObject["message"]!!.jsonPrimitive.content
    private fun JsonObject.resultString(): String {
        assertNull(this["error"], toString())
        return this["result"]!!.jsonPrimitive.content
    }

    // ---- eth_blobBaseFee --------------------------------------------------

    @Test fun blobBaseFee_isTheHeadsFee_fromItsOwnExcessAndFork() {
        // Mainnet block 25,000,000 (BPO2): the fee a full node reports for it.
        val b = Backend().apply {
            headBlock = """{"number":"0x17d7840","timestamp":"0x69f497f3","excessBlobGas":"0xb9e7b35"}"""
        }
        assertEquals("0x" + 17_593_154L.toString(16), call(b, "eth_blobBaseFee").resultString())
    }

    @Test fun blobBaseFee_refusals() {
        // No excessBlobGas on the head: no blob fee on this chain, for good.
        val noBlobs = Backend().apply { headBlock = """{"number":"0x1","timestamp":"0x69f42af3"}""" }
        assertEquals(-32602, call(noBlobs, "eth_blobBaseFee").code())
        // A chain this node holds no schedule for: refused, never a guessed fraction.
        val unknown = Backend(chain = 5).apply {
            headBlock = """{"number":"0x1","timestamp":"0x69f42af3","excessBlobGas":"0x0"}"""
        }
        val resp = call(unknown, "eth_blobBaseFee")
        assertEquals(-32602, resp.code())
        assertTrue(resp.message().contains("chain 5"), resp.message())
        // No head block right now: retryable.
        assertEquals(-32000, call(Backend(), "eth_blobBaseFee").code())
        // It takes no arguments.
        assertEquals(-32602, call(Backend(), "eth_blobBaseFee", """["latest"]""").code())
    }

    // ---- eth_getAccount ---------------------------------------------------

    private val addr = "0x" + "ab".repeat(20)

    @Test fun getAccount_isTheProofsAccountLeaf_atTheAskedBlock() {
        val b = Backend().apply {
            proofs = true
            proof = """{"address":"$addr","accountProof":["0xf8"],"balance":"0x2a","codeHash":"0x${"c5".repeat(32)}",
                "nonce":"0x7","storageHash":"0x${"56".repeat(32)}","storageProof":[]}"""
        }
        val result = call(b, "eth_getAccount", """["$addr","0x63"]""")["result"]!!.jsonObject
        assertEquals(listOf("codeHash", "storageRoot", "balance", "nonce"), result.keys.toList())
        assertEquals("0x2a", result["balance"]!!.jsonPrimitive.content)
        assertEquals("0x7", result["nonce"]!!.jsonPrimitive.content)
        assertEquals("0x" + "56".repeat(32), result["storageRoot"]!!.jsonPrimitive.content)
        // One proof, no storage keys, at exactly the block asked.
        assertEquals(Triple(addr, "[]", "0x63"), b.lastProof)
    }

    @Test fun getAccount_refusals() {
        // An engine without proofs (the Java engine): permanent, before any engine call.
        val java = Backend()
        val resp = call(java, "eth_getAccount", """["$addr","latest"]""")
        assertEquals(-32602, resp.code())
        assertNull(java.lastProof)
        // The engine's permanent proof refusal (a block it holds no attested root for).
        val old = Backend().apply { proofs = true; proof = """{"error":"block 0x1 is too old","code":-32602}""" }
        assertEquals(-32602, call(old, "eth_getAccount", """["$addr","0x1"]""").code())
        // A proof missing a field is the engine's fault: retryable, never made up.
        val partial = Backend().apply { proofs = true; proof = """{"balance":"0x1","nonce":"0x0","codeHash":"0x00"}""" }
        assertEquals(-32000, call(partial, "eth_getAccount", """["$addr","latest"]""").code())
        assertEquals(-32602, call(Backend().apply { proofs = true }, "eth_getAccount", """["0x12","latest"]""").code())
    }

    // ---- eth_getRawTransaction* --------------------------------------------

    private val rawTx = byteArrayOf(0x02, 0xc1.toByte(), 0x80.toByte())
    private val rawHex = Backend.hex(rawTx)
    private val rawHash = Backend.hex(Keccak256.digest(rawTx))

    @Test fun rawByHash_servesTheBytes_thatHashToTheTransactionAsked() {
        val b = Backend().apply { raw = true; rawByHash = "\"$rawHex\"" }
        assertEquals(rawHex, call(b, "eth_getRawTransactionByHash", """["$rawHash"]""").resultString())
        // Bytes of another transaction are never served for this hash.
        val other = "0x" + "11".repeat(32)
        assertEquals(-32000, call(b, "eth_getRawTransactionByHash", """["$other"]""").code())
        // Verified not seen: null.
        b.rawByHash = "null"
        assertEquals(JsonNull, call(b, "eth_getRawTransactionByHash", """["$rawHash"]""")["result"])
        // Malformed engine answers are no answer.
        b.rawByHash = "\"0xzz\""
        assertEquals(-32000, call(b, "eth_getRawTransactionByHash", """["$rawHash"]""").code())
        assertEquals(-32602, call(b, "eth_getRawTransactionByHash", """["0x1234"]""").code())
    }

    @Test fun rawByBlock_passesTheSelectorAndIndex() {
        val b = Backend().apply { raw = true; rawByBlock = "\"$rawHex\"" }
        assertEquals(rawHex, call(b, "eth_getRawTransactionByBlockNumberAndIndex", """["0x63","0x2"]""").resultString())
        assertEquals("0x63" to 2L, b.lastRawBlock)
        assertEquals(rawHex, call(b, "eth_getRawTransactionByBlockNumberAndIndex", """["latest","0x0"]""").resultString())
        assertEquals("latest" to 0L, b.lastRawBlock)
        val blockHash = "0x" + "AB".repeat(32)
        assertEquals(rawHex, call(b, "eth_getRawTransactionByBlockHashAndIndex", """["$blockHash","0x1"]""").resultString())
        assertEquals(blockHash.lowercase() to 1L, b.lastRawBlock)
        // The hash is placed header-only first, so a block never served is known.
        assertEquals(1, b.resolvedHashes)
        // A hash no canonical block carries: null, without a raw read.
        b.resolved = "null"
        b.lastRawBlock = null
        assertEquals(JsonNull, call(b, "eth_getRawTransactionByBlockHashAndIndex", """["$blockHash","0x1"]""")["result"])
        assertNull(b.lastRawBlock)
        b.resolved = """{"hash":"0x00","number":"0x63"}"""
        // No such index / unknown block: null.
        b.rawByBlock = "null"
        assertEquals(JsonNull, call(b, "eth_getRawTransactionByBlockNumberAndIndex", """["0x63","0x9"]""")["result"])
        // Selectors read as every block selector: `safe` refused, a hash is no number.
        assertEquals(-32602, call(b, "eth_getRawTransactionByBlockNumberAndIndex", """["safe","0x0"]""").code())
        assertEquals(-32602, call(b, "eth_getRawTransactionByBlockNumberAndIndex", """["$blockHash","0x0"]""").code())
        assertEquals(-32602, call(b, "eth_getRawTransactionByBlockHashAndIndex", """["0x63","0x0"]""").code())
        // The engine's permanent refusal keeps its code.
        b.rawByBlock = """{"error":"invalid block selector","code":-32602}"""
        assertEquals(-32602, call(b, "eth_getRawTransactionByBlockNumberAndIndex", """["0x63","0x0"]""").code())
    }

    @Test fun rawTransactions_onABackendWithout_areRefusedForGood() {
        val ios = Backend()
        for ((m, p) in listOf(
            "eth_getRawTransactionByHash" to """["$rawHash"]""",
            "eth_getRawTransactionByBlockNumberAndIndex" to """["0x63","0x0"]""",
            "eth_getRawTransactionByBlockHashAndIndex" to """["0x${"ab".repeat(32)}","0x0"]""",
        )) {
            assertEquals(-32602, call(ios, m, p).code(), m)
        }
        assertNull(ios.lastRawBlock)
    }
}
