package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 * Router-level tests for the Phase B verified handlers: param decoding, QUANTITY/
 * DATA result encoding, and the proxy/strict fallthrough when the backend can't
 * answer. These pin the exact wire encoding the on-device test can't exercise
 * without a connected snap peer (it correctly degrades to proxy there).
 */
class RpcRouterTest {

    private val json = Json { ignoreUnknownKeys = true }

    /** Configurable fake; records the last eth_call args so we can assert decoding. */
    private class FakeBackend(
        var callResult: ByteArray? = null,
        var balance: BigInteger? = null,
        var nonce: Long? = null,
        var head: Long? = 0x100,
        var code: ByteArray? = null,
        var storage: ByteArray? = null,
    ) : MyotisRpcBackend {
        var lastTo: ByteArray? = null
        var lastData: ByteArray? = null
        var lastBlock: String? = null
        var lastSlot: ByteArray? = null
        override fun chainId() = 1L
        override fun headBlockNumber() = head
        override fun syncState() = "SYNCED"
        override fun call(to: ByteArray, data: ByteArray, block: String): ByteArray? {
            lastTo = to; lastData = data; lastBlock = block; return callResult
        }
        override fun getBalance(address: ByteArray, block: String): BigInteger? = balance
        override fun getTransactionCount(address: ByteArray, block: String): Long? = nonce
        override fun getCode(address: ByteArray, block: String): ByteArray? = code
        override fun getStorageAt(address: ByteArray, slot: ByteArray, block: String): ByteArray? {
            lastSlot = slot; return storage
        }
        var lastRawTx: ByteArray? = null
        var txHash: ByteArray? = null
        override fun sendRawTransaction(rawTx: ByteArray): ByteArray? {
            lastRawTx = rawTx; return txHash
        }
        var lastReceiptTxHash: ByteArray? = null
        var receiptJson: String? = null
        override fun getTransactionReceipt(txHash: ByteArray): String? {
            lastReceiptTxHash = txHash; return receiptJson
        }
        var lastBlockTag: String? = null
        var lastFullTx: Boolean? = null
        var blockJson: String? = null
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? {
            lastBlockTag = block; lastFullTx = fullTransactions; return blockJson
        }
        var gasPriceWei: BigInteger? = null
        override fun gasPrice(): BigInteger? = gasPriceWei
        var tipWei: BigInteger? = null
        override fun maxPriorityFeePerGas(): BigInteger? = tipWei
        var lastFeeBlockCount: Long? = null
        var lastFeeNewest: String? = null
        var lastFeePercentiles: DoubleArray? = null
        var feeHistoryJson: String? = null
        override fun feeHistory(blockCount: Long, newestBlock: String,
                                rewardPercentiles: DoubleArray?): String? {
            lastFeeBlockCount = blockCount; lastFeeNewest = newestBlock
            lastFeePercentiles = rewardPercentiles
            return feeHistoryJson
        }
        var lastEstFrom: ByteArray? = null
        var lastEstTo: ByteArray? = null
        var lastEstData: ByteArray? = null
        var lastEstValue: BigInteger? = null
        var estimateResult: BigInteger? = null
        override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?,
                                 value: BigInteger?): BigInteger? {
            lastEstFrom = from; lastEstTo = to; lastEstData = data; lastEstValue = value
            return estimateResult
        }
    }

    private fun route(backend: MyotisRpcBackend?, body: String, proxy: UpstreamProxy? = null): String =
        runBlocking { RpcRouter(proxy, MethodLogger(), backend).handle(body) }

    private fun result(resp: String): String? =
        json.parseToJsonElement(resp).jsonObject["result"]?.jsonPrimitive?.content

    private fun hasError(resp: String): Boolean =
        json.parseToJsonElement(resp).jsonObject["error"] != null

    private fun errorCode(resp: String): Int =
        json.parseToJsonElement(resp).jsonObject["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt()

    @Test fun ethCall_encodesResultAsData_andDecodesToAndData() {
        val b = FakeBackend(callResult = byteArrayOf(0, 6))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},"latest"]}""")
        assertEquals("0x0006", result(resp))                       // DATA: leading zero kept
        assertEquals(20, b.lastTo!!.size)
        assertEquals(0xA0.toByte(), b.lastTo!![0])
        assertEquals("0x313ce567", b.lastData!!.toHex())           // decoded calldata
        assertEquals("latest", b.lastBlock)
    }

    @Test fun ethCall_acceptsInputAlias_forData() {
        val b = FakeBackend(callResult = byteArrayOf(1))
        route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","input":"0xabcd"}]}""")
        assertEquals("0xabcd", b.lastData!!.toHex())               // "input" honored; block defaults to latest
        assertEquals("latest", b.lastBlock)
    }

    @Test fun ethCall_missingTo_fallsThrough() {                   // contract creation -> proxy/strict
        val b = FakeBackend(callResult = byteArrayOf(9))
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0x00"}]}""")
        assertTrue(hasError(resp))                                 // strict (no proxy) -> error, not the fake result
        assertNull(b.lastTo)                                       // backend never invoked
    }

    @Test fun ethCall_malformedData_fallsThrough() {            // present-but-bad calldata -> proxy, not empty
        val b = FakeBackend(callResult = byteArrayOf(9))
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":"0xZZ"}]}""")
        assertTrue(hasError(resp))
        assertNull(b.lastTo)                                       // backend never invoked
    }

    @Test fun ethCall_nullData_treatedAsEmptyCalldata() {
        val b = FakeBackend(callResult = byteArrayOf(1))
        route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":null}]}""")
        assertEquals(0, b.lastData!!.size)                         // null calldata -> empty, still served
    }

    @Test fun getStorageAt_emptyHexSlot_fallsThrough() {          // "0x" is not a valid slot
        val b = FakeBackend(storage = ByteArray(32))
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt",
               "params":["0xabc0000000000000000000000000000000000001","0x"]}""")
        assertTrue(hasError(resp))
        assertNull(b.lastSlot)
    }

    @Test fun ethCall_backendNull_fallsThrough() {
        val b = FakeBackend(callResult = null)                     // no verified answer
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":"0x00"}]}""")
        assertTrue(hasError(resp))
    }

    @Test fun getBalance_encodesAsQuantity_minimalHex() {
        val b = FakeBackend(balance = BigInteger("1000000000000000000"))   // 1 ETH
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_getBalance",
               "params":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"]}""")
        assertEquals("0xde0b6b3a7640000", result(resp))            // QUANTITY: no leading zeros
    }

    @Test fun getBalance_zero_isHex0() {
        val resp = route(FakeBackend(balance = BigInteger.ZERO),
            """{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0xabc0000000000000000000000000000000000001"]}""")
        assertEquals("0x0", result(resp))
    }

    @Test fun getTransactionCount_encodesNonceAsQuantity() {
        val resp = route(FakeBackend(nonce = 0x1708),
            """{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045","latest"]}""")
        assertEquals("0x1708", result(resp))
    }

    @Test fun getBalance_backendNull_fallsThrough() {
        assertTrue(hasError(route(FakeBackend(balance = null),
            """{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"]}""")))
    }

    @Test fun getCode_encodesBytecodeAsData() {
        val b = FakeBackend(code = byteArrayOf(0x60, 0x80.toByte(), 0x60, 0x40))
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_getCode",
               "params":["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","latest"]}""")
        assertEquals("0x60806040", result(resp))
    }

    @Test fun getCode_emptyForEoa() {
        val resp = route(FakeBackend(code = ByteArray(0)),
            """{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0xabc0000000000000000000000000000000000001"]}""")
        assertEquals("0x", result(resp))
    }

    @Test fun getStorageAt_decodesSlotToWord_andEncodesValueAsData() {
        val b = FakeBackend(storage = ByteArray(32).also { it[31] = 0x2a }) // value 0x2a
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt",
               "params":["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","0x0","latest"]}""")
        // slot "0x0" -> 32-byte zero word
        assertArrayEquals(ByteArray(32), b.lastSlot)
        assertEquals("0x000000000000000000000000000000000000000000000000000000000000002a", result(resp))
    }

    @Test fun getStorageAt_paddsShortSlotKeyTo32Bytes() {
        val b = FakeBackend(storage = ByteArray(32))
        route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt",
               "params":["0xabc0000000000000000000000000000000000001","0x7b","latest"]}""")
        val expected = ByteArray(32).also { it[31] = 0x7b }   // 0x7b right-aligned
        assertArrayEquals(expected, b.lastSlot)
    }

    @Test fun getStorageAt_backendNull_fallsThrough() {
        assertTrue(hasError(route(FakeBackend(storage = null),
            """{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":["0xabc0000000000000000000000000000000000001","0x1"]}""")))
    }

    @Test fun sendRawTransaction_decodesRaw_andReturnsHashAsData() {
        val b = FakeBackend().apply { txHash = ByteArray(32).also { it[31] = 0xfe.toByte() } }
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction",
               "params":["0x02f8650182..."]}""".replace("...", "aabb"))
        assertEquals("0x" + "00".repeat(31) + "fe", result(resp))
        assertEquals("0x02f8650182aabb", b.lastRawTx!!.toHex())   // raw bytes passed through verbatim
    }

    @Test fun sendRawTransaction_noPeer_fallsThrough() {          // backend null -> proxy/strict
        assertTrue(hasError(route(FakeBackend(),                  // txHash defaults to null
            """{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x02aabb"]}""")))
    }

    @Test fun getTransactionReceipt_verified_embedsReceiptObject() {
        val b = FakeBackend().apply {
            receiptJson = """{"status":"0x1","blockNumber":"0x10","transactionHash":"0xab","logs":[]}"""
        }
        val resp = route(b, """{"jsonrpc":"2.0","id":7,"method":"eth_getTransactionReceipt",
            "params":["0x${"ab".repeat(32)}"]}""")
        val obj = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("0x1", obj["status"]!!.jsonPrimitive.content)        // verified object passed through
        assertEquals("0x10", obj["blockNumber"]!!.jsonPrimitive.content)
        assertEquals("0x" + "ab".repeat(32), b.lastReceiptTxHash!!.toHex()) // hash decoded + passed in
    }

    // ---- strict (permissionless, no-proxy) mode -------------------------------------

    @Test fun strict_unimplementedMethod_errorsMethodNotSupported() {
        val resp = route(FakeBackend(),                          // no proxy → strict
            """{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32601, errorCode(resp))                    // not served by this permissionless node
    }

    @Test fun strict_implementedButUnavailable_errorsServerError() {
        val resp = route(FakeBackend(balance = null),            // eth_getBalance handled, backend can't answer
            """{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x${"11".repeat(20)}","latest"]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))                    // supported, but not verifiable right now
    }

    @Test fun strict_getTransactionReceipt_verifiedPending_returnsNullResult_notError() {
        // "null" = verified "not seen yet" (synced, not in recent chain) → result: null.
        val resp = route(FakeBackend().apply { receiptJson = "null" },
            """{"jsonrpc":"2.0","id":7,"method":"eth_getTransactionReceipt","params":["0x${"ab".repeat(32)}"]}""")
        assertTrue(!hasError(resp))                              // pending is a valid verified answer, not an error
        val obj = json.parseToJsonElement(resp).jsonObject
        assertTrue(obj.containsKey("result"))
        assertTrue(obj["result"] is kotlinx.serialization.json.JsonNull)
    }

    @Test fun strict_getTransactionReceipt_cannotVerify_errors() {
        // Kotlin-null (not synced / no peer) → strict error, NOT a misleading null result.
        val resp = route(FakeBackend(),                          // receiptJson defaults to null
            """{"jsonrpc":"2.0","id":7,"method":"eth_getTransactionReceipt","params":["0x${"ab".repeat(32)}"]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))                    // implemented but can't answer right now
    }

    @Test fun getBlockByNumber_verified_embedsBlockObject_andPassesTagAndFlag() {
        val b = FakeBackend().apply { blockJson = """{"number":"0x10","baseFeePerGas":"0x7"}""" }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":["latest",false]}""")
        val obj = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("0x10", obj["number"]!!.jsonPrimitive.content)
        assertEquals("0x7", obj["baseFeePerGas"]!!.jsonPrimitive.content)
        assertEquals("latest", b.lastBlockTag)
        assertEquals(false, b.lastFullTx)
    }

    @Test fun getBlockByNumber_futureBlock_returnsNullResult() {
        // backend returns the literal "null" for a non-existent/future block → result: null.
        val resp = route(FakeBackend().apply { blockJson = "null" },
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":["0x7fffffff",false]}""")
        assertTrue(!hasError(resp))
        assertTrue(json.parseToJsonElement(resp).jsonObject["result"] is kotlinx.serialization.json.JsonNull)
    }

    @Test fun getBlockByNumber_nonBooleanFullTxFlag_fallsThrough() {
        // present-but-non-boolean flag (1) must not be coerced to false → strict error.
        val resp = route(FakeBackend().apply { blockJson = """{"number":"0x1"}""" },
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":["latest",1]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))
    }

    @Test fun getBlockByNumber_cannotVerify_errors() {
        val resp = route(FakeBackend(),  // blockJson null → can't verify → strict error
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":["latest",false]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))
    }

    @Test fun gasPrice_verified_encodesQuantity() {
        val b = FakeBackend().apply { gasPriceWei = BigInteger.valueOf(0x9184e72a000L) } // 10 gwei
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_gasPrice","params":[]}""")
        assertEquals("0x9184e72a000", result(resp))
    }

    @Test fun gasPrice_cannotVerify_errorsRetryable() {
        val resp = route(FakeBackend(), """{"jsonrpc":"2.0","id":1,"method":"eth_gasPrice","params":[]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))                    // implemented, retryable — not -32601
    }

    @Test fun maxPriorityFeePerGas_verified_encodesQuantity() {
        val b = FakeBackend().apply { tipWei = BigInteger.valueOf(100_000_000L) } // 0.1 gwei
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_maxPriorityFeePerGas","params":[]}""")
        assertEquals("0x5f5e100", result(resp))
    }

    @Test fun feeHistory_decodesHexCount_tagAndPercentiles_embedsResult() {
        val b = FakeBackend().apply {
            feeHistoryJson = """{"oldestBlock":"0xfc","baseFeePerGas":["0x7","0x8"],"gasUsedRatio":[0.5]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x5","latest",[10,20.5,30]]}""")
        val obj = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("0xfc", obj["oldestBlock"]!!.jsonPrimitive.content)
        assertEquals(5L, b.lastFeeBlockCount)
        assertEquals("latest", b.lastFeeNewest)
        assertArrayEquals(doubleArrayOf(10.0, 20.5, 30.0), b.lastFeePercentiles!!, 0.0)
    }

    @Test fun feeHistory_acceptsPlainNumberCount_andNoPercentiles() {
        val b = FakeBackend().apply { feeHistoryJson = """{"oldestBlock":"0x1"}""" }
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":[5,"0x100"]}""")
        assertTrue(!hasError(resp))
        assertEquals(5L, b.lastFeeBlockCount)
        assertEquals("0x100", b.lastFeeNewest)
        assertNull(b.lastFeePercentiles)
    }

    @Test fun feeHistory_rejectsBadPercentiles() {
        val b = FakeBackend().apply { feeHistoryJson = """{"oldestBlock":"0x1"}""" }
        // descending percentiles → invalid per EIP-1559 → strict error, backend not invoked
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x5","latest",[30,10]]}""")
        assertTrue(hasError(resp))
        assertNull(b.lastFeeBlockCount)
        // out-of-range percentile
        val resp2 = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x5","latest",[101]]}""")
        assertTrue(hasError(resp2))
        assertNull(b.lastFeeBlockCount)
    }

    @Test fun estimateGas_decodesCallObject_encodesQuantity() {
        val b = FakeBackend().apply { estimateResult = BigInteger.valueOf(21000) }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_estimateGas",
               "params":[{"from":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                          "to":"0x00000000219ab540356cBB839Cbe05303d7705Fa",
                          "value":"0xde0b6b3a7640000","data":"0xab"}]}""")
        assertEquals("0x5208", result(resp))
        assertEquals(0xd8.toByte(), b.lastEstFrom!![0])
        assertEquals(20, b.lastEstTo!!.size)
        assertEquals(BigInteger("de0b6b3a7640000", 16), b.lastEstValue)  // 1 ETH
        assertEquals("0xab", b.lastEstData!!.toHex())
    }

    @Test fun estimateGas_minimalParams_passesNulls() {
        val b = FakeBackend().apply { estimateResult = BigInteger.valueOf(53000) }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_estimateGas",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa"}]}""")
        assertEquals("0xcf08", result(resp))
        assertNull(b.lastEstFrom)
        assertNull(b.lastEstData)
        assertNull(b.lastEstValue)
    }

    @Test fun estimateGas_revertingTx_errors() {
        // Backend null (reverting tx / can't verify) → strict -32000, never a number.
        val resp = route(FakeBackend(),
            """{"jsonrpc":"2.0","id":1,"method":"eth_estimateGas",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa"}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))
    }

    @Test fun strict_batch_returnsPerRequestResponses() {
        // Batch must yield an array of individual responses (JSON-RPC 2.0), each matchable
        // by id — not a single error envelope. Mixes a verified hit and an unsupported method.
        val b = FakeBackend(head = 0x123)
        val resp = route(b, """[
            {"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]},
            {"jsonrpc":"2.0","id":2,"method":"eth_getLogs","params":[{}]}
        ]""")
        val arr = json.parseToJsonElement(resp).jsonArray
        assertEquals(2, arr.size)
        assertEquals("0x123", arr[0].jsonObject["result"]!!.jsonPrimitive.content)        // verified
        assertEquals(-32601, arr[1].jsonObject["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt()) // unsupported
        assertEquals(1, arr[0].jsonObject["id"]!!.jsonPrimitive.content.toInt())          // ids preserved
        assertEquals(2, arr[1].jsonObject["id"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun chainId_and_blockNumber_stillVerified() {
        val b = FakeBackend(head = 0x181af48)
        assertEquals("0x1", result(route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}""")))
        assertEquals("0x181af48", result(route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}""")))
    }

    @Test fun blockNumber_nullHead_fallsThrough() {
        assertTrue(hasError(route(FakeBackend(head = null),
            """{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}""")))
    }

    private fun ByteArray.toHex() = joinToString(prefix = "0x", separator = "") { "%02x".format(it.toInt() and 0xff) }
}
