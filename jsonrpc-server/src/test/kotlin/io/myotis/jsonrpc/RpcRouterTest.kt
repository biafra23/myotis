package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
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
    }

    private fun route(backend: MyotisRpcBackend?, body: String, proxy: UpstreamProxy? = null): String =
        runBlocking { RpcRouter(proxy, MethodLogger(), backend).handle(body) }

    private fun result(resp: String): String? =
        json.parseToJsonElement(resp).jsonObject["result"]?.jsonPrimitive?.content

    private fun hasError(resp: String): Boolean =
        json.parseToJsonElement(resp).jsonObject["error"] != null

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
