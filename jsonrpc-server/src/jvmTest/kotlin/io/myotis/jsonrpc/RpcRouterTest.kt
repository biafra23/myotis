package io.myotis.jsonrpc

import io.myotis.api.VerifiedReads
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.put
import kotlinx.serialization.json.booleanOrNull
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

    @Test fun ethCall_withOverride_isServedByAnOverrideCapableBackend_andLabelledSimulated() {
        val b = FakeBackend(callResult = byteArrayOf(0x2a), applyOverrides = true)
        val logger = MethodLogger()
        val resp = runBlocking {
            RpcRouter(null, logger, VerifiedReadsBackend(b)).handle(
                """{"jsonrpc":"2.0","id":1,"method":"eth_call",
                   "params":[{"to":"0x0000000000000000000000000000000000696969","data":"0x24b6b1a5"},
                             "latest",
                             {"0x0000000000000000000000000000000000696969":{"code":"0x6080"}}]}""")
        }
        assertEquals("0x2a", result(resp))
        assertTrue(b.lastOverrides!!.contains("0x6080"))   // reached the backend verbatim
        assertNull(b.lastTo)                               // via the override path, not the plain one
        // Counted as SIMULATED, not VERIFIED: the state underneath was proven,
        // but the answer is the caller's hypothesis, not a chain fact.
        val cov = logger.coverage()["eth_call"]!!.jsonObject
        assertEquals(1, cov["simulated"]!!.jsonPrimitive.content.toInt())
        assertEquals(0, cov["verified"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun ethCall_withoutOverride_staysVerified() {
        val b = FakeBackend(callResult = byteArrayOf(0x2a), applyOverrides = true)
        val logger = MethodLogger()
        runBlocking {
            RpcRouter(null, logger, VerifiedReadsBackend(b)).handle(
                """{"jsonrpc":"2.0","id":1,"method":"eth_call",
                   "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":"0xabcd"},"latest"]}""")
        }
        val cov = logger.coverage()["eth_call"]!!.jsonObject
        assertEquals(1, cov["verified"]!!.jsonPrimitive.content.toInt())
        assertEquals(0, cov["simulated"]!!.jsonPrimitive.content.toInt())
    }

    /** Configurable fake; records the last eth_call args so we can assert decoding. */
    @Test fun ethCall_withStateAndBlockOverrides_isRefused_evenOnACapableBackend() {
        // The regression that matters: with a state override the capable path
        // would otherwise answer, applying the state override and silently
        // leaving the BLOCK context unmodified — labelled SIMULATED, and wrong.
        // (The earlier blockOverrides test uses an incapable backend, so it
        // would still pass with the params[3] gate deleted.)
        val b = FakeBackend(callResult = byteArrayOf(0x2a), applyOverrides = true)
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x0000000000000000000000000000000000696969","data":"0x24b6b1a5"},
                         "latest",
                         {"0x0000000000000000000000000000000000696969":{"code":"0x6080"}},
                         {"time":"0xdeadbeef"}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32602, errorCode(resp))
        assertNull(b.lastOverrides)   // never reached the override path either
    }

    @Test fun capableBackendReturningNull_getsTheRETRYABLEcode_notPermanent() {
        // A capable backend returns null for ordinary reasons — not synced, no
        // peer, out-of-window block, a plain revert. Those are transient, so the
        // client must be told to retry; -32602 would make a wallet stop asking
        // and pin its public-node fallback for the session.
        val b = FakeBackend(callResult = null, applyOverrides = true)
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x0000000000000000000000000000000000696969","data":"0x24b6b1a5"},
                         "latest",
                         {"0x0000000000000000000000000000000000696969":{"code":"0x6080"}}]}""")
        assertEquals(-32000, errorCode(resp))
    }

    @Test fun anImplementationThatDoesNotOverride_inheritsUnsupported() {
        // Pins the property the design calls load-bearing: an engine that simply
        // doesn't implement callWithOverrides inherits the interface default
        // (null / unsupported), so the router refuses permanently instead of
        // answering against unmodified state. Deliberately NOT FakeBackend,
        // which simulates the default with a flag.
        val bare = object : io.myotis.api.VerifiedReads {
            override fun chainId(): Long = 1
            override fun headBlockNumber(): Long = 1
            override fun syncState(): io.myotis.api.SyncState = io.myotis.api.SyncState.SYNCED
            override fun call(f: ByteArray?, t: ByteArray?, d: ByteArray?, v: String?, b: String?) =
                byteArrayOf(0x2a)
            override fun getBalance(a: ByteArray?, b: String?): String? = null
            override fun getTransactionCount(a: ByteArray?, b: String?): Long? = null
            override fun getCode(a: ByteArray?, b: String?): ByteArray? = null
            override fun getStorageAt(a: ByteArray?, s: ByteArray?, b: String?): ByteArray? = null
            override fun sendRawTransaction(r: ByteArray?): ByteArray? = null
            override fun getTransactionReceipt(h: ByteArray?): String? = null
            override fun getTransactionByHash(h: ByteArray?): String? = null
            override fun getBlockByNumber(b: String?, full: Boolean): String? = null
            override fun getBlockByHash(h: ByteArray?, full: Boolean): String? = null
            override fun getBlockReceipts(s: String?): String? = null
            override fun gasPrice(): String? = null
            override fun maxPriorityFeePerGas(): String? = null
            override fun feeHistory(c: Long, n: String?, p: DoubleArray?): String? = null
            override fun estimateGas(f: ByteArray?, t: ByteArray?, d: ByteArray?, v: String?): Long? = null
        }
        assertEquals(false, bare.supportsStateOverrides())
        assertNull(bare.callWithOverrides(null, ByteArray(20), ByteArray(0), null, "latest", "{}"))
    }

    @Test fun malformedStateOverride_isRefusedPermanently_notServedAsVerified() {
        // Each of these would previously have been treated as ABSENT and served
        // by the plain path, counted VERIFIED — a caller-supplied parameter that
        // can change the answer, neither applied nor refused.
        val cases = listOf(
            """"latest"""",                                   // not an object at all
            """{"0xnothex":{"code":"0x60"}}""",              // key isn't an address
            """{"0x0000000000000000000000000000000000696969":"0x6080"}""",  // entry isn't an object
            """{"0x0000000000000000000000000000000000696969":{"nonsense":"0x1"}}""", // unknown field
        )
        cases.forEach { param ->
            val b = FakeBackend(callResult = byteArrayOf(0, 6), applyOverrides = true)
            val resp = route(b,
                """{"jsonrpc":"2.0","id":1,"method":"eth_call",
                   "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},
                             "latest",$param]}""")
            assertTrue(hasError(resp), "served instead of refused: $param")
            // -32602 permanent: the engine's parser would reject it too, but that
            // crosses the backend boundary as a bare null and would read retryable.
            assertEquals(-32602, errorCode(resp), "wrong code for: $param")
            assertNull(b.lastTo, "reached the plain path: $param")
            assertNull(b.lastOverrides, "reached the override path: $param")
        }
    }

    @Test fun noOpStateOverrideShapes_areServedNormally() {
        // Absent, explicit null, an empty map, an address mapped to an empty
        // object, and an address mapped to null (geth reads null as a
        // zero-valued override) all change nothing — refusing them would break
        // clients that always fill the positional slot.
        listOf(
            "", """,null""", """,{}""",
            """,{"0x0000000000000000000000000000000000696969":{}}""",
            """,{"0x0000000000000000000000000000000000696969":null}""",
        ).forEach { tail ->
            val b = FakeBackend(callResult = byteArrayOf(0, 6), applyOverrides = true)
            val resp = route(b,
                """{"jsonrpc":"2.0","id":1,"method":"eth_call",
                   "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},
                             "latest"$tail]}""")
            assertEquals("0x0006", result(resp), "not served for tail: $tail")
            assertNull(b.lastOverrides, "took the override path for a no-op: $tail")
        }
    }

    private class FakeBackend(
        var callResult: ByteArray? = null,
        /** When true this fake CAN apply overrides (the engine-backed case);
         *  when false it inherits the interface default (null = unsupported). */
        private val applyOverrides: Boolean = false,
        var balance: BigInteger? = null,
        var nonce: Long? = null,
        var head: Long? = 0x100,
        var code: ByteArray? = null,
        var storage: ByteArray? = null,
    ) : io.myotis.api.VerifiedReads {
        // The fake keeps values as BigInteger for the assertions below; VerifiedReads
        // speaks decimal-string wei and byte[] hashes, so it converts at the boundary
        // exactly as the real VerifiedRpcBackend does.
        var lastFrom: ByteArray? = null
        var lastTo: ByteArray? = null
        var lastData: ByteArray? = null
        var lastValue: BigInteger? = null
        var lastBlock: String? = null
        var lastSlot: ByteArray? = null
        override fun chainId() = 1L
        override fun headBlockNumber() = head
        var syncStateValue = io.myotis.api.SyncState.SYNCED
        override fun syncState() = syncStateValue
        var lastOverrides: String? = null

        override fun call(from: ByteArray?, to: ByteArray?, data: ByteArray,
                          valueWei: String?, block: String): ByteArray? {
            lastFrom = from; lastTo = to; lastData = data
            lastValue = valueWei?.let { BigInteger(it) }; lastBlock = block
            return callResult
        }
        override fun supportsStateOverrides(): Boolean = applyOverrides

        override fun callWithOverrides(from: ByteArray?, to: ByteArray?, data: ByteArray,
                                       valueWei: String?, block: String,
                                       stateOverridesJson: String): ByteArray? {
            if (!applyOverrides) return null   // the interface default: unsupported
            lastOverrides = stateOverridesJson
            return callResult
        }
        override fun getBalance(address: ByteArray, block: String): String? = balance?.toString()
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
        var lastByHashTxHash: ByteArray? = null
        var txByHashJson: String? = null
        override fun getTransactionByHash(txHash: ByteArray): String? {
            lastByHashTxHash = txHash; return txByHashJson
        }
        var lastBlockTag: String? = null
        var lastFullTx: Boolean? = null
        var blockJson: String? = null
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? {
            lastBlockTag = block; lastFullTx = fullTransactions; return blockJson
        }
        var lastBlockHash: ByteArray? = null
        var blockByHashJson: String? = null
        override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? {
            lastBlockHash = blockHash32; lastFullTx = fullTransactions; return blockByHashJson
        }
        var lastReceiptsSelector: String? = null
        var blockReceiptsJson: String? = null
        override fun getBlockReceipts(blockSelector: String): String? {
            lastReceiptsSelector = blockSelector; return blockReceiptsJson
        }
        var gasPriceWei: BigInteger? = null
        override fun gasPrice(): String? = gasPriceWei?.toString()
        var tipWei: BigInteger? = null
        override fun maxPriorityFeePerGas(): String? = tipWei?.toString()
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
        var estimateResult: Long? = null
        override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?,
                                 valueWei: String?): Long? {
            lastEstFrom = from; lastEstTo = to; lastEstData = data
            lastEstValue = valueWei?.let { BigInteger(it) }
            return estimateResult
        }
    }

    private fun route(backend: io.myotis.api.VerifiedReads?, body: String, proxy: UpstreamProxy? = null): String =
        runBlocking { RpcRouter(proxy, MethodLogger(), backend?.let { VerifiedReadsBackend(it) }).handle(body) }

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

    // --- state overrides (#314) -------------------------------------------------
    // The wallet failure this prevents: Ambire reads account state by injecting a
    // helper's bytecode via an override and calling a magic address. Ignoring the
    // override returns `0x` — a well-formed answer to a DIFFERENT question — and the
    // wallet reports "account state update error" with nothing to go on.

    @Test fun ethCall_withStateOverride_isRefused_notSilentlyAnswered() {
        val b = FakeBackend(callResult = byteArrayOf(1))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x0000000000000000000000000000000000696969","data":"0x24b6b1a5"},
                         "latest",
                         {"0x0000000000000000000000000000000000696969":{"code":"0x6080"}}]}""")
        assertTrue(hasError(resp))
        // -32602, NOT the retryable -32000: no retry can make this succeed on this
        // build, and a client backing off would spin instead of taking its fallback.
        assertEquals(-32602, errorCode(resp))
        // The backend must not have been consulted at all: answering from unmodified
        // state is the bug, so the call never reaches it.
        assertNull(b.lastTo)
    }

    @Test fun ethEstimateGas_withStateOverride_isRefused() {
        val b = FakeBackend(callResult = byteArrayOf(1))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_estimateGas",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":"0xabcd"},
                         "latest",
                         {"0x00000000219ab540356cBB839Cbe05303d7705Fa":{"balance":"0x1"}}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32602, errorCode(resp))
        // The assertion that actually pins the claim: the backend is never
        // consulted. Without it this would still pass if the gate moved below
        // tryVerified and the refusal became "estimate, then discard".
        assertNull(b.lastEstTo)
    }

    @Test fun ethCall_withBlockOverrides_isAlsoRefused() {
        // geth's fourth positional parameter rewrites number/time/baseFee — it
        // changes the answer exactly as a state override does, so checking only
        // index 2 would leave the same silent-wrong-answer hole for time-warp
        // simulations (vesting cliffs, deadlines, TWAP windows).
        val b = FakeBackend(callResult = byteArrayOf(1))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":"0xabcd"},
                         "latest",{},{"time":"0x deadbeef"}]}""".replace(" deadbeef", "deadbeef"))
        assertTrue(hasError(resp))
        assertEquals(-32602, errorCode(resp))
        assertNull(b.lastTo)
    }

    @Test fun ethCall_withOverride_stillReachesTheDevProxy() {
        // Proxy mode is unverified by construction, and an upstream DOES apply
        // the override — so forwarding is the CORRECT answer there. The rule is
        // "never fabricate one from unmodified state", not "never answer".
        // Without this, bringing a wallet up against a still-syncing node in dev
        // mode would break exactly where it used to work.
        //
        // UpstreamProxy is final and owns a real client, so this asserts the
        // ROUTING: with a proxy configured the request must reach the proxy
        // branch (which then fails to connect -> -32603) instead of being
        // short-circuited with the strict-mode -32602.
        val b = FakeBackend(callResult = byteArrayOf(9))
        val unreachable = UpstreamProxy("http://127.0.0.1:1/")
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x0000000000000000000000000000000000696969","data":"0x24b6b1a5"},
                         "latest",
                         {"0x0000000000000000000000000000000000696969":{"code":"0x6080"}}]}""",
            proxy = unreachable)
        assertTrue(hasError(resp))
        assertEquals(-32603, errorCode(resp))   // proxy attempted, upstream unreachable
        assertNull(b.lastTo)                    // never answered from unmodified state
        unreachable.close()
    }

    @Test fun ethCall_withNullThirdParam_isServedNormally() {
        // A library that always fills the positional slot sends an explicit
        // null. Handled today (`as? JsonObject` on JsonNull -> no override), but
        // unpinned a rewrite to e.g. `getOrNull(2) != null` would break it.
        val b = FakeBackend(callResult = byteArrayOf(0, 6))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},
                         "latest",null]}""")
        assertEquals("0x0006", result(resp))
    }

    @Test fun ethCall_withOverrideNamingAnAccountButChangingNothing_isServedNormally() {
        // `{"0x…":{}}` is a non-empty MAP whose only entry changes nothing. The
        // gate refuses what would alter execution, not what merely mentions an
        // address.
        val b = FakeBackend(callResult = byteArrayOf(0, 6))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},
                         "latest",{"0x0000000000000000000000000000000000696969":{}}]}""")
        assertEquals("0x0006", result(resp))
    }

    @Test fun batchElement_withOverride_isRefusedIndividually() {
        // The gate lives in handleOne, so it applies per element — and a batch is
        // where a regression would be least visible (MetaMask batches heavily).
        val b = FakeBackend(callResult = byteArrayOf(0, 6))
        val resp = route(b,
            """[{"jsonrpc":"2.0","id":1,"method":"eth_call",
                "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},"latest"]},
               {"jsonrpc":"2.0","id":2,"method":"eth_call",
                "params":[{"to":"0x0000000000000000000000000000000000696969","data":"0x24b6b1a5"},
                          "latest",{"0x0000000000000000000000000000000000696969":{"code":"0x6080"}}]}]""")
        val arr = json.parseToJsonElement(resp).jsonArray
        assertEquals("0x0006", arr[0].jsonObject["result"]!!.jsonPrimitive.content)
        assertEquals(-32602, arr[1].jsonObject["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt())
    }

    @Test fun ethCall_withEmptyOverrideObject_isServedNormally() {
        // An empty object changes nothing, so refusing it would break callers that
        // always send the parameter.
        val b = FakeBackend(callResult = byteArrayOf(0, 6))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},
                         "latest",{}]}""")
        assertEquals("0x0006", result(resp))
    }

    @Test fun ethCall_threadsFromAndValue_toBackend() {            // confirm-screen sim: msg.sender + value
        val b = FakeBackend(callResult = byteArrayOf(0, 6))
        route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"from":"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                          "to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                          "data":"0xa9059cbb","value":"0x0"},"latest"]}""")
        assertEquals(20, b.lastFrom!!.size)                        // from decoded + passed through
        assertEquals(0xd8.toByte(), b.lastFrom!![0])
        assertEquals(BigInteger.ZERO, b.lastValue)                 // value decoded
    }

    @Test fun ethCall_absentFrom_passesNull() {                    // anonymous read -> backend's zero-addr default
        val b = FakeBackend(callResult = byteArrayOf(1))
        route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","data":"0xabcd"}]}""")
        assertNull(b.lastFrom)                                     // no from -> null (not zero-length)
        assertNull(b.lastValue)                                    // no value -> null
    }

    @Test fun ethCall_acceptsInputAlias_forData() {
        val b = FakeBackend(callResult = byteArrayOf(1))
        route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x00000000219ab540356cBB839Cbe05303d7705Fa","input":"0xabcd"}]}""")
        assertEquals("0xabcd", b.lastData!!.toHex())               // "input" honored; block defaults to latest
        assertEquals("latest", b.lastBlock)
    }

    @Test fun ethCall_missingTo_isServedAsContractCreation() {
        // CHANGED deliberately: a `to`-less eth_call is contract creation — the
        // calldata is init code and its return data is the answer. It used to
        // fall through to proxy/strict, which left wallets using the deployless
        // Deploy form (Ambire picks it whenever a network is flagged
        // rpcNoStateOverride) unable to read account state at all.
        val b = FakeBackend(callResult = byteArrayOf(9))
        val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0x00"}]}""")
        assertEquals("0x09", result(resp))
        assertNull(b.lastTo)                                       // null `to` reached the backend as creation
        assertEquals("0x00", b.lastData!!.toHex())
    }

    @Test fun ethCall_explicitNullTo_isAlsoCreation() {
        val b = FakeBackend(callResult = byteArrayOf(9))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":null,"data":"0x00"}]}""")
        assertEquals("0x09", result(resp))
    }

    @Test fun ethCall_malformedTo_isStillRefused() {
        // Present-but-bad is not creation: serving it as one would run init code
        // the caller never asked to run.
        val b = FakeBackend(callResult = byteArrayOf(9))
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xZZ","data":"0x00"}]}""")
        assertTrue(hasError(resp))
        assertNull(b.lastData)
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
            """{"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32601, errorCode(resp))                    // not served by this permissionless node
    }

    // ---- eth_getLogs (opt-in watch-list index) ---------------------------------------

    @Test fun getLogs_backendWithoutIndex_errorsRetryable() {
        val resp = route(FakeBackend(),                          // default getLogs = null
            """{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"address":"0x${"11".repeat(20)}"}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))                    // verified method, can't serve now
    }

    @Test fun getLogs_engineErrorEnvelope_surfacesMessageAt32000() {
        val backend = object : VerifiedReads by FakeBackend() {
            override fun getLogs(filterJson: String?): String =
                """{"error":"requested range is not indexed yet (covered: 100-200); retry as the index catches up"}"""
        }
        val resp = route(backend,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"address":"0x${"11".repeat(20)}"}]}""")
        assertTrue(hasError(resp))
        assertEquals(-32000, errorCode(resp))
        assertTrue(resp.contains("covered: 100-200"))
    }

    @Test fun getLogs_arrayPassthrough_isResult() {
        val logs = """[{"address":"0x${"11".repeat(20)}","topics":[],"data":"0x","blockNumber":"0x64","blockHash":"0x${"22".repeat(32)}","transactionHash":"0x${"33".repeat(32)}","transactionIndex":"0x0","logIndex":"0x0","removed":false}]"""
        val backend = object : VerifiedReads by FakeBackend() {
            override fun getLogs(filterJson: String?): String = logs
        }
        val resp = route(backend,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"address":"0x${"11".repeat(20)}"}]}""")
        assertTrue(!hasError(resp))
        assertTrue(resp.contains("\"logIndex\":\"0x0\""))
    }

    @Test fun getLogs_missingFilterObject_isInvalidParams() {
        val resp = route(FakeBackend(),
            """{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[]}""")
        assertTrue(hasError(resp))
        assertEquals(-32602, errorCode(resp))                    // permanent, not retryable
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

    @Test fun getBlockReceipts_verified_passesSelectorAndEmbedsArray() {
        val b = FakeBackend()
        b.blockReceiptsJson = """[{"transactionHash":"0x11","status":"0x1"}]"""
        val resp = route(b,
            """{"jsonrpc":"2.0","id":7,"method":"eth_getBlockReceipts","params":["0x1406f40"]}""")
        assertEquals("0x1406f40", b.lastReceiptsSelector)
        assertTrue(resp.contains("\"transactionHash\":\"0x11\""), resp)
        // The result embeds as a JSON ARRAY, not a string.
        assertTrue(resp.contains("\"result\":[{"), resp)
    }

    @Test fun getBlockReceipts_absentParam_defaultsLatest() {
        val b = FakeBackend()
        b.blockReceiptsJson = "[]"
        route(b, """{"jsonrpc":"2.0","id":7,"method":"eth_getBlockReceipts","params":[]}""")
        assertEquals("latest", b.lastReceiptsSelector)
    }

    @Test fun getBlockReceipts_verifiedUnknownBlock_embedsNull() {
        val b = FakeBackend()
        b.blockReceiptsJson = "null"
        val resp = route(b,
            """{"jsonrpc":"2.0","id":7,"method":"eth_getBlockReceipts","params":["0xfffffff"]}""")
        assertTrue(resp.contains("\"result\":null"), resp)
    }

    @Test fun getBlockReceipts_backendNull_isStrictError() {
        val resp = route(FakeBackend(),
            """{"jsonrpc":"2.0","id":7,"method":"eth_getBlockReceipts","params":["latest"]}""")
        assertTrue(hasError(resp), resp)
        assertEquals(-32000, errorCode(resp))
    }

    @Test fun getBlockByHash_verified_decodesHashToBytes_andEmbedsBlock() {
        // VerifiedReads takes the block hash as 32 bytes: the router must decode the 0x-hex
        // param (case-insensitively) and hand the backend the raw bytes.
        val b = FakeBackend().apply { blockByHashJson = """{"number":"0x10"}""" }
        val hash = "0x" + "Ab".repeat(32)  // mixed case
        val resp = route(b,
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByHash","params":["$hash",false]}""")
        val obj = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("0x10", obj["number"]!!.jsonPrimitive.content)
        assertEquals(32, b.lastBlockHash!!.size)
        assertEquals(0xAB.toByte(), b.lastBlockHash!![0])  // decoded, case-folded
        assertEquals(false, b.lastFullTx)
    }

    @Test fun getBlockByHash_malformedHash_fallsThrough() {
        // A non-hex / odd-length hash can't decode to bytes → the router falls through
        // (strict error) rather than reaching the backend.
        val b = FakeBackend().apply { blockByHashJson = """{"number":"0x10"}""" }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByHash","params":["0xnothex",false]}""")
        assertTrue(hasError(resp))
        assertNull(b.lastBlockHash)  // backend never called
    }

    @Test fun getBlockByHash_wrongLengthHash_fallsThrough() {
        // Valid hex but not 32 bytes ("0x1234") must also fall through — the contract's
        // parameter is exactly 32 bytes; a short hash names nothing verifiable.
        val b = FakeBackend().apply { blockByHashJson = """{"number":"0x10"}""" }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByHash","params":["0x1234",false]}""")
        assertTrue(hasError(resp))
        assertNull(b.lastBlockHash)  // backend never called
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
        val b = FakeBackend().apply { estimateResult = 21000L }
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
        val b = FakeBackend().apply { estimateResult = 53000L }
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
            {"jsonrpc":"2.0","id":2,"method":"eth_newFilter","params":[{}]}
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

    @Test fun syncing_synced_isFalse() {
        // The spec's "not syncing" is the JSON BOOLEAN false — parse the
        // envelope and check the literal, not a substring.
        val resp = route(FakeBackend(head = 0x181af48),
            """{"jsonrpc":"2.0","id":1,"method":"eth_syncing","params":[]}""")
        val result = json.parseToJsonElement(resp).jsonObject["result"]
        assertEquals(false, result?.jsonPrimitive?.booleanOrNull, resp)
    }

    @Test fun syncing_notSynced_reportsTruthyObjectWithZeroBounds() {
        // The probe must answer promptly from syncState() alone — never a
        // wake-holding head read — so the object carries zero bounds (no reads
        // are served before SYNCED anyway); its truthy-ness is the signal.
        for (state in listOf(io.myotis.api.SyncState.CATCHING_UP, io.myotis.api.SyncState.SYNCING)) {
            val b = FakeBackend(head = 0x181af48)
            b.syncStateValue = state
            val resp = route(b, """{"jsonrpc":"2.0","id":1,"method":"eth_syncing","params":[]}""")
            val result = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
            assertEquals("0x0", result["startingBlock"]?.jsonPrimitive?.content, resp)
            assertEquals("0x0", result["currentBlock"]?.jsonPrimitive?.content, resp)
            assertEquals("0x0", result["highestBlock"]?.jsonPrimitive?.content, resp)
        }
    }

    // ---- compat batch ----

    @Test fun accounts_isExactlyEmpty() {
        val resp = route(FakeBackend(), """{"jsonrpc":"2.0","id":1,"method":"eth_accounts","params":[]}""")
        assertEquals(0, json.parseToJsonElement(resp).jsonObject["result"]!!.jsonArray.size, resp)
    }

    @Test fun netListening_isTrue() {
        val resp = route(FakeBackend(), """{"jsonrpc":"2.0","id":1,"method":"net_listening","params":[]}""")
        assertEquals(true, json.parseToJsonElement(resp).jsonObject["result"]?.jsonPrimitive?.booleanOrNull, resp)
    }

    @Test fun netPeerCount_fromStatusSnapshot() {
        val sr = object : RpcStatusSource {
            override fun uptimeSeconds() = 5L
            override fun statusJson(uptimeSeconds: Long) =
                buildJsonObject { put("connectedPeers", JsonPrimitive(7)) }
            override fun beaconStatusJson(uptimeSeconds: Long) = buildJsonObject {}
        }
        val resp = runBlocking {
            RpcRouter(null, MethodLogger(), VerifiedReadsBackend(FakeBackend()), sr)
                .handle("""{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}""")
        }
        assertEquals("0x7", result(resp))
    }

    @Test fun netPeerCount_withoutStatusSource_isStrictError() {
        // No status source → -32000 ("can't answer right now"), never a fabricated 0x0.
        val resp = route(FakeBackend(), """{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}""")
        assertEquals(-32000, errorCode(resp))
    }

    @Test fun web3Sha3_keccaksTheDataParam() {
        // keccak256(0x68656c6c6f20776f726c64 = "hello world") — a public vector.
        val resp = route(FakeBackend(),
            """{"jsonrpc":"2.0","id":1,"method":"web3_sha3","params":["0x68656c6c6f20776f726c64"]}""")
        assertEquals("0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad", result(resp))
    }

    @Test fun blockTransactionCount_countsTxArray_hashesForm() {
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":["0xaa","0xbb","0xcc"],"uncles":[]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getBlockTransactionCountByNumber","params":["0x10"]}""")
        assertEquals("0x3", result(resp))
        assertEquals(false, b.lastFullTx)   // counting needs only the hashes form
        assertEquals("0x10", b.lastBlockTag)
    }

    @Test fun blockTransactionCount_unknownBlock_isNullResult() {
        val b = FakeBackend().apply { blockJson = "null" }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getBlockTransactionCountByNumber","params":["0x10"]}""")
        assertEquals(true, json.parseToJsonElement(resp).jsonObject["result"] is JsonNull, resp)
    }

    @Test fun txByBlockNumberAndIndex_picksTheEmbeddedObject() {
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[{"hash":"0xaa"},{"hash":"0xbb"}],"uncles":[]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByBlockNumberAndIndex","params":["0x10","0x1"]}""")
        val tx = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("0xbb", tx["hash"]?.jsonPrimitive?.content, resp)
        assertEquals(true, b.lastFullTx)    // the lookup needs full tx objects
    }

    @Test fun txByBlockNumberAndIndex_pastEnd_isNullResult() {
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[{"hash":"0xaa"}],"uncles":[]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByBlockNumberAndIndex","params":["0x10","0x5"]}""")
        assertEquals(true, json.parseToJsonElement(resp).jsonObject["result"] is JsonNull, resp)
    }

    @Test fun txByBlockHashAndIndex_threadsTheHash() {
        val b = FakeBackend().apply {
            blockByHashJson = """{"number":"0x10","transactions":[{"hash":"0xaa"}],"uncles":[]}"""
        }
        val hash = "0x" + "ab".repeat(32)
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByBlockHashAndIndex","params":["$hash","0x0"]}""")
        val tx = json.parseToJsonElement(resp).jsonObject["result"]!!.jsonObject
        assertEquals("0xaa", tx["hash"]?.jsonPrimitive?.content, resp)
        assertEquals(hash, b.lastBlockHash!!.toHex())
    }

    @Test fun uncleCount_isZeroForServedBlocks() {
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[],"uncles":[]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getUncleCountByBlockNumber","params":["0x10"]}""")
        assertEquals("0x0", result(resp))
    }

    @Test fun uncleByIndex_isNullResult_neverAnObject() {
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[],"uncles":[]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getUncleByBlockNumberAndIndex","params":["0x10","0x0"]}""")
        assertEquals(true, json.parseToJsonElement(resp).jsonObject["result"] is JsonNull, resp)
    }

    @Test fun compatByNumber_bareNumericSelector_isStrictError() {
        // A JSON-number (or bare-string) selector must not reach the backend: the
        // engines' bare-numeric conventions differ (Java decimal vs Rust hex), so
        // only spec-shaped selectors pass — same gate as eth_getBlockReceipts.
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[],"uncles":[]}"""
        }
        for (params in listOf("""[291]""", """["291"]""")) {
            val resp = route(b,
                """{"jsonrpc":"2.0","id":1,"method":"eth_getBlockTransactionCountByNumber","params":$params}""")
            assertEquals(-32000, errorCode(resp))
            assertNull(b.lastBlockTag) // never reached the backend
        }
    }

    @Test fun txByIndex_hugeButWellFormedIndex_isNullResult() {
        // A well-formed QUANTITY beyond any real list (incl. leading-zero forms)
        // is "past the end" → eth's null result, not a retryable-looking error.
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[{"hash":"0xaa"}],"uncles":[]}"""
        }
        for (idx in listOf("0x100000000", "0x0000000001")) {
            val resp = route(b,
                """{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByBlockNumberAndIndex","params":["0x10","$idx"]}""")
            val result = json.parseToJsonElement(resp).jsonObject["result"]
            if (idx == "0x0000000001") {
                // leading zeros are still index 1 → past this 1-tx list's end → null
                assertEquals(true, result is JsonNull, resp)
            } else {
                assertEquals(true, result is JsonNull, resp)
            }
        }
    }

    @Test fun compatMethods_malformedIndex_isStrictError() {
        // A JSON-number index (not the spec's 0x-hex string) must not be coerced.
        val b = FakeBackend().apply {
            blockJson = """{"number":"0x10","transactions":[{"hash":"0xaa"}],"uncles":[]}"""
        }
        val resp = route(b,
            """{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByBlockNumberAndIndex","params":["0x10",1]}""")
        assertEquals(-32000, errorCode(resp))
    }

    private fun ByteArray.toHex() = joinToString(prefix = "0x", separator = "") { "%02x".format(it.toInt() and 0xff) }
}
