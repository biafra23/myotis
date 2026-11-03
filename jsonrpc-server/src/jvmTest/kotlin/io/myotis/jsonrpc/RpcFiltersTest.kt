package io.myotis.jsonrpc

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/**
 * The polled filter family (#714) through the router, over a modelled chain:
 * block and log filters, refusal at creation, expiry, stalls, reorgs delivered
 * as `removed: true`, and the bounds.
 */
class RpcFiltersTest {

    private val json = Json { ignoreUnknownKeys = true }

    private val watched = "0x" + "aa".repeat(20)
    private val unwatched = "0x" + "bb".repeat(20)

    /**
     * A chain the test edits: [blocks] holds the canonical chain by number
     * (hash, parent), each block carrying [logsPer] logs from [watched]. The log
     * index watches [watched] only and covers [coveredFrom] up to the head.
     */
    private class Chain(head: Long) : RpcBackend {
        val blocks = sortedMapOf<Long, Pair<String, String>>()
        var head: Long? = head
        var coveredFrom = 1L
        var logsPer = 1
        var indexLagsAt: Long? = null
        val logQueries = ArrayList<String>()

        init { for (n in 1..head) blocks[n] = hash(n, 'a') to hash(n - 1, 'a') }

        /** Replace the canonical chain from [from] up to [to] with branch [branch]. */
        fun reorg(from: Long, to: Long, branch: Char) {
            blocks.keys.filter { it >= from }.forEach { blocks.remove(it) }
            for (n in from..to) blocks[n] = hash(n, branch) to (blocks[n - 1]?.first ?: hash(n - 1, 'a'))
            head = to
        }

        fun extend(to: Long) {
            for (n in (blocks.lastKey() + 1)..to) blocks[n] = hash(n, 'c') to blocks[n - 1]!!.first
            head = to
        }

        companion object {
            fun hash(n: Long, branch: Char): String =
                "0x" + branch.toString().repeat(2) + n.toString(16).padStart(62, '0')
        }

        override fun chainId(): Long = 1
        override fun headBlockNumber(): Long? = head
        override fun syncState(): RpcSyncState = RpcSyncState.SYNCED
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? {
            val n = block.removePrefix("0x").toLong(16)
            val (h, p) = blocks[n] ?: return "null"
            return """{"number":"0x${n.toString(16)}","hash":"$h","parentHash":"$p","transactions":[]}"""
        }

        override fun getLogs(filterJson: String): String {
            logQueries += filterJson
            val f = Json.parseToJsonElement(filterJson).jsonObject
            val address = f["address"]?.jsonPrimitive?.content?.lowercase()
            if (address != "0x" + "aa".repeat(20)) {
                return """{"error":"address is not on this node's log watch-list"}"""
            }
            val h = head ?: return """{"error":"no verified head yet"}"""
            fun bound(key: String): Long = when (val v = f[key]?.jsonPrimitive?.contentOrNull) {
                null, "latest", "pending" -> h
                "earliest" -> 0
                else -> v.removePrefix("0x").toLong(16)
            }
            val from = bound("fromBlock")
            val to = bound("toBlock")
            if (from < coveredFrom || to > h || (indexLagsAt != null && to >= indexLagsAt!!)) {
                return """{"error":"requested range is not indexed yet (covered: $coveredFrom-$h); retry as the index catches up"}"""
            }
            val out = StringBuilder("[")
            for (n in from..to) {
                val (bh, _) = blocks[n] ?: continue
                for (i in 0 until logsPer) {
                    if (out.length > 1) out.append(',')
                    out.append("""{"address":"$address","topics":[],"data":"0x0$i","blockNumber":"0x${n.toString(16)}",""" +
                        """"blockHash":"$bh","transactionHash":"0x${"cc".repeat(32)}","transactionIndex":"0x0",""" +
                        """"logIndex":"0x$i","removed":false}""")
                }
            }
            return out.append(']').toString()
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
    }

    private val clock = TestTimeSource()

    private fun router(chain: Chain, filters: RpcFilters = RpcFilters(clock)) =
        RpcRouter(null, MethodLogger(), chain, null, null, filters)

    private fun RpcRouter.call(method: String, params: String = "[]"): JsonObject = runBlocking {
        json.parseToJsonElement(handle("""{"jsonrpc":"2.0","id":1,"method":"$method","params":$params}""")).jsonObject
    }

    private fun JsonObject.resultArray(): JsonArray {
        assertTrue(this["error"] == null, "unexpected error: $this")
        return this["result"]!!.jsonArray
    }

    private fun JsonObject.code(): Int = this["error"]!!.jsonObject["code"]!!.jsonPrimitive.content.toInt()
    private fun JsonObject.message(): String = this["error"]!!.jsonObject["message"]!!.jsonPrimitive.content
    private fun JsonObject.id(): String = this["result"]!!.jsonPrimitive.content

    private fun logFilter(r: RpcRouter, extra: String = ""): String =
        r.call("eth_newFilter", """[{"address":"$watched"$extra}]""").id()

    private fun JsonArray.blockNumbers(): List<Long> =
        map { it.jsonObject["blockNumber"]!!.jsonPrimitive.content.removePrefix("0x").toLong(16) }

    private fun JsonArray.removedFlags(): List<Boolean> =
        map { it.jsonObject["removed"]!!.jsonPrimitive.booleanOrNull!! }

    // ---- block filters ----------------------------------------------------

    @Test fun blockFilter_deliversEachNewHeadOnce_inOrder() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = r.call("eth_newBlockFilter").id()
        // geth's form: no leading zeros, so 1 to 16 digits (and not "0x0").
        assertTrue(id.matches(Regex("0x[1-9a-f][0-9a-f]{0,15}")), id)
        assertEquals(0, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
        chain.extend(13)   // the head jumped three blocks: all three are delivered
        val hashes = r.call("eth_getFilterChanges", """["$id"]""").resultArray().map { it.jsonPrimitive.content }
        assertEquals((11L..13L).map { chain.blocks[it]!!.first }, hashes)
        assertEquals(0, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
    }

    @Test fun blockFilter_headGoingBack_isNoReorg_andDeliversNothing() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = r.call("eth_newBlockFilter").id()
        chain.extend(12)
        assertEquals(2, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
        chain.head = 11    // this node's head view regressed; block 12 is not orphaned
        assertEquals(0, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
        chain.extend(13)
        val again = r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        assertEquals(listOf(chain.blocks[13L]!!.first), again.map { it.jsonPrimitive.content })
    }

    @Test fun blockFilter_hasNoLogs() {
        val r = router(Chain(head = 10))
        val id = r.call("eth_newBlockFilter").id()
        val resp = r.call("eth_getFilterLogs", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertEquals("filter not found", resp.message())
    }

    // ---- log filters ------------------------------------------------------

    @Test fun logFilter_deliversOnlyLogsAfterCreation_andGetFilterLogsIsGetLogs() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r, ""","fromBlock":"0x5"""")
        chain.extend(12)
        val changes = r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        assertEquals(listOf(11L, 12L), changes.blockNumbers())
        assertTrue(changes.removedFlags().none { it })
        // The changes query asked the index for exactly the new blocks.
        val last = json.parseToJsonElement(chain.logQueries.last()).jsonObject
        assertEquals("0xb", last["fromBlock"]!!.jsonPrimitive.content)
        assertEquals("0xc", last["toBlock"]!!.jsonPrimitive.content)
        // eth_getFilterLogs: the filter's own range, from block 5 to the head.
        assertEquals((5L..12L).toList(), r.call("eth_getFilterLogs", """["$id"]""").resultArray().blockNumbers())
        assertEquals(0, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
    }

    @Test fun logFilter_withAFutureFromBlock_isInstalled_andWaitsForIt() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r, ""","fromBlock":"0xc"""")
        assertEquals(0, r.call("eth_getFilterLogs", """["$id"]""").resultArray().size)   // no such block yet
        chain.extend(13)
        assertEquals(listOf(12L, 13L), r.call("eth_getFilterChanges", """["$id"]""").resultArray().blockNumbers())
        assertEquals(listOf(12L, 13L), r.call("eth_getFilterLogs", """["$id"]""").resultArray().blockNumbers())
        // An unwatched address is still refused, whatever the range.
        assertEquals(-32000, r.call("eth_newFilter", """[{"address":"$unwatched","fromBlock":"0x20"}]""").code())
    }

    @Test fun logFilter_toBlockBound_stopsDelivery() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r, ""","toBlock":"0xb"""")
        chain.extend(13)
        assertEquals(listOf(11L), r.call("eth_getFilterChanges", """["$id"]""").resultArray().blockNumbers())
        chain.extend(15)
        assertEquals(0, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
    }

    @Test fun logFilter_onAnUnindexedAddress_isRefusedAtCreation() {
        val chain = Chain(head = 10)
        val filters = RpcFilters(clock)
        val r = router(chain, filters)
        val resp = r.call("eth_newFilter", """[{"address":"$unwatched"}]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("watch-list"), resp.message())
        assertEquals(0, runBlocking { filters.size() })
    }

    @Test fun logFilter_overAnUncoveredRange_isRefusedAtCreation_withTheCoverage() {
        val chain = Chain(head = 10).apply { coveredFrom = 8 }
        val filters = RpcFilters(clock)
        val r = router(chain, filters)
        val resp = r.call("eth_newFilter", """[{"address":"$watched","fromBlock":"0x2"}]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("covered: 8-10"), resp.message())
        assertEquals(0, runBlocking { filters.size() })
    }

    @Test fun logFilter_selectorsItCannotApply_areRefused() {
        val r = router(Chain(head = 10))
        for (bad in listOf(
            ""","blockHash":"0x${"11".repeat(32)}"""",
            ""","fromBlock":"finalized"""",
            ""","toBlock":"safe"""",
            ""","toBlock":"earliest"""",
            ""","fromBlock":"12"""",
            ""","fromBlock":"0x9","toBlock":"0x8"""",
            ""","fromBlock":"0xffffffffffffffff"""",   // past 63 bits: refused, never a crash
            ""","toBlock":"0x5"""",                    // an open fromBlock is the head (10): nothing can match
        )) {
            val resp = r.call("eth_newFilter", """[{"address":"$watched"$bad}]""")
            assertEquals(-32602, resp.code(), "$bad → $resp")
        }
        assertEquals(-32602, r.call("eth_newFilter", """["$watched"]""").code())
    }

    @Test fun backendWithoutIndex_declinesLogFilters_butServesBlockFilters() {
        val chain = object : RpcBackend by Chain(head = 10) {
            override fun getLogs(filterJson: String): String? = null
        }
        val r = RpcRouter(null, MethodLogger(), chain, null, null, RpcFilters(clock))
        assertEquals(-32000, r.call("eth_newFilter", """[{"address":"$watched"}]""").code())
        assertNotNull(r.call("eth_newBlockFilter")["result"])
    }

    @Test fun logFilter_probesTheEndsOfItsRange_notTheWholeRange() {
        val chain = Chain(head = 10)
        val r = router(chain)
        logFilter(r, ""","fromBlock":"0x2"""")
        val probes = chain.logQueries.map { json.parseToJsonElement(it).jsonObject }
            .map { it["fromBlock"]!!.jsonPrimitive.content to it["toBlock"]!!.jsonPrimitive.content }
        assertEquals(listOf("0x2" to "0x2", "latest" to "latest"), probes)
    }

    @Test fun ids_carryNoLeadingZeros_andEitherSpellingFindsTheFilter() {
        val small = object : kotlin.random.Random() {
            override fun nextBits(bitCount: Int): Int = 0
            override fun nextLong(): Long = 0xabcL
        }
        val r = router(Chain(head = 10), RpcFilters(clock, small))
        val id = r.call("eth_newBlockFilter").id()
        assertEquals("0xabc", id)
        assertTrue(r.call("eth_getFilterChanges", """["0x0000000000000abc"]""")["error"] == null)
    }

    @Test fun aBlockTheEngineRefusesForGood_dropsTheFilter() {
        val chain = Chain(head = 10)
        var refuse = false
        val backend = object : RpcBackend by chain {
            override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? =
                if (refuse) """{"error":"block is too old","code":-32602}""" else chain.getBlockByNumber(block, fullTransactions)
        }
        val r = RpcRouter(null, MethodLogger(), backend, null, null, RpcFilters(clock))
        val id = r.call("eth_newBlockFilter").id()
        chain.extend(11)
        refuse = true
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("dropped") && resp.message().contains("from block 11"), resp.message())
    }

    @Test fun aPauseDuringCreation_dropsTheNewFilterToo() {
        val chain = Chain(head = 10)
        lateinit var r: RpcRouter
        var dropOnce = true
        val backend = object : RpcBackend by chain {
            override fun headBlockNumber(): Long? {
                if (dropOnce) { dropOnce = false; r.dropFilters() }   // the node paused mid-creation
                return chain.headBlockNumber()
            }
        }
        r = RpcRouter(null, MethodLogger(), backend, null, null, RpcFilters(clock))
        val id = r.call("eth_newBlockFilter").id()
        assertEquals("filter not found", r.call("eth_getFilterChanges", """["$id"]""").message())
    }

    // ---- reorgs -----------------------------------------------------------

    @Test fun reorg_deliversOrphanedLogsAsRemoved_beforeTheNewBranch() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r)
        chain.extend(12)
        assertEquals(listOf(11L, 12L), r.call("eth_getFilterChanges", """["$id"]""").resultArray().blockNumbers())
        chain.reorg(from = 11, to = 13, branch = 'b')   // 11 and 12 orphaned; 11', 12', 13'
        val changes = r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        assertEquals(listOf(11L, 12L, 11L, 12L, 13L), changes.blockNumbers())
        assertEquals(listOf(true, true, false, false, false), changes.removedFlags())
        // The removed logs carry the ORPHANED blocks' hashes; the new ones the new branch's.
        assertEquals(Chain.hash(11, 'c'), changes[0].jsonObject["blockHash"]!!.jsonPrimitive.content)
        assertEquals(Chain.hash(11, 'b'), changes[2].jsonObject["blockHash"]!!.jsonPrimitive.content)
    }

    @Test fun reorg_blockFilter_deliversTheNewBranch() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = r.call("eth_newBlockFilter").id()
        chain.extend(12)
        r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        chain.reorg(from = 12, to = 13, branch = 'b')
        val hashes = r.call("eth_getFilterChanges", """["$id"]""").resultArray().map { it.jsonPrimitive.content }
        assertEquals(listOf(Chain.hash(12, 'b'), Chain.hash(13, 'b')), hashes)
    }

    @Test fun reorgDeeperThanTheWindow_dropsTheFilter() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = r.call("eth_newBlockFilter").id()
        for (h in 11L..60L) {
            chain.extend(h)
            r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        }
        chain.reorg(from = 20, to = 61, branch = 'b')   // 41 blocks deep: past the 32 kept
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("dropped"), resp.message())
        assertEquals("filter not found", r.call("eth_getFilterChanges", """["$id"]""").message())
    }

    @Test fun headJumpPastTheBridge_dropsTheFilter() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = r.call("eth_newBlockFilter").id()
        chain.extend(10 + RpcFilters.MAX_BRIDGE_BLOCKS + 1L)
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("re-create it"), resp.message())
    }

    // ---- stalls, expiry, bounds -------------------------------------------

    @Test fun indexLag_holdsTheChanges_untilTheIndexCatchesUp_thenSaysSo() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r)
        chain.extend(12)
        chain.indexLagsAt = 12
        // Held, not lost: no changes now, and the cursor stays put.
        assertEquals(0, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
        chain.indexLagsAt = null
        assertEquals(listOf(11L, 12L), r.call("eth_getFilterChanges", """["$id"]""").resultArray().blockNumbers())
        // A lag that outlasts the stall limit is reported, retryably.
        chain.extend(13)
        chain.indexLagsAt = 13
        r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        clock += RpcFilters.STALL_LIMIT + 1.seconds
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("not indexed yet"), resp.message())
        chain.indexLagsAt = null
        assertEquals(listOf(13L), r.call("eth_getFilterChanges", """["$id"]""").resultArray().blockNumbers())
    }

    @Test fun logsOnAnotherBranchThanTheWalk_areHeldBack() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r)
        chain.extend(11)
        // The index answers block 12 under another hash than the walked chain.
        val stale = object : RpcBackend by chain {
            override fun getLogs(filterJson: String): String =
                chain.getLogs(filterJson).replace(Chain.hash(12, 'c'), Chain.hash(12, 'e'))
        }
        val filters = RpcFilters(clock)
        val r2 = RpcRouter(null, MethodLogger(), stale, null, null, filters)
        val id2 = r2.call("eth_newFilter", """[{"address":"$watched"}]""").id()
        chain.extend(12)
        assertEquals(0, r2.call("eth_getFilterChanges", """["$id2"]""").resultArray().size)
        // The honest backend serves the same blocks.
        assertEquals(listOf(11L, 12L), r.call("eth_getFilterChanges", """["$id"]""").resultArray().blockNumbers())
    }

    @Test fun unpolledFilter_expires_afterFiveMinutes() {
        val r = router(Chain(head = 10))
        val id = r.call("eth_newBlockFilter").id()
        clock += 4.minutes
        r.call("eth_getFilterChanges", """["$id"]""").resultArray()   // a poll resets the deadline
        clock += 4.minutes
        r.call("eth_getFilterChanges", """["$id"]""").resultArray()
        clock += RpcFilters.TIMEOUT + 1.seconds
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertEquals("filter not found", resp.message())
    }

    @Test fun uninstall_answersWhetherTheFilterExisted() {
        val r = router(Chain(head = 10))
        val id = r.call("eth_newBlockFilter").id()
        assertEquals(true, r.call("eth_uninstallFilter", """["$id"]""")["result"]!!.jsonPrimitive.booleanOrNull)
        assertEquals(false, r.call("eth_uninstallFilter", """["$id"]""")["result"]!!.jsonPrimitive.booleanOrNull)
        assertEquals("filter not found", r.call("eth_getFilterChanges", """["$id"]""").message())
        assertEquals(-32602, r.call("eth_uninstallFilter", """[7]""").code())
    }

    @Test fun filterCap_refusesTheNextOne() {
        val r = router(Chain(head = 10))
        repeat(RpcFilters.MAX_FILTERS) { r.call("eth_newBlockFilter").id() }
        val resp = r.call("eth_newBlockFilter")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("too many filters"), resp.message())
    }

    @Test fun tooManyLogsInOnePoll_dropsTheFilter() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r)
        chain.logsPer = RpcFilters.MAX_LOGS_PER_POLL / 2 + 1
        chain.extend(12)
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("more than"), resp.message())
    }

    @Test fun theLogCap_countsTheRemovedLogsToo() {
        val chain = Chain(head = 10)
        val r = router(chain)
        val id = logFilter(r)
        chain.logsPer = 4_000
        chain.extend(11)
        assertEquals(4_000, r.call("eth_getFilterChanges", """["$id"]""").resultArray().size)
        // 8,000 new logs alone fit the cap; with the 4,000 removed ones they do not.
        chain.reorg(from = 11, to = 12, branch = 'b')
        val resp = r.call("eth_getFilterChanges", """["$id"]""")
        assertEquals(-32000, resp.code())
        assertTrue(resp.message().contains("removed ones included"), resp.message())
    }

    @Test fun dropFilters_forgetsEveryFilter() {
        val r = router(Chain(head = 10))
        val a = r.call("eth_newBlockFilter").id()
        val b = logFilter(r)
        r.dropFilters()
        assertEquals("filter not found", r.call("eth_getFilterChanges", """["$a"]""").message())
        assertEquals("filter not found", r.call("eth_getFilterLogs", """["$b"]""").message())
        assertNotNull(r.call("eth_newBlockFilter")["result"])   // new ones install as before
    }

    @Test fun pause_dropsFilters() {
        val lifecycle = object : RpcLifecycle {
            override fun pause() = RpcLifecycleResult(true, "PAUSED")
            override fun wakeUp() = RpcLifecycleResult(true, "RUNNING")
        }
        val r = RpcRouter(null, MethodLogger(), Chain(head = 10), null, lifecycle, RpcFilters(clock))
        val id = r.call("eth_newBlockFilter").id()
        r.call("myotis_pause")
        assertEquals("filter not found", r.call("eth_getFilterChanges", """["$id"]""").message())
    }

    @Test fun pendingTransactionFilter_isNotServed() {
        val resp = router(Chain(head = 10)).call("eth_newPendingTransactionFilter")
        assertEquals(-32601, resp.code())
    }

    @Test fun noVerifiedHead_declinesCreation_retryably() {
        val chain = Chain(head = 10).apply { head = null }
        assertEquals(-32000, router(chain).call("eth_newBlockFilter").code())
    }

    @Test fun tooManyArguments_areRefused() {
        val r = router(Chain(head = 10))
        assertEquals(-32602, r.call("eth_newBlockFilter", """["x"]""").code())
        assertEquals(-32602, r.call("eth_getFilterChanges", """["0x1","0x2"]""").code())
    }

    @Test fun ids_areMatchedCaseInsensitively() {
        val r = router(Chain(head = 10))
        val id = r.call("eth_newBlockFilter").id()
        assertTrue(r.call("eth_getFilterChanges", """["${id.uppercase().replace("0X", "0x")}"]""")["error"] == null)
    }

    @Test fun answer_isAJsonPrimitiveId() {
        val r = router(Chain(head = 10))
        val resp = r.call("eth_newBlockFilter")
        assertTrue(resp["result"] is JsonPrimitive && (resp["result"] as JsonPrimitive).isString)
    }
}
