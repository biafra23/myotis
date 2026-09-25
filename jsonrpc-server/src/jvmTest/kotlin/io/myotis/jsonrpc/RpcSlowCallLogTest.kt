package io.myotis.jsonrpc

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory

/**
 * Pins the slow-call watchdog (#312): a request still unanswered past the threshold
 * is logged at WARN under [MethodLogger.SLOW_LOGGER] WHILE it is stuck — method, id,
 * batch position and phase — and again when it finishes. A fast request logs nothing
 * there, and the access stream keeps its single INFO level even for a slow call.
 */
class RpcSlowCallLogTest {

    private lateinit var slowLogger: Logger
    private lateinit var accessLogger: Logger
    private lateinit var slow: ListAppender<ILoggingEvent>
    private lateinit var access: ListAppender<ILoggingEvent>

    /** eth_getBalance blocks for [balanceDelayMs]; everything else answers at once. */
    private class SlowBalanceBackend(private val balanceDelayMs: Long) : io.myotis.api.VerifiedReads {
        override fun chainId() = 1L
        override fun headBlockNumber() = 0x1L
        override fun syncState() = io.myotis.api.SyncState.SYNCED
        override fun call(from: ByteArray?, to: ByteArray?, data: ByteArray, valueWei: String?, block: String): ByteArray? = null
        override fun getBalance(address: ByteArray, block: String): String? {
            Thread.sleep(balanceDelayMs)
            return "1"
        }
        override fun getTransactionCount(address: ByteArray, block: String): Long? = null
        override fun getCode(address: ByteArray, block: String): ByteArray? = null
        override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? = null
        override fun sendRawTransaction(rawTx: ByteArray): ByteArray? = null
        override fun getTransactionReceipt(txHash: ByteArray): String? = null
        override fun getTransactionByHash(txHash: ByteArray): String? = null
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? = null
        override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? = null
        override fun getBlockReceipts(blockSelector: String): String? = null
        override fun gasPrice(): String? = null
        override fun maxPriorityFeePerGas(): String? = null
        override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? = null
        override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long? = null
    }

    private val balance =
        """{"jsonrpc":"2.0","id":7,"method":"eth_getBalance",
           "params":["0x00000000219ab540356cBB839Cbe05303d7705Fa","latest"]}"""

    @BeforeEach fun setUp() {
        slowLogger = LoggerFactory.getLogger(MethodLogger.SLOW_LOGGER) as Logger
        accessLogger = LoggerFactory.getLogger(MethodLogger.ACCESS_LOGGER) as Logger
        slow = ListAppender<ILoggingEvent>().apply { start() }
        access = ListAppender<ILoggingEvent>().apply { start() }
        slowLogger.addAppender(slow)
        accessLogger.addAppender(access)
    }

    @AfterEach fun tearDown() {
        slowLogger.detachAppender(slow)
        accessLogger.detachAppender(access)
        slow.stop()
        access.stop()
    }

    /** The stalled call sleeps 700 ms against a 100 ms threshold: the watchdog has
     *  600 ms of margin to fire while the call is still stuck, even on a loaded CI box. */
    private fun route(body: String, slowCallWarnMs: Long = 100) {
        runBlocking {
            RpcRouter(null, MethodLogger(slowCallWarnMs = slowCallWarnMs),
                VerifiedReadsBackend(SlowBalanceBackend(balanceDelayMs = 700))).handle(body)
        }
    }

    private fun slowLines(): List<String> = slow.list.map { it.formattedMessage }

    @Test fun stalledCall_isWarnedWhileStuck_andAgainWhenItFinishes() {
        route(balance)
        val lines = slowLines()
        assertEquals(2, lines.size, lines.toString())
        assertTrue(slow.list.all { it.level == Level.WARN }, "slow-call lines are WARN")
        val stuck = lines[0]
        assertTrue(stuck.contains("method=eth_getBalance") && stuck.contains("id=7"), stuck)
        assertTrue(stuck.contains("still unanswered") && stuck.contains("phase=backend"), stuck)
        assertTrue(lines[1].contains("finished after"), lines[1])
        // The access stream is untouched: one line, INFO, even for a slow call.
        assertTrue(access.list.isNotEmpty() && access.list.all { it.level == Level.INFO },
            access.list.toString())
    }

    @Test fun fastCall_logsNothingOnTheSlowLogger() {
        // A generous threshold: the claim is "a call under it logs nothing", not a race
        // between a 100 ms budget and a cold JVM's first call (class loading, Json init).
        route("""{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}""", slowCallWarnMs = 10_000)
        assertTrue(slowLines().isEmpty(), slowLines().toString())
    }

    @Test fun stalledBatchElement_namesItsPosition() {
        route("""[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}, $balance]""")
        // Only the stalled element can log "still unanswered" (eth_chainId never suspends,
        // so its watchdog can't run before it ends). Whether eth_chainId itself crosses
        // 100 ms on a cold JVM is not this test's business — fastCall_logsNothingOnTheSlowLogger
        // pins the under-threshold case with a threshold no cold start can reach.
        val stuck = slowLines().first { it.contains("still unanswered") }
        assertTrue(stuck.contains("method=eth_getBalance") && stuck.contains("batch=2/2"), stuck)
    }
}
