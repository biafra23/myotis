package io.myotis.jsonrpc

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory

/**
 * Pins the RPC access log: every request the router answers — including parse and
 * batch errors — emits one concise line under [MethodLogger.ACCESS_LOGGER], and all
 * lines are INFO regardless of outcome (so raising the log level never silently hides
 * successful calls, the original bug).
 */
class RpcAccessLogTest {

    private lateinit var accessLogger: Logger
    private lateinit var appender: ListAppender<ILoggingEvent>

    /** Minimal synced backend so verified methods (eth_chainId) take the VERIFIED path. */
    private class StubBackend : io.myotis.api.VerifiedReads {
        override fun chainId() = 1L
        override fun headBlockNumber() = 0x1L
        override fun syncState() = io.myotis.api.SyncState.SYNCED
        override fun call(from: ByteArray?, to: ByteArray, data: ByteArray, valueWei: String?, block: String): ByteArray? = null
        override fun getBalance(address: ByteArray, block: String): String? = null
        override fun getTransactionCount(address: ByteArray, block: String): Long? = null
        override fun getCode(address: ByteArray, block: String): ByteArray? = null
        override fun getStorageAt(address: ByteArray, slot32: ByteArray, block: String): ByteArray? = null
        override fun sendRawTransaction(rawTx: ByteArray): ByteArray? = null
        override fun getTransactionReceipt(txHash: ByteArray): String? = null
        override fun getTransactionByHash(txHash: ByteArray): String? = null
        override fun getBlockByNumber(block: String, fullTransactions: Boolean): String? = null
        override fun getBlockByHash(blockHash32: ByteArray, fullTransactions: Boolean): String? = null
        override fun gasPrice(): String? = null
        override fun maxPriorityFeePerGas(): String? = null
        override fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? = null
        override fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?, valueWei: String?): Long? = null
    }

    @BeforeEach fun setUp() {
        accessLogger = LoggerFactory.getLogger(MethodLogger.ACCESS_LOGGER) as Logger
        accessLogger.level = Level.INFO
        appender = ListAppender<ILoggingEvent>().apply { start() }
        accessLogger.addAppender(appender)
    }

    @AfterEach fun tearDown() {
        accessLogger.detachAppender(appender)
        appender.stop()
    }

    private fun route(body: String) {
        runBlocking { RpcRouter(null, MethodLogger(), VerifiedReadsBackend(StubBackend())).handle(body) }
    }

    private fun lines(): List<String> = appender.list.map { it.formattedMessage }

    @Test fun validCall_logsVerifiedInfoLineWithId() {
        route("""{"jsonrpc":"2.0","id":42,"method":"eth_chainId","params":[]}""")
        val l = lines().single { it.contains("method=eth_chainId") }
        assertTrue(l.contains("id=42"), l)
        assertTrue(l.contains("outcome=VERIFIED"), l)
        assertTrue(appender.list.all { it.level == Level.INFO }, "all access lines are INFO")
    }

    @Test fun unsupportedMethod_logsErrorWithCode_atInfo() {
        route("""{"jsonrpc":"2.0","id":2,"method":"eth_getLogs","params":[{}]}""")
        val l = lines().single { it.contains("method=eth_getLogs") }
        assertTrue(l.contains("outcome=ERROR(-32601)"), l)
        // The whole access stream stays INFO — an error must NOT be emitted at WARN,
        // or raising the Logs-tab level would hide it along with the rest.
        assertTrue(appender.list.all { it.level == Level.INFO }, "error lines are INFO too")
    }

    @Test fun parseError_isLogged() {
        route("this is not json")
        val l = lines().single { it.contains("method=<parse-error>") }
        assertTrue(l.contains("outcome=ERROR(-32700)"), l)
    }

    @Test fun batch_logsOneLinePerElement() {
        route(
            """[
                {"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
                {"jsonrpc":"2.0","id":2,"method":"eth_getLogs","params":[{}]}
            ]""",
        )
        assertTrue(lines().any { it.contains("method=eth_chainId") && it.contains("id=1") }, lines().toString())
        assertTrue(lines().any { it.contains("method=eth_getLogs") && it.contains("id=2") }, lines().toString())
    }
}
