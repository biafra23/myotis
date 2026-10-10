package io.myotis.jsonrpc

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/**
 * The web-page gate over the real listener (#502): the acceptance list of the
 * issue, request by request, against a running [MyotisRpcServer] on an ephemeral
 * loopback port. Raw sockets, so every header a browser would send — `Origin`,
 * `Sec-Fetch-Site`, a hostile `Host` — is sent exactly as written.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WebAccessHttpTest {

    /** Minimal synced backend; counts eth_chainId so "the backend is never called" is provable. */
    private class CountingReads : io.myotis.api.VerifiedReads {
        val chainIdCalls = AtomicInteger()
        override fun chainId(): Long { chainIdCalls.incrementAndGet(); return 1L }
        override fun headBlockNumber() = 0x1L
        override fun syncState() = io.myotis.api.SyncState.SYNCED
        override fun call(from: ByteArray?, to: ByteArray?, data: ByteArray, valueWei: String?, block: String): ByteArray? = null
        override fun getBalance(address: ByteArray, block: String): String? = null
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

    private data class Reply(val status: Int, val headers: Map<String, String>, val body: String)

    private val reads = CountingReads()
    private val gate = WebAccess()
    private var port = 0
    private lateinit var server: MyotisRpcServer

    private val chainIdCall = """{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"""

    @BeforeAll fun start() {
        // An ephemeral port is probed, released and re-bound by Ktor (asynchronously), so
        // another process can take it in between: try a few, and treat any I/O hiccup
        // while the listener comes up as "not yet".
        var up = false
        for (attempt in 0 until 3) {
            port = ServerSocket(0).use { it.localPort }
            server = MyotisRpc.server(port, null, "127.0.0.1", reads, null, null, gate)
            server.start()
            for (i in 0 until 100) {
                if (!server.isServing()) break   // the bind failed inside Ktor's scope
                try {
                    if (http("GET", "/health").status == 200) { up = true; break }
                } catch (_: IOException) {
                    Thread.sleep(50)
                }
            }
            if (up) break
            server.stop()
        }
        assertTrue(up, "listener did not come up on 127.0.0.1:$port")
    }

    @AfterAll fun stop() { server.stop() }

    @BeforeEach fun resetPolicy() {
        gate.policy = WebAccessPolicy.DEFAULT
        reads.chainIdCalls.set(0)
    }

    /** One HTTP/1.1 exchange, written by hand; `Connection: close` so the body ends with the stream. */
    private fun http(
        method: String,
        path: String,
        headers: List<Pair<String, String>> = emptyList(),
        body: String? = null,
        host: String = "127.0.0.1:$port",
    ): Reply = Socket("127.0.0.1", port).use { s ->
        s.soTimeout = 10_000
        val bytes = body?.toByteArray()
        val head = buildString {
            append("$method $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n")
            headers.forEach { (k, v) -> append("$k: $v\r\n") }
            if (bytes != null) append("Content-Length: ${bytes.size}\r\n")
            append("\r\n")
        }
        s.getOutputStream().apply {
            write(head.toByteArray())
            if (bytes != null) write(bytes)
            flush()
        }
        val raw = s.getInputStream().readBytes().toString(Charsets.ISO_8859_1)
        val split = raw.indexOf("\r\n\r\n")
        require(split > 0) { "no header block in: $raw" }
        val lines = raw.substring(0, split).split("\r\n")
        val status = lines[0].split(" ")[1].toInt()
        val hs = lines.drop(1).associate {
            it.substringBefore(":").trim().lowercase() to it.substringAfter(":").trim()
        }
        Reply(status, hs, raw.substring(split + 4))
    }

    private fun postJson(origin: String?, contentType: String = "application/json", host: String = "127.0.0.1:$port"): Reply {
        val hs = mutableListOf("Content-Type" to contentType)
        if (origin != null) hs += "Origin" to origin
        return http("POST", "/", hs, chainIdCall, host)
    }

    private fun preflight(origin: String): Reply = http("OPTIONS", "/", listOf(
        "Origin" to origin,
        "Access-Control-Request-Method" to "POST",
        "Access-Control-Request-Headers" to "content-type",
    ))

    private val Reply.acao: String? get() = headers["access-control-allow-origin"]

    // ---- acceptance ----

    @Test fun nativeClientIsServedExactlyAsBefore() {
        val r = postJson(origin = null)
        assertEquals(200, r.status)
        assertTrue(r.body.contains("\"result\":\"0x1\""), r.body)
        assertEquals(1, reads.chainIdCalls.get())
        assertNull(r.acao, "no CORS headers for a client that sent no Origin")
    }

    @Test fun defaultRefusesEveryWebPageBeforeTheBackend_evenAsASimpleRequest() {
        for (ct in listOf("application/json", "text/plain")) {
            val r = postJson("https://evil.example", contentType = ct)
            assertEquals(403, r.status, ct)
            assertNull(r.acao)
        }
        assertEquals(0, reads.chainIdCalls.get(), "the backend never ran")
        val pre = preflight("https://evil.example")
        assertEquals(403, pre.status)
        assertNull(pre.acao, "a refused preflight carries no grant")
        val row = gate.recentOrigins().single { it.origin == "https://evil.example" }
        assertFalse(row.lastAllowed)
        assertEquals(3, row.attempts, "two posts and a preflight")
        // A malformed Origin (no browser sends one) is refused but never listed: the
        // list's Allow could not admit it.
        assertEquals(403, postJson("foo bar").status)
        assertTrue(gate.recentOrigins().none { it.origin == "foo bar" })
        assertEquals(0, reads.chainIdCalls.get())
    }

    @Test fun allowedSiteIsServedWithItsOriginEchoedAndVary_andTheChangeIsLive() {
        assertEquals(403, postJson("https://app.example").status)
        gate.policy = WebAccessPolicy.of(WebAccessMode.ALLOWLIST, listOf("app.example"))

        val pre = preflight("https://app.example")
        assertEquals(204, pre.status)
        assertEquals("https://app.example", pre.acao)
        assertEquals("Origin", pre.headers["vary"])
        assertTrue(pre.headers["access-control-allow-methods"]!!.contains("POST"))
        assertTrue(pre.headers["access-control-allow-headers"]!!.contains("Content-Type"))
        assertEquals(0, reads.chainIdCalls.get(), "a preflight never reaches the router")

        val r = postJson("https://app.example")
        assertEquals(200, r.status)
        assertEquals("https://app.example", r.acao)
        assertEquals("Origin", r.headers["vary"])
        assertTrue(r.body.contains("\"result\":\"0x1\""), r.body)
        assertEquals(1, reads.chainIdCalls.get())
        assertTrue(gate.recentOrigins().single { it.origin == "https://app.example" }.lastAllowed)

        // Exact origins only.
        assertEquals(403, postJson("http://app.example").status)
        assertEquals(403, postJson("https://other.example").status)
        assertEquals(403, postJson("https://app.example:8443").status)
        assertEquals(403, postJson("null").status)
        assertEquals(1, reads.chainIdCalls.get())

        // Removing the site takes effect on the next request — no restart.
        gate.policy = WebAccessPolicy.DEFAULT
        assertEquals(403, postJson("https://app.example").status)
    }

    @Test fun allSitesServesAnyPage_offServesNone() {
        gate.policy = WebAccessPolicy.of(WebAccessMode.ALL, emptyList())
        val r = postJson("https://anything.example")
        assertEquals(200, r.status)
        assertEquals("https://anything.example", r.acao)
        val opaque = postJson("null")
        assertEquals(200, opaque.status)
        assertEquals("null", opaque.acao)
        assertEquals(204, preflight("https://anything.example").status)

        gate.policy = WebAccessPolicy.of(WebAccessMode.OFF, listOf("https://anything.example"))
        assertEquals(403, postJson("https://anything.example").status, "Off refuses a listed site too")
        assertEquals(200, postJson(origin = null).status, "but never a native client")
    }

    @Test fun noCorsProbeIsRefused_navigationsAndNativeHealthChecksAreNot() {
        gate.policy = WebAccessPolicy.of(WebAccessMode.ALL, emptyList())
        val probe = http("GET", "/health", listOf("Sec-Fetch-Site" to "cross-site", "Sec-Fetch-Mode" to "no-cors"))
        assertEquals(403, probe.status)
        val typed = http("GET", "/health", listOf("Sec-Fetch-Site" to "none", "Sec-Fetch-Mode" to "navigate"))
        assertEquals(200, typed.status)
        val linked = http("GET", "/health", listOf(
            "Sec-Fetch-Site" to "cross-site", "Sec-Fetch-Mode" to "navigate", "Sec-Fetch-Dest" to "document"))
        assertEquals(200, linked.status, "a link clicked on a page is a top-level navigation, not a probe")
        assertEquals(200, http("GET", "/health").status)
    }

    @Test fun hostHeaderMustNameTheListenerInEveryMode() {
        gate.policy = WebAccessPolicy.of(WebAccessMode.ALL, emptyList())
        assertEquals(403, postJson(origin = null, host = "evil.example:$port").status)
        assertEquals(403, postJson("https://rebind.example", host = "evil.example:$port").status)
        assertEquals(0, reads.chainIdCalls.get())
        assertEquals(200, postJson(origin = null, host = "localhost:$port").status)
        assertEquals(200, postJson(origin = null, host = "[::1]:$port").status)
        assertEquals(200, postJson(origin = null, host = "LOCALHOST").status)
        // A Host refusal is not an origin "Allow" could admit, so it is not in the list
        // (the gate is shared by every test here, hence an origin of this test's own).
        assertTrue(gate.recentOrigins().none { it.origin == "https://rebind.example" })
    }
}
