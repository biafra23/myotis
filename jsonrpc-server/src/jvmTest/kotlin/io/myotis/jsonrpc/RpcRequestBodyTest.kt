package io.myotis.jsonrpc

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.readByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.Socket

/**
 * #667: the loopback server's request body is read under a size cap and a timeout,
 * like `myotis-rpcd`'s, never buffered whole first. The reader is driven directly
 * here (so the bytes it consumed can be counted), and the listener once over HTTP.
 */
class RpcRequestBodyTest {

    private fun body(read: BodyRead): String = (read as? BodyRead.Body)?.text
        ?: throw AssertionError("expected a body, got $read")

    @Test
    fun `the cap is the same as myotis-rpcd's`() {
        assertEquals(5L * 1024 * 1024, RpcRequestBody.MAX_BYTES)
        assertEquals(10_000L, RpcRequestBody.TIMEOUT_MS)
    }

    @Test
    fun `a body up to the cap is served whole`() = runBlocking {
        val max = 64L * 1024
        for (size in listOf(0, 1, (max * 49 / 50).toInt(), max.toInt())) {
            val channel = ByteChannel()
            launch {
                channel.writeFully(ByteArray(size) { 'a'.code.toByte() })
                channel.flushAndClose()
            }
            assertEquals(size, body(readRequestBody({ channel }, size.toLong(), max, 5_000)).length)
        }
    }

    @Test
    fun `an announced length past the cap is refused before a byte is read`() = runBlocking {
        val channel = ByteChannel()
        channel.writeFully(ByteArray(16))
        channel.flushAndClose()
        var opened = false
        val read = readRequestBody({ opened = true; channel }, RpcRequestBody.MAX_BYTES + 1)
        assertEquals(BodyRead.TooLarge(0), read)
        assertTrue(!opened, "the body was never received (no 100 Continue)")
        assertEquals(16, channel.readRemaining().readByteArray().size, "nothing was read")
    }

    @Test
    fun `an unannounced endless body stops one byte past the cap`() = runBlocking {
        val max = 64L * 1024
        val channel = ByteChannel()
        val writer = launch {
            val chunk = ByteArray(4096)
            while (true) {
                channel.writeFully(chunk)
                channel.flush()
            }
        }
        val read = readRequestBody({ channel }, null, max, 5_000)
        writer.cancel()
        assertEquals(BodyRead.TooLarge(max + 1), read, "read exactly cap + 1 bytes, then stopped")
    }

    @Test
    fun `a slow-drip body is cut off at the timeout`() = runBlocking {
        val channel = ByteChannel()
        val writer = launch {
            while (true) {
                channel.writeFully(ByteArray(1))
                channel.flush()
                delay(50)
            }
        }
        val started = System.nanoTime()
        val read = readRequestBody({ channel }, null, 1024, 300)
        writer.cancel()
        assertEquals(BodyRead.TimedOut, read)
        assertTrue((System.nanoTime() - started) / 1_000_000 < 3_000, "cut off near the timeout")
    }

    @Test
    fun `the listener answers 413 to an announced oversized body and still serves the next call`() {
        var port = 0
        var server: MyotisRpcServer? = null
        for (attempt in 0 until 3) {
            port = ServerSocket(0).use { it.localPort }
            val s = MyotisRpcServer(port)
            s.start()
            var up = false
            for (i in 0 until 100) {
                if (!s.isServing()) break
                try {
                    if (exchange(port, "GET /health HTTP/1.1\r\n", null).first == 200) { up = true; break }
                } catch (_: java.io.IOException) {
                    Thread.sleep(50)
                }
            }
            if (up) { server = s; break }
            s.stop()
        }
        val running = server ?: throw AssertionError("listener did not come up")
        try {
            // Announce one byte past the cap and send no body at all: a server that read
            // before checking would wait for the body; this one answers at once. The
            // socket stays open afterwards (Ktor drains the announced body), so the
            // answer is read by its Content-Length, not to EOF.
            val (status, _) = exchange(port,
                "POST / HTTP/1.1\r\nContent-Type: application/json\r\n" +
                    "Content-Length: ${RpcRequestBody.MAX_BYTES + 1}\r\n", null)
            assertEquals(413, status)

            val call = """{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}"""
            val (ok, reply) = exchange(port,
                "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: ${call.length}\r\n", call)
            assertEquals(200, ok)
            assertTrue(reply.contains("\"id\":1"), reply)
        } finally {
            running.stop()
        }
    }

    /** One request over a raw socket; `head` ends with its last header line. The answer
     *  is read by its `Content-Length` (or to EOF without one), never waiting for the
     *  server to close the socket. */
    private fun exchange(port: Int, head: String, body: String?): Pair<Int, String> =
        Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 10_000
            s.getOutputStream().apply {
                write((head + "Host: 127.0.0.1:$port\r\nConnection: close\r\n\r\n").toByteArray())
                if (body != null) write(body.toByteArray())
                flush()
            }
            val input = s.getInputStream()
            val raw = java.io.ByteArrayOutputStream()
            var split = -1
            while (split < 0) {
                val b = input.read()
                require(b >= 0) { "EOF before the header block ended: ${raw.toString(Charsets.ISO_8859_1)}" }
                raw.write(b)
                split = raw.toString(Charsets.ISO_8859_1).indexOf("\r\n\r\n")
            }
            val headers = raw.toString(Charsets.ISO_8859_1).substring(0, split).lines()
            val status = headers[0].split(" ")[1].toInt()
            val length = headers.drop(1)
                .firstOrNull { it.substringBefore(":").trim().equals("Content-Length", ignoreCase = true) }
                ?.substringAfter(":")?.trim()?.toInt()
            val reply = if (length != null) {
                val bytes = ByteArray(length)
                var off = 0
                while (off < length) {
                    val n = input.read(bytes, off, length - off)
                    require(n >= 0) { "EOF inside the body" }
                    off += n
                }
                bytes
            } else {
                input.readBytes()
            }
            status to reply.toString(Charsets.UTF_8)
        }
}
