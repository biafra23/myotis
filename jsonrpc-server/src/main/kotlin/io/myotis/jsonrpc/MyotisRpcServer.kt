package io.myotis.jsonrpc

import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.response.respondTextWriter
import kotlinx.coroutines.async
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import org.slf4j.LoggerFactory

/**
 * Embedded JSON-RPC HTTP server for Myotis (Ktor CIO engine — Android-safe).
 * Consumed by the Android app, where the wallet runs on the same device.
 *
 * Phase A: stands up the endpoint + CORS + a router that relays every method to
 * the [upstreamUrl] (if set) and logs the coverage map. With no upstream it runs
 * in strict mode (errors instead of proxying). Verified Myotis handlers are
 * layered into the router in later phases.
 *
 * @param upstreamUrl DEBUG-only upstream RPC to proxy unhandled methods to; null
 *   = strict mode (no proxy). Never commit this value — inject at runtime.
 * @param host bind address. Defaults to loopback ([127.0.0.1]) — the wallet is a
 *   same-device client, and the endpoint is unauthenticated/TLS-less, so it must
 *   not be exposed on a routable interface without an explicit opt-in.
 */
class MyotisRpcServer(
    private val port: Int,
    private val upstreamUrl: String? = null,
    private val host: String = "127.0.0.1",
    private val backend: MyotisRpcBackend? = null,
) {
    private val log = LoggerFactory.getLogger(MyotisRpcServer::class.java)

    private val proxy: UpstreamProxy? = upstreamUrl?.takeIf { it.isNotBlank() }?.let { UpstreamProxy(it) }
    private val logger = MethodLogger()
    private val router = RpcRouter(proxy, logger, backend)

    /**
     * Optional request/response capture for debugging + replay. Off unless the
     * system property {@code myotis.rpc.capture} names a file: then every
     * exchange is appended as one JSON line {@code {"t":<ms>,"req":<body>,"resp":<body>}}.
     * Lets us record a real client session (e.g. a MetaMask send) once and replay
     * it at the daemon on a loop while hardening the backend — no browser needed.
     * Synchronized append; best-effort (capture failures never affect serving).
     */
    private val captureFile: java.io.File? =
        System.getProperty("myotis.rpc.capture")?.takeIf { it.isNotBlank() }?.let { java.io.File(it) }

    private suspend fun capture(req: String, resp: String) {
        val f = captureFile ?: return
        // Off the Ktor request thread: the append is blocking disk I/O, so run it on
        // the IO dispatcher. (Capture is a debug feature, off by default; this keeps
        // it from stalling request handling when it IS on.)
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val line = buildString {
                    append("{\"t\":").append(System.currentTimeMillis())
                    append(",\"req\":").append(req.trim())
                    append(",\"resp\":").append(resp.trim())
                    append("}\n")
                }
                synchronized(this@MyotisRpcServer) { f.appendText(line) }
            } catch (_: Exception) { /* capture is best-effort */ }
        }
    }

    private companion object {
        /** How often to trickle a keep-alive whitespace byte while a response is still
         *  being computed. Short enough to reset any sane per-read socket timeout
         *  (OkHttp defaults to 10s), long enough to stay invisible for normal calls. */
        const val HEARTBEAT_INTERVAL_MS = 5_000L
    }

    @Volatile
    private var engine: EmbeddedServer<*, *>? = null

    fun start() {
        if (engine != null) return
        val server = embeddedServer(CIO, port = port, host = host) {
            install(CORS) {
                anyHost()
                allowHeader(HttpHeaders.ContentType)
                allowMethod(HttpMethod.Post)
                allowMethod(HttpMethod.Options)
            }
            routing {
                get("/health") { call.respondText("ok") }
                post("/") {
                    val body = call.receiveText()
                    // Heartbeat-streamed response: compute the answer concurrently and,
                    // while it's pending, trickle a whitespace byte every few seconds on
                    // the (chunked) response. JSON permits leading whitespace before the
                    // top-level value (RFC 8259), so clients parse the eventual payload
                    // unchanged — but the trickle resets per-read HTTP timeouts (OkHttp
                    // on Android / MetaMask Mobile resets its read deadline on every
                    // byte). That frees slow verified calls (a ~1000-token BalanceChecker
                    // sweep over devp2p needs >30s on mobile peers) from the wallet's
                    // socket timeout: the wallet waits as long as WE keep feeding bytes,
                    // and our backend cap (RPC_CALL_TIMEOUT) is the real deadline.
                    // Fast calls (<1 heartbeat) get zero padding — byte-identical to the
                    // old behavior.
                    // coroutineScope (NOT a standalone CoroutineScope): the compute is a
                    // CHILD of this request's coroutine, so if the client disconnects /
                    // the request is cancelled, the pending job is cancelled too rather
                    // than leaking — structured concurrency. (Its 120s backend deadline
                    // also bounds it regardless.)
                    kotlinx.coroutines.coroutineScope {
                        val pending = async(kotlinx.coroutines.Dispatchers.IO) {
                            router.handle(body)
                        }
                        call.respondTextWriter(ContentType.Application.Json) {
                            var response: String? = null
                            while (response == null) {
                                response = kotlinx.coroutines.withTimeoutOrNull(
                                    HEARTBEAT_INTERVAL_MS) { pending.await() }
                                if (response == null) {
                                    write(" ")
                                    flush()
                                }
                            }
                            write(response)
                            capture(body, response)
                        }
                    }
                }
            }
        }
        server.start(wait = false)
        engine = server
        log.info(
            "[rpc] JSON-RPC server listening on http://{}:{} (mode={})",
            host, port, if (proxy != null) "proxy" else "strict",
        )
    }

    fun stop() {
        engine?.stop(gracePeriodMillis = 200, timeoutMillis = 1000)
        engine = null
        proxy?.close()
        logger.logSummary()
        log.info("[rpc] JSON-RPC server stopped")
    }
}
