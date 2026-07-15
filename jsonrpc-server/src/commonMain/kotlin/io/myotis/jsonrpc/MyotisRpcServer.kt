package io.myotis.jsonrpc

import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.async
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import kotlin.concurrent.Volatile

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
    private val backend: RpcBackend? = null,
    private val statusReads: RpcStatusSource? = null,
) {
    private companion object {
        const val LOGGER = "io.myotis.jsonrpc.MyotisRpcServer"

        /** How often to trickle a keep-alive whitespace byte while a response is still
         *  being computed. Short enough to reset any sane per-read socket timeout
         *  (OkHttp defaults to 10s), long enough to stay invisible for normal calls. */
        const val HEARTBEAT_INTERVAL_MS = 5_000L

        /** Per-body cap for the DEBUG access log — keeps a large eth_call / batch from
         *  blowing the Android 50k-line ring or producing one enormous line. */
        const val MAX_BODY_LOG_CHARS = 4_096
    }

    private val proxy: UpstreamProxy? = upstreamUrl?.takeIf { it.isNotBlank() }?.let { UpstreamProxy(it) }
    private val logger = MethodLogger()
    private val router = RpcRouter(proxy, logger, backend, statusReads)

    /**
     * Optional request/response capture for debugging + replay (JVM-only —
     * gated on the {@code myotis.rpc.capture} system property; a no-op on iOS).
     * Blocking disk I/O, so run off the Ktor request thread.
     */
    private suspend fun capture(req: String, resp: String) {
        kotlinx.coroutines.withContext(rpcIoDispatcher) {
            appendRpcCapture(req, resp)
        }
    }

    /** Bound a body for the DEBUG access log: trim whitespace, cap length, and collapse
     *  newlines so one exchange stays one grep-able line. */
    private fun cap(s: String): String {
        val t = s.trim().replace('\n', ' ').replace('\r', ' ')
        return if (t.length > MAX_BODY_LOG_CHARS) {
            t.substring(0, MAX_BODY_LOG_CHARS) + "…(" + (t.length - MAX_BODY_LOG_CHARS) + " more)"
        } else t
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
                        val pending = async(rpcIoDispatcher) {
                            router.handle(body)
                        }
                        call.respondBytesWriter(ContentType.Application.Json) {
                            var response: String? = null
                            while (response == null) {
                                response = kotlinx.coroutines.withTimeoutOrNull(
                                    HEARTBEAT_INTERVAL_MS) { pending.await() }
                                if (response == null) {
                                    writeStringUtf8(" ")
                                    flush()
                                }
                            }
                            writeStringUtf8(response)
                            // Full request+response at DEBUG (concise per-call INFO lines come
                            // from MethodLogger). One record for the whole exchange, incl. batches
                            // and parse errors; bodies capped so a big eth_call / batch can't blow
                            // the Android log ring or produce one enormous line.
                            if (rpcLogDebugEnabled(MethodLogger.ACCESS_LOGGER)) {
                                rpcLogDebug(MethodLogger.ACCESS_LOGGER,
                                    "[rpc] req=${cap(body)} resp=${cap(response)}")
                            }
                            capture(body, response)
                        }
                    }
                }
            }
        }
        server.start(wait = false)
        engine = server
        rpcLogInfo(LOGGER,
            "[rpc] JSON-RPC server listening on http://$host:$port " +
                "(mode=${if (proxy != null) "proxy" else "strict"})")
    }

    fun stop() {
        engine?.stop(gracePeriodMillis = 200, timeoutMillis = 1000)
        engine = null
        proxy?.close()
        logger.logSummary()
        rpcLogInfo(LOGGER, "[rpc] JSON-RPC server stopped")
    }
}
