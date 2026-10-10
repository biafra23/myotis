package io.myotis.jsonrpc

import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.serverConfig
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.SupervisorJob
import io.ktor.server.request.httpMethod
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.async
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import kotlin.concurrent.Volatile

/**
 * Embedded JSON-RPC HTTP server for Myotis (Ktor CIO engine — Android-safe).
 * Consumed by the Android app, where the wallet runs on the same device.
 *
 * Phase A: stands up the endpoint + the web-page gate + a router that relays
 * every method to the [upstreamUrl] (if set) and logs the coverage map. With no
 * upstream it runs in strict mode (errors instead of proxying). Verified Myotis
 * handlers are layered into the router in later phases.
 *
 * Web pages: every request passes [webAccess] before routing (#502). A browser
 * request (one with an `Origin`, or a no-cors probe's `Sec-Fetch-Site`) is served
 * only when the policy admits its origin, and then with the CORS headers the
 * page needs; a refused one gets `403` and never reaches the router. Native
 * clients (no such headers) are served as they always were. The `Host` header
 * must name the loopback listener in every mode (DNS rebinding).
 *
 * @param upstreamUrl DEBUG-only upstream RPC to proxy unhandled methods to; null
 *   = strict mode (no proxy). Never commit this value — inject at runtime.
 * @param host bind address. Defaults to loopback ([127.0.0.1]) — the wallet is a
 *   same-device client, and the endpoint is unauthenticated/TLS-less, so it must
 *   not be exposed on a routable interface without an explicit opt-in.
 * @param webAccess the web-page gate: its policy is swapped live by the host and
 *   its recent-origins list read back. The engine keeps the instance so both work
 *   before the server exists and after it stopped; the default is a private gate
 *   with the default policy (specific sites, none yet).
 */
class MyotisRpcServer(
    private val port: Int,
    private val upstreamUrl: String? = null,
    private val host: String = "127.0.0.1",
    private val backend: RpcBackend? = null,
    private val statusReads: RpcStatusSource? = null,
    private val lifecycle: RpcLifecycle? = null,
    val webAccess: WebAccess = WebAccess(boundHost = host),
) {
    private companion object {
        const val LOGGER = "io.myotis.jsonrpc.MyotisRpcServer"

        /** Fetch Metadata: set by browsers on every request they initiate, never by page script. */
        const val SEC_FETCH_SITE = "Sec-Fetch-Site"
        const val SEC_FETCH_MODE = "Sec-Fetch-Mode"

        /** How long a browser may cache a preflight grant. Short, so a site removed from
         *  the list stops at its next preflight — its actual requests are refused at once
         *  either way; the cache only spares the browser a round trip. */
        const val PREFLIGHT_MAX_AGE_SECONDS = "300"

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
    private val router = RpcRouter(proxy, logger, backend, statusReads, lifecycle)

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

    /** Set by the engine-scope exception handler; see [isServing]. */
    @Volatile
    private var failed = false

    /** Whether the listener is up: started, and no engine-scope failure since.
     *  Hosts poll this for their status surface (the iOS Status RPC row). */
    fun isServing(): Boolean = engine != null && !failed

    fun start() {
        if (engine != null) return
        // Contain EVERY async engine failure: Ktor CIO surfaces some errors
        // asynchronously in its own coroutines (seen live: EADDRINUSE from a
        // TIME_WAIT-held port after a fast app relaunch), and an uncaught
        // coroutine exception kills a Kotlin/Native process outright. The
        // SupervisorJob is what contains them; the handler only OBSERVES —
        // it also replaces Ktor CIO's per-connection default handler (which
        // logs and ignores IO/cancellation), so it must never tear anything
        // down: a stray connection exception is not a server death. [failed]
        // records engine-scope deaths for isServing() without nulling
        // [engine], which would break stop().
        val crashGuard = CoroutineExceptionHandler { _, e ->
            failed = true
            rpcLogInfo(LOGGER, "[rpc] server error: $e")
        }
        failed = false
        val config = serverConfig(applicationEnvironment { }) {
            parentCoroutineContext = SupervisorJob() + crashGuard
            module(moduleBody())
        }
        val server = EmbeddedServer(config, CIO) {
            // TIME_WAIT sockets from a previous instance's connections must
            // not fail the re-bind (a fast app relaunch is normal on mobile);
            // this also matches the hosts' SO_REUSEADDR bind probes.
            reuseAddress = true
            connector {
                port = this@MyotisRpcServer.port
                host = this@MyotisRpcServer.host
            }
        }
        server.start(wait = false)
        engine = server
        rpcLogInfo(LOGGER,
            "[rpc] JSON-RPC server listening on http://$host:$port " +
                "(mode=${if (proxy != null) "proxy" else "strict"})")
    }

    /** The Ktor application module: the web-page gate + /health + the JSON-RPC POST route. */
    private fun moduleBody(): io.ktor.server.application.Application.() -> Unit = {
            // The web-page gate (#502) runs ahead of routing, on every path: a refused
            // browser request never reaches RpcRouter.handle, and an allowed page's CORS
            // headers come from the same decision — our own, not the CORS plugin's, so
            // that one policy object answers preflight, grant and refusal alike and a
            // Settings change is seen by the very next request. Native clients (no
            // Origin, no Sec-Fetch-Site) pass untouched. The rules live in WebAccess.
            intercept(ApplicationCallPipeline.Plugins) {
                val req = call.request
                val verdict = webAccess.decide(
                    method = req.httpMethod.value,
                    host = req.headers[HttpHeaders.Host],
                    origin = req.headers[HttpHeaders.Origin],
                    secFetchSite = req.headers[SEC_FETCH_SITE],
                    secFetchMode = req.headers[SEC_FETCH_MODE],
                )
                when (verdict) {
                    is WebAccessVerdict.Serve -> {
                        val origin = verdict.origin
                        val echo = verdict.echo
                        if (origin != null && echo != null) {
                            logOrigin(origin, allowed = true)
                            call.response.headers.append(HttpHeaders.AccessControlAllowOrigin, echo)
                            call.response.headers.append(HttpHeaders.Vary, "Origin")
                        }
                    }
                    is WebAccessVerdict.Preflight -> {
                        logOrigin(verdict.origin, allowed = true)
                        call.response.headers.append(HttpHeaders.AccessControlAllowOrigin, verdict.echo)
                        call.response.headers.append(HttpHeaders.Vary, "Origin")
                        call.response.headers.append(HttpHeaders.AccessControlAllowMethods, "POST, GET, OPTIONS")
                        call.response.headers.append(HttpHeaders.AccessControlAllowHeaders, "Content-Type")
                        call.response.headers.append(HttpHeaders.AccessControlMaxAge, PREFLIGHT_MAX_AGE_SECONDS)
                        call.respond(HttpStatusCode.NoContent)
                        finish()
                    }
                    is WebAccessVerdict.Refuse -> {
                        val origin = verdict.origin
                        if (verdict.reason == WebAccess.REASON_ORIGIN && origin != null) {
                            logOrigin(origin, allowed = false)
                        } else {
                            // A Host mismatch or a no-cors probe: not an origin the list could
                            // admit, so it is logged, not recorded — a page in the recent list
                            // must be one that "Allow" would actually let in.
                            rpcLogInfo(LOGGER, "[rpc] refused ${verdict.reason}: " +
                                "host=${req.headers[HttpHeaders.Host]} origin=$origin " +
                                "sec-fetch-site=${req.headers[SEC_FETCH_SITE]} " +
                                "sec-fetch-mode=${req.headers[SEC_FETCH_MODE]}")
                        }
                        call.respondText(refusalText(verdict.reason), status = HttpStatusCode.Forbidden)
                        finish()
                    }
                }
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

    /** Record a judged page; the first sighting and every outcome flip go out at INFO,
     *  a page retrying in a loop at DEBUG. */
    private suspend fun logOrigin(origin: String, allowed: Boolean) {
        val news = webAccess.record(origin, allowed)
        val line = if (allowed) "[rpc] web page allowed: origin=$origin"
            else "[rpc] web page refused: origin=$origin (allow it under Settings → Web page access)"
        if (news) rpcLogInfo(LOGGER, line)
        else if (rpcLogDebugEnabled(LOGGER)) rpcLogDebug(LOGGER, line)
    }

    /** The 403 body. Static text: the page's own script never sees it (the browser
     *  withholds a CORS-failed response), and nothing from the request is reflected. */
    private fun refusalText(reason: String): String = when (reason) {
        WebAccess.REASON_HOST ->
            "Myotis serves only its loopback names (localhost, 127.0.0.1, [::1]); " +
                "this request's Host header names something else.\n"
        WebAccess.REASON_PROBE ->
            "Myotis refused a browser request that carries no Origin header (a no-cors probe).\n"
        else ->
            "Myotis refused this web page. Allow it in the Myotis app under Settings > Web page access.\n"
    }

    fun stop() {
        engine?.stop(gracePeriodMillis = 200, timeoutMillis = 1000)
        engine = null
        proxy?.close()
        logger.logSummary()
        rpcLogInfo(LOGGER, "[rpc] JSON-RPC server stopped")
    }
}
