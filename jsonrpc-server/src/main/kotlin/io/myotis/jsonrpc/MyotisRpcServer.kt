package io.myotis.jsonrpc

import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import org.slf4j.LoggerFactory

/**
 * Embedded JSON-RPC HTTP server for Myotis, runnable on both the Android app and
 * the CLI daemon (Ktor CIO engine — Android-safe).
 *
 * Phase A: stands up the endpoint + CORS + a router that relays every method to
 * the [upstreamUrl] (if set) and logs the coverage map. With no upstream it runs
 * in strict mode (errors instead of proxying). Verified Myotis handlers are
 * layered into the router in later phases.
 *
 * @param upstreamUrl DEBUG-only upstream RPC to proxy unhandled methods to; null
 *   = strict mode (no proxy). Never commit this value — inject at runtime.
 */
class MyotisRpcServer(
    private val port: Int,
    private val upstreamUrl: String? = null,
    private val host: String = "0.0.0.0",
) {
    private val log = LoggerFactory.getLogger(MyotisRpcServer::class.java)

    private val proxy: UpstreamProxy? = upstreamUrl?.takeIf { it.isNotBlank() }?.let { UpstreamProxy(it) }
    private val logger = MethodLogger()
    private val router = RpcRouter(proxy, logger)

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
                    val response = router.handle(body)
                    call.respondText(response, ContentType.Application.Json)
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
