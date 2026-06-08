package io.myotis.jsonrpc

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType

/**
 * Upstream JSON-RPC relay (DEBUG/development only — see the trust note in the plan).
 *
 * Forwards the request body **verbatim** to a configured upstream RPC (e.g. Infura)
 * and returns its response body unchanged, so Phase A is a faithful mirror that
 * lets MetaMask work end-to-end while we record which methods it calls. Uses the
 * Ktor CIO client (Android-safe; NOT java.net.http).
 */
class UpstreamProxy(private val url: String) {

    private val client = HttpClient(CIO)

    /** POST the raw JSON-RPC body to the upstream and return the raw response body. */
    suspend fun forward(rawBody: String): String {
        val resp = client.post(url) {
            contentType(ContentType.Application.Json)
            setBody(rawBody)
        }
        return resp.bodyAsText()
    }

    fun close() = client.close()
}
