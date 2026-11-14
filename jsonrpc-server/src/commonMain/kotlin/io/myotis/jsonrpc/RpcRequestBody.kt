package io.myotis.jsonrpc

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.charsets.Charset
import io.ktor.utils.io.charsets.Charsets
import io.ktor.utils.io.core.readText
import io.ktor.utils.io.readRemaining
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The request-body limits of the loopback JSON-RPC server (#667), the same as
 * `myotis-rpcd`'s (`rust/myotis-rpcd/src/http.rs`: `MAX_BODY_BYTES`, and its
 * `--http-body-timeout` default), so the two servers refuse alike.
 */
object RpcRequestBody {
    /** geth's default `--http` body limit, 5 MiB. It holds the largest legitimate
     *  request: a maximal `eth_sendRawTransaction`, or a big batch of `eth_call`s. */
    const val MAX_BYTES: Long = 5L * 1024 * 1024

    /** Total time to receive one body. A client that drips its upload slower than
     *  that is cut off instead of holding the connection open indefinitely. */
    const val TIMEOUT_MS: Long = 10_000L
}

/** What reading one request body came to. */
internal sealed interface BodyRead {
    /** The whole body, within the cap, decoded in the request's charset (UTF-8, JSON's
     *  encoding per RFC 8259, when `Content-Type` names none), as `receiveText` did. */
    data class Body(val text: String) : BodyRead

    /** Past the cap: announced by `Content-Length` (and then never read), or found
     *  while reading. [bytes] is how much was read before stopping. */
    data class TooLarge(val bytes: Long) : BodyRead

    /** The body did not arrive within the timeout. */
    data object TimedOut : BodyRead
}

/**
 * Read a request body under [maxBytes] and [timeoutMs]. A [declaredLength] over the
 * cap is refused before a byte is read. Any other body, chunked or unannounced
 * included, is read at most `maxBytes + 1` bytes far: one byte past the cap is
 * enough to know it is too large, so memory stays bounded whatever the client sends,
 * and nothing is buffered whole before the check runs (`receiveText` would). A body
 * within the cap is decoded straight from the read buffer, in [charset].
 */
internal suspend fun readRequestBody(
    channel: ByteReadChannel,
    declaredLength: Long?,
    maxBytes: Long = RpcRequestBody.MAX_BYTES,
    timeoutMs: Long = RpcRequestBody.TIMEOUT_MS,
    charset: Charset = Charsets.UTF_8,
): BodyRead {
    if (declaredLength != null && declaredLength > maxBytes) return BodyRead.TooLarge(0)
    return withTimeoutOrNull(timeoutMs) {
        val source = channel.readRemaining(maxBytes + 1)
        if (source.request(maxBytes + 1)) BodyRead.TooLarge(maxBytes + 1)
        else BodyRead.Body(source.readText(charset))
    } ?: BodyRead.TimedOut
}
