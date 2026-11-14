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

    /** Total time the handler waits for one body. A client that drips its upload
     *  slower than that is answered 408 and no longer holds a handler or its
     *  buffer. The connection itself is Ktor's: after any answer, its engine
     *  pipeline drains and drops what the client still sends (no size or time
     *  limit, but no memory either), and CIO honours only the request's own
     *  `Connection: close`, so the socket stays open while the client keeps
     *  sending. The response says `Connection: close` for clients that listen. */
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
 * cap is refused before [open] is called, so the body is never received: in
 * particular CIO never answers an `Expect: 100-continue` with `100 Continue`, which
 * it does when the body is first received. Any other body, chunked or unannounced
 * included, is read at most `maxBytes + 1` bytes far: one byte past the cap is
 * enough to know it is too large, so memory stays bounded whatever the client sends,
 * and nothing is buffered whole before the check runs (`receiveText` would). A body
 * within the cap is decoded straight from the read buffer, in [charset].
 */
internal suspend fun readRequestBody(
    open: () -> ByteReadChannel,
    declaredLength: Long?,
    maxBytes: Long = RpcRequestBody.MAX_BYTES,
    timeoutMs: Long = RpcRequestBody.TIMEOUT_MS,
    charset: Charset = Charsets.UTF_8,
): BodyRead {
    if (declaredLength != null && declaredLength > maxBytes) return BodyRead.TooLarge(0)
    return withTimeoutOrNull(timeoutMs) {
        val channel = open()
        val source = channel.readRemaining(maxBytes + 1)
        if (source.request(maxBytes + 1)) {
            BodyRead.TooLarge(maxBytes + 1)
        } else {
            // readRemaining(max) returns once the channel is closed, also when it was
            // closed by an error (a client reset mid-body, bad chunk framing); unlike
            // the overload receiveText() used, it does not rethrow. A cut-off body
            // must fail as it did, never be routed as if it were whole.
            channel.closedCause?.let { throw it }
            BodyRead.Body(source.readText(charset))
        }
    } ?: BodyRead.TimedOut
}
