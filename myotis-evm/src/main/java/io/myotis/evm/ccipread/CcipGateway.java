package io.myotis.evm.ccipread;

import java.util.concurrent.CompletableFuture;

/**
 * Pluggable HTTP transport for CCIP-Read gateway requests.
 *
 * <p>{@code :myotis-evm} stays decoupled from any specific HTTP client.
 * The handler does URL template substitution, body construction, and
 * response parsing; the wallet integration supplies the transport via
 * this interface — typically a Ktor-backed implementation per the
 * {@code CLAUDE.md} platform direction.
 *
 * <p>Tests substitute an in-memory implementation that returns hardcoded
 * responses for specific URL/body combinations.
 *
 * <p>Same decoupling pattern as {@code SnapPeer} for the SNAP wire layer:
 * the EVM module owns the protocol logic; the wallet owns the network.
 */
public interface CcipGateway {

    /** HTTP method to use for the gateway request, per ERC-3668 §6.1. */
    enum Method { GET, POST }

    /**
     * Send a request to {@code url} and return the raw response body as a
     * UTF-8 string.
     *
     * @param method  GET or POST. ERC-3668 says GET when the URL template
     *                contains both {@code {sender}} and {@code {data}}
     *                placeholders (so the request can fit in the URL),
     *                POST otherwise.
     * @param url     URL with {@code {sender}}/{@code {data}} placeholders
     *                already substituted.
     * @param body    For POST requests: the JSON body
     *                {@code {"sender": "0x...", "data": "0x..."}}. Null
     *                or empty for GET requests.
     */
    CompletableFuture<String> request(Method method, String url, String body);
}
