package io.myotis.api.ports;

/**
 * The CCIP-Read (ERC-3668) HTTP transport — the single place the engine performs
 * HTTP, implemented per platform. The gateway is an untrusted data carrier: trust
 * comes from the resolver contract validating the response on-chain against
 * proof-verified state, so this port needs no TLS pinning or response validation
 * beyond size/timeout hygiene.
 *
 * <p>Blocking: the Java engine calls it from its own workers, the Rust engine's JVM
 * adapter ({@code CcipDriver}) on the thread that called the {@code EnsApi}.
 * Implementations must bound the response size (~1 MiB) and the whole request, from
 * connect to the body's last byte (~15 s). A per-read or headers-only timeout is not
 * enough: a gateway URL comes from the resolver contract, and a gateway sending its
 * body a byte at a time keeps every read short and holds that thread for as long as
 * it keeps sending.
 */
public interface HttpGateway {

    enum Method { GET, POST }

    /**
     * Perform one request and return the response body as a string.
     * {@code bodyOrNull} is the POST payload (null for GET).
     *
     * @throws RuntimeException on any transport failure (timeout, non-2xx,
     *                          oversized response) — the engine treats a throw as
     *                          "this gateway failed" and reports/falls back
     */
    String request(Method method, String url, String bodyOrNull);
}
