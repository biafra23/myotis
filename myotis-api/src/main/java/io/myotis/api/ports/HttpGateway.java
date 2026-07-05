package io.myotis.api.ports;

/**
 * The CCIP-Read (ERC-3668) HTTP transport — the single place the engine performs
 * HTTP, implemented per platform. The gateway is an untrusted data carrier: trust
 * comes from the resolver contract validating the response on-chain against
 * proof-verified state, so this port needs no TLS pinning or response validation
 * beyond size/timeout hygiene.
 *
 * <p>Blocking; called from engine worker threads. Implementations should apply
 * ~10–15 s timeouts and bound the response size (~1 MiB).
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
