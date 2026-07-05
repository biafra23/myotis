package com.jaeckel.ethp2p.app.rpc;

import io.myotis.api.ports.HttpGateway;

/**
 * JVM-only {@link HttpGateway} (the engine API's CCIP-Read transport) backed by
 * {@code java.net.http.HttpClient}. Used by the daemon, where JVM 21 is guaranteed.
 * Android consumers must supply a Ktor-backed gateway per {@code CLAUDE.md}
 * (java.net.http isn't covered by Android core library desugaring below API 33) —
 * which is also why this class lives in {@code :app}.
 *
 * <p>Blocking, per the port contract: the engine calls it from its own workers and
 * bridges to its internal async shape. Per ERC-3668 §6.1, any non-2xx HTTP status
 * must be treated as an error so the CCIP handler can fall through to the next URL
 * in the gateway list — surfaced here as a thrown {@link RuntimeException} carrying
 * the status code and URL.
 */
public final class JavaHttpCcipGateway implements HttpGateway {

    private static final java.net.http.HttpClient CLIENT = java.net.http.HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build();

    @Override
    public String request(Method method, String url, String bodyOrNull) {
        // URI.create() throws IllegalArgumentException on a malformed gateway URL
        // (CCIP gateway URLs are contract-supplied, so untrusted) — that's a valid
        // "this gateway failed" signal under the port's throw-on-failure contract.
        java.net.http.HttpRequest.Builder rb = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(15));
        if (method == Method.POST) {
            rb.header("Content-Type", "application/json");
            rb.POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                    bodyOrNull == null ? "" : bodyOrNull));
        } else {
            rb.GET();
        }
        try {
            java.net.http.HttpResponse<String> resp = CLIENT.send(
                    rb.build(), java.net.http.HttpResponse.BodyHandlers.ofString());
            int status = resp.statusCode();
            if (status >= 200 && status < 300) {
                return resp.body();
            }
            throw new RuntimeException("HTTP " + status + " from " + url);
        } catch (java.io.IOException e) {
            throw new RuntimeException("HTTP transport failure for " + url + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("interrupted during gateway request to " + url, e);
        }
    }
}
