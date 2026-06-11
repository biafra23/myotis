package com.jaeckel.ethp2p.app.rpc;

/**
 * JVM-only {@link io.myotis.evm.ccipread.CcipGateway} backed by
 * {@code java.net.http.HttpClient}. Used by the daemon, where JVM 21 is
 * guaranteed. Android consumers must supply a Ktor-backed gateway per
 * {@code CLAUDE.md} (java.net.http isn't covered by Android core library
 * desugaring below API 33) — which is also why this class lives in {@code :app}
 * and not in the Android-consumed {@code :rpc-backend}.
 *
 * <p>Per ERC-3668 §6.1, any non-2xx HTTP status code must be treated as
 * an error so {@link io.myotis.evm.ccipread.CcipReadHandler} can fall
 * through to the next URL in the gateway list. We surface non-2xx as a
 * failed future carrying an {@link java.io.IOException} with the status
 * code and URL, which the handler's {@code exceptionallyCompose} catches
 * and folds into the per-URL diagnostic list.
 */
public final class JavaHttpCcipGateway implements io.myotis.evm.ccipread.CcipGateway {

    private static final java.net.http.HttpClient CLIENT = java.net.http.HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build();

    @Override
    public java.util.concurrent.CompletableFuture<String> request(Method method, String url, String body) {
        java.net.http.HttpRequest.Builder rb = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(15));
        if (method == Method.POST) {
            rb.header("Content-Type", "application/json");
            rb.POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                    body == null ? "" : body));
        } else {
            rb.GET();
        }
        return CLIENT.sendAsync(rb.build(),
                java.net.http.HttpResponse.BodyHandlers.ofString())
                .thenCompose(resp -> {
                    int status = resp.statusCode();
                    if (status >= 200 && status < 300) {
                        return java.util.concurrent.CompletableFuture.completedFuture(resp.body());
                    }
                    return java.util.concurrent.CompletableFuture.failedFuture(
                            new java.io.IOException("HTTP " + status + " from " + url));
                });
    }
}
