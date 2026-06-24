package com.jaeckel.ethp2p.consensus;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Isolates <em>all</em> {@code java.net.http} references into one class.
 *
 * <p>{@code java.net.http} is not shipped on the Android runtime at any API level, so
 * resolving {@link HttpClient} et al. throws {@link NoClassDefFoundError} (a
 * {@link LinkageError}). Keeping every reference here — out of {@link BeaconLightClient}'s
 * bytecode — means the JVM/ART only resolves (and can only fail to resolve)
 * {@code java.net.http} at the moment this class is <em>first touched</em>, i.e. inside the
 * caller's {@code try { … } catch (LinkageError)}. A {@code catch} placed around inline
 * {@code java.net.http} usage is NOT enough on its own: class verification / method
 * resolution can throw at the call site (when the enclosing method is resolved) or at class
 * load, <em>outside</em> the {@code try}. Lazy class loading of this separate class makes the
 * failure happen exactly where it is caught.
 *
 * <p>These beacon-HTTP helpers are JVM-only <em>debug</em> conveniences; the real,
 * trust-minimised path is libp2p/discv5.
 */
final class BeaconApiHttp {

    private BeaconApiHttp() {}

    /** A beacon-API GET response: HTTP status code + raw body bytes. */
    record Response(int statusCode, byte[] body) {}

    /**
     * GET {@code url}, returning the status code and raw body bytes.
     *
     * @param accept            value for the {@code Accept} header, or {@code null} for none
     * @param connectTimeoutSec TCP connect timeout, seconds
     * @param requestTimeoutSec overall request timeout, seconds
     * @throws LinkageError if {@code java.net.http} is absent on this runtime — the caller
     *                      catches it and degrades to the P2P path
     * @throws Exception    on I/O failure / interruption
     */
    static Response get(String url, String accept,
                        int connectTimeoutSec, int requestTimeoutSec) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(connectTimeoutSec))
                .build();
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(requestTimeoutSec))
                .GET();
        if (accept != null) {
            builder.header("Accept", accept);
        }
        HttpResponse<byte[]> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        return new Response(response.statusCode(), response.body());
    }
}
