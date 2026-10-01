package com.jaeckel.ethp2p.app.rpc;

import io.myotis.api.ports.HttpGateway;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * JVM-only {@link HttpGateway} (the engine API's CCIP-Read transport) backed by
 * {@code java.net.http.HttpClient}. Used by the daemon and the desktop app, where
 * JVM 21 is guaranteed. Android uses its own {@code AndroidCcipGateway} over
 * {@code HttpURLConnection} instead, since the Android app cannot use
 * java.net.http at its minSdk 29 — which is also why this class lives in
 * {@code :app}.
 *
 * <p>Blocking, per the port contract. The Java engine calls it from its own
 * workers ({@code PortBridges.toCcipGateway}) and bridges to its internal async
 * shape; with the Rust engine, {@code CcipDriver} (in {@code :myotis-engines})
 * calls it on the thread that called the {@code EnsApi}. Any non-2xx HTTP status
 * is surfaced as a thrown {@link RuntimeException} carrying the status code and
 * URL, which both engines treat as "this gateway failed", moving on to the next
 * URL. That deviates from ERC-3668, whose client stops on a 4xx and tries the
 * next URL only on a 5xx.
 */
public final class JavaHttpCcipGateway implements HttpGateway {

    /** The {@link HttpGateway} contract's bounds: the response body, and the whole
     *  request from connect to the body's last byte. */
    static final int MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB
    static final Duration DEADLINE = Duration.ofSeconds(15);

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private final Duration deadline;
    private final int maxResponseBytes;

    public JavaHttpCcipGateway() {
        this(DEADLINE, MAX_RESPONSE_BYTES);
    }

    /** Tests shrink the bounds. */
    JavaHttpCcipGateway(Duration deadline, int maxResponseBytes) {
        this.deadline = deadline;
        this.maxResponseBytes = maxResponseBytes;
    }

    @Override
    public String request(Method method, String url, String bodyOrNull) {
        // URI.create() throws IllegalArgumentException on a malformed gateway URL
        // (CCIP gateway URLs are contract-supplied, so untrusted) — that's a valid
        // "this gateway failed" signal under the port's throw-on-failure contract.
        HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(url));
        if (method == Method.POST) {
            rb.header("Content-Type", "application/json");
            rb.POST(HttpRequest.BodyPublishers.ofString(bodyOrNull == null ? "" : bodyOrNull));
        } else {
            rb.GET();
        }
        // A request timeout would only bound the wait for the response headers: the body
        // is then read with no limit on its size or on how slowly it arrives. A gateway
        // URL comes from the resolver contract, so a hostile server can send headers and
        // then stream for as long as it likes, holding this thread and growing the heap.
        // So the whole exchange runs under one deadline, and the body stops at the cap.
        // An error body is not read at all: its status is all a failure needs.
        CompletableFuture<HttpResponse<String>> pending = CLIENT.sendAsync(rb.build(),
                info -> isSuccess(info.statusCode())
                        ? new CappedBody(maxResponseBytes)
                        : new NoBody());
        HttpResponse<String> resp;
        try {
            resp = pending.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw new RuntimeException("no complete response within " + deadline.toMillis()
                    + " ms from " + url);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            throw new RuntimeException("HTTP transport failure for " + url + ": "
                    + cause.getMessage(), cause);
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw new RuntimeException("interrupted during gateway request to " + url, e);
        }
        int status = resp.statusCode();
        if (isSuccess(status)) {
            return resp.body();
        }
        throw new RuntimeException("HTTP " + status + " from " + url);
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /**
     * Takes none of the body: cancels the transfer as it starts, so an error status is
     * reported as soon as the headers arrive, and the body is cut off, not drained.
     */
    private static final class NoBody implements HttpResponse.BodySubscriber<String> {

        private final CompletableFuture<String> body = new CompletableFuture<>();

        @Override
        public CompletionStage<String> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            s.cancel();
            body.complete(null);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
        }

        @Override
        public void onError(Throwable t) {
        }

        @Override
        public void onComplete() {
        }
    }

    /**
     * Collects the body up to {@code max} bytes; one byte more cancels the transfer and
     * fails the response. Decoded as UTF-8, the encoding of the JSON a gateway returns.
     * The client signals a subscriber serially, so the buffer needs no locking.
     */
    private static final class CappedBody implements HttpResponse.BodySubscriber<String> {

        private final int max;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private final CompletableFuture<String> body = new CompletableFuture<>();
        private Flow.Subscription subscription;

        CappedBody(int max) {
            this.max = max;
        }

        @Override
        public CompletionStage<String> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (body.isDone()) {
                return;
            }
            for (ByteBuffer item : items) {
                if (item.remaining() > max - buf.size()) {
                    subscription.cancel();
                    body.completeExceptionally(
                            new IOException("CCIP gateway response exceeds " + max + " bytes"));
                    return;
                }
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                buf.write(chunk, 0, chunk.length);
            }
        }

        @Override
        public void onError(Throwable t) {
            body.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            body.complete(buf.toString(StandardCharsets.UTF_8));
        }
    }
}
