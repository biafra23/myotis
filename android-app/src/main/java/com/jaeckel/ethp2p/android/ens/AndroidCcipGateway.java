package com.jaeckel.ethp2p.android.ens;

import io.myotis.evm.ccipread.CcipGateway;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * CCIP-Read ({@link CcipGateway}) transport for Android, backed by
 * {@link HttpURLConnection}.
 *
 * <p>The JVM daemon uses a {@code java.net.http.HttpClient} gateway, but that
 * API is unavailable on Android below API 33 and is not covered by
 * {@code coreLibraryDesugaring} — at minSdk 29 it would {@code NoClassDefFound}
 * at runtime. {@link HttpURLConnection} has been present since API 1.
 *
 * <p>This is a legitimate outbound HTTP call, not a "data source": ERC-3668
 * gateway responses are not trusted — the resolver re-validates them via the
 * on-chain callback. So it does not violate the devp2p/libp2p-only data-source
 * rule. Calls run on the supplied {@link Executor} (off the UI thread).
 */
public final class AndroidCcipGateway implements CcipGateway {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 15_000;

    private final Executor executor;

    public AndroidCcipGateway(Executor executor) {
        this.executor = executor;
    }

    @Override
    public CompletableFuture<String> request(Method method, String url, String body) {
        CompletableFuture<String> result = new CompletableFuture<>();
        executor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
                conn.setReadTimeout(READ_TIMEOUT_MS);
                if (method == Method.POST) {
                    conn.setRequestMethod("POST");
                    conn.setDoOutput(true);
                    conn.setRequestProperty("Content-Type", "application/json");
                    byte[] payload = (body == null ? "" : body).getBytes(StandardCharsets.UTF_8);
                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(payload);
                    }
                } else {
                    conn.setRequestMethod("GET");
                }
                int status = conn.getResponseCode();
                if (status >= 200 && status < 300) {
                    result.complete(readAll(conn.getInputStream()));
                } else {
                    result.completeExceptionally(
                            new IOException("HTTP " + status + " from " + url));
                }
            } catch (Exception e) {
                result.completeExceptionally(e);
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
        return result;
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
        }
        return buf.toString(StandardCharsets.UTF_8.name());
    }
}
