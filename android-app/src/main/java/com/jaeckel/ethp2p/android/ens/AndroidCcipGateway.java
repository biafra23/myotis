package com.jaeckel.ethp2p.android.ens;

import io.myotis.api.ports.HttpGateway;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * CCIP-Read transport for Android — the engine API's {@link HttpGateway} port, backed
 * by {@link HttpURLConnection}.
 *
 * <p>The JVM daemon uses a {@code java.net.http.HttpClient} gateway, but that API is
 * unavailable on Android below API 33 and not covered by {@code coreLibraryDesugaring} —
 * at minSdk 29 it would {@code NoClassDefFound} at runtime. {@link HttpURLConnection}
 * has been present since API 1.
 *
 * <p>Blocking, per the port contract: the engine calls it from its own worker threads
 * and bridges to its internal async shape. This is a legitimate outbound HTTP call, not
 * a "data source": ERC-3668 gateway responses are not trusted — the resolver
 * re-validates them via the on-chain callback, so the devp2p/libp2p-only rule holds.
 */
public final class AndroidCcipGateway implements HttpGateway {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 15_000;
    /**
     * Hard cap on the response body. ERC-3668 gateway responses are JSON wrapping a
     * small ABI blob (well under 1 MB); without a cap, a malicious or misconfigured
     * gateway could stream unbounded data into memory and OOM the app.
     */
    private static final int MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB

    @Override
    public String request(Method method, String url, String bodyOrNull) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            if (method == Method.POST) {
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                byte[] payload = (bodyOrNull == null ? "" : bodyOrNull).getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(payload);
                }
            } else {
                conn.setRequestMethod("GET");
            }
            int status = conn.getResponseCode();
            if (status >= 200 && status < 300) {
                // Close the stream explicitly (don't rely on disconnect()) so the
                // underlying socket can be released back for connection reuse.
                try (InputStream in = conn.getInputStream()) {
                    return readAll(in);
                }
            }
            throw new RuntimeException("HTTP " + status + " from " + url);
        } catch (IOException e) {
            throw new RuntimeException("HTTP transport failure for " + url + ": " + e.getMessage(), e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
            if (buf.size() > MAX_RESPONSE_BYTES) {
                throw new IOException("CCIP gateway response exceeds "
                        + MAX_RESPONSE_BYTES + " bytes");
            }
        }
        return buf.toString(StandardCharsets.UTF_8.name());
    }
}
