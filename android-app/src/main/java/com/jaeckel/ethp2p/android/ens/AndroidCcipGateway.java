package com.jaeckel.ethp2p.android.ens;

import io.myotis.api.ports.HttpGateway;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * CCIP-Read transport for Android — the engine API's {@link HttpGateway} port, backed
 * by {@link HttpURLConnection}.
 *
 * <p>The JVM daemon uses a {@code java.net.http.HttpClient} gateway, but that API is
 * unavailable on Android below API 33 and not covered by {@code coreLibraryDesugaring} —
 * at minSdk 29 it would {@code NoClassDefFound} at runtime. {@link HttpURLConnection}
 * has been present since API 1.
 *
 * <p>Blocking, per the port contract: the Java engine calls it from its own workers, the
 * Rust engine's JVM adapter ({@code CcipDriver}; the Rust engine is the only one below
 * API 33) on the thread that called the {@code EnsApi}. This is a legitimate outbound
 * HTTP call, not a "data source": ERC-3668 gateway responses are not trusted — the
 * resolver re-validates them via the on-chain callback, so the devp2p/libp2p-only rule
 * holds.
 */
public final class AndroidCcipGateway implements HttpGateway {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 15_000;
    /**
     * The whole request, from connect to the body's last byte. The read timeout bounds
     * each read, not their sum: a gateway sending a byte every few seconds never trips
     * it, and could hold the calling thread for as long as it likes. The one part the
     * deadline cannot cut short is the host's DNS lookup, made before there is a socket
     * to close: the platform resolver bounds that, and the request fails as it returns.
     */
    static final long DEADLINE_MS = 15_000;
    /** How often a request past its deadline is disconnected again (see {@link #DEADLINES}). */
    private static final long REDISCONNECT_MS = 1_000;
    /**
     * Hard cap on the response body. ERC-3668 gateway responses are JSON wrapping a
     * small ABI blob (well under 1 MB); without a cap, a malicious or misconfigured
     * gateway could stream unbounded data into memory and OOM the app.
     */
    private static final int MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB

    /**
     * Disconnects a request that outlives its deadline, then again every
     * {@link #REDISCONNECT_MS} until it ends. On Android a disconnect cancels the call by
     * closing the socket in use at that moment, so a blocked read throws; one opened just
     * after, or by a redirect to another host, is caught by the next. A finished
     * request's task is removed, not left holding its connection until the deadline.
     */
    private static final ScheduledThreadPoolExecutor DEADLINES =
            new ScheduledThreadPoolExecutor(1, r -> {
                Thread t = new Thread(r, "ccip-gateway-deadline");
                t.setDaemon(true);
                return t;
            });

    static {
        DEADLINES.setRemoveOnCancelPolicy(true);
    }

    /** Opens the connection: the platform's, or in tests the one Android's is forked from. */
    interface Opener {
        HttpURLConnection open(URL url) throws IOException;
    }

    private final long deadlineMs;
    private final Opener opener;

    public AndroidCcipGateway() {
        this(DEADLINE_MS, url -> (HttpURLConnection) url.openConnection());
    }

    /** Tests shrink the deadline and pick the HttpURLConnection. */
    AndroidCcipGateway(long deadlineMs, Opener opener) {
        this.deadlineMs = deadlineMs;
        this.opener = opener;
    }

    @Override
    public String request(Method method, String url, String bodyOrNull) {
        HttpURLConnection conn = null;
        ScheduledFuture<?> watchdog = null;
        AtomicBoolean expired = new AtomicBoolean();
        try {
            conn = opener.open(new URL(url));
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            HttpURLConnection timed = conn;
            watchdog = DEADLINES.scheduleWithFixedDelay(() -> {
                expired.set(true);
                try {
                    timed.disconnect();
                } catch (RuntimeException e) {
                    // Swallowed: a run that throws ends scheduleWithFixedDelay's repeats,
                    // and the repeat is what reaches a socket opened after this one.
                }
            }, deadlineMs, REDISCONNECT_MS, TimeUnit.MILLISECONDS);
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
                    return readAll(in, expired);
                }
            }
            throw new RuntimeException("HTTP " + status + " from " + url);
        } catch (IOException e) {
            if (expired.get()) {
                throw new RuntimeException("no complete response within " + deadlineMs
                        + " ms from " + url, e);
            }
            throw new RuntimeException("HTTP transport failure for " + url + ": " + e.getMessage(), e);
        } finally {
            if (watchdog != null) watchdog.cancel(false);
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * Reads the body to its end, or until the deadline. The deadline is checked between
     * reads as well, not left to the disconnect alone: a body arriving a byte at a time
     * keeps every read short, so it ends at the deadline however late the disconnect
     * lands (the JDK's HttpURLConnection, unlike Android's, makes it wait for the stream).
     */
    private static String readAll(InputStream in, AtomicBoolean expired) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while (!expired.get() && (n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
            if (buf.size() > MAX_RESPONSE_BYTES) {
                throw new IOException("CCIP gateway response exceeds "
                        + MAX_RESPONSE_BYTES + " bytes");
            }
        }
        // Checked after the last read too: a disconnect can end the body like an EOF
        // rather than failing a read, so a body that ended past the deadline may be cut short.
        if (expired.get()) {
            throw new IOException("deadline passed");
        }
        return buf.toString(StandardCharsets.UTF_8.name());
    }
}
