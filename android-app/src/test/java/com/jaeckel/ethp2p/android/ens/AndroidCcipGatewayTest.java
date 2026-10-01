package com.jaeckel.ethp2p.android.ens;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.OkUrlFactory;
import io.myotis.api.ports.HttpGateway.Method;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ProtocolException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.After;
import org.junit.Test;

/**
 * The gateway's deadline and size cap against local servers, one connection each. It runs
 * on OkHttp 2.7.5's HttpURLConnection, the code Android's platform HttpURLConnection is
 * forked from, not on the host JDK's: the deadline rests on how disconnect() cancels a
 * call, and the JDK's works differently (it waits for a read in progress). Every test
 * gets a fresh client and fresh connections: upstream OkHttp lacks Android's patch that a
 * cancelled call never recovers, and retries one on a pooled connection forever. The
 * per-test timeout turns a gateway that hangs into a failure.
 */
public class AndroidCcipGatewayTest {

    private static final long DEADLINE_MS = 500;
    /** How far past the deadline a request may end: scheduling, not network time. */
    private static final long SLACK_MS = 2_000;
    private static final int MAX_RESPONSE_BYTES = 1_048_576;

    private final AndroidCcipGateway gateway =
            new AndroidCcipGateway(DEADLINE_MS, new OkUrlFactory(new OkHttpClient())::open);
    private final List<ServerSocket> servers = new ArrayList<>();
    private final List<Thread> serverThreads = new ArrayList<>();

    /** Answers the one request a test makes, given its head and body. */
    private interface Responder {
        void respond(String head, String body, OutputStream out) throws IOException, InterruptedException;
    }

    private String serve(Responder responder) throws IOException {
        ServerSocket server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        servers.add(server);
        Thread serverThread = new Thread(() -> {
            try (Socket socket = server.accept()) {
                InputStream in = socket.getInputStream();
                String head = readHead(in);
                byte[] body = new byte[contentLength(head)];
                for (int off = 0, n; off < body.length; off += n) {
                    if ((n = in.read(body, off, body.length - off)) < 0) throw new IOException("short body");
                }
                responder.respond(head, new String(body, UTF_8), socket.getOutputStream());
            } catch (IOException | InterruptedException ignored) {
                // the test's assertions report what went wrong
            }
        }, "ccip-test-server");
        serverThread.setDaemon(true);
        serverThread.start();
        serverThreads.add(serverThread);
        return "http://127.0.0.1:" + server.getLocalPort() + "/";
    }

    @After
    public void stop() throws IOException {
        for (Thread serverThread : serverThreads) serverThread.interrupt();
        for (ServerSocket server : servers) server.close();
    }

    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            head.write(b);
            if (head.toString("UTF-8").endsWith("\r\n\r\n")) break;
        }
        return head.toString("UTF-8");
    }

    private static int contentLength(String head) {
        for (String line : head.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                return Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }
        return 0;
    }

    private static void respond(OutputStream out, int status, byte[] body) throws IOException {
        out.write(("HTTP/1.1 " + status + " X\r\nContent-Length: " + body.length
                + "\r\nConnection: close\r\n\r\n").getBytes(UTF_8));
        out.write(body);
        out.flush();
    }

    private static byte[] filled(int size) {
        byte[] bytes = new byte[size];
        Arrays.fill(bytes, (byte) 'a');
        return bytes;
    }

    private RuntimeException failure(String url) {
        return assertThrows(RuntimeException.class, () -> gateway.request(Method.GET, url, null));
    }

    private static long msSince(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    @Test(timeout = 30_000)
    public void returnsA2xxBody() throws IOException {
        String url = serve((head, body, out) -> respond(out, 200, "{\"data\":\"0x01\"}".getBytes(UTF_8)));
        assertEquals("{\"data\":\"0x01\"}", gateway.request(Method.GET, url, null));
    }

    @Test(timeout = 30_000)
    public void postsTheBodyAsJson() throws IOException {
        String url = serve((head, body, out) -> {
            boolean json = head.toLowerCase(Locale.ROOT).contains("content-type: application/json");
            respond(out, 200, (head.substring(0, head.indexOf(' ')) + " " + json + " " + body).getBytes(UTF_8));
        });
        assertEquals("POST true {\"sender\":\"0xab\"}",
                gateway.request(Method.POST, url, "{\"sender\":\"0xab\"}"));
    }

    @Test(timeout = 30_000)
    public void aNon2xxStatusFails() throws IOException {
        String url = serve((head, body, out) -> respond(out, 404, "not here".getBytes(UTF_8)));
        RuntimeException e = failure(url);
        assertTrue(e.getMessage(), e.getMessage().contains("HTTP 404"));
    }

    @Test(timeout = 30_000)
    public void aRedirectIsFollowedAndTheDeadlineCoversTheNextHop() throws IOException {
        // The next hop is another server whose headers never come. Not followed, the
        // redirect would fail at once with its status rather than at the deadline.
        String next = serve((head, body, out) -> Thread.sleep(60_000));
        String url = serve((head, body, out) -> out.write(("HTTP/1.1 302 Found\r\nLocation: " + next
                + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").getBytes(UTF_8)));
        long start = System.nanoTime();
        RuntimeException e = failure(url);
        long elapsedMs = msSince(start);
        assertTrue(e.getMessage(), e.getMessage().contains("no complete response within " + DEADLINE_MS + " ms"));
        assertTrue("took " + elapsedMs + " ms", elapsedMs < DEADLINE_MS + SLACK_MS);
    }

    @Test(timeout = 30_000)
    public void aBodyOverTheCapFails() throws IOException {
        String url = serve((head, body, out) -> respond(out, 200, filled(MAX_RESPONSE_BYTES + 1)));
        RuntimeException e = failure(url);
        assertTrue(e.getMessage(), e.getMessage().contains("exceeds " + MAX_RESPONSE_BYTES + " bytes"));
    }

    @Test(timeout = 30_000)
    public void aBodyThatNeverEndsFailsAtTheDeadlineAndClosesTheConnection()
            throws IOException, InterruptedException {
        // Headers at once, then a byte at a time: each read returns long before the read
        // timeout, so only a deadline on the whole request ends it.
        CountDownLatch hungUp = new CountDownLatch(1);
        String url = serve((head, body, out) -> {
            out.write("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n".getBytes(UTF_8));
            try {
                while (true) {
                    out.write('a');
                    out.flush();
                    Thread.sleep(20);
                }
            } catch (IOException e) {
                hungUp.countDown();
            }
        });
        long start = System.nanoTime();
        RuntimeException e = failure(url);
        long elapsedMs = msSince(start);
        assertTrue(e.getMessage(), e.getMessage().contains("no complete response within " + DEADLINE_MS + " ms"));
        assertTrue("took " + elapsedMs + " ms", elapsedMs < DEADLINE_MS + SLACK_MS);
        assertTrue("the connection was left open", hungUp.await(5, TimeUnit.SECONDS));
    }

    @Test(timeout = 30_000)
    public void aBodyThatStopsFailsAtTheDeadline() throws IOException {
        // Headers, then nothing: no read returns, so only the disconnect can end it.
        String url = serve((head, body, out) -> {
            out.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".getBytes(UTF_8));
            out.flush();
            Thread.sleep(60_000);
        });
        long start = System.nanoTime();
        RuntimeException e = failure(url);
        long elapsedMs = msSince(start);
        assertTrue(e.getMessage(), e.getMessage().contains("no complete response within " + DEADLINE_MS + " ms"));
        assertTrue("took " + elapsedMs + " ms", elapsedMs < DEADLINE_MS + SLACK_MS);
    }

    @Test(timeout = 30_000)
    public void aDisconnectThatThrowsIsRepeated() throws IOException {
        // The watchdog's first disconnect throws: the repeat a second later must still end
        // a request whose headers never come, not leave it to the 15 s read timeout.
        AndroidCcipGateway gateway = new AndroidCcipGateway(DEADLINE_MS,
                url -> new FirstDisconnectThrows(new OkUrlFactory(new OkHttpClient()).open(url)));
        String url = serve((head, body, out) -> Thread.sleep(60_000));
        long start = System.nanoTime();
        RuntimeException e = assertThrows(RuntimeException.class, () -> gateway.request(Method.GET, url, null));
        long elapsedMs = msSince(start);
        assertTrue(e.getMessage(), e.getMessage().contains("no complete response within " + DEADLINE_MS + " ms"));
        assertTrue("took " + elapsedMs + " ms", elapsedMs < DEADLINE_MS + 1_000 + SLACK_MS);
    }

    /** Android's HttpURLConnection, except that its first disconnect() throws. */
    private static final class FirstDisconnectThrows extends HttpURLConnection {

        private final HttpURLConnection delegate;
        private final AtomicBoolean thrown = new AtomicBoolean();

        FirstDisconnectThrows(HttpURLConnection delegate) {
            super(delegate.getURL());
            this.delegate = delegate;
        }

        @Override
        public void disconnect() {
            if (thrown.compareAndSet(false, true)) {
                throw new IllegalStateException("the first disconnect fails");
            }
            delegate.disconnect();
        }

        @Override public boolean usingProxy() { return delegate.usingProxy(); }
        @Override public void connect() throws IOException { delegate.connect(); }
        @Override public void setConnectTimeout(int ms) { delegate.setConnectTimeout(ms); }
        @Override public void setReadTimeout(int ms) { delegate.setReadTimeout(ms); }
        @Override public void setRequestMethod(String method) throws ProtocolException { delegate.setRequestMethod(method); }
        @Override public void setDoOutput(boolean doOutput) { delegate.setDoOutput(doOutput); }
        @Override public void setRequestProperty(String key, String value) { delegate.setRequestProperty(key, value); }
        @Override public OutputStream getOutputStream() throws IOException { return delegate.getOutputStream(); }
        @Override public int getResponseCode() throws IOException { return delegate.getResponseCode(); }
        @Override public InputStream getInputStream() throws IOException { return delegate.getInputStream(); }
    }

    @Test(timeout = 30_000)
    public void headersThatNeverComeFailAtTheDeadline() throws IOException {
        String url = serve((head, body, out) -> Thread.sleep(60_000));
        long start = System.nanoTime();
        RuntimeException e = failure(url);
        long elapsedMs = msSince(start);
        assertTrue(e.getMessage(), e.getMessage().contains("no complete response within " + DEADLINE_MS + " ms"));
        assertTrue("took " + elapsedMs + " ms", elapsedMs < DEADLINE_MS + SLACK_MS);
    }
}
