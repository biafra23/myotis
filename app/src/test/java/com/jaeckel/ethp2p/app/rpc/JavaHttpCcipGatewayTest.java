package com.jaeckel.ethp2p.app.rpc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.myotis.api.ports.HttpGateway.Method;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gateway's bounds against a local server: the response-size cap, and one deadline
 * for the whole exchange. The class timeout turns a gateway that hangs into a failure.
 */
@Timeout(30)
class JavaHttpCcipGatewayTest {

    private static final Duration DEADLINE = Duration.ofMillis(500);
    private static final int CAP = 1_000;
    /** How far past the deadline a request may end: scheduling, not network time. */
    private static final long SLACK_MS = 2_000;

    private final JavaHttpCcipGateway gateway = new JavaHttpCcipGateway(DEADLINE, CAP);
    private HttpServer server;
    private ExecutorService handlers;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        handlers = Executors.newCachedThreadPool();
        server.setExecutor(handlers);
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
        handlers.shutdownNow();
    }

    private String serve(String path, HttpHandler handler) {
        server.createContext(path, handler);
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    private static void respond(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(UTF_8);
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private RuntimeException failure(String url) {
        return assertThrows(RuntimeException.class, () -> gateway.request(Method.GET, url, null));
    }

    @Test
    void returnsA2xxBody() {
        String url = serve("/ok", ex -> respond(ex, 200, "{\"data\":\"0x01\"}"));
        assertEquals("{\"data\":\"0x01\"}", gateway.request(Method.GET, url, null));
    }

    @Test
    void postsTheBodyAsJson() {
        String url = serve("/post", ex -> {
            String received = new String(ex.getRequestBody().readAllBytes(), UTF_8);
            respond(ex, 200, ex.getRequestMethod() + " "
                    + ex.getRequestHeaders().getFirst("Content-Type") + " " + received);
        });
        assertEquals("POST application/json {\"sender\":\"0xab\"}",
                gateway.request(Method.POST, url, "{\"sender\":\"0xab\"}"));
    }

    @Test
    void aNon2xxStatusFails() {
        String url = serve("/missing", ex -> respond(ex, 404, "not here"));
        RuntimeException e = failure(url);
        assertTrue(e.getMessage().contains("HTTP 404"), e.getMessage());
    }

    @Test
    void aBodyAtTheCapIsReturnedAndOneByteMoreFails() {
        String atCap = serve("/at-cap", ex -> respond(ex, 200, "a".repeat(CAP)));
        assertEquals(CAP, gateway.request(Method.GET, atCap, null).length());

        String overCap = serve("/over-cap", ex -> respond(ex, 200, "a".repeat(CAP + 1)));
        RuntimeException e = failure(overCap);
        assertTrue(e.getMessage().contains("exceeds " + CAP + " bytes"), e.getMessage());
    }

    @Test
    void anErrorStatusIsReportedWithoutReadingItsBody() throws InterruptedException {
        // An error body that never ends: read, it would run into the deadline instead,
        // and drained, it would keep the connection open.
        CountDownLatch hungUp = new CountDownLatch(1);
        String url = serve("/endless-error", ex -> {
            ex.sendResponseHeaders(500, 0);
            OutputStream os = ex.getResponseBody();
            try {
                while (true) {
                    os.write('e');
                    os.flush();
                    Thread.sleep(20);
                }
            } catch (IOException e) {
                hungUp.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                ex.close();
            }
        });
        RuntimeException e = failure(url);
        assertTrue(e.getMessage().contains("HTTP 500"), e.getMessage());
        assertTrue(hungUp.await(5, TimeUnit.SECONDS), "the error response's connection was left open");
    }

    @Test
    void aBodyThatNeverEndsFailsAtTheDeadlineAndClosesTheConnection() throws InterruptedException {
        // Headers at once, then a byte at a time: no single read ever waits long, so only
        // a deadline on the whole exchange ends it. This hung the gateway before.
        CountDownLatch hungUp = new CountDownLatch(1);
        String url = serve("/drip", ex -> {
            ex.sendResponseHeaders(200, 0); // chunked: the body announces no end
            OutputStream os = ex.getResponseBody();
            try {
                while (true) {
                    os.write('a');
                    os.flush();
                    Thread.sleep(20);
                }
            } catch (IOException e) {
                hungUp.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                ex.close();
            }
        });
        long start = System.nanoTime();
        RuntimeException e = failure(url);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(e.getMessage().contains("no complete response within " + DEADLINE.toMillis() + " ms"),
                e.getMessage());
        assertTrue(elapsedMs < DEADLINE.toMillis() + SLACK_MS, "took " + elapsedMs + " ms");
        // Not just the caller let go: the exchange is cancelled and its connection closed.
        assertTrue(hungUp.await(5, TimeUnit.SECONDS), "the connection was left open");
    }

    @Test
    void headersThatNeverComeFailAtTheDeadline() {
        String url = serve("/stall", ex -> {
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        long start = System.nanoTime();
        RuntimeException e = failure(url);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(e.getMessage().contains("no complete response within " + DEADLINE.toMillis() + " ms"),
                e.getMessage());
        assertTrue(elapsedMs < DEADLINE.toMillis() + SLACK_MS, "took " + elapsedMs + " ms");
    }
}
