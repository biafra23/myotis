package io.myotis.engines;

import io.myotis.api.WebAccessMode;
import io.myotis.api.WebAccessPolicy;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The selector's Ktor listener behind the Rust engine's {@code LoopbackRpc} port:
 * it binds the loopback port it is given, answers HTTP there, reports its live
 * state, applies the web-page policy before and after start, and refuses a port
 * that is taken with the {@link IOException} the handle logs and continues on.
 */
class KtorLoopbackRpcTest {

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    @Test
    void bindsServesReportsAndStops() throws Exception {
        KtorLoopbackRpc rpc = new KtorLoopbackRpc();
        assertFalse(rpc.isServing(), "nothing listens before start()");
        // The policy lands on the gate before the server exists (hosts set it
        // between create() and start()); the non-origin entry is dropped from
        // what applies, as the ChainHandle contract describes.
        WebAccessPolicy applied = rpc.setWebAccessPolicy(new WebAccessPolicy(
                WebAccessMode.ALLOWLIST, List.of("https://app.example", "not an origin")));
        assertEquals(List.of("https://app.example"), applied.origins());

        int port = freePort();
        rpc.start(port, null, null, null);
        try {
            assertTrue(rpc.isServing());
            HttpURLConnection c = (HttpURLConnection) URI.create("http://127.0.0.1:" + port + "/").toURL().openConnection();
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            c.getOutputStream().write("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"web3_clientVersion\"}".getBytes());
            assertEquals(200, c.getResponseCode(), "the listener answers JSON-RPC on the bound port");
            c.disconnect();
        } finally {
            rpc.stop();
        }
        assertFalse(rpc.isServing(), "stopped");
        rpc.stop(); // idempotent
    }

    @Test
    void refusesATakenPortWithIOException() throws Exception {
        try (ServerSocket taken = new ServerSocket()) {
            taken.setReuseAddress(true);
            taken.bind(new java.net.InetSocketAddress("127.0.0.1", 0));
            KtorLoopbackRpc rpc = new KtorLoopbackRpc();
            assertThrows(IOException.class, () -> rpc.start(taken.getLocalPort(), null, null, null));
            assertFalse(rpc.isServing());
        }
    }
}
