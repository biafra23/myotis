package io.myotis.engines;

import io.myotis.api.NodeLifecycle;
import io.myotis.api.NodeStatusReads;
import io.myotis.api.VerifiedReads;
import io.myotis.api.WebAccessPolicy;
import io.myotis.api.WebOrigin;
import io.myotis.engines.rust.LoopbackRpc;
import io.myotis.jsonrpc.MyotisRpc;
import io.myotis.jsonrpc.MyotisRpcServer;
import io.myotis.jsonrpc.WebAccess;
import io.myotis.jsonrpc.WebAccessApi;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.List;

/**
 * The JVM hosts' loopback JSON-RPC listener for a Rust-hosted network: the shared
 * {@code jsonrpc-server} (Ktor CIO, strict — no upstream proxy) over the handle's
 * {@link VerifiedReads}, exactly what {@code RustChainHandle} used to self-start.
 * It lives here, with the selector, so that {@code :myotis-engine-rust} carries no
 * server (see {@link LoopbackRpc}); the selector hands one to every Rust handle it
 * creates, so the daemon, the desktop app and the Android app keep the listener
 * they always had.
 */
final class KtorLoopbackRpc implements LoopbackRpc {

    private static final String HOST = "127.0.0.1";

    /** The web-page gate (#502): the host's policy and the recent-origins list. Owned
     *  here so the policy can be set before the server exists and read after it stopped. */
    private final WebAccess webAccess = new WebAccess();
    private volatile MyotisRpcServer server;

    @Override
    public WebAccessPolicy setWebAccessPolicy(WebAccessPolicy policy) {
        return WebAccessApi.apply(webAccess, policy);
    }

    @Override
    public List<WebOrigin> recentWebOrigins() {
        return WebAccessApi.recent(webAccess);
    }

    @Override
    public synchronized void start(int port, VerifiedReads reads, NodeStatusReads status,
            NodeLifecycle lifecycle) throws IOException {
        if (server != null) return;
        // Deterministic up-front bind probe: Ktor's CIO engine surfaces bind
        // failures asynchronously, which a try/catch around start() can miss.
        try (ServerSocket probe = new ServerSocket()) {
            probe.setReuseAddress(true);
            probe.bind(new InetSocketAddress(HOST, port));
        }
        MyotisRpcServer s = MyotisRpc.server(port, null, HOST, reads, status, lifecycle, webAccess);
        s.start();
        server = s;
    }

    @Override
    public boolean isServing() {
        MyotisRpcServer s = server;
        return s != null && s.isServing();
    }

    @Override
    public synchronized void stop() {
        MyotisRpcServer s = server;
        if (s == null) return;
        server = null;
        s.stop();
    }
}
