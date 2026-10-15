package io.myotis.engines.rust;

import io.myotis.api.NodeLifecycle;
import io.myotis.api.NodeStatusReads;
import io.myotis.api.VerifiedReads;
import io.myotis.api.WebAccessPolicy;
import io.myotis.api.WebOrigin;

import java.io.IOException;
import java.util.List;

/**
 * The loopback JSON-RPC listener a host attaches to one Rust-hosted network — a
 * PORT, so this module carries no HTTP server: the engine library (the Android AAR,
 * the desktop jar) ships the engine without the listener (owner's request,
 * 2026-10-15), and the {@code :myotis-engines} selector supplies the Ktor one the
 * JVM hosts have always had ({@code KtorLoopbackRpc} there, over
 * {@code jsonrpc-server}). A handle created with no listener answers
 * {@link io.myotis.api.ChainHandle#reads()} in-process once started and judges no
 * web origin ({@link #setWebAccessPolicy} has nothing to install on).
 *
 * <p>One instance per handle ({@link Factory#create} is called once per
 * {@code create()}), owned by the handle: it survives idle sleep like the Java
 * engine's listener (a request on the port is what WAKES the stack) and is stopped
 * in {@code stop()}, before the native stack goes.
 */
public interface LoopbackRpc {

    /**
     * Builds one listener per handle, called once per {@code create()} before the
     * native handle exists (so a throw leaks nothing native). A {@code null} factory
     * means no listener; a factory RETURNING {@code null} means the same for that
     * handle — the handle then behaves exactly as with no factory (in-process
     * {@code reads()}, no RPC status row, policy normalized but judged by nothing).
     */
    @FunctionalInterface
    interface Factory {
        LoopbackRpc create();
    }

    /**
     * Install the host's web-page policy on the gate this listener judges requests
     * by — live, and before {@link #start} too (hosts set it between {@code create()}
     * and {@code start()}). Returns the policy that now applies, as the
     * {@link io.myotis.api.ChainHandle#setWebAccessPolicy} contract describes it.
     */
    WebAccessPolicy setWebAccessPolicy(WebAccessPolicy policy);

    /** The recent-origins list, most recent first ({@link io.myotis.api.ChainHandle#recentWebOrigins}). */
    List<WebOrigin> recentWebOrigins();

    /**
     * Bind {@code 127.0.0.1:port} and serve {@code reads}, with {@code status} and
     * {@code lifecycle} behind the status and wake surfaces. Blocking until the
     * listener is up.
     *
     * @throws IOException when the port cannot be bound — the handle logs it and
     *         continues without JSON-RPC, as the Java engine does
     */
    void start(int port, VerifiedReads reads, NodeStatusReads status, NodeLifecycle lifecycle)
            throws IOException;

    /** Bound AND no fatal supervisor failure — the live listener state the status row shows. */
    boolean isServing();

    /** Stop serving. Idempotent. */
    void stop();
}
