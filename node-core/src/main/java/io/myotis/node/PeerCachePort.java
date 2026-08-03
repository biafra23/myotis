package io.myotis.node;

import java.net.InetSocketAddress;
import java.util.List;

/**
 * The EL peer-cache operations a {@code ChainStack} needs, abstracted so the daemon
 * ({@code PeerCache}) and Android ({@code AndroidPeerCache}) can each supply their own
 * file-backed implementation (via a thin adapter) without {@code node-core} depending
 * on either host module.
 */
public interface PeerCachePort {

    /** Record a freshly-handshaked peer (idempotent). Wired as the RLPx connector callback. */
    void add(InetSocketAddress address, String publicKeyHex, boolean snap);

    /** Mark that {@code address} served a snap proof (promotes it toward CONFIRMED). */
    void recordSnapServed(InetSocketAddress address);

    /** Mark that {@code address} failed to serve snap (demotes it toward DENIED). */
    void recordSnapFailure(InetSocketAddress address);

    /** Mark a TCP-level connect failure against {@code address} (demotes toward
     *  eviction after sustained unreachability). Default no-op so existing
     *  implementations keep compiling; callers must only report while
     *  demonstrably online. */
    default void recordConnectFailure(InetSocketAddress address) {}

    /** Cached peers to re-dial on startup, in the cache's stored order. */
    List<CachedPeer> load();

    /** Flush queued writes and release resources. */
    void close();
}
