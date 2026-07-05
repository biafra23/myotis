package io.myotis.api.ports;

import java.util.List;

/**
 * The EL peer cache — remembers dialable peers (and their snap-serving quality)
 * across restarts so the engine re-dials proven peers first.
 */
public interface EnginePeerCache {

    /** Record a freshly-handshaked peer (idempotent). */
    void add(String host, int port, String publicKeyHex, boolean snap);

    /** {@code host:port} served a snap proof (promote toward CONFIRMED). */
    void recordSnapServed(String host, int port);

    /** {@code host:port} failed to serve snap (demote toward DENIED). */
    void recordSnapFailure(String host, int port);

    /** Cached peers to re-dial on startup, in stored order. */
    List<CachedPeerInfo> load();

    /** Flush queued writes and release resources. */
    void close();
}
