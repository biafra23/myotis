package com.jaeckel.ethp2p.android;

import io.myotis.api.ports.CachedPeerInfo;
import io.myotis.api.ports.EnginePeerCache;
import io.myotis.api.ports.SnapQuality;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Adapts {@link AndroidPeerCache} to the engine API's {@link EnginePeerCache} port.
 * Pure delegation plus the host/port ⇄ InetSocketAddress and
 * {@link AndroidPeerCache.SnapQuality} → api {@link SnapQuality} mappings. Mirrors the
 * daemon's {@code PeerCacheAdapter}; addresses are constructed unresolved (the cache
 * keys by host string, no DNS lookup wanted here).
 */
public final class AndroidPeerCacheAdapter implements EnginePeerCache {

    private final AndroidPeerCache delegate;

    public AndroidPeerCacheAdapter(AndroidPeerCache delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate, "delegate");
    }

    @Override public void add(String host, int port, String publicKeyHex, boolean snap) {
        delegate.add(InetSocketAddress.createUnresolved(host, port), publicKeyHex, snap);
    }

    @Override public void recordSnapServed(String host, int port) {
        delegate.recordSnapServed(InetSocketAddress.createUnresolved(host, port));
    }

    @Override public void recordConnectFailure(String host, int port) {
        delegate.recordConnectFailure(InetSocketAddress.createUnresolved(host, port));
    }

    @Override public void recordSnapFailure(String host, int port) {
        delegate.recordSnapFailure(InetSocketAddress.createUnresolved(host, port));
    }

    @Override public List<CachedPeerInfo> load() {
        List<AndroidPeerCache.CachedPeer> src = delegate.load();
        List<CachedPeerInfo> out = new ArrayList<>(src.size());
        for (AndroidPeerCache.CachedPeer p : src) {
            out.add(new CachedPeerInfo(
                    p.address().getHostString(), p.address().getPort(),
                    p.publicKeyHex(), p.snap(), map(p.snapQuality())));
        }
        return out;
    }

    @Override public void close() {
        delegate.close();
    }

    private static SnapQuality map(AndroidPeerCache.SnapQuality q) {
        return switch (q) {
            case CONFIRMED -> SnapQuality.CONFIRMED;
            case UNKNOWN -> SnapQuality.UNKNOWN;
            case DENIED -> SnapQuality.DENIED;
        };
    }
}
