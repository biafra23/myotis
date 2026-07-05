package com.jaeckel.ethp2p.app;

import io.myotis.api.ports.CachedPeerInfo;
import io.myotis.api.ports.EnginePeerCache;
import io.myotis.api.ports.SnapQuality;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Adapts the daemon's file-backed {@link PeerCache} to the engine API's
 * {@link EnginePeerCache} port. Pure delegation plus the host/port ⇄
 * InetSocketAddress and {@link PeerCache.SnapQuality} → api {@link SnapQuality}
 * mappings. Addresses are constructed unresolved — {@code PeerCache} keys by
 * {@code getHostString()}, so no DNS lookup is needed (or wanted) here.
 */
public final class PeerCacheAdapter implements EnginePeerCache {

    private final PeerCache delegate;

    public PeerCacheAdapter(PeerCache delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate, "delegate");
    }

    @Override public void add(String host, int port, String publicKeyHex, boolean snap) {
        delegate.add(InetSocketAddress.createUnresolved(host, port), publicKeyHex, snap);
    }

    @Override public void recordSnapServed(String host, int port) {
        delegate.recordSnapServed(InetSocketAddress.createUnresolved(host, port));
    }

    @Override public void recordSnapFailure(String host, int port) {
        delegate.recordSnapFailure(InetSocketAddress.createUnresolved(host, port));
    }

    @Override public List<CachedPeerInfo> load() {
        List<PeerCache.CachedPeer> src = delegate.load();
        List<CachedPeerInfo> out = new ArrayList<>(src.size());
        for (PeerCache.CachedPeer p : src) {
            out.add(new CachedPeerInfo(
                    p.address().getHostString(), p.address().getPort(),
                    p.publicKeyHex(), p.snap(), map(p.snapQuality())));
        }
        return out;
    }

    @Override public void close() {
        delegate.close();
    }

    private static SnapQuality map(PeerCache.SnapQuality q) {
        return switch (q) {
            case CONFIRMED -> SnapQuality.CONFIRMED;
            case UNKNOWN -> SnapQuality.UNKNOWN;
            case DENIED -> SnapQuality.DENIED;
        };
    }
}
