package com.jaeckel.ethp2p.android;

import io.myotis.node.CachedPeer;
import io.myotis.node.PeerCachePort;
import io.myotis.node.SnapQuality;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Adapts {@link AndroidPeerCache} to the {@link PeerCachePort} that {@code ChainStack}
 * consumes, so {@code node-core} stays independent of the Android module. Pure
 * delegation plus an {@link AndroidPeerCache.SnapQuality} → shared {@link SnapQuality}
 * mapping. Mirrors the daemon's {@code PeerCacheAdapter}.
 */
public final class AndroidPeerCacheAdapter implements PeerCachePort {

    private final AndroidPeerCache delegate;

    public AndroidPeerCacheAdapter(AndroidPeerCache delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate, "delegate");
    }

    @Override public void add(InetSocketAddress address, String publicKeyHex, boolean snap) {
        delegate.add(address, publicKeyHex, snap);
    }

    @Override public void recordSnapServed(InetSocketAddress address) {
        delegate.recordSnapServed(address);
    }

    @Override public void recordSnapFailure(InetSocketAddress address) {
        delegate.recordSnapFailure(address);
    }

    @Override public List<CachedPeer> load() {
        List<AndroidPeerCache.CachedPeer> src = delegate.load();
        List<CachedPeer> out = new ArrayList<>(src.size());
        for (AndroidPeerCache.CachedPeer p : src) {
            out.add(new CachedPeer(p.address(), p.publicKeyHex(), p.snap(), map(p.snapQuality())));
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
