package com.jaeckel.ethp2p.app;

import io.myotis.node.CachedPeer;
import io.myotis.node.PeerCachePort;
import io.myotis.node.SnapQuality;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Adapts the daemon's file-backed {@link PeerCache} to the {@link PeerCachePort}
 * that {@code ChainStack} consumes, so {@code node-core} stays independent of the
 * daemon module. Pure delegation plus a {@link PeerCache.SnapQuality} → shared
 * {@link SnapQuality} mapping.
 */
public final class PeerCacheAdapter implements PeerCachePort {

    private final PeerCache delegate;

    public PeerCacheAdapter(PeerCache delegate) {
        this.delegate = delegate;
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
        List<PeerCache.CachedPeer> src = delegate.load();
        List<CachedPeer> out = new ArrayList<>(src.size());
        for (PeerCache.CachedPeer p : src) {
            out.add(new CachedPeer(p.address(), p.publicKeyHex(), p.snap(), map(p.snapQuality())));
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
