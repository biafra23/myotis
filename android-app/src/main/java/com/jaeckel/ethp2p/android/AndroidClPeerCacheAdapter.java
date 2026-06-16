package com.jaeckel.ethp2p.android;

import io.myotis.node.ClPeerCachePort;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Adapts {@link AndroidCLPeerCache} to the {@link ClPeerCachePort} that {@code ChainStack}
 * consumes. Pure delegation. {@code AndroidCLPeerCache} flushes writes inline (no
 * {@code close()}), so {@link #close()} is a no-op. Mirrors the daemon's
 * {@code ClPeerCacheAdapter}.
 */
public final class AndroidClPeerCacheAdapter implements ClPeerCachePort {

    private final AndroidCLPeerCache delegate;

    public AndroidClPeerCacheAdapter(AndroidCLPeerCache delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate, "delegate");
    }

    @Override public List<String> load() { return delegate.load(); }
    @Override public void add(String multiaddr) { delegate.add(multiaddr); }
    @Override public void markFailure(String multiaddr) { delegate.markFailure(multiaddr); }
    @Override public Map<String, long[]> servedRanges() { return delegate.servedRanges(); }
    @Override public void recordServed(String multiaddr, long low, long high) { delegate.recordServed(multiaddr, low, high); }
    @Override public Map<String, Long> bootstrapPeers() { return delegate.bootstrapPeers(); }
    @Override public void recordBootstrap(String multiaddr, long period) { delegate.recordBootstrap(multiaddr, period); }
    @Override public Set<String> lightClientConfirmed() { return delegate.lightClientConfirmed(); }
    @Override public Set<String> lightClientDenied() { return delegate.lightClientDenied(); }
    @Override public void markLightClientBatch(Collection<String> confirmed, Collection<String> denied) {
        delegate.markLightClientBatch(confirmed, denied);
    }
    @Override public void close() { /* AndroidCLPeerCache flushes writes inline; nothing to close */ }
}
