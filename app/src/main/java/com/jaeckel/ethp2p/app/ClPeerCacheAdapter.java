package com.jaeckel.ethp2p.app;

import io.myotis.node.ClPeerCachePort;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Adapts the daemon's file-backed {@link CLPeerCache} to the {@link ClPeerCachePort}
 * that {@code ChainStack} consumes. Pure delegation. {@code CLPeerCache} flushes its
 * writes inline (no {@code close()}), so {@link #close()} is a no-op.
 */
public final class ClPeerCacheAdapter implements ClPeerCachePort {

    private final CLPeerCache delegate;

    public ClPeerCacheAdapter(CLPeerCache delegate) {
        this.delegate = delegate;
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
    @Override public void close() { /* CLPeerCache flushes writes inline; nothing to close */ }
}
