package com.jaeckel.ethp2p.android;

import io.myotis.api.ports.BootstrapPeer;
import io.myotis.api.ports.EngineClPeerCache;
import io.myotis.api.ports.ServedRange;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Adapts {@link AndroidCLPeerCache} to the engine API's {@link EngineClPeerCache} port.
 * Pure delegation plus Map/Set → flat-record-List conversions. {@code AndroidCLPeerCache}
 * flushes writes inline (no {@code close()}), so {@link #close()} is a no-op. Mirrors the
 * daemon's {@code ClPeerCacheAdapter}.
 */
public final class AndroidClPeerCacheAdapter implements EngineClPeerCache {

    private final AndroidCLPeerCache delegate;

    public AndroidClPeerCacheAdapter(AndroidCLPeerCache delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate, "delegate");
    }

    @Override public List<String> load() { return delegate.load(); }

    @Override public void add(String multiaddr) { delegate.add(multiaddr); }

    @Override public void markFailure(String multiaddr) { delegate.markFailure(multiaddr); }

    @Override public List<ServedRange> servedRanges() {
        List<ServedRange> out = new ArrayList<>();
        for (Map.Entry<String, long[]> e : delegate.servedRanges().entrySet()) {
            out.add(new ServedRange(e.getKey(), e.getValue()[0], e.getValue()[1]));
        }
        return out;
    }

    @Override public void recordServed(String multiaddr, long low, long high) {
        delegate.recordServed(multiaddr, low, high);
    }

    @Override public List<BootstrapPeer> bootstrapPeers() {
        List<BootstrapPeer> out = new ArrayList<>();
        for (Map.Entry<String, Long> e : delegate.bootstrapPeers().entrySet()) {
            out.add(new BootstrapPeer(e.getKey(), e.getValue()));
        }
        return out;
    }

    @Override public void recordBootstrap(String multiaddr, long period) {
        delegate.recordBootstrap(multiaddr, period);
    }

    @Override public List<String> lightClientConfirmed() {
        return List.copyOf(delegate.lightClientConfirmed());
    }

    @Override public List<String> lightClientDenied() {
        return List.copyOf(delegate.lightClientDenied());
    }

    @Override public void markLightClientBatch(List<String> confirmed, List<String> denied) {
        delegate.markLightClientBatch(confirmed, denied);
    }

    @Override public void close() { /* AndroidCLPeerCache flushes writes inline; nothing to close */ }
}
