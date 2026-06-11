package io.myotis.rpc;

import java.net.InetSocketAddress;

/**
 * Sink for per-peer snap-serving quality verdicts produced by the oracle path,
 * so good snap peers are remembered across restarts and repeat hangers are
 * deprioritized. The shared backend calls these from the snap routing supplier's
 * served/denied callbacks (via {@link io.myotis.rpc.snap.EthHandlerSnapPeer}); each
 * host implements persistence its own way — {@code :android-app} into its
 * filesDir peer cache, the {@code :app} daemon into its on-disk peer cache — so
 * both get the EL peer-quality optimization without the backend knowing how the
 * cache is stored.
 */
public interface SnapQualitySink {

    /** The peer at {@code address} returned a usable proof — mark it snap-confirmed. */
    void recordSnapServed(InetSocketAddress address);

    /** The peer at {@code address} failed to serve the current root (empty/invalid
     *  proof, timeout, IO) — count toward denial. */
    void recordSnapFailure(InetSocketAddress address);

    /** No-op sink for hosts/tests that don't persist peer quality. */
    static SnapQualitySink noop() {
        return new SnapQualitySink() {
            @Override public void recordSnapServed(InetSocketAddress address) { }
            @Override public void recordSnapFailure(InetSocketAddress address) { }
        };
    }
}
