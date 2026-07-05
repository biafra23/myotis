package io.myotis.node.api;

import io.myotis.api.ports.BootstrapPeer;
import io.myotis.api.ports.CachedPeerInfo;
import io.myotis.api.ports.EngineClPeerCache;
import io.myotis.api.ports.EnginePeerCache;
import io.myotis.api.ports.ServedRange;
import io.myotis.node.CachedPeer;
import io.myotis.node.ClPeerCachePort;
import io.myotis.node.PeerCachePort;
import io.myotis.node.SnapQuality;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PortBridgesTest {

    /** Minimal recording fake for the EL side. */
    static final class FakePeerCache implements EnginePeerCache {
        final List<String> added = new ArrayList<>();
        final List<String> served = new ArrayList<>();
        boolean closed;
        List<CachedPeerInfo> toLoad = List.of();

        @Override public void add(String host, int port, String publicKeyHex, boolean snap) {
            added.add(host + ":" + port + "/" + publicKeyHex + "/" + snap);
        }
        @Override public void recordSnapServed(String host, int port) { served.add(host + ":" + port); }
        @Override public void recordSnapFailure(String host, int port) { }
        @Override public List<CachedPeerInfo> load() { return toLoad; }
        @Override public void close() { closed = true; }
    }

    @Test
    void elPeerCacheRoundTrip() {
        FakePeerCache fake = new FakePeerCache();
        fake.toLoad = List.of(
                new CachedPeerInfo("10.0.0.1", 30303, "aa", true,
                        io.myotis.api.ports.SnapQuality.CONFIRMED),
                new CachedPeerInfo("10.0.0.2", 30304, "bb", false,
                        io.myotis.api.ports.SnapQuality.DENIED));
        PeerCachePort port = PortBridges.toPeerCachePort(fake);

        port.add(new InetSocketAddress("10.0.0.3", 30305), "cc", true);
        assertEquals(List.of("10.0.0.3:30305/cc/true"), fake.added);

        port.recordSnapServed(InetSocketAddress.createUnresolved("10.0.0.4", 30306));
        assertEquals(List.of("10.0.0.4:30306"), fake.served);

        List<CachedPeer> loaded = port.load();
        assertEquals(2, loaded.size());
        assertEquals("10.0.0.1", loaded.get(0).address().getHostString());
        assertEquals(30303, loaded.get(0).address().getPort());
        assertEquals("aa", loaded.get(0).publicKeyHex());
        assertTrue(loaded.get(0).snap());
        assertEquals(SnapQuality.CONFIRMED, loaded.get(0).snapQuality());
        assertEquals(SnapQuality.DENIED, loaded.get(1).snapQuality());

        port.close();
        assertTrue(fake.closed);
    }

    /** Minimal fake for the CL side, returning fixed flat records. */
    static final class FakeClCache implements EngineClPeerCache {
        List<String> confirmedBatch;
        List<String> deniedBatch;

        @Override public List<String> load() { return List.of("/ip4/1.2.3.4/tcp/9000/p2p/x"); }
        @Override public void add(String multiaddr) { }
        @Override public void markFailure(String multiaddr) { }
        @Override public List<ServedRange> servedRanges() {
            return List.of(new ServedRange("peerA", 100, 120));
        }
        @Override public void recordServed(String multiaddr, long low, long high) { }
        @Override public List<BootstrapPeer> bootstrapPeers() {
            return List.of(new BootstrapPeer("peerB", 1400));
        }
        @Override public void recordBootstrap(String multiaddr, long period) { }
        @Override public List<String> lightClientConfirmed() { return List.of("lc1", "lc2"); }
        @Override public List<String> lightClientDenied() { return List.of("bad1"); }
        @Override public void markLightClientBatch(List<String> confirmed, List<String> denied) {
            this.confirmedBatch = confirmed;
            this.deniedBatch = denied;
        }
        @Override public void close() { }
    }

    @Test
    void clPeerCacheListToMapConversions() {
        FakeClCache fake = new FakeClCache();
        ClPeerCachePort port = PortBridges.toClPeerCachePort(fake);

        Map<String, long[]> ranges = port.servedRanges();
        assertEquals(1, ranges.size());
        assertEquals(100, ranges.get("peerA")[0]);
        assertEquals(120, ranges.get("peerA")[1]);

        Map<String, Long> bootstraps = port.bootstrapPeers();
        assertEquals(1400L, bootstraps.get("peerB"));

        assertEquals(2, port.lightClientConfirmed().size());
        assertTrue(port.lightClientConfirmed().contains("lc1"));
        assertEquals(1, port.lightClientDenied().size());

        port.markLightClientBatch(List.of("a"), List.of("b"));
        assertEquals(List.of("a"), fake.confirmedBatch);
        assertEquals(List.of("b"), fake.deniedBatch);
    }

    @Test
    void nullDnsServersBridgesToNullProvider() {
        assertNull(PortBridges.toDnsServerProvider(null));
    }

    @Test
    void dnsServersBridge() {
        assertEquals(List.of("8.8.8.8"),
                PortBridges.toDnsServerProvider(() -> List.of("8.8.8.8")).get());
    }
}
