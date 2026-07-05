package io.myotis.node.api;

import io.myotis.api.ports.BootstrapPeer;
import io.myotis.api.ports.CachedPeerInfo;
import io.myotis.api.ports.DnsServers;
import io.myotis.api.ports.EngineClPeerCache;
import io.myotis.api.ports.EnginePeerCache;
import io.myotis.api.ports.HttpGateway;
import io.myotis.api.ports.ServedRange;
import io.myotis.node.CachedPeer;
import io.myotis.node.ClPeerCachePort;
import io.myotis.node.DnsServerProvider;
import io.myotis.node.PeerCachePort;
import io.myotis.node.SnapQuality;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Bridges between the language-neutral {@code io.myotis.api.ports} interfaces the host
 * implements and the engine-internal port shapes {@code ChainStack} consumes
 * (InetSocketAddress, Map/Set collections, CompletableFuture). All conversions are
 * mechanical; no behavior lives here.
 */
public final class PortBridges {

    private PortBridges() {}

    /** Public interim: hosts mid-migration (desktop until its engine-API rewiring PR)
     *  bridge their api-shaped port implementations back to the ChainStack shapes. */
    public static PeerCachePort toPeerCachePort(EnginePeerCache cache) {
        return new PeerCachePort() {
            @Override public void add(InetSocketAddress address, String publicKeyHex, boolean snap) {
                cache.add(address.getHostString(), address.getPort(), publicKeyHex, snap);
            }
            @Override public void recordSnapServed(InetSocketAddress address) {
                cache.recordSnapServed(address.getHostString(), address.getPort());
            }
            @Override public void recordSnapFailure(InetSocketAddress address) {
                cache.recordSnapFailure(address.getHostString(), address.getPort());
            }
            @Override public List<CachedPeer> load() {
                List<CachedPeerInfo> cached = cache.load();
                List<CachedPeer> out = new ArrayList<>(cached.size());
                for (CachedPeerInfo p : cached) {
                    out.add(new CachedPeer(
                            new InetSocketAddress(p.host(), p.port()),
                            p.publicKeyHex(), p.snap(),
                            SnapQuality.valueOf(p.snapQuality().name())));
                }
                return out;
            }
            @Override public void close() { cache.close(); }
        };
    }

    /** Public interim — see {@link #toPeerCachePort}. */
    public static ClPeerCachePort toClPeerCachePort(EngineClPeerCache cache) {
        return new ClPeerCachePort() {
            @Override public List<String> load() { return cache.load(); }
            @Override public void add(String multiaddr) { cache.add(multiaddr); }
            @Override public void markFailure(String multiaddr) { cache.markFailure(multiaddr); }
            @Override public Map<String, long[]> servedRanges() {
                Map<String, long[]> out = new HashMap<>();
                for (ServedRange r : cache.servedRanges()) {
                    out.put(r.multiaddr(), new long[]{r.low(), r.high()});
                }
                return out;
            }
            @Override public void recordServed(String multiaddr, long low, long high) {
                cache.recordServed(multiaddr, low, high);
            }
            @Override public Map<String, Long> bootstrapPeers() {
                Map<String, Long> out = new HashMap<>();
                for (BootstrapPeer p : cache.bootstrapPeers()) {
                    out.put(p.multiaddr(), p.period());
                }
                return out;
            }
            @Override public void recordBootstrap(String multiaddr, long period) {
                cache.recordBootstrap(multiaddr, period);
            }
            @Override public Set<String> lightClientConfirmed() {
                return new HashSet<>(cache.lightClientConfirmed());
            }
            @Override public Set<String> lightClientDenied() {
                return new HashSet<>(cache.lightClientDenied());
            }
            @Override public void markLightClientBatch(Collection<String> confirmed, Collection<String> denied) {
                cache.markLightClientBatch(List.copyOf(confirmed), List.copyOf(denied));
            }
            @Override public void close() { cache.close(); }
        };
    }

    /**
     * The api gateway is blocking (the FFI-portable shape); the engine's CCIP executor wants a
     * future. Run the blocking call on {@code executor} — never an engine I/O thread.
     */
    public static io.myotis.evm.ccipread.CcipGateway toCcipGateway(HttpGateway gateway, Executor executor) {
        return (method, url, body) -> CompletableFuture.supplyAsync(() ->
                gateway.request(
                        method == io.myotis.evm.ccipread.CcipGateway.Method.GET
                                ? HttpGateway.Method.GET : HttpGateway.Method.POST,
                        url, body),
                executor);
    }

    static DnsServerProvider toDnsServerProvider(DnsServers servers) {
        return servers == null ? null : servers::dnsServerIps;
    }
}
