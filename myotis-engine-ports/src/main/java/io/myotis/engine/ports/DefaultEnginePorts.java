package io.myotis.engine.ports;

import io.myotis.api.ports.DnsServers;
import io.myotis.api.ports.EnginePorts;
import io.myotis.api.ports.HttpGateway;
import io.myotis.api.ports.NodeKeyStore;

import java.io.Closeable;
import java.nio.file.Path;
import java.util.Objects;

/**
 * The default ports for ONE network, assembled from a key directory and a cache
 * directory with the {@link NetworkFiles} layout: the node-key file, a fresh EL and CL
 * peer cache, the host's DNS servers (or none — the resolver's default) and the
 * {@link UrlConnectionHttpGateway}. {@link #ports()} is what goes to
 * {@link io.myotis.api.MyotisEngine#create}; the cache instances stay reachable here
 * for what a host does beside the engine (show a cached-peer count, wipe the caches).
 *
 * <p>One instance per {@code create()}: the engine owns the peer caches from then on
 * (it writes them, and {@link #close()} drains the EL cache's writer), so a second
 * network, or a restart of this one, builds its own.
 */
public final class DefaultEnginePorts implements Closeable {

    private final String network;
    private final Path cacheDir;
    private final NodeKeyStore keyStore;
    private final FilePeerCache peerCache;
    private final FileClPeerCache clPeerCache;
    private final DnsServers dnsServers;
    private final HttpGateway httpGateway;

    private DefaultEnginePorts(String network, Path cacheDir, NodeKeyStore keyStore,
                               FilePeerCache peerCache, FileClPeerCache clPeerCache,
                               DnsServers dnsServers, HttpGateway httpGateway) {
        this.network = network;
        this.cacheDir = cacheDir;
        this.keyStore = keyStore;
        this.peerCache = peerCache;
        this.clPeerCache = clPeerCache;
        this.dnsServers = dnsServers;
        this.httpGateway = httpGateway;
    }

    /**
     * The defaults for {@code network} (its canonical name): the node key under
     * {@code keyDir}, the peer caches under {@code cacheDir}.
     *
     * @param dnsServersOrNull the host's DNS servers for EIP-1459 resolution — a mobile
     *                         host supplies the active network's (Android has no system
     *                         resolver config the engine could read); {@code null} on a
     *                         host whose system DNS the resolver can use (desktop, daemon)
     */
    public static DefaultEnginePorts forNetwork(Path keyDir, Path cacheDir, String network,
                                                DnsServers dnsServersOrNull) {
        Objects.requireNonNull(keyDir, "keyDir");
        Objects.requireNonNull(cacheDir, "cacheDir");
        NetworkFiles.suffix(network); // validates the name
        return new DefaultEnginePorts(
                network,
                cacheDir,
                FileNodeKeyStore.inDirectory(keyDir),
                new FilePeerCache(NetworkFiles.peerCache(cacheDir, network)),
                new FileClPeerCache(NetworkFiles.clPeerCache(cacheDir, network)),
                dnsServersOrNull,
                new UrlConnectionHttpGateway());
    }

    /** The {@link EnginePorts} for {@code create()}; the engine's default logger and clock. */
    public EnginePorts ports() {
        return new EnginePorts(keyStore, peerCache, clPeerCache, dnsServers, httpGateway, null, null);
    }

    public String network() { return network; }

    public NodeKeyStore keyStore() { return keyStore; }

    /** The EL peer cache the engine writes; {@link FilePeerCache#load()} for a count, {@link FilePeerCache#clear()} to wipe it. */
    public FilePeerCache peerCache() { return peerCache; }

    /** The CL peer cache the engine writes. */
    public FileClPeerCache clPeerCache() { return clPeerCache; }

    public DnsServers dnsServers() { return dnsServers; }

    public HttpGateway httpGateway() { return httpGateway; }

    /**
     * Where the light-client sync snapshot of this network goes under the same cache
     * directory — for {@link io.myotis.api.EngineConfig#syncSnapshotPath}.
     */
    public Path syncSnapshot() {
        return NetworkFiles.syncSnapshot(cacheDir, network);
    }

    /** Drains the EL cache's writer thread (the engine calls the caches' own close too). */
    @Override
    public void close() {
        peerCache.close();
        clPeerCache.close();
    }
}
