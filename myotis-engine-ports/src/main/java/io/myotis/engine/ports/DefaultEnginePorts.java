package io.myotis.engine.ports;

import io.myotis.api.ports.DnsServers;
import io.myotis.api.ports.EnginePorts;
import io.myotis.api.ports.HttpGateway;
import io.myotis.api.ports.NodeKeyStore;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * The default ports for ONE network, assembled from a key directory and a cache
 * directory with the {@link NetworkFiles} layout, for {@link io.myotis.api.MyotisEngine#create}
 * via {@link #ports()}.
 *
 * <p><b>Which engine reads what.</b> The engine library ships the Rust engine, and it
 * takes two of these ports: {@code dnsServers} (EIP-1459 resolution) and
 * {@code httpGateway} (CCIP-Read). Its identity, its peer caches and its sync snapshot
 * it keeps ITSELF, under {@link io.myotis.api.EngineConfig#dataDir()} — in the same
 * file names as {@link NetworkFiles}, so a consumer that passes one directory as both
 * the config's {@code dataDir} and this {@code cacheDir} finds the engine's files at
 * {@link #peerCacheFile()}, {@link #clPeerCacheFile()} and {@link #syncSnapshot()}.
 * The file-backed {@link #keyStore()}, {@link #peerCache()} and {@link #clPeerCache()}
 * are what the JAVA engine consumes — the Myotis apps run it through their engine
 * selector — and are inert under the Rust engine: do not read a live peer count or
 * wipe the caches through them there (the file is the engine's, and
 * {@link FilePeerCache#load()} serves a boot-time copy); read the file, and clear peer
 * state through {@link io.myotis.api.ChainHandle#clearPeerState()}.
 *
 * <p>One instance per {@code create()}: the Java engine owns the peer caches from then
 * on (it writes them; {@link #close()} drains the EL cache's writer), so a second
 * network, or a restart of this one, builds its own. Both directories are created if
 * missing.
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
     * The defaults for {@code network}: the node key under {@code keyDir}, the peer
     * caches under {@code cacheDir}.
     *
     * @param network          the CANONICAL network name
     *                         ({@link io.myotis.api.MyotisEngine#canonicalNetworkName}) —
     *                         refused otherwise (see {@link NetworkFiles#suffix}), never
     *                         silently given a second set of files
     * @param dnsServersOrNull the host's DNS servers for EIP-1459 resolution — a mobile
     *                         host supplies the active network's (Android has no system
     *                         resolver config the engine could read); {@code null} on a
     *                         host whose system DNS the resolver can use (desktop, daemon)
     * @throws java.io.UncheckedIOException when a directory cannot be created
     */
    public static DefaultEnginePorts forNetwork(Path keyDir, Path cacheDir, String network,
                                                DnsServers dnsServersOrNull) {
        Objects.requireNonNull(keyDir, "keyDir");
        Objects.requireNonNull(cacheDir, "cacheDir");
        NetworkFiles.suffix(network); // validates the name
        try {
            Files.createDirectories(keyDir);
            Files.createDirectories(cacheDir);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create the engine's directories", e);
        }
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

    /** The node-key file store (the Java engine's; the Rust engine keeps its own key under its data dir). */
    public NodeKeyStore keyStore() { return keyStore; }

    /** The EL peer cache (the Java engine's; see the class note for the Rust engine). */
    public FilePeerCache peerCache() { return peerCache; }

    /** The CL peer cache (the Java engine's; see the class note for the Rust engine). */
    public FileClPeerCache clPeerCache() { return clPeerCache; }

    /** The EL peer-cache file under the cache directory ({@link NetworkFiles#peerCache}). */
    public Path peerCacheFile() { return peerCache.cacheFile(); }

    /** The CL peer-cache file under the cache directory ({@link NetworkFiles#clPeerCache}). */
    public Path clPeerCacheFile() { return clPeerCache.cacheFile(); }

    public DnsServers dnsServers() { return dnsServers; }

    public HttpGateway httpGateway() { return httpGateway; }

    /**
     * The light-client sync snapshot of this network under the same cache directory —
     * for {@link io.myotis.api.EngineConfig#syncSnapshotPath} (the Java engine); the
     * Rust engine derives the same name under its {@code dataDir} itself.
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
