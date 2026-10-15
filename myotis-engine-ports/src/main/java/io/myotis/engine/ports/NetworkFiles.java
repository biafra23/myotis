package io.myotis.engine.ports;

import java.nio.file.Path;
import java.util.Objects;

/**
 * The per-network file layout the default ports share — ONE definition of the names
 * the Myotis hosts have always used, so the files of an existing install carry over
 * and a host that keeps its own paths (for a "clear cache" button, say) names the
 * same files the engine writes.
 *
 * <p>Mainnet keeps the legacy suffix-less names ({@code nodekey.hex},
 * {@code peers.cache}); every other network gets {@code -<network>} before the
 * extension. {@code network} is the canonical name
 * ({@link io.myotis.api.MyotisEngine#canonicalNetworkName}): an alias would name a
 * second set of files.
 *
 * <p>Two directories, on purpose: the node key is identity and lives with the
 * host's durable files; the caches and the sync snapshot are reconstructible
 * network state (peers are re-discovered, the snapshot is a private cache, never a
 * trust anchor) and live where a host may wipe them.
 */
public final class NetworkFiles {

    private NetworkFiles() {}

    /** {@code nodekey.hex}, or {@code nodekey-<network>.hex} off mainnet. */
    public static Path nodeKey(Path keyDir, String network) {
        return Objects.requireNonNull(keyDir, "keyDir").resolve("nodekey" + suffix(network) + ".hex");
    }

    /** {@code peers.cache}, or {@code peers-<network>.cache} off mainnet. */
    public static Path peerCache(Path cacheDir, String network) {
        return Objects.requireNonNull(cacheDir, "cacheDir").resolve("peers" + suffix(network) + ".cache");
    }

    /** {@code cl-peers.cache}, or {@code cl-peers-<network>.cache} off mainnet. */
    public static Path clPeerCache(Path cacheDir, String network) {
        return Objects.requireNonNull(cacheDir, "cacheDir").resolve("cl-peers" + suffix(network) + ".cache");
    }

    /**
     * {@code sync-state.snapshot}, or {@code sync-state-<network>.snapshot} off mainnet:
     * the light-client sync snapshot for {@link io.myotis.api.EngineConfig#syncSnapshotPath}.
     */
    public static Path syncSnapshot(Path cacheDir, String network) {
        return Objects.requireNonNull(cacheDir, "cacheDir").resolve("sync-state" + suffix(network) + ".snapshot");
    }

    /** The empty string for mainnet, {@code -<network>} otherwise. */
    public static String suffix(String network) {
        Objects.requireNonNull(network, "network");
        if (network.isEmpty()) throw new IllegalArgumentException("network name is empty");
        return network.equals("mainnet") ? "" : "-" + network;
    }
}
