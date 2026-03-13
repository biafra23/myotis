package com.jaeckel.ethp2p.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persists peers that reached READY state so they can be reconnected on restart.
 *
 * File format: one line per peer, {@code ip:port:publicKeyHex}
 */
public final class PeerCache {

    private static final Logger log = LoggerFactory.getLogger(PeerCache.class);

    public record CachedPeer(InetSocketAddress address, String publicKeyHex) {}

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public PeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    /** Add a peer to the cache file. Thread-safe, deduplicates by address. */
    public void add(InetSocketAddress address, String publicKeyHex) {
        String key = address.getAddress().getHostAddress() + ":" + address.getPort();
        if (!seen.add(key)) return;

        String line = key + ":" + publicKeyHex;
        try {
            Files.writeString(cacheFile, line + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            log.info("[cache] Saved READY peer {}", key);
        } catch (IOException e) {
            log.warn("[cache] Failed to write peer cache: {}", e.getMessage());
        }
    }

    /** Load all cached peers. Returns empty list if file doesn't exist. */
    public List<CachedPeer> load() {
        List<CachedPeer> result = new ArrayList<>();
        if (!Files.exists(cacheFile)) return result;

        try {
            for (String line : Files.readAllLines(cacheFile)) {
                line = line.strip();
                if (line.isEmpty()) continue;
                // format: ip:port:publicKeyHex
                int firstColon = line.indexOf(':');
                int secondColon = line.indexOf(':', firstColon + 1);
                if (firstColon < 0 || secondColon < 0) continue;

                String ip = line.substring(0, firstColon);
                int port = Integer.parseInt(line.substring(firstColon + 1, secondColon));
                String pubKeyHex = line.substring(secondColon + 1);

                result.add(new CachedPeer(new InetSocketAddress(ip, port), pubKeyHex));
                seen.add(ip + ":" + port);
            }
            log.info("[cache] Loaded {} cached peers from {}", result.size(), cacheFile);
        } catch (Exception e) {
            log.warn("[cache] Failed to read peer cache: {}", e.getMessage());
        }
        return result;
    }

    /** Delete the cache file. */
    public static void purge(Path cacheFile) {
        try {
            if (Files.deleteIfExists(cacheFile)) {
                System.out.println("Peer cache purged: " + cacheFile);
            } else {
                System.out.println("No peer cache found at: " + cacheFile);
            }
        } catch (IOException e) {
            System.err.println("Failed to purge cache: " + e.getMessage());
        }
    }
}
