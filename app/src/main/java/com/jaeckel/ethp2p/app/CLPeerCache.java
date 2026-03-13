package com.jaeckel.ethp2p.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persists Consensus Layer peers that successfully served light client responses
 * so they can be reconnected on restart without discovery.
 *
 * <p>File format: one multiaddr per line (e.g. {@code /ip4/1.2.3.4/tcp/9000/p2p/16Uiu2...}).
 */
public final class CLPeerCache {

    private static final Logger log = LoggerFactory.getLogger(CLPeerCache.class);

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public CLPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    /** Add a peer multiaddr to the cache. Thread-safe, deduplicates. */
    public void add(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        if (!seen.add(multiaddr)) return;

        try {
            Files.writeString(cacheFile, multiaddr + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            log.info("[cl-cache] Saved responsive CL peer: {}", multiaddr);
        } catch (IOException e) {
            log.warn("[cl-cache] Failed to write CL peer cache: {}", e.getMessage());
        }
    }

    /** Load all cached CL peer multiaddrs. Returns empty list if file doesn't exist. */
    public List<String> load() {
        List<String> result = new ArrayList<>();
        if (!Files.exists(cacheFile)) return result;

        try {
            for (String line : Files.readAllLines(cacheFile)) {
                line = line.strip();
                if (line.isEmpty() || !line.startsWith("/")) continue;
                result.add(line);
                seen.add(line);
            }
            if (!result.isEmpty()) {
                log.info("[cl-cache] Loaded {} cached CL peer(s) from {}", result.size(), cacheFile);
            }
        } catch (Exception e) {
            log.warn("[cl-cache] Failed to read CL peer cache: {}", e.getMessage());
        }
        return result;
    }

    /** Delete the cache file. */
    public static void purge(Path cacheFile) {
        try {
            if (Files.deleteIfExists(cacheFile)) {
                System.out.println("CL peer cache purged: " + cacheFile);
            } else {
                System.out.println("No CL peer cache found at: " + cacheFile);
            }
        } catch (IOException e) {
            System.err.println("Failed to purge CL cache: " + e.getMessage());
        }
    }
}
