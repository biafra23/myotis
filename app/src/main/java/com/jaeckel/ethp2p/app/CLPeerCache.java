package com.jaeckel.ethp2p.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persists Consensus Layer peers that successfully served light client responses
 * so they can be reconnected on restart without discovery.
 *
 * <p>File format: one peer per line, {@code multiaddr[\t<lowestServedPeriod>]}.
 * The optional trailing sync-committee period records the oldest period this peer
 * actually served during catch-up — proof it retains light-client updates that
 * deep. On restart we prefer peers whose served period covers the checkpoint,
 * instead of fanning out to discovery peers that don't serve catch-up at all.
 * The field is optional so older cache files load unchanged.
 *
 * <p>Peers are evicted after {@link #FAILURE_THRESHOLD} consecutive failures so the
 * cache does not accumulate dead peers across restarts. Any success resets a peer's
 * counter.
 */
public final class CLPeerCache {

    private static final Logger log = LoggerFactory.getLogger(CLPeerCache.class);

    /** Consecutive failures before a peer is evicted from the cache. */
    public static final int FAILURE_THRESHOLD = 3;

    private static final char SEP = '\t';

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> failures = new ConcurrentHashMap<>();
    /** multiaddr -> lowest sync-committee period it served during catch-up. */
    private final Map<String, Long> servedPeriod = new ConcurrentHashMap<>();

    public CLPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    /**
     * Record a successful interaction with a peer: add it to the cache if new and
     * reset its failure counter.
     */
    public synchronized void add(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        if (!seen.add(multiaddr)) return;

        try {
            // Shares the monitor with rewriteFile() so an append can't interleave
            // with a truncate+rewrite from a concurrent eviction.
            Files.writeString(cacheFile, multiaddr + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            log.info("[cl-cache] Saved responsive CL peer: {}", multiaddr);
        } catch (IOException e) {
            log.warn("[cl-cache] Failed to write CL peer cache: {}", e.getMessage());
        }
    }

    /**
     * Record a failed interaction. After {@link #FAILURE_THRESHOLD} consecutive
     * failures, the peer is removed from the cache file.
     */
    public void markFailure(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        if (!seen.contains(multiaddr)) return; // not a cached peer; ignore
        int count = failures.merge(multiaddr, 1, Integer::sum);
        if (count >= FAILURE_THRESHOLD) {
            if (seen.remove(multiaddr)) {
                failures.remove(multiaddr);
                servedPeriod.remove(multiaddr);
                rewriteFile();
                log.info("[cl-cache] Evicted peer after {} consecutive failures: {}", count, multiaddr);
            }
        }
    }

    /**
     * Record that a peer served catch-up down to {@code period}. Keeps the lowest
     * period seen (deepest history) so a peer that once served the checkpoint is
     * remembered as such. Persisted so restarts prefer proven catch-up servers.
     */
    public synchronized void recordServed(String multiaddr, long period) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Long prev = servedPeriod.get(multiaddr);
        if (prev != null && prev <= period) return; // already know it goes deeper
        servedPeriod.put(multiaddr, period);
        rewriteFile();
    }

    /** multiaddr -> lowest served period, for peers proven to serve catch-up. */
    public Map<String, Long> servedPeriods() {
        return new java.util.HashMap<>(servedPeriod);
    }

    /** Load all cached CL peer multiaddrs. Returns empty list if file doesn't exist. */
    public List<String> load() {
        List<String> result = new ArrayList<>();
        if (!Files.exists(cacheFile)) return result;

        try {
            for (String line : Files.readAllLines(cacheFile)) {
                line = line.strip();
                if (line.isEmpty() || !line.startsWith("/")) continue;
                String multiaddr = line;
                int sep = line.indexOf(SEP);
                if (sep >= 0) {
                    multiaddr = line.substring(0, sep);
                    try {
                        servedPeriod.put(multiaddr, Long.parseLong(line.substring(sep + 1).strip()));
                    } catch (NumberFormatException ignored) {}
                }
                result.add(multiaddr);
                seen.add(multiaddr);
            }
            if (!result.isEmpty()) {
                log.info("[cl-cache] Loaded {} cached CL peer(s) from {} ({} proven catch-up servers)",
                        result.size(), cacheFile, servedPeriod.size());
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

    private synchronized void rewriteFile() {
        try {
            // Stable order: sorted lines, idempotent across rewrites. Append the
            // served period when known so it survives the rewrite.
            List<String> peers = new ArrayList<>(seen);
            java.util.Collections.sort(peers);
            StringBuilder sb = new StringBuilder();
            for (String p : peers) {
                sb.append(p);
                Long sp = servedPeriod.get(p);
                if (sp != null) sb.append(SEP).append(sp);
                sb.append('\n');
            }
            Files.writeString(cacheFile, sb.toString());
        } catch (IOException e) {
            log.warn("[cl-cache] Failed to rewrite cache after eviction: {}", e.getMessage());
        }
    }
}
