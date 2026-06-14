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
 * <p>File format: one peer per line, {@code multiaddr[\t<token>]...}. Each optional
 * tab-separated token is self-describing by prefix and order-independent:
 * <ul>
 *   <li>{@code <low>-<high>} — the sync-committee period <em>range</em> this peer
 *       demonstrably served during catch-up. Knowing both ends (not just the floor)
 *       lets restart prefer peers whose range actually <em>covers</em> the period we
 *       need, instead of assuming monotonic-forward coverage from the floor alone.</li>
 *   <li>{@code b<period>} — the sync-committee period of a {@code LightClientBootstrap}
 *       this peer served. Proof it retained the checkpoint committee; seeds the
 *       preferred bootstrap peer on restart.</li>
 *   <li>{@code lc} / {@code nolc} — Identify confirmed / denied light_client support.</li>
 *   <li>a bare {@code <period>} integer — legacy lowest-served-period from older cache
 *       files; loaded as the degenerate range {@code [period, period]}.</li>
 * </ul>
 * All tokens are optional, so older cache files load unchanged.
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
    /** multiaddr -> the sync-committee period range it demonstrably served during catch-up. */
    private final Map<String, Range> servedRange = new ConcurrentHashMap<>();
    /** multiaddr -> the sync-committee period of a LightClientBootstrap it served (deepest kept). */
    private final Map<String, Long> bootstrapPeriod = new ConcurrentHashMap<>();
    /** Peers whose Identify confirmed light_client protocol support — dial these first. */
    private final Set<String> lcConfirmed = ConcurrentHashMap.newKeySet();
    /** Peers proven NOT to serve light_client (no LC protocols / negotiation failure) — dial last. */
    private final Set<String> lcDenied = ConcurrentHashMap.newKeySet();

    public CLPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    /** A demonstrably-served sync-committee period envelope {@code [low, high]}. Immutable;
     *  {@link #union} widens it. {@code low} never grows, {@code high} never shrinks. */
    public record Range(long low, long high) {
        public Range {
            if (high < low) { long t = low; low = high; high = t; } // normalize hand-edited files
        }
        Range union(Range o) {
            return new Range(Math.min(low, o.low), Math.max(high, o.high));
        }
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
    public synchronized void markFailure(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        if (!seen.contains(multiaddr)) return; // not a cached peer; ignore
        int count = failures.merge(multiaddr, 1, Integer::sum);
        if (count >= FAILURE_THRESHOLD) {
            if (seen.remove(multiaddr)) {
                failures.remove(multiaddr);
                servedRange.remove(multiaddr);
                bootstrapPeriod.remove(multiaddr);
                lcConfirmed.remove(multiaddr);
                lcDenied.remove(multiaddr);
                rewriteFile();
                log.info("[cl-cache] Evicted peer after {} consecutive failures: {}", count, multiaddr);
            }
        }
    }

    /**
     * Record that a peer served catch-up across the period range {@code [low, high]}.
     * Widens any existing range (lowest low / highest high) so a peer's full served
     * envelope is remembered. Persisted so restarts prefer peers whose range covers
     * the period we need.
     */
    public synchronized void recordServed(String multiaddr, long low, long high) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Range incoming = new Range(low, high);
        Range prev = servedRange.get(multiaddr);
        Range merged = prev == null ? incoming : prev.union(incoming);
        if (merged.equals(prev)) return; // no widening — nothing to persist
        servedRange.put(multiaddr, merged);
        rewriteFile();
    }

    /** Convenience overload for a single served period (degenerate range {@code [p, p]}). */
    public synchronized void recordServed(String multiaddr, long period) {
        recordServed(multiaddr, period, period);
    }

    /**
     * Record that a peer served a {@code LightClientBootstrap} for {@code period}. Keeps
     * the deepest (highest) checkpoint period a peer ever served — proof it retains the
     * checkpoint committee. Persisted so a restart prefers it as the bootstrap peer.
     */
    public synchronized void recordBootstrap(String multiaddr, long period) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Long prev = bootstrapPeriod.get(multiaddr);
        if (prev != null && prev >= period) return; // already know a deeper bootstrap
        bootstrapPeriod.put(multiaddr, period);
        rewriteFile();
    }

    /** multiaddr -> {low, high} served period range, for peers proven to serve catch-up. */
    public Map<String, long[]> servedRanges() {
        Map<String, long[]> out = new java.util.HashMap<>();
        servedRange.forEach((ma, r) -> out.put(ma, new long[]{r.low(), r.high()}));
        return out;
    }

    /** multiaddr -> lowest served period (range floor), for peers proven to serve catch-up. */
    public Map<String, Long> servedPeriods() {
        Map<String, Long> out = new java.util.HashMap<>();
        servedRange.forEach((ma, r) -> out.put(ma, r.low()));
        return out;
    }

    /** multiaddr -> bootstrap period served, for peers proven to serve a LightClientBootstrap. */
    public Map<String, Long> bootstrapPeers() {
        return new java.util.HashMap<>(bootstrapPeriod);
    }

    /** Record that a peer's Identify confirmed light_client protocol support. Persisted so
     *  a restart dials known light-client servers first instead of re-Identifying the whole
     *  fork-matched cache (most of which are full nodes without the light-client server). */
    public synchronized void markLightClient(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        seen.add(multiaddr);
        boolean changed = lcConfirmed.add(multiaddr);
        changed |= lcDenied.remove(multiaddr);
        if (changed) rewriteFile();
    }

    /** Record that a peer is proven NOT to serve light_client (no LC protocols on Identify,
     *  or a protocol-negotiation failure). Deprioritized on a restart, not evicted. A
     *  later confirmation (markLightClient) overrides this. */
    public synchronized void markNoLightClient(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty() || lcConfirmed.contains(multiaddr)) return;
        seen.add(multiaddr);
        if (lcDenied.add(multiaddr)) rewriteFile();
    }

    /** Persist a whole Identify round's verdicts in a single rewrite. Avoids one disk
     *  write per peer when dozens are identified in parallel at startup. A confirmation
     *  overrides a prior denial; a denial never demotes a confirmed peer. */
    public synchronized void markLightClientBatch(java.util.Collection<String> confirmed,
                                                  java.util.Collection<String> denied) {
        boolean changed = false;
        if (confirmed != null) {
            for (String ma : confirmed) {
                if (ma == null || ma.isEmpty()) continue;
                seen.add(ma);
                changed |= lcConfirmed.add(ma);
                changed |= lcDenied.remove(ma);
            }
        }
        if (denied != null) {
            for (String ma : denied) {
                if (ma == null || ma.isEmpty() || lcConfirmed.contains(ma)) continue;
                seen.add(ma);
                changed |= lcDenied.add(ma);
            }
        }
        if (changed) rewriteFile();
    }

    /** Peers whose Identify confirmed light_client support (dial first). */
    public Set<String> lightClientConfirmed() {
        return new java.util.HashSet<>(lcConfirmed);
    }

    /** Peers proven not to serve light_client (dial last / skip). */
    public Set<String> lightClientDenied() {
        return new java.util.HashSet<>(lcDenied);
    }

    /** Load all cached CL peer multiaddrs. Returns empty list if file doesn't exist. */
    public List<String> load() {
        List<String> result = new ArrayList<>();
        if (!Files.exists(cacheFile)) return result;

        try {
            for (String line : Files.readAllLines(cacheFile)) {
                line = line.strip();
                if (line.isEmpty() || !line.startsWith("/")) continue;
                // multiaddr [TAB token]...  token = <low>-<high> | b<period> | <period int> | lc | nolc
                String[] parts = line.split(String.valueOf(SEP));
                String multiaddr = parts[0].strip();
                if (multiaddr.isEmpty() || !multiaddr.startsWith("/")) continue;
                for (int i = 1; i < parts.length; i++) {
                    String tok = parts[i].strip();
                    if (tok.equals("lc")) lcConfirmed.add(multiaddr);
                    else if (tok.equals("nolc")) lcDenied.add(multiaddr);
                    else if (tok.startsWith("b")) {
                        try { bootstrapPeriod.put(multiaddr, Long.parseLong(tok.substring(1))); }
                        catch (NumberFormatException ignored) {}
                    } else {
                        int dash = tok.indexOf('-');
                        try {
                            if (dash > 0) {
                                long lo = Long.parseLong(tok.substring(0, dash));
                                long hi = Long.parseLong(tok.substring(dash + 1));
                                servedRange.put(multiaddr, new Range(lo, hi));
                            } else {
                                long p = Long.parseLong(tok); // legacy floor -> degenerate range
                                servedRange.put(multiaddr, new Range(p, p));
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
                result.add(multiaddr);
                seen.add(multiaddr);
            }
            if (!result.isEmpty()) {
                log.info("[cl-cache] Loaded {} cached CL peer(s) from {} ({} catch-up servers, "
                                + "{} bootstrap peers, {} light-client, {} non-LC)",
                        result.size(), cacheFile, servedRange.size(), bootstrapPeriod.size(),
                        lcConfirmed.size(), lcDenied.size());
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
                Range r = servedRange.get(p);
                if (r != null) sb.append(SEP).append(r.low()).append('-').append(r.high());
                Long bp = bootstrapPeriod.get(p);
                if (bp != null) sb.append(SEP).append('b').append(bp);
                if (lcConfirmed.contains(p)) sb.append(SEP).append("lc");
                else if (lcDenied.contains(p)) sb.append(SEP).append("nolc");
                sb.append('\n');
            }
            Files.writeString(cacheFile, sb.toString());
        } catch (IOException e) {
            log.warn("[cl-cache] Failed to rewrite cache after eviction: {}", e.getMessage());
        }
    }
}
