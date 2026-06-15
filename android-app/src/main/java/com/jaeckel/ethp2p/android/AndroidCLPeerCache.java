package com.jaeckel.ethp2p.android;

import com.jaeckel.ethp2p.android.log.LogBuffer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Android-native CL peer cache. Mirrors {@code CLPeerCache} in the :app module
 * but uses {@code android.util.Log} and {@code java.io} streams instead of
 * {@code java.nio.file.Files}, matching {@link AndroidPeerCache}.
 *
 * <p>Format: one peer per line, {@code multiaddr[\t<token>]...}, with optional
 * tab-separated tokens {@code <low>-<high>} (served period range), {@code b<period>}
 * (bootstrap period), {@code lc}/{@code nolc} (light_client confirmed/denied), and a
 * bare {@code <period>} for legacy files. Peers are evicted after
 * {@link #FAILURE_THRESHOLD} consecutive failures.
 */
public final class AndroidCLPeerCache {

    private static final String TAG = "ethp2p.cl-cache";
    private static final char SEP = '\t';

    public static final int FAILURE_THRESHOLD = 3;

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

    public AndroidCLPeerCache(Path cacheFile) {
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

    public synchronized void add(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        if (!seen.add(multiaddr)) return;
        try (FileOutputStream out = new FileOutputStream(cacheFile.toFile(), true)) {
            out.write((multiaddr + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            LogBuffer.w(TAG, "write failed: " + e.getMessage());
        }
    }

    /**
     * Record that a peer served catch-up across the period range {@code [low, high]}.
     * Widens any existing range (lowest low / highest high). Persisted as
     * {@code multiaddr\t<low>-<high>} so a restart can prefer peers whose range covers
     * the period we need.
     */
    public synchronized void recordServed(String multiaddr, long low, long high) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Range incoming = new Range(low, high);
        Range prev = servedRange.get(multiaddr);
        Range merged = prev == null ? incoming : prev.union(incoming);
        if (merged.equals(prev)) return;
        servedRange.put(multiaddr, merged);
        rewriteFile();
    }

    /** Convenience overload for a single served period (degenerate range {@code [p, p]}). */
    public synchronized void recordServed(String multiaddr, long period) {
        recordServed(multiaddr, period, period);
    }

    /**
     * Record that a peer served a {@code LightClientBootstrap} for {@code period}. Keeps
     * the deepest (highest) checkpoint period. Persisted as {@code multiaddr\tb<period>}
     * so a restart prefers it as the bootstrap peer.
     */
    public synchronized void recordBootstrap(String multiaddr, long period) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Long prev = bootstrapPeriod.get(multiaddr);
        if (prev != null && prev >= period) return;
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

    public synchronized void markFailure(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        if (!seen.contains(multiaddr)) return;
        int count = failures.merge(multiaddr, 1, Integer::sum);
        if (count >= FAILURE_THRESHOLD) {
            if (seen.remove(multiaddr)) {
                failures.remove(multiaddr);
                servedRange.remove(multiaddr);
                bootstrapPeriod.remove(multiaddr);
                lcConfirmed.remove(multiaddr);
                lcDenied.remove(multiaddr);
                rewriteFile();
                LogBuffer.i(TAG, "evicted peer after " + count + " failures: " + multiaddr);
            }
        }
    }

    public List<String> load() {
        List<String> result = new ArrayList<>();
        if (!cacheFile.toFile().exists()) return result;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(cacheFile.toFile()), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
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
                        // Keep the deepest bootstrap period if a line carries more than one.
                        try { bootstrapPeriod.merge(multiaddr, Long.parseLong(tok.substring(1)), Math::max); }
                        catch (NumberFormatException ignored) {}
                    } else {
                        int dash = tok.indexOf('-');
                        try {
                            Range incoming = dash > 0
                                    ? new Range(Long.parseLong(tok.substring(0, dash)),
                                                Long.parseLong(tok.substring(dash + 1)))
                                    : new Range(Long.parseLong(tok), Long.parseLong(tok)); // legacy floor
                            // Widen (not overwrite) if a line carries multiple range/legacy tokens,
                            // so duplicates keep the envelope instead of silently dropping data.
                            servedRange.merge(multiaddr, incoming, Range::union);
                        } catch (NumberFormatException ignored) {}
                    }
                }
                result.add(multiaddr);
                seen.add(multiaddr);
            }
            if (!result.isEmpty()) {
                LogBuffer.i(TAG, "loaded " + result.size() + " cached CL peer(s) ("
                        + servedRange.size() + " catch-up servers, "
                        + bootstrapPeriod.size() + " bootstrap peers, "
                        + lcConfirmed.size() + " light-client, " + lcDenied.size() + " non-LC)");
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "read failed: " + e.getMessage());
        }
        return result;
    }

    public synchronized void clear() {
        seen.clear();
        failures.clear();
        servedRange.clear();
        bootstrapPeriod.clear();
        lcConfirmed.clear();
        lcDenied.clear();
        if (!cacheFile.toFile().delete() && cacheFile.toFile().exists()) {
            LogBuffer.w(TAG, "failed to delete cache file " + cacheFile);
        }
    }

    private synchronized void rewriteFile() {
        List<String> peers = new ArrayList<>(seen);
        Collections.sort(peers);
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(cacheFile.toFile(), false), StandardCharsets.UTF_8)) {
            for (String p : peers) {
                w.write(p);
                Range r = servedRange.get(p);
                if (r != null) { w.write(SEP); w.write(r.low() + "-" + r.high()); }
                Long bp = bootstrapPeriod.get(p);
                if (bp != null) { w.write(SEP); w.write("b" + bp); }
                if (lcConfirmed.contains(p)) { w.write(SEP); w.write("lc"); }
                else if (lcDenied.contains(p)) { w.write(SEP); w.write("nolc"); }
                w.write('\n');
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "rewrite failed: " + e.getMessage());
        }
    }
}
