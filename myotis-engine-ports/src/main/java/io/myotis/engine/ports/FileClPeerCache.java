package io.myotis.engine.ports;

import io.myotis.api.ports.BootstrapPeer;
import io.myotis.api.ports.EngineClPeerCache;
import io.myotis.api.ports.ServedRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The file-backed CL (beacon, libp2p) peer cache — the engine API's
 * {@link EngineClPeerCache} port over one text file. The Myotis Android app's cache,
 * moved into the library (the daemon's twin is {@code com.jaeckel.ethp2p.app.CLPeerCache};
 * same file format).
 *
 * <p>Format: one peer per line, {@code multiaddr[\t<token>]...}, with optional
 * tab-separated tokens {@code <low>-<high>} (served period range), {@code b<period>}
 * (bootstrap period), {@code lc}/{@code nolc} (light_client confirmed/denied), and a
 * bare {@code <period>} for legacy files. Peers are evicted after
 * {@link #FAILURE_THRESHOLD} consecutive failures.
 *
 * <p>Writes are inline (an append per new peer, a sorted rewrite when a verdict
 * changes); the in-memory sets are authoritative and mutated under
 * {@code synchronized(this)}.
 */
public final class FileClPeerCache implements EngineClPeerCache {

    private static final Logger log = LoggerFactory.getLogger(FileClPeerCache.class);
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

    public FileClPeerCache(Path cacheFile) {
        this.cacheFile = Objects.requireNonNull(cacheFile, "cacheFile");
    }

    /** The file this cache persists to. */
    public Path cacheFile() {
        return cacheFile;
    }

    /** A demonstrably-served sync-committee period envelope {@code [low, high]}. Immutable;
     *  {@link #union} widens it. {@code low} never grows, {@code high} never shrinks. */
    private record Range(long low, long high) {
        private Range {
            if (high < low) { long t = low; low = high; high = t; } // normalize hand-edited files
        }
        Range union(Range o) {
            return new Range(Math.min(low, o.low), Math.max(high, o.high));
        }
    }

    @Override
    public synchronized void add(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        if (!seen.add(multiaddr)) return;
        try (FileOutputStream out = new FileOutputStream(cacheFile.toFile(), true)) {
            out.write((multiaddr + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            log.warn("write to {} failed: {}", cacheFile, e.getMessage());
        }
    }

    /**
     * Record that a peer served catch-up across the period range {@code [low, high]}.
     * Widens any existing range (lowest low / highest high). Persisted as
     * {@code multiaddr\t<low>-<high>} so a restart can prefer peers whose range covers
     * the period we need.
     */
    @Override
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

    /**
     * Record that a peer served a {@code LightClientBootstrap} for {@code period}. Keeps
     * the deepest (highest) checkpoint period. Persisted as {@code multiaddr\tb<period>}
     * so a restart prefers it as the bootstrap peer.
     */
    @Override
    public synchronized void recordBootstrap(String multiaddr, long period) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Long prev = bootstrapPeriod.get(multiaddr);
        if (prev != null && prev >= period) return;
        bootstrapPeriod.put(multiaddr, period);
        rewriteFile();
    }

    /** The served period range of every peer proven to serve catch-up. */
    @Override
    public List<ServedRange> servedRanges() {
        List<ServedRange> out = new ArrayList<>(servedRange.size());
        servedRange.forEach((ma, r) -> out.add(new ServedRange(ma, r.low(), r.high())));
        return out;
    }

    /** The bootstrap period of every peer proven to serve a LightClientBootstrap. */
    @Override
    public List<BootstrapPeer> bootstrapPeers() {
        List<BootstrapPeer> out = new ArrayList<>(bootstrapPeriod.size());
        bootstrapPeriod.forEach((ma, p) -> out.add(new BootstrapPeer(ma, p)));
        return out;
    }

    /** Persist a whole Identify round's verdicts in a single rewrite. Avoids one disk
     *  write per peer when dozens are identified in parallel at startup. A confirmation
     *  overrides a prior denial; a denial never demotes a confirmed peer. */
    @Override
    public synchronized void markLightClientBatch(List<String> confirmed, List<String> denied) {
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
    @Override
    public List<String> lightClientConfirmed() {
        return new ArrayList<>(lcConfirmed);
    }

    /** Peers proven not to serve light_client (dial last / skip). */
    @Override
    public List<String> lightClientDenied() {
        return new ArrayList<>(lcDenied);
    }

    @Override
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
                log.info("evicted CL peer after {} failures: {}", count, multiaddr);
            }
        }
    }

    /** Read the file: every peer on it, filling the verdict maps from its tokens. */
    @Override
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
                            // Widen (not overwrite) if a line carries multiple range/legacy
                            // tokens, so duplicates keep the envelope instead of silently
                            // dropping data.
                            servedRange.merge(multiaddr, incoming, Range::union);
                        } catch (NumberFormatException ignored) {}
                    }
                }
                result.add(multiaddr);
                seen.add(multiaddr);
            }
            if (!result.isEmpty()) {
                log.info("loaded {} cached CL peer(s) from {} ({} catch-up servers, {} bootstrap peers, {} light-client, {} non-LC)",
                        result.size(), cacheFile, servedRange.size(), bootstrapPeriod.size(),
                        lcConfirmed.size(), lcDenied.size());
            }
        } catch (IOException e) {
            log.warn("read of {} failed: {}", cacheFile, e.getMessage());
        }
        return result;
    }

    /** Forget every peer and delete the cache file. */
    public synchronized void clear() {
        seen.clear();
        failures.clear();
        servedRange.clear();
        bootstrapPeriod.clear();
        lcConfirmed.clear();
        lcDenied.clear();
        if (!cacheFile.toFile().delete() && cacheFile.toFile().exists()) {
            log.warn("failed to delete cache file {}", cacheFile);
        }
    }

    /** Writes are inline, so there is nothing to drain. */
    @Override
    public void close() {}

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
            log.warn("rewrite of {} failed: {}", cacheFile, e.getMessage());
        }
    }
}
