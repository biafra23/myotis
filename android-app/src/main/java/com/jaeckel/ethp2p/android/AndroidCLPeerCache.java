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
 * <p>Format: one libp2p multiaddr per line, e.g.
 * {@code /ip4/1.2.3.4/tcp/9000/p2p/16Uiu2...}. Peers are evicted after
 * {@link #FAILURE_THRESHOLD} consecutive failures.
 */
public final class AndroidCLPeerCache {

    private static final String TAG = "ethp2p.cl-cache";
    private static final char SEP = '\t';

    public static final int FAILURE_THRESHOLD = 3;

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> failures = new ConcurrentHashMap<>();
    /** multiaddr -> lowest sync-committee period it served during catch-up. */
    private final Map<String, Long> servedPeriod = new ConcurrentHashMap<>();

    public AndroidCLPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
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
     * Record that a peer served catch-up down to {@code period}. Keeps the lowest
     * period (deepest history). Persisted as {@code multiaddr\t<period>} so a
     * restart can prefer peers proven to serve the checkpoint period.
     */
    public synchronized void recordServed(String multiaddr, long period) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        failures.remove(multiaddr);
        seen.add(multiaddr);
        Long prev = servedPeriod.get(multiaddr);
        if (prev != null && prev <= period) return;
        servedPeriod.put(multiaddr, period);
        rewriteFile();
    }

    /** multiaddr -> lowest served period, for peers proven to serve catch-up. */
    public Map<String, Long> servedPeriods() {
        return new java.util.HashMap<>(servedPeriod);
    }

    public void markFailure(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        if (!seen.contains(multiaddr)) return;
        int count = failures.merge(multiaddr, 1, Integer::sum);
        if (count >= FAILURE_THRESHOLD) {
            if (seen.remove(multiaddr)) {
                failures.remove(multiaddr);
                servedPeriod.remove(multiaddr);
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
                LogBuffer.i(TAG, "loaded " + result.size() + " cached CL peer(s) ("
                        + servedPeriod.size() + " proven catch-up servers)");
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "read failed: " + e.getMessage());
        }
        return result;
    }

    public synchronized void clear() {
        seen.clear();
        failures.clear();
        servedPeriod.clear();
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
                Long sp = servedPeriod.get(p);
                if (sp != null) { w.write(SEP); w.write(Long.toString(sp)); }
                w.write('\n');
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "rewrite failed: " + e.getMessage());
        }
    }
}
