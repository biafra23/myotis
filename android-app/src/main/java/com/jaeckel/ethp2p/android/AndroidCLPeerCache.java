package com.jaeckel.ethp2p.android;

import android.util.Log;

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

    public static final int FAILURE_THRESHOLD = 3;

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> failures = new ConcurrentHashMap<>();

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
            Log.w(TAG, "write failed: " + e.getMessage());
        }
    }

    public void markFailure(String multiaddr) {
        if (multiaddr == null || multiaddr.isEmpty()) return;
        if (!seen.contains(multiaddr)) return;
        int count = failures.merge(multiaddr, 1, Integer::sum);
        if (count >= FAILURE_THRESHOLD) {
            if (seen.remove(multiaddr)) {
                failures.remove(multiaddr);
                rewriteFile();
                Log.i(TAG, "evicted peer after " + count + " failures: " + multiaddr);
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
                result.add(line);
                seen.add(line);
            }
            if (!result.isEmpty()) {
                Log.i(TAG, "loaded " + result.size() + " cached CL peer(s)");
            }
        } catch (IOException e) {
            Log.w(TAG, "read failed: " + e.getMessage());
        }
        return result;
    }

    public synchronized void clear() {
        seen.clear();
        failures.clear();
        if (!cacheFile.toFile().delete() && cacheFile.toFile().exists()) {
            Log.w(TAG, "failed to delete cache file " + cacheFile);
        }
    }

    private synchronized void rewriteFile() {
        List<String> lines = new ArrayList<>(seen);
        Collections.sort(lines);
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(cacheFile.toFile(), false), StandardCharsets.UTF_8)) {
            for (String line : lines) {
                w.write(line);
                w.write('\n');
            }
        } catch (IOException e) {
            Log.w(TAG, "rewrite failed: " + e.getMessage());
        }
    }
}
