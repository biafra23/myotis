package com.jaeckel.ethp2p.android;

import android.util.Log;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Android-native peer cache. Mirrors {@code PeerCache} in the :app module but
 * uses {@code android.util.Log} and the app's filesDir-rooted path supplied by
 * the caller, so we don't pull in slf4j-android or hardcode {@code /tmp}.
 *
 * <p>Record format: {@code ip\tport\tpublicKeyHex\n} (tab-separated, UTF-8).
 * Tabs can't appear in {@link java.net.InetAddress#getHostAddress()} output,
 * so the format stays unambiguous for IPv6 literals.
 */
public final class AndroidPeerCache {

    private static final String TAG = "ethp2p.cache";
    private static final char SEP = '\t';

    public record CachedPeer(InetSocketAddress address, String publicKeyHex) {}

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public AndroidPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    /**
     * Synchronized because RLPxConnector calls this from Netty worker threads;
     * without it two simultaneous writes can interleave and corrupt a line.
     */
    public synchronized void add(InetSocketAddress address, String publicKeyHex) {
        // getHostString() over getAddress().getHostAddress() — the latter NPEs
        // if the address is unresolved. RLPxConnector hands us resolved
        // addresses, but getHostString() returns the literal ip string
        // directly and skips the defensive branch.
        String key = address.getHostString() + SEP + address.getPort();
        if (!seen.add(key)) return;
        String line = key + SEP + publicKeyHex + "\n";
        try (FileOutputStream out = new FileOutputStream(cacheFile.toFile(), true)) {
            out.write(line.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Log.w(TAG, "write failed: " + e.getMessage());
        }
    }

    /**
     * Delete the cache file and forget every peer we've written. Next call
     * to {@link #add} will recreate the file.
     */
    public synchronized void clear() {
        seen.clear();
        if (!cacheFile.toFile().delete() && cacheFile.toFile().exists()) {
            Log.w(TAG, "failed to delete cache file " + cacheFile);
        }
    }

    public List<CachedPeer> load() {
        List<CachedPeer> result = new ArrayList<>();
        if (!cacheFile.toFile().exists()) return result;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(cacheFile.toFile()), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty()) continue;
                try {
                    int firstSep = line.indexOf(SEP);
                    int secondSep = line.indexOf(SEP, firstSep + 1);
                    if (firstSep < 0 || secondSep < 0) {
                        Log.w(TAG, "skipping malformed peer line");
                        continue;
                    }
                    String ip = line.substring(0, firstSep);
                    int port = Integer.parseInt(line.substring(firstSep + 1, secondSep));
                    String pubKeyHex = line.substring(secondSep + 1);
                    result.add(new CachedPeer(new InetSocketAddress(ip, port), pubKeyHex));
                    seen.add(ip + SEP + port);
                } catch (Exception e) {
                    Log.w(TAG, "skipping malformed peer line: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            Log.w(TAG, "read failed: " + e.getMessage());
        }
        return result;
    }
}
