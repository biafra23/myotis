package com.jaeckel.ethp2p.android;

import android.util.Log;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
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
 */
public final class AndroidPeerCache {

    private static final String TAG = "ethp2p.cache";

    public record CachedPeer(InetSocketAddress address, String publicKeyHex) {}

    private final Path cacheFile;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public AndroidPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    public void add(InetSocketAddress address, String publicKeyHex) {
        String key = address.getAddress().getHostAddress() + ":" + address.getPort();
        if (!seen.add(key)) return;
        try (FileOutputStream out = new FileOutputStream(cacheFile.toFile(), true)) {
            out.write((key + ":" + publicKeyHex + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Log.w(TAG, "write failed: " + e.getMessage());
        }
    }

    public List<CachedPeer> load() {
        List<CachedPeer> result = new ArrayList<>();
        if (!cacheFile.toFile().exists()) return result;
        try (BufferedReader r = new BufferedReader(new FileReader(cacheFile.toFile()))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty()) continue;
                int firstColon = line.indexOf(':');
                int secondColon = line.indexOf(':', firstColon + 1);
                if (firstColon < 0 || secondColon < 0) continue;
                String ip = line.substring(0, firstColon);
                int port = Integer.parseInt(line.substring(firstColon + 1, secondColon));
                String pubKeyHex = line.substring(secondColon + 1);
                result.add(new CachedPeer(new InetSocketAddress(ip, port), pubKeyHex));
                seen.add(ip + ":" + port);
            }
        } catch (Exception e) {
            Log.w(TAG, "read failed: " + e.getMessage());
        }
        return result;
    }
}
