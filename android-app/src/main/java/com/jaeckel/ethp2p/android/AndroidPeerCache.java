package com.jaeckel.ethp2p.android;

import android.util.Log;

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
        try {
            Files.writeString(cacheFile, key + ":" + publicKeyHex + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            Log.w(TAG, "write failed: " + e.getMessage());
        }
    }

    public List<CachedPeer> load() {
        List<CachedPeer> result = new ArrayList<>();
        if (!Files.exists(cacheFile)) return result;
        try {
            for (String line : Files.readAllLines(cacheFile)) {
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
