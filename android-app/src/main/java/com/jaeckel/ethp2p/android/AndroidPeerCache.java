package com.jaeckel.ethp2p.android;

import com.jaeckel.ethp2p.android.log.LogBuffer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Android-native peer cache. Mirrors {@code PeerCache} in the :app module but
 * uses {@code android.util.Log} and the app's filesDir-rooted path supplied by
 * the caller, so we don't pull in slf4j-android or hardcode {@code /tmp}.
 *
 * <p>Record format: {@code ip\tport\tpublicKeyHex[\tsnap][\tsnapok|\tsnapbad]\n}
 * (tab-separated, UTF-8). Tabs can't appear in
 * {@link java.net.InetAddress#getHostAddress()} output, so the format stays
 * unambiguous for IPv6 literals. The trailing {@code snap} flag ("1"/"0")
 * records snap/1 <em>capability</em> and is optional, so pre-existing cache
 * files load unchanged (missing flag → not snap-capable). An optional
 * {@code snapok}/{@code snapbad} token after it records snap-serving
 * <em>quality</em> — whether the peer actually returned usable proofs
 * ({@link SnapQuality}).
 *
 * <p><b>Capability vs quality.</b> The {@code snap} flag means the peer
 * negotiated snap/1 during Hello; it says nothing about whether the peer
 * actually serves the state trie for a given root. Many advertised snap peers
 * hang or return empty proofs. {@link #recordSnapServed} /
 * {@link #recordSnapFailure} layer a learned quality verdict on top — analogous
 * to the CL cache's light-client confirmed/denied — so a restart can dial peers
 * proven to serve proofs first and deprioritize known hangers, instead of
 * re-discovering the bad ones one timeout at a time. A peer needs
 * {@link #SNAP_FAILURE_THRESHOLD} consecutive failures (no intervening serve)
 * to be marked {@code DENIED}; any successful serve re-confirms it. Denied peers
 * are deprioritized, never evicted — state roots change, and a peer that
 * couldn't serve an old pivot may serve the current one (and is still a fine
 * plain-eth peer for headers/blocks).
 */
public final class AndroidPeerCache {

    private static final String TAG = "ethp2p.cache";
    private static final char SEP = '\t';

    /** Consecutive snap-serve failures before a peer is marked {@code DENIED}. */
    public static final int SNAP_FAILURE_THRESHOLD = 3;

    /** Learned snap-serving verdict, persisted across restarts. */
    public enum SnapQuality { CONFIRMED, UNKNOWN, DENIED }

    public record CachedPeer(InetSocketAddress address, String publicKeyHex,
                             boolean snap, SnapQuality snapQuality) {}

    /** In-memory record of a known peer, enough to rewrite its line. */
    private record PeerRec(String publicKeyHex, boolean snap) {}

    private final Path cacheFile;
    /** key ("ip\tport") -> identity (pubkey + snap capability). Insertion-ordered
     *  so a rewrite preserves discovery order among same-quality peers. */
    private final Map<String, PeerRec> entries = new LinkedHashMap<>();
    private final Set<String> snapConfirmed = ConcurrentHashMap.newKeySet();
    private final Set<String> snapDenied = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> snapFailures = new ConcurrentHashMap<>();

    public AndroidPeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    private static String keyOf(InetSocketAddress address) {
        // getHostString() over getAddress().getHostAddress() — the latter NPEs
        // if the address is unresolved. getHostString() returns the literal ip
        // string directly and skips the defensive branch.
        return address.getHostString() + SEP + address.getPort();
    }

    /**
     * Synchronized because RLPxConnector calls this from Netty worker threads;
     * without it two simultaneous writes can interleave and corrupt a line.
     */
    public synchronized void add(InetSocketAddress address, String publicKeyHex, boolean snap) {
        String key = keyOf(address);
        if (entries.containsKey(key)) return;
        entries.put(key, new PeerRec(publicKeyHex, snap));
        // Fast path: append the new line (UNKNOWN quality) rather than rewriting
        // the whole file on every newly-handshaked peer.
        String line = key + SEP + publicKeyHex + SEP + (snap ? "1" : "0") + "\n";
        try (FileOutputStream out = new FileOutputStream(cacheFile.toFile(), true)) {
            out.write(line.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            LogBuffer.w(TAG, "write failed: " + e.getMessage());
        }
    }

    /**
     * Record that a peer returned a usable snap proof for some state root —
     * promote it to {@code CONFIRMED} so a restart dials it first. Resets the
     * failure counter and clears any prior denial. Idempotent: once confirmed,
     * repeat serves are in-memory no-ops (no disk rewrite).
     */
    public synchronized void recordSnapServed(InetSocketAddress address) {
        String key = keyOf(address);
        snapFailures.remove(key);
        boolean changed = snapConfirmed.add(key);
        changed |= snapDenied.remove(key);
        if (changed) rewriteFile();
    }

    /**
     * Record that a peer failed to serve the current state root (empty/invalid
     * proof, timeout, or IO error — the same signals {@code SnapBackedStateOracle}
     * uses to rotate). After {@link #SNAP_FAILURE_THRESHOLD} consecutive failures
     * the peer is marked {@code DENIED} (deprioritized on restart, not evicted).
     * A later {@link #recordSnapServed} re-confirms it.
     */
    public synchronized void recordSnapFailure(InetSocketAddress address) {
        String key = keyOf(address);
        if (!entries.containsKey(key)) return; // never seen → nothing to demote
        int count = snapFailures.merge(key, 1, Integer::sum);
        if (count >= SNAP_FAILURE_THRESHOLD) {
            boolean changed = snapDenied.add(key);
            changed |= snapConfirmed.remove(key);
            if (changed) {
                rewriteFile();
                LogBuffer.i(TAG, "snap peer denied after " + count + " failures: " + key);
            }
        }
    }

    /**
     * Delete the cache file and forget every peer we've written. Next call
     * to {@link #add} will recreate the file.
     */
    public synchronized void clear() {
        entries.clear();
        snapConfirmed.clear();
        snapDenied.clear();
        snapFailures.clear();
        if (!cacheFile.toFile().delete() && cacheFile.toFile().exists()) {
            LogBuffer.w(TAG, "failed to delete cache file " + cacheFile);
        }
    }

    public synchronized List<CachedPeer> load() {
        List<CachedPeer> result = new ArrayList<>();
        if (!cacheFile.toFile().exists()) return result;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(cacheFile.toFile()), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty()) continue;
                try {
                    String[] parts = line.split(String.valueOf(SEP), -1);
                    if (parts.length < 3) {
                        LogBuffer.w(TAG, "skipping malformed peer line");
                        continue;
                    }
                    String ip = parts[0];
                    int port = Integer.parseInt(parts[1]);
                    String pubKeyHex = parts[2];
                    // Optional trailing tokens: snap flag ("1"/"0"), then a
                    // quality token ("snapok"/"snapbad"). Older lines without
                    // them parse as snap=false / UNKNOWN.
                    boolean snap = parts.length > 3 && "1".equals(parts[3]);
                    SnapQuality quality = SnapQuality.UNKNOWN;
                    for (int i = 4; i < parts.length; i++) {
                        if ("snapok".equals(parts[i])) quality = SnapQuality.CONFIRMED;
                        else if ("snapbad".equals(parts[i])) quality = SnapQuality.DENIED;
                    }
                    String key = ip + SEP + port;
                    entries.put(key, new PeerRec(pubKeyHex, snap));
                    if (quality == SnapQuality.CONFIRMED) snapConfirmed.add(key);
                    else if (quality == SnapQuality.DENIED) snapDenied.add(key);
                    result.add(new CachedPeer(
                            new InetSocketAddress(ip, port), pubKeyHex, snap, quality));
                } catch (Exception e) {
                    LogBuffer.w(TAG, "skipping malformed peer line: " + e.getMessage());
                }
            }
            int conf = snapConfirmed.size(), den = snapDenied.size();
            if (!result.isEmpty() && (conf > 0 || den > 0)) {
                LogBuffer.i(TAG, "loaded " + result.size() + " cached peer(s) ("
                        + conf + " snap-confirmed, " + den + " snap-denied)");
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "read failed: " + e.getMessage());
        }
        return result;
    }

    private synchronized void rewriteFile() {
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(cacheFile.toFile(), false), StandardCharsets.UTF_8)) {
            for (Map.Entry<String, PeerRec> e : entries.entrySet()) {
                String key = e.getKey();
                PeerRec rec = e.getValue();
                w.write(key);                       // ip\tport
                w.write(SEP); w.write(rec.publicKeyHex());
                w.write(SEP); w.write(rec.snap() ? "1" : "0");
                if (snapConfirmed.contains(key)) { w.write(SEP); w.write("snapok"); }
                else if (snapDenied.contains(key)) { w.write(SEP); w.write("snapbad"); }
                w.write('\n');
            }
        } catch (IOException e) {
            LogBuffer.w(TAG, "rewrite failed: " + e.getMessage());
        }
    }
}
