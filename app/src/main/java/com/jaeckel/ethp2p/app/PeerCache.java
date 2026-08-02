package com.jaeckel.ethp2p.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Persists peers that reached READY state so they can be reconnected on restart.
 * Mirrors {@code AndroidPeerCache} in the :android-app module (which went
 * through review) but logs via slf4j instead of the in-app {@code LogBuffer}.
 *
 * <p>Record format:
 * {@code ip\tport\tpublicKeyHex[\tsnap][\tsnapok|\tsnapbad][\tfails=N]\n}
 * (tab-separated, UTF-8). Tabs can't appear in
 * {@link java.net.InetAddress#getHostAddress()} output, so the format stays
 * unambiguous for IPv6 literals. The trailing {@code snap} flag ("1"/"0")
 * records snap/1 <em>capability</em> and is optional, so pre-existing cache
 * files load unchanged (missing flag → not snap-capable). An optional
 * {@code snapok}/{@code snapbad} token after it records snap-serving
 * <em>quality</em> — whether the peer actually returned usable proofs
 * ({@link SnapQuality}). Lines in the daemon's legacy colon-separated format
 * ({@code ip:port:publicKeyHex[:snap]}) still parse, so an existing cache file
 * migrates in place on the first rewrite.
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
 * are deprioritized, never evicted for serve failures — state roots change, and
 * a peer that couldn't serve an old pivot may serve the current one (and is
 * still a fine plain-eth peer for headers/blocks).
 *
 * <p><b>Reachability.</b> {@link #recordConnectFailure} tracks consecutive
 * TCP-level dial failures (refused/timeout — the peer is <em>gone</em>, not
 * merely unhelpful), persisted as a {@code fails=N} token. A peer past
 * {@link #CONNECT_FAILURE_DEMOTE} reports {@code DENIED} from {@link #load()}
 * so the dial loop stops leading with long-dead peers; past
 * {@link #CONNECT_FAILURE_EVICT} it is dropped from the cache entirely (the
 * only eviction path — re-discovery re-adds it if it ever comes back). Any
 * successful handshake ({@link #add} on a known peer) or serve resets the
 * streak. Callers should only report failures while demonstrably online, so an
 * offline laptop can't decimate its own cache.
 *
 * <p><b>Threading.</b> The in-memory maps are the authoritative copy and are
 * mutated only under {@code synchronized(this)}. Disk writes are offloaded to a
 * single daemon thread ({@link #diskWriter}) so the snap response callbacks
 * (which run on the Netty event loop) and the RLPx worker threads never block on
 * file I/O. Each write task is submitted <em>while holding the monitor</em>, so
 * submission order matches the in-memory state-capture order and the
 * single-threaded executor applies them in that order — the file converges to
 * the in-memory state. Persistence is best-effort: a process kill can drop a
 * queued write, which is fine because the cache is reconstructible (peers are
 * re-discovered) and was never fsync'd even when writes were synchronous.
 */
public final class PeerCache implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(PeerCache.class);
    private static final char SEP = '\t';

    /** Consecutive snap-serve failures before a peer is marked {@code DENIED}. */
    public static final int SNAP_FAILURE_THRESHOLD = 3;

    /** Consecutive TCP connect failures before a peer reports {@code DENIED}
     *  from {@link #load()} (≈3 min of unreachability at the maintainer's
     *  re-dial cadence — dead peers stop hogging the head of the dial order). */
    public static final int CONNECT_FAILURE_DEMOTE = 5;

    /** Consecutive TCP connect failures before a peer is evicted from the cache
     *  (≈35 min of continuous unreachability, cumulative across restarts). */
    public static final int CONNECT_FAILURE_EVICT = 50;

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
    /** Consecutive TCP connect failures per key. Persisted (as {@code fails=N})
     *  only when a rewrite happens anyway or a threshold is crossed, so a dead
     *  peer doesn't cost one disk write per failed dial. */
    private final Map<String, Integer> connectFailures = new ConcurrentHashMap<>();
    /** True once the on-disk file has been read into {@link #entries} (or shown
     *  absent), after which {@link #load()} serves from memory without disk I/O. */
    private boolean loaded = false;

    /** Serializes all file writes off the caller's (Netty) thread. Single-threaded
     *  so submission order == apply order; daemon so it never blocks JVM exit. */
    private final ExecutorService diskWriter = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "peer-cache-writer");
        t.setDaemon(true);
        return t;
    });

    public PeerCache(Path cacheFile) {
        this.cacheFile = cacheFile;
    }

    private static String keyOf(InetSocketAddress address) {
        // getHostString() over getAddress().getHostAddress() — the latter NPEs
        // if the address is unresolved. getHostString() returns the literal ip
        // string directly and skips the defensive branch.
        return address.getHostString() + SEP + address.getPort();
    }

    /**
     * Record a newly-handshaked peer. Updates the in-memory map and appends its
     * line to disk (asynchronously). No-op if already known.
     */
    public synchronized void add(InetSocketAddress address, String publicKeyHex, boolean snap) {
        String key = keyOf(address);
        if (entries.containsKey(key)) {
            // Re-handshake of a known peer: it's reachable — clear the connect
            // failure streak (persisted lazily, on the next rewrite).
            connectFailures.remove(key);
            return;
        }
        entries.put(key, new PeerRec(publicKeyHex, snap));
        // Append fast path: a single new line (UNKNOWN quality) rather than
        // rewriting the whole file on every newly-handshaked peer.
        byte[] line = (key + SEP + publicKeyHex + SEP + (snap ? "1" : "0") + "\n")
                .getBytes(StandardCharsets.UTF_8);
        submitWrite(() -> writeBytes(line, true));
        log.info("[cache] Saved READY peer {}:{} (snap={})",
                address.getHostString(), address.getPort(), snap);
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
        connectFailures.remove(key);
        boolean changed = snapConfirmed.add(key);
        changed |= snapDenied.remove(key);
        if (changed) rewriteAsync();
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
                rewriteAsync();
                log.info("[cache] snap peer denied after {} failures: {}",
                        count, key.replace(SEP, ':'));
            }
        }
    }

    /**
     * Record a TCP-level connect failure (refused/timeout/unreachable) against a
     * cached peer. No-op for unknown addresses, so the counter map can't grow
     * from DNS-pool/discv4 dials that were never cached. Crossing
     * {@link #CONNECT_FAILURE_DEMOTE} persists the streak and demotes the peer's
     * reported quality; crossing {@link #CONNECT_FAILURE_EVICT} evicts it.
     * Callers must only report while demonstrably online (some other peer or a
     * DNS resolve succeeded recently) — see class javadoc.
     */
    public synchronized void recordConnectFailure(InetSocketAddress address) {
        String key = keyOf(address);
        if (!entries.containsKey(key)) return;
        int count = connectFailures.merge(key, 1, Integer::sum);
        if (count >= CONNECT_FAILURE_EVICT) {
            entries.remove(key);
            snapConfirmed.remove(key);
            snapDenied.remove(key);
            snapFailures.remove(key);
            connectFailures.remove(key);
            rewriteAsync();
            log.info("[cache] evicted unreachable peer after {} consecutive connect failures: {}",
                    count, key.replace(SEP, ':'));
        } else if (count % CONNECT_FAILURE_DEMOTE == 0) {
            // Persist every 5th failure (not just the demote crossing) so a
            // restart resumes the streak with at most 4 counts lost — keeping
            // eviction genuinely cumulative across restarts.
            rewriteAsync();
            if (count == CONNECT_FAILURE_DEMOTE) {
                log.info("[cache] deprioritized unreachable peer after {} consecutive connect failures: {}",
                        count, key.replace(SEP, ':'));
            }
        }
    }

    /**
     * Return all cached peers. Reads and parses the file on the first call, then
     * serves from the in-memory copy — so periodic callers don't re-read/parse
     * the file every few seconds.
     */
    public synchronized List<CachedPeer> load() {
        if (!loaded) loadFromDisk();
        List<CachedPeer> result = new ArrayList<>(entries.size());
        for (Map.Entry<String, PeerRec> e : entries.entrySet()) {
            String key = e.getKey();
            int tab = key.indexOf(SEP);
            if (tab < 0) continue;
            String ip = key.substring(0, tab);
            int port;
            try {
                port = Integer.parseInt(key.substring(tab + 1));
            } catch (NumberFormatException ex) {
                continue;
            }
            PeerRec rec = e.getValue();
            // A peer past the connect-failure demote threshold reports DENIED
            // regardless of its learned serve quality: a currently-unreachable
            // CONFIRMED peer must not outrank reachable candidates (or get the
            // hunt's eager backoff bypass). The underlying verdict is kept — one
            // successful handshake clears the streak and restores it.
            SnapQuality quality =
                    connectFailures.getOrDefault(key, 0) >= CONNECT_FAILURE_DEMOTE ? SnapQuality.DENIED
                    : snapConfirmed.contains(key) ? SnapQuality.CONFIRMED
                    : snapDenied.contains(key) ? SnapQuality.DENIED
                    : SnapQuality.UNKNOWN;
            result.add(new CachedPeer(
                    new InetSocketAddress(ip, port), rec.publicKeyHex(), rec.snap(), quality));
        }
        return result;
    }

    /** Read the file into the in-memory maps. Runs at most once (guarded by
     *  {@link #loaded}); each line parses independently so a malformed entry is
     *  skipped without aborting the rest. */
    private void loadFromDisk() {
        loaded = true;
        if (!cacheFile.toFile().exists()) return;
        int conf = 0, den = 0, count = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(cacheFile.toFile()), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty()) continue;
                try {
                    String[] parts = line.split(String.valueOf(SEP), -1);
                    if (parts.length < 3) {
                        // Legacy daemon format: ip:port:publicKeyHex[:snap].
                        if (!parseLegacyLine(line)) {
                            log.warn("[cache] skipping malformed peer line");
                            continue;
                        }
                        count++;
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
                    int fails = 0;
                    for (int i = 4; i < parts.length; i++) {
                        if ("snapok".equals(parts[i])) quality = SnapQuality.CONFIRMED;
                        else if ("snapbad".equals(parts[i])) quality = SnapQuality.DENIED;
                        else if (parts[i].startsWith("fails=")) {
                            try {
                                fails = Integer.parseInt(parts[i].substring("fails=".length()));
                            } catch (NumberFormatException ignore) {
                                // unreadable token → streak starts over at 0
                            }
                        }
                    }
                    String key = ip + SEP + port;
                    entries.put(key, new PeerRec(pubKeyHex, snap));
                    if (fails > 0) connectFailures.put(key, fails);
                    if (quality == SnapQuality.CONFIRMED) { snapConfirmed.add(key); conf++; }
                    else if (quality == SnapQuality.DENIED) { snapDenied.add(key); den++; }
                    count++;
                } catch (Exception e) {
                    log.warn("[cache] skipping malformed peer line: {}", e.getMessage());
                }
            }
            log.info("[cache] Loaded {} cached peer(s) from {} ({} snap-confirmed, {} snap-denied)",
                    count, cacheFile, conf, den);
        } catch (IOException e) {
            log.warn("[cache] read failed: {}", e.getMessage());
        }
    }

    /** Parse one legacy colon-separated daemon line ({@code ip:port:pubKeyHex[:snap]},
     *  IPv4 only — the legacy writer used colons, so v6 literals were never
     *  representable). Returns true if the line was understood. */
    private boolean parseLegacyLine(String line) {
        int firstColon = line.indexOf(':');
        int secondColon = line.indexOf(':', firstColon + 1);
        if (firstColon < 0 || secondColon < 0) return false;
        String ip = line.substring(0, firstColon);
        int port;
        try {
            port = Integer.parseInt(line.substring(firstColon + 1, secondColon));
        } catch (NumberFormatException e) {
            return false;
        }
        String rest = line.substring(secondColon + 1);
        String pubKeyHex = rest;
        boolean snap = false;
        int flagColon = rest.lastIndexOf(':');
        if (flagColon >= 0) {
            String suffix = rest.substring(flagColon + 1);
            if (suffix.equals("0") || suffix.equals("1")) {
                pubKeyHex = rest.substring(0, flagColon);
                snap = suffix.equals("1");
            }
        }
        if (pubKeyHex.isEmpty() || pubKeyHex.indexOf(':') >= 0) return false;
        entries.put(ip + SEP + port, new PeerRec(pubKeyHex, snap));
        return true;
    }

    /** Render the full file content from the in-memory state (called under the
     *  monitor) and submit it as a truncating rewrite. */
    private void rewriteAsync() {
        StringBuilder sb = new StringBuilder(entries.size() * 96);
        for (Map.Entry<String, PeerRec> e : entries.entrySet()) {
            String key = e.getKey();
            PeerRec rec = e.getValue();
            sb.append(key)                                  // ip\tport
              .append(SEP).append(rec.publicKeyHex())
              .append(SEP).append(rec.snap() ? "1" : "0");
            if (snapConfirmed.contains(key)) sb.append(SEP).append("snapok");
            else if (snapDenied.contains(key)) sb.append(SEP).append("snapbad");
            int fails = connectFailures.getOrDefault(key, 0);
            if (fails > 0) sb.append(SEP).append("fails=").append(fails);
            sb.append('\n');
        }
        byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
        submitWrite(() -> writeBytes(data, false));
    }

    /** Submit a file op to the writer thread; tolerate a shutdown executor. */
    private void submitWrite(Runnable task) {
        try {
            diskWriter.execute(task);
        } catch (java.util.concurrent.RejectedExecutionException ignore) {
            // Cache already closed (daemon stopping) — drop the write; memory is
            // authoritative and the next start re-reads whatever did land.
        }
    }

    /** Write {@code data} to the cache file on the writer thread. */
    private void writeBytes(byte[] data, boolean append) {
        try (FileOutputStream out = new FileOutputStream(cacheFile.toFile(), append)) {
            out.write(data);
        } catch (IOException e) {
            log.warn("[cache] write failed: {}", e.getMessage());
        }
    }

    /** Stop the writer thread, draining any queued writes first. */
    @Override
    public void close() {
        diskWriter.shutdown();
        try {
            if (!diskWriter.awaitTermination(2, TimeUnit.SECONDS)) {
                diskWriter.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            diskWriter.shutdownNow();
        }
    }

    /**
     * Wipe the in-memory cache and delete the on-disk file, giving discovery a fresh slate. Unlike
     * the static {@link #purge(Path)}, this clears the LIVE instance's authoritative in-memory maps
     * too, so a running node can't rewrite the old peers back on the next {@code add}/serve event.
     */
    public synchronized void clear() {
        entries.clear();
        snapConfirmed.clear();
        snapDenied.clear();
        snapFailures.clear();
        connectFailures.clear();
        loaded = true;  // memory is now the (empty) authority; don't re-read the file we're deleting
        submitWrite(() -> {
            if (!cacheFile.toFile().delete() && cacheFile.toFile().exists()) {
                log.warn("[cache] failed to delete cache file {}", cacheFile);
            }
        });
    }

    /** Delete the cache file (CLI {@code purge-cache}, runs without a daemon). */
    public static void purge(Path cacheFile) {
        try {
            if (Files.deleteIfExists(cacheFile)) {
                System.out.println("Peer cache purged: " + cacheFile);
            } else {
                System.out.println("No peer cache found at: " + cacheFile);
            }
        } catch (IOException e) {
            System.err.println("Failed to purge cache: " + e.getMessage());
        }
    }
}
