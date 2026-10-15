package io.myotis.engine.ports;

import io.myotis.api.ports.CachedPeerInfo;
import io.myotis.api.ports.SnapQuality;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The daemon twin's {@code PeerCacheTest}, on the library cache's port-shaped API. */
class FilePeerCacheTest {

    private static final String PK = "0x" + "ab".repeat(64);
    private static final String HOST = "1.2.3.4";
    private static final int PORT = 30303;

    private static CachedPeerInfo only(FilePeerCache cache) {
        List<CachedPeerInfo> peers = cache.load();
        assertEquals(1, peers.size());
        return peers.get(0);
    }

    private static String read(Path file) throws Exception {
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }

    @Test
    void connectFailuresDemoteThenEvict(@TempDir Path dir) {
        FilePeerCache cache = new FilePeerCache(dir.resolve("peers.cache"));
        cache.add(HOST, PORT, PK, true);
        cache.recordSnapServed(HOST, PORT);
        assertEquals(SnapQuality.CONFIRMED, only(cache).snapQuality());
        // Below the demote threshold the learned verdict shows through.
        for (int i = 0; i < FilePeerCache.CONNECT_FAILURE_DEMOTE - 1; i++) {
            cache.recordConnectFailure(HOST, PORT);
        }
        assertEquals(SnapQuality.CONFIRMED, only(cache).snapQuality());
        // Crossing it reports DENIED without erasing the stored verdict.
        cache.recordConnectFailure(HOST, PORT);
        assertEquals(SnapQuality.DENIED, only(cache).snapQuality());
        // A successful re-handshake clears the streak and restores the verdict.
        cache.add(HOST, PORT, PK, true);
        assertEquals(SnapQuality.CONFIRMED, only(cache).snapQuality());
        // Sustained unreachability evicts the peer entirely.
        for (int i = 0; i < FilePeerCache.CONNECT_FAILURE_EVICT; i++) {
            cache.recordConnectFailure(HOST, PORT);
        }
        assertTrue(cache.load().isEmpty(), "peer should be evicted");
        // Unknown addresses never create entries.
        cache.recordConnectFailure("9.9.9.9", 1);
        assertTrue(cache.load().isEmpty());
        cache.close();
    }

    @Test
    void failsTokenRoundTripsThroughTheFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        FilePeerCache cache = new FilePeerCache(file);
        cache.add(HOST, PORT, PK, true);
        cache.recordSnapServed(HOST, PORT);
        for (int i = 0; i < FilePeerCache.CONNECT_FAILURE_DEMOTE; i++) {
            cache.recordConnectFailure(HOST, PORT);
        }
        cache.close(); // drain the async writer before reading the file
        String body = read(file);
        assertTrue(body.contains("\tsnapok\tfails=" + FilePeerCache.CONNECT_FAILURE_DEMOTE),
                "streak must be persisted alongside the verdict, got: " + body);
        // A fresh instance resumes the streak (still demoted), and further failures
        // count on from where the file left off — eviction is cumulative across restarts.
        FilePeerCache reloaded = new FilePeerCache(file);
        assertEquals(SnapQuality.DENIED, only(reloaded).snapQuality());
        for (int i = FilePeerCache.CONNECT_FAILURE_DEMOTE; i < FilePeerCache.CONNECT_FAILURE_EVICT; i++) {
            reloaded.recordConnectFailure(HOST, PORT);
        }
        assertTrue(reloaded.load().isEmpty(), "resumed streak should reach eviction");
        reloaded.close();
    }

    @Test
    void clearingAPersistedStreakRewritesTheFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        Files.write(file, ("1.2.3.4\t30303\t" + PK + "\t1\tsnapok\tfails=7\n").getBytes(StandardCharsets.UTF_8));
        FilePeerCache cache = new FilePeerCache(file);
        assertEquals(SnapQuality.DENIED, only(cache).snapQuality());
        // The peer re-handshakes: the reset must reach the FILE, or the next restart
        // resurrects fails=7 and re-demotes a reachable peer.
        cache.add(HOST, PORT, PK, true);
        assertEquals(SnapQuality.CONFIRMED, only(cache).snapQuality());
        cache.close();
        FilePeerCache reloaded = new FilePeerCache(file);
        assertEquals(SnapQuality.CONFIRMED, only(reloaded).snapQuality());
        reloaded.close();
    }

    @Test
    void parsesLinesWithUnknownTokensAndBadFailsCount(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        Files.write(file, ("1.2.3.4\t30303\t" + PK + "\t1\tsnapok\tfails=notanumber\tfuturetoken\n")
                .getBytes(StandardCharsets.UTF_8));
        FilePeerCache cache = new FilePeerCache(file);
        // Unreadable fails token → streak starts over at 0; unknown tokens skipped.
        CachedPeerInfo peer = only(cache);
        assertEquals(SnapQuality.CONFIRMED, peer.snapQuality());
        assertEquals(HOST, peer.host());
        assertEquals(PORT, peer.port());
        assertEquals(PK, peer.publicKeyHex());
        assertTrue(peer.snap());
        cache.close();
    }

    @Test
    void snapFailuresDenyAfterTheThresholdAndAServeReconfirms(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        FilePeerCache cache = new FilePeerCache(file);
        cache.add(HOST, PORT, PK, true);
        for (int i = 0; i < FilePeerCache.SNAP_FAILURE_THRESHOLD - 1; i++) {
            cache.recordSnapFailure(HOST, PORT);
        }
        assertEquals(SnapQuality.UNKNOWN, only(cache).snapQuality());
        cache.recordSnapFailure(HOST, PORT);
        assertEquals(SnapQuality.DENIED, only(cache).snapQuality());
        cache.recordSnapServed(HOST, PORT);
        assertEquals(SnapQuality.CONFIRMED, only(cache).snapQuality());
        cache.close();
        assertTrue(read(file).contains("\tsnapok"), "the verdict must reach the file");
    }

    @Test
    void clearForgetsEverythingAndDeletesTheFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        FilePeerCache cache = new FilePeerCache(file);
        cache.add(HOST, PORT, PK, false);
        cache.clear();
        assertTrue(cache.load().isEmpty());
        cache.close();
        assertTrue(!Files.exists(file), "the cache file must be gone");
    }
}
