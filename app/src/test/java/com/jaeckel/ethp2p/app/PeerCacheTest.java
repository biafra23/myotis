package com.jaeckel.ethp2p.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerCacheTest {

    private static final String PK = "0x" + "ab".repeat(64);
    private static final InetSocketAddress A = InetSocketAddress.createUnresolved("1.2.3.4", 30303);

    private static PeerCache.CachedPeer only(PeerCache cache) {
        List<PeerCache.CachedPeer> peers = cache.load();
        assertEquals(1, peers.size());
        return peers.get(0);
    }

    @Test
    void connectFailuresDemoteThenEvict(@TempDir Path dir) {
        PeerCache cache = new PeerCache(dir.resolve("peers.cache"));
        cache.add(A, PK, true);
        cache.recordSnapServed(A);
        assertEquals(PeerCache.SnapQuality.CONFIRMED, only(cache).snapQuality());

        // Below the demote threshold the learned verdict shows through.
        for (int i = 0; i < PeerCache.CONNECT_FAILURE_DEMOTE - 1; i++) {
            cache.recordConnectFailure(A);
        }
        assertEquals(PeerCache.SnapQuality.CONFIRMED, only(cache).snapQuality());

        // Crossing it reports DENIED without erasing the stored verdict.
        cache.recordConnectFailure(A);
        assertEquals(PeerCache.SnapQuality.DENIED, only(cache).snapQuality());

        // A successful re-handshake clears the streak and restores the verdict.
        cache.add(A, PK, true);
        assertEquals(PeerCache.SnapQuality.CONFIRMED, only(cache).snapQuality());

        // Sustained unreachability evicts the peer entirely.
        for (int i = 0; i < PeerCache.CONNECT_FAILURE_EVICT; i++) {
            cache.recordConnectFailure(A);
        }
        assertTrue(cache.load().isEmpty(), "peer should be evicted");

        // Unknown addresses never create entries.
        cache.recordConnectFailure(InetSocketAddress.createUnresolved("9.9.9.9", 1));
        assertTrue(cache.load().isEmpty());
        cache.close();
    }

    @Test
    void failsTokenRoundTripsThroughTheFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        PeerCache cache = new PeerCache(file);
        cache.add(A, PK, true);
        cache.recordSnapServed(A);
        for (int i = 0; i < PeerCache.CONNECT_FAILURE_DEMOTE; i++) {
            cache.recordConnectFailure(A);
        }
        cache.close(); // drain the async writer before reading the file

        String body = Files.readString(file);
        assertTrue(body.contains("\tsnapok\tfails=" + PeerCache.CONNECT_FAILURE_DEMOTE),
                "streak must be persisted alongside the verdict, got: " + body);

        // A fresh instance resumes the streak (still demoted), and further
        // failures count on from where the file left off — eviction is
        // cumulative across restarts.
        PeerCache reloaded = new PeerCache(file);
        assertEquals(PeerCache.SnapQuality.DENIED, only(reloaded).snapQuality());
        for (int i = PeerCache.CONNECT_FAILURE_DEMOTE; i < PeerCache.CONNECT_FAILURE_EVICT; i++) {
            reloaded.recordConnectFailure(A);
        }
        assertTrue(reloaded.load().isEmpty(), "resumed streak should reach eviction");
        reloaded.close();
    }

    @Test
    void clearingAPersistedStreakRewritesTheFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        Files.writeString(file, "1.2.3.4\t30303\t" + PK + "\t1\tsnapok\tfails=7\n");
        PeerCache cache = new PeerCache(file);
        assertEquals(PeerCache.SnapQuality.DENIED, only(cache).snapQuality());

        // The peer re-handshakes: the reset must reach the FILE, or the next
        // restart resurrects fails=7 and re-demotes a reachable peer.
        cache.add(A, PK, true);
        assertEquals(PeerCache.SnapQuality.CONFIRMED, only(cache).snapQuality());
        cache.close();

        PeerCache reloaded = new PeerCache(file);
        assertEquals(PeerCache.SnapQuality.CONFIRMED, only(reloaded).snapQuality());
        reloaded.close();
    }

    @Test
    void parsesLinesWithUnknownTokensAndBadFailsCount(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("peers.cache");
        Files.writeString(file,
                "1.2.3.4\t30303\t" + PK + "\t1\tsnapok\tfails=notanumber\tfuturetoken\n");
        PeerCache cache = new PeerCache(file);
        // Unreadable fails token → streak starts over at 0; unknown tokens skipped.
        assertEquals(PeerCache.SnapQuality.CONFIRMED, only(cache).snapQuality());
        cache.close();
    }
}
