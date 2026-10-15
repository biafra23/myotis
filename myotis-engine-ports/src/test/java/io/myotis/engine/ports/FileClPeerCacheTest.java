package io.myotis.engine.ports;

import io.myotis.api.ports.BootstrapPeer;
import io.myotis.api.ports.ServedRange;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The daemon twin's {@code CLPeerCacheTest}, on the library cache's port-shaped API. */
class FileClPeerCacheTest {

    private static final String MA = "/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmTestPeer";
    private static final String MB = "/ip4/5.6.7.8/tcp/9000/p2p/16Uiu2HAmOtherPeer";

    private static ServedRange range(FileClPeerCache cache, String multiaddr) {
        for (ServedRange r : cache.servedRanges()) {
            if (r.multiaddr().equals(multiaddr)) return r;
        }
        return null;
    }

    private static Long bootstrap(FileClPeerCache cache, String multiaddr) {
        for (BootstrapPeer p : cache.bootstrapPeers()) {
            if (p.multiaddr().equals(multiaddr)) return p.period();
        }
        return null;
    }

    private static String read(Path file) throws Exception {
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }

    private static void write(Path file, String body) throws Exception {
        Files.write(file, body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void servedRangeRoundTrips(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.recordServed(MA, 128, 130);
        assertTrue(read(file).contains("\t128-130"), "range token must be persisted");
        FileClPeerCache reloaded = new FileClPeerCache(file);
        reloaded.load();
        assertEquals(128L, range(reloaded, MA).low());
        assertEquals(130L, range(reloaded, MA).high());
    }

    @Test
    void servedRangeMergesMinAndMax(@TempDir Path dir) {
        FileClPeerCache cache = new FileClPeerCache(dir.resolve("c.cache"));
        cache.recordServed(MA, 130, 130);
        cache.recordServed(MA, 128, 135);
        assertEquals(128L, range(cache, MA).low());
        assertEquals(135L, range(cache, MA).high());
        // Order-independent.
        FileClPeerCache rev = new FileClPeerCache(dir.resolve("d.cache"));
        rev.recordServed(MB, 128, 135);
        rev.recordServed(MB, 130, 130);
        assertEquals(128L, range(rev, MB).low());
        assertEquals(135L, range(rev, MB).high());
    }

    @Test
    void bootstrapPeriodRoundTripsAndKeepsMax(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.recordBootstrap(MA, 256);
        cache.recordBootstrap(MA, 250); // shallower — must not lower the kept value
        assertEquals(256L, bootstrap(cache, MA));
        assertTrue(read(file).contains("\tb256"), "bootstrap token must be persisted");
        FileClPeerCache reloaded = new FileClPeerCache(file);
        reloaded.load();
        assertEquals(256L, bootstrap(reloaded, MA));
    }

    @Test
    void legacyFloorFormatLoadsAsDegenerateRange(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        write(file, MA + "\t512\tlc\n");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.load();
        assertEquals(512L, range(cache, MA).low());
        assertEquals(512L, range(cache, MA).high());
        assertTrue(cache.lightClientConfirmed().contains(MA));
        assertNull(bootstrap(cache, MA));
    }

    @Test
    void combinedLineParsesAllTokens(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        write(file, MA + "\t128-135\tb256\tlc\n");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.load();
        assertEquals(128L, range(cache, MA).low());
        assertEquals(135L, range(cache, MA).high());
        assertEquals(256L, bootstrap(cache, MA));
        assertTrue(cache.lightClientConfirmed().contains(MA));
    }

    @Test
    void duplicateTokensOnOneLineMergeNotOverwrite(@TempDir Path dir) throws Exception {
        // A hand-edited/merged line with multiple range and bootstrap tokens must widen the
        // range (union) and keep the deepest bootstrap, not let the last token silently win.
        Path file = dir.resolve("cl-peers.cache");
        write(file, MA + "\t128-130\t125-135\t512\tb200\tb256\n");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.load();
        assertEquals(125L, range(cache, MA).low(), "low must be the smallest seen");
        assertEquals(512L, range(cache, MA).high(), "high must be the largest seen");
        assertEquals(256L, bootstrap(cache, MA), "bootstrap must keep the deepest period");
    }

    @Test
    void evictionClearsRangeAndBootstrap(@TempDir Path dir) {
        FileClPeerCache cache = new FileClPeerCache(dir.resolve("c.cache"));
        cache.add(MA);
        cache.recordServed(MA, 128, 135);
        cache.recordBootstrap(MA, 256);
        for (int i = 0; i < FileClPeerCache.FAILURE_THRESHOLD; i++) {
            cache.markFailure(MA);
        }
        assertTrue(cache.servedRanges().isEmpty(), "served range must be dropped on eviction");
        assertTrue(cache.bootstrapPeers().isEmpty(), "bootstrap period must be dropped on eviction");
        assertFalse(cache.load().contains(MA), "evicted peer must be gone from the file");
    }

    @Test
    void writeIsIdempotentAcrossReload(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.recordServed(MA, 128, 135);
        cache.recordBootstrap(MA, 256);
        cache.markLightClientBatch(List.of(MA), List.of());
        String first = read(file);
        FileClPeerCache reloaded = new FileClPeerCache(file);
        List<String> loaded = reloaded.load();
        assertEquals(List.of(MA), loaded);
        // Re-persist via a no-op-ish rewrite path and confirm the format is stable.
        reloaded.markLightClientBatch(List.of(MA), List.of()); // already confirmed -> no change
        assertEquals(first, read(file));
        assertEquals(128L, range(reloaded, MA).low());
        assertEquals(135L, range(reloaded, MA).high());
    }

    @Test
    void aDenialNeverDemotesAConfirmedPeerAndAConfirmationOverridesADenial(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.markLightClientBatch(List.of(), List.of(MB));
        assertTrue(cache.lightClientDenied().contains(MB));
        cache.markLightClientBatch(List.of(MB), List.of());
        assertTrue(cache.lightClientConfirmed().contains(MB));
        assertFalse(cache.lightClientDenied().contains(MB));
        cache.markLightClientBatch(List.of(), List.of(MB)); // a later denial does not demote
        assertTrue(cache.lightClientConfirmed().contains(MB));
        assertTrue(read(file).contains(MB + "\tlc"));
    }

    @Test
    void clearForgetsEverythingAndDeletesTheFile(@TempDir Path dir) {
        Path file = dir.resolve("cl-peers.cache");
        FileClPeerCache cache = new FileClPeerCache(file);
        cache.add(MA);
        cache.recordBootstrap(MA, 1);
        cache.clear();
        assertTrue(cache.load().isEmpty());
        assertTrue(cache.bootstrapPeers().isEmpty());
        assertFalse(Files.exists(file));
    }
}
