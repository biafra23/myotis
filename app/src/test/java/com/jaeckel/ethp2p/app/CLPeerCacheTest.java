package com.jaeckel.ethp2p.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CLPeerCacheTest {

    private static final String MA = "/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmTestPeer";
    private static final String MB = "/ip4/5.6.7.8/tcp/9000/p2p/16Uiu2HAmOtherPeer";

    @Test
    void servedRangeRoundTrips(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        CLPeerCache cache = new CLPeerCache(file);
        cache.recordServed(MA, 128, 130);

        // File carries the range token.
        assertTrue(Files.readString(file).contains("\t128-130"), "range token must be persisted");

        // A fresh instance loads the same range.
        CLPeerCache reloaded = new CLPeerCache(file);
        reloaded.load();
        assertEquals(128L, reloaded.servedRanges().get(MA)[0]);
        assertEquals(130L, reloaded.servedRanges().get(MA)[1]);
        assertEquals(128L, reloaded.servedPeriods().get(MA), "servedPeriods() must expose the floor");
    }

    @Test
    void servedRangeMergesMinAndMax(@TempDir Path dir) {
        CLPeerCache cache = new CLPeerCache(dir.resolve("c.cache"));
        cache.recordServed(MA, 130, 130);
        cache.recordServed(MA, 128, 135);
        assertEquals(128L, cache.servedRanges().get(MA)[0]);
        assertEquals(135L, cache.servedRanges().get(MA)[1]);

        // Order-independent.
        CLPeerCache rev = new CLPeerCache(dir.resolve("d.cache"));
        rev.recordServed(MB, 128, 135);
        rev.recordServed(MB, 130, 130);
        assertEquals(128L, rev.servedRanges().get(MB)[0]);
        assertEquals(135L, rev.servedRanges().get(MB)[1]);
    }

    @Test
    void twoArgOverloadIsDegenerateRange(@TempDir Path dir) {
        CLPeerCache cache = new CLPeerCache(dir.resolve("c.cache"));
        cache.recordServed(MA, 200);
        assertEquals(200L, cache.servedRanges().get(MA)[0]);
        assertEquals(200L, cache.servedRanges().get(MA)[1]);
    }

    @Test
    void bootstrapPeriodRoundTripsAndKeepsMax(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        CLPeerCache cache = new CLPeerCache(file);
        cache.recordBootstrap(MA, 256);
        cache.recordBootstrap(MA, 250); // shallower — must not lower the kept value
        assertEquals(256L, cache.bootstrapPeers().get(MA));
        assertTrue(Files.readString(file).contains("\tb256"), "bootstrap token must be persisted");

        CLPeerCache reloaded = new CLPeerCache(file);
        reloaded.load();
        assertEquals(256L, reloaded.bootstrapPeers().get(MA));
    }

    @Test
    void legacyFloorFormatLoadsAsDegenerateRange(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        Files.writeString(file, MA + "\t512\tlc\n");
        CLPeerCache cache = new CLPeerCache(file);
        cache.load();
        assertEquals(512L, cache.servedRanges().get(MA)[0]);
        assertEquals(512L, cache.servedRanges().get(MA)[1]);
        assertTrue(cache.lightClientConfirmed().contains(MA));
        assertNull(cache.bootstrapPeers().get(MA));
    }

    @Test
    void combinedLineParsesAllTokens(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        Files.writeString(file, MA + "\t128-135\tb256\tlc\n");
        CLPeerCache cache = new CLPeerCache(file);
        cache.load();
        assertEquals(128L, cache.servedRanges().get(MA)[0]);
        assertEquals(135L, cache.servedRanges().get(MA)[1]);
        assertEquals(256L, cache.bootstrapPeers().get(MA));
        assertTrue(cache.lightClientConfirmed().contains(MA));
    }

    @Test
    void duplicateTokensOnOneLineMergeNotOverwrite(@TempDir Path dir) throws Exception {
        // A hand-edited/merged line with multiple range and bootstrap tokens must widen the
        // range (union) and keep the deepest bootstrap, not let the last token silently win.
        Path file = dir.resolve("cl-peers.cache");
        Files.writeString(file, MA + "\t128-130\t125-135\t512\tb200\tb256\n");
        CLPeerCache cache = new CLPeerCache(file);
        cache.load();
        assertEquals(125L, cache.servedRanges().get(MA)[0], "low must be the smallest seen");
        assertEquals(512L, cache.servedRanges().get(MA)[1], "high must be the largest seen");
        assertEquals(256L, cache.bootstrapPeers().get(MA), "bootstrap must keep the deepest period");
    }

    @Test
    void evictionClearsRangeAndBootstrap(@TempDir Path dir) {
        CLPeerCache cache = new CLPeerCache(dir.resolve("c.cache"));
        cache.add(MA);
        cache.recordServed(MA, 128, 135);
        cache.recordBootstrap(MA, 256);
        for (int i = 0; i < CLPeerCache.FAILURE_THRESHOLD; i++) {
            cache.markFailure(MA);
        }
        assertTrue(cache.servedRanges().isEmpty(), "served range must be dropped on eviction");
        assertTrue(cache.bootstrapPeers().isEmpty(), "bootstrap period must be dropped on eviction");
        assertFalse(cache.load().contains(MA), "evicted peer must be gone from the file");
    }

    @Test
    void writeIsIdempotentAcrossReload(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("cl-peers.cache");
        CLPeerCache cache = new CLPeerCache(file);
        cache.recordServed(MA, 128, 135);
        cache.recordBootstrap(MA, 256);
        cache.markLightClient(MA);
        String first = Files.readString(file);

        CLPeerCache reloaded = new CLPeerCache(file);
        List<String> loaded = reloaded.load();
        assertEquals(List.of(MA), loaded);
        // Re-persist via a no-op-ish rewrite path and confirm the format is stable.
        reloaded.markLightClient(MA); // already confirmed -> no change, file untouched
        assertEquals(first, Files.readString(file));
        Map<String, long[]> ranges = reloaded.servedRanges();
        assertEquals(128L, ranges.get(MA)[0]);
        assertEquals(135L, ranges.get(MA)[1]);
    }
}
