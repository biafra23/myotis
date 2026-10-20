package io.myotis.engines.common;

import io.myotis.api.DataUsage;
import io.myotis.api.NetworkMetering;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The Java twin of the Rust ledger's tests (rust/myotis-engine/src/usage.rs). */
class DataUsageLedgerTest {

    private static final LocalDate DAY = LocalDate.of(2026, 10, 20);

    /** {elIn, elOut, clIn, clOut}, mutable by the test. */
    private final long[] meter = new long[4];

    private DataUsageLedger ledger(Path file, LocalDate day) {
        return new DataUsageLedger(meter::clone, file, day);
    }

    @Test
    void growthLandsOnTodayAndMeteredOnlyWhileMetered() {
        DataUsageLedger l = ledger(null, DAY);
        meter[0] += 100;
        meter[3] += 40;
        DataUsage u = l.tick(DAY, NetworkMetering.UNMETERED, false, 0);
        assertEquals(new DataUsage(100, 40, 100, 0, 0, 40, "2026-10-20", 100, 40, 0, 0), u);
        meter[2] += 7;
        meter[1] += 3;
        u = l.tick(DAY, NetworkMetering.METERED, false, 0);
        assertEquals(107, u.todayBytesIn());
        assertEquals(43, u.todayBytesOut());
        assertEquals(7, u.todayMeteredBytesIn());
        assertEquals(3, u.todayMeteredBytesOut());
        // UNKNOWN is not metered.
        meter[0] += 1;
        u = l.tick(DAY, NetworkMetering.UNKNOWN, false, 0);
        assertEquals(108, u.todayBytesIn());
        assertEquals(7, u.todayMeteredBytesIn());
    }

    @Test
    void aNewDayStartsFromZeroButTheSessionKeepsCounting() {
        DataUsageLedger l = ledger(null, DAY);
        meter[0] += 500;
        l.tick(DAY, NetworkMetering.METERED, false, 0);
        meter[0] += 20;
        DataUsage u = l.tick(DAY.plusDays(1), NetworkMetering.METERED, false, 0);
        assertEquals("2026-10-21", u.day());
        assertEquals(20, u.todayBytesIn());
        assertEquals(20, u.todayMeteredBytesIn());
        assertEquals(520, u.bytesIn());
    }

    @Test
    void todaysFiguresSurviveAReopenAndYesterdaysDoNot(@TempDir Path dir) {
        Path file = dir.resolve(DataUsageLedger.fileName("gnosis"));
        assertEquals("data-usage-gnosis.json", file.getFileName().toString());
        DataUsageLedger l = ledger(file, DAY);
        meter[2] += 1000;
        meter[3] += 10;
        l.tick(DAY, NetworkMetering.METERED, true, 0);

        // Same day, a fresh stack (its meter starts again at zero).
        java.util.Arrays.fill(meter, 0);
        DataUsageLedger again = ledger(file, DAY);
        meter[1] += 5;
        DataUsage u = again.tick(DAY, NetworkMetering.UNMETERED, false, 0);
        assertEquals(1000, u.todayBytesIn());
        assertEquals(15, u.todayBytesOut());
        assertEquals(1000, u.todayMeteredBytesIn());
        assertEquals(10, u.todayMeteredBytesOut());
        assertEquals(5, u.bytesOut(), "the session is this stack's alone");

        // Next day: the file is yesterday's.
        DataUsage fresh = ledger(file, DAY.plusDays(1)).tick(DAY.plusDays(1), NetworkMetering.UNKNOWN, false, 0);
        assertEquals(0, fresh.todayBytes());
    }

    @Test
    void writesAreBatchedUnlessForcedOrANewDay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve(DataUsageLedger.fileName("mainnet"));
        assertEquals("data-usage.json", file.getFileName().toString());
        DataUsageLedger l = ledger(file, DAY);
        meter[0] += 1;
        l.tick(DAY, NetworkMetering.UNKNOWN, false, 1_000);            // first write is due
        assertEquals(1, DataUsageLedger.read(file, DAY)[0]);
        meter[0] += 1;
        l.tick(DAY, NetworkMetering.UNKNOWN, false, 2_000);            // within the window: held
        assertEquals(1, DataUsageLedger.read(file, DAY)[0]);
        l.tick(DAY, NetworkMetering.UNKNOWN, false, 1_000 + DataUsageLedger.WRITE_EVERY_MS);
        assertEquals(2, DataUsageLedger.read(file, DAY)[0]);           // window passed
        meter[0] += 1;
        l.tick(DAY, NetworkMetering.UNKNOWN, true, 1_000 + DataUsageLedger.WRITE_EVERY_MS);
        assertEquals(3, DataUsageLedger.read(file, DAY)[0]);           // forced (pause/stop)
        meter[0] += 4;
        l.tick(DAY.plusDays(1), NetworkMetering.UNKNOWN, false, 1_000 + DataUsageLedger.WRITE_EVERY_MS);
        assertEquals(4, DataUsageLedger.read(file, DAY.plusDays(1))[0]); // a new day: written
        assertFalse(Files.exists(dir.resolve("data-usage.json.tmp")));
    }

    @Test
    void theRustLedgersFileReadsHere(@TempDir Path dir) throws Exception {
        // Byte-for-byte what rust/myotis-engine/src/usage.rs writes (serde_json's
        // key order): the two engines share the file across an engine switch.
        Path file = dir.resolve("data-usage.json");
        Files.write(file, ("{\"bytesIn\":12,\"bytesOut\":3,\"day\":\"2026-10-20\",\"meteredBytesIn\":2,"
                + "\"meteredBytesOut\":1,\"version\":1}").getBytes(StandardCharsets.UTF_8));
        long[] t = DataUsageLedger.read(file, DAY);
        assertEquals(12, t[0]);
        assertEquals(3, t[1]);
        assertEquals(2, t[2]);
        assertEquals(1, t[3]);
    }

    @Test
    void aDamagedFileIsIgnored(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("data-usage.json");
        Files.write(file, "not json".getBytes(StandardCharsets.UTF_8));
        assertNull(DataUsageLedger.read(file, DAY));
        Files.write(file, "{\"version\":2,\"day\":\"2026-10-20\",\"bytesIn\":1,\"bytesOut\":1,\"meteredBytesIn\":0,\"meteredBytesOut\":0}"
                .getBytes(StandardCharsets.UTF_8));
        assertNull(DataUsageLedger.read(file, DAY));
        Files.write(file, "{\"version\":1,\"day\":\"2026-10-20\",\"bytesIn\":1}".getBytes(StandardCharsets.UTF_8));
        assertNull(DataUsageLedger.read(file, DAY));
        assertNull(DataUsageLedger.read(dir.resolve("missing.json"), DAY));
    }
}
