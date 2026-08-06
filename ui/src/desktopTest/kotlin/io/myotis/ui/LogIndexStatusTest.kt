package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Pins the engine serializer contract LogIndexStatus parses (host.rs
 *  log_index_status_json: fixed key order, no whitespace, optional span). */
class LogIndexStatusTest {

    // The serializer's current full shape (host.rs log_index_status_json):
    // pacing + backfill-progress keys sit between backfillCursor and entries.
    private val withSpans = "{\"enabled\":true,\"logCount\":42,\"backfillCursor\":6100000," +
        "\"maxSpeed\":true,\"targetLow\":5594611,\"blocksRemaining\":505389," +
        "\"blocksPerSec\":9.4,\"etaSeconds\":53764," +
        "\"entries\":[{\"address\":\"0x4e69fd587118dfb64957d18654e3894118e9b1bf\"," +
        "\"fromBlock\":5594611,\"coveredLow\":6000000,\"coveredHigh\":7000000}," +
        // Deliberately a WIDER covered edge than the target entry's: the x/y
        // fallback must anchor on the entry whose fromBlock IS the target,
        // not the widest edge across entries at different depths.
        "{\"address\":\"0x34a2068192b1297f2a7f85d7d8cde66f8f0921cb\"," +
        "\"fromBlock\":8461453,\"coveredLow\":8461453,\"coveredHigh\":9000000}]}"

    @Test
    fun parses_entries_with_and_without_coverage() {
        val p = LogIndexStatus.parse(withSpans)
        assertEquals(true, p.enabled)
        assertEquals(42L, p.logCount)
        assertEquals(2, p.entries.size)
        val covered = p.entries[0]
        assertEquals("0x4e69fd587118dfb64957d18654e3894118e9b1bf", covered.address)
        assertEquals(5594611L, covered.fromBlock)
        assertEquals(6000000L, covered.coveredLow)
        assertEquals(7000000L, covered.coveredHigh)
        val second = p.entries[1]
        assertEquals(8461453L, second.coveredLow)
        assertEquals(9000000L, second.coveredHigh)
        // Backfill-progress keys (additive; absent on older engines).
        assertEquals(5594611L, p.targetLow)
        assertEquals(505389L, p.blocksRemaining)
        assertEquals(9.4, p.blocksPerSec!!, 0.001)
        assertEquals(53764L, p.etaSeconds)
    }

    @Test
    fun progress_line_prefers_eta_then_falls_back_to_x_of_y() {
        val p = LogIndexStatus.parse(withSpans)
        assertEquals(
            "~14h 56m remaining (505,389 blocks, 9.4 blk/s)",
            LogIndexStatus.progressLine(p),
        )
        // Without a rate, x/y anchored on the TARGET entry's covered high
        // (7,000,000) — NOT the second entry's wider 9,000,000 edge:
        // total = high - target, done = total - remaining.
        val noRate = p.copy(blocksPerSec = null, etaSeconds = null)
        assertEquals("900,000 / 1,405,389 blocks", LogIndexStatus.progressLine(noRate))
        // Complete and pre-seed states.
        assertEquals("backfill complete", LogIndexStatus.progressLine(p.copy(blocksRemaining = 0)))
        assertNull(LogIndexStatus.progressLine(p.copy(blocksRemaining = null)))
    }

    @Test
    fun older_engine_json_without_progress_keys_still_parses() {
        val legacy = "{\"enabled\":true,\"logCount\":7,\"entries\":[]}"
        val p = LogIndexStatus.parse(legacy)
        assertEquals(7L, p.logCount)
        assertNull(p.targetLow)
        assertNull(LogIndexStatus.progressLine(p))
    }

    @Test
    fun disabled_and_error_shapes_parse_as_disabled() {
        assertEquals(false, LogIndexStatus.parse("{\"enabled\":false,\"logCount\":0,\"entries\":[]}").enabled)
        assertEquals(false, LogIndexStatus.parse("{\"error\":\"node is not running\"}").enabled)
    }
}
