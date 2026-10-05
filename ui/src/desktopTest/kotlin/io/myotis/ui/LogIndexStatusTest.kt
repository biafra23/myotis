package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
    fun pausedBackfillReportsAStandingDistanceNotProgress() {
        // With the walk off, "remaining" is a distance that will not shrink and no
        // ETA can be honest about it. The line must say so, and must say what it
        // means for queries down there: refused, never an empty list.
        val json = "{\"enabled\":true,\"logCount\":39213,\"backfillCursor\":6100000," +
            "\"maxSpeed\":false,\"backfillPaused\":true,\"targetLow\":5594611," +
            "\"blocksRemaining\":505389,\"headGap\":0," +
            "\"entries\":[{\"address\":\"0xabc\",\"fromBlock\":5594611," +
            "\"coveredLow\":6100000,\"coveredHigh\":6200000}]}"
        val p = LogIndexStatus.parse(json)
        assertTrue("backfillPaused must parse", p.backfillPaused)
        // The pacing bit parses beside it: the Index tab records both as the
        // host's settings when it takes over an index it never configured.
        assertFalse(p.maxSpeed)
        assertTrue(LogIndexStatus.parse(withSpans).maxSpeed)
        val line = LogIndexStatus.progressLine(p)!!
        assertTrue(line, line.contains("paused"))
        assertTrue(line, line.contains("refused"))
        assertFalse("no ETA while paused: $line", line.contains("remaining ("))
    }

    @Test
    fun a_topic_restricted_entry_is_marked_and_the_others_are_not() {
        val json = "{\"enabled\":true,\"logCount\":1,\"entries\":[" +
            "{\"address\":\"0x4e69fd587118dfb64957d18654e3894118e9b1bf\",\"fromBlock\":5," +
            "\"coveredLow\":6,\"coveredHigh\":7,\"restricted\":true}," +
            "{\"address\":\"0x34a2068192b1297f2a7f85d7d8cde66f8f0921cb\",\"fromBlock\":5,\"restricted\":true}," +
            "{\"address\":\"0x58e8dcc13be9780fc42e8723d8ead4cf46943df2\",\"fromBlock\":5," +
            "\"coveredLow\":6,\"coveredHigh\":7}]}"
        val entries = LogIndexStatus.parse(json).entries
        assertEquals(listOf(true, true, false), entries.map { it.restricted })
        assertEquals(7L, entries[0].coveredHigh)
        assertEquals(null, entries[1].coveredHigh)
    }

    @Test
    fun an_error_object_is_not_a_status() {
        // A paused handle answers the ungated probe with one; reading it as "an
        // index with no entries" is what must not happen.
        assertFalse(LogIndexStatus.isStatus("{\"error\":\"handle is paused\"}"))
        assertEquals(null, LogIndexStatus.parseOrNull("{\"error\":\"handle is paused\"}"))
        assertEquals(null, LogIndexStatus.parseOrNull(null))
        // Nor is one that merely mentions the key, or carries it as something
        // other than the entry array.
        assertFalse(LogIndexStatus.isStatus("{\"error\":\"missing \\\"entries\\\" key\"}"))
        assertFalse(LogIndexStatus.isStatus("{\"error\":\"x\",\"entries\":7}"))
        // The engine's "no index" default and the Java engine's are statuses.
        assertTrue(LogIndexStatus.isStatus("{\"enabled\":false,\"logCount\":0,\"entries\":[]}"))
        assertEquals(2, LogIndexStatus.parseOrNull(withSpans)!!.entries.size)
    }

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
    fun a_trailing_head_is_reported_instead_of_claiming_completion() {
        val json = "{\"enabled\":true,\"logCount\":13756,\"backfillCursor\":5594611," +
            "\"maxSpeed\":true,\"targetLow\":5594611,\"blocksRemaining\":0," +
            "\"headGap\":3821,\"entries\":[]}"
        val p = LogIndexStatus.parse(json)
        assertEquals(3821L, p.headGap)
        // Backfill done but coverage trails the head: `latest` queries are
        // still refused, so the line must not read "complete".
        assertEquals(
            "catching up to the head (3,821 blocks behind)",
            LogIndexStatus.progressLine(p),
        )
        // Within the engine's serving slack (LOG_INDEX_LATEST_SLACK) queries
        // ARE served, so "complete" is honest there.
        assertEquals("backfill complete", LogIndexStatus.progressLine(p.copy(headGap = 2)))
        // Just beyond it, queries are refused — say so rather than "complete".
        assertEquals(
            "catching up to the head (64 blocks behind)",
            LogIndexStatus.progressLine(p.copy(headGap = 64)),
        )
        // Engines that don't report the key keep the old wording.
        assertEquals("backfill complete", LogIndexStatus.progressLine(p.copy(headGap = null)))
    }

    @Test
    fun disabled_and_error_shapes_parse_as_disabled() {
        assertEquals(false, LogIndexStatus.parse("{\"enabled\":false,\"logCount\":0,\"entries\":[]}").enabled)
        assertEquals(false, LogIndexStatus.parse("{\"error\":\"node is not running\"}").enabled)
    }
}
