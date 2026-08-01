package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Pins the engine serializer contract LogIndexStatus parses (host.rs
 *  log_index_status_json: fixed key order, no whitespace, optional span). */
class LogIndexStatusTest {

    private val withSpans = "{\"enabled\":true,\"logCount\":42,\"backfillCursor\":123," +
        "\"entries\":[{\"address\":\"0x4e69fd587118dfb64957d18654e3894118e9b1bf\"," +
        "\"fromBlock\":5594611,\"coveredLow\":6000000,\"coveredHigh\":7000000}," +
        "{\"address\":\"0x34a2068192b1297f2a7f85d7d8cde66f8f0921cb\",\"fromBlock\":8461453}]}"

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
        val bare = p.entries[1]
        assertNull(bare.coveredLow)
        assertNull(bare.coveredHigh)
    }

    @Test
    fun disabled_and_error_shapes_parse_as_disabled() {
        assertEquals(false, LogIndexStatus.parse("{\"enabled\":false,\"logCount\":0,\"entries\":[]}").enabled)
        assertEquals(false, LogIndexStatus.parse("{\"error\":\"node is not running\"}").enabled)
    }
}
