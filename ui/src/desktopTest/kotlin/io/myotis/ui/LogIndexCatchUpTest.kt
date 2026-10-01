package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The top bar's log-index head catch-up: when it counts as catching up, and
 *  how the engine's instantaneous `headGap` becomes progress. */
class LogIndexCatchUpTest {

    private val coveredEntry = "{\"address\":\"0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9\"," +
        "\"fromBlock\":14737691,\"coveredLow\":14737691,\"coveredHigh\":26094715}"

    private fun status(gap: Long?, enabled: Boolean = true, entries: String = coveredEntry) =
        "{\"enabled\":$enabled,\"logCount\":426000,\"maxSpeed\":false,\"backfillPaused\":true," +
            "\"targetLow\":14737691,\"blocksRemaining\":0" +
            (gap?.let { ",\"headGap\":$it" } ?: "") +
            ",\"entries\":[$entries]}"

    @Test
    fun headGapReadsTheEnginesField() {
        assertEquals(3270L, LogIndexStatus.headGap(status(3270)))
        assertEquals(0L, LogIndexStatus.headGap(status(0)))
    }

    @Test
    fun aDisabledIndexHasNothingToCatchUp() {
        assertEquals(0L, LogIndexStatus.headGap(status(3270, enabled = false)))
        assertEquals(0L, LogIndexStatus.headGap("{\"enabled\":false}"))
    }

    @Test
    fun anIndexWithNothingCoveredHasNothingToCatchUp() {
        // An emptied watch list: enabled, no span anywhere, so the engine omits headGap.
        assertEquals(0L, LogIndexStatus.headGap(status(null, entries = "")))
        // An entry without a span yet (just added) is the same: nothing indexed.
        assertEquals(
            0L,
            LogIndexStatus.headGap(status(null, entries = "{\"address\":\"0x" + "ab".repeat(20) +
                "\",\"fromBlock\":1}")),
        )
    }

    @Test
    fun emptyingTheWatchListMidCatchUpEndsIt() {
        val t = LogIndexCatchUp()
        t.observeAll(mapOf("mainnet" to status(3200)))
        assertEquals(emptyMap<String, CatchUpProgress>(), t.observeAll(mapOf("mainnet" to status(null, entries = ""))))
    }

    @Test
    fun noStatusOrNoHeadIsUnknownNotCaughtUp() {
        assertNull(LogIndexStatus.headGap(null))
        assertNull(LogIndexStatus.headGap(status(null)))
        assertNull(LogIndexStatus.headGap("{\"error\":\"engine stopped\"}"))
    }

    @Test
    fun theServingSlackMatchesTheEngine() {
        // The engine refuses head-reaching queries when head - top > LOG_INDEX_LATEST_SLACK (4).
        assertFalse(LogIndexStatus.refusesHeadQueries(4))
        assertTrue(LogIndexStatus.refusesHeadQueries(5))
    }

    @Test
    fun progressIsMeasuredFromTheLargestGapOfTheCatchUp() {
        val t = LogIndexCatchUp()
        assertEquals(CatchUpProgress(3000, 3000), t.observe("mainnet", 3000))
        // The head outran the bridge: the start moves up, never a negative fraction.
        assertEquals(CatchUpProgress(3200, 3200), t.observe("mainnet", 3200))
        val p = t.observe("mainnet", 800)!!
        assertEquals(CatchUpProgress(800, 3200), p)
        assertEquals(0.75f, p.fraction, 1e-6f)
    }

    @Test
    fun aTrailingHeadFollowIsNotACatchUp() {
        // A healthy head-follow can sit a few blocks under the head indefinitely.
        val t = LogIndexCatchUp()
        listOf(3L, 6L, 4L, 8L, 7L, 31L).forEach { assertNull(t.observe("gnosis", it)) }
        assertEquals(CatchUpProgress(32, 32), t.observe("gnosis", LogIndexCatchUp.ENTER_GAP))
    }

    @Test
    fun aCatchUpLastsUntilTheGapIsBackWithinTheSlack() {
        val t = LogIndexCatchUp()
        t.observe("mainnet", 3000)
        assertEquals(CatchUpProgress(6, 3000), t.observe("mainnet", 6))
        assertEquals(CatchUpProgress(5, 3000), t.observe("mainnet", 5))
        assertNull(t.observe("mainnet", 4))
        // The next one needs the entry gap again, and measures from its own start.
        assertNull(t.observe("mainnet", 20))
        assertEquals(CatchUpProgress(300, 300), t.observe("mainnet", 300))
    }

    @Test
    fun anUnknownStatusHoldsTheProgress() {
        val t = LogIndexCatchUp()
        t.observe("mainnet", 40_000)
        val p = t.observe("mainnet", 16_000)
        assertEquals(p, t.observe("mainnet", null))
        assertEquals(CatchUpProgress(15_000, 40_000), t.observe("mainnet", 15_000))
        // Unknown before any catch-up stays nothing.
        assertNull(t.observe("gnosis", null))
    }

    @Test
    fun everyNetworkIsTrackedOnEverySnapshot() {
        val t = LogIndexCatchUp()
        t.observeAll(mapOf("mainnet" to status(3200), "gnosis" to status(0)))
        // The user is looking at gnosis while mainnet catches up and a new gap opens.
        t.observeAll(mapOf("mainnet" to status(0), "gnosis" to status(0)))
        val now = t.observeAll(mapOf("mainnet" to status(300), "gnosis" to status(0)))
        assertEquals(mapOf("mainnet" to CatchUpProgress(300, 300)), now)
    }

    @Test
    fun aNetworkThatStopsIsForgotten() {
        val t = LogIndexCatchUp()
        t.observeAll(mapOf("mainnet" to status(3200)))
        t.observeAll(emptyMap())
        assertEquals(
            mapOf("mainnet" to CatchUpProgress(100, 100)),
            t.observeAll(mapOf("mainnet" to status(100))),
        )
    }

    @Test
    fun labelSaysHowFarBehindAndHowMuchIsDone() {
        assertEquals(
            "Log index catching up to the head — 3,270 blocks behind",
            LogIndexStatus.catchUpLine(CatchUpProgress(3270, 3270)),
        )
        assertEquals(
            "Log index catching up to the head — 800 blocks behind (75% of 3,200)",
            LogIndexStatus.catchUpLine(CatchUpProgress(800, 3200)),
        )
    }

    @Test
    fun pastTheBridgeLimitItSaysItIsNotCatchingUp() {
        val p = CatchUpProgress(600_000, 600_000)
        assertTrue(p.stalled)
        assertFalse(CatchUpProgress(LogIndexStatus.BRIDGE_MAX_GAP, 600_000).stalled)
        assertEquals(
            "Log index 600,000 blocks behind the head — too far to bridge, not catching up",
            LogIndexStatus.catchUpLine(p),
        )
    }
}
