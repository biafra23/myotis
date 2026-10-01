package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The top bar's log-index head catch-up: when it counts as catching up, and
 *  how the instantaneous `headGap` becomes progress. */
class LogIndexCatchUpTest {

    private fun status(gap: Long?, enabled: Boolean = true) =
        "{\"enabled\":$enabled,\"logCount\":426000,\"maxSpeed\":false,\"backfillPaused\":true," +
            "\"targetLow\":14737691,\"blocksRemaining\":0" +
            (gap?.let { ",\"headGap\":$it" } ?: "") +
            ",\"entries\":[]}"

    @Test
    fun gapBeyondTheServingSlackIsACatchUp() {
        assertEquals(3270L, LogIndexStatus.headCatchUpGap(status(3270)))
        // 5 is the first gap the engine refuses head-reaching queries at.
        assertEquals(5L, LogIndexStatus.headCatchUpGap(status(5)))
    }

    @Test
    fun noCatchUpWithinTheSlackOrWithoutAnIndex() {
        assertNull(LogIndexStatus.headCatchUpGap(status(4)))
        assertNull(LogIndexStatus.headCatchUpGap(status(0)))
        assertNull(LogIndexStatus.headCatchUpGap(status(null)))
        assertNull(LogIndexStatus.headCatchUpGap(status(3270, enabled = false)))
        assertNull(LogIndexStatus.headCatchUpGap(null))
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
    fun aClosedGapEndsTheCatchUpAndTheNextStartsFresh() {
        val t = LogIndexCatchUp()
        t.observe("mainnet", 3000)
        assertNull(t.observe("mainnet", null))
        assertEquals(CatchUpProgress(40, 40), t.observe("mainnet", 40))
    }

    @Test
    fun networksAreTrackedSeparately() {
        val t = LogIndexCatchUp()
        t.observe("mainnet", 3000)
        assertEquals(CatchUpProgress(50, 50), t.observe("gnosis", 50))
        assertEquals(CatchUpProgress(1500, 3000), t.observe("mainnet", 1500))
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
}
