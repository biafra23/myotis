package io.myotis.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The readiness ladder, rung by rung: the level each node state lands on, the
 * strip's screen-reader label (pinned byte-for-byte — these strings predate the
 * ladder and the strip must keep announcing them), and the bar values the status
 * card draws. Plus the vitals tiles' rules.
 */
class ReadinessTest {

    @Test
    fun offlineOutranksEverythingButASleepingStack() {
        val r = readinessOf(synced(), deepPoolThreshold = 1, online = false)
        assertEquals(ReadinessLevel.OFFLINE, r.level)
        assertEquals("Node readiness: offline — no internet connection", r.a11yLabel)
        assertEquals("No internet connection", r.headline)
        // Not running + offline: offline is why Start is refused, so it leads.
        assertEquals(ReadinessLevel.OFFLINE, readinessOf(null, 1, online = false).level)
        // Sleeping has networking off by design — nothing is failing, so grey holds.
        assertEquals(ReadinessLevel.SLEEPING, readinessOf(synced().copy(lifecycle = "PAUSED"), 1, online = false).level)
    }

    @Test
    fun onlineDefaultsToTrueSoTheStripIsUnchanged() {
        assertEquals(ReadinessLevel.FULLY_READY, readinessOf(synced(), 1).level)
    }

    @Test
    fun sleepingIsGreyAndNamesAnUpgradeIfPeersReportOne() {
        val r = readinessOf(synced().copy(lifecycle = "PAUSED"), 1)
        assertEquals(ReadinessLevel.SLEEPING, r.level)
        assertEquals("Node readiness: sleeping — a request wakes it", r.a11yLabel)
        val u = readinessOf(synced().copy(lifecycle = "PAUSED", upgrade = scheduledUpgrade()), 1)
        assertEquals(ReadinessLevel.SLEEPING, u.level)
        assertEquals(
            "Node readiness: sleeping — peers report a network upgrade this version doesn't support",
            u.a11yLabel,
        )
    }

    @Test
    fun noSnapshotOrNotRunningIsStopped() {
        assertEquals(ReadinessLevel.STOPPED, readinessOf(null, 1).level)
        val r = readinessOf(synced().copy(running = false, lifecycle = "STOPPED"), 1)
        assertEquals(ReadinessLevel.STOPPED, r.level)
        assertEquals("Node readiness: not running", r.a11yLabel)
        assertEquals("Not running", r.headline)
        // A registered handle that is not running is mid-boot or mid-teardown: the card
        // offers Stop then, so the detail must not ask for a Start.
        assertEquals("Starting or stopping — give it a moment.", r.detail)
        assertEquals(
            "Start the node to verify balances and answer wallet requests.",
            readinessOf(null, 1).detail,
        )
    }

    @Test
    fun anActiveUpgradeTheNodeCorroboratesOutranksTheStaleAnchor() {
        val r = readinessOf(
            synced().copy(beaconState = "STALE_ANCHOR", upgrade = scheduledUpgrade().copy(phase = "ACTIVE")),
            1,
        )
        assertEquals(ReadinessLevel.UPDATE_REQUIRED, r.level)
        assertEquals(
            "Node readiness: not verifying — peers report a network upgrade this version doesn't " +
                "support; update the app",
            r.a11yLabel,
        )
    }

    @Test
    fun anActiveUpgradeOnAFreshSyncedNodeIsNotACutOff() {
        val r = readinessOf(synced().copy(upgrade = scheduledUpgrade().copy(phase = "ACTIVE")), 1)
        assertEquals(ReadinessLevel.FULLY_READY, r.level)
    }

    @Test
    fun staleAnchorNeedsADecisionAndSaysHowOld() {
        val r = readinessOf(
            synced().copy(beaconState = "STALE_ANCHOR", syncCurrentPeriod = 1400, syncTargetPeriod = 1419, wsBoundPeriods = 13),
            1,
        )
        assertEquals(ReadinessLevel.NEEDS_DECISION, r.level)
        assertEquals("Node readiness: sync anchor too old — paused awaiting your consent", r.a11yLabel)
        assertEquals("Needs your decision", r.headline)
        assertTrue(r.detail, r.detail!!.contains("19 periods old"))
        assertTrue(r.detail, r.detail!!.contains("13-period"))
        // Android reports no bound: say how old, not "the 0-period bound".
        val unknownBound = readinessOf(
            synced().copy(beaconState = "STALE_ANCHOR", syncCurrentPeriod = 1400, syncTargetPeriod = 1419),
            1,
        )
        assertEquals(
            "The sync anchor is 19 periods old. Syncing is paused until you decide.",
            unknownBound.detail,
        )
    }

    @Test
    fun catchingUpWithKnownPeriodsHasADeterminateBar() {
        val r = readinessOf(
            synced().copy(beaconState = "CATCHING_UP", syncStartPeriod = 10, syncCurrentPeriod = 15, syncTargetPeriod = 20),
            1,
        )
        assertEquals(ReadinessLevel.SYNCING, r.level)
        assertEquals("Node readiness: not synced", r.a11yLabel)
        assertEquals("Syncing", r.headline)
        assertEquals(0.5f, r.progress!!, 0f)
        assertEquals(false, r.indeterminate)
        assertEquals("Catching up sync committees — period 15 of 20.", r.detail)
    }

    @Test
    fun bootstrappingIsIndeterminateAndMentionsTheHunt() {
        val r = readinessOf(synced().copy(beaconState = "SYNCING", syncStartPeriod = -1, lcHunting = true), 1)
        assertEquals(ReadinessLevel.SYNCING, r.level)
        assertNull(r.progress)
        assertTrue(r.indeterminate)
        assertEquals("Bootstrapping the light client… Looking for light-client servers…", r.detail)
        // Android reports STARTING as STOPPED while the stack already runs.
        assertEquals("Starting the light client…", readinessOf(synced().copy(beaconState = "STOPPED"), 1).detail)
    }

    @Test
    fun aStaleOrMissingHeadIsWarming() {
        val stale = readinessOf(synced().copy(verifiedHeadAgeMs = 120_000), 1)
        assertEquals(ReadinessLevel.WARMING, stale.level)
        assertEquals("Node readiness: warming up, not ready to transact", stale.a11yLabel)
        assertEquals("Almost ready", stale.headline)
        assertTrue(stale.detail, stale.detail!!.contains("2 min old"))
        val none = readinessOf(synced().copy(verifiedHeadAgeMs = Long.MAX_VALUE, elHunting = true), 1)
        assertEquals(ReadinessLevel.WARMING, none.level)
        assertTrue(none.detail, none.detail!!.startsWith("Synced. Waiting for the first verified head"))
        assertTrue(none.detail, none.detail!!.endsWith("Looking for snap peers…"))
    }

    @Test
    fun theIndexCatchUpSitsBetweenWarmingAndTheGreens() {
        val r = readinessOf(synced(), 1, CatchUpProgress(800, 3200))
        assertEquals(ReadinessLevel.INDEX_CATCHING_UP, r.level)
        assertEquals(
            "Node readiness: Log index catching up to the head — 800 blocks behind " +
                "(75% of 3,200); eth_getLogs near the head is refused until it has caught up",
            r.a11yLabel,
        )
        assertEquals(0.75f, r.progress!!, 0f)
        assertEquals("Ready — log index catching up", r.headline)
        // Warming outranks it; so does every red rung.
        assertEquals(ReadinessLevel.WARMING, readinessOf(synced().copy(verifiedHeadAgeMs = 120_000), 1, CatchUpProgress(800, 3200)).level)
        assertEquals(ReadinessLevel.SYNCING, readinessOf(synced().copy(beaconState = "CATCHING_UP"), 1, CatchUpProgress(800, 3200)).level)
    }

    @Test
    fun aStalledCatchUpPromisesNoProgress() {
        val r = readinessOf(synced(), 1, CatchUpProgress(600_000, 600_000))
        assertEquals(ReadinessLevel.INDEX_CATCHING_UP, r.level)
        assertNull(r.progress)
        assertEquals("Ready — log index too far behind", r.headline)
        assertEquals(
            "Node readiness: Log index 600,000 blocks behind the head — too far to bridge, " +
                "not catching up; eth_getLogs near the head is refused",
            r.a11yLabel,
        )
    }

    @Test
    fun theDeepPoolThresholdSplitsTheTwoGreens() {
        val full = readinessOf(synced(), deepPoolThreshold = 8)
        assertEquals(ReadinessLevel.FULLY_READY, full.level)
        assertEquals("Node readiness: fully ready — deep peer pool, heavy confirm screens will load", full.a11yLabel)
        assertEquals("Ready", full.headline)
        val thin = readinessOf(synced(), deepPoolThreshold = 9)
        assertEquals(ReadinessLevel.READY, thin.level)
        assertEquals(
            "Node readiness: ready for simple reads; peer pool still filling for heavy confirm screens",
            thin.a11yLabel,
        )
        assertEquals("Ready", thin.headline)
        assertTrue(thin.detail, thin.detail!!.contains("(8 of 9)"))
    }

    @Test
    fun colorsFollowTheLadder() {
        assertEquals(StatusColors.Grey, StatusColors.of(ReadinessLevel.SLEEPING))
        assertEquals(StatusColors.Red, StatusColors.of(ReadinessLevel.OFFLINE))
        assertEquals(StatusColors.Red, StatusColors.of(ReadinessLevel.SYNCING))
        assertEquals(StatusColors.Amber, StatusColors.of(ReadinessLevel.WARMING))
        assertEquals(StatusColors.Amber, StatusColors.of(ReadinessLevel.INDEX_CATCHING_UP))
        assertEquals(StatusColors.Green, StatusColors.of(ReadinessLevel.READY))
        assertEquals(StatusColors.BrightGreen, StatusColors.of(ReadinessLevel.FULLY_READY))
    }

    @Test
    fun formatAgeRoundsDown() {
        assertEquals("0 s", formatAge(900))
        assertEquals("4 s", formatAge(4_012))
        assertEquals("59 s", formatAge(59_999))
        assertEquals("2 min", formatAge(120_000))
        assertEquals("3 h", formatAge(3 * 3600_000L + 59_000))
    }

    // --- vitals ---

    @Test
    fun stoppedVitalsAreDashesWithoutAnIndexTile() {
        val v = vitalsOf(null, 16)
        assertEquals("—", v.el.value)
        assertEquals(Tone.NONE, v.el.tone)
        assertEquals(Tone.NONE, v.cl.tone)
        assertEquals(Tone.NONE, v.head.tone)
        assertNull(v.index)
        assertNull(vitalsOf(synced().copy(running = false), 16).index)
    }

    @Test
    fun sleepingVitalsSaySo() {
        val v = vitalsOf(synced().copy(lifecycle = "PAUSED"), 16)
        assertEquals("—", v.el.value)
        assertEquals("sleeping", v.el.detail)
        assertEquals(Tone.NONE, v.cl.tone)
        // iOS reports a paused stack with running=false: still sleeping, not stopped,
        // and the index tile stays (as the ladder does).
        val ios = vitalsOf(
            synced().copy(lifecycle = "PAUSED", running = false, logIndexJson = indexJson(headGap = 0, remaining = 0)),
            16,
        )
        assertEquals("sleeping", ios.head.detail)
        assertEquals("Up to date", ios.index!!.value)
        assertEquals(ReadinessLevel.SLEEPING, readinessOf(synced().copy(lifecycle = "PAUSED", running = false), 1).level)
    }

    @Test
    fun executionPeersCountTheServingOnes() {
        val v = vitalsOf(synced().copy(readyPeers = 18, snapServingPeers = 12), 16)
        assertEquals("Execution peers", v.el.label)
        assertEquals("12 usable", v.el.value)
        assertEquals("of 18 connected", v.el.detail)
        assertEquals(Tone.OK, v.el.tone)
        assertEquals(Tone.GREAT, vitalsOf(synced().copy(snapServingPeers = 16), 16).el.tone)
        val none = vitalsOf(synced().copy(snapServingPeers = 0, elHunting = true), 16).el
        assertEquals(Tone.BAD, none.tone)
        assertEquals("of 8 connected · looking for more", none.detail)
    }

    @Test
    fun consensusFollowsTheBeaconState() {
        val v = vitalsOf(synced(), 16).cl
        assertEquals("Consensus", v.label)
        assertEquals("Synced", v.value)
        assertEquals("3 servers answering", v.detail)
        assertEquals(Tone.OK, v.tone)
        val one = vitalsOf(synced().copy(beaconState = "CATCHING_UP", clServedPeersLastMin = 1, lcHunting = true), 16).cl
        assertEquals("Catching up", one.value)
        assertEquals("1 server answering · looking for more", one.detail)
        assertEquals(Tone.WAIT, one.tone)
        assertEquals("Starting", vitalsOf(synced().copy(beaconState = "SYNCING"), 16).cl.value)
        assertEquals("Starting", vitalsOf(synced().copy(beaconState = "STOPPED"), 16).cl.value)
        val parked = vitalsOf(synced().copy(beaconState = "STALE_ANCHOR"), 16).cl
        assertEquals("Paused", parked.value)
        assertEquals(Tone.BAD, parked.tone)
    }

    @Test
    fun theHeadTileIsTheAgeWithAFreshnessWord() {
        val fresh = vitalsOf(synced().copy(verifiedHeadAgeMs = 4_012), 16).head
        assertEquals("Verified head", fresh.label)
        assertEquals("4 s", fresh.value)
        assertEquals("fresh", fresh.detail)
        assertEquals(Tone.OK, fresh.tone)
        val stale = vitalsOf(synced().copy(verifiedHeadAgeMs = 72_000), 16).head
        assertEquals("1 min", stale.value)
        assertEquals(Tone.WAIT, stale.tone)
        val none = vitalsOf(synced().copy(verifiedHeadAgeMs = Long.MAX_VALUE), 16).head
        assertEquals("None yet", none.value)
        assertEquals(Tone.WAIT, none.tone)
        val unsynced = vitalsOf(synced().copy(beaconState = "CATCHING_UP"), 16).head
        assertEquals("—", unsynced.value)
        assertEquals("waiting for sync", unsynced.detail)
        assertEquals(Tone.NONE, unsynced.tone)
        val parked = vitalsOf(synced().copy(beaconState = "STALE_ANCHOR"), 16).head
        assertEquals("paused — needs your decision", parked.detail)
    }

    @Test
    fun theIndexTileAppearsOnlyForAnEnabledIndex() {
        assertNull(vitalsOf(synced(), 16).index)
        assertNull(vitalsOf(synced().copy(logIndexJson = "{\"enabled\":false,\"logCount\":0,\"entries\":[]}"), 16).index)
        assertNull(vitalsOf(synced().copy(logIndexJson = "{\"error\":\"paused\"}"), 16).index)
        val v = vitalsOf(synced().copy(logIndexJson = indexJson(headGap = 2, remaining = 0)), 16).index!!
        assertEquals("Log index", v.label)
        assertEquals("Up to date", v.value)
    }

    @Test
    fun theIndexToneFollowsTheHeadSideOnly() {
        val atSlack = vitalsOf(synced().copy(logIndexJson = indexJson(headGap = 4, remaining = 0)), 16).index!!
        assertEquals(Tone.OK, atSlack.tone)
        assertEquals("history complete", atSlack.detail)
        // Past the serving slack but short of a catch-up (LogIndexCatchUp enters at 32):
        // the strip stays green by its hysteresis, so does the tile — naming the gap.
        val trailing = vitalsOf(synced().copy(logIndexJson = indexJson(headGap = 5, remaining = 0)), 16).index!!
        assertEquals("Trailing", trailing.value)
        assertEquals(Tone.OK, trailing.tone)
        assertEquals("5 blocks behind the head — queries at the very head wait · history complete", trailing.detail)
        // The same gap inside a tracked catch-up is the ladder's amber rung.
        val behind = vitalsOf(synced().copy(logIndexJson = indexJson(headGap = 5, remaining = 0)), 16, CatchUpProgress(5, 40)).index!!
        assertEquals("Behind head", behind.value)
        assertEquals(Tone.WAIT, behind.tone)
        assertEquals("5 blocks behind the head · history complete", behind.detail)
        // An incomplete backfill is an indication, never a tone change.
        val backfilling = vitalsOf(synced().copy(logIndexJson = indexJson(headGap = 0, remaining = 1_200_000)), 16).index!!
        assertEquals(Tone.OK, backfilling.tone)
        assertEquals("Up to date", backfilling.value)
        assertTrue(backfilling.detail, backfilling.detail!!.startsWith("history incomplete · "))
        val paused = vitalsOf(synced().copy(logIndexJson = indexJson(headGap = 0, remaining = 500, paused = true)), 16).index!!
        assertEquals(Tone.OK, paused.tone)
        assertEquals("history paused · 500 blocks unindexed", paused.detail)
        val stalled = vitalsOf(
            synced().copy(logIndexJson = indexJson(headGap = 600_000, remaining = 0)), 16, CatchUpProgress(600_000, 600_000),
        ).index!!
        assertEquals("Too far behind", stalled.value)
        assertEquals(Tone.WAIT, stalled.tone)
        assertEquals("600,000 blocks behind the head, not catching up · history complete", stalled.detail)
    }

    @Test
    fun anIndexThatHasCoveredNothingIsNotUpToDate() {
        val empty = vitalsOf(synced().copy(logIndexJson = "{\"enabled\":true,\"logCount\":0,\"entries\":[]}"), 16).index!!
        assertEquals("Nothing watched", empty.value)
        assertEquals(Tone.NONE, empty.tone)
        assertEquals("no contracts watched", empty.detail)
        val unseeded = "{\"enabled\":true,\"logCount\":0,\"maxSpeed\":false,\"backfillPaused\":false," +
            "\"entries\":[{\"address\":\"0x1111111111111111111111111111111111111111\",\"fromBlock\":5}]}"
        val v = vitalsOf(synced().copy(logIndexJson = unseeded), 16).index!!
        assertEquals("Starting", v.value)
        assertEquals(Tone.WAIT, v.tone)
        assertEquals("no blocks covered yet", v.detail)
    }

    @Test
    fun anEnabledIndexWithoutAHeadYetIsStarting() {
        val json = "{\"enabled\":true,\"logCount\":0,\"maxSpeed\":false,\"backfillPaused\":false," +
            "\"entries\":[{\"address\":\"0x1111111111111111111111111111111111111111\",\"fromBlock\":5," +
            "\"coveredLow\":5,\"coveredHigh\":9}]}"
        val v = vitalsOf(synced().copy(logIndexJson = json), 16).index!!
        assertEquals("Starting", v.value)
        assertEquals(Tone.WAIT, v.tone)
    }

    private fun indexJson(headGap: Long, remaining: Long, paused: Boolean = false): String =
        "{\"enabled\":true,\"logCount\":12,\"maxSpeed\":false,\"backfillPaused\":$paused," +
            "\"targetLow\":100,\"blocksRemaining\":$remaining,\"headGap\":$headGap," +
            "\"entries\":[{\"address\":\"0x1111111111111111111111111111111111111111\",\"fromBlock\":100," +
            "\"coveredLow\":${100 + remaining},\"coveredHigh\":9000}]}"

    private fun scheduledUpgrade() =
        UpgradeNotice(phase = "SCHEDULED", activationEpochSec = 1_800_000_000, forkId = "0x12345678", observedPeers = 3)

    private fun synced() = NodeSnapshot(
        running = true, lifecycle = "RUNNING", network = "mainnet", engine = "rust",
        beaconState = "SYNCED", connectedPeers = 17, readyPeers = 8, snapPeers = 8,
        snapServingPeers = 8, snap2ServingPeers = 0, clConnectedPeers = 0, clServedPeersLastMin = 3,
        clCachedPeers = 10, clCachedProven = 5, clCachedNolc = 1, elCachedPeers = 20,
        elCachedSnapOk = 8, elCachedSnapBad = 2, discoveredPeers = 137, backedOffPeers = 0,
        blacklistedPeers = 0, discv5Peers = 100, executionBlockNumber = 26_097_901,
        finalizedSlot = 1, syncStartPeriod = -1, syncCurrentPeriod = 0, syncTargetPeriod = 0,
        verifiedHeadAgeMs = 1_000, uptimeSeconds = 60, peerHeaderRequests = 0,
        peerHeaderRequestsServed = 0, peerBodyRequests = 0, peerBodyRequestsServed = 0,
        readyPeerList = emptyList(), pauseCount = 0, totalPausedMs = 0,
        lastPauseEpochMs = 0, lastResumeEpochMs = 0, lastWakeReason = null,
    )
}
