package io.myotis.ui

import io.myotis.logindex.LogIndexDownloads
import io.myotis.logindex.LogIndexPresets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Index tab's preset copy, the metered setting's push and its status keys. */
class LogIndexPresetTextTest {

    @Test
    fun `a preset row names its contracts, start and both costs`() {
        val p = LogIndexPresets.byId("railgun-mainnet")!!
        val line = LogIndexPresetText.presetLine(p, LogIndexDownloads.estimate(listOf(p)))
        assertTrue(line, line.startsWith("1 contract · from block 14,737,691 · ~"))
        assertTrue(line, line.contains(" download · ~") && line.endsWith(" on disk"))
    }

    @Test
    fun `the totals say what is downloaded and what is kept`() {
        val e = LogIndexDownloads.estimate(LogIndexPresets.forNetwork("sepolia"))
        val lines = LogIndexPresetText.totalLines(e)!!
        assertTrue(lines[0], lines[0].startsWith("Download: ~"))
        assertTrue(lines[1], lines[1].startsWith("Stored on this device: ~"))
        assertTrue(lines[1], lines[1].contains(LogIndexDownloads.formatBytes(e.peakDiskBytes)))
        assertNull(LogIndexPresetText.totalLines(LogIndexDownloads.estimate(emptyList())))
    }

    @Test
    fun `together is said only when it saves something`() {
        val mainnet = LogIndexPresets.forNetwork("mainnet")
        assertNotNull(LogIndexPresetText.togetherLine(LogIndexDownloads.estimate(mainnet)))
        assertNull(LogIndexPresetText.togetherLine(LogIndexDownloads.estimate(mainnet.take(1))))
        val advice = LogIndexPresetText.adviceLine(mainnet.take(1), mainnet, null)!!
        assertTrue(advice, advice.contains("all ${mainnet.size} together"))
        assertNull(LogIndexPresetText.adviceLine(mainnet, mainnet, null))
    }

    @Test
    fun `the metered line follows the setting and the host's report`() {
        assertTrue(LogIndexPresetText.meteredLine(true, "METERED").contains("also run on metered"))
        assertTrue(LogIndexPresetText.meteredLine(false, "METERED").contains("waits until"))
        assertTrue(LogIndexPresetText.meteredLine(false, "UNMETERED").startsWith("Unmetered only:"))
        assertTrue(LogIndexPresetText.meteredLine(false, null).contains("never held here"))
    }

    @Test
    fun `a preset whose contracts are all listed is no longer addable`() {
        val sw = LogIndexPresets.byId("swarm-gnosis")!!
        val all = sw.contracts.mapTo(HashSet()) { it.address.lowercase() }
        assertTrue(LogIndexPresetText.addable("gnosis", all).isEmpty())
        assertEquals(listOf(sw), LogIndexPresetText.addable("gnosis", all - all.first()))
    }

    @Test
    fun `allowMetered rides the push only when on`() {
        val watch = """[{"address":"0x1111111111111111111111111111111111111111","fromBlock":5}]"""
        val off = LogIndexWatch.configJson(watch, enabled = true)!!
        assertFalse(off, off.contains("allowMetered"))
        val on = LogIndexWatch.configJson(watch, enabled = true, allowMetered = true)!!
        assertTrue(on, on.contains(""""backfillPaused":false,"allowMetered":true,"watch":["""))
    }

    @Test
    fun `the status parse reads the metered hold and says the walk waits`() {
        val held = """{"enabled":true,"logCount":3,"backfillCursor":900,"maxSpeed":false,""" +
            """"backfillPaused":false,"allowMetered":false,"meteredHold":true,"targetLow":100,""" +
            """"blocksRemaining":800,"entries":[]}"""
        val p = LogIndexStatus.parse(held)
        assertTrue(p.meteredHold)
        assertFalse(p.allowMetered)
        val line = LogIndexStatus.progressLine(p)!!
        assertTrue(line, line.startsWith("backfill waiting for an unmetered network — 800 blocks"))
        // An engine before ABI 56 sends neither key: no hold.
        assertFalse(LogIndexStatus.parse(held.replace(""""allowMetered":false,"meteredHold":true,""", "")).meteredHold)
    }
}
