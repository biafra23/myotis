package io.myotis.logindex

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class LogIndexPresetsTest {

    private val hex = Regex("^0x[0-9a-fA-F]{40}$")

    @Test
    fun `every preset is well formed`() {
        val ids = HashSet<String>()
        for (p in LogIndexPresets.ALL) {
            assertTrue(ids.add(p.id), "duplicate id ${p.id}")
            assertNotNull(LogIndexPresets.chainCost(p.network), "no chain cost for ${p.network}")
            assertTrue(p.contracts.isNotEmpty(), p.id)
            val seen = HashSet<String>()
            for (c in p.contracts) {
                assertTrue(hex.matches(c.address), "${p.id}: ${c.address}")
                assertTrue(seen.add(c.address.lowercase()), "${p.id}: ${c.address} twice")
                assertTrue(c.fromBlock > 0, "${p.id}: ${c.address}")
                assertTrue(c.fromBlock <= p.census.atBlock, "${p.id}: ${c.address} created after its census")
            }
            assertTrue(p.census.candidateShare in 0.0..1.0, p.id)
            assertTrue(p.census.logs > 0 && p.census.bytesPerLog > 0, p.id)
        }
    }

    @Test
    fun `the four protocols are covered where they are deployed`() {
        val by = LogIndexPresets.ALL.groupBy { it.protocol }
        assertEquals(setOf("mainnet", "sepolia"), by.getValue(LogIndexPresets.Protocol.RAILGUN).map { it.network }.toSet())
        assertEquals(setOf("gnosis"), by.getValue(LogIndexPresets.Protocol.SWARM).map { it.network }.toSet())
        assertEquals(setOf("mainnet", "sepolia"), by.getValue(LogIndexPresets.Protocol.PRIVACY_POOLS).map { it.network }.toSet())
        assertEquals(setOf("mainnet", "sepolia"), by.getValue(LogIndexPresets.Protocol.TORNADO_CASH).map { it.network }.toSet())
        assertTrue(LogIndexPresets.forNetwork("holesky").isEmpty())
    }

    // The from-blocks are a trust assertion: these pin the ones other parts of the
    // repo also depend on, so a drift between them fails here.
    @Test
    fun `pinned from-blocks agree with the seeds and the guides`() {
        fun from(id: String, addr: String) =
            LogIndexPresets.byId(id)!!.contracts.single { it.address.equals(addr, ignoreCase = true) }.fromBlock
        // docs/guides/railgun-poc.md: the proxy's first log, not its creation block.
        assertEquals(14_737_691, from("railgun-mainnet", "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"))
        assertEquals(5_784_774, from("railgun-sepolia", "0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea"))
        // docs/guides/bee-rpc-service.md and the Bee seed's watch entry.
        assertEquals(31_305_656, from("swarm-gnosis", "0x45a1502382541cd610cc9068e88727426b696293"))
        // kohaku's deployment blocks where they are the chain's.
        assertEquals(22_153_713, from("privacy-pools-mainnet", "0x6818809eefce719e480a7526d76bd3e561526b46"))
        assertEquals(14_173_395, from("tornado-cash-mainnet", "0xb20c66c4de72433f3ce747b58b86830c459ca911"))
    }

    @Test
    fun `an estimate grows with the head and stores only logs`() {
        val rg = LogIndexPresets.byId("railgun-sepolia")!!
        val now = LogIndexDownloads.estimate(listOf(rg))
        val later = LogIndexDownloads.estimate(listOf(rg), rg.census.atBlock + 1_000_000)
        assertEquals(rg.census.atBlock, now.headBlock)
        assertEquals(rg.census.atBlock - rg.fromBlock + 1, now.blocksToWalk)
        assertEquals(rg.census.logs, now.logs)
        assertEquals(rg.census.logs * rg.census.bytesPerLog, now.storageBytes)
        assertEquals(2 * now.storageBytes, now.peakDiskBytes)
        assertTrue(later.downloadBytes > now.downloadBytes)
        assertTrue(later.logs > now.logs)
        // Headers alone are a floor: every walked block costs one.
        assertTrue(now.downloadBytes >= now.blocksToWalk * 600)
        // A single preset has nothing to save by being added with others.
        assertEquals(now.downloadBytes, now.separateDownloadBytes)
        assertFalse(now.cheaperTogether)
    }

    @Test
    fun `adding presets together is cheaper than one at a time, and it says so`() {
        val mainnet = LogIndexPresets.forNetwork("mainnet")
        val all = LogIndexDownloads.estimate(mainnet)
        assertTrue(all.separateDownloadBytes > all.downloadBytes)
        assertTrue(all.cheaperTogether, "headers are shared at the least")
        // Never more than the sum of its parts, never less than its largest part.
        val parts = mainnet.map { LogIndexDownloads.estimate(listOf(it), all.headBlock).downloadBytes }
        assertTrue(all.downloadBytes <= parts.sum())
        assertTrue(all.downloadBytes >= parts.max())
        assertEquals(parts.sum(), all.separateDownloadBytes)
    }

    @Test
    fun `together advice appears only when the user leaves some out`() {
        val mainnet = LogIndexPresets.forNetwork("mainnet")
        assertNull(LogIndexDownloads.togetherAdvice(mainnet, mainnet), "everything selected: nothing to add")
        assertNull(LogIndexDownloads.togetherAdvice(emptyList(), mainnet))
        val advice = LogIndexDownloads.togetherAdvice(mainnet.take(1), mainnet)
        assertNotNull(advice)
        assertEquals(mainnet.map { it.id }, advice!!.presetIds)
    }

    @Test
    fun `presets from two networks cannot share a walk`() {
        assertThrows<IllegalArgumentException> {
            LogIndexDownloads.estimate(listOf(LogIndexPresets.byId("railgun-mainnet")!!, LogIndexPresets.byId("swarm-gnosis")!!))
        }
        val empty = LogIndexDownloads.estimate(emptyList())
        assertEquals(0, empty.downloadBytes)
    }

    @Test
    fun `watch entries dedupe, keep the lowest from-block and skip what is watched`() {
        val tc = LogIndexPresets.byId("tornado-cash-sepolia")!!
        val entries = LogIndexDownloads.watchEntries(listOf(tc, tc), setOf(tc.contracts[0].address.uppercase()))
        assertEquals(tc.contracts.size - 1, entries.size)
        assertTrue(entries.none { it.address.equals(tc.contracts[0].address, ignoreCase = true) })
    }

    @Test
    fun `the config push is the engine's shape, unmetered only by default`() {
        val rg = LogIndexPresets.byId("railgun-sepolia")!!
        assertEquals(
            """{"enabled":true,"maxSpeed":false,"backfillPaused":false,"allowMetered":false,""" +
                """"watch":[{"address":"0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea","fromBlock":5784774}]}""",
            LogIndexDownloads.configJson(listOf(rg)),
        )
        val extra = LogIndexPresets.Contract("0x1111111111111111111111111111111111111111", 7, "mine")
        val json = LogIndexDownloads.configJson(listOf(rg), allowMetered = true, extraWatch = listOf(extra))
        assertTrue(json.contains("\"allowMetered\":true"), json)
        assertTrue(json.contains("""{"address":"0x1111111111111111111111111111111111111111","fromBlock":7}"""), json)
    }

    @Test
    fun `bytes format in decimal units`() {
        assertEquals("0 B", LogIndexDownloads.formatBytes(0))
        assertEquals("999 B", LogIndexDownloads.formatBytes(999))
        assertEquals("1.5 KB", LogIndexDownloads.formatBytes(1_500))
        assertEquals("12.4 MB", LogIndexDownloads.formatBytes(12_400_000))
        assertEquals("250 GB", LogIndexDownloads.formatBytes(250_000_000_000))
        assertEquals("1.2 TB", LogIndexDownloads.formatBytes(1_200_000_000_000))
        // Rounding up across a unit boundary moves to the next unit.
        assertEquals("1.0 GB", LogIndexDownloads.formatBytes(999_950_000))
        assertEquals("999 MB", LogIndexDownloads.formatBytes(999_400_000))
    }
}
