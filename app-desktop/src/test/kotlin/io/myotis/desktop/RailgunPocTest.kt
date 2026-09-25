package io.myotis.desktop

import io.myotis.api.NetworkInfo
import io.myotis.ui.LogIndexWatch
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * The RAILGUN PoC flavour: the things that differ from the Bee one and would each ship a
 * quietly broken demo if they drifted — the mainnet seed FILENAME (no network suffix, or
 * the engine never opens it), the watch entry's deployment block (too low turns real
 * history into empty answers), which network a first start boots, and the rule that the
 * two flavours never both claim a process.
 *
 * The shared install/re-seed/checksum machinery is covered by [BeePocTest]; only one
 * install case is repeated here, to prove this flavour's own names are wired through it.
 */
class RailgunPocTest {

    private val nets = listOf(
        NetworkInfo("mainnet", "Ethereum Mainnet", 1, true, 30303, 9000, 8545, 1606824023, 12),
        NetworkInfo("gnosis", "Gnosis Chain", 100, false, 30303, 9000, 8546, 1638993340, 5),
    )

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun stageBundle(dir: Path, seed: ByteArray, high: Long = 26_029_586): Path {
        val res = dir.resolve("resources-$high")
        Files.createDirectories(res)
        Files.write(res.resolve(RailgunPoc.seedFile), seed)
        Files.writeString(
            res.resolve(RailgunPoc.manifestFile),
            """
            network=mainnet
            address=$RAILGUN_PROXY
            coveredLow=$RAILGUN_PROXY_DEPLOYED
            coveredHigh=$high
            usableUntilBlock=${high + 500_000}
            logs=426563
            sha256=${sha256(seed)}
            """.trimIndent(),
        )
        return res
    }

    @Test
    fun `the seed filename is mainnet's, which carries no network suffix`() {
        // The engine derives dataDir/logindex.db for mainnet and logindex-<net>.db for the
        // rest (rust/myotis-engine/src/host.rs, log_index_path). A suffixed name here would
        // stage, install and checksum fine, and then never be opened — a "slow first start"
        // that never ends.
        assertEquals("logindex.db", RailgunPoc.seedFile)
        assertNotEquals(BeePoc.seedFile, RailgunPoc.seedFile)
        // The two flavours must also not share the data-dir manifest name, or one would
        // read the other's installed version when both have been run on a machine.
        assertNotEquals(BeePoc.installedManifestFile, RailgunPoc.installedManifestFile)
        assertNotEquals(BeePoc.dataDirName, RailgunPoc.dataDirName)
    }

    @Test
    fun `the watch entry pins the proxy at its real deployment block`() {
        val entries = LogIndexWatch.parse(RailgunPoc.watchJson)
        assertEquals(1, entries.size, "one contract: the wallet reads only the proxy")
        assertEquals(RAILGUN_PROXY.lowercase(), entries[0].address.lowercase())
        // 14693013 circulates as "the RAILGUN deployment block" and is WRONG for a watch
        // floor: the chain's first log from this proxy is at 14737691. A floor below that
        // is safe but leaves the 44678 blocks between it and the seed's coverage refused as
        // out of coverage (and this flavour's backfill is paused, so they stay refused); a
        // floor above it would answer [] without consulting coverage and hide real history.
        assertEquals(14_737_691L, entries[0].fromBlock)
        assertNotEquals(14_693_013L, entries[0].fromBlock)
    }

    @Test
    fun `a first start boots mainnet with the index on, and leaves later starts alone`(@TempDir dir: Path) {
        val settings = DesktopSettings(file = dir.resolve("settings.properties"), networks = nets)
        RailgunPoc.applyFirstStartSettings(settings, firstStart = true)

        assertTrue(settings.isNetworkEnabled("mainnet"), "the wallet's network must be on")
        assertFalse(settings.isNetworkEnabled("gnosis"), "the other flavour's network must be off")
        assertTrue(settings.logIndexEnabled("mainnet"))
        assertEquals(RailgunPoc.watchJson, settings.logIndexWatchJson("mainnet"))
        assertTrue(settings.logIndexBackfillPaused("mainnet"), "decided, not left at a default")
        // NOT mainnet's default 8545: a regular install serves that port, and a wallet
        // aimed at it could silently reach an install with no seeded index.
        assertEquals(RAILGUN_RPC_PORT, settings.rpcPortFor("mainnet"))
        assertNotEquals(8545, settings.rpcPortFor("mainnet"))

        // A later start must never re-apply: that would push logIndex=false style resets
        // over whatever the user changed, and turning a seeded index off makes every query
        // a -32000.
        settings.setNetworkEnabled("gnosis", true)
        RailgunPoc.applyFirstStartSettings(settings, firstStart = false)
        assertTrue(settings.isNetworkEnabled("gnosis"), "a later start must not touch settings")
    }

    @Test
    fun `the bundled seed installs under this flavour's own names`(@TempDir dir: Path) {
        val seed = "MLIX-fake-railgun-seed".toByteArray()
        val res = stageBundle(dir, seed)
        val data = dir.resolve("data")

        assertEquals(SeedOutcome.INSTALLED, RailgunPoc.installSeedIfAbsent(res, data))
        assertTrue(Files.exists(data.resolve(RailgunPoc.seedFile)))
        assertTrue(Files.exists(data.resolve(RailgunPoc.installedManifestFile)))
        // ...and not under the Bee flavour's, which would leave both dead.
        assertFalse(Files.exists(data.resolve(BeePoc.seedFile)))

        val notice = RailgunPoc.seededIndexNotice(data, "mainnet")
        assertTrue(notice != null && notice.contains("426563"), "the notice states the seed size: $notice")
        assertTrue(notice!!.contains("unverified"), "the notice must not present RPC data as verified")
        assertNull(RailgunPoc.seededIndexNotice(data, "gnosis"), "other networks get no notice")
    }

    @Test
    fun `no flavour is active in a regular build, and two at once is refused`() {
        val bee = System.getProperty(BeePoc.PROP)
        val rail = System.getProperty(RailgunPoc.PROP)
        try {
            System.clearProperty(BeePoc.PROP)
            System.clearProperty(RailgunPoc.PROP)
            assertNull(Poc.active(), "a regular build carries neither property")

            System.setProperty(RailgunPoc.PROP, "true")
            assertEquals(RailgunPoc, Poc.active())
            assertTrue(RailgunPoc.backfillPausedDefault())
            assertFalse(BeePoc.backfillPausedDefault(), "the inactive flavour stays inert")

            // Both set is a packaging mistake: the flavours disagree about the network and
            // the data dir, so half-applying each is worse than failing at start.
            System.setProperty(BeePoc.PROP, "true")
            val thrown = runCatching { Poc.active() }.exceptionOrNull()
            assertTrue(thrown is IllegalArgumentException, "expected a refusal, got $thrown")
        } finally {
            if (bee == null) System.clearProperty(BeePoc.PROP) else System.setProperty(BeePoc.PROP, bee)
            if (rail == null) System.clearProperty(RailgunPoc.PROP) else System.setProperty(RailgunPoc.PROP, rail)
        }
    }
}
