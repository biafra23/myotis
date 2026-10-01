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
 * quietly broken demo if they drifted — each seed's FILENAME (mainnet's carries no network
 * suffix, or the engine never opens it), each watch entry's deployment block (too high
 * turns real history into empty answers), which networks a first start boots and on which
 * ports, how an install that predates a network's seed picks it up, and the rule that the
 * two flavours never both claim a process.
 *
 * The shared install/re-seed/checksum machinery is covered by [BeePocTest]; only the
 * install itself is repeated here, to prove this flavour's own names are wired through it.
 */
class RailgunPocTest {

    private val nets = listOf(
        NetworkInfo("mainnet", "Ethereum Mainnet", 1, true, 30303, 9000, 8545, 1606824023, 12),
        NetworkInfo("gnosis", "Gnosis Chain", 100, false, 30304, 9001, 8546, 1638993340, 5),
        NetworkInfo("sepolia", "Sepolia", 11155111, true, 30305, 9002, 8547, 1655733600, 12),
    )

    private val mainnet = RailgunPoc.seedFor("mainnet")!!
    private val sepolia = RailgunPoc.seedFor("sepolia")!!

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Stage [seed]'s bundled index and manifest into [res], as the build does. */
    private fun stage(res: Path, seed: PocSeed, bytes: ByteArray, low: Long, high: Long, logs: Int) {
        Files.createDirectories(res)
        Files.write(res.resolve(seed.seedFile), bytes)
        Files.writeString(
            res.resolve(seed.manifestFile),
            """
            network=${seed.network}
            address=${seed.watchAddress}
            coveredLow=$low
            coveredHigh=$high
            usableUntilBlock=${high + 500_000}
            logs=$logs
            sha256=${sha256(bytes)}
            """.trimIndent(),
        )
    }

    @Test
    fun `the flavour seeds mainnet first, then sepolia`() {
        assertEquals(listOf("mainnet", "sepolia"), RailgunPoc.seeds.map { it.network })
        assertEquals("mainnet", RailgunPoc.primaryNetwork)
        assertNull(RailgunPoc.seedFor("gnosis"))
    }

    @Test
    fun `the seed filenames are the engine's own, which only mainnet's lacks a suffix for`() {
        // The engine derives dataDir/logindex.db for mainnet and logindex-<net>.db for the
        // rest (rust/myotis-engine/src/host.rs, log_index_path). A wrong name here would
        // stage, install and checksum fine, and then never be opened — a "slow first start"
        // that never ends.
        assertEquals("logindex.db", mainnet.seedFile)
        assertEquals("logindex-sepolia.db", sepolia.seedFile)
        // No two seeds of either flavour may share a data-dir or bundle name, or one would
        // overwrite or read the other's — the flavours' data dirs differ, but a machine
        // that has run both still has both dirs, and the bundle holds both RAILGUN seeds.
        val all = BeePoc.seeds + RailgunPoc.seeds
        for (names in listOf(all.map { it.seedFile }, all.map { it.manifestFile }, all.map { it.installedManifestFile })) {
            assertEquals(names.size, names.toSet().size, "names must be distinct: $names")
        }
        assertNotEquals(BeePoc.dataDirName, RailgunPoc.dataDirName)
    }

    @Test
    fun `each watch entry pins its proxy at its real deployment block`() {
        val main = LogIndexWatch.parse(mainnet.watchJson)
        assertEquals(1, main.size, "one contract: the wallet reads only the proxy")
        assertEquals(RAILGUN_PROXY.lowercase(), main[0].address.lowercase())
        // 14693013 circulates as "the RAILGUN deployment block" and is WRONG for a watch
        // floor: the chain's first log from this proxy is at 14737691. A floor below that
        // is safe but leaves the 44678 blocks between it and the seed's coverage refused as
        // out of coverage (and this flavour's backfill is paused, so they stay refused); a
        // floor above it would answer [] without consulting coverage and hide real history.
        assertEquals(14_737_691L, main[0].fromBlock)
        assertNotEquals(14_693_013L, main[0].fromBlock)

        val sep = LogIndexWatch.parse(sepolia.watchJson)
        assertEquals(1, sep.size, "one contract on Sepolia too")
        assertEquals(RAILGUN_SEPOLIA_PROXY.lowercase(), sep[0].address.lowercase())
        // The proxy's creation block. The SDK's 5784866 is where the wallet starts scanning,
        // ABOVE the 62 logs of the deployment's setup — as a floor it would assert they do
        // not exist, which is the direction that hides real history.
        assertEquals(5_784_774L, sep[0].fromBlock)
        assertNotEquals(5_784_866L, sep[0].fromBlock)
    }

    /**
     * Each seed's watch entry and names are written out three times: in the flavour (the
     * watch entry a first start pushes), in `build.gradle.kts` (what the bundled frame is
     * built with) and in railgun-dmg.yml (what CI requires of the built dmg). A correction
     * made in one place only would leave the frame and the pushed entry disagreeing — and
     * the engine merges the two with the LOWER from_block, silently — so pin the copies to
     * each other here, where a mismatch fails a unit test instead of a demo.
     */
    @Test
    fun `the build and the dmg workflow name each seed exactly as the flavour does`() {
        val build = Files.readString(repoFile("app-desktop/build.gradle.kts"))
        for (seed in BeePoc.seeds + RailgunPoc.seeds) {
            val watch = "\"${seed.watchAddress}:${seed.watchDeployBlock}\""
            assertTrue(build.contains(watch), "build.gradle.kts must frame the ${seed.network} seed with $watch")
            assertTrue(build.contains("\"${seed.seedFile}\""), "build.gradle.kts must stage ${seed.seedFile}")
            assertTrue(build.contains("\"${seed.manifestFile}\""), "build.gradle.kts must stage ${seed.manifestFile}")
        }
        val workflow = Files.readString(repoFile(".github/workflows/railgun-dmg.yml"))
        for (seed in RailgunPoc.seeds) {
            for (needle in listOf(
                "-name '${seed.seedFile}'",
                "-name '${seed.manifestFile}'",
                "grep -qx 'network=${seed.network}'",
                "grep -qx 'deploymentBlock=${seed.watchDeployBlock}'",
                "grep -qx 'coveredLow=${seed.watchDeployBlock}'",
            )) {
                assertTrue(workflow.contains(needle), "railgun-dmg.yml must assert $needle on the built dmg")
            }
        }
    }

    /** [rel] from the repository root, whether the test runs in the module dir (Gradle) or the root. */
    private fun repoFile(rel: String): Path {
        var dir: Path? = Path.of(System.getProperty("user.dir")).toAbsolutePath()
        while (dir != null) {
            dir.resolve(rel).takeIf { Files.isRegularFile(it) }?.let { return it }
            dir = dir.parent
        }
        error("$rel not found above ${System.getProperty("user.dir")}")
    }

    @Test
    fun `a first start boots mainnet and sepolia with the index on, and leaves later starts alone`(@TempDir dir: Path) {
        val settings = DesktopSettings(file = dir.resolve("settings.properties"), networks = nets)
        RailgunPoc.applyFirstStartSettings(settings, firstStart = true)

        assertEquals(listOf("mainnet", "sepolia"), settings.enabledNetworks(), "both wallet networks, mainnet first")
        assertEquals("mainnet", settings.primaryNetwork())
        for (seed in RailgunPoc.seeds) {
            assertTrue(settings.logIndexEnabled(seed.network), seed.network)
            assertEquals(seed.watchJson, settings.logIndexWatchJson(seed.network))
            assertTrue(settings.logIndexBackfillPaused(seed.network), "decided, not left at a default")
        }
        // NOT the defaults 8545/8547: a regular install serves those, and a wallet aimed at
        // them could silently reach an install with no seeded index.
        assertEquals(RAILGUN_RPC_PORT, settings.rpcPortFor("mainnet"))
        assertEquals(RAILGUN_SEPOLIA_RPC_PORT, settings.rpcPortFor("sepolia"))
        assertNotEquals(8545, settings.rpcPortFor("mainnet"))
        assertNotEquals(8547, settings.rpcPortFor("sepolia"))
        assertEquals(setOf("mainnet", "sepolia"), settings.pocConfiguredNetworks())

        // A later start must never re-apply: that would push logIndex=false style resets
        // over whatever the user changed, and turning a seeded index off makes every query
        // a -32000.
        settings.setNetworkEnabled("gnosis", true)
        settings.setNetworkEnabled("sepolia", false)
        RailgunPoc.applyFirstStartSettings(settings, firstStart = false)
        assertTrue(settings.isNetworkEnabled("gnosis"), "a later start must not touch settings")
        assertFalse(settings.isNetworkEnabled("sepolia"), "a network the user turned off stays off")
    }

    /**
     * The upgrade case: an install whose first start ran before this flavour seeded Sepolia
     * has a settings file that configured mainnet only, and no record of it. The next start
     * of a build that bundles the Sepolia seed configures Sepolia exactly as a first start
     * would, and touches nothing about mainnet the user may have changed since.
     */
    @Test
    fun `an install from before the sepolia seed picks sepolia up once`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        // What the single-network flavour's first start wrote, plus a user's later choice.
        Files.writeString(
            file,
            "networks.enabled=mainnet\n" +
                "rpcPort.mainnet=9545\n" +
                "logIndex.mainnet=true\n" +
                "logIndex.backfillPaused.mainnet=false\n" +
                "logIndex.watch.mainnet=" + mainnet.watchJson + "\n",
        )
        val settings = DesktopSettings(nets, file)
        assertNull(settings.pocConfiguredNetworks(), "a pre-record install has none")
        RailgunPoc.applyFirstStartSettings(settings, firstStart = false)

        val after = DesktopSettings(nets, file) // what the next start reads back
        assertEquals(listOf("mainnet", "sepolia"), after.enabledNetworks())
        assertEquals(RAILGUN_SEPOLIA_RPC_PORT, after.rpcPortFor("sepolia"))
        assertTrue(after.logIndexEnabled("sepolia"))
        assertEquals(sepolia.watchJson, after.logIndexWatchJson("sepolia"))
        assertTrue(after.logIndexBackfillPaused("sepolia"))
        // Mainnet was configured at the original first start; the user's changes stand.
        assertEquals(9545, after.rpcPortFor("mainnet"))
        assertFalse(after.logIndexBackfillPaused("mainnet"))
        assertEquals(setOf("mainnet", "sepolia"), after.pocConfiguredNetworks())

        // Once configured, never again: the user turns Sepolia off, and it stays off.
        after.setNetworkEnabled("sepolia", false)
        RailgunPoc.applyFirstStartSettings(after, firstStart = false)
        assertFalse(DesktopSettings(nets, file).isNetworkEnabled("sepolia"))
    }

    @Test
    fun `the bundled seeds install under each network's own names`(@TempDir dir: Path) {
        val res = dir.resolve("resources")
        stage(res, mainnet, "MLIX-fake-mainnet-seed".toByteArray(), RAILGUN_PROXY_DEPLOYED, 26_097_965, 437765)
        stage(res, sepolia, "MLIX-fake-sepolia-seed".toByteArray(), RAILGUN_SEPOLIA_PROXY_DEPLOYED, 11_824_017, 14761)
        val data = dir.resolve("data")

        val outcomes = RailgunPoc.installSeedsIfAbsent(res, data)
        assertEquals(mapOf("mainnet" to SeedOutcome.INSTALLED, "sepolia" to SeedOutcome.INSTALLED), outcomes)
        for (seed in RailgunPoc.seeds) {
            assertTrue(Files.exists(data.resolve(seed.seedFile)), seed.seedFile)
            assertTrue(Files.exists(data.resolve(seed.installedManifestFile)), seed.installedManifestFile)
        }
        assertEquals("MLIX-fake-sepolia-seed", Files.readString(data.resolve("logindex-sepolia.db")))
        // ...and not under the Bee flavour's, which would leave both dead.
        assertFalse(Files.exists(data.resolve(BeePoc.seeds.single().seedFile)))

        val mainNotice = RailgunPoc.seededIndexNotice(data, "mainnet")
        assertTrue(mainNotice != null && mainNotice.contains("437765"), "the notice states the seed size: $mainNotice")
        assertTrue(mainNotice!!.contains("unverified"), "the notice must not present RPC data as verified")
        val sepNotice = RailgunPoc.seededIndexNotice(data, "sepolia")
        assertTrue(sepNotice != null && sepNotice.contains("14761") && sepNotice.contains("5784774–11824017"), "$sepNotice")
        assertTrue(sepNotice!!.contains("a Sepolia full node"), sepNotice)
        assertNull(RailgunPoc.seededIndexNotice(data, "gnosis"), "unseeded networks get no notice")
    }

    @Test
    fun `a sepolia seed missing from the bundle says so, and does not stop mainnet's`(@TempDir dir: Path) {
        val res = dir.resolve("resources")
        stage(res, mainnet, "MLIX-fake-mainnet-seed".toByteArray(), RAILGUN_PROXY_DEPLOYED, 26_097_965, 437765)
        val data = dir.resolve("data")

        val outcomes = RailgunPoc.installSeedsIfAbsent(res, data)
        assertEquals(SeedOutcome.INSTALLED, outcomes["mainnet"])
        assertEquals(SeedOutcome.NOT_BUNDLED, outcomes["sepolia"])
        val notice = RailgunPoc.seededIndexNotice(data, "sepolia")!!
        assertTrue(notice.contains("NOT installed") && notice.contains("not bundled"), notice)
        // The walk starts paused in this flavour, so the notice must not promise one.
        assertFalse(notice.contains("will backfill"), notice)
        assertTrue(notice.contains("switched off"), notice)
    }

    @Test
    fun `an empty configured-networks record counts as none, so the primary is not re-applied`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        Files.writeString(file, "networks.enabled=mainnet\nrpcPort.mainnet=9545\npoc.configuredNetworks=\n")
        val settings = DesktopSettings(nets, file)
        assertNull(settings.pocConfiguredNetworks())
        RailgunPoc.applyFirstStartSettings(settings, firstStart = false)
        assertEquals(9545, settings.rpcPortFor("mainnet"), "the primary network's settings stand")
        assertTrue(settings.isNetworkEnabled("sepolia"), "the network it never configured is configured")
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

            // Both set is a packaging mistake: the flavours disagree about the networks and
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
