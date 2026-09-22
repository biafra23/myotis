package io.myotis.desktop

import io.myotis.api.NetworkInfo
import io.myotis.desktop.SeedOutcome
import io.myotis.ui.LogIndexWatch
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * The Bee PoC flavour's first-start behaviour: the bundled seed lands in the data dir
 * exactly once per seed version (never over an index this flavour did not install, and
 * never over a newer-or-equal one), only when its sha256 matches the manifest, and the
 * first start boots Gnosis with the log index on.
 */
class BeePocTest {

    private val nets = listOf(
        NetworkInfo("mainnet", "Ethereum Mainnet", 1, true, 30303, 9000, 8545, 1606824023, 12),
        NetworkInfo("gnosis", "Gnosis Chain", 100, false, 30303, 9000, 8546, 1638993340, 5),
    )

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun stageBundle(dir: Path, seed: ByteArray, sha: String = sha256(seed), high: Long = 48_262_676): Path {
        val res = dir.resolve("resources-$high")
        Files.createDirectories(res)
        Files.write(res.resolve(BeePoc.SEED_FILE), seed)
        Files.writeString(
            res.resolve(BeePoc.MANIFEST_FILE),
            """
            network=gnosis
            address=${BeePoc.POSTAGE_STAMP}
            coveredLow=47000000
            coveredHigh=$high
            usableUntilBlock=${high + 500_000}
            logs=39213
            sha256=$sha
            """.trimIndent(),
        )
        return res
    }

    @Test
    fun `seed is installed once, with its manifest, and never overwrites the same version`(@TempDir dir: Path) {
        val seed = "MLIX-fake-seed".toByteArray()
        val res = stageBundle(dir, seed)
        val data = dir.resolve("data")

        assertEquals(SeedOutcome.INSTALLED, BeePoc.installSeedIfAbsent(res, data))
        val installed = data.resolve(BeePoc.SEED_FILE)
        assertTrue(Files.readAllBytes(installed).contentEquals(seed))
        assertTrue(Files.isRegularFile(data.resolve(BeePoc.INSTALLED_MANIFEST_FILE)))
        assertFalse(Files.exists(data.resolve("${BeePoc.SEED_FILE}.tmp")), "no temp file left behind")

        // The engine owns the file after the first start: a later launch of the same
        // build must leave it alone.
        Files.write(installed, "engine-checkpoint".toByteArray())
        assertEquals(SeedOutcome.KEPT_EXISTING, BeePoc.installSeedIfAbsent(res, data))
        assertEquals("engine-checkpoint", Files.readString(installed))
    }

    @Test
    fun `a newer bundled seed re-seeds, an older one does not`(@TempDir dir: Path) {
        val data = dir.resolve("data")
        val v1 = stageBundle(dir, "seed-v1".toByteArray(), high = 48_262_676)
        assertEquals(SeedOutcome.INSTALLED, BeePoc.installSeedIfAbsent(v1, data))
        Files.write(data.resolve(BeePoc.SEED_FILE), "engine-checkpoint".toByteArray())

        val older = stageBundle(dir, "seed-v0".toByteArray(), high = 48_000_000)
        assertEquals(SeedOutcome.KEPT_EXISTING, BeePoc.installSeedIfAbsent(older, data))
        assertEquals("engine-checkpoint", Files.readString(data.resolve(BeePoc.SEED_FILE)))

        val newer = stageBundle(dir, "seed-v2".toByteArray(), high = 48_800_000)
        assertEquals(SeedOutcome.INSTALLED, BeePoc.installSeedIfAbsent(newer, data))
        assertEquals("seed-v2", Files.readString(data.resolve(BeePoc.SEED_FILE)))
        assertTrue(Files.readString(data.resolve(BeePoc.INSTALLED_MANIFEST_FILE)).contains("coveredHigh=48800000"))
    }

    @Test
    fun `a failed re-seed keeps the previous index and leaves no temp file`(@TempDir dir: Path) {
        org.junit.jupiter.api.Assumptions.assumeFalse(
            System.getProperty("os.name").lowercase().contains("win"),
            "relies on POSIX permissions to make the bundled seed unreadable",
        )
        val data = dir.resolve("data")
        val v1 = stageBundle(dir, "seed-v1".toByteArray(), high = 48_262_676)
        assertEquals(SeedOutcome.INSTALLED, BeePoc.installSeedIfAbsent(v1, data))
        Files.write(data.resolve(BeePoc.SEED_FILE), "engine-checkpoint".toByteArray())

        // A newer bundle whose seed cannot be read (the manifest still matches its
        // sha256, so the checksum gate passes and the copy itself fails).
        val newer = stageBundle(dir, "seed-v2".toByteArray(), high = 48_800_000)
        val newerSeed = newer.resolve(BeePoc.SEED_FILE)
        Files.setPosixFilePermissions(newerSeed, emptySet())
        try {
            // sha256 is computed by streaming the file, which the permission denies too:
            // that surfaces as FAILED via the checksum path or the copy path, and either
            // way the previous index must survive.
            val outcome = BeePoc.installSeedIfAbsent(newer, data)
            assertTrue(outcome == SeedOutcome.FAILED || outcome == SeedOutcome.BAD_CHECKSUM, "got $outcome")
            assertEquals("engine-checkpoint", Files.readString(data.resolve(BeePoc.SEED_FILE)))
            assertTrue(Files.readString(data.resolve(BeePoc.INSTALLED_MANIFEST_FILE)).contains("coveredHigh=48262676"))
            assertFalse(Files.exists(data.resolve("${BeePoc.SEED_FILE}.tmp")))
            assertFalse(Files.exists(data.resolve("${BeePoc.INSTALLED_MANIFEST_FILE}.tmp")))
        } finally {
            Files.setPosixFilePermissions(newerSeed, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"))
        }
    }

    @Test
    fun `an index this flavour did not install is never touched`(@TempDir dir: Path) {
        val data = dir.resolve("data")
        Files.createDirectories(data)
        Files.write(data.resolve(BeePoc.SEED_FILE), "user-imported".toByteArray()) // no installed manifest
        val res = stageBundle(dir, "seed".toByteArray())
        assertEquals(SeedOutcome.KEPT_EXISTING, BeePoc.installSeedIfAbsent(res, data))
        assertEquals("user-imported", Files.readString(data.resolve(BeePoc.SEED_FILE)))
    }

    @Test
    fun `a seed that does not match its manifest is not installed`(@TempDir dir: Path) {
        val res = stageBundle(dir, "MLIX-fake-seed".toByteArray(), sha = "00".repeat(32))
        val data = dir.resolve("data")
        assertEquals(SeedOutcome.BAD_CHECKSUM, BeePoc.installSeedIfAbsent(res, data))
        assertFalse(Files.exists(data.resolve(BeePoc.SEED_FILE)))
        // …and the Index tab says so instead of showing a seed.
        val notice = BeePoc.seededIndexNotice(data, "gnosis")!!
        assertTrue(notice.contains("NOT installed"), notice)
        assertTrue(notice.contains("bad checksum"), notice)
    }

    @Test
    fun `bundled peer caches land once and never over what the engine learned`(@TempDir dir: Path) {
        val res = stageBundle(dir, "seed".toByteArray())
        Files.writeString(res.resolve("peers-gnosis.cache"), "1.2.3.4\t30303\t0xab\t1\tsnapok\n")
        Files.writeString(res.resolve("cl-peers-gnosis.cache"), "/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmTest\n")
        val data = dir.resolve("data")
        Files.createDirectories(data)
        Files.writeString(data.resolve("cl-peers-gnosis.cache"), "engine-learned\n") // pre-existing: keep

        BeePoc.installSeedIfAbsent(res, data)
        assertTrue(Files.readString(data.resolve("peers-gnosis.cache")).startsWith("1.2.3.4\t30303"))
        assertEquals("engine-learned\n", Files.readString(data.resolve("cl-peers-gnosis.cache")))
        assertFalse(Files.exists(data.resolve("peers-gnosis.cache.tmp")))

        // A second start installs nothing more.
        assertEquals(emptyList<String>(), BeePoc.installPeerCachesIfAbsent(res, data))
    }

    @Test
    fun `peer caches install into a data dir that does not exist yet, and survive a second start`(@TempDir dir: Path) {
        val res = dir.resolve("resources")
        Files.createDirectories(res) // caches only, no seed: the PoC's cache install must not need one
        Files.writeString(res.resolve("peers-gnosis.cache"), "1.2.3.4\t30303\t0xab\t1\tsnapok\n")
        Files.writeString(res.resolve("cl-peers-gnosis.cache"), "/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmTest\n")
        val data = dir.resolve("fresh").resolve("data")
        assertEquals(listOf("peers-gnosis.cache", "cl-peers-gnosis.cache"), BeePoc.installPeerCachesIfAbsent(res, data))
        assertEquals("1.2.3.4\t30303\t0xab\t1\tsnapok\n", Files.readString(data.resolve("peers-gnosis.cache")))

        // The engine rewrites the files as it learns; a second start keeps that verbatim.
        Files.writeString(data.resolve("peers-gnosis.cache"), "engine-learned\n")
        assertEquals(emptyList<String>(), BeePoc.installPeerCachesIfAbsent(res, data))
        assertEquals("engine-learned\n", Files.readString(data.resolve("peers-gnosis.cache")))
        assertEquals("/ip4/1.2.3.4/tcp/9000/p2p/16Uiu2HAmTest\n", Files.readString(data.resolve("cl-peers-gnosis.cache")))
    }

    @Test
    fun `nothing bundled means nothing installed`(@TempDir dir: Path) {
        assertEquals(SeedOutcome.NOT_BUNDLED, BeePoc.installSeedIfAbsent(null, dir.resolve("data")))
        assertEquals(SeedOutcome.NOT_BUNDLED, BeePoc.installSeedIfAbsent(dir.resolve("missing"), dir.resolve("data")))
    }

    @Test
    fun `first start boots gnosis only with the log index on`(@TempDir dir: Path) {
        val settings = DesktopSettings(nets, dir.resolve("settings.properties"))
        BeePoc.applyFirstStartSettings(settings, firstStart = true)
        assertEquals(listOf("gnosis"), settings.enabledNetworks())
        assertEquals("gnosis", settings.primaryNetwork())
        assertTrue(settings.logIndexEnabled("gnosis"))
        assertTrue(settings.logIndexConfigured("gnosis"))
        assertTrue(settings.logIndexBackfillPaused("gnosis"), "the walk is off from the first start")
        assertEquals(
            listOf(LogIndexWatch.Entry(BeePoc.POSTAGE_STAMP, BeePoc.POSTAGE_STAMP_DEPLOYED)),
            LogIndexWatch.parse(settings.logIndexWatchJson("gnosis")),
        )
        // …and survives a restart (a fresh instance over the same file).
        val again = DesktopSettings(nets, dir.resolve("settings.properties"))
        assertEquals(listOf("gnosis"), again.enabledNetworks())
        assertTrue(again.logIndexEnabled("gnosis"))
        assertEquals(
            listOf(LogIndexWatch.Entry(BeePoc.POSTAGE_STAMP, BeePoc.POSTAGE_STAMP_DEPLOYED)),
            LogIndexWatch.parse(again.logIndexWatchJson("gnosis")),
        )
    }

    @Test
    fun `later starts leave the user's settings alone`(@TempDir dir: Path) {
        val settings = DesktopSettings(nets, dir.resolve("settings.properties"))
        settings.setNetworkEnabled("mainnet", true)
        BeePoc.applyFirstStartSettings(settings, firstStart = false)
        assertEquals(listOf("mainnet"), settings.enabledNetworks())
        assertFalse(settings.logIndexConfigured("gnosis"))
    }

    // -- the backfill OFF switch (the flavour's whole premise) -----------------

    /** Run [body] with the flavour property set as a PoC / regular build has it. */
    private fun withFlavour(on: Boolean, body: () -> Unit) {
        val saved = System.getProperty(BeePoc.PROP)
        try {
            if (on) System.setProperty(BeePoc.PROP, "true") else System.clearProperty(BeePoc.PROP)
            body()
        } finally {
            if (saved == null) System.clearProperty(BeePoc.PROP) else System.setProperty(BeePoc.PROP, saved)
        }
    }

    /**
     * The bundled seed IS the coverage: the PoC must never start the downward walk,
     * which only competes with head-follow for the snap pool (see
     * BeePoc.backfillPausedDefault). A regular install is untouched by that default.
     */
    @Test
    fun `the flavour starts the backfill paused, a regular install leaves it running`(@TempDir dir: Path) {
        withFlavour(true) {
            assertTrue(BeePoc.backfillPausedDefault())
            assertTrue(DesktopSettings(nets, dir.resolve("poc.properties")).logIndexBackfillPaused("gnosis"))
        }
        withFlavour(false) {
            assertFalse(BeePoc.backfillPausedDefault())
            assertFalse(DesktopSettings(nets, dir.resolve("regular.properties")).logIndexBackfillPaused("gnosis"))
        }
    }

    /**
     * The upgrade case, and the one every existing PoC install lands on: a settings
     * file written before the switch existed carries no `logIndex.backfillPaused.*`
     * key at all, so only the flavour default stands between it and a walk. Pinned
     * down to the config the desktop host builds for the engine ([logIndexConfigJson],
     * what pushLogIndexConfig sends): the engine activates the seeded index from disk
     * with the walk ON, and that push is what turns it off.
     */
    @Test
    fun `settings written before the switch existed still start the walk off`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        Files.writeString(
            file,
            "networks.enabled=gnosis\n" +
                "logIndex.gnosis=true\n" +
                """logIndex.watch.gnosis=[{"address":"${BeePoc.POSTAGE_STAMP}","fromBlock":${BeePoc.POSTAGE_STAMP_DEPLOYED}}]""" +
                "\n",
        )
        withFlavour(true) {
            val settings = DesktopSettings(nets, file)
            assertTrue(settings.logIndexBackfillPaused("gnosis"), "no stored preference: the flavour decides")
            // The mapping DesktopNode.pushLogIndexConfig hands the engine, called here
            // rather than re-spelled, so dropping the argument there fails this test.
            val json = logIndexConfigJson(settings, "gnosis")
            assertTrue(json != null && json.contains("\"backfillPaused\":true"), "pushed config: $json")
        }
    }

    /** First start PERSISTS the pause, so it holds however the flavour flag is read later. */
    @Test
    fun `first start writes the pause into the settings file`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        withFlavour(true) { BeePoc.applyFirstStartSettings(DesktopSettings(nets, file), firstStart = true) }
        assertTrue(
            Files.readString(file).contains("logIndex.backfillPaused.gnosis=true"),
            "the pause must be in the file, not only in the default",
        )
        withFlavour(false) {
            assertTrue(DesktopSettings(nets, file).logIndexBackfillPaused("gnosis"))
        }
    }

    /** The Index tab's switch still wins: a default nobody can override is a bug, not a policy. */
    @Test
    fun `a user who turns the walk back on keeps it across a restart`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        withFlavour(true) {
            DesktopSettings(nets, file).setLogIndexBackfillPaused("gnosis", false)
            assertFalse(DesktopSettings(nets, file).logIndexBackfillPaused("gnosis"))
        }
    }

    @Test
    fun `the index tab notice comes from the installed manifest`(@TempDir dir: Path) {
        val res = stageBundle(dir, "MLIX-fake-seed".toByteArray())
        val data = dir.resolve("data")
        BeePoc.installSeedIfAbsent(res, data)
        val notice = BeePoc.seededIndexNotice(data, "gnosis")!!
        assertTrue(notice.contains("47000000–48262676"), notice)
        assertTrue(notice.contains("48762676"), notice)
        assertTrue(notice.contains("39213"), notice)
        assertNull(BeePoc.seededIndexNotice(data, "mainnet"))
    }
}
