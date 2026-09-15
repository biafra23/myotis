package io.myotis.desktop

import io.myotis.api.NetworkInfo
import io.myotis.desktop.BeePoc.Outcome
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

        assertEquals(Outcome.INSTALLED, BeePoc.installSeedIfAbsent(res, data))
        val installed = data.resolve(BeePoc.SEED_FILE)
        assertTrue(Files.readAllBytes(installed).contentEquals(seed))
        assertTrue(Files.isRegularFile(data.resolve(BeePoc.INSTALLED_MANIFEST_FILE)))
        assertFalse(Files.exists(data.resolve("${BeePoc.SEED_FILE}.tmp")), "no temp file left behind")

        // The engine owns the file after the first start: a later launch of the same
        // build must leave it alone.
        Files.write(installed, "engine-checkpoint".toByteArray())
        assertEquals(Outcome.KEPT_EXISTING, BeePoc.installSeedIfAbsent(res, data))
        assertEquals("engine-checkpoint", Files.readString(installed))
    }

    @Test
    fun `a newer bundled seed re-seeds, an older one does not`(@TempDir dir: Path) {
        val data = dir.resolve("data")
        val v1 = stageBundle(dir, "seed-v1".toByteArray(), high = 48_262_676)
        assertEquals(Outcome.INSTALLED, BeePoc.installSeedIfAbsent(v1, data))
        Files.write(data.resolve(BeePoc.SEED_FILE), "engine-checkpoint".toByteArray())

        val older = stageBundle(dir, "seed-v0".toByteArray(), high = 48_000_000)
        assertEquals(Outcome.KEPT_EXISTING, BeePoc.installSeedIfAbsent(older, data))
        assertEquals("engine-checkpoint", Files.readString(data.resolve(BeePoc.SEED_FILE)))

        val newer = stageBundle(dir, "seed-v2".toByteArray(), high = 48_800_000)
        assertEquals(Outcome.INSTALLED, BeePoc.installSeedIfAbsent(newer, data))
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
        assertEquals(Outcome.INSTALLED, BeePoc.installSeedIfAbsent(v1, data))
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
            assertTrue(outcome == Outcome.FAILED || outcome == Outcome.BAD_CHECKSUM, "got $outcome")
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
        assertEquals(Outcome.KEPT_EXISTING, BeePoc.installSeedIfAbsent(res, data))
        assertEquals("user-imported", Files.readString(data.resolve(BeePoc.SEED_FILE)))
    }

    @Test
    fun `a seed that does not match its manifest is not installed`(@TempDir dir: Path) {
        val res = stageBundle(dir, "MLIX-fake-seed".toByteArray(), sha = "00".repeat(32))
        val data = dir.resolve("data")
        assertEquals(Outcome.BAD_CHECKSUM, BeePoc.installSeedIfAbsent(res, data))
        assertFalse(Files.exists(data.resolve(BeePoc.SEED_FILE)))
        // …and the Index tab says so instead of showing a seed.
        val notice = BeePoc.seededIndexNotice(data, "gnosis")!!
        assertTrue(notice.contains("NOT installed"), notice)
        assertTrue(notice.contains("bad checksum"), notice)
    }

    @Test
    fun `nothing bundled means nothing installed`(@TempDir dir: Path) {
        assertEquals(Outcome.NOT_BUNDLED, BeePoc.installSeedIfAbsent(null, dir.resolve("data")))
        assertEquals(Outcome.NOT_BUNDLED, BeePoc.installSeedIfAbsent(dir.resolve("missing"), dir.resolve("data")))
    }

    @Test
    fun `first start boots gnosis only with the log index on`(@TempDir dir: Path) {
        val settings = DesktopSettings(nets, dir.resolve("settings.properties"))
        BeePoc.applyFirstStartSettings(settings, firstStart = true)
        assertEquals(listOf("gnosis"), settings.enabledNetworks())
        assertEquals("gnosis", settings.primaryNetwork())
        assertTrue(settings.logIndexEnabled("gnosis"))
        assertTrue(settings.logIndexConfigured("gnosis"))
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
