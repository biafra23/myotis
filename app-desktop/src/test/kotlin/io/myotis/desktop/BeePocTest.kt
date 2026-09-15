package io.myotis.desktop

import io.myotis.api.NetworkInfo
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
 * exactly once (never over an index the engine owns), only when its sha256 matches the
 * manifest, and the first start boots Gnosis with the log index on.
 */
class BeePocTest {

    private val nets = listOf(
        NetworkInfo("mainnet", "Ethereum Mainnet", 1, true, 30303, 9000, 8545, 1606824023, 12),
        NetworkInfo("gnosis", "Gnosis Chain", 100, false, 30303, 9000, 8546, 1638993340, 5),
    )

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun stageBundle(dir: Path, seed: ByteArray, sha: String = sha256(seed)): Path {
        val res = dir.resolve("resources")
        Files.createDirectories(res)
        Files.write(res.resolve(BeePoc.SEED_FILE), seed)
        Files.writeString(
            res.resolve(BeePoc.MANIFEST_FILE),
            """
            network=gnosis
            address=${BeePoc.POSTAGE_STAMP}
            coveredLow=47000000
            coveredHigh=48262676
            usableUntilBlock=48762676
            logs=39213
            sha256=$sha
            """.trimIndent(),
        )
        return res
    }

    @Test
    fun `seed is installed once, with its manifest, and never overwrites`(@TempDir dir: Path) {
        val seed = "MLIX-fake-seed".toByteArray()
        val res = stageBundle(dir, seed)
        val data = dir.resolve("data")

        assertTrue(BeePoc.installSeedIfAbsent(res, data))
        val installed = data.resolve(BeePoc.SEED_FILE)
        assertTrue(Files.readAllBytes(installed).contentEquals(seed))
        assertTrue(Files.isRegularFile(data.resolve(BeePoc.INSTALLED_MANIFEST_FILE)))
        assertFalse(Files.exists(data.resolve("${BeePoc.SEED_FILE}.tmp")), "no temp file left behind")

        // The engine owns the file after the first start: a later launch must leave it alone.
        Files.write(installed, "engine-checkpoint".toByteArray())
        assertFalse(BeePoc.installSeedIfAbsent(res, data))
        assertEquals("engine-checkpoint", Files.readString(installed))
    }

    @Test
    fun `a seed that does not match its manifest is not installed`(@TempDir dir: Path) {
        val res = stageBundle(dir, "MLIX-fake-seed".toByteArray(), sha = "00".repeat(32))
        val data = dir.resolve("data")
        assertFalse(BeePoc.installSeedIfAbsent(res, data))
        assertFalse(Files.exists(data.resolve(BeePoc.SEED_FILE)))
    }

    @Test
    fun `nothing bundled means nothing installed`(@TempDir dir: Path) {
        assertFalse(BeePoc.installSeedIfAbsent(null, dir.resolve("data")))
        assertFalse(BeePoc.installSeedIfAbsent(dir.resolve("missing"), dir.resolve("data")))
    }

    @Test
    fun `first start boots gnosis only with the log index on`(@TempDir dir: Path) {
        val settings = DesktopSettings(nets, dir.resolve("settings.properties"))
        BeePoc.applyFirstStartSettings(settings, firstStart = true)
        assertEquals(listOf("gnosis"), settings.enabledNetworks())
        assertEquals("gnosis", settings.primaryNetwork())
        assertTrue(settings.logIndexEnabled("gnosis"))
        assertTrue(settings.logIndexConfigured("gnosis"))
        assertEquals(BeePoc.WATCH_JSON, settings.logIndexWatchJson("gnosis"))
        // …and survives a restart (a fresh instance over the same file).
        val again = DesktopSettings(nets, dir.resolve("settings.properties"))
        assertEquals(listOf("gnosis"), again.enabledNetworks())
        assertTrue(again.logIndexEnabled("gnosis"))
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
        assertNull(BeePoc.seededIndexNotice(data, "gnosis"), "nothing installed yet")
        BeePoc.installSeedIfAbsent(res, data)
        val notice = BeePoc.seededIndexNotice(data, "gnosis")!!
        assertTrue(notice.contains("47000000–48262676"), notice)
        assertTrue(notice.contains("48762676"), notice)
        assertTrue(notice.contains("39213"), notice)
        assertNull(BeePoc.seededIndexNotice(data, "mainnet"))
    }
}
