package io.myotis.desktop

import io.myotis.api.NetworkInfo
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * DesktopSettings must survive an app restart (a fresh instance over the same file) —
 * the engine choice and enabled networks in particular, which used to be in-memory only.
 */
class DesktopSettingsPersistenceTest {

    private val nets = listOf(
        NetworkInfo("mainnet", "Ethereum Mainnet", 1, true, 30303, 9000, 8545, 1606824023, 12),
        NetworkInfo("gnosis", "Gnosis Chain", 100, false, 30303, 9000, 8547, 1638993340, 5),
    )

    @Test
    fun `every setting round-trips across a restart`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        val first = DesktopSettings(nets, file)
        first.setRustEngineEnabled(true)
        first.setNetworkEnabled("gnosis", true)
        first.setNetworkEnabled("mainnet", false)
        first.setRpcPort("gnosis", 9999)
        first.setSnapTarget(48)
        first.setServedBlockWindow(64)
        first.setDeepPool(8)
        first.setStrictStateFreshness(false)
        first.setNativeBlsEnabled(true)

        // Fresh instance over the same file = app restart.
        val second = DesktopSettings(nets, file)
        assertTrue(second.rustEngineEnabled(), "engine choice must be sticky")
        assertEquals(listOf("gnosis"), second.enabledNetworks(), "network selection must be sticky")
        assertFalse(second.isNetworkEnabled("mainnet"))
        assertEquals(9999, second.rpcPortFor("gnosis"))
        assertEquals(48, second.snapTarget())
        assertEquals(64, second.servedBlockWindow())
        assertEquals(8, second.deepPoolThreshold())
        assertFalse(second.strictStateFreshness())
        assertTrue(second.nativeBlsEnabled())
    }

    @Test
    fun `all networks disabled persists as the empty set, not the default`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        DesktopSettings(nets, file).setNetworkEnabled("mainnet", false)
        val reloaded = DesktopSettings(nets, file)
        assertEquals(emptyList<String>(), reloaded.enabledNetworks())
    }

    @Test
    fun `missing file keeps the defaults`(@TempDir dir: Path) {
        val s = DesktopSettings(nets, dir.resolve("does-not-exist.properties"))
        assertEquals(listOf("mainnet"), s.enabledNetworks())
        assertFalse(s.rustEngineEnabled())
        assertTrue(s.strictStateFreshness())
        assertEquals(32, s.snapTarget())
        assertEquals(32, s.servedBlockWindow())
        assertEquals(16, s.deepPoolThreshold())
    }

    @Test
    fun `garbage values fall back to defaults instead of breaking boot`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        Files.writeString(
            file,
            """
            networks.enabled=gnosis,holesky, ,mainnet
            rpcPort.gnosis=99
            rpcPort.mainnet=not-a-number
            snapTarget=100000
            servedBlockWindow=-7
            deepPool=zero
            rustEngine=yes-please
            strictStateFreshness=false
            """.trimIndent(),
        )
        val s = DesktopSettings(nets, file)
        // Unknown ("holesky") and blank names dropped; known ones kept.
        assertEquals(listOf("gnosis", "mainnet"), s.enabledNetworks())
        // Out-of-range / unparsable ports ignored → network default.
        assertEquals(8547, s.rpcPortFor("gnosis"))
        assertEquals(8545, s.rpcPortFor("mainnet"))
        // Ints clamped, bad bools fall back to their defaults, good ones apply.
        assertEquals(128, s.snapTarget())
        assertEquals(1, s.servedBlockWindow())
        assertEquals(16, s.deepPoolThreshold())
        assertFalse(s.rustEngineEnabled())
        assertFalse(s.strictStateFreshness())
    }

    @Test
    fun `null file keeps the store in-memory`(@TempDir dir: Path) {
        val s = DesktopSettings(nets, null)
        s.setRustEngineEnabled(true)
        assertTrue(s.rustEngineEnabled())
        assertEquals(0, Files.list(dir).use { it.count() }, "no file must be written")
    }
}
