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
        first.setPreferJavaEngine(true)
        first.setNetworkEnabled("gnosis", true)
        first.setNetworkEnabled("mainnet", false)
        first.setRpcPort("gnosis", 9999)
        first.setSnapTarget(48)
        first.setServedBlockWindow(64)
        first.setDeepPool(8)
        first.setStrictStateFreshness(false)
        first.setNativeBlsEnabled(true)
        first.setLogIndexWatchJson(
            "gnosis",
            """[{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":31305656}]""",
        )

        // Fresh instance over the same file = app restart.
        val second = DesktopSettings(nets, file)
        assertTrue(second.preferJavaEngine(), "engine choice must be sticky")
        assertEquals(listOf("gnosis"), second.enabledNetworks(), "network selection must be sticky")
        assertFalse(second.isNetworkEnabled("mainnet"))
        assertEquals(9999, second.rpcPortFor("gnosis"))
        assertEquals(48, second.snapTarget())
        assertEquals(64, second.servedBlockWindow())
        assertEquals(8, second.deepPoolThreshold())
        assertFalse(second.strictStateFreshness())
        assertTrue(second.nativeBlsEnabled())
        assertEquals(
            """[{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":31305656}]""",
            second.logIndexWatchJson("gnosis"),
            "the watch list must be sticky",
        )
        assertEquals("[]", second.logIndexWatchJson("mainnet"))
    }

    @Test
    fun `expert mode and the App Nap opt-in round-trip across a restart`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        val first = DesktopSettings(nets, file)
        assertFalse(first.expertMode(), "normal mode is the default")
        assertFalse(first.allowAppNap(), "the no-nap activity is held by default")
        first.setExpertMode(true)
        first.setAllowAppNap(true)

        val second = DesktopSettings(nets, file)
        assertTrue(second.expertMode(), "Expert mode must be sticky")
        assertTrue(second.allowAppNap(), "the App Nap opt-in must be sticky")

        // Garbage falls back to the defaults, like every other boolean here.
        Files.writeString(file, "expertMode=sure\nappNap.allow=1\n")
        val third = DesktopSettings(nets, file)
        assertFalse(third.expertMode())
        assertFalse(third.allowAppNap())
    }

    @Test
    fun `web page access round-trips across a restart`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        val first = DesktopSettings(nets, file)
        assertEquals(io.myotis.ui.WebAccessMode.ALLOWLIST, first.webAccessMode(), "specific sites is the default")
        assertEquals(emptyList<String>(), first.webAccessOrigins(), "with no sites allowed")
        first.setWebAccessOrigins(listOf("https://app.example", "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn"))
        first.setWebAccessMode(io.myotis.ui.WebAccessMode.OFF)

        val second = DesktopSettings(nets, file)
        assertEquals(io.myotis.ui.WebAccessMode.OFF, second.webAccessMode(), "the mode must be sticky")
        assertEquals(
            listOf("https://app.example", "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn"),
            second.webAccessOrigins(),
            "the allowed sites must be sticky, in order",
        )
        // The engine-facing policy carries both.
        val policy = webAccessPolicy(second)
        assertEquals(io.myotis.api.WebAccessMode.OFF, policy.mode())
        assertEquals(2, policy.origins().size)

        // An unknown mode name keeps the safe default; a blank list entry is dropped.
        Files.writeString(file, "webAccess.mode=EVERYONE\nwebAccess.origins=https://a.example,, https://b.example \n")
        val third = DesktopSettings(nets, file)
        assertEquals(io.myotis.ui.WebAccessMode.ALLOWLIST, third.webAccessMode())
        assertEquals(listOf("https://a.example", "https://b.example"), third.webAccessOrigins())
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
        assertFalse(s.preferJavaEngine())
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
            engine.preferJava=yes-please
            logIndex.watch.gnosis=[{"address":"0xbad","fromBlock":1},{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":7}]
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
        assertFalse(s.preferJavaEngine())
        assertFalse(s.strictStateFreshness())
        // The bad watch entry is dropped at load; the good one survives.
        assertEquals(
            """[{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":7}]""",
            s.logIndexWatchJson("gnosis"),
        )
    }

    @Test
    fun `a removed contract's marker survives a restart`(@TempDir dir: Path) {
        // The marker is what makes the next config push name the address under
        // `unwatch`. A removal made while the network was stopped exists ONLY as
        // this marker until the network starts — so a load that normalized the
        // store through the entry parser alone would silently cancel it.
        val file = dir.resolve("settings.properties")
        val removed = io.myotis.ui.LogIndexWatch.unwatch(
            """[{"address":"0x45a1502382541cD610CC9068e88727426b696293","fromBlock":7},""" +
                """{"address":"0xB20c66C4DE72433F3cE747b58B86830c459CA911","fromBlock":9}]""",
            "0xB20c66C4DE72433F3cE747b58B86830c459CA911",
        )
        DesktopSettings(nets, file).setLogIndexWatchJson("gnosis", removed)

        val reloaded = DesktopSettings(nets, file)
        assertEquals(removed, reloaded.logIndexWatchJson("gnosis"))
        reloaded.setLogIndexEnabled("gnosis", true)
        val push = logIndexConfigJson(reloaded, "gnosis")!!
        assertTrue(push.contains(""""unwatch":["0xB20c66C4DE72433F3cE747b58B86830c459CA911"]"""), push)
    }

    @Test
    fun `a kohaku-preset user's enabled flag seeds the legacy watch list`(@TempDir dir: Path) {
        // Pre-generic users have logIndex.<net>=true persisted but NO watch
        // entries (the preset lived in code). Without the seed, their first
        // post-upgrade config push would silently drop every subscription.
        val file = dir.resolve("settings.properties")
        Files.writeString(file, "logIndex.mainnet=true\n")
        val s = DesktopSettings(nets, file)
        val seeded = io.myotis.ui.LogIndexWatch.parse(s.logIndexWatchJson("mainnet"))
        assertEquals(4, seeded.size, "the four mainnet Kohaku contracts must be seeded")
        assertTrue(s.logIndexConfigured("mainnet"))
        // A network without the flag stays virgin: no seed, not configured.
        assertEquals("[]", s.logIndexWatchJson("gnosis"))
        assertFalse(s.logIndexConfigured("gnosis"))
        // An explicit OFF flag is configured too (the disable push must go out)
        // but does not seed a watch list for an index the user turned off.
        Files.writeString(file, "logIndex.mainnet=false\n")
        val off = DesktopSettings(nets, file)
        assertTrue(off.logIndexConfigured("mainnet"))
        assertEquals("[]", off.logIndexWatchJson("mainnet"))
    }

    @Test
    fun `the balance watch list and state survive a restart`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        val alice = "0x" + "a1".repeat(20)
        val first = DesktopSettings(nets, file)
        assertTrue(first.supportsBalanceWatch())
        first.setWatchListJson("gnosis", """[{"address":"$alice","label":"Savings"}]""")
        first.setWatchStateJson("gnosis", """{"v":1,"lastCheckMs":5}""")

        val second = DesktopSettings(nets, file)
        assertEquals("""[{"address":"$alice","label":"Savings"}]""", second.watchListJson("gnosis"))
        assertEquals("""{"v":1,"lastCheckMs":5}""", second.watchStateJson("gnosis"))
        assertEquals("[]", second.watchListJson("mainnet"))
        assertEquals("{}", second.watchStateJson("mainnet"))
        // The state is rewritten on every check, so it lives beside the settings, not in them.
        assertTrue(Files.isRegularFile(dir.resolve("watch-state-gnosis.json")))
        assertFalse(Files.readString(file).contains("lastCheckMs"))
    }

    @Test
    fun `a hand-edited watch list keeps only what checks out`(@TempDir dir: Path) {
        val file = dir.resolve("settings.properties")
        val alice = "0x" + "a1".repeat(20)
        Files.writeString(
            file,
            "watch.list.mainnet=[{\"address\":\"0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1\",\"label\":\"x\"}," +
                "{\"address\":\"0x12\"}]\n",
        )
        assertEquals("""[{"address":"$alice","label":"x"}]""", DesktopSettings(nets, file).watchListJson("mainnet"))
    }

    @Test
    fun `one notification names every change of a check`() {
        val alice = "0x" + "a1".repeat(20)
        val change = io.myotis.ui.WatchChange(
            alice, "Savings", "1000000000000000000", "1500000000000000000", 0, 0, 1, 2, -1, 0,
            io.myotis.ui.WatchSearch.NONE, -1, emptyList(),
        )
        val (title, message) = watchNotificationText("Ethereum Mainnet", "mainnet", listOf(change))
        assertEquals("Savings: +0.5 ETH", title)
        assertTrue(message.startsWith("Ethereum Mainnet — Balance 1 → 1.5 ETH"), message)
        val (manyTitle, manyMessage) = watchNotificationText("Gnosis Chain", "gnosis", List(5) { change })
        assertEquals("5 watched balances changed", manyTitle)
        assertTrue(manyMessage.contains("Savings: +0.5 xDAI") && manyMessage.contains("and 2 more"), manyMessage)
    }

    @Test
    fun `null file keeps the store in-memory`(@TempDir dir: Path) {
        val s = DesktopSettings(nets, null)
        s.setPreferJavaEngine(true)
        assertTrue(s.preferJavaEngine())
        s.setWatchStateJson("mainnet", "{}")
        assertEquals("{}", s.watchStateJson("mainnet"))
        assertEquals(0, Files.list(dir).use { it.count() }, "no file must be written")
    }
}
