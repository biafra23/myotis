package io.myotis.desktop

import java.nio.file.Path
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * A `-Pengine=go` launch runs on its own profile (PR #832 review): the Go
 * engine's catalog lists only what it can RUN, and DesktopSettings prunes the
 * saved enabled-networks (and per-network RPC ports) that the running
 * engine's catalog lacks, rewriting the whole file on the next save — so a go
 * launch sharing `~/.myotis` would silently drop `gnosis`/`sepolia` from the
 * regular profile. `desktopDataDir` is the isolation; this pins it.
 */
class DesktopDataDirTest {

    @Test
    fun `regular launches use the shared profile`() {
        assertEquals(Path.of("/home/u", ".myotis"), desktopDataDir(null, null, "/home/u"))
        for (choice in listOf("auto", "java", "rust", "")) {
            assertEquals(Path.of("/home/u", ".myotis"), desktopDataDir(null, choice, "/home/u"),
                "choice '$choice' must not divert the profile")
        }
    }

    @Test
    fun `a go launch gets its own profile`() {
        assertEquals(Path.of("/home/u", ".myotis-go"), desktopDataDir(null, "go", "/home/u"))
        assertEquals(Path.of("/home/u", ".myotis-go"), desktopDataDir(null, " GO ", "/home/u"),
            "same tolerance as Engines.normalize")
    }

    @Test
    fun `a poc flavour wins over the engine flag`() {
        // The function stays total; main() REFUSES the flavour+go pair before
        // this precedence ever decides anything (see flavourOnGoRefusal below).
        val poc = Path.of("/tmp/poc-bee")
        assertEquals(poc, desktopDataDir(poc, "go", "/home/u"))
        assertEquals(poc, desktopDataDir(poc, null, "/home/u"))
    }

    @Test
    fun `only the go engine choice diverts`() {
        assertTrue(engineChoiceIsGo("go"))
        assertTrue(engineChoiceIsGo(" GO "), "same tolerance as Engines.normalize")
        for (other in listOf(null, "", "auto", "java", "rust", "gopher")) {
            assertFalse(engineChoiceIsGo(other), "'$other' is not the Go engine")
        }
    }

    /**
     * The PoC profiles' network would vanish: Bee runs gnosis only and the
     * RAILGUN PoC sepolia only, and DesktopSettings prunes saved
     * enabled-networks the RUNNING engine's catalog lacks — the Go catalog is
     * mainnet-only (PR #832 round-3 review). The combo must be a named error
     * at startup, not an empty app.
     */
    @Test
    fun `a flavour on the go engine is refused by name, everything else runs`() {
        val bee = flavourOnGoRefusal("Bee PoC", "go")
        assertNotNull(bee, "flavour + go must refuse")
        assertTrue(bee!!.contains("Bee PoC") && bee.contains("mainnet-only"),
            "refusal must name the flavour and the cause: $bee")
        assertNotNull(flavourOnGoRefusal("RAILGUN PoC", " GO "))
        assertNull(flavourOnGoRefusal("Bee PoC", null), "a flavour without the flag runs")
        assertNull(flavourOnGoRefusal("Bee PoC", "auto"), "auto never picks go")
        assertNull(flavourOnGoRefusal(null, "go"), "the go profile alone is the point")
        assertNull(flavourOnGoRefusal(null, null))
    }
}
