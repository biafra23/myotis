package io.myotis.desktop

import java.nio.file.Path
import org.junit.jupiter.api.Assertions.assertEquals
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
        val poc = Path.of("/tmp/poc-bee")
        assertEquals(poc, desktopDataDir(poc, "go", "/home/u"))
        assertEquals(poc, desktopDataDir(poc, null, "/home/u"))
    }
}
