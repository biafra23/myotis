package io.myotis.engines;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link Tor#configureStorage} through the real library (ABI 43): the directories
 * Arti keeps its state and cache in are applied or refused, never recorded and
 * ignored — the call answers whether the engine will use them. Self-skips on
 * cargo-less machines like the other live suites.
 */
class TorStorageTest {

    @BeforeAll
    static void setup() {
        assumeTrue(RustMyotisEngine.isAvailable(),
                "libmyotis_engine not loadable — skipping live Tor storage tests");
    }

    @Test
    void relativeAndNullDirectoriesAreRefused() {
        assertFalse(Tor.configureStorage("arti/state", "/abs/cache"));
        assertFalse(Tor.configureStorage(null, null));
    }

    @Test
    void absoluteDirectoriesAreTakenExactlyWhenTheBuildCanRoute(@TempDir Path dir) {
        // A Tor-less library (the default build) refuses every pair; a -PtorEngine
        // one takes any absolute pair before its first bootstrap. Never enabled
        // here, so no bootstrap ever holds them.
        boolean applied = Tor.configureStorage(
                dir.resolve("state").toString(), dir.resolve("cache").toString());
        assertEquals(Tor.supported(), applied);
    }
}
