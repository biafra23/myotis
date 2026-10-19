package io.myotis.engine.natives;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.myotis.engines.rust.RustMyotisEngine;
import org.junit.jupiter.api.Test;

/**
 * A desktop consumer's view of the engine library: the engine's bindings and this
 * host's natives jar on the classpath, no library path set (the build file's test task).
 * The engine must load from the jar's resource, not be reported unavailable.
 */
class NativesJarLoadTest {

    @Test
    void theEngineLoadsFromTheNativesJarAlone() {
        String entry = System.getProperty("myotis.natives.expectedEntry");
        assertNotNull(getClass().getClassLoader().getResource(entry),
                entry + " is not on the test classpath: the natives jar is missing or laid out differently");
        assertNull(System.getProperty("myotis.engine.lib"), "a library override would bypass the jar");

        assertTrue(RustMyotisEngine.isAvailable(),
                "the Rust engine did not load from " + entry + " on the classpath (see the log for JNA's reason)");
        assertTrue(new RustMyotisEngine().availableNetworks().stream().anyMatch(n -> n.name().equals("sepolia")),
                "the loaded engine's catalog has no sepolia");
    }
}
