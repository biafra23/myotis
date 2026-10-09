package com.jaeckel.ethp2p.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The generated identity constants follow the Gradle project version. The test
 * task passes the raw version in ({@code myotis.projectVersion},
 * core/build.gradle.kts) and this test derives the release version from it on
 * its own, so a stale generated file or a generator whose derivation goes wrong
 * fails here rather than shipping an engine that names the wrong release. Run it
 * through Gradle: outside it the property is missing and the test fails.
 */
class BuildInfoTest {

    @Test
    void releaseVersionIsTheGradleVersionWithoutItsSuffix() {
        String projectVersion = System.getProperty("myotis.projectVersion");
        assertNotNull(projectVersion, "run through Gradle: the test task passes myotis.projectVersion");
        int dash = projectVersion.indexOf('-');
        String expected = dash < 0 ? projectVersion : projectVersion.substring(0, dash);
        assertEquals(expected, BuildInfo.RELEASE_VERSION);
        assertTrue(expected.matches("\\d+\\.\\d+\\.\\d+"), "a MAJOR.MINOR.PATCH release version: " + expected);
    }

    @Test
    void helloClientIdIsMyotisSlashReleaseVersion() {
        // Dedicated myotis-serving nodes admit peers by matching "myotis" here,
        // and the Rust engine sends the same shape (myotis/<CARGO_PKG_VERSION>).
        assertEquals("myotis/" + BuildInfo.RELEASE_VERSION, BuildInfo.CLIENT_ID);
    }
}
