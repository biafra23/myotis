package com.jaeckel.ethp2p.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The generated identity constants follow the Gradle release version. The test
 * task passes that version in ({@code myotis.releaseVersion}, core/build.gradle.kts),
 * so a generator that drifts from {@code project.version} — or a stale generated
 * file — fails here rather than shipping an engine that names the wrong release.
 */
class BuildInfoTest {

    @Test
    void releaseVersionIsTheGradleVersion() {
        String gradleVersion = System.getProperty("myotis.releaseVersion");
        assertNotNull(gradleVersion, "the test task must pass myotis.releaseVersion");
        assertEquals(gradleVersion, BuildInfo.RELEASE_VERSION);
    }

    @Test
    void helloClientIdIsMyotisSlashReleaseVersion() {
        // Dedicated myotis-serving nodes admit peers by matching "myotis" here,
        // and the Rust engine sends the same shape (myotis/<CARGO_PKG_VERSION>).
        assertEquals("myotis/" + BuildInfo.RELEASE_VERSION, BuildInfo.CLIENT_ID);
    }
}
