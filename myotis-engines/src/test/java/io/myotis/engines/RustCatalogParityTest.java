package io.myotis.engines;

import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.node.api.JavaMyotisEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Live parity between the two engines' catalogs, THROUGH the real JNI boundary.
 * Self-skips when libmyotis_engine isn't available (cargo-less machine / CI) — the
 * schema is still pinned there by {@link NetworksJsonGoldenTest} + the Rust golden test.
 */
class RustCatalogParityTest {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
        assumeTrue(RustMyotisEngine.isAvailable(),
                "libmyotis_engine not on java.library.path — skipping live parity tests");
    }

    @Test
    void availableNetworksMatchTheJavaEngine() {
        assertEquals(new JavaMyotisEngine().availableNetworks(),
                new RustMyotisEngine().availableNetworks());
    }

    @Test
    void canonicalNamesMatchTheJavaEngine() {
        JavaMyotisEngine java = new JavaMyotisEngine();
        RustMyotisEngine rust = new RustMyotisEngine();
        for (String name : new String[]{"mainnet", "MAINNET", "gnosis", "gbc", "xdai", "sepolia"}) {
            assertEquals(java.canonicalNetworkName(name), rust.canonicalNetworkName(name),
                    "alias: " + name);
        }
        assertThrows(EngineException.class, () -> rust.canonicalNetworkName("holesky"));
        assertThrows(EngineException.class, () -> java.canonicalNetworkName("holesky"));
        assertThrows(EngineException.class, () -> rust.canonicalNetworkName("nope"));
        // Whitespace parity: NEITHER engine trims — both must reject.
        assertThrows(EngineException.class, () -> rust.canonicalNetworkName(" mainnet "));
        assertThrows(EngineException.class, () -> java.canonicalNetworkName(" mainnet "));
    }

    @Test
    void createRejectsNullConfig() {
        RustMyotisEngine rust = new RustMyotisEngine();
        assertThrows(EngineException.class, () -> rust.create(null, null));
    }

    @Test
    void createRejectsUnknownNetwork() {
        // All three CANONICAL networks (mainnet, sepolia, gnosis) are now hosted,
        // so the remaining rejection path is a truly-unknown network name: it
        // never reaches nativeCreate — canonicalNetworkName() rejects it first,
        // raising a named EngineException (auto mode falls back to Java).
        RustMyotisEngine rust = new RustMyotisEngine();
        EngineConfig cfg = new EngineConfig(
                "not-a-real-network", 0, 0, 0, null, false, 0, true, "/tmp/myotis-test");
        EngineException e = assertThrows(EngineException.class,
                () -> rust.create(cfg, null));
        org.junit.jupiter.api.Assertions.assertTrue(
                e.getMessage().contains("not-a-real-network"),
                "unexpected message: " + e.getMessage());
    }
}
