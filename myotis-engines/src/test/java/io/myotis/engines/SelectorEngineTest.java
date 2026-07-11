package io.myotis.engines;

import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.MyotisEngine;
import io.myotis.api.ports.BootstrapPeer;
import io.myotis.api.ports.CachedPeerInfo;
import io.myotis.api.ports.EngineClPeerCache;
import io.myotis.api.ports.EnginePeerCache;
import io.myotis.api.ports.EnginePorts;
import io.myotis.api.ports.NodeKeyStore;
import io.myotis.api.ports.ServedRange;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Selector semantics that hold with or without the native library. Choice state is
 * process-global ({@link Engines}), so every test restores the default afterwards.
 */
class SelectorEngineTest {

    @BeforeAll
    static void registerBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterEach
    void resetChoice() {
        Engines.select("java");
        // The engine is a process-global singleton: if an assertion fired between a
        // test's create() and its stop(), the network would stay hosted and poison
        // later tests. shutdownAll() clears every hosted network on both engines.
        Engines.engine().shutdownAll();
    }

    // --- minimal working ports so the JAVA path can actually create ---
    static final class MemoryKeyStore implements NodeKeyStore {
        final Map<String, byte[]> keys = new HashMap<>();
        @Override public byte[] load(String n) { return keys.get(n); }
        @Override public void store(String n, byte[] s) { keys.put(n, s); }
    }
    static final class NoopPeerCache implements EnginePeerCache {
        @Override public void add(String host, int port, String publicKeyHex, boolean snap) {}
        @Override public void recordSnapServed(String host, int port) {}
        @Override public void recordSnapFailure(String host, int port) {}
        @Override public List<CachedPeerInfo> load() { return List.of(); }
        @Override public void close() {}
    }
    static final class NoopClPeerCache implements EngineClPeerCache {
        @Override public List<String> load() { return List.of(); }
        @Override public void add(String multiaddr) {}
        @Override public void markFailure(String multiaddr) {}
        @Override public List<ServedRange> servedRanges() { return List.of(); }
        @Override public void recordServed(String multiaddr, long low, long high) {}
        @Override public List<BootstrapPeer> bootstrapPeers() { return List.of(); }
        @Override public void recordBootstrap(String multiaddr, long period) {}
        @Override public List<String> lightClientConfirmed() { return List.of(); }
        @Override public List<String> lightClientDenied() { return List.of(); }
        @Override public void markLightClientBatch(List<String> confirmed, List<String> denied) {}
        @Override public void close() {}
    }

    private static EnginePorts ports() {
        return new EnginePorts(new MemoryKeyStore(), new NoopPeerCache(), new NoopClPeerCache(),
                null, null, null, null);
    }

    private static EngineConfig config(String network) {
        // Non-default ports so a create-only test can't collide with a live daemon.
        return new EngineConfig(network, 42303, 42900, 42545, null, false, 0, true, null);
    }

    @Test
    void defaultChoiceIsJavaAndCatalogAnswers() {
        assertEquals("java", Engines.choice());
        MyotisEngine e = Engines.engine();
        assertEquals(3, e.availableNetworks().size());
        assertEquals("gnosis", e.canonicalNetworkName("xdai"));
    }

    @Test
    void invalidChoiceFallsBackToJava() {
        Engines.select("cobol");
        assertEquals("java", Engines.choice());
    }

    @Test
    void explicitRustWithoutLibraryThrowsNamedError() {
        assumeRustUnavailable();
        Engines.select("rust");
        MyotisEngine e = Engines.engine();
        EngineException ex = assertThrows(EngineException.class, e::availableNetworks);
        assertTrue(ex.getMessage().contains("myotis.engine=rust"),
                "unexpected message: " + ex.getMessage());
        assertThrows(EngineException.class, () -> e.create(config("mainnet"), ports()));
    }

    @Test
    void autoWithoutLibraryUsesJava() {
        assumeRustUnavailable();
        Engines.select("auto");
        assertEquals(3, Engines.engine().availableNetworks().size());
    }

    @Test
    void createRoutesAndOwnershipTracksAcrossStopAndSwitch() {
        MyotisEngine e = Engines.engine();
        // java-owned create; get() routes through recorded ownership.
        assertNull(e.get("mainnet"));
        var handle = e.create(config("mainnet"), ports());
        assertNotNull(handle);
        assertNotNull(e.get("mainnet"));
        assertTrue(e.hostedNetworks().contains("mainnet"));

        // Flipping the choice must NOT reroute an existing network's get/stop.
        Engines.select("auto");
        assertNotNull(e.get("mainnet"));
        e.stop("mainnet");
        assertNull(e.get("mainnet"));
        assertTrue(e.hostedNetworks().isEmpty());
    }

    @Test
    void engineKindForReportsOwnerAndNullWhenNotHosted() {
        assertNull(Engines.engineKindFor("mainnet"));
        Engines.engine().create(config("mainnet"), ports());
        assertEquals("java", Engines.engineKindFor("mainnet"));
        Engines.engine().stop("mainnet");
        assertNull(Engines.engineKindFor("mainnet"));
        // Never throws: null, aliases, and unknown names all answer quietly.
        assertNull(Engines.engineKindFor(null));
        assertNull(Engines.engineKindFor("no-such-network"));
    }

    @Test
    void engineKindForResolvesAliases() {
        Engines.engine().create(config("gnosis"), ports());
        assertEquals("java", Engines.engineKindFor("xdai"));
    }

    @Test
    void autoCreateFallsBackToJavaWhenRustCannotHost() {
        // With the library: rust create() fails (R0) → auto falls back to java.
        // Without: auto resolves straight to java. Either way create() must succeed.
        Engines.select("auto");
        MyotisEngine e = Engines.engine();
        var handle = e.create(config("gnosis"), ports());
        assertNotNull(handle);
        assertNotNull(e.get("gnosis"));
        e.stop("gnosis");
    }

    private static void assumeRustUnavailable() {
        org.junit.jupiter.api.Assumptions.assumeTrue(!RustMyotisEngine.isAvailable(),
                "libmyotis_engine IS available — the without-library selector paths "
                        + "are covered on cargo-less machines/CI");
    }
}
