package io.myotis.node.api;

import io.myotis.api.ChainHandle;
import io.myotis.api.EngineConfig;
import io.myotis.api.EngineException;
import io.myotis.api.NetworkInfo;
import io.myotis.api.ports.EngineClPeerCache;
import io.myotis.api.ports.EnginePeerCache;
import io.myotis.api.ports.EnginePorts;
import io.myotis.api.ports.NodeKeyStore;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JavaMyotisEngineTest {

    static final class MemoryKeyStore implements NodeKeyStore {
        final Map<String, byte[]> keys = new HashMap<>();
        @Override public byte[] load(String networkName) { return keys.get(networkName); }
        @Override public void store(String networkName, byte[] secret32) { keys.put(networkName, secret32); }
    }

    private static EnginePorts testPorts(NodeKeyStore keyStore) {
        EnginePeerCache peerCache = new PortBridgesTest.FakePeerCache();
        EngineClPeerCache clCache = new PortBridgesTest.FakeClCache();
        return new EnginePorts(keyStore, peerCache, clCache, null, null, null, null);
    }

    @Test
    void canonicalNameResolvesAliases() {
        JavaMyotisEngine engine = new JavaMyotisEngine();
        assertEquals("gnosis", engine.canonicalNetworkName("xdai"));
        assertEquals("gnosis", engine.canonicalNetworkName("GBC"));
        assertEquals("mainnet", engine.canonicalNetworkName("Mainnet"));
        assertThrows(EngineException.class, () -> engine.canonicalNetworkName("holesky"));
        assertThrows(EngineException.class, () -> engine.canonicalNetworkName(null));
    }

    @Test
    void availableNetworksCarriesMetadata() {
        JavaMyotisEngine engine = new JavaMyotisEngine();
        List<NetworkInfo> nets = engine.availableNetworks();
        assertEquals(3, nets.size());
        NetworkInfo mainnet = nets.stream().filter(n -> n.name().equals("mainnet")).findFirst().orElseThrow();
        assertEquals(1L, mainnet.chainId());
        assertTrue(mainnet.hasEns());
        assertEquals(30303, mainnet.defaultElPort());
        assertEquals(8545, mainnet.defaultRpcPort());
        assertEquals(12, mainnet.secondsPerSlot());
        NetworkInfo gnosis = nets.stream().filter(n -> n.name().equals("gnosis")).findFirst().orElseThrow();
        assertEquals(100L, gnosis.chainId());
        assertFalse(gnosis.hasEns());
        assertEquals(5, gnosis.secondsPerSlot());
    }

    @Test
    void createDefaultsPortsGeneratesKeyAndRegisters() {
        JavaMyotisEngine engine = new JavaMyotisEngine();
        MemoryKeyStore keyStore = new MemoryKeyStore();
        EngineConfig config = new EngineConfig("gnosis", 0, 0, 0, null, false, 0, true, null);

        ChainHandle handle = engine.create(config, testPorts(keyStore));
        assertNotNull(handle);
        assertEquals("gnosis", handle.networkName());
        assertEquals(100L, handle.chainId());
        assertFalse(handle.isRunning());

        // A fresh 32-byte identity was generated and persisted through the port.
        assertEquals(32, keyStore.keys.get("gnosis").length);

        assertEquals(List.of("gnosis"), engine.hostedNetworks());
        assertEquals(handle, engine.get("gnosis"));
        assertNull(engine.get("mainnet"));

        // Same network twice is a programmer error.
        assertThrows(EngineException.class, () -> engine.create(config, testPorts(keyStore)));

        engine.stop("gnosis");
        assertTrue(engine.hostedNetworks().isEmpty());
    }

    @Test
    void createReusesStoredKey() {
        JavaMyotisEngine engine = new JavaMyotisEngine();
        MemoryKeyStore keyStore = new MemoryKeyStore();
        byte[] secret = new byte[32];
        secret[31] = 1; // valid non-zero scalar
        keyStore.keys.put("sepolia", secret.clone());

        engine.create(new EngineConfig("sepolia", 0, 0, 0, null, false, 0, true, null),
                testPorts(keyStore));
        // The stored key was used, not overwritten.
        assertEquals(1, keyStore.keys.get("sepolia")[31]);
        engine.shutdownAll();
    }

    @Test
    void createRejectsBadStoredKey() {
        JavaMyotisEngine engine = new JavaMyotisEngine();
        MemoryKeyStore keyStore = new MemoryKeyStore();
        keyStore.keys.put("mainnet", new byte[16]); // wrong length
        assertThrows(EngineException.class, () ->
                engine.create(new EngineConfig("mainnet", 0, 0, 0, null, false, 0, true, null),
                        testPorts(keyStore)));
    }
}
