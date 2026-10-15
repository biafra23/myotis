package io.myotis.engine.ports;

import io.myotis.api.ports.EnginePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetworkFilesAndDefaultPortsTest {

    @Test
    void mainnetKeepsTheLegacyNamesAndOtherNetworksGetASuffix() {
        Path dir = Path.of("d");
        assertEquals(dir.resolve("nodekey.hex"), NetworkFiles.nodeKey(dir, "mainnet"));
        assertEquals(dir.resolve("peers.cache"), NetworkFiles.peerCache(dir, "mainnet"));
        assertEquals(dir.resolve("cl-peers.cache"), NetworkFiles.clPeerCache(dir, "mainnet"));
        assertEquals(dir.resolve("sync-state.snapshot"), NetworkFiles.syncSnapshot(dir, "mainnet"));
        assertEquals(dir.resolve("nodekey-gnosis.hex"), NetworkFiles.nodeKey(dir, "gnosis"));
        assertEquals(dir.resolve("peers-gnosis.cache"), NetworkFiles.peerCache(dir, "gnosis"));
        assertEquals(dir.resolve("cl-peers-sepolia.cache"), NetworkFiles.clPeerCache(dir, "sepolia"));
        assertEquals(dir.resolve("sync-state-sepolia.snapshot"), NetworkFiles.syncSnapshot(dir, "sepolia"));
        assertThrows(IllegalArgumentException.class, () -> NetworkFiles.suffix(""));
    }

    @Test
    void aNameTheEngineWouldCanonicalizeIsRefusedNotGivenItsOwnFiles(@TempDir Path dir) {
        // The engine turns "Mainnet" into mainnet and would read nodekey.hex; these
        // would have named nodekey-Mainnet.hex. Applied or refused, never silently different.
        assertThrows(IllegalArgumentException.class, () -> NetworkFiles.suffix("Mainnet"));
        assertThrows(IllegalArgumentException.class, () -> NetworkFiles.suffix("main net"));
        assertThrows(IllegalArgumentException.class,
                () -> DefaultEnginePorts.forNetwork(dir, dir, "Gnosis", null));
    }

    @Test
    void theDirectoriesAreCreatedOnAFreshInstall(@TempDir Path root) {
        Path keys = root.resolve("a/keys");
        Path caches = root.resolve("b/caches");
        try (DefaultEnginePorts d = DefaultEnginePorts.forNetwork(keys, caches, "sepolia", null)) {
            assertTrue(keys.toFile().isDirectory());
            assertTrue(caches.toFile().isDirectory());
            d.keyStore().store("sepolia", new byte[32]);
            d.peerCache().add("1.2.3.4", 30303, "0xab", false);
            d.clPeerCache().add("/ip4/1.2.3.4/tcp/9000/p2p/x");
        }
        assertTrue(keys.resolve("nodekey-sepolia.hex").toFile().isFile());
        assertTrue(caches.resolve("peers-sepolia.cache").toFile().isFile(), "the EL cache's writer was drained by close()");
        assertTrue(caches.resolve("cl-peers-sepolia.cache").toFile().isFile());
        try (DefaultEnginePorts again = DefaultEnginePorts.forNetwork(keys, caches, "sepolia", null)) {
            assertEquals(caches.resolve("peers-sepolia.cache"), again.peerCacheFile());
        }
    }

    @Test
    void theDefaultsAreWiredToTheLayout(@TempDir Path keys, @TempDir Path caches) {
        List<String> dns = List.of("9.9.9.9");
        try (DefaultEnginePorts d = DefaultEnginePorts.forNetwork(keys, caches, "gnosis", () -> dns)) {
            assertEquals(caches.resolve("peers-gnosis.cache"), d.peerCache().cacheFile());
            assertEquals(caches.resolve("cl-peers-gnosis.cache"), d.clPeerCache().cacheFile());
            assertEquals(caches.resolve("sync-state-gnosis.snapshot"), d.syncSnapshot());
            assertEquals("gnosis", d.network());
            d.keyStore().store("gnosis", new byte[32]);
            assertTrue(keys.resolve("nodekey-gnosis.hex").toFile().exists());
            EnginePorts ports = d.ports();
            assertSame(d.keyStore(), ports.keyStore());
            assertSame(d.peerCache(), ports.peerCache());
            assertSame(d.clPeerCache(), ports.clPeerCache());
            assertEquals(dns, ports.dnsServers().dnsServerIps());
            assertNotNull(ports.httpGateway());
            assertNull(ports.logger(), "the engine's default logger");
            assertNull(ports.clock(), "the engine's default clock");
        }
        try (DefaultEnginePorts noDns = DefaultEnginePorts.forNetwork(keys, caches, "mainnet", null)) {
            assertNull(noDns.ports().dnsServers(), "no DNS servers → the resolver's default");
        }
    }
}
