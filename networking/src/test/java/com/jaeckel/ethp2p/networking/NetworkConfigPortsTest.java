package com.jaeckel.ethp2p.networking;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Per-network default ports must be distinct across all networks so several
 * stacks can run in one process without colliding, and mainnet must keep its
 * historical 30303/9000/8545 (proven path).
 */
class NetworkConfigPortsTest {

    @Test
    void mainnetKeepsHistoricalPorts() {
        NetworkConfig m = NetworkConfig.MAINNET;
        assertEquals(30303, m.defaultElPort());
        assertEquals(9000, m.defaultDiscv5Port());
        assertEquals(8545, m.defaultRpcPort());
    }

    @Test
    void gnosisRpcPortIsDistinct() {
        assertEquals(8546, NetworkConfig.GNOSIS.defaultRpcPort());
        assertEquals(30304, NetworkConfig.GNOSIS.defaultElPort());
        assertEquals(9001, NetworkConfig.GNOSIS.defaultDiscv5Port());
    }

    @Test
    void allNetworksHaveDistinctPortsAcrossEveryFamily() {
        List<NetworkConfig> nets = NetworkConfig.allNetworks();
        assertNoDuplicates(nets.stream().map(NetworkConfig::defaultElPort).toList(), "EL/discv4");
        assertNoDuplicates(nets.stream().map(NetworkConfig::defaultDiscv5Port).toList(), "discv5");
        assertNoDuplicates(nets.stream().map(NetworkConfig::defaultRpcPort).toList(), "RPC");
    }

    @Test
    void allNetworksIncludesTheKnownConfigs() {
        List<NetworkConfig> nets = NetworkConfig.allNetworks();
        assertTrue(nets.contains(NetworkConfig.MAINNET));
        assertTrue(nets.contains(NetworkConfig.GNOSIS));
        assertTrue(nets.contains(NetworkConfig.SEPOLIA));
    }

    private static void assertNoDuplicates(List<Integer> ports, String label) {
        Set<Integer> seen = new HashSet<>();
        List<Integer> dupes = new ArrayList<>();
        for (int p : ports) {
            if (!seen.add(p)) dupes.add(p);
        }
        assertTrue(dupes.isEmpty(), label + " ports collide: " + dupes + " in " + ports);
    }
}
