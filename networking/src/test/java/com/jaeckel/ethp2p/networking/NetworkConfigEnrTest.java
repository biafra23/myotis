package com.jaeckel.ethp2p.networking;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkConfigEnrTest {

    @Test
    void mainnetHasClPeerMultiaddrsFromEnrs() {
        var addrs = NetworkConfig.MAINNET.clPeerMultiaddrs();
        assertNotNull(addrs);
        // We have 17 ENRs; some may lack tcp port, but most should convert
        assertTrue(addrs.size() >= 5, "Expected at least 5 CL multiaddrs, got " + addrs.size());
        for (String ma : addrs) {
            assertTrue(ma.startsWith("/ip4/"), "Multiaddr should start with /ip4/: " + ma);
            assertTrue(ma.contains("/tcp/"), "Multiaddr should contain /tcp/: " + ma);
            assertTrue(ma.contains("/p2p/"), "Multiaddr should contain /p2p/: " + ma);
        }
    }

    @Test
    void clPeerMultiaddrsAreUnique() {
        var addrs = NetworkConfig.MAINNET.clPeerMultiaddrs();
        assertEquals(addrs.size(), addrs.stream().distinct().count());
    }
}
