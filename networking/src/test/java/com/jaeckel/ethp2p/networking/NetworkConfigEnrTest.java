package com.jaeckel.ethp2p.networking;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkConfigEnrTest {

    @Test
    void mainnetHasClPeerMultiaddrsFromEnrs() {
        var addrs = NetworkConfig.MAINNET.clPeerMultiaddrs();
        assertNotNull(addrs);
        // No count floor: the exact list, count included, is pinned by
        // NetworkConfigGnosisTest.mainnetPinsRoostFirst, and a floor here only
        // trips on the next legitimate prune (the 2026-09-13 one left 5 pins,
        // exactly at the old ">= 5"). What this test owns is dialability, checked
        // per entry below, so "not empty" is the only floor it needs: an empty
        // list would pass that loop vacuously.
        assertFalse(addrs.isEmpty(), "mainnet must pin at least one CL multiaddr");
        for (String ma : addrs) {
            // /dns4/ stays allowed alongside /ip4/ even though no current pin uses a
            // name (roost moved from a DynDNS name to the netcup relay literal): what
            // this test is actually protecting is DIALABILITY — a transport and a
            // peer id — not the address family.
            assertTrue(ma.startsWith("/ip4/") || ma.startsWith("/dns4/"),
                    "Multiaddr should start with /ip4/ or /dns4/: " + ma);
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
