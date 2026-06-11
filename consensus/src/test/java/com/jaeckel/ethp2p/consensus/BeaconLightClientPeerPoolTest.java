package com.jaeckel.ethp2p.consensus;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The discovered CL peer pool ({@code clPeerMultiaddrs}) is fed continuously by discv5
 * and must stay bounded — an unbounded pool made every sync-committee period rotation
 * fan {@code updates_by_range} out across thousands of mostly-dead/non-light-client
 * nodes. {@link BeaconLightClient#addPeer} caps the pool at {@code MAX_CL_PEERS} and
 * evicts oldest-first, but never a peer with positive signal.
 */
class BeaconLightClientPeerPoolTest {

    private static BeaconLightClient newClient() {
        // Raw valid-length anchors; addPeer touches no network state and the
        // constructor doesn't start libp2p.
        byte[] root32 = new byte[32];
        byte[] fork4 = {0, 0, 0, 1};
        byte[] gvr32 = new byte[32];
        return new BeaconLightClient(
                List.of(), root32, 0L, fork4, gvr32,
                new BeaconSyncState(), null, null, null, 1_606_824_023L);
    }

    @SuppressWarnings("unchecked")
    private static List<String> pool(BeaconLightClient c) throws Exception {
        Field f = BeaconLightClient.class.getDeclaredField("clPeerMultiaddrs");
        f.setAccessible(true);
        return (List<String>) f.get(c);
    }

    private static int cap() throws Exception {
        Field f = BeaconLightClient.class.getDeclaredField("MAX_CL_PEERS");
        f.setAccessible(true);
        return (int) f.get(null);
    }

    private static String addr(int i) {
        return "/ip4/10.0." + (i / 256) + "." + (i % 256) + "/tcp/9000/p2p/16Uiu2HAm" + i;
    }

    @Test
    void poolStaysBoundedUnderFlood() throws Exception {
        BeaconLightClient c = newClient();
        int cap = cap();
        for (int i = 0; i < cap + 500; i++) {
            c.addPeer(addr(i));
        }
        assertTrue(pool(c).size() <= cap,
                "pool must not exceed MAX_CL_PEERS, was " + pool(c).size());
    }

    @Test
    void neverEvictsProvenOrLcConfirmedPeers() throws Exception {
        BeaconLightClient c = newClient();
        String proven = addr(1);
        String lc = addr(2);
        c.addPeer(proven);
        c.addPeer(lc);
        // Mark positive signal (the eviction guard reads these sets).
        c.setProvenCatchUpServers(Map.of(proven, 1700L));
        c.setProvenLightClient(List.of(lc));

        for (int i = 1000; i < 1000 + cap() + 500; i++) {
            c.addPeer(addr(i));
        }
        List<String> p = pool(c);
        assertTrue(p.contains(proven), "proven catch-up server must survive eviction");
        assertTrue(p.contains(lc), "LC-confirmed peer must survive eviction");
        assertTrue(p.size() <= cap());
    }

    @Test
    void evictedPeerCanBeRediscovered() throws Exception {
        BeaconLightClient c = newClient();
        for (int i = 0; i < cap() + 200; i++) {
            c.addPeer(addr(i));
        }
        // New peers insert near the front, so the oldest non-head adds drift to the
        // tail and evict first. addr(1) (the second add) is the tail-most → evicted;
        // re-discovery must then succeed (knownPeerAddrs was cleared for it on
        // eviction), not be silently deduped away forever.
        assertEquals(false, pool(c).contains(addr(1)), "tail-most old peer should be evicted");
        assertTrue(c.addPeer(addr(1)), "an evicted peer must be re-addable");
    }
}
