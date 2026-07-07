package com.jaeckel.ethp2p.consensus.libp2p;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the libp2p restart behavior BeaconLightClient.pause()/resume() relies on:
 * one BeaconP2PService instance must survive start → close → start → close in a
 * single process (fresh Host, bindings, and keepalive executor per start), and
 * close must be idempotent.
 */
class BeaconP2PServiceRestartTest {

    @Test
    void startCloseStartClose() {
        BeaconP2PService svc = new BeaconP2PService(null);

        svc.start();
        List<BeaconP2PService.PeerInfo> peers = svc.getConnectedPeers();
        assertTrue(peers.isEmpty(), "fresh local host has no peers");
        svc.close();

        // Between pause and resume the host is gone: peer queries fail fast/empty.
        assertEquals(0, svc.getConnectedPeers().size());

        // Second start must build a fresh host (the pause→resume path).
        svc.start();
        assertEquals(0, svc.getConnectedPeers().size());
        svc.close();

        // Double-close is a no-op.
        svc.close();
    }
}
