package com.jaeckel.ethp2p.consensus.libp2p;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The Lighthouse-ban regression: every host must negotiate a {@code /meshsub/}
 * stream opened toward it — that negotiation is what Lighthouse's
 * {@code does_not_support_gossipsub} Fatal report keys on — while joining no
 * light-client topic unless the separate topic switch is on.
 */
class BeaconP2PServiceGossipsubTest {

    private static final String MESHSUB = "/meshsub/1.1.0";

    private static String loopbackAddress(BeaconP2PService target) {
        return target.listenAddresses().stream()
                // jvm-libp2p reports the wildcard bind as /ip4/0.0.0.0/ or /ip6/::/;
                // either one is reachable on loopback.
                .map(a -> a.replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/").replace("/ip6/::/", "/ip4/127.0.0.1/"))
                .filter(a -> a.startsWith("/ip4/127.0.0.1/"))
                .findFirst()
                .orElseThrow();
    }

    @Test
    void restartCyclesLeaveNoGossipRouterThreadBehind() throws Exception {
        BeaconP2PService svc = new BeaconP2PService(null);
        for (int i = 0; i < 3; i++) {
            svc.start();
            assertTrue(gossipRouterThreads() >= 1, "router executor thread should exist while started");
            svc.close();
        }
        // shutdownNow() interrupts the idle worker; give it a moment to exit.
        long deadline = System.currentTimeMillis() + 5_000;
        while (gossipRouterThreads() > 0 && System.currentTimeMillis() < deadline) Thread.sleep(50);
        assertEquals(0, gossipRouterThreads(), "every close() must stop its gossip router executor");
    }

    private static long gossipRouterThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.isAlive() && t.getName().startsWith("beacon-gossip-router"))
                .count();
    }

    @Test
    void everyHostNegotiatesMeshsubWithoutJoiningTopics() throws Exception {
        BeaconP2PService target = new BeaconP2PService(null);
        BeaconP2PService observer = new BeaconP2PService(null);
        target.start();
        observer.start();
        try {
            String addr = loopbackAddress(target);
            assertEquals(MESHSUB, observer.probeProtocol(addr, MESHSUB).get(20, TimeUnit.SECONDS));
            assertTrue(target.subscribedGossipTopics().isEmpty(),
                    "protocol registration must not join any topic");

            // Control for the probe itself: a protocol nobody registered must fail
            // negotiation — the outcome that used to earn the Fatal report.
            ExecutionException refused = assertThrows(ExecutionException.class, () ->
                    observer.probeProtocol(addr, "/meshsub/9.9.9").get(20, TimeUnit.SECONDS));
            assertNotNull(refused.getCause(), "negotiation failure must carry a cause");
        } finally {
            observer.close();
            target.close();
        }
    }
}
