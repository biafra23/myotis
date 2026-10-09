package com.jaeckel.ethp2p.consensus.libp2p;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jaeckel.ethp2p.core.BuildInfo;
import identify.pb.IdentifyOuterClass;
import io.libp2p.core.crypto.KeyKt;
import io.libp2p.core.crypto.KeyType;
import io.libp2p.core.crypto.PubKey;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Our Identify answer. It used to be jvm-libp2p's fallback — agent "jvm/0.1",
 * no key, no protocols — because the binding is added after the host is built.
 * Now it names this release, {@code myotis/<release version>-java} (the Rust
 * engine's is {@code myotis/<release version>-rs}), and lists exactly the
 * protocols the host answers: never one it has no responder for, such as
 * light_client_updates_by_range or beacon_blocks_by_range (see registerBinding).
 */
class BeaconP2PServiceIdentifyTest {

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
    void agentNamesThisRelease() {
        assertEquals("myotis/" + BuildInfo.RELEASE_VERSION + "-java", BeaconP2PService.AGENT_VERSION);
    }

    @Test
    void messageCarriesAgentProtocolVersionAndKey() {
        PubKey key = KeyKt.generateKeyPair(KeyType.SECP256K1).getSecond();
        IdentifyOuterClass.Identify msg = BeaconP2PService.identifyMessage(key, List.of());
        assertEquals(BeaconP2PService.AGENT_VERSION, msg.getAgentVersion());
        assertEquals("eth2/1.0.0", msg.getProtocolVersion());
        assertArrayEquals(key.bytes(), msg.getPublicKey().toByteArray());
        assertEquals(0, msg.getListenAddrsCount(), "a wildcard listener has nothing to advertise");
    }

    @Test
    void peerSeesOurAgentAndOnlyTheProtocolsWeAnswer() throws Exception {
        BeaconP2PService target = new BeaconP2PService(null);
        BeaconP2PService observer = new BeaconP2PService(null);
        target.start();
        observer.start();
        try {
            String addr = loopbackAddress(target);
            observer.queryIdentify(addr).get(20, TimeUnit.SECONDS);

            assertEquals(BeaconP2PService.AGENT_VERSION, observer.cachedAgent(addr),
                    "the observer must have read our agent off the wire");

            String targetId = addr.substring(addr.indexOf("/p2p/") + "/p2p/".length());
            List<String> protocols = observer.getConnectedPeers().stream()
                    .filter(p -> p.peerId().equals(targetId))
                    .findFirst()
                    .orElseThrow()
                    .protocols();
            assertNotNull(protocols);
            assertEquals(protocols.stream().distinct().count(), protocols.size(), "no duplicates");

            // Exactly our own protocols: Identify plus every req/resp binding
            // registered with a responder, and nothing else.
            Set<String> ours = protocols.stream()
                    .filter(p -> !p.startsWith("/meshsub/"))
                    .collect(Collectors.toSet());
            assertEquals(Set.of(
                    "/ipfs/id/1.0.0",
                    BeaconP2PService.STATUS, BeaconP2PService.STATUS_V1,
                    BeaconP2PService.PING, BeaconP2PService.METADATA, BeaconP2PService.METADATA_V3,
                    BeaconP2PService.GOODBYE,
                    BeaconP2PService.BOOTSTRAP, BeaconP2PService.FINALITY, BeaconP2PService.OPTIMISTIC,
                    BeaconP2PService.BLOCKS_BY_ROOT, BeaconP2PService.DATA_COLUMN_SIDECARS_BY_ROOT,
                    BeaconP2PService.EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT), ours);
            assertFalse(ours.contains(BeaconP2PService.UPDATES), "updates_by_range has no responder");
            assertFalse(ours.contains(BeaconP2PService.BLOCKS_BY_RANGE), "blocks_by_range has no responder");
            assertEquals(Boolean.FALSE, observer.servesLightClientUpdates(addr));

            // Gossip's versions are jvm-libp2p's to choose; Lighthouse needs
            // /meshsub/1.1.0 among them (BeaconP2PServiceGossipsubTest).
            assertTrue(protocols.contains("/meshsub/1.1.0"), "gossipsub must be advertised: " + protocols);
        } finally {
            observer.close();
            target.close();
        }
    }
}
