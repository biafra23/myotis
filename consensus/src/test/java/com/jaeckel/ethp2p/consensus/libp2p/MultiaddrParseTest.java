package com.jaeckel.ethp2p.consensus.libp2p;

import io.libp2p.core.PeerId;
import io.libp2p.core.multiformats.Multiaddr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that jvm-libp2p can parse the multiaddr formats used in NetworkConfig,
 * particularly the CIDv1 base32 peer IDs used by Lighthouse.
 */
class MultiaddrParseTest {

    /** The local Lighthouse multiaddr from NetworkConfig. */
    static final String LIGHTHOUSE_MULTIADDR =
            "/ip4/188.68.32.16/tcp/9100/p2p/16Uiu2HAm5AH9YsNjHqLsQofyd1WUBVxyPY5cPC8Sec3gVwJPU7wD";

    /** An ENR-resolved multiaddr (base58 Qm... style peer ID). */
    static final String ENR_MULTIADDR =
            "/ip4/3.147.37.0/tcp/9000/p2p/16Uiu2HAkw949aUhLTe7QPCG9N8wfELtNVwzXXYXuuwknkA582bcX";

    @Test
    void parseLighthouseMultiaddr() {
        Multiaddr addr = new Multiaddr(LIGHTHOUSE_MULTIADDR);
        PeerId peerId = addr.getPeerId();
        assertNotNull(peerId, "PeerId should not be null for Lighthouse multiaddr");
        System.out.println("Lighthouse PeerId: " + peerId);
        System.out.println("Lighthouse multiaddr parsed successfully: " + addr);
    }

    @Test
    void parseEnrMultiaddr() {
        Multiaddr addr = new Multiaddr(ENR_MULTIADDR);
        PeerId peerId = addr.getPeerId();
        assertNotNull(peerId, "PeerId should not be null for ENR multiaddr");
        System.out.println("ENR PeerId: " + peerId);
        System.out.println("ENR multiaddr parsed successfully: " + addr);
    }

    @Test
    void bothPeerIdsAreDifferent() {
        PeerId lhPeerId = new Multiaddr(LIGHTHOUSE_MULTIADDR).getPeerId();
        PeerId enrPeerId = new Multiaddr(ENR_MULTIADDR).getPeerId();
        assertNotNull(lhPeerId);
        assertNotNull(enrPeerId);
        assertNotEquals(lhPeerId, enrPeerId);
    }
}
