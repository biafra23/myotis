package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.eth.messages.HelloMessage;
import com.jaeckel.ethp2p.networking.eth.messages.HelloMessage.Capability;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * snap/1 and snap/2 (EIP-8189) side by side: what our Hello offers and which
 * version a connection then runs. Twin of the Rust engine's
 * {@code negotiate_snap_runs_the_highest_shared_version} and
 * {@code hello_round_trip}.
 *
 * <p>snap/2 leaves the messages the verified reads use (GetAccountRange,
 * GetStorageRanges, GetByteCodes) unchanged, so a peer is a snap peer on either
 * version. Matching only snap/1, as the handler once did, turns every
 * snap/2-only node into "no snap" — reth implements snap/2 and no snap/1.
 */
class SnapVersionNegotiationTest {

    private static final Capability ETH_69 = new Capability("eth", 69);

    private static Capability snap(int version) {
        return new Capability("snap", version);
    }

    @Test
    void helloOffersBothSnapVersionsAscendingAfterEth() {
        HelloMessage hello = HelloMessage.decode(HelloMessage.encode(Bytes.repeat((byte) 0x11, 64), 30303));
        assertEquals(List.of(
                new Capability("eth", 66), new Capability("eth", 67),
                new Capability("eth", 68), ETH_69,
                snap(1), snap(2)), hello.capabilities);
    }

    @Test
    void aPeerWithOneSnapVersionRunsThatVersion() {
        assertEquals(1, EthHandler.negotiateSnapVersion(List.of(ETH_69, snap(1))));
        assertEquals(2, EthHandler.negotiateSnapVersion(List.of(ETH_69, snap(2))));
    }

    @Test
    void aPeerWithBothRunsTheHigherWhateverTheOrder() {
        assertEquals(2, EthHandler.negotiateSnapVersion(List.of(ETH_69, snap(1), snap(2))));
        assertEquals(2, EthHandler.negotiateSnapVersion(List.of(snap(2), ETH_69, snap(1))));
    }

    @Test
    void aVersionWeDoNotSpeakIsNotShared() {
        assertEquals(1, EthHandler.negotiateSnapVersion(List.of(ETH_69, snap(1), snap(3))));
        assertEquals(0, EthHandler.negotiateSnapVersion(List.of(ETH_69, snap(3))));
        assertEquals(0, EthHandler.negotiateSnapVersion(List.of(ETH_69)));
    }
}
