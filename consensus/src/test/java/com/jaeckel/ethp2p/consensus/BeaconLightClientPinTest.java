package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for {@link BeaconLightClient#verifyCheckpointPin(BeaconBlockHeader, byte[])}.
 *
 * <p>Before the pin was enforced, the light client accepted any internally-consistent
 * {@code LightClientBootstrap} the peer returned, regardless of which block it was
 * anchored to. These tests lock in that we now reject a bootstrap whose header does
 * not hash to the committed checkpoint root.
 */
class BeaconLightClientPinTest {

    /** Fixture header — arbitrary slot / indices; the roots are what {@link BeaconBlockHeader#hashTreeRoot()} feeds on. */
    private static BeaconBlockHeader fixtureHeader() {
        byte[] parent = new byte[32];
        byte[] state = new byte[32];
        byte[] body = new byte[32];
        // Distinguishable roots so a byte-flip elsewhere can't silently match.
        for (int i = 0; i < 32; i++) {
            parent[i] = (byte) (0x10 + i);
            state[i]  = (byte) (0x40 + i);
            body[i]   = (byte) (0x80 + i);
        }
        return new BeaconBlockHeader(14158720L, 1357792L, parent, state, body);
    }

    @Test
    void acceptsMatchingRoot() {
        BeaconBlockHeader header = fixtureHeader();
        byte[] expected = header.hashTreeRoot();
        assertDoesNotThrow(() -> BeaconLightClient.verifyCheckpointPin(header, expected));
    }

    @Test
    void rejectsFlippedRoot() {
        BeaconBlockHeader header = fixtureHeader();
        byte[] flipped = header.hashTreeRoot();
        flipped[0] ^= 0x01;
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> BeaconLightClient.verifyCheckpointPin(header, flipped));
        assertTrue(ex.getMessage().contains("does not match"),
                "message should explain the mismatch; got: " + ex.getMessage());
    }

    @Test
    void rejectsWhollyDifferentRoot() {
        BeaconBlockHeader header = fixtureHeader();
        byte[] different = new byte[32];
        for (int i = 0; i < 32; i++) different[i] = (byte) 0xff;
        assertThrows(IllegalStateException.class,
                () -> BeaconLightClient.verifyCheckpointPin(header, different));
    }
}
