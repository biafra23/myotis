package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The header-chain walk's anchor choice ({@link VerifiedAccountQuery#walkAnchor}), twin of the
 * Rust {@code el::verify} ladder tests: the walk ends at the optimistic head, which must be at
 * or ABOVE the peer's block — a walk can only prove headers below an attested hash.
 */
class WalkAnchorTest {

    private static final byte[] HASH = new byte[32];
    static {
        HASH[0] = (byte) 0xe1;
    }

    @Test
    void aPeerBlockAtOrBelowTheOptimisticHeadEndsTheWalkThere() {
        var opt = new BeaconSyncState.OptimisticExecution(264, 21_000_064, HASH);
        for (long peerBlock : new long[] {21_000_010, 21_000_064}) {
            VerifiedAccountQuery.WalkAnchor anchor = VerifiedAccountQuery.walkAnchor(peerBlock, opt);
            assertNotNull(anchor, "peer block " + peerBlock);
            assertEquals(21_000_064, anchor.blockNumber());
            assertArrayEquals(HASH, anchor.blockHash());
            assertEquals(264, anchor.slot());
        }
    }

    @Test
    void nothingAnchorsAPeerBlockPastTheOptimisticHead() {
        var opt = new BeaconSyncState.OptimisticExecution(264, 21_000_064, HASH);
        assertNull(VerifiedAccountQuery.walkAnchor(21_000_065, opt));
    }

    @Test
    void noOptimisticHeadAnchorsNothing() {
        assertNull(VerifiedAccountQuery.walkAnchor(100, null));
        assertNull(VerifiedAccountQuery.walkAnchor(100,
                new BeaconSyncState.OptimisticExecution(0, 0, null)));
        assertNull(VerifiedAccountQuery.walkAnchor(0,
                new BeaconSyncState.OptimisticExecution(5, 0, HASH)));
    }
}
