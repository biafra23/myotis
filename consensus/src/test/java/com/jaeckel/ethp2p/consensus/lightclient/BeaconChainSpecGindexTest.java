package com.jaeckel.ethp2p.consensus.lightclient;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/** Rust twin: {@code rust/myotis-consensus/src/spec.rs} unit tests. */
class BeaconChainSpecGindexTest {

    /** Same expectations the Rust spec helpers encode. */
    @Test
    void depthDerivedGindicesMatchTheSpec() {
        assertEquals(54, BeaconChainSpec.syncCommitteeGindex(5));
        assertEquals(55, BeaconChainSpec.nextSyncCommitteeGindex(5));
        assertEquals(105, BeaconChainSpec.finalizedRootGindex(6));
        // Electra depths
        assertEquals(86, BeaconChainSpec.syncCommitteeGindex(6));
        assertEquals(87, BeaconChainSpec.nextSyncCommitteeGindex(6));
        assertEquals(169, BeaconChainSpec.finalizedRootGindex(7));
    }

    /**
     * The Gloas constants against the spec's own values, and the reason they are
     * constants: the depth-derived formulas miss them.
     */
    @Test
    void gloasGindicesAreConstantsNotDepthDerived() {
        assertEquals(735, BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS);
        assertEquals(2945, BeaconChainSpec.CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS);
        assertEquals(2946, BeaconChainSpec.NEXT_SYNC_COMMITTEE_GINDEX_GLOAS);
        assertEquals(2856, BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_GLOAS);
        assertEquals(812, BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_DENEB);

        assertEquals(11, BeaconChainSpec.GLOAS_EXECUTION_BRANCH_LEN);
        assertEquals(11, BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN);
        assertEquals(11, BeaconChainSpec.gindexDepth(BeaconChainSpec.NEXT_SYNC_COMMITTEE_GINDEX_GLOAS));
        assertEquals(9, BeaconChainSpec.GLOAS_FINALITY_BRANCH_LEN);
        assertEquals(9, BeaconChainSpec.gindexDepth(BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_DENEB));
        assertEquals(BeaconChainSpec.EXECUTION_PAYLOAD_DEPTH,
                BeaconChainSpec.gindexDepth(BeaconChainSpec.EXECUTION_PAYLOAD_GINDEX));

        assertNotEquals(BeaconChainSpec.CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS, BeaconChainSpec.syncCommitteeGindex(11));
        assertNotEquals(BeaconChainSpec.NEXT_SYNC_COMMITTEE_GINDEX_GLOAS, BeaconChainSpec.nextSyncCommitteeGindex(11));
        assertNotEquals(BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS, BeaconChainSpec.finalizedRootGindex(9));
    }
}
