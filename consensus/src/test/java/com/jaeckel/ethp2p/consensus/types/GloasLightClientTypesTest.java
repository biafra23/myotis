package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.core.consensus.LcFork;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Gloas light-client decoders (consensus-specs v1.7.0-beta.2, mainnet preset).
 * Rust twin: {@code rust/myotis-consensus/src/types.rs} — its unit tests
 * ({@code gloas_sizes_are_exact}, {@code gloas_and_pre_gloas_sizes_do_not_collide}) and,
 * for the size bound, the compile-time asserts beside {@code MIN_PRE_GLOAS_HEADER_SIZE}.
 */
class GloasLightClientTypesTest {

    /**
     * The Gloas sizes are the spec's, and a Gloas decoder takes exactly that many
     * bytes — one short or one long is a rejection, never a silently ignored tail.
     */
    @Test
    void gloasSizesAreExact() {
        assertEquals(496, LightClientHeader.GLOAS_SIZE);
        assertEquals(25472, LightClientBootstrap.GLOAS_SIZE);
        assertEquals(26424, LightClientUpdate.GLOAS_SIZE);
        assertEquals(1448, LightClientFinalityUpdate.GLOAS_SIZE);
        for (int n : new int[]{LightClientHeader.GLOAS_SIZE - 1, LightClientHeader.GLOAS_SIZE + 1}) {
            assertThrows(IllegalArgumentException.class, () -> LightClientHeader.decodeGloas(new byte[n]));
        }
        for (int n : new int[]{LightClientBootstrap.GLOAS_SIZE - 1, LightClientBootstrap.GLOAS_SIZE + 1}) {
            assertThrows(IllegalArgumentException.class, () -> LightClientBootstrap.decodeGloas(new byte[n]));
        }
        for (int n : new int[]{LightClientUpdate.GLOAS_SIZE - 1, LightClientUpdate.GLOAS_SIZE + 1}) {
            assertThrows(IllegalArgumentException.class, () -> LightClientUpdate.decodeGloas(new byte[n]));
        }
        for (int n : new int[]{LightClientFinalityUpdate.GLOAS_SIZE - 1, LightClientFinalityUpdate.GLOAS_SIZE + 1}) {
            assertThrows(IllegalArgumentException.class, () -> LightClientFinalityUpdate.decodeGloas(new byte[n]));
        }
        LightClientHeader h = LightClientHeader.decodeGloas(new byte[496]);
        assertEquals(LcFork.GLOAS, h.shape());
        assertEquals(11, h.executionBranch().length);
        assertNull(h.execution());
        LightClientFinalityUpdate f = LightClientFinalityUpdate.decodeFor(LcFork.GLOAS, new byte[1448]);
        assertEquals(9, f.finalityBranch().length);

        // The other two containers carry their Gloas vectors, and every header in them
        // is Gloas-shaped.
        LightClientBootstrap b = LightClientBootstrap.decodeFor(LcFork.GLOAS, new byte[25472]);
        assertEquals(11, b.currentSyncCommitteeBranch().length);
        assertEquals(LcFork.GLOAS, b.header().shape());
        LightClientUpdate u = LightClientUpdate.decodeFor(LcFork.GLOAS, new byte[26424]);
        assertEquals(11, u.nextSyncCommitteeBranch().length);
        assertEquals(9, u.finalityBranch().length);
        assertEquals(LcFork.GLOAS, u.attestedHeader().shape());
        assertEquals(LcFork.GLOAS, u.finalizedHeader().shape());
        assertEquals(LcFork.GLOAS, f.attestedHeader().shape());
        assertEquals(LcFork.GLOAS, f.finalizedHeader().shape());
    }

    /**
     * Every Gloas container is SMALLER than the smallest canonical pre-Gloas encoding of
     * its type, so no pre-Gloas object is ever Gloas-sized: a Gloas decoder (exactly one
     * size) refuses every one of them, and a Gloas-sized payload is never a pre-Gloas one
     * — a wrong context digest is a clean rejection, not a misparse (the fork-keyed
     * dispatch is the rule; this is the belt to its braces). The smallest pre-Gloas header
     * is the fixed part plus a Capella payload header with empty {@code extra_data} (568
     * bytes; Deneb's and Electra's are larger), and the smallest container carries the
     * shortest (pre-Electra) branches, which is what each {@code FIXED_SIZE} counts.
     * {@code BeaconLightClientGloasTest.aGloasObjectIsNeverTheSizeOfAPreGloasOne} pins
     * the same bound for the containers the client tells apart by size.
     */
    @Test
    void gloasAndPreGloasSizesDoNotCollide() {
        int minPreGloasHeader = LightClientHeader.FIXED_SIZE + 568;
        int minPreGloasBootstrap = LightClientBootstrap.FIXED_SIZE + minPreGloasHeader;
        int minPreGloasUpdate = LightClientUpdate.FIXED_SIZE + 2 * minPreGloasHeader;
        int minPreGloasFinality = LightClientFinalityUpdate.FIXED_SIZE + 2 * minPreGloasHeader;
        assertTrue(LightClientHeader.GLOAS_SIZE < minPreGloasHeader);
        assertTrue(LightClientBootstrap.GLOAS_SIZE < minPreGloasBootstrap);
        assertTrue(LightClientUpdate.GLOAS_SIZE < minPreGloasUpdate);
        assertTrue(LightClientFinalityUpdate.GLOAS_SIZE < minPreGloasFinality);
        assertThrows(IllegalArgumentException.class,
                () -> LightClientHeader.decodeGloas(new byte[minPreGloasHeader]));
        assertThrows(IllegalArgumentException.class,
                () -> LightClientBootstrap.decodeGloas(new byte[minPreGloasBootstrap]));
        assertThrows(IllegalArgumentException.class,
                () -> LightClientUpdate.decodeGloas(new byte[minPreGloasUpdate]));
        assertThrows(IllegalArgumentException.class,
                () -> LightClientFinalityUpdate.decodeGloas(new byte[minPreGloasFinality]));
    }

    /** Each field sits where the Gloas layout puts it: beacon, block hash, then 11 nodes. */
    @Test
    void theGloasHeaderLayout() {
        byte[] ssz = new byte[LightClientHeader.GLOAS_SIZE];
        for (int i = 0; i < ssz.length; i++) ssz[i] = (byte) (i * 7 + 3);
        LightClientHeader h = LightClientHeader.decodeGloas(ssz);
        assertArrayEquals(Arrays.copyOfRange(ssz, 0, 112), h.beacon().encode());
        assertArrayEquals(Arrays.copyOfRange(ssz, 112, 144), h.executionBlockHash());
        for (int i = 0; i < 11; i++) {
            assertArrayEquals(Arrays.copyOfRange(ssz, 144 + 32 * i, 176 + 32 * i), h.executionBranch()[i], "node " + i);
        }
    }

    /** Malformed input is an IllegalArgumentException from every Gloas entry point — never another throwable. */
    @Test
    void malformedGloasInputIsOnlyEverAnIllegalArgument() {
        int[] sizes = {0, 1, 4, 112, 495, 497, 1447, 1449, 25471, 25473, 26423, 26425, 60000};
        for (int n : sizes) {
            byte[] bytes = new byte[n];
            if (n != LightClientHeader.GLOAS_SIZE)
                assertThrows(IllegalArgumentException.class, () -> LightClientHeader.decodeGloas(bytes), "header " + n);
            if (n != LightClientBootstrap.GLOAS_SIZE)
                assertThrows(IllegalArgumentException.class, () -> LightClientBootstrap.decodeGloas(bytes), "bootstrap " + n);
            if (n != LightClientUpdate.GLOAS_SIZE)
                assertThrows(IllegalArgumentException.class, () -> LightClientUpdate.decodeGloas(bytes), "update " + n);
            if (n != LightClientFinalityUpdate.GLOAS_SIZE)
                assertThrows(IllegalArgumentException.class,
                        () -> LightClientFinalityUpdate.decodeGloas(bytes), "finality " + n);
        }
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.decodeGloas(null));
        assertThrows(IllegalArgumentException.class, () -> LightClientBootstrap.decodeGloas(null));
        assertThrows(IllegalArgumentException.class, () -> LightClientUpdate.decodeGloas(null));
        assertThrows(IllegalArgumentException.class, () -> LightClientFinalityUpdate.decodeGloas(null));
        // The fork selects the format; there is no default to fall back on.
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.decodeFor(null, new byte[496]));
        assertThrows(IllegalArgumentException.class, () -> LightClientBootstrap.decodeFor(null, new byte[25472]));
        assertThrows(IllegalArgumentException.class, () -> LightClientUpdate.decodeFor(null, new byte[26424]));
        assertThrows(IllegalArgumentException.class, () -> LightClientFinalityUpdate.decodeFor(null, new byte[1448]));
    }

    /** The Gloas shape is a 32-byte hash and exactly 11 nodes; the payload shape reports its payload's hash. */
    @Test
    void theGloasFactoryAndTheShapes() {
        BeaconBlockHeader beacon = new BeaconBlockHeader(1, 2, new byte[32], new byte[32], new byte[32]);
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.gloas(beacon, new byte[31], new byte[11][32]));
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.gloas(beacon, null, new byte[11][32]));
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.gloas(beacon, new byte[32], new byte[10][32]));
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.gloas(beacon, new byte[32], new byte[12][32]));
        byte[][] badNode = new byte[11][32];
        badNode[3] = new byte[33];
        assertThrows(IllegalArgumentException.class, () -> LightClientHeader.gloas(beacon, new byte[32], badNode));

        byte[] hash = new byte[32];
        Arrays.fill(hash, (byte) 0xee);
        LightClientHeader gloas = LightClientHeader.gloas(beacon, hash, new byte[11][32]);
        assertEquals(LcFork.GLOAS, gloas.shape());
        assertArrayEquals(hash, gloas.executionBlockHash());
        assertNull(gloas.execution());

        ExecutionPayloadHeader payload = new ExecutionPayloadHeader(new byte[32], new byte[20], new byte[32],
                new byte[32], new byte[256], new byte[32], 0, 0, 0, 0, new byte[0], new byte[32], hash,
                new byte[32], new byte[32], 0, 0, null, null, null);
        LightClientHeader pre = new LightClientHeader(beacon, payload, new byte[4][32]);
        assertEquals(LcFork.PRE_GLOAS, pre.shape());
        assertArrayEquals(hash, pre.executionBlockHash());
        assertSame(payload, pre.execution());
    }
}
