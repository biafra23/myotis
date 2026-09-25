package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.TestUtil;
import com.jaeckel.ethp2p.consensus.bls.BlsVerifier;
import com.jaeckel.ethp2p.consensus.lightclient.LightClientProcessor.BootstrapReject;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.ForkData;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.consensus.types.SyncAggregate;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import com.jaeckel.ethp2p.core.consensus.LcFork;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The processor across the Fulu→Gloas boundary: synthetic committee, real BLS,
 * synthetic state/body trees with the leaves at the Gloas gindices. Covers the shape
 * gate, the per-slot proof selection (2856 for a Gloas header, 812 with zero padding
 * for a pre-Gloas finalized header in the Gloas shape), the Gloas state gindices
 * (735 / 2946 / 2945), and the rejections around each. Rust twin:
 * {@code rust/myotis-consensus/tests/gloas_boundary.rs}.
 *
 * <p>Signed the way {@code LightClientProcessorTest}'s boundary tests are: Milagro keys
 * from {@link TestUtil#generateSecretKey}, and the smallest participation the 2/3 rule
 * accepts (342 signers; the Rust twin signs with all 512 — the verdicts are the same,
 * and Milagro signing is ~8 ms per signer).
 */
class GloasBoundaryTest {

    private static final int FULU = 0x06000000;
    private static final int GLOAS = 0x07000000;
    private static final byte[] GLOAS_VERSION = {0x07, 0, 0, 0};
    private static final byte[] GVR = new byte[32];
    /** Gloas at epoch 10 = slot 320 on the mainnet preset. */
    private static final long GLOAS_EPOCH = 10;
    private static final long G = GLOAS_EPOCH * 32;
    private static final int MIN_PARTICIPANTS = 342;

    private static BIG[] keys;
    private static SyncCommittee committee;

    @BeforeAll
    static void generateKeys() {
        keys = new BIG[SyncCommittee.PUBKEY_COUNT];
        byte[][] pubkeys = new byte[SyncCommittee.PUBKEY_COUNT][];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = TestUtil.generateSecretKey(9000 + i);
            pubkeys[i] = TestUtil.getPublicKey(keys[i]);
        }
        ECP agg = BlsVerifier.deserializeG1(pubkeys[0]);
        for (int i = 1; i < pubkeys.length; i++) agg.add(BlsVerifier.deserializeG1(pubkeys[i]));
        agg.affine();
        committee = new SyncCommittee(pubkeys, BlsVerifier.serializeG1(agg));
    }

    private static ForkSchedule schedule() {
        return ForkSchedule.of(32, ForkSchedule.fork(0, FULU), ForkSchedule.fork(GLOAS_EPOCH, GLOAS))
                .withGloasEpoch(GLOAS_EPOCH);
    }

    /**
     * A Merkle tree given by the nodes we care about, at any depths; every other subtree
     * is a zero leaf. Enough to prove several gindices of different depths against ONE
     * root, as a real (progressive) state or body does.
     */
    private static final class Sparse {
        private final Map<Integer, byte[]> leaves = new HashMap<>();

        Sparse put(int gindex, byte[] leaf) {
            leaves.put(gindex, leaf);
            return this;
        }

        private boolean covers(int g) {
            for (int k : leaves.keySet()) {
                int x = k;
                while (x > g) x /= 2;
                if (x == g) return true;
            }
            return false;
        }

        byte[] node(int g) {
            byte[] v = leaves.get(g);
            if (v != null) return v;
            if (covers(g)) return SszUtil.sha256(node(2 * g), node(2 * g + 1));
            return new byte[32];
        }

        byte[] root() {
            return node(1);
        }

        /** Bottom-up sibling path of {@code g}. */
        byte[][] branch(int g) {
            List<byte[]> b = new ArrayList<>();
            while (g > 1) {
                b.add(node(g ^ 1));
                g /= 2;
            }
            return b.toArray(new byte[0][]);
        }
    }

    private static byte[] fill(int b) {
        byte[] out = new byte[32];
        Arrays.fill(out, (byte) b);
        return out;
    }

    private static ExecutionPayloadHeader payload() {
        return new ExecutionPayloadHeader(new byte[32], new byte[20], new byte[32], new byte[32], new byte[256],
                new byte[32], 0L, 0L, 0L, 0L, new byte[0], new byte[32], fill(0xee), new byte[32], new byte[32],
                0L, 0L, null, null, null);
    }

    private static BeaconBlockHeader beacon(long slot, byte[] stateRoot, byte[] bodyRoot) {
        return new BeaconBlockHeader(slot, 0L, new byte[32], stateRoot, bodyRoot);
    }

    /** Pre-Gloas shape: the payload header at gindex 25. */
    private static LightClientHeader payloadHeader(long slot, byte[] stateRoot) {
        ExecutionPayloadHeader p = payload();
        int g = BeaconChainSpec.EXECUTION_PAYLOAD_GINDEX;
        Sparse body = new Sparse().put(g, p.hashTreeRoot());
        return new LightClientHeader(beacon(slot, stateRoot, body.root()), p, body.branch(g));
    }

    /** Gloas shape at a Gloas slot: the block hash at 2856. */
    private static LightClientHeader gloasHeader(long slot, byte[] stateRoot, byte[] blockHash) {
        int g = BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_GLOAS;
        Sparse body = new Sparse().put(g, blockHash);
        return LightClientHeader.gloas(beacon(slot, stateRoot, body.root()), blockHash, body.branch(g));
    }

    /** Gloas shape of a PRE-Gloas header: the block hash at 812, zero-padded to 11. */
    private static LightClientHeader upgradedHeader(long slot, byte[] blockHash) {
        int g = BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_DENEB;
        Sparse body = new Sparse().put(g, blockHash);
        byte[][] proof = body.branch(g);
        byte[][] branch = new byte[2 + proof.length][];
        branch[0] = new byte[32];
        branch[1] = new byte[32];
        System.arraycopy(proof, 0, branch, 2, proof.length);
        return LightClientHeader.gloas(beacon(slot, new byte[32], body.root()), blockHash, branch);
    }

    private static SyncAggregate sign(LightClientHeader attested, byte[] forkVersion) {
        byte[] domain = ForkData.computeDomain(BeaconChainSpec.DOMAIN_SYNC_COMMITTEE, forkVersion, GVR);
        byte[] signingRoot = SszUtil.hashTreeRootContainer(attested.beacon().hashTreeRoot(), domain);
        List<byte[]> sigs = new ArrayList<>(MIN_PARTICIPANTS);
        byte[] bits = new byte[64];
        for (int i = 0; i < MIN_PARTICIPANTS; i++) {
            sigs.add(TestUtil.blsSign(keys[i], signingRoot));
            bits[i / 8] |= (byte) (1 << (i % 8));
        }
        return new SyncAggregate(bits, TestUtil.aggregateSignatures(sigs));
    }

    /**
     * A Gloas-format finality update: attested (Gloas shape, at {@code attestedSlot})
     * whose state holds {@code finalized}'s root at {@code finalityGindex}.
     */
    private static LightClientFinalityUpdate gloasFinality(
            LightClientHeader finalized, long attestedSlot, int finalityGindex) {
        Sparse state = new Sparse().put(finalityGindex, finalized.beacon().hashTreeRoot());
        LightClientHeader attested = gloasHeader(attestedSlot, state.root(), fill(0xaa));
        long signatureSlot = attestedSlot + 1;
        byte[] version = schedule().versionForSignatureSlot(signatureSlot);
        return new LightClientFinalityUpdate(attested, finalized, state.branch(finalityGindex),
                sign(attested, version), signatureSlot);
    }

    /** A pre-Gloas (Electra-format) finality update, depth-7 finality branch. */
    private static LightClientFinalityUpdate electraFinality(long finalizedSlot, long attestedSlot) {
        LightClientHeader finalized = payloadHeader(finalizedSlot, new byte[32]);
        int g = BeaconChainSpec.finalizedRootGindex(7);
        Sparse state = new Sparse().put(g, finalized.beacon().hashTreeRoot());
        LightClientHeader attested = payloadHeader(attestedSlot, state.root());
        long signatureSlot = attestedSlot + 1;
        byte[] version = schedule().versionForSignatureSlot(signatureSlot);
        return new LightClientFinalityUpdate(attested, finalized, state.branch(g),
                sign(attested, version), signatureSlot);
    }

    private static LightClientProcessor processor() {
        LightClientStore store = new LightClientStore();
        store.initialize(payloadHeader(100, new byte[32]), committee);
        return new LightClientProcessor(store, schedule(), GVR);
    }

    @Test
    void finalityWalksFromFuluIntoGloas() {
        LightClientProcessor p = processor();
        LightClientStore store = p.getStore();

        // Last Fulu finality: Electra format, payload-shaped headers.
        assertTrue(p.processFinalityUpdate(electraFinality(256, G - 8)));
        assertEquals(256L, store.getFinalizedSlot());

        // First Gloas finality: Gloas format, but the finalized header is still a
        // Fulu block — in the Gloas shape, proving its block hash at 812.
        LightClientHeader fin = upgradedHeader(G - 32, fill(0xf1));
        assertTrue(p.processFinalityUpdate(gloasFinality(fin, G + 2, BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS)));
        assertEquals(G - 32, store.getFinalizedSlot());
        LightClientHeader held = store.getFinalizedHeader();
        assertEquals(LcFork.GLOAS, held.shape());
        assertArrayEquals(fill(0xf1), held.executionBlockHash());
        assertArrayEquals(fill(0xaa), store.getOptimisticHeader().executionBlockHash());

        // Then a Gloas block finalizes: block hash at 2856.
        fin = gloasHeader(G, new byte[32], fill(0xf2));
        assertTrue(p.processFinalityUpdate(gloasFinality(fin, G + 64, BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS)));
        assertEquals(G, store.getFinalizedSlot());
        assertArrayEquals(fill(0xf2), store.getFinalizedHeader().executionBlockHash());
    }

    @Test
    void aGloasCatchUpUpdateProvesTheNextCommitteeAt2946() {
        LightClientProcessor p = processor();
        SyncCommittee next = committee;
        LightClientHeader fin = gloasHeader(G, new byte[32], fill(0xf3));
        int fg = BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS;
        int ng = BeaconChainSpec.NEXT_SYNC_COMMITTEE_GINDEX_GLOAS;
        // One attested state proving both leaves, at depths 9 and 11.
        Sparse state = new Sparse().put(fg, fin.beacon().hashTreeRoot()).put(ng, next.hashTreeRoot());
        LightClientHeader attested = gloasHeader(G + 40, state.root(), fill(0xab));
        LightClientUpdate update = new LightClientUpdate(attested, next, state.branch(ng), fin, state.branch(fg),
                sign(attested, GLOAS_VERSION), G + 41);
        assertEquals(11, update.nextSyncCommitteeBranch().length);
        assertEquals(9, update.finalityBranch().length);
        assertTrue(p.processUpdate(update));
        assertNotNull(p.getStore().getNextSyncCommittee());
        assertEquals(G, p.getStore().getFinalizedSlot());
    }

    @Test
    void rejectsWhatIsNotTheAttestedSlotsForksShapeOrProof() {
        LightClientProcessor p = processor();
        int fg = BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS;

        // Gloas format with a pre-Gloas attested slot: the shape gate (before BLS).
        LightClientHeader fin = upgradedHeader(G - 64, fill(0xf1));
        assertFalse(p.processFinalityUpdate(gloasFinality(fin, G - 10, fg)),
                "Gloas shape at a Fulu attested slot");

        // Electra format with a Gloas attested slot.
        assertFalse(p.processFinalityUpdate(electraFinality(256, G + 2)), "payload shape at a Gloas slot");

        // Gloas format, finality proven at the depth-derived gindex (553).
        assertFalse(p.processFinalityUpdate(gloasFinality(fin, G + 2, BeaconChainSpec.finalizedRootGindex(9))),
                "the depth-derived gindex is not Gloas'");

        // The pre-Gloas finalized header with a non-zero pad node.
        byte[][] dirtyBranch = new byte[11][];
        for (int i = 0; i < 11; i++) dirtyBranch[i] = fin.executionBranch()[i].clone();
        dirtyBranch[1][0] = 1;
        LightClientHeader dirty = LightClientHeader.gloas(fin.beacon(), fin.executionBlockHash(), dirtyBranch);
        assertFalse(p.processFinalityUpdate(gloasFinality(dirty, G + 2, fg)),
                "a non-zero pad is not padding");

        // A Gloas-slot finalized header proven at 812 instead of 2856.
        LightClientHeader at812 = upgradedHeader(G + 1, fill(0xf4));
        assertFalse(p.processFinalityUpdate(gloasFinality(at812, G + 40, fg)),
                "812 is the pre-Gloas slots' rule only");

        // A payload-shaped finalized header inside a Gloas-format update.
        assertFalse(p.processFinalityUpdate(gloasFinality(payloadHeader(G - 32, new byte[32]), G + 2, fg)),
                "every header of a Gloas update is Gloas-shaped");

        assertEquals(100L, p.getStore().getFinalizedSlot(), "nothing applied");
    }

    @Test
    void aGloasBootstrapVerifiesAt2945And2856() {
        LightClientProcessor p = processor();
        int cg = BeaconChainSpec.CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS;
        Sparse state = new Sparse().put(cg, committee.hashTreeRoot());
        LightClientHeader header = gloasHeader(G + 32, state.root(), fill(0xbb));
        LightClientBootstrap bootstrap = new LightClientBootstrap(header, committee, state.branch(cg));
        assertNull(p.verifyBootstrap(bootstrap));

        // The committee at the depth-derived gindex (2070) instead.
        int depthDerived = BeaconChainSpec.syncCommitteeGindex(11);
        Sparse wrong = new Sparse().put(depthDerived, committee.hashTreeRoot());
        LightClientBootstrap bad = new LightClientBootstrap(
                gloasHeader(G + 32, wrong.root(), fill(0xbb)), committee, wrong.branch(depthDerived));
        assertEquals(BootstrapReject.SYNC_COMMITTEE_BRANCH, p.verifyBootstrap(bad));

        // A Gloas-shaped bootstrap at a Fulu slot.
        BeaconBlockHeader b = header.beacon();
        LightClientHeader earlyHeader = LightClientHeader.gloas(
                new BeaconBlockHeader(G - 1, b.proposerIndex(), b.parentRoot(), b.stateRoot(), b.bodyRoot()),
                header.executionBlockHash(), header.executionBranch());
        assertEquals(BootstrapReject.SHAPE_NOT_ITS_FORKS, p.verifyBootstrap(
                new LightClientBootstrap(earlyHeader, committee, bootstrap.currentSyncCommitteeBranch())));

        // A forged block hash under a genuine body root.
        LightClientHeader forged = LightClientHeader.gloas(header.beacon(), fill(0xcc), header.executionBranch());
        assertEquals(BootstrapReject.EXECUTION_BRANCH, p.verifyBootstrap(
                new LightClientBootstrap(forged, committee, bootstrap.currentSyncCommitteeBranch())));
    }
}
