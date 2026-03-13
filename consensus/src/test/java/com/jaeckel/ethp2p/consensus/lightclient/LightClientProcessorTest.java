package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.TestUtil;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.SecretKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for LightClientProcessor chaining BLS + Merkle proofs.
 */
class LightClientProcessorTest {

    private static final byte[] FORK_VERSION = {0x05, 0x00, 0x00, 0x00};
    private static final byte[] GVR = new byte[32];

    private static SecretKey[] secretKeys;
    private static byte[][] pubkeys;
    private static SyncCommittee syncCommittee;

    private LightClientStore store;
    private LightClientProcessor processor;

    @BeforeAll
    static void generateKeys() {
        secretKeys = new SecretKey[512];
        pubkeys = new byte[512][];
        for (int i = 0; i < 512; i++) {
            secretKeys[i] = TestUtil.generateSecretKey(8000 + i);
            pubkeys[i] = TestUtil.getPublicKey(secretKeys[i]);
        }
        P1 agg = new P1(new P1_Affine(pubkeys[0]));
        for (int i = 1; i < 512; i++) {
            agg.aggregate(new P1_Affine(pubkeys[i]));
        }
        syncCommittee = new SyncCommittee(pubkeys, agg.compress());
    }

    @BeforeEach
    void setUp() {
        store = new LightClientStore();
        // Initialize with a header at slot 100
        BeaconBlockHeader initBeacon = new BeaconBlockHeader(100L, 0L, new byte[32], new byte[32], new byte[32]);
        store.initialize(TestUtil.dummyLightClientHeader(initBeacon), syncCommittee);
        processor = new LightClientProcessor(store, FORK_VERSION, GVR);
    }

    @Test
    void processFinalityUpdateSucceeds() {
        LightClientFinalityUpdate update = buildValidFinalityUpdate(200L, 201L);
        assertTrue(processor.processFinalityUpdate(update));
        assertEquals(200L, store.getFinalizedSlot());
    }

    @Test
    void rejectsInvalidBls() {
        LightClientFinalityUpdate valid = buildValidFinalityUpdate(300L, 301L);

        // Tamper the signature
        byte[] tamperedSig = Arrays.copyOf(valid.syncAggregate().syncCommitteeSignature(), 96);
        tamperedSig[10] ^= 0x01;
        SyncAggregate tamperedAgg = new SyncAggregate(valid.syncAggregate().syncCommitteeBits(), tamperedSig);

        LightClientFinalityUpdate tampered = new LightClientFinalityUpdate(
                valid.attestedHeader(), valid.finalizedHeader(), valid.finalityBranch(),
                tamperedAgg, valid.signatureSlot());

        assertFalse(processor.processFinalityUpdate(tampered));
        // Store should remain unchanged at initial slot
        assertEquals(100L, store.getFinalizedSlot());
    }

    @Test
    void rejectsInsufficientParticipation() {
        // Build with only 341 participants (below 342 threshold)
        LightClientFinalityUpdate update = buildFinalityUpdateWithParticipation(400L, 401L, 341);
        assertFalse(processor.processFinalityUpdate(update));
        assertEquals(100L, store.getFinalizedSlot());
    }

    @Test
    void rejectsInvalidFinalityBranch() {
        LightClientFinalityUpdate valid = buildValidFinalityUpdate(500L, 501L);

        // Corrupt a branch node
        byte[][] corruptBranch = new byte[6][];
        for (int i = 0; i < 6; i++) {
            corruptBranch[i] = Arrays.copyOf(valid.finalityBranch()[i], 32);
        }
        corruptBranch[2][0] ^= 0x01;

        LightClientFinalityUpdate corrupted = new LightClientFinalityUpdate(
                valid.attestedHeader(), valid.finalizedHeader(), corruptBranch,
                valid.syncAggregate(), valid.signatureSlot());

        assertFalse(processor.processFinalityUpdate(corrupted));
        assertEquals(100L, store.getFinalizedSlot());
    }

    @Test
    void rejectsWrongFinalizedHeader() {
        LightClientFinalityUpdate valid = buildValidFinalityUpdate(600L, 601L);

        // Use a different finalized header than what the branch proves
        BeaconBlockHeader wrongFinalized = new BeaconBlockHeader(
                600L, 99L, new byte[32], new byte[32], new byte[32]);
        LightClientHeader wrongFinalizedHeader = TestUtil.dummyLightClientHeader(wrongFinalized);

        LightClientFinalityUpdate wrong = new LightClientFinalityUpdate(
                valid.attestedHeader(), wrongFinalizedHeader, valid.finalityBranch(),
                valid.syncAggregate(), valid.signatureSlot());

        assertFalse(processor.processFinalityUpdate(wrong));
        assertEquals(100L, store.getFinalizedSlot());
    }

    @Test
    void rejectsNullCommittee() {
        // Fresh store without initialization
        LightClientStore emptyStore = new LightClientStore();
        LightClientProcessor emptyProcessor = new LightClientProcessor(emptyStore, FORK_VERSION, GVR);

        LightClientFinalityUpdate update = buildValidFinalityUpdate(700L, 701L);
        assertFalse(emptyProcessor.processFinalityUpdate(update));
    }

    @Test
    void processUpdateRejectsInvalidSyncCommitteeBranch() {
        // Build a LightClientUpdate with valid BLS + finality but corrupt committee branch
        long finalizedSlot = 800L;
        long signatureSlot = 801L;

        // Build finalized header and its Merkle proof in attested state
        BeaconBlockHeader finalizedBeacon = new BeaconBlockHeader(
                finalizedSlot, 0L, new byte[32], new byte[32], new byte[32]);
        byte[] finalizedRoot = finalizedBeacon.hashTreeRoot();

        // Build depth-6 tree for finality branch
        int finalityLeafIdx = BeaconChainSpec.FINALIZED_ROOT_GINDEX % 64;
        byte[][] finalityLeaves = new byte[64][32];
        finalityLeaves[finalityLeafIdx] = finalizedRoot;
        byte[][] finalityTree = TestUtil.buildMerkleTree(finalityLeaves);
        byte[][] finalityBranch = TestUtil.extractBranch(finalityTree, 6, finalityLeafIdx);

        // The attested header's stateRoot is the Merkle root for the finality tree
        byte[] attestedStateRoot = finalityTree[1];
        BeaconBlockHeader attestedBeacon = new BeaconBlockHeader(
                signatureSlot, 0L, new byte[32], attestedStateRoot, new byte[32]);
        LightClientHeader attestedHeader = TestUtil.dummyLightClientHeader(attestedBeacon);
        LightClientHeader finalizedHeader = TestUtil.dummyLightClientHeader(finalizedBeacon);

        SyncAggregate agg = buildSyncAggregate(attestedBeacon, 512);

        // Build a next sync committee with corrupt branch
        byte[][] corruptCommitteeBranch = new byte[5][32];
        corruptCommitteeBranch[0][0] = (byte) 0xFF; // garbage

        LightClientUpdate update = new LightClientUpdate(
                attestedHeader, syncCommittee, corruptCommitteeBranch,
                finalizedHeader, finalityBranch, agg, signatureSlot);

        assertFalse(processor.processUpdate(update));
    }

    @Test
    void syncCommitteeRotatesOnPeriodBoundary() {
        // Build a next sync committee with different keys
        SecretKey[] nextKeys = new SecretKey[512];
        byte[][] nextPubkeys = new byte[512][];
        for (int i = 0; i < 512; i++) {
            nextKeys[i] = TestUtil.generateSecretKey(9000 + i);
            nextPubkeys[i] = TestUtil.getPublicKey(nextKeys[i]);
        }
        P1 nextAgg = new P1(new P1_Affine(nextPubkeys[0]));
        for (int i = 1; i < 512; i++) {
            nextAgg.aggregate(new P1_Affine(nextPubkeys[i]));
        }
        SyncCommittee nextCommittee = new SyncCommittee(nextPubkeys, nextAgg.compress());

        // Store the next committee
        store.updateNextSyncCommittee(nextCommittee);

        // Process a finality update that crosses into period 1 (slot 8192+)
        long newSlot = BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD + 10; // period 1
        LightClientFinalityUpdate update = buildValidFinalityUpdate(newSlot, newSlot + 1);
        assertTrue(processor.processFinalityUpdate(update));
        assertEquals(newSlot, store.getFinalizedSlot());

        // The processor calls applyNextSyncCommitteeWhenPeriodChanges after updateFinalized,
        // so finalizedSlot is already at the new period. Test rotation via the store directly:
        // Reset state for direct store test.
        LightClientStore directStore = new LightClientStore();
        BeaconBlockHeader period0Header = new BeaconBlockHeader(100L, 0L, new byte[32], new byte[32], new byte[32]);
        directStore.initialize(TestUtil.dummyLightClientHeader(period0Header), syncCommittee);
        directStore.updateNextSyncCommittee(nextCommittee);

        // finalizedSlot is still 100 (period 0). Calling with period 1 slot should rotate.
        long period1Slot = BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD + 10;
        directStore.applyNextSyncCommitteeWhenPeriodChanges(directStore.getFinalizedSlot(), period1Slot);

        assertNull(directStore.getNextSyncCommittee());
        assertArrayEquals(nextCommittee.aggregatePubkey(), directStore.getCurrentSyncCommittee().aggregatePubkey());
    }

    // === Helpers ===

    private LightClientFinalityUpdate buildValidFinalityUpdate(long finalizedSlot, long signatureSlot) {
        return buildFinalityUpdateWithParticipation(finalizedSlot, signatureSlot, 512);
    }

    private LightClientFinalityUpdate buildFinalityUpdateWithParticipation(
            long finalizedSlot, long signatureSlot, int participantCount) {
        // Build finalized header
        BeaconBlockHeader finalizedBeacon = new BeaconBlockHeader(
                finalizedSlot, 0L, new byte[32], new byte[32], new byte[32]);
        byte[] finalizedRoot = finalizedBeacon.hashTreeRoot();

        // Build depth-6 tree for finality branch
        // The finalized root sits at gindex 105 in the state tree.
        // gindex 105 = 64 + 41 → leaf index 41 in a depth-6 tree
        int finalityLeafIdx = BeaconChainSpec.FINALIZED_ROOT_GINDEX % 64;
        byte[][] leaves = new byte[64][32];
        leaves[finalityLeafIdx] = finalizedRoot;

        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[][] finalityBranch = TestUtil.extractBranch(tree, 6, finalityLeafIdx);

        // The attested header's stateRoot must be the Merkle root
        byte[] attestedStateRoot = tree[1];
        BeaconBlockHeader attestedBeacon = new BeaconBlockHeader(
                signatureSlot, 0L, new byte[32], attestedStateRoot, new byte[32]);
        LightClientHeader attestedHeader = TestUtil.dummyLightClientHeader(attestedBeacon);
        LightClientHeader finalizedHeader = TestUtil.dummyLightClientHeader(finalizedBeacon);

        SyncAggregate agg = buildSyncAggregate(attestedBeacon, participantCount);

        return new LightClientFinalityUpdate(
                attestedHeader, finalizedHeader, finalityBranch, agg, signatureSlot);
    }

    private SyncAggregate buildSyncAggregate(BeaconBlockHeader attestedBeacon, int participantCount) {
        byte[] domain = ForkData.computeDomain(BeaconChainSpec.DOMAIN_SYNC_COMMITTEE, FORK_VERSION, GVR);
        byte[] signingRoot = SszUtil.hashTreeRootContainer(attestedBeacon.hashTreeRoot(), domain);

        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < participantCount; i++) {
            sigs.add(TestUtil.blsSign(secretKeys[i], signingRoot));
        }
        byte[] aggSig = TestUtil.aggregateSignatures(sigs);

        byte[] bits = new byte[64];
        for (int i = 0; i < participantCount; i++) {
            bits[i / 8] |= (1 << (i % 8));
        }
        return new SyncAggregate(bits, aggSig);
    }
}
