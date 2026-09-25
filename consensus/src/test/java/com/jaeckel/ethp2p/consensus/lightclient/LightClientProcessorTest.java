package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.TestUtil;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.*;
import com.jaeckel.ethp2p.consensus.bls.BlsVerifier;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

    private static BIG[] secretKeys;
    private static byte[][] pubkeys;
    private static SyncCommittee syncCommittee;

    private LightClientStore store;
    private LightClientProcessor processor;

    @BeforeAll
    static void generateKeys() {
        secretKeys = new BIG[512];
        pubkeys = new byte[512][];
        for (int i = 0; i < 512; i++) {
            secretKeys[i] = TestUtil.generateSecretKey(8000 + i);
            pubkeys[i] = TestUtil.getPublicKey(secretKeys[i]);
        }
        syncCommittee = new SyncCommittee(pubkeys, aggregatePubkeys(pubkeys));
    }

    @BeforeEach
    void setUp() {
        store = new LightClientStore();
        // Initialize with a header at slot 100
        BeaconBlockHeader initBeacon = new BeaconBlockHeader(100L, 0L, new byte[32], new byte[32], new byte[32]);
        store.initialize(TestUtil.dummyLightClientHeader(initBeacon), syncCommittee);
        processor = new LightClientProcessor(store, ForkSchedule.single(FORK_VERSION), GVR);
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
    void rejectsInvalidExecutionBranch() {
        LightClientFinalityUpdate valid = buildValidFinalityUpdate(900L, 901L);

        // Corrupt one node of the finalized header's execution branch so its execution
        // payload no longer proves against the beacon body root. The beacon header is
        // untouched, so the BLS signature and finality branch still verify — only the
        // execution-branch check can reject this update.
        LightClientHeader fin = valid.finalizedHeader();
        byte[][] corruptBranch = new byte[4][];
        for (int i = 0; i < 4; i++) corruptBranch[i] = Arrays.copyOf(fin.executionBranch()[i], 32);
        corruptBranch[0][0] ^= 0x01;
        LightClientHeader corruptFinalized =
                new LightClientHeader(fin.beacon(), fin.execution(), corruptBranch);

        LightClientFinalityUpdate tampered = new LightClientFinalityUpdate(
                valid.attestedHeader(), corruptFinalized, valid.finalityBranch(),
                valid.syncAggregate(), valid.signatureSlot());

        assertFalse(processor.processFinalityUpdate(tampered));
        assertEquals(100L, store.getFinalizedSlot());
    }

    @Test
    void rejectsForgedExecutionPayload() {
        LightClientFinalityUpdate valid = buildValidFinalityUpdate(950L, 951L);

        // Keep the genuine execution branch but swap in a different execution payload
        // (attacker-chosen state root). The branch now proves the original payload, not
        // the forged one, so verifyExecutionBranch must reject it.
        LightClientHeader fin = valid.finalizedHeader();
        ExecutionPayloadHeader forged = TestUtil.dummyExecutionPayloadHeader();
        byte[] forgedStateRoot = new byte[32];
        forgedStateRoot[0] = (byte) 0xAB; // differs from the all-zero dummy state root
        ExecutionPayloadHeader forgedPayload = new ExecutionPayloadHeader(
                forged.parentHash(), forged.feeRecipient(), forgedStateRoot, forged.receiptsRoot(),
                forged.logsBloom(), forged.prevRandao(), forged.blockNumber(), forged.gasLimit(),
                forged.gasUsed(), forged.timestamp(), forged.extraData(), forged.baseFeePerGas(),
                forged.blockHash(), forged.transactionsRoot(), forged.withdrawalsRoot(),
                forged.blobGasUsed(), forged.excessBlobGas(), forged.depositRequestsRoot(),
                forged.withdrawalRequestsRoot(), forged.consolidationRequestsRoot());
        LightClientHeader forgedFinalized =
                new LightClientHeader(fin.beacon(), forgedPayload, fin.executionBranch());

        LightClientFinalityUpdate tampered = new LightClientFinalityUpdate(
                valid.attestedHeader(), forgedFinalized, valid.finalityBranch(),
                valid.syncAggregate(), valid.signatureSlot());

        assertFalse(processor.processFinalityUpdate(tampered));
        assertEquals(100L, store.getFinalizedSlot());
    }

    // ---- #295: the signing domain follows the fork active at signature_slot ----

    private static final byte[] OLD_FORK = {0x05, 0x00, 0x00, 0x00};
    private static final byte[] NEW_FORK = {0x06, 0x00, 0x00, 0x00};
    /** Boundary epoch 10 = slot 320 on the mainnet preset. */
    private static final long BOUNDARY_EPOCH = 10;
    private static final long BOUNDARY_SLOT = BOUNDARY_EPOCH * 32;
    /** The smallest participation the 2/3 rule accepts (341 is refused above):
     *  Milagro signing is ~8 ms per signer, so every signer saved is CI time. */
    private static final int MIN_PARTICIPANTS = 342;
    /** Signed updates are immutable inputs here, so the four distinct ones are
     *  built once for all boundary tests (each build signs 342 messages). */
    private static final java.util.Map<String, Object> SIGNED = new java.util.HashMap<>();

    private static ForkSchedule boundarySchedule() {
        return ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x05000000),
                ForkSchedule.fork(BOUNDARY_EPOCH, 0x06000000));
    }

    private LightClientFinalityUpdate boundaryFinality(long finalizedSlot, long signatureSlot, byte[] fork) {
        String key = "fin:" + finalizedSlot + ":" + signatureSlot + ":" + fork[0];
        return (LightClientFinalityUpdate) SIGNED.computeIfAbsent(key,
                k -> buildFinalityUpdate(finalizedSlot, signatureSlot, MIN_PARTICIPANTS, fork));
    }

    private LightClientUpdate boundaryUpdate(long finalizedSlot, long signatureSlot, byte[] fork) {
        String key = "upd:" + finalizedSlot + ":" + signatureSlot + ":" + fork[0];
        return (LightClientUpdate) SIGNED.computeIfAbsent(key,
                k -> buildUpdate(finalizedSlot, signatureSlot, fork));
    }

    /** Rust twin: tests/fork_boundary.rs. */
    @Test
    void verifiesAcrossForkBoundary() {
        LightClientProcessor p = new LightClientProcessor(store, boundarySchedule(), GVR);
        // signatureSlot 320: the spec verifies epoch(319) = 9 -> still OLD.
        assertTrue(p.processFinalityUpdate(boundaryFinality(200L, BOUNDARY_SLOT, OLD_FORK)));
        assertEquals(200L, store.getFinalizedSlot());
        // signatureSlot 321: epoch(320) = 10 -> NEW.
        assertTrue(p.processFinalityUpdate(boundaryFinality(300L, BOUNDARY_SLOT + 1, NEW_FORK)));
        assertEquals(300L, store.getFinalizedSlot());
    }

    /** The catch-up path (LightClientUpdate) — how a pre-fork checkpoint walks across. */
    @Test
    void catchUpUpdatesVerifyAcrossForkBoundary() {
        LightClientProcessor p = new LightClientProcessor(store, boundarySchedule(), GVR);
        assertTrue(p.processUpdate(boundaryUpdate(200L, BOUNDARY_SLOT, OLD_FORK)));
        assertNotNull(store.getNextSyncCommittee(), "first update proves the next committee");
        assertTrue(p.processUpdate(boundaryUpdate(300L, BOUNDARY_SLOT + 1, NEW_FORK)));
        assertEquals(300L, store.getFinalizedSlot());
        // Cross-signed: rejected on both sides.
        assertFalse(p.processUpdate(boundaryUpdate(400L, BOUNDARY_SLOT, NEW_FORK)));
        assertFalse(p.processUpdate(boundaryUpdate(400L, BOUNDARY_SLOT + 1, OLD_FORK)));
        assertEquals(300L, store.getFinalizedSlot());
    }

    @Test
    void rejectsUpdateSignedUnderTheOtherSidesFork() {
        LightClientProcessor p = new LightClientProcessor(store, boundarySchedule(), GVR);
        // NEW at the last OLD slot, OLD at the first NEW slot: both must fail.
        assertFalse(p.processFinalityUpdate(boundaryFinality(200L, BOUNDARY_SLOT, NEW_FORK)));
        assertFalse(p.processFinalityUpdate(boundaryFinality(200L, BOUNDARY_SLOT + 1, OLD_FORK)));
        assertEquals(100L, store.getFinalizedSlot(), "nothing applied");
    }

    /** The pre-#295 behaviour, pinned as a regression: one fixed version cannot cross. */
    @Test
    void singleVersionScheduleStallsAtTheBoundary() {
        LightClientProcessor oldOnly = new LightClientProcessor(store, ForkSchedule.single(OLD_FORK), GVR);
        assertTrue(oldOnly.processFinalityUpdate(boundaryFinality(200L, BOUNDARY_SLOT, OLD_FORK)));
        assertFalse(oldOnly.processFinalityUpdate(boundaryFinality(300L, BOUNDARY_SLOT + 1, NEW_FORK)));

        LightClientStore fresh = new LightClientStore();
        fresh.initialize(TestUtil.dummyLightClientHeader(
                new BeaconBlockHeader(100L, 0L, new byte[32], new byte[32], new byte[32])), syncCommittee);
        LightClientProcessor newOnly = new LightClientProcessor(fresh, ForkSchedule.single(NEW_FORK), GVR);
        assertFalse(newOnly.processFinalityUpdate(boundaryFinality(200L, BOUNDARY_SLOT, OLD_FORK)));
    }

    /**
     * A LightClientUpdate whose finality branch (depth 6, gindex 105) and
     * next-sync-committee branch (depth 5, gindex 55) both verify against ONE
     * attested state root: a 32-leaf state tree with the checkpoint container
     * at field 20 (epoch root || finalized root) and the committee at field 23.
     */
    private LightClientUpdate buildUpdate(long finalizedSlot, long signatureSlot, byte[] forkVersion) {
        LightClientHeader finalizedHeader = TestUtil.consistentLightClientHeader(
                finalizedSlot, 0L, new byte[32], new byte[32]);
        byte[] zero = new byte[32];
        byte[][] leaves = new byte[32][32];
        leaves[20] = SszUtil.sha256(zero, finalizedHeader.beacon().hashTreeRoot()); // Checkpoint{epoch, root}
        leaves[23] = syncCommittee.hashTreeRoot();
        byte[][] tree = TestUtil.buildMerkleTree(leaves);
        byte[][] checkpointBranch = TestUtil.extractBranch(tree, 5, 20);
        byte[][] finalityBranch = new byte[6][];
        finalityBranch[0] = zero; // the epoch leaf, sibling of the root inside Checkpoint
        System.arraycopy(checkpointBranch, 0, finalityBranch, 1, 5);
        byte[][] committeeBranch = TestUtil.extractBranch(tree, 5, 23);

        LightClientHeader attestedHeader = TestUtil.consistentLightClientHeader(
                signatureSlot, 0L, new byte[32], tree[1]);
        SyncAggregate agg = buildSyncAggregate(attestedHeader.beacon(), MIN_PARTICIPANTS, forkVersion);
        return new LightClientUpdate(attestedHeader, syncCommittee, committeeBranch,
                finalizedHeader, finalityBranch, agg, signatureSlot);
    }

    @Test
    void rejectsNullCommittee() {
        // Fresh store without initialization
        LightClientStore emptyStore = new LightClientStore();
        LightClientProcessor emptyProcessor = new LightClientProcessor(emptyStore, ForkSchedule.single(FORK_VERSION), GVR);

        LightClientFinalityUpdate update = buildValidFinalityUpdate(700L, 701L);
        assertFalse(emptyProcessor.processFinalityUpdate(update));
    }

    @Test
    void processUpdateRejectsInvalidSyncCommitteeBranch() {
        // Build a LightClientUpdate with valid BLS + finality but corrupt committee branch
        long finalizedSlot = 800L;
        long signatureSlot = 801L;

        // Build finalized header and its Merkle proof in attested state
        LightClientHeader finalizedHeader = TestUtil.consistentLightClientHeader(
                finalizedSlot, 0L, new byte[32], new byte[32]);
        byte[] finalizedRoot = finalizedHeader.beacon().hashTreeRoot();

        // Build depth-6 tree for finality branch
        int finalityLeafIdx = BeaconChainSpec.FINALIZED_ROOT_GINDEX % 64;
        byte[][] finalityLeaves = new byte[64][32];
        finalityLeaves[finalityLeafIdx] = finalizedRoot;
        byte[][] finalityTree = TestUtil.buildMerkleTree(finalityLeaves);
        byte[][] finalityBranch = TestUtil.extractBranch(finalityTree, 6, finalityLeafIdx);

        // The attested header's stateRoot is the Merkle root for the finality tree
        byte[] attestedStateRoot = finalityTree[1];
        LightClientHeader attestedHeader = TestUtil.consistentLightClientHeader(
                signatureSlot, 0L, new byte[32], attestedStateRoot);

        SyncAggregate agg = buildSyncAggregate(attestedHeader.beacon(), 512, FORK_VERSION);

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
        BIG[] nextKeys = new BIG[512];
        byte[][] nextPubkeys = new byte[512][];
        for (int i = 0; i < 512; i++) {
            nextKeys[i] = TestUtil.generateSecretKey(9000 + i);
            nextPubkeys[i] = TestUtil.getPublicKey(nextKeys[i]);
        }
        SyncCommittee nextCommittee = new SyncCommittee(nextPubkeys, aggregatePubkeys(nextPubkeys));

        // Store the next committee
        store.updateNextSyncCommittee(nextCommittee);

        // Process a finality update that crosses into period 1 (slot 8192+). Its
        // signature slot is in period 1, so it is signed by the NEXT committee
        // (spec validate_light_client_update, #423) — the same bytes signed with the
        // period-0 keys are a relabelled current-committee signature and must fail.
        long newSlot = BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD + 10; // period 1
        LightClientFinalityUpdate relabelled = buildValidFinalityUpdate(newSlot, newSlot + 1);
        assertFalse(processor.processFinalityUpdate(relabelled),
                "period-1 signature slot must be verified with the next committee, not the current one");
        LightClientFinalityUpdate update =
                buildFinalityUpdateWithParticipation(newSlot, newSlot + 1, 512, nextKeys);
        assertTrue(processor.processFinalityUpdate(update));
        assertEquals(newSlot, store.getFinalizedSlot());
        // Finality crossed into period 1, so the store rotated: next is now current.
        assertNull(store.getNextSyncCommittee());
        assertArrayEquals(nextCommittee.aggregatePubkey(), store.getCurrentSyncCommittee().aggregatePubkey());

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
        return buildFinalityUpdateWithParticipation(finalizedSlot, signatureSlot, participantCount, secretKeys);
    }

    private LightClientFinalityUpdate buildFinalityUpdateWithParticipation(
            long finalizedSlot, long signatureSlot, int participantCount, BIG[] keys) {
        return buildFinalityUpdate(finalizedSlot, signatureSlot, participantCount, keys, FORK_VERSION);
    }

    private LightClientFinalityUpdate buildFinalityUpdate(
            long finalizedSlot, long signatureSlot, int participantCount, byte[] forkVersion) {
        return buildFinalityUpdate(finalizedSlot, signatureSlot, participantCount, secretKeys, forkVersion);
    }

    /** Signed by {@code keys} (the current or the next committee) under {@code forkVersion}. */
    private LightClientFinalityUpdate buildFinalityUpdate(
            long finalizedSlot, long signatureSlot, int participantCount, BIG[] keys, byte[] forkVersion) {
        // Build finalized header (execution payload genuinely committed to its body root)
        LightClientHeader finalizedHeader = TestUtil.consistentLightClientHeader(
                finalizedSlot, 0L, new byte[32], new byte[32]);
        byte[] finalizedRoot = finalizedHeader.beacon().hashTreeRoot();

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
        LightClientHeader attestedHeader = TestUtil.consistentLightClientHeader(
                signatureSlot, 0L, new byte[32], attestedStateRoot);

        SyncAggregate agg = buildSyncAggregate(attestedHeader.beacon(), participantCount, keys, forkVersion);

        return new LightClientFinalityUpdate(
                attestedHeader, finalizedHeader, finalityBranch, agg, signatureSlot);
    }

    private SyncAggregate buildSyncAggregate(BeaconBlockHeader attestedBeacon, int participantCount) {
        return buildSyncAggregate(attestedBeacon, participantCount, secretKeys, FORK_VERSION);
    }

    private SyncAggregate buildSyncAggregate(BeaconBlockHeader attestedBeacon, int participantCount, BIG[] keys) {
        return buildSyncAggregate(attestedBeacon, participantCount, keys, FORK_VERSION);
    }

    private SyncAggregate buildSyncAggregate(BeaconBlockHeader attestedBeacon, int participantCount,
                                             byte[] forkVersion) {
        return buildSyncAggregate(attestedBeacon, participantCount, secretKeys, forkVersion);
    }

    private SyncAggregate buildSyncAggregate(BeaconBlockHeader attestedBeacon, int participantCount,
                                             BIG[] keys, byte[] forkVersion) {
        byte[] domain = ForkData.computeDomain(BeaconChainSpec.DOMAIN_SYNC_COMMITTEE, forkVersion, GVR);
        byte[] signingRoot = SszUtil.hashTreeRootContainer(attestedBeacon.hashTreeRoot(), domain);

        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < participantCount; i++) {
            sigs.add(TestUtil.blsSign(keys[i], signingRoot));
        }
        byte[] aggSig = TestUtil.aggregateSignatures(sigs);

        byte[] bits = new byte[64];
        for (int i = 0; i < participantCount; i++) {
            bits[i / 8] |= (1 << (i % 8));
        }
        return new SyncAggregate(bits, aggSig);
    }

    private static byte[] aggregatePubkeys(byte[][] pks) {
        ECP agg = BlsVerifier.deserializeG1(pks[0]);
        for (int i = 1; i < pks.length; i++) {
            agg.add(BlsVerifier.deserializeG1(pks[i]));
        }
        agg.affine();
        return BlsVerifier.serializeG1(agg);
    }
}
