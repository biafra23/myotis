package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.TestUtil;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ForkData;
import com.jaeckel.ethp2p.consensus.types.SyncAggregate;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import supranational.blst.SecretKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SyncCommitteeVerifier participation counting, rejection logic, and BLS verification.
 */
class SyncCommitteeVerifierTest {

    private static final byte[] FORK_VERSION = {0x05, 0x00, 0x00, 0x00};
    private static final byte[] GVR = new byte[32]; // all-zero genesis validators root

    // Pre-generated keys for BLS tests (512 keys)
    private static SecretKey[] secretKeys;
    private static byte[][] pubkeys;

    @BeforeAll
    static void generateKeys() {
        secretKeys = new SecretKey[512];
        pubkeys = new byte[512][];
        for (int i = 0; i < 512; i++) {
            secretKeys[i] = TestUtil.generateSecretKey(5000 + i);
            pubkeys[i] = TestUtil.getPublicKey(secretKeys[i]);
        }
    }

    // === Existing tests ===

    @Test
    void rejectsBelowTwoThirdsParticipation() {
        byte[] bits = new byte[64];
        for (int i = 0; i < 341; i++) {
            bits[i / 8] |= (1 << (i % 8));
        }
        byte[] sig = new byte[96];
        byte[] syncAggSsz = new byte[64 + 96];
        System.arraycopy(bits, 0, syncAggSsz, 0, 64);
        System.arraycopy(sig, 0, syncAggSsz, 64, 96);
        SyncAggregate agg = SyncAggregate.decode(syncAggSsz);

        assertEquals(341, agg.countParticipants());

        byte[] committeeSsz = new byte[512 * 48 + 48];
        SyncCommittee committee = SyncCommittee.decode(committeeSsz);

        BeaconBlockHeader header = new BeaconBlockHeader(1L, 0L, new byte[32], new byte[32], new byte[32]);

        assertFalse(SyncCommitteeVerifier.verify(agg, committee, header, FORK_VERSION, GVR));
    }

    @Test
    void rejectsZeroParticipation() {
        byte[] syncAggSsz = new byte[160];
        SyncAggregate agg = SyncAggregate.decode(syncAggSsz);
        assertEquals(0, agg.countParticipants());

        byte[] committeeSsz = new byte[512 * 48 + 48];
        SyncCommittee committee = SyncCommittee.decode(committeeSsz);
        BeaconBlockHeader header = new BeaconBlockHeader(0L, 0L, new byte[32], new byte[32], new byte[32]);

        assertFalse(SyncCommitteeVerifier.verify(agg, committee, header, new byte[4], new byte[32]));
    }

    @Test
    void countParticipantsAtExactTwoThirds() {
        byte[] bits = new byte[64];
        for (int i = 0; i < 342; i++) {
            bits[i / 8] |= (1 << (i % 8));
        }
        byte[] syncAggSsz = new byte[160];
        System.arraycopy(bits, 0, syncAggSsz, 0, 64);
        SyncAggregate agg = SyncAggregate.decode(syncAggSsz);
        assertEquals(342, agg.countParticipants());
    }

    @Test
    void getBitCorrectness() {
        byte[] bits = new byte[64];
        bits[0] = 0b00000101; // bits 0 and 2 set
        bits[1] = (byte) 0b10000000; // bit 15 set
        byte[] syncAggSsz = new byte[160];
        System.arraycopy(bits, 0, syncAggSsz, 0, 64);
        SyncAggregate agg = SyncAggregate.decode(syncAggSsz);

        assertTrue(agg.getBit(0));
        assertFalse(agg.getBit(1));
        assertTrue(agg.getBit(2));
        assertTrue(agg.getBit(15));
        assertFalse(agg.getBit(16));
    }

    // === New BLS-verified tests ===

    @Test
    void validSyncAggregateVerifies() {
        BeaconBlockHeader header = new BeaconBlockHeader(100L, 0L, new byte[32], new byte[32], new byte[32]);
        SyncAggregate agg = buildValidSyncAggregate(header, 512);
        SyncCommittee committee = buildSyncCommittee();

        assertTrue(SyncCommitteeVerifier.verify(agg, committee, header, FORK_VERSION, GVR));
    }

    @Test
    void validAtExactTwoThirdsThreshold() {
        BeaconBlockHeader header = new BeaconBlockHeader(200L, 1L, new byte[32], new byte[32], new byte[32]);
        SyncAggregate agg = buildValidSyncAggregate(header, 342);
        SyncCommittee committee = buildSyncCommittee();

        assertTrue(SyncCommitteeVerifier.verify(agg, committee, header, FORK_VERSION, GVR));
    }

    @Test
    void rejectsWrongForkVersion() {
        BeaconBlockHeader header = new BeaconBlockHeader(300L, 0L, new byte[32], new byte[32], new byte[32]);
        SyncAggregate agg = buildValidSyncAggregate(header, 512);
        SyncCommittee committee = buildSyncCommittee();

        byte[] wrongFork = {0x06, 0x00, 0x00, 0x00};
        assertFalse(SyncCommitteeVerifier.verify(agg, committee, header, wrongFork, GVR));
    }

    @Test
    void rejectsWrongGenesisValidatorsRoot() {
        BeaconBlockHeader header = new BeaconBlockHeader(400L, 0L, new byte[32], new byte[32], new byte[32]);
        SyncAggregate agg = buildValidSyncAggregate(header, 512);
        SyncCommittee committee = buildSyncCommittee();

        byte[] wrongGvr = new byte[32];
        wrongGvr[0] = 0x01;
        assertFalse(SyncCommitteeVerifier.verify(agg, committee, header, FORK_VERSION, wrongGvr));
    }

    @Test
    void rejectsTamperedSignature() {
        BeaconBlockHeader header = new BeaconBlockHeader(500L, 0L, new byte[32], new byte[32], new byte[32]);
        SyncAggregate agg = buildValidSyncAggregate(header, 512);
        SyncCommittee committee = buildSyncCommittee();

        // Tamper the signature
        byte[] tamperedSig = Arrays.copyOf(agg.syncCommitteeSignature(), 96);
        tamperedSig[10] ^= 0x01;
        SyncAggregate tampered = new SyncAggregate(agg.syncCommitteeBits(), tamperedSig);

        assertFalse(SyncCommitteeVerifier.verify(tampered, committee, header, FORK_VERSION, GVR));
    }

    @Test
    void rejectsWrongHeader() {
        BeaconBlockHeader header = new BeaconBlockHeader(600L, 0L, new byte[32], new byte[32], new byte[32]);
        SyncAggregate agg = buildValidSyncAggregate(header, 512);
        SyncCommittee committee = buildSyncCommittee();

        // Verify against a different header (different slot)
        BeaconBlockHeader wrongHeader = new BeaconBlockHeader(601L, 0L, new byte[32], new byte[32], new byte[32]);
        assertFalse(SyncCommitteeVerifier.verify(agg, committee, wrongHeader, FORK_VERSION, GVR));
    }

    @Test
    void rejectsMismatchedBits() {
        BeaconBlockHeader header = new BeaconBlockHeader(700L, 0L, new byte[32], new byte[32], new byte[32]);
        // Sign with all 512 keys
        SyncAggregate fullAgg = buildValidSyncAggregate(header, 512);

        // But set bits to only 511 (missing the last one)
        byte[] bits511 = new byte[64];
        Arrays.fill(bits511, (byte) 0xFF);
        bits511[63] = (byte) 0x7F; // clear bit 511

        SyncAggregate mismatchedAgg = new SyncAggregate(bits511, fullAgg.syncCommitteeSignature());
        SyncCommittee committee = buildSyncCommittee();

        // Signature was from 512 keys, but bits say 511 → pubkey set mismatch → should fail
        assertFalse(SyncCommitteeVerifier.verify(mismatchedAgg, committee, header, FORK_VERSION, GVR));
    }

    // === Helpers ===

    private SyncCommittee buildSyncCommittee() {
        // Compute aggregate pubkey from all 512 keys
        supranational.blst.P1 agg = new supranational.blst.P1(new supranational.blst.P1_Affine(pubkeys[0]));
        for (int i = 1; i < 512; i++) {
            agg.aggregate(new supranational.blst.P1_Affine(pubkeys[i]));
        }
        return new SyncCommittee(pubkeys, agg.compress());
    }

    /**
     * Build a valid SyncAggregate: sign the attested header with the first {@code participantCount} keys.
     */
    private SyncAggregate buildValidSyncAggregate(BeaconBlockHeader header, int participantCount) {
        // Compute signing root (same as SyncCommitteeVerifier does internally)
        byte[] domain = ForkData.computeDomain(BeaconChainSpec.DOMAIN_SYNC_COMMITTEE, FORK_VERSION, GVR);
        byte[] signingRoot = SszUtil.hashTreeRootContainer(header.hashTreeRoot(), domain);

        // Sign with participating keys and aggregate
        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < participantCount; i++) {
            sigs.add(TestUtil.blsSign(secretKeys[i], signingRoot));
        }
        byte[] aggSig = TestUtil.aggregateSignatures(sigs);

        // Build bitvector with first participantCount bits set
        byte[] bits = new byte[64];
        for (int i = 0; i < participantCount; i++) {
            bits[i / 8] |= (1 << (i % 8));
        }

        return new SyncAggregate(bits, aggSig);
    }
}
