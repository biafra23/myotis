package com.jaeckel.ethp2p.consensus.bls;

import com.jaeckel.ethp2p.consensus.TestUtil;
import org.junit.jupiter.api.Test;
import supranational.blst.SecretKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for BlsVerifier BLS12-381 signature verification.
 */
class BlsVerifierTest {

    // === Existing negative tests (invalid inputs) ===

    @Test
    void rejectsEmptyPubkeyList() {
        byte[] msg = new byte[32];
        byte[] sig = new byte[96]; // all-zero, invalid
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(), msg, sig));
    }

    @Test
    void rejectsInvalidCompressedPubkey() {
        byte[] invalidPubkey = new byte[48]; // all zeros — invalid G1 point
        byte[] msg = new byte[32];
        byte[] sig = new byte[96];
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(invalidPubkey), msg, sig));
    }

    @Test
    void rejectsInvalidSignatureBytes() {
        byte[] pubkey = new byte[48]; // invalid but non-crashing
        byte[] msg = new byte[32];
        byte[] invalidSig = new byte[96]; // all zeros — invalid G2 point
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(pubkey), msg, invalidSig));
    }

    @Test
    void rejectsWrongPubkeySize() {
        byte[] wrongSize = new byte[47]; // should be 48
        byte[] msg = new byte[32];
        byte[] sig = new byte[96];
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(wrongSize), msg, sig));
    }

    @Test
    void rejectsWrongSignatureSize() {
        byte[] pubkey = new byte[48];
        byte[] msg = new byte[32];
        byte[] wrongSig = new byte[95]; // should be 96
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(pubkey), msg, wrongSig));
    }

    // === New positive tests ===

    @Test
    void validSingleSignatureVerifies() {
        SecretKey sk = TestUtil.generateSecretKey(1);
        byte[] pk = TestUtil.getPublicKey(sk);
        byte[] msg = new byte[32];
        msg[0] = 0x42;
        byte[] sig = TestUtil.blsSign(sk, msg);

        assertTrue(BlsVerifier.fastAggregateVerify(List.of(pk), msg, sig));
    }

    @Test
    void validAggregateOfMultipleSignatures() {
        int count = 10;
        byte[] msg = new byte[32];
        msg[0] = (byte) 0xAB;

        List<byte[]> pubkeys = new ArrayList<>();
        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            SecretKey sk = TestUtil.generateSecretKey(100 + i);
            pubkeys.add(TestUtil.getPublicKey(sk));
            sigs.add(TestUtil.blsSign(sk, msg));
        }

        byte[] aggSig = TestUtil.aggregateSignatures(sigs);
        assertTrue(BlsVerifier.fastAggregateVerify(pubkeys, msg, aggSig));
    }

    // === New negative tests ===

    @Test
    void rejectsWrongMessage() {
        SecretKey sk = TestUtil.generateSecretKey(2);
        byte[] pk = TestUtil.getPublicKey(sk);
        byte[] msg = new byte[32];
        msg[0] = 0x01;
        byte[] sig = TestUtil.blsSign(sk, msg);

        byte[] wrongMsg = new byte[32];
        wrongMsg[0] = 0x02;
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(pk), wrongMsg, sig));
    }

    @Test
    void rejectsWrongSignature() {
        SecretKey sk = TestUtil.generateSecretKey(3);
        byte[] pk = TestUtil.getPublicKey(sk);
        byte[] msg = new byte[32];
        byte[] sig = TestUtil.blsSign(sk, msg);

        // Flip a byte in the signature
        byte[] tamperedSig = Arrays.copyOf(sig, 96);
        tamperedSig[10] ^= 0x01;
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(pk), msg, tamperedSig));
    }

    @Test
    void rejectsWrongPubkey() {
        SecretKey sk1 = TestUtil.generateSecretKey(4);
        SecretKey sk2 = TestUtil.generateSecretKey(5);
        byte[] pk2 = TestUtil.getPublicKey(sk2);
        byte[] msg = new byte[32];
        byte[] sig = TestUtil.blsSign(sk1, msg);

        // Sign with sk1, verify with pk2
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(pk2), msg, sig));
    }

    @Test
    void rejectsAggregateWithMissingPubkey() {
        byte[] msg = new byte[32];
        msg[0] = 0x10;

        List<byte[]> allPks = new ArrayList<>();
        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            SecretKey sk = TestUtil.generateSecretKey(200 + i);
            allPks.add(TestUtil.getPublicKey(sk));
            sigs.add(TestUtil.blsSign(sk, msg));
        }

        byte[] aggSig = TestUtil.aggregateSignatures(sigs);
        // Verify with only 2 of the 3 pubkeys — should fail
        List<byte[]> partialPks = allPks.subList(0, 2);
        assertFalse(BlsVerifier.fastAggregateVerify(partialPks, msg, aggSig));
    }

    @Test
    void rejectsAggregateWithExtraPubkey() {
        byte[] msg = new byte[32];
        msg[0] = 0x20;

        List<byte[]> signerPks = new ArrayList<>();
        List<byte[]> sigs = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            SecretKey sk = TestUtil.generateSecretKey(300 + i);
            signerPks.add(TestUtil.getPublicKey(sk));
            sigs.add(TestUtil.blsSign(sk, msg));
        }

        byte[] aggSig = TestUtil.aggregateSignatures(sigs);

        // Add an extra pubkey that didn't sign
        List<byte[]> extraPks = new ArrayList<>(signerPks);
        extraPks.add(TestUtil.getPublicKey(TestUtil.generateSecretKey(999)));
        assertFalse(BlsVerifier.fastAggregateVerify(extraPks, msg, aggSig));
    }
}
