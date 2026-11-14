package com.jaeckel.ethp2p.consensus.bls;

import com.jaeckel.ethp2p.consensus.TestUtil;
import org.apache.milagro.amcl.BLS381.BIG;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The native backend ({@code rust/myotis-bls}, feature {@code jni}) named directly. Valid
 * signatures also reach it through {@code BlsBackends.active()} under the default
 * {@code auto} ({@code SyncCommitteeVerifierTest}, {@code LcVectorConformanceTest}); naming
 * it keeps this test's meaning if the selection, or another test's {@code BlsBackends.set},
 * changes. The second test calls the private native method itself, past
 * {@link NativeBlsBackend}'s own argument checks, so the shim's raw JNI reads see null
 * arrays, wrong lengths and out-of-range counts.
 *
 * <p>Skipped where the native library is not loaded, like every test behind
 * {@code isAvailable()}: a library that fails to load leaves it green.
 */
class NativeBlsBackendTest {

    private List<byte[]> pubkeys;
    private byte[] message;
    private byte[] signature;

    @BeforeEach
    void signWithMilagro() {
        assumeTrue(NativeBlsBackend.isAvailable(), "native blst library not loaded");
        pubkeys = new ArrayList<>();
        List<byte[]> sigs = new ArrayList<>();
        message = new byte[32];
        for (int i = 0; i < message.length; i++) message[i] = (byte) (i + 1);
        for (int seed = 1; seed <= 3; seed++) {
            BIG sk = TestUtil.generateSecretKey(seed);
            pubkeys.add(TestUtil.getPublicKey(sk));
            sigs.add(TestUtil.blsSign(sk, message));
        }
        signature = TestUtil.aggregateSignatures(sigs);
    }

    @Test
    void nativeAcceptsAValidAggregateAndRejectsAnotherMessage() {
        assertTrue(BlsVerifier.fastAggregateVerify(pubkeys, message, signature),
                "the Milagro reference accepts the aggregate");
        NativeBlsBackend backend = new NativeBlsBackend();
        assertTrue(backend.fastAggregateVerify(pubkeys, message, signature),
                "the native backend accepts the same aggregate");

        byte[] other = message.clone();
        other[0] ^= 1;
        assertFalse(backend.fastAggregateVerify(pubkeys, other, signature),
                "the native backend rejects the signature for another message");
    }

    @Test
    void theNativeMethodItselfRejectsEveryMalformedCall() throws Exception {
        Method nativeVerify = NativeBlsBackend.class.getDeclaredMethod(
                "nativeFastAggregateVerify", byte[].class, int.class, byte[].class, byte[].class);
        nativeVerify.setAccessible(true);
        byte[] flat = new byte[pubkeys.size() * 48];
        for (int i = 0; i < pubkeys.size(); i++) System.arraycopy(pubkeys.get(i), 0, flat, i * 48, 48);
        int n = pubkeys.size();

        assertEquals(true, nativeVerify.invoke(null, flat, n, message, signature), "valid call");

        byte[] shortSig = new byte[95];
        System.arraycopy(signature, 0, shortSig, 0, 95);
        byte[] flatPlusOne = new byte[flat.length + 1];
        System.arraycopy(flat, 0, flatPlusOne, 0, flat.length);
        Object[][] malformed = {
                {null, n, message, signature},
                {flat, n, null, signature},
                {flat, n, message, null},
                {flat, 0, message, signature},
                {flat, -1, message, signature},
                {flat, 4097, message, signature},
                {flat, Integer.MAX_VALUE, message, signature},
                {flat, n - 1, message, signature},
                {flatPlusOne, n, message, signature},
                {new byte[0], n, message, signature},
                {flat, n, message, shortSig},
                {flat, n, message, new byte[0]},
        };
        for (int i = 0; i < malformed.length; i++) {
            assertEquals(false, nativeVerify.invoke(null, malformed[i]), "malformed call " + i);
        }
        // Nothing left pending: a following call still answers normally.
        assertEquals(true, nativeVerify.invoke(null, flat, n, message, signature), "valid call after");
    }
}
