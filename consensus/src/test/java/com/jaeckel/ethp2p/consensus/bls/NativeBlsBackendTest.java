package com.jaeckel.ethp2p.consensus.bls;

import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.apache.milagro.amcl.BLS381.PAIR;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The native backend's JNI shim ({@code rust/myotis-bls}, feature {@code jni}) on a VALID
 * signature. The benchmark only compares verdicts, and its triple is invalid, so a shim that
 * returned {@code false} for every call (a JNI error is mapped to {@code false}) would agree
 * with Milagro there. Here the signature is made with Milagro under Ethereum's POP DST
 * (sig = H(m) * sum(sk), the aggregate of the three signers), so only a working shim says
 * {@code true}. Skipped where the native library is not on {@code java.library.path}.
 */
class NativeBlsBackendTest {

    private static final byte[] POP_DST =
            "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".getBytes(StandardCharsets.UTF_8);

    @Test
    void nativeAcceptsAValidAggregateAndRejectsAnotherMessage() {
        assumeTrue(NativeBlsBackend.isAvailable(), "native blst library not loaded");

        int[] secrets = {7, 11, 13};
        List<byte[]> pubkeys = new ArrayList<>();
        BIG sum = new BIG(0);
        for (int s : secrets) {
            BIG sk = new BIG(s);
            ECP pk = PAIR.G1mul(ECP.generator(), sk);
            pubkeys.add(BlsVerifier.serializeG1(pk));
            sum.add(sk);
        }
        byte[] message = new byte[32];
        for (int i = 0; i < message.length; i++) message[i] = (byte) (i + 1);
        ECP2 h = HashToCurve.hashToG2(message, POP_DST);
        byte[] signature = BlsVerifier.serializeG2(PAIR.G2mul(h, sum));

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
}
