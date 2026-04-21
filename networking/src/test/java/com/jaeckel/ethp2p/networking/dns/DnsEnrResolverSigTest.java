package com.jaeckel.ethp2p.networking.dns;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hermetic tests for the root-record signature verifier. Generates a fresh
 * keypair, signs a fabricated root record in-test, and asserts that
 * {@link DnsEnrResolver#parseAndVerifyRoot(String, SECP256K1.PublicKey)}
 * accepts the exact bytes and rejects single-bit flips or the wrong signer.
 */
class DnsEnrResolverSigTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static String buildSignedRoot(SECP256K1.KeyPair keyPair, String eHash, String lHash, long seq) {
        String signed = "enrtree-root:v1 e=" + eHash + " l=" + lHash + " seq=" + seq;
        Bytes32 hash = Hash.keccak256(Bytes.wrap(signed.getBytes(StandardCharsets.UTF_8)));
        SECP256K1.Signature sig = SECP256K1.signHashed(hash, keyPair);
        byte[] r = padTo32(sig.r().toByteArray());
        byte[] s = padTo32(sig.s().toByteArray());
        byte[] sigBytes = new byte[65];
        System.arraycopy(r, 0, sigBytes, 0, 32);
        System.arraycopy(s, 0, sigBytes, 32, 32);
        sigBytes[64] = (byte) sig.v();
        String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
        return signed + " sig=" + sigB64;
    }

    private static byte[] padTo32(byte[] in) {
        if (in.length == 32) return in;
        byte[] out = new byte[32];
        // BigInteger.toByteArray may emit a leading 0x00 or be shorter than 32 bytes
        int src = in.length > 32 ? in.length - 32 : 0;
        int dst = 32 - (in.length - src);
        System.arraycopy(in, src, out, dst, in.length - src);
        return out;
    }

    @Test
    void acceptsValidRoot() {
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();
        String root = buildSignedRoot(kp,
                "JWXYDBZXG3IZNBHNJKAPP7QPQEBA", "FDXN3SN67NA5PPNEKTH6OC6OM4", 42L);
        assertDoesNotThrow(() -> DnsEnrResolver.parseAndVerifyRoot(root, kp.publicKey()));
    }

    @Test
    void rejectsFlippedSignatureByte() {
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();
        String root = buildSignedRoot(kp,
                "JWXYDBZXG3IZNBHNJKAPP7QPQEBA", "FDXN3SN67NA5PPNEKTH6OC6OM4", 1L);
        // Flip a byte inside the base64 signature field
        int sigIdx = root.indexOf(" sig=") + " sig=".length();
        char orig = root.charAt(sigIdx);
        char flipped = (orig == 'A') ? 'B' : 'A';
        String tampered = root.substring(0, sigIdx) + flipped + root.substring(sigIdx + 1);
        Throwable t = assertThrows(RuntimeException.class,
                () -> DnsEnrResolver.parseAndVerifyRoot(tampered, kp.publicKey()));
        assertTrue(
                t instanceof IllegalStateException || t instanceof IllegalArgumentException,
                "expected verification failure, got: " + t);
    }

    @Test
    void rejectsWrongSigner() {
        SECP256K1.KeyPair signer = SECP256K1.KeyPair.random();
        SECP256K1.KeyPair wrongExpected = SECP256K1.KeyPair.random();
        String root = buildSignedRoot(signer,
                "JWXYDBZXG3IZNBHNJKAPP7QPQEBA", "FDXN3SN67NA5PPNEKTH6OC6OM4", 1L);
        assertThrows(IllegalStateException.class,
                () -> DnsEnrResolver.parseAndVerifyRoot(root, wrongExpected.publicKey()));
    }

    @Test
    void rejectsMissingSigField() {
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();
        assertThrows(IllegalArgumentException.class,
                () -> DnsEnrResolver.parseAndVerifyRoot(
                        "enrtree-root:v1 e=AAAA l=BBBB seq=1", kp.publicKey()));
    }

    @Test
    void rejectsNonRootPrefix() {
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();
        assertThrows(IllegalArgumentException.class,
                () -> DnsEnrResolver.parseAndVerifyRoot("enr:foo sig=bar", kp.publicKey()));
    }
}
