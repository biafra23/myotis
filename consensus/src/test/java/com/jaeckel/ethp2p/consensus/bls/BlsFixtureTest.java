package com.jaeckel.ethp2p.consensus.bls;

import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.apache.milagro.amcl.BLS381.PAIR;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the Milagro BLS implementation, anchored to hex-encoded
 * reference fixtures (generated once with supranational/blst). A mismatch here
 * indicates Milagro has diverged from canonical Ethereum BLS behavior.
 *
 * <p>Also asserts that a real mainnet sync-committee triple captured during
 * investigation (which is genuinely invalid — the committee was stale) continues
 * to be rejected.
 */
class BlsFixtureTest {

    private static final byte[] DST_BYTES = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_".getBytes(StandardCharsets.UTF_8);

    private static Map<String, String> fixtures;

    @BeforeAll
    static void loadFixtures() throws Exception {
        fixtures = new TreeMap<>();
        try (var stream = BlsFixtureTest.class.getResourceAsStream("/bls_fixtures.txt");
             var rdr = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = rdr.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq < 0) continue;
                fixtures.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
        assertFalse(fixtures.isEmpty(), "fixtures must load");
    }

    // ---- hash_to_G2 ----

    @Test
    void hashToG2_matchesJblst() {
        for (int i = 0; i < 5; i++) {
            byte[] msg = hex(fixtures.get("h2g2." + i + ".msg"));
            byte[] expected = hex(fixtures.get("h2g2." + i + ".out"));

            ECP2 point = HashToCurve.hashToG2(msg, DST_BYTES);
            byte[] actual = BlsVerifier.serializeG2(point);

            assertArrayEquals(expected, actual,
                    "hash_to_G2 mismatch at index " + i + "\n" +
                    "  expected: " + hex(expected) + "\n" +
                    "  actual:   " + hex(actual));
        }
    }

    // ---- sk -> pubkey (G1 scalar mul) ----

    @Test
    void skToPubkey_matchesJblst() {
        for (int i = 0; i < 5; i++) {
            byte[] skBytes = hex(fixtures.get("sk2pk." + i + ".sk"));
            byte[] expected = hex(fixtures.get("sk2pk." + i + ".pk"));

            byte[] padded = new byte[BIG.MODBYTES];
            System.arraycopy(skBytes, 0, padded, BIG.MODBYTES - skBytes.length, skBytes.length);
            BIG sk = BIG.fromBytes(padded);

            ECP pk = PAIR.G1mul(ECP.generator(), sk);
            byte[] actual = BlsVerifier.serializeG1(pk);

            assertArrayEquals(expected, actual,
                    "sk->pk mismatch at index " + i + "\n" +
                    "  expected: " + hex(expected) + "\n" +
                    "  actual:   " + hex(actual));
        }
    }

    // ---- sk -> sig via hash_to_G2 * sk ----

    @Test
    void sign_matchesJblst() {
        for (int i = 0; i < 3; i++) {
            byte[] skBytes = hex(fixtures.get("single." + i + ".sk"));
            byte[] msg = hex(fixtures.get("single." + i + ".msg"));
            byte[] expected = hex(fixtures.get("single." + i + ".sig"));

            byte[] padded = new byte[BIG.MODBYTES];
            System.arraycopy(skBytes, 0, padded, BIG.MODBYTES - skBytes.length, skBytes.length);
            BIG sk = BIG.fromBytes(padded);

            ECP2 hm = HashToCurve.hashToG2(msg, DST_BYTES);
            ECP2 sig = PAIR.G2mul(hm, sk);
            byte[] actual = BlsVerifier.serializeG2(sig);

            assertArrayEquals(expected, actual,
                    "sign mismatch at index " + i);
        }
    }

    // ---- single sig verify ----

    @Test
    void verifySingle_jblstFixtures() {
        for (int i = 0; i < 3; i++) {
            byte[] msg = hex(fixtures.get("single." + i + ".msg"));
            byte[] pk = hex(fixtures.get("single." + i + ".pk"));
            byte[] sig = hex(fixtures.get("single." + i + ".sig"));

            // Fixtures were generated under the NUL ciphersuite; production
            // uses POP (Ethereum's scheme). Explicit DST lets us regression-
            // test Milagro's hash_to_G2/pairing math without reshaping the
            // fixture corpus.
            assertTrue(BlsVerifier.fastAggregateVerify(List.of(pk), msg, sig, DST_BYTES),
                    "verify must pass for fixture single." + i);
        }
    }

    // ---- real-world rejection regression ----

    /**
     * Real mainnet sync-committee triple captured from libp2p (511-of-512 signers).
     * The signature does not match the (msg, agg_pk) — both Milagro and jblst rejected
     * it during investigation, because the wrong sync committee was being used to verify.
     * Asserting Milagro continues to reject it guards against any future regression
     * that would silently accept invalid signatures.
     */
    @Test
    void milagroRejectsInvalidRealTriple() throws Exception {
        var triple = loadTriple();
        assertFalse(BlsVerifier.fastAggregateVerify(triple.pks, triple.msg, triple.sig),
                "Milagro must reject the captured invalid triple");
    }

    private record Triple(List<byte[]> pks, byte[] msg, byte[] sig) {}

    private static Triple loadTriple() throws Exception {
        java.util.Map<String, String> m = new java.util.TreeMap<>();
        try (var s = BlsFixtureTest.class.getResourceAsStream("/bls_real_failure.txt");
             var r = new java.io.BufferedReader(new java.io.InputStreamReader(s, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq > 0) m.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
        int n = Integer.parseInt(m.get("n"));
        List<byte[]> pks = new ArrayList<>(n);
        for (int i = 0; i < n; i++) pks.add(hex(m.get("pk." + i)));
        return new Triple(pks, hex(m.get("msg")), hex(m.get("sig")));
    }

    // ---- aggregate verify ----

    @Test
    void verifyAggregate_jblstFixtures() {
        for (int n : new int[]{2, 4, 16}) {
            byte[] msg = hex(fixtures.get("agg." + n + ".msg"));
            byte[] sig = hex(fixtures.get("agg." + n + ".sig"));
            List<byte[]> pks = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                pks.add(hex(fixtures.get("agg." + n + ".pk." + i)));
            }
            // NUL-ciphersuite fixtures (see verifySingle_jblstFixtures).
            assertTrue(BlsVerifier.fastAggregateVerify(pks, msg, sig, DST_BYTES),
                    "aggregate verify must pass for n=" + n);
        }
    }

    // ---- G1 pubkey aggregation ----

    @Test
    void aggregateG1Pubkeys_matchesJblst() {
        int n = 8;
        byte[] expected = hex(fixtures.get("aggpk." + n + ".agg"));

        ECP agg = BlsVerifier.deserializeG1(hex(fixtures.get("aggpk." + n + ".pk.0")));
        for (int i = 1; i < n; i++) {
            ECP pk = BlsVerifier.deserializeG1(hex(fixtures.get("aggpk." + n + ".pk." + i)));
            agg.add(pk);
        }
        agg.affine();
        byte[] actual = BlsVerifier.serializeG1(agg);

        assertArrayEquals(expected, actual, "aggregate G1 pubkey mismatch");
    }

    // ---- non-canonical encoding rejection ----

    @Test
    void deserializeG1_rejectsUncompressed() {
        byte[] pk = hex(fixtures.get("sk2pk.0.pk"));
        byte[] bad = pk.clone();
        bad[0] &= 0x7F; // clear compression bit
        assertNull(BlsVerifier.deserializeG1(bad),
                "G1 must reject encoding without compression flag");
    }

    @Test
    void deserializeG2_rejectsUncompressed() {
        byte[] sig = hex(fixtures.get("single.0.sig"));
        byte[] bad = sig.clone();
        bad[0] &= 0x7F;
        assertNull(BlsVerifier.deserializeG2(bad),
                "G2 must reject encoding without compression flag");
    }

    @Test
    void deserializeG1_rejectsInfinityWithSortFlag() {
        byte[] bad = new byte[48];
        bad[0] = (byte) 0xE0; // compressed + infinity + sort — non-canonical
        assertNull(BlsVerifier.deserializeG1(bad),
                "G1 must reject infinity encoding with sort flag set");
    }

    @Test
    void deserializeG2_rejectsInfinityWithSortFlag() {
        byte[] bad = new byte[96];
        bad[0] = (byte) 0xE0;
        assertNull(BlsVerifier.deserializeG2(bad),
                "G2 must reject infinity encoding with sort flag set");
    }

    @Test
    void fastAggregateVerify_rejectsInfinitySignature() {
        byte[] pk = hex(fixtures.get("single.0.pk"));
        byte[] msg = hex(fixtures.get("single.0.msg"));
        byte[] infSig = new byte[96];
        infSig[0] = (byte) 0xC0; // canonical compressed infinity
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(pk), msg, infSig),
                "must reject identity-encoded signature");
    }

    @Test
    void fastAggregateVerify_rejectsInfinityPubkey() {
        byte[] infPk = new byte[48];
        infPk[0] = (byte) 0xC0;
        byte[] msg = hex(fixtures.get("single.0.msg"));
        byte[] sig = hex(fixtures.get("single.0.sig"));
        assertFalse(BlsVerifier.fastAggregateVerify(List.of(infPk), msg, sig),
                "must reject identity-encoded pubkey");
    }

    private static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4) | Character.digit(s.charAt(2 * i + 1), 16));
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
