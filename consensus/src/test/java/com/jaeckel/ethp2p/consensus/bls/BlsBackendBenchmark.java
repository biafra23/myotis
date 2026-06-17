package com.jaeckel.ethp2p.consensus.bls;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Micro-benchmark: pure-Java Milagro vs native blst (jblst) for the light client's
 * hot path — {@code fastAggregateVerify} over a real ~511-pubkey sync-committee
 * aggregate (resources/bls_real_failure.txt, captured from mainnet). Both backends do
 * identical work (decompress 511 G1 pubkeys, aggregate, hash-to-G2, pairing), so the
 * result (pass/fail) is irrelevant — only the wall-clock matters.
 *
 * <p>Prints two regimes that mirror production:
 * <ul>
 *   <li><b>cold</b> — first verify with an empty pubkey cache: the committee-rotation /
 *       fresh-bootstrap cost that triggered the Android ANR-mitigation work.</li>
 *   <li><b>warm</b> — Milagro with its decompressed-pubkey cache hot (steady state);
 *       jblst has no such cache, so every verify is a full native verify.</li>
 * </ul>
 *
 * Run: {@code ./gradlew :consensus:test --tests '*BlsBackendBenchmark'} (watch stdout).
 */
public class BlsBackendBenchmark {

    @Test
    void milagroVsJblst() throws Exception {
        Map<String, String> f = loadFixture("/bls_real_failure.txt");
        int n = Integer.parseInt(f.get("n").trim());
        byte[] msg = hex(f.get("msg"));
        byte[] sig = hex(f.get("sig"));
        List<byte[]> pks = new ArrayList<>(n);
        for (int i = 0; i < n; i++) pks.add(hex(f.get("pk." + i)));

        BlsBackend milagro = new MilagroBlsBackend();
        BlsBackend jblst = new JblstBlsBackend();

        // --- correctness: both backends must agree on the real aggregate ---
        // (cold timing piggybacks on this first call — Milagro's cache is empty here)
        long c0 = System.nanoTime();
        boolean rM = milagro.fastAggregateVerify(pks, msg, sig);
        long milagroColdMs = (System.nanoTime() - c0) / 1_000_000;

        long j0 = System.nanoTime();
        boolean rJ = jblst.fastAggregateVerify(pks, msg, sig);
        long jblstColdMs = (System.nanoTime() - j0) / 1_000_000;

        assertEquals(rM, rJ, "Milagro and jblst must agree on the same aggregate");

        // --- warm steady-state: average over N iterations ---
        for (int i = 0; i < 3; i++) { milagro.fastAggregateVerify(pks, msg, sig); jblst.fastAggregateVerify(pks, msg, sig); }
        int iters = 30;
        double milagroWarmMs = avgMs(milagro, pks, msg, sig, iters);
        double jblstWarmMs = avgMs(jblst, pks, msg, sig, iters);

        System.out.println();
        System.out.println("================ BLS fastAggregateVerify benchmark ================");
        System.out.printf ("pubkeys=%d   agree=%b (result=%b)%n", n, rM == rJ, rM);
        System.out.printf ("COLD (empty cache / rotation case):  Milagro=%d ms   jblst=%d ms   -> %.0fx%n",
                milagroColdMs, jblstColdMs, jblstColdMs == 0 ? Double.NaN : (double) milagroColdMs / Math.max(1, jblstColdMs));
        System.out.printf ("WARM (Milagro cache hot, %d iters):  Milagro=%.2f ms  jblst=%.2f ms  -> %.1fx%n",
                iters, milagroWarmMs, jblstWarmMs, milagroWarmMs / jblstWarmMs);
        System.out.println("===================================================================");
        System.out.println();

        // Sanity: the native path should not be slower than pure Java on either regime.
        assertTrue(jblstWarmMs <= milagroWarmMs * 1.5,
                "jblst warm should be in the same ballpark or faster than Milagro warm");
    }

    private static double avgMs(BlsBackend b, List<byte[]> pks, byte[] msg, byte[] sig, int iters) {
        long start = System.nanoTime();
        for (int i = 0; i < iters; i++) b.fastAggregateVerify(pks, msg, sig);
        return (System.nanoTime() - start) / 1e6 / iters;
    }

    private static Map<String, String> loadFixture(String resource) throws Exception {
        Map<String, String> m = new HashMap<>();
        try (var s = BlsBackendBenchmark.class.getResourceAsStream(resource);
             var r = new BufferedReader(new InputStreamReader(s, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq < 0) continue;
                m.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        return m;
    }

    private static byte[] hex(String s) {
        s = s.trim();
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }
}
