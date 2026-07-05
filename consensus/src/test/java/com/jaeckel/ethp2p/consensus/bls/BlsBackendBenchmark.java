package com.jaeckel.ethp2p.consensus.bls;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Micro-benchmark of the light client's BLS hot path — {@code fastAggregateVerify} over a
 * real ~511-pubkey mainnet sync-committee aggregate (resources/bls_real_failure.txt) —
 * across every available backend: pure-Java Milagro, jblst (blst via SWIG, desktop only),
 * and the in-house native Rust blst ({@code rust/myotis-bls}, when its lib is on
 * java.library.path — see consensus/build.gradle.kts). All backends do identical work, so
 * pass/fail is irrelevant; only wall-clock matters, and they must all agree.
 *
 * <p>Reports two regimes per backend: <b>cold</b> (first verify, empty caches — the
 * committee-rotation cost that triggers the Android ANR work) and <b>warm</b> (steady
 * state). Run: {@code ./gradlew :consensus:test --tests '*BlsBackendBenchmark'} (stdout).
 */
public class BlsBackendBenchmark {

    @Test
    void compareBackends() throws Exception {
        Map<String, String> f = loadFixture("/bls_real_failure.txt");
        int n = Integer.parseInt(f.get("n").trim());
        byte[] msg = hex(f.get("msg"));
        byte[] sig = hex(f.get("sig"));
        List<byte[]> pks = new ArrayList<>(n);
        for (int i = 0; i < n; i++) pks.add(hex(f.get("pk." + i)));

        // Build the backend list (native only if its lib loaded).
        Map<String, BlsBackend> backends = new LinkedHashMap<>();
        backends.put("Milagro (pure-Java)", new MilagroBlsBackend());
        backends.put("jblst (blst SWIG)", new JblstBlsBackend());
        if (NativeBlsBackend.isAvailable()) {
            backends.put("blst (native/rust)", new NativeBlsBackend());
        } else {
            System.out.println("[note] native blst lib not on java.library.path — "
                    + "build it: (cd rust && cargo build --release)");
        }

        System.out.println();
        System.out.println("=========== BLS fastAggregateVerify benchmark (" + n + " pubkeys) ===========");
        System.out.printf("%-22s %12s %12s%n", "backend", "cold (ms)", "warm (ms/op)");
        System.out.println("-----------------------------------------------------------");

        Boolean reference = null;
        double milagroWarm = -1, fastestWarm = Double.MAX_VALUE;
        for (Map.Entry<String, BlsBackend> e : backends.entrySet()) {
            BlsBackend b = e.getValue();

            try {
                long c0 = System.nanoTime();
                boolean r = b.fastAggregateVerify(pks, msg, sig);
                double coldMs = (System.nanoTime() - c0) / 1e6;

                if (reference == null) reference = r;
                else if (r != reference) {
                    throw new AssertionError(e.getKey() + " disagreed with the reference verdict");
                }

                for (int i = 0; i < 3; i++) b.fastAggregateVerify(pks, msg, sig); // warmup
                int iters = 30;
                long w0 = System.nanoTime();
                for (int i = 0; i < iters; i++) b.fastAggregateVerify(pks, msg, sig);
                double warmMs = (System.nanoTime() - w0) / 1e6 / iters;

                System.out.printf("%-22s %12.1f %12.2f%n", e.getKey(), coldMs, warmMs);
                if (e.getKey().startsWith("Milagro")) milagroWarm = warmMs;
                fastestWarm = Math.min(fastestWarm, warmMs);
            } catch (AssertionError disagreement) {
                throw disagreement;   // a genuine verdict disagreement is a real failure
            } catch (Throwable t) {
                // A backend's native lib may be absent for this OS/arch (UnsatisfiedLinkError
                // etc.). Skip it — this benchmark runs on many dev machines / CI environments —
                // rather than failing the whole run or printing a misleading timing.
                System.out.printf("%-22s %12s  (skipped: %s)%n",
                        e.getKey(), "—", t.getClass().getSimpleName());
            }
        }
        System.out.println("-----------------------------------------------------------");
        System.out.printf("all backends agree (result=%b)%n", reference);
        if (milagroWarm > 0) {
            System.out.printf("fastest warm vs Milagro warm: %.1fx%n", milagroWarm / fastestWarm);
        }
        System.out.println("NOTE: x86-64/HotSpot flatters Milagro; on Android/ART the native");
        System.out.println("      win is far larger (see docs/bls-rust-acceleration.md).");
        System.out.println("===========================================================");
        System.out.println();

        assertTrue(reference != null, "benchmark ran");
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
