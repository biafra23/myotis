package com.jaeckel.ethp2p.consensus.bls;

import org.apache.milagro.amcl.BLS381.*;

import java.util.Arrays;
import java.util.List;

/**
 * BLS12-381 signature verification for Ethereum 2.0 using Milagro AMCL (pure Java).
 *
 * <p>Ethereum 2.0 uses the "minimal-pubkey-size" variant:
 * <ul>
 *   <li>Public keys are G1 points (48 bytes compressed)</li>
 *   <li>Signatures are G2 points (96 bytes compressed)</li>
 * </ul>
 *
 * <p>The domain separation tag is defined in the Ethereum consensus spec for
 * sync committee messages.
 */
public final class BlsVerifier {

    /**
     * Domain separation tag for Ethereum 2.0 BLS signatures.
     */
    // Ethereum consensus uses the BLS Proof-of-Possession (POP) scheme per the
    // eth2 spec, not the basic (NUL) scheme. The hash-to-curve DST differs
    // between schemes: BLS_SIG_..._POP_ vs BLS_SIG_..._NUL_. Using NUL here
    // silently made every sync-aggregate verify fail — the hash_to_G2 output
    // didn't match what validators actually signed against. Regression from
    // the jblst → Milagro AMCL swap in 8acd8f1 (jblst hardcoded POP).
    // See draft-irtf-cfrg-bls-signature-05 §4.2.3 and consensus-specs.
    private static final String DST_STRING = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    private static final byte[] DST_BYTES = DST_STRING.getBytes();

    /** BLS12-381 prime-order subgroup generator scalar, used for subgroup membership checks. */
    private static final BIG CURVE_ORDER = new BIG(ROM.CURVE_Order);

    /**
     * (p-1)/2, used as the midpoint when encoding the y-coordinate sort flag for
     * compressed BLS12-381 points. Cached because every serialize/deserialize call
     * would otherwise rebuild it.
     */
    private static final BIG HALF_P = buildHalfP();

    private static BIG buildHalfP() {
        BIG halfP = new BIG(new BIG(ROM.Modulus));
        halfP.shr(1);
        return halfP;
    }

    // Decompressed-pubkey cache. G1 decompression (a field square root per key) is a
    // pure function of the 48 key bytes, and sync-committee pubkeys are fixed for a
    // ~27h period — yet fastAggregateVerify decompressed all ~512 on every update,
    // which dominates a finality-update verify on Android/ART (~35-55s). Capacity
    // covers current + next committee (2x512) with slack for rotation overlap; on
    // overflow the whole map is reset (rotations are rare; no LRU bookkeeping).
    // Values are master copies: Milagro ECP is mutable (reduce()/affine() normalize
    // in place), so lookups hand out fresh copies — concurrent verifies must never
    // share live point objects.
    private static final int PUBKEY_CACHE_MAX = 4096;
    private static final java.util.concurrent.ConcurrentHashMap<PubkeyKey, ECP> PUBKEY_CACHE =
            new java.util.concurrent.ConcurrentHashMap<>();

    // Dedicated pool for the parallel G1 decompression below — NOT the common
    // ForkJoinPool. parallelStream() defaults to the common pool (parallelism =
    // cores-1), so a committee warm-up or a burst of catch-up verifies pegged
    // every core at normal priority. On a foreground Android app that starved the
    // UI thread for >5s and triggered input-dispatch ANRs (the Compose hit-test /
    // frame work simply couldn't get scheduled). Two levers fix that without
    // meaningfully slowing sync:
    //   1) bound parallelism to leave cores free for rendering/input — half the
    //      cores (min 1), so a hot decompress can never occupy the whole CPU;
    //   2) run the workers at MIN_PRIORITY so the scheduler always prefers the
    //      foreground UI thread when they do compete.
    // The decompression is embarrassingly parallel and cache-backed, so even at
    // half width a cold committee warm-up still finishes in a few seconds, and a
    // warm verify pays only copies + the pairing.
    private static final int BLS_PARALLELISM =
            Math.max(1, Runtime.getRuntime().availableProcessors() / 2);
    private static final java.util.concurrent.ForkJoinPool BLS_DECOMPRESS_POOL =
            new java.util.concurrent.ForkJoinPool(
                    BLS_PARALLELISM,
                    pool -> {
                        java.util.concurrent.ForkJoinWorkerThread t =
                                java.util.concurrent.ForkJoinPool
                                        .defaultForkJoinWorkerThreadFactory.newThread(pool);
                        t.setName("bls-decompress-" + t.getPoolIndex());
                        t.setPriority(Thread.MIN_PRIORITY);
                        t.setDaemon(true);
                        return t;
                    },
                    null, false);

    /**
     * Run a parallel-stream pipeline on {@link #BLS_DECOMPRESS_POOL} instead of the
     * common ForkJoinPool. Submitting the task to a specific pool makes the parallel
     * stream's fork/join work execute on that pool's (bounded, low-priority) workers.
     * If the pool rejects the task (e.g. during shutdown), fall back to running it
     * directly on the calling thread so verification never silently fails.
     */
    private static <T> T onDecompressPool(java.util.function.Supplier<T> task) {
        try {
            return BLS_DECOMPRESS_POOL.submit(task::get).join();
        } catch (java.util.concurrent.RejectedExecutionException e) {
            return task.get();
        }
    }

    /** byte[]-keyed map entry (arrays don't implement value equals/hashCode). */
    private static final class PubkeyKey {
        private final byte[] bytes;
        private final int hash;
        PubkeyKey(byte[] bytes) {
            this.bytes = bytes;
            this.hash = Arrays.hashCode(bytes);
        }
        @Override public boolean equals(Object o) {
            return o instanceof PubkeyKey k && Arrays.equals(bytes, k.bytes);
        }
        @Override public int hashCode() { return hash; }
    }

    /** Decompress a trusted (Merkle-proven, no subgroup check) G1 pubkey through the
     *  cache. Returns a private copy the caller may freely use; null for invalid keys
     *  (never cached). computeIfAbsent guarantees one decompression per key even when
     *  a warm-up and a verify race on the same committee (the mapping function runs at
     *  most once; concurrent callers for the same key block briefly and reuse it). The
     *  overflow reset stays outside the compute — mutating the map from inside its own
     *  mapping function is forbidden. */
    private static ECP cachedTrustedG1(byte[] pubkey) {
        if (PUBKEY_CACHE.size() >= PUBKEY_CACHE_MAX) PUBKEY_CACHE.clear();
        ECP master = PUBKEY_CACHE.computeIfAbsent(
                new PubkeyKey(pubkey.clone()), k -> deserializeG1(k.bytes, false));
        return master == null ? null : new ECP(master);
    }

    /**
     * Pre-decompress a set of committee pubkeys into the cache so the next
     * fastAggregateVerify pays only the pairing, not ~512 square roots. Call off the
     * hot path (e.g. right after a snapshot resume or committee rotation); decompression
     * fans out across cores. Invalid keys are skipped — verify rejects them later.
     */
    public static void warmPubkeyCache(List<byte[]> pubkeyBytes) {
        if (pubkeyBytes == null) return;
        onDecompressPool(() -> {
            pubkeyBytes.parallelStream().forEach(b -> {
                if (b != null && b.length == 48) cachedTrustedG1(b);
            });
            return null;
        });
    }

    private BlsVerifier() {}

    /**
     * Perform a BLS fast-aggregate-verify.
     *
     * <p>This implements the Ethereum 2.0 fast_aggregate_verify operation:
     * <ol>
     *   <li>Decompress each 48-byte pubkey into a G1 point.</li>
     *   <li>Aggregate all G1 pubkeys into a single point.</li>
     *   <li>Decompress the 96-byte signature into a G2 point.</li>
     *   <li>Verify: e(aggregatePubkey, H(message)) == e(G1, signature).</li>
     * </ol>
     *
     * @param pubkeyBytes    list of 48-byte compressed BLS G1 public keys
     * @param message        the message that was signed (typically a 32-byte signing root)
     * @param signatureBytes 96-byte compressed BLS G2 aggregate signature
     * @return true if the signature is valid, false otherwise
     */
    public static boolean fastAggregateVerify(List<byte[]> pubkeyBytes, byte[] message, byte[] signatureBytes) {
        return fastAggregateVerify(pubkeyBytes, message, signatureBytes, DST_BYTES);
    }

    /**
     * Same as {@link #fastAggregateVerify(List, byte[], byte[])} but with an
     * explicit hash-to-curve DST. Production callers should use the no-DST
     * overload, which defaults to Ethereum's POP ciphersuite; the DST
     * parameter exists to let tests verify fixtures generated under a
     * different ciphersuite (e.g., the basic "NUL" scheme that our jblst
     * reference fixtures used).
     */
    public static boolean fastAggregateVerify(List<byte[]> pubkeyBytes, byte[] message,
                                               byte[] signatureBytes, byte[] dst) {
        if (pubkeyBytes == null || pubkeyBytes.isEmpty()) {
            return false;
        }
        try {
            // Pubkeys come from the Merkle-proven sync committee (committed to by a
            // header signed by the previous committee) and proved possession at
            // deposit (PoP/KeyValidate, incl. subgroup check). So we do NOT repeat
            // the O(scalar-mul) per-pubkey subgroup check here — it cost ~512 full
            // scalar multiplications per update, which on Android/ART made a single
            // sync-aggregate verify take >70s and stalled catch-up entirely. This
            // matches production clients (Lighthouse/Teku/Prysm/Lodestar), which
            // validate pubkeys once at registration, not per signature. The
            // signature (G2) subgroup check below is retained.
            //
            // Point decompression (a field square root per key) is independent
            // per pubkey, so we fan it out across cores: on Android/ART the serial
            // 512-key loop took ~30s, dwarfing everything else. We use a dedicated
            // bounded, low-priority pool (BLS_DECOMPRESS_POOL) rather than the common
            // ForkJoinPool so a verify burst can't saturate every core and starve the
            // foreground UI thread (input-dispatch ANRs). Decompressed points are
            // cached across calls (committees are period-stable), so a warm verify
            // pays only copies + the pairing. The aggregation (ECP.add) is then a
            // cheap sequential reduce — Milagro ECP isn't safe to mutate from
            // multiple threads, but each cache lookup returns a private copy.
            List<ECP> points = onDecompressPool(() -> pubkeyBytes.parallelStream()
                    .map(BlsVerifier::cachedTrustedG1)
                    .collect(java.util.stream.Collectors.toList()));
            ECP aggregated = new ECP(); // point at infinity
            for (ECP pk : points) {
                if (pk == null || pk.is_infinity()) return false;
                aggregated.add(pk);
            }
            if (aggregated.is_infinity()) return false;
            aggregated.affine();

            // Signature is attacker-controlled wire data — keep its subgroup check.
            ECP2 sig = deserializeG2(signatureBytes);
            if (sig == null || sig.is_infinity()) return false;

            ECP2 hm = HashToCurve.hashToG2(message, dst);

            ECP g1neg = ECP.generator();
            g1neg.neg();

            FP12 result = PAIR.ate2(hm, aggregated, sig, g1neg);
            result = PAIR.fexp(result);
            return result.isunity();
        } catch (Exception e) {
            return false;
        }
    }

    // ---- Serialization: Zcash/Ethereum compressed format <-> Milagro ----

    /**
     * Deserialize a 48-byte compressed G1 point (Zcash/Ethereum format) to Milagro ECP.
     */
    public static ECP deserializeG1(byte[] data) {
        return deserializeG1(data, true);
    }

    /**
     * Deserialize a 48-byte compressed G1 point. When {@code checkSubgroup} is
     * false the (expensive) prime-order subgroup membership test is skipped —
     * only safe for points already known to be valid subgroup elements (e.g.
     * Merkle-proven sync-committee pubkeys that proved possession at deposit).
     */
    public static ECP deserializeG1(byte[] data, boolean checkSubgroup) {
        if (data == null || data.length != 48) return null;

        boolean compressed = (data[0] & 0x80) != 0;
        boolean infinity = (data[0] & 0x40) != 0;
        boolean sortFlag = (data[0] & 0x20) != 0;

        // Ethereum BLS wire format for 48-byte G1 is always compressed.
        if (!compressed) return null;

        if (infinity) {
            // Canonical infinity: sort flag must be clear and remaining bytes zero.
            if (sortFlag) return null;
            byte[] rest = data.clone();
            rest[0] &= 0x1F;
            for (byte b : rest) if (b != 0) return null;
            return new ECP();
        }

        // Extract x coordinate (clear flag bits)
        byte[] xBytes = data.clone();
        xBytes[0] &= 0x1F;
        BIG x = BIG.fromBytes(xBytes);

        // Construct point from x
        ECP point = new ECP(x);
        if (point.is_infinity()) return null;

        // Choose correct y based on sort flag
        BIG y = point.getY();
        boolean yLarger = BIG.comp(y, HALF_P) > 0;
        if (yLarger != sortFlag) {
            point.neg();
        }
        if (checkSubgroup && !isInG1Subgroup(point)) return null;
        return point;
    }

    /**
     * Deserialize a 96-byte compressed G2 point (Zcash/Ethereum format) to Milagro ECP2.
     */
    public static ECP2 deserializeG2(byte[] data) {
        if (data == null || data.length != 96) return null;

        boolean compressed = (data[0] & 0x80) != 0;
        boolean infinity = (data[0] & 0x40) != 0;
        boolean sortFlag = (data[0] & 0x20) != 0;

        // Ethereum BLS wire format for 96-byte G2 is always compressed.
        if (!compressed) return null;

        if (infinity) {
            if (sortFlag) return null;
            byte[] rest = data.clone();
            rest[0] &= 0x1F;
            for (byte b : rest) if (b != 0) return null;
            return new ECP2();
        }

        // First 48 bytes = imaginary part of x (c1), with flags cleared
        byte[] c1Bytes = Arrays.copyOfRange(data, 0, 48);
        c1Bytes[0] &= 0x1F;
        BIG c1 = BIG.fromBytes(c1Bytes);

        // Last 48 bytes = real part of x (c0)
        byte[] c0Bytes = Arrays.copyOfRange(data, 48, 96);
        BIG c0 = BIG.fromBytes(c0Bytes);

        FP2 xCoord = new FP2(new FP(c0), new FP(c1));
        ECP2 point = new ECP2(xCoord);
        if (point.is_infinity()) return null;

        // Choose correct y based on sort flag (lexicographic ordering of FP2)
        if (isLargerY(point) != sortFlag) {
            point.neg();
        }
        if (!isInG2Subgroup(point)) return null;
        return point;
    }

    /**
     * Serialize a Milagro ECP to 48-byte Zcash/Ethereum compressed G1 format.
     */
    public static byte[] serializeG1(ECP point) {
        if (point.is_infinity()) {
            byte[] r = new byte[48];
            r[0] = (byte) 0xC0; // compressed + infinity
            return r;
        }
        point.affine();
        BIG x = point.getX();
        byte[] result = new byte[48];
        x.toBytes(result);
        result[0] |= (byte) 0x80; // compressed flag

        BIG y = point.getY();
        if (BIG.comp(y, HALF_P) > 0) {
            result[0] |= (byte) 0x20; // sort flag
        }
        return result;
    }

    /**
     * Serialize a Milagro ECP2 to 96-byte Zcash/Ethereum compressed G2 format.
     */
    public static byte[] serializeG2(ECP2 point) {
        if (point.is_infinity()) {
            byte[] r = new byte[96];
            r[0] = (byte) 0xC0;
            return r;
        }
        point.affine();
        FP2 x = point.getX();
        x.reduce();

        byte[] result = new byte[96];
        // imaginary part (c1) in first 48 bytes
        BIG c1 = x.getB();
        c1.toBytes(result);
        // real part (c0) in last 48 bytes
        BIG c0 = x.getA();
        byte[] c0Bytes = new byte[48];
        c0.toBytes(c0Bytes);
        System.arraycopy(c0Bytes, 0, result, 48, 48);

        result[0] |= (byte) 0x80; // compressed flag
        if (isLargerY(point)) {
            result[0] |= (byte) 0x20; // sort flag
        }
        return result;
    }

    /**
     * Subgroup membership check for G1. Rejects points on the curve that are not in
     * the prime-order subgroup (needed to prevent small-subgroup attacks during pairing).
     * Uses the straightforward r*P == O test; callers multiplying large batches may want
     * to cache validated points.
     */
    private static boolean isInG1Subgroup(ECP point) {
        return point.mul(CURVE_ORDER).is_infinity();
    }

    /**
     * Subgroup membership check for G2. See {@link #isInG1Subgroup}.
     */
    private static boolean isInG2Subgroup(ECP2 point) {
        return point.mul(CURVE_ORDER).is_infinity();
    }

    /**
     * Check if the y-coordinate of a G2 point is the "larger" one
     * (lexicographic ordering: compare imaginary part first, then real).
     */
    private static boolean isLargerY(ECP2 point) {
        FP2 y = point.getY();
        y.reduce();
        BIG yImag = y.getB();
        BIG yReal = y.getA();

        int cmpImag = BIG.comp(yImag, HALF_P);
        if (cmpImag > 0) return true;
        if (!yImag.iszilch()) return false;
        // imaginary part is zero, compare real part
        return BIG.comp(yReal, HALF_P) > 0;
    }
}
