package com.jaeckel.ethp2p.consensus.bls;

import supranational.blst.BLST_ERROR;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2_Affine;

import java.util.List;

/**
 * A {@link BlsBackend} backed by Supranational's blst via jblst (C + assembly, JNI).
 * Prototype in test scope — it proves the speedup vs {@link MilagroBlsBackend} before a
 * production swap. Mirrors the verify path Myotis used before commit 8acd8f1 (which
 * replaced jblst with Milagro for Android portability), but with the correct POP DST.
 *
 * <p>jblst ships desktop/JVM natives only; an Android build needs an NDK-compiled blst
 * (see docs/bls-rust-acceleration.md). The {@link BlsBackend} seam is what lets either
 * native impl drop in behind the portable Milagro fallback.
 */
public final class JblstBlsBackend implements BlsBackend {

    /** Ethereum consensus POP ciphersuite DST (matches {@link BlsVerifier}). */
    private static final String DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    @Override
    public boolean fastAggregateVerify(List<byte[]> pubkeys, byte[] message, byte[] signature) {
        if (pubkeys == null || pubkeys.isEmpty()) return false;
        try {
            // Aggregate the G1 pubkeys (native point adds).
            P1 aggregated = new P1_Affine(pubkeys.get(0)).to_jacobian();
            for (int i = 1; i < pubkeys.size(); i++) {
                aggregated.aggregate(new P1_Affine(pubkeys.get(i)));
            }
            P1_Affine aggregatedAffine = aggregated.to_affine();
            // Signature is attacker-controlled wire data → P2_Affine ctor does the subgroup check.
            P2_Affine sig = new P2_Affine(signature);
            // hash_or_encode=true (hash-to-curve), POP DST, no augmentation.
            return sig.core_verify(aggregatedAffine, true, message, DST) == BLST_ERROR.BLST_SUCCESS;
        } catch (Throwable t) {
            // Throwable, not Exception: the jblst native lib may be absent for this OS/arch,
            // surfacing as UnsatisfiedLinkError (an Error). Return false like the other
            // backends instead of crashing the benchmark/test JVM.
            return false;
        }
    }

    @Override
    public String name() { return "jblst (blst native)"; }
}
