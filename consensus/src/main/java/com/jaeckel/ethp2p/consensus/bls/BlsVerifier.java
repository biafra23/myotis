package com.jaeckel.ethp2p.consensus.bls;

import supranational.blst.BLST_ERROR;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2_Affine;

import java.util.List;

/**
 * BLS12-381 signature verification for Ethereum 2.0 using the jblst library.
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
     * BLS_SIG scheme with G2 messages, SHA-256 hash-to-curve, SSWU, random oracle.
     */
    private static final String DST_STRING = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

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
        if (pubkeyBytes == null || pubkeyBytes.isEmpty()) {
            return false;
        }
        try {
            // Decompress the first pubkey to start the aggregation
            P1_Affine firstAffine = new P1_Affine(pubkeyBytes.get(0));
            P1 aggregated = firstAffine.to_jacobian();

            // Aggregate remaining pubkeys
            for (int i = 1; i < pubkeyBytes.size(); i++) {
                P1_Affine affine = new P1_Affine(pubkeyBytes.get(i));
                aggregated.aggregate(affine);
            }

            // Convert aggregated pubkey back to affine
            P1_Affine aggregatedAffine = aggregated.to_affine();

            // Decompress the signature (G2 point)
            P2_Affine sig = new P2_Affine(signatureBytes);

            // Verify: core_verify on the G2 signature with the aggregated G1 pubkey
            // Signature in G2, pubkey in G1 — hash-to-curve on message with DST, no augmentation
            BLST_ERROR result = sig.core_verify(aggregatedAffine, true, message, DST_STRING);
            return result == BLST_ERROR.BLST_SUCCESS;
        } catch (Exception e) {
            return false;
        }
    }
}
