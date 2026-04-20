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
    private static final String DST_STRING = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    private static final byte[] DST_BYTES = DST_STRING.getBytes();

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
            // Decompress and aggregate pubkeys
            ECP aggregated = deserializeG1(pubkeyBytes.get(0));
            if (aggregated == null) return false;

            for (int i = 1; i < pubkeyBytes.size(); i++) {
                ECP pk = deserializeG1(pubkeyBytes.get(i));
                if (pk == null) return false;
                aggregated.add(pk);
            }
            aggregated.affine();

            // Decompress signature
            ECP2 sig = deserializeG2(signatureBytes);
            if (sig == null) return false;

            // Hash message to G2
            ECP2 hm = HashToCurve.hashToG2(message, DST_BYTES);

            // Pairing check: e(H(m), pk) * e(sig, -G1) == 1
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
        if (data == null || data.length != 48) return null;

        boolean compressed = (data[0] & 0x80) != 0;
        boolean infinity = (data[0] & 0x40) != 0;
        boolean sortFlag = (data[0] & 0x20) != 0;

        if (infinity) {
            // Check remaining bytes are zero
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
        BIG pMod = new BIG(ROM.Modulus);
        BIG halfP = new BIG(pMod);
        halfP.shr(1);
        boolean yLarger = BIG.comp(y, halfP) > 0;
        if (yLarger != sortFlag) {
            point.neg();
        }
        return point;
    }

    /**
     * Deserialize a 96-byte compressed G2 point (Zcash/Ethereum format) to Milagro ECP2.
     */
    public static ECP2 deserializeG2(byte[] data) {
        if (data == null || data.length != 96) return null;

        boolean infinity = (data[0] & 0x40) != 0;
        boolean sortFlag = (data[0] & 0x20) != 0;

        if (infinity) {
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
        BIG halfP = new BIG(new BIG(ROM.Modulus));
        halfP.shr(1);
        if (BIG.comp(y, halfP) > 0) {
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
     * Check if the y-coordinate of a G2 point is the "larger" one
     * (lexicographic ordering: compare imaginary part first, then real).
     */
    private static boolean isLargerY(ECP2 point) {
        FP2 y = point.getY();
        y.reduce();
        BIG yImag = y.getB();
        BIG yReal = y.getA();
        BIG halfP = new BIG(new BIG(ROM.Modulus));
        halfP.shr(1);

        int cmpImag = BIG.comp(yImag, halfP);
        if (cmpImag > 0) return true;
        if (cmpImag < 0 || !yImag.iszilch()) return false;
        // imaginary part is zero, compare real part
        return BIG.comp(yReal, halfP) > 0;
    }
}
