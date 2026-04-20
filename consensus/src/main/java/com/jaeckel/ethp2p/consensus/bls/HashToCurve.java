package com.jaeckel.ethp2p.consensus.bls;

import org.apache.milagro.amcl.BLS381.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Hash-to-curve implementation for BLS12-381 G2 following RFC 9380.
 * Maps arbitrary messages to points on the G2 subgroup of BLS12-381.
 *
 * <p>Suite: BLS12381G2_XMD:SHA-256_SSWU_RO_
 */
public final class HashToCurve {

    private static final int L = 64; // ceil((381 + 128) / 8)
    private static final int SHA256_BLOCK = 64;
    private static final int SHA256_OUT = 32;

    // BLS12-381 field modulus p
    private static final BigInteger P = new BigInteger(
            "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);

    // Isogenous curve E': y^2 = x^3 + A'x + B'
    private static final FP2 ISO_A;  // 240 * i
    private static final FP2 ISO_B;  // 1012 * (1+i)

    // Z for simplified SWU map: -(2+i)
    private static final FP2 Z_SWU;

    // Effective cofactor for G2
    private static final byte[] H_EFF_BYTES;

    // 3-isogeny map coefficients: [x_num, x_den, y_num, y_den][degree]
    private static final FP2[][] ISO_XNUM;
    private static final FP2[][] ISO_XDEN;
    private static final FP2[][] ISO_YNUM;
    private static final FP2[][] ISO_YDEN;

    static {
        ISO_A = fp2(0, 240);
        ISO_B = fp2(1012, 1012);
        Z_SWU = fp2neg(fp2(2, 1)); // -(2+i)

        BigInteger hEff = new BigInteger(
                "209869847837335686905080341498658477663839067235703451875" +
                "306851526599783796572738804459333109033834234622528588876" +
                "978987822447936461846631641690358257586228683615991308971" +
                "558879306463436166481");
        H_EFF_BYTES = hEff.toByteArray();

        // x_num coefficients k_(1,0) .. k_(1,3)
        ISO_XNUM = new FP2[][] {{ // index [0]
            fp2d("889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542",
                 "889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542"),
            fp2d("0",
                 "2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706522"),
            fp2d("2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706526",
                 "1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853261"),
            fp2d("3557697382419259905260257622876359250272784728834673675850718343221361467102966990615722337003569479144794908942033",
                 "0"),
        }};

        // x_den coefficients k_(2,0) .. k_(2,2), padded to 4
        ISO_XDEN = new FP2[][] {{ // index [0]
            fp2d("0",
                 "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559715"),
            fp2d("12",
                 "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559775"),
            fp2(1, 0),
            fp2(0, 0),
        }};

        // y_num coefficients k_(3,0) .. k_(3,3)
        ISO_YNUM = new FP2[][] {{ // index [0]
            fp2d("3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558",
                 "3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558"),
            fp2d("0",
                 "889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235518"),
            fp2d("2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706524",
                 "1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853263"),
            fp2d("2816510427748580758331037284777117739799287910327449993381818688383577828123182200904113516794492504322962636245776",
                 "0"),
        }};

        // y_den coefficients k_(4,0) .. k_(4,3)
        ISO_YDEN = new FP2[][] {{ // index [0]
            fp2d("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355",
                 "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355"),
            fp2d("0",
                 "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559571"),
            fp2d("18",
                 "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559769"),
            fp2(1, 0),
        }};
    }

    private HashToCurve() {}

    /**
     * Hash a message to a G2 point on BLS12-381.
     */
    public static ECP2 hashToG2(byte[] message, byte[] dst) {
        FP2[] u = hashToField(message, dst);

        // SWU map produces points on isogenous curve E', stored as raw FP2 coords
        FP2[] q0xy = mapToCurveSWU(u[0]);
        ECP2 q0 = iso3Map(q0xy[0], q0xy[1]);

        FP2[] q1xy = mapToCurveSWU(u[1]);
        ECP2 q1 = iso3Map(q1xy[0], q1xy[1]);

        q0.add(q1);
        q0.affine();

        return clearCofactor(q0);
    }

    // ---- expand_message_xmd (SHA-256) ----

    static byte[] expandMessageXmd(byte[] msg, byte[] dst, int lenInBytes) {
        int ell = (lenInBytes + SHA256_OUT - 1) / SHA256_OUT;
        if (ell > 255) throw new IllegalArgumentException("ell > 255");
        if (dst.length > 255) throw new IllegalArgumentException("DST too long");

        byte[] dstPrime = new byte[dst.length + 1];
        System.arraycopy(dst, 0, dstPrime, 0, dst.length);
        dstPrime[dst.length] = (byte) dst.length;

        byte[] zPad = new byte[SHA256_BLOCK];
        byte[] libStr = new byte[]{(byte) (lenInBytes >> 8), (byte) lenInBytes};

        // b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)
        byte[] b0input = concat(zPad, msg, libStr, new byte[]{0x00}, dstPrime);
        byte[] b0 = sha256(b0input);

        // b_1 = H(b_0 || 0x01 || DST_prime)
        byte[] b1 = sha256(concat(b0, new byte[]{0x01}, dstPrime));

        byte[] result = new byte[lenInBytes];
        byte[] prev = b1;
        System.arraycopy(b1, 0, result, 0, Math.min(SHA256_OUT, lenInBytes));

        for (int i = 2; i <= ell; i++) {
            byte[] xored = xor(b0, prev);
            prev = sha256(concat(xored, new byte[]{(byte) i}, dstPrime));
            int offset = (i - 1) * SHA256_OUT;
            int len = Math.min(SHA256_OUT, lenInBytes - offset);
            System.arraycopy(prev, 0, result, offset, len);
        }

        return result;
    }

    // ---- hash_to_field: returns 2 FP2 elements ----

    static FP2[] hashToField(byte[] msg, byte[] dst) {
        int lenInBytes = 2 * 2 * L; // count=2, m=2, L=64 => 256
        byte[] uniform = expandMessageXmd(msg, dst, lenInBytes);

        FP2[] result = new FP2[2];
        for (int i = 0; i < 2; i++) {
            FP[] fps = new FP[2];
            for (int j = 0; j < 2; j++) {
                int offset = (i * 2 + j) * L;
                byte[] chunk = Arrays.copyOfRange(uniform, offset, offset + L);
                BigInteger bi = new BigInteger(1, chunk);
                BigInteger reduced = bi.mod(P);
                fps[j] = bigIntToFP(reduced);
            }
            result[i] = new FP2(fps[0], fps[1]);
        }
        return result;
    }

    // ---- simplified SWU map on E' (RFC 9380 Section 6.6.2) ----

    // Returns [x, y] on isogenous curve E' (NOT on BLS12-381 E)
    static FP2[] mapToCurveSWU(FP2 u) {
        FP2 A = copyFP2(ISO_A);
        FP2 B = copyFP2(ISO_B);
        FP2 Z = copyFP2(Z_SWU);

        // 1. tv1 = u^2
        FP2 tv1 = copyFP2(u);
        tv1.sqr();

        // 2. tv1 = Z * tv1
        tv1.mul(Z);

        // 3. tv2 = tv1^2
        FP2 tv2 = copyFP2(tv1);
        tv2.sqr();

        // 4. tv2 = tv2 + tv1
        tv2.add(tv1);

        // 5. tv3 = tv2 + 1
        FP2 tv3 = copyFP2(tv2);
        FP2 one = fp2(1, 0);
        tv3.add(one);

        // 6. tv3 = B * tv3
        tv3.mul(B);

        // 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
        FP2 tv4;
        if (!tv2.iszilch()) {
            tv4 = copyFP2(tv2);
            tv4.neg();
        } else {
            tv4 = copyFP2(Z_SWU);
        }

        // 8. tv4 = A * tv4
        tv4.mul(copyFP2(ISO_A));

        // 9. tv2 = tv3^2
        tv2 = copyFP2(tv3);
        tv2.sqr();

        // 10. tv6 = tv4^2
        FP2 tv6 = copyFP2(tv4);
        tv6.sqr();

        // 11. tv5 = A * tv6
        FP2 tv5 = copyFP2(ISO_A);
        tv5.mul(tv6);

        // 12. tv2 = tv2 + tv5
        tv2.add(tv5);

        // 13. tv2 = tv2 * tv3
        tv2.mul(tv3);

        // 14. tv6 = tv6 * tv4
        tv6.mul(tv4);

        // 15. tv5 = B * tv6
        tv5 = copyFP2(ISO_B);
        tv5.mul(tv6);

        // 16. tv2 = tv2 + tv5
        tv2.add(tv5);

        // 17. x = tv1 * tv3
        FP2 x = copyFP2(tv1);
        x.mul(tv3);

        // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
        FP2 y1 = new FP2(0);
        boolean isGx1Square = sqrtRatio(tv2, tv6, y1);

        // 19. y = tv1 * u
        FP2 y = copyFP2(tv1);
        y.mul(u);

        // 20. y = y * y1
        y.mul(y1);

        // 21. x = CMOV(x, tv3, is_gx1_square)
        if (isGx1Square) {
            x = copyFP2(tv3);
        }

        // 22. y = CMOV(y, y1, is_gx1_square)
        if (isGx1Square) {
            y = copyFP2(y1);
        }

        // 23-24. if sgn0(u) != sgn0(y), negate y
        if (sgn0(u) != sgn0(y)) {
            y.neg();
        }

        // 25. x = x / tv4
        FP2 tv4Inv = copyFP2(tv4);
        tv4Inv.inverse();
        x.mul(tv4Inv);

        // 26. return (x, y) on E' as raw FP2 coordinates
        return new FP2[]{x, y};
    }

    // ---- sqrt_ratio(u, v) for FP2 ----
    // Returns true if u/v is QR, stores sqrt in result
    // If not QR, stores sqrt(Z * u/v) in result

    static boolean sqrtRatio(FP2 u, FP2 v, FP2 result) {
        if (v.iszilch()) {
            result.zero();
            return u.iszilch();
        }

        FP2 vInv = copyFP2(v);
        vInv.inverse();

        FP2 ratio = copyFP2(u);
        ratio.mul(vInv); // u/v

        FP2 candidate = copyFP2(ratio);
        if (candidate.sqrt()) {
            result.copy(candidate);
            return true;
        }

        // u/v is not QR => Z * u/v is QR
        FP2 zr = copyFP2(Z_SWU);
        zr.mul(ratio);
        zr.sqrt(); // must succeed since Z is non-QR
        result.copy(zr);
        return false;
    }

    // ---- sgn0 for FP2: returns 0 or 1 ----

    static int sgn0(FP2 x) {
        FP2 t = copyFP2(x);
        t.reduce();
        BIG a = t.getA(); // real part
        BIG b = t.getB(); // imaginary part
        int sign0 = a.parity();
        int zero0 = a.iszilch() ? 1 : 0;
        int sign1 = b.parity();
        return sign0 | (zero0 & sign1);
    }

    // ---- 3-isogeny map from E' to E ----

    // Takes (x, y) on isogenous curve E', returns ECP2 point on BLS12-381 E
    static ECP2 iso3Map(FP2 x, FP2 y) {
        FP2[] xn = ISO_XNUM[0];
        FP2[] xd = ISO_XDEN[0];
        FP2[] yn = ISO_YNUM[0];
        FP2[] yd = ISO_YDEN[0];

        // Horner evaluation: result = ((c[3]*x + c[2])*x + c[1])*x + c[0]
        FP2 xNum = horner(xn, x);
        FP2 xDen = horner(xd, x);
        FP2 yNum = horner(yn, x);
        FP2 yDen = horner(yd, x);

        // mapped_x = x_num / x_den
        FP2 xDenInv = copyFP2(xDen);
        xDenInv.inverse();
        FP2 mx = copyFP2(xNum);
        mx.mul(xDenInv);

        // mapped_y = y * y_num / y_den
        FP2 yDenInv = copyFP2(yDen);
        yDenInv.inverse();
        FP2 my = copyFP2(y);
        my.mul(yNum);
        my.mul(yDenInv);

        return new ECP2(mx, my);
    }

    private static FP2 horner(FP2[] coeffs, FP2 x) {
        // coeffs = [c0, c1, c2, c3]
        // Evaluate c3*x^3 + c2*x^2 + c1*x + c0 using Horner's method
        FP2 result = copyFP2(coeffs[3]);
        result.mul(x);
        result.add(copyFP2(coeffs[2]));
        result.mul(x);
        result.add(copyFP2(coeffs[1]));
        result.mul(x);
        result.add(copyFP2(coeffs[0]));
        return result;
    }

    // ---- clear cofactor via scalar multiplication by h_eff ----

    static ECP2 clearCofactor(ECP2 p) {
        // h_eff is ~636 bits. Double-and-add from MSB.
        ECP2 result = new ECP2(); // infinity
        for (byte hEffByte : H_EFF_BYTES) {
            for (int bit = 7; bit >= 0; bit--) {
                result.dbl();
                if (((hEffByte >> bit) & 1) == 1) {
                    result.add(p);
                }
            }
        }
        result.affine();
        return result;
    }

    // ---- Helper methods ----

    private static FP2 fp2(int c0, int c1) {
        return new FP2(new FP(new BIG(c0)), new FP(new BIG(c1)));
    }

    private static FP2 fp2d(String c0, String c1) {
        return new FP2(bigIntToFP(new BigInteger(c0)), bigIntToFP(new BigInteger(c1)));
    }

    private static FP2 fp2neg(FP2 x) {
        FP2 r = copyFP2(x);
        r.neg();
        return r;
    }

    private static FP2 copyFP2(FP2 x) {
        FP2 r = new FP2(x);
        return r;
    }

    private static FP bigIntToFP(BigInteger val) {
        byte[] raw = val.toByteArray();
        byte[] padded = new byte[BIG.MODBYTES];
        if (raw.length <= padded.length) {
            System.arraycopy(raw, 0, padded, padded.length - raw.length, raw.length);
        } else {
            // BigInteger may have leading sign byte
            System.arraycopy(raw, raw.length - padded.length, padded, 0, padded.length);
        }
        return new FP(BIG.fromBytes(padded));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
