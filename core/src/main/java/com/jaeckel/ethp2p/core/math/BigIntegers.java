package com.jaeckel.ethp2p.core.math;

import java.math.BigInteger;

/**
 * {@code BigInteger.intValueExact()}/{@code longValueExact()} replacements —
 * Android exposes those only from API 31 and no desugar_jdk_libs release or D8
 * backport covers them; the app's minSdk is 29. Same contract as the JDK:
 * {@link ArithmeticException} with the JDK's message on overflow (the
 * {@code bitLength()} bound excludes the sign bit, so {@code Integer.MIN_VALUE}
 * and {@code Long.MIN_VALUE} are accepted, exactly like the originals).
 */
public final class BigIntegers {

    private BigIntegers() {}

    public static int intValueExact(BigInteger v) {
        if (v.bitLength() > 31) throw new ArithmeticException("BigInteger out of int range");
        return v.intValue();
    }

    public static long longValueExact(BigInteger v) {
        if (v.bitLength() > 63) throw new ArithmeticException("BigInteger out of long range");
        return v.longValue();
    }
}
