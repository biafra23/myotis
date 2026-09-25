package com.jaeckel.ethp2p.core.math;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Pins BigIntegers to the JDK's int/longValueExact contract, boundaries included. */
class BigIntegersTest {

    @Test
    void intBoundaries() {
        assertEquals(Integer.MAX_VALUE, BigIntegers.intValueExact(BigInteger.valueOf(Integer.MAX_VALUE)));
        assertEquals(Integer.MIN_VALUE, BigIntegers.intValueExact(BigInteger.valueOf(Integer.MIN_VALUE)));
        assertEquals(0, BigIntegers.intValueExact(BigInteger.ZERO));
        assertThrows(ArithmeticException.class,
                () -> BigIntegers.intValueExact(BigInteger.valueOf(Integer.MAX_VALUE).add(BigInteger.ONE)));
        assertThrows(ArithmeticException.class,
                () -> BigIntegers.intValueExact(BigInteger.valueOf(Integer.MIN_VALUE).subtract(BigInteger.ONE)));
    }

    @Test
    void longBoundaries() {
        assertEquals(Long.MAX_VALUE, BigIntegers.longValueExact(BigInteger.valueOf(Long.MAX_VALUE)));
        assertEquals(Long.MIN_VALUE, BigIntegers.longValueExact(BigInteger.valueOf(Long.MIN_VALUE)));
        assertThrows(ArithmeticException.class,
                () -> BigIntegers.longValueExact(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)));
        assertThrows(ArithmeticException.class,
                () -> BigIntegers.longValueExact(BigInteger.valueOf(Long.MIN_VALUE).subtract(BigInteger.ONE)));
    }

    @Test
    void matchesJdkOnJvmHosts() {
        // The JVM hosts still run a JDK that has the real methods — pin equivalence.
        for (BigInteger v : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(-1),
                BigInteger.valueOf(Integer.MAX_VALUE), BigInteger.valueOf(Integer.MIN_VALUE),
                BigInteger.valueOf(Long.MAX_VALUE), BigInteger.valueOf(Long.MIN_VALUE)}) {
            assertEquals(v.longValueExact(), BigIntegers.longValueExact(v));
            if (v.bitLength() <= 31) {
                assertEquals(v.intValueExact(), BigIntegers.intValueExact(v));
            }
        }
    }
}
