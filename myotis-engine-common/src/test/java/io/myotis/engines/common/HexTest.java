package io.myotis.engines.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class HexTest {
    private static final byte[] BYTES = {0x00, 0x0a, (byte) 0xff, 0x7f};

    @Test
    void formatsLowercaseWithAndWithoutPrefix() {
        assertEquals("000aff7f", Hex.formatHex(BYTES));
        assertEquals("0x000aff7f", Hex.formatHexPrefixed(BYTES));
        assertEquals("0x", Hex.formatHexPrefixed(new byte[0]));
    }

    @Test
    void parsesEitherCaseAndRoundTrips() {
        assertArrayEquals(BYTES, Hex.parseHex("000aff7f"));
        assertArrayEquals(BYTES, Hex.parseHex("000AFF7F"));
        assertArrayEquals(BYTES, Hex.parseHexPrefixed("0x000aff7f"));
        assertArrayEquals(BYTES, Hex.parseHexPrefixed("0X000AFF7F"));
        assertArrayEquals(BYTES, Hex.parseHexPrefixed("000aff7f"));
        assertArrayEquals(new byte[0], Hex.parseHexPrefixed("0x"));
    }

    @Test
    void refusesWhatHexFormatRefuses() {
        assertThrows(IllegalArgumentException.class, () -> Hex.parseHex("abc"));
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("zz"));
        // The unprefixed parse does not take a prefix, so a doubled prefix cannot slip through.
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("0x0a"));
        assertThrows(NumberFormatException.class, () -> Hex.parseHexPrefixed("0x0x0a"));
        // Non-ASCII digits (which Character.digit accepts) are refused.
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("\u0661\u0662"));
    }
}
