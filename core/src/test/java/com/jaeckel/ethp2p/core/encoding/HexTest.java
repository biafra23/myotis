package com.jaeckel.ethp2p.core.encoding;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Pins Hex to the {@code java.util.HexFormat.of()} contract it replaces. */
class HexTest {

    private static final byte[] BYTES = {0x00, 0x01, 0x7f, (byte) 0x80, (byte) 0xab, (byte) 0xff};

    @Test
    void formatsLowercaseUnprefixed() {
        assertEquals("00017f80abff", Hex.formatHex(BYTES));
        assertEquals("", Hex.formatHex(new byte[0]));
    }

    @Test
    void formatsPrefixed() {
        assertEquals("0x00017f80abff", Hex.formatHexPrefixed(BYTES));
        assertEquals("0x", Hex.formatHexPrefixed(new byte[0]));
    }

    @Test
    void parsesBothCases() {
        assertArrayEquals(BYTES, Hex.parseHex("00017f80abff"));
        assertArrayEquals(BYTES, Hex.parseHex("00017F80ABFF"));
        assertArrayEquals(new byte[0], Hex.parseHex(""));
    }

    @Test
    void roundTrips() {
        byte[] all = new byte[256];
        for (int i = 0; i < 256; i++) all[i] = (byte) i;
        assertArrayEquals(all, Hex.parseHex(Hex.formatHex(all)));
    }

    @Test
    void rejectsOddLength() {
        assertThrows(IllegalArgumentException.class, () -> Hex.parseHex("abc"));
    }

    @Test
    void rejectsNonHexAscii() {
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("0g"));
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("0x12")); // prefix is the caller's job
        assertThrows(NumberFormatException.class, () -> Hex.parseHex(" 1"));
    }

    @Test
    void rejectsNonAsciiUnicodeDigits() {
        // HexFormat is ASCII-only; Character.digit would have accepted all of these.
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("０１")); // fullwidth 01
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("٠١")); // Arabic-Indic 01
        assertThrows(NumberFormatException.class, () -> Hex.parseHex("ａｂ")); // fullwidth ab
    }
}
