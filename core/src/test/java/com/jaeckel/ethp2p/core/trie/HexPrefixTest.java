package com.jaeckel.ethp2p.core.trie;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test vectors come from the Ethereum Yellow Paper Appendix C and the
 * canonical hex-prefix description: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
 */
class HexPrefixTest {

    @Test
    void encodeEvenExtension() {
        // Nibbles [1, 2, 3, 4], extension (leaf=false). Even-length, flag=0x00.
        // Output: 0x00 || 0x12 || 0x34
        byte[] enc = HexPrefix.encode(new byte[]{1, 2, 3, 4}, false);
        assertEquals("001234", HexFormat.of().formatHex(enc));
    }

    @Test
    void encodeOddExtension() {
        // Nibbles [1, 2, 3], extension. Odd-length, flag=0x10. First nibble in
        // low half of byte 0. Output: 0x11 || 0x23
        byte[] enc = HexPrefix.encode(new byte[]{1, 2, 3}, false);
        assertEquals("1123", HexFormat.of().formatHex(enc));
    }

    @Test
    void encodeEvenLeaf() {
        // Nibbles [1, 2, 3, 4], leaf (leaf=true). Even, flag=0x20.
        // Output: 0x20 || 0x12 || 0x34
        byte[] enc = HexPrefix.encode(new byte[]{1, 2, 3, 4}, true);
        assertEquals("201234", HexFormat.of().formatHex(enc));
    }

    @Test
    void encodeOddLeaf() {
        // Nibbles [0xf, 1, c, b, 8], leaf. Odd, flag=0x30. First nibble = 0xf.
        // Output: 0x3f || 0x1c || 0xb8
        byte[] enc = HexPrefix.encode(new byte[]{0xf, 1, 0xc, 0xb, 8}, true);
        assertEquals("3f1cb8", HexFormat.of().formatHex(enc));
    }

    @Test
    void decodeOddLeafRoundtrip() {
        byte[] nibbles = {0xa, 0xb, 0xc};
        byte[] enc = HexPrefix.encode(nibbles, true);
        HexPrefix.Decoded d = HexPrefix.decode(enc);
        assertTrue(d.leaf());
        assertArrayEquals(nibbles, d.nibbles());
    }

    @Test
    void decodeEvenExtensionRoundtrip() {
        byte[] nibbles = {1, 2, 3, 4, 5, 6};
        byte[] enc = HexPrefix.encode(nibbles, false);
        HexPrefix.Decoded d = HexPrefix.decode(enc);
        assertFalse(d.leaf());
        assertArrayEquals(nibbles, d.nibbles());
    }

    @Test
    void decodeEmptyEvenIsLeaf() {
        // Just the flag byte 0x20 — even-length leaf with zero nibbles.
        HexPrefix.Decoded d = HexPrefix.decode(new byte[]{0x20});
        assertTrue(d.leaf());
        assertEquals(0, d.nibbles().length);
    }

    @Test
    void toNibblesSplitsByteByByte() {
        byte[] nibs = HexPrefix.toNibbles(new byte[]{(byte) 0xab, (byte) 0xcd});
        assertArrayEquals(new byte[]{0xa, 0xb, 0xc, 0xd}, nibs);
    }
}
