package io.myotis.evm.ens;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test vectors from the ENS specification (ENSIP-1) and from the canonical
 * ENS test suite at https://docs.ens.domains/ens-improvement-proposals/ensip-1-ens.
 */
class NamehashTest {

    @Test
    void emptyNameIsZeroNode() {
        assertEquals("0".repeat(64), HexFormat.of().formatHex(Namehash.of("")));
    }

    @Test
    void ethTld() {
        // namehash("eth") = 0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae
        assertEquals(
                "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae",
                HexFormat.of().formatHex(Namehash.of("eth")));
    }

    @Test
    void foobarEth() {
        // namehash("foo.eth") = 0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f
        assertEquals(
                "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f",
                HexFormat.of().formatHex(Namehash.of("foo.eth")));
    }

    @Test
    void uppercaseIsLowercased() {
        assertEquals(
                HexFormat.of().formatHex(Namehash.of("foo.eth")),
                HexFormat.of().formatHex(Namehash.of("FOO.ETH")));
    }
}
