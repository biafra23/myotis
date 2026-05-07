package io.myotis.ens;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test vectors for the DNS wire-format encoder.
 *
 * <p>Examples per ENSIP-10 / DNS RFC 1035: each label is preceded by a
 * one-byte length, followed by the label bytes, terminated by a zero
 * byte for the root.
 */
class DnsEncoderTest {

    @Test
    void encodeVitalikEth() {
        // "vitalik" = 0x76 69 74 61 6c 69 6b (7 bytes), "eth" = 0x65 74 68 (3 bytes).
        // Wire: 07 vitalik 03 eth 00
        assertEquals(
                "0776697461 6c696b03657468 00".replace(" ", ""),
                HexFormat.of().formatHex(DnsEncoder.encode("vitalik.eth")));
    }

    @Test
    void encodeRootIsSingleZeroByte() {
        assertEquals("00", HexFormat.of().formatHex(DnsEncoder.encode("")));
        assertEquals("00", HexFormat.of().formatHex(DnsEncoder.encode(null)));
    }

    @Test
    void encodeSingleLabel() {
        // "eth" alone — label of 3 bytes, then root terminator.
        assertEquals("0365746800",
                HexFormat.of().formatHex(DnsEncoder.encode("eth")));
    }

    @Test
    void encodeMultiLevelSubdomain() {
        // "a.b.c.eth" — four labels.
        assertEquals(
                "01 61 01 62 01 63 03 65 74 68 00".replace(" ", ""),
                HexFormat.of().formatHex(DnsEncoder.encode("a.b.c.eth")));
    }

    @Test
    void encodeLowercasesInput() {
        assertEquals(
                HexFormat.of().formatHex(DnsEncoder.encode("vitalik.eth")),
                HexFormat.of().formatHex(DnsEncoder.encode("VITALIK.ETH")));
    }

    @Test
    void encodeRejectsLabelsLongerThan63Bytes() {
        String tooLong = "a".repeat(64);
        assertThrows(IllegalArgumentException.class,
                () -> DnsEncoder.encode(tooLong + ".eth"));
    }

    @Test
    void encodeAcceptsTrailingDotAsFqdnForm() {
        // FQDN form ("vitalik.eth.") is equivalent to the bare form;
        // the encoder strips the trailing dot before splitting.
        assertEquals(
                HexFormat.of().formatHex(DnsEncoder.encode("vitalik.eth")),
                HexFormat.of().formatHex(DnsEncoder.encode("vitalik.eth.")));
    }

    @Test
    void encodeRejectsEmptyMiddleLabel() {
        // "a..b" would otherwise produce 01 61 00 01 62 00 — invalid because
        // only the final root label may be zero-length.
        assertThrows(IllegalArgumentException.class,
                () -> DnsEncoder.encode("a..b"));
    }

    @Test
    void encodeRejectsEmptyLeadingLabel() {
        // ".eth" leads with an empty label, also invalid.
        assertThrows(IllegalArgumentException.class,
                () -> DnsEncoder.encode(".eth"));
    }
}
