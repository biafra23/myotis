package com.jaeckel.ethp2p.networking.dns;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnrTreeUrlTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Ethereum Foundation canonical mainnet EL tree. */
    private static final String MAINNET_EL =
            "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net";

    @Test
    void parsesCanonicalMainnetTree() {
        EnrTreeUrl url = EnrTreeUrl.parse(MAINNET_EL);
        assertEquals("all.mainnet.ethdisco.net", url.domain());
        // pubkey decoded successfully (33-byte compressed → 64-byte uncompressed SECP256K1 point)
        assertEquals(64, url.publicKey().bytes().size());
    }

    @Test
    void rejectsMissingScheme() {
        assertThrows(IllegalArgumentException.class,
                () -> EnrTreeUrl.parse("AKA3@example.com"));
    }

    @Test
    void rejectsMissingAt() {
        assertThrows(IllegalArgumentException.class,
                () -> EnrTreeUrl.parse("enrtree://AKA3EXAMPLE.COM"));
    }

    @Test
    void rejectsEmptyDomain() {
        assertThrows(IllegalArgumentException.class,
                () -> EnrTreeUrl.parse("enrtree://AKA3@"));
    }

    @Test
    void rejectsShortKey() {
        // Valid base32 but decodes to fewer than 33 bytes
        assertThrows(IllegalArgumentException.class,
                () -> EnrTreeUrl.parse("enrtree://AAAAAA@example.com"));
    }

    @Test
    void base32DecodesKnownValue() {
        // RFC 4648 test vector: "foobar" → "MZXW6YTBOI======" (16 chars unpadded)
        byte[] decoded = EnrTreeUrl.base32Decode("MZXW6YTBOI");
        assertEquals("foobar", new String(decoded));
    }

    @Test
    void base32DecodesFullRfc4648Vectors() {
        // Cover the full RFC 4648 §10 test vector set to catch overflow in the 5-bit
        // accumulator when inputs exceed what fits in an int without masking.
        assertEquals("",        new String(EnrTreeUrl.base32Decode("")));
        assertEquals("f",       new String(EnrTreeUrl.base32Decode("MY")));
        assertEquals("fo",      new String(EnrTreeUrl.base32Decode("MZXQ")));
        assertEquals("foo",     new String(EnrTreeUrl.base32Decode("MZXW6")));
        assertEquals("foob",    new String(EnrTreeUrl.base32Decode("MZXW6YQ")));
        assertEquals("fooba",   new String(EnrTreeUrl.base32Decode("MZXW6YTB")));
        assertEquals("foobar",  new String(EnrTreeUrl.base32Decode("MZXW6YTBOI")));
    }

    @Test
    void base32DecodesLongInput() {
        // 53-char input (the canonical mainnet tree pubkey) must decode to 33 bytes.
        // This would fail quietly if the 5-bit accumulator was not masked on emit.
        byte[] decoded = EnrTreeUrl.base32Decode("AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE");
        assertEquals(33, decoded.length);
        // Compressed secp256k1 points start with 0x02 or 0x03.
        assertTrue((decoded[0] & 0xFF) == 0x02 || (decoded[0] & 0xFF) == 0x03,
                "first byte of decoded pubkey should be 0x02 or 0x03; got 0x"
                        + Integer.toHexString(decoded[0] & 0xFF));
    }
}
