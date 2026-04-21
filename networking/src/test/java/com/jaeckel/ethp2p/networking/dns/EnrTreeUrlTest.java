package com.jaeckel.ethp2p.networking.dns;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
