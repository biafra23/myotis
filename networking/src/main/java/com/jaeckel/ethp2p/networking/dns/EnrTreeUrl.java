package com.jaeckel.ethp2p.networking.dns;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import java.io.ByteArrayOutputStream;
import java.util.Locale;
import java.util.Objects;

/**
 * EIP-1459 ENR tree URL: {@code enrtree://<base32-pubkey>@<domain>}.
 *
 * <p>The base32-encoded public key is the 33-byte compressed secp256k1 key for
 * the tree's operator. The DNS tree rooted at {@code <domain>} is authoritative
 * iff its root TXT record's signature recovers to this key.
 */
public final class EnrTreeUrl {

    private static final String PREFIX = "enrtree://";

    private final SECP256K1.PublicKey publicKey;
    private final String domain;

    public EnrTreeUrl(SECP256K1.PublicKey publicKey, String domain) {
        this.publicKey = Objects.requireNonNull(publicKey);
        this.domain = Objects.requireNonNull(domain);
    }

    public static EnrTreeUrl parse(String url) {
        if (url == null || !url.startsWith(PREFIX)) {
            throw new IllegalArgumentException("expected enrtree:// URL, got: " + url);
        }
        String rest = url.substring(PREFIX.length());
        int at = rest.indexOf('@');
        if (at <= 0 || at == rest.length() - 1) {
            throw new IllegalArgumentException("missing '@' or empty part in: " + url);
        }
        String base32Key = rest.substring(0, at);
        String domain = rest.substring(at + 1);

        byte[] compressed = base32Decode(base32Key);
        if (compressed.length != 33) {
            throw new IllegalArgumentException(
                    "expected 33-byte compressed secp256k1 key, got " + compressed.length + " bytes");
        }
        SECP256K1.PublicKey pubkey = decompressSecp256k1(compressed);
        return new EnrTreeUrl(pubkey, domain);
    }

    public SECP256K1.PublicKey publicKey() {
        return publicKey;
    }

    public String domain() {
        return domain;
    }

    @Override
    public String toString() {
        return "EnrTreeUrl{domain=" + domain + "}";
    }

    // ---- helpers ----

    /**
     * RFC 4648 base32 decoder, case-insensitive, accepts '=' padding or no padding.
     */
    static byte[] base32Decode(String s) {
        if (s == null) throw new IllegalArgumentException("null input");
        String up = s.toUpperCase(Locale.ROOT);
        int end = up.indexOf('=');
        if (end >= 0) up = up.substring(0, end);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0, bits = 0;
        for (int i = 0; i < up.length(); i++) {
            char c = up.charAt(i);
            int val;
            if (c >= 'A' && c <= 'Z') val = c - 'A';
            else if (c >= '2' && c <= '7') val = 26 + (c - '2');
            else throw new IllegalArgumentException("invalid base32 character: " + c);
            buffer = (buffer << 5) | val;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.write((buffer >> bits) & 0xFF);
            }
        }
        return out.toByteArray();
    }

    /**
     * Decompress a 33-byte compressed secp256k1 point into a {@link SECP256K1.PublicKey}.
     * Mirrors the decompression pattern used by {@code Enr.publicKey()}.
     */
    static SECP256K1.PublicKey decompressSecp256k1(byte[] compressed) {
        try {
            org.bouncycastle.asn1.x9.X9ECParameters curve =
                    org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1");
            org.bouncycastle.math.ec.ECPoint point = curve.getCurve().decodePoint(compressed);
            byte[] encoded = point.getEncoded(false); // 0x04 || x || y
            return SECP256K1.PublicKey.fromBytes(Bytes.wrap(encoded, 1, 64));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid compressed secp256k1 point", e);
        }
    }
}
