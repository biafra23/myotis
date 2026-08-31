package com.jaeckel.ethp2p.core.encoding;

import java.nio.charset.StandardCharsets;

/**
 * Hex codec with the exact semantics of {@code java.util.HexFormat.of()}
 * ({@code formatHex}/{@code parseHex}): lowercase unprefixed output, and
 * strict even-length ASCII-only parsing — odd length throws
 * {@link IllegalArgumentException}, a non-hex character throws
 * {@link NumberFormatException}, matching the JDK. Exists because
 * {@code HexFormat} needs Android API 34 and no desugar_jdk_libs release
 * covers it — the app's minSdk is 29 (see CLAUDE.md's minSdk API budget).
 *
 * <p>Parsing deliberately does NOT use {@link Character#digit(char, int)}:
 * that method also accepts non-ASCII Unicode digits (Arabic-Indic, fullwidth,
 * …), which {@code HexFormat} rejects — a real difference on paths that parse
 * untrusted strings (addresses, CCIP-Read gateway responses).
 *
 * <p>Why not Tuweni's {@code Bytes.fromHexString} (already a dependency of
 * most modules using this class): same laxness problem, verified against
 * tuweni-bytes 2.7.2 — it accepts a {@code 0x} prefix (so callers that strip
 * one prefix themselves would silently accept doubled-prefix input, and a
 * 40-char length check no longer proves 20 bytes) and accepts the same
 * non-ASCII Unicode digits as {@code Character.digit}. This class is the
 * strict codec for validation paths; Tuweni {@code Bytes} remains fine where
 * the input is already trusted bytes. (Also: {@code :myotis-engines} has no
 * Tuweni on its classpath at all.)
 */
public final class Hex {

    private static final byte[] DIGITS = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private Hex() {}

    /** Lowercase unprefixed hex, like {@code HexFormat.of().formatHex(bytes)}. */
    public static String formatHex(byte[] bytes) {
        return new String(encode(bytes, 0), StandardCharsets.ISO_8859_1);
    }

    /** Lowercase {@code 0x}-prefixed hex — the common wire/log form. */
    public static String formatHexPrefixed(byte[] bytes) {
        byte[] out = encode(bytes, 2);
        out[0] = '0';
        out[1] = 'x';
        return new String(out, StandardCharsets.ISO_8859_1);
    }

    private static byte[] encode(byte[] bytes, int offset) {
        byte[] out = new byte[offset + bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            out[offset + 2 * i] = DIGITS[b >>> 4];
            out[offset + 2 * i + 1] = DIGITS[b & 0xf];
        }
        return out;
    }

    /**
     * Parse unprefixed hex (either case), like {@code HexFormat.of().parseHex(hex)}.
     *
     * @throws IllegalArgumentException on odd length
     * @throws NumberFormatException    on a character outside ASCII {@code [0-9a-fA-F]}
     */
    public static byte[] parseHex(CharSequence hex) {
        int len = hex.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("hex string has odd length: " + len);
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((digit(hex.charAt(2 * i)) << 4) | digit(hex.charAt(2 * i + 1)));
        }
        return out;
    }

    private static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new NumberFormatException("not a hexadecimal digit: '" + c + "'");
    }
}
