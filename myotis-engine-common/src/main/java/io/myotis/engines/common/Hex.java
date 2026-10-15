package io.myotis.engines.common;

import java.nio.charset.StandardCharsets;

/**
 * The engine library's hex codec: lowercase {@code 0x}-prefixed output and a STRICT
 * parse (ASCII {@code [0-9a-fA-F]} only, even length) — the one definition the
 * Rust engine's FFI boundary ({@code :myotis-engine-rust}) and the default ports
 * ({@code :myotis-engine-ports}' node-key file) share.
 *
 * <p>Why not {@code java.util.HexFormat}: it is Android API 34, and the library
 * ships at minSdk 29 (CLAUDE.md's minSdk-29 budget). Why not {@code :core}'s
 * {@code Hex}: {@code :core} carries Tuweni and BouncyCastle, which the Rust engine
 * never uses — a dependency on it would put four Tuweni artifacts and a second
 * crypto provider into every consumer of the AAR for a 40-line codec. The strict
 * parse matches {@code :core}'s: {@code Character.digit} would also accept the
 * non-ASCII Unicode digits, so a validation path that used it could accept input
 * no other codec in the project does.
 */
public final class Hex {
    private static final byte[] DIGITS = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private Hex() {}

    /** Lowercase unprefixed hex, like {@code HexFormat.of().formatHex(bytes)}. */
    public static String formatHex(byte[] bytes) {
        return new String(encode(bytes, 0), StandardCharsets.ISO_8859_1);
    }

    /** Lowercase {@code 0x}-prefixed hex — the wire/log form the natives speak. */
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
     * A {@code 0x} prefix is NOT accepted: a caller that strips one itself would
     * otherwise silently accept doubled-prefix input.
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

    /** {@link #parseHex} after dropping one leading {@code 0x}/{@code 0X}, if present. */
    public static byte[] parseHexPrefixed(CharSequence hex) {
        int len = hex.length();
        if (len >= 2 && hex.charAt(0) == '0' && (hex.charAt(1) == 'x' || hex.charAt(1) == 'X')) {
            return parseHex(hex.subSequence(2, len));
        }
        return parseHex(hex);
    }

    private static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new NumberFormatException("not a hexadecimal digit: '" + c + "'");
    }
}
