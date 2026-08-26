package io.myotis.evm;

/**
 * Minimal hex codec with the exact semantics of {@code java.util.HexFormat.of()}
 * ({@code formatHex}/{@code parseHex}), which Android exposes only from API 34
 * and no desugar_jdk_libs release covers — the app's minSdk is 29. Lowercase
 * output, no {@code 0x} prefix, strict even-length case-insensitive parsing.
 */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {}

    /** Lowercase unprefixed hex, like {@code HexFormat.of().formatHex(bytes)}. */
    public static String formatHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            out[2 * i] = DIGITS[b >>> 4];
            out[2 * i + 1] = DIGITS[b & 0xf];
        }
        return new String(out);
    }

    /**
     * Parse unprefixed hex (either case), like {@code HexFormat.of().parseHex(hex)}.
     *
     * @throws IllegalArgumentException on odd length or a non-hex character
     */
    public static byte[] parseHex(CharSequence hex) {
        int len = hex.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("hex string has odd length: " + len);
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = digit(hex.charAt(2 * i));
            int lo = digit(hex.charAt(2 * i + 1));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int digit(char c) {
        int d = Character.digit(c, 16);
        if (d < 0) {
            throw new IllegalArgumentException("not a hex digit: '" + c + "'");
        }
        return d;
    }
}
