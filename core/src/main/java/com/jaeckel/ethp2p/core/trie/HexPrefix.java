package com.jaeckel.ethp2p.core.trie;

/**
 * Compact (hex-prefix) encoding used inside Modified Merkle Patricia Trie
 * leaf and extension nodes.
 *
 * <p>The first nibble of the encoded path holds two bits:
 * <pre>
 *   0x00 — extension, even-length nibbles
 *   0x10 — extension, odd-length nibbles  (low nibble = first path nibble)
 *   0x20 — leaf,      even-length nibbles
 *   0x30 — leaf,      odd-length nibbles  (low nibble = first path nibble)
 * </pre>
 *
 * <p>Even-length encodings carry a padding nibble of zero in the second
 * position; odd-length encodings carry the first path nibble in the second
 * position so all subsequent bytes are pairs.
 *
 * <p>Reference: Ethereum Yellow Paper, Appendix C.
 */
public final class HexPrefix {

    private HexPrefix() {}

    /** Result of decoding a hex-prefix path. */
    public record Decoded(boolean leaf, byte[] nibbles) {}

    /** Decode a compact-encoded path into ({@code isLeaf}, raw nibble array). */
    public static Decoded decode(byte[] encoded) {
        if (encoded.length == 0) {
            throw new IllegalArgumentException("empty hex-prefix path");
        }
        int flag = (encoded[0] & 0xff) >>> 4;
        if (flag > 3) {
            throw new IllegalArgumentException("invalid hex-prefix flag nibble: " + flag);
        }
        boolean leaf = (flag & 0x02) != 0;
        boolean odd = (flag & 0x01) != 0;

        int totalNibbles = encoded.length * 2 - (odd ? 1 : 2);
        if (totalNibbles < 0) totalNibbles = 0;
        byte[] nibbles = new byte[totalNibbles];
        int n = 0;
        // Odd: first nibble is encoded[0] & 0x0f. Even: skip the padding nibble.
        if (odd) {
            nibbles[n++] = (byte) (encoded[0] & 0x0f);
        }
        for (int i = 1; i < encoded.length; i++) {
            int b = encoded[i] & 0xff;
            nibbles[n++] = (byte) (b >>> 4);
            nibbles[n++] = (byte) (b & 0x0f);
        }
        return new Decoded(leaf, nibbles);
    }

    /** Encode raw nibbles + leaf flag into the compact hex-prefix form. */
    public static byte[] encode(byte[] nibbles, boolean leaf) {
        for (byte n : nibbles) {
            if ((n & 0xf0) != 0) throw new IllegalArgumentException("not a nibble: " + n);
        }
        boolean odd = (nibbles.length & 1) == 1;
        int flag = (leaf ? 2 : 0) | (odd ? 1 : 0);
        int outLen = (nibbles.length + (odd ? 1 : 2)) / 2;
        byte[] out = new byte[outLen];
        int srcIdx;
        if (odd) {
            out[0] = (byte) ((flag << 4) | (nibbles[0] & 0x0f));
            srcIdx = 1;
        } else {
            out[0] = (byte) (flag << 4);
            srcIdx = 0;
        }
        int dstIdx = 1;
        while (srcIdx < nibbles.length) {
            int high = nibbles[srcIdx++] & 0x0f;
            int low = nibbles[srcIdx++] & 0x0f;
            out[dstIdx++] = (byte) ((high << 4) | low);
        }
        return out;
    }

    /** Convert raw bytes to a nibble array (each byte → high nibble then low nibble). */
    public static byte[] toNibbles(byte[] bytes) {
        byte[] out = new byte[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xff;
            out[2 * i] = (byte) (b >>> 4);
            out[2 * i + 1] = (byte) (b & 0x0f);
        }
        return out;
    }
}
