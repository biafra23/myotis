package com.jaeckel.ethp2p.core.trie;

import org.apache.tuweni.bytes.Bytes;

import java.util.ArrayList;
import java.util.List;

/**
 * Splits an RLP-encoded list into its child items, returning each child as
 * the raw RLP bytes (header + payload). The standard Tuweni
 * {@code RLPReader} is callback-based and does not expose an
 * "embedded child as raw bytes" view, which the MPT verifier needs to
 * interpret in-line trie nodes recursively without re-encoding.
 *
 * <p>Reference: Ethereum Yellow Paper, Appendix B (RLP).
 */
final class RlpItems {

    private RlpItems() {}

    /**
     * Take {@code listRlp}, which must be an RLP-encoded list, and return the
     * raw bytes of each child item (each itself a valid RLP item).
     */
    static List<Bytes> split(Bytes listRlp) {
        if (listRlp.isEmpty()) throw new IllegalArgumentException("empty RLP");
        int first = listRlp.get(0) & 0xff;
        int payloadStart;
        int payloadLen;
        if (first >= 0xc0 && first <= 0xf7) {
            payloadStart = 1;
            payloadLen = first - 0xc0;
        } else if (first >= 0xf8) {
            int lenOfLen = first - 0xf7;
            payloadStart = 1 + lenOfLen;
            payloadLen = readBigEndianInt(listRlp, 1, lenOfLen);
        } else {
            throw new IllegalArgumentException("not an RLP list (first byte=0x"
                    + Integer.toHexString(first) + ")");
        }
        if (payloadStart + payloadLen > listRlp.size()) {
            throw new IllegalArgumentException("RLP list payload runs past end");
        }
        List<Bytes> out = new ArrayList<>();
        int pos = payloadStart;
        int end = payloadStart + payloadLen;
        while (pos < end) {
            int itemLen = itemLength(listRlp, pos);
            out.add(listRlp.slice(pos, itemLen));
            pos += itemLen;
        }
        if (pos != end) {
            throw new IllegalArgumentException("trailing bytes inside RLP list");
        }
        return out;
    }

    /** Total length (header + payload) of the RLP item starting at {@code offset}. */
    private static int itemLength(Bytes data, int offset) {
        int first = data.get(offset) & 0xff;
        if (first <= 0x7f) {
            // Single byte item, the byte itself is the value.
            return 1;
        }
        if (first <= 0xb7) {
            // Short string.
            return 1 + (first - 0x80);
        }
        if (first <= 0xbf) {
            int lenOfLen = first - 0xb7;
            int payloadLen = readBigEndianInt(data, offset + 1, lenOfLen);
            return 1 + lenOfLen + payloadLen;
        }
        if (first <= 0xf7) {
            return 1 + (first - 0xc0);
        }
        // Long list.
        int lenOfLen = first - 0xf7;
        int payloadLen = readBigEndianInt(data, offset + 1, lenOfLen);
        return 1 + lenOfLen + payloadLen;
    }

    private static int readBigEndianInt(Bytes data, int offset, int len) {
        if (len <= 0 || len > 4) {
            throw new IllegalArgumentException("RLP length-of-length must be 1-4 bytes (got " + len + ")");
        }
        if (offset + len > data.size()) {
            throw new IllegalArgumentException("RLP length runs past end");
        }
        int v = 0;
        for (int i = 0; i < len; i++) {
            v = (v << 8) | (data.get(offset + i) & 0xff);
        }
        if (v < 0) throw new IllegalArgumentException("RLP length overflows int");
        return v;
    }

    /** Detects whether the RLP item at {@code item.get(0)} is a list (0xc0..0xff). */
    static boolean isList(Bytes item) {
        if (item.isEmpty()) return false;
        return (item.get(0) & 0xff) >= 0xc0;
    }
}
