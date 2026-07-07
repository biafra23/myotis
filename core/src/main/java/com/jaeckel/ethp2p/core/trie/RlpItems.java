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
     *
     * <p>Canonical-strict (Rust-twin parity, pinned by the el/mpt conformance
     * corpus; geth's RLP decoder is equally strict): non-minimal length
     * prefixes and leading-zero length bytes are rejected, and every child
     * item must lie fully inside the list payload — previously a truncated
     * item escaped as an uncaught {@code IndexOutOfBoundsException} from
     * {@code slice()} instead of the {@code IllegalArgumentException} the
     * verifier maps to {@code Result.Invalid}.
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
            payloadLen = readCanonicalLength(listRlp, 1, lenOfLen);
        } else {
            throw new IllegalArgumentException("not an RLP list (first byte=0x"
                    + Integer.toHexString(first) + ")");
        }
        if (payloadStart + payloadLen != listRlp.size()) {
            throw new IllegalArgumentException("RLP list length does not match input size");
        }
        List<Bytes> out = new ArrayList<>();
        int pos = payloadStart;
        int end = payloadStart + payloadLen;
        while (pos < end) {
            int itemLen = itemLength(listRlp, pos);
            // Overflow-safe form: itemLen can be up to Integer.MAX_VALUE for a
            // hostile length declaration, so never compute pos + itemLen.
            if (itemLen > end - pos) {
                throw new IllegalArgumentException("RLP item runs past list payload");
            }
            out.add(listRlp.slice(pos, itemLen));
            pos += itemLen;
        }
        return out;
    }

    /**
     * {@link #split} plus a full structural validation of every embedded list
     * child, recursively (depth-capped) — so a node is either wholly
     * well-formed or rejected, exactly like the Rust twin's eager
     * {@code rlp::decode}. Without this, a malformed embedded list in an
     * UNTRAVERSED branch slot would split fine here but fail the whole-node
     * decode there — divergent verdicts under {@code myotis.engine=java|rust}.
     */
    static List<Bytes> splitValidated(Bytes listRlp) {
        List<Bytes> items = split(listRlp);
        for (Bytes item : items) validateStructure(item, 1);
        return items;
    }

    /** Depth cap mirrors the Rust decoder's MAX_DEPTH (top-level node = 0). */
    private static void validateStructure(Bytes item, int depth) {
        if (depth > 32) {
            throw new IllegalArgumentException("RLP nesting too deep");
        }
        if (!isList(item)) return;
        for (Bytes child : split(item)) validateStructure(child, depth + 1);
    }

    /** Total length (header + payload) of the RLP item starting at {@code offset}. */
    private static int itemLength(Bytes data, int offset) {
        int first = data.get(offset) & 0xff;
        if (first <= 0x7f) {
            // Single byte item, the byte itself is the value.
            return 1;
        }
        if (first <= 0xb7) {
            // Short string — reject the non-canonical single-byte form
            // (0x81 0x0X where the byte should encode as itself).
            if (first == 0x81 && offset + 1 < data.size() && (data.get(offset + 1) & 0xff) < 0x80) {
                throw new IllegalArgumentException("non-canonical single byte RLP item");
            }
            return 1 + (first - 0x80);
        }
        if (first <= 0xbf) {
            int lenOfLen = first - 0xb7;
            int payloadLen = readCanonicalLength(data, offset + 1, lenOfLen);
            return 1 + lenOfLen + payloadLen;
        }
        if (first <= 0xf7) {
            return 1 + (first - 0xc0);
        }
        // Long list.
        int lenOfLen = first - 0xf7;
        int payloadLen = readCanonicalLength(data, offset + 1, lenOfLen);
        return 1 + lenOfLen + payloadLen;
    }

    /** Long-form length: canonical (no leading zero, value > 55) big-endian. */
    private static int readCanonicalLength(Bytes data, int offset, int len) {
        if (len <= 0 || len > 4) {
            throw new IllegalArgumentException("RLP length-of-length must be 1-4 bytes (got " + len + ")");
        }
        if (offset + len > data.size()) {
            throw new IllegalArgumentException("RLP length runs past end");
        }
        if (data.get(offset) == 0) {
            throw new IllegalArgumentException("RLP length has leading zero byte");
        }
        int v = 0;
        for (int i = 0; i < len; i++) {
            v = (v << 8) | (data.get(offset + i) & 0xff);
        }
        if (v < 0) throw new IllegalArgumentException("RLP length overflows int");
        if (v <= 55) throw new IllegalArgumentException("non-canonical long-form RLP length <= 55");
        // Bound against the input NOW (Rust-twin parity): a near-INT_MAX
        // declared length would otherwise overflow itemLength()'s sum and
        // escape as an uncaught IndexOutOfBoundsException downstream.
        if (v > data.size()) {
            throw new IllegalArgumentException("RLP length exceeds input size");
        }
        return v;
    }

    /** Detects whether the RLP item at {@code item.get(0)} is a list (0xc0..0xff). */
    static boolean isList(Bytes item) {
        if (item.isEmpty()) return false;
        return (item.get(0) & 0xff) >= 0xc0;
    }
}
