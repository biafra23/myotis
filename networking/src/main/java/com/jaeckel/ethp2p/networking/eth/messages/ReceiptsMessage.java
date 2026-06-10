package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;
import org.apache.tuweni.rlp.RLPReader;

import java.util.ArrayList;
import java.util.List;

/**
 * eth/Receipts (wire code 0x20 = eth message 0x10 + base offset 0x10).
 *
 * eth/66-68 format:
 *   RLP: [requestId, [ [receipt, receipt, ...] , ... ]]
 *
 * The outer list has one entry per requested block; each inner list holds that block's
 * receipts in order. Each receipt is its consensus encoding: a legacy receipt is an RLP
 * list {@code [status, cumulativeGasUsed, logsBloom, logs]}; a typed (EIP-2718) receipt
 * is the envelope {@code type || rlp(...)} sent as an RLP byte-string. We capture each
 * receipt's RAW consensus bytes — that is exactly the value stored in the receipts trie,
 * so the caller can rebuild the trie and check its root against {@code header.receiptsRoot}.
 *
 * <p>(eth/69 omits the bloom from the wire receipt; this decoder targets eth/66-68, where
 * the receipt is the full canonical encoding. Request receipts from an eth/&le;68 peer.)
 */
public final class ReceiptsMessage {

    public static final int CODE = 0x20;

    private ReceiptsMessage() {}

    /** Raw consensus-encoded receipts, grouped per requested block (request order). */
    public record DecodeResult(long requestId, List<List<Bytes>> perBlockReceipts) {}

    public static DecodeResult decode(byte[] rlp) {
        List<List<Bytes>> blocks = new ArrayList<>();
        long[] reqId = {0};
        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            reader.readList(blocksReader -> {
                while (!blocksReader.isComplete()) {
                    List<Bytes> receipts = new ArrayList<>();
                    blocksReader.readList(receiptListReader -> {
                        while (!receiptListReader.isComplete()) {
                            if (receiptListReader.nextIsList()) {
                                // Legacy receipt: an RLP list (with nested logs). Reconstruct
                                // its raw RLP bytes — that's the trie value.
                                receipts.add(reconstructRlpList(receiptListReader));
                            } else {
                                // Typed receipt: the byte-string content IS type||rlp(...),
                                // which is the trie value as-is (not re-wrapped).
                                receipts.add(receiptListReader.readValue());
                            }
                        }
                        return null;
                    });
                    blocks.add(receipts);
                }
                return null;
            });
            return null;
        });
        return new DecodeResult(reqId[0], blocks);
    }

    /**
     * Decode an eth/69 (EIP-7642) Receipts message into CANONICAL consensus receipt
     * bytes. eth/69 strips the logsBloom from each wire receipt and flattens the
     * typed envelope: every receipt arrives as the 4-item list
     * {@code [txType, postStateOrStatus, cumulativeGas, logs]}. The bloom is a pure
     * function of the logs, so we recompute it and re-encode the canonical form
     * (legacy: {@code rlp([status, cumGas, bloom, logs])}; typed: {@code type || rlp(...)})
     * — the caller's receipts-trie verification against {@code header.receiptsRoot}
     * then works exactly as for eth/66-68. A peer that lies about the logs still
     * fails that root check; recomputing the bloom adds no trust.
     */
    public static DecodeResult decode69(byte[] rlp) {
        List<List<Bytes>> blocks = new ArrayList<>();
        long[] reqId = {0};
        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            reader.readList(blocksReader -> {
                while (!blocksReader.isComplete()) {
                    List<Bytes> receipts = new ArrayList<>();
                    blocksReader.readList(receiptListReader -> {
                        while (!receiptListReader.isComplete()) {
                            receipts.add(canonicalizeEth69Receipt(receiptListReader));
                        }
                        return null;
                    });
                    blocks.add(receipts);
                }
                return null;
            });
            return null;
        });
        return new DecodeResult(reqId[0], blocks);
    }

    /** Read one eth/69 wire receipt and return its canonical consensus encoding. */
    private static Bytes canonicalizeEth69Receipt(RLPReader outer) {
        return outer.readList(r -> {
            Bytes typeBytes = r.readValue();
            int type = typeBytes.isEmpty() ? 0 : typeBytes.get(typeBytes.size() - 1) & 0xFF;
            Bytes statusOrState = r.readValue();
            Bytes cumGas = r.readValue();
            byte[] bloom = new byte[256];
            List<Bytes> rawLogs = new ArrayList<>();
            r.readList(logsReader -> {
                while (!logsReader.isComplete()) {
                    logsReader.readList(logReader -> {
                        Bytes address = logReader.readValue();
                        List<Bytes> topics = new ArrayList<>();
                        logReader.readList(tr -> {
                            while (!tr.isComplete()) topics.add(tr.readValue());
                            return null;
                        });
                        Bytes data = logReader.readValue();
                        bloomAccrue(bloom, address);
                        for (Bytes t : topics) bloomAccrue(bloom, t);
                        rawLogs.add(RLP.encodeList(w -> {
                            w.writeValue(address);
                            w.writeList(tw -> topics.forEach(tw::writeValue));
                            w.writeValue(data);
                        }));
                        return null;
                    });
                }
                return null;
            });
            Bytes payload = RLP.encodeList(w -> {
                w.writeValue(statusOrState);
                w.writeValue(cumGas);
                w.writeValue(Bytes.wrap(bloom));
                w.writeList(lw -> rawLogs.forEach(lw::writeRLP));
            });
            return type == 0 ? payload : Bytes.concatenate(Bytes.of((byte) type), payload);
        });
    }

    /**
     * Accrue one bloom item (log address or topic) into a 2048-bit logs bloom
     * (Yellow Paper M3:2048): three bits indexed by the low 11 bits of the first
     * three byte-PAIRS of keccak256(item); bit i sets byte {@code 255 - i/8},
     * bit {@code i % 8}.
     */
    private static void bloomAccrue(byte[] bloom, Bytes item) {
        byte[] h = org.apache.tuweni.crypto.Hash.keccak256(item).toArrayUnsafe();
        for (int i = 0; i < 6; i += 2) {
            int bit = (((h[i] & 0xFF) << 8) | (h[i + 1] & 0xFF)) & 0x7FF;
            bloom[255 - bit / 8] |= (byte) (1 << (bit % 8));
        }
    }

    /**
     * Reconstruct the canonical raw RLP of the list the reader is positioned on, recursing
     * into nested lists (e.g. a receipt's logs). RLP is canonical, so re-encoding a decoded
     * structure reproduces the original bytes that the receipts trie was built over.
     */
    private static Bytes reconstructRlpList(RLPReader reader) {
        List<Bytes> rawChildren = new ArrayList<>();
        reader.readList(inner -> {
            while (!inner.isComplete()) {
                if (inner.nextIsList()) {
                    rawChildren.add(reconstructRlpList(inner));
                } else {
                    rawChildren.add(RLP.encodeValue(inner.readValue()));
                }
            }
            return null;
        });
        return RLP.encodeList(w -> rawChildren.forEach(w::writeRLP));
    }
}
