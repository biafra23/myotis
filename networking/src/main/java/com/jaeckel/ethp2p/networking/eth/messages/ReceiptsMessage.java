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
