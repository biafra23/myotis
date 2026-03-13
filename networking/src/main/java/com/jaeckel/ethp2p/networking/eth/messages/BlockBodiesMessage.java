package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * eth/BlockBodies (message code 0x16).
 *
 * eth/68 format:
 *   RLP: [requestId, [[txs, uncles, withdrawals?], ...]]
 *
 * Each body: [transactions[], uncles[], withdrawals[]?]
 * Each transaction is either legacy RLP or typed (EIP-2718 envelope).
 */
public final class BlockBodiesMessage {

    public static final int CODE = 0x16;

    private BlockBodiesMessage() {}

    /** A decoded block body with raw transaction bytes and uncle count. */
    public record BlockBody(List<Bytes> transactions, int uncleCount, int withdrawalCount) {}

    public record DecodeResult(long requestId, List<BlockBody> bodies) {}

    public static DecodeResult decode(byte[] rlp) {
        List<BlockBody> bodies = new ArrayList<>();
        long[] reqId = {0};

        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            reader.readList(bodiesReader -> {
                decodeBodiesList(bodiesReader, bodies);
                return null;
            });
            return null;
        });

        return new DecodeResult(reqId[0], bodies);
    }

    /** eth/69: Decode block bodies without requestId wrapper. */
    public static DecodeResult decode69(byte[] rlp) {
        List<BlockBody> bodies = new ArrayList<>();
        RLP.decodeList(Bytes.wrap(rlp), bodiesReader -> {
            decodeBodiesList(bodiesReader, bodies);
            return null;
        });
        return new DecodeResult(0, bodies);
    }

    private static void decodeBodiesList(org.apache.tuweni.rlp.RLPReader bodiesReader,
                                          List<BlockBody> bodies) {
        while (!bodiesReader.isComplete()) {
            // each body: [transactions[], uncles[], withdrawals[]?]
            bodiesReader.readList(bodyReader -> {
                // transactions list — legacy txs are RLP lists, typed txs (EIP-2718) are values
                List<Bytes> txs = new ArrayList<>();
                bodyReader.readList(txReader -> {
                    while (!txReader.isComplete()) {
                        if (txReader.nextIsList()) {
                            // Legacy transaction: RLP list — read and discard inner structure
                            txReader.readList(legacyReader -> {
                                legacyReader.readRemaining();
                                return null;
                            });
                            txs.add(Bytes.EMPTY); // placeholder — we only need the count
                        } else {
                            txs.add(txReader.readValue());
                        }
                    }
                    return null;
                });
                // uncles list — each uncle is an RLP-encoded block header (a list)
                int[] uncleCount = {0};
                bodyReader.readList(uncleReader -> {
                    while (!uncleReader.isComplete()) {
                        if (uncleReader.nextIsList()) {
                            uncleReader.readList(u -> { u.readRemaining(); return null; });
                        } else {
                            uncleReader.readValue();
                        }
                        uncleCount[0]++;
                    }
                    return null;
                });
                // optional withdrawals list (post-Shanghai) — each withdrawal is a list
                int[] withdrawalCount = {0};
                if (!bodyReader.isComplete()) {
                    bodyReader.readList(wReader -> {
                        while (!wReader.isComplete()) {
                            if (wReader.nextIsList()) {
                                wReader.readList(w -> { w.readRemaining(); return null; });
                            } else {
                                wReader.readValue();
                            }
                            withdrawalCount[0]++;
                        }
                        return null;
                    });
                }
                bodies.add(new BlockBody(txs, uncleCount[0], withdrawalCount[0]));
                return null;
            });
        }
    }
}
