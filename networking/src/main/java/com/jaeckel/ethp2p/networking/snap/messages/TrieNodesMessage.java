package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * snap/1 TrieNodes response (snap message id 0x07; absolute code 0x28
 * under eth/68's protocol length 17).
 *
 * <p>Wire format: {@code [reqId, [trieNode, ...]]}
 *
 * <p>Trie nodes are returned in the same order as the paths in the
 * corresponding {@link GetTrieNodesMessage}. Per the spec, peers may serve
 * a prefix and stop early once the response size cap is reached; missing
 * entries are not zero-filled.
 *
 * <p>The caller verifies each returned node by hashing it (keccak256) and
 * confirming the hash matches the trie position the request implied.
 * Mismatches indicate a malicious or buggy peer.
 */
public final class TrieNodesMessage {

    private TrieNodesMessage() {}

    public record DecodeResult(long requestId, List<Bytes> nodes) {}

    /** Extract just the request ID without fully decoding. */
    public static long extractRequestId(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> reader.readLong());
    }

    /** Encode an empty response (peer declined to serve). */
    public static byte[] encodeEmpty(long requestId) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(nodes -> {});
        }).toArrayUnsafe();
    }

    /** Encode a populated response. */
    public static byte[] encode(long requestId, List<Bytes> nodes) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(listWriter -> {
                for (Bytes n : nodes) listWriter.writeValue(n);
            });
        }).toArrayUnsafe();
    }

    public static DecodeResult decode(byte[] rlp) {
        List<Bytes> nodes = new ArrayList<>();
        long[] reqId = {0L};

        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            // The nodes field can be a list (the normal case) or an empty
            // bytes value (some clients use 0x80 for an empty response).
            if (!reader.isComplete() && reader.nextIsList()) {
                reader.readList(nodeReader -> {
                    while (!nodeReader.isComplete()) {
                        nodes.add(nodeReader.readValue());
                    }
                    return null;
                });
            } else if (!reader.isComplete()) {
                reader.readValue();
            }
            return null;
        });

        return new DecodeResult(reqId[0], nodes);
    }
}
