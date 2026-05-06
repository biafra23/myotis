package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * snap/1 ByteCodes response (absolute message code 0x25).
 *
 * <p>Wire format: {@code [reqId, [bytecode, ...]]}
 *
 * <p>Entries are returned in the same order as the requested code hashes.
 * Per the spec, peers may serve a prefix and stop early once the response
 * size cap is reached; missing entries are not zero-filled, the response
 * simply ends.
 *
 * <p>The caller is responsible for hashing each returned bytecode and
 * matching it against the originally-requested hash. Mismatches indicate a
 * malicious or buggy peer.
 */
public final class ByteCodesMessage {

    private ByteCodesMessage() {}

    public record DecodeResult(long requestId, List<Bytes> codes) {}

    /** Extract just the request ID without fully decoding. */
    public static long extractRequestId(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> reader.readLong());
    }

    /** Encode an empty response (peer declined to serve). */
    public static byte[] encodeEmpty(long requestId) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(codes -> {});
        }).toArrayUnsafe();
    }

    /** Encode a populated response. */
    public static byte[] encode(long requestId, List<Bytes> codes) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(listWriter -> {
                for (Bytes c : codes) listWriter.writeValue(c);
            });
        }).toArrayUnsafe();
    }

    public static DecodeResult decode(byte[] rlp) {
        List<Bytes> codes = new ArrayList<>();
        long[] reqId = {0L};

        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            // The codes field can be a list (the normal case) or an empty
            // bytes value (some clients use 0x80 for an empty response).
            if (!reader.isComplete() && reader.nextIsList()) {
                reader.readList(codeReader -> {
                    while (!codeReader.isComplete()) {
                        codes.add(codeReader.readValue());
                    }
                    return null;
                });
            } else if (!reader.isComplete()) {
                reader.readValue();
            }
            return null;
        });

        return new DecodeResult(reqId[0], codes);
    }
}
