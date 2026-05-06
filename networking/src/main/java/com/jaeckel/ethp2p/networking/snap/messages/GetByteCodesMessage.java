package com.jaeckel.ethp2p.networking.snap.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.util.ArrayList;
import java.util.List;

/**
 * snap/1 GetByteCodes request (absolute message code 0x24).
 *
 * <p>Wire format: {@code [reqId, [hash, ...], responseBytes]}
 *
 * <p>Each {@code hash} is the keccak256 of the bytecode being requested. The
 * response ({@link ByteCodesMessage}) contains the bytecodes in the same
 * order as the requested hashes; missing entries are returned as empty.
 *
 * <p>Bytecode is immutable forever, so this request does not need a state
 * root — the {@code codeHash} alone is the integrity anchor.
 */
public final class GetByteCodesMessage {

    private GetByteCodesMessage() {}

    public record DecodeResult(long requestId, List<Bytes32> hashes, long responseBytes) {}

    /** Encode a GetByteCodes request. */
    public static byte[] encode(long requestId, List<Bytes32> hashes, long responseBytes) {
        return RLP.encodeList(w -> {
            w.writeLong(requestId);
            w.writeList(listWriter -> {
                for (Bytes32 h : hashes) listWriter.writeValue(h);
            });
            w.writeLong(responseBytes);
        }).toArrayUnsafe();
    }

    public static DecodeResult decode(byte[] rlp) {
        List<Bytes32> hashes = new ArrayList<>();
        long[] reqId = {0L};
        long[] respBytes = {0L};

        RLP.decodeList(Bytes.wrap(rlp), reader -> {
            reqId[0] = reader.readLong();
            reader.readList(hashReader -> {
                while (!hashReader.isComplete()) {
                    hashes.add(Bytes32.wrap(hashReader.readValue()));
                }
                return null;
            });
            respBytes[0] = reader.readLong();
            return null;
        });

        return new DecodeResult(reqId[0], hashes, respBytes[0]);
    }
}
