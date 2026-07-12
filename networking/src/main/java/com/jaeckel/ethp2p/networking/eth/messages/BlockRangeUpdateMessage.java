package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/69 (EIP-7642) {@code BlockRangeUpdate} (message id 0x11 within the eth capability).
 *
 * <p>Wire form: {@code [earliestBlock, latestBlock, latestBlockHash]}. A node sends it to
 * already-connected peers when the range of blocks it can serve changes — for us, when
 * our {@link com.jaeckel.ethp2p.networking.eth.ServedHeaderWindow} grows as we cache more
 * recent headers, so peers learn they can now ask us for a wider window than we could
 * back at handshake time. Only valid on eth/69+ (on eth/68 the same id 0x11 is the
 * obsolete NewBlockHashes, so callers MUST gate on the negotiated version).
 */
public final class BlockRangeUpdateMessage {

    private BlockRangeUpdateMessage() {}

    public record Decoded(long earliestBlock, long latestBlock, Bytes32 latestBlockHash) {}

    public static byte[] encode(long earliestBlock, long latestBlock, Bytes32 latestBlockHash) {
        return RLP.encodeList(writer -> {
            writer.writeLong(earliestBlock);
            writer.writeLong(latestBlock);
            writer.writeValue(latestBlockHash);
        }).toArrayUnsafe();
    }

    public static Decoded decode(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> {
            long earliest = reader.readLong();
            long latest = reader.readLong();
            Bytes32 latestHash = Bytes32.wrap(reader.readValue());
            return new Decoded(earliest, latest, latestHash);
        });
    }
}
