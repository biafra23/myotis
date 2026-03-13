package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/Status (message code 0x10, offset 0x10 from p2p base = 0x00).
 *
 * eth/67-68 RLP: [protocolVersion, networkId, td, bestHash, genesisHash, forkId([hash, next])]
 * eth/69    RLP: [protocolVersion, networkId, genesis, forkId([hash, next]), earliestBlock, latestBlock, latestBlockHash]
 */
public final class StatusMessage {

    public static final int CODE = 0x10;
    public static final int MIN_ETH_VERSION = 67;
    public static final int MAX_ETH_VERSION = 69;

    // Post-merge: TD is irrelevant, send 0 (matches Geth v1.17+ behavior)
    private static final Bytes DEFAULT_TOTAL_DIFFICULTY = Bytes.EMPTY;

    public final int protocolVersion;
    public final long networkId;
    public final Bytes totalDifficulty; // null for eth/69
    public final Bytes32 bestHash;      // latestBlockHash for eth/69
    public final Bytes32 genesisHash;
    public final long earliestBlock;    // eth/69 only (-1 for eth/67-68)
    public final long latestBlock;      // eth/69 only (-1 for eth/67-68)
    public final Bytes forkIdHash;      // decoded fork ID hash (for debug)
    public final long forkNext;         // decoded fork next (for debug)

    private StatusMessage(int protoVer, long networkId, Bytes td,
                          Bytes32 best, Bytes32 genesis,
                          long earliestBlock, long latestBlock,
                          Bytes forkIdHash, long forkNext) {
        this.protocolVersion = protoVer;
        this.networkId = networkId;
        this.totalDifficulty = td;
        this.bestHash = best;
        this.genesisHash = genesis;
        this.earliestBlock = earliestBlock;
        this.latestBlock = latestBlock;
        this.forkIdHash = forkIdHash;
        this.forkNext = forkNext;
    }

    /**
     * Encode an eth/67-68 Status message.
     */
    public static byte[] encode(int ethVersion, long networkId, Bytes32 genesisHash,
                                Bytes32 bestHash, byte[] forkIdHash, long forkNext,
                                long latestBlockNumber) {
        if (ethVersion >= 69) {
            return encode69(ethVersion, networkId, genesisHash, bestHash, forkIdHash, forkNext, latestBlockNumber);
        }
        return RLP.encodeList(writer -> {
            writer.writeInt(ethVersion);
            writer.writeLong(networkId);
            writer.writeValue(DEFAULT_TOTAL_DIFFICULTY);
            writer.writeValue(bestHash);
            writer.writeValue(genesisHash);
            writer.writeList(forkWriter -> {
                forkWriter.writeValue(Bytes.wrap(forkIdHash));
                forkWriter.writeLong(forkNext);
            });
        }).toArrayUnsafe();
    }

    /**
     * Encode an eth/69 Status message.
     * Format: [version, networkId, genesis, forkId, earliestBlock, latestBlock, latestBlockHash]
     */
    private static byte[] encode69(int ethVersion, long networkId, Bytes32 genesisHash,
                                   Bytes32 latestBlockHash, byte[] forkIdHash, long forkNext,
                                   long latestBlockNumber) {
        return RLP.encodeList(writer -> {
            writer.writeInt(ethVersion);
            writer.writeLong(networkId);
            writer.writeValue(genesisHash);
            writer.writeList(forkWriter -> {
                forkWriter.writeValue(Bytes.wrap(forkIdHash));
                forkWriter.writeLong(forkNext);
            });
            writer.writeLong(0);              // earliestBlock (we have genesis = block 0)
            writer.writeLong(latestBlockNumber); // latestBlock from chain head
            writer.writeValue(latestBlockHash);
        }).toArrayUnsafe();
    }

    /**
     * Decode an eth/67-68 Status message.
     */
    public static StatusMessage decode(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> {
            int version = reader.readInt();
            long netId = reader.readLong();
            Bytes td = reader.readValue();
            Bytes32 best = Bytes32.wrap(reader.readValue());
            Bytes32 genesis = Bytes32.wrap(reader.readValue());
            Bytes[] forkHash = {null};
            long[] forkNextArr = {0};
            if (!reader.isComplete()) {
                reader.readList(fr -> {
                    forkHash[0] = fr.readValue();
                    forkNextArr[0] = fr.readLong();
                    return null;
                });
            }
            return new StatusMessage(version, netId, td, best, genesis, -1, -1, forkHash[0], forkNextArr[0]);
        });
    }

    /**
     * Decode an eth/69 Status message.
     * Format: [version, networkId, genesis, forkId, earliestBlock, latestBlock, latestBlockHash]
     */
    public static StatusMessage decode69(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> {
            int version = reader.readInt();
            long netId = reader.readLong();
            Bytes32 genesis = Bytes32.wrap(reader.readValue());
            Bytes[] forkHash = {null};
            long[] forkNextArr = {0};
            reader.readList(fr -> {
                forkHash[0] = fr.readValue();
                forkNextArr[0] = fr.readLong();
                return null;
            });
            long earliest = reader.readLong();
            long latest = reader.readLong();
            Bytes32 latestHash = Bytes32.wrap(reader.readValue());
            return new StatusMessage(version, netId, null, latestHash, genesis, earliest, latest, forkHash[0], forkNextArr[0]);
        });
    }

    public boolean isCompatible(long expectedNetworkId, Bytes32 expectedGenesis) {
        return networkId == expectedNetworkId && genesisHash.equals(expectedGenesis);
    }

    @Override
    public String toString() {
        String forkStr = forkIdHash != null
            ? ", forkId=" + forkIdHash.toHexString() + "/" + forkNext
            : "";
        if (earliestBlock >= 0) {
            return "Status{version=" + protocolVersion + ", networkId=" + networkId +
                   ", genesis=" + genesisHash.toShortHexString() +
                   ", latestBlock=" + latestBlock +
                   ", latestHash=" + bestHash.toShortHexString() +
                   forkStr + "}";
        }
        return "Status{version=" + protocolVersion + ", networkId=" + networkId +
               ", genesis=" + genesisHash.toShortHexString() +
               ", best=" + bestHash.toShortHexString() +
               forkStr + "}";
    }
}
