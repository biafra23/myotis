package devp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

/**
 * eth/Status (message code 0x10, offset 0x10 from p2p base = 0x00).
 *
 * After eth capability is negotiated (offset 0x10 for eth messages):
 *   Status code = 0x10 + 0x00 = 0x10
 *
 * RLP: [protocolVersion, networkId, td, bestHash, genesisHash, forkId([hash, next])]
 *
 * For eth/68, forkId is required.
 */
public final class StatusMessage {

    // eth/68 code within the eth namespace = 0x00 (first message)
    // Over the wire: 0x10 (base offset for eth capability after p2p hello)
    public static final int CODE = 0x10;
    public static final int ETH_VERSION = 68;

    // Mainnet constants
    public static final long MAINNET_NETWORK_ID = 1L;
    // Genesis hash of Ethereum mainnet
    public static final Bytes32 MAINNET_GENESIS_HASH = Bytes32.fromHexString(
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    // Mainnet genesis total difficulty (used in legacy eth; for post-Merge td=0 is accepted)
    public static final Bytes MAINNET_TOTAL_DIFFICULTY = Bytes.fromHexString("0x400000000000000000");

    public final int protocolVersion;
    public final long networkId;
    public final Bytes totalDifficulty;
    public final Bytes32 bestHash;
    public final Bytes32 genesisHash;

    private StatusMessage(int protoVer, long networkId, Bytes td,
                          Bytes32 best, Bytes32 genesis) {
        this.protocolVersion = protoVer;
        this.networkId = networkId;
        this.totalDifficulty = td;
        this.bestHash = best;
        this.genesisHash = genesis;
    }

    /**
     * Encode a mainnet Status message.
     *
     * @param bestBlockHash  the hash of our best known block (use genesis for new node)
     * @param forkIdHash     4-byte fork ID hash (post-Cancun mainnet: 0x9f3d2254)
     * @param forkNext       block number of next fork (0 if none known)
     */
    public static byte[] encodeMainnet(Bytes32 bestBlockHash, byte[] forkIdHash, long forkNext) {
        return RLP.encodeList(writer -> {
            writer.writeInt(ETH_VERSION);
            writer.writeLong(MAINNET_NETWORK_ID);
            writer.writeValue(MAINNET_TOTAL_DIFFICULTY);
            writer.writeValue(bestBlockHash);
            writer.writeValue(MAINNET_GENESIS_HASH);
            writer.writeList(forkWriter -> {
                forkWriter.writeValue(Bytes.wrap(forkIdHash));
                forkWriter.writeLong(forkNext);
            });
        }).toArrayUnsafe();
    }

    public static StatusMessage decode(byte[] rlp) {
        return RLP.decodeList(Bytes.wrap(rlp), reader -> {
            int version = reader.readInt();
            long netId = reader.readLong();
            Bytes td = reader.readValue();
            Bytes32 best = Bytes32.wrap(reader.readValue());
            Bytes32 genesis = Bytes32.wrap(reader.readValue());
            // forkId is an RLP list [hash(4), next(uint64)] — must readList(), not readValue()
            if (!reader.isComplete()) {
                reader.readList(fr -> null); // consume the forkId list; we only need genesis+networkId
            }
            return new StatusMessage(version, netId, td, best, genesis);
        });
    }

    public boolean isCompatible() {
        return networkId == MAINNET_NETWORK_ID && genesisHash.equals(MAINNET_GENESIS_HASH);
    }

    @Override
    public String toString() {
        return "Status{version=" + protocolVersion + ", networkId=" + networkId +
               ", best=" + bestHash.toShortHexString() + "}";
    }
}
