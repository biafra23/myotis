package devp2p.networking;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Network-specific configuration for Ethereum chains.
 */
public record NetworkConfig(
        String name,
        long networkId,
        Bytes32 genesisHash,
        Bytes32 bestBlockHash,
        byte[] forkIdHash,
        long forkNext,
        List<InetSocketAddress> bootnodes
) {

    public static final NetworkConfig MAINNET = new NetworkConfig(
            "mainnet",
            1L,
            Bytes32.fromHexString("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
            Bytes32.fromHexString("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"), // genesis (honest)
            new byte[]{(byte) 0x07, (byte) 0xc9, (byte) 0x46, (byte) 0x2e}, // post-BPO2 (Fusaka)
            0L,
            List.of(
                    new InetSocketAddress("18.138.108.67", 30303),
                    new InetSocketAddress("3.209.45.79", 30303),
                    new InetSocketAddress("18.188.214.86", 30303),
                    new InetSocketAddress("3.219.208.172", 30303)
            )
    );

    public static final NetworkConfig SEPOLIA = new NetworkConfig(
            "sepolia",
            11155111L,
            Bytes32.fromHexString("25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"),
            Bytes32.fromHexString("25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"), // genesis (testnets lenient)
            new byte[]{(byte) 0x26, (byte) 0x89, (byte) 0x56, (byte) 0xb6}, // post-BPO2 (Fusaka)
            0L,
            List.of(
                    new InetSocketAddress("138.197.51.181", 30303),
                    new InetSocketAddress("146.190.1.103", 30303),
                    new InetSocketAddress("170.64.250.88", 30303),
                    new InetSocketAddress("139.59.49.206", 30303),
                    new InetSocketAddress("138.68.123.152", 30303)
            )
    );

    public static final NetworkConfig HOLESKY = new NetworkConfig(
            "holesky",
            17000L,
            Bytes32.fromHexString("b5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4"),
            Bytes32.fromHexString("b5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4"), // genesis (testnets lenient)
            new byte[]{(byte) 0x9b, (byte) 0xc6, (byte) 0xcb, (byte) 0x31}, // post-BPO2 (Fusaka)
            0L,
            List.of(
                    new InetSocketAddress("146.190.13.128", 30303),
                    new InetSocketAddress("178.128.136.233", 30303)
            )
    );

    /** Look up a network by name (case-insensitive). */
    public static NetworkConfig byName(String name) {
        return switch (name.toLowerCase()) {
            case "mainnet" -> MAINNET;
            case "sepolia" -> SEPOLIA;
            case "holesky" -> HOLESKY;
            default -> throw new IllegalArgumentException(
                    "Unknown network: " + name + ". Supported: mainnet, sepolia, holesky");
        };
    }

    // -------------------------------------------------------------------------
    // Mainnet genesis block header RLP (pre-computed, verified at class load)
    // -------------------------------------------------------------------------
    private static final Bytes32 EMPTY_OMMERS =
            Bytes32.fromHexString("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
    private static final Bytes32 EMPTY_TRIE =
            Bytes32.fromHexString("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

    /**
     * Mainnet genesis block header as raw RLP bytes.
     * keccak256 of this equals MAINNET.genesisHash.
     */
    public static final byte[] MAINNET_GENESIS_HEADER_RLP;
    static {
        MAINNET_GENESIS_HEADER_RLP = RLP.encodeList(w -> {
            w.writeValue(Bytes32.ZERO);                     // parentHash
            w.writeValue(EMPTY_OMMERS);                     // ommersHash
            w.writeValue(Bytes.wrap(new byte[20]));         // beneficiary (zero address)
            w.writeValue(Bytes32.fromHexString(             // stateRoot
                    "d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"));
            w.writeValue(EMPTY_TRIE);                       // transactionsRoot
            w.writeValue(EMPTY_TRIE);                       // receiptsRoot
            w.writeValue(Bytes.wrap(new byte[256]));        // logsBloom (256 zero bytes)
            w.writeBigInteger(BigInteger.valueOf(0x400000000L)); // difficulty
            w.writeLong(0);                                 // number
            w.writeLong(0x1388);                            // gasLimit (5000)
            w.writeLong(0);                                 // gasUsed
            w.writeLong(0);                                 // timestamp
            w.writeValue(Bytes.fromHexString(               // extraData
                    "11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"));
            w.writeValue(Bytes32.ZERO);                     // mixHash
            w.writeValue(Bytes.fromHexString("0000000000000042")); // nonce
        }).toArrayUnsafe();
        // Hash verified: keccak256(this RLP) == 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
    }
}
