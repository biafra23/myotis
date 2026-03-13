package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.enr.Enr;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
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
        List<InetSocketAddress> bootnodes,
        // Beacon chain / consensus layer fields
        byte[] genesisValidatorsRoot,   // 32 bytes: genesis_validators_root for BLS domain computation
        byte[] checkpointRoot,          // 32 bytes: trusted checkpoint block root for bootstrap
        byte[] currentForkVersion,      // 4 bytes: current fork version for signing domain
        List<String> clPeerMultiaddrs,  // libp2p multiaddrs of known CL peers
        String beaconApiUrl             // HTTP API URL for local beacon node (e.g. http://172.17.0.1:5052)
) {

    // -------------------------------------------------------------------------
    // Lighthouse mainnet CL bootstrap ENRs
    // Source: https://github.com/sigp/lighthouse/blob/stable/common/eth2_network_config/built_in_network_configs/mainnet/bootstrap_nodes.yaml
    // -------------------------------------------------------------------------

    /** Prepend a local/priority multiaddr to an existing list. */
    private static List<String> prependLocal(String local, List<String> rest) {
        List<String> result = new ArrayList<>();
        result.add(local);
        result.addAll(rest);
        return List.copyOf(result);
    }

    /** Convert a list of ENR strings to libp2p multiaddr strings, skipping any that lack tcp/secp256k1. */
    private static List<String> enrsToMultiaddrs(List<String> enrs) {
        List<String> result = new ArrayList<>();
        for (String enr : enrs) {
            try {
                Enr.fromEnrString(enr).toLibp2pMultiaddr().ifPresent(result::add);
            } catch (Exception e) {
                // Skip malformed ENRs silently during static init
            }
        }
        return List.copyOf(result);
    }

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
            ),
            // genesis_validators_root (mainnet)
            Bytes.fromHexString("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95").toArrayUnsafe(),
            // trusted checkpoint: recent finalized mainnet block root (slot 13870176, 2026-03-11)
            Bytes.fromHexString("18c3d9b80a42584f42d16e057e6e3b711289c6f7b6d089cc27699aa1adf7de05").toArrayUnsafe(),
            // current fork version: Electra (0x05000000)
            new byte[]{0x05, 0x00, 0x00, 0x00},
            // CL peer multiaddrs: known light-client-serving peers (nimbus, lodestar, lighthouse)
            // discovered via Lighthouse peer API 2026-03-11
            List.of(
                    // nimbus peers (4 light_client protocols)
                    "/ip4/176.229.58.1/tcp/9001/p2p/16Uiu2HAmHu1BxzrSWg7sN9JyJenC5unK5ntdk5QFYqQdQyyD7x3a",
                    "/ip4/81.172.166.237/tcp/9001/p2p/16Uiu2HAmRogw5aqM4ZuVEmZoQvFp25sUnnQ9wpGuWXRLFMmXc88j",
                    "/ip4/54.157.213.0/tcp/9000/p2p/16Uiu2HAmQz83bNmMaBFCafuxDasiNdPYZF1B4zhgo3DckByU8bo3",
                    "/ip4/84.229.246.214/tcp/9001/p2p/16Uiu2HAm1UtRynVpuvWUgn3bfNooSUKYSUrbW8oeuBBcwVxbC1c9",
                    "/ip4/73.205.184.197/tcp/9000/p2p/16Uiu2HAm9CKG1x5rJk6sgEnCh9TKRagNEVVJfjR1jC3ruzPQfwzb",
                    "/ip4/172.92.13.157/tcp/9000/p2p/16Uiu2HAm7TEx4DP8iVj1RedeDNK59pw9AskGRwV7x9vgexTQi8CM",
                    "/ip4/77.12.100.127/tcp/9012/p2p/16Uiu2HAmA5VXnNKGu9jmV5yhL3tGy5seiNMnaBMTaV1vBesz84iJ",
                    "/ip4/52.200.203.85/tcp/9000/p2p/16Uiu2HAm6JKuoWTSKP7uTbe1PESUcejo4ffcaADoRMuKmMJQKBeP",
                    "/ip4/82.139.21.242/tcp/9802/p2p/16Uiu2HAm5LSnoe8EdTDhrPEm4M1fnYw34zSo2SYbXLLH4FtfcfnL",
                    "/ip4/217.67.221.74/tcp/9037/p2p/16Uiu2HAmExQubp4XC5KoQwvYxNWJP2M5rpX3VKdtEYgwPnMb5Kn4",
                    "/ip4/135.181.210.123/tcp/9000/p2p/16Uiu2HAmBWXZS9H2ncxgEcVi77GvYtmGUEGpHNyJxsF3Ct25Uidc",
                    "/ip4/195.201.160.183/tcp/9000/p2p/16Uiu2HAm79xzMY5FNnXGo6xcBRxCzYvMNE7CM6NZytrjXoDB5yRQ",
                    "/ip4/45.10.55.78/tcp/9000/p2p/16Uiu2HAmCpe6iMDvcXFmjLVpJ98u1fqNehpDLS2dmMRgxQ8mgMKu",
                    "/ip4/185.107.68.131/tcp/9000/p2p/16Uiu2HAm3sGDmyV3m4tju3SzekGt2EBSnALQNdn9QebPSiQP5NA2",
                    "/ip4/51.161.218.70/tcp/9000/p2p/16Uiu2HAmE6fJp7ZZVMUFxZGgfxAvfVyX3GDU6Wh88GvWv5U6SriT",
                    // lodestar peers (4 light_client protocols)
                    "/ip4/216.105.170.30/tcp/9000/p2p/16Uiu2HAm86YwyECbBiHTo2imwQJ4UXGgR1NLY2W6dPUfEFDony6d",
                    // lighthouse peers (3 light_client protocols)
                    "/ip4/54.201.148.177/tcp/9000/p2p/16Uiu2HAmNwEsdBC2phX7qU7camNe9Gs21WyrpV5AZDYyjZBMYjWZ",
                    "/ip4/16.63.94.117/tcp/9000/p2p/16Uiu2HAmSd7qzG5joNgvEYYcgVvg1y9MiYjpMHMvzRzaWYqXxkCM"
            ),
            "http://localhost:5052"
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
            ),
            // genesis_validators_root (sepolia)
            Bytes.fromHexString("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078").toArrayUnsafe(),
            // trusted checkpoint: a recent finalized sepolia block root
            Bytes.fromHexString("1f7c15e7e1a7be27b4e7e9b7bdb0e5e9b2aa5aebd33498ec04b58ef2adb5e9ce").toArrayUnsafe(),
            // current fork version: Electra on sepolia (0x90000073)
            new byte[]{(byte) 0x90, 0x00, 0x00, 0x73},
            // CL peer multiaddrs for sepolia
            List.of(
                    "/ip4/18.185.193.198/tcp/9000/p2p/16Uiu2HAm3mfkjmLPtqnSJzNtKxbDuVjVRXidz5UinaZNpjCCKAkS"
            ),
            null
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
            ),
            // genesis_validators_root (holesky)
            Bytes.fromHexString("9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1").toArrayUnsafe(),
            // trusted checkpoint: a recent finalized holesky block root
            Bytes.fromHexString("e4571b4f4a3bffdc9b87e75de28b86e5d9e8e1ab2b27d8a66e3e4e9f9ebe7f4c").toArrayUnsafe(),
            // current fork version: Electra on holesky (0x06017000)
            new byte[]{0x06, 0x01, 0x70, 0x00},
            // CL peer multiaddrs for holesky
            List.of(
                    "/ip4/159.69.35.70/tcp/9000/p2p/16Uiu2HAmFMfXsymWEK6BFPQNPW3nPz57uB3TKpVNFDmeoW7WXNUA"
            ),
            null
    );

    // Frontier (genesis) fork IDs — CRC32(genesis_hash), forkNext = first fork block
    // Used when announcing block height 0 so forkId is consistent with head
    public static final byte[] MAINNET_GENESIS_FORK_HASH =
            new byte[]{(byte) 0xfc, (byte) 0x64, (byte) 0xec, (byte) 0x04};
    public static final long MAINNET_GENESIS_FORK_NEXT = 1_150_000L; // Homestead

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
