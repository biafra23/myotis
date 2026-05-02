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
        long checkpointSlot,            // slot of the trusted checkpoint. Used to populate
                                        // Status.finalized_epoch before bootstrap so Lighthouse
                                        // doesn't goodbye us with IrrelevantNetwork(code=2).
        byte[] currentForkVersion,      // 4 bytes: current fork version for signing domain
        long activeBlobParamsEpoch,     // EIP-7892: epoch of the currently-active BPO fork, or 0 if none.
                                        // Folded into compute_fork_digest via the XOR formula so our digest
                                        // tracks the network's post-Fulu BPO activations.
        long activeBlobParamsMaxBlobs,  // EIP-7892: MAX_BLOBS_PER_BLOCK for the active BPO entry (paired
                                        // with activeBlobParamsEpoch). Ignored when activeBlobParamsEpoch == 0.
        byte[] priorForkVersion,        // 4 bytes: immediately preceding fork (nullable). Accepted as
                                        // a discv5 fork_digest fallback so a configured "current" fork
                                        // that hasn't yet activated on the network doesn't filter every
                                        // peer out. Null skips the fallback (testnets, genesis fork).
        List<String> clPeerMultiaddrs,  // libp2p multiaddrs of known CL peers
        String beaconApiUrl,            // HTTP API URL for local beacon node (e.g. http://172.17.0.1:5052)
        long clGenesisTime,             // beacon chain genesis time (seconds since epoch) for wall-clock period estimation
        List<String> elEnrTreeUrls,     // EIP-1459 enrtree:// URLs for execution-layer discv4 peers
        List<String> clEnrTreeUrls,     // EIP-1459 enrtree:// URLs for consensus-layer libp2p peers
        List<String> clDiscv5Bootnodes  // ENR strings of CL discv5 bootnodes (seed for DHT discovery)
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
            // @checkpoint:mainnet:begin — managed by `./gradlew refreshMainnetCheckpoint`
            // trusted checkpoint: recent finalized mainnet block root (slot 14158720, 2026-04-20, period 1728)
            Bytes.fromHexString("611c852c9c52812d1a8701d06c230617159b69d33b344704fb524558ee79ff5d").toArrayUnsafe(),
            14158720L, // checkpoint slot (epoch = slot/32). Must stay in sync with the root above.
            // @checkpoint:mainnet:end
            // current fork version: Fulu (0x06000000) — activated at slot 13164544 (2025-12-03)
            new byte[]{0x06, 0x00, 0x00, 0x00},
            // EIP-7892 BLOB_SCHEDULE — latest active entry on mainnet.
            // BPO2 (Fusaka) at epoch 419072, MAX_BLOBS_PER_BLOCK=21, 2026-01-07.
            // Feeds into compute_fork_digest (XOR of base_digest with sha256 of
            // (epoch_le || max_blobs_le)).
            419072L, 21L,
            // No prior-fork fallback: mainnet is on Fulu; peers still advertising
            // an older digest are either stale ENRs or unupgraded nodes — matching
            // them wouldn't help us sync to the current head anyway.
            null,
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
            "http://localhost:5052",
            1606824023L, // mainnet beacon genesis: 2020-12-01 12:00:23 UTC
            // EIP-1459 ENR tree URLs — DNS-seeded discv4 bootnodes (EL) and libp2p peers (CL).
            // EL: Ethereum Foundation canonical tree used by all EL clients.
            List.of("enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"),
            // CL: no canonical single tree; each CL client team (Lighthouse, Lodestar, Nimbus, Teku)
            // publishes their own. Empty for now — add entries once a tree URL is pinned and verified.
            List.of(),
            // CL discv5 bootnodes — the canonical seed set for the consensus-layer DHT.
            // Mirrors sigp/lighthouse .../mainnet/bootstrap_nodes.yaml (Teku, Prylabs, Sigma
            // Prime, EF, Nimbus, Lodestar). These are hardened, long-running ENRs; discv5
            // uses them only to seed the routing table, then the Kademlia lookup loop
            // expands beyond them.
            List.of(
                    // Teku
                    "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
                    "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",
                    // Prylabs
                    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
                    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
                    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
                    // Sigma Prime (Lighthouse)
                    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
                    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
                    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
                    "enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",
                    // Ethereum Foundation
                    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
                    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
                    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
                    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
                    // Nimbus
                    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
                    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
                    // Lodestar
                    "enr:-IS4QPi-onjNsT5xAIAenhCGTDl4z-4UOR25Uq-3TmG4V3kwB9ljLTb_Kp1wdjHNj-H8VVLRBSSWVZo3GUe3z6k0E-IBgmlkgnY0gmlwhKB3_qGJc2VjcDI1NmsxoQMvAfgB4cJXvvXeM6WbCG86CstbSxbQBSGx31FAwVtOTYN1ZHCCIyg",
                    "enr:-KG4QPUf8-g_jU-KrwzG42AGt0wWM1BTnQxgZXlvCEIfTQ5hSmptkmgmMbRkpOqv6kzb33SlhPHJp7x4rLWWiVq5lSECgmlkgnY0gmlwhFPlR9KDaXA2kCoGxcAJAAAVAAAAAAAAABCJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA"
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
            ),
            // genesis_validators_root (sepolia)
            Bytes.fromHexString("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078").toArrayUnsafe(),
            // trusted checkpoint: a recent finalized sepolia block root
            Bytes.fromHexString("1f7c15e7e1a7be27b4e7e9b7bdb0e5e9b2aa5aebd33498ec04b58ef2adb5e9ce").toArrayUnsafe(),
            0L, // checkpoint slot — unknown for sepolia, use 0 (spec-default). refresh job should fill this.
            // current fork version: Electra on sepolia (0x90000073)
            new byte[]{(byte) 0x90, 0x00, 0x00, 0x73},
            0L, 0L, // no BPO active on sepolia
            null, // prior fork version not pinned for sepolia
            // CL peer multiaddrs for sepolia
            List.of(
                    "/ip4/18.185.193.198/tcp/9000/p2p/16Uiu2HAm3mfkjmLPtqnSJzNtKxbDuVjVRXidz5UinaZNpjCCKAkS"
            ),
            null,
            1655733600L, // sepolia beacon genesis: 2022-06-20 14:00:00 UTC
            List.of(), // EL ENR trees — not pinned
            List.of(), // CL ENR trees — not pinned
            List.of()  // CL discv5 bootnodes — not pinned for sepolia this PR
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
            0L, // checkpoint slot — unknown for holesky, use 0 (spec-default). refresh job should fill this.
            // current fork version: Electra on holesky (0x06017000)
            new byte[]{0x06, 0x01, 0x70, 0x00},
            0L, 0L, // no BPO active on holesky
            null, // prior fork version not pinned for holesky
            // CL peer multiaddrs for holesky
            List.of(
                    "/ip4/159.69.35.70/tcp/9000/p2p/16Uiu2HAmFMfXsymWEK6BFPQNPW3nPz57uB3TKpVNFDmeoW7WXNUA"
            ),
            null,
            1695902400L, // holesky beacon genesis: 2023-09-28 12:00:00 UTC
            List.of(), // EL ENR trees — not pinned
            List.of(), // CL ENR trees — not pinned
            List.of()  // CL discv5 bootnodes — not pinned for holesky this PR
    );

    // Frontier (genesis) fork IDs — CRC32(genesis_hash), forkNext = first fork block
    // Used when announcing block height 0 so forkId is consistent with head
    public static final byte[] MAINNET_GENESIS_FORK_HASH =
            new byte[]{(byte) 0xfc, (byte) 0x64, (byte) 0xec, (byte) 0x04};
    public static final long MAINNET_GENESIS_FORK_NEXT = 1_150_000L; // Homestead

    /**
     * Compute {@code fork_digest} per the CL spec for an arbitrary fork version:
     * {@code fork_digest = SHA256( (fork_version || 28 zero bytes) || genesis_validators_root )[:4]}.
     *
     * <p>Used to filter discv5-advertised ENRs down to peers on the same fork
     * as us. The padding to 32 bytes is the SSZ chunk size; the whole thing
     * is really {@code hash_tree_root(ForkData(fork_version, genesis_validators_root))}
     * but for a 2-field container with leaf sizes &le; 32 bytes that collapses
     * to a single SHA-256 over the concatenated, chunked leaves.
     */
    public byte[] forkDigestFor(byte[] forkVersion) {
        byte[] genesisValidatorsRoot = genesisValidatorsRoot();
        if (forkVersion == null || forkVersion.length != 4)
            throw new IllegalArgumentException("forkVersion must be 4 bytes");
        if (genesisValidatorsRoot == null || genesisValidatorsRoot.length != 32)
            throw new IllegalArgumentException("genesisValidatorsRoot must be 32 bytes");
        try {
            byte[] buf = new byte[64];
            System.arraycopy(forkVersion, 0, buf, 0, 4);
            // bytes 4..32 are zeros (SSZ padding for Bytes4 leaf)
            System.arraycopy(genesisValidatorsRoot, 0, buf, 32, 32);
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(buf);
            byte[] digest = new byte[4];
            System.arraycopy(hash, 0, digest, 0, 4);
            return digest;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 missing", e);
        }
    }

    /**
     * Compute the current 4-byte fork digest per the Fulu / EIP-7892 spec:
     * <pre>
     *   base_digest = compute_fork_data_root(fork_version, gvr)  // 32 bytes
     *   bp_hash     = sha256(u64_le(epoch) || u64_le(max_blobs)) // 32 bytes
     *   fork_digest = (base_digest XOR bp_hash)[0..4]
     * </pre>
     * When no BPO is active ({@code activeBlobParamsEpoch == 0}), falls back
     * to the pre-EIP-7892 formula {@code base_digest[0..4]} that testnets
     * still use. See consensus-specs/specs/fulu/beacon-chain.md.
     */
    public byte[] currentForkDigest() {
        byte[] base = forkDigestFor32(currentForkVersion());
        if (activeBlobParamsEpoch == 0) {
            byte[] out = new byte[4];
            System.arraycopy(base, 0, out, 0, 4);
            return out;
        }
        byte[] bpInput = new byte[16];
        // SSZ uint64 is little-endian
        longToLeBytes(activeBlobParamsEpoch, bpInput, 0);
        longToLeBytes(activeBlobParamsMaxBlobs, bpInput, 8);
        byte[] bpHash;
        try {
            bpHash = java.security.MessageDigest.getInstance("SHA-256").digest(bpInput);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) out[i] = (byte) (base[i] ^ bpHash[i]);
        return out;
    }

    /** Same as {@link #forkDigestFor} but returns the full 32-byte fork_data_root. */
    private byte[] forkDigestFor32(byte[] forkVersion) {
        byte[] genesisValidatorsRoot = genesisValidatorsRoot();
        try {
            byte[] buf = new byte[64];
            System.arraycopy(forkVersion, 0, buf, 0, 4);
            System.arraycopy(genesisValidatorsRoot, 0, buf, 32, 32);
            return java.security.MessageDigest.getInstance("SHA-256").digest(buf);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private static void longToLeBytes(long v, byte[] out, int offset) {
        for (int i = 0; i < 8; i++) out[offset + i] = (byte) (v >>> (8 * i));
    }

    /**
     * Fork digests to accept when filtering discv5 ENRs — current first, then
     * the prior fork if configured. Matching the prior digest keeps discv5
     * useful during the period around a fork activation (our {@code
     * currentForkVersion} may be ahead of — or behind — the network's actual
     * state without a config bump) instead of rejecting every peer.
     */
    public List<byte[]> acceptedForkDigests() {
        List<byte[]> digests = new ArrayList<>(2);
        digests.add(currentForkDigest());
        if (priorForkVersion != null) {
            digests.add(forkDigestFor(priorForkVersion));
        }
        return List.copyOf(digests);
    }

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
