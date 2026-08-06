package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.enr.Enr;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
            // trusted checkpoint: recent finalized mainnet block root (slot 14560000, 2026-06-15, period 1777)
            Bytes.fromHexString("58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e").toArrayUnsafe(),
            14560000L, // checkpoint slot (epoch = slot/32). Must stay in sync with the root above.
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
            // @checkpoint:sepolia:begin — managed by `./gradlew refreshSepoliaCheckpoint`
            // trusted checkpoint: recent finalized sepolia block root (slot 10851360, 2026-08-05, period 1324)
            Bytes.fromHexString("a064b99bb711d152efbc88674dcba50d4e6c1b9151dae0a2e5bfbb7c40bc7cb9").toArrayUnsafe(),
            10851360L, // checkpoint slot (epoch = slot/32). Must stay in sync with the root above.
            // @checkpoint:sepolia:end
            // current fork version: Fulu on sepolia (0x90000075) — activated at epoch 272640 (2025-10-14)
            new byte[]{(byte) 0x90, 0x00, 0x00, 0x75},
            // EIP-7892 BLOB_SCHEDULE — latest active entry on sepolia:
            // BPO2 at epoch 275712, MAX_BLOBS_PER_BLOCK=21 (2025-10-28). Folds into
            // the fork digest XOR — see activeBlobParams.
            275712L, 21L,
            // No prior-fork fallback (same rationale as mainnet: stale digests
            // wouldn't help us sync to the current head anyway).
            null,
            // CL peer multiaddrs for sepolia. First entry is the dedicated
            // myotis-serving Nimbus (docs/dedicated-sepolia-node.md): it serves
            // light_client_bootstrap / updates_by_range default-on, and being
            // first means the light client tries it before the discovered pool.
            // Its peer-id is stable only because the node pins --netkey-file;
            // Nimbus otherwise mints a new one per restart, which invalidates
            // this entry with InvalidRemotePubKey (see the doc's §5 note).
            prependLocal(
                    "/ip4/87.154.209.161/tcp/9104/p2p/16Uiu2HAkvYx58piGw1oxz34CUoeTv8nNQwTwE2cZZh4jR4wVMYy6",
                    List.of(
                            "/ip4/18.185.193.198/tcp/9000/p2p/16Uiu2HAm3mfkjmLPtqnSJzNtKxbDuVjVRXidz5UinaZNpjCCKAkS"
                    )),
            null,
            1655733600L, // sepolia beacon genesis: 2022-06-20 14:00:00 UTC
            // EL: Ethereum Foundation canonical sepolia tree (same EF signing key
            // as the mainnet tree; the resolver verifies the signature).
            List.of("enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.sepolia.ethdisco.net"),
            List.of(), // CL ENR trees — no canonical single tree (same as mainnet)
            // CL discv5 bootnodes — the canonical seed set for the sepolia beacon DHT.
            // Mirrors eth-clients/sepolia metadata/bootstrap_nodes.yaml (EF, Teku,
            // Lodestar). Seeds only: discv5's Kademlia loop expands beyond them.
            List.of(
                    // EF
                    "enr:-Ku4QDZ_rCowZFsozeWr60WwLgOfHzv1Fz2cuMvJqN5iJzLxKtVjoIURY42X_YTokMi3IGstW5v32uSYZyGUXj9Q_IECh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIpEe5iJc2VjcDI1NmsxoQNHTpFdaNSCEWiN_QqT396nb0PzcUpLe3OVtLph-AciBYN1ZHCCIy0",
                    "enr:-Ku4QHRyRwEPT7s0XLYzJ_EeeWvZTXBQb4UCGy1F_3m-YtCNTtDlGsCMr4UTgo4uR89pv11uM-xq4w6GKfKhqU31hTgCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIrFM7WJc2VjcDI1NmsxoQI4diTwChN3zAAkarf7smOHCdFb1q3DSwdiQ_Lc_FdzFIN1ZHCCIy0",
                    "enr:-Ku4QOkvvf0u5Hg4-HhY-SJmEyft77G5h3rUM8VF_e-Hag5cAma3jtmFoX4WElLAqdILCA-UWFRN1ZCDJJVuEHrFeLkDh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhJK-AWeJc2VjcDI1NmsxoQLFcT5VE_NMiIC8Ll7GypWDnQ4UEmuzD7hF_Hf4veDJwIN1ZHCCIy0",
                    "enr:-Ku4QH6tYsHKITYeHUu5kdfXgEZWI18EWk_2RtGOn1jBPlx2UlS_uF3Pm5Dx7tnjOvla_zs-wwlPgjnEOcQDWXey51QCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIs7Mc6Jc2VjcDI1NmsxoQIET4Mlv9YzhrYhX_H9D7aWMemUrvki6W4J2Qo0YmFMp4N1ZHCCIy0",
                    "enr:-Ku4QDmz-4c1InchGitsgNk4qzorWMiFUoaPJT4G0IiF8r2UaevrekND1o7fdoftNucirj7sFFTTn2-JdC2Ej0p1Mn8Ch2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhKpA-liJc2VjcDI1NmsxoQMpHP5U1DK8O_JQU6FadmWbE42qEdcGlllR8HcSkkfWq4N1ZHCCIy0",
                    // Teku
                    "enr:-Iu4QKvMF7Ne_RSQoZGvavTuZ1QA5_Pgeb0nq_hrjhU8s0UDV3KhcMXJkGwOWhsDGZL3ISjL0CTP-hfoTjZtEtCEwR4BgmlkgnY0gmlwhAOAaySJc2VjcDI1NmsxoQNta5b_bexSSwwrGW2Re24MjfMntzFd0f2SAxQtMj3ueYN0Y3CCIyiDdWRwgiMo",
                    // Lodestar
                    "enr:-KG4QJejf8KVtMeAPWFhN_P0c4efuwu1pZHELTveiXUeim6nKYcYcMIQpGxxdgT2Xp9h-M5pr9gn2NbbwEAtxzu50Y8BgmlkgnY0gmlwhEEVkQCDaXA2kCoBBPnAEJg4AAAAAAAAAAGJc2VjcDI1NmsxoQLEh_eVvk07AQABvLkTGBQTrrIOQkzouMgSBtNHIRUxOIN1ZHCCIyiEdWRwNoIjKA",
                    // remaining bootstrap_nodes.yaml entries (unattributed)
                    "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
                    "enr:-L64QC9Hhov4DhQ7mRukTOz4_jHm4DHlGL726NWH4ojH1wFgEwSin_6H95Gs6nW2fktTWbPachHJ6rUFu0iJNgA0SB2CARqHYXR0bmV0c4j__________4RldGgykDb6UBOQAABx__________-CaWSCdjSCaXCEA-2vzolzZWNwMjU2azGhA17lsUg60R776rauYMdrAz383UUgESoaHEzMkvm4K6k6iHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo"
            )
    );

    // Gnosis Chain (xDai). EL chainId 100; its own Consensus Layer (Gnosis Beacon
    // Chain) with a *different preset*: 5s slots, 16 slots/epoch, 512 epochs/period
    // — see secondsPerSlot()/slotsPerEpoch(). Note SLOTS_PER_SYNC_COMMITTEE_PERIOD is
    // still 8192 (16*512), same as mainnet (32*256). Gnosis is on Fulu, and its
    // fork digest folds the Electra-baseline blob params (no explicit BLOB_SCHEDULE
    // list) into the EIP-7892 XOR — see activeBlobParams below; verified against live
    // peers' eth2 ENR digest 0x3237dab6.
    public static final NetworkConfig GNOSIS = new NetworkConfig(
            "gnosis",
            100L,
            Bytes32.fromHexString("4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756"),
            Bytes32.fromHexString("4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756"), // genesis
            // EL fork-id hash (EIP-2124), forkNext=0. PINNED from live Gnosis peers'
            // eth Status (networkId=100 → forkId=0xcfca387c/0), the EIP-2124 fork-id for
            // the Fulu/Osaka head. Remote peers validate our fork-id, so this must match
            // the network or they disconnect with DiscSubprotocolError.
            new byte[]{(byte) 0xcf, (byte) 0xca, (byte) 0x38, (byte) 0x7c},
            0L,
            // EL discv4 bootnodes (ip:port from gnosischain/configs enodes).
            List.of(
                    new InetSocketAddress("65.109.103.148", 30303),
                    new InetSocketAddress("65.109.103.149", 30303),
                    new InetSocketAddress("141.94.97.22", 30303),
                    new InetSocketAddress("141.94.97.74", 30303),
                    new InetSocketAddress("141.94.97.84", 30303),
                    new InetSocketAddress("51.68.39.206", 30303)
            ),
            // genesis_validators_root (Gnosis Beacon Chain)
            Bytes.fromHexString("f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47").toArrayUnsafe(),
            // @checkpoint:gnosis:begin — managed by `./gradlew refreshGnosisCheckpoint`
            // trusted checkpoint: Gnosis block root one period behind head (slot 28516336, 2026-06-16, period 3480)
            // — deliberately stale so the light client must catch up to head via light_client_updates_by_range.
            Bytes.fromHexString("dc1ce049946173d38463595f907f19893e4fd956c740913fb70d94d34e07e789").toArrayUnsafe(),
            28516336L, // checkpoint slot. Must stay in sync with the root above.
            // @checkpoint:gnosis:end
            // current fork version: Fulu on Gnosis (0x06000064), active since 2026-04-14
            new byte[]{0x06, 0x00, 0x00, 0x64},
            // EIP-7892: Gnosis has no explicit BLOB_SCHEDULE, so clients fold the
            // Electra-baseline blob params (ELECTRA_FORK_EPOCH=1337856, MAX_BLOBS_PER_BLOCK_ELECTRA=2)
            // into the Fulu fork digest. Yields the live-verified eth2 digest 0x3237dab6.
            1337856L, 2L,
            new byte[]{0x05, 0x00, 0x00, 0x64}, // prior fork: Electra — accepted as a discv5 fork-digest fallback
            // CL peer multiaddrs for Gnosis: Identify-confirmed LC servers harvested
            // from a long-running desktop profile's cl-peers-gnosis.cache (2026-08-06,
            // issue #291 — a cold Gnosis pool starves catch-up because so few nodes
            // serve light-client data; these give a fresh install a serving head start).
            // Same list and ORDER as the Rust GNOSIS_STATIC_PEERS (sync.rs) — keep in
            // step. 141.94.46.9 appears on two ports deliberately (same peer id).
            List.of(
                    "/ip4/104.37.190.86/tcp/15974/p2p/16Uiu2HAky9pZH5QBGwtPgXm3A58ahKLSuuUJbZpreBMZrmksUW59",
                    "/ip4/134.65.194.144/tcp/9500/p2p/16Uiu2HAmLZasEWSgafRb5hqW5M2jSN7YcERyVQ81AeCGCFZmynsQ",
                    "/ip4/135.129.103.34/tcp/9006/p2p/16Uiu2HAmA5FYL7dQftsHktHvuVTRyPdc1sH6qcWiXaVEPM6FMyN2",
                    "/ip4/135.148.35.18/tcp/9000/p2p/16Uiu2HAm5g8koS1AgicyMZKekLoyh5rK3eBGoZJP5KUsoK5wcehs",
                    "/ip4/136.243.146.247/tcp/9000/p2p/16Uiu2HAmEFCgE5gLHQRHNMv1P1R673849q7cgH7S3WJBXTkg5698",
                    "/ip4/138.201.196.44/tcp/4001/p2p/16Uiu2HAmFXPBdWLwQQSLpXhvSAzUfRErcH1whnq3SuPE5dRmojAT",
                    "/ip4/141.94.46.9/tcp/4001/p2p/16Uiu2HAmBCpdwswdk1wdzZH4gkhPtytx1Jt8GfSjgNsgPdPHUW67",
                    "/ip4/141.94.46.9/tcp/9000/p2p/16Uiu2HAmBCpdwswdk1wdzZH4gkhPtytx1Jt8GfSjgNsgPdPHUW67",
                    "/ip4/144.76.106.139/tcp/9200/p2p/16Uiu2HAm4B91Fn21jnSPKw58R46THxhp1ZTHmTWU1TDWvNpJySRB",
                    "/ip4/144.76.118.19/tcp/9000/p2p/16Uiu2HAmEJpzjSyajPJzzrN8TnV1VaNMaEecQo1v4Mkedwb6UYwE",
                    "/ip4/144.76.163.174/tcp/9000/p2p/16Uiu2HAkxLFxkn7MbAPH17VdwEvXytqgteNAr52AaqKYuEmsw2bt",
                    "/ip4/144.76.164.21/tcp/9016/p2p/16Uiu2HAm2UAjrJax6SAtu53VykpbmPrzDDdfB3G79ypQeiXnjj3u",
                    "/ip4/144.76.196.184/tcp/13000/p2p/16Uiu2HAm6wUQPL4FYKHqmGfZQBPYbDd8GNHxNYeH5DZGLunPAw4J",
                    "/ip4/146.103.38.79/tcp/4101/p2p/16Uiu2HAmKnRLFoU3QMX3zkTZLRv5mG8FBp4qfZpGJYuT3LAErt11",
                    "/ip4/146.70.243.142/tcp/9000/p2p/16Uiu2HAm6uE18CuSgCEi5LyjxvbEXdZFQHv1HJCad3WpqerJfDrE",
                    "/ip4/148.251.181.49/tcp/9000/p2p/16Uiu2HAmAWrwxf2murYQp1tdbwKbFwqUiVofwJ3xgJP5T7BLSpRa",
                    "/ip4/148.251.184.20/tcp/15974/p2p/16Uiu2HAmQYoJ6Gn5caze4BAZXMQ5CJX5qZbdkY3o7S23vvSAPLu9",
                    "/ip4/148.251.235.60/tcp/9001/p2p/16Uiu2HAmTeAHEG2tCFgC5RmrjZcw6zGeCgnE5svqM4528R5inSjA",
                    "/ip4/148.251.237.209/tcp/9000/p2p/16Uiu2HAmSLirTFzTcPE9wsHE6UhbXXmDxFkunHDVhPtrBfuPMq5U",
                    "/ip4/148.56.243.210/tcp/9000/p2p/16Uiu2HAkyQr5e7gobYTAutAoCDR6ZKEMrgmsChUztDkw2fQTiYL4",
                    "/ip4/159.195.138.9/tcp/9000/p2p/16Uiu2HAmUimXaHiCvWhx2YuvwTkDLtca6oq1bCH85Eb6JcEYiaGi",
                    "/ip4/159.195.30.80/tcp/9100/p2p/16Uiu2HAmDMWLqML5zdVVVuptjpfKAZi1qEb784HFtrqyJZGPFL3X",
                    "/ip4/164.152.161.131/tcp/9500/p2p/16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw"
            ),
            null,
            1638993340L, // Gnosis beacon genesis: 2021-12-08 19:55:40 UTC
            List.of(), // EL ENR trees — Gnosis has no enrtree
            List.of(), // CL ENR trees — not pinned
            // CL discv5 bootnodes from gnosischain/configs bootstrap_nodes.txt
            List.of(
                    "enr:-Ly4QIAhiTHk6JdVhCdiLwT83wAolUFo5J4nI5HrF7-zJO_QEw3cmEGxC1jvqNNUN64Vu-xxqDKSM528vKRNCehZAfEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhEFtZ5SJc2VjcDI1NmsxoQJwgL5C-30E8RJmW8gCb7sfwWvvfre7wGcCeV4X1G2wJYhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
                    "enr:-Ly4QDhEjlkf8fwO5uWAadexy88GXZneTuUCIPHhv98v8ZfXMtC0S1S_8soiT0CMEgoeLe9Db01dtkFQUnA9YcnYC_8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhEFtZ5WJc2VjcDI1NmsxoQMRSho89q2GKx_l2FZhR1RmnSiQr6o_9hfXfQUuW6bjMohzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
                    "enr:-Ly4QLKgv5M2D4DYJgo6s4NG_K4zu4sk5HOLCfGCdtgoezsbfRbfGpQ4iSd31M88ec3DHA5FWVbkgIas9EaJeXia0nwBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhI1eYRaJc2VjcDI1NmsxoQLpK_A47iNBkVjka9Mde1F-Kie-R0sq97MCNKCxt2HwOIhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
                    "enr:-Ly4QF_0qvji6xqXrhQEhwJR1W9h5dXV7ZjVCN_NlosKxcgZW6emAfB_KXxEiPgKr_-CZG8CWvTiojEohG1ewF7P368Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhI1eYUqJc2VjcDI1NmsxoQIpNRUT6llrXqEbjkAodsZOyWv8fxQkyQtSvH4sg2D7n4hzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
                    "enr:-Ly4QCD5D99p36WafgTSxB6kY7D2V1ca71C49J4VWI2c8UZCCPYBvNRWiv0-HxOcbpuUdwPVhyWQCYm1yq2ZH0ukCbQBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCCS-QxAgAAZP__________gmlkgnY0gmlwhI1eYVSJc2VjcDI1NmsxoQJJMSV8iSZ8zvkgbi8cjIGEUVJeekLqT0LQha_co-siT4hzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
                    "enr:-KK4QKXJq1QOVWuJAGige4uaT8LRPQGCVRf3lH3pxjaVScMRUfFW1eiiaz8RwOAYvw33D4EX-uASGJ5QVqVCqwccxa-Bi4RldGgykCGm-DYDAABk__________-CaWSCdjSCaXCEM0QnzolzZWNwMjU2azGhAhNvrRkpuK4MWTf3WqiOXSOePL8Zc-wKVpZ9FQx_BDadg3RjcIIjKIN1ZHCCIyg",
                    "enr:-LO4QO87Rn2ejN3SZdXkx7kv8m11EZ3KWWqoIN5oXwQ7iXR9CVGd1dmSyWxOL1PGsdIqeMf66OZj4QGEJckSi6okCdWBpIdhdHRuZXRziAAAAABgAAAAhGV0aDKQPr_UhAQAAGT__________4JpZIJ2NIJpcIQj0iX1iXNlY3AyNTZrMaEDd-_eqFlWWJrUfEp8RhKT9NxdYaZoLHvsp3bbejPyOoeDdGNwgiMog3VkcIIjKA",
                    "enr:-LK4QIJUAxX9uNgW4ACkq8AixjnSTcs9sClbEtWRq9F8Uy9OEExsr4ecpBTYpxX66cMk6pUHejCSX3wZkK2pOCCHWHEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpA-v9SEBAAAZP__________gmlkgnY0gmlwhCPSnDuJc2VjcDI1NmsxoQNuaAjFE-ANkH3pbeBdPiEIwjR5kxFuKaBWxHkqFuPz5IN0Y3CCIyiDdWRwgiMo"
            )
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

    /**
     * Lower bound for what counts as a sensible peer-reported chain head on
     * this network. Used as a sanity floor when probing peers for a fresh
     * head: a peer claiming a head far below current is either far behind or
     * lying, and routing SNAP requests at its stateRoot will surface as
     * proof-verification failures rather than clean errors.
     *
     * <p>Values are chosen with comfortable margin under the actual current
     * head so the floor doesn't need to chase the chain — only catch egregious
     * outliers. {@code 0} for unknown networks disables the floor (better to
     * try than to refuse).
     */
    public long minSensibleHeadBlock() {
        return switch ((int) networkId) {
            case 1 -> 20_000_000L;        // mainnet (current ~25M, 2026-05)
            case 11155111 -> 5_000_000L;  // sepolia
            case 100 -> 40_000_000L;      // gnosis (current ~43M, 2026-06)
            default -> 0L;
        };
    }

    /**
     * Floor (in wei) for the suggested EIP-1559 priority tip / legacy gas price on this
     * network, used when recent blocks are empty or full of zero-tip txs so a suggestion is
     * still "inclusive-but-sane". This MUST track the network's fee market: a one-size floor
     * is wrong by orders of magnitude across chains. Mainnet/Sepolia run at gwei-scale tips,
     * so 0.1 gwei is sane; Gnosis runs at ~10 wei base fee with sub-gwei tips, where a 0.1 gwei
     * floor over-suggests by ~10^7× (harmless in absolute terms — fractions of a cent — but
     * wrong, and misleading to wallets/dapps that read eth_gasPrice / eth_maxPriorityFeePerGas).
     */
    public java.math.BigInteger minSuggestedTipWei() {
        return switch ((int) networkId) {
            case 1, 11155111 -> java.math.BigInteger.valueOf(100_000_000L); // 0.1 gwei
            case 100 -> java.math.BigInteger.valueOf(1_000_000L);           // gnosis: 0.001 gwei
            default -> java.math.BigInteger.valueOf(1_000_000L);            // cheap-chain-safe default
        };
    }

    /**
     * Full EL enodes (enode:// with node pubkey) for DIRECT RLPx dialing — the discovery
     * seed for chains that have NO EIP-1459 EL enrtree (e.g. Gnosis). Unlike {@link
     * #bootnodes()} (bare ip:port, usable only as a discv4 ping target), these carry the
     * secp256k1 pubkey, so a NAT'd / mobile host can reach them over RLPx directly without
     * bootstrapping discv4 UDP — the same role the DNS-resolved enrtree enodes play on
     * networks that publish one. Empty for networks whose {@code elEnrTreeUrls} already
     * supply a refreshing pool (mainnet, sepolia).
     *
     * <p>Source: gnosischain / Nethermind {@code gnosis.json} chainspec {@code nodes} list.
     */
    public List<String> elBootEnodes() {
        return switch ((int) networkId) {
            case 100 -> GNOSIS_EL_ENODES;
            case 11155111 -> SEPOLIA_EL_ENODES;
            default -> List.of();
        };
    }

    /** Sepolia EL enodes: the dedicated myotis-serving node (docs/dedicated-sepolia-node.md).
     *
     *  <p>Unlike Gnosis's entries this is NOT a discovery gap-filler — sepolia has an
     *  enrtree. It is pinned because discovery is a lottery we lose exactly when it
     *  matters: on a saturated testnet most peers answer {@code DiscTooManyPeers}, and
     *  this node runs the name-based cap bypass so a myotis wallet is admitted even when
     *  it is full. Direct-dialing it removes the wait for discovery to surface it.
     *
     *  <p>Operational caveat: the key is stable (persisted nodekey), the IP is a
     *  residential address — if it rotates this entry goes stale and discovery carries
     *  the load until it is refreshed. */
    private static final List<String> SEPOLIA_EL_ENODES = List.of(
            "enode://cfd3572bd7691fe03baf52106b873e01d9b5dca1714a74b316cb94151127dfd20adae3be559e3e6b44b78a5af1ed6f92ecc8676a2555fc7cdb2d29a0c37e1b2c@87.154.209.161:30405"
    );

    /** Gnosis EL enodes (chainspec {@code nodes}) — Gnosis publishes no EL enrtree, so these
     *  are the direct-dial discovery seed (see {@link #elBootEnodes()}). */
    private static final List<String> GNOSIS_EL_ENODES = List.of(
            "enode://6765fff89db92aa8d923e28c438af626c8ae95a43093cdccbd6f550a7b6ce6ab5d1a3dc60dd79af3e6d2c2e6731bae629f0e54446a0d9da408c4eca7ebcd8485@3.75.159.31:30303",
            "enode://9a7c98e8ee8cdd3199db68092b48868847d4743a471b26afc2ff878bafaa829ed43ee405f9aff58ae13fce53b898f7c2e3c30cb80af8eb111682c3c13f686dbb@18.198.130.54:30303",
            "enode://2c4307831914c237801993eac4f9596d8b2f78e1e76830419b64cb23f0933e52cb1e2bb3009cb4af76454bb5bc296135b36869fd6c13e2c2e536a0780e60fe82@3.64.242.196:30303",
            "enode://074f68e1a7df5b0859314ff721d55b59d9690e93249c941660609a29b302f02864df4f93ee48884f7ede57dc7f7646379d017a43c9745e34baff049749896b50@3.126.169.151:30303",
            "enode://d239697375d7586c7ea1de790401c310b0b1d389326849fa3b7c7005833c7a6b9020e49dfb3b61abfa39135237ffc4ff219cb84ca7653069e8548497527aa432@107.22.4.120:30303",
            "enode://d5852bf415d89b756faa809f4ff3f8beb661dc7d60cfb4a5542f9a5fcdf41e1ed0708a210db64b8c7ca32426e04ef0a50da58974124fdf562a8510314d11e28c@3.26.206.142:30303",
            "enode://01d372392bb22dd8a91f8b10b6bbb8d80d2dbe98d695801e0df9e4bd4825781df84bba88361f24d1b6580a61313f64e6cec82e8d842ad5f1b3d7cf8d6d132da7@15.152.45.82:30303",
            "enode://aee88e803b8e54925081957965b2527961cd90f4d6d14664884580b429da44729678a1258a8b49a42d1582c9c7c5ded05733622f7ab442ad9c6f655545a5ecdd@54.207.220.169:30303",
            "enode://fb14d72321ee823fcf21e163091849ee42e0f6ac0cddc737d79e324b0a734c4fc51823ef0a96b749c954483c25e8d2e534d1d5fc2619ea22d58671aff96f5188@65.109.103.148:30303",
            "enode://40f40acd78004650cce57aa302de9acbf54becf91b609da93596a18979bb203ba79fcbee5c2e637407b91be23ce72f0cc13dfa38d13e657005ce842eafb6b172@65.109.103.149:30303",
            "enode://9e50857aa48a7a31bc7b46957e8ced0ef69a7165d3199bea924cb6d02b81f1f35bd8e29d21a54f4a331316bf09bb92716772ea76d3ef75ce027699eccfa14fad@141.94.97.22:30303",
            "enode://96dc133ce3aeb5d9430f1dce1d77a36418c8789b443ae0445f06f73c6b363f5b35c019086700a098c3e6e54974d64f37e97d72a5c711d1eae34dc06e3e00eed5@141.94.97.74:30303",
            "enode://516cbfbe9bbf26b6395ed68b24e383401fc33e7fe96b9d235ebca86c9f812fde8d33a7dbebc0fb5595459d2c5cc6381595d96507af89e6b48b5bdd0ebf8af0c0@141.94.97.84:30303",
            "enode://fc86a93545c56322dd861180b76632b9baeb65af8f304269b489b4623ae060847569c3c3c10c4b39baf221a2cdefea66efabce061a542cdcda374cbba45aa3d4@51.68.39.206:30303",
            "enode://0e6dd3815a627893515465130c1e95aa73b18fe2f723b2467f3abf94df9be036f27595f301b5e78750ad128e59265f980c92033ae903330c0460c40ae088c04a@35.210.37.245:30303",
            "enode://b72d6233d50bef7b31c09f3ea39459257520178f985a872bbaa4e371ed619455b7671053ffe985af1b5fb3270606e2a49e4e67084debd75e6c9b93e227c5b01c@35.210.156.59:30303"
    );

    /** Look up a network by name (case-insensitive). */
    public static NetworkConfig byName(String name) {
        return switch (name.toLowerCase(Locale.ROOT)) {
            case "mainnet" -> MAINNET;
            case "sepolia" -> SEPOLIA;
            case "gnosis", "gbc", "xdai" -> GNOSIS;
            // holesky retired: the EF shut it down in Oct 2025 (no peers, no
            // checkpoint servers). Use gnosis, or sepolia for an Ethereum testnet.
            default -> throw new IllegalArgumentException(
                    "Unknown network: " + name + ". Supported: mainnet, sepolia, gnosis");
        };
    }

    /**
     * All supported networks, in display order. Drives multi-network UIs and the
     * daemon's registry so adding a network here is the single point of expansion
     * (the static instance + a {@link #byName} case + this list).
     */
    public static List<NetworkConfig> allNetworks() {
        return List.of(MAINNET, GNOSIS, SEPOLIA);
    }

    /**
     * Beacon-chain slot time in seconds. Mainnet and the mainnet-preset testnets
     * use 12; Gnosis Beacon Chain uses 5. Used for wall-clock sync-committee period
     * estimation in the light client.
     */
    public int secondsPerSlot() {
        return networkId == 100 ? 5 : 12;
    }

    /**
     * Beacon-chain slots per epoch. Mainnet preset uses 32; Gnosis uses 16. Used for
     * the Status {@code finalized_epoch} and epoch display. (Slots per sync-committee
     * period is 8192 on both presets, so that helper is shared.)
     */
    public int slotsPerEpoch() {
        return networkId == 100 ? 16 : 32;
    }

    // -------------------------------------------------------------------------
    // Per-network default ports. Pinned per network (not index-allocated) so a
    // wallet pointed at a given RPC port always reaches the same chain regardless
    // of which other networks are enabled, and so adding a network carries its own
    // ports. Distinct across networks so several can run in one process without
    // colliding. Mainnet keeps the historical 30303/9000/8545 (proven path).
    // -------------------------------------------------------------------------

    /** RLPx TCP + discv4 UDP port. */
    public int defaultElPort() {
        return switch ((int) networkId) {
            case 100 -> 30304;       // gnosis
            case 11155111 -> 30305;  // sepolia
            default -> 30303;        // mainnet (and unknown)
        };
    }

    /** Consensus-layer discv5 UDP port. */
    public int defaultDiscv5Port() {
        return switch ((int) networkId) {
            case 100 -> 9001;       // gnosis
            case 11155111 -> 9002;  // sepolia
            default -> 9000;        // mainnet (and unknown)
        };
    }

    /** Verified JSON-RPC HTTP port. */
    public int defaultRpcPort() {
        return switch ((int) networkId) {
            case 100 -> 8546;       // gnosis
            case 11155111 -> 8547;  // sepolia
            default -> 8545;        // mainnet (and unknown)
        };
    }

    // -------------------------------------------------------------------------

    /**
     * Whether ENS name resolution is available on this chain. ENS is deployed only on
     * Ethereum mainnet and Sepolia — {@link io.myotis.ens.EnsResolver#forChainId} pins
     * the registry + UniversalResolver only for chainId 1 / 11155111 (holesky is retired)
     * and throws for everything else (e.g. Gnosis 100, which has no canonical ENS). UIs
     * gate the ENS query path on this; plain address balance/account queries work on every
     * chain regardless.
     */
    public boolean hasEns() {
        return networkId == 1 || networkId == 11155111;
    }

    /** Human-readable chain name for UI labels (the {@link #name} is the lowercase id). */
    public String displayName() {
        return switch ((int) networkId) {
            case 100 -> "Gnosis Chain";
            case 11155111 -> "Sepolia";
            default -> "Ethereum Mainnet";
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
