package com.jaeckel.ethp2p.networking;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Self-consistency checks for the Gnosis Chain network configuration. */
class NetworkConfigGnosisTest {

    private static final NetworkConfig G = NetworkConfig.GNOSIS;

    @Test
    void identity() {
        assertEquals("gnosis", G.name());
        assertEquals(100L, G.networkId());
        assertEquals(
                Bytes32.fromHexString("4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756"),
                G.genesisHash());
        // genesis is honest (== bestBlockHash) like the other configs
        assertEquals(G.genesisHash(), G.bestBlockHash());
    }

    @Test
    void byNameResolvesAliasesCaseInsensitively() {
        assertSame(G, NetworkConfig.byName("gnosis"));
        assertSame(G, NetworkConfig.byName("GNOSIS"));
        assertSame(G, NetworkConfig.byName("gbc"));
        assertSame(G, NetworkConfig.byName("xdai"));
    }

    @Test
    void holeskyIsRetired() {
        // Holesky was shut down by the EF (Oct 2025); it must no longer resolve.
        assertThrows(IllegalArgumentException.class, () -> NetworkConfig.byName("holesky"));
    }

    @Test
    void beaconPresetIsGnosisNotMainnet() {
        // The whole point of the change: Gnosis uses 5s slots / 16 slots-per-epoch.
        assertEquals(5, G.secondsPerSlot());
        assertEquals(16, G.slotsPerEpoch());
        // Mainnet preset unchanged.
        assertEquals(12, NetworkConfig.MAINNET.secondsPerSlot());
        assertEquals(32, NetworkConfig.MAINNET.slotsPerEpoch());
    }

    @Test
    void consensusFieldsAreWellFormed() {
        assertEquals(32, G.genesisValidatorsRoot().length, "GVR must be 32 bytes");
        assertEquals(
                Bytes.fromHexString("f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"),
                Bytes.wrap(G.genesisValidatorsRoot()));
        assertEquals(4, G.currentForkVersion().length, "fork version must be 4 bytes");
        assertArrayEquals(new byte[]{0x06, 0x00, 0x00, 0x64}, G.currentForkVersion(), "Fulu fork version");
        assertTrue(G.acceptPriorForkDigest());
        assertNotNull(G.priorForkVersion());
        assertArrayEquals(new byte[]{0x05, 0x00, 0x00, 0x64}, G.priorForkVersion(), "Electra prior fork version");
        // The full schedule is pinned in NetworkConfigForkScheduleTest.
        assertEquals(16, G.forkSchedule().slotsPerEpoch(), "schedule carries the gnosis geometry");
        assertEquals(32, G.checkpointRoot().length, "checkpoint root must be 32 bytes");
        assertTrue(G.checkpointSlot() > 0, "checkpoint slot must be set");
        // EIP-7892: Gnosis folds the Electra-baseline blob params into the Fulu digest.
        assertEquals(1337856L, G.activeBlobParamsEpoch());
        assertEquals(2L, G.activeBlobParamsMaxBlobs());
        assertEquals(1638993340L, G.clGenesisTime());
    }

    @Test
    void forkDigestMatchesLivePeers() {
        // Fulu digest = base(0x06000064) XOR sha256(le64(1337856) || le64(2))[:4].
        // Pinned against the eth2 fork_digest real Gnosis peers advertise on discv5.
        assertEquals("3237dab6", HexFormat.of().formatHex(G.currentForkDigest()),
                "Gnosis Fulu fork_digest (EIP-7892 mix-in)");
        // discv5 acceptance must include current (Fulu) + prior (Electra, pre-7892 base) digests.
        var accepted = G.acceptedForkDigests();
        assertEquals(2, accepted.size());
        assertEquals("3237dab6", HexFormat.of().formatHex(accepted.get(0)));
        assertEquals("7d5aab40", HexFormat.of().formatHex(accepted.get(1)));
    }

    @Test
    void discoveryPeersArePresent() {
        assertFalse(G.bootnodes().isEmpty(), "EL discv4 bootnodes must be present");
        assertEquals(9, G.clDiscv5Bootnodes().size(), "CL discv5 bootnodes seed");
        for (String enr : G.clDiscv5Bootnodes()) {
            assertTrue(enr.startsWith("enr:"), "CL bootnode must be an ENR: " + enr);
        }
    }

    @Test
    void minSensibleHeadIsSet() {
        assertEquals(40_000_000L, G.minSensibleHeadBlock());
    }

    @Test
    void gnosisHasNoEns() {
        // ENS is mainnet/Sepolia-only; Gnosis has no canonical registry (EnsResolver
        // .forChainId throws for chainId 100), so the UI must not offer ENS lookups here.
        assertFalse(G.hasEns(), "Gnosis must not advertise ENS");
        assertTrue(NetworkConfig.MAINNET.hasEns(), "mainnet has ENS");
        assertTrue(NetworkConfig.SEPOLIA.hasEns(), "sepolia has ENS");
        assertEquals("Gnosis Chain", G.displayName());
        assertEquals("Ethereum Mainnet", NetworkConfig.MAINNET.displayName());
    }

    @Test
    void elBootEnodesAreDialableWhereShipped() {
        // Gnosis publishes no EL enrtree, so it ships full enode://<pubkey>@host:port seeds
        // for direct RLPx dialing. Sepolia HAS an enrtree but pins one entry anyway: the
        // dedicated myotis-serving node, which admits wallets past its peer cap
        // (docs/dedicated-sepolia-node.md) — direct-dialing it beats waiting for discovery
        // to surface it on a saturated testnet. Mainnet ships none.
        assertTrue(NetworkConfig.MAINNET.elBootEnodes().isEmpty(), "mainnet has an enrtree");

        assertEquals(16, G.elBootEnodes().size(), "Gnosis must ship static EL enode seeds");
        assertEquals(1, NetworkConfig.SEPOLIA.elBootEnodes().size(),
                "sepolia pins the dedicated serving node");

        for (NetworkConfig net : List.of(G, NetworkConfig.SEPOLIA)) {
            for (String enode : net.elBootEnodes()) {
                // Parse exactly as ChainStack does — proves each entry yields a valid
                // pubkey + addr.
                assertTrue(enode.startsWith("enode://"), enode);
                String b = enode.substring(enode.indexOf("//") + 2);
                int at = b.indexOf('@');
                assertTrue(at > 0, "missing @ in " + enode);
                // 64-byte uncompressed secp256k1 pubkey (128 hex chars), must decode to a key.
                assertEquals(128, at, "pubkey must be 128 hex chars in " + enode);
                assertNotNull(org.apache.tuweni.crypto.SECP256K1.PublicKey.fromBytes(
                        Bytes.fromHexString(b.substring(0, at))), enode);
                String hostPort = b.substring(at + 1);
                int colon = hostPort.lastIndexOf(':');
                assertTrue(colon > 0, "missing host:port in " + enode);
                assertTrue(Integer.parseInt(hostPort.substring(colon + 1)) > 0, enode);
            }
        }
    }

    @Test
    void gnosisPinsHarvestedLcServers() {
        // LC servers harvested from a long-running desktop cache (issue #291),
        // pruned 2026-09-13 to the ones a census found serving — the per-entry
        // evidence is in the Rust GNOSIS_STATIC_PEERS. The FULL list, order and
        // addresses: the Rust twin (sync.rs gnosis_config_matches_networkconfig_java)
        // pins the same strings, so a one-sided edit fails on whichever side
        // diverges; this used to pin only the count and three positions.
        // roost FIRST, by the netcup relay literal (188.68.32.16, static VPS in
        // front of zbox).
        List<String> cl = G.clPeerMultiaddrs();
        assertEquals(List.of(
                "/ip4/188.68.32.16/tcp/9108/p2p/16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh",
                "/ip4/134.65.194.144/tcp/9500/p2p/16Uiu2HAmLZasEWSgafRb5hqW5M2jSN7YcERyVQ81AeCGCFZmynsQ",
                "/ip4/144.76.118.19/tcp/9000/p2p/16Uiu2HAmEJpzjSyajPJzzrN8TnV1VaNMaEecQo1v4Mkedwb6UYwE",
                "/ip4/144.76.163.174/tcp/9000/p2p/16Uiu2HAkxLFxkn7MbAPH17VdwEvXytqgteNAr52AaqKYuEmsw2bt",
                "/ip4/148.251.181.49/tcp/9000/p2p/16Uiu2HAmAWrwxf2murYQp1tdbwKbFwqUiVofwJ3xgJP5T7BLSpRa",
                "/ip4/148.251.235.60/tcp/9001/p2p/16Uiu2HAmTeAHEG2tCFgC5RmrjZcw6zGeCgnE5svqM4528R5inSjA",
                "/ip4/159.195.138.9/tcp/9000/p2p/16Uiu2HAmUimXaHiCvWhx2YuvwTkDLtca6oq1bCH85Eb6JcEYiaGi",
                "/ip4/164.152.161.131/tcp/9500/p2p/16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw"),
                cl,
                "same list, order AND addresses as the Rust GNOSIS_STATIC_PEERS; roost first");
        assertEquals(cl.size(), cl.stream().map(a -> a.substring(a.lastIndexOf('/') + 1)).distinct().count(),
                "one address per peer id");
        for (String addr : cl) {
            assertTrue(addr.matches("/(ip4/\\d+\\.\\d+\\.\\d+\\.\\d+|dns4/[\\w.-]+)/tcp/\\d+/p2p/16Uiu2HA\\S+"), addr);
        }
    }

    @Test
    void sepoliaPinsTheDedicatedServingNodeOnBothLayers() {
        // Both halves of the dedicated pair are pinned so a wallet reaches them without
        // waiting on discovery. The CL entry must come FIRST: the light client walks
        // clPeerMultiaddrs in order, and this is the peer we know serves bootstraps.
        String enode = NetworkConfig.SEPOLIA.elBootEnodes().get(0);
        assertTrue(enode.endsWith("@188.68.32.16:30405"), enode);

        // roost, the dedicated light-client server, is tried first — that is the
        // point of having it. The census-verified public servers follow, so a
        // roost fault degrades to working peers rather than to dead pins.
        // The full list, in order — the Rust twin
        // (sepolia_config_matches_networkconfig_java) pins the same strings.
        assertEquals(List.of(
                        "/ip4/188.68.32.16/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5",
                        "/ip4/65.109.144.95/tcp/9000/p2p/16Uiu2HAkwKbnJCnfFsNGjGd5TURbXyNBdTWoVZjw8jqiCEf47gc2",
                        "/ip4/138.201.192.180/tcp/9000/p2p/16Uiu2HAmNHPaVrDFi7zVnEd9vhSHy9e4a5eF5a3aBxNXPPAucWbE",
                        "/ip4/198.13.138.237/tcp/9000/p2p/16Uiu2HAmMb2mLN12B5vnJGv2LMuXxKsAiKQ8yTdy5gSJY1zKgE5f"),
                NetworkConfig.SEPOLIA.clPeerMultiaddrs(),
                "roost first, then the census-verified public servers, same list as the Rust twin");
    }

    @Test
    void mainnetPinsRoostFirst() {
        // The Rust twin (sync.rs mainnet_config_matches_networkconfig_java)
        // asserts index 0 and the list length; without this, POSITION was pinned
        // on one side only. That asymmetry is the failure worth catching: both
        // engines would still "contain" roost while disagreeing about which peer
        // the light client actually tries first, and only one of them would be
        // reaching the dedicated server.
        //
        // It also matters more here than in Rust: addPeer inserts discovered
        // peers at Math.min(1, size()), so presence-anywhere is a weak claim on
        // this side.
        // The FULL list, order and addresses — the Rust twin
        // (mainnet_config_matches_networkconfig_java) pins the same strings, so
        // an address typo or one-sided IP rotation fails a test on WHICHEVER
        // side diverges; count + element 0 alone let every later element drift
        // machine-unchecked (PR #411 review).
        List<String> cl = NetworkConfig.MAINNET.clPeerMultiaddrs();
        assertEquals(List.of(
                "/ip4/188.68.32.16/tcp/9109/p2p/16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
                "/ip4/57.129.130.18/tcp/9000/p2p/16Uiu2HAkwmBd7zSRAiBkGar6ghHYfKCKTpGbGL1igrD6mC4W99T9",
                "/ip4/84.112.35.112/tcp/9000/p2p/16Uiu2HAm6YkLaGLMH1Q9caGi4A2WctHPhENumfQMJXVCMVpc7GQY",
                "/ip4/91.189.182.90/tcp/9000/p2p/16Uiu2HAmJJUAs17wxW1i4HM5Fce1zYPCvvavxsYorWr4EQVx1Ui8",
                "/ip4/54.201.148.177/tcp/9000/p2p/16Uiu2HAmNwEsdBC2phX7qU7camNe9Gs21WyrpV5AZDYyjZBMYjWZ"),
                cl,
                "same list, order AND addresses as the Rust MAINNET_STATIC_PEERS; "
                        + "roost mainnet must be the first CL peer tried");
    }
}
