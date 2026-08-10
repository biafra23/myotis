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
        assertNotNull(G.priorForkVersion());
        assertArrayEquals(new byte[]{0x05, 0x00, 0x00, 0x64}, G.priorForkVersion(), "Electra prior fork version");
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
        // 22 Identify-confirmed LC servers from a long-running desktop cache
        // (issue #291) — same list and ORDER as the Rust GNOSIS_STATIC_PEERS
        // (sync.rs gnosis_config_matches_networkconfig_java pins the twin side).
        List<String> cl = G.clPeerMultiaddrs();
        assertEquals(23, cl.size(), "22 harvested peers + roost, pinned by NAME only");
        // roost FIRST, and by NAME — no literal behind it. A dynamic address is
        // absorbed by DNS instead of by a second entry.
        assertEquals("/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9108/p2p/16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh", cl.get(0));
        // The harvested list is unchanged, just shifted by the one roost entry.
        assertEquals("/ip4/104.37.190.86/tcp/15974/p2p/"
                + "16Uiu2HAky9pZH5QBGwtPgXm3A58ahKLSuuUJbZpreBMZrmksUW59", cl.get(1));
        assertEquals("/ip4/164.152.161.131/tcp/9500/p2p/"
                + "16Uiu2HAmUNdWoUb47hazEeMaZF8nSRac13QxZoE9hE5X6EVN2cnw", cl.get(22));
        assertEquals(23, cl.stream().distinct().count());
        assertEquals(23, cl.stream().map(a -> a.substring(a.lastIndexOf('/') + 1)).distinct().count(),
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
        assertTrue(enode.endsWith("@87.154.209.161:30405"), enode);

        // roost, the dedicated light-client server, is tried first — that is the
        // point of having it. The dedicated Nimbus stays behind it as fallback,
        // so a roost fault degrades to the previous behaviour.
        String cl = NetworkConfig.SEPOLIA.clPeerMultiaddrs().get(0);
        assertEquals("/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5", cl,
                "roost must be the first CL peer tried");
        // POSITION, not presence: the Rust twin asserts index 1, and index is
        // load-bearing on this side in particular — addPeer inserts every
        // discovered peer at Math.min(1, size()), i.e. exactly the slot the
        // Nimbus occupies, so "somewhere in the list" is a weaker guarantee here
        // than anywhere else.
        assertEquals("/ip4/87.154.209.161/tcp/9104/p2p/"
                        + "16Uiu2HAkvYx58piGw1oxz34CUoeTv8nNQwTwE2cZZh4jR4wVMYy6",
                NetworkConfig.SEPOLIA.clPeerMultiaddrs().get(1),
                "the dedicated Nimbus must remain SECOND as fallback — a roost outage "
                        + "then degrades to exactly the previous behaviour");
        assertTrue(NetworkConfig.SEPOLIA.clPeerMultiaddrs().size() > 2,
                "pinning must not drop the existing CL peers");
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
        List<String> cl = NetworkConfig.MAINNET.clPeerMultiaddrs();
        assertEquals("/dns4/be833f3590cd0388.dyndns.dappnode.io/tcp/9109/p2p/"
                        + "16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
                cl.get(0),
                "roost mainnet must be the first CL peer tried");
        assertEquals(19, cl.size(),
                "18 discovered peers + roost; pinning must not drop the fallbacks");
    }
}
