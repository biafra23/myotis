package com.jaeckel.ethp2p.networking;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

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
        assertEquals(8, G.clDiscv5Bootnodes().size(), "CL discv5 bootnodes seed");
        for (String enr : G.clDiscv5Bootnodes()) {
            assertTrue(enr.startsWith("enr:"), "CL bootnode must be an ENR: " + enr);
        }
    }

    @Test
    void minSensibleHeadIsSet() {
        assertEquals(40_000_000L, G.minSensibleHeadBlock());
    }

    @Test
    void elBootEnodesAreDialableForGnosisOnly() {
        // Gnosis publishes no EL enrtree, so it ships full enode://<pubkey>@host:port seeds for
        // direct RLPx dialing. Networks that have an enrtree return an empty list.
        assertTrue(NetworkConfig.MAINNET.elBootEnodes().isEmpty(), "mainnet has an enrtree");
        assertTrue(NetworkConfig.SEPOLIA.elBootEnodes().isEmpty(), "sepolia has an enrtree");

        var enodes = G.elBootEnodes();
        assertFalse(enodes.isEmpty(), "Gnosis must ship static EL enode seeds");
        assertEquals(16, enodes.size());
        for (String enode : enodes) {
            // Parse exactly as ChainStack does — proves each entry yields a valid pubkey + addr.
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
