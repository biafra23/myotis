package com.jaeckel.ethp2p.networking;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Self-consistency checks for Chiado, Gnosis Chain's testnet. The Rust twin is
 * {@code chiado_config_matches_networkconfig_java} in rust/myotis-net/src/sync.rs.
 */
class NetworkConfigChiadoTest {

    private static final NetworkConfig C = NetworkConfig.CHIADO;

    @Test
    void identity() {
        assertEquals("chiado", C.name());
        assertEquals(10200L, C.networkId());
        assertEquals(
                Bytes32.fromHexString("ada44fd8d2ecab8b08f256af07ad3e777f17fb434f8f8e678b312f576212ba9a"),
                C.genesisHash());
        assertEquals(C.genesisHash(), C.bestBlockHash());
        assertSame(C, NetworkConfig.byName("chiado"));
        assertSame(C, NetworkConfig.byName("CHIADO"));
        assertTrue(NetworkConfig.allNetworks().contains(C));
        assertEquals("Chiado", C.displayName());
    }

    @Test
    void beaconPresetIsGnosisNotMainnet() {
        // Chiado runs the GNOSIS preset; keying the geometry on chainId 100 alone would
        // put it on 12 s slots and 32-slot epochs and misplace every period boundary.
        assertTrue(C.isGnosisPreset());
        assertTrue(NetworkConfig.GNOSIS.isGnosisPreset());
        assertFalse(NetworkConfig.MAINNET.isGnosisPreset());
        assertFalse(NetworkConfig.SEPOLIA.isGnosisPreset());
        assertEquals(5, C.secondsPerSlot());
        assertEquals(16, C.slotsPerEpoch());
        assertEquals(16, C.forkSchedule().slotsPerEpoch(), "schedule carries the gnosis geometry");
        assertEquals(3L, C.wsBoundPeriods(), "Gnosis's preset and churn parameters");
    }

    @Test
    void consensusFieldsMatchTheLiveBeaconApi() {
        assertEquals(
                Bytes.fromHexString("9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e"),
                Bytes.wrap(C.genesisValidatorsRoot()));
        assertEquals(1665396300L, C.clGenesisTime());
        // /eth/v1/config/fork_schedule: seven entries, the Gnosis-family 0x..6f versions.
        long[][] schedule = {
                {0, 0x0000006f}, {90, 0x0100006f}, {180, 0x0200006f}, {244224, 0x0300006f},
                {516608, 0x0400006f}, {948224, 0x0500006f}, {1353216, 0x0600006f}};
        for (long[] fork : schedule) {
            byte[] want = Bytes.ofUnsignedInt(fork[1]).toArrayUnsafe();
            assertArrayEquals(want, C.forkVersionAtEpoch(fork[0]), "fork at epoch " + fork[0]);
            if (fork[0] > 0) {
                assertFalse(Bytes.wrap(want).equals(Bytes.wrap(C.forkVersionAtEpoch(fork[0] - 1))),
                        "fork at epoch " + fork[0] + " activates exactly there");
            }
        }
        assertArrayEquals(new byte[]{0x06, 0x00, 0x00, 0x6f}, C.currentForkVersion(), "Fulu fork version");
        assertFalse(C.acceptPriorForkDigest());
        assertNull(C.priorForkVersion());
        assertEquals(32, C.checkpointRoot().length);
        assertTrue(C.checkpointSlot() > 0);
        // Empty BLOB_SCHEDULE: the Electra baseline folds into the Fulu digest, as on Gnosis.
        assertEquals(948224L, C.activeBlobParamsEpoch());
        assertEquals(2L, C.activeBlobParamsMaxBlobs());
    }

    @Test
    void forkDigestFoldsTheElectraBaseline() {
        // Fulu digest = base(0x0600006f) XOR sha256(le64(948224) || le64(2))[:4]; the plain
        // base would be a26586db. Same value the Rust twin pins.
        assertEquals("25f9148e", HexFormat.of().formatHex(C.currentForkDigest()));
        assertEquals(1, C.acceptedForkDigests().size());
    }

    @Test
    void elForkIdIsTheOsakaHead() {
        // Erigon p2p/forkid tests, Chiado's first Osaka block: 0x71c457cd, next 0.
        assertEquals("71c457cd", HexFormat.of().formatHex(C.forkIdHash()));
        assertEquals(0L, C.forkNext());
    }

    @Test
    void discoverySeedsArePresent() {
        assertEquals(List.of("51.75.246.2:30303", "57.129.70.222:30303",
                        "57.128.252.123:30303", "54.39.148.98:30303"),
                C.bootnodes().stream().map(a -> a.getHostString() + ":" + a.getPort()).toList());
        assertEquals(4, C.clDiscv5Bootnodes().size());
        for (String enr : C.clDiscv5Bootnodes()) {
            assertTrue(enr.startsWith("enr:"), enr);
        }
        // Nothing census-confirmed to pin yet: discovery finds the LC servers, and the
        // boot nodes are UDP-only (no RLPx), so there are no EL enodes to direct-dial.
        assertTrue(C.clPeerMultiaddrs().isEmpty());
        assertTrue(C.elBootEnodes().isEmpty());
        assertTrue(C.elEnrTreeUrls().isEmpty());
    }

    @Test
    void portsAndFeesAndNames() {
        assertEquals(30306, C.defaultElPort());
        assertEquals(9003, C.defaultDiscv5Port());
        assertEquals(8548, C.defaultRpcPort());
        assertEquals(20_000_000L, C.minSensibleHeadBlock());
        assertEquals(java.math.BigInteger.valueOf(1_000_000L), C.minSuggestedTipWei());
        // No name service is pinned for chainId 10200.
        assertFalse(C.hasEns());
    }
}
