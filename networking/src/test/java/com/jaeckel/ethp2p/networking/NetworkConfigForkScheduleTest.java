package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins every network's fork schedule (#295). The Rust twin
 * ({@code rust/myotis-net/src/sync.rs}, {@code *_config_matches_networkconfig_java})
 * pins the same lists, so a one-sided edit fails on the side that was not
 * updated. Sources: consensus-specs {@code configs/mainnet.yaml},
 * eth-clients/sepolia {@code metadata/config.yaml}, gnosischain/configs
 * {@code mainnet/config.yaml}.
 */
class NetworkConfigForkScheduleTest {

    private static void assertSchedule(ForkSchedule s, int slotsPerEpoch, long[] epochs, int[] versions) {
        assertEquals(slotsPerEpoch, s.slotsPerEpoch());
        List<ForkSchedule.Fork> forks = s.forks();
        assertEquals(epochs.length, forks.size(), "entry count");
        for (int i = 0; i < epochs.length; i++) {
            assertEquals(epochs[i], forks.get(i).epoch(), "epoch of entry " + i);
            assertEquals(versions[i], forks.get(i).version(), "version of entry " + i);
        }
    }

    @Test
    void mainnetSchedule() {
        NetworkConfig c = NetworkConfig.MAINNET;
        assertSchedule(c.forkSchedule(), 32,
                new long[]{0, 74240, 144896, 194048, 269568, 364032, 411392},
                new int[]{0x00000000, 0x01000000, 0x02000000, 0x03000000, 0x04000000, 0x05000000, 0x06000000});
        assertArrayEquals(new byte[]{0x06, 0, 0, 0}, c.currentForkVersion());
        assertFalse(c.acceptPriorForkDigest());
        assertNull(c.priorForkVersion(), "fallback digest off on mainnet");
        // Fulu's first slot (411392 * 32 = 13164544) still verifies under Electra;
        // the next slot switches — the spec's max(signature_slot, 1) - 1.
        assertArrayEquals(new byte[]{0x05, 0, 0, 0}, c.forkSchedule().versionForSignatureSlot(13164544L));
        assertArrayEquals(new byte[]{0x06, 0, 0, 0}, c.forkSchedule().versionForSignatureSlot(13164545L));
    }

    @Test
    void sepoliaSchedule() {
        NetworkConfig c = NetworkConfig.SEPOLIA;
        assertSchedule(c.forkSchedule(), 32,
                new long[]{0, 50, 100, 56832, 132608, 222464, 272640},
                new int[]{0x90000069, 0x90000070, 0x90000071, 0x90000072, 0x90000073, 0x90000074, 0x90000075});
        assertArrayEquals(new byte[]{(byte) 0x90, 0, 0, 0x75}, c.currentForkVersion());
        assertFalse(c.acceptPriorForkDigest());
        assertNull(c.priorForkVersion());
    }

    @Test
    void gnosisSchedule() {
        NetworkConfig c = NetworkConfig.GNOSIS;
        assertSchedule(c.forkSchedule(), 16,
                new long[]{0, 512, 385536, 648704, 889856, 1337856, 1714688},
                new int[]{0x00000064, 0x01000064, 0x02000064, 0x03000064, 0x04000064, 0x05000064, 0x06000064});
        assertArrayEquals(new byte[]{0x06, 0, 0, 0x64}, c.currentForkVersion());
        assertTrue(c.acceptPriorForkDigest());
        assertArrayEquals(new byte[]{0x05, 0, 0, 0x64}, c.priorForkVersion());
        // Fulu epoch 1714688 x 16 = slot 27435008: the first slot is still Electra.
        assertArrayEquals(new byte[]{0x05, 0, 0, 0x64}, c.forkSchedule().versionForSignatureSlot(27435008L));
        assertArrayEquals(new byte[]{0x06, 0, 0, 0x64}, c.forkSchedule().versionForSignatureSlot(27435009L));
    }

    /**
     * The digest-side "current" version is the schedule entry active at the WALL
     * CLOCK, so the next fork can be pinned before it activates without flipping
     * the digest early. Pinned with a far-future entry appended to each real
     * schedule: every digest and version must be exactly what it is today.
     */
    @Test
    void aFutureForkPinnedAheadDoesNotChangeTodaysDigest() {
        for (NetworkConfig c : List.of(NetworkConfig.MAINNET, NetworkConfig.SEPOLIA, NetworkConfig.GNOSIS)) {
            assertArrayEquals(c.forkSchedule().newest(), c.currentForkVersion(),
                    c.name() + ": every pinned fork is active today");
            List<ForkSchedule.Fork> forks = new java.util.ArrayList<>(c.forkSchedule().forks());
            forks.add(ForkSchedule.fork(Long.MAX_VALUE / 64, 0x7F000000)); // never activates in this test's lifetime
            NetworkConfig ahead = new NetworkConfig(c.name(), c.networkId(), c.genesisHash(), c.bestBlockHash(),
                    c.forkIdHash(), c.forkNext(), c.bootnodes(), c.genesisValidatorsRoot(), c.checkpointRoot(),
                    c.checkpointSlot(), new ForkSchedule(c.forkSchedule().slotsPerEpoch(), forks),
                    c.activeBlobParamsEpoch(), c.activeBlobParamsMaxBlobs(), c.acceptPriorForkDigest(),
                    c.clPeerMultiaddrs(), c.beaconApiUrl(), c.clGenesisTime(), c.elEnrTreeUrls(),
                    c.clEnrTreeUrls(), c.clDiscv5Bootnodes());
            assertArrayEquals(c.currentForkVersion(), ahead.currentForkVersion(), c.name());
            assertArrayEquals(c.currentForkDigest(), ahead.currentForkDigest(), c.name());
            assertEquals(c.acceptedForkDigests().size(), ahead.acceptedForkDigests().size(), c.name());
            for (int i = 0; i < c.acceptedForkDigests().size(); i++) {
                assertArrayEquals(c.acceptedForkDigests().get(i), ahead.acceptedForkDigests().get(i), c.name());
            }
            // ...while signatures from that far future would already verify under it.
            assertArrayEquals(new byte[]{0x7F, 0, 0, 0}, ahead.forkSchedule().versionForSignatureSlot(Long.MAX_VALUE));
        }
    }

    /** A schedule with another chain's geometry is refused at construction. */
    @Test
    void mismatchedGeometryIsRefused() {
        NetworkConfig c = NetworkConfig.GNOSIS;
        ForkSchedule mainnetGeometry = new ForkSchedule(32, c.forkSchedule().forks());
        assertThrows(IllegalArgumentException.class, () -> new NetworkConfig(c.name(), c.networkId(),
                c.genesisHash(), c.bestBlockHash(), c.forkIdHash(), c.forkNext(), c.bootnodes(),
                c.genesisValidatorsRoot(), c.checkpointRoot(), c.checkpointSlot(), mainnetGeometry,
                c.activeBlobParamsEpoch(), c.activeBlobParamsMaxBlobs(), c.acceptPriorForkDigest(),
                c.clPeerMultiaddrs(), c.beaconApiUrl(), c.clGenesisTime(), c.elEnrTreeUrls(),
                c.clEnrTreeUrls(), c.clDiscv5Bootnodes()));
    }

    /** The digest inputs are unchanged by the schedule refactor (live-verified values). */
    @Test
    void digestsUnchanged() {
        assertArrayEquals(new byte[]{(byte) 0x8C, (byte) 0x9F, 0x62, (byte) 0xFE}, NetworkConfig.MAINNET.currentForkDigest());
        assertArrayEquals(new byte[]{0x74, (byte) 0xD0, 0x14, 0x59}, NetworkConfig.SEPOLIA.currentForkDigest());
        assertArrayEquals(new byte[]{0x32, 0x37, (byte) 0xDA, (byte) 0xB6}, NetworkConfig.GNOSIS.currentForkDigest());
        assertEquals(1, NetworkConfig.MAINNET.acceptedForkDigests().size());
        assertEquals(1, NetworkConfig.SEPOLIA.acceptedForkDigests().size());
        assertEquals(2, NetworkConfig.GNOSIS.acceptedForkDigests().size());
        assertArrayEquals(new byte[]{0x7D, 0x5A, (byte) 0xAB, 0x40}, NetworkConfig.GNOSIS.acceptedForkDigests().get(1));
    }
}
