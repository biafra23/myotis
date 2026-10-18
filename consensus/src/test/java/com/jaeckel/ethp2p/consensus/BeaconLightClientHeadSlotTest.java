package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.lightclient.LightClientStore;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #658: the sync state labels the optimistic head with ITS block's slot, as the Rust engine's
 * {@code update_exec_anchor} does — not the store's optimistic slot, which is the update's
 * signature slot. A read matched at the head reports the window's slot as its
 * {@code matchedBeaconSlot}, and the beacon status and the read's {@code optimisticSlot} report
 * {@link BeaconSyncState#getOptimisticSlot()} beside it, so all of them must be the block's.
 */
class BeaconLightClientHeadSlotTest {

    private static final long SEPOLIA_GENESIS = 1_655_733_600L;

    /** Sepolia's schedule as NetworkConfig pins it, without a Gloas date. */
    private static ForkSchedule sepolia() {
        return ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x90000069), ForkSchedule.fork(50, 0x90000070),
                ForkSchedule.fork(100, 0x90000071), ForkSchedule.fork(56832, 0x90000072),
                ForkSchedule.fork(132608, 0x90000073), ForkSchedule.fork(222464, 0x90000074),
                ForkSchedule.fork(272640, 0x90000075), ForkSchedule.fork(353024, 0x90000076));
    }

    private static byte[] root(int seed) {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) b[i] = (byte) (seed + i);
        return b;
    }

    /**
     * The committed LCSS-v1 golden (snapshot.rs {@code snapshot(true)}): the optimistic header
     * is payload-shaped block 23_000_050 at beacon slot 14_600_050, tracked by the store at
     * 14_600_033. Patterned values, not a real update's pair — which is what keeps the two
     * slots apart here. Resumed through the real path, every head slot reads the block's.
     */
    @Test
    void theHeadIsLabelledWithItsBlocksSlotNotTheStoresSignatureSlot() throws Exception {
        Path golden = Path.of("..", "rust", "testdata", "snapshot", "lcss-v1-golden.bin");
        assertTrue(Files.exists(golden), "LCSS-v1 golden missing at " + golden.toAbsolutePath());
        Path file = Files.createTempDirectory("lcss-v1-head-slot").resolve("sync-state.snapshot");
        Files.write(file, Files.readAllBytes(golden)); // a copy: close() may persist over it

        BeaconSyncState syncState = new BeaconSyncState();
        BeaconLightClient blc = new BeaconLightClient(List.of(), new byte[32], 0L, sepolia(), root(99),
                syncState, null, null, null, SEPOLIA_GENESIS);
        try {
            blc.setSnapshotFile(file);
            Method read = BeaconLightClient.class.getDeclaredMethod("readSnapshot");
            read.setAccessible(true);
            Method resume = BeaconLightClient.class.getDeclaredMethod(
                    "tryResumeFromSnapshot", LightClientStore.Snapshot.class);
            resume.setAccessible(true);
            LightClientStore.Snapshot snap = (LightClientStore.Snapshot) read.invoke(blc);
            assertNotNull(snap, "the v1 golden decodes");
            assertEquals(14_600_033L, snap.optimisticSlot(), "the store's own slot");
            assertEquals(14_600_050L, snap.optimisticHeader().beacon().slot());
            assertTrue((Boolean) resume.invoke(blc, snap), "resumed, not fallen back to bootstrap");

            assertEquals(14_600_050L, syncState.getOptimisticSlot());
            BeaconSyncState.OptimisticExecution head = syncState.getOptimisticExecution();
            assertEquals(23_000_050L, head.blockNumber());
            assertEquals(14_600_050L, head.slot(), "a header walk's matchedBeaconSlot");
            BeaconSyncState.SlottedStateRoot match = syncState.findStateRoot(root(54)); // header(50)'s
            assertNotNull(match, "the head's state root is in the window");
            assertEquals(14_600_050L, match.slot(), "a stateRootMatch's matchedBeaconSlot");
            assertEquals(14_600_001L, syncState.getFinalizedSlot());
        } finally {
            blc.close();
        }
    }
}
