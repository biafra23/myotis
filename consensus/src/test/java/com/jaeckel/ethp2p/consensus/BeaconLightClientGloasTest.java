package com.jaeckel.ethp2p.consensus;

import com.jaeckel.ethp2p.consensus.lightclient.LightClientStore;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import com.jaeckel.ethp2p.core.consensus.LcFork;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The light client's Gloas integration, without the network: context bytes pick the
 * decoder, a Rust-written LCSS-v2 snapshot resumes through the real resume path, and the
 * beacon-block chain fill never runs for Gloas slots.
 */
class BeaconLightClientGloasTest {

    private static final long SEPOLIA_GENESIS = 1_655_733_600L;

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** Sepolia's schedule as NetworkConfig pins it (this module can't depend on :networking). */
    private static ForkSchedule sepolia() {
        return ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x90000069), ForkSchedule.fork(50, 0x90000070),
                ForkSchedule.fork(100, 0x90000071), ForkSchedule.fork(56832, 0x90000072),
                ForkSchedule.fork(132608, 0x90000073), ForkSchedule.fork(222464, 0x90000074),
                ForkSchedule.fork(272640, 0x90000075), ForkSchedule.fork(353024, 0x90000076));
    }

    private static BeaconLightClient client(ForkSchedule schedule, byte[] gvr, long checkpointSlot,
                                            BeaconSyncState syncState) {
        return new BeaconLightClient(List.of(), new byte[32], checkpointSlot, schedule, gvr, syncState,
                null, null, null, SEPOLIA_GENESIS);
    }

    /**
     * Twin of the Rust {@code lc_fork_of_chunk} digest pins: Sepolia's Gloas digest (its own fork
     * digest formula over 0x90000076, BPO2 fold included) selects the Gloas decoders; the
     * Fulu digest, anything else, and every digest on a chain with no Gloas date, the
     * pre-Gloas ones.
     */
    @Test
    void contextBytesPickTheWireFormat() {
        byte[] gvr = hex("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078");
        BeaconLightClient blc = client(sepolia().withGloasEpoch(353024), gvr, 0L, new BeaconSyncState());
        BeaconLightClient noGloas = client(sepolia(), gvr, 0L, new BeaconSyncState());
        try {
            blc.setBlobParameters(275712L, 21L);
            noGloas.setBlobParameters(275712L, 21L);
            assertEquals(LcFork.GLOAS, blc.lcForkOfDigest(hex("669e6c11")));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOfDigest(hex("74d01459")));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOfDigest(new byte[0]));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOfDigest(null));
            assertEquals(LcFork.PRE_GLOAS, noGloas.lcForkOfDigest(hex("669e6c11")));
        } finally {
            blc.close();
            noGloas.close();
        }
    }

    /**
     * Twin of the Rust {@code lc_fork_of_chunk} pins: a payload of exactly its type's Gloas
     * size is Gloas under ANY context bytes — the digest of a later blob-parameter fork this
     * client does not compute, or a mislabelled one — while a pre-Gloas payload under an
     * unknown digest decodes as before. Real objects both ways: the consensus-specs Gloas
     * {@code ssz_static} vectors and the recorded mainnet (pre-Gloas) corpus. Nothing is
     * Gloas on a chain with no Gloas date, by digest or by size.
     */
    @Test
    void aGloasSizedChunkIsGloasUnderAnyDigest() throws Exception {
        byte[] gvr = hex("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078");
        BeaconLightClient blc = client(sepolia().withGloasEpoch(353024), gvr, 0L, new BeaconSyncState());
        BeaconLightClient noGloas = client(sepolia(), gvr, 0L, new BeaconSyncState());
        byte[] gloasDigest = hex("669e6c11");
        byte[] fuluDigest = hex("74d01459");
        byte[] unknown = hex("01020304");
        int update = LightClientUpdate.GLOAS_SIZE;
        int fin = LightClientFinalityUpdate.GLOAS_SIZE;
        int boot = LightClientBootstrap.GLOAS_SIZE;
        try {
            blc.setBlobParameters(275712L, 21L);
            noGloas.setBlobParameters(275712L, 21L);
            // The digest rule alone, for a payload that is not the Gloas size.
            assertEquals(LcFork.GLOAS, blc.lcForkOf(gloasDigest, 27_000, update));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOf(fuluDigest, 27_000, update));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOf(new byte[0], 27_000, update));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOf(null, 27_000, update));
            // The size rule, whatever the context bytes say.
            assertEquals(LcFork.GLOAS, blc.lcForkOf(unknown, update, update));
            assertEquals(LcFork.GLOAS, blc.lcForkOf(fuluDigest, update, update));
            assertEquals(LcFork.GLOAS, blc.lcForkOf(unknown, fin, fin));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOf(unknown, fin + 1, fin));
            assertEquals(LcFork.GLOAS, blc.lcForkOf(null, boot, boot)); // the HTTP bootstrap
            // No Gloas date: neither rule fires.
            assertEquals(LcFork.PRE_GLOAS, noGloas.lcForkOf(gloasDigest, 27_000, update));
            assertEquals(LcFork.PRE_GLOAS, noGloas.lcForkOf(gloasDigest, update, update));

            // Gloas objects under an unknown digest decode in the Gloas format...
            Path gloasSpec = Path.of("..", "rust", "testdata", "lc", "gloas-spec", "mainnet", "ssz_static");
            byte[] gUpdate = Files.readAllBytes(gloasSpec.resolve("LightClientUpdate/case_0.ssz"));
            assertEquals(LcFork.GLOAS, LightClientUpdate.decodeFor(
                    blc.lcForkOf(unknown, gUpdate.length, update), gUpdate).attestedHeader().shape());
            byte[] gFin = Files.readAllBytes(gloasSpec.resolve("LightClientFinalityUpdate/case_0.ssz"));
            assertEquals(LcFork.GLOAS, LightClientFinalityUpdate.decodeFor(
                    blc.lcForkOf(unknown, gFin.length, fin), gFin).attestedHeader().shape());
            byte[] gBoot = Files.readAllBytes(gloasSpec.resolve("LightClientBootstrap/case_0.ssz"));
            assertEquals(LcFork.GLOAS, LightClientBootstrap.decodeFor(
                    blc.lcForkOf(unknown, gBoot.length, boot), gBoot).header().shape());

            // ...and pre-Gloas ones exactly as before (the sniffing pre-Gloas decoders).
            Path corpus = Path.of("..", "rust", "testdata", "lc", "mainnet");
            byte[] eUpdate = Files.readAllBytes(corpus.resolve("001-update.ssz"));
            assertEquals(LcFork.PRE_GLOAS, blc.lcForkOf(unknown, eUpdate.length, update));
            LightClientUpdate u = LightClientUpdate.decodeFor(blc.lcForkOf(unknown, eUpdate.length, update), eUpdate);
            assertEquals(LcFork.PRE_GLOAS, u.attestedHeader().shape());
            assertEquals(LightClientUpdate.decode(eUpdate).signatureSlot(), u.signatureSlot());
            byte[] eFin = Files.readAllBytes(corpus.resolve("001-finality.ssz"));
            LightClientFinalityUpdate f = LightClientFinalityUpdate.decodeFor(
                    blc.lcForkOf(unknown, eFin.length, fin), eFin);
            assertEquals(LcFork.PRE_GLOAS, f.attestedHeader().shape());
            assertEquals(LightClientFinalityUpdate.decode(eFin).signatureSlot(), f.signatureSlot());
            byte[] eBoot = Files.readAllBytes(corpus.resolve("bootstrap.ssz"));
            LightClientBootstrap b = LightClientBootstrap.decodeFor(blc.lcForkOf(unknown, eBoot.length, boot), eBoot);
            assertEquals(LcFork.PRE_GLOAS, b.header().shape());
            assertEquals(LightClientBootstrap.decode(eBoot).header().beacon().slot(), b.header().beacon().slot());
        } finally {
            blc.close();
            noGloas.close();
        }
    }

    /**
     * Relayed objects are served under the fork digest of their OWN slot — the spec's rule —
     * never the upstream's context bytes, which nothing checks: a Fulu-era object keeps the
     * Fulu digest after the fork, a Gloas-era one gets the Gloas digest.
     */
    @Test
    void relayedObjectsCarryTheDigestOfTheirOwnSlot() {
        byte[] gvr = hex("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078");
        BeaconLightClient blc = client(sepolia().withGloasEpoch(353024), gvr, 0L, new BeaconSyncState());
        try {
            blc.setBlobParameters(275712L, 21L);
            byte[] fulu = hex("74d01459");
            byte[] gloas = hex("669e6c11");
            assertArrayEquals(fulu, blc.relayDigest(11_209_280L)); // the pinned checkpoint's slot
            assertArrayEquals(fulu, blc.relayDigest(353_024L * 32 - 1));
            assertArrayEquals(gloas, blc.relayDigest(353_024L * 32));
        } finally {
            blc.close();
        }
    }

    /**
     * What makes the size rule safe (the Rust twin pins it at compile time in
     * {@code myotis_consensus::types}): every Gloas container is smaller than the smallest
     * canonical pre-Gloas encoding of its type, so a Gloas-sized payload is never a pre-Gloas
     * object. The smallest pre-Gloas header is the fixed part plus a Capella payload header
     * with empty {@code extra_data} (568 bytes; Deneb's and Electra's are larger).
     */
    @Test
    void aGloasObjectIsNeverTheSizeOfAPreGloasOne() {
        int minPreGloasHeader = LightClientHeader.FIXED_SIZE + 568;
        assertTrue(LightClientBootstrap.GLOAS_SIZE < LightClientBootstrap.FIXED_SIZE + minPreGloasHeader);
        assertTrue(LightClientUpdate.GLOAS_SIZE < LightClientUpdate.FIXED_SIZE + 2 * minPreGloasHeader);
        assertTrue(LightClientFinalityUpdate.GLOAS_SIZE
                < LightClientFinalityUpdate.FIXED_SIZE + 2 * minPreGloasHeader);
    }

    /**
     * A Rust-written LCSS-v2 snapshot — the committed golden, finalized header payload-shaped
     * and optimistic header Gloas-shaped — resumes through readSnapshot + tryResumeFromSnapshot
     * without an exception (it used to NPE in updateSyncState, and the resume fell back to a
     * fresh bootstrap). The payload-shaped finality goes straight into the sync state; the
     * Gloas head waits there as a pending block hash for the EL resolver.
     */
    @Test
    void aRustWrittenV2SnapshotResumesThroughTheRealResumePath() throws Exception {
        Path golden = Path.of("..", "rust", "testdata", "snapshot", "lcss-v2-golden.bin");
        assertTrue(Files.exists(golden), "LCSS-v2 golden missing at " + golden.toAbsolutePath());
        Path dir = Files.createTempDirectory("lcss-v2-resume");
        Path file = dir.resolve("sync-state.snapshot");
        Files.write(file, Files.readAllBytes(golden)); // a copy: close() may persist over it
        byte[] gvr = new byte[32];
        for (int i = 0; i < 32; i++) gvr[i] = (byte) (99 + i); // the golden's root(99)

        BeaconSyncState syncState = new BeaconSyncState();
        BeaconLightClient blc = client(sepolia().withGloasEpoch(353024), gvr, 0L, syncState);
        try {
            blc.setSnapshotFile(file);
            Method read = BeaconLightClient.class.getDeclaredMethod("readSnapshot");
            read.setAccessible(true);
            Method resume = BeaconLightClient.class.getDeclaredMethod(
                    "tryResumeFromSnapshot", LightClientStore.Snapshot.class);
            resume.setAccessible(true);

            LightClientStore.Snapshot snap = (LightClientStore.Snapshot) read.invoke(blc);
            assertNotNull(snap, "the v2 golden decodes");
            assertEquals(1379L, snap.currentSyncCommitteePeriod());
            assertTrue((Boolean) resume.invoke(blc, snap), "resumed, not fallen back to bootstrap");

            assertEquals(11_296_700L, syncState.getFinalizedSlot());
            assertEquals(23_000_001L, syncState.getExecutionBlockNumber()); // header(1, true)
            List<byte[]> pending = syncState.pendingHashes();
            assertEquals(1, pending.size(), "the Gloas optimistic head waits for its header");
            byte[] want = new byte[32];
            for (int i = 0; i < 32; i++) want[i] = (byte) (63 + i); // gloas_header(60)'s root(63)
            assertArrayEquals(want, pending.get(0));
            assertEquals(1379L, syncState.getCurrentSyncCommitteePeriod());
        } finally {
            blc.close();
        }
    }

    /**
     * The beacon-block chain fill anchors its walk at the attested block. From Gloas a
     * block body carries no execution payload (no state root to record) and the parser
     * would misread it — so a Gloas attested slot is "nothing to fill", not a failure that
     * sends the fallback sweeping every peer. An unstarted client fails any real request
     * at once, which is what the pre-Gloas case shows.
     */
    @Test
    void theChainFillNeverRunsForGloasSlots() {
        long gloasEpoch = 10;
        long g = gloasEpoch * 32;
        ForkSchedule schedule = ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x06000000), ForkSchedule.fork(gloasEpoch, 0x07000000))
                .withGloasEpoch(gloasEpoch);
        BeaconLightClient blc = client(schedule, new byte[32], 0L, new BeaconSyncState());
        String peer = "/ip4/127.0.0.1/tcp/9000/p2p/16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ";
        try {
            assertTrue(blc.fillChainStateRoots(peer, true, g - 40, g + 5, new byte[32]),
                    "a Gloas attested slot: nothing to fill, and no request sent");
            assertTrue(blc.fillChainStateRoots(peer, true, g, g + 30, new byte[32]));
            assertFalse(blc.fillChainStateRoots(peer, true, g - 40, g - 1, new byte[32]),
                    "a pre-Gloas range still asks a peer (and fails here, unstarted)");
        } finally {
            blc.close();
        }
    }

    /** No Gloas date: the gate never fires. */
    @Test
    void withoutAGloasDateTheChainFillRunsAsBefore() {
        BeaconLightClient blc = client(sepolia(), new byte[32], 0L, new BeaconSyncState());
        String peer = "/ip4/127.0.0.1/tcp/9000/p2p/16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ";
        try {
            long far = 353_024L * 32 + 100;
            assertFalse(blc.fillChainStateRoots(peer, true, far - 40, far, new byte[32]));
        } finally {
            blc.close();
        }
    }
}
