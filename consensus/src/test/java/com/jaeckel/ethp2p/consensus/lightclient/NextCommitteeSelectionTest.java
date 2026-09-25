package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.consensus.types.SyncAggregate;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * #423 — the Java twin of {@code rust/myotis-consensus/tests/next_committee_selection.rs}.
 * An update's aggregate is signed by the committee of its signature slot's PERIOD. With
 * the store at period P holding the next committee, a P+1-signed update must verify
 * against the NEXT committee (and be accepted), while a current-committee signature
 * whose unsigned signature slot was relabelled into P+1 must be rejected. Uses the
 * committed, genuinely signed mainnet corpus; no network, and no force-rotation
 * between updates (rotation is what hides the selection on the live path).
 */
class NextCommitteeSelectionTest {

    private static final Path CORPUS = Path.of("..", "rust", "testdata", "lc", "mainnet");
    private static final byte[] FORK_VERSION = {0x06, 0x00, 0x00, 0x00};
    private static final byte[] GVR = hex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");

    private record Fixture(LightClientStore store, LightClientProcessor processor) {}

    private static byte[] hex(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    private static byte[] corpus(String name) throws IOException {
        return Files.readAllBytes(CORPUS.resolve(name));
    }

    /** Store at period 1777 holding BOTH committees: bootstrap, then 001-update, no rotation. */
    private static Fixture withNext() throws IOException {
        assumeTrue(Files.isDirectory(CORPUS), "lc corpus not present at " + CORPUS.toAbsolutePath());
        LightClientBootstrap b = LightClientBootstrap.decode(corpus("bootstrap.ssz"));
        LightClientStore store = new LightClientStore();
        store.initialize(b.header(), b.currentSyncCommittee());
        LightClientProcessor p = new LightClientProcessor(store, ForkSchedule.single(FORK_VERSION), GVR);
        assertTrue(p.processUpdate(LightClientUpdate.decode(corpus("001-update.ssz"))));
        assertEquals(1777, store.getCurrentSyncCommitteePeriod());
        assertFalse(Arrays.equals(store.getCurrentSyncCommittee().hashTreeRoot(),
                store.getNextSyncCommittee().hashTreeRoot()), "distinct current and next committees");
        return new Fixture(store, p);
    }

    private static boolean signatureValid(LightClientUpdate u, SyncCommittee committee) {
        return SyncCommitteeVerifier.verify(u.syncAggregate(), committee, u.attestedHeader().beacon(),
                FORK_VERSION, GVR);
    }

    private static LightClientUpdate with(LightClientUpdate u, SyncAggregate aggregate, long signatureSlot) {
        return new LightClientUpdate(u.attestedHeader(), u.nextSyncCommittee(), u.nextSyncCommitteeBranch(),
                u.finalizedHeader(), u.finalityBranch(), aggregate, signatureSlot);
    }

    @Test
    void nextPeriodSignatureVerifiesWithTheNextCommittee() throws IOException {
        Fixture f = withNext();
        LightClientUpdate second = LightClientUpdate.decode(corpus("002-update.ssz"));
        assertEquals(1778, BeaconChainSpec.computeSyncCommitteePeriod(second.signatureSlot()));
        assertFalse(signatureValid(second, f.store().getCurrentSyncCommittee()), "signed by the NEXT committee");
        assertTrue(signatureValid(second, f.store().getNextSyncCommittee()));
        byte[] heldNextRoot = f.store().getNextSyncCommittee().hashTreeRoot();
        assertTrue(f.processor().processUpdate(second),
                "a valid next-committee update must be accepted before rotation");
        assertEquals(1778, f.store().getCurrentSyncCommitteePeriod());
        assertEquals(second.finalizedHeader().beacon().slot(), f.store().getFinalizedSlot());
        // The rotation installed the HELD next committee, not the P+2 committee this
        // update carries (processUpdate stores an embedded next only when none is held).
        assertTrue(Arrays.equals(heldNextRoot, f.store().getCurrentSyncCommittee().hashTreeRoot()));
        assertNull(f.store().getNextSyncCommittee());
    }

    @Test
    void currentCommitteeSignatureRelabelledIntoTheNextPeriodIsRejected() throws IOException {
        Fixture f = withNext();
        LightClientUpdate first = LightClientUpdate.decode(corpus("001-update.ssz"));
        // signatureSlot is not itself signed: claiming next-period participation must
        // select the next keys, under which this genuine current-committee signature fails.
        LightClientUpdate relabelled = with(first, first.syncAggregate(),
                first.signatureSlot() + BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD);
        assertTrue(signatureValid(relabelled, f.store().getCurrentSyncCommittee()));
        assertFalse(signatureValid(relabelled, f.store().getNextSyncCommittee()));
        assertFalse(f.processor().processUpdate(relabelled),
                "current keys must not authenticate next-period participation");
    }

    @Test
    void currentPeriodSignatureStillUsesTheCurrentCommittee() throws IOException {
        Fixture f = withNext();
        LightClientUpdate first = LightClientUpdate.decode(corpus("001-update.ssz"));
        assertEquals(1777, BeaconChainSpec.computeSyncCommitteePeriod(first.signatureSlot()));
        assertTrue(f.processor().processUpdate(first));
    }

    @Test
    void unknownNextCommitteeAndOutOfRangePeriodAreRejected() throws IOException {
        // Bootstrapped only: no next committee held, so period 1778 is not admissible.
        assumeTrue(Files.isDirectory(CORPUS));
        LightClientBootstrap b = LightClientBootstrap.decode(corpus("bootstrap.ssz"));
        LightClientStore store = new LightClientStore();
        store.initialize(b.header(), b.currentSyncCommittee());
        LightClientProcessor bare = new LightClientProcessor(store, ForkSchedule.single(FORK_VERSION), GVR);
        LightClientUpdate second = LightClientUpdate.decode(corpus("002-update.ssz"));
        assertFalse(bare.processUpdate(second));
        // Two periods ahead is never admissible, next committee or not.
        Fixture f = withNext();
        LightClientUpdate tooFar = with(second, second.syncAggregate(),
                second.signatureSlot() + BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD);
        assertFalse(f.processor().processUpdate(tooFar));
    }

    private static LightClientFinalityUpdate finalityOf(LightClientUpdate u, long signatureSlot) {
        return new LightClientFinalityUpdate(u.attestedHeader(), u.finalizedHeader(), u.finalityBranch(),
                u.syncAggregate(), signatureSlot);
    }

    @Test
    void nextPeriodFinalityUpdateIsAcceptedBeforeRotation() throws IOException {
        Fixture f = withNext();
        LightClientUpdate second = LightClientUpdate.decode(corpus("002-update.ssz"));
        LightClientFinalityUpdate fin = finalityOf(second, second.signatureSlot());
        assertTrue(f.processor().processFinalityUpdate(fin), "signed by the held next committee");
        assertEquals(second.finalizedHeader().beacon().slot(), f.store().getFinalizedSlot());
        // Its finalized slot is the first of period 1778, so the store rotated on apply.
        assertEquals(1778, f.store().getCurrentSyncCommitteePeriod());
        assertNull(f.store().getNextSyncCommittee());
    }

    @Test
    void appliedFinalityUpdateReplayedWithARelabelledSlotIsRejected() throws IOException {
        Fixture f = withNext();
        LightClientUpdate first = LightClientUpdate.decode(corpus("001-update.ssz"));
        LightClientFinalityUpdate applied = finalityOf(first, first.signatureSlot());
        assertTrue(f.processor().processFinalityUpdate(applied));
        // Same aggregate bytes, unsigned signature slot moved into period 1778: the
        // duplicate memo must not answer for it — it faces the next committee's keys.
        LightClientFinalityUpdate relabelled = finalityOf(first,
                first.signatureSlot() + BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD);
        assertFalse(f.processor().processFinalityUpdate(relabelled));
        // The genuine duplicate is still memoised.
        assertTrue(f.processor().processFinalityUpdate(applied));
    }

    @Test
    void currentPeriodFinalityUpdateStillVerifies() throws IOException {
        Fixture f = withNext();
        LightClientUpdate first = LightClientUpdate.decode(corpus("001-update.ssz"));
        assertEquals(1777, BeaconChainSpec.computeSyncCommitteePeriod(first.signatureSlot()));
        assertTrue(f.processor().processFinalityUpdate(finalityOf(first, first.signatureSlot())));
    }

    @Test
    void relabelledCurrentCommitteeFinalityUpdateIsRejected() throws IOException {
        Fixture f = withNext();
        LightClientUpdate first = LightClientUpdate.decode(corpus("001-update.ssz"));
        LightClientFinalityUpdate fin = finalityOf(first,
                first.signatureSlot() + BeaconChainSpec.SLOTS_PER_SYNC_COMMITTEE_PERIOD);
        assertFalse(f.processor().processFinalityUpdate(fin));
    }

    @Test
    void corruptedSignaturesAreRejectedInBothPeriods() throws IOException {
        for (String name : new String[] {"001-update.ssz", "002-update.ssz"}) {
            Fixture f = withNext();
            LightClientUpdate u = LightClientUpdate.decode(corpus(name));
            LightClientUpdate bad = with(u,
                    new SyncAggregate(u.syncAggregate().syncCommitteeBits(), new byte[96]), u.signatureSlot());
            assertFalse(f.processor().processUpdate(bad), name);
        }
    }
}
