package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.TestUtil;
import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import com.jaeckel.ethp2p.core.consensus.ForkSchedule;
import com.jaeckel.ethp2p.core.consensus.LcFork;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Gloas light-client decoding and proof selection against the consensus-specs
 * v1.7.0-beta.2 vectors in {@code rust/testdata/lc/gloas-spec} (see its README).
 * Rust twin: {@code rust/myotis-consensus/tests/gloas_spec_vectors.rs}.
 *
 * <ul>
 *   <li>{@code ssz_static} (mainnet preset): the production Gloas decoders read each
 *       container, and the container root recomputed from the decoded fields equals the
 *       spec's — so every field sits where the decoder reads it.</li>
 *   <li>{@code light_client_sync} / {@code gloas_fork} (minimal preset, sliced by hand):
 *       the production gindices and {@link LightClientProcessor#verifyExecutionBranchAt}
 *       accept genuine Gloas proofs, and the depth-derived pre-Gloas gindices do not. A
 *       genuine Fulu header upgraded to the Gloas shape ({@code upgrade_lc_header_to_gloas})
 *       — what a Gloas update carries as its finalized header in the first epochs after
 *       the fork — proves at 812 with zero padding.</li>
 * </ul>
 *
 * <p>The vectors are committed next to this change; a missing directory is a failure,
 * not a skip.
 */
class GloasSpecVectorTest {

    /** Vector location, relative to the :consensus module dir Gradle runs tests in. */
    private static final Path DIR = Path.of("..", "rust", "testdata", "lc", "gloas-spec");

    @BeforeAll
    static void vectorsPresent() {
        assertTrue(Files.isDirectory(DIR), "Gloas spec vectors missing at " + DIR.toAbsolutePath());
    }

    private static byte[] read(String rel) throws IOException {
        return Files.readAllBytes(DIR.resolve(rel));
    }

    private static String readText(String rel) throws IOException {
        return new String(read(rel), StandardCharsets.UTF_8);
    }

    private static byte[] hex32(String s) {
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    // ---- container roots, recomputed from decoded fields (test-side only) ----

    private static byte[] headerRoot(LightClientHeader h) {
        return SszUtil.hashTreeRootContainer(
                h.beacon().hashTreeRoot(),
                h.executionBlockHash(),
                SszUtil.merkleize(h.executionBranch()));
    }

    @Test
    void sszStaticContainersDecodeToTheSpecRoots() throws IOException {
        int checked = 0;
        for (String line : readText("mainnet/ssz_static/roots.txt").split("\n")) {
            if (line.isBlank()) continue;
            String[] parts = line.trim().split(" ");
            String name = parts[0];
            byte[] want = hex32(parts[1]);
            byte[] bytes = read("mainnet/ssz_static/" + name + ".ssz");
            byte[] got;
            switch (name.substring(0, name.indexOf('/'))) {
                case "LightClientHeader" -> {
                    LightClientHeader h = LightClientHeader.decodeFor(LcFork.GLOAS, bytes);
                    assertEquals(LcFork.GLOAS, h.shape());
                    got = headerRoot(h);
                }
                case "LightClientBootstrap" -> {
                    LightClientBootstrap b = LightClientBootstrap.decodeFor(LcFork.GLOAS, bytes);
                    got = SszUtil.hashTreeRootContainer(
                            headerRoot(b.header()),
                            b.currentSyncCommittee().hashTreeRoot(),
                            SszUtil.merkleize(b.currentSyncCommitteeBranch()));
                }
                case "LightClientUpdate" -> {
                    LightClientUpdate u = LightClientUpdate.decodeFor(LcFork.GLOAS, bytes);
                    got = SszUtil.hashTreeRootContainer(
                            headerRoot(u.attestedHeader()),
                            u.nextSyncCommittee().hashTreeRoot(),
                            SszUtil.merkleize(u.nextSyncCommitteeBranch()),
                            headerRoot(u.finalizedHeader()),
                            SszUtil.merkleize(u.finalityBranch()),
                            u.syncAggregate().hashTreeRoot(),
                            SszUtil.hashTreeRootUint64(u.signatureSlot()));
                }
                case "LightClientFinalityUpdate" -> {
                    LightClientFinalityUpdate u = LightClientFinalityUpdate.decodeFor(LcFork.GLOAS, bytes);
                    got = SszUtil.hashTreeRootContainer(
                            headerRoot(u.attestedHeader()),
                            headerRoot(u.finalizedHeader()),
                            SszUtil.merkleize(u.finalityBranch()),
                            u.syncAggregate().hashTreeRoot(),
                            SszUtil.hashTreeRootUint64(u.signatureSlot()));
                }
                default -> throw new AssertionError("unexpected type " + name);
            }
            assertArrayEquals(want, got, name + ": hash_tree_root of the decoded fields");
            checked++;
        }
        assertEquals(8, checked);
    }

    // ---- minimal preset: slice by hand, verify with the production rules ----

    /** Minimal-preset sizes (32-member sync committee). */
    private static final int MIN_COMMITTEE = 32;
    private static final int MIN_SYNC_COMMITTEE_SIZE = MIN_COMMITTEE * 48 + 48; // 1584
    private static final int H = LightClientHeader.GLOAS_SIZE;

    private static byte[] pubkeyRoot(byte[] bytes, int at) {
        byte[] c0 = Arrays.copyOfRange(bytes, at, at + 32);
        byte[] c1 = new byte[32];
        System.arraycopy(bytes, at + 32, c1, 0, 16);
        return SszUtil.merkleize(new byte[][]{c0, c1});
    }

    private static byte[] minimalCommitteeRoot(byte[] bytes) {
        assertEquals(MIN_SYNC_COMMITTEE_SIZE, bytes.length);
        byte[][] keys = new byte[MIN_COMMITTEE][];
        for (int i = 0; i < MIN_COMMITTEE; i++) keys[i] = pubkeyRoot(bytes, i * 48);
        return SszUtil.hashTreeRootContainer(SszUtil.merkleize(keys), pubkeyRoot(bytes, MIN_COMMITTEE * 48));
    }

    private static byte[][] nodes(byte[] bytes, int at, int n) {
        byte[][] out = new byte[n][];
        for (int i = 0; i < n; i++) out[i] = Arrays.copyOfRange(bytes, at + 32 * i, at + 32 * (i + 1));
        return out;
    }

    /** The minimal config of these vectors: 8-slot epochs, Gloas at epoch 3. */
    private static ForkSchedule minimalSchedule() {
        return ForkSchedule.of(8, ForkSchedule.fork(0, 0x06000001), ForkSchedule.fork(3, 0x07000001))
                .withGloasEpoch(3);
    }

    @Test
    void aGenuineGloasBootstrapProvesAtTheGloasGindices() throws IOException {
        byte[] b = read("minimal/light_client_sync/bootstrap.ssz");
        assertEquals(H + MIN_SYNC_COMMITTEE_SIZE + 11 * 32, b.length);
        LightClientHeader header = LightClientHeader.decodeGloas(Arrays.copyOfRange(b, 0, H));
        String trusted = readText("minimal/light_client_sync/trusted_block_root.txt");
        assertArrayEquals(hex32(trusted.trim()), header.beacon().hashTreeRoot());

        assertTrue(LightClientProcessor.verifyExecutionBranchAt(header, LcFork.GLOAS));
        assertFalse(LightClientProcessor.verifyExecutionBranchAt(header, LcFork.PRE_GLOAS),
                "812 must not accept a 2856 proof");

        byte[] committee = minimalCommitteeRoot(Arrays.copyOfRange(b, H, H + MIN_SYNC_COMMITTEE_SIZE));
        byte[][] branch = nodes(b, H + MIN_SYNC_COMMITTEE_SIZE, 11);
        byte[] state = header.beacon().stateRoot();
        assertTrue(SszUtil.verifyMerkleBranch(committee, branch,
                BeaconChainSpec.GLOAS_SYNC_COMMITTEE_BRANCH_LEN, BeaconChainSpec.CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS,
                state));
        assertFalse(SszUtil.verifyMerkleBranch(committee, branch, 11, BeaconChainSpec.syncCommitteeGindex(11), state));
    }

    @Test
    void gloasUpdatesAcrossTheForkProveAtTheirSlotsGindices() throws IOException {
        ForkSchedule schedule = minimalSchedule();
        int checked = 0;
        for (String line : readText("minimal/gloas_fork/expected.txt").split("\n")) {
            if (line.isBlank()) continue;
            String[] kv = line.trim().split(" ");
            String name = kv[0];
            byte[] u = read("minimal/gloas_fork/" + name + ".ssz");
            final int nsc = H;
            final int nscBranch = nsc + MIN_SYNC_COMMITTEE_SIZE;
            final int fin = nscBranch + 11 * 32;
            final int finBranch = fin + H;
            final int agg = finBranch + 9 * 32;
            assertEquals(agg + (4 + 96) + 8, u.length, name);

            LightClientHeader attested = LightClientHeader.decodeGloas(Arrays.copyOfRange(u, 0, H));
            LightClientHeader finalized = LightClientHeader.decodeGloas(Arrays.copyOfRange(u, fin, finBranch));
            assertArrayEquals(hex32(field(kv, "attested_root=")), attested.beacon().hashTreeRoot(), name);
            assertEquals(LcFork.GLOAS, schedule.lcForkAtSlot(attested.beacon().slot()), name);
            assertTrue(LightClientProcessor.verifyExecutionBranchAt(attested, LcFork.GLOAS), name + ": attested");
            assertFalse(LightClientProcessor.verifyExecutionBranchAt(attested, LcFork.PRE_GLOAS),
                    name + ": attested at 812");

            // Finality: the ATTESTED slot's fork picks the gindex. Until the chain
            // finalizes past genesis the spec carries an EMPTY finalized header and
            // proves a zero leaf (the genesis checkpoint root) — the store keeps its
            // own finalized header then, which is what expected.txt records.
            byte[] state = attested.beacon().stateRoot();
            byte[][] finality = nodes(u, finBranch, 9);
            byte[] leaf;
            if (finalized.beacon().slot() == 0) {
                LightClientHeader empty = LightClientHeader.decodeGloas(new byte[H]);
                assertEquals(empty.beacon(), finalized.beacon(), name);
                assertArrayEquals(empty.executionBlockHash(), finalized.executionBlockHash(), name);
                for (int i = 0; i < 11; i++) {
                    assertArrayEquals(empty.executionBranch()[i], finalized.executionBranch()[i], name);
                }
                leaf = new byte[32];
            } else {
                assertArrayEquals(hex32(field(kv, "finalized_root=")), finalized.beacon().hashTreeRoot(), name);
                assertEquals(field(kv, "finalized_slot="), Long.toString(finalized.beacon().slot()), name);
                LcFork fork = schedule.lcForkAtSlot(finalized.beacon().slot());
                assertTrue(LightClientProcessor.verifyExecutionBranchAt(finalized, fork), name + ": finalized");
                leaf = finalized.beacon().hashTreeRoot();
            }
            assertTrue(SszUtil.verifyMerkleBranch(leaf, finality, 9, BeaconChainSpec.FINALIZED_ROOT_GINDEX_GLOAS, state),
                    name);
            assertFalse(SszUtil.verifyMerkleBranch(leaf, finality, 9, BeaconChainSpec.finalizedRootGindex(9), state),
                    name);

            byte[] next = minimalCommitteeRoot(Arrays.copyOfRange(u, nsc, nscBranch));
            byte[][] nextBranch = nodes(u, nscBranch, 11);
            assertTrue(SszUtil.verifyMerkleBranch(next, nextBranch, 11,
                    BeaconChainSpec.NEXT_SYNC_COMMITTEE_GINDEX_GLOAS, state), name);
            checked++;
        }
        assertEquals(3, checked);
    }

    private static String field(String[] kv, String key) {
        for (String t : kv) {
            if (t.startsWith(key)) return t.substring(key.length());
        }
        throw new AssertionError(key + " in " + String.join(" ", kv));
    }

    /**
     * {@code upgrade_lc_header_to_gloas} on two genuine Fulu headers of the transition test:
     * the first update's attested header (slot 17) and the bootstrap's (slot 16 — the block
     * the spec's store holds as FINALIZED across the fork, i.e. the header a Gloas update
     * carries as its finalized header in the first epochs after it). Block hash + [proof of
     * the block hash inside the payload header (5) ++ the payload's own branch (4)],
     * normalized to 11. Each must prove at 812 (the pre-Gloas slot's rule) with the two zero
     * pad nodes, and nowhere else.
     *
     * <p>v1.7.0-beta.2 has no Gloas-format update whose finalized header is a non-genesis
     * pre-Gloas block (its transition carries the empty genesis header, then finalizes a
     * Gloas slot), so this upgrade — the computation a serving node performs — is the
     * genuine input for that path; {@code GloasBoundaryTest} walks it through the processor.
     * Rust twin: {@code a_fulu_header_in_the_gloas_shape_proves_at_812}.
     */
    @Test
    void aFuluHeaderInTheGloasShapeProvesAt812() throws IOException {
        byte[] u = read("minimal/gloas_fork/fulu_update.ssz");
        int attestedAt = SszUtil.readUint32(u, 0);
        int finalizedAt = SszUtil.readUint32(u, 4 + MIN_SYNC_COMMITTEE_SIZE + 6 * 32);
        LightClientHeader attested = LightClientHeader.decode(Arrays.copyOfRange(u, attestedAt, finalizedAt));
        byte[] b = read("minimal/gloas_fork/fulu_bootstrap.ssz");
        LightClientHeader finalized = LightClientHeader.decode(
                Arrays.copyOfRange(b, SszUtil.readUint32(b, 0), b.length));
        // The trusted block root of the test, and expected.txt's store finality.
        assertArrayEquals(hex32("b80f3f35165bdc5afb240b420faed2875d00b593d86ed17d450ac0e09b8f7019"),
                finalized.beacon().hashTreeRoot());
        assertProvesAt812OnceUpgraded(attested, 17);
        assertProvesAt812OnceUpgraded(finalized, 16);
    }

    private static void assertProvesAt812OnceUpgraded(LightClientHeader pre, long slot) {
        assertEquals(slot, pre.beacon().slot());
        assertTrue(LightClientProcessor.verifyExecutionBranchAt(pre, LcFork.PRE_GLOAS),
                "slot " + slot + ": genuine at gindex 25");

        ExecutionPayloadHeader p = pre.execution();
        byte[][] fields = {
                p.parentHash(),
                SszUtil.hashTreeRootBytes20(p.feeRecipient()),
                p.stateRoot(),
                p.receiptsRoot(),
                SszUtil.hashTreeRootBytes256(p.logsBloom()),
                p.prevRandao(),
                SszUtil.hashTreeRootUint64(p.blockNumber()),
                SszUtil.hashTreeRootUint64(p.gasLimit()),
                SszUtil.hashTreeRootUint64(p.gasUsed()),
                SszUtil.hashTreeRootUint64(p.timestamp()),
                SszUtil.hashTreeRootByteList(p.extraData(), 1),
                p.baseFeePerGas(),
                p.blockHash(),
                p.transactionsRoot(),
                p.withdrawalsRoot(),
                SszUtil.hashTreeRootUint64(p.blobGasUsed()),
                SszUtil.hashTreeRootUint64(p.excessBlobGas()),
        };
        // Proof of field 12 (block_hash) in the 32-leaf payload-header tree.
        byte[][] tree = TestUtil.buildMerkleTree(fields);
        assertEquals(64, tree.length);
        assertArrayEquals(p.hashTreeRoot(), tree[1]);
        byte[][] proof = TestUtil.extractBranch(tree, 5, 12);

        byte[][] branch = new byte[11][];
        branch[0] = new byte[32];
        branch[1] = new byte[32];
        System.arraycopy(proof, 0, branch, 2, 5);
        System.arraycopy(pre.executionBranch(), 0, branch, 7, 4);
        LightClientHeader upgraded = LightClientHeader.gloas(pre.beacon(), p.blockHash(), branch);
        assertTrue(LightClientProcessor.verifyExecutionBranchAt(upgraded, LcFork.PRE_GLOAS),
                "slot " + slot + ": 812, normalized");
        assertFalse(LightClientProcessor.verifyExecutionBranchAt(upgraded, LcFork.GLOAS),
                "slot " + slot + ": not at 2856");
        // The schedule-less check takes the payload shape only: it refuses the Gloas
        // shape outright, however genuine, so an unmigrated call site fails loudly.
        assertTrue(LightClientProcessor.verifyExecutionBranch(pre));
        assertFalse(LightClientProcessor.verifyExecutionBranch(upgraded));

        byte[][] dirtyBranch = new byte[11][];
        for (int i = 0; i < 11; i++) dirtyBranch[i] = branch[i].clone();
        dirtyBranch[0][0] = 1;
        LightClientHeader dirty = LightClientHeader.gloas(pre.beacon(), p.blockHash(), dirtyBranch);
        assertFalse(LightClientProcessor.verifyExecutionBranchAt(dirty, LcFork.PRE_GLOAS),
                "slot " + slot + ": a non-zero pad is not padding");

        // The Gloas vector is 11 nodes. One pad node short, the normalized check alone
        // would still accept the proof; the Rust verifier refuses it by length, and the
        // Java type cannot even hold it.
        byte[][] shortBranch = Arrays.copyOfRange(branch, 1, 11);
        assertTrue(SszUtil.verifyNormalizedMerkleBranch(p.blockHash(), shortBranch,
                BeaconChainSpec.EXECUTION_BLOCK_HASH_GINDEX_DENEB, pre.beacon().bodyRoot()));
        assertThrows(IllegalArgumentException.class,
                () -> LightClientHeader.gloas(pre.beacon(), p.blockHash(), shortBranch));
    }
}
