package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;
import com.jaeckel.ethp2p.consensus.types.LightClientBootstrap;
import com.jaeckel.ethp2p.consensus.types.LightClientFinalityUpdate;
import com.jaeckel.ethp2p.consensus.types.LightClientUpdate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Replays the committed light-client conformance corpus ({@code rust/testdata/lc/mainnet/}
 * — raw SSZ captured from live mainnet via {@link VectorDump}) through the JAVA verify
 * path and asserts the recorded verdicts in {@code expected.txt}. The Rust light client
 * (plan PRs 4–6) must reproduce exactly these verdicts from exactly these bytes — this
 * test is what keeps the recorded expectations honest on the Java side.
 *
 * <p>Regenerating {@code expected.txt} after refreshing the corpus:
 * {@code ./gradlew :consensus:test --tests "*LcVectorConformanceTest*"
 * -Dmyotis.lc.writeExpected=true} — then review the diff like any golden change.
 *
 * <p>The whole flow is wall-clock-free: {@link LightClientProcessor} validates
 * signatures, Merkle branches, and period applicability only. The one wall-clock input
 * the LIVE path uses — the current-slot estimate driving
 * {@code LightClientStore.forceRotateIfPastPeriod} between applied catch-up updates —
 * is RECORDED at capture time ({@code input.currentSlotEstimate} in expected.txt) and
 * replayed verbatim, so old captures replay forever. BLS runs on whatever backend
 * {@code BlsBackends} selects (Milagro on CI).
 */
class LcVectorConformanceTest {

    /** Corpus location, relative to the :consensus module dir Gradle runs tests in. */
    private static final Path CORPUS = Path.of("..", "rust", "testdata", "lc", "mainnet");

    // Mainnet fork context at capture time (Fulu, activated 2025-12-03) + the mainnet
    // genesis validators root (NetworkConfig.MAINNET carries the same constants; the
    // consensus module deliberately doesn't depend on :networking, so they're pinned
    // here AND recorded in expected.txt).
    private static final byte[] FORK_VERSION = {0x06, 0x00, 0x00, 0x00};
    private static final byte[] GVR =
            hex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");

    private static Map<String, String> expected;

    @BeforeAll
    static void loadExpected() throws Exception {
        assumeTrue(Files.isDirectory(CORPUS),
                "lc conformance corpus not present at " + CORPUS.toAbsolutePath());
        expected = new TreeMap<>();
        Path f = CORPUS.resolve("expected.txt");
        if (Files.exists(f)) {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq > 0) expected.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
    }

    @Test
    void replayReproducesRecordedVerdicts() throws Exception {
        // --- bootstrap: branch checks exactly as BeaconLightClient does them ---
        LightClientBootstrap bootstrap =
                LightClientBootstrap.decode(Files.readAllBytes(CORPUS.resolve("bootstrap.ssz")));

        int scDepth = bootstrap.currentSyncCommitteeBranch().length;
        assertTrue(SszUtil.verifyMerkleBranch(
                        bootstrap.currentSyncCommittee().hashTreeRoot(),
                        bootstrap.currentSyncCommitteeBranch(),
                        scDepth,
                        BeaconChainSpec.syncCommitteeGindex(scDepth),
                        bootstrap.header().beacon().stateRoot()),
                "bootstrap sync-committee branch must verify");
        assertTrue(LightClientProcessor.verifyExecutionBranch(bootstrap.header()),
                "bootstrap execution branch must verify");

        LightClientStore store = new LightClientStore();
        store.initialize(bootstrap.header(), bootstrap.currentSyncCommittee());
        LightClientProcessor processor = new LightClientProcessor(store, FORK_VERSION, GVR);

        // The recorded wall-clock input (see class javadoc). Generation mode computes it
        // once from the clock; assert mode replays the committed value.
        long slotEstimate = Boolean.getBoolean("myotis.lc.writeExpected")
                ? (System.currentTimeMillis() / 1000L - 1606824023L) / 12L
                : Long.parseLong(expected.getOrDefault("input.currentSlotEstimate", "0"));

        Map<String, String> actual = new TreeMap<>();
        actual.put("input.currentSlotEstimate", Long.toString(slotEstimate));
        actual.put("forkVersion", hex(FORK_VERSION));
        actual.put("genesisValidatorsRoot", hex(GVR));
        actual.put("bootstrap.slot", Long.toString(bootstrap.header().beacon().slot()));
        actual.put("bootstrap.headerRoot", hex(bootstrap.header().beacon().hashTreeRoot()));

        // --- catch-up updates, in capture order ---
        List<Path> updates = listSorted("update");
        actual.put("updates.count", Integer.toString(updates.size()));
        for (int i = 0; i < updates.size(); i++) {
            LightClientUpdate u = LightClientUpdate.decode(Files.readAllBytes(updates.get(i)));
            boolean applied = processor.processUpdate(u);
            // Mirrors the live applyCatchUpResponses loop: rotate on the (recorded)
            // slot estimate after each applied update so the next period's update
            // verifies against the rotated committee.
            if (applied) store.forceRotateIfPastPeriod(slotEstimate);
            actual.put("update." + i + ".applied", Boolean.toString(applied));
            actual.put("update." + i + ".finalizedSlot", Long.toString(store.getFinalizedSlot()));
        }

        // --- finality updates, in capture order ---
        List<Path> finals = listSorted("finality");
        actual.put("finality.count", Integer.toString(finals.size()));
        for (int i = 0; i < finals.size(); i++) {
            LightClientFinalityUpdate u =
                    LightClientFinalityUpdate.decode(Files.readAllBytes(finals.get(i)));
            boolean applied = processor.processFinalityUpdate(u);
            actual.put("finality." + i + ".applied", Boolean.toString(applied));
        }
        actual.put("final.finalizedSlot", Long.toString(store.getFinalizedSlot()));
        actual.put("final.finalizedExecStateRoot",
                hex(store.getFinalizedHeader().execution().stateRoot()));

        if (Boolean.getBoolean("myotis.lc.writeExpected")) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/lc/mainnet — generated by\n"
                            + "# LcVectorConformanceTest with -Dmyotis.lc.writeExpected=true.\n"
                            + "# The Rust light client must reproduce these from the same bytes.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.writeString(CORPUS.resolve("expected.txt"), sb.toString());
            System.out.println("[lc-conformance] wrote " + CORPUS.resolve("expected.txt"));
            return;
        }

        // A present corpus with a missing/empty expected.txt is a BROKEN state (bad
        // merge, botched regen commit) — fail loudly. Skipping here would silently
        // disable the exact golden this test exists to enforce; only a wholly absent
        // corpus dir (assumeTrue in loadExpected) legitimately skips.
        if (expected.isEmpty()) {
            org.junit.jupiter.api.Assertions.fail(
                    "corpus present but expected.txt missing/empty — regenerate with "
                            + "-Dmyotis.lc.writeExpected=true and commit it");
        }
        assertEquals(expected, actual,
                "replay verdicts diverge from the recorded expected.txt");
    }

    private static List<Path> listSorted(String kind) throws Exception {
        List<Path> out = new ArrayList<>();
        // Exactly-3-digit prefix: the committed corpus convention (001-…, 099 = the
        // stale negative). VectorDump writes 4-digit raw captures — the width gap
        // keeps an accidentally-dumped-into-corpus file from being ingested.
        try (var s = Files.newDirectoryStream(CORPUS, "[0-9][0-9][0-9]-" + kind + ".ssz")) {
            s.forEach(out::add);
        }
        out.sort(null);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
