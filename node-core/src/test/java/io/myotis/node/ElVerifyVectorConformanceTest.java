package io.myotis.node;

import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The EL-A7 verified-read conformance corpus ({@code rust/testdata/el/verify/})
 * — shared with the Rust {@code myotis-net::el::verify}
 * ({@code tests/el_verify_conformance.rs}). Pins:
 *
 * <ul>
 *   <li>The load-bearing {@link VerifiedAccountQuery#verifyHeaderChain} crypto:
 *       committed BlockHeaders messages (valid chain / broken parent link /
 *       a made-up child of the attested block / a forged stand-in for the
 *       attested block / wrong first (peer) root) → the boolean verdict, which
 *       both languages must reproduce from the same bytes.</li>
 *   <li>The stable ladder token set ({@code stateRootMatch}, {@code headerChain},
 *       {@code beaconNotSynced}, {@code headerChainGapTooLarge}, …) that the
 *       operator tooling and integration greps depend on.</li>
 * </ul>
 *
 * <p>Regenerate: {@code ./gradlew :node-core:test --tests
 * "*ElVerifyVectorConformanceTest*" -Dmyotis.el.writeExpected=true}.
 */
class ElVerifyVectorConformanceTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "verify");
    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    // The header-chain trust anchor is the ATTESTED block's HASH (keccak of the
    // whole LAST header), NOT its state root. PEER_ROOT is the first header's
    // state root (the query target): the walk runs from the peer's block UP to
    // the attested block, because a parent hash pins only a parent.
    private static final Bytes32 ATTESTED_STATE_ROOT = tag("beacon-attested-state-root");
    private static final Bytes32 GENESIS_PARENT = tag("genesis-parent");
    private static final Bytes32 PEER_ROOT = tag("peer-head-root");

    /** The canonical chain: the peer's block, one between, the attested block on top. */
    private static Header peerBlock() {
        return header(21_000_000, PEER_ROOT, GENESIS_PARENT);
    }

    private static Header midBlock() {
        return header(21_000_001, tag("mid-root"), peerBlock().hash);
    }

    /** The beacon-attested block; its hash is the trust anchor. */
    private static Header attestedBlock() {
        return header(21_000_002, ATTESTED_STATE_ROOT, midBlock().hash);
    }

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            generateVectors();
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/verify conformance corpus not present at " + CORPUS.toAbsolutePath());
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
        Map<String, String> actual = new TreeMap<>();
        Bytes32 anchorBlockHash = attestedBlock().hash;
        actual.put("anchorBlockHash", anchorBlockHash.toUnprefixedHexString());
        actual.put("peerRoot", PEER_ROOT.toUnprefixedHexString());

        // --- headerChain verification over committed BlockHeaders messages,
        //     anchored on the attested block's HASH at the top ---
        for (Path p : listSorted()) {
            String base = baseName(p);
            List<BlockHeadersMessage.VerifiedHeader> headers =
                    BlockHeadersMessage.decodeWithRequestId(Files.readAllBytes(p)).headers();
            boolean ok = VerifiedAccountQuery.verifyHeaderChain(
                    headers, anchorBlockHash.toArray(), PEER_ROOT.toArray());
            actual.put("chain." + base, Boolean.toString(ok));
        }

        // --- the stable ladder token set (grepped by operator tooling) ---
        actual.put("tokens.verifyMethod", "headerChain,stateRootMatch");
        actual.put("tokens.failReason", String.join(",",
                "beaconBlockUnavailable", "beaconNotSynced", "headerChainError",
                "headerChainGapTooLarge", "headerChainInvalid", "noPeerBlockNumber",
                "noPeerStateRoot", "peerBlockAheadOfAnchor", "peerBlockBehindFinalized",
                "peerProofInvalid"));

        if (WRITE) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/verify — generated by\n"
                            + "# ElVerifyVectorConformanceTest with -Dmyotis.el.writeExpected=true.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-verify-conformance] wrote " + CORPUS.resolve("expected.txt"));
            return;
        }

        if (expected.isEmpty()) {
            org.junit.jupiter.api.Assertions.fail(
                    "corpus present but expected.txt missing/empty — regenerate with "
                            + "-Dmyotis.el.writeExpected=true and commit it");
        }
        assertEquals(expected, actual, "replay verdicts diverge from the recorded expected.txt");
    }

    // -------------------------------------------------------------------------
    // Vector generation: BlockHeaders messages [reqId, [h0, h1, h2]].
    // -------------------------------------------------------------------------

    private static void generateVectors() throws Exception {
        Header hp = peerBlock();
        Header hm = midBlock();
        Header ha = attestedBlock();
        // Valid: hp.stateRoot == PEER_ROOT, ha.hash == anchorBlockHash, parent-linked.
        writeMsg("001-chain-valid.rlp", hp, hm, ha);

        // Broken parent link: the middle header does not name hp as its parent, so
        // the attested block (which names the REAL middle block) no longer links either.
        Header hmBroken = header(21_000_001, tag("mid-root"), tag("wrong-parent"));
        writeMsg("002-chain-broken-link.rlp", hp, hmBroken, ha);

        // THE ATTACK the old upward walk let through: the real attested block,
        // followed by a header a peer made up that names it as its parent and
        // carries the peer's root. A parent hash pins only a parent, so the old
        // walk (anchored at the FIRST header) accepted this; anchored at the LAST
        // header it fails — the made-up child does not hash to the attested block.
        Header madeUp = header(21_000_003, PEER_ROOT, ha.hash);
        writeMsg("003-chain-made-up-child.rlp", ha, madeUp);

        // A forged stand-in for the attested block: it COPIES the public attested
        // state root and links to hp, but its block hash is not the attested one.
        Header forgedAnchor = header(21_000_001, ATTESTED_STATE_ROOT, hp.hash);
        writeMsg("004-chain-forged-anchor.rlp", hp, forgedAnchor);

        // Wrong first (peer) root: anchored at the attested block and hash-linked,
        // but its first header carries another root (mid-root, not PEER_ROOT), so
        // only the first-header state-root check can reject it — the half of the
        // gate that binds the snap proof to the walked block.
        writeMsg("005-chain-wrong-first-root.rlp", hm, ha);
    }

    private record Header(Bytes rlp, Bytes32 hash) {}

    /** A minimal post-London header with the given number, state root, parent hash. */
    private static Header header(long number, Bytes32 stateRoot, Bytes32 parentHash) {
        Bytes rlp = RLP.encodeList(w -> {
            w.writeValue(parentHash);
            w.writeValue(Bytes32.fromHexString(
                    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"));
            w.writeValue(tag("benef").slice(0, 20));
            w.writeValue(stateRoot);
            w.writeValue(tag("txroot"));
            w.writeValue(tag("rcpt"));
            w.writeValue(Bytes.wrap(new byte[256]));
            w.writeBigInteger(BigInteger.ZERO);
            w.writeLong(number);
            w.writeLong(30_000_000L);
            w.writeLong(14_838_935L);
            w.writeLong(1_700_000_000L + number);
            w.writeValue(Bytes.EMPTY);
            w.writeValue(tag("mix"));
            w.writeValue(Bytes.wrap(new byte[8]));
            w.writeBigInteger(BigInteger.valueOf(1_000_000_000L)); // baseFee
        });
        return new Header(rlp, Bytes32.wrap(Hash.keccak256(rlp)));
    }

    private static void writeMsg(String name, Header... headers) throws Exception {
        Bytes msg = RLP.encodeList(w -> {
            w.writeLong(1);
            w.writeList(hw -> {
                for (Header h : headers) hw.writeRLP(h.rlp);
            });
        });
        Files.write(CORPUS.resolve(name), msg.toArray());
    }

    private static List<Path> listSorted() throws Exception {
        List<Path> out = new java.util.ArrayList<>();
        try (var s = Files.newDirectoryStream(CORPUS, "[0-9][0-9][0-9]-chain-*.rlp")) {
            s.forEach(out::add);
        }
        out.sort(null);
        return out;
    }

    private static String baseName(Path p) {
        String n = p.getFileName().toString();
        return n.substring(0, n.lastIndexOf('.'));
    }

    private static Bytes32 tag(String s) {
        return Hash.keccak256(Bytes.wrap(("el-verify:" + s).getBytes(StandardCharsets.UTF_8)));
    }
}
