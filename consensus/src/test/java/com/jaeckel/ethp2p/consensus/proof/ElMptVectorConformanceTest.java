package com.jaeckel.ethp2p.consensus.proof;

import com.jaeckel.ethp2p.core.trie.HexPrefix;
import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier.Result;

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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The EL-A2 conformance corpus ({@code rust/testdata/el/mpt/}): Merkle-Patricia
 * proof vectors (Found / Absent / Invalid, embedded nodes, exclusion proofs,
 * account/storage leaves), ordered-trie-root pins, and logs-bloom pins — shared
 * with the Rust {@code myotis-core} crate ({@code tests/el_mpt_conformance.rs}).
 * Same discipline as the el/core corpus: ONE set of files, replayed
 * byte-identically by both languages against ONE {@code expected.txt}.
 *
 * <p>Proof vector file format ({@code NNN-proof-<name>.txt}): line 1 = root hex,
 * line 2 = key hex, remaining lines = one proof node hex each.
 *
 * <p>Regenerating: {@code ./gradlew :consensus:test --tests
 * "*ElMptVectorConformanceTest*" -Dmyotis.el.writeExpected=true}.
 *
 * <p>Lives in {@code :consensus} because it pins BOTH the {@code core.trie}
 * verifier and {@link OrderedTrieRoot} (consensus depends on core; the reverse
 * doesn't hold). The M3:2048 bloom accrual is replicated inline from
 * {@code ReceiptsMessage} (:networking would create a cycle).
 */
class ElMptVectorConformanceTest {

    static {
        // Tuweni's KECCAK-256 needs the BouncyCastle JCA provider registered
        // before the first hash (generation runs in @BeforeAll).
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /** Corpus location, relative to the :consensus module dir Gradle runs tests in. */
    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "mpt");

    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            generateVectors();
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/mpt conformance corpus not present at " + CORPUS.toAbsolutePath());
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

        // --- proof vectors ---
        List<Path> proofs = new ArrayList<>();
        try (var s = Files.newDirectoryStream(CORPUS, "[0-9][0-9][0-9]-proof-*.txt")) {
            s.forEach(proofs::add);
        }
        proofs.sort(null);
        for (Path p : proofs) {
            String base = p.getFileName().toString().replace(".txt", "");
            List<String> lines = new ArrayList<>();
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                line = line.trim();
                if (!line.isEmpty()) lines.add(line);
            }
            Bytes32 root = Bytes32.fromHexString(lines.get(0));
            byte[] key = Bytes.fromHexString(lines.get(1)).toArrayUnsafe();
            List<Bytes> nodes = new ArrayList<>();
            for (int i = 2; i < lines.size(); i++) nodes.add(Bytes.fromHexString(lines.get(i)));

            String k = "mpt." + base;
            try {
                Result r = MerklePatriciaProofVerifier.verify(root, key, nodes);
                if (r instanceof Result.Found found) {
                    actual.put(k + ".result", "found");
                    actual.put(k + ".value", found.value().toUnprefixedHexString());
                    // Leaf-decode pins for the realistic vectors (base-name rule
                    // duplicated in the Rust test — keep in lockstep).
                    if (base.contains("account")) {
                        RLP.decodeList(found.value(), reader -> {
                            actual.put(k + ".account.nonce", Long.toString(reader.readLong()));
                            actual.put(k + ".account.balance", reader.readBigInteger().toString(16));
                            actual.put(k + ".account.storageRoot",
                                    Bytes32.wrap(reader.readValue()).toUnprefixedHexString());
                            actual.put(k + ".account.codeHash",
                                    Bytes32.wrap(reader.readValue()).toUnprefixedHexString());
                            return null;
                        });
                    }
                    if (base.contains("storage-leaf")) {
                        Bytes slot = RLP.decodeValue(found.value());
                        actual.put(k + ".storage.value",
                                slot.isEmpty() ? "0" : new BigInteger(1, slot.toArrayUnsafe()).toString(16));
                    }
                } else if (r instanceof Result.Absent) {
                    actual.put(k + ".result", "absent");
                } else {
                    actual.put(k + ".result", "invalid");
                }
            } catch (Exception e) {
                // Post-hardening nothing should escape; if it does, the Rust
                // side won't match and the corpus flags it.
                actual.put(k + ".result", "error");
            }
        }

        // --- ordered-trie-root pins (lists derived from strings shared with Rust) ---
        actual.put("triehash.empty", OrderedTrieRoot.ofList(List.of()).toUnprefixedHexString());
        actual.put("triehash.single",
                OrderedTrieRoot.ofList(List.of(utf8("myotis-tx-0"))).toUnprefixedHexString());
        actual.put("triehash.three", OrderedTrieRoot.ofList(List.of(
                Hash.keccak256(utf8("mpt:item:0")),
                Hash.keccak256(utf8("mpt:item:1")).slice(0, 8),
                Bytes.EMPTY)).toUnprefixedHexString());
        List<Bytes> spanning = new ArrayList<>();
        for (int i = 0; i < 200; i++) spanning.add(Hash.keccak256(utf8("mpt:span:" + i)));
        actual.put("triehash.spanning", OrderedTrieRoot.ofList(spanning).toUnprefixedHexString());

        // --- logs-bloom pins (M3:2048, accrual replicated from ReceiptsMessage) ---
        byte[] bloom = new byte[256];
        bloomAccrue(bloom, Hash.keccak256(utf8("mpt:bloom:addr")).slice(0, 20));
        actual.put("bloom.single", Bytes.wrap(bloom.clone()).toUnprefixedHexString());
        bloomAccrue(bloom, Hash.keccak256(utf8("mpt:bloom:t1")));
        bloomAccrue(bloom, Hash.keccak256(utf8("mpt:bloom:t2")));
        actual.put("bloom.multi", Bytes.wrap(bloom).toUnprefixedHexString());

        if (WRITE) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/mpt — generated by\n"
                            + "# ElMptVectorConformanceTest with -Dmyotis.el.writeExpected=true.\n"
                            + "# The Rust myotis-core crate must reproduce these from the same bytes.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-mpt-conformance] wrote " + CORPUS.resolve("expected.txt"));
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
    // Vector generation (writeExpected mode only).
    // -------------------------------------------------------------------------

    private static void generateVectors() throws Exception {
        // -- 001: whole trie is one leaf; prove its key → found.
        Bytes32 key1 = Hash.keccak256(utf8("mpt:key1"));
        Bytes value1 = utf8("myotis-account-value");
        Bytes leaf1 = leaf(nibbles(key1), value1);
        writeProof("001-proof-single-leaf", root(leaf1), key1, List.of(leaf1));

        // Two keys diverging at the FIRST nibble → a root branch + two leaves.
        Bytes32 keyA = withFirstNibble(Hash.keccak256(utf8("mpt:keyA")), 0x3);
        Bytes32 keyB = withFirstNibble(Hash.keccak256(utf8("mpt:keyB")), 0x7);
        Bytes valueA = utf8("value-under-A-is-long-enough-to-hash");
        Bytes valueB = utf8("value-under-B-is-long-enough-to-hash");
        Bytes leafA = leaf(tail(nibbles(keyA), 1), valueA);
        Bytes leafB = leaf(tail(nibbles(keyB), 1), valueB);
        Bytes[] slots = emptySlots();
        slots[0x3] = hashRef(leafA);
        slots[0x7] = hashRef(leafB);
        Bytes branchAB = branch(slots, Bytes.EMPTY);
        // -- 002: prove keyA (leafB not needed in the proof) → found.
        writeProof("002-proof-branch-found", root(branchAB), keyA, List.of(branchAB, leafA));
        // -- 003: first nibble 0xC hits an empty slot → absent (exclusion).
        writeProof("003-proof-branch-absent-empty-slot", root(branchAB),
                withFirstNibble(Hash.keccak256(utf8("mpt:keyC")), 0xC), List.of(branchAB));

        // -- 004: extension: keys sharing 3 nibbles, then a branch → found.
        Bytes32 keyE1 = withPrefixNibbles(Hash.keccak256(utf8("mpt:keyE1")), new byte[]{1, 2, 3, 0x8});
        Bytes32 keyE2 = withPrefixNibbles(Hash.keccak256(utf8("mpt:keyE2")), new byte[]{1, 2, 3, 0xd});
        Bytes leafE1 = leaf(tail(nibbles(keyE1), 4), utf8("extension-child-one-padded-past-32"));
        Bytes leafE2 = leaf(tail(nibbles(keyE2), 4), utf8("extension-child-two-padded-past-32"));
        Bytes[] eSlots = emptySlots();
        eSlots[0x8] = hashRef(leafE1);
        eSlots[0xd] = hashRef(leafE2);
        Bytes eBranch = branch(eSlots, Bytes.EMPTY);
        Bytes ext = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(HexPrefix.encode(new byte[]{1, 2, 3}, false)));
            w.writeValue(root(eBranch));
        }));
        writeProof("004-proof-extension-found", root(ext), keyE1, List.of(ext, eBranch, leafE1));

        // -- 005: EMBEDDED leaf (< 32-byte node inlined in the branch slot).
        // Short 2-byte keys keep the child leaf tiny: key 0xab01 under slot 0xa.
        Bytes keyEmb = Bytes.fromHexString("ab01");
        Bytes tinyLeaf = leaf(tail(nibbles(keyEmb), 1), Bytes.of(0x2a)); // ~6 bytes
        Bytes[] embSlots = emptySlots();
        embSlots[0xa] = tinyLeaf; // inlined raw, NOT hashed
        Bytes embBranch = branch(embSlots, Bytes.EMPTY);
        writeProof("005-proof-embedded-leaf", root(embBranch), keyEmb, List.of(embBranch));

        // Branch VALUE slot: keys 0xab (ends at the branch) and 0xab01.
        Bytes keyShort = Bytes.fromHexString("ab");
        Bytes keyLong = Bytes.fromHexString("ab01");
        Bytes valueShort = utf8("value-at-branch-carried-in-slot-16-x");
        // tail(…, 3): the extension consumed nibbles a,b and the branch slot
        // consumed the 0 — the leaf carries only the final nibble 1.
        Bytes leafLong = leaf(tail(nibbles(keyLong), 3), utf8("value-below-branch-long-enough-xxxx"));
        Bytes[] vSlots = emptySlots();
        vSlots[0x0] = hashRef(leafLong); // keyLong nibble after 'ab' is 0
        Bytes vBranch = branch(vSlots, valueShort);
        Bytes vExt = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(HexPrefix.encode(new byte[]{0xa, 0xb}, false)));
            w.writeValue(root(vBranch));
        }));
        // -- 006: path exhausted at the branch → found from slot 16.
        writeProof("006-proof-branch-value", root(vExt), keyShort, List.of(vExt, vBranch));
        // -- 007: the longer key under the same trie → found from the leaf.
        writeProof("007-proof-below-branch-value", root(vExt), keyLong, List.of(vExt, vBranch, leafLong));

        // -- 008: single-leaf trie, different key → absent (path divergence).
        writeProof("008-proof-leaf-divergence-absent", root(leaf1),
                Hash.keccak256(utf8("mpt:other-key")), List.of(leaf1));

        // -- 009: realistic account leaf [nonce, balance, storageRoot, codeHash].
        Bytes32 acctKey = Hash.keccak256(utf8("mpt:account"));
        Bytes acctValue = materialize(RLP.encodeList(w -> {
            w.writeLong(5);
            w.writeBigInteger(new BigInteger("de0b6b3a7640000", 16)); // 1 ETH
            w.writeValue(Hash.keccak256(utf8("mpt:storage-root")));
            w.writeValue(Hash.keccak256(utf8("mpt:code")));
        }));
        Bytes acctLeaf = leaf(nibbles(acctKey), acctValue);
        writeProof("009-proof-account-leaf", root(acctLeaf), acctKey, List.of(acctLeaf));

        // -- 010: realistic storage leaf, value = rlp(trimmed uint256).
        Bytes32 slotKey = Hash.keccak256(utf8("mpt:slot"));
        Bytes slotValue = RLP.encodeValue(Bytes.fromHexString("0563918244f40000")); // 0.389 ETH-ish
        Bytes slotLeaf = leaf(nibbles(slotKey), slotValue);
        writeProof("010-proof-storage-leaf", root(slotLeaf), slotKey, List.of(slotLeaf));

        // -- 011: extension whose encoded path DIVERGES from the key → absent.
        writeProof("011-proof-extension-divergence-absent", root(ext),
                withPrefixNibbles(Hash.keccak256(utf8("mpt:keyE3")), new byte[]{1, 2, 9, 0x8}),
                List.of(ext));
        // -- 012: key continues PAST a fully-matched leaf → absent.
        writeProof("012-proof-key-past-leaf-absent", root(leaf(nibbles(keyShort), valueShort)),
                keyLong, List.of(leaf(nibbles(keyShort), valueShort)));
        // -- 013: EMBEDDED extension (ext + embedded leaf, all < 32 bytes inline).
        Bytes keyEmb2 = Bytes.fromHexString("abcd");
        Bytes tinyLeaf2 = leaf(tail(nibbles(keyEmb2), 2), Bytes.of(0x11));
        Bytes tinyExt = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(HexPrefix.encode(new byte[]{0xb}, false)));
            w.writeRLP(tinyLeaf2); // embedded leaf inside the embedded extension
        }));
        Bytes[] emb2Slots = emptySlots();
        emb2Slots[0xa] = tinyExt;
        Bytes emb2Branch = branch(emb2Slots, Bytes.EMPTY);
        writeProof("013-proof-embedded-extension", root(emb2Branch), keyEmb2, List.of(emb2Branch));
        // -- 014: extension child of 31 bytes (neither hash nor embedded) → invalid.
        Bytes badExt = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(HexPrefix.encode(new byte[]{0xa, 0xb}, false)));
            w.writeValue(Hash.keccak256(utf8("mpt:short-ext")).slice(0, 31));
        }));
        writeProof("014-proof-extension-child-31", root(badExt), keyShort, List.of(badExt));
        // -- 015: extra unrelated nodes in the proof list are tolerated → found.
        writeProof("015-proof-extra-unused-nodes", root(leaf1), key1,
                List.of(leaf1, leafA, leafB));

        // -- 084: malformed embedded list in an UNTRAVERSED branch slot →
        //         invalid on both sides (whole-node validation parity).
        Bytes[] mSlots = emptySlots();
        mSlots[0x3] = hashRef(leafA);                     // traversed, valid
        mSlots[0x5] = Bytes.fromHexString("c28301");      // truncated inner item
        Bytes mBranch = branch(mSlots, Bytes.EMPTY);
        writeProof("084-proof-untraversed-malformed-slot", root(mBranch), keyA,
                List.of(mBranch, leafA));
        // -- 085: 40-deep nested list in a slot → invalid (nesting cap, both).
        byte[] deep = new byte[40];
        java.util.Arrays.fill(deep, (byte) 0xc1);
        deep[39] = (byte) 0xc0;
        Bytes[] dSlots = emptySlots();
        dSlots[0x3] = hashRef(leafA);
        dSlots[0x6] = Bytes.wrap(deep);
        Bytes dBranch = branch(dSlots, Bytes.EMPTY);
        writeProof("085-proof-deep-nested-slot", root(dBranch), keyA,
                List.of(dBranch, leafA));

        // -- 090: branch references a leaf the proof doesn't contain → invalid.
        writeProof("090-proof-missing-node", root(branchAB), keyB, List.of(branchAB));
        // -- 091: 3-item node → invalid (unexpected arity).
        Bytes threeItems = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.of(1));
            w.writeValue(Bytes.of(2));
            w.writeValue(Bytes.of(3));
        }));
        writeProof("091-proof-wrong-arity", root(threeItems), key1, List.of(threeItems));
        // -- 092: branch child of 31 bytes (neither hash nor embedded) → invalid.
        Bytes[] badSlots = emptySlots();
        badSlots[0x3] = RLP.encodeValue(Hash.keccak256(utf8("mpt:short")).slice(0, 31));
        Bytes badBranch = branch(badSlots, Bytes.EMPTY);
        writeProof("092-proof-branch-child-31", root(badBranch), keyA, List.of(badBranch));
        // -- 093: leaf whose hex-prefix flag nibble is 4 → invalid.
        Bytes badHp = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.fromHexString("40ab"));
            w.writeValue(utf8("v"));
        }));
        writeProof("093-proof-bad-hexprefix", root(badHp), key1, List.of(badHp));
        // -- 094: node truncated by one byte (root hashes the truncated bytes,
        //         so the hash matches but the RLP is malformed) → invalid.
        Bytes truncated = leaf1.slice(0, leaf1.size() - 1);
        writeProof("094-proof-truncated-node", root(truncated), key1, List.of(truncated));
        // -- 095: leaf value encoded as non-canonical single byte (0x81 0x05).
        Bytes hpItem = RLP.encodeValue(Bytes.wrap(HexPrefix.encode(nibbles(key1), true)));
        var ncPayload = new java.io.ByteArrayOutputStream();
        ncPayload.writeBytes(safeArray(hpItem));
        ncPayload.writeBytes(new byte[]{(byte) 0x81, 0x05});
        Bytes nonCanonical = rawList(Bytes.wrap(ncPayload.toByteArray()));
        writeProof("095-proof-noncanonical-value", root(nonCanonical), key1, List.of(nonCanonical));
        // -- 096: empty proof for a non-empty root → invalid.
        writeProof("096-proof-empty-for-nonempty", Hash.keccak256(utf8("mpt:some-root")),
                key1, List.of());
        // -- 097: empty proof for THE empty-trie root → absent.
        writeProof("097-proof-empty-trie", MerklePatriciaProofVerifier.EMPTY_TRIE_ROOT,
                key1, List.of());
        // -- 099: near-INT_MAX declared child length (c6 80 bb 7f ff ff fa):
        //         previously overflowed Java's itemLength sum and escaped as an
        //         uncaught IndexOutOfBoundsException → now invalid, both sides.
        Bytes overflow = Bytes.fromHexString("c680bb7ffffffa");
        writeProof("099-proof-overflow-length", root(overflow), key1, List.of(overflow));
        // -- 098: branch VALUE slot holds a LIST → found with the raw list RLP
        //         (the stripBytesHeader passthrough parity case).
        Bytes listValue = Bytes.fromHexString("c13f"); // [0x3f]
        var lvPayload = new java.io.ByteArrayOutputStream();
        lvPayload.writeBytes(safeArray(Bytes.repeat((byte) 0x80, 16)));
        lvPayload.writeBytes(safeArray(listValue));
        Bytes lvBranch = rawList(Bytes.wrap(lvPayload.toByteArray()));
        Bytes lvExt = materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(HexPrefix.encode(new byte[]{0xa, 0xb}, false)));
            w.writeValue(root(lvBranch));
        }));
        writeProof("098-proof-branch-value-list", root(lvExt), keyShort, List.of(lvExt, lvBranch));
    }

    // -------------------------------------------------------------------------
    // Node-building helpers (generation only).
    // -------------------------------------------------------------------------

    private static Bytes leaf(byte[] pathNibbles, Bytes value) {
        return materialize(RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(HexPrefix.encode(pathNibbles, true)));
            w.writeValue(value);
        }));
    }

    /** Copy into a plain array-backed Bytes (see {@link #safeArray}). */
    private static Bytes materialize(Bytes b) {
        return Bytes.wrap(safeArray(b));
    }

    private static Bytes[] emptySlots() {
        Bytes[] slots = new Bytes[16];
        java.util.Arrays.fill(slots, RLP.encodeValue(Bytes.EMPTY)); // 0x80
        return slots;
    }

    /** Branch from 16 already-RLP-encoded slot items + a value (encoded as bytes). */
    private static Bytes branch(Bytes[] slotItems, Bytes value) {
        var payload = new java.io.ByteArrayOutputStream();
        for (Bytes s : slotItems) payload.writeBytes(safeArray(s));
        payload.writeBytes(safeArray(RLP.encodeValue(value)));
        return rawList(Bytes.wrap(payload.toByteArray()));
    }

    /** RLP list header over an already-encoded payload (for hand-crafted nodes). */
    private static Bytes rawList(Bytes payload) {
        byte[] p = safeArray(payload);
        var out = new java.io.ByteArrayOutputStream();
        if (p.length <= 55) {
            out.write(0xc0 + p.length);
        } else {
            byte[] lenBytes = safeArray(Bytes.minimalBytes(p.length));
            out.write(0xf7 + lenBytes.length);
            out.writeBytes(lenBytes);
        }
        out.writeBytes(p);
        return Bytes.wrap(out.toByteArray());
    }

    /**
     * Materialize Bytes index-by-index — {@code toArray()} on Tuweni
     * {@code ConcatenatedBytes} compositions trips "element sizes do not
     * match total size".
     */
    private static byte[] safeArray(Bytes b) {
        byte[] out = new byte[b.size()];
        for (int i = 0; i < out.length; i++) out[i] = b.get(i);
        return out;
    }

    /** A 32-byte hash reference to a node, as an RLP bytes item. */
    private static Bytes hashRef(Bytes nodeRlp) {
        return RLP.encodeValue(root(nodeRlp));
    }

    private static Bytes32 root(Bytes nodeRlp) {
        return Hash.keccak256(materialize(nodeRlp));
    }

    private static byte[] nibbles(Bytes key) {
        return HexPrefix.toNibbles(key.toArrayUnsafe());
    }

    private static byte[] tail(byte[] nibbles, int from) {
        return java.util.Arrays.copyOfRange(nibbles, from, nibbles.length);
    }

    /** Replace the first nibble of a 32-byte key (to force branch layouts). */
    private static Bytes32 withFirstNibble(Bytes32 key, int nibble) {
        byte[] b = key.toArray();
        b[0] = (byte) ((nibble << 4) | (b[0] & 0x0f));
        return Bytes32.wrap(b);
    }

    /** Overwrite the first nibbles of a key (to force shared prefixes). */
    private static Bytes32 withPrefixNibbles(Bytes32 key, byte[] prefix) {
        byte[] n = HexPrefix.toNibbles(key.toArray());
        System.arraycopy(prefix, 0, n, 0, prefix.length);
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = (byte) ((n[2 * i] << 4) | n[2 * i + 1]);
        }
        return Bytes32.wrap(out);
    }

    private static void writeProof(String base, Bytes32 root, Bytes key, List<Bytes> nodes)
            throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(root.toUnprefixedHexString()).append('\n');
        sb.append(key.toUnprefixedHexString()).append('\n');
        for (Bytes n : nodes) sb.append(n.toUnprefixedHexString()).append('\n');
        Files.write(CORPUS.resolve(base + ".txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static Bytes utf8(String s) {
        return Bytes.wrap(s.getBytes(StandardCharsets.UTF_8));
    }

    /** M3:2048 accrual — replicated verbatim from ReceiptsMessage.bloomAccrue. */
    private static void bloomAccrue(byte[] bloom, Bytes item) {
        byte[] h = Hash.keccak256(item).toArrayUnsafe();
        for (int i = 0; i < 6; i += 2) {
            int bit = (((h[i] & 0xFF) << 8) | (h[i + 1] & 0xFF)) & 0x7FF;
            bloom[255 - bit / 8] |= (byte) (1 << (bit % 8));
        }
    }
}
