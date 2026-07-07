package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier;
import com.jaeckel.ethp2p.networking.snap.messages.AccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetAccountRangeMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetByteCodesMessage;
import com.jaeckel.ethp2p.networking.snap.messages.GetStorageRangesMessage;

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
 * The EL-A6 snap/1 conformance corpus ({@code rust/testdata/el/snap/}) — shared
 * with the Rust {@code myotis-net::el::snap} ({@code tests/el_snap_conformance.rs}).
 * Pins:
 * <ul>
 *   <li>GetAccountRange / GetStorageRanges / GetByteCodes encode bytes
 *       (byte-identical across languages).</li>
 *   <li>The full VERIFY-ON-FETCH path: a real single-leaf state trie is built,
 *       wrapped into a committed AccountRange / StorageRanges message, and the
 *       proof-verified account fields / slot value are pinned — both languages
 *       decode the same message and run the MPT verifier, and must agree. The
 *       proof leaf (not the peer's slim body) is the source of truth.</li>
 * </ul>
 *
 * <p>Regenerate: {@code ./gradlew :networking:test --tests
 * "*ElSnapVectorConformanceTest*" -Dmyotis.el.writeExpected=true}.
 */
class ElSnapVectorConformanceTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "snap");
    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    // Deterministic inputs shared with the Rust test (change only in lockstep).
    private static final Bytes ADDRESS = Hash.keccak256(utf8("snap:account")).slice(0, 20);
    private static final Bytes32 SLOT = Hash.keccak256(utf8("snap:slot"));
    private static final Bytes32 STORAGE_ROOT_FIELD = Hash.keccak256(utf8("snap:storage-root"));
    private static final Bytes32 CODE_HASH_FIELD = Hash.keccak256(utf8("snap:code-hash"));

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/snap conformance corpus not present at " + CORPUS.toAbsolutePath());
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

        // --- (1) request encode bytes ---
        Bytes32 stateRoot = accountStateRoot();
        Bytes32 accountHash = Bytes32.wrap(Hash.keccak256(ADDRESS));
        byte[] getAcct = GetAccountRangeMessage.encode(1, stateRoot, accountHash, allFF(), 4096);
        actual.put("encode.getAccountRange", Bytes.wrap(getAcct).toUnprefixedHexString());

        Bytes32 slotHash = Bytes32.wrap(Hash.keccak256(SLOT));
        byte[] getStorage = GetStorageRangesMessage.encode(2, stateRoot, accountHash, slotHash, allFF(), 4096);
        actual.put("encode.getStorageRanges", Bytes.wrap(getStorage).toUnprefixedHexString());

        Bytes32 codeHash = Bytes32.wrap(Hash.keccak256(utf8("snap:some-code")));
        byte[] getCodes = GetByteCodesMessage.encode(3, List.of(codeHash), 262144);
        actual.put("encode.getByteCodes", Bytes.wrap(getCodes).toUnprefixedHexString());

        // --- (2) verify-on-fetch: AccountRange over a real single-leaf proof ---
        actual.put("account.stateRoot", stateRoot.toUnprefixedHexString());
        MerklePatriciaProofVerifier.Result acctResult = MerklePatriciaProofVerifier.verify(
                stateRoot, Hash.keccak256(ADDRESS).toArray(), List.of(accountLeafNode()));
        if (acctResult instanceof MerklePatriciaProofVerifier.Result.Found found) {
            actual.put("account.verified", "found");
            // Decode the proof-verified leaf (the source of truth).
            RLP.decodeList(found.value(), r -> {
                actual.put("account.nonce", Long.toString(r.readLong()));
                actual.put("account.balance", r.readBigInteger().toString(16));
                actual.put("account.storageRoot", Bytes32.wrap(r.readValue()).toUnprefixedHexString());
                actual.put("account.codeHash", Bytes32.wrap(r.readValue()).toUnprefixedHexString());
                return null;
            });
        } else {
            actual.put("account.verified", acctResult.getClass().getSimpleName());
        }

        // --- (3) verify-on-fetch: StorageRanges over a real single-leaf proof ---
        Bytes32 storageRoot = storageStateRoot();
        actual.put("storage.storageRoot", storageRoot.toUnprefixedHexString());
        MerklePatriciaProofVerifier.Result stgResult = MerklePatriciaProofVerifier.verify(
                storageRoot, Hash.keccak256(SLOT).toArray(), List.of(storageLeafNode()));
        if (stgResult instanceof MerklePatriciaProofVerifier.Result.Found found) {
            // The trie value is rlp(uint256); strip to the integer for the pin.
            Bytes slotValue = RLP.decodeValue(found.value());
            actual.put("storage.verified", "found");
            actual.put("storage.value", slotValue.isEmpty() ? "0"
                    : new BigInteger(1, slotValue.toArrayUnsafe()).toString(16));
        } else {
            actual.put("storage.verified", stgResult.getClass().getSimpleName());
        }

        if (WRITE) {
            // Commit the full messages so the Rust side decodes THEM, not a
            // hand-built proof — exercising decode_account_range / _storage_ranges.
            Files.write(CORPUS.resolve("001-accountrange.bin"), accountRangeMessage());
            Files.write(CORPUS.resolve("002-storageranges.bin"), storageRangesMessage());
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/snap — generated by\n"
                            + "# ElSnapVectorConformanceTest with -Dmyotis.el.writeExpected=true.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-snap-conformance] wrote " + CORPUS.resolve("expected.txt"));
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
    // Trie / message construction.
    // -------------------------------------------------------------------------

    /** RLP([nonce, balance, storageRoot, codeHash]) — the trie value. */
    private static Bytes accountLeafValue() {
        return RLP.encodeList(w -> {
            w.writeLong(7);
            w.writeBigInteger(new BigInteger("de0b6b3a7640000", 16)); // 1 ETH
            w.writeValue(STORAGE_ROOT_FIELD);
            w.writeValue(CODE_HASH_FIELD);
        });
    }

    /** The single leaf node: [compact(0x20 || key), accountLeafValue]. */
    private static Bytes accountLeafNode() {
        Bytes key = Hash.keccak256(ADDRESS);
        Bytes compact = Bytes.concatenate(Bytes.of(0x20), key);
        return RLP.encodeList(w -> {
            w.writeValue(compact);
            w.writeValue(accountLeafValue());
        });
    }

    private static Bytes32 accountStateRoot() {
        return Bytes32.wrap(Hash.keccak256(materialize(accountLeafNode())));
    }

    /** AccountRange msg: [reqId, [[accountHash, slimBody]], [leafNode]]. */
    private static byte[] accountRangeMessage() {
        Bytes accountHash = Hash.keccak256(ADDRESS);
        return RLP.encodeList(w -> {
            w.writeLong(1);
            w.writeList(accts -> accts.writeList(pair -> {
                pair.writeValue(accountHash);
                pair.writeValue(accountLeafValue()); // slim body (bytes-wrapped)
            }));
            w.writeList(proof -> proof.writeValue(accountLeafNode()));
        }).toArrayUnsafe();
    }

    /** rlp(uint256) trie value for the slot. */
    private static Bytes storageLeafValue() {
        return RLP.encodeValue(Bytes.fromHexString("0563918244f40000")); // ~0.389e18
    }

    private static Bytes storageLeafNode() {
        Bytes key = Hash.keccak256(SLOT);
        Bytes compact = Bytes.concatenate(Bytes.of(0x20), key);
        return RLP.encodeList(w -> {
            w.writeValue(compact);
            w.writeValue(storageLeafValue());
        });
    }

    private static Bytes32 storageStateRoot() {
        return Bytes32.wrap(Hash.keccak256(materialize(storageLeafNode())));
    }

    /** StorageRanges msg: [reqId, [[[slotHash, wrappedValue]]], [leafNode]]. */
    private static byte[] storageRangesMessage() {
        Bytes slotHash = Hash.keccak256(SLOT);
        return RLP.encodeList(w -> {
            w.writeLong(2);
            w.writeList(perAccount -> perAccount.writeList(slots -> slots.writeList(pair -> {
                pair.writeValue(slotHash);
                pair.writeValue(storageLeafValue()); // wire value = the trie value
            })));
            w.writeList(proof -> proof.writeValue(storageLeafNode()));
        }).toArrayUnsafe();
    }

    private static Bytes32 allFF() {
        byte[] ff = new byte[32];
        java.util.Arrays.fill(ff, (byte) 0xff);
        return Bytes32.wrap(ff);
    }

    private static byte[] materialize(Bytes b) {
        byte[] out = new byte[b.size()];
        for (int i = 0; i < out.length; i++) out[i] = b.get(i);
        return out;
    }

    private static Bytes utf8(String s) {
        return Bytes.wrap(s.getBytes(StandardCharsets.UTF_8));
    }
}
