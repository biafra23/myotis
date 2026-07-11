package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import com.jaeckel.ethp2p.networking.eth.messages.ReceiptsMessage;
import com.jaeckel.ethp2p.networking.eth.messages.StatusMessage;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.rlp.RLP;
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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The EL-A5 eth/66-69 conformance corpus ({@code rust/testdata/el/eth/}) —
 * shared with the Rust {@code myotis-net::el::eth::messages}
 * ({@code tests/el_eth_conformance.rs}). Pins the wire encode/decode that a
 * light client depends on:
 *
 * <ul>
 *   <li>Status encode bytes (eth/68 and eth/69 shapes) — byte-identical.</li>
 *   <li>GetBlockHeaders encode bytes (by-number eth/68 with reqId + eth/69
 *       without).</li>
 *   <li>BlockHeaders decode → per-header keccak hash (the value verified
 *       against the beacon anchor), for a committed multi-fork header list.</li>
 *   <li>eth/69 bloomless Receipts → recomputed-bloom canonical receipt bytes,
 *       matching the eth/66-68 trie value.</li>
 * </ul>
 *
 * <p>Regenerate: {@code ./gradlew :networking:test --tests
 * "*ElEthVectorConformanceTest*" -Dmyotis.el.writeExpected=true}.
 */
class ElEthVectorConformanceTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "eth");
    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    private static final Bytes32 GENESIS = Bytes32.fromHexString(
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    private static final Bytes32 BEST = Hash.keccak256(utf8("eth:best-hash"));
    private static final byte[] FORK = {(byte) 0x07, (byte) 0xc9, (byte) 0x46, (byte) 0x2e};

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            generateVectors();
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/eth conformance corpus not present at " + CORPUS.toAbsolutePath());
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

        // (1) Status encode bytes (eth/68 + eth/69).
        byte[] s68 = StatusMessage.encode(68, 1, GENESIS, BEST, FORK, 0, 0);
        actual.put("status.eth68.bytes", Bytes.wrap(s68).toUnprefixedHexString());
        byte[] s69 = StatusMessage.encode(69, 100, GENESIS, BEST, FORK, 0, 21_000_000L);
        actual.put("status.eth69.bytes", Bytes.wrap(s69).toUnprefixedHexString());

        // Decode round-trip pins.
        StatusMessage d68 = StatusMessage.decode(s68);
        actual.put("status.eth68.networkId", Long.toString(d68.networkId));
        actual.put("status.eth68.genesis", d68.genesisHash.toUnprefixedHexString());
        StatusMessage d69 = StatusMessage.decode69(s69);
        actual.put("status.eth69.latestBlock", Long.toString(d69.latestBlock));
        actual.put("status.eth69.latestHash", d69.bestHash.toUnprefixedHexString());

        // (2) BlockHeaders decode → per-header hashes, from a committed list.
        byte[] headersMsg = Files.readAllBytes(CORPUS.resolve("001-blockheaders.rlp"));
        BlockHeadersMessage.DecodeResult hs =
                BlockHeadersMessage.decodeWithRequestId(headersMsg);
        actual.put("headers.reqId", Long.toString(hs.requestId()));
        actual.put("headers.count", Integer.toString(hs.headers().size()));
        for (int i = 0; i < hs.headers().size(); i++) {
            var vh = hs.headers().get(i);
            actual.put("headers." + i + ".hash", vh.hash().toUnprefixedHexString());
            actual.put("headers." + i + ".number", Long.toString(vh.header().number));
        }

        // (3) eth/69 bloomless Receipts → recomputed-bloom canonical bytes.
        byte[] receipts69 = Files.readAllBytes(CORPUS.resolve("002-receipts69.rlp"));
        ReceiptsMessage.DecodeResult rr = ReceiptsMessage.decode69(receipts69);
        actual.put("receipts69.blocks", Integer.toString(rr.perBlockReceipts().size()));
        for (int b = 0; b < rr.perBlockReceipts().size(); b++) {
            List<Bytes> block = rr.perBlockReceipts().get(b);
            for (int r = 0; r < block.size(); r++) {
                actual.put("receipts69." + b + "." + r + ".canonical",
                        block.get(r).toUnprefixedHexString());
            }
        }

        if (WRITE) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/eth — generated by\n"
                            + "# ElEthVectorConformanceTest with -Dmyotis.el.writeExpected=true.\n"
                            + "# The Rust myotis-net::el::eth::messages must reproduce these.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-eth-conformance] wrote " + CORPUS.resolve("expected.txt"));
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
    // Vector generation.
    // -------------------------------------------------------------------------

    private static void generateVectors() throws Exception {
        // A [reqId, [header, header, header]] message across fork eras.
        Bytes h0 = header(19_426_587L, /*cancun*/ true, false);
        Bytes h1 = header(19_426_588L, true, false);
        Bytes h2 = header(22_431_084L, /*prague*/ true, true); // + requestsHash
        Bytes msg = RLP.encodeList(w -> {
            w.writeLong(7);
            w.writeList(hw -> {
                hw.writeRLP(h0);
                hw.writeRLP(h1);
                hw.writeRLP(h2);
            });
        });
        Files.write(CORPUS.resolve("001-blockheaders.rlp"), msg.toArray());

        // eth/69 bloomless receipts. NOTE the request-id wrapper is retained in
        // eth/69 (only the Status shape + bloomless receipt bodies changed):
        // [reqId, [ [ [txType, status, cumGas, logs], ... ] ]].
        Bytes r69 = RLP.encodeList(top -> {
            top.writeLong(9);
            top.writeList(outer -> outer.writeList(block -> {
            // A typed (type 2) receipt with one log (addr + 2 topics).
            block.writeList(rc -> {
                rc.writeInt(2);          // txType
                rc.writeInt(1);          // status
                rc.writeLong(21_000L);   // cumulativeGas
                rc.writeList(logs -> logs.writeList(log -> {
                    log.writeValue(addr());
                    log.writeList(topics -> {
                        topics.writeValue(topic(1));
                        topics.writeValue(topic(2));
                    });
                    log.writeValue(Bytes.fromHexString("deadbeef"));
                }));
            });
            // A legacy (type 0) receipt with no logs.
            block.writeList(rc -> {
                rc.writeInt(0);
                rc.writeInt(1);
                rc.writeLong(42_000L);
                rc.writeList(logs -> { });
            });
        }));
        });
        Files.write(CORPUS.resolve("002-receipts69.rlp"), r69.toArray());
    }

    /** A deterministic header; {@code cancun} adds the 4844/4788 tail, {@code prague} adds requestsHash. */
    private static Bytes header(long number, boolean cancun, boolean prague) {
        return RLP.encodeList(w -> {
            w.writeValue(tag("parent", number));
            w.writeValue(Bytes32.fromHexString(
                    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")); // ommers
            w.writeValue(tag("benef", number).slice(0, 20));
            w.writeValue(tag("state", number));
            w.writeValue(tag("txroot", number));
            w.writeValue(tag("rcpt", number));
            w.writeValue(Bytes.wrap(new byte[256]));
            w.writeBigInteger(java.math.BigInteger.ZERO); // difficulty
            w.writeLong(number);
            w.writeLong(30_000_000L);
            w.writeLong(14_838_935L);
            w.writeLong(1_700_000_000L + number);
            w.writeValue(Bytes.EMPTY);
            w.writeValue(tag("mix", number));
            w.writeValue(Bytes.wrap(new byte[8]));
            w.writeBigInteger(java.math.BigInteger.valueOf(1_000_000_000L)); // baseFee
            w.writeValue(tag("wroot", number)); // withdrawalsRoot
            if (cancun) {
                w.writeLong(0L);        // blobGasUsed
                w.writeLong(393_216L);  // excessBlobGas
                w.writeValue(tag("beacon", number)); // parentBeaconBlockRoot
            }
            if (prague) {
                w.writeValue(tag("requests", number)); // requestsHash
            }
        });
    }

    private static Bytes32 tag(String field, long n) {
        return Hash.keccak256(utf8("eth:" + field + ":" + n));
    }

    private static Bytes addr() {
        return Hash.keccak256(utf8("eth:log-addr")).slice(0, 20);
    }

    private static Bytes topic(int i) {
        return Hash.keccak256(utf8("eth:topic:" + i));
    }

    private static Bytes utf8(String s) {
        return Bytes.wrap(s.getBytes(StandardCharsets.UTF_8));
    }
}
