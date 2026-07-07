package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.discv4.Packet;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
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
 * The EL-A3 discv4 conformance corpus ({@code rust/testdata/el/discv4/}):
 * signed ping/pong/findnode packet bytes with fixed keys + expiries, and a set
 * of inbound parse verdicts (hash check, sender recovery, Neighbors leniency) —
 * shared with the Rust {@code myotis-net::el::discv4}
 * ({@code tests/el_discv4_conformance.rs}). Same discipline as the other EL
 * corpora: ONE set of files, replayed byte-identically both sides against ONE
 * {@code expected.txt}.
 *
 * <p>Because both {@link Packet#encode} (via Tuweni {@code signHashed}) and the
 * Rust {@code NodeKey::sign_hash} (k256) produce deterministic RFC-6979 low-s
 * signatures, the signed packet BYTES are identical across languages — the
 * corpus pins the exact wire output, not just a decode round-trip.
 *
 * <p>Regenerate: {@code ./gradlew :networking:test --tests
 * "*ElDiscv4VectorConformanceTest*" -Dmyotis.el.writeExpected=true}.
 */
class ElDiscv4VectorConformanceTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "discv4");
    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    // Deterministic identity + expiry shared with the Rust test (change only in lockstep).
    private static final Bytes32 SECRET = Hash.keccak256(utf8("myotis-el-a3:discv4-key"));
    private static final long EXPIRY = 1_700_000_020L;

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            generateVectors();
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/discv4 conformance corpus not present at " + CORPUS.toAbsolutePath());
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
        NodeKey key = NodeKey.fromSecretKey(SECP256K1.SecretKey.fromBytes(SECRET));
        actual.put("key.pubkey", key.publicKeyBytes().toUnprefixedHexString());

        // --- signed packet byte pins (encoded here, byte-matched in Rust) ---
        for (Path p : listSorted("packet", ".bin")) {
            String base = baseName(p);
            Bytes packet = Bytes.wrap(Files.readAllBytes(p));
            // Round-trip through parse to pin the decoded shape too.
            Packet.Parsed parsed = Packet.parse(packet);
            actual.put("packet." + base + ".bytes", packet.toUnprefixedHexString());
            actual.put("packet." + base + ".type", Integer.toString(parsed.type() & 0xff));
            actual.put("packet." + base + ".hash", parsed.hash().toUnprefixedHexString());
            actual.put("packet." + base + ".sender",
                    parsed.senderKey().bytes().toUnprefixedHexString());
        }

        // --- inbound parse verdicts (valid / tampered / short) ---
        for (Path p : listSorted("parse", ".bin")) {
            String base = baseName(p);
            byte[] raw = Files.readAllBytes(p);
            try {
                Packet.Parsed parsed = Packet.parse(Bytes.wrap(raw));
                actual.put("parse." + base + ".result", "ok");
                actual.put("parse." + base + ".sender",
                        parsed.senderKey().bytes().toUnprefixedHexString());
            } catch (Exception e) {
                actual.put("parse." + base + ".result", "error");
            }
        }

        // --- Neighbors decode verdicts (the skip-vs-break leniency) ---
        // Files hold raw packet-DATA (not a signed packet), decoded directly
        // via Packet.decodeNeighbors — the same bytes the Rust decode_neighbors
        // consumes. Verdict = the ordered list of surviving node ids.
        for (Path p : listSorted("neighbors", ".bin")) {
            String base = baseName(p);
            Bytes data = Bytes.wrap(Files.readAllBytes(p));
            List<Packet.DiscoveredPeer> peers = Packet.decodeNeighbors(data);
            StringBuilder ids = new StringBuilder();
            for (Packet.DiscoveredPeer peer : peers) {
                if (ids.length() > 0) ids.append(',');
                ids.append(peer.nodeId().toUnprefixedHexString());
            }
            actual.put("neighbors." + base + ".ids", ids.toString());
        }

        if (WRITE) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/discv4 — generated by\n"
                            + "# ElDiscv4VectorConformanceTest with -Dmyotis.el.writeExpected=true.\n"
                            + "# The Rust myotis-net::el::discv4 must reproduce these from the same bytes.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-discv4-conformance] wrote " + CORPUS.resolve("expected.txt"));
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
        NodeKey key = NodeKey.fromSecretKey(SECP256K1.SecretKey.fromBytes(SECRET));
        InetSocketAddress from = new InetSocketAddress("0.0.0.0", 30303);
        InetSocketAddress to = new InetSocketAddress("192.0.2.1", 30304);

        Bytes ping = encodePingWithExpiry(key, from, to, EXPIRY);
        writeVector("001-packet-ping.bin", ping);
        Bytes32 pingHash = Bytes32.wrap(ping, 0);
        writeVector("002-packet-pong.bin", encodePongWithExpiry(key, to, pingHash, EXPIRY));
        writeVector("003-packet-findnode.bin",
                encodeFindNodeWithExpiry(key, key.publicKeyBytes(), EXPIRY));

        // Parse vectors: a valid ping, a hash-tampered ping, a truncated packet.
        writeVector("001-parse-valid.bin", ping);
        byte[] tampered = ping.toArray();
        tampered[40] ^= 0x01; // flip a signature byte → hash mismatch on parse
        writeVector("090-parse-tampered.bin", Bytes.wrap(tampered));
        writeVector("091-parse-short.bin", ping.slice(0, 97));

        // Neighbors packet-data vectors pinning the skip-vs-break leniency.
        // 001: all clean. 002: a bad-ip (3 bytes) and an oob-udp-port node are
        // SKIPPED individually. 003: a structurally-broken entry (not a list)
        // STOPS the walk, so nodes after it are lost.
        writeVector("001-neighbors-clean.bin", neighborsData(new NodeSpec[]{
                node(new byte[]{1, 1, 1, 1}, 100, "aa"),
                node(new byte[]{2, 2, 2, 2}, 200, "bb"),
        }));
        writeVector("002-neighbors-skip.bin", neighborsData(new NodeSpec[]{
                node(new byte[]{1, 1, 1, 1}, 100, "aa"),
                node(new byte[]{9, 9, 9}, 100, "bb"),        // bad ip length → skip
                node(new byte[]{2, 2, 2, 2}, 70000, "cc"),   // udp > 65535 → skip
                node(new byte[]{3, 3, 3, 3}, 300, "dd"),
        }));
        writeVector("003-neighbors-break.bin", neighborsDataRaw(new Object[]{
                node(new byte[]{1, 1, 1, 1}, 100, "aa"),
                RAW_NOT_A_LIST,                              // stops the walk
                node(new byte[]{4, 4, 4, 4}, 400, "ee"),     // never reached
        }));
    }

    private record NodeSpec(byte[] ip, long udp, String idHex) {}
    private static final Object RAW_NOT_A_LIST = new Object();

    private static NodeSpec node(byte[] ip, long udp, String idPrefix) {
        byte[] id = new byte[64];
        java.util.Arrays.fill(id, (byte) Integer.parseInt(idPrefix, 16));
        return new NodeSpec(ip, udp, Bytes.wrap(id).toUnprefixedHexString());
    }

    private static Bytes neighborsData(NodeSpec[] nodes) {
        return neighborsDataRaw(nodes);
    }

    /** Build `[[node…], expiry]` packet-data; entries may be a NodeSpec or the
     *  RAW_NOT_A_LIST sentinel (encoded as a bytes value to break the walk). */
    private static Bytes neighborsDataRaw(Object[] entries) {
        return org.apache.tuweni.rlp.RLP.encodeList(outer -> {
            outer.writeList(nodesW -> {
                for (Object e : entries) {
                    if (e == RAW_NOT_A_LIST) {
                        nodesW.writeValue(Bytes.of(0x01));
                    } else {
                        NodeSpec ns = (NodeSpec) e;
                        nodesW.writeList(nodeW -> {
                            nodeW.writeValue(Bytes.wrap(ns.ip));
                            nodeW.writeLong(ns.udp);
                            nodeW.writeInt(30303); // tcp
                            nodeW.writeValue(Bytes.fromHexString(ns.idHex));
                        });
                    }
                }
            });
            outer.writeLong(EXPIRY);
        });
    }

    /**
     * The production {@link Packet} helpers stamp their own {@code now()+20s}
     * expiry, which would make the corpus non-reproducible. Re-sign with a
     * fixed expiry via the same private {@code encode(key,type,data)} path
     * (reflection) so the bytes are pinnable.
     */
    private static Bytes encodePingWithExpiry(NodeKey key, InetSocketAddress from,
                                              InetSocketAddress to, long expiry) throws Exception {
        Bytes data = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeInt(4); // VERSION
            w.writeRLP(endpoint(from, from.getPort()));
            w.writeRLP(endpoint(to, 0));
            w.writeLong(expiry);
        });
        return encode(key, Packet.TYPE_PING, data);
    }

    private static Bytes encodePongWithExpiry(NodeKey key, InetSocketAddress to,
                                              Bytes32 pingHash, long expiry) throws Exception {
        Bytes data = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeRLP(endpoint(to, 0));
            w.writeValue(pingHash);
            w.writeLong(expiry);
        });
        return encode(key, Packet.TYPE_PONG, data);
    }

    private static Bytes encodeFindNodeWithExpiry(NodeKey key, Bytes target, long expiry)
            throws Exception {
        Bytes data = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeValue(target);
            w.writeLong(expiry);
        });
        return encode(key, Packet.TYPE_FIND_NODE, data);
    }

    private static Bytes endpoint(InetSocketAddress addr, int tcpPort) {
        return org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeValue(Bytes.wrap(addr.getAddress().getAddress()));
            w.writeInt(addr.getPort());
            w.writeInt(tcpPort);
        });
    }

    private static Bytes encode(NodeKey key, byte type, Bytes data) throws Exception {
        Method m = Packet.class.getDeclaredMethod("encode", NodeKey.class, byte.class, Bytes.class);
        m.setAccessible(true);
        return (Bytes) m.invoke(null, key, type, data);
    }

    // -------------------------------------------------------------------------
    // Helpers.
    // -------------------------------------------------------------------------

    private static void writeVector(String name, Bytes content) throws Exception {
        Files.write(CORPUS.resolve(name), content.toArray());
    }

    private static List<Path> listSorted(String kind, String ext) throws Exception {
        List<Path> out = new ArrayList<>();
        try (var s = Files.newDirectoryStream(CORPUS, "[0-9][0-9][0-9]-" + kind + "-*" + ext)) {
            s.forEach(out::add);
        }
        out.sort(null);
        return out;
    }

    private static String baseName(Path p) {
        String n = p.getFileName().toString();
        return n.substring(0, n.lastIndexOf('.'));
    }

    private static Bytes utf8(String s) {
        return Bytes.wrap(s.getBytes(StandardCharsets.UTF_8));
    }
}
