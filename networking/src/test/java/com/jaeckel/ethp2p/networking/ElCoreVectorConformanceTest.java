package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.core.enr.Enr;
import com.jaeckel.ethp2p.core.types.BlockHeader;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.rlp.RLP;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The EL-A1 conformance corpus ({@code rust/testdata/el/core/}): header RLP vectors,
 * ENR vectors, and key/signing/ECDH/fork-id pins shared with the Rust {@code myotis-core}
 * crate ({@code tests/el_conformance.rs}). Same discipline as {@code LcVectorConformanceTest}:
 * ONE set of files on disk, replayed byte-identically by both languages against ONE
 * {@code expected.txt}.
 *
 * <p>Regenerating (writes the vector files AND expected.txt — the vectors here are
 * synthetic/deterministic, unlike the live-captured LC corpus):
 * {@code ./gradlew :networking:test --tests "*ElCoreVectorConformanceTest*"
 * -Dmyotis.el.writeExpected=true} — then review the diff like any golden change.
 *
 * <p>Lives in {@code :networking} (not {@code :core}) because the fork-id pins are
 * asserted against {@link NetworkConfig}, which {@code :core} cannot see.
 */
class ElCoreVectorConformanceTest {

    static {
        // Tuweni's KECCAK-256 needs the BouncyCastle JCA provider, and the
        // deterministic key/message constants below hash during <clinit> —
        // before any class that registers it (NodeKey) gets loaded.
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /** Corpus location, relative to the :networking module dir Gradle runs tests in. */
    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "core");

    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    // Deterministic key/message material — derivation strings duplicated verbatim
    // in the Rust test; change them only in lockstep.
    private static final Bytes32 SECRET_1 = Hash.keccak256(utf8("myotis-el-a1:secret-1"));
    private static final Bytes32 SECRET_2 = Hash.keccak256(utf8("myotis-el-a1:secret-2"));
    private static final Bytes32 MSG_HASH = Hash.keccak256(utf8("myotis-el-a1:message"));

    /** keccak256(RLP([])) — the canonical empty-ommers hash, for realistic headers. */
    private static final Bytes32 EMPTY_OMMERS = Bytes32.fromHexString(
            "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            generateVectors();
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/core conformance corpus not present at " + CORPUS.toAbsolutePath());
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

        // --- headers ---
        for (Path p : listSorted("header", ".rlp")) {
            String base = baseName(p);
            Bytes rlp = Bytes.wrap(Files.readAllBytes(p));
            try {
                BlockHeader h = BlockHeader.decode(rlp);
                actual.put("header." + base + ".decode", "ok");
                actual.put("header." + base + ".hash", BlockHeader.hash(rlp).toUnprefixedHexString());
                actual.put("header." + base + ".parentHash", h.parentHash.toUnprefixedHexString());
                actual.put("header." + base + ".stateRoot", h.stateRoot.toUnprefixedHexString());
                actual.put("header." + base + ".transactionsRoot", h.transactionsRoot.toUnprefixedHexString());
                actual.put("header." + base + ".receiptsRoot", h.receiptsRoot.toUnprefixedHexString());
                actual.put("header." + base + ".beneficiary", h.beneficiary.toUnprefixedHexString());
                actual.put("header." + base + ".difficulty", h.difficulty.toString(16));
                actual.put("header." + base + ".number", Long.toString(h.number));
                actual.put("header." + base + ".gasLimit", Long.toString(h.gasLimit));
                actual.put("header." + base + ".gasUsed", Long.toString(h.gasUsed));
                actual.put("header." + base + ".timestamp", Long.toString(h.timestamp));
                actual.put("header." + base + ".extraData", h.extraData.toUnprefixedHexString());
                actual.put("header." + base + ".mixHash", h.mixHashOrPrevRandao.toUnprefixedHexString());
                actual.put("header." + base + ".nonce", h.nonce.toUnprefixedHexString());
                actual.put("header." + base + ".baseFee",
                        h.baseFeePerGas != null ? h.baseFeePerGas.toString(16) : "absent");
                actual.put("header." + base + ".withdrawalsRoot",
                        h.withdrawalsRoot != null ? h.withdrawalsRoot.toUnprefixedHexString() : "absent");
                actual.put("header." + base + ".blobGasUsed", Long.toString(h.blobGasUsed));
                actual.put("header." + base + ".excessBlobGas", Long.toString(h.excessBlobGas));
                actual.put("header." + base + ".parentBeaconBlockRoot",
                        h.parentBeaconBlockRoot != null ? h.parentBeaconBlockRoot.toUnprefixedHexString() : "absent");
            } catch (Exception e) {
                actual.put("header." + base + ".decode", "error");
            }
        }

        // --- ENRs ---
        for (Path p : listSorted("enr", ".txt")) {
            String base = baseName(p);
            String enrString = new String(Files.readAllBytes(p), StandardCharsets.UTF_8).strip();
            try {
                Enr enr = Enr.fromEnrString(enrString);
                actual.put("enr." + base + ".decode", "ok");
                actual.put("enr." + base + ".seq", Long.toString(enr.seq()));
                Bytes ip = enr.pairs().get("ip");
                actual.put("enr." + base + ".ip", ip != null ? ip.toUnprefixedHexString() : "absent");
                actual.put("enr." + base + ".tcp", portString(enr.pairs().get("tcp")));
                actual.put("enr." + base + ".udp", portString(enr.pairs().get("udp")));
                Bytes comp = enr.pairs().get("secp256k1");
                actual.put("enr." + base + ".secp256k1",
                        comp != null ? comp.toUnprefixedHexString() : "absent");
                actual.put("enr." + base + ".pubkey", enr.publicKey()
                        .map(k -> k.bytes().toUnprefixedHexString()).orElse("absent"));
                actual.put("enr." + base + ".eth2ForkDigest", enr.eth2()
                        .map(f -> Bytes.wrap(f.forkDigest()).toUnprefixedHexString()).orElse("absent"));
                actual.put("enr." + base + ".ethForkIdHash", enr.ethForkIdHash()
                        .map(f -> Bytes.wrap(f).toUnprefixedHexString()).orElse("absent"));
            } catch (Exception e) {
                actual.put("enr." + base + ".decode", "error");
            }
        }

        // --- keys: identity, signing, recovery, ECDH ---
        NodeKey key1 = NodeKey.fromSecretKey(SECP256K1.SecretKey.fromBytes(SECRET_1));
        NodeKey key2 = NodeKey.fromSecretKey(SECP256K1.SecretKey.fromBytes(SECRET_2));
        actual.put("key.secret1", SECRET_1.toUnprefixedHexString());
        actual.put("key.secret2", SECRET_2.toUnprefixedHexString());
        actual.put("key.msgHash", MSG_HASH.toUnprefixedHexString());
        actual.put("key.pubkey1", key1.publicKeyBytes().toUnprefixedHexString());
        actual.put("key.pubkey2", key2.publicKeyBytes().toUnprefixedHexString());
        actual.put("key.nodeId1", key1.nodeId().toUnprefixedHexString());
        actual.put("key.nodeId2", key2.nodeId().toUnprefixedHexString());
        SECP256K1.Signature sig = key1.sign(MSG_HASH);
        actual.put("key.sig1", Bytes.wrap(encodeSignature(sig)).toUnprefixedHexString());
        SECP256K1.PublicKey recovered =
                SECP256K1.PublicKey.recoverFromHashAndSignature(MSG_HASH, sig);
        actual.put("key.recovered1",
                recovered != null ? recovered.bytes().toUnprefixedHexString() : "error");
        Bytes32 ecdh12 = ecdhX(key1.secretKey(), key2.publicKey());
        Bytes32 ecdh21 = ecdhX(key2.secretKey(), key1.publicKey());
        assertEquals(ecdh12, ecdh21, "ECDH must be symmetric");
        actual.put("key.ecdh", ecdh12.toUnprefixedHexString());

        // --- fork-id pins, asserted against NetworkConfig so neither side drifts ---
        actual.put("forkid.mainnet",
                Bytes.wrap(NetworkConfig.MAINNET.forkIdHash()).toUnprefixedHexString());
        actual.put("forkid.gnosis",
                Bytes.wrap(NetworkConfig.GNOSIS.forkIdHash()).toUnprefixedHexString());
        actual.put("forkid.sepolia",
                Bytes.wrap(NetworkConfig.SEPOLIA.forkIdHash()).toUnprefixedHexString());
        actual.put("forkid.forkNext.mainnet", Long.toString(NetworkConfig.MAINNET.forkNext()));
        actual.put("forkid.forkNext.gnosis", Long.toString(NetworkConfig.GNOSIS.forkNext()));
        actual.put("forkid.forkNext.sepolia", Long.toString(NetworkConfig.SEPOLIA.forkNext()));

        if (WRITE) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/core — generated by\n"
                            + "# ElCoreVectorConformanceTest with -Dmyotis.el.writeExpected=true.\n"
                            + "# The Rust myotis-core crate must reproduce these from the same bytes.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-conformance] wrote " + CORPUS.resolve("expected.txt"));
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
    // Vector generation (writeExpected mode only) — synthetic and deterministic.
    // -------------------------------------------------------------------------

    private static void generateVectors() throws Exception {
        // Headers across the fork eras (docs/reimplementation/02 §1.2), plus
        // tolerance and negative cases.
        writeVector("001-header-frontier.rlp", header("frontier", 15));
        writeVector("002-header-london.rlp", header("london", 16));
        writeVector("003-header-shanghai.rlp", header("shanghai", 17));
        writeVector("004-header-cancun.rlp", header("cancun", 20));
        writeVector("005-header-prague.rlp", header("prague", 21));      // + requestsHash (read-and-discarded)
        writeVector("006-header-future-extra.rlp", header("future", 22)); // + unknown trailing fields (tolerated)
        // Materialize before slicing — slicing Tuweni ConcatenatedBytes trips
        // "element sizes do not match total size" in toArray().
        writeVector("090-header-truncated.rlp",
                Bytes.wrap(header("cancun", 20).toArray()).slice(0, 100)); // cut → decode error
        writeVector("091-header-nonlist.rlp", RLP.encodeValue(utf8("dog"))); // not a list → error
        writeVector("092-header-short-stateroot.rlp", brokenStateRootHeader()); // 31-byte root → error
        // Trailing garbage after the header list — both decoders reject (the
        // hash covers the whole input, so slack bytes must not slip through).
        byte[] full = header("cancun", 20).toArray();
        byte[] withTrailing = java.util.Arrays.copyOf(full, full.length + 1);
        writeVector("093-header-trailing-byte.rlp", Bytes.wrap(withTrailing));
        // A LIST in the requestsHash slot (field 21) — readValue/as_bytes reject.
        writeVector("094-header-list-in-requests-slot.rlp",
                header("cancun", 20, w -> w.writeList(l -> { })));
        // 8-byte high-bit blobGasUsed: signed readLong would yield -1 (the
        // "absent" sentinel!) — both sides reject the signed-overflow range.
        writeVector("095-header-negative-blobgas.rlp",
                header("cancun", 17, w -> w.writeValue(Bytes.fromHexString("ffffffffffffffff"))));

        // ENRs: the EIP-778 example, a real Gnosis discv5 bootnode (CL eth2 field),
        // a synthetic EL record with the list-valued "eth" fork-id field, negatives.
        writeVector("001-enr-eip778.txt", utf8(
                "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj4"
                        + "99SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2"
                        + "_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"));
        writeVector("002-enr-gnosis-bootnode.txt",
                utf8(NetworkConfig.GNOSIS.clDiscv5Bootnodes().get(0)));
        writeVector("003-enr-el-eth.txt", utf8(syntheticElEnr()));
        // Non-minimal 3-byte tcp port: rejected as a port on BOTH sides
        // (reported absent) — pins the strict 1-2-byte rule (geth-parity;
        // the record itself still decodes).
        writeVector("004-enr-wide-port.txt", utf8("enr:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        RLP.encodeList(w -> {
                            w.writeValue(Bytes.wrap(new byte[64])); // dummy signature
                            w.writeLong(3);                          // seq
                            w.writeString("id");
                            w.writeString("v4");
                            w.writeString("ip");
                            w.writeValue(Bytes.wrap(new byte[]{(byte) 192, 0, 2, 2}));
                            w.writeString("tcp");
                            w.writeValue(Bytes.fromHexString("00751f")); // 3-byte port
                            w.writeString("udp");
                            w.writeLong(30303);
                        }).toArrayUnsafe())));
        writeVector("090-enr-nonlist.txt", utf8("enr:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        RLP.encodeValue(utf8("dog")).toArrayUnsafe())));
        writeVector("091-enr-dangling-key.txt", utf8("enr:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        RLP.encodeList(w -> {
                            w.writeValue(Bytes.wrap(new byte[64])); // signature
                            w.writeLong(1);                          // seq
                            w.writeString("id");                     // key without value
                        }).toArrayUnsafe())));
        // Trailing byte after the record list — both decoders reject.
        byte[] record = Base64.getUrlDecoder().decode(
                new String(Files.readAllBytes(CORPUS.resolve("001-enr-eip778.txt")),
                        StandardCharsets.UTF_8).strip().substring(4));
        byte[] recordTrailing = java.util.Arrays.copyOf(record, record.length + 1);
        writeVector("092-enr-trailing-byte.txt", utf8("enr:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(recordTrailing)));
        // Wrong-count base64url padding ("QQ=") — both text decoders reject.
        writeVector("093-enr-bad-padding.txt", utf8("enr:QQ="));
    }

    /**
     * Deterministic synthetic header for a fork era; {@code fields} selects how much
     * of the optional tail is present (15 = pre-London … 20 = Cancun, 21 = +requestsHash,
     * 22 = +unknown trailing field).
     */
    private static Bytes header(String era, int fields) {
        return header(era, fields, null);
    }

    private static Bytes header(String era, int fields,
                                java.util.function.Consumer<org.apache.tuweni.rlp.RLPWriter> tail) {
        boolean postMerge = fields >= 17;
        return RLP.encodeList(w -> {
            w.writeValue(tag32(era, "parentHash"));
            w.writeValue(EMPTY_OMMERS);
            w.writeValue(tag32(era, "beneficiary").slice(0, 20));
            w.writeValue(tag32(era, "stateRoot"));
            w.writeValue(tag32(era, "transactionsRoot"));
            w.writeValue(tag32(era, "receiptsRoot"));
            w.writeValue(Bytes.wrap(new byte[256])); // logsBloom
            w.writeBigInteger(postMerge ? BigInteger.ZERO : new BigInteger("17179869184"));
            w.writeLong(switch (era) {
                case "frontier" -> 46_147L;
                case "london" -> 12_965_000L;
                case "shanghai" -> 17_034_870L;
                case "cancun" -> 19_426_587L;
                default -> 22_431_084L;
            });
            w.writeLong(30_000_000L); // gasLimit
            w.writeLong(14_838_935L); // gasUsed
            w.writeLong(1_700_000_000L + era.length()); // timestamp (deterministic per era)
            w.writeValue(era.equals("cancun") ? Bytes.EMPTY : utf8("myotis-" + era)); // extraData
            w.writeValue(tag32(era, "mixHash"));
            w.writeValue(postMerge ? Bytes.wrap(new byte[8]) : tag32(era, "nonce").slice(0, 8));
            if (fields >= 16) w.writeBigInteger(new BigInteger("1000000000")); // baseFee: 1 gwei
            if (fields >= 17) w.writeValue(tag32(era, "withdrawalsRoot"));
            if (fields >= 18) w.writeLong(0L);        // blobGasUsed = 0 (zero-scalar encoding)
            if (fields >= 19) w.writeLong(393_216L);  // excessBlobGas
            if (fields >= 20) w.writeValue(tag32(era, "parentBeaconBlockRoot"));
            if (fields >= 21) w.writeValue(tag32(era, "requestsHash"));
            if (fields >= 22) w.writeValue(utf8("unknown-future-field"));
            if (tail != null) tail.accept(w);
        });
    }

    /** A Cancun-shaped header whose stateRoot is 31 bytes — must fail decode. */
    private static Bytes brokenStateRootHeader() {
        return RLP.encodeList(w -> {
            w.writeValue(tag32("broken", "parentHash"));
            w.writeValue(EMPTY_OMMERS);
            w.writeValue(tag32("broken", "beneficiary").slice(0, 20));
            w.writeValue(tag32("broken", "stateRoot").slice(0, 31)); // ← wrong size
            w.writeValue(tag32("broken", "transactionsRoot"));
            w.writeValue(tag32("broken", "receiptsRoot"));
            w.writeValue(Bytes.wrap(new byte[256]));
            w.writeBigInteger(BigInteger.ZERO);
            w.writeLong(1L);
            w.writeLong(30_000_000L);
            w.writeLong(0L);
            w.writeLong(1_700_000_000L);
            w.writeValue(Bytes.EMPTY);
            w.writeValue(tag32("broken", "mixHash"));
            w.writeValue(Bytes.wrap(new byte[8]));
        });
    }

    /**
     * Synthetic EL ENR carrying the list-valued {@code eth} fork-id field (EIP-868):
     * {@code eth = [[fork_hash, fork_next]]}. Signature bytes are dummies — the
     * decode path deliberately does not verify them (docs/reimplementation/02 §1.3).
     */
    private static String syntheticElEnr() {
        NodeKey key1 = NodeKey.fromSecretKey(SECP256K1.SecretKey.fromBytes(SECRET_1));
        byte[] compressed = compress(key1.publicKey());
        Bytes record = RLP.encodeList(w -> {
            w.writeValue(Bytes.concatenate(
                    Hash.keccak256(utf8("myotis-el-a1:enr-sig-a")),
                    Hash.keccak256(utf8("myotis-el-a1:enr-sig-b")))); // dummy 64-byte signature
            w.writeLong(7); // seq
            // Pairs in sorted key order (EIP-778): eth, id, ip, secp256k1, tcp, udp.
            w.writeString("eth");
            w.writeList(outer -> outer.writeList(tuple -> {
                tuple.writeValue(Bytes.wrap(NetworkConfig.MAINNET.forkIdHash()));
                tuple.writeLong(NetworkConfig.MAINNET.forkNext());
            }));
            w.writeString("id");
            w.writeString("v4");
            w.writeString("ip");
            w.writeValue(Bytes.wrap(new byte[]{(byte) 192, 0, 2, 1})); // TEST-NET-1
            w.writeString("secp256k1");
            w.writeValue(Bytes.wrap(compressed));
            w.writeString("tcp");
            w.writeLong(30303);
            w.writeString("udp");
            w.writeLong(30303);
        });
        return "enr:" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(record.toArrayUnsafe());
    }

    // -------------------------------------------------------------------------
    // Helpers.
    // -------------------------------------------------------------------------

    private static void writeVector(String name, Bytes content) throws Exception {
        Files.write(CORPUS.resolve(name), content.toArrayUnsafe());
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

    private static String portString(Bytes port) {
        // 1-2 bytes big-endian, else absent — the Enr.address() / Rust port()
        // rule (wider-than-u16 encodings are rejected, matching geth).
        if (port == null || port.size() < 1 || port.size() > 2) return "absent";
        return Integer.toString(port.toInt());
    }

    /** 32 deterministic bytes tagged by era + field name. */
    private static Bytes32 tag32(String era, String field) {
        return Hash.keccak256(utf8("myotis-el-a1:" + era + ":" + field));
    }

    private static Bytes utf8(String s) {
        return Bytes.wrap(s.getBytes(StandardCharsets.UTF_8));
    }

    /** 65-byte r ‖ s ‖ v signature encoding (v = recovery id 0/1) — as Packet does. */
    private static byte[] encodeSignature(SECP256K1.Signature sig) {
        byte[] out = new byte[65];
        byte[] r = sig.r().toByteArray();
        byte[] s = sig.s().toByteArray();
        int rOff = Math.max(0, r.length - 32);
        int sOff = Math.max(0, s.length - 32);
        System.arraycopy(r, rOff, out, 32 - Math.min(r.length, 32), Math.min(r.length, 32));
        System.arraycopy(s, sOff, out, 64 - Math.min(s.length, 32), Math.min(s.length, 32));
        out[64] = (byte) sig.v();
        return out;
    }

    /** Compress a Tuweni public key to the 33-byte SEC1 form. */
    private static byte[] compress(SECP256K1.PublicKey key) {
        var params = SECNamedCurves.getByName("secp256k1");
        var curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(key.bytes().toArrayUnsafe(), 0, uncompressed, 1, 64);
        return curve.getCurve().decodePoint(uncompressed).getEncoded(true);
    }

    /** ECDH x-coordinate as 32-byte big-endian — mirrors AuthHandshake's private helper. */
    private static Bytes32 ecdhX(SECP256K1.SecretKey priv, SECP256K1.PublicKey pub) {
        var params = SECNamedCurves.getByName("secp256k1");
        var curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        var privParams = new ECPrivateKeyParameters(
                new BigInteger(1, priv.bytes().toArrayUnsafe()), curve);
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(pub.bytes().toArrayUnsafe(), 0, uncompressed, 1, 64);
        var pubParams = new ECPublicKeyParameters(
                curve.getCurve().decodePoint(uncompressed), curve);
        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privParams);
        BigInteger result = agreement.calculateAgreement(pubParams);
        byte[] bytes = result.toByteArray();
        byte[] out = new byte[32];
        if (bytes.length >= 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return Bytes32.wrap(out);
    }
}
