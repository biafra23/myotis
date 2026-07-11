package com.jaeckel.ethp2p.networking;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import com.jaeckel.ethp2p.networking.rlpx.EciesCodec;
import com.jaeckel.ethp2p.networking.rlpx.FrameCodec;
import com.jaeckel.ethp2p.networking.rlpx.SessionSecrets;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The EL-A4 RLPx conformance corpus ({@code rust/testdata/el/rlpx/}) — shared
 * with the Rust {@code myotis-net::el::rlpx}
 * ({@code tests/el_rlpx_conformance.rs}). Three fully-deterministic pins that
 * don't depend on ECIES's live randomness:
 *
 * <ol>
 *   <li><b>ECIES decrypt</b> of the canonical EIP-8 auth vectors (legacy +
 *       EIP-8 form) → the decrypted plaintext. Both languages decrypt the same
 *       committed ciphertext with the same static key.</li>
 *   <li><b>Session-secret derivation</b> from fixed EIP-8 ephemeral keys +
 *       nonces → aes-secret / mac-secret. The channel secrets are a pure
 *       function of the key material, independent of the auth/ack transport
 *       randomness.</li>
 *   <li><b>Frame bytes</b>: with fixed (aes, mac, nonces, auth-wire, ack-wire)
 *       SessionSecrets, {@link FrameCodec} produces byte-identical frames — a
 *       Hello (uncompressed) and a snappy-compressed message — that decode
 *       round-trip on the peer codec.</li>
 * </ol>
 *
 * <p>Regenerate: {@code ./gradlew :networking:test --tests
 * "*ElRlpxVectorConformanceTest*" -Dmyotis.el.writeExpected=true}.
 */
class ElRlpxVectorConformanceTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final Path CORPUS = Path.of("..", "rust", "testdata", "el", "rlpx");
    private static final boolean WRITE = Boolean.getBoolean("myotis.el.writeExpected");

    // EIP-8 test key material (https://eips.ethereum.org/EIPS/eip-8).
    private static final String STATIC_B =
            "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    private static final String STATIC_A =
            "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee";
    private static final String A_EPH =
            "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d";
    private static final String B_EPH =
            "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4";
    private static final String A_NONCE =
            "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6";
    private static final String B_NONCE =
            "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";

    // Canonical EIP-8 auth vectors (from the spec appendix).
    private static final String AUTH1_LEGACY_HEX =
            "048ca79ad18e4b0659fab4853fe5bc58eb83992980f4c9cc147d2aa31532efd29a3d3dc6a3d89eaf"
            + "913150cfc777ce0ce4af2758bf4810235f6e6ceccfee1acc6b22c005e9e3a49d6448610a58e98744"
            + "ba3ac0399e82692d67c1f58849050b3024e21a52c9d3b01d871ff5f210817912773e610443a9ef14"
            + "2e91cdba0bd77b5fdf0769b05671fc35f83d83e4d3b0b000c6b2a1b1bba89e0fc51bf4e460df310"
            + "5c444f14be226458940d6061c296350937ffd5e3acaceeaaefd3c6f74be8e23e0f45163cc7ebd762"
            + "20f0128410fd05250273156d548a414444ae2f7dea4dfca2d43c057adb701a715bf59f6fb66b2d1d"
            + "20f2c703f851cbf5ac47396d9ca65b6260bd141ac4d53e2de585a73d1750780db4c9ee4cd4d22517"
            + "3a4592ee77e2bd94d0be3691f3b406f9bba9b591fc63facc016bfa8";
    private static final String AUTH2_EIP8_HEX =
            "01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b"
            + "0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b849"
            + "634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6c"
            + "da61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc"
            + "147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6"
            + "d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee"
            + "70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09"
            + "c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec3"
            + "6f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e"
            + "2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c"
            + "3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c";

    // Fixed frame-codec material (arbitrary but committed): auth/ack-wire are
    // opaque MAC seeds, so any bytes pin the frame output.
    private static final String FRAME_AES = keccakHex("rlpx:frame:aes");
    private static final String FRAME_MAC = keccakHex("rlpx:frame:mac");
    private static final String FRAME_A_NONCE = keccakHex("rlpx:frame:A-nonce");
    private static final String FRAME_B_NONCE = keccakHex("rlpx:frame:B-nonce");
    private static final byte[] FRAME_AUTH_WIRE = "RLPX-AUTH-WIRE-OPAQUE".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FRAME_ACK_WIRE = "RLPX-ACK-WIRE-OPAQUE".getBytes(StandardCharsets.UTF_8);

    private static Map<String, String> expected;

    @BeforeAll
    static void loadOrPrepare() throws Exception {
        if (WRITE) {
            Files.createDirectories(CORPUS);
            return;
        }
        assumeTrue(Files.isDirectory(CORPUS),
                "el/rlpx conformance corpus not present at " + CORPUS.toAbsolutePath());
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

        // (1) ECIES decrypt of the canonical EIP-8 vectors.
        SECP256K1.SecretKey privB = SECP256K1.SecretKey.fromBytes(Bytes32.fromHexString(STATIC_B));
        byte[] auth1 = hex(AUTH1_LEGACY_HEX);
        Bytes plain1 = EciesCodec.decrypt(Bytes.wrap(auth1), privB, new byte[0]);
        actual.put("ecies.auth1-legacy.plaintext", plain1.toUnprefixedHexString());

        byte[] auth2 = hex(AUTH2_EIP8_HEX);
        byte[] aad2 = {auth2[0], auth2[1]};
        Bytes plain2 = EciesCodec.decrypt(Bytes.wrap(auth2, 2, auth2.length - 2), privB, aad2);
        actual.put("ecies.auth2-eip8.plaintext", plain2.toUnprefixedHexString());

        // (2) Session-secret derivation from the EIP-8 handshake material.
        SessionSecrets derived = deriveInitiatorSecrets();
        actual.put("secrets.aes", derived.aesSecret().toUnprefixedHexString());
        actual.put("secrets.mac", derived.macSecret().toUnprefixedHexString());

        // (3) Frame bytes + round-trip with fixed SessionSecrets.
        SessionSecrets initiator = frameSecrets(true);
        SessionSecrets responder = frameSecrets(false);
        FrameCodec enc = new FrameCodec(initiator);
        FrameCodec dec = new FrameCodec(responder);

        // Hello is uncompressed → the frame bytes are bit-identical across
        // languages (Rust re-encodes and byte-matches). The compressed frame's
        // bytes are NOT pinned — snappy encoders differ (iq80 vs the Rust
        // `snap` crate) — so instead its bytes are committed as a .bin file and
        // the Rust side DECODES Java's actual frame (the real interop proof).
        byte[] helloBody = {(byte) 0xc0}; // Hello, RLP empty list
        byte[] helloFrame = enc.encodeFrame(0x00, helloBody);
        actual.put("frame.hello.bytes", Bytes.wrap(helloFrame).toUnprefixedHexString());
        actual.put("frame.hello.decode", decodeVerdict(dec, helloFrame, 0x00, helloBody));

        byte[] msgBody = new byte[300];
        for (int i = 0; i < msgBody.length; i++) msgBody[i] = (byte) (i & 0xff);
        byte[] msgFrame = enc.encodeFrame(0x10, msgBody); // snappy-compressed
        actual.put("frame.compressed.decode", decodeVerdict(dec, msgFrame, 0x10, msgBody));
        if (WRITE) {
            Files.write(CORPUS.resolve("001-frame-hello.bin"), helloFrame);
            Files.write(CORPUS.resolve("002-frame-compressed.bin"), msgFrame);
        }

        if (WRITE) {
            StringBuilder sb = new StringBuilder(
                    "# Recorded verdicts for rust/testdata/el/rlpx — generated by\n"
                            + "# ElRlpxVectorConformanceTest with -Dmyotis.el.writeExpected=true.\n"
                            + "# The Rust myotis-net::el::rlpx must reproduce these from the same bytes.\n");
            actual.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            Files.write(CORPUS.resolve("expected.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[el-rlpx-conformance] wrote " + CORPUS.resolve("expected.txt"));
            return;
        }

        if (expected.isEmpty()) {
            org.junit.jupiter.api.Assertions.fail(
                    "corpus present but expected.txt missing/empty — regenerate with "
                            + "-Dmyotis.el.writeExpected=true and commit it");
        }
        assertEquals(expected, actual, "replay verdicts diverge from the recorded expected.txt");
    }

    /** Initiator (A) secret derivation from the fixed EIP-8 ephemerals + nonces. */
    private static SessionSecrets deriveInitiatorSecrets() {
        SECP256K1.KeyPair aEph = SECP256K1.KeyPair.fromSecretKey(
                SECP256K1.SecretKey.fromBytes(Bytes32.fromHexString(A_EPH)));
        SECP256K1.KeyPair bEph = SECP256K1.KeyPair.fromSecretKey(
                SECP256K1.SecretKey.fromBytes(Bytes32.fromHexString(B_EPH)));
        Bytes32 aNonce = Bytes32.fromHexString(A_NONCE);
        Bytes32 bNonce = Bytes32.fromHexString(B_NONCE);

        // ephemeral-shared = ECDH(aEph, bEph.pub); mirrors AuthHandshake.deriveSecrets.
        byte[] ephShared = ecdhX(aEph.secretKey(), bEph.publicKey());
        Bytes32 nonceHash = Hash.keccak256(Bytes.concatenate(bNonce, aNonce)); // remote ‖ local
        Bytes32 sharedSecret = Hash.keccak256(Bytes.concatenate(Bytes.wrap(ephShared), nonceHash));
        Bytes32 aes = Hash.keccak256(Bytes.concatenate(Bytes.wrap(ephShared), sharedSecret));
        Bytes32 mac = Hash.keccak256(Bytes.concatenate(Bytes.wrap(ephShared), aes));
        return new SessionSecrets(aes, mac, aNonce, bNonce, new byte[0], new byte[0]);
    }

    private static SessionSecrets frameSecrets(boolean initiator) {
        Bytes32 aes = Bytes32.fromHexString(FRAME_AES);
        Bytes32 mac = Bytes32.fromHexString(FRAME_MAC);
        Bytes32 aNonce = Bytes32.fromHexString(FRAME_A_NONCE);
        Bytes32 bNonce = Bytes32.fromHexString(FRAME_B_NONCE);
        if (initiator) {
            return new SessionSecrets(aes, mac, aNonce, bNonce, FRAME_AUTH_WIRE, FRAME_ACK_WIRE);
        }
        // Responder: swap nonce + auth/ack-wire roles.
        return new SessionSecrets(aes, mac, bNonce, aNonce, FRAME_ACK_WIRE, FRAME_AUTH_WIRE);
    }

    private static String decodeVerdict(FrameCodec dec, byte[] frame, int wantCode, byte[] wantBody) {
        byte[] encHeader = java.util.Arrays.copyOfRange(frame, 0, 16);
        byte[] headerMac = java.util.Arrays.copyOfRange(frame, 16, 32);
        int bodyLen = dec.decodeHeader(encHeader, headerMac);
        int padded = (bodyLen + 15) & ~15;
        byte[] encBody = java.util.Arrays.copyOfRange(frame, 32, 32 + padded);
        byte[] bodyMac = java.util.Arrays.copyOfRange(frame, 32 + padded, 32 + padded + 16);
        FrameCodec.DecodeResult r = dec.decodeBody(encBody, bodyMac, bodyLen);
        boolean ok = r.messageCode() == wantCode
                && java.util.Arrays.equals(r.payload(), wantBody);
        return ok ? "ok" : "MISMATCH";
    }

    /** ECDH x-coordinate as 32-byte big-endian (mirrors the private helpers). */
    private static byte[] ecdhX(SECP256K1.SecretKey priv, SECP256K1.PublicKey pub) {
        var params = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1");
        var curve = new org.bouncycastle.crypto.params.ECDomainParameters(
                params.getCurve(), params.getG(), params.getN());
        var privParams = new org.bouncycastle.crypto.params.ECPrivateKeyParameters(
                new java.math.BigInteger(1, priv.bytes().toArrayUnsafe()), curve);
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(pub.bytes().toArrayUnsafe(), 0, uncompressed, 1, 64);
        var pubParams = new org.bouncycastle.crypto.params.ECPublicKeyParameters(
                curve.getCurve().decodePoint(uncompressed), curve);
        var agreement = new org.bouncycastle.crypto.agreement.ECDHBasicAgreement();
        agreement.init(privParams);
        java.math.BigInteger result = agreement.calculateAgreement(pubParams);
        byte[] b = result.toByteArray();
        byte[] out = new byte[32];
        if (b.length >= 32) System.arraycopy(b, b.length - 32, out, 0, 32);
        else System.arraycopy(b, 0, out, 32 - b.length, b.length);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String keccakHex(String seed) {
        return Hash.keccak256(Bytes.wrap(seed.getBytes(StandardCharsets.UTF_8))).toUnprefixedHexString();
    }
}
