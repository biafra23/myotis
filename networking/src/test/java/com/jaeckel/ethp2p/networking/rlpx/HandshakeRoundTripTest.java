package com.jaeckel.ethp2p.networking.rlpx;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end RLPx handshake test using EIP-8 key material.
 *
 * Tests the full flow:
 *   1. Initiator (A) builds auth message
 *   2. Responder (B) decrypts auth (verifies ECIES and format)
 *   3. Responder builds ack
 *   4. Initiator processes ack → derives session secrets
 *   5. Both sides produce matching FrameCodec instances
 *   6. Encoded frame is successfully decoded on the other side
 *
 * Key material from EIP-8 test appendix (https://eips.ethereum.org/EIPS/eip-8):
 *   initiator-static  = 49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee
 *   recipient-static  = b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291
 *   initiator-ephemeral = 869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d
 *   recipient-ephemeral = e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4
 *   initiator-nonce = 7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6
 *   recipient-nonce = 559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
 */
class HandshakeRoundTripTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // EIP-8 static private keys
    private static final Bytes32 A_STATIC_PRIV = Bytes32.fromHexString(
        "49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee");
    private static final Bytes32 B_STATIC_PRIV = Bytes32.fromHexString(
        "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    // EIP-8 ephemeral private keys
    private static final Bytes32 A_EPH_PRIV = Bytes32.fromHexString(
        "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d");
    private static final Bytes32 B_EPH_PRIV = Bytes32.fromHexString(
        "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4");
    // EIP-8 nonces
    private static final Bytes32 A_NONCE = Bytes32.fromHexString(
        "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6");
    private static final Bytes32 B_NONCE = Bytes32.fromHexString(
        "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd");

    /**
     * Full handshake round-trip: auth → ack → session secrets → frame encode/decode.
     */
    @Test
    void fullHandshakeRoundTrip() {
        // Build key material
        SECP256K1.SecretKey aStaticPriv = SECP256K1.SecretKey.fromBytes(A_STATIC_PRIV);
        SECP256K1.SecretKey bStaticPriv = SECP256K1.SecretKey.fromBytes(B_STATIC_PRIV);
        SECP256K1.KeyPair aEphKP = SECP256K1.KeyPair.fromSecretKey(SECP256K1.SecretKey.fromBytes(A_EPH_PRIV));
        SECP256K1.KeyPair bEphKP = SECP256K1.KeyPair.fromSecretKey(SECP256K1.SecretKey.fromBytes(B_EPH_PRIV));

        NodeKey aNodeKey = NodeKey.fromSecretKey(aStaticPriv);
        SECP256K1.KeyPair bStaticKP = SECP256K1.KeyPair.fromSecretKey(bStaticPriv);

        // ---------------------------------------------------------------
        // STEP 1: A builds auth message with known ephemeral key + nonce
        // ---------------------------------------------------------------
        AuthHandshake initiator = new AuthHandshake(aNodeKey, bStaticKP.publicKey(), aEphKP, A_NONCE);
        Bytes authWire = initiator.buildAuthMessage();

        byte[] authWireBytes = authWire.toArrayUnsafe();
        assertTrue(authWireBytes.length > 200,
            "auth wire must be at least 200 bytes, got " + authWireBytes.length);
        // EIP-8 format: first byte is NOT 0x04 (it's the high byte of the 2-byte size)
        assertNotEquals(0x04, authWireBytes[0] & 0xFF,
            "EIP-8 auth must start with size prefix, not 0x04");

        // ---------------------------------------------------------------
        // STEP 2: B decrypts auth (verifies ECIES and message format)
        // ---------------------------------------------------------------
        byte[] authAad = {authWireBytes[0], authWireBytes[1]};
        Bytes authEncBody = Bytes.wrap(authWireBytes, 2, authWireBytes.length - 2);

        Bytes authPlain = assertDoesNotThrow(
            () -> EciesCodec.decrypt(authEncBody, bStaticPriv, authAad),
            "B must be able to ECIES-decrypt A's auth message");

        // First byte of decrypted auth should be an RLP long-list marker (>= 0xF8)
        // because the list is sig(65)+pub(64)+nonce(32)+ver(1)+padding(100+)
        assertTrue((authPlain.get(0) & 0xFF) >= 0xF8,
            String.format("Decrypted auth must be an RLP long-list (>= 0xF8), got 0x%02X",
                authPlain.get(0) & 0xFF));

        // ---------------------------------------------------------------
        // STEP 3: B builds ack = ECIES([bEph.pub(64), bNonce(32), version(4)])
        //         encrypted to A's static public key, with EIP-8 size AAD
        // ---------------------------------------------------------------
        Bytes ackBody = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeValue(bEphKP.publicKey().bytes()); // 64 bytes (no prefix)
            w.writeValue(B_NONCE);
            w.writeInt(4); // RLPx version 4
        });
        int ackEncBodySize = ackBody.size() + 65 + 16 + 32; // ephPub + IV + ciphertext + MAC
        byte[] ackSizeBytes = {(byte) (ackEncBodySize >> 8), (byte) (ackEncBodySize & 0xFF)};
        Bytes ackEncBody = EciesCodec.encrypt(ackBody, aNodeKey.publicKey(), ackSizeBytes);
        byte[] ackWire = Bytes.concatenate(Bytes.wrap(ackSizeBytes), ackEncBody).toArrayUnsafe();

        System.out.printf("[handshake-test] auth wire: %d bytes, ack wire: %d bytes%n",
            authWireBytes.length, ackWire.length);

        // ---------------------------------------------------------------
        // STEP 4: A processes ack → derives session secrets
        // ---------------------------------------------------------------
        assertDoesNotThrow(
            () -> initiator.processAck(ackEncBody, ackSizeBytes, ackWire),
            "Initiator must process ack without error");

        SessionSecrets secrets = assertDoesNotThrow(initiator::secrets);
        assertNotNull(secrets.aesSecret(), "aes-secret must not be null");
        assertNotNull(secrets.macSecret(), "mac-secret must not be null");
        assertEquals(32, secrets.aesSecret().size(), "aes-secret must be 32 bytes");
        assertEquals(32, secrets.macSecret().size(), "mac-secret must be 32 bytes");
        // Secrets must be non-trivial (not all zeros)
        assertFalse(secrets.aesSecret().isZero(), "aes-secret must not be all-zeros");
        assertFalse(secrets.macSecret().isZero(), "mac-secret must not be all-zeros");
        assertNotEquals(secrets.aesSecret(), secrets.macSecret(),
            "aes-secret and mac-secret must differ");

        System.out.printf("[handshake-test] aes-secret: %s%n", secrets.aesSecret().toHexString());
        System.out.printf("[handshake-test] mac-secret: %s%n", secrets.macSecret().toHexString());

        // ---------------------------------------------------------------
        // STEP 5: Verify FrameCodec encode/decode round-trip
        //
        // Initiator codec: egress → towards responder, ingress ← from responder
        // Responder codec: needs swapped nonces and swapped auth/ack bytes
        //   egressNonce  = B_NONCE (B's own nonce, used for: keccak(mac-secret ^ A_NONCE || ackWire))
        //   ingressNonce = A_NONCE
        //   authWireBytes = ackWire  (what B sent)
        //   ackWireBytes  = authWire (what B received)
        // ---------------------------------------------------------------
        FrameCodec initiatorCodec = new FrameCodec(secrets);

        SessionSecrets responderSecrets = new SessionSecrets(
            secrets.aesSecret(),
            secrets.macSecret(),
            B_NONCE,          // responder egressNonce = B's own nonce
            A_NONCE,          // responder ingressNonce = A's nonce
            ackWire,          // what responder sent (ack)
            authWireBytes     // what responder received (auth)
        );
        FrameCodec responderCodec = new FrameCodec(responderSecrets);

        // Encode a Hello frame from initiator
        byte[] helloPayload = {(byte) 0xc0}; // RLP empty-list (minimal valid payload)
        byte[] encodedFrame = initiatorCodec.encodeFrame(0x00, helloPayload);

        // Responder decodes the header
        byte[] encHeader = Arrays.copyOfRange(encodedFrame, 0, 16);
        byte[] headerMac  = Arrays.copyOfRange(encodedFrame, 16, 32);
        int bodyLen = assertDoesNotThrow(
            () -> responderCodec.decodeHeader(encHeader, headerMac),
            "Responder must decode frame header successfully");
        assertTrue(bodyLen > 0, "bodyLen must be positive, got " + bodyLen);

        // Responder decodes the body
        int paddedBodyLen = (bodyLen + 15) & ~15;
        byte[] encBody = Arrays.copyOfRange(encodedFrame, 32, 32 + paddedBodyLen);
        byte[] bodyMac  = Arrays.copyOfRange(encodedFrame, 32 + paddedBodyLen,
                                              32 + paddedBodyLen + 16);
        FrameCodec.DecodeResult decoded = assertDoesNotThrow(
            () -> responderCodec.decodeBody(encBody, bodyMac, bodyLen),
            "Responder must decode frame body successfully");

        assertEquals(0x00, decoded.messageCode(), "Message code must be 0x00 (Hello)");
        assertArrayEquals(helloPayload, decoded.payload(),
            "Decoded payload must match original");

        System.out.printf("[handshake-test] Frame round-trip OK: code=0x%02X payload=%d bytes%n",
            decoded.messageCode(), decoded.payload().length);
    }

    /**
     * Verify a fresh random handshake also works end-to-end (non-deterministic keys).
     */
    @Test
    void randomHandshakeRoundTrip() {
        NodeKey aNodeKey = NodeKey.generate();
        SECP256K1.KeyPair bStaticKP = SECP256K1.KeyPair.random();
        SECP256K1.KeyPair bEphKP = SECP256K1.KeyPair.random();
        Bytes32 bNonce = randomBytes32();

        // A builds auth (uses internal random ephemeral key and nonce)
        AuthHandshake initiator = new AuthHandshake(aNodeKey, bStaticKP.publicKey());
        Bytes authWire = initiator.buildAuthMessage();

        // B builds ack
        Bytes ackBody = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeValue(bEphKP.publicKey().bytes());
            w.writeValue(bNonce);
            w.writeInt(4);
        });
        int ackEncBodySize = ackBody.size() + 65 + 16 + 32;
        byte[] ackSizeBytes = {(byte) (ackEncBodySize >> 8), (byte) (ackEncBodySize & 0xFF)};
        Bytes ackEncBody = EciesCodec.encrypt(ackBody, aNodeKey.publicKey(), ackSizeBytes);
        byte[] ackWire = Bytes.concatenate(Bytes.wrap(ackSizeBytes), ackEncBody).toArrayUnsafe();

        // A processes ack
        assertDoesNotThrow(() -> initiator.processAck(ackEncBody, ackSizeBytes, ackWire));
        SessionSecrets secrets = initiator.secrets();

        assertNotNull(secrets.aesSecret());
        assertNotNull(secrets.macSecret());
        assertEquals(32, secrets.aesSecret().size());
        assertEquals(32, secrets.macSecret().size());

        System.out.printf("[random-test] aes-secret: %s%n", secrets.aesSecret().toHexString());
    }

    private static Bytes32 randomBytes32() {
        byte[] b = new byte[32];
        new java.security.SecureRandom().nextBytes(b);
        return Bytes32.wrap(b);
    }
}
