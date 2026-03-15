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
 * Unit tests for {@link FrameCodec}, focusing on frame-level guardrails.
 */
class FrameCodecTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Verify that decodeHeader rejects frames whose body length exceeds MAX_FRAME_BODY_SIZE.
     * This guards against resource exhaustion from oversized frame bodies.
     */
    @Test
    void decodeHeader_rejectsOversizedFrameBody() {
        // Set up a valid codec pair via a random handshake
        FrameCodec[] codecs = createCodecPair();
        FrameCodec initiatorCodec = codecs[0];
        FrameCodec responderCodec = codecs[1];

        // Encode a frame with body size = MAX_FRAME_BODY_SIZE (payload that, with the
        // 1-byte RLP message code prefix, produces bodyLen = MAX_FRAME_BODY_SIZE + 1).
        // Using messageCode 0x00 (Hello) to skip Snappy compression.
        byte[] oversizedPayload = new byte[FrameCodec.MAX_FRAME_BODY_SIZE];
        byte[] encodedFrame = initiatorCodec.encodeFrame(0x00, oversizedPayload);

        // Extract header and header MAC
        byte[] encHeader = Arrays.copyOfRange(encodedFrame, 0, 16);
        byte[] headerMac = Arrays.copyOfRange(encodedFrame, 16, 32);

        // decodeHeader must throw because bodyLen (MAX_FRAME_BODY_SIZE + 1) exceeds the limit
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> responderCodec.decodeHeader(encHeader, headerMac));
        assertTrue(ex.getMessage().contains("exceeds maximum"),
            "Exception message should mention the size limit, got: " + ex.getMessage());
    }

    /**
     * Verify that decodeHeader accepts frames at exactly MAX_FRAME_BODY_SIZE.
     */
    @Test
    void decodeHeader_acceptsFrameAtMaxSize() {
        FrameCodec[] codecs = createCodecPair();
        FrameCodec initiatorCodec = codecs[0];
        FrameCodec responderCodec = codecs[1];

        // bodyLen = rlpCode(1) + payload.length = 1 + (MAX - 1) = MAX → exactly at limit
        byte[] maxPayload = new byte[FrameCodec.MAX_FRAME_BODY_SIZE - 1];
        byte[] encodedFrame = initiatorCodec.encodeFrame(0x00, maxPayload);

        byte[] encHeader = Arrays.copyOfRange(encodedFrame, 0, 16);
        byte[] headerMac = Arrays.copyOfRange(encodedFrame, 16, 32);

        int bodyLen = assertDoesNotThrow(
            () -> responderCodec.decodeHeader(encHeader, headerMac),
            "Frame at exactly MAX_FRAME_BODY_SIZE should be accepted");
        assertEquals(FrameCodec.MAX_FRAME_BODY_SIZE, bodyLen);
    }

    /**
     * Creates a matched initiator/responder FrameCodec pair using a random handshake.
     */
    private FrameCodec[] createCodecPair() {
        NodeKey aNodeKey = NodeKey.generate();
        SECP256K1.KeyPair bStaticKP = SECP256K1.KeyPair.random();
        SECP256K1.KeyPair bEphKP = SECP256K1.KeyPair.random();
        Bytes32 bNonce = randomBytes32();

        AuthHandshake initiator = new AuthHandshake(aNodeKey, bStaticKP.publicKey());
        Bytes authWire = initiator.buildAuthMessage();
        byte[] authWireBytes = authWire.toArrayUnsafe();

        Bytes ackBody = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeValue(bEphKP.publicKey().bytes());
            w.writeValue(bNonce);
            w.writeInt(4);
        });
        int ackEncBodySize = ackBody.size() + 65 + 16 + 32;
        byte[] ackSizeBytes = {(byte) (ackEncBodySize >> 8), (byte) (ackEncBodySize & 0xFF)};
        Bytes ackEncBody = EciesCodec.encrypt(ackBody, aNodeKey.publicKey(), ackSizeBytes);
        byte[] ackWire = Bytes.concatenate(Bytes.wrap(ackSizeBytes), ackEncBody).toArrayUnsafe();

        initiator.processAck(ackEncBody, ackSizeBytes, ackWire);
        SessionSecrets secrets = initiator.secrets();

        FrameCodec initiatorCodec = new FrameCodec(secrets);
        SessionSecrets responderSecrets = new SessionSecrets(
            secrets.aesSecret(),
            secrets.macSecret(),
            bNonce,
            secrets.egressNonce(),
            ackWire,
            authWireBytes
        );
        FrameCodec responderCodec = new FrameCodec(responderSecrets);

        return new FrameCodec[]{initiatorCodec, responderCodec};
    }

    private static Bytes32 randomBytes32() {
        byte[] b = new byte[32];
        new java.security.SecureRandom().nextBytes(b);
        return Bytes32.wrap(b);
    }
}
