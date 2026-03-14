package com.jaeckel.ethp2p.networking.rlpx;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import org.xerial.snappy.Snappy;

import java.io.IOException;
import java.util.Arrays;

/**
 * RLPx frame codec (AES-256-CTR + Keccak-256 MAC).
 *
 * Frame format:
 *   header(16) | header-mac(16) | body(padded to 16) | body-mac(16)
 *
 * Header (first 16 bytes, encrypted):
 *   body-size(3) | header-data(RLP) | padding
 *
 * MAC state machine (go-ethereum compatible):
 *   For initiator:
 *     egress-mac  = keccak(mac-secret XOR resp-nonce  || auth-wire-bytes)
 *     ingress-mac = keccak(mac-secret XOR init-nonce  || ack-wire-bytes)
 *
 *   Header MAC = updateMac(mac, encHeader)
 *     where updateMac(mac, seed):
 *       aesbuf = AES-256-ECB(keccak_digest[:16]) XOR seed[:16]
 *       mac.update(aesbuf)
 *       return mac.digest[:16]
 *
 *   Body MAC:
 *       mac.update(encBody)
 *       bodyMac = updateMac(mac, mac.digest[:16])
 *
 * Reference: ethereum/devp2p/rlpx.md, go-ethereum p2p/rlpx/rlpx.go
 */
public final class FrameCodec {

    public static final int MAX_FRAME_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

    private final StreamCipher encryptCipher;  // AES-256-CTR for outgoing
    private final StreamCipher decryptCipher;  // AES-256-CTR for incoming

    private final KeccakMacState egressMac;
    private final KeccakMacState ingressMac;

    public FrameCodec(SessionSecrets secrets) {
        byte[] zeroIv = new byte[16];

        // Egress cipher (for sending)
        SICBlockCipher encCtr = new SICBlockCipher(new AESEngine());
        encCtr.init(true, new ParametersWithIV(new KeyParameter(secrets.aesSecret().toArrayUnsafe()), zeroIv));
        this.encryptCipher = encCtr;

        // Ingress cipher (for receiving)
        SICBlockCipher decCtr = new SICBlockCipher(new AESEngine());
        decCtr.init(false, new ParametersWithIV(new KeyParameter(secrets.aesSecret().toArrayUnsafe()), zeroIv));
        this.decryptCipher = decCtr;

        byte[] macSecret = secrets.macSecret().toArrayUnsafe();
        byte[] localNonce  = secrets.egressNonce().toArrayUnsafe();   // init-nonce
        byte[] remoteNonce = secrets.ingressNonce().toArrayUnsafe();  // resp-nonce

        // egress-mac:  keccak(mac-secret XOR resp-nonce || auth-wire-bytes)   [initiator]
        byte[] egressSeed = xor(macSecret, remoteNonce);
        this.egressMac = new KeccakMacState(egressSeed, macSecret, secrets.authWireBytes());

        // ingress-mac: keccak(mac-secret XOR init-nonce || ack-wire-bytes)    [initiator]
        byte[] ingressSeed = xor(macSecret, localNonce);
        this.ingressMac = new KeccakMacState(ingressSeed, macSecret, secrets.ackWireBytes());

    }

    // -------------------------------------------------------------------------
    // Encode a message into a frame
    // -------------------------------------------------------------------------
    public byte[] encodeFrame(int messageCode, byte[] body) {
        // Snappy-compress payload for all messages except Hello (0x00)
        byte[] payload = body;
        if (messageCode != 0x00) {
            try {
                payload = Snappy.compress(body);
            } catch (IOException e) {
                throw new IllegalStateException("Snappy compress failed", e);
            }
        }

        // RLP message code prefix (msg-id is an RLP-encoded integer per devp2p spec)
        // RLP integer encoding: 0 → 0x80 (empty string), 1-127 → single byte, 128+ → 0x81+ prefix
        byte[] rlpCode;
        if (messageCode == 0) {
            rlpCode = new byte[]{(byte) 0x80}; // canonical RLP encoding of integer 0
        } else if (messageCode < 0x80) {
            rlpCode = new byte[]{(byte) messageCode};
        } else {
            rlpCode = org.apache.tuweni.rlp.RLP.encodeInt(messageCode).toArrayUnsafe();
        }
        byte[] codedBody = new byte[rlpCode.length + payload.length];
        System.arraycopy(rlpCode, 0, codedBody, 0, rlpCode.length);
        System.arraycopy(payload, 0, codedBody, rlpCode.length, payload.length);

        int bodyLen = codedBody.length;
        int paddedBodyLen = (bodyLen + 15) & ~15;
        byte[] paddedBody = Arrays.copyOf(codedBody, paddedBodyLen);

        // Build header (16 bytes): body-size(3) | RLP([]) (0xc0) | padding(zeros)
        byte[] header = new byte[16];
        header[0] = (byte) ((bodyLen >> 16) & 0xFF);
        header[1] = (byte) ((bodyLen >> 8) & 0xFF);
        header[2] = (byte) (bodyLen & 0xFF);
        header[3] = (byte) 0xc0; // RLP empty list

        // Encrypt header
        byte[] encHeader = new byte[16];
        encryptCipher.processBytes(header, 0, 16, encHeader, 0);

        // Header MAC: updateMac(egressMac, encHeader)
        byte[] headerMac = egressMac.updateMac(encHeader);

        // Encrypt body
        byte[] encBody = new byte[paddedBodyLen];
        encryptCipher.processBytes(paddedBody, 0, paddedBodyLen, encBody, 0);

        // Body MAC: first update with encBody, then updateMac(egressMac, digest[:16])
        egressMac.updateWithData(encBody);
        byte[] bodyMac = egressMac.updateMac(Arrays.copyOf(egressMac.currentDigest(), 16));

        // Assemble: encHeader | headerMac | encBody | bodyMac
        byte[] frame = new byte[16 + 16 + paddedBodyLen + 16];
        System.arraycopy(encHeader, 0, frame, 0, 16);
        System.arraycopy(headerMac, 0, frame, 16, 16);
        System.arraycopy(encBody, 0, frame, 32, paddedBodyLen);
        System.arraycopy(bodyMac, 0, frame, 32 + paddedBodyLen, 16);
        return frame;
    }

    // -------------------------------------------------------------------------
    // Decode a frame header: verifies MAC, returns body length
    // -------------------------------------------------------------------------
    public int decodeHeader(byte[] encHeader, byte[] headerMac) {
        // Verify header MAC
        byte[] expectedMac = ingressMac.updateMac(encHeader);
        if (!Arrays.equals(headerMac, expectedMac)) {
            throw new IllegalStateException("Header MAC mismatch");
        }
        // Decrypt header
        byte[] header = new byte[16];
        decryptCipher.processBytes(encHeader, 0, 16, header, 0);
        int bodyLen = ((header[0] & 0xFF) << 16) | ((header[1] & 0xFF) << 8) | (header[2] & 0xFF);
        if (bodyLen > MAX_FRAME_BODY_SIZE) {
            throw new IllegalArgumentException("Frame body size " + bodyLen + " exceeds maximum " + MAX_FRAME_BODY_SIZE);
        }
        return bodyLen;
    }

    /** Decode frame body: verifies MAC, returns decoded message. */
    public DecodeResult decodeBody(byte[] encBody, byte[] bodyMac, int bodyLen) {
        // Update MAC with encrypted body, then verify
        ingressMac.updateWithData(encBody);
        byte[] expectedBodyMac = ingressMac.updateMac(Arrays.copyOf(ingressMac.currentDigest(), 16));
        if (!Arrays.equals(bodyMac, expectedBodyMac)) {
            throw new IllegalStateException("Body MAC mismatch");
        }
        byte[] body = new byte[encBody.length];
        decryptCipher.processBytes(encBody, 0, encBody.length, body, 0);

        // First byte(s) = RLP-encoded message code
        int code;
        int offset;
        if ((body[0] & 0xFF) < 0x80) {
            code = body[0] & 0xFF;
            offset = 1;
        } else {
            int lenOfLen = (body[0] & 0xFF) - 0x80;
            code = 0;
            for (int i = 0; i < lenOfLen; i++) {
                code = (code << 8) | (body[1 + i] & 0xFF);
            }
            offset = 1 + lenOfLen;
        }
        byte[] payload = Arrays.copyOfRange(body, offset, bodyLen);
        // Snappy-decompress payload for all messages except Hello (0x00).
        // Some peers send p2p control messages (Disconnect, Ping, Pong) without
        // Snappy compression, so fall back to raw payload if decompression fails.
        if (code != 0x00 && payload.length > 0) {
            try {
                payload = Snappy.uncompress(payload);
            } catch (IOException e) {
                // Not Snappy-compressed; use raw payload (common for Disconnect/Ping/Pong)
            }
        }
        return new DecodeResult(code, payload);
    }

    public record DecodeResult(int messageCode, byte[] payload) {}

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------
    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    /**
     * Running Keccak-256 MAC state for RLPx frames (go-ethereum compatible).
     *
     * Initialization: keccak.update(seed) then keccak.update(handshakeCiphertext)
     *
     * updateMac(seed16):
     *   aesbuf = AES-256-ECB(current_digest[:16]) XOR seed[:16]
     *   keccak.update(aesbuf)
     *   return keccak.digest[:16]
     */
    private static final class KeccakMacState {
        private final KeccakDigest mac;         // streaming Keccak-256 state
        private final BlockCipher  aesCipher;   // AES-256 keyed with mac-secret

        KeccakMacState(byte[] seed, byte[] macSecret, byte[] handshakeCiphertext) {
            this.mac = new KeccakDigest(256);
            mac.update(seed, 0, seed.length);
            mac.update(handshakeCiphertext, 0, handshakeCiphertext.length);

            this.aesCipher = new AESEngine();
            aesCipher.init(true, new KeyParameter(macSecret));
        }

        /** Update MAC state with data (e.g., encrypted frame body). */
        void updateWithData(byte[] data) {
            mac.update(data, 0, data.length);
        }

        /**
         * Compute and update MAC using the given 16-byte seed.
         *   aesbuf = AES(current_digest[:16]) XOR seed[:16]
         *   mac.update(aesbuf)
         *   return mac.digest[:16]
         */
        byte[] updateMac(byte[] seed) {
            byte[] digest = currentDigest();    // non-destructive
            byte[] aesbuf = new byte[16];
            aesCipher.processBlock(digest, 0, aesbuf, 0);  // AES-ECB of first 16 bytes
            for (int i = 0; i < 16; i++) aesbuf[i] ^= seed[i];
            mac.update(aesbuf, 0, 16);
            return Arrays.copyOf(currentDigest(), 16);
        }

        /** Return current Keccak-256 digest (32 bytes) without disturbing the state. */
        byte[] currentDigest() {
            KeccakDigest copy = new KeccakDigest(mac);
            byte[] out = new byte[32];
            copy.doFinal(out, 0);
            return out;
        }
    }
}
