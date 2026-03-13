package com.jaeckel.ethp2p.networking.rlpx;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * RLPx authentication handshake (EIP-8).
 *
 * Implements the initiator side:
 *   1. Generate ephemeral key pair
 *   2. Compute static-shared-secret = ECDH(local-static-key, remote-static-pubkey)
 *   3. Build auth body, sign, ECIES-encrypt → send
 *   4. Receive ECIES-encrypted ack → decrypt
 *   5. Derive session secrets
 *
 * Auth message (EIP-8 RLP format):
 *   [sig(65), pubkey(64), nonce(32), version(4)]
 *
 * Ack message (EIP-8 RLP format):
 *   [ephemeral-pubkey(64), nonce(32), version(4)]
 */
public final class AuthHandshake {

    private static final X9ECParameters CURVE_PARAMS = SECNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
        CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

    private final NodeKey localKey;
    private final SECP256K1.PublicKey remotePubkey;
    private final SECP256K1.KeyPair ephemeralKey;
    private final Bytes32 localNonce;

    // Populated after receiving ack
    private SECP256K1.PublicKey remoteEphemeralKey;
    private Bytes32 remoteNonce;

    // Full wire bytes for MAC initialization
    private byte[] authWireBytes;
    private byte[] ackWireBytes;

    private SessionSecrets secrets;

    public AuthHandshake(NodeKey localKey, SECP256K1.PublicKey remotePubkey) {
        this.localKey = localKey;
        this.remotePubkey = remotePubkey;
        this.ephemeralKey = SECP256K1.KeyPair.random();
        this.localNonce = randomBytes32();
    }

    /** Package-private constructor for testing with deterministic keys and nonces. */
    AuthHandshake(NodeKey localKey, SECP256K1.PublicKey remotePubkey,
                  SECP256K1.KeyPair ephemeralKey, Bytes32 localNonce) {
        this.localKey = localKey;
        this.remotePubkey = remotePubkey;
        this.ephemeralKey = ephemeralKey;
        this.localNonce = localNonce;
    }

    // -------------------------------------------------------------------------
    // Step 1: Build and encrypt auth message
    // -------------------------------------------------------------------------
    public Bytes buildAuthMessage() {
        // static-shared-secret = ECDH(local-static-privkey, remote-static-pubkey)
        Bytes32 staticShared = ecdh(localKey.secretKey(), remotePubkey);

        // token = static-shared-secret XOR local-nonce
        byte[] token = xor(staticShared.toArrayUnsafe(), localNonce.toArrayUnsafe());

        // sig = signHashed(token, ephemeral-privkey)
        // token is already a 32-byte "hash" (XOR of two 32-byte values).
        // go-ethereum uses crypto.Ecrecover(token, sig) — no re-hashing — so we must
        // sign token directly (signHashed), not hash-then-sign (sign).
        Bytes32 tokenHash = Bytes32.wrap(token);
        SECP256K1.Signature sig = SECP256K1.signHashed(tokenHash, ephemeralKey);
        byte[] sigBytes = encodeSignature(sig);

        // Auth body (plain): [sig(65) | pubkey(64) | nonce(32) | version(4)]
        byte[] pubkeyBytes = localKey.publicKeyBytes().toArrayUnsafe(); // 64 bytes
        byte[] nonceBytes = localNonce.toArrayUnsafe();
        byte version = 4;

        // EIP-8: RLP encode the auth body. Random padding goes INSIDE the list
        // as a trailing byte-string element (go-ethereum's rlp:"tail" consumes it).
        byte[] padding = new byte[100 + new java.security.SecureRandom().nextInt(200)];
        new java.security.SecureRandom().nextBytes(padding);
        Bytes authBody = org.apache.tuweni.rlp.RLP.encodeList(writer -> {
            writer.writeValue(Bytes.wrap(sigBytes));
            writer.writeValue(Bytes.wrap(pubkeyBytes));
            writer.writeValue(Bytes.wrap(nonceBytes));
            writer.writeInt(version);
            writer.writeValue(Bytes.wrap(padding)); // EIP-8 trailing padding element
        });

        // EIP-8: compute auth-size BEFORE encryption (it's used as HMAC AAD).
        // enc-auth-body = ephPub(65, includes 0x04) + IV(16) + plaintext_len + MAC(32)
        int encAuthBodySize = authBody.size() + 65 + 16 + 32;
        byte[] sizeBytes = {(byte)(encAuthBodySize >> 8), (byte)(encAuthBodySize & 0xFF)};

        // ECIES encrypt — auth-size (2 bytes) is appended to HMAC input (SharedInfo2)
        Bytes ciphertext = EciesCodec.encrypt(authBody, remotePubkey, sizeBytes);

        // EIP-8 wire format: [size(2 bytes BE)] [enc-auth-body]
        Bytes wire = Bytes.concatenate(Bytes.wrap(sizeBytes), ciphertext);
        authWireBytes = wire.toArrayUnsafe();
        return wire;
    }

    // -------------------------------------------------------------------------
    // Step 2: Process received ack
    // -------------------------------------------------------------------------
    public void processAck(Bytes encryptedAck, byte[] ackSizeAad, byte[] fullAckWireBytes) {
        this.ackWireBytes = fullAckWireBytes;
        // ECIES decrypt — for EIP-8, ack-size (2 bytes) is the HMAC AAD
        Bytes plainAck = EciesCodec.decrypt(encryptedAck, localKey.secretKey(), ackSizeAad);

        // Parse EIP-8 RLP ack: [ephemeral-pubkey(64), nonce(32), version(4)]
        org.apache.tuweni.rlp.RLP.decodeList(plainAck, reader -> {
            Bytes ephPubBytes = reader.readValue(); // 64 bytes
            remoteEphemeralKey = SECP256K1.PublicKey.fromBytes(ephPubBytes);
            remoteNonce = Bytes32.wrap(reader.readValue());
            reader.skipNext(); // version
            return null;
        });

        // Derive session secrets
        secrets = deriveSecrets();
    }

    public SessionSecrets secrets() {
        if (secrets == null) throw new IllegalStateException("Handshake not complete");
        return secrets;
    }

    // -------------------------------------------------------------------------
    // Session key derivation
    // -------------------------------------------------------------------------
    private SessionSecrets deriveSecrets() {
        // ephemeral-shared-secret = ECDH(local-ephemeral-privkey, remote-ephemeral-pubkey)
        Bytes32 ephShared = ecdh(ephemeralKey.secretKey(), remoteEphemeralKey);

        // shared-secret = keccak256(ephemeral-shared || keccak256(remote-nonce || local-nonce))
        Bytes32 nonceHash = Hash.keccak256(Bytes.concatenate(remoteNonce, localNonce));
        Bytes32 sharedSecret = Hash.keccak256(Bytes.concatenate(ephShared, nonceHash));

        // aes-secret = keccak256(ephemeral-shared || shared-secret)
        Bytes32 aesSecret = Hash.keccak256(Bytes.concatenate(ephShared, sharedSecret));

        // mac-secret = keccak256(ephemeral-shared || aes-secret)
        Bytes32 macSecret = Hash.keccak256(Bytes.concatenate(ephShared, aesSecret));

        return new SessionSecrets(aesSecret, macSecret, localNonce, remoteNonce, authWireBytes, ackWireBytes);
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------
    private static Bytes32 ecdh(SECP256K1.SecretKey privKey, SECP256K1.PublicKey pubKey) {
        // Recover EC parameters from Tuweni's key types
        BigInteger privScalar = new BigInteger(1, privKey.bytes().toArrayUnsafe());
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(privScalar, CURVE);

        // Reconstruct ECPoint from uncompressed 64-byte pubkey
        byte[] pubBytes = pubKey.bytes().toArrayUnsafe(); // 64 bytes (no prefix)
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(pubBytes, 0, uncompressed, 1, 64);
        ECPoint point = CURVE.getCurve().decodePoint(uncompressed);
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(point, CURVE);

        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privParams);
        BigInteger result = agreement.calculateAgreement(pubParams);

        // Return as 32-byte big-endian
        byte[] bytes = result.toByteArray();
        byte[] out = new byte[32];
        if (bytes.length >= 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return Bytes32.wrap(out);
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    private static byte[] encodeSignature(SECP256K1.Signature sig) {
        byte[] r = padTo32(sig.r().toByteArray());
        byte[] s = padTo32(sig.s().toByteArray());
        byte[] out = new byte[65];
        System.arraycopy(r, 0, out, 0, 32);
        System.arraycopy(s, 0, out, 32, 32);
        out[64] = (byte) sig.v();
        return out;
    }

    private static byte[] padTo32(byte[] in) {
        if (in.length == 32) return in;
        byte[] out = new byte[32];
        int srcOff = Math.max(0, in.length - 32);
        int dstOff = 32 - Math.min(in.length, 32);
        System.arraycopy(in, srcOff, out, dstOff, Math.min(in.length, 32));
        return out;
    }

    private static Bytes32 randomBytes32() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Bytes32.wrap(b);
    }
}
