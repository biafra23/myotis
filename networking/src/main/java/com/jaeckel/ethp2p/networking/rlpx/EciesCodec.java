package com.jaeckel.ethp2p.networking.rlpx;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ECIES encryption/decryption for RLPx auth/ack messages.
 *
 * Specification: ethereum/devp2p/rlpx.md
 *
 * Algorithm:
 *   - ECDH key agreement using secp256k1
 *   - KDF: NIST SP 800-56 Concatenation KDF with SHA-256
 *   - Symmetric encryption: AES-128-CTR
 *   - MAC: HMAC-SHA-256 over (IV || ciphertext)
 *
 * Encrypted message format:
 *   0x04 || ephemeral-pubkey(65) || IV(16) || ciphertext || MAC(32)
 */
public final class EciesCodec {

    private static final X9ECParameters CURVE_PARAMS = SECNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
        CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

    private static final int KEY_SIZE = 16; // AES-128 enc key
    private static final int MAC_KEY_SIZE = 16; // 16 bytes from KDF, then sha256() → 32-byte HMAC key
    private static final int IV_SIZE = 16;
    private static final int MAC_SIZE = 32;
    private static final SecureRandom RNG = new SecureRandom();

    private EciesCodec() {}

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------
    public static Bytes encrypt(Bytes plaintext, SECP256K1.PublicKey recipientPubkey) {
        return encrypt(plaintext, recipientPubkey, new byte[0]);
    }

    /**
     * Encrypt with optional AAD (EIP-8: the 2-byte auth-size is appended to the MAC data).
     * MAC = HMAC-SHA256(keccak256(macKey), IV || ciphertext || aad)
     */
    public static Bytes encrypt(Bytes plaintext, SECP256K1.PublicKey recipientPubkey, byte[] aad) {
        // 1. Generate ephemeral key pair
        SECP256K1.KeyPair ephemeral = SECP256K1.KeyPair.random();

        // 2. ECDH
        byte[] shared = ecdh(ephemeral.secretKey(), recipientPubkey);

        // 3. KDF: derive enc-key (16 bytes) and raw mac-key (16 bytes)
        // devp2p spec: key-material = KDF(shared, 32), k_E=[:16], k_M=[16:32]
        byte[] keyMaterial = kdf(shared, KEY_SIZE + MAC_KEY_SIZE);
        byte[] encKey = Arrays.copyOf(keyMaterial, KEY_SIZE);
        byte[] macKey = Arrays.copyOfRange(keyMaterial, KEY_SIZE, KEY_SIZE + MAC_KEY_SIZE);

        // 4. AES-128-CTR encrypt
        byte[] iv = new byte[IV_SIZE];
        RNG.nextBytes(iv);
        byte[] ciphertext = aesCtr(plaintext.toArrayUnsafe(), encKey, iv, true);

        // 5. MAC = HMAC-SHA256(SHA-256(macKey), IV || ciphertext [|| aad (auth-size as S2)])
        // devp2p spec: d = MAC(sha256(k_M), iv || c || s2)
        byte[] macInput = aad.length > 0 ? concat(iv, ciphertext, aad) : concat(iv, ciphertext);
        byte[] mac = hmacSha256(sha256(macKey), macInput);

        // 6. Assemble: ephemeral-pubkey(65) || IV(16) || ciphertext || MAC(32)
        // toUncompressed() already includes the 0x04 prefix — do NOT prepend another one.
        byte[] ephPubUncompressed = toUncompressed(ephemeral.publicKey()); // 65 bytes: 0x04 || x || y
        return Bytes.wrap(concat(ephPubUncompressed, concat(iv, concat(ciphertext, mac))));
    }

    // -------------------------------------------------------------------------
    // Decryption
    // -------------------------------------------------------------------------
    public static Bytes decrypt(Bytes encrypted, SECP256K1.SecretKey recipientPrivkey) {
        return decrypt(encrypted, recipientPrivkey, new byte[0]);
    }

    /**
     * Decrypt with optional AAD (EIP-8: the 2-byte auth-size/ack-size is the expected AAD).
     */
    public static Bytes decrypt(Bytes encrypted, SECP256K1.SecretKey recipientPrivkey, byte[] aad) {
        byte[] data = encrypted.toArrayUnsafe();
        if (data[0] != 0x04) {
            throw new IllegalArgumentException("Expected uncompressed point marker 0x04");
        }

        // Parse: ephPub(65) || IV(16) || ciphertext || MAC(32)
        // ephPub[0] = 0x04, already checked above
        byte[] ephPubBytes = Arrays.copyOfRange(data, 0, 65);       // 65 bytes (includes 0x04)
        byte[] iv = Arrays.copyOfRange(data, 65, 65 + IV_SIZE);
        byte[] cipherAndMac = Arrays.copyOfRange(data, 65 + IV_SIZE, data.length);
        byte[] ciphertext = Arrays.copyOf(cipherAndMac, cipherAndMac.length - MAC_SIZE);
        byte[] mac = Arrays.copyOfRange(cipherAndMac, cipherAndMac.length - MAC_SIZE, cipherAndMac.length);

        // Recover ephemeral pubkey
        ECPoint point = CURVE.getCurve().decodePoint(ephPubBytes);
        byte[] ephPubUncompressed64 = Arrays.copyOfRange(point.getEncoded(false), 1, 65);
        SECP256K1.PublicKey ephPub = SECP256K1.PublicKey.fromBytes(Bytes.wrap(ephPubUncompressed64));

        // ECDH
        byte[] shared = ecdh(recipientPrivkey, ephPub);

        // KDF: 32 bytes total — k_E(16) || k_M(16)
        byte[] keyMaterial = kdf(shared, KEY_SIZE + MAC_KEY_SIZE);
        byte[] encKey = Arrays.copyOf(keyMaterial, KEY_SIZE);
        byte[] macKey = Arrays.copyOfRange(keyMaterial, KEY_SIZE, KEY_SIZE + MAC_KEY_SIZE);

        // Verify MAC = HMAC-SHA256(SHA-256(macKey), IV || ciphertext [|| aad])
        byte[] macInputWithAad = aad.length > 0 ? concat(iv, ciphertext, aad) : concat(iv, ciphertext);
        byte[] macInputNoAad = concat(iv, ciphertext);
        byte[] expectedMacWithAad = hmacSha256(sha256(macKey), macInputWithAad);
        byte[] expectedMacNoAad = hmacSha256(sha256(macKey), macInputNoAad);
        byte[] expectedMac;
        if (Arrays.equals(mac, expectedMacWithAad)) {
            expectedMac = expectedMacWithAad;
        } else if (Arrays.equals(mac, expectedMacNoAad)) {
            System.err.println("ECIES DEBUG: MAC matched WITHOUT AAD — test vector does not use auth-size as AAD!");
            expectedMac = expectedMacNoAad;
        } else {
            System.err.printf("ECIES DEBUG: shared=%s%n", bytesToHex(shared));
            System.err.printf("ECIES DEBUG: keyMat=%s%n", bytesToHex(keyMaterial));
            System.err.printf("ECIES DEBUG: macKey=%s sha256(macKey)=%s%n",
                bytesToHex(macKey), bytesToHex(sha256(macKey)));
            System.err.printf("ECIES DEBUG: iv=%s%n", bytesToHex(iv));
            System.err.printf("ECIES DEBUG: mac(wire)=%s%n", bytesToHex(mac));
            System.err.printf("ECIES DEBUG: mac(withAad)=%s%n", bytesToHex(expectedMacWithAad));
            System.err.printf("ECIES DEBUG: mac(noAad)=%s%n", bytesToHex(expectedMacNoAad));
            throw new IllegalArgumentException("ECIES MAC verification failed");
        }

        // Decrypt
        byte[] plain = aesCtr(ciphertext, encKey, iv, false);
        return Bytes.wrap(plain);
    }

    // -------------------------------------------------------------------------
    // Primitives
    // -------------------------------------------------------------------------
    private static byte[] ecdh(SECP256K1.SecretKey privKey, SECP256K1.PublicKey pubKey) {
        BigInteger priv = new BigInteger(1, privKey.bytes().toArrayUnsafe());
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(priv, CURVE);

        byte[] pubBytes = pubKey.bytes().toArrayUnsafe(); // 64 bytes
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(pubBytes, 0, uncompressed, 1, 64);
        ECPoint point = CURVE.getCurve().decodePoint(uncompressed);
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(point, CURVE);

        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privParams);
        BigInteger result = agreement.calculateAgreement(pubParams);

        byte[] bytes = result.toByteArray();
        byte[] out = new byte[32];
        int srcOff = Math.max(0, bytes.length - 32);
        int len = Math.min(bytes.length, 32);
        System.arraycopy(bytes, srcOff, out, 32 - len, len);
        return out;
    }

    private static byte[] kdf(byte[] shared, int outputLen) {
        // NIST SP 800-56 Concatenation KDF used by go-ethereum: SHA-256(counter || Z)
        // counter is 4-byte big-endian starting at 1.
        // NOTE: BouncyCastle's KDF2BytesGenerator uses SHA-256(Z || counter) which is WRONG here.
        SHA256Digest digest = new SHA256Digest();
        byte[] out = new byte[outputLen];
        int generated = 0;
        for (int counter = 1; generated < outputLen; counter++) {
            digest.reset();
            digest.update((byte)(counter >> 24));
            digest.update((byte)(counter >> 16));
            digest.update((byte)(counter >> 8));
            digest.update((byte) counter);
            digest.update(shared, 0, shared.length);
            byte[] hash = new byte[32];
            digest.doFinal(hash, 0);
            int copyLen = Math.min(32, outputLen - generated);
            System.arraycopy(hash, 0, out, generated, copyLen);
            generated += copyLen;
        }
        return out;
    }

    private static byte[] aesCtr(byte[] input, byte[] key, byte[] iv, boolean encrypt) {
        // SICBlockCipher (CTR mode) is a stream cipher — processBytes handles arbitrary lengths
        org.bouncycastle.crypto.StreamCipher ctr =
            new SICBlockCipher(new AESEngine());
        ctr.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[input.length];
        ctr.processBytes(input, 0, input.length, out, 0);
        return out;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] out = new byte[32];
        hmac.doFinal(out, 0);
        return out;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] toUncompressed(SECP256K1.PublicKey pub) {
        byte[] raw = pub.bytes().toArrayUnsafe(); // 64 bytes
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(raw, 0, out, 1, 64);
        return out;
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, offset, a.length);
            offset += a.length;
        }
        return out;
    }
}
