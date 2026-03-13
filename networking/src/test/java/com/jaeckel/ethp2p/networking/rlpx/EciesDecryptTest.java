package com.jaeckel.ethp2p.networking.rlpx;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies our ECIES implementation against the EIP-8 test vectors.
 * Keys and packet hex taken directly from https://eips.ethereum.org/EIPS/eip-8
 */
class EciesDecryptTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // EIP-8 test keys
    // Static key B (recipient in auth tests)
    private static final String STATIC_B = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";

    // Auth₁: RLPx v4 (legacy, no EIP-8, no size prefix)
    private static final String AUTH1_HEX =
        "048ca79ad18e4b0659fab4853fe5bc58eb83992980f4c9cc147d2aa31532efd29a3d3dc6a3d89eaf" +
        "913150cfc777ce0ce4af2758bf4810235f6e6ceccfee1acc6b22c005e9e3a49d6448610a58e98744" +
        "ba3ac0399e82692d67c1f58849050b3024e21a52c9d3b01d871ff5f210817912773e610443a9ef14" +
        "2e91cdba0bd77b5fdf0769b05671fc35f83d83e4d3b0b000c6b2a1b1bba89e0fc51bf4e460df310" +
        "5c444f14be226458940d6061c296350937ffd5e3acaceeaaefd3c6f74be8e23e0f45163cc7ebd762" +
        "20f0128410fd05250273156d548a414444ae2f7dea4dfca2d43c057adb701a715bf59f6fb66b2d1d" +
        "20f2c703f851cbf5ac47396d9ca65b6260bd141ac4d53e2de585a73d1750780db4c9ee4cd4d22517" +
        "3a4592ee77e2bd94d0be3691f3b406f9bba9b591fc63facc016bfa8";

    // Auth₂: EIP-8 format auth from A to B (no additional elements)
    // First 2 bytes = size prefix, remainder = enc-auth-body
    private static final String AUTH2_HEX =
        "01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b" +
        "0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b849" +
        "634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6c" +
        "da61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc" +
        "147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6" +
        "d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee" +
        "70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09" +
        "c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec3" +
        "6f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e" +
        "2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c" +
        "3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c";

    @Test
    void roundTrip() {
        // Generate a key pair for the recipient
        SECP256K1.KeyPair recipient = SECP256K1.KeyPair.random();
        byte[] plaintext = "Hello, World! This is a test message.".getBytes();
        Bytes pt = org.apache.tuweni.bytes.Bytes.wrap(plaintext);

        // Encrypt and decrypt without AAD
        Bytes encrypted = EciesCodec.encrypt(pt, recipient.publicKey());
        Bytes decrypted = EciesCodec.decrypt(encrypted, recipient.secretKey());
        assertEquals(pt, decrypted, "Round-trip without AAD must work");

        // With AAD
        byte[] aad = new byte[]{(byte)0x01, (byte)0xB3};
        int expectedSize = pt.size() + 65 + 16 + 32;
        byte[] sizeAad = new byte[]{(byte)(expectedSize >> 8), (byte)(expectedSize & 0xFF)};
        Bytes encryptedAad = EciesCodec.encrypt(pt, recipient.publicKey(), sizeAad);
        Bytes decryptedAad = EciesCodec.decrypt(encryptedAad, recipient.secretKey(), sizeAad);
        assertEquals(pt, decryptedAad, "Round-trip WITH AAD must work");

        System.out.println("Round-trip test passed! enc size (no aad)=" + encrypted.size()
            + ", enc size (with aad)=" + encryptedAad.size());
    }

    @Test
    void decryptAuth1Legacy() {
        // Auth₁ is legacy format: no size prefix, just raw ECIES blob starting with 0x04
        SECP256K1.SecretKey privB = SECP256K1.SecretKey.fromBytes(Bytes32.fromHexString(STATIC_B));
        byte[] auth1Bytes = Bytes.fromHexString(AUTH1_HEX).toArrayUnsafe();
        System.out.printf("auth1 size: %d, first byte: 0x%02X%n",
            auth1Bytes.length, auth1Bytes[0] & 0xFF);

        // No AAD for legacy format
        Bytes encAuthBody = Bytes.wrap(auth1Bytes);
        Bytes plain = assertDoesNotThrow(() -> EciesCodec.decrypt(encAuthBody, privB, new byte[0]),
            "Legacy auth1 decryption must succeed");
        assertNotNull(plain);
        System.out.printf("auth1 decrypted size=%d, first byte=0x%02X%n",
            plain.size(), plain.get(0) & 0xFF);
    }

    @Test
    void decryptAuth2WithEip8TestVector() {
        // Load B's static private key
        SECP256K1.SecretKey privB = SECP256K1.SecretKey.fromBytes(
            Bytes32.fromHexString(STATIC_B));

        // Parse the auth₂ packet: 2-byte size prefix || enc-auth-body
        byte[] auth2Bytes = Bytes.fromHexString(AUTH2_HEX).toArrayUnsafe();
        byte[] aad = {auth2Bytes[0], auth2Bytes[1]}; // auth-size as AAD
        Bytes encAuthBody = Bytes.wrap(auth2Bytes, 2, auth2Bytes.length - 2);

        System.out.printf("auth2 total=%d, enc-auth-body size=%d, aad=%02X%02X%n",
            auth2Bytes.length, encAuthBody.size(), aad[0] & 0xFF, aad[1] & 0xFF);
        System.out.printf("enc-auth-body first byte (should be 0x04): 0x%02X%n",
            encAuthBody.get(0) & 0xFF);

        Bytes plain = assertDoesNotThrow(() -> EciesCodec.decrypt(encAuthBody, privB, aad),
            "ECIES decryption of EIP-8 auth2 test vector must succeed");

        assertNotNull(plain);
        assertTrue(plain.size() > 0, "Decrypted plaintext must be non-empty");
        int firstByte = plain.get(0) & 0xFF;
        assertTrue(firstByte >= 0xF8,
            String.format("First byte should be RLP list marker >= 0xF8, got 0x%02X", firstByte));
        System.out.printf("auth2 decrypted size=%d, first byte=0x%02X%n", plain.size(), firstByte);
    }
}
