package com.jaeckel.ethp2p.core.crypto;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

/**
 * The node's secp256k1 identity key pair.
 * Used for: ENR identity, RLPx ECIES handshake, discv4 packet signing.
 */
public final class NodeKey {

    static {
        // BouncyCastle must be registered as JCA provider for SECP256K1 key generation
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final SECP256K1.KeyPair keyPair;

    private NodeKey(SECP256K1.KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public static NodeKey generate() {
        return new NodeKey(SECP256K1.KeyPair.random());
    }

    public static NodeKey fromSecretKey(SECP256K1.SecretKey secret) {
        return new NodeKey(SECP256K1.KeyPair.fromSecretKey(secret));
    }

    /**
     * Load from a 32-byte hex file, or generate and save a new one.
     */
    public static NodeKey loadOrGenerate(Path file) throws IOException {
        if (Files.exists(file)) {
            String hex = Files.readString(file).strip();
            Bytes32 privBytes = Bytes32.fromHexString(hex);
            SECP256K1.SecretKey secret = SECP256K1.SecretKey.fromBytes(privBytes);
            SECP256K1.KeyPair kp = SECP256K1.KeyPair.fromSecretKey(secret);
            return new NodeKey(kp);
        }
        NodeKey key = generate();
        Files.writeString(file, key.privateKeyHex());
        return key;
    }

    public SECP256K1.KeyPair keyPair() {
        return keyPair;
    }

    public SECP256K1.PublicKey publicKey() {
        return keyPair.publicKey();
    }

    public SECP256K1.SecretKey secretKey() {
        return keyPair.secretKey();
    }

    /** Uncompressed 64-byte public key (without 0x04 prefix). */
    public Bytes publicKeyBytes() {
        // Tuweni public key is 64 bytes (uncompressed, without prefix)
        return keyPair.publicKey().bytes();
    }

    /** Node ID = keccak256(publicKeyBytes) — used as Kademlia node ID. */
    public Bytes32 nodeId() {
        return org.apache.tuweni.crypto.Hash.keccak256(publicKeyBytes());
    }

    private String privateKeyHex() {
        return keyPair.secretKey().bytes().toHexString();
    }

    /** Sign a pre-computed 32-byte hash directly (no re-hashing). */
    public SECP256K1.Signature sign(Bytes32 hash) {
        return SECP256K1.signHashed(hash, keyPair);
    }

    @Override
    public String toString() {
        return "NodeKey{nodeId=" + nodeId().toShortHexString() + "...}";
    }
}
