package io.myotis.api.ports;

/**
 * Where the node's secp256k1 identity lives (a P2P identity, not a wallet key).
 * The engine calls {@link #load}; when it returns null the engine generates a
 * fresh key and persists it via {@link #store} so the enode/PeerId stays stable
 * across restarts.
 */
public interface NodeKeyStore {

    /** The 32-byte secret for {@code networkName}, or null when none stored. */
    byte[] load(String networkName);

    /** Persist a freshly generated 32-byte secret for {@code networkName}. */
    void store(String networkName, byte[] secret32);
}
