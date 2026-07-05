package io.myotis.api.ports;

/**
 * One cached EL peer.
 *
 * @param host         IP literal or hostname
 * @param port         RLPx TCP port
 * @param publicKeyHex the peer's uncompressed secp256k1 public key (hex, no 0x04 prefix)
 * @param snap         whether the peer advertised snap/1
 * @param snapQuality  the learned snap-serving verdict
 */
public record CachedPeerInfo(
        String host,
        int port,
        String publicKeyHex,
        boolean snap,
        SnapQuality snapQuality) {
}
