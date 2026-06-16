package io.myotis.node;

import java.net.InetSocketAddress;

/**
 * A cached EL peer: its address, secp256k1 public key (hex), whether it advertised
 * snap/1, and its learned snap-serving verdict. Host peer caches return these from
 * {@link PeerCachePort#load()} so {@code ChainStack} can re-dial in snap-quality order.
 */
public record CachedPeer(InetSocketAddress address, String publicKeyHex,
                         boolean snap, SnapQuality snapQuality) {
}
