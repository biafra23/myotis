package com.jaeckel.ethp2p.consensus.libp2p;

/** Test fixture: dialing a started {@link BeaconP2PService} from the same machine. */
final class Loopback {

    private Loopback() {}

    /**
     * A loopback multiaddr for {@code target}, {@code /p2p/<peerId>} included.
     * jvm-libp2p reports the wildcard bind as {@code /ip4/0.0.0.0/} or
     * {@code /ip6/::/}; either one is reachable on loopback.
     */
    static String address(BeaconP2PService target) {
        return target.listenAddresses().stream()
                .map(a -> a.replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/").replace("/ip6/::/", "/ip4/127.0.0.1/"))
                .filter(a -> a.startsWith("/ip4/127.0.0.1/"))
                .findFirst()
                .orElseThrow();
    }
}
