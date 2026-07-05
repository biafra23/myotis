package io.myotis.api;

/**
 * One EL peer with an open RLPx session, including those still handshaking
 * (unlike {@link PeerInfo}, which covers only READY peers).
 *
 * @param remoteAddress "host:port" display string
 * @param state         connection state name (e.g. "AWAITING_STATUS", "READY")
 * @param snapSupported whether the peer negotiated snap/1
 * @param clientId      the peer's Hello client id, or null until received
 */
public record ConnectedPeer(String remoteAddress, String state, boolean snapSupported, String clientId) {
}
