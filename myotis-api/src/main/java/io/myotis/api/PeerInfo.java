package io.myotis.api;

/**
 * One connected READY peer (past the eth handshake), for status peer lists.
 *
 * @param remoteAddress "host:port" display string
 * @param snapSupported whether the peer negotiated snap/1
 * @param clientId      the peer's Hello client id, or null until received
 */
public record PeerInfo(String remoteAddress, boolean snapSupported, String clientId) {
}
