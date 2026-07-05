package io.myotis.api;

/**
 * One connected CL (beacon libp2p) peer.
 *
 * @param peerId        the libp2p peer id (full)
 * @param remoteAddress remote multiaddr/endpoint display string
 * @param clientId      the peer's agent version, or null when unknown
 * @param lightClient   whether the peer serves the light_client req/resp protocols
 * @param protocols     number of protocols the peer advertised
 */
public record ClPeerInfo(String peerId, String remoteAddress, String clientId,
                         boolean lightClient, int protocols) {
}
