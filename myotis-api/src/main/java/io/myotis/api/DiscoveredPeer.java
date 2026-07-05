package io.myotis.api;

/**
 * One entry from EL discovery's routing table (operator diagnostics).
 *
 * @param host      IP literal
 * @param udpPort   discv4 UDP port
 * @param tcpPort   advertised RLPx TCP port (0 when unknown)
 * @param nodeIdHex the peer's full 64-byte node id (0x-hex)
 */
public record DiscoveredPeer(String host, int udpPort, int tcpPort, String nodeIdHex) {
}
