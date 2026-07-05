package io.myotis.api;

/**
 * Result of an operator-initiated peer dial. {@code accepted} means the connect
 * was initiated (the handshake outcome arrives asynchronously and shows up in
 * {@link StatusSnapshot} peer counts), not that the peer is connected.
 *
 * @param accepted the dial was initiated
 * @param error    null when accepted; otherwise why the dial was rejected
 */
public record DialResult(boolean accepted, String error) {
}
