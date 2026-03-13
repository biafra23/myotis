package com.jaeckel.ethp2p.networking.rlpx;

import org.apache.tuweni.bytes.Bytes32;

/**
 * Session secrets derived from the RLPx handshake.
 * Used to initialize the FrameCodec for all subsequent messages.
 */
public record SessionSecrets(
    Bytes32 aesSecret,
    Bytes32 macSecret,
    Bytes32 egressNonce,        // local nonce  (initiator-nonce)
    Bytes32 ingressNonce,       // remote nonce (responder-nonce)
    byte[] authWireBytes,       // full wire auth bytes sent (including EIP-8 size prefix)
    byte[] ackWireBytes         // full wire ack bytes received (including EIP-8 size prefix)
) {}
