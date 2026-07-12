package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * eth/69 (EIP-7642) Status carries a served block range {@code [earliestBlock,
 * latestBlock]}. As a light client we hold only a recent window near the head, so
 * we must advertise that window — NOT {@code [0, head]}, which would invite peers to
 * request arbitrary history we cannot serve (empty responses → peer scores us down
 * and drops us). These tests pin the encoder to a narrow, head-relative range.
 */
class StatusMessage69RangeTest {

    private static final long NETWORK_ID = 1L;
    private static final Bytes32 GENESIS = Bytes32.rightPad(Bytes.fromHexString("0xabcd"));
    private static final Bytes32 HEAD_HASH = Bytes32.rightPad(Bytes.fromHexString("0x1234"));
    private static final byte[] FORK_ID = Bytes.fromHexString("0xdeadbeef").toArrayUnsafe();

    @Test
    void encodesTheAdvertisedRangeAndRoundTrips() {
        long earliest = 21_000_000L - 32;
        long head = 21_000_000L;

        byte[] rlp = StatusMessage.encode(69, NETWORK_ID, GENESIS, HEAD_HASH,
                FORK_ID, 0L, earliest, head);
        StatusMessage decoded = StatusMessage.decode69(rlp);

        assertEquals(69, decoded.protocolVersion);
        assertEquals(earliest, decoded.earliestBlock, "earliestBlock must survive the round trip");
        assertEquals(head, decoded.latestBlock, "latestBlock must be our head");
        assertEquals(HEAD_HASH, decoded.bestHash, "latestBlockHash must be our head hash");
        // The window is the last 32 blocks, not the whole chain.
        assertEquals(32, decoded.latestBlock - decoded.earliestBlock);
        assertNotEquals(0, decoded.earliestBlock,
                "must not advertise genesis as earliest for a head deep in the chain");
    }

    @Test
    void earliestNeverGoesNegativeForLowHeads() {
        // A head below the window (e.g. genesis, before we've synced) must clamp to 0,
        // never wrap to a huge unsigned/negative earliest.
        long head = 5L;
        long earliest = Math.max(0, head - 32); // mirrors EthHandler.sendStatus

        byte[] rlp = StatusMessage.encode(69, NETWORK_ID, GENESIS, HEAD_HASH,
                FORK_ID, 0L, earliest, head);
        StatusMessage decoded = StatusMessage.decode69(rlp);

        assertEquals(0, decoded.earliestBlock);
        assertEquals(head, decoded.latestBlock);
        assertTrue(decoded.earliestBlock <= decoded.latestBlock, "range must be well-ordered");
    }

    @Test
    void eth68IgnoresTheRangeArgument() {
        // The pre-69 wire form has no range; passing an earliestBlock must not affect it.
        byte[] withRange = StatusMessage.encode(68, NETWORK_ID, GENESIS, HEAD_HASH,
                FORK_ID, 0L, 100L, 200L);
        byte[] withoutRange = StatusMessage.encode(68, NETWORK_ID, GENESIS, HEAD_HASH,
                FORK_ID, 0L, 0L, 200L);
        assertEquals(Bytes.wrap(withoutRange), Bytes.wrap(withRange),
                "eth/68 encoding must not depend on the eth/69-only range");

        StatusMessage decoded = StatusMessage.decode(withRange);
        assertEquals(-1, decoded.earliestBlock, "eth/68 decode reports no range");
        assertEquals(-1, decoded.latestBlock);
    }
}
