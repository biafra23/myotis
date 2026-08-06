package com.jaeckel.ethp2p.networking.eth.messages;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** eth/69 (EIP-7642) BlockRangeUpdate wire round-trip: [earliest, latest, latestHash]. */
class BlockRangeUpdateMessageTest {

    @Test
    void roundTrips() {
        Bytes32 latestHash = Bytes32.rightPad(Bytes.fromHexString("0xbeef"));
        byte[] rlp = BlockRangeUpdateMessage.encode(20_999_968L, 21_000_000L, latestHash);

        BlockRangeUpdateMessage.Decoded d = BlockRangeUpdateMessage.decode(rlp);
        assertEquals(20_999_968L, d.earliestBlock());
        assertEquals(21_000_000L, d.latestBlock());
        assertEquals(latestHash, d.latestBlockHash());
    }

    /**
     * GOLDEN VECTOR shared with the Rust engine. The same hex is pinned in
     * {@code rust/myotis-net/src/el/eth/messages.rs}
     * ({@code BLOCK_RANGE_UPDATE_GOLDEN_HEX}, asserted by
     * {@code block_range_update_matches_the_java_golden_vector}), so neither
     * engine can change the wire shape without failing a test on one side.
     *
     * <p>Inputs: earliest=100, latest=131 (a 32-block window — the default
     * served window size), latestBlockHash=0x11…11.
     */
    @Test
    void matchesTheCrossEngineGoldenVector() {
        Bytes32 latestHash = Bytes32.repeat((byte) 0x11);
        byte[] rlp = BlockRangeUpdateMessage.encode(100L, 131L, latestHash);

        assertEquals(
                "0xe4648183a01111111111111111111111111111111111111111111111111111111111111111",
                Bytes.wrap(rlp).toHexString(),
                "wire shape must stay byte-identical to the Rust engine's encode_block_range_update");
    }
}
