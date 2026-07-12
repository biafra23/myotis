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
}
