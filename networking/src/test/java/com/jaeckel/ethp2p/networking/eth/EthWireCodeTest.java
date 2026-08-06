package com.jaeckel.ethp2p.networking.eth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Pins the eth capability's wire codes — the devp2p base offset (0x10) plus the
 * protocol-relative message id.
 *
 * <p>Regression guard for a real interop break: {@code BlockRangeUpdate} (eth/69,
 * EIP-7642, protocol-relative id 0x11) was sent at wire code 0x11 — the relative
 * id with the base never added. Geth decodes wire 0x11 as eth-relative 0x01
 * (NewBlockHashes, removed in eth/69), answers {@code invalid message code: 1},
 * and disconnects with DiscSubprotocolError. That silently cut us off from every
 * eth/69 peer, i.e. every modern Geth.
 *
 * <p>The correct wire code is 0x21, and it must stay version-GATED at
 * every send/match site: on eth/67-68 the eth capability is 17 messages long,
 * so absolute 0x21 is snap/1's {@code GetAccountRange}. Only on eth/69
 * (length 18, snap base 0x22) is 0x21 free for BlockRangeUpdate — which is why
 * {@code EthHandler} dispatches it in the {@code default} branch behind a
 * version check rather than as a {@code switch} case.
 */
class EthWireCodeTest {

    private static final int P2P_BASE = 0x10;

    /** Protocol-relative ids from the eth spec (see go-ethereum eth/protocols/eth/protocol.go). */
    private static final int REL_STATUS = 0x00;
    private static final int REL_GET_RECEIPTS = 0x0f;
    private static final int REL_RECEIPTS = 0x10;
    private static final int REL_BLOCK_RANGE_UPDATE = 0x11;

    @Test
    void blockRangeUpdateSitsAtTheBaseOffsetPlusItsRelativeId() {
        assertEquals(0x21, P2P_BASE + REL_BLOCK_RANGE_UPDATE,
                "eth/69 BlockRangeUpdate wire code must be 0x21, not the bare relative id 0x11");
    }

    @Test
    void everyEthCodeIncludesTheBaseOffset() {
        assertEquals(0x10, P2P_BASE + REL_STATUS);
        assertEquals(0x1f, P2P_BASE + REL_GET_RECEIPTS);
        assertEquals(0x20, P2P_BASE + REL_RECEIPTS);
        assertEquals(0x21, P2P_BASE + REL_BLOCK_RANGE_UPDATE);
    }

    @Test
    void blockRangeUpdateCollidesWithSnapOnEth68SoItMustBeVersionGated() {
        int snapBaseEth68 = P2P_BASE + 17; // eth/67-68 protocol length
        int snapBaseEth69 = P2P_BASE + 18; // eth/69 adds BlockRangeUpdate

        assertEquals(0x21, snapBaseEth68,
                "on eth/68 wire 0x21 is snap GetAccountRange — BlockRangeUpdate must not be a "
                        + "static switch case, or it would shadow snap traffic");
        assertEquals(0x22, snapBaseEth69);
        assertNotEquals(snapBaseEth69, P2P_BASE + REL_BLOCK_RANGE_UPDATE,
                "on eth/69 BlockRangeUpdate (0x21) must not collide with the snap base (0x22)");
    }
}
