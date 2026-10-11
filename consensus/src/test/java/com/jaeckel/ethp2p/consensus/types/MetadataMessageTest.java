package com.jaeckel.ethp2p.consensus.types;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The MetaData answers a light client gives: v2 is 17 zero bytes, v3 is v2
 * followed by the custody group count every peer already assumed for us.
 */
class MetadataMessageTest {

    @Test
    void v2IsSeventeenZeroBytes() {
        byte[] v2 = MetadataMessage.lightClientDefaults().encode();
        assertEquals(MetadataMessage.SSZ_SIZE, v2.length);
        assertArrayEquals(new byte[17], v2);
    }

    @Test
    void v3IsV2PlusTheCustodyRequirement() {
        MetadataMessage md = MetadataMessage.lightClientDefaults();
        byte[] v3 = md.encodeV3();
        assertEquals(MetadataMessage.SSZ_SIZE_V3, v3.length);
        assertEquals(25, v3.length);
        assertArrayEquals(md.encode(), Arrays.copyOf(v3, 17));
        long cgc = ByteBuffer.wrap(v3, 17, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
        assertEquals(MetadataMessage.CUSTODY_GROUP_COUNT, cgc);
        assertEquals(4L, cgc); // CUSTODY_REQUIREMENT on mainnet, Sepolia and Gnosis
    }

    @Test
    void v3KeepsTheSequenceNumber() {
        MetadataMessage md = new MetadataMessage(7L, new byte[8], new byte[1]);
        byte[] v3 = md.encodeV3();
        assertEquals(7L, ByteBuffer.wrap(v3, 0, 8).order(ByteOrder.LITTLE_ENDIAN).getLong());
        assertEquals(7L, MetadataMessage.decode(v3).seqNumber()); // v2 decoder reads the prefix
    }
}
