package com.jaeckel.ethp2p.consensus.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * SSZ container: {@code MetaData} (v2) — what a peer advertises in response to
 * {@code /req/metadata/2/ssz_snappy}.
 *
 * <pre>
 *   seq_number: uint64            (8)
 *   attnets   : Bitvector[64]     (8)
 *   syncnets  : Bitvector[4]      (1)
 * </pre>
 * Total fixed size: 17 bytes.
 *
 * <p>A pure light client subscribes to no attnets or syncnets, so both
 * bitfields are always all-zero. {@code seq_number} starts at 0 and would
 * increment on any future subscription change; since we have none, it stays 0.
 */
public record MetadataMessage(long seqNumber, byte[] attnets, byte[] syncnets) {

    public static final int SSZ_SIZE = 17;

    /** v3 ({@code /req/metadata/3}, Fulu): v2 plus {@code custody_group_count} uint64. */
    public static final int SSZ_SIZE_V3 = SSZ_SIZE + 8;

    /**
     * The {@code custody_group_count} advertised in v3: {@code CUSTODY_REQUIREMENT}
     * (4 on mainnet, Sepolia and Gnosis) rather than the honest 0. The Fulu p2p
     * spec lets clients "reject peers with a value less than CUSTODY_REQUIREMENT",
     * and Lighthouse does (goodbye with reason Fault, which bans). The minimum
     * changes nothing about how peers treat us: a peer that only got our v2
     * metadata assumed exactly this value. Same constant as the Rust engine's
     * {@code status::CUSTODY_GROUP_COUNT}.
     */
    public static final long CUSTODY_GROUP_COUNT = 4L;

    public MetadataMessage {
        if (attnets == null || attnets.length != 8)
            throw new IllegalArgumentException("attnets must be 8 bytes (Bitvector[64])");
        if (syncnets == null || syncnets.length != 1)
            throw new IllegalArgumentException("syncnets must be 1 byte (Bitvector[4])");
    }

    /** Light-client defaults: no attnets, no syncnets subscribed. */
    public static MetadataMessage lightClientDefaults() {
        return new MetadataMessage(0L, new byte[8], new byte[1]);
    }

    public byte[] encode() {
        ByteBuffer buf = ByteBuffer.allocate(SSZ_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(seqNumber);
        buf.put(attnets);
        buf.put(syncnets);
        return buf.array();
    }

    /** v3 encoding: {@link #encode()} followed by {@link #CUSTODY_GROUP_COUNT}. */
    public byte[] encodeV3() {
        ByteBuffer buf = ByteBuffer.allocate(SSZ_SIZE_V3).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(encode());
        buf.putLong(CUSTODY_GROUP_COUNT);
        return buf.array();
    }

    public static MetadataMessage decode(byte[] ssz) {
        if (ssz.length < SSZ_SIZE) {
            throw new IllegalArgumentException(
                    "MetaData requires " + SSZ_SIZE + " bytes, got " + ssz.length);
        }
        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);
        long seq = buf.getLong();
        byte[] attnets = new byte[8];
        byte[] syncnets = new byte[1];
        buf.get(attnets);
        buf.get(syncnets);
        return new MetadataMessage(seq, attnets, syncnets);
    }
}
