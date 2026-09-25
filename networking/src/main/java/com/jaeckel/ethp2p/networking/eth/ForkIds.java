package com.jaeckel.ethp2p.networking.eth;

import java.util.Locale;

/**
 * EIP-2124 fork identifier arithmetic.
 *
 * <p>A fork hash is the IEEE CRC32 of the genesis hash, continued over every
 * <em>passed</em> fork's activation point encoded as a big-endian uint64 (block
 * numbers up to the Merge, timestamps since Shanghai). CRC32 resumes from its own
 * checksum, so the hash after a fork follows from the hash before it plus the
 * activation value alone — and runs backwards too: {@link #activationOf} recovers,
 * from our pinned hash and a peer's unknown one, the activation that would turn one
 * into the other ({@link ForkWatch}). That PLACES a hash; it does not authenticate it:
 * every 32-bit hash has exactly one such activation below 2³², so anyone can compute a
 * "successor" for any date they like.
 *
 * <p>{@link java.util.zip.CRC32} cannot be resumed from an arbitrary checksum, hence
 * this table-driven implementation (reflected polynomial {@code 0xEDB88320}, with the
 * init/final inversion folded into {@link #update} / {@link #successor}). Verified
 * against the full mainnet chain Frontier → BPO2 ({@code 0x07c9462e}) and Sepolia's
 * Glamsterdam fork id ({@code 0x268956b6} → {@code 0x6c1d9423}) in ForkIdsTest.
 * Twin: the Rust engine's {@code myotis_core::forkid}.
 */
public final class ForkIds {

    /**
     * Activation values at or above this are unix timestamps, below it block numbers
     * (geth's threshold: the Frontier genesis timestamp). Every fork since Shanghai is
     * timestamp-activated, so this also separates live announcements from legacy ones.
     */
    public static final long TIMESTAMP_THRESHOLD = 1_438_269_973L;

    private static final int[] TABLE = new int[256];
    /** {@code TABLE[TOP_INDEX[b]] >>> 24 == b}: the top bytes of the 256 entries are all
     *  distinct, which is what makes a CRC32 step reversible. */
    private static final int[] TOP_INDEX = new int[256];

    static {
        for (int n = 0; n < 256; n++) {
            int c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
            TABLE[n] = c;
            TOP_INDEX[c >>> 24] = n;
        }
    }

    private ForkIds() {}

    /** CRC32 of {@code data} continued from the checksum {@code crc} (0 = a fresh CRC). */
    public static int update(int crc, byte[] data) {
        int c = ~crc;
        for (byte b : data) c = TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
        return ~c;
    }

    /**
     * The fork hash in effect once a fork activating at {@code activation} has passed,
     * given the hash {@code hash} in effect before it — {@code update(hash, be64(activation))}
     * without the allocation.
     */
    public static int successor(int hash, long activation) {
        int c = ~hash;
        for (int shift = 56; shift >= 0; shift -= 8) {
            c = TABLE[(c ^ (int) (activation >>> shift)) & 0xff] ^ (c >>> 8);
        }
        return ~c;
    }

    /**
     * The activation {@code T} (0 ≤ T < 2³²) with {@code successor(hash, T) == next} —
     * there is always exactly one, found in O(1) ("CRC forcing"): with be64(T)'s four high
     * bytes zero, the four low bytes map bijectively onto the final register. Each step's
     * table index is fixed by the top byte of the register after it, so walk the target
     * back four steps to learn the indices, then pick each byte to land on its index.
     */
    public static long activationOf(int hash, int next) {
        int a = ~hash;
        for (int k = 0; k < 4; k++) a = TABLE[a & 0xff] ^ (a >>> 8);   // be64(T)'s zero high bytes
        int z = ~next;
        int[] idx = new int[4];
        for (int k = 3; k >= 0; k--) {
            idx[k] = TOP_INDEX[z >>> 24];
            z = (z ^ TABLE[idx[k]]) << 8;
        }
        long t = 0;
        for (int k = 0; k < 4; k++) {
            t = t << 8 | ((a ^ idx[k]) & 0xff);
            a = TABLE[idx[k]] ^ (a >>> 8);
        }
        return t;
    }

    /** A 4-byte big-endian fork hash as an int. */
    public static int toInt(byte[] hash) {
        if (hash == null || hash.length != 4) {
            throw new IllegalArgumentException("fork hash must be 4 bytes");
        }
        return (hash[0] & 0xff) << 24 | (hash[1] & 0xff) << 16 | (hash[2] & 0xff) << 8 | (hash[3] & 0xff);
    }

    /** {@code 0x}-prefixed, 8 lowercase hex digits — the form clients log fork ids in. */
    public static String toHex(int hash) {
        return String.format(Locale.ROOT, "0x%08x", hash);
    }
}
