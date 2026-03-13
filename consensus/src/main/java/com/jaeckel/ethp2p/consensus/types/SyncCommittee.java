package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: SyncCommittee
 * pubkeys (Vector[BLSPubkey, 512] = 512 * 48 bytes = 24576 bytes)
 * aggregatePubkey (BLSPubkey = 48 bytes)
 * Total: 24624 bytes
 */
public record SyncCommittee(
        byte[][] pubkeys,
        byte[] aggregatePubkey
) {

    public static final int PUBKEY_COUNT = 512;
    public static final int PUBKEY_SIZE = 48;
    public static final int ENCODED_SIZE = PUBKEY_COUNT * PUBKEY_SIZE + PUBKEY_SIZE; // 24624

    public SyncCommittee {
        if (pubkeys.length != PUBKEY_COUNT) throw new IllegalArgumentException("pubkeys must have 512 entries");
        for (byte[] pk : pubkeys) {
            if (pk.length != PUBKEY_SIZE) throw new IllegalArgumentException("each pubkey must be 48 bytes");
        }
        if (aggregatePubkey.length != PUBKEY_SIZE) throw new IllegalArgumentException("aggregatePubkey must be 48 bytes");
    }

    /**
     * Decode a SyncCommittee from 24624 bytes of SSZ.
     */
    public static SyncCommittee decode(byte[] ssz) {
        if (ssz.length < ENCODED_SIZE) {
            throw new IllegalArgumentException("SyncCommittee requires " + ENCODED_SIZE + " bytes, got " + ssz.length);
        }
        byte[][] pubkeys = new byte[PUBKEY_COUNT][PUBKEY_SIZE];
        int offset = 0;
        for (int i = 0; i < PUBKEY_COUNT; i++) {
            pubkeys[i] = Arrays.copyOfRange(ssz, offset, offset + PUBKEY_SIZE);
            offset += PUBKEY_SIZE;
        }
        byte[] aggregatePubkey = Arrays.copyOfRange(ssz, offset, offset + PUBKEY_SIZE);
        return new SyncCommittee(pubkeys, aggregatePubkey);
    }

    /**
     * Compute the hash_tree_root of a single BLS pubkey (48 bytes).
     * Process: zero-pad to 64 bytes, split into 2 chunks of 32 each, merkleize.
     */
    private static byte[] pubkeyHashTreeRoot(byte[] pubkey) {
        byte[] padded = new byte[64];
        System.arraycopy(pubkey, 0, padded, 0, PUBKEY_SIZE);
        byte[] chunk0 = Arrays.copyOfRange(padded, 0, 32);
        byte[] chunk1 = Arrays.copyOfRange(padded, 32, 64);
        return SszUtil.merkleize(new byte[][]{chunk0, chunk1});
    }

    /**
     * hash_tree_root of this container.
     *
     * pubkeys vector:
     *   - Each pubkey: zero-pad to 64 bytes, split into 2 chunks of 32, merkleize → pubkey_root
     *   - Vector[BLSPubkey, 512]: merkleize(512 pubkey_roots) — already power of 2
     *
     * aggregatePubkey:
     *   - Same as single pubkey: 48 bytes → 64 bytes → 2 chunks → merkleize
     *
     * Container: merkleize([pubkeysRoot, aggregatePubkeyRoot])
     */
    public byte[] hashTreeRoot() {
        // Compute pubkeys vector root
        byte[][] pubkeyRoots = new byte[PUBKEY_COUNT][];
        for (int i = 0; i < PUBKEY_COUNT; i++) {
            pubkeyRoots[i] = pubkeyHashTreeRoot(pubkeys[i]);
        }
        byte[] pubkeysVectorRoot = SszUtil.merkleize(pubkeyRoots);

        // Compute aggregatePubkey root
        byte[] aggregatePubkeyRoot = pubkeyHashTreeRoot(aggregatePubkey);

        // Container merkleize
        return SszUtil.hashTreeRootContainer(pubkeysVectorRoot, aggregatePubkeyRoot);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SyncCommittee other)) return false;
        if (!Arrays.equals(aggregatePubkey, other.aggregatePubkey)) return false;
        if (pubkeys.length != other.pubkeys.length) return false;
        for (int i = 0; i < pubkeys.length; i++) {
            if (!Arrays.equals(pubkeys[i], other.pubkeys[i])) return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(aggregatePubkey);
        for (byte[] pk : pubkeys) {
            result = 31 * result + Arrays.hashCode(pk);
        }
        return result;
    }
}
