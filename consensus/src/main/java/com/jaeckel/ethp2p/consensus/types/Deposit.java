package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: Deposit
 * proof(Vector[Bytes32, 33] = 1056B) + data(DepositData = 184B)
 * Total fixed size: 1240 bytes
 */
public record Deposit(
        byte[][] proof,
        DepositData data
) {

    public static final int SSZ_SIZE = 1240;

    public static Deposit decode(byte[] raw, int offset) {
        byte[][] proof = new byte[33][];
        for (int i = 0; i < 33; i++) {
            proof[i] = Arrays.copyOfRange(raw, offset + i * 32, offset + i * 32 + 32);
        }
        DepositData data = DepositData.decode(raw, offset + 1056);
        return new Deposit(proof, data);
    }

    public byte[] hashTreeRoot() {
        // proof: Vector[Bytes32, 33] — 33 chunks, merkleize with next_pow2(33) = 64
        byte[] proofRoot = SszUtil.merkleize(proof);
        byte[] dataRoot = data.hashTreeRoot();
        return SszUtil.hashTreeRootContainer(proofRoot, dataRoot);
    }

    /** Hash from raw bytes at offset without constructing the record. */
    public static byte[] hashTreeRootAt(byte[] data, int offset) {
        return decode(data, offset).hashTreeRoot();
    }
}
