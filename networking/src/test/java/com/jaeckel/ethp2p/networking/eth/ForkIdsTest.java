package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.networking.NetworkConfig;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.SplittableRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * EIP-2124 fork-id arithmetic against real-world values: the CRC32 check value, the
 * full mainnet chain up to our pinned id, and Sepolia's Glamsterdam fork id.
 */
class ForkIdsTest {

    /** Sepolia's Glamsterdam activation (ethereum/pm#2205: epoch 353024, 2026-10-06 13:53:36 UTC). */
    static final long SEPOLIA_GLAMSTERDAM = 1_791_294_816L;
    /** Sepolia's post-Glamsterdam fork id, as published with that activation. */
    static final int SEPOLIA_GLAMSTERDAM_FORK_ID = 0x6c1d9423;

    @Test
    void crc32CheckValue() {
        // The standard CRC-32/IEEE check value, from a fresh (0) checksum.
        assertEquals(0xCBF43926, ForkIds.update(0, "123456789".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void genesisChecksumIsThePinnedFrontierForkId() {
        assertEquals(ForkIds.toInt(NetworkConfig.MAINNET_GENESIS_FORK_HASH),
                ForkIds.update(0, NetworkConfig.MAINNET.genesisHash().toArrayUnsafe()));
    }

    @Test
    void mainnetChainReproducesOurPinnedForkId() {
        // Every mainnet activation Frontier → BPO2 (blocks, then timestamps from
        // Shanghai on; Constantinople+Petersburg share one block and count once).
        long[] activations = {
                1_150_000, 1_920_000, 2_463_000, 2_675_000, 4_370_000, 7_280_000, 9_069_000,
                9_200_000, 12_244_000, 12_965_000, 13_773_000, 15_050_000,
                1_681_338_455L, 1_710_338_135L, 1_746_612_311L,      // Shanghai, Cancun, Prague
                1_764_798_551L, 1_765_290_071L, 1_767_747_671L};     // Osaka, BPO1, BPO2
        int hash = ForkIds.update(0, NetworkConfig.MAINNET.genesisHash().toArrayUnsafe());
        for (long a : activations) hash = ForkIds.successor(hash, a);
        assertEquals(ForkIds.toInt(NetworkConfig.MAINNET.forkIdHash()), hash);
    }

    @Test
    void sepoliaGlamsterdamIsTheSuccessorOfOurPin() {
        assertEquals(SEPOLIA_GLAMSTERDAM_FORK_ID,
                ForkIds.successor(ForkIds.toInt(NetworkConfig.SEPOLIA.forkIdHash()), SEPOLIA_GLAMSTERDAM));
    }

    @Test
    void successorIsUpdateOverBigEndianUint64() {
        long[] values = {0, 1, 1_150_000, SEPOLIA_GLAMSTERDAM, Long.MAX_VALUE, -1L};
        for (long v : values) {
            byte[] be = ByteBuffer.allocate(8).putLong(v).array();
            assertEquals(ForkIds.update(0x268956b6, be), ForkIds.successor(0x268956b6, v), "value " + v);
        }
    }

    @Test
    void activationOfInvertsSuccessorExactly() {
        int pin = ForkIds.toInt(NetworkConfig.SEPOLIA.forkIdHash());
        assertEquals(SEPOLIA_GLAMSTERDAM, ForkIds.activationOf(pin, SEPOLIA_GLAMSTERDAM_FORK_ID));
        SplittableRandom rnd = new SplittableRandom(7);
        for (int i = 0; i < 100_000; i++) {
            int hash = rnd.nextInt();
            long t = rnd.nextLong() >>> 32;   // any activation below 2^32
            assertEquals(t, ForkIds.activationOf(hash, ForkIds.successor(hash, t)), "hash " + hash + " t " + t);
        }
    }

    @Test
    void everyHashPlacesSomewhereSoAPlacementIsNotProof() {
        // A hash nobody announced still inverts to an activation — here even an epoch-aligned
        // one (2026-09-23T23:55:12Z on Sepolia's grid). Anyone can mint such a "successor",
        // which is why ForkWatch votes by network and weighs dissent instead of trusting it.
        int pin = ForkIds.toInt(NetworkConfig.SEPOLIA.forkIdHash());
        long t = ForkIds.activationOf(pin, 0x47e12c82);
        assertEquals(1_790_207_712L, t);
        assertEquals(0, (t - NetworkConfig.SEPOLIA.clGenesisTime()) % (32 * 12));
        assertEquals(0x47e12c82, ForkIds.successor(pin, t));
    }

    @Test
    void conversions() {
        assertEquals(0x07c9462e, ForkIds.toInt(new byte[]{0x07, (byte) 0xc9, 0x46, 0x2e}));
        assertEquals("0x07c9462e", ForkIds.toHex(0x07c9462e));
        assertEquals("0xffffffff", ForkIds.toHex(-1));
        assertThrows(IllegalArgumentException.class, () -> ForkIds.toInt(new byte[3]));
        assertThrows(IllegalArgumentException.class, () -> ForkIds.toInt(null));
    }
}
