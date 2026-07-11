package io.myotis.evm.besu;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Cross-BASE pins for the fork-boundary constants (hex vs the decimal
 * definitions): a transposition typo in either form cannot survive both
 * representations. Twin of the Rust {@code osaka_times_pin_their_sources} —
 * these constants are trust-critical (a wrong one silently mis-selects EVM
 * rules) and previously had no pin at all on the Java side.
 */
class ForkTimePinsTest {

    @Test
    void forkTimesMatchTheirHexForms() {
        assertEquals(0x6437_3057L, EvmFactory.SHANGHAI_TIME);
        assertEquals(0x65f1_b057L, EvmFactory.CANCUN_TIME);
        assertEquals(0x681b_3057L, EvmFactory.PRAGUE_TIME);
        assertEquals(0x6930_b057L, EvmFactory.OSAKA_TIME);
    }

    @Test
    void sepoliaForkTimesMatchTheirHexForms() {
        assertEquals(0x63fd_7d60L, EvmFactory.SEPOLIA_SHANGHAI_TIME);
        assertEquals(0x65b9_7d60L, EvmFactory.SEPOLIA_CANCUN_TIME);
        assertEquals(0x67c7_fd60L, EvmFactory.SEPOLIA_PRAGUE_TIME);
        assertEquals(0x68ed_fd60L, EvmFactory.SEPOLIA_OSAKA_TIME);
    }

    @Test
    void gnosisForkTimesMatchTheNethermindHex() {
        assertEquals(0x64c8_edbcL, EvmFactory.GNOSIS_SHANGHAI_TIME);
        assertEquals(0x65ef_4dbcL, EvmFactory.GNOSIS_CANCUN_TIME);
        assertEquals(0x6812_2dbcL, EvmFactory.GNOSIS_PRAGUE_TIME);
        assertEquals(0x69de_2dbcL, EvmFactory.GNOSIS_OSAKA_TIME);
    }
}
