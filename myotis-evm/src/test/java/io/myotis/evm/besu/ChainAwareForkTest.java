package io.myotis.evm.besu;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.myotis.evm.BlockContext;
import java.math.BigInteger;
import org.hyperledger.besu.evm.EvmSpecVersion;
import org.junit.jupiter.api.Test;

/**
 * Per-chain fork selection — the Java twin of the Rust {@code spec_for} tests
 * ({@code osaka_boundaries_map_on_every_chain} and the per-chain cascades), so
 * the two engines can never diverge on (chainId, block, timestamp) → spec.
 */
class ChainAwareForkTest {

    private static BlockContext ctx(final long chainId, final long block, final long ts) {
        return new BlockContext(
                new byte[32], block, ts, BigInteger.valueOf(1_000_000_000L),
                io.myotis.evm.Address.ZERO, new byte[32],
                BigInteger.valueOf(chainId), 30_000_000L);
    }

    private static EvmSpecVersion spec(final long chainId, final long block, final long ts) {
        return EvmFactory.buildForBlock(ctx(chainId, block, ts)).specVersion();
    }

    @Test
    void sepoliaUsesItsOwnSchedule() {
        long s = 11_155_111L;
        assertEquals(EvmSpecVersion.OSAKA, spec(s, 9_000_000, EvmFactory.SEPOLIA_OSAKA_TIME));
        assertEquals(EvmSpecVersion.PRAGUE, spec(s, 9_000_000, EvmFactory.SEPOLIA_OSAKA_TIME - 1));
        assertEquals(EvmSpecVersion.CANCUN, spec(s, 9_000_000, EvmFactory.SEPOLIA_PRAGUE_TIME - 1));
        assertEquals(EvmSpecVersion.SHANGHAI, spec(s, 9_000_000, EvmFactory.SEPOLIA_CANCUN_TIME - 1));
        // THE case the old mainnet-times-for-all table got wrong: sepolia's
        // Osaka window before mainnet's activation.
        assertEquals(EvmSpecVersion.OSAKA, spec(s, 9_000_000, EvmFactory.OSAKA_TIME - 1_000_000));
        assertThrows(IllegalArgumentException.class,
                () -> spec(s, 9_000_000, EvmFactory.SEPOLIA_SHANGHAI_TIME - 1));
    }

    @Test
    void gnosisUsesItsOwnSchedule() {
        long g = 100L;
        assertEquals(EvmSpecVersion.OSAKA, spec(g, 30_000_000, EvmFactory.GNOSIS_OSAKA_TIME));
        assertEquals(EvmSpecVersion.PRAGUE, spec(g, 30_000_000, EvmFactory.GNOSIS_OSAKA_TIME - 1));
        assertEquals(EvmSpecVersion.CANCUN, spec(g, 30_000_000, EvmFactory.GNOSIS_PRAGUE_TIME - 1));
        assertEquals(EvmSpecVersion.SHANGHAI, spec(g, 30_000_000, EvmFactory.GNOSIS_CANCUN_TIME - 1));
        // The flip side: mainnet's Osaka time must NOT flip gnosis early.
        assertEquals(EvmSpecVersion.PRAGUE, spec(g, 30_000_000, EvmFactory.OSAKA_TIME));
        assertThrows(IllegalArgumentException.class,
                () -> spec(g, 30_000_000, EvmFactory.GNOSIS_SHANGHAI_TIME - 1));
    }

    @Test
    void mainnetCascadeUnchanged() {
        assertEquals(EvmSpecVersion.OSAKA, spec(1, 21_000_000, EvmFactory.OSAKA_TIME));
        assertEquals(EvmSpecVersion.PRAGUE, spec(1, 21_000_000, EvmFactory.OSAKA_TIME - 1));
        assertEquals(EvmSpecVersion.PARIS, spec(1, 15_537_394, EvmFactory.SHANGHAI_TIME - 1));
        assertEquals(EvmSpecVersion.LONDON, spec(1, 12_965_000, EvmFactory.SHANGHAI_TIME - 1));
    }

    @Test
    void unknownChainFailsClosed() {
        // Never silently mainnet rules (Rust UnsupportedChain twin).
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> spec(137, 21_000_000, EvmFactory.OSAKA_TIME));
        assertTrue(e.getMessage().contains("unsupported chain id 137"), e.getMessage());
    }
}
