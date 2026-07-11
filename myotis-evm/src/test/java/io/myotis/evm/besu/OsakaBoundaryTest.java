package io.myotis.evm.besu;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.myotis.evm.BlockContext;
import java.math.BigInteger;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.evm.EvmSpecVersion;
import org.junit.jupiter.api.Test;

/**
 * The OSAKA fork boundary (Fusaka's EL half), twinned with the Rust engine's
 * `osaka_boundaries_map_on_every_chain` so spec selection can't diverge:
 * timestamps at/after go-ethereum's MainnetChainConfig.OsakaTime select the
 * Osaka EVM (P256VERIFY at 0x100), a second earlier stays Prague.
 */
class OsakaBoundaryTest {

    private static final Address P256 =
            Address.fromHexString("0x0000000000000000000000000000000000000100");

    private static BlockContext ctx(final long ts) {
        return new BlockContext(
                new byte[32],
                /* blockNumber */ 21_000_000L,
                /* timestamp   */ ts,
                /* baseFee     */ BigInteger.valueOf(1_000_000_000L),
                /* coinbase    */ io.myotis.evm.Address.ZERO,
                /* prevRandao  */ new byte[32],
                /* chainId     */ BigInteger.ONE,
                /* gasLimit    */ 30_000_000L);
    }

    @Test
    void osakaTimestampSelectsOsakaWithP256() {
        EvmFactory.EvmAndPrecompiles built = EvmFactory.buildForBlock(ctx(EvmFactory.OSAKA_TIME));
        assertEquals(EvmSpecVersion.OSAKA, built.specVersion());
        assertNotNull(built.precompiles().get(P256), "P256VERIFY must be registered under Osaka");
    }

    @Test
    void secondBeforeOsakaStaysPragueWithoutP256() {
        EvmFactory.EvmAndPrecompiles built =
                EvmFactory.buildForBlock(ctx(EvmFactory.OSAKA_TIME - 1));
        assertEquals(EvmSpecVersion.PRAGUE, built.specVersion());
        assertNull(built.precompiles().get(P256), "P256VERIFY is Osaka-only");
    }
}
