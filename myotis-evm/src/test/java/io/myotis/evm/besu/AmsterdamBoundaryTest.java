package io.myotis.evm.besu;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.myotis.evm.BlockContext;
import io.myotis.evm.DefaultEvmExecutor;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import io.myotis.evm.PrefetchingEvmExecutor;
import io.myotis.evm.UnsignedTransaction;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.FixtureSnapStateOracle;
import io.myotis.evm.world.SnapStateOracle;
import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.evm.EvmSpecVersion;
import org.junit.jupiter.api.Test;

/**
 * The AMSTERDAM fork boundary (Glamsterdam's EL half), twinned with the Rust
 * engine's `amsterdam_boundaries_map_on_every_chain` — deliberately ASYMMETRIC:
 * at Sepolia's activation the Rust engine selects revm's AMSTERDAM, while this
 * engine REFUSES (Besu 26.4 cannot price Amsterdam) instead of silently
 * executing the block under Osaka rules. A second earlier is Osaka on both;
 * mainnet and gnosis have no Amsterdam date and stay Osaka on both.
 */
class AmsterdamBoundaryTest {

    private static final long SEPOLIA = 11_155_111L;

    private static final Address P256 =
            Address.fromHexString("0x0000000000000000000000000000000000000100");

    private static BlockContext ctx(final long chainId, final long ts) {
        return new BlockContext(
                new byte[32],
                /* blockNumber */ 10_000_000L,
                /* timestamp   */ ts,
                /* baseFee     */ BigInteger.valueOf(1_000_000_000L),
                /* coinbase    */ io.myotis.evm.Address.ZERO,
                /* prevRandao  */ new byte[32],
                /* chainId     */ BigInteger.valueOf(chainId),
                /* gasLimit    */ 30_000_000L);
    }

    private static void assertUnsupportedFork(final Throwable t) {
        Throwable c = t instanceof ExecutionException ? t.getCause() : t;
        EvmExecutionException e = assertInstanceOf(EvmExecutionException.class, c);
        assertInstanceOf(EvmExecutionError.UnsupportedFork.class, e.error());
    }

    @Test
    void secondBeforeAmsterdamStaysOsaka() {
        EvmFactory.EvmAndPrecompiles built =
                EvmFactory.buildForBlock(ctx(SEPOLIA, EvmFactory.SEPOLIA_AMSTERDAM_TIME - 1));
        assertEquals(EvmSpecVersion.OSAKA, built.specVersion());
        assertNotNull(built.precompiles().get(P256), "the Osaka precompile set is served");
    }

    @Test
    void amsterdamTimestampIsRefusedNotPricedAsOsaka() {
        for (long ts : new long[] {EvmFactory.SEPOLIA_AMSTERDAM_TIME, Long.MAX_VALUE}) {
            BlockContext c = ctx(SEPOLIA, ts);
            assertUnsupportedFork(assertThrows(EvmExecutionException.class,
                    () -> EvmFactory.buildForBlock(c)));
            // The build-nothing check refuses too: callers that answer without an
            // EVM (the rpc-backend estimate's plain-transfer fast path) rely on it.
            assertUnsupportedFork(assertThrows(EvmExecutionException.class,
                    () -> EvmFactory.requireSupported(c)));
        }
    }

    @Test
    void mainnetAndGnosisHaveNoAmsterdamDate() {
        // Sepolia's activation must not flip them, nor may any far-future timestamp.
        for (long chainId : new long[] {1L, 100L}) {
            for (long ts : new long[] {EvmFactory.SEPOLIA_AMSTERDAM_TIME, Long.MAX_VALUE}) {
                assertEquals(EvmSpecVersion.OSAKA,
                        EvmFactory.buildForBlock(ctx(chainId, ts)).specVersion(),
                        "chain " + chainId + " at " + ts);
            }
        }
    }

    /** Counts state fetches — a refused block must not cost the peers anything. */
    private static final class CountingOracle implements SnapStateOracle {
        final AtomicInteger fetches = new AtomicInteger();
        private final SnapStateOracle inner = FixtureSnapStateOracle.builder().build();

        @Override
        public CompletableFuture<AccountState> fetchAccount(byte[] root, io.myotis.evm.Address a) {
            fetches.incrementAndGet();
            return inner.fetchAccount(root, a);
        }

        @Override
        public CompletableFuture<BigInteger> fetchStorage(byte[] root, io.myotis.evm.Address a,
                                                          BigInteger slot) {
            fetches.incrementAndGet();
            return inner.fetchStorage(root, a, slot);
        }

        @Override
        public CompletableFuture<byte[]> fetchBytecode(byte[] codeHash) {
            fetches.incrementAndGet();
            return inner.fetchBytecode(codeHash);
        }
    }

    @Test
    void executorsRefuseBeforeFetchingAnyState() {
        CountingOracle oracle = new CountingOracle();
        PrefetchingEvmExecutor exec = new PrefetchingEvmExecutor(new DefaultEvmExecutor(oracle));
        BlockContext at = ctx(SEPOLIA, EvmFactory.SEPOLIA_AMSTERDAM_TIME);
        io.myotis.evm.Address target = io.myotis.evm.Address.fromHex(
                "0x1111111111111111111111111111111111111111");

        assertUnsupportedFork(assertThrows(ExecutionException.class,
                () -> exec.callView(target, new byte[0], at).get()));
        UnsignedTransaction tx = new UnsignedTransaction(
                io.myotis.evm.Address.ZERO, target, BigInteger.ONE, new byte[0], null);
        assertUnsupportedFork(assertThrows(ExecutionException.class,
                () -> exec.estimateGas(tx, at).get()));
        assertEquals(0, oracle.fetches.get(), "the refusal must precede every state fetch");
    }
}
