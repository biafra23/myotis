package io.myotis.rpc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import io.myotis.evm.besu.EvmFactory;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/**
 * Pins the Java engine's refusal path: {@code rpcCallDetailed} /
 * {@code rpcEstimateGasDetailed} map a throwable chain carrying
 * {@link EvmExecutionError.UnsupportedFork} to a REFUSED result (served as the
 * permanent -32602) via this cause-walk — and nothing else may read as a
 * refusal (a transient failure must stay the retryable UNAVAILABLE).
 */
class UnsupportedForkOfTest {

    private static BlockContext sepolia(final long ts) {
        return new BlockContext(new byte[32], 10_000_000L, ts, BigInteger.ONE,
                io.myotis.evm.Address.ZERO, new byte[32], BigInteger.valueOf(11_155_111L),
                30_000_000L);
    }

    @Test
    void theFactoryRefusalIsFoundThroughWrappedCauses() {
        // The real production refusal, in the shape the dedup path produces:
        // ExecutionException(RuntimeException(EvmExecutionException)).
        EvmExecutionException refusal = assertThrows(EvmExecutionException.class,
                () -> EvmFactory.requireSupported(sepolia(EvmFactory.SEPOLIA_AMSTERDAM_TIME)));
        Exception chain = new java.util.concurrent.ExecutionException(new RuntimeException(refusal));
        String reason = VerifiedRpcBackend.unsupportedForkOf(chain);
        assertNotNull(reason);
        assertTrue(reason.contains("Amsterdam"), reason);
    }

    /**
     * The head-build warm-up gate: primeConfirmContracts / replayHotCalls run only when
     * {@code evmRefusalOf} is null. It reads the factory's own refusal — a head past
     * Sepolia's Amsterdam (every call there is REFUSED) is not warmed, the block before
     * it is, and a head below the fork floor is not — and it never throws.
     */
    @Test
    void theHeadWarmGateSkipsAHeadTheFactoryRefuses() {
        String amsterdam = VerifiedRpcBackend.evmRefusalOf(sepolia(EvmFactory.SEPOLIA_AMSTERDAM_TIME));
        assertNotNull(amsterdam);
        assertTrue(amsterdam.contains("Amsterdam"), amsterdam);
        assertNull(VerifiedRpcBackend.evmRefusalOf(sepolia(EvmFactory.SEPOLIA_AMSTERDAM_TIME - 1)));
        assertNotNull(VerifiedRpcBackend.evmRefusalOf(sepolia(EvmFactory.SEPOLIA_SHANGHAI_TIME - 1)));
        assertNotNull(VerifiedRpcBackend.evmRefusalOf(null));
    }

    @Test
    void otherFailuresAreNotRefusals() {
        assertNull(VerifiedRpcBackend.unsupportedForkOf(new RuntimeException("timeout")));
        assertNull(VerifiedRpcBackend.unsupportedForkOf(
                new EvmExecutionException(new EvmExecutionError.Reverted(new byte[0]))));
        assertNull(VerifiedRpcBackend.unsupportedForkOf(new java.util.concurrent.ExecutionException(
                new EvmExecutionException(
                        new EvmExecutionError.StateUnavailable(new byte[32], null, null)))));
        // The pre-existing fork-floor refusal keeps its old (unavailable) mapping.
        assertNull(VerifiedRpcBackend.unsupportedForkOf(assertThrows(IllegalArgumentException.class,
                () -> EvmFactory.requireSupported(sepolia(EvmFactory.SEPOLIA_SHANGHAI_TIME - 1)))));
    }
}
