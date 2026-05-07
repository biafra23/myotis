package io.myotis.evm;

import io.myotis.evm.abi.AbiDecoder;
import io.myotis.evm.abi.AbiEncoder;
import io.myotis.evm.abi.FunctionSignature;
import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.prefetch.ConvergenceTracker;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.BytecodeCache;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Convergence tests for the Phase 2 prefetch loop.
 *
 * <p>Each test runs hand-written bytecode through {@link PrefetchingEvmExecutor}
 * against a {@link FixtureSnapStateOracle}. The fixture oracle answers
 * synchronously (no real network), so the latency claim of the prefetch loop
 * isn't measurable here — but the convergence-iteration-count claim is, and
 * that's the unit-testable invariant.
 *
 * <p>Convergence-count expectations follow directly from the loop logic in
 * {@link PrefetchingEvmExecutor}: at least one EVM run is needed to discover
 * the access set, and at least one more is needed to confirm the access set
 * is stable. Hence the minimum convergence count is 2, regardless of how
 * trivial the bytecode is.
 */
class PrefetchingEvmExecutorTest {

    /** PUSH1 0; SLOAD; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN */
    private static final byte[] SLOAD_SLOT_0 =
            HexFormat.of().parseHex("60005460005260206000f3");

    /**
     * Reads two slots and concatenates them into the return buffer.
     * Layout: SLOAD(0) -> mem[0..32]; SLOAD(1) -> mem[32..64]; RETURN(0, 64).
     */
    private static final byte[] SLOAD_TWO_SLOTS = HexFormat.of().parseHex(
            "60005460005260015460205260406000f3");

    private static final BigInteger SLOT_0_VALUE = new BigInteger("12345678900000000000000");
    private static final BigInteger SLOT_1_VALUE = BigInteger.valueOf(42);

    private static final io.myotis.evm.Address CONTRACT =
            io.myotis.evm.Address.fromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

    @Test
    void simpleSloadConvergesInTwoIterations() throws Exception {
        var oracle = fixtureOracle(SLOAD_SLOT_0)
                .storage(CONTRACT, BigInteger.ZERO, SLOT_0_VALUE)
                .build();
        var inner = new DefaultEvmExecutor(oracle);
        var convergenceTracker = new ConvergenceTracker();
        var executor = new PrefetchingEvmExecutor(inner,
                PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP, convergenceTracker);

        byte[] result = executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        assertEquals(SLOT_0_VALUE, AbiDecoder.uint256(result, 0),
                "result must be the value at slot 0 — prefetch must not change correctness");

        // Two iterations: the first discovers the (CONTRACT, 0) access; the
        // second observes the same access but recognises it's already in the
        // seen set, so it converges.
        assertEquals(1, convergenceTracker.snapshot().size(),
                "exactly one call should have been recorded");
        assertEquals(2, convergenceTracker.snapshot().get(0),
                "simple single-SLOAD bytecode should converge in 2 iterations");
    }

    @Test
    void twoSloadsConvergeInTwoIterations() throws Exception {
        var oracle = fixtureOracle(SLOAD_TWO_SLOTS)
                .storage(CONTRACT, BigInteger.ZERO, SLOT_0_VALUE)
                .storage(CONTRACT, BigInteger.ONE, SLOT_1_VALUE)
                .build();
        var inner = new DefaultEvmExecutor(oracle);
        var convergenceTracker = new ConvergenceTracker();
        var executor = new PrefetchingEvmExecutor(inner,
                PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP, convergenceTracker);

        byte[] result = executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        assertEquals(64, result.length, "two-slot return must be 64 bytes");
        assertEquals(SLOT_0_VALUE, AbiDecoder.uint256(result, 0));
        assertEquals(SLOT_1_VALUE, AbiDecoder.uint256(result, 32));

        // Both slots get discovered in iteration 0, both are seen by iteration 1.
        // Convergence = 2 even though the access set has two entries; the
        // prefetch loop's iteration count is independent of the access cardinality.
        assertEquals(2, convergenceTracker.snapshot().get(0),
                "two-SLOAD bytecode in a single straight path should still converge in 2");
    }

    @Test
    void iterationCapOfOneAlwaysExceeds() {
        // Cap=1 means the loop runs once and never gets a chance to confirm
        // stability — we always throw IterationLimitExceeded. This is the
        // test that the cap path is actually wired up.
        var oracle = fixtureOracle(SLOAD_SLOT_0)
                .storage(CONTRACT, BigInteger.ZERO, SLOT_0_VALUE)
                .build();
        var inner = new DefaultEvmExecutor(oracle);
        var executor = new PrefetchingEvmExecutor(inner, 1, new ConvergenceTracker());

        try {
            executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
            fail("expected IterationLimitExceeded");
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException
                    ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.IterationLimitExceeded.class, eee.error());
            assertEquals(1,
                    ((EvmExecutionError.IterationLimitExceeded) eee.error()).cap());
        }
    }

    @Test
    void prefetchingDoesNotChangeCorrectness() throws Exception {
        // Sanity: the same bytecode + state through both DefaultEvmExecutor
        // and PrefetchingEvmExecutor must return byte-identical bytes. This
        // is the regression net for the entire phase: optimization that
        // changes results is worse than no optimization.
        var oracle = fixtureOracle(SLOAD_SLOT_0)
                .storage(CONTRACT, BigInteger.ZERO, SLOT_0_VALUE)
                .build();
        var direct = new DefaultEvmExecutor(oracle);
        var prefetched = new PrefetchingEvmExecutor(new DefaultEvmExecutor(oracle));

        byte[] direct_result = direct.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        byte[] prefetched_result = prefetched.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        assertEquals(
                HexFormat.of().formatHex(direct_result),
                HexFormat.of().formatHex(prefetched_result));
    }

    @Test
    void convergenceTrackerRecordsAcrossMultipleCalls() throws Exception {
        var oracle = fixtureOracle(SLOAD_SLOT_0)
                .storage(CONTRACT, BigInteger.ZERO, SLOT_0_VALUE)
                .build();
        var convergenceTracker = new ConvergenceTracker();
        var executor = new PrefetchingEvmExecutor(new DefaultEvmExecutor(oracle),
                PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP, convergenceTracker);

        executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();

        var counts = convergenceTracker.snapshot();
        assertEquals(3, counts.size(), "tracker should record one entry per call");
        for (int c : counts) {
            assertTrue(c >= 2 && c <= PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP,
                    "iteration count " + c + " is out of expected range");
        }
    }

    // ---- Helpers -----------------------------------------------------------

    private static FixtureSnapStateOracle.Builder fixtureOracle(byte[] bytecode) {
        byte[] codeHash = FixtureSnapStateOracle.codeHashOf(bytecode);
        return FixtureSnapStateOracle.builder()
                .account(new AccountState(CONTRACT, 0L, BigInteger.ZERO, codeHash))
                .bytecode(bytecode);
    }

    private static byte[] balanceOfCalldata() {
        FunctionSignature sig = FunctionSignature.of("balanceOf(address)");
        return AbiEncoder.encodeCall(sig,
                AbiEncoder.address(io.myotis.evm.Address.fromHex(
                        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")));
    }

    private static BlockContext ctx() {
        return new BlockContext(
                new byte[32],
                19_500_000L,
                EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(1_000_000_000L),
                io.myotis.evm.Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
    }
}
