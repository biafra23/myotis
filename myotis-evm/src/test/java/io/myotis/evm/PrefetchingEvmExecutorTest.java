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

        byte[] directResult = direct.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        byte[] prefetchedResult = prefetched.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        assertEquals(
                HexFormat.of().formatHex(directResult),
                HexFormat.of().formatHex(prefetchedResult));
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

    // ---- Sentinel-mode-specific tests --------------------------------------

    /**
     * Three independent SLOADs whose slot values are all non-zero. With
     * trace-based execution this used to require N=3 serial network round
     * trips in iteration 0; with sentinel-return iteration 0 records all
     * three at memory speed, the parallel batch fetch covers them in one
     * round trip, and iteration 1 returns the real value of slot 0.
     *
     * <p>The fixture oracle is synchronous, so we can't time the win — but we
     * can verify that the convergence count is still 2 (not more, despite
     * the multi-slot access set) and that the returned value is correct.
     */
    @Test
    void multipleSloadsConvergeInTwoIterationsWithSentinelMode() throws Exception {
        // PUSH1 0; SLOAD; PUSH1 1; SLOAD; PUSH1 2; SLOAD; POP; POP;
        // PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
        byte[] bytecode = HexFormat.of().parseHex(
                "60005460015460025450506000526020600 0f3".replace(" ", ""));
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(CONTRACT, 0L, BigInteger.ZERO,
                        FixtureSnapStateOracle.codeHashOf(bytecode)))
                .bytecode(bytecode)
                .storage(CONTRACT, BigInteger.ZERO, BigInteger.TEN)
                .storage(CONTRACT, BigInteger.ONE, BigInteger.valueOf(20))
                .storage(CONTRACT, BigInteger.TWO, BigInteger.valueOf(30))
                .build();
        var tracker = new ConvergenceTracker();
        var executor = new PrefetchingEvmExecutor(new DefaultEvmExecutor(oracle),
                PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP, tracker);

        byte[] result = executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        assertEquals(BigInteger.TEN, AbiDecoder.uint256(result, 0));
        assertEquals(2, tracker.snapshot().get(0),
                "three independent SLOADs should still converge in 2 iterations");
    }

    /**
     * Sentinel mode causes iteration 0 to see {@code SLOAD(0) == 0}, which
     * trips an explicit {@code REVERT} in the bytecode. The convergence loop
     * must absorb that exception and run iteration 1 with real values
     * (slot 0 = 42), producing a successful return.
     *
     * <p>This is the test that proves "iteration 0's wrong values don't leak
     * to the caller" — without the catch in {@link PrefetchingEvmExecutor},
     * the first iteration's revert would propagate as the call's failure.
     */
    @Test
    void sentinelIteration0RevertDoesNotSurface() throws Exception {
        // Pseudocode:
        //   v = sload(0)
        //   if (v == 0) revert
        //   else return v
        //
        // 60 00 SLOAD DUP1 ISZERO PUSH1 0x10 JUMPI
        // PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
        // JUMPDEST PUSH1 0 PUSH1 0 REVERT
        byte[] bytecode = HexFormat.of().parseHex(
                "6000" + "54" + "80" + "15" + "6010" + "57" +
                "6000" + "52" + "6020" + "6000" + "f3" +
                "5b" + "6000" + "6000" + "fd");
        BigInteger realBalance = BigInteger.valueOf(42);
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(CONTRACT, 0L, BigInteger.ZERO,
                        FixtureSnapStateOracle.codeHashOf(bytecode)))
                .bytecode(bytecode)
                .storage(CONTRACT, BigInteger.ZERO, realBalance)
                .build();
        var tracker = new ConvergenceTracker();
        var executor = new PrefetchingEvmExecutor(new DefaultEvmExecutor(oracle),
                PrefetchingEvmExecutor.DEFAULT_ITERATION_CAP, tracker);

        byte[] result = executor.callView(CONTRACT, balanceOfCalldata(), ctx()).get();
        // Without sentinel-revert recovery the call would fail with Reverted.
        assertEquals(realBalance, AbiDecoder.uint256(result, 0));
        assertEquals(2, tracker.snapshot().get(0));
    }

    /**
     * Last line of defense: regardless of execution path through the prefetch
     * loop, the result of {@code PrefetchingEvmExecutor.callView} must be
     * byte-for-byte identical to {@code DefaultEvmExecutor.callView}. The
     * sentinel run produces wrong intermediate state, but the convergence
     * loop must always end up returning the real-iteration result.
     */
    @Test
    void prefetchedAndDirectAgreeAcrossManyCallShapes() throws Exception {
        record Case(byte[] bytecode, java.util.List<long[]> storage) {}
        var cases = java.util.List.of(
                new Case(SLOAD_SLOT_0, java.util.List.of(new long[]{0, 100})),
                new Case(SLOAD_TWO_SLOTS, java.util.List.of(
                        new long[]{0, 7}, new long[]{1, 13})),
                new Case(HexFormat.of().parseHex(
                        "60005460015460025450506000526020600 0f3".replace(" ", "")),
                        java.util.List.of(
                                new long[]{0, 42}, new long[]{1, 99}, new long[]{2, 256})));

        for (Case c : cases) {
            var b = FixtureSnapStateOracle.builder()
                    .account(new AccountState(CONTRACT, 0L, BigInteger.ZERO,
                            FixtureSnapStateOracle.codeHashOf(c.bytecode())))
                    .bytecode(c.bytecode());
            for (long[] s : c.storage()) {
                b.storage(CONTRACT, BigInteger.valueOf(s[0]), BigInteger.valueOf(s[1]));
            }
            var oracle = b.build();

            byte[] direct = new DefaultEvmExecutor(oracle)
                    .callView(CONTRACT, balanceOfCalldata(), ctx()).get();
            byte[] prefetched = new PrefetchingEvmExecutor(new DefaultEvmExecutor(oracle))
                    .callView(CONTRACT, balanceOfCalldata(), ctx()).get();
            assertEquals(
                    HexFormat.of().formatHex(direct),
                    HexFormat.of().formatHex(prefetched),
                    "mismatch for bytecode " + HexFormat.of().formatHex(c.bytecode()));
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
