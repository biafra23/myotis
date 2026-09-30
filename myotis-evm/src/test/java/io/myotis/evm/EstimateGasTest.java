package io.myotis.evm;

import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit tests for {@link DefaultEvmExecutor#estimateGas}.
 *
 * <p>Each test sets up a fixture oracle with the contracts and balances
 * the transaction needs, asks the executor for an estimate, and verifies
 * the returned number sits in the expected range. Exact match isn't
 * useful — Besu's gas accounting is the source of truth, and geth's search
 * stops within 1.5% of the lowest limit that works, with the 15% buffer on
 * top — so the assertions are bounded ranges with rationale in comments, or
 * {@link #assertIsTheSearchedEstimate} against the lowest limit a call
 * actually runs with.
 */
class EstimateGasTest {

    private static final Address SENDER = Address.fromHex(
            "0x1111111111111111111111111111111111111111");
    private static final Address EOA_RECIPIENT = Address.fromHex(
            "0x2222222222222222222222222222222222222222");
    // Dummy address — the fixture installs an arbitrary SLOAD-and-return
    // bytecode here, unrelated to whatever lives at this slot on mainnet.
    // Using a placeholder avoids confusing test output that names a real
    // mainnet contract whose bytecode we're not actually executing.
    private static final Address CONTRACT = Address.fromHex(
            "0x3333333333333333333333333333333333333333");

    @Test
    void intrinsicGasMatchesYellowPaper() {
        // Empty calldata: just 21000 base.
        assertEquals(21_000L, DefaultEvmExecutor.computeIntrinsicGas(new byte[0]));
        // 4 per zero byte.
        assertEquals(21_000L + 4 * 4,
                DefaultEvmExecutor.computeIntrinsicGas(new byte[]{0, 0, 0, 0}));
        // 16 per non-zero byte (post-Istanbul EIP-2028).
        assertEquals(21_000L + 16 * 4,
                DefaultEvmExecutor.computeIntrinsicGas(new byte[]{1, 1, 1, 1}));
        // Mixed.
        assertEquals(21_000L + 16 + 4 + 16 + 4,
                DefaultEvmExecutor.computeIntrinsicGas(new byte[]{1, 0, 1, 0}));
    }

    @Test
    void ethTransferToEoaEstimatesIntrinsicPlusBuffer() throws Exception {
        // Sender has 1 ETH. Recipient is an EOA (no code). No calldata.
        // Expected gas: intrinsic 21000, EVM = 0, total * 1.15 ≈ 24150.
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L,
                        new BigInteger("1000000000000000000"),
                        emptyCodeHash()))
                .account(new AccountState(EOA_RECIPIENT, 0L, BigInteger.ZERO,
                        emptyCodeHash()))
                .build();
        var executor = new DefaultEvmExecutor(oracle);

        var tx = new UnsignedTransaction(
                SENDER, EOA_RECIPIENT,
                new BigInteger("100000000000000000"),  // 0.1 ETH
                new byte[0],
                /* gasLimit */ null);

        // Intrinsic 21000 is the lowest limit that runs; the estimate is the
        // search's answer over it (within 1.5%, then × 1.15).
        assertEquals(21_000L, lowestLimitThatRuns(executor, tx, ctx()));
        assertIsTheSearchedEstimate(executor, tx, ctx(), executor.estimateGas(tx, ctx()).get());
    }

    @Test
    void callIntoSimpleContractEstimatesIntrinsicPlusEvmGas() throws Exception {
        // Contract: load slot 0, return its value. Same bytecode used in
        // EvmFactoryTest. EVM should consume around 2100 gas (cold SLOAD
        // + a handful of cheap opcodes).
        byte[] bytecode = HexFormat.of().parseHex("60005460005260206000f3");
        BigInteger storedValue = new BigInteger("12345678900000000000000");
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L,
                        new BigInteger("1000000000000000000"),
                        emptyCodeHash()))
                .account(new AccountState(CONTRACT, 0L, BigInteger.ZERO,
                        FixtureSnapStateOracle.codeHashOf(bytecode)))
                .bytecode(bytecode)
                .storage(CONTRACT, BigInteger.ZERO, storedValue)
                .build();
        var executor = new DefaultEvmExecutor(oracle);

        var tx = new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);

        long estimate = executor.estimateGas(tx, ctx()).get();
        // Intrinsic 21000 + EVM ~2100 (cold SLOAD) + a few for MSTORE/RETURN.
        // Total ~23200 gas, * 1.15 ≈ 26680. Reasonable window: 24000-30000.
        assertTrue(estimate >= 24_000 && estimate <= 30_000,
                "simple SLOAD call should estimate in [24000, 30000]; got " + estimate);
    }

    @Test
    void revertingTransactionThrowsRatherThanReturningEstimate() {
        // Contract that always reverts with empty data.
        byte[] bytecode = HexFormat.of().parseHex("60006000fd");  // PUSH1 0; PUSH1 0; REVERT
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L,
                        new BigInteger("1000000000000000000"),
                        emptyCodeHash()))
                .account(new AccountState(CONTRACT, 0L, BigInteger.ZERO,
                        FixtureSnapStateOracle.codeHashOf(bytecode)))
                .bytecode(bytecode)
                .build();
        var executor = new DefaultEvmExecutor(oracle);

        var tx = new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);

        try {
            executor.estimateGas(tx, ctx()).get();
            fail("expected estimateGas to fail for a reverting transaction");
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException
                    ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.Reverted.class, eee.error());
        }
    }

    @Test
    void gasLimitBelowTheIntrinsicCostIsGasAllowanceExceeded() {
        // 21000 is a real cap, but 4 non-zero calldata bytes make the intrinsic
        // cost 21064: the transaction cannot fit — geth's answer (#509).
        var executor = new DefaultEvmExecutor(fundedSenderAnd(EOA_RECIPIENT, null));
        var tx = new UnsignedTransaction(
                SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[]{1, 2, 3, 4},
                /* gasLimit */ 21_000L);
        var error = estimateError(executor, tx, ctx());
        assertEquals(new EvmExecutionError.GasAllowanceExceeded(21_000L), error);
        assertEquals("gas required exceeds allowance (21000)",
                ((EvmExecutionError.GasAllowanceExceeded) error).message());
    }

    @Test
    void gasLimitBelow21000IsNoLimitAsInGeth() throws Exception {
        // geth reads a gas below 21000 as unset (a wallet's "gas": "0x0" means
        // "no opinion"), so it must not turn a valid estimate into an error.
        var executor = new DefaultEvmExecutor(fundedSenderAnd(EOA_RECIPIENT, null));
        long uncapped = executor.estimateGas(new UnsignedTransaction(
                SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[]{1}, null), ctx()).get();
        long zeroGas = executor.estimateGas(new UnsignedTransaction(
                SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[]{1}, 0L), ctx()).get();
        assertEquals(uncapped, zeroGas);
    }

    @Test
    void estimateNeverExceedsTheCallersGas() throws Exception {
        // Ten fresh SSTOREs: 21000 + 10 × 22106 = 242060 gross, ~278k buffered.
        var executor = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, sstores(10)));
        long uncapped = executor.estimateGas(new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null), ctx()).get();
        assertTrue(uncapped > 250_000, "buffered estimate above the cap; got " + uncapped);
        // A cap between the gross draw and the buffered answer IS the answer.
        assertEquals(250_000L, executor.estimateGas(new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], 250_000L), ctx()).get());
        // A cap below the gross draw cannot fit.
        assertEquals(new EvmExecutionError.GasAllowanceExceeded(200_000L), estimateError(executor,
                new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], 200_000L), ctx()));
    }

    @Test
    void outOfGasAtTheDefaultCeilingIsGasAllowanceExceeded() {
        // JUMPDEST; PUSH1 0; JUMP — forever.
        byte[] loop = HexFormat.of().parseHex("5b600056");
        var executor = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, loop));
        assertEquals(new EvmExecutionError.GasAllowanceExceeded(30_000_000L), estimateError(executor,
                new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null), ctx()));
    }

    @Test
    void feeCapBoundsTheCeilingByWhatTheSenderCanPay() throws Exception {
        // geth's affordability cap: (balance − value) / feeCap. 1_000_000 wei at
        // 10 wei/gas funds 100_000 gas; the ten SSTOREs need ~242k. (A block at
        // a 7 wei base fee, so the 10 wei cap is one a block would include.)
        byte[] code = sstores(10);
        var poor = new DefaultEvmExecutor(senderWithBalanceAnd(BigInteger.valueOf(1_000_000L), CONTRACT, code));
        var priced = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null,
                BigInteger.TEN, BigInteger.TEN);
        assertEquals(new EvmExecutionError.GasAllowanceExceeded(100_000L), estimateError(poor, priced, ctx(7)));

        var funded = new DefaultEvmExecutor(senderWithBalanceAnd(BigInteger.valueOf(100_000_000L), CONTRACT, code));
        assertTrue(funded.estimateGas(priced, ctx(7)).get() > 242_060L);

        // A value the sender cannot cover is refused outright — even before the
        // fee cap is weighed against the base fee (geth's order).
        var allIn = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.valueOf(100_000_000L), new byte[0], null,
                BigInteger.TEN, BigInteger.TEN);
        assertEquals(new EvmExecutionError.InsufficientFundsForTransfer(), estimateError(funded, allIn, ctx(7)));
        assertEquals(new EvmExecutionError.InsufficientFundsForTransfer(), estimateError(funded, allIn, ctx()));
        // Affordable, but under a 1 gwei base fee: refused at the funded ceiling.
        assertEquals(new EvmExecutionError.FailedWithGas(100_000L,
                        new EvmExecutionError.FeeCapTooLow(SENDER, BigInteger.TEN, 1_000_000_000L)),
                estimateError(poor, priced, ctx()));
    }

    @Test
    void gaspriceReadsTheRequestsEffectivePrice() throws Exception {
        // GASPRICE; PUSH1 0; SSTORE; STOP — a zero price writes nothing new, a
        // non-zero one stores a fresh slot (22100).
        byte[] code = HexFormat.of().parseHex("3a60005500");
        var executor = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, code));
        long free = executor.estimateGas(new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null), ctx()).get();
        long priced = executor.estimateGas(new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null,
                BigInteger.valueOf(2_000_000_000L), BigInteger.ONE), ctx()).get();
        assertTrue(priced > free + 15_000, "non-zero GASPRICE must store: " + free + " -> " + priced);
        // min(feeCap, baseFee + tip): the context's base fee is 1 gwei.
        assertEquals(BigInteger.valueOf(1_000_000_001L), new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null,
                BigInteger.valueOf(2_000_000_000L), BigInteger.ONE)
                .effectiveGasPrice(BigInteger.valueOf(1_000_000_000L)));
        assertEquals(BigInteger.ZERO, new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null).effectiveGasPrice(BigInteger.TEN));
    }

    @Test
    void estimateNeverExceedsTheOsakaTransactionCap() throws Exception {
        // EIP-7825: from Osaka no transaction may carry more than 2^24 gas. 680
        // fresh SSTOREs (~15.05M gross, ~17.3M buffered) fit under it, so the cap
        // IS the answer; 800 (~17.7M) cannot fit at all.
        long cap = 1L << 24;
        var fits = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, sstoresWide(680)));
        assertEquals(cap, fits.estimateGas(new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null), osakaCtx()).get());
        var tooBig = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, sstoresWide(800)));
        var tx = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);
        assertEquals(new EvmExecutionError.GasAllowanceExceeded(cap), estimateError(tooBig, tx, osakaCtx()));
        // Before Osaka the same work is simply estimated.
        assertTrue(tooBig.estimateGas(tx, pragueCtx()).get() > cap);
    }

    @Test
    void calldataFloorAppliesFromPrague() throws Exception {
        // 200 non-zero bytes to an EOA: the standard intrinsic is 21000 + 3200,
        // EIP-7623's floor 21000 + 10 × 800 = 29000 — which Prague charges.
        var executor = new DefaultEvmExecutor(fundedSenderAnd(EOA_RECIPIENT, null));
        byte[] calldata = new byte[200];
        java.util.Arrays.fill(calldata, (byte) 0x11);
        var tx = new UnsignedTransaction(SENDER, EOA_RECIPIENT, BigInteger.ZERO, calldata, null);
        assertEquals(29_000L, lowestLimitThatRuns(executor, tx, pragueCtx()));
        assertIsTheSearchedEstimate(executor, tx, pragueCtx(), executor.estimateGas(tx, pragueCtx()).get());
        // Before Prague the floor does not exist.
        assertEquals(24_200L, lowestLimitThatRuns(executor, tx, ctx()));
        assertIsTheSearchedEstimate(executor, tx, ctx(), executor.estimateGas(tx, ctx()).get());
    }

    @Test
    void contractCreationIsExplicitlyUnsupported() {
        var oracle = FixtureSnapStateOracle.builder().build();
        var executor = new DefaultEvmExecutor(oracle);

        var tx = new UnsignedTransaction(
                SENDER, /* to */ null, BigInteger.ZERO, new byte[]{1, 2, 3}, null);

        try {
            executor.estimateGas(tx, ctx()).get();
            fail("expected UnsupportedOperationException for to=null");
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException
                    ? e.getCause() : e;
            assertInstanceOf(UnsupportedOperationException.class, cause);
        }
    }

    @Test
    void calldataNonZeroBytesContributeToIntrinsic() throws Exception {
        // 4 bytes of calldata, all non-zero: +64 gas of intrinsic.
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L,
                        new BigInteger("1000000000000000000"),
                        emptyCodeHash()))
                .account(new AccountState(EOA_RECIPIENT, 0L, BigInteger.ZERO,
                        emptyCodeHash()))
                .build();
        var executor = new DefaultEvmExecutor(oracle);

        var tx = new UnsignedTransaction(
                SENDER, EOA_RECIPIENT, BigInteger.ZERO,
                new byte[]{1, 2, 3, 4},  // 4 non-zero bytes => +64 intrinsic
                null);

        long estimate = executor.estimateGas(tx, ctx()).get();
        // Base 21000 + 64 = 21064; * 1.15 ≈ 24224. Allow ±200 slop.
        assertTrue(estimate >= 24_000 && estimate <= 24_500,
                "EOA call with 4 non-zero calldata bytes should estimate ≈24224; got " + estimate);
    }

    // ---- geth's search (#509 stage 2) -------------------------------------

    @Test
    void theEstimateCoversTheGasNestedCallsWithhold() throws Exception {
        // 20 levels, each CALLing the next with all its gas and reverting if the
        // callee failed; the innermost stores 14 fresh slots. CALL withholds
        // 1/64 at every level (EIP-150), so the limit that works grows as
        // (64/63)^20 ≈ 1.37 over the innermost work — past the 1.15 one run's
        // draw was buffered with.
        int depth = 20;
        var builder = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L, new BigInteger("1000000000000000000"), emptyCodeHash()));
        for (int i = 0; i < depth; i++) {
            contract(builder, level(i), forwarder(level(i + 1)));
        }
        contract(builder, level(depth), sstores(14));
        var executor = new DefaultEvmExecutor(builder.build());
        var tx = new UnsignedTransaction(SENDER, level(0), BigInteger.ZERO, new byte[0], null);

        assertIsTheSearchedEstimate(executor, tx, ctx(), executor.estimateGas(tx, ctx()).get());
        assertFalse(runs(executor, tx, ctx(), oneRunEstimate(executor, tx, ctx())),
                "the one-run estimate should fail here");
    }

    @Test
    void theEstimateCoversARefundHeavyTransaction() throws Exception {
        // Ten SSTORE(slot i, 0) over slots holding 1, then STOP: clearing refunds
        // up to a fifth of the gas, at the end — so the charge sits far below
        // what the run needs, and the search must answer the need.
        byte[] code = new byte[10 * 5 + 1];
        for (int i = 0; i < 10; i++) {
            code[i * 5] = 0x60;
            code[i * 5 + 1] = 0x00;
            code[i * 5 + 2] = 0x60;
            code[i * 5 + 3] = (byte) i;
            code[i * 5 + 4] = 0x55;
        }
        var builder = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L, new BigInteger("1000000000000000000"), emptyCodeHash()));
        contract(builder, CONTRACT, code);
        for (int i = 0; i < 10; i++) {
            builder.storage(CONTRACT, BigInteger.valueOf(i), BigInteger.ONE);
        }
        var executor = new DefaultEvmExecutor(builder.build());
        var tx = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);

        // 21000 + 10 × (2100 cold + 2900 reset + 6) = 71060 needed, ~57k charged.
        assertEquals(71_060L, lowestLimitThatRuns(executor, tx, ctx()));
        assertIsTheSearchedEstimate(executor, tx, ctx(), executor.estimateGas(tx, ctx()).get());
    }

    @Test
    void theEstimateCoversAGasleftCheck() throws Exception {
        // GAS PUSH3 100000 LT ISZERO PUSH1 11 JUMPI STOP JUMPDEST PUSH1 0 DUP1
        // REVERT — revert unless gasleft() > 100000: little is drawn at the
        // budget, yet any limit that leaves it short reverts.
        byte[] code = HexFormat.of().parseHex("5a620186a01015600b57005b600080fd");
        var executor = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, code));
        var tx = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);

        long estimate = executor.estimateGas(tx, ctx()).get();
        assertTrue(estimate > 100_000, "the estimate must leave the contract its 100000: " + estimate);
        assertIsTheSearchedEstimate(executor, tx, ctx(), estimate);
        assertFalse(runs(executor, tx, ctx(), oneRunEstimate(executor, tx, ctx())),
                "the one-run estimate should revert here");
    }

    @Test
    void aFeeLessEstimateMovingMoreThanTheSenderHoldsIsGethsAnswer() throws Exception {
        // Without a fee geth still holds the sender to the value it moves.
        var executor = new DefaultEvmExecutor(senderWithBalanceAnd(BigInteger.valueOf(5L), CONTRACT, new byte[]{0x00}));
        var error = estimateError(executor,
                new UnsignedTransaction(SENDER, CONTRACT, BigInteger.valueOf(6L), new byte[0], null), ctx());
        assertEquals(new EvmExecutionError.FailedWithGas(30_000_000L, new EvmExecutionError.InsufficientFunds(
                SENDER, BigInteger.valueOf(5L), BigInteger.valueOf(6L))), error);
        assertEquals("failed with 30000000 gas: insufficient funds for gas * price + value: address "
                        + "0x1111111111111111111111111111111111111111 have 5 want 6",
                ((EvmExecutionError.FailedWithGas) error).message());
        // All of it is fine.
        assertTrue(executor.estimateGas(new UnsignedTransaction(SENDER, CONTRACT, BigInteger.valueOf(5L),
                new byte[0], null), ctx()).get() >= 21_000L);
    }

    @Test
    void theBlockGasLimitBoundsTheEstimate() throws Exception {
        // No block holds a transaction above its gas limit: geth's search starts
        // there, and so does the ceiling.
        var executor = new DefaultEvmExecutor(fundedSenderAnd(CONTRACT, sstores(10)));
        var tx = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);
        assertTrue(executor.estimateGas(tx, ctx()).get() > 200_000);
        var small = new BlockContext(new byte[32], 19_500_000L, EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(1_000_000_000L), Address.ZERO, new byte[32], BigInteger.ONE, 200_000L);
        assertEquals(new EvmExecutionError.GasAllowanceExceeded(200_000L), estimateError(executor, tx, small));
        // Only a default, as in geth: the caller's own gas replaces it.
        assertEquals(250_000L, executor.estimateGas(new UnsignedTransaction(
                SENDER, CONTRACT, BigInteger.ZERO, new byte[0], 250_000L), small).get());
    }

    @Test
    void theEstimateCoversASwallowedCallOneLevelDeep() throws Exception {
        // Ten SSTORE(slot i, 0) over slots holding 1 (refunds), then CALL an inner
        // contract with all gas and return the success flag, whatever it is. What
        // the run is CHARGED — where geth's search starts — is a limit at which it
        // still "runs" without its inner call; the estimate never goes below the
        // draw, so the call the caller simulated happens. One level deep: the
        // buffer covers a caught failure through 8 levels (lowestWorkingLimit).
        Address inner = Address.fromHex("0x7777777777777777777777777777777777777777");
        StringBuilder outer = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            outer.append(String.format("600060%02x55", i));
        }
        outer.append("60006000600060006000").append("73").append(inner.toHex().substring(2))
                .append("5af1").append("600052").append("60206000f3");
        byte[] code = HexFormat.of().parseHex(outer.toString());
        var builder = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L, new BigInteger("1000000000000000000"), emptyCodeHash()));
        contract(builder, CONTRACT, code);
        contract(builder, inner, sstores(5));
        for (int i = 0; i < 10; i++) {
            builder.storage(CONTRACT, BigInteger.valueOf(i), BigInteger.ONE);
        }
        var executor = new DefaultEvmExecutor(builder.build());
        var tx = new UnsignedTransaction(SENDER, CONTRACT, BigInteger.ZERO, new byte[0], null);

        long drawn = executor.drawnAt(tx, ctx(), 30_000_000L);
        // At four fifths of the draw — about what the run is charged after its
        // refund — the transaction still runs, without its inner call.
        assertEquals(BigInteger.ZERO, new BigInteger(1, callWithGas(executor, tx, ctx(), drawn * 4 / 5)));

        long estimate = executor.estimateGas(tx, ctx()).get();
        assertTrue(estimate >= (long) Math.ceil(drawn * 1.15), "estimate " + estimate + " below the draw " + drawn);
        assertEquals(BigInteger.ONE, new BigInteger(1, callWithGas(executor, tx, ctx(), estimate)),
                "at the estimate the inner call must succeed");
    }

    @Test
    void theCeilingRuleIsSharedByTheEstimateAndThePlainTransferShortCircuit() {
        // DefaultEvmExecutor.estimateCeiling is what the JSON-RPC backend's 21000
        // short-circuit answers with, so its refusals are pinned here once.
        java.util.function.Supplier<BigInteger> five = () -> BigInteger.valueOf(5L);
        java.util.function.Supplier<BigInteger> unasked = () -> fail("the balance was not needed");
        var transfer = new UnsignedTransaction(SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[0], null);
        // No fee, no value: the budget, bounded by the block's gas limit.
        assertEquals(30_000_000L, DefaultEvmExecutor.estimateCeiling(transfer, ctx(), unasked));
        // The caller's gas replaces the block's limit, from 21000.
        assertEquals(40_000L, DefaultEvmExecutor.estimateCeiling(
                new UnsignedTransaction(SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[0], 40_000L), ctx(), unasked));
        // Fee-less, the sender must cover the value it moves.
        var tooMuch = new UnsignedTransaction(SENDER, EOA_RECIPIENT, BigInteger.valueOf(6L), new byte[0], null);
        var refused = assertThrows(EvmExecutionException.class,
                () -> DefaultEvmExecutor.estimateCeiling(tooMuch, ctx(), five));
        assertEquals(new EvmExecutionError.FailedWithGas(30_000_000L, new EvmExecutionError.InsufficientFunds(
                SENDER, BigInteger.valueOf(5L), BigInteger.valueOf(6L))), refused.error());
        // Under a fee cap: what the sender can pay for is the ceiling ...
        var priced = new UnsignedTransaction(SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[0], null,
                BigInteger.TEN, BigInteger.ONE);
        assertEquals(100_000L, DefaultEvmExecutor.estimateCeiling(priced, ctx(7), () -> BigInteger.valueOf(1_000_000L)));
        // ... and a fee cap below the base fee is refused at that ceiling.
        refused = assertThrows(EvmExecutionException.class,
                () -> DefaultEvmExecutor.estimateCeiling(priced, ctx(), () -> BigInteger.valueOf(1_000_000L)));
        assertEquals(new EvmExecutionError.FailedWithGas(100_000L,
                new EvmExecutionError.FeeCapTooLow(SENDER, BigInteger.TEN, 1_000_000_000L)), refused.error());
    }

    // ---- Helpers ----------------------------------------------------------

    /** The lowest gas limit at which {@code tx} runs, found exactly by bisecting
     *  over call outcomes (the transactions in these tests are monotone in it). */
    private static long lowestLimitThatRuns(DefaultEvmExecutor executor, UnsignedTransaction tx, BlockContext ctx) {
        long fails = 0;
        long works = 30_000_000L;
        assertTrue(runs(executor, tx, ctx, works), "the transaction must run at the budget");
        while (fails + 1 < works) {
            long mid = (fails + works) / 2;
            if (runs(executor, tx, ctx, mid)) {
                works = mid;
            } else {
                fails = mid;
            }
        }
        return works;
    }

    /** {@code estimate} is the search's answer for {@code tx}: the lowest limit
     *  that runs, within geth's 1.5%, plus the 1.15 buffer — and itself a limit
     *  that runs. */
    private static void assertIsTheSearchedEstimate(DefaultEvmExecutor executor, UnsignedTransaction tx,
                                                    BlockContext ctx, long estimate) {
        long lowest = lowestLimitThatRuns(executor, tx, ctx);
        long lower = (long) Math.ceil(lowest * 1.15);
        long upper = (long) Math.ceil((lowest * 10_153L / 10_000L + 1) * 1.15);
        assertTrue(estimate >= lower && estimate <= upper, "estimate " + estimate
                + " is not the searched answer over the lowest limit " + lowest + " (" + lower + ".." + upper + ")");
        assertTrue(runs(executor, tx, ctx, estimate), "the estimate must be a limit that runs");
    }

    /** Whether {@code tx} runs as a call with {@code gas} as its limit. Only an
     *  answer from the executor counts as "does not run"; anything else fails. */
    private static boolean runs(DefaultEvmExecutor executor, UnsignedTransaction tx, BlockContext ctx, long gas) {
        return callWithGas(executor, tx, ctx, gas) != null;
    }

    /** {@code tx}'s return data as a call with {@code gas} as its limit, or null
     *  when the executor answers that it does not run at it. */
    private static byte[] callWithGas(DefaultEvmExecutor executor, UnsignedTransaction tx, BlockContext ctx,
                                      long gas) {
        try {
            return executor.callTx(new UnsignedTransaction(tx.from(), tx.to(), tx.value(), tx.data(), gas,
                    tx.gasFeeCap(), tx.gasTipCap()), ctx).get();
        } catch (java.util.concurrent.ExecutionException e) {
            if (e.getCause() instanceof EvmExecutionException) return null;
            throw new AssertionError("not an answer at gas " + gas, e.getCause());
        } catch (InterruptedException e) {
            throw new AssertionError(e);
        }
    }

    /** The one-run estimate this search replaced: what a run at the budget
     *  drew, buffered by 1.15. */
    private static long oneRunEstimate(DefaultEvmExecutor executor, UnsignedTransaction tx, BlockContext ctx) {
        return (long) Math.ceil(executor.drawnAt(tx, ctx, 30_000_000L) * 1.15);
    }

    private static Address level(int i) {
        return Address.fromHex(String.format("0x60606060606060606060606060606060606060%02x", i));
    }

    /** CALL {@code next} with all remaining gas, and revert if it failed:
     *  PUSH1 0 ×5 (retSize, retOffset, argsSize, argsOffset, value), PUSH20 next,
     *  GAS CALL ISZERO PUSH1 38 JUMPI STOP JUMPDEST PUSH1 0 DUP1 REVERT. */
    private static byte[] forwarder(Address next) {
        return HexFormat.of().parseHex("60006000600060006000" + "73" + next.toHex().substring(2)
                + "5af11560265700" + "5b600080fd");
    }

    private static void contract(FixtureSnapStateOracle.Builder builder, Address address, byte[] code) {
        builder.account(new AccountState(address, 1L, BigInteger.ZERO, FixtureSnapStateOracle.codeHashOf(code)))
                .bytecode(code);
    }

    /** The error an estimate fails with (unwrapping the future). */
    private static EvmExecutionError estimateError(DefaultEvmExecutor executor, UnsignedTransaction tx,
                                                   BlockContext ctx) {
        try {
            long gas = executor.estimateGas(tx, ctx).get();
            return fail("expected the estimate to fail; got " + gas);
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException ? e.getCause() : e;
            return assertInstanceOf(EvmExecutionException.class, cause).error();
        }
    }

    /** SENDER with 1 ETH, plus {@code address} holding {@code code} (an EOA when null). */
    private static FixtureSnapStateOracle fundedSenderAnd(Address address, byte[] code) {
        return senderWithBalanceAnd(new BigInteger("1000000000000000000"), address, code);
    }

    private static FixtureSnapStateOracle senderWithBalanceAnd(BigInteger balance, Address address, byte[] code) {
        var builder = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L, balance, emptyCodeHash()));
        if (code == null) {
            builder.account(new AccountState(address, 0L, BigInteger.ZERO, emptyCodeHash()));
        } else {
            builder.account(new AccountState(address, 1L, BigInteger.ZERO,
                    FixtureSnapStateOracle.codeHashOf(code))).bytecode(code);
        }
        return builder.build();
    }

    /** {@code n} fresh-slot SSTOREs (slot i := 1), then STOP — 22106 gas each. */
    private static byte[] sstores(int n) {
        byte[] code = new byte[n * 5 + 1];
        for (int i = 0; i < n; i++) {
            code[i * 5] = 0x60;
            code[i * 5 + 1] = 0x01;
            code[i * 5 + 2] = 0x60;
            code[i * 5 + 3] = (byte) i;
            code[i * 5 + 4] = 0x55;
        }
        code[n * 5] = 0x00;
        return code;
    }

    /** {@code n} fresh-slot SSTOREs with 2-byte slot numbers (slot i := 1), then STOP. */
    private static byte[] sstoresWide(int n) {
        byte[] code = new byte[n * 6 + 1];
        for (int i = 0; i < n; i++) {
            code[i * 6] = 0x60;
            code[i * 6 + 1] = 0x01;
            code[i * 6 + 2] = 0x61;
            code[i * 6 + 3] = (byte) (i >> 8);
            code[i * 6 + 4] = (byte) i;
            code[i * 6 + 5] = 0x55;
        }
        code[n * 6] = 0x00;
        return code;
    }

    private static BlockContext osakaCtx() {
        return new BlockContext(
                new byte[32],
                23_900_000L,
                EvmFactory.OSAKA_TIME + 1,
                BigInteger.valueOf(1_000_000_000L),
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                60_000_000L);
    }

    private static BlockContext pragueCtx() {
        return new BlockContext(
                new byte[32],
                22_500_000L,
                EvmFactory.PRAGUE_TIME + 1,
                BigInteger.valueOf(1_000_000_000L),
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
    }

    private static byte[] emptyCodeHash() {
        // keccak256("") — the codeHash for an EOA / no-code account.
        return HexFormat.of().parseHex(
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    private static BlockContext ctx() {
        return ctx(1_000_000_000L);
    }

    /** A Cancun block at {@code baseFee} wei. */
    private static BlockContext ctx(long baseFee) {
        return new BlockContext(
                new byte[32],
                19_500_000L,
                EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(baseFee),
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
    }
}
