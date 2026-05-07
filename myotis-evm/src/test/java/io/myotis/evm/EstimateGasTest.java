package io.myotis.evm;

import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit tests for {@link DefaultEvmExecutor#estimateGas}.
 *
 * <p>Each test sets up a fixture oracle with the contracts and balances
 * the transaction needs, asks the executor for an estimate, and verifies
 * the returned number sits in the expected range. Exact match isn't
 * useful — Besu's gas accounting is the source of truth, and the 15%
 * buffer means any specific number is approximate by design — so the
 * assertions are bounded ranges with rationale in comments.
 */
class EstimateGasTest {

    private static final Address SENDER = Address.fromHex(
            "0x1111111111111111111111111111111111111111");
    private static final Address EOA_RECIPIENT = Address.fromHex(
            "0x2222222222222222222222222222222222222222");
    private static final Address CONTRACT = Address.fromHex(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

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

        long estimate = executor.estimateGas(tx, ctx()).get();
        // Intrinsic 21000 * 1.15 = 24150. Allow a 100-gas slop window.
        assertTrue(estimate >= 24_000 && estimate <= 24_300,
                "ETH transfer to EOA should estimate ≈24150 gas; got " + estimate);
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
    void gasLimitTooLowForIntrinsicThrowsOutOfGas() {
        // Caller passed a gasLimit that's lower than the intrinsic 21000.
        var oracle = FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L,
                        new BigInteger("1000000000000000000"),
                        emptyCodeHash()))
                .account(new AccountState(EOA_RECIPIENT, 0L, BigInteger.ZERO,
                        emptyCodeHash()))
                .build();
        var executor = new DefaultEvmExecutor(oracle);

        var tx = new UnsignedTransaction(
                SENDER, EOA_RECIPIENT, BigInteger.ZERO, new byte[0],
                /* gasLimit */ 20_000L);

        try {
            executor.estimateGas(tx, ctx()).get();
            fail("expected OutOfGas — caller's gasLimit < intrinsic 21000");
        } catch (Exception e) {
            Throwable cause = e instanceof java.util.concurrent.ExecutionException
                    ? e.getCause() : e;
            var eee = assertInstanceOf(EvmExecutionException.class, cause);
            assertInstanceOf(EvmExecutionError.OutOfGas.class, eee.error());
        }
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

    // ---- Helpers ----------------------------------------------------------

    private static byte[] emptyCodeHash() {
        // keccak256("") — the codeHash for an EOA / no-code account.
        return HexFormat.of().parseHex(
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    private static BlockContext ctx() {
        return new BlockContext(
                new byte[32],
                19_500_000L,
                EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(1_000_000_000L),
                Address.ZERO,
                new byte[32],
                BigInteger.ONE,
                30_000_000L);
    }
}
