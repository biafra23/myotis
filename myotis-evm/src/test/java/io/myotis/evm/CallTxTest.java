package io.myotis.evm;

import io.myotis.evm.besu.EvmFactory;
import io.myotis.evm.world.AccountState;
import io.myotis.evm.world.FixtureSnapStateOracle;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@link EvmExecutor#callTx}: {@code eth_call} for a transaction object (#509),
 * the Java twin of the Rust executor's {@code call_tx} tests — the caller's gas
 * bounds the call, a fee is checked, charged and read by GASPRICE, and each
 * refusal is geth's answer, word for word.
 */
class CallTxTest {

    private static final Address SENDER = Address.fromHex(
            "0x1111111111111111111111111111111111111111");
    private static final Address TARGET = Address.fromHex(
            "0x3333333333333333333333333333333333333333");
    private static final BigInteger ONE_ETH = new BigInteger("1000000000000000000");
    private static final long BUDGET = 30_000_000L;

    @Test
    void withoutGasOrFeesItIsThePlainCall() throws Exception {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, returning(0x60, 0x07)));
        byte[] plain = executor.callView(SENDER, TARGET, new byte[0], BigInteger.ZERO, ctx(7)).get();
        assertArrayEquals(plain, executor.callTx(tx(null), ctx(7)).get());
        assertEquals(BigInteger.valueOf(7), word(plain));
    }

    @Test
    void runningOutOfTheCallersGasIsGethsOutOfGas() throws Exception {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, sstores(10)));
        executor.callTx(tx(null), ctx(7)).get();

        var error = callError(executor, tx(100_000L), ctx(7));
        assertEquals(new EvmExecutionError.CallOutOfGas(), error);
        assertEquals("out of gas", ((EvmExecutionError.CallOutOfGas) error).message());
    }

    @Test
    void theCallersGasIsCappedAtTheBudget() throws Exception {
        // GAS, returned: what the frame was handed, less the opcode's own 2.
        var gasLeft = new DefaultEvmExecutor(senderAnd(ONE_ETH, returning(0x5a)));
        BigInteger left = word(gasLeft.callTx(tx(50_000_000L), ctx(7)).get());
        assertTrue(left.compareTo(BigInteger.valueOf(BUDGET - 21_000)) < 0, "ran with at most the budget: " + left);

        // JUMPDEST; PUSH1 0; JUMP — spins until the gas is gone. Dry at the
        // caller's limit is the answer; dry at the budget the caller's larger
        // limit was capped to is refused; without a limit it stays OutOfGas.
        var spin = new DefaultEvmExecutor(senderAnd(ONE_ETH, HexFormat.of().parseHex("5b600056")));
        var capped = callError(spin, tx(50_000_000L), ctx(7));
        assertEquals(new EvmExecutionError.CallBudgetExceeded(BUDGET, 50_000_000L), capped);
        assertEquals("the call ran out of this node's 30000000-gas call budget, below the 50000000 gas it allows",
                ((EvmExecutionError.CallBudgetExceeded) capped).detail());
        assertEquals(new EvmExecutionError.CallOutOfGas(), callError(spin, tx(BUDGET), ctx(7)));
        assertEquals(new EvmExecutionError.CallOutOfGas(), callError(spin, tx(1_000_000L), ctx(7)));
        assertEquals(new EvmExecutionError.OutOfGas(),
                callError(spin, priced(BigInteger.ZERO, null, BigInteger.TEN, BigInteger.ONE), ctx(7)));
    }

    @Test
    void aLimitBelowTheIntrinsicCostOrTheFloorIsRefused() throws Exception {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, new byte[]{0x00}));
        var error = callError(executor, tx(20_000L), ctx(7));
        assertEquals(failed(20_000L, new EvmExecutionError.IntrinsicGasTooLow(20_000L, 21_000L)), error);
        assertEquals("err: intrinsic gas too low: have 20000, want 21000 (supplied gas 20000)", message(error));
        // geth takes a call's gas literally: 0 is a limit, not "unset".
        assertEquals(failed(0L, new EvmExecutionError.IntrinsicGasTooLow(0L, 21_000L)),
                callError(executor, tx(0L), ctx(7)));

        // Prague: 1000 non-zero bytes cost 37000 intrinsic, but floor at 61000.
        byte[] calldata = new byte[1000];
        java.util.Arrays.fill(calldata, (byte) 0xff);
        var floored = new UnsignedTransaction(SENDER, TARGET, BigInteger.ZERO, calldata, 50_000L);
        error = callError(executor, floored, pragueCtx());
        assertEquals(failed(50_000L, new EvmExecutionError.FloorDataGasTooLow(50_000L, 61_000L)), error);
        assertEquals("err: insufficient gas for floor data gas cost: have 50000, want 61000 (supplied gas 50000)",
                message(error));
        // Before Prague the floor does not exist: the same limit runs.
        assertArrayEquals(new byte[0], executor.callTx(floored, ctx(7)).get());
    }

    @Test
    void aFeeIsChargedToTheSenderBeforeTheCallRuns() throws Exception {
        // BALANCE(CALLER), returned.
        var executor = new DefaultEvmExecutor(senderAnd(BigInteger.valueOf(10_000_000L), returning(0x33, 0x31)));
        assertEquals(BigInteger.valueOf(10_000_000L), word(executor.callTx(tx(null), ctx(7)).get()));

        // Effective price min(10, 7 + 1) = 8 on a 100k limit.
        var priced = priced(BigInteger.ZERO, 100_000L, BigInteger.TEN, BigInteger.ONE);
        assertEquals(BigInteger.valueOf(10_000_000L - 800_000L), word(executor.callTx(priced, ctx(7)).get()));

        // 100k × 10 + 9.1M = 10.1M > 10M.
        var error = callError(executor,
                priced(BigInteger.valueOf(9_100_000L), 100_000L, BigInteger.TEN, BigInteger.ONE), ctx(7));
        assertEquals(failed(100_000L, new EvmExecutionError.InsufficientFunds(SENDER,
                BigInteger.valueOf(10_000_000L), BigInteger.valueOf(10_100_000L))), error);
        assertEquals("err: insufficient funds for gas * price + value: address "
                        + "0x1111111111111111111111111111111111111111 have 10000000 want 10100000 "
                        + "(supplied gas 100000)", message(error));
    }

    @Test
    void aValueTheSenderCannotCoverIsRefusedEvenWithoutAFee() throws Exception {
        // geth's buyGas holds for a fee-less call too; a call that moves nothing
        // needs no balance at all.
        var executor = new DefaultEvmExecutor(senderAnd(BigInteger.valueOf(1_000L), new byte[]{0x00}));
        var tooMuch = new UnsignedTransaction(SENDER, TARGET, BigInteger.valueOf(1_001L), new byte[0], 100_000L);
        assertEquals(failed(100_000L, new EvmExecutionError.InsufficientFunds(SENDER,
                BigInteger.valueOf(1_000L), BigInteger.valueOf(1_001L))), callError(executor, tooMuch, ctx(7)));
        var all = new UnsignedTransaction(SENDER, TARGET, BigInteger.valueOf(1_000L), new byte[0], 100_000L);
        assertArrayEquals(new byte[0], executor.callTx(all, ctx(7)).get());
        var broke = new UnsignedTransaction(Address.fromHex("0x7777777777777777777777777777777777777777"),
                TARGET, BigInteger.ZERO, new byte[0], 100_000L);
        assertArrayEquals(new byte[0], executor.callTx(broke, ctx(7)).get());
    }

    @Test
    void aRequiredBalancePast256BitsIsGethsRefusal() {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, new byte[]{0x00}));
        var max = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        var error = callError(executor, priced(max, 21_000L, BigInteger.valueOf(7), BigInteger.valueOf(7)), ctx(7));
        assertEquals(failed(21_000L, new EvmExecutionError.RequiredBalanceOverflow(SENDER)), error);
        assertEquals("err: insufficient funds for gas * price + value: address "
                + "0x1111111111111111111111111111111111111111 required balance exceeds 256 bits "
                + "(supplied gas 21000)", message(error));
    }

    @Test
    void gaspriceReadsTheRequestsEffectivePrice() throws Exception {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, returning(0x3a)));
        assertEquals(BigInteger.ZERO, word(executor.callTx(tx(null), ctx(7)).get()));
        assertEquals(BigInteger.valueOf(8), word(executor.callTx(
                priced(BigInteger.ZERO, null, BigInteger.TEN, BigInteger.ONE), ctx(7)).get()));
    }

    @Test
    void aFeeCapBelowTheBaseFeeIsRefusedForCallsAndEstimates() {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, new byte[]{0x00}));
        // A legacy gas price is its own cap; a dynamic fee's cap is maxFeePerGas.
        for (var tx : new UnsignedTransaction[]{
                priced(BigInteger.ZERO, null, BigInteger.valueOf(5), BigInteger.valueOf(5)),
                priced(BigInteger.ZERO, null, BigInteger.valueOf(6), BigInteger.ONE)}) {
            var want = new EvmExecutionError.FeeCapTooLow(SENDER, tx.gasFeeCap(), 7L);
            var call = callError(executor, tx, ctx(7));
            assertEquals(failed(BUDGET, want), call);
            assertEquals("err: " + want.message() + " (supplied gas 30000000)", message(call));
            assertEquals("max fee per gas less than block base fee: address "
                    + "0x1111111111111111111111111111111111111111, maxFeePerGas: " + tx.gasFeeCap()
                    + ", baseFee: 7", want.message());
            // The estimate reports it as geth's estimator does: with the ceiling
            // the refused run was made at.
            var estimate = estimateError(executor, tx, ctx(7));
            assertEquals(new EvmExecutionError.FailedWithGas(BUDGET, want), estimate);
            assertEquals("failed with 30000000 gas: " + want.message(),
                    ((EvmExecutionError.FailedWithGas) estimate).message());
        }
    }

    @Test
    void theConvergingExecutorAppliesTheSamePlan() throws Exception {
        // The prefetch loop's discovery passes must not decide the answer: the
        // caller's limit, the fee debit and the refusals are the plan's.
        var executor = new PrefetchingEvmExecutor(new DefaultEvmExecutor(
                senderAnd(BigInteger.valueOf(10_000_000L), returning(0x33, 0x31))));
        assertEquals(BigInteger.valueOf(10_000_000L - 800_000L), word(executor.callTx(
                priced(BigInteger.ZERO, 100_000L, BigInteger.TEN, BigInteger.ONE), ctx(7)).get()));
        assertEquals(failed(20_000L, new EvmExecutionError.IntrinsicGasTooLow(20_000L, 21_000L)),
                callError(executor, tx(20_000L), ctx(7)));

        var spin = new PrefetchingEvmExecutor(new DefaultEvmExecutor(
                senderAnd(ONE_ETH, HexFormat.of().parseHex("5b600056"))));
        assertEquals(new EvmExecutionError.CallOutOfGas(), callError(spin, tx(1_000_000L), ctx(7)));
    }

    @Test
    void theConvergingExecutorRunsCallsThatMoveValue() throws Exception {
        // CALLVALUE, returned. The discovery pass must see the sender's real
        // balance: a placeholder cannot cover the transfer, and Besu fails it
        // outright rather than reverting — for a plain call as for a priced one.
        var executor = new PrefetchingEvmExecutor(new DefaultEvmExecutor(senderAnd(ONE_ETH, returning(0x34))));
        assertEquals(BigInteger.ONE, word(executor.callView(SENDER, TARGET, new byte[0], BigInteger.ONE, ctx(7)).get()));
        assertEquals(BigInteger.ONE, word(executor.callTx(
                priced(BigInteger.ONE, 100_000L, BigInteger.TEN, BigInteger.ONE), ctx(7)).get()));
        assertEquals(BigInteger.ONE, word(executor.callTx(
                new UnsignedTransaction(SENDER, TARGET, BigInteger.ONE, new byte[0], 100_000L), ctx(7)).get()));
    }

    @Test
    void contractCreationIsNotServed() {
        var executor = new DefaultEvmExecutor(senderAnd(ONE_ETH, new byte[]{0x00}));
        var create = new UnsignedTransaction(SENDER, null, BigInteger.ZERO, new byte[]{0x00}, 100_000L);
        for (EvmExecutor e : new EvmExecutor[]{executor, new PrefetchingEvmExecutor(executor)}) {
            var failure = assertThrowsExecution(() -> e.callTx(create, ctx(7)).get());
            assertInstanceOf(UnsupportedOperationException.class, failure);
        }
    }

    @Test
    void addressesInMessagesAreEip55Checksummed() {
        // EIP-55's own test vectors, as geth prints an address in these errors.
        for (String expected : new String[]{
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"}) {
            assertEquals(expected, EvmExecutionError.checksummed(
                    Address.fromHex(expected.toLowerCase(java.util.Locale.ROOT))));
        }
    }

    // ---- Helpers ----------------------------------------------------------

    /** {@code op} followed by "return the top of the stack as one word". */
    private static byte[] returning(int... op) {
        byte[] tail = HexFormat.of().parseHex("60005260206000f3");
        byte[] code = new byte[op.length + tail.length];
        for (int i = 0; i < op.length; i++) code[i] = (byte) op[i];
        System.arraycopy(tail, 0, code, op.length, tail.length);
        return code;
    }

    private static BigInteger word(byte[] out) {
        return new BigInteger(1, out);
    }

    /** A fee-less call from SENDER to TARGET with {@code gas} as its limit. */
    private static UnsignedTransaction tx(Long gas) {
        return new UnsignedTransaction(SENDER, TARGET, BigInteger.ZERO, new byte[0], gas);
    }

    private static UnsignedTransaction priced(BigInteger value, Long gas, BigInteger feeCap, BigInteger tip) {
        return new UnsignedTransaction(SENDER, TARGET, value, new byte[0], gas, feeCap, tip);
    }

    /** {@code error} as geth's eth_call reports a check failed before the run. */
    private static EvmExecutionError failed(long suppliedGas, EvmExecutionError.Infeasible error) {
        return new EvmExecutionError.CallFailed(suppliedGas, error);
    }

    private static String message(EvmExecutionError error) {
        return assertInstanceOf(EvmExecutionError.Infeasible.class, error).message();
    }

    private static EvmExecutionError callError(EvmExecutor executor, UnsignedTransaction tx, BlockContext ctx) {
        var failure = assertThrowsExecution(() -> executor.callTx(tx, ctx).get());
        return assertInstanceOf(EvmExecutionException.class, failure).error();
    }

    private static EvmExecutionError estimateError(EvmExecutor executor, UnsignedTransaction tx, BlockContext ctx) {
        var failure = assertThrowsExecution(() -> executor.estimateGas(tx, ctx).get());
        return assertInstanceOf(EvmExecutionException.class, failure).error();
    }

    private interface Blocking {
        Object get() throws Exception;
    }

    /** The cause a blocking call fails with (unwrapping the future's wrapper). */
    private static Throwable assertThrowsExecution(Blocking call) {
        try {
            return fail("expected a failure; got " + call.get());
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (Exception e) {
            return e;
        }
    }

    /** SENDER holding {@code balance}, and TARGET holding {@code code}. */
    private static FixtureSnapStateOracle senderAnd(BigInteger balance, byte[] code) {
        return FixtureSnapStateOracle.builder()
                .account(new AccountState(SENDER, 0L, balance, emptyCodeHash()))
                .account(new AccountState(TARGET, 1L, BigInteger.ZERO, FixtureSnapStateOracle.codeHashOf(code)))
                .bytecode(code)
                .build();
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

    private static byte[] emptyCodeHash() {
        return HexFormat.of().parseHex(
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    /** A Cancun block at {@code baseFee} wei. */
    private static BlockContext ctx(long baseFee) {
        return new BlockContext(new byte[32], 19_500_000L, EvmFactory.CANCUN_TIME + 1,
                BigInteger.valueOf(baseFee), Address.ZERO, new byte[32], BigInteger.ONE, 30_000_000L);
    }

    private static BlockContext pragueCtx() {
        return new BlockContext(new byte[32], 22_500_000L, EvmFactory.PRAGUE_TIME + 1,
                BigInteger.valueOf(7), Address.ZERO, new byte[32], BigInteger.ONE, 30_000_000L);
    }
}
