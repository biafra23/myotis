package io.myotis.rpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
import org.junit.jupiter.api.Test;

/**
 * Pins the Java engine's production revert path: {@code rpcCallDetailed} maps a
 * throwable chain carrying {@link EvmExecutionError.Reverted} to a REVERTED
 * result via this cause-walk — the payload must survive, and non-revert errors
 * must NOT read as reverts (they stay retryable UNAVAILABLE).
 */
class RevertDataOfTest {

    @Test
    void findsTheRevertPayloadThroughWrappedCauses() {
        byte[] payload = {0x08, (byte) 0xc3, 0x79, (byte) 0xa0, 0x01};
        // The shape the dedup path produces: ExecutionException(RuntimeException(EvmExecutionException)).
        Exception chain = new java.util.concurrent.ExecutionException(
                new RuntimeException(
                        new EvmExecutionException(new EvmExecutionError.Reverted(payload))));
        assertArrayEquals(payload, VerifiedRpcBackend.revertDataOf(chain));
    }

    @Test
    void directRevertAndEmptyPayload() {
        assertArrayEquals(new byte[0], VerifiedRpcBackend.revertDataOf(
                new EvmExecutionException(new EvmExecutionError.Reverted(new byte[0]))));
    }

    @Test
    void nonRevertErrorsAreNotReverts() {
        assertNull(VerifiedRpcBackend.revertDataOf(new RuntimeException("timeout")));
        assertNull(VerifiedRpcBackend.revertDataOf(
                new EvmExecutionException(new EvmExecutionError.OutOfGas())));
        // An exceptional halt carries a LOCAL diagnostic, not chain-produced
        // revert data — it must never surface as a code-3 revert.
        assertNull(VerifiedRpcBackend.revertDataOf(
                new EvmExecutionException(
                        new EvmExecutionError.Halted("halt=INVALID_OPERATION state=EXCEPTIONAL_HALT"))));
        assertNull(VerifiedRpcBackend.revertDataOf(new java.util.concurrent.ExecutionException(
                new EvmExecutionException(
                        new EvmExecutionError.StateUnavailable(new byte[32], null, null)))));
    }

    /** #509: an estimate that does not fit the caller's gas or funds is an ANSWER in
     *  geth's words (INFEASIBLE → -32000 with the message), found through the same
     *  wrapped causes — and nothing else reads as one. */
    @Test
    void infeasibleEstimatesCarryGethsMessage() {
        assertEquals("gas required exceeds allowance (50000)", VerifiedRpcBackend.infeasibleOf(
                new java.util.concurrent.ExecutionException(new RuntimeException(new EvmExecutionException(
                        new EvmExecutionError.GasAllowanceExceeded(50_000L))))));
        assertEquals("insufficient funds for transfer", VerifiedRpcBackend.infeasibleOf(
                new EvmExecutionException(new EvmExecutionError.InsufficientFundsForTransfer())));
        assertNull(VerifiedRpcBackend.infeasibleOf(
                new EvmExecutionException(new EvmExecutionError.Reverted(new byte[0]))));
        assertNull(VerifiedRpcBackend.infeasibleOf(new RuntimeException("timeout")));
        // Running out of gas is an answer only when the caller set the limit.
        assertNull(VerifiedRpcBackend.infeasibleOf(new EvmExecutionException(new EvmExecutionError.OutOfGas())));
    }

    /** #509 stage 2: a transaction-object eth_call's refusals are answers too, and
     *  the estimate names the ceiling its refused run was made at — geth's words. */
    @Test
    void infeasibleCallsCarryGethsMessage() {
        var sender = io.myotis.evm.Address.fromHex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assertEquals("out of gas", VerifiedRpcBackend.infeasibleOf(new java.util.concurrent.ExecutionException(
                new EvmExecutionException(new EvmExecutionError.CallOutOfGas()))));
        assertEquals("intrinsic gas too low: have 20000, want 21000", VerifiedRpcBackend.infeasibleOf(
                new EvmExecutionException(new EvmExecutionError.IntrinsicGasTooLow(20_000L, 21_000L))));
        assertEquals("insufficient funds for gas * price + value: address "
                        + "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed have 1 want 2",
                VerifiedRpcBackend.infeasibleOf(new EvmExecutionException(new EvmExecutionError.InsufficientFunds(
                        sender, java.math.BigInteger.ONE, java.math.BigInteger.TWO))));
        var feeCapTooLow = new EvmExecutionError.FeeCapTooLow(sender, java.math.BigInteger.valueOf(5), 7L);
        assertEquals("max fee per gas less than block base fee: address "
                        + "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed, maxFeePerGas: 5, baseFee: 7",
                VerifiedRpcBackend.infeasibleOf(new EvmExecutionException(feeCapTooLow)));
        assertEquals("failed with 30000000 gas: max fee per gas less than block base fee: address "
                        + "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed, maxFeePerGas: 5, baseFee: 7",
                VerifiedRpcBackend.infeasibleOf(new EvmExecutionException(
                        new EvmExecutionError.FailedWithGas(30_000_000L, feeCapTooLow))));
    }
}
