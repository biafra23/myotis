package io.myotis.rpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
        assertNull(VerifiedRpcBackend.revertDataOf(new java.util.concurrent.ExecutionException(
                new EvmExecutionException(
                        new EvmExecutionError.StateUnavailable(new byte[32], null, null)))));
    }
}
