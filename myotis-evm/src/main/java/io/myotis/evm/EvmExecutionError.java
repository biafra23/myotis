package io.myotis.evm;

import java.util.List;

/**
 * Closed hierarchy of execution failures the executor surfaces to callers.
 *
 * <p>Callers must handle each case explicitly. {@code InvalidProof} is
 * security-relevant: it indicates a peer returned data that did not verify
 * against the trusted state root.
 */
public sealed interface EvmExecutionError {

    /** SNAP fetch failed after retries. {@code slot} is null for account fetches. */
    record StateUnavailable(byte[] stateRoot, Address address, byte[] slot) implements EvmExecutionError {}

    /** Bytecode fetch failed after retries. */
    record BytecodeUnavailable(byte[] codeHash) implements EvmExecutionError {}

    /** All listed CCIP-Read gateways failed. */
    record CcipGatewayFailed(List<String> urls, List<String> reasons) implements EvmExecutionError {}

    /**
     * EVM reverted. {@code data} is the raw revert payload; for solidity-style
     * {@code Error(string)} reverts the first 4 bytes are the {@code 0x08c379a0}
     * selector.
     */
    record Reverted(byte[] data) implements EvmExecutionError {}

    /** Estimation: execution exceeded the configured gas ceiling. */
    record OutOfGas() implements EvmExecutionError {}

    /** Prefetch loop did not converge within the iteration cap. */
    record IterationLimitExceeded(int cap) implements EvmExecutionError {}

    /**
     * SNAP proof did not verify against {@code stateRoot}. This is the
     * security-critical condition: log loudly, deprioritise the peer, surface
     * to the user only if it persists across multiple peers.
     */
    record InvalidProof(byte[] stateRoot, Address address, String detail) implements EvmExecutionError {}
}
