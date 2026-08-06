package io.myotis.evm;

import java.util.HexFormat;
import java.util.List;

/**
 * Closed hierarchy of execution failures the executor surfaces to callers.
 *
 * <p>Callers must handle each case explicitly. {@code InvalidProof} is
 * security-relevant: it indicates a peer returned data that did not verify
 * against the trusted state root.
 *
 * <p>Variants that carry byte arrays clone them in their canonical
 * constructors and accessors. Records' default {@code equals}/{@code toString}
 * for {@code byte[]} are not content-aware; the explicit accessor at least
 * prevents callers from mutating the captured payload after the error has
 * been logged. {@link #toHex(byte[])} is the canonical content-aware format
 * for log lines.
 */
public sealed interface EvmExecutionError {

    /** SNAP fetch failed after retries. {@code slot} is null for account fetches. */
    record StateUnavailable(byte[] stateRoot, Address address, byte[] slot) implements EvmExecutionError {
        public StateUnavailable {
            stateRoot = stateRoot.clone();
            slot = slot == null ? null : slot.clone();
        }
        @Override public byte[] stateRoot() { return stateRoot.clone(); }
        @Override public byte[] slot() { return slot == null ? null : slot.clone(); }
        // Records render byte[] by identity — useless in logs; see InvalidProof.
        @Override public String toString() {
            return "StateUnavailable[stateRoot=" + toHex(stateRoot)
                    + ", address=" + address + ", slot=" + toHex(slot) + "]";
        }
    }

    /** Bytecode fetch failed after retries. */
    record BytecodeUnavailable(byte[] codeHash) implements EvmExecutionError {
        public BytecodeUnavailable { codeHash = codeHash.clone(); }
        @Override public byte[] codeHash() { return codeHash.clone(); }
    }

    /** All listed CCIP-Read gateways failed. */
    record CcipGatewayFailed(List<String> urls, List<String> reasons) implements EvmExecutionError {}

    /**
     * EVM reverted. {@code data} is the raw revert payload; for solidity-style
     * {@code Error(string)} reverts the first 4 bytes are the {@code 0x08c379a0}
     * selector.
     */
    record Reverted(byte[] data) implements EvmExecutionError {
        public Reverted { data = data.clone(); }
        @Override public byte[] data() { return data.clone(); }
    }

    /** Estimation: execution exceeded the configured gas ceiling. */
    record OutOfGas() implements EvmExecutionError {}

    /** Prefetch loop did not converge within the iteration cap. */
    record IterationLimitExceeded(int cap) implements EvmExecutionError {}

    /**
     * SNAP proof did not verify against {@code stateRoot}. This is the
     * security-critical condition: log loudly, deprioritise the peer, surface
     * to the user only if it persists across multiple peers.
     */
    record InvalidProof(byte[] stateRoot, Address address, String detail) implements EvmExecutionError {
        public InvalidProof { stateRoot = stateRoot.clone(); }
        @Override public byte[] stateRoot() { return stateRoot.clone(); }
        // Records render byte[] by identity ("[B@6e8e2cf3") — useless in logs.
        // Every diagnostic surface prints this record, so render the root as hex.
        @Override public String toString() {
            return "InvalidProof[stateRoot=" + toHex(stateRoot)
                    + ", address=" + address + ", detail=" + detail + "]";
        }
    }

    /** Content-aware hex formatter for error log lines. */
    static String toHex(byte[] bytes) {
        return bytes == null ? "<null>" : "0x" + HexFormat.of().formatHex(bytes);
    }
}
