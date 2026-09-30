package io.myotis.evm;

import com.jaeckel.ethp2p.core.encoding.Hex;

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

    /**
     * An ANSWER about the request, not a failure to answer (#509): the
     * transaction cannot succeed within the caller's own limits — its gas, its
     * fee cap, its funds. {@link #message()} is geth's, which hosts serve
     * verbatim as geth does (JSON-RPC -32000), never as a number or return
     * data: a wallet that broadcast one would lose the fee.
     */
    sealed interface Infeasible extends EvmExecutionError {
        String message();
    }

    /**
     * Estimation: the transaction does not succeed within the gas the caller
     * allowed — its gas limit, what its fee cap lets the sender pay for, or the
     * executor's own ceiling, whichever is lowest (#509). An ANSWER, not a
     * failure to answer; {@link #message()} is geth's, which hosts serve
     * verbatim as geth does.
     */
    record GasAllowanceExceeded(long allowance) implements Infeasible {
        public String message() {
            return "gas required exceeds allowance (" + allowance + ")";
        }
    }

    /**
     * Estimation under a fee cap: the sender cannot even cover the transferred
     * value (#509) — geth's {@code insufficient funds for transfer}, an answer
     * like {@link GasAllowanceExceeded}.
     */
    record InsufficientFundsForTransfer() implements Infeasible {
        public String message() {
            return "insufficient funds for transfer";
        }
    }

    /**
     * A transaction-object call under a fee (#509): the sender cannot pay
     * {@code gas × fee cap + value} — geth's {@code insufficient funds for gas
     * * price + value}, an answer like {@link GasAllowanceExceeded}.
     */
    record InsufficientFunds(Address address, java.math.BigInteger have, java.math.BigInteger want)
            implements Infeasible {
        public String message() {
            return "insufficient funds for gas * price + value: address " + checksummed(address)
                    + " have " + have + " want " + want;
        }
    }

    /**
     * A fee cap (or legacy gas price) below the block's base fee (#509): no
     * block at that base fee includes the transaction, so geth answers
     * {@code max fee per gas less than block base fee} for a call and an
     * estimate alike.
     */
    record FeeCapTooLow(Address address, java.math.BigInteger feeCap, long baseFee)
            implements Infeasible {
        public String message() {
            return "max fee per gas less than block base fee: address " + checksummed(address)
                    + ", maxFeePerGas: " + feeCap + ", baseFee: " + baseFee;
        }
    }

    /** A transaction-object call whose {@code gas} is below its intrinsic cost
     *  (#509) — geth's {@code intrinsic gas too low}. */
    record IntrinsicGasTooLow(long have, long want) implements Infeasible {
        public String message() {
            return "intrinsic gas too low: have " + have + ", want " + want;
        }
    }

    /** A transaction-object call whose {@code gas} is below the EIP-7623
     *  calldata floor (#509) — geth's {@code insufficient gas for floor data
     *  gas cost}. */
    record FloorDataGasTooLow(long have, long want) implements Infeasible {
        public String message() {
            return "insufficient gas for floor data gas cost: have " + have + ", want " + want;
        }
    }

    /** A transaction-object call that ran out of the {@code gas} the caller
     *  gave it (#509) — geth's {@code out of gas}. Without a caller limit a
     *  call that runs dry is {@link OutOfGas}, as before. */
    record CallOutOfGas() implements Infeasible {
        public String message() {
            return "out of gas";
        }
    }

    /** An estimate whose run at its ceiling {@code gas} was refused outright (a
     *  fee cap below the base fee): geth's estimator reports that run's error as
     *  {@code failed with <gas> gas: <error>}, and so does this one. */
    record FailedWithGas(long gas, Infeasible error) implements Infeasible {
        public String message() {
            return "failed with " + gas + " gas: " + error.message();
        }
    }

    /** A transaction-object call whose {@code gas × fee cap + value} is past
     *  2^256 wei (#509) — geth's {@code insufficient funds for gas * price +
     *  value: address … required balance exceeds 256 bits}. */
    record RequiredBalanceOverflow(Address address) implements Infeasible {
        public String message() {
            return "insufficient funds for gas * price + value: address " + checksummed(address)
                    + " required balance exceeds 256 bits";
        }
    }

    /** A transaction-object call refused by a check it failed before running
     *  (fee cap, balance, intrinsic cost, floor): geth's {@code eth_call}
     *  reports it as {@code err: <error> (supplied gas <gas>)}, and so does
     *  this one. */
    record CallFailed(long suppliedGas, Infeasible error) implements Infeasible {
        public String message() {
            return "err: " + error.message() + " (supplied gas " + suppliedGas + ")";
        }
    }

    /**
     * EVM halted exceptionally WITHOUT a revert payload (invalid opcode, stack
     * violation, the deliberate BLOCKHASH gap, …). Distinct from
     * {@link Reverted} on purpose: a revert is a verified chain answer whose
     * payload hosts serve verbatim (JSON-RPC code 3), while a halt's
     * {@code detail} is a local diagnostic string the chain never produced —
     * conflating them would serve fabricated revert data for calls that may
     * succeed on a full node.
     */
    record Halted(String detail) implements EvmExecutionError {}

    /**
     * The block's fork is known but this engine cannot price it — the Java engine
     * past Sepolia's Amsterdam activation, which its Besu (26.4) has no final EVM
     * for. A PERMANENT refusal for this build, not a transient failure: running
     * the previous fork's rules instead would be a well-formed answer to a
     * different question (CLAUDE.md apply-or-refuse), and no retry can help, so
     * hosts serve it as a permanent JSON-RPC error, never the retryable -32000.
     */
    record UnsupportedFork(String detail) implements EvmExecutionError {}

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

    /** {@code address} as geth prints it ({@code common.Address.Hex()}): EIP-55
     *  mixed-case checksum hex, so a wallet reads the same message from this
     *  engine as from the Rust one and from a public node. */
    static String checksummed(Address address) {
        CryptoProviders.ensureRegistered();
        String hex = address.toHex().substring(2).toLowerCase(java.util.Locale.ROOT);
        byte[] hash = org.apache.tuweni.crypto.Hash.keccak256(
                org.apache.tuweni.bytes.Bytes.wrap(hex.getBytes(java.nio.charset.StandardCharsets.US_ASCII)))
                .toArrayUnsafe();
        StringBuilder out = new StringBuilder("0x");
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            int nibble = (hash[i / 2] >> (i % 2 == 0 ? 4 : 0)) & 0xf;
            out.append(Character.isLetter(c) && nibble >= 8 ? Character.toUpperCase(c) : c);
        }
        return out.toString();
    }

    /** Content-aware hex formatter for error log lines. */
    static String toHex(byte[] bytes) {
        return bytes == null ? "<null>" : Hex.formatHexPrefixed(bytes);
    }
}
