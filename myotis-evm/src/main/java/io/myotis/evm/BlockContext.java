package io.myotis.evm;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Block-level execution context derived from a sync-committee-verified header.
 *
 * <p>All fields must come from the verified header. They are never sourced
 * locally — using the local clock for {@code timestamp} would, for instance,
 * desynchronise EVM execution from consensus.
 *
 * @param stateRoot      32-byte state root the call must verify against
 * @param blockNumber    block number; selects the EVM hard fork rules
 * @param timestamp      Unix seconds; selects fork rules where ranges are timestamp-keyed
 * @param baseFeePerGas  EIP-1559 base fee, or null pre-London
 * @param coinbase       block proposer address (used by {@code COINBASE} opcode)
 * @param prevRandao     post-merge {@code PREVRANDAO}; pre-merge this is the difficulty
 * @param chainId        EIP-155 chain id (used by {@code CHAINID} opcode)
 * @param gasLimit       block gas limit
 */
public record BlockContext(
        byte[] stateRoot,
        long blockNumber,
        long timestamp,
        BigInteger baseFeePerGas,
        Address coinbase,
        byte[] prevRandao,
        BigInteger chainId,
        long gasLimit) {

    public BlockContext {
        Objects.requireNonNull(stateRoot, "stateRoot");
        if (stateRoot.length != 32) {
            throw new IllegalArgumentException("stateRoot must be 32 bytes");
        }
        Objects.requireNonNull(coinbase, "coinbase");
        Objects.requireNonNull(prevRandao, "prevRandao");
        if (prevRandao.length != 32) {
            throw new IllegalArgumentException("prevRandao must be 32 bytes");
        }
        Objects.requireNonNull(chainId, "chainId");
    }
}
