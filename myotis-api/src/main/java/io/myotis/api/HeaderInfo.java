package io.myotis.api;

/**
 * One fetched block header (integrity-checked: {@code hash} is the recomputed
 * keccak256 of the header RLP, not peer-claimed).
 *
 * @param number           block number
 * @param hashHex          recomputed block hash (0x-hex)
 * @param parentHashHex    parent hash (0x-hex)
 * @param stateRootHex     state root (0x-hex)
 * @param transactionsRootHex transactions root (0x-hex)
 * @param timestamp        block timestamp (unix seconds)
 * @param gasUsed          gas used
 * @param gasLimit         gas limit
 * @param baseFeePerGasWei base fee in decimal wei, or null pre-London
 */
public record HeaderInfo(
        long number,
        String hashHex,
        String parentHashHex,
        String stateRootHex,
        String transactionsRootHex,
        long timestamp,
        long gasUsed,
        long gasLimit,
        String baseFeePerGasWei) {
}
