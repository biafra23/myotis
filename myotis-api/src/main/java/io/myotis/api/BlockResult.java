package io.myotis.api;

/**
 * A verified single-block fetch: the header + body summary, plus the beacon
 * verification verdict. A fetch failure sets {@link #error}; a verification
 * failure sets {@link #failReason} (e.g. "preMergeBlock",
 * "headerChainGapTooLarge") with {@code beaconChainVerified=false}.
 *
 * @param number              block number
 * @param hashHex             recomputed block hash (0x-hex)
 * @param parentHashHex       parent hash
 * @param stateRootHex        state root
 * @param transactionsRootHex transactions root
 * @param receiptsRootHex     receipts root
 * @param timestamp           block timestamp (unix seconds)
 * @param gasUsed             gas used
 * @param gasLimit            gas limit
 * @param baseFeePerGasWei    base fee in decimal wei, or null pre-London
 * @param transactionCount    transactions in the body
 * @param uncleCount          uncles in the body
 * @param withdrawalCount     withdrawals in the body
 * @param beaconSynced        beacon client was SYNCED at query time
 * @param beaconChainVerified the block ties to a beacon-attested root/hash
 * @param blsVerified         the beacon match was BLS-signed
 * @param matchedBeaconSlot   slot of the matching attestation; -1 if none
 * @param verifyMethod        "stateRootMatch" / "headerChain" / null
 * @param failReason          null when verified; otherwise a stable reason token
 * @param error               null when the fetch succeeded; otherwise the fetch
 *                            failure message (all other fields are zero/null then)
 */
public record BlockResult(
        long number,
        String hashHex,
        String parentHashHex,
        String stateRootHex,
        String transactionsRootHex,
        String receiptsRootHex,
        long timestamp,
        long gasUsed,
        long gasLimit,
        String baseFeePerGasWei,
        int transactionCount,
        int uncleCount,
        int withdrawalCount,
        boolean beaconSynced,
        boolean beaconChainVerified,
        boolean blsVerified,
        long matchedBeaconSlot,
        String verifyMethod,
        String failReason,
        String error) {
}
