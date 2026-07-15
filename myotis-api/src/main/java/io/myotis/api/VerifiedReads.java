package io.myotis.api;

/**
 * The verified eth_* read surface — every method is answered ONLY from
 * cryptographically verified data. {@code null} means "cannot answer verified
 * right now" (not synced / no peer / head not anchored); the host maps that to a
 * JSON-RPC error in strict mode. The engine never proxies an unverified answer.
 *
 * <p>Methods returning JSON strings ({@code getTransactionReceipt},
 * {@code getBlockByNumber}, …) use the tri-state convention: a JSON object, the
 * literal {@code "null"} (a <em>verified</em> "not found" — e.g. an unknown tx on
 * a synced chain), or {@code null} (no verified answer).
 *
 * <p>All methods are blocking; call from a worker thread. Block selectors are
 * strings: {@code "latest"}, {@code "pending"}, or a 0x-hex block number.
 */
public interface VerifiedReads {

    /** The chain id (static config; never null). */
    long chainId();

    /** Beacon optimistic-head block number, or null when not synced enough. */
    Long headBlockNumber();

    /** The beacon light client's sync state. */
    SyncState syncState();

    /**
     * eth_call against proof-served state in the local EVM. {@code from} may be
     * null (zero sender — reverts {@code msg.sender}-gated contracts, as geth
     * does); {@code valueWei} decimal or null for zero.
     *
     * @return ABI return bytes, or null when unanswerable verified
     */
    byte[] call(byte[] from, byte[] to, byte[] data, String valueWei, String block);

    /** Balance in decimal wei, or null. */
    String getBalance(byte[] address, String block);

    /** Account nonce (with the own-tx pending overlay for "pending"), or null. */
    Long getTransactionCount(byte[] address, String block);

    /** Contract bytecode (verified against the proven codeHash), or null. */
    byte[] getCode(byte[] address, String block);

    /** One 32-byte storage word (proof-verified), or null. */
    byte[] getStorageAt(byte[] address, byte[] slot32, String block);

    /**
     * Gossip a signed raw transaction to peers (the engine never signs).
     *
     * @return keccak256(rawTx) — the tx hash — or null when no peer accepted it
     */
    byte[] sendRawTransaction(byte[] rawTx);

    /** Receipt JSON (verified vs receiptsRoot) | "null" literal | null. */
    String getTransactionReceipt(byte[] txHash);

    /** Transaction JSON (verified vs transactionsRoot) | "null" literal | null. */
    String getTransactionByHash(byte[] txHash);

    /** Block JSON (beacon-anchored header) | "null" literal | null. */
    String getBlockByNumber(String block, boolean fullTransactions);

    /** Block JSON | "null" literal | null. */
    String getBlockByHash(byte[] blockHash32, boolean fullTransactions);

    /**
     * Every receipt of one block as a JSON array (each element the
     * {@code getTransactionReceipt} object shape, verified against the anchored
     * header's {@code receiptsRoot}) | {@code "null"} literal (verified
     * unknown/future block, or a block hash this engine never verified) |
     * {@code null}. {@code blockSelector} is a tag, a 0x-hex number, or a
     * 0x-32-byte block hash.
     */
    String getBlockReceipts(String blockSelector);

    /** Legacy gas price in decimal wei (base fee + tip heuristics), or null. */
    String gasPrice();

    /** Suggested priority fee in decimal wei (from verified bodies), or null. */
    String maxPriorityFeePerGas();

    /** eth_feeHistory result JSON, or null. */
    String feeHistory(long blockCount, String newestBlock, double[] rewardPercentiles);

    /**
     * Gas estimate via the local EVM (intrinsic + metered + safety buffer), or
     * null. A reverting call yields null (the engine won't estimate a doomed tx).
     */
    Long estimateGas(byte[] from, byte[] to, byte[] data, String valueWei);
}
