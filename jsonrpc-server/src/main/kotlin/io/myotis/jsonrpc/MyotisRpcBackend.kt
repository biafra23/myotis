package io.myotis.jsonrpc

/**
 * Host-provided access to Myotis's verified light-client state, used by the
 * verified JSON-RPC handlers. Each host (Android `NodeService`, the CLI daemon)
 * implements this by delegating to the same shared `RLPxConnector` /
 * `BeaconSyncState` / EVM primitives it already runs — so the JSON-RPC module
 * stays host-agnostic.
 *
 * Methods return null when the answer isn't available verified (e.g. the beacon
 * light client isn't synced yet); the router then falls back to the upstream
 * proxy (or a strict-mode error). Grows phase by phase — Phase B starts with
 * chain id + verified head.
 */
interface MyotisRpcBackend {

    /** EVM chain id (e.g. 1 for mainnet). Always available (from config). */
    fun chainId(): Long

    /**
     * Verified head execution block number (the beacon optimistic head), or null
     * if not synced enough to answer. Returned to wallets as `eth_blockNumber`.
     */
    fun headBlockNumber(): Long?

    /** "SYNCING" | "CATCHING_UP" | "SYNCED". */
    fun syncState(): String

    // --- Phase B verified reads -------------------------------------------
    // Each takes a JSON-RPC block tag (e.g. "latest"); implementations may
    // honor only the fresh-head tags ("latest"/"pending") for now and return
    // null for anything they can't answer verified (unsupported tag, no peer,
    // head not beacon-anchored), in which case the router proxies. These are
    // BLOCKING (network + EVM round-trips) — the router calls them off the IO
    // dispatcher, never on a Java `suspend` boundary, so they stay plain.

    /**
     * eth_call: run [data] against contract [to] in a local EVM over verified
     * state, returning the raw ABI return bytes. Null falls through to the proxy.
     */
    fun call(to: ByteArray, data: ByteArray, block: String): ByteArray?

    /** eth_getBalance: account balance in wei, or null to proxy. */
    fun getBalance(address: ByteArray, block: String): java.math.BigInteger?

    /** eth_getTransactionCount: account nonce, or null to proxy. */
    fun getTransactionCount(address: ByteArray, block: String): Long?

    /**
     * eth_getCode: the account's contract bytecode (empty for an EOA), verified
     * against the proven codeHash, or null to proxy.
     */
    fun getCode(address: ByteArray, block: String): ByteArray?

    /**
     * eth_getStorageAt: the 32-byte value at storage key [slot] (a 32-byte
     * big-endian key), proven against the account's verified storageRoot, or null
     * to proxy (including absent slots, which can't be positively proven here).
     */
    fun getStorageAt(address: ByteArray, slot: ByteArray, block: String): ByteArray?

    /**
     * eth_getProof (EIP-1186): a pre-built JSON object string carrying the account's
     * {balance, nonce, codeHash, storageHash}, the {@code accountProof} (RLP trie
     * nodes proving the account against the verified state root), and one
     * {@code storageProof} entry {key,value,proof[]} per requested 32-byte
     * [storageKeys] slot. The proofs and values are extracted from the SNAP-served
     * trie nodes and re-verified here against the beacon-anchored state root — an
     * absent account/slot yields the canonical empty/zero values with its exclusion
     * proof. Returns Kotlin null when it can't be served verified (not synced, no
     * snap peer, or a historical block the peers have pruned), so the router errors
     * rather than emitting an unverified or fabricated proof. A JSON string keeps the
     * nested proof arrays host-built (no array assembly in the router).
     */
    fun getProof(address: ByteArray, storageKeys: List<ByteArray>, block: String): String? = null

    /**
     * eth_sendRawTransaction: gossip an already-signed [rawTx] to the devp2p
     * network and return its hash (keccak256 of the raw bytes), or null if it
     * couldn't be broadcast (no peer) so the router can fall back to the proxy.
     * Myotis never signs — the wallet user does; this only relays the bytes.
     */
    fun sendRawTransaction(rawTx: ByteArray): ByteArray?

    /**
     * eth_getTransactionReceipt for [txHash], verified against a beacon-anchored
     * header's receiptsRoot. Returns:
     *  - the receipt as a pre-built JSON object string when found + verified;
     *  - the literal "null" when VERIFIED-not-found (node synced, tx not in the recent
     *    verified chain → eth's standard pending/unknown — a valid result);
     *  - Kotlin null when it CAN'T be answered verified (not synced / no peer), so the
     *    router errors rather than implying "pending on a healthy chain".
     * A JSON string keeps the nested receipt+logs host-built (no Map→JSON in the router).
     */
    fun getTransactionReceipt(txHash: ByteArray): String?

    /**
     * eth_getTransactionByHash for [txHash]. Returns:
     *  - the tx as a pre-built JSON object string when found — either in a recent
     *    beacon-verified block (blockHash/blockNumber/transactionIndex set) or, for a tx
     *    this node itself broadcast and not yet mined, from the local sent-tx cache
     *    (blockNumber null = pending; the node holds the signed bytes, so no trust);
     *  - the literal "null" for a VERIFIED "unknown tx" (synced, not in the recent chain
     *    and not one we sent — eth's standard);
     *  - Kotlin null when it CAN'T be answered verified (not synced / no peer) → router errors.
     */
    fun getTransactionByHash(txHash: ByteArray): String? = null

    /**
     * eth_getBlockByNumber for [block] (a tag like "latest" or a 0x hex number), verified
     * from a beacon-anchored header (no snap state needed). Returns the block as a JSON
     * object string (transactions as hashes); the literal "null" for a non-existent
     * (future) block; or Kotlin null when it can't be answered verified (not synced / too
     * far back / [fullTransactions]=true, which isn't served verified yet) → router errors.
     */
    fun getBlockByNumber(block: String, fullTransactions: Boolean): String?

    // --- Fee suggestion (MetaMask's signing screen blocks on these) -----------
    // Defaults return null (→ router errors) so hosts can adopt incrementally.

    /**
     * eth_gasPrice: a legacy-style total gas price suggestion (next baseFee + suggested
     * tip), derived from beacon-verified headers + body-verified tips. Null to error.
     */
    fun gasPrice(): java.math.BigInteger? = null

    /**
     * eth_maxPriorityFeePerGas: suggested priority fee from recent blocks' verified
     * transactions (effective tips, verified against transactionsRoot). Null to error.
     */
    fun maxPriorityFeePerGas(): java.math.BigInteger? = null

    /**
     * eth_feeHistory: the EIP-1559 fee history result as a pre-built JSON object string
     * ({oldestBlock, baseFeePerGas[], gasUsedRatio[], reward[][]?}), computed from
     * beacon-verified headers (+ verified bodies/receipts when [rewardPercentiles] is
     * non-empty). [blockCount] may be clamped by the host (the result reflects what was
     * served, per EIP-1559). Kotlin null when it can't be answered verified → router errors.
     */
    fun feeHistory(blockCount: Long, newestBlock: String, rewardPercentiles: DoubleArray?): String? = null

    /**
     * eth_estimateGas: gas estimate for executing the call/tx against verified state at
     * the head. [value] is the wei value (null = 0). Null when it can't be answered
     * verified (not synced / no snap peer / execution failure) → router errors.
     */
    fun estimateGas(from: ByteArray?, to: ByteArray?, data: ByteArray?,
                    value: java.math.BigInteger?): java.math.BigInteger? = null
}
