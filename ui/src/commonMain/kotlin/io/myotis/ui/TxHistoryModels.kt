package io.myotis.ui

/**
 * Streaming transaction-history scan events, mirrored from `:tx-history`'s
 * TxHistoryEvent so commonMain never sees JVM types. Display strings arrive
 * pre-formatted from the host (commonMain has no BigInteger/BigDecimal).
 */
sealed interface TxScanEvent {
    /** Scan begins: which index manifest is used and how fresh it is. */
    data class Started(
        val manifestCid: String,
        val cidSource: String,         // "contract" | "cached" | "hardcoded"
        val totalChunks: Int,
        val latestIndexedBlock: Long,
        val headBlock: Long?,          // null when the node isn't synced
    ) : TxScanEvent

    data class Progress(
        val chunksScanned: Int,
        val totalChunks: Int,
        val currentRange: String,      // "013433393-013436304"-style block range
        val hits: Int,
        val bytesDownloaded: Long,
    ) : TxScanEvent

    /** An appearance in the index; shown as a placeholder row until its Tx arrives. */
    data class Hit(val blockNumber: Long, val txIndex: Int) : TxScanEvent

    /** The resolved, parsed transaction — replaces the matching Hit row in place. */
    data class Tx(val row: TxRowUi) : TxScanEvent

    /** The appearance couldn't be resolved; replaces the Hit row with an error note. */
    data class Failed(val blockNumber: Long, val txIndex: Int, val error: String) : TxScanEvent

    data class Done(val total: Int) : TxScanEvent
}

/** One resolved transaction, ready to render. */
data class TxRowUi(
    val blockNumber: Long,
    val txIndex: Int,
    val hash: String,
    val from: String?,       // null = sender recovery failed
    val to: String?,         // null = contract creation
    val kind: String,        // "eth" | "erc20" | "call" | "create"
    /** Pre-formatted one-liner: "1.25 ETH → 0xab…9e4" / "1250.50 USDC → 0x30…76e" /
     *  "call · 132 bytes calldata" / "contract creation". */
    val headline: String,
)
