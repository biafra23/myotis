package io.myotis.txhistory

import com.jaeckel.ethp2p.networking.rlpx.RLPxConnector
import io.myotis.api.VerifiedReads
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.runInterruptible
import org.apache.tuweni.bytes.Bytes
import org.apache.tuweni.bytes.Bytes32
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.file.Path
import java.util.concurrent.TimeUnit

sealed interface TxHistoryEvent {
    /** Scan begins: which manifest, how it was found, and how fresh the index is. */
    data class Started(
        val manifestCid: String,
        val cidSource: String,         // "contract" | "cached" | "hardcoded"
        val totalChunks: Int,
        val latestIndexedBlock: Long,  // last block the index covers
        val headBlock: Long?,          // node's verified head, null when not synced
    ) : TxHistoryEvent

    /** Emitted once per chunk, before its bloom is tested. */
    data class Progress(
        val chunksScanned: Int,
        val totalChunks: Int,
        val currentRange: String,
        val hits: Int,
        val bytesDownloaded: Long,
    ) : TxHistoryEvent

    /** An appearance found in the index — the tx itself is still being fetched. */
    data class Hit(val blockNumber: Long, val txIndex: Int) : TxHistoryEvent

    /** The appearance resolved into a parsed transaction (upgrades the matching Hit). */
    data class Tx(val summary: TxSummary) : TxHistoryEvent

    /** The appearance could not be resolved (peer timeouts etc.); scan continues. */
    data class TxFailed(val blockNumber: Long, val txIndex: Int, val error: String) : TxHistoryEvent

    data class Done(val txCount: Int) : TxHistoryEvent
}

/**
 * Streams an address's transaction history out of the TrueBlocks Unchained Index,
 * newest first: manifest (freshest CID via [ManifestCidResolver]) → per-chunk bloom
 * test ([UnchainedIndexStore], disk-cached) → appearance list → header+body fetch over
 * devp2p → [TxClassifier].
 *
 * DEBUG/explorer aid, outside the engine API boundary: it wraps the raw
 * [RLPxConnector], and resolved transactions are UNVERIFIED (never checked against a
 * block's transactionsRoot). Mainnet only — the index, the well-known-token table and
 * the manifest contract are all mainnet.
 */
class TxHistoryService @JvmOverloads constructor(
    private val connector: RLPxConnector,
    private val reads: () -> VerifiedReads?,
    private val cacheDir: Path,
    /** Current address of `publisher.unchainedindex.eth` (0x-hex), or null to use the
     *  last-known default — hosts wire myotis' verified ENS resolution here. */
    publisherResolver: () -> String? = { null },
    private val gatewayBase: String = UnchainedIndexStore.DEFAULT_GATEWAY,
) {
    private val resolver = ManifestCidResolver(
        reads, cacheDir.resolve("manifest-cid-mainnet.txt"), publisherResolver)

    /**
     * Cold, cancellable stream of scan events for [address] (a 0x 20-byte hex string).
     * Cancelling the collection stops the scan promptly, including mid-devp2p-fetch.
     */
    fun scan(address: String): Flow<TxHistoryEvent> = flow {
        val hex = address.removePrefix("0x").removePrefix("0X")
        require(hex.length == 40 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            "address must be a 20-byte hex string (40 hex chars)"
        }
        val addr = "0x" + hex.lowercase()

        UnchainedIndexStore(cacheDir, gatewayBase).use { store ->
            val resolved = resolver.resolve()
            val chunks = store.chunks(resolved.cid).sortedBy { it.lastBlock }
            emit(TxHistoryEvent.Started(
                manifestCid = resolved.cid,
                cidSource = when (resolved.source) {
                    ManifestCidResolver.Source.CONTRACT_CALL -> "contract"
                    ManifestCidResolver.Source.CACHED -> "cached"
                    ManifestCidResolver.Source.HARDCODED -> "hardcoded"
                },
                totalChunks = chunks.size,
                latestIndexedBlock = chunks.last().lastBlock,
                headBlock = try { reads()?.headBlockNumber() } catch (e: Exception) { null },
            ))

            var hits = 0
            var resolvedCount = 0
            // Newest chunk first so recent history streams before the deep past.
            chunks.asReversed().forEachIndexed { i, chunk ->
                emit(TxHistoryEvent.Progress(
                    chunksScanned = i, totalChunks = chunks.size,
                    currentRange = chunk.range, hits = hits,
                    bytesDownloaded = store.bytesDownloaded.get(),
                ))
                try {
                    if (!store.bloom(chunk).containsAddress(addr)) return@forEachIndexed
                    val appearances = store.index(chunk).findAppearances(addr)
                        .map { it.blockNumber.toLong() to it.txIndex.toInt() }
                        .sortedWith(compareByDescending<Pair<Long, Int>> { it.first }
                            .thenByDescending { it.second })
                    if (appearances.isEmpty()) return@forEachIndexed // bloom false positive

                    hits += appearances.size
                    log.info("[tx-history] {} appearances in chunk {}", appearances.size, chunk.range)
                    // All placeholders first: the UI shows every block number in the
                    // chunk immediately, then upgrades them one by one.
                    appearances.forEach { (block, txIdx) ->
                        emit(TxHistoryEvent.Hit(block, txIdx))
                    }
                    var lastBlock = -1L
                    var lastTxs: List<Bytes>? = null
                    appearances.forEach { (block, txIdx) ->
                        try {
                            val txs = if (block == lastBlock) lastTxs!! else fetchBlockTxs(block)
                            lastBlock = block; lastTxs = txs
                            if (txIdx >= txs.size) {
                                emit(TxHistoryEvent.TxFailed(block, txIdx,
                                    "transaction index out of range (${txs.size} txs)"))
                                return@forEach
                            }
                            val summary = TxClassifier.classify(block, txIdx, txs[txIdx])
                            if (summary == null) {
                                emit(TxHistoryEvent.TxFailed(block, txIdx, "undecodable transaction"))
                            } else {
                                emit(TxHistoryEvent.Tx(summary))
                                resolvedCount++
                            }
                        } catch (e: Exception) {
                            if (e is kotlinx.coroutines.CancellationException) throw e
                            emit(TxHistoryEvent.TxFailed(block, txIdx, e.message ?: e.javaClass.simpleName))
                        }
                    }
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    // One bad chunk (gateway hiccup, truncated response) must not kill
                    // the scan — same tolerance the IPC stream always had.
                    log.warn("[tx-history] chunk {} failed: {}", chunk.range, e.message)
                }
            }
            emit(TxHistoryEvent.Done(resolvedCount))
        }
    }.flowOn(Dispatchers.IO)

    /** Header by number, then body by hash. runInterruptible → cancellation interrupts the get(). */
    private suspend fun fetchBlockTxs(blockNumber: Long): List<Bytes> = runInterruptible {
        val headers = connector.requestBlockHeadersBatched(blockNumber, 1)
            .get(FETCH_TIMEOUT_S, TimeUnit.SECONDS)
        if (headers.isEmpty()) throw IOException("no header returned for block $blockNumber")
        val hash: Bytes32 = headers[0].hash()
        val bodies = connector.requestBlockBodies(hash).get(FETCH_TIMEOUT_S, TimeUnit.SECONDS)
        if (bodies.isEmpty()) throw IOException("no body returned for block $blockNumber")
        bodies[0].transactions()
    }

    /** Java-friendly sink for the IPC stream. Throwing [IOException] from the sink
     *  (client hung up) cancels the scan. */
    fun interface EventSink {
        @Throws(IOException::class)
        fun onEvent(event: TxHistoryEvent)
    }

    /** Blocking adapter for the daemon's virtual-thread-per-connection IPC server. */
    @Throws(IOException::class)
    fun scanBlocking(address: String, sink: EventSink) {
        runBlocking {
            scan(address).collect { sink.onEvent(it) }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(TxHistoryService::class.java)
        private const val FETCH_TIMEOUT_S = 30L
    }
}
