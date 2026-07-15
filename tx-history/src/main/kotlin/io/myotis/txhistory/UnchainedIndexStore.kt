package io.myotis.txhistory

import com.jaeckel.trueblocks.Bloom
import com.jaeckel.trueblocks.IndexParser
import com.jaeckel.trueblocks.IpfsHttpClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.client.statement.readRawBytes
import io.ktor.http.HttpStatusCode
import io.ktor.http.isSuccess
import org.slf4j.LoggerFactory
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.concurrent.atomic.AtomicLong

/**
 * One Unchained Index chunk from the manifest. [range] is TrueBlocks' zero-padded
 * "firstBlock-lastBlock" string; the CIDs are content addresses of the bloom filter
 * and the full appearance index for that block range.
 */
data class ChunkRef(
    val range: String,
    val bloomCid: String,
    val bloomSize: Long,
    val indexCid: String,
    val indexSize: Long,
) {
    val firstBlock: Long = range.substringBefore('-').toLongOrNull() ?: 0
    val lastBlock: Long = range.substringAfter('-').toLongOrNull() ?: 0
}

/**
 * Content-addressed disk cache over the Unchained Index's IPFS objects.
 *
 * Everything here is immutable-by-address (a CID never changes content), so the cache
 * policy is just file existence — no TTL, no invalidation — and concurrent scans
 * (daemon + desktop sharing a dir, or two UI scans) are safe via unique-tmp-file +
 * atomic-rename writes. Bytes are only cached AFTER they parse, so a truncated gateway
 * response can't poison the cache.
 *
 * Layout under [cacheDir]: `manifests/<cid>.tsv`, `blooms/<cid>`, `index/<cid>`.
 */
class UnchainedIndexStore(
    private val cacheDir: Path,
    private val gatewayBase: String = DEFAULT_GATEWAY,
    /** Injectable for tests; the default does an HTTP GET of `gatewayBase + cid`. */
    private val fetcher: (suspend (String) -> ByteArray)? = null,
) : AutoCloseable {

    /** Total bytes fetched over HTTP by this store instance (cache misses only). */
    val bytesDownloaded = AtomicLong()

    private val http by lazy { HttpClient(CIO) }

    /** Manifest [cid] → its chunk list, newest range last (manifest order preserved). */
    suspend fun chunks(manifestCid: String): List<ChunkRef> {
        val cached = cacheDir.resolve("manifests").resolve("$manifestCid.tsv")
        if (Files.exists(cached)) {
            parseManifestTsv(cached)?.let { return it }
            log.warn("Corrupt cached manifest {}; refetching", manifestCid)
        }
        // The trueblocks-kotlin client already knows the manifest JSON shape; reuse it
        // for the (small, once-per-CID) manifest fetch instead of hand-parsing JSON.
        val manifest = IpfsHttpClient(gatewayBase).fetchAndParseManifestUrl(manifestCid)
            ?: throw IOException("Manifest $manifestCid not fetchable via $gatewayBase")
        val refs = manifest.chunks.map {
            ChunkRef(it.range, it.bloomHash, it.bloomSize.toLong(), it.indexHash, it.indexSize.toLong())
        }
        if (refs.isEmpty()) throw IOException("Manifest $manifestCid contains no chunks")
        atomicWrite(cached) { tmp ->
            Files.write(tmp, refs.map {
                "${it.range}\t${it.bloomCid}\t${it.bloomSize}\t${it.indexCid}\t${it.indexSize}"
            })
        }
        return refs
    }

    fun bloomCached(c: ChunkRef): Boolean = Files.exists(bloomFile(c))

    /** The chunk's bloom filter — disk cache first, gateway on miss. */
    suspend fun bloom(c: ChunkRef): Bloom {
        val file = bloomFile(c)
        if (Files.exists(file)) {
            try {
                val bytes = Files.readAllBytes(file)
                return Bloom.parseBloomBytes(bytes, bytes.size.toLong())
            } catch (e: Exception) {
                log.warn("Corrupt cached bloom {}; refetching: {}", c.bloomCid, e.message)
                Files.deleteIfExists(file)
            }
        }
        val bytes = fetch(c.bloomCid, c.bloomSize)
        val bloom = Bloom.parseBloomBytes(bytes, bytes.size.toLong()) // parse BEFORE caching
        atomicWrite(file) { tmp -> Files.write(tmp, bytes) }
        return bloom
    }

    /** The chunk's full appearance index — disk cache first, gateway on miss. */
    suspend fun index(c: ChunkRef): IndexParser {
        val file = cacheDir.resolve("index").resolve(c.indexCid)
        if (Files.exists(file)) {
            try {
                return IndexParser(Files.readAllBytes(file))
            } catch (e: Exception) {
                log.warn("Corrupt cached index {}; refetching: {}", c.indexCid, e.message)
                Files.deleteIfExists(file)
            }
        }
        val bytes = fetch(c.indexCid, c.indexSize)
        val index = IndexParser(bytes) // parse BEFORE caching
        atomicWrite(file) { tmp -> Files.write(tmp, bytes) }
        return index
    }

    private fun bloomFile(c: ChunkRef) = cacheDir.resolve("blooms").resolve(c.bloomCid)

    private suspend fun fetch(cid: String, expectedSize: Long): ByteArray {
        val bytes = fetcher?.invoke(cid) ?: httpGet(cid)
        bytesDownloaded.addAndGet(bytes.size.toLong())
        // The manifest's per-chunk byte sizes are the integrity gate: the lib's parsers
        // are lenient (no magic validation, truncation tolerated — verified against the
        // bytecode), so a short gateway response would otherwise cache as a silently
        // empty bloom and permanently mask every appearance in that block range.
        if (expectedSize > 0 && bytes.size.toLong() != expectedSize) {
            throw IOException(
                "$cid: fetched ${bytes.size} bytes but manifest says $expectedSize — truncated response?")
        }
        return bytes
    }

    private suspend fun httpGet(cid: String): ByteArray {
        val resp = http.get(gatewayBase + cid)
        if (!resp.status.isSuccess()) {
            throw IOException("GET $gatewayBase$cid → ${resp.status}")
        }
        if (resp.status == HttpStatusCode.PartialContent) {
            throw IOException("GET $gatewayBase$cid → unexpected partial content")
        }
        return resp.readRawBytes()
    }

    private inline fun atomicWrite(target: Path, write: (Path) -> Unit) {
        try {
            Files.createDirectories(target.parent)
            val tmp = Files.createTempFile(target.parent, target.fileName.toString(), ".tmp")
            try {
                write(tmp)
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE)
            } finally {
                Files.deleteIfExists(tmp)
            }
        } catch (e: Exception) {
            // Cache write failure must never fail the scan — next run just refetches.
            log.warn("Could not cache {}: {}", target.fileName, e.message)
        }
    }

    private fun parseManifestTsv(file: Path): List<ChunkRef>? = try {
        val refs = Files.readAllLines(file).filter { it.isNotBlank() }.map { line ->
            val f = line.split('\t')
            if (f.size != 5) return null
            ChunkRef(f[0], f[1], f[2].toLong(), f[3], f[4].toLong())
        }
        refs.ifEmpty { null }
    } catch (e: Exception) {
        null
    }

    override fun close() {
        // Only tear down the lazy client if it was actually created.
        if (fetcher == null) {
            try {
                http.close()
            } catch (ignored: Exception) {
            }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(UnchainedIndexStore::class.java)
        const val DEFAULT_GATEWAY = "https://ipfs.unchainedindex.io/ipfs/"
    }
}
