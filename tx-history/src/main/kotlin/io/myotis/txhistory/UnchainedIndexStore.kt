package io.myotis.txhistory

import com.eclipsesource.json.Json
import com.jaeckel.trueblocks.Bloom
import com.jaeckel.trueblocks.IndexParser
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
import java.nio.file.Paths
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
 * Disk cache over the Unchained Index's IPFS objects, keyed by CID.
 *
 * CIDs are content addresses, so a given CID's bytes never change and the cache policy
 * is just file existence — no TTL, no invalidation. Writes are unique-tmp-file +
 * atomic-rename, so concurrent scans (daemon + desktop sharing a dir, or two UI scans)
 * never see a half-written file. Two integrity gates apply before bytes are cached:
 * they must be exactly the manifest's stated size (rejects truncation) AND parse
 * successfully. NOTE: this does NOT re-derive the multihash and check it against the
 * CID — a same-length, still-parseable but corrupt object from a buggy/hostile gateway
 * would be cached and, for a bloom, could yield false negatives that mask appearances.
 * That residual risk is bounded by TLS to the trusted gateway and by everything on this
 * path already being unverified (`verified:false`); full CIDv0/dag-pb verification is
 * intentionally not attempted here.
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

    // Explicit Lazy holder so close() can tell whether the client was ever created.
    private val httpLazy = lazy { HttpClient(CIO) }
    private val http get() = httpLazy.value

    /** Manifest [cid] → its chunk list, newest range last (manifest order preserved). */
    suspend fun chunks(manifestCid: String): List<ChunkRef> {
        val cached = cacheDir.resolve("manifests").resolve("$manifestCid.tsv")
        if (Files.exists(cached)) {
            parseManifestTsv(cached)?.let { return it }
            log.warn("Corrupt cached manifest {}; refetching", manifestCid)
        }
        // Fetched over the same Ktor path as blooms/indexes and parsed with minimal-json.
        // Deliberately NOT trueblocks-kotlin's IpfsHttpClient: its constructor force-casts
        // the slf4j factory to logback's LoggerContext, which crashes on hosts whose slf4j
        // binding isn't logback (Android), and it would drag OkHttp+Moshi into the APK.
        // Manifest size isn't known in advance → expectedSize 0 (JSON parse is the gate).
        val refs = parseManifestJson(fetch(manifestCid, 0))
            ?: throw IOException("Manifest $manifestCid from $gatewayBase is not a valid manifest")
        atomicWrite(cached) { tmp ->
            Files.write(tmp, refs.map {
                "${it.range}\t${it.bloomCid}\t${it.bloomSize}\t${it.indexCid}\t${it.indexSize}"
            })
        }
        return refs
    }

    /**
     * TrueBlocks manifest JSON → chunk refs; null when the shape is wrong/empty.
     * Strict per-chunk validation: every entry needs both CIDs, POSITIVE byte sizes,
     * and a parseable block range. A zero size would silently disable the fetch size
     * gate (expectedSize > 0) — the very defense against truncated downloads being
     * cached — and a malformed range breaks ordering/freshness, so a manifest with
     * any such entry is rejected whole rather than partially trusted.
     */
    private fun parseManifestJson(bytes: ByteArray): List<ChunkRef>? = try {
        val rangeRe = Regex("^\\d+-\\d+$")
        val root = Json.parse(String(bytes, Charsets.UTF_8)).asObject()
        val refs = root.get("chunks").asArray().map { it.asObject() }.map {
            ChunkRef(
                range = it.getString("range", ""),
                bloomCid = it.getString("bloomHash", ""),
                bloomSize = it.getLong("bloomSize", 0),
                indexCid = it.getString("indexHash", ""),
                indexSize = it.getLong("indexSize", 0),
            )
        }
        refs.takeIf { list ->
            list.isNotEmpty() && list.all {
                it.bloomCid.isNotEmpty() && it.indexCid.isNotEmpty() &&
                    it.bloomSize > 0 && it.indexSize > 0 && rangeRe.matches(it.range)
            }
        }
    } catch (e: Exception) {
        log.warn("Manifest JSON parse failed: {}", e.message)
        null
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
        // Size check is the first integrity gate (parse success is the second): the lib's
        // parsers are lenient (no magic validation, truncation tolerated — verified against
        // the bytecode), so a short gateway response would otherwise cache as a silently
        // empty bloom and permanently mask every appearance in that block range. It is NOT
        // a content check — see the class doc for the residual same-length-corrupt risk.
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
            // Fall back to the working dir when a flat (parent-less) path is supplied.
            // Paths.get, not Path.of: the latter needs Android API 34 (minSdk is 29).
            val parent = target.parent ?: Paths.get(".")
            Files.createDirectories(parent)
            val tmp = Files.createTempFile(parent, target.fileName.toString(), ".tmp")
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
        // Close the Ktor client (the only HTTP client — manifests, blooms and indexes
        // all fetch through it) if it was actually created this run.
        if (httpLazy.isInitialized()) {
            try { http.close() } catch (ignored: Exception) {}
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(UnchainedIndexStore::class.java)
        const val DEFAULT_GATEWAY = "https://ipfs.unchainedindex.io/ipfs/"
    }
}
