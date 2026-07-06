package io.myotis.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap

/**
 * Live peer-cache counts for the Status UI, parsed from the cache FILES — the
 * cross-engine source of truth (the Rust engine reads/writes the same files
 * directly, so in-memory cache objects go stale for Rust-hosted chains).
 * Memoized on (mtime, size): the 2 s status poll costs one stat() per file.
 * Kotlin twin of the Android `CacheFileStats`; formats documented on the
 * cache classes (`PeerCache`/`CLPeerCache`).
 */
object CacheFileStats {

    data class ClStats(val total: Int, val proven: Int, val nolc: Int) {
        companion object { val EMPTY = ClStats(0, 0, 0) }
    }

    data class ElStats(val total: Int, val snapOk: Int, val snapBad: Int) {
        companion object { val EMPTY = ElStats(0, 0, 0) }
    }

    private data class Memo(val mtime: Long, val size: Long, val stats: Any)

    private val memo = ConcurrentHashMap<Path, Memo>()

    fun cl(file: Path): ClStats = memoized(file, ClStats.EMPTY) { lines ->
        var total = 0; var proven = 0; var nolc = 0
        for (line in lines) {
            val t = line.trim()
            if (!t.startsWith("/")) continue
            total++
            // Per-PEER flags (loader merges multiple range tokens by widening).
            var hasRange = false; var hasNolc = false
            val tokens = t.split('\t')
            for (i in 1 until tokens.size) {
                when {
                    tokens[i] == "nolc" -> hasNolc = true
                    isServedRange(tokens[i]) -> hasRange = true
                }
            }
            if (hasRange) proven++
            if (hasNolc) nolc++
        }
        ClStats(total, proven, nolc)
    }

    fun el(file: Path): ElStats = memoized(file, ElStats.EMPTY) { lines ->
        var total = 0; var snapOk = 0; var snapBad = 0
        for (line in lines) {
            val t = line.trim()
            if (t.isEmpty()) continue
            val tokens = t.split('\t')
            if (tokens.size < 3) {
                // The daemon/desktop PeerCache still LOADS the legacy colon form
                // (ip:port:pubkey[:snap]) and only migrates it on the first full
                // rewrite — count those lines too or a pre-existing data dir
                // under-reports until a rewrite happens.
                if (!t.contains('\t') && t.split(':').size >= 3) total++
                continue
            }
            total++
            // Loader parity: index 3 is the snap flag; quality tokens are
            // recognized from index 4, LAST one wins.
            var quality: String? = null
            for (i in 4 until tokens.size) {
                if (tokens[i] == "snapok" || tokens[i] == "snapbad") quality = tokens[i]
            }
            when (quality) {
                "snapok" -> snapOk++
                "snapbad" -> snapBad++
            }
        }
        ElStats(total, snapOk, snapBad)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T : Any> memoized(file: Path, empty: T, parse: (List<String>) -> T): T {
        val cached = memo[file]
        return try {
            if (!Files.isRegularFile(file)) {
                memo.remove(file)
                return empty
            }
            val mtime = Files.getLastModifiedTime(file).toMillis()
            val size = Files.size(file)
            cached?.let { if (it.mtime == mtime && it.size == size) return it.stats as T }
            val stats = parse(Files.readAllLines(file))
            // Re-stat after the read: the Java-side writers rewrite in place, so
            // only memoize when the identity held across the read — a torn parse
            // is shown once but never sticks.
            if (Files.getLastModifiedTime(file).toMillis() == mtime && Files.size(file) == size) {
                memo[file] = Memo(mtime, size, stats)
            }
            stats
        } catch (e: Exception) {
            // Show last-known counts rather than flashing zeros.
            @Suppress("UNCHECKED_CAST")
            (cached?.stats as? T) ?: empty
        }
    }

    /** A proven served range `<low>-<high>` (or legacy bare integer floor). */
    private fun isServedRange(tok: String): Boolean {
        if (tok.isEmpty()) return false
        val dash = tok.indexOf('-')
        if (dash < 0) return tok.all { it.isDigit() }
        val low = tok.substring(0, dash)
        val high = tok.substring(dash + 1)
        return low.isNotEmpty() && high.isNotEmpty() &&
            low.all { it.isDigit() } && high.all { it.isDigit() }
    }
}
