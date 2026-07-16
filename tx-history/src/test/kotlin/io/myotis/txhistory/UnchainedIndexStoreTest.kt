package io.myotis.txhistory

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class UnchainedIndexStoreTest {

    @TempDir
    lateinit var dir: Path

    @Test
    fun manifestTsvRoundTrips() = runTest {
        val tsv = dir.resolve("manifests").resolve("QmTest.tsv")
        Files.createDirectories(tsv.parent)
        Files.write(tsv, listOf(
            "000000000-000999999\tQmBloomA\t1024\tQmIndexA\t2048",
            "001000000-001999999\tQmBloomB\t4096\tQmIndexB\t8192",
        ))
        val store = UnchainedIndexStore(dir, fetcher = { error("no network expected") })
        val chunks = store.chunks("QmTest")
        assertEquals(2, chunks.size)
        assertEquals(0L, chunks[0].firstBlock)
        assertEquals(999_999L, chunks[0].lastBlock)
        assertEquals("QmBloomB", chunks[1].bloomCid)
        assertEquals(8192L, chunks[1].indexSize)
        assertEquals(1_000_000L, chunks[1].firstBlock)
    }

    @Test
    fun corruptManifestTsvIsNotTrusted() = runTest {
        val tsv = dir.resolve("manifests").resolve("QmBad.tsv")
        Files.createDirectories(tsv.parent)
        Files.write(tsv, listOf("only\ttwo"))
        // A corrupt TSV must NOT round-trip into ChunkRefs; it falls through to a real
        // manifest fetch. Point that at an unroutable gateway so the fetch fails fast and
        // deterministically instead of hitting the network (the fetcher lambda only serves
        // bloom/index fetches, never the manifest — so it can't make this test hermetic).
        val store = UnchainedIndexStore(dir, gatewayBase = "http://127.0.0.1:1/")
        val failed = runCatching { store.chunks("QmBad") }
        assertTrue(failed.isFailure)
    }

    @Test
    fun bloomBytesAreCachedAfterSuccessfulParseAndServedFromDiskAfter() = runTest {
        val bloomBytes = syntheticBloom()
        var fetches = 0
        val store = UnchainedIndexStore(dir, fetcher = { fetches++; bloomBytes })
        val chunk = ChunkRef("000000000-000000100", "QmBloomX", bloomBytes.size.toLong(), "QmIdx", 0)

        assertTrue(!store.bloomCached(chunk))
        store.bloom(chunk)
        assertEquals(1, fetches)
        assertTrue(store.bloomCached(chunk))
        assertEquals(bloomBytes.size.toLong(), store.bytesDownloaded.get())

        store.bloom(chunk) // second read: disk only
        assertEquals(1, fetches)
    }

    @Test
    fun truncatedBloomResponseFailsAndIsNeverCached() = runTest {
        // The lib's parser tolerates truncation silently, so the store's manifest-size
        // check is the integrity gate: a short response must throw, not cache.
        val store = UnchainedIndexStore(dir, fetcher = { ByteArray(10) /* truncated */ })
        val chunk = ChunkRef("000000000-000000100", "QmBloomY", 5_000, "QmIdx", 0)
        val failed = runCatching { store.bloom(chunk) }
        assertTrue(failed.isFailure)
        assertTrue(!store.bloomCached(chunk), "corrupt bytes must not be cached")
    }

    /**
     * Minimal valid bloom file, mirroring trueblocks-kotlin's parse layout (verified
     * against its bytecode): header = u16 magic + 32-byte hash, then u32 count (LE),
     * then per bloom section [u32 nInserted + 131072 filter bytes].
     */
    private fun syntheticBloom(): ByteArray {
        val widthBytes = 131_072 // BLOOM_WIDTH_IN_BYTES in trueblocks-kotlin
        val out = java.io.ByteArrayOutputStream()
        fun u32(v: Int) { // little-endian
            out.write(v and 0xff); out.write((v shr 8) and 0xff)
            out.write((v shr 16) and 0xff); out.write((v shr 24) and 0xff)
        }
        out.write(0xd5); out.write(0xba)   // magic (u16)
        out.write(ByteArray(32))            // header hash
        u32(1)                              // bloom count
        u32(0)                              // nInserted for bloom[0]
        out.write(ByteArray(widthBytes))    // filter bits
        return out.toByteArray()
    }
}
