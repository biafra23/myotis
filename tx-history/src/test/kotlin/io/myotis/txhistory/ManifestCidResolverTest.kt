package io.myotis.txhistory

import io.myotis.api.VerifiedReads
import org.apache.tuweni.bytes.Bytes
import org.apache.tuweni.crypto.Hash
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.lang.reflect.Proxy
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class ManifestCidResolverTest {

    companion object {
        init {
            java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }
    }

    @TempDir
    lateinit var dir: Path

    private val cacheFile: Path get() = dir.resolve("manifest-cid-mainnet.txt")

    private val validCid = "QmUBS83qjRmXmSgEvZADVv2ch47137jkgNbqfVVxQep5Y2"

    /** A VerifiedReads whose call() returns [ret]; every other method must not be touched. */
    private fun readsReturning(ret: ByteArray?): VerifiedReads =
        Proxy.newProxyInstance(
            VerifiedReads::class.java.classLoader,
            arrayOf(VerifiedReads::class.java),
        ) { _, method, _ ->
            if (method.name == "call") ret else throw AssertionError("unexpected ${method.name}")
        } as VerifiedReads

    private fun abiString(s: String): ByteArray {
        val bytes = s.toByteArray(StandardCharsets.US_ASCII)
        val padded = bytes + ByteArray((32 - bytes.size % 32) % 32)
        return word(32) + word(bytes.size) + padded
    }

    private fun word(v: Int): ByteArray = ByteArray(32).also {
        it[28] = (v ushr 24).toByte(); it[29] = (v ushr 16).toByte()
        it[30] = (v ushr 8).toByte(); it[31] = v.toByte()
    }

    @Test
    fun calldataMatchesHandBuiltEncoding() {
        // Selector derived independently from the signature, not copied from the constant.
        val selector = Hash.keccak256(
            Bytes.wrap("manifestHashMap(address,string)".toByteArray())).slice(0, 4)
        val publisher = Bytes.fromHexString("0x" + ManifestCidResolver.DEFAULT_PUBLISHER_HEX)
        val chain = "mainnet".toByteArray(StandardCharsets.US_ASCII)
        val expected = Bytes.concatenate(
            selector,
            org.apache.tuweni.bytes.Bytes32.leftPad(publisher),  // address arg
            Bytes.wrap(word(64)),                                 // offset of string arg
            Bytes.wrap(word(chain.size)),                         // string length
            Bytes.wrap(chain + ByteArray(32 - chain.size)),       // right-padded content
        )
        assertArrayEquals(
            expected.toArray(),
            ManifestCidResolver.calldataFor(ManifestCidResolver.DEFAULT_PUBLISHER_HEX))
        assertEquals("7087e4bd", selector.toUnprefixedHexString())
    }

    @Test
    fun ensResolvedPublisherIsUsedInTheCall() {
        val ensPublisher = "0xEDE750e437251Eb69423713d5BE21cbe88116141" // mixed case + 0x on purpose
        var calledWith: ByteArray? = null
        val reads = Proxy.newProxyInstance(
            VerifiedReads::class.java.classLoader,
            arrayOf(VerifiedReads::class.java),
        ) { _, method, args ->
            if (method.name == "call") {
                calledWith = args[2] as ByteArray
                abiString(validCid)
            } else throw AssertionError("unexpected ${method.name}")
        } as VerifiedReads
        val resolver = ManifestCidResolver(
            { reads }, cacheFile, publisherResolver = { ensPublisher }, clock = { 1L })
        assertEquals(validCid, resolver.resolve().cid)
        assertArrayEquals(
            ManifestCidResolver.calldataFor("ede750e437251eb69423713d5be21cbe88116141"),
            calledWith)
    }

    @Test
    fun garbagePublisherResolutionFallsBackToDefaultPublisher() {
        var calledWith: ByteArray? = null
        val reads = Proxy.newProxyInstance(
            VerifiedReads::class.java.classLoader,
            arrayOf(VerifiedReads::class.java),
        ) { _, method, args ->
            if (method.name == "call") {
                calledWith = args[2] as ByteArray
                abiString(validCid)
            } else throw AssertionError("unexpected ${method.name}")
        } as VerifiedReads
        val resolver = ManifestCidResolver(
            { reads }, cacheFile, publisherResolver = { "not-an-address" }, clock = { 1L })
        assertEquals(validCid, resolver.resolve().cid)
        assertArrayEquals(
            ManifestCidResolver.calldataFor(ManifestCidResolver.DEFAULT_PUBLISHER_HEX),
            calledWith)
    }

    @Test
    fun contractCallResolvesAndPersistsCache() {
        val resolver = ManifestCidResolver(
            { readsReturning(abiString(validCid)) }, cacheFile, clock = { 1_000_000L })
        val r = resolver.resolve()
        assertEquals(ManifestCidResolver.Source.CONTRACT_CALL, r.source)
        assertEquals(validCid, r.cid)
        assertEquals("1000000\t$validCid", Files.readString(cacheFile))
    }

    @Test
    fun freshCacheShortCircuitsWithoutCalling() {
        Files.writeString(cacheFile, "1000000\t$validCid")
        // reads supplier throws if consulted — the fresh cache must win first.
        val resolver = ManifestCidResolver(
            { throw AssertionError("must not call") }, cacheFile,
            maxCacheAgeMs = 100_000, clock = { 1_050_000L })
        val r = resolver.resolve()
        assertEquals(ManifestCidResolver.Source.CACHED, r.source)
        assertEquals(validCid, r.cid)
    }

    @Test
    fun staleCacheRefreshesFromContract() {
        Files.writeString(cacheFile, "1000000\tQmStaleStaleStaleStaleStaleStaleStaleStaleSta")
        val resolver = ManifestCidResolver(
            { readsReturning(abiString(validCid)) }, cacheFile,
            maxCacheAgeMs = 100_000, clock = { 2_000_000L })
        val r = resolver.resolve()
        assertEquals(ManifestCidResolver.Source.CONTRACT_CALL, r.source)
        assertEquals(validCid, r.cid)
    }

    @Test
    fun staleCacheBeatsHardcodedWhenNodeUnsynced() {
        Files.writeString(cacheFile, "1000000\t$validCid")
        val resolver = ManifestCidResolver(
            { null }, cacheFile, maxCacheAgeMs = 100_000, clock = { 2_000_000L })
        val r = resolver.resolve()
        assertEquals(ManifestCidResolver.Source.CACHED, r.source)
        assertEquals(validCid, r.cid)
    }

    @Test
    fun hardcodedFallbackWhenNothingElse() {
        val resolver = ManifestCidResolver({ null }, cacheFile)
        val r = resolver.resolve()
        assertEquals(ManifestCidResolver.Source.HARDCODED, r.source)
        assertEquals(ManifestCidResolver.FALLBACK_CID, r.cid)
    }

    @Test
    fun garbageReturnFallsThrough() {
        val garbage = ByteArray(64) { 0x7f }
        val resolver = ManifestCidResolver({ readsReturning(garbage) }, cacheFile)
        assertEquals(ManifestCidResolver.Source.HARDCODED, resolver.resolve().source)
        assertTrue(!Files.exists(cacheFile), "garbage must not be cached")
    }

    @Test
    fun implausibleCidStringRejected() {
        val resolver = ManifestCidResolver(
            { readsReturning(abiString("not-a-cid")) }, cacheFile)
        assertEquals(ManifestCidResolver.Source.HARDCODED, resolver.resolve().source)
    }
}
