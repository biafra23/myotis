package io.myotis.txhistory

import io.myotis.api.VerifiedReads
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

/**
 * Resolves the LATEST mainnet Unchained Index manifest CID.
 *
 * TrueBlocks publishes each new manifest's IPFS hash on-chain: the UnchainedIndex_V2
 * contract's `manifestHashMap(address publisher, string chain)` returns the newest CID
 * for a publisher/chain pair. We read it through myotis' own VERIFIED eth_call (local
 * EVM over proof-served state) — no external RPC, consistent with the trust model.
 *
 * The publisher identity is the ENS name `publisher.unchainedindex.eth` (chifra's
 * default `PreferredPublisher`) — TrueBlocks re-points it when their publishing wallet
 * rotates, which has happened repeatedly. [publisherResolver] supplies the current
 * address (hosts wire myotis' verified ENS resolution); when it yields nothing the
 * last-known address [DEFAULT_PUBLISHER_HEX] is used. The map is permissionless —
 * anyone can publish under their OWN key (junk entries exist, including under
 * trueblocks.eth itself) — so only the ENS-designated publisher's slot is trusted.
 *
 * Fallback ladder (the call returns null whenever the node isn't SYNCED):
 *   fresh disk cache (< [maxCacheAgeMs]) → contract call → stale disk cache → [FALLBACK_CID].
 */
class ManifestCidResolver(
    private val reads: () -> VerifiedReads?,
    private val cacheFile: Path,
    private val publisherResolver: () -> String? = { null },
    private val maxCacheAgeMs: Long = 24 * 60 * 60 * 1000L,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    enum class Source { CONTRACT_CALL, CACHED, HARDCODED }

    data class Resolved(val cid: String, val source: Source)

    fun resolve(): Resolved {
        val cached = readCache()
        val now = clock()
        if (cached != null && now - cached.first < maxCacheAgeMs) {
            return Resolved(cached.second, Source.CACHED)
        }
        fromContract()?.let { cid ->
            writeCache(now, cid)
            return Resolved(cid, Source.CONTRACT_CALL)
        }
        if (cached != null) {
            log.warn("Manifest contract call unavailable; using stale cached CID {}", cached.second)
            return Resolved(cached.second, Source.CACHED)
        }
        log.warn("Manifest contract call unavailable and no cache; using hardcoded CID")
        return Resolved(FALLBACK_CID, Source.HARDCODED)
    }

    private fun fromContract(): String? {
        val reads = reads() ?: return null
        val publisher = try {
            publisherResolver()?.removePrefix("0x")?.lowercase()
                ?.takeIf { it.length == 40 && it.all { c -> c.isDigit() || c in 'a'..'f' } }
        } catch (e: Exception) {
            log.warn("Publisher ENS resolution failed: {}", e.message)
            null
        } ?: DEFAULT_PUBLISHER_HEX
        val ret = try {
            reads.call(null, CONTRACT_ADDRESS, calldataFor(publisher), null, "latest")
        } catch (e: Exception) {
            log.warn("manifestHashMap eth_call failed: {}", e.message)
            null
        } ?: return null
        val cid = decodeAbiString(ret) ?: return null
        // Sanity: an IPFS CID (v0 "Qm…" base58, or v1 "baf…" base32). Anything else means
        // the return decoded wrong — don't poison the cache with it.
        if (!Regex("^(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[a-z2-7]{20,})$").matches(cid)) {
            log.warn("manifestHashMap returned implausible CID '{}'", cid)
            return null
        }
        return cid
    }

    /** abi-encoded `string` return: [0..32) offset, [off..off+32) length, then the bytes. */
    private fun decodeAbiString(ret: ByteArray): String? {
        try {
            if (ret.size < 64) return null
            val offset = wordToInt(ret, 0) ?: return null
            if (offset + 32 > ret.size) return null
            val len = wordToInt(ret, offset) ?: return null
            if (len <= 0 || offset + 32 + len > ret.size) return null
            return String(ret, offset + 32, len, StandardCharsets.US_ASCII)
        } catch (e: Exception) {
            return null
        }
    }

    /** Big-endian 32-byte word → Int; null when it doesn't fit (a garbage return). */
    private fun wordToInt(b: ByteArray, at: Int): Int? {
        for (i in at until at + 28) if (b[i] != 0.toByte()) return null
        var v = 0L
        for (i in at + 28 until at + 32) v = (v shl 8) or (b[i].toLong() and 0xff)
        return if (v in 0..Int.MAX_VALUE) v.toInt() else null
    }

    private fun readCache(): Pair<Long, String>? = try {
        if (!Files.exists(cacheFile)) null
        else Files.readString(cacheFile).trim().split('\t').takeIf { it.size == 2 }
            ?.let { (ts, cid) -> ts.toLongOrNull()?.let { it to cid } }
    } catch (e: Exception) {
        null
    }

    private fun writeCache(now: Long, cid: String) {
        try {
            Files.createDirectories(cacheFile.parent)
            val tmp = cacheFile.resolveSibling(cacheFile.fileName.toString() + ".tmp")
            Files.writeString(tmp, "$now\t$cid")
            Files.move(tmp, cacheFile, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE)
        } catch (e: Exception) {
            log.warn("Could not persist manifest CID cache: {}", e.message)
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(ManifestCidResolver::class.java)

        /** UnchainedIndex_V2, mainnet. */
        val CONTRACT_ADDRESS: ByteArray =
            hex("0c316b7042b419d07d343f2f4f5bd54ff731183d")

        /** The rotation-proof publisher identity — hosts resolve this via verified ENS. */
        const val PUBLISHER_ENS_NAME = "publisher.unchainedindex.eth"

        /**
         * publisher.unchainedindex.eth's address at implementation time, used when ENS
         * resolution isn't available. NOT trueblocks.eth (0xf503…79b) — that wallet's
         * "mainnet" slot holds a junk placeholder on-chain; the ENS-designated publisher
         * is what chifra trusts.
         */
        const val DEFAULT_PUBLISHER_HEX = "02f2b09b33fdbd406ead954a31f98bd29a2a3492"

        /**
         * manifestHashMap(address,string) calldata for a publisher:
         *   7087e4bd                             selector
         *   000…0<publisher>                     word 0: publisher address, left-padded
         *   000…040                              word 1: offset of the string arg (64)
         *   000…007                              word 2: string length ("mainnet" = 7)
         *   6d61696e6e6574 + 25×00               word 3: "mainnet", right-padded
         */
        fun calldataFor(publisherHex: String): ByteArray = hex(
            "7087e4bd" +
                "000000000000000000000000" + publisherHex +
                "0000000000000000000000000000000000000000000000000000000000000040" +
                "0000000000000000000000000000000000000000000000000000000000000007" +
                "6d61696e6e657400000000000000000000000000000000000000000000000000")

        /**
         * Last-resort manifest: publisher.unchainedindex.eth's on-chain publication at
         * implementation time (5,948 chunks, indexed to block 22,997,660; verified
         * fetchable from ipfs.unchainedindex.io). Replaces the years-older CID the
         * debug stream historically hardcoded. A stale index still serves old history;
         * the UI surfaces the staleness against the verified head.
         */
        const val FALLBACK_CID = "QmQb8BZ1aX7CP34s4KatfCbK34VZshEJFgLRM6c5LNPe4n"

        private fun hex(s: String): ByteArray {
            require(s.length % 2 == 0)
            return ByteArray(s.length / 2) {
                ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
            }
        }
    }
}
