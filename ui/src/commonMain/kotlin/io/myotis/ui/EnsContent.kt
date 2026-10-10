package io.myotis.ui

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

/** The key under which [EnsProfile] carries the contenthash next to the ENSIP-5 text keys. */
const val ENS_CONTENTHASH_KEY = "contenthash"

/**
 * The ENSIP-5 text records the Query tab's ENS card reads beyond the address, in display
 * order: the global keys a profile usually fills, then the service keys.
 */
val ENS_PROFILE_KEYS: List<String> = listOf(
    "avatar", "description", "url", "email", "com.twitter", "com.github", "org.telegram", "com.discord",
)

/**
 * The fan-out behind every host's [NodeController.resolveEnsProfile]: [read] one record per
 * key — the contenthash under [ENS_CONTENTHASH_KEY], then [ENS_PROFILE_KEYS] — concurrently,
 * and fold a read that THREW into that record's error, so one failure never hides the
 * others (a host's engine call can throw for a stopped or sleeping node). Hosts supply only
 * the single-record read; the key set and the failure policy live here, once.
 */
suspend fun readEnsProfile(name: String, read: suspend (key: String) -> EnsRecord): EnsProfile {
    val n = name.trim()
    val records = coroutineScope {
        (listOf(ENS_CONTENTHASH_KEY) + ENS_PROFILE_KEYS).map { key ->
            async {
                try {
                    read(key)
                } catch (c: CancellationException) {
                    throw c
                } catch (t: Throwable) {
                    EnsRecord(key, null, -1L, false, t.message ?: t.toString())
                }
            }
        }.awaitAll()
    }
    return EnsProfile(n, records)
}

/** A decoded ENSIP-7 contenthash: the `scheme://…` URI wallets and gateways show. */
data class ContentLink(val scheme: String, val uri: String)

/**
 * Decode an ENSIP-7 contenthash (0x-prefixed multicodec bytes) into the URI it names:
 * `ipfs://` (ipfs-ns, 0xe3), `ipns://` (ipns-ns, 0xe5) and `bzz://` (swarm-ns, 0xe4). An
 * IPFS CIDv1 of dag-pb + sha2-256 is shown in its CIDv0 base58 form (`Qm…` — the form
 * ENSIP-7's own example and ethers show); any other CID as CIDv1 base32 (`b…`); an IPNS
 * name in base36 (`k…`), the canonical libp2p-key form — or, for the dag-pb CIDs older
 * encoders wrote under ipns-ns, the same `Qm…` form as IPFS; a Swarm reference as the hex
 * of its keccak-256 hash. Null for anything else — another codec, malformed bytes — and
 * the card then shows the raw hex.
 */
internal fun decodeContenthash(hex: String): ContentLink? {
    val bytes = hexBytes(hex) ?: return null
    val code = readVarint(bytes, 0) ?: return null
    val payload = bytes.copyOfRange(code.next, bytes.size)
    return when (code.value) {
        0xe3L -> cidString(payload)?.let { ContentLink("ipfs", "ipfs://$it") }
        0xe5L -> ipnsName(payload)?.let { ContentLink("ipns", "ipns://$it") }
        0xe4L -> swarmHash(payload)?.let { ContentLink("bzz", "bzz://$it") }
        else -> null
    }
}

/**
 * The eth.limo gateway page for a `.eth` name — a THIRD PARTY that resolves the name
 * itself and serves its content over HTTPS, so opening it leaves the verified path. Null
 * for any other name, and for a `.eth` name that is not a plain hostname: labels are
 * registered by hash, so a resolvable name can carry `/`, `?`, `#` or anything else, and
 * `https://evil.com/x.eth.limo/` would open `evil.com` under a button that says eth.limo.
 * Only `[a-z0-9.-]` names get the offer; the decoded link with Copy serves the rest.
 */
internal fun ensGatewayUrl(name: String): String? {
    val n = name.trim().lowercase()
    if (!n.endsWith(".eth") || n.length <= 4) return null
    if (!n.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' }) return null
    return "https://$n.limo/"
}

private class Cid(val version: Long, val codec: Long, val multihash: ByteArray, val bytes: ByteArray)

private fun isSha256Multihash(mh: ByteArray) =
    mh.size == 34 && mh[0] == 0x12.toByte() && mh[1] == 0x20.toByte()

private fun parseCid(b: ByteArray): Cid? {
    if (isSha256Multihash(b)) return Cid(0, 0x70, b, b)  // CIDv0: a bare sha2-256 multihash
    val version = readVarint(b, 0) ?: return null
    if (version.value != 1L) return null
    val codec = readVarint(b, version.next) ?: return null
    val mh = b.copyOfRange(codec.next, b.size)
    val code = readVarint(mh, 0) ?: return null
    val len = readVarint(mh, code.next) ?: return null
    if (len.next + len.value != mh.size.toLong()) return null
    return Cid(1, codec.value, mh, b)
}

private fun cidString(b: ByteArray): String? {
    val cid = parseCid(b) ?: return null
    return if (cid.codec == 0x70L && isSha256Multihash(cid.multihash)) baseN(cid.multihash, BASE58)
    else "b" + base32(cid.bytes)
}

private fun ipnsName(b: ByteArray): String? {
    val cid = parseCid(b) ?: return null
    // libp2p-key is the canonical IPNS CID; a dag-pb CID (or bare CIDv0) under ipns-ns
    // is what @ensdomains/content-hash before 2.5 and manual encoders wrote, and gateways
    // still accept it as ipns://Qm….
    return if (cid.version == 1L && cid.codec == 0x72L) "k" + baseN(cid.bytes, BASE36) else cidString(b)
}

private fun swarmHash(b: ByteArray): String? {
    // CIDv1, codec swarm-manifest (0xfa), multihash keccak-256 (0x1b) of 32 bytes.
    val version = readVarint(b, 0) ?: return null
    if (version.value != 1L) return null
    val codec = readVarint(b, version.next) ?: return null
    if (codec.value != 0xfaL) return null
    val mh = b.copyOfRange(codec.next, b.size)
    if (mh.size != 34 || mh[0] != 0x1b.toByte() || mh[1] != 0x20.toByte()) return null
    return hexOf(mh.copyOfRange(2, 34))
}

private class Varint(val value: Long, val next: Int)

/** Unsigned LEB128 at [at]; null when the bytes end mid-number or it exceeds 63 bits. */
private fun readVarint(b: ByteArray, at: Int): Varint? {
    var value = 0L
    var shift = 0
    var i = at
    while (i < b.size && shift < 63) {
        val x = b[i].toInt() and 0xff
        value = value or ((x and 0x7f).toLong() shl shift)
        i++
        if (x and 0x80 == 0) return Varint(value, i)
        shift += 7
    }
    return null
}

private const val BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
private const val BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
private const val BASE32 = "abcdefghijklmnopqrstuvwxyz234567"

/** The big-endian number in [input] in [alphabet]'s base, each leading zero byte as one
 *  leading `alphabet[0]` — the base58btc convention, which base36 CIDs share. */
private fun baseN(input: ByteArray, alphabet: String): String {
    val base = alphabet.length
    var zeros = 0
    while (zeros < input.size && input[zeros] == 0.toByte()) zeros++
    val digits = ArrayList<Int>()  // little-endian
    for (byte in input) {
        var carry = byte.toInt() and 0xff
        for (j in digits.indices) {
            val x = digits[j] * 256 + carry
            digits[j] = x % base
            carry = x / base
        }
        while (carry > 0) {
            digits += carry % base
            carry /= base
        }
    }
    val sb = StringBuilder(zeros + digits.size)
    repeat(zeros) { sb.append(alphabet[0]) }
    for (j in digits.indices.reversed()) sb.append(alphabet[digits[j]])
    return sb.toString()
}

/** RFC 4648 base32, lowercase, unpadded — the multibase `b` form of a CID. */
private fun base32(b: ByteArray): String {
    val sb = StringBuilder((b.size * 8 + 4) / 5)
    var buffer = 0
    var bits = 0
    for (x in b) {
        buffer = (buffer shl 8) or (x.toInt() and 0xff)
        bits += 8
        while (bits >= 5) {
            bits -= 5
            sb.append(BASE32[(buffer shr bits) and 0x1f])
        }
    }
    if (bits > 0) sb.append(BASE32[(buffer shl (5 - bits)) and 0x1f])
    return sb.toString()
}

private fun hexBytes(hex: String): ByteArray? {
    val h = hex.trim().removePrefix("0x").removePrefix("0X")
    if (h.isEmpty() || h.length % 2 != 0) return null
    val out = ByteArray(h.length / 2)
    for (i in out.indices) {
        val hi = h[2 * i].digitToIntOrNull(16) ?: return null
        val lo = h[2 * i + 1].digitToIntOrNull(16) ?: return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

private fun hexOf(b: ByteArray): String = buildString(b.size * 2) {
    for (x in b) {
        val v = x.toInt() and 0xff
        append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0xf])
    }
}
