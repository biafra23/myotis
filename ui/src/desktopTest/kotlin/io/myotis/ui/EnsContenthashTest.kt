package io.myotis.ui

import kotlinx.datetime.TimeZone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** ENSIP-7 contenthash decoding, against the spec's own examples and constructed vectors. */
class EnsContenthashTest {

    private val sha = "29f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f"

    @Test
    fun ipfsDagPbIsShownAsTheCidV0Base58Form() {
        // ENSIP-7's example: ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4
        val link = decodeContenthash("0xe30101701220$sha")
        assertEquals("ipfs", link?.scheme)
        assertEquals("ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4", link?.uri)
    }

    @Test
    fun ipfsWithAnotherCodecIsShownAsCidV1Base32() {
        // raw (0x55) instead of dag-pb: no CIDv0 form exists, so the multibase b… form.
        val link = decodeContenthash("0xe30101551220$sha")
        assertEquals("ipfs://bafkreibj6lixxzqtsb45ysdjnupvqkufgdvzqbnvmhw2kf7cfkesy7r7d4", link?.uri)
    }

    @Test
    fun ipnsIsShownAsTheBase36LibP2pKeyName() {
        // libp2p-key (0x72) CID over an identity-encoded key (the shape ENS tooling writes).
        val link = decodeContenthash("0xe5010172002408011220$sha")
        assertEquals("ipns", link?.scheme)
        assertEquals("ipns://k51qzi5uqu5dh887mvidx1r2ltrmvd6mbis4tgnni81yy5frxmgnrlez8866n3", link?.uri)
    }

    @Test
    fun ipnsWrittenAsADagPbCidIsShownLikeIpfs() {
        // What @ensdomains/content-hash before 2.5 wrote under ipns-ns; gateways accept it.
        assertEquals("ipns://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4", decodeContenthash("0xe50101701220$sha")?.uri)
    }

    @Test
    fun aBareCidV0MultihashUnderIpfsIsAccepted() {
        assertEquals("ipfs://QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4", decodeContenthash("0xe3011220$sha")?.uri)
    }

    @Test
    fun swarmIsShownAsTheHexHash() {
        // ENSIP-7's example.
        val hash = "d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162"
        val link = decodeContenthash("0xe40101fa011b20$hash")
        assertEquals("bzz", link?.scheme)
        assertEquals("bzz://$hash", link?.uri)
    }

    @Test
    fun otherCodecsAndMalformedBytesDecodeToNothing() {
        assertNull(decodeContenthash("0x90b2ca05" + "00".repeat(8)))   // arweave-ns: not decoded here
        assertNull(decodeContenthash("0xe301"))                           // truncated CID
        assertNull(decodeContenthash("0xe30101701220" + sha.dropLast(2))) // multihash short by a byte
        assertNull(decodeContenthash("0xe4010170122012"))                 // swarm with the wrong codec
        assertNull(decodeContenthash("0x"))
        assertNull(decodeContenthash("not hex"))
    }

    @Test
    fun theExpiryLineSaysWhatATermMeansNow() {
        val tz = TimeZone.UTC
        val expires = 1_823_155_031L  // 2027-10-10 07:57 UTC
        assertEquals("Expires 2027-10-10 07:57 (in 365 days)", ensExpiryLine(expires, 7_776_000, expires - 365 * 86_400 - 10, tz))
        assertEquals("Expires 2027-10-10 07:57 (today)", ensExpiryLine(expires, 7_776_000, expires - 3_600, tz))
        // Calendar days, not 86 400-second buckets: 07:57 tomorrow seen at 23:50 tonight.
        assertEquals("Expires 2027-10-10 07:57 (tomorrow)", ensExpiryLine(expires, 7_776_000, expires - 8 * 3_600 - 7 * 60, tz))
        assertEquals("Expires 2027-10-10 07:57 (in 2 days)", ensExpiryLine(expires, 7_776_000, expires - 32 * 3_600, tz))
        assertEquals(
            "Expired 2027-10-10 07:57 — in the grace period until 2028-01-08 07:57; only the registrant can renew",
            ensExpiryLine(expires, 7_776_000, expires + 86_400, tz),
        )
        assertEquals(
            "Expired 2027-10-10 07:57 — past the grace period; free to register",
            ensExpiryLine(expires, 7_776_000, expires + 7_776_000 + 1, tz),
        )
        assertEquals("", ensExpiryLine(-1, -1, expires, tz))
    }

    @Test
    fun theGatewayIsOfferedForDotEthNamesOnly() {
        assertEquals("https://vitalik.eth.limo/", ensGatewayUrl("Vitalik.eth "))
        assertEquals("https://sub.myotis.eth.limo/", ensGatewayUrl("sub.myotis.eth"))
        assertNull(ensGatewayUrl("example.com"))
        assertNull(ensGatewayUrl(".eth"))
        // A .eth label can hold anything (registered by hash): a name that is not a plain
        // hostname gets no gateway button, or its host would not be eth.limo.
        assertNull(ensGatewayUrl("evil.com/x.eth"))
        assertNull(ensGatewayUrl("a?b.eth"))
        assertNull(ensGatewayUrl("a#b.eth"))
        assertNull(ensGatewayUrl("ümlaut.eth"))
        assertEquals("https://my-name2.eth.limo/", ensGatewayUrl("my-name2.eth"))
    }
}
