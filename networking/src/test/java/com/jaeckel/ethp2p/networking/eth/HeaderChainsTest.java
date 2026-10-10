package com.jaeckel.ethp2p.networking.eth;

import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage.VerifiedHeader;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderChainsTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Test
    void aWindowHashLinkedUpToTheAttestedHashAnchors() {
        VerifiedHeader h0 = header(100, tag("r0"), tag("genesis"));
        VerifiedHeader h1 = header(101, tag("r1"), h0.hash());
        VerifiedHeader h2 = header(102, tag("r2"), h1.hash());
        assertTrue(HeaderChains.anchoredAtTop(List.of(h0, h1, h2), h2.hash().toArray()));
        // A one-header window is the attested block itself.
        assertTrue(HeaderChains.anchoredAtTop(List.of(h2), h2.hash().toArray()));
    }

    @Test
    void aMadeUpChildOfTheAttestedBlockDoesNotAnchor() {
        // The attack the old upward walks let through: a header naming the attested block
        // as its parent links fine, but nothing attested pins IT — anchored at the top,
        // it would have to hash to the attested block.
        VerifiedHeader attested = header(100, tag("r0"), tag("genesis"));
        VerifiedHeader madeUp = header(101, tag("any-root"), attested.hash());
        assertFalse(HeaderChains.anchoredAtTop(List.of(attested, madeUp), attested.hash().toArray()));
    }

    @Test
    void aBrokenLinkOrAWrongTopOrNoWindowDoesNotAnchor() {
        VerifiedHeader h0 = header(100, tag("r0"), tag("genesis"));
        VerifiedHeader h1 = header(101, tag("r1"), tag("not-h0"));
        assertFalse(HeaderChains.anchoredAtTop(List.of(h0, h1), h1.hash().toArray()));
        VerifiedHeader linked = header(101, tag("r1"), h0.hash());
        assertFalse(HeaderChains.anchoredAtTop(List.of(h0, linked), tag("other").toArray()));
        assertFalse(HeaderChains.anchoredAtTop(List.of(), linked.hash().toArray()));
        assertFalse(HeaderChains.anchoredAtTop(List.of(h0, linked), null));
    }

    private static Bytes32 tag(String s) {
        return Bytes32.wrap(org.apache.tuweni.crypto.Hash.keccak256(
                Bytes.wrap(s.getBytes(StandardCharsets.UTF_8))));
    }

    /** A minimal post-London header with the given number, state root and parent hash. */
    private static VerifiedHeader header(long number, Bytes32 stateRoot, Bytes32 parentHash) {
        Bytes rlp = RLP.encodeList(w -> {
            w.writeValue(parentHash);
            w.writeValue(Bytes32.fromHexString(
                    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"));
            w.writeValue(Bytes.wrap(new byte[20]));
            w.writeValue(stateRoot);
            w.writeValue(tag("txroot"));
            w.writeValue(tag("rcpt"));
            w.writeValue(Bytes.wrap(new byte[256]));
            w.writeBigInteger(BigInteger.ZERO);
            w.writeLong(number);
            w.writeLong(30_000_000L);
            w.writeLong(0L);
            w.writeLong(1_700_000_000L + number);
            w.writeValue(Bytes.EMPTY);
            w.writeValue(tag("mix"));
            w.writeValue(Bytes.wrap(new byte[8]));
            w.writeBigInteger(BigInteger.valueOf(1_000_000_000L)); // baseFee
        });
        return new VerifiedHeader(BlockHeader.hash(rlp), BlockHeader.decode(rlp), rlp);
    }
}
