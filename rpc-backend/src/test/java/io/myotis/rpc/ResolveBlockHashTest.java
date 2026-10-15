package io.myotis.rpc;

import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage.VerifiedHeader;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The pure halves of {@link VerifiedRpcBackend#resolveBlockHash} (#641). */
class ResolveBlockHashTest {

    static {
        io.myotis.evm.CryptoProviders.ensureRegistered();
    }

    @Test
    void aHashInAWindowAnchoredAtTheHeadIsPlacedAsItsBlocksNumber() {
        VerifiedHeader a = header(98, tag("genesis"));
        VerifiedHeader b = header(99, a.hash());
        VerifiedHeader top = header(100, b.hash());
        List<VerifiedHeader> window = List.of(a, b, top);
        byte[] anchor = top.hash().toArray();
        // The golden shape the Rust resolved_block_json twin pins: a block object's own
        // "hash" and "number" fields.
        assertEquals("{\"hash\":\"" + b.hash().toHexString() + "\",\"number\":\"0x63\"}",
                VerifiedRpcBackend.resolvedFromWindow(window, anchor, b.hash().toArray()));
        assertEquals("{\"hash\":\"" + top.hash().toHexString() + "\",\"number\":\"0x64\"}",
                VerifiedRpcBackend.resolvedFromWindow(window, anchor, top.hash().toArray()));
        // A hash no header in the proven window carries: verified "not placed".
        assertEquals("null", VerifiedRpcBackend.resolvedFromWindow(window, anchor, tag("fork").toArray()));
    }

    @Test
    void aWindowThatDoesNotAnchorPlacesNothing() {
        VerifiedHeader a = header(98, tag("genesis"));
        VerifiedHeader b = header(99, a.hash());
        VerifiedHeader top = header(100, b.hash());
        // Another top than the anchor, or a window that is not hash-linked: nothing
        // in it is proven, so no verdict at all — not even "null".
        assertNull(VerifiedRpcBackend.resolvedFromWindow(
                List.of(a, b, top), tag("other").toArray(), b.hash().toArray()));
        VerifiedHeader stranger = header(99, tag("elsewhere"));
        assertNull(VerifiedRpcBackend.resolvedFromWindow(
                List.of(a, stranger, top), top.hash().toArray(), a.hash().toArray()));
    }

    @Test
    void theScanReachesDownToAKnownNumberWithinTheLookback() {
        assertEquals(936, VerifiedRpcBackend.hashScanStart(1_000, null));
        // Inside the 64-block span already: the span is the window.
        assertEquals(936, VerifiedRpcBackend.hashScanStart(1_000, 990L));
        // Deeper, but within the 512-block lookback: down to it.
        assertEquals(600, VerifiedRpcBackend.hashScanStart(1_000, 600L));
        // Past the lookback: the span alone.
        assertEquals(936, VerifiedRpcBackend.hashScanStart(1_000, 400L));
        // Near genesis the span stops at block 0.
        assertEquals(0, VerifiedRpcBackend.hashScanStart(10, null));
    }

    private static Bytes32 tag(String s) {
        return Bytes32.wrap(org.apache.tuweni.crypto.Hash.keccak256(
                Bytes.wrap(s.getBytes(StandardCharsets.UTF_8))));
    }

    private static VerifiedHeader header(long number, Bytes32 parentHash) {
        Bytes rlp = RLP.encodeList(w -> {
            w.writeValue(parentHash);
            w.writeValue(Bytes32.fromHexString(
                    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"));
            w.writeValue(Bytes.wrap(new byte[20]));
            w.writeValue(tag("state-" + number));
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
            w.writeBigInteger(BigInteger.valueOf(1_000_000_000L));
        });
        return new VerifiedHeader(BlockHeader.hash(rlp), BlockHeader.decode(rlp), rlp);
    }
}
