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

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/** {@link VerifiedRpcBackend#provenHead}: the pure half of proving a head context. */
class ProvenHeadTest {

    static {
        io.myotis.evm.CryptoProviders.ensureRegistered();
    }

    @Test
    void aHeadHashLinkedUpToTheOptimisticHashIsProven() {
        VerifiedHeader head = header(100, tag("head-root"), tag("genesis"));
        VerifiedHeader top = header(101, tag("top-root"), head.hash());
        assertSame(head, VerifiedRpcBackend.provenHead(
                List.of(head, top), 2, top.hash().toArray(), tag("head-root").toArray()));
        // The head IS the optimistic head: a one-header window.
        assertSame(top, VerifiedRpcBackend.provenHead(
                List.of(top), 1, top.hash().toArray(), tag("top-root").toArray()));
    }

    @Test
    void aMadeUpChildAWrongRootOrAShortWindowIsNot() {
        VerifiedHeader head = header(100, tag("head-root"), tag("genesis"));
        VerifiedHeader top = header(101, tag("top-root"), head.hash());
        byte[] topHash = top.hash().toArray();
        // The probed root is not the canonical block's.
        assertNull(VerifiedRpcBackend.provenHead(List.of(head, top), 2, topHash, tag("other").toArray()));
        // Short window.
        assertNull(VerifiedRpcBackend.provenHead(List.of(head), 2, topHash, tag("head-root").toArray()));
        // A header naming the attested block as its parent is not pinned by it.
        VerifiedHeader child = header(102, tag("any-root"), top.hash());
        assertNull(VerifiedRpcBackend.provenHead(List.of(top, child), 2, topHash, tag("top-root").toArray()));
    }

    private static Bytes32 tag(String s) {
        return Bytes32.wrap(org.apache.tuweni.crypto.Hash.keccak256(
                Bytes.wrap(s.getBytes(StandardCharsets.UTF_8))));
    }

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
            w.writeBigInteger(BigInteger.valueOf(1_000_000_000L));
        });
        return new VerifiedHeader(BlockHeader.hash(rlp), BlockHeader.decode(rlp), rlp);
    }
}
