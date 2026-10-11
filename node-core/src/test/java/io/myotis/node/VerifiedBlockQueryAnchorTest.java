package io.myotis.node;

import com.jaeckel.ethp2p.consensus.BeaconSyncState;
import com.jaeckel.ethp2p.core.types.BlockHeader;
import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage.VerifiedHeader;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@link VerifiedBlockQuery}'s anchor choice and window binding — the pure halves of its walk. */
class VerifiedBlockQueryAnchorTest {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final byte[] FIN_HASH = tag("fin").toArray();
    private static final byte[] OPT_HASH = tag("opt").toArray();
    private static final BeaconSyncState.FinalizedExecution FIN =
            new BeaconSyncState.FinalizedExecution(21_000_000, tag("fin-root").toArray(), FIN_HASH);
    private static final BeaconSyncState.OptimisticExecution OPT =
            new BeaconSyncState.OptimisticExecution(264, 21_000_064, OPT_HASH);

    @Test
    void aBlockAtOrBelowFinalityEndsItsWalkAtTheFinalizedBlock() {
        for (long block : new long[] {20_999_000, 21_000_000}) {
            VerifiedBlockQuery.BlockAnchor a = VerifiedBlockQuery.blockAnchor(block, FIN, 200, true, OPT);
            assertNotNull(a);
            assertEquals(21_000_000, a.blockNumber());
            assertArrayEquals(FIN_HASH, a.blockHash());
            assertEquals(200, a.slot());
            assertTrue(a.blsVerified());
        }
        // A finality the seed fallbacks set is reported as not BLS-verified.
        assertFalse(VerifiedBlockQuery.blockAnchor(20_999_000, FIN, 200, false, OPT).blsVerified());
    }

    @Test
    void aBlockAboveFinalityEndsItsWalkAtTheOptimisticHeadOrNowhere() {
        for (long block : new long[] {21_000_001, 21_000_064}) {
            VerifiedBlockQuery.BlockAnchor a = VerifiedBlockQuery.blockAnchor(block, FIN, 200, false, OPT);
            assertNotNull(a);
            assertEquals(21_000_064, a.blockNumber());
            assertArrayEquals(OPT_HASH, a.blockHash());
            assertEquals(264, a.slot());
            assertTrue(a.blsVerified(), "the optimistic head only ever comes from a signed update");
        }
        assertNull(VerifiedBlockQuery.blockAnchor(21_000_065, FIN, 200, true, OPT));
        assertNull(VerifiedBlockQuery.blockAnchor(21_000_001, FIN, 200, true,
                new BeaconSyncState.OptimisticExecution(0, 0, null)));
    }

    @Test
    void theWindowProvesOnlyItsOwnFirstHeader() {
        VerifiedHeader target = header(100, tag("r0"), tag("genesis"));
        VerifiedHeader mid = header(101, tag("r1"), target.hash());
        VerifiedHeader top = header(102, tag("r2"), mid.hash());
        byte[] topHash = top.hash().toArray();
        assertTrue(VerifiedBlockQuery.windowProves(List.of(target, mid, top), 3, topHash, target));
        // A reported header fetched separately, not the window's own first header.
        VerifiedHeader impostor = header(100, tag("r0"), tag("other-parent"));
        assertFalse(VerifiedBlockQuery.windowProves(List.of(target, mid, top), 3, topHash, impostor));
        // Short, not anchored, or not linked.
        assertFalse(VerifiedBlockQuery.windowProves(List.of(target, mid), 3, topHash, target));
        assertFalse(VerifiedBlockQuery.windowProves(List.of(target, mid, top), 3, FIN_HASH, target));
        // A made-up child of the attested block proves nothing.
        VerifiedHeader child = header(103, tag("any"), top.hash());
        assertFalse(VerifiedBlockQuery.windowProves(List.of(top, child), 2, topHash, top));
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
