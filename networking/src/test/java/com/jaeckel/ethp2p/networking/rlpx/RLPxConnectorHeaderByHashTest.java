package com.jaeckel.ethp2p.networking.rlpx;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jaeckel.ethp2p.networking.eth.messages.BlockHeadersMessage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * The execution-anchor resolver's peer rotation (Gloas: a light-client header proves only
 * the block hash, and any EL peer may serve the header behind it). The acceptor — the
 * anchor, which hashes the raw RLP itself — is the only verifier, so every kind of bad or
 * missing answer just hands the turn to the next peer.
 */
class RLPxConnectorHeaderByHashTest {

    private static final Bytes32 WANTED = Bytes32.repeat((byte) 0x11);
    private static final Bytes32 OTHER = Bytes32.repeat((byte) 0x22);
    private static final long TIMEOUT_MS = 200;

    private static BlockHeadersMessage.VerifiedHeader served(Bytes32 hash, int marker) {
        return new BlockHeadersMessage.VerifiedHeader(hash, null, Bytes.of(marker));
    }

    private static Supplier<CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>>> peer(
            AtomicInteger asked, BlockHeadersMessage.VerifiedHeader... headers) {
        return () -> {
            asked.incrementAndGet();
            return CompletableFuture.completedFuture(Arrays.asList(headers));
        };
    }

    @Test
    void theFirstAcceptedHeaderWinsAndLaterPeersAreNotAsked() {
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        List<byte[]> offered = new ArrayList<>();
        boolean ok = RLPxConnector.firstAcceptedHeader(WANTED,
                List.of(peer(a, served(WANTED, 1)), peer(b, served(WANTED, 2))), TIMEOUT_MS,
                raw -> offered.add(raw));
        assertTrue(ok);
        assertEquals(1, a.get());
        assertEquals(0, b.get(), "no second peer once a header is accepted");
        assertEquals(1, offered.size());
    }

    @Test
    void everyBadOrMissingAnswerRotatesToTheNextPeer() {
        AtomicInteger asked = new AtomicInteger();
        List<Supplier<CompletableFuture<List<BlockHeadersMessage.VerifiedHeader>>>> attempts = List.of(
                () -> null,                                            // peer gone: skipped
                () -> { asked.incrementAndGet(); return CompletableFuture.failedFuture(new RuntimeException("reset")); },
                () -> { asked.incrementAndGet(); return new CompletableFuture<>(); }, // never answers
                peer(asked),                                           // clean but empty
                peer(asked, served(OTHER, 3)),                         // another block's header
                peer(asked, served(WANTED, 4)),                        // claims the hash, acceptor refuses
                peer(asked, served(WANTED, 5)));                       // the genuine one
        List<Integer> offered = new ArrayList<>();
        boolean ok = RLPxConnector.firstAcceptedHeader(WANTED, attempts, TIMEOUT_MS, raw -> {
            offered.add((int) raw[0]);
            return raw[0] == 5; // the anchor adopts only the header whose keccak IS the hash
        });
        assertTrue(ok);
        assertEquals(List.of(4, 5), offered, "another block's header never reaches the acceptor");
        assertEquals(6, asked.get());
    }

    @Test
    void falseWhenNoPeerServesIt() {
        AtomicInteger asked = new AtomicInteger();
        assertFalse(RLPxConnector.firstAcceptedHeader(WANTED,
                List.of(peer(asked), peer(asked, served(OTHER, 1))), TIMEOUT_MS, raw -> true));
        assertEquals(2, asked.get());
        assertFalse(RLPxConnector.firstAcceptedHeader(WANTED, List.of(), TIMEOUT_MS, raw -> true));
    }
}
