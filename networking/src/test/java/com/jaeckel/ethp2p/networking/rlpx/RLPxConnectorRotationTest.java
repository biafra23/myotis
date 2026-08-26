package com.jaeckel.ethp2p.networking.rlpx;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * The bodies/receipts rotation policy (#359). Previously the first ready peer's
 * empty reply was terminal — ~1-in-3 on mainnet. These pin the rotation:
 * a complete reply wins, an empty/short one rotates to the next peer, and the
 * distinction between "no peer served it" (empty list, caller falls back) and
 * "couldn't reach a peer" (error) is preserved.
 */
class RLPxConnectorRotationTest {

    private static final long TIMEOUT_MS = 200;

    private static Supplier<CompletableFuture<List<Integer>>> serves(int n, AtomicInteger calls) {
        return () -> {
            calls.incrementAndGet();
            List<Integer> out = new ArrayList<>();
            for (int i = 0; i < n; i++) out.add(i);
            return CompletableFuture.completedFuture(out);
        };
    }

    private static Supplier<CompletableFuture<List<Integer>>> empty(AtomicInteger calls) {
        return serves(0, calls);
    }

    private static Supplier<CompletableFuture<List<Integer>>> errors(AtomicInteger calls, String msg) {
        return () -> {
            calls.incrementAndGet();
            return CompletableFuture.failedFuture(new RuntimeException(msg));
        };
    }

    private static <T> List<T> join(CompletableFuture<List<T>> f) throws Exception {
        return f.get(2, TimeUnit.SECONDS);
    }

    @Test
    void firstCompleteReplyWins_andLaterPeersAreNotTried() throws Exception {
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 1, List.of(serves(1, a), serves(1, b)), TIMEOUT_MS);
        assertEquals(1, join(out).size());
        assertEquals(1, a.get(), "first peer answered");
        assertEquals(0, b.get(), "second peer must not be tried after a complete reply");
    }

    @Test
    void anEmptyReplyRotatesToTheNextPeer() throws Exception {
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 1, List.of(empty(a), serves(1, b)), TIMEOUT_MS);
        assertEquals(1, join(out).size(), "the second, non-empty peer's reply is returned");
        assertEquals(1, a.get());
        assertEquals(1, b.get());
    }

    @Test
    void anExceptionRotatesToTheNextPeer() throws Exception {
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 1, List.of(errors(a, "disconnected"), serves(1, b)), TIMEOUT_MS);
        assertEquals(1, join(out).size());
        assertEquals(1, a.get());
        assertEquals(1, b.get());
    }

    @Test
    void allEmpty_yieldsAnEmptyList_soTheCallerFallbackFires() throws Exception {
        // The key #359 semantic: after trying every peer, an all-empty outcome is an
        // empty list (not an error), so serveStaleBlock / the "null" path still runs —
        // only now after genuine rotation instead of one peer.
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger(), c = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 1, List.of(empty(a), empty(b), empty(c)), TIMEOUT_MS);
        assertTrue(join(out).isEmpty());
        assertEquals(1, a.get());
        assertEquals(1, b.get());
        assertEquals(1, c.get());
    }

    @Test
    void allExceptions_failWithTheLastError_notAMaskedEmptyList() {
        // Pure transport failure (no clean reply) must surface as an error → the
        // caller's -32000, not a masked "not found".
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 1, List.of(errors(a, "e1"), errors(b, "last")), TIMEOUT_MS);
        ExecutionException ex = assertThrows(ExecutionException.class, () -> join(out));
        assertTrue(ex.getCause().getMessage().contains("last"));
        assertEquals(1, a.get());
        assertEquals(1, b.get());
    }

    @Test
    void aCleanEmptyAmongErrors_stillYieldsEmptyList() throws Exception {
        // If any peer definitively (cleanly) said "I don't have it", treat the
        // aggregate as not-served (empty), not a transport error.
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 1, List.of(empty(a), errors(b, "boom")), TIMEOUT_MS);
        assertTrue(join(out).isEmpty());
    }

    @Test
    void aNullFutureIsSkippedWithoutCounting() throws Exception {
        // A peer that dropped between snapshot and invocation returns null: skip it,
        // don't let it fail the call.
        AtomicInteger b = new AtomicInteger();
        Supplier<CompletableFuture<List<Integer>>> gone = () -> null;
        var out = RLPxConnector.rotate("bodies", 1, List.of(gone, serves(1, b)), TIMEOUT_MS);
        assertEquals(1, join(out).size());
        assertEquals(1, b.get());
    }

    @Test
    void aHangingPeerIsTimedOutAndRotated() throws Exception {
        // A silent peer (never-completing future) must not hold the whole call: the
        // per-attempt timeout fires and rotation continues.
        AtomicInteger b = new AtomicInteger();
        Supplier<CompletableFuture<List<Integer>>> silent = CompletableFuture::new; // never completes
        long t0 = System.nanoTime();
        var out = RLPxConnector.rotate("bodies", 1, List.of(silent, serves(1, b)), TIMEOUT_MS);
        assertEquals(1, join(out).size());
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(elapsedMs >= TIMEOUT_MS, "must wait out the per-attempt timeout before rotating");
        // No tight upper bound: the shared Delayer thread can fire late under CI load,
        // and the point is only that it DID rotate (b served) rather than hanging.
        assertEquals(1, b.get());
    }

    @Test
    void aShortMultiHashReplyRotates() throws Exception {
        // expected=2: a peer returning only 1 is incomplete → rotate for the full set.
        AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
        var out = RLPxConnector.rotate("bodies", 2, List.of(serves(1, a), serves(2, b)), TIMEOUT_MS);
        assertEquals(2, join(out).size());
        assertEquals(1, a.get());
        assertEquals(1, b.get());
    }

    @Test
    void noAttempts_failsRatherThanReturningEmpty() {
        var out = RLPxConnector.rotate("bodies", 1, List.of(), TIMEOUT_MS);
        ExecutionException ex = assertThrows(ExecutionException.class, () -> join(out));
        assertInstanceOf(IllegalStateException.class, ex.getCause());
    }
}
