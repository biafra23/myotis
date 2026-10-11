package io.myotis.rpc;

import com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Java engine's pre-broadcast check (#531). The verdict and freshness cases are the
 * Rust twin's ({@code el/send_check.rs} tests, the reader's {@code judge_read} tests),
 * with the same numbers and the same words; the funds-at-the-optimistic-head rule and the
 * {@link SendCheck.Checker} cases are this engine's own.
 */
class SendCheckTest {

    private static final long SLOT = 12;
    private static final long HEAD_TIME = 1_700_000_000L;
    private static final BigInteger RICH = BigInteger.TWO.pow(256).subtract(BigInteger.ONE);

    /** A decoded type-{@code ty} transaction: chain 1, nonce 5, 21 000 gas at 10 wei,
     *  value 1 000 — a maximum cost of 211 000. */
    private static EthTxDecoder.DecodedTx tx(int ty) {
        boolean legacyFee = ty < 2;
        return new EthTxDecoder.DecodedTx(ty, 1L, 5,
                legacyFee ? BigInteger.TEN : null,
                legacyFee ? null : BigInteger.ONE,
                legacyFee ? null : BigInteger.TEN,
                21_000, Bytes.repeat((byte) 0x22, 20), BigInteger.valueOf(1_000), Bytes.EMPTY,
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, Bytes.repeat((byte) 0x11, 20));
    }

    /** Block 100 at {@link #HEAD_TIME}, anchored, the optimistic head, adopted at
     *  monotonic {@code adoptedAtMs}. */
    private static SendCheck.Head head(long adoptedAtMs) {
        return new SendCheck.Head(100, true, true, HEAD_TIME, adoptedAtMs);
    }

    @Test
    void theCostIsValuePlusGasAtTheHighestFee() {
        for (int ty : new int[] {0, 1, 2, 4}) {
            assertEquals(BigInteger.valueOf(211_000), SendCheck.maxCost(tx(ty)), "type " + ty);
        }
        // A blob transaction also pays a blob fee the decode does not carry.
        assertNull(SendCheck.maxCost(tx(3)));
    }

    @Test
    void aBalanceOneWeiShortOfTheCostIsInsufficientFunds() {
        for (int ty : new int[] {0, 2, 4}) {
            assertEquals("insufficient funds for gas * price + value: balance 210999, tx cost 211000, overshot 1",
                    SendCheck.verdict(tx(ty), BigInteger.valueOf(210_999), 5), "type " + ty);
            assertNull(SendCheck.verdict(tx(ty), BigInteger.valueOf(211_000), 5), "type " + ty + ": exactly the cost");
            assertNull(SendCheck.verdict(tx(ty), BigInteger.valueOf(211_001), 5), "type " + ty);
        }
    }

    @Test
    void aUsedNonceIsTooLowAndAGapIsNotAnError() {
        assertEquals("nonce too low: next nonce 6, tx nonce 5", SendCheck.verdict(tx(2), RICH, 6));
        // The account's next nonce: a new transaction, or a replacement.
        assertNull(SendCheck.verdict(tx(2), RICH, 5));
        // A gap: geth queues it, and wallets send several in a row.
        assertNull(SendCheck.verdict(tx(2), RICH, 2));
        // geth's order: the nonce, then the balance.
        assertTrue(SendCheck.verdict(tx(2), BigInteger.ZERO, 9).startsWith("nonce too low"));
        // Nonces are unsigned 64-bit: 2^63 is not "below" the account's 5, and an account
        // at 2^64 - 1 names itself so.
        EthTxDecoder.DecodedTx t = tx(2);
        EthTxDecoder.DecodedTx high = new EthTxDecoder.DecodedTx(2, 1L, Long.MIN_VALUE, null,
                t.maxPriorityFeePerGas(), t.maxFeePerGas(), t.gas(), t.to(), t.value(), t.input(), t.v(), t.r(),
                t.s(), t.from());
        assertNull(SendCheck.verdict(high, RICH, 5));
        assertEquals("nonce too low: next nonce 18446744073709551615, tx nonce 5", SendCheck.verdict(t, RICH, -1L));
    }

    @Test
    void aBlobTransactionIsJudgedByItsNonceOnly() {
        assertNotNull(SendCheck.verdict(tx(3), BigInteger.ZERO, 9));
        assertNull(SendCheck.verdict(tx(3), BigInteger.ZERO, 5), "its cost is unknown, so its funds are not judged");
    }

    @Test
    void aHeadIsFreshForTwoBlockTimesAndTheGrace() {
        long just = 1_000;
        // A light client's head is normally one to two blocks old.
        assertTrue(SendCheck.headIsFresh(HEAD_TIME + 12, HEAD_TIME, just, SLOT));
        assertTrue(SendCheck.headIsFresh(HEAD_TIME + 30, HEAD_TIME, just, SLOT), "2 x 12 s + 6 s");
        assertFalse(SendCheck.headIsFresh(HEAD_TIME + 31, HEAD_TIME, just, SLOT));
        // Gnosis: 5 s blocks.
        assertTrue(SendCheck.headIsFresh(HEAD_TIME + 16, HEAD_TIME, just, 5));
        assertFalse(SendCheck.headIsFresh(HEAD_TIME + 17, HEAD_TIME, just, 5));
        // A clock behind the chain's.
        assertTrue(SendCheck.headIsFresh(HEAD_TIME - 3, HEAD_TIME, just, SLOT));
    }

    @Test
    void aWrongWallClockCannotPassAStalledHeadAsFresh() {
        // The wall clock says the head is 10 s old, but this node saw it advance a
        // minute ago and has seen no newer one: its light client stalled.
        assertFalse(SendCheck.headIsFresh(HEAD_TIME + 10, HEAD_TIME, 60_000L, SLOT));
        assertTrue(SendCheck.headIsFresh(HEAD_TIME + 10, HEAD_TIME, 30_000L, SLOT));
        // Never seen to advance (the first head after a start): not fresh, whatever
        // the wall clock says.
        assertFalse(SendCheck.headIsFresh(HEAD_TIME + 10, HEAD_TIME, null, SLOT));
    }

    @Test
    void aSendIsJudgedOnlyAtAFreshAnchoredHeadOnItsOwnChain() {
        long now = HEAD_TIME + 20;
        long nowMs = 10_000;
        assertNull(SendCheck.unjudgedWhy(tx(2), 1, head(5_000), now, nowMs, SLOT));
        assertEquals("head not fresh", SendCheck.unjudgedWhy(tx(2), 1, head(5_000), HEAD_TIME + 60, nowMs, SLOT));
        assertEquals("head not fresh", SendCheck.unjudgedWhy(tx(2), 1, head(5_000), now, 60_000, SLOT));
        assertEquals("head not fresh", SendCheck.unjudgedWhy(tx(2), 1,
                new SendCheck.Head(100, true, true, HEAD_TIME, null), now, nowMs, SLOT));
        assertEquals("no verified head yet", SendCheck.unjudgedWhy(tx(2), 1, null, now, nowMs, SLOT));
        assertEquals("head not beacon-anchored", SendCheck.unjudgedWhy(tx(2), 1,
                new SendCheck.Head(100, false, false, HEAD_TIME, 5_000L), now, nowMs, SLOT));
        // Signed for Sepolia, posted to mainnet: this chain's state says nothing about it.
        assertEquals("another chain's transaction",
                SendCheck.unjudgedWhy(tx(2), 11_155_111, head(5_000), now, nowMs, SLOT));
        // A pre-EIP-155 legacy transaction names no chain: judged here.
        EthTxDecoder.DecodedTx t = tx(0);
        EthTxDecoder.DecodedTx unprotected = new EthTxDecoder.DecodedTx(0, null, t.nonce(), t.gasPrice(), null,
                null, t.gas(), t.to(), t.value(), t.input(), BigInteger.valueOf(27), t.r(), t.s(), t.from());
        assertNull(SendCheck.unjudgedWhy(unprotected, 100, head(5_000), now, nowMs, SLOT));
    }

    @Test
    void onlyAnAccountReadAtTheFreshHeadJudgesTheSend() {
        long now = HEAD_TIME + 20;
        long nowMs = 10_000;
        SendCheck.Head h = head(5_000);
        assertEquals(SendCheck.PreBroadcast.doomed(
                        "insufficient funds for gas * price + value: balance 210999, tx cost 211000, overshot 1"),
                SendCheck.judgeRead(tx(2), h, SendCheck.AccountRead.of(BigInteger.valueOf(210_999), 5), now, nowMs,
                        SLOT));
        assertEquals(SendCheck.PreBroadcast.passed(), SendCheck.judgeRead(tx(2), h,
                SendCheck.AccountRead.of(BigInteger.valueOf(211_000), 5), now, nowMs, SLOT));
        assertEquals(SendCheck.PreBroadcast.doomed("nonce too low: next nonce 6, tx nonce 5"),
                SendCheck.judgeRead(tx(2), h, SendCheck.AccountRead.of(BigInteger.valueOf(211_000), 6), now, nowMs,
                        SLOT));
        assertEquals(SendCheck.PreBroadcast.unchecked("account read failed"),
                SendCheck.judgeRead(tx(2), h, SendCheck.AccountRead.failure(), now, nowMs, SLOT));
        assertEquals(SendCheck.PreBroadcast.unchecked("account read timed out"),
                SendCheck.judgeRead(tx(2), h, null, now, nowMs, SLOT));
        // The bound holds at the verdict, not only before the read: each of these would
        // refuse at a head still fresh.
        SendCheck.AccountRead broke = SendCheck.AccountRead.of(BigInteger.ZERO, 5);
        assertEquals(SendCheck.PreBroadcast.unchecked("head went stale during the read"),
                SendCheck.judgeRead(tx(2), h, broke, HEAD_TIME + 31, nowMs, SLOT));
        assertEquals(SendCheck.PreBroadcast.unchecked("head went stale during the read"),
                SendCheck.judgeRead(tx(2), h, broke, now, 5_000 + 31_000, SLOT));
    }

    @Test
    void fundsAreJudgedOnlyAtTheOptimisticHeadAndAUsedNonceAtAnyFreshOne() {
        // One block below the attested head, a sender funded in the newest block —
        // whose receipt this node serves — would be refused: funds are not judged there.
        // A used nonce is: an older head can only under-report it.
        long now = HEAD_TIME + 20;
        SendCheck.Head below = new SendCheck.Head(100, true, false, HEAD_TIME, 5_000L);
        assertEquals(SendCheck.PreBroadcast.passed(),
                SendCheck.judgeRead(tx(2), below, SendCheck.AccountRead.of(BigInteger.ZERO, 5), now, 10_000, SLOT));
        assertEquals(SendCheck.PreBroadcast.doomed("nonce too low: next nonce 6, tx nonce 5"),
                SendCheck.judgeRead(tx(2), below, SendCheck.AccountRead.of(BigInteger.ZERO, 6), now, 10_000, SLOT));
    }

    @Test
    void aHeadIsAdoptedWhenItAdvancesNotWhenItIsRebuilt() {
        SendCheck.HeadAdvance advance = new SendCheck.HeadAdvance();
        assertNull(advance.adoptedAtMs(100), "nothing seen yet");
        // The first head after a start was never seen advancing.
        advance.note(100, 1_000);
        assertNull(advance.adoptedAtMs(100));
        // It advances: adopted then, and a rebuild of the same block keeps that time.
        advance.note(101, 5_000);
        assertEquals(5_000L, advance.adoptedAtMs(101));
        advance.note(101, 9_000);
        assertEquals(5_000L, advance.adoptedAtMs(101));
        // A lower head rebuilt below it is not the head seen advancing.
        advance.note(99, 11_000);
        assertNull(advance.adoptedAtMs(99));
        assertEquals(5_000L, advance.adoptedAtMs(101));
        // The monotonic clock's epoch is arbitrary: a negative reading is a time too.
        SendCheck.HeadAdvance negative = new SendCheck.HeadAdvance();
        negative.note(7, -9_000);
        negative.note(8, -5_000);
        assertEquals(-5_000L, negative.adoptedAtMs(8));
    }

    // ---- SendCheck.Checker: the orchestration, over a fake read and fake clocks ----

    private final AtomicLong wallSec = new AtomicLong(HEAD_TIME + 20);
    private final AtomicLong monoMs = new AtomicLong(10_000);

    private SendCheck.Checker checker(int maxReads, long budgetMs) {
        return new SendCheck.Checker(maxReads, budgetMs, wallSec::get, monoMs::get);
    }

    @Test
    void theCheckerJudgesARead() {
        SendCheck.Checker c = checker(4, 1_000);
        assertEquals(SendCheck.PreBroadcast.doomed("nonce too low: next nonce 6, tx nonce 5"),
                c.check(tx(2), 1, SLOT, head(5_000), () -> CompletableFuture.completedFuture(
                        SendCheck.AccountRead.of(RICH, 6))));
        assertEquals(SendCheck.PreBroadcast.passed(), c.check(tx(2), 1, SLOT, head(5_000),
                () -> CompletableFuture.completedFuture(SendCheck.AccountRead.of(RICH, 5))));
        assertEquals(4, c.freeReads(), "a finished read frees its permit");
        // Not judged: no read is made.
        assertEquals(SendCheck.PreBroadcast.unchecked("no verified head yet"), c.check(tx(2), 1, SLOT, null,
                () -> { throw new AssertionError("no read without a head"); }));
    }

    @Test
    void aSlowReadIsJudgedByTheAdoptionTakenBeforeIt() {
        // The Head, adoption time included, is taken once before the read
        // (VerifiedRpcBackend.sendCheckHead); the verdict measures its age at the clock
        // after the read, so time spent reading counts, but nothing re-reads the adoption.
        SendCheck.Checker c = checker(4, 1_000);
        SendCheck.Head h = head(5_000);
        assertEquals(SendCheck.PreBroadcast.doomed("nonce too low: next nonce 6, tx nonce 5"),
                c.check(tx(2), 1, SLOT, h, () -> {
                    monoMs.addAndGet(800); // a slow read
                    return CompletableFuture.completedFuture(SendCheck.AccountRead.of(RICH, 6));
                }));
    }

    @Test
    void aSlowReadIsNotWaitedOnPastTheBudgetAndKeepsItsPermitUntilItEnds() {
        SendCheck.Checker c = checker(1, 50);
        CompletableFuture<SendCheck.AccountRead> slow = new CompletableFuture<>();
        assertEquals(SendCheck.PreBroadcast.unchecked("account read timed out"),
                c.check(tx(2), 1, SLOT, head(5_000), () -> slow));
        // Still running, detached: it holds the one permit, so the next send is unchecked.
        assertEquals(0, c.freeReads());
        assertEquals(SendCheck.PreBroadcast.unchecked("account reads busy"),
                c.check(tx(2), 1, SLOT, head(5_000), () -> CompletableFuture.completedFuture(
                        SendCheck.AccountRead.of(RICH, 6))));
        slow.complete(SendCheck.AccountRead.of(RICH, 5));
        assertEquals(1, c.freeReads(), "the read ended: its permit is free");
    }

    @Test
    void aFailedReadOrAnythingUnexpectedFailsOpen() {
        SendCheck.Checker c = checker(2, 1_000);
        assertEquals(SendCheck.PreBroadcast.unchecked("account read failed"), c.check(tx(2), 1, SLOT, head(5_000),
                () -> CompletableFuture.failedFuture(new IllegalStateException("no snap peer"))));
        assertEquals(SendCheck.PreBroadcast.unchecked("account read failed"), c.check(tx(2), 1, SLOT, head(5_000),
                () -> { throw new IllegalStateException("oracle closed"); }));
        assertEquals(SendCheck.PreBroadcast.unchecked("account read failed"),
                c.check(tx(2), 1, SLOT, head(5_000), () -> null));
        assertEquals(2, c.freeReads(), "no permit leaked");
        SendCheck.Checker broken = new SendCheck.Checker(2, 1_000,
                () -> { throw new IllegalStateException("clock"); }, monoMs::get);
        assertEquals(SendCheck.PreBroadcast.Kind.UNCHECKED, broken.check(tx(2), 1, SLOT, head(5_000),
                () -> CompletableFuture.completedFuture(SendCheck.AccountRead.of(RICH, 6))).kind());
    }

    @Test
    void theOptimisticHeadIsMatchedByNumberAndHashTogether() {
        byte[] h = Bytes.repeat((byte) 0xaa, 32).toArray();
        byte[] other = Bytes.repeat((byte) 0xbb, 32).toArray();
        assertTrue(SendCheck.atOptimistic(100, h, 100, h.clone()));
        // The same number on another fork, or the same hash read at another number.
        assertFalse(SendCheck.atOptimistic(100, h, 100, other));
        assertFalse(SendCheck.atOptimistic(99, h, 100, h));
        // Unknown on either side is no.
        assertFalse(SendCheck.atOptimistic(100, null, 100, h));
        assertFalse(SendCheck.atOptimistic(100, h, 100, null));
    }

    @Test
    void theSkipLogNamesTheHeadsTwoAges() {
        assertEquals("no head", SendCheck.describe(null, HEAD_TIME, 0));
        assertEquals("head #100 20s old, adopted 5s ago", SendCheck.describe(head(5_000), HEAD_TIME + 20, 10_000));
        assertEquals("head #100 20s old, never seen advancing, below the optimistic head",
                SendCheck.describe(new SendCheck.Head(100, true, false, HEAD_TIME, null), HEAD_TIME + 20, 10_000));
    }
}
