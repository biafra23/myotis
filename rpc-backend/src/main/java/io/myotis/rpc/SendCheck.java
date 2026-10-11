package io.myotis.rpc;

import com.jaeckel.ethp2p.networking.eth.messages.EthTxDecoder;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The pre-broadcast check of {@code eth_sendRawTransaction} (#531) — the Java twin of
 * the Rust engine's {@code el/send_check.rs} plus its reader's {@code ready_to_judge} /
 * {@code judge_read}: same rules, same words. A transaction its sender cannot pay for,
 * or whose nonce is already used, is never mined, and the eth protocol sends no word
 * back when a peer drops it. geth, Nethermind, Besu and Reth refuse such a transaction
 * before they answer, and wallets read geth's words (ethers v6 and viem classify by
 * message text). The pure half — geth's two txpool verdicts and the freshness rule —
 * and the {@link Checker} that runs them over one account read; {@link VerifiedRpcBackend}
 * supplies the head and the read.
 *
 * <p>The check fails OPEN: anything that stops it from judging (another chain's
 * transaction, no anchored head, a stale head, too many reads already in flight, a
 * slow or failed account read, anything unexpected) broadcasts the transaction as
 * before — a node that lags the chain must never block a send.
 *
 * <p>Where it judges differs from the Rust engine's, and so does one rule. The Rust
 * engine reads at the light client's optimistic head; this engine at its anchored head —
 * the snap-servable block hash-linked up to that head, which the warmer rebuilds every
 * dozen seconds or so and every other state read is served from. The same freshness
 * bound applied to it lets this engine judge less often (on a 5 s chain, rarely); it
 * never judges by older state. And it judges FUNDS only when that head IS the attested
 * optimistic head: one block behind it, a sender funded in the newest block — whose
 * receipt this node already serves — would be refused. A used nonce is judged at any
 * fresh anchored head: a nonce only grows, so an older head can only under-report it.
 */
final class SendCheck {

    private SendCheck() {}

    /** Slack on top of two block times before the head is too old to judge a send by.
     *  A light client learns block N from block N+1's sync aggregate, so its head is
     *  normally one to two blocks old. */
    static final long FRESH_HEAD_GRACE_SEC = 6;

    /** How long the check may wait for the sender's verified account. */
    static final long ACCOUNT_READ_BUDGET_MS = 2_000;

    /** The most such reads in flight at once; past that a send goes unchecked rather
     *  than pile reads onto slow peers. A read holds its permit until it ends: it is not
     *  cut, as the Rust engine cuts its at 20 s, so the bound is the oracle's own — at most
     *  {@code SNAP_ORACLE_MAX_ATTEMPTS} (8) requests of 10 s each, up to 80 s. */
    static final int DETACHED_READS_MAX = 4;

    /** How old a head may be to judge a send by, in seconds: two block times plus
     *  {@link #FRESH_HEAD_GRACE_SEC}. */
    static long freshBoundSec(long blockTimeSec) {
        return 2 * blockTimeSec + FRESH_HEAD_GRACE_SEC;
    }

    /**
     * Whether a head is fresh enough to judge a send by ({@link #freshBoundSec}): by its
     * proven timestamp (unix seconds) against the wall clock {@code nowUnix} — a head in
     * the future, clock skew, counts as fresh — AND by how long ago this node saw it
     * advance, on its own monotonic clock, which a wall clock set wrong cannot fake. A
     * head never seen to advance ({@code adoptedAgoMs} null: the first after a start)
     * is not fresh.
     */
    static boolean headIsFresh(long nowUnix, long headTimestamp, Long adoptedAgoMs, long blockTimeSec) {
        long bound = freshBoundSec(blockTimeSec);
        return nowUnix <= headTimestamp + bound && adoptedAgoMs != null && adoptedAgoMs <= bound * 1_000;
    }

    /**
     * What the transaction may cost its sender at most: {@code value + gas × fee}, the
     * fee being the gas price (types 0 and 1) or the max fee per gas (types 2 and 4), as
     * geth's {@code tx.Cost()} reckons it. Null for any other type and for fields the
     * decode lacks; the check then judges the nonce only.
     */
    static BigInteger maxCost(EthTxDecoder.DecodedTx tx) {
        BigInteger fee = switch (tx.type()) {
            case 0, 1 -> tx.gasPrice();
            case 2, 4 -> tx.maxFeePerGas();
            default -> null;
        };
        if (fee == null || tx.value() == null) return null;
        return new BigInteger(Long.toUnsignedString(tx.gas())).multiply(fee).add(tx.value());
    }

    /**
     * geth's txpool verdict for {@code tx} against its sender's account, in geth's order
     * and words: the message when the transaction can never be mined as sent, null when
     * it may be. A nonce above the account's is a gap a later transaction fills (geth
     * queues it). Each transaction is judged alone against the balance: geth's pool also
     * counts the sender's transactions it already queued, which this node does not see.
     */
    static String verdict(EthTxDecoder.DecodedTx tx, BigInteger balance, long accountNonce) {
        return verdict(tx, balance, accountNonce, true);
    }

    /** {@link #verdict(EthTxDecoder.DecodedTx, BigInteger, long)}, the balance judged only
     *  when {@code judgeFunds}. */
    static String verdict(EthTxDecoder.DecodedTx tx, BigInteger balance, long accountNonce, boolean judgeFunds) {
        if (Long.compareUnsigned(tx.nonce(), accountNonce) < 0) {
            return "nonce too low: next nonce " + Long.toUnsignedString(accountNonce)
                    + ", tx nonce " + Long.toUnsignedString(tx.nonce());
        }
        BigInteger cost = judgeFunds ? maxCost(tx) : null;
        if (cost == null || balance.compareTo(cost) >= 0) return null;
        return "insufficient funds for gas * price + value: balance " + balance + ", tx cost " + cost
                + ", overshot " + cost.subtract(balance);
    }

    /**
     * A head a send may be judged at: its number, whether it is beacon-anchored (its hash
     * proven against the light client), whether it is the attested optimistic head itself,
     * its proven header timestamp (unix seconds) and when this node saw it advance, on its
     * monotonic clock ({@link HeadAdvance}; null: never). Taken once, before the read.
     */
    record Head(long blockNumber, boolean anchored, boolean atOptimistic, long timestamp, Long adoptedAtMs) {
        Long adoptedAgoMs(long nowMs) {
            return adoptedAtMs == null ? null : nowMs - adoptedAtMs;
        }
    }

    /**
     * Whether a head is the attested optimistic head itself: the same number AND the same
     * hash, both read from one optimistic update ({@code optimisticNumber},
     * {@code optimisticHash}). Unknown on either side is no.
     */
    static boolean atOptimistic(long blockNumber, byte[] blockHash, long optimisticNumber, byte[] optimisticHash) {
        return blockHash != null && optimisticHash != null && blockNumber == optimisticNumber
                && java.util.Arrays.equals(blockHash, optimisticHash);
    }

    /**
     * Why there is nothing to judge, or null when the send can be judged at {@code head}:
     * an unrecovered sender (which {@link EthTxDecoder#checkSendable} refuses before a
     * send gets here), another chain's transaction (peers drop it anyway, and this
     * chain's state says nothing about it), no anchored head, or a head older than
     * {@link #freshBoundSec}.
     */
    static String unjudgedWhy(EthTxDecoder.DecodedTx tx, long chainId, Head head, long nowUnix, long nowMs,
                              long blockTimeSec) {
        if (tx.from() == null) return "sender not recovered";
        if (tx.chainId() != null && tx.chainId() != chainId) return "another chain's transaction";
        if (head == null) return "no verified head yet";
        if (!head.anchored()) return "head not beacon-anchored";
        if (!headIsFresh(nowUnix, head.timestamp(), head.adoptedAgoMs(nowMs), blockTimeSec)) {
            return "head not fresh";
        }
        return null;
    }

    /** The sender's account as read at the judged head: proven, or the read failed. */
    record AccountRead(BigInteger balance, long nonce, boolean failed) {
        static AccountRead of(BigInteger balance, long nonce) {
            return new AccountRead(balance, nonce, false);
        }

        static AccountRead failure() {
            return new AccountRead(null, 0, true);
        }
    }

    /** The check's verdict: never mined as sent (geth's message), judged and may be
     *  mined, or not judged and why (logged; the send goes out as before). */
    record PreBroadcast(Kind kind, String text) {
        enum Kind { DOOMED, PASSED, UNCHECKED }

        static PreBroadcast doomed(String reason) {
            return new PreBroadcast(Kind.DOOMED, reason);
        }

        static PreBroadcast passed() {
            return new PreBroadcast(Kind.PASSED, null);
        }

        static PreBroadcast unchecked(String why) {
            return new PreBroadcast(Kind.UNCHECKED, why);
        }
    }

    /**
     * The verdict on the sender's account read at {@code head} ({@code read} null: it
     * timed out). The account is proven against the head's own state root by
     * construction — the read runs at that root. The clocks are read after the read: the
     * head taken before it must still be fresh when the verdict is made. Funds are judged
     * only at the attested optimistic head ({@link Head#atOptimistic}).
     */
    static PreBroadcast judgeRead(EthTxDecoder.DecodedTx tx, Head head, AccountRead read, long nowUnix,
                                  long nowMs, long blockTimeSec) {
        if (!headIsFresh(nowUnix, head.timestamp(), head.adoptedAgoMs(nowMs), blockTimeSec)) {
            return PreBroadcast.unchecked("head went stale during the read");
        }
        if (read == null) return PreBroadcast.unchecked("account read timed out");
        if (read.failed()) return PreBroadcast.unchecked("account read failed");
        String reason = verdict(tx, read.balance(), read.nonce(), head.atOptimistic());
        return reason != null ? PreBroadcast.doomed(reason) : PreBroadcast.passed();
    }

    /** {@code head}'s two ages for the skip log, as the Rust engine logs them: by its
     *  proven timestamp, and since this node saw it advance. */
    static String describe(Head head, long nowUnix, long nowMs) {
        if (head == null) return "no head";
        Long ago = head.adoptedAgoMs(nowMs);
        return "head #" + head.blockNumber() + " " + (nowUnix - head.timestamp()) + "s old, "
                + (ago == null ? "never seen advancing" : "adopted " + (ago / 1_000) + "s ago")
                + (head.atOptimistic() ? "" : ", below the optimistic head");
    }

    /**
     * Runs the check over one account read: the freshness gate, a permit
     * ({@link #DETACHED_READS_MAX}), the read waited on for at most the budget, and the
     * verdict at the clocks after it. The read runs on, detached and not cut, past the
     * budget, and holds its permit until it ends. Anything unexpected is UNCHECKED: the
     * check never fails a send.
     */
    static final class Checker {
        private final Semaphore reads;
        private final long readBudgetMs;
        private final LongSupplier wallClockSec;
        private final LongSupplier monotonicMs;

        Checker(int maxReads, long readBudgetMs, LongSupplier wallClockSec, LongSupplier monotonicMs) {
            this.reads = new Semaphore(maxReads);
            this.readBudgetMs = readBudgetMs;
            this.wallClockSec = wallClockSec;
            this.monotonicMs = monotonicMs;
        }

        PreBroadcast check(EthTxDecoder.DecodedTx tx, long chainId, long blockTimeSec, Head head,
                           Supplier<CompletableFuture<AccountRead>> read) {
            try {
                String why = unjudgedWhy(tx, chainId, head, wallClockSec.getAsLong(), monotonicMs.getAsLong(),
                        blockTimeSec);
                if (why != null) return PreBroadcast.unchecked(why);
                if (!reads.tryAcquire()) return PreBroadcast.unchecked("account reads busy");
                CompletableFuture<AccountRead> f;
                try {
                    f = read.get();
                } catch (RuntimeException e) {
                    f = null;
                }
                if (f == null) {
                    reads.release();
                    return PreBroadcast.unchecked("account read failed");
                }
                f.whenComplete((a, e) -> reads.release());
                AccountRead account;
                try {
                    account = f.get(readBudgetMs, TimeUnit.MILLISECONDS);
                } catch (TimeoutException e) {
                    account = null; // still running: detached, not cut
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    account = AccountRead.failure();
                } catch (Exception e) {
                    account = AccountRead.failure();
                }
                return judgeRead(tx, head, account, wallClockSec.getAsLong(), monotonicMs.getAsLong(),
                        blockTimeSec);
            } catch (RuntimeException e) {
                return PreBroadcast.unchecked("check failed: " + e);
            }
        }

        /** Permits free right now — for tests. */
        int freeReads() {
            return reads.availablePermits();
        }
    }

    /**
     * When this node saw its anchored head advance, on its monotonic clock — the
     * "adopted" half of {@link #headIsFresh}. Noted at every anchored-head install: a
     * higher block than any before is adopted then; the same block rebuilt keeps the time
     * it first advanced; the first head after a start was never seen advancing.
     */
    static final class HeadAdvance {
        /** The highest head seen, and when it advanced to — null: never seen advancing (out
         *  of band: the monotonic clock's epoch is arbitrary, so any long may be a time). */
        private record Seen(long blockNumber, Long advancedAtMs) {}

        private final AtomicReference<Seen> seen = new AtomicReference<>();

        void note(long blockNumber, long nowMs) {
            seen.updateAndGet(prev -> prev == null ? new Seen(blockNumber, null)
                    : blockNumber > prev.blockNumber() ? new Seen(blockNumber, nowMs)
                    : prev);
        }

        /** When {@code blockNumber} was seen advancing, or null when it is not the head
         *  this node saw advance last (or it never did). */
        Long adoptedAtMs(long blockNumber) {
            Seen s = seen.get();
            return s != null && s.blockNumber() == blockNumber ? s.advancedAtMs() : null;
        }
    }
}
