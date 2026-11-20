//! Client-side accounting mirror for bee retrieval.
//!
//! # Why this exists
//!
//! Bee's `pkg/retrieval/retrieval.go::RetrieveChunk` calls
//! `accounting.PrepareCredit(peer, price)` *before* dispatching a
//! request. The check fails with `ErrOverdraft` if the dispatch
//! would push our expected debt with that peer over the
//! `paymentThreshold + 1s × refreshRate` envelope, at which point
//! bee silently picks the next-closest peer instead and re-tries the
//! original 600 ms later (after one `lightRefreshRate` worth of
//! allowance has accumulated). The dispatched request therefore
//! never lands on a peer that's about to disconnect us — the worst
//! case is an extra 600 ms of latency for a single saturated chunk.
//!
//! Without this mirror, we instead **find out** that a peer is over
//! its disconnect limit by being RST'd at the TCP layer (bee's
//! `accounting.go::debitAction.Apply()::if nextBalance >=
//! disconnectLimit { Blocklist }`). A 4-track bench against
//! production saw the 112 MiB file drop ~52 peers and finish in
//! 312 s vs bee's 195 s on the identical file under identical
//! handshake terms. The 117 s gap is almost entirely
//! "dispatch-then-find-out" overhead: we hedge harder, the hedge
//! lands on a saturated peer, the peer RSTs us, we cancel +
//! re-dispatch, peer set degrades, retry budget drains.
//!
//! # What this does
//!
//! [`Accounting`] tracks per-peer state mirroring bee's
//! `accountingPeer` (just the four fields that matter for
//! admission):
//!
//! - `balance`: real debt accumulated on this peer since the last
//!   accepted pseudosettle, in chunk-price units.
//! - `reserved`: prospective debt for in-flight retrievals (added
//!   on `try_reserve`, cleared on `apply` or guard drop).
//! - `last_refresh`: when the pseudosettle driver last credited
//!   this peer with an accepted refresh, so the same time-elapsed
//!   allowance bee uses can be added to the overdraft envelope.
//! - `last_used`: last successful chunk fetch from this peer, used
//!   only to age out idle peers when the gateway processes
//!   thousands of distinct peers per hour.
//!
//! [`Accounting::try_reserve`] returns a [`DebitGuard`] (RAII) on
//! success; on failure (`balance + reserved + price` >
//! `OVERDRAFT_LIMIT`) it returns `None`, and the fetcher must skip
//! this peer with a 600 ms TTL, mirroring bee's
//! `skip.Add(chunkAddr, peer, overDraftRefresh)`.
//!
//! On success the [`DebitGuard`] is moved into the per-chunk fetch
//! future. Either `apply()` is called when the chunk arrives (debit
//! moves from reserved into balance, hot hint sent if balance just
//! crossed [`HOT_DEBT_THRESHOLD`]) or the guard is dropped without
//! `apply()` (reserved is released — the chunk fetch failed and the
//! request never reached the peer's `PrepareDebit`, so bee's
//! `creditAction.Cleanup` cleared its reserve too without touching
//! ghost balance).
//!
//! [`Accounting::credit`] is the pseudosettle ack callback: when
//! the driver receives a `PaymentAck { accepted, timestamp }`,
//! call `credit(peer, accepted)` to drop our balance by that
//! amount. `last_refresh` is bumped to `Instant::now()` so the
//! envelope's `1 s × refreshRate` term reopens.
//!
//! # Sizing
//!
//! - Chunk price at typical proximity (PO 8): ~240 k units.
//! - `lightDisconnectLimit` (the line bee enforces on us when we
//!   declare `full_node = false`): 1.69 M units.
//! - `lightRefreshRate`: 450 k units / sec.
//!
//! [`OVERDRAFT_LIMIT`] is set to `lightDisconnectLimit + 1 s ×
//! lightRefreshRate ≈ 2.14 M units` — that's the exact ceiling bee
//! enforces in `debitAction.Apply` (line 1357), the boundary at
//! which a peer disconnects us. We refuse to dispatch any request
//! that would cross it.
//!
//! [`HOT_DEBT_THRESHOLD`] is set at 50 % of the disconnect limit
//! (≈ 850 k units). Crossing it sends a hot hint to the pseudosettle
//! driver, which registers the peer with it. The driver refreshes a peer
//! once [`Accounting::refresh_due`] says so: bee's settle trigger, an
//! expected debt of [`EARLY_PAYMENT_THRESHOLD`] with at least one second
//! of refresh ([`LIGHT_REFRESH_RATE_PER_SEC`]) applied (issue #129).
//!
//! # Paying with SWAP (issue #121)
//!
//! With a [`RetrievalPayment`] installed (a funded chequebook, `swap-enable`
//! on), debt is settled in two steps, as bee's
//! `Accounting.settle` does. The free pseudosettle refresh stays first
//! (the driver above). Once the expected debt to a peer reaches
//! [`EARLY_PAYMENT_THRESHOLD`] (half the peer's payment threshold), the
//! debt the refresh isn't expected to cover is paid with a cheque
//! (`PeerBalance::cheque_due`), one payment per peer at a time, at least
//! [`MINIMUM_CHEQUE`] (one second of refresh, stricter than bee's
//! [`MINIMUM_PAYMENT`]; issue #131), with [`FAILED_SETTLEMENT_INTERVAL`] of back-off
//! after a failure. A paid debt frees credit like a refresh does. Without
//! a payer nothing here runs, and the mirror behaves as before.
//!
//! The mirror is bee's one balance per peer: pushsync debits land in it
//! too (`ant_p2p::push_pseudosettle`), so uploads are settled — and paid
//! for — exactly like downloads (issue #127).
//!
//! # Conservatism
//!
//! Our mirror is intentionally conservative: we only ever
//! *increase* `balance` on `apply()`, so the worst-case error in
//! our envelope check is "we think this peer is more loaded than
//! it really is" → we skip them for 600 ms → tiny per-chunk latency
//! penalty. The opposite error ("we think the peer has more
//! headroom than it does") would let us blow past
//! `lightDisconnectLimit`, which is exactly the regression we're
//! trying to prevent. Cancellations release the reserve (no debit
//! ever happened on bee's side either, see
//! `creditAction.Cleanup`); only successful applies stay on the
//! books until pseudosettle clears them.

use async_trait::async_trait;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

use crate::fetcher::Overlay;

type SharedBalances = Arc<Mutex<HashMap<PeerId, PeerBalance>>>;

/// The slot holding the node's [`RetrievalPayment`], shared by the
/// [`Accounting`] and every [`DebitGuard`] it hands out so a payer
/// installed (or removed) at runtime takes effect on the next settle.
type PaymentSlot = Arc<RwLock<Option<Arc<dyn RetrievalPayment>>>>;

/// Bee's `lightDisconnectLimit` for a peer that declares itself
/// `full_node = false` in the BZZ handshake. Computed by bee as
/// `(100 + paymentTolerance) % * lightPaymentThreshold` =
/// `1.25 * (paymentThreshold / lightFactor)` =
/// `1.25 * (13.5 M / 10)` = 1.6875 M units.
///
/// See `bee/pkg/accounting/accounting.go::NotifyPeerConnect` for
/// the wiring and `pkg/node/node.go` for the
/// `paymentThreshold = 13.5M` and `lightFactor = 10` constants.
pub const LIGHT_DISCONNECT_LIMIT: u64 = 1_687_500;

/// Bee's per-peer light-mode refresh allowance. From `pkg/node/node.go`:
/// `lightRefreshRate = refreshRate / lightFactor = 4.5 M / 10`.
/// Bee's `debitAction.Apply` allows up to `1 s × refreshRate`
/// of "in-flight" allowance on top of the disconnect limit, capped
/// at one second's worth (`min(elapsed_seconds, 1)`).
pub const LIGHT_REFRESH_RATE_PER_SEC: u64 = 450_000;

/// Combined ceiling we refuse to cross. Bee's `debitAction.Apply`
/// blocklists at `disconnectLimit + min(int64(elapsed_seconds), 1) * refreshRate`,
/// which is *either* `disconnectLimit` (when
/// elapsed < 1 s) *or* `disconnectLimit + refreshRate` (when
/// elapsed ≥ 1 s) — bee's `min` operates on `int64` second
/// granularity, no fractional seconds. See
/// `bee/pkg/accounting/accounting.go:1346`:
///
/// ```text
/// timeElapsedInSeconds := min(timeNow().Unix() - refreshReceivedTimestamp, 1)
/// ```
///
/// We pick the *lower* of the two boundaries — `disconnectLimit`
/// alone, no allowance — to leave headroom for the
/// `min(elapsed, 1) * refreshRate` we don't precisely model. With
/// 100 peers each consuming ≥ 4 chunks/sec (24-s download of a
/// 44 MiB file), the difference between 1.687 M and 2.137 M is
/// roughly one second of saturation, which a single
/// pseudosettle round-trip can clear. Anything beyond is
/// indistinguishable from a stall on bee's end.
pub const OVERDRAFT_LIMIT: u64 = LIGHT_DISCONNECT_LIMIT;

/// Threshold at which the mirror hints to the pseudosettle driver that
/// a peer's debt is approaching the limit, so the driver tracks the peer
/// even when no fetch has notified it (pushsync debt). The refresh itself
/// is due earlier, at [`EARLY_PAYMENT_THRESHOLD`]
/// ([`Accounting::refresh_due`]).
///
/// 50 % of `LIGHT_DISCONNECT_LIMIT`.
pub const HOT_DEBT_THRESHOLD: u64 = LIGHT_DISCONNECT_LIMIT / 2;

/// Bee's `lightPaymentThreshold`: the payment threshold a bee peer
/// announces to a light node (`paymentThreshold / lightFactor` =
/// 13.5 M / 10 units, `pkg/node/node.go`).
pub const LIGHT_PAYMENT_THRESHOLD: u64 = 1_350_000;

/// Expected debt to a peer at which retrieval settles with money (issue
/// #121): bee's `earlyPayment`, `--payment-early-percent 50` of the
/// peer's payment threshold (`accounting.go::PrepareCredit`, where it
/// "pays early to avoid needlessly blocking requests later when
/// concurrent requests occur").
pub const EARLY_PAYMENT_THRESHOLD: u64 = LIGHT_PAYMENT_THRESHOLD / 2;

/// Bee's smallest SWAP payment: `minimumPayment = refreshRate /
/// minimumPaymentDivisor` (5), with a light node's refresh rate. Ant's
/// payer uses the larger [`MINIMUM_CHEQUE`].
pub const MINIMUM_PAYMENT: u64 = LIGHT_REFRESH_RATE_PER_SEC / 5;

/// Smallest SWAP payment Ant sends as a cheque: one second of light
/// refresh (issue #131).
///
/// The cheque is bee's `balance − refreshDue − shadowReserved`, and
/// `refreshDue` jumps by a whole [`LIGHT_REFRESH_RATE_PER_SEC`] the moment
/// the last refresh is a second old. Paid on bee's [`MINIMUM_PAYMENT`]
/// floor, that turned a debt just past the trigger into a cheque of less
/// than one chunk (90 k – 225 k units), sent while the refresh that clears
/// the same debt for free was due: on a paid mainnet burst, 38 % of the
/// cheques carried 14 % of the debt. Each cheque costs the receiving bee
/// the same — `chequeStore.ReceiveCheque` takes one node-wide lock and
/// makes three chain calls (`Issuer`, `Balance`, `PaidOut`) per cheque,
/// whatever its size — so a sliver of debt is the most expensive way to
/// pay it.
///
/// So a payment under one second of refresh waits: the refresh clears
/// it, or the debt grows into a cheque at least this large. This is the
/// rule bee applies to its own refresh ("minimum amount to trigger
/// settlement for is 1 * refresh rate to avoid ineffective use of
/// refreshments", `Accounting.settle`), applied to the cheque too. It is
/// stricter than bee's payer and changes nothing a bee receiver checks
/// (any cheque worth at least one unit is accepted, `ErrChequeValueTooLow`).
/// With no refresh due the floor never bites: `PeerBalance::cheque_due`
/// already pays only a settled debt of at least this much.
///
/// "The refresh clears it" assumes the refresh is landing. When
/// refreshes stall (rejected, timing out), `refreshDue` keeps growing by
/// one refresh second per second since the last *accepted* refresh, and
/// a cheque needs `balance ≥ (whole seconds + 1) × refresh rate`. So the
/// floor stops cheques about a second sooner than bee's would: from 3 s
/// after the last accepted refresh only a debt of at least 1.8 M is
/// paid, and from 4 s nothing within bee's light ceiling
/// (`disconnectLimit + refreshRate` = 2.1375 M) is, until a refresh
/// lands. A 1.8 M debt is past [`OVERDRAFT_LIMIT`] but still reachable
/// by ordinary admitted traffic: once the last refresh is a second old,
/// [`Accounting::try_reserve`] (used by retrieval and, since issue #128,
/// by every push) adds the one-second allowance and admits up to that
/// same 2.1375 M ceiling, so between 3 s and 4 s plain downloads and
/// uploads still produce cheques (a 450 k one at 1.8 M applied). From
/// 4 s the admission ceiling itself is out of the floor's reach: only
/// already-incurred debt recorded past it with [`Accounting::debit`]
/// could still be paid. Bee's [`MINIMUM_PAYMENT`] floor stops one second
/// later (a 250 k cheque 3.2 s after the refresh on a 1.6 M debt;
/// nothing from 5 s), so the gap is bounded to that second.
pub const MINIMUM_CHEQUE: u64 = LIGHT_REFRESH_RATE_PER_SEC;

/// After a failed SWAP payment to a peer, no new one to that peer for
/// this long: bee's `failedSettlementInterval` (10 s). The pseudosettle
/// refresh keeps running meanwhile.
pub const FAILED_SETTLEMENT_INTERVAL: Duration = Duration::from_secs(10);

/// Pays a peer for retrieval debt with money: the second step of bee's
/// `Accounting.settle` (`payFunction` = `swap.Pay`), after the free
/// pseudosettle refresh. Implemented over the node's chequebook in
/// `ant-p2p` (`PushsyncSwap`); installed with
/// [`Accounting::set_payment`]. Without one, retrieval settles with the
/// refresh alone, as before issue #121.
// `#[async_trait]` marks the boxed-future method `#[must_use]`; clippy
// 1.99's `double_must_use` flags that expansion (as on `ChunkFetcher`).
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait RetrievalPayment: Send + Sync {
    /// Send `peer` a SWAP cheque worth `amount` accounting units of debt.
    /// `Ok` once the peer has processed the cheque (credited it, when it
    /// accepted it); [`Accounting`] then lowers its mirrored debt by
    /// `amount`. `Err` (no beneficiary, no
    /// chequebook credit left, stream failure, unacceptable rates) leaves
    /// the debt to the refresh and backs off for
    /// [`FAILED_SETTLEMENT_INTERVAL`].
    async fn pay(&self, peer: PeerId, amount: u64) -> Result<(), String>;
}

/// Credit a look-ahead fetch of the streaming joiner leaves unreserved
/// on every peer, for the fetches at the head of the window (issue #46;
/// [`crate::priority`]): one chunk at the highest price a peer charges
/// (`peer_price` at proximity 0).
///
/// Without it, on a cold node the look-ahead fetches (up to 16 sibling
/// subtrees of a download, each with its own fan-out) take every unit of
/// credit a pseudosettle refresh frees, and the chunk the consumer is
/// waiting for queues behind all of them. With it, a peer's last chunk
/// of credit can only be taken by a head fetch (or by a fetch outside a
/// streaming join, which is served as before), so a head fetch finds
/// credit on any peer that has a chunk's worth left. It costs no
/// throughput once the pool is starved: the refresh pays the debt down
/// at the same rate whether or not this much of it is kept free, and the
/// look-ahead takes the rest as before. The initial burst of a fresh
/// peer (its 1.69M-unit limit, about five chunks) shrinks by one chunk
/// for look-ahead fetches.
pub const HEAD_CREDIT_RESERVE: u64 = 32 * 10_000;

/// Per-chunk skip TTL for peers that fail [`Accounting::try_reserve`].
///
/// Mirrors bee's `overDraftRefresh = time.Millisecond * 600` in
/// `pkg/retrieval/retrieval.go`. The fetcher's per-chunk skip
/// list lifts the entry after this elapses, so the same peer
/// becomes available again on the next preemptive tick once
/// pseudosettle has had a chance to clear its debt.
pub const OVERDRAFT_REFRESH: Duration = Duration::from_millis(600);

/// Longest one credit-waiting fetch
/// ([`crate::ChunkFetcher::fetch_waiting_for_credit`]) waits, in total,
/// for credit while every candidate peer is overdraft-skipped (issue
/// #117).
///
/// Bee's `RetrieveChunk` waits for credit without a bound of its own:
/// it sleeps [`OVERDRAFT_REFRESH`] and retries until the request context
/// ends. We have no per-chunk context, so here the wait is opt-in and
/// bounded. Plain [`crate::ChunkFetcher::fetch`] never waits: a fetch
/// whose candidates are all overdraft-skipped fails at once as
/// `FetchExhausted { pool_starved: true }`, as before #117.
///
/// Only the fetches below wait. Each sits in a retry loop that passes
/// every attempt what is left of the loop's [`CreditWindow`] (at most
/// this budget) and retries a starved miss only inside that window, so
/// the waits of one loop never add up past its window:
///
/// - **Streaming and range joiner data chunks** (`/bytes`, `/bzz`
///   bodies). Each data child has a 60 s window opened by its first
///   fetch: a plain child's subtree retries and a redundant child's
///   recovery retries both live inside it. Recovery sweeps never wait.
///   A starved child therefore stalls the body for at most 60 s plus the
///   last attempt's network time, under the gateway's 90 s
///   `BODY_STALL_TIMEOUT`. That bound is per tree level: once a child
///   has arrived, its own children get their own windows.
/// - **Buffered joiner data chunks** (`GetBytes` / `GetBzz`: `antctl
///   get`, FFI `ant_get`). Each child has a 10 s window (one wait). A
///   redundant child's recovery retries keep their 60 s window. The
///   request's whole-join retries share a 30 s deadline
///   (`RoutingFetcher::with_credit_deadline`), so a request spends at
///   most 30 s waiting for credit, across all of its attempts.
/// - **The data-root fetch of `/bytes` and `/bzz`**, plus the buffered
///   requests' data roots. This is the direct fetch only: dispersed-replica
///   probes never wait. A `/bytes` or `/bzz` root waits at most this long
///   and never past the 30 s resolution budget.
/// - **The `/bzz` manifest walk** (`mantaray::lookup_path_with_credit`):
///   each node load's root-chunk fetch (issue #130; one per trie level:
///   the root, a feed's target root, each fork's child on the way down,
///   also in the directory-redirect check and the index / error-document
///   retries), and below it the header sniff's root → leftmost-leaf
///   fetches (issue #122; two for a few-MiB raw segment behind a bare
///   `/bzz/<ref>/`, none for a single-chunk node). Without them a
///   starved walk fails and the resolution loop backs off and retries
///   it while concurrent body fetches take every freed credit, and a
///   starved sniff can't tell and falls back to joining the whole file
///   before the first byte. The walk loads one node at a time, so its
///   waits run one after another.
///
///   Every waiting fetch of a `/bzz` request (bare root, walk and sniff,
///   data root), in every attempt, takes its budget from one window, the
///   30 s resolution budget, and they run one after another. So a `/bzz`
///   request waits at most 30 s for credit in total before its body,
///   however many attempts, roots and trie levels it goes through; once
///   the window has passed, these fetches no longer wait at all.
/// - **Pushes** (`RoutingFetcher::push_stamped_chunk`, issue #128). Each
///   push first reserves credit with its peer, as bee's pushsync client
///   runs `PrepareCredit` (a peer at its limit is skipped for
///   [`OVERDRAFT_REFRESH`] and the next-closest one is tried). Only when
///   every candidate is at its limit and nothing is in flight does the
///   walk sleep until a skipped peer may be asked again (≤
///   [`OVERDRAFT_REFRESH`]) and retry, for at most this budget in total
///   per walk, then give up. The node's push commands (`PushChunk`:
///   every upload-job chunk and the gateway's `/bytes`, `/bzz`, `/chunks`
///   uploads; `PushSoc`) cut that to a deadline this long after the push
///   starts (`RoutingFetcher::with_credit_deadline`), shared by all of
///   the gateway patience loop's re-walks, so one push command waits at
///   most this long for credit in total; the upload job then re-queues
///   the chunk. The other push walks (stewardship re-upload, the batch
///   self-probe) wait at most this long per chunk walk. A push waiting
///   for credit only sleeps: it never takes a credit wake-up
///   ([`Accounting::wait_for_credit`]) from a waiting fetch.
///
/// Of the retrieval paths, nothing else waits. That covers every manifest walk outside the
/// streaming `/bzz` loop (buffered `GetBzz`, manifest listings), the
/// fallback join of a multi-chunk manifest node, encrypted manifest
/// nodes, feed probes, replica probes, recovery
/// sweeps, the encrypted joiner (in-order and buffered, so one wait per
/// chunk would add up within one body stall), pin / stewardship /
/// verify, traversal, ACT, and the SOC / chunk API. A joiner run on one
/// of these (a fetcher whose [`crate::ChunkFetcher::waits_for_credit`]
/// is `false`) has no wait to bound, so its windows don't cut off a
/// starved child's subtree retries either: it keeps all of them, as
/// before #117.
///
/// **Head-of-window priority (issue #46) changes who gets freed credit
/// first, not how long anyone waits.** A streaming joiner's data-chunk
/// fetches are ranked against the consumer's read position
/// ([`crate::priority`]): a look-ahead one leaves
/// [`HEAD_CREDIT_RESERVE`] of every peer's limit to the head of the
/// window, so it finds the pool starved a little sooner. It waits
/// exactly as above, within the same per-attempt budget and the same
/// window; no site waits that didn't, and no bound above changes.
pub const CREDIT_WAIT_BUDGET: Duration = Duration::from_secs(10);

/// A retry loop's credit window: the bound on how long the credit waits
/// of all its attempts may run (see [`CREDIT_WAIT_BUDGET`]).
///
/// Opened when the loop's first fetch starts. Each attempt passes
/// [`CreditWindow::budget`] to
/// [`crate::ChunkFetcher::fetch_waiting_for_credit`], so no wait runs
/// past the window, and retries an overdraft-starved miss only while
/// [`CreditWindow::allows_retry`] holds. Once the window has passed,
/// attempts don't wait at all, exactly like plain `fetch`.
#[derive(Debug, Clone, Copy)]
pub struct CreditWindow {
    started: tokio::time::Instant,
    window: Duration,
}

impl CreditWindow {
    /// Open a window of `window` now.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            started: tokio::time::Instant::now(),
            window,
        }
    }

    /// Credit budget for the next attempt: [`CREDIT_WAIT_BUDGET`], cut
    /// to what is left of the window (zero once it has passed).
    #[must_use]
    pub fn budget(&self) -> Duration {
        CREDIT_WAIT_BUDGET.min(self.window.saturating_sub(self.started.elapsed()))
    }

    /// May a starved miss be retried after sleeping `backoff`? Only if
    /// the retry would still start inside the window.
    #[must_use]
    pub fn allows_retry(&self, backoff: Duration) -> bool {
        self.started.elapsed() + backoff < self.window
    }
}

/// Per-peer mirror of bee's `accountingPeer`, restricted to the
/// fields that affect admission control. We don't track
/// `ghostBalance`, `paymentThresholdForPeer`, or any of bee's
/// pricing-protocol state — those are the receiver's concern
/// (they decide when to disconnect us), and the only number we
/// can act on locally is "what does the receiver think we owe
/// them right now."
#[derive(Debug)]
struct PeerBalance {
    balance: u64,
    reserved: u64,
    last_refresh: Option<Instant>,
    last_used: Instant,
    /// Cumulative pseudosettle amount this peer has accepted from our
    /// refreshes since the connection was established (bee's
    /// `SettlementsSent` counterpart for the time-based settlement).
    /// Only ever grows via [`Accounting::credit`]; dropped with the
    /// rest of the entry on disconnect (`forget`), matching the
    /// mirror's connection-scoped lifetime — unlike bee, which
    /// persists totals in its statestore.
    time_settled: u64,
    /// SWAP payments sent but not finished yet, in accounting units
    /// (bee's `shadowReservedBalance`). Debt they will clear is not paid
    /// twice.
    shadow_reserved: u64,
    /// The SWAP payment to this peer in flight, if any (bee's
    /// `paymentOngoing`): at most one at a time. Held as the payment's
    /// [`PaymentTicket`] so only that payment's outcome clears it, not a
    /// payment started on a previous connection's entry.
    payment_ongoing: Option<PaymentTicket>,
    /// When the last SWAP payment to this peer failed, for the
    /// [`FAILED_SETTLEMENT_INTERVAL`] back-off.
    last_payment_failure: Option<Instant>,
    /// Debt cleared by SWAP cheques since the connection was established,
    /// in accounting units.
    swap_settled: u64,
}

impl Default for PeerBalance {
    fn default() -> Self {
        Self {
            balance: 0,
            reserved: 0,
            last_refresh: None,
            last_used: Instant::now(),
            time_settled: 0,
            shadow_reserved: 0,
            payment_ongoing: None,
            last_payment_failure: None,
            swap_settled: 0,
        }
    }
}

impl PeerBalance {
    /// The refresh half of bee's `Accounting.settle`: the debt a
    /// pseudosettle refresh to this peer should clear now, if one is due
    /// by debt. Bee calls `settle` once the expected debt less payments in
    /// flight reaches the early-payment threshold (`PrepareCredit`,
    /// `creditAction.Apply`), and `settle` refreshes only when the
    /// applied debt less payments in flight (`shadowBalance`) is at least
    /// one second of refresh (`paymentAmount >= refreshRate`, "to avoid
    /// ineffective use of refreshments").
    ///
    /// Below that, a refresh would be accepted for little or nothing,
    /// and bee still restarts its per-peer allowance clock on every
    /// refresh it answers (`lastTime.Timestamp = timestamp`, even for a
    /// zero amount), so the allowance that had built up is lost.
    fn refresh_due(&self) -> Option<u64> {
        let expected = self
            .balance
            .saturating_add(self.reserved)
            .saturating_sub(self.shadow_reserved);
        let refreshable = self.balance.saturating_sub(self.shadow_reserved);
        (expected >= EARLY_PAYMENT_THRESHOLD && refreshable >= LIGHT_REFRESH_RATE_PER_SEC)
            .then_some(refreshable)
    }

    /// The money half of bee's `Accounting.settle`: how much of this
    /// peer's debt to pay with a SWAP cheque now, if any. `expected_debt`
    /// is the debt once every reservation in flight is applied
    /// (`balance + reserved`, plus the price being reserved).
    ///
    /// Pays only when the expected debt, less payments already in
    /// flight, has reached [`EARLY_PAYMENT_THRESHOLD`], the settled debt
    /// is at least one second of refresh, no payment is in flight and the
    /// last failure is more than [`FAILED_SETTLEMENT_INTERVAL`] ago. The
    /// amount is the debt the pseudosettle refresh is not expected to
    /// cover (`balance − refreshDue − shadowReserved`, where `refreshDue`
    /// is a light refresh rate per whole second since the last accepted
    /// refresh) and must be at least [`MINIMUM_CHEQUE`] (issue #131: below
    /// that, the refresh due within a second pays it for free if it
    /// lands, and a cheque would cost the peer as much as a large one;
    /// while refreshes stall, this stops cheques about a second sooner
    /// than bee's floor, see [`MINIMUM_CHEQUE`]). A peer never
    /// refreshed has, as in bee (zero refresh timestamp), everything
    /// still due to the refresh, so it's not paid.
    ///
    /// On `Some` the payment is marked in flight under the returned
    /// ticket and its amount is shadow-reserved; the caller must report
    /// the outcome with [`Accounting::payment_done`].
    fn cheque_due(&mut self, expected_debt: u64, now: Instant) -> Option<PaymentTicket> {
        if self.balance == 0
            || expected_debt.saturating_sub(self.shadow_reserved) < EARLY_PAYMENT_THRESHOLD
            || self.balance.saturating_sub(self.shadow_reserved) < LIGHT_REFRESH_RATE_PER_SEC
            || self.payment_ongoing.is_some()
        {
            return None;
        }
        if self
            .last_payment_failure
            .is_some_and(|failed| now.duration_since(failed) <= FAILED_SETTLEMENT_INTERVAL)
        {
            return None;
        }
        let since_refresh = now.duration_since(self.last_refresh?).as_secs();
        let refresh_due = since_refresh.saturating_mul(LIGHT_REFRESH_RATE_PER_SEC);
        let amount = self
            .balance
            .saturating_sub(refresh_due)
            .saturating_sub(self.shadow_reserved);
        if amount < MINIMUM_CHEQUE {
            return None;
        }
        let ticket = PaymentTicket {
            id: NEXT_PAYMENT_ID.fetch_add(1, Ordering::Relaxed),
            amount,
        };
        self.payment_ongoing = Some(ticket);
        self.shadow_reserved = self.shadow_reserved.saturating_add(amount);
        Some(ticket)
    }
}

/// One SWAP payment started by [`PeerBalance::cheque_due`]: a
/// process-unique id and the amount, in accounting units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PaymentTicket {
    id: u64,
    amount: u64,
}

/// Source of [`PaymentTicket::id`]s.
static NEXT_PAYMENT_ID: AtomicU64 = AtomicU64::new(0);

/// Shared accounting state.
///
/// Held behind an `Arc<Mutex<_>>` so all sibling chunk fetches of
/// a single user request observe the same balance per peer. The
/// joiner fans out concurrent fetches against the same fetcher
/// (`&self`), so admission decisions on chunk N must see the
/// reservations made by chunks N-1, N-2, ... still in flight.
///
/// We never hold the lock across an `.await`; the `try_reserve`
/// path is purely synchronous, and `apply` / `credit` /
/// `cleanup_reserved` are likewise.
pub struct Accounting {
    peers: SharedBalances,
    /// Channel into the pseudosettle driver. Each event is a
    /// peer that has just crossed [`HOT_DEBT_THRESHOLD`]; the driver
    /// coalesces duplicates and refreshes the peer when
    /// [`Accounting::refresh_due`] lists it.
    hot_hint: Option<mpsc::Sender<HotHint>>,
    /// Wakes fetches waiting for credit ([`Accounting::wait_for_credit`])
    /// when credit may have come free: a pseudosettle refresh landed
    /// ([`Accounting::credit`]) or a reservation was released unused
    /// ([`DebitGuard`] dropped without `apply`). Woken one at a time,
    /// oldest first; see [`Accounting::pass_credit`].
    credit_freed: Arc<Notify>,
    /// Count of credit releases (each `credit_freed` event), so a woken
    /// waiter can tell a release it hasn't looked at yet from one it
    /// already has; see [`Accounting::credit_epoch`].
    credit_epoch: Arc<AtomicU64>,
    /// Pays retrieval debt with SWAP cheques once it reaches
    /// [`EARLY_PAYMENT_THRESHOLD`] (issue #121). Empty on a node without
    /// a funded chequebook, or with retrieval payments switched off:
    /// debt is then settled by the pseudosettle refresh alone.
    payment: PaymentSlot,
}

/// Hint payload sent from the fetcher hot path into the
/// pseudosettle driver. Currently just carries the peer id, but
/// is wrapped in a struct so future fields (e.g., observed debt)
/// can be added without touching every call site.
#[derive(Debug, Clone, Copy)]
pub struct HotHint {
    pub peer: PeerId,
}

impl Default for Accounting {
    fn default() -> Self {
        Self::new()
    }
}

impl Accounting {
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            hot_hint: None,
            credit_freed: Arc::new(Notify::new()),
            credit_epoch: Arc::new(AtomicU64::new(0)),
            payment: Arc::new(RwLock::new(None)),
        }
    }

    /// Install (`Some`) or remove (`None`) the payer that settles
    /// retrieval debt with SWAP cheques. Takes effect for the next
    /// settlement; payments already in flight finish.
    pub fn set_payment(&self, payment: Option<Arc<dyn RetrievalPayment>>) {
        if let Ok(mut slot) = self.payment.write() {
            *slot = payment;
        }
    }

    /// Whether retrieval debt is currently settled with SWAP cheques.
    #[must_use]
    pub fn pays_with_swap(&self) -> bool {
        self.payment.read().is_ok_and(|slot| slot.is_some())
    }

    #[must_use]
    pub fn with_hot_hint(mut self, tx: mpsc::Sender<HotHint>) -> Self {
        self.hot_hint = Some(tx);
        self
    }

    /// Compute the chunk price for a peer at a given chunk address.
    /// Mirrors `bee/pkg/pricer/pricer.go::PeerPrice`:
    ///
    /// ```text
    /// price = (MaxPO - proximity(peer, chunk) + 1) * basePrice
    /// ```
    ///
    /// where `MaxPO = 31` (256-bit address space, byte boundary)
    /// and `basePrice = 10_000`. Closer peers (higher proximity)
    /// charge less; far peers charge more, because the far peer's
    /// forwarding chain is longer and more nodes earn along the
    /// way.
    #[must_use]
    pub fn peer_price(peer_overlay: &Overlay, chunk_addr: &[u8; 32]) -> u64 {
        const MAX_PO: u64 = 31;
        const BASE_PRICE: u64 = 10_000;
        (MAX_PO - proximity(peer_overlay, chunk_addr) + 1) * BASE_PRICE
    }

    /// Try to reserve `price` against `peer` for chunk `chunk_addr`.
    ///
    /// Returns `Some(DebitGuard)` if the dispatch is admissible —
    /// i.e., `balance + reserved + price <= OVERDRAFT_LIMIT` after
    /// adding back any `lightRefreshRate × elapsed` allowance that
    /// has accrued since the last successful refresh.
    ///
    /// Returns `None` if the dispatch would cross the limit; the
    /// caller is expected to skip this peer for
    /// [`OVERDRAFT_REFRESH`] and try the next-closest one. This
    /// matches bee's
    /// `pkg/retrieval/retrieval.go::case ErrOverdraft` arm.
    #[must_use]
    pub fn try_reserve(&self, peer: PeerId, price: u64) -> Option<DebitGuard> {
        self.try_reserve_leaving(peer, price, 0)
    }

    /// [`Accounting::try_reserve`], but admit the dispatch only if it
    /// leaves at least `headroom` of the peer's limit unreserved. A
    /// look-ahead fetch of the streaming joiner passes
    /// [`HEAD_CREDIT_RESERVE`], so the credit a peer gets back always
    /// goes to the chunks the consumer is waiting for first (issue #46).
    #[must_use]
    pub fn try_reserve_leaving(
        &self,
        peer: PeerId,
        price: u64,
        headroom: u64,
    ) -> Option<DebitGuard> {
        let payer = current_payer(&self.payment);
        let mut peers = self.peers.lock().ok()?;
        let now = Instant::now();
        let entry = peers.entry(peer).or_insert_with(|| PeerBalance {
            last_used: now,
            ..PeerBalance::default()
        });

        // Mirror bee's `min(timeNow().Unix() - refreshReceivedTimestamp, 1)`
        // exactly: the allowance is binary on a one-second boundary,
        // not interpolated. Bee grants the full
        // `lightRefreshRate` only after a full second has elapsed
        // since the last *accepted* refresh.
        //
        // For never-refreshed peers (`last_refresh = None`) we
        // intentionally use the smaller, zero-allowance branch so a
        // burst of dispatches at startup doesn't pile reservations
        // up to bee's max line before pseudosettle has had a chance
        // to land.
        let allowance = match entry.last_refresh {
            Some(last) if now.duration_since(last) >= Duration::from_secs(1) => {
                LIGHT_REFRESH_RATE_PER_SEC
            }
            _ => 0,
        };
        let limit = OVERDRAFT_LIMIT.saturating_add(allowance);
        let next = entry
            .balance
            .saturating_add(entry.reserved)
            .saturating_add(price);
        // Bee's `PrepareCredit` settles first when this reservation
        // takes the expected debt to the early-payment threshold, then
        // checks the overdraft limit. The payment runs in the background,
        // so (as in bee) it frees credit for later reservations, not this
        // one.
        let cheque = payer.as_ref().and_then(|_| entry.cheque_due(next, now));
        let admitted = next.saturating_add(headroom) <= limit;
        if admitted {
            entry.reserved = entry.reserved.saturating_add(price);
            entry.last_used = now;
        }
        drop(peers);
        if let (Some(payer), Some(ticket)) = (payer, cheque) {
            self.spawn_payment(payer, peer, ticket);
        }
        if !admitted {
            return None;
        }
        Some(DebitGuard {
            peer,
            price,
            applied: false,
            balances: self.peers.clone(),
            hot_hint: self.hot_hint.clone(),
            credit_freed: self.credit_freed.clone(),
            credit_epoch: self.credit_epoch.clone(),
            payment: self.payment.clone(),
        })
    }

    /// Record `price` of debt to `peer` that was already incurred, with
    /// no overdraft check: bee debited it when it served the request, so
    /// the mirror has to hold it whatever the limit says:
    /// [`Accounting::try_reserve`]'s settle step without its admission
    /// check, then [`DebitGuard::apply`] (the hot hint when the debt
    /// crosses [`HOT_DEBT_THRESHOLD`], and a cheque if one is still
    /// due), so debt past [`OVERDRAFT_LIMIT`] is paid too rather than
    /// dropped (PR #126 R1-M2).
    ///
    /// Pushsync no longer records its debt here: like bee's pushsync
    /// client, which runs `PrepareCredit` before every push, each push
    /// now reserves with [`Accounting::try_reserve`] first and applies the
    /// reservation once the receipt is in (issue #128).
    pub fn debit(&self, peer: PeerId, price: u64) {
        let payer = current_payer(&self.payment);
        let cheque = {
            let Ok(mut peers) = self.peers.lock() else {
                return;
            };
            let now = Instant::now();
            let entry = peers.entry(peer).or_insert_with(|| PeerBalance {
                last_used: now,
                ..PeerBalance::default()
            });
            let next = entry
                .balance
                .saturating_add(entry.reserved)
                .saturating_add(price);
            let cheque = payer.as_ref().and_then(|_| entry.cheque_due(next, now));
            entry.reserved = entry.reserved.saturating_add(price);
            entry.last_used = now;
            cheque
        };
        if let (Some(payer), Some(ticket)) = (payer, cheque) {
            self.spawn_payment(payer, peer, ticket);
        }
        DebitGuard {
            peer,
            price,
            applied: false,
            balances: self.peers.clone(),
            hot_hint: self.hot_hint.clone(),
            credit_freed: self.credit_freed.clone(),
            credit_epoch: self.credit_epoch.clone(),
            payment: self.payment.clone(),
        }
        .apply();
    }

    fn spawn_payment(&self, payer: Arc<dyn RetrievalPayment>, peer: PeerId, ticket: PaymentTicket) {
        spawn_payment(
            payer,
            peer,
            ticket,
            self.peers.clone(),
            self.credit_freed.clone(),
            self.credit_epoch.clone(),
        );
    }

    /// Record the outcome of a SWAP payment started by
    /// [`PeerBalance::cheque_due`] (bee's `NotifyPaymentSent`): release
    /// the shadow reservation, and on success lower the debt by the
    /// ticket's amount and wake a fetch waiting for credit; on failure
    /// start the [`FAILED_SETTLEMENT_INTERVAL`] back-off.
    fn payment_done(
        balances: &SharedBalances,
        epoch: &AtomicU64,
        notify: &Notify,
        peer: PeerId,
        ticket: PaymentTicket,
        ok: bool,
    ) {
        let amount = ticket.amount;
        let Ok(mut peers) = balances.lock() else {
            return;
        };
        // A peer forgotten (disconnected) meanwhile starts afresh, on
        // bee's side too: its entry now, if any, is a later connection's,
        // and this payment is not the one in flight there.
        let Some(entry) = peers
            .get_mut(&peer)
            .filter(|entry| entry.payment_ongoing == Some(ticket))
        else {
            return;
        };
        entry.payment_ongoing = None;
        entry.shadow_reserved = entry.shadow_reserved.saturating_sub(amount);
        if !ok {
            entry.last_payment_failure = Some(Instant::now());
            return;
        }
        entry.balance = entry.balance.saturating_sub(amount);
        entry.swap_settled = entry.swap_settled.saturating_add(amount);
        drop(peers);
        Self::release_credit(epoch, notify);
    }

    /// Wait until credit may have come free, or `max` elapses, whichever
    /// is first. Returns `true` when woken by freed credit.
    ///
    /// Used by [`crate::RoutingFetcher`]'s credit-waiting fetches when
    /// every candidate peer for a chunk is overdraft-skipped (issue
    /// #117), in place of bee's plain `time.After(overDraftRefresh)`
    /// sleep in `RetrieveChunk`. The caller passes [`OVERDRAFT_REFRESH`]
    /// (or less, near the end of its credit budget) as `max`, so it
    /// still re-checks on bee's
    /// cadence; that also catches credit that opens without an event
    /// (the one-second refresh allowance, newly connected peers).
    ///
    /// No stampede: a refresh or a released reservation wakes exactly
    /// one waiter, the one that has waited longest (`Notify::notify_one`
    /// is FIFO), not every fetch parked on the pool. A woken waiter that
    /// gets a reservation calls [`Accounting::pass_credit`] to wake the
    /// next, since the credit may cover more than one chunk. One that
    /// can't use the credit (it's on a peer this waiter has no use for)
    /// passes it on too, unless it already looked at the pool after that
    /// release ([`Accounting::credit_epoch`] unchanged); since waiters
    /// re-queue at the back, an unusable wake-up visits each waiter at
    /// most once and then stops. A waiter whose wait ended on its timer
    /// passes nothing. So a refill admitting `k` chunks wakes the
    /// waiters up to the `k`-th one that can use it, plus one, not all
    /// of them. A wake-up delivered while nobody waits is kept for the
    /// next waiter.
    pub async fn wait_for_credit(&self, max: Duration) -> bool {
        tokio::time::timeout(max, self.credit_freed.notified())
            .await
            .is_ok()
    }

    /// Hand a credit wake-up on to the next waiter. Called by a fetch
    /// that was waiting for credit and just got a reservation; see
    /// [`Accounting::wait_for_credit`].
    pub fn pass_credit(&self) {
        self.credit_freed.notify_one();
    }

    /// How many times credit has been released so far (pseudosettle
    /// refreshes and unused reservations dropped). A woken waiter
    /// compares it against the value it last saw to tell whether the
    /// wake-up carries a release it hasn't looked at yet; see
    /// [`Accounting::wait_for_credit`].
    #[must_use]
    pub fn credit_epoch(&self) -> u64 {
        self.credit_epoch.load(Ordering::SeqCst)
    }

    /// Record a credit release and wake one waiter.
    fn release_credit(epoch: &AtomicU64, notify: &Notify) {
        epoch.fetch_add(1, Ordering::SeqCst);
        notify.notify_one();
    }

    /// Credit a peer with the bee-side accepted refresh amount.
    /// Subtracts `accepted` from `balance` (saturating) and bumps
    /// `last_refresh` to `Instant::now()`, opening the per-second
    /// allowance window again.
    pub fn credit(&self, peer: PeerId, accepted: u64) {
        let Ok(mut peers) = self.peers.lock() else {
            return;
        };
        let entry = peers.entry(peer).or_default();
        entry.balance = entry.balance.saturating_sub(accepted);
        entry.time_settled = entry.time_settled.saturating_add(accepted);
        entry.last_refresh = Some(Instant::now());
        drop(peers);
        if accepted > 0 {
            Self::release_credit(&self.credit_epoch, &self.credit_freed);
        }
    }

    /// Drop all per-peer state for `peer`. Called when the swarm
    /// `ConnectionClosed` event fires (peers reconnect with a
    /// fresh balance on bee's side too — bee's
    /// `notifyPeerConnect` resets the `accountingPeer`, so we
    /// should match).
    pub fn forget(&self, peer: &PeerId) {
        let Ok(mut peers) = self.peers.lock() else {
            return;
        };
        peers.remove(peer);
    }

    /// Debt to `peer` cleared by SWAP cheques since it connected, in
    /// accounting units (0 for an unknown peer).
    #[must_use]
    pub fn swap_settled(&self, peer: &PeerId) -> u64 {
        self.peers
            .lock()
            .ok()
            .and_then(|peers| peers.get(peer).map(|b| b.swap_settled))
            .unwrap_or(0)
    }

    /// Move `peer`'s last accepted refresh `by` into the past.
    #[cfg(test)]
    fn backdate_refresh(&self, peer: &PeerId, by: Duration) {
        let mut peers = self.peers.lock().unwrap();
        let entry = peers.get_mut(peer).unwrap();
        entry.last_refresh = entry.last_refresh.and_then(|t| t.checked_sub(by));
    }

    /// Snapshot a peer's balance for diagnostic logging. Returns
    /// `(balance, reserved)`. Cheap (single lock acquisition).
    #[must_use]
    pub fn debug_snapshot(&self, peer: &PeerId) -> Option<(u64, u64)> {
        let peers = self.peers.lock().ok()?;
        peers.get(peer).map(|b| (b.balance, b.reserved))
    }

    /// Every peer a pseudosettle refresh is due to by debt, with the debt
    /// it would clear (bee's `shadowBalance`). Read by the pseudosettle
    /// driver on every tick; see `PeerBalance::refresh_due` for the rule.
    /// Cheap (single lock acquisition).
    #[must_use]
    pub fn refresh_due(&self) -> HashMap<PeerId, u64> {
        let Ok(peers) = self.peers.lock() else {
            return HashMap::new();
        };
        peers
            .iter()
            .filter_map(|(peer, b)| b.refresh_due().map(|debt| (*peer, debt)))
            .collect()
    }

    /// Enumerate every tracked peer as `(peer, balance,
    /// time_settled)` — the outstanding debt we owe the peer and the
    /// cumulative pseudosettle amount it has accepted from us. Backs
    /// the gateway's `/balances`, `/consumed`, and `/timesettlements`
    /// endpoints via `ControlCommand::AccountingSnapshot`. Cheap
    /// (single lock acquisition, one row per connected peer).
    #[must_use]
    pub fn settlement_snapshot(&self) -> Vec<(PeerId, u64, u64)> {
        let Ok(peers) = self.peers.lock() else {
            return Vec::new();
        };
        peers
            .iter()
            .map(|(peer, b)| (*peer, b.balance, b.time_settled))
            .collect()
    }
}

/// RAII guard returned by [`Accounting::try_reserve`]. Wraps the
/// reserved debit; either [`DebitGuard::apply`] is called (debit
/// moves from `reserved` into `balance`) or the guard drops with
/// `applied = false` (reserved is released without touching
/// balance).
///
/// The guard does NOT hold the `peers` lock — the `Mutex` is
/// re-acquired in `apply`/`Drop` for the brief moment of
/// state mutation.
pub struct DebitGuard {
    peer: PeerId,
    price: u64,
    applied: bool,
    balances: SharedBalances,
    hot_hint: Option<mpsc::Sender<HotHint>>,
    credit_freed: Arc<Notify>,
    credit_epoch: Arc<AtomicU64>,
    payment: PaymentSlot,
}

impl DebitGuard {
    /// Mark the debit as applied. Moves `price` from `reserved`
    /// into `balance`. If the new `balance` crosses
    /// [`HOT_DEBT_THRESHOLD`], fire a [`HotHint`] into the
    /// pseudosettle driver so it tracks the peer.
    pub fn apply(mut self) {
        let payer = current_payer(&self.payment);
        let (crossed, cheque) = {
            let Ok(mut peers) = self.balances.lock() else {
                return;
            };
            let entry = peers.entry(self.peer).or_default();
            entry.reserved = entry.reserved.saturating_sub(self.price);
            let prev_balance = entry.balance;
            entry.balance = entry.balance.saturating_add(self.price);
            // Bee's `creditAction.Apply` settles once the expected debt
            // is past the early-payment threshold.
            let expected = entry.balance.saturating_add(entry.reserved);
            let cheque = payer
                .as_ref()
                .and_then(|_| entry.cheque_due(expected, Instant::now()));
            (
                prev_balance < HOT_DEBT_THRESHOLD && entry.balance >= HOT_DEBT_THRESHOLD,
                cheque,
            )
        };
        self.applied = true;
        if let (Some(payer), Some(ticket)) = (payer, cheque) {
            spawn_payment(
                payer,
                self.peer,
                ticket,
                self.balances.clone(),
                self.credit_freed.clone(),
                self.credit_epoch.clone(),
            );
        }
        if crossed {
            if let Some(tx) = &self.hot_hint {
                let _ = tx.try_send(HotHint { peer: self.peer });
            }
        }
    }

    /// Peer this guard is for. Useful for logging.
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
}

impl Drop for DebitGuard {
    fn drop(&mut self) {
        if self.applied {
            return;
        }
        // Cancellation path: release the reservation without
        // touching balance. Mirrors bee's
        // `creditAction.Cleanup` (line 430 of
        // `pkg/accounting/accounting.go`): if the action wasn't
        // applied, just decrement the per-peer reserve. No
        // ghost-balance increment on the *credit* side; the
        // ghost-balance penalty is on bee's *debit* side and is
        // the receiver's concern, not ours.
        let Ok(mut peers) = self.balances.lock() else {
            return;
        };
        if let Some(entry) = peers.get_mut(&self.peer) {
            entry.reserved = entry.reserved.saturating_sub(self.price);
        }
        drop(peers);
        // The released reserve is credit a fetch waiting on this peer
        // can use now.
        Accounting::release_credit(&self.credit_epoch, &self.credit_freed);
    }
}

fn current_payer(slot: &PaymentSlot) -> Option<Arc<dyn RetrievalPayment>> {
    slot.read().ok().and_then(|p| p.clone())
}

/// Run one SWAP payment in the background (bee's `go a.payFunction`)
/// and record its outcome.
fn spawn_payment(
    payer: Arc<dyn RetrievalPayment>,
    peer: PeerId,
    ticket: PaymentTicket,
    balances: SharedBalances,
    credit_freed: Arc<Notify>,
    credit_epoch: Arc<AtomicU64>,
) {
    let amount = ticket.amount;
    tokio::spawn(async move {
        let result = payer.pay(peer, amount).await;
        if let Err(e) = &result {
            tracing::debug!(
                target: "ant_retrieval::accounting",
                %peer,
                amount,
                "SWAP payment failed (debt kept, retried after the back-off): {e}",
            );
        }
        Accounting::payment_done(
            &balances,
            &credit_epoch,
            &credit_freed,
            peer,
            ticket,
            result.is_ok(),
        );
    });
}

/// XOR-distance proximity order between two 32-byte addresses,
/// matching `bee/pkg/swarm/swarm.go::Proximity`. Returns the
/// number of leading zero bits in `a XOR b`, capped at `MAX_PO =
/// 31` (we don't bother with the full 256 because chunk price
/// uses `MAX_PO - po + 1` and any `po >= MAX_PO` collapses to
/// the same minimum price anyway).
fn proximity(a: &[u8; 32], b: &[u8; 32]) -> u64 {
    const MAX_PO: u64 = 31;
    let mut po = 0u64;
    for i in 0..32 {
        let x = a[i] ^ b[i];
        if x == 0 {
            po = po.saturating_add(8);
            if po >= MAX_PO {
                return MAX_PO;
            }
            continue;
        }
        po = po.saturating_add(u64::from(x.leading_zeros()));
        return po.min(MAX_PO);
    }
    MAX_PO
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`RetrievalPayment`] that records every call and answers with
    /// `ok`, after `gate` opens if one is set.
    #[derive(Default)]
    struct Payer {
        calls: Mutex<Vec<(PeerId, u64)>>,
        fail: bool,
        gate: Option<Arc<Notify>>,
    }

    #[async_trait]
    impl RetrievalPayment for Payer {
        async fn pay(&self, peer: PeerId, amount: u64) -> Result<(), String> {
            self.calls.lock().unwrap().push((peer, amount));
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            if self.fail {
                Err("refused".into())
            } else {
                Ok(())
            }
        }
    }

    impl Payer {
        fn calls(&self) -> Vec<(PeerId, u64)> {
            self.calls.lock().unwrap().clone()
        }
    }

    /// Reserve and apply `n` chunks of `price` against `peer`.
    fn take(acc: &Accounting, peer: PeerId, n: usize, price: u64) {
        for _ in 0..n {
            acc.try_reserve(peer, price).expect("admitted").apply();
        }
    }

    /// Let spawned payments run to completion.
    async fn settle_payments() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn paying(payer: &Arc<Payer>) -> Accounting {
        let acc = Accounting::new();
        acc.set_payment(Some(payer.clone() as Arc<dyn RetrievalPayment>));
        acc
    }

    /// Issue #121, bee's `settle`: once the debt reaches the early-payment
    /// threshold, the debt the refresh won't cover is paid with one cheque,
    /// and the debt drops by it, which frees credit for waiting fetches.
    #[tokio::test]
    async fn debt_past_early_payment_is_paid_by_cheque() {
        let payer = Arc::new(Payer::default());
        let acc = paying(&payer);
        let peer = PeerId::random();
        acc.credit(peer, 0); // a refresh has been accepted just now
        take(&acc, peer, 2, 300_000);
        settle_payments().await;
        assert!(
            payer.calls().is_empty(),
            "600 k is below the 675 k early payment"
        );

        let epoch = acc.credit_epoch();
        // As in bee's `PrepareCredit`, the reservation that takes the
        // expected debt to 900 k settles the 600 k already owed.
        // Refreshed under a second ago, nothing of it is due to the
        // refresh yet, so all of it goes into the cheque.
        take(&acc, peer, 1, 300_000);
        settle_payments().await;
        assert_eq!(payer.calls(), vec![(peer, 600_000)]);
        assert_eq!(acc.debug_snapshot(&peer), Some((300_000, 0)));
        assert_eq!(acc.swap_settled(&peer), 600_000);
        assert!(acc.credit_epoch() > epoch, "a paid debt frees credit");
    }

    /// The cheque covers only what the refresh is not expected to: a
    /// light refresh rate per whole second since the last accepted
    /// refresh comes off it, and less than [`MINIMUM_CHEQUE`] (one second
    /// of refresh) is not worth a cheque: it waits for the refresh or for
    /// more debt (issue #131).
    #[tokio::test]
    async fn cheque_leaves_the_refresh_its_share() {
        let payer = Arc::new(Payer::default());
        let acc = paying(&payer);
        let peer = PeerId::random();
        acc.credit(peer, 0);
        acc.backdate_refresh(&peer, Duration::from_millis(1_500));
        take(&acc, peer, 4, 300_000);
        settle_payments().await;
        assert_eq!(
            payer.calls(),
            vec![(peer, 900_000 - LIGHT_REFRESH_RATE_PER_SEC)]
        );
        assert_eq!(acc.debug_snapshot(&peer), Some((750_000, 0)));

        // 2 s since the refresh: 900 k due to it, nothing left to pay.
        let other = PeerId::random();
        acc.credit(other, 0);
        acc.backdate_refresh(&other, Duration::from_millis(2_100));
        take(&acc, other, 3, 300_000);
        // 1 s: 450 k due, 50 k left, under the minimum cheque.
        let third = PeerId::random();
        acc.credit(third, 0);
        acc.backdate_refresh(&third, Duration::from_millis(1_100));
        take(&acc, third, 1, 500_000);
        drop(acc.try_reserve(third, 175_000));
        settle_payments().await;
        assert_eq!(payer.calls().len(), 1, "{:?}", payer.calls());
    }

    /// Issue #131: with a refresh due, bee's sizing (`balance −
    /// refreshDue`) leaves a debt just past the trigger a sliver. That
    /// sliver is not sent as a cheque (on `main` it was: 150 k units, half
    /// a chunk, at the third chunk); the debt waits until the cheque is
    /// worth one second of refresh, and then pays all of it at once.
    #[tokio::test]
    async fn a_sliver_past_the_refresh_waits_for_a_larger_cheque() {
        let payer = Arc::new(Payer::default());
        let acc = paying(&payer);
        let peer = PeerId::random();
        acc.credit(peer, 0);
        acc.backdate_refresh(&peer, Duration::from_millis(1_500));
        // The reservation taking the expected debt to 900 k finds 600 k
        // applied: 150 k past the refresh's share. Not paid.
        take(&acc, peer, 2, 300_000);
        let third = acc.try_reserve(peer, 300_000).expect("admitted");
        settle_payments().await;
        assert_eq!(payer.calls(), Vec::new(), "no cheque for a 150 k sliver");
        // Once that chunk is applied, 450 k is past the refresh's share:
        // one cheque for all of it.
        third.apply();
        settle_payments().await;
        assert_eq!(payer.calls(), vec![(peer, 450_000)]);
        assert_eq!(acc.debug_snapshot(&peer), Some((450_000, 0)));

        // Whatever the debt and the time since the refresh, no cheque is
        // ever smaller than one second of refresh.
        for backdate_ms in [0, 400, 1_000, 1_300, 1_900, 2_000, 2_500, 3_100] {
            for chunks in 1..=8 {
                let payer = Arc::new(Payer::default());
                let acc = paying(&payer);
                let peer = PeerId::random();
                acc.credit(peer, 0);
                acc.backdate_refresh(&peer, Duration::from_millis(backdate_ms));
                for _ in 0..chunks {
                    acc.debit(peer, 290_000);
                }
                settle_payments().await;
                for (_, amount) in payer.calls() {
                    assert!(
                        amount >= MINIMUM_CHEQUE,
                        "cheque of {amount} units ({backdate_ms} ms since the refresh, \
                         {chunks} chunks)",
                    );
                }
            }
        }
    }

    /// While refreshes stall, the floor stops cheques a second sooner than
    /// bee's [`MINIMUM_PAYMENT`] would (PR #139 R1-M1): 3.2 s after the
    /// last accepted refresh a 1.6 M debt leaves 250 k past the refresh's
    /// share, not sent; at 2.2 s the same debt still pays 700 k; from 4 s
    /// not even bee's light ceiling (2.1375 M) is worth a cheque.
    #[tokio::test]
    async fn a_stalled_refresh_stops_cheques_a_second_before_bee() {
        let cheque = |backdate_ms: u64, debt: u64| async move {
            let payer = Arc::new(Payer::default());
            let acc = paying(&payer);
            let peer = PeerId::random();
            acc.credit(peer, 0);
            acc.backdate_refresh(&peer, Duration::from_millis(backdate_ms));
            acc.debit(peer, debt);
            settle_payments().await;
            payer
                .calls()
                .into_iter()
                .map(|(_, a)| a)
                .collect::<Vec<_>>()
        };
        assert_eq!(cheque(2_200, 1_600_000).await, vec![700_000]);
        assert_eq!(cheque(3_200, 1_600_000).await, Vec::<u64>::new());
        assert_eq!(cheque(3_200, 1_800_000).await, vec![450_000]);
        let ceiling = LIGHT_DISCONNECT_LIMIT + LIGHT_REFRESH_RATE_PER_SEC;
        assert_eq!(cheque(4_200, ceiling).await, Vec::<u64>::new());
        // Bee's floor would still pay the first and last of those.
        const { assert!(1_600_000 - 3 * LIGHT_REFRESH_RATE_PER_SEC >= MINIMUM_PAYMENT) };
        assert!(
            ceiling - 4 * LIGHT_REFRESH_RATE_PER_SEC >= MINIMUM_PAYMENT,
            "{ceiling}"
        );
    }

    /// The same stall seen through plain admission (PR #139 R2-M1): once
    /// the refresh is a second old, [`Accounting::try_reserve`] admits up
    /// to `OVERDRAFT_LIMIT + refreshRate` (2.1375 M), so 3.2 s after the
    /// refresh ordinary reservations reach a 1.8 M debt and pay a 450 k
    /// cheque; 4.2 s after it, reserving all the way to the admission
    /// ceiling pays nothing.
    #[tokio::test]
    async fn a_stalled_refresh_through_admission() {
        let run = |backdate_ms: u64| async move {
            let payer = Arc::new(Payer::default());
            let acc = paying(&payer);
            let peer = PeerId::random();
            acc.credit(peer, 0);
            acc.backdate_refresh(&peer, Duration::from_millis(backdate_ms));
            let mut admitted = 0u64;
            while let Some(g) = acc.try_reserve(peer, 300_000) {
                g.apply();
                admitted += 300_000;
            }
            settle_payments().await;
            let calls = payer
                .calls()
                .into_iter()
                .map(|(_, a)| a)
                .collect::<Vec<_>>();
            (admitted, calls)
        };
        const CEILING: u64 = OVERDRAFT_LIMIT + LIGHT_REFRESH_RATE_PER_SEC;
        let (admitted, calls) = run(3_200).await;
        assert!(
            admitted > OVERDRAFT_LIMIT && admitted <= CEILING,
            "{admitted}"
        );
        assert_eq!(
            calls,
            vec![450_000],
            "a cheque from admitted traffic at 3.2 s"
        );
        let (admitted, calls) = run(4_200).await;
        assert!(
            admitted > OVERDRAFT_LIMIT && admitted <= CEILING,
            "{admitted}"
        );
        assert_eq!(
            calls,
            Vec::<u64>::new(),
            "nothing admitted is paid at 4.2 s"
        );
        // The largest debt admission can reach leaves less than a minimum
        // cheque past the refresh's share at 4 s.
        const { assert!(CEILING - 4 * LIGHT_REFRESH_RATE_PER_SEC < MINIMUM_CHEQUE) };
    }

    /// Debt incurred past the overdraft limit (a pushed chunk, debited by
    /// bee once the receipt is in) is recorded, not dropped, so the next
    /// cheque pays it too (PR #126 R1-M2). Here the push debt piles up
    /// while the peer's one payment is in flight.
    #[tokio::test]
    async fn incurred_debt_past_the_limit_is_kept_and_paid() {
        let gate = Arc::new(Notify::new());
        let payer = Arc::new(Payer {
            gate: Some(gate.clone()),
            ..Payer::default()
        });
        let acc = paying(&payer);
        let peer = PeerId::random();
        acc.credit(peer, 0);
        for _ in 0..3 {
            acc.debit(peer, 300_000);
        }
        settle_payments().await;
        assert_eq!(payer.calls(), vec![(peer, 600_000)], "one in flight");

        for _ in 0..10 {
            acc.debit(peer, 300_000);
        }
        const { assert!(3_900_000 > OVERDRAFT_LIMIT) };
        assert_eq!(acc.debug_snapshot(&peer), Some((3_900_000, 0)));
        assert!(
            acc.try_reserve(peer, 1).is_none(),
            "past the limit: retrieval skips the peer"
        );

        gate.notify_one();
        settle_payments().await;
        assert_eq!(acc.debug_snapshot(&peer), Some((3_300_000, 0)));
        acc.debit(peer, 300_000);
        settle_payments().await;
        assert_eq!(
            payer.calls(),
            vec![(peer, 600_000), (peer, 3_300_000)],
            "the debt past the limit is paid by the next cheque"
        );
        gate.notify_one();
        settle_payments().await;
        assert_eq!(acc.debug_snapshot(&peer), Some((300_000, 0)));
    }

    /// A peer never refreshed has its whole debt still due to the refresh
    /// (bee's zero refresh timestamp): no cheque.
    #[tokio::test]
    async fn never_refreshed_peer_is_not_paid() {
        let payer = Arc::new(Payer::default());
        let acc = paying(&payer);
        let peer = PeerId::random();
        take(&acc, peer, 5, 300_000);
        settle_payments().await;
        assert_eq!(payer.calls(), Vec::new());
    }

    /// One payment per peer at a time; while it runs its amount is not
    /// paid again. A failed payment leaves the debt and backs off for
    /// `FAILED_SETTLEMENT_INTERVAL`.
    #[tokio::test]
    async fn one_payment_at_a_time_and_back_off_after_a_failure() {
        let gate = Arc::new(Notify::new());
        let payer = Arc::new(Payer {
            fail: true,
            gate: Some(gate.clone()),
            ..Payer::default()
        });
        let acc = paying(&payer);
        let peer = PeerId::random();
        acc.credit(peer, 0);
        take(&acc, peer, 3, 300_000);
        settle_payments().await;
        take(&acc, peer, 1, 300_000);
        settle_payments().await;
        assert_eq!(payer.calls(), vec![(peer, 600_000)], "one in flight");

        gate.notify_one();
        settle_payments().await;
        assert_eq!(
            acc.debug_snapshot(&peer),
            Some((1_200_000, 0)),
            "failed: debt stays"
        );
        take(&acc, peer, 1, 300_000);
        settle_payments().await;
        assert_eq!(payer.calls().len(), 1, "backing off after the failure");
    }

    /// A payment that finishes after its peer disconnected and came back
    /// (PR #126 R1-M2) leaves the new connection's entry alone: the debt,
    /// and the payment in flight there, are that connection's.
    #[tokio::test]
    async fn a_payment_from_a_previous_connection_does_not_touch_the_new_one() {
        let gate = Arc::new(Notify::new());
        let payer = Arc::new(Payer {
            gate: Some(gate.clone()),
            ..Payer::default()
        });
        let acc = paying(&payer);
        let peer = PeerId::random();
        acc.credit(peer, 0);
        take(&acc, peer, 3, 300_000);
        settle_payments().await;
        assert_eq!(payer.calls().len(), 1, "first connection's payment");

        acc.forget(&peer);
        acc.credit(peer, 0);
        take(&acc, peer, 3, 300_000);
        settle_payments().await;
        assert_eq!(payer.calls().len(), 2, "second connection's payment");

        // The first payment finishes (waiters wake oldest first).
        gate.notify_one();
        settle_payments().await;
        assert_eq!(acc.debug_snapshot(&peer), Some((900_000, 0)));
        take(&acc, peer, 1, 300_000);
        settle_payments().await;
        assert_eq!(
            payer.calls().len(),
            2,
            "the second payment is still in flight: no third"
        );

        gate.notify_one();
        settle_payments().await;
        assert_eq!(acc.debug_snapshot(&peer), Some((600_000, 0)));
        assert_eq!(acc.swap_settled(&peer), 600_000);
    }

    /// Without a payer (no funded chequebook, or the switch off) the
    /// accounting behaves exactly as before issue #121: debt only moves
    /// with refreshes, and admission stops at the same point.
    #[tokio::test]
    async fn without_a_payer_debt_waits_for_the_refresh() {
        let payer = Arc::new(Payer::default());
        let acc = paying(&payer);
        acc.set_payment(None);
        assert!(!acc.pays_with_swap());
        let peer = PeerId::random();
        acc.credit(peer, 0);
        let mut admitted = 0;
        while let Some(g) = acc.try_reserve(peer, 300_000) {
            g.apply();
            admitted += 1;
        }
        settle_payments().await;
        assert_eq!(payer.calls(), Vec::new());
        assert_eq!(admitted, OVERDRAFT_LIMIT / 300_000);
        assert_eq!(acc.swap_settled(&peer), 0);
    }

    fn addr(b: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    }

    #[test]
    fn proximity_identical_addrs_is_max_po() {
        let a = addr(0xab);
        assert_eq!(proximity(&a, &a), 31);
    }

    #[test]
    fn proximity_first_byte_differs() {
        let a = addr(0b1000_0000);
        let b = addr(0b0000_0000);
        assert_eq!(proximity(&a, &b), 0);
    }

    #[test]
    fn proximity_capped_at_max_po() {
        // 8 leading zero bytes = 64 matching bits, far above MAX_PO = 31.
        let mut a = [0u8; 32];
        a[8] = 0x80;
        let b = [0u8; 32];
        assert_eq!(proximity(&a, &b), 31);
    }

    #[test]
    fn peer_price_higher_for_far_peer() {
        let chunk = addr(0xff);
        let close = addr(0xff);
        let far = addr(0x00);
        let close_price = Accounting::peer_price(&close, &chunk);
        let far_price = Accounting::peer_price(&far, &chunk);
        assert!(far_price > close_price);
        // (MAX_PO - po + 1) * BASE_PRICE = (31 - 31 + 1) * 10_000 = 10_000.
        assert_eq!(close_price, 10_000);
        // (MAX_PO - po + 1) * BASE_PRICE = (31 -  0 + 1) * 10_000 = 320_000.
        assert_eq!(far_price, 320_000);
    }

    /// Issue #117: a refill wakes one fetch waiting for credit, not
    /// every fetch parked on the pool. Each woken waiter that got a
    /// reservation passes the wake-up on (`pass_credit`), so a refill
    /// covering `k` chunks wakes `k + 1` waiters in FIFO order.
    #[tokio::test]
    async fn freed_credit_wakes_one_waiter_at_a_time() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let acc = Arc::new(Accounting::new());
        let woken = Arc::new(AtomicUsize::new(0));
        let mut waiters = Vec::new();
        for _ in 0..20 {
            let acc = acc.clone();
            let woken = woken.clone();
            waiters.push(tokio::spawn(async move {
                if acc.wait_for_credit(Duration::from_mins(1)).await {
                    woken.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        let settle = || tokio::time::sleep(Duration::from_millis(50));
        settle().await;
        assert_eq!(woken.load(Ordering::SeqCst), 0);

        // A pseudosettle refresh lands: one waiter, not twenty.
        let p = PeerId::random();
        acc.credit(p, 450_000);
        settle().await;
        assert_eq!(
            woken.load(Ordering::SeqCst),
            1,
            "a refill must not stampede"
        );

        // That waiter got its reservation and hands the wake-up on.
        acc.pass_credit();
        settle().await;
        assert_eq!(woken.load(Ordering::SeqCst), 2);

        // A reservation released unused is freed credit too.
        let g = acc.try_reserve(p, 240_000).expect("admits");
        drop(g);
        settle().await;
        assert_eq!(woken.load(Ordering::SeqCst), 3);

        // An applied debit frees nothing and wakes nobody.
        acc.try_reserve(p, 240_000).expect("admits").apply();
        settle().await;
        assert_eq!(woken.load(Ordering::SeqCst), 3);

        for w in waiters {
            w.abort();
        }
    }

    #[test]
    fn try_reserve_admits_under_limit() {
        let acc = Accounting::new();
        let p = PeerId::random();
        let g = acc.try_reserve(p, 240_000);
        assert!(g.is_some());
        let snap = acc.debug_snapshot(&p).unwrap();
        assert_eq!(snap, (0, 240_000));
        drop(g);
        let snap = acc.debug_snapshot(&p).unwrap();
        assert_eq!(snap, (0, 0), "guard drop should release the reservation");
    }

    #[test]
    fn try_reserve_rejects_over_limit() {
        let acc = Accounting::new();
        let p = PeerId::random();
        // Each call before any successful refresh gets a full 1 s
        // allowance: limit = OVERDRAFT_LIMIT + 450 k = 2.5875 M.
        // 11 chunks × 240 k = 2.64 M crosses it.
        let mut guards = Vec::new();
        for _ in 0..15 {
            if let Some(g) = acc.try_reserve(p, 240_000) {
                guards.push(g);
            }
        }
        assert!(
            !guards.is_empty(),
            "first reservation should always succeed",
        );
        assert!(
            guards.len() < 15,
            "got {} reservations, expected the cap to bite before 15",
            guards.len(),
        );
    }

    #[test]
    fn apply_moves_reserved_to_balance() {
        let acc = Accounting::new();
        let p = PeerId::random();
        let g = acc.try_reserve(p, 240_000).unwrap();
        g.apply();
        let snap = acc.debug_snapshot(&p).unwrap();
        assert_eq!(snap, (240_000, 0));
    }

    #[test]
    fn credit_reduces_balance() {
        let acc = Accounting::new();
        let p = PeerId::random();
        let g = acc.try_reserve(p, 500_000).unwrap();
        g.apply();
        acc.credit(p, 300_000);
        let snap = acc.debug_snapshot(&p).unwrap();
        assert_eq!(snap, (200_000, 0));
    }

    /// Issue #129: a refresh is due only at bee's settle trigger — expected
    /// debt (reservations included) at the early-payment threshold, and at
    /// least one second of refresh applied — and is sized from the applied
    /// debt.
    #[test]
    fn refresh_due_follows_bees_settle_trigger() {
        let acc = Accounting::new();
        let p = PeerId::random();
        assert!(acc.refresh_due().is_empty(), "unknown peer");
        acc.try_reserve(p, 600_000).unwrap().apply();
        assert!(acc.refresh_due().is_empty(), "600 k < early payment");
        // A reservation in flight lifts the expected debt past 675 k; the
        // applied 600 k is at least one second of refresh.
        let g = acc.try_reserve(p, 100_000).unwrap();
        assert_eq!(acc.refresh_due().get(&p), Some(&600_000));
        drop(g);
        assert!(acc.refresh_due().is_empty());
        // Expected debt past the threshold but less than a second of it
        // applied: not worth a refresh yet.
        acc.credit(p, 300_000);
        let g = acc.try_reserve(p, 400_000).unwrap();
        assert!(acc.refresh_due().is_empty(), "300 k applied < 450 k");
        g.apply();
        assert_eq!(acc.refresh_due().get(&p), Some(&700_000));
        acc.credit(p, 700_000);
        assert!(acc.refresh_due().is_empty(), "paid off");
    }

    #[test]
    fn forget_removes_peer_state() {
        let acc = Accounting::new();
        let p = PeerId::random();
        let g = acc.try_reserve(p, 240_000).unwrap();
        g.apply();
        assert!(acc.debug_snapshot(&p).is_some());
        acc.forget(&p);
        assert!(acc.debug_snapshot(&p).is_none());
    }

    #[test]
    fn hot_hint_fires_when_crossing_threshold() {
        let (tx, mut rx) = mpsc::channel::<HotHint>(8);
        let acc = Accounting::new().with_hot_hint(tx);
        let p = PeerId::random();
        // First 3 chunks of 240 k = 720 k, just under HOT_DEBT_THRESHOLD = 843 k.
        for _ in 0..3 {
            acc.try_reserve(p, 240_000).unwrap().apply();
        }
        assert!(rx.try_recv().is_err(), "should not fire below threshold");
        // Fourth chunk crosses the threshold (3 × 240 k + 240 k = 960 k > 843 k).
        acc.try_reserve(p, 240_000).unwrap().apply();
        let hint = rx.try_recv().expect("hot hint should fire");
        assert_eq!(hint.peer, p);
    }
}
