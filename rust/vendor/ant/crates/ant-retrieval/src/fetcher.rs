//! Routing-aware [`ChunkFetcher`] for production use.
//!
//! Wraps a `libp2p_stream::Control` and a static snapshot of
//! `(PeerId, overlay)` peers — the closest BZZ peers we have to *any*
//! target — and exposes a fetch method that:
//!
//! 1. picks the peer whose overlay XORs with the requested chunk address
//!    to the smallest big-endian value (forwarding-Kademlia "closest");
//! 2. opens a `/swarm/retrieval/1.4.0/retrieval` stream, runs the bee
//!    headers handshake, sends a [`crate::PROTOCOL_RETRIEVAL`] request,
//!    and reads the delivery;
//! 3. on failure, falls back to the next-closest peer up to a small
//!    bounded retry count, so a single bad peer doesn't tank a whole
//!    file fetch.
//!
//! The snapshot is taken at command time by the node loop; new BZZ
//! handshakes during the fetch don't show up here, but no in-flight
//! manifest walk is so long-lived that it matters in practice. Re-issuing
//! the command is cheap.

use crate::accounting::{Accounting, DebitGuard, CREDIT_WAIT_BUDGET, OVERDRAFT_REFRESH};
use crate::counters::RetrievalCounters;
use crate::disk_cache::DiskChunkCache;
use crate::priority::{self, Priority};
use crate::progress::ProgressTracker;
use crate::push_skip_cache::{PushSkipCache, DEFAULT_SKIP_TTL};
use crate::pushsync_settlement::{peer_chunk_price, PushCredit, PushsyncSettlement};
use crate::{retrieve_chunk, ChunkFetcher, InMemoryChunkCache, RetrievalError, RetrievedChunk};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use libp2p::PeerId;
use libp2p_stream::Control;
use std::cmp::Ordering;
use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tracing::{debug, trace, warn};

/// 32-byte Swarm overlay. Duplicated locally rather than re-exported from
/// `ant_p2p::routing` to keep `ant-retrieval` free of a circular dep.
pub type Overlay = [u8; 32];

/// Per-chunk error budget, matching bee `maxOriginErrors` in
/// `pkg/retrieval/retrieval.go`. Bee's origin path tolerates up to 32
/// peer errors (Remote / Timeout / Io / `OpenStream`) before giving up
/// on a chunk; we mirror that exactly so behaviour is comparable
/// chunk-for-chunk. Beyond ~32 candidates the chunk is almost
/// certainly not retrievable from our connected set anyway.
const MAX_ORIGIN_ERRORS: usize = 32;

/// How many distinct peers may answer "not found" before a fetch that
/// ended with ranked peers still unasked stops counting as
/// [`FetchExhausted::pool_starved`]. On a cold node one or two peers
/// answer `storage: not found` / `no peer found` for chunks that exist
/// (issue #114); several independent closest-first answers agreeing is
/// the network's answer, even if the rest of the pool was
/// overdraft-skipped. Without this cap a busy node (where *some* ranked
/// peer is nearly always overdraft-skipped) would class every genuinely
/// lost shard as unreached and run the joiner's whole recovery-retry
/// budget before failing.
const STARVED_MAX_NOT_FOUND: usize = 2;

/// Whether a fetch that gave up counts as starved by the peer pool
/// rather than answered by the network: error budget left, ranked
/// peers never asked (all overdraft-skipped), and no more than
/// [`STARVED_MAX_NOT_FOUND`] peers saying the chunk is missing.
const fn pool_starved(errors_left: usize, unasked_ranked: bool, not_found_answers: usize) -> bool {
    errors_left > 0 && unasked_ranked && not_found_answers <= STARVED_MAX_NOT_FOUND
}

/// Idle hedge interval. If the active retrieval stream hasn't returned
/// a delivery within this window we dispatch a single backup peer in
/// parallel. Mirrors bee's `preemptiveInterval = time.Second` from
/// `pkg/retrieval/retrieval.go` exactly.
///
/// History: this used to be 4 s — we widened it deliberately when
/// hedge-induced ghost debits were collapsing the peer set during
/// large-file streaming. The widening worked, but at the cost of
/// per-chunk latency (a tail-slow chunk waited 4 s before getting a
/// second chance). Now that admission control via [`Accounting`]
/// keeps hedges off already-saturated peers (bee's
/// `pkg/retrieval/retrieval.go::case ErrOverdraft` arm in
/// `prepareCredit`), we can match bee's 1 s preemptive cadence
/// without re-introducing the cascade — the worst a 1 s hedge can
/// do now is dispatch a request to a peer with admission headroom,
/// not pile debt onto a hot peer. Hedging remains bounded by the
/// 32-attempt error budget for that single chunk.
const HEDGE_DELAY: Duration = Duration::from_secs(1);

/// How many peers a [`RoutingFetcher::with_fast_miss`] lookup keeps in
/// flight once a peer has answered that the chunk is missing (issue
/// #146). Until then it asks one peer at a time, like every other fetch:
/// most chunks that exist come from the closest peer, so the extra
/// requests are only spent once a miss is likely.
pub const FAST_MISS_FANOUT: usize = 8;

/// How many peers must answer "not found" (`storage: not found` or `no
/// peer found`, [`RetrievalError::is_chunk_not_found`]) before a
/// [`RoutingFetcher::with_fast_miss`] lookup stops and reports the chunk
/// missing, instead of spending the whole [`MAX_ORIGIN_ERRORS`] budget
/// (issue #146). Timeouts, refused streams and other failures don't
/// count: they say nothing about the chunk, so the lookup carries on
/// past them to further peers, as before.
///
/// Why 16 and not "the closest two or three": a light node's closest
/// peers are forwarders, not the chunk's storers, and on mainnet a chunk
/// that exists is sometimes delivered only after several of them said
/// "not found" — of 147 existing feed chunks fetched cold in issue
/// #146's measurements, 5 needed four or more such answers first and one
/// needed fifteen.
/// Sixteen keeps that one, and still ends a miss well before the 32nd
/// answer.
pub const FAST_MISS_NOT_FOUND: usize = 16;

// A fast-miss stop is a corroborated miss (`FetchExhausted::
// corroborated_missing`, which retry loops trust as final), and it comes
// before the error budget runs out.
const _: () =
    assert!(FAST_MISS_NOT_FOUND > STARVED_MAX_NOT_FOUND && FAST_MISS_NOT_FOUND < MAX_ORIGIN_ERRORS);

/// Peers a [`RoutingFetcher::with_fast_miss`] lookup keeps in flight
/// after `not_found_answers` "not found" answers: one until the first,
/// then [`FAST_MISS_FANOUT`].
const fn fast_miss_width(not_found_answers: usize) -> usize {
    if not_found_answers == 0 {
        1
    } else {
        FAST_MISS_FANOUT
    }
}

/// How many requests the error arm wants in flight after a failure, with
/// `in_flight` still outstanding and `errors_left` failures left in the
/// budget (always > 0 here).
///
/// A plain fetch replaces the failed request with one new peer, as bee's
/// `retry()` does, and so does a [`RoutingFetcher::with_fast_miss`]
/// lookup until a peer has said "not found" (it is a plain fetch until
/// then). After that it tops up to [`FAST_MISS_FANOUT`], but never past
/// `errors_left` requests in flight: each outstanding request can still
/// fail and spend one error, so a request beyond that could only be
/// answered after the budget is gone. If enough are already in flight it
/// adds none and waits on them.
const fn backfill_target(
    fast_miss: bool,
    in_flight: usize,
    not_found_answers: usize,
    errors_left: usize,
) -> usize {
    let replace = in_flight + 1;
    if !fast_miss || not_found_answers == 0 {
        return replace;
    }
    let width = fast_miss_width(not_found_answers);
    let want = if replace > width { replace } else { width };
    if want < errors_left {
        want
    } else {
        errors_left
    }
}

/// Whether a [`RoutingFetcher::with_fast_miss`] lookup has heard enough
/// "not found" answers to call the chunk missing now.
const fn fast_miss_done(not_found_answers: usize) -> bool {
    not_found_answers >= FAST_MISS_NOT_FOUND
}

/// Stateful per-call fetcher. Owns a clone of `Control` and a live
/// peer-snapshot subscription via `tokio::sync::watch::Receiver`.
/// Reading from the watch on every `ranked()` call is what keeps the
/// per-chunk peer pool aligned with the swarm's *current* set of BZZ
/// peers. A frozen `Vec<(PeerId, Overlay)>` (the previous design) would
/// drift over the seconds-to-minutes of a multi-MiB fetch and leave us
/// repeatedly trying to open streams on long-dead libp2p connections,
/// surfacing as `oneshot canceled` / `connection is closed` /
/// `Dial error: no addresses for peer` in the retry loop's error
/// messages. The blacklist is still per-fetcher (single retrieval
/// attempt) so misbehaving peers don't get re-tried for sibling chunks
/// of the same request, and it sits behind a `Mutex` because the
/// joiner fans out sibling fetches concurrently against the same
/// `&self` fetcher. We never hold the lock across an `.await`, so a
/// `std::sync::Mutex` is fine and avoids the `tokio::sync::Mutex`
/// overhead.
pub struct RoutingFetcher {
    control: Control,
    /// Live `(PeerId, Overlay)` snapshot of the BZZ peer set. Subscribed
    /// from the swarm's `peers_watch` in `ant-p2p`; tests can hand in a
    /// fixed-value receiver via `RoutingFetcher::with_static_peers`.
    peers_rx: watch::Receiver<Vec<(PeerId, Overlay)>>,
    /// Peers that have failed at least once during this fetch. Used to
    /// rotate through candidates on retry without picking the same dud
    /// peer twice.
    blacklist: Mutex<Vec<PeerId>>,
    /// Optional shared chunk cache. When set, every `fetch` consults
    /// the cache before going to the network and writes back on
    /// success. The daemon holds one cache shared across requests so
    /// re-fetches (within a retry attempt or across `antctl get`
    /// invocations) skip the network entirely.
    cache: Option<Arc<InMemoryChunkCache>>,
    /// Optional persistent (SQLite-backed) tier-2 chunk cache. When
    /// set, the [`ChunkFetcher::fetch`] lookup order is `memory ->
    /// disk -> network`. Disk hits are CAC/SOC-validated before
    /// being returned (a corrupt row is deleted in place and the
    /// fetch falls through to the network). Network successes
    /// write through to both tiers; the writes are dispatched
    /// without blocking the retrieval task.
    ///
    /// `bypass_cache` semantics are honoured by *not* attaching the
    /// disk cache for that request — see
    /// `ant-p2p::behaviour::cache_for_request` for the wiring.
    disk_cache: Option<Arc<DiskChunkCache>>,
    /// When set, every CAC-validated chunk is dumped to
    /// `<dir>/<hex_addr>.bin` (wire bytes: `span || payload`) just
    /// before being returned to the caller. Used by `antd
    /// --record-chunks <dir>` to capture an offline fixture of the
    /// chunks involved in a successful `antctl get`. Best-effort: a
    /// failed write logs a warning but does not break the fetch.
    record_dir: Option<PathBuf>,
    /// Optional shared progress counters. When set, every chunk
    /// returned from this fetcher (network or cache) increments
    /// `chunks_done` / `bytes_done` and — for network fetches —
    /// adds the source peer to the unique-peer set. The daemon
    /// reads from it on a timer to emit `Response::Progress` lines.
    progress: Option<Arc<ProgressTracker>>,
    /// Optional process-wide cap on concurrent `retrieve_chunk`
    /// invocations. The daemon constructs **one** semaphore in
    /// `ant-p2p` and clones it into every fetcher built for any
    /// `GetBytes` / `GetBzz` request, so the cap applies *across*
    /// concurrent requests, not per-request. Without this, two
    /// browser-driven `bzz://` fetches happily race ~64 retrieval
    /// streams (8-wide joiner × 2-wide hedge × 2 files × 2 retries
    /// stacking) — bee-side queueing then makes individual chunks
    /// time out at our 20 s envelope even though the *same chunks*
    /// fetched in 90–200 ms in isolation when probed via
    /// `/chunks/<addr>`. The semaphore tames that stampede; absent
    /// (i.e. `None`), every fetch runs unbounded — appropriate for
    /// unit tests and the (single-request) `antctl get` path.
    inflight_limit: Option<Arc<Semaphore>>,
    /// Per-request cap layered in front of `inflight_limit`. Futures
    /// acquire this semaphore before they enter the process-wide queue,
    /// which prevents one large joiner from filling the global FIFO with
    /// hundreds of descendant chunk fetches while another HTTP request is
    /// still trying to fetch its root or first ordered subtree. A fetch
    /// at the head of a streaming join's window skips it
    /// ([`acquire_request_permit`], issue #46).
    request_inflight_limit: Option<Arc<Semaphore>>,
    /// Notification channel into the pseudosettle driver. When set, every
    /// successful chunk fetch sends the source peer's id, which registers
    /// the peer with the driver. It does not schedule a refresh: with the
    /// accounting mirror attached (as in the daemon), the driver refreshes
    /// a peer only once the mirror's debt to it reaches bee's settle
    /// trigger (`Accounting::refresh_due`), so the debit recorded through
    /// `accounting` is what keeps our per-peer debt below bee's light-mode
    /// `disconnectLimit`. Omitted in unit tests (no real bee on the other
    /// end means there's no debt to settle).
    payment_notify: Option<mpsc::Sender<PeerId>>,
    /// Optional client-side accounting mirror. When set, every
    /// chunk fetch dispatch goes through
    /// [`Accounting::try_reserve`] first; peers whose mirrored
    /// debt would cross
    /// [`crate::accounting::OVERDRAFT_LIMIT`] are skipped for
    /// [`crate::accounting::OVERDRAFT_REFRESH`] and the
    /// next-closest peer is picked instead — exactly bee's
    /// `pkg/retrieval/retrieval.go::case ErrOverdraft` arm.
    /// Omitted in unit tests (no real bee debt to mirror) and
    /// when the daemon's accounting hasn't been constructed
    /// (legacy `antctl get` paths).
    accounting: Option<Arc<Accounting>>,
    /// No credit-waiting fetch or push through this fetcher waits for
    /// credit past this instant ([`RoutingFetcher::with_credit_deadline`]).
    /// Only the credit wait is capped: a push already in flight runs to
    /// its own pushsync timeout, and a fetch's network round trips are
    /// not bounded by it.
    credit_deadline: Option<tokio::time::Instant>,
    /// Process-wide cumulative counters. Bumped on every chunk the
    /// fetcher hands back (network or cache); read by the status
    /// publisher to populate `StatusSnapshot::retrieval` so `antctl
    /// top` can derive instantaneous bandwidth from the snapshot
    /// delta. `None` in unit tests (no daemon); the daemon clones
    /// one shared `Arc` into every fetcher.
    counters: Option<Arc<RetrievalCounters>>,
    /// Optional pushsync-side settlement hook. When `Some`, every push
    /// first asks it for credit with the peer
    /// ([`PushsyncSettlement::prepare_credit`], bee's `PrepareCredit`):
    /// a peer at its credit limit is skipped (issue #128), and every
    /// pushsync receipt — deep or shallow, and one that arrives after the
    /// walk moved on (a losing hedge, a dropped push) — applies the
    /// push's credit, debiting the peer. The fetcher itself stays
    /// ignorant of SWAP / chequebook concerns; the implementation lives
    /// in `ant-p2p::push_pseudosettle`. `None` pushes without credit
    /// checks or debits: unit tests, the ultra-light read-only build
    /// (where the daemon never opens a pushsync stream anyway) and a
    /// chequebook-less node with `ANT_PUSH_PSEUDOSETTLE=0`.
    pushsync_settlement: Option<Arc<dyn PushsyncSettlement>>,
    /// Optional shared push-side peer skip cache. When set,
    /// `push_stamped_chunk` filters its ranked candidate list
    /// against this cache before picking the closest peer for the
    /// chunk. The cache is process-wide, so a peer that just
    /// bounced a pushsync on chunk N is automatically excluded from
    /// chunk N+1's candidate list for the duration of the TTL
    /// (default 5 s). Same `Arc` is cloned into every fetcher
    /// built for `PushChunk` / `PushSoc` so the cool-down survives
    /// across the per-chunk fetcher lifetime. `None` keeps the
    /// legacy per-chunk-only skip behaviour for unit tests.
    push_skip: Option<PushSkipCache>,
    push_load: Option<std::sync::Arc<crate::PushLoadTracker>>,
    /// Neighbourhoods where a deep-storer hunt already ended shallow
    /// (see [`crate::ShallowNeighbourhoods`]).
    shallow_memory: Option<std::sync::Arc<crate::ShallowNeighbourhoods>>,
    /// Swarm network id used to derive the storer overlay when
    /// verifying a pushsync receipt's signature (see
    /// [`crate::pushsync::push_chunk_to_peer`]). `Some(1)` on mainnet;
    /// `None` skips receipt verification entirely, which is what the
    /// unit tests want (a mock peer can't produce a real storer
    /// signature). The daemon sets this so a push only counts as
    /// success when a genuine neighbourhood storer signed the receipt.
    push_network_id: Option<u64>,
    /// Optional on-demand neighbourhood-dial request channel into the swarm
    /// loop. When [`Self::push_stamped_chunk`] is about to push a chunk for
    /// which we have no connected peer inside the chunk's neighbourhood, it
    /// sends the chunk address here; the swarm loop dials the closest peers
    /// it knows about toward that address so the push can land deep (the
    /// way a full bee node's saturated Kademlia always has a near peer).
    /// Best-effort: a full channel drops the request rather than blocking
    /// the push. `None` for retrieval-only fetchers and tests.
    neighborhood_dial: Option<mpsc::Sender<[u8; 32]>>,
    /// Strict receipts (the upload-job path). When `true`,
    /// [`Self::push_stamped_chunk`] never *accepts* a merely-shallow
    /// receipt: after the deeper-storer hunt is exhausted it returns
    /// [`crate::pushsync::PushSyncError::ShallowReceipt`] instead, so the
    /// caller's retry machinery re-queues the chunk and each fresh walk
    /// (with its neighbourhood re-dial cycle) gets another chance to
    /// land a deep receipt. `false` (the default) keeps the bee-aligned
    /// accept-after-budget behaviour for the gateway's parity endpoints.
    /// See [`Self::with_require_deep`] for why the upload path opts in.
    require_deep: bool,
    /// Single-chunk lookup mode ([`Self::with_fast_miss`]).
    fast_miss: bool,
    /// Fired by a push the first time a storer receipts the chunk
    /// shallow ([`Self::with_stored_signal`]).
    stored: Option<Arc<Mutex<Option<oneshot::Sender<()>>>>>,
    /// Test stand-in for [`retrieve_chunk`]: answers each request
    /// instead of the network.
    #[cfg(test)]
    mock_retrieve: Option<MockRetrieve>,
}

/// A test peer's answer to one retrieval request.
#[cfg(test)]
type MockRetrieve = Arc<
    dyn Fn(
            PeerId,
            [u8; 32],
        ) -> futures::future::BoxFuture<'static, Result<RetrievedChunk, RetrievalError>>
        + Send
        + Sync,
>;

impl RoutingFetcher {
    /// Build a fetcher around a `libp2p` stream control and a *live*
    /// peer-snapshot subscription. Every chunk fetch consults
    /// `peers_rx.borrow()` afresh, so peers that disconnect mid-fetch
    /// drop out of the candidate pool the moment the swarm's
    /// `ConnectionClosed` handler fires (rather than sitting in a frozen
    /// list and giving us "connection is closed" errors over and over).
    /// Bee's retrieval works the same way: its skip-list is per-request
    /// and the candidate set is always the *current* forwarding-Kademlia
    /// table.
    ///
    /// The blacklist starts empty — each `RoutingFetcher` is a single
    /// retrieval attempt, so misbehaving peers don't get re-tried for
    /// sibling chunks of the same request, but they're not banned
    /// across attempts either. The retry wrapper in `ant-p2p` constructs
    /// a fresh fetcher per attempt to keep that scoping honest.
    #[must_use]
    pub const fn new(control: Control, peers_rx: watch::Receiver<Vec<(PeerId, Overlay)>>) -> Self {
        Self {
            control,
            peers_rx,
            blacklist: Mutex::new(Vec::new()),
            cache: None,
            disk_cache: None,
            record_dir: None,
            progress: None,
            inflight_limit: None,
            request_inflight_limit: None,
            payment_notify: None,
            accounting: None,
            credit_deadline: None,
            counters: None,
            pushsync_settlement: None,
            push_skip: None,
            push_load: None,
            shallow_memory: None,
            push_network_id: None,
            neighborhood_dial: None,
            require_deep: false,
            fast_miss: false,
            stored: None,
            #[cfg(test)]
            mock_retrieve: None,
        }
    }

    /// Require a *deep* receipt for [`Self::push_stamped_chunk`] to
    /// report success: a chunk whose every receipt is shallow errors
    /// with [`crate::pushsync::PushSyncError::ShallowReceipt`] instead
    /// of being accepted after the retry budget.
    ///
    /// Why the upload-job path opts in: bee accepts a shallow receipt
    /// because a full node's pull-sync migrates the chunk into its true
    /// neighbourhood afterwards. A light node has no pull-sync — a
    /// shallow-accepted chunk stays readable only through the
    /// uploader's own link to the shallow storer, is invisible to the
    /// network's routed lookups, and gets GC'd from the storer's
    /// reserve within hours (observed: a 4 MB upload whose shallow-heavy
    /// chunk set was 404 network-wide a day later). Erroring instead
    /// hands the chunk back to the upload driver's retry-forever queue,
    /// whose every re-dispatch re-runs the gossip-deepening dial cycle
    /// — so the upload only completes when the data is genuinely
    /// placed. The gateway's bee-parity `POST` endpoints keep the
    /// accept-shallow default.
    #[must_use]
    pub const fn with_require_deep(mut self, require_deep: bool) -> Self {
        self.require_deep = require_deep;
        self
    }

    /// Tell `stored` the first time a push of this fetcher draws a
    /// shallow receipt: the chunk is stored from then on, while the push
    /// itself goes on hunting for a deep storer (issue #212). A caller
    /// that only needs the chunk stored, not yet deep, answers on this
    /// and leaves the hunt to finish in the background. A deep receipt
    /// never fires it: the push returns `Ok` then anyway. For one push.
    /// Such a push also hedges sooner until the signal fires: after 1 s,
    /// not bee's 5 s (`STORED_PREEMPTIVE_INTERVAL`). The signal firing
    /// ends that, whatever the receiver does with it: a caller that
    /// still waits for the push to end afterwards (`ant-p2p` does when
    /// every background-hunt slot is taken) waits on the 5 s hedge.
    #[must_use]
    pub fn with_stored_signal(mut self, stored: oneshot::Sender<()>) -> Self {
        self.stored = Some(Arc::new(Mutex::new(Some(stored))));
        self
    }

    /// See [`Self::with_stored_signal`]. Whether this call fired it.
    fn note_stored(&self) -> bool {
        let sender = self.stored.as_ref().and_then(|slot| {
            slot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        });
        sender.is_some_and(|sender| {
            let _ = sender.send(());
            true
        })
    }

    /// The preemptive hedge interval of a push: the short
    /// [`Self::STORED_PREEMPTIVE_INTERVAL`] until its stored signal
    /// ([`Self::with_stored_signal`]) has fired, bee's
    /// [`Self::PREEMPTIVE_INTERVAL`] otherwise, including the hunt for a
    /// deep storer that goes on after it: once answered, nobody waits on
    /// its latency any more, and every hedge is a paid push. The switch
    /// keys off the signal, not the answer: a caller that declines to
    /// answer early on it (`ant-p2p` with every `MAX_BACKGROUND_HUNTS`
    /// slot taken) gets the 5 s hedge for the rest of the push, like a
    /// push without the header, which is what that cap is for: fewer
    /// extra pushes while the node is already busy hunting.
    fn preemptive_interval(&self) -> Duration {
        let waiting = self.stored.as_ref().is_some_and(|slot| {
            slot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
        });
        if waiting {
            Self::STORED_PREEMPTIVE_INTERVAL
        } else {
            Self::PREEMPTIVE_INTERVAL
        }
    }

    /// Single-chunk lookup mode, for a read whose miss is an answer the
    /// caller acts on rather than a failure: the gateway's `/chunks` and
    /// `/soc` reads (Freedom's exact-index `swarm_readFeedEntry` reads
    /// `/chunks/<soc address>`), which a live-stream player polls for the
    /// next feed slot until it is written (issue #146).
    ///
    /// The lookup starts as every fetch does, one closest-first peer at
    /// a time. Once a peer answers that the chunk is missing it keeps
    /// [`FAST_MISS_FANOUT`] peers in flight instead of one, and it stops
    /// at [`FAST_MISS_NOT_FOUND`] "not found" answers instead of running
    /// the whole [`MAX_ORIGIN_ERRORS`] budget one peer after another
    /// (~1.7 s on mainnet). Failures that aren't a "not found" answer
    /// (timeouts, unreachable peers) don't count toward the stop, so the
    /// lookup still falls through them to further peers. Requests still
    /// in flight at the stop are drained, not cut off: a late delivery
    /// lands in the chunk caches, so the next poll is served locally.
    /// Nothing is cached about the miss itself.
    ///
    /// Off by default: a file join fetches chunks that are expected to
    /// exist, and keeping several peers in flight there would mostly buy
    /// duplicate deliveries.
    #[must_use]
    pub const fn with_fast_miss(mut self, fast_miss: bool) -> Self {
        self.fast_miss = fast_miss;
        self
    }

    /// Answer every retrieval request with `f` instead of the network.
    #[cfg(test)]
    #[must_use]
    fn with_mock_retrieve<F>(mut self, f: F) -> Self
    where
        F: Fn(
                PeerId,
                [u8; 32],
            )
                -> futures::future::BoxFuture<'static, Result<RetrievedChunk, RetrievalError>>
            + Send
            + Sync
            + 'static,
    {
        self.mock_retrieve = Some(Arc::new(f));
        self
    }

    /// Attach the on-demand neighbourhood-dial request channel. When set,
    /// [`Self::push_stamped_chunk`] asks the swarm loop to dial peers
    /// toward a chunk's neighbourhood when our connected set has nothing
    /// close enough, so pushes reach the deep neighbourhood instead of
    /// drawing shallow receipts. See the `neighborhood_dial` field.
    #[must_use]
    pub fn with_neighborhood_dialer(mut self, tx: mpsc::Sender<[u8; 32]>) -> Self {
        self.neighborhood_dial = Some(tx);
        self
    }

    /// Set the swarm network id used to verify pushsync receipt
    /// signatures. When set, [`Self::push_stamped_chunk`] only treats a
    /// push as successful if the receipt carries a storer signature
    /// that recovers an overlay genuinely inside the chunk's
    /// neighbourhood. Left unset, receipts are accepted on an address
    /// match alone (the legacy behaviour, used by unit tests whose mock
    /// peers can't sign).
    #[must_use]
    pub fn with_network_id(mut self, network_id: u64) -> Self {
        self.push_network_id = Some(network_id);
        self
    }

    /// Share a memory of neighbourhoods where a deep-storer hunt ended
    /// shallow: best-effort pushes of chunks in them then accept their
    /// first shallow receipt instead of hunting again (see
    /// [`crate::ShallowNeighbourhoods`]).
    #[must_use]
    pub fn with_shallow_memory(
        mut self,
        memory: std::sync::Arc<crate::ShallowNeighbourhoods>,
    ) -> Self {
        self.shallow_memory = Some(memory);
        self
    }

    /// Whether `addr`'s neighbourhood is marked as lacking a reachable
    /// deep storer (see [`crate::ShallowNeighbourhoods`]).
    #[must_use]
    pub fn in_shallow_neighbourhood(&self, addr: &[u8; 32]) -> bool {
        self.shallow_memory
            .as_ref()
            .is_some_and(|m| m.is_marked_any(addr))
    }

    /// Mark `addr`'s neighbourhood at `radius` as lacking a reachable deep
    /// storer: a strict push that had to settle for shallow.
    pub fn mark_shallow_neighbourhood(&self, addr: &[u8; 32], radius: u32) {
        if let Some(m) = &self.shallow_memory {
            m.mark(addr, radius);
        }
    }

    /// Attach the daemon-wide push-side peer skip cache. Same
    /// `PushSkipCache` should be cloned into every fetcher built for
    /// `PushChunk` / `PushSoc` so a peer that just bounced a
    /// pushsync on chunk N is excluded from chunk N+1's candidate
    /// list. See [`PushSkipCache`] for the rationale.
    #[must_use]
    pub fn with_push_skip(mut self, cache: PushSkipCache) -> Self {
        self.push_skip = Some(cache);
        self
    }

    /// Attach the per-peer pushsync load tracker (perf-lab Experiment
    /// 2). When set, `push_candidates` ranks peers at their
    /// latency-aware concurrent-push cap after every other candidate —
    /// so they are picked only if EVERY candidate is saturated — and every
    /// dispatch reports begin/end + latency into the tracker.
    #[must_use]
    pub fn with_push_load(mut self, load: std::sync::Arc<crate::PushLoadTracker>) -> Self {
        self.push_load = Some(load);
        self
    }

    /// Attach a pushsync-side settlement hook. Before every push we ask
    /// it for credit with the peer (`settlement.prepare_credit(peer,
    /// price)`, bee's `PrepareCredit`) and push only to a peer that has
    /// it (issue #128); after every pushsync receipt, deep or shallow,
    /// accepted or not (the storer debits us for each one it writes), we
    /// apply that credit. Payment is best-effort: a failed one does not
    /// fail the upload, it leaves the debt to the refresh, and the credit
    /// check keeps the next pushes inside the peer's limit meanwhile. See
    /// [`PushsyncSettlement`] for the rationale.
    #[must_use]
    pub fn with_pushsync_settlement(mut self, settlement: Arc<dyn PushsyncSettlement>) -> Self {
        self.pushsync_settlement = Some(settlement);
        self
    }

    /// Attach the process-wide retrieval counters. The daemon shares
    /// one `Arc<RetrievalCounters>` across every fetcher it builds;
    /// `antop` reads it from `StatusSnapshot::retrieval`.
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<RetrievalCounters>) -> Self {
        self.counters = Some(counters);
        self
    }

    /// Attach a shared client-side accounting mirror. Once set,
    /// the fetcher consults it on every dispatch decision and
    /// updates per-peer balance on every successful fetch — the
    /// `RoutingFetcher` owns no accounting state of its own, so
    /// the same `Arc<Accounting>` must be shared across all
    /// fetchers built for one daemon process for the mirror to
    /// reflect cross-request debt.
    #[must_use]
    pub fn with_accounting(mut self, accounting: Arc<Accounting>) -> Self {
        self.accounting = Some(accounting);
        self
    }

    /// Cap every credit wait of this fetcher
    /// ([`ChunkFetcher::fetch_waiting_for_credit`]) at `deadline`: past
    /// it, a starved fetch fails at once as plain `fetch` does. For a
    /// request that retries a whole buffered join, so its attempts can't
    /// stack one credit wait each (see
    /// [`crate::accounting::CREDIT_WAIT_BUDGET`]). It caps a push walk's
    /// credit wait the same way, for the gateway's push re-walks (issue
    /// #128).
    #[must_use]
    pub fn with_credit_deadline(mut self, deadline: tokio::time::Instant) -> Self {
        self.credit_deadline = Some(deadline);
        self
    }

    /// Test helper: wrap a fixed peer list in a watch channel. The
    /// returned fetcher behaves identically to the production one but
    /// never sees a peer-set update — appropriate for unit tests where
    /// we drive a `MapFetcher`-style fixture rather than a live swarm.
    /// The `Sender` is dropped immediately; `watch::Receiver::borrow`
    /// keeps returning the seeded value indefinitely afterwards.
    #[cfg(test)]
    #[must_use]
    pub fn with_static_peers(control: Control, peers: Vec<(PeerId, Overlay)>) -> Self {
        let (_tx, rx) = watch::channel(peers);
        Self::new(control, rx)
    }

    /// Attach a shared chunk cache to this fetcher. Chainable so call
    /// sites can write `RoutingFetcher::new(..).with_cache(cache.clone())`
    /// without juggling a second constructor variant. Passing the same
    /// `Arc<InMemoryChunkCache>` to every fetcher built for the same
    /// daemon process is what makes the cache persist across retry
    /// attempts and across `antctl get` invocations.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<InMemoryChunkCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Attach a shared persistent chunk cache (SQLite-backed) as
    /// tier 2. The same `Arc<DiskChunkCache>` should be passed to
    /// every fetcher built for the same daemon process so the
    /// underlying connection (and its byte-total mirror) is shared
    /// rather than rebuilt per request. Omitted when the daemon-
    /// wide disk cache is disabled or when `bypass_cache` is set
    /// for the request — both bypass the disk read *and* the disk
    /// write, exactly per `PLAN.md` § 6.1.
    #[must_use]
    pub fn with_disk_cache(mut self, disk_cache: Arc<DiskChunkCache>) -> Self {
        self.disk_cache = Some(disk_cache);
        self
    }

    /// Dump every successfully-fetched chunk to `dir` as
    /// `<dir>/<hex_addr>.bin` (raw wire bytes: 8-byte LE span ||
    /// payload). Combined with `MapFetcher::from_dir` this lets the
    /// caller replay a real `antctl get` offline. Set by `antd
    /// --record-chunks <dir>` (debug builds only); a `None` value (the
    /// default) is a no-op. The directory is *not* created here — the
    /// caller is responsible for that.
    #[must_use]
    pub fn with_record_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.record_dir = dir;
        self
    }

    /// Hook a [`ProgressTracker`] into this fetcher. Every chunk the
    /// fetcher hands back (cache hit or network success) updates the
    /// tracker; the daemon's progress emitter reads it on a timer.
    /// Pass the same `Arc<ProgressTracker>` to every fetcher built
    /// for the same `Get*` request — the retry-loop wrapper in
    /// `ant-p2p` already does this.
    #[must_use]
    pub fn with_progress(mut self, tracker: Arc<ProgressTracker>) -> Self {
        self.progress = Some(tracker);
        self
    }

    /// Cap concurrent in-flight `retrieve_chunk` calls across every
    /// fetcher that shares this `Arc<Semaphore>`. Pass the same
    /// `Arc<Semaphore>` to every fetcher built within one daemon
    /// process — see `inflight_limit` on the struct for why.
    #[must_use]
    pub fn with_inflight_limit(mut self, sem: Arc<Semaphore>) -> Self {
        self.inflight_limit = Some(sem);
        self
    }

    /// Cap concurrent in-flight `retrieve_chunk` calls for one
    /// user-visible tree join. This is deliberately separate from the
    /// process-wide cap: `ant-p2p` creates one fetcher per `GetBytes` /
    /// `GetBzz` command, so this keeps concurrent browser downloads fair
    /// while still allowing the daemon as a whole to use the network.
    ///
    /// Fetches at the head of a streaming join's window bypass this cap
    /// (issue #46, see [`crate::priority`]): a streaming request can go
    /// over `limit` by its head-window fetches (the chunks within
    /// [`crate::priority::HEAD_WINDOW`] of the read head), their hedges
    /// and a recovery sweep one of them triggers. Those still take a
    /// process-wide permit ([`Self::with_inflight_limit`]). Every other
    /// fetch, including all of a non-streaming join, stays within it.
    #[must_use]
    pub fn with_request_inflight_limit(mut self, limit: usize) -> Self {
        self.request_inflight_limit = Some(Arc::new(Semaphore::new(limit.max(1))));
        self
    }

    /// Wire this fetcher to the daemon's pseudosettle driver. On every
    /// successful chunk fetch, the source peer's id is sent on
    /// `notify_tx`, registering the peer with the driver. With the
    /// accounting mirror attached ([`Self::with_accounting`]) that is all
    /// it does: the driver refreshes
    /// (`/swarm/pseudosettle/1.0.0/pseudosettle`) a peer only once the
    /// mirror's debt to it reaches bee's settle trigger, so the mirror,
    /// not this channel, keeps debt below bee's `disconnectLimit` (~7-30
    /// chunks per peer in light mode — see the 0.3.0 streaming-regression
    /// appendix in `PLAN.md`). Without a mirror a notified peer is
    /// refreshed on the driver's interval. The channel is bounded; if it
    /// backs up the fetcher drops the notification rather than blocking
    /// the hot path.
    #[must_use]
    pub fn with_payment_notify(mut self, notify_tx: mpsc::Sender<PeerId>) -> Self {
        self.payment_notify = Some(notify_tx);
        self
    }

    /// `(peer, overlay)` ordered by ascending XOR distance to `target`,
    /// excluding any peer currently in the blacklist. The blacklist is
    /// snapshotted under the lock and dropped before we await anything.
    /// The peer pool itself is read fresh from the watch on every call
    /// — that's the load-bearing line for "peer disappears mid-fetch":
    /// the next sibling chunk's `ranked()` call automatically excludes
    /// the now-disconnected peer because the swarm's
    /// `ConnectionClosed` handler already published a watch update.
    fn ranked(&self, target: &Overlay) -> Vec<(PeerId, Overlay)> {
        let blacklist = self.blacklist.lock().expect("blacklist mutex poisoned");
        let live_peers = self.peers_rx.borrow();
        let mut ranked: Vec<(PeerId, Overlay)> = live_peers
            .iter()
            .filter(|(p, _)| !blacklist.contains(p))
            .copied()
            .collect();
        drop(live_peers);
        drop(blacklist);
        ranked.sort_by(|(_, a), (_, b)| {
            for i in 0..32 {
                let da = a[i] ^ target[i];
                let db = b[i] ^ target[i];
                if da != db {
                    return da.cmp(&db);
                }
            }
            Ordering::Equal
        });
        ranked
    }

    fn blacklist_peer(&self, peer: PeerId) {
        self.blacklist
            .lock()
            .expect("blacklist mutex poisoned")
            .push(peer);
    }

    /// Hard-failure budget for one chunk's push, matching bee 2.8.0
    /// `pushsync.maxPushErrors` (`pkg/pushsync/pushsync.go`). Bee's
    /// origin `pushToClosest` seeds `sentErrorsLeft = maxPushErrors` and
    /// decrements it on every *failed* send attempt (stream open / io /
    /// remote-rejection), giving up with `ErrNoPush` once it hits zero. A
    /// shallow receipt is **not** a failure and does not consume this
    /// budget. We mirror the value exactly so a chunk is abandoned after
    /// the same number of genuinely-bad peers bee would tolerate.
    const MAX_PUSH_ERRORS: usize = 32;

    /// Preemptive hedge interval, matching bee 2.8.0
    /// `pushsync.preemptiveInterval`. Bee's origin pushToClosest arms a
    /// ticker at this interval and, on every tick, fans the chunk out to
    /// one additional closest peer *concurrently* with the in-flight
    /// attempt(s) — "early replication / opportunistic receipting" from
    /// the pushsync multiplexing design. This is what stops a single
    /// slow-but-not-dead closest storer from pinning the whole upload
    /// (the upload finishes only when its slowest chunk does): rather
    /// than waiting out the full per-attempt deadline, we keep widening
    /// the concurrent attempt set every 5 s and take the first valid
    /// receipt.
    const PREEMPTIVE_INTERVAL: Duration = Duration::from_secs(5);

    /// The preemptive hedge interval of a push answered once stored
    /// ([`Self::with_stored_signal`]): someone is waiting on exactly this
    /// push's first receipt (a live segment, which every later segment
    /// waits behind), so a closest peer that hasn't answered within a
    /// second gets company instead of up to five seconds' grace. On a
    /// live broadcast (issue #212) a push that hung until the 5 s hedge
    /// was what was left of the slowest segments once shallow receipts
    /// no longer held them back.
    const STORED_PREEMPTIVE_INTERVAL: Duration = Duration::from_secs(1);

    /// How many distinct peers may return a *shallow* receipt before we
    /// stop hunting for a deeper storer and accept the chunk as stored.
    ///
    /// A shallow receipt is **not** a failed push: the responding storer
    /// *did* run its `store()` path (reserve-put + sign), so the chunk is
    /// retrievable from that node and its neighbours — it just landed
    /// shallower than the storer's own reported radius (the common cause
    /// on mainnet today is the reserve-doubling feature, where a node
    /// keeps a chunk that hashes into its *sister* neighbourhood). Bee's
    /// own uploader treats this exactly as a soft outcome: its pusher
    /// retries a shallow receipt up to `DefaultRetryCount` (6) times and
    /// then reports the chunk `ChunkSynced` regardless (see
    /// `bee/pkg/pusher/pusher.go::pushDeferred`, the
    /// `pushsync.ErrShallowReceipt` arm). Rejecting shallow receipts
    /// outright — as we did before — made uploads spuriously fail or
    /// thrash through all 64 candidates whenever the chunk's
    /// neighbourhood legitimately answers shallow, which a NAT'd light
    /// node with a ~100-peer view hits routinely. Matching bee's count
    /// keeps us interoperable: we prefer a deep storer when one is
    /// reachable, but accept a shallow (still-retrievable) one rather
    /// than failing the upload.
    ///
    /// Raised above bee's `DefaultRetryCount` because a light node, unlike a
    /// full node, cannot lean on pull-sync to repair a shallow placement
    /// after the fact — a chunk that lands shallow stays readable *by the
    /// uploader* (it's connected to the shallow storer) but not by the wider
    /// network, which routes to the proper neighbourhood. So we spend more
    /// rounds — each preceded by an active neighbourhood dial and, from the
    /// second shallow receipt on, a bounded wait for a deeper peer to
    /// connect (see [`SHALLOW_REDIAL_WAIT`] and `waits_for_deeper_peer`) —
    /// hunting for a deep storer before falling back to accepting shallow.
    const MAX_SHALLOW_ATTEMPTS: u32 = 12;

    /// Bounded wait, after a shallow receipt triggers a neighbourhood dial,
    /// for a peer deeper than the shallow storer to actually connect before
    /// we retry the push. This is one round of the *gossip-deepening cycle*
    /// — the only way a light node (which can't pull-discover peers: bee's
    /// hive is push-only gossip) reaches an arbitrary neighbourhood:
    ///
    /// 1. dial the closest peer we currently *know* toward the chunk,
    /// 2. once it handshakes it broadcasts its own neighbourhood to us over
    ///    hive (a node gossips the peers closest to itself, i.e. even
    ///    closer to our chunk),
    /// 3. those land in `known_dialable`, so the next dial reaches deeper,
    /// 4. repeat until a peer inside the chunk's neighbourhood is connected.
    ///
    /// The previous 800 ms was too short for even step 1: a fresh dial +
    /// BZZ handshake routinely takes 1–2 s, so `best_connected_po` never
    /// improved inside the window and the retry just re-drew the same
    /// shallow set — which is why ~27% of a 10 MB file's chunks stayed
    /// shallow and the public gateway couldn't stream them. 2.5 s lets the
    /// dial complete and the first gossip batch arrive; [`dial_and_await_deeper`]
    /// re-issues the dial on every peer-set change within the window so the
    /// deepening cycle advances across rounds. Chunks whose neighbourhood is
    /// already connected skip the wait entirely, and so does the retry after
    /// a chunk's first shallow receipt, which goes straight to the
    /// next-closest peer (`waits_for_deeper_peer`, issue #212).
    const SHALLOW_REDIAL_WAIT: Duration = Duration::from_millis(2500);

    /// Rank the live peer set closest-first to `chunk_addr`, leaving out
    /// peers already used for this chunk, in the order a push tries them.
    /// The per-process push-skip cache (cross-chunk cool-down) is applied
    /// as a *soft* filter: peers cooling down come after every other
    /// candidate rather than not at all, so a small / flappy network can
    /// still make progress. The first entry is the next peer to push to;
    /// the rest are where a push goes when that one has no credit
    /// (issue #128), one ranked pass instead of one per refusal.
    fn push_candidates(&self, chunk_addr: &[u8; 32], used: &[PeerId]) -> Vec<(PeerId, Overlay)> {
        let live = self.peers_rx.borrow();
        let mut ranked: Vec<(PeerId, Overlay)> = live
            .iter()
            .filter(|(p, _)| !used.contains(p))
            .copied()
            .collect();
        drop(live);
        ranked.sort_by(|(_, a), (_, b)| {
            for i in 0..32 {
                let da = a[i] ^ chunk_addr[i];
                let db = b[i] ^ chunk_addr[i];
                if da != db {
                    return da.cmp(&db);
                }
            }
            Ordering::Equal
        });
        // The push-skip cache's soft filter: cooling peers after fresh
        // ones, each group still closest-first.
        let fresh_first = |group: Vec<(PeerId, Overlay)>| -> Vec<(PeerId, Overlay)> {
            match self.push_skip.as_ref() {
                None => group,
                Some(skip) => {
                    let (mut fresh, cooling): (Vec<_>, Vec<_>) =
                        group.into_iter().partition(|(p, _)| !skip.is_skipped(*p));
                    fresh.extend(cooling);
                    fresh
                }
            }
        };
        // Per-peer in-flight cap (Experiment 2): saturated peers go after
        // every unsaturated one, so concurrent chunks fan out to lower-PO
        // peers instead of stacking debt on the same closest storers.
        // Soft: if EVERY candidate is at cap, they are all still
        // candidates — a small peer set must still make progress.
        if let Some(load) = self.push_load.as_ref() {
            let (unsaturated, saturated): (Vec<_>, Vec<_>) =
                ranked.into_iter().partition(|(p, _)| !load.at_cap(p));
            if unsaturated.is_empty() && !saturated.is_empty() {
                load.note_saturated_fallthrough();
            }
            ranked = fresh_first(unsaturated);
            ranked.extend(fresh_first(saturated));
        } else {
            ranked = fresh_first(ranked);
        }
        ranked
    }

    /// Best-effort request to the swarm loop to dial peers toward `target`'s
    /// neighbourhood. Dropped silently if no dialer is wired or the request
    /// channel is full (the loop is already busy dialing).
    /// Public alias of [`Self::request_neighborhood_dial`] for the
    /// gateway read-retry path (`ant-p2p`, bug-hunt Fix C).
    pub fn request_neighborhood_dial_pub(&self, target: &[u8; 32]) {
        self.request_neighborhood_dial(target);
    }

    fn request_neighborhood_dial(&self, target: &[u8; 32]) {
        if let Some(tx) = self.neighborhood_dial.as_ref() {
            let _ = tx.try_send(*target);
        }
    }

    /// Highest proximity order to `chunk_addr` among the peers we're
    /// currently connected to. A higher value means we have a peer deeper in
    /// the chunk's neighbourhood, so a push is likelier to land deep.
    fn best_connected_po(&self, chunk_addr: &[u8; 32]) -> u8 {
        let live = self.peers_rx.borrow();
        live.iter()
            .map(|(_, overlay)| crate::pushsync::proximity(chunk_addr, overlay))
            .max()
            .unwrap_or(0)
    }

    /// Ask the swarm to dial `chunk_addr`'s neighbourhood, then wait — bounded
    /// by [`Self::SHALLOW_REDIAL_WAIT`] — for a peer at least as deep as
    /// `target_po` (the storer radius a shallow receipt told us about) to
    /// connect, so the next push attempt can reach a deep storer instead of
    /// re-drawing a shallow receipt off the same connected set. Returns early
    /// the moment such a peer is connected; if none arrives in time we retry
    /// anyway against the best we have (the attempt budget still bounds the
    /// hunt). A no-op wait when a deep-enough peer is already connected.
    async fn dial_and_await_deeper(&self, chunk_addr: &[u8; 32], target_po: u8) {
        self.request_neighborhood_dial(chunk_addr);
        if self.best_connected_po(chunk_addr) >= target_po {
            return;
        }
        let mut rx = self.peers_rx.clone();
        let sleep = tokio::time::sleep(Self::SHALLOW_REDIAL_WAIT);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                biased;
                changed = rx.changed() => {
                    if changed.is_err() || self.best_connected_po(chunk_addr) >= target_po {
                        return;
                    }
                    // The peer set moved — a neighbourhood dial connected
                    // and/or fresh hive gossip arrived. Re-issue the dial so
                    // any peer we *now* know that's deeper than our current
                    // best gets pulled in: this is what advances the
                    // gossip-deepening cycle (each nearer peer we connect
                    // advertises even-closer peers). Without re-issuing, the
                    // swarm only ever acts on the peers we knew at the first
                    // request and the cycle stalls one hop short.
                    self.request_neighborhood_dial(chunk_addr);
                }
                () = &mut sleep => return,
            }
        }
    }

    /// Bee's `PrepareCredit` for one push of `price` to `peer` (issue
    /// #128). `Ok(None)` without a settlement hook (nothing is metered),
    /// `Ok(Some(credit))` once the price is reserved, `Err(())` when the
    /// push would take our debt to the peer past its disconnect limit.
    fn prepare_push_credit(&self, peer: PeerId, price: u64) -> Result<Option<PushCredit>, ()> {
        match self.pushsync_settlement.as_ref() {
            None => Ok(None),
            Some(s) => s.prepare_credit(peer, price).map(Some).ok_or(()),
        }
    }

    /// How long one push walk may wait for credit, in total, while every
    /// candidate peer is at its credit limit and nothing is in flight:
    /// [`CREDIT_WAIT_BUDGET`], cut to what is left before the fetcher's
    /// credit deadline ([`Self::with_credit_deadline`]), which the
    /// gateway's push paths set so their re-walks share one budget.
    fn push_credit_budget(&self) -> Duration {
        self.push_credit_left(CREDIT_WAIT_BUDGET)
    }

    /// `left` of a push walk's credit budget, cut to what is left before
    /// the credit deadline right now. Re-read before every nap, not once
    /// per walk: a walk can outlive the deadline with a push in flight
    /// (one peer hanging to its pushsync timeout), and must not nap past
    /// it afterwards.
    fn push_credit_left(&self, left: Duration) -> Duration {
        self.credit_deadline.map_or(left, |deadline| {
            deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(left)
        })
    }

    /// Push one stamped chunk into the network, porting bee 2.8.0's
    /// origin upload path (`pkg/pushsync::pushToClosest(origin=true)`
    /// followed by `pkg/pusher`'s shallow-receipt handling).
    ///
    /// Behaviour, matched to bee:
    /// * **Closest-first, concurrent.** We push to the closest connected
    ///   peer and, every [`PREEMPTIVE_INTERVAL`] (bee `preemptiveInterval`),
    ///   fan out to one more closest peer *concurrently* — bee's
    ///   "preemptive" early-replication hedge. The first valid receipt
    ///   wins; the remaining attempts are handed to a detached drain
    ///   ([`PushInFlight`]) that records the debit of any receipt they
    ///   still return.
    /// * **Shallow receipts are not failures.** A shallow receipt proves a
    ///   storer ran its reserve-put + sign path (so the chunk is stored
    ///   and will be pull-synced through the neighbourhood); it just
    ///   landed shallower than ideal. Like bee's pusher
    ///   (`pushDeferred`/`pushDirect`, the `ErrShallowReceipt` arm) we
    ///   retry for a deeper storer up to [`MAX_SHALLOW_ATTEMPTS`] (bee
    ///   `DefaultRetryCount`) and then **accept** it — bee reports the
    ///   chunk `ChunkSynced` rather than ever failing the upload on a
    ///   shallow receipt. Every shallow receipt is debited to the
    ///   settlement mirror, not just the accepted one: the storer
    ///   applied the debit when it wrote it. Under [`Self::with_require_deep`] (the upload-
    ///   job path) the exhausted hunt returns
    ///   [`PushSyncError::ShallowReceipt`] instead of accepting, so the
    ///   caller's retry queue keeps working the chunk until it lands
    ///   deep.
    /// * **Hard failures** (stream open / io / remote rejection) consume a
    ///   bounded budget ([`MAX_PUSH_ERRORS`], bee `maxPushErrors`); a
    ///   single mid-exchange `Io` gets one same-peer retry first.
    /// * **Credit before every push** (issue #128, bee's `PrepareCredit`),
    ///   with a settlement hook installed: a peer the push would take past
    ///   its disconnect limit is skipped for [`OVERDRAFT_REFRESH`] and the
    ///   next-closest peer is tried, without spending the error budget.
    ///   With every candidate at its limit and nothing in flight, the walk
    ///   waits for credit, at most [`CREDIT_WAIT_BUDGET`] (cut to the
    ///   fetcher's credit deadline), then gives up with
    ///   `no pushsync peer has credit`.
    ///
    /// Does **not** mutate the retrieval blacklist; push uses its own
    /// skip list because a peer that rejects a stamped write may still
    /// serve retrieval traffic.
    pub async fn push_stamped_chunk(
        &self,
        chunk_addr: [u8; 32],
        wire: Vec<u8>,
        stamp: [u8; ant_postage::STAMP_SIZE],
    ) -> Result<(), crate::pushsync::PushSyncError> {
        self.push_stamped_chunk_with_policy(chunk_addr, wire, stamp, self.require_deep)
            .await
    }

    /// [`Self::push_stamped_chunk`] with a per-call receipt policy
    /// override. The gateway's patience loop (`ant-p2p`, bug-hunt Fix
    /// A/B) runs SOC walks strict while its outer budget lasts and
    /// downgrades to shallow-accept for one final walk at the ceiling —
    /// a per-call knob, not a per-fetcher one.
    pub async fn push_stamped_chunk_with_policy(
        &self,
        chunk_addr: [u8; 32],
        wire: Vec<u8>,
        stamp: [u8; ant_postage::STAMP_SIZE],
        require_deep: bool,
    ) -> Result<(), crate::pushsync::PushSyncError> {
        use crate::pushsync::{
            push_chunk_to_peer_with_timeout, PushSyncError, DEFAULT_PUSHSYNC_TIMEOUT,
        };

        // Shared across the concurrent in-flight attempts.
        let wire = Arc::new(wire);
        let stamp = Arc::new(stamp);
        let net = self.push_network_id;

        // Peers already dialled for this chunk (bee's per-chunk skip
        // list): never re-pick the same peer for the same chunk.
        let mut used = Vec::<PeerId>::new();
        // Peers we've already granted the one-shot same-peer transient
        // retry to (so a flapping peer can't loop forever).
        let mut retried = Vec::<PeerId>::new();

        // Hard-failure budget (bee `sentErrorsLeft = maxPushErrors`).
        let mut errors_left: i32 = Self::MAX_PUSH_ERRORS as i32;
        // Distinct peers that rejected the STAMP (phantom-batch
        // signature). Two independent storers agreeing the batch isn't
        // on chain is decisive — abort the walk instead of hedging
        // through the whole candidate set.
        let mut stamp_rejecters: Vec<PeerId> = Vec::new();
        let mut stamp_reject_sample = String::new();
        let mut shallow_attempts: u32 = 0;
        let mut shallow_seen = false;
        // Most recent shallow receipt's (po, storage_radius), so the
        // strict-receipts error can report what the network answered.
        let mut last_shallow = (0u8, 0u32);
        let mut last_err: Option<PushSyncError> = None;

        // In-flight pushsync attempts. Each yields
        // `(peer, overlay, chunk_price, result)`. Whatever is still in
        // flight when this function returns (a winner beat the hedges, the
        // walk gave up, or the caller dropped us) goes to a detached drain
        // that records the debit of every receipt that still arrives:
        // the storer debits us once it has written a receipt, whether or
        // not we are still listening.
        let mut inflight = PushInFlight::new(self.pushsync_settlement.is_some());

        // Peers refused credit for this chunk in the current credit round:
        // bee's `skip.Add(chunk, peer, overDraftRefresh)` after
        // `PrepareCredit` returns `ErrOverdraft` (issue #128). Unlike
        // `used`, the skip ends — at `credit_retry_at`, one
        // `OVERDRAFT_REFRESH` after the round's first refusal, when every
        // one of them may be asked again (bee's `PruneExpiresAfter` and
        // retry) — and it costs no error budget.
        let mut overdrawn: Vec<PeerId> = Vec::new();
        let mut credit_retry_at: Option<tokio::time::Instant> = None;
        // Time spent waiting for credit with every candidate overdrawn and
        // nothing in flight; at most `credit_budget` per walk.
        let mut credit_waited = Duration::ZERO;
        let credit_budget = self.push_credit_budget();

        // `want` is bee's `retryC`: how many fresh attempts to dispatch to
        // the next-closest peers. Seed with one; the preemptive ticker and
        // soft (shallow / failed) outcomes bump it.
        let mut want: i32 = 1;

        let mut preempt = tokio::time::interval(self.preemptive_interval());
        // The first tick fires immediately; consume it so the real hedge
        // doesn't go out until one interval has elapsed.
        preempt.tick().await;

        // Ask the swarm loop to dial peers toward this chunk's
        // neighbourhood so the push can land deep instead of relying on a
        // possibly-shallow forwarding chain. Best-effort and self-limiting:
        // the loop only dials when it knows a peer closer to the chunk than
        // anything we're already connected to, so this is a no-op once
        // we're well-connected to the neighbourhood.
        self.request_neighborhood_dial(&chunk_addr);

        // Dispatch one attempt against `peer`, optionally after a short
        // delay (used for the same-peer transient retry). Pushes the
        // future onto `inflight`.
        macro_rules! dispatch {
            ($peer:expr, $overlay:expr, $price:expr, $credit:expr, $delay_ms:expr) => {{
                let peer = $peer;
                let overlay = $overlay;
                let price = $price;
                let credit: Option<PushCredit> = $credit;
                let mut control = self.control.clone();
                let wire = wire.clone();
                let stamp = stamp.clone();
                let delay_ms: u64 = $delay_ms;
                // Load-book the dispatch SYNCHRONOUSLY so the very next
                // `push_candidates` (for a concurrent chunk) already sees
                // this peer's in-flight count (Experiment 2). The guard
                // moves into the attempt, so the slot is released however
                // the attempt ends — finished, drained, or dropped
                // unfinished (no settlement hook to drain into) — instead
                // of leaking whenever the future is discarded (R4-M1).
                let load_guard = self.push_load.as_ref().map(|l| l.book(peer));
                inflight.futs.push(Box::pin(async move {
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    let started = std::time::Instant::now();
                    let r = push_chunk_to_peer_with_timeout(
                        &mut control,
                        peer,
                        chunk_addr,
                        wire.as_slice(),
                        stamp.as_ref(),
                        net,
                        DEFAULT_PUSHSYNC_TIMEOUT,
                    )
                    .await;
                    if let Some(g) = load_guard {
                        g.finish(started.elapsed());
                    }
                    (peer, overlay, price, credit, r)
                }));
            }};
        }

        loop {
            // A credit round has run out: every peer refused credit in it
            // may be asked again.
            if credit_retry_at.is_some_and(|at| tokio::time::Instant::now() >= at) {
                overdrawn.clear();
                credit_retry_at = None;
            }
            // Fill the requested dispatch slots with the next-closest
            // peers we haven't dialled yet for this chunk, each only once
            // it has credit (bee's `PrepareCredit` before every push,
            // issue #128): a peer this push would take past its
            // disconnect limit is skipped until the round ends and the
            // next-closest one is tried instead. Reserving also starts a
            // payment to the peer when one is due (the mirror's settle
            // step), in the background.
            if want > 0 {
                let excluded: Vec<PeerId> = used.iter().chain(&overdrawn).copied().collect();
                for (peer, overlay) in self.push_candidates(&chunk_addr, &excluded) {
                    if want == 0 {
                        break;
                    }
                    let price = peer_chunk_price(&overlay, &chunk_addr);
                    let Ok(credit) = self.prepare_push_credit(peer, price) else {
                        trace!(
                            target: "ant_retrieval::fetcher",
                            %peer,
                            price,
                            "pushsync: peer is at its credit limit; trying the next-closest peer",
                        );
                        overdrawn.push(peer);
                        continue;
                    };
                    used.push(peer);
                    dispatch!(peer, overlay, price, credit, 0u64);
                    want -= 1;
                }
            }
            // Start the round's clock at its first refusal, whether or not
            // the pass still filled its slots: the skip lasts one
            // `OVERDRAFT_REFRESH` (bee's `skip.Add(.., overDraftRefresh)`),
            // so a later hedge or re-dispatch may ask the refused peer
            // again instead of passing over it for the rest of the walk
            // (PR #138 R2-F1).
            if !overdrawn.is_empty() && credit_retry_at.is_none() {
                credit_retry_at = Some(tokio::time::Instant::now() + OVERDRAFT_REFRESH);
            }
            // When to ask the overdrawn peers again, while a dispatch slot
            // is open for one of them.
            let retry_at = credit_retry_at.filter(|_| want > 0);

            if inflight.futs.is_empty() {
                // Nothing pending and no admissible candidate left. When
                // peers were skipped only for credit, wait for it like
                // bee's `pushToClosest` ("sleeping to refresh overdraft
                // balance") and try them again, at most `credit_budget`
                // per walk and never past the credit deadline (checked
                // now, not only at walk start: a push that hung to its
                // timeout may have outlived it); without a budget left,
                // give up.
                if let Some(at) = retry_at {
                    let left = self.push_credit_left(credit_budget.saturating_sub(credit_waited));
                    if !left.is_zero() {
                        let nap = at
                            .saturating_duration_since(tokio::time::Instant::now())
                            .min(left);
                        debug!(
                            target: "ant_retrieval::fetcher",
                            addr = %hex::encode(chunk_addr),
                            overdrawn = overdrawn.len(),
                            waited_ms = credit_waited.as_millis() as u64,
                            "pushsync: every candidate peer is at its credit limit; waiting for credit",
                        );
                        tokio::time::sleep(nap).await;
                        credit_waited += nap;
                        // The budget is spent: end the round now, so the
                        // last one asks every peer again before giving up.
                        if self
                            .push_credit_left(credit_budget.saturating_sub(credit_waited))
                            .is_zero()
                        {
                            credit_retry_at = Some(tokio::time::Instant::now());
                        }
                        continue;
                    }
                }
                break;
            }

            tokio::select! {
                // Prefer draining results over firing more hedges.
                biased;
                Some((peer, overlay, price, credit, res)) = inflight.futs.next() => {
                    match res {
                        Ok(()) => {
                            if let Some(credit) = credit {
                                credit.apply();
                            }
                            // A peer that just accepted a chunk is healthy
                            // right now: clear any cool-down so the next
                            // chunk ranks it at the top again.
                            if let Some(s) = self.push_skip.as_ref() {
                                s.clear(peer);
                            }
                            return Ok(());
                        }
                        Err(PushSyncError::ShallowReceipt { po, storage_radius }) => {
                            // Not a failure: the storer ran its reserve-put
                            // + sign path, so the chunk is stored. But a light
                            // node can't rely on pull-sync to deepen it later,
                            // so — unlike bee — we work hard to land a deep
                            // receipt now. Do NOT cool-down a shallow peer;
                            // it's a fine storer for chunks in its own
                            // neighbourhood.
                            // The storer debits us once it has written a
                            // receipt, shallow or deep, so every one is
                            // real debt the mirror must record — not just
                            // the one we finally accept (PR #134 R3-M1).
                            if let Some(credit) = credit {
                                credit.apply();
                            }
                            if self.note_stored() {
                                // Answered: back to bee's hedge for the
                                // rest of the hunt.
                                preempt = tokio::time::interval_at(
                                    tokio::time::Instant::now() + Self::PREEMPTIVE_INTERVAL,
                                    Self::PREEMPTIVE_INTERVAL,
                                );
                            }
                            shallow_attempts += 1;
                            shallow_seen = true;
                            last_shallow = (po, storage_radius);
                            warn!(
                                target: "ant_retrieval::fetcher",
                                %peer,
                                po,
                                storage_radius,
                                shallow_attempts,
                                "pushsync got a shallow receipt; chunk stored but shallow — trying for a deeper storer",
                            );
                            let known_shallow = self
                                .shallow_memory
                                .as_ref()
                                .is_some_and(|m| m.is_marked(&chunk_addr, storage_radius));
                            let verdict = shallow_verdict(shallow_attempts, require_deep, known_shallow);
                            if matches!(verdict, ShallowVerdict::AcceptAndMark | ShallowVerdict::Strict) {
                                if let Some(m) = &self.shallow_memory {
                                    m.mark(&chunk_addr, storage_radius);
                                }
                            }
                            match verdict {
                                ShallowVerdict::AcceptKnown => {
                                    debug!(
                                        target: "ant_retrieval::fetcher",
                                        addr = %hex::encode(chunk_addr),
                                        storage_radius,
                                        "accepting shallow receipt: this neighbourhood recently had no reachable deep storer",
                                    );
                                    return Ok(());
                                }
                                ShallowVerdict::Strict => {
                                    // Strict receipts: hand the chunk back to
                                    // the caller's retry queue instead of
                                    // accepting a placement the routed network
                                    // can't see (see `with_require_deep`). The
                                    // debit was recorded above either way.
                                    warn!(
                                        target: "ant_retrieval::fetcher",
                                        addr = %hex::encode(chunk_addr),
                                        shallow_attempts,
                                        "deep receipt required: reporting shallow placement so the upload re-queues the chunk",
                                    );
                                    return Err(PushSyncError::ShallowReceipt { po, storage_radius });
                                }
                                ShallowVerdict::AcceptAndMark => {
                                    warn!(
                                        target: "ant_retrieval::fetcher",
                                        addr = %hex::encode(chunk_addr),
                                        shallow_attempts,
                                        "accepting shallow receipt after deeper-storer attempts (bee-aligned: chunk is stored)",
                                    );
                                    return Ok(());
                                }
                                ShallowVerdict::Hunt => {}
                            }
                            // A shallow receipt is direct evidence we lack a
                            // connected peer in this chunk's neighbourhood.
                            // Dial it, and from the second shallow receipt on
                            // wait (bounded) for a peer at least as deep as
                            // the storer radius to connect before retrying, so
                            // the next attempt can land deep instead of
                            // re-drawing shallow off the same set. The first
                            // retry goes straight to the next-closest peer
                            // (see `waits_for_deeper_peer`).
                            let target_po = storage_radius.min(u32::from(u8::MAX)) as u8;
                            if waits_for_deeper_peer(shallow_attempts) {
                                self.dial_and_await_deeper(&chunk_addr, target_po).await;
                            } else {
                                self.request_neighborhood_dial(&chunk_addr);
                            }
                            want += 1;
                        }
                        Err(e) if is_transient_pushsync_error(&e) && !retried.contains(&peer) => {
                            // One same-peer retry on a fresh stream for a
                            // mid-exchange Io error (the connection was
                            // alive moments ago). It is a new push, so it
                            // needs credit of its own: the failed one's
                            // reservation was released with it.
                            retried.push(peer);
                            drop(credit);
                            if let Ok(credit) = self.prepare_push_credit(peer, price) {
                                warn!(
                                    target: "ant_retrieval::fetcher",
                                    %peer,
                                    err=%e,
                                    "pushsync attempt failed; retrying same peer once on a fresh stream",
                                );
                                dispatch!(peer, overlay, price, credit, 150u64);
                            } else {
                                // No credit for the retry: hedge onto the
                                // next-closest peer instead.
                                last_err = Some(e);
                                want += 1;
                            }
                        }
                        Err(e) => {
                            if is_stamp_rejection(&e) {
                                if !stamp_rejecters.contains(&peer) {
                                    stamp_rejecters.push(peer);
                                }
                                stamp_reject_sample = e.to_string();
                                if stamp_rejecters.len() >= 2 {
                                    let mut batch_id = [0u8; 32];
                                    batch_id.copy_from_slice(&stamp[..32]);
                                    warn!(
                                        target: "ant_retrieval::fetcher",
                                        addr = %hex::encode(chunk_addr),
                                        batch = %hex::encode(batch_id),
                                        rejecters = stamp_rejecters.len(),
                                        "peers reject the postage stamp as an unknown batch — aborting the walk (not retryable)",
                                    );
                                    return Err(PushSyncError::StampRejected {
                                        batch_id,
                                        rejections: stamp_rejecters.len() as u32,
                                        sample: stamp_reject_sample,
                                    });
                                }
                            }
                            warn!(
                                target: "ant_retrieval::fetcher",
                                %peer,
                                err=%e,
                                "pushsync attempt failed; hedging onto the next-closest peer",
                            );
                            // Cross-chunk cool-down so the next chunk
                            // doesn't immediately re-pick a broken peer.
                            if let Some(s) = self.push_skip.as_ref() {
                                s.note_failure(peer, DEFAULT_SKIP_TTL);
                            }
                            errors_left -= 1;
                            last_err = Some(e);
                            if errors_left <= 0 {
                                break;
                            }
                            want += 1;
                        }
                    }
                }
                _ = preempt.tick() => {
                    // Preemptive early-replication hedge: widen the
                    // concurrent attempt set to one more closest peer.
                    want += 1;
                }
                // The credit round ran out while a dispatch slot waits for
                // a peer: ask the overdrawn ones again.
                () = sleep_until_or_never(retry_at) => {}
            }
        }

        // Every candidate was at its credit limit for the whole credit
        // budget and none was pushed to: say so, rather than as a generic
        // exhaustion. The upload job re-queues the chunk; the gateway's
        // patience loop re-walks it.
        if used.is_empty() && !overdrawn.is_empty() {
            debug!(
                target: "ant_retrieval::fetcher",
                addr = %hex::encode(chunk_addr),
                overdrawn = overdrawn.len(),
                waited_ms = credit_waited.as_millis() as u64,
                "pushsync: no candidate peer had credit within the credit budget; giving up the walk",
            );
            return Err(crate::pushsync::no_push_credit_error(
                overdrawn.len(),
                credit_waited,
            ));
        }

        // Candidate set / error budget exhausted. Bee never fails an
        // upload on a shallow receipt — its pusher reports the chunk
        // `ChunkSynced` after the retry budget — so if any storer accepted
        // the chunk (even shallow), treat the push as done. Under strict
        // receipts (`with_require_deep`) the shallow outcome is instead
        // surfaced as an error so the upload driver re-queues the chunk
        // and keeps hunting on the next dispatch.
        if shallow_seen {
            if require_deep {
                let (po, storage_radius) = last_shallow;
                warn!(
                    target: "ant_retrieval::fetcher",
                    addr = %hex::encode(chunk_addr),
                    "deep receipt required: exhausted candidates with only shallow receipts — reporting shallow so the upload re-queues",
                );
                return Err(PushSyncError::ShallowReceipt { po, storage_radius });
            }
            warn!(
                target: "ant_retrieval::fetcher",
                addr = %hex::encode(chunk_addr),
                "accepting shallow receipt after exhausting candidates (bee-aligned: chunk is stored)",
            );
            return Ok(());
        }
        // Perf-lab Experiment 9 (straggler patience): a walk that dies
        // with zero receipts — every candidate connection-killed — is
        // the hostile-neighbourhood straggler signature. Before
        // erroring back to the job's retry queue, ask the swarm to
        // dial deeper toward this chunk and wait (bounded, ≤2.5 s) for
        // anyone deeper than our current best to connect, so the NEXT
        // attempt has a fresh storer instead of re-drawing the same
        // blocklisted trio.
        if straggler_patience() {
            let target = self.best_connected_po(&chunk_addr).saturating_add(1);
            self.dial_and_await_deeper(&chunk_addr, target).await;
        }
        // A walk that ended with nobody accepting AND at least one
        // stamp rejection is classified as a stamp problem: any peer
        // that considered the batch valid would have receipted.
        if let Some(first) = stamp_rejecters.first() {
            let _ = first;
            let mut batch_id = [0u8; 32];
            batch_id.copy_from_slice(&stamp[..32]);
            return Err(PushSyncError::StampRejected {
                batch_id,
                rejections: stamp_rejecters.len() as u32,
                sample: stamp_reject_sample,
            });
        }
        Err(PushSyncError::Remote(format!(
            "exhausted pushsync peers (last: {})",
            last_err.map_or_else(|| "unknown".to_string(), |e| e.to_string()),
        )))
    }
}

/// Sleep until `at`, or forever when there is nothing to wait for (a
/// `select!` arm that never fires).
async fn sleep_until_or_never(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Perf-lab Experiment 9: DEFAULT ON since the verdict (see
/// `ant-node::uploads::straggler_patience`, which the same env var
/// gates). `ANT_PUSH_STRAGGLER_PATIENCE=0` opts out. Read once.
fn straggler_patience() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| match std::env::var("ANT_PUSH_STRAGGLER_PATIENCE") {
        Err(_) => true,
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
    })
}

/// `true` when a peer's pushsync error means it REJECTED THE STAMP —
/// bee's stamp validation failing against its chain-synced batchstore
/// (`invalid stamp: batchstore get: … not found`, `batch not found`,
/// `invalid batch id`…). Message-based because the rejection arrives
/// as bee's free-text `Receipt.err`. Deliberately narrow: only
/// batch-existence/validity phrasings count, not signature/bucket
/// errors (those are OUR bug, not a phantom batch).
fn is_stamp_rejection(err: &crate::pushsync::PushSyncError) -> bool {
    let crate::pushsync::PushSyncError::Remote(m) = err else {
        return false;
    };
    let m = m.to_ascii_lowercase();
    m.contains("invalid stamp")
        && (m.contains("not found") || m.contains("batchstore") || m.contains("unknown batch"))
}

/// `true` for the one `PushSyncError` worth a single fast retry on a
/// fresh stream against the *same* peer: a mid-exchange `Io` error. The
/// stream had already negotiated, so the connection was alive moments ago
/// and a fresh stream on it often goes through — this is the
/// "connection recycled mid-pushsync" case the retry was built for.
///
/// `OpenStream(_)` is **not** transient. An open failure means the
/// connection itself is gone (`libp2p-stream` surfaces it as
/// `oneshot canceled` / `receiver is gone` when the connection handler is
/// dropped, or a dial error when there's no connection at all). Re-opening
/// to the same peer needs a fresh *dial*, which doesn't complete inside
/// the 150 ms retry window — so the retry just re-fails and we skip the
/// peer anyway. A live 28-upload mainnet run made this stark: of 509
/// same-peer retries (overwhelmingly `OpenStream`), ~0 succeeded, and each
/// burned a 150 ms sleep *and* a doomed re-open that itself added to the
/// connection-reset churn. Skipping straight to the next-closest
/// (already-connected) peer is both faster and far more likely to land.
///
/// Explicit `Remote(_)` rejections (the peer told us, on the wire, that
/// it didn't want the chunk) and protocol-level errors (`ProstEncode`,
/// `ProstDecode`, `ReceiptMismatch`) are not transient — retrying just
/// wastes time.
///
/// `Timeout` is not transient either: a peer that opened the stream but
/// didn't relay a receipt within the (already generous) deadline is
/// wedged forwarding the chunk deeper, and an immediate same-peer retry
/// would just burn a second full deadline. The caller skips it and hedges
/// onto the next-closest peer instead, which is both faster and more
/// likely to succeed.
fn is_transient_pushsync_error(err: &crate::pushsync::PushSyncError) -> bool {
    use crate::pushsync::PushSyncError as E;
    matches!(err, E::Io(_))
}

/// What a push does with a shallow receipt (the chunk is stored, but
/// outside its neighbourhood).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShallowVerdict {
    /// Keep hunting for a deep storer (dial the neighbourhood, retry).
    Hunt,
    /// Accept: the hunt is used up. Mark the neighbourhood so the next
    /// chunks in it don't hunt again for a while.
    AcceptAndMark,
    /// Accept at once: a recent hunt in this neighbourhood already found
    /// no reachable deep storer.
    AcceptKnown,
    /// A strict (`require_deep`) push whose hunt is used up: report the
    /// shallow placement so the caller re-queues the chunk.
    Strict,
}

/// Decide a shallow receipt: the `shallow_attempts`-th one for this
/// chunk, on a strict push or not, in a neighbourhood marked as lacking
/// a reachable deep storer or not. Strict pushes never take the
/// neighbourhood shortcut.
const fn shallow_verdict(
    shallow_attempts: u32,
    require_deep: bool,
    known_shallow: bool,
) -> ShallowVerdict {
    if known_shallow && !require_deep {
        ShallowVerdict::AcceptKnown
    } else if !accept_shallow_after(shallow_attempts) {
        ShallowVerdict::Hunt
    } else if require_deep {
        ShallowVerdict::Strict
    } else {
        ShallowVerdict::AcceptAndMark
    }
}

/// Whether the retry after the `shallow_attempts`-th shallow receipt
/// (1-based) first waits, up to [`RoutingFetcher::SHALLOW_REDIAL_WAIT`],
/// for a peer deeper than the shallow storer to connect.
///
/// Not after the first one: that retry goes at once to the next-closest
/// peer, while the neighbourhood dial runs alongside. Measured on
/// mainnet (issue #212): about one chunk in ten drew a shallow first
/// receipt, mostly one bit short of the storer's radius, and the retry
/// landed deep for 84% of them after the wait and for 87-90% with no
/// wait at all. The wait itself nearly always ran its full 2.5 s (no
/// deeper peer connected in time), so it bought nothing there and set a
/// ~2.7 s floor under almost every multi-chunk upload (a 150 KB live
/// segment is ~45 pushes, so one of them nearly always draws a shallow
/// receipt). A chunk that comes back shallow twice is the one that needs
/// the gossip-deepening cycle, and gets the wait from then on.
const fn waits_for_deeper_peer(shallow_attempts: u32) -> bool {
    shallow_attempts > 1
}

/// Given how many distinct peers have answered this chunk with a
/// *shallow* receipt so far (1-based, counting the current one), decide
/// whether to stop hunting for a deeper storer and accept the chunk as
/// stored.
///
/// A shallow receipt is proof the chunk was stored (the storer ran its
/// reserve-put + sign path), so accepting one keeps the chunk
/// retrievable; we only spend a bounded number of attempts looking for a
/// deeper storer first. The threshold matches bee's pusher, which retries
/// a shallow receipt `DefaultRetryCount` (6) times before reporting the
/// chunk synced regardless. See [`RoutingFetcher::MAX_SHALLOW_ATTEMPTS`].
const fn accept_shallow_after(shallow_attempts: u32) -> bool {
    shallow_attempts >= RoutingFetcher::MAX_SHALLOW_ATTEMPTS
}

/// The error [`RoutingFetcher::fetch`] gives up with once its candidate
/// loop ends (`all peers failed for chunk … (last: …)`). The message is
/// unchanged from the plain-string error it replaces; the type adds
/// whether the loop ended because the peer pool was *starved*: ranked
/// peers were left unasked because every one of them was
/// overdraft-skipped, and at most [`STARVED_MAX_NOT_FOUND`] of the peers
/// that were asked answered "not found". A `storage: not found` tail is then one peer's
/// answer, not the network's, so the RS decoder (`crate::rs`) must not
/// read it as the chunk being confirmed missing (issue #114).
///
/// It also records, typed, whether the last peer answer was a miss
/// ([`RetrievalError::is_chunk_not_found`]: `storage: not found` *or*
/// `no peer found`), so callers can tell a confirmed miss
/// ([`Self::confirmed_missing`]) from a transport failure without
/// matching on the message (issue #123).
#[derive(Debug, Clone)]
pub struct FetchExhausted {
    pub(crate) message: String,
    pub pool_starved: bool,
    /// The last peer that answered said the chunk is missing.
    pub last_not_found: bool,
    /// How many distinct peers answered that the chunk is missing.
    /// Tells a miss the network corroborated
    /// ([`Self::corroborated_missing`]) from a cold node's one or two
    /// "not found" answers, which can also be [`Self::confirmed_missing`]
    /// when those were the only ranked peers.
    pub not_found_answers: usize,
}

impl FetchExhausted {
    /// Build one by hand, for fetchers other than [`RoutingFetcher`]
    /// and for tests that stand in for it. A miss counts as one peer's
    /// answer; see [`Self::with_not_found_answers`].
    #[must_use]
    pub fn new(message: impl Into<String>, pool_starved: bool, last_not_found: bool) -> Self {
        Self {
            message: message.into(),
            pool_starved,
            last_not_found,
            not_found_answers: usize::from(last_not_found),
        }
    }

    /// Set how many peers answered "not found" ([`Self::not_found_answers`]).
    #[must_use]
    pub const fn with_not_found_answers(mut self, n: usize) -> Self {
        self.not_found_answers = n;
        self
    }

    /// Peers confirmed the chunk missing: the last answer was a miss and
    /// the fetch wasn't cut short by an overdraft-starved pool. This is
    /// the network's answer, not one cold peer's (issue #114), so it is
    /// final, and the gateway answers bee's 404 for it (issue #123).
    #[must_use]
    pub const fn confirmed_missing(&self) -> bool {
        self.last_not_found && !self.pool_starved
    }

    /// [`Self::confirmed_missing`], and by more than
    /// [`STARVED_MAX_NOT_FOUND`] peers. Only this is safe to stop a
    /// retry loop on at once: a cold node with one or two peers in its
    /// table can have every ranked peer asked (so not starved) and still
    /// hear `no peer found` for a chunk that exists (issue #114), which a
    /// retry with a fresher peer set can serve. A confirmed miss that is
    /// not corroborated is still the answer to report once the retries
    /// run out.
    #[must_use]
    pub const fn corroborated_missing(&self) -> bool {
        self.confirmed_missing() && self.not_found_answers > STARVED_MAX_NOT_FOUND
    }

    /// The `FetchExhausted` behind `e`, found by walking its `source()`
    /// chain, so it is still found when wrapped (`JoinError::FetchChunk`,
    /// `ManifestError::Fetch`, …).
    #[must_use]
    pub fn find<'a>(e: &'a (dyn StdError + 'static)) -> Option<&'a Self> {
        let mut cur = Some(e);
        while let Some(err) = cur {
            if let Some(x) = err.downcast_ref::<Self>() {
                return Some(x);
            }
            cur = err.source();
        }
        None
    }
}

impl std::fmt::Display for FetchExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for FetchExhausted {}

#[async_trait]
impl ChunkFetcher for RoutingFetcher {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        self.fetch_within(addr, Duration::ZERO).await
    }

    async fn fetch_waiting_for_credit(
        &self,
        addr: [u8; 32],
        credit_budget: Duration,
    ) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        let credit_budget = match self.credit_deadline {
            Some(deadline) => {
                credit_budget.min(deadline.saturating_duration_since(tokio::time::Instant::now()))
            }
            None => credit_budget,
        };
        self.fetch_within(addr, credit_budget).await
    }

    /// Only a fetcher with accounting attached can be overdraft-starved,
    /// and so wait for credit — and only until its credit deadline
    /// ([`RoutingFetcher::with_credit_deadline`]): past it,
    /// `fetch_waiting_for_credit` fails at once like plain `fetch`, so a
    /// later whole-join attempt has no wait to stack and its starved
    /// misses keep their full subtree retries (PR #119 R2-M2).
    fn waits_for_credit(&self) -> bool {
        self.accounting.is_some()
            && self
                .credit_deadline
                .is_none_or(|deadline| tokio::time::Instant::now() < deadline)
    }

    /// Store a locally-reconstructed chunk (RS-recovered data shard or a
    /// root rebuilt from a dispersed replica) in the same cache tiers a
    /// successful network fetch would land in, so subsequent fetches —
    /// including retries of the same request — are served locally.
    async fn put_recovered(&self, addr: [u8; 32], wire: &[u8]) {
        if let Some(cache) = self.cache.as_ref() {
            cache.put(addr, wire.to_vec());
        }
        if let Some(disk) = self.disk_cache.as_ref() {
            if let Err(e) = disk.put(addr, wire.to_vec()).await {
                warn!(
                    target: "ant_retrieval::fetcher",
                    chunk = %hex::encode(addr),
                    "disk cache write of recovered chunk failed: {e}",
                );
            }
        }
    }

    /// A fresh fetcher over the same peers, caches, limits and accounting
    /// (see [`RoutingFetcher::detached_copy`]).
    fn detached(&self) -> Option<Arc<dyn ChunkFetcher>> {
        Some(Arc::new(self.detached_copy()))
    }
}

impl RoutingFetcher {
    /// A copy for a fetch that outlives this one's borrow
    /// ([`ChunkFetcher::detached`], a feed probe finishing in the
    /// background, issue #190). It shares every node-wide handle (peer
    /// watch, chunk caches, semaphores, accounting, payment and counters),
    /// so what it fetches is cached and paid for like any retrieval, but
    /// starts with an empty blacklist, none of the request's own state (its
    /// progress tracker, its per-request in-flight cap) and the full
    /// retrieval budget (`fast_miss` off): it finishes a lookup
    /// nobody is waiting on any more, so it may as well run to the end.
    fn detached_copy(&self) -> Self {
        Self {
            control: self.control.clone(),
            peers_rx: self.peers_rx.clone(),
            blacklist: Mutex::new(Vec::new()),
            cache: self.cache.clone(),
            disk_cache: self.disk_cache.clone(),
            record_dir: self.record_dir.clone(),
            progress: None,
            inflight_limit: self.inflight_limit.clone(),
            request_inflight_limit: None,
            payment_notify: self.payment_notify.clone(),
            accounting: self.accounting.clone(),
            credit_deadline: self.credit_deadline,
            counters: self.counters.clone(),
            pushsync_settlement: self.pushsync_settlement.clone(),
            push_skip: self.push_skip.clone(),
            push_load: self.push_load.clone(),
            shallow_memory: self.shallow_memory.clone(),
            push_network_id: self.push_network_id,
            neighborhood_dial: self.neighborhood_dial.clone(),
            require_deep: self.require_deep,
            fast_miss: false,
            stored: self.stored.clone(),
            #[cfg(test)]
            mock_retrieve: self.mock_retrieve.clone(),
        }
    }

    /// The fetch itself, waiting at most `credit_budget` in total for
    /// credit while every candidate peer is overdraft-skipped: zero for
    /// [`ChunkFetcher::fetch`], the caller's budget for
    /// [`ChunkFetcher::fetch_waiting_for_credit`].
    async fn fetch_within(
        &self,
        addr: [u8; 32],
        credit_budget: Duration,
    ) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        if let Some(cache) = self.cache.as_ref() {
            if let Some(bytes) = cache.get(&addr) {
                trace!(
                    target: "ant_retrieval::fetcher",
                    chunk = %hex::encode(addr),
                    "cache hit (memory)",
                );
                if let Some(dir) = self.record_dir.as_ref() {
                    record_chunk(dir, &addr, &bytes);
                }
                if let Some(tracker) = self.progress.as_ref() {
                    tracker.record_chunk(None, bytes.len() as u64);
                }
                if let Some(counters) = self.counters.as_ref() {
                    counters.record_chunk(bytes.len() as u64, crate::ChunkSource::Memory);
                }
                return Ok(bytes);
            }
        }

        // Tier 2: persistent (SQLite) cache. The blocking work runs on
        // the pool inside [`DiskChunkCache::get`] so the retrieval task
        // yields. Disk hits trust stored bytes (same contract as bee's
        // `chunkstore.Get`: validated on wire ingest, not re-hashed on
        // every local read).
        if let Some(disk) = self.disk_cache.as_ref() {
            match disk.get(addr).await {
                Ok(Some(bytes)) => {
                    trace!(
                        target: "ant_retrieval::fetcher",
                        chunk = %hex::encode(addr),
                        "cache hit (disk)",
                    );
                    // Lift the chunk into the in-memory tier so
                    // subsequent fetches in this process don't have to
                    // hit SQLite again.
                    if let Some(cache) = self.cache.as_ref() {
                        cache.put(addr, bytes.clone());
                    }
                    if let Some(dir) = self.record_dir.as_ref() {
                        record_chunk(dir, &addr, &bytes);
                    }
                    if let Some(tracker) = self.progress.as_ref() {
                        tracker.record_chunk(None, bytes.len() as u64);
                    }
                    if let Some(counters) = self.counters.as_ref() {
                        counters.record_chunk(bytes.len() as u64, crate::ChunkSource::Disk);
                    }
                    return Ok(bytes);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        target: "ant_retrieval::fetcher",
                        chunk = %hex::encode(addr),
                        "disk cache read errored, falling through to network: {e}",
                    );
                }
            }
        }

        // Bee-shaped retrieval, lightly tuned for the origin / forwarder
        // split (`bee/pkg/retrieval/retrieval.go`):
        //
        //  - dispatch the closest unasked peer immediately;
        //  - if the chunk hasn't returned within `HEDGE_DELAY`, dispatch
        //    one more peer in parallel and reset the timer (so a really
        //    pathological chunk can build up 2-3 racers, but only after
        //    several seconds of silence on each); whichever returns the
        //    delivery first wins and the remaining streams are dropped;
        //  - on per-stream error, backfill with the next-closest peer
        //    immediately (no timer wait — the racer pool just lost a
        //    slot and we want it filled before the consumer notices);
        //  - the per-chunk skip set keeps growing until either someone
        //    answers, the candidate pool is empty, or `errors_left`
        //    drops to zero.
        //
        // Why we wait `HEDGE_DELAY` instead of bee's `1 s` preemptive
        // ticker: bee dispatches another peer every second on the
        // origin path so a slow forwarder doesn't stall the chunk —
        // but every cancelled inflight stream lands either as an
        // *applied debit* (we read past their write) or a *ghost
        // overdraw* (we don't read, so bee's `debitAction.Cleanup`
        // bumps `accountingPeer.ghostBalance` by the chunk price; cf.
        // `bee/pkg/accounting/accounting.go::debitAction.Cleanup`).
        // Either kind of debit counts against bee's
        // `lightDisconnectLimit` (≈1.69M units). The previous design
        // (1 s preemptive on every chunk that took >1 s) showed up as
        // a peer-set collapse from 100 → 37 over a 4-track media
        // benchmark; widening the hedge window to several seconds
        // dramatically reduces those redundant dispatches without
        // losing the safety net.
        //
        // We deliberately do not implement the `proximity >= radius`
        // multiplex-forward branch from bee's code — that's for nodes
        // that ARE in the chunk's neighbourhood (storage nodes pushing
        // to neighbours). As a light origin we always walk closest-first
        // through forwarder peers.
        let mut asked: Vec<PeerId> = Vec::new();
        let mut errors_left = MAX_ORIGIN_ERRORS;
        let mut last_err: Option<RetrievalError> = None;
        // Peers that answered "not found" / "no peer found" (see
        // `pool_starved`).
        let mut not_found_answers = 0usize;
        // Dispatched requests. If this fetch is dropped mid-flight (an
        // outer `timeout` — a feed probe deadline, `verify_chunks_present`'s
        // per-chunk cap — or a gateway client going away), the guard hands
        // whatever is still in flight to the loser drain instead of
        // dropping it: bee may already have applied the debit for a
        // delivery it is writing, and the mirror must record it (see
        // `InFlight`).
        let abandoned = Arc::new(AtomicBool::new(false));
        let mut in_flight = InFlight::new(
            addr,
            abandoned.clone(),
            self.cache.clone(),
            self.disk_cache.clone(),
            self.record_dir.clone(),
            self.payment_notify.clone(),
        );
        let mut hedge_timer = Box::pin(tokio::time::sleep(HEDGE_DELAY));
        // Per-chunk overdraft skip: a peer landed here when
        // `Accounting::try_reserve` refused to admit the dispatch.
        // The entry expires after `OVERDRAFT_REFRESH` (600 ms),
        // mirroring bee's `pkg/retrieval/retrieval.go::skip.Add`
        // with the `overDraftRefresh` TTL. We also keep the
        // entry in `asked` for the same chunk so we never
        // re-dispatch a saturated peer twice without a refresh
        // having had a chance to land.
        let mut overdraft_skip: std::collections::HashMap<PeerId, std::time::Instant> =
            std::collections::HashMap::new();

        let make_fut = |peer: PeerId, guard: Option<DebitGuard>| {
            let mut control = self.control.clone();
            let sem = self.inflight_limit.clone();
            let request_sem = self.request_inflight_limit.clone();
            let tracker = self.progress.clone();
            let abandoned = abandoned.clone();
            #[cfg(test)]
            let mock = self.mock_retrieve.clone();
            async move {
                let _request_permit = match request_sem {
                    Some(s) => acquire_request_permit(s).await,
                    None => None,
                };
                let _permit = match sem {
                    Some(s) => Some(s.acquire_owned().await.expect("retrieval semaphore closed")),
                    None => None,
                };
                // Still queued at a semaphore when the fetch was won or
                // dropped: nothing reached bee yet, so don't send it now.
                // The reservation releases with the guard. (Only the
                // drain ever sees this error; it discards it.)
                if abandoned.load(AtomicOrdering::Acquire) {
                    let e = RetrievalError::OpenStream("abandoned before dispatch".into());
                    return (peer, Err(e), guard);
                }
                // Count "in flight" only after both semaphore permits
                // are held — fetches still queued at the semaphore are
                // not yet consuming network bandwidth.
                if let Some(t) = tracker.as_ref() {
                    t.begin_fetch();
                }
                #[cfg(test)]
                let r = match mock {
                    Some(mock) => mock(peer, addr).await,
                    None => retrieve_chunk(&mut control, peer, addr).await,
                };
                #[cfg(not(test))]
                let r = retrieve_chunk(&mut control, peer, addr).await;
                if let Some(t) = tracker.as_ref() {
                    t.end_fetch();
                }
                (peer, r, guard)
            }
        };

        // Pick the next-closest live peer that we haven't asked yet for
        // THIS chunk *and* that has admission-control headroom. Reads
        // `peers_rx` afresh on every call so peers that disconnect
        // mid-fetch automatically drop out of the candidate pool, and a
        // peer that gets blacklisted (CAC mismatch, malformed framing)
        // by a sibling chunk's fetcher also disappears here.
        //
        // When [`Accounting`] is attached, the picker calls
        // `try_reserve(peer, price)` for each candidate in proximity
        // order. The first peer that accepts the reservation wins; the
        // returned [`DebitGuard`] is moved into the dispatched future.
        // Peers that refuse the reservation are added to
        // `overdraft_skip` for [`OVERDRAFT_REFRESH`] (600 ms) and the
        // walk continues to the next-closest peer — exactly bee's
        // `pkg/retrieval/retrieval.go` flow when `prepareCredit`
        // returns `ErrOverdraft`.
        let pick_next =
            |asked: &Vec<PeerId>,
             overdraft_skip: &mut std::collections::HashMap<PeerId, std::time::Instant>|
             -> Option<(PeerId, Option<DebitGuard>)> {
                let now = std::time::Instant::now();
                // A look-ahead chunk of a streaming join leaves every
                // peer's last chunk of credit to the head of the window
                // (issue #46). Ranked afresh on every pick: a fetch the
                // consumer has caught up with is the head from now on.
                let headroom = match priority::current() {
                    Priority::LookAhead => crate::accounting::HEAD_CREDIT_RESERVE,
                    Priority::Head | Priority::Unranked => 0,
                };
                // Sweep expired overdraft entries so the candidate set
                // reopens once `lightRefreshRate` has had time to clear
                // the peer's debt on bee's side.
                overdraft_skip.retain(|_, until| now < *until);
                let ranked = self.ranked(&addr);
                for (peer, peer_overlay) in ranked {
                    if asked.contains(&peer) {
                        continue;
                    }
                    if overdraft_skip.contains_key(&peer) {
                        continue;
                    }
                    match self.accounting.as_ref() {
                        Some(acc) => {
                            let price = Accounting::peer_price(&peer_overlay, &addr);
                            if let Some(guard) = acc.try_reserve_leaving(peer, price, headroom) {
                                return Some((peer, Some(guard)));
                            }
                            trace!(
                                target: "ant_retrieval::fetcher",
                                %peer,
                                chunk = %hex::encode(addr),
                                price,
                                "overdraft skip; trying next-closest peer",
                            );
                            overdraft_skip.insert(peer, now + crate::accounting::OVERDRAFT_REFRESH);
                        }
                        None => return Some((peer, None)),
                    }
                }
                None
            };

        // True iff at least one ranked peer is admissible right now —
        // i.e., not in `asked`, not in the overdraft skip set. Used by
        // the "give up" arm of the loop. Doesn't actually try_reserve
        // (cheaper, and avoids burning a reservation we'd discard).
        let candidate_available =
            |asked: &Vec<PeerId>,
             overdraft_skip: &std::collections::HashMap<PeerId, std::time::Instant>|
             -> bool {
                let now = std::time::Instant::now();
                for (peer, _) in self.ranked(&addr) {
                    if asked.contains(&peer) {
                        continue;
                    }
                    if let Some(until) = overdraft_skip.get(&peer) {
                        if now < *until {
                            continue;
                        }
                    }
                    return true;
                }
                false
            };

        // Initial dispatch. With no peers at all there is nothing to
        // wait for; with peers that are all overdraft-skipped, the loop
        // below waits for credit if this fetch has a credit budget
        // (issue #117), and otherwise fails at once as a starved
        // `FetchExhausted`.
        match pick_next(&asked, &mut overdraft_skip) {
            Some((peer, guard)) => {
                asked.push(peer);
                in_flight.push(make_fut(peer, guard));
            }
            None if overdraft_skip.is_empty() => return Err("no BZZ peers available".into()),
            None => {}
        }
        // Total time this fetch has spent waiting for credit, against
        // `credit_budget`.
        let mut credit_waited = Duration::ZERO;
        // The credit-release count (`Accounting::credit_epoch`) this
        // fetch last looked at the pool after; see the hand-off below.
        let mut seen_epoch: Option<u64> = None;

        loop {
            // Loop exit when we've burned the error budget AND have
            // nothing else racing. Mirrors bee's `for errorsLeft > 0`
            // outer loop with the "continue if inflight" inner check.
            if errors_left == 0 && in_flight.is_empty() {
                break;
            }
            // No more candidates and nothing inflight → can't possibly
            // succeed *now*. This is bee's `topology.ErrNotFound` arm.
            // Bee then checks whether any of the peers it ran out of are
            // only overdraft-skipped (`skip.PruneExpiresAfter(chunk,
            // overDraftRefresh) != 0`); if so it sleeps
            // `overDraftRefresh` and tries again, and it only gives up
            // when every peer was really asked. We do the same while the
            // pool is starved (the condition `FetchExhausted::pool_starved`
            // reports), within `credit_budget`: on a cold node every
            // peer admits ~5 chunks before pseudosettle refills it, and
            // giving up at once turned each such miss into an
            // erasure-recovery sweep or a 502 (issue #117). The budget
            // is zero for plain `fetch`, which never waits; only
            // `fetch_waiting_for_credit` callers opt in.
            if in_flight.is_empty() && !candidate_available(&asked, &overdraft_skip) {
                let starved = pool_starved(
                    errors_left,
                    self.ranked(&addr).iter().any(|(p, _)| !asked.contains(p)),
                    not_found_answers,
                );
                let Some(acc) = self.accounting.as_ref() else {
                    break;
                };
                if !starved || credit_waited >= credit_budget {
                    break;
                }
                if credit_waited.is_zero() {
                    debug!(
                        target: "ant_retrieval::fetcher",
                        chunk = %hex::encode(addr),
                        asked = asked.len(),
                        "every candidate peer overdraft-skipped; waiting for credit",
                    );
                }
                let started = tokio::time::Instant::now();
                let woken = acc
                    .wait_for_credit(
                        OVERDRAFT_REFRESH.min(credit_budget.saturating_sub(credit_waited)),
                    )
                    .await;
                credit_waited += started.elapsed();
                // Has credit been released since this fetch last looked?
                // Read before `pick_next`, so a release racing the pick
                // counts as unseen next time.
                let epoch = acc.credit_epoch();
                let unseen = seen_epoch != Some(epoch);
                seen_epoch = Some(epoch);
                // Every skip entry is due again: bee prunes them all
                // before its retry, too.
                overdraft_skip.clear();
                let picked = pick_next(&asked, &mut overdraft_skip);
                // Hand the wake-up on (one waiter, not all of them) only
                // if this fetch was actually woken by it; one that woke
                // on its own timer holds no wake-up to pass, and passing
                // one would store a spurious permit for the next waiter.
                //  - Got a reservation: the credit may cover more than
                //    this chunk.
                //  - Couldn't use it (the freed peer isn't one of our
                //    candidates, or was already asked for this chunk):
                //    someone behind us may be able to, so don't swallow
                //    it. But only for a release we haven't looked at
                //    yet: waiters re-queue at the back, so a wake-up
                //    nobody can use goes round each waiter once and then
                //    stops, instead of ping-ponging until the budget
                //    runs out.
                if woken && (picked.is_some() || unseen) {
                    acc.pass_credit();
                }
                if let Some((peer, guard)) = picked {
                    trace!(
                        target: "ant_retrieval::fetcher",
                        %peer,
                        chunk = %hex::encode(addr),
                        waited_ms = credit_waited.as_millis() as u64,
                        "credit came free; dispatching",
                    );
                    asked.push(peer);
                    in_flight.push(make_fut(peer, guard));
                    // The hedge timer ran down while we waited; don't
                    // let it hedge the fresh dispatch at once.
                    hedge_timer = Box::pin(tokio::time::sleep(HEDGE_DELAY));
                }
                continue;
            }

            tokio::select! {
                biased;
                Some((peer, result, guard)) = in_flight.next() => {
                    match result {
                        Ok(chunk) => {
                            // Apply the accounting debit now that we
                            // know the chunk arrived: mirrors bee's
                            // `creditAction.Apply()` from
                            // `pkg/accounting/accounting.go:337`.
                            // Bumps balance, fires hot hint into
                            // pseudosettle if the peer just crossed
                            // HOT_DEBT_THRESHOLD.
                            if let Some(g) = guard {
                                g.apply();
                            }
                            // Cancel-tolerant hedging. Instead of
                            // `drop(in_flight)`, hand the remaining
                            // futures to a detached drain task that
                            // reads each loser's delivery message to
                            // completion before letting the future drop.
                            //
                            // Why: bee's retrieval handler in
                            // `pkg/retrieval/retrieval.go::handler`
                            // calls `accounting.PrepareDebit` *before*
                            // `WriteMsgWithContext(&Delivery{...})`,
                            // and only then `debit.Apply()`. If we drop
                            // the future mid-write, bee's write fails,
                            // `Apply()` doesn't run, and bee's deferred
                            // `debit.Cleanup()` increments
                            // `accountingPeer.ghostBalance` by the chunk
                            // price — which counts against
                            // `lightDisconnectLimit` exactly like real
                            // debt does, but pseudosettle does NOT clear
                            // ghostBalance. The result was a peer-set
                            // collapse from 100 → 36 over a four-track
                            // benchmark even with HEDGE_DELAY = 4 s.
                            //
                            // By draining the loser to completion we
                            // turn the cancellation into a real applied
                            // debit on bee's side. Pseudosettle clears
                            // those, and the peer set stays warm.
                            //
                            // The drain task also write-throughs cached
                            // wire bytes (free, CAC-validated) and
                            // notifies pseudosettle for every success,
                            // so hot peers stay debt-cleared even when
                            // they lose the race.
                            in_flight.drain_in_background();
                            let mut wire = Vec::with_capacity(8 + chunk.payload().len());
                            wire.extend_from_slice(&chunk.span_bytes());
                            wire.extend_from_slice(chunk.payload());
                            if let Some(cache) = self.cache.as_ref() {
                                cache.put(addr, wire.clone());
                            }
                            // Tier-2 write-through. We dispatch this on a
                            // detached `tokio::spawn` so the blocking
                            // SQLite write doesn't sit on the retrieval
                            // task's critical path — the caller sees
                            // `Ok(wire)` the moment the in-memory cache
                            // is populated. Errors are logged but not
                            // propagated; a failed disk write only loses
                            // a future cache hit, never the current
                            // chunk.
                            if let Some(disk) = self.disk_cache.as_ref() {
                                let disk = disk.clone();
                                let wire_clone = wire.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = disk.put(addr, wire_clone).await {
                                        warn!(
                                            target: "ant_retrieval::fetcher",
                                            chunk = %hex::encode(addr),
                                            "disk cache write-through failed: {e}",
                                        );
                                    }
                                });
                            }
                            if let Some(dir) = self.record_dir.as_ref() {
                                record_chunk(dir, &addr, &wire);
                            }
                            if let Some(tracker) = self.progress.as_ref() {
                                tracker.record_chunk(Some(peer), wire.len() as u64);
                            }
                            if let Some(counters) = self.counters.as_ref() {
                                counters.record_chunk(wire.len() as u64, crate::ChunkSource::Network);
                            }
                            // Register the peer with the pseudosettle
                            // driver. `try_send` keeps the hot path
                            // strictly non-blocking; a dropped
                            // notification is harmless with the mirror
                            // attached, since the driver schedules
                            // refreshes off the mirror's debt (the
                            // debit applied above), not off this
                            // channel.
                            if let Some(notify) = self.payment_notify.as_ref() {
                                let _ = notify.try_send(peer);
                            }
                            return Ok(wire);
                        }
                        Err(e) => {
                            // Drop the guard: error means the request
                            // never reached bee's `PrepareDebit`, so
                            // bee's `creditAction.Cleanup` has already
                            // released its reserve too. Our reservation
                            // releases via guard's Drop impl.
                            drop(guard);
                            let blacklist = is_peer_fatal(&e);
                            debug!(
                                target: "ant_retrieval::fetcher",
                                %peer,
                                chunk = %hex::encode(addr),
                                blacklist,
                                inflight = in_flight.len(),
                                errors_left,
                                "fetch failed: {e}",
                            );
                            if blacklist {
                                self.blacklist_peer(peer);
                            }
                            if is_link_failure(&e) {
                                if let Some(counters) = self.counters.as_ref() {
                                    counters.record_link_failure();
                                }
                            }
                            if e.is_chunk_not_found() {
                                not_found_answers += 1;
                            }
                            last_err = Some(e);
                            errors_left = errors_left.saturating_sub(1);
                            // Single-chunk lookup: enough peers said the
                            // chunk is missing (issue #146). Whatever is
                            // still in flight goes to the drain.
                            if self.fast_miss && fast_miss_done(not_found_answers) {
                                break;
                            }
                            if errors_left == 0 {
                                continue;
                            }
                            // Backfill immediately on error: don't wait
                            // for the next preemptive tick. Mirrors bee's
                            // `retry()` call inside the error arm. A
                            // single-chunk lookup tops up per
                            // `backfill_target`.
                            let target = backfill_target(
                                self.fast_miss,
                                in_flight.len(),
                                not_found_answers,
                                errors_left,
                            );
                            while in_flight.len() < target {
                                let Some((peer, guard)) = pick_next(&asked, &mut overdraft_skip) else {
                                    break;
                                };
                                asked.push(peer);
                                in_flight.push(make_fut(peer, guard));
                            }
                        }
                    }
                }
                () = &mut hedge_timer, if errors_left > 0 => {
                    // Tail-slow chunk: layer one more peer onto the race.
                    // Reset the timer so the next hedge needs another
                    // full HEDGE_DELAY of silence before firing — we
                    // don't want a single stuck chunk to spin up 32
                    // hedges in a tight loop.
                    if let Some((peer, guard)) = pick_next(&asked, &mut overdraft_skip) {
                        asked.push(peer);
                        in_flight.push(make_fut(peer, guard));
                    }
                    hedge_timer = Box::pin(tokio::time::sleep(HEDGE_DELAY));
                }
            }
        }

        // Starved: we stopped with error budget left and ranked peers we
        // never asked — they were all overdraft-skipped — and too few of
        // the peers we did ask said "not found" to call it the network's
        // answer. Then the pool, not the network, ended this fetch.
        let pool_starved = pool_starved(
            errors_left,
            self.ranked(&addr).iter().any(|(p, _)| !asked.contains(p)),
            not_found_answers,
        );
        if !credit_waited.is_zero() && credit_waited >= credit_budget {
            debug!(
                target: "ant_retrieval::fetcher",
                chunk = %hex::encode(addr),
                asked = asked.len(),
                pool_starved,
                "credit wait budget exhausted; giving up",
            );
        }
        Err(Box::new(exhausted(
            addr,
            asked.len(),
            last_err,
            pool_starved,
            not_found_answers,
        )))
    }
}

/// Take a permit from the request's own in-flight cap
/// (`request_inflight_limit`), unless the fetch is at the head of a
/// streaming join's window ([`crate::priority`], issue #46).
///
/// A head fetch skips this queue: on a large file the joiner's nested
/// fan-out keeps far more fetches going than the cap admits, and the
/// queue is first come, first served, so the chunk the consumer waits
/// for would otherwise queue behind look-ahead fetches started before
/// it. Head fetches are few (the chunks within
/// [`priority::HEAD_WINDOW`] of the read head, their hedges, and a
/// recovery sweep one of them triggers), so the request goes over its
/// cap by that much at most; the process-wide cap still applies to
/// them. A look-ahead fetch queues as before, keeping its place in the
/// queue for as long as it waits, and leaves it the moment the consumer
/// catches up with it ([`priority::until_head`]: woken by the read
/// head's advance, not by polling). An unranked fetch (outside a
/// streaming join) queues as before.
async fn acquire_request_permit(sem: Arc<Semaphore>) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let acquire = async {
        sem.acquire_owned()
            .await
            .expect("request retrieval semaphore closed")
    };
    match priority::current() {
        Priority::Head => None,
        Priority::Unranked => Some(acquire.await),
        Priority::LookAhead => {
            // One `Acquire` future for the whole wait: dropping and
            // re-creating it would send the fetch to the back of the
            // FIFO queue each time.
            tokio::select! {
                biased;
                permit = acquire => Some(permit),
                () = priority::until_head() => None,
            }
        }
    }
}

/// The error a fetch that asked `asked` peers gives up with. Never got a
/// peer to ask (the pool stayed overdraft-skipped for the whole credit
/// wait): same message as the immediate no-candidate exit, so the
/// gateway and feed classification read it the same way.
pub(crate) fn exhausted(
    addr: [u8; 32],
    asked: usize,
    last_err: Option<RetrievalError>,
    pool_starved: bool,
    not_found_answers: usize,
) -> FetchExhausted {
    let last_not_found = last_err
        .as_ref()
        .is_some_and(RetrievalError::is_chunk_not_found);
    let message = if asked == 0 {
        "no BZZ peers available".to_string()
    } else {
        format!(
            "all peers failed for chunk {} after {asked} attempts (last: {})",
            hex::encode(addr),
            last_err.map_or_else(|| "no candidates".into(), |e| e.to_string())
        )
    };
    FetchExhausted {
        message,
        pool_starved,
        last_not_found,
        not_found_answers,
    }
}

/// Classify a retrieval failure as "this peer is broken" (true) vs
/// "this peer just couldn't help with this one chunk" (false). The
/// fetcher only adds peers to the cross-chunk blacklist for the
/// former; the latter group stays in the candidate pool for sibling
/// chunks of the same request, which dramatically widens the effective
/// peer set on multi-chunk file fetches where a peer's chunk coverage
/// is sparse but not non-existent.
///
/// `Remote(_)` is the load-bearing case here: bee returns
/// `storage: not found` whenever its own forwarding attempt couldn't
/// locate the chunk within its retry budget — that's a property of
/// the chunk's locality, not a property of the peer's health, so
/// banning the peer for the rest of the request is wasteful.
/// `Timeout` likewise often reflects a deep forwarding hop that
/// stalled, not the local peer being broken.
///
/// `Io(_)` is *also* non-fatal, and this is the load-bearing addition
/// that fixed the "WAV files won't load" production regression: bee
/// signals "I don't have this chunk" by closing the `libp2p_stream`
/// without writing the protobuf reply. Our reader then surfaces
/// `UnexpectedEof` (most common) or `BrokenPipe` / `ConnectionReset`
/// (when the close races our read), all of which surface here as
/// `Io(_)`. Treating those as peer-fatal blacklisted ~3 peers per
/// chunk on a multi-MiB media file: we observed 292 distinct peers
/// blacklisted in a single 90-second `/bytes/` fetch (against a
/// connected peer set of ~100), at which point sibling chunks had
/// no candidates left and the joiner deadlocked into the request
/// timeout. If a peer's libp2p *connection* (not just one stream)
/// genuinely dies, libp2p emits a `peer disconnected` event and the
/// `peers_watch` removes them from the candidate pool — that's the
/// proper signal, not an Io error from a single stream.
///
/// `OpenStream(_)` is likewise kept per-chunk. Treating it as fatal was
/// faster for isolated single-file fetches, but live gateway verification
/// with four parallel WAVs showed the shared request blacklist poisoning
/// otherwise healthy file attempts: enough sibling chunks raced through
/// stale address-book entries that later chunks exhausted their candidate
/// set and returned `all peers failed`. The `peers_watch` remains the
/// source of truth for peer liveness; one stream-open failure is not
/// enough to ban a peer for every other chunk in the file.
///
/// We still blacklist on framing errors (`MessageTooLarge`,
/// `BadPayloadSize`, protobuf decode failures) and CAC mismatches: those
/// say the peer is misbehaving or speaking a protocol we can't decode,
/// and there's no reason to expect a different chunk fetch against the
/// same peer to behave any differently.
const fn is_peer_fatal(err: &RetrievalError) -> bool {
    match err {
        RetrievalError::Remote(_)
        | RetrievalError::Timeout(_)
        | RetrievalError::Io(_)
        | RetrievalError::OpenStream(_) => false,
        RetrievalError::ProstEncode(_)
        | RetrievalError::ProstDecode(_)
        | RetrievalError::MessageTooLarge { .. }
        | RetrievalError::InvalidChunk
        | RetrievalError::BadPayloadSize(_) => true,
    }
}

/// Whether `err` is what a dead link to the peer looks like: the request
/// timed out or the stream couldn't be opened. `Remote` (bee answered),
/// `Io` (bee closed the stream, its "not found") and framing errors all
/// prove the connection works. The swarm loop self-heals after a streak
/// of these with no chunk delivered in between (issue #83,
/// `RetrievalCounters::record_link_failure`).
const fn is_link_failure(err: &RetrievalError) -> bool {
    matches!(
        err,
        RetrievalError::Timeout(_) | RetrievalError::OpenStream(_)
    )
}

/// Detached drain of the losing in-flight fetches after a winner has
/// returned. See the comment at the call site for the full ghost-balance
/// rationale; the short version is that bee's retrieval handler debits
/// us *only* once `WriteMsgWithContext` succeeds, so we let each loser
/// run to completion on a background task instead of cancelling its
/// libp2p stream mid-write.
///
/// Side effects performed by the drain task on each loser that returns
/// a CAC-valid chunk:
///   - **Cache write-through.** The loser already paid for the bytes;
///     caching them is free and a sibling fetch (or a future request
///     for the same chunk) skips the network entirely.
///   - **Debit apply + pseudosettle notify.** The chunk price was applied
///     as a real debit on bee's accounting, so it must land in our
///     mirror too: the pseudosettle driver refreshes a peer only once
///     the mirror's debt to it is due (`Accounting::refresh_due`), so a
///     debit we skipped here would accumulate on bee's side unseen and
///     we'd just trade ghost-overdraw blocklists for
///     `lightDisconnectLimit` blocklists. The notify only registers the
///     peer with the driver.
///   - **`record_chunk`** if recording is enabled.
///
/// Errors from losing fetches are silently discarded — the winner has
/// already returned so there's nothing useful for the caller to do
/// with them.
///
/// The spawned task is detached: we don't await it, and dropping the
/// `JoinHandle` (returned implicitly by `tokio::spawn` and ignored
/// here) does not cancel the task. The loser permits on the per-request
/// and process-wide retrieval semaphores stay held until the drain
/// task finishes, which is exactly the back-pressure we want — sibling
/// chunks of the same request keep waiting until losers finish, so we
/// don't pile on the network while old hedges are still resolving.
fn spawn_drain_losers<S>(
    in_flight: S,
    addr: [u8; 32],
    cache: Option<Arc<InMemoryChunkCache>>,
    disk_cache: Option<Arc<DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
) where
    S: futures::stream::Stream<
            Item = (
                PeerId,
                Result<RetrievedChunk, RetrievalError>,
                Option<DebitGuard>,
            ),
        > + Send
        + 'static,
{
    tokio::spawn(async move {
        let mut s = Box::pin(in_flight);
        while let Some((peer, result, guard)) = s.next().await {
            match result {
                Ok(chunk) => {
                    // Apply the loser's debit too: bee's
                    // `creditAction.Apply` ran on its end (we read
                    // their delivery), so the chunk price is real
                    // debt now and pseudosettle needs to clear it.
                    if let Some(g) = guard {
                        g.apply();
                    }
                    let mut wire = Vec::with_capacity(8 + chunk.payload().len());
                    wire.extend_from_slice(&chunk.span_bytes());
                    wire.extend_from_slice(chunk.payload());
                    if let Some(cache) = cache.as_ref() {
                        cache.put(addr, wire.clone());
                    }
                    // Tier-2 write-through for losers. The bytes have
                    // already been validated (the loser future returned
                    // a `RetrievedChunk`, which goes through CAC/SOC
                    // verification in `retrieve_chunk`), so persisting
                    // them is free safety net for the *next* request.
                    // Errors are downgraded to a trace because the
                    // winner has already returned to the caller.
                    if let Some(disk) = disk_cache.as_ref() {
                        let disk = disk.clone();
                        let wire_clone = wire.clone();
                        tokio::spawn(async move {
                            if let Err(e) = disk.put(addr, wire_clone).await {
                                trace!(
                                    target: "ant_retrieval::fetcher",
                                    chunk = %hex::encode(addr),
                                    "disk cache loser write-through failed: {e}",
                                );
                            }
                        });
                    }
                    if let Some(dir) = record_dir.as_ref() {
                        record_chunk(dir, &addr, &wire);
                    }
                    // We deliberately do NOT call
                    // `progress.record_chunk(...)`: the winner already
                    // counted this chunk against the request's totals
                    // and we don't want this loser to double-count the
                    // bytes-served gauge.
                    if let Some(notify) = payment_notify.as_ref() {
                        let _ = notify.try_send(peer);
                    }
                    trace!(
                        target: "ant_retrieval::fetcher",
                        %peer,
                        chunk = %hex::encode(addr),
                        "drained losing hedge to applied debit",
                    );
                }
                Err(e) => {
                    drop(guard);
                    trace!(
                        target: "ant_retrieval::fetcher",
                        %peer,
                        chunk = %hex::encode(addr),
                        "drained losing hedge errored: {e}",
                    );
                }
            }
        }
    });
}

/// One pushsync attempt's outcome: `(peer, overlay, chunk_price, credit,
/// result)`. `credit` is the reservation the attempt was admitted with
/// ([`PushsyncSettlement::prepare_credit`]); `None` without a settlement
/// hook.
type PushAttempt = (
    PeerId,
    Overlay,
    u64,
    Option<PushCredit>,
    Result<(), crate::pushsync::PushSyncError>,
);

/// A boxed, detachable pushsync attempt.
type PushAttemptFuture = std::pin::Pin<Box<dyn std::future::Future<Output = PushAttempt> + Send>>;

/// `push_stamped_chunk`'s in-flight attempts. On drop (the walk returned
/// with hedges still running, or the caller dropped the push), whatever is
/// still in flight goes to a detached drain that records the debit of
/// every receipt that still arrives — deep or shallow — in the pushsync
/// settlement mirror (it applies the attempt's credit; an attempt that
/// ends without a receipt releases it). A storer applies the debit once it has written its
/// receipt, whether or not we read it, and the pseudosettle driver only
/// refreshes a peer once its *mirrored* debt is due, so a dropped receipt
/// is debt bee holds and nothing ever clears. Each attempt is bounded by
/// `DEFAULT_PUSHSYNC_TIMEOUT`, so the drain is too.
///
/// Cost of the drain: a losing hedge's stream now stays open until its
/// receipt (or the up-to-45s timeout) instead of closing the moment the
/// walk returns, so a push's streams can outlive the upload's concurrency
/// window, and those attempts keep their [`crate::PushLoadGuard`] slot
/// (counting toward the peer's push cap) and their credit reservation
/// (counting toward the peer's disconnect limit, as bee's pushsync holds
/// its `Action` until the push returns) until they end. Without a
/// settlement hook nothing is drained: the attempts are dropped, which
/// closes their streams and — via the guard — frees their load slots.
struct PushInFlight {
    futs: FuturesUnordered<PushAttemptFuture>,
    /// A settlement hook is installed, so receipts are debited.
    records_debits: bool,
}

impl PushInFlight {
    fn new(records_debits: bool) -> Self {
        Self {
            futs: FuturesUnordered::new(),
            records_debits,
        }
    }
}

impl Drop for PushInFlight {
    fn drop(&mut self) {
        if self.futs.is_empty() {
            return;
        }
        let futs = std::mem::take(&mut self.futs);
        // Without a settlement hook there is nothing to record; dropping
        // the attempts closes their streams, and each attempt's
        // `PushLoadGuard` frees its push-load slot on drop (R4-M1).
        if !self.records_debits {
            return;
        }
        // A drop outside any runtime (process teardown) has nowhere to
        // spawn to; the requests die with the runtime anyway.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        tokio::spawn(async move {
            let mut futs = futs;
            while let Some((_peer, _overlay, _price, credit, res)) = futs.next().await {
                if matches!(
                    res,
                    Ok(()) | Err(crate::pushsync::PushSyncError::ShallowReceipt { .. })
                ) {
                    if let Some(credit) = credit {
                        credit.apply();
                    }
                }
            }
        });
    }
}

/// The in-flight set of one [`RoutingFetcher::fetch_within`] call, which
/// is never simply dropped while requests are still running.
///
/// Bee applies a retrieval debit when it writes the delivery
/// (`creditAction.Apply`), so a request dropped after that point leaves
/// debt at bee the accounting mirror never records — and pseudosettle
/// refreshes only off the mirror (`Accounting::refresh_due`), so that debt
/// would only clear incidentally. A fetch can end with requests still in
/// flight in two ways:
///
/// - it is won: the losers are handed off explicitly
///   ([`InFlight::drain_in_background`]);
/// - its future is dropped by the caller (an outer `tokio::time::timeout`
///   such as the feed look-ahead deadline or `verify_chunks_present`'s
///   per-chunk cap, or a gateway request whose client disconnected): the
///   [`Drop`] impl does the same hand-off.
///
/// Either way [`spawn_drain_losers`] reads each remaining request to
/// completion (bounded by `retrieve_chunk`'s own `RETRIEVE_TIMEOUT`) and
/// applies its debit on a delivery. Requests still queued at a retrieval
/// semaphore have sent nothing; the shared `abandoned` flag stops them
/// from being sent at all.
struct InFlight<F: std::future::Future<Output = DrainItem> + Send + 'static> {
    futures: Option<FuturesUnordered<F>>,
    addr: [u8; 32],
    abandoned: Arc<AtomicBool>,
    cache: Option<Arc<InMemoryChunkCache>>,
    disk_cache: Option<Arc<DiskChunkCache>>,
    record_dir: Option<PathBuf>,
    payment_notify: Option<mpsc::Sender<PeerId>>,
}

/// What one dispatched retrieval resolves to.
type DrainItem = (
    PeerId,
    Result<RetrievedChunk, RetrievalError>,
    Option<DebitGuard>,
);

impl<F: std::future::Future<Output = DrainItem> + Send + 'static> InFlight<F> {
    fn new(
        addr: [u8; 32],
        abandoned: Arc<AtomicBool>,
        cache: Option<Arc<InMemoryChunkCache>>,
        disk_cache: Option<Arc<DiskChunkCache>>,
        record_dir: Option<PathBuf>,
        payment_notify: Option<mpsc::Sender<PeerId>>,
    ) -> Self {
        Self {
            futures: Some(FuturesUnordered::new()),
            addr,
            abandoned,
            cache,
            disk_cache,
            record_dir,
            payment_notify,
        }
    }

    fn set(&mut self) -> &mut FuturesUnordered<F> {
        self.futures
            .as_mut()
            .expect("in-flight set already drained")
    }

    fn push(&mut self, fut: F) {
        self.set().push(fut);
    }

    fn len(&self) -> usize {
        self.futures.as_ref().map_or(0, FuturesUnordered::len)
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    async fn next(&mut self) -> Option<DrainItem> {
        self.set().next().await
    }

    /// Hand every request still in flight to a detached drain task. No-op
    /// if none are (or the set was already handed off).
    fn drain_in_background(&mut self) {
        let Some(futures) = self.futures.take() else {
            return;
        };
        if futures.is_empty() {
            return;
        }
        self.abandoned.store(true, AtomicOrdering::Release);
        // A drop outside any runtime (process teardown) has nowhere to
        // spawn to; the requests die with the runtime anyway.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        spawn_drain_losers(
            futures,
            self.addr,
            self.cache.clone(),
            self.disk_cache.clone(),
            self.record_dir.clone(),
            self.payment_notify.clone(),
        );
    }
}

impl<F: std::future::Future<Output = DrainItem> + Send + 'static> Drop for InFlight<F> {
    fn drop(&mut self) {
        self.drain_in_background();
    }
}

/// Best-effort dump of a CAC-validated chunk's wire bytes to
/// `<dir>/<hex_addr>.bin`. Used by the daemon's `--record-chunks`
/// flag to capture a fixture of every chunk a successful `antctl
/// get` touched. Skips if the file already exists (chunks are
/// content-addressed, so the bytes can't differ); a write error
/// only logs a warning so a full disk doesn't poison a live
/// retrieval.
fn record_chunk(dir: &std::path::Path, addr: &[u8; 32], wire: &[u8]) {
    let path = dir.join(format!("{}.bin", hex::encode(addr)));
    if path.exists() {
        return;
    }
    if let Err(e) = std::fs::write(&path, wire) {
        warn!(
            target: "ant_retrieval::fetcher",
            chunk = %hex::encode(addr),
            error = %e,
            path = %path.display(),
            "record-chunks write failed",
        );
    } else {
        trace!(
            target: "ant_retrieval::fetcher",
            chunk = %hex::encode(addr),
            bytes = wire.len(),
            "recorded chunk",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Grants every credit and records each one applied.
    #[derive(Default)]
    struct RecordingSettlement(Arc<Mutex<Vec<(PeerId, u64)>>>);

    struct RecordedCredit {
        applied: Arc<Mutex<Vec<(PeerId, u64)>>>,
        peer: PeerId,
        price: u64,
    }

    impl crate::PushCreditAction for RecordedCredit {
        fn apply(self: Box<Self>) {
            self.applied.lock().unwrap().push((self.peer, self.price));
        }
    }

    impl PushsyncSettlement for RecordingSettlement {
        fn prepare_credit(&self, peer: PeerId, price: u64) -> Option<PushCredit> {
            Some(PushCredit::new(RecordedCredit {
                applied: self.0.clone(),
                peer,
                price,
            }))
        }
        fn forget(&self, _peer: &PeerId) {}
    }

    /// Bee's `PrepareCredit` over an accounting mirror, as
    /// `ant-p2p::push_pseudosettle` does it.
    struct MirrorSettlement(Arc<Accounting>);

    impl PushsyncSettlement for MirrorSettlement {
        fn prepare_credit(&self, peer: PeerId, price: u64) -> Option<PushCredit> {
            self.0.try_reserve(peer, price).map(PushCredit::new)
        }
        fn forget(&self, peer: &PeerId) {
            self.0.forget(peer);
        }
    }

    /// A push fetcher over `peers` whose pushes get credit from `acc`
    /// and are booked in a one-slot push-load tracker, so a peer is
    /// `at_cap` exactly while a push to it is in flight. Pushes never
    /// get an answer (the stream behaviour is never polled), so they stay
    /// in flight until the pushsync timeout.
    fn credit_gated_push_fetcher(
        peers: Vec<(PeerId, Overlay)>,
        acc: &Arc<Accounting>,
    ) -> (
        RoutingFetcher,
        Arc<crate::PushLoadTracker>,
        libp2p_stream::Behaviour,
    ) {
        let behaviour = libp2p_stream::Behaviour::default();
        let load = Arc::new(crate::PushLoadTracker::new(1));
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), peers)
            .with_network_id(1)
            .with_push_load(load.clone())
            .with_pushsync_settlement(Arc::new(MirrorSettlement(acc.clone())));
        (fetcher, load, behaviour)
    }

    /// Take every unit of `peer`'s credit (its whole disconnect limit).
    fn hold_all_credit(acc: &Accounting, peer: PeerId) -> DebitGuard {
        acc.try_reserve(peer, crate::accounting::OVERDRAFT_LIMIT)
            .expect("a fresh peer has its whole limit")
    }

    /// Issue #128, bee's `PrepareCredit` before every push: the closest
    /// peer is at its credit limit, so the push goes to the next-closest
    /// peer, with that peer's price reserved, instead of taking the
    /// closest one past its disconnect limit.
    #[tokio::test(start_paused = true)]
    async fn push_skips_a_peer_at_its_credit_limit() {
        let addr = [0u8; 32];
        let (near, far) = (PeerId::random(), PeerId::random());
        let (near_o, far_o) = ([0x01u8; 32], [0x80u8; 32]);
        let acc = Arc::new(Accounting::new());
        let held = hold_all_credit(&acc, near);
        let (fetcher, load, _behaviour) =
            credit_gated_push_fetcher(vec![(near, near_o), (far, far_o)], &acc);
        let push = tokio::spawn(async move {
            fetcher
                .push_stamped_chunk(addr, vec![0u8; 16], [0u8; ant_postage::STAMP_SIZE])
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !load.at_cap(&near),
            "pushed to the closest peer although it is at its credit limit",
        );
        assert!(load.at_cap(&far), "the next-closest peer gets the push");
        assert_eq!(
            acc.debug_snapshot(&far),
            Some((0, peer_chunk_price(&far_o, &addr))),
            "the push holds the far peer's price",
        );
        assert_eq!(
            acc.debug_snapshot(&near),
            Some((0, crate::accounting::OVERDRAFT_LIMIT)),
        );
        push.abort();
        drop(held);
    }

    /// Issue #128: with every candidate at its credit limit, the push
    /// waits for credit, like bee's `pushToClosest` ("sleeping to refresh
    /// overdraft balance"), and pushes as soon as the peer has credit
    /// again, within one `OVERDRAFT_REFRESH`.
    #[tokio::test(start_paused = true)]
    async fn push_waits_for_credit_then_pushes() {
        let addr = [0u8; 32];
        let (p, o) = (PeerId::random(), [0x80u8; 32]);
        let acc = Arc::new(Accounting::new());
        let held = hold_all_credit(&acc, p);
        let (fetcher, load, _behaviour) = credit_gated_push_fetcher(vec![(p, o)], &acc);
        let push = tokio::spawn(async move {
            fetcher
                .push_stamped_chunk(addr, vec![0u8; 16], [0u8; ant_postage::STAMP_SIZE])
                .await
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!push.is_finished(), "the push waits for credit");
        assert!(!load.at_cap(&p), "pushed past the peer's credit limit");
        drop(held); // a refresh or a payment freed the peer's credit
        tokio::time::sleep(OVERDRAFT_REFRESH + Duration::from_millis(10)).await;
        assert!(load.at_cap(&p), "pushed once the peer had credit");
        assert_eq!(
            acc.debug_snapshot(&p),
            Some((0, peer_chunk_price(&o, &addr)))
        );
        push.abort();
    }

    /// Push `addr` on `fetcher` until it gives up; how long it took and
    /// why.
    async fn push_until_refused(fetcher: &RoutingFetcher, addr: [u8; 32]) -> (Duration, String) {
        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(
            CREDIT_WAIT_BUDGET * 3,
            fetcher.push_stamped_chunk(addr, vec![0u8; 16], [0u8; ant_postage::STAMP_SIZE]),
        )
        .await
        .expect("the credit wait must be bounded")
        .expect_err("the peer never has credit");
        (started.elapsed(), err.to_string())
    }

    /// Issue #128: the credit wait is bounded per walk by
    /// `CREDIT_WAIT_BUDGET`, cut to the fetcher's credit deadline, which
    /// the gateway's push paths share across their re-walks; past it a
    /// walk gives up at once. The walk never pushes past the limit, and
    /// says why it gave up.
    #[tokio::test(start_paused = true)]
    async fn push_credit_wait_is_bounded() {
        let addr = [0u8; 32];
        let (p, o) = (PeerId::random(), [0x80u8; 32]);
        let acc = Arc::new(Accounting::new());
        let _held = hold_all_credit(&acc, p);
        let (fetcher, load, _behaviour) = credit_gated_push_fetcher(vec![(p, o)], &acc);
        let (took, err) = push_until_refused(&fetcher, addr).await;
        assert_eq!(took, CREDIT_WAIT_BUDGET, "{err}");
        assert!(err.starts_with("no pushsync peer has credit"), "{err}");
        assert!(!load.at_cap(&p));

        let (fetcher, _load, _behaviour) = credit_gated_push_fetcher(vec![(p, o)], &acc);
        let fetcher =
            fetcher.with_credit_deadline(tokio::time::Instant::now() + Duration::from_secs(3));
        let (took, err) = push_until_refused(&fetcher, addr).await;
        assert_eq!(took, Duration::from_secs(3), "{err}");
        let (took, err) = push_until_refused(&fetcher, addr).await;
        assert_eq!(took, Duration::ZERO, "past the deadline: {err}");
        assert!(err.starts_with("no pushsync peer has credit"), "{err}");
    }

    /// PR #138 R1-M1: the credit deadline is re-read before every nap,
    /// not once at walk start. The closest peer has credit and hangs to
    /// its pushsync timeout while the other one stays overdrawn; when
    /// the hung push fails, the deadline has passed, so the walk gives
    /// up at once instead of napping its leftover per-walk budget.
    #[tokio::test(start_paused = true)]
    async fn push_does_not_nap_past_the_credit_deadline() {
        let addr = [0u8; 32];
        let (near, far) = (PeerId::random(), PeerId::random());
        let acc = Arc::new(Accounting::new());
        let _held = hold_all_credit(&acc, far);
        let (fetcher, _load, _behaviour) =
            credit_gated_push_fetcher(vec![(near, [0x01u8; 32]), (far, [0x80u8; 32])], &acc);
        let fetcher =
            fetcher.with_credit_deadline(tokio::time::Instant::now() + CREDIT_WAIT_BUDGET);
        let started = tokio::time::Instant::now();
        let err = fetcher
            .push_stamped_chunk(addr, vec![0u8; 16], [0u8; ant_postage::STAMP_SIZE])
            .await
            .expect_err("the near peer never answers, the far one never has credit");
        assert!(crate::pushsync::DEFAULT_PUSHSYNC_TIMEOUT > CREDIT_WAIT_BUDGET);
        assert_eq!(
            started.elapsed(),
            crate::pushsync::DEFAULT_PUSHSYNC_TIMEOUT,
            "{err}"
        );
    }

    /// PR #138 R2-F1: a peer refused credit in a pass that still filled
    /// its slot is skipped for one `OVERDRAFT_REFRESH`, not for the rest
    /// of the walk. The closest peer is overdrawn at the first dispatch
    /// and has credit again soon after; the 5 s preemptive hedge goes to
    /// it, not to the farthest peer.
    #[tokio::test(start_paused = true)]
    async fn push_hedge_asks_a_peer_again_once_its_credit_round_ends() {
        let addr = [0u8; 32];
        let (near, mid, far) = (PeerId::random(), PeerId::random(), PeerId::random());
        let acc = Arc::new(Accounting::new());
        let held = hold_all_credit(&acc, near);
        let (fetcher, load, _behaviour) = credit_gated_push_fetcher(
            vec![
                (near, [0x01u8; 32]),
                (mid, [0x40u8; 32]),
                (far, [0x80u8; 32]),
            ],
            &acc,
        );
        let push = tokio::spawn(async move {
            fetcher
                .push_stamped_chunk(addr, vec![0u8; 16], [0u8; ant_postage::STAMP_SIZE])
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(load.at_cap(&mid), "the first push skips the overdrawn peer");
        assert!(!load.at_cap(&near));
        drop(held); // the closest peer has credit again
        tokio::time::sleep(RoutingFetcher::PREEMPTIVE_INTERVAL).await;
        assert!(load.at_cap(&near), "the hedge asks the closest peer again");
        assert!(!load.at_cap(&far), "the hedge passed over the closest peer");
        push.abort();
    }

    /// Issue #212: a push answered once stored hedges onto the
    /// next-closest peer after one second of silence from the closest,
    /// where any other push gives it bee's five.
    #[tokio::test(start_paused = true)]
    async fn a_push_answered_when_stored_hedges_after_a_second() {
        let addr = [0u8; 32];
        for stored in [true, false] {
            let (near, far) = (PeerId::random(), PeerId::random());
            let acc = Arc::new(Accounting::new());
            let (fetcher, load, _behaviour) =
                credit_gated_push_fetcher(vec![(near, [0x01u8; 32]), (far, [0x80u8; 32])], &acc);
            let (tx, _rx) = tokio::sync::oneshot::channel();
            let fetcher = if stored {
                fetcher.with_stored_signal(tx)
            } else {
                fetcher
            };
            let push = tokio::spawn(async move {
                fetcher
                    .push_stamped_chunk(addr, vec![0u8; 16], [0u8; ant_postage::STAMP_SIZE])
                    .await
            });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(load.at_cap(&near), "the closest peer gets the push");
            assert!(!load.at_cap(&far));
            tokio::time::sleep(Duration::from_millis(1000)).await;
            assert_eq!(
                load.at_cap(&far),
                stored,
                "hedged by 1.1 s (stored: {stored})"
            );
            tokio::time::sleep(RoutingFetcher::PREEMPTIVE_INTERVAL).await;
            assert!(load.at_cap(&far), "hedged by 6.1 s (stored: {stored})");
            push.abort();
        }
    }

    /// Pushes still in flight when `push_stamped_chunk` returns (a winner
    /// beat the hedges) or is dropped keep running in a detached drain,
    /// and every receipt that still arrives — deep or shallow — is debited
    /// to the mirror: the storer debited us when it wrote it. Failed
    /// attempts record nothing (PR #134 R3-M1).
    #[tokio::test(start_paused = true)]
    async fn dropped_push_attempts_still_record_late_receipts() {
        use crate::pushsync::PushSyncError;
        let rec = Arc::new(RecordingSettlement::default());
        let (deep, shallow, failed) = (PeerId::random(), PeerId::random(), PeerId::random());
        {
            let inflight = PushInFlight::new(true);
            for (peer, price, delay, res) in [
                (deep, 110_000u64, 3u64, Ok(())),
                (
                    shallow,
                    220_000,
                    5,
                    Err(PushSyncError::ShallowReceipt {
                        po: 3,
                        storage_radius: 8,
                    }),
                ),
                (
                    failed,
                    330_000,
                    1,
                    Err(PushSyncError::Remote("nope".into())),
                ),
            ] {
                let credit = rec.prepare_credit(peer, price);
                inflight.futs.push(Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    (peer, [0u8; 32], price, credit, res)
                }));
            }
            // Dropped with all three still pending.
        }
        assert!(rec.0.lock().unwrap().is_empty(), "nothing has answered yet");
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut got = rec.0.lock().unwrap().clone();
        got.sort_by_key(|(_, p)| *p);
        assert_eq!(got, vec![(deep, 110_000), (shallow, 220_000)]);
    }

    /// With no settlement hook (`ANT_PUSH_PSEUDOSETTLE=0`) unfinished
    /// attempts are dropped, not drained — and must still free the
    /// push-load slot they booked at dispatch, or every discarded hedge
    /// ratchets its peer toward `at_cap` for good (PR #134 R4-M1). With a
    /// hook, the drained attempt holds its slot until it really ends.
    #[tokio::test(start_paused = true)]
    async fn dropped_push_attempts_release_push_load() {
        let load = Arc::new(crate::PushLoadTracker::new(1));
        let peer = PeerId::random();
        let rec = Arc::new(RecordingSettlement::default());
        let attempt = |load: &Arc<crate::PushLoadTracker>| -> PushAttemptFuture {
            let guard = load.book(peer);
            let credit = rec.prepare_credit(peer, 1);
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                guard.finish(Duration::from_secs(5));
                (peer, [0u8; 32], 1, credit, Ok(()))
            })
        };
        {
            let inflight = PushInFlight::new(false);
            inflight.futs.push(attempt(&load));
            assert!(load.at_cap(&peer));
        }
        assert!(!load.at_cap(&peer), "dropped attempt leaked its slot");

        {
            let inflight = PushInFlight::new(true);
            inflight.futs.push(attempt(&load));
        }
        assert!(load.at_cap(&peer), "drained attempt is still in flight");
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!load.at_cap(&peer));
        assert_eq!(rec.0.lock().unwrap().len(), 1);
    }
    use crate::accounting::CREDIT_WAIT_BUDGET;
    use std::time::Duration;

    /// Issue #123: both of bee's miss answers — `storage: not found` and
    /// `no peer found` — are typed as a miss on the error the fetch gives
    /// up with, so a fetch that ran out on either is confirmed missing
    /// (unless the pool was starved), with its message unchanged.
    #[test]
    fn exhausted_types_both_miss_tails() {
        let addr = [0xab; 32];
        for tail in [
            "retrieve chunk: storage: not found",
            "retrieve chunk: no peer found",
        ] {
            let e = exhausted(
                addr,
                34,
                Some(RetrievalError::Remote(tail.into())),
                false,
                34,
            );
            assert!(e.last_not_found, "{tail}");
            assert!(e.confirmed_missing(), "{tail}");
            assert!(e.corroborated_missing(), "{tail}");
            assert_eq!(
                e.to_string(),
                format!(
                    "all peers failed for chunk {} after 34 attempts (last: remote: {tail})",
                    hex::encode(addr)
                )
            );
            // Starved: one cold peer's answer, never a confirmed miss (#114).
            let e = exhausted(addr, 1, Some(RetrievalError::Remote(tail.into())), true, 1);
            assert!(e.last_not_found && !e.confirmed_missing(), "{tail}");
            assert!(!e.corroborated_missing(), "{tail}");
            // R1-M2 on PR #124: a cold node's only peer (every ranked
            // peer asked, so not starved) answering a miss is confirmed —
            // the answer once retries run out — but not corroborated, so
            // retry loops don't stop on it at once.
            for n in 1..=STARVED_MAX_NOT_FOUND {
                let e = exhausted(addr, n, Some(RetrievalError::Remote(tail.into())), false, n);
                assert!(
                    e.confirmed_missing() && !e.corroborated_missing(),
                    "{tail} x{n}"
                );
            }
        }
        for last in [
            Some(RetrievalError::Timeout(Duration::from_secs(5))),
            Some(RetrievalError::Remote("retrieve chunk: forbidden".into())),
            Some(RetrievalError::OpenStream("no addresses: not found".into())),
            None,
        ] {
            let e = exhausted(addr, 3, last, false, 3);
            assert!(!e.confirmed_missing() && !e.corroborated_missing(), "{e}");
        }
        assert!(!exhausted(addr, 0, None, false, 0).confirmed_missing());
    }

    /// Starvation needs budget left *and* unasked ranked peers, and stops
    /// counting once more than `STARVED_MAX_NOT_FOUND` peers agreed the
    /// chunk is missing: a busy node where some ranked peer is always
    /// overdraft-skipped must still report genuine loss as confirmed
    /// (PR #116 R1-M1).
    #[test]
    fn pool_starved_yields_to_several_not_found_answers() {
        // Cold node: one peer said "not found", the rest were skipped.
        assert!(pool_starved(31, true, 1));
        assert!(pool_starved(30, true, STARVED_MAX_NOT_FOUND));
        // Busy node, real loss: ten peers said "not found".
        assert!(!pool_starved(22, true, 10));
        assert!(!pool_starved(29, true, STARVED_MAX_NOT_FOUND + 1));
        // Every ranked peer asked, or the budget spent: not starved.
        assert!(!pool_starved(31, false, 0));
        assert!(!pool_starved(0, true, 0));
        // And the classification it feeds: a peer's "not found" reply
        // counts toward the cap.
        assert!(crate::feed::is_chunk_not_found(&RetrievalError::Remote(
            "retrieve chunk: storage: not found".into()
        )));
    }

    /// `is_peer_fatal` is the load-bearing classifier: it decides
    /// whether a per-chunk failure spreads into a request-wide
    /// blacklist or stays scoped to the current chunk fetch. Getting
    /// this wrong is exactly the failure mode we hit in production
    /// before this change — `Remote("not found")` from one chunk took
    /// the peer out of the running for *all* sibling chunks of the
    /// same file fetch, even though the peer was perfectly capable of
    /// serving them.
    ///
    /// The matrix below pins the policy variant-by-variant so an
    /// accidental edit to the `is_peer_fatal` arms surfaces here
    /// instead of in a flaky retrieval regression.
    #[test]
    fn peer_fatal_classifier_matrix() {
        assert!(
            !is_peer_fatal(&RetrievalError::Remote("storage: not found".into())),
            "remote 'not found' must NOT poison the peer for sibling chunks",
        );
        assert!(
            !is_peer_fatal(&RetrievalError::Timeout(Duration::from_secs(20))),
            "single timeout must NOT poison the peer for sibling chunks",
        );

        assert!(
            !is_peer_fatal(&RetrievalError::OpenStream("dial failed".into())),
            "stream-open failure must NOT poison the peer for sibling chunks",
        );
        assert!(
            is_peer_fatal(&RetrievalError::InvalidChunk),
            "CAC mismatch: peer is misbehaving",
        );
        assert!(
            is_peer_fatal(&RetrievalError::BadPayloadSize(42)),
            "out-of-range payload: peer is misbehaving",
        );
        assert!(
            is_peer_fatal(&RetrievalError::MessageTooLarge {
                got: 1 << 20,
                cap: 16 << 10
            }),
            "oversized message: peer is misbehaving or compromised",
        );
        // Bee signals "I don't have this chunk" by closing the
        // libp2p_stream without writing a reply. Our reader then
        // surfaces those closes as `Io(UnexpectedEof)` (most common)
        // or `Io(BrokenPipe)` / `Io(ConnectionReset)` (when the close
        // races a read). Pre-fix we treated all of those as peer-fatal
        // and burned ~3 peers per chunk on a multi-MiB file; the
        // joiner then deadlocked into its request timeout because
        // sibling chunks had no candidates left. The matrix below
        // pins the post-fix policy: an `Io(_)` from any kind is
        // a per-chunk signal, never a per-peer one.
        for kind in [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
        ] {
            assert!(
                !is_peer_fatal(&RetrievalError::Io(std::io::Error::new(kind, "stream closed"))),
                "Io({kind:?}) is bee's 'no chunk' signal, must NOT poison the peer for sibling chunks",
            );
        }
    }

    /// Mirror of `peer_fatal_classifier_matrix` for the pushsync side:
    /// pins which `PushSyncError` variants get one same-peer retry on
    /// a fresh stream before the peer hits the per-chunk skip list.
    /// Pre-fix every error class — including the dominant
    /// `Io("Connection is closed")` we saw from libp2p mid-pushsync —
    /// burned a fresh closest peer per attempt, so 24 unrelated TCP
    /// recycles in a row were enough to fail an otherwise-healthy
    /// upload.
    #[test]
    fn pushsync_transient_classifier_matrix() {
        use crate::pushsync::PushSyncError as E;
        assert!(
            is_transient_pushsync_error(&E::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "connection is closed",
            ))),
            "stream-level Io is the dominant transient case; must retry the same peer once",
        );
        assert!(
            !is_transient_pushsync_error(&E::OpenStream("dial: no addresses".into())),
            "open-stream failure means the connection is gone; a fresh dial can't finish in the retry window, so skip to the next-closest peer instead of re-hammering this one",
        );
        assert!(
            !is_transient_pushsync_error(&E::Timeout(Duration::from_secs(20))),
            "a stalled peer past its deadline is wedged; skip it and hedge to the next-closest, don't re-wait a second deadline",
        );

        assert!(
            !is_transient_pushsync_error(&E::Remote("invalid postage stamp".into())),
            "explicit remote rejection: do NOT retry, skip the peer",
        );
        assert!(
            !is_transient_pushsync_error(&E::ReceiptMismatch),
            "receipt mismatch is a protocol violation, not transient",
        );

        // A shallow receipt must NOT be classified transient: it is a
        // soft *success* (the chunk was stored), handled by the dedicated
        // shallow-acceptance path, not by the same-peer fresh-stream
        // retry. If it leaked into the transient set we'd pointlessly
        // re-push to the same shallow storer.
        assert!(
            !is_transient_pushsync_error(&E::ShallowReceipt {
                po: 3,
                storage_radius: 5,
            }),
            "shallow receipt is a soft success, not a transient stream error",
        );
    }

    /// A shallow receipt hunts for a deep storer until the hunt is used
    /// up, or not at all in a neighbourhood already known to lack one;
    /// strict pushes never take that shortcut.
    #[test]
    fn a_shallow_receipt_hunts_until_used_up_or_known_shallow() {
        use ShallowVerdict::{AcceptAndMark, AcceptKnown, Hunt, Strict};
        // Unknown neighbourhood: hunt, then accept and remember it.
        assert_eq!(shallow_verdict(1, false, false), Hunt);
        assert_eq!(shallow_verdict(11, false, false), Hunt);
        assert_eq!(shallow_verdict(12, false, false), AcceptAndMark);
        // Known neighbourhood: the first shallow receipt is enough.
        assert_eq!(shallow_verdict(1, false, true), AcceptKnown);
        // Strict pushes ignore the memory and hand the chunk back.
        assert_eq!(shallow_verdict(1, true, true), Hunt);
        assert_eq!(shallow_verdict(12, true, true), Strict);
        assert_eq!(shallow_verdict(12, true, false), Strict);
    }

    /// Issue #212: a stored signal fires once, at the first shallow
    /// receipt, however many follow; a fetcher without one has nothing
    /// to fire. The push hedges after 1 s only while its caller still
    /// waits for that answer, and after bee's 5 s once it went out.
    #[test]
    fn the_stored_signal_fires_once_and_ends_the_short_hedge() {
        let behaviour = libp2p_stream::Behaviour::default();
        let plain = RoutingFetcher::with_static_peers(behaviour.new_control(), Vec::new());
        assert_eq!(
            plain.preemptive_interval(),
            RoutingFetcher::PREEMPTIVE_INTERVAL
        );
        assert!(!plain.note_stored());

        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), Vec::new())
            .with_stored_signal(tx);
        assert!(rx.try_recv().is_err(), "fired before any receipt");
        assert_eq!(
            fetcher.preemptive_interval(),
            RoutingFetcher::STORED_PREEMPTIVE_INTERVAL
        );
        assert!(fetcher.note_stored());
        assert!(!fetcher.note_stored(), "fired twice");
        assert_eq!(rx.try_recv(), Ok(()));
        assert_eq!(
            fetcher.preemptive_interval(),
            RoutingFetcher::PREEMPTIVE_INTERVAL
        );
    }

    /// Issue #212: the retry after a chunk's first shallow receipt goes
    /// straight to the next-closest peer; every later one waits for the
    /// neighbourhood dial first.
    #[test]
    fn only_a_repeated_shallow_receipt_waits_for_a_deeper_peer() {
        assert!(!waits_for_deeper_peer(1));
        assert!(waits_for_deeper_peer(2));
        assert!(waits_for_deeper_peer(
            RoutingFetcher::MAX_SHALLOW_ATTEMPTS - 1
        ));
    }

    /// Pin shallow-receipt acceptance: we hunt for a deeper storer for a
    /// bounded number of shallow hits, then accept (a shallow receipt still
    /// means the chunk *is* stored, so failing the upload would be wrong).
    /// The threshold sits above bee's pusher `DefaultRetryCount` (6) because
    /// a light node can't lean on pull-sync to deepen a shallow placement
    /// after the fact, so it spends extra rounds — each with an active
    /// neighbourhood dial + bounded wait — hunting for a deep storer first.
    #[test]
    fn shallow_receipt_accepted_after_bounded_attempts() {
        assert_eq!(
            RoutingFetcher::MAX_SHALLOW_ATTEMPTS,
            12,
            "light node hunts harder than bee's DefaultRetryCount before accepting shallow",
        );
        // Below the threshold: keep trying for a deeper storer.
        assert!(!accept_shallow_after(1));
        assert!(!accept_shallow_after(11));
        // At/above the threshold: accept the shallow (stored) chunk.
        assert!(accept_shallow_after(12));
        assert!(accept_shallow_after(13));
    }

    /// Pin the consumer side of the live-peers fix: every `ranked()`
    /// call must reflect the *current* contents of the `peers_watch`,
    /// not a snapshot frozen at fetcher-construction time. The pre-fix
    /// regression — using a `Vec<(PeerId, Overlay)>` cloned once and
    /// stored on `Self` — survived months of testing because no unit
    /// test exercised the consumer at all (the publisher side, in
    /// `ant-p2p::behaviour::tests::publish_peers_reflects_admit_and_forget`,
    /// was added later but doesn't observably catch a fetcher that
    /// just ignored the watch). This test closes that gap: it
    /// constructs the fetcher with one peer, asserts `ranked()` sees
    /// it, swaps the channel value to a different peer set, and asserts
    /// the same `ranked()` call now reflects the new set. If the
    /// fetcher ever regresses to a stored snapshot the second
    /// assertion is what fails.
    #[test]
    fn ranked_reflects_live_watch_updates() {
        use libp2p::identity::Keypair;

        // Two arbitrary, distinct peers. The actual XOR-distance
        // ordering doesn't matter for this test; we only assert which
        // peers `ranked()` *includes*.
        let p1 = Keypair::generate_ed25519().public().to_peer_id();
        let o1 = [0xaa_u8; 32];
        let p2 = Keypair::generate_ed25519().public().to_peer_id();
        let o2 = [0xbb_u8; 32];

        let (tx, rx) = watch::channel(vec![(p1, o1)]);

        // We need a `Control` to construct a `RoutingFetcher` even
        // though `ranked()` never touches it. `libp2p_stream::Behaviour`
        // hands one out without requiring a swarm to be running.
        let behaviour = libp2p_stream::Behaviour::default();
        let control = behaviour.new_control();

        let fetcher = RoutingFetcher::new(control, rx);
        let target = [0u8; 32];

        let ranked_before = fetcher.ranked(&target);
        assert_eq!(
            ranked_before,
            vec![(p1, o1)],
            "ranked() must surface the initial watch value",
        );

        // Republish a different peer set. Production calls this from
        // `SwarmState::publish_peers` on every admit / forget.
        tx.send_replace(vec![(p2, o2)]);

        let ranked_after = fetcher.ranked(&target);
        assert_eq!(
            ranked_after,
            vec![(p2, o2)],
            "ranked() must read the watch on every call, not at construction time",
        );
    }

    /// Pin the contract that `with_inflight_limit` actually parks the
    /// fetch path on the supplied semaphore. The whole point of the
    /// process-wide cap is to keep concurrent `bzz://` requests from
    /// stampeding bee with ~60 simultaneous retrieval streams; if a
    /// future refactor accidentally drops the permit-acquire (or
    /// acquires it *after* `retrieve_chunk` runs) the saturation
    /// regression returns silently — failing tests would have to
    /// actually drive a multi-MiB fetch over the wire to notice. This
    /// test catches that without leaving the unit-test boundary: with
    /// the only permit externally held, a `fetch` call must never
    /// reach `retrieve_chunk` (which would resolve near-instantly to a
    /// transport error against the dummy `Control`) and must therefore
    /// still be running after a generous park window.
    #[tokio::test]
    async fn fetch_parks_when_inflight_cap_exhausted() {
        use libp2p::identity::Keypair;
        use std::time::Duration;

        let sem = Arc::new(Semaphore::new(1));
        // Hold the only permit so any `fetch` task that respects the
        // limit must park at `acquire_owned()`.
        let hold = sem.clone().acquire_owned().await.unwrap();

        let p = Keypair::generate_ed25519().public().to_peer_id();
        let o = [0u8; 32];
        let (_tx, rx) = watch::channel(vec![(p, o)]);
        let behaviour = libp2p_stream::Behaviour::default();
        let control = behaviour.new_control();
        let fetcher = RoutingFetcher::new(control, rx).with_inflight_limit(sem.clone());

        let h = tokio::spawn(async move {
            let _ = fetcher.fetch([0u8; 32]).await;
        });

        // 100 ms is well past the 250 ms hedge timer's first fire too —
        // even after the loop has tried to schedule a second peer, every
        // future is parked at the semaphore.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !h.is_finished(),
            "fetch must be parked at the inflight-permit acquire while the cap is exhausted",
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "the held permit must still be the only outstanding one",
        );

        // Cleanup — drop our holder, then abort the spawned task so
        // the test doesn't depend on a real swarm being available to
        // satisfy `retrieve_chunk`.
        drop(hold);
        h.abort();
    }

    /// R2-M1 on PR #134: an [`InFlight`] set dropped with a request still
    /// running (the caller's future was cancelled by an outer timeout)
    /// hands it to the loser drain, so a late delivery still applies its
    /// debit to the mirror instead of releasing the reservation unpaid.
    #[tokio::test(start_paused = true)]
    async fn dropped_in_flight_set_still_applies_a_late_debit() {
        let acc = Arc::new(Accounting::new());
        let p = PeerId::random();
        let addr = [0x5au8; 32];
        let guard = acc.try_reserve(p, 1_000).expect("fresh peer admits");
        let abandoned = Arc::new(AtomicBool::new(false));
        let mut set = InFlight::new(addr, abandoned.clone(), None, None, None, None);
        set.push(Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let chunk = RetrievedChunk {
                address: addr,
                data: vec![0u8; 8],
            };
            (p, Ok(chunk), Some(guard))
        }));
        assert_eq!(acc.debug_snapshot(&p), Some((0, 1_000)));
        drop(set);
        assert!(abandoned.load(AtomicOrdering::Acquire));
        // Still reserved while the drain waits for the delivery…
        assert_eq!(acc.debug_snapshot(&p), Some((0, 1_000)));
        tokio::time::sleep(Duration::from_secs(6)).await;
        // …and applied once it lands.
        assert_eq!(acc.debug_snapshot(&p), Some((1_000, 0)));
    }

    /// R2-M1 on PR #134, through the real `fetch`: cancelling it with an
    /// outer timeout (the feed look-ahead deadline, verify's per-chunk
    /// cap) no longer drops the dispatched request and its reservation.
    /// The request here is parked at the retrieval semaphore; once a slot
    /// frees, the drain sees the fetch was abandoned and releases the
    /// reservation without sending anything.
    #[tokio::test(start_paused = true)]
    async fn cancelled_fetch_keeps_its_request_for_the_drain() {
        let acc = Arc::new(Accounting::new());
        let p = PeerId::random();
        let o = [0x80u8; 32];
        let addr = [0x3cu8; 32];
        let sem = Arc::new(Semaphore::new(1));
        let hold = sem.clone().acquire_owned().await.unwrap();
        let behaviour = libp2p_stream::Behaviour::default();
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), vec![(p, o)])
            .with_accounting(acc.clone())
            .with_inflight_limit(sem.clone());
        let r = tokio::time::timeout(Duration::from_millis(500), fetcher.fetch(addr)).await;
        assert!(
            r.is_err(),
            "the fetch must still be parked at the semaphore"
        );
        let price = Accounting::peer_price(&o, &addr);
        assert_eq!(
            acc.debug_snapshot(&p),
            Some((0, price)),
            "the cancelled fetch's request must survive in the drain",
        );
        drop(hold);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            acc.debug_snapshot(&p),
            Some((0, 0)),
            "an abandoned request that never reached bee releases its reservation",
        );
        assert_eq!(sem.available_permits(), 1);
    }

    /// A fetcher with accounting over one peer whose credit is used up:
    /// the returned guards hold the peer's whole overdraft allowance.
    fn starved_fetcher(
        addr: [u8; 32],
    ) -> (RoutingFetcher, Arc<Accounting>, PeerId, Vec<DebitGuard>) {
        let acc = Arc::new(Accounting::new());
        let (fetcher, p, held) = starved_fetcher_on(acc.clone(), addr);
        (fetcher, acc, p, held)
    }

    /// [`starved_fetcher`] over a caller-supplied (possibly shared)
    /// [`Accounting`], with a fresh peer of its own.
    fn starved_fetcher_on(
        acc: Arc<Accounting>,
        addr: [u8; 32],
    ) -> (RoutingFetcher, PeerId, Vec<DebitGuard>) {
        let p = PeerId::random();
        let o = [0x80u8; 32];
        let price = Accounting::peer_price(&o, &addr);
        let mut held = Vec::new();
        while let Some(g) = acc.try_reserve(p, price) {
            held.push(g);
        }
        assert!(!held.is_empty());
        let behaviour = libp2p_stream::Behaviour::default();
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), vec![(p, o)])
            .with_accounting(acc);
        (fetcher, p, held)
    }

    /// Issue #83: a retrieval that times out on its peer's link counts
    /// toward the process-wide link-failure streak the swarm loop
    /// self-heals on. The peer here never answers (its stream can't
    /// even be opened), exactly what a half-open socket looks like.
    #[tokio::test(start_paused = true)]
    async fn timed_out_retrieval_counts_as_a_link_failure() {
        let behaviour = libp2p_stream::Behaviour::default();
        let counters = Arc::new(RetrievalCounters::new());
        let fetcher = RoutingFetcher::with_static_peers(
            behaviour.new_control(),
            vec![(PeerId::random(), [0x80u8; 32])],
        )
        .with_counters(counters.clone());
        let err = fetcher.fetch([0x55u8; 32]).await.expect_err("dead peer");
        assert!(err.to_string().contains("timed out"), "{err}");
        assert_eq!(counters.link_failure_streak(), 1);
        assert!(is_link_failure(&RetrievalError::OpenStream(
            "closed".into()
        )));
        assert!(!is_link_failure(&RetrievalError::Remote(
            "storage: not found".into()
        )));
        assert!(!is_link_failure(&RetrievalError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "bee's not found"
        ))));
    }

    /// Wire bytes of a plain two-leaf intermediate root (span 8 KiB)
    /// whose children are both `child`.
    fn two_leaf_root(child: [u8; 32]) -> Vec<u8> {
        let mut root = 8192u64.to_le_bytes().to_vec();
        root.extend_from_slice(&child);
        root.extend_from_slice(&child);
        root
    }

    /// Issue #117 redesign on PR #119: plain `fetch` never waits for
    /// credit. A pool whose every candidate is overdraft-skipped fails
    /// at t = 0, typed as a starved `FetchExhausted`, as on `main`.
    #[tokio::test(start_paused = true)]
    async fn plain_fetch_on_a_starved_pool_fails_at_once() {
        let addr = [0x55u8; 32];
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        let started = tokio::time::Instant::now();
        let err = fetcher.fetch(addr).await.expect_err("starved");
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(err.to_string(), "no BZZ peers available");
        let typed = err.downcast_ref::<FetchExhausted>().expect("typed");
        assert!(typed.pool_starved);
        // A path that must never wait stays non-waiting even when it
        // asks for a credit wait.
        let err = crate::NoCreditWait(&fetcher)
            .fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET)
            .await
            .expect_err("starved");
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(err.to_string(), "no BZZ peers available");
    }

    /// R1-F1 on PR #119: the dispersed-replica fallback after a starved
    /// root fetch must not wait for credit on each of its ~30 probes.
    /// The direct fetch waits its `CREDIT_WAIT_BUDGET`; the replica
    /// probes use plain `fetch` and fail at once, so the whole root fetch
    /// ends at the budget, not at ~50 s (8 waves × 10 s at fanout 4).
    #[tokio::test(start_paused = true)]
    async fn starved_root_fetch_does_not_wait_per_replica() {
        let addr = [0x44u8; 32];
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        let started = tokio::time::Instant::now();
        let err = crate::rs::fetch_root_with_replicas(&fetcher, addr, CREDIT_WAIT_BUDGET)
            .await
            .expect_err("pool never refills");
        let waited = started.elapsed();
        assert!(
            waited >= CREDIT_WAIT_BUDGET && waited < CREDIT_WAIT_BUDGET + OVERDRAFT_REFRESH,
            "root fetch with replica fallback took {waited:?}",
        );
        // The direct fetch's error is what the caller sees.
        assert_eq!(err.to_string(), "no BZZ peers available");
        let typed = err.downcast_ref::<FetchExhausted>().expect("typed");
        assert!(typed.pool_starved);
    }

    /// R3-F1 on PR #119: a feed anchor probe on a starved pool must not
    /// wait for credit per probe retry (4 × 10 s, past the 30 s `/bzz`
    /// resolution budget). Feed probes use plain `fetch`, so the probe
    /// gives up after its own 3 × 200 ms retry delays, as on `main`.
    #[tokio::test(start_paused = true)]
    async fn starved_feed_anchor_probe_does_not_wait_for_credit() {
        let feed = crate::feed::Feed {
            owner: [0x24u8; 20],
            topic: [0x42u8; 32],
            kind: crate::feed::FeedType::Sequence,
        };
        let addr = crate::feed::sequence_update_address(&feed, 0);
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        let started = tokio::time::Instant::now();
        let r = crate::feed::resolve_sequence_feed_after(&fetcher, &feed, 0).await;
        let waited = started.elapsed();
        assert!(r.is_err(), "pool never refills: {r:?}");
        assert!(
            waited < Duration::from_secs(1),
            "starved anchor probe took {waited:?}",
        );
    }

    /// R4-F1 on PR #119: an erasure-recovery sweep after a starved data
    /// child's direct fetch must not wait for credit on each of its up
    /// to 128 shard fetches. The direct fetch waits its budget; the
    /// sweep's fetches are plain and fail at once (as unreached, so the
    /// failure is transient and the joiner retries), so the attempt ends
    /// at the budget, not at ~90 s (8 waves × 10 s at fanout 16, plus the
    /// direct wait).
    #[tokio::test(start_paused = true)]
    async fn starved_recovery_sweep_does_not_wait_per_shard() {
        let addr = [0x66u8; 32];
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        let decoder = crate::rs::RsDecoder::new(vec![addr; 128], 119);
        let started = tokio::time::Instant::now();
        let err = decoder
            .fetch_data_shard(&fetcher, 0, CREDIT_WAIT_BUDGET)
            .await
            .expect_err("pool never refills");
        let waited = started.elapsed();
        assert!(
            waited >= CREDIT_WAIT_BUDGET && waited < CREDIT_WAIT_BUDGET + OVERDRAFT_REFRESH,
            "direct fetch plus recovery sweep took {waited:?}",
        );
        assert!(
            err.transient,
            "a starved sweep is retryable: {}",
            err.detail
        );
    }

    /// R6-F1 on PR #119: the buffered joiner must not re-fetch a starved
    /// child 32 times, each waiting the full credit budget (~444 s). Its
    /// child gets one credit window (10 s): the first fetch waits it out
    /// and the starved miss isn't retried in place, so the join fails at
    /// the budget for the caller's whole-request retry to take over.
    #[tokio::test(start_paused = true)]
    async fn starved_buffered_join_waits_one_credit_window_per_child() {
        let addr = [0x77u8; 32];
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        let started = tokio::time::Instant::now();
        let err = crate::join(&fetcher, &two_leaf_root(addr), 1 << 20)
            .await
            .expect_err("pool never refills");
        let waited = started.elapsed();
        assert!(
            waited >= CREDIT_WAIT_BUDGET && waited < CREDIT_WAIT_BUDGET + OVERDRAFT_REFRESH,
            "buffered join of a starved child took {waited:?}",
        );
        assert!(err.to_string().contains("no BZZ peers available"), "{err}");
    }

    /// Issue #122: a bare `/bzz/<ref>/`'s sniff waits for credit on a
    /// starved pool (real `RoutingFetcher`), but only inside its credit
    /// window, and the fallback join after it adds no wait of its own.
    /// The root is in the request cache (`run_stream_bzz` already fetched
    /// it); its leftmost child is starved and never refills. Measured
    /// against the same lookup with the window already spent (exactly
    /// the pre-#122, non-waiting lookup), the sniff adds one capped wait
    /// (10 s from a fresh 30 s window), what is left of a nearly spent
    /// window (5 s), and nothing more: the fallback join's fetches and
    /// retries stay non-waiting.
    #[tokio::test(start_paused = true)]
    async fn starved_bare_root_sniff_waits_only_inside_its_window() {
        let child = [0x99u8; 32];
        let root_wire = two_leaf_root(child);
        let root =
            ant_crypto::bmt_hash_with_span(root_wire[..8].try_into().unwrap(), &root_wire[8..])
                .unwrap();
        let window = Duration::from_secs(30);
        let lookup = |left: Duration| {
            let root_wire = root_wire.clone();
            async move {
                let (fetcher, _acc, _p, held) = starved_fetcher(child);
                let cache = Arc::new(InMemoryChunkCache::new(8));
                cache.put(root, root_wire);
                let fetcher = fetcher.with_cache(cache);
                let credit = crate::accounting::CreditWindow::new(window);
                tokio::time::advance(window.saturating_sub(left)).await;
                let started = tokio::time::Instant::now();
                let r = crate::lookup_path_with_credit(
                    &fetcher,
                    &root,
                    "",
                    &credit,
                    &crate::ReplicaSweeps::new(),
                    None,
                )
                .await;
                drop(held);
                assert!(r.is_err(), "pool never refills");
                started.elapsed()
            }
        };
        let non_waiting = lookup(Duration::ZERO).await;
        for (left, sniff_wait) in [
            (window, CREDIT_WAIT_BUDGET),
            (Duration::from_secs(5), Duration::from_secs(5)),
        ] {
            let took = lookup(left).await;
            let extra = took.saturating_sub(non_waiting);
            assert!(
                extra >= sniff_wait && extra < sniff_wait + OVERDRAFT_REFRESH,
                "{left:?} left in the window: lookup took {took:?}, \
                 {extra:?} more than the non-waiting {non_waiting:?}",
            );
        }
    }

    /// A one-page site's manifest (`index.html` as index document) for
    /// the walk tests below: its root node, and every node below the
    /// root, which a cold walk must fetch. Returns `(root, root wire,
    /// cheapest node below the root)`; a pool starved at that node's
    /// price is starved for every node (a peer's price only rises with
    /// distance), so wherever the walk goes next it finds no credit.
    fn one_page_site() -> ([u8; 32], Vec<u8>, [u8; 32]) {
        use crate::manifest_writer::{build_collection_manifest, IndexAnchor, ManifestFile};
        let page = crate::split_bytes(b"<html>hi</html>");
        let manifest = build_collection_manifest(
            &[ManifestFile {
                path: "index.html".into(),
                content_type: Some("text/html".into()),
                data_ref: page.root.to_vec(),
            }],
            Some("index.html"),
            IndexAnchor::ZeroEntry,
        )
        .unwrap();
        let root_wire = manifest
            .chunks
            .iter()
            .find(|c| c.address == manifest.root)
            .unwrap()
            .wire
            .clone();
        let o = [0x80u8; 32];
        let cheapest = manifest
            .chunks
            .iter()
            .map(|c| c.address)
            .filter(|a| *a != manifest.root)
            .min_by_key(|a| Accounting::peer_price(&o, a))
            .expect("a node below the root");
        (manifest.root, root_wire, cheapest)
    }

    /// Issue #130: the `/bzz` walk's node loads wait for credit on a
    /// starved pool (real `RoutingFetcher`), but only inside the
    /// resolution window. The site's root is in the request cache; the
    /// node below it is starved and never refills. Measured against the
    /// same lookup with the window already spent (exactly the pre-#130,
    /// non-waiting walk, which fails at once), the walk adds one capped
    /// wait (10 s from a fresh 30 s window), what is left of a nearly
    /// spent window (5 s), and nothing more.
    #[tokio::test(start_paused = true)]
    async fn starved_manifest_walk_waits_only_inside_its_window() {
        let (root, root_wire, starved) = one_page_site();
        let window = Duration::from_secs(30);
        for path in ["", "index.html"] {
            let lookup = |left: Duration| {
                let root_wire = root_wire.clone();
                async move {
                    let (fetcher, _acc, _p, held) = starved_fetcher(starved);
                    let cache = Arc::new(InMemoryChunkCache::new(8));
                    cache.put(root, root_wire);
                    let fetcher = fetcher.with_cache(cache);
                    let credit = crate::accounting::CreditWindow::new(window);
                    tokio::time::advance(window.saturating_sub(left)).await;
                    let started = tokio::time::Instant::now();
                    let r = crate::lookup_path_with_credit(
                        &fetcher,
                        &root,
                        path,
                        &credit,
                        &crate::ReplicaSweeps::new(),
                        None,
                    )
                    .await;
                    drop(held);
                    let err = r.expect_err("pool never refills");
                    assert!(
                        err.to_string().contains("no BZZ peers available"),
                        "{path:?}: {err}",
                    );
                    started.elapsed()
                }
            };
            let non_waiting = lookup(Duration::ZERO).await;
            assert_eq!(
                non_waiting,
                Duration::ZERO,
                "{path:?}: a plain walk fails at once"
            );
            for (left, walk_wait) in [
                (window, CREDIT_WAIT_BUDGET),
                (Duration::from_secs(5), Duration::from_secs(5)),
            ] {
                let took = lookup(left).await;
                assert!(
                    took >= walk_wait && took < walk_wait + OVERDRAFT_REFRESH,
                    "{path:?}, {left:?} left in the window: lookup took {took:?}",
                );
            }
        }
    }

    /// Issue #130: a site lookup queues for credit like the body fetches
    /// it competes with. Its walk, starved below the cached root, waits
    /// instead of failing, and once the peer's credit comes free it is
    /// woken (not left to its 600 ms timer) and asks that peer: its
    /// reservation shows up in the accounting.
    #[tokio::test]
    async fn starved_manifest_walk_waits_for_credit_then_asks_the_peer() {
        let (root, root_wire, starved) = one_page_site();
        let (fetcher, acc, p, held) = starved_fetcher(starved);
        let cache = Arc::new(InMemoryChunkCache::new(8));
        cache.put(root, root_wire);
        let fetcher = fetcher.with_cache(cache);
        let h = tokio::spawn(async move {
            let credit = crate::accounting::CreditWindow::new(Duration::from_secs(30));
            crate::lookup_path_with_credit(
                &fetcher,
                &root,
                "",
                &credit,
                &crate::ReplicaSweeps::new(),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !h.is_finished(),
            "the walk must wait for credit on a starved pool, got {:?}",
            h.await.unwrap(),
        );

        let held_reserve = acc.debug_snapshot(&p).unwrap().1;
        drop(held);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (_, reserved) = acc.debug_snapshot(&p).unwrap();
        assert!(
            reserved > 0 && reserved < held_reserve,
            "the walk's node fetch must have reserved credit and dispatched: reserved {reserved}",
        );
        h.abort();
    }

    /// Issue #117: the opted-in data path (the streaming joiner's child
    /// fetches) waits for credit instead of failing on a starved pool,
    /// and once the peer's credit comes free it is woken (not left to
    /// its 600 ms timer) and dispatches to that peer: its reservation
    /// shows up in the accounting.
    #[tokio::test]
    async fn streaming_join_waits_for_credit_then_asks_the_peer() {
        let addr = [0x88u8; 32];
        let (fetcher, acc, p, held) = starved_fetcher(addr);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let h = tokio::spawn(async move {
            crate::join_to_sender(
                &fetcher,
                &two_leaf_root(addr),
                1 << 20,
                crate::JoinOptions::default(),
                tx,
            )
            .await
            .map_err(|e| e.to_string())
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !h.is_finished(),
            "the streaming joiner must wait for credit on a starved pool, got {:?}",
            h.await.unwrap(),
        );

        let held_reserve = acc.debug_snapshot(&p).unwrap().1;
        drop(held);
        // Woken by the release, well before the 600 ms re-check.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (_, reserved) = acc.debug_snapshot(&p).unwrap();
        assert!(
            reserved > 0 && reserved < held_reserve,
            "the joiner's fetch must have reserved credit and dispatched: reserved {reserved}",
        );
        h.abort();
    }

    /// Issue #46: a peer's last chunk of credit goes to the head of a
    /// streaming join's window, not to a look-ahead fetch that asked for
    /// it first. The peer has 400k units left: one chunk, but not one
    /// chunk plus [`HEAD_CREDIT_RESERVE`](crate::accounting::HEAD_CREDIT_RESERVE).
    /// The look-ahead fetch is polled first, as the joiner's fan-out
    /// polls a sibling that started earlier; it must leave the credit
    /// and wait, and the head fetch must reserve it and be dispatched.
    /// The two chunks are priced differently, so the reservation shows
    /// which one got it.
    #[tokio::test(start_paused = true)]
    async fn look_ahead_fetch_leaves_the_last_credit_to_the_head() {
        use crate::priority::{at_offset, with_read_head, ReadHead, HEAD_WINDOW};
        let acc = Arc::new(Accounting::new());
        let p = PeerId::random();
        let o = [0x80u8; 32];
        // Proximity 0 to `o`: the highest price, 320k.
        let ahead_addr = [0x11u8; 32];
        // Proximity 1: 310k.
        let head_addr = [0xC1u8; 32];
        assert_eq!(Accounting::peer_price(&o, &ahead_addr), 320_000);
        assert_eq!(Accounting::peer_price(&o, &head_addr), 310_000);
        let held = crate::accounting::OVERDRAFT_LIMIT - 400_000;
        let _held = acc.try_reserve(p, held).expect("admits");
        let behaviour = libp2p_stream::Behaviour::default();
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), vec![(p, o)])
            .with_accounting(acc.clone());

        let ahead_done = Arc::new(std::sync::Mutex::new(None));
        let done = ahead_done.clone();
        let h = tokio::spawn(with_read_head(ReadHead::new(0), async move {
            let started = tokio::time::Instant::now();
            let ahead = at_offset(4 * HEAD_WINDOW, async {
                let r = fetcher
                    .fetch_waiting_for_credit(ahead_addr, CREDIT_WAIT_BUDGET)
                    .await;
                let starved = r
                    .as_ref()
                    .err()
                    .and_then(|e| e.downcast_ref::<FetchExhausted>())
                    .is_some_and(|e| e.pool_starved);
                *done.lock().unwrap() = Some((started.elapsed(), starved));
            });
            // The dummy transport never answers: the head fetch hangs
            // in its dispatch, holding its reservation.
            let head = at_offset(0, async {
                let _ = fetcher
                    .fetch_waiting_for_credit(head_addr, CREDIT_WAIT_BUDGET)
                    .await;
            });
            futures::join!(ahead, head);
        }));

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            acc.debug_snapshot(&p).unwrap().1,
            held + 310_000,
            "the head fetch, not the look-ahead one, must hold the last credit",
        );
        tokio::time::sleep(CREDIT_WAIT_BUDGET).await;
        let (waited, starved) = ahead_done.lock().unwrap().expect("look-ahead fetch done");
        assert!(
            starved && waited >= CREDIT_WAIT_BUDGET,
            "the look-ahead fetch must wait for credit beyond the head's reserve: starved {starved} after {waited:?}",
        );
        h.abort();
    }

    /// Issue #46: a fetch at the head of a streaming join's window skips
    /// its request's in-flight queue; a look-ahead or unranked one waits
    /// its turn, and a look-ahead one skips it too once the consumer has
    /// caught up with it. "Dispatched" = past the permits, where the
    /// progress tracker counts a fetch in flight.
    #[tokio::test]
    async fn head_fetch_skips_the_request_queue() {
        use crate::priority::{at_offset, with_read_head, ReadHead, HEAD_WINDOW};
        let p = PeerId::random();
        let behaviour = libp2p_stream::Behaviour::default();
        let tracker = Arc::new(ProgressTracker::new(false));
        let fetcher = Arc::new(
            RoutingFetcher::with_static_peers(behaviour.new_control(), vec![(p, [0u8; 32])])
                .with_request_inflight_limit(1)
                .with_progress(tracker.clone()),
        );
        // Hold the request's only permit.
        let _hold = fetcher
            .request_inflight_limit
            .clone()
            .unwrap()
            .acquire_owned()
            .await
            .unwrap();
        let read_head = ReadHead::new(0);
        let spawn_at = |offset: Option<u64>| {
            let fetcher = fetcher.clone();
            let read_head = read_head.clone();
            tokio::spawn(async move {
                let fetch = async { fetcher.fetch([0x42u8; 32]).await.map(|_| ()) };
                match offset {
                    Some(offset) => with_read_head(read_head, at_offset(offset, fetch)).await,
                    None => fetch.await,
                }
            })
        };
        let in_flight = || tracker.snapshot().in_flight;
        let unranked = spawn_at(None);
        let ahead = spawn_at(Some(2 * HEAD_WINDOW));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            in_flight(),
            0,
            "unranked and look-ahead fetches wait for the permit"
        );

        let head = spawn_at(Some(0));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            in_flight(),
            1,
            "the head fetch must not wait for the request's permit"
        );

        // The consumer catches up: the waiting look-ahead fetch is now
        // the head and goes ahead at once.
        read_head.advance(2 * HEAD_WINDOW);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            in_flight(),
            2,
            "a look-ahead fetch the consumer caught up with skips the queue",
        );
        for h in [unranked, ahead, head] {
            h.abort();
        }
    }

    /// R1-M2 on PR #135: a look-ahead fetch waiting for its request's
    /// permit keeps its place in the FIFO queue, so an unranked fetch
    /// that queued after it does not overtake it, however long it waited.
    #[tokio::test(start_paused = true)]
    async fn look_ahead_keeps_its_place_in_the_request_queue() {
        use crate::priority::{at_offset, with_read_head, ReadHead, HEAD_WINDOW};
        let sem = Arc::new(Semaphore::new(1));
        let hold = sem.clone().acquire_owned().await.unwrap();
        let ahead = tokio::spawn(with_read_head(
            ReadHead::new(0),
            at_offset(2 * HEAD_WINDOW, acquire_request_permit(sem.clone())),
        ));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let unranked = tokio::spawn(acquire_request_permit(sem.clone()));
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(hold);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            ahead.is_finished(),
            "the look-ahead fetch queued first and must get the permit first",
        );
        assert!(!unranked.is_finished());
        drop(ahead.await.unwrap().expect("a permit, not a head bypass"));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(unranked.is_finished());
    }

    /// R1-M2 on PR #119: a credit wake-up the oldest waiter can't use
    /// (the credit is on a peer it has no use for) is handed on, not
    /// swallowed: a later waiter that can use it dispatches at once
    /// instead of sleeping out its `OVERDRAFT_REFRESH` timer.
    #[tokio::test]
    async fn unusable_credit_wake_up_is_passed_on() {
        let addr = [0x66u8; 32];
        let acc = Arc::new(Accounting::new());
        // Oldest waiter: its only peer stays starved.
        let (a, _pa, _held_a) = starved_fetcher_on(acc.clone(), addr);
        let ha = tokio::spawn(async move {
            a.fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET)
                .await
                .map_err(|e| e.to_string())
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Younger waiter: its peer gets one chunk's credit back.
        let (b, pb, mut held_b) = starved_fetcher_on(acc.clone(), addr);
        let hb = tokio::spawn(async move {
            b.fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET)
                .await
                .map_err(|e| e.to_string())
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!ha.is_finished() && !hb.is_finished(), "both must wait");

        // One release on `pb`: wakes the oldest waiter (`a`) first,
        // which can't use it and must pass it on to `b`.
        let before = acc.debug_snapshot(&pb).unwrap().1;
        drop(held_b.pop());
        tokio::time::sleep(Duration::from_millis(150)).await;
        let (_, reserved) = acc.debug_snapshot(&pb).unwrap();
        assert_eq!(
            reserved, before,
            "the younger waiter must have re-reserved the freed credit \
             well before its 600 ms re-check",
        );
        ha.abort();
        hb.abort();
    }

    /// Issue #117: a credit-waiting fetch on a starved pool waits for
    /// credit, as bee's `RetrieveChunk` sleeps `overDraftRefresh`,
    /// instead of failing with `no BZZ peers available` at once. Once
    /// the peer's credit comes free, the waiter is woken (not left to its
    /// timer) and dispatches to that peer.
    #[tokio::test]
    async fn starved_fetch_waits_for_credit_then_asks_the_peer() {
        let addr = [0x11u8; 32];
        let (fetcher, acc, p, held) = starved_fetcher(addr);
        let h = tokio::spawn(async move {
            fetcher
                .fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET)
                .await
                .map_err(|e| e.to_string())
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !h.is_finished(),
            "a credit-waiting fetch starved by accounting must wait, got {:?}",
            h.await.unwrap(),
        );

        let held_reserve = acc.debug_snapshot(&p).unwrap().1;
        drop(held);
        // Woken by the release, well before the 600 ms re-check.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (_, reserved) = acc.debug_snapshot(&p).unwrap();
        assert!(
            reserved > 0 && reserved < held_reserve,
            "the fetch must have reserved credit and dispatched: reserved {reserved}",
        );
        h.abort();
    }

    /// The credit wait is bounded: a pool that never refills fails after
    /// the caller's budget with the old message, flagged starved.
    #[tokio::test(start_paused = true)]
    async fn starved_fetch_gives_up_after_the_credit_wait_budget() {
        let addr = [0x22u8; 32];
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(
            CREDIT_WAIT_BUDGET * 3,
            fetcher.fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET),
        )
        .await
        .expect("the credit wait must be bounded")
        .expect_err("pool never refills");
        let waited = started.elapsed();
        assert!(
            waited >= CREDIT_WAIT_BUDGET && waited < CREDIT_WAIT_BUDGET + OVERDRAFT_REFRESH,
            "waited {waited:?}",
        );
        assert_eq!(err.to_string(), "no BZZ peers available");
        let typed = err.downcast_ref::<FetchExhausted>().expect("typed");
        assert!(typed.pool_starved);
    }

    /// A fetcher's credit deadline cuts every credit wait short: the
    /// buffered whole-request retries share one deadline this way. Past
    /// it the fetcher no longer reports that it waits for credit, so a
    /// later join's starved misses aren't cut off at the credit window
    /// either (PR #119 R2-M2).
    #[tokio::test(start_paused = true)]
    async fn credit_deadline_caps_the_wait() {
        let addr = [0x23u8; 32];
        let (fetcher, _acc, _p, _held) = starved_fetcher(addr);
        assert!(fetcher.waits_for_credit());
        let deadline = Duration::from_secs(2);
        let fetcher = fetcher.with_credit_deadline(tokio::time::Instant::now() + deadline);
        assert!(fetcher.waits_for_credit(), "deadline not yet reached");
        let started = tokio::time::Instant::now();
        fetcher
            .fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET)
            .await
            .expect_err("pool never refills");
        let waited = started.elapsed();
        assert!(
            waited >= deadline && waited < deadline + OVERDRAFT_REFRESH,
            "waited {waited:?}",
        );
        // Past the deadline a credit-waiting fetch fails at once.
        let started = tokio::time::Instant::now();
        fetcher
            .fetch_waiting_for_credit(addr, CREDIT_WAIT_BUDGET)
            .await
            .expect_err("pool never refills");
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(
            !fetcher.waits_for_credit(),
            "past its deadline the fetcher no longer waits for credit",
        );
    }

    /// No peers at all is not starvation: nothing can refill, so even a
    /// credit-waiting fetch fails at once.
    #[tokio::test(start_paused = true)]
    async fn fetch_without_peers_fails_at_once() {
        let behaviour = libp2p_stream::Behaviour::default();
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), Vec::new())
            .with_accounting(Arc::new(Accounting::new()));
        let started = tokio::time::Instant::now();
        let err = fetcher
            .fetch_waiting_for_credit([0x33u8; 32], CREDIT_WAIT_BUDGET)
            .await
            .expect_err("no peers");
        assert_eq!(err.to_string(), "no BZZ peers available");
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// Tier-2 short-circuit: a `fetch` whose chunk is already stored
    /// in the persistent disk cache must return the wire bytes
    /// without ever reaching the network. Without an empty peer set
    /// (which would normally produce `"no BZZ peers available"`) the
    /// disk hit must succeed *before* we get to the dispatcher loop.
    /// This test pins the load-bearing rule that the disk tier sits
    /// in front of the network, not behind it.
    #[tokio::test]
    async fn fetch_returns_disk_cache_hit_without_peers() {
        use ant_crypto::cac_new;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let disk = Arc::new(DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap());
        let (addr, wire) = cac_new(b"tier-2 hit").unwrap();
        disk.put(addr, wire.clone()).await.unwrap();

        // Empty peer set: any code path that reaches the dispatcher
        // returns `Err("no BZZ peers available")`. The disk hit must
        // short-circuit it.
        let (_tx, rx) = watch::channel(Vec::new());
        let behaviour = libp2p_stream::Behaviour::default();
        let control = behaviour.new_control();
        let mem = Arc::new(InMemoryChunkCache::new(8));
        let counters = Arc::new(RetrievalCounters::new());
        let fetcher = RoutingFetcher::new(control, rx)
            .with_cache(mem.clone())
            .with_disk_cache(disk)
            .with_counters(counters.clone());

        let bytes = fetcher.fetch(addr).await.expect("disk hit");
        assert_eq!(bytes, wire, "disk hit returned the wrong bytes");

        // Tier promotion: a disk hit must also lift the chunk into
        // the in-memory tier so the next fetch in this process skips
        // SQLite. Without this, every fetch in a hot loop would pay
        // the spawn_blocking + lock + UPDATE last_access cost even
        // though the bytes are already in RAM.
        assert_eq!(
            mem.get(&addr),
            Some(wire.clone()),
            "disk hit must write through to the in-memory tier",
        );

        // Counter accounting: the first fetch was a disk hit (tier
        // promotion writes back to memory but the *delivery* came
        // from disk), so `disk_hits` must bump and `mem_hits` must
        // stay at zero. A second fetch then comes out of the
        // freshly-warmed in-memory tier, so it bumps `mem_hits`
        // without re-incrementing `disk_hits`. This pins the
        // tier-attribution rule the `antop` Disk-cache row
        // depends on.
        let snap = counters.snapshot();
        assert_eq!(snap.disk_hits, 1, "disk delivery must record disk_hits");
        assert_eq!(snap.mem_hits, 0, "tier-promotion is not a memory hit");
        assert_eq!(snap.chunks_fetched, 1);

        let _ = fetcher.fetch(addr).await.expect("memory hit");
        let snap = counters.snapshot();
        assert_eq!(
            snap.disk_hits, 1,
            "warm in-memory hit must not bump disk_hits"
        );
        assert_eq!(snap.mem_hits, 1, "warm in-memory hit must bump mem_hits");
        assert_eq!(snap.chunks_fetched, 2);
    }

    /// Tier-2 bypass: when the daemon runs in `bypass_cache` mode for
    /// a given request, neither disk reads nor disk writes happen.
    /// We model that here by simply not attaching the disk cache to
    /// the fetcher — the production wiring in
    /// `ant-p2p::SwarmState::cache_for_request` does the same thing.
    /// The test asserts: with a chunk planted on disk and bypass in
    /// effect, the fetch falls through to the network (no peers →
    /// errors out). The disk row must still be there afterwards (no
    /// stealth read-and-discard).
    #[tokio::test]
    async fn fetch_with_bypass_skips_disk_reads() {
        use ant_crypto::cac_new;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let disk = Arc::new(DiskChunkCache::open(dir.path().join("disk.sqlite"), 1 << 20).unwrap());
        let (addr, wire) = cac_new(b"bypass test").unwrap();
        disk.put(addr, wire.clone()).await.unwrap();
        assert_eq!(disk.row_count().await.unwrap(), 1);

        // Same empty peer set as above: the only way `fetch` returns
        // bytes is if the disk hit short-circuits. We deliberately
        // build the fetcher *without* `.with_disk_cache(...)` — that
        // is the bypass path.
        let (_tx, rx) = watch::channel(Vec::new());
        let behaviour = libp2p_stream::Behaviour::default();
        let control = behaviour.new_control();
        let fetcher =
            RoutingFetcher::new(control, rx).with_cache(Arc::new(InMemoryChunkCache::new(8)));

        let res = fetcher.fetch(addr).await;
        assert!(res.is_err(), "bypass must not consult the disk cache");

        // The disk row must remain untouched — bypass means "skip
        // the disk", not "read it and pretend the row didn't exist".
        assert_eq!(
            disk.row_count().await.unwrap(),
            1,
            "bypass must not read or delete the planted disk row",
        );
    }

    #[test]
    fn stamp_rejection_classifier_matches_bee_phrasings() {
        use crate::pushsync::PushSyncError as E;
        // The live bee 2.8 rejection observed in the field report.
        assert!(is_stamp_rejection(&E::Remote(
            "invalid stamp: batchstore get: get batch de33180c: storage: not found, not found"
                .into()
        )));
        assert!(is_stamp_rejection(&E::Remote(
            "invalid stamp: unknown batch".into()
        )));
        // Signature/bucket stamp problems are OUR bug, not a phantom
        // batch — must not trip the classifier.
        assert!(!is_stamp_rejection(&E::Remote(
            "invalid stamp: signature recovery failed".into()
        )));
        assert!(!is_stamp_rejection(&E::Remote(
            "could not push chunk".into()
        )));
        assert!(!is_stamp_rejection(&E::Timeout(
            std::time::Duration::from_secs(1)
        )));
    }

    /// How a scripted test peer answers a retrieval request.
    #[derive(Clone, Copy)]
    enum Answer {
        /// Bee's `storage: not found`, after `ms`.
        NotFound(u64),
        /// Bee's `no peer found`, after `ms`.
        NoPeer(u64),
        /// The request times out after `ms` (a dead link).
        Timeout(u64),
        /// The chunk, after `ms`.
        Deliver(u64),
    }

    /// What the scripted peers saw: requests made, and the most that
    /// were ever in flight at once.
    #[derive(Default)]
    struct Script {
        asked: std::sync::atomic::AtomicUsize,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
    }

    /// Wire bytes the scripted peers deliver.
    fn scripted_wire() -> Vec<u8> {
        let mut wire = 5u64.to_le_bytes().to_vec();
        wire.extend_from_slice(b"slot!");
        wire
    }

    /// A fetcher over `answers.len()` peers, ranked closest-first to
    /// `addr` (`answers[0]` answers for the closest), each answering as
    /// scripted. Requests never touch the network.
    fn scripted_fetcher(
        addr: [u8; 32],
        answers: &[Answer],
        fast_miss: bool,
    ) -> (RoutingFetcher, Arc<Script>) {
        let mut peers = Vec::new();
        let mut table = std::collections::HashMap::new();
        for (i, answer) in answers.iter().enumerate() {
            let p = PeerId::random();
            let mut o = addr;
            // Distance to `addr` grows with `i`.
            o[0] ^= u8::try_from(i + 1).expect("< 256 peers");
            peers.push((p, o));
            table.insert(p, *answer);
        }
        let script = Arc::new(Script::default());
        let seen = script.clone();
        let behaviour = libp2p_stream::Behaviour::default();
        let fetcher = RoutingFetcher::with_static_peers(behaviour.new_control(), peers)
            .with_fast_miss(fast_miss)
            .with_mock_retrieve(move |peer, address| {
                let answer = table[&peer];
                let seen = seen.clone();
                Box::pin(async move {
                    use std::sync::atomic::Ordering::SeqCst;
                    seen.asked.fetch_add(1, SeqCst);
                    let now = seen.in_flight.fetch_add(1, SeqCst) + 1;
                    seen.max_in_flight.fetch_max(now, SeqCst);
                    let (ms, result) = match answer {
                        Answer::NotFound(ms) => (
                            ms,
                            Err(RetrievalError::Remote(
                                "retrieve chunk: storage: not found".into(),
                            )),
                        ),
                        Answer::NoPeer(ms) => (
                            ms,
                            Err(RetrievalError::Remote(
                                "retrieve chunk: no peer found".into(),
                            )),
                        ),
                        Answer::Timeout(ms) => {
                            (ms, Err(RetrievalError::Timeout(Duration::from_millis(ms))))
                        }
                        Answer::Deliver(ms) => (
                            ms,
                            Ok(RetrievedChunk {
                                address,
                                data: scripted_wire(),
                            }),
                        ),
                    };
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    seen.in_flight.fetch_sub(1, SeqCst);
                    result
                })
            });
        (fetcher, script)
    }

    fn asked(script: &Script) -> usize {
        script.asked.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn max_in_flight(script: &Script) -> usize {
        script
            .max_in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[test]
    fn fast_miss_rule() {
        assert_eq!(fast_miss_width(0), 1);
        assert_eq!(fast_miss_width(1), FAST_MISS_FANOUT);
        assert_eq!(fast_miss_width(FAST_MISS_NOT_FOUND - 1), FAST_MISS_FANOUT);
        assert!(!fast_miss_done(FAST_MISS_NOT_FOUND - 1));
        assert!(fast_miss_done(FAST_MISS_NOT_FOUND));
    }

    /// Once a "not found" is in, a fast-miss lookup's top-up never puts
    /// more requests in flight than the error budget left can answer for;
    /// before that, and in a plain fetch, the failed request is just
    /// replaced.
    #[test]
    fn backfill_target_respects_error_budget() {
        // Plain fetch: one replacement, whatever the budget.
        assert_eq!(backfill_target(false, 7, 5, 3), 8);
        assert_eq!(backfill_target(false, 0, 0, 1), 1);
        // Fast miss, before any "not found": a plain fetch's replacement.
        assert_eq!(backfill_target(true, 0, 0, 31), 1);
        assert_eq!(backfill_target(true, 1, 0, 31), 2);
        assert_eq!(backfill_target(true, 7, 0, 3), 8);
        // After a "not found": top up to the fan-out.
        assert_eq!(backfill_target(true, 0, 1, 31), FAST_MISS_FANOUT);
        assert_eq!(backfill_target(true, 7, 1, 31), FAST_MISS_FANOUT);
        // The finding's case: 7 in flight, 3 errors left — no 8th request.
        assert_eq!(backfill_target(true, 7, 5, 3), 3);
        // Nothing in flight, budget nearly gone: still one request.
        assert_eq!(backfill_target(true, 0, 5, 1), 1);
        assert_eq!(backfill_target(true, 0, 5, 3), 3);
    }

    /// Issue #146: a slot that doesn't exist yet. Every peer answers
    /// "not found" in 60 ms. A fast-miss lookup asks the closest peer,
    /// then keeps `FAST_MISS_FANOUT` in flight and stops at
    /// `FAST_MISS_NOT_FOUND` answers: three round trips instead of 32,
    /// with a corroborated miss for the gateway's 404. A plain fetch
    /// still walks the whole budget one peer at a time (plus its 1 s
    /// hedges).
    #[tokio::test(start_paused = true)]
    async fn fast_miss_stops_once_enough_peers_say_not_found() {
        let addr = [0x46u8; 32];
        let mut answers = vec![Answer::NotFound(60); 48];
        // Both of bee's miss tails count.
        answers[3] = Answer::NoPeer(60);
        let (fetcher, script) = scripted_fetcher(addr, &answers, true);
        let started = tokio::time::Instant::now();
        let err = fetcher.fetch(addr).await.expect_err("nobody has it");
        assert_eq!(started.elapsed(), Duration::from_millis(180));
        let typed = err.downcast_ref::<FetchExhausted>().expect("typed");
        assert!(typed.corroborated_missing(), "{typed:?}");
        assert_eq!(typed.not_found_answers, FAST_MISS_NOT_FOUND);
        assert_eq!(max_in_flight(&script), FAST_MISS_FANOUT);
        assert!(asked(&script) < FAST_MISS_NOT_FOUND + FAST_MISS_FANOUT);

        let (fetcher, script) = scripted_fetcher(addr, &answers, false);
        let started = tokio::time::Instant::now();
        let err = fetcher.fetch(addr).await.expect_err("nobody has it");
        assert!(started.elapsed() > Duration::from_millis(1_400));
        let typed = err.downcast_ref::<FetchExhausted>().expect("typed");
        assert!(typed.not_found_answers >= MAX_ORIGIN_ERRORS);
        assert!(max_in_flight(&script) <= 2);
    }

    /// A chunk the closest peer has costs one request, as before: the
    /// lookup only widens after a "not found".
    #[tokio::test(start_paused = true)]
    async fn fast_miss_asks_one_peer_until_a_miss() {
        let addr = [0x46u8; 32];
        let mut answers = vec![Answer::Deliver(60)];
        answers.extend([Answer::NotFound(60); 20]);
        let (fetcher, script) = scripted_fetcher(addr, &answers, true);
        let wire = fetcher.fetch(addr).await.expect("closest peer has it");
        assert_eq!(wire, scripted_wire());
        assert_eq!(asked(&script), 1);
    }

    /// On mainnet a chunk that exists sometimes comes only after many
    /// peers said "not found" (one of 147 feed chunks needed fifteen).
    /// The lookup finds it as long as it arrives before the
    /// `FAST_MISS_NOT_FOUND`th "not found".
    #[tokio::test(start_paused = true)]
    async fn fast_miss_still_finds_a_chunk_after_many_not_found_answers() {
        let addr = [0x46u8; 32];
        let mut answers = vec![Answer::NotFound(60); 40];
        answers[FAST_MISS_NOT_FOUND - 1] = Answer::Deliver(40);
        let (fetcher, script) = scripted_fetcher(addr, &answers, true);
        let wire = fetcher.fetch(addr).await.expect("rank-15 peer has it");
        assert_eq!(wire, scripted_wire());
        assert!(asked(&script) <= FAST_MISS_NOT_FOUND + FAST_MISS_FANOUT);
    }

    /// Timeouts say nothing about the chunk: they don't count toward the
    /// stop, so the lookup falls through them to further peers, even
    /// with `FAST_MISS_NOT_FOUND - 1` "not found" answers already in.
    #[tokio::test(start_paused = true)]
    async fn fast_miss_timeouts_fall_through_to_further_peers() {
        let addr = [0x46u8; 32];
        let mut answers = vec![Answer::NotFound(60); FAST_MISS_NOT_FOUND - 1];
        answers.extend([Answer::Timeout(500); 12]);
        answers.push(Answer::Deliver(60));
        let deliverer = answers.len();
        let (fetcher, script) = scripted_fetcher(addr, &answers, true);
        let wire = fetcher.fetch(addr).await.expect("found past the timeouts");
        assert_eq!(wire, scripted_wire());
        assert_eq!(asked(&script), deliverer);

        // With no "not found" answer at all the lookup is exactly a
        // plain fetch: same peers, same time, whole error budget.
        let answers = vec![Answer::Timeout(500); 48];
        let mut runs = Vec::new();
        for fast_miss in [true, false] {
            let (fetcher, script) = scripted_fetcher(addr, &answers, fast_miss);
            let started = tokio::time::Instant::now();
            let err = fetcher.fetch(addr).await.expect_err("dead links");
            let typed = err.downcast_ref::<FetchExhausted>().expect("typed");
            assert!(!typed.confirmed_missing(), "{typed:?}");
            runs.push((started.elapsed(), asked(&script), max_in_flight(&script)));
        }
        assert_eq!(runs[0], runs[1]);
        assert!(runs[0].1 >= MAX_ORIGIN_ERRORS);
    }

    /// No negative caching: a request still in flight when the lookup
    /// stops is drained, and its late delivery lands in the cache, so the
    /// next poll for the slot is served at once.
    #[tokio::test(start_paused = true)]
    async fn fast_miss_late_delivery_serves_the_next_poll() {
        let addr = [0x46u8; 32];
        let mut answers = vec![Answer::NotFound(60); 40];
        answers[1] = Answer::Deliver(2_000);
        let (fetcher, script) = scripted_fetcher(addr, &answers, true);
        let fetcher = fetcher.with_cache(Arc::new(InMemoryChunkCache::new(16)));
        fetcher
            .fetch(addr)
            .await
            .expect_err("stops before the slow peer answers");
        tokio::time::sleep(Duration::from_secs(3)).await;
        let asked_before = asked(&script);
        let wire = fetcher.fetch(addr).await.expect("drained delivery cached");
        assert_eq!(wire, scripted_wire());
        assert_eq!(asked(&script), asked_before, "served from cache");
    }

    /// A detached copy (a feed probe finishing in the background, issue
    /// #190) runs the full retrieval budget even when the original was a
    /// fast-miss lookup, and what it fetches lands in the original's
    /// chunk cache.
    #[tokio::test(start_paused = true)]
    async fn detached_copy_runs_the_full_budget_into_the_shared_cache() {
        let addr = [0x47u8; 32];
        // Past the fast-miss stop, inside the full error budget.
        let mut answers = vec![Answer::NotFound(10); 28];
        answers.push(Answer::Deliver(10));
        let (fetcher, script) = scripted_fetcher(addr, &answers, true);
        let fetcher = fetcher.with_cache(Arc::new(InMemoryChunkCache::new(16)));
        fetcher
            .fetch(addr)
            .await
            .expect_err("fast miss stops before the holder");
        let detached = fetcher.detached().expect("RoutingFetcher detaches");
        let wire = detached.fetch(addr).await.expect("full budget reaches it");
        assert_eq!(wire, scripted_wire());
        drop(detached);
        let asked_before = asked(&script);
        assert_eq!(fetcher.fetch(addr).await.expect("cached"), scripted_wire());
        assert_eq!(asked(&script), asked_before, "served from the shared cache");
    }
}
