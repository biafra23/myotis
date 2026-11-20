//! `antctl upload` job manager.
//!
//! Responsible for the long-lived state of in-flight, paused,
//! completed, and cancelled uploads. Each job is one daemon-side
//! task that walks a source file, splits it incrementally with
//! [`StreamingSplitter`], and pushsyncs every produced chunk to the
//! network through the existing [`ControlCommand::PushChunk`]
//! pipeline (so postage stamping reuses
//! `ant_p2p::UploadRuntime::issuer` exactly the way `POST /chunks`
//! does today).
//!
//! ## Key design points
//!
//! - **Streaming.** The source is mmap'd via [`memmap2::Mmap`] so a
//!   7 GiB file doesn't double-allocate; the kernel pages it in/out
//!   as we walk it. Resident memory is `levels × BRANCHES × 32 B +
//!   in-flight push window` ≈ tens of KB for any file size.
//!
//! - **Resume.** [`StreamingSplitter`] is deterministic (same input
//!   ⇒ same chunk addresses), so on resume we re-mmap, re-stream
//!   from byte 0, recompute every address, and skip pushsync for
//!   the first `chunks_pushed` chunks. No per-chunk receipts on
//!   disk, and the postage issuer is only consulted when we
//!   actually dispatch a `PushChunk`, so skipped data chunks are
//!   never stamped twice. The exception is the splitter's tail and
//!   the manifest chunks, which are re-dispatched (and so stamped
//!   again) on every resume; see `run_job`'s tail loop. That is a
//!   handful of chunks, and the issuer reuses the slot it already
//!   recorded for an address, so no bucket capacity is lost.
//!
//! - **Pause / cancel.** A driver checks
//!   [`JobHandle::pause_requested`] / [`JobHandle::cancel_requested`]
//!   between every chunk dispatch and every chunk completion. On
//!   pause it drains in-flight pushes, checkpoints state, and parks
//!   on a [`Notify`]. Cancel returns immediately and lets the
//!   future call drop in-flight work.
//!
//! - **Persistence.** [`UploadJobInfo`] is rewritten atomically
//!   (tmp → fsync → rename) every `CHECKPOINT_INTERVAL_CHUNKS`
//!   pushes plus on every state transition. A daemon crash mid-push
//!   loses at most this many chunks of progress (we just re-push
//!   them on the next start; pushsync is idempotent at the
//!   network level, so duplicate pushes for already-replicated
//!   chunks are a wasted RTT but not a correctness bug).
//!
//! - **Concurrency.** Bounded at [`MAX_PUSH_CONCURRENCY`] in-flight
//!   pushes per job (matches the gateway's parallel push width).
//!   Multiple jobs share the daemon's process-wide retrieval /
//!   pushsync semaphores, so two simultaneous uploads don't double
//!   the load on neighbours.
//!
//! - **Retries never hold a slot.** A transiently-failed chunk parks
//!   in a [`RetryQueue`] for its (jittered) back-off and is
//!   re-dispatched when due, so every in-flight slot is always doing
//!   network work (bee's pusher shape). Once the splitter is drained
//!   and only a few stragglers remain, re-dispatches are hedged
//!   across [`TAIL_HEDGE_WIDTH`] concurrent pushsync commands and the
//!   first receipt wins — pushsync is idempotent, so the losers cost
//!   wasted RTTs, not correctness.

pub mod state;

use ant_control::{ControlAck, ControlCommand, StatusSnapshot, UploadJobView};
use ant_retrieval::{
    build_single_file_manifest, ManifestWriteError, SplitChunk, StreamingSplitter,
};
// `ManifestWriteError` is re-exported from `ant-retrieval`'s root.
use futures::stream::{FuturesUnordered, StreamExt};
use memmap2::Mmap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tracing::{debug, info, warn};

pub use state::{UploadJobInfo, UploadStatus};

/// Bee's leaf chunk size — kept here as a private constant so the
/// driver doesn't have to depend on `ant-crypto` for one number.
/// Re-exported from `ant_retrieval` if outside callers need it.
const CHUNK_SIZE: usize = 4096;

/// Maximum simultaneous in-flight `PushChunk` futures per job.
///
/// # Sizing experiments (Phase 7e, 2026-05-08)
///
/// We tried raising this to 256 to multiply throughput. The 256 MiB
/// smoke test **failed at 27 %** with `push timed out after 60s`
/// across the peer set: bee's per-peer stream-acceptance rate is
/// strict, and 256 concurrent open-stream attempts trigger
/// `units_accepted = 0` from the pseudosettle path (bee deciding our
/// debt picture is inconsistent with what it expects) and yamux
/// disconnects in droves. 32 reproducibly completes the same upload.
///
/// The real bottleneck is bee-side accounting: at ~100 active peers
/// the network-wide credit budget is roughly
/// `100 peers × lightRefreshRate (5 K PLUR/s) + cheques`, which caps
/// chunk acceptance at ~30-50 chunks/s regardless of how many
/// streams we open. Pushing harder just causes bee to RST our
/// streams. So we keep 32 — it saturates the network path without
/// upsetting bee. Future throughput gains should come from paying
/// for the bandwidth (SWAP cheques from a funded chequebook), not
/// from raising this constant or from widening the peer set to
/// collect more unpaid per-peer allowance.
const MAX_PUSH_CONCURRENCY: usize = 32;

/// Effective in-flight push width: [`MAX_PUSH_CONCURRENCY`] unless the
/// perf-lab override `ANT_PUSH_CONCURRENCY` is set (Experiment 2 pairs
/// a higher total width with the per-peer in-flight cap in
/// `ant-retrieval::push_load` — the 2026-05 finding that 256 collapses
/// was measured WITHOUT a per-peer cap, so the pair must be re-tested
/// together; see PERF-LAB.md). Read once per process.
fn max_push_concurrency() -> usize {
    /// Perf-lab exp 8 verdict (2026-07-06): with the per-peer
    /// in-flight cap spreading load, width 128 measured 3.6× width 32
    /// at 256 MiB (565/558 vs 157/154 KiB/s, interleaved pairs) with
    /// 4× fewer failed attempts — the run finishes before per-peer
    /// debt scars accumulate. The 2026-05 "256 collapses" finding
    /// predates the cap; the historical 32 remains as
    /// [`MAX_PUSH_CONCURRENCY`] for the bounded heal path.
    const DEFAULT_PUSH_WIDTH: usize = 128;
    static WIDTH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *WIDTH.get_or_init(|| {
        std::env::var("ANT_PUSH_CONCURRENCY")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_PUSH_WIDTH)
    })
}

/// Re-checkpoint the on-disk job manifest every N successful pushes.
/// Chosen so a crash loses ≤ ~250 chunks (~1 MB at 4 KiB chunks)
/// without thrashing the disk: at peak push throughput (~5 K
/// chunks/s on a fast LAN) this is one fsync per 50 ms.
const CHECKPOINT_INTERVAL_CHUNKS: u64 = 256;

/// Cap on outstanding `PushChunk` ack timeout. Raised from 60 s to
/// 120 s once the bee 2.7→2.8 cutover surfaced reproducible
/// receipt-batching tails of ~25-35 s per chunk on slow storers:
/// the inner `push_stamped_chunk` runs one 45 s pushsync envelope
/// per candidate peer (see `ant_retrieval::pushsync::PUSHSYNC_TIMEOUT`)
/// and on the cutover network it routinely needs two consecutive
/// candidates before a storer issues the final receipt. 60 s here
/// cut the first attempt short on the slow path; 120 s gives the
/// inner peer-walk room to settle one re-route inside the outer
/// retry budget, instead of bouncing into `PER_CHUNK_RETRY_BUDGET`
/// re-dispatches that all queue against the same hot storer set.
const PUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

/// Per-chunk retry budget for the **bounded** push paths (the
/// post-upload heal re-push and the manual "Push again"). The *upload*
/// path itself is unbounded — it re-queues a struggling chunk forever,
/// bee-style, and never fails the job on transient peer churn (see
/// [`RetryQueue`] and `run_job`). Heal keeps a bounded budget so a
/// background heal task can't wedge forever on a dead network: it gives
/// up the current round (the user can tap "Push again" to retry).
///
/// Pushsync against a freshly-handshaked peer set occasionally fires a
/// transient "no peers available" or "stamp signature rejected"
/// error; a small fixed retry hides those from the operator without
/// wallpapering over a real protocol failure.
///
/// Bumped from 5 to 8 in lockstep with the inter-attempt back-off
/// extension below: under the bee 2.7→2.8 cutover load the slow-
/// storer tail is bursty (clusters around the chunks that hash into
/// the same neighbourhood), and a 5-retry budget with the previous
/// 100 ms × 2^n back-off saturated in about 3.1 s — short enough
/// that all 5 retries hit the same momentarily-overloaded storer
/// set. 8 retries with the new back-off (see [`backoff_for_retry`])
/// stretches that to ~38 s, which is the empirical settle-time of
/// the cutover receipt-batching tail in our B5 traces.
const PER_CHUNK_RETRY_BUDGET: u32 = 8;

/// Back-off between consecutive same-chunk retries.
///
/// Old curve was `100 ms × 2^attempt` capped at 4 s. Combined with
/// the old 5-retry budget that gave ~3.1 s total back-off — short
/// enough that retries 2-5 routinely landed inside the bee 2.8.0
/// receipt-batching window for a slow storer, so they all queued
/// against the same wedged path.
///
/// The new curve is `250 ms × 2^attempt` capped at 4 s, steps as
/// 0.25 / 0.5 / 1 / 2 / 4 / 4 / 4 / 4 s for the 8-attempt budget
/// (≈ 19.75 s total back-off). The bulk of the extension comes
/// from the larger budget (8 retries instead of 5) combined with
/// the cross-chunk [`ant_retrieval::PushSkipCache`] — the cache
/// rotates the inner peer pick to a different storer between
/// retries, so we don't burn additional back-off just because the
/// network has one slow storer; we surf past it on the next
/// attempt's pick. Keeping the per-attempt back-off cap at 4 s
/// (rather than the multi-second values an earlier iteration of
/// this fix tried) avoids stretching the happy-path P95 by tens
/// of seconds on busy uploads.
fn backoff_for_retry(attempt: u32) -> std::time::Duration {
    // Perf-lab Experiment 9 (straggler patience): a chunk that has
    // already burned many walks is almost always blocked by
    // bee-side blocklists on its few closest storers — and every
    // further hammering round EXTENDS those blocklists (bee
    // escalates repeat offenders). Backing far off after the early
    // attempts lets the windows lapse instead of refreshing them.
    // Escalation only kicks in past the classic 8-attempt curve, so
    // the happy-path P95 is untouched.
    if straggler_patience() {
        let secs = match attempt {
            0..=7 => return classic_backoff(attempt),
            8..=11 => 15,
            _ => 30,
        };
        return std::time::Duration::from_secs(secs);
    }
    classic_backoff(attempt)
}

fn classic_backoff(attempt: u32) -> std::time::Duration {
    let ms = 250u64.saturating_mul(1u64 << attempt.min(20)).min(4_000);
    std::time::Duration::from_millis(ms)
}

/// Perf-lab Experiment 9: DEFAULT ON since the verdict (2026-07-06 —
/// completed a 512 MiB upload in 17 min in the window where the
/// control arm ground indefinitely; +26 % in a healthy window).
/// `ANT_PUSH_STRAGGLER_PATIENCE=0` opts out (the A/B control arm).
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

/// Longer pause inserted between re-pushes when the failure looks like
/// "no peer found for this chunk's neighbourhood" rather than a busy
/// storer. Mirrors bee's `time.After(5 * time.Second)` on
/// `topology.ErrNotFound` in `pushDeferred`: hammering instantly when
/// the candidate set is empty just feeds the churn (a reset storm
/// drops ~all candidates at once), so we back off and let topology
/// re-converge before the next attempt.
const NO_PEER_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the upload driver wakes (when otherwise blocked draining
/// in-flight pushes) to fold the live re-queue counter into the job
/// snapshot and re-evaluate the `stalled` liveness flag.
const STALL_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// No chunk has acked for this long ⇒ surface `stalled = true` to
/// watchers. The job is *not* failed — the daemon keeps retrying
/// forever — but a blocking caller (`antctl upload` without
/// `--detach`, the iOS follow stream) learns the upload isn't
/// progressing instead of hanging silently against a dead network.
const STALL_THRESHOLD: std::time::Duration = std::time::Duration::from_mins(3);

/// Post-upload self-heal: after every chunk has been pushed, read the
/// whole file back from the network and re-push any chunk that didn't
/// land, repeating up to this many rounds. Sized small — pushsync's own
/// retry budget already absorbs transient per-chunk failures, so heal
/// only has to mop up the rare chunk that a storer dropped after acking;
/// 3 read-back/re-push rounds is plenty in practice.
const MAX_HEAL_ROUNDS: usize = 3;

/// Wait this long before each heal read-back so freshly-pushed chunks
/// have a moment to replicate across the neighbourhood. Without it the
/// first read-back races propagation and re-pushes chunks that were
/// about to be reachable anyway (harmless — pushsync is idempotent —
/// but wasteful).
const HEAL_SETTLE_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

/// Address-set batch size per [`ControlCommand::VerifyChunksPresent`]
/// so each ack's JSON stays bounded on a large file.
const HEAL_VERIFY_BATCH: usize = 512;

/// Ceiling on one read-back batch's ack. The verify probes up to
/// [`HEAL_VERIFY_BATCH`] chunks against the live network, so minutes are
/// legitimate — but an *unbounded* await meant a wedged node loop hung
/// the securing pass forever, leaking its in-flight marker and silently
/// killing every future automatic retry for that job. On expiry the
/// read-back is inconclusive; the pass gives up its round and the retry
/// schedule stays alive.
const HEAL_VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(10);

/// Minimum spacing between *automatic* re-heals of a **degraded** job —
/// one whose securing pass ran to the end but couldn't confirm every
/// chunk deep-reachable. Historically such jobs were only repaired by a
/// manual "Push again"; now every launch and every wake re-queues them
/// (a file must not silently stay uploader-only), but with this long
/// backoff so an app that flips foreground/background every few seconds
/// doesn't burn a read-back + re-push pass each time. In-memory only: a
/// fresh process always retries once immediately, which is exactly the
/// "on every launch" cadence we want. Tunable.
const DEGRADED_HEAL_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_mins(15);

/// Escalating wait before the next automatic securing retry, keyed by
/// how many completed-but-unverified passes the job has had. A fresh
/// upload usually finishes settling within minutes (neighbourhood
/// pull-sync moves the last shallow chunks on its own), so the first
/// re-checks come quickly and the badge flips green without the user
/// tapping anything; a long-degraded file backs off to the
/// [`DEGRADED_HEAL_RETRY_INTERVAL`] cap so it can't burn postage and
/// battery on a file the network refuses to settle. Keyed off the
/// *persisted* `heal_attempts`, so the schedule continues across
/// relaunches instead of restarting.
fn degraded_retry_interval(attempts: u64) -> std::time::Duration {
    match attempts {
        0 | 1 => std::time::Duration::from_mins(1),
        2 => std::time::Duration::from_mins(2),
        3 => std::time::Duration::from_mins(5),
        4 => std::time::Duration::from_mins(10),
        _ => DEGRADED_HEAL_RETRY_INTERVAL,
    }
}

/// How often the manager's retry ticker re-evaluates the heal queue
/// (cheap: a snapshot walk gated by the backoff map and the in-flight
/// set). The ticker is what turns [`DEGRADED_HEAL_RETRY_INTERVAL`] from
/// a *minimum spacing* (retries only ever fired at launch/wake) into an
/// actual schedule — required for the user-visible "next check in
/// ~M min" countdown (`heal_retry_unix`) to be honest, and it lets a
/// long-running daemon re-check degraded uploads without waiting for a
/// restart.
const DEGRADED_RETRY_TICK: std::time::Duration = std::time::Duration::from_mins(1);

/// How long [`UploadManager::suspend_all`] waits for paused drivers to
/// drain their in-flight pushes and write the final checkpoint before
/// returning anyway. Sized to fit inside iOS's background grace window
/// (the host wraps the call in a `beginBackgroundTask`, which gives
/// roughly tens of seconds; we use a conservative slice of it). A
/// driver that misses the window loses at most one checkpoint interval
/// of progress — resume re-pushes those chunks; pushsync is idempotent.
const SUSPEND_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Number of closest peers heal probes per chunk. Non-zero, so the
/// read-back is the *deep* neighbourhood check (see
/// [`ControlCommand::VerifyChunksPresent`]): each chunk's own closest
/// peers are probed first, and probe misses are confirmed via the
/// routed download path before counting as missing. That's what lets
/// heal detect and re-push shallow placements — including in files
/// uploaded before the deep-push fix — without re-pushing hundreds of
/// perfectly healthy chunks on probe noise.
const HEAL_PROBES: usize = 4;

/// Minimum connected BZZ peers before the **automatic** post-upload heal is
/// allowed to also re-push *shallow* placements (Sketch B: readiness-gated
/// auto shallow heal). Below this the node's per-chunk closest-peer probes
/// can't reliably tell a shallow chunk from a healthy one — the routing
/// table is too thin for the probe to reach the chunk's true neighbourhood,
/// so an automatic shallow re-push would churn postage on probe noise (the
/// exact reason the post-upload heal historically passed `include_shallow =
/// false`). At or above this we trust the probe enough to promote shallow
/// chunks unattended; a constrained node falls back to the conservative
/// reachable-only heal and defers shallow repair to the user's manual "Push
/// again". Set to ~3× [`HEAL_PROBES`] so the closest-peer set each probe
/// walks is genuinely populated, not barely. Tunable.
const MIN_PEERS_FOR_AUTO_SHALLOW_HEAL: u32 = 12;

/// Cap on concurrent **automatic** "Securing…" passes. Every completed
/// upload — and every completed-but-unsecured job re-loaded at startup —
/// wants a heal, but they all share the node's single command channel and
/// network: run them all at once and each chunk read-back / re-push crawls,
/// so no file's progress visibly moves (the "many files stuck Securing…"
/// symptom). A small fair semaphore turns the heals into a queue — a few
/// run at full speed while the rest park in FIFO order (surfaced to the UI
/// as "queued") and start the instant a slot frees. Manual "Push again"
/// bypasses this cap (it's user-initiated, one at a time, and awaited).
/// Tunable.
const MAX_CONCURRENT_HEALS: usize = 3;

/// Optional sink for streamed re-push/heal progress (the app's "push
/// again"). Each item is a JSON line `{"phase":"checking"|"repushing",
/// "checked"?:n,"total"?:n}`. `None` runs the heal silently (the
/// post-upload heal, antctl resume).
type HealProgress = Option<mpsc::UnboundedSender<String>>;

/// One queued automatic heal pass. Carries everything
/// [`UploadManager::verify_and_heal`] needs so the work can be deferred
/// behind the [`MAX_CONCURRENT_HEALS`] semaphore without re-reading job
/// state. `addrs` is `Some` when the caller already holds the chunk
/// address list in memory (the post-upload path — robust even if the
/// source file is deleted right after upload); `None` means derive it
/// from the source file when the pass actually runs (startup re-heal,
/// `resume` of a completed job).
struct HealRequest {
    job_id: String,
    mode: HealMode,
    addrs: Option<Vec<[u8; 32]>>,
    batch_id: [u8; 32],
    source_path: PathBuf,
    source_size: u64,
    raw: bool,
    name: Option<String>,
    content_type: Option<String>,
}

/// What a [`verify_and_heal`](UploadManager::verify_and_heal) pass is allowed
/// to re-push, and how many rounds it spends doing it. Decouples "how
/// thorough is the reachable mop-up" from "do we also promote shallow
/// placements", so a well-connected node can have both (the old single
/// `include_shallow` bool forced a choice — shallow meant exactly one round,
/// losing the multi-round straggler mop-up).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HealMode {
    /// Constrained-node automatic heal: up to [`MAX_HEAL_ROUNDS`] rounds
    /// re-pushing only genuinely-unreachable chunks. Never touches
    /// merely-shallow placements — the node's probe can't reliably judge
    /// them, so re-pushing would churn postage on noise.
    ReachableOnly,
    /// Well-connected automatic heal: the full [`MAX_HEAL_ROUNDS`]
    /// reachable-only mop-up *and then* one shallow-promotion round, so it
    /// repairs both transient stragglers and shallow placements.
    ReachableThenShallow,
    /// Manual "Push again": a single deterministic shallow-aware round.
    /// Re-measuring the shallow set mid-pass inflates it (the budget we just
    /// spent saturates peers, and a saturated peer can't confirm a chunk), so
    /// capture once, re-push, and let the final read-back decide.
    ShallowOnce,
}

impl HealMode {
    /// Rounds of reachable-only mop-up before the shallow pass / verdict.
    fn mopup_rounds(self) -> usize {
        match self {
            HealMode::ShallowOnce => 0,
            HealMode::ReachableOnly | HealMode::ReachableThenShallow => MAX_HEAL_ROUNDS,
        }
    }
    /// Whether to run a shallow-aware promotion round (and decide the verdict
    /// against the shallow set) after the mop-up.
    fn promotes_shallow(self) -> bool {
        matches!(self, HealMode::ReachableThenShallow | HealMode::ShallowOnce)
    }
    /// Human-readable trigger label for logs.
    fn label(self) -> &'static str {
        match self {
            HealMode::ReachableOnly => "auto heal (reachable-only)",
            HealMode::ReachableThenShallow => "auto heal (reachable + shallow)",
            HealMode::ShallowOnce => "manual push-again",
        }
    }
}

/// Emit one heal progress line, best-effort (a dropped receiver is a no-op
/// and never stalls the heal).
fn emit_heal(progress: &HealProgress, phase: &str, checked: Option<usize>, total: Option<usize>) {
    let Some(tx) = progress else { return };
    let mut v = serde_json::json!({ "phase": phase });
    if let Some(c) = checked {
        v["checked"] = c.into();
    }
    if let Some(t) = total {
        v["total"] = t.into();
    }
    let _ = tx.send(v.to_string());
}

/// Skip the heal pass for files above this chunk count. Raised from
/// 50 000 (~200 MB) to 2 000 000 (~8 GB) now that heal re-pushes from
/// the local chunk store (see [`UploadManager::repush_missing`])
/// instead of re-reading + re-splitting the source file: the missing
/// set is verified and re-pushed in bounded batches
/// ([`HEAL_VERIFY_BATCH`] / [`MAX_PUSH_CONCURRENCY`]), so memory stays
/// flat regardless of file size. The cap only bounds the address Vec
/// the read-back walks (32 B/chunk ⇒ ~64 MB at the ceiling) and the
/// total read-back cost; large multi-GB uploads now get a durability
/// pass too, which they previously skipped entirely. Tunable.
const HEAL_MAX_CHUNKS: usize = 2_000_000;

/// When the splitter is drained and at most this many chunks are
/// still unacked, the driver switches to **tail hedging** (Fix 2 of
/// the big-uploads plan): each *re-dispatched* straggler is raced as
/// [`TAIL_HEDGE_WIDTH`] concurrent pushsync commands instead of one.
/// pushsync is idempotent at the network level, so the duplicate
/// pushes cost a few wasted round-trips at worst — and convert the
/// "one straggler walks peers serially with back-off" tail (observed
/// at ~1 chunk/min on the 1 GiB stress run) into a parallel race
/// where the first receipt wins.
const TAIL_HEDGE_THRESHOLD: usize = 16;

/// How many concurrent pushsync commands a hedged tail re-dispatch
/// fans out to. Each command independently walks the closest-peer
/// list (with its own per-chunk skip list), so 3 commands race ~3
/// different storer paths.
const TAIL_HEDGE_WIDTH: usize = 3;

/// Stagger between the hedged attempts of one chunk, so a fast first
/// receipt cancels the rest before they hit the wire.
const TAIL_HEDGE_STAGGER: std::time::Duration = std::time::Duration::from_millis(500);

/// Add ±25 % decorrelation jitter to a retry back-off (part of Fix 4
/// of the big-uploads plan): a connection reset that drops a whole
/// neighbourhood's streams at once would otherwise re-queue dozens of
/// chunks with byte-identical wake times, and the synchronized retry
/// burst re-trips the same storers. Cheap xorshift over an atomic —
/// no `rand` dependency, statistical quality is irrelevant here.
fn with_jitter(d: std::time::Duration) -> std::time::Duration {
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let mut x = STATE
        .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
        .wrapping_add(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |t| u64::from(t.subsec_nanos())),
        );
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let per_mille = 750 + (x % 501) as u32; // 0.75x ..= 1.25x
    d * per_mille / 1000
}

/// Future returned by [`UploadManager::dispatch_push_once`]: a
/// chunk-emit index (so the ack log can advance the in-order cursor)
/// plus the outcome of one (possibly hedged) pushsync round-trip.
type PushFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = (u64, PushOnceOutcome)> + Send>>;

/// Future returned by [`UploadManager::dispatch_push_bounded`] (the
/// heal re-push path, which keeps its internal bounded retry loop).
type BoundedPushFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = (u64, Result<(), UploadError>)> + Send>>;

/// Outcome of a single dispatched push (no internal retry loop — the
/// upload driver owns retries via [`RetryQueue`], Fix 1 of the
/// big-uploads plan).
enum PushOnceOutcome {
    /// A storer issued a receipt.
    Acked,
    /// Transient failure (busy peers, timeouts, connection resets,
    /// "no peers"). The chunk is handed back to the driver so it can
    /// be re-queued *without* holding an in-flight slot during the
    /// back-off.
    Transient {
        chunk: SplitChunk,
        /// Attempt counter as of the failed dispatch; the driver
        /// re-queues with `attempt + 1`.
        attempt: u32,
        no_peer: bool,
        message: String,
    },
    /// Genuinely unrecoverable (daemon gone / bad batch / bad wire).
    Fatal(UploadError),
}

/// Result of one raw `PushChunk` round-trip (shared by the upload
/// and heal dispatch paths).
enum AttemptResult {
    Acked,
    Transient { no_peer: bool, message: String },
    Fatal(UploadError),
}

/// Strict receipts for the upload-job path: a chunk only counts as
/// pushed once a storer *inside its own neighbourhood* signs the
/// receipt. A merely-shallow receipt comes back as a transient error,
/// parks in the retry queue, and every re-dispatch re-runs the
/// gossip-deepening dial cycle — so `Completed` means the data is
/// genuinely placed where the network routes to, not merely
/// acked-somewhere. Bee accepts shallow because a full node's
/// pull-sync repairs placement afterwards; a light node has no
/// pull-sync, and a shallow-accepted chunk is readable only through
/// the uploader's own links and ages out of the network (observed: a
/// 4 MB iOS upload 404 network-wide a day later — issue #41
/// follow-up). `ANT_UPLOAD_ACCEPT_SHALLOW=1` opts back into the old
/// bee-aligned accept; the gateway's parity endpoints are unaffected
/// either way. Read once per process.
fn require_deep_receipts() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| match std::env::var("ANT_UPLOAD_ACCEPT_SHALLOW") {
        Err(_) => true,
        Ok(v) => {
            let v = v.trim();
            v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")
        }
    })
}

/// One `PushChunk` command → ack round-trip, classified. No retries.
async fn push_attempt(
    cmd_tx: &mpsc::Sender<ControlCommand>,
    wire: Vec<u8>,
    batch_id: [u8; 32],
) -> AttemptResult {
    let (ack_tx, ack_rx) = oneshot::channel::<ControlAck>();
    if cmd_tx
        .send(ControlCommand::PushChunk {
            wire,
            batch_id,
            stamp: None,
            require_deep: require_deep_receipts(),
            ack_when_stored: false,
            ack: ack_tx,
        })
        .await
        .is_err()
    {
        return AttemptResult::Fatal(UploadError::DaemonGone);
    }
    match tokio::time::timeout(PUSH_TIMEOUT, ack_rx).await {
        Ok(Ok(ControlAck::ChunkUploaded { .. })) => AttemptResult::Acked,
        Ok(Ok(ControlAck::Error { message })) => {
            // A clearly-permanent condition (bad batch / stamp /
            // wire) is fatal even on the upload path — retrying
            // forever would just spin.
            if is_fatal_push_error(&message) {
                return AttemptResult::Fatal(UploadError::PushFailed(message));
            }
            AttemptResult::Transient {
                no_peer: is_no_peer_error(&message),
                message,
            }
        }
        // "Accepted but not ready" (e.g. zero peers yet) is
        // transient — retry, don't fail.
        Ok(Ok(ControlAck::NotReady { message })) => AttemptResult::Transient {
            no_peer: true,
            message,
        },
        Ok(Ok(other)) => AttemptResult::Fatal(UploadError::PushFailed(format!(
            "unexpected ack: {other:?}",
        ))),
        Ok(Err(_)) => AttemptResult::Fatal(UploadError::DaemonGone),
        Err(_) => AttemptResult::Transient {
            no_peer: false,
            message: format!("push timed out after {}s", PUSH_TIMEOUT.as_secs()),
        },
    }
}

/// A chunk parked between push attempts (Fix 1). It holds **no**
/// in-flight slot while its back-off runs; the driver re-dispatches
/// it once `due` elapses and a slot is free.
struct RetryEntry {
    due: tokio::time::Instant,
    index: u64,
    chunk: SplitChunk,
    attempt: u32,
}

impl PartialEq for RetryEntry {
    fn eq(&self, other: &Self) -> bool {
        self.due == other.due && self.index == other.index
    }
}
impl Eq for RetryEntry {}
impl PartialOrd for RetryEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for RetryEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reversed (earliest due first): `BinaryHeap` is a max-heap.
        other
            .due
            .cmp(&self.due)
            .then_with(|| other.index.cmp(&self.index))
    }
}

/// Min-heap of parked chunks keyed by wake time. This is the delay
/// queue at the heart of the Fix-1 scheduler: a transiently-failed
/// chunk goes here instead of sleeping inside its own future, so all
/// [`MAX_PUSH_CONCURRENCY`] slots keep doing network work while the
/// back-off runs.
#[derive(Default)]
struct RetryQueue {
    heap: std::collections::BinaryHeap<RetryEntry>,
}

impl RetryQueue {
    fn push(&mut self, e: RetryEntry) {
        self.heap.push(e);
    }
    /// Pop the earliest entry whose wake time has elapsed, if any.
    fn pop_due(&mut self, now: tokio::time::Instant) -> Option<RetryEntry> {
        if self.heap.peek().is_some_and(|e| e.due <= now) {
            self.heap.pop()
        } else {
            None
        }
    }
    fn next_due(&self) -> Option<tokio::time::Instant> {
        self.heap.peek().map(|e| e.due)
    }
    fn len(&self) -> usize {
        self.heap.len()
    }
    fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

/// Fan-out width for one dispatch: hedge a *re-dispatched* straggler
/// across several peers when the splitter is drained and only a
/// handful of chunks remain (Fix 2); everything else is a single
/// command. First attempts are never hedged — they nearly always
/// succeed, and hedging them would triple the postage/stream cost of
/// the happy path.
const fn hedge_width(splitter_done: bool, remaining: usize) -> usize {
    if splitter_done && remaining <= TAIL_HEDGE_THRESHOLD {
        TAIL_HEDGE_WIDTH
    } else {
        1
    }
}

/// Driver-side liveness state: stall detection plus the periodic
/// heartbeat tick that keeps `follow` streams alive (Fix 7 — both the
/// daemon's streaming dispatch and the client socket treat a long
/// gap between frames as a dead stream).
struct Liveness {
    last_progress: Instant,
    stalled: bool,
    tick: tokio::time::Interval,
}

impl Liveness {
    fn new() -> Self {
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + STALL_CHECK_INTERVAL,
            STALL_CHECK_INTERVAL,
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            last_progress: Instant::now(),
            stalled: false,
            tick,
        }
    }
}

/// Classify a `PushChunk` error message as genuinely unrecoverable
/// (so the upload path fails fast instead of retrying forever).
///
/// These are misconfiguration / capacity dead-ends, not peer churn:
/// an unregistered or saturated immutable batch, a stamp-issuer
/// failure, or a malformed chunk. Everything else (no peers,
/// timeouts, connection resets, shallow placement, generic
/// `pushsync:` transport errors) is treated as transient and
/// re-pushed.
fn is_fatal_push_error(message: &str) -> bool {
    const FATAL_MARKERS: &[&str] = &[
        "not usable",         // batch id not registered
        "not found on-chain", // peers reject the stamp: phantom batch (deterministic)
        "saturated",          // immutable batch collision bucket full
        "stamp issue failed", // postage signing dead-end
        "wire size out of range",
        "failed to BMT-hash",
        "uploads not configured",
    ];
    let m = message.to_ascii_lowercase();
    FATAL_MARKERS.iter().any(|marker| m.contains(marker))
}

/// Whether a transient error looks like "no peer found for this
/// chunk's neighbourhood" (vs a busy/slow storer). Such failures get
/// the longer [`NO_PEER_BACKOFF`] pause, matching bee's `pushDeferred`
/// 5 s wait on `topology.ErrNotFound`.
fn is_no_peer_error(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("no peers")
        || m.contains("no peer")
        || m.contains("not found")
        || m.contains("exhausted")
        || m.contains("no closest")
}

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest: {0}")]
    Manifest(#[from] ManifestWriteError),
    #[error(
        "source file changed since job was created (size {expected_size}, found {actual_size})"
    )]
    SourceChanged {
        expected_size: u64,
        actual_size: u64,
    },
    #[error("source file modified since job was created (mtime {expected_mtime_ms}, found {actual_mtime_ms})")]
    SourceMtimeChanged {
        expected_mtime_ms: u64,
        actual_mtime_ms: u64,
    },
    #[error("daemon node loop is no longer accepting commands")]
    DaemonGone,
    #[error("push chunk failed: {0}")]
    PushFailed(String),
    #[error("upload not found: {0}")]
    NotFound(String),
    #[error("upload in unexpected state: {0:?}")]
    BadState(UploadStatus),
}

/// Owned, daemon-resident job state plus its driver controls.
struct JobHandle {
    info: Mutex<UploadJobInfo>,
    /// Last persisted snapshot of `info`, broadcast to every
    /// `follow`er.
    progress: watch::Sender<UploadJobInfo>,
    /// Set by `pause`; the driver checks it between chunks. Never
    /// reset — instead, `resume` spawns a fresh driver task.
    pause_requested: AtomicBool,
    /// Set by `cancel`; same observation cadence as `pause`. Once
    /// set, the driver aborts at the next opportunity.
    cancel_requested: AtomicBool,
    /// Wakes a paused driver when `resume` is called. Only the
    /// resume path uses it; the driver itself calls `notified()`
    /// inside its run loop after observing `pause_requested`.
    notify: Notify,
    /// The live driver task, kept so [`UploadManager::suspend_all`] can
    /// await (bounded) the drain-and-checkpoint that `pause` triggers —
    /// the driver's final act before exiting is a state save, so a
    /// completed join means the resume cursor is durably on disk.
    /// Replaced by every `spawn_driver`; `None` when no driver runs.
    driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl JobHandle {
    fn snapshot(&self) -> UploadJobInfo {
        self.info.lock().expect("upload mutex poisoned").clone()
    }
}

/// Public, cheaply-cloneable handle to the daemon-side upload
/// system. Owned by the swarm event loop; dispatched into from each
/// `ControlCommand::Upload*` variant.
#[derive(Clone)]
pub struct UploadManager {
    inner: Arc<UploadManagerInner>,
}

struct UploadManagerInner {
    state_dir: PathBuf,
    cmd_tx: mpsc::Sender<ControlCommand>,
    jobs: Mutex<HashMap<String, Arc<JobHandle>>>,
    id_counter: AtomicU64,
    /// Batch id used when a job doesn't carry its own (`antctl upload`
    /// without `--batch-id`). Set from the operator's startup
    /// `--postage-batch`. `None` → jobs must name a batch or the push
    /// is rejected by the node loop with "batch … not usable".
    default_batch_id: Option<[u8; 32]>,
    /// The daemon's persistent chunk store. The `PushChunk` handler
    /// writes every stamped chunk's wire bytes here (keyed by address)
    /// *before* pushsync, so heal can re-push a missing chunk by
    /// reading its payload straight from disk — no dependency on the
    /// source file (which an app may have deleted) and surviving a
    /// node restart. `None` in tests / `--no-disk-cache`, where heal
    /// falls back to re-deriving chunks from the source file.
    disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    /// Live daemon status (the same `watch` the gateway's `/readiness`
    /// reads). Lets the automatic post-upload heal gate its shallow re-push
    /// on routing-table health (see [`MIN_PEERS_FOR_AUTO_SHALLOW_HEAL`] and
    /// [`UploadManager::neighbourhood_ready`]). `None` in tests / older
    /// embedders → the heal stays conservative (reachable-only).
    status: Option<watch::Receiver<StatusSnapshot>>,
    /// Bounds concurrent automatic heals to [`MAX_CONCURRENT_HEALS`]; the
    /// rest of the enqueued passes park here (fair FIFO) and form the heal
    /// queue, so a backlog of just-completed / rehydrated uploads secures a
    /// few at a time instead of thundering the network and stalling.
    heal_slots: Arc<tokio::sync::Semaphore>,
    /// Job ids with an automatic heal queued or running, so a second
    /// trigger for the same job (a fresh upload completing, a startup
    /// re-heal, a `resume`) doesn't enqueue a duplicate pass.
    heal_inflight: Mutex<HashSet<String>>,
    /// Root under which app-managed sources live (the iOS
    /// `Application Support/antdrive/imports` dir). Jobs whose source
    /// is under it persist a relative path too, so a container move
    /// (iOS reassigning the app-container UUID) can be healed by
    /// re-anchoring `source_root/source_rel` — see
    /// [`UploadManager::resolve_job_source`]. `None` (the `antd`
    /// daemon) leaves absolute-path behaviour untouched.
    source_root: Option<PathBuf>,
    /// Flipped by [`UploadManager::suspend_all`] /
    /// [`UploadManager::wake_all`]. While set, running securing passes
    /// bail at their next check *without* marking the heal finished,
    /// so wake re-queues them; queued passes park until wake.
    suspended: AtomicBool,
    /// Earliest next automatic re-heal per *degraded* job (see
    /// [`DEGRADED_HEAL_RETRY_INTERVAL`]). Also stamped by a user's
    /// "Stop securing" so the very next wake doesn't immediately undo
    /// the stop. In-memory: resets on relaunch by design.
    degraded_retry_after: Mutex<HashMap<String, Instant>>,
    /// One retry ticker per manager process (see
    /// [`DEGRADED_RETRY_TICK`]); spawned by the first
    /// `rehydrate_from_disk`.
    retry_ticker_started: AtomicBool,
}

impl UploadManager {
    /// Build a new manager rooted at `state_dir` (typically
    /// `<data-dir>/uploads`). Creates the directory if it doesn't
    /// exist. `cmd_tx` is the same control-command channel the
    /// HTTP gateway and `antctl` socket use; the manager dispatches
    /// `PushChunk` commands through it so the existing postage
    /// stamping + pushsync pipeline is reused unchanged.
    pub fn new(
        state_dir: PathBuf,
        cmd_tx: mpsc::Sender<ControlCommand>,
        default_batch_id: Option<[u8; 32]>,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&state_dir)?;
        Ok(Self {
            inner: Arc::new(UploadManagerInner {
                state_dir,
                cmd_tx,
                jobs: Mutex::new(HashMap::new()),
                id_counter: AtomicU64::new(0),
                default_batch_id,
                disk_cache: None,
                status: None,
                heal_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HEALS)),
                heal_inflight: Mutex::new(HashSet::new()),
                source_root: None,
                suspended: AtomicBool::new(false),
                degraded_retry_after: Mutex::new(HashMap::new()),
                retry_ticker_started: AtomicBool::new(false),
            }),
        })
    }

    /// Set the root under which app-managed sources live, enabling the
    /// container-move rebase (`source_rel` recording at `start`,
    /// re-anchoring on rehydrate/heal). Must be configured *before*
    /// `rehydrate_from_disk` so rehydrated jobs rebase immediately.
    /// Same lifecycle / `Arc::get_mut` rationale as [`with_disk_cache`]:
    /// called once, before the manager is cloned into the node loop.
    #[must_use]
    pub fn with_source_root(mut self, source_root: Option<PathBuf>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.source_root = source_root;
        }
        self
    }

    /// Attach the daemon's persistent chunk store so heal can re-push
    /// missing chunks from local disk instead of re-reading the source
    /// file. The `PushChunk` handler already populates this store on
    /// every push, so a freshly-uploaded job's chunks are present even
    /// after the source file is deleted, and persist across restarts.
    #[must_use]
    pub fn with_disk_cache(
        mut self,
        disk_cache: Option<Arc<ant_retrieval::DiskChunkCache>>,
    ) -> Self {
        // `Arc::get_mut` succeeds here because the manager is
        // configured before it's cloned into the node loop / driver
        // tasks (same lifecycle as the gateway's builder methods).
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.disk_cache = disk_cache;
        }
        self
    }

    /// Attach the daemon's live status `watch` so the automatic post-upload
    /// heal can gate its shallow re-push on routing-table health (Sketch B).
    /// Same lifecycle / `Arc::get_mut` rationale as [`with_disk_cache`]:
    /// called once, before the manager is cloned into the node loop. `None`
    /// (tests / embedders without a status sink) keeps the heal conservative.
    #[must_use]
    pub fn with_status_watch(mut self, status: Option<watch::Receiver<StatusSnapshot>>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.status = status;
        }
        self
    }

    /// Whether the node is well-connected enough that the per-chunk
    /// closest-peer probe heal uses can be trusted to distinguish a shallow
    /// placement from a healthy one — the gate for letting the automatic
    /// post-upload heal also re-push shallow chunks (Sketch B). A handshake
    /// must have completed and at least [`MIN_PEERS_FOR_AUTO_SHALLOW_HEAL`]
    /// BZZ peers be connected. With no status wired (tests) this is `false`,
    /// so the heal stays reachable-only exactly as before.
    fn neighbourhood_ready(&self) -> bool {
        let Some(rx) = self.inner.status.as_ref() else {
            return false;
        };
        let snap = rx.borrow();
        snap.peers.last_handshake.is_some()
            && snap.peers.connected >= MIN_PEERS_FOR_AUTO_SHALLOW_HEAL
    }

    /// State-dir path so the daemon can log it / surface it in
    /// `antctl status`.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.inner.state_dir
    }

    /// Create a new job for `source_path` with optional manifest
    /// metadata. Writes the persistent manifest, registers the job,
    /// spawns the driver, and returns the assigned job id. Does
    /// *not* wait for the first chunk to push.
    ///
    /// `raw = true` skips the trailing single-file mantaray
    /// manifest. The completed job's `reference` is the data root
    /// chunk address (a `/bytes/<ref>` reference) instead of the
    /// manifest root. Saves 1-2 chunks of postage and a final
    /// round-trip but loses the embedded filename + content-type;
    /// consumers must know the type out-of-band. `raw = false`
    /// keeps the historical bzz-compatible behaviour.
    pub fn start(
        &self,
        source_path: PathBuf,
        batch_id: Option<String>,
        name: Option<String>,
        content_type: Option<String>,
        raw: bool,
    ) -> Result<String, UploadError> {
        let metadata = std::fs::metadata(&source_path)?;
        if !metadata.is_file() {
            return Err(UploadError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("not a regular file: {}", source_path.display()),
            )));
        }
        let source_size = metadata.len();
        let source_mtime_unix_ms = mtime_unix_ms(&metadata);

        let job_id = self.mint_id();
        let now_s = unix_seconds();
        // Record the root-relative path alongside the absolute one when
        // the source lives under the configured root, so the job can be
        // re-anchored after a container move (see `resolve_job_source`).
        let source_rel = self
            .inner
            .source_root
            .as_deref()
            .and_then(|root| source_path.strip_prefix(root).ok())
            .map(Path::to_path_buf);
        let info = UploadJobInfo {
            job_id: job_id.clone(),
            source_path: source_path.clone(),
            source_rel,
            source_size,
            source_mtime_unix_ms,
            batch_id,
            name: name.or_else(|| {
                source_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(str::to_string)
            }),
            content_type,
            raw,
            status: UploadStatus::Pending,
            bytes_pushed: 0,
            chunks_pushed: 0,
            chunks_total: Some(estimate_chunk_count(source_size, raw)),
            created_at_unix: now_s,
            last_update_unix: now_s,
            last_error: None,
            reference: None,
            heal_verified: false,
            heal_finished: false,
            heal_missing: None,
            heal_retry_unix: None,
            heal_attempts: 0,
            heal_last_check_unix: None,
            heal_phase: None,
            heal_checked: None,
            heal_total: None,
            chunks_requeued: 0,
            stalled: false,
            auto_paused: false,
        };
        info.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &job_id,
        ))?;

        let (progress_tx, _progress_rx) = watch::channel(info.clone());
        let handle = Arc::new(JobHandle {
            info: Mutex::new(info),
            progress: progress_tx,
            pause_requested: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            notify: Notify::new(),
            driver: Mutex::new(None),
        });
        self.inner
            .jobs
            .lock()
            .expect("uploads jobs mutex poisoned")
            .insert(job_id.clone(), handle.clone());

        info!(
            target: "ant_node::uploads",
            job_id, source = %source_path.display(), source_size,
            "started upload",
        );
        self.spawn_driver(handle);
        Ok(job_id)
    }

    /// Look up a job by id (or by unique 8-hex-char prefix, which
    /// the operator can shorten to). Returns `NotFound` if absent.
    fn resolve(&self, id_or_prefix: &str) -> Result<Arc<JobHandle>, UploadError> {
        let jobs = self.inner.jobs.lock().expect("uploads jobs mutex poisoned");
        if let Some(h) = jobs.get(id_or_prefix) {
            return Ok(h.clone());
        }
        let mut hits = jobs
            .iter()
            .filter(|(k, _)| k.starts_with(id_or_prefix))
            .map(|(_, v)| v.clone());
        let first = hits.next();
        if hits.next().is_some() {
            return Err(UploadError::NotFound(format!(
                "ambiguous prefix {id_or_prefix}",
            )));
        }
        first.ok_or_else(|| UploadError::NotFound(id_or_prefix.to_string()))
    }

    /// Snapshot every known job. Stable insertion order is not
    /// guaranteed (`HashMap`), so callers that want a deterministic
    /// list sort by `created_at_unix`.
    #[must_use]
    pub fn list(&self) -> Vec<UploadJobInfo> {
        self.inner
            .jobs
            .lock()
            .expect("uploads jobs mutex poisoned")
            .values()
            .map(|h| h.snapshot())
            .collect()
    }

    /// Snapshot one job.
    pub fn status(&self, id: &str) -> Result<UploadJobInfo, UploadError> {
        Ok(self.resolve(id)?.snapshot())
    }

    /// Subscribe to live progress updates for `id`. Returns a
    /// [`watch::Receiver`] whose initial value is the current
    /// snapshot. Caller drops it when done following.
    pub fn subscribe(&self, id: &str) -> Result<watch::Receiver<UploadJobInfo>, UploadError> {
        let handle = self.resolve(id)?;
        Ok(handle.progress.subscribe())
    }

    /// Soft-stop a `Running` (or `Pending`) job. Idempotent on
    /// already-paused jobs; errors on terminal states so the CLI
    /// surfaces the operator's mistake.
    pub fn pause(&self, id: &str) -> Result<UploadJobInfo, UploadError> {
        let handle = self.resolve(id)?;
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            match info.status {
                UploadStatus::Running | UploadStatus::Pending => {
                    handle.pause_requested.store(true, Ordering::SeqCst);
                    info.status = UploadStatus::Paused;
                    // A user pause is sticky: wake/rehydrate must not
                    // auto-resume it.
                    info.auto_paused = false;
                    info.last_update_unix = unix_seconds();
                    info.clone()
                }
                UploadStatus::Paused => {
                    // Pausing an already-(auto-)paused job converts it
                    // to a user pause, so wake leaves it alone.
                    info.auto_paused = false;
                    info.clone()
                }
                other => return Err(UploadError::BadState(other)),
            }
        };
        let _ = handle.progress.send(snap.clone());
        snap.save(&UploadJobInfo::manifest_path(&self.inner.state_dir, id))?;
        Ok(snap)
    }

    /// Bring a `Paused` (or `Failed`) job back to `Running`. Spawns
    /// a fresh driver task; the previous driver has already
    /// exited. A `Completed` job instead triggers a background self-heal
    /// that re-pushes only its missing chunks on the same job (see body);
    /// other terminal states error with `BadState`.
    pub fn resume(&self, id: &str) -> Result<UploadJobInfo, UploadError> {
        let handle = self.resolve(id)?;

        // A `Completed` job can't be driver-"resumed", but the app's
        // "Push again" routes here for a completed file whose chunks didn't
        // fully propagate. Rather than mint a new upload, kick off the same
        // self-heal the daemon runs at startup: read the file back from the
        // network and re-push ONLY the chunks that are missing (from the
        // local chunk store, falling back to the source) against this same
        // job. It runs in the background and leaves the job `Completed`
        // throughout, so the caller gets the current snapshot back at once.
        {
            let status = handle.info.lock().expect("upload mutex poisoned").status;
            if status == UploadStatus::Completed {
                let snap = handle.snapshot();
                // Queue the heal (bounded + deduped) instead of spawning it
                // unbounded; the worker re-derives the address list from the
                // source. Returns the current snapshot immediately — the job
                // stays `Completed` while it secures.
                self.enqueue_heal(HealRequest {
                    job_id: snap.job_id.clone(),
                    mode: HealMode::ReachableOnly,
                    addrs: None,
                    batch_id: resolve_batch_id(
                        snap.batch_id.as_deref(),
                        self.inner.default_batch_id,
                    ),
                    source_path: snap.source_path.clone(),
                    source_size: snap.source_size,
                    raw: snap.raw,
                    name: snap.name.clone(),
                    content_type: snap.content_type.clone(),
                });
                return Ok(snap);
            }
        }

        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            match info.status {
                UploadStatus::Paused | UploadStatus::Failed => {
                    handle.pause_requested.store(false, Ordering::SeqCst);
                    handle.cancel_requested.store(false, Ordering::SeqCst);
                    info.status = UploadStatus::Running;
                    info.auto_paused = false;
                    info.last_error = None;
                    info.last_update_unix = unix_seconds();
                    info.clone()
                }
                UploadStatus::Running | UploadStatus::Pending => info.clone(),
                other => return Err(UploadError::BadState(other)),
            }
        };
        let _ = handle.progress.send(snap.clone());
        snap.save(&UploadJobInfo::manifest_path(&self.inner.state_dir, id))?;
        self.spawn_driver(handle);
        Ok(snap)
    }

    /// Hard-stop a job. Already-pushed chunks are left in the
    /// network (Swarm GCs them at postage TTL expiry — we can't
    /// unpush). Idempotent.
    pub fn cancel(&self, id: &str) -> Result<UploadJobInfo, UploadError> {
        let handle = self.resolve(id)?;
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            handle.cancel_requested.store(true, Ordering::SeqCst);
            handle.pause_requested.store(false, Ordering::SeqCst);
            handle.notify.notify_waiters();
            if !info.status.is_terminal() {
                info.status = UploadStatus::Cancelled;
                info.last_update_unix = unix_seconds();
            }
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        snap.save(&UploadJobInfo::manifest_path(&self.inner.state_dir, id))?;
        Ok(snap)
    }

    /// On daemon boot, scan the state directory for persisted jobs
    /// and re-register them. Jobs in `Running` state are restarted
    /// (the previous daemon was killed mid-push); jobs in
    /// `Paused`/`Failed`/`Cancelled`/`Completed` are loaded into
    /// memory but not restarted, so `antctl upload list` still
    /// shows them.
    ///
    /// `auto_resume` controls whether `Running`/`Pending` jobs
    /// found on disk get a fresh driver task. Operators who want
    /// to inspect state before re-engaging the network can pass
    /// `false` (mapped from `--no-resume-uploads`).
    pub fn rehydrate_from_disk(&self, auto_resume: bool) -> std::io::Result<usize> {
        let dir = &self.inner.state_dir;
        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let mut info = match UploadJobInfo::load(&path) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        target: "ant_node::uploads",
                        path = %path.display(),
                        "skipping unreadable job manifest: {e}",
                    );
                    continue;
                }
            };
            let job_id = info.job_id.clone();
            // Re-anchor a source stranded by a container move (iOS
            // reassigning the app-container UUID) before the job is
            // registered, so the driver / heal opens a live path from
            // the start. Guarded by a size+mtime match — see
            // `rebase_candidate` — and persisted immediately: the
            // rebase is a durable repair, not a per-run guess.
            if let Some(rebased) = self.rebase_candidate(&info) {
                info!(
                    target: "ant_node::uploads",
                    job_id,
                    from = %info.source_path.display(),
                    to = %rebased.display(),
                    "re-anchored upload source after data-container move",
                );
                info.source_path = rebased;
                info.last_update_unix = unix_seconds();
                let _ = info.save(&path);
            }
            // Auto-resume also restarts jobs the *system* paused
            // (`auto_paused` — the app was suspended mid-upload and
            // never woke), but never a user pause.
            let needs_restart =
                matches!(info.status, UploadStatus::Running | UploadStatus::Pending)
                    || (info.status == UploadStatus::Paused && info.auto_paused);
            let (progress_tx, _rx) = watch::channel(info.clone());
            let handle = Arc::new(JobHandle {
                info: Mutex::new(info),
                progress: progress_tx,
                pause_requested: AtomicBool::new(false),
                cancel_requested: AtomicBool::new(false),
                notify: Notify::new(),
                driver: Mutex::new(None),
            });
            self.inner
                .jobs
                .lock()
                .expect("uploads jobs mutex poisoned")
                .insert(job_id.clone(), handle.clone());
            count += 1;
            if needs_restart && auto_resume {
                info!(
                    target: "ant_node::uploads",
                    job_id, "auto-resuming upload after daemon restart",
                );
                self.spawn_driver(handle);
            } else if needs_restart {
                // Park as Paused so the operator can inspect via
                // `antctl upload list` and `resume` explicitly.
                let snap = {
                    let mut info = handle.info.lock().expect("upload mutex poisoned");
                    info.status = UploadStatus::Paused;
                    info.last_update_unix = unix_seconds();
                    info.clone()
                };
                let _ = handle.progress.send(snap.clone());
                let _ = snap.save(&UploadJobInfo::manifest_path(
                    &self.inner.state_dir,
                    &job_id,
                ));
            }
        }
        // Startup heal: finish securing any completed-but-unverified job
        // whose heal was interrupted. Without this they sit "Securing…"
        // forever — nothing else re-runs heal on boot. Shared with
        // `wake_all`, which needs the same re-queue after a suspension.
        self.requeue_unsecured_heals();
        // Keep degraded uploads retrying on a schedule (not only at
        // launch/wake): the ticker re-runs the same re-queue, with the
        // backoff map and in-flight set bounding the actual work. Started
        // once per process; skipped entirely while suspended.
        if !self.inner.retry_ticker_started.swap(true, Ordering::SeqCst) {
            let mgr = self.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(DEGRADED_RETRY_TICK);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    if mgr.inner.suspended.load(Ordering::SeqCst) {
                        continue;
                    }
                    mgr.requeue_unsecured_heals();
                }
            });
        }
        Ok(count)
    }

    /// Queue a securing pass for every `Completed` job that isn't
    /// `heal_verified` yet. Two flavours:
    ///
    /// * **Unfinished** — the pass was interrupted (shutdown /
    ///   suspension) or never ran: re-queued unconditionally.
    /// * **Degraded** — the pass ran to the end but couldn't confirm
    ///   deep reachability: re-queued too, but no more than once per
    ///   [`DEGRADED_HEAL_RETRY_INTERVAL`]. Repair used to be left to a
    ///   manual "Push again"; that let shallow-placed uploads silently
    ///   age out of the network while the row read "completed", so the
    ///   node now keeps trying at every launch/wake until the file
    ///   verifies. The postage/battery worry that made this manual is
    ///   bounded by the long backoff, the [`MAX_CONCURRENT_HEALS`]
    ///   queue, and the connectivity gate on shallow re-pushes (see
    ///   [`run_heal`](Self::run_heal)).
    ///
    /// Bounded + deduped by [`enqueue_heal`](Self::enqueue_heal) so a
    /// backlog secures a few at a time instead of thundering the
    /// network. Requests are enqueued reachable-only; `run_heal`
    /// upgrades to the shallow-aware mode at execution time when the
    /// node is well-connected. Shared by `rehydrate_from_disk` and
    /// [`wake_all`](Self::wake_all).
    fn requeue_unsecured_heals(&self) {
        let handles: Vec<Arc<JobHandle>> = self
            .inner
            .jobs
            .lock()
            .expect("uploads jobs mutex poisoned")
            .values()
            .cloned()
            .collect();
        for handle in handles {
            let snap = handle.snapshot();
            if snap.status != UploadStatus::Completed || snap.heal_verified {
                continue;
            }
            // A pass already queued or running needs no re-queue (and
            // the retry ticker must not re-log it every tick).
            if self
                .inner
                .heal_inflight
                .lock()
                .expect("heal inflight mutex poisoned")
                .contains(&snap.job_id)
            {
                continue;
            }
            if snap.heal_finished {
                // Degraded: retry, but with the long backoff. The window
                // is stamped when a pass *ends* degraded (note_degraded),
                // so spacing runs from the last attempt.
                let retry = self
                    .inner
                    .degraded_retry_after
                    .lock()
                    .expect("degraded retry mutex poisoned");
                if retry
                    .get(&snap.job_id)
                    .is_some_and(|&next| Instant::now() < next)
                {
                    continue;
                }
            }
            info!(
                target: "ant_node::uploads",
                job_id = %snap.job_id,
                degraded = snap.heal_finished,
                "queuing heal for unsecured completed upload",
            );
            self.enqueue_heal(HealRequest {
                job_id: snap.job_id.clone(),
                mode: HealMode::ReachableOnly,
                addrs: None,
                batch_id: resolve_batch_id(snap.batch_id.as_deref(), self.inner.default_batch_id),
                source_path: snap.source_path.clone(),
                source_size: snap.source_size,
                raw: snap.raw,
                name: snap.name.clone(),
                content_type: snap.content_type.clone(),
            });
        }
    }

    /// System-initiated pause of the whole upload subsystem — the app is
    /// moving to the background or the network went away. Every
    /// `Running`/`Pending` job is paused with the `auto_paused` marker
    /// (so [`wake_all`](Self::wake_all) / the next rehydrate knows to
    /// restart it; a job the *user* paused is left untouched), running
    /// securing passes are asked to stop, and the call waits — bounded
    /// by `SUSPEND_DRAIN_TIMEOUT` — for the paused drivers to drain
    /// their in-flight pushes and write their final checkpoint, so a
    /// host with a short background grace window (iOS gives ~a few
    /// seconds) knows the resume cursors are durably on disk when this
    /// returns. Idempotent. Returns the number of jobs it suspended.
    pub async fn suspend_all(&self) -> usize {
        // Flag first: securing passes observe it at their next round /
        // batch boundary and bail without claiming heal_finished.
        self.inner.suspended.store(true, Ordering::SeqCst);
        let handles: Vec<Arc<JobHandle>> = self
            .inner
            .jobs
            .lock()
            .expect("uploads jobs mutex poisoned")
            .values()
            .cloned()
            .collect();
        let mut suspended = 0usize;
        let mut drivers = Vec::new();
        for handle in handles {
            let snap = {
                let mut info = handle.info.lock().expect("upload mutex poisoned");
                match info.status {
                    UploadStatus::Running | UploadStatus::Pending => {
                        handle.pause_requested.store(true, Ordering::SeqCst);
                        info.status = UploadStatus::Paused;
                        info.auto_paused = true;
                        info.last_update_unix = unix_seconds();
                        info.clone()
                    }
                    _ => continue,
                }
            };
            suspended += 1;
            let _ = handle.progress.send(snap.clone());
            let _ = snap.save(&UploadJobInfo::manifest_path(
                &self.inner.state_dir,
                &snap.job_id,
            ));
            if let Some(task) = handle.driver.lock().expect("driver mutex poisoned").take() {
                drivers.push(task);
            }
        }
        // The driver's last act before exiting on pause is the
        // drain-and-checkpoint (`drain_for_pause`), so joining it means
        // the resume cursor is on disk. Bounded: a wedged push can hold
        // a driver for up to PUSH_TIMEOUT, far past any OS grace window
        // — losing at most one checkpoint interval of progress there is
        // the accepted trade (resume re-pushes; pushsync is idempotent).
        if !drivers.is_empty() {
            let _ = tokio::time::timeout(SUSPEND_DRAIN_TIMEOUT, futures::future::join_all(drivers))
                .await;
        }
        info!(
            target: "ant_node::uploads",
            suspended, "upload subsystem suspended",
        );
        suspended
    }

    /// Undo [`suspend_all`](Self::suspend_all): restart only the jobs it
    /// paused (`auto_paused` — a user pause stays paused) and re-queue
    /// securing passes for completed-but-unsecured jobs, exactly like a
    /// daemon boot does. Idempotent and safe without a prior suspend.
    /// Returns the number of jobs it resumed.
    pub fn wake_all(&self) -> usize {
        self.inner.suspended.store(false, Ordering::SeqCst);
        let jobs: Vec<(String, bool)> = self
            .inner
            .jobs
            .lock()
            .expect("uploads jobs mutex poisoned")
            .iter()
            .map(|(id, h)| {
                let info = h.info.lock().expect("upload mutex poisoned");
                (
                    id.clone(),
                    info.status == UploadStatus::Paused && info.auto_paused,
                )
            })
            .collect();
        let mut woken = 0usize;
        for (job_id, auto_paused) in jobs {
            if !auto_paused {
                continue;
            }
            // `resume` clears `auto_paused` and spawns a fresh driver.
            if self.resume(&job_id).is_ok() {
                woken += 1;
            }
        }
        self.requeue_unsecured_heals();
        info!(
            target: "ant_node::uploads",
            woken, "upload subsystem woken",
        );
        woken
    }

    /// Queue an automatic heal for a completed job, bounded by
    /// [`MAX_CONCURRENT_HEALS`] and deduplicated against in-flight heals.
    /// The spawned task parks on the semaphore — the job shows as "queued"
    /// meanwhile — until a slot frees, then runs the pass and clears its
    /// marker. Must be called from within a tokio runtime (the post-upload
    /// driver task, `resume`, or `rehydrate_from_disk` under
    /// `runtime.enter()`).
    fn enqueue_heal(&self, req: HealRequest) {
        let job_id = req.job_id.clone();
        if !self
            .inner
            .heal_inflight
            .lock()
            .expect("heal inflight mutex poisoned")
            .insert(job_id.clone())
        {
            return; // already queued or running — don't double-secure
        }
        // Surface the wait immediately so a backlog reads as "queued" rather
        // than a frozen "Securing…". The worker overwrites this with
        // "checking" / "repushing" once it starts; mark_heal_* clears it.
        self.set_heal_progress(&job_id, "queued", None, None);
        let mgr = self.clone();
        tokio::spawn(async move {
            // Park here until a heal slot frees (fair FIFO = the queue).
            let permit = mgr.inner.heal_slots.clone().acquire_owned().await;
            if permit.is_ok() {
                mgr.run_heal(req).await;
            }
            mgr.inner
                .heal_inflight
                .lock()
                .expect("heal inflight mutex poisoned")
                .remove(&job_id);
        });
    }

    /// Run one queued automatic heal to completion. Derives the chunk
    /// address list if the request didn't carry it: from the (possibly
    /// re-anchored) source file when it's still present and unchanged,
    /// else — for a job with a `reference` — by traversing the completed
    /// chunk tree through the persistent chunk store (the same store the
    /// re-push reads payloads from), so heal proceeds store-only instead
    /// of failing when the app deleted or lost the source. A job whose
    /// addresses can't be derived either way is marked heal-finished to
    /// stop the endless "Securing…". No progress sink — the automatic
    /// bar is driven by the job snapshot via [`set_heal_progress`], not
    /// a stream.
    async fn run_heal(&self, req: HealRequest) {
        if self.heal_aborted(&req.job_id) {
            return;
        }
        // A pass that actually runs re-opens the job's securing state:
        // watchers see live "Securing…" progress again, and a retry
        // interrupted mid-pass re-queues unconditionally on the next
        // launch (the degraded backoff only applies to *finished*
        // passes).
        self.mark_heal_running(&req.job_id);
        // Requests are enqueued conservative (reachable-only); upgrade
        // to the shallow-aware mode at *execution* time when the node
        // is well-connected — the queue wait often spans the window in
        // which the routing table fills, and degraded jobs are almost
        // always shallow-placement victims that a reachable-only pass
        // cannot repair (Sketch B's gate, applied when it matters).
        let mode = if req.mode == HealMode::ReachableOnly && self.neighbourhood_ready() {
            info!(
                target: "ant_node::uploads",
                job_id = %req.job_id,
                "node well-connected — queued heal will also re-push shallow placements",
            );
            HealMode::ReachableThenShallow
        } else {
            req.mode
        };
        let addrs = if let Some(addrs) = req.addrs {
            addrs
        } else {
            // Prefer the live (rebased) source; the request's copy of
            // the path may predate a container-move re-anchor.
            let resolved = self
                .job_handle(&req.job_id)
                .map_or_else(|| req.source_path.clone(), |h| self.resolve_job_source(&h));
            let source_ok =
                std::fs::metadata(&resolved).is_ok_and(|md| md.len() == req.source_size);
            let derived = if source_ok {
                match collect_heal_addrs(
                    &resolved,
                    req.source_size,
                    req.raw,
                    req.name.as_deref(),
                    req.content_type.as_deref(),
                ) {
                    Ok(Some(addrs)) => Some(addrs),
                    Ok(None) => {
                        info!(
                            target: "ant_node::uploads",
                            job_id = %req.job_id,
                            "queued heal: file exceeds heal chunk cap — skipping",
                        );
                        self.mark_heal_finished(&req.job_id);
                        return;
                    }
                    Err(e) => {
                        warn!(
                            target: "ant_node::uploads",
                            job_id = %req.job_id,
                            "queued heal: could not re-derive chunks: {e}",
                        );
                        None
                    }
                }
            } else {
                None
            };
            let derived = if derived.is_some() {
                derived
            } else {
                self.collect_heal_addrs_from_store(&req.job_id).await
            };
            let Some(addrs) = derived else {
                info!(
                    target: "ant_node::uploads",
                    job_id = %req.job_id,
                    "queued heal: source unavailable and store traversal failed — marking secured-as-is",
                );
                self.mark_heal_finished(&req.job_id);
                return;
            };
            addrs
        };
        self.verify_and_heal(
            &req.job_id,
            &addrs,
            req.batch_id,
            &req.source_path,
            req.source_size,
            req.raw,
            req.name.as_deref(),
            req.content_type.as_deref(),
            mode,
            None,
        )
        .await;
    }

    /// Record a degraded / inconclusive securing outcome: stamp the
    /// long-backoff window that gates the next automatic retry (both in
    /// the manager map the requeue consults and as the user-visible
    /// `heal_retry_unix`), and — when the pass measured one — the
    /// residual chunk count (`heal_missing`), so a client can show
    /// "N parts still settling · next check in ~M min" instead of a
    /// bare warning. `missing = None` (inconclusive read-back, user
    /// cancel) keeps the previous residual figure.
    fn note_degraded(&self, job_id: &str, missing: Option<u64>) {
        let Some(handle) = self.job_handle(job_id) else {
            // Unknown job: still park a conservative window so it can't
            // spin the requeue.
            self.defer_degraded_retry(job_id, DEGRADED_HEAL_RETRY_INTERVAL);
            return;
        };
        let (snap, interval) = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            if let Some(n) = missing {
                info.heal_missing = Some(n);
            }
            info.heal_attempts = info.heal_attempts.saturating_add(1);
            // Escalate from quick early re-checks to the cap (see
            // `degraded_retry_interval`).
            let interval = degraded_retry_interval(info.heal_attempts);
            info.heal_last_check_unix = Some(unix_seconds());
            info.heal_retry_unix = Some(unix_seconds() + interval.as_secs());
            info.last_update_unix = unix_seconds();
            (info.clone(), interval)
        };
        self.inner
            .degraded_retry_after
            .lock()
            .expect("degraded retry mutex poisoned")
            .insert(job_id.to_string(), Instant::now() + interval);
        let _ = handle.progress.send(snap.clone());
        let _ = snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ));
    }

    /// Park the next automatic retry of `job_id` for `interval` without
    /// counting a check (the user-cancel path: a stop is not a pass,
    /// but it must hold for the full window regardless of how young the
    /// escalation schedule is). Also updates the user-visible countdown.
    fn defer_degraded_retry(&self, job_id: &str, interval: std::time::Duration) {
        self.inner
            .degraded_retry_after
            .lock()
            .expect("degraded retry mutex poisoned")
            .insert(job_id.to_string(), Instant::now() + interval);
        let Some(handle) = self.job_handle(job_id) else {
            return;
        };
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            info.heal_retry_unix = Some(unix_seconds() + interval.as_secs());
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        let _ = snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ));
    }

    /// Re-open a job's securing state as a queued heal pass actually
    /// starts running: clear `heal_finished` (persisted) so watchers see
    /// the pass as live progress rather than a stale terminal verdict,
    /// and so an interruption mid-pass re-queues unconditionally on the
    /// next launch. No-op when the flag is already clear (the fresh
    /// post-upload pass).
    fn mark_heal_running(&self, job_id: &str) {
        let Some(handle) = self.job_handle(job_id) else {
            return;
        };
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            if !info.heal_finished {
                return;
            }
            info.heal_finished = false;
            // The pass is live again — the countdown no longer applies.
            info.heal_retry_unix = None;
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        let _ = snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ));
    }

    /// Deep-heal one `Completed` job. Re-validates the source file
    /// (existence + size), re-derives the chunk set, then runs the
    /// [`verify_and_heal`](Self::verify_and_heal) loop. Best-effort: a
    /// missing/changed source or an oversized file is logged and skipped.
    /// Now only the user-initiated "Push again"
    /// ([`repush_with_progress`](Self::repush_with_progress)) calls this
    /// directly — it awaits the pass and streams progress. The automatic
    /// heals (post-upload, `resume`, startup re-heal) go through the bounded
    /// queue instead ([`enqueue_heal`](Self::enqueue_heal) →
    /// [`run_heal`](Self::run_heal)).
    async fn heal_completed_job(
        &self,
        handle: Arc<JobHandle>,
        mode: HealMode,
        progress: HealProgress,
    ) {
        let snap = handle.snapshot();
        let job_id = snap.job_id.clone();
        let source_path = self.resolve_job_source(&handle);

        // Prefer re-deriving the chunk set from the source file — it must
        // still be present and have the same content, or the set wouldn't
        // match what was uploaded. We gate on size only, not mtime: heal
        // re-derives every chunk address straight from the bytes, and a
        // re-anchored import (carried into a new data container) can
        // legitimately carry a fresh mtime while its content is
        // byte-identical. With the source gone/changed, fall back to
        // traversing the completed chunk tree through the persistent
        // chunk store, so "Push again" keeps working after the app
        // deleted the original.
        let source_ok =
            std::fs::metadata(&source_path).is_ok_and(|md| md.len() == snap.source_size);
        let all_addrs = if source_ok {
            match collect_heal_addrs(
                &source_path,
                snap.source_size,
                snap.raw,
                snap.name.as_deref(),
                snap.content_type.as_deref(),
            ) {
                Ok(Some(addrs)) => addrs,
                Ok(None) => {
                    info!(
                        target: "ant_node::uploads",
                        job_id = %job_id,
                        "skipping heal: file exceeds heal chunk cap",
                    );
                    return;
                }
                Err(e) => {
                    warn!(
                        target: "ant_node::uploads",
                        job_id = %job_id,
                        "skipping heal: could not re-derive chunks: {e}",
                    );
                    return;
                }
            }
        } else if let Some(addrs) = self.collect_heal_addrs_from_store(&job_id).await {
            addrs
        } else {
            info!(
                target: "ant_node::uploads",
                job_id = %job_id,
                "skipping heal: source unavailable and store traversal failed",
            );
            return;
        };

        let batch_id = resolve_batch_id(snap.batch_id.as_deref(), self.inner.default_batch_id);
        info!(
            target: "ant_node::uploads",
            job_id = %job_id, chunks = all_addrs.len(), mode = mode.label(),
            "running {} for completed upload", mode.label(),
        );
        self.verify_and_heal(
            &job_id,
            &all_addrs,
            batch_id,
            &source_path,
            snap.source_size,
            snap.raw,
            snap.name.as_deref(),
            snap.content_type.as_deref(),
            mode,
            progress,
        )
        .await;
    }

    /// "Push again" with progress: run the self-heal for a `Completed` job
    /// to completion, streaming progress to `progress`, then return the
    /// job's snapshot. Re-pushes only the missing chunks on the same job —
    /// no new job. Errors if the job is unknown or not completed.
    pub async fn repush_with_progress(
        &self,
        job_id: &str,
        progress: HealProgress,
    ) -> Result<UploadJobInfo, UploadError> {
        let handle = self.resolve(job_id)?;
        let status = handle.info.lock().expect("upload mutex poisoned").status;
        if status != UploadStatus::Completed {
            return Err(UploadError::BadState(status));
        }
        // Manual "Push again": a single shallow-aware round, so it actually
        // repairs a file that loads but isn't durably stored.
        self.heal_completed_job(handle.clone(), HealMode::ShallowOnce, progress)
            .await;
        Ok(handle.snapshot())
    }

    fn mint_id(&self) -> String {
        let counter = self.inner.id_counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        // 8 bytes of identity: low 40 bits of nanos XOR with the
        // counter (so two starts in the same nanosecond don't
        // collide). Hex-encoded for `antctl upload <id>` ergonomics.
        let raw = (nanos & 0x0000_00FF_FFFF_FFFF) ^ (counter << 40);
        format!("{raw:016x}")
    }

    fn spawn_driver(&self, handle: Arc<JobHandle>) {
        let mgr = self.clone();
        let task_handle = handle.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = mgr.run_job(task_handle.clone()).await {
                warn!(
                    target: "ant_node::uploads",
                    "upload driver returned error: {e}",
                );
                // Defensive: any unhandled error from the driver
                // already surfaced by `mark_failed`; this branch
                // exists for the `?` propagation path before the
                // driver's own error handling kicks in.
                mgr.mark_failed(&task_handle, e.to_string());
            }
        });
        // Keep the task joinable so `suspend_all` can await the
        // drain-and-checkpoint a pause triggers.
        *handle.driver.lock().expect("driver mutex poisoned") = Some(task);
    }

    /// Move `info.status` to `Failed` and persist. Called on
    /// terminal driver errors; the operator can `resume` to retry.
    fn mark_failed(&self, handle: &Arc<JobHandle>, message: String) {
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            info.status = UploadStatus::Failed;
            info.last_error = Some(message);
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        let _ = snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ));
    }

    /// Drive a single job through to completion (or pause /
    /// cancel). Re-streams the source file from byte 0, recomputing
    /// every chunk address; chunks below the persisted resume
    /// cursor are skipped (no postage stamp consumed, no pushsync
    /// dispatched). All other chunks go through the existing
    /// `ControlCommand::PushChunk` pipeline with bounded
    /// concurrency.
    async fn run_job(&self, handle: Arc<JobHandle>) -> Result<(), UploadError> {
        // Mark Running — even Pending jobs flip here so the watch
        // receiver sees the transition. A running driver also means any
        // prior system pause is over. Skipped when a pause/cancel beat
        // the driver to its first turn (a suspend can land between
        // `start` and here): the requester already persisted the
        // Paused/Cancelled state and the loop below exits on the flag —
        // overwriting it with `Running` would strand a parked job
        // looking alive.
        {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            if !handle.pause_requested.load(Ordering::SeqCst)
                && !handle.cancel_requested.load(Ordering::SeqCst)
            {
                info.status = UploadStatus::Running;
                info.auto_paused = false;
                info.last_update_unix = unix_seconds();
                let _ = handle.progress.send(info.clone());
            }
        }

        // Re-anchor the source if its stored absolute path went stale
        // across a data-container move (see `resolve_job_source`).
        let source_path = self.resolve_job_source(&handle);
        let snap = handle.snapshot();
        // Resolve which postage batch stamps this job's chunks: the
        // job's own `batch_id` (hex) if set, else the manager's startup
        // default. A zeroed id means "none configured" — the node loop
        // then rejects the push with a clear "batch … not usable".
        let batch_id = resolve_batch_id(snap.batch_id.as_deref(), self.inner.default_batch_id);

        // Re-validate: file must exist, be the same size and mtime
        // we recorded at start. Resume across mtime change would
        // produce a different chunk tree → the persisted reference
        // would not match the actual content.
        let metadata = std::fs::metadata(&source_path)?;
        if metadata.len() != snap.source_size {
            let e = UploadError::SourceChanged {
                expected_size: snap.source_size,
                actual_size: metadata.len(),
            };
            self.mark_failed(&handle, e.to_string());
            return Err(e);
        }
        let live_mtime = mtime_unix_ms(&metadata);
        if live_mtime != snap.source_mtime_unix_ms {
            let e = UploadError::SourceMtimeChanged {
                expected_mtime_ms: snap.source_mtime_unix_ms,
                actual_mtime_ms: live_mtime,
            };
            self.mark_failed(&handle, e.to_string());
            return Err(e);
        }

        // Best-effort capacity warning before we start stamping, so a
        // tight batch is flagged up-front rather than discovered when a
        // chunk fails to stamp (immutable) or evicts an older one
        // (mutable) part-way through. Never fatal.
        let est_chunks = snap
            .chunks_total
            .unwrap_or_else(|| estimate_chunk_count(snap.source_size, snap.raw));
        self.capacity_preflight(&batch_id, est_chunks).await;

        // mmap (zero-copy). Empty files are a special case: mmap
        // on a 0-byte file is undefined on some platforms, so we
        // produce the empty leaf via the streaming splitter's
        // `finish` path without ever feeding a leaf.
        let file = std::fs::File::open(&source_path)?;
        let body: Option<Mmap> = if snap.source_size == 0 {
            None
        } else {
            // SAFETY: `body` is immutable for the upload's life; we
            // refuse to resume on mtime change, so the OS will not
            // relocate the file under us. macOS/Linux page faults
            // are tolerated by walking the bytes in 4 KiB strides.
            Some(unsafe { Mmap::map(&file)? })
        };

        let resume_cursor = snap.chunks_pushed;
        let mut splitter = StreamingSplitter::new();
        let mut next_index: u64 = 0;
        let mut ack_log = AckLog::new(resume_cursor);
        // Bounded queue of in-flight pushes. Each entry carries the
        // chunk's emit index so we can advance the in-order
        // checkpoint cursor on completion.
        let mut in_flight: FuturesUnordered<PushFuture> = FuturesUnordered::new();

        let mut bytes_emitted: u64 = 0;
        let mut leaf_iter = LeafIter::new(body.as_deref(), snap.source_size);

        // Every chunk address this file produces (data leaves,
        // intermediates, manifest), regardless of the resume cursor —
        // the post-upload heal pass reads them all back. Collection
        // stops (and heal is skipped) once the file exceeds
        // `HEAL_MAX_CHUNKS` so a multi-GB upload doesn't buffer millions
        // of addresses or trigger a full re-download to verify.
        let mut heal_addrs: Vec<[u8; 32]> = Vec::new();
        let mut heal_overflow = false;

        // Shared counter bumped on every transient re-queue. Folded
        // into the job snapshot on each checkpoint / heartbeat tick
        // for observability — never a kill switch. Seeded from the
        // persisted value so a resumed job's counter keeps climbing
        // rather than resetting.
        let requeued = Arc::new(AtomicU64::new(snap.chunks_requeued));
        // Liveness tracking. The upload never fails on peer churn (a
        // struggling chunk is re-queued forever), so a blocking caller
        // needs a signal that it's not progressing: if no chunk acks
        // for STALL_THRESHOLD we flip `stalled` true (and broadcast
        // it) without changing the job's terminal outcome.
        let mut live = Liveness::new();
        // Fix 1 (re-queue scheduler): a chunk whose push transiently
        // failed parks here for its back-off instead of sleeping
        // inside its own future — so all MAX_PUSH_CONCURRENCY slots
        // keep doing network work while it waits.
        let mut retries = RetryQueue::default();

        loop {
            // Cancellation check at the top of every loop turn —
            // no chunk dispatch can sneak in after a `cancel` call.
            if handle.cancel_requested.load(Ordering::SeqCst) {
                debug!(
                    target: "ant_node::uploads",
                    job_id = %snap.job_id,
                    "cancel observed; draining in-flight pushes",
                );
                // Drop in_flight; let the spawned futures error
                // out on their own. We don't care about results.
                drop(in_flight);
                return Ok(());
            }
            // Pause check — drain in-flight, persist, park. Parked
            // retries are simply dropped: the contiguous cursor can't
            // advance past them, so resume re-derives and re-pushes.
            if handle.pause_requested.load(Ordering::SeqCst) {
                self.drain_for_pause(&mut in_flight, &mut ack_log, &handle, &requeued, &mut live)
                    .await?;
                debug!(
                    target: "ant_node::uploads",
                    job_id = %snap.job_id,
                    chunks_pushed = ack_log.cursor(),
                    "paused; awaiting resume",
                );
                // resume() flips pause_requested to false then
                // spawns a fresh driver task — so this driver
                // exits and is replaced.
                return Ok(());
            }

            // Re-dispatch parked chunks whose back-off has elapsed
            // before pulling fresh chunks off the splitter, so older
            // chunks aren't starved by new ones (bee's pusher does
            // the same: the retry channel outranks the fresh-chunk
            // channel).
            let now = tokio::time::Instant::now();
            while in_flight.len() < max_push_concurrency() {
                let Some(entry) = retries.pop_due(now) else {
                    break;
                };
                let width = hedge_width(leaf_iter.is_done(), in_flight.len() + retries.len() + 1);
                in_flight.push(self.dispatch_push_once(
                    entry.index,
                    entry.chunk,
                    entry.attempt,
                    batch_id,
                    width,
                ));
            }

            // Then: dispatch the next fresh chunk(s), await an
            // in-flight completion, or — if all queues are empty
            // and the splitter is exhausted — break to the finish
            // step.
            if in_flight.len() < max_push_concurrency() {
                if let Some(leaf) = leaf_iter.next() {
                    bytes_emitted += leaf.len() as u64;
                    let chunks = splitter.push_leaf(leaf);
                    for chunk in chunks {
                        let i = next_index;
                        next_index += 1;
                        note_heal_addr(&mut heal_addrs, &mut heal_overflow, chunk.address);
                        if i < resume_cursor {
                            // Already pushed in a previous run.
                            // No stamp consumed, no command
                            // dispatched. The next-chunk index
                            // bookkeeping is what matters; the
                            // streaming splitter has just
                            // re-derived this address byte-for-byte.
                            continue;
                        }
                        in_flight.push(self.dispatch_push_once(i, chunk, 0, batch_id, 1));
                    }
                    continue;
                }
            }

            // Nothing more to dispatch and nothing in flight or
            // parked — break to the finish step. Checked before the
            // await so we never park on an empty queue.
            if leaf_iter.is_done() && in_flight.is_empty() && retries.is_empty() {
                break;
            }

            // Drain an in-flight completion, wake when the earliest
            // parked retry comes due (only if a slot is free for it),
            // or refresh liveness on the heartbeat tick. The job
            // never fails here on peer churn: only a genuinely
            // unrecoverable condition (daemon gone / bad batch)
            // surfaces as an error.
            let next_due = retries.next_due();
            tokio::select! {
                biased;
                Some((i, outcome)) = in_flight.next() => {
                    self.handle_outcome(
                        i, outcome, &mut retries, &mut ack_log, &handle,
                        &requeued, &mut live, snap.source_size,
                    )?;
                }
                () = tokio::time::sleep_until(next_due.unwrap_or(now)),
                    if next_due.is_some() && in_flight.len() < max_push_concurrency() => {
                    // Loop turn re-dispatches the due retry.
                }
                _ = live.tick.tick() => {
                    self.heartbeat(&handle, &requeued, &mut live, &snap.job_id);
                }
            }
        }
        // Source fully consumed. Cancel/pause check before pushing
        // intermediates is unnecessary because they were emitted
        // inline by `push_leaf` already; only the splitter's tail
        // (root + partial intermediates) remains — a handful of
        // chunks (one partial intermediate per tree level), well
        // under MAX_PUSH_CONCURRENCY, so dispatch them all at once.
        //
        // The tail and the manifest chunks are pushed even below
        // `resume_cursor`: they are a handful of chunks, and their
        // shape is not stable across builds. #234 dropped the 1-child
        // wrapper from the tail, so a job that failed or was killed
        // mid-tail under an older build would otherwise resume with
        // its cursor past the index of the new data root and finish
        // without ever pushing it. Re-pushing an already-stored chunk
        // is harmless; `AckLog::record` ignores indices below the
        // cursor.
        let (data_root, _total_bytes, tail) = splitter.finish();
        for chunk in tail {
            let i = next_index;
            next_index += 1;
            note_heal_addr(&mut heal_addrs, &mut heal_overflow, chunk.address);
            in_flight.push(self.dispatch_push_once(i, chunk, 0, batch_id, 1));
        }
        // Drain the tail (with the same re-queue + tail-hedging
        // machinery as the main loop).
        self.drain_with_requeue(
            &mut in_flight,
            &mut retries,
            &mut ack_log,
            &handle,
            &requeued,
            &mut live,
            batch_id,
            snap.source_size,
        )
        .await?;
        if handle.cancel_requested.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Either wrap the data root in a single-file mantaray
        // manifest (the bzz-compatible default) or finish at the
        // raw data root (saves 1-2 chunks but loses the embedded
        // filename + content-type, so consumers must know the
        // file type out-of-band).
        let info_at_finish = handle.snapshot();
        let final_root: [u8; 32] = if info_at_finish.raw {
            data_root
        } else {
            let filename = info_at_finish
                .name
                .clone()
                .unwrap_or_else(|| "blob.bin".to_string());
            let manifest = build_single_file_manifest(
                &filename,
                info_at_finish.content_type.as_deref(),
                data_root,
            )?;
            for chunk in &manifest.chunks {
                let i = next_index;
                next_index += 1;
                note_heal_addr(&mut heal_addrs, &mut heal_overflow, chunk.address);
                // Never skipped on resume; see the tail loop above.
                in_flight.push(self.dispatch_push_once(i, chunk.clone(), 0, batch_id, 1));
            }
            self.drain_with_requeue(
                &mut in_flight,
                &mut retries,
                &mut ack_log,
                &handle,
                &requeued,
                &mut live,
                batch_id,
                snap.source_size,
            )
            .await?;
            if handle.cancel_requested.load(Ordering::SeqCst) {
                return Ok(());
            }
            manifest.root
        };

        // Job complete. Record the final reference (manifest root,
        // or — for raw jobs — the data root) and flush a final
        // checkpoint. Pause/cancel from here on no-op (job is in
        // a terminal state).
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            info.status = UploadStatus::Completed;
            info.bytes_pushed = info.source_size;
            info.chunks_pushed = next_index;
            info.reference = Some(format!("0x{}", hex::encode(final_root)));
            info.chunks_requeued = requeued.load(Ordering::Relaxed);
            info.stalled = false;
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ))?;
        info!(
            target: "ant_node::uploads",
            job_id = %snap.job_id,
            reference = %snap.reference.as_deref().unwrap_or(""),
            chunks = snap.chunks_pushed,
            bytes = snap.bytes_pushed,
            "upload completed",
        );

        // Self-heal, in the background so the job reports `Completed`
        // immediately. Reads every chunk back from the network and
        // re-pushes any that didn't land, so the file ends up actually
        // retrievable rather than merely pushed-once. Best-effort and
        // bounded; skipped for very large files (see `HEAL_MAX_CHUNKS`).
        if heal_overflow {
            info!(
                target: "ant_node::uploads",
                job_id = %snap.job_id,
                "skipping post-upload heal: file exceeds heal chunk cap",
            );
        } else if !handle.cancel_requested.load(Ordering::SeqCst) {
            // Sketch B: on a well-connected node the per-chunk probe is
            // trustworthy, so the automatic heal runs the full reachable
            // mop-up AND a shallow-promotion pass — repairing both transient
            // stragglers and shallow placements. On a constrained node the
            // probe can't reliably judge durability, so stay reachable-only
            // and leave shallow repair to the user.
            let mode = if self.neighbourhood_ready() {
                info!(
                    target: "ant_node::uploads",
                    job_id = %snap.job_id,
                    "node well-connected — post-upload heal will also re-push shallow placements",
                );
                HealMode::ReachableThenShallow
            } else {
                HealMode::ReachableOnly
            };
            // Queue rather than spawn unbounded: a burst of completing uploads
            // would otherwise launch a heal each and thunder the one command
            // channel, stalling them all. The address list is already in
            // memory, so pass it through (robust even if the source is
            // deleted right after upload).
            self.enqueue_heal(HealRequest {
                job_id: snap.job_id.clone(),
                mode,
                addrs: Some(heal_addrs),
                batch_id,
                source_path: source_path.clone(),
                source_size: snap.source_size,
                raw: snap.raw,
                name: snap.name.clone(),
                content_type: snap.content_type.clone(),
            });
        }

        // Defensive: silence "unused" lint for `bytes_emitted` —
        // we keep the counter on the side as a debug aid for
        // tracing slow uploads even though `info.bytes_pushed`
        // is the wire-visible field.
        let _ = bytes_emitted;
        Ok(())
    }

    /// Record one acked chunk: advance the in-order cursor, refresh
    /// liveness, broadcast progress, and checkpoint to disk every
    /// [`CHECKPOINT_INTERVAL_CHUNKS`] pushes. Shared by the main
    /// driver loop and both drain paths.
    fn note_acked(
        &self,
        handle: &Arc<JobHandle>,
        ack_log: &mut AckLog,
        requeued: &Arc<AtomicU64>,
        live: &mut Liveness,
        i: u64,
        source_size: u64,
    ) {
        ack_log.record(i);
        live.last_progress = Instant::now();
        live.stalled = false;
        let cursor = ack_log.cursor();
        let mut info = handle.info.lock().expect("upload mutex poisoned");
        let advanced = cursor > info.chunks_pushed;
        let mut dirty = false;
        if advanced {
            info.chunks_pushed = cursor;
            // bytes_pushed tracks data leaves pushed (cursor includes
            // intermediates, so derive from the leaf-bytes counter we
            // keep on the side).
            info.bytes_pushed = ack_log.bytes_pushed(source_size).min(source_size);
            dirty = true;
        }
        let rq = requeued.load(Ordering::Relaxed);
        if info.chunks_requeued != rq {
            info.chunks_requeued = rq;
            dirty = true;
        }
        if info.stalled {
            info.stalled = false;
            dirty = true;
        }
        if dirty {
            info.last_update_unix = unix_seconds();
            let snap = info.clone();
            drop(info);
            let _ = handle.progress.send(snap.clone());
            // Checkpoint to disk every N chunks — pubsub watchers
            // always see updates.
            if advanced && cursor.is_multiple_of(CHECKPOINT_INTERVAL_CHUNKS) {
                let _ = snap.save(&UploadJobInfo::manifest_path(
                    &self.inner.state_dir,
                    &snap.job_id,
                ));
            }
        }
    }

    /// Fold one completed push outcome back into the driver state:
    /// ack bookkeeping on success, re-queue with jittered back-off on
    /// a transient failure (Fix 1 — the in-flight slot was already
    /// freed when the future completed), `Err` on a genuinely
    /// unrecoverable condition.
    #[allow(clippy::too_many_arguments)]
    fn handle_outcome(
        &self,
        i: u64,
        outcome: PushOnceOutcome,
        retries: &mut RetryQueue,
        ack_log: &mut AckLog,
        handle: &Arc<JobHandle>,
        requeued: &Arc<AtomicU64>,
        live: &mut Liveness,
        source_size: u64,
    ) -> Result<(), UploadError> {
        match outcome {
            PushOnceOutcome::Acked => {
                self.note_acked(handle, ack_log, requeued, live, i, source_size);
                Ok(())
            }
            PushOnceOutcome::Transient {
                chunk,
                attempt,
                no_peer,
                message,
            } => {
                requeued.fetch_add(1, Ordering::Relaxed);
                let base = if no_peer {
                    NO_PEER_BACKOFF
                } else {
                    backoff_for_retry(attempt)
                };
                let delay = with_jitter(base);
                debug!(
                    target: "ant_node::uploads",
                    index = i,
                    attempt,
                    no_peer,
                    delay_ms = delay.as_millis() as u64,
                    "re-queueing chunk after transient push failure: {message}",
                );
                retries.push(RetryEntry {
                    due: tokio::time::Instant::now() + delay,
                    index: i,
                    chunk,
                    attempt: attempt.saturating_add(1),
                });
                Ok(())
            }
            PushOnceOutcome::Fatal(e) => {
                // Only genuinely unrecoverable errors reach here (the
                // upload path re-queues transient failures forever).
                // Surface and exit; the operator can `resume` from
                // the persisted cursor.
                let msg = e.to_string();
                self.mark_failed(handle, msg.clone());
                Err(UploadError::PushFailed(msg))
            }
        }
    }

    /// Periodic liveness + keep-alive broadcast (Fix 7). Always sends
    /// a progress frame — even when nothing changed — because both
    /// the daemon's streaming dispatch (60 s) and the client socket
    /// (75 s) treat a long gap between frames as a dead stream, and a
    /// stalled-but-alive upload must keep its `follow`ers attached.
    #[allow(clippy::unused_self)] // driver-loop helper, kept on the manager for symmetry
    fn heartbeat(
        &self,
        handle: &Arc<JobHandle>,
        requeued: &Arc<AtomicU64>,
        live: &mut Liveness,
        job_id: &str,
    ) {
        let rq = requeued.load(Ordering::Relaxed);
        let now_stalled = live.last_progress.elapsed() >= STALL_THRESHOLD;
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            info.chunks_requeued = rq;
            info.stalled = now_stalled;
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap);
        if now_stalled && !live.stalled {
            warn!(
                target: "ant_node::uploads",
                job_id = %job_id,
                requeued = rq,
                "upload stalled: no chunk acked for {}s — still retrying (job not failed)",
                STALL_THRESHOLD.as_secs(),
            );
        }
        live.stalled = now_stalled;
    }

    /// Run the re-queue scheduler until every in-flight and parked
    /// chunk has acked. Used after the splitter tail is dispatched
    /// and after the manifest is pushed — the phases where the
    /// remaining set is small, so re-dispatches hedge across peers
    /// (Fix 2). Returns early (Ok) on cancel; the caller re-checks
    /// `cancel_requested` before declaring the job complete.
    #[allow(clippy::too_many_arguments)]
    async fn drain_with_requeue(
        &self,
        in_flight: &mut FuturesUnordered<PushFuture>,
        retries: &mut RetryQueue,
        ack_log: &mut AckLog,
        handle: &Arc<JobHandle>,
        requeued: &Arc<AtomicU64>,
        live: &mut Liveness,
        batch_id: [u8; 32],
        source_size: u64,
    ) -> Result<(), UploadError> {
        let job_id = handle.snapshot().job_id;
        loop {
            if handle.cancel_requested.load(Ordering::SeqCst) {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            while in_flight.len() < max_push_concurrency() {
                let Some(entry) = retries.pop_due(now) else {
                    break;
                };
                let width = hedge_width(true, in_flight.len() + retries.len() + 1);
                in_flight.push(self.dispatch_push_once(
                    entry.index,
                    entry.chunk,
                    entry.attempt,
                    batch_id,
                    width,
                ));
            }
            if in_flight.is_empty() && retries.is_empty() {
                break;
            }
            let next_due = retries.next_due();
            tokio::select! {
                biased;
                Some((i, outcome)) = in_flight.next() => {
                    self.handle_outcome(
                        i, outcome, retries, ack_log, handle, requeued, live, source_size,
                    )?;
                }
                () = tokio::time::sleep_until(next_due.unwrap_or(now)),
                    if next_due.is_some() && in_flight.len() < max_push_concurrency() => {}
                _ = live.tick.tick() => {
                    self.heartbeat(handle, requeued, live, &job_id);
                }
            }
        }
        // Final checkpoint after each drain.
        let snap = handle.snapshot();
        snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ))?;
        Ok(())
    }

    /// Wait for every in-flight push to complete and update the
    /// cursor, dropping transiently-failed chunks (the contiguous
    /// cursor can't advance past them, so resume re-derives and
    /// re-pushes). Used at pause time only — single-attempt futures
    /// complete within [`PUSH_TIMEOUT`], so pause is prompt instead
    /// of waiting out a forever-retry loop.
    async fn drain_for_pause(
        &self,
        in_flight: &mut FuturesUnordered<PushFuture>,
        ack_log: &mut AckLog,
        handle: &Arc<JobHandle>,
        requeued: &Arc<AtomicU64>,
        live: &mut Liveness,
    ) -> Result<(), UploadError> {
        let source_size = handle.snapshot().source_size;
        while let Some((i, outcome)) = in_flight.next().await {
            match outcome {
                PushOnceOutcome::Acked => {
                    self.note_acked(handle, ack_log, requeued, live, i, source_size);
                }
                // Dropped on pause: re-pushed after resume.
                PushOnceOutcome::Transient { .. } => {}
                PushOnceOutcome::Fatal(e) => {
                    let msg = e.to_string();
                    self.mark_failed(handle, msg.clone());
                    return Err(UploadError::PushFailed(msg));
                }
            }
        }
        // Final checkpoint after the drain.
        let snap = handle.snapshot();
        snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ))?;
        Ok(())
    }

    /// Build the future for **one** push of one chunk through the
    /// existing `ControlCommand::PushChunk` pipeline — no internal
    /// retry loop (the driver's [`RetryQueue`] owns retries, Fix 1).
    /// Boxed so the `FuturesUnordered` queue can hold heterogeneous
    /// push types (data leaf vs intermediate vs manifest chunk — the
    /// wire shape is identical, but boxing keeps the type uniform).
    ///
    /// `width > 1` enables tail hedging (Fix 2): the chunk is raced
    /// as `width` concurrent pushsync commands, staggered by
    /// [`TAIL_HEDGE_STAGGER`], and the first receipt wins (pushsync
    /// is idempotent, so the losers are wasted RTTs, not bugs). The
    /// outcome is `Transient` only if *every* lane failed
    /// transiently; any fatal lane fails the dispatch.
    fn dispatch_push_once(
        &self,
        index: u64,
        chunk: SplitChunk,
        attempt: u32,
        batch_id: [u8; 32],
        width: usize,
    ) -> PushFuture {
        let cmd_tx = self.inner.cmd_tx.clone();
        Box::pin(async move {
            let mut lanes: FuturesUnordered<_> = (0..width.max(1))
                .map(|k| {
                    let cmd_tx = cmd_tx.clone();
                    let wire = chunk.wire.clone();
                    async move {
                        if k > 0 {
                            tokio::time::sleep(TAIL_HEDGE_STAGGER * k as u32).await;
                        }
                        push_attempt(&cmd_tx, wire, batch_id).await
                    }
                })
                .collect();
            // `no_peer` only if every lane reported it: one lane
            // finding candidates means the neighbourhood isn't empty,
            // so the shorter busy-storer back-off applies.
            let mut no_peer = true;
            let mut last_msg = String::new();
            while let Some(res) = lanes.next().await {
                match res {
                    AttemptResult::Acked => return (index, PushOnceOutcome::Acked),
                    AttemptResult::Fatal(e) => return (index, PushOnceOutcome::Fatal(e)),
                    AttemptResult::Transient {
                        no_peer: np,
                        message,
                    } => {
                        no_peer &= np;
                        last_msg = message;
                    }
                }
            }
            drop(lanes);
            (
                index,
                PushOnceOutcome::Transient {
                    chunk,
                    attempt,
                    no_peer,
                    message: last_msg,
                },
            )
        })
    }

    /// Build the future that pushes one chunk with an **internal**
    /// bounded retry loop — the heal re-push path. Transient errors
    /// are retried up to `budget` attempts with jittered back-off,
    /// then the future returns `Err` so a background heal task can
    /// give up the round (the user can tap "Push again" to retry)
    /// rather than wedging forever.
    fn dispatch_push_bounded(
        &self,
        index: u64,
        chunk: SplitChunk,
        batch_id: [u8; 32],
        budget: u32,
    ) -> BoundedPushFuture {
        let cmd_tx = self.inner.cmd_tx.clone();
        Box::pin(async move {
            let mut attempt: u32 = 0;
            loop {
                match push_attempt(&cmd_tx, chunk.wire.clone(), batch_id).await {
                    AttemptResult::Acked => return (index, Ok(())),
                    AttemptResult::Fatal(e) => return (index, Err(e)),
                    AttemptResult::Transient { no_peer, message } => {
                        if attempt + 1 >= budget {
                            return (
                                index,
                                Err(UploadError::PushFailed(format!(
                                    "exhausted {budget} retries: {message}",
                                ))),
                            );
                        }
                        let delay = if no_peer {
                            NO_PEER_BACKOFF
                        } else {
                            backoff_for_retry(attempt)
                        };
                        tokio::time::sleep(with_jitter(delay)).await;
                        attempt = attempt.saturating_add(1);
                    }
                }
            }
        })
    }

    /// Post-upload self-heal. Reads `all_addrs` back from the network with
    /// the *deep* presence check (via [`ControlCommand::VerifyChunksPresent`]
    /// with [`HEAL_PROBES`]) and re-pushes what didn't land properly, in two
    /// phases gated by [`HealMode`]:
    ///
    /// 1. **Reachable mop-up** — up to [`MAX_HEAL_ROUNDS`] rounds re-pushing
    ///    only genuinely-unreachable chunks, to clear transient pushsync
    ///    stragglers. (`ShallowOnce` skips this.)
    /// 2. **Shallow promotion** — one deterministic round re-pushing
    ///    merely-shallow chunks too, so a file that loads but isn't deeply
    ///    placed becomes durable. Only `ReachableThenShallow` / `ShallowOnce`
    ///    run it; `ReachableOnly` stops after phase 1.
    ///
    /// A settle delay precedes every read-back.
    ///
    /// Verdict:
    /// * every chunk deep-reachable ⇒ flag the job `heal_verified` and
    ///   leave it `Completed`;
    /// * chunks still shallow/absent after all rounds + re-pushes ⇒
    ///   leave the job `Completed` but **not** `heal_verified` (a
    ///   "degraded" sub-state). We deliberately do **not** flip a
    ///   fully-pushed, already-retrievable upload to `Failed` just
    ///   because some chunks are still only *shallow*: the data is
    ///   reachable, and a false `Failed` on a retrievable file is worse
    ///   than leaving it degraded. There is no automatic retry — the user
    ///   can tap "Push again" to try again;
    /// * read-back inconclusive (peers not ready / transport error) ⇒
    ///   also leave it `Completed` but not `heal_verified` (again,
    ///   retried only on a manual "Push again").
    ///
    /// Re-pushes pull payloads from the local chunk store first (see
    /// [`repush_missing`](Self::repush_missing)), falling back to the
    /// source file, so heal works even when the source was deleted and
    /// repairs files uploaded before the deep-push fix when re-run at
    /// startup.
    #[allow(clippy::too_many_arguments)]
    async fn verify_and_heal(
        &self,
        job_id: &str,
        all_addrs: &[[u8; 32]],
        batch_id: [u8; 32],
        source_path: &Path,
        source_size: u64,
        raw: bool,
        name: Option<&str>,
        content_type: Option<&str>,
        // Decides how thorough the reachable mop-up is and whether shallow
        // placements are also promoted — see [`HealMode`]. The automatic
        // heals pick `ReachableOnly` / `ReachableThenShallow` by connectivity;
        // the manual "Push again" passes `ShallowOnce`.
        mode: HealMode,
        progress: HealProgress,
    ) {
        // Phase 1 — reachable-only mop-up. Re-push only genuinely-unreachable
        // chunks (`include_shallow = false`), re-measuring each round to catch
        // transient pushsync stragglers. Skipped entirely for `ShallowOnce`
        // (the manual single-pass repair). A clean reachable read-back means
        // "no unreachable chunks left" — for `ReachableOnly` that's the
        // verdict; for `ReachableThenShallow` it just gates entry to phase 2,
        // since reachable-but-shallow chunks aren't counted here.
        for round in 0..mode.mopup_rounds() {
            if self.heal_aborted(job_id) {
                return;
            }
            tokio::time::sleep(HEAL_SETTLE_DELAY).await;
            let Some(missing) = self
                .query_missing(job_id, all_addrs, HEAL_PROBES, false, &progress)
                .await
            else {
                if self.heal_aborted(job_id) {
                    return;
                }
                // Read-back couldn't run (peers not ready / transport
                // error). Do NOT claim the upload is healthy — just try
                // again next round after another settle delay.
                warn!(
                    target: "ant_node::uploads",
                    job_id, round, chunks = all_addrs.len(),
                    "post-upload heal: read-back inconclusive (peers not ready?); retrying",
                );
                continue;
            };
            if missing.is_empty() {
                if mode.promotes_shallow() {
                    // Reachability settled; chunks may still be shallow.
                    // Fall through to the shallow-promotion pass.
                    break;
                }
                info!(
                    target: "ant_node::uploads",
                    job_id, round, chunks = all_addrs.len(),
                    "post-upload heal: all chunks deep-reachable",
                );
                self.mark_heal_verified(job_id);
                return;
            }
            warn!(
                target: "ant_node::uploads",
                job_id, round, missing = missing.len(), total = all_addrs.len(),
                "post-upload heal: re-pushing unreachable chunks",
            );
            let missing_set: HashSet<[u8; 32]> = missing.into_iter().collect();
            if let Err(e) = self
                .repush_missing(
                    job_id,
                    &missing_set,
                    batch_id,
                    source_path,
                    source_size,
                    raw,
                    name,
                    content_type,
                    &progress,
                )
                .await
            {
                warn!(
                    target: "ant_node::uploads",
                    job_id, "post-upload heal re-push failed: {e}",
                );
                self.mark_heal_finished(job_id);
                return;
            }
        }
        // Phase 2 — shallow promotion (one deterministic round). Capture the
        // shallow set once, re-push it, and let the final read-back below
        // decide: re-measuring mid-round inflates it (the budget we just spent
        // saturates peers, and a saturated peer can't confirm a chunk). Only
        // `ReachableThenShallow` / `ShallowOnce` run this; `ReachableOnly`
        // skips straight to the reachable-set verdict.
        let include_shallow = mode.promotes_shallow();
        if include_shallow {
            if self.heal_aborted(job_id) {
                return;
            }
            tokio::time::sleep(HEAL_SETTLE_DELAY).await;
            if let Some(missing) = self
                .query_missing(job_id, all_addrs, HEAL_PROBES, true, &progress)
                .await
            {
                if !missing.is_empty() {
                    warn!(
                        target: "ant_node::uploads",
                        job_id, missing = missing.len(), total = all_addrs.len(),
                        "post-upload heal: re-pushing shallow placements",
                    );
                    let missing_set: HashSet<[u8; 32]> = missing.into_iter().collect();
                    if let Err(e) = self
                        .repush_missing(
                            job_id,
                            &missing_set,
                            batch_id,
                            source_path,
                            source_size,
                            raw,
                            name,
                            content_type,
                            &progress,
                        )
                        .await
                    {
                        warn!(
                            target: "ant_node::uploads",
                            job_id, "post-upload heal shallow re-push failed: {e}",
                        );
                        self.mark_heal_finished(job_id);
                        return;
                    }
                }
            }
        }
        // One final read-back after the last re-push decides the verdict. It
        // probes for the same depth the pass repaired: deep reachability when
        // shallow was promoted, plain reachability otherwise.
        if self.heal_aborted(job_id) {
            return;
        }
        tokio::time::sleep(HEAL_SETTLE_DELAY).await;
        let final_missing = self
            .query_missing(job_id, all_addrs, HEAL_PROBES, include_shallow, &progress)
            .await;
        // An abort mid-read-back surfaces as an inconclusive result;
        // don't let it masquerade as "heal ran its course" below.
        if self.heal_aborted(job_id) {
            return;
        }
        match final_missing {
            Some(missing) if missing.is_empty() => {
                info!(
                    target: "ant_node::uploads",
                    job_id, chunks = all_addrs.len(),
                    "post-upload heal: all chunks deep-reachable after re-push",
                );
                self.mark_heal_verified(job_id);
            }
            // Chunks are still shallow or absent after every re-push
            // round. The upload itself is `Completed` and the data is
            // retrievable (we pushed every chunk, and re-pushed the
            // shallow ones); it's just not *deeply* placed yet. Leave
            // the job `Completed` but un-`heal_verified` — never flip a
            // retrievable upload to `Failed`. There is no startup heal, so
            // this won't be retried automatically; the user can tap "Push
            // again" to try once more (its payloads live in the local
            // store, so the retry doesn't need the source).
            Some(missing) => {
                let n = missing.len();
                let total = all_addrs.len();
                warn!(
                    target: "ant_node::uploads",
                    job_id, missing = n, total, mode = mode.label(),
                    "post-upload heal: {n}/{total} chunks not deep-reachable after {} — leaving job completed (degraded); auto-retry scheduled",
                    mode.label(),
                );
                self.note_degraded(job_id, Some(n as u64));
            }
            None => {
                warn!(
                    target: "ant_node::uploads",
                    job_id, total = all_addrs.len(), mode = mode.label(),
                    "post-upload heal: final read-back inconclusive (peers not ready?) — leaving job completed; auto-retry scheduled",
                );
                self.note_degraded(job_id, None);
            }
        }
        // Heal has run its full course for this job. `mark_heal_verified`
        // already set this on the verified arms; this idempotent call
        // covers the degraded / inconclusive arms so a `--await-sync`
        // follower stops waiting instead of blocking forever.
        self.mark_heal_finished(job_id);
    }

    /// The `source_root/source_rel` re-anchor candidate for a job whose
    /// absolute source path went stale across a data-container move,
    /// guarded by a size **and mtime** match so a *different* file that
    /// happens to share the relative path can never be silently
    /// substituted (its chunk tree wouldn't match the persisted resume
    /// cursor / reference). `None` when the stored path still exists,
    /// no root/rel is configured, or the guard fails.
    fn rebase_candidate(&self, info: &UploadJobInfo) -> Option<PathBuf> {
        if info.source_path.exists() {
            return None;
        }
        let root = self.inner.source_root.as_ref()?;
        let rel = info.source_rel.as_ref()?;
        let candidate = root.join(rel);
        let md = std::fs::metadata(&candidate).ok()?;
        (md.len() == info.source_size && mtime_unix_ms(&md) == info.source_mtime_unix_ms)
            .then_some(candidate)
    }

    /// Resolve a job's source to a file that actually exists,
    /// re-anchoring app-managed imports across data-container moves.
    ///
    /// The iOS app stages picked files under the configured source root
    /// but the job manifest persists an *absolute* path that embeds the
    /// OS data-container id. When the OS reassigns that id (app update,
    /// reinstall, or device migration) the absolute path goes stale even
    /// though the bytes were carried into the new container — which is
    /// exactly what left old uploads unable to resume or self-heal.
    ///
    /// Order: the stored absolute path if it still exists; else the
    /// guarded `source_root/source_rel` candidate, which is **persisted**
    /// back into the job (rewrite + checkpoint) so every later open is
    /// direct; else the legacy `<data_dir>/imports/<basename>` fallback
    /// kept for jobs persisted before `source_rel` existed (no rewrite —
    /// its only guard is the size check every caller performs
    /// downstream); else the stored path, letting the caller surface the
    /// open error.
    fn resolve_job_source(&self, handle: &Arc<JobHandle>) -> PathBuf {
        let snap = handle.snapshot();
        if snap.source_path.exists() {
            return snap.source_path;
        }
        if let Some(candidate) = self.rebase_candidate(&snap) {
            let rebased = {
                let mut info = handle.info.lock().expect("upload mutex poisoned");
                info.source_path.clone_from(&candidate);
                info.last_update_unix = unix_seconds();
                info.clone()
            };
            info!(
                target: "ant_node::uploads",
                job_id = %rebased.job_id,
                to = %candidate.display(),
                "re-anchored upload source after data-container move",
            );
            let _ = handle.progress.send(rebased.clone());
            let _ = rebased.save(&UploadJobInfo::manifest_path(
                &self.inner.state_dir,
                &rebased.job_id,
            ));
            return candidate;
        }
        if let (Some(name), Some(data_dir)) =
            (snap.source_path.file_name(), self.inner.state_dir.parent())
        {
            let candidate = data_dir.join("imports").join(name);
            if candidate.exists() {
                return candidate;
            }
        }
        snap.source_path
    }

    /// Look up a registered job handle by id, if the manager still holds
    /// it (it does for the lifetime of the daemon once rehydrated/started).
    fn job_handle(&self, job_id: &str) -> Option<Arc<JobHandle>> {
        self.inner
            .jobs
            .lock()
            .expect("uploads jobs mutex poisoned")
            .get(job_id)
            .cloned()
    }

    /// Enumerate a completed job's full chunk address set (data leaves +
    /// intermediates + manifest) **without the source file**, by
    /// traversing its final `reference` through the persistent chunk
    /// store — the same store [`repush_missing`](Self::repush_missing)
    /// re-pushes payloads from, populated by the `PushChunk` handler on
    /// the way up. Store-only: a chunk missing from the store fails the
    /// traversal (`None`) rather than touching the network, and the
    /// caller falls back to marking the heal finished. Also `None` when
    /// no store is wired, the job has no reference, or the tree exceeds
    /// [`HEAL_MAX_CHUNKS`].
    async fn collect_heal_addrs_from_store(&self, job_id: &str) -> Option<Vec<[u8; 32]>> {
        let cache = self.inner.disk_cache.clone()?;
        let reference = self.job_handle(job_id)?.snapshot().reference?;
        let hexstr = reference.strip_prefix("0x").unwrap_or(&reference);
        let mut root = [0u8; 32];
        hex::decode_to_slice(hexstr, &mut root).ok()?;
        let fetcher = StoreFetcher(cache);
        match ant_retrieval::traverse_chunk_addresses(&fetcher, root, HEAL_MAX_CHUNKS * CHUNK_SIZE)
            .await
        {
            Ok(addrs) if addrs.len() <= HEAL_MAX_CHUNKS => {
                info!(
                    target: "ant_node::uploads",
                    job_id, chunks = addrs.len(),
                    "heal: enumerated chunk set from the local store (source file unavailable)",
                );
                Some(addrs)
            }
            Ok(_) => None,
            Err(e) => {
                warn!(
                    target: "ant_node::uploads",
                    job_id, "heal: store-only traversal failed: {e}",
                );
                None
            }
        }
    }

    /// Whether a securing pass for `job_id` should stop at its next
    /// opportunity — the manager is suspended, or the user cancelled the
    /// job. Pure check, no exit bookkeeping; dispatch loops use it to
    /// stop issuing new work while [`heal_aborted`](Self::heal_aborted)
    /// at the caller's next boundary performs the actual exit.
    fn heal_abort_pending(&self, job_id: &str) -> bool {
        self.inner.suspended.load(Ordering::SeqCst)
            || self
                .job_handle(job_id)
                .is_some_and(|h| h.cancel_requested.load(Ordering::SeqCst))
    }

    /// Check for an abort request and, when one is pending, perform the
    /// exit bookkeeping. Returns `true` when the securing pass must stop.
    ///
    /// * **Suspended** (system pause): stop quietly *without* marking
    ///   the heal finished, so `wake_all` / the next rehydrate re-queues
    ///   the pass; just clear the live progress so the UI doesn't show a
    ///   frozen bar.
    /// * **Cancelled** (user's "Stop securing"): clear the cancel flag —
    ///   a later "Push again" on this still-`Completed` job must work —
    ///   and mark the heal finished so the UI stops showing "Securing…".
    ///   (The `heal_inflight` marker is cleared by the `enqueue_heal`
    ///   wrapper as the pass exits, so a re-heal can be queued.)
    fn heal_aborted(&self, job_id: &str) -> bool {
        if self.inner.suspended.load(Ordering::SeqCst) {
            info!(
                target: "ant_node::uploads",
                job_id, "securing pass stopping: upload subsystem suspended",
            );
            self.clear_heal_progress(job_id);
            return true;
        }
        if let Some(handle) = self.job_handle(job_id) {
            if handle.cancel_requested.swap(false, Ordering::SeqCst) {
                info!(
                    target: "ant_node::uploads",
                    job_id, "securing pass stopping: cancelled by the user",
                );
                // Honour the stop beyond this pass: the degraded
                // auto-retry must not re-queue the job on the very next
                // wake. (One backoff interval, not forever — durability
                // is still pursued on later launches.)
                self.defer_degraded_retry(job_id, DEGRADED_HEAL_RETRY_INTERVAL);
                self.mark_heal_finished(job_id);
                return true;
            }
        }
        false
    }

    /// Clear the transient "Securing…" progress fields without touching
    /// `heal_finished` — the suspended-abort path, where the pass will
    /// be re-queued on wake and must still read as unsecured.
    fn clear_heal_progress(&self, job_id: &str) {
        let Some(handle) = self.job_handle(job_id) else {
            return;
        };
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            if info.heal_phase.is_none() && info.heal_checked.is_none() && info.heal_total.is_none()
            {
                return;
            }
            info.heal_phase = None;
            info.heal_checked = None;
            info.heal_total = None;
            info.clone()
        };
        let _ = handle.progress.send(snap);
    }

    /// Fold one live heal step into the job snapshot's transient
    /// `heal_phase` / `heal_checked` / `heal_total` fields and broadcast it
    /// to watchers — the app's determinate "Securing…" bar. Runtime-only:
    /// never saved to disk (the fields are `skip_serializing`), and the
    /// terminal `mark_heal_*` clear them when heal ends. A no-op for a job
    /// the manager no longer holds.
    fn set_heal_progress(
        &self,
        job_id: &str,
        phase: &str,
        checked: Option<u64>,
        total: Option<u64>,
    ) {
        let Some(handle) = self.job_handle(job_id) else {
            return;
        };
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            info.heal_phase = Some(phase.to_string());
            info.heal_checked = checked;
            info.heal_total = total;
            info.clone()
        };
        let _ = handle.progress.send(snap);
    }

    /// Report one heal progress step to *both* sinks: the optional live
    /// stream (`emit_heal`, the manual "Push again" bar) and the job
    /// snapshot (`set_heal_progress`, the automatic "Securing…" bar).
    /// Synchronous and in-order, so the terminal `mark_heal_*` clear always
    /// wins over a trailing progress line.
    fn report_heal(
        &self,
        job_id: &str,
        progress: &HealProgress,
        phase: &str,
        checked: Option<usize>,
        total: Option<usize>,
    ) {
        emit_heal(progress, phase, checked, total);
        self.set_heal_progress(
            job_id,
            phase,
            checked.map(|c| c as u64),
            total.map(|t| t as u64),
        );
    }

    /// Mark a job's chunks confirmed deep-reachable. Persists the flag and
    /// clears any live "Securing…" progress; leaves status untouched.
    fn mark_heal_verified(&self, job_id: &str) {
        let Some(handle) = self.job_handle(job_id) else {
            return;
        };
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            let progress_set = info.heal_phase.is_some()
                || info.heal_checked.is_some()
                || info.heal_total.is_some();
            if info.heal_verified && info.heal_finished && !progress_set {
                return;
            }
            info.heal_verified = true;
            // Verified implies the heal has run its course.
            info.heal_finished = true;
            info.heal_missing = None;
            info.heal_retry_unix = None;
            info.heal_phase = None;
            info.heal_checked = None;
            info.heal_total = None;
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        let _ = snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ));
    }

    /// Mark the post-upload heal as *finished* for `job_id` without
    /// claiming `heal_verified` — the degraded path where heal ran every
    /// round and re-pushed the shallow chunks but the final read-back was
    /// still inconclusive. Broadcasting this lets a durability-waiting
    /// follower (`antctl upload … --await-sync`, the app) stop waiting
    /// instead of blocking forever on a network that can't confirm deep
    /// placement right now (the user can retry with a manual "Push again").
    fn mark_heal_finished(&self, job_id: &str) {
        let Some(handle) = self.job_handle(job_id) else {
            return;
        };
        let snap = {
            let mut info = handle.info.lock().expect("upload mutex poisoned");
            let progress_set = info.heal_phase.is_some()
                || info.heal_checked.is_some()
                || info.heal_total.is_some();
            if info.heal_finished && !progress_set {
                return;
            }
            info.heal_finished = true;
            info.heal_phase = None;
            info.heal_checked = None;
            info.heal_total = None;
            info.last_update_unix = unix_seconds();
            info.clone()
        };
        let _ = handle.progress.send(snap.clone());
        let _ = snap.save(&UploadJobInfo::manifest_path(
            &self.inner.state_dir,
            &snap.job_id,
        ));
    }

    /// Ask the node loop which of `all_addrs` aren't retrievable from
    /// the network, batching the address list so each ack stays bounded.
    ///
    /// Returns `Some(missing)` only when **every** batch was actually
    /// verified against the network. Returns `None` when the read-back
    /// was inconclusive — a transport error, a `NotReady` (peers not yet
    /// handshaked), an unexpected ack, or an unparseable body. The
    /// distinction matters: an inconclusive read-back must **not** be
    /// mistaken for "nothing missing", or heal would silently declare an
    /// unretrievable upload healthy (the exact failure mode that made
    /// self-heal a no-op on a flaky/cold peer set). The caller retries
    /// the round instead of claiming success.
    /// Best-effort pre-upload capacity check. Looks up the postage
    /// batch this job stamps against and logs a clear warning when it's
    /// tight, so the operator/app can dilute (or buy a larger batch)
    /// *before* stamps start failing or evicting mid-upload. Two signals:
    ///
    /// * **A full collision bucket already exists** (`bucket_fill_max >=
    ///   bucket_capacity`). Any chunk routing into a full bucket will, on
    ///   an immutable batch, fail to stamp (and fail the upload), or on a
    ///   mutable batch, evict the oldest stamp in that bucket. Either way
    ///   the batch wants diluting.
    /// * **The upload likely exceeds the conservative headroom**
    ///   (`est_chunks > worst_case_remaining_chunks`). This is the
    ///   pessimistic "every chunk hashes into the fullest bucket" bound,
    ///   so it errs toward warning early.
    ///
    /// Never fails the job: a missing/erroring status, an unregistered
    /// batch, or a transport error just skips the warning.
    async fn capacity_preflight(&self, batch_id: &[u8; 32], est_chunks: u64) {
        let want = hex::encode(batch_id);
        let (ack_tx, ack_rx) = oneshot::channel::<ControlAck>();
        if self
            .inner
            .cmd_tx
            .send(ControlCommand::PostageList { ack: ack_tx })
            .await
            .is_err()
        {
            return;
        }
        let Ok(ControlAck::PostageList(views)) = ack_rx.await else {
            return;
        };
        let Some(view) = views.into_iter().find(|v| {
            v.batch_id
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(&want)
        }) else {
            return;
        };
        if !view.enabled {
            return;
        }

        if view.bucket_capacity > 0 && view.bucket_fill_max >= view.bucket_capacity {
            warn!(
                target: "ant_node::uploads",
                batch = %want,
                depth = view.batch_depth,
                immutable = view.immutable,
                fullest_bucket = view.bucket_fill_max,
                bucket_capacity = view.bucket_capacity,
                consequence = if view.immutable {
                    "chunks landing there will fail to stamp (this upload may fail)"
                } else {
                    "chunks landing there will evict the oldest stamp in that bucket"
                },
                "postage pre-flight: batch has at least one full collision bucket — dilute to a larger depth to be safe",
            );
        } else if est_chunks > view.worst_case_remaining_chunks {
            warn!(
                target: "ant_node::uploads",
                batch = %want,
                depth = view.batch_depth,
                est_chunks,
                worst_case_remaining = view.worst_case_remaining_chunks,
                issued = view.issued_chunks,
                capacity = view.total_capacity_chunks,
                "postage pre-flight: upload may exceed the batch's conservative headroom — if stamping starts failing, dilute to a larger depth",
            );
        }
    }

    async fn query_missing(
        &self,
        job_id: &str,
        all_addrs: &[[u8; 32]],
        probes: usize,
        include_shallow: bool,
        progress: &HealProgress,
    ) -> Option<Vec<[u8; 32]>> {
        let mut missing = Vec::new();
        // Determinate "checking" progress: count chunks as each read-back
        // batch is verified, so the "Securing…" bar advances across the
        // read-back (the bulk of heal time on a healthy file, which never
        // reaches the "repushing" phase).
        let total = all_addrs.len();
        let mut checked = 0usize;
        self.report_heal(job_id, progress, "checking", Some(0), Some(total));
        for batch in all_addrs.chunks(HEAL_VERIFY_BATCH) {
            // Abort (suspend / user cancel) surfaces as an inconclusive
            // read-back; the caller's next boundary check does the exit
            // bookkeeping.
            if self.heal_abort_pending(job_id) {
                return None;
            }
            let (ack_tx, ack_rx) = oneshot::channel::<ControlAck>();
            if self
                .inner
                .cmd_tx
                .send(ControlCommand::VerifyChunksPresent {
                    addresses: batch.to_vec(),
                    probes,
                    include_shallow,
                    ack: ack_tx,
                })
                .await
                .is_err()
            {
                return None;
            }
            match tokio::time::timeout(HEAL_VERIFY_TIMEOUT, ack_rx).await {
                Err(_) => {
                    warn!(
                        target: "ant_node::uploads",
                        job_id,
                        "heal read-back batch timed out after {}s — treating as inconclusive",
                        HEAL_VERIFY_TIMEOUT.as_secs(),
                    );
                    return None;
                }
                Ok(ack) => match ack {
                    Ok(ControlAck::Ok { message }) => match parse_missing(&message) {
                        Some(batch_missing) => missing.extend(batch_missing),
                        // A malformed body means we can't trust this batch —
                        // treat the whole read-back as inconclusive rather
                        // than assuming the batch was fully present.
                        None => return None,
                    },
                    // No peers yet, an error, or an unexpected ack — can't
                    // verify now, so the read-back is inconclusive.
                    _ => return None,
                },
            }
            checked += batch.len();
            self.report_heal(job_id, progress, "checking", Some(checked), Some(total));
        }
        Some(missing)
    }

    /// Re-push every chunk whose address is in `missing`, preferring the
    /// node's **local chunk store** over the source file (Fix 2).
    ///
    /// Pass 1 reads each missing chunk's wire bytes from
    /// [`DiskChunkCache`] — the `PushChunk` handler wrote them there on
    /// the way up, so a just-completed job's chunks are present even if
    /// the app already deleted the source file, and they survive a node
    /// restart (resume re-push from disk). Pass 2 is a last resort: for
    /// any chunk *not* found in the store (evicted, or
    /// `--no-disk-cache`), re-derive it by re-streaming the source file
    /// through the deterministic splitter — but only if the file is
    /// still there. A deleted source with a populated cache heals fine;
    /// a deleted source with a cache miss simply can't re-push *those*
    /// chunks this round (logged; the user can retry with "Push again")
    /// rather than failing the whole upload.
    ///
    /// Re-pushes use a bounded retry budget so a background heal task
    /// can't wedge forever on a dead network.
    #[allow(clippy::too_many_arguments)]
    async fn repush_missing(
        &self,
        job_id: &str,
        missing: &HashSet<[u8; 32]>,
        batch_id: [u8; 32],
        source_path: &Path,
        source_size: u64,
        raw: bool,
        name: Option<&str>,
        content_type: Option<&str>,
        progress: &HealProgress,
    ) -> Result<(), UploadError> {
        let mut in_flight: FuturesUnordered<BoundedPushFuture> = FuturesUnordered::new();
        // Addresses still needing a re-push after the disk-cache pass.
        // Anything left is re-derived from the source file in pass 2.
        let mut remaining: HashSet<[u8; 32]> = missing.clone();

        // Re-push progress: count each completed push against the missing
        // set so the app can draw a determinate bar. `note_done!` is
        // invoked at every drain point below.
        let total = missing.len();
        let mut pushed = 0usize;
        self.report_heal(job_id, progress, "repushing", Some(0), Some(total));
        macro_rules! note_done {
            () => {{
                pushed += 1;
                self.report_heal(job_id, progress, "repushing", Some(pushed), Some(total));
            }};
        }

        // --- Pass 1: re-push from the local chunk store. ---
        if let Some(cache) = self.inner.disk_cache.clone() {
            let addrs: Vec<[u8; 32]> = remaining.iter().copied().collect();
            for addr in addrs {
                // Stop dispatching on abort; in-flight pushes are simply
                // dropped (pushsync is idempotent). The caller's next
                // boundary check performs the exit bookkeeping.
                if self.heal_abort_pending(job_id) {
                    return Ok(());
                }
                match cache.get(addr).await {
                    Ok(Some(wire)) => {
                        if in_flight.len() >= MAX_PUSH_CONCURRENCY {
                            if let Some((_, res)) = in_flight.next().await {
                                res?;
                                note_done!();
                            }
                        }
                        in_flight.push(self.dispatch_push_bounded(
                            0,
                            SplitChunk {
                                address: addr,
                                wire,
                            },
                            batch_id,
                            PER_CHUNK_RETRY_BUDGET,
                        ));
                        remaining.remove(&addr);
                    }
                    // Not cached → fall through to the source-file pass.
                    Ok(None) => {}
                    Err(e) => {
                        warn!(
                            target: "ant_node::uploads",
                            addr = %hex::encode(addr),
                            "heal: local chunk-store read failed: {e}; will try source file",
                        );
                    }
                }
            }
        }

        // --- Pass 2: re-derive remaining chunks from the source file. ---
        if !remaining.is_empty() {
            match std::fs::File::open(source_path) {
                Ok(file) => {
                    let body: Option<Mmap> = if source_size == 0 {
                        None
                    } else {
                        // SAFETY: same contract as the upload path — the
                        // file is immutable for the duration; resume
                        // already refused on mtime change before here.
                        Some(unsafe { Mmap::map(&file)? })
                    };
                    let mut splitter = StreamingSplitter::new();
                    let leaf_iter = LeafIter::new(body.as_deref(), source_size);

                    // Dispatch `chunk` if still needed, holding the
                    // in-flight window at `MAX_PUSH_CONCURRENCY`.
                    macro_rules! maybe_push {
                        ($chunk:expr) => {{
                            let chunk = $chunk;
                            if self.heal_abort_pending(job_id) {
                                return Ok(());
                            }
                            if remaining.contains(&chunk.address) {
                                if in_flight.len() >= MAX_PUSH_CONCURRENCY {
                                    if let Some((_, res)) = in_flight.next().await {
                                        res?;
                                        note_done!();
                                    }
                                }
                                in_flight.push(self.dispatch_push_bounded(
                                    0,
                                    chunk,
                                    batch_id,
                                    PER_CHUNK_RETRY_BUDGET,
                                ));
                            }
                        }};
                    }

                    for leaf in leaf_iter {
                        for chunk in splitter.push_leaf(leaf) {
                            maybe_push!(chunk);
                        }
                    }
                    let (data_root, _bytes, tail) = splitter.finish();
                    for chunk in tail {
                        maybe_push!(chunk);
                    }
                    if !raw {
                        let filename = name.unwrap_or("blob.bin").to_string();
                        let manifest =
                            build_single_file_manifest(&filename, content_type, data_root)?;
                        for chunk in &manifest.chunks {
                            maybe_push!(chunk.clone());
                        }
                    }
                }
                Err(e) => {
                    // Source gone and the cache didn't cover every
                    // missing chunk. Don't fail the upload: the cache
                    // pass may have re-pushed most of them. Log the
                    // shortfall; the user can retry with "Push again".
                    warn!(
                        target: "ant_node::uploads",
                        remaining = remaining.len(),
                        "heal: {} chunk(s) absent from local store and source file unavailable ({e}); cannot re-push this round",
                        remaining.len(),
                    );
                }
            }
        }

        while let Some((_, res)) = in_flight.next().await {
            if self.heal_abort_pending(job_id) {
                return Ok(());
            }
            res?;
            note_done!();
        }
        Ok(())
    }
}

/// Store-only [`ant_retrieval::ChunkFetcher`] for enumerating a
/// completed upload's chunk addresses when the source file is gone:
/// reads exclusively from the persistent chunk store and errors on a
/// miss, so the traversal never touches the network (heal's read-back
/// is what talks to peers, not the enumeration).
struct StoreFetcher(Arc<ant_retrieval::DiskChunkCache>);

#[async_trait::async_trait]
impl ant_retrieval::ChunkFetcher for StoreFetcher {
    async fn fetch(
        &self,
        addr: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        match self.0.get(addr).await {
            Ok(Some(wire)) => Ok(wire),
            Ok(None) => Err(format!("chunk 0x{} not in local store", hex::encode(addr)).into()),
            Err(e) => Err(e.to_string().into()),
        }
    }
}

/// Record a chunk address for the heal pass, capping memory: once the
/// file crosses [`HEAL_MAX_CHUNKS`] we set `overflow`, drop what we've
/// collected, and stop — the caller then skips heal for this upload.
fn note_heal_addr(addrs: &mut Vec<[u8; 32]>, overflow: &mut bool, addr: [u8; 32]) {
    if *overflow {
        return;
    }
    if addrs.len() >= HEAL_MAX_CHUNKS {
        *overflow = true;
        addrs.clear();
        addrs.shrink_to_fit();
        return;
    }
    addrs.push(addr);
}

/// Re-derive the complete chunk address set (data leaves +
/// intermediates + manifest) for a finished upload by re-streaming its
/// source file through the deterministic splitter — the same traversal
/// `run_job` does, minus the pushes. Used by [`heal_completed_job`] (the
/// manual "Push again"), which doesn't have the in-memory `heal_addrs`
/// the upload run kept.
///
/// Returns `Ok(None)` when the file exceeds [`HEAL_MAX_CHUNKS`] (heal is
/// skipped for very large files, matching the post-upload path). The
/// source file must still exist, unchanged; the caller is expected to
/// have re-validated size/mtime before invoking.
fn collect_heal_addrs(
    source_path: &Path,
    source_size: u64,
    raw: bool,
    name: Option<&str>,
    content_type: Option<&str>,
) -> std::io::Result<Option<Vec<[u8; 32]>>> {
    let file = std::fs::File::open(source_path)?;
    let body: Option<Mmap> = if source_size == 0 {
        None
    } else {
        // SAFETY: same contract as the upload/repush paths — the file is
        // immutable for the duration; the caller re-validates mtime first.
        Some(unsafe { Mmap::map(&file)? })
    };

    let mut addrs: Vec<[u8; 32]> = Vec::new();
    let mut overflow = false;

    let mut splitter = StreamingSplitter::new();
    for leaf in LeafIter::new(body.as_deref(), source_size) {
        for chunk in splitter.push_leaf(leaf) {
            note_heal_addr(&mut addrs, &mut overflow, chunk.address);
        }
    }
    let (data_root, _bytes, tail) = splitter.finish();
    for chunk in tail {
        note_heal_addr(&mut addrs, &mut overflow, chunk.address);
    }
    if !raw {
        let filename = name.unwrap_or("blob.bin").to_string();
        let manifest = build_single_file_manifest(&filename, content_type, data_root)
            .map_err(std::io::Error::other)?;
        for chunk in &manifest.chunks {
            note_heal_addr(&mut addrs, &mut overflow, chunk.address);
        }
    }
    if overflow {
        return Ok(None);
    }
    Ok(Some(addrs))
}

/// Parse the `{"checked":N,"missing":["0x..",...]}` body of a
/// [`ControlCommand::VerifyChunksPresent`] ack into the missing chunk
/// addresses. Malformed entries are skipped; a wholly unparseable body
/// yields `None`.
fn parse_missing(message: &str) -> Option<Vec<[u8; 32]>> {
    #[derive(serde::Deserialize)]
    struct Resp {
        missing: Vec<String>,
    }
    let resp: Resp = serde_json::from_str(message).ok()?;
    let mut out = Vec::with_capacity(resp.missing.len());
    for s in resp.missing {
        let hexstr = s.strip_prefix("0x").unwrap_or(&s);
        let mut addr = [0u8; 32];
        if hex::decode_to_slice(hexstr, &mut addr).is_ok() {
            out.push(addr);
        }
    }
    Some(out)
}

/// Iterator over the source file in `CHUNK_SIZE`-byte windows. The
/// last window may be shorter; an empty source produces zero leaves
/// (the splitter's `finish` will emit the canonical empty leaf).
struct LeafIter<'a> {
    body: Option<&'a [u8]>,
    cursor: usize,
    total: usize,
    done: bool,
}

impl<'a> LeafIter<'a> {
    const fn new(body: Option<&'a [u8]>, total: u64) -> Self {
        Self {
            body,
            cursor: 0,
            total: total as usize,
            done: total == 0,
        }
    }

    const fn is_done(&self) -> bool {
        self.done
    }
}

impl<'a> Iterator for LeafIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let body = self.body?;
        let end = (self.cursor + CHUNK_SIZE).min(self.total);
        let leaf = &body[self.cursor..end];
        self.cursor = end;
        if self.cursor >= self.total {
            self.done = true;
        }
        Some(leaf)
    }
}

/// Tracks which chunk indices have been confirmed pushed. The
/// chunk-emit order is deterministic (a property of
/// [`StreamingSplitter`]) but completion order is not — the cursor
/// advances by the highest contiguous prefix of completed indices.
///
/// On resume the cursor starts at `resume_cursor`; the driver
/// re-derives indices `0..resume_cursor` from the splitter and
/// skips dispatching them, except the splitter tail and manifest
/// chunks, which are always re-pushed; their completions below the
/// cursor are ignored by [`AckLog::record`].
struct AckLog {
    resume_cursor: u64,
    cursor: u64,
    /// Sparse "have we seen this index yet" bitmap relative to
    /// `cursor`. Each bit covers one chunk; the bitmap collapses
    /// when the leading run of set bits advances `cursor`.
    pending: std::collections::BTreeSet<u64>,
}

impl AckLog {
    const fn new(resume_cursor: u64) -> Self {
        Self {
            resume_cursor,
            cursor: resume_cursor,
            pending: std::collections::BTreeSet::new(),
        }
    }

    fn record(&mut self, i: u64) {
        if i < self.cursor {
            return;
        }
        self.pending.insert(i);
        // Collapse the leading run.
        while let Some(&first) = self.pending.iter().next() {
            if first == self.cursor {
                self.pending.remove(&first);
                self.cursor += 1;
            } else {
                break;
            }
        }
    }

    const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Best-effort estimate of source bytes covered by the pushed
    /// prefix. Counts each chunk index ≤ `source_chunks` as
    /// `CHUNK_SIZE` bytes, capping at `source_size`. This is
    /// approximate (intermediates carry no source bytes themselves
    /// but advance the cursor) and is intended for the progress UI
    /// only.
    fn bytes_pushed(&self, source_size: u64) -> u64 {
        // For a depth-D tree, the first ceil(source_size /
        // CHUNK_SIZE) chunks emitted are leaves, but the streaming
        // splitter interleaves intermediates. As a UX-grade
        // estimator, cap at source_size — operators care about
        // "fraction of file uploaded", not chunk-tree pedantry.
        let approx = (self.cursor.saturating_sub(self.resume_cursor)) * CHUNK_SIZE as u64
            + (self.resume_cursor * CHUNK_SIZE as u64);
        approx.min(source_size)
    }
}

/// Estimate the chunk count for a file of `source_size` bytes.
///
/// Includes data leaves + every intermediate level, plus the
/// trailing single-file mantaray manifest root when `raw` is
/// `false` (the default). Used to prefill `chunks_total` so the
/// progress bar can show a percentage from chunk #1.
///
/// The estimate is slightly conservative: very small files
/// produce richer mantaray nodes that occasionally spill across
/// 2-3 chunks (extra metadata fork + value fork). The driver
/// always reports the true count via `chunks_pushed` once the
/// upload completes, so a slight under-count here only affects
/// the UX percentage during the last few hundred milliseconds of
/// the run.
#[must_use]
pub const fn estimate_chunk_count(source_size: u64, raw: bool) -> u64 {
    if source_size == 0 {
        // An empty raw upload still has a single (empty) data
        // leaf; an empty manifested upload has the leaf + a
        // manifest root.
        return if raw { 1 } else { 2 };
    }
    let leaves = source_size.div_ceil(CHUNK_SIZE as u64);
    let mut total: u64 = leaves;
    let mut level = leaves;
    while level > 1 {
        // A lone trailing reference is carried up unwrapped (bee's
        // hashtrie `Sum`, issue #234), so it adds no chunk.
        let next = level.div_ceil(ant_retrieval::BRANCHES as u64);
        total += if level % ant_retrieval::BRANCHES as u64 == 1 {
            next - 1
        } else {
            next
        };
        level = next;
    }
    if raw {
        total
    } else {
        // +1 single-file mantaray root.
        total + 1
    }
}

/// Wire-shape conversion: `UploadJobInfo` → `UploadJobView`. Used by
/// the command interceptor to turn a daemon-side snapshot into the
/// JSON shape `antctl` expects on the wire. Kept as a free function
/// so `ant-control` doesn't take a build-graph dependency on
/// `ant-node`.
#[must_use]
pub fn to_view(info: UploadJobInfo) -> UploadJobView {
    UploadJobView {
        job_id: info.job_id,
        source_path: info.source_path.display().to_string(),
        source_size: info.source_size,
        batch_id: info.batch_id,
        name: info.name,
        content_type: info.content_type,
        raw: info.raw,
        status: match info.status {
            UploadStatus::Pending => "pending".into(),
            UploadStatus::Running => "running".into(),
            UploadStatus::Paused => "paused".into(),
            UploadStatus::Completed => "completed".into(),
            UploadStatus::Cancelled => "cancelled".into(),
            UploadStatus::Failed => "failed".into(),
        },
        bytes_pushed: info.bytes_pushed,
        chunks_pushed: info.chunks_pushed,
        chunks_total: info.chunks_total,
        created_at_unix: info.created_at_unix,
        last_update_unix: info.last_update_unix,
        last_error: info.last_error,
        reference: info.reference,
        chunks_requeued: info.chunks_requeued,
        stalled: info.stalled,
        auto_paused: info.auto_paused,
        heal_verified: info.heal_verified,
        heal_finished: info.heal_finished,
        heal_missing: info.heal_missing,
        heal_retry_unix: info.heal_retry_unix,
        heal_attempts: info.heal_attempts,
        heal_last_check_unix: info.heal_last_check_unix,
        heal_phase: info.heal_phase,
        heal_checked: info.heal_checked,
        heal_total: info.heal_total,
    }
}

/// Drive a `ControlCommand::UploadFollow` connection to completion.
///
/// Subscribes to the job's progress watch, emits one
/// [`ControlAck::UploadProgress`] per state change, and finishes
/// with a terminal [`ControlAck::UploadJob`] (the final snapshot)
/// when the job reaches a terminal status. If the job vanishes
/// mid-stream (cancelled and removed from the table — not done
/// today, but defensively handled), emits an `Error` ack instead.
pub async fn run_follow(mgr: UploadManager, job_id: String, ack: mpsc::Sender<ControlAck>) {
    let mut rx = match mgr.subscribe(&job_id) {
        Ok(rx) => rx,
        Err(e) => {
            let _ = ack
                .send(ControlAck::Error {
                    message: e.to_string(),
                })
                .await;
            return;
        }
    };
    // Always ship the current snapshot first so a follower that
    // attaches mid-flight gets immediate state.
    let snap0 = rx.borrow().clone();
    let terminal = snap0.status.is_terminal();
    let frame = if terminal {
        ControlAck::UploadJob(to_view(snap0))
    } else {
        ControlAck::UploadProgress(to_view(snap0))
    };
    if ack.send(frame).await.is_err() {
        return;
    }
    if terminal {
        return;
    }
    while rx.changed().await.is_ok() {
        let snap = rx.borrow().clone();
        let terminal = snap.status.is_terminal();
        let frame = if terminal {
            ControlAck::UploadJob(to_view(snap))
        } else {
            ControlAck::UploadProgress(to_view(snap))
        };
        if ack.send(frame).await.is_err() {
            return;
        }
        if terminal {
            return;
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn mtime_unix_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64)
}

/// Pick the 32-byte postage batch id for a job: its own hex `batch_id`
/// (with or without `0x`) if present and well-formed, else the
/// manager's startup default, else all-zeros (which the node loop
/// rejects with "batch … not usable" so the operator gets a clear
/// error rather than a silent miss-stamp).
fn resolve_batch_id(job_batch: Option<&str>, default: Option<[u8; 32]>) -> [u8; 32] {
    if let Some(hex_id) = job_batch.map(str::trim).filter(|s| !s.is_empty()) {
        let stripped = hex_id
            .strip_prefix("0x")
            .or_else(|| hex_id.strip_prefix("0X"))
            .unwrap_or(hex_id);
        let mut out = [0u8; 32];
        if hex::decode_to_slice(stripped, &mut out).is_ok() {
            return out;
        }
    }
    default.unwrap_or([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_control::ControlCommand;
    use ant_crypto::cac_valid;
    use std::collections::HashSet;
    use std::io::Write as _;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// The raw estimate is exact: it equals the number of chunks the
    /// streaming splitter emits, including trees whose levels end in a
    /// lone reference that is carried up unwrapped (#234).
    #[test]
    fn raw_estimate_matches_streaming_splitter() {
        for len in [
            0usize,
            1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE * 128,
            CHUNK_SIZE * 128 + 1,
            CHUNK_SIZE * 129 + 1,
            CHUNK_SIZE * 257 + 1,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut splitter = StreamingSplitter::new();
            let mut n = 0u64;
            for leaf in payload.chunks(CHUNK_SIZE) {
                n += splitter.push_leaf(leaf).len() as u64;
            }
            n += splitter.finish().2.len() as u64;
            assert_eq!(estimate_chunk_count(len as u64, true), n, "len {len}");
        }
    }

    /// Counts of pushes a fake node loop has accepted.
    #[derive(Default)]
    struct PushStats {
        /// Distinct chunk addresses (deduped). Lower than
        /// `total_dispatches` for payloads with content that
        /// collides at chunk boundaries.
        unique_addresses: HashSet<[u8; 32]>,
        /// Every accepted `PushChunk`, including duplicates produced
        /// by content collisions.
        total_dispatches: u64,
    }

    /// Spawn a fake "node loop" that consumes `PushChunk` commands
    /// and acks them as if they were really pushed to a peer.
    /// Validates each chunk's CAC so a regression in the splitter
    /// trips the test.
    fn spawn_fake_pushsync() -> (mpsc::Sender<ControlCommand>, Arc<Mutex<PushStats>>) {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        let stats: Arc<Mutex<PushStats>> = Arc::new(Mutex::new(PushStats::default()));
        let stats_for_task = stats.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        // Recompute the address from the wire bytes
                        // (span ‖ payload) and accept only CAC-valid
                        // chunks — this is the same cross-check the
                        // real `PushChunk` handler does inline.
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        assert!(cac_valid(&addr, &wire), "invalid CAC chunk submitted");
                        {
                            let mut s = stats_for_task.lock().expect("pushed mutex");
                            s.unique_addresses.insert(addr);
                            s.total_dispatches += 1;
                        }
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent {
                        addresses,
                        probes: _,
                        include_shallow: _,
                        ack,
                    } => {
                        // The background heal pass fires after every
                        // completed upload. Report every pushed chunk as
                        // present (nothing missing) so heal no-ops and
                        // the exact dispatch-count assertions below hold.
                        let present = stats_for_task.lock().expect("stats");
                        let missing: Vec<String> = addresses
                            .iter()
                            .filter(|a| !present.unique_addresses.contains(*a))
                            .map(|a| format!("0x{}", hex::encode(a)))
                            .collect();
                        drop(present);
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": missing,
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PushSoc { ack, .. } => {
                        // Upload pipeline never emits PushSoc; surface a
                        // bug if it ever does.
                        let _ = ack.send(ControlAck::Error {
                            message: "PushSoc unexpected in upload tests".into(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        // The pre-upload capacity check lists batches; the
                        // fake loop has none, so report an empty set (no
                        // warning, no effect on dispatch-count assertions).
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in upload tests: {other:?}"),
                }
            }
        });
        (tx, stats)
    }

    fn write_temp_file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(bytes).expect("write");
        f.flush().expect("flush");
        f
    }

    /// A minimal completed-handshake report for status snapshots.
    fn fake_handshake() -> ant_control::HandshakeReport {
        ant_control::HandshakeReport {
            remote_overlay: String::new(),
            remote_peer_id: String::new(),
            agent_version: String::new(),
            full_node: true,
            at_unix: 0,
        }
    }

    /// Sketch B gate: the automatic post-upload heal only re-pushes shallow
    /// placements once the node is well-connected — a completed handshake
    /// AND at least `MIN_PEERS_FOR_AUTO_SHALLOW_HEAL` peers. No status wired,
    /// too few peers, or no handshake all keep it conservative (false).
    #[tokio::test]
    async fn neighbourhood_ready_gates_shallow_heal() {
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, _rx) = mpsc::channel::<ControlCommand>(8);

        // No status watch wired ⇒ conservative.
        let bare =
            UploadManager::new(state_dir.path().to_path_buf(), tx.clone(), None).expect("manager");
        assert!(!bare.neighbourhood_ready(), "no status ⇒ not ready");

        // Enough peers but no handshake yet ⇒ not ready.
        let mut snap = ant_control::StatusSnapshot::default();
        snap.peers.connected = MIN_PEERS_FOR_AUTO_SHALLOW_HEAL;
        let (status_tx, status_rx) = watch::channel(snap);
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None)
            .expect("manager")
            .with_status_watch(Some(status_rx));
        assert!(
            !mgr.neighbourhood_ready(),
            "peers but no handshake ⇒ not ready"
        );

        // Handshake done but a peer short ⇒ still not ready.
        let mut snap = ant_control::StatusSnapshot::default();
        snap.peers.connected = MIN_PEERS_FOR_AUTO_SHALLOW_HEAL - 1;
        snap.peers.last_handshake = Some(fake_handshake());
        status_tx.send(snap).expect("send");
        assert!(!mgr.neighbourhood_ready(), "one peer short ⇒ not ready");

        // Handshake done AND enough peers ⇒ ready.
        let mut snap = ant_control::StatusSnapshot::default();
        snap.peers.connected = MIN_PEERS_FOR_AUTO_SHALLOW_HEAL;
        snap.peers.last_handshake = Some(fake_handshake());
        status_tx.send(snap).expect("send");
        assert!(mgr.neighbourhood_ready(), "handshake + peers ⇒ ready");
    }

    /// State for the self-heal harness: which chunks are "present" on
    /// the fake network, how many times each was pushed, and the
    /// address we force to look missing on the first read-back.
    struct HealHarness {
        present: Mutex<HashSet<[u8; 32]>>,
        dispatches: Mutex<HashMap<[u8; 32], u32>>,
        forced_target: Mutex<Option<[u8; 32]>>,
        verify_calls: std::sync::atomic::AtomicUsize,
    }

    impl HealHarness {
        fn target(&self) -> Option<[u8; 32]> {
            *self.forced_target.lock().expect("target mutex")
        }
        fn dispatch_count(&self, addr: [u8; 32]) -> u32 {
            self.dispatches
                .lock()
                .expect("dispatch mutex")
                .get(&addr)
                .copied()
                .unwrap_or(0)
        }
    }

    /// Fake node loop that accepts `PushChunk` (recording every push and
    /// marking the chunk present) and answers `VerifyChunksPresent`. On
    /// the *first* read-back it forces the first queried address to look
    /// missing, simulating a chunk a storer dropped after acking — the
    /// upload's heal loop must then re-push exactly that chunk.
    fn spawn_fake_pushsync_with_heal() -> (mpsc::Sender<ControlCommand>, Arc<HealHarness>) {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        let h = Arc::new(HealHarness {
            present: Mutex::new(HashSet::new()),
            dispatches: Mutex::new(HashMap::new()),
            forced_target: Mutex::new(None),
            verify_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let hc = h.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        {
                            hc.present.lock().expect("present").insert(addr);
                            *hc.dispatches
                                .lock()
                                .expect("dispatch")
                                .entry(addr)
                                .or_insert(0) += 1;
                        }
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent {
                        addresses,
                        probes: _,
                        include_shallow: _,
                        ack,
                    } => {
                        let mut missing: Vec<String> = {
                            let present = hc.present.lock().expect("present");
                            addresses
                                .iter()
                                .filter(|a| !present.contains(*a))
                                .map(|a| format!("0x{}", hex::encode(a)))
                                .collect()
                        };
                        let n = hc.verify_calls.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            if let Some(first) = addresses.first().copied() {
                                *hc.forced_target.lock().expect("target") = Some(first);
                                let hexs = format!("0x{}", hex::encode(first));
                                if !missing.contains(&hexs) {
                                    missing.push(hexs);
                                }
                            }
                        }
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": missing,
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PushSoc { ack, .. } => {
                        let _ = ack.send(ControlAck::Error {
                            message: "PushSoc unexpected in heal test".into(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in heal test: {other:?}"),
                }
            }
        });
        (tx, h)
    }

    /// End-to-end happy path: a multi-MiB file ends in `Completed`
    /// with a non-empty manifest reference, and every chunk the
    /// driver dispatched matches a CAC-valid wire chunk.
    #[tokio::test]
    async fn upload_completes_multi_mib_file() {
        let len = 2_500_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 31) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, stats) = spawn_fake_pushsync();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, false)
            .expect("start");

        let mut rx = mgr.subscribe(&id).expect("subscribe");
        loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                assert_eq!(snap.status, UploadStatus::Completed);
                let r = snap.reference.expect("manifest reference");
                assert!(r.starts_with("0x"));
                assert_eq!(r.len(), 2 + 64);
                break;
            }
            // Wait for the next state change. `recv` errors when
            // the sender drops; that shouldn't happen mid-test.
            rx.changed().await.expect("watch");
        }
        // Sanity on dispatch count: leaves + ceil(leaves /
        // BRANCHES) intermediates + 1 root + 1 manifest. Every
        // dispatch is one PushChunk regardless of whether the
        // address turns out to be a duplicate of a previous push
        // (some payload patterns produce content collisions
        // between leaves; pushsync's idempotency makes that fine).
        let leaves = len.div_ceil(CHUNK_SIZE) as u64;
        let estimate = estimate_chunk_count(len as u64, false);
        let s = stats.lock().expect("stats");
        assert!(
            s.total_dispatches >= leaves,
            "expected ≥ {leaves} dispatches, got {}",
            s.total_dispatches,
        );
        // Estimate is "data + intermediates + 1 manifest"; real
        // manifests for single-file uploads sometimes spill across
        // 2-3 chunks (extra metadata fork + value fork). Accept up
        // to 4 manifest chunks of slack so a richer manifest
        // payload doesn't fail this guard.
        assert!(
            (estimate..=estimate + 4).contains(&s.total_dispatches),
            "dispatches {} not in estimate window {}..={}",
            s.total_dispatches,
            estimate,
            estimate + 4,
        );
    }

    /// After an upload reports `Completed`, the background self-heal
    /// loop reads every chunk back and re-pushes any that aren't
    /// reachable. The harness forces one chunk to look missing on the
    /// first read-back; the heal loop must then re-push exactly that
    /// chunk (dispatch count for it reaches 2).
    #[tokio::test]
    async fn upload_self_heals_unreachable_chunk() {
        // A few leaves + an intermediate so `all_addrs` is non-trivial.
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 13) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, harness) = spawn_fake_pushsync_with_heal();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, false)
            .expect("start");

        let mut rx = mgr.subscribe(&id).expect("subscribe");
        loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                assert_eq!(snap.status, UploadStatus::Completed);
                break;
            }
            rx.changed().await.expect("watch");
        }

        // The heal task runs in the background after Completed; poll for
        // the forced-missing chunk to be re-pushed (settle delay is a
        // few seconds, so allow generous slack).
        let mut healed = false;
        for _ in 0..80 {
            if let Some(t) = harness.target() {
                if harness.dispatch_count(t) >= 2 {
                    healed = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            healed,
            "self-heal should have re-pushed the chunk forced missing on first read-back",
        );
    }

    /// Harness for the shallow-promotion path. Every pushed chunk is
    /// "reachable" (so the reachable-only read-back, `include_shallow =
    /// false`, finds nothing missing), but the first address it ever sees is
    /// *shallow*: it shows as missing under `include_shallow = true` until it
    /// has been pushed twice (the original upload push plus the shallow
    /// promotion re-push). That lets a test prove `ReachableThenShallow`
    /// runs phase 2 and re-pushes the shallow chunk, where `ReachableOnly`
    /// would have left it alone.
    fn spawn_fake_pushsync_shallow() -> (mpsc::Sender<ControlCommand>, Arc<HealHarness>) {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        let h = Arc::new(HealHarness {
            present: Mutex::new(HashSet::new()),
            dispatches: Mutex::new(HashMap::new()),
            forced_target: Mutex::new(None),
            verify_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let hc = h.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        hc.present.lock().expect("present").insert(addr);
                        *hc.dispatches
                            .lock()
                            .expect("dispatch")
                            .entry(addr)
                            .or_insert(0) += 1;
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent {
                        addresses,
                        probes: _,
                        include_shallow,
                        ack,
                    } => {
                        let mut missing: Vec<String> = {
                            let present = hc.present.lock().expect("present");
                            addresses
                                .iter()
                                .filter(|a| !present.contains(*a))
                                .map(|a| format!("0x{}", hex::encode(a)))
                                .collect()
                        };
                        // Designate the first-ever queried address as shallow.
                        let target = {
                            let mut t = hc.forced_target.lock().expect("target");
                            if t.is_none() {
                                *t = addresses.first().copied();
                            }
                            *t
                        };
                        // Under the deep (shallow-aware) check it reads missing
                        // until the promotion round re-pushes it (push #2).
                        if include_shallow {
                            if let Some(tgt) = target {
                                let pushed = hc
                                    .dispatches
                                    .lock()
                                    .expect("dispatch")
                                    .get(&tgt)
                                    .copied()
                                    .unwrap_or(0);
                                if pushed < 2 {
                                    let hexs = format!("0x{}", hex::encode(tgt));
                                    if !missing.contains(&hexs) {
                                        missing.push(hexs);
                                    }
                                }
                            }
                        }
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": missing,
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PushSoc { ack, .. } => {
                        let _ = ack.send(ControlAck::Error {
                            message: "PushSoc unexpected in shallow heal test".into(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in shallow heal test: {other:?}"),
                }
            }
        });
        (tx, h)
    }

    /// On a well-connected node the automatic post-upload heal runs the
    /// shallow-promotion phase: a chunk that's reachable but only *shallow*
    /// is re-pushed and the job ends `heal_verified`. A constrained node
    /// (no ready status) would have stopped after the reachable-only mop-up
    /// and left it shallow — so the same harness must NOT re-push it then.
    #[tokio::test]
    async fn well_connected_heal_promotes_shallow_chunk() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 13) % 251) as u8).collect();

        // Well-connected: shallow chunk gets promoted (dispatched twice) and
        // the job ends heal_verified.
        {
            let f = write_temp_file(&payload);
            let state_dir = tempfile::tempdir().expect("tempdir");
            let (tx, harness) = spawn_fake_pushsync_shallow();
            let mut snap = ant_control::StatusSnapshot::default();
            snap.peers.connected = MIN_PEERS_FOR_AUTO_SHALLOW_HEAL;
            snap.peers.last_handshake = Some(fake_handshake());
            let (_status_tx, status_rx) = watch::channel(snap);
            let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None)
                .expect("manager")
                .with_status_watch(Some(status_rx));

            let id = mgr
                .start(f.path().to_path_buf(), None, None, None, false)
                .expect("start");
            let mut rx = mgr.subscribe(&id).expect("subscribe");
            loop {
                if rx.borrow().clone().status.is_terminal() {
                    break;
                }
                rx.changed().await.expect("watch");
            }

            let mut promoted = false;
            for _ in 0..80 {
                if let Some(t) = harness.target() {
                    if harness.dispatch_count(t) >= 2
                        && mgr.status(&id).expect("status").heal_verified
                    {
                        promoted = true;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            assert!(
                promoted,
                "well-connected heal should re-push the shallow chunk and mark heal_verified",
            );
        }

        // Constrained: no status wired ⇒ ReachableOnly ⇒ phase 2 never runs,
        // so the shallow chunk is pushed exactly once and the job stays
        // un-verified (degraded).
        {
            let f = write_temp_file(&payload);
            let state_dir = tempfile::tempdir().expect("tempdir");
            let (tx, harness) = spawn_fake_pushsync_shallow();
            let mgr =
                UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

            let id = mgr
                .start(f.path().to_path_buf(), None, None, None, false)
                .expect("start");
            let mut rx = mgr.subscribe(&id).expect("subscribe");
            loop {
                if rx.borrow().clone().status.is_terminal() {
                    break;
                }
                rx.changed().await.expect("watch");
            }

            // Let the reachable-only heal run to completion (it finishes fast:
            // the first reachable read-back finds nothing missing).
            let mut finished = false;
            for _ in 0..80 {
                if mgr.status(&id).expect("status").heal_finished {
                    finished = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            assert!(finished, "reachable-only heal should finish");
            let snap = mgr.status(&id).expect("status");
            // Reachable-only path verifies against the reachable read-back,
            // which finds nothing missing — so it (correctly) reports
            // heal_verified WITHOUT ever touching the shallow chunk.
            assert!(
                snap.heal_verified,
                "reachable-only heal verifies reachability"
            );
            if let Some(t) = harness.target() {
                assert_eq!(
                    harness.dispatch_count(t),
                    1,
                    "reachable-only heal must NOT re-push the shallow chunk",
                );
            }
        }
    }

    /// Fake node loop for the re-queue test: the first chunk address it
    /// ever sees is made "flaky" — its first `fail_until` pushes ack
    /// with a transient error, after which it (and every other chunk)
    /// acks success. `fail_until` is set well above the bounded retry
    /// budget so the test proves the upload path re-pushes **forever**
    /// (never fails) rather than giving up after a fixed count.
    struct RequeueHarness {
        target: Mutex<Option<[u8; 32]>>,
        target_attempts: std::sync::atomic::AtomicUsize,
        fail_until: usize,
    }

    fn spawn_fake_pushsync_flaky(fail_until: usize) -> mpsc::Sender<ControlCommand> {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        let h = Arc::new(RequeueHarness {
            target: Mutex::new(None),
            target_attempts: std::sync::atomic::AtomicUsize::new(0),
            fail_until,
        });
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        let is_target = {
                            let mut t = h.target.lock().expect("target");
                            if t.is_none() {
                                *t = Some(addr);
                            }
                            *t == Some(addr)
                        };
                        if is_target {
                            let n = h
                                .target_attempts
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if n < h.fail_until {
                                let _ = ack.send(ControlAck::Error {
                                    message: "connection reset by peer (transient)".into(),
                                });
                                continue;
                            }
                        }
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent { addresses, ack, .. } => {
                        // Report nothing missing so the background heal
                        // no-ops; this test only checks the upload path.
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": Vec::<String>::new(),
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in requeue test: {other:?}"),
                }
            }
        });
        tx
    }

    /// Fix 1: a chunk that fails its push far more times than the old
    /// fixed retry budget (8) must **not** fail the job. The upload
    /// path re-pushes it indefinitely; once it finally acks, the job
    /// reaches `Completed` with `chunks_pushed == total`, and the
    /// observability `chunks_requeued` counter reflects the retries.
    ///
    /// `start_paused` auto-advances tokio's clock so the back-off
    /// sleeps resolve in logical time — the test runs in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn upload_never_fails_on_exhausted_retries() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 29) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        // 12 failures > PER_CHUNK_RETRY_BUDGET (8): a fixed budget would
        // have failed the job here.
        let fail_until = 12usize;
        let tx = spawn_fake_pushsync_flaky(fail_until);
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, true)
            .expect("start");

        let mut rx = mgr.subscribe(&id).expect("subscribe");
        let final_snap = loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                break snap;
            }
            rx.changed().await.expect("watch");
        };
        assert_eq!(
            final_snap.status,
            UploadStatus::Completed,
            "job must complete despite a chunk failing {fail_until}× (last_error: {:?})",
            final_snap.last_error,
        );
        let total = estimate_chunk_count(len as u64, true);
        assert_eq!(
            final_snap.chunks_pushed, total,
            "every chunk must be acked once the flaky one recovers",
        );
        // `chunks_requeued` counts re-queues, not attempts: once the
        // splitter drains, each re-dispatch hedges TAIL_HEDGE_WIDTH
        // parallel attempts, so `fail_until` attempt-failures are
        // absorbed by ~fail_until / TAIL_HEDGE_WIDTH re-queues.
        let min_requeues = (fail_until as u64).div_ceil(TAIL_HEDGE_WIDTH as u64);
        assert!(
            final_snap.chunks_requeued >= min_requeues,
            "requeue counter should reflect ≥ {min_requeues} re-queues for {fail_until} failed attempts, got {}",
            final_snap.chunks_requeued,
        );
        assert!(
            !final_snap.stalled,
            "a recovered job must not report stalled"
        );
    }

    /// Harness for the tail-hedging test: the first chunk address it
    /// sees becomes the "straggler". Its first push fails transiently
    /// (so it enters the retry queue); every later push of it is
    /// *held* (the ack sender is parked, no reply) so the test can
    /// observe how many parallel pushsync lanes the driver opened for
    /// it. All other chunks ack instantly.
    struct HedgeHarness {
        target: Mutex<Option<[u8; 32]>>,
        held: Mutex<Vec<oneshot::Sender<ControlAck>>>,
        target_attempts: std::sync::atomic::AtomicUsize,
    }

    fn spawn_fake_pushsync_hedge() -> (mpsc::Sender<ControlCommand>, Arc<HedgeHarness>) {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        let h = Arc::new(HedgeHarness {
            target: Mutex::new(None),
            held: Mutex::new(Vec::new()),
            target_attempts: std::sync::atomic::AtomicUsize::new(0),
        });
        let hc = h.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        let is_target = {
                            let mut t = hc.target.lock().expect("target");
                            if t.is_none() {
                                *t = Some(addr);
                            }
                            *t == Some(addr)
                        };
                        if is_target {
                            let n = hc
                                .target_attempts
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if n == 0 {
                                // First attempt: transient failure → the
                                // chunk parks in the retry queue and its
                                // re-dispatch is hedged once the splitter
                                // is drained.
                                let _ = ack.send(ControlAck::Error {
                                    message: "connection reset by peer (transient)".into(),
                                });
                            } else {
                                // Hedged re-dispatch lanes: hold the ack so
                                // the test can count the parallel lanes
                                // before releasing one.
                                hc.held.lock().expect("held").push(ack);
                            }
                            continue;
                        }
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent { addresses, ack, .. } => {
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": Vec::<String>::new(),
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in hedge test: {other:?}"),
                }
            }
        });
        (tx, h)
    }

    /// Fix 2 (tail hedging): once the splitter is drained and a lone
    /// straggler is being retried, its re-dispatch must fan out to
    /// [`TAIL_HEDGE_WIDTH`] *concurrent* pushsync commands — the
    /// serial peer-walk tail observed on the 1 GiB stress run — and
    /// the first receipt completes the chunk.
    #[tokio::test(start_paused = true)]
    async fn tail_straggler_is_hedged_across_parallel_pushes() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 19) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, harness) = spawn_fake_pushsync_hedge();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, true)
            .expect("start");

        // Wait (in auto-advanced logical time) for the straggler's
        // re-dispatch to open all hedge lanes.
        let mut lanes = 0;
        for _ in 0..2_000 {
            lanes = harness.held.lock().expect("held").len();
            if lanes >= TAIL_HEDGE_WIDTH {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            lanes, TAIL_HEDGE_WIDTH,
            "tail straggler should race TAIL_HEDGE_WIDTH parallel pushes",
        );

        // Release one lane — the first receipt must win and the job
        // must complete (the other lanes' acks are simply dropped).
        let ack = harness.held.lock().expect("held").pop().expect("lane");
        let addr = harness.target.lock().expect("target").expect("target");
        let _ = ack.send(ControlAck::ChunkUploaded {
            reference: format!("0x{}", hex::encode(addr)),
        });

        let mut rx = mgr.subscribe(&id).expect("subscribe");
        let final_snap = loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                break snap;
            }
            rx.changed().await.expect("watch");
        };
        assert_eq!(final_snap.status, UploadStatus::Completed);
        assert_eq!(
            final_snap.chunks_pushed,
            estimate_chunk_count(len as u64, true),
        );
    }

    /// Fix 4 (jitter): the retry back-off must stay inside the
    /// documented ±25 % band and actually vary between calls, so a
    /// reset storm that re-queues a whole window of chunks at once
    /// doesn't wake them all in the same instant.
    #[test]
    fn jitter_stays_within_band_and_varies() {
        let base = Duration::from_secs(4);
        let mut distinct = HashSet::new();
        for _ in 0..200 {
            let j = with_jitter(base);
            assert!(
                j >= base * 750 / 1000 && j <= base * 1250 / 1000,
                "jitter {j:?} outside ±25% of {base:?}",
            );
            distinct.insert(j.as_nanos());
        }
        assert!(distinct.len() > 1, "jitter should vary across calls");
    }

    /// Fake node loop that mirrors the real `PushChunk` handler's
    /// store-then-push behaviour: every pushed chunk is written into the
    /// supplied [`DiskChunkCache`] before acking. On the first read-back
    /// it forces the first queried address to look missing, so heal must
    /// re-push it — and, crucially, must re-push it **from the cache**
    /// (the test deletes the source file), proving Fix 2.
    fn spawn_fake_pushsync_with_cache(
        cache: Arc<ant_retrieval::DiskChunkCache>,
    ) -> (mpsc::Sender<ControlCommand>, Arc<HealHarness>) {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        let h = Arc::new(HealHarness {
            present: Mutex::new(HashSet::new()),
            dispatches: Mutex::new(HashMap::new()),
            forced_target: Mutex::new(None),
            verify_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let hc = h.clone();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        // Store-then-push, like the real node loop.
                        let _ = cache.put(addr, wire.clone()).await;
                        {
                            hc.present.lock().expect("present").insert(addr);
                            *hc.dispatches
                                .lock()
                                .expect("dispatch")
                                .entry(addr)
                                .or_insert(0) += 1;
                        }
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent { addresses, ack, .. } => {
                        let mut missing: Vec<String> = {
                            let present = hc.present.lock().expect("present");
                            addresses
                                .iter()
                                .filter(|a| !present.contains(*a))
                                .map(|a| format!("0x{}", hex::encode(a)))
                                .collect()
                        };
                        let n = hc.verify_calls.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            if let Some(first) = addresses.first().copied() {
                                *hc.forced_target.lock().expect("target") = Some(first);
                                let hexs = format!("0x{}", hex::encode(first));
                                if !missing.contains(&hexs) {
                                    missing.push(hexs);
                                }
                            }
                        }
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": missing,
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in cache-heal test: {other:?}"),
                }
            }
        });
        (tx, h)
    }

    /// Fix 2: heal re-pushes a missing chunk from the local chunk store
    /// even after the source file is deleted. We upload with a real
    /// `DiskChunkCache` wired in, `rm` the source the moment the job
    /// completes, then force one chunk missing on the first read-back.
    /// Heal must re-push it (dispatch count → 2) by reading its wire
    /// bytes from the cache — no `No such file or directory`.
    #[tokio::test]
    async fn heal_repushes_from_cache_after_source_deleted() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 23) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let source = f.path().to_path_buf();
        let state_dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = tempfile::tempdir().expect("cachedir");
        let cache = Arc::new(
            ant_retrieval::DiskChunkCache::open(cache_dir.path().join("c.sqlite"), 1 << 30)
                .expect("cache"),
        );
        let (tx, harness) = spawn_fake_pushsync_with_cache(cache.clone());
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None)
            .expect("manager")
            .with_disk_cache(Some(cache));

        let id = mgr
            .start(source.clone(), None, None, None, false)
            .expect("start");

        let mut rx = mgr.subscribe(&id).expect("subscribe");
        loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                assert_eq!(snap.status, UploadStatus::Completed);
                break;
            }
            rx.changed().await.expect("watch");
        }

        // Delete the source the moment the upload completes — heal must
        // not depend on it.
        drop(f);
        std::fs::remove_file(&source).ok();
        assert!(!source.exists(), "source should be gone before heal runs");

        let mut healed = false;
        for _ in 0..80 {
            if let Some(t) = harness.target() {
                if harness.dispatch_count(t) >= 2 {
                    healed = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            healed,
            "heal should have re-pushed the forced-missing chunk from the local cache despite the deleted source",
        );
    }

    /// `raw = true` skips the trailing single-file mantaray
    /// manifest. The completed job's `reference` is the data root
    /// chunk address (deterministic from the splitter), and the
    /// total dispatch count matches the no-manifest estimate.
    #[tokio::test]
    async fn raw_upload_skips_manifest() {
        // Chosen to span multiple leaves + an intermediate so the
        // splitter exercises the full tree code path, not just a
        // single-chunk file.
        let len = 600_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 7) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, stats) = spawn_fake_pushsync();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, true)
            .expect("start");

        let mut rx = mgr.subscribe(&id).expect("subscribe");
        let final_snap = loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                break snap;
            }
            rx.changed().await.expect("watch");
        };
        assert_eq!(final_snap.status, UploadStatus::Completed);
        assert!(final_snap.raw, "info.raw should round-trip through finish");
        let r = final_snap
            .reference
            .as_deref()
            .expect("data-root reference");
        assert!(r.starts_with("0x"));
        assert_eq!(r.len(), 2 + 64);

        // Independently re-derive the data root via the same
        // streaming splitter and assert the raw upload's reference
        // matches it byte-for-byte. Catches accidental "we still
        // returned the manifest root" regressions.
        let mut splitter = StreamingSplitter::new();
        let mut idx = 0usize;
        while idx < payload.len() {
            let end = (idx + CHUNK_SIZE).min(payload.len());
            let _ = splitter.push_leaf(&payload[idx..end]);
            idx = end;
        }
        let (data_root, _bytes, _tail) = splitter.finish();
        assert_eq!(r, format!("0x{}", hex::encode(data_root)));

        // Dispatch count should match the no-manifest estimate
        // exactly — there is no extra metadata fork to spill into
        // 2-3 chunks here.
        let estimate = estimate_chunk_count(len as u64, true);
        let s = stats.lock().expect("stats");
        assert_eq!(
            s.total_dispatches, estimate,
            "raw upload pushed {} chunks; expected {}",
            s.total_dispatches, estimate,
        );
    }

    /// Resume math: pre-seed an on-disk manifest with
    /// `chunks_pushed = N`, call `rehydrate`, and check the driver
    /// emits exactly `total - N` push commands. Proves the
    /// skip-first-N optimisation is wired and that re-pushing
    /// already-acknowledged chunks doesn't happen.
    #[tokio::test]
    async fn resume_skips_already_pushed_chunks() {
        let len = 250_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 17) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");

        // First pass: complete the upload normally.
        let (tx1, stats1) = spawn_fake_pushsync();
        let mgr1 = UploadManager::new(state_dir.path().to_path_buf(), tx1, None).expect("manager");
        let id = mgr1
            .start(f.path().to_path_buf(), None, None, None, false)
            .expect("start");
        let mut rx = mgr1.subscribe(&id).expect("subscribe");
        let final_snap = loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                break snap;
            }
            rx.changed().await.expect("watch");
        };
        let total_chunks = final_snap.chunks_pushed;
        let pushed1_count = stats1.lock().expect("stats").total_dispatches;
        assert!(pushed1_count > 0);
        // Drop the manager to release the watch sender, simulating
        // a daemon shutdown after a successful upload.
        drop(mgr1);

        // Manually rewind the on-disk manifest to mid-flight: cut
        // chunks_pushed in half, status back to Running. This is
        // the "we crashed mid-push" scenario.
        let manifest_path = state_dir.path().join(format!("{id}.json"));
        let mut info = UploadJobInfo::load(&manifest_path).expect("load");
        info.chunks_pushed = total_chunks / 2;
        info.status = UploadStatus::Running;
        info.reference = None;
        info.save(&manifest_path).expect("save rewound");

        // Second pass: rehydrate, auto-resume, expect to push
        // exactly `total_chunks - chunks_pushed` further commands.
        let (tx2, stats2) = spawn_fake_pushsync();
        let mgr2 = UploadManager::new(state_dir.path().to_path_buf(), tx2, None).expect("manager");
        let restored = mgr2.rehydrate_from_disk(true).expect("rehydrate");
        assert_eq!(restored, 1);

        let mut rx2 = mgr2.subscribe(&id).expect("subscribe");
        loop {
            let snap = rx2.borrow().clone();
            if snap.status.is_terminal() {
                assert_eq!(snap.status, UploadStatus::Completed);
                break;
            }
            rx2.changed().await.expect("watch");
        }
        let pushed2_count = stats2.lock().expect("stats").total_dispatches;
        assert_eq!(
            pushed2_count,
            total_chunks - (total_chunks / 2),
            "resume should push exactly the chunks past the cursor",
        );
    }

    /// A resume whose cursor already reaches past the splitter tail
    /// (a job that failed or was killed while pushing its tail or
    /// manifest under a build whose tail had a different shape, e.g.
    /// the 1-child wrapper #234 removed) still pushes the data root
    /// and the manifest, instead of skipping them by index.
    #[tokio::test]
    async fn resume_always_pushes_tail_and_manifest() {
        // 129 leaves, the last one 1 byte: a lone trailing leaf.
        let len = CHUNK_SIZE * 128 + 1;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 13) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");

        let (tx1, _stats1) = spawn_fake_pushsync();
        let mgr1 = UploadManager::new(state_dir.path().to_path_buf(), tx1, None).expect("manager");
        let id = mgr1
            .start(f.path().to_path_buf(), None, None, None, false)
            .expect("start");
        let mut rx = mgr1.subscribe(&id).expect("subscribe");
        let final_snap = loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                break snap;
            }
            rx.changed().await.expect("watch");
        };
        let total_chunks = final_snap.chunks_pushed;
        let reference = final_snap.reference.clone().expect("reference");
        drop(mgr1);

        // An older tail had one more chunk, so its cursor can sit
        // past every index this build assigns to the tail.
        let manifest_path = state_dir.path().join(format!("{id}.json"));
        let mut info = UploadJobInfo::load(&manifest_path).expect("load");
        info.chunks_pushed = total_chunks;
        info.status = UploadStatus::Running;
        info.reference = None;
        info.save(&manifest_path).expect("save rewound");

        let (tx2, stats2) = spawn_fake_pushsync();
        let mgr2 = UploadManager::new(state_dir.path().to_path_buf(), tx2, None).expect("manager");
        assert_eq!(mgr2.rehydrate_from_disk(true).expect("rehydrate"), 1);
        let mut rx2 = mgr2.subscribe(&id).expect("subscribe");
        let snap = loop {
            let snap = rx2.borrow().clone();
            if snap.status.is_terminal() {
                break snap;
            }
            rx2.changed().await.expect("watch");
        };
        assert_eq!(snap.status, UploadStatus::Completed);
        assert_eq!(snap.reference.as_deref(), Some(reference.as_str()));

        let mut splitter = StreamingSplitter::new();
        for leaf in payload.chunks(CHUNK_SIZE) {
            let _ = splitter.push_leaf(leaf);
        }
        let (data_root, _, tail) = splitter.finish();
        let s = stats2.lock().expect("stats");
        assert!(
            s.unique_addresses.contains(&data_root),
            "resumed run must push the data root",
        );
        let manifest_root = hex::decode(reference.trim_start_matches("0x")).expect("hex");
        assert!(
            s.unique_addresses
                .iter()
                .any(|a| a[..] == manifest_root[..]),
            "resumed run must push the manifest root",
        );
        assert!(
            s.total_dispatches > tail.len() as u64,
            "tail + manifest re-pushed, got {}",
            s.total_dispatches,
        );
    }

    /// Back-off curve sanity. Locks in the documented step
    /// sequence so future tuning can't silently regress to the
    /// pre-cutover 100 ms × 2^n curve that was retrying inside the
    /// receipt-batching window. See `backoff_for_retry` for the
    /// rationale.
    #[test]
    fn backoff_curve_matches_documented_steps() {
        let steps: Vec<u64> = (0..PER_CHUNK_RETRY_BUDGET)
            .map(|a| backoff_for_retry(a).as_millis() as u64)
            .collect();
        assert_eq!(steps, vec![250, 500, 1000, 2000, 4000, 4000, 4000, 4000]);
        let total: u64 = steps.iter().sum();
        // Total budget across all retries: ~20 s. Comfortably
        // inside the 120 s outer PUSH_TIMEOUT wall, leaves room
        // for the 45 s single-attempt pushsync envelope.
        assert!((15_000..=25_000).contains(&total), "total={total}");
    }

    /// `cancel` flips status and stops the driver. Already-pushed
    /// chunks stay in `pushed`; we just check the job ends in
    /// `Cancelled`.
    #[tokio::test]
    async fn cancel_stops_running_job() {
        let len = 8 * 1024 * 1024usize;
        let payload: Vec<u8> = vec![0xAB; len];
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, _stats) = spawn_fake_pushsync();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, false)
            .expect("start");

        // Give the driver a moment to dispatch a few chunks, then
        // cancel.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snap = mgr.cancel(&id).expect("cancel");
        assert_eq!(snap.status, UploadStatus::Cancelled);

        // Re-read from disk to confirm the cancel was persisted.
        let manifest_path = state_dir.path().join(format!("{id}.json"));
        let on_disk = UploadJobInfo::load(&manifest_path).expect("load");
        assert_eq!(on_disk.status, UploadStatus::Cancelled);
    }

    /// A source-file mtime change after the job was started causes
    /// resume to refuse and mark the job `Failed`. Important
    /// safety property: silently re-uploading mismatched bytes
    /// would produce a manifest that doesn't match what the user
    /// thinks they uploaded.
    #[tokio::test]
    async fn resume_refuses_on_mtime_change() {
        let len = 8000usize;
        let payload: Vec<u8> = vec![0x42; len];
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");

        // Pre-stage a manifest that points at the file but with an
        // older mtime than the actual file.
        let job_id = "0123456789abcdef".to_string();
        let info = UploadJobInfo {
            job_id: job_id.clone(),
            source_path: f.path().to_path_buf(),
            source_rel: None,
            source_size: len as u64,
            // Older than the file's true mtime.
            source_mtime_unix_ms: 1,
            batch_id: None,
            name: Some("blob.bin".into()),
            content_type: None,
            raw: false,
            status: UploadStatus::Running,
            bytes_pushed: 0,
            chunks_pushed: 0,
            chunks_total: Some(estimate_chunk_count(len as u64, false)),
            created_at_unix: 0,
            last_update_unix: 0,
            last_error: None,
            reference: None,
            heal_verified: false,
            heal_finished: false,
            heal_missing: None,
            heal_retry_unix: None,
            heal_attempts: 0,
            heal_last_check_unix: None,
            heal_phase: None,
            heal_checked: None,
            heal_total: None,
            chunks_requeued: 0,
            stalled: false,
            auto_paused: false,
        };
        info.save(&UploadJobInfo::manifest_path(state_dir.path(), &job_id))
            .expect("save");

        let (tx, _stats) = spawn_fake_pushsync();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");
        mgr.rehydrate_from_disk(true).expect("rehydrate");

        let mut rx = mgr.subscribe(&job_id).expect("subscribe");
        loop {
            let snap = rx.borrow().clone();
            if snap.status.is_terminal() {
                assert_eq!(snap.status, UploadStatus::Failed);
                let err = snap.last_error.expect("last_error set");
                assert!(
                    err.contains("modified") || err.contains("mtime"),
                    "expected mtime-mismatch message, got: {err}",
                );
                break;
            }
            rx.changed().await.expect("watch");
        }
    }

    /// Fake node loop whose `PushChunk` acks are delayed, so a
    /// several-dozen-chunk upload reliably stays `Running` long enough
    /// for the suspend / container-move tests to interrupt it
    /// mid-flight. Acks are processed serially (one command at a time),
    /// which is exactly what stretches the run. Heal read-backs report
    /// everything present so post-completion securing no-ops.
    fn spawn_fake_pushsync_delayed(delay: Duration) -> mpsc::Sender<ControlCommand> {
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        tokio::time::sleep(delay).await;
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent { addresses, ack, .. } => {
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": Vec::<String>::new(),
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected control command in delayed-push test: {other:?}"),
                }
            }
        });
        tx
    }

    /// Poll a job until `pred` holds, panicking after ~20 s.
    async fn wait_for(
        mgr: &UploadManager,
        id: &str,
        what: &str,
        pred: impl Fn(&UploadJobInfo) -> bool,
    ) -> UploadJobInfo {
        for _ in 0..80 {
            let snap = mgr.status(id).expect("status");
            if pred(&snap) {
                return snap;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// `suspend_all` pauses running jobs with the `auto_paused` marker
    /// and `wake_all` resumes exactly those — a job the *user* paused
    /// stays paused across the suspend/wake cycle.
    #[tokio::test]
    async fn suspend_wake_resumes_auto_paused_but_not_user_paused() {
        let len = 250_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 11) % 251) as u8).collect();
        let f_user = write_temp_file(&payload);
        let f_auto = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let tx = spawn_fake_pushsync_delayed(Duration::from_millis(5));
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let user_id = mgr
            .start(f_user.path().to_path_buf(), None, None, None, true)
            .expect("start user job");
        wait_for(&mgr, &user_id, "user job running", |s| {
            s.status == UploadStatus::Running
        })
        .await;
        mgr.pause(&user_id).expect("user pause");

        let auto_id = mgr
            .start(f_auto.path().to_path_buf(), None, None, None, true)
            .expect("start auto job");
        wait_for(&mgr, &auto_id, "auto job running", |s| {
            s.status == UploadStatus::Running
        })
        .await;

        let suspended = mgr.suspend_all().await;
        assert_eq!(suspended, 1, "only the running job is suspended");
        let user_snap = mgr.status(&user_id).expect("status");
        assert_eq!(user_snap.status, UploadStatus::Paused);
        assert!(!user_snap.auto_paused, "user pause must stay a user pause");
        let auto_snap = mgr.status(&auto_id).expect("status");
        assert_eq!(auto_snap.status, UploadStatus::Paused);
        assert!(auto_snap.auto_paused, "system pause carries the marker");
        // The marker must be persisted — a relaunch decides restart vs
        // stay-paused from the on-disk manifest.
        let on_disk =
            UploadJobInfo::load(&UploadJobInfo::manifest_path(state_dir.path(), &auto_id))
                .expect("load");
        assert!(on_disk.auto_paused && on_disk.status == UploadStatus::Paused);

        let woken = mgr.wake_all();
        assert_eq!(woken, 1, "only the auto-paused job wakes");
        let done = wait_for(&mgr, &auto_id, "auto job completion", |s| {
            s.status.is_terminal()
        })
        .await;
        assert_eq!(done.status, UploadStatus::Completed);
        assert!(!done.auto_paused, "resume clears the marker");
        let user_snap = mgr.status(&user_id).expect("status");
        assert_eq!(
            user_snap.status,
            UploadStatus::Paused,
            "user-paused job must still be paused after wake",
        );
    }

    /// The container-move simulation (the iOS quirk end-to-end): an
    /// upload started under `source_root` is suspended mid-flight, the
    /// whole container directory is renamed (what iOS does to the app
    /// container on update), and a fresh manager rehydrates with the
    /// *new* root. The job must rebase its source path, auto-resume from
    /// the persisted cursor, and complete.
    #[tokio::test]
    async fn container_move_rebases_resumes_and_completes() {
        let len = 250_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 37) % 251) as u8).collect();
        let root = tempfile::tempdir().expect("tempdir");
        let container_a = root.path().join("container-A");
        let imports_a = container_a.join("imports");
        std::fs::create_dir_all(&imports_a).expect("mkdir imports");
        let source_a = imports_a.join("blob.bin");
        std::fs::write(&source_a, &payload).expect("write source");
        let state_dir = tempfile::tempdir().expect("state dir");

        // Phase 1: upload under root A, suspend mid-flight.
        let tx1 = spawn_fake_pushsync_delayed(Duration::from_millis(5));
        let mgr1 = UploadManager::new(state_dir.path().to_path_buf(), tx1, None)
            .expect("manager")
            .with_source_root(Some(imports_a.clone()));
        let id = mgr1
            .start(source_a.clone(), None, None, None, false)
            .expect("start");
        wait_for(&mgr1, &id, "job running", |s| {
            s.status == UploadStatus::Running
        })
        .await;
        mgr1.suspend_all().await;
        let snap = mgr1.status(&id).expect("status");
        assert_eq!(snap.status, UploadStatus::Paused);
        assert!(snap.auto_paused);
        assert!(
            snap.chunks_pushed < estimate_chunk_count(len as u64, false),
            "suspend must land mid-upload for the resume leg to mean anything",
        );
        assert_eq!(snap.source_rel.as_deref(), Some(Path::new("blob.bin")));
        drop(mgr1);

        // Phase 2: the OS moves the container.
        let container_b = root.path().join("container-B");
        std::fs::rename(&container_a, &container_b).expect("rename container");
        let imports_b = container_b.join("imports");

        // Phase 3: relaunch against the new root; the job must rebase,
        // resume from the cursor, and complete.
        let (tx2, stats2) = spawn_fake_pushsync();
        let mgr2 = UploadManager::new(state_dir.path().to_path_buf(), tx2, None)
            .expect("manager")
            .with_source_root(Some(imports_b.clone()));
        mgr2.rehydrate_from_disk(true).expect("rehydrate");

        let done = wait_for(&mgr2, &id, "completion after move", |s| {
            s.status.is_terminal()
        })
        .await;
        assert_eq!(
            done.status,
            UploadStatus::Completed,
            "job must complete after the container move (last_error: {:?})",
            done.last_error,
        );
        assert!(
            done.source_path.starts_with(&imports_b),
            "source path must be re-anchored under the new container, got {}",
            done.source_path.display(),
        );
        assert!(done.reference.is_some());
        // The second run resumed from the persisted cursor instead of
        // re-pushing the whole file.
        let resumed_pushes = stats2.lock().expect("stats").total_dispatches;
        assert!(
            resumed_pushes < estimate_chunk_count(len as u64, false),
            "resume should skip already-pushed chunks (pushed {resumed_pushes})",
        );
    }

    /// The rebase guard: a candidate at `source_root/source_rel` whose
    /// mtime doesn't match the recorded one must NOT be substituted (it
    /// could be a different file with the same name), so the job fails
    /// on its stale absolute path instead of silently uploading the
    /// wrong bytes.
    #[tokio::test]
    async fn rebase_refuses_on_mtime_mismatch() {
        let len = 8_000usize;
        let payload: Vec<u8> = vec![0x5A; len];
        let root = tempfile::tempdir().expect("tempdir");
        let imports = root.path().join("imports");
        std::fs::create_dir_all(&imports).expect("mkdir");
        std::fs::write(imports.join("blob.bin"), &payload).expect("write candidate");
        let state_dir = tempfile::tempdir().expect("state dir");

        let stale = root.path().join("gone-container").join("blob.bin");
        let job_id = "feedfacefeedface".to_string();
        let info = UploadJobInfo {
            job_id: job_id.clone(),
            source_path: stale.clone(),
            source_rel: Some(PathBuf::from("blob.bin")),
            source_size: len as u64,
            // Deliberately different from the candidate's real mtime.
            source_mtime_unix_ms: 1,
            batch_id: None,
            name: Some("blob.bin".into()),
            content_type: None,
            raw: true,
            status: UploadStatus::Running,
            bytes_pushed: 0,
            chunks_pushed: 0,
            chunks_total: Some(estimate_chunk_count(len as u64, true)),
            created_at_unix: 0,
            last_update_unix: 0,
            last_error: None,
            reference: None,
            heal_verified: false,
            heal_finished: false,
            heal_missing: None,
            heal_retry_unix: None,
            heal_attempts: 0,
            heal_last_check_unix: None,
            heal_phase: None,
            heal_checked: None,
            heal_total: None,
            chunks_requeued: 0,
            stalled: false,
            auto_paused: false,
        };
        info.save(&UploadJobInfo::manifest_path(state_dir.path(), &job_id))
            .expect("save");

        let (tx, _stats) = spawn_fake_pushsync();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None)
            .expect("manager")
            .with_source_root(Some(imports));
        mgr.rehydrate_from_disk(true).expect("rehydrate");

        let snap = wait_for(&mgr, &job_id, "terminal state", |s| s.status.is_terminal()).await;
        assert_eq!(
            snap.status,
            UploadStatus::Failed,
            "a guarded rebase miss must fail the job, not substitute the file",
        );
        assert_eq!(
            snap.source_path, stale,
            "the stale path must not be rewritten on a guard mismatch",
        );
    }

    /// Cancelling a `Completed` job stops its securing pass cleanly: the
    /// heal bails before re-pushing anything, `heal_finished` flips so
    /// the UI stops showing "Securing…", the live progress fields clear,
    /// and a subsequent "Push again" still works.
    #[tokio::test]
    async fn cancel_stops_securing_and_allows_repush() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 41) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");
        let (tx, harness) = spawn_fake_pushsync_with_heal();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");

        let id = mgr
            .start(f.path().to_path_buf(), None, None, None, false)
            .expect("start");
        wait_for(&mgr, &id, "completion", |s| s.status.is_terminal()).await;

        // Cancel while the enqueued heal is still in its settle window —
        // it must bail before re-pushing the forced-missing chunk.
        mgr.cancel(&id).expect("cancel");
        let snap = wait_for(&mgr, &id, "heal_finished after cancel", |s| s.heal_finished).await;
        assert_eq!(snap.status, UploadStatus::Completed);
        assert!(snap.heal_phase.is_none(), "no frozen Securing… state");
        if let Some(t) = harness.target() {
            assert_eq!(
                harness.dispatch_count(t),
                1,
                "cancelled securing pass must not have re-pushed",
            );
        }

        // The stop is honoured across the next wake: the cancel stamped
        // the degraded-retry backoff, so wake must not immediately
        // re-queue the pass (enqueue would synchronously set
        // heal_phase = "queued").
        mgr.wake_all();
        let snap = mgr.status(&id).expect("status");
        assert!(
            snap.heal_phase.is_none(),
            "Stop securing must not be undone by the very next wake",
        );

        // "Push again" after the cancel must still run a full pass.
        let after = mgr
            .repush_with_progress(&id, None)
            .await
            .expect("repush after cancelled securing");
        assert_eq!(after.status, UploadStatus::Completed);
        let snap = wait_for(&mgr, &id, "heal verdict after repush", |s| s.heal_finished).await;
        assert!(
            snap.heal_verified,
            "push-again after a cancelled securing pass should verify",
        );
    }

    /// Strict receipts: the shallow-placement error the push path returns
    /// under `require_deep` must be classified *transient* by the upload
    /// driver — the chunk parks in the retry queue and keeps hunting for
    /// a deep storer — and must not take the long no-peer back-off (the
    /// neighbourhood answered; it just answered shallow).
    #[test]
    fn shallow_receipt_error_is_transient_for_uploads() {
        let msg = "pushsync: shallow receipt: storer proximity 3 < storage radius 9";
        assert!(
            !is_fatal_push_error(msg),
            "a shallow placement must be retried, not fail the job",
        );
        assert!(
            !is_no_peer_error(msg),
            "shallow means the neighbourhood answered — use the normal back-off",
        );
    }

    /// Issue #128 / PR #138 R1-M2: a walk that gives up because every
    /// candidate peer stayed at its credit limit is a momentary state of
    /// the neighbourhood (credit comes back with refreshes and payments),
    /// so the upload job must re-queue the chunk, not fail. The message is
    /// built by the real constructor and wrapped as the daemon acks it
    /// (`pushsync: {e}`), so a rewording that trips a fatal marker
    /// ("saturated", "not usable", …) fails here instead of in the field.
    #[test]
    fn no_push_credit_error_is_transient_for_uploads() {
        let e = ant_retrieval::pushsync::no_push_credit_error(3, Duration::from_secs(10));
        let msg = format!("pushsync: {e}");
        assert!(
            !is_fatal_push_error(&msg),
            "an all-overdrawn neighbourhood must re-queue the chunk, not fail the job: {msg}",
        );
    }

    /// Pin the escalation schedule: quick early re-checks (a fresh
    /// upload usually settles within minutes), backing off to the cap.
    #[test]
    fn degraded_retry_schedule_escalates_to_cap() {
        let mins: Vec<u64> = (0..7)
            .map(|a| degraded_retry_interval(a).as_secs() / 60)
            .collect();
        assert_eq!(mins, vec![1, 1, 2, 5, 10, 15, 15]);
    }

    /// A degraded persisted job (securing pass ran but couldn't verify)
    /// is re-queued on launch and, once the network cooperates, ends
    /// `heal_verified` — repair no longer waits for a manual Push again.
    #[tokio::test]
    async fn launch_retries_degraded_heal_until_verified() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 47) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");

        let md = std::fs::metadata(f.path()).expect("metadata");
        let job_id = "deadbeefdeadbeef".to_string();
        let info = UploadJobInfo {
            job_id: job_id.clone(),
            source_path: f.path().to_path_buf(),
            source_rel: None,
            source_size: len as u64,
            source_mtime_unix_ms: mtime_unix_ms(&md),
            batch_id: None,
            name: Some("blob.bin".into()),
            content_type: None,
            raw: false,
            status: UploadStatus::Completed,
            bytes_pushed: len as u64,
            chunks_pushed: estimate_chunk_count(len as u64, false),
            chunks_total: Some(estimate_chunk_count(len as u64, false)),
            created_at_unix: 0,
            last_update_unix: 0,
            last_error: None,
            reference: Some(format!("0x{}", "11".repeat(32))),
            heal_verified: false,
            // Degraded: the pass ran to the end without verifying.
            heal_finished: true,
            heal_missing: None,
            heal_retry_unix: None,
            heal_attempts: 0,
            heal_last_check_unix: None,
            heal_phase: None,
            heal_checked: None,
            heal_total: None,
            chunks_requeued: 0,
            stalled: false,
            auto_paused: false,
        };
        info.save(&UploadJobInfo::manifest_path(state_dir.path(), &job_id))
            .expect("save");

        // The fake network now confirms everything present, so the retry
        // pass verifies.
        let (tx, _stats) = spawn_fake_pushsync();
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");
        mgr.rehydrate_from_disk(true).expect("rehydrate");

        let snap = wait_for(&mgr, &job_id, "degraded retry to verify", |s| {
            s.heal_verified
        })
        .await;
        assert!(snap.heal_finished, "the retry pass ran to completion");
    }

    /// The degraded auto-retry is spaced by a long backoff: after a retry
    /// pass ends degraded again, an immediate wake must NOT re-queue the
    /// heal (the backoff window hasn't lapsed).
    #[tokio::test]
    async fn degraded_retry_backs_off_between_wakes() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 53) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let state_dir = tempfile::tempdir().expect("tempdir");

        let md = std::fs::metadata(f.path()).expect("metadata");
        let job_id = "cafebabecafebabe".to_string();
        let info = UploadJobInfo {
            job_id: job_id.clone(),
            source_path: f.path().to_path_buf(),
            source_rel: None,
            source_size: len as u64,
            source_mtime_unix_ms: mtime_unix_ms(&md),
            batch_id: None,
            name: Some("blob.bin".into()),
            content_type: None,
            raw: false,
            status: UploadStatus::Completed,
            bytes_pushed: len as u64,
            chunks_pushed: estimate_chunk_count(len as u64, false),
            chunks_total: Some(estimate_chunk_count(len as u64, false)),
            created_at_unix: 0,
            last_update_unix: 0,
            last_error: None,
            reference: Some(format!("0x{}", "22".repeat(32))),
            heal_verified: false,
            heal_finished: true,
            heal_missing: None,
            heal_retry_unix: None,
            heal_attempts: 0,
            heal_last_check_unix: None,
            heal_phase: None,
            heal_checked: None,
            heal_total: None,
            chunks_requeued: 0,
            stalled: false,
            auto_paused: false,
        };
        info.save(&UploadJobInfo::manifest_path(state_dir.path(), &job_id))
            .expect("save");

        // Fake loop that keeps one chunk permanently missing, so every
        // retry pass ends degraded again.
        let (tx, mut rx) = mpsc::channel::<ControlCommand>(64);
        tokio::spawn(async move {
            let mut target: Option<[u8; 32]> = None;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ControlCommand::PushChunk { wire, ack, .. } => {
                        let mut span = [0u8; 8];
                        span.copy_from_slice(&wire[..8]);
                        let addr =
                            ant_crypto::bmt::bmt_hash_with_span(&span, &wire[8..]).expect("BMT");
                        let _ = ack.send(ControlAck::ChunkUploaded {
                            reference: format!("0x{}", hex::encode(addr)),
                        });
                    }
                    ControlCommand::VerifyChunksPresent { addresses, ack, .. } => {
                        let t = *target.get_or_insert_with(|| addresses[0]);
                        let missing: Vec<String> = addresses
                            .iter()
                            .filter(|a| **a == t)
                            .map(|a| format!("0x{}", hex::encode(a)))
                            .collect();
                        let body = serde_json::json!({
                            "checked": addresses.len(),
                            "missing": missing,
                        });
                        let _ = ack.send(ControlAck::Ok {
                            message: body.to_string(),
                        });
                    }
                    ControlCommand::PostageList { ack } => {
                        let _ = ack.send(ControlAck::PostageList(Vec::new()));
                    }
                    other => panic!("unexpected command in backoff test: {other:?}"),
                }
            }
        });
        let mgr = UploadManager::new(state_dir.path().to_path_buf(), tx, None).expect("manager");
        mgr.rehydrate_from_disk(true).expect("rehydrate");

        // First retry pass runs (rehydrate re-queued it) and ends
        // degraded again: heal_finished flips false while running, then
        // back to true, still unverified.
        wait_for(&mgr, &job_id, "first retry pass to start", |s| {
            !s.heal_finished || s.heal_phase.is_some()
        })
        .await;
        let snap = wait_for(&mgr, &job_id, "first retry pass to finish", |s| {
            s.heal_finished && s.heal_phase.is_none()
        })
        .await;
        assert!(!snap.heal_verified, "harness keeps one chunk missing");

        // The degraded verdict surfaces its honest residual and the
        // retry schedule, so the UI can say
        // "N parts still settling · next check in ~M min".
        assert_eq!(
            snap.heal_missing,
            Some(1),
            "the pass measured exactly one unconfirmed chunk",
        );
        assert!(
            snap.heal_retry_unix.is_some_and(|at| at > unix_seconds()),
            "next automatic retry must be scheduled in the future",
        );
        assert!(
            snap.heal_attempts >= 1,
            "the completed unsuccessful pass must count as a check",
        );
        assert!(
            snap.heal_last_check_unix.is_some(),
            "the pass must stamp its completion time",
        );

        // An immediate wake must be suppressed by the backoff: enqueue
        // would synchronously stamp heal_phase = "queued".
        mgr.wake_all();
        let snap = mgr.status(&job_id).expect("status");
        assert!(
            snap.heal_phase.is_none(),
            "degraded retry must back off, not re-queue on every wake",
        );
        assert!(snap.heal_finished && !snap.heal_verified);
    }

    /// Store-only heal (source gone): a completed-but-unsecured job whose
    /// source file was deleted enumerates its chunk set by traversing the
    /// reference through the persistent chunk store, re-pushes the
    /// missing chunk from that same store, and ends verified.
    #[tokio::test]
    async fn startup_heal_traverses_store_when_source_deleted() {
        let len = 20_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 43) % 251) as u8).collect();
        let f = write_temp_file(&payload);
        let source = f.path().to_path_buf();
        let state_dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = tempfile::tempdir().expect("cachedir");
        let cache = Arc::new(
            ant_retrieval::DiskChunkCache::open(cache_dir.path().join("c.sqlite"), 1 << 30)
                .expect("cache"),
        );

        // Run 1: upload with the store wired and let securing finish.
        let (tx1, _h1) = spawn_fake_pushsync_with_cache(cache.clone());
        let mgr1 = UploadManager::new(state_dir.path().to_path_buf(), tx1, None)
            .expect("manager")
            .with_disk_cache(Some(cache.clone()));
        let id = mgr1
            .start(source.clone(), None, None, None, false)
            .expect("start");
        wait_for(&mgr1, &id, "first-run securing", |s| s.heal_finished).await;
        drop(mgr1);

        // Simulate a relaunch that still owes this job a securing pass,
        // with the source file gone.
        let manifest_path = state_dir.path().join(format!("{id}.json"));
        let mut info = UploadJobInfo::load(&manifest_path).expect("load");
        info.heal_finished = false;
        info.heal_verified = false;
        info.save(&manifest_path).expect("save");
        drop(f);
        std::fs::remove_file(&source).ok();
        assert!(!source.exists());

        // Run 2: rehydrate; the startup heal must proceed store-only —
        // enumerate from the reference, re-push the forced-missing chunk
        // from the cache — and end verified.
        let (tx2, h2) = spawn_fake_pushsync_with_cache(cache.clone());
        let mgr2 = UploadManager::new(state_dir.path().to_path_buf(), tx2, None)
            .expect("manager")
            .with_disk_cache(Some(cache));
        mgr2.rehydrate_from_disk(true).expect("rehydrate");

        let snap = wait_for(&mgr2, &id, "store-only securing", |s| s.heal_finished).await;
        assert!(
            snap.heal_verified,
            "store-only heal should verify without the source file",
        );
        let target = h2.target().expect("second run forced a missing chunk");
        assert!(
            h2.dispatch_count(target) >= 1,
            "the forced-missing chunk must have been re-pushed from the store",
        );
    }
}
