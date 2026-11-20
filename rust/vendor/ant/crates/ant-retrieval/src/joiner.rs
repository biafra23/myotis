//! Multi-chunk file reconstruction.
//!
//! Bee splits files larger than 4 KiB into a balanced k-ary tree of chunks
//! (`pkg/file/joiner`, `pkg/file/splitter`):
//!
//! - **Leaf chunks** carry up to 4096 bytes of file data behind their
//!   8-byte little-endian span. The span equals the payload length.
//! - **Intermediate chunks** carry a list of 32-byte child references
//!   (max 128 per chunk = `swarm.Branches`). Their span is the *total*
//!   size of the subtree rooted at this chunk, not the chunk's own
//!   payload length.
//! - The root chunk's span is the file's full length. If `span <= 4096`
//!   the root *is* a leaf.
//!
//! The splitter wraps levels greedily: a 5 KiB file produces a root with
//! two children (4 KiB + 1 KiB); a 500 KiB file produces a root with 125
//! direct children (each 4 KiB). For any intermediate chunk with `N`
//! children and total span `T`, the first `N-1` children each cover the
//! same `branchSize` bytes (`= 4096 * 128^k` for the smallest `k` that
//! keeps the last child within `branchSize`); the last child carries
//! the remainder. This is the [`subtrie_section`] formula and matches
//! `bee/pkg/file/joiner.subtrieSection` byte-for-byte.
//!
//! # Erasure-coded (Reed-Solomon) files
//!
//! Files uploaded with `swarm-redundancy-level` 1–4 carry the level in
//! the top byte of every intermediate chunk's span (`level | 0x80`) and
//! append parity references after the data references in each
//! intermediate node. The joiner decodes the level per node, computes
//! the parity count from the node's own span via the level's erasure
//! table ([`crate::rs::reference_count`]), walks only the data
//! references — with the branching factor reduced to the level's
//! `maxShards` — and, when a data child cannot be fetched, recovers it
//! from the remaining siblings + parities through a per-node
//! [`crate::rs::RsDecoder`]. Recovered chunks are CAC-validated and fed
//! back into the fetcher's caches. This is always on; see
//! [`JoinOptions::allow_degraded_redundancy`] for the legacy flag.
//!
//! **Encrypted chunks** (`refLength == 64`) are handled by a separate
//! entry point, [`join_encrypted`], which fetches each chunk by its
//! 32-byte address and decrypts it with the per-chunk key carried in the
//! 64-byte reference that pointed to it. The plaintext [`join`] family
//! still rejects a 64-byte root via [`JoinError::UnsupportedEncryption`].

use crate::accounting::{CreditWindow, CREDIT_WAIT_BUDGET};
use crate::priority::{self, ReadHead};
use crate::ChunkFetcher;
use ant_crypto::CHUNK_SIZE;
use futures::stream::{self, StreamExt, TryStreamExt};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::trace;

/// Size of an encrypted reference: `address(32) ‖ key(32)`. Re-exported
/// from `ant-crypto` so feed / gateway callers don't depend on the crypto
/// crate directly.
pub const ENCRYPTED_REF_SIZE: usize = ant_crypto::REFERENCE_SIZE;

/// Default cap on a joined file's total size, in bytes. Sized to comfortably
/// hold a small website or text file while making it impossible for a
/// malformed root chunk (huge declared span, tiny actual contents) to make
/// us allocate gigabytes before noticing. Override per-call when there's a
/// legitimate reason to fetch more.
pub const DEFAULT_MAX_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Span ceiling for **durability** enumeration (post-upload verify / deep
/// verify), as opposed to the interactive CLI [`DEFAULT_MAX_FILE_BYTES`].
/// A file the gateway will serve (up to ~16 GiB) must also be *verifiable*,
/// or the verify path reuses the tight 32 MiB interactive cap and reports
/// large-but-healthy uploads as "not fully stored" (the `file too large:
/// span … cap 33554432` failure a 55 MB upload hits). Sized to the gateway
/// serving ceiling. Enumeration only walks interior nodes and records
/// 32-byte addresses, so even at the ceiling the memory cost is tens of
/// MiB. Expressed as `u64` and narrowed at the call site with saturation,
/// so 32-bit targets clamp to `usize::MAX` instead of overflowing.
pub const DURABILITY_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Hard ceiling on intermediate-chunk fan-out. `swarm.Branches`.
const MAX_BRANCHES: usize = CHUNK_SIZE / 32;

/// Maximum number of sibling subtrees expanded at once from a single
/// intermediate node. Each subtree may fetch its own descendants, so the
/// daemon's process-wide retrieval semaphore remains the final cap on
/// live libp2p streams; this fanout controls how much of a deep file can
/// make progress instead of walking left-to-right one subtree at a time.
/// Combined with bee's per-chunk retrieval client (preemptive multi-peer
/// fanout, 1 s ticker), this gives roughly the same effective breadth
/// per file as bee's `errgroup.Group` model in `pkg/file/joiner`.
///
/// Sized at 16 from a sweep on the `litter-ally.eth` WAV tree (release
/// `antd`, ~100 BZZ peers, cold disk cache, two files of 44–55 MiB):
/// 8 → 16 lifted average throughput from 0.55 → 0.61 MiB/s (≈ +12 %)
/// for ~6 MiB extra resident set; 32 was indistinguishable from 16; 64
/// regressed to baseline as extra in-flight requests just diluted load
/// across peers without the chunk. Past ~16 the bottleneck shifts to
/// per-chunk close-peer latency (XOR-distance ranking + 1 s hedge),
/// not local fanout, so adding more subtree workers buys nothing.
const FETCH_FANOUT: usize = 16;

/// Retry a child subtree in place when it fails because one descendant
/// chunk could not be fetched. This is the streaming equivalent of the
/// old whole-file retry loop: once the gateway has emitted earlier bytes
/// it cannot restart the response, so transient mainnet misses must be
/// retried before the child subtree is handed to the caller. Successful
/// descendant chunks are cached by `RoutingFetcher`, so retries normally
/// jump straight to the missing tail.
const SUBTREE_RETRY_ATTEMPTS: usize = 32;
/// Erasure-recovery retries for one data child of a redundant node,
/// when the recovery sweep came up short for want of reachable peers
/// rather than because peers confirmed the shards missing
/// ([`crate::rs::RecoveryError::transient`]). On a cold node the peer
/// pool is overdraft-starved: a never-refreshed peer admits about five
/// ~300k-unit chunks against its 1.69M limit and then only what
/// pseudosettle restores (450k units/s, ~1.5 chunks/s per peer), so
/// concurrent cold segments find every ranked peer overdraft-skipped
/// and sweeps collect a fraction of their shards (issue #114). The
/// content is fine; it just has to wait for credit. Once bytes have
/// gone out the response can't restart, so this is retried in place,
/// like [`SUBTREE_RETRY_ATTEMPTS`] does for plain fetch misses. The same
/// goes for shards peers answered "not found" until those answers have
/// held for [`crate::rs::MISS_CONFIRM_AFTER`] (10 s, issue #79): only
/// then does a shortfall of them become permanent and end the retries.
///
/// The bound is wall-clock: no new sweep starts once
/// [`RECOVERY_RETRY_BUDGET`] has passed since this child's first fetch
/// began (the attempt cap is a backstop). Back-off is
/// `RECOVERY_RETRY_BACKOFF × attempt`, capped at
/// [`RECOVERY_RETRY_BACKOFF_MAX`]. 60 s covers the credit a light node
/// needs to pull several cold 1.6 MB segments at once at startup (on
/// mainnet, 8 concurrent ones completed in 14–20 s and 12 in 19–28 s,
/// where an 8-sweep / 14 s budget still truncated 6 of 16).
///
/// It is a budget on sweep *starts*, not a deadline: the last sweep may
/// begin just inside the window and runs to completion (bounded only by
/// the fetcher's own per-chunk limits), and each redundant level has its
/// own window, so a data child that is itself an intermediate chunk of a
/// redundant subtree can spend one window recovering and then its own
/// child another, with no bytes emitted in between. So this is chosen
/// to leave a single-level recovery comfortably inside the gateway's
/// 90 s `BODY_STALL_TIMEOUT`, but does not guarantee it: a stuck nested
/// recovery may end in the gateway's stall timeout instead of a join
/// error. For the client the outcome is the same — a truncated body (or
/// a 502 if nothing was sent yet).
const RECOVERY_RETRY_ATTEMPTS: usize = 32;
const RECOVERY_RETRY_BACKOFF: Duration = Duration::from_millis(500);
const RECOVERY_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(4);
const RECOVERY_RETRY_BUDGET: Duration = Duration::from_secs(60);
/// Credit window ([`CreditWindow`]) of one data child of the streaming
/// and range joiners: its subtree retries wait for peer credit, and
/// retry a starved miss, only within this long of its first fetch. The
/// same 60 s a redundant child's recovery retries get, so a starved
/// child, plain or redundant, stalls the body for at most 60 s plus the
/// last attempt's network time, under the gateway's 90 s
/// `BODY_STALL_TIMEOUT` (see [`CREDIT_WAIT_BUDGET`]).
const STREAM_CREDIT_WINDOW: Duration = RECOVERY_RETRY_BUDGET;
/// Credit window of one data child of the buffered joiner ([`join`]):
/// one credit wait, after which a starved miss isn't retried in place
/// and goes back to the caller's whole-request retry (whose fetcher
/// carries its own credit deadline, `RoutingFetcher::with_credit_deadline`).
/// Binds only a fetcher that waits ([`ChunkFetcher::waits_for_credit`]);
/// a never-waiting buffered join (manifest fallback join, traversal)
/// keeps every subtree retry for a starved miss ([`retry_child_miss`]).
const BUFFERED_CREDIT_WINDOW: Duration = CREDIT_WAIT_BUDGET;
/// Per-child output-channel depth for the streaming joiner. This is
/// exactly bee's "moving window" knob: each in-flight sibling subtree
/// has at most this many resolved 4 KiB chunks (≈ 256 KiB) buffered
/// while waiting for the in-order merger to forward them downstream.
/// Combined with `FETCH_FANOUT`, the joiner keeps roughly
/// `FETCH_FANOUT * STREAM_PIPE_DEPTH` chunks (≈ 2 MiB) ahead of the
/// consumer at any given level — comparable to bee's langos lookahead
/// (256–512 KiB) layered on top of its joiner errgroup. Output stays
/// strictly in document order at every level because the merger drains
/// children left-to-right; later siblings backfill as soon as the first
/// finishes, so a fast 4 MiB child never has to wait for the slow
/// previous 4 MiB child to produce its first byte.
const STREAM_PIPE_DEPTH: usize = 64;

/// Knobs that aren't span/payload-defined. Pass [`JoinOptions::default`]
/// for the strict joiner; flip flags on for explicit, narrowly-scoped
/// fallbacks.
#[derive(Debug, Clone, Copy, Default)]
pub struct JoinOptions {
    /// **Legacy no-op.** Historically this gated reading files whose
    /// root span carries a redundancy/erasure-coding level byte at all
    /// (masking the level and hoping every data chunk was reachable).
    /// The joiner now always decodes redundant trees with the correct
    /// parity-aware geometry *and* recovers missing data chunks from
    /// parities, which strictly supersedes both prior behaviors, so the
    /// flag no longer changes anything. It is retained so existing CLI
    /// (`antctl get --allow-degraded-redundancy`) and control-protocol
    /// callers keep working unchanged.
    pub allow_degraded_redundancy: bool,
}

/// Reason a join failed. Distinct variants so the caller can decide
/// whether to retry, fall back, or surface a clean error to the user.
#[derive(Debug, Error)]
pub enum JoinError {
    /// The file's declared span exceeds the configured cap.
    #[error("file too large: span {span} bytes, cap {cap} bytes")]
    TooLarge { span: u64, cap: usize },
    /// An intermediate chunk's payload size isn't a whole multiple of
    /// the reference length, or the chunk is shorter than declared.
    #[error("malformed intermediate chunk at offset {offset}: {detail}")]
    MalformedChunk { offset: u64, detail: String },
    /// A data chunk of a redundancy-encoded intermediate node could not
    /// be fetched **and** Reed-Solomon recovery from the node's
    /// remaining shards + parities failed (more than `parityCnt` chunks
    /// of that node are unreachable, or the reconstruction output
    /// failed CAC validation). Terminal: a recovery that fell short only
    /// for want of reachable peers has already been retried in place
    /// with back-off before this is returned (issue #114), as has one
    /// whose shards peers answered "not found" for less than
    /// [`crate::rs::MISS_CONFIRM_AFTER`] (issue #79); one that failed on
    /// shards denied for that long or a bad decode can't improve.
    #[error("erasure recovery failed: {detail}")]
    Recovery { detail: String },
    /// Encrypted chunks (64-byte refs) aren't supported. Only triggered
    /// if the *caller* passes a 64-byte root reference; for the
    /// 32-byte path we never decode a 64-byte ref-length intermediate.
    #[error("encrypted chunks not supported")]
    UnsupportedEncryption,
    /// A child fetch failed. Wraps the underlying retrieval error so
    /// `antctl get` can surface a useful message ("not found", "timed
    /// out", peer id, etc.).
    #[error("fetch chunk {addr}: {source}")]
    FetchChunk {
        addr: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The downstream consumer went away while the joiner was streaming
    /// output chunks.
    #[error("output stream closed")]
    OutputClosed,
}

/// Reconstruct a file from a Swarm reference using the chunk tree.
///
/// `root_chunk_data` is the full wire bytes of the chunk addressed by
/// `root_addr` (`span (8 LE) || payload`). Pass it in (rather than fetching
/// it inside) so callers that already have the root chunk in hand — e.g.
/// the manifest path which fetched it to decode mantaray and *then*
/// realises it's actually a binary blob with a missing manifest, or the
/// retrieval-client path which has just verified it — don't fetch twice.
///
/// `fetcher` is responsible for retrieving and CAC-verifying every
/// non-root chunk in the tree. The joiner doesn't itself talk to libp2p;
/// this keeps the multi-chunk reconstruction logic pure and unit-testable
/// against a `HashMap` mock.
pub async fn join(
    fetcher: &dyn ChunkFetcher,
    root_chunk_data: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, JoinError> {
    join_with_options(fetcher, root_chunk_data, max_bytes, JoinOptions::default()).await
}

/// Like [`join`], but with explicit knobs (currently just
/// `allow_degraded_redundancy`). Kept as a separate entry point so the
/// strict default has the simplest possible signature for the test
/// suite and the unit-tested mantaray internals; production callers
/// that need to flip flags use this variant.
pub async fn join_with_options(
    fetcher: &dyn ChunkFetcher,
    root_chunk_data: &[u8],
    max_bytes: usize,
    _options: JoinOptions,
) -> Result<Vec<u8>, JoinError> {
    let (span_raw, payload) = split_chunk(root_chunk_data, 0)?;
    let (level, span, parity) = decode_root_span(span_raw);
    if span > max_bytes as u64 {
        return Err(JoinError::TooLarge {
            span,
            cap: max_bytes,
        });
    }

    join_subtree(fetcher, payload, span, 0, level, parity).await
}

/// Decode a root chunk's span into `(redundancy level, plain span,
/// parity ref count of the root node)`. Level 0 spans pass through
/// unchanged with zero parity; level-encoded spans additionally derive
/// the root's parity count from the file size via the level's erasure
/// table, exactly like bee's `joiner.NewJoiner` does with
/// `file.ReferenceCount`.
fn decode_root_span(span_raw: [u8; 8]) -> (u8, u64, usize) {
    let (level, plain) = crate::rs::decode_span(span_raw);
    let span = u64::from_le_bytes(plain);
    let parity = if level != 0 && span > CHUNK_SIZE as u64 {
        crate::rs::reference_count(span, level).1
    } else {
        0
    };
    if level != 0 {
        tracing::debug!(
            target: "ant_retrieval::joiner",
            level,
            span,
            parity,
            "root span carries a redundancy level; RS-aware decode with recovery enabled",
        );
    }
    (level, span, parity)
}

/// Flat inventory of the chunk addresses that make up a file's data
/// tree, produced by [`enumerate_chunk_tree`].
///
/// `intermediates` are the addresses of the tree's interior nodes
/// (including the data root) — enumeration has to *fetch* each of these
/// to read its child references, so by the time enumeration returns
/// successfully every intermediate is known to be retrievable.
/// `leaves` are the addresses of the data-bearing chunks; enumeration
/// does **not** fetch them (their addresses are listed in their parent
/// intermediate), so a caller that wants to confirm leaves are
/// retrievable must probe them separately — typically a bounded random
/// sample rather than the whole set.
#[derive(Debug, Default, Clone)]
pub struct ChunkInventory {
    pub leaves: Vec<[u8; 32]>,
    pub intermediates: Vec<[u8; 32]>,
}

impl ChunkInventory {
    /// Total chunk count of the data tree (leaves + interior nodes).
    #[must_use]
    pub fn total(&self) -> usize {
        self.leaves.len() + self.intermediates.len()
    }
}

/// Enumerate every chunk address in the data tree rooted at `root_addr`
/// without downloading the whole file.
///
/// Interior nodes are fetched through `fetcher` (so their child
/// references can be read and so they're proven retrievable); leaf
/// addresses are collected from their parents but **not** fetched. Pass
/// a cache-free fetcher to make the interior-node fetches go to the
/// network rather than a local store. `root_chunk_data` is the data
/// root's full wire bytes (`span (8 LE) || payload`), which the caller
/// has typically just fetched to learn the file size.
///
/// Used by the propagation-verification path to learn a file's exact
/// chunk layout and then probe a sample of real data leaves, instead of
/// only checking the root reference.
pub async fn enumerate_chunk_tree(
    fetcher: &dyn ChunkFetcher,
    root_addr: [u8; 32],
    root_chunk_data: &[u8],
    max_bytes: usize,
    _options: JoinOptions,
) -> Result<ChunkInventory, JoinError> {
    let (span_raw, payload) = split_chunk(root_chunk_data, 0)?;
    let (level, span, parity) = decode_root_span(span_raw);
    if span > max_bytes as u64 {
        return Err(JoinError::TooLarge {
            span,
            cap: max_bytes,
        });
    }

    let mut inv = ChunkInventory::default();
    // A root whose span fits within its own payload *is* the single data
    // leaf — there are no interior nodes to walk.
    if span <= payload.len() as u64 {
        inv.leaves.push(root_addr);
        return Ok(inv);
    }
    inv.intermediates.push(root_addr);
    let sub = enumerate_subtree(fetcher, payload, span, 0, level, parity).await?;
    inv.leaves.extend(sub.leaves);
    inv.intermediates.extend(sub.intermediates);
    Ok(inv)
}

/// Recursively collect the inventory of an intermediate node's subtree.
/// Mirrors [`join_subtree`]'s spec computation (`subtrie_section`,
/// zero-pad stripping, last-child remainder) but only fetches interior
/// nodes and records addresses rather than reconstructing bytes. Walks
/// sequentially — interior nodes are ~1/128 of all chunks, so there's
/// no need for the fan-out the byte-joiner uses.
///
/// For redundancy-encoded nodes the parity references are recorded as
/// leaves (they are real, fetchable chunks a durability check should
/// cover — bee's `IterateChunkAddresses` reports them too) but never
/// descended into. Enumeration stays *strict*: a missing interior node
/// fails the walk rather than being RS-recovered, because the callers
/// (durability verify, stewardship) are asking "is everything stored?",
/// not "can the file be salvaged?".
fn enumerate_subtree<'a>(
    fetcher: &'a dyn ChunkFetcher,
    chunk_payload: &'a [u8],
    subtree_span: u64,
    offset: u64,
    level: u8,
    parity: usize,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<ChunkInventory, JoinError>> + Send + 'a>,
> {
    Box::pin(async move {
        let node = parse_intermediate(chunk_payload, subtree_span, offset, level, parity)?;

        let mut inv = ChunkInventory::default();
        for (_, child_addr, child_span, child_offset) in node.specs {
            // A child covering at most one chunk's worth of bytes is a
            // data leaf; anything larger is another interior node we
            // must fetch to read its own children.
            if child_span <= CHUNK_SIZE as u64 {
                inv.leaves.push(child_addr);
            } else {
                inv.intermediates.push(child_addr);
                let child = fetcher
                    .fetch(child_addr)
                    .await
                    .map_err(|e| JoinError::FetchChunk {
                        addr: hex::encode(child_addr),
                        source: e,
                    })?;
                let (_, child_payload) = split_chunk(&child, child_offset)?;
                let (child_level, _, child_parity) =
                    crate::rs::chunk_meta(&child).unwrap_or((0, 0, 0));
                let sub = enumerate_subtree(
                    fetcher,
                    child_payload,
                    child_span,
                    child_offset,
                    child_level,
                    child_parity,
                )
                .await?;
                inv.leaves.extend(sub.leaves);
                inv.intermediates.extend(sub.intermediates);
            }
        }
        inv.leaves.extend(node.parity_addrs);
        Ok(inv)
    })
}

/// Stream a joined file in byte order without materialising the entire
/// body in one `Vec<u8>`.
///
/// This mirrors Bee's HTTP path more closely than [`join`]: the caller
/// fetches the root chunk once, learns the total span, and then receives
/// ordered body chunks as the joiner resolves subtrees. The current
/// implementation emits one buffer per completed child subtree at each
/// intermediate level; that is intentionally coarser than Bee's
/// `io.ReadSeeker`, but it lets the gateway send body bytes while the
/// rest of the tree is still being retrieved.
pub async fn join_to_sender(
    fetcher: &dyn ChunkFetcher,
    root_chunk_data: &[u8],
    max_bytes: usize,
    options: JoinOptions,
    out: mpsc::Sender<Vec<u8>>,
) -> Result<(), JoinError> {
    join_to_sender_range(fetcher, root_chunk_data, max_bytes, options, None, out).await
}

/// Inclusive byte range expressed against the joined file body.
///
/// Both ends are inclusive (matching HTTP `Range: bytes=start-end`);
/// callers ensure `start <= end < total_span` and convert HTTP suffix
/// or open-ended ranges to absolute bounds before calling.
#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub end_inclusive: u64,
}

impl ByteRange {
    /// Build a range covering `[start, end_inclusive]` after clamping to
    /// `total - 1` on the right edge. Returns `None` for empty / invalid
    /// inputs so the caller can short-circuit to a 416 response.
    #[must_use]
    pub fn clamp(start: u64, end_inclusive: u64, total: u64) -> Option<Self> {
        if total == 0 || start > end_inclusive || start >= total {
            return None;
        }
        Some(Self {
            start,
            end_inclusive: end_inclusive.min(total - 1),
        })
    }
}

/// Like [`join_to_sender`], but only emits the requested byte range.
///
/// `range = None` is identical to [`join_to_sender`]: the whole body
/// streams. With `range = Some(_)` the joiner walks the chunk tree
/// without fetching subtrees that fall entirely outside `[start, end]`,
/// and slices the leftmost / rightmost subtrees to drop any prefix or
/// suffix bytes outside the range. This is what lets `/bzz` and
/// `/bytes` answer browser media seeks (`Range: bytes=N-M`) without
/// joining the whole file first.
///
/// Callers are responsible for emitting the correct HTTP `206
/// Partial Content` headers — this function only produces the body
/// bytes for the range. It does not emit chunks before `start` or
/// after `end`.
///
/// The join tracks how far `out` has taken the body, and ranks every
/// data-chunk fetch against it, so the fetcher gives the chunks the
/// consumer needs next priority over look-ahead ([`crate::priority`],
/// issue #46).
pub async fn join_to_sender_range(
    fetcher: &dyn ChunkFetcher,
    root_chunk_data: &[u8],
    max_bytes: usize,
    _options: JoinOptions,
    range: Option<ByteRange>,
    out: mpsc::Sender<Vec<u8>>,
) -> Result<(), JoinError> {
    let (span_raw, payload) = split_chunk(root_chunk_data, 0)?;
    let (level, span, parity) = decode_root_span(span_raw);
    if span > max_bytes as u64 {
        return Err(JoinError::TooLarge {
            span,
            cap: max_bytes,
        });
    }

    let range = range.map(|range| ByteRange {
        start: range.start.min(span.saturating_sub(1)),
        end_inclusive: range.end_inclusive.min(span.saturating_sub(1)),
    });

    // The consumer's read position, for head-of-window priority (issue
    // #46, [`crate::priority`]): the joiner sends into `relay_tx`, and
    // the relay moves the read head on once `out` has taken each buffer.
    let head = ReadHead::new(range.map_or(0, |r| r.start));
    let (relay_tx, mut relay_rx) = mpsc::channel::<Vec<u8>>(1);
    let join = priority::with_read_head(head.clone(), async move {
        let r = match range {
            None => {
                join_subtree_to_sender(fetcher, payload, span, 0, level, parity, &relay_tx).await
            }
            Some(range) => {
                join_subtree_range_to_sender(
                    fetcher, payload, span, 0, level, parity, range, &relay_tx,
                )
                .await
            }
        };
        drop(relay_tx);
        r
    });
    // Once `out` closes, the relay ends and drops `relay_rx`, so the
    // joiner's next send fails with `OutputClosed`, as it did on `out`.
    let relay = async move {
        while let Some(buf) = relay_rx.recv().await {
            let len = buf.len() as u64;
            out.send(buf).await.map_err(|_| JoinError::OutputClosed)?;
            head.advance(len);
        }
        Ok::<(), JoinError>(())
    };
    // Not `try_join!`: a join error still lets the relay hand `out`
    // every buffer the joiner sent before it.
    let (joined, relayed) = tokio::join!(join, relay);
    joined.and(relayed)
}

/// Decoded layout of one intermediate chunk, shared by every tree
/// walker: the per-data-child fetch specs, the parity references (if
/// any), and — when the node is redundancy-encoded — the RS decoder its
/// child fetches route through.
struct IntermediateNode {
    /// `(index, addr, child_span, child_offset)` for each **data**
    /// child, in document order. Parity refs never appear here.
    specs: Vec<(usize, [u8; 32], u64, u64)>,
    /// The node's parity chunk addresses (empty at level 0).
    parity_addrs: Vec<[u8; 32]>,
    /// Present when `parity > 0`: recovery decoder over all
    /// `shard_cnt + parity` references of this node.
    decoder: Option<std::sync::Arc<crate::rs::RsDecoder>>,
}

/// Validate an intermediate chunk's payload and split it into data
/// shard specs + parity refs.
///
/// `level`/`parity` describe **this** node (decoded from its own span
/// by the caller). The reference layout is bee's: the payload holds
/// `shard_cnt` data references followed by `parity` parity references,
/// where `shard_cnt = effective_refs - parity`; the subtree geometry
/// (`subtrie_section`) is computed over the *data* references only,
/// with the branching factor shrunk to the level's `maxShards` because
/// full intermediate nodes at level L hold only `maxShards(L)` data
/// children (the rest of the 128 slots are parities).
fn parse_intermediate(
    chunk_payload: &[u8],
    subtree_span: u64,
    offset: u64,
    level: u8,
    parity: usize,
) -> Result<IntermediateNode, JoinError> {
    if !chunk_payload.len().is_multiple_of(32) {
        return Err(JoinError::MalformedChunk {
            offset,
            detail: format!(
                "intermediate payload len {} not a multiple of 32",
                chunk_payload.len()
            ),
        });
    }
    // Bee's splitter zero-pads trailing ref slots when the last
    // branch doesn't fill the chunk. Strip those before computing
    // `refs`, otherwise we dispatch `fetch([0u8; 32])` requests
    // that every peer rejects.
    let effective = effective_payload_size(chunk_payload);
    if effective == 0 {
        return Err(JoinError::MalformedChunk {
            offset,
            detail: "intermediate chunk has no non-zero refs".into(),
        });
    }
    let chunk_payload = &chunk_payload[..effective];
    let refs = chunk_payload.len() / 32;
    if refs > MAX_BRANCHES {
        return Err(JoinError::MalformedChunk {
            offset,
            detail: format!("intermediate ref count {refs} out of range"),
        });
    }
    if parity >= refs {
        return Err(JoinError::MalformedChunk {
            offset,
            detail: format!(
                "redundant intermediate chunk holds {refs} refs but its span implies {parity} parities",
            ),
        });
    }
    let shard_cnt = refs - parity;

    let branching = if level == 0 {
        MAX_BRANCHES as u64
    } else {
        crate::rs::max_shards(level) as u64
    };
    let branch_size = subtrie_section(shard_cnt, subtree_span, branching);

    // Pre-compute (child_addr, child_span, child_offset) for every data
    // sibling so the walkers can run without touching the parent payload
    // again, and so the order is fixed before any I/O starts.
    let mut specs: Vec<(usize, [u8; 32], u64, u64)> = Vec::with_capacity(shard_cnt);
    let mut remaining = subtree_span;
    let mut child_offset = offset;
    for i in 0..shard_cnt {
        let mut child_addr = [0u8; 32];
        child_addr.copy_from_slice(&chunk_payload[i * 32..(i + 1) * 32]);
        // Last child carries whatever's left; siblings each cover a
        // full `branch_size` worth of file bytes.
        let child_span = if i == shard_cnt - 1 {
            remaining
        } else {
            branch_size.min(remaining)
        };
        specs.push((i, child_addr, child_span, child_offset));
        remaining = remaining.saturating_sub(child_span);
        child_offset = child_offset.saturating_add(child_span);
    }

    let mut parity_addrs = Vec::with_capacity(parity);
    for i in shard_cnt..refs {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&chunk_payload[i * 32..(i + 1) * 32]);
        parity_addrs.push(addr);
    }

    let decoder = (parity > 0).then(|| {
        let mut all = Vec::with_capacity(refs);
        for i in 0..refs {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&chunk_payload[i * 32..(i + 1) * 32]);
            all.push(addr);
        }
        std::sync::Arc::new(crate::rs::RsDecoder::new(all, shard_cnt))
    });

    Ok(IntermediateNode {
        specs,
        parity_addrs,
        decoder,
    })
}

/// Fetch one data child of an intermediate node: directly for plain
/// nodes, through the node's shared [`crate::rs::RsDecoder`] for
/// redundancy-encoded nodes (which transparently recovers the chunk
/// from parities on a miss).
///
/// A plain child's fetch waits up to `credit_budget` for peer credit
/// (issue #117); a redundant child's recovery retries run their own
/// credit window.
async fn fetch_child_chunk(
    fetcher: &dyn ChunkFetcher,
    decoder: Option<&std::sync::Arc<crate::rs::RsDecoder>>,
    index: usize,
    addr: [u8; 32],
    credit_budget: Duration,
) -> Result<Vec<u8>, JoinError> {
    match decoder {
        Some(d) => fetch_shard_with_recovery_retries(fetcher, d, index).await,
        None => fetcher
            .fetch_waiting_for_credit(addr, credit_budget)
            .await
            .map_err(|e| JoinError::FetchChunk {
                addr: hex::encode(addr),
                source: e,
            }),
    }
}

/// Fetch data shard `index` through a redundant node's decoder,
/// retrying a transient recovery failure with back-off within
/// [`RECOVERY_RETRY_ATTEMPTS`] / [`RECOVERY_RETRY_BUDGET`]. Each retry
/// starts with a fresh direct fetch and, if that misses, a fresh sweep
/// (the decoder doesn't cache transient failures). A permanent failure,
/// or a transient one that outlasts the budget, becomes a terminal
/// [`JoinError::Recovery`].
///
/// The budget is also the child's credit window: each direct fetch
/// waits for peer credit only within what is left of it, and the sweeps
/// never wait (issue #117).
async fn fetch_shard_with_recovery_retries(
    fetcher: &dyn ChunkFetcher,
    decoder: &crate::rs::RsDecoder,
    index: usize,
) -> Result<Vec<u8>, JoinError> {
    // The window opens when the first fetch starts, so the first sweep's
    // own duration counts against it too.
    let window = CreditWindow::new(RECOVERY_RETRY_BUDGET);
    for attempt in 1..=RECOVERY_RETRY_ATTEMPTS {
        match decoder
            .fetch_data_shard(fetcher, index, window.budget())
            .await
        {
            Ok(wire) => {
                if attempt > 1 {
                    tracing::debug!(
                        target: "ant_retrieval::joiner",
                        index,
                        attempt,
                        "erasure recovery succeeded on retry",
                    );
                }
                return Ok(wire);
            }
            Err(e) => {
                let backoff =
                    (RECOVERY_RETRY_BACKOFF * attempt as u32).min(RECOVERY_RETRY_BACKOFF_MAX);
                let retry = e.transient
                    && attempt < RECOVERY_RETRY_ATTEMPTS
                    && window.allows_retry(backoff);
                if !retry {
                    return Err(JoinError::Recovery { detail: e.detail });
                }
                tracing::debug!(
                    target: "ant_retrieval::joiner",
                    index,
                    attempt,
                    next_in_ms = backoff.as_millis() as u64,
                    "transient erasure recovery failure, retrying: {}",
                    e.detail,
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
    unreachable!("retry loop returns on the final attempt");
}

/// Recursive joiner core. Returns `subtree_span` bytes worth of file data,
/// given an intermediate or leaf chunk's *payload* (post-span) and the
/// declared span of the subtree it roots.
///
/// At each intermediate level we fan out up to [`FETCH_FANOUT`] sibling
/// subtrees in parallel. Each sibling builds into its own `Vec<u8>`,
/// then the parent concatenates completed subtrees in document order.
/// That keeps output ordering deterministic without forcing the
/// right-hand siblings to wait for every recursive fetch in the
/// left-hand subtree.
fn join_subtree<'a>(
    fetcher: &'a dyn ChunkFetcher,
    chunk_payload: &'a [u8],
    subtree_span: u64,
    offset: u64,
    level: u8,
    parity: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, JoinError>> + Send + 'a>> {
    Box::pin(async move {
        // Leaf: the chunk *is* the data. `subtree_span` was carried from
        // the parent ref so we don't even need to re-read this chunk's own
        // span; the payload bytes are already what we want.
        if subtree_span <= chunk_payload.len() as u64 {
            return Ok(chunk_payload[..subtree_span as usize].to_vec());
        }

        // Intermediate: payload must be `[ref32; N]`. We never accept
        // 64-byte (encrypted) refs in the joiner.
        let node = parse_intermediate(chunk_payload, subtree_span, offset, level, parity)?;
        let refs = node.specs.len();
        trace!(
            target: "ant_retrieval::joiner",
            refs,
            parity,
            level,
            subtree_span,
            fanout = FETCH_FANOUT.min(refs).max(1),
            "intermediate chunk",
        );

        // Fan out whole subtrees, not just the immediate child chunk
        // fetch. `buffer_unordered` avoids head-of-line blocking when an
        // early sibling is tail-slow; the index lets us restore byte
        // order before concatenating.
        let fanout = FETCH_FANOUT.min(refs).max(1);
        let decoder = node.decoder;
        let mut children = stream::iter(node.specs.into_iter().map(
            |(index, addr, child_span, child_offset)| {
                let decoder = decoder.clone();
                async move {
                    let child = join_child_with_retries(
                        fetcher,
                        decoder.as_ref(),
                        index,
                        addr,
                        child_span,
                        child_offset,
                    )
                    .await?;
                    Ok((index, child))
                }
            },
        ))
        .buffer_unordered(fanout);

        let mut pending = BTreeMap::new();
        let mut next_index = 0;
        let mut out = Vec::with_capacity(subtree_span as usize);
        while let Some((index, child)) = children.try_next().await? {
            pending.insert(index, child);
            while let Some(child) = pending.remove(&next_index) {
                out.extend_from_slice(&child);
                next_index += 1;
            }
        }
        Ok(out)
    })
}

#[allow(clippy::too_many_arguments)]
fn join_subtree_to_sender<'a>(
    fetcher: &'a dyn ChunkFetcher,
    chunk_payload: &'a [u8],
    subtree_span: u64,
    offset: u64,
    level: u8,
    parity: usize,
    out: &'a mpsc::Sender<Vec<u8>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), JoinError>> + Send + 'a>> {
    Box::pin(async move {
        if subtree_span <= chunk_payload.len() as u64 {
            out.send(chunk_payload[..subtree_span as usize].to_vec())
                .await
                .map_err(|_| JoinError::OutputClosed)?;
            return Ok(());
        }

        let node = parse_intermediate(chunk_payload, subtree_span, offset, level, parity)?;
        let refs = node.specs.len();
        let decoder = node.decoder;

        // Streaming pipelined fan-out. Each sibling subtree gets its own
        // bounded `mpsc::channel(STREAM_PIPE_DEPTH)`, so it can keep
        // producing chunks ahead of the in-order merger until its buffer
        // fills. The merger drains receivers strictly left-to-right, so
        // output stays in document order while later siblings can already
        // be fetching descendants. This is the streaming analogue of
        // bee's `errgroup.Group` model in `pkg/file/joiner.readAtOffset`,
        // and matches bee's "moving window" by way of the per-child
        // depth (the consumer-side `langos` buffer in bee).
        //
        // We bound concurrent producers with `buffer_unordered(fanout)`
        // so a deep tree doesn't spawn 128 simultaneous subtree workers
        // at the leaf level — the process-wide retrieval semaphore
        // remains the final cap, but this keeps the joiner's own
        // bookkeeping in check too.
        //
        // A sibling that has fetched its chunks frees its slot whether
        // or not the merger has reached it, so while the leftmost one is
        // slow the others pull in the rest of the window. Each data-chunk
        // fetch therefore carries its file offset
        // (`join_child_to_sender`), and the fetcher serves the ones
        // within `priority::HEAD_WINDOW` of the consumer's read position
        // first (issue #46).
        type ProducerFut<'b> =
            std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), JoinError>> + Send + 'b>>;
        let fanout = FETCH_FANOUT.min(refs).max(1);
        let mut child_rxs: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(refs);
        let mut producers: Vec<ProducerFut<'a>> = Vec::with_capacity(refs);
        for (index, addr, child_span, child_offset) in node.specs {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(STREAM_PIPE_DEPTH);
            child_rxs.push(rx);
            let decoder = decoder.clone();
            producers.push(Box::pin(async move {
                let r = join_child_to_sender(
                    fetcher,
                    decoder.as_ref(),
                    index,
                    addr,
                    child_span,
                    child_offset,
                    &tx,
                )
                .await;
                drop(tx);
                r
            }));
        }

        // Driver: run up to `fanout` producers concurrently and surface
        // the first error. Producers carry their own per-child sender,
        // so dropping the stream after a failure cleanly tears down
        // every in-flight subtree (their `tx` drops → the merger's `rx`
        // closes on the next read → joiner returns `OutputClosed`).
        let producers_drive = async move {
            let mut s = stream::iter(producers).buffer_unordered(fanout);
            while let Some(result) = s.next().await {
                result?;
            }
            Ok::<(), JoinError>(())
        };

        // Merger: drain receivers left-to-right and forward each
        // buffer downstream. `out.send` honours the consumer's own
        // back-pressure, which fans back up through this channel into
        // each child's bounded receiver, then into the producer that
        // blocks on `tx.send` once its window is full.
        let merger = async move {
            for mut rx in child_rxs {
                while let Some(buf) = rx.recv().await {
                    out.send(buf).await.map_err(|_| JoinError::OutputClosed)?;
                }
            }
            Ok::<(), JoinError>(())
        };

        tokio::try_join!(producers_drive, merger)?;
        Ok(())
    })
}

async fn join_child_to_sender(
    fetcher: &dyn ChunkFetcher,
    decoder: Option<&std::sync::Arc<crate::rs::RsDecoder>>,
    index: usize,
    addr: [u8; 32],
    child_span: u64,
    child_offset: u64,
    out: &mpsc::Sender<Vec<u8>>,
) -> Result<(), JoinError> {
    let child_chunk = priority::at_offset(
        child_offset,
        fetch_child_with_retries(fetcher, decoder, index, addr),
    )
    .await?;
    let (_, child_payload) = split_chunk(&child_chunk, child_offset)?;
    let (child_level, _, child_parity) = crate::rs::chunk_meta(&child_chunk).unwrap_or((0, 0, 0));
    join_subtree_to_sender(
        fetcher,
        child_payload,
        child_span,
        child_offset,
        child_level,
        child_parity,
        out,
    )
    .await
}

/// Streaming-path chunk fetch with in-place retries. Plain fetch misses
/// are retried with backoff (the pre-RS behavior for transient mainnet
/// misses). Erasure-recovery failures are not retried here: a transient
/// one was already retried by [`fetch_shard_with_recovery_retries`]
/// within its own budget, and a permanent one can't improve.
///
/// Each fetch waits for peer credit within the child's
/// [`STREAM_CREDIT_WINDOW`], and a starved miss is retried only inside it
/// ([`retry_child_miss`]), so the waits never add up past the window.
async fn fetch_child_with_retries(
    fetcher: &dyn ChunkFetcher,
    decoder: Option<&std::sync::Arc<crate::rs::RsDecoder>>,
    index: usize,
    addr: [u8; 32],
) -> Result<Vec<u8>, JoinError> {
    let window = CreditWindow::new(STREAM_CREDIT_WINDOW);
    for attempt in 1..=SUBTREE_RETRY_ATTEMPTS {
        match fetch_child_chunk(fetcher, decoder, index, addr, window.budget()).await {
            Ok(chunk) => return Ok(chunk),
            Err(e @ JoinError::FetchChunk { .. }) => {
                let backoff = subtree_retry_backoff(attempt);
                if !retry_child_miss(fetcher, &e, attempt, &window, backoff) {
                    return Err(e);
                }
                drop(e);
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("retry loop returns on the final attempt");
}

/// Back-off before subtree retry `attempt + 1`.
fn subtree_retry_backoff(attempt: usize) -> Duration {
    Duration::from_millis(250 * attempt as u64)
}

/// Retry a child whose fetch failed with `err` on `attempt`, after
/// sleeping `backoff`? The one rule both joiners' subtree retry loops
/// share: only a [`JoinError::FetchChunk`], at most
/// [`SUBTREE_RETRY_ATTEMPTS`] times, and a miss on an overdraft-starved
/// pool ([`fetch_chunk_pool_starved`]) only while the retry still starts
/// inside the child's credit `window` — that fetch already waited for
/// credit, and retrying it past the window would stack another wait.
///
/// The window bound applies only when `fetcher` actually waits for
/// credit ([`ChunkFetcher::waits_for_credit`]). A never-waiting fetcher
/// (the manifest sniff's [`crate::mantaray`] fallback join, traversal's
/// [`crate::NoCreditWait`]) has no wait to stack, so its starved misses
/// keep all [`SUBTREE_RETRY_ATTEMPTS`] retries, as before #117 — capping
/// them at the window would leave a starved pool only a few seconds of
/// back-off to refill in, with no credit wait to make up for it.
fn retry_child_miss(
    fetcher: &dyn ChunkFetcher,
    err: &JoinError,
    attempt: usize,
    window: &CreditWindow,
    backoff: Duration,
) -> bool {
    matches!(err, JoinError::FetchChunk { .. })
        && attempt < SUBTREE_RETRY_ATTEMPTS
        && (!fetcher.waits_for_credit()
            || !fetch_chunk_pool_starved(err)
            || window.allows_retry(backoff))
}

/// Did a child fetch end because the fetcher's peer pool stayed
/// overdraft-starved ([`crate::fetcher::FetchExhausted::pool_starved`])?
fn fetch_chunk_pool_starved(err: &JoinError) -> bool {
    match err {
        JoinError::FetchChunk { source, .. } => source
            .downcast_ref::<crate::fetcher::FetchExhausted>()
            .is_some_and(|x| x.pool_starved),
        _ => false,
    }
}

/// Range-aware version of [`join_subtree_to_sender`].
///
/// `range` is expressed against the **whole file**, not the subtree. The
/// caller passes the subtree's absolute `offset` and `subtree_span` so
/// every level can convert "which part of this subtree falls inside the
/// requested range?" into chunk-local terms without rebuilding state.
///
/// At an intermediate level we drop child subtrees that fall entirely
/// outside `[start, end]` (no fetch issued at all) and recurse only into
/// the ones that overlap. The leftmost overlapping leaf is sliced to
/// drop any prefix before `range.start`; the rightmost is truncated at
/// `range.end_inclusive + 1`. Output stays strictly in file order so
/// the gateway can pipe it straight into the HTTP response body.
#[allow(clippy::too_many_arguments)]
fn join_subtree_range_to_sender<'a>(
    fetcher: &'a dyn ChunkFetcher,
    chunk_payload: &'a [u8],
    subtree_span: u64,
    offset: u64,
    level: u8,
    parity: usize,
    range: ByteRange,
    out: &'a mpsc::Sender<Vec<u8>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), JoinError>> + Send + 'a>> {
    Box::pin(async move {
        let subtree_end = offset.saturating_add(subtree_span);
        // The caller already filtered overlapping subtrees; defensive
        // bound check keeps a buggy descent from emitting stray bytes.
        if subtree_end <= range.start || offset > range.end_inclusive {
            return Ok(());
        }

        if subtree_span <= chunk_payload.len() as u64 {
            // Leaf. Slice down to the file-relative window.
            let leaf = &chunk_payload[..subtree_span as usize];
            let leaf_start = offset;
            let leaf_end_excl = offset + subtree_span;
            let lo = range.start.max(leaf_start) - leaf_start;
            let hi = (range.end_inclusive + 1).min(leaf_end_excl) - leaf_start;
            if lo >= hi {
                return Ok(());
            }
            out.send(leaf[lo as usize..hi as usize].to_vec())
                .await
                .map_err(|_| JoinError::OutputClosed)?;
            return Ok(());
        }

        let node = parse_intermediate(chunk_payload, subtree_span, offset, level, parity)?;
        let decoder = node.decoder;

        // Keep only the children whose
        // [child_offset, child_offset+child_span) overlaps the range.
        let specs: Vec<(usize, [u8; 32], u64, u64)> = node
            .specs
            .into_iter()
            .filter(|&(_, _, child_span, child_offset)| {
                let child_end = child_offset + child_span;
                child_end > range.start && child_offset <= range.end_inclusive
            })
            .collect();

        if specs.is_empty() {
            return Ok(());
        }

        // Walk overlapping children in document order. We can't use the
        // unordered fan-out trick from the full-file path because the
        // sliced leftmost / rightmost children must reach the consumer
        // in order. Inner full-coverage subtrees are still parallelised
        // by [`join_subtree_to_sender`] when we descend into them via
        // `join_child_to_sender`.
        for (index, addr, child_span, child_offset) in specs {
            let child_end = child_offset + child_span;
            let fully_inside = child_offset >= range.start && child_end <= range.end_inclusive + 1;
            if fully_inside {
                join_child_to_sender(
                    fetcher,
                    decoder.as_ref(),
                    index,
                    addr,
                    child_span,
                    child_offset,
                    out,
                )
                .await?;
            } else {
                join_child_range_to_sender(
                    fetcher,
                    decoder.as_ref(),
                    index,
                    addr,
                    child_span,
                    child_offset,
                    range,
                    out,
                )
                .await?;
            }
        }
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
async fn join_child_range_to_sender(
    fetcher: &dyn ChunkFetcher,
    decoder: Option<&std::sync::Arc<crate::rs::RsDecoder>>,
    index: usize,
    addr: [u8; 32],
    child_span: u64,
    child_offset: u64,
    range: ByteRange,
    out: &mpsc::Sender<Vec<u8>>,
) -> Result<(), JoinError> {
    let child_chunk = priority::at_offset(
        child_offset,
        fetch_child_with_retries(fetcher, decoder, index, addr),
    )
    .await?;
    let (_, child_payload) = split_chunk(&child_chunk, child_offset)?;
    let (child_level, _, child_parity) = crate::rs::chunk_meta(&child_chunk).unwrap_or((0, 0, 0));
    join_subtree_range_to_sender(
        fetcher,
        child_payload,
        child_span,
        child_offset,
        child_level,
        child_parity,
        range,
        out,
    )
    .await
}

/// Buffered-path child join with in-place retries: the same rule as the
/// streaming [`fetch_child_with_retries`] ([`retry_child_miss`]), over
/// the child's [`BUFFERED_CREDIT_WINDOW`].
async fn join_child_with_retries(
    fetcher: &dyn ChunkFetcher,
    decoder: Option<&std::sync::Arc<crate::rs::RsDecoder>>,
    index: usize,
    addr: [u8; 32],
    child_span: u64,
    child_offset: u64,
) -> Result<Vec<u8>, JoinError> {
    let window = CreditWindow::new(BUFFERED_CREDIT_WINDOW);
    for attempt in 1..=SUBTREE_RETRY_ATTEMPTS {
        match join_child_once(
            fetcher,
            decoder,
            index,
            addr,
            child_span,
            child_offset,
            window.budget(),
        )
        .await
        {
            Ok(child) => return Ok(child),
            Err(e) => {
                let backoff = subtree_retry_backoff(attempt);
                if !retry_child_miss(fetcher, &e, attempt, &window, backoff) {
                    return Err(e);
                }
                tokio::time::sleep(backoff).await;
            }
        }
    }
    unreachable!("retry loop returns on the final attempt");
}

async fn join_child_once(
    fetcher: &dyn ChunkFetcher,
    decoder: Option<&std::sync::Arc<crate::rs::RsDecoder>>,
    index: usize,
    addr: [u8; 32],
    child_span: u64,
    child_offset: u64,
    credit_budget: Duration,
) -> Result<Vec<u8>, JoinError> {
    let child_chunk = fetch_child_chunk(fetcher, decoder, index, addr, credit_budget).await?;
    let (_, child_payload) = split_chunk(&child_chunk, child_offset)?;
    let (child_level, _, child_parity) = crate::rs::chunk_meta(&child_chunk).unwrap_or((0, 0, 0));
    join_subtree(
        fetcher,
        child_payload,
        child_span,
        child_offset,
        child_level,
        child_parity,
    )
    .await
}

/// Split `[span (8 LE) || payload]` into its two parts, with a positional
/// hint (`offset` in the file) for diagnostics.
fn split_chunk(data: &[u8], offset: u64) -> Result<([u8; 8], &[u8]), JoinError> {
    if data.len() < 8 {
        return Err(JoinError::MalformedChunk {
            offset,
            detail: format!("chunk shorter than span ({} bytes)", data.len()),
        });
    }
    let mut span = [0u8; 8];
    span.copy_from_slice(&data[..8]);
    Ok((span, &data[8..]))
}

/// Effective payload size of an intermediate chunk: trailing 32-byte
/// all-zero ref slots are zero-padding, not real children.
///
/// Mirrors `bee/pkg/file/utils.go::ChunkPayloadSize`. The splitter that
/// produces intermediate chunks always writes a `[ref; N]` array, but
/// when the file's last branch isn't full it leaves the trailing slots
/// zeroed. The joiner has to drop those slots before iterating —
/// otherwise it dispatches `fetch([0u8; 32])` requests to peers, which
/// bee's retrieval handler rejects with `invalid address queried by
/// peer …`. (We saw this in the wild as a 30s timeout flood when
/// serving a feed-backed `.eth` site whose index document was a 12-ref
/// intermediate chunk in a 128-slot payload — 116 spurious fetches per
/// request.)
///
/// Returns the byte length up to and including the last non-zero
/// 32-byte slot, rounded up to a 32-byte boundary. Callers slice with
/// `payload[..effective_payload_size(payload)]` before computing
/// `refs`. An all-zero payload yields `0`, which the caller surfaces
/// as a malformed chunk (intermediate payloads must hold at least one
/// child).
fn effective_payload_size(payload: &[u8]) -> usize {
    const HASH: usize = 32;
    let mut l = payload.len();
    // Don't overshoot a non-multiple-of-32 payload; outer code already
    // rejects those, but be defensive.
    l -= l % HASH;
    while l >= HASH {
        if payload[l - HASH..l].iter().any(|&b| b != 0) {
            return l;
        }
        l -= HASH;
    }
    0
}

/// Compute the per-child subtrie capacity of an intermediate chunk with
/// `refs` **data** children and total span `subtree_span`.
///
/// Mirrors `bee/pkg/file/joiner.subtrieSection`: starting from one chunk
/// (`4096`), grow by the branching factor until the last child fits
/// within `branch_size`. The first `refs-1` children are full subtrees of
/// `branch_size` bytes; the last child holds the remainder. The branching
/// factor is 128 for plain trees and the level's `maxShards` for
/// redundancy-encoded trees (full nodes hold that many data refs).
pub(crate) const fn subtrie_section(refs: usize, subtree_span: u64, branching: u64) -> u64 {
    let refs = refs as u64;
    let mut branch_size = CHUNK_SIZE as u64;
    loop {
        // What's left over for the rightmost child if every other child
        // filled `branch_size`. Once that fits, we're done.
        let whats_left = subtree_span.saturating_sub(branch_size * refs.saturating_sub(1));
        if whats_left <= branch_size {
            return branch_size;
        }
        // Defend against a malformed `subtree_span` that would loop forever
        // (refs is bounded by 128, so `branching^4 = 256M` is already far
        // above any sane file size given our 32 MiB cap).
        if branch_size > u64::MAX / branching {
            return branch_size;
        }
        branch_size *= branching;
    }
}

/// Reconstruct a file from a 64-byte **encrypted** root reference
/// (`address(32) ‖ key(32)`) into a single buffer.
///
/// This is the read-path mirror of bee's decrypting joiner
/// (`pkg/encryption/store` wrapping `pkg/file/joiner`): every chunk is
/// fetched by its 32-byte address, decrypted with the key carried in the
/// reference that pointed to it, then either appended as leaf data or
/// expanded into its list of 64-byte child references. Child decryption
/// keys come from those child references, so the whole subtree is
/// self-describing once the root key is known. Redundancy-encoded spans
/// (`level | 0x80` in the top byte) are handled like bee's
/// `DecryptChunkData`: the intermediate's payload is `shards` 64-byte
/// data references followed by `parities` 32-byte parity references
/// (encrypted-erasure-table geometry). When a data child of such a node
/// cannot be fetched, it is Reed-Solomon **recovered** from the node's
/// remaining siblings + parities through a per-node
/// [`crate::rs::RsDecoder`] in encrypted mode: parities were computed
/// over the children's *ciphertext* wires, so recovery reconstructs the
/// ciphertext, CAC-validates it against the address half of the child's
/// 64-byte reference, feeds it back via
/// [`ChunkFetcher::put_recovered`], and only then decrypts with the key
/// half. Over-loss (more than `parityCnt` unreachable children of one
/// node) is a terminal [`JoinError::Recovery`]. The root chunk fetch
/// additionally falls back to the root's dispersed replicas
/// ([`crate::rs::fetch_root_with_replicas`], keyed on the 32-byte
/// address half — the replica wraps the *encrypted* root chunk), like
/// bee wrapping the root getter in `replicas.NewGetter`.
///
/// Unlike [`join`] this is a buffered, in-order full download — no range
/// or streaming. It backs encrypted feed content and the gateway's
/// `/bytes`+`/bzz` reads of 128-hex references; `max_bytes` bounds the
/// allocation and range requests over encrypted content fall back to a
/// full fetch at the gateway.
///
/// Never waits for peer credit (issue #117): the walk is in order and
/// buffered, with no in-place retry, so a credit wait per chunk would add
/// up across the whole file inside one body stall. Every fetch, the
/// shards' recovery included, fails at once on a starved pool, as before
/// #117.
pub async fn join_encrypted(
    fetcher: &dyn ChunkFetcher,
    root_ref: [u8; ENCRYPTED_REF_SIZE],
    max_bytes: usize,
) -> Result<Vec<u8>, JoinError> {
    let fetcher = &crate::NoCreditWait(fetcher);
    let mut out = Vec::new();
    join_encrypted_into(fetcher, root_ref, EncFetch::Root, max_bytes, &mut out).await?;
    Ok(out)
}

/// How an encrypted node's *stored* (ciphertext) wire is fetched.
enum EncFetch {
    /// The tree root: direct fetch with dispersed-replica fallback
    /// (replicas are keyed on the root's 32-byte address half; bee's
    /// joiner likewise wraps only the root getter in
    /// `replicas.NewGetter`).
    Root,
    /// Child of a non-redundant node: direct fetch, a miss fails the
    /// join.
    Plain,
    /// Data shard `index` of a redundancy-encoded parent: fetched
    /// through the parent's shared [`crate::rs::RsDecoder`], which
    /// recovers the ciphertext wire from siblings + parities on a miss.
    Shard(std::sync::Arc<crate::rs::RsDecoder>, usize),
}

/// Recursive worker for [`join_encrypted`]. Boxed because the recursion is
/// async (a node expands into child nodes of the same future type).
fn join_encrypted_into<'a>(
    fetcher: &'a dyn ChunkFetcher,
    node_ref: [u8; ENCRYPTED_REF_SIZE],
    via: EncFetch,
    max_bytes: usize,
    out: &'a mut Vec<u8>,
) -> Pin<Box<dyn Future<Output = Result<(), JoinError>> + Send + 'a>> {
    Box::pin(async move {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&node_ref[..32]);
        let mut key = [0u8; ant_crypto::KEY_LENGTH];
        key.copy_from_slice(&node_ref[32..]);

        // Fetch the stored *ciphertext* wire. Recovery (the `Shard` arm)
        // and the replica fallback both validate the wire against `addr`
        // before it is handed back; decryption with `key` only happens
        // after that.
        let stored = match via {
            EncFetch::Root => crate::rs::fetch_root_with_replicas(fetcher, addr, Duration::ZERO)
                .await
                .map_err(|source| JoinError::FetchChunk {
                    addr: hex::encode(addr),
                    source,
                })?,
            EncFetch::Plain => {
                fetcher
                    .fetch(addr)
                    .await
                    .map_err(|source| JoinError::FetchChunk {
                        addr: hex::encode(addr),
                        source,
                    })?
            }
            EncFetch::Shard(decoder, index) => {
                fetch_shard_with_recovery_retries(fetcher, &decoder, index).await?
            }
        };
        let (span_raw, payload) = ant_crypto::decrypt_chunk_parts(&stored, &key).map_err(|e| {
            JoinError::MalformedChunk {
                offset: out.len() as u64,
                detail: format!("decrypt chunk {}: {e}", hex::encode(addr)),
            }
        })?;

        // The decrypted span may carry a redundancy level in its top byte
        // (bee `redundancy.DecodeSpan`); the rest is the plain byte count.
        let (level, plain_span) = crate::rs::decode_span(span_raw);
        let span = u64::from_le_bytes(plain_span);
        if span > max_bytes as u64 {
            return Err(JoinError::TooLarge {
                span,
                cap: max_bytes,
            });
        }

        // Leaf: any subtree of at most one chunk is stored as a single
        // data chunk whose payload is exactly the file bytes (the rest of
        // the fixed 4096-byte encrypted payload is padding).
        if span <= CHUNK_SIZE as u64 {
            let n = span as usize;
            if n > payload.len() {
                return Err(JoinError::MalformedChunk {
                    offset: out.len() as u64,
                    detail: format!("leaf span {n} exceeds payload {}", payload.len()),
                });
            }
            if out.len().saturating_add(n) > max_bytes {
                return Err(JoinError::TooLarge {
                    span: out.len().saturating_add(n) as u64,
                    cap: max_bytes,
                });
            }
            out.extend_from_slice(&payload[..n]);
            return Ok(());
        }

        // Intermediate: `shards` 64-byte data references, then `parities`
        // 32-byte parity references (level 0 has none), then padding —
        // bee `DecryptChunkData` + `file.ReferenceCount(_, _, encrypted)`.
        let (shards, parities) = crate::rs::reference_count_enc(span, level);
        let needed = shards * ENCRYPTED_REF_SIZE + parities * 32;
        if needed > payload.len() {
            return Err(JoinError::MalformedChunk {
                offset: out.len() as u64,
                detail: format!(
                    "intermediate needs {needed} reference bytes, payload has {}",
                    payload.len()
                ),
            });
        }
        // Redundancy-encoded node: share one ciphertext-space decoder
        // across this node's data children. Its address list is the
        // 32-byte address halves of the 64-byte data refs followed by
        // the bare 32-byte parity refs — exactly bee's
        // `file.ChunkAddresses(payload, parities, 64)`.
        let decoder = (parities > 0).then(|| {
            let mut all: Vec<[u8; 32]> = Vec::with_capacity(shards + parities);
            for i in 0..shards {
                let mut a = [0u8; 32];
                a.copy_from_slice(&payload[i * ENCRYPTED_REF_SIZE..i * ENCRYPTED_REF_SIZE + 32]);
                all.push(a);
            }
            let parity_base = shards * ENCRYPTED_REF_SIZE;
            for i in 0..parities {
                let mut a = [0u8; 32];
                a.copy_from_slice(&payload[parity_base + i * 32..parity_base + (i + 1) * 32]);
                all.push(a);
            }
            std::sync::Arc::new(crate::rs::RsDecoder::new_encrypted(all, shards))
        });

        let branching = crate::rs::max_enc_shards(level) as u64;
        let branch_size = subtrie_section(shards, span, branching);
        let mut remaining = span;
        for i in 0..shards {
            if remaining == 0 {
                break;
            }
            let mut child = [0u8; ENCRYPTED_REF_SIZE];
            child.copy_from_slice(&payload[i * ENCRYPTED_REF_SIZE..(i + 1) * ENCRYPTED_REF_SIZE]);
            let via = match &decoder {
                Some(d) => EncFetch::Shard(d.clone(), i),
                None => EncFetch::Plain,
            };
            join_encrypted_into(fetcher, child, via, max_bytes, out).await?;
            remaining = remaining.saturating_sub(branch_size.min(remaining));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::cac_new;
    use std::collections::{HashMap, HashSet};
    use std::error::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// HashMap-backed fetcher for tests. Pre-populated with whatever
    /// chunks the test wants the joiner to find.
    struct MapFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
    }

    impl MapFetcher {
        fn new() -> Self {
            Self {
                chunks: HashMap::new(),
            }
        }
        fn insert(&mut self, addr: [u8; 32], wire: Vec<u8>) {
            self.chunks.insert(addr, wire);
        }
    }

    #[async_trait::async_trait]
    impl crate::ChunkFetcher for MapFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            // Worded like `RoutingFetcher`'s give-up after peers answered
            // bee's `storage: not found`, so the RS decoder reads an
            // absent chunk as denied (permanent once denied for
            // `rs::MISS_CONFIRM_AFTER`), not as a peer-pool shortage.
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> {
                    format!(
                        "missing chunk {} (last: remote: storage: not found)",
                        hex::encode(addr)
                    )
                    .into()
                })
        }
    }

    /// Fetcher that makes selected leaf chunks linger long enough for
    /// the test to observe whether independent subtrees overlap.
    struct ObservedFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
        delayed: HashSet<[u8; 32]>,
        active_delayed: AtomicUsize,
        max_active_delayed: AtomicUsize,
    }

    impl ObservedFetcher {
        fn new() -> Self {
            Self {
                chunks: HashMap::new(),
                delayed: HashSet::new(),
                active_delayed: AtomicUsize::new(0),
                max_active_delayed: AtomicUsize::new(0),
            }
        }

        fn insert(&mut self, addr: [u8; 32], wire: Vec<u8>) {
            self.chunks.insert(addr, wire);
        }

        fn insert_delayed(&mut self, addr: [u8; 32], wire: Vec<u8>) {
            self.delayed.insert(addr);
            self.insert(addr, wire);
        }

        fn max_active_delayed(&self) -> usize {
            self.max_active_delayed.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::ChunkFetcher for ObservedFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if self.delayed.contains(&addr) {
                let active = self.active_delayed.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active_delayed.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(25)).await;
                self.active_delayed.fetch_sub(1, Ordering::SeqCst);
            }

            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> {
                    format!("missing chunk {}", hex::encode(addr)).into()
                })
        }
    }

    /// Single-chunk file: the root *is* the data. No intermediate chunks
    /// are fetched; we don't need a populated map.
    #[tokio::test]
    async fn joins_single_chunk_file() {
        let payload = b"hello swarm".to_vec();
        let (_, wire) = cac_new(&payload).unwrap();
        let fetcher = MapFetcher::new();
        let out = join(&fetcher, &wire, DEFAULT_MAX_FILE_BYTES).await.unwrap();
        assert_eq!(out, payload);
    }

    /// 5 KiB file: root has two child refs (4096 + 1024). Verifies the
    /// last-child remainder math and the leaf-chunk truncation.
    #[tokio::test]
    async fn joins_two_chunk_file() {
        // Two leaf chunks: 4096 + 1024 bytes.
        let leaf_a = vec![0xaa; CHUNK_SIZE];
        let leaf_b = vec![0xbb; 1024];
        let (addr_a, wire_a) = cac_new(&leaf_a).unwrap();
        let (addr_b, wire_b) = cac_new(&leaf_b).unwrap();

        // Build the root chunk: span = 5120, payload = addr_a || addr_b.
        let mut intermediate_payload = Vec::new();
        intermediate_payload.extend_from_slice(&addr_a);
        intermediate_payload.extend_from_slice(&addr_b);
        let span: u64 = (CHUNK_SIZE + 1024) as u64;
        let mut root_wire = Vec::with_capacity(8 + intermediate_payload.len());
        root_wire.extend_from_slice(&span.to_le_bytes());
        root_wire.extend_from_slice(&intermediate_payload);

        let mut fetcher = MapFetcher::new();
        fetcher.insert(addr_a, wire_a);
        fetcher.insert(addr_b, wire_b);

        let out = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap();
        assert_eq!(out.len(), span as usize);
        assert!(out[..CHUNK_SIZE].iter().all(|&b| b == 0xaa));
        assert!(out[CHUNK_SIZE..].iter().all(|&b| b == 0xbb));
    }

    /// File large enough to require a third level: 130 leaves of 4 KiB
    /// (a touch over 128 chunks → root must point at two intermediate
    /// chunks, the first holding 128 leaves and the second holding 2).
    /// Exercises `subtrie_section` non-trivially.
    #[tokio::test]
    async fn joins_three_level_tree() {
        let mut fetcher = MapFetcher::new();
        let mut leaf_addrs = Vec::with_capacity(130);
        let mut expected: Vec<u8> = Vec::with_capacity(130 * CHUNK_SIZE);
        for i in 0..130u8 {
            let payload = vec![i; CHUNK_SIZE];
            let (addr, wire) = cac_new(&payload).unwrap();
            fetcher.insert(addr, wire);
            leaf_addrs.push(addr);
            expected.extend_from_slice(&payload);
        }

        // First intermediate: 128 leaves, span = 128 * 4096 = 524288.
        let mut int1_payload = Vec::with_capacity(128 * 32);
        for addr in &leaf_addrs[..128] {
            int1_payload.extend_from_slice(addr);
        }
        let int1_span: u64 = 128 * CHUNK_SIZE as u64;
        let mut int1_wire = Vec::new();
        int1_wire.extend_from_slice(&int1_span.to_le_bytes());
        int1_wire.extend_from_slice(&int1_payload);
        let (int1_addr, int1_full) = (chunk_addr(&int1_payload, int1_span), int1_wire.clone());
        fetcher.insert(int1_addr, int1_full);

        // Second intermediate: 2 leaves, span = 2 * 4096 = 8192.
        let mut int2_payload = Vec::with_capacity(2 * 32);
        for addr in &leaf_addrs[128..] {
            int2_payload.extend_from_slice(addr);
        }
        let int2_span: u64 = 2 * CHUNK_SIZE as u64;
        let mut int2_wire = Vec::new();
        int2_wire.extend_from_slice(&int2_span.to_le_bytes());
        int2_wire.extend_from_slice(&int2_payload);
        let (int2_addr, int2_full) = (chunk_addr(&int2_payload, int2_span), int2_wire.clone());
        fetcher.insert(int2_addr, int2_full);

        // Root: 2 children with total span = 130 * 4096 = 532480.
        let mut root_payload = Vec::with_capacity(64);
        root_payload.extend_from_slice(&int1_addr);
        root_payload.extend_from_slice(&int2_addr);
        let total_span: u64 = 130 * CHUNK_SIZE as u64;
        let mut root_wire = Vec::new();
        root_wire.extend_from_slice(&total_span.to_le_bytes());
        root_wire.extend_from_slice(&root_payload);

        let out = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap();
        assert_eq!(out.len(), expected.len());
        assert_eq!(&out[..256], &expected[..256], "leading prefix");
        assert_eq!(
            &out[out.len() - 256..],
            &expected[expected.len() - 256..],
            "trailing"
        );
    }

    /// Two large L1 subtrees should overlap while joining. The previous
    /// implementation fetched both L1 chunks in parallel, then recursively
    /// joined the left L1 subtree to completion before starting the right
    /// one, so delayed leaf fetch concurrency never exceeded
    /// `FETCH_FANOUT`. The fixed joiner builds sibling subtrees in
    /// parallel and restores byte order at the parent.
    #[tokio::test]
    async fn joins_sibling_subtrees_in_parallel() {
        let mut fetcher = ObservedFetcher::new();
        let mut intermediate_addrs = Vec::with_capacity(2);
        let mut expected: Vec<u8> = Vec::with_capacity(256 * CHUNK_SIZE);

        for group in 0..2u16 {
            let mut intermediate_payload = Vec::with_capacity(128 * 32);
            for leaf in 0..128u16 {
                let byte = ((group * 128 + leaf) % 251) as u8;
                let payload = vec![byte; CHUNK_SIZE];
                let (addr, wire) = cac_new(&payload).unwrap();
                fetcher.insert_delayed(addr, wire);
                intermediate_payload.extend_from_slice(&addr);
                expected.extend_from_slice(&payload);
            }

            let span = 128 * CHUNK_SIZE as u64;
            let mut wire = Vec::new();
            wire.extend_from_slice(&span.to_le_bytes());
            wire.extend_from_slice(&intermediate_payload);
            let addr = chunk_addr(&intermediate_payload, span);
            fetcher.insert(addr, wire);
            intermediate_addrs.push(addr);
        }

        let mut root_payload = Vec::with_capacity(2 * 32);
        for addr in &intermediate_addrs {
            root_payload.extend_from_slice(addr);
        }
        let total_span = expected.len() as u64;
        let mut root_wire = Vec::new();
        root_wire.extend_from_slice(&total_span.to_le_bytes());
        root_wire.extend_from_slice(&root_payload);

        let out = tokio::time::timeout(
            Duration::from_secs(5),
            join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES),
        )
        .await
        .expect("join timed out")
        .unwrap();

        assert_eq!(out, expected);
        assert!(
            fetcher.max_active_delayed() > FETCH_FANOUT,
            "expected delayed leaves from multiple L1 subtrees to overlap; max active was {}",
            fetcher.max_active_delayed()
        );
    }

    /// Cap is honored before any allocation happens. Even a manifestly
    /// dishonest root chunk (span = `u64::MAX`) is rejected promptly.
    #[tokio::test]
    async fn rejects_oversized_span() {
        let bogus_payload = vec![0u8; 32];
        // A span just over the cap exercises TooLarge.
        let span: u64 = (DEFAULT_MAX_FILE_BYTES as u64) + 1;
        let mut wire = Vec::new();
        wire.extend_from_slice(&span.to_le_bytes());
        wire.extend_from_slice(&bogus_payload);

        let fetcher = MapFetcher::new();
        let err = join(&fetcher, &wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, JoinError::TooLarge { .. }));

        // A top byte of 1..=128 is NOT a redundancy level (bee's
        // IsLevelEncoded needs > 128) — it reads as an absurd plain
        // span, which the cap rejects the same way.
        let mut wire = Vec::new();
        let mut span = [0u8; 8];
        span[7] = 1;
        wire.extend_from_slice(&span);
        wire.extend_from_slice(&bogus_payload);
        let err = join(&fetcher, &wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, JoinError::TooLarge { .. }));
    }

    /// A level-encoded span (`level | 0x80` in the top byte) on a
    /// single-leaf root decodes like a plain leaf: the level is
    /// stripped, the masked span is the payload length, and there are
    /// no parities to account for (replica fallback handles small
    /// redundant files; the tree itself is unchanged).
    #[tokio::test]
    async fn level_encoded_leaf_root_decodes() {
        let payload = b"hello swarm".to_vec();
        let (_, mut wire) = cac_new(&payload).unwrap();
        // Splice a level into the root span. The CAC address mismatch
        // doesn't matter here — we feed the wire bytes straight into
        // `join`, bypassing the per-chunk verifier.
        wire[7] = 3 | 0x80; // INSANE
        let fetcher = MapFetcher::new();
        let out = join(&fetcher, &wire, DEFAULT_MAX_FILE_BYTES).await.unwrap();
        assert_eq!(out, payload);
    }

    /// Build a level-1 redundant single-level tree the way bee's
    /// pipeline does: data leaves, RS-encode their padded wires into
    /// parity chunks, append the parity refs after the data refs, and
    /// mark the root span with `1 | 0x80`. Returns
    /// `(root_wire, leaf_addrs, expected_bytes)` with every chunk
    /// inserted into the fetcher.
    fn build_redundant_fixture(
        fetcher: &mut MapFetcher,
        leaves: usize,
        last_leaf_len: usize,
    ) -> (Vec<u8>, Vec<[u8; 32]>, Vec<u8>) {
        assert!(last_leaf_len <= CHUNK_SIZE);
        let mut shards: Vec<Vec<u8>> = Vec::new();
        let mut leaf_addrs = Vec::new();
        let mut expected = Vec::new();
        for i in 0..leaves {
            let len = if i == leaves - 1 {
                last_leaf_len
            } else {
                CHUNK_SIZE
            };
            let payload: Vec<u8> = (0..len).map(|b| (b as u8).wrapping_add(i as u8)).collect();
            let (addr, wire) = cac_new(&payload).unwrap();
            fetcher.insert(addr, wire.clone());
            leaf_addrs.push(addr);
            expected.extend_from_slice(&payload);
            let mut padded = wire;
            padded.resize(CHUNK_SIZE + 8, 0);
            shards.push(padded);
        }
        let parity_cnt = crate::rs::get_parities(1, leaves);
        let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(leaves, parity_cnt).unwrap();
        for _ in 0..parity_cnt {
            shards.push(vec![0u8; CHUNK_SIZE + 8]);
        }
        rs.encode(&mut shards).unwrap();

        let mut root_payload = Vec::new();
        for addr in &leaf_addrs {
            root_payload.extend_from_slice(addr);
        }
        for parity in &shards[leaves..] {
            // A parity chunk's wire *is* the encoded shard: bee stores
            // it with span = the first 8 encoded bytes.
            let span: [u8; 8] = parity[..8].try_into().unwrap();
            let addr = ant_crypto::bmt_hash_with_span(&span, &parity[8..]).unwrap();
            fetcher.insert(addr, parity.clone());
            root_payload.extend_from_slice(&addr);
        }

        let mut root_wire = Vec::new();
        let mut span = (expected.len() as u64).to_le_bytes();
        span[7] = 1 | 0x80; // MEDIUM
        root_wire.extend_from_slice(&span);
        root_wire.extend_from_slice(&root_payload);
        (root_wire, leaf_addrs, expected)
    }

    /// RS recovery end-to-end on a synthetic level-1 tree: with up to
    /// `parityCnt` data leaves missing (first and last included) the
    /// join still returns the exact bytes.
    #[tokio::test]
    async fn recovers_missing_data_chunks_from_parities() {
        let mut fetcher = MapFetcher::new();
        // 5 full leaves + a short tail = spans 4096*5 + 100; level 1
        // gives 4 parities for 6 shards.
        let (root_wire, leaf_addrs, expected) = build_redundant_fixture(&mut fetcher, 6, 100);
        // Delete first, last and one middle data leaf (3 <= 4 parities).
        fetcher.chunks.remove(&leaf_addrs[0]);
        fetcher.chunks.remove(&leaf_addrs[3]);
        fetcher.chunks.remove(&leaf_addrs[5]);

        let out = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap();
        assert_eq!(out, expected);
    }

    /// Losing more data chunks than the node has parities fails with a
    /// terminal `Recovery` error once peers have kept denying the lost
    /// shards for [`crate::rs::MISS_CONFIRM_AFTER`], well inside the
    /// recovery retry budget. Paused clock: the back-offs auto-advance.
    #[tokio::test(start_paused = true)]
    async fn over_loss_fails_cleanly() {
        let mut fetcher = MapFetcher::new();
        let (root_wire, leaf_addrs, _) = build_redundant_fixture(&mut fetcher, 6, 100);
        // 6 shards at level 1 → 4 parities; delete 5 data leaves.
        for addr in leaf_addrs.iter().take(5) {
            fetcher.chunks.remove(addr);
        }
        let err = tokio::time::timeout(
            RECOVERY_RETRY_BUDGET,
            join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES),
        )
        .await
        .expect("over-loss join must fail promptly, not hang")
        .unwrap_err();
        assert!(matches!(err, JoinError::Recovery { .. }), "got {err:?}");
    }

    /// A cold node's view of the network (issue #114): chunks in
    /// `starved` fail their first `starve_for` fetches the two ways a
    /// `RoutingFetcher` with an exhausted pool does — first with one
    /// peer's `storage: not found` and the rest overdraft-skipped
    /// (`FetchExhausted { pool_starved: true }`), then with `no BZZ
    /// peers available` — and serve normally after. Absent chunks
    /// answer like peers confirmed them missing.
    struct ColdPoolFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
        starved: HashSet<[u8; 32]>,
        starve_for: usize,
        calls: std::sync::Mutex<HashMap<[u8; 32], usize>>,
    }

    impl ColdPoolFetcher {
        fn new(map: MapFetcher, starve_for: usize) -> Self {
            Self {
                chunks: map.chunks,
                starved: HashSet::new(),
                starve_for,
                calls: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::ChunkFetcher for ColdPoolFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if self.starved.contains(&addr) {
                let mut calls = self.calls.lock().unwrap();
                let n = calls.entry(addr).or_insert(0);
                *n += 1;
                if *n <= self.starve_for {
                    if *n == 1 {
                        return Err(Box::new(crate::fetcher::FetchExhausted {
                            message: format!(
                                "all peers failed for chunk {} after 1 attempts \
                                 (last: remote: retrieve chunk: storage: not found)",
                                hex::encode(addr)
                            ),
                            pool_starved: true,
                            last_not_found: true,
                            not_found_answers: 1,
                        }));
                    }
                    return Err("no BZZ peers available".into());
                }
            }
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> {
                    format!(
                        "all peers failed for chunk {} after 3 attempts \
                         (last: remote: retrieve chunk: storage: not found)",
                        hex::encode(addr)
                    )
                    .into()
                })
        }
    }

    /// Issue #114: a recovery sweep that falls short only because the
    /// peer pool was momentarily exhausted is retried with a fresh
    /// sweep, and the join completes — through the streaming joiner
    /// (what `/bytes` and `/bzz` serve), a range of it, and the
    /// buffered joiner. Pre-fix the first sweep's failure was cached and
    /// returned as a terminal `Recovery` error mid-stream.
    // Paused clock: the retry back-off auto-advances.
    #[tokio::test(start_paused = true)]
    async fn transient_recovery_failure_is_retried_until_it_succeeds() {
        let mut map = MapFetcher::new();
        // 6 data + 4 parity shards.
        let (root_wire, leaf_addrs, expected) = build_redundant_fixture(&mut map, 6, 100);
        // One data leaf is really gone (recoverable from parities)...
        map.chunks.remove(&leaf_addrs[2]);
        // ...and on the first sweep every other shard is unreachable:
        // `no BZZ peers available`, like the cold-node field case.
        let shards: Vec<[u8; 32]> = map
            .chunks
            .keys()
            .copied()
            .filter(|a| !leaf_addrs.contains(a))
            .chain(leaf_addrs.iter().copied().filter(|a| *a != leaf_addrs[2]))
            .collect();

        let cold = |starve_for| {
            let mut m = MapFetcher::new();
            m.chunks = map.chunks.clone();
            let mut f = ColdPoolFetcher::new(m, starve_for);
            f.starved = shards.iter().copied().collect();
            f
        };

        // Streaming, whole body.
        let fetcher = cold(2);
        let (tx, mut rx) = mpsc::channel(256);
        let (res, body) = tokio::join!(
            join_to_sender(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                tx
            ),
            drain(&mut rx)
        );
        res.expect("streaming join must recover once the pool refills");
        assert_eq!(body, expected);

        // Streaming, a range that only touches the lost leaf.
        let fetcher = cold(2);
        let range = ByteRange::clamp(2 * 4096 + 10, 2 * 4096 + 99, expected.len() as u64).unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let (res, body) = tokio::join!(
            join_to_sender_range(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                Some(range),
                tx
            ),
            drain(&mut rx)
        );
        res.expect("range join must recover once the pool refills");
        assert_eq!(body, expected[2 * 4096 + 10..2 * 4096 + 100]);

        // Buffered.
        let fetcher = cold(2);
        let out = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .expect("buffered join must recover once the pool refills");
        assert_eq!(out, expected);
    }

    /// A cold node's "not found" (issue #79): chunks in `flaky` answer
    /// like peers denied them (`storage: not found`, an unstarved pool)
    /// on their first `misses` fetches, and serve normally after.
    struct DeniedThenServedFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
        flaky: HashSet<[u8; 32]>,
        misses: usize,
        calls: std::sync::Mutex<HashMap<[u8; 32], usize>>,
    }

    #[async_trait::async_trait]
    impl crate::ChunkFetcher for DeniedThenServedFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if self.flaky.contains(&addr) {
                let mut calls = self.calls.lock().unwrap();
                let n = calls.entry(addr).or_insert(0);
                *n += 1;
                if *n <= self.misses {
                    return Err(Box::new(crate::fetcher::FetchExhausted {
                        message: format!(
                            "all peers failed for chunk {} after 33 attempts \
                             (last: remote: retrieve chunk: storage: not found)",
                            hex::encode(addr)
                        ),
                        pool_starved: false,
                        last_not_found: true,
                        not_found_answers: 32,
                    }));
                }
            }
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> { "absent".into() })
        }
    }

    /// Issue #79: on a cold node, more shards of a redundant node than it
    /// has parities can come back "not found" from every peer asked and
    /// still be served a fetch or two later. That shortfall is transient
    /// until the misses have held for `MISS_CONFIRM_AFTER`, so the node
    /// sweeps again and the join completes — streaming (what `/bytes` and
    /// `/bzz` serve), a range of it, and buffered. Pre-fix the first
    /// sweep's answer was final and the stream ended after one leaf.
    #[tokio::test(start_paused = true)]
    async fn denied_shards_served_on_a_later_sweep_complete_the_join() {
        let mut map = MapFetcher::new();
        let (root_wire, leaf_addrs, expected) = build_redundant_fixture(&mut map, 6, 100);
        // 5 of 6 data shards denied; the node has only 4 parities.
        let flaky: HashSet<[u8; 32]> = leaf_addrs.iter().skip(1).copied().collect();
        let fetcher = || DeniedThenServedFetcher {
            chunks: map.chunks.clone(),
            flaky: flaky.clone(),
            misses: 2,
            calls: std::sync::Mutex::default(),
        };

        let fetcher_full = fetcher();
        let (tx, mut rx) = mpsc::channel(256);
        let (res, body) = tokio::join!(
            join_to_sender(
                &fetcher_full,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                tx
            ),
            drain(&mut rx)
        );
        res.expect("streaming join must sweep again for denied shards");
        assert_eq!(body, expected);

        let fetcher_range = fetcher();
        let range = ByteRange::clamp(4096 + 10, 3 * 4096 + 99, expected.len() as u64).unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let (res, body) = tokio::join!(
            join_to_sender_range(
                &fetcher_range,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                Some(range),
                tx
            ),
            drain(&mut rx)
        );
        res.expect("range join must sweep again for denied shards");
        assert_eq!(body, expected[4096 + 10..3 * 4096 + 100]);

        let out = join(&fetcher(), &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .expect("buffered join must sweep again for denied shards");
        assert_eq!(out, expected);
    }

    /// A pool that never refills still fails, and within the recovery
    /// budget rather than hanging the response.
    #[tokio::test(start_paused = true)]
    async fn transient_recovery_failure_gives_up_after_its_budget() {
        let mut map = MapFetcher::new();
        let (root_wire, leaf_addrs, _) = build_redundant_fixture(&mut map, 6, 100);
        map.chunks.remove(&leaf_addrs[2]);
        let starved: HashSet<[u8; 32]> = map.chunks.keys().copied().collect();
        let mut fetcher = ColdPoolFetcher::new(map, usize::MAX);
        fetcher.starved = starved;

        let started = tokio::time::Instant::now();
        let err = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, JoinError::Recovery { .. }), "got {err:?}");
        // Paused clock: only the retry back-off advances it.
        assert!(
            started.elapsed() <= RECOVERY_RETRY_BUDGET,
            "gave up after {:?}, budget {RECOVERY_RETRY_BUDGET:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() >= RECOVERY_RETRY_BACKOFF,
            "a transient failure must be retried before giving up"
        );
    }

    /// A plain (non-redundant) child whose pool stays starved: every
    /// credit-waiting fetch waits out its budget, so 32 subtree retries
    /// would stall the body for ~7 min (PR #119 R5-M1). The child's
    /// fetches wait, and a starved miss is retried, only within its
    /// `STREAM_CREDIT_WINDOW`, each wait capped at what is left of it, so
    /// the child gives up by the window's end — and is still retried
    /// before that.
    #[tokio::test(start_paused = true)]
    async fn starved_plain_child_retries_stay_inside_the_credit_window() {
        /// Models a starved `RoutingFetcher`: a credit-waiting fetch
        /// waits out its budget, plain `fetch` fails at once.
        struct StarvedFetcher {
            calls: AtomicUsize,
        }
        fn starved() -> Box<dyn Error + Send + Sync> {
            Box::new(crate::fetcher::FetchExhausted {
                message: "no BZZ peers available".into(),
                pool_starved: true,
                last_not_found: false,
                not_found_answers: 0,
            })
        }
        #[async_trait::async_trait]
        impl ChunkFetcher for StarvedFetcher {
            async fn fetch(
                &self,
                _addr: [u8; 32],
            ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(starved())
            }
            async fn fetch_waiting_for_credit(
                &self,
                _addr: [u8; 32],
                credit_budget: Duration,
            ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(credit_budget).await;
                Err(starved())
            }
            fn waits_for_credit(&self) -> bool {
                true
            }
        }
        let fetcher = StarvedFetcher {
            calls: AtomicUsize::new(0),
        };
        let started = tokio::time::Instant::now();
        let err = fetch_child_with_retries(&fetcher, None, 0, [7u8; 32])
            .await
            .unwrap_err();
        assert!(fetch_chunk_pool_starved(&err), "got {err:?}");
        assert!(
            started.elapsed() <= STREAM_CREDIT_WINDOW,
            "starved child stalled {:?}",
            started.elapsed()
        );
        let calls = fetcher.calls.load(Ordering::SeqCst);
        assert!(
            calls > 1 && calls < SUBTREE_RETRY_ATTEMPTS,
            "{calls} fetches"
        );
    }

    /// A fetcher that never waits for credit (the manifest sniff's
    /// fallback join, traversal's `NoCreditWait`) has no wait to stack,
    /// so a starved miss keeps every subtree retry, as before #117, in
    /// the buffered joiner as in the streaming one (PR #119 R1-M1) —
    /// rather than being cut off at `BUFFERED_CREDIT_WINDOW` after a few
    /// seconds of back-off. A waiting fetcher is still cut off there.
    #[tokio::test(start_paused = true)]
    async fn never_waiting_starved_child_keeps_all_subtree_retries() {
        struct StarvedFetcher {
            calls: AtomicUsize,
        }
        fn starved() -> Box<dyn Error + Send + Sync> {
            Box::new(crate::fetcher::FetchExhausted {
                message: "no BZZ peers available".into(),
                pool_starved: true,
                last_not_found: false,
                not_found_answers: 0,
            })
        }
        #[async_trait::async_trait]
        impl ChunkFetcher for StarvedFetcher {
            async fn fetch(
                &self,
                _addr: [u8; 32],
            ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(starved())
            }
            async fn fetch_waiting_for_credit(
                &self,
                _addr: [u8; 32],
                credit_budget: Duration,
            ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(credit_budget).await;
                Err(starved())
            }
            fn waits_for_credit(&self) -> bool {
                true
            }
        }

        // Never waiting: all retries, in both joiners.
        let inner = StarvedFetcher {
            calls: AtomicUsize::new(0),
        };
        let fetcher = crate::NoCreditWait(&inner);
        let started = tokio::time::Instant::now();
        let err = join_child_with_retries(&fetcher, None, 0, [7u8; 32], 8192, 0)
            .await
            .unwrap_err();
        assert!(fetch_chunk_pool_starved(&err), "got {err:?}");
        assert_eq!(inner.calls.load(Ordering::SeqCst), SUBTREE_RETRY_ATTEMPTS);
        assert!(started.elapsed() > BUFFERED_CREDIT_WINDOW);
        inner.calls.store(0, Ordering::SeqCst);
        fetch_child_with_retries(&fetcher, None, 0, [7u8; 32])
            .await
            .unwrap_err();
        assert_eq!(inner.calls.load(Ordering::SeqCst), SUBTREE_RETRY_ATTEMPTS);

        // Waiting: the buffered child gives up by its window's end.
        inner.calls.store(0, Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        join_child_with_retries(&inner, None, 0, [7u8; 32], 8192, 0)
            .await
            .unwrap_err();
        assert!(started.elapsed() <= BUFFERED_CREDIT_WINDOW);
        let calls = inner.calls.load(Ordering::SeqCst);
        assert!(calls < SUBTREE_RETRY_ATTEMPTS, "{calls} fetches");
    }

    /// A non-starved miss keeps the full subtree retry count: a fast
    /// failure costs no credit wait, so the window bound doesn't apply.
    #[tokio::test(start_paused = true)]
    async fn unstarved_plain_child_keeps_all_subtree_retries() {
        struct MissFetcher {
            calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl ChunkFetcher for MissFetcher {
            async fn fetch(
                &self,
                _addr: [u8; 32],
            ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(Box::new(crate::fetcher::FetchExhausted {
                    message: "timed out".into(),
                    pool_starved: false,
                    last_not_found: false,
                    not_found_answers: 0,
                }))
            }
        }
        let fetcher = MissFetcher {
            calls: AtomicUsize::new(0),
        };
        fetch_child_with_retries(&fetcher, None, 0, [7u8; 32])
            .await
            .unwrap_err();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), SUBTREE_RETRY_ATTEMPTS);
    }

    /// Real data loss stays terminal: more shards denied than the node
    /// has parities fails once peers have kept denying them for
    /// [`crate::rs::MISS_CONFIRM_AFTER`] (issue #79), not after the whole
    /// recovery budget, even though other shards were also starved of
    /// peers. Paused clock: the back-offs auto-advance.
    #[tokio::test(start_paused = true)]
    async fn confirmed_shard_loss_fails_once_the_misses_are_confirmed() {
        let mut map = MapFetcher::new();
        let (root_wire, leaf_addrs, _) = build_redundant_fixture(&mut map, 6, 100);
        // 5 of 10 shards confirmed missing; 4 parities can't cover it.
        for addr in leaf_addrs.iter().take(5) {
            map.chunks.remove(addr);
        }
        let starved: HashSet<[u8; 32]> = map.chunks.keys().copied().collect();
        let mut fetcher = ColdPoolFetcher::new(map, 1);
        fetcher.starved = starved;

        let started = tokio::time::Instant::now();
        let err = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, JoinError::Recovery { .. }), "got {err:?}");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= crate::rs::MISS_CONFIRM_AFTER,
            "a miss must be confirmed before it is final ({elapsed:?})",
        );
        assert!(
            elapsed < crate::rs::MISS_CONFIRM_AFTER + RECOVERY_RETRY_BACKOFF_MAX,
            "permanent loss must fail once confirmed, not wait out the budget ({elapsed:?})",
        );
    }

    /// Every absent chunk is denied only after `delay`, like a mainnet
    /// fetch that walks its peers before they all answer "not found".
    struct SlowDeniedFetcher {
        map: MapFetcher,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl crate::ChunkFetcher for SlowDeniedFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if !self.map.chunks.contains_key(&addr) {
                tokio::time::sleep(self.delay).await;
            }
            self.map.fetch(addr).await
        }
    }

    /// Issue #79: slow denials (several seconds a fetch, as on mainnet)
    /// keep one episode of denials going across the retry loop's sweeps,
    /// so real loss is still confirmed about `MISS_CONFIRM_AFTER` in,
    /// not left transient until the 60 s recovery budget runs out.
    #[tokio::test(start_paused = true)]
    async fn slowly_denied_shard_loss_is_confirmed_too() {
        for secs in [0u64, 2, 5, 8] {
            let delay = Duration::from_secs(secs);
            let mut map = MapFetcher::new();
            let (root_wire, leaf_addrs, _) = build_redundant_fixture(&mut map, 6, 100);
            // 5 of 10 shards gone; 4 parities can't cover it.
            for addr in leaf_addrs.iter().take(5) {
                map.chunks.remove(addr);
            }
            let fetcher = SlowDeniedFetcher { map, delay };

            let started = tokio::time::Instant::now();
            let err = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
                .await
                .unwrap_err();
            let elapsed = started.elapsed();
            let JoinError::Recovery { detail } = &err else {
                panic!("{secs}s denials: got {err:?}");
            };
            assert!(
                detail.contains("5 confirmed missing, 0 denied for less than"),
                "{secs}s denials: {detail}",
            );
            // Confirmed on the first sweep that ends a window after the
            // first denial: at most one back-off, direct fetch and sweep
            // past it.
            assert!(
                elapsed
                    <= delay
                        + crate::rs::MISS_CONFIRM_AFTER
                        + RECOVERY_RETRY_BACKOFF_MAX
                        + delay * 2,
                "{secs}s denials: final only after {elapsed:?}",
            );
        }
    }

    /// A decode that fails after every shard arrived (here: a corrupted
    /// parity makes the reconstructed chunk fail CAC validation) is
    /// permanent too: one sweep, no retry.
    #[tokio::test]
    async fn failed_decode_after_full_sweep_is_terminal() {
        let mut map = MapFetcher::new();
        let (root_wire, leaf_addrs, _) = build_redundant_fixture(&mut map, 6, 100);
        map.chunks.remove(&leaf_addrs[0]);
        // Flip a byte in every parity chunk (served under its original
        // address — the test fetcher doesn't validate).
        for parity in map
            .chunks
            .iter_mut()
            .filter(|(a, _)| !leaf_addrs.contains(a))
        {
            parity.1[100] ^= 0xff;
        }
        let fetcher = ColdPoolFetcher::new(map, 0);

        let started = std::time::Instant::now();
        let err = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap_err();
        match &err {
            JoinError::Recovery { detail } => {
                assert!(detail.contains("CAC validation"), "got {detail}");
            }
            other => panic!("got {other:?}"),
        }
        assert!(
            started.elapsed() < RECOVERY_RETRY_BACKOFF,
            "a failed decode must not be retried ({:?})",
            started.elapsed()
        );
    }

    /// Compute the CAC address of a constructed intermediate chunk for
    /// the test fixtures above. Mirrors `cac_new` but for the case where
    /// the caller already controls span and payload separately.
    fn chunk_addr(payload: &[u8], span: u64) -> [u8; 32] {
        let mut wire = Vec::new();
        wire.extend_from_slice(&span.to_le_bytes());
        wire.extend_from_slice(payload);
        // BMT hash of payload + span prefix. The simpler way is to round
        // through `cac_new` with the payload (which fixes its own span);
        // but here we have a synthetic span, so go via `bmt_hash_with_span`.
        let span_bytes: [u8; 8] = wire[..8].try_into().unwrap();
        ant_crypto::bmt_hash_with_span(&span_bytes, payload).unwrap()
    }

    /// `effective_payload_size` strips trailing zero refs and rounds
    /// down to the last non-zero 32-byte slot. Pinned because a
    /// regression here re-introduces the all-zero fetch flood that
    /// shipped the joiner straight into a 30s timeout when serving a
    /// feed-backed `.eth` site (3 leaves padded to 128 ref slots →
    /// 125 spurious peer requests).
    #[test]
    fn effective_payload_size_strips_trailing_zeros() {
        // No padding: the whole payload is real refs.
        let mut full = vec![0u8; 128 * 32];
        for slot in full.chunks_mut(32) {
            slot[0] = 1;
        }
        assert_eq!(effective_payload_size(&full), 128 * 32);

        // 12 real refs followed by 116 zero slots = bee's typical
        // shape for a small file in a redundancy-NONE intermediate
        // chunk. Effective size is 12 * 32 = 384.
        let mut padded = vec![0u8; 128 * 32];
        for slot in padded[..12 * 32].chunks_mut(32) {
            slot[0] = 0xab;
        }
        assert_eq!(effective_payload_size(&padded), 12 * 32);

        // All zeros: caller surfaces this as a malformed chunk error.
        let zeros = vec![0u8; 4096];
        assert_eq!(effective_payload_size(&zeros), 0);

        // Single non-zero ref at the start.
        let mut one = vec![0u8; 4096];
        one[0] = 1;
        assert_eq!(effective_payload_size(&one), 32);
    }

    /// End-to-end: the joiner must NOT dispatch zero-address fetches
    /// when an intermediate chunk has trailing zero-padded ref slots.
    /// Build a 12-leaf file whose intermediate root is zero-padded to
    /// 128 slots, then prove `join` returns the joined bytes without
    /// ever asking `MapFetcher` for `[0u8; 32]` (`MapFetcher` panics
    /// on missing chunks, so a stray fetch surfaces as a test panic).
    #[tokio::test]
    async fn join_skips_trailing_zero_padded_refs() {
        let mut fetcher = MapFetcher::new();
        let mut leaf_addrs = Vec::new();
        let mut expected = Vec::new();
        for i in 0..12 {
            let payload: Vec<u8> = (0..CHUNK_SIZE as u8).map(|b| b.wrapping_add(i)).collect();
            let (addr, wire) = cac_new(&payload).unwrap();
            fetcher.insert(addr, wire);
            leaf_addrs.push(addr);
            expected.extend_from_slice(&payload);
        }
        // Build the intermediate root: 12 real refs ‖ 116 zero refs.
        let mut root_payload = vec![0u8; 128 * 32];
        for (i, addr) in leaf_addrs.iter().enumerate() {
            root_payload[i * 32..(i + 1) * 32].copy_from_slice(addr);
        }
        let total_span = expected.len() as u64;
        let mut root_wire = Vec::new();
        root_wire.extend_from_slice(&total_span.to_le_bytes());
        root_wire.extend_from_slice(&root_payload);

        let out = join(&fetcher, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .expect("join should succeed without zero-ref fetches");
        assert_eq!(out, expected);
    }

    /// Build a 130-leaf 3-level tree (same shape as `joins_three_level_tree`)
    /// and return the root wire bytes plus the expected joined body.
    /// Reused across the range tests below so each one stays focused on
    /// the slicing semantics rather than fixture construction.
    fn build_three_level_fixture(fetcher: &mut MapFetcher) -> (Vec<u8>, Vec<u8>) {
        let mut leaf_addrs = Vec::with_capacity(130);
        let mut expected: Vec<u8> = Vec::with_capacity(130 * CHUNK_SIZE);
        for i in 0..130u8 {
            let payload = vec![i; CHUNK_SIZE];
            let (addr, wire) = cac_new(&payload).unwrap();
            fetcher.insert(addr, wire);
            leaf_addrs.push(addr);
            expected.extend_from_slice(&payload);
        }
        let mut int1_payload = Vec::with_capacity(128 * 32);
        for addr in &leaf_addrs[..128] {
            int1_payload.extend_from_slice(addr);
        }
        let int1_span: u64 = 128 * CHUNK_SIZE as u64;
        let int1_addr = chunk_addr(&int1_payload, int1_span);
        let mut int1_wire = Vec::new();
        int1_wire.extend_from_slice(&int1_span.to_le_bytes());
        int1_wire.extend_from_slice(&int1_payload);
        fetcher.insert(int1_addr, int1_wire);

        let mut int2_payload = Vec::with_capacity(2 * 32);
        for addr in &leaf_addrs[128..] {
            int2_payload.extend_from_slice(addr);
        }
        let int2_span: u64 = 2 * CHUNK_SIZE as u64;
        let int2_addr = chunk_addr(&int2_payload, int2_span);
        let mut int2_wire = Vec::new();
        int2_wire.extend_from_slice(&int2_span.to_le_bytes());
        int2_wire.extend_from_slice(&int2_payload);
        fetcher.insert(int2_addr, int2_wire);

        let mut root_payload = Vec::with_capacity(64);
        root_payload.extend_from_slice(&int1_addr);
        root_payload.extend_from_slice(&int2_addr);
        let total_span: u64 = 130 * CHUNK_SIZE as u64;
        let mut root_wire = Vec::new();
        root_wire.extend_from_slice(&total_span.to_le_bytes());
        root_wire.extend_from_slice(&root_payload);
        (root_wire, expected)
    }

    /// A single-chunk file enumerates to exactly one leaf (the root)
    /// and no interior nodes, and never touches the fetcher.
    #[tokio::test]
    async fn enumerate_single_chunk_file() {
        let payload = b"hello swarm".to_vec();
        let (addr, wire) = cac_new(&payload).unwrap();
        let fetcher = MapFetcher::new();
        let inv = enumerate_chunk_tree(
            &fetcher,
            addr,
            &wire,
            DEFAULT_MAX_FILE_BYTES,
            JoinOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(inv.leaves, vec![addr]);
        assert_eq!(inv.intermediates, [] as [[u8; 32]; 0]);
        assert_eq!(inv.total(), 1);
    }

    /// The 130-leaf 3-level tree enumerates to 130 leaves and 3 interior
    /// nodes (root + the two L1 intermediates), and the leaf addresses
    /// match the tree's data chunks. The two L1 intermediates must be
    /// fetched during the walk; the leaves must NOT be (the fixture's
    /// `MapFetcher` panics on missing chunks, but leaves are present
    /// anyway, so we instead assert the addresses line up).
    #[tokio::test]
    async fn enumerate_three_level_tree() {
        let mut fetcher = MapFetcher::new();
        let (root_wire, _expected) = build_three_level_fixture(&mut fetcher);
        let root_addr = chunk_addr(
            &root_wire[8..],
            u64::from_le_bytes(root_wire[..8].try_into().unwrap()),
        );
        let inv = enumerate_chunk_tree(
            &fetcher,
            root_addr,
            &root_wire,
            DEFAULT_MAX_FILE_BYTES,
            JoinOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(inv.leaves.len(), 130, "130 data leaves");
        assert_eq!(inv.intermediates.len(), 3, "root + 2 L1 interior nodes");
        assert_eq!(inv.total(), 133);
        // The root must be the first recorded interior node.
        assert_eq!(inv.intermediates[0], root_addr);
    }

    /// Drain the streaming joiner into a single buffer for comparison.
    async fn drain(rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = rx.recv().await {
            out.extend_from_slice(&chunk);
        }
        out
    }

    /// `join_to_sender_range` with `range = None` matches `join_to_sender`
    /// byte-for-byte. Pins the no-range path against a regression that
    /// would otherwise show up only in integration.
    #[tokio::test]
    async fn range_none_matches_full_join() {
        let mut fetcher = MapFetcher::new();
        let (root_wire, expected) = build_three_level_fixture(&mut fetcher);
        let (tx, mut rx) = mpsc::channel(8);
        let join = tokio::spawn(async move {
            join_to_sender_range(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                None,
                tx,
            )
            .await
        });
        let body = drain(&mut rx).await;
        join.await.unwrap().unwrap();
        assert_eq!(body, expected);
    }

    /// Single-leaf prefix range. Verifies the leftmost-leaf slicing
    /// path returns exactly the requested bytes.
    #[tokio::test]
    async fn range_prefix_single_leaf() {
        let mut fetcher = MapFetcher::new();
        let (root_wire, expected) = build_three_level_fixture(&mut fetcher);
        let (tx, mut rx) = mpsc::channel(8);
        let join = tokio::spawn(async move {
            join_to_sender_range(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                Some(ByteRange {
                    start: 0,
                    end_inclusive: 999,
                }),
                tx,
            )
            .await
        });
        let body = drain(&mut rx).await;
        join.await.unwrap().unwrap();
        assert_eq!(body.len(), 1000);
        assert_eq!(body, expected[..1000]);
    }

    /// Suffix range crosses an L1 subtree boundary (last 4 KiB of int1 +
    /// first 4 KiB of int2). Exercises both right-edge slicing of int1
    /// and left-edge slicing of int2 in the same request.
    #[tokio::test]
    async fn range_crosses_subtree_boundary() {
        let mut fetcher = MapFetcher::new();
        let (root_wire, expected) = build_three_level_fixture(&mut fetcher);
        // int1 covers [0, 128*4096); int2 starts at 128*4096.
        let pivot = 128 * CHUNK_SIZE as u64;
        let start = pivot - 1024;
        let end = pivot + 1023;
        let (tx, mut rx) = mpsc::channel(8);
        let join = tokio::spawn(async move {
            join_to_sender_range(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                Some(ByteRange {
                    start,
                    end_inclusive: end,
                }),
                tx,
            )
            .await
        });
        let body = drain(&mut rx).await;
        join.await.unwrap().unwrap();
        let want = &expected[start as usize..=end as usize];
        assert_eq!(body, want);
    }

    /// Records the [`crate::priority`] rank each fetch runs with. The
    /// fetch of `gate` (if set) records its rank, waits for the test to
    /// open the gate, and records it again.
    struct RankingFetcher {
        map: MapFetcher,
        ranks: std::sync::Mutex<HashMap<[u8; 32], crate::priority::Priority>>,
        gate: Option<([u8; 32], std::sync::Arc<tokio::sync::Notify>)>,
        gated_rank_before: std::sync::Mutex<Option<crate::priority::Priority>>,
    }

    #[async_trait::async_trait]
    impl crate::ChunkFetcher for RankingFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if let Some((gate, open)) = self.gate.as_ref() {
                if *gate == addr {
                    *self.gated_rank_before.lock().unwrap() = Some(crate::priority::current());
                    open.notified().await;
                }
            }
            self.ranks
                .lock()
                .unwrap()
                .insert(addr, crate::priority::current());
            self.map.fetch(addr).await
        }
    }

    /// A file built by [`two_subtree_file`].
    struct TwoSubtreeFile {
        root: Vec<u8>,
        intermediates: [[u8; 32]; 2],
        /// Every leaf address, in document order.
        leaves: Vec<[u8; 32]>,
        bytes: Vec<u8>,
    }

    /// Two 128-leaf subtrees (2 × 512 KiB), its chunks in `fetcher`.
    fn two_subtree_file(fetcher: &mut MapFetcher) -> TwoSubtreeFile {
        let mut expected = Vec::with_capacity(256 * CHUNK_SIZE);
        let mut leaves = Vec::with_capacity(256);
        let mut intermediates = [[0u8; 32]; 2];
        for (group, intermediate) in intermediates.iter_mut().enumerate() {
            let mut payload = Vec::with_capacity(128 * 32);
            for leaf in 0..128usize {
                let mut data = vec![(group * 128 + leaf) as u8; CHUNK_SIZE];
                data[..2].copy_from_slice(&((group * 128 + leaf) as u16).to_le_bytes());
                let (addr, wire) = cac_new(&data).unwrap();
                fetcher.insert(addr, wire);
                payload.extend_from_slice(&addr);
                leaves.push(addr);
                expected.extend_from_slice(&data);
            }
            let span = 128 * CHUNK_SIZE as u64;
            let mut wire = span.to_le_bytes().to_vec();
            wire.extend_from_slice(&payload);
            *intermediate = chunk_addr(&payload, span);
            fetcher.insert(*intermediate, wire);
        }
        let mut root = (expected.len() as u64).to_le_bytes().to_vec();
        root.extend_from_slice(&intermediates[0]);
        root.extend_from_slice(&intermediates[1]);
        TwoSubtreeFile {
            root,
            intermediates,
            leaves,
            bytes: expected,
        }
    }

    /// Issue #46: the streaming joiner ranks every data-chunk fetch
    /// against how far its consumer has read, so the fetcher can serve
    /// the head of the window first. While the consumer has read
    /// nothing, only the chunks within `HEAD_WINDOW` of byte 0 are the
    /// head; once it has read the first subtree, the second subtree's
    /// chunks at the new read position are, including a fetch that
    /// started as look-ahead and was still running.
    #[tokio::test]
    async fn streaming_join_ranks_fetches_by_the_read_position() {
        use crate::priority::{Priority, HEAD_WINDOW};
        let mut map = MapFetcher::new();
        let TwoSubtreeFile {
            root,
            intermediates,
            leaves,
            bytes: expected,
        } = two_subtree_file(&mut map);
        let open = std::sync::Arc::new(tokio::sync::Notify::new());
        let fetcher = std::sync::Arc::new(RankingFetcher {
            map,
            ranks: std::sync::Mutex::default(),
            gate: Some((intermediates[1], open.clone())),
            gated_rank_before: std::sync::Mutex::default(),
        });
        let (tx, mut rx) = mpsc::channel(1);
        let f = fetcher.clone();
        let join = tokio::spawn(async move {
            join_to_sender(
                &*f,
                &root,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                tx,
            )
            .await
        });

        let half = 128 * CHUNK_SIZE;
        let mut got = Vec::new();
        while got.len() < half {
            got.extend_from_slice(&rx.recv().await.expect("first subtree"));
        }
        assert_eq!(
            *fetcher.gated_rank_before.lock().unwrap(),
            Some(Priority::LookAhead),
            "the second subtree starts as look-ahead",
        );
        {
            let ranks = fetcher.ranks.lock().unwrap();
            assert_eq!(ranks[&intermediates[0]], Priority::Head);
            for (i, leaf) in leaves[..128].iter().enumerate() {
                let want = if ((i * CHUNK_SIZE) as u64) < HEAD_WINDOW {
                    Priority::Head
                } else {
                    Priority::LookAhead
                };
                assert_eq!(ranks[leaf], want, "first subtree, leaf {i}");
            }
        }
        open.notify_one();
        got.extend_from_slice(&drain(&mut rx).await);
        join.await.unwrap().unwrap();
        assert_eq!(got, expected);
        let ranks = fetcher.ranks.lock().unwrap();
        assert_eq!(
            ranks[&intermediates[1]],
            Priority::Head,
            "a running fetch the consumer caught up with is the head",
        );
        for (i, leaf) in leaves[128..].iter().enumerate() {
            let want = if ((i * CHUNK_SIZE) as u64) < HEAD_WINDOW {
                Priority::Head
            } else {
                Priority::LookAhead
            };
            assert_eq!(ranks[leaf], want, "second subtree, leaf {i}");
        }
    }

    /// Issue #46: a range request's read position starts at the range,
    /// and the buffered joiner has no consumer to rank against (its
    /// fetches stay unranked, served as before).
    #[tokio::test]
    async fn range_join_ranks_from_the_range_start_and_buffered_join_is_unranked() {
        use crate::priority::{Priority, HEAD_WINDOW};
        let mut map = MapFetcher::new();
        let TwoSubtreeFile {
            root,
            intermediates,
            leaves,
            bytes: expected,
        } = two_subtree_file(&mut map);
        let fetcher = RankingFetcher {
            map,
            ranks: std::sync::Mutex::default(),
            gate: None,
            gated_rank_before: std::sync::Mutex::default(),
        };
        let start = 600 * 1024;
        let (tx, mut rx) = mpsc::channel(512);
        join_to_sender_range(
            &fetcher,
            &root,
            DEFAULT_MAX_FILE_BYTES,
            JoinOptions::default(),
            Some(ByteRange {
                start,
                end_inclusive: expected.len() as u64 - 1,
            }),
            tx,
        )
        .await
        .unwrap();
        assert_eq!(drain(&mut rx).await, expected[start as usize..]);
        {
            let mut ranks = fetcher.ranks.lock().unwrap();
            assert!(!ranks.contains_key(&intermediates[0]), "outside the range");
            assert_eq!(ranks[&intermediates[1]], Priority::Head);
            // The range walk fetches one child after another, each once
            // the one before it went out, and this consumer never falls
            // behind: every leaf is the head when it is fetched. Ranked
            // from byte 0, the first one (at 600 KiB) would be look-ahead.
            for (i, leaf) in leaves.iter().enumerate() {
                let offset = (i * CHUNK_SIZE) as u64;
                if offset + CHUNK_SIZE as u64 <= start {
                    assert!(!ranks.contains_key(leaf), "leaf {i} is outside the range");
                    continue;
                }
                assert_eq!(ranks[leaf], Priority::Head, "leaf {i}");
            }
            assert!(start >= HEAD_WINDOW);
            ranks.clear();
        }

        let out = join(&fetcher, &root, DEFAULT_MAX_FILE_BYTES).await.unwrap();
        assert_eq!(out, expected);
        let ranks = fetcher.ranks.lock().unwrap();
        assert_eq!(ranks.len(), 2 + 256);
        assert!(ranks.values().all(|r| *r == Priority::Unranked));
    }

    /// Tail range of the very last leaf: this is the MP4 `moov`-at-end
    /// case the plan cares about. Browser issues a single
    /// `Range: bytes=<tail>-<total-1>` and only the trailing slice
    /// should reach the consumer.
    #[tokio::test]
    async fn range_tail_only() {
        let mut fetcher = MapFetcher::new();
        let (root_wire, expected) = build_three_level_fixture(&mut fetcher);
        let total = expected.len() as u64;
        let start = total - 256;
        let end = total - 1;
        let (tx, mut rx) = mpsc::channel(8);
        let join = tokio::spawn(async move {
            join_to_sender_range(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                Some(ByteRange {
                    start,
                    end_inclusive: end,
                }),
                tx,
            )
            .await
        });
        let body = drain(&mut rx).await;
        join.await.unwrap().unwrap();
        assert_eq!(body, &expected[start as usize..=end as usize]);
    }

    /// Range fetch must not touch chunks fully outside the requested
    /// window. Build a fixture where the second L1 subtree's leaves
    /// (last two 4 KiB chunks) are deliberately *not* inserted into
    /// the fetcher; a request for the first 4 KiB must succeed
    /// because the joiner never asks for them. The previous
    /// implementation joined first and sliced afterwards, so it would
    /// trip the missing-chunk error before returning a single byte.
    #[tokio::test]
    async fn range_avoids_fetching_unrelated_subtrees() {
        // Build the same 130-leaf tree, but only insert leaves 0..128
        // into the fetcher. The L1 #2 intermediate chunk is also
        // omitted so a stray fetch panics.
        let mut fetcher = MapFetcher::new();
        let mut leaf_addrs = Vec::with_capacity(130);
        for i in 0..130u8 {
            let payload = vec![i; CHUNK_SIZE];
            let (addr, wire) = cac_new(&payload).unwrap();
            // Skip leaves 128/129 — they live under int2 which we
            // expect never to touch.
            if i < 128 {
                fetcher.insert(addr, wire);
            }
            leaf_addrs.push(addr);
        }
        let mut int1_payload = Vec::with_capacity(128 * 32);
        for addr in &leaf_addrs[..128] {
            int1_payload.extend_from_slice(addr);
        }
        let int1_span: u64 = 128 * CHUNK_SIZE as u64;
        let int1_addr = chunk_addr(&int1_payload, int1_span);
        let mut int1_wire = Vec::new();
        int1_wire.extend_from_slice(&int1_span.to_le_bytes());
        int1_wire.extend_from_slice(&int1_payload);
        fetcher.insert(int1_addr, int1_wire);

        // Compute (but don't insert) int2. Its address must still be
        // valid in the root chunk so the joiner can pick it as a
        // candidate; we just expect the range filter to discard it.
        let mut int2_payload = Vec::with_capacity(2 * 32);
        for addr in &leaf_addrs[128..] {
            int2_payload.extend_from_slice(addr);
        }
        let int2_span: u64 = 2 * CHUNK_SIZE as u64;
        let int2_addr = chunk_addr(&int2_payload, int2_span);

        let mut root_payload = Vec::with_capacity(64);
        root_payload.extend_from_slice(&int1_addr);
        root_payload.extend_from_slice(&int2_addr);
        let total_span: u64 = 130 * CHUNK_SIZE as u64;
        let mut root_wire = Vec::new();
        root_wire.extend_from_slice(&total_span.to_le_bytes());
        root_wire.extend_from_slice(&root_payload);

        let (tx, mut rx) = mpsc::channel(8);
        let join = tokio::spawn(async move {
            join_to_sender_range(
                &fetcher,
                &root_wire,
                DEFAULT_MAX_FILE_BYTES,
                JoinOptions::default(),
                Some(ByteRange {
                    start: 0,
                    end_inclusive: 1023,
                }),
                tx,
            )
            .await
        });
        let body = drain(&mut rx).await;
        join.await.unwrap().expect("range fetch must succeed");
        assert_eq!(body.len(), 1024);
        assert!(body.iter().all(|&b| b == 0u8), "leaf 0 is all zeros");
    }

    // --- encrypted joiner ---------------------------------------------

    /// Independent re-derivation of bee's chunk encryption keystream, used
    /// only to *build* encrypted test fixtures (the production code only
    /// decrypts). Reusing `ant_crypto::keccak256` keeps it honest while
    /// proving the joiner walks a genuine encrypted tree.
    fn enc_segment_key(key: &[u8; 32], ctr: u32) -> [u8; 32] {
        let mut input = [0u8; 36];
        input[..32].copy_from_slice(key);
        input[32..].copy_from_slice(&ctr.to_le_bytes());
        ant_crypto::keccak256(&ant_crypto::keccak256(&input))
    }
    fn enc_transcrypt(data: &mut [u8], key: &[u8; 32], init: u32) {
        for (i, seg) in data.chunks_mut(32).enumerate() {
            let ks = enc_segment_key(key, init.wrapping_add(i as u32));
            for (b, k) in seg.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
        }
    }

    /// Build one encrypted chunk from its plaintext payload + total span,
    /// returning `(stored_wire, encrypted_ref)` where the ref is
    /// `address(32) ‖ key(32)` and the address is the BMT hash of the
    /// *encrypted* span ‖ data — exactly what the network stores.
    fn build_enc_chunk(plain_payload: &[u8], span: u64, key: &[u8; 32]) -> (Vec<u8>, [u8; 64]) {
        let mut enc_span = span.to_le_bytes();
        enc_transcrypt(&mut enc_span, key, (CHUNK_SIZE / 32) as u32);
        let mut data = vec![0u8; CHUNK_SIZE];
        data[..plain_payload.len()].copy_from_slice(plain_payload);
        enc_transcrypt(&mut data, key, 0);

        let mut wire = Vec::with_capacity(8 + CHUNK_SIZE);
        wire.extend_from_slice(&enc_span);
        wire.extend_from_slice(&data);
        let addr = ant_crypto::bmt_hash_with_span(&enc_span, &wire[8..]).unwrap();

        let mut r = [0u8; 64];
        r[..32].copy_from_slice(&addr);
        r[32..].copy_from_slice(key);
        (wire, r)
    }

    /// A single-leaf encrypted file: one chunk, content shorter than 4 KiB.
    #[tokio::test]
    async fn join_encrypted_single_leaf() {
        let key = [0x33u8; 32];
        let content = b"encrypted swarm feed payload".to_vec();
        let (wire, root_ref) = build_enc_chunk(&content, content.len() as u64, &key);
        let addr: [u8; 32] = root_ref[..32].try_into().unwrap();

        let mut fetcher = MapFetcher::new();
        fetcher.insert(addr, wire);

        let out = join_encrypted(&fetcher, root_ref, DEFAULT_MAX_FILE_BYTES)
            .await
            .expect("encrypted single-leaf join");
        assert_eq!(out, content);
    }

    /// A two-leaf encrypted file behind an encrypted intermediate root:
    /// proves the joiner decrypts the intermediate, reads 64-byte child
    /// references, and stitches the leaves back in order.
    #[tokio::test]
    async fn join_encrypted_two_leaf_tree() {
        let mut fetcher = MapFetcher::new();

        // Leaf 0: a full 4 KiB chunk of 'A'. Leaf 1: 100 bytes of 'B'.
        let leaf0 = vec![b'A'; CHUNK_SIZE];
        let leaf1 = vec![b'B'; 100];
        let (w0, ref0) = build_enc_chunk(&leaf0, leaf0.len() as u64, &[0x01u8; 32]);
        let (w1, ref1) = build_enc_chunk(&leaf1, leaf1.len() as u64, &[0x02u8; 32]);
        fetcher.insert(ref0[..32].try_into().unwrap(), w0);
        fetcher.insert(ref1[..32].try_into().unwrap(), w1);

        // Root intermediate: payload is the two 64-byte child refs; its
        // span is the whole file.
        let mut root_payload = Vec::with_capacity(2 * 64);
        root_payload.extend_from_slice(&ref0);
        root_payload.extend_from_slice(&ref1);
        let total = (leaf0.len() + leaf1.len()) as u64;
        let (wroot, root_ref) = build_enc_chunk(&root_payload, total, &[0x99u8; 32]);
        fetcher.insert(root_ref[..32].try_into().unwrap(), wroot);

        let out = join_encrypted(&fetcher, root_ref, DEFAULT_MAX_FILE_BYTES)
            .await
            .expect("encrypted two-leaf join");

        let mut expected = leaf0.clone();
        expected.extend_from_slice(&leaf1);
        assert_eq!(out, expected);
    }

    /// The size cap is enforced for encrypted downloads too.
    #[tokio::test]
    async fn join_encrypted_respects_max_bytes() {
        let key = [0x44u8; 32];
        let content = vec![0u8; 2000];
        let (wire, root_ref) = build_enc_chunk(&content, content.len() as u64, &key);
        let mut fetcher = MapFetcher::new();
        fetcher.insert(root_ref[..32].try_into().unwrap(), wire);

        match join_encrypted(&fetcher, root_ref, 1000).await {
            Err(JoinError::TooLarge { cap, .. }) => assert_eq!(cap, 1000),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }
}
