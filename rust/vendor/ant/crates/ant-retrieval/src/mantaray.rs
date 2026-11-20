//! Mantaray manifest decoder and path lookup.
//!
//! Bee's binary manifest format. A manifest reference points at the **root
//! node** of a trie, where each edge carries a 1..30 byte path prefix and
//! each node optionally carries a value (a chunk reference to file data)
//! and arbitrary string metadata.
//!
//! `swarm-cli upload <file>` produces a manifest with one fork keyed on
//! the file's name, plus a `website-index-document` metadata entry on the
//! root pointing at that name (so `bzz://<ref>/` resolves to the file).
//! `swarm-cli upload <dir>` produces one fork per top-level entry, no
//! `index-document` unless the directory has an `index.html` and you
//! pass `--index-document=index.html`.
//!
//! # Wire format ([`bee/pkg/manifest/mantaray/marshal.go`])
//!
//! After XOR-decoding the body (every 32-byte block past the first `XORed`
//! with the obfuscation key, which lives unencrypted in bytes 0..32):
//!
//! ```text
//! [0..32]   obfuscation key (XOR pad; all-zero on unencrypted manifests)
//! [32..63]  31-byte version hash
//!           - "mantaray:0.2" → 5768b3...28f7b   (current)
//!           - "mantaray:0.1" → 025184...a9b7   (legacy, also handled)
//! [63]      ref-bytes-size (32 = unencrypted, 64 = encrypted — entry
//!           and fork references are `address ‖ decryption key` and the
//!           node chunks themselves are stored encrypted; the
//!           obfuscation key is random rather than all-zero)
//! [64..64+R] entry: data reference for *this* node (zeroed if no entry)
//! [+0..+32] forks index — 256-bit bitmap, bit `b` set ⇒ a fork starts on
//!           input byte `b`
//! [forks…]  in ascending bit order, for each set bit:
//!             - 1 byte node type (1=value, 2=value+, 4=edge, 8=path-sep,
//!               16=with-metadata; bitwise-or)
//!             - 1 byte prefix length (1..30)
//!             - 30 bytes prefix (only first prefixLen bytes meaningful)
//!             - R bytes child reference
//!             - if (type & 16): 2 BE bytes metadata length, then JSON
//!               metadata (padded with '\n' to a multiple of 32)
//! ```
//!
//! # Path lookup
//!
//! Walk the root: at each node, find the fork whose first byte matches the
//! current head of `path`, check the fork's prefix is itself a prefix of
//! `path`, advance, recurse. When `path` is exhausted return the current
//! node's `entry` and any `Content-Type` metadata. Mirrors
//! `mantaray.Node.LookupNode`.
//!
//! Empty path is **not** an error — if the root has metadata key
//! `website-index-document`, we treat that as the path. This matches what
//! `bee/pkg/api/bzz.go` does when serving `bzz://<ref>/`.

use crate::accounting::CreditWindow;
use crate::feed::{
    feed_from_metadata, resolve_sequence_feed_hinted, FeedError, FeedHints, FeedType,
};
use crate::joiner::{join_encrypted, ENCRYPTED_REF_SIZE};
use crate::ChunkFetcher;
use crate::{cac_valid, join, JoinError, DEFAULT_MAX_FILE_BYTES};
use futures::stream::{self, StreamExt};
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;
use tracing::{debug, trace};

/// Metadata key on a node carrying its MIME type. Set on file value
/// nodes by `swarm-cli upload`.
pub const MANTARAY_CONTENT_TYPE_KEY: &str = "Content-Type";
/// Metadata key on a directory's root naming the default file to serve
/// for an empty path.
pub const MANTARAY_INDEX_DOC_KEY: &str = "website-index-document";
/// Metadata key on a directory's root naming the file to serve when no
/// other path matches (404 fallback). We honour it after the index doc.
pub const MANTARAY_ERROR_DOC_KEY: &str = "website-error-document";

const OBFUSCATION_KEY_SIZE: usize = 32;
const VERSION_HASH_SIZE: usize = 31;
const NODE_HEADER_SIZE: usize = OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE + 1;
const FORK_PREFIX_MAX: usize = 30;
const FORK_PRE_REF_SIZE: usize = 32; // type(1) + prefixLen(1) + prefix(30)
const FORK_METADATA_SIZE_BYTES: usize = 2;
const NODE_TYPE_VALUE: u8 = 2;
const NODE_TYPE_EDGE: u8 = 4;
const NODE_TYPE_WITH_METADATA: u8 = 16;
const MANIFEST_LIST_MAX_DEPTH: usize = 6;
const MANIFEST_LIST_MAX_ENTRIES: usize = 512;

/// Dispersed-replica sweeps one manifest listing may run, counting its
/// root (always the first node loaded, so it always gets one). A sweep
/// only happens after a node's direct fetch failed, and each costs up to
/// ~30 replica probes (~13-21 s on mainnet for a node that isn't there).
/// Without a cap a [`list_manifest`] with dozens of unreachable children
/// would run one sweep per child, sequentially, and outlast its timeout
/// instead of returning the partial listing (unexpanded children listed
/// by reference) it always has. A [`list_manifest_page`] fails at its
/// first unreachable node, so it runs at most this many sweeps too.
const MANIFEST_LIST_REPLICA_SWEEPS: usize = 4;

/// Per-request memo of the dispersed-replica sweeps a manifest node load
/// runs after its direct fetch fails (#154).
///
/// * A node whose sweep ended in a *final* miss (every replica address
///   a corroborated miss, [`crate::rs::SweepMiss::Final`]) is not swept
///   again for the rest of the request: one `/bzz` lookup can load the
///   same node more than once (the literal walk, the directory-redirect
///   check, the index- and error-document retries), and a request that
///   retries its lookup loads it again per attempt. Later loads of that
///   node only repeat the direct fetch.
/// * A node whose sweep failed *transiently* (a starved pool, a miss
///   only one or two peers answered, a transport error) is not swept
///   again within the same attempt, but is swept again after
///   [`Self::next_attempt`]: a retry exists precisely because such a
///   miss can clear, and a replica-only node (#154) is reachable through
///   nothing but the sweep (R2-F1 on PR #155).
/// * [`Self::capped`] additionally bounds the total number of sweeps
///   (used by manifest listings, which load every node of the trie).
///
/// The lock is never held across an `.await`.
#[derive(Debug, Default)]
pub struct ReplicaSweeps {
    state: std::sync::Mutex<SweepState>,
}

#[derive(Debug, Default)]
struct SweepState {
    /// Nodes whose sweep ended in a final miss: skipped for the request.
    failed: HashSet<[u8; 32]>,
    /// Nodes whose sweep failed transiently: skipped until the next
    /// attempt.
    failed_this_attempt: HashSet<[u8; 32]>,
    /// Sweeps still allowed; `None` is unlimited.
    left: Option<usize>,
}

impl ReplicaSweeps {
    /// Unlimited sweeps, but at most one per distinct node per attempt.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The memo for one manifest listing (page): at most
    /// `MANIFEST_LIST_REPLICA_SWEEPS` (4) sweeps.
    #[must_use]
    pub fn for_listing() -> Self {
        Self::capped(MANIFEST_LIST_REPLICA_SWEEPS)
    }

    /// At most `max` sweeps in total, and at most one per distinct node.
    #[must_use]
    pub fn capped(max: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(SweepState {
                left: Some(max),
                ..SweepState::default()
            }),
        }
    }

    /// Start a new attempt of the request: nodes whose sweep failed only
    /// transiently may be swept again. Final misses stay memoized.
    pub fn next_attempt(&self) {
        self.lock().failed_this_attempt.clear();
    }

    /// Did the lookup that failed with `e` fail on a node whose replica
    /// sweep missed only *transiently* in this attempt? Then a retry can
    /// still recover the node, whatever the direct fetch's error says: a
    /// replica-only node (#154) answers "not found" from every peer asked
    /// for its own address, so its direct miss is corroborated and would
    /// on its own end the request (R3-M1 on PR #155).
    #[must_use]
    pub fn swept_transiently(&self, e: &ManifestError) -> bool {
        let ManifestError::Fetch(JoinError::FetchChunk { addr, .. }) = e else {
            return false;
        };
        let Some(addr) = hex::decode(addr)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return false;
        };
        self.lock().failed_this_attempt.contains(&addr)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SweepState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Claim a sweep for `addr`: `false` when `addr`'s sweep already
    /// failed under this memo (finally, or transiently in this attempt)
    /// or the cap is used up.
    fn begin(&self, addr: &[u8; 32]) -> bool {
        let mut st = self.lock();
        if st.failed.contains(addr) || st.failed_this_attempt.contains(addr) {
            return false;
        }
        match &mut st.left {
            Some(0) => false,
            Some(n) => {
                *n -= 1;
                true
            }
            None => true,
        }
    }

    fn failed(&self, addr: [u8; 32], miss: crate::rs::SweepMiss) {
        let mut st = self.lock();
        match miss {
            crate::rs::SweepMiss::Final => st.failed.insert(addr),
            crate::rs::SweepMiss::Transient => st.failed_this_attempt.insert(addr),
        };
    }
}

const VERSION_02_HASH_HEX: &str =
    "5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b";
const VERSION_01_HASH_HEX: &str =
    "025184789d63635766d78c41900196b57d7400875ebe4d9b5d1e76bd9652a9b7";

#[derive(Debug, Error)]
pub enum ManifestError {
    /// The path being looked up doesn't exist in the manifest.
    #[error("path '{path}' not found")]
    NotFound { path: String },
    /// Manifest node bytes are too short for the declared layout.
    #[error("manifest node too short: {0}")]
    TooShort(String),
    /// Version hash on the node is neither mantaray:0.1 nor mantaray:0.2.
    #[error("unsupported manifest version: {0}")]
    UnsupportedVersion(String),
    /// Ref length is something other than 0, 32, or 64.
    #[error("invalid manifest reference length: {0}")]
    InvalidRefLength(u8),
    /// Metadata blob isn't valid UTF-8 / JSON.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),
    /// Walking past a value-only node when the path still has bytes left.
    /// Typically signals a broken path like `/index.html/extra`.
    #[error("path '{path}' descends past leaf")]
    DescendPastLeaf { path: String },
    /// The literal path missed but `path + "/"` is a prefix of entries
    /// in the manifest — bee's `bzzDownloadHandler` answers this with a
    /// `308` redirect to the slash-terminated URL (`HasPrefix` check in
    /// `bee/pkg/api/bzz.go`) *before* trying the index-document suffix.
    /// The gateway maps this variant to that redirect.
    #[error("path '{path}' is a directory (redirect to trailing slash)")]
    Directory { path: String },
    /// The reference points at file data instead of a manifest. Bee's
    /// own bzz handler treats this as a 404 too; we propagate it as a
    /// distinct variant so callers can fall back to raw bytes if they
    /// want to.
    #[error("reference is not a mantaray manifest")]
    NotAManifest,
    /// Underlying chunk-fetch failed while loading a node.
    #[error("fetch manifest node: {0}")]
    Fetch(#[from] JoinError),
    /// The reference is a feed manifest but feed dereferencing failed —
    /// either the feed has no updates, the SOC signature didn't match
    /// the declared owner, or the metadata was malformed.
    #[error("dereference feed: {0}")]
    Feed(#[from] FeedError),
    /// A manifest listing page loaded its whole node budget (`2 * limit
    /// +` [`MANIFEST_PAGE_NODE_SLACK`]) without finding a single item:
    /// a trie of value-less nodes, not a listing that fits in a page.
    #[error("manifest listing exceeded its node budget before finding an entry")]
    ListBudgetExceeded,
    /// A manifest listing page spent its wall-clock budget
    /// ([`MANIFEST_PAGE_WALK_BUDGET`]) loading trie nodes without finding
    /// a single item. Transient: the nodes it did load are cached, so a
    /// retry gets further.
    #[error("manifest listing ran out of time before finding an entry")]
    ListTimedOut,
    /// A manifest listing page would return a path (or common prefix)
    /// that is not valid UTF-8. Paths travel as JSON strings and come
    /// back as `after`, so a lossily-decoded path would page wrongly
    /// (skip or repeat items); the page fails instead.
    #[error("manifest path is not valid UTF-8: {path_lossy:?}")]
    ListNonUtf8Path { path_lossy: String },
    /// A manifest listing page reached a trie node deeper than
    /// [`MANIFEST_PAGE_MAX_DEPTH`] levels.
    #[error("manifest is deeper than {MANIFEST_PAGE_MAX_DEPTH} trie levels")]
    ListTooDeep,
}

/// One match in the manifest trie.
#[derive(Debug, Clone)]
pub struct LookupResult {
    /// Reference to the file data: 32 bytes for a plain manifest entry
    /// (feed it to [`crate::join`] after fetching the chunk it points
    /// at) or 64 bytes (`address ‖ decryption key`) for an entry in an
    /// encrypted manifest (feed it to [`crate::join_encrypted`]).
    pub data_ref: Vec<u8>,
    /// `Content-Type` metadata at the matched value node, if present.
    pub content_type: Option<String>,
    /// All metadata at the matched value node. Caller may inspect for
    /// `Filename` etc.
    pub metadata: HashMap<String, String>,
    /// `Some` when `root_addr` was a **feed manifest** that we
    /// dereferenced to reach `data_ref`, carrying the feed update it
    /// resolved to (see [`LookupResult::is_feed`]). `None` for a plain
    /// static manifest.
    pub feed: Option<ResolvedFeed>,
}

impl LookupResult {
    /// `true` when the lookup went through a **feed manifest**. The
    /// resolved content is then *mutable* at the (stable) manifest
    /// reference — the same bzz URL returns newer content as the feed
    /// advances — so callers must not cache the response immutably.
    #[must_use]
    pub const fn is_feed(&self) -> bool {
        self.feed.is_some()
    }
}

/// The feed update a feed manifest dereferenced to: what bee's `/bzz`
/// handler reports in its `swarm-feed-index` and
/// `swarm-feed-resolved-version` response headers (`pkg/api/bzz.go`,
/// ethersphere/bee#5287).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedFeed {
    /// Sequence index of the resolved update.
    pub index: u64,
    /// `true` when the update was resolved as v2 (the SOC wraps the
    /// content root itself), `false` for v1 (`ts ‖ ref`).
    pub v2: bool,
}

/// One path/value discovered while walking a mantaray manifest.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Path prefix represented by this manifest entry.
    pub path: String,
    /// File data reference for value entries (32 bytes, or 64 in an
    /// encrypted manifest). `None` means the entry only carries
    /// metadata, e.g. the synthetic `/` fork with
    /// `website-index-document`.
    pub reference: Option<Vec<u8>>,
    /// Metadata attached to this entry or fork.
    pub metadata: BTreeMap<String, String>,
    /// Total file size in bytes, derived from the 8-byte BMT span on the
    /// data root chunk pointed to by `reference`. `None` means either the
    /// entry has no `reference` (metadata-only fork) or the data root
    /// chunk could not be fetched while listing the manifest. Populated
    /// by [`list_manifest`] best-effort; callers that don't want the
    /// extra round-trips per entry should use [`list_manifest_paths`].
    pub size: Option<u64>,
}

/// If `root_addr` points at a *feed manifest* — a mantaray manifest
/// whose `/` fork carries `swarm-feed-{owner,topic,type}` metadata —
/// dereference the feed and return the address of the current content
/// root the feed points at. Otherwise return `root_addr` unchanged.
///
/// This is the mechanical equivalent of bee's `goto FETCH;` in
/// `bee/pkg/api/bzz.go::serveReference`: feed-backed `.eth` sites
/// publish a stable feed-manifest reference that resolves transparently
/// to whichever rolling content root is current. Callers wrap their
/// usual lookup against the returned address, so the rest of the
/// manifest decoder doesn't need to know feeds exist.
/// Returns `(effective_root, feed)`: `feed` is `Some` when `root_ref`
/// was a feed manifest (so the resolved content is mutable at the
/// stable manifest reference and must not be cached immutably), with
/// the index and payload version of the update it resolved to. The
/// returned reference is 32 bytes, or 64 when the feed points at
/// encrypted content (bee's 80-byte v1 payload) — the subsequent
/// manifest load decrypts transparently.
pub async fn resolve_feed_root(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
) -> Result<(Vec<u8>, Option<ResolvedFeed>), ManifestError> {
    resolve_feed_root_with_credit(fetcher, root_ref, None, &ReplicaSweeps::new(), None).await
}

/// [`resolve_feed_root`] whose root-node load may wait for peer credit
/// within `credit` (see [`lookup_path_with_credit`]). The feed probes
/// never wait. With `hints`, a sequence feed's walk is anchored at the
/// node's last resolved index for it and raises that index on success,
/// falling back to the walk from 0 if the hinted walk fails (see
/// [`resolve_sequence_feed_hinted`], issue #159).
async fn resolve_feed_root_with_credit(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
    credit: Option<&CreditWindow>,
    sweeps: &ReplicaSweeps,
    hints: Option<&FeedHints>,
) -> Result<(Vec<u8>, Option<ResolvedFeed>), ManifestError> {
    let root_node = load_node_ref_with_credit(fetcher, root_ref, credit, sweeps).await?;
    // The feed metadata lives on the `/` fork's metadata blob; on the
    // root node itself there is none. Look there first; if it isn't
    // present, this isn't a feed manifest.
    let Some(slash_fork) = root_node.forks.get(&b'/') else {
        return Ok((root_ref.to_vec(), None));
    };
    let Some(feed) = feed_from_metadata(&slash_fork.metadata)? else {
        return Ok((root_ref.to_vec(), None));
    };
    debug!(
        target: "ant_retrieval::mantaray",
        feed_owner = %hex::encode(feed.owner),
        feed_topic = %hex::encode(feed.topic),
        "feed manifest detected; dereferencing",
    );
    match feed.kind {
        FeedType::Sequence => {
            let resolution = resolve_sequence_feed_hinted(fetcher, &feed, 0, hints).await?;
            let mut resolved = resolution.reference.to_vec();
            if let Some(key) = resolution.decrypt_key {
                resolved.extend_from_slice(&key);
            }
            Ok((
                resolved,
                Some(ResolvedFeed {
                    index: resolution.index,
                    v2: resolution.v2,
                }),
            ))
        }
    }
}

/// Walk a mantaray manifest and resolve `path` to the file it points at.
///
/// `fetcher` is used to load every node in the trie. `root_ref` is the
/// reference the user gave us (usually a bzz reference): 32 bytes for a
/// plain manifest, or 64 (`address ‖ decryption key`) for an encrypted
/// one — encrypted nodes are decrypted transparently while walking.
/// `path` is what comes after the reference in `bzz://<ref>/<path>` —
/// leading slash optional. An empty path triggers the
/// `website-index-document` lookup stored on the manifest's "/" fork
/// (this is what `swarm-cli upload <file>` produces and what bee's
/// `bzzDownloadHandler` looks up; see `bee/pkg/api/bzz.go`).
///
/// If `root_ref` is a feed manifest, the lookup transparently
/// dereferences it once before walking, exactly like bee's
/// `bzzDownloadHandler` does — callers don't need to know whether
/// they're looking at a static manifest or a feed.
pub async fn lookup_path(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
    path: &str,
) -> Result<LookupResult, ManifestError> {
    lookup_path_inner(fetcher, root_ref, path, None, &ReplicaSweeps::new(), None).await
}

/// [`lookup_path`] whose feed-manifest dereference is anchored at the
/// node's last resolved index for the feed in `hints` (issue #159), the
/// map `GET /feeds` shares. Results are the same as [`lookup_path`];
/// only the number of feed probes differs.
pub async fn lookup_path_with_hints(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
    path: &str,
    hints: &FeedHints,
) -> Result<LookupResult, ManifestError> {
    lookup_path_inner(
        fetcher,
        root_ref,
        path,
        None,
        &ReplicaSweeps::new(),
        Some(hints),
    )
    .await
}

/// [`lookup_path`] whose manifest walk may wait for peer credit, within
/// `credit` (issues #122, #130). Used by the `/bzz` resolution loop.
///
/// The walk is sequential: it loads one node per trie level (the root,
/// a feed's target root, then each fork's child, and the same again for
/// the directory-redirect check and the index / error-document
/// retries). Each node load fetches its root chunk with
/// [`ChunkFetcher::fetch_waiting_for_credit`] and
/// [`CreditWindow::budget`]; so do the header sniff's root →
/// leftmost-leaf fetches below it (normally two for a few-MiB raw file
/// behind a bare `/bzz/<ref>/`, none for a single-chunk node). One fetch
/// runs at a time, so together they wait no longer than what is left of
/// the window, and a caller that shares one window across its retries
/// and its other waiting fetches (the `/bzz` resolution loop) can't
/// stack waits past it. One attempt can wait more than once: on each
/// starved node of the literal walk, and again when a starved node in
/// the directory-redirect check falls through and the index-document
/// retry loads the same node — but all of it comes out of the same
/// window. Everything else stays non-waiting, as in
/// [`lookup_path`]: the fallback join of a multi-chunk node, feed
/// probes, and the decrypting join of an encrypted node.
///
/// A node whose direct fetch fails falls back to its dispersed replicas
/// (#154), at most once per distinct node under `sweeps`: pass the same
/// [`ReplicaSweeps`] to every attempt of one request (calling
/// [`ReplicaSweeps::next_attempt`] between them) so a node that loads
/// several times (directory-redirect check then index-document retry,
/// or a retried attempt) is swept once per attempt at most, and not at
/// all again once a sweep has confirmed its replicas missing.
///
/// With `hints`, a feed manifest's sequence feed is walked from the
/// node's last resolved index for it, as in [`lookup_path_with_hints`]
/// (issue #159).
pub async fn lookup_path_with_credit(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
    path: &str,
    credit: &CreditWindow,
    sweeps: &ReplicaSweeps,
    hints: Option<&FeedHints>,
) -> Result<LookupResult, ManifestError> {
    lookup_path_inner(fetcher, root_ref, path, Some(credit), sweeps, hints).await
}

async fn lookup_path_inner(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
    path: &str,
    credit: Option<&CreditWindow>,
    sweeps: &ReplicaSweeps,
    hints: Option<&FeedHints>,
) -> Result<LookupResult, ManifestError> {
    let path = path.trim_start_matches('/');

    // `load_node_ref_with_credit` below reloads the same node for a
    // non-feed manifest from the request's cache.
    let (effective_root, feed) =
        resolve_feed_root_with_credit(fetcher, root_ref, credit, sweeps, hints).await?;
    let root_node = load_node_ref_with_credit(fetcher, &effective_root, credit, sweeps).await?;
    debug!(
        target: "ant_retrieval::mantaray",
        root = %hex::encode(root_ref),
        effective_root = %hex::encode(&effective_root),
        forks = root_node.forks.len(),
        "loaded mantaray root",
    );

    // Bee stores `website-index-document` and `website-error-document` as
    // metadata on the **fork at byte '/'**, not on the root node itself.
    // (Marshalled as `m.Add("/", NewEntry(zero, {website-index-document:
    // ...}))` in `bee/pkg/api/bzz.go::fileUploadHandler`.) Read both off
    // the root's "/" fork.
    let slash_meta = root_node.forks.get(&b'/').map(|f| &f.metadata);
    let index_doc = slash_meta
        .and_then(|m| m.get(MANTARAY_INDEX_DOC_KEY))
        .cloned();
    let error_doc = slash_meta
        .and_then(|m| m.get(MANTARAY_ERROR_DOC_KEY))
        .cloned();

    // Empty path: serve the index document if the manifest declares one.
    // This matches what `bee/pkg/api/bzz.go` does for `bzz://<ref>/`.
    if path.is_empty() {
        if let Some(idx) = &index_doc {
            if let Some(mut result) = try_walk(fetcher, &root_node, idx, credit, sweeps).await? {
                result.feed = feed;
                return Ok(result);
            }
        }
        // No index document (or it didn't resolve): bee's empty-path
        // branch goes straight to `404 "address not found or
        // incorrect"` — it does NOT consult the error document (that
        // fallback only exists on the non-empty-path branch of
        // `bzzDownloadHandler`). The "(root)" marker lets the gateway
        // map this miss to bee's distinct root-404 message.
        return Err(ManifestError::NotFound {
            path: "(root)".into(),
        });
    }

    // Non-empty path: try the literal path first.
    if let Some(mut result) = try_walk(fetcher, &root_node, path, credit, sweeps).await? {
        result.feed = feed;
        return Ok(result);
    }

    // Directory redirect. Bee checks — BEFORE the index-document
    // retry — whether `path + "/"` is a prefix of anything in the
    // manifest, and answers with a 308 to the slash-terminated URL.
    // (Bee skips the check when pathVar starts with '/'; ant already
    // trimmed leading slashes above, matching the common form.) A
    // prefix-walk failure (unfetchable node) falls through like bee's
    // `err == nil && exists` guard.
    let dir_path = format!("{path}/");
    if let Ok(true) = has_prefix(fetcher, &root_node, dir_path.as_bytes(), credit, sweeps).await {
        return Err(ManifestError::Directory {
            path: path.to_string(),
        });
    }

    // Directory-suffix retry. Bee appends the single root-level index
    // document to *any* directory path with `path.Join`, so a request for
    // `developer/` (or `developer`) serves `developer/index.html`. Skip
    // when the path already ends with the index document so we never
    // double-suffix `.../index.html`.
    if let Some(idx) = &index_doc {
        if !path.ends_with(idx.as_str()) {
            let with_index = join_index_document(path, idx);
            if let Some(mut result) =
                try_walk(fetcher, &root_node, &with_index, credit, sweeps).await?
            {
                result.feed = feed;
                return Ok(result);
            }
        }
    }

    // Final fallback: the error document (Bee's `website-error-document`).
    if let Some(err) = &error_doc {
        if path != err {
            if let Some(mut result) = try_walk(fetcher, &root_node, err, credit, sweeps).await? {
                result.feed = feed;
                return Ok(result);
            }
        }
    }

    Err(ManifestError::NotFound {
        path: path.to_string(),
    })
}

/// Walk the manifest for `effective_path`, mapping a "no such path" miss
/// (`NotFound` / `DescendPastLeaf`) to `Ok(None)` so callers can try the
/// next fallback, while still propagating real failures (fetch errors,
/// non-manifest references, …). A `None` therefore means "this path isn't
/// in the manifest"; an `Err` means "we couldn't tell".
async fn try_walk(
    fetcher: &dyn ChunkFetcher,
    root_node: &Node,
    effective_path: &str,
    credit: Option<&CreditWindow>,
    sweeps: &ReplicaSweeps,
) -> Result<Option<LookupResult>, ManifestError> {
    match walk(
        fetcher,
        root_node.clone(),
        effective_path.as_bytes(),
        effective_path,
        credit,
        sweeps,
    )
    .await
    {
        Ok(result) => Ok(Some(result)),
        Err(ManifestError::NotFound { .. } | ManifestError::DescendPastLeaf { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Bee's `Node.HasPrefix` (`pkg/manifest/mantaray/node.go`): true iff
/// `path` can be fully consumed walking the trie, where landing in the
/// *middle* of a fork prefix still counts (`bytes.HasPrefix(f.prefix,
/// rest)`). Used only for the directory-redirect check, so it loads
/// nodes lazily and stops as soon as the answer is known.
async fn has_prefix(
    fetcher: &dyn ChunkFetcher,
    root_node: &Node,
    path: &[u8],
    credit: Option<&CreditWindow>,
    sweeps: &ReplicaSweeps,
) -> Result<bool, ManifestError> {
    let mut node = root_node.clone();
    let mut remaining = path;
    loop {
        if remaining.is_empty() {
            return Ok(true);
        }
        let Some(fork) = node.forks.get(&remaining[0]) else {
            return Ok(false);
        };
        let common = fork
            .prefix
            .iter()
            .zip(remaining.iter())
            .take_while(|(a, b)| a == b)
            .count();
        if common < fork.prefix.len() {
            // Path ends inside this fork's prefix ⇒ prefix match iff
            // the whole remaining path was consumed.
            return Ok(common == remaining.len());
        }
        let child_ref = fork.child_ref.clone();
        remaining = &remaining[common..];
        if remaining.is_empty() {
            return Ok(true);
        }
        node = load_node_ref_with_credit(fetcher, &child_ref, credit, sweeps).await?;
    }
}

/// Join a directory path with the index-document suffix the way Bee's
/// `path.Join(pathVar, indexDocumentSuffixKey)` does: drop a trailing
/// slash on the directory and separate the two with a single `/`. So
/// `developer/` and `developer` both yield `developer/index.html`.
fn join_index_document(path: &str, index_doc: &str) -> String {
    let base = path.trim_end_matches('/');
    if base.is_empty() {
        index_doc.to_string()
    } else {
        format!("{base}/{index_doc}")
    }
}

/// Concurrent in-flight chunk fetches when populating per-entry sizes
/// for a manifest listing. Each entry costs one extra fetch (the data
/// root chunk, whose 8-byte BMT span is the file size). Bounded so a
/// huge directory listing doesn't fan out hundreds of simultaneous
/// retrieval streams against the same set of peers.
const MANIFEST_SIZE_FANOUT: usize = 16;

/// List paths and metadata stored in a mantaray manifest, populating
/// each value entry's `size` from its data root chunk's BMT span.
///
/// If `root_addr` is a feed manifest, the listing transparently
/// dereferences it first and lists the *resolved* content root — this
/// matches the behaviour callers expect from a "show me what's at this
/// reference" API.
///
/// This is the original whole-manifest listing, kept for `ant_list_bzz`
/// (the iOS player): it stops silently at 512 entries or 6 trie levels
/// and lists an unreachable child by its node reference. The gateway's
/// `/v0/manifest` uses the paged [`list_manifest_page`] instead, which
/// does neither.
///
/// Sizes are best-effort: a chunk that can't be fetched (peer 404,
/// timeout, ...) leaves `size` as `None` rather than failing the whole
/// listing. The walker still surfaces every entry; only sizes go
/// missing for unreachable data roots. If the caller doesn't need
/// sizes, [`list_manifest_paths`] skips the per-entry round trips.
pub async fn list_manifest(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
) -> Result<Vec<ManifestEntry>, ManifestError> {
    let mut entries = list_manifest_paths(fetcher, root_ref).await?;
    populate_sizes(fetcher, &mut entries).await;
    Ok(entries)
}

/// Same as [`list_manifest`] but skips the per-entry data-root chunk
/// fetch — `size` stays `None` on every entry. Useful when the caller
/// only needs paths and metadata (e.g. `bzz://<ref>/` redirect logic
/// that just wants to know whether a given path is in the manifest).
pub async fn list_manifest_paths(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
) -> Result<Vec<ManifestEntry>, ManifestError> {
    // One sweep budget for the whole listing (root included), so
    // unreachable children can't each add a full replica sweep.
    let sweeps = ReplicaSweeps::capped(MANIFEST_LIST_REPLICA_SWEEPS);
    let (effective_root, _feed) =
        resolve_feed_root_with_credit(fetcher, root_ref, None, &sweeps, None).await?;
    let root_node = load_node_ref_with_credit(fetcher, &effective_root, None, &sweeps).await?;
    let mut entries = Vec::new();
    let mut visited = HashSet::from([effective_root]);
    collect_entries(
        fetcher,
        root_node,
        Vec::new(),
        &mut entries,
        &mut visited,
        0,
        &sweeps,
    )
    .await?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Default page size of [`list_manifest_page`], bee's
/// `manifestListDefaultLimit` (ethersphere/bee#5537).
pub const MANIFEST_PAGE_DEFAULT_LIMIT: usize = 1000;

/// Largest page [`list_manifest_page`] serves. A whole page is buffered
/// (and, with `sizes`, costs one extra chunk read per entry) before it
/// is answered, so this bounds one request; total enumeration is still
/// unbounded through `after`/`next_marker`. Inside the 1,000-10,000
/// range bee#5535 suggests for a node-enforced cap, and far below
/// #5537's 1,000,000.
///
/// `limit` bounds items, not time: the walk loads nodes one after
/// another (~85 ms each on a cold mainnet node), and a manifest of long
/// hashed names costs a few loads per entry, so a cold full-size page
/// can need well over 10 minutes. Time is bounded separately by
/// [`MANIFEST_PAGE_WALK_BUDGET`] and [`MANIFEST_PAGE_SIZES_BUDGET`]: a
/// page that runs out of time ends `truncated` with fewer than `limit`
/// items (S3 allows that), and the client continues from `next_marker`.
pub const MANIFEST_PAGE_MAX_LIMIT: usize = 5_000;

/// Wall-clock time, from the start of [`list_manifest_page`] (feed
/// resolution and the root load included), after which the walk starts
/// no further node load. A page that hits it after at least one item
/// ends `truncated` (and is not cacheable: a warm retry gets further);
/// one that hits it before any item fails with
/// [`ManifestError::ListTimedOut`]. It bounds when loads *start*: the
/// check is before each load, so a load already in flight still
/// finishes, and the page overruns the budget by that one load's time.
/// That is ~85 ms for a cold load that succeeds; a load that fails runs
/// until the fetcher gives up (its peer attempts are each capped at 30 s
/// and hedged, plus at most one replica sweep), with no hard bound
/// promised here. The 6 minutes left before the gateway's 10-minute
/// request timeout cover any ordinary give-up. Bounds the walk a
/// timed-out request leaves running detached, too.
pub const MANIFEST_PAGE_WALK_BUDGET: std::time::Duration = std::time::Duration::from_mins(4);

/// Wall-clock time, from the start of [`list_manifest_page`], after
/// which `sizes` starts no further span read; an entry not read by
/// then has no `size` and the page is marked `sizes_incomplete`. Like
/// [`MANIFEST_PAGE_WALK_BUDGET`] it bounds when reads start; reads in
/// flight (16 at a time) finish. A walk that ends by its own budget
/// leaves span reads at least 2 minutes, and in-flight reads 4 minutes
/// before the gateway's 10-minute request timeout.
pub const MANIFEST_PAGE_SIZES_BUDGET: std::time::Duration = std::time::Duration::from_mins(6);

/// Trie levels a manifest listing page descends before failing with
/// [`ManifestError::ListTooDeep`]. Every level consumes at least one
/// path byte and a long name chains 30-byte forks, so a real manifest
/// stays far below this (a 7 KiB name is ~240 levels); the bound exists
/// because the walk recurses once per level, and an adversarial
/// one-byte-fork chain otherwise grows it without limit.
pub const MANIFEST_PAGE_MAX_DEPTH: usize = 256;

/// Trie nodes one page may load on top of one per item it returns.
/// `limit` bounds items, not node loads: chained forks (a long name is
/// split into 30-byte forks, one node each), metadata-only nodes and
/// value-less inner nodes all cost a load without yielding an item.
/// The budget is `2 * limit + MANIFEST_PAGE_NODE_SLACK`; a page that
/// runs out of it after returning at least one item ends early with
/// `truncated` set (the next page resumes from `next_marker`), and one
/// that runs out before any item fails with
/// [`ManifestError::ListBudgetExceeded`]. This bounds loads, not time:
/// at limit 5,000 it allows 11,024 loads, ~15 minutes cold, so wall
/// time is bounded separately by [`MANIFEST_PAGE_WALK_BUDGET`].
pub const MANIFEST_PAGE_NODE_SLACK: usize = 1024;

/// One page request for [`list_manifest_page`], with bee#5535's
/// `ListObjectsV2`-style semantics. Paths compare as raw bytes.
#[derive(Debug, Clone, Default)]
pub struct ManifestPageQuery {
    /// Only paths starting with this are listed. Any byte prefix, not
    /// only a directory boundary (bee#5537 requires the prefix to end
    /// on a trie node); a prefix no path in the manifest starts with is
    /// [`ManifestError::NotFound`].
    pub prefix: String,
    /// Empty: list recursively. Otherwise every path whose remainder
    /// after `prefix` contains the delimiter is folded into one
    /// `common_prefixes` item (`prefix` + remainder up to and including
    /// the first delimiter) and its subtree is not walked.
    pub delimiter: String,
    /// Only items (paths or common prefixes) sorting strictly after this
    /// are returned. Entries under a common prefix that sorts at or
    /// before `after` are skipped with it. Empty: from the start.
    pub after: String,
    /// Items per page, `1..=MANIFEST_PAGE_MAX_LIMIT`; callers validate.
    pub limit: usize,
    /// Read each returned entry's size from its data root chunk's span.
    pub sizes: bool,
}

/// One page of a manifest listing ([`list_manifest_page`]).
#[derive(Debug, Clone, Default)]
pub struct ManifestPage {
    /// Value entries on this page, in path order. `reference` is always
    /// set; metadata-only nodes (bee's root `/` website metadata) are
    /// not entries. `size` is set only when `sizes` was asked for and
    /// the span could be read.
    pub entries: Vec<ManifestEntry>,
    /// Common prefixes on this page (only with a `delimiter`), in order.
    pub common_prefixes: Vec<String>,
    /// More items may follow: ask again with `after = next_marker`.
    /// Set when the page is full, or when the walk ran out of its node
    /// budget or of [`MANIFEST_PAGE_WALK_BUDGET`] after at least one
    /// item (then with fewer than `limit` items). A full page is also
    /// `truncated` when the load that would tell whether more follows
    /// failed ([`Self::lookahead_failed`]).
    pub truncated: bool,
    /// The last item on this page, set iff `truncated`.
    pub next_marker: Option<String>,
    /// The reference was a feed manifest, listed at its current update:
    /// the same request can answer differently later.
    pub feed: bool,
    /// The page ended early on [`MANIFEST_PAGE_WALK_BUDGET`]: the same
    /// request, once the nodes are cached, returns more items.
    pub timed_out: bool,
    /// The page is full and the node loaded only to look for one more
    /// item (to decide `truncated`) could not be fetched, so the page
    /// ends `truncated` without knowing whether anything follows. The
    /// same request may later answer `truncated: false`; the next page
    /// (`after = next_marker`) needs that node and fails on it.
    pub lookahead_failed: bool,
    /// `sizes` was asked for and at least one entry's span could not be
    /// read, so the same request can answer differently later.
    pub sizes_incomplete: bool,
}

/// List one page of a mantaray manifest, walking it in path order and
/// loading only the nodes the page needs: forks outside `prefix`, forks
/// whose paths all sort at or before `after`, and the subtree behind a
/// common prefix are never loaded. A page costs the trie depth plus its
/// own items, wherever it starts (bee#5535's seek, not a re-walk).
///
/// Feed manifests are dereferenced first, as in [`list_manifest`].
/// Unlike [`list_manifest`] the result is never silently partial: a trie
/// node that can't be loaded fails the page (bee#5535: "listings that
/// silently omit subtrees are dangerous"), `truncated` is the only way a
/// page ends short (full, or out of node or time budget), a trie deeper
/// than [`MANIFEST_PAGE_MAX_DEPTH`] is an error
/// ([`ManifestError::ListTooDeep`]), not a cut-off, and a path that is
/// not valid UTF-8 fails the page ([`ManifestError::ListNonUtf8Path`])
/// rather than being returned in a lossy form that pages wrongly.
///
/// Wall-clock time is bounded by [`MANIFEST_PAGE_WALK_BUDGET`] for the
/// walk and [`MANIFEST_PAGE_SIZES_BUDGET`] for `sizes`.
///
/// `sweeps` should be a fresh [`ReplicaSweeps::for_listing`]; after an
/// error, its [`ReplicaSweeps::swept_transiently`] tells whether a retry
/// could still recover the node that failed (a 503, not a 404).
///
/// There is no retry or credit wait inside: one failed node load fails
/// the page, and the client retries the page. The one exception is a
/// load past a page that is already full, made only to decide
/// `truncated`: its failure ends the page `truncated`
/// ([`ManifestPage::lookahead_failed`]) instead of discarding the items
/// already collected, and the next page, which needs the node, fails.
/// A full page whose lookahead would pass [`MANIFEST_PAGE_MAX_DEPTH`]
/// likewise ends `truncated`, and the next page is the one that fails.
pub async fn list_manifest_page(
    fetcher: &dyn ChunkFetcher,
    root_ref: &[u8],
    query: &ManifestPageQuery,
    sweeps: &ReplicaSweeps,
) -> Result<ManifestPage, ManifestError> {
    let started = tokio::time::Instant::now();
    let (effective_root, feed) =
        resolve_feed_root_with_credit(fetcher, root_ref, None, sweeps, None).await?;
    let root_node = load_node_ref_with_credit(fetcher, &effective_root, None, sweeps).await?;
    let limit = query.limit.clamp(1, MANIFEST_PAGE_MAX_LIMIT);
    let mut walk = PageWalk {
        fetcher,
        sweeps,
        prefix: query.prefix.as_bytes(),
        delimiter: query.delimiter.as_bytes(),
        after: query.after.as_bytes(),
        start: page_walk_start(
            query.prefix.as_bytes(),
            query.delimiter.as_bytes(),
            query.after.as_bytes(),
        ),
        limit,
        loads_left: limit
            .saturating_mul(2)
            .saturating_add(MANIFEST_PAGE_NODE_SLACK),
        deadline: started + MANIFEST_PAGE_WALK_BUDGET,
        items: Vec::new(),
        prefix_seen: query.prefix.is_empty(),
        done: false,
        truncated: false,
        timed_out: false,
        lookahead_failed: false,
    };
    if walk.start.is_some() {
        walk.visit(root_node.clone(), Vec::new(), 0).await?;
    }
    if walk.items.is_empty()
        && !walk.prefix_seen
        && !has_prefix(fetcher, &root_node, query.prefix.as_bytes(), None, sweeps).await?
    {
        return Err(ManifestError::NotFound {
            path: query.prefix.clone(),
        });
    }

    let mut page = ManifestPage {
        feed: feed.is_some(),
        truncated: walk.truncated,
        timed_out: walk.timed_out,
        lookahead_failed: walk.lookahead_failed,
        ..ManifestPage::default()
    };
    // `push` only keeps valid UTF-8 paths, so these conversions are
    // lossless and `next_marker` round-trips exactly as `after`.
    if walk.truncated {
        page.next_marker = walk
            .items
            .last()
            .map(|item| utf8_path(item.path().to_vec()))
            .transpose()?;
    }
    for item in walk.items {
        match item {
            PageItem::Prefix(p) => page.common_prefixes.push(utf8_path(p)?),
            PageItem::Entry {
                path,
                reference,
                metadata,
            } => page.entries.push(ManifestEntry {
                path: utf8_path(path)?,
                reference: Some(reference),
                metadata: metadata_to_btree(metadata),
                size: None,
            }),
        }
    }
    if query.sizes {
        populate_sizes_until(
            fetcher,
            &mut page.entries,
            Some(started + MANIFEST_PAGE_SIZES_BUDGET),
        )
        .await;
        page.sizes_incomplete = page.entries.iter().any(|e| e.size.is_none());
    }
    Ok(page)
}

/// A page item's path as a `String`, or [`ManifestError::ListNonUtf8Path`].
fn utf8_path(bytes: Vec<u8>) -> Result<String, ManifestError> {
    String::from_utf8(bytes).map_err(|e| ManifestError::ListNonUtf8Path {
        path_lossy: String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

/// The first path a page may visit, or `None` when nothing can sort
/// after `after` (bee#5537's `walkStart`). Without a delimiter, or when
/// `after` is not below a common prefix, that is `after ‖ 0x00`, the
/// smallest path sorting after it. When `after` is a common prefix or a
/// path below one, the whole common prefix sorts at or before it and
/// stands for every path below it, so the walk starts at the first path
/// not beginning with it.
fn page_walk_start(prefix: &[u8], delimiter: &[u8], after: &[u8]) -> Option<Vec<u8>> {
    if after.is_empty() {
        return Some(Vec::new());
    }
    let folded = (!delimiter.is_empty())
        .then(|| after.strip_prefix(prefix))
        .flatten()
        .and_then(|rest| find_subslice(rest, delimiter))
        .map(|i| prefix.len() + i + delimiter.len());
    let Some(end) = folded else {
        let mut start = after.to_vec();
        start.push(0);
        return Some(start);
    };
    let mut start = after[..end].to_vec();
    while let Some(last) = start.pop() {
        if last < 0xff {
            start.push(last + 1);
            return Some(start);
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

enum PageItem {
    Entry {
        path: Vec<u8>,
        reference: Vec<u8>,
        metadata: HashMap<String, String>,
    },
    Prefix(Vec<u8>),
}

impl PageItem {
    fn path(&self) -> &[u8] {
        match self {
            Self::Entry { path, .. } | Self::Prefix(path) => path,
        }
    }
}

struct PageWalk<'a> {
    fetcher: &'a dyn ChunkFetcher,
    sweeps: &'a ReplicaSweeps,
    prefix: &'a [u8],
    delimiter: &'a [u8],
    after: &'a [u8],
    /// From [`page_walk_start`]; `Some(empty)` when there is no `after`.
    start: Option<Vec<u8>>,
    limit: usize,
    loads_left: usize,
    /// [`MANIFEST_PAGE_WALK_BUDGET`] after the page started.
    deadline: tokio::time::Instant,
    items: Vec<PageItem>,
    /// Some fork reached a path starting with `prefix`.
    prefix_seen: bool,
    done: bool,
    truncated: bool,
    /// The walk stopped on `deadline`, not on a full page.
    timed_out: bool,
    /// See [`ManifestPage::lookahead_failed`].
    lookahead_failed: bool,
}

impl PageWalk<'_> {
    /// Add one item, or end the page (`truncated`) when it is already
    /// full: the lookahead means an exactly-full last page reports
    /// `truncated: false`, as in bee#5537. An item that is kept must
    /// have a UTF-8 path ([`ManifestError::ListNonUtf8Path`]); the
    /// lookahead is not returned, so it is not checked.
    fn push(&mut self, item: PageItem) -> Result<(), ManifestError> {
        if item.path() <= self.after && !self.after.is_empty() {
            return Ok(());
        }
        if self
            .items
            .last()
            .is_some_and(|last| last.path() == item.path())
        {
            return Ok(());
        }
        if self.items.len() >= self.limit {
            self.truncated = true;
            self.done = true;
            return Ok(());
        }
        if std::str::from_utf8(item.path()).is_err() {
            return Err(ManifestError::ListNonUtf8Path {
                path_lossy: String::from_utf8_lossy(item.path()).into_owned(),
            });
        }
        self.items.push(item);
        Ok(())
    }

    fn before_start(&self, path: &[u8]) -> bool {
        self.start.as_deref().is_some_and(|s| path < s)
    }

    fn visit<'s>(
        &'s mut self,
        node: Node,
        path: Vec<u8>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ManifestError>> + Send + 's>>
    {
        Box::pin(async move {
            let has_value = (node.entry.len() == 32 || node.entry.len() == ENCRYPTED_REF_SIZE)
                && node.entry.iter().any(|&b| b != 0);
            if path.starts_with(self.prefix) && !self.before_start(&path) {
                let rest = &path[self.prefix.len()..];
                if let Some(i) = find_subslice(rest, self.delimiter) {
                    // Every path below shares this common prefix: report
                    // it once and skip the subtree. A metadata-only leaf
                    // (bee's root `/` node) has no path below it at all.
                    let live_forks = node
                        .forks
                        .values()
                        .any(|f| f.child_ref.iter().any(|&b| b != 0));
                    if has_value || live_forks {
                        let end = self.prefix.len() + i + self.delimiter.len();
                        self.push(PageItem::Prefix(path[..end].to_vec()))?;
                    }
                    return Ok(());
                }
                // A value on the root itself has the empty path: as an
                // item it would sort before everything and, as a
                // `next_marker`, read as "start over". Not listed.
                if has_value && !path.is_empty() {
                    self.push(PageItem::Entry {
                        path: path.clone(),
                        reference: node.entry.clone(),
                        metadata: node.metadata.clone(),
                    })?;
                    if self.done {
                        return Ok(());
                    }
                }
            }

            let mut forks: Vec<Fork> = node.forks.into_values().collect();
            forks.sort_by(|a, b| a.prefix.cmp(&b.prefix));
            for fork in forks {
                if self.done {
                    return Ok(());
                }
                if fork.child_ref.iter().all(|&b| b == 0) {
                    continue;
                }
                let mut next = path.clone();
                next.extend_from_slice(&fork.prefix);
                // Outside `prefix`: neither on the way down to it nor
                // below it.
                if !(next.starts_with(self.prefix) || self.prefix.starts_with(&next)) {
                    continue;
                }
                if next.starts_with(self.prefix) {
                    self.prefix_seen = true;
                }
                // Every path below `next` sorts before `start`.
                if let Some(start) = self.start.as_deref() {
                    let common = next.len().min(start.len());
                    if next[..common] < start[..common] {
                        continue;
                    }
                }
                if depth >= MANIFEST_PAGE_MAX_DEPTH {
                    // Past a full page this descent would only decide
                    // `truncated`: end the page there, as below for a
                    // failed load; the next page reports the depth.
                    if self.items.len() >= self.limit {
                        self.truncated = true;
                        self.done = true;
                        return Ok(());
                    }
                    return Err(ManifestError::ListTooDeep);
                }
                if self.loads_left == 0 {
                    if self.items.is_empty() {
                        return Err(ManifestError::ListBudgetExceeded);
                    }
                    self.truncated = true;
                    self.done = true;
                    return Ok(());
                }
                // Checked before a load, never during one: a load in
                // flight finishes (see `MANIFEST_PAGE_WALK_BUDGET`).
                if tokio::time::Instant::now() >= self.deadline {
                    if self.items.is_empty() {
                        return Err(ManifestError::ListTimedOut);
                    }
                    self.truncated = true;
                    self.timed_out = true;
                    self.done = true;
                    return Ok(());
                }
                self.loads_left -= 1;
                let mut child = match load_node_ref_with_credit(
                    self.fetcher,
                    &fork.child_ref,
                    None,
                    self.sweeps,
                )
                .await
                {
                    Ok(child) => child,
                    // The page is already full: this load only looks
                    // for one more item to decide `truncated`. Its
                    // failure ends the page `truncated`, as running
                    // out of node or time budget here would; the next
                    // page, which needs this node, reports it.
                    Err(_) if self.items.len() >= self.limit => {
                        self.truncated = true;
                        self.lookahead_failed = true;
                        self.done = true;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };
                for (k, v) in fork.metadata {
                    child.metadata.entry(k).or_insert(v);
                }
                self.visit(child, next, depth + 1).await?;
            }
            Ok(())
        })
    }
}

/// Fetch every entry's data root chunk in parallel (capped at
/// [`MANIFEST_SIZE_FANOUT`]) and stamp the resulting BMT span into
/// `entry.size`. Best-effort — fetch failures leave `size` as `None`
/// without failing the listing. Skips entries with no `reference`
/// (metadata-only forks like `website-index-document`).
async fn populate_sizes(fetcher: &dyn ChunkFetcher, entries: &mut [ManifestEntry]) {
    populate_sizes_until(fetcher, entries, None).await;
}

/// [`populate_sizes`], starting no read at or after `deadline`: an
/// entry not read by then keeps `size: None`. Reads already in flight
/// finish.
async fn populate_sizes_until(
    fetcher: &dyn ChunkFetcher,
    entries: &mut [ManifestEntry],
    deadline: Option<tokio::time::Instant>,
) {
    let to_fetch: Vec<(usize, Vec<u8>)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e.reference.clone().map(|r| (i, r)))
        .collect();

    let results: Vec<(usize, Option<u64>)> = stream::iter(to_fetch)
        .map(|(idx, reference)| async move {
            if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
                return (idx, None);
            }
            (idx, reference_span(fetcher, &reference).await)
        })
        .buffer_unordered(MANIFEST_SIZE_FANOUT)
        .collect()
        .await;

    for (idx, size) in results {
        if let Some(entry) = entries.get_mut(idx) {
            entry.size = size;
        }
    }
}

/// Best-effort file size behind a 32- or 64-byte data reference: the
/// (decrypted, for 64-byte refs) 8-byte LE span of the data root chunk,
/// with any redundancy-level top byte masked off.
async fn reference_span(fetcher: &dyn ChunkFetcher, reference: &[u8]) -> Option<u64> {
    let addr: [u8; 32] = reference.get(..32)?.try_into().ok()?;
    let wire = fetcher.fetch(addr).await.ok()?;
    let mut span = *wire.first_chunk::<8>()?;
    if reference.len() == ENCRYPTED_REF_SIZE {
        let key: [u8; 32] = reference[32..].try_into().ok()?;
        let (dec_span, _) = ant_crypto::decrypt_chunk_parts(&wire, &key).ok()?;
        span = dec_span;
    }
    let (_, plain) = crate::rs::decode_span(span);
    Some(u64::from_le_bytes(plain))
}

/// Recursive walker. Loads nodes lazily from `fetcher` as it descends.
/// At each fork hop, reads the file's actual data reference from the
/// child node's *own* `entry` bytes (set by bee when `m.Add("hello.txt",
/// entry, …)` ultimately marshals the child) and merges fork-level
/// metadata (Content-Type, Filename) onto that result.
fn walk<'a>(
    fetcher: &'a dyn ChunkFetcher,
    node: Node,
    remaining: &'a [u8],
    full_path: &'a str,
    credit: Option<&'a CreditWindow>,
    sweeps: &'a ReplicaSweeps,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<LookupResult, ManifestError>> + Send + 'a>,
> {
    Box::pin(async move {
        if remaining.is_empty() {
            // Land on this node. The data reference is the node's `entry`
            // (32 bytes, or 64 in an encrypted manifest; non-zero); the
            // file's metadata (Content-Type, Filename) was already merged
            // in by the caller from the fork that pointed here.
            if node.entry.len() != 32 && node.entry.len() != ENCRYPTED_REF_SIZE {
                return Err(ManifestError::InvalidRefLength(node.entry.len() as u8));
            }
            let data_ref = node.entry.clone();
            if data_ref.iter().all(|&b| b == 0) {
                // A zero entry is bee's "no value here" sentinel — used
                // on the synthetic "/" fork that holds website metadata
                // but not a file. Calling `Lookup("/")` on a real bee
                // node will return NotFound; we mirror that.
                return Err(ManifestError::NotFound {
                    path: full_path.to_string(),
                });
            }
            let content_type = node.metadata.get(MANTARAY_CONTENT_TYPE_KEY).cloned();
            return Ok(LookupResult {
                data_ref,
                content_type,
                metadata: node.metadata,
                // Set by `lookup_path` once it knows whether the root was a
                // feed manifest; the walker itself works on the resolved
                // (post-dereference) root and can't tell.
                feed: None,
            });
        }

        // Find a fork whose first byte matches.
        let head = remaining[0];
        let fork = match node.forks.get(&head) {
            Some(f) => f.clone(),
            None => {
                return Err(ManifestError::NotFound {
                    path: full_path.to_string(),
                });
            }
        };

        // The fork's prefix must be a prefix of `remaining`.
        if remaining.len() < fork.prefix.len() || remaining[..fork.prefix.len()] != fork.prefix[..]
        {
            return Err(ManifestError::NotFound {
                path: full_path.to_string(),
            });
        }
        let next_remaining = &remaining[fork.prefix.len()..];
        trace!(
            target: "ant_retrieval::mantaray",
            consumed = %String::from_utf8_lossy(&fork.prefix),
            child_ref = %hex::encode(&fork.child_ref),
            "descending into fork",
        );
        let mut child_node =
            load_node_ref_with_credit(fetcher, &fork.child_ref, credit, sweeps).await?;
        // Merge fork-level metadata onto the child. In bee's wire format
        // (mantaray 0.2) per-file Content-Type / Filename are stored on
        // the parent fork, not on the child node's own bytes — yet bee's
        // `LookupNode` returns them as if they were on the child via Go
        // pointer-embedding tricks. We do it explicitly.
        for (k, v) in fork.metadata {
            child_node.metadata.entry(k).or_insert(v);
        }
        walk(
            fetcher,
            child_node,
            next_remaining,
            full_path,
            credit,
            sweeps,
        )
        .await
    })
}

/// A listing entry's path: the root's own entry lists as `/`.
fn entry_path(path: &[u8]) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        String::from_utf8_lossy(path).into_owned()
    }
}

fn metadata_to_btree(metadata: HashMap<String, String>) -> BTreeMap<String, String> {
    metadata.into_iter().collect()
}

fn collect_entries<'a>(
    fetcher: &'a dyn ChunkFetcher,
    node: Node,
    path: Vec<u8>,
    entries: &'a mut Vec<ManifestEntry>,
    visited: &'a mut HashSet<Vec<u8>>,
    depth: usize,
    sweeps: &'a ReplicaSweeps,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ManifestError>> + Send + 'a>> {
    Box::pin(async move {
        if entries.len() >= MANIFEST_LIST_MAX_ENTRIES {
            return Ok(());
        }

        let node_has_value = (node.entry.len() == 32 || node.entry.len() == ENCRYPTED_REF_SIZE)
            && node.entry.iter().any(|&b| b != 0);
        let node_metadata = node.metadata.clone();
        if node_has_value {
            let reference = node.entry.clone();
            entries.push(ManifestEntry {
                path: entry_path(&path),
                reference: Some(reference),
                metadata: metadata_to_btree(node_metadata),
                size: None,
            });
        } else if !node_metadata.is_empty() {
            entries.push(ManifestEntry {
                path: entry_path(&path),
                reference: None,
                metadata: metadata_to_btree(node_metadata),
                size: None,
            });
        }

        if depth >= MANIFEST_LIST_MAX_DEPTH {
            return Ok(());
        }

        let mut forks: Vec<Fork> = node.forks.into_values().collect();
        forks.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        for fork in forks {
            if entries.len() >= MANIFEST_LIST_MAX_ENTRIES {
                break;
            }

            // Concatenate raw bytes and decode only the whole path: a
            // fork boundary can fall inside a UTF-8 sequence (`é.txt` and
            // `è.txt` share the lead byte 0xc3), so decoding per prefix
            // would mangle both names.
            let fork_path = [path.as_slice(), &fork.prefix].concat();
            if fork.child_ref.iter().all(|&b| b == 0) {
                if !fork.metadata.is_empty() {
                    entries.push(ManifestEntry {
                        path: entry_path(&fork_path),
                        reference: None,
                        metadata: metadata_to_btree(fork.metadata),
                        size: None,
                    });
                }
                continue;
            }

            if !visited.insert(fork.child_ref.clone()) {
                entries.push(ManifestEntry {
                    path: entry_path(&fork_path),
                    reference: Some(fork.child_ref),
                    metadata: metadata_to_btree(fork.metadata),
                    size: None,
                });
                continue;
            }

            match load_node_ref_with_credit(fetcher, &fork.child_ref, None, sweeps).await {
                Ok(mut child_node) => {
                    for (k, v) in fork.metadata {
                        child_node.metadata.entry(k).or_insert(v);
                    }
                    // The listing path is the plain concatenation of fork
                    // prefixes — real `/` separators are already inside the
                    // prefix bytes, exactly as `walk` matches them. Bee's
                    // path-separator type bit means "this prefix *contains*
                    // a separator" (see `bee_path_separator` in
                    // manifest_writer.rs), never "append one": deriving a
                    // `/` from it can split a name mid-byte when a fork
                    // boundary falls inside a segment (issue #13).
                    collect_entries(
                        fetcher,
                        child_node,
                        fork_path,
                        entries,
                        visited,
                        depth + 1,
                        sweeps,
                    )
                    .await?;
                }
                Err(_) => {
                    entries.push(ManifestEntry {
                        path: entry_path(&fork_path),
                        reference: Some(fork.child_ref),
                        metadata: metadata_to_btree(fork.metadata),
                        size: None,
                    });
                }
            }
        }
        Ok(())
    })
}

/// Fetch a manifest node by a 32-byte (plain) or 64-byte (encrypted)
/// reference and unmarshal it. Encrypted nodes go through the
/// decrypting joiner; plain nodes fetch the root chunk and join.
pub(crate) async fn load_node_ref(
    fetcher: &dyn ChunkFetcher,
    node_ref: &[u8],
) -> Result<Node, ManifestError> {
    load_node_ref_with_credit(fetcher, node_ref, None, &ReplicaSweeps::new()).await
}

/// [`load_node_ref`] whose root-chunk fetch (issue #130) and header
/// sniff (issue #122) wait for peer credit within `credit`, if given:
/// one fetch at a time, each with [`CreditWindow::budget`]. The fallback
/// join of a multi-chunk node and the decrypting join of an encrypted
/// node never wait. A plain node's root chunk falls back to its
/// dispersed replicas when the direct fetch fails (#154), with or
/// without a window, if `sweeps` allows it (see [`ReplicaSweeps`]).
async fn load_node_ref_with_credit(
    fetcher: &dyn ChunkFetcher,
    node_ref: &[u8],
    credit: Option<&CreditWindow>,
    sweeps: &ReplicaSweeps,
) -> Result<Node, ManifestError> {
    if node_ref.len() == ENCRYPTED_REF_SIZE {
        let enc_ref: [u8; ENCRYPTED_REF_SIZE] = node_ref.try_into().expect("length checked");
        let bytes = join_encrypted(fetcher, enc_ref, DEFAULT_MAX_FILE_BYTES).await?;
        return Node::unmarshal(&bytes);
    }
    let Ok(addr) = <[u8; 32]>::try_from(node_ref) else {
        return Err(ManifestError::InvalidRefLength(node_ref.len() as u8));
    };
    // The node is itself a Swarm file: fetch the root chunk, then join.
    // For tiny manifests (< 4 KiB) the root chunk's payload is already
    // the entire serialised node.
    //
    // Like any file root, the node's root chunk falls back to its
    // dispersed replicas when the direct fetch fails: bee loads every
    // manifest node through its joiner, whose root getter is
    // `replicas.NewGetter`, and a redundant upload's manifest root can
    // be reachable *only* through a replica (#154). Without this a
    // `/bzz/<ref>/<path>` on a cold node failed to load that root at
    // all — `404 "Not Found"` instead of `"path address not found"`,
    // every time, since nothing reached the cache — while a bare
    // `/bzz/<ref>/` (whose root `run_stream_bzz` fetches with replicas
    // up front) worked. A recovered chunk is stored via
    // `put_recovered`, so the next lookup reads it from the cache. On
    // total failure the direct fetch's error comes back unchanged, so
    // retry / not-found classification is as before. Only the direct
    // fetch waits for credit (and only with a window); the replica
    // probes never do (`rs::recover_from_replicas_classified`). `sweeps`
    // skips the sweep for a node whose sweep already ended in a final
    // miss in this request, or failed transiently in this attempt, and
    // caps a listing's total.
    let budget = credit.map_or(std::time::Duration::ZERO, CreditWindow::budget);
    let root_chunk = if budget.is_zero() {
        fetcher.fetch(addr).await
    } else {
        fetcher.fetch_waiting_for_credit(addr, budget).await
    };
    let root_chunk = match root_chunk {
        Ok(wire) => Ok(wire),
        Err(e) if sweeps.begin(&addr) => {
            match crate::rs::recover_from_replicas_classified(fetcher, addr).await {
                Ok(wire) => Ok(wire),
                Err(miss) => {
                    sweeps.failed(addr, miss);
                    Err(e)
                }
            }
        }
        Err(e) => Err(e),
    };
    let root_chunk = root_chunk.map_err(|e| {
        ManifestError::Fetch(JoinError::FetchChunk {
            addr: hex::encode(addr),
            source: e,
        })
    })?;
    // Defensive: cac_valid should already have run inside `fetch`, but
    // re-check so a buggy custom fetcher can't hand us garbage.
    if !cac_valid(&addr, &root_chunk) {
        return Err(ManifestError::Fetch(JoinError::FetchChunk {
            addr: hex::encode(addr),
            source: "chunk failed CAC validation".into(),
        }));
    }
    // Rule out a raw file from its first data chunk before joining the
    // whole thing: `/bzz/<ref>/` asks this of every raw `/bytes`
    // reference (#112), and a full join of a multi-MiB file just to read
    // its 64-byte header would make the answer depend on every chunk of
    // the file arriving inside the manifest lookup (#113).
    let sniffed = SniffedFetcher::new(fetcher);
    if leftmost_leaf_is_not_a_manifest(&sniffed, &root_chunk, credit).await {
        debug!(
            target: "ant_retrieval::mantaray",
            root = %hex::encode(addr),
            "mantaray: first data chunk has no manifest header, returning NotAManifest",
        );
        return Err(ManifestError::NotAManifest);
    }
    // The join reuses what the sniff already paid for (R2-M1, #115): the
    // chunks it fetched, and its failed fetch counts as the join's first
    // attempt at that chunk instead of being repeated before the join's
    // own retries / erasure recovery.
    sniffed.replay();
    let bytes = join(&sniffed, &root_chunk, DEFAULT_MAX_FILE_BYTES).await?;
    Node::unmarshal(&bytes)
}

/// Fetch error as handed out by [`ChunkFetcher::fetch`].
type FetchErr = Box<dyn std::error::Error + Send + Sync>;

/// [`ChunkFetcher`] wrapper that lets the header sniff and the join in
/// [`load_node_ref`] share their fetches. While recording (the sniff) it
/// remembers every chunk fetched and the one failed fetch that ends a
/// sniff; after [`Self::replay`] (the join) it serves those chunks from
/// memory and answers the *first* request for the failed address with
/// the sniff's error, so the join's retry back-off / erasure recovery
/// starts from where the sniff left off instead of re-waiting for the
/// same miss. Later requests for that address go to the network as
/// usual, so the join's own retries are untouched.
///
/// It deliberately doesn't forward
/// [`ChunkFetcher::fetch_waiting_for_credit`]: the trait default turns
/// that into a plain `fetch`, so the fallback join of a manifest node
/// never waits for peer credit (issue #117): it fetches the rest of a
/// multi-chunk node, many chunks per node, and a starved one fails at
/// once, as before #117, for the resolution loop to retry the walk. The
/// one waiting fetch here is the sniff's own [`Self::sniff_fetch`], and
/// only when its caller hands it a credit window (the `/bzz` resolution
/// loop's walk, issues #122, #130).
struct SniffedFetcher<'a> {
    inner: &'a dyn ChunkFetcher,
    state: std::sync::Mutex<SniffState>,
}

#[derive(Default)]
struct SniffState {
    replaying: bool,
    fetched: HashMap<[u8; 32], Vec<u8>>,
    failed: Option<([u8; 32], FetchErr)>,
}

impl<'a> SniffedFetcher<'a> {
    fn new(inner: &'a dyn ChunkFetcher) -> Self {
        Self {
            inner,
            state: std::sync::Mutex::new(SniffState::default()),
        }
    }

    fn replay(&self) {
        self.state.lock().expect("sniff state lock").replaying = true;
    }

    /// A sniff fetch, recorded like [`ChunkFetcher::fetch`]. With a
    /// `credit` window it waits for peer credit for at most what is left
    /// of the window ([`CreditWindow::budget`]); without one, or once the
    /// window has passed, it is a plain `fetch`.
    async fn sniff_fetch(
        &self,
        addr: [u8; 32],
        credit: Option<&CreditWindow>,
    ) -> Result<Vec<u8>, FetchErr> {
        let budget = credit.map_or(std::time::Duration::ZERO, CreditWindow::budget);
        self.fetch_recorded(addr, budget).await
    }

    async fn fetch_recorded(
        &self,
        addr: [u8; 32],
        credit_budget: std::time::Duration,
    ) -> Result<Vec<u8>, FetchErr> {
        let replaying = {
            let mut state = self.state.lock().expect("sniff state lock");
            if state.replaying {
                if let Some(wire) = state.fetched.get(&addr) {
                    return Ok(wire.clone());
                }
                if state.failed.as_ref().is_some_and(|(a, _)| *a == addr) {
                    let (_, err) = state.failed.take().expect("checked");
                    return Err(err);
                }
            }
            state.replaying
        };
        let result = if credit_budget.is_zero() {
            self.inner.fetch(addr).await
        } else {
            self.inner
                .fetch_waiting_for_credit(addr, credit_budget)
                .await
        };
        if !replaying {
            let mut state = self.state.lock().expect("sniff state lock");
            match &result {
                Ok(wire) if cac_valid(&addr, wire) => {
                    state.fetched.insert(addr, wire.clone());
                }
                Ok(_) => {}
                Err(e) => state.failed = Some((addr, replayable_err(e.as_ref()))),
            }
        }
        result
    }
}

#[async_trait::async_trait]
impl ChunkFetcher for SniffedFetcher<'_> {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, FetchErr> {
        self.fetch_recorded(addr, std::time::Duration::ZERO).await
    }

    async fn put_recovered(&self, addr: [u8; 32], wire: &[u8]) {
        self.inner.put_recovered(addr, wire).await;
    }

    /// The inner fetcher's handle: a detached feed-probe fetch only has
    /// to land in the node's caches, not in this sniff's memo.
    fn detached(&self) -> Option<std::sync::Arc<dyn ChunkFetcher>> {
        self.inner.detached()
    }
}

/// A copy of a fetch error the sniff can replay later. Boxed errors
/// aren't `Clone`, so most are kept as their message — but a
/// [`crate::fetcher::FetchExhausted`] keeps its type, because the RS
/// decoder reads its `pool_starved` flag to tell a starved "not found"
/// from a confirmed-missing shard (`rs::shard_confirmed_missing`).
fn replayable_err(e: &(dyn std::error::Error + Send + Sync + 'static)) -> FetchErr {
    match e.downcast_ref::<crate::fetcher::FetchExhausted>() {
        Some(x) => Box::new(x.clone()),
        None => e.to_string().into(),
    }
}

/// Deepest chunk tree [`leftmost_leaf_is_not_a_manifest`] descends.
/// Seven intermediate levels already address more than any gateway cap
/// (`128^7 × 4 KiB`); a deeper "tree" is malformed and left to the join.
const HEADER_SNIFF_MAX_DEPTH: usize = 8;

/// `true` only when the file rooted at `root_chunk` positively is **not**
/// a mantaray node: its first data chunk is in hand, holds at least a
/// node header, and that header's version hash isn't mantaray's.
///
/// A serialised node starts with its 64-byte header, so the leftmost
/// leaf of the file's chunk tree decides the question; reaching it costs
/// one fetch per tree level (two for a few-MiB file) instead of a join
/// of the whole file. Every "can't tell" case answers `false` so the
/// caller falls back to the full join exactly as before: a leftmost
/// chunk that can't be fetched (the join may still recover it through
/// erasure coding) or a malformed tree. A file shorter than a node
/// header counts as positively not a manifest (#115), so `/bzz/<ref>/`
/// on a tiny raw `/bytes` upload serves the bytes instead of failing the
/// lookup with `TooShort`.
///
/// With a `credit` window each level's fetch may wait for peer credit
/// within what is left of it (issue #122, see
/// [`lookup_path_with_credit`]); without one they are plain.
async fn leftmost_leaf_is_not_a_manifest(
    fetcher: &SniffedFetcher<'_>,
    root_chunk: &[u8],
    credit: Option<&CreditWindow>,
) -> bool {
    let mut chunk = root_chunk.to_vec();
    for _ in 0..HEADER_SNIFF_MAX_DEPTH {
        let Some((span, payload)) = chunk.split_first_chunk::<8>() else {
            return false;
        };
        let (_, plain) = crate::rs::decode_span(*span);
        if u64::from_le_bytes(plain) <= ant_crypto::CHUNK_SIZE as u64 {
            // A serialised node is never shorter than its header, so a
            // leaf that can't hold one is just as positively raw bytes as
            // one whose header carries the wrong version hash. (Only a
            // single-chunk file can have a leftmost leaf this short: every
            // leaf but the last of a split file is a full chunk.)
            return payload.len() < NODE_HEADER_SIZE || !has_manifest_header(payload);
        }
        // Intermediate chunk: the first reference is the leftmost child
        // (parity references, if any, come after the data references).
        let Some(child) = payload.first_chunk::<32>().copied() else {
            return false;
        };
        match fetcher.sniff_fetch(child, credit).await {
            Ok(wire) if cac_valid(&child, &wire) => chunk = wire,
            _ => return false,
        }
    }
    false
}

/// Does `data` (the start of a serialised node) carry a mantaray
/// version hash? The first 32 bytes are the obfuscation key, the next
/// 31 the version hash `XOR`ed with it. Caller ensures
/// `data.len() >= NODE_HEADER_SIZE`.
fn has_manifest_header(data: &[u8]) -> bool {
    let key = &data[..OBFUSCATION_KEY_SIZE];
    let version_hash: Vec<u8> = data
        [OBFUSCATION_KEY_SIZE..OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % OBFUSCATION_KEY_SIZE])
        .collect();
    is_mantaray_version_hash(&version_hash)
}

/// Is `version_hash` (31 bytes, de-obfuscated) one of the mantaray
/// versions we parse? The Go constants are the full 32-byte
/// keccak256 of "mantaray:0.2" / "mantaray:0.1"; bee writes only the
/// first 31 bytes on the wire (see `versionHashSize = 31` and
/// `copy(*bytes, b)` in `mantaray.initVersion`), so compare truncated.
fn is_mantaray_version_hash(version_hash: &[u8]) -> bool {
    [VERSION_02_HASH_HEX, VERSION_01_HASH_HEX]
        .iter()
        .any(|hex| {
            let full = hex::decode(hex).expect("const");
            version_hash == &full[..VERSION_HASH_SIZE]
        })
}

/// In-memory representation of a mantaray node after unmarshalling.
/// Crate-visible so the chunk-tree traverser in [`crate::traversal`] can
/// walk raw manifest tries (bee `pkg/traversal` semantics: node chunks
/// and value entries, *without* feed dereferencing).
// `node_type` is the on-wire type-tag bitfield (value/edge/with-metadata),
// not a stuttering field name.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone)]
pub(crate) struct Node {
    /// Bee-side bitfield (value/edge/with-metadata). We parse it for
    /// fidelity with the on-wire format and to keep diagnostics readable;
    /// fork lookup is currently driven by `entry`/`forks` directly.
    #[allow(dead_code)]
    node_type: u8,
    pub(crate) entry: Vec<u8>,
    metadata: HashMap<String, String>,
    pub(crate) forks: HashMap<u8, Fork>,
}

#[derive(Debug, Clone)]
pub(crate) struct Fork {
    /// Bee-side bitfield. Parsed for wire fidelity and `Debug` output
    /// only — never for path reconstruction: deriving a `/` from the
    /// path-separator bit is exactly the bug behind issue #13.
    #[allow(dead_code)]
    node_type: u8,
    pub(crate) prefix: Vec<u8>,
    /// 32 bytes, or 64 (`address ‖ key`) in an encrypted manifest.
    pub(crate) child_ref: Vec<u8>,
    pub(crate) metadata: HashMap<String, String>,
}

impl Node {
    /// Parse a fully-joined manifest node. The first 32 bytes are the
    /// obfuscation key (treated literally), the rest is `XORed` with that
    /// key as a 32-byte rolling pad before parsing.
    pub(crate) fn unmarshal(input: &[u8]) -> Result<Self, ManifestError> {
        if input.len() < NODE_HEADER_SIZE {
            return Err(ManifestError::TooShort(format!(
                "{} bytes < header {}",
                input.len(),
                NODE_HEADER_SIZE
            )));
        }
        // De-obfuscate. The key lives in [0..32] in the clear.
        let mut data = input.to_vec();
        let key: [u8; 32] = data[..32].try_into().unwrap();
        for chunk in data[OBFUSCATION_KEY_SIZE..].chunks_mut(OBFUSCATION_KEY_SIZE) {
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= key[i % OBFUSCATION_KEY_SIZE];
            }
        }
        Self::parse_decoded(&data)
    }

    fn parse_decoded(data: &[u8]) -> Result<Self, ManifestError> {
        let version_hash = &data[OBFUSCATION_KEY_SIZE..OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE];
        if !is_mantaray_version_hash(version_hash) {
            // Most often this means the user passed a `/bytes/`
            // reference (raw file) where a `/bzz/` reference was
            // expected. Log the head so a debug-level run can tell
            // that case apart from a corrupt manifest.
            debug!(
                target: "ant_retrieval::mantaray",
                len = data.len(),
                version_hash_31 = %hex::encode(version_hash),
                "mantaray: version-hash mismatch, returning NotAManifest",
            );
            return Err(ManifestError::NotAManifest);
        }
        let v01_full = hex::decode(VERSION_01_HASH_HEX).expect("const");
        let is_v01 = version_hash == &v01_full[..VERSION_HASH_SIZE];
        let ref_size = data[OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE];
        if ref_size != 32 && ref_size != 64 && ref_size != 0 {
            return Err(ManifestError::InvalidRefLength(ref_size));
        }
        let ref_size = ref_size as usize;

        let mut offset = NODE_HEADER_SIZE;
        // Entry: `ref_size` bytes (zeroed for nodes without an entry).
        if data.len() < offset + ref_size {
            return Err(ManifestError::TooShort(format!(
                "entry: have {}, need {}",
                data.len(),
                offset + ref_size
            )));
        }
        let entry_bytes = data[offset..offset + ref_size].to_vec();
        offset += ref_size;

        // 32-byte fork-index bitmap.
        if data.len() < offset + 32 {
            return Err(ManifestError::TooShort("forks index".into()));
        }
        let index = data[offset..offset + 32].to_vec();
        offset += 32;

        // Determine if this node holds an entry: bee's marshaller doesn't
        // round-trip the bare value-flag, so we infer it from the entry
        // bytes being non-zero. A directory node with no own value has
        // an all-zero entry slot.
        let has_entry = entry_bytes.iter().any(|&b| b != 0);
        let mut node_type: u8 = 0;
        if has_entry {
            node_type |= NODE_TYPE_VALUE;
        }
        // Edge: any fork present.
        if index.iter().any(|&b| b != 0) {
            node_type |= NODE_TYPE_EDGE;
        }

        let mut forks = HashMap::new();
        // Walk the bitmap in ascending bit order. Bee writes forks in the
        // same order during marshal so we follow suit.
        for byte in 0u16..256u16 {
            let b = byte as u8;
            let bit_set = (index[(b / 8) as usize] >> (b % 8)) & 1 != 0;
            if !bit_set {
                continue;
            }

            // Per-fork header: type(1) + prefixLen(1) + 30 prefix bytes.
            if is_v01 {
                if data.len() < offset + FORK_PRE_REF_SIZE + ref_size {
                    return Err(ManifestError::TooShort(format!(
                        "fork {b:02x}: need {}, have {}",
                        offset + FORK_PRE_REF_SIZE + ref_size,
                        data.len()
                    )));
                }
                let f_type = data[offset];
                let prefix_len = data[offset + 1] as usize;
                if prefix_len == 0 || prefix_len > FORK_PREFIX_MAX {
                    return Err(ManifestError::TooShort(format!(
                        "fork {b:02x} prefix_len {prefix_len} out of range"
                    )));
                }
                let prefix = data[offset + 2..offset + 2 + prefix_len].to_vec();
                let child_ref = data
                    [offset + FORK_PRE_REF_SIZE..offset + FORK_PRE_REF_SIZE + ref_size]
                    .to_vec();
                forks.insert(
                    b,
                    Fork {
                        node_type: f_type,
                        prefix,
                        child_ref,
                        metadata: HashMap::new(),
                    },
                );
                offset += FORK_PRE_REF_SIZE + ref_size;
            } else {
                // mantaray:0.2
                if data.len() < offset + 1 {
                    return Err(ManifestError::TooShort("fork type byte".into()));
                }
                let f_type = data[offset];
                let mut fork_size = FORK_PRE_REF_SIZE + ref_size;
                let has_meta = (f_type & NODE_TYPE_WITH_METADATA) != 0;
                let mut meta_size = 0usize;
                if has_meta {
                    if data.len() < offset + fork_size + FORK_METADATA_SIZE_BYTES {
                        return Err(ManifestError::TooShort("fork metadata size".into()));
                    }
                    meta_size = u16::from_be_bytes([
                        data[offset + fork_size],
                        data[offset + fork_size + 1],
                    ]) as usize;
                    fork_size += FORK_METADATA_SIZE_BYTES + meta_size;
                }
                if data.len() < offset + fork_size {
                    return Err(ManifestError::TooShort(format!(
                        "fork body: need {}, have {}",
                        offset + fork_size,
                        data.len()
                    )));
                }
                let prefix_len = data[offset + 1] as usize;
                if prefix_len == 0 || prefix_len > FORK_PREFIX_MAX {
                    return Err(ManifestError::TooShort(format!(
                        "fork {b:02x} prefix_len {prefix_len} out of range"
                    )));
                }
                let prefix = data[offset + 2..offset + 2 + prefix_len].to_vec();
                let child_ref = data
                    [offset + FORK_PRE_REF_SIZE..offset + FORK_PRE_REF_SIZE + ref_size]
                    .to_vec();
                let mut fork_meta = HashMap::new();
                if has_meta && meta_size > 0 {
                    let meta_start =
                        offset + FORK_PRE_REF_SIZE + ref_size + FORK_METADATA_SIZE_BYTES;
                    let meta_bytes = &data[meta_start..meta_start + meta_size];
                    fork_meta = parse_metadata(meta_bytes)?;
                    // Forks set with-metadata flag on themselves; some of
                    // the keys (e.g. `Content-Type`) are bee-specific,
                    // others (`website-index-document`) belong on the
                    // *parent* node. Treat them as fork-level for now;
                    // walk() lifts them onto the child during traversal.
                }
                forks.insert(
                    b,
                    Fork {
                        node_type: f_type,
                        prefix,
                        child_ref,
                        metadata: fork_meta,
                    },
                );
                offset += fork_size;
            }
        }

        // Per the bee marshaller, root-level metadata (the kind that
        // holds `website-index-document`) is encoded on the **fork that
        // covers the root's path-separator key** in v0.2. In practice,
        // for `swarm-cli upload <file>`, the metadata goes on the value
        // fork; we already pulled that into fork_meta. The root node
        // itself doesn't carry metadata directly in this serialiser.
        Ok(Self {
            node_type,
            entry: entry_bytes,
            metadata: HashMap::new(),
            forks,
        })
    }
}

/// Parse JSON metadata after stripping bee's `\n` padding. Mantaray pads
/// the metadata blob to a multiple of 32 with newlines so each metadata
/// region aligns to the obfuscation block size.
fn parse_metadata(raw: &[u8]) -> Result<HashMap<String, String>, ManifestError> {
    let s = std::str::from_utf8(raw).map_err(|e| ManifestError::InvalidMetadata(e.to_string()))?;
    let s = s.trim_end_matches('\n');
    if s.is_empty() {
        return Ok(HashMap::new());
    }
    // Tiny bespoke JSON object parser: bee writes a flat
    // `map[string]string`, so the expected shape is `{"k":"v",...}` with
    // no nesting. Avoids pulling in serde_json for a five-line use case
    // — and crucially preserves whatever ordering the producer chose
    // without imposing one.
    parse_flat_json_object(s)
}

/// Parse a flat JSON object `{"k":"v",...}` into a string map. Tolerant
/// of standard JSON escape sequences inside strings; bee never emits
/// non-ASCII keys, but values may contain spaces or punctuation.
fn parse_flat_json_object(s: &str) -> Result<HashMap<String, String>, ManifestError> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut out = HashMap::new();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'{' {
        return Err(ManifestError::InvalidMetadata(format!(
            "expected '{{', got {:?}",
            &s[..s.len().min(40)]
        )));
    }
    i += 1;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'}' {
            return Ok(out);
        }
        let key = parse_json_string(bytes, &mut i)?;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            return Err(ManifestError::InvalidMetadata("missing ':'".into()));
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = parse_json_string(bytes, &mut i)?;
        out.insert(key, value);
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
            continue;
        }
        if i < bytes.len() && bytes[i] == b'}' {
            return Ok(out);
        }
        return Err(ManifestError::InvalidMetadata("expected ',' or '}'".into()));
    }
}

/// Parse a single JSON-quoted string starting at `*i`. Advances `*i`
/// past the closing quote. Handles `\"`, `\\`, `\/`, `\n`, `\t`, `\r`,
/// `\b`, `\f`, and `\uXXXX` (BMP only — bee never writes anything else).
fn parse_json_string(bytes: &[u8], i: &mut usize) -> Result<String, ManifestError> {
    if *i >= bytes.len() || bytes[*i] != b'"' {
        return Err(ManifestError::InvalidMetadata("expected '\"'".into()));
    }
    *i += 1;
    let mut out = String::new();
    while *i < bytes.len() {
        let c = bytes[*i];
        if c == b'"' {
            *i += 1;
            return Ok(out);
        }
        if c == b'\\' {
            *i += 1;
            if *i >= bytes.len() {
                return Err(ManifestError::InvalidMetadata("dangling escape".into()));
            }
            match bytes[*i] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000c}'),
                b'u' => {
                    if *i + 4 >= bytes.len() {
                        return Err(ManifestError::InvalidMetadata("\\u truncated".into()));
                    }
                    let hex = std::str::from_utf8(&bytes[*i + 1..*i + 5])
                        .map_err(|e| ManifestError::InvalidMetadata(e.to_string()))?;
                    let cp = u32::from_str_radix(hex, 16)
                        .map_err(|e| ManifestError::InvalidMetadata(e.to_string()))?;
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                    }
                    *i += 4;
                }
                other => {
                    return Err(ManifestError::InvalidMetadata(format!(
                        "bad escape \\{}",
                        other as char
                    )))
                }
            }
            *i += 1;
        } else {
            // Raw UTF-8 bytes pass through. Reading char-by-char from
            // `bytes` would be cheaper but mantaray metadata is tiny so
            // we eat the cost of the helper.
            let s = std::str::from_utf8(&bytes[*i..]).map_err(|e| {
                ManifestError::InvalidMetadata(format!("non-utf8 in metadata: {e}"))
            })?;
            let ch = s.chars().next().unwrap();
            out.push(ch);
            *i += ch.len_utf8();
        }
    }
    Err(ManifestError::InvalidMetadata("unterminated string".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChunkFetcher;
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};
    use std::error::Error;

    /// HashMap-backed fetcher mirroring `joiner::tests::MapFetcher`.
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

    #[async_trait]
    impl ChunkFetcher for MapFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> {
                    format!("missing chunk {}", hex::encode(addr)).into()
                })
        }
    }

    /// Pre-recorded wire bytes from a real `swarm-cli upload` of an
    /// 85-byte text file via the public Bee gateway (April 2026). Root
    /// reference is `b6c8b1b6...`. Captured to make sure the v0.2
    /// version-hash truncation, fork-metadata extraction and the
    /// website-index-document fallback all stay in sync with bee.
    const ROOT_HEX: &str = "a00100000000000000000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f200000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000100000000000000000000000000000000000012012f00000000000000000000000000000000000000000000000000000000000cc878d32c96126d47f63fbe391114ee1438cd521146fc975dea1546d302b6c0003e7b22776562736974652d696e6465782d646f63756d656e74223a2268656c6c6f2e747874227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a120968656c6c6f2e7478740000000000000000000000000000000000000000000ad6c856f417b0805250d41a46559c9402a9251f8bc6acd65540fe0e68b45d41005e7b22436f6e74656e742d54797065223a22746578742f706c61696e3b20636861727365743d7574662d38222c2246696c656e616d65223a2268656c6c6f2e747874227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    const CHILD_SLASH_HEX: &str = "600000000000000000000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f000000000000000000000000000000000000000000000000000000000000000000";
    const CHILD_H_HEX: &str = "800000000000000000000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f202f63d85b71d63176df24ea98df065d4de18163fcbc9f75e6d23f4327f33bca820000000000000000000000000000000000000000000000000000000000000000";
    const ROOT_ADDR_HEX: &str = "b6c8b1b632dac74382f7f0fb9ac44d4885b4b894d2b794e57fd1c43f773f78a2";
    const CHILD_SLASH_ADDR_HEX: &str =
        "0cc878d32c96126d47f63fbe391114ee1438cd521146fc975dea1546d302b6c0";
    const CHILD_H_ADDR_HEX: &str =
        "0ad6c856f417b0805250d41a46559c9402a9251f8bc6acd65540fe0e68b45d41";
    const FILE_DATA_REF_HEX: &str =
        "2f63d85b71d63176df24ea98df065d4de18163fcbc9f75e6d23f4327f33bca82";

    /// Build a fetcher pre-populated with the three on-wire chunks from
    /// the gateway capture above. Tests can then walk the manifest as
    /// if `antd` had fetched these chunks itself.
    fn gateway_fetcher() -> MapFetcher {
        let mut f = MapFetcher::new();
        f.insert(decode_addr(ROOT_ADDR_HEX), hex::decode(ROOT_HEX).unwrap());
        f.insert(
            decode_addr(CHILD_SLASH_ADDR_HEX),
            hex::decode(CHILD_SLASH_HEX).unwrap(),
        );
        f.insert(
            decode_addr(CHILD_H_ADDR_HEX),
            hex::decode(CHILD_H_HEX).unwrap(),
        );
        f
    }

    fn decode_addr(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }

    /// Empty path: should resolve via `website-index-document` on the
    /// "/" fork, descend into the "hello.txt" fork, and return the
    /// file's data ref + Content-Type.
    #[tokio::test]
    async fn lookup_empty_path_uses_index_document() {
        let fetcher = gateway_fetcher();
        let root = decode_addr(ROOT_ADDR_HEX);
        let res = lookup_path(&fetcher, &root, "").await.unwrap();
        assert_eq!(hex::encode(res.data_ref), FILE_DATA_REF_HEX);
        assert_eq!(
            res.content_type.as_deref(),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(
            res.metadata
                .get("Filename")
                .map(std::string::String::as_str),
            Some("hello.txt")
        );
    }

    /// Build a fetcher pre-loaded with a multi-page collection (each
    /// file a tiny HTML body) plus its `website-index-document:
    /// index.html` manifest, and return `(fetcher, root, data_refs)`.
    /// Mirrors what `swarm-deploy` produces for a static site.
    fn website_fetcher(paths: &[&str]) -> (MapFetcher, [u8; 32], HashMap<String, [u8; 32]>) {
        use crate::manifest_writer::{build_collection_manifest, IndexAnchor, ManifestFile};
        let mut fetcher = MapFetcher::new();
        let mut files = Vec::new();
        let mut data_refs = HashMap::new();
        for p in paths {
            let body = format!("<html>{p}</html>");
            let split = crate::splitter::split_bytes(body.as_bytes());
            for c in &split.chunks {
                fetcher.insert(c.address, c.wire.clone());
            }
            data_refs.insert((*p).to_string(), split.root);
            files.push(ManifestFile {
                path: (*p).to_string(),
                content_type: Some("text/html".to_string()),
                data_ref: split.root.to_vec(),
            });
        }
        let manifest =
            build_collection_manifest(&files, Some("index.html"), IndexAnchor::ZeroEntry).unwrap();
        for c in &manifest.chunks {
            fetcher.insert(c.address, c.wire.clone());
        }
        (fetcher, manifest.root, data_refs)
    }

    /// Bee-compat directory handling: a slash-terminated directory path
    /// resolves to that directory's `index.html` (the directory-suffix
    /// retry), while the slash-less form is a `Directory` miss — bee's
    /// `bzzDownloadHandler` answers those with a 308 redirect to the
    /// slash-terminated URL *before* trying the index suffix, and the
    /// gateway maps `ManifestError::Directory` to exactly that.
    #[tokio::test]
    async fn lookup_directory_path_uses_index_document() {
        let (fetcher, root, refs) = website_fetcher(&[
            "index.html",
            "developer/index.html",
            "developer/deep/index.html",
        ]);

        for (req, want) in [
            ("developer/", "developer/index.html"),
            ("/developer/", "developer/index.html"),
            ("developer/deep/", "developer/deep/index.html"),
        ] {
            let res = lookup_path(&fetcher, &root, req).await.unwrap();
            assert_eq!(res.data_ref, refs[want], "request {req:?}");
        }

        // Slash-less directory requests redirect (bee's HasPrefix check
        // runs before the index-document retry).
        for req in ["developer", "developer/deep"] {
            let err = lookup_path(&fetcher, &root, req).await.unwrap_err();
            assert!(
                matches!(err, ManifestError::Directory { ref path } if path == req),
                "request {req:?}: expected Directory, got {err:?}",
            );
        }
    }

    /// A genuine miss still 404s — the directory-suffix retry must not
    /// invent pages. Also covers "path already ending in index.html is
    /// not double-suffixed": `missing/index.html` is looked up verbatim
    /// (and not as `missing/index.html/index.html`).
    #[tokio::test]
    async fn lookup_missing_directory_still_not_found() {
        let (fetcher, root, _refs) = website_fetcher(&["index.html", "developer/index.html"]);
        for req in ["nonexistent/", "missing/index.html"] {
            let err = lookup_path(&fetcher, &root, req).await.unwrap_err();
            assert!(
                matches!(err, ManifestError::NotFound { .. }),
                "request {req:?}: expected NotFound, got {err:?}",
            );
        }
    }

    /// `join_index_document` mirrors Bee's `path.Join(pathVar, indexDoc)`:
    /// a trailing slash is collapsed, an empty base yields the bare index.
    #[test]
    fn join_index_document_matches_bee_path_join() {
        assert_eq!(
            join_index_document("developer", "index.html"),
            "developer/index.html"
        );
        assert_eq!(
            join_index_document("developer/", "index.html"),
            "developer/index.html"
        );
        assert_eq!(join_index_document("a/b/", "index.html"), "a/b/index.html");
        assert_eq!(join_index_document("", "index.html"), "index.html");
    }

    /// Explicit path matches the same file via the `h` fork.
    #[tokio::test]
    async fn lookup_explicit_path() {
        let fetcher = gateway_fetcher();
        let root = decode_addr(ROOT_ADDR_HEX);
        let res = lookup_path(&fetcher, &root, "hello.txt").await.unwrap();
        assert_eq!(hex::encode(res.data_ref), FILE_DATA_REF_HEX);
        assert_eq!(
            res.content_type.as_deref(),
            Some("text/plain; charset=utf-8")
        );
    }

    /// Non-existent path returns a clear `NotFound`.
    #[tokio::test]
    async fn lookup_unknown_path_not_found() {
        let fetcher = gateway_fetcher();
        let root = decode_addr(ROOT_ADDR_HEX);
        let err = lookup_path(&fetcher, &root, "missing.txt")
            .await
            .unwrap_err();
        assert!(matches!(err, ManifestError::NotFound { .. }));
    }

    /// A `/bytes/`-style raw chunk passed in by mistake should yield
    /// `NotAManifest` (so the caller can guide the user to `--bytes`
    /// or `antctl get` for a single chunk). Use a payload long enough
    /// to clear the header-size check so we hit the version-hash
    /// comparison rather than `TooShort`.
    #[tokio::test]
    async fn lookup_non_manifest_chunk_distinct_error() {
        let payload = vec![0xab; 200];
        let (addr, wire) = ant_crypto::cac_new(&payload).unwrap();
        let mut fetcher = MapFetcher::new();
        fetcher.insert(addr, wire);
        let err = lookup_path(&fetcher, &addr, "anything").await.unwrap_err();
        assert!(
            matches!(err, ManifestError::NotAManifest),
            "expected NotAManifest, got {err:?}",
        );
    }

    /// Regression for issue #13: `collect_entries` used to append a `/`
    /// to the listing path whenever a fork carried bee's path-separator
    /// type bit. That bit means "this prefix *contains* a separator",
    /// never "append one" — so whenever a fork boundary fell inside a
    /// name segment the listing emitted a path with a spurious `/`
    /// (`assets/…` as `a/ssets/…`, `…payment.png` as `…payment.pn/g`)
    /// that retrieval 404s on. Invariant locked here: every value path
    /// returned by `list_manifest_paths` must round-trip through
    /// `lookup_path` on the same manifest to the same data ref.
    #[tokio::test]
    async fn listed_paths_round_trip_through_lookup() {
        // Paths chosen so the trie forks mid-segment:
        //  - `admin/…` vs `assets/…` share only `a`, so the split-off
        //    prefixes carry a later `/` inside them (directory variant —
        //    unrecoverable from metadata);
        //  - the two `fonts/iAWriterMonoS-…` names split inside the
        //    basename (the originally reported variant).
        let paths = [
            "admin/.gitignore",
            "assets/hero/build.png",
            "fonts/iAWriterMonoS-Bold.woff",
            "fonts/iAWriterMonoS-Regular.woff",
            "index.html",
        ];
        let (fetcher, root, data_refs) = website_fetcher(&paths);

        let entries = list_manifest_paths(&fetcher, &root).await.unwrap();
        let listed: Vec<&str> = entries
            .iter()
            .filter(|e| e.reference.is_some())
            .map(|e| e.path.as_str())
            .collect();
        let mut want = paths;
        want.sort_unstable();
        assert_eq!(listed, want, "listing must emit exactly the stored paths");

        for entry in entries.iter().filter(|e| e.reference.is_some()) {
            let looked_up = lookup_path(&fetcher, &root, &entry.path)
                .await
                .unwrap_or_else(|e| panic!("listed path {:?} does not resolve: {e:?}", entry.path));
            assert_eq!(
                looked_up.data_ref.as_slice(),
                data_refs[entry.path.as_str()].as_slice(),
                "listed path {:?} resolved to a different data ref than it was stored under",
                entry.path,
            );
        }
    }

    /// JSON escape parser: covers every escape mantaray emits.
    #[test]
    fn json_string_round_trip() {
        let mut i = 0;
        let s = b"\"hello world\"";
        assert_eq!(parse_json_string(s, &mut i).unwrap(), "hello world");
        assert_eq!(i, s.len());

        let mut i = 0;
        let s = b"\"a\\nb\"";
        assert_eq!(parse_json_string(s, &mut i).unwrap(), "a\nb");
    }

    /// Flat JSON object parser: handles the shapes bee actually writes
    /// (Content-Type strings, filenames with spaces).
    #[test]
    fn flat_json_object_basic() {
        let m = parse_flat_json_object(
            "{\"Content-Type\":\"text/plain; charset=utf-8\",\"Filename\":\"hello.txt\"}",
        )
        .unwrap();
        assert_eq!(m.get("Content-Type").unwrap(), "text/plain; charset=utf-8");
        assert_eq!(m.get("Filename").unwrap(), "hello.txt");
        assert_eq!(m.len(), 2);
    }

    /// Trailing newline padding (bee pads metadata blocks to 32 bytes
    /// with '\n' before serialising).
    #[test]
    fn flat_json_object_strip_padding() {
        let raw = b"{\"k\":\"v\"}\n\n\n\n";
        let m = parse_metadata(raw).unwrap();
        assert_eq!(m.get("k").unwrap(), "v");
    }

    /// Empty padded metadata = no entries, no error.
    #[test]
    fn flat_json_object_empty_padding() {
        let raw = b"\n\n\n";
        let m = parse_metadata(raw).unwrap();
        assert!(m.is_empty());
    }

    /// End-to-end walk of the blog.swarm.eth content manifest for the
    /// path `/search`. This was the request that timed out in
    /// production with a flood of `chunk=00000000…` retrievals. The
    /// literal `search` path misses (the `s` fork's child prefix is
    /// `earch/index.html`, not `earch`), and `search/` IS a prefix of
    /// entries in this manifest — so bee's `bzzDownloadHandler` answers
    /// with a 308 redirect to `search/` before ever trying the
    /// index-document retry. The lookup must surface
    /// `ManifestError::Directory` (which the gateway turns into that
    /// redirect) and crucially never ask the fetcher for the all-zero
    /// address that caused the original flood — the prefix walk decides
    /// from the already-staged `s` child node alone.
    #[tokio::test]
    async fn walk_blog_swarm_eth_search_falls_back_to_index_document() {
        const ROOT_PAYLOAD: &str = "00000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f2000000000000000000000000000000000000000000000000000000000000000000000000000801000000000007a03a9040000000000000000000000000000000012012f00000000000000000000000000000000000000000000000000000000000cc878d32c96126d47f63fbe391114ee1438cd521146fc975dea1546d302b6c0003e7b22776562736974652d696e6465782d646f63756d656e74223a22696e6465782e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a12083430342e68746d6c000000000000000000000000000000000000000000009d2afcaf1de60508865777137fc2eafd61221b37101083a0b4847dc818d6b4e7005e7b22436f6e74656e742d54797065223a22746578742f68746d6c3b20636861727365743d7574662d38222c2246696c656e616d65223a223430342e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a1a1061646d696e2f2e67697469676e6f726500000000000000000000000000003891cf97520e77cc4b11d0606863f6d25b1476ee01e23eed4ec8196a74ac8fea005e7b22436f6e74656e742d54797065223a226170706c69636174696f6e2f6f637465742d73747265616d222c2246696c656e616d65223a222e67697469676e6f7265227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0401630000000000000000000000000000000000000000000000000000000000d7b04da63d26b8b8b40300102f810a7ca5247095d6c6a6d030d8d9f25e9dea71120b64656661756c742e706e6700000000000000000000000000000000000000e1eb16a43f2bd7d41cc476c129eace731e4c9f620b8d6241a6e3c051ba7b4bd7003e7b22436f6e74656e742d54797065223a22696d6167652f706e67222c2246696c656e616d65223a2264656661756c742e706e67227d0a0a0a0a0a0a0a0a0a0c03656e2f000000000000000000000000000000000000000000000000000000d30d9932f844f8aeeef19f8aa2a45fd90c83aba3afed92447ba0931b4cf29ddb0401660000000000000000000000000000000000000000000000000000000000348afc6f95e6dd6612631a66777352849add9f451f43490dd220f44a03ad548d0c05686976652f0000000000000000000000000000000000000000000000000094289260467f5cb1a285b1d6d772f585337e1202eacd148c0d2e95eca29206b1120a696e6465782e68746d6c0000000000000000000000000000000000000000ba2e49319f9718dedc1cebd3b3d1933c41b3212aa89677e2e5c5a1bae3518375005e7b22436f6e74656e742d54797065223a22746578742f68746d6c3b20636861727365743d7574662d38222c2246696c656e616d65223a22696e6465782e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c097061676566696e642f00000000000000000000000000000000000000000031f2e6c0601ee97fd5127b3c00d4539b183b2dd8a4380f280b186f066bdfba7a0401730000000000000000000000000000000000000000000000000000000000e8aa9151a4c271bc7099cd1de086aa563b6b2e5ad8191e5208ad55fdaccb44840c0875706c6f6164732f000000000000000000000000000000000000000000002613920be866d1dc196a1ebe17bf89058d7f3236fbbb6b0206b286fab20d45eb0c0477616d2f0000000000000000000000000000000000000000000000000000fadf98f25eb13245da5a0ee52a9c899d964a5d8bd9b1716787a69779118c82df0c037a682f00000000000000000000000000000000000000000000000000000069892465cd55cbd6cce1e3fcca4b24566355dfa05fdbfadb80341181e60b640b";
        const S_PAYLOAD: &str = "00000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020028000000000000000000000000000000000001a1065617263682f696e6465782e68746d6c000000000000000000000000000014c3a451758dcac5dc003b131c20df4d012898f304c492d0264db0d6d1552bcc005e7b22436f6e74656e742d54797065223a22746578742f68746d6c3b20636861727365743d7574662d38222c2246696c656e616d65223a22696e6465782e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a120a6974656d61702e786d6c0000000000000000000000000000000000000000d8de45fc0674d70a63a8f51378f6a714a9e5d288ec925accf8b65d13a701d939003e7b22436f6e74656e742d54797065223a226170706c69636174696f6e2f786d6c222c2246696c656e616d65223a22736974656d61702e786d6c227d0a0a0a04057761726d5f00000000000000000000000000000000000000000000000000ced34a771ed8377594ea6fca11c76ec22f61d4366882c658dcb9ae7dba644ae3";

        // The chunks the fetcher needs are stored as `span (8 LE) ‖
        // payload`. For these manifests the span byte width is the
        // payload length itself (single-chunk node).
        let root_payload = hex::decode(ROOT_PAYLOAD).unwrap();
        let s_payload = hex::decode(S_PAYLOAD).unwrap();
        let root_addr =
            decode_addr("567fbf0f92c09ad52afd736398deb3a674a6f8eca2495694292f42a859d9e60e");
        let s_addr =
            decode_addr("e8aa9151a4c271bc7099cd1de086aa563b6b2e5ad8191e5208ad55fdaccb4484");
        let mut root_wire = Vec::with_capacity(8 + root_payload.len());
        root_wire.extend_from_slice(&(root_payload.len() as u64).to_le_bytes());
        root_wire.extend_from_slice(&root_payload);
        let mut s_wire = Vec::with_capacity(8 + s_payload.len());
        s_wire.extend_from_slice(&(s_payload.len() as u64).to_le_bytes());
        s_wire.extend_from_slice(&s_payload);

        let mut fetcher = MapFetcher::new();
        fetcher.insert(root_addr, root_wire);
        fetcher.insert(s_addr, s_wire);

        let err = lookup_path(&fetcher, &root_addr, "search")
            .await
            .unwrap_err();
        // `search/` prefixes the real `search/index.html` entry, so the
        // lookup reports a directory (the gateway 308s to `search/`,
        // exactly like bee). The decision comes from the staged `s`
        // child node alone — in particular the walk never requested the
        // all-zero address from the original production bug (the
        // MapFetcher would have errored with a "missing 0000…" fetch).
        match err {
            ManifestError::Directory { path } => assert_eq!(path, "search"),
            other => panic!("expected Directory for 'search', got {other:?}"),
        }

        // The slash-terminated form runs the index-document retry and
        // descends into the real `search/index.html` leaf, whose node
        // chunk we deliberately didn't stage: the error names that
        // exact non-zero address, never the all-zero one.
        let err = lookup_path(&fetcher, &root_addr, "search/")
            .await
            .unwrap_err();
        match err {
            ManifestError::Fetch(JoinError::FetchChunk { addr, .. }) => {
                assert_eq!(
                    addr, "14c3a451758dcac5dc003b131c20df4d012898f304c492d0264db0d6d1552bcc",
                    "fallback should fetch the real search/index.html leaf",
                );
                assert_ne!(
                    addr,
                    hex::encode([0u8; 32]),
                    "must never request the all-zero address",
                );
            }
            other => panic!("expected Fetch(FetchChunk) for the index leaf, got {other:?}"),
        }
    }

    /// Real-world fixture: the `s` child node from blog.swarm.eth's
    /// content manifest. This is the node `walk` descends into when
    /// asked for `/search/...` — three forks (`e` for `earch/index.html`,
    /// `i` for `itemap.xml`, `w` for `warm_`).
    #[test]
    fn unmarshal_real_blog_swarm_eth_s_child() {
        const PAYLOAD_HEX: &str = "00000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020028000000000000000000000000000000000001a1065617263682f696e6465782e68746d6c000000000000000000000000000014c3a451758dcac5dc003b131c20df4d012898f304c492d0264db0d6d1552bcc005e7b22436f6e74656e742d54797065223a22746578742f68746d6c3b20636861727365743d7574662d38222c2246696c656e616d65223a22696e6465782e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a120a6974656d61702e786d6c0000000000000000000000000000000000000000d8de45fc0674d70a63a8f51378f6a714a9e5d288ec925accf8b65d13a701d939003e7b22436f6e74656e742d54797065223a226170706c69636174696f6e2f786d6c222c2246696c656e616d65223a22736974656d61702e786d6c227d0a0a0a04057761726d5f00000000000000000000000000000000000000000000000000ced34a771ed8377594ea6fca11c76ec22f61d4366882c658dcb9ae7dba644ae3";
        let payload = hex::decode(PAYLOAD_HEX).expect("hex");
        assert_eq!(payload.len(), 480);
        let node = Node::unmarshal(&payload).expect("unmarshal");
        let mut keys: Vec<u8> = node.forks.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, b"eiw".to_vec());
        let e = node.forks.get(&b'e').unwrap();
        assert_eq!(e.prefix, b"earch/index.html");
        assert_eq!(
            hex::encode(&e.child_ref),
            "14c3a451758dcac5dc003b131c20df4d012898f304c492d0264db0d6d1552bcc"
        );
    }

    /// Real-world fixture: the resolved content manifest of
    /// `blog.swarm.eth` at feed index 47 (April 2026). Captured as the
    /// raw 1440-byte node payload (post-span-strip). This is the
    /// manifest `antd` was failing to walk after feed dereferencing —
    /// the on-disk obfuscation key happens to be all zeros, so
    /// XOR-decryption is a no-op and bee's parse can be exercised
    /// directly. Pins the v0.2 fork header layout (type, `prefix_len`,
    /// padded prefix, `child_ref`, optional metadata size + bytes) so
    /// any drift between us and bee surfaces here rather than as a
    /// silent all-zero `child_ref` request at runtime.
    #[test]
    fn unmarshal_real_blog_swarm_eth_root() {
        // 1440 bytes = exactly the chunk payload (no outer span).
        const PAYLOAD_HEX: &str = "00000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f2000000000000000000000000000000000000000000000000000000000000000000000000000801000000000007a03a9040000000000000000000000000000000012012f00000000000000000000000000000000000000000000000000000000000cc878d32c96126d47f63fbe391114ee1438cd521146fc975dea1546d302b6c0003e7b22776562736974652d696e6465782d646f63756d656e74223a22696e6465782e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a12083430342e68746d6c000000000000000000000000000000000000000000009d2afcaf1de60508865777137fc2eafd61221b37101083a0b4847dc818d6b4e7005e7b22436f6e74656e742d54797065223a22746578742f68746d6c3b20636861727365743d7574662d38222c2246696c656e616d65223a223430342e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a1a1061646d696e2f2e67697469676e6f726500000000000000000000000000003891cf97520e77cc4b11d0606863f6d25b1476ee01e23eed4ec8196a74ac8fea005e7b22436f6e74656e742d54797065223a226170706c69636174696f6e2f6f637465742d73747265616d222c2246696c656e616d65223a222e67697469676e6f7265227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0401630000000000000000000000000000000000000000000000000000000000d7b04da63d26b8b8b40300102f810a7ca5247095d6c6a6d030d8d9f25e9dea71120b64656661756c742e706e6700000000000000000000000000000000000000e1eb16a43f2bd7d41cc476c129eace731e4c9f620b8d6241a6e3c051ba7b4bd7003e7b22436f6e74656e742d54797065223a22696d6167652f706e67222c2246696c656e616d65223a2264656661756c742e706e67227d0a0a0a0a0a0a0a0a0a0c03656e2f000000000000000000000000000000000000000000000000000000d30d9932f844f8aeeef19f8aa2a45fd90c83aba3afed92447ba0931b4cf29ddb0401660000000000000000000000000000000000000000000000000000000000348afc6f95e6dd6612631a66777352849add9f451f43490dd220f44a03ad548d0c05686976652f0000000000000000000000000000000000000000000000000094289260467f5cb1a285b1d6d772f585337e1202eacd148c0d2e95eca29206b1120a696e6465782e68746d6c0000000000000000000000000000000000000000ba2e49319f9718dedc1cebd3b3d1933c41b3212aa89677e2e5c5a1bae3518375005e7b22436f6e74656e742d54797065223a22746578742f68746d6c3b20636861727365743d7574662d38222c2246696c656e616d65223a22696e6465782e68746d6c227d0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c097061676566696e642f00000000000000000000000000000000000000000031f2e6c0601ee97fd5127b3c00d4539b183b2dd8a4380f280b186f066bdfba7a0401730000000000000000000000000000000000000000000000000000000000e8aa9151a4c271bc7099cd1de086aa563b6b2e5ad8191e5208ad55fdaccb44840c0875706c6f6164732f000000000000000000000000000000000000000000002613920be866d1dc196a1ebe17bf89058d7f3236fbbb6b0206b286fab20d45eb0c0477616d2f0000000000000000000000000000000000000000000000000000fadf98f25eb13245da5a0ee52a9c899d964a5d8bd9b1716787a69779118c82df0c037a682f00000000000000000000000000000000000000000000000000000069892465cd55cbd6cce1e3fcca4b24566355dfa05fdbfadb80341181e60b640b";
        let payload = hex::decode(PAYLOAD_HEX).expect("hex");
        assert_eq!(payload.len(), 1440);
        let node = Node::unmarshal(&payload).expect("unmarshal");

        // 14 forks: '/', '4', 'a', 'c', 'd', 'e', 'f', 'h', 'i', 'p',
        // 's', 'u', 'w', 'z'. (Verified against `swarm-cli` output.)
        let want_keys: Vec<u8> = b"/4acdefhipsuwz".to_vec();
        let mut got_keys: Vec<u8> = node.forks.keys().copied().collect();
        got_keys.sort_unstable();
        assert_eq!(got_keys, want_keys, "fork set mismatch");

        // Spot-check three forks across the manifest to catch drift in
        // either the meta-size handling (fork[/]: with-metadata, big
        // meta) or the bare-edge case (fork[c]: edge, no meta).
        let slash = node.forks.get(&b'/').expect("/ fork");
        assert_eq!(slash.prefix, b"/");
        assert_eq!(
            hex::encode(&slash.child_ref),
            "0cc878d32c96126d47f63fbe391114ee1438cd521146fc975dea1546d302b6c0",
        );
        assert_eq!(
            slash
                .metadata
                .get("website-index-document")
                .map(String::as_str),
            Some("index.html"),
        );

        let s_fork = node.forks.get(&b's').expect("s fork");
        assert_eq!(s_fork.prefix, b"s");
        assert_eq!(
            hex::encode(&s_fork.child_ref),
            "e8aa9151a4c271bc7099cd1de086aa563b6b2e5ad8191e5208ad55fdaccb4484",
        );
        assert!(s_fork.metadata.is_empty());

        let z_fork = node.forks.get(&b'z').expect("z fork");
        assert_eq!(z_fork.prefix, b"zh/");
        assert_eq!(
            hex::encode(&z_fork.child_ref),
            "69892465cd55cbd6cce1e3fcca4b24566355dfa05fdbfadb80341181e60b640b",
        );
    }

    /// Fetcher that serves a fixed chunk set and counts every fetch, so
    /// a test can tell a header sniff from a full join.
    struct CountingFetcher {
        inner: MapFetcher,
        fetches: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ChunkFetcher for CountingFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.fetch(addr).await
        }
    }

    /// Every chunk of `chunks` keyed by address.
    fn chunk_map(chunks: &[crate::SplitChunk]) -> HashMap<[u8; 32], Vec<u8>> {
        chunks.iter().map(|c| (c.address, c.wire.clone())).collect()
    }

    /// The root-to-leftmost-leaf path of a split file, root first.
    fn leftmost_path(all: &HashMap<[u8; 32], Vec<u8>>, root: [u8; 32]) -> Vec<[u8; 32]> {
        let mut path = vec![root];
        loop {
            let wire = &all[path.last().unwrap()];
            let (_, plain) = crate::rs::decode_span(wire[..8].try_into().unwrap());
            if u64::from_le_bytes(plain) <= ant_crypto::CHUNK_SIZE as u64 {
                return path;
            }
            path.push(wire[8..40].try_into().unwrap());
        }
    }

    /// Bytes that are not a mantaray node: no version hash anywhere.
    fn raw_file(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    /// #113: deciding that a multi-chunk raw file (an HLS segment behind
    /// `bzz://<ref>/`) is not a manifest must need only the root and the
    /// leftmost leaf — not every chunk of the file. Before the fix the
    /// lookup joined the whole file first, so here (every other chunk
    /// absent, as on a cold or thin peer set) it failed with a fetch /
    /// erasure-recovery error, which the gateway answered with a 404.
    // Paused clock so the pre-fix full join's retry back-off on the
    // absent chunks fails the test fast instead of after ~2 min.
    #[tokio::test(start_paused = true)]
    async fn raw_multi_chunk_file_is_not_a_manifest_from_its_first_leaf() {
        // ~1.6 MB like the field's segments: a two-level tree. Both a
        // plain and a redundancy-coded (level 1, parity refs, level-
        // encoded spans) upload.
        let data = raw_file(1_601_572);
        for level in [0u8, 1] {
            let split = crate::split_bytes_with_redundancy(&data, level);
            let all = chunk_map(&split.chunks);
            let path = leftmost_path(&all, split.root);
            assert_eq!(path.len(), 3, "level {level}: root → intermediate → leaf");
            let mut inner = MapFetcher::new();
            for addr in &path {
                inner.insert(*addr, all[addr].clone());
            }
            let fetcher = CountingFetcher {
                inner,
                fetches: 0.into(),
            };
            let err = lookup_path(&fetcher, &split.root, "").await.unwrap_err();
            assert!(
                matches!(err, ManifestError::NotAManifest),
                "level {level}: expected NotAManifest, got {err:?}",
            );
            assert_eq!(
                fetcher.fetches.load(std::sync::atomic::Ordering::Relaxed),
                path.len(),
                "level {level}: one fetch per tree level, nothing else",
            );
        }
    }

    /// A raw file larger than the manifest join cap (32 MiB) behind
    /// `bzz://<ref>/` is recognised as raw bytes too. Before the sniff the
    /// lookup's join refused the file's span (`TooLarge`) before it could
    /// look at the header, which the gateway answered with a 404. The
    /// tree here is just the leftmost path of a 40 MiB file.
    #[tokio::test]
    async fn raw_file_above_the_manifest_join_cap_is_not_a_manifest() {
        let span = (40u64 << 20).to_le_bytes();
        let chunk_with_span = |payload: &[u8]| {
            let addr = ant_crypto::bmt_hash_with_span(&span, payload).unwrap();
            let mut wire = span.to_vec();
            wire.extend_from_slice(payload);
            (addr, wire)
        };
        let (leaf, leaf_wire) = ant_crypto::cac_new(&raw_file(4096)).unwrap();
        let (mid, mid_wire) = chunk_with_span(&leaf);
        let (root, root_wire) = chunk_with_span(&mid);
        let mut fetcher = MapFetcher::new();
        fetcher.insert(leaf, leaf_wire);
        fetcher.insert(mid, mid_wire);
        fetcher.insert(root, root_wire);
        let err = lookup_path(&fetcher, &root, "").await.unwrap_err();
        assert!(matches!(err, ManifestError::NotAManifest), "got {err:?}");
    }

    /// The sniff only ever short-circuits on a *positive* "not a
    /// manifest". When the leftmost leaf can't be fetched the lookup
    /// falls back to the full join exactly as before, so its error (and
    /// any erasure recovery the join can do) is unchanged.
    // Paused clock: the join's per-subtree retry back-off (~2 min of
    // sleeps on a missing chunk) auto-advances instead of stalling.
    #[tokio::test(start_paused = true)]
    async fn unreachable_first_leaf_falls_back_to_the_full_join() {
        let split = crate::split_bytes(&raw_file(64 * 1024));
        let all = chunk_map(&split.chunks);
        let path = leftmost_path(&all, split.root);
        let mut fetcher = MapFetcher::new();
        for (addr, wire) in &all {
            if addr != path.last().unwrap() {
                fetcher.insert(*addr, wire.clone());
            }
        }
        let err = lookup_path(&fetcher, &split.root, "").await.unwrap_err();
        assert!(
            matches!(err, ManifestError::Fetch(JoinError::FetchChunk { .. })),
            "expected the join's fetch error, got {err:?}",
        );

        // With every chunk present the full join runs and still lands on
        // NotAManifest.
        let mut fetcher = MapFetcher::new();
        for (addr, wire) in all {
            fetcher.insert(addr, wire);
        }
        let err = lookup_path(&fetcher, &split.root, "").await.unwrap_err();
        assert!(matches!(err, ManifestError::NotAManifest), "got {err:?}");
    }

    /// R2-M1 (#115): when the sniff can't fetch the leftmost leaf, the
    /// fallback join must not pay for that miss (or the chunks the sniff
    /// already fetched) a second time. The lookup costs exactly what a
    /// bare join of the same file costs: every chunk request, the leaf's
    /// retries included, matches one-for-one. Before the fix the lookup
    /// made one extra leaf fetch and re-fetched the whole leftmost path.
    #[tokio::test(start_paused = true)]
    async fn sniff_fetches_are_not_repeated_by_the_fallback_join() {
        let split = crate::split_bytes(&raw_file(64 * 1024));
        let all = chunk_map(&split.chunks);
        let path = leftmost_path(&all, split.root);
        let leaf = *path.last().unwrap();
        let fetcher = || {
            let mut inner = MapFetcher::new();
            for (addr, wire) in &all {
                if *addr != leaf {
                    inner.insert(*addr, wire.clone());
                }
            }
            LoggingFetcher {
                inner,
                log: std::sync::Mutex::new(Vec::new()),
            }
        };

        let bare = fetcher();
        let root_wire = all[&split.root].clone();
        join(&bare, &root_wire, DEFAULT_MAX_FILE_BYTES)
            .await
            .unwrap_err();
        let mut bare_log = bare.log.into_inner().unwrap();
        bare_log.insert(0, split.root); // the lookup fetches the root itself

        let looked_up = fetcher();
        lookup_path(&looked_up, &split.root, "").await.unwrap_err();
        let mut lookup_log = looked_up.log.into_inner().unwrap();

        let leaf_fetches = |log: &[[u8; 32]]| log.iter().filter(|a| **a == leaf).count();
        assert_eq!(leaf_fetches(&lookup_log), leaf_fetches(&bare_log));
        bare_log.sort_unstable();
        lookup_log.sort_unstable();
        assert_eq!(lookup_log, bare_log);
    }

    /// PR #116 R1-M3: a sniff miss replayed to the fallback join keeps
    /// its `FetchExhausted` type, so a starved "not found" still reads as
    /// unreached (not confirmed missing) when a recovery sweep is served
    /// the replay. Other errors replay with their message.
    #[tokio::test]
    async fn sniff_replay_keeps_the_fetch_exhausted_type() {
        struct Starved;
        #[async_trait]
        impl ChunkFetcher for Starved {
            async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
                if addr[0] == 1 {
                    return Err(Box::new(crate::fetcher::FetchExhausted {
                        message: "all peers failed for chunk 01 after 1 attempts \
                                  (last: remote: retrieve chunk: storage: not found)"
                            .into(),
                        pool_starved: true,
                        last_not_found: true,
                        not_found_answers: 1,
                    }));
                }
                Err("timeout".into())
            }
        }
        for addr in [[1u8; 32], [2u8; 32]] {
            let sniffed = SniffedFetcher::new(&Starved);
            let first = sniffed.fetch(addr).await.unwrap_err();
            sniffed.replay();
            let replayed = sniffed.fetch(addr).await.unwrap_err();
            assert_eq!(replayed.to_string(), first.to_string());
            let typed = replayed.downcast_ref::<crate::fetcher::FetchExhausted>();
            if addr[0] == 1 {
                assert!(typed.is_some_and(|x| x.pool_starved));
            } else {
                assert!(typed.is_none());
            }
        }
    }

    /// Fetcher over a starved peer pool that credit can refill: a plain
    /// `fetch` of anything but `plain_ok` fails at once as a starved
    /// `FetchExhausted` (every candidate overdraft-skipped), while
    /// `fetch_waiting_for_credit` with a budget gets the chunk (credit
    /// came free during the wait). Records every waiting fetch.
    struct CreditGatedFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
        plain_ok: HashSet<[u8; 32]>,
        waits: std::sync::Mutex<Vec<([u8; 32], std::time::Duration)>>,
    }

    impl CreditGatedFetcher {
        fn new(chunks: HashMap<[u8; 32], Vec<u8>>, plain_ok: &[[u8; 32]]) -> Self {
            Self {
                chunks,
                plain_ok: plain_ok.iter().copied().collect(),
                waits: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn waits(&self) -> Vec<([u8; 32], std::time::Duration)> {
            self.waits.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ChunkFetcher for CreditGatedFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            match self.chunks.get(&addr) {
                Some(wire) if self.plain_ok.contains(&addr) => Ok(wire.clone()),
                _ => Err(Box::new(crate::fetcher::FetchExhausted::new(
                    "no BZZ peers available",
                    true,
                    false,
                ))),
            }
        }

        async fn fetch_waiting_for_credit(
            &self,
            addr: [u8; 32],
            credit_budget: std::time::Duration,
        ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            self.waits.lock().unwrap().push((addr, credit_budget));
            if credit_budget.is_zero() {
                return self.fetch(addr).await;
            }
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| "missing chunk".into())
        }

        fn waits_for_credit(&self) -> bool {
            true
        }
    }

    /// Issue #122: on a starved pool, a bare `/bzz/<raw-ref>/`'s sniff
    /// waits for credit on its root → leftmost-leaf fetches (two for a
    /// 1.6 MB segment), so the raw file is recognised (`NotAManifest`,
    /// streamed like `/bytes`) instead of failing the sniff and falling
    /// into the full join. Each fetch gets the window's budget. The plain
    /// `lookup_path` (requests with a path, every other caller) still
    /// never waits.
    // Paused clock: the plain lookup's fallback join retries its starved
    // children with ~2 min of back-off.
    #[tokio::test(start_paused = true)]
    async fn starved_bare_root_sniff_waits_for_credit_and_spots_raw_bytes() {
        let window = std::time::Duration::from_secs(30);
        let data = raw_file(1_601_572);
        for level in [0u8, 1] {
            let split = crate::split_bytes_with_redundancy(&data, level);
            let all = chunk_map(&split.chunks);
            let path = leftmost_path(&all, split.root);
            assert_eq!(path.len(), 3, "level {level}: root → intermediate → leaf");

            // The root is already in the request cache (`run_stream_bzz`
            // fetched it, waiting, so the walk's waiting root load is a
            // cache hit); everything else needs credit.
            let fetcher = CreditGatedFetcher::new(all.clone(), &[split.root]);
            let err = lookup_path_with_credit(
                &fetcher,
                &split.root,
                "",
                &CreditWindow::new(window),
                &ReplicaSweeps::new(),
                None,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, ManifestError::NotAManifest),
                "level {level}: expected NotAManifest, got {err:?}",
            );
            let budget = crate::accounting::CREDIT_WAIT_BUDGET;
            assert_eq!(
                fetcher.waits(),
                vec![(path[0], budget), (path[1], budget), (path[2], budget)],
                "level {level}: one waiting fetch per tree level",
            );

            let fetcher = CreditGatedFetcher::new(all, &[split.root]);
            let err = lookup_path(&fetcher, &split.root, "").await.unwrap_err();
            assert!(
                matches!(err, ManifestError::Fetch(_)),
                "level {level}: a non-waiting sniff can't tell on a starved pool, \
                 so the fallback join runs and fails: {err:?}",
            );
            assert!(
                fetcher.waits().is_empty(),
                "level {level}: lookup_path waited"
            );
        }
    }

    /// Issue #122: only the sniff waits. When the leftmost leaf carries a
    /// manifest header (or the sniff can't tell), the fallback join of
    /// the node stays non-waiting, as #117 decided: none of its fetches
    /// reach `fetch_waiting_for_credit`, so it adds no credit wait on
    /// top of the sniff's, however many chunks it fetches or retries.
    // Paused clock: the join retries its starved chunks with back-off.
    #[tokio::test(start_paused = true)]
    async fn fallback_join_after_a_waiting_sniff_never_waits() {
        let root_wire = hex::decode(ROOT_HEX).unwrap();
        let mut node = root_wire[8..].to_vec();
        node.resize(64 * 1024, 0);
        let split = crate::split_bytes(&node);
        let all = chunk_map(&split.chunks);
        let path = leftmost_path(&all, split.root);
        assert_eq!(path.len(), 2, "root → leaf");
        let fetcher = CreditGatedFetcher::new(all, &[split.root]);
        let err = lookup_path_with_credit(
            &fetcher,
            &split.root,
            "",
            &CreditWindow::new(std::time::Duration::from_secs(30)),
            &ReplicaSweeps::new(),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ManifestError::Fetch(JoinError::FetchChunk { .. })),
            "expected the non-waiting full join to run and fail, got {err:?}",
        );
        let budget = crate::accounting::CREDIT_WAIT_BUDGET;
        assert_eq!(
            fetcher.waits(),
            vec![(path[0], budget), (path[1], budget)],
            "the node's root and the sniff's leaf fetch wait; the fallback join's fetches don't",
        );
    }

    /// Issue #130: on a starved pool, the `/bzz` walk's node loads wait
    /// for credit (one fetch per trie level, each given the window's
    /// budget), so a site's index and a path inside it resolve instead
    /// of failing for the resolution loop to back off and retry. The
    /// plain `lookup_path` (every other caller) still never waits and
    /// fails at once on the same pool.
    #[tokio::test(start_paused = true)]
    async fn starved_manifest_walk_waits_for_credit_on_every_node() {
        let (site, root, refs) = website_fetcher(&[
            "index.html",
            "developer/index.html",
            "developer/deep/index.html",
        ]);
        let nodes: HashSet<[u8; 32]> = site
            .chunks
            .keys()
            .copied()
            .filter(|a| !refs.values().any(|r| r == a))
            .collect();
        let window = std::time::Duration::from_secs(30);
        let budget = crate::accounting::CREDIT_WAIT_BUDGET;
        for (path, file) in [
            ("", "index.html"),
            ("developer/deep/index.html", "developer/deep/index.html"),
            ("developer/", "developer/index.html"),
        ] {
            // Nothing is cached: every node load needs credit.
            let fetcher = CreditGatedFetcher::new(site.chunks.clone(), &[]);
            let found = lookup_path_with_credit(
                &fetcher,
                &root,
                path,
                &CreditWindow::new(window),
                &ReplicaSweeps::new(),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{path:?}: {e:?}"));
            assert_eq!(found.data_ref, refs[file].to_vec(), "{path:?}");
            let waits = fetcher.waits();
            assert!(waits.len() >= 2, "{path:?}: root and a child: {waits:?}");
            assert!(
                waits.iter().all(|(a, b)| nodes.contains(a) && *b == budget),
                "{path:?}: only manifest nodes are fetched, each with the budget: {waits:?}",
            );

            let fetcher = CreditGatedFetcher::new(site.chunks.clone(), &[]);
            let err = lookup_path(&fetcher, &root, path).await.unwrap_err();
            assert!(
                matches!(err, ManifestError::Fetch(_)),
                "{path:?}: a non-waiting walk fails on a starved pool: {err:?}",
            );
            assert!(fetcher.waits().is_empty(), "{path:?}: lookup_path waited");
        }

        // The walk's waits come out of one window: with 4 s of it left,
        // every node load gets 4 s; once it has passed, none waits and
        // the walk fails as `lookup_path` does.
        for (left, expected) in [
            (
                std::time::Duration::from_secs(4),
                std::time::Duration::from_secs(4),
            ),
            (std::time::Duration::ZERO, std::time::Duration::ZERO),
        ] {
            let credit = CreditWindow::new(window);
            tokio::time::advance(window.saturating_sub(left)).await;
            let fetcher = CreditGatedFetcher::new(site.chunks.clone(), &[]);
            let r = lookup_path_with_credit(
                &fetcher,
                &root,
                "developer/index.html",
                &credit,
                &ReplicaSweeps::new(),
                None,
            )
            .await;
            let waits = fetcher.waits();
            // A spent window falls back to plain `fetch`.
            assert_eq!(waits.is_empty(), expected.is_zero(), "{left:?} left");
            assert!(
                waits.iter().all(|(_, b)| *b == expected),
                "{left:?} left: {waits:?}",
            );
            assert_eq!(r.is_ok(), !expected.is_zero(), "{left:?} left: {r:?}");
        }
    }

    /// Fetcher that records every requested address.
    struct LoggingFetcher {
        inner: MapFetcher,
        log: std::sync::Mutex<Vec<[u8; 32]>>,
    }

    #[async_trait]
    impl ChunkFetcher for LoggingFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            self.log.lock().unwrap().push(addr);
            self.inner.fetch(addr).await
        }
    }

    /// A raw upload shorter than a node header (64 bytes) behind
    /// `bzz://<ref>/` is raw bytes, not a malformed manifest: the lookup
    /// must answer `NotAManifest` so the gateway falls back to serving the
    /// bytes. Before the fix the sniff answered "can't tell" for it, and
    /// the join + unmarshal surfaced `TooShort`, which the gateway turned
    /// into a 404. Covers the empty file and the length just below the
    /// header too.
    #[tokio::test]
    async fn raw_file_shorter_than_a_node_header_is_not_a_manifest() {
        for len in [0usize, 1, 20, NODE_HEADER_SIZE - 1] {
            let (addr, wire) = ant_crypto::cac_new(&raw_file(len)).unwrap();
            let mut fetcher = MapFetcher::new();
            fetcher.insert(addr, wire);
            let err = lookup_path(&fetcher, &addr, "").await.unwrap_err();
            assert!(
                matches!(err, ManifestError::NotAManifest),
                "len {len}: expected NotAManifest, got {err:?}",
            );
        }
    }

    /// A multi-chunk file that *starts* like a mantaray node is not
    /// rejected by the sniff: the lookup goes on to join the whole node
    /// (proved here by the join tripping over a missing later chunk).
    // Paused clock: the join's per-subtree retry back-off (~2 min of
    // sleeps on a missing chunk) auto-advances instead of stalling.
    #[tokio::test(start_paused = true)]
    async fn manifest_header_in_first_leaf_still_joins_the_node() {
        let root_wire = hex::decode(ROOT_HEX).unwrap();
        let mut node = root_wire[8..].to_vec();
        node.resize(64 * 1024, 0);
        assert!(has_manifest_header(&node));
        let split = crate::split_bytes(&node);
        let all = chunk_map(&split.chunks);
        let path = leftmost_path(&all, split.root);
        let mut fetcher = MapFetcher::new();
        for addr in &path {
            fetcher.insert(*addr, all[addr].clone());
        }
        let err = lookup_path(&fetcher, &split.root, "").await.unwrap_err();
        assert!(
            matches!(err, ManifestError::Fetch(JoinError::FetchChunk { .. })),
            "expected the full join to run, got {err:?}",
        );
    }

    /// [`MapFetcher`] that counts fetches of addresses it doesn't hold
    /// (in these tests: dispersed-replica probes and dead node loads).
    struct MissCountingFetcher {
        inner: MapFetcher,
        misses: std::sync::atomic::AtomicUsize,
    }

    impl MissCountingFetcher {
        fn misses(&self) -> usize {
            self.misses.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChunkFetcher for MissCountingFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            let r = self.inner.fetch(addr).await;
            if r.is_err() {
                self.misses
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            // Every miss is the network's final answer (more than
            // `STARVED_MAX_NOT_FOUND` peers say "not found").
            r.map_err(|e| -> Box<dyn Error + Send + Sync> {
                Box::new(
                    crate::fetcher::FetchExhausted::new(e.to_string(), false, true)
                        .with_not_found_answers(3),
                )
            })
        }
    }

    /// A redundant upload's site whose manifest root exists only as
    /// dispersed replicas (#154); every other chunk is present. The
    /// direct root fetch always misses uncorroborated (a cold node), and
    /// the replica probes are starved until `open` is set. Recovered
    /// chunks are kept, like the request cache.
    struct ReplicaOnlyRootFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
        replicas: HashSet<[u8; 32]>,
        recovered: std::sync::Mutex<HashMap<[u8; 32], Vec<u8>>>,
        open: std::sync::atomic::AtomicBool,
        replica_probes: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ChunkFetcher for ReplicaOnlyRootFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if let Some(w) = self.recovered.lock().unwrap().get(&addr) {
                return Ok(w.clone());
            }
            let replica = self.replicas.contains(&addr);
            if replica {
                self.replica_probes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !self.open.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(Box::new(crate::fetcher::FetchExhausted::new(
                        "no BZZ peers available",
                        true,
                        false,
                    )));
                }
            }
            self.chunks.get(&addr).cloned().ok_or_else(|| {
                // #154's shape: 20 peers agree the address is missing.
                Box::new(
                    crate::fetcher::FetchExhausted::new(
                        format!("no peer found for {}", hex::encode(addr)),
                        false,
                        true,
                    )
                    .with_not_found_answers(20),
                ) as Box<dyn Error + Send + Sync>
            })
        }

        async fn put_recovered(&self, addr: [u8; 32], wire: &[u8]) {
            self.recovered.lock().unwrap().insert(addr, wire.to_vec());
        }
    }

    fn replica_only_site() -> (ReplicaOnlyRootFetcher, [u8; 32]) {
        use crate::manifest_writer::{build_collection_manifest, IndexAnchor, ManifestFile};
        let body = b"<html>hi</html>";
        let page = crate::splitter::split_bytes(body);
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
        let mut chunks = HashMap::new();
        let mut root_wire = None;
        for c in &manifest.chunks {
            if c.address == manifest.root {
                root_wire = Some(c.wire.clone());
            } else {
                chunks.insert(c.address, c.wire.clone());
            }
        }
        let mut replicas = HashSet::new();
        for r in crate::rs_encode::replica_chunks(&manifest.root, &root_wire.unwrap(), 2) {
            replicas.insert(r.address);
            chunks.insert(r.address, r.wire);
        }
        let fetcher = ReplicaOnlyRootFetcher {
            chunks,
            replicas,
            recovered: std::sync::Mutex::default(),
            open: std::sync::atomic::AtomicBool::new(false),
            replica_probes: std::sync::atomic::AtomicUsize::new(0),
        };
        (fetcher, manifest.root)
    }

    /// R2-F1 (#155): a sweep that failed only transiently (starved replica
    /// probes) is not memoized for the rest of the request. The same
    /// attempt doesn't sweep the node again, but the next attempt does,
    /// and recovers a manifest root that exists only as replicas.
    #[tokio::test]
    async fn retried_lookup_resweeps_after_a_transient_sweep_failure() {
        let (fetcher, root) = replica_only_site();
        let credit = CreditWindow::new(std::time::Duration::ZERO);
        let sweeps = ReplicaSweeps::new();
        let probes = || {
            fetcher
                .replica_probes
                .load(std::sync::atomic::Ordering::SeqCst)
        };

        let first = lookup_path_with_credit(&fetcher, &root, "index.html", &credit, &sweeps, None)
            .await
            .unwrap_err();
        assert!(matches!(first, ManifestError::Fetch(_)), "{first:?}");
        let swept = probes();
        assert!(swept > 0, "attempt 1 sweeps the root's replicas");
        // R3-M1: the direct miss alone is final (corroborated), so the
        // retry hinges on the memo reporting the transient sweep.
        assert!(
            crate::fetcher::FetchExhausted::find(&first)
                .is_some_and(crate::fetcher::FetchExhausted::corroborated_missing),
            "the direct error comes back unchanged: {first:?}",
        );
        assert!(
            sweeps.swept_transiently(&first),
            "a transiently failed sweep keeps the request retrying",
        );

        // Same attempt: no second sweep of the same node.
        let _ =
            lookup_path_with_credit(&fetcher, &root, "index.html", &credit, &sweeps, None).await;
        assert_eq!(probes(), swept, "one sweep per node per attempt");

        // The pool refills; the retried attempt sweeps again and recovers.
        fetcher
            .open
            .store(true, std::sync::atomic::Ordering::SeqCst);
        sweeps.next_attempt();
        let found = lookup_path_with_credit(&fetcher, &root, "index.html", &credit, &sweeps, None)
            .await
            .expect("attempt 2 recovers the replica-only root");
        assert_eq!(found.content_type.as_deref(), Some("text/html"));
    }

    /// Website manifest whose root is the only reachable node: every
    /// child node chunk is dropped. Returns the fetcher and the root.
    fn site_with_dead_children(paths: &[&str]) -> (MissCountingFetcher, [u8; 32]) {
        use crate::manifest_writer::{build_collection_manifest, IndexAnchor, ManifestFile};
        let files: Vec<ManifestFile> = paths
            .iter()
            .map(|p| ManifestFile {
                path: (*p).to_string(),
                content_type: Some("text/html".to_string()),
                data_ref: crate::splitter::split_bytes(p.as_bytes()).root.to_vec(),
            })
            .collect();
        let manifest =
            build_collection_manifest(&files, Some("index.html"), IndexAnchor::ZeroEntry).unwrap();
        let mut inner = MapFetcher::new();
        for c in &manifest.chunks {
            if c.address == manifest.root {
                inner.insert(c.address, c.wire.clone());
            }
        }
        let fetcher = MissCountingFetcher {
            inner,
            misses: std::sync::atomic::AtomicUsize::new(0),
        };
        (fetcher, manifest.root)
    }

    /// R1-F1 (#155): a listing whose root loads but whose children are
    /// all unreachable sweeps replicas for at most
    /// `MANIFEST_LIST_REPLICA_SWEEPS` of them, not one full sweep per
    /// child, and still returns the partial listing.
    #[tokio::test]
    async fn listing_caps_replica_sweeps_for_unreachable_children() {
        let names: Vec<String> = ('a'..='p').map(|c| format!("{c}.html")).collect();
        let paths: Vec<&str> = names.iter().map(String::as_str).collect();
        let (fetcher, root) = site_with_dead_children(&paths);

        let entries = list_manifest_paths(&fetcher, &root).await.unwrap();
        for p in &paths {
            assert!(
                entries
                    .iter()
                    .any(|e| e.path == *p && e.reference.is_some()),
                "{p} listed unexpanded, by reference",
            );
        }
        // One direct miss per dead child, plus the capped sweeps.
        let children = paths.len();
        // A sweep probes at most 2 + 4 + 8 + 16 replica addresses.
        let max_sweep: usize = crate::rs::REPLICA_COUNTS.iter().sum();
        assert!(
            fetcher.misses() <= children + MANIFEST_LIST_REPLICA_SWEEPS * max_sweep,
            "{} misses for {children} dead children: replica sweeps not capped",
            fetcher.misses(),
        );
        assert!(
            fetcher.misses() > children,
            "the listing still sweeps (up to the cap) for a replica-only child",
        );
    }

    /// R1-M1 (#155): retrying a lookup with the same [`ReplicaSweeps`]
    /// (as `run_stream_bzz` does across its attempts) sweeps a node whose
    /// replicas are confirmed missing once; the retry only repeats the
    /// direct fetch.
    #[tokio::test]
    async fn retried_lookup_sweeps_a_dead_node_once() {
        let (fetcher, root) = site_with_dead_children(&["index.html", "docs/index.html"]);
        let credit = CreditWindow::new(std::time::Duration::ZERO);
        let sweeps = ReplicaSweeps::new();

        let first = lookup_path_with_credit(&fetcher, &root, "docs/", &credit, &sweeps, None)
            .await
            .unwrap_err();
        assert!(matches!(first, ManifestError::Fetch(_)), "{first:?}");
        let after_first = fetcher.misses();
        assert!(after_first > 1, "the first attempt sweeps the dead node");

        sweeps.next_attempt();
        let second = lookup_path_with_credit(&fetcher, &root, "docs/", &credit, &sweeps, None)
            .await
            .unwrap_err();
        assert!(matches!(second, ManifestError::Fetch(_)), "{second:?}");
        assert_eq!(
            fetcher.misses() - after_first,
            1,
            "the retry repeats only the direct fetch",
        );

        // A fresh memo (a new request) sweeps again.
        let before = fetcher.misses();
        let _ = lookup_path_with_credit(
            &fetcher,
            &root,
            "docs/",
            &credit,
            &ReplicaSweeps::new(),
            None,
        )
        .await;
        assert_eq!(fetcher.misses() - before, after_first);
    }

    #[test]
    fn replica_sweeps_dedupe_and_cap() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let unlimited = ReplicaSweeps::new();
        assert!(unlimited.begin(&a));
        unlimited.failed(a, crate::rs::SweepMiss::Final);
        assert!(
            !unlimited.begin(&a),
            "a finally failed node isn't swept again"
        );
        assert!(unlimited.begin(&b));
        unlimited.failed(b, crate::rs::SweepMiss::Transient);
        assert!(!unlimited.begin(&b), "not again in the same attempt");
        unlimited.next_attempt();
        assert!(
            unlimited.begin(&b),
            "a transient failure is swept next attempt"
        );
        assert!(!unlimited.begin(&a), "a final failure stays memoized");

        let miss = |addr: [u8; 32]| {
            ManifestError::Fetch(JoinError::FetchChunk {
                addr: hex::encode(addr),
                source: "not found".into(),
            })
        };
        let sweeps = ReplicaSweeps::new();
        sweeps.failed(a, crate::rs::SweepMiss::Final);
        sweeps.failed(b, crate::rs::SweepMiss::Transient);
        assert!(!sweeps.swept_transiently(&miss(a)), "final sweep miss");
        assert!(sweeps.swept_transiently(&miss(b)), "transient sweep miss");
        assert!(!sweeps.swept_transiently(&miss(c)), "never swept");
        assert!(!sweeps.swept_transiently(&ManifestError::NotAManifest));
        sweeps.next_attempt();
        assert!(
            !sweeps.swept_transiently(&miss(b)),
            "scoped to the attempt that swept it",
        );

        let capped = ReplicaSweeps::capped(2);
        assert!(capped.begin(&a));
        assert!(capped.begin(&b));
        assert!(!capped.begin(&c), "cap used up");
    }

    // ---- list_manifest_page (issue #61, bee#5535 listing shape) ----

    async fn list_page(
        fetcher: &dyn ChunkFetcher,
        root: &[u8],
        q: &ManifestPageQuery,
    ) -> Result<ManifestPage, ManifestError> {
        list_manifest_page(fetcher, root, q, &ReplicaSweeps::for_listing()).await
    }

    /// Collection manifest over `paths` with distinct data refs (no data
    /// chunks stored: listings never read file bodies, only with `sizes`).
    fn page_fixture(paths: &[String], index: bool) -> (MapFetcher, [u8; 32]) {
        use crate::manifest_writer::{build_collection_manifest, IndexAnchor, ManifestFile};
        let files: Vec<ManifestFile> = paths
            .iter()
            .map(|p| ManifestFile {
                path: p.clone(),
                content_type: Some("text/plain".to_string()),
                data_ref: crate::splitter::split_bytes(p.as_bytes()).root.to_vec(),
            })
            .collect();
        let manifest = build_collection_manifest(
            &files,
            index.then_some("index.html"),
            IndexAnchor::ZeroEntry,
        )
        .unwrap();
        let mut fetcher = MapFetcher::new();
        for c in &manifest.chunks {
            fetcher.insert(c.address, c.wire.clone());
        }
        (fetcher, manifest.root)
    }

    /// The listing `query` must produce, computed the naive way: every
    /// path under the prefix, folded at the delimiter, deduplicated,
    /// strictly after `after`, cut at `limit`. Items are `(is_prefix,
    /// path)`; `None` when the prefix names nothing in the manifest.
    fn page_reference(
        paths: &[String],
        index: bool,
        q: &ManifestPageQuery,
    ) -> Option<(Vec<(bool, String)>, bool)> {
        let mut sorted: Vec<&[u8]> = paths.iter().map(String::as_bytes).collect();
        sorted.sort_unstable();
        sorted.dedup();
        let (prefix, delim, after) = (
            q.prefix.as_bytes(),
            q.delimiter.as_bytes(),
            q.after.as_bytes(),
        );
        let exists = prefix.is_empty()
            || sorted.iter().any(|p| p.starts_with(prefix))
            || (index && prefix == b"/");
        if !exists {
            return None;
        }
        let mut items: Vec<(bool, Vec<u8>)> = Vec::new();
        for p in sorted.into_iter().filter(|p| p.starts_with(prefix)) {
            let rest = &p[prefix.len()..];
            let item = match find_subslice(rest, delim) {
                Some(i) => (true, p[..prefix.len() + i + delim.len()].to_vec()),
                None => (false, p.to_vec()),
            };
            if items.last() != Some(&item) {
                items.push(item);
            }
        }
        items.retain(|(_, p)| after.is_empty() || p.as_slice() > after);
        let truncated = items.len() > q.limit;
        items.truncate(q.limit);
        Some((
            items
                .into_iter()
                .map(|(d, p)| (d, String::from_utf8(p).unwrap()))
                .collect(),
            truncated,
        ))
    }

    fn page_items(page: &ManifestPage) -> Vec<(bool, String)> {
        let mut items: Vec<(bool, String)> = page
            .entries
            .iter()
            .map(|e| (false, e.path.clone()))
            .chain(page.common_prefixes.iter().map(|p| (true, p.clone())))
            .collect();
        items.sort_by(|a, b| a.1.cmp(&b.1));
        items
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn word(&mut self, alphabet: &[u8], max: usize) -> String {
            let len = 1 + self.below(max);
            (0..len)
                .map(|_| alphabet[self.below(alphabet.len())] as char)
                .collect()
        }
    }

    /// Differential test: random manifests (short alphabet so paths
    /// share prefixes, fork mid-segment and nest; some names long
    /// enough to chain 30-byte forks) against [`page_reference`] for
    /// random prefix / delimiter / after / limit combinations, plus a
    /// `limit = 1` pagination run whose pages must add up to the full
    /// listing with nothing repeated or lost.
    #[tokio::test]
    async fn manifest_page_matches_naive_listing() {
        let mut rng = Lcg(0x5eed_0061);
        let alphabet = b"ab/.";
        for round in 0..24 {
            let index = round % 3 == 0;
            let mut paths: Vec<String> = (0..=rng.below(24))
                .map(|_| {
                    let mut p = rng.word(alphabet, 7);
                    if rng.below(8) == 0 {
                        p.push_str(&"x".repeat(31 + rng.below(40)));
                    }
                    p
                })
                .filter(|p| !p.starts_with('/'))
                .collect();
            if paths.is_empty() {
                paths.push("a".into());
            }
            if index {
                paths.push("index.html".into());
            }
            let (fetcher, root) = page_fixture(&paths, index);

            for _ in 0..30 {
                let pick = |rng: &mut Lcg| -> String {
                    match rng.below(4) {
                        0 => String::new(),
                        1 => paths[rng.below(paths.len())].clone(),
                        2 => {
                            let p = &paths[rng.below(paths.len())];
                            p[..rng.below(p.len() + 1)].to_string()
                        }
                        _ => rng.word(alphabet, 4),
                    }
                };
                let prefix = if rng.below(2) == 0 {
                    String::new()
                } else {
                    pick(&mut rng)
                };
                let q = ManifestPageQuery {
                    prefix,
                    delimiter: ["", "/", "/", "a/", "ab", "."][rng.below(6)].to_string(),
                    after: pick(&mut rng),
                    limit: [1, 2, 3, 5, 1000][rng.below(5)],
                    sizes: false,
                };
                let got = list_page(&fetcher, &root, &q).await;
                match page_reference(&paths, index, &q) {
                    None => assert!(
                        matches!(got, Err(ManifestError::NotFound { .. })),
                        "{q:?} over {paths:?}: want NotFound, got {got:?}",
                    ),
                    Some((want, truncated)) => {
                        let page = got.unwrap_or_else(|e| panic!("{q:?} over {paths:?}: {e}"));
                        assert_eq!(page_items(&page), want, "{q:?} over {paths:?}");
                        assert_eq!(page.truncated, truncated, "{q:?} over {paths:?}");
                        assert_eq!(
                            page.next_marker,
                            truncated.then(|| want.last().unwrap().1.clone()),
                            "{q:?} over {paths:?}",
                        );
                        assert!(page.entries.iter().all(|e| e.reference.is_some()));
                    }
                }

                // Paging one item at a time from the same start must
                // reassemble the whole listing.
                let Some((full, _)) = page_reference(
                    &paths,
                    index,
                    &ManifestPageQuery {
                        limit: usize::MAX,
                        ..q.clone()
                    },
                ) else {
                    continue;
                };
                let mut paged = Vec::new();
                let mut after = q.after.clone();
                for _ in 0..=full.len() {
                    let page = list_page(
                        &fetcher,
                        &root,
                        &ManifestPageQuery {
                            after: after.clone(),
                            limit: 1,
                            ..q.clone()
                        },
                    )
                    .await
                    .unwrap();
                    paged.extend(page_items(&page));
                    match page.next_marker {
                        Some(m) => after = m,
                        None => break,
                    }
                }
                assert_eq!(paged, full, "limit=1 pages of {q:?} over {paths:?}");
            }
        }
    }

    /// Bee's uploader keeps website metadata on a zero-entry `/` node:
    /// it is neither an entry nor a `/` common prefix (bee#5537 found
    /// it leaking as a `/` entry against a live node).
    #[tokio::test]
    async fn manifest_page_skips_root_metadata_node() {
        let paths: Vec<String> = ["index.html", "css/site.css"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (fetcher, root) = page_fixture(&paths, true);
        for delimiter in ["", "/"] {
            let page = list_page(
                &fetcher,
                &root,
                &ManifestPageQuery {
                    delimiter: delimiter.into(),
                    limit: 10,
                    ..ManifestPageQuery::default()
                },
            )
            .await
            .unwrap();
            let entries: Vec<&str> = page.entries.iter().map(|e| e.path.as_str()).collect();
            if delimiter.is_empty() {
                assert_eq!(entries, ["css/site.css", "index.html"]);
                assert_eq!(page.common_prefixes, Vec::<String>::new());
            } else {
                assert_eq!(entries, ["index.html"]);
                assert_eq!(page.common_prefixes, ["css/"]);
            }
            assert_eq!(
                page.entries[entries.len() - 1].metadata.get("Content-Type"),
                Some(&"text/plain".to_string()),
            );
        }
    }

    /// The seek and the delimiter fold never load what they skip: a
    /// page deep into a big directory, or a shallow listing next to
    /// one, costs a handful of node loads, not the directory.
    #[tokio::test]
    async fn manifest_page_loads_only_what_it_lists() {
        let mut paths: Vec<String> = (0..300).map(|i| format!("big/f{i:04}.bin")).collect();
        paths.push("readme.txt".into());
        let (inner, root) = page_fixture(&paths, false);
        let fetcher = CountingFetcher {
            inner,
            fetches: std::sync::atomic::AtomicUsize::new(0),
        };
        let loads = |q: ManifestPageQuery| {
            let fetcher = &fetcher;
            async move {
                fetcher
                    .fetches
                    .store(0, std::sync::atomic::Ordering::SeqCst);
                let page = list_page(fetcher, &root, &q).await.unwrap();
                (
                    page,
                    fetcher.fetches.load(std::sync::atomic::Ordering::SeqCst),
                )
            }
        };

        let (full, full_loads) = loads(ManifestPageQuery {
            limit: 1000,
            ..ManifestPageQuery::default()
        })
        .await;
        assert_eq!(full.entries.len(), 301);
        assert!(!full.truncated);

        let (deep, deep_loads) = loads(ManifestPageQuery {
            after: "big/f0250.bin".into(),
            limit: 2,
            ..ManifestPageQuery::default()
        })
        .await;
        let deep_paths: Vec<&str> = deep.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(deep_paths, ["big/f0251.bin", "big/f0252.bin"]);
        assert_eq!(deep.next_marker.as_deref(), Some("big/f0252.bin"));
        assert!(
            deep_loads <= 12,
            "a 2-entry page 250 entries in loaded {deep_loads} nodes (full walk: {full_loads})",
        );

        let (shallow, shallow_loads) = loads(ManifestPageQuery {
            delimiter: "/".into(),
            limit: 1000,
            ..ManifestPageQuery::default()
        })
        .await;
        assert_eq!(shallow.common_prefixes, ["big/"]);
        assert_eq!(shallow.entries.len(), 1);
        assert!(
            shallow_loads <= 4,
            "a shallow root listing loaded {shallow_loads} nodes (full walk: {full_loads})",
        );
    }

    /// A trie node that can't be loaded fails the page instead of being
    /// listed by its node reference (the legacy `list_manifest`
    /// fallback): a listing that silently omits a subtree is wrong.
    #[tokio::test]
    async fn manifest_page_fails_on_unreachable_node() {
        let names: Vec<String> = ["a.html", "b.html"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let paths: Vec<&str> = names.iter().map(String::as_str).collect();
        let (fetcher, root) = site_with_dead_children(&paths);
        let err = list_page(
            &fetcher,
            &root,
            &ManifestPageQuery {
                limit: 10,
                ..ManifestPageQuery::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ManifestError::Fetch(_)), "got {err:?}");
    }

    /// R3-M1: a node that is only loaded to look past a full page (to
    /// decide `truncated`) does not fail that page when it is
    /// unreachable: the page ends `truncated` with the items it has, and
    /// the next page, which needs the node, fails on it.
    #[tokio::test]
    async fn manifest_page_full_page_survives_an_unreachable_lookahead() {
        let paths: Vec<String> = vec!["a.html".into(), "b.html".into()];
        let (mut fetcher, root) = page_fixture(&paths, false);
        let root_node =
            load_node_ref_with_credit(&fetcher, &root, None, &ReplicaSweeps::for_listing())
                .await
                .unwrap();
        let dead = root_node
            .forks
            .values()
            .find(|f| f.prefix.starts_with(b"b"))
            .expect("fork for b.html")
            .child_ref
            .clone();
        let dead: [u8; 32] = dead[..32].try_into().unwrap();
        assert!(fetcher.chunks.remove(&dead).is_some());

        let page = list_page(
            &fetcher,
            &root,
            &ManifestPageQuery {
                limit: 1,
                ..ManifestPageQuery::default()
            },
        )
        .await
        .unwrap();
        let entries: Vec<&str> = page.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(entries, ["a.html"]);
        assert!(page.truncated);
        assert!(!page.timed_out);
        assert!(page.lookahead_failed);
        assert_eq!(page.next_marker.as_deref(), Some("a.html"));

        // A page that needs the dead node still fails on it.
        for q in [
            ManifestPageQuery {
                after: "a.html".into(),
                limit: 1,
                ..ManifestPageQuery::default()
            },
            ManifestPageQuery {
                limit: 2,
                ..ManifestPageQuery::default()
            },
        ] {
            let err = list_page(&fetcher, &root, &q).await.unwrap_err();
            assert!(matches!(err, ManifestError::Fetch(_)), "got {err:?}");
        }
    }

    /// `sizes` reads spans for the entries on the page only, and flags a
    /// page whose span read failed so it isn't cached as final.
    #[tokio::test]
    async fn manifest_page_sizes_are_opt_in() {
        let (fetcher, root, _) = website_fetcher(&["a.html", "b.html", "c.html"]);
        let q = ManifestPageQuery {
            limit: 2,
            ..ManifestPageQuery::default()
        };
        let plain = list_page(&fetcher, &root, &q).await.unwrap();
        assert!(plain.entries.iter().all(|e| e.size.is_none()));
        assert!(!plain.sizes_incomplete);

        let sized = list_page(
            &fetcher,
            &root,
            &ManifestPageQuery {
                sizes: true,
                ..q.clone()
            },
        )
        .await
        .unwrap();
        let sizes: Vec<Option<u64>> = sized.entries.iter().map(|e| e.size).collect();
        assert_eq!(
            sizes,
            [Some(19), Some(19)],
            "<html>a.html</html> is 19 bytes"
        );
        assert!(!sized.sizes_incomplete);

        let (fetcher, root) = page_fixture(&["a".to_string()], false);
        let missing = list_page(&fetcher, &root, &ManifestPageQuery { sizes: true, ..q })
            .await
            .unwrap();
        assert_eq!(missing.entries[0].size, None);
        assert!(missing.sizes_incomplete);
    }

    /// A trie deeper than `MANIFEST_PAGE_MAX_DEPTH` (a chain of one-byte
    /// forks, `a`, `aa`, `aaa`, ...) fails the page with `ListTooDeep`
    /// rather than recursing without bound or listing it cut short; one
    /// at exactly the cap lists in full.
    #[tokio::test]
    async fn manifest_page_rejects_a_trie_past_the_depth_cap() {
        let q = ManifestPageQuery {
            limit: MANIFEST_PAGE_MAX_LIMIT,
            ..ManifestPageQuery::default()
        };
        let at_cap: Vec<String> = (1..=MANIFEST_PAGE_MAX_DEPTH)
            .map(|n| "a".repeat(n))
            .collect();
        let (fetcher, root) = page_fixture(&at_cap, false);
        let page = list_page(&fetcher, &root, &q).await.unwrap();
        assert_eq!(page.entries.len(), MANIFEST_PAGE_MAX_DEPTH);

        let past_cap: Vec<String> = (1..=MANIFEST_PAGE_MAX_DEPTH + 1)
            .map(|n| "a".repeat(n))
            .collect();
        let (fetcher, root) = page_fixture(&past_cap, false);
        let err = list_page(&fetcher, &root, &q).await.unwrap_err();
        assert!(matches!(err, ManifestError::ListTooDeep), "got {err:?}");

        // A page that fills up just above the cap keeps its items and
        // ends `truncated`; the next page is the one that is too deep.
        let full = ManifestPageQuery {
            limit: MANIFEST_PAGE_MAX_DEPTH,
            ..ManifestPageQuery::default()
        };
        let page = list_page(&fetcher, &root, &full).await.unwrap();
        assert_eq!(page.entries.len(), MANIFEST_PAGE_MAX_DEPTH);
        assert!(page.truncated);
        let marker = "a".repeat(MANIFEST_PAGE_MAX_DEPTH);
        assert_eq!(page.next_marker.as_deref(), Some(marker.as_str()));
        let err = list_page(
            &fetcher,
            &root,
            &ManifestPageQuery {
                after: marker,
                ..full
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ManifestError::ListTooDeep), "got {err:?}");
    }

    /// Sleeps `delay` per fetch, `missing_delay` for a chunk the map
    /// doesn't hold (a data root `sizes` reads), on tokio's clock.
    struct SlowFetcher {
        inner: MapFetcher,
        delay: std::time::Duration,
        missing_delay: std::time::Duration,
        missing_fetches: std::sync::atomic::AtomicUsize,
    }

    impl SlowFetcher {
        fn new(inner: MapFetcher, delay: std::time::Duration) -> Self {
            Self {
                inner,
                delay,
                missing_delay: delay,
                missing_fetches: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ChunkFetcher for SlowFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            if self.inner.chunks.contains_key(&addr) {
                tokio::time::sleep(self.delay).await;
            } else {
                self.missing_fetches
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::time::sleep(self.missing_delay).await;
            }
            self.inner.fetch(addr).await
        }
    }

    /// R1-F1 on PR #260: a cold `limit=5000` page of hashed asset names
    /// costs a few node loads per entry (here 3,000 names, well over 10
    /// minutes of loads at 85 ms), past the gateway's 10-minute timeout,
    /// although the node budget allows it. The walk stops starting loads at
    /// `MANIFEST_PAGE_WALK_BUDGET` and ends `truncated` (not
    /// cacheable), and following `next_marker` still yields every path
    /// once, in order.
    #[tokio::test(start_paused = true)]
    async fn manifest_page_ends_on_its_time_budget() {
        let mut paths: Vec<String> = (0..3000u32)
            .map(|i| {
                let h = crate::splitter::split_bytes(&i.to_le_bytes()).root;
                format!("assets/{}.js", hex::encode(h))
            })
            .collect();
        let (inner, root) = page_fixture(&paths, false);
        paths.sort();
        let fetcher = SlowFetcher::new(inner, std::time::Duration::from_millis(85));
        let mut listed: Vec<String> = Vec::new();
        let mut after = String::new();
        let mut pages = 0;
        loop {
            let started = tokio::time::Instant::now();
            let page = list_page(
                &fetcher,
                &root,
                &ManifestPageQuery {
                    after: after.clone(),
                    limit: MANIFEST_PAGE_MAX_LIMIT,
                    ..ManifestPageQuery::default()
                },
            )
            .await
            .unwrap();
            let took = started.elapsed();
            assert!(
                took <= MANIFEST_PAGE_WALK_BUDGET + std::time::Duration::from_millis(85),
                "page {pages} took {took:?}",
            );
            pages += 1;
            listed.extend(page.entries.iter().map(|e| e.path.clone()));
            if !page.truncated {
                assert!(!page.timed_out);
                break;
            }
            assert!(page.timed_out, "page {pages} truncated by the clock");
            assert!(page.entries.len() < MANIFEST_PAGE_MAX_LIMIT);
            after = page.next_marker.unwrap();
            assert_eq!(after, *listed.last().unwrap());
        }
        assert!(
            pages > 2,
            "a cold 3000-entry listing fit in {pages} page(s)"
        );
        assert_eq!(listed, paths);
    }

    /// A page that runs out of time before its first item fails as a
    /// retryable `ListTimedOut`, not an empty or partial listing.
    #[tokio::test(start_paused = true)]
    async fn manifest_page_times_out_before_its_first_item() {
        let paths: Vec<String> = vec!["a/b/c".into(), "a/b/d".into()];
        let (inner, root) = page_fixture(&paths, false);
        let fetcher = SlowFetcher::new(inner, MANIFEST_PAGE_WALK_BUDGET);
        let err = list_page(
            &fetcher,
            &root,
            &ManifestPageQuery {
                limit: 10,
                ..ManifestPageQuery::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ManifestError::ListTimedOut), "got {err:?}");
    }

    /// `sizes` starts no span read after `MANIFEST_PAGE_SIZES_BUDGET`:
    /// the entries left over have no size and mark the page incomplete.
    #[tokio::test(start_paused = true)]
    async fn manifest_page_sizes_stop_at_their_deadline() {
        let paths: Vec<String> = (0..20).map(|i| format!("f{i:02}")).collect();
        let (inner, root) = page_fixture(&paths, false);
        let mut fetcher = SlowFetcher::new(inner, std::time::Duration::from_millis(1));
        fetcher.missing_delay = MANIFEST_PAGE_SIZES_BUDGET;
        let started = tokio::time::Instant::now();
        let page = list_page(
            &fetcher,
            &root,
            &ManifestPageQuery {
                limit: 100,
                sizes: true,
                ..ManifestPageQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(page.entries.len(), 20);
        assert!(page.sizes_incomplete);
        assert_eq!(
            fetcher
                .missing_fetches
                .load(std::sync::atomic::Ordering::Relaxed),
            MANIFEST_SIZE_FANOUT,
            "only the first wave of span reads started before the deadline",
        );
        assert!(started.elapsed() < 2 * MANIFEST_PAGE_SIZES_BUDGET);
    }

    /// R1-M1 on PR #260: a path that is not valid UTF-8 would come back
    /// lossily (`caf\xE9` as `caf\u{FFFD}`), and as `after` that marker
    /// skips or repeats real paths. A page that would return one fails;
    /// one that only looks at it (the lookahead past a full page) does
    /// not.
    #[tokio::test]
    async fn manifest_page_refuses_a_non_utf8_path() {
        let paths: Vec<String> = vec!["a".into(), "cafX".into(), "z".into()];
        let (mut inner, root) = page_fixture(&paths, false);
        // Patch the root node's `cafX` fork prefix to `caf\xE9` and
        // re-address the root chunk.
        let wire = inner.chunks.remove(&root).unwrap();
        let at = wire.windows(4).position(|w| w == b"cafX").unwrap();
        let mut payload = wire[8..].to_vec();
        payload[at - 8 + 3] = 0xE9;
        let patched = crate::splitter::split_bytes(&payload);
        assert_eq!(patched.chunks.len(), 1);
        let root = patched.root;
        inner.insert(root, patched.chunks[0].wire.clone());

        let q = |after: &str, limit| ManifestPageQuery {
            after: after.into(),
            limit,
            ..ManifestPageQuery::default()
        };
        let first = list_page(&inner, &root, &q("", 1)).await.unwrap();
        assert_eq!(first.entries[0].path, "a");
        assert_eq!(first.next_marker.as_deref(), Some("a"));
        let err = list_page(&inner, &root, &q("a", 1)).await.unwrap_err();
        assert!(
            matches!(&err, ManifestError::ListNonUtf8Path { path_lossy } if path_lossy == "caf\u{FFFD}"),
            "got {err:?}",
        );
        let err = list_page(&inner, &root, &q("", 10)).await.unwrap_err();
        assert!(
            matches!(err, ManifestError::ListNonUtf8Path { .. }),
            "got {err:?}"
        );
        // Past it (U+10FFFF is F4 8F BF BF, after \xE9), the listing
        // still works.
        let last = list_page(&inner, &root, &q("caf\u{10FFFF}", 10))
            .await
            .unwrap();
        assert_eq!(last.entries[0].path, "z");
    }

    #[test]
    fn page_walk_start_skips_a_folded_after() {
        assert_eq!(page_walk_start(b"", b"/", b""), Some(Vec::new()));
        assert_eq!(page_walk_start(b"", b"", b"a/b"), Some(b"a/b\0".to_vec()));
        assert_eq!(page_walk_start(b"", b"/", b"a/b"), Some(b"a0".to_vec()));
        assert_eq!(
            page_walk_start(b"a/", b"/", b"a/b/c"),
            Some(b"a/b0".to_vec())
        );
        assert_eq!(
            page_walk_start(b"", b"/", b"\xff/"),
            Some(b"\xff0".to_vec())
        );
        assert_eq!(page_walk_start(b"x", b"/", b"a/b"), Some(b"a/b\0".to_vec()));
    }
}
