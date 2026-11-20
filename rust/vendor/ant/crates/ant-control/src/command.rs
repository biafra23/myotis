//! Control-plane command + ack types shared between the daemon's node
//! loop and every transport that drives it.
//!
//! These are plain data + tokio channel handles — deliberately free of
//! any OS-socket dependency so the crate (and its consumers `ant-node`,
//! `ant-gateway`, `ant-ffi`, `antd`) compile on every platform. The Unix
//! domain-socket transport that *carries* them lives in the `server`
//! module, which is `#[cfg(unix)]`-gated; Windows builds get the types
//! without the socket I/O.

use crate::protocol::{
    AccountingSnapshotView, GetProgress, PostageStatusView, PullsyncProbeView, UploadJobView,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Buffer depth for the streaming ack channel. Sized big enough to
/// hold a couple of progress emissions plus the terminal ack without
/// the producer ever blocking, and small enough that a stalled writer
/// is observable in memory pressure rather than runaway buffering.
const STREAM_ACK_CAPACITY: usize = 16;

/// A mutating or network-touching command issued by a client and forwarded
/// to the node loop.
///
/// The node loop owns state that needs a single-writer path (the peerstore,
/// the swarm), so the transport does not touch it directly; instead it relays
/// a `ControlCommand` through an `mpsc::Sender` and awaits the ack(s) on the
/// embedded reply channel. Non-streaming commands (peerstore reset, single-
/// chunk retrieve) carry a `oneshot` — exactly one ack lands and the
/// channel closes. Streaming-capable commands (`GetBytes`, `GetBzz`)
/// carry an `mpsc::Sender` that produces zero or more
/// [`ControlAck::Progress`] samples followed by exactly one terminal
/// variant (`Bytes` / `BzzBytes` / `Error`).
#[derive(Debug)]
pub enum ControlCommand {
    /// Drop the on-disk peerstore snapshot and clear the in-memory dedup
    /// state. Does not disconnect current peers.
    ResetPeerstore { ack: oneshot::Sender<ControlAck> },
    /// Force a post-suspension recovery of the swarm. Re-warms the dial
    /// queue from the on-disk peerstore and fires a fresh bootstrap dial
    /// **unconditionally** — bypassing the count-based gates that keep the
    /// automatic `maybe_top_up_peers` / `maybe_rebootstrap` maintenance
    /// parked while the swarm still *believes* it has peers.
    ///
    /// This is the lever an embedded host (the iOS in-process node) pulls
    /// on a background→foreground transition: after a long OS suspension
    /// the libp2p connections can be half-open (the kernel sockets were
    /// reaped but no FIN was seen, so `bzz_peers` looks healthy). The
    /// swarm loop's liveness pass (issue #83) closes connections that
    /// stop answering pings ~20-30 s after the loop runs again, and runs
    /// this same recovery itself on a streak of retrieval link failures
    /// (at most once a minute); this command skips that wait. A fresh
    /// bootstrap dial opens new sockets in parallel so retrieval has
    /// live routes again.
    ///
    /// Cheap and idempotent — safe to call on every foreground. The ack is
    /// a [`ControlAck::Ok`] whose message reports how many warm hints were
    /// re-queued. Does **not** forcibly disconnect surviving peers (a
    /// healthy short-background resume must not pay a full re-handshake).
    Resume { ack: oneshot::Sender<ControlAck> },
    /// Retrieve a chunk by 32-byte reference. The node loop picks the
    /// closest BZZ peer, runs `ant_retrieval::retrieve_chunk`, and acks
    /// with the verified payload bytes (or an error string).
    GetChunk {
        reference: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Like `GetChunk`, but the ack carries the chunk's full **wire
    /// bytes** (`span (8 LE) || payload`) instead of just the payload.
    /// Used by `ant-gateway` to serve `/chunks/{addr}` in a bee-shaped
    /// way (bee's `chunkstore.Get` returns `Chunk.Data()` which is the
    /// wire form). Routing / peer-pick / CAC verification logic is
    /// identical to `GetChunk`, except that with `fast_miss` set the
    /// lookup runs in fast-miss mode (`RoutingFetcher::with_fast_miss`,
    /// issue #146): it ends once enough peers have answered "not found"
    /// instead of asking up to 32 peers one after another. Ends in
    /// [`ControlAck::Bytes`], [`ControlAck::NotFound`] (peers confirmed
    /// the chunk missing) or [`ControlAck::Error`]. The node runs this
    /// lookup without retrieval accounting, so no peer is ever
    /// overdraft-skipped and the pool is never reported starved
    /// (`FetchExhausted::pool_starved`): a miss is a `NotFound`, not the
    /// [`ControlAck::NotReady`] a starved `/bytes`/`/bzz` fetch gets.
    /// A consumer may still map a `NotReady` (to 503) defensively.
    GetChunkRaw {
        reference: [u8; 32],
        /// Run the lookup in fast-miss mode. Set it for reads whose miss
        /// is an expected answer (`/chunks`, `/soc`: a feed slot polled
        /// until it is written); leave it off for chunks expected to
        /// exist (ACT histories and grantee lists, a feed's resolved
        /// root chunk), where the extra in-flight peers would mostly buy
        /// duplicate, separately-charged deliveries.
        fast_miss: bool,
        /// Skip the daemon's shared memory and disk chunk caches for
        /// this lookup: no cached hit (so no read-after-own-write and no
        /// locally pinned copy either), and the fetched chunk is not
        /// written back. Set by `GET /chunks/{addr}` with
        /// `swarm-cache: false` (issue #80); every other caller leaves it
        /// off.
        bypass_cache: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Run a bounded pullsync probe against the closest connected peer to
    /// `target`: fetch its per-bin reserve cursors, then pull one page of
    /// bin `bin` starting at binID `start`, requesting the delivery of
    /// every offered chunk (bounded by `max_deliver`). This is the
    /// GSOC/PSS lurker's underlying operation and the Exp-1 viability
    /// probe (does a mainnet full node serve pullsync to our light peer?).
    /// The node selects the peer via its routing table's proximity order.
    /// The ack is [`ControlAck::PullsyncProbe`].
    PullsyncProbe {
        /// Overlay to select the closest connected peer to (and, by
        /// default, the bin is that peer's proximity order to it).
        target: [u8; 32],
        /// Bin to pull. `None` = the closest peer's proximity-order bin
        /// to `target` (the neighborhood bin a lurker cares about).
        bin: Option<u8>,
        /// Start binID (inclusive). `None` = a historical page just
        /// below the peer's cursor (answered immediately — see
        /// `PROBE_BACKLOG`); an explicit start past the cursor
        /// live-blocks until the next chunk arrives.
        start: Option<u64>,
        /// Cap on chunks whose delivery to actually request this page.
        max_deliver: usize,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Start a GSOC/PSS lurker subscription: reside in the `target`
    /// neighborhood, pull its bin live, and stream every decoded message
    /// matching the watch set back as [`ControlAck::LurkerMessage`]
    /// frames until the receiver is dropped. Backs the gateway's
    /// `GET /gsoc/subscribe/{address}` and `GET /pss/subscribe/{topic}`
    /// WebSocket endpoints. `target` all-zeros means "the node's own
    /// overlay" (the neighborhood PSS messages to this node land in).
    LurkerSubscribe {
        target: [u8; 32],
        /// Exact GSOC SOC addresses to watch (precise, offer-time filter).
        gsoc_addresses: Vec<[u8; 32]>,
        /// PSS topics to watch (`keccak256(topic_string)`); reception uses
        /// the node's PSS key if present, else topic-broadcast.
        pss_topics: Vec<[u8; 32]>,
        /// **Mailbox mode**: run one bounded sweep of the trojan-bin
        /// backlog on subscribe so recent PSS messages sent while the
        /// receiver was offline are recovered (delivered to this
        /// subscriber only), rather than only tailing live traffic. Backs
        /// the WebSocket `?history=true` option; ignored for GSOC. See
        /// `ant_p2p`'s `WatchState::history`.
        history: bool,
        ack: mpsc::Sender<ControlAck>,
    },
    /// Walk the manifest at `reference`, resolve `path`, then join the
    /// resulting chunk tree into a single `Vec<u8>`. Acks with
    /// [`ControlAck::BzzBytes`] including any `Content-Type` metadata
    /// recovered from the manifest. `allow_degraded_redundancy` is a
    /// legacy no-op (RS-aware decoding with parity recovery is always
    /// on), retained for protocol compatibility.
    /// `bypass_cache` swaps the daemon's shared chunk cache for a
    /// fresh per-request one and skips the disk cache entirely (no
    /// reads, no writes; intra-request retries still benefit from the
    /// per-request cache). `progress` opts the request into streaming
    /// [`ControlAck::Progress`] emissions. `max_bytes` overrides the
    /// joiner's per-request size cap; `None` means "use the joiner's
    /// `DEFAULT_MAX_FILE_BYTES` (32 MiB)" — appropriate for `antctl get`
    /// where allocating gigabytes from a malformed root chunk would be
    /// a footgun. The HTTP gateway raises this so real bzz sites with
    /// videos / archives don't 502 at the joiner step.
    GetBzz {
        reference: [u8; 32],
        path: String,
        allow_degraded_redundancy: bool,
        bypass_cache: bool,
        progress: bool,
        max_bytes: Option<u64>,
        ack: mpsc::Sender<ControlAck>,
    },
    /// List the paths and metadata in a mantaray manifest.
    ///
    /// `page: None` is the original whole-manifest listing the FFI
    /// (`ant_list_bzz`) still uses: every entry's size, metadata-only
    /// nodes included, capped at 512 entries / 6 trie levels, ends in
    /// [`ControlAck::Manifest`] or [`ControlAck::Error`].
    ///
    /// `page: Some(query)` is one page of the bee#5535-shaped listing
    /// behind `GET /v0/manifest/{addr}/{prefix}` (issue #61). Ends in
    /// [`ControlAck::ManifestPage`], [`ControlAck::NotFound`] (the
    /// reference is not a manifest, the prefix names nothing in it, a
    /// path on the page is not valid UTF-8, or peers confirmed a trie
    /// node missing and its replica sweep missed for good),
    /// [`ControlAck::NotReady`] (no peers; a miss from a starved peer
    /// pool; a corroborated miss whose replica sweep failed only
    /// transiently; or the walk's wall-clock budget ran out before any
    /// item) or [`ControlAck::Error`] (any other fetch failure, or a
    /// trie too deep or too sparse for one page).
    ListBzz {
        reference: [u8; 32],
        bypass_cache: bool,
        page: Option<ManifestListQuery>,
        ack: mpsc::Sender<ControlAck>,
    },
    /// Join the multi-chunk tree rooted at `reference` (a `/bytes/` ref,
    /// no manifest) and ack with the joined file bytes. See
    /// [`ControlCommand::GetBzz`] for `bypass_cache`, `progress`, and
    /// `max_bytes`.
    GetBytes {
        reference: [u8; 32],
        bypass_cache: bool,
        progress: bool,
        max_bytes: Option<u64>,
        ack: mpsc::Sender<ControlAck>,
    },
    /// Gateway-only: join the **encrypted** chunk tree rooted at the
    /// encrypted reference `reference ‖ key` and ack with the decrypted
    /// file bytes ([`ControlAck::Bytes`]). Backs `GET /bytes/{128-hex}`
    /// and encrypted feed content (bee's 80-byte v1 payload). Encrypted
    /// content is not streamed: the body is buffered (bounded by
    /// `max_bytes`) and the gateway applies any HTTP Range by slicing
    /// the buffer. Not exposed on the JSON control socket.
    GetBytesEncrypted {
        reference: [u8; 32],
        key: [u8; 32],
        bypass_cache: bool,
        max_bytes: Option<u64>,
        ack: mpsc::Sender<ControlAck>,
    },
    /// Gateway-only streaming `/bytes/{ref}` path. Sends
    /// [`ControlAck::BytesStreamStart`], zero or more
    /// [`ControlAck::BytesChunk`] messages, then [`ControlAck::StreamDone`]
    /// or [`ControlAck::Error`]. Before the stream starts (instead of
    /// `BytesStreamStart`) the single terminal ack can also be
    /// [`ControlAck::NotFound`] (peers confirmed the root missing) or
    /// [`ControlAck::NotReady`] (no peers, or a miss from a starved peer
    /// pool); a consumer must treat both as final, like `Error`, or it
    /// waits for a stream that never comes. The JSON control socket does not expose
    /// this command; it exists so `ant-gateway` can behave like Bee and
    /// write the HTTP body while the joiner is still retrieving.
    ///
    /// `range` is interpreted against the file body (the joined bytes,
    /// not chunk wire bytes). `None` streams the whole file. The
    /// daemon clamps `range.end_inclusive` to `total_bytes - 1`.
    /// `head_only` short-circuits the body retrieval entirely: the
    /// daemon emits a `BytesStreamStart` with the file size and goes
    /// straight to `StreamDone`. This is what backs `HEAD /bytes/{addr}`
    /// without joining the chunk tree.
    ///
    /// `bypass_cache` runs the request without the daemon's shared
    /// memory and disk chunk caches (see [`ControlCommand::GetBzz`]):
    /// every chunk comes from the network and none is written back. The
    /// gateway sets it for `swarm-cache: false` (issue #80).
    StreamBytes {
        reference: [u8; 32],
        bypass_cache: bool,
        max_bytes: Option<u64>,
        range: Option<StreamRange>,
        head_only: bool,
        ack: mpsc::Sender<ControlAck>,
    },
    /// Gateway-only streaming `/bzz/{ref}/{path}` path. Resolves the
    /// manifest, then streams the file body the same way `StreamBytes`
    /// does. Sends [`ControlAck::BzzStreamStart`] (with content type +
    /// filename + total size), zero or more
    /// [`ControlAck::BytesChunk`] messages, then
    /// [`ControlAck::StreamDone`] or [`ControlAck::Error`]. As with
    /// `StreamBytes`, a failure before the stream starts can instead end
    /// in [`ControlAck::NotFound`] (the manifest root or data root
    /// confirmed missing) or [`ControlAck::NotReady`] (a starved peer
    /// pool, or a manifest node whose dispersed-replica sweep missed only
    /// transiently, even when its direct miss is corroborated); both are
    /// terminal.
    ///
    /// `range`, `head_only` and `bypass_cache` behave identically to
    /// `StreamBytes`.
    /// `head_only` is what backs `HEAD /bzz/{ref}/{path}`: the daemon
    /// resolves the manifest, fetches the data root chunk to learn
    /// the size, returns metadata + total span, and never joins.
    ///
    /// `reference` is 32 bytes for a plain manifest root or 64
    /// (`address ‖ decryption key`) for an **encrypted** one
    /// (`GET /bzz/{128-hex}/…`); the node loop walks encrypted
    /// manifests transparently and serves their bodies buffered.
    StreamBzz {
        reference: Vec<u8>,
        path: String,
        allow_degraded_redundancy: bool,
        bypass_cache: bool,
        max_bytes: Option<u64>,
        range: Option<StreamRange>,
        head_only: bool,
        ack: mpsc::Sender<ControlAck>,
    },
    /// Gateway `POST /chunks`: stamp locally (postage issuer) then pushsync.
    /// `batch_id` selects which registered postage batch issues the
    /// stamp; the node loop rejects the push if no issuer is registered
    /// for it (`ControlAck::Error "batch … not usable"`).
    ///
    /// `stamp`, when `Some`, carries a **pre-signed** 113-byte postage
    /// stamp (bee's `swarm-postage-stamp` request header, layout
    /// `batch_id(32) ‖ index(8) ‖ timestamp(8) ‖ sig(65)`). The node
    /// then pushes the chunk with *that* stamp instead of issuing one
    /// from its own registry — no local issuer (or upload runtime) is
    /// required, mirroring bee's `postage.NewPresignedStamper` path.
    /// `batch_id` is redundantly the stamp's own leading 32 bytes.
    PushChunk {
        wire: Vec<u8>,
        batch_id: [u8; 32],
        /// Pre-signed 113-byte stamp; `None` = stamp locally.
        stamp: Option<Vec<u8>>,
        /// Require a receipt from a storer inside the chunk's own
        /// neighbourhood: a merely-shallow receipt then errors (so the
        /// caller's retry machinery keeps working the chunk) instead of
        /// being accepted after the deeper-storer hunt. The upload-job
        /// manager passes `true` — a light node has no pull-sync to
        /// repair a shallow placement later, so accepting one strands
        /// the chunk with the uploader as its only route. The gateway's
        /// bee-parity endpoints pass `false` (bee's own accept-shallow
        /// semantics).
        require_deep: bool,
        /// Answer `ChunkUploaded` as soon as the chunk is **stored**: the
        /// first receipt, shallow or deep. A shallow one no longer holds
        /// the answer back while the push hunts for a deeper storer; the
        /// hunt goes on in the background exactly as it would have, and
        /// its outcome is only logged. At most `MAX_BACKGROUND_HUNTS` (64)
        /// such hunts run node-wide; with every slot taken the push is
        /// answered when done, as with `false` (and from its first
        /// receipt on, hedging every 5 s like it). For a caller that needs
        /// the chunk held by the network now and in its own neighbourhood
        /// seconds later, rather than deep before it may go on: a live broadcast's
        /// segments, which every later segment waits behind (issue #212).
        /// `false` (every other caller) answers when the push is done.
        /// Ignored with `require_deep`, whose answer is the deep receipt.
        ack_when_stored: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `POST /soc/{owner}/{id}`: stamp the SOC at `address` and
    /// pushsync the wire bytes. `address` is `keccak256(id || owner)`,
    /// already validated by the gateway via `soc_valid(&address, &wire)`;
    /// `wire` is the SOC's `swarm.Chunk.Data()` form (`id || sig ||
    /// inner_cac`). The node stamps directly at `address` rather than
    /// rederiving via BMT, since SOC addresses are not BMT-addressable.
    ///
    /// `stamp` carries an optional pre-signed 113-byte postage stamp —
    /// see [`ControlCommand::PushChunk`] for the semantics.
    PushSoc {
        address: [u8; 32],
        wire: Vec<u8>,
        batch_id: [u8; 32],
        /// Pre-signed 113-byte stamp; `None` = stamp locally.
        stamp: Option<Vec<u8>>,
        /// See [`ControlCommand::PushChunk`]: answer at the first
        /// receipt, shallow or deep, and finish the hunt for a deep
        /// storer in the background (a live segment's replica SOCs).
        ack_when_stored: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `POST /envelope/{address}`: issue (and persist) a postage
    /// stamp for a chunk address the caller will upload later — bee's
    /// `envelopePostHandler` (`stamper.Stamp(address, address)`).
    /// Consumes a bucket slot on the registered issuer exactly like
    /// stamping an upload; re-requesting the same address reuses the
    /// original stamp (the issuer's per-chunk stamp cache). The ack is
    /// [`ControlAck::Envelope`] carrying the issuer's Ethereum address
    /// and the full 113-byte stamp.
    Envelope {
        address: [u8; 32],
        batch_id: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `GET /stewardship/{address}`: traverse the full content
    /// tree rooted at `reference` (span trees *and* mantaray manifests,
    /// bee `pkg/traversal` semantics) and check that every chunk is
    /// retrievable. The ack is [`ControlAck::Retrievable`]; any
    /// traversal failure (missing root, unreachable interior node,
    /// unreachable leaf) reports `retrievable: false` rather than an
    /// error, matching bee's `steward.IsRetrievable` mapping of
    /// not-found to `{"isRetrievable": false}`.
    StewardshipGet {
        reference: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `PUT /stewardship/{address}`: re-upload the content tree
    /// rooted at `reference` — traverse it, fetch every chunk
    /// (cache-first via the normal fetcher), stamp each against
    /// `batch_id`, and pushsync them all (bee `steward.Reupload`). The
    /// ack is [`ControlAck::Ok`] on success; an unknown batch fails
    /// with the same "batch … not usable" error `PushChunk` reports.
    StewardshipPut {
        reference: [u8; 32],
        batch_id: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Register (or refresh) a postage batch with the running node so it
    /// can stamp uploads against it without a restart. Sent by the
    /// gateway right after a successful on-chain `createBatch`
    /// (`POST /stamps/{amount}/{depth}`) and after a `dilute`. The node
    /// opens (or reopens) the issuer's persistent `.bin` at
    /// `<data-dir>/postage/<batch_id>.bin` and inserts it into the live
    /// issuer registry. Idempotent: re-registering an existing batch
    /// reopens the same counters; a higher `depth` bumps the live
    /// issuer's depth in place (dilute). `bucket_depth` must equal the
    /// value baked into the `createBatch` transaction (bee uses 16) or
    /// the resulting stamps won't validate.
    RegisterBatch {
        batch_id: [u8; 32],
        depth: u8,
        bucket_depth: u8,
        immutable: bool,
        /// The block of the `createBatch` receipt, when the caller has
        /// just bought this batch; `None` for a batch registered by id,
        /// rediscovered, or re-registered after a dilute.
        ///
        /// A just-bought batch isn't usable yet: storers accept its
        /// stamps only once their postage listeners have synced its
        /// creation block. The node then reports it `usable: false`
        /// and treats peers' "not found on-chain" rejections as
        /// propagation lag rather than a phantom batch, for bee's
        /// confirmation window.
        bought_at_block: Option<u64>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Install (or replace) the outbound SWAP settlement subsystem on
    /// the running node, so pushsync starts emitting cheques without a
    /// restart. Sent by `ant-ffi` right after it deploys / rediscovers
    /// the node's chequebook on first storage purchase: at that point
    /// the node wallet is funded and a factory-registered chequebook
    /// exists, but the swarm loop came up (at `ant_init`) before either
    /// was true. Without this the freshly bought batch would upload at
    /// most ~20 K chunks across the peer set before bee's accounting
    /// locks us out, and settlement would only take effect on the next
    /// app launch (when init reloads the persisted chequebook).
    ///
    /// `swap_secret` is the 32-byte secp256k1 secret of the
    /// chequebook's issuer EOA (the node identity key for an
    /// auto-deployed chequebook). Idempotent: re-installing the same
    /// `chequebook` is a no-op that re-acks `Ok`.
    EnablePushsyncSwap {
        chequebook: [u8; 20],
        swap_secret: [u8; 32],
        chain_id: u64,
        outbound_ledger_path: String,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Switch outbound SWAP settlement off again, if (and only if) it is
    /// currently running on `chequebook`. Sent by `ant-ffi` when a
    /// chain check disqualifies the chequebook that `ant_init` enabled
    /// unchecked from the persisted record (no RPC at init): signing
    /// cheques every peer drops is worse than pseudosettle alone. A
    /// service on a different chequebook (a concurrent enable won) is
    /// left alone; acks `Ok` either way.
    DisablePushsyncSwap {
        chequebook: [u8; 20],
        ack: oneshot::Sender<ControlAck>,
    },
    /// What `chequebook` can put into retrieval cheques, and at which
    /// rates (issue #121), as read from the chain by
    /// `ant_chain::chequebook_store::watch_retrieval_funds`. Kept for
    /// `chequebook` and applied to the outbound SWAP service whenever it
    /// runs on that chequebook (now, or once it starts). Acks `Ok`.
    SetRetrievalFunds {
        chequebook: [u8; 20],
        /// xBZZ ever deposited and not withdrawn, PLUR. A chequebook
        /// withdrawal hands the node this lowered by its amount before
        /// the transaction goes out, so no cheque is signed against it.
        deposited_plur: u128,
        /// Bee's oracle exchange rate, PLUR per accounting unit.
        exchange_rate_plur: u128,
        /// Bee's oracle deduction, PLUR.
        deduction_plur: u128,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Bee's node-wide SWAP settlement switch (`swap-enable`), changed at
    /// runtime (a superset of bee, which reads it at start). `true` (the
    /// default) pays peers with SWAP cheques for downloads (issue #121)
    /// and uploads (issue #127) alike past the early-payment threshold
    /// once a funded chequebook backs settlement, as bee does; `false`
    /// keeps both on the free pseudosettle tier even with one. Acks `Ok`.
    SetSwapEnabled {
        enabled: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Create a new upload job. The node loop forwards to its
    /// `UploadManager`, which writes the persistent manifest, spawns
    /// the driver task, and acks with the assigned job id.
    UploadStart {
        source_path: PathBuf,
        batch_id: Option<String>,
        name: Option<String>,
        content_type: Option<String>,
        /// Skip the trailing single-file mantaray manifest. The
        /// completed job's `reference` is the data root chunk
        /// address (a `/bytes/<ref>` reference). See the
        /// [`crate::Request::UploadStart`] doc for the trade-off.
        raw: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Snapshot every known upload job. Cheap (returns the in-memory
    /// table; no I/O).
    UploadList { ack: oneshot::Sender<ControlAck> },
    /// Snapshot one upload job by id (or unique 8-hex-char prefix).
    UploadStatus {
        job_id: String,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Soft-stop, hard-stop, or restart an upload job. Each variant
    /// acks with a fresh [`UploadJobView`] reflecting the new state.
    UploadPause {
        job_id: String,
        ack: oneshot::Sender<ControlAck>,
    },
    UploadResume {
        job_id: String,
        ack: oneshot::Sender<ControlAck>,
    },
    UploadCancel {
        job_id: String,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Re-push a completed-but-degraded job's missing chunks on the same
    /// job (the app's "push again"), running the self-heal to completion
    /// and streaming progress while it does. `progress` (if set) receives
    /// JSON lines `{"phase":"checking"|"repushing","checked"?:n,"total"?:n}`
    /// — `checking` for each read-back round, `repushing` with a running
    /// chunk count as the gap is re-pushed. The terminal `ack` is the
    /// updated job JSON once the heal settles. `None` progress runs the
    /// heal silently.
    UploadRepush {
        job_id: String,
        progress: Option<mpsc::UnboundedSender<String>>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Subscribe to live upload progress. Sends zero or more
    /// [`ControlAck::UploadProgress`] frames followed by a terminal
    /// [`ControlAck::UploadJob`] / [`ControlAck::Error`] when the job
    /// reaches a terminal status (or an error happens).
    UploadFollow {
        job_id: String,
        ack: mpsc::Sender<ControlAck>,
    },
    /// System-initiated suspend of the whole upload subsystem (an app
    /// moving to the background / the network going away). Pauses every
    /// non-terminal job with the `auto_paused` marker (distinguishing
    /// it from a user pause), asks running securing passes to stop, and
    /// acks only after the drivers have drained their in-flight pushes
    /// and checkpointed (bounded wait), so a host with a short
    /// background grace window knows state is safely on disk. Safe to
    /// call repeatedly.
    UploadSuspendAll { ack: oneshot::Sender<ControlAck> },
    /// Undo [`ControlCommand::UploadSuspendAll`]: restart only the jobs
    /// it paused (`auto_paused` — a user-paused job stays paused) and
    /// re-queue securing passes for completed-but-unverified jobs. Safe
    /// to call repeatedly and without a prior suspend.
    UploadWakeAll { ack: oneshot::Sender<ControlAck> },
    /// Snapshot of the local postage stamp issuer (capacity, fill,
    /// per-bucket extremes). Pure local read — no chain RPC, no
    /// network round-trip. With multiple registered batches this returns
    /// the first one (back-compat for `antctl postage status`); use
    /// [`ControlCommand::PostageList`] to enumerate every batch.
    PostageStatus { ack: oneshot::Sender<ControlAck> },
    /// Snapshot of **every** registered postage batch. Backs the
    /// gateway's `GET /stamps`, which bee-js / Freedom poll to learn the
    /// set of usable batches. Pure local read.
    PostageList { ack: oneshot::Sender<ControlAck> },
    /// Write a single CAC chunk straight into the local disk chunk
    /// cache (no postage stamp, no pushsync). Backs `antctl pin`,
    /// which lets an operator make a previously-uploaded file
    /// retrievable through this node's HTTP gateway without
    /// waiting for bee-side neighbourhood replication.
    ///
    /// `wire` is the full chunk wire bytes (`span (8 LE) ||
    /// payload`); the handler recomputes the address (BMT-with-span)
    /// and rejects payloads whose hash doesn't match.
    PutChunkLocal {
        wire: Vec<u8>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Deep read-back propagation check for a freshly-uploaded
    /// reference. Resolves `reference` as a mantaray manifest (falling
    /// back to treating it as a raw `/bytes/` data root if it isn't
    /// one), then enumerates the file's chunk tree and probes the
    /// *actual data chunks* — not just the root reference.
    ///
    /// Every interior (intermediate) node of the tree is fetched
    /// network-only to walk it, so reaching the end proves the whole
    /// skeleton is retrievable. The data **leaves** are then checked
    /// network-only along the same path (so the daemon's own
    /// store-then-push copy can't mask a failed push): when `samples == 0`
    /// *every* leaf is checked (a full verification, internally bounded so
    /// a huge file stays tractable); a non-zero `samples` checks an
    /// evenly-spread sample of that many leaves only. A bounded subset is
    /// additionally probed across up to `probes` distinct closest BZZ peers
    /// for the replication floor.
    ///
    /// The ack is a [`ControlAck::Ok`] whose `message` is a JSON
    /// document `{reference, retrievable, total_chunks, leaf_chunks,
    /// intermediate_chunks, checked_chunks, retrievable_chunks,
    /// sampled_leaves, sources, error?}`. `retrievable` is true iff the
    /// data root and every interior node were fetched and every checked
    /// leaf returned from at least one peer; `sources` is the minimum
    /// distinct-route count observed across the probed subset (a
    /// replication floor). `samples == 0` means a full check; `probes == 0`
    /// falls back to a sensible default.
    VerifyPropagation {
        reference: [u8; 32],
        samples: u8,
        probes: u8,
        /// Optional sink for incremental progress while the (potentially
        /// slow) leaf-checking pass runs. Each item is a JSON line of the
        /// shape `{"phase":"resolving"|"enumerating"|"checking",
        /// "checked"?:n,"total"?:n}`. `None` opts out: the socket
        /// transport and CLI paths pass `None`; only the in-process FFI
        /// (the `AntDrive` app) streams progress to drive a real bar.
        progress: Option<mpsc::UnboundedSender<String>>,
        /// Optional cooperative cancel flag. Set to `true` by the caller
        /// (the FFI's `ant_verify_cancel`) to abort an in-flight check; the
        /// verify polls it between phases and per leaf and returns a
        /// `{"cancelled":true,...}` body promptly. `None` = not cancellable.
        cancel: Option<Arc<AtomicBool>>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Read-back presence check for a specific set of chunk addresses.
    /// Backs the upload self-heal loop. The ack is a [`ControlAck::Ok`]
    /// whose `message` is JSON `{"checked":N,"missing":["0x..",...]}`
    /// listing the addresses that didn't come back. Callers batch the
    /// address list to keep each ack bounded.
    ///
    /// `probes` selects the presence test:
    /// * `0` — *any-route* fetch (cache-free, the same robust
    ///   closest-first / forwarder-walking path a real download takes).
    ///   A chunk counts as present if it can be retrieved by any path.
    /// * `>0` — *deep* check: probe each chunk's `probes` closest known
    ///   peers (its neighbourhood vantage) first; chunks those one-shot
    ///   probes miss are then confirmed via the any-route fetch and
    ///   count missing only when **both** fail. The probe stage flags
    ///   shallow placements (a chunk reachable only because the uploader
    ///   stays linked to a far storer that signed a shallow receipt);
    ///   the routed confirmation clears the probes' substantial
    ///   single-attempt false-failure rate, so "missing" tracks what a
    ///   third party (e.g. the public gateway) can actually retrieve.
    VerifyChunksPresent {
        addresses: Vec<[u8; 32]>,
        probes: usize,
        /// Only meaningful when `probes > 0`. When `false` (the default,
        /// used by the automatic post-upload heal), a chunk
        /// counts missing only if **both** the neighbourhood probe and the
        /// routed confirmation fail — i.e. no route can serve it. When
        /// `true`, a chunk counts missing as soon as the neighbourhood
        /// probe fails, *even if* the privileged routed path still serves
        /// it: that flags merely-shallow placements for re-push. Reserved
        /// for the explicit, user-initiated "Push again" (re-pushing a few
        /// healthy chunks on probe noise is acceptable for a manual,
        /// infrequent action, but would be a re-push storm on every
        /// automatic heal — which is why it stays off by default).
        include_shallow: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Resolve a sequence feed `(owner, topic)` to its latest update.
    /// Backs the gateway's `GET /feeds/{owner}/{topic}` endpoint. The
    /// handler uses the same `RoutingFetcher` machinery `GetBytes` does,
    /// so the lookup is bounded by `ant_retrieval::feed`'s scan limits
    /// and tolerates transient peer flakiness. Epoch feeds aren't a
    /// supported variant: the gateway short-circuits `?type=epoch` with
    /// `501 Not Implemented` before sending the command, so the wire
    /// here is sequence-only.
    ///
    /// Ends in [`ControlAck::FeedResolved`], [`ControlAck::FeedNotFound`]
    /// (an anchor miss more than a couple of peers agree on: a feed
    /// nothing was written to), [`ControlAck::NotReady`] (an anchor miss
    /// only one or two cold peers answered, which can't tell an empty
    /// feed from one the node can't reach yet, or with `exact` a head
    /// whose next slot isn't confirmed empty) or [`ControlAck::Error`].
    GetFeed {
        owner: [u8; 20],
        topic: [u8; 32],
        /// Anchor index for the lookup — the `?after=N` query parameter
        /// of bee's `GET /feeds/{owner}/{topic}`: the finder starts at
        /// this index (absent ⇒ "no update found", even if earlier
        /// updates exist) and searches for the latest update from
        /// there. `0` is the plain "latest" lookup.
        after: u64,
        /// The gateway's `?exact=true` (ant only, not bee): resolve
        /// through `ant_retrieval::resolve_sequence_feed_exact`, which
        /// answers only once the slot after the head is confirmed empty
        /// and otherwise ends in [`ControlAck::NotReady`]. For a writer
        /// about to take the next slot (the live publisher's head read,
        /// issue #173); a reader leaves it off and gets bee's finder,
        /// whose bounded look-ahead can land below a slow head.
        exact: bool,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `POST /pins/{reference}` — pin a content tree into the
    /// node's local store (bee `pinRootHash`). The node traverses the
    /// tree rooted at `reference` (32-byte plain or 64-byte
    /// `address ‖ decryption-key` encrypted reference), fetches every
    /// chunk through the normal cache-first/network-fallback fetcher
    /// (bee's `storer.Download(true)` getter — pinning cold content
    /// pulls it in), and marks every chunk pin-protected in the disk
    /// cache. The ack is [`ControlAck::PinAdded`]; a tree with
    /// unreachable chunks fails with an `Error` whose message contains
    /// `not found`, which the gateway maps to bee's 404
    /// "pin collection failed".
    PinAdd {
        reference: Vec<u8>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `DELETE /pins/{reference}` — drop a pin (bee
    /// `unpinRootHash`). Clears the pin flags recorded by
    /// [`ControlCommand::PinAdd`]; chunks whose last pin is removed
    /// become evictable again. Ack is [`ControlAck::PinRemoved`].
    PinRemove {
        reference: Vec<u8>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `GET /pins/{reference}` — is this root pinned? Ack is
    /// [`ControlAck::PinPresent`].
    PinHas {
        reference: Vec<u8>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `GET /pins` — list every pinned root reference in
    /// insertion order. Ack is [`ControlAck::PinList`].
    PinList { ack: oneshot::Sender<ControlAck> },
    /// Gateway `GET /pins/check[?ref=…]` — bee's pin-integrity check:
    /// for each pinned root (or just `reference` when given), report
    /// how many member chunks the pin recorded, how many are missing
    /// from the local store, and how many are present but fail
    /// validation. Ack is [`ControlAck::PinCheck`].
    PinCheck {
        reference: Option<Vec<u8>>,
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `GET /stamps/{id}/buckets` — per-bucket collision
    /// counters of a registered postage batch (bee
    /// `postageGetStampBucketsHandler`). Ack is
    /// [`ControlAck::PostageBuckets`], or `Error` containing
    /// `issuer does not exist` for an unregistered batch.
    PostageBuckets {
        batch_id: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `GET /stamps/{id}/chunks/{address}` (proposed for bee in
    /// ethersphere/bee#5682): whether this node stamped `address` with
    /// `batch_id`, read from the batch issuer's own per-chunk stamp
    /// records (the `.stamps` sidecar). One lookup, no network. Ack is
    /// [`ControlAck::StampedChunk`] (`stamp: None` when the issuer has
    /// no record of the chunk), or `Error` containing `issuer does not
    /// exist` for an unregistered batch, starting `uploads not
    /// configured` when the node has no upload runtime yet, or
    /// containing `stamp records unavailable` when the issuer's sidecar
    /// can't be safely used (see
    /// `ant_postage::StampIssuer::stamp_records_unavailable`; a miss
    /// then can't be told apart from a lost record).
    StampedChunk {
        batch_id: [u8; 32],
        address: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway `GET /stewardship/{reference}/stamps` (proposed for bee in
    /// ethersphere/bee#5682): walk the content tree at `reference` the
    /// way [`ControlCommand::StewardshipGet`] does, then count, for each
    /// batch this node issues stamps from, how many of the tree's chunks
    /// its records say it stamped, and how many chunks no batch stamped.
    /// Ack is [`ControlAck::StewardshipStamps`]; `Error` when the walk
    /// fails (no partial counts), when the node has no upload runtime
    /// (`uploads not configured`), or when any issuer's records are
    /// unavailable (`stamp records unavailable`).
    StewardshipStamps {
        reference: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    },
    /// Gateway read-only settlement/balance endpoints (`GET /balances`,
    /// `/consumed`, `/settlements`, `/timesettlements`,
    /// `/chequebook/cheque` and their `/{peer}` variants): snapshot the
    /// node's per-peer accounting mirror, swap ledgers, and
    /// pseudosettle totals in one ack so a single command serves every
    /// endpoint. The ack is [`ControlAck::Accounting`]; a node with no
    /// peers (or none of the subsystems configured) acks an empty
    /// snapshot, which the gateway renders as bee's empty list shapes.
    AccountingSnapshot { ack: oneshot::Sender<ControlAck> },
}

/// Inclusive byte range used by [`ControlCommand::StreamBytes`] and
/// [`ControlCommand::StreamBzz`]. Mirrors
/// [`ant_retrieval::ByteRange`] but kept local so `ant-control` doesn't
/// take a build-graph dependency on the retrieval crate.
#[derive(Debug, Clone, Copy)]
pub struct StreamRange {
    pub start: u64,
    pub end_inclusive: u64,
}

/// The feed update a `/bzz` feed manifest resolved to, carried on
/// [`ControlAck::BzzStreamStart`]. Mirrors
/// `ant_retrieval::ResolvedFeed`, kept local for the same reason as
/// [`StreamRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BzzFeed {
    /// Sequence index of the resolved update.
    pub index: u64,
    /// `true` for a v2 update (the SOC wraps the content root), `false`
    /// for v1 (`ts ‖ ref`).
    pub v2: bool,
}

/// The transport a lurker message was decoded from (house style: typed,
/// not stringly — the wire form stays `"gsoc"`/`"pss"` via serde).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LurkerMessageKind {
    Gsoc,
    Pss,
}

/// Node-loop reply to a [`ControlCommand`]. Serialized back to the client as
/// `Response::Ok`, `Response::Bytes`, `Response::BzzBytes`,
/// `Response::Progress`, or `Response::Error` depending on the variant.
#[derive(Debug, Clone)]
pub enum ControlAck {
    Ok {
        message: String,
    },
    Bytes {
        data: Vec<u8>,
    },
    BzzBytes {
        data: Vec<u8>,
        content_type: Option<String>,
        filename: Option<String>,
    },
    Manifest {
        entries: Vec<ManifestEntryInfo>,
    },
    /// One page of a [`ControlCommand::ListBzz`] with `page: Some(..)`.
    ManifestPage(ManifestListPage),
    /// Streaming progress sample for a `GetBytes` / `GetBzz` request.
    /// Producer can fire as many of these as it likes; the dispatcher
    /// keeps writing them until a terminal variant arrives or the
    /// channel closes.
    Progress(GetProgress),
    BytesStreamStart {
        total_bytes: u64,
    },
    /// Streaming-bzz prologue: emitted by `StreamBzz` once the manifest
    /// has resolved and the data root chunk has been fetched (so the
    /// total span is known). Followed by zero or more `BytesChunk`s
    /// and a terminal `StreamDone` / `Error`.
    BzzStreamStart {
        total_bytes: u64,
        /// Resolved **data reference** of the manifest entry being
        /// served (the reference bee's `downloadHandler` receives from
        /// `manifestEntry.Reference()`): 32 bytes, or 64 for an entry in
        /// an encrypted manifest. The gateway quotes it in the `ETag`
        /// response header, matching bee's
        /// `w.Header().Set(ETagHeader, fmt.Sprintf("%q", reference))`.
        reference: Vec<u8>,
        content_type: Option<String>,
        filename: Option<String>,
        /// `Some` when the resolved reference was a **feed manifest**,
        /// carrying the feed update it resolved to. The content is then
        /// mutable at the (stable) bzz URL, so the gateway serves it with
        /// `Cache-Control: no-cache` instead of the immutable cache
        /// normal content-addressed bzz responses get, and reports the
        /// update in bee's `swarm-feed-index` /
        /// `swarm-feed-resolved-version` headers. `None` for static
        /// manifests.
        feed: Option<BzzFeed>,
    },
    BytesChunk {
        data: Vec<u8>,
    },
    StreamDone,
    /// Successful `PushChunk`; reference is lowercase `0x` + 64 nibbles (bee-compatible).
    ChunkUploaded {
        reference: String,
    },
    /// Successful `Envelope`: the issuing node's Ethereum address plus
    /// the full 113-byte stamp (`batch_id(32) ‖ index(8) ‖ timestamp(8)
    /// ‖ sig(65)`). The gateway slices index/timestamp/signature out of
    /// the stamp for bee's `postEnvelopeResponse` JSON shape.
    Envelope {
        issuer: [u8; 20],
        stamp: [u8; 113],
    },
    /// Terminal ack on `StewardshipGet`: whether every chunk of the
    /// traversed content tree could be retrieved.
    Retrievable {
        retrievable: bool,
    },
    /// Terminal ack on `PullsyncProbe`.
    PullsyncProbe(PullsyncProbeView),
    /// Non-terminal streaming frame on `LurkerSubscribe`: one decoded
    /// GSOC/PSS message. `key` is the SOC address (gsoc) or topic (pss)
    /// as lowercase hex; `payload` is the application bytes.
    LurkerMessage {
        kind: LurkerMessageKind,
        key: String,
        payload: Vec<u8>,
    },
    /// Successful `UploadStart`.
    UploadStarted {
        job_id: String,
    },
    /// Snapshot of one upload job (terminal ack on
    /// `UploadStatus`/`UploadPause`/`UploadResume`/`UploadCancel`,
    /// terminal frame on `UploadFollow`).
    UploadJob(UploadJobView),
    /// Snapshot of every upload job (terminal ack on `UploadList`).
    UploadList(Vec<UploadJobView>),
    /// Streaming progress frame for `UploadFollow`. Non-terminal.
    UploadProgress(UploadJobView),
    /// Local postage stamp issuer snapshot. Terminal ack on
    /// `PostageStatus`.
    PostageStatus(PostageStatusView),
    /// Snapshot of every registered postage batch. Terminal ack on
    /// `PostageList`.
    PostageList(Vec<PostageStatusView>),
    /// Per-peer settlement/balance snapshot. Terminal ack on
    /// `AccountingSnapshot`.
    Accounting(AccountingSnapshotView),
    /// Terminal ack on `PinAdd`. `already_pinned` distinguishes bee's
    /// idempotent 200 "OK" (root already pinned) from the fresh 201
    /// "Created".
    PinAdded {
        already_pinned: bool,
    },
    /// Terminal ack on `PinRemove`. `was_pinned = false` maps to bee's
    /// 404 on unpinning an unknown root.
    PinRemoved {
        was_pinned: bool,
    },
    /// Terminal ack on `PinHas`.
    PinPresent {
        pinned: bool,
    },
    /// Terminal ack on `PinList`: every pinned root reference (32 bytes
    /// plain, 64 bytes for an encrypted reference) in pin-creation
    /// order.
    PinList {
        references: Vec<Vec<u8>>,
    },
    /// Terminal ack on `PinCheck`: one integrity row per inspected pin.
    PinCheck {
        stats: Vec<PinCheckStat>,
    },
    /// Terminal ack on `PostageBuckets`.
    PostageBuckets(PostageBucketsView),
    /// Terminal ack on `StampedChunk`: the full 113-byte stamp
    /// (`batch_id(32) ‖ index(8) ‖ timestamp(8) ‖ sig(65)`) the issuer
    /// recorded for the chunk, or `None` when it has no record of it.
    StampedChunk {
        stamp: Option<[u8; 113]>,
    },
    /// Terminal ack on `StewardshipStamps`.
    StewardshipStamps(StewardshipStampsView),
    /// Successful feed resolution: the reference the latest update points
    /// at, the sequence index it lived at, the SOC signature of that
    /// update chunk, and whether it resolved as v2 (the wrapped CAC is
    /// the content root) rather than v1 (`ts ‖ ref`). Bee's
    /// `GET /feeds/{owner}/{topic}` surfaces the index (big-endian
    /// 8-byte) in the `swarm-feed-index` header, `index + 1` in
    /// `swarm-feed-index-next`, the signature (hex) in
    /// `swarm-soc-signature`, and `v1`/`v2` in
    /// `swarm-feed-resolved-version`; the response body is the
    /// dereferenced content at `reference`. Carrying these through the
    /// ack lets the gateway build those headers without recomputing.
    FeedResolved {
        reference: [u8; 32],
        index: u64,
        signature: [u8; 65],
        v2: bool,
        /// `Some(key)` when `reference` is an encrypted chunk address and
        /// the content must be decrypted with `key` (bee's 80-byte v1
        /// payload). The gateway joins `reference ‖ key` via the
        /// decrypting joiner. `None` for unencrypted content.
        decrypt_key: Option<[u8; 32]>,
    },
    /// Empty-feed signal from `GetFeed`: the anchor miss was
    /// corroborated by more than a couple of peers
    /// (`FeedError::NoUpdates { corroborated: true, .. }`); an
    /// uncorroborated one is [`Self::NotReady`] instead. Distinct from
    /// [`Self::Error`] so the gateway can map it to `404 Not Found`
    /// without substring-matching an error message.
    FeedNotFound,
    /// The node loop accepted the command but isn't ready to serve it
    /// (most commonly: zero connected peers). `StreamBytes` /
    /// `StreamBzz` also send it, before their stream starts, when a
    /// fetch's last answer was a miss but the peer pool was starved
    /// (`FetchExhausted::pool_starved`): one cold peer's "not found" is
    /// not the network's answer (issue #114), so it is a 503 to retry,
    /// never a 404. `StreamBzz` also sends it for a manifest node whose
    /// direct miss *is* corroborated but whose dispersed-replica sweep
    /// missed only transiently in the last attempt
    /// (`ReplicaSweeps::swept_transiently`): a replica-only node (#154) is
    /// a corroborated direct miss by construction, so under credit
    /// pressure the content may still be reachable through its replicas
    /// and the answer is a 503, not a 404 (R4-M1 on PR #155). So a
    /// corroborated miss does not by itself rule out `NotReady`.
    /// `GetFeed` sends it for an anchor miss only one or two peers
    /// answered (`FeedError::NoUpdates { corroborated: false, .. }`):
    /// not proof the feed is empty, so a 503 rather than bee's
    /// `404 "no update found"` (issue #173). An `exact` `GetFeed` also
    /// sends it for a head whose next slot isn't confirmed empty
    /// (`FeedError::EndUnconfirmed`). A paged [`ControlCommand::ListBzz`]
    /// sends it when no peers are connected yet, for a trie node
    /// missed by a starved pool or whose replica sweep failed only
    /// transiently, the same split as `StreamBzz` (issue #61), and when
    /// the walk ran out of its wall-clock budget before finding a single
    /// item (`ManifestError::ListTimedOut`; a warm retry gets further).
    /// Terminal, like [`Self::Error`]. Distinct from
    /// [`Self::Error`] so the gateway can map it to `503 Service
    /// Unavailable` rather than the `502 Bad Gateway` it returns for
    /// genuine I/O failures.
    NotReady {
        message: String,
    },
    /// A retrieval the network answered: peers confirmed the chunk
    /// missing (`ant_retrieval::fetcher::FetchExhausted::confirmed_missing`,
    /// i.e. a `storage: not found` *or* `no peer found` last answer from
    /// a fetch whose peer pool wasn't starved). Distinct from
    /// [`Self::Error`] so the gateway answers bee's `404` without
    /// substring-matching the message, whichever of the two tails it
    /// ends in (issue #123). Only sent before a stream starts, or as the
    /// whole answer to a single-chunk [`ControlCommand::GetChunkRaw`]
    /// (issue #146). A paged [`ControlCommand::ListBzz`] (issue #61) also
    /// sends it when the reference or a trie node is not a decodable
    /// manifest, the listing's prefix names nothing in it, or a path on
    /// the page is not valid UTF-8 (`ManifestError::ListNonUtf8Path`):
    /// answers about the manifest, not the network, but bee#5537's 404
    /// all the same.
    NotFound {
        message: String,
    },
    Error {
        message: String,
    },
}

/// One row of a pin-integrity check (`GET /pins/check`), mirroring
/// bee's `PinIntegrityResponse`: the pinned root, how many member
/// chunks the pin recorded, how many of those are missing from the
/// local store, and how many are present but fail CAC/SOC validation.
#[derive(Debug, Clone, Default)]
pub struct PinCheckStat {
    /// Pinned root reference (32 bytes, or 64 for an encrypted ref).
    pub reference: Vec<u8>,
    pub total: u64,
    pub missing: u64,
    pub invalid: u64,
}

/// Per-bucket collision counters of a postage batch issuer, mirroring
/// bee's `postageStampBucketsResponse` (`GET /stamps/{id}/buckets`).
/// `collisions[i]` is the fill of bucket `i`; the gateway renders it as
/// bee's `[{bucketID, collisions}]` array.
#[derive(Debug, Clone, Default)]
pub struct PostageBucketsView {
    pub depth: u8,
    pub bucket_depth: u8,
    /// `2^(depth - bucket_depth)` — max collisions per bucket.
    pub bucket_upper_bound: u32,
    pub collisions: Vec<u32>,
}

/// Per-batch stamp coverage of a content tree, answering
/// `GET /stewardship/{reference}/stamps`. `chunks` is the number of
/// distinct chunks in the tree; `batches` lists every batch this node
/// issues stamps from (sorted by id, zero counts included) with how many
/// of those chunks its records say it stamped; `unstamped` is how many
/// chunks no listed batch stamped. A chunk stamped by two batches counts
/// once in each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StewardshipStampsView {
    pub chunks: u64,
    pub batches: Vec<BatchChunkCount>,
    pub unstamped: u64,
}

/// One row of [`StewardshipStampsView::batches`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchChunkCount {
    pub batch_id: [u8; 32],
    pub chunks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntryInfo {
    pub path: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// File size in bytes derived from the data root chunk's BMT span.
    /// `None` means the entry is metadata-only (no data reference) or
    /// the data root chunk could not be fetched while listing the
    /// manifest. Skipped from the JSON wire when absent so older
    /// clients keep deserializing newer responses unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// One page request of a manifest listing, bee#5535's query parameters
/// (`GET /v0/manifest/{addr}/{prefix}?delimiter=&after=&limit=&sizes=`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestListQuery {
    /// Only paths starting with this (any byte prefix) are listed.
    pub prefix: String,
    /// Empty: recursive. Otherwise a shallow listing that folds deeper
    /// paths into `common_prefixes`.
    pub delimiter: String,
    /// Continuation: only items sorting strictly after this.
    pub after: String,
    /// Items (entries plus common prefixes) per page, already validated.
    pub limit: usize,
    /// Read each entry's size from its data root chunk's span.
    pub sizes: bool,
}

/// One page of a manifest listing ([`ControlAck::ManifestPage`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestListPage {
    /// Value entries, in path order; `reference` is always set and
    /// `size` only when asked for and readable.
    pub entries: Vec<ManifestEntryInfo>,
    pub common_prefixes: Vec<String>,
    pub truncated: bool,
    /// Set iff `truncated`: pass it back as the next page's `after`.
    pub next_marker: Option<String>,
    /// The same request always answers the same: the reference was not
    /// a feed manifest, every size asked for was read, and the page was
    /// not cut short by the walk's wall-clock budget
    /// (`ant_retrieval::MANIFEST_PAGE_WALK_BUDGET`) or by a failed
    /// lookahead load past a full page
    /// (`ant_retrieval::ManifestPage::lookahead_failed`). Gates the gateway's
    /// immutable `Cache-Control`.
    pub immutable: bool,
}

impl ControlAck {
    pub(crate) const fn is_terminal(&self) -> bool {
        !matches!(
            self,
            Self::Progress(_)
                | Self::BytesStreamStart { .. }
                | Self::BzzStreamStart { .. }
                | Self::BytesChunk { .. }
                | Self::UploadProgress(_)
        )
    }
}

/// Build the `mpsc` ack channel handed to streaming-capable
/// `ControlCommand`s. Public so the node loop's tests can wire one up
/// without reaching into the server module's internals.
#[must_use]
pub fn streaming_ack_channel() -> (mpsc::Sender<ControlAck>, mpsc::Receiver<ControlAck>) {
    mpsc::channel(STREAM_ACK_CAPACITY)
}
