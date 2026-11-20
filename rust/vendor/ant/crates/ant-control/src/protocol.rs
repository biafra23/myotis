//! Wire types shared by the daemon and `antctl`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Bumped whenever the wire format changes in a non-additive way.
///
/// v2 introduced streaming progress on `Get`/`GetBytes`/`GetBzz`: when the
/// client sends `progress: true`, the daemon may emit zero or more
/// [`Response::Progress`] messages on the same connection before the
/// terminal response. Older clients leave `progress` at its default
/// (`false`) and continue to see exactly one response, preserving the
/// v1 single-shot behaviour. The new `bypass_cache` request flag is
/// equally additive — old daemons simply ignore the field.
///
/// v3 added the `Upload*` request set: long-lived daemon-resident
/// upload jobs that stream `UploadProgress` over a control-socket
/// follow connection and survive daemon restarts via on-disk
/// manifests. v2 daemons reject `Upload*` with the standard
/// "bad request" envelope, so an old `antctl` against a new
/// daemon and vice versa are both observably wrong instead of
/// silently misbehaving. The optional `raw` flag on `UploadStart`
/// (and the `raw` field echoed back on `UploadJobView`) is
/// additive — old daemons leave it at the `#[serde(default)]`
/// `false` value, which preserves the original "always wrap in a
/// single-file mantaray manifest" behaviour.
pub const PROTOCOL_VERSION: u32 = 3;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Client → daemon request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Current daemon status snapshot.
    Status,
    /// Daemon agent string + control-protocol version.
    Version,
    /// Drop the on-disk peerstore (`<data-dir>/peers.json`) and the in-memory
    /// dedup set without disconnecting current peers. The next restart will
    /// bootstrap fresh from bootnodes.
    PeersReset,
    /// Run a pullsync viability probe against the closest connected peer
    /// to `target` (64-hex overlay). Fetches the peer's cursors and pulls
    /// one page of the neighborhood bin. Answers with
    /// [`Response::PullsyncProbe`]. Ops/validation tool for the GSOC/PSS
    /// lurker (Exp-1: does a mainnet full node serve pullsync to us?).
    PullsyncProbe {
        target: String,
        #[serde(default)]
        bin: Option<u8>,
        #[serde(default)]
        start: Option<u64>,
        #[serde(default)]
        max_deliver: Option<usize>,
    },
    /// Retrieve the chunk at `reference` from the network. The 32-byte
    /// reference is a `0x`-prefixed hex string. The daemon answers with
    /// [`Response::Bytes`] carrying the verified chunk payload (without
    /// the span prefix).
    ///
    /// `bypass_cache` skips the daemon's shared in-memory and disk
    /// chunk caches for this request only: the daemon mints a fresh
    /// per-request in-memory cache so intra-request retries still
    /// benefit from caching, but no chunk hits or writes touch the
    /// long-lived caches. Useful for
    /// timing the cold path or reproducing a transient retrieval.
    /// `progress` opts the request into streaming
    /// [`Response::Progress`] updates emitted at a regular cadence
    /// while the chunk tree is fetched.
    Get {
        reference: String,
        #[serde(default)]
        bypass_cache: bool,
        #[serde(default)]
        progress: bool,
    },
    /// Retrieve a file via the bzz read-path: walks the manifest at
    /// `reference`, resolves `path` (empty triggers `website-index-document`),
    /// then joins the resulting chunk tree into the file's raw bytes.
    /// Daemon answers with [`Response::BzzBytes`].
    ///
    /// `allow_degraded_redundancy`: legacy no-op, kept for protocol
    /// compatibility. Redundancy-encoded files (Reed-Solomon levels
    /// 1–4) are now always decoded with parity-aware geometry and
    /// missing data chunks are recovered from parities automatically.
    /// See [`Request::Get`] for `bypass_cache` and `progress`.
    GetBzz {
        reference: String,
        #[serde(default)]
        path: String,
        #[serde(default)]
        allow_degraded_redundancy: bool,
        #[serde(default)]
        bypass_cache: bool,
        #[serde(default)]
        progress: bool,
    },
    /// Retrieve a multi-chunk raw byte tree by joining its chunk tree.
    /// `reference` points at the root chunk of a `/bytes/` tree. Daemon
    /// answers with [`Response::Bytes`] (no content-type, no manifest
    /// metadata). See [`Request::Get`] for `bypass_cache` and `progress`.
    GetBytes {
        reference: String,
        #[serde(default)]
        bypass_cache: bool,
        #[serde(default)]
        progress: bool,
    },
    /// Create a new upload job for a file at `source_path`. The daemon
    /// reads the file from disk (the control socket is `0o600` and
    /// owned by the same user, so no further auth is needed); the
    /// CLI's job is just to hand over the path. Returns immediately
    /// with [`Response::UploadStarted`] carrying the assigned
    /// `job_id`; the actual splitting + pushsync happens on a daemon
    /// background task whose progress is observable via
    /// [`Request::UploadFollow`].
    ///
    /// `batch_id`: optional per-job postage batch override (32-byte
    /// hex). `None` means "use the daemon's configured default
    /// (`--postage-batch`)".
    /// `name` / `content_type`: Mantaray manifest entry metadata.
    /// `name` defaults to the source file's basename;
    /// `content_type` defaults to `application/octet-stream`.
    /// `raw` skips the trailing single-file mantaray manifest; the
    /// completed job's `reference` is the data root chunk address
    /// itself (a `/bytes/<ref>` reference, not a `/bzz/<ref>` one).
    /// Saves 1-2 chunks of postage and a final round-trip; loses
    /// the embedded filename + content-type, so consumers must
    /// know the type out-of-band. Defaults to `false` so the
    /// reference returned is bzz-compatible.
    UploadStart {
        source_path: String,
        #[serde(default)]
        batch_id: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        content_type: Option<String>,
        #[serde(default)]
        raw: bool,
    },
    /// Snapshot every known upload job (running, paused, completed,
    /// cancelled, failed). Daemon answers with [`Response::UploadList`].
    UploadList,
    /// Snapshot one upload job by id (or by unique 8-hex-char prefix —
    /// the daemon resolves prefixes for ergonomic CLI use). Daemon
    /// answers with [`Response::UploadJob`] or [`Response::Error`].
    UploadStatus { job_id: String },
    /// Soft-stop a running upload. Idempotent on already-paused jobs.
    /// Daemon answers with [`Response::UploadJob`] reflecting the new
    /// state.
    UploadPause { job_id: String },
    /// Bring a paused or failed upload back to running. Spawns a
    /// fresh driver task; the previous driver has already exited.
    UploadResume { job_id: String },
    /// Hard-stop an upload. Already-pushed chunks are left in the
    /// network (Swarm GCs them at postage TTL expiry — there's no
    /// unpush). Idempotent.
    UploadCancel { job_id: String },
    /// Subscribe to live upload progress. Daemon emits zero or more
    /// [`Response::UploadProgress`] frames until the job reaches a
    /// terminal status, then closes with [`Response::UploadJob`]
    /// (the terminal snapshot) and EOF. Multiple followers per job
    /// are supported; each gets its own broadcast.
    UploadFollow { job_id: String },
    /// Snapshot of the daemon's local postage stamp issuer:
    /// theoretical capacity, indices issued so far, per-bucket
    /// fill min/max, and the conservative "worst-case remaining
    /// chunks" budget that bounds the size of the next upload.
    /// Returns [`Response::PostageStatus`]. Pure local read — no
    /// chain RPC. Old daemons reject this with the standard "bad
    /// request" envelope.
    PostageStatus,
    /// Insert a CAC-validated chunk directly into the daemon's
    /// disk chunk cache, without stamping or pushsync. Used by
    /// `antctl pin` to make a previously-uploaded file
    /// retrievable through *this* node's HTTP gateway without
    /// waiting for bee-side neighbourhood replication.
    ///
    /// `wire_hex` is the chunk's full wire bytes (`span (8 LE) ||
    /// payload`, ≤ 8 + 4096 bytes), `0x`-prefixed lowercase hex.
    /// The daemon recomputes the chunk address from the wire
    /// (CAC) and rejects mismatched payloads — callers cannot
    /// poison the disk cache by putting wrong-address bytes.
    ///
    /// Returns [`Response::Ok`] on success; the message carries
    /// the resulting chunk address. Old daemons reject this with
    /// the standard "bad request" envelope.
    PutChunkLocal {
        /// `0x`-prefixed lowercase hex of the chunk wire bytes.
        wire_hex: String,
    },
}

/// Daemon → client response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusSnapshot>),
    Version(VersionInfo),
    /// Generic acknowledgement for commands that have no structured payload
    /// (e.g. `PeersReset`). `message` carries a human-readable summary of
    /// what the daemon did.
    Ok {
        message: String,
    },
    /// Hex-encoded chunk payload returned by [`Request::Get`] /
    /// [`Request::GetBytes`]. Hex (rather than base64 or raw binary) keeps
    /// the wire format newline-delimited JSON for now; we'll revisit when
    /// multi-chunk fetches need streaming.
    Bytes {
        /// `0x`-prefixed lowercase hex of the payload bytes.
        hex: String,
    },
    /// Hex-encoded file payload returned by [`Request::GetBzz`], plus the
    /// `Content-Type` metadata read from the matching mantaray value
    /// node (when the manifest carried one).
    BzzBytes {
        hex: String,
        #[serde(default)]
        content_type: Option<String>,
        /// Best-effort filename derived from the resolved path or
        /// manifest metadata; useful for `antctl get -o`.
        #[serde(default)]
        filename: Option<String>,
    },
    /// Streaming progress emitted by `Get` / `GetBytes` / `GetBzz`
    /// when the client opted in via `progress: true`. May be sent
    /// zero or more times before a terminal `Bytes` / `BzzBytes` /
    /// `Error` reply on the same connection. Clients that didn't ask
    /// for progress will never receive this variant; old clients can
    /// ignore it.
    Progress(GetProgress),
    Error {
        message: String,
    },
    /// Bee `chunkAddressResponse` after `POST /chunks`.
    ChunkUploaded {
        reference: String,
    },
    /// Successful [`Request::UploadStart`]. The daemon has written
    /// the on-disk job manifest and spawned the driver task.
    UploadStarted {
        job_id: String,
    },
    /// Snapshot of one upload job. Returned by `UploadStatus`,
    /// `UploadPause`, `UploadResume`, `UploadCancel`, and as the
    /// terminal frame on a `UploadFollow` connection.
    UploadJob(UploadJobView),
    /// All known upload jobs at the time of the request. Returned
    /// by `UploadList`.
    ///
    /// Wrapped in a struct variant rather than a newtype around the
    /// vec because `#[serde(tag = "result")]` cannot inject the tag
    /// into a JSON array (serde fails with "cannot serialize tagged
    /// newtype variant ... containing a sequence" at runtime). The
    /// extra `jobs` key on the wire is the price of keeping the
    /// outer enum internally tagged.
    UploadList {
        jobs: Vec<UploadJobView>,
    },
    /// Streaming progress frame on a `UploadFollow` connection.
    /// Emitted at most once per state change; old daemons never send
    /// this variant.
    UploadProgress(UploadJobView),
    /// Local postage stamp issuer snapshot. Returned by
    /// [`Request::PostageStatus`].
    PostageStatus(PostageStatusView),
    /// Result of a pullsync viability probe. Returned by
    /// [`Request::PullsyncProbe`].
    PullsyncProbe(PullsyncProbeView),
}

/// Wire shape of one upload job (status snapshot). Mirrors
/// `ant_node::UploadJobInfo` but is defined here so `ant-control`
/// stays free of an `ant-node` dependency.
///
/// Field semantics:
///
/// - `bytes_pushed` / `source_size`: drives the byte progress bar.
/// - `chunks_pushed` / `chunks_total`: drives the chunk progress
///   bar; `chunks_total` is `None` for very-old daemons that
///   didn't pre-compute the estimate.
/// - `reference`: only set once `status == "completed"`; the value
///   is the lowercase `0x`-prefixed mantaray manifest root the
///   uploader would publish (e.g. as a `bzz://` URL). If the job
///   was started with `raw = true`, this is instead the data root
///   chunk address (a `/bytes/<ref>` reference).
/// - `raw`: echoes the request flag so consumers can pick the
///   right URL prefix (`bzz://` vs `bytes://`) without an extra
///   round-trip. Old daemons leave it at the `#[serde(default)]`
///   `false`, matching the historical always-manifest behaviour.
/// - `last_error`: most recent transient or terminal driver error,
///   useful for debugging stalled jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadJobView {
    pub job_id: String,
    pub source_path: String,
    pub source_size: u64,
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub raw: bool,
    pub status: String,
    pub bytes_pushed: u64,
    pub chunks_pushed: u64,
    #[serde(default)]
    pub chunks_total: Option<u64>,
    pub created_at_unix: u64,
    pub last_update_unix: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    /// Cumulative chunk-push retries (observability only; see
    /// `UploadJobInfo::chunks_requeued`). Defaults to `0` so older
    /// daemons / clients keep deserializing.
    #[serde(default)]
    pub chunks_requeued: u64,
    /// `true` while the driver is retrying but making no progress
    /// (sustained transient failure). The job is still alive — this
    /// is a liveness hint, not a terminal status. Defaults to `false`.
    #[serde(default)]
    pub stalled: bool,
    /// `true` when the job was paused by the *system* (an app
    /// suspension / offline transition via `UploadSuspendAll`), not by
    /// the user. Such jobs resume automatically on `UploadWakeAll` or
    /// the next rehydrate, so a client should render them as "Paused —
    /// resumes automatically" rather than offering a Resume button as
    /// the only way forward. Defaults to `false` for older daemons.
    #[serde(default)]
    pub auto_paused: bool,
    /// `true` once the post-upload self-heal confirmed every chunk is
    /// *deep-reachable* (held by its true neighbourhood, not merely
    /// reachable via the uploader's privileged link to a shallow
    /// storer). This is the signal a client should wait for before
    /// telling the user the file is "safe / available everywhere":
    /// `status == "completed"` only means every chunk was pushed once
    /// (some may have landed shallow and not yet propagated). Defaults
    /// to `false` so older daemons / clients keep deserializing.
    #[serde(default)]
    pub heal_verified: bool,
    /// `true` once the post-upload self-heal has finished its rounds for
    /// this job, whether or not it could verify deep reachability
    /// (`heal_verified`). Lets a client waiting on durability stop
    /// waiting on the degraded path (heal ran, re-pushed the shallow
    /// chunks, but the final read-back was still inconclusive) instead
    /// of blocking forever. Defaults to `false`.
    #[serde(default)]
    pub heal_finished: bool,
    /// Chunks the most recent completed securing pass could not confirm
    /// deep-reachable — the residual behind a degraded verdict, so a
    /// client can render "N parts still settling" and watch it shrink
    /// across the automatic retries. Absent on older daemons or when
    /// never measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_missing: Option<u64>,
    /// When the next automatic securing retry becomes eligible (unix
    /// seconds), for a "next check in ~M min" label. Absent while a
    /// pass runs, once verified, and on older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_retry_unix: Option<u64>,
    /// Completed securing passes that ended without verifying —
    /// "Checked N times" evidence that the retry loop is active.
    /// Defaults to `0` on older daemons.
    #[serde(default)]
    pub heal_attempts: u64,
    /// Unix seconds of the most recent completed-but-unverified pass
    /// ("last checked 3 min ago"). Absent on older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_last_check_unix: Option<u64>,
    /// Live post-upload self-heal ("Securing…") progress, surfaced while
    /// the automatic heal runs so a client can draw a *determinate* bar
    /// instead of an indeterminate spinner. `heal_phase` names the current
    /// step — `"checking"` while reading chunks back, `"repushing"` while
    /// re-sending the ones that didn't land; `heal_checked` / `heal_total`
    /// are that step's counts (`heal_checked` of `heal_total`). All three
    /// are absent for a daemon that doesn't report heal progress, for a
    /// step with no determinate count, and once heal finishes (the daemon
    /// clears them), so a client treats "all absent" as "not securing".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_checked: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_total: Option<u64>,
}

/// Snapshot of the daemon's local postage stamp issuer.
///
/// `enabled = false` means the daemon was started without a postage
/// batch (no `--postage-batch` / `STORAGE_STAMP_BATCH_ID`); in that
/// case every other field is at its default and the renderer should
/// label the batch as "uploads disabled". When `enabled = true`:
///
/// - `total_capacity_chunks` is the theoretical ceiling
///   (`2^batch_depth`). Reachable only with perfectly-even chunk
///   routing across buckets — almost never the practical limit.
/// - `worst_case_remaining_chunks` is the conservative budget: room
///   left in the *currently fullest* bucket, scaled to a global
///   count. Use this to decide whether a planned upload of N
///   chunks is guaranteed to fit. For an immutable batch this is
///   the right answer; for a mutable batch the upload still
///   "fits" past this budget, but at the cost of overwriting older
///   stamps (their chunks become un-stampable for resync).
/// - `bucket_fill_min` / `bucket_fill_max` characterise the
///   distribution. A large `max - min` gap signals lopsided
///   routing: usually fine for random uploads, worth investigating
///   if you've been pinning many addresses with a shared prefix.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostageStatusView {
    pub enabled: bool,
    /// `false` while a just-bought batch is still propagating to the
    /// storers (see `ControlCommand::RegisterBatch::bought_at_block`),
    /// and once storer peers have rejected this batch's stamps as
    /// not-on-chain (peer-attested phantom batch: never created on
    /// this chain, expired and evicted, or not yet synced) — the
    /// gateway's `/stamps` must then stop reporting the batch green.
    /// Defaults `true` so old daemons keep deserializing.
    #[serde(default = "default_true")]
    pub usable: bool,
    /// `true` while `usable` is `false` only because a just-bought
    /// batch is still propagating to the storers (not because peers
    /// rejected it). `PushChunk` accepts such a batch and waits the
    /// propagation out, so a pre-flight that applies the push's bar
    /// (the gateway's `/pss/send`) must accept it too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub propagating: bool,
    /// Seconds since the node registered this batch at runtime (a buy
    /// or connect via `RegisterBatch`); `None` for a batch reloaded
    /// from disk or pre-configured at startup. Lets the gateway give a
    /// freshly-bought batch a grace window before believing a chain
    /// read that says it doesn't exist (a load-balanced RPC backend
    /// may lag the block that created it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_secs_ago: Option<u64>,
    /// The block the batch was created in, when the node registered it
    /// right after buying it (the buy receipt's block); `None` for a
    /// batch registered by id, rediscovered, or reloaded from disk.
    /// The gateway reports it as bee's `blockNumber`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// `0x`-prefixed hex of the configured batch id. Empty when
    /// `enabled = false`.
    #[serde(default)]
    pub batch_id: String,
    #[serde(default)]
    pub batch_depth: u8,
    #[serde(default)]
    pub bucket_depth: u8,
    #[serde(default)]
    pub immutable: bool,
    #[serde(default)]
    pub bucket_count: u64,
    #[serde(default)]
    pub bucket_capacity: u32,
    #[serde(default)]
    pub total_capacity_chunks: u64,
    #[serde(default)]
    pub issued_chunks: u64,
    #[serde(default)]
    pub bucket_fill_min: u32,
    #[serde(default)]
    pub bucket_fill_max: u32,
    /// Sum of free indices across all buckets (optimistic budget).
    #[serde(default)]
    pub remaining_total_chunks: u64,
    /// `(bucket_capacity − bucket_fill_max) × bucket_count`.
    /// Pessimistic upper bound on the next upload (see the
    /// type-level doc). 0 when the batch is empty.
    #[serde(default)]
    pub worst_case_remaining_chunks: u64,
}

/// Missing-field default for [`PostageStatusView::usable`].
fn default_true() -> bool {
    true
}

/// Point-in-time snapshot of the node's settlement/balance mirror,
/// acked by `ControlCommand::AccountingSnapshot` and rendered by the
/// gateway's bee-parity read-only endpoints (`/balances`, `/consumed`,
/// `/settlements`, `/timesettlements`, `/chequebook/cheque`).
///
/// Ant is a light client: its accounting state is a *mirror* of what
/// connected bee peers believe, not bee's bidirectional store. The
/// snapshot therefore only carries rows for peers the node can still
/// attribute (connected peers with a known overlay); persisted
/// outbound-cheque totals for peers that are gone are omitted rather
/// than invented.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountingSnapshotView {
    pub peers: Vec<PeerAccountingView>,
    /// PLUR promised in every cheque this node has issued from its
    /// chequebook, for pushsync and retrieval alike (bee's
    /// `totalIssued`, the sum of the outbound ledger's cumulatives),
    /// decimal, for the chequebook in [`Self::cheques_issued_chequebook`].
    /// `None` when outbound settlement has never run in this process, or
    /// when the outbound ledger file can't be read (the total is
    /// unknown). Feeds `/chequebook/balance`'s `availableBalance`.
    #[serde(default)]
    pub cheques_issued_plur: Option<String>,
    /// Chequebook (lowercase hex, no `0x`) whose cheques
    /// `cheques_issued_plur` counts: the running outbound settlement's,
    /// or the last one switched off by `DisablePushsyncSwap`. `None`
    /// when outbound settlement has never run in this process.
    #[serde(default)]
    pub cheques_issued_chequebook: Option<String>,
    /// Set when that chequebook's figures were lost — the outbound
    /// ledger file was unparseable and moved aside, or its pre-section
    /// figures may belong to it (an unparsable fresh-chequebook marker,
    /// or a fresh deploy that couldn't be recorded as such), and no
    /// operator has confirmed the chequebook's outstanding liability
    /// since — saying which and how to clear it. `cheques_issued_plur` then counts only
    /// the cheques issued after the loss, and downloads don't pay from
    /// this chequebook (PR #126 R4-M1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cheques_ledger_lost: Option<String>,
}

impl AccountingSnapshotView {
    /// Every cheque this node has issued from `chequebook`, in PLUR, when
    /// the snapshot knows the full figure, for a withdrawal that must
    /// leave them backed: an error, never a guess, when settlement hasn't
    /// run on `chequebook` in this process (its ledger isn't loaded, so
    /// its cheques aren't counted), the total is another chequebook's,
    /// the ledger is unreadable, or it lost this chequebook's earlier
    /// cheques ([`Self::cheques_ledger_lost`]). Unlike
    /// `/chequebook/balance`'s `availableBalance`, "nothing ran" is not
    /// read as "nothing issued": a ledger on disk may hold cheques.
    ///
    /// # Errors
    ///
    /// A message for the user saying why the total isn't known.
    pub fn issued_from(&self, chequebook: &[u8; 20]) -> Result<u128, String> {
        let ours = hex::encode(chequebook);
        match self.cheques_issued_chequebook.as_deref() {
            None => {
                return Err(format!(
                    "settlement isn't running on chequebook 0x{ours} in this session, so its \
                     issued cheques aren't known"
                ))
            }
            Some(theirs) if !theirs.eq_ignore_ascii_case(&ours) => {
                return Err(format!(
                    "the node's issued-cheques total is for chequebook 0x{theirs}, not 0x{ours}"
                ))
            }
            Some(_) => {}
        }
        if let Some(lost) = &self.cheques_ledger_lost {
            return Err(format!(
                "the node's cheque ledger lost this chequebook's earlier cheques: {lost}"
            ));
        }
        let issued = self
            .cheques_issued_plur
            .as_deref()
            .ok_or_else(|| "the node's outbound cheque ledger is unreadable".to_string())?;
        issued
            .parse()
            .map_err(|_| format!("the node's issued-cheques total {issued:?} is not a number"))
    }
}

/// Result of a `PullsyncProbe` — the GSOC/PSS lurker's underlying
/// operation, and the Exp-1 viability check. Confirms whether a light
/// ant node can drive Swarm's pullsync protocol against a real full-node
/// peer and pull chunks out of a neighborhood bin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PullsyncProbeView {
    /// The peer that was probed (overlay, 64 lowercase hex, no `0x`).
    /// Empty when no connected peer was available.
    pub peer_overlay: String,
    /// The peer's libp2p peer id (base58), for logs.
    pub peer_id: String,
    /// Bin that was pulled.
    pub bin: u8,
    /// Start binID the page was requested from.
    pub start: u64,
    /// Whether the cursor exchange succeeded.
    pub cursors_ok: bool,
    /// The peer's cursor (highest binID) for `bin`, if cursors succeeded.
    pub bin_cursor: u64,
    /// The peer's reserve epoch, if cursors succeeded.
    pub epoch: u64,
    /// Whether the sync page (Get→Offer→Want→Delivery) completed.
    pub sync_ok: bool,
    /// `Offer.Topmost` returned for the page.
    pub topmost: u64,
    /// Number of chunk references the peer offered in the page.
    pub offered: usize,
    /// Number of chunks actually delivered (wanted and received).
    pub delivered: usize,
    /// Wall-clock milliseconds for the cursor exchange.
    pub cursors_ms: u64,
    /// Wall-clock milliseconds for the sync page.
    pub sync_ms: u64,
    /// Non-empty on failure: what went wrong.
    pub error: String,
}

/// Per-peer settlement/balance row. All amounts are non-negative
/// decimal strings in PLUR (bee's accounting unit); `None` means "no
/// record exists" — bee's stores distinguish a missing entry (404 on
/// the per-peer endpoints) from a zero-valued one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerAccountingView {
    /// Peer overlay address, 64 lowercase hex chars (no `0x`) — the
    /// key bee's balances/settlements endpoints use.
    pub peer: String,
    /// Our outstanding retrieval debt toward the peer (what the peer's
    /// accounting believes we owe it). Ant's mirror is one-directional
    /// — the gateway renders bee's sign convention (positive = peer
    /// owes us) by negating this. `None` = no accounting entry.
    #[serde(default)]
    pub debt_to_peer: Option<String>,
    /// Cumulative SWAP (cheque) amount settled *to* the peer — the
    /// outbound ledger's cumulative payout for the peer's beneficiary.
    #[serde(default)]
    pub swap_sent: Option<String>,
    /// Cumulative SWAP amount settled *by* the peer (cheques we
    /// accepted from its chequebook).
    #[serde(default)]
    pub swap_received: Option<String>,
    /// Cumulative pseudosettle (time-based) amount the peer accepted
    /// from our refreshes. Ant never accepts inbound refreshes (its
    /// inbound handler acks zero), so there is no `time_received`.
    #[serde(default)]
    pub time_sent: Option<String>,
    /// Last cheque we issued to the peer (beneficiary = the peer's
    /// EOA, chequebook = ours, payout = cumulative).
    #[serde(default)]
    pub cheque_sent: Option<LastChequeView>,
    /// Last cheque we accepted from the peer (beneficiary = ours,
    /// chequebook = the peer's, payout = highest accepted cumulative).
    #[serde(default)]
    pub cheque_received: Option<LastChequeView>,
}

/// Cheque rendering data for `/chequebook/cheque`. Addresses are 40
/// lowercase hex chars (no `0x`); the gateway EIP-55-checksums them
/// the way Go's `common.Address.String()` does.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LastChequeView {
    pub beneficiary: String,
    pub chequebook: String,
    /// Cumulative payout, decimal string.
    pub payout: String,
}

/// One streaming progress sample for an in-flight `Get*` request.
///
/// All counters are cumulative since the request started. Spans of `0`
/// for `total_*_estimate` mean "not yet known" — the daemon doesn't
/// learn the file size until it has fetched the data root chunk and
/// inspected its 8-byte span prefix, so the first few samples on a
/// large file may report only `chunks_done` / `bytes_done`.
///
/// `in_flight` (added in v3 of this crate) is the only non-cumulative
/// field — it's an instantaneous count of chunk fetches the request
/// has dispatched but not yet seen a delivery for. Old daemons leave
/// it at `0`; a `0` value on a new daemon is also legitimate (cache
/// hits and idle moments).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetProgress {
    /// Wall-clock milliseconds since the daemon accepted the request.
    pub elapsed_ms: u64,
    /// Number of chunks delivered to the joiner so far (cache hits +
    /// successful network fetches).
    pub chunks_done: u64,
    /// Best-effort estimate of total chunks for the request, derived
    /// from the data root's span. `0` until the data root has been
    /// fetched (and for single-chunk files where the root *is* the
    /// data, the first sample carries `chunks_done == 1` and
    /// `total_chunks_estimate == 1`).
    pub total_chunks_estimate: u64,
    /// Bytes of chunk wire data fetched so far (`span (8) || payload`
    /// for each delivered chunk).
    pub bytes_done: u64,
    /// File-body byte count reported by the data root's span. `0`
    /// until known. For `Get` and `GetBytes` this is the file size;
    /// for `GetBzz` it's the size of the resolved file body, not the
    /// manifest.
    pub total_bytes_estimate: u64,
    /// Cache hits served without going to the network. Useful for
    /// distinguishing "fast retrieval from a warm cache" from "fast
    /// retrieval from a single very-close peer".
    pub cache_hits: u64,
    /// Distinct peers we successfully retrieved at least one chunk
    /// from during this request. `0` means everything seen so far
    /// came from cache.
    pub peers_used: u32,
    /// Echoes the request's `bypass_cache` flag so a client that
    /// forgot which mode it asked for can reconcile when rendering.
    pub bypass_cache: bool,
    /// Chunks the request currently has dispatched (acquired the
    /// retrieval semaphore but not yet returned a delivery). Cache
    /// hits don't increment this; an idle stretch reads `0` even on
    /// a healthy connection. Old daemons leave this at the
    /// `#[serde(default)]` zero value.
    #[serde(default)]
    pub in_flight: u32,
}

/// Everything `antctl status` wants to show.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub agent: String,
    pub protocol_version: u32,
    pub network_id: u64,
    pub pid: u32,
    pub started_at_unix: u64,
    pub identity: IdentityInfo,
    pub peers: PeerInfo,
    pub listeners: Vec<String>,
    /// Externally-advertised multiaddrs the daemon has registered with
    /// libp2p-identify, with the source that produced each one
    /// (operator-supplied, listener auto-promotion, observed-from-peer,
    /// or `UPnP`). Older daemons leave this at the `#[serde(default)]`
    /// empty value; new clients should fall back to `listeners` when it
    /// is empty. Order is insertion-stable so the UI can show a
    /// deterministic history.
    #[serde(default)]
    pub external_addresses: Vec<ExternalAddressInfo>,
    pub control_socket: String,
    /// Data-plane snapshot: chunk cache fill, in-flight retrievals,
    /// cumulative download counters, and the list of currently active
    /// gateway HTTP requests. Populated by the daemon on every status
    /// update; surfaced as the `Retrieval` tab in `antop`. Old
    /// daemons leave this at the `#[serde(default)]` zero value.
    #[serde(default)]
    pub retrieval: RetrievalInfo,
    /// Whether the daemon's startup chain init (postage batch
    /// validation/rediscovery, chequebook resolution) has resolved.
    /// `false` during the first seconds of an `antd` start: the swarm
    /// loop and control socket come up before the Gnosis reads
    /// complete, so `antop` can watch the peer-set ramp live.
    /// Upload-affecting commands answer "not configured" until this
    /// flips — scripts should poll it, not the socket's existence, as
    /// the readiness signal. Old daemons never send the field (they
    /// opened the socket only after chain init), so the missing-field
    /// default is `true`.
    #[serde(default = "chain_ready_missing_default")]
    pub chain_ready: bool,
    /// The node's SWAP settlement switch and whether it pays (issues
    /// #121, #127). Published by the node loop whenever the switch, the
    /// chequebook or its funds change. Old daemons leave this at the
    /// `#[serde(default)]` value.
    #[serde(default)]
    pub settlement: SettlementInfo,
}

/// Node-wide SWAP settlement state: bee's `swap-enable` switch, read by
/// the gateway's `GET /node` and `GET /v0/settlement/swap` and by
/// ant-ffi's `ant_swap_status`, so hosts needn't probe for support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementInfo {
    /// Bee's `swap-enable`: SWAP cheques may pay peers, for downloads and
    /// uploads alike. Changed at runtime by `SetSwapEnabled`
    /// (`PUT /v0/settlement/swap`, `ant_set_swap_enabled`, the control
    /// socket).
    pub swap_enabled: bool,
    /// The chequebook outbound settlement runs on (`0x` + 40 hex), if
    /// any.
    #[serde(default)]
    pub chequebook: Option<String>,
    /// Cheques are being paid now: the switch is on and the chequebook
    /// has funds the node has read from the chain and not yet spent, with
    /// its cheque ledger known. `false` means the free pseudosettle tier.
    #[serde(default)]
    pub paying: bool,
    /// xBZZ deposited into the chequebook and not withdrawn, in PLUR
    /// (decimal), as the node last read it from the chain (re-read every
    /// minute). `None` until funds have been read.
    #[serde(default)]
    pub deposited_plur: Option<String>,
    /// Every cheque this node has issued from the chequebook, in PLUR
    /// (decimal): the outbound ledger's lifetime total, current with each
    /// cheque. `None` without a chequebook.
    #[serde(default)]
    pub issued_plur: Option<String>,
    /// What the chequebook can still put into cheques, in PLUR (decimal):
    /// `deposited_plur` less `issued_plur` (bee's `availableBalance`),
    /// with no chain read. `None` until funds have been read.
    #[serde(default)]
    pub available_plur: Option<String>,
}

impl Default for SettlementInfo {
    fn default() -> Self {
        Self {
            swap_enabled: true,
            chequebook: None,
            paying: false,
            deposited_plur: None,
            issued_plur: None,
            available_plur: None,
        }
    }
}

/// Missing-field default for [`StatusSnapshot::chain_ready`]: a daemon
/// old enough not to send it was always chain-ready by construction.
fn chain_ready_missing_default() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub eth_address: String,
    pub overlay: String,
    pub peer_id: String,
}

/// One externally-advertised multiaddr, with metadata about how the
/// daemon learned it. UIs typically render the `source` column verbatim
/// so operators can tell at a glance whether their address came from a
/// CLI flag, listener auto-promotion, a peer's identify push, or the
/// `UPnP` behaviour talking to a home router.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalAddressInfo {
    /// Multiaddr we advertise via libp2p-identify (e.g.
    /// `/ip4/203.0.113.42/tcp/1634`).
    pub addr: String,
    /// Free-form source identifier. Stable values produced by `antd`:
    /// `manual` (`--external-address`), `listener` (auto-promoted
    /// non-loopback listener), `observed` (from a remote's identify
    /// `observed_addr`), `upnp` (mapped via libp2p-upnp / IGD). Future
    /// daemons may add new sources, so UIs should treat unknown values
    /// as opaque labels.
    pub source: String,
    /// Wall-clock unix timestamp at which the address was registered.
    /// Useful for "added 12 s ago" rendering.
    pub added_at_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Connected peers that answer pings: `connected_peers` minus the
    /// rows marked [`PeerConnectionInfo::stale`]. This is what
    /// `ant_peer_count` reports.
    pub connected: u32,
    #[serde(default)]
    pub node_limit: u32,
    #[serde(default)]
    pub connected_peers: Vec<PeerConnectionInfo>,
    /// Unified peer rows for UIs (e.g. `antop`); includes dialing / pipeline
    /// states not present in `connected_peers` alone. Empty on older daemons.
    #[serde(default)]
    pub peer_pipeline: Vec<PeerPipelineEntry>,
    pub last_handshake: Option<HandshakeReport>,
    /// Monotonic time from process start to first BZZ peer (seconds, e.g. for `antop`).
    #[serde(default)]
    pub time_to_first_peer_s: Option<f64>,
    /// Monotonic time from process start to reaching `node_limit` BZZ peers.
    #[serde(default)]
    pub time_to_node_limit_s: Option<f64>,
    /// Forwarding-Kademlia routing table summary (per-bin peer counts).
    /// Empty `bins` on older daemons.
    #[serde(default)]
    pub routing: RoutingInfo,
}

impl PeerInfo {
    /// The [`Self::connected`] figure for `connected_peers`: rows not
    /// marked stale.
    #[must_use]
    pub fn live_connected_count(connected_peers: &[PeerConnectionInfo]) -> u32 {
        u32::try_from(connected_peers.iter().filter(|p| !p.stale).count()).unwrap_or(u32::MAX)
    }

    /// The node has a peer it can serve retrievals through: a routing-table
    /// peer that answers pings and isn't a bootnode on its way out
    /// ([`RoutingInfo::serving`]). What `/readiness` reports (#78). Not
    /// `connected`, which also counts libp2p connections still in the BZZ
    /// handshake, and not the routing table's `size`: a cold node's first
    /// handshaked peer is always a bootnode, which resets the connection
    /// within milliseconds and never serves a chunk.
    #[must_use]
    pub fn can_retrieve(&self) -> bool {
        self.routing.serving > 0
    }
}

/// Snapshot of the forwarding-Kademlia routing table: how many BZZ peers
/// we currently have, indexed by proximity order to our overlay. `bins[i]`
/// is the count of peers in PO bin `i` (0 = farthest, 31 = closest).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingInfo {
    /// Local Swarm overlay as a `0x`-prefixed hex string. Empty when the
    /// daemon has no peers and hasn't computed it yet.
    #[serde(default)]
    pub base_overlay: String,
    /// Total entries in the routing table (== number of connected BZZ
    /// peers we have).
    #[serde(default)]
    pub size: u32,
    /// Per-bin connected peer counts. Always 32 elements when populated.
    #[serde(default)]
    pub bins: Vec<u32>,
    /// Routing-table peers the node can serve retrievals through: every
    /// entry except one whose connection stopped answering pings (stale,
    /// #83) and a bootnode that joined less than a few seconds ago.
    /// Mainnet bootnodes hand out their peer list and reset the
    /// connection within milliseconds of the handshake (bee's bootnode
    /// mode), and bee never sends a protocol request to a bootnode
    /// anyway (`topology.Select.IncludeBootnodes`). A bootnode that stays
    /// connected — a private network's only node — counts after the
    /// grace. `/readiness` is `serving > 0`. Zero on older daemons.
    #[serde(default)]
    pub serving: u32,
    /// Total known peers (connected + hive-discovered-but-unconnected),
    /// deduped by overlay. Always `>= size`. Zero on older daemons that
    /// didn't track a known-peer book.
    #[serde(default)]
    pub known_size: u32,
    /// Per-bin known-peer counts (connected + discovered). Always 32
    /// elements when populated; empty on older daemons. bee-shaped
    /// clients read "visible peers" as `sum(known_bins)`.
    #[serde(default)]
    pub known_bins: Vec<u32>,
}

/// Connection / pipeline state for a peer, aligned with the daemon’s swarm view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PeerConnectionState {
    #[default]
    Ready,
    Dialing,
    Identifying,
    Handshaking,
    Failed,
    Closing,
}

/// One row in `PeerInfo::peer_pipeline` (full `peer_id`; clients may shorten for display).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPipelineEntry {
    pub peer_id: String,
    pub state: PeerConnectionState,
    /// Best-effort remote endpoint for UI (e.g. `192.0.2.1` or a DNS name).
    #[serde(default)]
    pub ip: String,
    /// Wall-clock milliseconds from the first dial attempt (or, for inbound
    /// peers, from `ConnectionEstablished`) to the moment the BZZ handshake
    /// completed and the peer entered `Ready`. `None` for peers that
    /// haven't reached `Ready` yet, and for peers tracked by older
    /// daemons that didn't record this. Reset on disconnect, so a
    /// reconnect produces a fresh measurement.
    #[serde(default)]
    pub ready_in_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerConnectionInfo {
    pub peer_id: String,
    pub direction: String,
    pub address: String,
    pub connected_at_unix: u64,
    #[serde(default)]
    pub agent_version: String,
    #[serde(default)]
    pub bzz_overlay: Option<String>,
    #[serde(default)]
    pub full_node: Option<bool>,
    #[serde(default)]
    pub last_bzz_at_unix: Option<u64>,
    /// The connection hasn't answered a ping within the liveness window
    /// (issue #83): most likely a dead socket the node is about to close.
    /// Not counted in [`PeerInfo::connected`]. `false` on older daemons.
    #[serde(default)]
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeReport {
    pub remote_overlay: String,
    pub remote_peer_id: String,
    pub agent_version: String,
    pub full_node: bool,
    pub at_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionInfo {
    pub agent: String,
    pub protocol_version: u32,
}

/// Snapshot of the in-memory chunk cache.
///
/// `capacity` reflects `ant_retrieval::DEFAULT_CACHE_CAPACITY` (or
/// whatever the daemon was configured with) and is constant for the
/// lifetime of the process; `used` is the live LRU fill, refreshed
/// on every status tick.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct CacheInfo {
    pub used: u32,
    pub capacity: u32,
}

/// Snapshot of the persistent (SQLite-backed) chunk cache.
///
/// All-zero / `enabled = false` when the daemon was started with
/// `--no-disk-cache` (or with no disk cache wired up at all). Sizes
/// are tracked in *bytes* — unlike the in-memory tier the disk
/// cache's eviction key is total bytes, not slot count, so the row
/// count is informational and the byte total is what drives the
/// "fullness" gauge in `antop`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskCacheInfo {
    /// Whether the daemon has a persistent cache attached. When
    /// `false`, every other field is zero / empty and `antop` should
    /// label the row as `disabled` rather than render
    /// `0/0 (0.0%)`.
    pub enabled: bool,
    /// Live byte total mirrored from `SUM(size)`. May lag by a
    /// single in-flight write but never diverges by more than one
    /// chunk.
    pub used_bytes: u64,
    /// Configured hard cap (`--disk-cache-max-gb` × 1 GiB).
    pub capacity_bytes: u64,
    /// Cumulative tier-2 hits since process start. A subset of
    /// `RetrievalInfo::chunks_fetched_total` and disjoint from
    /// `mem_hits_total` — a chunk that lifts from disk into memory
    /// counts toward `disk_hits_total` only on the lifting fetch;
    /// subsequent fetches from the warm in-memory entry count toward
    /// `mem_hits_total`.
    pub hits_total: u64,
    /// Live row count mirrored from `COUNT(*) FROM chunks`. Combined
    /// with `used_bytes` this exposes the on-disk mean chunk size
    /// (useful for sanity-checking against the 4 KiB BMT chunk size).
    /// Reports `0` for the ~30 s after a cold start while the backfill
    /// `COUNT(*)` is still running — see `DiskChunkCache::open` for
    /// why we don't block startup on that scan.
    #[serde(default)]
    pub chunks: u64,
    /// Absolute on-disk path of the `chunks.sqlite` file. Empty when
    /// `enabled = false`. Surfaced so `antop` operators don't have to
    /// guess between the default `~/.antd/chunks.sqlite` and whatever
    /// `--disk-cache-path` the daemon was started with.
    #[serde(default)]
    pub path: String,
    /// Number of dedicated read-worker threads servicing `get`
    /// requests. Reported so an operator can correlate sustained
    /// retrieval queue depth against the worker pool size without
    /// digging into the binary.
    #[serde(default)]
    pub read_workers: u32,
    /// Bytes of pinned chunks, held outside `capacity_bytes` (and not
    /// part of `used_bytes`).
    #[serde(default)]
    pub pinned_bytes: u64,
    /// Number of pinned chunks (included in `chunks`).
    #[serde(default)]
    pub pinned_chunks: u64,
    /// Number of pinned root references.
    #[serde(default)]
    pub pin_collections: u64,
    /// Pin members summed per collection (a chunk shared by two pins
    /// counts twice) — bee's `/debugstore` `Pinning.TotalChunks`.
    #[serde(default)]
    pub pin_member_chunks: u64,
}

/// Data-plane snapshot read by the `Retrieval` tab in `antop`.
///
/// All numeric fields are cumulative since process start except
/// `cache.used`, `in_flight`, and the per-request entries in
/// `gateway_requests`, which are instantaneous. Bandwidth is *not*
/// reported as a derived rate here — the daemon publishes raw
/// cumulative `bytes_fetched_total` and `chunks_fetched_total`, and
/// the consumer (`antop`) computes whatever smoothing /
/// peak-tracking it wants from successive snapshots. That keeps the
/// daemon free of UI-tier policy and makes the rate trivially
/// reproducible from the wire log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetrievalInfo {
    pub cache: CacheInfo,
    /// Chunk fetches the daemon currently has on the wire across all
    /// in-flight requests (sum of `RoutingFetcher::FuturesUnordered`
    /// pools that are past their semaphore acquire). Bounded above by
    /// `in_flight_capacity`.
    pub in_flight: u32,
    /// Process-wide cap on concurrent retrievals
    /// (`RETRIEVAL_INFLIGHT_CAP` in `ant-p2p`).
    pub in_flight_capacity: u32,
    /// Cumulative chunk count delivered to joiners since process
    /// start. Includes both network deliveries and cache hits.
    pub chunks_fetched_total: u64,
    /// Cumulative wire bytes (`span (8) || payload`) delivered to
    /// joiners. Used by `antop` to compute instantaneous
    /// bandwidth as `(b2 - b1) / dt`.
    pub bytes_fetched_total: u64,
    /// Cumulative cache hits (subset of `chunks_fetched_total`).
    /// Equal to `mem_hits_total + disk_hits_total`; kept on the
    /// snapshot for backward compatibility with consumers that
    /// don't yet split memory and disk hits.
    pub cache_hits_total: u64,
    /// Cumulative tier-1 (in-memory LRU) hits. Disjoint from
    /// `disk_hits_total`.
    #[serde(default)]
    pub mem_hits_total: u64,
    /// Persistent (`SQLite`) chunk-cache snapshot. `enabled = false`
    /// when the daemon was started without a disk cache.
    #[serde(default)]
    pub disk: DiskCacheInfo,
    /// Snapshot of currently-active gateway HTTP requests. Empty when
    /// the gateway is idle or disabled.
    #[serde(default)]
    pub gateway_requests: Vec<GatewayRequestInfo>,
}

/// One in-flight gateway request as surfaced by `StatusSnapshot::retrieval`.
///
/// `path` is a short human-readable label — usually `<short_ref>` for
/// `/bytes` and `/chunks` and `<short_ref>/<path>` for `/bzz`. The
/// daemon truncates the reference to its leading 8 hex chars to keep
/// the table column width sane in `antop`; clients that need the
/// full reference can correlate via the gateway access log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequestInfo {
    pub kind: GatewayRequestKind,
    pub path: String,
    pub started_at_unix: u64,
    /// Chunks delivered to the joiner so far for this request (network +
    /// cache). `0` until the first chunk lands; common for fresh
    /// requests where the root hasn't been fetched yet.
    pub chunks_done: u64,
    /// Best-effort total derived from the data root's span. `0` until
    /// the daemon has fetched the root chunk.
    pub total_chunks_estimate: u64,
    /// Live count of chunk fetches the request has dispatched but not
    /// yet seen a delivery for. Mirrors
    /// [`GetProgress::in_flight`] for this request.
    pub chunks_in_flight: u32,
    pub bytes_done: u64,
}

/// Coarse classification of the gateway endpoint so `antop` can
/// label each row. Mapped from the axum handler that registered the
/// active request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayRequestKind {
    /// `GET/HEAD /bytes/{addr}` — raw chunk-tree streaming.
    Bytes,
    /// `GET/HEAD /bzz/{addr}` or `/bzz/{addr}/{path}` — manifest-aware
    /// streaming.
    Bzz,
    /// `GET/HEAD /chunks/{addr}` — single-chunk wire fetch.
    Chunk,
    /// `GET/HEAD/POST /soc/{owner}/{id}` — single-owner-chunk wire
    /// fetch or upload. Distinct from [`Self::Chunk`] so operators can
    /// tell SOC traffic apart from CAC traffic in `antctl top`.
    Soc,
    /// `GET /feeds/{owner}/{topic}` — sequence-feed resolution.
    Feed,
    /// `GET /v0/manifest/{addr}[/{prefix}]` — Ant-specific manifest
    /// listing (bee#5535 shape).
    Manifest,
}

impl GatewayRequestKind {
    /// Short label shown in the `antop` Retrieval tab. Up to 5
    /// ASCII characters so the table's `Kind` column stays narrow
    /// while still being self-explanatory: each label is the bee /
    /// Ant endpoint name (`/bytes`, `/bzz`, `/chunks`, `/soc`,
    /// `/feeds`, `/v0/manifest`) either spelled in full or trimmed
    /// to the same root.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bytes => "Bytes",
            Self::Bzz => "BZZ",
            Self::Chunk => "Chunk",
            Self::Soc => "SOC",
            Self::Feed => "Feed",
            Self::Manifest => "Manif",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A withdrawal only trusts a complete issued total for its own
    /// chequebook; "settlement never ran" is unknown, not zero.
    #[test]
    fn issued_from_needs_the_full_figure_for_this_chequebook() {
        let cb = [0xab; 20];
        let view = |chequebook: Option<&str>, issued: Option<&str>, lost: Option<&str>| {
            AccountingSnapshotView {
                peers: Vec::new(),
                cheques_issued_plur: issued.map(str::to_string),
                cheques_issued_chequebook: chequebook.map(str::to_string),
                cheques_ledger_lost: lost.map(str::to_string),
            }
        };
        let ours = hex::encode(cb);
        assert_eq!(
            view(Some(&ours), Some("1200"), None).issued_from(&cb),
            Ok(1200)
        );
        assert_eq!(
            view(Some(&ours.to_uppercase()), Some("0"), None).issued_from(&cb),
            Ok(0)
        );
        let other = "cd".repeat(20);
        let unknown: [(Option<&str>, Option<&str>, Option<&str>); 6] = [
            (None, None, None),
            (None, Some("5"), None),
            (Some(&other), Some("5"), None),
            (Some(&ours), None, None),
            (Some(&ours), Some("5"), Some("moved aside")),
            (Some(&ours), Some("x"), None),
        ];
        for (chequebook, issued, lost) in unknown {
            assert!(
                view(chequebook, issued, lost).issued_from(&cb).is_err(),
                "{chequebook:?} {issued:?} {lost:?}"
            );
        }
    }

    /// `can_retrieve` (what `/readiness` reports, #78) follows the routing
    /// table's serving peers only: open libp2p connections (a bootnode
    /// mid-handshake, a handshaked row whose peer left the table) and a
    /// routing table holding just a bootnode don't make a node ready.
    #[test]
    fn can_retrieve_follows_the_routing_table_not_connections() {
        let mut peers = PeerInfo {
            connected: 2,
            connected_peers: vec![PeerConnectionInfo {
                peer_id: "12D3KooWBootnode".into(),
                bzz_overlay: Some(format!("0x{}", "ab".repeat(32))),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(!peers.can_retrieve(), "connections alone are not readiness");
        // A bootnode in the routing table: in it, but not serving.
        peers.routing.size = 1;
        assert!(!peers.can_retrieve(), "a bootnode alone is not readiness");
        peers.routing.serving = 1;
        assert!(peers.can_retrieve());
    }

    /// Catch the "tagged newtype variant containing a sequence" trap
    /// before it reaches a live socket: serde's internally-tagged enum
    /// representation cannot inject the discriminator field into a
    /// JSON array, so any `Response::Foo(Vec<_>)` newtype variant
    /// panics at the first write. Round-tripping every collection-
    /// shaped variant here keeps the wire format honest.
    #[test]
    fn response_upload_list_roundtrips() {
        let view = UploadJobView {
            job_id: "deadbeef".into(),
            source_path: "/tmp/x".into(),
            source_size: 1,
            batch_id: None,
            name: None,
            content_type: None,
            raw: false,
            status: "running".into(),
            bytes_pushed: 0,
            chunks_pushed: 0,
            chunks_total: None,
            created_at_unix: 0,
            last_update_unix: 0,
            last_error: None,
            reference: None,
            chunks_requeued: 0,
            stalled: false,
            auto_paused: false,
            heal_verified: false,
            heal_finished: false,
            heal_missing: None,
            heal_retry_unix: None,
            heal_attempts: 0,
            heal_last_check_unix: None,
            heal_phase: None,
            heal_checked: None,
            heal_total: None,
        };
        for jobs in [Vec::new(), vec![view]] {
            let resp = Response::UploadList { jobs: jobs.clone() };
            let wire = serde_json::to_string(&resp).expect("serialize");
            assert!(wire.contains("\"result\":\"upload_list\""), "{wire}");
            let back: Response = serde_json::from_str(&wire).expect("deserialize");
            match back {
                Response::UploadList { jobs: round } => {
                    assert_eq!(round.len(), jobs.len());
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }
}
