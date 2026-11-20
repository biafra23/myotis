//! On-disk state for an in-flight or completed upload job.
//!
//! Each job is one `<job_id>.json` under `<data-dir>/uploads/`. The
//! manager rewrites the file atomically (tmp → fsync → rename) on every
//! checkpoint so a crash mid-write can never produce a half-readable
//! manifest. This is the same idiom `ant_postage::StampIssuer` uses for
//! its bucket counters.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Lifecycle status of an upload job.
///
/// State machine:
///
/// ```text
///   pending ─► running ─► completed
///                │  ▲
///                ▼  │
///              paused
///                │
///                ▼
///             cancelled / failed
/// ```
///
/// `Failed` is the terminal-error state and carries the last error
/// message. `Cancelled` is operator-initiated. Both are kept on disk
/// so `antctl upload list` can show recent history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadStatus {
    /// Job manifest written but the driver task hasn't yet
    /// dispatched its first chunk. Transient: callers will rarely
    /// observe this directly because `start` returns after the first
    /// status flush.
    Pending,
    /// Driver task is actively dispatching pushsyncs.
    Running,
    /// Operator-initiated soft stop. The driver has drained
    /// in-flight pushes and parked on a notify; `resume` brings it
    /// back to `Running`.
    Paused,
    /// All data + manifest chunks pushed. `reference` carries the
    /// manifest root.
    Completed,
    /// Operator-initiated hard stop. Already-pushed chunks are left
    /// in the network (Swarm will GC them when the postage TTL
    /// expires; we can't unpush).
    Cancelled,
    /// Driver hit an unrecoverable error. `last_error` carries the
    /// message. Operator can inspect, then either `cancel` (to clean
    /// up) or `resume` (to retry from the last checkpoint).
    Failed,
}

impl UploadStatus {
    /// Status implies the driver should stop holding resources.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

/// Persistent + live job state. The same struct serialises to disk
/// (manifest at `<data-dir>/uploads/<job_id>.json`) and to the wire
/// (`Response::UploadJob` from the control socket), so adding a field
/// only requires `#[serde(default)]` for backward compatibility with
/// older daemons / clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadJobInfo {
    /// 16-hex-char identifier, opaque to the operator. Stable across
    /// restarts.
    pub job_id: String,
    /// Absolute path to the source file on the daemon's filesystem.
    /// The daemon mmaps this — it must stay in place and unchanged
    /// for the upload's life. Resume refuses if the size or mtime
    /// changed.
    pub source_path: PathBuf,
    /// Path of the source relative to the manager's configured
    /// `source_root`, recorded at job creation when the source lives
    /// under that root. iOS relocates the whole app container (new
    /// UUID) on updates/reinstalls, which strands the absolute
    /// `source_path`; on rehydrate the manager re-anchors it as
    /// `source_root/source_rel` (guarded by a size+mtime match) so the
    /// job survives the move. `None` for sources outside the root and
    /// for daemons without a root (`antd`) — their behaviour is
    /// unchanged.
    #[serde(default)]
    pub source_rel: Option<PathBuf>,
    /// File body size in bytes at job creation. Cross-checked
    /// against the live `metadata().len()` on resume.
    pub source_size: u64,
    /// Source file's modification time at job creation, in
    /// milliseconds since the Unix epoch. Resume refuses on
    /// mismatch.
    pub source_mtime_unix_ms: u64,
    /// Optional postage batch override. `None` ⇒ use the daemon's
    /// configured default (`--postage-batch`).
    #[serde(default)]
    pub batch_id: Option<String>,
    /// Filename to use inside the single-file mantaray manifest.
    /// Defaults to the source file's basename.
    #[serde(default)]
    pub name: Option<String>,
    /// Optional content-type metadata for the manifest entry.
    /// Defaults to `application/octet-stream` (matches bee).
    #[serde(default)]
    pub content_type: Option<String>,
    /// When `true`, the driver skips the trailing single-file
    /// mantaray manifest and finishes with `reference` set to the
    /// data root chunk address (a `/bytes/<ref>` reference). When
    /// `false` (the default — and the value old persisted
    /// manifests get via `#[serde(default)]`), the original
    /// always-wrap-in-manifest behaviour applies.
    #[serde(default)]
    pub raw: bool,
    /// Lifecycle.
    pub status: UploadStatus,
    /// Cumulative source bytes whose covering leaf has been
    /// successfully pushed. Equal to `chunks_pushed × CHUNK_SIZE`
    /// for the in-progress prefix; `source_size` once complete.
    /// Used by the progress UI for the byte progress bar.
    pub bytes_pushed: u64,
    /// Cumulative chunks (leaves + intermediates + manifest)
    /// successfully pushed. Used as the resume cursor: on restart
    /// the driver re-streams from byte 0, recomputes every chunk
    /// address (deterministic by construction), and skips pushsync
    /// for the first `chunks_pushed` of them.
    pub chunks_pushed: u64,
    /// Best-effort estimate of total chunks (data + intermediates +
    /// manifest). Computed at job start from `source_size`. `None`
    /// for very-old persisted jobs that didn't record it.
    #[serde(default)]
    pub chunks_total: Option<u64>,
    /// Wall-clock unix seconds at `start`.
    pub created_at_unix: u64,
    /// Wall-clock unix seconds of the last status mutation. Updated
    /// on every checkpoint flush so `antctl upload list` can show
    /// "last seen 12 s ago".
    pub last_update_unix: u64,
    /// Most recent driver error (transient or terminal). Cleared on
    /// `resume`; preserved on `pause`.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Final manifest root reference (`0x` + 64 hex). Set once
    /// `status` flips to `Completed`.
    #[serde(default)]
    pub reference: Option<String>,
    /// Set once the post-upload self-heal confirmed every chunk is
    /// deep-reachable (held by its true neighbourhood, not merely
    /// reachable from the uploader's privileged link to a shallow
    /// storer). Startup re-runs the deep heal for any `Completed` job
    /// where this is still `false`, so files uploaded before the
    /// deep-push fix — or whose final read-back was inconclusive —
    /// self-repair on the next launch. Defaults to `false` for jobs
    /// persisted by older daemons.
    #[serde(default)]
    pub heal_verified: bool,
    /// Cumulative count of chunk-push retries this job has issued
    /// (observability only — never a kill switch). Bee-style "slow,
    /// never fail" means a chunk is re-pushed indefinitely under
    /// transient peer churn; this counter lets an operator see *how
    /// hard* a job is fighting the network without changing its
    /// terminal outcome. Defaults to `0` for older persisted jobs.
    #[serde(default)]
    pub chunks_requeued: u64,
    /// Liveness sub-state surfaced to watchers (CLI / iOS follow
    /// stream) while the driver keeps retrying a struggling upload.
    /// `true` means no chunk has acked for a sustained window (the
    /// network is effectively down for us) — the job is *not* failed,
    /// just not progressing. Cleared the moment a chunk acks again.
    /// Never persisted as a terminal state; defaults to `false`.
    #[serde(default)]
    pub stalled: bool,
    /// `true` when the current `Paused` state was imposed by the
    /// *system* ([`UploadManager::suspend_all`] — app backgrounded /
    /// network gone), not by the user. Wake (`wake_all`) and rehydrate
    /// auto-resume only these; a user-paused job stays paused until the
    /// user says otherwise. Cleared on any resume and on a user pause.
    /// Persisted so the distinction survives a relaunch. Defaults to
    /// `false` for jobs persisted by older daemons.
    #[serde(default)]
    pub auto_paused: bool,
    /// Set once the post-upload self-heal has run its rounds for this
    /// job (whether or not it could confirm `heal_verified`). Lets a
    /// durability-waiting client distinguish "heal still in progress"
    /// from "heal done — verified, or done its best on a degraded
    /// network". Defaults to `false` for jobs persisted by older
    /// daemons; a manual "Push again" refreshes it.
    #[serde(default)]
    pub heal_finished: bool,
    /// Chunks the most recent *completed* securing pass could not
    /// confirm deep-reachable — the honest residual behind a degraded
    /// verdict, so a client can show "N parts still settling" (and
    /// watch it shrink across automatic retries) instead of a bare
    /// warning. Persisted so the figure survives a relaunch; cleared
    /// when a pass finally verifies. `None` = never measured (older
    /// jobs, or heal skipped).
    #[serde(default)]
    pub heal_missing: Option<u64>,
    /// Completed securing passes that ended *without* verifying —
    /// "Checked N times" evidence for the UI that the automatic retry
    /// loop really is working the file between visible passes.
    /// Persisted; stops mattering (and stops being shown) once the job
    /// verifies.
    #[serde(default)]
    pub heal_attempts: u64,
    /// Unix seconds of the most recent completed-but-unverified
    /// securing pass ("last checked 3 min ago"). Persisted alongside
    /// `heal_attempts`.
    #[serde(default)]
    pub heal_last_check_unix: Option<u64>,
    /// When the next *automatic* securing retry for a degraded job
    /// becomes eligible (unix seconds) — the manager's retry ticker
    /// re-queues the pass at roughly this time, so a client can render
    /// "next check in ~M min". Runtime-only (`skip_serializing`): a
    /// relaunch retries immediately, making a persisted value stale by
    /// construction.
    #[serde(default, skip_serializing)]
    pub heal_retry_unix: Option<u64>,
    /// Live "Securing…" (post-upload self-heal) progress, surfaced to
    /// watchers while the automatic heal runs so the app can draw a
    /// determinate bar. `heal_phase` is the current step (`"checking"` /
    /// `"repushing"`); `heal_checked` of `heal_total` is that step's count.
    /// Transient/runtime-only — `skip_serializing` keeps it out of the
    /// persisted manifest (a reloaded job re-derives it when heal re-runs),
    /// and the heal clears all three the moment it finishes.
    #[serde(default, skip_serializing)]
    pub heal_phase: Option<String>,
    #[serde(default, skip_serializing)]
    pub heal_checked: Option<u64>,
    #[serde(default, skip_serializing)]
    pub heal_total: Option<u64>,
}

impl UploadJobInfo {
    /// Path of the on-disk manifest for `state_dir/<job_id>.json`.
    #[must_use]
    pub fn manifest_path(state_dir: &Path, job_id: &str) -> PathBuf {
        state_dir.join(format!("{job_id}.json"))
    }

    /// Read a persisted manifest from disk. Returns `Err` for I/O
    /// failures; an empty / missing file maps to `Err`. Callers can
    /// treat `NotFound` as "job not found" and surface it to the
    /// client.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Crash-safe write: write to `<path>.tmp`, fsync, rename over
    /// `<path>`, then best-effort fsync the directory so the rename
    /// is durable across a power loss.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}
