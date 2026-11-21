//! Blocking std-only client for `antctl`. No tokio runtime needed.

use crate::protocol::{GetProgress, Request, Response, UploadJobView};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("connect {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("empty response from daemon")]
    EmptyResponse,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Tree-walking requests (`GetBytes`, `GetBzz`) can require many serial
/// chunk fetches; mirror the daemon-side `TREE_COMMAND_TIMEOUT` plus a
/// little headroom so the client doesn't bail before the daemon does.
const TREE_TIMEOUT: Duration = Duration::from_secs(75);
/// Probe budget: the daemon dispatches `PullsyncProbe` under its 20 s
/// `NETWORK_COMMAND_TIMEOUT` and the probe task self-bounds below that,
/// so the client only needs to outlast the daemon by a little — not the
/// old 75 s tree budget, which left a 55 s window where the daemon had
/// long given up but the client still sat waiting.
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);

const fn timeout_for(request: &Request) -> Duration {
    match request {
        Request::GetBytes { .. } | Request::GetBzz { .. } | Request::UploadFollow { .. } => {
            TREE_TIMEOUT
        }
        Request::PullsyncProbe { .. } => PROBE_TIMEOUT,
        _ => DEFAULT_TIMEOUT,
    }
}

/// Did this request opt into streaming `Progress` updates? Streaming
/// reads need a more lenient per-line read timeout (the gap between
/// progress samples is what the timer measures, not the total request
/// wall time), so we hand the daemon's tree timeout to the underlying
/// stream regardless of whether progress was actually requested.
const fn is_streamable(request: &Request) -> bool {
    matches!(
        request,
        Request::GetBytes { .. } | Request::GetBzz { .. } | Request::UploadFollow { .. },
    )
}

/// Round-trip one request to the daemon and return its terminal response.
///
/// Any streaming `Progress` updates the daemon emits before the terminal
/// response are silently dropped; callers that want to render them
/// should use [`request_streaming`] instead.
pub fn request_sync(socket_path: &Path, request: &Request) -> Result<Response, ClientError> {
    request_streaming(socket_path, request, |_| {})
}

/// One streaming event from the daemon. `Progress` is delivered to the
/// `on_progress` callback in [`request_streaming`]; `Final` is the
/// terminal `Response` returned to the caller.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    Progress(GetProgress),
    // Boxed: `Response`'s largest variant dwarfs `GetProgress`, so an
    // un-boxed `Final` would make every `StreamEvent` pay the full
    // `Response` size (clippy `large_enum_variant`).
    Final(Box<Response>),
}

/// Round-trip one request, calling `on_progress` for every streaming
/// `Progress` update and returning the terminal response. For
/// non-streaming requests, `on_progress` is never called and the single
/// `Response` line is returned as-is.
///
/// `on_progress` is invoked synchronously from the read loop, so heavy
/// work in the callback will throttle subsequent reads. Renderers
/// typically just update a stderr status line and return.
pub fn request_streaming<F>(
    socket_path: &Path,
    request: &Request,
    mut on_progress: F,
) -> Result<Response, ClientError>
where
    F: FnMut(&GetProgress),
{
    let mut stream = UnixStream::connect(socket_path).map_err(|e| ClientError::Connect {
        path: socket_path.display().to_string(),
        source: e,
    })?;
    let timeout = timeout_for(request);
    // Streaming requests want the read timeout to reset on every
    // received line (the gap *between* progress samples), not on the
    // overall wall clock. `BufRead::read_line` already does the
    // per-call read; the timeout we set on the socket is the gap
    // budget. Match the daemon's `TREE_COMMAND_TIMEOUT` so the
    // client's bound is just slightly looser than the daemon's.
    let read_timeout = if is_streamable(request) {
        TREE_TIMEOUT
    } else {
        timeout
    };
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            return Err(ClientError::EmptyResponse);
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Response>(trimmed)? {
            Response::Progress(p) => {
                on_progress(&p);
            }
            other => return Ok(other),
        }
    }
}

/// Stream a `Request::UploadFollow` (or any other request that may
/// emit `Response::UploadProgress` frames). `on_progress` fires for
/// every progress frame; the call returns the *terminal*
/// `Response::UploadJob` (or `Response::Error`) once the daemon
/// closes the stream.
///
/// Why a separate helper instead of overloading [`request_streaming`]:
/// the existing helper's callback type is tied to [`GetProgress`];
/// upload progress carries a richer per-job snapshot, so the two
/// paths bind to different types and can't share a single closure.
pub fn request_upload_follow<F>(
    socket_path: &Path,
    request: &Request,
    mut on_progress: F,
) -> Result<Response, ClientError>
where
    F: FnMut(&UploadJobView),
{
    let mut stream = UnixStream::connect(socket_path).map_err(|e| ClientError::Connect {
        path: socket_path.display().to_string(),
        source: e,
    })?;
    stream.set_read_timeout(Some(TREE_TIMEOUT))?;
    stream.set_write_timeout(Some(DEFAULT_TIMEOUT))?;

    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            return Err(ClientError::EmptyResponse);
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Response>(trimmed)? {
            Response::UploadProgress(view) => {
                on_progress(&view);
            }
            other => return Ok(other),
        }
    }
}
