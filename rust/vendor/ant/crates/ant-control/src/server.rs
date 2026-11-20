//! Tokio-based UDS server. Reads one NDJSON request, writes one or more
//! NDJSON responses, closes.
//!
//! The wire is single-shot for almost every request: one [`Request`] line
//! in, one [`Response`] line out, EOF. The exception is a `Get*` request
//! with `progress: true` — the daemon may emit zero or more
//! [`Response::Progress`] lines before the terminal response, all on the
//! same connection. Old clients that don't ask for progress only ever
//! see the terminal line, so the v1 single-shot framing is preserved.
//!
//! This module is `#[cfg(unix)]`-gated: it is the Unix domain-socket
//! transport. The command/ack data types it relays live in the
//! cross-platform `command` module so non-Unix targets (Windows) still
//! get the node-loop protocol types without the socket I/O.

use crate::command::{streaming_ack_channel, ControlAck, ControlCommand};
use crate::protocol::{Request, Response, StatusSnapshot, VersionInfo, PROTOCOL_VERSION};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// How long to wait for the node loop to acknowledge a near-instant
/// command (e.g. `PeersReset`). If the node loop is wedged we don't want
/// to hang the socket handler indefinitely.
const FAST_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap for commands that may take a network round-trip (retrieval). Sized
/// to comfortably cover `ant_retrieval::retrieve_chunk`'s own 10 s
/// timeout plus per-attempt overhead, without hanging the socket forever
/// if the node loop wedges.
const NETWORK_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
/// Cap for commands that walk a chunk tree (joiner / mantaray): every
/// node and every leaf is one round-trip. A 1 MB file is ~256 leaves +
/// 2-3 intermediates; a manifest with one fork adds one more fetch on
/// top. Real-world chunk fetches usually complete in <1 s, but pad for
/// the unlucky path.
const TREE_COMMAND_TIMEOUT: Duration = Duration::from_mins(1);

/// Serve control requests on `socket_path` until the task is cancelled.
///
/// `status_rx` is the live status view maintained by the node loop; each
/// request call `.borrow()` on it and replies with the current snapshot.
///
/// `command_tx` is the single-producer channel into the node loop for
/// mutating requests (e.g. `Request::PeersReset`). `None` means mutating
/// commands will reply with `Response::Error`.
///
/// `agent` is the daemon agent string (e.g. `"antd/0.1.0"`), returned by
/// `Request::Version` and overriding `snapshot.agent` in case the sender
/// shipped an older value.
pub async fn serve(
    socket_path: PathBuf,
    agent: String,
    status_rx: watch::Receiver<StatusSnapshot>,
    command_tx: Option<mpsc::Sender<ControlCommand>>,
) -> Result<(), ServerError> {
    bind(socket_path)?.serve(agent, status_rx, command_tx).await
}

/// A control socket whose Unix listener is already bound. Split from
/// [`serve`] so the daemon can surface bind failures immediately (a
/// too-long socket path fails `bind(2)` with `SUN_LEN`, not the accept
/// loop) and decide what to do about them — e.g. fall back to a shorter
/// path or run without the socket — instead of discovering the error
/// seconds later when the spawned serve task is first joined, and
/// tearing down an otherwise healthy node over it (issue #39).
pub struct BoundControlSocket {
    listener: UnixListener,
    socket_path: PathBuf,
}

/// Remove a stale socket, create the parent directory, bind, and
/// restrict permissions. Must be called from within a tokio runtime
/// (the listener registers with the reactor).
pub fn bind(socket_path: PathBuf) -> Result<BoundControlSocket, ServerError> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    restrict_socket_permissions(&socket_path)?;
    Ok(BoundControlSocket {
        listener,
        socket_path,
    })
}

impl BoundControlSocket {
    /// The path the listener is actually bound to.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accept-and-dispatch loop; runs until the task is cancelled.
    /// Accept errors are logged and survived, so this only returns if
    /// the future is dropped.
    pub async fn serve(
        self,
        agent: String,
        status_rx: watch::Receiver<StatusSnapshot>,
        command_tx: Option<mpsc::Sender<ControlCommand>>,
    ) -> Result<(), ServerError> {
        debug!(
            target: "ant_control",
            "control socket listening at {}",
            self.socket_path.display(),
        );

        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let rx = status_rx.clone();
                    let agent = agent.clone();
                    let cmd_tx = command_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, agent, rx, cmd_tx).await {
                            warn!(target: "ant_control", "control request failed: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!(target: "ant_control", "accept failed: {e}");
                }
            }
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    agent: String,
    status_rx: watch::Receiver<StatusSnapshot>,
    command_tx: Option<mpsc::Sender<ControlCommand>>,
) -> Result<(), ServerError> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).take(MAX_REQUEST_BYTES as u64);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);

    match serde_json::from_str::<Request>(trimmed) {
        Ok(Request::Status) => {
            let snap = status_rx.borrow().clone();
            write_response(&mut write_half, &Response::Status(Box::new(snap))).await?;
        }
        Ok(Request::Version) => {
            write_response(
                &mut write_half,
                &Response::Version(VersionInfo {
                    agent,
                    protocol_version: PROTOCOL_VERSION,
                }),
            )
            .await?;
        }
        Ok(Request::PeersReset) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::ResetPeerstore { ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::Get {
            reference,
            bypass_cache: _,
            progress: _,
        }) => match parse_reference(&reference) {
            Ok(addr) => {
                let response =
                    dispatch_oneshot(command_tx.as_ref(), NETWORK_COMMAND_TIMEOUT, |ack| {
                        ControlCommand::GetChunk {
                            reference: addr,
                            ack,
                        }
                    })
                    .await;
                write_response(&mut write_half, &response).await?;
            }
            Err(e) => {
                write_response(
                    &mut write_half,
                    &Response::Error {
                        message: format!("bad reference: {e}"),
                    },
                )
                .await?;
            }
        },
        Ok(Request::GetBzz {
            reference,
            path,
            allow_degraded_redundancy,
            bypass_cache,
            progress,
        }) => match parse_reference(&reference) {
            Ok(addr) => {
                dispatch_streaming(
                    &mut write_half,
                    command_tx.as_ref(),
                    TREE_COMMAND_TIMEOUT,
                    |ack| ControlCommand::GetBzz {
                        reference: addr,
                        path,
                        allow_degraded_redundancy,
                        bypass_cache,
                        progress,
                        // CLI keeps the conservative joiner default; the
                        // HTTP gateway opts in to a higher ceiling for
                        // real-site downloads.
                        max_bytes: None,
                        ack,
                    },
                )
                .await?;
            }
            Err(e) => {
                write_response(
                    &mut write_half,
                    &Response::Error {
                        message: format!("bad reference: {e}"),
                    },
                )
                .await?;
            }
        },
        Ok(Request::GetBytes {
            reference,
            bypass_cache,
            progress,
        }) => match parse_reference(&reference) {
            Ok(addr) => {
                dispatch_streaming(
                    &mut write_half,
                    command_tx.as_ref(),
                    TREE_COMMAND_TIMEOUT,
                    |ack| ControlCommand::GetBytes {
                        reference: addr,
                        bypass_cache,
                        progress,
                        max_bytes: None,
                        ack,
                    },
                )
                .await?;
            }
            Err(e) => {
                write_response(
                    &mut write_half,
                    &Response::Error {
                        message: format!("bad reference: {e}"),
                    },
                )
                .await?;
            }
        },
        Ok(Request::UploadStart {
            source_path,
            batch_id,
            name,
            content_type,
            raw,
        }) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::UploadStart {
                    source_path: PathBuf::from(source_path),
                    batch_id,
                    name,
                    content_type,
                    raw,
                    ack,
                }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::UploadList) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::UploadList { ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::UploadStatus { job_id }) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::UploadStatus { job_id, ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::UploadPause { job_id }) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::UploadPause { job_id, ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::UploadResume { job_id }) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::UploadResume { job_id, ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::UploadCancel { job_id }) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::UploadCancel { job_id, ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::PostageStatus) => {
            let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                ControlCommand::PostageStatus { ack }
            })
            .await;
            write_response(&mut write_half, &response).await?;
        }
        Ok(Request::PullsyncProbe {
            target,
            bin,
            start,
            max_deliver,
        }) => match parse_reference(&target) {
            Ok(target) => {
                // The probe can long-block server-side on an empty live
                // bin; give it the network timeout, not the fast one.
                let response =
                    dispatch_oneshot(command_tx.as_ref(), NETWORK_COMMAND_TIMEOUT, |ack| {
                        ControlCommand::PullsyncProbe {
                            target,
                            bin,
                            start,
                            max_deliver: max_deliver.unwrap_or(16),
                            ack,
                        }
                    })
                    .await;
                write_response(&mut write_half, &response).await?;
            }
            Err(e) => {
                write_response(
                    &mut write_half,
                    &Response::Error {
                        message: format!("bad request: {e}"),
                    },
                )
                .await?;
            }
        },
        Ok(Request::PutChunkLocal { wire_hex }) => match parse_chunk_wire(&wire_hex) {
            Ok(wire) => {
                let response = dispatch_oneshot(command_tx.as_ref(), FAST_COMMAND_TIMEOUT, |ack| {
                    ControlCommand::PutChunkLocal { wire, ack }
                })
                .await;
                write_response(&mut write_half, &response).await?;
            }
            Err(e) => {
                write_response(
                    &mut write_half,
                    &Response::Error {
                        message: format!("bad request: {e}"),
                    },
                )
                .await?;
            }
        },
        Ok(Request::UploadFollow { job_id }) => {
            // Use the upload-specific timeout: a stalled upload may
            // emit no progress for many seconds (e.g. waiting on a
            // slow neighbour during pushsync), so reuse the
            // tree-command timeout that already covers the
            // analogous "no progress for a while" case on reads.
            dispatch_streaming(
                &mut write_half,
                command_tx.as_ref(),
                TREE_COMMAND_TIMEOUT,
                |ack| ControlCommand::UploadFollow { job_id, ack },
            )
            .await?;
        }
        Err(e) => {
            write_response(
                &mut write_half,
                &Response::Error {
                    message: format!("bad request: {e}"),
                },
            )
            .await?;
        }
    }

    write_half.flush().await?;
    write_half.shutdown().await?;
    Ok(())
}

async fn write_response<W>(write_half: &mut W, response: &Response) -> Result<(), ServerError>
where
    W: AsyncWriteExt + Unpin,
{
    let mut out = serde_json::to_vec(response).expect("serialize Response");
    out.push(b'\n');
    write_half.write_all(&out).await?;
    Ok(())
}

/// Forward a non-streaming command to the node loop and block until it
/// acks (or the timeout fires). Returns a `Response` ready to serialize
/// back to the client.
async fn dispatch_oneshot<F>(
    command_tx: Option<&mpsc::Sender<ControlCommand>>,
    timeout: Duration,
    build: F,
) -> Response
where
    F: FnOnce(oneshot::Sender<ControlAck>) -> ControlCommand,
{
    let Some(tx) = command_tx else {
        return Response::Error {
            message: "daemon has no control-command channel wired up".to_string(),
        };
    };
    let (ack_tx, ack_rx) = oneshot::channel();
    if tx.send(build(ack_tx)).await.is_err() {
        return Response::Error {
            message: "daemon node loop is no longer accepting commands".to_string(),
        };
    }
    match tokio::time::timeout(timeout, ack_rx).await {
        Ok(Ok(ack)) => ack_to_response(ack),
        Ok(Err(_)) => Response::Error {
            message: "daemon dropped the command without replying".to_string(),
        },
        Err(_) => Response::Error {
            message: format!("daemon did not ack within {} seconds", timeout.as_secs()),
        },
    }
}

/// Forward a streaming-capable command to the node loop, write each
/// non-terminal `Progress` ack as its own NDJSON line, and finish with
/// the terminal response. The `timeout` resets every time a fresh ack
/// lands so a long-but-progressing fetch isn't killed for taking longer
/// than the per-message bound.
async fn dispatch_streaming<W, F>(
    write_half: &mut W,
    command_tx: Option<&mpsc::Sender<ControlCommand>>,
    timeout: Duration,
    build: F,
) -> Result<(), ServerError>
where
    W: AsyncWriteExt + Unpin,
    F: FnOnce(mpsc::Sender<ControlAck>) -> ControlCommand,
{
    let Some(tx) = command_tx else {
        let response = Response::Error {
            message: "daemon has no control-command channel wired up".to_string(),
        };
        return write_response(write_half, &response).await;
    };
    let (ack_tx, mut ack_rx) = streaming_ack_channel();
    if tx.send(build(ack_tx)).await.is_err() {
        let response = Response::Error {
            message: "daemon node loop is no longer accepting commands".to_string(),
        };
        return write_response(write_half, &response).await;
    }
    loop {
        match tokio::time::timeout(timeout, ack_rx.recv()).await {
            Ok(Some(ack)) => {
                let is_terminal = ack.is_terminal();
                let response = ack_to_response(ack);
                write_response(write_half, &response).await?;
                if is_terminal {
                    return Ok(());
                }
            }
            Ok(None) => {
                let response = Response::Error {
                    message: "daemon dropped the command without replying".to_string(),
                };
                return write_response(write_half, &response).await;
            }
            Err(_) => {
                let response = Response::Error {
                    message: format!(
                        "daemon went silent for more than {} seconds",
                        timeout.as_secs()
                    ),
                };
                return write_response(write_half, &response).await;
            }
        }
    }
}

fn ack_to_response(ack: ControlAck) -> Response {
    match ack {
        ControlAck::Ok { message } => Response::Ok { message },
        ControlAck::Bytes { data } => Response::Bytes {
            hex: format!("0x{}", hex::encode(data)),
        },
        ControlAck::BzzBytes {
            data,
            content_type,
            filename,
        } => Response::BzzBytes {
            hex: format!("0x{}", hex::encode(data)),
            content_type,
            filename,
        },
        ControlAck::Manifest { .. } | ControlAck::ManifestPage(_) => Response::Error {
            message: "manifest listing is only supported by ant-gateway".to_string(),
        },
        ControlAck::Progress(p) => Response::Progress(p),
        ControlAck::BytesStreamStart { .. }
        | ControlAck::BzzStreamStart { .. }
        | ControlAck::BytesChunk { .. } => Response::Error {
            message: "streaming byte bodies are only supported by ant-gateway".to_string(),
        },
        ControlAck::StreamDone => Response::Ok {
            message: "stream complete".to_string(),
        },
        ControlAck::ChunkUploaded { reference } => Response::ChunkUploaded { reference },
        // Envelope issuance and stewardship checks are HTTP-gateway
        // surfaces (`POST /envelope`, `GET|PUT /stewardship`); the
        // Unix-socket protocol doesn't expose the commands, so an ack
        // leaking here means a wiring bug — surface it clearly.
        ControlAck::Envelope { .. } | ControlAck::Retrievable { .. } => Response::Error {
            message: "envelope/stewardship are only supported by ant-gateway".to_string(),
        },
        ControlAck::UploadStarted { job_id } => Response::UploadStarted { job_id },
        ControlAck::UploadJob(view) => Response::UploadJob(view),
        ControlAck::UploadList(views) => Response::UploadList { jobs: views },
        ControlAck::UploadProgress(view) => Response::UploadProgress(view),
        ControlAck::PostageStatus(view) => Response::PostageStatus(view),
        ControlAck::PullsyncProbe(view) => Response::PullsyncProbe(view),
        // Lurker message frames are a gateway WebSocket surface
        // (`/gsoc/subscribe`, `/pss/subscribe`); the Unix-socket protocol
        // doesn't expose the subscription command.
        ControlAck::LurkerMessage { .. } => Response::Error {
            message: "lurker subscriptions are only supported by ant-gateway".to_string(),
        },
        // The Unix-socket protocol returns a single batch via
        // `PostageStatus`; the multi-batch list is an HTTP-gateway-only
        // surface (`GET /stamps`).
        ControlAck::PostageList(_) => Response::Error {
            message: "postage batch listing is only supported by ant-gateway".to_string(),
        },
        // The settlement/balance snapshot backs the gateway's bee-parity
        // `/balances` / `/settlements` / `/chequebook/cheque` family;
        // the Unix-socket protocol doesn't expose the command.
        ControlAck::Accounting(_) => Response::Error {
            message: "accounting snapshots are only supported by ant-gateway".to_string(),
        },
        // The pin surface (bee `/pins`) and the per-bucket postage
        // counters are gateway HTTP endpoints; the Unix-socket protocol
        // doesn't expose the commands that produce these acks.
        ControlAck::PinAdded { .. }
        | ControlAck::PinRemoved { .. }
        | ControlAck::PinPresent { .. }
        | ControlAck::PinList { .. }
        | ControlAck::PinCheck { .. }
        | ControlAck::PostageBuckets(_)
        | ControlAck::StampedChunk { .. }
        | ControlAck::StewardshipStamps(_) => Response::Error {
            message:
                "pin / postage-bucket / stamp-record queries are only supported by ant-gateway"
                    .to_string(),
        },
        // The Unix-socket protocol used by `antctl` doesn't expose feed
        // reads today; the control surface is just for renderers and
        // ops tooling, and feed lookup lives on the gateway HTTP API.
        // If a future client wants to drive `GetFeed` over the control
        // socket we'll add `Response::FeedResolved` / `FeedNotFound`
        // variants; for now surface a clear error so the seam is visible.
        ControlAck::FeedResolved { .. } | ControlAck::FeedNotFound => Response::Error {
            message: "feed resolution is only supported by ant-gateway".to_string(),
        },
        // `NotReady` and `NotFound` exist for the gateway HTTP path so it
        // can return `503 Service Unavailable` / `404 Not Found`;
        // collapsing to a generic error here keeps the Unix-socket
        // surface unchanged.
        ControlAck::NotReady { message }
        | ControlAck::NotFound { message }
        | ControlAck::Error { message } => Response::Error { message },
    }
}

/// Parse a 32-byte chunk reference. Accepts `0x`-prefixed or bare hex.
/// Lower- or upper-case is fine. Anything else is rejected before the
/// command hits the node loop so the caller gets a tidy error.
fn parse_reference(s: &str) -> Result<[u8; 32], String> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if stripped.len() != 64 {
        return Err(format!(
            "reference must be 32 bytes (64 hex chars); got {}",
            stripped.len()
        ));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(stripped, &mut out).map_err(|e| format!("invalid hex: {e}"))?;
    Ok(out)
}

/// Parse the chunk wire bytes carried by `Request::PutChunkLocal`.
/// Accepts `0x`-prefixed or bare hex; even-length only. Enforces a
/// generous upper bound (~4200 bytes) so a hostile client can't OOM
/// the daemon by sending a giant "chunk"; tighter per-variant
/// validation (CAC vs SOC, BMT match) lives in the ant-p2p handler
/// where chunk crypto helpers are already in scope.
fn parse_chunk_wire(s: &str) -> Result<Vec<u8>, String> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !stripped.len().is_multiple_of(2) {
        return Err("chunk wire hex must have even length".to_string());
    }
    const MAX_WIRE_BYTES: usize = 4200;
    if stripped.len() / 2 > MAX_WIRE_BYTES {
        return Err(format!(
            "chunk wire {} bytes exceeds cap {} bytes",
            stripped.len() / 2,
            MAX_WIRE_BYTES
        ));
    }
    if stripped.len() < 16 {
        return Err("chunk wire must include the 8-byte span prefix".to_string());
    }
    hex::decode(stripped).map_err(|e| format!("invalid hex: {e}"))
}

fn restrict_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
