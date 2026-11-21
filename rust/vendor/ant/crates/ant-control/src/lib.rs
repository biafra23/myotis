//! Control-plane protocol and transports for `antd` ↔ `antctl`.
//!
//! Transport: newline-delimited JSON over a Unix domain socket. One request,
//! one response, then close. Keeping the wire format framing-trivial lets us
//! debug with `nc -U ~/.antd/antd.sock` and evolve the payload independently.

mod activity;
mod command;
mod protocol;

#[cfg(unix)]
mod client;
#[cfg(unix)]
mod server;

pub use activity::{ActiveRequestGuard, GatewayActivity, GatewayActivityHandle};
// Command/ack types + the streaming ack channel are platform-neutral
// (plain data + tokio channels); they live outside the `#[cfg(unix)]`
// transport so `ant-node` / `ant-gateway` / `ant-ffi` / `antd` build on
// Windows too. Only the Unix domain-socket transport (`serve`, client)
// is gated.
pub use command::{
    streaming_ack_channel, BatchChunkCount, BzzFeed, ControlAck, ControlCommand, LurkerMessageKind,
    ManifestEntryInfo, ManifestListPage, ManifestListQuery, PinCheckStat, PostageBucketsView,
    StewardshipStampsView, StreamRange,
};
pub use protocol::{
    AccountingSnapshotView, CacheInfo, DiskCacheInfo, ExternalAddressInfo, GatewayRequestInfo,
    GatewayRequestKind, GetProgress, HandshakeReport, IdentityInfo, LastChequeView,
    PeerAccountingView, PeerConnectionInfo, PeerConnectionState, PeerInfo, PeerPipelineEntry,
    PostageStatusView, ProtocolError, PullsyncProbeView, Request, Response, RetrievalInfo,
    RoutingInfo, SettlementInfo, StatusSnapshot, UploadJobView, VersionInfo, PROTOCOL_VERSION,
};

#[cfg(unix)]
pub use client::{
    request_streaming, request_sync, request_upload_follow, ClientError, StreamEvent,
};
#[cfg(unix)]
pub use server::{bind, serve, BoundControlSocket, ServerError};

/// Name of the pointer file `antd` writes into the data dir when the
/// control socket could not bind at its intended `<data-dir>/antd.sock`
/// path (most commonly: the path exceeds `sun_path`'s ~104-byte limit,
/// issue #39) and a fallback in the system temp dir was bound instead.
/// Contains the actual socket path, one line. Clients resolve through
/// it via [`resolve_client_socket`].
pub const SOCKET_POINTER_FILE: &str = "antd.sock.path";

/// Resolve the daemon control-socket path the way `antctl`/`antop` do:
/// an explicit `--socket` always wins; otherwise `<data_dir>/antd.sock`,
/// unless that socket is absent and a [`SOCKET_POINTER_FILE`] names the
/// fallback the daemon actually bound.
#[must_use]
pub fn resolve_client_socket(
    explicit: Option<std::path::PathBuf>,
    data_dir: &std::path::Path,
) -> std::path::PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    let default = data_dir.join("antd.sock");
    if default.exists() {
        return default;
    }
    if let Ok(contents) = std::fs::read_to_string(data_dir.join(SOCKET_POINTER_FILE)) {
        let pointed = contents.trim();
        if !pointed.is_empty() {
            return std::path::PathBuf::from(pointed);
        }
    }
    default
}
