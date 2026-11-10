//! A minimal HTTPS GET — the engine's only HTTP client, for the two sources
//! that are not devp2p/libp2p peers (CLAUDE.md *Data sources* carve-outs):
//!
//! - Colibri's ZK sync proofs ([`crate::zksync`]) — self-verifying, so this
//!   transport is trusted for nothing but availability;
//! - checkpointz finalized roots ([`crate::checkpointz`]) — NOT self-verifying,
//!   which is why that module cross-validates several independent operators and
//!   why the certificate check here is not optional.
//!
//! Deliberately small: HTTP/1.1, `Connection: close`, no redirects (a 3xx is a
//! failure — every URL is pinned), no compression, a hard body cap, and a
//! wall-clock deadline. Blocking rustls over a std socket, run on tokio's
//! blocking pool by [`get`]: the async path would need tokio-rustls, a crate the
//! engine does not otherwise carry. TLS 1.3/1.2 under rustls' ring provider,
//! named explicitly (never the process-default provider, which Android's Tor
//! path installs for Arti), against Mozilla's root store (webpki-roots).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// A completed exchange: the status code and the (de-chunked) body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// Not an `https://host[:port]/path` URL.
    BadUrl,
    /// DNS, TCP or TLS failed, or the deadline passed.
    Connect(String),
    Io(String),
    /// The response is not HTTP/1.x, is truncated, or is larger than allowed.
    BadResponse(&'static str),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::BadUrl => f.write_str("not an https URL"),
            HttpError::Connect(e) => write!(f, "connect: {e}"),
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::BadResponse(why) => write!(f, "bad response: {why}"),
        }
    }
}

/// [`get_blocking`] on tokio's blocking pool, the WHOLE exchange bounded by
/// `deadline` — name resolution included, which the system resolver does not
/// bound (a stuck lookup keeps its blocking thread until the resolver gives up,
/// but the caller is answered on time).
pub async fn get(url: &str, accept: &str, max_body: usize, deadline: Duration) -> Result<Response, HttpError> {
    let (url, accept) = (url.to_string(), accept.to_string());
    let task = tokio::task::spawn_blocking(move || get_blocking(&url, &accept, max_body, deadline));
    match tokio::time::timeout(deadline, task).await {
        Ok(joined) => joined.map_err(|e| HttpError::Io(e.to_string()))?,
        Err(_) => Err(HttpError::Connect("deadline".into())),
    }
}

/// GET `url`, returning whatever status the server answered with (callers
/// decide what a 404 means) and at most `max_body` bytes of body.
pub fn get_blocking(url: &str, accept: &str, max_body: usize, deadline: Duration) -> Result<Response, HttpError> {
    let started = Instant::now();
    let (host, port, path) = parse_url(url).ok_or(HttpError::BadUrl)?;
    let remaining = || deadline.checked_sub(started.elapsed()).filter(|d| !d.is_zero());

    let addrs: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| HttpError::Connect(e.to_string()))?
        .collect();
    let mut tcp = None;
    let mut last_err = String::from("no address");
    for addr in addrs {
        let Some(left) = remaining() else { break };
        match TcpStream::connect_timeout(&addr, left) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let tcp = tcp.ok_or(HttpError::Connect(last_err))?;
    let left = remaining().ok_or(HttpError::Connect("deadline".into()))?;
    let _ = tcp.set_read_timeout(Some(left));
    let _ = tcp.set_write_timeout(Some(left));

    let server_name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| HttpError::BadUrl)?;
    let conn = rustls::ClientConnection::new(tls_config(), server_name)
        .map_err(|e| HttpError::Connect(e.to_string()))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: myotis\r\nAccept: {accept}\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).map_err(|e| HttpError::Connect(e.to_string()))?;
    tls.flush().map_err(|e| HttpError::Io(e.to_string()))?;

    // Headers are small; allow them on top of the body cap.
    let cap = max_body.saturating_add(64 * 1024);
    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        if remaining().is_none() {
            return Err(HttpError::Io("deadline".into()));
        }
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > cap {
                    return Err(HttpError::BadResponse("body too large"));
                }
                // A complete Content-Length response need not wait for close.
                if let Some(true) = complete(&raw) {
                    break;
                }
            }
            // Many servers close without TLS close_notify; parse_response
            // still refuses a body shorter than its framing says.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(HttpError::Io(e.to_string())),
        }
    }
    parse_response(&raw, max_body)
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Arc::new(config)
    }))
}

/// `https://host[:port][/path]` → (host, port, path). Anything else — another
/// scheme, userinfo, an empty host — is refused.
fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || path.contains(['\r', '\n', ' ']) {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 443),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), port, path.to_string()))
}

fn split_head(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((&raw[..i], &raw[i + 4..]))
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// `Some(true)` once a Content-Length response has all its bytes.
fn complete(raw: &[u8]) -> Option<bool> {
    let (head, body) = split_head(raw)?;
    let head = std::str::from_utf8(head).ok()?;
    let len: usize = header(head, "content-length")?.parse().ok()?;
    Some(body.len() >= len)
}

/// Parse a whole HTTP/1.x response.
pub(crate) fn parse_response(raw: &[u8], max_body: usize) -> Result<Response, HttpError> {
    let (head, body) = split_head(raw).ok_or(HttpError::BadResponse("no header end"))?;
    let head = std::str::from_utf8(head).map_err(|_| HttpError::BadResponse("header not utf-8"))?;
    let status_line = head.split("\r\n").next().unwrap_or("");
    let mut parts = status_line.split(' ');
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(HttpError::BadResponse("not HTTP/1.x"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::BadResponse("status"))?;

    let body = if header(head, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        dechunk(body, max_body)?
    } else if let Some(len) = header(head, "content-length") {
        let len: usize = len.parse().map_err(|_| HttpError::BadResponse("content-length"))?;
        if len > max_body {
            return Err(HttpError::BadResponse("body too large"));
        }
        if body.len() < len {
            return Err(HttpError::BadResponse("truncated body"));
        }
        body[..len].to_vec()
    } else {
        // Delimited by the close.
        if body.len() > max_body {
            return Err(HttpError::BadResponse("body too large"));
        }
        body.to_vec()
    };
    Ok(Response { status, body })
}

fn dechunk(mut data: &[u8], max_body: usize) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let eol = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(HttpError::BadResponse("truncated chunk size"))?;
        let size_str = std::str::from_utf8(&data[..eol]).map_err(|_| HttpError::BadResponse("chunk size"))?;
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| HttpError::BadResponse("chunk size"))?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        // `size` is the server's number, up to usize::MAX: compare without
        // adding to it, or a wrapped sum passes both guards and the slice
        // below panics (an abort under the workspace's release profile).
        if size > max_body.saturating_sub(out.len()) {
            return Err(HttpError::BadResponse("body too large"));
        }
        if data.len() < 2 || data.len() - 2 < size {
            return Err(HttpError::BadResponse("truncated chunk"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_strictly() {
        assert_eq!(
            parse_url("https://Mainnet.colibri-proof.tech/period_store/1/zk_proof.ssz"),
            Some(("mainnet.colibri-proof.tech".into(), 443, "/period_store/1/zk_proof.ssz".into()))
        );
        assert_eq!(parse_url("https://h:8443"), Some(("h".into(), 8443, "/".into())));
        assert_eq!(parse_url("http://h/x"), None);
        assert_eq!(parse_url("https://u@h/x"), None);
        assert_eq!(parse_url("https:///x"), None);
        assert_eq!(parse_url("https://h/x\r\nEvil: 1"), None);
    }

    #[test]
    fn content_length_bodies() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef", 10).unwrap();
        assert_eq!(r, Response { status: 200, body: b"abc".to_vec() });
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc", 10),
            Err(HttpError::BadResponse("truncated body"))
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n", 10),
            Err(HttpError::BadResponse("body too large"))
        );
        assert_eq!(complete(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nab"), Some(true));
        assert_eq!(complete(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\na"), Some(false));
    }

    #[test]
    fn chunked_bodies() {
        let raw = b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw, 10).unwrap(), Response { status: 404, body: b"abcde".to_vec() });
        assert!(parse_response(raw, 4).is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab", 10).is_err());
    }

    #[test]
    fn a_huge_chunk_size_is_refused_not_wrapped() {
        // After a non-empty first chunk, `len + size` would wrap to 0 and
        // `size + 2` to 1 (#761 review): both guards must still refuse.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\nx";
        assert_eq!(parse_response(raw, 64 * 1024), Err(HttpError::BadResponse("body too large")));
        // A size the body cap admits must still be refused as truncated, with
        // `size + 2` (which would wrap) never computed.
        let near_max = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n{:x}\r\nx",
            usize::MAX - 1
        );
        assert_eq!(
            parse_response(near_max.as_bytes(), usize::MAX),
            Err(HttpError::BadResponse("truncated chunk"))
        );
        let first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nx";
        assert!(parse_response(first, usize::MAX).is_err());
    }

    #[test]
    fn non_http_is_refused() {
        assert!(parse_response(b"SSH-2.0\r\n\r\n", 10).is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n", 10).is_err());
    }

    #[test]
    fn the_tls_config_builds() {
        let _ = tls_config();
    }
}
