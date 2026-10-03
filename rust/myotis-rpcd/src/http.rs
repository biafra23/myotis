//! The HTTP side: a blocking tiny_http server with two thread pools.
//!
//! - INTAKE ([`INTAKE_THREADS`]) accepts every request, checks its Host and
//!   Content-Type, reads its body, and answers everything that cannot block on
//!   the engine's readiness itself: `GET /`, `GET /logindex`, the config-only
//!   methods and the status snapshot (and every malformed body). A health check
//!   therefore answers while every read worker is held waiting for a verified
//!   head.
//! - READ (`--workers`) takes the bodies that name a gated method and blocks in
//!   the router for as long as it must. Its size bounds concurrent engine reads.
//!
//! An async server would only add a second runtime whose every handler is
//! `spawn_blocking` around the same calls.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use crate::engine::{Engine, Readiness};
use crate::rpc::{Body, Router};

/// geth's default `--http` body limit.
pub const MAX_BODY_BYTES: u64 = 5 * 1024 * 1024;
/// Intake threads. Small on purpose: nothing they do waits on the engine.
pub const INTAKE_THREADS: usize = 4;

/// The Host-header allowlist, as geth's `--http.vhosts`: a browser page cannot
/// reach the node through a DNS name it controls (DNS rebinding), because the
/// Host it sends names the attacker's domain, not one listed here.
#[derive(Debug, Clone, PartialEq)]
pub enum VHosts {
    /// `--http-vhosts '*'`: no check.
    Any,
    /// Lowercase host names, without a port; IPv6 in brackets.
    Only(Vec<String>),
}

impl VHosts {
    /// The flag's list (comma-separated on the command line; `*` disables the
    /// check), or by default: localhost, 127.0.0.1, [::1] and the address the
    /// server is bound to. A given list REPLACES the default, as geth's does.
    pub fn new(flag: Option<&[String]>, listen: SocketAddr) -> VHosts {
        match flag {
            Some(list) if list.iter().any(|h| h.trim() == "*") => VHosts::Any,
            Some(list) => VHosts::Only(
                list.iter()
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect(),
            ),
            None => {
                let bound = match listen.ip() {
                    IpAddr::V4(a) => a.to_string(),
                    IpAddr::V6(a) => format!("[{a}]"),
                };
                let mut v: Vec<String> =
                    ["localhost", "127.0.0.1", "[::1]"].map(String::from).into();
                if !v.contains(&bound) {
                    v.push(bound);
                }
                VHosts::Only(v)
            }
        }
    }

    /// Whether a request with this `Host` header may be served. No header at
    /// all passes, as in geth: every browser sends one, so its absence is a
    /// non-browser client the check is not about.
    pub fn allows(&self, host: Option<&str>) -> bool {
        match (self, host) {
            (VHosts::Any, _) | (_, None) => true,
            (VHosts::Only(list), Some(h)) => list.contains(&host_name(h)),
        }
    }
}

/// A Host header's name, lowercased and without its port (`[::1]:8545` →
/// `[::1]`, `LocalHost:8545` → `localhost`).
fn host_name(h: &str) -> String {
    let h = h.trim();
    let name = if h.starts_with('[') {
        h.find(']').map_or(h, |i| &h[..=i])
    } else {
        h.rsplit_once(':').map_or(h, |(name, _)| name)
    };
    name.to_ascii_lowercase()
}

/// geth's accepted JSON-RPC media types, parameters (charset) allowed. A form
/// or `text/plain` POST — what a page may send cross-origin without a CORS
/// preflight — is refused, and so is a POST that names no type.
pub fn json_content_type(v: Option<&str>) -> bool {
    let Some(v) = v else { return false };
    let media = v.split(';').next().unwrap_or("").trim();
    [
        "application/json",
        "application/json-rpc",
        "application/jsonrequest",
    ]
    .iter()
    .any(|t| media.eq_ignore_ascii_case(t))
}

/// Start both pools on `server`. Returns how many threads wait in
/// `server.recv()`: each needs its own `server.unblock()` at shutdown.
pub fn spawn<E: Engine + 'static>(
    server: Arc<tiny_http::Server>,
    router: Arc<Router<E>>,
    vhosts: VHosts,
    workers: usize,
) -> usize {
    let (tx, rx) = mpsc::channel::<(tiny_http::Request, Body)>();
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..workers.max(1) {
        let (rx, router) = (rx.clone(), router.clone());
        std::thread::spawn(move || loop {
            let next = match rx.lock() {
                Ok(r) => r.recv(),
                Err(_) => return,
            };
            let Ok((req, body)) = next else { return };
            let _ = req.respond(rpc_response(router.handle_parsed(body)));
        });
    }
    let vhosts = Arc::new(vhosts);
    for _ in 0..INTAKE_THREADS {
        let (server, router, vhosts, tx) =
            (server.clone(), router.clone(), vhosts.clone(), tx.clone());
        std::thread::spawn(move || {
            while let Ok(req) = server.recv() {
                intake(req, &router, &vhosts, &tx);
            }
        });
    }
    INTAKE_THREADS
}

type Reply = tiny_http::Response<std::io::Cursor<Vec<u8>>>;

fn intake<E: Engine>(
    mut req: tiny_http::Request,
    router: &Router<E>,
    vhosts: &VHosts,
    reads: &mpsc::Sender<(tiny_http::Request, Body)>,
) {
    let response = if !vhosts.allows(header(&req, "Host").as_deref()) {
        text(403, "invalid host specified\n".into())
    } else {
        match req.method() {
            tiny_http::Method::Get if req.url() == "/" => {
                text(200, status_line(&router.engine().status_json()))
            }
            tiny_http::Method::Get if req.url() == "/logindex" => {
                tiny_http::Response::from_string(router.engine().log_index_status_json())
                    .with_header(content_type("application/json"))
            }
            tiny_http::Method::Post
                if !json_content_type(header(&req, "Content-Type").as_deref()) =>
            {
                text(
                    415,
                    "invalid content type, only application/json is supported\n".into(),
                )
            }
            tiny_http::Method::Post => match read_body(&mut req) {
                Err(r) => r,
                Ok(body) => {
                    let body = Body::parse(&body);
                    if body.blocking() {
                        // A read worker answers it; if none is left (shutdown),
                        // say so rather than drop the connection.
                        match reads.send((req, body)) {
                            Ok(()) => return,
                            Err(mpsc::SendError((req, _))) => {
                                let _ = req.respond(text(503, "shutting down\n".into()));
                                return;
                            }
                        }
                    }
                    rpc_response(router.handle_parsed(body))
                }
            },
            _ => text(405, "POST a JSON-RPC request, or GET / for status\n".into()),
        }
    };
    let _ = req.respond(response);
}

fn read_body(req: &mut tiny_http::Request) -> Result<String, Reply> {
    let mut body = String::new();
    if req
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_string(&mut body)
        .is_err()
    {
        return Err(text(400, "request body is not UTF-8\n".into()));
    }
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(text(
            413,
            format!("request body exceeds {MAX_BODY_BYTES} bytes\n"),
        ));
    }
    Ok(body)
}

fn header(req: &tiny_http::Request, name: &'static str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}

/// An empty answer (notifications only) is an empty body.
fn rpc_response(out: Option<String>) -> Reply {
    tiny_http::Response::from_string(out.unwrap_or_default())
        .with_header(content_type("application/json"))
}

/// `GET /`: one line, for humans and health checks.
fn status_line(status: &str) -> String {
    let r = Readiness::parse(status);
    let v: serde_json::Value = serde_json::from_str(status).unwrap_or_default();
    format!(
        "synced={} ready={} beacon={} head={} finalized={} peers={} snapServing={} network={}\n",
        r.beacon_state == "SYNCED",
        r.ready_for_reads(),
        if r.beacon_state.is_empty() {
            "?"
        } else {
            &r.beacon_state
        },
        r.optimistic_block,
        v["finalizedBlockNumber"].as_u64().unwrap_or(0),
        r.peer_count,
        r.snap_serving_peers,
        v["network"].as_str().unwrap_or("?"),
    )
}

fn text(code: u16, body: String) -> Reply {
    tiny_http::Response::from_string(body)
        .with_status_code(code)
        .with_header(content_type("text/plain; charset=utf-8"))
}

fn content_type(v: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes("Content-Type", v).expect("static header is valid")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::rpc::tests::Fake;

    const LOCAL: &str = "127.0.0.1:8546";

    #[test]
    fn vhosts_default_to_loopback_and_the_bound_address() {
        let v = VHosts::new(None, LOCAL.parse().unwrap());
        for ok in [
            "localhost",
            "LOCALHOST:8546",
            "127.0.0.1",
            "127.0.0.1:8546",
            "[::1]",
            "[::1]:8546",
        ] {
            assert!(v.allows(Some(ok)), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:8546",
            "localhost.evil.example",
            "127.0.0.2",
            "",
        ] {
            assert!(!v.allows(Some(bad)), "{bad}");
        }
        assert!(v.allows(None), "no Host header: not a browser");
        let lan = VHosts::new(None, "192.168.5.7:8546".parse().unwrap());
        assert!(lan.allows(Some("192.168.5.7:8546")));
        let v6 = VHosts::new(None, "[fe80::1]:8546".parse().unwrap());
        assert!(v6.allows(Some("[FE80::1]:8546")));
    }

    #[test]
    fn vhosts_flag_replaces_the_default_and_star_disables_it() {
        let list = ["rpc.local".to_string(), " Node.Lan ".into()];
        let v = VHosts::new(Some(&list), LOCAL.parse().unwrap());
        assert!(v.allows(Some("rpc.local:8546")) && v.allows(Some("node.lan")));
        assert!(!v.allows(Some("localhost")));
        let any = VHosts::new(Some(&["*".to_string()]), LOCAL.parse().unwrap());
        assert_eq!(any, VHosts::Any);
        assert!(any.allows(Some("evil.example")));
    }

    #[test]
    fn content_type_must_be_json() {
        for ok in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
            "application/json-rpc",
            "application/jsonrequest",
        ] {
            assert!(json_content_type(Some(ok)), "{ok}");
        }
        for bad in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "application/jsonx",
            "",
        ] {
            assert!(!json_content_type(Some(bad)), "{bad}");
        }
        assert!(!json_content_type(None));
    }

    /// One raw HTTP/1.1 exchange: (status, body). Times out rather than hangs.
    fn exchange(addr: SocketAddr, head: &str, body: &str) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(
            s,
            "{head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status = out
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = out.split_once("\r\n\r\n").map_or("", |x| x.1).to_string();
        (status, body)
    }

    fn post(addr: SocketAddr, body: &str) -> (u16, String) {
        exchange(
            addr,
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json",
            body,
        )
    }

    /// A node that never becomes ready, one read worker, and a long hold: the
    /// worker is stuck in the hold, and everything non-blocking still answers.
    #[test]
    fn non_blocking_requests_answer_while_every_read_worker_is_held() {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let mut f = Fake::new();
        f.status = r#"{"running":true,"beaconState":"CATCHING_UP","elReaderAvailable":true,"network":"gnosis"}"#.into();
        let router = Arc::new(Router::new(f).with_ready_wait(Duration::from_secs(4)));
        spawn(server.clone(), router, VHosts::new(None, addr), 1);

        let held = std::thread::spawn(move || {
            let t0 = Instant::now();
            let r = post(
                addr,
                r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}"#,
            );
            (r, t0.elapsed())
        });
        std::thread::sleep(Duration::from_millis(300)); // let it reach the hold

        let t0 = Instant::now();
        let (code, body) = exchange(addr, "GET / HTTP/1.1\r\nHost: localhost", "");
        assert_eq!(code, 200);
        assert!(
            body.starts_with("synced=false ready=false beacon=CATCHING_UP"),
            "{body}"
        );
        let (code, body) = post(addr, r#"{"jsonrpc":"2.0","id":2,"method":"eth_chainId"}"#);
        assert_eq!(
            (code, body.contains(r#""result":"0x64""#)),
            (200, true),
            "{body}"
        );
        let (_, body) = post(
            addr,
            r#"[{"jsonrpc":"2.0","id":3,"method":"net_version"},
                {"jsonrpc":"2.0","id":4,"method":"eth_syncing"}]"#,
        );
        assert!(body.contains(r#""result":"100""#), "{body}");
        let (_, body) = post(addr, "{nope");
        assert!(body.contains("-32700"), "{body}");
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "non-blocking requests queued behind the held read: {:?}",
            t0.elapsed()
        );

        // The held read waited out its hold once, then the engine answered.
        let ((code, body), waited) = held.join().unwrap();
        assert_eq!(code, 200);
        assert!(body.contains(r#""result":"0x3e8""#), "{body}");
        assert!(waited >= Duration::from_secs(3), "{waited:?}");
    }

    #[test]
    fn foreign_hosts_and_non_json_posts_are_refused() {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let addr = server.server_addr().to_ip().unwrap();
        let router = Arc::new(Router::new(Fake::new()));
        spawn(server, router, VHosts::new(None, addr), 1);
        let rpc = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}"#;

        let (code, _) = exchange(
            addr,
            "POST / HTTP/1.1\r\nHost: rebound.evil.example:8546\r\nContent-Type: application/json",
            rpc,
        );
        assert_eq!(code, 403);
        let (code, _) = exchange(addr, "GET / HTTP/1.1\r\nHost: evil.example", "");
        assert_eq!(code, 403);
        let (code, _) = exchange(
            addr,
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain",
            rpc,
        );
        assert_eq!(code, 415);
        let (code, _) = exchange(addr, "POST / HTTP/1.1\r\nHost: localhost", rpc);
        assert_eq!(code, 415, "a POST with no Content-Type");
        let (code, body) = post(addr, rpc);
        assert_eq!((code, body.contains("0x64")), (200, true), "{body}");
    }
}
