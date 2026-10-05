//! The JSON-RPC router: a port of the strict (no-proxy) path of the Kotlin
//! `RpcRouter` (jsonrpc-server, `tryVerified` and `dispatchOne`), with the
//! engine-JSON reading of its Rust-engine adapters (`IosRpcBackend`,
//! `RustVerifiedReads`) folded in.
//!
//! There is no upstream proxy, ever: a request is answered from the engine's
//! verified surface or refused. The error codes carry the distinction a client
//! acts on:
//! - `-32000` — implemented, but not answerable verified right now (not synced,
//!   no serving peer, the log index has not covered the range). Retryable.
//! - `-32602` — can never be answered as asked (malformed, out of spec, or
//!   asking for state this node does not hold). Retrying will not help.
//! - `-32601` — not implemented here.
//! - `3` — the call REVERTED: a verified answer, with the revert data.

use std::cell::Cell;
use std::collections::VecDeque;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::engine::{Engine, Readiness};
use crate::quantity::{
    decimal_to_hex, engine_bytes, hex_data, hex_quantity, hex_quantity_decimal, parse_hex,
    parse_wei_quantity,
};

/// geth's default `BatchRequestLimit`: elements are served one after another,
/// so an unbounded batch would hold a worker for as long as its sender likes.
pub const MAX_BATCH_REQUESTS: usize = 1000;
/// How far BELOW the anchored head a number pin is still served from head
/// state (`RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE`).
const BLOCK_NUM_LAG_TOLERANCE: u64 = 64;
/// How far ABOVE the anchored head a number pin is still served
/// (`RpcBlockWindow.BLOCK_NUM_TOLERANCE`).
const BLOCK_NUM_TOLERANCE: u64 = 16;
/// geth's caps for `eth_feeHistory`.
const MAX_FEE_HISTORY_BLOCKS: i64 = 1024;
const MAX_FEE_HISTORY_PERCENTILES: usize = 100;

/// How often the readiness hold re-reads the engine's status.
const READY_POLL: Duration = Duration::from_millis(250);

/// Methods answered from config or the engine's status snapshot. They are
/// never held for readiness, so a client or health check gets them at once
/// whatever the node is doing; every other served method is.
const NON_BLOCKING: [&str; 7] = [
    "eth_chainId",
    "net_version",
    "web3_clientVersion",
    "eth_accounts",
    "net_listening",
    "eth_syncing",
    "myotis_status",
];

/// Whether `method` is served and held for readiness before the engine is
/// asked (so may block for up to `--ready-wait`).
fn gated(method: &str) -> bool {
    arity(method).is_some() && !NON_BLOCKING.contains(&method)
}

/// Fields geth's state override defines; anything else is malformed.
const OVERRIDE_FIELDS: [&str; 5] = ["code", "balance", "nonce", "state", "stateDiff"];
/// Transaction-object quantity fields — canonicalized to 0x-hex before the
/// engine sees them (its parser takes hex only; clients may send decimal).
const TX_QUANTITIES: [&str; 8] = [
    "value",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "nonce",
    "chainId",
    "type",
];
const BLOB_FIELDS: [&str; 6] = [
    "blobVersionedHashes",
    "maxFeePerBlobGas",
    "blobs",
    "commitments",
    "proofs",
    "sidecar",
];

/// The most positional arguments each served method takes — geth's arity, so a
/// request geth refuses with "too many arguments" is refused here too, never
/// served with the extra argument dropped. Also the served-method list.
fn arity(method: &str) -> Option<usize> {
    Some(match method {
        "eth_chainId"
        | "net_version"
        | "eth_blockNumber"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas"
        | "web3_clientVersion"
        | "eth_syncing"
        | "eth_accounts"
        | "net_listening"
        | "myotis_status" => 0,
        "eth_sendRawTransaction"
        | "eth_getTransactionReceipt"
        | "eth_getTransactionByHash"
        | "eth_getBlockReceipts"
        | "eth_getLogs" => 1,
        "eth_getBalance"
        | "eth_getTransactionCount"
        | "eth_getCode"
        | "eth_getBlockByNumber"
        | "eth_getBlockByHash" => 2,
        "eth_getStorageAt" | "eth_feeHistory" => 3,
        // transaction, block, state overrides, block overrides
        "eth_call" | "eth_estimateGas" => 4,
        _ => return None,
    })
}

/// Why a request got no result. The router turns each into its error envelope
/// in one place ([`Router::handle_one`]), so a handler only says what happened.
#[derive(Debug, PartialEq)]
pub enum Fail {
    /// The request can never be served as asked: `-32602` with this text.
    Invalid(String),
    /// No verified answer right now: `-32000`, with the engine's reason when it
    /// gave one.
    Unavailable(Option<String>),
    /// The ENGINE refused for good (`{"error","code":-32602}`): `-32602`.
    Refused(String),
    /// A complete error served verbatim: geth's reverts (code 3, with data)
    /// and geth-worded `-32000` answers (infeasible, txpool rejection, logs).
    Rpc {
        code: i64,
        message: String,
        data: Option<String>,
    },
    /// Not a method this node serves: `-32601`.
    Unsupported,
}

type Out = Result<String, Fail>;

fn invalid<T>(why: impl Into<String>) -> Result<T, Fail> {
    Err(Fail::Invalid(why.into()))
}

/// Heads this node answered `eth_blockNumber` with over the last 15 minutes.
/// A wallet pins its reads to the number it was just handed, so a pin at or
/// above the lowest of them came from this node: declined retryably, never
/// called invalid, even after the head moved on (Kotlin `ReportedHeads`).
struct ReportedHeads {
    entries: Mutex<VecDeque<(u64, Instant)>>,
}

impl ReportedHeads {
    const WINDOW: Duration = Duration::from_secs(15 * 60);
    const MAX_ENTRIES: usize = 512;

    fn record(&self, head: u64) {
        let Ok(mut e) = self.entries.lock() else {
            return;
        };
        Self::prune(&mut e);
        let now = Instant::now();
        match e.back_mut() {
            Some(last) if last.0 == head => last.1 = now,
            _ => {
                e.push_back((head, now));
                if e.len() > Self::MAX_ENTRIES {
                    e.pop_front();
                }
            }
        }
    }

    fn lowest(&self) -> Option<u64> {
        let mut e = self.entries.lock().ok()?;
        Self::prune(&mut e);
        e.iter().map(|x| x.0).min()
    }

    fn prune(e: &mut VecDeque<(u64, Instant)>) {
        while e.front().is_some_and(|x| x.1.elapsed() > Self::WINDOW) {
            e.pop_front();
        }
    }
}

pub struct Router<E: Engine> {
    engine: E,
    client_version: String,
    reported_heads: ReportedHeads,
    ready_wait: Duration,
    access_log: bool,
    call_log: Option<Mutex<Box<dyn std::io::Write + Send>>>,
}

/// The readiness hold ONE HTTP body may spend: a single request, or a whole
/// batch, waits at most `ready_wait` in total. Once a wait has run out, later
/// gated elements of the batch that still find the node unready fail fast.
struct Budget {
    deadline: Instant,
    spent: Cell<bool>,
}

/// One request's pass through the hold: taken at most once, lazily — at its
/// first engine read, so a request refused on its parameters never waits.
struct Gate<'b> {
    budget: &'b Budget,
    passed: Cell<bool>,
}

/// A request body, parsed once: the server classifies it ([`Self::blocking`])
/// before deciding which thread answers it, and the router serves the same
/// parse ([`Router::handle_parsed`]).
pub struct Body {
    root: Option<Value>,
}

impl Body {
    pub fn parse(body: &str) -> Body {
        Body {
            root: serde_json::from_str(body).ok(),
        }
    }

    /// Whether answering may hold for readiness: some request in it (a lone
    /// object, or any element of a batch the router will serve) names a gated
    /// method. Everything else — config methods, the status snapshot, and every
    /// malformed or refused-whole body — is answered without the engine's
    /// readiness, so it never needs to queue behind blocked reads.
    pub fn blocking(&self) -> bool {
        let is_gated = |v: &Value| v.get("method").and_then(Value::as_str).is_some_and(gated);
        match &self.root {
            Some(v @ Value::Object(_)) => is_gated(v),
            Some(Value::Array(a)) if a.len() <= MAX_BATCH_REQUESTS => a.iter().any(is_gated),
            _ => false,
        }
    }

    /// The same error for every request in the body that expects an answer —
    /// a lone object, or each batch element with an id — for a body refused
    /// before it is routed (the server's queue is full). One error with a null
    /// id when there is nothing to answer by id (malformed, or unread).
    pub fn refusal(&self, code: i64, message: &str) -> String {
        let one = |v: &Value| {
            let id = v
                .get("id")
                .filter(|id| valid_id(id))
                .unwrap_or(&Value::Null);
            error_envelope(id, code, message, None)
        };
        match &self.root {
            Some(v @ Value::Object(_)) => one(v),
            Some(Value::Array(a)) if a.iter().any(|v| v.get("id").is_some()) => format!(
                "[{}]",
                a.iter()
                    .filter(|v| v.get("id").is_some())
                    .map(one)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => error_envelope(&Value::Null, code, message, None),
        }
    }
}

/// What the call log records of a request's outcome (handed over as computed,
/// never recovered by re-parsing the response).
enum Logged<'a> {
    Result(&'a str),
    Error { code: i64, message: &'a str },
}

/// Which block selectors a method takes — geth's split between a
/// `BlockNumber` (tag or number) and a `BlockNumberOrHash` (adds a 32-byte
/// hash and EIP-1898's object form).
#[derive(Clone, Copy, PartialEq)]
enum Takes {
    Number,
    NumberOrHash,
}

/// A block selector as read: `value` is what the engine is handed (a tag, a
/// minimal 0x-number or a lowercase 0x-hash).
#[derive(Debug)]
struct Selector {
    value: String,
    number: Option<u64>,
    hash: bool,
}

/// An `eth_call` / `eth_estimateGas` transaction object, shape-checked.
struct TxArgs {
    from: Option<String>,
    /// `None` = contract creation (`to` absent or null).
    to: Option<String>,
    /// Calldata as 0x-hex, or empty for none.
    data: String,
    /// Decimal wei, or empty for zero.
    value: String,
    chain_id: Option<String>,
    /// Anything beyond from/to/data/value that the engine APPLIES — then only
    /// the transaction-object call answers it.
    extended: bool,
    /// The object with every quantity as 0x-hex: what the engine parses.
    canonical: String,
}

enum OverrideParam {
    Absent,
    Valid(String),
    Malformed(String),
}

impl<E: Engine> Router<E> {
    pub fn new(engine: E) -> Self {
        Router {
            engine,
            client_version: format!("myotis-rpcd/{}", env!("CARGO_PKG_VERSION")),
            reported_heads: ReportedHeads {
                entries: Mutex::new(VecDeque::new()),
            },
            ready_wait: Duration::ZERO,
            access_log: false,
            call_log: None,
        }
    }

    /// Write one JSON line per request (batch elements each get their own):
    /// `ts`, `method`, `params` (long strings shortened), `outcome` (`ok`,
    /// `null`, or `error`), `code`/`message` for errors, a shortened `result`,
    /// and `ms`.
    pub fn with_call_log(mut self, sink: Box<dyn std::io::Write + Send>) -> Self {
        self.call_log = Some(Mutex::new(sink));
        self
    }

    /// How long a gated read (or a whole batch) is held waiting for the node to
    /// become serveable before the engine is asked anyway — the JVM's
    /// `WAKE_WAIT_CAP_MS`, `--ready-wait`. Zero (the default) never holds.
    pub fn with_ready_wait(mut self, wait: Duration) -> Self {
        self.ready_wait = wait;
        self
    }

    /// Log each request's method, outcome and time to stderr.
    pub fn with_access_log(mut self, on: bool) -> Self {
        self.access_log = on;
        self
    }

    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Handle one HTTP body: a request object or a batch array. `None` when
    /// nothing may be answered — a notification, or a batch of only those
    /// (JSON-RPC 2.0 §4.1, §6) — which the server sends as an empty body.
    #[cfg(test)]
    pub fn handle(&self, body: &str) -> Option<String> {
        self.handle_parsed(Body::parse(body))
    }

    /// [`Self::handle`] for a body the server has already parsed.
    pub fn handle_parsed(&self, body: Body) -> Option<String> {
        let Some(root) = body.root else {
            return Some(error_envelope(&Value::Null, -32700, "Parse error", None));
        };
        let budget = Budget {
            deadline: Instant::now() + self.ready_wait,
            spent: Cell::new(false),
        };
        match root {
            Value::Object(o) => self.handle_one(&o, &budget),
            Value::Array(items) => {
                if items.is_empty() {
                    return Some(error_envelope(
                        &Value::Null,
                        -32600,
                        "Invalid Request",
                        None,
                    ));
                }
                if items.len() > MAX_BATCH_REQUESTS {
                    // geth's answer: one error refusing the whole batch, carrying
                    // the first usable id.
                    let first = items
                        .iter()
                        .filter_map(|e| e.get("id").filter(|id| valid_id(id)))
                        .next()
                        .cloned()
                        .unwrap_or(Value::Null);
                    let msg = format!(
                        "batch too large: {} requests (at most {MAX_BATCH_REQUESTS})",
                        items.len()
                    );
                    return Some(format!("[{}]", error_envelope(&first, -32600, &msg, None)));
                }
                let responses: Vec<String> = items
                    .iter()
                    .filter_map(|el| match el {
                        Value::Object(o) => self.handle_one(o, &budget),
                        _ => Some(error_envelope(
                            &Value::Null,
                            -32600,
                            "Invalid Request",
                            None,
                        )),
                    })
                    .collect();
                if responses.is_empty() {
                    None
                } else {
                    Some(format!("[{}]", responses.join(",")))
                }
            }
            _ => Some(error_envelope(
                &Value::Null,
                -32600,
                "Invalid Request",
                None,
            )),
        }
    }

    /// One request object → its response envelope (`None` for a notification).
    fn handle_one(&self, root: &Map<String, Value>, budget: &Budget) -> Option<String> {
        let raw_id = root.get("id");
        let id_ok = raw_id.is_none_or(valid_id);
        let id = if id_ok {
            raw_id.cloned().unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        let method = root.get("method").and_then(|m| m.as_str());
        let version = root.get("jsonrpc").and_then(|m| m.as_str());
        let malformed = if version != Some("2.0") {
            Some("'jsonrpc' must be \"2.0\"")
        } else if method.is_none() {
            Some("'method' must be a string")
        } else if !id_ok {
            Some("'id' must be a string, a number or null")
        } else {
            None
        };
        if let Some(why) = malformed {
            return Some(error_envelope(
                &id,
                -32600,
                &format!("Invalid Request: {why}"),
                None,
            ));
        }
        let method = method.unwrap_or_default();
        let t0 = Instant::now();
        let gate = Gate {
            budget,
            passed: Cell::new(false),
        };
        let outcome = self
            .dispatch(method, root, &gate)
            .map_err(|fail| self.fail_parts(method, fail));
        let response = match &outcome {
            Ok(result) => result_envelope(&id, result),
            Err((code, message, data)) => error_envelope(&id, *code, message, data.as_deref()),
        };
        let ms = t0.elapsed().as_millis();
        if self.access_log {
            // `{:?}`: the method is client text; escaped, it cannot forge a line.
            match &outcome {
                Ok(_) => eprintln!("rpc {method:?} id={id} ok {ms}ms"),
                Err((code, ..)) => eprintln!("rpc {method:?} id={id} error {code} {ms}ms"),
            }
        }
        if let Some(sink) = &self.call_log {
            let logged = match &outcome {
                Ok(result) => Logged::Result(result),
                Err((code, message, _)) => Logged::Error {
                    code: *code,
                    message,
                },
            };
            let line = call_log_line(method, root.get("params"), logged, ms);
            if let Ok(mut w) = sink.lock() {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
        // A notification (no `id` member; JSON null IS an id) is served but
        // never answered.
        raw_id.map(|_| response)
    }

    /// A [`Fail`] as its JSON-RPC error: code, message and optional `data`.
    fn fail_parts(&self, method: &str, fail: Fail) -> (i64, String, Option<String>) {
        match fail {
            Fail::Invalid(why) => (-32602, why, None),
            Fail::Refused(why) => (-32602, format!("method '{method}' refused: {why}"), None),
            Fail::Rpc {
                code,
                message,
                data,
            } => (code, message, data),
            Fail::Unsupported => (
                -32601,
                format!("method '{method}' is not supported by this permissionless node"),
                None,
            ),
            Fail::Unavailable(reason) => {
                // A STALE_ANCHOR park gets its own message: unlike not-synced it
                // will NOT progress on its own — a human must decide.
                if Readiness::parse(&self.engine.status_json()).beacon_state == "STALE_ANCHOR" {
                    let msg = format!(
                        "method '{method}' refused: the node's trust anchor is past the \
                         weak-subjectivity bound and syncing is paused awaiting consent — \
                         raise the bound or accept the risk"
                    );
                    return (-32000, msg, None);
                }
                let msg = match reason {
                    Some(r) => format!("method '{method}' cannot be served verified right now: {r}"),
                    None => format!(
                        "method '{method}' cannot be served verified right now (no peer / not synced)"
                    ),
                };
                (-32000, msg, None)
            }
        }
    }

    fn ready(&self) -> bool {
        Readiness::parse(&self.engine.status_json()).ready_for_reads()
    }

    /// The engine, once this request has passed the readiness hold. The first
    /// call holds until the node is serveable or the body's budget runs out,
    /// then lets the read go ahead regardless — the engine then answers with its
    /// own, more precise, reason. A later element of a batch whose budget is
    /// already spent does not wait again: unready, it fails fast (-32000).
    fn engine_ready(&self, g: &Gate) -> Result<&E, Fail> {
        if g.passed.replace(true) || self.ready() {
            return Ok(&self.engine);
        }
        if g.budget.spent.get() {
            return Err(Fail::Unavailable(Some(
                "the node is not ready for verified reads, and this batch has already \
                 waited --ready-wait for it"
                    .into(),
            )));
        }
        loop {
            let now = Instant::now();
            if now >= g.budget.deadline {
                g.budget.spent.set(true);
                return Ok(&self.engine);
            }
            std::thread::sleep(READY_POLL.min(g.budget.deadline - now));
            if self.ready() {
                return Ok(&self.engine);
            }
        }
    }

    /// Route one request; `Ok` is the raw JSON of its result.
    fn dispatch(&self, method: &str, root: &Map<String, Value>, g: &Gate) -> Out {
        let Some(max_args) = arity(method) else {
            return Err(Fail::Unsupported);
        };
        // geth's positional-argument rules: `params` absent, null or an array of
        // at most the method's arguments — anything else is refused, never ignored.
        let empty = Vec::new();
        let params: &Vec<Value> = match root.get("params") {
            None | Some(Value::Null) => &empty,
            Some(Value::Array(a)) => a,
            Some(_) => return invalid("params must be an array of positional arguments"),
        };
        if params.len() > max_args {
            return invalid(format!("too many arguments, want at most {max_args}"));
        }
        // Not held for readiness: config and the status snapshot only (the
        // NON_BLOCKING list). Every gated arm reaches the engine through
        // `self.engine_ready(g)?`, which holds once per request.
        let e = &self.engine;
        match method {
            // Config-derived: always answerable, no sync needed.
            "eth_chainId" => Ok(json_str(&hex_quantity(e.chain_id()))),
            "net_version" => Ok(json_str(&e.chain_id().to_string())),
            "web3_clientVersion" => Ok(json_str(&self.client_version)),
            // The node holds no keys: the accounts list is exactly empty.
            "eth_accounts" => Ok("[]".into()),
            "net_listening" => Ok("true".into()),
            // The engine's own status object, for clients that want to poll
            // sync progress (the Kotlin router's myotis_status, minus uptime).
            "myotis_status" => {
                let s = e.status_json();
                serde_json::from_str::<Value>(&s)
                    .map(|_| s)
                    .map_err(|_| Fail::Unavailable(None))
            }
            // `false` once SYNCED, else the zeros object: the verified surface has
            // no block-download notion and serves no reads before SYNCED, so zero
            // bounds are the honest report (and never a false 100%). Non-blocking.
            "eth_syncing" => {
                if Readiness::parse(&e.status_json()).beacon_state == "SYNCED" {
                    Ok("false".into())
                } else {
                    Ok(
                        r#"{"startingBlock":"0x0","currentBlock":"0x0","highestBlock":"0x0"}"#
                            .into(),
                    )
                }
            }
            "eth_blockNumber" => {
                let head = self
                    .engine_ready(g)?
                    .head_block_number()
                    .ok_or(Fail::Unavailable(None))?;
                self.reported_heads.record(head);
                Ok(json_str(&hex_quantity(head)))
            }
            "eth_getBalance" => {
                let addr = address_at(params, 0)?;
                let sel = state_selector_at(params, 1, method)?;
                self.pin_servable(&sel, method, g)?;
                // Verified-absent account → balance 0: the proof of exclusion IS
                // the verified answer.
                let acct = self.account(&addr, &sel, g)?;
                Ok(json_str(&acct.balance))
            }
            "eth_getTransactionCount" => {
                let addr = address_at(params, 0)?;
                let sel = state_selector_at(params, 1, method)?;
                self.pin_servable(&sel, method, g)?;
                let mined = self.account(&addr, &sel, g)?.nonce;
                // ONLY the pending tag consults the sent-tx overlay:
                // max(mined, our broadcast nonce + 1) while unmined and unexpired.
                let nonce = if sel.value == "pending" {
                    // The overlay answers max(mined, ours + 1), or -1 for none.
                    let o =
                        e.pending_nonce_overlay(&addr, i64::try_from(mined).unwrap_or(i64::MAX));
                    u64::try_from(o).unwrap_or(mined)
                } else {
                    mined
                };
                Ok(json_str(&hex_quantity(nonce)))
            }
            "eth_getCode" => {
                let addr = address_at(params, 0)?;
                let sel = state_selector_at(params, 1, method)?;
                self.pin_servable(&sel, method, g)?;
                self.in_window(&sel, g)?;
                let o = engine_object(&self.engine_ready(g)?.get_code(&addr, &sel.value))?;
                verified(&o)?;
                let code = engine_bytes(o.get("codeHex")).ok_or(Fail::Unavailable(Some(
                    "malformed codeHex from engine".into(),
                )))?;
                Ok(json_str(&hex_data(&code)))
            }
            "eth_getStorageAt" => {
                let addr = address_at(params, 0)?;
                let slot = word32(required(params, 1, "storage slot")?).ok_or_else(|| {
                    Fail::Invalid(
                        "invalid argument 1: expected a storage slot (a hex quantity or 32-byte word)"
                            .into(),
                    )
                })?;
                let sel = state_selector_at(params, 2, method)?;
                self.pin_servable(&sel, method, g)?;
                self.in_window(&sel, g)?;
                let o = engine_object(&self.engine_ready(g)?.get_storage_at(
                    &addr,
                    &hex_data(&slot),
                    &sel.value,
                ))?;
                verified(&o)?;
                // Left-pad to the full word (an unset slot → 32 zero bytes). A
                // value WIDER than a word is shape drift: fail closed.
                let raw = engine_bytes(o.get("valueHex"))
                    .filter(|r| r.len() <= 32)
                    .ok_or(Fail::Unavailable(Some(
                        "malformed valueHex from engine".into(),
                    )))?;
                let mut w = [0u8; 32];
                w[32 - raw.len()..].copy_from_slice(&raw);
                Ok(json_str(&hex_data(&w)))
            }
            "eth_call" => self.eth_call(params, g),
            "eth_estimateGas" => self.eth_estimate_gas(params, g),
            "eth_gasPrice" | "eth_maxPriorityFeePerGas" => {
                let o = engine_object(&self.engine_ready(g)?.fee_estimate())?;
                let key = if method == "eth_gasPrice" {
                    "gasPriceWei"
                } else {
                    "maxPriorityFeePerGasWei"
                };
                let q = o
                    .get(key)
                    .and_then(|v| v.as_str())
                    .and_then(hex_quantity_decimal);
                q.map(|q| json_str(&q)).ok_or(Fail::Unavailable(None))
            }
            "eth_feeHistory" => {
                let count = fee_history_count_at(params, 0)?;
                // Required, as geth has it: a node that picked a block for the
                // caller would answer a question nobody asked.
                if params.get(1).is_none_or(Value::is_null) {
                    return invalid(
                        "missing argument 1: the newest block (a tag or a 0x-prefixed hex number)",
                    );
                }
                let newest = selector_at(params, 1, Takes::Number)?;
                let pct = reward_percentiles_at(params, 2)?;
                tri_state(
                    &self
                        .engine_ready(g)?
                        .fee_history(count, &newest.value, &pct),
                    false,
                )
            }
            "eth_getBlockByNumber" => {
                let sel = selector_at(params, 0, Takes::Number)?;
                let full = flag_at(params, 1)?;
                tri_state(
                    &self.engine_ready(g)?.block_by_number(&sel.value, full),
                    false,
                )
            }
            "eth_getBlockByHash" => {
                let h = hash_at(params, 0, "block hash")?;
                let full = flag_at(params, 1)?;
                tri_state(&self.engine_ready(g)?.block_by_hash(&h, full), false)
            }
            "eth_getBlockReceipts" => {
                let sel = selector_at(params, 0, Takes::NumberOrHash)?;
                tri_state(&self.engine_ready(g)?.block_receipts(&sel.value), true)
            }
            // Receipt / tx: an object when found+verified, the literal null for a
            // VERIFIED "not seen" (a valid result), or -32000 when it could not
            // check — never "pending" on a healthy chain it did not look at.
            "eth_getTransactionReceipt" => {
                let h = hash_at(params, 0, "transaction hash")?;
                tri_state(&self.engine_ready(g)?.transaction_receipt(&h), false)
            }
            "eth_getTransactionByHash" => {
                let h = hash_at(params, 0, "transaction hash")?;
                tri_state(&self.engine_ready(g)?.transaction_by_hash(&h), false)
            }
            "eth_sendRawTransaction" => {
                let raw = data_at(params, 0, "the signed transaction")?;
                if raw.is_empty() {
                    return invalid("invalid argument 0: the signed transaction is empty");
                }
                let o =
                    engine_object(&self.engine_ready(g)?.send_raw_transaction(&hex_data(&raw)))?;
                // Refused before broadcast: geth's txpool verdict, verbatim under
                // geth's -32000. A reasonless refusal fails closed.
                if o.get("status").and_then(|s| s.as_str()) == Some("rejected") {
                    let reason = o
                        .get("reason")
                        .and_then(|r| r.as_str())
                        .filter(|r| !r.is_empty());
                    return match reason {
                        Some(r) => Err(Fail::Rpc {
                            code: -32000,
                            message: r.into(),
                            data: None,
                        }),
                        None => Err(Fail::Unavailable(Some(
                            "send rejected without a reason".into(),
                        ))),
                    };
                }
                // Fail CLOSED on a missing/short hash: a success with a bogus hash
                // would tell the wallet a send happened.
                let hash = o
                    .get("txHash")
                    .and_then(|h| h.as_str())
                    .and_then(parse_hex)
                    .filter(|h| h.len() == 32)
                    .ok_or(Fail::Unavailable(None))?;
                Ok(json_str(&hex_data(&hash)))
            }
            "eth_getLogs" => {
                // A missing/non-object param is PERMANENTLY malformed.
                let Some(filter) = params.first().filter(|f| f.is_object()) else {
                    return invalid("eth_getLogs expects one filter object param");
                };
                let out = self.engine_ready(g)?.get_logs(&filter.to_string());
                let parsed: Value =
                    serde_json::from_str(out.trim()).map_err(|_| Fail::Unavailable(None))?;
                // The engine owns filter semantics AND the coverage-honesty rule:
                // a range the index has not covered is {"error": ...}, surfaced
                // verbatim so the client sees WHY. -32602 when marked permanent.
                if let Some(err) = parsed.as_object().and_then(|o| o.get("error")) {
                    let msg = err
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| err.to_string());
                    let code = if permanent_code(&parsed) {
                        -32602
                    } else {
                        -32000
                    };
                    return Err(Fail::Rpc {
                        code,
                        message: msg,
                        data: None,
                    });
                }
                if parsed.is_array() {
                    Ok(out.trim().to_string())
                } else {
                    Err(Fail::Unavailable(None))
                }
            }
            _ => Err(Fail::Unsupported),
        }
    }

    fn eth_call(&self, params: &[Value], g: &Gate) -> Out {
        // blockOverrides are never applied: their presence refuses on its own.
        if block_override_present(params) {
            return invalid(OVERRIDE_UNSUPPORTED.replace("{m}", "eth_call"));
        }
        let overrides = match state_override_param(params) {
            OverrideParam::Malformed(why) => {
                return invalid(format!("invalid state override: {why}"))
            }
            OverrideParam::Valid(j) => Some(j),
            OverrideParam::Absent => None,
        };
        let Some(obj) = params.first().and_then(|v| v.as_object()) else {
            return invalid("eth_call expects a transaction object as its first parameter");
        };
        let tx =
            parse_tx(obj).or_else(|why| invalid(format!("invalid transaction object: {why}")))?;
        let sel = state_selector_at(params, 1, "eth_call")?;
        self.check_chain_id(&tx)?;
        self.pin_servable(&sel, "eth_call", g)?;
        let json = if tx.extended {
            let e = self.engine_ready(g)?;
            // Gas, fees or lists: only the transaction-object call applies them.
            e.eth_call_tx(
                &tx.canonical,
                &sel.value,
                overrides.as_deref().unwrap_or(""),
            )
        } else {
            // Nothing beyond from/to/data/value: the plain call, window-checked as
            // the adapters check it (the tx call applies the selector itself).
            self.in_window(&sel, g)?;
            let e = self.engine_ready(g)?;
            let from = tx.from.as_deref().unwrap_or(""); // empty = anonymous sender
            let to = tx.to.as_deref().unwrap_or(""); // empty = contract creation
            match &overrides {
                None => e.eth_call(from, to, &tx.data, &tx.value, &sel.value),
                Some(ov) => e.eth_call_overrides(from, to, &tx.data, &tx.value, &sel.value, ov),
            }
        };
        call_outcome(&json, false)
    }

    fn eth_estimate_gas(&self, params: &[Value], g: &Gate) -> Out {
        if block_override_present(params) {
            return invalid(OVERRIDE_UNSUPPORTED.replace("{m}", "eth_estimateGas"));
        }
        let overrides = match state_override_param(params) {
            OverrideParam::Malformed(why) => {
                return invalid(format!("invalid state override: {why}"))
            }
            OverrideParam::Valid(j) => j,
            OverrideParam::Absent => String::new(),
        };
        let Some(obj) = params.first().and_then(|v| v.as_object()) else {
            return invalid("eth_estimateGas expects a transaction object as its first parameter");
        };
        let tx =
            parse_tx(obj).or_else(|why| invalid(format!("invalid transaction object: {why}")))?;
        let sel = state_selector_at(params, 1, "eth_estimateGas")?;
        self.check_chain_id(&tx)?;
        self.pin_servable(&sel, "eth_estimateGas", g)?;
        // Always the transaction-object estimate: the engine applies the selector
        // and every field, or refuses with the permanent envelope.
        call_outcome(
            &self
                .engine_ready(g)?
                .estimate_gas_tx(&tx.canonical, &sel.value, &overrides),
            true,
        )
    }

    fn check_chain_id(&self, tx: &TxArgs) -> Result<(), Fail> {
        match &tx.chain_id {
            Some(c) if *c != self.engine.chain_id().to_string() => invalid(format!(
                "invalid transaction object: chainId {c} does not match this node's chain ({})",
                self.engine.chain_id()
            )),
            _ => Ok(()),
        }
    }

    /// Judge a number pin against the state window before the engine is asked:
    /// BEHIND it is refused for good (-32602) — no engine holds older state —
    /// unless this node itself recently reported a head at or below the pin;
    /// no verified head known is a retryable decline. Tags pass.
    fn pin_servable(&self, sel: &Selector, method: &str, g: &Gate) -> Result<(), Fail> {
        let Some(n) = sel.number else { return Ok(()) };
        let head = self
            .engine_ready(g)?
            .head_block_number()
            .ok_or(Fail::Unavailable(None))?;
        if n < head.saturating_sub(BLOCK_NUM_LAG_TOLERANCE) {
            if self.reported_heads.lowest().is_some_and(|low| n >= low) {
                return Err(Fail::Unavailable(None));
            }
            return invalid(format!(
                "{method} at block {n} is not supported: it is more than \
                 {BLOCK_NUM_LAG_TOLERANCE} blocks behind the verified head ({head}), and this node \
                 holds no historical state"
            ));
        }
        Ok(())
    }

    /// The adapters' serving window (`RpcBlockWindow.blockInWindow`): a number
    /// pin is served from head state only within [head-64, head+16]; ahead of
    /// it is a retryable decline (the head may yet reach it).
    fn in_window(&self, sel: &Selector, g: &Gate) -> Result<(), Fail> {
        let Some(n) = sel.number else { return Ok(()) };
        let head = self
            .engine_ready(g)?
            .head_block_number()
            .ok_or(Fail::Unavailable(None))?;
        if n + BLOCK_NUM_LAG_TOLERANCE >= head && n <= head + BLOCK_NUM_TOLERANCE {
            Ok(())
        } else {
            Err(Fail::Unavailable(Some(format!(
                "block {n} is outside the served window around the verified head ({head})"
            ))))
        }
    }

    fn account(&self, address: &str, sel: &Selector, g: &Gate) -> Result<Account, Fail> {
        self.in_window(sel, g)?;
        let o = engine_object(&self.engine_ready(g)?.request_account(address, &sel.value))?;
        verified(&o)?;
        parse_account(&o)
    }
}

const OVERRIDE_UNSUPPORTED: &str = "method '{m}' with state/block overrides is not supported by \
    this node (the override was rejected, not ignored — a result computed without it would answer \
    a different question than you asked)";

/// A verified account read, ready for the wire.
#[derive(Debug, PartialEq)]
struct Account {
    /// QUANTITY-encoded balance (`0x0` for a verified-absent account).
    balance: String,
    nonce: u64,
}

/// Read a VERIFIED account object, failing closed: `exists` must be a boolean,
/// and an existing account needs a non-negative integer `nonce` and a decimal
/// `balanceWei`. Anything else is engine shape drift — retryable (-32000),
/// never a verified 0. Only a proof of exclusion (`exists: false`) answers 0.
fn parse_account(o: &Map<String, Value>) -> Result<Account, Fail> {
    let drift = |what: &str| Fail::Unavailable(Some(format!("malformed {what} from engine")));
    match o.get("exists") {
        Some(Value::Bool(false)) => Ok(Account {
            balance: "0x0".into(),
            nonce: 0,
        }),
        Some(Value::Bool(true)) => Ok(Account {
            nonce: o
                .get("nonce")
                .and_then(Value::as_u64)
                .ok_or_else(|| drift("nonce"))?,
            balance: o
                .get("balanceWei")
                .and_then(Value::as_str)
                .and_then(hex_quantity_decimal)
                .ok_or_else(|| drift("balance"))?,
        }),
        _ => Err(drift("account (no boolean 'exists')")),
    }
}

// ---------------------------------------------------------------------------
// Engine JSON reading.
// ---------------------------------------------------------------------------

/// The engine's error envelope: `{"error": …}` (retryable) or
/// `{"error": …, "code": -32602}` (permanent). Anything else — including an
/// object that merely HAS an error key among others — is a result. Returns the
/// message and whether it is permanent.
fn error_envelope_of(v: &Value) -> Option<(String, bool)> {
    let o = v.as_object()?;
    let err = o.get("error")?;
    if !(o.len() == 1 || (o.len() == 2 && o.contains_key("code"))) {
        return None;
    }
    let msg = err
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| err.to_string());
    Some((msg, permanent_code(v)))
}

fn permanent_code(v: &Value) -> bool {
    v.get("code").and_then(|c| c.as_i64()) == Some(-32602)
}

fn envelope_fail(msg: String, permanent: bool) -> Fail {
    if permanent {
        Fail::Refused(msg)
    } else {
        Fail::Unavailable(Some(msg))
    }
}

/// A result-object read (account, code, storage, fees, call, send): the
/// object, or the engine's error as a [`Fail`]. Any non-null `error` key counts.
fn engine_object(json: &str) -> Result<Map<String, Value>, Fail> {
    let v: Value = serde_json::from_str(json.trim()).map_err(|_| Fail::Unavailable(None))?;
    if let Some((msg, permanent)) = error_envelope_of(&v) {
        return Err(envelope_fail(msg, permanent));
    }
    match v {
        Value::Object(o) if o.get("error").is_none_or(Value::is_null) => Ok(o),
        Value::Object(o) => Err(Fail::Unavailable(o.get("error").map(|e| e.to_string()))),
        _ => Err(Fail::Unavailable(None)),
    }
}

/// A state read produced a verdict only when `verifyMethod` is set; otherwise
/// it could not be verified right now (`failReason` says why).
fn verified(o: &Map<String, Value>) -> Result<(), Fail> {
    if o.get("verifyMethod").is_some_and(|v| v.is_string()) {
        return Ok(());
    }
    Err(Fail::Unavailable(
        o.get("failReason")
            .and_then(|r| r.as_str())
            .map(str::to_owned),
    ))
}

/// The tri-state JSON reads (blocks, receipts, txs, fee history): the found
/// object (an ARRAY for block receipts), the literal `null` (a verified
/// "unknown" — a valid null result), or the engine's error envelope.
fn tri_state(json: &str, array: bool) -> Out {
    let t = json.trim();
    if t == "null" {
        return Ok("null".into());
    }
    let v: Value = serde_json::from_str(t).map_err(|_| Fail::Unavailable(None))?;
    if let Some((msg, permanent)) = error_envelope_of(&v) {
        return Err(envelope_fail(msg, permanent));
    }
    if (array && v.is_array()) || (!array && v.is_object()) {
        Ok(t.to_string())
    } else {
        Err(Fail::Unavailable(None))
    }
}

/// The engine's call / estimate JSON as a result or a [`Fail`]: `ok` →
/// return data (or gas), `revert` → geth's code 3 with the payload (a
/// VERIFIED answer), `infeasible` → geth's -32000 in geth's words, the
/// permanent envelope → -32602, anything else → retryable.
fn call_outcome(json: &str, estimate: bool) -> Out {
    let o = engine_object(json)?;
    let unavailable = |why: &str| Err(Fail::Unavailable(Some(why.into())));
    match o.get("status").and_then(|s| s.as_str()) {
        Some("ok") if estimate => match o.get("gas").and_then(|g| g.as_u64()) {
            Some(gas) => Ok(json_str(&hex_quantity(gas))),
            None => unavailable("ok without gas"),
        },
        Some("ok") => match engine_bytes(o.get("resultHex")) {
            Some(b) => Ok(json_str(&hex_data(&b))),
            None => unavailable("malformed resultHex from engine"),
        },
        // Malformed dataHex is shape drift: retryable, never a definitive revert.
        Some("revert") => match engine_bytes(o.get("dataHex")) {
            Some(d) => Err(revert_fail(&d)),
            None => unavailable("malformed dataHex from engine"),
        },
        Some("infeasible") => match o
            .get("reason")
            .and_then(|r| r.as_str())
            .filter(|r| !r.is_empty())
        {
            Some(r) => Err(Fail::Rpc {
                code: -32000,
                message: r.into(),
                data: None,
            }),
            None => unavailable("infeasible without a reason from engine"),
        },
        _ => Err(Fail::Unavailable(
            o.get("reason").and_then(|r| r.as_str()).map(str::to_owned),
        )),
    }
}

/// geth's execution-reverted error: code 3, `data` = the raw payload, the
/// message suffixed with a decoded `Error(string)` / `Panic(uint256)`.
fn revert_fail(data: &[u8]) -> Fail {
    let message = match decode_revert_reason(data) {
        Some(r) => format!("execution reverted: {r}"),
        None => "execution reverted".into(),
    };
    Fail::Rpc {
        code: 3,
        message,
        data: Some(hex_data(data)),
    }
}

/// Best-effort human reason from a revert payload; `None` for custom errors or
/// anything malformed (the raw payload is always in `data`). Bounds are
/// attacker-controlled and checked at every step; the text is reduced to
/// printable ASCII so it can neither forge log lines nor spoof a UI.
fn decode_revert_reason(d: &[u8]) -> Option<String> {
    // A 32-byte ABI word as u64 — only when its high 24 bytes are zero.
    let word = |at: usize| -> Option<u64> {
        let w = d.get(at..at.checked_add(32)?)?;
        if w[..24].iter().any(|&b| b != 0) {
            return None;
        }
        Some(
            w[24..]
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
        )
    };
    if d.len() >= 36 && d[..4] == [0x4e, 0x48, 0x7b, 0x71] {
        return Some(format!("panic 0x{:x}", word(4)?));
    }
    if d.len() < 68 || d[..4] != [0x08, 0xc3, 0x79, 0xa0] {
        return None;
    }
    let off = usize::try_from(word(4)?).ok()?;
    let len_pos = 4usize.checked_add(off)?;
    let len = usize::try_from(word(len_pos)?).ok()?;
    if len > 1024 {
        return None;
    }
    let start = len_pos.checked_add(32)?;
    let bytes = d.get(start..start.checked_add(len)?)?;
    let s = String::from_utf8_lossy(bytes);
    Some(
        s.chars()
            .map(|c| if (' '..='~').contains(&c) { c } else { ' ' })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Parameter reading (the Kotlin router's JsonArray extensions).
// ---------------------------------------------------------------------------

fn required<'a>(p: &'a [Value], i: usize, what: &str) -> Result<&'a Value, Fail> {
    p.get(i)
        .filter(|v| !v.is_null())
        .ok_or_else(|| Fail::Invalid(format!("missing argument {i}: {what}")))
}

fn hex_bytes(v: &Value) -> Option<Vec<u8>> {
    v.as_str().and_then(parse_hex)
}

/// params[i] as a 20-byte address, returned as lowercase 0x-hex.
fn address_at(p: &[Value], i: usize) -> Result<String, Fail> {
    hex_bytes(required(p, i, "address")?)
        .filter(|b| b.len() == 20)
        .map(|b| hex_data(&b))
        .ok_or_else(|| {
            Fail::Invalid(format!(
                "invalid argument {i}: expected a 20-byte address (0x + 40 hex digits)"
            ))
        })
}

fn hash_at(p: &[Value], i: usize, what: &str) -> Result<String, Fail> {
    hex_bytes(required(p, i, what)?)
        .filter(|b| b.len() == 32)
        .map(|b| hex_data(&b))
        .ok_or_else(|| {
            Fail::Invalid(format!(
                "invalid argument {i}: expected a 32-byte {what} (0x + 64 hex digits)"
            ))
        })
}

fn data_at(p: &[Value], i: usize, what: &str) -> Result<Vec<u8>, Fail> {
    hex_bytes(required(p, i, what)?).ok_or_else(|| {
        Fail::Invalid(format!(
            "invalid argument {i}: expected {what} as 0x-prefixed hex"
        ))
    })
}

/// The `fullTransactions` flag: absent or null is false; any other
/// non-boolean is refused, never coerced into a different shape.
fn flag_at(p: &[Value], i: usize) -> Result<bool, Fail> {
    match p.get(i) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => invalid(format!("invalid argument {i}: expected a boolean")),
    }
}

/// A storage position (QUANTITY or 32-byte DATA) as a left-padded word.
fn word32(v: &Value) -> Option<[u8; 32]> {
    let s = v.as_str()?;
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.is_empty() || h.len() > 64 {
        return None;
    }
    let padded = if h.len() % 2 == 1 {
        format!("0{h}")
    } else {
        h.to_string()
    };
    let raw = parse_hex(&padded)?;
    let mut w = [0u8; 32];
    w[32 - raw.len()..].copy_from_slice(&raw);
    Some(w)
}

fn is_hex(s: &str) -> bool {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The ONE reading of a block selector (#366): applied or refused, never
/// silently read as the head.
/// - absent or null: `latest`;
/// - `latest`, `pending`, `finalized` (the Rust engine applies it, ABI ≥ 32);
///   `safe` and `earliest` refused — nothing here serves the safe head or genesis;
/// - a number: 0x-hex only (bare digits refused rather than guessed), not 0;
/// - where the method takes a `BlockNumberOrHash`: a 32-byte hash, bare or as
///   `{"blockHash"}`, and `{"blockNumber"}` for a number.
fn parse_selector(param: Option<&Value>, arg: usize, takes: Takes) -> Result<Selector, Fail> {
    let refuse = |why: String| Err(Fail::Invalid(format!("invalid argument {arg}: {why}")));
    let mut hash_allowed = takes == Takes::NumberOrHash;
    let raw: String = match param {
        None | Some(Value::Null) => "latest".into(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Object(o)) => {
            if takes != Takes::NumberOrHash {
                return refuse(
                    "expected a block tag or number; this method takes no EIP-1898 block object"
                        .into(),
                );
            }
            let by_hash = o.get("blockHash").filter(|v| !v.is_null());
            let by_number = o.get("blockNumber").filter(|v| !v.is_null());
            if let Some(rc) = o.get("requireCanonical").filter(|v| !v.is_null()) {
                if !rc.is_boolean() {
                    return refuse("'requireCanonical' must be a boolean".into());
                }
            }
            match (by_hash, by_number) {
                (Some(_), Some(_)) => {
                    return refuse(
                        "a block object takes 'blockHash' or 'blockNumber', not both".into(),
                    )
                }
                (Some(h), None) => {
                    let h = h.as_str().map(str::trim).unwrap_or("");
                    if h.len() != 66 || !is_hex(h) {
                        return refuse(
                            "'blockHash' must be a 32-byte hash (0x + 64 hex digits)".into(),
                        );
                    }
                    return Ok(Selector {
                        value: h.to_ascii_lowercase(),
                        number: None,
                        hash: true,
                    });
                }
                (None, Some(n)) => {
                    hash_allowed = false;
                    match n.as_str() {
                        Some(s) => s.trim().to_string(),
                        None => {
                            return refuse(
                                "'blockNumber' must be a block tag or a 0x-prefixed hex number"
                                    .into(),
                            )
                        }
                    }
                }
                (None, None) => {
                    return refuse("a block object needs 'blockHash' or 'blockNumber'".into())
                }
            }
        }
        Some(_) => {
            return refuse(
                "expected a block tag or a 0x-prefixed hex block number as a JSON string".into(),
            )
        }
    };
    if raw.is_empty() {
        return refuse(
            "an empty string names no block; ask for 'latest' or a 0x-prefixed hex number".into(),
        );
    }
    match raw.as_str() {
        "latest" | "pending" | "finalized" => {
            return Ok(Selector { value: raw, number: None, hash: false })
        }
        "safe" => {
            return refuse("the 'safe' tag is not served: this node tracks the verified head and the \
                beacon-finalized block, not the safe (justified) head; ask for 'latest' or 'finalized'"
                .into())
        }
        "earliest" => {
            return refuse("the 'earliest' tag (genesis) is not served: this node holds recent blocks \
                and state only"
                .into())
        }
        _ => {}
    }
    if raw.len() <= 2 || !is_hex(&raw) {
        let shown: String = raw.chars().take(70).collect();
        let tail = if takes == Takes::NumberOrHash {
            " or block hash"
        } else {
            ""
        };
        return refuse(format!(
            "invalid block selector '{shown}': expected latest, pending, finalized or a 0x-prefixed \
             hex block number{tail}"
        ));
    }
    if raw.len() == 66 && hash_allowed {
        return Ok(Selector {
            value: raw.to_ascii_lowercase(),
            number: None,
            hash: true,
        });
    }
    if raw.len() == 66 && takes == Takes::Number {
        return refuse(
            "a block hash is not a block number; this method takes a number or a tag".into(),
        );
    }
    let digits = raw[2..].trim_start_matches('0');
    let n = if digits.is_empty() {
        0
    } else if digits.len() <= 16 {
        match u64::from_str_radix(digits, 16) {
            Ok(n) if n <= i64::MAX as u64 => n,
            _ => return refuse(format!("block number {raw} is out of range")),
        }
    } else {
        return refuse(format!("block number {raw} is out of range"));
    };
    if n == 0 {
        return refuse(
            "block 0 (genesis) is not served: this node holds recent blocks and state only".into(),
        );
    }
    Ok(Selector {
        value: format!("0x{n:x}"),
        number: Some(n),
        hash: false,
    })
}

fn selector_at(p: &[Value], i: usize, takes: Takes) -> Result<Selector, Fail> {
    parse_selector(p.get(i), i, takes)
}

/// A state read's selector: a `BlockNumberOrHash`, but a hash names historical
/// state this node does not hold — refused, never answered from the head.
fn state_selector_at(p: &[Value], i: usize, method: &str) -> Result<Selector, Fail> {
    let sel = selector_at(p, i, Takes::NumberOrHash)?;
    if sel.hash {
        return invalid(format!(
            "{method} at a block hash is not supported (this node holds no historical state)"
        ));
    }
    Ok(sel)
}

/// `eth_feeHistory`'s block count: a hex or decimal string or a JSON number,
/// at least 1, clamped to geth's 1024.
fn fee_history_count_at(p: &[Value], i: usize) -> Result<i64, Fail> {
    let v = required(p, i, "block count")?;
    let s = match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let dec = parse_wei_quantity(&s).ok_or_else(|| {
        Fail::Invalid(format!(
            "invalid argument {i}: expected the block count as a quantity"
        ))
    })?;
    if dec == "0" {
        return invalid(format!(
            "invalid argument {i}: the block count must be at least 1"
        ));
    }
    Ok(dec
        .parse::<i64>()
        .unwrap_or(i64::MAX)
        .min(MAX_FEE_HISTORY_BLOCKS))
}

/// `eth_feeHistory`'s reward percentiles as the engine's JSON array, or empty
/// for none: JSON numbers in [0, 100], non-decreasing, at most 100.
fn reward_percentiles_at(p: &[Value], i: usize) -> Result<String, Fail> {
    let arr = match p.get(i) {
        None | Some(Value::Null) => return Ok(String::new()),
        Some(Value::Array(a)) => a,
        Some(_) => {
            return invalid(format!(
                "invalid argument {i}: expected the reward percentiles as an array"
            ))
        }
    };
    if arr.is_empty() {
        return Ok(String::new());
    }
    if arr.len() > MAX_FEE_HISTORY_PERCENTILES {
        return invalid(format!(
            "invalid argument {i}: at most {MAX_FEE_HISTORY_PERCENTILES} reward percentiles, got {}",
            arr.len()
        ));
    }
    let mut vals: Vec<f64> = Vec::with_capacity(arr.len());
    for v in arr {
        let d = v.as_f64().ok_or_else(|| {
            Fail::Invalid(format!(
                "invalid argument {i}: reward percentiles must be JSON numbers"
            ))
        })?;
        if !(0.0..=100.0).contains(&d) {
            return invalid(format!(
                "invalid argument {i}: reward percentile {d} is outside [0, 100]"
            ));
        }
        if vals.last().is_some_and(|&prev| prev > d) {
            return invalid(format!(
                "invalid argument {i}: reward percentiles must be non-decreasing"
            ));
        }
        vals.push(d);
    }
    Ok(serde_json::to_string(&vals).unwrap_or_default())
}

/// `params[2]`, the state override: absent (nothing to apply), valid, or
/// malformed — never collapsed, because serving a malformed one as absent
/// answers a question the caller did not ask.
fn state_override_param(p: &[Value]) -> OverrideParam {
    let ov = match p.get(2) {
        None | Some(Value::Null) => return OverrideParam::Absent,
        Some(Value::Object(o)) => o,
        Some(_) => {
            return OverrideParam::Malformed(
                "state override must be an object keyed by address".into(),
            )
        }
    };
    let mut changes = false;
    for (addr, entry) in ov {
        if addr.len() != 42 || !is_hex(addr) {
            return OverrideParam::Malformed(format!(
                "state override key '{addr}' is not a 20-byte address"
            ));
        }
        let fields = match entry {
            Value::Null => continue, // "no override for this account", as geth reads it
            Value::Object(f) => f,
            _ => {
                return OverrideParam::Malformed(format!(
                    "state override for '{addr}' must be an object"
                ))
            }
        };
        if let Some(k) = fields
            .keys()
            .find(|k| !OVERRIDE_FIELDS.contains(&k.as_str()))
        {
            return OverrideParam::Malformed(format!("unsupported state override field '{k}'"));
        }
        changes |= !fields.is_empty();
    }
    if changes {
        OverrideParam::Valid(Value::Object(ov.clone()).to_string())
    } else {
        OverrideParam::Absent
    }
}

/// `params[3]`, blockOverrides — never applied, so anything but absent, null
/// or an empty object is present (and refused).
fn block_override_present(p: &[Value]) -> bool {
    match p.get(3) {
        None | Some(Value::Null) => false,
        Some(Value::Object(o)) => !o.is_empty(),
        Some(_) => true,
    }
}

/// Shape-check a transaction object. The cross-field rules (fee/type
/// consistency, EIP-7702 lists) are the engine's `parse_tx_request` +
/// `TxRequest::validate`, which refuse with the permanent envelope on the
/// transaction-object path; what is checked here is what the PLAIN call path
/// would otherwise silently drop.
fn parse_tx(obj: &Map<String, Value>) -> Result<TxArgs, String> {
    let field = |k: &str| obj.get(k).filter(|v| !v.is_null());
    for blob in BLOB_FIELDS {
        if let Some(v) = field(blob) {
            if v.as_array().is_none_or(|a| !a.is_empty()) {
                return Err(format!(
                    "blob transactions (type 0x3) are not supported by this node ('{blob}')"
                ));
            }
        }
    }
    let address = |k: &str| -> Result<Option<String>, String> {
        field(k)
            .map(|v| {
                hex_bytes(v)
                    .filter(|b| b.len() == 20)
                    .map(|b| hex_data(&b))
                    .ok_or(format!("'{k}' is not a 20-byte hex address"))
            })
            .transpose()
    };
    let from = address("from")?;
    let to = address("to")?;
    let bytes = |k: &str| -> Result<Option<Vec<u8>>, String> {
        field(k)
            .map(|v| hex_bytes(v).ok_or(format!("'{k}' is not hex data")))
            .transpose()
    };
    let data = match (bytes("input")?, bytes("data")?) {
        (Some(i), Some(d)) if i != d => {
            return Err("both 'data' and 'input' are set and not equal; use 'input'".into())
        }
        (Some(d), _) | (None, Some(d)) => d,
        (None, None) => Vec::new(),
    };
    let mut canonical = obj.clone();
    let mut q = std::collections::HashMap::new();
    for k in TX_QUANTITIES {
        if let Some(v) = field(k) {
            let dec = v
                .as_str()
                .and_then(|s| parse_wei_quantity(s.trim()))
                .ok_or(format!("'{k}' is not a quantity"))?;
            canonical.insert(
                k.into(),
                Value::String(format!("0x{}", decimal_to_hex(&dec))),
            );
            q.insert(k, dec);
        }
    }
    if let Some(t) = q.get("type") {
        match t.as_str() {
            "0" | "1" | "2" | "4" => {}
            "3" => {
                return Err("blob transactions (type 0x3) are not supported by this node".into())
            }
            other => {
                return Err(format!(
                    "unsupported transaction type 0x{}",
                    decimal_to_hex(other)
                ));
            }
        }
    }
    if q.contains_key("gasPrice")
        && (q.contains_key("maxFeePerGas") || q.contains_key("maxPriorityFeePerGas"))
    {
        return Err("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified".into());
    }
    let access_list =
        field("accessList").is_some_and(|a| a.as_array().is_none_or(|a| !a.is_empty()));
    // An explicit `type` is extended too, whatever its value: the plain call
    // has no type to pass, so it would drop it; the transaction-object call
    // applies it or refuses it (type 0x4 without an authorizationList, …).
    let extended = [
        "type",
        "gas",
        "gasPrice",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
    ]
    .iter()
    .any(|k| q.contains_key(k))
        || access_list
        || field("authorizationList").is_some()
        || (to.is_none() && q.contains_key("nonce"));
    Ok(TxArgs {
        from,
        to,
        data: if data.is_empty() {
            String::new()
        } else {
            hex_data(&data)
        },
        value: q.get("value").cloned().unwrap_or_default(),
        chain_id: q.get("chainId").cloned(),
        extended,
        canonical: Value::Object(canonical).to_string(),
    })
}

// ---------------------------------------------------------------------------
// Envelopes.
// ---------------------------------------------------------------------------

/// A JSON-RPC id may be a string, a FINITE number or null — not a boolean,
/// object or array.
fn valid_id(id: &Value) -> bool {
    matches!(id, Value::Null | Value::String(_) | Value::Number(_))
}

fn json_str(s: &str) -> String {
    Value::String(s.into()).to_string()
}

/// `result` is already-serialized JSON, embedded verbatim (a full-transaction
/// block can run to megabytes; it is not re-encoded).
fn result_envelope(id: &Value, result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

fn error_envelope(id: &Value, code: i64, message: &str, data: Option<&str>) -> String {
    let mut err = Map::new();
    err.insert("code".into(), code.into());
    err.insert("message".into(), message.into());
    if let Some(d) = data {
        err.insert("data".into(), d.into());
    }
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{}}}"#,
        Value::Object(err)
    )
}

/// Strings longer than this are shortened in the call log.
const CALL_LOG_MAX_STR: usize = 200;
/// A result longer than this (serialized) is logged as its size and a hash.
const CALL_LOG_MAX_RESULT: usize = 600;

/// One `--log-calls` line. A result is the raw JSON the router served: only a
/// short one is parsed (to embed it); a long one is logged by its length and
/// hash, and a long array by its element count, read without building it.
fn call_log_line(method: &str, params: Option<&Value>, outcome: Logged, ms: u128) -> String {
    let mut line = Map::new();
    line.insert("ts".into(), Value::from(unix_millis_iso()));
    line.insert("method".into(), Value::from(method));
    line.insert("params".into(), params.map(shorten).unwrap_or(Value::Null));
    match outcome {
        Logged::Error { code, message } => {
            line.insert("outcome".into(), Value::from("error"));
            line.insert("code".into(), Value::from(code));
            line.insert("message".into(), Value::from(message));
        }
        Logged::Result(text) => {
            let text = text.trim();
            let outcome = if text == "null" { "null" } else { "ok" };
            line.insert("outcome".into(), Value::from(outcome));
            if text.len() <= CALL_LOG_MAX_RESULT {
                let result = serde_json::from_str(text).unwrap_or(Value::Null);
                line.insert("result".into(), result);
            } else {
                let mut summary = Map::new();
                if text.starts_with('[') {
                    if let Ok(items) = serde_json::from_str::<Vec<serde::de::IgnoredAny>>(text) {
                        summary.insert("items".into(), Value::from(items.len()));
                    }
                }
                summary.insert("bytes".into(), Value::from(text.len()));
                summary.insert(
                    "fnv64".into(),
                    Value::from(format!("{:016x}", fnv64(text.as_bytes()))),
                );
                line.insert("result".into(), Value::Object(summary));
            }
        }
    }
    line.insert("ms".into(), Value::from(ms as u64));
    Value::Object(line).to_string()
}

/// Params with every long string cut to its head plus its full length.
fn shorten(v: &Value) -> Value {
    match v {
        Value::String(s) if s.len() > CALL_LOG_MAX_STR => Value::from(format!(
            "{}…(+{} chars)",
            &s[..s.floor_char_boundary(CALL_LOG_MAX_STR)],
            s.len() - s.floor_char_boundary(CALL_LOG_MAX_STR)
        )),
        Value::Array(a) => Value::Array(a.iter().map(shorten).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), shorten(v))).collect()),
        other => other.clone(),
    }
}

fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ *b as u64).wrapping_mul(0x100000001b3)
    })
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` from the system clock, with no date-time
/// dependency (Howard Hinnant's civil-from-days).
fn unix_millis_iso() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let (secs, milli) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    )
}

#[cfg(test)]
pub(crate) mod tests;
