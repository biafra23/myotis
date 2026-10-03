//! Envelope and engine-JSON reading tests. The engine replies below are the
//! shapes pinned by the engine's own golden tests (eljson.rs: account_json,
//! call_json, estimate_json, fee_json, get_logs_json, send_rejected_json, the
//! error / invalid-params envelopes), so a reshaped engine fails here too.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;

const ADDR: &str = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
const TOKEN: &str = "0xdbf3ea6f5bee45c02255b2c26a16f300502f68da";

/// account_json golden (exists).
fn account(balance: &str, nonce: i64) -> String {
    json!({
        "address": ADDR, "exists": true, "nonce": nonce, "balanceWei": balance,
        "storageRootHex": "0x33", "codeHashHex": "0x44", "blockNumber": 21_000_000,
        "verifyMethod": "headerChain", "failReason": null, "anchor": "head"
    })
    .to_string()
}

const ABSENT: &str = r#"{"address":"0xabc","exists":false,"nonce":-1,"balanceWei":null,"verifyMethod":"headerChain","failReason":null}"#;
const UNVERIFIED: &str = r#"{"address":"0xabc","exists":false,"nonce":-1,"balanceWei":null,"verifyMethod":null,"failReason":"beaconNotSynced","matchedBeaconSlot":-1}"#;
const SYNCED: &str = r#"{"running":true,"beaconState":"SYNCED","elReaderAvailable":true,"optimisticBlockNumber":1000,"snapServingPeers":3}"#;

/// A recorded engine: canned replies per method, and the calls it saw.
pub(crate) struct Fake {
    replies: HashMap<&'static str, String>,
    head: Option<u64>,
    pub(crate) status: String,
    overlay: i64,
    calls: Mutex<Vec<String>>,
    /// How many times the status was read (the readiness hold polls it).
    status_reads: AtomicUsize,
}

impl Fake {
    pub(crate) fn new() -> Self {
        Fake {
            replies: HashMap::new(),
            head: Some(1000),
            status: SYNCED.into(),
            overlay: -1,
            calls: Mutex::new(Vec::new()),
            status_reads: AtomicUsize::new(0),
        }
    }
    fn reply(mut self, method: &'static str, json: &str) -> Self {
        self.replies.insert(method, json.into());
        self
    }
    fn get(&self, method: &'static str, args: String) -> String {
        self.calls.lock().unwrap().push(format!("{method}({args})"));
        self.replies
            .get(method)
            .cloned()
            .unwrap_or_else(|| r#"{"error":"not stubbed"}"#.into())
    }
}

impl Engine for Fake {
    fn chain_id(&self) -> u64 {
        100
    }
    fn status_json(&self) -> String {
        self.status_reads.fetch_add(1, Ordering::SeqCst);
        self.status.clone()
    }
    fn log_index_status_json(&self) -> String {
        "{}".into()
    }
    fn head_block_number(&self) -> Option<u64> {
        self.head
    }
    fn request_account(&self, a: &str, b: &str) -> String {
        self.get("account", format!("{a},{b}"))
    }
    fn pending_nonce_overlay(&self, _: &str, _: i64) -> i64 {
        self.overlay
    }
    fn get_code(&self, a: &str, b: &str) -> String {
        self.get("code", format!("{a},{b}"))
    }
    fn get_storage_at(&self, a: &str, p: &str, b: &str) -> String {
        self.get("storage", format!("{a},{p},{b}"))
    }
    fn eth_call(&self, f: &str, t: &str, d: &str, v: &str, b: &str) -> String {
        self.get("call", format!("{f},{t},{d},{v},{b}"))
    }
    fn eth_call_overrides(&self, f: &str, t: &str, d: &str, v: &str, b: &str, o: &str) -> String {
        self.get("call_overrides", format!("{f},{t},{d},{v},{b},{o}"))
    }
    fn eth_call_tx(&self, tx: &str, b: &str, o: &str) -> String {
        self.get("call_tx", format!("{tx}|{b}|{o}"))
    }
    fn estimate_gas_tx(&self, tx: &str, b: &str, o: &str) -> String {
        self.get("estimate_tx", format!("{tx}|{b}|{o}"))
    }
    fn block_by_number(&self, t: &str, f: bool) -> String {
        self.get("block", format!("{t},{f}"))
    }
    fn block_by_hash(&self, h: &str, f: bool) -> String {
        self.get("block_hash", format!("{h},{f}"))
    }
    fn fee_estimate(&self) -> String {
        self.get("fee", String::new())
    }
    fn fee_history(&self, c: i64, n: &str, p: &str) -> String {
        self.get("fee_history", format!("{c},{n},{p}"))
    }
    fn send_raw_transaction(&self, r: &str) -> String {
        self.get("send", r.into())
    }
    fn transaction_receipt(&self, h: &str) -> String {
        self.get("receipt", h.into())
    }
    fn transaction_by_hash(&self, h: &str) -> String {
        self.get("tx", h.into())
    }
    fn block_receipts(&self, s: &str) -> String {
        self.get("block_receipts", s.into())
    }
    fn get_logs(&self, f: &str) -> String {
        self.get("logs", f.into())
    }
}

fn call(r: &Router<Fake>, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}).to_string();
    serde_json::from_str(&r.handle(&body).expect("a response")).expect("valid JSON")
}

fn result(r: &Router<Fake>, method: &str, params: Value) -> Value {
    let v = call(r, method, params);
    assert!(v.get("error").is_none(), "{method}: unexpected error {v}");
    assert_eq!(v["id"], 7);
    v["result"].clone()
}

fn error(r: &Router<Fake>, method: &str, params: Value) -> (i64, String, Value) {
    let v = call(r, method, params);
    let e = &v["error"];
    assert!(e.is_object(), "{method}: expected an error, got {v}");
    (
        e["code"].as_i64().unwrap(),
        e["message"].as_str().unwrap().to_string(),
        e["data"].clone(),
    )
}

fn calls(r: &Router<Fake>) -> Vec<String> {
    r.engine().calls.lock().unwrap().clone()
}

#[test]
fn constants_need_no_engine_read() {
    let r = Router::new(Fake::new());
    assert_eq!(result(&r, "eth_chainId", json!([])), "0x64");
    assert_eq!(result(&r, "net_version", json!([])), "100");
    assert!(result(&r, "web3_clientVersion", json!([]))
        .as_str()
        .unwrap()
        .starts_with("myotis-rpcd/"));
    assert_eq!(result(&r, "eth_accounts", json!([])), json!([]));
    assert_eq!(result(&r, "net_listening", json!(null)), true);
    assert_eq!(result(&r, "eth_blockNumber", json!([])), "0x3e8");
    assert!(calls(&r).is_empty());
}

#[test]
fn envelope_rules() {
    let r = Router::new(Fake::new());
    let parse: Value = serde_json::from_str(&r.handle("{nope").unwrap()).unwrap();
    assert_eq!(parse["error"]["code"], -32700);
    let empty: Value = serde_json::from_str(&r.handle("[]").unwrap()).unwrap();
    assert_eq!(empty["error"]["code"], -32600);
    let bad_version: Value = serde_json::from_str(
        &r.handle(r#"{"jsonrpc":"1.0","id":1,"method":"eth_chainId"}"#)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bad_version["error"]["code"], -32600);
    // A notification is served but never answered.
    assert_eq!(
        r.handle(r#"{"jsonrpc":"2.0","method":"eth_chainId"}"#),
        None
    );
    // Unknown method, and too many arguments.
    assert_eq!(error(&r, "eth_mining", json!([])).0, -32601);
    assert_eq!(error(&r, "eth_chainId", json!([1])).0, -32602);
    assert_eq!(error(&r, "eth_getBalance", json!({"a":1})).0, -32602);
}

#[test]
fn batches_answer_each_element_by_id() {
    let r = Router::new(Fake::new().reply("account", &account("5", 1)));
    let body = format!(
        r#"[{{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}},
            {{"jsonrpc":"2.0","method":"eth_chainId"}},
            {{"jsonrpc":"2.0","id":"b","method":"eth_getBalance","params":["{ADDR}","latest"]}},
            42]"#
    );
    let v: Value = serde_json::from_str(&r.handle(&body).unwrap()).unwrap();
    let a = v.as_array().unwrap();
    assert_eq!(a.len(), 3, "the notification gets no element: {v}");
    assert_eq!(a[0]["id"], 1);
    assert_eq!(a[0]["result"], "0x64");
    assert_eq!(a[1]["id"], "b");
    assert_eq!(a[1]["result"], "0x5");
    assert_eq!(a[2]["error"]["code"], -32600);
    // A batch of only notifications has nothing to answer.
    assert_eq!(
        r.handle(r#"[{"jsonrpc":"2.0","method":"eth_chainId"}]"#),
        None
    );
}

#[test]
fn balance_and_nonce_from_the_account_proof() {
    let r = Router::new(Fake::new().reply("account", &account("1000000000000000000", 5898)));
    assert_eq!(
        result(&r, "eth_getBalance", json!([ADDR, "latest"])),
        "0xde0b6b3a7640000"
    );
    assert_eq!(
        result(&r, "eth_getTransactionCount", json!([ADDR])),
        "0x170a"
    );
    assert_eq!(calls(&r)[0], format!("account({ADDR},latest)"));
    // Verified-absent → 0, for both.
    let r = Router::new(Fake::new().reply("account", ABSENT));
    assert_eq!(result(&r, "eth_getBalance", json!([ADDR, "latest"])), "0x0");
    assert_eq!(
        result(&r, "eth_getTransactionCount", json!([ADDR, "latest"])),
        "0x0"
    );
}

#[test]
fn pending_nonce_consults_the_overlay_only_for_pending() {
    let mut f = Fake::new().reply("account", &account("0", 4));
    f.overlay = 9;
    let r = Router::new(f);
    assert_eq!(
        result(&r, "eth_getTransactionCount", json!([ADDR, "latest"])),
        "0x4"
    );
    assert_eq!(
        result(&r, "eth_getTransactionCount", json!([ADDR, "pending"])),
        "0x9"
    );
}

#[test]
fn unverified_and_engine_errors_are_retryable_or_permanent() {
    let r = Router::new(Fake::new().reply("account", UNVERIFIED));
    let (code, msg, _) = error(&r, "eth_getBalance", json!([ADDR, "latest"]));
    assert_eq!(code, -32000);
    assert!(msg.ends_with("beaconNotSynced"), "{msg}");
    let r = Router::new(Fake::new().reply("account", r#"{"error":"no snap peer"}"#));
    let (code, msg, _) = error(&r, "eth_getBalance", json!([ADDR, "latest"]));
    assert_eq!((code, msg.ends_with("no snap peer")), (-32000, true));
    let r = Router::new(Fake::new().reply(
        "account",
        r#"{"error":"block \"0x1\" is too old","code":-32602}"#,
    ));
    let (code, msg, _) = error(&r, "eth_getBalance", json!([ADDR, "latest"]));
    assert_eq!(code, -32602);
    assert!(msg.contains("refused") && msg.contains("too old"), "{msg}");
}

#[test]
fn selectors_are_applied_or_refused() {
    let r = Router::new(Fake::new().reply("account", &account("1", 1)));
    for bad in [
        json!("safe"),
        json!("earliest"),
        json!("0x0"),
        json!("123"),
        json!(""),
        json!(5),
    ] {
        assert_eq!(
            error(&r, "eth_getBalance", json!([ADDR, bad])).0,
            -32602,
            "{bad}"
        );
    }
    // A hash names historical state this node does not hold.
    assert_eq!(
        error(
            &r,
            "eth_getBalance",
            json!([ADDR, format!("0x{}", "ab".repeat(32))])
        )
        .0,
        -32602
    );
    // Behind the window: refused for good. Inside: served. Ahead: retryable.
    assert_eq!(
        error(&r, "eth_getBalance", json!([ADDR, "0x100"])).0,
        -32602
    );
    assert_eq!(result(&r, "eth_getBalance", json!([ADDR, "0x3c0"])), "0x1");
    assert_eq!(
        error(&r, "eth_getBalance", json!([ADDR, "0x400"])).0,
        -32000
    );
    // EIP-1898 object with a number; finalized passes through as a tag.
    assert_eq!(
        result(
            &r,
            "eth_getBalance",
            json!([ADDR, {"blockNumber": "0x3e8"}])
        ),
        "0x1"
    );
    assert_eq!(
        result(&r, "eth_getBalance", json!([ADDR, "finalized"])),
        "0x1"
    );
    // A pin at or above a head this node reported recently is never "invalid".
    let r = Router::new(Fake::new().reply("account", &account("1", 1)));
    assert_eq!(result(&r, "eth_blockNumber", json!([])), "0x3e8");
    let mut moved = Fake::new().reply("account", &account("1", 1));
    moved.head = Some(2000);
    let r2 = Router { engine: moved, ..r };
    assert_eq!(
        error(&r2, "eth_getBalance", json!([ADDR, "0x3e8"])).0,
        -32000
    );
}

#[test]
fn code_and_storage() {
    let code = r#"{"address":"0xabc","exists":true,"codeHex":"0x6080","verifyMethod":"headerChain","failReason":null}"#;
    let r = Router::new(Fake::new().reply("code", code));
    assert_eq!(
        result(&r, "eth_getCode", json!([TOKEN, "latest"])),
        "0x6080"
    );
    let st = r#"{"addressHex":"0xC0","slot":3,"exists":true,"valueHex":"0x2a","valueDecimal":"42","verifyMethod":"headerChain"}"#;
    let r = Router::new(Fake::new().reply("storage", st));
    let word = result(&r, "eth_getStorageAt", json!([TOKEN, "0x3", "latest"]));
    assert_eq!(word, format!("0x{}2a", "0".repeat(62)));
    assert_eq!(
        calls(&r)[0],
        format!("storage({TOKEN},0x{}03,latest)", "0".repeat(62))
    );
    // An unset slot (valueHex null) is a zero word.
    let unset = r#"{"exists":false,"valueHex":null,"verifyMethod":"headerChain"}"#;
    let r = Router::new(Fake::new().reply("storage", unset));
    assert_eq!(
        result(&r, "eth_getStorageAt", json!([TOKEN, "0x0"])),
        format!("0x{}", "0".repeat(64))
    );
    assert_eq!(
        error(&r, "eth_getStorageAt", json!([TOKEN, "0x"])).0,
        -32602
    );
}

#[test]
fn eth_call_outcomes() {
    let to = TOKEN;
    let req = json!([{"to": to, "data": "0x70a08231"}, "latest"]);
    let ok = r#"{"status":"ok","resultHex":"0xdead","blockNumber":21000000,"verified":false}"#;
    let r = Router::new(Fake::new().reply("call", ok));
    assert_eq!(result(&r, "eth_call", req.clone()), "0xdead");
    assert_eq!(calls(&r)[0], format!("call(,{to},0x70a08231,,latest)"));

    // Error(string) "nope": a verified answer, geth's code 3 with the payload.
    let reason = hex_data(b"nope");
    let payload = format!(
        "08c379a0{:064x}{:064x}{:0<64}",
        32,
        4,
        reason.trim_start_matches("0x")
    );
    let rev = format!(
        r#"{{"status":"revert","dataHex":"0x{payload}","blockNumber":1,"verified":false}}"#
    );
    let r = Router::new(Fake::new().reply("call", &rev));
    let (code, msg, data) = error(&r, "eth_call", req.clone());
    assert_eq!((code, msg.as_str()), (3, "execution reverted: nope"));
    assert_eq!(data, format!("0x{payload}"));

    let un = r#"{"status":"unavailable","reason":"out of gas","blockNumber":1,"verified":false}"#;
    let r = Router::new(Fake::new().reply("call", un));
    let (code, msg, _) = error(&r, "eth_call", req.clone());
    assert_eq!((code, msg.ends_with("out of gas")), (-32000, true));

    let inf = r#"{"status":"infeasible","reason":"intrinsic gas too low: have 20000, want 21000","blockNumber":1,"verified":false}"#;
    let r = Router::new(Fake::new().reply("call", inf));
    assert_eq!(
        error(&r, "eth_call", req.clone()).1,
        "intrinsic gas too low: have 20000, want 21000"
    );

    let refused = r#"{"error":"block \"0x1\" is too old","code":-32602}"#;
    let r = Router::new(Fake::new().reply("call", refused));
    assert_eq!(error(&r, "eth_call", req).0, -32602);
}

#[test]
fn eth_call_paths_and_refusals() {
    let ok = r#"{"status":"ok","resultHex":"0x","blockNumber":1,"verified":false}"#;
    let r = Router::new(Fake::new().reply("call_tx", ok).reply("call_overrides", ok));
    // A gas limit is an extended field: the transaction-object call, with every
    // quantity canonicalized to hex (decimal value 255 → 0xff).
    result(
        &r,
        "eth_call",
        json!([{"to": TOKEN, "gas": "0x5208", "value": "255"}, "latest"]),
    );
    let c = &calls(&r)[0];
    assert!(
        c.starts_with("call_tx(")
            && c.contains(r#""value":"0xff""#)
            && c.contains(r#""gas":"0x5208""#),
        "{c}"
    );
    // A state override on a plain call goes to the override call.
    let ov = json!({ TOKEN: {"balance": "0x1"} });
    result(&r, "eth_call", json!([{"to": TOKEN}, "latest", ov]));
    assert!(calls(&r)[1].starts_with("call_overrides("));
    // Refusals, all permanent.
    for bad in [
        json!([{"to": TOKEN}, "latest", {"0xnot": {}}]),
        json!([{"to": TOKEN}, "latest", null, {"time": "0x1"}]),
        json!([{"to": TOKEN, "chainId": "0x1"}, "latest"]),
        json!([{"to": TOKEN, "data": "0x01", "input": "0x02"}]),
        json!([{"to": TOKEN, "blobVersionedHashes": ["0x01"]}]),
        json!([{"to": "0x1234"}]),
        json!(["not an object"]),
        json!([{"to": TOKEN}, format!("0x{}", "ab".repeat(32))]),
    ] {
        assert_eq!(error(&r, "eth_call", bad.clone()).0, -32602, "{bad}");
    }
}

#[test]
fn estimate_gas() {
    let r = Router::new(Fake::new().reply("estimate_tx", r#"{"status":"ok","gas":21000}"#));
    assert_eq!(
        result(&r, "eth_estimateGas", json!([{"from": ADDR, "to": TOKEN}])),
        "0x5208"
    );
    assert!(calls(&r)[0].ends_with("|latest|)"), "{:?}", calls(&r));
    let r = Router::new(Fake::new().reply("estimate_tx", r#"{"status":"revert","dataHex":"0x"}"#));
    let (code, msg, data) = error(&r, "eth_estimateGas", json!([{"to": TOKEN}]));
    assert_eq!(
        (code, msg.as_str(), data),
        (3, "execution reverted", json!("0x"))
    );
    let r = Router::new(Fake::new().reply(
        "estimate_tx",
        r#"{"status":"infeasible","reason":"gas required exceeds allowance (50000)"}"#,
    ));
    assert_eq!(
        error(&r, "eth_estimateGas", json!([{"to": TOKEN}])).0,
        -32000
    );
}

#[test]
fn fees() {
    let r = Router::new(
        Fake::new()
            .reply(
                "fee",
                r#"{"gasPriceWei":"12345678900","maxPriorityFeePerGasWei":"1500000000"}"#,
            )
            .reply(
                "fee_history",
                r#"{"oldestBlock":"0x1406f40","baseFeePerGas":["0x0","0x0"],"gasUsedRatio":[0.0]}"#,
            ),
    );
    assert_eq!(result(&r, "eth_gasPrice", json!([])), "0x2dfdc1c34");
    assert_eq!(
        result(&r, "eth_maxPriorityFeePerGas", json!([])),
        "0x59682f00"
    );
    assert_eq!(
        result(&r, "eth_feeHistory", json!(["0x2", "latest", [25, 75]]))["oldestBlock"],
        "0x1406f40"
    );
    assert_eq!(calls(&r)[2], "fee_history(2,latest,[25.0,75.0])");
    assert_eq!(error(&r, "eth_feeHistory", json!(["0x2"])).0, -32602); // newest is required
    assert_eq!(
        error(&r, "eth_feeHistory", json!(["0x0", "latest"])).0,
        -32602
    );
    assert_eq!(
        error(&r, "eth_feeHistory", json!(["0x2", "latest", [75, 25]])).0,
        -32602
    );
}

#[test]
fn tri_state_reads() {
    let block = r#"{"number":"0x3e8","hash":"0xab","transactions":[]}"#;
    let r = Router::new(
        Fake::new()
            .reply("block", block)
            .reply("receipt", "null")
            .reply("tx", r#"{"error":"no snap peer"}"#)
            .reply("block_receipts", "[]")
            .reply("block_hash", r#"{"error":"bad selector","code":-32602}"#),
    );
    assert_eq!(
        result(&r, "eth_getBlockByNumber", json!(["0x3e8", false]))["number"],
        "0x3e8"
    );
    assert_eq!(calls(&r)[0], "block(0x3e8,false)");
    assert_eq!(
        error(&r, "eth_getBlockByNumber", json!(["latest", "yes"])).0,
        -32602
    );
    let h = format!("0x{}", "11".repeat(32));
    assert_eq!(
        result(&r, "eth_getTransactionReceipt", json!([h])),
        Value::Null
    );
    assert_eq!(error(&r, "eth_getTransactionByHash", json!([h])).0, -32000);
    assert_eq!(error(&r, "eth_getBlockByHash", json!([h, true])).0, -32602);
    assert_eq!(
        result(&r, "eth_getBlockReceipts", json!(["latest"])),
        json!([])
    );
    assert_eq!(
        error(&r, "eth_getTransactionReceipt", json!(["0x1234"])).0,
        -32602
    );
}

#[test]
fn get_logs() {
    // get_logs_json golden shape.
    let log = format!(
        r#"[{{"address":"0x{}","topics":["0x{}"],"data":"0xdead","blockNumber":"0x64","blockHash":"0x{}","transactionHash":"0x{}","transactionIndex":"0x1","logIndex":"0x5","removed":false}}]"#,
        "11".repeat(20),
        "aa".repeat(32),
        "22".repeat(32),
        "33".repeat(32)
    );
    let r = Router::new(Fake::new().reply("logs", &log));
    let filter = json!({"address": TOKEN, "fromBlock": "0x3e0", "toBlock": "latest"});
    assert_eq!(
        result(&r, "eth_getLogs", json!([filter.clone()]))[0]["logIndex"],
        "0x5"
    );
    let msg = "range 0x3e0..latest is outside the indexed coverage";
    let r = Router::new(Fake::new().reply("logs", &json!({"error": msg}).to_string()));
    assert_eq!(
        error(&r, "eth_getLogs", json!([filter.clone()])),
        (-32000, msg.to_string(), Value::Null)
    );
    let r = Router::new(Fake::new().reply(
        "logs",
        &json!({"error": "bad topic", "code": -32602}).to_string(),
    ));
    assert_eq!(error(&r, "eth_getLogs", json!([filter])).0, -32602);
    assert_eq!(error(&r, "eth_getLogs", json!([])).0, -32602);
}

#[test]
fn syncing_and_send() {
    let mut f = Fake::new().reply(
        "send",
        r#"{"status":"rejected","reason":"nonce too low: next nonce 5, tx nonce 4"}"#,
    );
    let r = Router::new(f);
    assert_eq!(result(&r, "eth_syncing", json!([])), false);
    let (code, msg, _) = error(&r, "eth_sendRawTransaction", json!(["0x02f8"]));
    assert_eq!(
        (code, msg.as_str()),
        (-32000, "nonce too low: next nonce 5, tx nonce 4")
    );
    assert_eq!(error(&r, "eth_sendRawTransaction", json!(["0x"])).0, -32602);

    f = Fake::new().reply("send", &format!(r#"{{"txHash":"0x{}"}}"#, "ab".repeat(32)));
    f.status = r#"{"running":true,"beaconState":"CATCHING_UP"}"#.into();
    let r = Router::new(f);
    assert_eq!(
        result(&r, "eth_sendRawTransaction", json!(["0x02f8"])),
        format!("0x{}", "ab".repeat(32))
    );
    assert_eq!(result(&r, "eth_syncing", json!([]))["highestBlock"], "0x0");
}

#[test]
fn stale_anchor_gets_its_own_message() {
    let mut f = Fake::new().reply("account", r#"{"error":"beacon not synced"}"#);
    f.status = r#"{"running":true,"beaconState":"STALE_ANCHOR"}"#.into();
    let r = Router::new(f);
    let (code, msg, _) = error(&r, "eth_getBalance", json!([ADDR]));
    assert_eq!(code, -32000);
    assert!(msg.contains("weak-subjectivity"), "{msg}");
}

#[test]
fn revert_reason_decoding_is_bounded() {
    assert_eq!(decode_revert_reason(&[]), None);
    let mut panic = vec![0x4e, 0x48, 0x7b, 0x71];
    panic.extend_from_slice(&[0u8; 31]);
    panic.push(0x11);
    assert_eq!(decode_revert_reason(&panic).as_deref(), Some("panic 0x11"));
    // An offset pointing past the end decodes to nothing rather than panicking.
    let mut bad = vec![0x08, 0xc3, 0x79, 0xa0];
    bad.extend_from_slice(&[0xff; 64]);
    assert_eq!(decode_revert_reason(&bad), None);
    // A u64::MAX offset (high bytes zero, so it passes the word check) must not
    // overflow the index arithmetic: under panic=abort that would kill the node.
    let mut huge = vec![0x08, 0xc3, 0x79, 0xa0];
    huge.extend_from_slice(&[0u8; 24]);
    huge.extend_from_slice(&[0xff; 8]);
    huge.extend_from_slice(&[0u8; 32]);
    assert_eq!(decode_revert_reason(&huge), None);
}

#[test]
fn call_log_lines_carry_outcome_and_shortened_params() {
    let long = format!("0x{}", "ab".repeat(200));
    let p = json!([{"data": long}, "latest"]);
    let ok = call_log_line("eth_call", Some(&p), Logged::Result(r#""0x01""#), 7);
    let v: Value = serde_json::from_str(&ok).unwrap();
    assert_eq!(v["outcome"], "ok");
    assert_eq!(v["result"], "0x01");
    assert_eq!(v["ms"], 7);
    assert!(v["params"][0]["data"]
        .as_str()
        .unwrap()
        .contains("(+202 chars)"));
    let null = call_log_line("eth_getTransactionReceipt", None, Logged::Result("null"), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&null).unwrap()["outcome"],
        "null"
    );
    let err = call_log_line(
        "x",
        None,
        Logged::Error {
            code: -32601,
            message: "nope",
        },
        1,
    );
    let v: Value = serde_json::from_str(&err).unwrap();
    assert_eq!(
        (
            v["outcome"].as_str(),
            v["code"].as_i64(),
            v["message"].as_str()
        ),
        (Some("error"), Some(-32601), Some("nope"))
    );
    // A long result: its size, hash and (for an array) element count, without
    // being embedded.
    let long = format!("[{}]", vec![r#"{"a":"0x00"}"#; 100].join(","));
    let v: Value = serde_json::from_str(&call_log_line(
        "eth_getLogs",
        None,
        Logged::Result(&long),
        1,
    ))
    .unwrap();
    assert_eq!(v["result"]["items"], 100);
    assert_eq!(v["result"]["bytes"], long.len());
    assert!(v["result"]["fnv64"].is_string());
    assert!(unix_millis_iso().starts_with("20"));
}

/// The call log sees what the router served, through the router.
#[test]
fn the_call_log_records_each_served_request() {
    #[derive(Clone)]
    struct Sink(std::sync::Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink(Default::default());
    let r = Router::new(Fake::new()).with_call_log(Box::new(sink.clone()));
    result(&r, "eth_chainId", json!([]));
    error(&r, "eth_mining", json!([]));
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(
        (lines[0]["outcome"].as_str(), lines[0]["result"].as_str()),
        (Some("ok"), Some("0x64"))
    );
    assert_eq!(lines[1]["code"], -32601);
    assert!(lines[1]["message"].as_str().unwrap().contains("eth_mining"));
}

/// account_json with one field replaced (or removed, for `Value::Null`).
fn account_with(field: &str, v: Value) -> String {
    let mut a: Value = serde_json::from_str(&account("5", 3)).unwrap();
    match v {
        Value::Null => {
            a.as_object_mut().unwrap().remove(field);
        }
        v => a[field] = v,
    }
    a.to_string()
}

#[test]
fn account_shape_drift_fails_closed_never_a_verified_zero() {
    for (field, v) in [
        ("exists", Value::Null),
        ("exists", json!("true")),
        ("exists", json!(1)),
        ("nonce", Value::Null),
        ("nonce", json!(-1)),
        ("nonce", json!("3")),
        ("nonce", json!(1.5)),
        ("balanceWei", Value::Null),
        ("balanceWei", json!(5)),
        ("balanceWei", json!("0x5")),
        ("balanceWei", json!("")),
    ] {
        let r = Router::new(Fake::new().reply("account", &account_with(field, v.clone())));
        for m in ["eth_getBalance", "eth_getTransactionCount"] {
            let (code, msg, _) = error(&r, m, json!([ADDR, "latest"]));
            assert_eq!(code, -32000, "{m} with {field}={v}: {msg}");
            assert!(msg.contains("malformed"), "{m} with {field}={v}: {msg}");
        }
    }
    // The pure reader: absent is the only zero, whatever else it carries.
    let o = |j: &str| serde_json::from_str::<Map<String, Value>>(j).unwrap();
    assert_eq!(
        parse_account(&o(ABSENT)),
        Ok(Account {
            balance: "0x0".into(),
            nonce: 0
        })
    );
    assert_eq!(
        parse_account(&o(&account("1000000000000000000", 7))),
        Ok(Account {
            balance: "0xde0b6b3a7640000".into(),
            nonce: 7
        })
    );
    assert!(parse_account(&o("{}")).is_err());
}

/// A node that is not ready for reads, and a hold of `wait`.
fn unready(wait: Duration) -> Router<Fake> {
    let mut f = Fake::new().reply("account", &account("5", 1));
    f.status = r#"{"running":true,"beaconState":"CATCHING_UP","elReaderAvailable":true}"#.into();
    Router::new(f).with_ready_wait(wait)
}

#[test]
fn a_number_pinned_read_waits_at_most_once() {
    // pin_servable, the window check and the account read each used to wait.
    let r = unready(Duration::from_millis(300));
    let t0 = Instant::now();
    assert_eq!(result(&r, "eth_getBalance", json!([ADDR, "0x3e8"])), "0x5");
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(550),
        "{took:?}"
    );
    // Same for eth_call through the plain path (pin, window, call).
    let t0 = Instant::now();
    error(&r, "eth_call", json!([{"to": TOKEN}, "0x3e8"]));
    assert!(
        t0.elapsed() < Duration::from_millis(550),
        "{:?}",
        t0.elapsed()
    );
}

#[test]
fn non_blocking_methods_and_bad_params_never_wait() {
    let r = unready(Duration::from_secs(30));
    let t0 = Instant::now();
    assert_eq!(result(&r, "eth_chainId", json!([])), "0x64");
    result(&r, "eth_syncing", json!([]));
    result(&r, "myotis_status", json!([]));
    // Refused on its parameters before any engine read: no hold.
    assert_eq!(error(&r, "eth_getBalance", json!(["0x12"])).0, -32602);
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    assert!(calls(&r).is_empty());
}

#[test]
fn a_batch_waits_once_then_fails_the_rest_fast() {
    let r = unready(Duration::from_millis(300));
    let el = |id: u32| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"eth_getBalance","params":["{ADDR}","latest"]}}"#
        )
    };
    let body = format!(
        r#"[{},{},{},{{"jsonrpc":"2.0","id":9,"method":"eth_chainId"}}]"#,
        el(1),
        el(2),
        el(3)
    );
    let t0 = Instant::now();
    let v: Value = serde_json::from_str(&r.handle(&body).unwrap()).unwrap();
    let took = t0.elapsed();
    assert!(
        took < Duration::from_millis(550),
        "one hold per batch: {took:?}"
    );
    let a = v.as_array().unwrap();
    // The element that spent the hold is asked anyway; the rest fail fast,
    // retryably, without reaching the engine.
    assert_eq!(a[0]["result"], "0x5");
    for e in &a[1..3] {
        assert_eq!(e["error"]["code"], -32000, "{e}");
        assert!(
            e["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--ready-wait"),
            "{e}"
        );
    }
    assert_eq!(a[3]["result"], "0x64");
    assert_eq!(calls(&r).len(), 1, "{:?}", calls(&r));
    // A ready node serves the whole batch.
    let r = Router::new(Fake::new().reply("account", &account("5", 1)))
        .with_ready_wait(Duration::from_secs(30));
    let v: Value = serde_json::from_str(&r.handle(&body).unwrap()).unwrap();
    assert!(
        v.as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("result").is_some()),
        "{v}"
    );
}

#[test]
fn bodies_are_classified_blocking_only_when_they_name_a_gated_method() {
    let b = |s: &str| Body::parse(s).blocking();
    assert!(!b(r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}"#));
    assert!(!b(
        r#"[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_syncing"}]"#
    ));
    assert!(!b("{nope"));
    assert!(!b("[]"));
    assert!(!b("[1,2]"));
    assert!(!b(r#"{"jsonrpc":"2.0","id":1,"method":"eth_mining"}"#));
    assert!(b(r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}"#));
    // One gated element makes the whole batch blocking.
    assert!(b(
        r#"[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_getBalance"}]"#
    ));
    // A batch over the limit is refused whole, without the engine.
    let big = format!(
        "[{}]",
        vec![r#"{"method":"eth_blockNumber"}"#; MAX_BATCH_REQUESTS + 1].join(",")
    );
    assert!(!b(&big));
    for m in NON_BLOCKING {
        assert!(arity(m).is_some() && !gated(m), "{m}");
    }
}
