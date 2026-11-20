//! An address's history from the addr1 index on Swarm (`.claude/agent/data-sources.md`, the
//! carve-out for Swarm reads of the address index; part 5 of #899).
//!
//! The reader is the embedded `ant` node (`myotis-swarm`), linked in only with the `swarm`
//! feature, and the lookup is `myotis_addr1::client`'s, which checks every chunk. The
//! entries are candidates: each one is `"unverified"` until the per-entry check against
//! verified chain data (part 6) says otherwise.
//!
//! **Refused with the permanent `-32602`, never an empty list** (the carve-out):
//! - a build without the reader (no `swarm` feature), and Android and iOS in this version;
//! - without an importer key (an experimental setting: the user trusts that importer);
//! - while Tor routing is on (the embedded node does not route through Tor).
//!
//! The settings are engine-wide ([`set_config_json`]); the node starts on the first read and
//! is replaced when the Swarm network changes.

use crate::eljson;

/// Why every read is refused in a build like this one, if it is.
fn build_refusal() -> Option<&'static str> {
    if cfg!(any(target_os = "android", target_os = "ios")) {
        return Some("the address history is not available on mobile in this version");
    }
    if !cfg!(feature = "swarm") {
        return Some("the address history needs the Swarm reader, which this build does not include");
    }
    None
}

/// Whether Tor routing is on (the reader would bypass it).
fn tor_on() -> bool {
    #[cfg(feature = "tor")]
    {
        myotis_net::el::tor::is_enabled()
    }
    #[cfg(not(feature = "tor"))]
    {
        false
    }
}

/// The settings, as the host sets them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// The importer whose index is read: `None` refuses every read.
    pub importer: Option<[u8; 20]>,
    /// The Swarm network the reader joins.
    pub network: Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Network {
    /// Swarm mainnet, through its published bootnodes.
    #[default]
    Mainnet,
    /// A local network (bee-factory): its network id and the multiaddrs of its nodes.
    Dev { network_id: u64, bootnodes: Vec<String> },
}

/// Parse `{"importer": "0x…" | null, "swarm": {"network": "mainnet"} | {"network": "dev",
/// "networkId": N, "bootnodes": ["/ip4/…", …]}}`. Every field is applied or the whole
/// request refused; unknown fields are refused too.
pub fn parse_config(json: &str) -> Result<Config, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("invalid settings JSON: {e}"))?;
    let obj = v.as_object().ok_or("settings must be a JSON object")?;
    for k in obj.keys() {
        if k != "importer" && k != "swarm" {
            return Err(format!("unknown setting '{k}'"));
        }
    }
    let importer = match obj.get("importer") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(parse_address(s).ok_or("invalid importer (expected a 20-byte 0x address)")?),
        Some(_) => return Err("invalid importer (expected a 20-byte 0x address or null)".into()),
    };
    let network = match obj.get("swarm") {
        None | Some(serde_json::Value::Null) => Network::Mainnet,
        Some(serde_json::Value::Object(s)) => {
            for k in s.keys() {
                if !matches!(k.as_str(), "network" | "networkId" | "bootnodes") {
                    return Err(format!("unknown swarm setting '{k}'"));
                }
            }
            match s.get("network").and_then(|n| n.as_str()) {
                Some("mainnet") if s.len() == 1 => Network::Mainnet,
                Some("mainnet") => return Err("swarm network 'mainnet' takes no other settings".into()),
                Some("dev") => {
                    let network_id = s
                        .get("networkId")
                        .and_then(|n| n.as_u64())
                        .ok_or("swarm network 'dev' needs a numeric networkId")?;
                    let bootnodes: Vec<String> = s
                        .get("bootnodes")
                        .and_then(|b| b.as_array())
                        .ok_or("swarm network 'dev' needs a bootnodes array")?
                        .iter()
                        .map(|b| b.as_str().map(str::to_string).ok_or("a bootnode must be a multiaddr string"))
                        .collect::<Result<_, _>>()?;
                    if bootnodes.is_empty() {
                        return Err("swarm network 'dev' needs at least one bootnode".into());
                    }
                    #[cfg(feature = "swarm")]
                    for b in &bootnodes {
                        b.parse::<myotis_swarm::Multiaddr>()
                            .map_err(|_| format!("invalid bootnode multiaddr '{b}'"))?;
                    }
                    Network::Dev { network_id, bootnodes }
                }
                _ => return Err("swarm network must be 'mainnet' or 'dev'".into()),
            }
        }
        Some(_) => return Err("swarm must be an object".into()),
    };
    Ok(Config { importer, network })
}

fn parse_address(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    // from_str_radix takes a leading '+': check the digits first.
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A page's cursor as the API carries it: `"<block>:<slot>"`, exclusive.
pub fn parse_cursor(s: &str) -> Option<(u64, u32)> {
    let (b, slot) = s.split_once(':')?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    if !digits(b) || !digits(slot) {
        return None;
    }
    Some((b.parse().ok()?, slot.parse().ok()?))
}

/// The most entries one page returns.
pub const MAX_PAGE: usize = 500;

static CONFIG: std::sync::Mutex<Option<Config>> = std::sync::Mutex::new(None);

/// `set_address_history_config_json`: apply the settings, or refuse them whole with the
/// permanent `{"error","code":-32602}`. `{}` on success.
pub fn set_config_json(json: &str) -> String {
    match parse_config(json) {
        Ok(cfg) => {
            if let Ok(mut c) = CONFIG.lock() {
                *c = Some(cfg);
            }
            "{}".to_string()
        }
        Err(msg) => eljson::invalid_params_json(&msg),
    }
}

fn config() -> Config {
    CONFIG.lock().ok().and_then(|c| c.clone()).unwrap_or_default()
}

/// The refusal of a build without the reader, before the chain handle is even looked up.
pub fn early_refusal() -> Option<String> {
    build_refusal().map(|why| eljson::invalid_params_json(why))
}

/// Tor routing was turned on: the reader stops, so no Swarm connection outlives the switch
/// (refusing the next read alone would leave the node connected, outside Tor).
pub fn tor_switched_on() {
    reader::stop();
}

/// The refusal a read gets before any I/O, if any.
fn refusal(cfg: &Config) -> Option<String> {
    if let Some(why) = build_refusal() {
        return Some(why.to_string());
    }
    if cfg.importer.is_none() {
        return Some("no importer key is set for the address history (an experimental setting)".to_string());
    }
    if tor_on() {
        reader::stop();
        return Some(
            "the address history is not available while Tor routing is on: the Swarm reader does not route through Tor"
                .to_string(),
        );
    }
    None
}

/// `address_history_json`: one page of `address`'s history on chain `chain_id`, newest
/// first, strictly older than `cursor` (`""`: from the newest), at most `limit` entries.
/// `chain_head` is the node's verified head, for the head gap. The answer:
///
/// ```json
/// {"importer":"0x…","headUpdate":73,"coveredFrom":26236928,"coveredTo":26458303,
///  "headGap":{"fromBlock":26458304,"toBlock":26458400} | null,
///  "gaps":[{"fromBlock":…,"toBlock":…}],
///  "entries":[{"block":…,"slot":…,"roles":["from","to"],"state":"unverified"}],
///  "next":"26458303:256" | null}
/// ```
///
/// A refusal is the permanent `-32602`; Swarm not delivering what the read needs is the
/// retryable `{"error"}`.
pub fn history_json(
    rt: &tokio::runtime::Runtime,
    chain_id: u64,
    chain_head: Option<u64>,
    address: &str,
    cursor: &str,
    limit: i64,
) -> String {
    let cfg = config();
    if let Some(why) = refusal(&cfg) {
        return eljson::invalid_params_json(&why);
    }
    let Some(address) = parse_address(address) else {
        return eljson::invalid_params_json("invalid address (expected 20-byte hex)");
    };
    let before = if cursor.is_empty() {
        None
    } else {
        match parse_cursor(cursor) {
            Some(c) => Some(c),
            None => return eljson::invalid_params_json("invalid cursor (expected the 'next' of an earlier page)"),
        }
    };
    if limit < 1 || limit as u64 > MAX_PAGE as u64 {
        return eljson::invalid_params_json(&format!("invalid limit (expected 1 to {MAX_PAGE})"));
    }
    let importer = cfg.importer.expect("refusal() checked it");
    match reader::page(rt, &cfg, chain_id, importer, &address, before, limit as usize) {
        Ok(read) => page_json(&read, importer, chain_head),
        Err(reader::Failure::Refused(msg)) => eljson::invalid_params_json(&msg),
        Err(reader::Failure::Retry(msg)) => eljson::error_json(&msg),
    }
}

/// A page as read, before it is rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    pub head_update: u64,
    pub page: myotis_addr1::client::Page,
}

fn page_json(read: &Read, importer: [u8; 20], chain_head: Option<u64>) -> String {
    use myotis_addr1::records::role;
    let p = &read.page;
    let roles = |bits: u8| -> Vec<&'static str> {
        [
            (role::FROM, "from"),
            (role::TO, "to"),
            (role::EMITTER, "emitter"),
            (role::TOPIC, "topic"),
            (role::WORD, "word"),
            (role::TRACE, "trace"),
            (role::BLOCK, "block"),
            (role::AUTH, "auth"),
        ]
        .into_iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| n)
        .collect()
    };
    let head_gap = chain_head
        .filter(|h| *h > p.to_block)
        .map(|h| serde_json::json!({"fromBlock": p.to_block + 1, "toBlock": h}));
    serde_json::json!({
        "importer": hex(&importer),
        "headUpdate": read.head_update,
        "coveredFrom": p.from_block,
        "coveredTo": p.to_block,
        "headGap": head_gap,
        "gaps": p.gaps.iter().map(|g| serde_json::json!({"fromBlock": g.from_block, "toBlock": g.to_block})).collect::<Vec<_>>(),
        "entries": p.entries.iter().map(|e| serde_json::json!({
            "block": e.block,
            "slot": e.slot,
            "roles": roles(e.roles),
            "state": "unverified",
        })).collect::<Vec<_>>(),
        "next": p.next.map(|(b, s)| format!("{b}:{s}")),
    })
    .to_string()
}

#[cfg(feature = "swarm")]
mod reader {
    //! The embedded node and the lookup through it.
    use super::{Config, Network, Read};
    use myotis_addr1::client::{Index, ReadError};
    use myotis_swarm::{SwarmConfig, SwarmNode};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    pub enum Failure {
        /// The index's data was invalid, or the settings cannot work: permanent.
        Refused(String),
        /// Swarm did not deliver, or the node is not ready: retryable.
        Retry(String),
    }

    struct Running {
        network: Network,
        node: Arc<SwarmNode>,
        started: Instant,
        /// The newest head update found per (chain, importer): where the next probe starts.
        hints: std::collections::HashMap<(u64, [u8; 20]), u64>,
    }

    static NODE: Mutex<Option<Running>> = Mutex::new(None);

    /// How long after its start a node may answer "no usable peers" and be asked again.
    const STARTUP_WAIT: Duration = Duration::from_secs(20);
    /// The most one page may take, retries included.
    const READ_DEADLINE: Duration = Duration::from_secs(120);

    /// Stop the node, if one runs: it shuts down when the last read holding it lets go.
    pub fn stop() {
        if let Ok(mut slot) = NODE.lock() {
            if slot.take().is_some() {
                tracing::info!("addr1: Swarm reader stopped");
            }
        }
    }

    /// The node for `network`, started (or restarted for another network) on first use.
    fn node(network: &Network) -> Result<(Arc<SwarmNode>, Instant), Failure> {
        let mut slot = NODE.lock().map_err(|_| Failure::Retry("Swarm reader lock poisoned".into()))?;
        if slot.as_ref().map(|r| &r.network) != Some(network) {
            let cfg = match network {
                Network::Mainnet => SwarmConfig::mainnet(),
                Network::Dev { network_id, bootnodes } => {
                    let addrs = bootnodes
                        .iter()
                        .map(|b| b.parse().map_err(|_| Failure::Refused(format!("invalid bootnode multiaddr '{b}'"))))
                        .collect::<Result<Vec<_>, _>>()?;
                    SwarmConfig::dev(*network_id, addrs)
                }
            };
            let node = SwarmNode::start(cfg).map_err(|e| Failure::Retry(format!("Swarm reader did not start: {e}")))?;
            *slot = Some(Running {
                network: network.clone(),
                node: Arc::new(node),
                started: Instant::now(),
                hints: Default::default(),
            });
        }
        let running = slot.as_ref().expect("set above");
        Ok((Arc::clone(&running.node), running.started))
    }

    fn hint(chain_id: u64, importer: [u8; 20]) -> u64 {
        NODE.lock().ok().and_then(|s| s.as_ref().and_then(|r| r.hints.get(&(chain_id, importer)).copied())).unwrap_or(0)
    }

    fn remember(chain_id: u64, importer: [u8; 20], n: u64) {
        if let Ok(mut s) = NODE.lock() {
            if let Some(r) = s.as_mut() {
                r.hints.insert((chain_id, importer), n);
            }
        }
    }

    fn failure(e: ReadError) -> Failure {
        match e {
            ReadError::Invalid(err) => Failure::Refused(format!("the importer's index failed its checks: {err}")),
            other => Failure::Retry(other.to_string()),
        }
    }

    /// A failure of the node itself (not a miss, not invalid data): on a freshly started node
    /// "no usable peers yet" (`myotis_swarm::NOT_READY_TEXT`) or a stream that could not be
    /// opened yet, worth asking again while the node is fresh, and only then.
    fn transient(e: &ReadError) -> bool {
        matches!(e, ReadError::Source(_))
    }

    /// One page, on the engine's runtime (as every other host read).
    pub fn page(
        rt: &tokio::runtime::Runtime,
        cfg: &Config,
        chain_id: u64,
        importer: [u8; 20],
        address: &[u8; 20],
        before: Option<(u64, u32)>,
        limit: usize,
    ) -> Result<Read, Failure> {
        let (node, started) = node(&cfg.network)?;
        let start = hint(chain_id, importer);
        let read = rt.block_on(async {
            let index = Index::new(node.as_ref(), chain_id, importer);
            let attempts = async {
                loop {
                    let attempt = async {
                        let origin = index.origin().await?;
                        let (n, head) = index.head(&origin, start).await?;
                        let page = index.page(&head, address, before, limit).await?;
                        Ok::<_, ReadError>(Read { head_update: n, page })
                    };
                    match attempt.await {
                        // A freshly started node is connected before its peers are usable.
                        Err(e) if transient(&e) && started.elapsed() < STARTUP_WAIT => {
                            tracing::debug!(error = %e, "addr1: Swarm reader not ready yet");
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                        other => break other,
                    }
                }
            };
            tokio::time::timeout(READ_DEADLINE, attempts)
                .await
                .unwrap_or_else(|_| Err(ReadError::Source(format!("no page within {READ_DEADLINE:?}"))))
        });
        let read = read.map_err(failure)?;
        remember(chain_id, importer, read.head_update);
        Ok(read)
    }
}

#[cfg(not(feature = "swarm"))]
mod reader {
    use super::{Config, Read};

    pub enum Failure {
        Refused(String),
        #[allow(dead_code)]
        Retry(String),
    }

    pub fn stop() {}

    pub fn page(
        _rt: &tokio::runtime::Runtime,
        _cfg: &Config,
        _chain_id: u64,
        _importer: [u8; 20],
        _address: &[u8; 20],
        _before: Option<(u64, u32)>,
        _limit: usize,
    ) -> Result<Read, Failure> {
        Err(Failure::Refused(super::build_refusal().unwrap_or("no Swarm reader").to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_applied_or_refused_whole() {
        let ok = parse_config(r#"{"importer":"0xefdb28e3Eac685FC0fFb8B61A2692FC671559e4b","swarm":{"network":"dev","networkId":1337,"bootnodes":["/ip4/127.0.0.1/tcp/1734/p2p/QmQxLnj3rigCh7JbpoDSwW7VsNWWQ65ANuQ5GXN11KEPKM"]}}"#).unwrap();
        assert_eq!(ok.importer.map(|a| a[0]), Some(0xef));
        assert!(matches!(ok.network, Network::Dev { network_id: 1337, .. }));
        assert_eq!(parse_config("{}").unwrap(), Config::default());
        assert_eq!(parse_config(r#"{"importer":null,"swarm":{"network":"mainnet"}}"#).unwrap(), Config::default());
        for bad in [
            r#"{"importer":"0x12"}"#,
            r#"{"importer":5}"#,
            r#"{"other":1}"#,
            r#"{"swarm":{"network":"dev","networkId":1337}}"#,
            r#"{"swarm":{"network":"dev","networkId":1337,"bootnodes":[]}}"#,
            r#"{"swarm":{"network":"mainnet","networkId":1}}"#,
            r#"{"swarm":{"network":"testnet"}}"#,
            r#"{"swarm":{"network":"dev","networkId":1,"bootnodes":["x"],"extra":1}}"#,
            "[]",
            "nope",
        ] {
            assert!(parse_config(bad).is_err(), "{bad}");
            let v: serde_json::Value = serde_json::from_str(&set_config_json(bad)).unwrap();
            assert_eq!(v["code"], eljson::INVALID_PARAMS, "{bad}");
        }
    }

    #[test]
    fn cursors_round_trip() {
        assert_eq!(parse_cursor("26458303:256"), Some((26_458_303, 256)));
        for bad in ["", "1", "a:1", "1:b", "1:2:3", "+5:+1", ":1", "1:"] {
            assert_eq!(parse_cursor(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_read_without_an_importer_or_bad_arguments_is_refused_permanently() {
        let code = |json: String| serde_json::from_str::<serde_json::Value>(&json).unwrap()["code"].clone();
        // Without an importer (or without the reader in this build): -32602, never [].
        let none = refusal(&Config::default()).expect("refused");
        assert!(none.contains("importer") || none.contains("Swarm reader") || none.contains("mobile"), "{none}");
        // The arguments are checked once the reader may run; with the default settings the
        // refusal comes first, so check the shapes through parse_cursor/limit rules here.
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        assert_eq!(code(history_json(&rt, 1, None, "0x00", "", 10)), serde_json::json!(eljson::INVALID_PARAMS));
        assert_eq!(parse_address(&format!("0x{}", "+f".repeat(20))), None, "a '+' is no hex digit");
    }

    /// Live, against a local Swarm network holding an index: `MYOTIS_ADDR1_DEV="<network id>
    /// <bootnode multiaddr> <importer>"`, e.g. bee-factory's queen and the month index.
    #[cfg(feature = "swarm")]
    #[test]
    #[ignore]
    fn a_live_page_through_the_embedded_node() {
        let env = std::env::var("MYOTIS_ADDR1_DEV").expect("MYOTIS_ADDR1_DEV");
        let f: Vec<&str> = env.split_whitespace().collect();
        let cfg = format!(r#"{{"importer":"{}","swarm":{{"network":"dev","networkId":{},"bootnodes":["{}"]}}}}"#, f[2], f[0], f[1]);
        assert_eq!(set_config_json(&cfg), "{}");
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let first: serde_json::Value = serde_json::from_str(&history_json(&rt, 1, None, weth, "", 5)).unwrap();
        assert!(first["error"].is_null(), "{first}");
        assert_eq!(first["entries"].as_array().unwrap().len(), 5, "{first}");
        let next = first["next"].as_str().unwrap().to_string();
        let second: serde_json::Value = serde_json::from_str(&history_json(&rt, 1, None, weth, &next, 5)).unwrap();
        let (a, b) = (&first["entries"][4], &second["entries"][0]);
        assert!((a["block"].as_u64(), a["slot"].as_u64()) > (b["block"].as_u64(), b["slot"].as_u64()));
        println!("{first}\n{second}");
    }

    #[test]
    fn a_page_renders_its_range_gaps_and_cursor() {
        use myotis_addr1::client::{Gap, Page};
        use myotis_addr1::records::{role, Entry};
        let read = Read {
            head_update: 73,
            page: Page {
                entries: vec![Entry { block: 26_458_303, slot: 477, roles: role::TO | role::EMITTER }],
                next: Some((26_458_303, 477)),
                from_block: 26_236_928,
                to_block: 26_458_303,
                gaps: vec![Gap { from_block: 10, to_block: 20 }],
            },
        };
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0xef; 20], Some(26_458_400))).unwrap();
        assert_eq!(v["headUpdate"], 73);
        assert_eq!(v["coveredFrom"], 26_236_928);
        assert_eq!(v["headGap"]["fromBlock"], 26_458_304);
        assert_eq!(v["headGap"]["toBlock"], 26_458_400);
        assert_eq!(v["gaps"][0]["toBlock"], 20);
        assert_eq!(v["entries"][0]["roles"], serde_json::json!(["to", "emitter"]));
        assert_eq!(v["entries"][0]["state"], "unverified");
        assert_eq!(v["next"], "26458303:477");
        // At the head: no head gap.
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0xef; 20], Some(26_458_303))).unwrap();
        assert!(v["headGap"].is_null());
    }
}
