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
    /// A local network: its network id and the multiaddrs of its nodes.
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

/// A page's cursor as the API carries it: `"<head update>:<block>:<slot>"`, exclusive in
/// `(block, slot)`. The head update is the one the page was read at: a later page is read at
/// that head or a newer one, never an older (which would miss entries between its end and
/// the cursor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub head_update: u64,
    pub before: (u64, u32),
}

pub fn parse_cursor(s: &str) -> Option<Cursor> {
    let mut f = s.split(':');
    let (u, b, slot) = (f.next()?, f.next()?, f.next()?);
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    if f.next().is_some() || !digits(u) || !digits(b) || !digits(slot) {
        return None;
    }
    Some(Cursor { head_update: u.parse().ok()?, before: (b.parse().ok()?, slot.parse().ok()?) })
}

/// The most entries one page returns.
pub const MAX_PAGE: usize = 500;

static CONFIG: std::sync::Mutex<Option<Config>> = std::sync::Mutex::new(None);

/// `set_address_history_config_json`: apply the settings, or refuse them whole with the
/// permanent `{"error","code":-32602}`. `{}` on success.
pub fn set_config_json(json: &str) -> String {
    match parse_config(json) {
        Ok(cfg) => {
            let Ok(mut c) = CONFIG.lock() else {
                return eljson::error_json("address history settings lock poisoned");
            };
            // No importer: nothing may be read, so no node keeps running for it.
            if cfg.importer.is_none() {
                reader::stop();
            }
            *c = Some(cfg);
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
/// {"importer":"0x…","headUpdate":<n>,"coveredFrom":<first block>,"coveredTo":<last block>,
///  "headGap":{"fromBlock":<last block + 1>,"toBlock":<verified head> | null} | null,
///  "tailGap":{"fromBlock":0,"toBlock":<first block - 1>} | null,
///  "gaps":[{"fromBlock":…,"toBlock":…}],
///  "entries":[{"block":…,"slot":…,"roles":["from","to"],"state":"unverified"}],
///  "next":"<head update>:<block>:<slot>" | null}
/// ```
///
/// Every range the index does not cover is named: the head gap above it (open, `toBlock`
/// null, while the node has no verified head), the tail gap below an index that starts
/// late, and the slices Swarm did not deliver.
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
    let cursor = if cursor.is_empty() {
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
    match reader::page(rt, &cfg, chain_id, importer, &address, cursor, limit as usize) {
        Ok(read) => page_json(&read, importer, chain_head, (chain_id, address)),
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

/// The role bits and their API names, in bit order.
const ROLE_NAMES: [(u8, &str); 8] = [
    (0x01, "from"),
    (0x02, "to"),
    (0x04, "emitter"),
    (0x08, "topic"),
    (0x10, "word"),
    (0x20, "trace"),
    (0x40, "block"),
    (0x80, "auth"),
];

fn role_names(bits: u8) -> Vec<&'static str> {
    ROLE_NAMES.iter().filter(|(b, _)| bits & b != 0).map(|(_, n)| *n).collect()
}

fn page_json(read: &Read, importer: [u8; 20], chain_head: Option<u64>, who: (u64, [u8; 20])) -> String {
    let p = &read.page;
    let roles = role_names;
    let head_gap = match chain_head {
        Some(h) if h > p.to_block => Some(serde_json::json!({"fromBlock": p.to_block + 1, "toBlock": h})),
        Some(_) => None,
        // No verified head yet: the gap above the index is open, never "none".
        None => Some(serde_json::json!({"fromBlock": p.to_block + 1, "toBlock": null})),
    };
    let tail_gap = (p.from_block > 0).then(|| serde_json::json!({"fromBlock": 0, "toBlock": p.from_block - 1}));
    serde_json::json!({
        "importer": hex(&importer),
        "headUpdate": read.head_update,
        "coveredFrom": p.from_block,
        "coveredTo": p.to_block,
        "headGap": head_gap,
        "tailGap": tail_gap,
        "gaps": p.gaps.iter().map(|g| serde_json::json!({"fromBlock": g.from_block, "toBlock": g.to_block})).collect::<Vec<_>>(),
        // Each entry with its state so far: what an earlier verify call found for it, else
        // "unverified".
        "entries": p.entries.iter().map(|e| {
            verified::cached(who.0, &who.1, e.block, e.slot, e.roles).unwrap_or_else(|| serde_json::json!({
                "block": e.block,
                "slot": e.slot,
                "roles": roles(e.roles),
                "state": "unverified",
            }))
        }).collect::<Vec<_>>(),
        "next": p.next.map(|(b, s)| format!("{}:{b}:{s}", read.head_update)),
    })
    .to_string()
}

/// The most entries one verify call checks.
pub const MAX_VERIFY: usize = 50;

/// The most one verify call takes: the blocks not reached by then come back `unavailable`.
const VERIFY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// `verify_address_history_json`: check `entries` (a JSON array of `{"block", "slot",
/// "roles"}`, as a page returns them) of `address` against verified chain data
/// (`myotis_net::el::addrcheck`, part 6 of #899), one verified block (and, for the log
/// roles, its verified receipts) per block. Each entry comes back with its state:
///
/// ```json
/// [{"block":…,"slot":…,"roles":[…],"state":"verified"|"contradicted"|"unverified"|"unavailable",
///   "final":true,"confirmed":[…],"contradicted":[…],"unchecked":[…],
///   "txHash":"0x…","from":"0x…","to":"0x…"|null,"value":"0x…",
///   "transfer":{"token":"0x…","from":"0x…","to":"0x…","data":"0x…"}|null,"reason":"…"}]
/// ```
///
/// `unavailable` (with its `reason`) is a block or its receipts no peer served now: ask
/// again. `unverified` with a `reason` is a block this node cannot verify (outside what it
/// can anchor, or the checkpoint table's alarm): asking again does not help. A final, complete
/// verdict (`verified` or `contradicted` in a finalized block, every checkable role checked)
/// is kept, and later pages carry it. A refusal is the permanent `-32602`.
///
/// The entries may be sent as a page returned them: the fields a page renders (`state`,
/// `final`, `confirmed`, …) come back as they were and are not inputs, the verdict is
/// computed (or taken from the kept one) afresh; a `state` the engine never renders is
/// refused.
pub fn verify_json(
    rt: &tokio::runtime::Runtime,
    reader: &std::sync::Arc<myotis_net::el::reader::ElReader>,
    chain_id: u64,
    address: &str,
    entries_json: &str,
) -> String {
    let Some(address) = parse_address(address) else {
        return eljson::invalid_params_json("invalid address (expected 20-byte hex)");
    };
    let entries = match parse_entries(entries_json) {
        Ok(e) => e,
        Err(msg) => return eljson::invalid_params_json(&msg),
    };
    let finalized = reader.finalized_block_number();
    let mut out = vec![serde_json::Value::Null; entries.len()];
    // One read per block, the entries of a block together.
    let mut blocks: std::collections::BTreeMap<u64, Vec<usize>> = Default::default();
    for (i, e) in entries.iter().enumerate() {
        match verified::cached(chain_id, &address, e.0, e.1, e.2) {
            Some(v) => out[i] = v,
            None => blocks.entry(e.0).or_default().push(i),
        }
    }
    use myotis_net::el::addrcheck::{check, role, State};
    let needs_receipts = |(_, slot, roles): (u64, u32, u8)| slot > 0 && roles & role::NEEDS_RECEIPTS != 0;
    let started = std::time::Instant::now();
    for (block, idx) in blocks {
        if started.elapsed() > VERIFY_DEADLINE {
            for i in idx {
                let (_, slot, roles) = entries[i];
                out[i] = verified::unavailable(block, slot, roles, "the call's deadline passed before this block");
            }
            continue;
        }
        let fetched = rt.block_on(reader.request(async { reader.get_block_by_number(Some(block), true).await }));
        let b = match fetched {
            Ok(Some(b)) => b,
            Ok(None) => {
                let why = format!(
                    "the node holds no canonical block {block} now (its verified head is {})",
                    reader.optimistic_block_number()
                );
                for i in idx {
                    let (_, slot, roles) = entries[i];
                    out[i] = verified::unavailable(block, slot, roles, &why);
                }
                continue;
            }
            Err(e) => {
                // A lasting refusal (outside what this node can verify, the checkpoint
                // table's alarm) is no "ask again".
                let lasting = e.starts_with(myotis_net::el::deep::ALARM_PREFIX) || e.contains("verify window");
                for i in idx {
                    let (_, slot, roles) = entries[i];
                    out[i] = if lasting {
                        verified::not_verifiable(block, slot, roles, &e)
                    } else {
                        verified::unavailable(block, slot, roles, &e)
                    };
                }
                continue;
            }
        };
        // The receipts on their own, only when an entry needs them, and only if they are this
        // block's (a reorg between the two reads would pair another block's logs).
        let receipts: Result<Option<Vec<_>>, String> = if idx.iter().any(|i| needs_receipts(entries[*i])) {
            match rt.block_on(reader.request(async { reader.get_block_receipts(Some(block)).await })) {
                Ok(Some(r)) if r.iter().all(|x| x.block_hash == b.hash) => Ok(Some(r)),
                Ok(Some(_)) => Err("the block's receipts came from another block (a reorg between the reads)".into()),
                Ok(None) => Err("the block's receipts were not served".into()),
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        };
        for i in idx {
            let (_, slot, roles) = entries[i];
            let r = match (&receipts, needs_receipts(entries[i])) {
                (Err(e), true) => {
                    out[i] = verified::unavailable(block, slot, roles, e);
                    continue;
                }
                (Ok(r), _) => r.as_deref(),
                (Err(_), false) => None,
            };
            let c = check(&address, slot, roles, &b, r);
            let v = verified::render(block, slot, roles, &c, block <= finalized);
            // Kept only when final and complete: every role that verified data can check was
            // checked (TRACE never is).
            let complete = c.unchecked & !role::TRACE == 0;
            if block <= finalized && c.state != State::Unverified && complete {
                verified::keep(chain_id, &address, block, slot, roles, &v);
            }
            out[i] = v;
        }
    }
    serde_json::Value::Array(out).to_string()
}

/// `[{"block": N, "slot": S, "roles": ["from", …]}, …]`, every field applied or the whole
/// request refused.
fn parse_entries(json: &str) -> Result<Vec<(u64, u32, u8)>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("invalid entries JSON: {e}"))?;
    let list = v.as_array().ok_or("entries must be a JSON array")?;
    if list.is_empty() || list.len() > MAX_VERIFY {
        return Err(format!("expected 1 to {MAX_VERIFY} entries"));
    }
    list.iter()
        .map(|e| {
            let o = e.as_object().ok_or("an entry must be an object")?;
            for k in o.keys() {
                // A page's own fields are accepted back (a host may pass entries as it got
                // them); they are not inputs. Anything else is refused.
                if !matches!(
                    k.as_str(),
                    "block" | "slot" | "roles" | "state" | "final" | "confirmed" | "contradicted" | "unchecked"
                        | "txHash" | "from" | "to" | "value" | "transfer" | "reason"
                ) {
                    return Err(format!("unknown entry field '{k}'"));
                }
            }
            if let Some(state) = o.get("state") {
                let known = ["verified", "contradicted", "unverified", "unavailable"];
                if !state.as_str().is_some_and(|s| known.contains(&s)) {
                    return Err(format!("unknown entry state {state}"));
                }
            }
            let block = o.get("block").and_then(|b| b.as_u64()).ok_or("an entry needs a numeric block")?;
            let slot = o
                .get("slot")
                .and_then(|s| s.as_u64())
                .and_then(|s| u32::try_from(s).ok())
                .ok_or("an entry needs a numeric slot")?;
            let names = o.get("roles").and_then(|r| r.as_array()).ok_or("an entry needs a roles array")?;
            let mut roles = 0u8;
            for n in names {
                let n = n.as_str().ok_or("a role must be a string")?;
                let bit = ROLE_NAMES.iter().find(|(_, name)| *name == n).ok_or(format!("unknown role '{n}'"))?.0;
                roles |= bit;
            }
            if roles == 0 {
                return Err("an entry needs at least one role".to_string());
            }
            Ok((block, slot, roles))
        })
        .collect()
}

mod verified {
    //! The verdicts kept, and how an entry with one is rendered.
    use myotis_net::el::addrcheck::{Check, State};
    use std::collections::HashMap;
    use std::sync::Mutex;

    type Key = (u64, [u8; 20], u64, u32, u8);

    /// Final verdicts only (a finalized block's verified or contradicted entry): they never
    /// change. Bounded: cleared whole when full, a cache, not a store.
    static KEPT: Mutex<Option<HashMap<Key, serde_json::Value>>> = Mutex::new(None);
    const MAX_KEPT: usize = 50_000;

    pub(super) fn cached(chain: u64, address: &[u8; 20], block: u64, slot: u32, roles: u8) -> Option<serde_json::Value> {
        KEPT.lock().ok()?.as_ref()?.get(&(chain, *address, block, slot, roles)).cloned()
    }

    pub(super) fn keep(chain: u64, address: &[u8; 20], block: u64, slot: u32, roles: u8, v: &serde_json::Value) {
        if let Ok(mut kept) = KEPT.lock() {
            let map = kept.get_or_insert_with(HashMap::new);
            if map.len() >= MAX_KEPT {
                map.clear();
            }
            map.insert((chain, *address, block, slot, roles), v.clone());
        }
    }

    fn hex(b: &[u8]) -> String {
        super::hex(b)
    }

    fn scalar(b: &[u8]) -> String {
        let b = &b[b.iter().take_while(|x| **x == 0).count()..];
        if b.is_empty() {
            "0x0".to_string()
        } else {
            let s = hex(b);
            format!("0x{}", s[2..].trim_start_matches('0'))
        }
    }

    pub(super) fn render(block: u64, slot: u32, roles: u8, c: &Check, finalized: bool) -> serde_json::Value {
        let state = match c.state {
            State::Verified => "verified",
            State::Contradicted => "contradicted",
            State::Unverified => "unverified",
        };
        let mut v = serde_json::json!({
            "block": block,
            "slot": slot,
            "roles": super::role_names(roles),
            "state": state,
            "final": finalized,
            "confirmed": super::role_names(c.confirmed),
            "contradicted": super::role_names(c.contradicted),
            "unchecked": super::role_names(c.unchecked),
        });
        if slot > 0 {
            let o = v.as_object_mut().expect("an object");
            o.insert("txHash".into(), c.tx_hash.map(|h| hex(&h)).into());
            o.insert("from".into(), c.from.map(|a| hex(&a)).into());
            o.insert("to".into(), c.to.map(|a| hex(&a)).into());
            o.insert("value".into(), scalar(&c.value).into());
            o.insert(
                "transfer".into(),
                c.transfer
                    .as_ref()
                    .map(|t| {
                        serde_json::json!({"token": hex(&t.token), "from": hex(&t.from), "to": hex(&t.to), "data": hex(&t.data)})
                    })
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        v
    }

    /// A block this node cannot verify: asking again does not help.
    pub(super) fn not_verifiable(block: u64, slot: u32, roles: u8, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "block": block,
            "slot": slot,
            "roles": super::role_names(roles),
            "state": "unverified",
            "reason": reason,
        })
    }

    pub(super) fn unavailable(block: u64, slot: u32, roles: u8, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "block": block,
            "slot": slot,
            "roles": super::role_names(roles),
            "state": "unavailable",
            "reason": reason,
        })
    }
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
            if let Some(running) = slot.take() {
                // At once, also for reads still holding the node: no Swarm request may
                // outlive the switch (the node does not route through Tor).
                running.node.stop();
                tracing::info!("addr1: Swarm reader stopped");
            }
        }
    }

    /// The node for `network`, started (or restarted for another network) on first use.
    fn node(network: &Network) -> Result<(Arc<SwarmNode>, Instant), Failure> {
        let mut slot = NODE.lock().map_err(|_| Failure::Retry("Swarm reader lock poisoned".into()))?;
        // Checked again under the lock: Tor turned on between the caller's check and here
        // (its stop() found no node) must not see one started now.
        if super::tor_on() {
            return Err(Failure::Refused(
                "the address history is not available while Tor routing is on".to_string(),
            ));
        }
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

    /// A read that failed for now (`ReadError::Transient`) before any page could be read
    /// (the origin, the head): on a freshly started node "no usable peers yet"
    /// (`myotis_swarm::NOT_READY_TEXT`) or a stream that could not be opened yet. Worth
    /// asking again while the node is fresh, and only then; a stopped node never is.
    fn transient(e: &ReadError) -> bool {
        matches!(e, ReadError::Transient(_))
    }

    /// One page, on the engine's runtime (as every other host read).
    pub fn page(
        rt: &tokio::runtime::Runtime,
        cfg: &Config,
        chain_id: u64,
        importer: [u8; 20],
        address: &[u8; 20],
        cursor: Option<super::Cursor>,
        limit: usize,
    ) -> Result<Read, Failure> {
        let (node, started) = node(&cfg.network)?;
        let floor = cursor.map(|c| c.head_update).unwrap_or(0);
        let start = hint(chain_id, importer).max(floor);
        let before = cursor.map(|c| c.before);
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
        if read.head_update < floor {
            // An update the cursor's page was read at was not found now: retryable, never
            // a page from an older head (it would miss entries without naming a gap).
            return Err(Failure::Retry(format!(
                "the index's head update {} was found, older than the cursor's {floor}: try again",
                read.head_update
            )));
        }
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
        _cursor: Option<super::Cursor>,
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
        let ok = parse_config(r#"{"importer":"0x1111111111111111111111111111111111111111","swarm":{"network":"dev","networkId":7,"bootnodes":["/ip4/192.0.2.1/tcp/1634"]}}"#).unwrap();
        assert_eq!(ok.importer, Some([0x11; 20]));
        assert!(matches!(ok.network, Network::Dev { network_id: 7, .. }));
        assert_eq!(parse_config("{}").unwrap(), Config::default());
        assert_eq!(parse_config(r#"{"importer":null,"swarm":{"network":"mainnet"}}"#).unwrap(), Config::default());
        for bad in [
            r#"{"importer":"0x12"}"#,
            r#"{"importer":5}"#,
            r#"{"other":1}"#,
            r#"{"swarm":{"network":"dev","networkId":7}}"#,
            r#"{"swarm":{"network":"dev","networkId":7,"bootnodes":[]}}"#,
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
    fn verify_entries_are_applied_or_refused_whole() {
        let ok = parse_entries(r#"[{"block":100,"slot":3,"roles":["from","emitter"],"state":"unverified"},{"block":101,"slot":0,"roles":["block"]}]"#).unwrap();
        assert_eq!(ok, vec![(100, 3, 0x05), (101, 0, 0x40)]);
        // A kept verdict as a page renders it goes back in as it came.
        let echoed = r#"[{"block":1,"slot":2,"roles":["from"],"state":"verified","final":true,"confirmed":["from"],"contradicted":[],"unchecked":[],"txHash":"0x00","from":"0x01","to":null,"value":"0x0","transfer":null}]"#;
        assert_eq!(parse_entries(echoed).unwrap(), vec![(1, 2, 0x01)]);
        for bad in [
            "[]",
            "{}",
            r#"[{"block":1,"slot":1}]"#,
            r#"[{"block":1,"slot":1,"roles":[]}]"#,
            r#"[{"block":1,"slot":1,"roles":["sender"]}]"#,
            r#"[{"block":1,"slot":1,"roles":["from"],"extra":1}]"#,
            r#"[{"block":"1","slot":1,"roles":["from"]}]"#,
            r#"[{"block":1,"slot":4294967296,"roles":["from"]}]"#,
            r#"[{"block":1,"slot":1,"roles":["from"],"state":"trusted"}]"#,
        ] {
            assert!(parse_entries(bad).is_err(), "{bad}");
        }
        let many = format!("[{}]", vec![r#"{"block":1,"slot":1,"roles":["from"]}"#; MAX_VERIFY + 1].join(","));
        assert!(parse_entries(&many).is_err());
    }

    #[test]
    fn a_kept_verdict_is_what_a_later_page_shows() {
        use myotis_addr1::client::Page;
        use myotis_addr1::records::{role, Entry};
        let who = (1u64, [0x42; 20]);
        let kept = serde_json::json!({"block": 500, "slot": 2, "roles": ["from"], "state": "verified", "final": true});
        verified::keep(who.0, &who.1, 500, 2, role::FROM, &kept);
        let read = Read {
            head_update: 1,
            page: Page {
                entries: vec![Entry { block: 500, slot: 2, roles: role::FROM }, Entry { block: 499, slot: 1, roles: role::TO }],
                next: None,
                from_block: 0,
                to_block: 600,
                gaps: vec![],
            },
        };
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0; 20], Some(600), who)).unwrap();
        assert_eq!(v["entries"][0]["state"], "verified");
        assert_eq!(v["entries"][1]["state"], "unverified");
        // Another address's page does not see it.
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0; 20], Some(600), (1, [0x43; 20]))).unwrap();
        assert_eq!(v["entries"][0]["state"], "unverified");
    }

    #[test]
    fn cursors_round_trip() {
        assert_eq!(
            parse_cursor("9:1000:5"),
            Some(Cursor { head_update: 9, before: (1000, 5) })
        );
        for bad in ["", "1", "1:2", "a:1:1", "1:b:1", "1:2:c", "1:2:3:4", "+5:+1:1", ":1:1", "1:2:"] {
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
    /// <bootnode multiaddr> <importer> <address with at least ten entries>"`. Nothing of the
    /// setup is in the test: the same code reads any index.
    #[cfg(feature = "swarm")]
    #[test]
    #[ignore]
    fn a_live_page_through_the_embedded_node() {
        let env = std::env::var("MYOTIS_ADDR1_DEV").expect("MYOTIS_ADDR1_DEV");
        let f: Vec<&str> = env.split_whitespace().collect();
        let cfg = format!(r#"{{"importer":"{}","swarm":{{"network":"dev","networkId":{},"bootnodes":["{}"]}}}}"#, f[2], f[0], f[1]);
        assert_eq!(set_config_json(&cfg), "{}");
        let weth = f[3];
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
                entries: vec![Entry { block: 127_999, slot: 477, roles: role::TO | role::EMITTER }],
                next: Some((127_999, 477)),
                from_block: 64_000,
                to_block: 127_999,
                gaps: vec![Gap { from_block: 10, to_block: 20 }],
            },
        };
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0xef; 20], Some(128_100), (1, [0x42; 20]))).unwrap();
        assert_eq!(v["headUpdate"], 73);
        assert_eq!(v["coveredFrom"], 64_000);
        assert_eq!(v["headGap"]["fromBlock"], 128_000);
        assert_eq!(v["headGap"]["toBlock"], 128_100);
        assert_eq!(v["gaps"][0]["toBlock"], 20);
        assert_eq!(v["entries"][0]["roles"], serde_json::json!(["to", "emitter"]));
        assert_eq!(v["entries"][0]["state"], "unverified");
        assert_eq!(v["next"], "73:127999:477");
        // An index that starts late names the blocks below it.
        assert_eq!(v["tailGap"]["toBlock"], 63_999);
        // At the head: no head gap.
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0xef; 20], Some(127_999), (1, [0x42; 20]))).unwrap();
        assert!(v["headGap"].is_null());
        // No verified head yet: an open head gap, never "none".
        let v: serde_json::Value = serde_json::from_str(&page_json(&read, [0xef; 20], None, (1, [0x42; 20]))).unwrap();
        assert_eq!(v["headGap"]["fromBlock"], 128_000);
        assert!(v["headGap"]["toBlock"].is_null());
    }
}
