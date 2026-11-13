//! Helpers shared by the diagnostic probes (`snap_probe`, `eez_probe`), pulled
//! in with `#[path = "probe_common/mod.rs"] mod probe_common;`. A directory
//! without a `main.rs`, so Cargo's example auto-discovery leaves it alone.
//!
//! Everything here speaks RAW frames on an [`RlpxConnection`], for the cases
//! where the production `EthSession` cannot be used: reading a peer's Status
//! without first sending ours, or a foreign chain's Status / header shape.

// Each probe uses its own subset.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use myotis_core::nodekey::NodeKey;
use myotis_core::rlp;
use myotis_net::el::eth::messages as eth;
use myotis_net::el::rlpx::transport::RlpxConnection;
use myotis_wire::rlpx::hello::{Hello, P2P_PING, P2P_PONG};

/// A fresh node id per run: a fixed one would carry any peer's throttle or
/// ban of an earlier run into every later one, from every host.
pub fn fresh_node_key() -> Arc<NodeKey> {
    Arc::new(loop {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("OS entropy");
        if let Ok(k) = NodeKey::from_secret_bytes(&secret) {
            break k;
        }
    })
}

/// Bound and escape a peer-controlled string (client id, capability names)
/// before it reaches the terminal.
pub fn truncate(s: &str, n: usize) -> String {
    s.chars()
        .take(n)
        .collect::<String>()
        .escape_debug()
        .to_string()
}

/// A Hello's capabilities as `name/version,…`, escaped and bounded: the names
/// are peer-controlled bytes (`from_utf8_lossy` in `decode_hello`).
pub fn caps_line(hello: &Hello) -> String {
    truncate(
        &hello
            .capabilities
            .iter()
            .map(|c| format!("{}/{}", c.name, c.version))
            .collect::<Vec<_>>()
            .join(","),
        120,
    )
}

/// Receive the next non-Ping frame, answering Pings and politely refusing any
/// eth Get* request with an empty response (we serve nothing).
pub async fn recv_frame(conn: &mut RlpxConnection, secs: u64) -> Result<(u64, Vec<u8>), String> {
    let fut = async {
        loop {
            let f = conn.recv().await?;
            match f.message_code {
                P2P_PING => conn.send(P2P_PONG, &[0xc0]).await?,
                eth::GET_BLOCK_HEADERS | eth::GET_BLOCK_BODIES | eth::GET_RECEIPTS => {
                    if let Some(id) = eth::leading_request_id(&f.payload) {
                        conn.send(f.message_code + 1, &eth::encode_empty_response(id))
                            .await?;
                    }
                }
                code => return Ok((code, f.payload)),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(secs), fut)
        .await
        .map_err(|_| "recv timeout".to_string())?
}

/// Highest eth / snap version both sides advertise. Our side is read back from
/// the very Hello we send (`encode_hello`), so this can never disagree with it.
pub fn negotiate(ours: &Hello, theirs: &Hello) -> (Option<u64>, Option<u64>) {
    let common = |name: &str| {
        theirs
            .capabilities
            .iter()
            .filter(|c| {
                c.name == name
                    && ours
                        .capabilities
                        .iter()
                        .any(|o| o.name == name && o.version == c.version)
            })
            .map(|c| c.version)
            .max()
    };
    (common("eth"), common("snap"))
}

/// Lenient Status read: network id is always field 1. The head hash is the
/// standard field when the strict decoder accepts the Status; otherwise (Bor's
/// eth/69 keeps a TD field) pick by layout: eth/66-68 `[ver, nid, td,
/// bestHash, genesis, forkId]` → field 3; eth/69+ → the last field
/// (`latestHash`).
pub fn read_status(
    payload: &[u8],
    eth_version: u64,
) -> Result<(u64, [u8; 32], Option<u64>), String> {
    if let Ok(s) = eth::decode_status(payload, eth_version) {
        return Ok((s.network_id, s.best_hash, s.latest_block));
    }
    let top = rlp::decode(payload).map_err(|e| e.0)?;
    let items = top.as_list().map_err(|e| e.0)?;
    let nid = items
        .get(1)
        .ok_or("short status")?
        .as_u64()
        .map_err(|e| e.0)?;
    let head = if eth_version >= 69 {
        items.last()
    } else {
        items.get(3)
    };
    let head = head.ok_or("short status")?.as_bytes().map_err(|e| e.0)?;
    let head: [u8; 32] = head
        .try_into()
        .map_err(|_| format!("status: head hash is {} bytes", head.len()))?;
    Ok((nid, head, None))
}

/// A p2p Disconnect's reason code — `[reason]` or a bare byte, both seen in
/// the wild — so a verdict histogram groups by reason, not by encoding.
pub fn disconnect_reason(payload: &[u8]) -> String {
    let reason = rlp::decode(payload)
        .ok()
        .and_then(|item| match item.as_list() {
            Ok(list) => list.first().and_then(|r| r.as_u64().ok()),
            Err(_) => item.as_u64().ok(),
        });
    match reason {
        Some(r) => format!("reason {r}"),
        None => format!("undecodable ({} bytes)", payload.len()),
    }
}
