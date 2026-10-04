//! The p2p Hello message and base-protocol message codes, moved here from
//! `myotis-net::el::rlpx::transport` (myotis#505).

#[allow(unused_imports)]
use alloc::{borrow::ToOwned, format, string::{String, ToString}, vec, vec::Vec};

pub const P2P_HELLO: u64 = 0x00;
pub const P2P_DISCONNECT: u64 = 0x01;
pub const P2P_PING: u64 = 0x02;
pub const P2P_PONG: u64 = 0x03;

/// Build a p2p Hello body: `[protocolVersion, clientId, [[cap,ver]…], listenPort, nodeId]`.
/// Advertises eth/66-69 + snap/1 (ascending), matching the Java `HelloMessage`.
pub fn encode_hello(node_pubkey: &[u8; 64], listen_port: u16) -> Vec<u8> {
    use myotis_core::rlp::{self, Item};
    let cap = |name: &str, ver: u64| {
        Item::List(vec![
            Item::Bytes(name.as_bytes().to_vec()),
            Item::Bytes(rlp::u64_to_minimal_be(ver)),
        ])
    };
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(5)), // protocol version
        // CARGO_PKG_VERSION is the workspace version (rust/Cargo.toml
        // [workspace.package]), kept equal to the Gradle release version by
        // `verifyCrateVersions`; the Java engine generates its Hello id from
        // that same Gradle version, so the two engines agree by construction.
        Item::Bytes(concat!("myotis/", env!("CARGO_PKG_VERSION")).as_bytes().to_vec()),
        Item::List(vec![
            cap("eth", 66),
            cap("eth", 67),
            cap("eth", 68),
            cap("eth", 69),
            cap("snap", 1),
        ]),
        Item::Bytes(rlp::u64_to_minimal_be(u64::from(listen_port))),
        Item::Bytes(node_pubkey.to_vec()),
    ]))
}

/// One negotiated capability from a peer's Hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub name: String,
    pub version: u64,
}

/// A decoded p2p Hello. Full eth capability negotiation is EL-A5; this is
/// enough to confirm FRAMED and read the peer's advertised caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: u64,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u64,
    pub node_id: Vec<u8>,
}

/// Decode a p2p Hello body. A Hello over [`MAX_CONTROL_MSG_SIZE`] is refused
/// before its tree is built (#454); real ones are a few hundred bytes.
///
/// [`MAX_CONTROL_MSG_SIZE`]: super::frame::MAX_CONTROL_MSG_SIZE
pub fn decode_hello(body: &[u8]) -> Result<Hello, String> {
    use super::frame::MAX_CONTROL_MSG_SIZE;
    use myotis_core::rlp;
    if body.len() > MAX_CONTROL_MSG_SIZE {
        return Err(format!(
            "hello: {} bytes is over the {MAX_CONTROL_MSG_SIZE}-byte control-message cap",
            body.len()
        ));
    }
    let top = rlp::decode(body).map_err(|e| format!("hello: {}", e.0))?;
    let items = top.as_list().map_err(|e| format!("hello: {}", e.0))?;
    if items.len() < 5 {
        return Err(format!("hello: expected 5 fields, got {}", items.len()));
    }
    let protocol_version = items[0].as_u64().map_err(|e| e.0)?;
    let client_id = String::from_utf8_lossy(items[1].as_bytes().map_err(|e| e.0)?).into_owned();
    let mut capabilities = Vec::new();
    for c in items[2].as_list().map_err(|e| e.0)? {
        let fields = c.as_list().map_err(|e| e.0)?;
        if fields.len() >= 2 {
            capabilities.push(Capability {
                name: String::from_utf8_lossy(fields[0].as_bytes().map_err(|e| e.0)?).into_owned(),
                version: fields[1].as_u64().map_err(|e| e.0)?,
            });
        }
    }
    let listen_port = items[3].as_u64().map_err(|e| e.0)?;
    let node_id = items[4].as_bytes().map_err(|e| e.0)?.to_vec();
    Ok(Hello {
        protocol_version,
        client_id,
        capabilities,
        listen_port,
        node_id,
    })
}

