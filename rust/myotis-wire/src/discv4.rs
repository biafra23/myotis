//! discv4 — UDP Kademlia peer discovery (EL-A3), twin of the Java
//! `networking.discv4` package (docs/reimplementation/02 §2).
//!
//! Wire format:
//! ```text
//! packet    = hash(32) ‖ signature(65) ‖ packet-type(1) ‖ packet-data(RLP)
//! sigHash   = keccak256(packet-type ‖ packet-data)      — signed DIRECTLY, no re-hash
//! signature = r(32) ‖ s(32) ‖ v(1)                       — v = recovery id 0/1
//! hash      = keccak256(signature ‖ packet-type ‖ packet-data)
//! ```
//!
//! Client-only, like the Java reference: we ping / find-node and consume
//! Neighbors, we never answer FindNode and never send Neighbors (inbound
//! Pings get a Pong so bonds form). The packet codec, Kademlia table, and
//! rate limiter are pure (clock values are parameters) and pinned by the
//! `rust/testdata/el/discv4/` cross-language corpus; only `myotis-net`'s `Discv4Service`
//! touches sockets.
//
// Moved here from `myotis-net::el::discv4` (myotis#505) so hosts without tokio
// (firmware, wasm, their own event loop) get the same codec; `myotis-net`
// re-exports it unchanged.


#[allow(unused_imports)]
use alloc::{borrow::ToOwned, format, string::{String, ToString}, vec, vec::Vec};
use myotis_core::keccak::{keccak256, keccak256_concat};
use myotis_core::nodekey::{recover_public_key, NodeKey};
use myotis_core::rlp::{self, Item};
use myotis_core::CoreError;


pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_FIND_NODE: u8 = 0x03;
pub const TYPE_NEIGHBORS: u8 = 0x04;
/// EIP-868: ask a bonded node for its ENR; the reply echoes the request hash.
pub const TYPE_ENR_REQUEST: u8 = 0x05;
pub const TYPE_ENR_RESPONSE: u8 = 0x06;

/// Ping/Pong protocol version.
const VERSION: u64 = 4;

/// Expiry horizon for outgoing packets (seconds past `now`).
pub const EXPIRY_SECONDS: u64 = 20;

// ---------------------------------------------------------------------------
// Packet codec (pure — expiry is a parameter, entropy comes from the caller).
// ---------------------------------------------------------------------------

/// A parsed and signature-verified inbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The packet hash (echoed in Pong as the ping reference).
    pub hash: [u8; 32],
    pub packet_type: u8,
    /// The RLP packet-data (after the type byte).
    pub data: Vec<u8>,
    /// Recovered 64-byte sender public key (the enode id / RLPx dial key).
    pub sender_pubkey: [u8; 64],
}

/// Encode `Ping: [version, from, to, expiry]`. The `from` endpoint carries
/// our UDP port as the TCP port too (Java parity); `to.tcp` is 0.
pub fn encode_ping(
    key: &NodeKey,
    from_ip: &[u8],
    from_udp_port: u16,
    to_ip: &[u8],
    to_udp_port: u16,
    expiry: u64,
) -> Result<Vec<u8>, CoreError> {
    let mut payload = rlp::encode_u64(VERSION);
    payload.extend_from_slice(&encode_endpoint(from_ip, from_udp_port, from_udp_port));
    payload.extend_from_slice(&encode_endpoint(to_ip, to_udp_port, 0));
    payload.extend_from_slice(&rlp::encode_u64(expiry));
    encode_packet(key, TYPE_PING, &rlp::encode_list_payload(&payload))
}

/// Encode `Pong: [to, ping-hash, expiry]`.
pub fn encode_pong(
    key: &NodeKey,
    to_ip: &[u8],
    to_udp_port: u16,
    ping_hash: &[u8; 32],
    expiry: u64,
) -> Result<Vec<u8>, CoreError> {
    let mut payload = encode_endpoint(to_ip, to_udp_port, 0);
    payload.extend_from_slice(&rlp::encode_bytes(ping_hash));
    payload.extend_from_slice(&rlp::encode_u64(expiry));
    encode_packet(key, TYPE_PONG, &rlp::encode_list_payload(&payload))
}

/// Encode `FindNode: [target(64-byte pubkey), expiry]`.
pub fn encode_find_node(key: &NodeKey, target: &[u8], expiry: u64) -> Result<Vec<u8>, CoreError> {
    let mut payload = rlp::encode_bytes(target);
    payload.extend_from_slice(&rlp::encode_u64(expiry));
    encode_packet(key, TYPE_FIND_NODE, &rlp::encode_list_payload(&payload))
}

/// EIP-868 ENRRequest: `[expiration]`.
pub fn encode_enr_request(key: &NodeKey, expiry: u64) -> Result<Vec<u8>, CoreError> {
    let payload = rlp::encode_u64(expiry);
    encode_packet(key, TYPE_ENR_REQUEST, &rlp::encode_list_payload(&payload))
}

/// The expiration of an ENRRequest.
pub fn decode_enr_request_expiry(data: &[u8]) -> Result<u64, CoreError> {
    decode_lenient(data)?
        .as_list()?
        .first()
        .ok_or_else(|| CoreError("ENRRequest: missing expiration".into()))?
        .as_u64()
}

/// EIP-868 ENRResponse: `[request-hash, ENR]`, the ENR spliced in as the RLP
/// list it already is.
pub fn encode_enr_response(
    key: &NodeKey,
    request_hash: &[u8; 32],
    enr_rlp: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut payload = rlp::encode_bytes(request_hash);
    payload.extend_from_slice(enr_rlp);
    encode_packet(key, TYPE_ENR_RESPONSE, &rlp::encode_list_payload(&payload))
}

/// The request hash and the ENR (re-encoded from the parsed list — canonical
/// RLP, which is what an ENR signature covers) of an ENRResponse.
pub fn decode_enr_response(data: &[u8]) -> Result<([u8; 32], Vec<u8>), CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    let hash_item = items
        .first()
        .ok_or_else(|| CoreError("ENRResponse: missing request hash".into()))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hash_item.as_fixed_bytes(32)?);
    let enr = items
        .get(1)
        .filter(|e| e.is_list())
        .ok_or_else(|| CoreError("ENRResponse: missing ENR".into()))?;
    Ok((hash, rlp::encode(enr)))
}

/// Endpoint: `[ip(4|16), udpPort, tcpPort]`.
fn encode_endpoint(ip: &[u8], udp_port: u16, tcp_port: u16) -> Vec<u8> {
    let mut payload = rlp::encode_bytes(ip);
    payload.extend_from_slice(&rlp::encode_u64(u64::from(udp_port)));
    payload.extend_from_slice(&rlp::encode_u64(u64::from(tcp_port)));
    rlp::encode_list_payload(&payload)
}

fn encode_packet(key: &NodeKey, packet_type: u8, data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let sig_hash = keccak256_concat(&[packet_type], data);
    let sig = key.sign_hash(&sig_hash)?;
    // hash = keccak256(sig ‖ type ‖ data)
    let mut tail = Vec::with_capacity(65 + 1 + data.len());
    tail.extend_from_slice(&sig);
    tail.push(packet_type);
    tail.extend_from_slice(data);
    let hash = keccak256(&tail);
    let mut out = Vec::with_capacity(32 + tail.len());
    out.extend_from_slice(&hash);
    out.extend_from_slice(&tail);
    Ok(out)
}

/// Sign and frame any packet type -- for tests that craft packets this client
/// never sends (Neighbors, from a peer's side).
#[cfg(any(test, feature = "test-util"))]
pub fn encode_packet_for_test(key: &NodeKey, packet_type: u8, data: &[u8]) -> Result<Vec<u8>, CoreError> {
    encode_packet(key, packet_type, data)
}

/// Parse and verify an inbound packet: hash check, then sender recovery.
pub fn parse(packet: &[u8]) -> Result<Parsed, CoreError> {
    if packet.len() < 98 {
        return Err(CoreError(format!("Packet too short: {}", packet.len())));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&packet[..32]);
    if keccak256(&packet[32..]) != hash {
        return Err(CoreError("Packet hash mismatch".into()));
    }
    let mut sig = [0u8; 65];
    sig.copy_from_slice(&packet[32..97]);
    let msg_hash = keccak256(&packet[97..]); // type ‖ data
    let sender_pubkey = recover_public_key(&msg_hash, &sig)?;
    Ok(Parsed {
        hash,
        packet_type: packet[97],
        data: packet[98..].to_vec(),
        sender_pubkey,
    })
}

/// Decode one RLP value from a discv4 packet-data field, TOLERATING trailing
/// bytes (EIP-8: discovery packets may carry extra data after the RLP value,
/// and the Java twin's Tuweni `decodeList` never checks for completeness).
fn decode_lenient(data: &[u8]) -> Result<Item, CoreError> {
    let (item, _used) = rlp::decode_at(data, 0)?;
    Ok(item)
}

/// The `(udp, tcp)` ports from a Ping's self-reported FROM endpoint.
pub fn decode_ping_from_ports(data: &[u8]) -> Result<(u32, u32), CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    // [version, from, to, expiry] — from = [ip, udp, tcp].
    let from = items
        .get(1)
        .ok_or_else(|| CoreError("Ping: missing from endpoint".into()))?
        .as_list()?;
    if from.len() < 3 {
        return Err(CoreError("Ping: short from endpoint".into()));
    }
    Ok((read_u32(&from[1])?, read_u32(&from[2])?))
}

/// The echoed ping hash from a Pong: `[to, ping-hash, expiry]`.
pub fn decode_pong_ping_hash(data: &[u8]) -> Result<[u8; 32], CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    let hash_item = items
        .get(1)
        .ok_or_else(|| CoreError("Pong: missing ping hash".into()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(hash_item.as_fixed_bytes(32)?);
    Ok(out)
}

/// A node from a Neighbors packet: `[ip, udp, tcp, nodeId(64-byte pubkey)]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// 4 (v4) or 16 (v6) bytes — anything else is skipped at decode.
    pub ip: Vec<u8>,
    pub udp_port: u16,
    /// Kept as the wire integer (Java parity: not range-checked).
    pub tcp_port: u32,
    /// The node's public key bytes as sent (64 expected, not enforced).
    pub node_id: Vec<u8>,
}

/// Decode `Neighbors: [[node, …], expiry]` with the Java decoder's exact
/// leniency: a structurally malformed node entry STOPS the walk (keeping
/// nodes decoded so far); a node with a bad ip length or an out-of-range
/// UDP port is SKIPPED individually.
pub fn decode_neighbors(data: &[u8]) -> Result<Vec<DiscoveredPeer>, CoreError> {
    let top = decode_lenient(data)?;
    let items = top.as_list()?;
    let nodes = items
        .first()
        .ok_or_else(|| CoreError("Neighbors: missing node list".into()))?
        .as_list()?;
    let mut peers = Vec::new();
    for node in nodes {
        let fields = match node.as_list() {
            Ok(f) if f.len() >= 4 => f,
            _ => break, // malformed entry → stop, keep what we have (Java parity)
        };
        let (Ok(ip), Ok(udp), Ok(tcp), Ok(node_id)) = (
            fields[0].as_bytes(),
            read_u32(&fields[1]),
            read_u32(&fields[2]),
            fields[3].as_bytes(),
        ) else {
            break; // field-level RLP type errors also stop the walk
        };
        // Java skips a node whose InetAddress/InetSocketAddress construction
        // throws: wrong ip length or udp port > 65535.
        if !(ip.len() == 4 || ip.len() == 16) || udp > 65535 {
            continue;
        }
        peers.push(DiscoveredPeer {
            ip: ip.to_vec(),
            udp_port: udp as u16,
            tcp_port: tcp,
            node_id: node_id.to_vec(),
        });
    }
    Ok(peers)
}

/// Canonical unsigned integer ≤ 4 bytes (Tuweni `readInt` shape).
fn read_u32(item: &Item) -> Result<u32, CoreError> {
    let v = item.as_u64()?;
    if v > u64::from(u32::MAX) {
        return Err(CoreError("integer exceeds 32 bits".into()));
    }
    Ok(v as u32)
}

// ---------------------------------------------------------------------------
