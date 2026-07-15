//! eth/66-69 sub-protocol messages (EL-A5), twin of the Java
//! `networking.eth.messages` package (docs/reimplementation/02 §6).
//!
//! Pure encode/decode over bytes — the async handshake + request correlation
//! live in [`super::session`]. Message codes are the ABSOLUTE eth codes (p2p
//! base 0x10); the session maps the p2p Hello/Ping/Pong below 0x10.

use myotis_core::bloom::{accrue, EMPTY_BLOOM};
use myotis_core::header::{self, BlockHeader};
use myotis_core::rlp::{self, Item};
use myotis_core::CoreError;

// Absolute eth message codes (p2p base 0x10).
pub const STATUS: u64 = 0x10;
pub const NEW_BLOCK_HASHES: u64 = 0x11;
pub const TRANSACTIONS: u64 = 0x12;
pub const GET_BLOCK_HEADERS: u64 = 0x13;
pub const BLOCK_HEADERS: u64 = 0x14;
pub const GET_BLOCK_BODIES: u64 = 0x15;
pub const BLOCK_BODIES: u64 = 0x16;
pub const NEW_POOLED_TRANSACTION_HASHES: u64 = 0x18;
pub const GET_RECEIPTS: u64 = 0x1f;
pub const RECEIPTS: u64 = 0x20;

// ---------------------------------------------------------------------------
// Status (0x10).
// ---------------------------------------------------------------------------

/// A decoded eth Status. eth/67-68 carries `td`; eth/69 carries block numbers
/// instead (docs/reimplementation/02 §6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub protocol_version: u64,
    pub network_id: u64,
    pub genesis_hash: [u8; 32],
    /// eth/69: the latest block hash; eth/67-68: the peer's best hash.
    pub best_hash: [u8; 32],
    pub fork_id_hash: [u8; 4],
    pub fork_next: u64,
    /// eth/69 only (`None` on 67-68).
    pub latest_block: Option<u64>,
    /// eth/69 only (`None` on 67-68): the oldest block the peer can serve.
    pub earliest_block: Option<u64>,
}

/// Encode our Status for eth/67-68: `[version, networkId, td(empty), bestHash,
/// genesisHash, [forkHash, forkNext]]` (post-Merge td is empty).
pub fn encode_status(
    eth_version: u64,
    network_id: u64,
    genesis_hash: &[u8; 32],
    best_hash: &[u8; 32],
    fork_id_hash: &[u8; 4],
    fork_next: u64,
) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(eth_version)),
        Item::Bytes(rlp::u64_to_minimal_be(network_id)),
        Item::Bytes(Vec::new()), // total difficulty = empty (post-Merge)
        Item::Bytes(best_hash.to_vec()),
        Item::Bytes(genesis_hash.to_vec()),
        fork_id_item(fork_id_hash, fork_next),
    ]))
}

/// Encode our Status for eth/69: `[version, networkId, genesis, [forkHash,
/// forkNext], earliestBlock, latestBlock, latestBlockHash]` (no td).
///
/// The eth/69 (EIP-7642) block range is a promise of what we can SERVE — the
/// Java twin advertises only its held header window (never `[0, head]`), and
/// callers here must do the same.
pub fn encode_status69(
    eth_version: u64,
    network_id: u64,
    genesis_hash: &[u8; 32],
    latest_block_hash: &[u8; 32],
    fork_id_hash: &[u8; 4],
    fork_next: u64,
    earliest_block: u64,
    latest_block: u64,
) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(eth_version)),
        Item::Bytes(rlp::u64_to_minimal_be(network_id)),
        Item::Bytes(genesis_hash.to_vec()),
        fork_id_item(fork_id_hash, fork_next),
        Item::Bytes(rlp::u64_to_minimal_be(earliest_block)),
        Item::Bytes(rlp::u64_to_minimal_be(latest_block)),
        Item::Bytes(latest_block_hash.to_vec()),
    ]))
}

fn fork_id_item(fork_id_hash: &[u8; 4], fork_next: u64) -> Item {
    Item::List(vec![
        Item::Bytes(fork_id_hash.to_vec()),
        Item::Bytes(rlp::u64_to_minimal_be(fork_next)),
    ])
}

/// Decode a peer Status. `eth_version >= 69` selects the eth/69 layout.
pub fn decode_status(rlp_bytes: &[u8], eth_version: u64) -> Result<Status, CoreError> {
    let top = rlp::decode(rlp_bytes)?;
    let items = top.as_list()?;
    if eth_version >= 69 {
        // [version, networkId, genesis, forkId, earliest, latest, latestHash]
        if items.len() < 7 {
            return err_status(items.len());
        }
        let fork = items[3].as_list()?;
        Ok(Status {
            protocol_version: items[0].as_u64()?,
            network_id: items[1].as_u64()?,
            genesis_hash: fixed32(&items[2])?,
            best_hash: fixed32(&items[6])?,
            fork_id_hash: fork_id_hash(fork)?,
            fork_next: fork.get(1).map_or(Ok(0), Item::as_u64)?,
            latest_block: Some(items[5].as_u64()?),
            earliest_block: Some(items[4].as_u64()?),
        })
    } else {
        // [version, networkId, td, bestHash, genesis, forkId]. forkId is
        // MANDATORY for eth/66+ (EIP-2124), so require all 6 fields.
        if items.len() < 6 {
            return err_status(items.len());
        }
        let fork = items[5].as_list()?;
        Ok(Status {
            protocol_version: items[0].as_u64()?,
            network_id: items[1].as_u64()?,
            genesis_hash: fixed32(&items[4])?,
            best_hash: fixed32(&items[3])?,
            fork_id_hash: fork_id_hash(fork)?,
            fork_next: fork.get(1).map_or(Ok(0), Item::as_u64)?,
            latest_block: None,
            earliest_block: None,
        })
    }
}

impl Status {
    /// Compatibility gate: same network id AND genesis (docs/reimplementation/02 §6.4).
    pub fn is_compatible(&self, expected_network_id: u64, expected_genesis: &[u8; 32]) -> bool {
        self.network_id == expected_network_id && &self.genesis_hash == expected_genesis
    }
}

fn err_status<T>(n: usize) -> Result<T, CoreError> {
    Err(CoreError(format!("Status: too few fields ({n})")))
}

fn fork_id_hash(fork: &[Item]) -> Result<[u8; 4], CoreError> {
    // EIP-2124: the fork hash is EXACTLY 4 bytes (CRC32). Reject anything else.
    let bytes = fork
        .first()
        .ok_or_else(|| CoreError("Status: empty forkId".into()))?
        .as_fixed_bytes(4)?;
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// GetBlockHeaders (0x13) / BlockHeaders (0x14).
// ---------------------------------------------------------------------------

/// A peer's GetBlockHeaders origin: by number or by hash (fork probes).
pub enum HeadersOrigin {
    Number(u64),
    Hash([u8; 32]),
}

/// Decode an INBOUND GetBlockHeaders request:
/// `[reqId, [origin, maxHeaders, skip, reverse]]` → `(reqId, origin, max, skip, reverse)`.
/// The origin is a hash iff it is exactly 32 bytes (numbers are minimal-BE ≤ 8).
pub fn decode_get_block_headers(
    payload: &[u8],
) -> Result<(u64, HeadersOrigin, u64, u64, bool), CoreError> {
    let top = rlp::decode(payload)?;
    let items = top.as_list()?;
    if items.len() < 2 {
        return Err(CoreError("GetBlockHeaders: missing query".into()));
    }
    let id = items[0].as_u64()?;
    let q = items[1].as_list()?;
    if q.len() < 4 {
        return Err(CoreError("GetBlockHeaders: short query".into()));
    }
    let origin_bytes = q[0].as_bytes()?;
    let origin = if origin_bytes.len() == 32 {
        let mut h = [0u8; 32];
        h.copy_from_slice(origin_bytes);
        HeadersOrigin::Hash(h)
    } else if origin_bytes.len() <= 8 {
        HeadersOrigin::Number(q[0].as_u64()?)
    } else {
        return Err(CoreError("GetBlockHeaders: origin is neither number nor hash".into()));
    };
    Ok((id, origin, q[1].as_u64()?, q[2].as_u64()?, q[3].as_u64()? != 0))
}

/// Encode a BlockHeaders RESPONSE `[reqId, [header, ...]]` from raw header RLP
/// items (served back exactly as they arrived on the wire — byte-preserving).
pub fn encode_block_headers_response(request_id: u64, raw_headers: &[Vec<u8>]) -> Vec<u8> {
    let mut inner = Vec::new();
    for h in raw_headers {
        inner.extend_from_slice(h);
    }
    let mut body = rlp::encode(&Item::Bytes(rlp::u64_to_minimal_be(request_id)));
    body.extend_from_slice(&rlp::encode_list_payload(&inner));
    rlp::encode_list_payload(&body)
}

/// Encode GetBlockHeaders by block number. ALL of eth/66-69 wrap the request
/// id (only the Status shape and bloomless receipts changed in eth/69 — the
/// Java `EthHandler` decodes every version with the reqId path).
pub fn encode_get_block_headers_by_number(
    request_id: u64,
    block_number: u64,
    max_headers: u64,
    skip: u64,
    reverse: bool,
) -> Vec<u8> {
    encode_get_headers(request_id, Item::Bytes(rlp::u64_to_minimal_be(block_number)), max_headers, skip, reverse)
}

/// Encode GetBlockHeaders by block hash.
pub fn encode_get_block_headers_by_hash(
    request_id: u64,
    block_hash: &[u8; 32],
    max_headers: u64,
    skip: u64,
    reverse: bool,
) -> Vec<u8> {
    encode_get_headers(request_id, Item::Bytes(block_hash.to_vec()), max_headers, skip, reverse)
}

/// `[reqId, []]` — an empty BlockHeaders / BlockBodies / Receipts response, the
/// answer a passive wallet returns to any inbound eth Get* request (it serves
/// no chain data). The response code is the request code + 1 (the caller picks
/// it).
pub fn encode_empty_response(request_id: u64) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        Item::List(vec![]),
    ]))
}

fn encode_get_headers(request_id: u64, start: Item, max_headers: u64, skip: u64, reverse: bool) -> Vec<u8> {
    let body = Item::List(vec![
        start,
        Item::Bytes(rlp::u64_to_minimal_be(max_headers)),
        Item::Bytes(rlp::u64_to_minimal_be(skip)),
        Item::Bytes(rlp::u64_to_minimal_be(u64::from(reverse))),
    ]);
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        body,
    ]))
}

/// A decoded header with its keccak hash and the exact RLP bytes it hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHeader {
    pub hash: [u8; 32],
    pub raw_rlp: Vec<u8>,
    pub header: BlockHeader,
}

/// Decode a BlockHeaders response `[reqId, [header, …]]`. Returns
/// `(request_id, headers)`.
pub fn decode_block_headers(rlp_bytes: &[u8]) -> Result<(u64, Vec<VerifiedHeader>), CoreError> {
    let (request_id, headers_rlp) = strip_request_id(rlp_bytes)?;
    // Each element's RAW sub-slice is the canonical header encoding → hash it.
    let mut out = Vec::new();
    for raw in rlp::raw_list_items(headers_rlp)? {
        let header = BlockHeader::decode(raw)?;
        out.push(VerifiedHeader {
            hash: header::hash(raw),
            raw_rlp: raw.to_vec(),
            header,
        });
    }
    Ok((request_id, out))
}

// ---------------------------------------------------------------------------
// GetBlockBodies (0x15) / BlockBodies (0x16).
// ---------------------------------------------------------------------------

/// Encode GetBlockBodies from a list of block hashes.
pub fn encode_get_block_bodies(request_id: u64, hashes: &[[u8; 32]]) -> Vec<u8> {
    encode_hash_request(request_id, hashes)
}

/// A decoded block body: raw consensus tx bytes (legacy re-encoded, typed kept
/// as the envelope) plus uncle/withdrawal counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBody {
    pub transactions: Vec<Vec<u8>>,
    pub uncle_count: usize,
    pub withdrawal_count: usize,
}

/// Decode a BlockBodies response `[reqId, [body, …]]`.
pub fn decode_block_bodies(rlp_bytes: &[u8]) -> Result<(u64, Vec<BlockBody>), CoreError> {
    let (request_id, bodies_rlp) = strip_request_id(rlp_bytes)?;
    let mut bodies = Vec::new();
    for body_raw in rlp::raw_list_items(bodies_rlp)? {
        // body = [transactions, uncles, withdrawals?] — transactions AND uncles
        // are mandatory (withdrawals only post-Shanghai).
        let fields = rlp::raw_list_items(body_raw)?;
        if fields.len() < 2 {
            return Err(CoreError(format!(
                "BlockBody: expected >= 2 fields, got {}",
                fields.len()
            )));
        }
        let txs_raw = fields[0];
        let mut transactions = Vec::new();
        for tx in rlp::raw_list_items(txs_raw)? {
            // Legacy tx = RLP list (kept as-is, it's canonical); typed tx =
            // byte-string whose payload IS the consensus tx bytes.
            if rlp::is_list_prefix(tx) {
                transactions.push(tx.to_vec());
            } else {
                transactions.push(rlp::strip_bytes_header(tx)?.to_vec());
            }
        }
        let uncle_count = fields
            .get(1)
            .map_or(Ok(0), |u| rlp::raw_list_items(u).map(|v| v.len()))?;
        let withdrawal_count = fields
            .get(2)
            .map_or(Ok(0), |w| rlp::raw_list_items(w).map(|v| v.len()))?;
        bodies.push(BlockBody {
            transactions,
            uncle_count,
            withdrawal_count,
        });
    }
    Ok((request_id, bodies))
}

// ---------------------------------------------------------------------------
// GetReceipts (0x1f) / Receipts (0x20).
// ---------------------------------------------------------------------------

/// Encode GetReceipts from a list of block hashes.
pub fn encode_get_receipts(request_id: u64, hashes: &[[u8; 32]]) -> Vec<u8> {
    encode_hash_request(request_id, hashes)
}

/// Encode an eth `Transactions` message carrying a single raw transaction (no
/// request id — it's an unsolicited broadcast). A legacy tx (a bare RLP list) is
/// embedded as-is; a typed tx (EIP-2718 `type_byte ‖ payload`) is wrapped as an
/// RLP byte-string, per the eth wire rules.
pub fn encode_transactions(raw_tx: &[u8]) -> Vec<u8> {
    let element = if rlp::is_list_prefix(raw_tx) {
        raw_tx.to_vec()
    } else {
        rlp::encode_bytes(raw_tx)
    };
    rlp::encode_list_payload(&element)
}

/// Decode a `NewPooledTransactionHashes` announcement into its 32-byte tx
/// hashes, tolerating BOTH wire shapes: the eth/68 triple
/// `[types: bytes, sizes: [..], hashes: [h, ..]]` and the eth/66-67 flat list
/// `[h, ..]`. Tolerant on purpose — this feeds only the sent-tx watch's
/// "seen in gossip" signal (never a trust surface), so a malformed or
/// unexpected announcement yields the hashes it can read, or none.
pub fn decode_new_pooled_tx_hashes(payload: &[u8]) -> Vec<[u8; 32]> {
    let Ok(top) = rlp::decode(payload) else {
        return Vec::new();
    };
    let Ok(items) = top.as_list() else {
        return Vec::new();
    };
    // eth/68: exactly [types, sizes, hashes] where the LAST item is the hash
    // list. A flat eth/66 list of 3 hashes would ALSO be length 3 — the two
    // are distinguished by the last item's kind (list vs 32-byte string).
    if items.len() == 3 {
        if let Ok(hashes) = items[2].as_list() {
            return collect_hashes(hashes);
        }
    }
    collect_hashes(items)
}

/// The 32-byte items of an RLP hash list; anything else is skipped.
fn collect_hashes(items: &[Item]) -> Vec<[u8; 32]> {
    items
        .iter()
        .filter_map(|item| {
            let bytes = item.as_bytes().ok()?;
            <[u8; 32]>::try_from(bytes).ok()
        })
        .collect()
}

/// Decode a Receipts response into RAW consensus receipt bytes per block (the
/// trie values). eth/66-68 form. Returns `(request_id, per_block_receipts)`.
pub fn decode_receipts(rlp_bytes: &[u8]) -> Result<(u64, Vec<Vec<Vec<u8>>>), CoreError> {
    let (request_id, blocks_rlp) = strip_request_id(rlp_bytes)?;
    let mut blocks = Vec::new();
    for block_raw in rlp::raw_list_items(blocks_rlp)? {
        let mut receipts = Vec::new();
        for receipt in rlp::raw_list_items(block_raw)? {
            // Legacy = RLP list (canonical as-is); typed = byte-string whose
            // payload IS `type ‖ rlp(...)`, the trie value.
            if rlp::is_list_prefix(receipt) {
                receipts.push(receipt.to_vec());
            } else {
                receipts.push(rlp::strip_bytes_header(receipt)?.to_vec());
            }
        }
        blocks.push(receipts);
    }
    Ok((request_id, blocks))
}

/// Decode an eth/69 (EIP-7642) Receipts response into CANONICAL consensus
/// receipt bytes. eth/69 strips the logsBloom and flattens the typed envelope:
/// each receipt arrives as `[txType, statusOrState, cumGas, logs]`. The bloom
/// is a pure function of the logs, so recompute it and re-canonicalize
/// (`type ‖ rlp([status, cumGas, bloom, logs])`) — the receipts-trie check then
/// works exactly as for eth/66-68 (docs/reimplementation/02 §6.6).
pub fn decode_receipts69(rlp_bytes: &[u8]) -> Result<(u64, Vec<Vec<Vec<u8>>>), CoreError> {
    let (request_id, blocks_rlp) = strip_request_id(rlp_bytes)?;
    let mut blocks = Vec::new();
    for block_raw in rlp::raw_list_items(blocks_rlp)? {
        let mut receipts = Vec::new();
        for wire in rlp::raw_list_items(block_raw)? {
            receipts.push(canonicalize_eth69_receipt(wire)?);
        }
        blocks.push(receipts);
    }
    Ok((request_id, blocks))
}

/// One eth/69 wire receipt `[txType, statusOrState, cumGas, logs]` → its
/// canonical consensus encoding with the recomputed bloom.
fn canonicalize_eth69_receipt(wire: &[u8]) -> Result<Vec<u8>, CoreError> {
    let top = rlp::decode(wire)?;
    let fields = top.as_list()?;
    if fields.len() < 4 {
        return Err(CoreError("eth/69 receipt: too few fields".into()));
    }
    // The receipt tx-type is a single byte in `0x00..=0x7f` (0 = legacy). Keep
    // the Java last-byte extraction for the valid single-byte case, but reject
    // multi-byte / out-of-range encodings rather than silently truncating.
    let ty = match fields[0].as_bytes()? {
        [] => 0u8,
        &[b] if b <= 0x7f => b,
        _ => return Err(CoreError("eth/69 receipt: invalid tx type".into())),
    };
    let status_or_state = fields[1].as_bytes()?;
    let cum_gas = fields[2].as_bytes()?;
    let logs = fields[3].as_list()?;

    // Recompute the M3:2048 bloom over every log's address + topics.
    let mut bloom = EMPTY_BLOOM;
    let mut log_items = Vec::with_capacity(logs.len());
    for log in logs {
        let lf = log.as_list()?;
        if lf.len() < 3 {
            return Err(CoreError("eth/69 receipt: malformed log".into()));
        }
        // Consensus rules: a log address is exactly 20 bytes, each topic 32.
        let address = lf[0].as_fixed_bytes(20)?;
        accrue(&mut bloom, address);
        let topics = lf[1].as_list()?;
        for t in topics {
            accrue(&mut bloom, t.as_fixed_bytes(32)?);
        }
        log_items.push(log.clone());
    }

    let payload = rlp::encode(&Item::List(vec![
        Item::Bytes(status_or_state.to_vec()),
        Item::Bytes(cum_gas.to_vec()),
        Item::Bytes(bloom.to_vec()),
        Item::List(log_items),
    ]));
    if ty == 0 {
        Ok(payload)
    } else {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(ty);
        out.extend_from_slice(&payload);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

fn encode_hash_request(request_id: u64, hashes: &[[u8; 32]]) -> Vec<u8> {
    let list = Item::List(hashes.iter().map(|h| Item::Bytes(h.to_vec())).collect());
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(request_id)),
        list,
    ]))
}

/// Strip the `[reqId, payload]` wrapper (present in every eth/66-69 request/
/// response message), returning `(reqId, payload_raw)`.
fn strip_request_id(rlp_bytes: &[u8]) -> Result<(u64, &[u8]), CoreError> {
    let items = rlp::raw_list_items(rlp_bytes)?;
    if items.len() < 2 {
        return Err(CoreError("eth message: missing [reqId, payload]".into()));
    }
    Ok((rlp::decode(items[0])?.as_u64()?, items[1]))
}

fn fixed32(item: &Item) -> Result<[u8; 32], CoreError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(item.as_fixed_bytes(32)?);
    Ok(out)
}

#[cfg(test)]
mod tests {

    #[test]
    fn get_block_headers_request_decode_round_trips() {
        let by_num = encode_get_block_headers_by_number(42, 21_000_000, 16, 2, true);
        let (id, origin, max, skip, reverse) = decode_get_block_headers(&by_num).unwrap();
        assert_eq!(id, 42);
        assert!(matches!(origin, HeadersOrigin::Number(21_000_000)));
        assert_eq!((max, skip, reverse), (16, 2, true));

        let h = [0xabu8; 32];
        let by_hash = encode_get_block_headers_by_hash(7, &h, 1, 0, false);
        let (id, origin, ..) = decode_get_block_headers(&by_hash).unwrap();
        assert_eq!(id, 7);
        assert!(matches!(origin, HeadersOrigin::Hash(x) if x == h));

        assert!(decode_get_block_headers(b"junk").is_err());
    }

    #[test]
    fn block_headers_response_is_byte_preserving() {
        let h1 = rlp::encode(&Item::List(vec![Item::Bytes(vec![1, 2, 3])]));
        let h2 = rlp::encode(&Item::List(vec![Item::Bytes(vec![4])]));
        let resp = encode_block_headers_response(9, &[h1.clone(), h2.clone()]);
        let items = rlp::raw_list_items(&resp).unwrap();
        assert_eq!(rlp::decode(items[0]).unwrap().as_u64().unwrap(), 9);
        let served = rlp::raw_list_items(items[1]).unwrap();
        assert_eq!(served, vec![&h1[..], &h2[..]]);
    }

    use super::*;
    use myotis_core::keccak::keccak256;

    #[test]
    fn decode_new_pooled_tx_hashes_reads_both_wire_shapes() {
        let h1 = [0xaa; 32];
        let h2 = [0xbb; 32];
        // eth/66-67: a flat list of 32-byte hash strings.
        let flat = rlp::encode(&Item::List(vec![
            Item::Bytes(h1.to_vec()),
            Item::Bytes(h2.to_vec()),
        ]));
        assert_eq!(decode_new_pooled_tx_hashes(&flat), vec![h1, h2]);

        // eth/68: [types, sizes, hashes] — the hashes ride in the THIRD item.
        let eth68 = rlp::encode(&Item::List(vec![
            Item::Bytes(vec![0x02, 0x00]),
            Item::List(vec![Item::Bytes(vec![0x80]), Item::Bytes(vec![0x70])]),
            Item::List(vec![Item::Bytes(h1.to_vec()), Item::Bytes(h2.to_vec())]),
        ]));
        assert_eq!(decode_new_pooled_tx_hashes(&eth68), vec![h1, h2]);

        // A flat list of exactly THREE hashes must not be mistaken for eth/68
        // (its third item is a hash string, not a list).
        let three = rlp::encode(&Item::List(vec![
            Item::Bytes(h1.to_vec()),
            Item::Bytes(h2.to_vec()),
            Item::Bytes([0xcc; 32].to_vec()),
        ]));
        assert_eq!(decode_new_pooled_tx_hashes(&three).len(), 3);

        // Tolerant: garbage and wrong-width items yield nothing/skip, no error.
        assert!(decode_new_pooled_tx_hashes(&[0xff, 0x00]).is_empty());
        let short = rlp::encode(&Item::List(vec![Item::Bytes(vec![1, 2, 3])]));
        assert!(decode_new_pooled_tx_hashes(&short).is_empty());
    }

    #[test]
    fn encode_transactions_wraps_legacy_and_typed() {
        // Legacy tx (a bare RLP list) is embedded as-is: the outer item stays a list.
        let legacy = rlp::encode(&Item::List(vec![Item::Bytes(vec![1]), Item::Bytes(vec![2])]));
        let items = rlp::decode(&encode_transactions(&legacy)).unwrap().as_list().unwrap().to_vec();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_list());

        // Typed tx (0x02 ‖ payload) is wrapped as a byte-string: the outer item is
        // the raw envelope bytes recovered verbatim.
        let typed = vec![0x02u8, 0xc2, 0x01, 0x02];
        let items = rlp::decode(&encode_transactions(&typed)).unwrap().as_list().unwrap().to_vec();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_bytes().unwrap(), typed.as_slice());
    }

    #[test]
    fn status_round_trip_67_and_69() {
        let genesis = keccak256(b"genesis");
        let best = keccak256(b"best");
        let fork = [0x07, 0xc9, 0x46, 0x2e];

        let s67 = encode_status(68, 1, &genesis, &best, &fork, 0);
        let d67 = decode_status(&s67, 68).unwrap();
        assert_eq!(d67.network_id, 1);
        assert_eq!(d67.genesis_hash, genesis);
        assert_eq!(d67.best_hash, best);
        assert_eq!(d67.fork_id_hash, fork);
        assert_eq!(d67.latest_block, None);
        assert!(d67.is_compatible(1, &genesis));
        assert!(!d67.is_compatible(2, &genesis));

        let s69 = encode_status69(69, 100, &genesis, &best, &fork, 0, 21_000_000 - 32, 21_000_000);
        let d69 = decode_status(&s69, 69).unwrap();
        assert_eq!(d69.network_id, 100);
        assert_eq!(d69.best_hash, best);
        assert_eq!(d69.latest_block, Some(21_000_000));
        assert_eq!(d69.earliest_block, Some(21_000_000 - 32));
        assert_eq!(d69.fork_id_hash, fork);
    }

    #[test]
    fn get_headers_encoding_wraps_request_id() {
        // All of eth/66-69 wrap `[reqId, [start, max, skip, reverse]]`.
        let msg = encode_get_block_headers_by_number(42, 21_000_000, 1024, 0, false);
        let outer = rlp::decode(&msg).unwrap();
        let items = outer.as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_u64().unwrap(), 42);
        assert_eq!(items[1].as_list().unwrap().len(), 4);
    }

    #[test]
    fn block_headers_decode_and_hash() {
        // Two minimal but well-formed headers, wrapped `[reqId, [h0, h1]]`.
        let h0 = minimal_header(100);
        let h1 = minimal_header(101);
        let hash0 = header::hash(&h0);
        let msg = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(7)),
            Item::List(vec![raw(&h0), raw(&h1)]),
        ]));
        let (req_id, headers) = decode_block_headers(&msg).unwrap();
        assert_eq!(req_id, 7);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].hash, hash0);
        assert_eq!(headers[0].header.number, 100);
        assert_eq!(headers[0].raw_rlp, h0);
    }

    /// Decode an Item back into raw bytes for nesting inside a List literal.
    fn raw(rlp_bytes: &[u8]) -> Item {
        rlp::decode(rlp_bytes).unwrap()
    }

    /// A minimal post-London header (16 fields) with a given block number.
    fn minimal_header(number: u64) -> Vec<u8> {
        let z32 = vec![0u8; 32];
        let mut fields = vec![
            Item::Bytes(z32.clone()),           // parentHash
            Item::Bytes(z32.clone()),           // ommersHash
            Item::Bytes(vec![0u8; 20]),         // beneficiary
            Item::Bytes(z32.clone()),           // stateRoot
            Item::Bytes(z32.clone()),           // txRoot
            Item::Bytes(z32.clone()),           // receiptsRoot
            Item::Bytes(vec![0u8; 256]),        // logsBloom
            Item::Bytes(Vec::new()),            // difficulty = 0
            Item::Bytes(rlp::u64_to_minimal_be(number)),
            Item::Bytes(rlp::u64_to_minimal_be(30_000_000)), // gasLimit
            Item::Bytes(Vec::new()),            // gasUsed = 0
            Item::Bytes(rlp::u64_to_minimal_be(1_700_000_000)),
            Item::Bytes(Vec::new()),            // extraData
            Item::Bytes(z32),                   // mixHash
            Item::Bytes(vec![0u8; 8]),          // nonce
            Item::Bytes(rlp::u64_to_minimal_be(1_000_000_000)), // baseFee
        ];
        // avoid an unused-mut warning if the vec is later extended
        fields.shrink_to_fit();
        rlp::encode(&Item::List(fields))
    }

    #[test]
    fn eth69_receipt_recomputes_bloom() {
        // wire receipt: [txType=2, status=1, cumGas=21000, [ [addr,[topic],data] ]]
        let addr = vec![0x11u8; 20];
        let topic = vec![0x22u8; 32];
        let log = Item::List(vec![
            Item::Bytes(addr.clone()),
            Item::List(vec![Item::Bytes(topic.clone())]),
            Item::Bytes(vec![0xde, 0xad]),
        ]);
        let wire = rlp::encode(&Item::List(vec![
            Item::List(vec![]), // outer wrapper: one block
        ]));
        let _ = wire;
        let block = Item::List(vec![Item::List(vec![
            Item::Bytes(vec![2]),                       // txType
            Item::Bytes(vec![1]),                       // status
            Item::Bytes(rlp::u64_to_minimal_be(21000)), // cumGas
            Item::List(vec![log]),                      // logs
        ])]);
        // eth/69 keeps the [reqId, [blocks]] wrapper.
        let msg = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(9)),
            Item::List(vec![block]),
        ]));
        let (id, blocks) = decode_receipts69(&msg).unwrap();
        assert_eq!(id, 9);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 1);
        let canonical = &blocks[0][0];
        assert_eq!(canonical[0], 2); // typed envelope preserved
        // The recomputed bloom must have the addr + topic bits set.
        let mut expect = EMPTY_BLOOM;
        accrue(&mut expect, &addr);
        accrue(&mut expect, &topic);
        // Decode the canonical receipt payload and check its bloom field.
        let payload = rlp::decode(&canonical[1..]).unwrap();
        let rf = payload.as_list().unwrap();
        assert_eq!(rf[2].as_bytes().unwrap(), &expect[..]);
    }
}
