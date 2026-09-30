//! eth/66-69 sub-protocol messages (EL-A5), twin of the Java
//! `networking.eth.messages` package (docs/reimplementation/02 §6).
//!
//! Pure encode/decode over bytes — the async handshake + request correlation
//! live in [`super::session`]. Message codes are the ABSOLUTE eth codes (p2p
//! base 0x10); the session maps the p2p Hello/Ping/Pong below 0x10.

use std::borrow::Cow;

use myotis_core::bloom::{accrue, EMPTY_BLOOM};
use myotis_core::header::{self, BlockHeader};
use myotis_core::keccak::keccak256;
use myotis_core::rlp::{self, Item};
use myotis_core::CoreError;

use crate::el::rlpx::frame::MAX_CONTROL_MSG_SIZE;

// Absolute eth message codes (p2p base 0x10).
pub const STATUS: u64 = 0x10;
pub const NEW_BLOCK_HASHES: u64 = 0x11;
/// eth/69 (EIP-7642) BlockRangeUpdate. The spec id is RELATIVE 0x11 — this file
/// uses absolute wire codes (eth base 0x10), so 0x21: the new slot after
/// Receipts (0x20) that grows the eth/69 protocol length 17 → 18 (which is why
/// the snap base moves 0x21 → 0x22, see snap::SnapCodes). Senders MUST still
/// gate on the negotiated version: on eth/68 absolute 0x21 is the SNAP base
/// (GetAccountRange), not a free slot.
pub const BLOCK_RANGE_UPDATE: u64 = 0x21;

/// GOLDEN VECTOR shared with the Java engine: `encode_block_range_update(100,
/// 131, [0x11; 32])`. The Java `BlockRangeUpdateMessageTest` pins the identical
/// hex, so neither engine can change the wire shape without failing a test on
/// the other side.
#[cfg(test)]
pub(crate) const BLOCK_RANGE_UPDATE_GOLDEN_HEX: &str =
    "e4648183a01111111111111111111111111111111111111111111111111111111111111111";
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

/// eth/69 BlockRangeUpdate body `[earliestBlock, latestBlock, latestBlockHash]`.
/// Sent to already-connected peers when our servable range changes.
pub fn encode_block_range_update(earliest: u64, latest: u64, latest_hash: &[u8; 32]) -> Vec<u8> {
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(earliest)),
        Item::Bytes(rlp::u64_to_minimal_be(latest)),
        Item::Bytes(latest_hash.to_vec()),
    ]))
}

/// A decoded eth/69 BlockRangeUpdate: the peer's servable block range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRangeUpdate {
    pub earliest: u64,
    pub latest: u64,
    pub latest_hash: [u8; 32],
}

/// Decode an inbound eth/69 BlockRangeUpdate (absolute 0x21):
/// `[earliestBlock, latestBlock, latestBlockHash]`. Twin of the Java
/// `BlockRangeUpdateMessage.decode`, pinned to the same golden vector as the
/// encoder. An inverted range (`earliest > latest`) is an error too: EIP-7642
/// calls it a protocol violation, and a range that cannot be true must not
/// become a fact about the peer. Callers IGNORE the frame on an error, as the
/// Java `EthHandler` does, rather than disconnect — a peer's malformed
/// notification must never decide that we drop a usable connection. (The Java
/// engine decodes and logs the update but does not yet route requests by it;
/// the Rust pool does — see `peer::KnownHead`.)
pub fn decode_block_range_update(rlp_bytes: &[u8]) -> Result<BlockRangeUpdate, CoreError> {
    check_control_size("BlockRangeUpdate", rlp_bytes)?;
    let top = rlp::decode(rlp_bytes)?;
    let items = top.as_list()?;
    if items.len() < 3 {
        return Err(CoreError(format!("BlockRangeUpdate: expected 3 items, got {}", items.len())));
    }
    let earliest = items[0].as_u64()?;
    let latest = items[1].as_u64()?;
    if earliest > latest {
        return Err(CoreError(format!("BlockRangeUpdate: earliest {earliest} above latest {latest}")));
    }
    Ok(BlockRangeUpdate { earliest, latest, latest_hash: fixed32(&items[2])? })
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
    check_control_size("Status", rlp_bytes)?;
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
    check_control_size("GetBlockHeaders", payload)?;
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

/// Decode a BlockHeaders response `[reqId, [header, …]]` to a request for
/// `requested` headers. Returns `(request_id, headers)`, at most one more than
/// `requested` (see [`kept`]). Each header is read in place from the checked
/// response, never built into a tree (#454).
pub fn decode_block_headers(
    rlp_bytes: &[u8],
    requested: usize,
) -> Result<(u64, Vec<VerifiedHeader>), CoreError> {
    let (request_id, headers) = request_and_payload(rlp_bytes)?;
    // Each element's RAW sub-slice is the canonical header encoding → hash it.
    let mut out = Vec::new();
    for (i, raw) in headers.as_list()?.enumerate() {
        let header = BlockHeader::decode_view(raw)?;
        if i < kept(requested) {
            out.push(VerifiedHeader {
                hash: header::hash(raw.raw()),
                raw_rlp: raw.raw().to_vec(),
                header,
            });
        }
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
    pub transactions: RawList,
    pub uncle_count: usize,
    pub withdrawal_count: usize,
}

/// Decode a BlockBodies response `[reqId, [body, …]]` to a request for
/// `requested` bodies, keeping at most one more (see [`kept`]). The
/// transactions go into a [`RawList`] as they arrived, so a body of millions
/// of one-byte "transactions" costs about its own size, where a buffer per
/// transaction cost some fifty times that (#454).
pub fn decode_block_bodies(rlp_bytes: &[u8], requested: usize) -> Result<(u64, Vec<BlockBody>), CoreError> {
    let (request_id, bodies_view) = request_and_payload(rlp_bytes)?;
    let mut bodies = Vec::new();
    for (i, body) in bodies_view.as_list()?.enumerate() {
        // body = [transactions, uncles, withdrawals?] — transactions AND uncles
        // are mandatory (withdrawals only post-Shanghai).
        let mut fields = body.as_list()?;
        let (Some(txs), Some(uncles)) = (fields.next(), fields.next()) else {
            return Err(CoreError(format!(
                "BlockBody: expected >= 2 fields, got {}",
                body.as_list()?.count()
            )));
        };
        let tx_items = txs.as_list()?;
        let uncle_count = uncles.as_list()?.count();
        let withdrawal_count = fields.next().map_or(Ok(0), |w| w.as_list().map(Iterator::count))?;
        if i >= kept(requested) {
            continue;
        }
        // Legacy tx = RLP list (kept as-is, it's canonical); typed tx =
        // byte-string whose payload IS the consensus tx bytes. Both are kept
        // as they arrived, and read back as those bytes.
        let mut transactions = RawList::with_capacity(txs.raw().len());
        for tx in tx_items {
            transactions.push_item(tx);
        }
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

/// Per-message cap on gossip hashes worth reading (the Java
/// `MAX_GOSSIP_HASHES_PER_MSG` twin): these feed only the sent-tx watch's
/// "seen" signal, so an oversized announcement is truncated, never an
/// asymmetric-cost decode.
pub const MAX_GOSSIP_HASHES_PER_MSG: usize = 256;

/// Decode a `NewPooledTransactionHashes` announcement into its 32-byte tx
/// hashes (capped at [`MAX_GOSSIP_HASHES_PER_MSG`]), tolerating BOTH wire
/// shapes: the eth/68 triple `[types: bytes, sizes: [..], hashes: [h, ..]]`
/// and the eth/66-67 flat list `[h, ..]`. Tolerant on purpose — this feeds
/// only the sent-tx watch's "seen in gossip" signal (never a trust surface),
/// so a malformed or unexpected announcement yields the hashes it can read,
/// or none.
///
/// The frame is validated and walked, never built (#454): the cap limits what
/// is read, not what a full decode would have allocated.
pub fn decode_new_pooled_tx_hashes(payload: &[u8]) -> Vec<[u8; 32]> {
    // The verdict a full decode of the frame would reach.
    if rlp::validate(payload).is_err() {
        return Vec::new();
    }
    // Up to the cap: a prefix holding exactly 3 elements is the whole list.
    let Ok(items) = rlp::raw_list_prefix(payload, MAX_GOSSIP_HASHES_PER_MSG) else {
        return Vec::new();
    };
    // eth/68: exactly [types, sizes, hashes] where the LAST item is the hash
    // list. A flat eth/66 list of 3 hashes would ALSO be length 3 — the two
    // are distinguished by the last item's kind (list vs 32-byte string).
    if items.len() == 3 && rlp::is_list_prefix(items[2]) {
        return rlp::raw_list_prefix(items[2], MAX_GOSSIP_HASHES_PER_MSG)
            .map(collect_hashes)
            .unwrap_or_default();
    }
    collect_hashes(items)
}

/// Hash the elements of an inbound `Transactions` (0x12) full-body gossip
/// frame (capped at [`MAX_GOSSIP_HASHES_PER_MSG`]): a tx's hash is keccak of
/// its raw wire element — the RLP list bytes for a legacy tx, the byte-string
/// CONTENT for a typed one (the Java `TransactionsMessage.hashes` twin).
/// Same tolerance rationale as the announcement decoder. Every element is
/// validated, but only the ones hashed are kept (#454).
pub fn transactions_gossip_hashes(payload: &[u8]) -> Vec<[u8; 32]> {
    let Ok(raws) = rlp::raw_list_prefix(payload, MAX_GOSSIP_HASHES_PER_MSG) else {
        return Vec::new();
    };
    raws.iter()
        .filter_map(|raw| {
            if rlp::is_list_prefix(raw) {
                Some(keccak256(raw)) // legacy: the list bytes ARE the tx
            } else {
                let typed = rlp::decode(raw).ok()?.as_bytes().ok()?.to_vec();
                Some(keccak256(&typed)) // typed: hash the byte-string content
            }
        })
        .collect()
}

/// The 32-byte strings among already-validated raw RLP elements; anything
/// else is skipped.
fn collect_hashes(items: Vec<&[u8]>) -> Vec<[u8; 32]> {
    items
        .into_iter()
        .filter(|item| !rlp::is_list_prefix(item))
        .filter_map(|item| <[u8; 32]>::try_from(rlp::strip_bytes_header(item).ok()?).ok())
        .collect()
}

/// One block's receipts from a Receipts response, as the peer served them:
/// canonical receipts-trie values (eth/66-68), or eth/69's bloomless form
/// (EIP-7642). Recomputing an eth/69 bloom adds 256 bytes to every receipt,
/// however small, so it waits for [`BlockReceipts::canonical`]. That takes the
/// block's transaction count from its verified body, and refuses any other
/// count before recomputing anything: a peer cannot make us expand more
/// receipts than the block holds (#454).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReceipts {
    /// eth/66-68: each element is already the receipts-trie value.
    Canonical(RawList),
    /// eth/69: each element is a checked `[txType, statusOrState, cumGas, logs]`.
    Eth69(RawList),
}

impl BlockReceipts {
    /// How many receipts the peer served for the block.
    pub fn len(&self) -> usize {
        match self {
            BlockReceipts::Canonical(list) | BlockReceipts::Eth69(list) => list.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The receipts-trie values, for a block of `verified_tx_count`
    /// transactions. Any other number of receipts is an error, raised before an
    /// eth/69 bloom is recomputed. The count must come from the block's
    /// transactionsRoot-verified body: that is what bounds the expansion, so
    /// every caller verifies the body first.
    pub fn canonical(&self, verified_tx_count: usize) -> Result<Cow<'_, RawList>, CoreError> {
        if self.len() != verified_tx_count {
            return Err(CoreError(format!(
                "{} receipts for {verified_tx_count} transactions",
                self.len()
            )));
        }
        match self {
            BlockReceipts::Canonical(list) => Ok(Cow::Borrowed(list)),
            BlockReceipts::Eth69(wire) => {
                // The stored receipts were checked on decode: walk them as views.
                let mut out = RawList::new();
                for receipt in wire.0.iter() {
                    out.push(&canonicalize_eth69_receipt(receipt)?);
                }
                Ok(Cow::Owned(out))
            }
        }
    }
}

/// Decode a Receipts response (eth/66-68) to a request for `requested`
/// blocks into each block's receipts-trie values, keeping at most one block
/// more (see [`kept`]). Returns `(request_id, per_block_receipts)`.
pub fn decode_receipts(rlp_bytes: &[u8], requested: usize) -> Result<(u64, Vec<BlockReceipts>), CoreError> {
    let (request_id, blocks_view) = request_and_payload(rlp_bytes)?;
    let mut blocks = Vec::new();
    for (i, block) in blocks_view.as_list()?.enumerate() {
        let receipts_view = block.as_list()?;
        if i >= kept(requested) {
            continue;
        }
        // Legacy = RLP list (canonical as-is); typed = byte-string whose
        // payload IS `type ‖ rlp(...)`, the trie value.
        let mut receipts = RawList::with_capacity(block.raw().len());
        for receipt in receipts_view {
            receipts.push_item(receipt);
        }
        blocks.push(BlockReceipts::Canonical(receipts));
    }
    Ok((request_id, blocks))
}

/// Decode an eth/69 (EIP-7642) Receipts response to a request for `requested`
/// blocks, keeping at most one block more (see [`kept`]).
/// eth/69 strips the logsBloom and flattens the typed envelope: each receipt
/// arrives as `[txType, statusOrState, cumGas, logs]`. The bloom is a pure
/// function of the logs, so [`BlockReceipts::canonical`] recomputes it and
/// re-canonicalizes (`type ‖ rlp([status, cumGas, bloom, logs])`), after which
/// the receipts-trie check works exactly as for eth/66-68
/// (docs/reimplementation/02 §6.6). Each receipt is checked here, so a
/// malformed one fails the response as before; only the recomputation waits.
pub fn decode_receipts69(rlp_bytes: &[u8], requested: usize) -> Result<(u64, Vec<BlockReceipts>), CoreError> {
    let (request_id, blocks_view) = request_and_payload(rlp_bytes)?;
    let mut blocks = Vec::new();
    for (i, block) in blocks_view.as_list()?.enumerate() {
        for wire in block.as_list()? {
            eth69_receipt_fields(wire)?;
        }
        if i < kept(requested) {
            let mut receipts = RawList::with_capacity(block.raw().len());
            for wire in block.as_list()? {
                receipts.push_item(wire);
            }
            blocks.push(BlockReceipts::Eth69(receipts));
        }
    }
    Ok((request_id, blocks))
}

/// The fields of an eth/69 wire receipt `[txType, statusOrState, cumGas, logs]`
/// (extra trailing fields are ignored), with everything the canonical form
/// relies on checked: the tx type, byte-string status and gas, and every log a
/// list with a 20-byte address and 32-byte topics.
fn eth69_receipt_fields(wire: rlp::View<'_>) -> Result<(u8, [rlp::View<'_>; 3]), CoreError> {
    let mut fields = wire.as_list()?;
    let (Some(ty), Some(status_or_state), Some(cum_gas), Some(logs)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(CoreError("eth/69 receipt: too few fields".into()));
    };
    // The receipt tx-type is a single byte in `0x00..=0x7f` (0 = legacy). Keep
    // the Java last-byte extraction for the valid single-byte case, but reject
    // multi-byte / out-of-range encodings rather than silently truncating.
    let ty = match ty.as_bytes()? {
        [] => 0u8,
        &[b] if b <= 0x7f => b,
        _ => return Err(CoreError("eth/69 receipt: invalid tx type".into())),
    };
    status_or_state.as_bytes()?;
    cum_gas.as_bytes()?;
    for log in logs.as_list()? {
        let mut lf = log.as_list()?;
        let (Some(address), Some(topics), Some(_data)) = (lf.next(), lf.next(), lf.next()) else {
            return Err(CoreError("eth/69 receipt: malformed log".into()));
        };
        // Consensus rules: a log address is exactly 20 bytes, each topic 32.
        address.as_fixed_bytes(20)?;
        for t in topics.as_list()? {
            t.as_fixed_bytes(32)?;
        }
    }
    Ok((ty, [status_or_state, cum_gas, logs]))
}

/// One checked eth/69 wire receipt → its canonical consensus encoding with the
/// recomputed bloom. The status, gas and logs are copied as they arrived: the
/// view checked them canonical, so the bytes are what re-encoding them gives.
fn canonicalize_eth69_receipt(wire: rlp::View<'_>) -> Result<Vec<u8>, CoreError> {
    let (ty, [status_or_state, cum_gas, logs]) = eth69_receipt_fields(wire)?;
    // Recompute the M3:2048 bloom over every log's address + topics.
    let mut bloom = EMPTY_BLOOM;
    for log in logs.as_list()? {
        let mut lf = log.as_list()?;
        if let (Some(address), Some(topics)) = (lf.next(), lf.next()) {
            accrue(&mut bloom, address.as_bytes()?);
            for t in topics.as_list()? {
                accrue(&mut bloom, t.as_bytes()?);
            }
        }
    }
    let mut payload = Vec::with_capacity(
        status_or_state.raw().len() + cum_gas.raw().len() + 3 + bloom.len() + logs.raw().len(),
    );
    payload.extend_from_slice(status_or_state.raw());
    payload.extend_from_slice(cum_gas.raw());
    payload.extend_from_slice(&rlp::encode_bytes(&bloom));
    payload.extend_from_slice(logs.raw());
    let receipt = rlp::encode_list_payload(&payload);
    if ty == 0 {
        Ok(receipt)
    } else {
        let mut out = Vec::with_capacity(1 + receipt.len());
        out.push(ty);
        out.extend_from_slice(&receipt);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Transaction and receipt lists (#454).
// ---------------------------------------------------------------------------

/// Transactions or receipts in the eth wire's form, in one [`rlp::ListBuf`]:
/// a legacy one (an RLP list) as itself, a typed one (`type ‖ rlp(…)`) as the
/// byte string around it. A peer's list is kept exactly as it arrived, so a
/// body of millions of one-byte transactions costs what it weighed on the
/// wire, with no allocation per element. A `Vec<Vec<u8>>` spent about 50 bytes
/// on each. Reading an element gives back the list's encoding or the string's
/// content, the bytes the trie and the hashes are built over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawList(rlp::ListBuf);

impl RawList {
    pub fn new() -> RawList {
        RawList::default()
    }

    fn with_capacity(bytes: usize) -> RawList {
        RawList(rlp::ListBuf::with_capacity(bytes))
    }

    /// Append an element of a checked peer message as it arrived.
    fn push_item(&mut self, item: rlp::View<'_>) {
        self.0.push_view(item);
    }

    /// Append `bytes`, which [`RawList::get`] gives back unchanged: kept as
    /// itself when it is an RLP list, as a byte string around it otherwise.
    pub fn push(&mut self, bytes: &[u8]) {
        match rlp::View::new(bytes) {
            Ok(list) if list.is_list() => self.0.push_view(list),
            _ => self.0.push_bytes(bytes),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Element `i`, found by walking the list up to it.
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        self.iter().nth(i)
    }

    pub fn iter(&self) -> RawListIter<'_> {
        RawListIter { items: self.0.iter(), left: self.0.len() }
    }
}

impl<'a> IntoIterator for &'a RawList {
    type Item = &'a [u8];
    type IntoIter = RawListIter<'a>;

    fn into_iter(self) -> RawListIter<'a> {
        self.iter()
    }
}

/// The elements of a [`RawList`], in order.
#[derive(Debug, Clone)]
pub struct RawListIter<'a> {
    items: rlp::ViewIter<'a>,
    left: usize,
}

impl<'a> Iterator for RawListIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let item = self.items.next()?;
        self.left = self.left.saturating_sub(1);
        Some(if item.is_list() { item.raw() } else { item.as_bytes().unwrap_or_default() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for RawListIter<'_> {}

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

/// The request id heading an eth/66-69 or snap/1 request or response
/// (`[reqId, …]`), or `None` when the payload is not one. The read loops
/// call this on every frame a peer sends, so it walks the list instead of
/// building it (#454). The whole list is still validated, as before.
pub fn leading_request_id(payload: &[u8]) -> Option<u64> {
    request_id_at(rlp::raw_list_prefix(payload, 1).ok()?.first()?).ok()
}

/// The request id in the raw head element of a `[reqId, …]` message. A
/// canonical u64 encodes in at most 9 bytes; a longer head (a list, or a
/// longer string) cannot be one, so it is not worth building to find out.
fn request_id_at(head: &[u8]) -> Result<u64, CoreError> {
    if head.len() > 9 {
        return Err(CoreError("eth message: request id is not a u64".into()));
    }
    rlp::decode(head)?.as_u64()
}

/// Refuse a control message too large to be a real one before building its
/// tree ([`MAX_CONTROL_MSG_SIZE`], #454).
fn check_control_size(what: &str, payload: &[u8]) -> Result<(), CoreError> {
    if payload.len() > MAX_CONTROL_MSG_SIZE {
        return Err(CoreError(format!(
            "{what}: {} bytes is over the {MAX_CONTROL_MSG_SIZE}-byte control-message cap",
            payload.len()
        )));
    }
    Ok(())
}

/// Split an eth/66-69 `[reqId, payload]` response into the request id and a
/// view of the payload to read in place (#454). The elements of the message
/// are checked as they always were (each a whole item, anything after the
/// payload checked but not read), so the nesting a response may use is
/// unchanged.
fn request_and_payload(rlp_bytes: &[u8]) -> Result<(u64, rlp::View<'_>), CoreError> {
    let items = rlp::raw_list_prefix(rlp_bytes, 2)?;
    let (Some(id), Some(payload)) = (items.first(), items.get(1)) else {
        return Err(CoreError("eth message: missing [reqId, payload]".into()));
    };
    // `View::new` walks the payload a second time; `raw_list_prefix` has just
    // checked it the same way, so this cannot fail. Both halves stay: the first
    // keeps the nesting budget a response always had (a view over the whole
    // message would count one more level), and checking is the only way to
    // make a view.
    Ok((request_id_at(id)?, rlp::View::new(payload)?))
}

/// How many elements of a response to a request for `requested` to keep: one
/// more than asked for, so a caller still sees a peer that over-serves. Any
/// further element is checked exactly as a kept one would be, so the verdict
/// on the response doesn't change, but it is not kept (#454). The eth and
/// snap decoders share it.
pub(crate) fn kept(requested: usize) -> usize {
    requested.saturating_add(1)
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
    /// Cross-engine parity: byte-identical to the Java
    /// `BlockRangeUpdateMessageTest.matchesTheCrossEngineGoldenVector`.
    /// earliest=100, latest=131 (a 32-block window), hash=0x11..11.
    fn block_range_update_matches_the_java_golden_vector() {
        let encoded = encode_block_range_update(100, 131, &[0x11u8; 32]);
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, BLOCK_RANGE_UPDATE_GOLDEN_HEX);
    }

    #[test]
    fn block_range_update_round_trips() {
        let h = [0xab_u8; 32];
        let enc = encode_block_range_update(20_999_968, 21_000_000, &h);
        let items = rlp::raw_list_items(&enc).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(rlp::decode(items[0]).unwrap().as_u64().unwrap(), 20_999_968);
        assert_eq!(rlp::decode(items[1]).unwrap().as_u64().unwrap(), 21_000_000);
        assert_eq!(rlp::decode(items[2]).unwrap().as_bytes().unwrap(), &h[..]);
    }

    #[test]
    /// The decoder is pinned to the SAME cross-engine golden vector as the
    /// encoder, so the Java `BlockRangeUpdateMessageTest` now covers both
    /// directions of the Rust codec.
    fn block_range_update_decodes_the_java_golden_vector() {
        let bytes: Vec<u8> = (0..BLOCK_RANGE_UPDATE_GOLDEN_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&BLOCK_RANGE_UPDATE_GOLDEN_HEX[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(
            decode_block_range_update(&bytes).unwrap(),
            BlockRangeUpdate { earliest: 100, latest: 131, latest_hash: [0x11; 32] }
        );
        // ...and the encoder's own output, so the pair cannot drift apart.
        let enc = encode_block_range_update(20_999_968, 21_000_000, &[0xab; 32]);
        assert_eq!(
            decode_block_range_update(&enc).unwrap(),
            BlockRangeUpdate { earliest: 20_999_968, latest: 21_000_000, latest_hash: [0xab; 32] }
        );
    }

    #[test]
    fn a_malformed_block_range_update_is_an_error_not_a_panic() {
        assert!(decode_block_range_update(b"junk").is_err());
        let short = rlp::encode(&Item::List(vec![Item::Bytes(vec![1]), Item::Bytes(vec![2])]));
        assert!(decode_block_range_update(&short).is_err());
        let bad_hash = rlp::encode(&Item::List(vec![
            Item::Bytes(vec![1]),
            Item::Bytes(vec![2]),
            Item::Bytes(vec![0xab; 31]),
        ]));
        assert!(decode_block_range_update(&bad_hash).is_err());
    }

    #[test]
    fn an_inverted_block_range_is_rejected() {
        // EIP-7642 calls earliest > latest a violation; a range that cannot be
        // true must never become a fact about the peer.
        let enc = encode_block_range_update(131, 100, &[0x11; 32]);
        assert!(decode_block_range_update(&enc).is_err());
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
    fn transactions_gossip_hashes_match_tx_keccak() {
        // A legacy tx element is the raw RLP list; a typed element's CONTENT is
        // the tx — either way the extracted hash must be keccak of the raw tx
        // (what our own broadcast watches by).
        let legacy = rlp::encode(&Item::List(vec![Item::Bytes(vec![1]), Item::Bytes(vec![2])]));
        let typed: Vec<u8> = {
            let mut t = vec![0x02];
            t.extend_from_slice(&rlp::encode(&Item::List(vec![Item::Bytes(vec![9])])));
            t
        };
        let frame = rlp::encode(&Item::List(vec![
            rlp::decode(&legacy).unwrap(),
            Item::Bytes(typed.clone()),
        ]));
        assert_eq!(
            transactions_gossip_hashes(&frame),
            vec![keccak256(&legacy), keccak256(&typed)]
        );
        // Tolerant on garbage.
        assert!(transactions_gossip_hashes(&[0xff]).is_empty());
    }

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
    fn leading_request_id_reads_the_head_and_validates_the_tail() {
        let msg = |head: Item, tail: Vec<u8>| {
            let mut payload = rlp::encode(&head);
            payload.extend_from_slice(&tail);
            rlp::encode_list_payload(&payload)
        };
        let id = |n: u64| Item::Bytes(rlp::u64_to_minimal_be(n));
        assert_eq!(leading_request_id(&msg(id(4242), vec![0xc0])), Some(4242));
        assert_eq!(leading_request_id(&msg(id(0), vec![0xc0])), Some(0));
        assert_eq!(leading_request_id(&msg(id(u64::MAX), vec![])), Some(u64::MAX));
        // A bare byte string is not a `[reqId, …]` list.
        assert_eq!(leading_request_id(&[0x80]), None);
        // A head that cannot be a u64: a list, or a nine-byte string.
        assert_eq!(leading_request_id(&msg(Item::List(vec![id(1)]), vec![])), None);
        assert_eq!(leading_request_id(&msg(Item::Bytes(vec![1; 9]), vec![])), None);
        // A malformed tail still voids the id, as when the whole list was decoded.
        assert_eq!(leading_request_id(&msg(id(7), vec![0x81, 0x05])), None);
        // A huge tail is walked, not built, to the same answer (#454).
        let mut tail = vec![0x01; 1 << 20];
        tail.splice(0..0, [0xfa, 0x10, 0x00, 0x00]); // list header for 1 MiB
        assert_eq!(leading_request_id(&msg(id(9), tail)), Some(9));
    }

    #[test]
    fn control_decoders_refuse_a_message_over_the_cap() {
        // Each message plus trailing one-byte fields, which the decoders
        // tolerate at any real size.
        let padded = |message: Vec<u8>, extra: usize| {
            let mut fields = rlp::raw_list_items(&message).unwrap().concat();
            fields.resize(fields.len() + extra, 0x01);
            rlp::encode_list_payload(&fields)
        };
        let over = MAX_CONTROL_MSG_SIZE;
        let refused = |r: Result<(), CoreError>| {
            let e = r.unwrap_err().0;
            assert!(e.contains("control-message cap"), "{e}");
        };

        let status = encode_status69(69, 1, &[0x11; 32], &[0x22; 32], &[0xaa; 4], 0, 0, 100);
        assert!(decode_status(&padded(status.clone(), 1_000), 69).is_ok());
        refused(decode_status(&padded(status, over), 69).map(drop));

        let range = encode_block_range_update(100, 131, &[0x11; 32]);
        assert!(decode_block_range_update(&padded(range.clone(), 1_000)).is_ok());
        refused(decode_block_range_update(&padded(range, over)).map(drop));

        let get = encode_get_block_headers_by_number(42, 21_000_000, 16, 0, false);
        assert!(decode_get_block_headers(&padded(get.clone(), 1_000)).is_ok());
        refused(decode_get_block_headers(&padded(get, over)).map(drop));
    }

    #[test]
    fn gossip_decoders_read_a_prefix_of_a_huge_frame() {
        // 300 hashes then a million one-byte elements: capped at the first
        // MAX_GOSSIP_HASHES_PER_MSG, with the rest walked but not built (#454).
        let mut elements = Vec::new();
        for i in 0..300u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            elements.extend_from_slice(&rlp::encode_bytes(&h));
        }
        elements.resize(elements.len() + (1 << 20), 0x01);
        let frame = rlp::encode_list_payload(&elements);

        let hashes = decode_new_pooled_tx_hashes(&frame);
        assert_eq!(hashes.len(), MAX_GOSSIP_HASHES_PER_MSG);
        assert_eq!(hashes[255][..4], 255u32.to_be_bytes());
        assert_eq!(transactions_gossip_hashes(&frame).len(), MAX_GOSSIP_HASHES_PER_MSG);

        // Still all-or-nothing on a malformed element past the prefix.
        let mut bad = elements.clone();
        let last = bad.len() - 2;
        bad[last] = 0x81; // `0x81 0x01`: non-canonical single byte
        let bad = rlp::encode_list_payload(&bad);
        assert!(decode_new_pooled_tx_hashes(&bad).is_empty());
        assert!(transactions_gossip_hashes(&bad).is_empty());
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
    fn block_headers_keep_one_past_the_request_and_check_the_rest() {
        let h = |n| raw(&minimal_header(n));
        let msg = |headers: Vec<Item>| {
            rlp::encode(&Item::List(vec![Item::Bytes(rlp::u64_to_minimal_be(7)), Item::List(headers)]))
        };
        let (_, headers) = decode_block_headers(&msg(vec![h(1), h(2), h(3), h(4)]), 2).unwrap();
        assert_eq!(headers.iter().map(|v| v.header.number).collect::<Vec<_>>(), vec![1, 2, 3]);
        // A dropped header is still decoded, so a bad one fails the response.
        assert!(decode_block_headers(&msg(vec![h(1), h(2), h(3), Item::List(vec![])]), 1).is_err());
    }

    #[test]
    fn a_response_may_nest_as_deep_as_before() {
        // One header with a trailing field of `depth` nested lists. The header
        // sits two lists below the message; the deepest list then reaches
        // depth `2 + depth - 1`, and MAX_DEPTH (32) allows 31 levels.
        let with_trailing = |depth: usize| {
            let mut field = Item::List(vec![]);
            for _ in 1..depth {
                field = Item::List(vec![field]);
            }
            let mut fields = rlp::decode(&minimal_header(9)).unwrap().as_list().unwrap().to_vec();
            // withdrawalsRoot, blobGasUsed, excessBlobGas, parentBeaconBlockRoot,
            // requestsHash, then the nested field where blockAccessListHash
            // would be (tolerated when it isn't a hash).
            fields.extend([
                Item::Bytes(vec![0; 32]),
                Item::Bytes(vec![]),
                Item::Bytes(vec![]),
                Item::Bytes(vec![0; 32]),
                Item::Bytes(vec![0; 32]),
                field,
            ]);
            rlp::encode(&Item::List(vec![
                Item::Bytes(rlp::u64_to_minimal_be(7)),
                Item::List(vec![Item::List(fields)]),
            ]))
        };
        assert_eq!(decode_block_headers(&with_trailing(31), 1).unwrap().1[0].header.number, 9);
        assert!(decode_block_headers(&with_trailing(32), 1).is_err());
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
        let (req_id, headers) = decode_block_headers(&msg, 2).unwrap();
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
    fn raw_list_holds_its_elements_in_order() {
        let legacy = rlp::encode(&Item::List(vec![Item::Bytes(vec![1])]));
        let not_rlp = [0xc5, 0x01];
        let items: [&[u8]; 6] = [b"ab", b"", &[0x02, 0xc0], &legacy, &not_rlp, &[0x81, 0x7f]];
        let mut list = RawList::new();
        assert!(list.is_empty());
        for item in items {
            list.push(item);
        }
        // Whatever went in comes back unchanged, list or not.
        assert_eq!(list.len(), items.len());
        assert_eq!(list.iter().collect::<Vec<_>>(), items.to_vec());
        assert_eq!(list.get(3), Some(&legacy[..]));
        assert_eq!(list.get(6), None);
        assert_eq!(list.iter().len(), 6);
    }

    /// `[reqId, [element, …]]`, with each element given as its encoding.
    fn response(id: u64, elements: &[Vec<u8>]) -> Vec<u8> {
        let mut out = rlp::encode(&Item::Bytes(rlp::u64_to_minimal_be(id)));
        out.extend_from_slice(&rlp::encode_list_payload(&elements.concat()));
        rlp::encode_list_payload(&out)
    }

    #[test]
    fn block_bodies_keep_the_requested_bodies_and_each_tx_as_served() {
        let legacy = rlp::encode(&Item::List(vec![Item::Bytes(vec![1]), Item::Bytes(vec![2])]));
        let typed = [&[0x02][..], &rlp::encode(&Item::List(vec![Item::Bytes(vec![9])]))].concat();
        let body = |uncles: usize, withdrawals: Option<usize>| {
            let mut fields = vec![
                Item::List(vec![raw(&legacy), Item::Bytes(typed.clone())]),
                Item::List((0..uncles).map(|_| Item::List(vec![])).collect()),
            ];
            if let Some(w) = withdrawals {
                fields.push(Item::List((0..w).map(|_| Item::List(vec![])).collect()));
            }
            rlp::encode(&Item::List(fields))
        };
        let msg = response(4, &[body(1, Some(3)), body(0, None), body(2, None)]);

        let (id, bodies) = decode_block_bodies(&msg, 1).unwrap();
        assert_eq!(id, 4);
        // One body asked for: it and one more are kept (so the over-serving
        // shows), the third is checked, then dropped.
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0].transactions.iter().collect::<Vec<_>>(), vec![&legacy[..], &typed[..]]);
        assert_eq!((bodies[0].uncle_count, bodies[0].withdrawal_count), (1, 3));
        assert_eq!((bodies[1].uncle_count, bodies[1].withdrawal_count), (0, 0));
        assert_eq!(decode_block_bodies(&msg, 10).unwrap().1.len(), 3);

        // Transactions and uncles are mandatory, in a dropped body too.
        let short = rlp::encode(&Item::List(vec![Item::List(vec![])]));
        let err = decode_block_bodies(&response(4, std::slice::from_ref(&short)), 1).unwrap_err();
        assert_eq!(err.0, "BlockBody: expected >= 2 fields, got 1");
        let surplus = response(4, &[body(0, None), body(0, None), short, vec![0x80]]);
        assert!(decode_block_bodies(&surplus, 1).is_err());
    }

    #[test]
    fn receipts_keep_the_requested_blocks_and_check_the_count_before_use() {
        let receipt = rlp::encode(&Item::List(vec![
            Item::Bytes(vec![1]),
            Item::Bytes(rlp::u64_to_minimal_be(21_000)),
            Item::Bytes(vec![0; 256]),
            Item::List(vec![]),
        ]));
        let block = |n: usize| rlp::encode_list_payload(&vec![receipt.clone(); n].concat());
        let msg = response(6, &[block(2), block(1), block(3)]);

        // One block asked for: it and one more are kept.
        let (id, blocks) = decode_receipts(&msg, 1).unwrap();
        assert_eq!((id, blocks.len(), blocks[0].len(), blocks[1].len()), (6, 2, 2, 1));
        // A dropped block is still checked: a byte string where a list must be.
        assert!(decode_receipts(&response(6, &[block(1), block(1), vec![0x80]]), 1).is_err());
        let canonical = blocks[0].canonical(2).unwrap();
        assert!(matches!(canonical, Cow::Borrowed(_)), "eth/66-68 receipts are used as served");
        assert_eq!(canonical.iter().collect::<Vec<_>>(), vec![&receipt[..], &receipt[..]]);
        // Any other count than the verified body's is refused.
        assert_eq!(blocks[0].canonical(3).unwrap_err().0, "2 receipts for 3 transactions");
    }

    #[test]
    fn eth69_receipts_are_checked_on_decode_and_expanded_only_for_the_right_count() {
        let wire = |fields: Vec<Item>| rlp::encode(&Item::List(fields));
        let good = wire(vec![
            Item::Bytes(vec![]),
            Item::Bytes(vec![1]),
            Item::Bytes(rlp::u64_to_minimal_be(21_000)),
            Item::List(vec![]),
        ]);
        let msg = response(8, &[rlp::encode_list_payload(&[good.clone(), good.clone()].concat())]);
        let (_, blocks) = decode_receipts69(&msg, 1).unwrap();
        assert!(matches!(blocks[0], BlockReceipts::Eth69(_)));
        // Refused before any bloom is recomputed...
        assert_eq!(blocks[0].canonical(1).unwrap_err().0, "2 receipts for 1 transactions");
        // ...and expanded for the right count: a legacy receipt with a bloom.
        let canonical = blocks[0].canonical(2).unwrap();
        let fields = rlp::decode(canonical.get(0).unwrap()).unwrap();
        assert_eq!(fields.as_list().unwrap()[2].as_bytes().unwrap(), &EMPTY_BLOOM[..]);

        // A malformed receipt still fails the response on decode, as before.
        for (bad, error) in [
            (wire(vec![Item::Bytes(vec![])]), "eth/69 receipt: too few fields"),
            (
                wire(vec![
                    Item::Bytes(vec![0x80]),
                    Item::Bytes(vec![1]),
                    Item::Bytes(vec![]),
                    Item::List(vec![]),
                ]),
                "eth/69 receipt: invalid tx type",
            ),
            (
                wire(vec![
                    Item::Bytes(vec![]),
                    Item::Bytes(vec![1]),
                    Item::Bytes(vec![]),
                    Item::List(vec![Item::List(vec![Item::Bytes(vec![0; 20])])]),
                ]),
                "eth/69 receipt: malformed log",
            ),
        ] {
            let msg = response(8, &[rlp::encode_list_payload(&bad)]);
            assert_eq!(decode_receipts69(&msg, 1).unwrap_err().0, error);
        }
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
        let (id, blocks) = decode_receipts69(&msg, 1).unwrap();
        assert_eq!(id, 9);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 1);
        let canonical = blocks[0].canonical(1).unwrap();
        let canonical = canonical.get(0).unwrap();
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
