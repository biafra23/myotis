//! Transaction field decoders over raw (consensus-encoded) transactions.
//!
//! Two consumers, two shapes:
//! - [`effective_tip`] — the minimal fee-field read for the `eth_gasPrice` /
//!   `eth_maxPriorityFeePerGas` tip suggestion.
//! - [`decode_summary`] — the receipt-facing decode (type, nonce, `to`, fee
//!   fields, recovered sender) that `eth_getTransactionReceipt` needs for its
//!   `from` / `to` / `contractAddress` / `effectiveGasPrice` fields. Twin of the
//!   Java `EthTxDecoder` + `VerifiedRpcBackend.effectiveGasPrice` /
//!   `contractAddressFor`.
//!
//! Pure decoders: the caller has already verified the tx bytes against a block's
//! `transactionsRoot` (sender recovery is deterministic ECDSA over the signing
//! hash — a malformed signature yields `from = None`, not a trust hole).

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::recover_public_key;
use myotis_core::rlp::{self, Item};

/// The effective priority fee (tip) a raw tx pays at `base_fee`, or `None` when
/// the tx can't be decoded (skipped — one bad tx never kills the suggestion).
///
/// - legacy / EIP-2930: `gasPrice - base_fee`
/// - EIP-1559 / 4844 / 7702: `min(maxPriorityFeePerGas, maxFeePerGas - base_fee)`
///
/// Saturating at 0. Values are per-gas wei — `u128` covers any real fee
/// (≤ ~3.4e38 wei); a fee scalar wider than 16 bytes is treated as undecodable.
pub fn effective_tip(raw: &[u8], base_fee: u128) -> Option<u128> {
    let first = *raw.first()?;
    // EIP-2718 typed txs are `type_byte(0x01..=0x7f) ‖ rlp_payload`; a legacy tx is
    // a bare RLP list (first byte >= 0xc0).
    let (ty, payload): (u8, &[u8]) = if first >= 0xc0 {
        (0, raw)
    } else if (0x01..=0x04).contains(&first) {
        (first, &raw[1..])
    } else {
        return None; // unknown / reserved tx type
    };
    let item = rlp::decode(payload).ok()?;
    let list = item.as_list().ok()?;
    match ty {
        // legacy [nonce, gasPrice, gasLimit, …] — gasPrice at index 1.
        0 => {
            let gas_price = scalar_u128(list.get(1)?)?;
            Some(gas_price.saturating_sub(base_fee))
        }
        // 2930 [chainId, nonce, gasPrice, …] — gasPrice at index 2.
        0x01 => {
            let gas_price = scalar_u128(list.get(2)?)?;
            Some(gas_price.saturating_sub(base_fee))
        }
        // 1559 / 4844 / 7702 [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, …].
        _ => {
            let max_priority_fee = scalar_u128(list.get(2)?)?;
            let max_fee = scalar_u128(list.get(3)?)?;
            let room = max_fee.saturating_sub(base_fee);
            Some(max_priority_fee.min(room))
        }
    }
}

/// A minimal big-endian RLP scalar as `u128`, or `None` if it isn't bytes or is
/// wider than 16 bytes (beyond any real per-gas fee).
fn scalar_u128(item: &Item) -> Option<u128> {
    let bytes = item.as_bytes().ok()?;
    if bytes.len() > 16 {
        return None;
    }
    Some(bytes.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128))
}

// ---------------------------------------------------------------------------
// Receipt-facing tx summary (EthTxDecoder twin, the fields buildReceiptJson
// consumes). Legacy (incl. EIP-155), 2930, 1559, 4844, 7702; unknown → None.
// ---------------------------------------------------------------------------

/// The decoded tx fields the verified-read responses derive from the
/// (transactionsRoot-verified) raw tx bytes: the receipt's
/// `from`/`to`/`contractAddress`/`effectiveGasPrice` inputs plus the full
/// `eth_getTransactionByHash` field set (the Java `EthTxDecoder.DecodedTx`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSummary {
    /// 0 legacy, 1 = 2930, 2 = 1559, 3 = 4844, 4 = 7702.
    pub ty: u8,
    /// `None` only for a pre-EIP-155 legacy tx (v = 27/28).
    pub chain_id: Option<u64>,
    pub nonce: u64,
    /// `None` = contract creation (an empty `to` field).
    pub to: Option<[u8; 20]>,
    /// legacy / 2930 gas price; `None` for 1559+.
    pub gas_price: Option<u128>,
    /// 1559+; `None` otherwise.
    pub max_priority_fee_per_gas: Option<u128>,
    /// 1559+; `None` otherwise.
    pub max_fee_per_gas: Option<u128>,
    /// The gas limit.
    pub gas: u64,
    /// The wei value as minimal big-endian bytes (empty = 0) — kept as raw
    /// scalar bytes because a value can exceed u128.
    pub value: Vec<u8>,
    /// The calldata (`input`).
    pub input: Vec<u8>,
    /// The signature's v: the raw legacy v (27/28 or the EIP-155 form), or the
    /// typed tx's yParity (0/1).
    pub v: u64,
    /// Signature r/s, left-padded to 32 bytes (the JSON DATA form).
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// The recovered sender, or `None` when the signature is unrecoverable
    /// (mirrors the Java decoder: a bad signature is a missing field, never an
    /// error — the response is still served without the derived fields).
    pub from: Option<[u8; 20]>,
}

/// Decode a raw consensus tx into the receipt-facing summary, or `None` when the
/// type is unknown / the layout is malformed (the Java decoder's null → the
/// receipt omits `from`/`to`/`contractAddress`/`effectiveGasPrice`).
pub fn decode_summary(raw: &[u8]) -> Option<TxSummary> {
    let first = *raw.first()?;
    if first >= 0xc0 {
        return decode_summary_legacy(raw);
    }
    let (expected, gas_price_idx, to_idx) = typed_layout(first)?; // unknown / reserved → None
    let payload = &raw[1..];
    let items = rlp::decode(payload).ok()?;
    let list = items.as_list().ok()?;
    let raws = rlp::raw_list_items(payload).ok()?;
    if list.len() != expected {
        return None;
    }
    let chain_id = list.first()?.as_u64().ok()?;
    let nonce = list.get(1)?.as_u64().ok()?;
    let to = to_field(list.get(to_idx)?)?;
    let (gas_price, max_priority, max_fee) = match gas_price_idx {
        Some(i) => (Some(scalar_u128(list.get(i)?)?), None, None),
        None => (None, Some(scalar_u128(list.get(2)?)?), Some(scalar_u128(list.get(3)?)?)),
    };
    // gas sits just before `to`; value and data just after (every typed layout).
    let gas = list.get(to_idx - 1)?.as_u64().ok()?;
    let value = scalar_bytes(list.get(to_idx + 1)?)?;
    let input = list.get(to_idx + 2)?.as_bytes().ok()?.to_vec();
    // Signing preimage: type ‖ rlp([all fields except yParity, r, s]). The raw
    // item slices are canonical wire bytes, so re-wrapping them is byte-exact.
    let mut unsigned = Vec::new();
    for item in raws.get(..expected - 3)? {
        unsigned.extend_from_slice(item);
    }
    let mut preimage = vec![first];
    preimage.extend_from_slice(&rlp::encode_list_payload(&unsigned));
    // The typed v IS the recovery id (yParity); consensus requires 0/1, so a
    // wider value fails the whole decode (Java would emit it but its recovery
    // throws the same way — no real tx reaches here with yParity > 1).
    let v = list.get(expected - 3)?.as_u64().ok()?;
    let r_item = list.get(expected - 2)?;
    let s_item = list.get(expected - 1)?;
    let from = recover_sender(&keccak256(&preimage), r_item, s_item, Some(v));
    Some(TxSummary {
        ty: first,
        chain_id: Some(chain_id),
        nonce,
        to,
        gas_price,
        max_priority_fee_per_gas: max_priority,
        max_fee_per_gas: max_fee,
        gas,
        value,
        input,
        v,
        r: pad32(r_item)?,
        s: pad32(s_item)?,
        from,
    })
}

/// A typed transaction's field layout — `(field count, gasPrice index, to
/// index)` — or `None` for an unknown / reserved type: the one table
/// [`decode_summary`] and [`decode_sendable`] both read. Exact consensus field
/// counts; the last three fields are always `[yParity, r, s]`, gas sits just
/// before `to`, value and data just after it, and the access list after data.
fn typed_layout(ty: u8) -> Option<(usize, Option<usize>, usize)> {
    match ty {
        0x01 => Some((11, Some(2), 4)), // [chainId, nonce, gasPrice, gas, to, …]
        0x02 => Some((12, None, 5)),    // [chainId, nonce, maxPrio, maxFee, gas, to, …]
        0x03 => Some((14, None, 5)),    // 1559 layout + [maxFeePerBlobGas, blobHashes]
        0x04 => Some((13, None, 5)),    // 1559 layout + [authorizationList]
        _ => None,
    }
}

/// legacy: `rlp([nonce, gasPrice, gas, to, value, data, v, r, s])`, with the
/// EIP-155 `v = chainId*2 + 35 + recid` signing form when `v` isn't 27/28.
fn decode_summary_legacy(raw: &[u8]) -> Option<TxSummary> {
    let items = rlp::decode(raw).ok()?;
    let list = items.as_list().ok()?;
    if list.len() != 9 {
        return None;
    }
    let nonce = list.first()?.as_u64().ok()?;
    let gas_price = scalar_u128(list.get(1)?)?;
    let gas = list.get(2)?.as_u64().ok()?;
    let to = to_field(list.get(3)?)?;
    let value = scalar_bytes(list.get(4)?)?;
    let input = list.get(5)?.as_bytes().ok()?.to_vec();
    let v = list.get(6)?.as_u64().ok()?;
    let raws = rlp::raw_list_items(raw).ok()?;
    let mut unsigned = Vec::new();
    for item in raws.get(..6)? {
        unsigned.extend_from_slice(item);
    }
    let (chain_id, recid) = match v {
        27..=28 => (None, Some(v - 27)), // pre-155: sign over the 6 tx fields
        v if v >= 35 => {
            // EIP-155: the preimage appends [chainId, 0, 0].
            let chain_id = (v - 35) / 2;
            unsigned.extend_from_slice(&rlp::encode_u64(chain_id));
            unsigned.extend_from_slice(&[0x80, 0x80]); // two empty scalars
            (Some(chain_id), Some((v - 35) % 2))
        }
        // v below 27 can't map to a recovery id; keep the decoded summary but
        // drop the sender, like the Java recover() fallback.
        _ => (None, None),
    };
    let preimage = rlp::encode_list_payload(&unsigned);
    let r_item = list.get(7)?;
    let s_item = list.get(8)?;
    let from = recover_sender(&keccak256(&preimage), r_item, s_item, recid);
    Some(TxSummary {
        ty: 0,
        chain_id,
        nonce,
        to,
        gas_price: Some(gas_price),
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        gas,
        value,
        input,
        v,
        r: pad32(r_item)?,
        s: pad32(s_item)?,
        from,
    })
}

// ---------------------------------------------------------------------------
// The eth_sendRawTransaction gate (#360): only a transaction is relayed. Twin
// of the Java `EthTxDecoder.checkSendable` — same rules, same words.
// ---------------------------------------------------------------------------

/// The refusal of a blob transaction (type 0x3) — the words the
/// transaction-object refusals use (`myotis_evm::tx`, `RpcTransactionArgs`).
/// Its network form wraps the blobs around the transaction, and the eth
/// protocol forbids pushing one in a `Transactions` message: geth drops the
/// peer that does.
pub const BLOB_SEND_REFUSAL: &str = "blob transactions (type 0x3) are not supported by this node";

/// secp256k1's group order n, big-endian: a signature's r lies in [1, n).
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// ⌊n / 2⌋: the ceiling EIP-2 puts on a transaction signature's s.
const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Whether the bytes posted to `eth_sendRawTransaction` are a transaction this
/// node relays (#360): the decoded transaction, or why not, in words the
/// hosts serve under the permanent -32602 — no retry changes the bytes.
///
/// - A legacy RLP list, or an EIP-2718 type this node relays (0x1, 0x2, 0x4);
///   a blob transaction is refused ([`BLOB_SEND_REFUSAL`]).
/// - Its type's exact field layout, strictly encoded: canonical RLP with
///   nothing trailing, integers without a leading zero byte, a set-code
///   transaction's `to` an address, and the access list (and a set-code
///   transaction's authorization list) entries as geth decodes them
///   ([`access_list_well_formed`], [`authorization_list_well_formed`]) — an
///   entry geth cannot read fails the whole `Transactions` packet, and geth
///   drops the peer that sent it. Strict, so `keccak256(raw)` is the hash of
///   the transaction decoded — the one its peers compute — and never a hash
///   of whatever bytes were posted.
/// - Signature values a peer accepts (geth's `ValidateSignatureValues`): v
///   27, 28 or EIP-155 for a legacy transaction, yParity 0 or 1 for a typed
///   one, 0 < r < n, and 0 < s ≤ n/2 (EIP-2).
/// - A sender the signature recovers.
///
/// Whether the transaction can be mined — fees, nonce, balance, chain — is
/// not judged here: the chain is [`check_chain`]'s, against the node's own,
/// and the rest the pre-broadcast check's ([`crate::el::send_check`]) on
/// verified state, and otherwise the peers'.
pub fn decode_sendable(raw: &[u8]) -> Result<TxSummary, String> {
    let Some(&first) = raw.first() else {
        return Err("invalid raw transaction: empty".into());
    };
    // The payload, and the index of `to` (value and data follow it).
    let (payload, to_idx) = match first {
        0xc0..=0xff => (raw, 3), // legacy: [nonce, gasPrice, gas, to, value, data, v, r, s]
        0x03 => return Err(BLOB_SEND_REFUSAL.into()),
        _ => match typed_layout(first) {
            Some((_, _, to_idx)) => (&raw[1..], to_idx),
            // geth's words (ErrTxTypeNotSupported), then which type.
            None if first <= 0x7f => {
                return Err(format!("invalid raw transaction: transaction type not supported ({first:#x})"))
            }
            None => {
                return Err("invalid raw transaction: neither an RLP list nor an EIP-2718 typed transaction".into())
            }
        },
    };
    // The lists: a typed transaction's access list after its data, and a
    // set-code transaction's authorization list after that.
    let is_list = |i: usize| first < 0xc0 && (i == to_idx + 3 || (first == 0x04 && i == to_idx + 4));
    let kind = if first >= 0xc0 { "legacy".to_string() } else { format!("type {first:#x}") };
    let malformed = || format!("invalid raw transaction: malformed {kind} transaction");
    let item = rlp::decode(payload).map_err(|_| malformed())?;
    let fields = item.as_list().map_err(|_| malformed())?;
    let canonical = fields.iter().enumerate().all(|(i, field)| match field.as_bytes() {
        Err(_) => is_list(i),
        Ok(_) if is_list(i) => false,
        // `to` and `data` are free-form bytes; every other field is an integer.
        Ok(bytes) => i == to_idx || i == to_idx + 2 || bytes.first() != Some(&0),
    });
    let lists_well_formed = first >= 0xc0
        || (fields.get(to_idx + 3).is_some_and(access_list_well_formed)
            && (first != 0x04 || fields.get(to_idx + 4).is_some_and(authorization_list_well_formed)));
    if !(canonical && lists_well_formed) {
        return Err(malformed());
    }
    let tx = decode_summary(raw).ok_or_else(malformed)?;
    if first == 0x04 && tx.to.is_none() {
        return Err("invalid raw transaction: a type 0x4 transaction cannot create a contract".into());
    }
    let v_valid = if tx.ty == 0 { matches!(tx.v, 27 | 28) || tx.v >= 35 } else { tx.v <= 1 };
    let r_valid = tx.r != [0; 32] && tx.r < SECP256K1_N;
    let s_valid = tx.s != [0; 32] && tx.s <= SECP256K1_HALF_N;
    if !(v_valid && r_valid && s_valid) {
        return Err("invalid transaction v, r, s values".into());
    }
    if tx.from.is_none() {
        return Err("invalid sender: the signature recovers no address".into());
    }
    Ok(tx)
}

/// Whether a transaction [`decode_sendable`] passed was signed for `chain_id`
/// (#665): the refusal in geth's words when it was signed for another chain
/// (its txpool's `ErrInvalidSender` around the signer's `ErrInvalidChainId`).
/// No peer here would ever include it, so broadcasting it and answering its
/// hash would show a wallet "sent" for a transaction that can never confirm.
/// Unlike the pre-broadcast check's verdicts this one rests on the signed
/// bytes alone — no state, no head to be stale — so it never fails open.
/// A pre-EIP-155 legacy transaction names no chain and passes, as geth's
/// signer recovers it without one. Twin of the Java
/// `EthTxDecoder.chainRefusal` — same rule, same words.
pub fn check_chain(tx: &TxSummary, chain_id: u64) -> Result<(), String> {
    match tx.chain_id {
        Some(signed) if signed != chain_id => {
            Err(format!("invalid sender: invalid chain id for signer: have {signed} want {chain_id}"))
        }
        _ => Ok(()),
    }
}

/// An access list as geth decodes one (`[]AccessTuple`): every entry is
/// `[address, [storage key, …]]`, a 20-byte and 32-byte strings.
fn access_list_well_formed(list: &Item) -> bool {
    let Ok(entries) = list.as_list() else { return false };
    entries.iter().all(|entry| match entry.as_list() {
        Ok([address, keys]) => {
            address.as_bytes().is_ok_and(|a| a.len() == 20)
                && keys.as_list().is_ok_and(|keys| keys.iter().all(|k| k.as_bytes().is_ok_and(|k| k.len() == 32)))
        }
        _ => false,
    })
}

/// An EIP-7702 authorization list as geth decodes one
/// (`[]SetCodeAuthorization`): every entry is `[chainId, address, nonce,
/// yParity, r, s]`, the address 20 bytes and the integers canonical and no
/// wider than geth reads them (32, 8, 1, 32 and 32 bytes). Whether an
/// authorization is valid is not judged — geth skips an invalid one and the
/// transaction stands.
fn authorization_list_well_formed(list: &Item) -> bool {
    let int = |item: &Item, width: usize| item.as_bytes().is_ok_and(|b| b.len() <= width && b.first() != Some(&0));
    let Ok(entries) = list.as_list() else { return false };
    entries.iter().all(|entry| match entry.as_list() {
        Ok([chain_id, address, nonce, y_parity, r, s]) => {
            int(chain_id, 32)
                && address.as_bytes().is_ok_and(|a| a.len() == 20)
                && int(nonce, 8)
                && int(y_parity, 1)
                && int(r, 32)
                && int(s, 32)
        }
        _ => false,
    })
}

/// A tx `to` field: 20 bytes → the target, empty → contract creation (`None`);
/// any other length is consensus-invalid → the outer `None` (bad tx).
#[allow(clippy::option_option)]
fn to_field(item: &Item) -> Option<Option<[u8; 20]>> {
    let bytes = item.as_bytes().ok()?;
    match bytes.len() {
        0 => Some(None),
        20 => {
            let mut out = [0u8; 20];
            out.copy_from_slice(bytes);
            Some(Some(out))
        }
        _ => None,
    }
}

/// Recover the 20-byte sender from the signing hash + minimal-BE `r`/`s` items
/// and the recovery id. `None` on any malformed input — never an error.
fn recover_sender(hash: &[u8; 32], r: &Item, s: &Item, recid: Option<u64>) -> Option<[u8; 20]> {
    let recid = match recid {
        Some(v @ 0..=1) => v as u8,
        _ => return None,
    };
    let mut sig = [0u8; 65];
    pad32_into(r, &mut sig[..32])?;
    pad32_into(s, &mut sig[32..64])?;
    sig[64] = recid;
    let pubkey = recover_public_key(hash, &sig).ok()?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&keccak256(&pubkey)[12..32]);
    Some(out)
}

/// Left-pad a minimal-BE RLP scalar into a 32-byte slot; `None` if it's wider
/// than 32 bytes (not a valid secp256k1 scalar).
fn pad32_into(item: &Item, out: &mut [u8]) -> Option<()> {
    let bytes = item.as_bytes().ok()?;
    if bytes.len() > 32 {
        return None;
    }
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(())
}

/// A minimal-BE RLP scalar left-padded to a fresh 32-byte word (the JSON DATA
/// form of a signature scalar).
fn pad32(item: &Item) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    pad32_into(item, &mut out)?;
    Some(out)
}

/// A minimal-BE RLP scalar as raw bytes (a wei value — can exceed u128, so it
/// stays bytes). `None` if it isn't a byte string or is wider than a 32-byte
/// word (not a valid EVM scalar).
fn scalar_bytes(item: &Item) -> Option<Vec<u8>> {
    let bytes = item.as_bytes().ok()?;
    if bytes.len() > 32 {
        return None;
    }
    Some(bytes.to_vec())
}

/// The effective gas price a mined tx paid (the receipt convention): the
/// legacy/2930 `gasPrice`, or `baseFee + min(maxPriorityFee, maxFee - baseFee)`
/// for 1559+ using the CONTAINING block's base fee. Twin of the Java
/// `VerifiedRpcBackend.effectiveGasPrice`.
pub fn effective_gas_price(tx: &TxSummary, base_fee: u128) -> Option<u128> {
    if let Some(gp) = tx.gas_price {
        return Some(gp);
    }
    let max_fee = tx.max_fee_per_gas?;
    let prio = tx.max_priority_fee_per_gas.unwrap_or(0);
    let room = max_fee.saturating_sub(base_fee);
    Some(base_fee.saturating_add(prio.min(room)))
}

/// The address a creation tx deploys to: `keccak256(rlp([from, nonce]))[12..]`
/// (twin of the Java `VerifiedRpcBackend.contractAddressFor`).
pub fn contract_address(from: &[u8; 20], nonce: u64) -> [u8; 20] {
    let rlp = rlp::encode(&Item::List(vec![
        Item::Bytes(from.to_vec()),
        Item::Bytes(rlp::u64_to_minimal_be(nonce)),
    ]));
    let mut out = [0u8; 20];
    out.copy_from_slice(&keccak256(&rlp)[12..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::rlp::{encode, Item};

    fn be(v: u128) -> Vec<u8> {
        // Minimal big-endian encoding (RLP scalar form).
        if v == 0 {
            return Vec::new();
        }
        let bytes = v.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap();
        bytes[first..].to_vec()
    }

    /// Build a legacy tx RLP: [nonce, gasPrice, gasLimit, to, value, data, v, r, s].
    fn legacy_tx(gas_price: u128) -> Vec<u8> {
        encode(&Item::List(vec![
            Item::Bytes(be(1)),           // nonce
            Item::Bytes(be(gas_price)),   // gasPrice
            Item::Bytes(be(21000)),       // gasLimit
            Item::Bytes(vec![0x11; 20]),  // to
            Item::Bytes(be(0)),           // value
            Item::Bytes(Vec::new()),      // data
            Item::Bytes(be(27)),          // v
            Item::Bytes(vec![0x22; 32]),  // r
            Item::Bytes(vec![0x33; 32]),  // s
        ]))
    }

    /// Build a 1559 tx: 0x02 ‖ rlp([chainId, nonce, maxPrio, maxFee, gasLimit, …]).
    fn eip1559_tx(max_priority: u128, max_fee: u128) -> Vec<u8> {
        let mut out = vec![0x02];
        out.extend_from_slice(&encode(&Item::List(vec![
            Item::Bytes(be(1)),             // chainId
            Item::Bytes(be(7)),             // nonce
            Item::Bytes(be(max_priority)),  // maxPriorityFeePerGas
            Item::Bytes(be(max_fee)),       // maxFeePerGas
            Item::Bytes(be(21000)),         // gasLimit
            Item::Bytes(vec![0x11; 20]),    // to
            Item::Bytes(be(0)),             // value
            Item::Bytes(Vec::new()),        // data
            Item::List(Vec::new()),         // accessList
            Item::Bytes(be(0)),             // yParity
            Item::Bytes(vec![0x22; 32]),    // r
            Item::Bytes(vec![0x33; 32]),    // s
        ])));
        out
    }

    #[test]
    fn legacy_tip_is_gas_price_minus_base() {
        // gasPrice 30 gwei, base 10 gwei → tip 20 gwei.
        let tx = legacy_tx(30_000_000_000);
        assert_eq!(effective_tip(&tx, 10_000_000_000), Some(20_000_000_000));
    }

    #[test]
    fn legacy_tip_saturates_at_zero() {
        // gasPrice below base (a mispriced/edge tx) → 0, not underflow.
        let tx = legacy_tx(5_000_000_000);
        assert_eq!(effective_tip(&tx, 10_000_000_000), Some(0));
    }

    #[test]
    fn eip1559_tip_is_min_of_priority_and_room() {
        // maxPrio 2 gwei, maxFee 100 gwei, base 10 gwei → room 90 gwei → min = 2 gwei.
        let tx = eip1559_tx(2_000_000_000, 100_000_000_000);
        assert_eq!(effective_tip(&tx, 10_000_000_000), Some(2_000_000_000));
        // maxFee-constrained: maxPrio 50 gwei, maxFee 12 gwei, base 10 gwei → room 2 gwei.
        let tx2 = eip1559_tx(50_000_000_000, 12_000_000_000);
        assert_eq!(effective_tip(&tx2, 10_000_000_000), Some(2_000_000_000));
    }

    #[test]
    fn unknown_type_and_empty_are_none() {
        assert_eq!(effective_tip(&[], 1), None);
        assert_eq!(effective_tip(&[0x7f, 0xc0], 1), None); // reserved type byte
    }

    /// EIP-2930 (type 0x01): [chainId, nonce, gasPrice, …] — gasPrice at index 2.
    fn eip2930_tx(gas_price: u128) -> Vec<u8> {
        let mut out = vec![0x01];
        out.extend_from_slice(&encode(&Item::List(vec![
            Item::Bytes(be(1)),          // chainId
            Item::Bytes(be(1)),          // nonce
            Item::Bytes(be(gas_price)),  // gasPrice
            Item::Bytes(be(21000)),      // gasLimit
            Item::Bytes(vec![0x11; 20]), // to
            Item::Bytes(be(0)),          // value
            Item::Bytes(Vec::new()),     // data
            Item::List(Vec::new()),      // accessList
            Item::Bytes(be(0)),          // yParity
            Item::Bytes(vec![0x22; 32]), // r
            Item::Bytes(vec![0x33; 32]), // s
        ])));
        out
    }

    #[test]
    fn eip2930_tip_reads_gas_price_at_index_2() {
        // gasPrice 30 gwei, base 10 gwei → tip 20 gwei (a wrong index would misread).
        let tx = eip2930_tx(30_000_000_000);
        assert_eq!(effective_tip(&tx, 10_000_000_000), Some(20_000_000_000));
    }

    #[test]
    fn typed_4844_and_7702_share_the_1559_fee_layout() {
        // 0x03 (blob) and 0x04 (7702) read maxPriorityFee@2 / maxFee@3 like 0x02;
        // the decoder ignores their trailing fields, so a 1559-shaped list suffices.
        for ty in [0x03u8, 0x04] {
            let mut tx = eip1559_tx(2_000_000_000, 100_000_000_000);
            tx[0] = ty;
            assert_eq!(effective_tip(&tx, 10_000_000_000), Some(2_000_000_000), "type {ty:#x}");
        }
    }

    // -----------------------------------------------------------------------
    // decode_summary / sender recovery.
    // -----------------------------------------------------------------------

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The EIP-155 spec example: chainId 1, nonce 9, signed with the private key
    /// 0x46…46 → sender 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f, v = 37.
    #[test]
    fn eip155_spec_vector_recovers_the_sender() {
        let raw = hex(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7\
             6400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a0\
             67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
        );
        let t = decode_summary(&raw).expect("decodes");
        assert_eq!(t.ty, 0);
        assert_eq!(t.chain_id, Some(1)); // v = 37 → EIP-155 chainId 1
        assert_eq!(t.nonce, 9);
        assert_eq!(t.gas_price, Some(20_000_000_000));
        assert_eq!(t.gas, 21_000);
        assert_eq!(t.to, Some([0x35; 20]));
        assert_eq!(t.value, be(1_000_000_000_000_000_000)); // 1 ETH
        assert!(t.input.is_empty());
        assert_eq!(t.v, 37);
        // r/s are the spec vector's scalars, left-padded to 32 bytes.
        assert_eq!(
            t.r.to_vec(),
            hex("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")
        );
        assert_eq!(
            t.s.to_vec(),
            hex("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
        );
        assert_eq!(
            t.from.map(|f| f.to_vec()),
            Some(hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"))
        );
    }

    /// Sign a 1559 tx with a throwaway key and check the recovered sender is
    /// the key's own address (round-trip through the typed signing preimage).
    #[test]
    fn eip1559_signed_roundtrip_recovers_the_sender() {
        let key = myotis_core::nodekey::NodeKey::from_secret_bytes(&[0x42; 32]).unwrap();
        let expected: [u8; 20] =
            keccak256(&key.public_key_bytes())[12..32].try_into().unwrap();

        let unsigned_fields = vec![
            Item::Bytes(be(1)),            // chainId
            Item::Bytes(be(7)),            // nonce
            Item::Bytes(be(2_000_000_000)), // maxPriorityFeePerGas
            Item::Bytes(be(50_000_000_000)), // maxFeePerGas
            Item::Bytes(be(21000)),        // gasLimit
            Item::Bytes(Vec::new()),       // to: EMPTY → contract creation
            Item::Bytes(be(0)),            // value
            Item::Bytes(Vec::new()),       // data
            Item::List(Vec::new()),        // accessList
        ];
        let mut preimage = vec![0x02];
        preimage.extend_from_slice(&encode(&Item::List(unsigned_fields.clone())));
        let sig = key.sign_hash(&keccak256(&preimage)).unwrap();
        let strip = |b: &[u8]| b.iter().skip_while(|&&x| x == 0).copied().collect::<Vec<_>>();

        let mut signed = unsigned_fields;
        signed.push(Item::Bytes(be(sig[64] as u128))); // yParity
        signed.push(Item::Bytes(strip(&sig[..32]))); // r (minimal BE)
        signed.push(Item::Bytes(strip(&sig[32..64]))); // s
        let mut raw = vec![0x02];
        raw.extend_from_slice(&encode(&Item::List(signed)));

        let t = decode_summary(&raw).expect("decodes");
        assert_eq!(t.ty, 2);
        assert_eq!(t.chain_id, Some(1));
        assert_eq!(t.nonce, 7);
        assert_eq!(t.to, None); // creation
        assert_eq!(t.gas_price, None);
        assert_eq!(t.max_priority_fee_per_gas, Some(2_000_000_000));
        assert_eq!(t.max_fee_per_gas, Some(50_000_000_000));
        assert_eq!(t.gas, 21_000);
        assert!(t.value.is_empty()); // 0
        assert_eq!(t.v, sig[64] as u64);
        assert_eq!(t.from, Some(expected));

        // The created contract address: keccak256(rlp([from, nonce]))[12..].
        let created = contract_address(&expected, t.nonce);
        let rlp = encode(&Item::List(vec![
            Item::Bytes(expected.to_vec()),
            Item::Bytes(be(7)),
        ]));
        assert_eq!(created.to_vec(), keccak256(&rlp)[12..32].to_vec());
    }

    #[test]
    fn invalid_signature_yields_summary_without_sender() {
        // r = 0 is not a valid secp256k1 scalar — recovery fails, so the
        // summary decodes with `from` absent (the Java recover() null
        // convention), never an error.
        let mut raw = vec![0x02];
        raw.extend_from_slice(&encode(&Item::List(vec![
            Item::Bytes(be(1)),             // chainId
            Item::Bytes(be(7)),             // nonce
            Item::Bytes(be(2_000_000_000)), // maxPriorityFeePerGas
            Item::Bytes(be(100_000_000_000)), // maxFeePerGas
            Item::Bytes(be(21000)),         // gasLimit
            Item::Bytes(vec![0x11; 20]),    // to
            Item::Bytes(be(0)),             // value
            Item::Bytes(Vec::new()),        // data
            Item::List(Vec::new()),         // accessList
            Item::Bytes(be(0)),             // yParity
            Item::Bytes(Vec::new()),        // r = 0 (invalid scalar)
            Item::Bytes(vec![0x33; 32]),    // s
        ])));
        let t = decode_summary(&raw).expect("decodes");
        assert_eq!(t.ty, 2);
        assert_eq!(t.to, Some([0x11; 20]));
        assert_eq!(t.from, None);
    }

    #[test]
    fn unknown_type_and_wrong_arity_are_none() {
        assert_eq!(decode_summary(&[]), None);
        assert_eq!(decode_summary(&[0x7f, 0xc0]), None); // reserved type byte
        // A 1559 list with a missing field is rejected (exact arity).
        let mut raw = vec![0x02];
        raw.extend_from_slice(&encode(&Item::List(vec![Item::Bytes(be(1))])));
        assert_eq!(decode_summary(&raw), None);
    }

    /// A zero-filled summary for tests that only care about the fee fields.
    fn bare_summary(ty: u8) -> TxSummary {
        TxSummary {
            ty,
            chain_id: None,
            nonce: 0,
            to: None,
            gas_price: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            gas: 0,
            value: Vec::new(),
            input: Vec::new(),
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
            from: None,
        }
    }

    #[test]
    fn effective_gas_price_matches_the_receipt_convention() {
        let legacy = TxSummary { gas_price: Some(30_000_000_000), ..bare_summary(0) };
        assert_eq!(effective_gas_price(&legacy, 10_000_000_000), Some(30_000_000_000));

        let dyn_fee = TxSummary {
            max_priority_fee_per_gas: Some(2_000_000_000),
            max_fee_per_gas: Some(50_000_000_000),
            ..bare_summary(2)
        };
        // base 10 + min(2, 40) = 12 gwei.
        assert_eq!(effective_gas_price(&dyn_fee, 10_000_000_000), Some(12_000_000_000));
        // maxFee-constrained: base 49 + min(2, 1) = 50 gwei.
        assert_eq!(effective_gas_price(&dyn_fee, 49_000_000_000), Some(50_000_000_000));
        // base above maxFee: room saturates at 0 → base (mirrors Java's floor).
        assert_eq!(effective_gas_price(&dyn_fee, 60_000_000_000), Some(60_000_000_000));
    }

    // -----------------------------------------------------------------------
    // decode_sendable: the eth_sendRawTransaction gate (#360). The Java
    // EthTxSendCheckTest checks the same cases against checkSendable.
    // -----------------------------------------------------------------------

    /// The EIP-155 spec example (see eip155_spec_vector_recovers_the_sender).
    const SPEC_TX: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7\
                           6400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a0\
                           67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    /// The unsigned fields of a type-`ty` (1, 2 or 4) transfer on chain 1.
    fn unsigned_fields(ty: u8) -> Vec<Item> {
        let mut fields = vec![Item::Bytes(be(1)), Item::Bytes(be(7))]; // chainId, nonce
        if ty == 1 {
            fields.push(Item::Bytes(be(30_000_000_000))); // gasPrice
        } else {
            fields.push(Item::Bytes(be(2_000_000_000))); // maxPriorityFeePerGas
            fields.push(Item::Bytes(be(30_000_000_000))); // maxFeePerGas
        }
        fields.extend([
            Item::Bytes(be(21_000)),      // gas
            Item::Bytes(vec![0x11; 20]),  // to
            Item::Bytes(be(1)),           // value
            Item::Bytes(Vec::new()),      // data
            Item::List(Vec::new()),       // accessList
        ]);
        if ty == 4 {
            // One authorization; the gate does not read its contents.
            fields.push(Item::List(vec![Item::List(vec![
                Item::Bytes(be(1)),
                Item::Bytes(vec![0xde; 20]),
                Item::Bytes(Vec::new()),
                Item::Bytes(be(1)),
                Item::Bytes(vec![1; 32]),
                Item::Bytes(vec![2; 32]),
            ])]));
        }
        fields
    }

    /// `ty ‖ rlp([..unsigned, yParity, r, s])` signed by a throwaway key, and
    /// that key's address.
    fn sign_typed(ty: u8, unsigned: Vec<Item>) -> (Vec<u8>, [u8; 20]) {
        let key = myotis_core::nodekey::NodeKey::from_secret_bytes(&[0x42; 32]).unwrap();
        let from: [u8; 20] = keccak256(&key.public_key_bytes())[12..32].try_into().unwrap();
        let mut preimage = vec![ty];
        preimage.extend_from_slice(&encode(&Item::List(unsigned.clone())));
        let sig = key.sign_hash(&keccak256(&preimage)).unwrap();
        let strip = |b: &[u8]| b.iter().skip_while(|&&x| x == 0).copied().collect::<Vec<_>>();
        let mut fields = unsigned;
        fields.push(Item::Bytes(be(sig[64] as u128)));
        fields.push(Item::Bytes(strip(&sig[..32])));
        fields.push(Item::Bytes(strip(&sig[32..64])));
        let mut raw = vec![ty];
        raw.extend_from_slice(&encode(&Item::List(fields)));
        (raw, from)
    }

    /// A typed `raw` with its fields edited and its signature left as it was.
    fn edited(raw: &[u8], edit: impl FnOnce(&mut Vec<Item>)) -> Vec<u8> {
        let mut fields = rlp::decode(&raw[1..]).unwrap().as_list().unwrap().to_vec();
        edit(&mut fields);
        let mut out = vec![raw[0]];
        out.extend_from_slice(&encode(&Item::List(fields)));
        out
    }

    /// `a - b` over 32-byte big-endian words (`a >= b`), minimally encoded.
    fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> Vec<u8> {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = a[i] as i16 - b[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            out[i] = d.rem_euclid(256) as u8;
        }
        out.iter().copied().skip_while(|&x| x == 0).collect()
    }

    #[test]
    fn a_signed_transaction_of_every_relayed_type_passes_the_send_gate() {
        let spec = decode_sendable(&hex(SPEC_TX)).expect("the EIP-155 spec vector");
        assert_eq!(spec.from.map(|f| f.to_vec()), Some(hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")));
        for ty in [1u8, 2, 4] {
            let (raw, from) = sign_typed(ty, unsigned_fields(ty));
            let tx = decode_sendable(&raw).unwrap_or_else(|e| panic!("type {ty}: {e}"));
            assert_eq!((tx.ty, tx.from), (ty, Some(from)), "type {ty}");
        }
        // A creation is a transaction like any other — except for type 0x4.
        let (create, _) = sign_typed(2, {
            let mut f = unsigned_fields(2);
            f[5] = Item::Bytes(Vec::new());
            f
        });
        assert_eq!(decode_sendable(&create).map(|t| t.to), Ok(None));
    }

    #[test]
    fn only_a_transaction_signed_for_this_chain_passes_the_chain_check() {
        let chain = |raw: &[u8], chain_id: u64| {
            check_chain(&decode_sendable(raw).expect("sendable"), chain_id)
        };
        // Typed: the signed chainId field. unsigned_fields signs for chain 1.
        for ty in [1u8, 2, 4] {
            let (raw, _) = sign_typed(ty, unsigned_fields(ty));
            assert_eq!(chain(&raw, 1), Ok(()), "type {ty}");
            assert_eq!(
                chain(&raw, 11_155_111),
                Err("invalid sender: invalid chain id for signer: have 1 want 11155111".to_string()),
                "type {ty}"
            );
        }
        // Legacy EIP-155: the chain in v. The spec vector is chain 1.
        let spec = hex(SPEC_TX);
        assert_eq!(chain(&spec, 1), Ok(()));
        assert_eq!(chain(&spec, 100), Err("invalid sender: invalid chain id for signer: have 1 want 100".to_string()));
        // Pre-EIP-155 legacy (v 27/28) names no chain: it passes on any.
        let unsigned = vec![
            Item::Bytes(be(7)),              // nonce
            Item::Bytes(be(30_000_000_000)), // gasPrice
            Item::Bytes(be(21_000)),         // gas
            Item::Bytes(vec![0x11; 20]),     // to
            Item::Bytes(be(1)),              // value
            Item::Bytes(Vec::new()),         // data
        ];
        let key = myotis_core::nodekey::NodeKey::from_secret_bytes(&[0x42; 32]).unwrap();
        let sig = key.sign_hash(&keccak256(&encode(&Item::List(unsigned.clone())))).unwrap();
        let strip = |b: &[u8]| b.iter().skip_while(|&&x| x == 0).copied().collect::<Vec<_>>();
        let mut fields = unsigned;
        fields.push(Item::Bytes(be(27 + sig[64] as u128)));
        fields.push(Item::Bytes(strip(&sig[..32])));
        fields.push(Item::Bytes(strip(&sig[32..64])));
        let unprotected = encode(&Item::List(fields));
        assert_eq!(decode_sendable(&unprotected).expect("sendable").chain_id, None);
        for chain_id in [1, 100, 11_155_111] {
            assert_eq!(chain(&unprotected, chain_id), Ok(()), "chain {chain_id}");
        }
    }

    #[test]
    fn bytes_that_are_no_transaction_are_refused() {
        let refused = |raw: &[u8]| decode_sendable(raw).expect_err("refused");
        // The issue's reproduction: one 0x00 byte.
        assert_eq!(refused(&[0x00]), "invalid raw transaction: transaction type not supported (0x0)");
        assert_eq!(refused(&[]), "invalid raw transaction: empty");
        assert_eq!(refused(&[0x05, 0xc0]), "invalid raw transaction: transaction type not supported (0x5)");
        assert_eq!(refused(&[0x7f]), "invalid raw transaction: transaction type not supported (0x7f)");
        assert_eq!(
            refused(&[0x83, b'd', b'o', b'g']),
            "invalid raw transaction: neither an RLP list nor an EIP-2718 typed transaction"
        );
        assert_eq!(refused(&[0xc0]), "invalid raw transaction: malformed legacy transaction");
        assert_eq!(refused(&[0x02]), "invalid raw transaction: malformed type 0x2 transaction");
        assert_eq!(refused(&[0x02, 0xc0]), "invalid raw transaction: malformed type 0x2 transaction");
        // Truncated by one byte.
        let spec = hex(SPEC_TX);
        assert_eq!(refused(&spec[..spec.len() - 1]), "invalid raw transaction: malformed legacy transaction");
    }

    #[test]
    fn a_blob_transaction_is_refused_in_either_form() {
        // The network form (`0x03 ‖ rlp([tx, blobs, commitments, proofs])`)
        // and the bare one alike: neither may be pushed in `Transactions`.
        let (bare, _) = sign_typed(2, unsigned_fields(2));
        let mut blob = bare.clone();
        blob[0] = 0x03;
        assert_eq!(decode_sendable(&blob), Err(BLOB_SEND_REFUSAL.to_string()));
        let mut network = vec![0x03];
        network.extend_from_slice(&encode(&Item::List(vec![
            rlp::decode(&bare[1..]).unwrap(),
            Item::List(Vec::new()),
            Item::List(Vec::new()),
            Item::List(Vec::new()),
        ])));
        assert_eq!(decode_sendable(&network), Err(BLOB_SEND_REFUSAL.to_string()));
    }

    #[test]
    fn only_a_strict_encoding_passes_so_the_hash_is_the_transactions_own() {
        let malformed = Err("invalid raw transaction: malformed type 0x2 transaction".to_string());
        let (raw, _) = sign_typed(2, unsigned_fields(2));
        // Anything trailing the transaction.
        let mut trailing = raw.clone();
        trailing.push(0x00);
        assert_eq!(decode_sendable(&trailing), malformed);
        let mut spec_trailing = hex(SPEC_TX);
        spec_trailing.push(0x80);
        assert_eq!(
            decode_sendable(&spec_trailing),
            Err("invalid raw transaction: malformed legacy transaction".to_string())
        );
        // A field too many, or too few.
        assert_eq!(decode_sendable(&edited(&raw, |f| f.push(Item::Bytes(Vec::new())))), malformed);
        assert_eq!(decode_sendable(&edited(&raw, |f| drop(f.remove(7)))), malformed);
        // An integer with a leading zero byte, even one the signature covers.
        let (padded, _) = sign_typed(2, {
            let mut f = unsigned_fields(2);
            f[1] = Item::Bytes(vec![0x00, 0x07]); // nonce
            f
        });
        assert_eq!(decode_sendable(&padded), malformed);
        let padded_s = edited(&raw, |f| {
            let s = f[11].as_bytes().unwrap().to_vec();
            f[11] = Item::Bytes([vec![0x00], s].concat());
        });
        assert_eq!(decode_sendable(&padded_s), malformed);
        // The access list as bytes, or `to` as a list.
        let (bytes_list, _) = sign_typed(2, {
            let mut f = unsigned_fields(2);
            f[8] = Item::Bytes(Vec::new());
            f
        });
        assert_eq!(decode_sendable(&bytes_list), malformed);
        assert_eq!(decode_sendable(&edited(&raw, |f| f[5] = Item::List(Vec::new()))), malformed);
        // A `to` that is neither empty nor an address; a fee wider than 16 bytes.
        assert_eq!(decode_sendable(&edited(&raw, |f| f[5] = Item::Bytes(vec![0x11; 5]))), malformed);
        assert_eq!(decode_sendable(&edited(&raw, |f| f[3] = Item::Bytes(vec![0x01; 17]))), malformed);
        // An access list geth cannot read, even under a valid signature: an
        // entry that is no `[address, [key…]]` tuple, a short address, a
        // short key — or a nest past the RLP depth bound.
        let tuple = |address: Vec<u8>, keys: Vec<Vec<u8>>| {
            Item::List(vec![Item::Bytes(address), Item::List(keys.into_iter().map(Item::Bytes).collect())])
        };
        let with_access_list = |list: Item| {
            sign_typed(2, {
                let mut f = unsigned_fields(2);
                f[8] = list;
                f
            })
            .0
        };
        assert!(decode_sendable(&with_access_list(Item::List(vec![tuple(vec![0x11; 20], vec![vec![0x22; 32]])]))).is_ok());
        let nested = |levels: usize| (1..levels).fold(Item::List(Vec::new()), |inner, _| Item::List(vec![inner]));
        for bad in [
            Item::List(vec![Item::Bytes(vec![0x01])]),
            Item::List(vec![tuple(vec![0x11; 5], vec![])]),
            Item::List(vec![tuple(vec![0x11; 20], vec![vec![0x22; 31]])]),
            Item::List(vec![Item::List(vec![Item::Bytes(vec![0x11; 20])])]),
            Item::List(vec![Item::List(vec![Item::Bytes(vec![0x11; 20]), Item::List(vec![]), Item::List(vec![])])]),
            Item::List(vec![Item::List(vec![Item::Bytes(vec![0x11; 20]), Item::Bytes(vec![0x22; 32])])]),
            nested(33),
            nested(200),
        ] {
            assert_eq!(decode_sendable(&with_access_list(bad.clone())), malformed, "{bad:?}");
        }
        // Non-canonical RLP: the nonce 0x07 spelled `0x81 0x07`, where a byte
        // below 0x80 must stand for itself.
        assert_eq!(&raw[..5], &[0x02, 0xf8, raw[2], 0x01, 0x07]); // type, list prefix, chainId 1, nonce 7
        let mut long_form = raw[..4].to_vec();
        long_form.push(0x81);
        long_form.extend_from_slice(&raw[4..]);
        long_form[2] += 1; // the list's length byte
        assert_eq!(decode_sendable(&long_form), malformed);
    }

    #[test]
    fn a_set_code_authorization_list_must_read_as_geth_reads_it() {
        let malformed = Err("invalid raw transaction: malformed type 0x4 transaction".to_string());
        type Edit = dyn Fn(&mut Vec<Item>);
        // [chainId, address, nonce, yParity, r, s] — unsigned_fields(4)'s one entry.
        let auth = |edit: &Edit| {
            let mut entry = vec![
                Item::Bytes(be(1)),
                Item::Bytes(vec![0xde; 20]),
                Item::Bytes(Vec::new()),
                Item::Bytes(be(1)),
                Item::Bytes(vec![1; 32]),
                Item::Bytes(vec![2; 32]),
            ];
            edit(&mut entry);
            sign_typed(4, {
                let mut f = unsigned_fields(4);
                f[9] = Item::List(vec![Item::List(entry)]);
                f
            })
            .0
        };
        assert!(decode_sendable(&auth(&|_| {})).is_ok());
        // Not judged: an authorization geth would skip as invalid (yParity 5,
        // another chain) leaves the transaction standing.
        assert!(decode_sendable(&auth(&|e| e[3] = Item::Bytes(be(5)))).is_ok());
        let bad: [&Edit; 7] = [
            &|e| drop(e.pop()),                              // five fields
            &|e| e.push(Item::Bytes(Vec::new())),            // seven
            &|e| e[1] = Item::Bytes(vec![0xde; 19]),         // a short address
            &|e| e[2] = Item::Bytes(vec![0x01; 9]),          // a nonce past u64
            &|e| e[3] = Item::Bytes(vec![0x01, 0x00]),       // a yParity past u8
            &|e| e[0] = Item::Bytes(vec![0x00, 0x01]),       // a leading zero
            &|e| e[4] = Item::List(Vec::new()),              // r as a list
        ];
        for (i, edit) in bad.into_iter().enumerate() {
            assert_eq!(decode_sendable(&auth(edit)), malformed, "case {i}");
        }
        // An entry that is no list at all.
        let (bytes_entry, _) = sign_typed(4, {
            let mut f = unsigned_fields(4);
            f[9] = Item::List(vec![Item::Bytes(vec![0x01])]);
            f
        });
        assert_eq!(decode_sendable(&bytes_entry), malformed);
    }

    #[test]
    fn a_set_code_transaction_must_name_its_target() {
        let (raw, _) = sign_typed(4, {
            let mut f = unsigned_fields(4);
            f[5] = Item::Bytes(Vec::new());
            f
        });
        assert_eq!(
            decode_sendable(&raw),
            Err("invalid raw transaction: a type 0x4 transaction cannot create a contract".to_string())
        );
    }

    #[test]
    fn a_signature_a_peer_would_refuse_is_refused() {
        let invalid = Err("invalid transaction v, r, s values".to_string());
        // A legacy v that is neither 27/28 nor EIP-155.
        let spec = hex(SPEC_TX);
        let at = spec.len() - 67; // v = 0x25 sits before the r (0xa0 ‖ 32) and s items
        assert_eq!(spec[at], 0x25);
        let mut v29 = spec.clone();
        v29[at] = 29;
        assert_eq!(decode_sendable(&v29), invalid);
        let (raw, from) = sign_typed(2, unsigned_fields(2));
        // A typed yParity above 1 — 2, or one past 32 bits (the Java twin
        // must not read that as malformed).
        assert_eq!(decode_sendable(&edited(&raw, |f| f[9] = Item::Bytes(be(2)))), invalid);
        assert_eq!(decode_sendable(&edited(&raw, |f| f[9] = Item::Bytes(be(1 << 40)))), invalid);
        // r or s zero, r at or past n.
        assert_eq!(decode_sendable(&edited(&raw, |f| f[10] = Item::Bytes(Vec::new()))), invalid);
        assert_eq!(decode_sendable(&edited(&raw, |f| f[11] = Item::Bytes(Vec::new()))), invalid);
        assert_eq!(decode_sendable(&edited(&raw, |f| f[10] = Item::Bytes(SECP256K1_N.to_vec()))), invalid);
        // The malleated twin of a valid signature — s' = n - s, the parity
        // flipped — would name the same sender, but it is high-s: EIP-2
        // refuses it, whatever a recoverer makes of it.
        let malleated = edited(&raw, |f| {
            let s: [u8; 32] = pad32(&f[11]).unwrap();
            let parity = f[9].as_u64().unwrap();
            f[9] = Item::Bytes(be((1 - parity) as u128));
            f[11] = Item::Bytes(sub_be(&SECP256K1_N, &s));
        });
        assert_eq!(decode_sendable(&malleated), invalid);
        assert_eq!(decode_sendable(&raw).map(|t| t.from), Ok(Some(from)));
        // An r in range that is no curve point's x: nothing recovers.
        let senderless = (1u8..=255)
            .map(|x| edited(&raw, |f| f[10] = Item::Bytes(vec![x])))
            .find(|t| decode_summary(t).is_some_and(|t| t.from.is_none()))
            .expect("some small r is no x-coordinate");
        assert_eq!(
            decode_sendable(&senderless),
            Err("invalid sender: the signature recovers no address".to_string())
        );
    }
}
