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
    if !(0x01..=0x04).contains(&first) {
        return None; // unknown / reserved tx type
    }
    let payload = &raw[1..];
    let items = rlp::decode(payload).ok()?;
    let list = items.as_list().ok()?;
    let raws = rlp::raw_list_items(payload).ok()?;
    // Exact consensus field counts per type; the last three items are always
    // [yParity, r, s].
    let (expected, gas_price_idx, to_idx) = match first {
        0x01 => (11, Some(2), 4), // [chainId, nonce, gasPrice, gas, to, …]
        0x02 => (12, None, 5),    // [chainId, nonce, maxPrio, maxFee, gas, to, …]
        0x03 => (14, None, 5),    // 1559 layout + [maxFeePerBlobGas, blobHashes]
        0x04 => (13, None, 5),    // 1559 layout + [authorizationList]
        _ => return None,
    };
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
}
