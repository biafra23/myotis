//! Minimal transaction fee-field decoder for the `eth_gasPrice` /
//! `eth_maxPriorityFeePerGas` tip suggestion. It extracts ONLY the per-tx
//! effective priority fee from a raw (consensus-encoded) transaction — not a full
//! tx decode. Twin of the fee-relevant slice of the Java `EthTxDecoder` +
//! `VerifiedRpcBackend.effectiveGasPrice`.

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
}
