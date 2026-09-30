//! Decoder for a single consensus-encoded transaction receipt (the receipts-trie
//! value form), twin of the Java `networking.eth.messages.Receipt`.
//!
//! Consensus encoding:
//! - legacy: `rlp([status|stateRoot, cumulativeGasUsed, logsBloom, logs])`
//! - typed:  `type ‖ rlp([status, cumulativeGasUsed, logsBloom, logs])`
//!
//! where each log is `[address, [topic, …], data]`. Post-Byzantium the first
//! field is a 0/1 status byte; the rare pre-Byzantium form carries a 32-byte
//! intermediate stateRoot instead, in which case `has_status` is false.
//!
//! Pure decoder over bytes the caller has ALREADY verified against a trusted
//! `receiptsRoot` (see `myotis_core::triehash`) — it does no verification itself.

use myotis_core::rlp;

/// A decoded receipt (typed or legacy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReceipt {
    /// The EIP-2718 envelope type byte (0 = legacy).
    pub ty: u8,
    /// Whether the first field was a post-Byzantium status (vs a pre-Byzantium
    /// intermediate stateRoot, which carries no success bit).
    pub has_status: bool,
    /// The status bit when `has_status` (false otherwise).
    pub success: bool,
    pub cumulative_gas_used: u64,
    /// The 256-byte logs bloom (as carried; eth/69 responses arrive with the
    /// bloom already recomputed by the wire decoder).
    pub logs_bloom: Vec<u8>,
    pub logs: Vec<ReceiptLog>,
}

/// One log entry: `[address, [topic, …], data]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptLog {
    pub address: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub data: Vec<u8>,
}

/// Decode one receipt from its raw consensus bytes (as returned per block by
/// `ManagedPeer::get_receipts`). `Err` carries a diagnostic message. The
/// receipt is read in place and only its logs are copied out (#454).
pub fn decode(raw: &[u8]) -> Result<DecodedReceipt, String> {
    let Some(&first) = raw.first() else {
        return Err("receipt bytes are empty".to_string());
    };
    // RLP list → legacy receipt; else EIP-2718 envelope: type byte + payload.
    let (ty, payload) = if first >= 0xc0 { (0, raw) } else { (first, &raw[1..]) };
    let top = rlp::View::new(payload).map_err(|e| format!("receipt RLP: {}", e.0))?;
    let mut fields = top.as_list().map_err(|e| format!("receipt RLP: {}", e.0))?;
    let (Some(status_or_root), Some(cumulative_gas_used), Some(logs_bloom), Some(log_items)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        let count = top.as_list().map_or(0, Iterator::count);
        return Err(format!("receipt: expected 4 fields, got {count}"));
    };
    let status_or_root = status_or_root.as_bytes().map_err(|e| format!("receipt status: {}", e.0))?;
    // A <= 1-byte first field is the status; a longer one (32 bytes) is the
    // pre-Byzantium intermediate stateRoot — no status bit.
    let (has_status, success) = if status_or_root.len() <= 1 {
        (true, status_or_root.last().is_some_and(|&b| b != 0))
    } else {
        (false, false)
    };
    let cumulative_gas_used = cumulative_gas_used
        .as_u64()
        .map_err(|e| format!("receipt cumulativeGasUsed: {}", e.0))?;
    let logs_bloom =
        logs_bloom.as_bytes().map_err(|e| format!("receipt logsBloom: {}", e.0))?.to_vec();
    let log_items = log_items.as_list().map_err(|e| format!("receipt logs: {}", e.0))?;
    let mut logs = Vec::new();
    for item in log_items {
        logs.push(decode_log(item)?);
    }
    Ok(DecodedReceipt { ty, has_status, success, cumulative_gas_used, logs_bloom, logs })
}

fn decode_log(item: rlp::View<'_>) -> Result<ReceiptLog, String> {
    let mut parts = item.as_list().map_err(|e| format!("receipt log: {}", e.0))?;
    let (Some(address), Some(topic_items), Some(data)) = (parts.next(), parts.next(), parts.next())
    else {
        let count = item.as_list().map_or(0, Iterator::count);
        return Err(format!("receipt log: expected 3 fields, got {count}"));
    };
    let address = address.as_bytes().map_err(|e| format!("log address: {}", e.0))?.to_vec();
    let topic_items = topic_items.as_list().map_err(|e| format!("log topics: {}", e.0))?;
    let mut topics = Vec::new();
    for t in topic_items {
        topics.push(t.as_bytes().map_err(|e| format!("log topic: {}", e.0))?.to_vec());
    }
    let data = data.as_bytes().map_err(|e| format!("log data: {}", e.0))?.to_vec();
    Ok(ReceiptLog { address, topics, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::rlp::{encode, Item};

    fn be(v: u64) -> Vec<u8> {
        rlp::u64_to_minimal_be(v)
    }

    /// rlp([status, cumGas, bloom, [[addr, [t1, t2], data]]]) — the payload shared
    /// by legacy (bare) and typed (type ‖ payload) receipts.
    fn payload(status: &[u8], cum_gas: u64, logs: bool) -> Vec<u8> {
        let log = Item::List(vec![
            Item::Bytes(vec![0xaa; 20]),
            Item::List(vec![Item::Bytes(vec![0x11; 32]), Item::Bytes(vec![0x22; 32])]),
            Item::Bytes(vec![0xde, 0xad]),
        ]);
        encode(&Item::List(vec![
            Item::Bytes(status.to_vec()),
            Item::Bytes(be(cum_gas)),
            Item::Bytes(vec![0u8; 256]),
            Item::List(if logs { vec![log] } else { vec![] }),
        ]))
    }

    #[test]
    fn legacy_success_receipt_with_logs() {
        let r = decode(&payload(&[1], 21_000, true)).unwrap();
        assert_eq!(r.ty, 0);
        assert!(r.has_status);
        assert!(r.success);
        assert_eq!(r.cumulative_gas_used, 21_000);
        assert_eq!(r.logs_bloom.len(), 256);
        assert_eq!(r.logs.len(), 1);
        assert_eq!(r.logs[0].address, vec![0xaa; 20]);
        assert_eq!(r.logs[0].topics.len(), 2);
        assert_eq!(r.logs[0].data, vec![0xde, 0xad]);
    }

    #[test]
    fn typed_failed_receipt() {
        // status = empty scalar (0) → failed; envelope type 2.
        let mut raw = vec![0x02];
        raw.extend_from_slice(&payload(&[], 100_000, false));
        let r = decode(&raw).unwrap();
        assert_eq!(r.ty, 2);
        assert!(r.has_status);
        assert!(!r.success);
        assert!(r.logs.is_empty());
    }

    #[test]
    fn pre_byzantium_root_has_no_status() {
        // First field is a 32-byte intermediate stateRoot.
        let r = decode(&payload(&[0x33; 32], 42, false)).unwrap();
        assert!(!r.has_status);
        assert!(!r.success);
        assert_eq!(r.cumulative_gas_used, 42);
    }

    #[test]
    fn malformed_receipts_error() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x02]).is_err()); // type byte with no payload
        // A 3-field list is short.
        let short = encode(&Item::List(vec![
            Item::Bytes(vec![1]),
            Item::Bytes(be(1)),
            Item::Bytes(vec![0u8; 256]),
        ]));
        assert!(decode(&short).is_err());
    }
}
