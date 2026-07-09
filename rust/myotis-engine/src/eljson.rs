//! Pure JSON serializers for the EL verified-read natives — the golden contract
//! the Java `RustChainHandle` parses into `AccountProofResult` /
//! `StorageProofResult`. Hand-built (not serde derive) so the key set + shape is
//! the pinned contract both sides' tests assert.
//!
//! A successful query serializes the full result object. A transport/no-peer
//! failure (NOT a verification failure — those are reported in `failReason`)
//! serializes `{"error": "..."}`, which the Java side raises as an
//! `EngineException`.

use myotis_net::el::evm::{CallOutcome, EnsOutcome, GasOutcome};
use myotis_net::el::reader::{
    FeeEstimate, VerifiedAccount, VerifiedBlock, VerifiedCode, VerifiedStorage,
};

/// The header-chain gap cap the ladder enforces (mirrors the Java
/// `VerifiedAccountQuery.MAX_HEADER_CHAIN_GAP`), echoed in the storage result's
/// diagnostics.
const MAX_HEADER_CHAIN_GAP: i64 = 8192;

/// `{"error": "..."}` — a transport / not-running / bad-input failure the Java
/// side turns into an `EngineException` (distinct from a verification failure,
/// which is a full result with `failReason` set).
pub fn error_json(message: &str) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("error".into(), message.into());
    serde_json::Value::Object(obj).to_string()
}

/// Serialize a verified account result to the `AccountProofResult` shape.
/// `address_echo` is the address exactly as the caller supplied it.
pub fn account_json(
    address_echo: &str,
    a: &VerifiedAccount,
    finalized_period: u64,
    wall_clock_period: u64,
) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("address".into(), address_echo.into());
    obj.insert("exists".into(), a.exists.into());
    // Java convention: nonce -1 and balance null when the account is absent. On
    // the (unrealistic) chance a nonce exceeds i64::MAX, saturate rather than
    // wrap — a wrap to -1 would collide with the absent sentinel.
    obj.insert(
        "nonce".into(),
        if a.exists { json_i64(i64::try_from(a.nonce).unwrap_or(i64::MAX)) } else { json_i64(-1) },
    );
    obj.insert(
        "balanceWei".into(),
        if a.exists { be_to_decimal(&a.balance).into() } else { serde_json::Value::Null },
    );
    obj.insert("storageRootHex".into(), hex0x(&a.storage_root).into());
    obj.insert("codeHashHex".into(), hex0x(&a.code_hash).into());
    obj.insert("blockNumber".into(), json_u64(a.block_number));
    obj.insert("peerStateRootHex".into(), hex0x(&a.peer_state_root).into());
    obj.insert("peerProofValid".into(), a.peer_proof_valid.into());
    obj.insert("beaconChainVerified".into(), a.beacon_chain_verified.into());
    obj.insert("blsVerified".into(), a.bls_verified.into());
    obj.insert("matchedBeaconSlot".into(), json_i64(a.matched_beacon_slot));
    obj.insert("verifyMethod".into(), opt_str(a.verify_method));
    obj.insert("failReason".into(), opt_str(a.fail_reason));
    obj.insert("accountHashHex".into(), hex0x(&a.account_hash).into());
    // proofNodesHex: the proof-node echo is a diagnostic, not part of the trust
    // path (the proof is verified inside snap_get_account before this result
    // exists). Threading the raw nodes out is deferred; emit an empty array.
    obj.insert("proofNodesHex".into(), serde_json::Value::Array(Vec::new()));
    obj.insert("beaconSynced".into(), a.beacon_synced.into());
    obj.insert("finalizedPeriod".into(), json_u64(finalized_period));
    obj.insert("wallClockPeriod".into(), json_u64(wall_clock_period));
    obj.insert("finalizedBlockNumber".into(), json_u64(a.finalized_block_number));
    obj.insert("optimisticBlockNumber".into(), json_u64(a.optimistic_block_number));
    serde_json::Value::Object(obj).to_string()
}

/// Serialize a verified storage result to the `StorageProofResult` shape.
pub fn storage_json(
    address_echo: &str,
    holder_echo: Option<&str>,
    s: &VerifiedStorage,
    finalized_slot: u64,
    optimistic_slot: u64,
) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("addressHex".into(), address_echo.into());
    obj.insert("slot".into(), json_u64(s.slot));
    obj.insert("holderHex".into(), holder_echo.map(Into::into).unwrap_or(serde_json::Value::Null));
    obj.insert("storageKeyHex".into(), hex0x(&s.storage_key).into());
    obj.insert("storageKeyHashHex".into(), hex0x(&s.slot_key_hash).into());
    obj.insert("exists".into(), s.found.into());
    obj.insert(
        "valueHex".into(),
        if s.found { hex0x_var(&s.value).into() } else { serde_json::Value::Null },
    );
    obj.insert(
        "valueDecimal".into(),
        if s.found { be_to_decimal(&s.value).into() } else { serde_json::Value::Null },
    );
    obj.insert("slotsReturned".into(), json_i64(if s.found { 1 } else { 0 }));
    obj.insert("storageRootHex".into(), hex0x(&s.storage_root).into());
    obj.insert("proofNodesHex".into(), serde_json::Value::Array(Vec::new()));
    obj.insert("storageProofValid".into(), s.storage_proof_valid.into());
    obj.insert("beaconSynced".into(), s.beacon_synced.into());
    obj.insert("beaconChainVerified".into(), s.beacon_chain_verified.into());
    obj.insert("blsVerified".into(), s.bls_verified.into());
    obj.insert("matchedBeaconSlot".into(), json_i64(s.matched_beacon_slot));
    obj.insert("verifyMethod".into(), opt_str(s.verify_method));
    obj.insert("failReason".into(), opt_str(s.fail_reason));
    obj.insert("peerBlockNumber".into(), json_u64(s.block_number));
    obj.insert("finalizedBlockNumber".into(), json_u64(s.finalized_block_number));
    obj.insert("optimisticBlockNumber".into(), json_u64(s.optimistic_block_number));
    obj.insert("finalizedSlot".into(), json_u64(finalized_slot));
    obj.insert("optimisticSlot".into(), json_u64(optimistic_slot));
    obj.insert("maxHeaderChainGap".into(), json_i64(MAX_HEADER_CHAIN_GAP));
    serde_json::Value::Object(obj).to_string()
}

/// Serialize a verified contract-code result (`eth_getCode`). `codeHex` is the
/// full bytecode (0x-hex, `0x` for empty); the Java side reads it plus
/// `verifyMethod` — data only when a verdict is present.
pub fn code_json(
    address_echo: &str,
    c: &VerifiedCode,
    finalized_period: u64,
    wall_clock_period: u64,
) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("address".into(), address_echo.into());
    obj.insert("exists".into(), c.exists.into());
    obj.insert("codeHex".into(), hex0x_var(&c.code).into());
    obj.insert("codeHashHex".into(), hex0x(&c.code_hash).into());
    obj.insert("blockNumber".into(), json_u64(c.block_number));
    obj.insert("beaconChainVerified".into(), c.beacon_chain_verified.into());
    obj.insert("blsVerified".into(), c.bls_verified.into());
    obj.insert("matchedBeaconSlot".into(), json_i64(c.matched_beacon_slot));
    obj.insert("verifyMethod".into(), opt_str(c.verify_method));
    obj.insert("failReason".into(), opt_str(c.fail_reason));
    obj.insert("beaconSynced".into(), c.beacon_synced.into());
    obj.insert("finalizedPeriod".into(), json_u64(finalized_period));
    obj.insert("wallClockPeriod".into(), json_u64(wall_clock_period));
    obj.insert("finalizedBlockNumber".into(), json_u64(c.finalized_block_number));
    obj.insert("optimisticBlockNumber".into(), json_u64(c.optimistic_block_number));
    serde_json::Value::Object(obj).to_string()
}

/// Serialize a verified block to the `eth_getBlockByNumber` JSON — transactions as
/// hashes, `uncles` always empty (a verified header serve). Mirrors the Java
/// `VerifiedRpcBackend.buildBlockJson` field set and QUANTITY encoding exactly.
/// Hand-built (not serde) so the shape is the pinned cross-language contract.
pub fn block_json(b: &VerifiedBlock) -> String {
    let h = &b.header;
    let mut s = String::with_capacity(1024);
    s.push_str("{\"number\":\"");
    s.push_str(&hex_quantity(h.number));
    s.push_str("\",\"hash\":\"");
    s.push_str(&hex0x(&b.hash));
    s.push_str("\",\"parentHash\":\"");
    s.push_str(&hex0x(&h.parent_hash));
    s.push_str("\",\"nonce\":\"");
    s.push_str(&hex0x_var(&h.nonce));
    s.push_str("\",\"sha3Uncles\":\"");
    s.push_str(&hex0x(&h.ommers_hash));
    s.push_str("\",\"logsBloom\":\"");
    s.push_str(&hex0x_var(&h.logs_bloom));
    s.push_str("\",\"transactionsRoot\":\"");
    s.push_str(&hex0x(&h.transactions_root));
    s.push_str("\",\"stateRoot\":\"");
    s.push_str(&hex0x(&h.state_root));
    s.push_str("\",\"receiptsRoot\":\"");
    s.push_str(&hex0x(&h.receipts_root));
    s.push_str("\",\"miner\":\"");
    s.push_str(&hex0x_var(&h.beneficiary));
    s.push_str("\",\"difficulty\":\"");
    s.push_str(&hex_quantity_scalar(&h.difficulty));
    s.push_str("\",\"extraData\":\"");
    s.push_str(&hex0x_var(&h.extra_data));
    s.push_str("\",\"gasLimit\":\"");
    s.push_str(&hex_quantity(h.gas_limit));
    s.push_str("\",\"gasUsed\":\"");
    s.push_str(&hex_quantity(h.gas_used));
    s.push_str("\",\"timestamp\":\"");
    s.push_str(&hex_quantity(h.timestamp));
    s.push_str("\",\"mixHash\":\"");
    s.push_str(&hex0x(&h.mix_hash_or_prev_randao));
    s.push('"');
    // Optional post-fork fields — emitted only when present (fork-gated), exactly
    // like the Java serializer.
    if let Some(bf) = &h.base_fee_per_gas {
        s.push_str(",\"baseFeePerGas\":\"");
        s.push_str(&hex_quantity_scalar(bf));
        s.push('"');
    }
    if let Some(wr) = &h.withdrawals_root {
        s.push_str(",\"withdrawalsRoot\":\"");
        s.push_str(&hex0x(wr));
        s.push('"');
    }
    if let Some(bg) = h.blob_gas_used {
        s.push_str(",\"blobGasUsed\":\"");
        s.push_str(&hex_quantity(bg));
        s.push('"');
    }
    if let Some(eg) = h.excess_blob_gas {
        s.push_str(",\"excessBlobGas\":\"");
        s.push_str(&hex_quantity(eg));
        s.push('"');
    }
    if let Some(pr) = &h.parent_beacon_block_root {
        s.push_str(",\"parentBeaconBlockRoot\":\"");
        s.push_str(&hex0x(pr));
        s.push('"');
    }
    s.push_str(",\"transactions\":[");
    for (i, txh) in b.tx_hashes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(&hex0x(txh));
        s.push('"');
    }
    s.push_str("],\"uncles\":[]}");
    s
}

/// Serialize a verified fee suggestion. Both values are decimal-wei strings (the
/// FFI-neutral form the Java `VerifiedReads.gasPrice()/maxPriorityFeePerGas()`
/// return); the Java side re-encodes to 0x-QUANTITY at the JSON-RPC boundary.
pub fn fee_json(f: &FeeEstimate) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("gasPriceWei".into(), f.gas_price_wei.to_string().into());
    obj.insert("maxPriorityFeePerGasWei".into(), f.max_priority_fee_wei.to_string().into());
    serde_json::Value::Object(obj).to_string()
}

/// Serialize a broadcast transaction hash (`eth_sendRawTransaction`).
/// `eth_call` result: `{"status":"ok","resultHex":"0x…"}` on success,
/// `{"status":"revert","dataHex":"0x…"}` on a revert, or
/// `{"status":"unavailable","reason":"…"}` when it couldn't be executed/verified.
/// The Java side returns the bytes for `ok` and a JSON-RPC null for the other two
/// (matching the reference engine, which treats revert/unavailable as "no answer").
pub fn call_json(outcome: &CallOutcome) -> String {
    let mut obj = serde_json::Map::new();
    match outcome {
        CallOutcome::Success(data) => {
            obj.insert("status".into(), "ok".into());
            obj.insert("resultHex".into(), hex0x_var(data).into());
        }
        CallOutcome::Revert(data) => {
            obj.insert("status".into(), "revert".into());
            obj.insert("dataHex".into(), hex0x_var(data).into());
        }
        CallOutcome::Unavailable(reason) => {
            obj.insert("status".into(), "unavailable".into());
            obj.insert("reason".into(), reason.as_str().into());
        }
    }
    serde_json::Value::Object(obj).to_string()
}

/// `estimateGas` result: `{"status":"ok","gas":N}` (the buffered gas-limit estimate
/// as a JSON number — the 1.15 buffer can put it slightly above the 30 M base) or
/// `{"status":"unavailable","reason":"…"}`. The Java side returns the number for
/// `ok` and null otherwise (a reverting/unverifiable estimate has no number).
/// ENS forward-resolution result: `{"status":"ok","addressHex":"0x…","blockNumber":N}`,
/// `{"status":"noRecord","blockNumber":N}` (successfully determined absent — the
/// Java side maps it to addressHex null + error null, the API's "no record"
/// convention), or `{"status":"offchain","blockNumber":N}` (ERC-3668 name; the
/// Java side sets a descriptive error — the record exists but needs CCIP-Read).
pub fn ens_json(outcome: &EnsOutcome) -> String {
    let mut obj = serde_json::Map::new();
    match outcome {
        EnsOutcome::Resolved { address, block_number } => {
            obj.insert("status".into(), "ok".into());
            obj.insert("addressHex".into(), hex0x_var(address).into());
            obj.insert("blockNumber".into(), json_u64(*block_number));
        }
        EnsOutcome::NoRecord { block_number } => {
            obj.insert("status".into(), "noRecord".into());
            obj.insert("blockNumber".into(), json_u64(*block_number));
        }
        EnsOutcome::Offchain { block_number } => {
            obj.insert("status".into(), "offchain".into());
            obj.insert("blockNumber".into(), json_u64(*block_number));
        }
    }
    serde_json::Value::Object(obj).to_string()
}

pub fn estimate_json(outcome: &GasOutcome) -> String {
    let mut obj = serde_json::Map::new();
    match outcome {
        GasOutcome::Estimate(gas) => {
            obj.insert("status".into(), "ok".into());
            obj.insert("gas".into(), json_u64(*gas));
        }
        GasOutcome::Unavailable(reason) => {
            obj.insert("status".into(), "unavailable".into());
            obj.insert("reason".into(), reason.as_str().into());
        }
    }
    serde_json::Value::Object(obj).to_string()
}

pub fn tx_hash_json(hash: &[u8; 32]) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("txHash".into(), hex0x(hash).into());
    serde_json::Value::Object(obj).to_string()
}

/// A u64 as a minimal-hex QUANTITY (`0x0` for zero).
fn hex_quantity(v: u64) -> String {
    format!("0x{v:x}")
}

/// A minimal big-endian scalar (header difficulty / baseFee) as a QUANTITY:
/// empty/all-zero → `0x0`; else `0x` + hex with leading zero bytes/nibble stripped.
fn hex_quantity_scalar(bytes: &[u8]) -> String {
    use std::fmt::Write;
    match bytes.iter().position(|&b| b != 0) {
        None => "0x0".to_string(),
        Some(i) => {
            let mut s = String::with_capacity(2 + (bytes.len() - i) * 2);
            s.push_str("0x");
            let _ = write!(s, "{:x}", bytes[i]); // first non-zero byte: no leading-zero nibble
            for b in &bytes[i + 1..] {
                let _ = write!(s, "{b:02x}");
            }
            s
        }
    }
}

fn opt_str(v: Option<&'static str>) -> serde_json::Value {
    v.map(Into::into).unwrap_or(serde_json::Value::Null)
}

fn json_u64(v: u64) -> serde_json::Value {
    serde_json::Value::Number(v.into())
}

fn json_i64(v: i64) -> serde_json::Value {
    serde_json::Value::Number(v.into())
}

/// A 32-byte hash as `0x`-prefixed lowercase hex.
fn hex0x(bytes: &[u8; 32]) -> String {
    hex0x_var(bytes)
}

/// Variable-length bytes as `0x`-prefixed lowercase hex.
fn hex0x_var(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        // Append directly into the buffer — no per-byte String allocation.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Big-endian bytes → base-10 decimal string (schoolbook division by 10; no
/// bignum dep). Empty / all-zero → "0".
fn be_to_decimal(bytes: &[u8]) -> String {
    // Strip leading zero bytes.
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let digits = &bytes[start..];
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut value = digits.to_vec();
    let mut out = Vec::new();
    while value.iter().any(|&b| b != 0) {
        let mut remainder = 0u16;
        for byte in value.iter_mut() {
            let acc = (remainder << 8) | u16::from(*byte);
            *byte = (acc / 10) as u8;
            remainder = acc % 10;
        }
        out.push(b'0' + remainder as u8);
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_net::el::reader::{
        FeeEstimate, VerifiedAccount, VerifiedBlock, VerifiedCode, VerifiedStorage,
    };

    fn sample_account() -> VerifiedAccount {
        VerifiedAccount {
            address: [0x11; 20],
            account_hash: [0x22; 32],
            exists: true,
            nonce: 5898,
            // 6.6 ETH ≈ 6_600_000_000_000_000_000 wei = 0x5b9b7c... ; use a round value.
            balance: 1_000_000_000_000_000_000u64.to_be_bytes().to_vec(),
            storage_root: [0x33; 32],
            code_hash: [0x44; 32],
            block_number: 21_000_000,
            peer_state_root: [0x55; 32],
            peer_proof_valid: true,
            beacon_chain_verified: true,
            bls_verified: true,
            matched_beacon_slot: 7_000_000,
            verify_method: Some("headerChain"),
            fail_reason: None,
            beacon_synced: true,
            finalized_block_number: 20_999_000,
            optimistic_block_number: 21_000_010,
        }
    }

    #[test]
    fn account_json_shape_and_values() {
        let json = account_json("0xabc", &sample_account(), 1777, 1795);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["address"], "0xabc");
        assert_eq!(v["exists"], true);
        assert_eq!(v["nonce"], 5898);
        assert_eq!(v["balanceWei"], "1000000000000000000");
        assert_eq!(v["storageRootHex"], hex0x(&[0x33; 32]));
        assert_eq!(v["codeHashHex"], hex0x(&[0x44; 32]));
        assert_eq!(v["blockNumber"], 21_000_000);
        assert_eq!(v["peerStateRootHex"], hex0x(&[0x55; 32]));
        assert_eq!(v["peerProofValid"], true);
        assert_eq!(v["beaconChainVerified"], true);
        assert_eq!(v["blsVerified"], true);
        assert_eq!(v["matchedBeaconSlot"], 7_000_000);
        assert_eq!(v["verifyMethod"], "headerChain");
        assert_eq!(v["failReason"], serde_json::Value::Null);
        assert_eq!(v["accountHashHex"], hex0x(&[0x22; 32]));
        assert!(v["proofNodesHex"].is_array());
        assert_eq!(v["beaconSynced"], true);
        assert_eq!(v["finalizedPeriod"], 1777);
        assert_eq!(v["wallClockPeriod"], 1795);
        assert_eq!(v["finalizedBlockNumber"], 20_999_000);
        assert_eq!(v["optimisticBlockNumber"], 21_000_010);
    }

    #[test]
    fn absent_account_uses_negative_one_and_null() {
        let mut a = sample_account();
        a.exists = false;
        let v: serde_json::Value =
            serde_json::from_str(&account_json("0x0", &a, 1, 1)).unwrap();
        assert_eq!(v["exists"], false);
        assert_eq!(v["nonce"], -1);
        assert_eq!(v["balanceWei"], serde_json::Value::Null);
    }

    #[test]
    fn failed_verdict_carries_tokens_not_error() {
        let mut a = sample_account();
        a.beacon_chain_verified = false;
        a.bls_verified = false;
        a.verify_method = None;
        a.fail_reason = Some("beaconNotSynced");
        a.matched_beacon_slot = -1;
        let v: serde_json::Value =
            serde_json::from_str(&account_json("0x0", &a, 1, 1)).unwrap();
        assert!(v.get("error").is_none());
        assert_eq!(v["verifyMethod"], serde_json::Value::Null);
        assert_eq!(v["failReason"], "beaconNotSynced");
        assert_eq!(v["matchedBeaconSlot"], -1);
    }

    #[test]
    fn storage_json_shape() {
        let s = VerifiedStorage {
            address: [0x11; 20],
            slot: 3,
            holder: None,
            storage_key: {
                let mut k = [0u8; 32];
                k[31] = 3;
                k
            },
            slot_key_hash: [0x66; 32],
            found: true,
            value: vec![0x2a],
            storage_root: [0x33; 32],
            storage_proof_valid: true,
            block_number: 21_000_000,
            peer_state_root: [0x55; 32],
            beacon_chain_verified: true,
            bls_verified: true,
            matched_beacon_slot: 7_000_000,
            verify_method: Some("headerChain"),
            fail_reason: None,
            beacon_synced: true,
            finalized_block_number: 20_999_000,
            optimistic_block_number: 21_000_010,
        };
        let v: serde_json::Value =
            serde_json::from_str(&storage_json("0xC0", None, &s, 14_560_000, 14_560_032)).unwrap();
        assert_eq!(v["addressHex"], "0xC0");
        assert_eq!(v["slot"], 3);
        assert_eq!(v["holderHex"], serde_json::Value::Null);
        assert_eq!(v["exists"], true);
        assert_eq!(v["valueHex"], "0x2a");
        assert_eq!(v["valueDecimal"], "42");
        assert_eq!(v["storageRootHex"], hex0x(&[0x33; 32]));
        assert_eq!(v["verifyMethod"], "headerChain");
        assert_eq!(v["peerBlockNumber"], 21_000_000);
        assert_eq!(v["finalizedSlot"], 14_560_000);
        assert_eq!(v["optimisticSlot"], 14_560_032);
        assert_eq!(v["maxHeaderChainGap"], 8192);
        // Plain-slot key: 32 bytes ending in 0x03.
        assert!(v["storageKeyHex"].as_str().unwrap().ends_with("03"));
    }

    #[test]
    fn error_json_shape() {
        let v: serde_json::Value = serde_json::from_str(&error_json("no snap peer")).unwrap();
        assert_eq!(v["error"], "no snap peer");
    }

    #[test]
    fn call_json_shapes() {
        // ok → status + resultHex
        let ok: serde_json::Value =
            serde_json::from_str(&call_json(&CallOutcome::Success(vec![0xde, 0xad]))).unwrap();
        assert_eq!(ok["status"], "ok");
        assert_eq!(ok["resultHex"], "0xdead");

        // empty success data serializes as 0x
        let empty: serde_json::Value =
            serde_json::from_str(&call_json(&CallOutcome::Success(Vec::new()))).unwrap();
        assert_eq!(empty["resultHex"], "0x");

        // revert → status + dataHex (the raw revert payload)
        let rev: serde_json::Value =
            serde_json::from_str(&call_json(&CallOutcome::Revert(vec![0x08, 0xc3]))).unwrap();
        assert_eq!(rev["status"], "revert");
        assert_eq!(rev["dataHex"], "0x08c3");

        // unavailable → status + reason (a diagnostic string; the Java side nulls it)
        let un: serde_json::Value = serde_json::from_str(&call_json(&CallOutcome::Unavailable(
            "out of gas".to_string(),
        )))
        .unwrap();
        assert_eq!(un["status"], "unavailable");
        assert_eq!(un["reason"], "out of gas");
    }

    #[test]
    fn estimate_json_shapes() {
        let ok: serde_json::Value =
            serde_json::from_str(&estimate_json(&GasOutcome::Estimate(24_150))).unwrap();
        assert_eq!(ok["status"], "ok");
        assert_eq!(ok["gas"], 24_150);

        let un: serde_json::Value = serde_json::from_str(&estimate_json(
            &GasOutcome::Unavailable("execution reverted".to_string()),
        ))
        .unwrap();
        assert_eq!(un["status"], "unavailable");
        assert_eq!(un["reason"], "execution reverted");
    }

    #[test]
    fn ens_json_shapes() {
        let ok: serde_json::Value = serde_json::from_str(&ens_json(&EnsOutcome::Resolved {
            address: [0xd8; 20],
            block_number: 21_000_010,
        }))
        .unwrap();
        assert_eq!(ok["status"], "ok");
        assert_eq!(ok["addressHex"], "0xd8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8");
        assert_eq!(ok["blockNumber"], 21_000_010);

        let none: serde_json::Value =
            serde_json::from_str(&ens_json(&EnsOutcome::NoRecord { block_number: 21_000_010 }))
                .unwrap();
        assert_eq!(none["status"], "noRecord");
        assert!(none.get("addressHex").is_none());

        let off: serde_json::Value =
            serde_json::from_str(&ens_json(&EnsOutcome::Offchain { block_number: 21_000_010 }))
                .unwrap();
        assert_eq!(off["status"], "offchain");
    }

    fn sample_code() -> VerifiedCode {
        VerifiedCode {
            address: [0x11; 20],
            exists: true,
            code: vec![0x60, 0x80, 0x60, 0x40], // a snippet of contract bytecode
            code_hash: [0x44; 32],
            block_number: 21_000_000,
            beacon_chain_verified: true,
            bls_verified: true,
            matched_beacon_slot: 7_000_000,
            verify_method: Some("headerChain"),
            fail_reason: None,
            beacon_synced: true,
            finalized_block_number: 20_999_000,
            optimistic_block_number: 21_000_010,
        }
    }

    #[test]
    fn code_json_shape_and_values() {
        let json = code_json("0xabc", &sample_code(), 1777, 1795);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["address"], "0xabc");
        assert_eq!(v["exists"], true);
        assert_eq!(v["codeHex"], "0x60806040");
        assert_eq!(v["codeHashHex"], hex0x(&[0x44; 32]));
        assert_eq!(v["blockNumber"], 21_000_000);
        assert_eq!(v["beaconChainVerified"], true);
        assert_eq!(v["blsVerified"], true);
        assert_eq!(v["matchedBeaconSlot"], 7_000_000);
        assert_eq!(v["verifyMethod"], "headerChain");
        assert_eq!(v["failReason"], serde_json::Value::Null);
        assert_eq!(v["beaconSynced"], true);
        assert_eq!(v["finalizedPeriod"], 1777);
        assert_eq!(v["wallClockPeriod"], 1795);
        assert_eq!(v["finalizedBlockNumber"], 20_999_000);
        assert_eq!(v["optimisticBlockNumber"], 21_000_010);
    }

    #[test]
    fn empty_code_serializes_as_0x() {
        // An EOA / empty-code account: verified, but no bytecode → "0x".
        let mut c = sample_code();
        c.code = Vec::new();
        c.exists = false;
        let v: serde_json::Value = serde_json::from_str(&code_json("0x0", &c, 1, 1)).unwrap();
        assert_eq!(v["codeHex"], "0x");
        assert_eq!(v["exists"], false);
        assert_eq!(v["verifyMethod"], "headerChain");
    }

    fn sample_block() -> VerifiedBlock {
        use myotis_net::el::reader::VerifiedBlock as VB;
        let header = myotis_core::header::BlockHeader {
            parent_hash: [0x11; 32],
            ommers_hash: [0x22; 32],
            beneficiary: vec![0xaa; 20],
            state_root: [0x33; 32],
            transactions_root: [0x44; 32],
            receipts_root: [0x55; 32],
            logs_bloom: vec![0x00; 256],
            difficulty: Vec::new(), // post-Merge: 0 -> "0x0"
            number: 21_000_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000,
            extra_data: vec![0xde, 0xad],
            mix_hash_or_prev_randao: [0x66; 32],
            nonce: vec![0x00; 8],
            base_fee_per_gas: Some(vec![0x07, 0x5b, 0xcd, 0x15]), // 123_456_789
            withdrawals_root: Some([0x77; 32]),
            blob_gas_used: Some(131_072),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some([0x88; 32]),
        };
        VB { hash: [0x99; 32], header, tx_hashes: vec![[0xa1; 32], [0xb2; 32]] }
    }

    #[test]
    fn block_json_shape_and_values() {
        let v: serde_json::Value =
            serde_json::from_str(&block_json(&sample_block())).expect("valid json");
        assert_eq!(v["number"], "0x1406f40"); // 21_000_000
        assert_eq!(v["hash"], hex0x(&[0x99; 32]));
        assert_eq!(v["parentHash"], hex0x(&[0x11; 32]));
        assert_eq!(v["nonce"], hex0x_var(&[0u8; 8]));
        assert_eq!(v["sha3Uncles"], hex0x(&[0x22; 32]));
        assert_eq!(v["transactionsRoot"], hex0x(&[0x44; 32]));
        assert_eq!(v["stateRoot"], hex0x(&[0x33; 32]));
        assert_eq!(v["receiptsRoot"], hex0x(&[0x55; 32]));
        assert_eq!(v["miner"], hex0x_var(&[0xaau8; 20]));
        assert_eq!(v["difficulty"], "0x0"); // post-Merge
        assert_eq!(v["extraData"], "0xdead");
        assert_eq!(v["gasLimit"], "0x1c9c380"); // 30_000_000
        assert_eq!(v["gasUsed"], "0xe4e1c0"); // 15_000_000
        assert_eq!(v["timestamp"], "0x6553f100"); // 1_700_000_000
        assert_eq!(v["mixHash"], hex0x(&[0x66; 32]));
        assert_eq!(v["baseFeePerGas"], "0x75bcd15"); // 123_456_789
        assert_eq!(v["withdrawalsRoot"], hex0x(&[0x77; 32]));
        assert_eq!(v["blobGasUsed"], "0x20000"); // 131_072
        assert_eq!(v["excessBlobGas"], "0x0");
        assert_eq!(v["parentBeaconBlockRoot"], hex0x(&[0x88; 32]));
        assert_eq!(v["transactions"][0], hex0x(&[0xa1; 32]));
        assert_eq!(v["transactions"][1], hex0x(&[0xb2; 32]));
        assert!(v["uncles"].as_array().unwrap().is_empty());
    }

    #[test]
    fn pre_london_block_omits_optional_fields() {
        let mut b = sample_block();
        b.header.base_fee_per_gas = None;
        b.header.withdrawals_root = None;
        b.header.blob_gas_used = None;
        b.header.excess_blob_gas = None;
        b.header.parent_beacon_block_root = None;
        let v: serde_json::Value = serde_json::from_str(&block_json(&b)).unwrap();
        assert!(v.get("baseFeePerGas").is_none());
        assert!(v.get("withdrawalsRoot").is_none());
        assert!(v.get("blobGasUsed").is_none());
        assert!(v.get("excessBlobGas").is_none());
        assert!(v.get("parentBeaconBlockRoot").is_none());
    }

    #[test]
    fn fee_json_shape() {
        let f = FeeEstimate { max_priority_fee_wei: 1_500_000_000, gas_price_wei: 12_345_678_900 };
        let v: serde_json::Value = serde_json::from_str(&fee_json(&f)).expect("valid json");
        assert_eq!(v["gasPriceWei"], "12345678900");
        assert_eq!(v["maxPriorityFeePerGasWei"], "1500000000");
    }

    #[test]
    fn be_to_decimal_cases() {
        assert_eq!(be_to_decimal(&[]), "0");
        assert_eq!(be_to_decimal(&[0, 0]), "0");
        assert_eq!(be_to_decimal(&[0x2a]), "42");
        assert_eq!(be_to_decimal(&255u64.to_be_bytes()), "255");
        assert_eq!(
            be_to_decimal(&1_000_000_000_000_000_000u64.to_be_bytes()),
            "1000000000000000000"
        );
        // A value larger than u64: 2^64 = 18446744073709551616.
        let mut big = vec![0x01];
        big.extend_from_slice(&[0u8; 8]);
        assert_eq!(be_to_decimal(&big), "18446744073709551616");
    }
}
