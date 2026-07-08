//! Pure JSON serializers for the EL verified-read natives — the golden contract
//! the Java `RustChainHandle` parses into `AccountProofResult` /
//! `StorageProofResult`. Hand-built (not serde derive) so the key set + shape is
//! the pinned contract both sides' tests assert.
//!
//! A successful query serializes the full result object. A transport/no-peer
//! failure (NOT a verification failure — those are reported in `failReason`)
//! serializes `{"error": "..."}`, which the Java side raises as an
//! `EngineException`.

use myotis_net::el::reader::{VerifiedAccount, VerifiedCode, VerifiedStorage};

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
    use myotis_net::el::reader::{VerifiedAccount, VerifiedCode, VerifiedStorage};

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
