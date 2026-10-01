//! [`EvmFixture`]: a recorded world as a JSON file, and the [`ReplayOracle`]
//! that serves it.
//!
//! The file is deterministic (sorted keys, lowercase hex) so a re-recording
//! diffs cleanly:
//!
//! ```text
//! { "format":   "myotis-evm-fixture/1",
//!   "meta":     { provenance, synthetic keys — free-form },
//!   "block":    { hash, number, stateRoot, timestamp, baseFeePerGas, gasLimit,
//!                 coinbase, prevRandao, chainId, slotNumber },
//!   "request":  { the eth_estimateGas call object, as a wallet sends it },
//!   "stateOverride": { "0x<address>": { "balance": "<quantity>" } },
//!   "measured": { numbers the recorder measured — free-form },
//!   "accounts": { "0x<address>": null | { nonce, balance, codeHash, storageRoot } },
//!   "storage":  { "0x<address>": { "0x<32-byte slot>": "<quantity>" } },
//!   "code":     { "0x<code hash>": "0x<bytecode>" } }
//! ```
//!
//! A `null` account is one the proof showed ABSENT, which is part of the world
//! as much as a present one. The world is chain state only: anything the
//! request needs that the chain does not hold (a synthetic sender's funds) is a
//! `stateOverride`, in the shape `eth_estimateGas` takes as its third
//! parameter, which every replay applies.

use std::collections::BTreeMap;

use revm::primitives::U256;
use serde_json::{json, Map, Value};

use myotis_core::keccak::keccak256;
use myotis_core::trie::EMPTY_CODE_HASH;

use super::hex0x;
use super::recording::RecordedWorld;
use crate::block::BlockContext;
use crate::oracle::{OracleAccount, OracleError, SnapStateOracle};
use crate::overrides::{AccountOverride, StateOverrides};
use crate::tx::{AccessListItem, Authorization, Fees, TxRequest};

/// The format tag every fixture file carries; a reader refuses any other.
pub const FIXTURE_FORMAT: &str = "myotis-evm-fixture/1";

/// A recorded world: the verified block a transaction ran against, the request
/// as a wallet sent it, and every piece of state the runs read.
#[derive(Clone, Debug, PartialEq)]
pub struct EvmFixture {
    /// Provenance, and anything a replay needs besides the world (the
    /// synthetic keys, say). Kept verbatim.
    pub meta: Value,
    /// The verified header's hash. Provenance only: no EVM input reads it.
    pub block_hash: [u8; 32],
    /// The context the recorded runs executed in.
    pub block: BlockContext,
    /// The request exactly as a wallet sends it to `eth_estimateGas`.
    pub request: Value,
    /// Balances the request needs that the chain does not hold, applied as a
    /// state override on every replay.
    pub balance_overrides: BTreeMap<[u8; 20], U256>,
    /// What the recorder measured, for a replay to pin. Kept verbatim.
    pub measured: Value,
    /// Every account, slot and bytecode the recorded runs read.
    pub world: RecordedWorld,
}

impl EvmFixture {
    /// The fixture as its JSON file.
    pub fn to_json(&self) -> String {
        let accounts: Map<String, Value> = self
            .world
            .accounts
            .iter()
            .map(|(address, account)| {
                let entry = match account {
                    None => Value::Null,
                    Some(a) => json!({
                        "nonce": quantity(U256::from(a.nonce)),
                        "balance": quantity(a.balance),
                        "codeHash": hex0x(&a.code_hash),
                        "storageRoot": hex0x(&a.storage_root),
                    }),
                };
                (hex0x(address), entry)
            })
            .collect();
        let storage: Map<String, Value> = self
            .world
            .storage
            .iter()
            .map(|(address, slots)| {
                let slots: Map<String, Value> =
                    slots.iter().map(|(slot, value)| (hex0x(slot), Value::String(quantity(*value)))).collect();
                (hex0x(address), Value::Object(slots))
            })
            .collect();
        let code: Map<String, Value> =
            self.world.code.iter().map(|(hash, code)| (hex0x(hash), Value::String(hex0x(code)))).collect();
        let b = &self.block;
        let file = json!({
            "format": FIXTURE_FORMAT,
            "meta": self.meta,
            "block": {
                "hash": hex0x(&self.block_hash),
                "number": quantity(U256::from(b.block_number)),
                "stateRoot": hex0x(&b.state_root),
                "timestamp": quantity(U256::from(b.timestamp)),
                "baseFeePerGas": quantity(U256::from(b.base_fee_per_gas)),
                "gasLimit": quantity(U256::from(b.gas_limit)),
                "coinbase": hex0x(&b.coinbase),
                "prevRandao": hex0x(&b.prev_randao),
                "chainId": quantity(U256::from(b.chain_id)),
                "slotNumber": b.slot_number.map(|n| quantity(U256::from(n))),
            },
            "request": self.request,
            "stateOverride": self
                .balance_overrides
                .iter()
                .map(|(address, balance)| (hex0x(address), json!({ "balance": quantity(*balance) })))
                .collect::<Map<String, Value>>(),
            "measured": self.measured,
            "accounts": accounts,
            "storage": storage,
            "code": code,
        });
        // A Value always serializes; the file ends in a newline like any text file.
        let mut text = serde_json::to_string_pretty(&file).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Read a fixture file. Strict: an unknown key, a bytecode that does not
    /// hash to its key, or a request this module cannot read fully is an
    /// error, never skipped.
    pub fn from_json(text: &str) -> Result<EvmFixture, String> {
        let file: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let obj = object(&file, "the fixture")?;
        match obj.get("format").and_then(Value::as_str) {
            Some(FIXTURE_FORMAT) => {}
            other => return Err(format!("not a {FIXTURE_FORMAT} file (format {other:?})")),
        }
        only_keys(
            obj,
            "the fixture",
            &["format", "meta", "block", "request", "stateOverride", "measured", "accounts", "storage", "code"],
        )?;

        let block = object(required(obj, "block")?, "block")?;
        only_keys(
            block,
            "block",
            &["hash", "number", "stateRoot", "timestamp", "baseFeePerGas", "gasLimit", "coinbase", "prevRandao", "chainId", "slotNumber"],
        )?;
        let context = BlockContext {
            state_root: fixed(required(block, "stateRoot")?, "block.stateRoot")?,
            block_number: quantity_u64(required(block, "number")?, "block.number")?,
            timestamp: quantity_u64(required(block, "timestamp")?, "block.timestamp")?,
            base_fee_per_gas: quantity_u64(required(block, "baseFeePerGas")?, "block.baseFeePerGas")?,
            coinbase: fixed(required(block, "coinbase")?, "block.coinbase")?,
            prev_randao: fixed(required(block, "prevRandao")?, "block.prevRandao")?,
            chain_id: quantity_u64(required(block, "chainId")?, "block.chainId")?,
            gas_limit: quantity_u64(required(block, "gasLimit")?, "block.gasLimit")?,
            slot_number: match block.get("slotNumber") {
                None | Some(Value::Null) => None,
                Some(n) => Some(quantity_u64(n, "block.slotNumber")?),
            },
        };

        let mut world = RecordedWorld { state_root: context.state_root, ..RecordedWorld::default() };
        for (address, account) in object(required(obj, "accounts")?, "accounts")? {
            let address = fixed_str::<20>(address, "an account address")?;
            let account = match account {
                Value::Null => None,
                entry => {
                    let fields = object(entry, "an account")?;
                    only_keys(fields, "an account", &["nonce", "balance", "codeHash", "storageRoot"])?;
                    Some(OracleAccount {
                        nonce: quantity_u64(required(fields, "nonce")?, "nonce")?,
                        balance: quantity_u256(required(fields, "balance")?, "balance")?,
                        code_hash: fixed(required(fields, "codeHash")?, "codeHash")?,
                        storage_root: fixed(required(fields, "storageRoot")?, "storageRoot")?,
                    })
                }
            };
            world.accounts.insert(address, account);
        }
        for (address, slots) in object(required(obj, "storage")?, "storage")? {
            let address = fixed_str::<20>(address, "a storage address")?;
            let mut read = BTreeMap::new();
            for (slot, value) in object(slots, "storage slots")? {
                read.insert(fixed_str::<32>(slot, "a storage slot")?, quantity_u256(value, "a storage value")?);
            }
            world.storage.insert(address, read);
        }
        for (hash, code) in object(required(obj, "code")?, "code")? {
            let hash = fixed_str::<32>(hash, "a code hash")?;
            let code = bytes(code, "bytecode")?;
            if keccak256(&code) != hash {
                return Err(format!("the bytecode under {} does not hash to it", hex0x(&hash)));
            }
            world.code.insert(hash, code);
        }

        let request = required(obj, "request")?.clone();
        request_from_json(&request)?;
        let mut balance_overrides = BTreeMap::new();
        if let Some(overrides) = obj.get("stateOverride") {
            for (address, entry) in object(overrides, "stateOverride")? {
                let entry = object(entry, "a state override")?;
                // Only what a replay can apply identically on every engine.
                only_keys(entry, "a state override", &["balance"])?;
                balance_overrides.insert(
                    fixed_str::<20>(address, "an overridden address")?,
                    quantity_u256(required(entry, "balance")?, "an overridden balance")?,
                );
            }
        }
        Ok(EvmFixture {
            meta: obj.get("meta").cloned().unwrap_or(Value::Null),
            block_hash: fixed(required(block, "hash")?, "block.hash")?,
            block: context,
            request,
            balance_overrides,
            measured: obj.get("measured").cloned().unwrap_or(Value::Null),
            world,
        })
    }

    /// The recorded request as the executor's [`TxRequest`].
    pub fn tx_request(&self) -> Result<TxRequest, String> {
        request_from_json(&self.request)
    }

    /// The fixture's state override, for every run against its world.
    pub fn overrides(&self) -> StateOverrides {
        let mut overrides = StateOverrides::new();
        for (address, balance) in &self.balance_overrides {
            overrides.insert(*address, AccountOverride { balance: Some(*balance), ..AccountOverride::default() });
        }
        overrides
    }

    /// An oracle serving exactly this fixture's world.
    pub fn oracle(&self) -> ReplayOracle {
        ReplayOracle { world: self.world.clone() }
    }

    /// A number the recorder measured, by key.
    pub fn measured_u64(&self, key: &str) -> Option<u64> {
        self.measured.get(key).and_then(|v| quantity_u64(v, key).ok())
    }
}

/// Serves exactly a recorded world, at its state root.
///
/// A read the recording did not make, or a read at another root, FAILS:
/// [`OracleError::StateUnavailable`] naming the account and slot, or
/// [`OracleError::BytecodeUnavailable`]. Nothing is guessed: "absent" for an
/// unrecorded account would be a world no block had. The run fails with that
/// error. Re-record the fixture when a change makes the EVM read more. An error,
/// not a panic, so a recorder built with `panic = "abort"` can check its own
/// recording and retry.
pub struct ReplayOracle {
    world: RecordedWorld,
}

impl ReplayOracle {
    fn missing(&self, state_root: &[u8; 32], address: [u8; 20], slot: Option<[u8; 32]>) -> OracleError {
        OracleError::StateUnavailable { state_root: *state_root, address, slot }
    }
}

impl SnapStateOracle for ReplayOracle {
    fn fetch_account(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
    ) -> Result<Option<OracleAccount>, OracleError> {
        match self.world.accounts.get(&address) {
            Some(account) if state_root == &self.world.state_root => Ok(account.clone()),
            _ => Err(self.missing(state_root, address, None)),
        }
    }

    fn fetch_storage(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
        slot: U256,
    ) -> Result<U256, OracleError> {
        let key = slot.to_be_bytes::<32>();
        match self.world.storage.get(&address).and_then(|slots| slots.get(&key)) {
            Some(value) if state_root == &self.world.state_root => Ok(*value),
            _ => Err(self.missing(state_root, address, Some(key))),
        }
    }

    fn fetch_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
        if code_hash == &EMPTY_CODE_HASH {
            return Ok(Vec::new());
        }
        self.world
            .code
            .get(code_hash)
            .cloned()
            .ok_or(OracleError::BytecodeUnavailable { code_hash: *code_hash })
    }
}

/// The JSON-RPC call object for `tx`, as a wallet sends it: every field the
/// request names, nothing it does not.
pub fn request_to_json(tx: &TxRequest) -> Value {
    let mut out = Map::new();
    out.insert("from".into(), Value::String(hex0x(&tx.from)));
    if let Some(to) = tx.to {
        out.insert("to".into(), Value::String(hex0x(&to)));
    }
    out.insert("value".into(), Value::String(quantity(tx.value)));
    out.insert("data".into(), Value::String(hex0x(&tx.data)));
    if let Some(ty) = tx.tx_type {
        out.insert("type".into(), Value::String(quantity(U256::from(ty))));
    }
    if let Some(gas) = tx.gas {
        out.insert("gas".into(), Value::String(quantity(U256::from(gas))));
    }
    match tx.fees {
        Fees::None => {}
        Fees::Legacy { gas_price } => {
            out.insert("gasPrice".into(), Value::String(quantity(U256::from(gas_price))));
        }
        Fees::DynamicFee { max_fee_per_gas, max_priority_fee_per_gas } => {
            out.insert("maxFeePerGas".into(), Value::String(quantity(U256::from(max_fee_per_gas))));
            out.insert("maxPriorityFeePerGas".into(), Value::String(quantity(U256::from(max_priority_fee_per_gas))));
        }
    }
    if let Some(nonce) = tx.nonce {
        out.insert("nonce".into(), Value::String(quantity(U256::from(nonce))));
    }
    if let Some(chain_id) = tx.chain_id {
        out.insert("chainId".into(), Value::String(quantity(chain_id)));
    }
    if let Some(list) = &tx.access_list {
        let items = list
            .iter()
            .map(|item| {
                json!({
                    "address": hex0x(&item.address),
                    "storageKeys": item.storage_keys.iter().map(|k| hex0x(k)).collect::<Vec<_>>(),
                })
            })
            .collect();
        out.insert("accessList".into(), Value::Array(items));
    }
    if let Some(list) = &tx.authorization_list {
        let items = list
            .iter()
            .map(|a| {
                json!({
                    "chainId": quantity(a.chain_id),
                    "address": hex0x(&a.address),
                    "nonce": quantity(U256::from(a.nonce)),
                    "yParity": quantity(U256::from(a.y_parity)),
                    "r": quantity(a.r),
                    "s": quantity(a.s),
                })
            })
            .collect();
        out.insert("authorizationList".into(), Value::Array(items));
    }
    Value::Object(out)
}

/// Read a call object [`request_to_json`] writes. Strict: a field this reader
/// does not apply is an error, so a fixture can never carry part of a request
/// the replay silently drops.
pub fn request_from_json(request: &Value) -> Result<TxRequest, String> {
    let obj = object(request, "the request")?;
    only_keys(
        obj,
        "the request",
        &[
            "from", "to", "value", "data", "input", "type", "gas", "gasPrice", "maxFeePerGas",
            "maxPriorityFeePerGas", "nonce", "chainId", "accessList", "authorizationList",
        ],
    )?;
    let field = |k: &str| obj.get(k).filter(|v| !v.is_null());
    let data = match (field("data").map(|d| bytes(d, "data")).transpose()?, field("input").map(|i| bytes(i, "input")).transpose()?) {
        (Some(d), Some(i)) if d != i => return Err("the request's data and input differ".into()),
        (Some(d), _) | (None, Some(d)) => d,
        (None, None) => Vec::new(),
    };
    let optional_u64 = |k: &str| field(k).map(|v| quantity_u64(v, k)).transpose();
    let optional_u128 = |k: &str| -> Result<Option<u128>, String> {
        field(k)
            .map(|v| quantity_u256(v, k).and_then(|n| u128::try_from(n).map_err(|_| format!("{k} exceeds 128 bits"))))
            .transpose()
    };
    let fees = match (optional_u128("gasPrice")?, optional_u128("maxFeePerGas")?, optional_u128("maxPriorityFeePerGas")?) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            return Err("the request names gasPrice and an EIP-1559 fee".into())
        }
        (Some(gas_price), None, None) => Fees::Legacy { gas_price },
        (None, None, None) => Fees::None,
        (None, cap, tip) => Fees::DynamicFee {
            max_fee_per_gas: cap.unwrap_or(0),
            max_priority_fee_per_gas: tip.unwrap_or(0),
        },
    };
    let access_list = field("accessList")
        .map(|list| {
            list.as_array()
                .ok_or("accessList is not an array")?
                .iter()
                .map(|item| {
                    let item = object(item, "an access-list entry")?;
                    only_keys(item, "an access-list entry", &["address", "storageKeys"])?;
                    let keys = match item.get("storageKeys") {
                        None | Some(Value::Null) => Vec::new(),
                        Some(keys) => keys
                            .as_array()
                            .ok_or("storageKeys is not an array")?
                            .iter()
                            .map(|k| fixed::<32>(k, "a storage key"))
                            .collect::<Result<_, _>>()?,
                    };
                    Ok(AccessListItem { address: fixed(required(item, "address")?, "an access-list address")?, storage_keys: keys })
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .transpose()?;
    let authorization_list = field("authorizationList")
        .map(|list| {
            list.as_array()
                .ok_or("authorizationList is not an array")?
                .iter()
                .map(|item| {
                    let a = object(item, "an authorization")?;
                    only_keys(a, "an authorization", &["chainId", "address", "nonce", "yParity", "r", "s"])?;
                    Ok(Authorization {
                        chain_id: quantity_u256(required(a, "chainId")?, "authorization chainId")?,
                        address: fixed(required(a, "address")?, "authorization address")?,
                        nonce: quantity_u64(required(a, "nonce")?, "authorization nonce")?,
                        y_parity: u8::try_from(quantity_u64(required(a, "yParity")?, "yParity")?)
                            .map_err(|_| "yParity exceeds 8 bits")?,
                        r: quantity_u256(required(a, "r")?, "authorization r")?,
                        s: quantity_u256(required(a, "s")?, "authorization s")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .transpose()?;
    Ok(TxRequest {
        from: fixed(required(obj, "from")?, "from")?,
        to: field("to").map(|v| fixed(v, "to")).transpose()?,
        data: data.into(),
        value: field("value").map(|v| quantity_u256(v, "value")).transpose()?.unwrap_or(U256::ZERO),
        gas: optional_u64("gas")?,
        fees,
        nonce: optional_u64("nonce")?,
        chain_id: field("chainId").map(|v| quantity_u256(v, "chainId")).transpose()?,
        tx_type: optional_u64("type")?
            .map(|t| u8::try_from(t).map_err(|_| format!("transaction type {t:#x} exceeds 8 bits")))
            .transpose()?,
        access_list,
        authorization_list,
    })
}

/// A JSON-RPC QUANTITY: `0x`, then the value's hex digits without leading zeros.
fn quantity(value: U256) -> String {
    format!("{value:#x}")
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value.as_object().ok_or(format!("{what} is not a JSON object"))
}

fn required<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    obj.get(key).ok_or(format!("missing \"{key}\""))
}

fn only_keys(obj: &Map<String, Value>, what: &str, known: &[&str]) -> Result<(), String> {
    match obj.keys().find(|k| !known.contains(&k.as_str())) {
        Some(unknown) => Err(format!("{what} has an unknown key \"{unknown}\"")),
        None => Ok(()),
    }
}

fn hex_digits<'a>(value: &'a Value, what: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(format!("{what} is not 0x-hex"))
}

fn quantity_u256(value: &Value, what: &str) -> Result<U256, String> {
    let digits = hex_digits(value, what)?;
    if digits.is_empty() || digits.len() > 64 {
        return Err(format!("{what} is not a quantity"));
    }
    U256::from_str_radix(digits, 16).map_err(|_| format!("{what} is not a quantity"))
}

fn quantity_u64(value: &Value, what: &str) -> Result<u64, String> {
    u64::try_from(quantity_u256(value, what)?).map_err(|_| format!("{what} exceeds 64 bits"))
}

fn bytes(value: &Value, what: &str) -> Result<Vec<u8>, String> {
    decode(hex_digits(value, what)?).ok_or(format!("{what} is not whole bytes"))
}

fn fixed<const N: usize>(value: &Value, what: &str) -> Result<[u8; N], String> {
    bytes(value, what)?.try_into().map_err(|_| format!("{what} is not {N} bytes"))
}

/// A 20-byte address from `0x`-hex, strictly.
pub(super) fn address(value: &Value, what: &str) -> Result<[u8; 20], String> {
    fixed(value, what)
}

fn fixed_str<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    fixed(&Value::String(text.to_owned()), what)
}

fn decode(digits: &str) -> Option<Vec<u8>> {
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::trie::EMPTY_TRIE_ROOT;
    use revm::primitives::Bytes;

    fn fixture() -> EvmFixture {
        let code = vec![0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let code_hash = keccak256(&code);
        let mut world = RecordedWorld { state_root: [0x11; 32], ..RecordedWorld::default() };
        world.accounts.insert(
            [0xaa; 20],
            Some(OracleAccount { nonce: 1, balance: U256::from(10u64).pow(U256::from(18)), code_hash, storage_root: EMPTY_TRIE_ROOT }),
        );
        world.accounts.insert([0xbb; 20], None);
        world.storage.entry([0xaa; 20]).or_default().insert([0x01; 32], U256::from(0x2au64));
        world.storage.entry([0xaa; 20]).or_default().insert([0x02; 32], U256::ZERO);
        world.code.insert(code_hash, code);
        let mut tx = TxRequest::call([0xbb; 20], Some([0xaa; 20]), Bytes::from(vec![0x3e, 0x12, 0xcc, 0x2e]), U256::from(7u64));
        tx.tx_type = Some(4);
        tx.authorization_list = Some(vec![Authorization {
            chain_id: U256::from(1u64),
            address: [0xcc; 20],
            nonce: 0,
            y_parity: 1,
            r: U256::from(3u64),
            s: U256::from(4u64),
        }]);
        EvmFixture {
            meta: json!({ "note": "unit test" }),
            block_hash: [0x22; 32],
            block: BlockContext {
                state_root: [0x11; 32],
                block_number: 26_000_000,
                timestamp: 1_790_000_000,
                base_fee_per_gas: 1_000_000_000,
                coinbase: [0x33; 20],
                prev_randao: [0x44; 32],
                chain_id: 1,
                gas_limit: 45_000_000,
                slot_number: None,
            },
            request: request_to_json(&tx),
            balance_overrides: BTreeMap::from([([0xbb; 20], U256::from(10u64).pow(U256::from(19)))]),
            measured: json!({ "estimate": "0x5208" }),
            world,
        }
    }

    #[test]
    fn a_fixture_round_trips_through_its_file() {
        let original = fixture();
        let text = original.to_json();
        let read = EvmFixture::from_json(&text).unwrap();
        assert_eq!(read, original);
        assert_eq!(read.to_json(), text, "the file is deterministic");
        assert_eq!(read.measured_u64("estimate"), Some(21_000));
        let overrides = read.overrides();
        assert_eq!(overrides.get(&[0xbb; 20]).and_then(|o| o.balance), Some(U256::from(10u64).pow(U256::from(19))));
    }

    #[test]
    fn a_state_override_the_replay_could_not_apply_everywhere_is_refused() {
        let mut file: Value = serde_json::from_str(&fixture().to_json()).unwrap();
        file["stateOverride"][hex0x(&[0xbb; 20])]["nonce"] = json!("0x1");
        let err = EvmFixture::from_json(&file.to_string()).unwrap_err();
        assert!(err.contains("nonce"), "{err}");
    }

    #[test]
    fn a_request_round_trips_with_every_field() {
        let mut tx = fixture().tx_request().unwrap();
        tx.gas = Some(100_000);
        tx.nonce = Some(3);
        tx.chain_id = Some(U256::from(1u64));
        tx.fees = Fees::DynamicFee { max_fee_per_gas: 30, max_priority_fee_per_gas: 2 };
        tx.access_list = Some(vec![AccessListItem { address: [0xdd; 20], storage_keys: vec![[0x05; 32]] }]);
        assert_eq!(request_from_json(&request_to_json(&tx)).unwrap(), tx);
    }

    #[test]
    fn a_request_field_the_replay_would_drop_is_refused() {
        let mut request = fixture().request;
        request["blobVersionedHashes"] = json!([]);
        let err = request_from_json(&request).unwrap_err();
        assert!(err.contains("blobVersionedHashes"), "{err}");
    }

    #[test]
    fn a_file_whose_bytecode_does_not_hash_to_its_key_is_refused() {
        let text = fixture().to_json().replace("0x6001600055", "0x6002600055");
        let err = EvmFixture::from_json(&text).unwrap_err();
        assert!(err.contains("does not hash"), "{err}");
    }

    #[test]
    fn a_file_with_an_unknown_key_is_refused() {
        let text = fixture().to_json().replacen("\"meta\"", "\"extra\": 1,\n  \"meta\"", 1);
        let err = EvmFixture::from_json(&text).unwrap_err();
        assert!(err.contains("extra"), "{err}");
    }

    #[test]
    fn the_replay_serves_the_recorded_world_including_absence() {
        let f = fixture();
        let oracle = f.oracle();
        let root = f.block.state_root;
        assert_eq!(oracle.fetch_account(&root, [0xbb; 20]).unwrap(), None);
        assert_eq!(oracle.fetch_account(&root, [0xaa; 20]).unwrap().unwrap().nonce, 1);
        assert_eq!(oracle.fetch_storage(&root, [0xaa; 20], U256::from_be_bytes([0x01; 32])).unwrap(), U256::from(0x2au64));
        assert_eq!(oracle.fetch_bytecode(&EMPTY_CODE_HASH).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn the_replay_refuses_what_nobody_recorded() {
        let f = fixture();
        let (oracle, root) = (f.oracle(), f.block.state_root);
        let unavailable = |e: OracleError| matches!(e, OracleError::StateUnavailable { .. });
        assert!(unavailable(oracle.fetch_account(&root, [0xee; 20]).unwrap_err()));
        assert!(unavailable(oracle.fetch_storage(&root, [0xaa; 20], U256::from(9u64)).unwrap_err()));
        assert!(oracle.fetch_bytecode(&[0x77; 32]).is_err());
        // Nor at another root, even what was recorded.
        assert!(unavailable(oracle.fetch_account(&[0x12; 32], [0xbb; 20]).unwrap_err()));
    }
}
