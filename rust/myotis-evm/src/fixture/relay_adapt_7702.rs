//! A RAILGUN "shield ETH" through a fresh EIP-7702 ephemeral account, built
//! the way the RAILGUN wallet SDK builds it. It is the transaction #509
//! reported, with throwaway keys in place of a user's.
//!
//! Sources (`@railgun-community/wallet` 11.2, `engine` 9.8):
//! `tx-shield-base-token-7702.js` (the calls and the transaction),
//! `relay-adapt-7702-signature.js` (the payload hash and its EIP-712
//! signature) and `relay-adapt-7702-execution.js` (the nonce-aware `execute`).
//!
//! The sender pays `value` to the ephemeral account in a type-4 transaction
//! whose one authorization delegates that account to RelayAdapt7702. Running
//! the delegate's code, the account executes
//! `execute([], (requireSuccess, 0, calls), executeNonce, signature)`, where
//! `calls` are `wrapBase(value)` and `shield([request])`, both addressed to the
//! account itself. It wraps the ETH it received into WETH and shields the WETH
//! into RAILGUN. `signature` is the ephemeral key's EIP-712 signature over
//! `keccak256(abi.encode(transactions, actionData, executeNonce))`, with the
//! account itself as the verifying contract.

use std::collections::BTreeMap;
use std::sync::Arc;

use revm::context::result::ExecutionResult;
use revm::context_interface::transaction::Authorization as RevmAuthorization;
use revm::primitives::{Address, Bytes, Log, U256};
use serde_json::{json, Value};

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;

use super::{hex0x, lowest_limit_that_runs, request_from_json, request_to_json, runs_at, EvmFixture, RecordingOracle};
use crate::block::BlockContext;
use crate::cache::{InMemoryBytecodeCache, InMemoryStateProofCache};
use crate::executor::{EvmExecutor, VIEW_CALL_GAS};
use crate::oracle::SnapStateOracle;
use crate::overrides::{AccountOverride, StateOverrides};
use crate::tx::{Authorization, TxRequest, TYPE_SET_CODE};

/// RAILGUN's mainnet proxy (RailgunSmartWallet), where the shield lands.
pub const MAINNET_RAILGUN_PROXY: [u8; 20] = h20("fa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9");
/// Mainnet WETH, RAILGUN's wrapped base token.
pub const MAINNET_WETH: [u8; 20] = h20("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
/// The RelayAdapt7702 #509's failing transactions delegated to (Terminal
/// Wallet 2.0.2). `shared-models` 8.2 lists it in mainnet's history.
pub const RELAY_ADAPT_7702_OF_509: [u8; 20] = h20("05ae73c5925d843864ae6f261f3175de2ebcd963");
/// The RelayAdapt7702 `shared-models` 8.2 names for mainnet today.
pub const MAINNET_RELAY_ADAPT_7702: [u8; 20] = h20("1f74b4339990db761bc0168f20d294a3a141497e");

/// `execute(Transaction[],ActionData,uint256,bytes)`, the nonce-aware form
/// every mainnet RelayAdapt7702 exposes.
pub const EXECUTE_SIGNATURE: &str = "execute((((uint256,uint256),(uint256[2],uint256[2]),(uint256,uint256)),\
bytes32,bytes32[],bytes32[],(uint16,uint72,uint8,uint64,address,bytes32,(bytes32[4],bytes32,bytes32,bytes,bytes)[]),\
(bytes32,(uint8,address,uint256),uint120))[],(bool,uint256,(address,bytes,uint256)[]),uint256,bytes)";
const SHIELD_SIGNATURE: &str = "shield(((bytes32,(uint8,address,uint256),uint120),(bytes32[3],bytes32))[])";
const WRAP_BASE_SIGNATURE: &str = "wrapBase(uint256)";
const DOMAIN_TYPE: &str = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const EXECUTE_TYPE: &str = "Execute(bytes32 payloadHash)";

/// RailgunSmartWallet's `Shield` event: the shield ran.
pub const SHIELD_EVENT: &str =
    "Shield(uint256,uint256,(bytes32,(uint8,address,uint256),uint120)[],(bytes32[3],bytes32)[],uint256[])";
/// RelayAdapt's `CallError` event: a call failed and `requireSuccess = false`
/// swallowed it.
pub const CALL_ERROR_EVENT: &str = "CallError(uint256,bytes)";
/// WETH's `Deposit` event: the wrap ran.
pub const DEPOSIT_EVENT: &str = "Deposit(address,uint256)";

/// The note's public key must be below this (RailgunLogic's
/// `validateCommitmentPreimage`); nothing else about the note is checked on
/// chain.
pub const SNARK_SCALAR_FIELD: U256 = U256::from_limbs([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// What the wallet picks for one shield, plus the note fields RAILGUN only
/// range-checks.
#[derive(Clone, Debug)]
pub struct ShieldParams {
    pub chain_id: u64,
    /// The RelayAdapt7702 the authorization delegates to.
    pub delegate: [u8; 20],
    /// The wrapped base token (WETH on mainnet).
    pub wrapped_base: [u8; 20],
    /// Wei to shield: the transaction's value and the note's (uint120).
    pub value: u128,
    /// The SDK passes `true` for a shield; a broadcaster's cross-contract
    /// calls pass `false`, which swallows a failed call instead of reverting.
    pub require_success: bool,
    /// The ephemeral account's nonce: 0 for a fresh one.
    pub authorization_nonce: u64,
    /// RelayAdapt7702's own replay nonce in the account's storage: 0 until
    /// its first `execute`.
    pub execute_nonce: U256,
    /// The note public key (below [`SNARK_SCALAR_FIELD`]).
    pub npk: [u8; 32],
    /// The note ciphertext and the shield key: opaque to the contract.
    pub encrypted_bundle: [[u8; 32]; 3],
    pub shield_key: [u8; 32],
}

/// The built shield.
#[derive(Clone, Debug)]
pub struct ShieldTx {
    /// The type-4 request, as the SDK hands it to `eth_estimateGas` (no gas,
    /// no fee fields).
    pub request: TxRequest,
    /// The ephemeral account: the transaction's `to` and the authority.
    pub ephemeral: [u8; 20],
    /// What the execute signature commits to.
    pub payload_hash: [u8; 32],
}

/// The account `key` controls.
pub fn address_of(key: &NodeKey) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&keccak256(&key.public_key_bytes())[12..]);
    out
}

/// Build the shield `sender` sends through the fresh account `ephemeral_key`
/// controls.
pub fn shield_base_token(sender: [u8; 20], ephemeral_key: &NodeKey, p: &ShieldParams) -> Result<ShieldTx, String> {
    if U256::from_be_bytes(p.npk) >= SNARK_SCALAR_FIELD {
        return Err("the note public key must be below the SNARK scalar field".into());
    }
    if p.value == 0 || p.value >= 1u128 << 120 {
        return Err("a shield's value must be non-zero and fit uint120".into());
    }
    let ephemeral = address_of(ephemeral_key);
    let action_data = action_data(ephemeral, p);
    let payload_hash = payload_hash(&action_data, p.execute_nonce);
    let digest = execute_digest(p.chain_id, ephemeral, payload_hash);
    let mut signature = ephemeral_key.sign_hash(&digest).map_err(|e| e.to_string())?;
    // `bytes signature` carries v as 27/28 (ethers' signTypedData), which the
    // contract's ECDSA recovery expects.
    signature[64] += 27;
    let data = call(
        EXECUTE_SIGNATURE,
        &[Abi::Array(Vec::new()), action_data, word(p.execute_nonce), Abi::Bytes(signature.to_vec())],
    );
    let authorization = authorize(ephemeral_key, p.chain_id, p.delegate, p.authorization_nonce)?;
    let mut request = TxRequest::call(sender, Some(ephemeral), Bytes::from(data), U256::from(p.value));
    request.tx_type = Some(TYPE_SET_CODE);
    request.authorization_list = Some(vec![authorization]);
    Ok(ShieldTx { request, ephemeral, payload_hash })
}

/// An EIP-7702 authorization `key` signs: keccak(0x05 ‖ rlp([chain_id,
/// delegate, nonce])).
pub fn authorize(key: &NodeKey, chain_id: u64, delegate: [u8; 20], nonce: u64) -> Result<Authorization, String> {
    let hash = RevmAuthorization { chain_id: U256::from(chain_id), address: Address::from(delegate), nonce }
        .signature_hash();
    let sig = key.sign_hash(&hash.0).map_err(|e| e.to_string())?;
    Ok(Authorization {
        chain_id: U256::from(chain_id),
        address: delegate,
        nonce,
        y_parity: sig[64],
        r: U256::from_be_slice(&sig[..32]),
        s: U256::from_be_slice(&sig[32..64]),
    })
}

/// The RelayAdapt7702 EIP-712 domain separator at `verifying_contract`.
pub fn domain_separator(chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    buf.extend_from_slice(&keccak256(b"RelayAdapt7702"));
    buf.extend_from_slice(&keccak256(b"1"));
    buf.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    buf.extend_from_slice(&address_word(verifying_contract));
    keccak256(&buf)
}

/// `keccak256("Execute(bytes32 payloadHash)")`: RelayAdapt7702's `EXECUTE_TYPEHASH`.
pub fn execute_typehash() -> [u8; 32] {
    keccak256(EXECUTE_TYPE.as_bytes())
}

/// The topic an event with this signature logs under.
pub fn event_topic(signature: &str) -> [u8; 32] {
    keccak256(signature.as_bytes())
}

/// The digest the ephemeral key signs: EIP-712 over `Execute(payloadHash)`.
fn execute_digest(chain_id: u64, ephemeral: [u8; 20], payload_hash: [u8; 32]) -> [u8; 32] {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&execute_typehash());
    message.extend_from_slice(&payload_hash);
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_separator(chain_id, ephemeral));
    buf.extend_from_slice(&keccak256(&message));
    keccak256(&buf)
}

/// `(requireSuccess, minGasLimit = 0, [wrapBase(value), shield([request])])`,
/// both calls to the ephemeral account itself with no value.
fn action_data(ephemeral: [u8; 20], p: &ShieldParams) -> Abi {
    let value = U256::from(p.value);
    let request = Abi::Tuple(vec![
        Abi::Tuple(vec![
            Abi::Word(p.npk),
            Abi::Tuple(vec![word(U256::ZERO), Abi::Word(address_word(p.wrapped_base)), word(U256::ZERO)]),
            word(value),
        ]),
        Abi::Tuple(vec![
            Abi::Tuple(p.encrypted_bundle.iter().map(|w| Abi::Word(*w)).collect()),
            Abi::Word(p.shield_key),
        ]),
    ]);
    let calls = [
        call(WRAP_BASE_SIGNATURE, &[word(value)]),
        call(SHIELD_SIGNATURE, &[Abi::Array(vec![request])]),
    ]
    .into_iter()
    .map(|data| Abi::Tuple(vec![Abi::Word(address_word(ephemeral)), Abi::Bytes(data), word(U256::ZERO)]))
    .collect();
    Abi::Tuple(vec![word(U256::from(u8::from(p.require_success))), word(U256::ZERO), Abi::Array(calls)])
}

/// `keccak256(abi.encode(Transaction[] [], actionData, executeNonce))`.
fn payload_hash(action_data: &Abi, execute_nonce: U256) -> [u8; 32] {
    keccak256(&encode(&[Abi::Array(Vec::new()), action_data.clone(), word(execute_nonce)]))
}

/// The synthetic sender's balance, a state override: the shield's value plus
/// any fee a replay variant prices the run at.
pub fn sender_funds() -> U256 {
    U256::from(10u64).pow(U256::from(19))
}

/// The EIP-7702 delegation designator for `delegate`: `0xef0100 ‖ address`.
pub fn designator(delegate: [u8; 20]) -> Vec<u8> {
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend_from_slice(&delegate);
    code
}

/// The retry of `shield` from the account its failed first attempt left
/// delegated. That is #509's own aftermath: the authorization was applied, the
/// shield ran out of gas. It is the same call without an authorization list,
/// a plain call that both engines serve. Run it with [`delegated`].
pub fn retry_from_delegated(shield: &TxRequest) -> TxRequest {
    let mut retry = shield.clone();
    retry.tx_type = None;
    retry.authorization_list = None;
    retry
}

/// `overrides` plus the ephemeral account as a failed first attempt left it:
/// delegated to `delegate`, nonce 1. RelayAdapt7702's own nonce in its storage
/// is still 0, since no `execute` completed.
pub fn delegated(overrides: StateOverrides, ephemeral: [u8; 20], delegate: [u8; 20]) -> StateOverrides {
    let mut overrides = overrides;
    overrides.insert(
        ephemeral,
        AccountOverride { code: Some(designator(delegate)), nonce: Some(1), ..AccountOverride::default() },
    );
    overrides
}

/// The shield's own events in one run's logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldEvents {
    /// WETH logged `Deposit`: the wrap ran.
    pub deposited: bool,
    /// RAILGUN logged `Shield`: the shield ran to its end.
    pub shielded: bool,
    /// The ephemeral account logged `CallError`: a call failed and was
    /// swallowed.
    pub call_errors: usize,
}

impl ShieldEvents {
    pub fn of(logs: &[Log], wrapped_base: [u8; 20], railgun: [u8; 20], ephemeral: [u8; 20]) -> ShieldEvents {
        let logged = |address: [u8; 20], event: &str| {
            let topic = event_topic(event);
            logs.iter()
                .filter(|log| log.address.0 == address && log.data.topics().first().map(|t| t.0) == Some(topic))
                .count()
        };
        ShieldEvents {
            deposited: logged(wrapped_base, DEPOSIT_EVENT) > 0,
            shielded: logged(railgun, SHIELD_EVENT) > 0,
            call_errors: logged(ephemeral, CALL_ERROR_EVENT),
        }
    }

    /// The whole shield ran: wrapped, shielded, nothing swallowed.
    pub fn complete(&self) -> bool {
        self.deposited && self.shielded && self.call_errors == 0
    }

    fn to_json(self) -> Value {
        json!({ "deposited": self.deposited, "shielded": self.shielded, "callErrors": self.call_errors })
    }

    fn from_json(v: &Value) -> Result<ShieldEvents, String> {
        let flag = |key: &str| v[key].as_bool().ok_or(format!("{key} is not a boolean"));
        Ok(ShieldEvents {
            deposited: flag("deposited")?,
            shielded: flag("shielded")?,
            call_errors: v["callErrors"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("callErrors is not a count")?,
        })
    }
}

/// The shield's accounts: who sends it, the account it runs in, and where its
/// events come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldAccounts {
    pub sender: [u8; 20],
    /// The fresh account the authorization delegates.
    pub ephemeral: [u8; 20],
    /// The RelayAdapt7702 it delegates to.
    pub delegate: [u8; 20],
    /// The wrapped base token, which logs `Deposit`.
    pub wrapped_base: [u8; 20],
    /// The RailgunSmartWallet proxy, which logs `Shield`.
    pub railgun_proxy: [u8; 20],
}

impl ShieldAccounts {
    /// As a fixture's `meta.shield` records them.
    pub fn to_json(&self) -> Value {
        json!({
            "sender": hex0x(&self.sender),
            "ephemeral": hex0x(&self.ephemeral),
            "delegate": hex0x(&self.delegate),
            "wrappedBase": hex0x(&self.wrapped_base),
            "railgunProxy": hex0x(&self.railgun_proxy),
        })
    }

    /// The accounts a fixture's `meta.shield` records.
    pub fn from_fixture(fixture: &EvmFixture) -> Result<ShieldAccounts, String> {
        let shield = &fixture.meta["shield"];
        let address = |key: &str| super::world::address(&shield[key], &format!("meta.shield.{key}"));
        Ok(ShieldAccounts {
            sender: address("sender")?,
            ephemeral: address("ephemeral")?,
            delegate: address("delegate")?,
            wrapped_base: address("wrappedBase")?,
            railgun_proxy: address("railgunProxy")?,
        })
    }
}

/// The requests a recording runs: the shield a wallet sends, and the variants
/// the replay checks against the same world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldRequests {
    /// The type-4 shield, as the wallet SDK hands it to `eth_estimateGas`.
    pub shield: TxRequest,
    /// The same shield as a broadcaster's multicall (`requireSuccess = false`),
    /// which swallows a failed call. Signed anew: the flag is in the signed
    /// payload.
    pub require_success_false: TxRequest,
    /// The retry from the account a failed first attempt left delegated
    /// ([`retry_from_delegated`]); it runs with [`delegated`].
    pub retry_from_delegated: TxRequest,
    /// The shield without its authorization list: what Myotis estimated
    /// before #509.
    pub without_authorization: TxRequest,
}

impl ShieldRequests {
    /// Build them all from the throwaway `ephemeral_key`.
    pub fn build(sender: [u8; 20], ephemeral_key: &NodeKey, params: &ShieldParams) -> Result<ShieldRequests, String> {
        let shield = shield_base_token(sender, ephemeral_key, params)?.request;
        let require_success_false =
            shield_base_token(sender, ephemeral_key, &ShieldParams { require_success: false, ..params.clone() })?.request;
        Ok(ShieldRequests::around(shield, require_success_false))
    }

    fn around(shield: TxRequest, require_success_false: TxRequest) -> ShieldRequests {
        let mut without_authorization = shield.clone();
        without_authorization.tx_type = None;
        without_authorization.authorization_list = None;
        ShieldRequests { retry_from_delegated: retry_from_delegated(&shield), without_authorization, require_success_false, shield }
    }

    /// The requests a fixture records: the shield is its request, and the
    /// variant the recorder had to sign is `meta.variants.requireSuccessFalse`
    /// (the fixture keeps no keys). The others follow from the shield.
    pub fn from_fixture(fixture: &EvmFixture) -> Result<ShieldRequests, String> {
        let tolerant = request_from_json(&fixture.meta["variants"]["requireSuccessFalse"])
            .map_err(|e| format!("meta.variants.requireSuccessFalse: {e}"))?;
        Ok(ShieldRequests::around(fixture.tx_request()?, tolerant))
    }

    /// As a fixture's `meta.variants` records them: the signed variant, and
    /// the retry, which a replay that cannot derive it reads (the Java one).
    pub fn variants_json(&self) -> Value {
        json!({
            "requireSuccessFalse": request_to_json(&self.require_success_false),
            "retryFromDelegated": request_to_json(&self.retry_from_delegated),
        })
    }
}

/// What running the shield and its variants measures: everything the replay
/// tests assert. A recording measures it against live state and a replay
/// against the recorded world, by the same [`measure`], so the replay makes
/// exactly the runs the recording made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldMeasurements {
    /// The shield's estimate.
    pub estimate: u64,
    /// What it uses at that limit, and its events there.
    pub gas_used_at_estimate: u64,
    pub events_at_estimate: ShieldEvents,
    /// The lowest limit at which the shield runs.
    pub lowest_limit: u64,
    /// The estimate without the authorization list (#509's answer), and
    /// whether the shield itself runs at it.
    pub estimate_without_authorization: u64,
    pub runs_at_estimate_without_authorization: bool,
    /// The `requireSuccess = false` multicall: its estimate and events there,
    /// the lowest limit at which it succeeds and its events there, and what
    /// it draws at the executor's budget.
    pub require_success_false_estimate: u64,
    pub require_success_false_events_at_estimate: ShieldEvents,
    pub require_success_false_lowest_limit: u64,
    pub require_success_false_events_at_lowest_limit: ShieldEvents,
    pub require_success_false_drawn: u64,
    /// The retry from the delegated account: its estimate and events there.
    pub retry_estimate: u64,
    pub retry_events_at_estimate: ShieldEvents,
}

impl ShieldMeasurements {
    /// As a fixture's `measured` records them.
    pub fn to_json(&self) -> Value {
        let q = |n: u64| Value::String(format!("{n:#x}"));
        json!({
            "estimate": q(self.estimate),
            "gasUsedAtEstimate": q(self.gas_used_at_estimate),
            "eventsAtEstimate": self.events_at_estimate.to_json(),
            "lowestLimit": q(self.lowest_limit),
            "estimateWithoutAuthorization": q(self.estimate_without_authorization),
            "runsAtEstimateWithoutAuthorization": self.runs_at_estimate_without_authorization,
            "requireSuccessFalseEstimate": q(self.require_success_false_estimate),
            "requireSuccessFalseEventsAtEstimate": self.require_success_false_events_at_estimate.to_json(),
            "requireSuccessFalseLowestLimit": q(self.require_success_false_lowest_limit),
            "requireSuccessFalseEventsAtLowestLimit": self.require_success_false_events_at_lowest_limit.to_json(),
            "requireSuccessFalseDrawn": q(self.require_success_false_drawn),
            "retryFromDelegatedEstimate": q(self.retry_estimate),
            "retryFromDelegatedEventsAtEstimate": self.retry_events_at_estimate.to_json(),
        })
    }

    /// What a fixture's `measured` records.
    pub fn from_fixture(fixture: &EvmFixture) -> Result<ShieldMeasurements, String> {
        let m = &fixture.measured;
        let number = |key: &str| fixture.measured_u64(key).ok_or(format!("measured.{key} is missing"));
        let events = |key: &str| ShieldEvents::from_json(&m[key]).map_err(|e| format!("measured.{key}: {e}"));
        Ok(ShieldMeasurements {
            estimate: number("estimate")?,
            gas_used_at_estimate: number("gasUsedAtEstimate")?,
            events_at_estimate: events("eventsAtEstimate")?,
            lowest_limit: number("lowestLimit")?,
            estimate_without_authorization: number("estimateWithoutAuthorization")?,
            runs_at_estimate_without_authorization: m["runsAtEstimateWithoutAuthorization"]
                .as_bool()
                .ok_or("measured.runsAtEstimateWithoutAuthorization is missing")?,
            require_success_false_estimate: number("requireSuccessFalseEstimate")?,
            require_success_false_events_at_estimate: events("requireSuccessFalseEventsAtEstimate")?,
            require_success_false_lowest_limit: number("requireSuccessFalseLowestLimit")?,
            require_success_false_events_at_lowest_limit: events("requireSuccessFalseEventsAtLowestLimit")?,
            require_success_false_drawn: number("requireSuccessFalseDrawn")?,
            retry_estimate: number("retryFromDelegatedEstimate")?,
            retry_events_at_estimate: events("retryFromDelegatedEventsAtEstimate")?,
        })
    }
}

/// Run the shield and its variants on `exec`: each estimate, a run at each,
/// the lowest limits at which the shield and the multicall run (by
/// [`lowest_limit_that_runs`]), and the multicall's draw, every run asking
/// [`runs_at`]'s one question. `overrides`
/// is the sender's funding. Any run that is not an answer (state that cannot
/// be read, a recording's missing slot) is an error.
pub fn measure(
    exec: &EvmExecutor,
    block: &BlockContext,
    overrides: &StateOverrides,
    requests: &ShieldRequests,
    accounts: &ShieldAccounts,
) -> Result<ShieldMeasurements, String> {
    // One run at `gas` by the bisection's own question ([`runs_at`]):
    // (used, drawn, events) when it runs, `None` when it does not.
    let run = |what: &str, tx: &TxRequest, gas: u64, overrides: &StateOverrides| -> Result<Option<(u64, u64, ShieldEvents)>, String> {
        Ok(match runs_at(exec, tx, gas, block, overrides).map_err(|e| format!("{what}: {e}"))? {
            Some(ExecutionResult::Success { gas: spent, logs, .. }) => Some((
                spent.tx_gas_used(),
                spent.total_gas_spent().max(spent.tx_gas_used()),
                ShieldEvents::of(&logs, accounts.wrapped_base, accounts.railgun_proxy, accounts.ephemeral),
            )),
            _ => None,
        })
    };
    let runs = |what: &str, tx: &TxRequest, gas: u64, overrides: &StateOverrides| {
        run(what, tx, gas, overrides)?.ok_or(format!("{what} does not run at gas {gas}"))
    };
    let estimate = |what: &str, tx: &TxRequest, overrides: &StateOverrides| {
        exec.estimate_tx(tx, block, overrides.clone()).map_err(|e| format!("{what}: the estimate failed: {e}"))
    };
    let lowest = |what: &str, tx: &TxRequest, overrides: &StateOverrides| {
        lowest_limit_that_runs(exec, tx, block, overrides).map_err(|e| format!("{what}: {e}"))
    };

    let shield = &requests.shield;
    let shield_estimate = estimate("the shield", shield, overrides)?;
    let (gas_used_at_estimate, _, events_at_estimate) = runs("the shield", shield, shield_estimate, overrides)?;
    let lowest_limit = lowest("the shield", shield, overrides)?;

    let without = estimate("the shield without its authorization", &requests.without_authorization, overrides)?;
    let runs_at_without = run("the shield", shield, without, overrides)?.is_some();

    let tolerant = &requests.require_success_false;
    let tolerant_estimate = estimate("requireSuccess = false", tolerant, overrides)?;
    let (_, _, tolerant_at_estimate) = runs("requireSuccess = false", tolerant, tolerant_estimate, overrides)?;
    let tolerant_lowest = lowest("requireSuccess = false", tolerant, overrides)?;
    let (_, _, tolerant_at_lowest) = runs("requireSuccess = false", tolerant, tolerant_lowest, overrides)?;
    let (_, tolerant_drawn, _) = runs("requireSuccess = false", tolerant, VIEW_CALL_GAS, overrides)?;

    let retry = &requests.retry_from_delegated;
    let retry_overrides = delegated(overrides.clone(), accounts.ephemeral, accounts.delegate);
    let retry_estimate = estimate("the retry", retry, &retry_overrides)?;
    let (_, _, retry_at_estimate) = runs("the retry", retry, retry_estimate, &retry_overrides)?;

    Ok(ShieldMeasurements {
        estimate: shield_estimate,
        gas_used_at_estimate,
        events_at_estimate,
        lowest_limit,
        estimate_without_authorization: without,
        runs_at_estimate_without_authorization: runs_at_without,
        require_success_false_estimate: tolerant_estimate,
        require_success_false_events_at_estimate: tolerant_at_estimate,
        require_success_false_lowest_limit: tolerant_lowest,
        require_success_false_events_at_lowest_limit: tolerant_at_lowest,
        require_success_false_drawn: tolerant_drawn,
        retry_estimate,
        retry_events_at_estimate: retry_at_estimate,
    })
}

/// Record the shield `sender` sends through `ephemeral_key`'s fresh account,
/// against `oracle` at `block`.
///
/// [`measure`] runs everything the replay tests run, through one
/// [`RecordingOracle`] over empty caches, so the fixture holds every read any
/// of those runs made; then it reads the coinbase, which an engine may credit
/// even where revm does not read it. The shield must complete at its estimate.
/// Last, [`measure`] runs again against the recorded world alone, and the
/// recording fails unless every measurement comes back unchanged.
///
/// `sender` holds nothing on chain: [`sender_funds`] is its state override,
/// the fixture's one value that is not chain state. The ephemeral account must
/// be absent on chain, or the authorization's nonce 0 would be stale.
#[allow(clippy::too_many_arguments)]
pub fn record_shield(
    oracle: Arc<dyn SnapStateOracle>,
    block: BlockContext,
    block_hash: [u8; 32],
    sender: [u8; 20],
    ephemeral_key: &NodeKey,
    params: &ShieldParams,
    railgun_proxy: [u8; 20],
    meta: Value,
) -> Result<EvmFixture, String> {
    let accounts = ShieldAccounts {
        sender,
        ephemeral: address_of(ephemeral_key),
        delegate: params.delegate,
        wrapped_base: params.wrapped_base,
        railgun_proxy,
    };
    let requests = ShieldRequests::build(sender, ephemeral_key, params)?;
    let recording = Arc::new(RecordingOracle::new(oracle));
    let exec = EvmExecutor::new(
        Arc::clone(&recording) as Arc<dyn SnapStateOracle>,
        Arc::new(InMemoryStateProofCache::new(1 << 16)),
        Arc::new(InMemoryBytecodeCache::new()),
    );
    let mut overrides = StateOverrides::new();
    overrides.insert(sender, AccountOverride { balance: Some(sender_funds()), ..AccountOverride::default() });

    let live = measure(&exec, &block, &overrides, &requests, &accounts)?;
    if !live.events_at_estimate.complete() {
        return Err(format!("at its estimate {} the shield did not complete: {:?}", live.estimate, live.events_at_estimate));
    }
    recording.fetch_account(&block.state_root, block.coinbase).map_err(|e| e.to_string())?;
    let world = recording.recorded();
    for (who, address) in [("ephemeral", accounts.ephemeral), ("sender", sender)] {
        match world.accounts.get(&address) {
            Some(None) => {}
            Some(Some(_)) => {
                return Err(format!("the {who} account {} exists on chain; draw new keys", hex0x(&address)))
            }
            None => return Err(format!("the recording never read the {who} account {}", hex0x(&address))),
        }
    }

    // The recorder's provenance, plus what a replay needs besides the world:
    // the shield's accounts and the variant it cannot sign (no keys are kept).
    let mut meta = match meta {
        Value::Object(fields) => fields,
        Value::Null => serde_json::Map::new(),
        other => serde_json::Map::from_iter([("note".to_string(), other)]),
    };
    meta.insert("shield".into(), accounts.to_json());
    meta.insert("variants".into(), requests.variants_json());
    let fixture = EvmFixture {
        meta: Value::Object(meta),
        block_hash,
        block,
        request: request_to_json(&requests.shield),
        balance_overrides: BTreeMap::from([(sender, sender_funds())]),
        measured: live.to_json(),
        world,
    };

    // A fixture that does not replay is no fixture: everything the live state
    // answered, the recorded world alone must answer the same.
    let replay = EvmExecutor::new(
        Arc::new(fixture.oracle()),
        Arc::new(InMemoryStateProofCache::new(1 << 16)),
        Arc::new(InMemoryBytecodeCache::new()),
    );
    let replayed = measure(&replay, &fixture.block, &fixture.overrides(), &requests, &accounts)
        .map_err(|e| format!("the recorded world does not replay: {e}"))?;
    if replayed != live {
        return Err(format!("the recorded world replays {replayed:?}, not {live:?}"));
    }
    Ok(fixture)
}

/// Calldata: the signature's selector, then its ABI-encoded arguments.
fn call(signature: &str, args: &[Abi]) -> Vec<u8> {
    let mut data = keccak256(signature.as_bytes())[..4].to_vec();
    data.extend(encode(args));
    data
}

/// The ABI types these calls use. A static tuple also stands for a static
/// fixed-size array (`bytes32[3]`), which encodes the same way.
#[derive(Clone, Debug)]
enum Abi {
    /// A static 32-byte word: uint, bool, address, bytes32.
    Word([u8; 32]),
    Bytes(Vec<u8>),
    Tuple(Vec<Abi>),
    /// A dynamic array `T[]`.
    Array(Vec<Abi>),
}

impl Abi {
    fn is_dynamic(&self) -> bool {
        match self {
            Abi::Word(_) => false,
            Abi::Bytes(_) | Abi::Array(_) => true,
            Abi::Tuple(items) => items.iter().any(Abi::is_dynamic),
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Abi::Word(w) => w.to_vec(),
            Abi::Bytes(b) => {
                let mut out = U256::from(b.len()).to_be_bytes::<32>().to_vec();
                out.extend_from_slice(b);
                out.resize(32 + b.len().div_ceil(32) * 32, 0);
                out
            }
            Abi::Tuple(items) => encode(items),
            Abi::Array(items) => {
                let mut out = U256::from(items.len()).to_be_bytes::<32>().to_vec();
                out.extend(encode(items));
                out
            }
        }
    }
}

/// Head-tail encoding of a sequence (a tuple's fields, an array's elements).
fn encode(items: &[Abi]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = items.iter().map(Abi::encode).collect();
    let head_len: usize = items.iter().zip(&encoded).map(|(i, e)| if i.is_dynamic() { 32 } else { e.len() }).sum();
    let (mut head, mut tail) = (Vec::new(), Vec::new());
    for (item, bytes) in items.iter().zip(encoded) {
        if item.is_dynamic() {
            head.extend_from_slice(&U256::from(head_len + tail.len()).to_be_bytes::<32>());
            tail.extend(bytes);
        } else {
            head.extend(bytes);
        }
    }
    head.extend(tail);
    head
}

fn word(value: U256) -> Abi {
    Abi::Word(value.to_be_bytes::<32>())
}

fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

/// A 20-byte constant from 40 hex digits.
const fn h20(hex: &str) -> [u8; 20] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let b = hex.as_bytes();
    assert!(b.len() == 40, "an address is 40 hex digits");
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The throwaway inputs of the golden vector below.
    fn golden_params() -> ShieldParams {
        ShieldParams {
            chain_id: 1,
            delegate: RELAY_ADAPT_7702_OF_509,
            wrapped_base: MAINNET_WETH,
            value: 10u128.pow(16),
            require_success: true,
            authorization_nonce: 0,
            execute_nonce: U256::ZERO,
            npk: [0x0a; 32],
            encrypted_bundle: [[0xb1; 32], [0xb2; 32], [0xb3; 32]],
            shield_key: [0x5c; 32],
        }
    }

    #[test]
    fn the_selectors_and_typehash_are_the_contracts() {
        assert_eq!(hex0x(&keccak256(EXECUTE_SIGNATURE.as_bytes())[..4]), "0x3e12cc2e");
        assert_eq!(hex0x(&keccak256(SHIELD_SIGNATURE.as_bytes())[..4]), "0x044a40c3");
        assert_eq!(hex0x(&keccak256(WRAP_BASE_SIGNATURE.as_bytes())[..4]), "0xe9a059a3");
        // RelayAdapt7702.EXECUTE_TYPEHASH(), read from both mainnet deployments.
        assert_eq!(hex0x(&execute_typehash()), "0xf24df5a0a7b800b8aa018f2ee7814e1f20511e66c80cc9b50ad5e68d95c85ff0");
    }

    /// DOMAIN_SEPARATOR() as each mainnet deployment reports it for its own
    /// address: the domain's name, version, chain and verifying contract are
    /// the contract's.
    #[test]
    fn the_domain_separator_is_the_contracts() {
        assert_eq!(
            hex0x(&domain_separator(1, RELAY_ADAPT_7702_OF_509)),
            "0x077e144cc74113895f9af8ef1f7e238e017df7a8d6077e7ca21ea2c0eee1bed2"
        );
        assert_eq!(
            hex0x(&domain_separator(1, MAINNET_RELAY_ADAPT_7702)),
            "0x62615f60e6de8a1f4686082f9507bcd1b989a17bf7aad577657d344991d12c56"
        );
    }

    #[test]
    fn the_snark_field_constant_is_the_bn254_scalar_field() {
        let expected = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();
        assert_eq!(SNARK_SCALAR_FIELD, expected);
    }

    /// Byte for byte what eth-account and eth-abi build for the same keys and
    /// note: an independent implementation of the SDK's encoding and signing
    /// (`scripts/relay_adapt_7702_golden.py` writes the vector).
    #[test]
    fn the_shield_matches_an_independent_encoding() {
        let sender = address_of(&NodeKey::from_secret_bytes(&[0x22; 32]).unwrap());
        let ephemeral_key = NodeKey::from_secret_bytes(&[0x11; 32]).unwrap();
        let shield = shield_base_token(sender, &ephemeral_key, &golden_params()).unwrap();
        let golden: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
        assert_eq!(hex0x(&shield.ephemeral), golden["ephemeral"].as_str().unwrap());
        assert_eq!(hex0x(&shield.payload_hash), golden["payloadHash"].as_str().unwrap());
        let request = crate::fixture::request_to_json(&shield.request);
        assert_eq!(request, golden["request"]);
    }

    #[test]
    fn a_note_key_outside_the_field_or_a_zero_value_is_refused() {
        let key = NodeKey::from_secret_bytes(&[0x11; 32]).unwrap();
        let mut p = golden_params();
        p.npk = SNARK_SCALAR_FIELD.to_be_bytes::<32>();
        assert!(shield_base_token([0x22; 20], &key, &p).is_err());
        let mut p = golden_params();
        p.value = 0;
        assert!(shield_base_token([0x22; 20], &key, &p).is_err());
    }

    const GOLDEN: &str = include_str!("relay_adapt_7702_golden.json");
}
