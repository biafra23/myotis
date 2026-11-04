//! `eth_simulateV1` over a fixture world: each geth rule the module applies,
//! and each refusal. The run against a full node's answer is the engine's
//! golden test (`myotis-engine`, `simulate_matches_a_full_nodes_answer`).

use std::sync::Arc;

use super::*;
use crate::cache::{NoopBytecodeCache, NoopStateProofCache};
use crate::fork::{OSAKA_TIME, SEPOLIA_AMSTERDAM_TIME};
use crate::oracle::{FixtureSnapStateOracle, OracleAccount};
use crate::overrides::AccountOverride;

const ROOT: [u8; 32] = [0xAA; 32];
const BASE: u64 = 24_000_000;
const BASE_TIME: u64 = OSAKA_TIME + 1_000;
const BASE_HASH: [u8; 32] = [0xB0; 32];
const PARENT_HASH: [u8; 32] = [0xB1; 32];
const COINBASE: [u8; 20] = [0xC0; 20];

const S: [u8; 20] = [0x51; 20];
const C: [u8; 20] = [0xC1; 20];
const R: [u8; 20] = [0x77; 20];
const P: [u8; 20] = [0x99; 20];
const Q: [u8; 20] = [0x88; 20];
const BLK: [u8; 20] = [0xB2; 20];
const BAL: [u8; 20] = [0xBA; 20];
const X: [u8; 20] = [0x42; 20];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Stores calldata word 0 at slot 0 and LOG1s it (when there is calldata),
/// then returns slot 0.
fn store_and_log() -> Vec<u8> {
    hex("36156011576000358060005560006000a15b60005460005260206000f3")
}

/// NUMBER, TIMESTAMP, COINBASE, BASEFEE, PREVRANDAO, GASLIMIT, CHAINID.
fn block_fields() -> Vec<u8> {
    hex("43600052426020524160405248606052446080524560a0524660c05260e06000f3")
}

/// BALANCE of the address in calldata word 0.
fn balance_of() -> Vec<u8> {
    hex("6000353160005260206000f3")
}

/// CALLs Q with 1 wei, ignores the result, LOG0s, stops.
fn forwarder() -> Vec<u8> {
    let mut code = hex("6000600060006000600173");
    code.extend_from_slice(&Q);
    code.extend(hex("5af15060006000a000"));
    code
}

/// LOG0s, then reverts.
fn log_then_revert() -> Vec<u8> {
    hex("60006000a060006000fd")
}

/// Reverts with `Error("nope")`.
fn revert_nope() -> Vec<u8> {
    let w0 = format!("08c379a0{}", "00".repeat(28));
    let w1 = format!("00000020{}", "00".repeat(28));
    let w2 = format!("000000046e6f7065{}", "00".repeat(24));
    hex(&format!("7f{w0}6000527f{w1}6020527f{w2}60405260646000fd"))
}

/// Returns BLOCKHASH(calldata word 0).
fn blockhash_of() -> Vec<u8> {
    hex("6000354060005260206000f3")
}

/// Returns BLOBBASEFEE.
fn blob_base_fee() -> Vec<u8> {
    hex("4a60005260206000f3")
}

/// Spins until it runs out of gas.
fn spinner() -> Vec<u8> {
    hex("5b600056")
}

/// The EIP-2935 history contract's deployed code (`get` on a call, `set`
/// from the system address).
fn history_contract() -> Vec<u8> {
    hex("3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500")
}

fn word(n: u64) -> Vec<u8> {
    U256::from(n).to_be_bytes::<32>().to_vec()
}

fn address_word(address: [u8; 20]) -> Vec<u8> {
    let mut w = vec![0u8; 12];
    w.extend_from_slice(&address);
    w
}

fn ctx(chain_id: u64, number: u64, time: u64) -> BlockContext {
    BlockContext {
        state_root: ROOT,
        block_number: number,
        parent_hash: Some(PARENT_HASH),
        timestamp: time,
        base_fee_per_gas: 7,
        coinbase: COINBASE,
        prev_randao: [0x33; 32],
        chain_id,
        gas_limit: 60_000_000,
        slot_number: None,
    }
}

fn base() -> SimBase {
    SimBase { ctx: ctx(1, BASE, BASE_TIME), hash: BASE_HASH, gas_used: 30_000_000 }
}

/// A world with nothing in it but `extra` accounts (code, balance).
fn executor_with(extra: &[([u8; 20], Vec<u8>, U256)]) -> EvmExecutor {
    let mut fx = FixtureSnapStateOracle::new();
    let mut accounts = Vec::new();
    for (address, code, balance) in extra {
        let code_hash = if code.is_empty() { myotis_core::trie::EMPTY_CODE_HASH } else { fx.with_bytecode(code.clone()) };
        accounts.push((*address, OracleAccount { nonce: 1, balance: *balance, code_hash, storage_root: [0x9; 32] }));
    }
    for (address, account) in accounts {
        fx = fx.with_account(ROOT, address, account);
    }
    EvmExecutor::new(Arc::new(fx), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache))
}

fn executor() -> EvmExecutor {
    executor_with(&[])
}

fn overrides(entries: Vec<([u8; 20], AccountOverride)>) -> StateOverrides {
    let mut out = StateOverrides::new();
    for (address, over) in entries {
        out.insert(address, over);
    }
    out
}

fn code(code: Vec<u8>) -> AccountOverride {
    AccountOverride { code: Some(code), ..Default::default() }
}

fn funded() -> AccountOverride {
    AccountOverride { balance: Some(U256::from(10u64).pow(U256::from(19))), ..Default::default() }
}

fn call(to: Option<[u8; 20]>, data: Vec<u8>) -> TxRequest {
    let mut tx = TxRequest::call(S, to, Bytes::from(data), U256::ZERO);
    tx.gas = Some(1_000_000);
    tx
}

fn block(calls: Vec<TxRequest>) -> SimBlock {
    SimBlock { calls, ..SimBlock::default() }
}

fn run(executor: &EvmExecutor, opts: SimOptions) -> Result<Vec<SimulatedBlock>, EvmError> {
    executor.simulate(&base(), &opts)
}

fn simulate(blocks: Vec<SimBlock>) -> Vec<SimulatedBlock> {
    run(&executor(), SimOptions { blocks, ..SimOptions::default() }).expect("simulates")
}

fn code_of(err: Result<Vec<SimulatedBlock>, EvmError>) -> (i64, String) {
    match err {
        Err(EvmError::Simulation { code, message }) => (code, message),
        other => panic!("expected a simulation error, got {other:?}"),
    }
}

fn refused(err: Result<Vec<SimulatedBlock>, EvmError>) -> String {
    match err {
        Err(error @ EvmError::SimulationNotServed { .. }) => {
            assert!(error.is_refusal());
            error.to_string()
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn state_carries_across_calls_and_blocks_and_a_gap_is_filled() {
    let mut first = block(vec![call(Some(C), word(42)), call(Some(C), vec![])]);
    first.state_overrides = overrides(vec![(S, funded()), (C, code(store_and_log()))]);
    let mut later = block(vec![call(Some(C), vec![])]);
    later.block_overrides.number = Some(U256::from(BASE + 3));
    let blocks = simulate(vec![first, later]);

    assert_eq!(blocks.iter().map(|b| b.number).collect::<Vec<_>>(), [BASE + 1, BASE + 2, BASE + 3]);
    assert_eq!(
        blocks.iter().map(|b| b.timestamp).collect::<Vec<_>>(),
        [BASE_TIME + 12, BASE_TIME + 24, BASE_TIME + 36]
    );
    // The first block's parent is the base; a simulated block's hash is unknown.
    assert_eq!(blocks[0].parent_hash, Some(BASE_HASH));
    assert_eq!(blocks[1].parent_hash, None);
    assert!(blocks[1].calls.is_empty() && blocks[1].transactions.is_empty() && blocks[1].gas_used == 0);
    // The store is seen by the next call, and by the next block.
    assert_eq!(blocks[0].calls[0].return_data, word(42));
    assert_eq!(blocks[0].calls[1].return_data, word(42));
    assert_eq!(blocks[2].calls[0].return_data, word(42));
    // The store logged once; the read did not.
    assert_eq!(blocks[0].calls[0].logs.len(), 1);
    assert_eq!(blocks[0].calls[0].logs[0].topics, vec![U256::from(42).to_be_bytes::<32>()]);
    assert!(blocks[0].calls[1].logs.is_empty());
    // Nonces count up from the sender's, one per call, and gas adds up.
    assert_eq!(blocks[0].transactions.iter().map(|t| t.nonce).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(blocks[2].transactions[0].nonce, 2);
    assert_eq!(blocks[0].gas_used, blocks[0].calls.iter().map(|c| c.gas_used).sum::<u64>());
    assert_ne!(blocks[0].receipts_root, myotis_core::trie::EMPTY_TRIE_ROOT);
    assert_eq!(blocks[1].receipts_root, myotis_core::trie::EMPTY_TRIE_ROOT);
}

#[test]
fn the_header_fields_follow_the_overrides_and_otherwise_geths_defaults() {
    let mut first = block(vec![call(Some(BLK), vec![])]);
    first.state_overrides = overrides(vec![(BLK, code(block_fields()))]);
    let mut second = block(vec![call(Some(BLK), vec![])]);
    second.block_overrides = BlockOverrides {
        time: Some(BASE_TIME + 100),
        gas_limit: Some(40_000_000),
        fee_recipient: Some(X),
        prev_randao: Some([0xAB; 32]),
        base_fee_per_gas: Some(U256::from(9)),
        ..BlockOverrides::default()
    };
    let mut third = block(vec![call(Some(BLK), vec![])]);
    third.block_overrides.gas_limit = None;
    let blocks = simulate(vec![first, second, third]);
    let fields = |b: usize| -> Vec<U256> {
        blocks[b].calls[0].return_data.chunks(32).map(U256::from_be_slice).collect()
    };
    // Defaults: the base's gas limit and fee recipient, PREVRANDAO zero, no base fee.
    assert_eq!(
        fields(0),
        [BASE + 1, BASE_TIME + 12, 0, 0, 0, 60_000_000, 1].map(U256::from).iter().enumerate().map(|(i, v)| {
            if i == 2 { U256::from_be_slice(&address_word(COINBASE)) } else { *v }
        }).collect::<Vec<_>>()
    );
    assert_eq!(fields(1)[1], U256::from(BASE_TIME + 100));
    assert_eq!(fields(1)[2], U256::from_be_slice(&address_word(X)));
    assert_eq!(fields(1)[3], U256::from(9));
    assert_eq!(fields(1)[4], U256::from_be_bytes([0xAB; 32]));
    assert_eq!(fields(1)[5], U256::from(40_000_000));
    // The next block inherits the gas limit and the fee recipient, not the
    // base fee or PREVRANDAO.
    assert_eq!(fields(2)[2], U256::from_be_slice(&address_word(X)));
    assert_eq!(fields(2)[3], U256::ZERO);
    assert_eq!(fields(2)[4], U256::ZERO);
    assert_eq!(fields(2)[5], U256::from(40_000_000));
    assert_eq!(blocks[1].fee_recipient, X);
    assert_eq!(blocks[1].base_fee_per_gas, 9);
}

#[test]
fn the_chains_order_and_the_limits_fail_as_geth_fails_them() {
    let ex = executor();
    let blocks = |list: Vec<SimBlock>| SimOptions { blocks: list, ..SimOptions::default() };
    assert_eq!(code_of(run(&ex, blocks(vec![]))), (codes::INVALID_PARAMS, "empty input".into()));
    let numbered = |n: u64| {
        let mut b = block(vec![]);
        b.block_overrides.number = Some(U256::from(n));
        b
    };
    assert_eq!(
        code_of(run(&ex, blocks(vec![numbered(BASE + 2), numbered(BASE + 2)]))),
        (codes::BLOCK_NUMBER_INVALID, format!("block numbers must be in order: {} <= {}", BASE + 2, BASE + 2))
    );
    assert_eq!(code_of(run(&ex, blocks(vec![numbered(BASE + 257)]))), (codes::CLIENT_LIMIT_EXCEEDED, "too many blocks".into()));
    assert_eq!(code_of(run(&ex, blocks(vec![block(vec![]); 257]))), (codes::CLIENT_LIMIT_EXCEEDED, "too many blocks".into()));
    // 256 blocks is the limit itself: served.
    assert_eq!(run(&ex, blocks(vec![block(vec![]); 256])).unwrap().len(), 256);
    let mut late = block(vec![]);
    late.block_overrides.time = Some(BASE_TIME);
    assert_eq!(
        code_of(run(&ex, blocks(vec![late]))),
        (codes::BLOCK_TIMESTAMP_INVALID, format!("block timestamps must be in order: {BASE_TIME} <= {BASE_TIME}"))
    );
    let mut difficult = block(vec![]);
    difficult.block_overrides.difficulty = Some(U256::from(1));
    assert_eq!(
        code_of(run(&ex, blocks(vec![difficult]))),
        (codes::INVALID_PARAMS, format!("block {}: difficulty override is not allowed after the merge", BASE + 1))
    );
    let crowded = block(vec![call(Some(R), vec![]); MAX_SIMULATE_CALLS_PER_BLOCK + 1]);
    assert_eq!(
        code_of(run(&ex, blocks(vec![crowded]))),
        (codes::CLIENT_LIMIT_EXCEEDED, format!("too many calls in block: {} > 5000", MAX_SIMULATE_CALLS_PER_BLOCK + 1))
    );
}

#[test]
fn trace_transfers_logs_every_ether_move_and_a_failed_frame_drops_its_own() {
    let world = || {
        let mut b = block(vec![
            {
                let mut c = call(Some(P), vec![]);
                c.value = U256::from(2);
                c
            },
            call(Some(C), word(5)),
        ]);
        b.state_overrides = overrides(vec![
            (S, funded()),
            (P, code(forwarder())),
            (Q, code(log_then_revert())),
            (C, code(store_and_log())),
        ]);
        b
    };
    let traced = run(&executor(), SimOptions { blocks: vec![world()], trace_transfers: true, ..SimOptions::default() })
        .unwrap();
    let logs = &traced[0].calls[0].logs;
    // S → P (2 wei), then P's LOG0. P → Q's transfer and Q's log went with Q's revert.
    assert_eq!(logs.len(), 2, "{logs:?}");
    assert_eq!(logs[0].address, TRANSFER_LOG_ADDRESS.into_array());
    assert_eq!(logs[0].topics, vec![TRANSFER_TOPIC, Address::from(S).into_word().0, Address::from(P).into_word().0]);
    assert_eq!(U256::from_be_slice(&logs[0].data), U256::from(2));
    assert_eq!((logs[0].log_index, logs[1].log_index), (0, 1));
    assert_eq!(logs[1].address, P);
    // Indices run across the block's calls.
    assert_eq!(traced[0].calls[1].logs[0].log_index, 2);

    let plain = run(&executor(), SimOptions { blocks: vec![world()], ..SimOptions::default() }).unwrap();
    assert_eq!(plain[0].calls[0].logs.len(), 1);
    assert_eq!(plain[0].calls[0].logs[0].address, P);
    assert_eq!(plain[0].calls[1].logs[0].log_index, 1);
    // The receipts hold the EVM's logs only, so the roots agree either way.
    assert_eq!(plain[0].receipts_root, traced[0].receipts_root);
    assert_eq!(plain[0].logs_bloom, traced[0].logs_bloom);
}

#[test]
fn a_revert_and_a_halt_are_results_in_geths_words() {
    let mut b = block(vec![call(Some(R), vec![]), call(Some(Q), vec![])]);
    b.state_overrides = overrides(vec![(R, code(revert_nope())), (Q, code(hex("fe")))]);
    let blocks = simulate(vec![b]);
    let reverted = &blocks[0].calls[0];
    assert!(!reverted.status);
    assert!(reverted.return_data.is_empty(), "a revert's payload is its error's data, not its return data");
    let error = reverted.error.as_ref().unwrap();
    assert_eq!((error.message.as_str(), error.code), ("execution reverted: nope", codes::REVERTED));
    assert_eq!(error.data.as_deref().map(<[u8]>::len), Some(100));
    let halted = &blocks[0].calls[1];
    let error = halted.error.as_ref().unwrap();
    assert_eq!((error.message.as_str(), error.code, error.data.is_none()), ("invalid opcode: INVALID", codes::VM_ERROR, true));
    assert_eq!(halted.gas_used, 1_000_000, "a halt spends the call's whole gas");
}

#[test]
fn a_simulated_blocks_hash_is_refused_and_the_bases_is_served() {
    let reads = |n: u64| {
        let mut b = block(vec![call(Some(C), word(n))]);
        b.state_overrides = overrides(vec![(C, code(blockhash_of()))]);
        b
    };
    // From block N+1, BLOCKHASH(N) is the base's own hash, and N-1 its parent's.
    let blocks = simulate(vec![reads(BASE)]);
    assert_eq!(blocks[0].calls[0].return_data, BASE_HASH.to_vec());
    let blocks = simulate(vec![reads(BASE - 1)]);
    assert_eq!(blocks[0].calls[0].return_data, PARENT_HASH.to_vec());
    // From block N+2, BLOCKHASH(N+1) would be a simulated block's.
    let detail = refused(run(
        &executor(),
        SimOptions { blocks: vec![block(vec![]), reads(BASE + 1)], ..SimOptions::default() },
    ));
    assert!(detail.contains(&format!("BLOCKHASH({})", BASE + 1)), "{detail}");
}

#[test]
fn the_history_contract_serves_the_bases_hash_and_refuses_a_simulated_blocks() {
    let history = Address::from(HISTORY_STORAGE_ADDRESS).into_array();
    let ex = executor_with(&[(history, history_contract(), U256::ZERO)]);
    let get = |n: u64| {
        let mut c = call(Some(history), word(n));
        c.gas = Some(100_000);
        c
    };
    // Block N+1's system call stored the base's hash; N+2 reads it.
    let blocks = run(&ex, SimOptions { blocks: vec![block(vec![]), block(vec![get(BASE)])], ..SimOptions::default() })
        .unwrap();
    assert_eq!(blocks[1].calls[0].return_data, BASE_HASH.to_vec());
    // Block N+2's call stored N+1's, which is unknown: N+3 may not read it.
    let detail = refused(run(
        &ex,
        SimOptions { blocks: vec![block(vec![]), block(vec![]), block(vec![get(BASE + 1)])], ..SimOptions::default() },
    ));
    assert!(detail.contains("EIP-2935"), "{detail}");
    // A state override of the slot replaces the unknown hash with the caller's.
    let mut overridden = block(vec![get(BASE + 1)]);
    let mut slot = AccountOverride::default();
    slot.state_diff.insert(U256::from((BASE + 1) % HISTORY_SERVE_WINDOW), U256::from(7));
    overridden.state_overrides = overrides(vec![(history, slot)]);
    let blocks = run(&ex, SimOptions { blocks: vec![block(vec![]), block(vec![]), overridden], ..SimOptions::default() })
        .unwrap();
    assert_eq!(blocks[2].calls[0].return_data, word(7));
}

#[test]
fn blobbasefee_is_refused_unless_the_override_sets_it() {
    let mut reads = block(vec![call(Some(C), vec![])]);
    reads.state_overrides = overrides(vec![(C, code(blob_base_fee()))]);
    let detail = refused(run(&executor(), SimOptions { blocks: vec![reads.clone()], ..SimOptions::default() }));
    assert!(detail.contains("blobBaseFee"), "{detail}");
    reads.block_overrides.blob_base_fee = Some(U256::from(123));
    let blocks = run(&executor(), SimOptions { blocks: vec![reads], ..SimOptions::default() }).unwrap();
    assert_eq!(blocks[0].calls[0].return_data, word(123));
}

#[test]
fn what_this_node_does_not_model_is_refused() {
    // A precompile's address overridden.
    let mut b = block(vec![]);
    b.state_overrides = overrides(vec![([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], code(hex("00")))]);
    assert!(refused(run(&executor(), SimOptions { blocks: vec![b], ..SimOptions::default() })).contains("precompile"));
    // `state` and `stateDiff` for one account: geth's error.
    let mut both = AccountOverride { state: Some(Default::default()), ..Default::default() };
    both.state_diff.insert(U256::ZERO, U256::from(1));
    let mut b = block(vec![]);
    b.state_overrides = overrides(vec![(C, both)]);
    let (err_code, message) = code_of(run(&executor(), SimOptions { blocks: vec![b], ..SimOptions::default() }));
    assert_eq!(err_code, codes::INVALID_PARAMS);
    assert!(message.ends_with("has both 'state' and 'stateDiff'"), "{message}");
    // An Amsterdam block (sepolia).
    let sepolia = SimBase { ctx: ctx(11_155_111, 9_000_000, SEPOLIA_AMSTERDAM_TIME - 100), ..base() };
    let mut amsterdam = block(vec![]);
    amsterdam.block_overrides.time = Some(SEPOLIA_AMSTERDAM_TIME);
    // The block before the fork is served.
    assert!(executor().simulate(&sepolia, &SimOptions { blocks: vec![block(vec![])], ..SimOptions::default() }).is_ok());
    let detail = match executor().simulate(&sepolia, &SimOptions { blocks: vec![amsterdam], ..SimOptions::default() }) {
        Err(error @ EvmError::SimulationNotServed { .. }) => error.to_string(),
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert!(detail.contains("Amsterdam"), "{detail}");
}

#[test]
fn validation_checks_nonces_fees_and_funds_and_computes_the_base_fee() {
    let validating = |blocks: Vec<SimBlock>| SimOptions { blocks, validation: true, ..SimOptions::default() };
    let fee = |mut c: TxRequest, cap: u128| {
        c.fees = Fees::DynamicFee { max_fee_per_gas: cap, max_priority_fee_per_gas: 0 };
        c
    };
    // The base used half its 60M limit: the base fee stays at 7.
    let mut first = block(vec![fee(call(Some(BLK), vec![]), 7)]);
    first.state_overrides = overrides(vec![(S, funded()), (BLK, code(block_fields()))]);
    let blocks = run(&executor(), validating(vec![first.clone()])).unwrap();
    assert_eq!(blocks[0].base_fee_per_gas, 7);
    assert_eq!(U256::from_be_slice(&blocks[0].calls[0].return_data[96..128]), U256::from(7));

    // No fee at all under validation is below the base fee.
    let mut feeless = first.clone();
    feeless.calls = vec![call(Some(BLK), vec![])];
    let (err_code, message) = code_of(run(&executor(), validating(vec![feeless])));
    assert_eq!(err_code, codes::BASE_FEE_TOO_LOW);
    assert!(message.starts_with("max fee per gas less than block base fee: address 0x"), "{message}");
    assert!(message.ends_with("maxFeePerGas: 0, baseFee: 7"), "{message}");

    // A nonce ahead of the sender's, and one behind it.
    let mut ahead = first.clone();
    ahead.calls[0].nonce = Some(5);
    let (err_code, message) = code_of(run(&executor(), validating(vec![ahead])));
    assert_eq!(err_code, codes::NONCE_TOO_HIGH);
    assert!(message.ends_with("tx: 5 state: 0"), "{message}");
    let mut behind = first.clone();
    behind.calls.push(fee(call(Some(BLK), vec![]), 7));
    behind.calls[1].nonce = Some(0);
    let (err_code, message) = code_of(run(&executor(), validating(vec![behind])));
    assert_eq!(err_code, codes::NONCE_TOO_LOW);
    assert!(message.ends_with("tx: 0 state: 1"), "{message}");

    // A sender without the funds.
    let mut poor = first;
    poor.state_overrides = overrides(vec![(BLK, code(block_fields()))]);
    let (err_code, message) = code_of(run(&executor(), validating(vec![poor])));
    assert_eq!(err_code, codes::INSUFFICIENT_FUNDS);
    assert!(message.contains("have 0 want 7000000"), "{message}");

    // Without validation the nonce is not checked.
    let mut loose = block(vec![call(Some(BLK), vec![])]);
    loose.calls[0].nonce = Some(5);
    loose.state_overrides = overrides(vec![(BLK, code(block_fields()))]);
    let blocks = run(&executor(), SimOptions { blocks: vec![loose], ..SimOptions::default() }).unwrap();
    assert_eq!(blocks[0].transactions[0].nonce, 5, "the block's transaction carries the nonce the caller named");
}

#[test]
fn the_budget_caps_calls_and_the_block_gas_limit_bounds_them() {
    // A call without gas gets the block's remaining gas, capped to the budget.
    let mut b = block(vec![call(Some(C), vec![]), call(Some(R), vec![])]);
    b.calls[0].gas = None;
    b.calls[1].gas = None;
    b.state_overrides = overrides(vec![(C, code(spinner()))]);
    let (code, message) = match run(&executor(), SimOptions { blocks: vec![b.clone()], ..SimOptions::default() }) {
        Err(EvmError::Simulation { code, message }) => (code, message),
        other => panic!("expected the second call to find no budget left, got {other:?}"),
    };
    assert_eq!((code, message.as_str()), (codes::INTRINSIC_GAS, "intrinsic gas too low: have 0, want 21000"));
    b.calls.pop();
    let blocks = run(&executor(), SimOptions { blocks: vec![b], ..SimOptions::default() }).unwrap();
    let spun = &blocks[0].calls[0];
    assert_eq!(spun.gas_used, SIMULATE_GAS_BUDGET);
    assert_eq!(blocks[0].transactions[0].gas, SIMULATE_GAS_BUDGET);
    assert_eq!(
        spun.error.as_ref().unwrap().message,
        "out of gas (gas limit was capped by the RPC server's global gas cap)"
    );

    // More gas than the block has left.
    let mut tight = block(vec![call(Some(R), vec![])]);
    tight.block_overrides.gas_limit = Some(100_000);
    tight.calls[0].gas = Some(200_000);
    assert_eq!(
        code_of(run(&executor(), SimOptions { blocks: vec![tight], ..SimOptions::default() })),
        (codes::BLOCK_GAS_LIMIT_REACHED, "block gas limit reached: remaining: 100000, required: 200000".into())
    );
}

#[test]
fn withdrawals_credit_balances_and_a_creation_gets_its_address() {
    let mut first = block(vec![{
        let mut c = call(None, hex("60006000a0" /* LOG0 */));
        c.value = U256::from(3);
        c
    }]);
    first.state_overrides = overrides(vec![(S, funded())]);
    first.block_overrides.withdrawals =
        Some(vec![Withdrawal { index: 1, validator_index: 2, address: R, amount: 5 }]);
    let mut second = block(vec![call(Some(BAL), address_word(R))]);
    second.state_overrides = overrides(vec![(BAL, code(balance_of()))]);
    let blocks = run(&executor(), SimOptions { blocks: vec![first, second], trace_transfers: true, ..SimOptions::default() })
        .unwrap();
    assert_eq!(blocks[1].calls[0].return_data, word(5 * GWEI));
    assert_ne!(blocks[0].withdrawals_root, Some(myotis_core::trie::EMPTY_TRIE_ROOT));
    assert_eq!(blocks[1].withdrawals_root, Some(myotis_core::trie::EMPTY_TRIE_ROOT));
    // The creation's transfer names the address the contract got.
    let created = Address::from(S).create(0);
    let transfer = &blocks[0].calls[0].logs[0];
    assert_eq!(transfer.topics[2], created.into_word().0);
    assert_eq!(blocks[0].transactions[0].to, None);
}

#[test]
fn gnosis_credits_the_base_fee_to_its_collector_and_refuses_withdrawals() {
    let gnosis = SimBase { ctx: ctx(100, 45_000_000, crate::fork::GNOSIS_OSAKA_TIME + 1_000), ..base() };
    let mut first = block(vec![{
        let mut c = call(Some(R), vec![]);
        c.fees = Fees::DynamicFee { max_fee_per_gas: 2_000_000_000, max_priority_fee_per_gas: 0 };
        c
    }]);
    first.block_overrides.base_fee_per_gas = Some(U256::from(1_000_000_000u64));
    first.state_overrides = overrides(vec![(S, funded())]);
    let mut second = block(vec![call(Some(BAL), address_word(GNOSIS_FEE_COLLECTOR.into_array()))]);
    second.state_overrides = overrides(vec![(BAL, code(balance_of()))]);
    let blocks = executor().simulate(&gnosis, &SimOptions { blocks: vec![first, second], ..SimOptions::default() }).unwrap();
    assert_eq!(blocks[1].calls[0].return_data, word(21_000 * 1_000_000_000));

    let mut withdrawing = block(vec![]);
    withdrawing.block_overrides.withdrawals =
        Some(vec![Withdrawal { index: 0, validator_index: 0, address: R, amount: 1 }]);
    match executor().simulate(&gnosis, &SimOptions { blocks: vec![withdrawing], ..SimOptions::default() }) {
        Err(error @ EvmError::SimulationNotServed { .. }) => assert!(error.to_string().contains("Gnosis")),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_block_transaction_is_geths_unsigned_transaction() {
    // The type geth picks for each kind of request.
    let mut tx = call(Some(R), vec![]);
    assert_eq!(block_tx_type(&tx), TYPE_DYNAMIC_FEE);
    tx.fees = Fees::Legacy { gas_price: 5 };
    assert_eq!(block_tx_type(&tx), TYPE_LEGACY);
    tx.access_list = Some(vec![]);
    assert_eq!(block_tx_type(&tx), TYPE_ACCESS_LIST);
    tx.tx_type = Some(TYPE_LEGACY);
    assert_eq!(block_tx_type(&tx), TYPE_LEGACY, "an explicit type is the caller's");
    // A gas price wins over an authorization list, as in geth.
    let mut priced = call(Some(R), vec![]);
    priced.fees = Fees::Legacy { gas_price: 5 };
    priced.authorization_list = Some(vec![]);
    assert_eq!(block_tx_type(&priced), TYPE_LEGACY);
    priced.fees = Fees::None;
    assert_eq!(block_tx_type(&priced), TYPE_SET_CODE);
    // A dynamic-fee transaction's effective price, and a legacy one without a chain id.
    let mut dynamic = call(Some(R), vec![]);
    dynamic.fees = Fees::DynamicFee { max_fee_per_gas: 100, max_priority_fee_per_gas: 3 };
    let t = block_transaction(&dynamic, 4, 21_000, 1, 10);
    assert_eq!((t.gas_price, t.chain_id, t.max_fee_per_gas), (13, Some(1), Some(100)));
    assert_eq!(t.hash, keccak256(&encode::transaction(&t)));
    let mut legacy = call(Some(R), vec![]);
    legacy.fees = Fees::Legacy { gas_price: 5 };
    let t = block_transaction(&legacy, 0, 21_000, 1, 10);
    assert_eq!((t.gas_price, t.chain_id, t.access_list.is_none()), (5, None, true));
}
