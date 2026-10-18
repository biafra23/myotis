//! `BLOCKHASH` from verified data (#664): the call header's `parentHash` for
//! N-1, the EIP-2935 history contract's proven storage from Prague on, a
//! proven header walk where the contract holds nothing, and zero outside the
//! opcode's window. Nothing unproven is ever served; what cannot be proven
//! fails the call.

use super::*;
use crate::database::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use crate::fork::{GNOSIS_CANCUN_TIME, GNOSIS_PRAGUE_TIME, PRAGUE_TIME, SEPOLIA_CANCUN_TIME, SEPOLIA_PRAGUE_TIME};

const N: u64 = 22_500_000;

/// A contract returning `blockhash(number - d)` for each `d`, one word each.
fn blockhash_reader(depths: &[u16]) -> Vec<u8> {
    let mut code = Vec::new();
    for (i, d) in depths.iter().enumerate() {
        let [hi, lo] = d.to_be_bytes();
        // NUMBER PUSH2 d SWAP1 SUB BLOCKHASH PUSH1 32*i MSTORE
        code.extend_from_slice(&[0x43, 0x61, hi, lo, 0x90, 0x03, 0x40, 0x60, (32 * i) as u8, 0x52]);
    }
    // PUSH1 len PUSH1 0 RETURN
    code.extend_from_slice(&[0x60, (32 * depths.len()) as u8, 0x60, 0x00, 0xf3]);
    code
}

/// A distinct, recognisable hash for block `n`.
fn hash_of(n: u64) -> [u8; 32] {
    let mut h = [0xb0u8; 32];
    h[24..].copy_from_slice(&n.to_be_bytes());
    h
}

fn history_slot(n: u64) -> [u8; 32] {
    U256::from(n % HISTORY_SERVE_WINDOW).to_be_bytes::<32>()
}

/// A world with the reader at TARGET, the history contract holding `ring`
/// (block numbers whose hash its storage holds), and the header walk serving
/// `walk`.
fn world(depths: &[u16], ring: &[u64], walk: &[u64]) -> FixtureSnapStateOracle {
    let mut fx = FixtureSnapStateOracle::new();
    let ch = fx.with_bytecode(blockhash_reader(depths));
    let mut fx = fx
        .with_account(ROOT, TARGET, OracleAccount { nonce: 1, balance: U256::ZERO, code_hash: ch, storage_root: [0x9; 32] })
        .with_account(
            ROOT,
            HISTORY_STORAGE_ADDRESS,
            OracleAccount { nonce: 1, balance: U256::ZERO, code_hash: [0x77; 32], storage_root: [0x8; 32] },
        );
    for n in ring {
        fx = fx.with_storage(ROOT, HISTORY_STORAGE_ADDRESS, history_slot(*n), U256::from_be_bytes(hash_of(*n)));
    }
    for n in walk {
        fx = fx.with_block_hash(*n, hash_of(*n));
    }
    fx
}

fn exec_over(oracle: impl SnapStateOracle + 'static) -> EvmExecutor {
    EvmExecutor::new(Arc::new(oracle), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache))
}

fn words(out: &[u8]) -> Vec<[u8; 32]> {
    out.chunks(32).map(|w| w.try_into().unwrap()).collect()
}

/// A context for block N on `chain_id` at `timestamp`, with the PARENT hash.
fn on_chain(chain_id: u64, timestamp: u64) -> BlockContext {
    let mut c = ctx(N, timestamp);
    c.chain_id = chain_id;
    c
}

#[test]
fn recent_hashes_come_from_the_parent_hash_and_the_history_contract() {
    let exec = exec_over(world(&[1, 2, 200, 256], &[N - 2, N - 200, N - 256], &[]));
    let out = exec.call_view(TARGET, &[], &on_chain(1, PRAGUE_TIME + 1)).unwrap();
    assert_eq!(words(&out), vec![PARENT, hash_of(N - 2), hash_of(N - 200), hash_of(N - 256)]);
}

#[test]
fn the_current_block_and_one_past_the_window_are_zero() {
    // Hashes in the ring and the walk for both: zero comes from the opcode's
    // window, not from a missing value.
    let exec = exec_over(world(&[0, 257], &[N - 257], &[N - 257]));
    let out = exec.call_view(TARGET, &[], &on_chain(1, PRAGUE_TIME + 1)).unwrap();
    assert_eq!(words(&out), vec![[0u8; 32], [0u8; 32]]);
}

#[test]
fn every_network_reads_the_history_contract_from_prague_on() {
    // The walk would serve a different value: the answer shows which source ran.
    for (chain, prague) in [(1, PRAGUE_TIME), (11_155_111, SEPOLIA_PRAGUE_TIME), (100, GNOSIS_PRAGUE_TIME)] {
        let mut fx = world(&[100], &[N - 100], &[]);
        fx = fx.with_block_hash(N - 100, [0xee; 32]);
        let out = exec_over(fx).call_view(TARGET, &[], &on_chain(chain, prague + 1)).unwrap();
        assert_eq!(words(&out), vec![hash_of(N - 100)], "chain {chain}");
    }
}

#[test]
fn before_prague_every_network_walks_the_header_chain() {
    // A value in the history slot that is not the block's hash: a pre-Prague
    // context must not read the contract at all.
    for (chain, cancun) in [(1, CANCUN_TIME), (11_155_111, SEPOLIA_CANCUN_TIME), (100, GNOSIS_CANCUN_TIME)] {
        let fx = world(&[1, 100], &[], &[N - 100]).with_storage(
            ROOT,
            HISTORY_STORAGE_ADDRESS,
            history_slot(N - 100),
            U256::from(0xdeadu64),
        );
        let out = exec_over(fx).call_view(TARGET, &[], &on_chain(chain, cancun + 1)).unwrap();
        assert_eq!(words(&out), vec![PARENT, hash_of(N - 100)], "chain {chain}");
    }
}

#[test]
fn a_block_the_ring_never_held_is_walked() {
    // Just after the fork: the ring holds the fork's parent onward, and an
    // older block in the window reads zero from the contract.
    let exec = exec_over(world(&[10, 200], &[N - 10], &[N - 200]));
    let out = exec.call_view(TARGET, &[], &on_chain(1, PRAGUE_TIME + 1)).unwrap();
    assert_eq!(words(&out), vec![hash_of(N - 10), hash_of(N - 200)]);
}

#[test]
fn a_hash_nothing_proves_fails_the_call_and_is_never_zero() {
    let exec = exec_over(world(&[200], &[], &[]));
    let err = exec.call_view(TARGET, &[], &on_chain(1, PRAGUE_TIME + 1)).unwrap_err();
    assert_eq!(err, EvmError::Oracle(OracleError::BlockHashUnavailable { number: N - 200 }));
}

#[test]
fn without_a_parent_hash_the_parent_and_a_walk_are_refused() {
    let mut c = on_chain(1, PRAGUE_TIME + 1);
    c.parent_hash = None;
    let exec = exec_over(world(&[1], &[], &[N - 1]));
    assert_eq!(
        exec.call_view(TARGET, &[], &c).unwrap_err(),
        EvmError::Oracle(OracleError::BlockHashUnsupported { number: N - 1 })
    );
    let exec = exec_over(world(&[100], &[], &[N - 100]));
    assert_eq!(
        exec.call_view(TARGET, &[], &c).unwrap_err(),
        EvmError::Oracle(OracleError::BlockHashUnsupported { number: N - 100 })
    );
    // The ring needs no anchor: it is proven against the state root.
    let exec = exec_over(world(&[100], &[N - 100], &[]));
    assert_eq!(words(&exec.call_view(TARGET, &[], &c).unwrap()), vec![hash_of(N - 100)]);
}

/// A world whose every proof of the history contract's storage fails.
struct ForgedHistory(FixtureSnapStateOracle);

impl SnapStateOracle for ForgedHistory {
    fn fetch_account(&self, r: &[u8; 32], a: [u8; 20]) -> Result<Option<OracleAccount>, OracleError> {
        self.0.fetch_account(r, a)
    }
    fn fetch_storage(&self, r: &[u8; 32], a: [u8; 20], s: U256) -> Result<U256, OracleError> {
        if a == HISTORY_STORAGE_ADDRESS {
            return Err(OracleError::InvalidProof { state_root: *r, address: a, detail: "forged slot".into() });
        }
        self.0.fetch_storage(r, a, s)
    }
    fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
        self.0.fetch_bytecode(h)
    }
    fn fetch_block_hash(&self, anchor_number: u64, anchor_hash: &[u8; 32], number: u64) -> Result<[u8; 32], OracleError> {
        self.0.fetch_block_hash(anchor_number, anchor_hash, number)
    }
}

#[test]
fn a_history_value_that_fails_its_proof_fails_the_call() {
    // The walk could answer; a failed proof must not fall back to it either.
    let exec = exec_over(ForgedHistory(world(&[100], &[N - 100], &[N - 100])));
    let err = exec.call_view(TARGET, &[], &on_chain(1, PRAGUE_TIME + 1)).unwrap_err();
    assert!(matches!(err, EvmError::Oracle(OracleError::InvalidProof { address, .. }) if address == HISTORY_STORAGE_ADDRESS), "{err:?}");
}

#[test]
fn an_override_of_the_history_contract_does_not_change_blockhash() {
    let exec = exec_over(world(&[100], &[N - 100], &[]));
    let mut overrides = StateOverrides::new();
    overrides.insert(
        HISTORY_STORAGE_ADDRESS,
        crate::overrides::AccountOverride {
            state_diff: std::collections::HashMap::from([(U256::from((N - 100) % HISTORY_SERVE_WINDOW), U256::from(1u64))]),
            ..Default::default()
        },
    );
    let out = exec
        .call_view_overridden([0x42; 20], TARGET, &[], U256::ZERO, &on_chain(1, PRAGUE_TIME + 1), overrides)
        .unwrap();
    assert_eq!(words(&out), vec![hash_of(N - 100)]);
}

#[test]
fn an_estimate_of_a_transaction_reading_blockhash_answers() {
    let exec = exec_over(world(&[1, 100], &[N - 100], &[]));
    let estimate = exec.estimate_gas([0x42; 20], TARGET, &[], U256::ZERO, &on_chain(1, PRAGUE_TIME + 1)).unwrap();
    assert!(estimate > 21_000, "{estimate}");
}

#[test]
fn the_history_slot_comes_in_a_wave_and_is_cached_by_root() {
    let oracle = Arc::new(WaveFilling { inner: world(&[100], &[N - 100], &[]), ..Default::default() });
    let exec = EvmExecutor::new(
        Arc::clone(&oracle) as Arc<dyn SnapStateOracle>,
        Arc::new(crate::cache::InMemoryStateProofCache::new(1024)),
        Arc::new(crate::cache::InMemoryBytecodeCache::default()),
    );
    let c = on_chain(1, PRAGUE_TIME + 1);
    assert_eq!(words(&exec.call_view(TARGET, &[], &c).unwrap()), vec![hash_of(N - 100)]);
    assert_eq!(oracle.serial_storage.load(std::sync::atomic::Ordering::SeqCst), 0, "the slot was read in a wave");
    let waves = oracle.waves();
    // A second call at the same root reads the cached, proven slot.
    assert_eq!(words(&exec.call_view(TARGET, &[], &c).unwrap()), vec![hash_of(N - 100)]);
    assert_eq!(oracle.waves(), waves, "a warm call makes no wave");
    assert_eq!(oracle.serial_storage.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn a_warm_call_that_walks_is_its_one_discovery_pass() {
    // Before Prague: the walk runs in the discovery pass itself, so a call
    // whose state is cached needs no placeholder and no second run.
    let oracle = Arc::new(WaveFilling { inner: world(&[1, 100], &[], &[N - 100]), ..Default::default() });
    let exec = EvmExecutor::new(
        Arc::clone(&oracle) as Arc<dyn SnapStateOracle>,
        Arc::new(crate::cache::InMemoryStateProofCache::new(1024)),
        Arc::new(crate::cache::InMemoryBytecodeCache::default()),
    );
    let c = on_chain(1, CANCUN_TIME + 1);
    assert_eq!(words(&exec.call_view(TARGET, &[], &c).unwrap()), vec![PARENT, hash_of(N - 100)]);
    let runs = exec.cost().evm_runs;
    assert_eq!(words(&exec.call_view(TARGET, &[], &c).unwrap()), vec![PARENT, hash_of(N - 100)]);
    assert_eq!(exec.cost().evm_runs - runs, 1, "the warm call's discovery pass was its answer");
}

#[test]
fn an_unsupported_blockhash_is_a_refusal_not_a_retry() {
    // No anchor to walk from can never improve with a retry.
    let mut c = on_chain(1, CANCUN_TIME + 1);
    c.parent_hash = None;
    let err = exec_over(world(&[100], &[], &[N - 100])).call_view(TARGET, &[], &c).unwrap_err();
    assert!(err.is_refusal(), "{err:?}");
    // A walk no peer could serve is retryable.
    let err = exec_over(world(&[100], &[], &[])).call_view(TARGET, &[], &on_chain(1, CANCUN_TIME + 1)).unwrap_err();
    assert!(!err.is_refusal(), "{err:?}");
}
