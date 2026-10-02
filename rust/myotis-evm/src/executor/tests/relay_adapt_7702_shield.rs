//! Replays the mainnet RelayAdapt7702 shield (#509 stage 2, part 3): the
//! "shield ETH" the RAILGUN wallet sends through a fresh EIP-7702 account.
//! `rust/myotis-net/examples/record_shield_fixture.rs` recorded it, with
//! throwaway keys, from the live engine's verified mainnet state
//! (`rust/testdata/evm/relayadapt7702-shield.json`).
//!
//! The replay runs exactly what the recording ran ([`railgun::measure`]),
//! against the recorded world only: a read the recording did not make fails
//! the run, so nothing here passes against state nobody recorded. Set
//! `MYOTIS_SHIELD_FIXTURE` to replay another recording, such as a fresh one
//! before it is committed.

use std::sync::OnceLock;

use super::*;
use crate::fixture::relay_adapt_7702::{self as railgun, ShieldAccounts, ShieldMeasurements, ShieldRequests};
use crate::fixture::EvmFixture;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/evm/relayadapt7702-shield.json");

/// What the recorder measured live, and what the recorded world measures now.
struct Replay {
    recorded: ShieldMeasurements,
    replayed: ShieldMeasurements,
}

/// Measured once for every test here: the bisections take a few seconds.
fn replay() -> &'static Replay {
    static REPLAY: OnceLock<Replay> = OnceLock::new();
    REPLAY.get_or_init(|| {
        let path = std::env::var("MYOTIS_SHIELD_FIXTURE").unwrap_or_else(|_| FIXTURE.to_string());
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let fixture = EvmFixture::from_json(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
        let exec = EvmExecutor::new(Arc::new(fixture.oracle()), Arc::new(NoopStateProofCache), Arc::new(NoopBytecodeCache));
        let replayed = railgun::measure(
            &exec,
            &fixture.block,
            &fixture.overrides(),
            &ShieldRequests::from_fixture(&fixture).unwrap(),
            &ShieldAccounts::from_fixture(&fixture).unwrap(),
        )
        .unwrap_or_else(|e| panic!("{path} does not replay: {e}"));
        Replay { recorded: ShieldMeasurements::from_fixture(&fixture).unwrap(), replayed }
    })
}

/// The recorded world answers everything exactly as the live engine did
/// when it recorded: every estimate, every lowest limit, every event.
#[test]
fn the_recorded_world_replays_what_the_live_engine_measured() {
    let r = replay();
    assert_eq!(r.replayed, r.recorded);
}

/// #509's acceptance: the estimate is at least what the transaction uses,
/// at the estimate the whole shield runs (the wrap, RAILGUN's `Shield`), and
/// it is the search's answer: the lowest limit that runs, within geth's 1.5%,
/// plus the buffer.
#[test]
fn the_estimate_is_a_limit_the_whole_shield_runs_under() {
    let m = &replay().replayed;
    assert!(m.events_at_estimate.complete(), "at the estimate the whole shield must run: {:?}", m.events_at_estimate);
    assert!(m.gas_used_at_estimate <= m.estimate, "the shield uses {}, above its estimate {}", m.gas_used_at_estimate, m.estimate);
    let (lower, upper) = (with_estimate_buffer(m.lowest_limit), with_estimate_buffer(m.lowest_limit * 10_153 / 10_000 + 1));
    assert!(
        (lower..=upper).contains(&m.estimate),
        "estimate {} is not the searched answer over the lowest limit {} ({lower}..={upper})",
        m.estimate,
        m.lowest_limit
    );
}

/// #509 itself: without its authorization list the request calls an account
/// with no code, and that answer is a limit the real shield cannot run under.
#[test]
fn without_its_authorization_the_estimate_is_509s_failure() {
    let m = &replay().replayed;
    assert!(m.estimate_without_authorization < 100_000, "a call to a codeless account: {}", m.estimate_without_authorization);
    assert!(!m.runs_at_estimate_without_authorization, "the shield must not run at #509's answer");
}

/// The #519 review's question, at the shield's real depth. A broadcaster's
/// multicall (`requireSuccess = false`) swallows a failed call: far below what
/// the shield needs, the transaction still succeeds, with the shield
/// swallowed. The estimate never goes below the ceiling run's draw, so at it
/// the shield itself runs.
#[test]
fn the_estimate_keeps_the_shield_when_its_failure_would_be_swallowed() {
    let m = &replay().replayed;
    let at_estimate = m.require_success_false_events_at_estimate;
    assert!(at_estimate.complete(), "at the estimate the shield itself must run: {at_estimate:?}");
    let at_lowest = m.require_success_false_events_at_lowest_limit;
    assert!(
        !at_lowest.shielded && at_lowest.call_errors > 0,
        "at the lowest limit that succeeds, {}, the shield is swallowed: {at_lowest:?}",
        m.require_success_false_lowest_limit
    );
    assert!(m.require_success_false_lowest_limit < m.require_success_false_drawn);
}

/// The retry from the account the failed first attempt left delegated, a
/// plain call, completes at its estimate. The Java engine serves it too, and
/// its `RelayAdapt7702ShieldFixtureTest` must answer the same number.
#[test]
fn the_retry_from_the_delegated_account_completes_at_its_estimate() {
    let m = &replay().replayed;
    assert!(m.retry_events_at_estimate.complete(), "{:?}", m.retry_events_at_estimate);
}

/// The recorded world behind an oracle whose prefetch waves really fill the
/// caches, as the network oracle's do: serving what the recording holds and
/// skipping what it does not (a discovery pass can ask for state the real run
/// never reads). It counts the reads the EVM waits on one at a time (#532).
struct WaveServing {
    inner: crate::fixture::ReplayOracle,
    serial: std::sync::atomic::AtomicUsize,
    waves: std::sync::atomic::AtomicUsize,
    fill: bool,
}

impl crate::oracle::SnapStateOracle for WaveServing {
    fn fetch_account(&self, r: &[u8; 32], a: [u8; 20]) -> Result<Option<crate::oracle::OracleAccount>, crate::oracle::OracleError> {
        self.serial.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.fetch_account(r, a)
    }
    fn fetch_storage(&self, r: &[u8; 32], a: [u8; 20], s: U256) -> Result<U256, crate::oracle::OracleError> {
        self.serial.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.fetch_storage(r, a, s)
    }
    fn fetch_bytecode(&self, h: &[u8; 32]) -> Result<Vec<u8>, crate::oracle::OracleError> {
        self.serial.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.fetch_bytecode(h)
    }
    fn prefetch_batch(
        &self,
        root: &[u8; 32],
        accounts: &[([u8; 20], Vec<U256>)],
        code: &[[u8; 32]],
        ps: &dyn crate::cache::StateProofCache,
        cs: &dyn crate::cache::BytecodeCache,
    ) {
        if !self.fill {
            return;
        }
        self.waves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for (addr, slots) in accounts {
            if let Ok(account) = self.inner.fetch_account(root, *addr) {
                ps.put_account(root, addr, account);
            }
            for slot in slots {
                if let Ok(value) = self.inner.fetch_storage(root, *addr, *slot) {
                    ps.put_storage(root, addr, slot, value);
                }
            }
        }
        for hash in code {
            if let Ok(bytes) = self.inner.fetch_bytecode(hash) {
                cs.put(hash, Bytes::from(bytes));
            }
        }
    }
}

/// An executor over the recorded world behind [`WaveServing`] (filling waves
/// or no-op ones) and real caches, with the fixture's shield requests.
fn wave_world(fill: bool) -> (Arc<WaveServing>, EvmExecutor, EvmFixture, ShieldRequests) {
    let path = std::env::var("MYOTIS_SHIELD_FIXTURE").unwrap_or_else(|_| FIXTURE.to_string());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let fixture = EvmFixture::from_json(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    let oracle = Arc::new(WaveServing { inner: fixture.oracle(), serial: Default::default(), waves: Default::default(), fill });
    let exec = EvmExecutor::new(
        Arc::clone(&oracle) as Arc<dyn crate::oracle::SnapStateOracle>,
        Arc::new(crate::cache::InMemoryStateProofCache::new(4096)),
        Arc::new(crate::cache::InMemoryBytecodeCache::default()),
    );
    let requests = ShieldRequests::from_fixture(&fixture).unwrap();
    (oracle, exec, fixture, requests)
}

fn serial(oracle: &WaveServing) -> usize {
    oracle.serial.load(std::sync::atomic::Ordering::SeqCst)
}

/// #532: estimating the shield took 4–33 s. Its run at the ceiling was a
/// single real run, which made each of the shield's reads (57 in this world)
/// one round-trip at a time. Through the convergence loop, with waves that
/// follow each fetched account to its code and a discovery cap deep enough
/// for the shield's chain of contracts, every read goes out in a wave.
#[test]
fn the_shield_estimate_reads_its_state_in_waves() {
    let (oracle, exec, fixture, requests) = wave_world(true);
    let estimate = exec.estimate_tx(&requests.shield, &fixture.block, fixture.overrides()).unwrap();
    assert_eq!(serial(&oracle), 0, "every read of the estimate in a wave");
    assert!(oracle.waves.load(std::sync::atomic::Ordering::SeqCst) > 0);
    // Waves change what the estimate costs, never what it answers.
    assert_eq!(estimate, replay().recorded.estimate);
    // Without waves the same world is read one by one: the counts above are
    // the change, not the world.
    let (serial_world, exec, fixture, requests) = wave_world(false);
    exec.estimate_tx(&requests.shield, &fixture.block, fixture.overrides()).unwrap();
    assert!(serial(&serial_world) > 50, "{}", serial(&serial_world));
}

/// The same for a wallet's `eth_call` of the shield: all but the target's
/// own account and code, which the loop reads before its first pass, come in
/// waves. And the estimate right after it, as a wallet simulates and then
/// estimates, has nothing left to read one by one (#532 proposal 5).
#[test]
fn the_shield_call_reads_its_state_in_waves_and_leaves_the_estimate_nothing() {
    let (oracle, exec, fixture, requests) = wave_world(true);
    exec.call_tx(&requests.shield, &fixture.block, fixture.overrides()).unwrap();
    assert!(serial(&oracle) <= 2, "{}", serial(&oracle));
    let after_call = serial(&oracle);
    exec.estimate_tx(&requests.shield, &fixture.block, fixture.overrides()).unwrap();
    assert_eq!(serial(&oracle), after_call, "the estimate after the call reads nothing one by one");
}
