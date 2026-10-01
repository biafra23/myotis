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
