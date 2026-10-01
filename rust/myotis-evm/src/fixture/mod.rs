//! Recorded worlds for replay tests — test tooling behind the `fixture`
//! feature, never in a default build.
//!
//! A recorder wraps a verified oracle in a [`RecordingOracle`], runs a
//! transaction through the executor, and keeps every account, slot and
//! bytecode the EVM read. An [`EvmFixture`] holds that world together with the
//! block it was read at and the request as a wallet sent it, and round-trips
//! through JSON. Its [`EvmFixture::oracle`] serves exactly the recorded world
//! and fails any read the recording did not make, so a replay never runs
//! against state nobody recorded.
//!
//! The mainnet RelayAdapt7702 shield (#509,
//! `rust/testdata/evm/relayadapt7702-shield.json`) is the first fixture:
//! `rust/myotis-net/examples/record_shield_fixture.rs` records it from the live
//! engine, and the executor's replay tests run it.

mod recording;
pub mod relay_adapt_7702;
mod world;

pub use recording::{RecordedWorld, RecordingOracle};
pub use world::{request_from_json, request_to_json, EvmFixture, ReplayOracle, FIXTURE_FORMAT};

use revm::context::result::ExecutionResult;

use crate::block::BlockContext;
use crate::error::EvmError;
use crate::executor::{EvmExecutor, VIEW_CALL_GAS};
use crate::overrides::StateOverrides;
use crate::tx::TxRequest;

/// Whether `tx` runs at `gas`, executed as a block would include it: the
/// estimator's own probe question (`succeeds_with`). A revert, a halt, or a
/// limit below the intrinsic cost or the EIP-7623 floor is "no"; anything
/// else that is not a success, such as state nobody recorded, is an error.
pub fn runs_at(
    exec: &EvmExecutor,
    tx: &TxRequest,
    gas: u64,
    ctx: &BlockContext,
    overrides: &StateOverrides,
) -> Result<Option<ExecutionResult>, String> {
    let mut limited = tx.clone();
    limited.gas = Some(gas);
    match exec.run_tx(&limited, gas, ctx, overrides.clone()) {
        Ok(result @ ExecutionResult::Success { .. }) => Ok(Some(result)),
        Ok(_) | Err(EvmError::IntrinsicGasTooLow { .. } | EvmError::FloorDataGasTooLow { .. }) => Ok(None),
        Err(e) => Err(format!("not an answer at gas {gas}: {e}")),
    }
}

/// The lowest gas limit at which `tx` runs ([`runs_at`]), found exactly by
/// bisecting between zero and the executor's budget, for a transaction
/// monotone in its limit. One bisection for the recorder, the replay and the
/// executor's own tests, so a replay reads exactly what the recording read.
pub fn lowest_limit_that_runs(
    exec: &EvmExecutor,
    tx: &TxRequest,
    ctx: &BlockContext,
    overrides: &StateOverrides,
) -> Result<u64, String> {
    let runs = |gas: u64| runs_at(exec, tx, gas, ctx, overrides).map(|r| r.is_some());
    let (mut fails, mut works) = (0u64, VIEW_CALL_GAS);
    if !runs(works)? {
        return Err("the transaction does not run at the budget".into());
    }
    while fails + 1 < works {
        let mid = (fails + works) / 2;
        if runs(mid)? {
            works = mid;
        } else {
            fails = mid;
        }
    }
    Ok(works)
}

/// `0x`-prefixed lowercase hex.
pub fn hex0x(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}
