//! `eth_simulateV1` (#716): blocks of calls simulated on top of a verified
//! block, as geth's `internal/ethapi/simulate.go` simulates them.
//!
//! The simulation starts from block N's post-state, which every read proves
//! against N's state root like any `eth_call`. The blocks it builds — N+1,
//! N+2, … — exist only in this request: each call's state changes carry to the
//! next call and the next block, in a cache that lives for one pass and is
//! never written to a cache another request reads (as for a state override,
//! [`crate::overrides`]). Each pass of the prefetch loop
//! ([`EvmExecutor::converge_runs`]) re-runs the whole simulation over a fresh
//! cache, so the answer is the run whose every read was verified.
//!
//! What geth does, and this does too:
//! - **Blocks**: numbers and timestamps strictly increase (12 s by default),
//!   a gap in the numbers is filled with empty blocks, and each block's header
//!   fields come from its `blockOverrides` or from the block before it: the gas
//!   limit and the fee recipient carry over, PREVRANDAO reads zero, and the
//!   base fee is zero unless overridden, or computed from the parent under
//!   `validation`.
//! - **Calls**: a missing `nonce` is the sender's nonce at that point, a
//!   missing `gas` the block's remaining gas, and every call draws on one
//!   budget for the whole request ([`SIMULATE_GAS_BUDGET`], the role of geth's
//!   RPC gas cap): a call asking for more is capped to what is left, and a
//!   failure then says so. Without `validation` the nonce is not checked and a
//!   call without fees pays nothing; with it, nonces, fee caps against the base
//!   fee and balances are checked, each failure ending the request with geth's
//!   error code. A call that reverts or halts is a result, as in geth.
//! - **System calls**: EIP-4788 (the beacon root, zero unless overridden) and
//!   EIP-2935 (the parent's hash) before a block's calls, EIP-7002 and
//!   EIP-7251 after them, then the block's withdrawals.
//! - **Results**: per call `returnData`, `logs`, `gasUsed`, `maxUsedGas`,
//!   `status` and `error` in geth's words; `traceTransfers` adds every ether
//!   transfer as an ERC-7528 log from `0xEeee…EeE`, in emission order.
//!
//! What this node cannot compute, and so leaves out or refuses — never fills
//! in ([`EvmError::SimulationNotServed`]):
//! - **A simulated block's state root, and so its hash.** Its post-state root
//!   needs trie nodes no proof carries. The block's `stateRoot` and `hash`, a
//!   log's `blockHash` and the next block's `parentHash` are unknown
//!   ([`SimulatedBlock::parent_hash`] is `None` after the first block), and a
//!   call that READS one — `BLOCKHASH` of a simulated block, or the EIP-2935
//!   history slot that holds it — is refused rather than run against a made-up
//!   hash.
//! - **The blob base fee.** Its excess-gas update needs the chain's blob
//!   schedule, which this crate does not carry: `excessBlobGas` is unknown, and
//!   `BLOBBASEFEE` is refused unless the block's `blobBaseFee` override sets it.
//! - **`requestsHash`** (EIP-7685), which needs the chain's deposit contract.
//! - **Amsterdam blocks**: their two-dimensional gas pool and block access
//!   list are not modelled.
//! - **Withdrawals on Gnosis**, which go through its withdrawal contract
//!   rather than a balance credit.
//! - **A state override of a precompile's address**: geth then runs the
//!   account as a plain account, and revm cannot stop running the precompile.
//!
//! One Gnosis rule is applied: the base fee a call pays goes to the chain's
//! fee collector, as Gnosis clients credit it, instead of being burned.

mod encode;
#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::collections::HashSet;

use revm::bytecode::opcode;
use revm::context::result::{EVMError, ExecutionResult, InvalidTransaction};
use revm::context::{BlockEnv, CfgEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::context_interface::CreateScheme;
use revm::database::CacheDB;
use revm::database_interface::{Database, DatabaseRef};
use revm::handler::system_call::{SystemCallCommitEvm, SYSTEM_ADDRESS};
use revm::interpreter::interpreter_types::Jumps;
use revm::interpreter::{CallInputs, CallScheme, CallValue, CreateInputs, InstructionResult, Interpreter, InterpreterResult};
use revm::precompile::{PrecompileSpecId, Precompiles};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{address, Address, Bytes, Log, B256, KECCAK_EMPTY, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, InspectCommitEvm, MainBuilder, MainContext};

use myotis_core::bloom::{accrue, LogsBloom, EMPTY_BLOOM};
use myotis_core::keccak::keccak256;

use crate::block::BlockContext;
use crate::database::{AccessSet, OracleDatabase, HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use crate::error::EvmError;
use crate::executor::{
    check_tx, map_evm_error, output_bytes, tx_env, view_cfg, CodeNeeded, EvmExecutor, RequestInspector,
    PREFETCH_ITERATION_CAP, VIEW_CALL_GAS,
};
use crate::fork::spec_for;
use crate::oracle::OracleError;
use crate::overrides::StateOverrides;
use crate::trace::{error_string, unpack_revert};
use crate::tx::{AccessListItem, Authorization, Fees, TxRequest, TYPE_ACCESS_LIST, TYPE_DYNAMIC_FEE, TYPE_LEGACY, TYPE_SET_CODE};

/// geth's `maxSimulateBlocks`: the highest block a request may reach above its
/// base, and the most blocks it may list.
pub const MAX_SIMULATE_BLOCKS: u64 = 256;
/// geth's `maxSimulateCallsPerBlock`.
pub const MAX_SIMULATE_CALLS_PER_BLOCK: usize = 5_000;
/// geth's `maxSimulateTotalCalls`.
pub const MAX_SIMULATE_TOTAL_CALLS: usize = 10_000;
/// geth's `timestampIncrement`: a block without a `time` override comes this
/// many seconds after the one before it.
pub const TIMESTAMP_INCREMENT: u64 = 12;
/// The gas every call of one request draws on together — this node's
/// [`VIEW_CALL_GAS`] call budget, in the role geth's RPC gas cap plays: a
/// simulation costs at most what one `eth_call` can.
pub const SIMULATE_GAS_BUDGET: u64 = VIEW_CALL_GAS;

/// geth's simulation error codes (`internal/ethapi/errors.go`).
pub mod codes {
    pub const NONCE_TOO_HIGH: i64 = -38011;
    pub const NONCE_TOO_LOW: i64 = -38010;
    pub const BASE_FEE_TOO_LOW: i64 = -38012;
    pub const INTRINSIC_GAS: i64 = -38013;
    pub const INSUFFICIENT_FUNDS: i64 = -38014;
    pub const BLOCK_GAS_LIMIT_REACHED: i64 = -38015;
    pub const BLOCK_NUMBER_INVALID: i64 = -38020;
    pub const BLOCK_TIMESTAMP_INVALID: i64 = -38021;
    pub const MAX_INIT_CODE_SIZE_EXCEEDED: i64 = -38025;
    pub const CLIENT_LIMIT_EXCEEDED: i64 = -38026;
    pub const INTERNAL_ERROR: i64 = -32603;
    pub const INVALID_PARAMS: i64 = -32602;
    /// A call that halted (not reverted): its `error.code`.
    pub const VM_ERROR: i64 = -32015;
    /// A call that reverted: its `error.code` (geth's revert error).
    pub const REVERTED: i64 = 3;
}

/// The EIP-4788 beacon roots contract.
pub const BEACON_ROOTS_ADDRESS: Address = address!("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02");
/// The EIP-7002 withdrawal request contract.
pub const WITHDRAWAL_REQUEST_ADDRESS: Address = address!("0x00000961Ef480Eb55e80D19ad83579A64c007002");
/// The EIP-7251 consolidation request contract.
pub const CONSOLIDATION_REQUEST_ADDRESS: Address = address!("0x0000BBdDc7CE488642fb579F8B00f3a590007251");
/// Gnosis's EIP-1559 fee collector (its chainspec's `feeCollector`): the base
/// fee a transaction pays is credited here instead of being burned.
pub const GNOSIS_FEE_COLLECTOR: Address = address!("0x6BBe78ee9e474842Dbd4AB4987b3CeFE88426A92");
/// Gnosis's chain id.
const GNOSIS_CHAIN_ID: u64 = 100;
/// ERC-7528's native-asset address: the emitter of `traceTransfers` logs.
pub const TRANSFER_LOG_ADDRESS: Address = address!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");
/// `keccak256("Transfer(address,address,uint256)")`.
pub const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7,
    0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];
/// EIP-3860's init code limit (Shanghai to Osaka).
const MAX_INITCODE_SIZE: usize = 49_152;
/// One gwei, the unit a withdrawal's amount is in.
const GWEI: u64 = 1_000_000_000;

/// One EIP-4895 withdrawal of a block override: `amount` in gwei.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}

/// A simulated block's `blockOverrides`: every field geth's `BlockOverrides`
/// has, each applied or the request refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockOverrides {
    pub number: Option<U256>,
    /// Refused: every block this node simulates is post-merge, where geth
    /// refuses it too.
    pub difficulty: Option<U256>,
    pub time: Option<u64>,
    pub gas_limit: Option<u64>,
    pub fee_recipient: Option<[u8; 20]>,
    pub prev_randao: Option<[u8; 32]>,
    pub base_fee_per_gas: Option<U256>,
    pub blob_base_fee: Option<U256>,
    pub beacon_root: Option<[u8; 32]>,
    pub withdrawals: Option<Vec<Withdrawal>>,
}

/// One block of a request: its overrides and its calls.
#[derive(Debug, Clone, Default)]
pub struct SimBlock {
    pub block_overrides: BlockOverrides,
    /// Applied to the state as it stands when the block starts (after the
    /// blocks before it), in address order.
    pub state_overrides: StateOverrides,
    pub calls: Vec<TxRequest>,
}

/// An `eth_simulateV1` request (geth's `simOpts`; `returnFullTransactions`
/// only shapes the answer, so the host applies it).
#[derive(Debug, Clone, Default)]
pub struct SimOptions {
    pub blocks: Vec<SimBlock>,
    pub trace_transfers: bool,
    pub validation: bool,
}

/// The verified block a simulation starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimBase {
    /// Its context: the state root the reads prove against, and the header
    /// fields the first simulated block inherits.
    pub ctx: BlockContext,
    /// Its hash: the first simulated block's `parentHash`, and `BLOCKHASH(N)`.
    pub hash: [u8; 32],
    /// Its gas used: the first block's base fee under `validation`.
    pub gas_used: u64,
}

/// A log of a simulated call, in the order geth's tracer records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    /// Its index in the block (geth counts across the block's calls).
    pub log_index: u64,
}

/// A failed call's `error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimCallError {
    pub message: String,
    pub code: i64,
    /// A revert's payload (`data`, hex in the answer); `None` for a halt.
    pub data: Option<Vec<u8>>,
}

/// One call's result (geth's `simCallResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimCallResult {
    /// The output of a call that succeeded; empty for one that failed (geth's
    /// `ExecutionResult.Return`: a revert's payload is in [`SimCallError::data`]).
    pub return_data: Vec<u8>,
    pub logs: Vec<SimLog>,
    /// After refunds (the receipt's).
    pub gas_used: u64,
    /// Before refunds (geth's `maxUsedGas`).
    pub max_used_gas: u64,
    pub status: bool,
    pub error: Option<SimCallError>,
}

/// A call as the transaction geth puts in the block (`TransactionArgs.
/// ToTransaction`), unsigned: `v`, `r` and `s` are zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimTransaction {
    pub hash: [u8; 32],
    pub tx_type: u8,
    pub from: [u8; 20],
    pub to: Option<[u8; 20]>,
    pub nonce: u64,
    pub gas: u64,
    pub value: U256,
    pub input: Vec<u8>,
    /// `None` for a legacy transaction (unprotected, as geth builds it).
    pub chain_id: Option<u64>,
    /// Legacy and EIP-2930: the price. Later types: the effective price,
    /// `min(tip + base fee, fee cap)`.
    pub gas_price: u128,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub access_list: Option<Vec<AccessListItem>>,
    pub authorization_list: Option<Vec<Authorization>>,
}

/// One simulated block: its header fields, its transactions and its calls'
/// results. What is not here is unknown to this node (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedBlock {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub fee_recipient: [u8; 20],
    pub prev_randao: [u8; 32],
    pub base_fee_per_gas: u64,
    /// The base block's hash for the first block; `None` after it (a
    /// simulated block's hash is unknown).
    pub parent_hash: Option<[u8; 32]>,
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: LogsBloom,
    /// From Shanghai on.
    pub withdrawals: Option<Vec<Withdrawal>>,
    pub withdrawals_root: Option<[u8; 32]>,
    /// From Cancun on: always zero (blob transactions are refused).
    pub blob_gas_used: Option<u64>,
    /// From Cancun on.
    pub parent_beacon_block_root: Option<[u8; 32]>,
    /// From Prague on the header has a `requestsHash`, which this node does
    /// not compute: `true` puts it in the answer as unknown.
    pub has_requests_hash: bool,
    pub transactions: Vec<SimTransaction>,
    pub calls: Vec<SimCallResult>,
}

/// A geth simulation error: the whole request fails with `code`.
fn sim_error(code: i64, message: impl Into<String>) -> EvmError {
    EvmError::Simulation { code, message: message.into() }
}

fn not_served(detail: impl Into<String>) -> EvmError {
    EvmError::SimulationNotServed { detail: detail.into() }
}

/// geth's request-level limits (`SimulateV1`), checked before anything else.
fn check_limits(opts: &SimOptions) -> Result<(), EvmError> {
    if opts.blocks.is_empty() {
        return Err(sim_error(codes::INVALID_PARAMS, "empty input"));
    }
    if opts.blocks.len() as u64 > MAX_SIMULATE_BLOCKS {
        return Err(sim_error(codes::CLIENT_LIMIT_EXCEEDED, "too many blocks"));
    }
    let mut total = 0usize;
    for block in &opts.blocks {
        if block.calls.len() > MAX_SIMULATE_CALLS_PER_BLOCK {
            return Err(sim_error(
                codes::CLIENT_LIMIT_EXCEEDED,
                format!("too many calls in block: {} > {MAX_SIMULATE_CALLS_PER_BLOCK}", block.calls.len()),
            ));
        }
        total += block.calls.len();
        if total > MAX_SIMULATE_TOTAL_CALLS {
            return Err(sim_error(
                codes::CLIENT_LIMIT_EXCEEDED,
                format!("too many calls: {total} > {MAX_SIMULATE_TOTAL_CALLS}"),
            ));
        }
    }
    Ok(())
}

/// geth's `sanitizeChain`: every block gets its number and timestamp, numbers
/// and timestamps strictly increase, and a gap in the numbers is filled with
/// empty blocks 12 s apart.
fn sanitize_chain(base: &BlockContext, blocks: &[SimBlock]) -> Result<Vec<SimBlock>, EvmError> {
    let mut out = Vec::with_capacity(blocks.len());
    let base_number = U256::from(base.block_number);
    let mut prev_number = base_number;
    let mut prev_time = base.timestamp;
    for block in blocks {
        let mut block = block.clone();
        let overrides = &mut block.block_overrides;
        let number = *overrides.number.get_or_insert(prev_number + U256::from(1));
        if overrides.withdrawals.is_none() {
            overrides.withdrawals = Some(Vec::new());
        }
        if number <= prev_number {
            return Err(sim_error(
                codes::BLOCK_NUMBER_INVALID,
                format!("block numbers must be in order: {number} <= {prev_number}"),
            ));
        }
        if number - base_number > U256::from(MAX_SIMULATE_BLOCKS) {
            return Err(sim_error(codes::CLIENT_LIMIT_EXCEEDED, "too many blocks"));
        }
        let gap = number - prev_number - U256::from(1);
        // At most 255 gap blocks: the number is within 256 of the base.
        for i in 0..gap.saturating_to::<u64>() {
            prev_time = prev_time.saturating_add(TIMESTAMP_INCREMENT);
            out.push(SimBlock {
                block_overrides: BlockOverrides {
                    number: Some(prev_number + U256::from(i + 1)),
                    time: Some(prev_time),
                    withdrawals: Some(Vec::new()),
                    ..BlockOverrides::default()
                },
                ..SimBlock::default()
            });
        }
        prev_number = number;
        let time = match overrides.time {
            None => {
                let time = prev_time.saturating_add(TIMESTAMP_INCREMENT);
                overrides.time = Some(time);
                time
            }
            Some(time) if time <= prev_time => {
                return Err(sim_error(
                    codes::BLOCK_TIMESTAMP_INVALID,
                    format!("block timestamps must be in order: {time} <= {prev_time}"),
                ))
            }
            Some(time) => time,
        };
        prev_time = time;
        out.push(block);
    }
    Ok(out)
}

/// What a block runs under, settled before any state is read.
#[derive(Debug, Clone, Copy)]
struct BlockPlan {
    number: u64,
    time: u64,
    spec: SpecId,
    base_fee: Option<u64>,
    blob_price: Option<u128>,
}

/// The checks geth's `makeHeaders` makes, and this node's refusals of what it
/// does not serve, for every block before the first one runs.
fn plan_blocks(chain_id: u64, blocks: &[SimBlock]) -> Result<Vec<BlockPlan>, EvmError> {
    let mut plans = Vec::with_capacity(blocks.len());
    for block in blocks {
        let overrides = &block.block_overrides;
        // Sanitized: within 256 of a u64 base, and set.
        let number = overrides.number.unwrap_or_default().saturating_to::<u64>();
        let time = overrides.time.unwrap_or_default();
        if overrides.difficulty.is_some() {
            return Err(sim_error(
                codes::INVALID_PARAMS,
                format!("block {number}: difficulty override is not allowed after the merge"),
            ));
        }
        let spec = spec_for(chain_id, number, time)?;
        if spec.is_enabled_in(SpecId::AMSTERDAM) {
            return Err(not_served(format!(
                "block {number} would be an Amsterdam block, which this node does not simulate \
                 (its two-dimensional gas pool and block access list are not modelled)"
            )));
        }
        let base_fee = match overrides.base_fee_per_gas {
            None => None,
            Some(fee) => Some(u64::try_from(fee).map_err(|_| {
                not_served(format!("block {number}: a baseFeePerGas above 2^64-1 ({fee}) is not served"))
            })?),
        };
        let blob_price = match overrides.blob_base_fee {
            None => None,
            Some(fee) => Some(u128::try_from(fee).map_err(|_| {
                not_served(format!("block {number}: a blobBaseFee above 2^128-1 ({fee}) is not served"))
            })?),
        };
        let precompiles = Precompiles::new(PrecompileSpecId::from_spec_id(spec));
        if let Some((address, _)) = block.state_overrides.sorted().into_iter().find(|(a, _)| precompiles.contains(&Address::from(**a))) {
            return Err(not_served(format!(
                "a state override of the precompile {} is not served: geth then runs the account as a \
                 plain one, which this node's EVM cannot do",
                Address::from(*address)
            )));
        }
        if chain_id == GNOSIS_CHAIN_ID && overrides.withdrawals.as_ref().is_some_and(|w| !w.is_empty()) {
            return Err(not_served(format!(
                "block {number}: withdrawals are not simulated on Gnosis, whose withdrawals go \
                 through its withdrawal contract"
            )));
        }
        plans.push(BlockPlan { number, time, spec, base_fee, blob_price });
    }
    Ok(plans)
}

/// The verified state under a simulation: the base block's database, whose
/// `BLOCKHASH` answers for the base block and the chain below it, and refuses
/// a simulated block's.
struct SimDb<'a> {
    base: &'a OracleDatabase,
    base_number: u64,
    base_hash: [u8; 32],
    refusal: &'a RefCell<Option<String>>,
}

impl DatabaseRef for SimDb<'_> {
    type Error = OracleError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, OracleError> {
        self.base.basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, OracleError> {
        self.base.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, OracleError> {
        self.base.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, OracleError> {
        if number > self.base_number {
            self.refusal.borrow_mut().get_or_insert_with(|| {
                format!(
                    "BLOCKHASH({number}) reads a simulated block's hash, which this node does not \
                     compute (it needs the block's post-state root)"
                )
            });
            return Err(OracleError::BlockHashUnsupported { number });
        }
        if number == self.base_number {
            return Ok(B256::from(self.base_hash));
        }
        self.base.block_hash_ref(number)
    }
}

type SimCache<'a> = CacheDB<SimDb<'a>>;

/// A log as the recorder holds it while its frame is open.
#[derive(Debug, Clone)]
struct RawLog {
    address: [u8; 20],
    topics: Vec<[u8; 32]>,
    data: Vec<u8>,
    index: u64,
}

#[derive(Default)]
struct SimState {
    /// Whether the block's blob base fee is known (overridden).
    blob_fee_known: bool,
    /// EIP-2935 history slots holding a simulated block's (unknown) hash.
    poisoned: HashSet<U256>,
    /// Each open frame's logs (geth's tracer: a failed frame drops its own).
    frames: Vec<Vec<RawLog>>,
    /// The next log index in the block.
    count: u64,
    /// Each open frame's last opcode and stack height, for its error.
    last_op: Vec<(u8, usize)>,
    /// Each open frame's pending create transfer log: its index in the frame,
    /// filled with the new address when the create ends.
    pending_create: Vec<Option<usize>>,
    /// The top frame's end: its result, last opcode and stack height.
    top: Option<(InstructionResult, u8, usize)>,
    /// The finished call's logs.
    done: Vec<RawLog>,
}

/// The simulation's view of a run, behind the request inspector: geth's
/// simulate tracer (`internal/ethapi/logtracer.go` — the logs, with ether
/// transfers as logs under `traceTransfers`), the top frame's error, and the
/// reads the simulation refuses.
pub(crate) struct SimRecorder {
    trace_transfers: bool,
    refusal: RefCell<Option<String>>,
    state: RefCell<SimState>,
}

impl SimRecorder {
    fn new(trace_transfers: bool) -> SimRecorder {
        SimRecorder { trace_transfers, refusal: RefCell::new(None), state: RefCell::new(SimState::default()) }
    }

    fn refuse(&self, detail: String) {
        self.refusal.borrow_mut().get_or_insert(detail);
    }

    fn refusal(&self) -> Option<String> {
        self.refusal.borrow().clone()
    }

    /// A block starts: its log indices start at zero.
    fn begin_block(&self, blob_fee_known: bool) {
        let mut st = self.state.borrow_mut();
        st.count = 0;
        st.blob_fee_known = blob_fee_known;
    }

    /// A call starts.
    fn begin_call(&self) {
        let mut st = self.state.borrow_mut();
        st.frames.clear();
        st.last_op.clear();
        st.pending_create.clear();
        st.top = None;
        st.done.clear();
    }

    fn poison(&self, slot: U256) {
        self.state.borrow_mut().poisoned.insert(slot);
    }

    fn unpoison(&self, slot: U256) {
        self.state.borrow_mut().poisoned.remove(&slot);
    }

    fn unpoison_all(&self) {
        self.state.borrow_mut().poisoned.clear();
    }

    /// Before each opcode; `true` stops the run (a refused read).
    pub(crate) fn step(&self, interp: &Interpreter) -> bool {
        if self.refusal.borrow().is_some() {
            return true;
        }
        let op = interp.bytecode.opcode();
        let mut st = self.state.borrow_mut();
        if let Some(last) = st.last_op.last_mut() {
            *last = (op, interp.stack.len());
        }
        if op == opcode::BLOBBASEFEE && !st.blob_fee_known {
            drop(st);
            self.refuse(
                "BLOBBASEFEE reads the simulated block's blob base fee, which this node does not \
                 compute (it needs the chain's blob schedule); set it with the block override \
                 'blobBaseFee'"
                    .to_string(),
            );
            return true;
        }
        if op == opcode::SLOAD
            && interp.input.target_address == Address::from(HISTORY_STORAGE_ADDRESS)
            && !st.poisoned.is_empty()
        {
            if let Ok(slot) = interp.stack.peek(0) {
                if st.poisoned.contains(&slot) {
                    drop(st);
                    self.refuse(format!(
                        "the EIP-2935 history contract's slot {slot} holds a simulated block's \
                         hash, which this node does not compute"
                    ));
                    return true;
                }
            }
        }
        false
    }

    fn open_frame(&self) {
        let mut st = self.state.borrow_mut();
        st.frames.push(Vec::new());
        st.last_op.push((0, 0));
        st.pending_create.push(None);
    }

    /// geth's `captureLog` into the open frame.
    fn capture(&self, address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> Option<usize> {
        let mut st = self.state.borrow_mut();
        let index = st.count;
        let frame = st.frames.last_mut()?;
        frame.push(RawLog { address, topics, data, index });
        let at = frame.len() - 1;
        st.count += 1;
        Some(at)
    }

    /// geth's `captureTransfer`.
    fn transfer(&self, from: Address, to: Address, value: U256) -> Option<usize> {
        if !self.trace_transfers || value.is_zero() {
            return None;
        }
        self.capture(
            TRANSFER_LOG_ADDRESS.into_array(),
            vec![TRANSFER_TOPIC, from.into_word().0, to.into_word().0],
            value.to_be_bytes::<32>().to_vec(),
        )
    }

    /// A call frame begins (geth's `OnEnter`): its value moves, unless it is a
    /// DELEGATECALL or CALLCODE.
    pub(crate) fn call(&self, inputs: &CallInputs) {
        self.open_frame();
        if matches!(inputs.scheme, CallScheme::Call | CallScheme::StaticCall) {
            if let CallValue::Transfer(value) = inputs.value {
                self.transfer(inputs.caller, inputs.target_address, value);
            }
        }
    }

    /// A create frame begins. A CREATE2's address is known now; a CREATE's
    /// comes with its end, and its transfer log keeps its place meanwhile.
    pub(crate) fn create(&self, inputs: &CreateInputs) {
        self.open_frame();
        let to = match inputs.scheme() {
            CreateScheme::Create2 { .. } => inputs.created_address(0),
            _ => Address::ZERO,
        };
        if let Some(at) = self.transfer(inputs.caller(), to, inputs.value()) {
            if !matches!(inputs.scheme(), CreateScheme::Create2 { .. }) {
                if let Some(pending) = self.state.borrow_mut().pending_create.last_mut() {
                    *pending = Some(at);
                }
            }
        }
    }

    /// A frame ends (geth's `OnExit`): a failed frame's logs go, and their
    /// indices are free again; a successful one's join its parent's.
    pub(crate) fn end(&self, result: &InterpreterResult, created: Option<Address>) {
        let mut st = self.state.borrow_mut();
        let (op, stack_len) = st.last_op.pop().unwrap_or((0, 0));
        let mut logs = st.frames.pop().unwrap_or_default();
        if let Some(Some(at)) = st.pending_create.pop() {
            if let Some(log) = logs.get_mut(at) {
                log.topics[2] = created.unwrap_or_default().into_word().0;
            }
        }
        let failed = !result.result.is_ok();
        if failed {
            st.count = st.count.saturating_sub(logs.len() as u64);
            logs.clear();
        }
        match st.frames.last_mut() {
            Some(parent) => parent.extend(logs),
            None => {
                st.top = Some((result.result, op, stack_len));
                st.done = logs;
            }
        }
    }

    pub(crate) fn log(&self, log: &Log) {
        self.capture(
            log.address.into_array(),
            log.data.topics().iter().map(|t| t.0).collect(),
            log.data.data.to_vec(),
        );
    }

    /// A SELFDESTRUCT moves the contract's balance to `target`.
    pub(crate) fn selfdestruct(&self, contract: Address, target: Address, value: U256) {
        self.transfer(contract, target, value);
    }

    /// The finished call's logs, and its top frame's end.
    fn finish_call(&self) -> (Vec<SimLog>, Option<(InstructionResult, u8, usize)>) {
        let mut st = self.state.borrow_mut();
        let logs = std::mem::take(&mut st.done)
            .into_iter()
            .map(|raw| SimLog { address: raw.address, topics: raw.topics, data: raw.data, log_index: raw.index })
            .collect();
        (logs, st.top.take())
    }
}

/// The parent a block inherits from.
#[derive(Debug, Clone, Copy)]
struct Parent {
    gas_limit: u64,
    gas_used: u64,
    base_fee: u64,
    coinbase: [u8; 20],
    hash: Option<[u8; 32]>,
}

/// The fee fields as geth's message reads them: `(fee cap, tip)`.
fn fee_cap_and_tip(fees: &Fees) -> (u128, u128) {
    match *fees {
        Fees::None => (0, 0),
        Fees::Legacy { gas_price } => (gas_price, gas_price),
        Fees::DynamicFee { max_fee_per_gas, max_priority_fee_per_gas } => (max_fee_per_gas, max_priority_fee_per_gas),
    }
}

/// The type of the transaction geth puts in the block for `call`
/// (geth master's `ToTransaction(DynamicFeeTxType)`): a `gasPrice` makes a
/// legacy one — EIP-2930 with an access list — whatever else the call
/// carries, an authorization list a set-code one, and anything else a
/// dynamic-fee one. An explicit `type`, which geth's arguments have no field
/// for, is applied as named (the request was refused unless its fields fit
/// it, `TxRequest::validate`).
fn block_tx_type(call: &TxRequest) -> u8 {
    if let Some(ty) = call.tx_type {
        return ty;
    }
    if let Fees::Legacy { .. } = call.fees {
        return if call.access_list.is_some() { TYPE_ACCESS_LIST } else { TYPE_LEGACY };
    }
    if call.authorization_list.is_some() {
        return TYPE_SET_CODE;
    }
    TYPE_DYNAMIC_FEE
}

impl EvmExecutor {
    /// `eth_simulateV1` (#716): `opts`' blocks of calls on top of `base`, as
    /// geth simulates them (see the module docs). Request-level failures are
    /// geth's errors with geth's codes ([`EvmError::Simulation`]); what this
    /// node cannot compute is refused ([`EvmError::SimulationNotServed`]).
    pub fn simulate(&self, base: &SimBase, opts: &SimOptions) -> Result<Vec<SimulatedBlock>, EvmError> {
        self.oracle.check_request()?;
        check_limits(opts)?;
        let blocks = sanitize_chain(&base.ctx, &opts.blocks)?;
        let plans = plan_blocks(base.ctx.chain_id, &blocks)?;
        let base_spec = spec_for(base.ctx.chain_id, base.ctx.block_number, base.ctx.timestamp)?;
        if base_spec.is_enabled_in(SpecId::AMSTERDAM) {
            return Err(not_served(format!(
                "the base block {} is an Amsterdam block, which this node does not simulate on",
                base.ctx.block_number
            )));
        }
        // Each call as a transaction object, before any state is read.
        for (block, plan) in blocks.iter().zip(&plans) {
            for call in &block.calls {
                check_tx(call, &base.ctx, plan.spec)?;
            }
        }
        let db = self.database_for_with(&base.ctx, StateOverrides::new());
        self.first_simulation_wave(base, &blocks);
        self.converge_runs(&db, &base.ctx, PREFETCH_ITERATION_CAP, |code_needed| {
            self.simulation_pass(&db, base, opts, &blocks, &plans, code_needed)
        })
    }

    /// What every pass reads first, fetched in one wave: the senders, the
    /// targets, the authorizations' delegates, the fee recipients and the
    /// system contracts, and the code of every one that runs.
    fn first_simulation_wave(&self, base: &SimBase, blocks: &[SimBlock]) {
        let mut accounts: HashSet<[u8; 20]> = HashSet::new();
        let mut code_needed: HashSet<[u8; 20]> = HashSet::new();
        for system in [BEACON_ROOTS_ADDRESS, WITHDRAWAL_REQUEST_ADDRESS, CONSOLIDATION_REQUEST_ADDRESS] {
            code_needed.insert(system.into_array());
        }
        code_needed.insert(HISTORY_STORAGE_ADDRESS);
        accounts.insert(base.ctx.coinbase);
        for block in blocks {
            accounts.extend(block.block_overrides.fee_recipient);
            for call in &block.calls {
                accounts.insert(call.from);
                code_needed.extend(call.to);
                code_needed.extend(call.authorization_list.iter().flatten().map(|auth| auth.address));
            }
        }
        accounts.extend(code_needed.iter().copied());
        self.prefetch_wave(&base.ctx, &AccessSet { accounts, ..Default::default() }, &code_needed);
    }

    /// One whole simulation over a fresh cache: one pass of the prefetch loop.
    fn simulation_pass(
        &self,
        db: &OracleDatabase,
        base: &SimBase,
        opts: &SimOptions,
        blocks: &[SimBlock],
        plans: &[BlockPlan],
        code_needed: Option<&CodeNeeded>,
    ) -> Result<Vec<SimulatedBlock>, EvmError> {
        let recorder = SimRecorder::new(opts.trace_transfers);
        let mut cache = CacheDB::new(SimDb {
            base: db,
            base_number: base.ctx.block_number,
            base_hash: base.hash,
            refusal: &recorder.refusal,
        });
        let mut run = Run {
            executor: self,
            chain_id: base.ctx.chain_id,
            validation: opts.validation,
            recorder: &recorder,
            code_needed,
            budget: SIMULATE_GAS_BUDGET,
        };
        let mut parent = Parent {
            gas_limit: base.ctx.gas_limit,
            gas_used: base.gas_used,
            base_fee: base.ctx.base_fee_per_gas,
            coinbase: base.ctx.coinbase,
            hash: Some(base.hash),
        };
        let mut out = Vec::with_capacity(blocks.len());
        for (block, plan) in blocks.iter().zip(plans) {
            let simulated = run.block(&mut cache, &parent, block, plan).map_err(|error| match recorder.refusal() {
                Some(detail) => not_served(detail),
                None => error,
            })?;
            parent = Parent {
                gas_limit: simulated.gas_limit,
                gas_used: simulated.gas_used,
                base_fee: simulated.base_fee_per_gas,
                coinbase: simulated.fee_recipient,
                hash: None,
            };
            out.push(simulated);
        }
        Ok(out)
    }
}

/// One pass's running state.
struct Run<'a> {
    executor: &'a EvmExecutor,
    chain_id: u64,
    validation: bool,
    recorder: &'a SimRecorder,
    code_needed: Option<&'a CodeNeeded>,
    /// What is left of [`SIMULATE_GAS_BUDGET`].
    budget: u64,
}

impl Run<'_> {
    fn inspector(&self, sim: bool) -> RequestInspector<'_> {
        RequestInspector {
            oracle: self.executor.oracle.as_ref(),
            code_needed: self.code_needed,
            access_list: None,
            trace: None,
            sim: sim.then_some(self.recorder),
        }
    }

    /// geth's `processBlock`.
    fn block(
        &mut self,
        cache: &mut SimCache<'_>,
        parent: &Parent,
        block: &SimBlock,
        plan: &BlockPlan,
    ) -> Result<SimulatedBlock, EvmError> {
        let overrides = &block.block_overrides;
        let spec = plan.spec;
        let number = plan.number;
        let gas_limit = overrides.gas_limit.unwrap_or(parent.gas_limit);
        let fee_recipient = overrides.fee_recipient.unwrap_or(parent.coinbase);
        let prev_randao = overrides.prev_randao.unwrap_or([0; 32]);
        let base_fee = match plan.base_fee {
            Some(fee) => fee,
            None if self.validation => {
                // geth's `eip1559.CalcBaseFee`.
                let fee = myotis_core::fees::next_base_fee(u128::from(parent.base_fee), parent.gas_limit, parent.gas_used);
                u64::try_from(fee).map_err(|_| {
                    not_served(format!("block {number}: its base fee ({fee}) exceeds 2^64-1"))
                })?
            }
            None => 0,
        };
        let cancun = spec.is_enabled_in(SpecId::CANCUN);
        let prague = spec.is_enabled_in(SpecId::PRAGUE);
        let shanghai = spec.is_enabled_in(SpecId::SHANGHAI);
        self.apply_state_overrides(cache, &block.state_overrides)?;

        let cfg = view_cfg(spec, self.chain_id);
        let block_env = BlockEnv {
            number: U256::from(number),
            timestamp: U256::from(plan.time),
            gas_limit,
            basefee: base_fee,
            beneficiary: Address::from(fee_recipient),
            difficulty: U256::ZERO,
            prevrandao: Some(B256::from(prev_randao)),
            // Read only by BLOBBASEFEE, which the recorder refuses unless
            // the override set it.
            blob_excess_gas_and_price: Some(BlobExcessGasAndPrice {
                excess_blob_gas: 0,
                blob_gasprice: plan.blob_price.unwrap_or(0),
            }),
            ..BlockEnv::default()
        };
        self.recorder.begin_block(plan.blob_price.is_some());

        // geth's PreExecution system calls.
        let beacon_root = overrides.beacon_root.unwrap_or([0; 32]);
        if cancun {
            self.system_call(cache, &block_env, &cfg, BEACON_ROOTS_ADDRESS, beacon_root.to_vec())?;
        }
        if prague {
            let history = Address::from(HISTORY_STORAGE_ADDRESS);
            self.system_call(cache, &block_env, &cfg, history, parent.hash.unwrap_or([0; 32]).to_vec())?;
            let slot = U256::from((number - 1) % HISTORY_SERVE_WINDOW);
            match parent.hash {
                Some(_) => self.recorder.unpoison(slot),
                None => self.recorder.poison(slot),
            }
        }

        let mut transactions = Vec::with_capacity(block.calls.len());
        let mut calls = Vec::with_capacity(block.calls.len());
        let mut receipts = Vec::with_capacity(block.calls.len());
        let mut logs_bloom = EMPTY_BLOOM;
        let mut cumulative = 0u64;
        for call in &block.calls {
            let (tx, result, receipt_logs) =
                self.call(cache, &block_env, &cfg, call, base_fee, gas_limit, &mut cumulative)?;
            let mut bloom = EMPTY_BLOOM;
            for log in &receipt_logs {
                accrue(&mut bloom, log.address.as_slice());
                for topic in log.data.topics() {
                    accrue(&mut bloom, topic.as_slice());
                }
            }
            for (have, add) in logs_bloom.iter_mut().zip(bloom.iter()) {
                *have |= add;
            }
            receipts.push(encode::receipt(tx.tx_type, result.status, cumulative, &bloom, &receipt_logs));
            transactions.push(tx);
            calls.push(result);
        }

        // geth's PostExecution system calls, then the withdrawals.
        if prague {
            self.system_call(cache, &block_env, &cfg, WITHDRAWAL_REQUEST_ADDRESS, Vec::new())?;
            self.system_call(cache, &block_env, &cfg, CONSOLIDATION_REQUEST_ADDRESS, Vec::new())?;
        }
        let withdrawals = overrides.withdrawals.clone().unwrap_or_default();
        for withdrawal in &withdrawals {
            let amount = U256::from(withdrawal.amount) * U256::from(GWEI);
            credit(cache, Address::from(withdrawal.address), amount)?;
        }

        let encoded_txs: Vec<Vec<u8>> = transactions.iter().map(encode::transaction).collect();
        let encoded_withdrawals: Vec<Vec<u8>> = withdrawals.iter().map(encode::withdrawal).collect();
        Ok(SimulatedBlock {
            number,
            timestamp: plan.time,
            gas_limit,
            gas_used: cumulative,
            fee_recipient,
            prev_randao,
            base_fee_per_gas: base_fee,
            parent_hash: parent.hash,
            transactions_root: myotis_core::triehash::ordered_trie_root(encoded_txs.iter().map(Vec::as_slice)),
            receipts_root: myotis_core::triehash::ordered_trie_root(receipts.iter().map(Vec::as_slice)),
            logs_bloom,
            withdrawals_root: shanghai
                .then(|| myotis_core::triehash::ordered_trie_root(encoded_withdrawals.iter().map(Vec::as_slice))),
            withdrawals: shanghai.then_some(withdrawals),
            blob_gas_used: cancun.then_some(0),
            parent_beacon_block_root: cancun.then_some(beacon_root),
            has_requests_hash: prague,
            transactions,
            calls,
        })
    }

    /// geth's `StateOverride.Apply` on the state as the block starts.
    fn apply_state_overrides(
        &self,
        cache: &mut SimCache<'_>,
        overrides: &StateOverrides,
    ) -> Result<(), EvmError> {
        // A precompile's address was refused before the run (`plan_blocks`).
        let history = Address::from(HISTORY_STORAGE_ADDRESS);
        for (address, over) in overrides.sorted() {
            let address = Address::from(*address);
            if over.state.is_some() && !over.state_diff.is_empty() {
                return Err(sim_error(
                    codes::INVALID_PARAMS,
                    format!("account {address} has both 'state' and 'stateDiff'"),
                ));
            }
            if over.nonce.is_some() || over.balance.is_some() || over.code.is_some() {
                let mut info = cache.basic(address)?.unwrap_or_default();
                if let Some(nonce) = over.nonce {
                    info.nonce = nonce;
                }
                if let Some(balance) = over.balance {
                    info.balance = balance;
                }
                if let Some(code) = &over.code {
                    info.code_hash = B256::from(keccak256(code));
                    info.code = Some(crate::database::to_bytecode(code.clone().into()));
                }
                cache.insert_account_info(address, info);
            }
            if let Some(state) = &over.state {
                cache.replace_account_storage(address, state.iter().map(|(k, v)| (*k, *v)).collect())?;
                if address == history {
                    self.recorder.unpoison_all();
                }
            }
            for (slot, value) in &over.state_diff {
                cache.insert_account_storage(address, *slot, *value)?;
                if address == history {
                    self.recorder.unpoison(*slot);
                }
            }
        }
        Ok(())
    }

    /// A system call to `contract` (no gas charged, from the system address),
    /// committed. A contract without code does nothing, as before its fork's
    /// deployment.
    fn system_call(
        &self,
        cache: &mut SimCache<'_>,
        block_env: &BlockEnv,
        cfg: &CfgEnv,
        contract: Address,
        data: Vec<u8>,
    ) -> Result<(), EvmError> {
        let Some(info) = cache.basic(contract)? else { return Ok(()) };
        if info.code_hash == KECCAK_EMPTY || info.code_hash == B256::ZERO {
            return Ok(());
        }
        let mut evm = Context::mainnet()
            .with_db(&mut *cache)
            .with_block(block_env.clone())
            .with_cfg(cfg.clone())
            .build_mainnet_with_inspector(self.inspector(false));
        evm.system_call_with_caller_commit(SYSTEM_ADDRESS, contract, Bytes::from(data)).map_err(map_evm_error)?;
        self.executor.oracle.check_request()?;
        Ok(())
    }

    /// geth's `sanitizeCall` and the state transition's checks in its order,
    /// then the run, committed. Yields the block's transaction, the call's
    /// result and the receipt's logs.
    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        cache: &mut SimCache<'_>,
        block_env: &BlockEnv,
        cfg: &CfgEnv,
        call: &TxRequest,
        base_fee: u64,
        gas_limit: u64,
        cumulative: &mut u64,
    ) -> Result<(SimTransaction, SimCallResult, Vec<Log>), EvmError> {
        self.executor.oracle.check_request()?;
        let sender = Address::from(call.from);
        let account = cache.basic(sender)?.unwrap_or_default();
        let state_nonce = account.nonce;
        let nonce = call.nonce.unwrap_or(state_nonce);
        let remaining = gas_limit.saturating_sub(*cumulative);
        let requested = call.gas.unwrap_or(remaining);
        if remaining < requested {
            return Err(sim_error(
                codes::BLOCK_GAS_LIMIT_REACHED,
                format!("block gas limit reached: remaining: {remaining}, required: {requested}"),
            ));
        }
        let gas = requested.min(self.budget);
        let capped = gas < requested;
        if !self.validation && state_nonce == u64::MAX {
            return Err(sim_error(
                codes::INTERNAL_ERROR,
                format!("nonce has max value: address {sender}, nonce: {state_nonce}"),
            ));
        }
        if self.validation {
            if state_nonce < nonce {
                return Err(sim_error(
                    codes::NONCE_TOO_HIGH,
                    format!("nonce too high: address {sender}, tx: {nonce} state: {state_nonce}"),
                ));
            }
            if state_nonce > nonce {
                return Err(sim_error(
                    codes::NONCE_TOO_LOW,
                    format!("nonce too low: address {sender}, tx: {nonce} state: {state_nonce}"),
                ));
            }
        }
        let (fee_cap, tip) = fee_cap_and_tip(&call.fees);
        // geth skips the fee checks only for a fee-less call outside validation.
        if (self.validation || fee_cap > 0 || tip > 0) && fee_cap < u128::from(base_fee) {
            return Err(sim_error(
                codes::BASE_FEE_TOO_LOW,
                format!(
                    "max fee per gas less than block base fee: address {sender}, maxFeePerGas: {fee_cap}, baseFee: {base_fee}"
                ),
            ));
        }
        if call.to.is_none() && call.data.len() > MAX_INITCODE_SIZE {
            return Err(sim_error(
                codes::MAX_INIT_CODE_SIZE_EXCEEDED,
                format!("max initcode size exceeded: code size {} limit {MAX_INITCODE_SIZE}", call.data.len()),
            ));
        }
        // geth's buyGas.
        let Some(want) = U256::from(gas).checked_mul(U256::from(fee_cap)).and_then(|cost| cost.checked_add(call.value))
        else {
            return Err(sim_error(
                codes::INSUFFICIENT_FUNDS,
                format!("insufficient funds for gas * price + value: address {sender} required balance exceeds 256 bits"),
            ));
        };
        let have = account.balance;
        if have < want {
            return Err(sim_error(
                codes::INSUFFICIENT_FUNDS,
                format!("insufficient funds for gas * price + value: address {sender} have {have} want {want}"),
            ));
        }
        // revm prices the run as `gas × price` in u128 and `expect`s it to fit.
        if u128::from(gas).checked_mul(fee_cap).is_none() {
            return Err(not_served(format!(
                "gas × fee cap ({gas} × {fee_cap}) exceeds the 2^128 wei this engine can price"
            )));
        }

        let tx = block_transaction(call, nonce, gas, self.chain_id, base_fee);
        self.recorder.begin_call();
        let env = tx_env(call, gas, self.chain_id)?;
        let outcome = {
            let mut evm = Context::mainnet()
                .with_db(&mut *cache)
                .with_block(block_env.clone())
                .with_cfg(cfg.clone())
                .build_mainnet_with_inspector(self.inspector(true));
            evm.inspect_tx_commit(env)
        };
        self.executor.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.executor.oracle.check_request()?;
        if let Some(detail) = self.recorder.refusal() {
            return Err(not_served(detail));
        }
        let result = outcome.map_err(map_simulated_tx_error)?;
        let gas_used = result.tx_gas_used();
        let result_gas = result.gas();
        let max_used_gas = result_gas.total_gas_spent().max(result_gas.floor_gas());
        self.budget = self.budget.saturating_sub(gas_used);
        *cumulative = cumulative.saturating_add(gas_used);
        // Gnosis credits the base fee a call paid to its fee collector.
        if self.chain_id == GNOSIS_CHAIN_ID && base_fee > 0 && (fee_cap > 0 || tip > 0) {
            credit(cache, GNOSIS_FEE_COLLECTOR, U256::from(base_fee) * U256::from(gas_used))?;
        }
        let (logs, top) = self.recorder.finish_call();
        let (status, return_data, error, receipt_logs) = match result {
            ExecutionResult::Success { output, logs: receipt_logs, .. } => {
                (true, output_bytes(output), None, receipt_logs)
            }
            ExecutionResult::Revert { output, .. } => {
                let message = match unpack_revert(&output) {
                    Some(reason) => format!("execution reverted: {reason}"),
                    None => "execution reverted".to_string(),
                };
                let error = SimCallError { message, code: codes::REVERTED, data: Some(output.to_vec()) };
                (false, Vec::new(), Some(error), Vec::new())
            }
            ExecutionResult::Halt { reason, .. } => {
                let mut message = match top {
                    Some((result, op, stack_len)) => error_string(result, op, stack_len),
                    None => format!("{reason:?}"),
                };
                if capped {
                    message.push_str(" (gas limit was capped by the RPC server's global gas cap)");
                }
                (false, Vec::new(), Some(SimCallError { message, code: codes::VM_ERROR, data: None }), Vec::new())
            }
        };
        let result = SimCallResult { return_data, logs, gas_used, max_used_gas, status, error };
        Ok((tx, result, receipt_logs))
    }
}

/// A transaction revm refused before running it, in geth's words and codes.
fn map_simulated_tx_error(error: EVMError<OracleError>) -> EvmError {
    match error {
        EVMError::Transaction(InvalidTransaction::CallGasCostMoreThanGasLimit { initial_gas, gas_limit }) => {
            sim_error(codes::INTRINSIC_GAS, format!("intrinsic gas too low: have {gas_limit}, want {initial_gas}"))
        }
        EVMError::Transaction(InvalidTransaction::GasFloorMoreThanGasLimit { gas_floor, gas_limit }) => sim_error(
            codes::INTERNAL_ERROR,
            format!("insufficient gas for floor data gas cost: have {gas_limit}, want {gas_floor}"),
        ),
        other => map_evm_error(other),
    }
}

/// Add `amount` to `address`'s balance in the simulation's state.
fn credit(cache: &mut SimCache<'_>, address: Address, amount: U256) -> Result<(), EvmError> {
    let mut info = cache.basic(address)?.unwrap_or_default();
    info.balance = info.balance.saturating_add(amount);
    cache.insert_account_info(address, info);
    Ok(())
}

/// `call` as the transaction geth puts in the block, at the nonce and gas it
/// ran with.
fn block_transaction(call: &TxRequest, nonce: u64, gas: u64, chain_id: u64, base_fee: u64) -> SimTransaction {
    let tx_type = block_tx_type(call);
    let (fee_cap, tip) = fee_cap_and_tip(&call.fees);
    let typed_fees = tx_type >= TYPE_DYNAMIC_FEE;
    let gas_price = if typed_fees { (tip.saturating_add(u128::from(base_fee))).min(fee_cap) } else { fee_cap };
    let mut tx = SimTransaction {
        hash: [0; 32],
        tx_type,
        from: call.from,
        to: call.to,
        nonce,
        gas,
        value: call.value,
        input: call.data.to_vec(),
        chain_id: (tx_type != TYPE_LEGACY).then_some(chain_id),
        gas_price,
        max_fee_per_gas: typed_fees.then_some(fee_cap),
        max_priority_fee_per_gas: typed_fees.then_some(tip),
        access_list: (tx_type != TYPE_LEGACY).then(|| call.access_list.clone().unwrap_or_default()),
        authorization_list: (tx_type == TYPE_SET_CODE).then(|| call.authorization_list.clone().unwrap_or_default()),
    };
    tx.hash = keccak256(&encode::transaction(&tx));
    tx
}
