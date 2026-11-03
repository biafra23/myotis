//! `debug_traceCall`'s tracers (#716): geth's `callTracer` and
//! `prestateTracer` (`eth/tracers/native/call.go`, `prestate.go`), recorded
//! over the same run `eth_call` makes — revm over proof-served state, through
//! the speculative prefetch loop.
//!
//! The recorder is reset at the start of every run the loop makes, so what it
//! holds when the loop settles is the returned run's trace, never a discovery
//! pass's (the [`crate::executor`] access-list recorder works the same way).
//!
//! What is honoured, and nothing else (the host refuses every other option):
//! - `callTracer` with `onlyTopCall` and `withLog`;
//! - `prestateTracer` with `disableCode`, `disableStorage` and `includeEmpty`.
//!   `diffMode` is not served.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use revm::bytecode::opcode;
use revm::interpreter::interpreter_types::Jumps;
use revm::interpreter::{CallInputs, CallScheme, CallValue, CreateInputs, InstructionResult, Interpreter, InterpreterResult};
use revm::primitives::{Address, Log, B256, U256};

use crate::tx::TxRequest;

/// The tracer a `debug_traceCall` asked for, with the options it set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tracer {
    /// geth's `callTracer`: the call tree.
    Call {
        /// Only the top frame, no sub-calls (and only its own logs).
        only_top_call: bool,
        /// The logs each frame emitted, with their position among its sub-calls.
        with_log: bool,
    },
    /// geth's `prestateTracer` (not `diffMode`): every account and storage slot
    /// the run touched, as it stood before the run.
    Prestate {
        disable_code: bool,
        disable_storage: bool,
        /// Keep accounts that did not exist before the run (geth drops them).
        include_empty: bool,
    },
}

/// A call frame's type, as geth's `callTracer` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    Create,
    Create2,
    SelfDestruct,
}

impl FrameKind {
    pub fn name(self) -> &'static str {
        match self {
            FrameKind::Call => "CALL",
            FrameKind::CallCode => "CALLCODE",
            FrameKind::DelegateCall => "DELEGATECALL",
            FrameKind::StaticCall => "STATICCALL",
            FrameKind::Create => "CREATE",
            FrameKind::Create2 => "CREATE2",
            FrameKind::SelfDestruct => "SELFDESTRUCT",
        }
    }
}

/// One frame of a `callTracer` answer (geth's `callFrame`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFrame {
    pub kind: FrameKind,
    pub from: [u8; 20],
    /// The callee; for a create, the new contract — `None` when it failed.
    pub to: Option<[u8; 20]>,
    /// `None` for a `STATICCALL`, which carries no value (geth omits the field).
    pub value: Option<U256>,
    /// The gas the frame was given; the top frame's is the transaction's limit.
    pub gas: u64,
    /// What the frame used; the top frame's is the transaction's, after refunds.
    pub gas_used: u64,
    pub input: Vec<u8>,
    /// The return data — on success, or a revert's payload. Empty is `None`.
    pub output: Option<Vec<u8>>,
    /// geth's error string: `execution reverted`, `out of gas`, …
    pub error: Option<String>,
    /// A revert's `Error(string)` or `Panic(uint256)` reason, decoded as geth decodes it.
    pub revert_reason: Option<String>,
    pub calls: Vec<CallFrame>,
    pub logs: Vec<CallLog>,
}

/// A log a frame emitted (geth's `callLog`): `index` counts the run's logs
/// (those a revert discarded do not count), `position` is the number of
/// sub-calls the frame had made when it emitted the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub index: u64,
    pub position: u64,
}

/// One account of a `prestateTracer` answer, as it stood before the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrestateAccount {
    pub balance: U256,
    pub nonce: u64,
    /// `None` without code, or under `disableCode`.
    pub code: Option<Vec<u8>>,
    /// `None` without code.
    pub code_hash: Option<[u8; 32]>,
    /// The slots the run touched; `None` under `disableStorage`. geth omits an
    /// empty map, as the serializer does.
    pub storage: Option<BTreeMap<[u8; 32], [u8; 32]>>,
}

/// A `debug_traceCall` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trace {
    /// Boxed: a frame is far larger than the prestate's map handle.
    Call(Box<CallFrame>),
    Prestate(BTreeMap<[u8; 20], PrestateAccount>),
}

/// What the run touched that a `prestateTracer` reports, before the values
/// are read ([`crate::executor`] reads them from the run's database, which a
/// run never writes, so they are the state before it).
#[derive(Debug, Default)]
pub(crate) struct Touched {
    pub accounts: BTreeSet<Address>,
    pub slots: BTreeMap<Address, BTreeSet<B256>>,
    /// Accounts reached by a call (or the transaction's `to`): when one holds
    /// an EIP-7702 delegation, its delegate is looked up too, as geth does.
    pub call_targets: BTreeSet<Address>,
}

#[derive(Debug, Default)]
struct State {
    // callTracer
    stack: Vec<CallFrame>,
    root: Option<CallFrame>,
    /// Open frames, the top one included.
    depth: usize,
    /// Logs the run has kept so far (geth's `log.Index`).
    log_count: u64,
    /// `log_count` as each open frame began: a failed frame's logs are
    /// discarded, and with them their indexes.
    log_marks: Vec<u64>,
    /// Per open frame, the last opcode it stepped and its stack height then —
    /// for geth's wording of an invalid opcode or a stack fault.
    last_op: Vec<(u8, usize)>,
    // prestateTracer
    touched: Touched,
}

/// Records one tracer's view of a run (see the module comment).
pub(crate) struct TraceRecorder {
    tracer: Tracer,
    state: RefCell<State>,
}

impl TraceRecorder {
    pub fn new(tracer: Tracer) -> TraceRecorder {
        TraceRecorder { tracer, state: RefCell::new(State::default()) }
    }

    pub fn tracer(&self) -> Tracer {
        self.tracer
    }

    /// Back to nothing, at the start of each run.
    pub fn reset(&self) {
        *self.state.borrow_mut() = State::default();
    }

    fn only_top_call(&self) -> bool {
        matches!(self.tracer, Tracer::Call { only_top_call: true, .. })
    }

    /// Whether frames are built: the callTracer's tree. The prestateTracer
    /// keeps only the depth and log bookkeeping.
    fn frames(&self) -> bool {
        matches!(self.tracer, Tracer::Call { .. })
    }

    /// Before each opcode.
    pub fn step(&self, interp: &Interpreter) {
        let op = interp.bytecode.opcode();
        let mut st = self.state.borrow_mut();
        if let Some(last) = st.last_op.last_mut() {
            *last = (op, interp.stack.len());
        }
        if !matches!(self.tracer, Tracer::Prestate { .. }) {
            return;
        }
        let address_in = |word: U256| Address::from_word(B256::from(word.to_be_bytes::<32>()));
        let len = interp.stack.len();
        match op {
            opcode::SLOAD | opcode::SSTORE if len >= 1 => {
                if let Ok(slot) = interp.stack.peek(0) {
                    st.touched
                        .slots
                        .entry(interp.input.target_address)
                        .or_default()
                        .insert(B256::from(slot.to_be_bytes::<32>()));
                    st.touched.accounts.insert(interp.input.target_address);
                }
            }
            opcode::EXTCODECOPY
            | opcode::EXTCODEHASH
            | opcode::EXTCODESIZE
            | opcode::BALANCE
            | opcode::SELFDESTRUCT
                if len >= 1 =>
            {
                if let Ok(word) = interp.stack.peek(0) {
                    st.touched.accounts.insert(address_in(word));
                }
            }
            opcode::DELEGATECALL | opcode::CALL | opcode::STATICCALL | opcode::CALLCODE if len >= 5 => {
                if let Ok(word) = interp.stack.peek(1) {
                    let target = address_in(word);
                    st.touched.accounts.insert(target);
                    st.touched.call_targets.insert(target);
                }
            }
            _ => {}
        }
    }

    /// A call frame begins. `input` yields its calldata, and is called only
    /// when the frame is recorded: a `prestateTracer` run and `onlyTopCall`'s
    /// inner frames need the depth and log bookkeeping, not a copy of the input.
    pub fn call(&self, inputs: &CallInputs, input: impl FnOnce() -> Vec<u8>) {
        let mut st = self.state.borrow_mut();
        let depth = st.depth;
        st.depth += 1;
        let mark = st.log_count;
        st.log_marks.push(mark);
        st.last_op.push((0, 0));
        if !self.frames() || (depth > 0 && self.only_top_call()) {
            return;
        }
        let (kind, from, to, value) = match inputs.scheme {
            CallScheme::Call => (FrameKind::Call, inputs.caller, inputs.target_address, Some(call_value(&inputs.value))),
            CallScheme::StaticCall => (FrameKind::StaticCall, inputs.caller, inputs.target_address, None),
            // geth's from is the contract that delegates (revm's target, whose
            // storage the code runs on) and its to the code's account.
            CallScheme::DelegateCall => {
                (FrameKind::DelegateCall, inputs.target_address, inputs.bytecode_address, Some(call_value(&inputs.value)))
            }
            CallScheme::CallCode => {
                (FrameKind::CallCode, inputs.target_address, inputs.bytecode_address, Some(call_value(&inputs.value)))
            }
        };
        st.stack.push(CallFrame {
            kind,
            from: from.into_array(),
            to: Some(to.into_array()),
            value,
            gas: inputs.gas_limit,
            gas_used: 0,
            input: input(),
            output: None,
            error: None,
            revert_reason: None,
            calls: Vec::new(),
            logs: Vec::new(),
        });
    }

    /// A create frame begins.
    pub fn create(&self, inputs: &CreateInputs) {
        let mut st = self.state.borrow_mut();
        let depth = st.depth;
        st.depth += 1;
        let mark = st.log_count;
        st.log_marks.push(mark);
        st.last_op.push((0, 0));
        // geth's prestateTracer looks a CREATE2's address up at the opcode,
        // whether or not the create then succeeds; it needs no nonce. (A CREATE's
        // address is recorded at its end: the caller's nonce is not readable
        // here without warming an account, and a collision there would need a
        // nonce-derived address that already holds code.)
        if let revm::context_interface::CreateScheme::Create2 { .. } = inputs.scheme() {
            st.touched.accounts.insert(inputs.created_address(0));
        }
        if !self.frames() || (depth > 0 && self.only_top_call()) {
            return;
        }
        let kind = match inputs.scheme() {
            revm::context_interface::CreateScheme::Create2 { .. } => FrameKind::Create2,
            _ => FrameKind::Create,
        };
        st.stack.push(CallFrame {
            kind,
            from: inputs.caller().into_array(),
            to: None,
            value: Some(inputs.value()),
            gas: inputs.gas_limit(),
            gas_used: 0,
            input: inputs.init_code().to_vec(),
            output: None,
            error: None,
            revert_reason: None,
            calls: Vec::new(),
            logs: Vec::new(),
        });
    }

    /// A call or create frame ends with `result`; `created` is a create's new
    /// address.
    pub fn end(&self, result: &InterpreterResult, created: Option<Address>) {
        let mut st = self.state.borrow_mut();
        st.depth = st.depth.saturating_sub(1);
        let mark = st.log_marks.pop().unwrap_or(st.log_count);
        let (op, stack_len) = st.last_op.pop().unwrap_or((0, 0));
        if !result.result.is_ok() {
            // The journal drops a failed frame's logs, and the count with them.
            st.log_count = mark;
        }
        if created.is_some() {
            st.touched.accounts.extend(created);
        }
        if !self.frames() || (st.depth > 0 && self.only_top_call()) {
            return;
        }
        let Some(mut frame) = st.stack.pop() else { return };
        frame.gas_used = result.gas.total_gas_spent();
        if matches!(frame.kind, FrameKind::Create | FrameKind::Create2) {
            frame.to = created.map(Address::into_array);
        }
        process_output(&mut frame, result, op, stack_len);
        match st.stack.last_mut() {
            Some(parent) => parent.calls.push(frame),
            None => st.root = Some(frame),
        }
    }

    /// A `SELFDESTRUCT`: geth records it as a frame of its own under the one
    /// that ran it, with no gas and the balance it moved.
    pub fn selfdestruct(&self, contract: Address, target: Address, value: U256) {
        let mut st = self.state.borrow_mut();
        if !self.frames() || self.only_top_call() {
            return;
        }
        let frame = CallFrame {
            kind: FrameKind::SelfDestruct,
            from: contract.into_array(),
            to: Some(target.into_array()),
            value: Some(value),
            gas: 0,
            gas_used: 0,
            input: Vec::new(),
            output: None,
            error: None,
            revert_reason: None,
            calls: Vec::new(),
            logs: Vec::new(),
        };
        if let Some(parent) = st.stack.last_mut() {
            parent.calls.push(frame);
        }
    }

    /// A log, emitted by the frame running now.
    pub fn log(&self, log: &Log) {
        let mut st = self.state.borrow_mut();
        let index = st.log_count;
        st.log_count += 1;
        let Tracer::Call { only_top_call, with_log: true } = self.tracer else { return };
        if only_top_call && st.depth > 1 {
            return;
        }
        if let Some(frame) = st.stack.last_mut() {
            let position = frame.calls.len() as u64;
            frame.logs.push(CallLog {
                address: log.address.into_array(),
                topics: log.data.topics().iter().map(|t| t.0).collect(),
                data: log.data.data.to_vec(),
                index,
                position,
            });
        }
    }

    /// The call tree once the run is over: the top frame's gas is the
    /// transaction's limit and its gas used the transaction's (geth's
    /// `OnTxStart` / `OnTxEnd`), and a failed frame's logs are cleared, with
    /// those of every frame under it (geth's `clearFailedLogs`).
    pub fn call_tree(&self, gas_limit: u64, tx_gas_used: u64) -> Option<CallFrame> {
        let mut root = self.state.borrow_mut().root.take()?;
        root.gas = gas_limit;
        root.gas_used = tx_gas_used;
        clear_failed_logs(&mut root, false);
        Some(root)
    }

    /// What the run touched, for a `prestateTracer` answer.
    pub fn touched(&self) -> Touched {
        std::mem::take(&mut self.state.borrow_mut().touched)
    }
}

fn call_value(value: &CallValue) -> U256 {
    match value {
        CallValue::Transfer(v) | CallValue::Apparent(v) => *v,
    }
}

/// geth's `processOutput`: a success keeps its return data; a failure gets
/// geth's error string, a failed create loses its `to`, and a revert keeps its
/// payload with the reason decoded from it.
fn process_output(frame: &mut CallFrame, result: &InterpreterResult, op: u8, stack_len: usize) {
    if result.result.is_ok() {
        frame.output = (!result.output.is_empty()).then(|| result.output.to_vec());
        return;
    }
    frame.error = Some(error_string(result.result, op, stack_len));
    if matches!(frame.kind, FrameKind::Create | FrameKind::Create2) {
        frame.to = None;
    }
    if result.result != InstructionResult::Revert || result.output.is_empty() {
        return;
    }
    frame.output = Some(result.output.to_vec());
    frame.revert_reason = unpack_revert(&result.output);
}

/// A frame failed: geth's `failed()` — an error, under a reverted snapshot,
/// which every error is since Homestead.
fn failed(frame: &CallFrame) -> bool {
    frame.error.is_some()
}

fn clear_failed_logs(frame: &mut CallFrame, parent_failed: bool) {
    let failed = failed(frame) || parent_failed;
    if failed {
        frame.logs.clear();
    }
    for call in &mut frame.calls {
        clear_failed_logs(call, failed);
    }
}

/// geth's error for a frame that ended with `result` (`core/vm/errors.go`).
/// `op` and `stack_len` are the frame's last opcode and its stack height
/// then, which geth's invalid-opcode and stack-fault messages name.
///
/// Where geth has no single string, the frame's error is this crate's own
/// wording: a failed precompile carries the precompile's own message in geth
/// (blake2f's `invalid input length`, …), but revm reduces every such halt to
/// `PrecompileError` before an inspector sees the frame end, so it reads
/// `precompile failed` here. Results no plain request reaches fall back to
/// revm's name for them.
pub(crate) fn error_string(result: InstructionResult, op: u8, stack_len: usize) -> String {
    use InstructionResult as R;
    let info = opcode::OPCODE_INFO[op as usize];
    match result {
        R::Revert => "execution reverted".into(),
        R::OutOfGas | R::MemoryOOG | R::MemoryLimitOOG | R::PrecompileOOG | R::InvalidOperandOOG
        | R::ReentrancySentryOOG => "out of gas".into(),
        R::CallTooDeep => "max call depth exceeded".into(),
        R::OutOfFunds => "insufficient balance for transfer".into(),
        R::CreateCollision => "contract address collision".into(),
        R::CreateContractSizeLimit => "max code size exceeded".into(),
        R::CreateInitCodeSizeLimit => "max initcode size exceeded".into(),
        R::InvalidJump => "invalid jump destination".into(),
        R::StateChangeDuringStaticCall | R::CallNotAllowedInsideStatic => "write protection".into(),
        R::OutOfOffset => "return data out of bounds".into(),
        R::OverflowPayment => "gas uint64 overflow".into(),
        R::CreateContractStartingWithEF => "invalid code: must not begin with 0xef".into(),
        R::NonceOverflow => "nonce uint64 overflow".into(),
        R::InvalidFEOpcode => "invalid opcode: INVALID".into(),
        R::OpcodeNotFound | R::NotActivated => format!("invalid opcode: {}", opcode_name(op)),
        R::StackUnderflow => match info {
            Some(info) => format!("stack underflow ({stack_len} <=> {})", info.inputs()),
            None => "stack underflow".into(),
        },
        R::StackOverflow => match info {
            // geth's limit for an opcode: the 1024-item stack, less what it
            // pushes beyond what it pops.
            Some(info) => {
                let limit = 1024 + usize::from(info.inputs()) - usize::from(info.outputs());
                format!("stack limit reached {stack_len} ({limit})")
            }
            None => "stack overflow".into(),
        },
        R::PrecompileError => "precompile failed".into(),
        other => format!("{other:?}"),
    }
}

/// geth's name for an opcode (`OpCode.String`): its mnemonic, or
/// `opcode 0x… not defined`.
fn opcode_name(op: u8) -> String {
    match opcode::OpCode::new(op) {
        Some(code) => code.as_str().to_string(),
        None => format!("opcode {op:#x} not defined"),
    }
}

/// geth's `abi.UnpackRevert`: an `Error(string)`'s message, a `Panic(uint256)`'s
/// reason, or `None` for anything else (or a malformed encoding).
pub(crate) fn unpack_revert(data: &[u8]) -> Option<String> {
    const ERROR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
    const PANIC: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];
    if data.len() < 4 {
        return None;
    }
    let (selector, body) = data.split_at(4);
    let word = |at: usize| -> Option<U256> { body.get(at..at.checked_add(32)?).map(U256::from_be_slice) };
    if selector == ERROR {
        let offset = usize::try_from(word(0)?).ok()?;
        let len = usize::try_from(word(offset)?).ok()?;
        let start = offset.checked_add(32)?;
        let bytes = body.get(start..start.checked_add(len)?)?;
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }
    if selector == PANIC {
        let code = word(0)?;
        let reason = match u64::try_from(code) {
            Ok(0x00) => "generic panic",
            Ok(0x01) => "assert(false)",
            Ok(0x11) => "arithmetic underflow or overflow",
            Ok(0x12) => "division or modulo by zero",
            Ok(0x21) => "enum overflow",
            Ok(0x22) => "invalid encoded storage byte array accessed",
            Ok(0x31) => "out-of-bounds array access; popping on an empty array",
            Ok(0x32) => "out-of-bounds access of an array or bytesN",
            Ok(0x41) => "out of memory",
            Ok(0x51) => "uninitialized function",
            _ => return Some(format!("unknown panic code: {code:#x}")),
        };
        return Some(reason.to_string());
    }
    None
}

/// The accounts a `prestateTracer` looks up before the run (geth's
/// `OnTxStart`): the sender, the recipient (for a creation, the address the
/// contract gets), the block's coinbase, and each EIP-7702 authority whose
/// signature recovers.
pub(crate) fn tx_start_accounts(tx: &TxRequest, created: Option<Address>, coinbase: Address) -> Vec<Address> {
    let mut out = vec![Address::from(tx.from)];
    match tx.to {
        Some(to) => out.push(Address::from(to)),
        None => out.extend(created),
    }
    out.push(coinbase);
    for auth in tx.authorization_list.iter().flatten() {
        let signed = revm::context_interface::transaction::SignedAuthorization::new_unchecked(
            revm::context_interface::transaction::Authorization {
                chain_id: auth.chain_id,
                address: Address::from(auth.address),
                nonce: auth.nonce,
            },
            auth.y_parity,
            auth.r,
            auth.s,
        );
        if let Ok(authority) = signed.recover_authority() {
            out.push(authority);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi_error(message: &str) -> Vec<u8> {
        let mut out = vec![0x08, 0xc3, 0x79, 0xa0];
        out.extend(U256::from(32).to_be_bytes::<32>());
        out.extend(U256::from(message.len()).to_be_bytes::<32>());
        let mut body = message.as_bytes().to_vec();
        body.resize(message.len().div_ceil(32) * 32, 0);
        out.extend(body);
        out
    }

    #[test]
    fn unpacks_reverts_as_geth_does() {
        assert_eq!(unpack_revert(&abi_error("nope")).as_deref(), Some("nope"));
        let mut panic = vec![0x4e, 0x48, 0x7b, 0x71];
        panic.extend(U256::from(0x11).to_be_bytes::<32>());
        assert_eq!(unpack_revert(&panic).as_deref(), Some("arithmetic underflow or overflow"));
        panic[4 + 31] = 0x99;
        assert_eq!(unpack_revert(&panic).as_deref(), Some("unknown panic code: 0x99"));
        // A custom error, a short payload, a truncated string: no reason.
        assert_eq!(unpack_revert(&[0xde, 0xad, 0xbe, 0xef, 0x00]), None);
        assert_eq!(unpack_revert(&[0x08, 0xc3]), None);
        let truncated = abi_error("nope");
        assert_eq!(unpack_revert(&truncated[..4 + 64]), None);
    }

    #[test]
    fn errors_read_as_geths() {
        assert_eq!(error_string(InstructionResult::Revert, 0, 0), "execution reverted");
        assert_eq!(error_string(InstructionResult::MemoryOOG, 0, 0), "out of gas");
        assert_eq!(error_string(InstructionResult::InvalidFEOpcode, 0xfe, 0), "invalid opcode: INVALID");
        assert_eq!(error_string(InstructionResult::OpcodeNotFound, 0x0c, 0), "invalid opcode: opcode 0xc not defined");
        // ADD pops two: one item is one short.
        assert_eq!(error_string(InstructionResult::StackUnderflow, opcode::ADD, 1), "stack underflow (1 <=> 2)");
        // PUSH1 pops none and pushes one: the limit is 1023.
        assert_eq!(error_string(InstructionResult::StackOverflow, opcode::PUSH1, 1024), "stack limit reached 1024 (1023)");
        assert_eq!(error_string(InstructionResult::StateChangeDuringStaticCall, 0, 0), "write protection");
        // revm drops the precompile's own message before the frame ends.
        assert_eq!(error_string(InstructionResult::PrecompileError, 0, 0), "precompile failed");
    }
}
