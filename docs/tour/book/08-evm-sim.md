# myotis-evm, part 2: simulation, tracing and fixtures

*Stop 8 · crate `myotis-evm`, plus one `myotis-net` example* · 11 files · 5,254 lines · about 155 minutes

Stop 7 showed the one verified EVM run behind `eth_call`. This stop covers what has been built on top of that run since September: the full JSON-RPC transaction object (`TxRequest`, with EIP-7702 authorization lists), the two tracers of `debug_traceCall`, and `eth_simulateV1`, which runs whole blocks of calls on top of a verified block. It ends with the test machinery that replays a real mainnet RAILGUN shield from a **recorded world**: every account, slot and bytecode the EVM read, saved as JSON and served back by an oracle that refuses anything it was not given. The Rust lessons are **interior mutability on one thread** (`RefCell` recorders behind shared references), **enums that carry data**, and **test-only code** that never reaches the shipped library.

## Rust you will practise

- **RefCell recorders** — state mutated through `&self`, borrow scopes that must not overlap, `drop(guard)`, and why a `Mutex` appears only where the type must be `Sync`.
- **Enums and patterns** `Fees`, `Tracer`, `Trace` and a recursive `Abi`; tuple matches with guards, `let … else`, `name @ Pattern`, nested or-patterns.
- **Test-only code** `#[cfg(test)]` modules in their own files, `cfg(any(test, feature = "fixture"))`, a crate that depends on itself, `OnceLock`, `include_str!` and `env!`.

## One run, several recorders

None of these files existed in the September tour. They share one design idea. revm lets you attach an *inspector* to a run: an object whose hooks revm calls before every opcode (`step`), when a call or create frame opens and closes, when a log is emitted, and on `SELFDESTRUCT`. `executor.rs` (stop 7) has exactly one inspector type, `RequestInspector`. It holds a set of *optional* recorders, and each hook forwards to whichever ones are present. The tracer of `debug_traceCall` and the log recorder of `eth_simulateV1` are two of those recorders.

`rust/myotis-evm/src/executor.rs` · lines 52–73

```rust
pub(crate) struct RequestInspector<'a> {
    pub(crate) oracle: &'a dyn SnapStateOracle,
    /// Records, during a discovery pass, the accounts whose code the run
    /// needed: the account each call runs the code of
    /// (`CallInputs::bytecode_address`), and the one an `EXTCODESIZE` or
    /// `EXTCODECOPY` inspects. Solidity guards a call to a contract with an
    /// `EXTCODESIZE`, and against a placeholder (no code) that guard fails
    /// before the call runs, so the target shows there a pass earlier. The
    /// pass's wave fetches the code of these and no other (#532 review).
    /// `None` outside discovery passes.
    pub(crate) code_needed: Option<&'a CodeNeeded>,
    /// Records, for `eth_createAccessList`, every address and storage key the
    /// run touches ([`AccessListRecorder`]). `None` on every other run.
    pub(crate) access_list: Option<&'a AccessListRecorder>,
    /// Records, for `debug_traceCall`, the tracer's view of the run
    /// ([`TraceRecorder`]). `None` on every other run.
    pub(crate) trace: Option<&'a TraceRecorder>,
    /// Records, for `eth_simulateV1`, each call's logs and transfers and
    /// stops a run that reads what the simulation cannot serve
    /// ([`SimRecorder`]). `None` on every other run.
    pub(crate) sim: Option<&'a SimRecorder>,
}
```

Every field is a shared reference, `&'a`. The inspector owns nothing; the request's code owns each recorder on its stack and lends it to the inspector for the run. But recorders must change as the run goes on, and a shared reference does not allow mutation. So each recorder keeps its state in a `RefCell` and mutates it through `&self`. That is the pattern you will see in `trace.rs` and `simulate.rs`.

> [!TIP]
> **Why RefCell and not Mutex**<br>A `RefCell<T>` checks borrows at run time: `borrow_mut()` hands out a `RefMut` guard, and a second `borrow_mut()` while the first guard lives panics. It costs a counter, not a lock, and it is not `Sync`, so a type holding one cannot be shared between threads. That fits: one EVM run executes on one blocking thread from start to end (the reader in `myotis-net` wraps each `simulate` and `trace_call` call in its `blocking` helper). If anyone tried to move a `&TraceRecorder` to another thread, compilation would fail. The oracle, by contrast, is shared across threads behind `Arc<dyn SnapStateOracle>`, whose trait requires `Send + Sync`; that is why `RecordingOracle` later in this stop uses a `Mutex`.

> [!NOTE]
> **Java/Kotlin view**<br>An inspector is a listener interface with default no-op methods, like an `EventListener` in OkHttp. The difference is ownership: in Java the listener would keep references to its collaborators forever. Here the borrow checker proves that every recorder outlives the run that borrows it.

![revm calls the hooks of one RequestInspector. It forwards each hook to the recorders that are present: code_needed for the prefetch loop's discovery passes, access_list for eth_createAccessList, trace for debug_traceCall, and sim for eth_simulateV1. Each recorder is borrowed for the run and keeps its state in a RefCell.](img/08-evm-sim-1.svg)

One more piece from stop 7 matters here: the **prefetch loop** (`converge_runs`). It runs the EVM several times, first in a discovery mode where missing state reads as a placeholder zero, then for real. A recorder therefore sees several runs. Each one is reset (or created fresh) at the start of every run, so what it holds when the loop settles describes the run whose answer is returned, never a discovery pass.

<a id="f-myotis-evm-src-tx-rs"></a>

### myotis-evm/src/tx.rs

*library · 349 lines*

`TxRequest` is the JSON-RPC transaction object (geth's `TransactionArgs`) in the form the executor applies it. It exists because of #509: a type-4 `eth_estimateGas` whose `authorizationList` was silently dropped ran against an account with no code, answered about 59k gas for a transaction that needs several hundred thousand, and the wallet's real transaction ran out of gas on chain. The module doc states the rule this file enforces: every field that changes the answer is applied, or the request is refused by `TxRequest::validate`. Each field's meaning follows geth, so a wallet gets the same answer from Myotis as from a public node.

`rust/myotis-evm/src/tx.rs` · lines 76–100

```rust
/// The fee fields, normalized. geth refuses `gasPrice` together with either
/// EIP-1559 field, so a request carries at most one of the two models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fees {
    /// No fee field: the run is priced at zero (GASPRICE reads 0) and the
    /// sender's balance does not bound the estimate.
    #[default]
    None,
    /// `gasPrice`.
    Legacy { gas_price: u128 },
    /// `maxFeePerGas` / `maxPriorityFeePerGas` (either may be absent = 0).
    DynamicFee { max_fee_per_gas: u128, max_priority_fee_per_gas: u128 },
}

impl Fees {
    /// The fee cap geth's affordability rule divides by: `maxFeePerGas` for a
    /// dynamic-fee request, else `gasPrice`, else zero (no cap).
    pub fn fee_cap(&self) -> u128 {
        match *self {
            Fees::None => 0,
            Fees::Legacy { gas_price } => gas_price,
            Fees::DynamicFee { max_fee_per_gas, .. } => max_fee_per_gas,
        }
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **An enum that makes a bad state unrepresentable.** geth refuses `gasPrice` together with the EIP-1559 fields, so `Fees` holds one fee model or none. Compare a Java class with three nullable fields, where "both set" would be a state every reader has to check for. Each variant carries its own data, like a Kotlin `sealed class` with data-class subclasses.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `#[derive(Default)]` on an enum needs one variant marked `#[default]`. All fields are `u128`, so the enum can also derive `Copy`: it is copied bit for bit, like a primitive.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Ownership & moves](01-primer.md#primer-ownership)* `match *self` matches on the value behind the reference. That is allowed only because `Fees` is `Copy`: the bound `gas_price` is a copied `u128`. For a non-`Copy` type you would write `match self` and get references to the fields instead. `DynamicFee { max_fee_per_gas, .. }` ignores the other field with `..`.

The struct itself (lines 105–130) is plain data: `from`, `to: Option<[u8; 20]>` (`None` is contract creation), `data`, `value`, and then a row of `Option`s, one per optional JSON field. `TxRequest::call` builds the plain four-field subset that older entry points carry, with every other field absent. The transaction *type* is a `u8` with five constants, not an enum. A plausible reason, which the code does not state: the type comes from the request and may be any byte (a test feeds it `0x7e`), and `validate` must be able to hold it in order to refuse it with a message. `tx_type()` returns the explicit type, or derives one in revm's order: an authorization list makes 4, EIP-1559 fees make 2, a non-empty access list makes 1, anything else 0.

`rust/myotis-evm/src/tx.rs` · lines 210–224

```rust
match (&self.authorization_list, ty) {
    (None, TYPE_SET_CODE) => {
        return Err("transaction type 0x4 requires an authorizationList".into())
    }
    (Some(_), t) if t != TYPE_SET_CODE => {
        return Err(format!(
            "authorizationList requires transaction type 0x4 (the request names \
             type 0x{t:x})"
        ))
    }
    (Some(list), _) if list.is_empty() => {
        return Err("authorizationList must not be empty (EIP-7702)".into())
    }
    _ => {}
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Matching a tuple with guards.** `(&self.authorization_list, ty)` builds a temporary tuple of a *reference* and a `u8`. Matching through the reference means `list` binds as `&Vec<Authorization>`: nothing is moved out of `self`, which a `&self` method could not do anyway. Arms are tried top to bottom, and an `if` guard can reject an arm whose pattern matched. The last arm, `_ => {}`, makes the match exhaustive.
- *[Protocol & domain](01-primer.md#primer-domain) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Three kinds of "nothing".** For both lists, `None` means "the field was absent" and `Some(vec![])` means "an empty list was sent". They are treated differently: an empty access list is accepted because it changes nothing, but an empty authorization list is refused, as EIP-7702 requires.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `validate` returns `Result<(), String>`: success carries nothing, failure a message. The executor turns that string into a permanent refusal. The remaining checks (lines 225–233) refuse a type-4 creation and a nonce of `u64::MAX` (EIP-2681).
- *[Tests](01-primer.md#primer-testing)* The inline `#[cfg(test)] mod tests` (lines 238–349) pins each contradiction by the text of its error, with `unwrap_err().contains(…)`.

<a id="f-myotis-evm-src-trace-rs"></a>

### myotis-evm/src/trace.rs

*library · 616 lines*

`debug_traceCall`'s two tracers, as geth defines them: `callTracer` (the tree of call frames, with gas, input, output, errors and optionally logs) and `prestateTracer` (every account and slot the run touched, as it stood before the run). The tracing runs over the same verified run and prefetch loop as `eth_call`. Only the options listed in the module doc are served; the host refuses every other one, and `diffMode` is not served. The executor's `trace_call` (stop 7's file) builds a `TraceRecorder`, runs the loop with it, and then assembles the answer: the call tree, or the prestate read back from the run's database.

`rust/myotis-evm/src/trace.rs` · lines 26–43

```rust
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
```

`rust/myotis-evm/src/trace.rs` · lines 121–127

```rust
/// A `debug_traceCall` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trace {
    /// Boxed: a frame is far larger than the prestate's map handle.
    Call(Box<CallFrame>),
    Prestate(BTreeMap<[u8; 20], PrestateAccount>),
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Options live inside their variant.** `onlyTopCall` only exists for the call tracer, so it is a field of `Tracer::Call`, not a loose flag beside an enum. The recorder asks questions like `matches!(self.tracer, Tracer::Call { only_top_call: true, .. })`: a pattern with a literal inside it, evaluated to a `bool`.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Why `Box<CallFrame>`.** An enum value is as large as its largest variant. A `CallFrame` is a big struct (several `Vec`s and `Option`s), while a `BTreeMap` is a small handle to heap data. Boxing the frame moves it to the heap and keeps `Trace` small; Clippy's `large_enum_variant` lint suggests exactly this. Java never faces the question, because every object is behind a reference already.

The recorder is `TraceRecorder { tracer: Tracer, state: RefCell<State> }` (lines 161–164). `State` holds a stack of open frames, the finished root, the depth, a log counter, and the prestate's `Touched` sets. `reset` writes `*self.state.borrow_mut() = State::default()`: assigning through the `RefMut` drops the old state and puts a fresh one in its place. In `step`, a prestate run peeks at the stack before `SLOAD`/`SSTORE`, the `EXT*` opcodes, `BALANCE`, `SELFDESTRUCT` and the four call opcodes to learn which accounts and slots will be touched.

`rust/myotis-evm/src/trace.rs` · lines 238–247

```rust
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
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Ownership & moves](01-primer.md#primer-ownership)* **A lazy argument.** `input: impl FnOnce() -> Vec<u8>` is a closure that produces the calldata. The executor passes `|| inputs.input.bytes(context).to_vec()`, so the copy is made only on line 267, when the frame is actually recorded. A prestate run, and the inner frames under `onlyTopCall`, return early and never call it. `FnOnce` is the weakest closure bound: the closure may be called at most once, which is all this needs. In Kotlin you would pass a `() -> ByteArray` lambda for the same reason.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Borrowing & slices](01-primer.md#primer-borrowing)* `let mut st = self.state.borrow_mut();` holds the `RefMut` guard until the function returns, early `return` included. The borrow is released when `st` goes out of scope.

`rust/myotis-evm/src/trace.rs` · lines 317–342

```rust
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
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Building a tree without parent pointers.** Open frames live in `st.stack`, a `Vec`. When a frame ends, `pop()` moves it out of the stack by value. `let Some(mut frame) = … else { return };` is a *let-else*: bind on the matching pattern, otherwise run the `else` block, which must leave the function. The finished frame is then *moved* into its parent's `calls` vector, or becomes the root. Each frame has exactly one owner at every moment, so no `Rc` or parent reference is needed. A Java version would typically keep a mutable parent pointer in every node.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `st.stack.last_mut()` is a mutable borrow of the last element, used once for `push`. The match arms show why it is `Option`: an empty stack means the frame was the top one.
- *[Protocol & domain](01-primer.md#primer-domain)* A failed frame resets `log_count` to the mark taken when it began, because the EVM discards a reverted frame's logs and their indexes with it. After the run, `call_tree` also clears the logs of every failed frame and of everything under it (`clear_failed_logs`, a short recursion over `&mut frame.calls`).

`rust/myotis-evm/src/trace.rs` · lines 509–523

```rust
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
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `unpack_revert` decodes a revert's `Error(string)` the way geth does. The payload comes from contract code, so every offset in it is untrusted. Each step uses a tool that returns `None` instead of panicking: `body.get(range)` rather than `body[range]` (slice indexing panics when out of bounds), `checked_add` rather than `+` (which panics on overflow in debug builds), and `usize::try_from(…).ok()`. The `?` operator works on `Option` too: inside a function returning `Option`, `x?` returns `None` early. `String::from_utf8_lossy` replaces invalid bytes rather than failing, and `into_owned` turns its `Cow` into a `String`. The rest of the file maps revm's `InstructionResult` to geth's error strings (`error_string`), names `Panic(uint256)` codes, and lists the accounts geth's prestate tracer looks up before the run (`tx_start_accounts`, which recovers each EIP-7702 authority from its signature).

<a id="f-myotis-evm-src-simulate-rs"></a>

### myotis-evm/src/simulate.rs

*library · 1,278 lines*

`eth_simulateV1` (#716), following geth's `internal/ethapi/simulate.go`. A request lists blocks; each block has `blockOverrides` (number, time, gas limit, fee recipient, base fee, withdrawals …), `stateOverrides` and a list of calls. The simulation starts from a verified block N, whose state every read proves against N's state root. It then builds N+1, N+2, … that exist only inside this request: each call's state changes carry over to the next call and the next block. The answer gives each block's header fields and each call's return data, logs, gas and error, in geth's words and error codes. The module doc (lines 1–56) is also a precise list of what this node *cannot* compute and therefore refuses: a simulated block's state root and hash (they need trie nodes no proof carries), the blob base fee, `requestsHash`, Amsterdam blocks, withdrawals on Gnosis, and state overrides of precompile addresses.

| Lines | What happens |
|---|---|
| 1–95 | Module doc, submodules `encode` and `tests`, imports. |
| 97–153 | geth's limits (256 blocks, 5,000 calls per block, 10,000 in all), the gas budget, geth's error codes in `mod codes`, the system-contract addresses, Gnosis's fee collector, the ERC-7528 transfer-log address and topic. |
| 155–299 | Request types (`Withdrawal`, `BlockOverrides`, `SimBlock`, `SimOptions`, `SimBase`) and answer types (`SimLog`, `SimCallError`, `SimCallResult`, `SimTransaction`, `SimulatedBlock`). |
| 301–457 | Checks before any state is read: `check_limits`, `sanitize_chain` (numbers, times, gap blocks), `plan_blocks` (fork rules per block and the refusals). |
| 459–501 | `SimDb`: the verified base database, which refuses `BLOCKHASH` of a simulated block. `SimCache` layers the simulation's writes over it. |
| 503–728 | `SimRecorder`: the logs per frame, ether transfers as logs, the top frame's error, and the reads the simulation refuses. |
| 730–767 | `Parent`, `fee_cap_and_tip`, `block_tx_type`. |
| 769–871 | `impl EvmExecutor`: `simulate` (entry point), the first prefetch wave, and one whole simulation pass. |
| 873–1229 | `Run`: one block (system calls, calls, withdrawals, roots), state overrides, system calls, and one call with geth's checks in geth's order. |
| 1231–1278 | Error mapping, `credit`, and the unsigned transaction geth puts in a block. |

`rust/myotis-evm/src/simulate.rs` · lines 58–60

```rust
mod encode;
#[cfg(test)]
mod tests;
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **Where submodules live.** `mod encode;` inside `simulate.rs` makes Cargo look for `simulate/encode.rs`. A file and a directory with the same name hold the module and its children; this is the newer layout, and `fixture/mod.rs` later in this stop shows the older one, with the parent in `mod.rs`. `#[cfg(test)] mod tests;` puts the tests in `simulate/tests.rs` and compiles them only for `cargo test`. No `#[path]` attribute is needed anywhere in this stop, because every file sits where the default rules look.

#### Settling the chain before anything runs

The request types are plain structs of `Option`s that derive `Default`: `BlockOverrides` has one `Option` per geth field, so "not overridden" is `None`. `sanitize_chain` fills in what the caller left out, as geth does.

`rust/myotis-evm/src/simulate.rs` · lines 340–394

```rust
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
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Borrowed input, owned output.** The function receives `&[SimBlock]`, a borrowed slice, and must return completed blocks. It cannot change the caller's blocks, so it clones each one (`block.clone()`) and edits the copy. The new `block` shadows the loop variable of the same name; shadowing is common in Rust and creates a new binding rather than reassigning.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `let overrides = &mut block.block_overrides;` borrows one field of the local `block` mutably. The borrow is last used on line 379, so by line 391 it has ended and `out.push(block)` may move the whole block into the vector. The compiler tracks the end of a borrow by its last use (non-lexical lifetimes), not by the closing brace.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `*overrides.number.get_or_insert(prev + 1)`: `get_or_insert` stores the value if the `Option` is `None` and returns `&mut` to its content either way; the `*` copies the `U256` out (it is `Copy`). The `match overrides.time` has a guarded arm, `Some(time) if time <= prev_time`, whose body is a `return`. A `return` expression has type `!` ("never"), which fits any arm type, so the match still evaluates to a `u64`.
- *[Methods & self](01-primer.md#primer-methods)* `BlockOverrides { number: …, time: …, ..BlockOverrides::default() }` is struct update syntax: name some fields, take the rest from another value. It replaces a builder in many Rust codebases. A gap between block numbers is filled with empty blocks 12 seconds apart, as geth does.

`plan_blocks` then picks each block's fork rules with `spec_for` (stop 7) and refuses, before any state is read: a difficulty override, an Amsterdam block, a base fee above 264−1, a state override of a precompile's address, and withdrawals on Gnosis.

#### Where simulated writes go

`rust/myotis-evm/src/simulate.rs` · lines 462–501

```rust
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
```

- *[Lifetimes](01-primer.md#primer-lifetimes)* **A struct that borrows.** `SimDb<'a>` holds two references: to the verified `OracleDatabase` and to the recorder's refusal cell. The lifetime parameter says "a `SimDb` cannot outlive what it points to". In `impl DatabaseRef for SimDb<'_>`, `'_` means "some lifetime I don't need to name".
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* revm's `DatabaseRef` is a read-only database trait whose methods take `&self`. `type Error = OracleError;` is an *associated type*: each implementation picks its error type once, instead of the trait being generic over it. Three methods delegate to the base; only `block_hash_ref` adds behaviour.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `block_hash_ref` takes `&self` but must record why it refused. It does so through the shared `&RefCell<Option<String>>`, which the recorder also holds. `get_or_insert_with(|| format!(…))` keeps the *first* refusal, and the closure (and its `format!` allocation) runs only when the cell is still empty.
- *[Protocol & domain](01-primer.md#primer-domain)* `type SimCache<'a> = CacheDB<SimDb<'a>>`. revm's `CacheDB` keeps its own maps of accounts and storage over a read-only database: reads fall through to `SimDb` once, and every write stays in the `CacheDB`. That is how "state carries from call to call" while nothing is ever written into a cache another request reads. The cache lives for one pass of the prefetch loop and is then dropped.

#### The recorder

`SimRecorder` (lines 537–541) has a `trace_transfers` flag and two cells: `refusal: RefCell<Option<String>>` and `state: RefCell<SimState>`. `SimState` holds a stack of per-frame log vectors (geth's simulate tracer drops a failed frame's own logs), the next log index in the block, each open frame's last opcode and stack height (for geth's error wording), and the set of EIP-2935 history slots that hold a simulated block's unknown hash.

`rust/myotis-evm/src/simulate.rs` · lines 585–621

```rust
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
```

- *[Interior mutability](01-primer.md#primer-interior-mutability)* **Ending a borrow early.** `drop(st)` releases the `RefMut` on `state` before `self.refuse(…)` runs. `refuse` borrows the *other* cell, `refusal`, so today the two borrows would not collide. The explicit drop keeps the state borrow from overlapping anything `refuse` might do later. With `RefCell`, an overlap would compile and then panic at run time with `BorrowMutError`, so short borrow scopes are the habit to keep.
- *[Protocol & domain](01-primer.md#primer-domain)* **Refusing a read in flight.** Returning `true` tells `RequestInspector::step` to end the frame with `InstructionResult::Stop`; every frame above it stops at its next step, because the first check sees the refusal. Two reads are refused this way: `BLOBBASEFEE` without a `blobBaseFee` override, and an `SLOAD` of a poisoned EIP-2935 slot. The third, `BLOCKHASH` of a simulated block, is refused by `SimDb` above.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `if let Ok(slot) = interp.stack.peek(0)` ignores a stack too short to peek at: the opcode will then fail on its own.

The frame hooks mirror geth's tracer. `call` and `create` push an empty log vector for the new frame, and record an ether transfer as an ERC-7528 log under `traceTransfers` (a `CREATE`'s address is only known when it ends, so its log's third topic is patched then). `end` pops the frame's logs; if the frame failed, it clears them and gives their indexes back, otherwise it appends them to the parent's vector. When no parent is left, the logs are the finished call's.

#### Entry point and one pass

`rust/myotis-evm/src/simulate.rs` · lines 774–797

```rust
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
```

- *[Methods & self](01-primer.md#primer-methods) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* **An `impl` block in another module.** `EvmExecutor` is defined in `executor.rs`, yet this file adds methods to it. Any module of the same crate may write `impl EvmExecutor`; field access still follows visibility, which is why `oracle` and `runs` are `pub(crate)` in the struct. It feels like a Kotlin extension function, but these are real methods with access to crate-visible fields.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The function is a pipeline of `?`: cancellation, limits, sanitizing, planning, the fork of the base block, and each call checked as a transaction object (`check_tx`, stop 7), all before a single state read.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* The last statement hands `converge_runs` a closure that borrows `db`, `base`, `opts`, `blocks` and `plans` from this stack frame. `converge_runs` takes `impl FnMut(Option<&CodeNeeded>) -> Result<T, EvmError>` and calls it once per pass. So for a simulation, a "run" of the prefetch loop is the *whole* simulation, every block and every call.

`rust/myotis-evm/src/simulate.rs` · lines 832–869

```rust
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
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Ownership & moves](01-primer.md#primer-ownership)* **Everything a pass needs lives in this frame.** The recorder, the `CacheDB` and the `Run` are created here and dropped at the end of the function, so each pass starts from nothing. `refusal: &recorder.refusal` borrows one field of a local, and `Run { recorder: &recorder, … }` borrows the whole recorder. Both are shared borrows, so they may coexist.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `.map_err(|error| match recorder.refusal() { … })`: when a block fails and the recorder holds a refusal, the refusal's explanation replaces the low-level error. A refused `BLOCKHASH` surfaces from revm as a database error, and this is where it becomes a readable "not served".
- *[Ownership & moves](01-primer.md#primer-ownership)* `Parent` derives `Copy`; reassigning `parent` after each block simply overwrites a small value. After the first block, `hash` is `None`, because a simulated block's hash is unknown.

#### One call

`Run::call` (lines 1093–1228) applies geth's checks in geth's order: the block gas limit, the shared budget (`SIMULATE_GAS_BUDGET`, the same 30M-gas ceiling (`VIEW_CALL_GAS`) one `eth_call` has, playing the role of geth's RPC gas cap), nonces and fee caps under `validation`, init code size, and geth's `buyGas` balance check. Then it runs the call.

`rust/myotis-evm/src/simulate.rs` · lines 1176–1201

```rust
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
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Reborrowing a `&mut`.** `cache` is a `&mut SimCache` parameter. `with_db` is generic over its argument, and passing `cache` itself would *move* the mutable reference into the builder (a `&mut` is not `Copy`), leaving `cache` unusable afterwards. `&mut *cache` creates a new, shorter mutable borrow instead. The EVM is built inside a block, so it is dropped at the `}` on line 1186; the borrow ends there and `credit(cache, …)` on line 1200 may use the cache again. When the parameter type is a concrete `&mut T`, as in `credit`, the compiler inserts this reborrow for you.
- *[Methods & self](01-primer.md#primer-methods) · [Ownership & moves](01-primer.md#primer-ownership)* **A consuming builder.** `Context::mainnet().with_db(…).with_block(…).with_cfg(…)` takes each value by ownership and returns a new type each time. The builder keeps what it is given, so the shared `block_env` and `cfg` are cloned for every call.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* `self.executor.runs.fetch_add(1, Relaxed)` counts EVM runs through a shared reference with an atomic. `Relaxed` ordering is enough for a statistic that no other memory access depends on.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The order of the checks after the run matters: cancellation first, then a refusal the recorder raised, and only then revm's own result, so a refused read is reported as a refusal rather than as whatever revm made of the stopped frame.

The rest of `call` matches revm's `ExecutionResult`. `Success { output, logs: receipt_logs, .. }` renames a field while destructuring it. A revert becomes `SimCallError` with code 3, geth's decoded reason (`unpack_revert` from `trace.rs`) and the raw payload; a halt uses the top frame's last opcode for geth's wording, and adds geth's note when the gas was capped. `block_transaction` (lines 1255–1278) builds the unsigned transaction geth puts in the block, and hashes its encoding from `encode.rs`.

> [!WARNING]
> **Two derivations of a transaction type**<br> `TxRequest::tx_type()` (in `tx.rs`) and `block_tx_type` (lines 756–767 here) answer different questions and do not agree. The first is the type revm *runs*: an authorization list makes type 4. The second is the type geth *puts in the simulated block* when the caller named none: a `gasPrice` makes a legacy transaction (type 1 if any access list is present, even an empty one) whatever else the call carries, and no fee at all makes type 2. A test pins this (`a_block_transaction_is_geths_unsigned_transaction`). The doc comment says it follows geth master's `ToTransaction`.

> [!WARNING]
> **Comment slightly broader than the code**<br>The module doc (lines 22–24) says a call capped to the remaining budget "and a failure then says so". Only a halt gets the note (lines 1220–1222). A revert carries no note, and a call whose capped gas is below the intrinsic cost fails the whole request with geth's "intrinsic gas too low" text, without the note; the test on lines 495–525 pins that message.

<a id="f-myotis-evm-src-simulate-encode-rs"></a>

### myotis-evm/src/simulate/encode.rs

*library (submodule) · 122 lines*

The consensus encodings a simulated block's roots are built from: a transaction's EIP-2718 envelope (`type ‖ rlp(fields)`, legacy as plain RLP), a receipt's and a withdrawal's. `Run::block` feeds them into `myotis_core`'s `ordered_trie_root` for `transactionsRoot`, `receiptsRoot` and `withdrawalsRoot`, which this node *can* compute, unlike the state root. The RLP primitives come from `myotis-core` (stop 4).

`rust/myotis-evm/src/simulate/encode.rs` · lines 16–21

```rust
/// An RLP scalar: minimal big-endian, zero as the empty string.
fn scalar(value: U256) -> Vec<u8> {
    let be = value.to_be_bytes::<32>();
    let skip = be.iter().take_while(|&&b| b == 0).count();
    encode_bytes(&be[skip..])
}
```

`rust/myotis-evm/src/simulate/encode.rs` · lines 54–86

```rust
    let fields = match tx.tx_type {
        TYPE_LEGACY => {
            return list(&[nonce, scalar_u128(tx.gas_price), gas, to, value, input, zero(), zero(), zero()]);
        }
        TYPE_ACCESS_LIST => {
            vec![chain_id, nonce, scalar_u128(tx.gas_price), gas, to, value, input, access_list, zero(), zero(), zero()]
        }
        TYPE_DYNAMIC_FEE => vec![chain_id, nonce, tip, fee_cap, gas, to, value, input, access_list, zero(), zero(), zero()],
        // EIP-7702 (the only other type a request can name).
        _ => {
            let authorizations = list(
                &tx.authorization_list
                    .iter()
                    .flatten()
                    .map(|auth| {
                        list(&[
                            scalar(auth.chain_id),
                            encode_bytes(&auth.address),
                            encode_u64(auth.nonce),
                            encode_u64(u64::from(auth.y_parity)),
                            scalar(auth.r),
                            scalar(auth.s),
                        ])
                    })
                    .collect::<Vec<_>>(),
            );
            vec![chain_id, nonce, tip, fee_cap, gas, to, value, input, access_list, authorizations, zero(), zero(), zero()]
        }
    };
    let mut out = vec![tx.tx_type];
    out.extend(list(&fields));
    out
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* `take_while(|&&b| b == 0)`: `be.iter()` yields `&u8`, and `take_while` passes its closure a reference to each item, so the closure receives `&&u8`. The pattern `&&b` peels both references off and binds `b: u8`.
- *[Ownership & moves](01-primer.md#primer-ownership)* **Why `zero` is a closure.** Line 34 defines `let zero = || encode_u64(0);`. Each `vec![…]` takes ownership of its elements, and the zero signature fields `v`, `r`, `s` appear three times. One `Vec<u8>` cannot be moved into three places, so each `zero()` call makes a fresh one. The other fields appear in several arms, but only one arm runs, so each is moved at most once and needs no clone.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let fields = match tx.tx_type { TYPE_LEGACY => { return …; } … }`: matching a `u8` against `const` names works because constants may be used as patterns. The legacy arm returns from the whole function, because a legacy transaction has no type byte in front.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `tx.authorization_list.iter().flatten()` (and the same for the access list on line 36) iterates an `Option<Vec<T>>`: `iter()` on an `Option` yields zero or one item, and `flatten` turns that one `Vec` into its elements. `None` becomes an empty list with no special case.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `pub(super)` makes these functions visible to the parent `simulate` module and nowhere else.

<a id="f-myotis-evm-src-simulate-tests-rs"></a>

### myotis-evm/src/simulate/tests.rs

*unit tests (submodule) · 603 lines*

The simulation's unit tests over an in-memory fixture world (`FixtureSnapStateOracle`, stop 7), one test per geth rule or refusal: state carrying across calls and blocks, gap blocks, header defaults, limits and their error codes, `traceTransfers`, reverts and halts, `BLOCKHASH` and the EIP-2935 history contract, `BLOBBASEFEE`, validation, the gas budget, withdrawals, and Gnosis's fee collector. The contracts are hand-assembled EVM bytecode in hex, each with a one-line comment saying what it does. The comparison against a real full node's answer lives in the engine crate (`simulate_matches_a_full_nodes_answer`, stop 16).

`rust/myotis-evm/src/simulate/tests.rs` · lines 189–220

```rust
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
```

- *[Tests](01-primer.md#primer-testing) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* **Tests in a child module see private items.** The file starts with `use super::*;`. Because `tests` is a child of `simulate`, the glob brings in the parent's private functions and types as well (`block_tx_type`, `encode`, `GWEI`), with no `pub` needed. Java gets a similar effect only by putting tests in the same package and widening private members to package-private.
- *[Tests](01-primer.md#primer-testing)* Small helpers keep each test short: `call(to, data)`, `block(calls)`, `overrides(…)`, `code(bytes)`, `funded()`. `executor_with` (lines 121–132) builds the fixture oracle with a consuming builder in a loop, `fx = fx.with_account(…)`: the builder is moved into the method and the returned value is bound to the same name again.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `blocks.iter().map(|b| b.number).collect::<Vec<_>>()` compared with an array literal: `assert_eq!` works because `Vec<u64>` implements `PartialEq` with `[u64; 3]`.

## Recorded worlds: keeping test tooling out of the library

The remaining files are test tooling. They solve one problem: how do you test the EVM against *real* mainnet state (a RAILGUN shield touches WETH, the RAILGUN proxy, its implementation, a RelayAdapt7702 delegate and more) without a network in the test? The answer is to record once and replay many times. A recorder runs the transaction through the live engine's verified read path and keeps every account, slot and bytecode the EVM read. The replay serves exactly that world and fails any read outside it.

![Recording: the example syncs the light client, gets a verified head and a snap-proof oracle from ElReader, wraps it in a RecordingOracle, and runs measure over an executor with empty caches. The recorded world becomes an EvmFixture, which is replayed by a ReplayOracle; measure runs again and the recording fails unless the measurements match. The fixture is then written as JSON to rust/testdata. Replay in tests: the JSON file is read, a ReplayOracle serves it, measure runs, and the result is compared with the measurements stored in the file.](img/08-evm-sim-2.svg)

None of this may ship in the engine library that goes into the Android and iOS apps. Three pieces of Cargo configuration keep it out.

`rust/myotis-evm/src/lib.rs` · lines 38–51

```rust
pub mod block;
pub mod cache;
pub mod database;
pub mod ens;
pub mod error;
pub mod executor;
#[cfg(any(test, feature = "fixture"))]
pub mod fixture;
pub mod fork;
pub mod oracle;
pub mod overrides;
pub mod simulate;
pub mod trace;
pub mod tx;
```

`rust/myotis-evm/Cargo.toml` · lines 46–53

```toml
[features]
# Test tooling, off by default so it never ships in the engine .so; the crate's
# own tests see it through `cfg(test)`. The in-memory FixtureSnapStateOracle
# for downstream tests (the engine crate's EVM tests), and `fixture::` — the
# recorded-world files the mainnet fixture recorder
# (rust/myotis-net/examples/record_shield_fixture) writes and the replay tests
# read.
fixture = ["dep:serde_json"]
```

`rust/myotis-net/Cargo.toml` · lines 94–106

```toml
# The EVM fixture recorder's seam (`ElReader::head_evm_oracle`) and
# myotis-evm's recorded-world files, for examples/record_shield_fixture.rs.
# Test tooling: on only through this crate's own dev-dependency below.
fixture-recorder = ["myotis-evm/fixture"]

[dev-dependencies]
myotis-wire = { path = "../myotis-wire", features = ["test-util"] }
# readstats shape tests parse their own JSON output.
serde_json = "1"
# Tests and examples build this crate with `fixture-recorder`, so the fixture
# recorder example compiles in every `cargo test`/clippy run while the engine
# library and the shipped .so never carry its seam.
myotis-net = { path = ".", features = ["fixture-recorder"] }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **`cfg(test)` is per crate.** It is set only while compiling *this* crate's own tests. `myotis-net`'s example cannot see a `cfg(test)` item of `myotis-evm`, so the `fixture` module is also compiled under `feature = "fixture"`. The feature turns on `serde_json` through `"dep:serde_json"`: an optional dependency that exists only when the feature is on. Gradle's `testFixtures` plays a similar role.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A crate that depends on itself.** `myotis-net` lists *itself* as a dev-dependency, with its `fixture-recorder` feature on. Dev-dependencies apply only to tests, examples and benchmarks, so `cargo test` and every example build `myotis-net` with the feature, and the library the engine links does not. The feature in turn enables `myotis-evm/fixture` and the `#[cfg(feature = "fixture-recorder")]` method `ElReader::head_evm_oracle` the recorder needs. The example has no `[[example]]` entry: Cargo discovers every file in `examples/` on its own.

<a id="f-myotis-evm-src-fixture-mod-rs"></a>

### myotis-evm/src/fixture/mod.rs

*test tooling (feature fixture) · 88 lines*

The root of the recorded-world module. Its doc gives the whole design in a paragraph: a `RecordingOracle` keeps every answer, an `EvmFixture` holds the world with its block and request and round-trips through JSON, and `EvmFixture::oracle` serves only that world. It declares the three submodules (older `mod.rs` layout: the parent's code is in `fixture/mod.rs`), re-exports what callers need, and defines the bisection both the recorder and the replay use, plus a hex helper.

`rust/myotis-evm/src/fixture/mod.rs` · lines 36–50

```rust
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
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **`name @ pattern`.** `Ok(result @ ExecutionResult::Success { .. })` checks that the value is a `Success` and binds the *whole* value to `result`, not just its fields. The second arm nests or-patterns: `Ok(_) | Err(EvmError::IntrinsicGasTooLow { .. } | EvmError::FloorDataGasTooLow { .. })` means "any other outcome of a run, or one of these two errors".
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `Result<Option<ExecutionResult>, String>` has three outcomes: "runs at this gas" (`Ok(Some)`), "does not run at this gas" (`Ok(None)`, a revert, a halt or too little gas), and "this is not an answer" (`Err`, for example a read the recording never made). Treating the third as a "no" would let a bisection silently converge on a wrong limit.
- *[Ownership & moves](01-primer.md#primer-ownership)* `let mut limited = tx.clone();`: the caller's request is borrowed, so the function clones it to set `gas`. `overrides.clone()` is needed because `run_tx` takes its `StateOverrides` by value.

`lowest_limit_that_runs` bisects between 0 and the executor's budget with a closure `runs = |gas| runs_at(…).map(|r| r.is_some())`, propagating the `Err` case with `?`. One shared bisection means the replay makes exactly the runs the recording made, so it reads exactly the recorded state. `run_tx` itself is in `executor.rs`, also behind `cfg(any(test, feature = "fixture"))`: it runs once at a given limit and returns revm's raw result, skipping the call path's checks.

<a id="f-myotis-evm-src-fixture-recording-rs"></a>

### myotis-evm/src/fixture/recording.rs

*test tooling (feature fixture) · 174 lines*

`RecordingOracle` wraps any `Arc<dyn SnapStateOracle>`, answers every read from it, and keeps a copy of each answer in a `RecordedWorld`: accounts (with `None` for a proven absence), storage by account and slot, and bytecode by hash. It adds no verification of its own; it only observes what the inner oracle verified. Its doc points out two traps. It does not forward `prefetch_batch`, because a prefetch writes straight into the executor's caches and would bypass the recorder (the trait's default, a no-op, applies instead). And it must be used over empty caches, because a value already cached is never read again.

`rust/myotis-evm/src/fixture/recording.rs` · lines 24–46

```rust
#[derive(Default)]
struct Recording {
    /// Bound by the first account or storage read.
    state_root: Option<[u8; 32]>,
    world: RecordedWorld,
}

impl Recording {
    /// The world for a read against `state_root`, or the read's failure when
    /// the recording is already bound to another root.
    fn bind(&mut self, state_root: &[u8; 32], address: [u8; 20], slot: Option<U256>) -> Result<&mut RecordedWorld, OracleError> {
        let bound = *self.state_root.get_or_insert(*state_root);
        if &bound != state_root {
            return Err(OracleError::StateUnavailable {
                state_root: *state_root,
                address,
                slot: slot.map(|s| s.to_be_bytes::<32>()),
            });
        }
        self.world.state_root = bound;
        Ok(&mut self.world)
    }
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* **Returning a borrow of yourself.** `bind(&mut self, …) -> Result<&mut RecordedWorld, OracleError>` hands back a mutable reference into `self`. Lifetime elision ties the output's lifetime to `&mut self`, so the caller can write into the world exactly as long as it holds the recording. The check comes first: `get_or_insert` fixes the state root on the first read, and a read at any other root is an error, since a world mixed from two roots is a state no block ever had.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `slot.map(|s| s.to_be_bytes::<32>())` converts `Option<U256>` into `Option<[u8; 32]>` for the error. `::<32>` is the "turbofish", naming a generic parameter (here a const generic, the byte count) at the call site.

`rust/myotis-evm/src/fixture/recording.rs` · lines 101–125

```rust
fn fetch_account(
    &self,
    state_root: &[u8; 32],
    address: [u8; 20],
) -> Result<Option<OracleAccount>, OracleError> {
    let account = self.inner.fetch_account(state_root, address)?;
    self.lock().bind(state_root, address, None)?.accounts.insert(address, account.clone());
    Ok(account)
}

fn fetch_storage(
    &self,
    state_root: &[u8; 32],
    address: [u8; 20],
    slot: U256,
) -> Result<U256, OracleError> {
    let value = self.inner.fetch_storage(state_root, address, slot)?;
    self.lock()
        .bind(state_root, address, Some(slot))?
        .storage
        .entry(address)
        .or_default()
        .insert(slot.to_be_bytes::<32>(), value);
    Ok(value)
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Why a `Mutex` here.** `SnapStateOracle` requires `Send + Sync`, because oracles are shared between threads behind `Arc`. A `RefCell` field would make `RecordingOracle` non-`Sync` and the `impl` would not compile. So the recording sits in a `Mutex<Recording>`, reached through a small `lock()` helper (lines 75–79) that recovers from a poisoned lock with `unwrap_or_else(|poisoned| poisoned.into_inner())`: the maps stay consistent because each insert is a single call.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Not holding the lock across the slow part.** The inner fetch (a network round trip in production) happens *before* the lock is taken. `self.lock().bind(…)?.accounts.insert(…)` is one statement: the `MutexGuard` is a temporary that lives until the `;`, so the lock covers the bind and the insert and is released right after. If `bind` fails, `?` returns early and the guard is dropped on the way out.
- *[Ownership & moves](01-primer.md#primer-ownership)* `account.clone()`: the answer goes into the map *and* back to the caller, so one of the two needs its own copy. A `U256` is `Copy`, so `value` needs no clone. Bytecode is content-addressed, so it is stored without binding to the state root.
- *[Protocol & domain](01-primer.md#primer-domain)* `fetch_block_hash` (lines 92–99) is forwarded but not recorded: a world holds state, not headers. A replay of a run that needed the header chain for `BLOCKHASH` fails there instead of answering from nothing.

<a id="f-myotis-evm-src-fixture-world-rs"></a>

### myotis-evm/src/fixture/world.rs

*test tooling (feature fixture) · 667 lines*

`EvmFixture`: a recorded world as a deterministic JSON file (sorted keys, lowercase hex, so a re-recording diffs cleanly), and `ReplayOracle`, which serves it. The fixture holds the block context, the request exactly as a wallet sends it, the sender's synthetic balance as a `stateOverride`, free-form `meta` and `measured` sections, and the world. The reader is strict: an unknown key, a bytecode that does not hash to its key, or a request field the reader cannot apply is an error, never skipped.

`rust/myotis-evm/src/fixture/world.rs` · lines 7–18

````text
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
````

> [!WARNING]
> **Stale or inaccurate comments**<br>The layout above lists the `block` fields without `parentHash`, but `to_json` writes it (line 105) and `from_json` accepts it (line 152), as an optional field for files recorded before `BLOCKHASH` was served. The order shown is a schema, not the file's order: the file's keys are sorted (the committed fixture begins with `"accounts"`), because `serde_json`'s `Map` is a sorted map unless its `preserve_order` feature is on.

`rust/myotis-evm/src/fixture/world.rs` · lines 279–314

```rust
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
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **A guard on the root.** `Some(account) if state_root == &self.world.state_root => Ok(account.clone())` serves a recorded account only at the recorded root. Everything else, including an unrecorded address, falls to `_` and becomes `StateUnavailable`. The doc explains why "absent" would be the wrong default: a missing entry is not evidence of absence, and treating it as absence describes a world no block had.
- *[Ownership & moves](01-primer.md#primer-ownership)* `account` is `&Option<OracleAccount>` borrowed from the map, and the trait returns an owned value, so it is cloned. The `EMPTY_CODE_HASH` shortcut serves empty code for every codeless account without recording it.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `.ok_or(OracleError::BytecodeUnavailable { … })` builds the error value even on success. `ok_or_else(|| …)` would build it only on failure; for a small enum the difference does not matter.

`rust/myotis-evm/src/fixture/world.rs` · lines 392–414

```rust
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
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **`transpose`.** `field("gas").map(|v| quantity_u64(v, k))` gives an `Option<Result<u64, String>>`: maybe absent, and if present maybe malformed. `.transpose()` flips it into `Result<Option<u64>, String>`, so a single `?` propagates the parse error and leaves an `Option`. In Kotlin you would write `obj["gas"]?.let { parse(it) }` and throw from `parse`.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* The fee model is chosen by matching a tuple of three `Option`s. The first arm refuses `gasPrice` together with either EIP-1559 field; the order of the arms makes the last one, `(None, cap, tip)`, mean "at least one 1559 field". `data` and `input` are both accepted, and must agree when both are present.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* The closures `field`, `optional_u64` and `optional_u128` borrow `obj` from the enclosing function. `optional_u128` spells out its return type, `Result<Option<u128>, String>`, which documents the `transpose` it ends with.

`rust/myotis-evm/src/fixture/world.rs` · lines 519–521

```rust
fn fixed<const N: usize>(value: &Value, what: &str) -> Result<[u8; N], String> {
    bytes(value, what)?.try_into().map_err(|_| format!("{what} is not {N} bytes"))
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Lifetimes](01-primer.md#primer-lifetimes)* `fixed<const N: usize>` is generic over a *number*: one function serves 20-byte addresses and 32-byte hashes. `Vec<u8>::try_into::<[u8; N]>()` succeeds only if the length is exactly `N`. The type expected at the call site picks `N` (a struct field of type `[u8; 32]`, say), or a turbofish names it, as in `fixed::<32>(k, "a storage key")` on line 429. Next to it, `fn object<'a>(value: &'a Value, …) -> Result<&'a Map<…>, String>` (line 480) names its lifetime explicitly: with two reference parameters (`value` and `what`), elision could not tell which one the result borrows from.

<a id="f-myotis-evm-src-fixture-relay-adapt-7702-rs"></a>

### myotis-evm/src/fixture/relay\_adapt\_7702.rs

*test tooling (feature fixture) · 824 lines*

The first and so far only fixture's domain code: a RAILGUN "shield ETH" through a fresh EIP-7702 account, built byte for byte the way the RAILGUN wallet SDK builds it (the transaction #509 reported, with throwaway keys). The sender sends `value` to a fresh "ephemeral" account in a type-4 transaction whose one authorization delegates that account to the RelayAdapt7702 contract. Running the delegate's code, the account calls itself to wrap the ETH into WETH and shield it into RAILGUN, authorized by the ephemeral key's EIP-712 signature. The file also defines the variants a replay checks, `measure` (everything the tests assert), and `record_shield`, the recording procedure with its self-check.

`rust/myotis-evm/src/fixture/relay_adapt_7702.rs` · lines 123–149

```rust
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
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Two signatures by one key.** The EIP-712 signature (lines 133–139) authorizes the `execute` payload inside the contract. The EIP-7702 authorization (`authorize`, signed over `keccak(0x05 ‖ rlp([chain_id, delegate, nonce]))` via revm's `signature_hash`) installs the delegation. `signature[64] += 27` turns the recovery id into the 27/28 form the contract's ECDSA recovery expects.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `.map_err(|e| e.to_string())?` converts the key's error type into this module's `String` errors, then propagates it. Test tooling can afford string errors; the library's own errors are typed enums.
- *[Ownership & moves](01-primer.md#primer-ownership)* `TxRequest::call(…)` returns an owned request; `let mut request` then sets the two extra fields. `ShieldTx { request, ephemeral, payload_hash }` uses field-init shorthand and moves the request into the result.

`rust/myotis-evm/src/fixture/relay_adapt_7702.rs` · lines 383–388

```rust
fn around(shield: TxRequest, require_success_false: TxRequest) -> ShieldRequests {
    let mut without_authorization = shield.clone();
    without_authorization.tx_type = None;
    without_authorization.authorization_list = None;
    ShieldRequests { retry_from_delegated: retry_from_delegated(&shield), without_authorization, require_success_false, shield }
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Field order in a struct literal is evaluation order.** `retry_from_delegated(&shield)` borrows `shield`, and the last field, `shield`, moves it. Fields are evaluated in the order written, so the borrow ends before the move. Write `shield` first and the compiler reports "borrow of moved value". The struct's declared field order does not matter here; only the order in the literal does.

`measure` (lines 491–555) runs the shield and its variants: the shield's estimate, a run at it, the lowest limit that runs; the estimate without the authorization list (#509's wrong answer); the broadcaster's `requireSuccess = false` multicall, which swallows a failed call; and the retry from an account a failed first attempt left delegated. It defines four local closures (`run`, `runs`, `estimate`, `lowest`) that capture `exec`, `block` and `accounts` by reference and add a label to every error. `ShieldEvents::of` reads the outcome from the logs: WETH's `Deposit`, RAILGUN's `Shield`, and the ephemeral account's `CallError`.

`rust/myotis-evm/src/fixture/relay_adapt_7702.rs` · lines 633–645

```rust
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
```

- *[Tests](01-primer.md#primer-testing)* **A recording that checks itself.** `record_shield` first runs `measure` through a `RecordingOracle` over fresh, empty in-memory caches, reads the coinbase too, and checks that the sender and the ephemeral account were read and are absent on chain. Then it builds the fixture and, as shown, runs `measure` again over a new executor whose only state is `fixture.oracle()`. Any difference between the two `ShieldMeasurements` fails the recording. A fixture that would not replay is never written.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `replayed != live` works because `ShieldMeasurements` derives `PartialEq`; `{replayed:?}` needs `Debug`. Both are derived on almost every data type in this crate for exactly these two uses.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `Arc::new(fixture.oracle())` creates an `Arc<ReplayOracle>`, which coerces to the `Arc<dyn SnapStateOracle>` that `EvmExecutor::new` expects. Earlier in the function, `Arc::clone(&recording) as Arc<dyn SnapStateOracle>` does the same explicitly while keeping a typed handle, so the function can still call `recording.recorded()`.

`rust/myotis-evm/src/fixture/relay_adapt_7702.rs` · lines 655–693

```rust
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
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **A recursive enum.** `Tuple(Vec<Abi>)` contains more `Abi` values. That is fine because a `Vec` stores its elements on the heap: the enum's own size stays fixed. A variant `Tuple(Abi)` without indirection would be rejected as a type of infinite size, and you would need `Box<Abi>`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `items.iter().any(Abi::is_dynamic)` passes a method as a function value: `Abi::is_dynamic` has type `fn(&Abi) -> bool`, exactly what `any` wants for an iterator of `&Abi`.
- *[Protocol & domain](01-primer.md#primer-domain)* The free function `encode` below (lines 696–710) does Solidity's head–tail ABI encoding: static items go into the head in place, dynamic ones leave a 32-byte offset in the head and their bytes in the tail. A golden test compares the result byte for byte with an independent Python encoder (`relay_adapt_7702_golden.json`, loaded with `include_str!`).

`rust/myotis-evm/src/fixture/relay_adapt_7702.rs` · lines 722–741

```rust
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
```

*[Macros & attributes](01-primer.md#primer-macros) · [Methods & self](01-primer.md#primer-methods)* `const fn h20` turns a 40-digit hex string into an address *at compile time*, so `pub const MAINNET_WETH: [u8; 20] = h20("c02a…")` costs nothing at run time. A `const fn` may only do what the compiler can evaluate: hence a `while` loop with an index instead of a `for` loop (which would call the iterator trait's methods, not allowed there), and a nested `const fn nibble`. A `panic!` or failed `assert!` during constant evaluation is a compile error, so a typo in an address constant stops the build.

<a id="f-myotis-evm-src-executor-tests-relay-adapt-7702-shield-rs"></a>

### myotis-evm/src/executor/tests/relay\_adapt\_7702\_shield.rs

*unit tests (submodule) · 239 lines*

The replay tests for the committed fixture, `rust/testdata/evm/relayadapt7702-shield.json`. They run `measure` against the recorded world alone, compare with what the recorder measured live, and assert #509's acceptance: the estimate is a limit the whole shield runs under, the old estimate without the authorization list is not, a swallowed failure cannot lower the estimate, and the retry completes. Two tests count reads to prove the prefetch waves of #532 fetch everything (stop 7), and one compares `debug_traceCall`'s call tree, frame by frame and gas included, with a full node's trace of the same request.

`rust/myotis-evm/src/executor.rs` · lines 1667–1679

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{NoopBytecodeCache, NoopStateProofCache};
    use crate::fork::{CANCUN_TIME, LONDON_BLOCK};
    use crate::oracle::{FixtureSnapStateOracle, OracleAccount};
    use myotis_core::keccak::keccak256;

    /// The mainnet RelayAdapt7702 shield, replayed from its recorded world (#509).
    mod relay_adapt_7702_shield;

    /// BLOCKHASH from verified data (#664).
    mod blockhash;
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **How this file is found.** `executor.rs` declares an inline `mod tests { … }`, and inside it `mod relay_adapt_7702_shield;` without a body. For a module declared inside an inline module, Cargo looks in a directory named after the path: `src/executor/tests/relay_adapt_7702_shield.rs`. Again no `#[path]` is needed. The file's `use super::*;` then sees everything `tests` sees, which includes `executor.rs`'s private items and its imports (`Arc`, `NoopStateProofCache`, `with_estimate_buffer`, `assert_frame_matches`), because glob imports pass imported names along too.

`rust/myotis-evm/src/executor/tests/relay_adapt_7702_shield.rs` · lines 19–45

```rust
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
```

- *[Macros & attributes](01-primer.md#primer-macros)* `concat!(env!("CARGO_MANIFEST_DIR"), "/../…")` builds the path at compile time: `env!` reads an environment variable while compiling (Cargo sets `CARGO_MANIFEST_DIR` to the crate's directory) and `concat!` joins string literals into one `&'static str`. The test works from any working directory.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Lifetimes](01-primer.md#primer-lifetimes) · [Tests](01-primer.md#primer-testing)* **Compute once, share between tests.** `cargo test` runs tests on several threads at once. `static REPLAY: OnceLock<Replay>` runs the expensive replay (a few seconds of bisections) the first time any test asks, and every other caller waits for that result. `get_or_init` returns a `&'static Replay`: a static lives for the whole program, so references into it may too. In Kotlin this is `val replay by lazy { … }` at top level.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Tests](01-primer.md#primer-testing)* `unwrap_or_else(|e| panic!("{path}: {e}"))` panics with the path in the message, which a plain `unwrap()` would not show. `MYOTIS_SHIELD_FIXTURE` lets you replay a fresh recording before committing it. (One test, `the_call_trace_matches_a_full_nodes`, reads `FIXTURE` directly and ignores that variable.)

`rust/myotis-evm/src/executor/tests/relay_adapt_7702_shield.rs` · lines 189–202

```rust
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
```

*[Tests](01-primer.md#primer-testing) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `WaveServing` (lines 114–162) wraps the replay oracle, counts single reads and waves in `AtomicUsize` fields (atomics, because the trait's methods take `&self` and the type must be `Sync`), and with `fill: true` really writes a wave's results into the caches, as the network oracle does. `wave_world` keeps an `Arc<WaveServing>` for the test while the executor holds the same object as `Arc<dyn SnapStateOracle>`. The test shows the two sides of #532: with filling waves, no read is made one at a time; without them the same world is read one by one more than 50 times. The answer is the same either way.

<a id="f-myotis-net-examples-record-shield-fixture-rs"></a>

### myotis-net/examples/record\_shield\_fixture.rs

*example binary · 294 lines*

The recorder: `cargo run --release -p myotis-net --example record_shield_fixture`. It syncs the mainnet light client from the embedded checkpoint (up to 25 minutes), starts the EL reader with a peer cache, waits until there is a snap peer and a verified head it can serve, and then records the shield with fresh random keys. A failed attempt (a peer vanishes, the head moves past what peers serve) is retried at a fresh head with fresh keys, up to five times within a 30-minute budget. On its first run it seeds its own peer cache with a *copy* of the newest one an installed Myotis keeps, because finding snap peers on mainnet from scratch is slow. Finally it writes the fixture to `rust/testdata/evm/` and prints the world's size. The keys come from OS randomness and are never written anywhere.

`rust/myotis-net/examples/record_shield_fixture.rs` · lines 228–238

```rust
type Head = ([u8; 32], myotis_evm::BlockContext, std::sync::Arc<dyn myotis_evm::SnapStateOracle>);

/// One recording at `head`, with fresh keys.
async fn record((block_hash, block, oracle): Head, delegate: [u8; 20]) -> Result<EvmFixture, String> {
    tracing::info!(block = block.block_number, "recording the shield");
    let ephemeral_key = fresh_key()?;
    let sender = railgun::address_of(&fresh_key()?);
    let note = random_bytes()?;
    let field = |label: &[u8]| keccak256(&[&note[..], label].concat());
    let mut npk = field(b"npk");
    npk[0] &= 0x0f; // below the SNARK scalar field (0x3064…)
```

`rust/myotis-net/examples/record_shield_fixture.rs` · lines 259–273

```rust
    tokio::task::spawn_blocking(move || {
        railgun::record_shield(
            oracle,
            block,
            block_hash,
            sender,
            &ephemeral_key,
            &params,
            railgun::MAINNET_RAILGUN_PROXY,
            meta,
        )
    })
    .await
    .map_err(|e| format!("the recording thread failed: {e}"))?
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Destructuring in the parameter list.** `type Head = ([u8; 32], BlockContext, Arc<dyn SnapStateOracle>)` names the triple `head_evm_oracle` returns. `async fn record((block_hash, block, oracle): Head, …)` takes it apart right in the signature; any irrefutable pattern may stand where a parameter name would.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Leaving the async world.** `record_shield` blocks: the oracle's reads wait on network I/O by blocking the thread (stop 7). Calling it directly inside an async task would stall a tokio worker thread. `tokio::task::spawn_blocking(move || …)` runs it on tokio's blocking pool. `move` transfers ownership of `oracle`, `block`, the key, `params` and `meta` into the closure, because the closure must be `'static`: the thread may outlive this stack frame. The `&ephemeral_key` and `&params` inside are borrows of the closure's *own* moved copies.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [async/await & tokio](01-primer.md#primer-async)* `.await` yields `Result<Result<EvmFixture, String>, JoinError>`: the outer error means the thread panicked. `.map_err(…)?` handles the outer layer and the function returns the inner `Result` as it is.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* The note fields are derived from one random value: `keccak256(&[&note[..], label].concat())` concatenates two byte slices into a new `Vec`. `npk[0] &= 0x0f` forces the note key below the SNARK scalar field, which `shield_base_token` checks.

`rust/myotis-net/examples/record_shield_fixture.rs` · lines 290–294

```rust
fn fail(message: &str) -> ! {
    tracing::error!("{message}");
    eprintln!("record_shield_fixture: {message}");
    std::process::exit(1)
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Binaries, CLIs & signals](01-primer.md#primer-cli)* `fn fail(message: &str) -> !` never returns: `std::process::exit` has type `!`. That is what lets `main` write `unwrap_or_else(|e| fail(…))` where a value is expected, and use `fail(…)` as a match arm next to arms that produce an address. The rest of `main` uses `tokio::time` deadlines and a 5-second poll of `sync.status()`, and stops the reader and the light client before writing the file. The testdata README describes the same procedure, and how to re-run the replay tests, including the Java engine's twin test, after a re-recording.

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-sim-q1"></a>

**Q1** · Multiple choice

`TraceRecorder` keeps its state in a `RefCell`, while `RecordingOracle` uses a `Mutex`. Why the difference?

- **A.** `RefCell` is faster for large structs, and `RecordingOracle`'s maps are small
- **B.** `RecordingOracle` implements `SnapStateOracle`, which requires `Send + Sync`; a `RefCell` field would make it non-`Sync`. A recorder is only lent to one run on one thread.
- **C.** A `Mutex` is needed whenever a struct is reached through `&self`
- **D.** `RefCell` cannot hold a `BTreeMap`

[Answer →](answers.md#a-sim-q1)

<a id="q-sim-q2"></a>

**Q2** · Written answer

In `Run::call`, the EVM is built with `.with_db(&mut *cache)` inside a block `let outcome = { … };`, and later `credit(cache, …)` uses the cache again. Explain what `&mut *cache` does, why plain `cache` would be a problem, and why the inner block matters.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sim-q2)

<a id="q-sim-q3"></a>

**Q3** · Multiple choice

During `eth_simulateV1`, a call writes a storage slot. Where does that write go?

- **A.** Into the cross-call `StateProofCache`, so the next request starts warm
- **B.** Into the `OracleDatabase`'s per-call view cache
- **C.** Into the pass's `CacheDB<SimDb>`, which layers writes over the read-only verified database and is dropped at the end of the pass
- **D.** Nowhere: simulated calls are read-only, like `eth_call`

[Answer →](answers.md#a-sim-q3)

<a id="q-sim-q4"></a>

**Q4** · Written answer

Name three things `eth_simulateV1` refuses to serve, and explain the common reason behind the `BLOCKHASH` and EIP-2935 refusals in particular.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sim-q4)

<a id="q-sim-q5"></a>

**Q5** · Multiple choice

`ShieldRequests::around` builds `ShieldRequests { retry_from_delegated: retry_from_delegated(&shield), without_authorization, require_success_false, shield }`. What happens if you move `shield` to be the first field in the literal?

- **A.** Nothing; field order in a literal never matters
- **B.** A compile error: fields are evaluated in the order written, so `shield` would be moved before `&shield` is taken (borrow of moved value)
- **C.** A runtime panic, because the borrow checker defers the check to run time
- **D.** It compiles, but the struct's fields are stored in a different order

[Answer →](answers.md#a-sim-q5)

<a id="q-sim-q6"></a>

**Q6** · Written answer

The `fixture` module must be usable by `myotis-net`'s example but must never ship in the engine library. Explain the three Cargo mechanisms that achieve this.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sim-q6)

<a id="q-sim-q7"></a>

**Q7** · Multiple choice

In `runs_at`, what does the pattern `Ok(result @ ExecutionResult::Success { .. })` bind?

- **A.** `result` is bound to the `Success` variant's first field
- **B.** `result` is bound to the whole `Result`
- **C.** `result` is bound to the whole `ExecutionResult` value, after checking that it is the `Success` variant
- **D.** Nothing; `@` is a comment marker inside patterns

[Answer →](answers.md#a-sim-q7)

<a id="q-sim-q8"></a>

**Q8** · Written answer

Look at `RecordingOracle::fetch_account`. When is the mutex locked and unlocked, and why is the inner fetch done before taking the lock?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sim-q8)

<a id="q-sim-q9"></a>

**Q9** · Multiple choice

The `ReplayOracle` gets a read for an account that the recording never read. What does it return?

- **A.** `Ok(None)`: an unrecorded account is treated as absent
- **B.** A default empty account
- **C.** `Err(OracleError::StateUnavailable { … })`, so the run fails rather than running against state nobody recorded
- **D.** It forwards the read to the network

[Answer →](answers.md#a-sim-q9)

<a id="q-sim-q10"></a>

**Q10** · Written answer

`TraceRecorder` builds a tree of `CallFrame`s without parent pointers or `Rc`. How does it do it, and who owns a frame while it is open and after it ends?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sim-q10)

<a id="q-sim-q11"></a>

**Q11** · Multiple choice

Why do the shield replay tests share their result through `static REPLAY: OnceLock<Replay>`?

- **A.** Because tests may not allocate memory
- **B.** Because the replay takes seconds, tests run on several threads, and `OnceLock` runs the initializer once and hands every caller a `&'static Replay`
- **C.** Because `static` values are reset between tests
- **D.** Because `EvmExecutor` cannot be created twice in one process

[Answer →](answers.md#a-sim-q11)

<a id="q-sim-q12"></a>

**Q12** · Written answer

How does `record_shield` make sure that a fixture it produces will actually replay, and why does it build the executor over empty caches?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sim-q12)

<a id="q-sim-q13"></a>

**Q13** · Multiple choice

The recorder example calls `tokio::task::spawn_blocking(move || railgun::record_shield(oracle, …, &ephemeral_key, &params, …))`. What does `move` do here?

- **A.** It moves the closure to another crate
- **B.** It transfers ownership of the captured values (oracle, block, key, params, meta) into the closure, which must be `'static` because the blocking thread may outlive the current stack frame
- **C.** It makes the closure run asynchronously
- **D.** It copies every captured value, so the originals stay usable

[Answer →](answers.md#a-sim-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
