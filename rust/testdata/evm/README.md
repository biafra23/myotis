# Recorded EVM worlds

## `relayadapt7702-shield.json`

The state a RAILGUN "shield ETH" through a fresh EIP-7702 account reads on
mainnet: #509's transaction, with throwaway keys. A type-4 transaction from a
sender to a fresh account carries one authorization that delegates the account
to RelayAdapt7702 (`0x05ae73c5…`, the delegate #509's failing transactions
used). The account then runs `execute([], (true, 0, [wrapBase, shield]),
nonce, signature)` against itself, wrapping the ETH it received into WETH and
shielding the WETH into RAILGUN. That is how `@railgun-community/wallet`
builds it (`rust/myotis-evm/src/fixture/relay_adapt_7702.rs`, cross-checked
byte for byte by `scripts/relay_adapt_7702_golden.py`).

### Where it comes from

`rust/myotis-net/examples/record_shield_fixture.rs` syncs the Rust engine's
light client, then runs the transaction through the engine's verified-read
path. Every account and slot passed the engine's snap-proof checks against
the verified head's state root, and every bytecode was checked against its
code hash. The recorder keeps every value any run read, in a recording made
over empty caches so nothing is served from a cache it did not see:

1. the estimate;
2. a run at the estimate, which must complete the shield (WETH `Deposit` and
   RAILGUN `Shield`, nothing swallowed);
3. three variants:
   - a broadcaster's `requireSuccess = false` multicall;
   - the retry from the account a failed first attempt left delegated;
   - the request without its authorization list;
4. the coinbase.

It then replays every measured estimate against the recorded world alone and
fails unless each comes back unchanged.

Two things in the file are not chain state:

- the sender's funds, a `stateOverride` (the sender is a fresh address, like
  the ephemeral account);
- the variants' requests, signed by the recorder with the throwaway ephemeral
  key, which it never writes anywhere.

No wallet's data is involved.

### Re-recording

On a machine where Myotis syncs (it reaches mainnet devp2p and libp2p peers):

```bash
cd rust
cargo run --release -p myotis-net --example record_shield_fixture
cargo test -p myotis-evm relay_adapt_7702_shield
cd .. && ./gradlew :myotis-evm:test --tests '*RelayAdapt7702ShieldFixtureTest' -PskipRustEngine
```

It takes minutes: the light-client sync, then finding snap peers, which is
slow from scratch on mainnet. So the recorder keeps its own EL peer cache
(`rust/target/record_shield_fixture/peers.cache`), seeded on its first run
with a copy of the newest one an installed Myotis keeps (`~/.myotis`,
`~/.myotis-railgun-poc`, or the daemon's `app/`), and every later run starts
from the snap peers the earlier ones proved. Re-record
when a change makes the EVM read state the file lacks: the replay oracle fails
any read the recording did not make, and the replay reports it ("does not
replay: state unavailable for 0x…").
`MYOTIS_SHIELD_FIXTURE=<path>` points both replays at another recording.

### What replays it

- `rust/myotis-evm/src/executor/tests/relay_adapt_7702_shield.rs` (Rust
  engine, which applies authorization lists):
  - the estimate is the live answer, the search's answer, and a limit at which
    the whole shield runs;
  - without its authorization list the request gets #509's answer, a limit
    the shield cannot run under;
  - with `requireSuccess = false`, the lowest limit at which the transaction
    succeeds swallows the shield, while the estimate keeps it;
  - the retry completes at its estimate.
- `myotis-evm/src/test/java/io/myotis/evm/RelayAdapt7702ShieldFixtureTest.java`
  (Java engine, which refuses authorization lists): the retry's estimate
  must equal the Rust engine's exactly.

The format is `myotis-evm-fixture/1`, documented in
`rust/myotis-evm/src/fixture/world.rs`.

## `callTracer-golden.json` and `relayadapt7702-shield-calltrace.json`

`debug_traceCall` answers from a full node, the references for this node's
`callTracer` (#716; `executor::tests::trace_call_matches_a_full_nodes_call_tracer`
and `relay_adapt_7702_shield::the_call_trace_matches_a_full_nodes`). Both were
fetched from `eth.drpc.org` on 2026-11-03: its client is not identified, but its
answers have geth's `callTracer` shape. The tests compare every frame and log,
gas included.

- `callTracer-golden.json`: two synthetic call trees (nested calls, a STATICCALL,
  logs, a reverted callee with a `Panic` reason) at mainnet block 19,500,000
  (Cancun). The contracts are installed by `stateOverrides`, so nothing else is
  read; the replay installs the same code in a fixture world.
- `relayadapt7702-shield-calltrace.json`: the recorded shield request
  (`relayadapt7702-shield.json`) at its block, with its state override, an
  explicit 30,000,000 gas limit (this node's call budget; without a `gas` the
  node used its own RPC gas cap) and `withLog`.

Only the `callTracer` is pinned this way. The same provider's `prestateTracer`
answers differ from current geth (no `codeHash`, no coinbase entry), so that
tracer follows geth's source (`eth/tracers/native/prestate.go`) and is covered by
unit tests instead.

## `simulateV1-golden.json`

`eth_simulateV1` answers from a full node that identifies as geth
(`eth.rpc.blxrbdn.com`, `Geth/v1.16.7`), the reference for this node's
simulator (#716; `myotis-engine`'s
`host::simulate_tests::simulate_matches_a_full_nodes_answer`). Recorded on
2026-11-04 at a mainnet block near that node's head, because it keeps no older
state. The file holds the base block's header, the two requests, geth's
answers, and the balances of the accounts the runs touch (`accounts`).

The calls run synthetic contracts installed by `stateOverrides` at vanity
addresses (`0x5151…`, `0xc0c0…`). None of them has code or a nonce on mainnet,
but several hold a balance, recorded with `eth_getBalance` at the base block.
The replay builds a fixture world from those balances and nothing else, so the
runs read the same state geth read.

- **blocks, logs and transfers** (`traceTransfers`): storage carried from one
  call to the next, a value transfer, a revert with an `Error(string)` reason,
  an invalid opcode, and an inner call that reverts with its own logs. Then a
  gap block, and a block with every header override. Its calls read the header
  fields, pay a fee, read balances and create a contract.
- **validation and full transactions** (`validation`,
  `returnFullTransactions`): nonces, the base fee computed from the base
  block's header, and legacy, EIP-1559 and EIP-7702 transactions (an
  authorization with an invalid signature, skipped as on chain) shown as
  objects.

The test compares every field this node computes: calls, logs, gas,
transaction hashes and objects, both roots, the bloom and the header fields.
Every field it does not compute must be `null` there: `hash`, `stateRoot`,
`excessBlobGas`, `requestsHash`, `size`, a later block's `parentHash`, and every
`blockHash`. Five differences from v1.16.7 are deliberate, and the test names
each one:

1. A frame that reverted frees its log indices. That is geth master's simulate
   tracer, and how a receipt's indices behave.
2. `maxUsedGas` is present (geth master).
3. A reverted call's `error.code` is 3, as for `eth_call` (geth master).
4. A transaction object has `blockTimestamp` (geth master).
5. A legacy transaction names no `chainId`. geth derives one from `v` = 0 and
   underflows to `0x7fffffffffffffee`.

To re-record, run the requests in the file against a geth node at a recent
block, and update `base`, `accounts` and the responses together.
