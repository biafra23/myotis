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

It takes minutes: the light-client sync, then finding snap peers. Re-record
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
