# Start here: the map

*Stop 0 · Orientation* · about 20 minutes

The Rust workspace is a second Myotis engine behind the same `io.myotis.api` contract the Java engine implements. That's 122,922 lines in 176 files and twelve crates, twice the size of the September tour. This stop shows how the crates fit together, which way calls flow, and a route through all of it, in legs of a few hours each.

## By the end of this stop you can

- **Name every crate** — and say what it is for, and which ones are allowed to do I/O.
- **Trace the four entrances** — through which Kotlin/JVM, iOS, Node and plain JSON-RPC clients reach the Rust engine.
- **State the five rules** — that explain most of the design decisions you will see in the code.

## What you are looking at

You already know the Java engine: `ChainStack`, `RLPxConnector`, `BeaconP2PService`, `MerklePatriciaProofVerifier`. Almost every Rust file here is a *twin* of one of those classes. Doc comments usually name the twin, and this tour shows it as a violet chip on each file. Wherever a twin exists, you can ask: “what does the Java version do here?” That makes the Rust version much easier to read.

The hosts (desktop, daemon, Android, iOS, Node) never see Rust types. They call a flat, FFI-friendly surface that passes numbers, strings and JSON documents. Behind that surface, Rust owns everything: a tokio runtime, the consensus-layer light client, the execution-layer peer pool and the EVM.

![Crate map. Wallets and dapps reach myotis-rpcd over HTTP JSON-RPC; myotis-rpcd calls the engine's exported functions directly as a Rust library. JVM hosts reach myotis-engine through UniFFI and JNA, iOS through the plain C ABI, Node through myotis-node which calls the C ABI functions. myotis-engine starts the sync loop and the EL reader in myotis-net, which does all I/O and depends on the sans-I/O crates myotis-wire, myotis-consensus, myotis-core and myotis-evm. myotis-wire uses myotis-core and myotis-consensus; myotis-evm uses myotis-core; myotis-consensus uses myotis-bls, which the Java engine also loads through JNI. roost and tor-poc are standalone binaries built on myotis-net.](img/00-map-1.svg)

*Dashed boxes are callers outside Rust. Solid boxes are crates, and arrows point from a caller to what it calls or depends on. Oxide fills mark the three crates that face the outside world. The dashed oxide frame is the sans-I/O core: plain functions over bytes, with no sockets, clock or files. `myotis-wire` is new since September: the wire codecs moved out of `myotis-net` into it. `myotis-engine` also depends on `myotis-consensus`, `myotis-evm` and `myotis-core` directly; those edges are left out to keep the picture readable.*

## Five rules that explain most of the code

Keep these in mind. Many strange-looking lines exist because of one of them.

| Rule | What it means | Where you will feel it |
|---|---|---|
| 1 · sans-I/O core | `myotis-core`, `myotis-wire`, `myotis-consensus` and `myotis-evm` never open a socket, read the clock, touch the filesystem or draw randomness. They are pure functions over bytes. Two canaries in `./gradlew check` enforce it: a wasm32 build of core, wire and consensus (tokio and sockets do not compile there), and a `no_std` build of `myotis-core` for a bare-metal target. | Stops 4–8. The current time reaches the light client only as a plain slot number that `myotis-net` computes. |
| 2 · one-way dependencies | `myotis-net → myotis-wire → myotis-consensus`, never the other way. When protocol logic needs I/O, the I/O stays in net and passes results in as values. | Stops 9–15. Traits such as `SnapStateOracle` let a pure crate ask for data without knowing where it comes from. |
| 3 · `panic = "abort"` | The release profile aborts the process on a panic instead of unwinding. Inside a JVM or an iOS app, that means a Rust panic kills the whole app. So decoding untrusted bytes must never panic: code returns `Option`/`Result`, and avoids `unwrap()` and unchecked indexing on runtime data. | Everywhere, especially `host.rs`, which is “panic-free by construction”. `roost` is a server, so it opts out and uses `panic = "unwind"`. |
| 4 · JSON across the boundary | Compound values cross FFI as JSON strings, not as native structs. The shapes are pinned by golden tests on both the Kotlin and the Rust side. | Stops 16 and 17: `eljson.rs`, `ffi.rs`, `capi.rs`, and how UniFFI carries them. |
| 5 · verify, never trust | Every answer is proven. BLS sync-committee signatures anchor the beacon chain, the beacon chain anchors an execution block hash, the block hash anchors headers, headers anchor state roots, and Merkle-Patricia proofs anchor accounts and storage. | Stops 6, 12 and 14. A peer that cannot prove its data is skipped, and a read that cannot be proven fails. It never guesses. |

> [!NOTE]
> **JVM lens**
>
> Rule 3 is the biggest culture shock. In Java, an unexpected `NullPointerException` in a background thread gets logged and the app keeps running. Here, the equivalent (`unwrap()` on a `None`) would take the whole Android process down. That is why you will see `let Some(x) = … else { return false; };` in places where Java code would simply dereference.

## The route

You get the memory-model primer first, then the workspace, then the code *bottom-up*. The order follows the Rust concepts, which get harder as you go. The pure crates teach borrowing and slices. `myotis-evm` adds traits and shared ownership. `myotis-net` is async and concurrency all the way down. The boundary crates finish with `unsafe` and FFI, including a deep dive into how UniFFI actually connects Kotlin to Rust. The workbook then makes you write the mechanisms yourself.

| Stops | Code | Rust you will practise |
|---|---|---|
| 1–2 | Primer; workspace manifests | ownership, borrowing, lifetimes, methods and `self`, smart pointers; crates, features, profiles |
| 3–8 | `myotis-bls`, `-core`, `-wire`, `-consensus`, `-evm` (two stops) | slices and byte parsing, `no_std`, `Result`/`?`, enums and `match`, traits and `Arc<dyn Trait>`, `Mutex` behind `&self` |
| 9–15 | `myotis-net`: libp2p, the sync loop, EL peers, the pool and trust chain, EL services, the verified reader, tests | `async`/`.await`, `tokio::spawn`, channels, `select!`, cancellation by drop, `Drop` guards, generics over `AsyncRead`, the sync/async bridge |
| 16–21 | `myotis-engine`, the UniFFI deep dive, `myotis-node`, `myotis-rpcd`, `roost`, `tor-poc` | global state with `OnceLock`, `extern "C"`, raw pointers and string ownership, proc macros, `anyhow`, servers and daemons |
| 22–23 | Workbook; final checkpoint | writing it yourself, then everything traced through one real request |

## The full route

The whole tour reads in about 56 hours, front to back. The route below is the same order, cut into 11 legs, most of them four to seven hours long, with each workbook exercise placed right after the stop whose ideas it practises. Times come from each stop's own estimate: unhurried reading of the prose and every excerpt, plus two minutes per checkpoint question. On a long flight, start at Leg 1 and keep going: eight hours take you through Leg 1 and about 3 h 50 into Leg 2. Take breaks between legs, or between stops, not inside one.

Everything works offline: the exercises run against your local cargo cache, and the reading list points to your EPUBs and the Rust docs rustup installed.

- **Leg 1 · The language, then the workspace** *(about 4 h 10)*

  - [Stop 0](#) *(20 min)*: this map. Skim the file index; no need to read it.
  - [Stop 1](01-primer.md) *(1 h 00)*: the primer, including [methods and `self`](01-primer.md#primer-methods). Do its checkpoint carefully: it tells you which concepts to revisit.
  - [Workbook exercises 1, 2, 3, 4](22-workbook.md) *(1 h 00)*: cursor, hex, errors, methods: the primer's ideas in your own hands.
  - [Stop 2](02-workspace.md) *(1 h 10)*: the manifests: crates, features, profiles, the no\_std and wasm canaries.
  - [Stop 3](03-bls.md) *(40 min)*: the smallest real crate, a warm-up for slices and borrowed `Vec`s.

- **Leg 2 · Bytes, hashes and wire formats** *(about 5 h 00)*

  - [Stop 4](04-core.md) *(2 h 15)*: RLP, Keccak, tries and proofs: borrowing slices at speed.
  - [Workbook exercise 8](22-workbook.md) *(15 min)*: verify a header chain with slices and iterators, the shape of `verify.rs`.
  - [Stop 5](05-wire.md) *(2 h 30)*: every protocol as a pure function: enums, `Result` and `?` everywhere.

- **Leg 3 · The light client and the EVM** *(about 6 h 15)*

  - [Stop 6](06-consensus.md) *(3 h 00)*: the light client as a state machine you can test without a network.
  - [Stop 7](07-evm.md) *(3 h 00)*: an EVM over verified state: traits, `Arc<dyn Trait>`, interior mutability.
  - [Workbook exercise 10](22-workbook.md) *(15 min)*: traits, generics versus `dyn`, and a decorator like the test oracle.

- **Leg 4 · Simulation, then the network begins** *(about 5 h 05)*

  - [Stop 8](08-evm-sim.md) *(2 h 35)*: transaction requests, tracers and `eth_simulateV1`.
  - [Stop 9](09-net-cl.md) *(2 h 30)*: libp2p, request/response and discovery: your first async-heavy stop.

- **Leg 5 · Sync loop and execution-layer peers** *(about 6 h 45)*

  - [Stop 10](10-net-sync.md) *(3 h 00)*: the sync loop: tasks, channels, `select!`, cancellation by drop.
  - [Workbook exercises 5, 6, 7](22-workbook.md) *(45 min)*: a registry behind a `Mutex`, a drop guard, a worker that holds only a `Weak`.
  - [Stop 11](11-el-transport.md) *(3 h 00)*: RLPx, eth and snap sessions: an actor with a split reader and writer.

- **Leg 6 · The pool and the services** *(about 5 h 55)*

  - [Stop 12](12-el-pool.md) *(3 h 20)*: the peer pool and the trust chain from beacon anchor to Merkle proof.
  - [Stop 13](13-el-services.md) *(2 h 35)*: the EVM bridge, the log index and transactions.

- **Leg 7 · The verified reader and the tests** *(about 5 h 20)*

  - [Stop 14](14-el-reader.md) *(3 h 05)*: the biggest file: read its section map first, then the excerpts.
  - [Workbook exercise 9](22-workbook.md) *(15 min)*: the hedged race on a paused tokio clock, the shape of `hedged_race`.
  - [Stop 15](15-net-tests.md) *(2 h 00)*: integration tests, live probes and how `#[ignore]` keeps them out of CI.

- **Leg 8 · The engine boundary** *(about 3 h 10)*

  - [Stop 16](16-engine.md) *(3 h 10)*: the engine: global state, the catalog, `ffi.rs` and `capi.rs`.

- **Leg 9 · UniFFI, end to end** *(about 5 h 55)*

  - [Stop 17](17-uniffi.md) *(5 h 55)*: what the macros write, who frees which buffer, how the checksums guard it, and how the Android build regenerates the bindings. Long: read it in two or three sittings, at its section breaks.

- **Leg 10 · The binaries** *(about 6 h 40)*

  - [Stop 18](18-node.md) *(1 h 50)*: the Node addon: a scheduler and admission control around the C ABI.
  - [Stop 19](19-rpcd.md) *(2 h 35)*: rpcd: a JSON-RPC daemon on the engine.
  - [Stop 20](20-roost.md) *(2 h 15)*: roost, the light-client server.

- **Leg 11 · Generics over transports, and the whole picture** *(about 1 h 30)*

  - [Stop 21](21-torpoc.md) *(1 h 00)*: tor-poc: the same stack over Tor, generic over the transport.
  - [Stop 23](23-final.md) *(30 min)*: one request traced through every layer, and the final checkpoint.

The other stops make good chapters for later evenings, in order. Each one stands alone, and its checkpoint keeps feeding the same reading list.

## How to use each stop

- **Read with the code open.** Every excerpt shows its real path and line numbers. They are cut from the repository at build time, from commit `5263a421` (`origin/main` on 6 November 2026). If your checkout has moved on, `git worktree add ../myotis-tour 5263a421` gives you exactly the code the tour quotes.
- **Follow the concept chips.** Oxide chips such as *[Borrowing & slices](01-primer.md#primer-borrowing)* jump to the primer section that explains the idea.
- **Big files get a section map:** line ranges and what happens in each. Use it to jump around in your editor.
- **Do the checkpoint at the end of each stop.** Missed questions feed the [reading list](reading-list.md#progress), which points to specific chapters in your books.

## Every file in the tour

All 176 `.rs` files, grouped by crate, with their size. Each links to its entry.

### myotis-bls 2 files · 271 lines

- [src/lib.rs](03-bls.md#f-myotis-bls-src-lib-rs) 133
- [tests/conformance.rs](03-bls.md#f-myotis-bls-tests-conformance-rs) 138

### myotis-core 14 files · 3,603 lines

- [src/lib.rs](04-core.md#f-myotis-core-src-lib-rs) 58
- [src/keccak.rs](04-core.md#f-myotis-core-src-keccak-rs) 49
- [src/fees.rs](04-core.md#f-myotis-core-src-fees-rs) 40
- [src/rlp.rs](04-core.md#f-myotis-core-src-rlp-rs) 966
- [src/nodekey.rs](04-core.md#f-myotis-core-src-nodekey-rs) 203
- [src/header.rs](04-core.md#f-myotis-core-src-header-rs) 373
- [src/enr.rs](04-core.md#f-myotis-core-src-enr-rs) 264
- [src/forkid.rs](04-core.md#f-myotis-core-src-forkid-rs) 296
- [src/trie.rs](04-core.md#f-myotis-core-src-trie-rs) 525
- [src/triehash.rs](04-core.md#f-myotis-core-src-triehash-rs) 144
- [src/bloom.rs](04-core.md#f-myotis-core-src-bloom-rs) 103
- [tests/el\_conformance.rs](04-core.md#f-myotis-core-tests-el-conformance-rs) 262
- [tests/el\_mpt\_conformance.rs](04-core.md#f-myotis-core-tests-el-mpt-conformance-rs) 185
- [tests/rlp\_alloc\_bound.rs](04-core.md#f-myotis-core-tests-rlp-alloc-bound-rs) 135

### myotis-wire 16 files · 5,785 lines

- [src/lib.rs](05-wire.md#f-myotis-wire-src-lib-rs) 28
- [src/snappy.rs](05-wire.md#f-myotis-wire-src-snappy-rs) 444
- [src/discv4.rs](05-wire.md#f-myotis-wire-src-discv4-rs) 292
- [src/rlpx/mod.rs](05-wire.md#f-myotis-wire-src-rlpx-mod-rs) 7
- [src/rlpx/ecies.rs](05-wire.md#f-myotis-wire-src-rlpx-ecies-rs) 185
- [src/rlpx/handshake.rs](05-wire.md#f-myotis-wire-src-rlpx-handshake-rs) 298
- [src/rlpx/frame.rs](05-wire.md#f-myotis-wire-src-rlpx-frame-rs) 415
- [src/rlpx/hello.rs](05-wire.md#f-myotis-wire-src-rlpx-hello-rs) 133
- [src/eth.rs](05-wire.md#f-myotis-wire-src-eth-rs) 1,533
- [src/eth2/mod.rs](05-wire.md#f-myotis-wire-src-eth2-mod-rs) 8
- [src/eth2/protocols.rs](05-wire.md#f-myotis-wire-src-eth2-protocols-rs) 129
- [src/eth2/status.rs](05-wire.md#f-myotis-wire-src-eth2-status-rs) 219
- [src/eth2/codec.rs](05-wire.md#f-myotis-wire-src-eth2-codec-rs) 749
- [src/snap/mod.rs](05-wire.md#f-myotis-wire-src-snap-mod-rs) 4
- [src/snap/messages.rs](05-wire.md#f-myotis-wire-src-snap-messages-rs) 981
- [src/snap/fetch.rs](05-wire.md#f-myotis-wire-src-snap-fetch-rs) 360

### myotis-consensus 16 files · 5,103 lines

- [src/lib.rs](06-consensus.md#f-myotis-consensus-src-lib-rs) 49
- [src/spec.rs](06-consensus.md#f-myotis-consensus-src-spec-rs) 158
- [src/ssz.rs](06-consensus.md#f-myotis-consensus-src-ssz-rs) 238
- [src/types.rs](06-consensus.md#f-myotis-consensus-src-types-rs) 943
- [src/verify.rs](06-consensus.md#f-myotis-consensus-src-verify-rs) 68
- [src/fork.rs](06-consensus.md#f-myotis-consensus-src-fork-rs) 314
- [src/store.rs](06-consensus.md#f-myotis-consensus-src-store-rs) 636
- [src/snapshot.rs](06-consensus.md#f-myotis-consensus-src-snapshot-rs) 550
- [tests/lc\_conformance.rs](06-consensus.md#f-myotis-consensus-tests-lc-conformance-rs) 177
- [tests/fork\_boundary.rs](06-consensus.md#f-myotis-consensus-tests-fork-boundary-rs) 228
- [tests/gloas\_boundary.rs](06-consensus.md#f-myotis-consensus-tests-gloas-boundary-rs) 619
- [tests/gloas\_spec\_vectors.rs](06-consensus.md#f-myotis-consensus-tests-gloas-spec-vectors-rs) 399
- [tests/next\_committee\_selection.rs](06-consensus.md#f-myotis-consensus-tests-next-committee-selection-rs) 175
- [tests/next\_committee\_finality.rs](06-consensus.md#f-myotis-consensus-tests-next-committee-finality-rs) 113
- [tests/next\_committee\_adoption.rs](06-consensus.md#f-myotis-consensus-tests-next-committee-adoption-rs) 250
- [tests/resume\_equivalence.rs](06-consensus.md#f-myotis-consensus-tests-resume-equivalence-rs) 186

### myotis-evm 23 files · 15,187 lines

- [src/lib.rs](07-evm.md#f-myotis-evm-src-lib-rs) 508
- [src/error.rs](07-evm.md#f-myotis-evm-src-error-rs) 319
- [src/oracle.rs](07-evm.md#f-myotis-evm-src-oracle-rs) 380
- [src/cache.rs](07-evm.md#f-myotis-evm-src-cache-rs) 251
- [src/block.rs](07-evm.md#f-myotis-evm-src-block-rs) 80
- [src/database.rs](07-evm.md#f-myotis-evm-src-database-rs) 511
- [src/overrides.rs](07-evm.md#f-myotis-evm-src-overrides-rs) 165
- [src/fork.rs](07-evm.md#f-myotis-evm-src-fork-rs) 409
- [src/executor.rs](07-evm.md#f-myotis-evm-src-executor-rs) 4,508
- [src/executor/tests/blockhash.rs](07-evm.md#f-myotis-evm-src-executor-tests-blockhash-rs) 250
- [src/ens/name.rs](07-evm.md#f-myotis-evm-src-ens-name-rs) 166
- [src/ens/abi.rs](07-evm.md#f-myotis-evm-src-ens-abi-rs) 423
- [src/ens/mod.rs](07-evm.md#f-myotis-evm-src-ens-mod-rs) 2,257
- [src/tx.rs](08-evm-sim.md#f-myotis-evm-src-tx-rs) 349
- [src/trace.rs](08-evm-sim.md#f-myotis-evm-src-trace-rs) 616
- [src/simulate.rs](08-evm-sim.md#f-myotis-evm-src-simulate-rs) 1,278
- [src/simulate/encode.rs](08-evm-sim.md#f-myotis-evm-src-simulate-encode-rs) 122
- [src/simulate/tests.rs](08-evm-sim.md#f-myotis-evm-src-simulate-tests-rs) 603
- [src/fixture/mod.rs](08-evm-sim.md#f-myotis-evm-src-fixture-mod-rs) 88
- [src/fixture/recording.rs](08-evm-sim.md#f-myotis-evm-src-fixture-recording-rs) 174
- [src/fixture/world.rs](08-evm-sim.md#f-myotis-evm-src-fixture-world-rs) 667
- [src/fixture/relay\_adapt\_7702.rs](08-evm-sim.md#f-myotis-evm-src-fixture-relay-adapt-7702-rs) 824
- [src/executor/tests/relay\_adapt\_7702\_shield.rs](08-evm-sim.md#f-myotis-evm-src-executor-tests-relay-adapt-7702-shield-rs) 239

### myotis-net 74 files · 66,665 lines

- [src/codec.rs](05-wire.md#f-myotis-net-src-codec-rs) 4
- [src/status.rs](05-wire.md#f-myotis-net-src-status-rs) 4
- [src/protocols.rs](05-wire.md#f-myotis-net-src-protocols-rs) 4
- [src/el/rlpx/ecies.rs](05-wire.md#f-myotis-net-src-el-rlpx-ecies-rs) 4
- [src/el/rlpx/frame.rs](05-wire.md#f-myotis-net-src-el-rlpx-frame-rs) 4
- [src/el/rlpx/handshake.rs](05-wire.md#f-myotis-net-src-el-rlpx-handshake-rs) 4
- [src/el/eth/messages.rs](05-wire.md#f-myotis-net-src-el-eth-messages-rs) 4
- [src/el/snap/fetch.rs](05-wire.md#f-myotis-net-src-el-snap-fetch-rs) 4
- [src/el/snap/messages.rs](05-wire.md#f-myotis-net-src-el-snap-messages-rs) 4
- [examples/record\_shield\_fixture.rs](08-evm-sim.md#f-myotis-net-examples-record-shield-fixture-rs) 294
- [src/lib.rs](09-net-cl.md#f-myotis-net-src-lib-rs) 45
- [src/reqresp.rs](09-net-cl.md#f-myotis-net-src-reqresp-rs) 3,506
- [src/discovery.rs](09-net-cl.md#f-myotis-net-src-discovery-rs) 1,215
- [src/clcache.rs](09-net-cl.md#f-myotis-net-src-clcache-rs) 477
- [src/traffic.rs](09-net-cl.md#f-myotis-net-src-traffic-rs) 343
- [src/sync.rs](10-net-sync.md#f-myotis-net-src-sync-rs) 6,124
- [src/cl\_fork\_watch.rs](10-net-sync.md#f-myotis-net-src-cl-fork-watch-rs) 1,055
- [examples/live\_sync.rs](10-net-sync.md#f-myotis-net-examples-live-sync-rs) 81
- [examples/probe\_updates.rs](10-net-sync.md#f-myotis-net-examples-probe-updates-rs) 84
- [examples/lc\_crawl.rs](10-net-sync.md#f-myotis-net-examples-lc-crawl-rs) 270
- [examples/period\_census.rs](10-net-sync.md#f-myotis-net-examples-period-census-rs) 649
- [examples/enr\_lookup.rs](10-net-sync.md#f-myotis-net-examples-enr-lookup-rs) 117
- [src/el/mod.rs](11-el-transport.md#f-myotis-net-src-el-mod-rs) 40
- [src/el/tasks.rs](11-el-transport.md#f-myotis-net-src-el-tasks-rs) 40
- [src/el/discv4.rs](11-el-transport.md#f-myotis-net-src-el-discv4-rs) 2,536
- [src/el/enrfilter.rs](11-el-transport.md#f-myotis-net-src-el-enrfilter-rs) 528
- [src/el/dnsdisco.rs](11-el-transport.md#f-myotis-net-src-el-dnsdisco-rs) 1,461
- [src/el/rlpx/mod.rs](11-el-transport.md#f-myotis-net-src-el-rlpx-mod-rs) 17
- [src/el/rlpx/transport.rs](11-el-transport.md#f-myotis-net-src-el-rlpx-transport-rs) 424
- [src/el/eth/mod.rs](11-el-transport.md#f-myotis-net-src-el-eth-mod-rs) 11
- [src/el/eth/session.rs](11-el-transport.md#f-myotis-net-src-el-eth-session-rs) 931
- [src/el/snap/mod.rs](11-el-transport.md#f-myotis-net-src-el-snap-mod-rs) 16
- [src/el/peer.rs](11-el-transport.md#f-myotis-net-src-el-peer-rs) 1,695
- [src/el/peercache.rs](11-el-transport.md#f-myotis-net-src-el-peercache-rs) 1,133
- [src/el/torreserve.rs](11-el-transport.md#f-myotis-net-src-el-torreserve-rs) 442
- [src/el/tor.rs](11-el-transport.md#f-myotis-net-src-el-tor-rs) 394
- [src/el/request.rs](12-el-pool.md#f-myotis-net-src-el-request-rs) 656
- [src/el/verify.rs](12-el-pool.md#f-myotis-net-src-el-verify-rs) 550
- [src/el/anchor.rs](12-el-pool.md#f-myotis-net-src-el-anchor-rs) 1,130
- [src/el/pool.rs](12-el-pool.md#f-myotis-net-src-el-pool-rs) 4,745
- [src/el/served.rs](12-el-pool.md#f-myotis-net-src-el-served-rs) 456
- [src/el/receipt.rs](12-el-pool.md#f-myotis-net-src-el-receipt-rs) 169
- [src/el/getproof.rs](12-el-pool.md#f-myotis-net-src-el-getproof-rs) 411
- [src/el/fork\_watch.rs](12-el-pool.md#f-myotis-net-src-el-fork-watch-rs) 884
- [src/el/readstats.rs](12-el-pool.md#f-myotis-net-src-el-readstats-rs) 785
- [src/el/evm.rs](13-el-services.md#f-myotis-net-src-el-evm-rs) 2,117
- [src/el/logindex.rs](13-el-services.md#f-myotis-net-src-el-logindex-rs) 3,718
- [src/el/activity.rs](13-el-services.md#f-myotis-net-src-el-activity-rs) 1,213
- [src/el/feecache.rs](13-el-services.md#f-myotis-net-src-el-feecache-rs) 786
- [src/el/tx.rs](13-el-services.md#f-myotis-net-src-el-tx-rs) 1,131
- [src/el/send\_check.rs](13-el-services.md#f-myotis-net-src-el-send-check-rs) 197
- [src/el/sent\_tx.rs](13-el-services.md#f-myotis-net-src-el-sent-tx-rs) 389
- [src/el/reader.rs](14-el-reader.md#f-myotis-net-src-el-reader-rs) 18,846
- [tests/el\_discv4\_conformance.rs](15-net-tests.md#f-myotis-net-tests-el-discv4-conformance-rs) 166
- [tests/el\_rlpx\_conformance.rs](15-net-tests.md#f-myotis-net-tests-el-rlpx-conformance-rs) 208
- [tests/el\_eth\_conformance.rs](15-net-tests.md#f-myotis-net-tests-el-eth-conformance-rs) 127
- [tests/el\_snap\_conformance.rs](15-net-tests.md#f-myotis-net-tests-el-snap-conformance-rs) 152
- [tests/el\_verify\_conformance.rs](15-net-tests.md#f-myotis-net-tests-el-verify-conformance-rs) 138
- [tests/el\_hostile\_frames.rs](15-net-tests.md#f-myotis-net-tests-el-hostile-frames-rs) 317
- [tests/live\_discv4.rs](15-net-tests.md#f-myotis-net-tests-live-discv4-rs) 243
- [tests/live\_enr\_filter.rs](15-net-tests.md#f-myotis-net-tests-live-enr-filter-rs) 87
- [tests/live\_dns\_tree.rs](15-net-tests.md#f-myotis-net-tests-live-dns-tree-rs) 72
- [tests/live\_rlpx.rs](15-net-tests.md#f-myotis-net-tests-live-rlpx-rs) 113
- [tests/live\_eth.rs](15-net-tests.md#f-myotis-net-tests-live-eth-rs) 232
- [tests/live\_snap.rs](15-net-tests.md#f-myotis-net-tests-live-snap-rs) 212
- [tests/live\_managed\_peer.rs](15-net-tests.md#f-myotis-net-tests-live-managed-peer-rs) 239
- [tests/live\_pool.rs](15-net-tests.md#f-myotis-net-tests-live-pool-rs) 151
- [tests/live\_reader.rs](15-net-tests.md#f-myotis-net-tests-live-reader-rs) 91
- [tests/live\_dedicated\_node.rs](15-net-tests.md#f-myotis-net-tests-live-dedicated-node-rs) 138
- [tests/live\_pipeline\_bench.rs](15-net-tests.md#f-myotis-net-tests-live-pipeline-bench-rs) 216
- [tests/live\_mainnet.rs](15-net-tests.md#f-myotis-net-tests-live-mainnet-rs) 53
- [tests/live\_pins\_alive.rs](15-net-tests.md#f-myotis-net-tests-live-pins-alive-rs) 575
- [tests/live\_cold\_start.rs](15-net-tests.md#f-myotis-net-tests-live-cold-start-rs) 466
- [examples/snap\_probe.rs](15-net-tests.md#f-myotis-net-examples-snap-probe-rs) 522

### myotis-engine 9 files · 12,941 lines

- [src/lib.rs](16-engine.md#f-myotis-engine-src-lib-rs) 406
- [src/catalog.rs](16-engine.md#f-myotis-engine-src-catalog-rs) 136
- [src/ringlog.rs](16-engine.md#f-myotis-engine-src-ringlog-rs) 175
- [src/usage.rs](16-engine.md#f-myotis-engine-src-usage-rs) 394
- [src/host.rs](16-engine.md#f-myotis-engine-src-host-rs) 7,199
- [src/ffi.rs](16-engine.md#f-myotis-engine-src-ffi-rs) 515
- [src/capi.rs](16-engine.md#f-myotis-engine-src-capi-rs) 1,190
- [src/eljson.rs](16-engine.md#f-myotis-engine-src-eljson-rs) 2,805
- [examples/bal\_follow\_check.rs](16-engine.md#f-myotis-engine-examples-bal-follow-check-rs) 121

### uniffi-bindgen 1 files · 3 lines

- [src/main.rs](17-uniffi.md#f-uniffi-bindgen-src-main-rs) 3

### myotis-node 4 files · 1,922 lines

- [build.rs](18-node.md#f-myotis-node-build-rs) 3
- [src/lib.rs](18-node.md#f-myotis-node-src-lib-rs) 1,078
- [src/admission.rs](18-node.md#f-myotis-node-src-admission-rs) 95
- [src/scheduler.rs](18-node.md#f-myotis-node-src-scheduler-rs) 746

### myotis-rpcd 8 files · 5,176 lines

- [src/main.rs](19-rpcd.md#f-myotis-rpcd-src-main-rs) 455
- [src/engine.rs](19-rpcd.md#f-myotis-rpcd-src-engine-rs) 246
- [src/http.rs](19-rpcd.md#f-myotis-rpcd-src-http-rs) 704
- [src/rpc.rs](19-rpcd.md#f-myotis-rpcd-src-rpc-rs) 1,980
- [src/quantity.rs](19-rpcd.md#f-myotis-rpcd-src-quantity-rs) 204
- [src/checkpoint.rs](19-rpcd.md#f-myotis-rpcd-src-checkpoint-rs) 103
- [src/seeds.rs](19-rpcd.md#f-myotis-rpcd-src-seeds-rs) 188
- [src/rpc/tests.rs](19-rpcd.md#f-myotis-rpcd-src-rpc-tests-rs) 1,296

### roost 8 files · 5,722 lines

- [src/main.rs](20-roost.md#f-roost-src-main-rs) 921
- [src/rest.rs](20-roost.md#f-roost-src-rest-rs) 769
- [src/store.rs](20-roost.md#f-roost-src-store-rs) 672
- [src/archive.rs](20-roost.md#f-roost-src-archive-rs) 542
- [src/forks.rs](20-roost.md#f-roost-src-forks-rs) 744
- [src/framing.rs](20-roost.md#f-roost-src-framing-rs) 343
- [src/serve.rs](20-roost.md#f-roost-src-serve-rs) 1,569
- [src/enr.rs](20-roost.md#f-roost-src-enr-rs) 162

### tor-poc 1 files · 544 lines

- [src/main.rs](21-torpoc.md#f-tor-poc-src-main-rs) 544

## Checkpoint

5 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-s00-q1"></a>

**Q1** · Multiple choice

Which crate is allowed to open sockets and read the wall clock?

- **A.** `myotis-core`
- **B.** `myotis-consensus`
- **C.** `myotis-net`
- **D.** `myotis-evm`

[Answer →](answers.md#a-s00-q1)

<a id="q-s00-q2"></a>

**Q2** · Multiple choice

How does a call from the Android app reach the Rust engine, compared with a call from the iOS app?

- **A.** Both go through JNI hand-written in `lib.rs`
- **B.** Android: UniFFI-generated Kotlin bindings over JNA into `ffi.rs`. iOS: Kotlin/Native cinterop against the plain C ABI in `capi.rs`
- **C.** Android: the C ABI. iOS: UniFFI
- **D.** Both call `myotis-node`

[Answer →](answers.md#a-s00-q2)

<a id="q-s00-q3"></a>

**Q3** · Multiple choice

Why are `roost` and `tor-poc` excluded from the workspace instead of being members?

- **A.** They are written in a different Rust edition
- **B.** They pull large dependency trees (an HTTP stack, Arti) that no engine target should compile. `roost` also needs `panic = "unwind"`, which a member cannot set
- **C.** Cargo does not allow binaries in workspaces
- **D.** They do not depend on any workspace crate

[Answer →](answers.md#a-s00-q3)

<a id="q-s00-q4"></a>

**Q4** · Written answer

The release profile sets `panic = "abort"`. Explain what that means for a Rust panic inside the Android app, and how it changes the way the code handles untrusted bytes.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-s00-q4)

<a id="q-s00-q5"></a>

**Q5** · Multiple choice

In the trust chain, what anchors an account balance that the reader returns?

- **A.** The answer of the fastest peer
- **B.** A Merkle-Patricia proof against a state root, whose header is linked by hash to a block that the beacon light client verified through sync-committee BLS signatures
- **C.** A local HTTP call to an execution client
- **D.** The peer cache on disk

[Answer →](answers.md#a-s00-q5)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
