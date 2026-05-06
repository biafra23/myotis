# Besu EVM extraction notes

This document records the dependency footprint of the standalone Besu EVM
artifact as used by `myotis-evm`. Read it before bumping the Besu version or
when chasing classpath conflicts.

## Coordinates

```
groupId    = org.hyperledger.besu
artifactId = evm
version    = 24.12.2 (pinned in gradle/libs.versions.toml as `besu`)
repo       = https://hyperledger.jfrog.io/artifactory/besu-maven
```

`besu-datatypes` is also pulled directly so the `Address`/`Hash`/`Wei` value
types are explicit on the classpath rather than transitive — when those types
appear in our internal API surface (e.g. `BlockContextValues`) we want a
deterministic version match.

## What `org.hyperledger.besu:evm:24.12.2` pulls in

The artifact's POM imports `org.hyperledger.besu:bom:24.12.2`, which in turn
pins (without forcing) a large surface of transitive deps:

| Group | What we use | Notes |
|-------|-------------|-------|
| `com.fasterxml.jackson` | nothing directly | pulled by Vertx; not on the runtime path of `callView` |
| `io.netty` | nothing | Besu's EVM module itself does not link Netty; it appears in the BOM only because shared modules need it |
| `io.opentelemetry` | nothing | Besu node modules use this for tracing; the EVM module does not |
| `io.prometheus` | nothing | metrics for the node, not the EVM |
| `io.vertx` | nothing | HTTP server stack for the JSON-RPC layer |
| `org.apache.logging.log4j` | nothing | Besu's logging surface; we use slf4j |
| `org.apache.tuweni` | `Bytes`, `UInt256` | already a Myotis dep |
| `org.bouncycastle` | nothing directly from Besu (Tuweni and our own code use it) | already a Myotis dep |
| `com.google.guava` | indirectly (e.g. `Multimap` on `MessageFrame.Builder.accessListWarmStorage`) | transient; if Guava becomes load-bearing, pin it explicitly |

`./gradlew :myotis-evm:dependencies --configuration runtimeClasspath` is the
canonical way to reproduce this list after a bump.

## What we do NOT need

The plan flagged "Besu's full pom pulls in a lot of node-runtime stuff
(RocksDB, etc.) that we do not need." Empirically, the standalone `evm`
artifact does NOT pull RocksDB. Module subgraphs that require it
(`org.hyperledger.besu:storage`, `:datatypes`-RocksDB plugins, etc.) are
not transitive from the EVM. Verified at `24.12.2` — keep an eye on this on
upgrade.

## Phase 0 result

`./gradlew :myotis-evm:test` passes. `EvmFactoryTest` runs hand-written
SLOAD/MSTORE/RETURN bytecode against a `FixtureSnapStateOracle`, exercising:

- `EvmFactory.buildForBlock` (Cancun branch)
- `SnapWorldUpdater` reads through `SyncStateView`
- `SnapAccount.getCode` triggers a `bytecode` fetch on first `getCode()` call
- Storage slot 0 is read through to the fixture
- Result is decoded and matches the expected `uint256`

The Besu integration is therefore proven viable. The plan's Phase 0 exit
condition — "decide by end of Phase 0 before proceeding to Phase 1" — is
**Besu retained**.

## How `MessageCallProcessor` is driven

`MessageCallProcessor.start()` only initialises the frame; it does **not**
run the bytecode to completion. Calling `start()` and reading the state
returns `CODE_EXECUTING`, not `COMPLETED_*`.

The right entry point is `AbstractMessageProcessor.process()`, which walks
the state machine:
`NOT_STARTED → CODE_EXECUTING (via subclass start) → runToHalt → CODE_SUCCESS/REVERT/HALT → COMPLETED_*`.

We loop on `process()` until the frame reaches a `COMPLETED_*` state to
correctly handle CALL/CREATE child frames, which suspend the parent at
`CODE_SUSPENDED` and require re-entry. (Today's Phase 0 test bytecode does
not exercise that path; Phase 2 will, against real ERC-20 contracts.)

## Hard-fork awareness

`EvmFactory.buildForBlock(BlockContext)` selects between London / Paris
(post-merge, block-keyed) / Shanghai / Cancun / Prague (timestamp-keyed)
using mainnet's published transition values. Pre-London is intentionally
unsupported — the wallet only operates on recent finalised heads. Add a
test per fork transition (one block before, one block after) before any
upgrade.

Precompile sets are paired with the fork:

- London / Paris → `MainnetPrecompiledContracts.istanbul(gc)` (point evaluation
  not yet active)
- Shanghai → `istanbul(gc)` again (KZG point-evaluation arrives in Cancun)
- Cancun → `cancun(gc)` (adds 0x0a)
- Prague → `prague(gc)` (BLS12-381 precompiles)

## Determinism audit

The plan calls out determinism as a cross-cutting concern. Spot checks:

- `BlockValues` is sourced exclusively from `BlockContext`, which itself is
  derived from a sync-committee-verified header. No system clock, no
  `System.currentTimeMillis`, no `ThreadLocalRandom`.
- `OperationTracer.NO_TRACING` is a no-op stub; tracers cannot inject
  observable side effects into execution by default.
- The EVM's internal jump-dest cache is per-`Code` instance; different
  invocations produce identical jump-dest analyses.
- `EvmConfiguration.DEFAULT` selects a deterministic `WorldUpdaterMode`.

No non-deterministic hooks were observed in the EVM module itself. Re-check
on upgrade.
