# 06 — Rust phase: working notes, open items, and process conventions

> Companion to the [re-implementation spec](README.md). Docs 01–05 are the
> *specification*; this file is the *state of the effort* — decisions made with the
> user, carried review findings, known gaps, and what the EL phase must pick up.
> It exists so any session, on any machine, can continue without the original
> session's local context. Update it as items close.

## Where things stand (2026-07-06)

Phase 1 (CL-only Rust engine behind `:myotis-api`) is **done and merged to
`rust-engine`**: PRs #124 (cargo workspace + Gradle), #127 (`:myotis-engines`
selector + R0 stub), #128 (conformance seeds), #129 (`myotis-consensus`
verification core), #130 (`myotis-net`), #131 (`myotis-engine` R1 + benchmark).
First benchmark numbers: [benchmarks.md](benchmarks.md). The EL phase now has an
execution plan — [07-el-implementation-plan.md](07-el-implementation-plan.md)
(crate layout, dependencies, conformance corpora, PR-by-PR breakdown); coding
starts per that plan's entry criteria (see also "EL-phase entry" below).

## Process conventions (user rulings — follow them)

- **All Rust-phase PRs target the long-lived `rust-engine` branch, not main.**
  Main stays clean for bug fixes until the phase (incl. its benchmark gate) is
  done, then `rust-engine` merges to main once. Cut each PR branch from
  up-to-date `rust-engine`; periodically merge main INTO `rust-engine` (last
  sync: 2026-07-06, brought in the #132 diagnostics + #133 freeze fix).
- Every PR gets an **independent no-context review before it is opened**, and
  every review comment gets an **inline reply on the PR** when addressed.
- **No HTTP fallback, ever** (unless EL/CL nodes themselves adopt HTTP as a p2p
  transport). devp2p + libp2p are the only production data sources; local-client
  HTTP is debugging-only. The wasm32 canary (`cargoCheckWasm`) survives purely as
  the sans-I/O discipline tripwire — wasm is NOT a shipping target.
- **`myotis-consensus` stays permanently sans-I/O** (no tokio/socket deps; clock
  values are parameters; `tracing` only, no logger init; `getrandom` for entropy;
  no global mutable I/O singletons). Networking lives in `myotis-net`; the JNI
  shell in `myotis-engine`. This protects the future Kohaku/extension and iOS
  embeddings (docs/myotis-rust-engine-guidelines.md).
- **Month-old-checkpoint catch-up is a MUST.** Never "fix" slow catch-up by
  refreshing the embedded checkpoint — the wallet must sync from a stale trust
  anchor in the field.
- Binding choice (REVISED): the JVM boundary is **UniFFI + JSON marshalling** —
  the original hand-JNI decision was reversed (user decision, 2026-07) as a
  transport swap only: `#[uniffi::export]` fns in `rust/myotis-engine/src/ffi.rs`,
  generated Kotlin bindings committed in `:myotis-engines`
  (`uniffiGenerateKotlin` regenerates), `RustEngineNative` reduced to a static
  delegator. Compound values STILL cross as JSON strings with the golden-test-
  pinned shapes; UniFFI's per-function API checksums replace the hand-rolled
  stale-.so ABI probe. The iOS plain C ABI (`capi.rs`) is unchanged — doc
  [05](05-engine-api-bindings.md)'s typed-record mapping remains the eventual
  full-UniFFI path if the JSON transport is ever retired.

## Phone-failure diagnosis (reframes the Rust justification)

Diagnosed 2026-07-06 on a Pixel 7 (Android 16): the Java wallet's "unusable on
phone" failure was **NOT memory** — it was a lock-contention freeze (debuggable
builds defaulted BLS to the `compare` measurement harness at 10–16 s/update,
while `BeaconLightClient` held the store monitor across verification, starving
every status reader). The node itself synced fine on-device (~9 min, PSS
105–283 MiB). **Fixed in PR #133** (merged to main and into `rust-engine`).

Consequence: "Java can't run on phones" is no longer a valid justification for
the Rust engine. The case is now **footprint + embeddability** (13 MiB native
vs a JVM; Kohaku/extension and iOS targets) and CPU efficiency — see the
correction note in [benchmarks.md](benchmarks.md). The EL go/no-go should weigh
a Pixel re-test of the fixed Java build.

## Known gaps in the Rust CL (close before or early in the EL phase)

1. **No persistence.** `EngineConfig.dataDir` reaches `myotis-engine` but is
   unused: no sync-state snapshot, no CL peer cache. Every process start
   cold-bootstraps from the embedded checkpoint and re-catches-up. This is the
   dominant cause of the poor/variable wall-time numbers (25-min timeout under
   peer starvation) and the single most valuable next Rust PR: persist the
   verified store snapshot + a proven-server peer cache (the Java CL cache's
   `provenCatchUpRanges` role) under dataDir.
2. **No Android observability.** The engine initializes no tracing subscriber
   and the hosts have no log-drain pump, so Rust-side logs are invisible in
   logcat; on-device you only see the status JSON (period/finalizedSlot/
   peerCount). Wire an android-logger or a drainable ring buffer before serious
   phone debugging.
3. **Checkpoint constant is duplicated in Rust** (`myotis-net/src/sync.rs`),
   with a cross-check test but no rewrite tooling: `refreshMainnetCheckpoint`
   does not update it. Gnosis/sepolia are not wired in the Rust engine at all.
4. **Live-tuned LC-server behavior — preserve it** (learned the hard way,
   documented in #130): mainstream LC servers (Lighthouse) truncate a count=16
   `updates_by_range` to ONE ~27 KB chunk (rate limiter, ~1 req/10 s/peer);
   identical full-span fan-out is CORRECT and staggered disjoint ranges are
   WORSE; never cooldown a serving peer; exponential backoff (5→60 s) on empty
   rounds; evict unproven peers at 1 failure, proven at 3, serve resets.
5. Optional polish not done: `rust.yml` CI job, jniLibs packaging notes in doc
   05, per-negative rejection-reason codes in the conformance corpus (a Rust
   decoder rejecting for the WRONG reason still matches today), network-tagged
   `VectorDump` filenames (needed before capturing a gnosis corpus).

## Carried review findings (from phase-1 PR reviews — still apply)

- **JNI panic convention:** the workspace builds with `panic = "abort"`, so
  `catch_unwind` is a no-op and any panic crossing JNI kills the app process.
  Native paths must be panic-free by construction (checked reads, `Err` not
  `unwrap`); keep that discipline for every new native.
- **`create()` must stay all-or-nothing** (no side effects on failure):
  `SelectorEngine`'s auto-fallback creates with the Java engine after a Rust
  failure, so a half-created Rust chain would double-host.
- `RustMyotisEngine`'s "Supported: mainnet, sepolia, gnosis" error text is a
  hand-copy of `NetworkConfig.byName`'s — keep in sync when networks change.
- **OPEN (user decision pending): extraData-offset leniency.** Both the Java
  and Rust `ExecutionPayloadHeader` decoders tolerate out-of-range extraData
  offsets (decode as empty) instead of rejecting — declined in #129 for Java
  parity; believed inert because a wrong EPH root fails the signed
  execution-branch check. If tightened: change BOTH decoders in one PR + add a
  malformed-offset corpus vector + regen expected.txt. Re-surface during the
  EL phase or any security review.

## EL-phase entry

The EL phase (discv4/RLPx/eth/snap → MPT → revm; spec in
[02](02-execution-networking.md) and [03](03-state-verification-and-evm.md),
crate map in [README §7](README.md)) starts only when the user says go, informed
by: the benchmark numbers, the Pixel re-test of the fixed Java build, and the
embeddability targets. Before trusting a latency comparison, close gap #1 above
and re-run `rust/bench/sync_bench.sh` under fresh peer conditions.

**The execution plan for the phase is
[07-el-implementation-plan.md](07-el-implementation-plan.md)** — milestones
A (devp2p + MPT + verified account/storage/headers, ending at the CLAUDE.md
integration gate on `-Pengine=rust`), B (full `VerifiedReads`), C (revm + ENS).
Design decisions recorded there (user-confirmed 2026-07-06): hand-rolled devp2p
on small primitive crates (not reth), hand-ported MPT verifier (not alloy-trie),
new sans-I/O `myotis-core` crate + `el/` modules in `myotis-net`.
