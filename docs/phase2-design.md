# Phase 2 — Speculative prefetching

Phase 1 made `callView` correct against mainnet — but slow. Each SLOAD or
CODECOPY blocks on a synchronous SNAP round trip, and a single ERC-20
`balanceOf` typically touches 3–10 storage slots through the proxy chain.
At 200 ms per round trip that's 1–2 s of unnecessary serial latency.

> **Goal:** reduce p50 latency to under 1 s on the benchmark corpus by
> parallelising state fetches.

## Acceptance criteria (from the original plan)

- All benchmark cases converge in ≤ 3 iterations.
- p95 latency under 2 s on simulated good network conditions.
- Convergence histogram per contract type recorded in
  `docs/prefetch-benchmarks.md`.

The benchmark corpus (per the plan):

- Plain Solidity ERC-20 (USDC pre-proxy paths)
- EIP-1967 proxy ERC-20 (USDC, DAI)
- Vyper ERC-20 (Curve LP token)
- Rebasing token (stETH)
- ENS Public Resolver `addr()`
- ENS Public Resolver `resolve()` (multi-record path)

## Approach (decision — revised in commit 3)

The Phase 0 plan flagged two options: sentinel-return and trace-based
access tracking. The branch shipped trace-based first (commits 1–2) and
then switched to **sentinel-return** in commit 3, after Copilot's review
on PR #14 surfaced that trace-based's "parallel prefetch wave" was
largely a no-op against a synchronously-caching `SyncStateView`.

The two approaches:

- **Trace-based** (commits 1–2 of this branch): use Besu's
  `OperationTracer.tracePreExecution` to observe SLOAD's stack arguments
  (account from `getRecipientAddress()`, slot from `getStackItem(0)`) and
  EXTCODECOPY / EXTCODEHASH / EXTCODESIZE for target accounts. Access
  list is exact for the EVM's real execution path. Iteration 0 blocks on
  every miss serially.
- **Sentinel-return** (commit 3, current): run the EVM with sentinel
  zeros for cache misses. The tracer still records the access list, but
  no oracle calls are made during iteration 0. Result is bogus and
  discarded. Parallel-fetch the recorded misses, then re-run with sentinel
  mode off to get a real result.

The fundamental advantage of sentinel-return: iteration 0 produces a full
access list at memory speed (0 wire RTTs), so the parallel batch fetch
that follows it actually saves round trips. Trace-based's iteration 0
already paid for those RTTs serially.

The fundamental cost: iteration 0's wrong values can cause the EVM to
take a different path than the real run would. This means:
- The recorded access list may include slots the real path doesn't read
  (over-fetching — wasteful but harmless).
- The recorded access list may miss slots the real path does read (the
  real iteration 1 then blocks serially on them).

In practice both happen rarely for view-style calls. ERC-20 `balanceOf`
and ENS `addr` both produce identical access lists under sentinel and
real runs because the access pattern is purely a function of the inputs.
Where divergence does happen, the convergence loop catches it: iteration
1 records the real-path access set, the loop checks for new misses, and
re-runs iteration 2 if needed.

Special case for the *target contract*: sentinel mode for the target's
account record means its codeHash comes back as `keccak256("")` and the
EVM finds no bytecode to execute, defeating the iteration. The executor
synchronously pre-populates the target's account and bytecode before
iteration 0 starts. Two RTTs upfront, but they would have been paid
during iteration 0 in any other design.

## Wire-up

The Phase 0/1 architecture has `DefaultEvmExecutor` driving Besu's EVM
through `MessageCallProcessor.process()` against a `SnapWorldUpdater`.
Phase 2 adds two seams: a `PrefetchingTracer` plugged into Besu's
`OperationTracer` slot, and a `setSentinelOnMiss(boolean)` toggle on
`SyncStateView` that switches cache-miss behaviour between
"block-on-oracle" and "return placeholder zero".

```
PrefetchingEvmExecutor.callView(target, calldata, ctx)
  primeTarget(view, target)                          // 2 RTTs, blocking
  loop iteration ≤ iterationCap:
    iterationTracker = new AccessTracker()
    view.setAccessTracker(iterationTracker)          // record via view too
    view.setSentinelOnMiss(iter == 0)
    tracer = new PrefetchingTracer(iterationTracker)
    DefaultEvmExecutor.runOnTracedView(target, calldata, ctx, view, tracer)
        ↳ iter 0: sentinel returns on miss, no oracle calls
        ↳ iter 1+: real values from cache or blocking oracle fetch
    if iter == 0:
      // Discard the (bogus) result; keep the access list.
      parallel-batch fetch tracker.snapshot() into the view's cache
      continue
    if tracker.snapshot() ⊆ seenAccesses: return result   // converged
    new misses = tracker.snapshot() - already-cached
    if new misses is empty: return result        // converged
    batch fetch new misses through SnapPeer in parallel
    populate per-call cache (BytecodeCache + an in-call storage cache)
  after loop: throw IterationLimitExceeded
```

Iteration 0 makes no oracle calls (other than the synchronous prime of
the target contract). Every miss returns a placeholder; the tracer and
view together record the access. The result is discarded. The parallel
batch fetch wave then covers all the recorded misses in one round-trip
window. Iteration 1 runs against the populated cache and produces the
real result; any data-dependent accesses iteration 0's wrong path didn't
reach are blocking-fetched serially in iteration 1, which adds them to
the cache for iteration 2 to verify stability if needed.

## Open question (settled in commit 1)

- `PrefetchingEvmExecutor` is a thin wrapper around a `DefaultEvmExecutor`
  delegate (constructor: `new PrefetchingEvmExecutor(DefaultEvmExecutor)`),
  not a sibling executor. The wrapper relies on `DefaultEvmExecutor`'s
  package-private `runOnTracedView(...)` seam to share a single
  `SyncStateView` cache across iterations, and on its package-private
  config accessors (`oracle()`, `bytecodeCache()`, `executor()`) to inherit
  the delegate's wiring. A pure decorator that only delegated `callView`
  wouldn't have access to those internals, so the wrapper deliberately
  reaches into the same package; that coupling is the cost of running the
  same EVM-driving code twice with shared state.

## Latency profile

After commit 3 (sentinel-return), the convergence loop's structure is:

| Step | Mode | Network round trips |
|------|------|---------------------|
| Pre-prime target | Block | 2 RTT (target account + bytecode) |
| Iteration 0 | Sentinel | 0 RTT (records access list at memory speed) |
| Parallel batch fetch | — | 1 RTT (covers all of iter 0's recorded misses) |
| Iteration 1 | Block-on-miss | 0 RTT in the common case (everything is cached) |
| If unstable: iter 2+ | Block-on-miss | 1 RTT per truly data-dependent miss |

For the canonical ERC-20 `balanceOf` (storage at `keccak(holder . slot)`):
~3 RTTs total — 2 for target prime, 1 for the parallel batch covering the
balance slot. Roughly half of the trace-based predecessor's ~5 RTTs.

For a multi-balance call (e.g., reading several token balances of the
same holder via one contract): the saving scales linearly. N independent
SLOADs go from `N · RTT` to `1 · RTT` after the prime.

For chained data-dependent reads (proxy slot → impl bytecode → balance
slot): sentinel-return doesn't help much because each chain link blocks
on its own RTT in iteration 1. The win in proxy patterns comes mostly
from the parallel batch covering the impl slot + same-account storage
slots together.

## Trade-offs we accepted

- **Sentinel iteration 0's result is wrong by construction.** The
  convergence loop guarantees it never leaks — the caller only sees the
  iteration-1+ result that ran with real values. There's a unit test for
  this exact scenario (`sentinelIteration0RevertDoesNotSurface`).
- **Sentinel iteration 0 may revert.** Bytecode that does
  `require(balance > 0)` will revert with a sentinel zero. The executor
  catches the revert during sentinel iteration only and continues with
  whatever access list was recorded up to that point. Iteration 1 with
  real values either succeeds or surfaces the genuine revert.
- **Two extra RTTs upfront** for the target's account + bytecode. Same
  cost the trace-based design paid in iteration 0; just paid earlier.
- **Doesn't help fully chained access patterns.** A proxy that calls into
  another contract that calls into another contract still needs N RTTs
  in iteration 1. Sentinel-return saves on parallel-discoverable
  accesses, not on dependency-chained ones. Documented because future
  contributors might over-attribute latency wins.

## What this branch ships

- Commit 1 (`bf09dcd`): tracer + executor convergence loop scaffolding +
  unit tests. Originally trace-based.
- Commit 2 (`3bea3fd`): benchmark scaffolding —
  `MainnetPrefetchBenchmarkIT` measures latency and iteration counts for
  the corpus, `docs/prefetch-benchmarks.md` is the artifact callers paste
  numbers into. Same env-gating as Phase 1's `MainnetCallViewIT`; both
  ITs share the missing `connectToMainnetPeer()` helper.
- Commit 3 (current): switched to sentinel-return after PR #14 review
  identified that the trace-based parallel-fetch wave was largely a
  no-op against `SyncStateView`'s synchronous cache. `SyncStateView` got
  a `setSentinelOnMiss(boolean)` mode; `PrefetchingEvmExecutor` toggles
  it on for iteration 0 and off thereafter, with a synchronous prime
  step for the target contract beforehand. Three new unit tests pin
  down the new semantics: multi-SLOAD parallel batch, sentinel-revert
  recovery, and direct-vs-prefetched correctness parity across several
  bytecode shapes.

## Deliberately not in this commit

- **Wire-level batching in `SnapBackedStateOracle`.** The current loop
  fires N parallel `oracle.fetchAccount` / `fetchStorage` calls; each
  goes through the per-key retry loop independently. Folding them into
  one `peer.getTrieNodes` request with N path-sets saves wire round
  trips, which probably doesn't move p95 latency much (the peer
  pipelines well), but it does reduce peer load. Defer until benchmark
  numbers say it matters.
- **Bytecode prefetching as a separate wave.** Tried it earlier and
  reverted: bytecode is fetched synchronously during the run that
  records its access, so a separate wave finds everything already
  cached. (Bytecode for *non-target* accounts under sentinel mode
  does miss in iter 0; iter 1 fetches it serially. Could be batched
  with the iter-0-discovered accounts in a future refinement.)
- **Sentinel mode for the target contract.** Pre-priming is intentional;
  see "Special case for the target contract" in the Approach section.

## Out of scope

- Changing the public `EvmExecutor.callView` signature. The prefetch
  layer is constructed by the wallet integration — the same way the
  oracle is.
- Cross-call cache. The plan calls out a per-stateRoot cache for the
  duration of a session; that's a Phase 2-adjacent concern that lives in
  the wallet layer, not in the EVM module's prefetch loop.
