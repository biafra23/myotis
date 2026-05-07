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

## Approach (decision)

The Phase 0 plan flagged two options: sentinel-return and trace-based
access tracking. `docs/decisions.md` already recorded the Phase 2
recommendation as **trace-based** — that decision stands.

Rationale, re-stated:

- Sentinel-return runs the EVM with a placeholder value for every miss
  and collects the access list. Data-dependent branches can take a
  *different* path with the placeholder, so the access list captures
  slots the real run would never touch — and misses ones it does. The
  loop converges, but slowly and with wasted bandwidth.
- Trace-based uses Besu's `OperationTracer.tracePreExecution` hook to
  observe SLOAD's stack arguments (account from `getRecipientAddress()`,
  slot from `getStackItem(0)`) and EXTCODECOPY / EXTCODEHASH / EXTCODESIZE
  for the target accounts whose bytecode the EVM may need — without
  changing what the EVM reads. (`getRecipientAddress()` returns the
  storage-owning account in Besu's frame model: the called contract for
  CALL, the caller for DELEGATECALL.)
  Access list is exact for the path the EVM would have taken. No false
  positives or negatives.

Trade-off: the trace-based approach still observes behaviour from a *first*
EVM run that necessarily misses on every fetch (since the cache is empty).
That first run is slow — every miss is a blocking SyncStateView fetch.
Subsequent runs use the populated cache and fly. The convergence loop
exists because data-dependent branches in the real path may issue new
fetches once earlier values are populated; we re-run to catch those.

## Wire-up

The Phase 0/1 architecture has `DefaultEvmExecutor` driving Besu's EVM
through `MessageCallProcessor.process()` against a `SnapWorldUpdater`.
The tracer hook is the natural insertion point — pass a non-`NO_TRACING`
tracer that observes (but doesn't mutate) execution.

```
PrefetchingEvmExecutor.callView(target, calldata, ctx)
  loop iteration ≤ iterationCap:
    tracer = new PrefetchingTracer()
    DefaultEvmExecutor.runOnceWithTracer(target, calldata, ctx, tracer)
        ↳ Besu EVM executes normally; tracer records SLOAD/CODE* ops
    new misses = tracer.observed - already-cached
    if new misses is empty: return result        // converged
    batch fetch new misses through SnapPeer in parallel
    populate per-call cache (BytecodeCache + an in-call storage cache)
  after loop: throw IterationLimitExceeded
```

The first iteration's run is SLOW — each miss is a serial blocking fetch.
Subsequent iterations are fast because the cache satisfies the hits. That
matches the plan's expectation: "first run is slow but produces a complete
access list; subsequent runs use the parallel-batched cache."

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

## Honesty about latency

The trace-based design's win was always nuanced. Worth being explicit so
future readers don't over-promise:

- **Iteration 0 is fully serial.** Every cache miss blocks on a synchronous
  `SyncStateView.account()` / `storage()` call, which `join()`s the
  oracle's per-call retry path. There is no parallelism in iteration 0.
- **The "parallel prefetch wave" between iterations is largely a no-op
  for data-independent contracts.** By the time the wave runs, iteration
  N's synchronous reads have already populated the SyncStateView cache
  for every successfully-executed access. The wave's `view.hasAccount(a)
  ? skip : fetch` predicate skips almost everything.
- **Where the wave actually helps:** iterations N+1 onwards that take a
  *different* data-dependent path than iteration N — the cache is shared
  but the access set changed. Rare in practice for the Phase 2 corpus
  (ERC-20 balances, ENS resolver lookups), more common in contracts with
  branching on storage values.
- **The convergence loop's primary value is correctness, not speed.**
  Iteration 1 verifies the access set is stable, which is the trust
  property — without it we wouldn't know if data-dependent branches
  matter. The latency saved relative to `DefaultEvmExecutor` alone is
  whatever round trips iteration N+1's parallel fetches saved over the
  serial reads they replace, which is `0` when N+1's accesses are a
  subset of N's.

A genuine end-to-end latency win requires a different design — sentinel-
return for iteration 0 (run with placeholders, get the access list
without blocking on each miss, then parallel-fetch and run for real).
That's deferred to a future phase. The current code ships the structural
prerequisites: tracer hooks, convergence-loop scaffolding, per-call cache.
A sentinel-return mode is additive on top.

The Phase 2 acceptance criteria (`≤3 iterations, p95 < 2s`) are still
achievable with the current design — they're statements about iteration
counts and total latency, not about parallel-fetch ratios. Whether the
current design hits the p95 target is something we'll only know once
the benchmark runs against mainnet.

## What this branch ships

- Commit 1 (`bf09dcd`): design doc + `PrefetchingTracer` + `PrefetchingEvmExecutor`.
  Tracer observes SLOAD / EXTCODE* on every opcode; executor drives the
  convergence loop; fixture-oracle unit tests prove the loop converges in
  2 iterations on simple cases and respects the iteration cap.
- Commit 2 (this one): benchmark scaffolding —
  `MainnetPrefetchBenchmarkIT` measures latency and iteration counts for
  the corpus, `docs/prefetch-benchmarks.md` is the artifact callers paste
  numbers into. Same env-gating as Phase 1's `MainnetCallViewIT`; both
  ITs share the missing `connectToMainnetPeer()` helper. Originally
  drafted as "wire-level batching in `SnapBackedStateOracle`", but tracing
  through the existing prefetcher logic showed the parallel-fetch path
  is already in place — the next real win comes from measuring against
  mainnet, not from condensing N parallel wire requests into 1.

## Deliberately not in this commit

- **Wire-level batching in `SnapBackedStateOracle`.** The current loop
  fires N parallel `oracle.fetchAccount` / `fetchStorage` calls; each
  goes through the per-key retry loop independently. Folding them into
  one `peer.getTrieNodes` request with N path-sets saves wire round
  trips, which probably doesn't move p95 latency much (the peer
  pipelines well), but it does reduce peer load. Defer until benchmark
  numbers say it matters.
- **Bytecode prefetching as a separate wave.** Tried it in an earlier
  draft of commit 2 and reverted: `SyncStateView.bytecode()` already
  populates the shared `BytecodeCache` synchronously during the run that
  records the access. A separate "fetch new accounts' bytecode" wave
  between iterations finds everything already cached. No latency win.
- **Sentinel-return mode.** The plan flagged it as an alternative; the
  trace-based design we shipped in commit 1 is the choice. Revisiting
  would require pulling apart the convergence-loop assumptions and isn't
  motivated until the benchmark numbers say trace-based isn't fast enough.

## Out of scope

- Changing the public `EvmExecutor.callView` signature. The prefetch
  layer is constructed by the wallet integration — the same way the
  oracle is.
- Cross-call cache. The plan calls out a per-stateRoot cache for the
  duration of a session; that's a Phase 2-adjacent concern that lives in
  the wallet layer, not in the EVM module's prefetch loop.
