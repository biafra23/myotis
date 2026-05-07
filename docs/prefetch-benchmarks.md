# Phase 2 prefetch benchmarks

Convergence iteration counts and end-to-end latency for the corpus the
Phase 2 plan calls out, measured with `MainnetPrefetchBenchmarkIT`.

> **Status: scaffolding only.** The benchmark IT compiles and runs the
> measurement loop, but `connectToMainnetPeer()` currently throws
> `UnsupportedOperationException` — the same gap as
> `MainnetCallViewIT`. Both light up when the Phase 1 follow-up that
> extracts an `EthHandler` bootstrap helper out of `:app:Main` lands.
> Until then, the table below carries placeholders.

## Methodology

For each corpus entry the benchmark:

1. Issues one warm-up `callView` (untimed) so the process-local bytecode
   cache is hot.
2. Runs `N = 10` timed iterations against `DefaultEvmExecutor` alone
   (Phase 1 baseline — no convergence loop, every miss is a serial
   round trip).
3. Runs `N = 10` timed iterations against `PrefetchingEvmExecutor`
   (Phase 2). The convergence loop's iteration counts are captured by
   `ConvergenceTracker`.
4. Reports min / p50 / p95 / max wall-clock latency for both modes plus
   the min/max convergence iteration counts.

The acceptance assertions in the IT:

- `convergenceTracker.max() ≤ 3` — every call settles within 3 iterations.
- `prefetchStats.p95 ≤ 2000 ms` — Phase 2's stated latency target.

## Corpus

| Call | Description | Why it's in the corpus |
|------|-------------|------------------------|
| `USDC.balanceOf(vitalik)` | EIP-1967 proxy → impl → mapping read | Most common ERC-20 path; canonical proxy SLOAD |
| `DAI.balanceOf(vitalik)` | Plain Solidity ERC-20 | Different storage layout from USDC |
| `ENS.addr(namehash("vitalik.eth"))` | Public Resolver storage read | Multi-step on-chain lookup; no CCIP-Read |

Vyper ERC-20 (Curve LP), rebasing tokens (stETH), and ENS Public Resolver
`resolve()` aren't in the IT yet. Add them once the bootstrap helper lands
and the placeholder numbers below get real values — at that point we'll
know whether the existing three already exercise the corner cases or
whether the additional tokens reveal something new.

## Results

> _to be filled once `MainnetPrefetchBenchmarkIT` runs against a real peer_

| Call | Baseline p50 | Baseline p95 | Prefetch p50 | Prefetch p95 | Iterations (min / max) |
|------|--------------|--------------|--------------|--------------|------------------------|
| USDC.balanceOf | TBD          | TBD          | TBD          | TBD          | TBD                    |
| DAI.balanceOf  | TBD          | TBD          | TBD          | TBD          | TBD                    |
| ENS.addr       | TBD          | TBD          | TBD          | TBD          | TBD                    |

## What we expect to see

Calibration ahead of measurement, so the numbers can be cross-checked when
they arrive. Phase 2 ships the **sentinel-return** convergence loop —
iteration 0 makes no oracle calls aside from priming the target contract;
iteration 1 runs against a cache pre-populated by a parallel batch fetch.

- **Iterations**: Sentinel-return converges in 2 iterations for any contract
  whose access path is data-independent. ERC-20 `balanceOf` is trivially
  data-independent (the slot is `keccak256(addr || mappingSlot)`, computed
  entirely from inputs). ENS `addr` involves one mapping lookup in the
  Public Resolver — also data-independent. Expected: 2 iterations for all
  three. If we see 3, the iter-0 sentinel run took a different path than
  iter 1 (a data-dependent branch); if we see > 3, the cap is hit and the
  call fails.
- **Baseline latency** (`DefaultEvmExecutor`): ~1 round trip per SLOAD
  plus 1 for the account fetch and 1 for the bytecode. USDC's proxy slot
  + impl + balance mapping = ~5 serial RTTs. At 100 ms RTT to a typical
  peer, that's ~500 ms baseline p50.
- **Prefetch latency** (sentinel-return): 2 RTTs for the synchronous
  target prime (account + bytecode), then 0 RTTs in iteration 0 (sentinel
  values), then 1 RTT for the parallel batch covering all the recorded
  storage misses plus any non-target accounts the iter-0 path visited,
  then ~0 ms for iteration 1's all-cache run. Total: ~3 RTTs ≈ 300 ms
  prefetch p50. About 40% faster than baseline at 100 ms RTT; the win
  scales linearly with RTT and with the number of independent storage
  reads on the contract.
- **Where prefetching does NOT help**: chained-dependency calls where
  each step's input depends on the previous step's output (deep proxy
  chains, contracts that resolve a slot's value as the slot index of
  another read). Iteration 1 has to block serially on those, so the
  total latency is roughly the same as the baseline.
- **p95 vs p50**: depends entirely on peer tail latency. The convergence
  loop doesn't add tail-latency surface relative to the baseline.

## Updating this file

After running the benchmark:

```bash
MYOTIS_MAINNET=1 \
  MYOTIS_INTEGRATION_PEER_ENODE=enode://… \
  MYOTIS_INTEGRATION_STATE_ROOT=0x… \
  MYOTIS_INTEGRATION_BLOCK_NUMBER=… \
  MYOTIS_INTEGRATION_BLOCK_TIMESTAMP=… \
  MYOTIS_INTEGRATION_BASE_FEE_WEI=… \
  ./gradlew :myotis-evm:integrationTest --tests "*PrefetchBenchmark*"
```

Paste the printed `[bench]` lines into the table above, then commit the
update. Re-run after any meaningful prefetch-loop change so the table
captures regressions.
