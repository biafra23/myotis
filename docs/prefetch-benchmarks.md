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
they arrive:

- **Iterations**: Trace-based prefetching converges in 2 iterations for any
  contract whose access path is data-independent. ERC-20 `balanceOf` is
  trivially data-independent (the slot is `keccak256(addr || mappingSlot)`,
  computed entirely from inputs). ENS `addr` involves one mapping lookup
  in the Public Resolver — also data-independent. Expected: 2 iterations
  for all three. If we see 3, that's worth investigating; if we see > 3,
  the cap is hit and the call fails.
- **Baseline latency**: ~1 round trip per SLOAD plus 1 for the account.
  USDC's proxy slot + impl mapping = 2 SLOADs + account = ~3 RTT. With
  100 ms RTT to a typical peer, that's ~300 ms baseline p50.
- **Prefetch latency**: 1 RTT for iteration 0's serial fetches +
  1 RTT for the parallel batch + ~0 ms for iteration 1's all-cache run =
  ~200 ms prefetch p50. About 30% faster than baseline at 100 ms RTT;
  the win is bigger at higher RTTs.
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
