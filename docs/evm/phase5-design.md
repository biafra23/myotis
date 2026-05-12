# Phase 5 — Gas estimation

Phases 0–4 made the EVM execute trustlessly against SNAP-verified state.
Phase 5 puts that machinery to one more concrete use: locally estimating
the gas required to broadcast a transaction, replacing the conservative
fixed limits the wallet would otherwise have to use.

> **Scope:** make `EvmExecutor.estimateGas(UnsignedTransaction)` return
> a number close to what a node would return for `eth_estimateGas`,
> using only verified state and verified bytecode. No RPC fallback.

## Acceptance criteria (from the original plan)

- ✅ `EvmExecutor.estimateGas` works for the benchmark corpus.
- ✅ Estimates within 5% of `eth_estimateGas` for the benchmark transactions
  (`MainnetGasEstimationIT`, env-gated; cross-check on per-test
  `MYOTIS_INTEGRATION_<NAME>_REFERENCE_GAS`):
  - ETH transfer to EOA
  - ETH transfer to contract (WETH deposit)
  - ERC-20 transfer (USDC)
  - ERC-721 transfer (ENS BaseRegistrar)
  - Uniswap V3 exact-input swap (requires operator-supplied calldata)
- ✅ End-to-end IT (`AnvilForkedBroadcastIT`) that builds a USDC.transfer
  with a locally-estimated gas limit, broadcasts it against a forked-
  mainnet Anvil (via `anvil_impersonateAccount`), and asserts the
  receipt succeeded without OOG and `gasUsed <= localEstimate`. This is
  the unique signal that the 15% safety buffer is actually sufficient
  on the wire — the 5%-of-reference cross-check alone can't prove it.

All four are env-gated; `./gradlew check` stays offline. The bootstrap
helper (`app/testing/MainnetPeerBootstrap`) that this phase introduced
unblocks every mainnet IT across Phases 1–5, not just Phase 5's.

## Design

### Gas-cost components

A transaction's total gas cost has three layers per the Yellow Paper:

1. **Intrinsic gas** — paid before any EVM execution starts.
   - `21000` base for a transaction.
   - `4` per zero byte of calldata, `16` per non-zero byte (post-Istanbul,
     EIP-2028).
   - EIP-2930 access-list cost (out of scope for v1; we don't take an
     access list as input).
   - EIP-3860 init-code cost for contract creation (out of scope: v1
     handles `to != null` only).
2. **EVM execution gas** — measured by Besu's `MessageFrame.getRemainingGas()`
   subtracted from the initial-gas budget. Handles all opcode-level
   metering, refund accounting, and the post-Berlin warm/cold storage
   distinction natively.
3. **Safety buffer** — `15%` per the plan. State the EVM read may
   change between estimation and broadcast, gas pricing of one specific
   opcode (e.g. SSTORE refunds) is sensitive to the exact storage
   value, and a slightly-too-high estimate just costs the user some
   priority fee, while a too-low one OOG's the transaction.

### Strategy

```
estimateGas(tx, ctx):
  if tx.to == null:
    fail UnsupportedOperationException        // contract creation v1.1
  intrinsic = 21000
            + 4*zero_bytes(tx.data)
            + 16*nonzero_bytes(tx.data)
  ceiling = tx.gasLimit ?? 30_000_000
  evmBudget = ceiling - intrinsic
  if evmBudget <= 0:
    fail OutOfGas
  run EVM at tx.to with calldata=tx.data, value=tx.value,
              sender=tx.from, initialGas=evmBudget, isStatic=false
  case run.state of
    COMPLETED_SUCCESS:  used = evmBudget - run.remainingGas
                        return ceil((intrinsic + used) * 1.15)
    REVERT (any kind):  fail Reverted(reason)         // do NOT estimate
    INSUFFICIENT_GAS:   fail OutOfGas
    other halt:         fail Reverted(detail)
```

The behaviour for reverting transactions matters: the plan says "do
*not* return a gas estimate for a reverting transaction (the caller
should not broadcast it)." Returning the gas-up-to-revert would let a
broadcasted transaction silently consume gas to revert; failing
explicitly forces the caller to handle it.

### Why not a binary search

`eth_estimateGas` on most node implementations binary-searches the gas
limit between the actual usage and the ceiling, looking for the minimum
that still succeeds. We don't, because:

- It costs N × execution time (typically ~30 iterations).
- The 15% buffer above the high-water mark of one execution captures
  the same slack at one EVM run instead of many.
- For the corpus (transfers, swaps, NFT mints) the gas usage is mostly
  data-independent — one run gives a tight number.

If the corpus reveals cases where a binary search would noticeably
beat the buffer, we can add it as a config flag later. Out of scope
for v1.

### Public surface

`EvmExecutor.estimateGas(UnsignedTransaction tx, BlockContext ctx)` —
already declared in Phase 0 as a default-throwing method. Phase 5
overrides it in `DefaultEvmExecutor` with the real implementation.
`PrefetchingEvmExecutor` and `CcipReadEvmExecutor` inherit the default
unless they want to wrap (Phase 5.1: have the prefetcher run estimation
inside the convergence loop too, so the access list is warmed before
the high-water-mark run; defer until benchmark numbers say it matters).

### Wallet integration

The plan calls for `myotis-tx-builder` to switch from fixed limits to
`estimateGas`. That module doesn't exist in the repo yet — `:app` has a
daemon CLI but not a transaction builder. The integration point is
deferred to whenever the wallet team adds the tx-builder module; this
phase ships the `estimateGas` API ready for it.

## What shipped

PR #17 (initial Phase 5):
- `DefaultEvmExecutor.estimateGas` with intrinsic-gas accounting, EVM
  run with caller-supplied ceiling, 15% buffer, revert/OOG mapping.
  Unit tests for ETH→EOA, call-into-contract, revert path, OOG path.
- `MainnetGasEstimationIT` scaffold covering ETH→EOA, ERC-20, Uniswap V3.

Phase 5 completion (this branch):
- Review-comment fixes orphaned by the merge of PR #17: `evmBudget < 0`
  (was `<= 0`), `Math.ceil` safety buffer (was `Math.round`),
  `scope.get(besuTarget)` caching, dummy CONTRACT address in
  EstimateGasTest, `assumeTrue` skip for the Uniswap IT when realistic
  calldata isn't supplied.
- `MainnetPeerBootstrap` test fixture (`:app.testing`) — unblocks every
  Phase 1–5 mainnet IT by standing up a single RLPx connection from
  inside a test. Drops the four `connectToMainnetPeer()` stubs.
- Missing corpus cases: ETH→contract (WETH deposit) and ERC-721 transfer
  (ENS BaseRegistrar default).
- `AnvilForkedBroadcastIT` — the headline acceptance test. Builds a
  USDC.transfer with the local estimate, broadcasts to a forked Anvil
  via `anvil_impersonateAccount`, asserts receipt success and
  `gasUsed <= estimate`.

## Out of scope

- Contract-creation transactions (`to == null`). Phase 5.1.
- EIP-2930 access lists. Phase 5.1.
- EIP-3860 init-code length cost. Phase 5.1.
- Binary-search refinement. Likely never; the buffer is fine.
- Cross-state-root estimation (using a state different from the one
  the tx will execute against). Out of scope.
