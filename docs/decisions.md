# myotis-evm — implementation decisions

Tracks the answers to "Open Questions for the Implementer" in the original
plan, plus deviations made during implementation.

## Language: Java, not Kotlin

The plan was drafted in Kotlin; the existing project (apart from `android-app`)
is Java + Gradle Kotlin DSL. Adopting Kotlin in this module would have
required the Kotlin/JVM plugin and `kotlinx-coroutines-core` for `suspend`,
which would diverge from the rest of the JVM modules and bloat the Android
consumer's runtime classpath.

Chosen translation:
- `suspend fun callView(...): Result<X, Y>` → `CompletableFuture<X> callView(...)`
- Errors propagated as `EvmExecutionException` whose `error()` carries a
  typed `EvmExecutionError` (sealed interface; functionally equivalent to a
  Kotlin sealed class for pattern-matching).
- `data class` / sealed class → Java records / sealed interfaces.

When `myotis-evm` is consumed from Android Kotlin, callers can wrap the
`CompletableFuture` with `kotlinx.coroutines.future.await` for the same
ergonomics.

## Open question 1 — Sentinel-return vs. trace-based access tracking (Phase 2)

Deferred to Phase 2 implementation. Phase 0/1 use the simpler synchronous
`SyncStateView` that joins on each oracle call. The `AccessTracker` class is
already in place to record (address, slot) and codeHash misses per call.

Recommended path for Phase 2: **trace-based**. Besu's `OperationTracer`
exposes `tracePreExecution(MessageFrame)` which fires before every opcode
dispatch. We can intercept SLOAD's stack arguments and record the access
without affecting the value the EVM ultimately reads. This avoids the
correctness fragility of sentinel-return (where data-dependent branches
can take "the wrong path" on the first pass and miss slots that are only
read on the correct path).

Document the chosen path in Phase 2's PR.

## Open question 2 — Persistent bytecode cache layout

Deferred. The Phase 0 `BytecodeCache.inMemory()` is intentional: it works
for tests and per-session use without committing to a storage backend.

The recommendation, when wired into the wallet:
- Reuse the existing Myotis SQLite database (`code_hash BLOB PRIMARY KEY,
  bytecode BLOB`).
- Bytecode is immutable; no eviction policy is needed in v1.
- A simple `ON CONFLICT IGNORE` insert handles the dedup.

A separate file-based cache (e.g. content-addressed under
`$cacheDir/bytecode/<first-2-hex-bytes>/<full-hash>`) is also viable and
avoids large-blob churn in SQLite. Decision to be made when the wallet
team integrates this module.

## Open question 3 — CCIP-Read gateway selection strategy

The handler tries each URL in order, per spec ("try each in order"). No
randomisation. Rationale:

- Resolvers typically list the canonical operator's gateway first and a
  failover second; randomising would silently shift load to the failover
  even when the primary is healthy.
- Operators that want load distribution can list multiple URLs and use
  client-side or DNS-level mechanisms.

Revisit if measurable: if a gateway emerges as a centralisation point
across the wallet's user base, randomising the order across users (not
within a single call) would help.

## Open question 4 — Reverse ENS resolution edge cases

Documented for Phase 3. ENSIP-3 reverse resolution requires a verification
step to defeat impersonation: after computing
`name = resolveName(addrToReverseNode(addr))`, the resolver MUST then
re-resolve `name` forward and confirm the resulting address matches the
original `addr`. Without that step, anyone can claim any name in their
reverse record without proof of ownership.

Phase 3's `EnsResolver.resolveName` will perform this verification and
return `null` if the round-trip mismatches.

## Plan deviation — module language for ENS

The plan separates `myotis-ens` into its own Gradle module that depends on
`myotis-evm`. To avoid a half-empty module, the Phase 0 / pre-Phase-3
`Namehash` helper lives in `io.myotis.evm.ens` for now. Phase 3 relocates
it without API impact; only the package import changes.
