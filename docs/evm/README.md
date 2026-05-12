# EVM module docs (`myotis-evm`)

Documents specific to the local EVM module — Hyperledger Besu's standalone
`evm` artifact running against a SNAP-backed `StateOracle`. For
cross-cutting documentation see `../architecture-doc.md` and
`../implementation-status.md`.

| Document | Scope |
|----------|-------|
| [besu-extraction.md](besu-extraction.md) | Dependency footprint of `org.hyperledger.besu:evm`; read before bumping the Besu version or chasing classpath conflicts. |
| [decisions.md](decisions.md) | Implementation decisions tracked against the original "Open Questions for the Implementer" list. |
| [phase1-design.md](phase1-design.md) | Phase 1 — SNAP-backed state oracle. The first end-to-end correct EVM run against a verified `stateRoot`. |
| [phase2-design.md](phase2-design.md) | Phase 2 — speculative prefetching. Eliminates the round-trip-per-SLOAD latency that dominated Phase 1. |
| [phase5-design.md](phase5-design.md) | Phase 5 — local gas estimation via `DefaultEvmExecutor.estimateGas`. Intrinsic + Besu-EVM-metered + 15% buffer; revert / OOG halt instead of returning a number. Validated end-to-end against an Anvil fork. |
| [prefetch-benchmarks.md](prefetch-benchmarks.md) | Convergence iteration counts and end-to-end latency for the Phase 2 corpus. |
