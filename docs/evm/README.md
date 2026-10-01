# EVM module docs (`myotis-evm`)

Documents specific to the **Java engine's** local EVM module — Hyperledger
Besu's standalone `evm` artifact running against a SNAP-backed `StateOracle`.
The **Rust engine** (the default engine) has its own EVM, `rust/myotis-evm`
(revm behind a `SnapStateOracle` trait, same proof-verified state model), which
is where `eth_call`/`eth_estimateGas` run on most installs today; its design
lives in `../reimplementation/03-state-verification-and-evm.md` and
`../reimplementation/07-el-implementation-plan.md`. The phase documents below
are the Java engine's history and are kept as written. For cross-cutting
documentation see `../architecture-doc.md` and `../implementation-status.md`.

| Document | Scope |
|----------|-------|
| [besu-extraction.md](besu-extraction.md) | Dependency footprint of `org.hyperledger.besu:evm`; read before bumping the Besu version or chasing classpath conflicts. |
| [decisions.md](decisions.md) | Implementation decisions tracked against the original "Open Questions for the Implementer" list. |
| [phase1-design.md](phase1-design.md) | Phase 1 — SNAP-backed state oracle. The first end-to-end correct EVM run against a verified `stateRoot`. |
| [phase2-design.md](phase2-design.md) | Phase 2 — speculative prefetching. Eliminates the round-trip-per-SLOAD latency that dominated Phase 1. |
| [phase5-design.md](phase5-design.md) | Phase 5 — local gas estimation via `DefaultEvmExecutor.estimateGas`: geth's search for the lowest gas limit that works, + 15% buffer (#509 stage 2); revert / OOG halt instead of returning a number. Validated end-to-end against an Anvil fork and a recorded mainnet RelayAdapt7702 shield. |
| [prefetch-benchmarks.md](prefetch-benchmarks.md) | Convergence iteration counts and end-to-end latency for the Phase 2 corpus. |
