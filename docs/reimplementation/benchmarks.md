# Rust engine vs JVM engine — Phase-1 benchmark gate

> The plan's phase-1 exit criterion: side-by-side sync correctness + resource numbers,
> so the EL-phase go/no-go is made on data, not vibes. Harness: `rust/bench/sync_bench.sh`
> (one command, re-runnable). **These are PRELIMINARY v1 numbers** — read the caveats
> before drawing conclusions; a clean multi-run pass is recommended before the final
> EL-phase decision.

## Correctness (the part that is NOT preliminary)

Both engines produce **byte-identical verified state** — this is pinned cryptographically,
independent of the perf runs:

- The captured mainnet light-client corpus (`rust/testdata/lc/mainnet`, 19 updates +
  2 finality updates) replays to **identical verdicts** on both engines
  (`LcVectorConformanceTest` on the JVM, `lc_conformance.rs` on Rust — same
  `expected.txt`).
- In the live perf runs below, both reached SYNCED at the **same sync-committee period
  (1795)** with finalized slots one epoch apart (14696448 vs 14707968 — the gap is just
  wall-clock drift between the sequential runs, not disagreement).

Rust hosting mainnet through `io.myotis.api` is real: `-Pengine=rust` boots the daemon,
bootstraps from the embedded checkpoint, and advances the finalized head via the JNI
`SyncHandle`.

## Resource numbers (v1 — 2026-07-06, single sequential run, one Linux x86-64 box)

| Metric | JVM engine (`-Pengine=java`) | Rust engine R1 (`-Pengine=rust`) |
|---|---|---|
| CPU to SYNCED | 48 s | **15 s** |
| Daemon RSS (steady) | 2156 MiB | **118 MiB** |
| Cold-sync wall-time | 30 s | 890 s |
| Verified state | period 1795 | period 1795 |

Plus the **pure-native** binary (no JVM — the footprint a future iOS / native-messaging
shell could reach): peak RSS ≈ 13 MiB.

## What these numbers do and don't mean (READ THIS)

**Trustworthy signals:**
- **CPU: Rust ~3× lower** (15 s vs 48 s) to reach the same verified state — native BLS +
  no JVM/JIT/GC overhead. Directionally solid and expected.
- **Footprint: order-of-magnitude lower** (118 MiB vs 2156 MiB). This is *real* but
  **scope-caveated** (see below): with `-Pengine=rust` the SelectorEngine never
  instantiates the heavy Java stack (Netty EL, Besu/EVM, jvm-libp2p), so the JVM only
  loads the engine classes + the native CL lib. On mobile/embedded this is the number
  that matters most.

**Confounds — why this is v1, not the final word:**
1. **Scope mismatch.** The JVM run is **full EL+CL** (it stands up the entire Java
   execution-layer + Besu stack); the Rust R1 is **CL-only** (no EL yet). So the
   footprint gap is inflated by capability the Rust engine does not yet have. A fair
   CL-to-CL comparison is the *native* binary vs the JVM's CL subsystem alone — not
   isolated here.
2. **Peer exhaustion.** The runs are sequential, and a full night of testing drained the
   cooperative mainnet LC-server pool. The Rust cold-sync wall-time (890 s vs the JVM's
   30 s) is **dominated by this + the R1's missing persisted peer-cache**, NOT by engine
   speed: the JVM client has years of peer-management tuning (proven-server persistence,
   scoring) the Rust R1 lacks. A pure-native run right after **timed out at 25 min**
   purely from peer starvation. Wall-time is the LEAST trustworthy number here.
3. **Single run.** No averaging; RSS is a coarse `ps` sample.

## Bottom line for the EL-phase decision

> **Correction (2026-07-06, post phone diagnosis):** the working hypothesis that the
> Java wallet failed on phones for resource reasons is **disproven**. On a Pixel 7 the
> Java stack synced fine (PSS 105–283 MiB — ART, not the desktop JVM's 2.1 GiB); the
> "app looks dead" failure was a lock-contention freeze (compare-BLS debug default ×
> store monitor held across verification), fixed in PR #133. So "Java can't run on
> phones" is NOT a valid justification for the port. The Rust case rests on footprint
> (13 MiB native — extension/iOS embeddings per docs/myotis-rust-engine-guidelines.md),
> CPU efficiency, and multi-platform reach. See
> [06-rust-phase-notes.md](06-rust-phase-notes.md).

- **Efficiency: Rust wins clearly** on CPU and (scope-caveated) memory — the mobile /
  extension case benefits most.
- **Sync latency: not yet a clean win.** The Rust R1 catch-up is slower and
  variance-prone, but the cause is a **known, deferred, fixable gap** (persisted
  peer/proven-server cache — the Java CL peer cache's role), not a fundamental Rust
  limitation. This should be closed before latency is re-measured.
- **Recommended before committing to the EL phase:** a clean benchmark pass — fresh peer
  conditions, multiple iterations, and ideally a CL-to-CL footprint comparison — plus the
  peer-cache persistence work so wall-time reflects the engine, not the peer pool.

Re-run any time with `rust/bench/sync_bench.sh [java|rust|native|all]`.
