# Myotis Rust Engine — Design Guidelines for Embeddability

> Companion to `docs/myotis-integration.md`. These are constraints to bake into the Myotis
> Rust reimplementation **now, while the code is young**, so that one core serves every
> Kohaku target: desktop daemon / native-messaging host (browser extension), in-process
> Android/iOS (React Native app), and optionally WASM. Retrofitting any of these later is
> far more expensive than respecting them from the first commit.

## Target matrix the engine must serve

| Target | Packaging | Sockets | Threads | Filesystem | Lifecycle |
|---|---|---|---|---|---|
| Desktop daemon / CLI | binary | ✅ raw TCP/UDP | ✅ tokio multi-thread | ✅ | long-running, user-managed |
| Native-messaging host (Chrome/Firefox) | binary, spawned by browser | ✅ raw TCP/UDP | ✅ | ✅ | **spawned/killed on demand** — cold start matters |
| Android (in-process) | `.aar` via UniFFI | ✅ | ✅ (thermal/battery limits) | ✅ app storage | foreground service; OS may kill/restore |
| iOS (in-process) | `.xcframework` via UniFFI | ✅ | ✅ (stricter background limits) | ✅ app storage | aggressive suspension |
| WASM (optional, degraded) | wasm-bindgen pkg | ❌ WebSocket/fetch only | ❌ single-threaded | ❌ IndexedDB via port | MV3 service worker killed after ~30 s idle |

The common denominator drives the architecture: **the core must not assume sockets,
threads, filesystem, or wall-clock time. All of these are host-provided.**

## 1. Sans-I/O core: everything through port traits

The reimplementation spec already injects host ports (keystore, peer cache, DNS, HTTP
gateway, logger, clock). Extend that to the two things currently *not* behind ports:

- **`StreamTransport`** — async open/read/write/close of ordered byte streams. RLPx
  crypto and framing stay in the core; only the byte pipe is host-provided (native: TCP;
  wasm: WebSocket bridge; tests: in-memory duplex).
- **`PacketTransport`** — datagram send/recv for discv4/discv5.

Plus, promote to explicit ports:

- **`Storage`** — atomic key→blob store (node identity, peer caches, LCSS light-client
  snapshot). Native: files; Android/iOS: app storage; wasm: IndexedDB/`chrome.storage`.
  Design snapshots as *small, atomic, versioned blobs* — `chrome.storage` has quotas and
  no partial writes.
- **`Clock`** — both wall time and monotonic time. Never call
  `std::time::Instant::now()` / `SystemTime::now()` in core crates (they panic or lie on
  `wasm32-unknown-unknown`; injected time also enables deterministic tests).
- **`Spawner` + timers** — no direct `tokio::spawn`, `std::thread::spawn`, or
  `tokio::time::sleep` in core crates. The host decides: multi-threaded tokio natively,
  `wasm_bindgen_futures::spawn_local` + `setTimeout` timers in the browser.
- **`Entropy`** — route randomness through `getrandom` (works everywhere with the right
  backend) or an injected source; never seed from time.

**Rule of thumb: `myotis-core`, `myotis-consensus`, `myotis-evm`, `myotis-ens`, and
`myotis-engine` must compile with no dependency on `tokio` (beyond `tokio::sync` if
needed), `mio`, `socket2`, `std::net`, `std::fs`, `std::thread`, or `std::time`
constructors.** Shells own all of those.

## 2. Suggested crate layout

```
myotis-core        # crypto, RLP/SSZ, MPT proof verification        — sans-I/O, no_std-friendly where cheap
myotis-consensus   # beacon light client, BLS gate, LCSS snapshots  — sans-I/O
myotis-evm         # revm over proof-served state                   — sans-I/O
myotis-ens         # ENSIP-10, CCIP-Read (via HttpGateway port)     — sans-I/O
myotis-engine      # orchestration: sync loops, peer mgmt, VerifiedReads — only port traits
myotis-shell-native  # tokio + real sockets + fs + threads → daemon, NM host
myotis-shell-mobile  # UniFFI bindings (.aar / .xcframework), reuses shell-native internals
myotis-shell-wasm    # wasm-bindgen + WebSocket transport + IndexedDB storage (optional)
myotis-jsonrpc     # transport-independent RPC dispatch (see §5)
myotis-cli         # native only
```

## 3. Async & threading discipline

- **Executor-agnostic futures.** Core async code must run on a single-threaded executor.
  Avoid gratuitous `Send + 'static` bounds in core traits; where the native shell needs
  `Send`, use the `cfg(target_arch = "wasm32")` conditional-bound pattern (as reqwest and
  libp2p do) rather than forcing `Send` everywhere or nowhere.
- **No rayon / worker pools in core.** Heavy operations — BLS aggregate verification over
  512-validator committees, EVM runs with proof round-trips — must be structured as
  **chunked, yieldable async tasks** so a single-threaded host stays responsive. The
  native shell may parallelize them via `Spawner`; the wasm shell runs them cooperatively
  (or in a dedicated Web Worker — but never assume `SharedArrayBuffer`/wasm-threads;
  cross-origin isolation in MV3 extensions is not realistically available).
- **Cancellation safety.** Any await point may be the last one (service worker killed,
  phone suspended, NM host SIGKILLed). Persist at explicit checkpoints; never require a
  clean shutdown to avoid corruption. Restart must be idempotent.

## 4. Crypto choices

- **BLS: `blst` with the `portable` feature as the guaranteed-everywhere baseline**, asm
  paths where available. blst compiles for wasm32; benchmark before assuming browser
  performance is a problem (the 76× Android-ART slowdown that motivated the JNI crate was
  a JVM artifact, not intrinsic).
- Prefer pure-Rust RustCrypto crates (`k256`, `sha2`, `sha3`) for everything else — they
  are portable to all targets by construction. Avoid `ring` and anything with mandatory
  platform assembly or a C build that breaks cross-compilation (cargo-ndk, wasm32).
- Keccak/secp256k1 hot paths: measure first; only take native-only accelerations behind
  feature flags with a portable fallback.

## 5. One RPC dispatch layer, many fronts

Implement method dispatch (`eth_*`, `myotis_*`) once, against the engine handle,
transport-independent. Then wrap it in thin fronts:

- **HTTP/WS server** on loopback (daemon mode) — with an auth token or `Origin` check,
  since localhost is reachable by any local process and any webpage.
- **Native-messaging stdio** (Chrome framing: 4-byte LE length + JSON, **≤1 MB per
  host→browser message** — build response chunking into the front, not the dispatch).
- **In-process calls** (UniFFI for mobile, wasm-bindgen for wasm) — same dispatch, no
  serialization detour where avoidable.

Include a `myotis_status` method from day one: version, network, sync state, verified
head, finality lag. Kohaku's provider uses it for detection, the verification badge, and
degraded-mode UX.

## 6. FFI-friendly API boundary

The engine boundary (`MyotisEngine` → `ChainHandle` → `VerifiedReads`) must be expressible
in **both UniFFI and wasm-bindgen** without a redesign:

- DTOs are plain owned `serde` structs — no lifetimes, no generics, no trait objects
  crossing the boundary.
- Methods are `async fn(...) -> Result<T, MyotisError>` with a flat, enumerated error
  type (FFI can't do rich error hierarchies).
- Events/subscriptions (new verified head, sync progress, peer count) via a registered
  callback interface — the one pattern that works over UniFFI callbacks, JS callbacks,
  and channels alike. Avoid returning streams/iterators across the boundary.
- Strict mode semantics preserved at the boundary: unverifiable → typed error, never a
  silently proxied answer.

## 7. Lifecycle: assume the host kills you

This is the single most important behavioral requirement across MV3 service workers,
native-messaging hosts, and mobile OSes:

- **Fast warm start is a feature, not an optimization.** Persist the LCSS snapshot + peer
  caches aggressively (the JVM implementation's ~10 s warm re-sync is the bar; the NM
  host should aim lower since the browser spawns it per session).
- Cold start (weak-subjectivity checkpoint) must be possible headlessly, with progress
  events, and interruptible/resumable.
- Embedded weak-subjectivity checkpoints must be updatable by the host without a binary
  release (host passes a newer checkpoint via config).

## 8. CI gates (cheap now, priceless later)

Add from the first commit of the port traits:

```
cargo check --target wasm32-unknown-unknown -p myotis-core -p myotis-consensus -p myotis-evm -p myotis-ens -p myotis-engine
cargo ndk -t arm64-v8a check          # Android cross-compile of shell-mobile deps
cargo deny check                      # lockfile hygiene; ban wasm-hostile deps from core crates
```

The wasm32 check is the canary: it fails the moment someone adds `std::net`, `tokio/rt`,
`SystemTime::now()`, or a C-asm dependency to a core crate — even if a browser build is
never shipped, this check keeps the core honest about §1.

## 9. Miscellaneous portability traps

- **Logging/metrics:** `tracing` with host-installed subscriber only; no
  `env_logger`/`tracing_subscriber::fmt` init inside core or engine crates.
- **Binary size:** mobile and wasm care; keep `opt-level = "z"` / `lto = true` release
  profiles measured in CI, and avoid mega-deps in core (e.g. full `alloy` when only
  `alloy-rlp`/`alloy-primitives` are needed).
- **DNS:** already a port in the spec — keep it that way (browsers and Android have no
  `/etc/resolv.conf`).
- **No global mutable state / no `lazy_static` singletons holding I/O** — multiple engine
  instances per process must work (tests, multi-network, mobile app restarts).
- **Determinism as a test strategy:** with time, entropy, transport, and storage all
  injected, the whole engine can run under deterministic simulation (fake clock,
  scripted peers) — this is the payoff of sans-I/O beyond portability.

## What this buys Kohaku specifically

- **Desktop extension:** the daemon and native-messaging host are two thin `shell-native`
  fronts over the same dispatch — the Kohaku `MyotisProvider` talks to either without
  caring which.
- **Kohaku mobile apps:** the identical engine ships *in-process* via `shell-mobile`
  (UniFFI), so `rpcProvider: 'myotis'` means the same thing on every platform.
- **Optional in-extension WASM:** ruled out for real P2P (no raw sockets), but a
  wasm-clean core leaves the door open for verified consensus-over-HTTPS light-client
  reads inside the extension as a degraded fallback when no native engine is installed —
  at essentially zero extra engine cost.
