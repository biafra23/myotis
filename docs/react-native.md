# React Native (Android + iOS) integration — design & roadmap

Status: **design only.** Nothing in this document is implemented yet; it
records what is necessary to consume myotis from a React Native app on
Android and iOS, what already exists (much more than one would expect,
especially for iOS), the decisions taken, and a phased plan. Facts marked
*(feat/ios-target)* live on that unmerged branch; everything else is on
`main`.

## Goal & constraints

- A React Native wallet app must use myotis **on the native side**: the
  engine needs raw UDP/TCP sockets (discv4/discv5, RLPx, libp2p), which the
  JS runtime cannot provide. JS gets a thin, typed API over a native module;
  all protocol work, verification, and persistence stay native.
- The trust model is unchanged: everything cryptographically verified, data
  only via devp2p/libp2p (see CLAUDE.md "Trust" / "Data sources").
- The engine's **poll-only status contract is preserved**. `ChainHandle`
  deliberately exposes getters, not callbacks, so the surface stays
  FFI-portable — the RN layer polls natively and *emits* to JS; we do not
  add a callback seam to the engine.

## What already exists

The integration builds on three assets:

   > **Note (updated):** `:android-app` no longer commits the `.so` binaries.
   > It builds the Rust engine **from source** by default (cargo + cargo-ndk +
   > NDK required; `-PskipRustEngine` opts out to the Java engine). The
   > "committed jniLibs as a no-toolchain fallback" model described in this
   > proposal is stale; an RN package can still ship prebuilt binaries **in its
   > published npm tarball** without committing them to git — decide that
   > independently rather than by analogy to `:android-app`.

1. **Android: RN-ready today.** The Rust engine ships behind the UniFFI
   surface (`myotis-engines/.../RustEngineNative.java` over the generated
   Kotlin bindings), so consumers on the published package build without a
   Rust toolchain. Compound values cross as JSON strings pinned by golden
   tests on both sides (`rust/testdata/networks_catalog.json`, the
   `Rust*JsonTest` suite).

2. **iOS: the seam exists on `feat/ios-target`.** That branch contains:
   - `rust/myotis-engine/src/capi.rs` — a plain C ABI beside the JNI shim,
     1:1 over the same `host.rs`: JSON strings + scalars in/out, errors as
     sentinels (negative handle ids, `false`, `{"error":...}`), every
     returned `char*` released via `myotis_string_free`. **No callbacks** —
     the engine self-persists its node key, peer caches, and finality
     snapshots under `data_dir`, so the FFI is purely blocking call-in.
   - `rust/include/myotis_engine.h` — the hand-written header, consumed via
     Kotlin/Native cinterop by `:app-ios`.
   - Cargo tasks `cargoBuildIosDevice` / `cargoBuildIosSim`
     (aarch64-apple-ios, aarch64-apple-ios-sim) producing
     `libmyotis_engine.a`.
   - `:app-ios` (Kotlin/Native `MyotisKit.framework` bundling the Compose
     `:ui`) and the `ios-app/` Xcode shell — proof the C ABI hosts a real
     iOS light client (`app-ios/src/iosMain/kotlin/io/myotis/ios/RustEngine.kt`,
     `IosNodeController.kt`).

3. **Engine features on `main`.** ABI 14 includes verified reads
   (account/storage/code), revm `eth_call`/`estimateGas`, `sendRawTransaction`,
   verified `eth_getTransactionReceipt` (PR #234), fee estimates, full ENS
   incl. CCIP-Read re-entry, block-by-number, pause/resume idle-sleep, and
   the drainable log ring — for mainnet, sepolia, and gnosis.

The known drift: the `feat/ios-target` C ABI was written against engine
ABI **13**; `main` is at **14**. `capi.rs`/`myotis_engine.h` lack
`myotis_get_transaction_receipt_json` and their handshake expectation needs
the bump. Per the lockstep rule
(docs/reimplementation/05-engine-api-bindings.md), every future ABI
bump must update **both shims and the C header together**.

## Decisions

### Rust engine on both platforms

The RN package uses the Rust engine on Android too, not just iOS (where it
is the only option — the JVM engine can never run there).

- One engine → one behavior → one QA surface behind the JS API. Shipping
  Java-on-Android would mean permanent cross-engine divergence testing
  inside the RN layer.
- The RN Android artifact stays tiny and clean: `:myotis-api` +
  `:myotis-engines` + two `.so`s. Pulling `:node-core` into third-party RN
  apps would export the entire dependency-hygiene problem `android-app`
  solved internally (Besu ART fork, single-Netty policy, BouncyCastle
  provider order, log4j shim, desugaring constraints).
- The engine selector is untouched for existing hosts; the RN module binds
  `RustMyotisEngine` directly (or pins `myotis.engine=rust`). The three
  `RustChainHandle` methods that still throw (`getHeaders`,
  `getBlockVerified`, `dialPeer`) are diagnostics, not wallet-blocking; see
  Gaps.

### iOS binding: the existing C ABI, wrapped in Swift

RN iOS consumes `rust/include/myotis_engine.h` directly through a thin
Swift marshalling layer — the Swift twin of `:app-ios`'s `RustEngine.kt`
and `:myotis-engines`' minimal-json layer (JSON decode, error mapping,
`myotis_string_free` discipline, pause/resume idempotency accounting as in
`RustChainHandle.java`).

- **Not** via the Kotlin/Native `MyotisKit.framework`: it bundles Compose
  UI and would force the K/N toolchain onto every RN consumer. (A UI-free
  K/N "engine-only" framework shared by `:app-ios` and RN was considered
  and rejected for the same toolchain-weight reason.)
- **Not** via UniFFI-for-RN: the JVM boundary now IS UniFFI (the hand-JNI was
  swapped out, 2026-07 — see docs/reimplementation/06), but that covers
  Kotlin/JVM hosts; an RN shim would still need its own C surface, and with
  zero engine→host callbacks in the FFI, UniFFI's main selling point
  (callback interfaces) buys nothing extra here.
- Panic policy carries over: the workspace builds `panic = "abort"`, so the
  C shim must stay unwrap-free by construction like `ffi.rs`/`capi.rs`;
  a panic kills the RN app process.

### Alternative considered: a JS-side engine

Implementing the engine itself in JavaScript inside the RN app was
evaluated and **rejected**. For the record, since the question recurs:

- **There is no pure-JS variant.** RN's JS runtime (Hermes/JSC) has no
  TCP/UDP API at all; the only route is native socket-shim modules
  (`react-native-tcp-socket`, `react-native-udp`). So a "JS engine" still
  keeps sockets native and instead pays per-packet bridge marshalling in
  both directions — the bridge's worst-case workload, given how chatty
  discovery and RLPx framing are.
- **Crypto cost, with no escape hatch.** ECIES, AES-CTR framing, keccak,
  secp256k1, and BLS fast-aggregate-verify in pure JS (noble/ethereumjs)
  run 10–100× slower than blst/native — a sustained battery tax for
  continuous sync. Hermes has no WebAssembly, so compiling the existing
  Rust crates to WASM is not available in the default RN engine.
- **The ecosystem targets Node, not RN.** `@ethereumjs/devp2p`,
  js-libp2p, Lodestar, and `@ethereumjs/evm` are real building blocks,
  but they sit on Node's `net`/`dgram`/worker APIs — ports, not
  drop-ins.
- **Lifecycle gets worse, not better.** The JS runtime only runs while
  RN runs: iOS background JS is effectively nonexistent, Android
  headless-JS is fragile. This doc already rejects headless-JS as the
  wrong lifetime for sockets even as a *service host*; a JS engine would
  make it the only mode.
- **A third verification surface.** The trust model ("peer trusted is
  never an option") would gain a third independent implementation after
  Java and Rust — tripling where a verification bug can hide, without
  the golden-test parity that pins the two existing engines to each
  other.

What deliberately *does* live on the JS side is everything above the
`VerifiedReads` line: wallet/account state, transaction construction and
ABI encoding, signing orchestration, ENS UX, polling orchestration, and
all UI logic. That split is what the module shape below is designed
around.

### RN module shape

One package, `react-native-myotis/`, built as a **New Architecture Turbo
Module** (with interop mode for old-architecture apps; no investment in the
legacy bridge).

```
react-native-myotis/
  package.json                    # codegenConfig for the TurboModule spec
  src/NativeMyotis.ts             # codegen spec
  src/index.ts                    # public TS API (engine/chain/reads/ens classes)
  android/                        # Kotlin Turbo Module + foreground service,
                                  # AAR over :myotis-api + :myotis-engines + jniLibs
  ios/                            # Swift Turbo Module over myotis_engine.h
  react-native-myotis.podspec     # vendors the prebuilt Rust library
examples/rn-demo/                 # bare RN app used as the validation harness
```

- **TypeScript surface**: promise-based mirror of `MyotisEngine` /
  `ChainHandle` / `VerifiedReads` / `EnsApi`. Chains are opaque handle ids.
  All natives run on a native query pool (the `NodeService` `QUERY_POOL`
  pattern), never the JS or UI thread — verified reads block up to ~90 s.
- **Binary values cross as 0x-hex strings**, not base64: the JSON ABI is
  already hex end-to-end (`resultHex`, `dataHex`, addresses), so hex keeps
  one convention and stays debuggable. Composite results cross in their
  existing pinned JSON shapes and are parsed once in TS.
- **Events**: the native layer owns a poll loop per running chain — every
  2 s call status/beacon status, diff against the last snapshot, emit
  `onMyotisStatus` / `onMyotisBeaconStatus` only on change; every 5 s drain
  the log ring (`Engines.drainRustLogs` / `myotis_drain_logs`) into
  `onMyotisLog`. This is exactly `AndroidNodeBridge.kt`'s snapshot-poll→Flow
  pattern and `IosNodeController.kt`'s 2 s `delay` loop, relocated. Pull
  (`chain.status()`) remains available.
  The loop is **listener-gated**: it runs only while JS listeners are
  registered — `startObserving`/`stopObserving` in interop mode, listener
  count tracking with the New-Architecture `EventEmitter` — and is torn
  down entirely when the last listener unsubscribes or the app backgrounds
  (on iOS the chains pause then anyway). No listeners → zero polling →
  zero wakeups; a fresh subscriber gets one immediate snapshot emit before
  the cadence resumes.

### Lifecycle per platform

- **Android**: a `dataSync` foreground service, reusing the solved
  `NodeService.java` playbook — per-network boot threads + `bootLock`,
  query pool, idle-pause after N minutes, `onTrimMemory` emergency pause,
  WorkManager daily catch-up, ConnectivityManager refresh, Rust log pump.
  Optionally extract the engine-facing core into a `:myotis-host-android`
  library shared by `android-app` and the RN module (the RN module needs
  none of the Java-engine port adapters — the Rust engine self-persists).
  Headless-JS is rejected: the JS runtime's lifetime is the wrong lifetime
  for sockets.
- **iOS**: no foreground-service equivalent exists; the engine's
  pause/resume idle-sleep contract maps onto the platform instead.
  Foreground → RUNNING with the poll loop live. On
  `sceneDidEnterBackground` → `beginBackgroundTask` (~30 s grace) →
  `myotis_pause` (tear down sockets/timers, keep warm state) → schedule a
  `BGAppRefreshTaskRequest` (plus an opportunistic `BGProcessingTaskRequest`
  for longer catch-ups). BG task fires → `myotis_resume` (warm start from
  persisted snapshot + peer caches, no checkpoint re-bootstrap) → sync
  within the budget → `myotis_pause` → reschedule. Accept the platform
  truth: after long background periods the verified head is stale until the
  next resume (`readiness-and-verified-head-age.md` already models this).
  **Watchdog invariant**: every `beginBackgroundTask` is paired with an
  `endBackgroundTask` on *both* exits — in a `defer` once `myotis_pause`
  returns, and unconditionally in the expiration handler — because a
  leaked or overrun background task gets the process killed by the iOS
  watchdog. Likewise every `BGTask` path must reach `setTaskCompleted`
  (including from `expirationHandler`). A timing test must confirm
  `myotis_pause` completes well inside the iOS grace window — it is what
  makes this pairing safe rather than hopeful.

### Packaging

- **Android**: an AAR bundling the Kotlin module, `:myotis-api` +
  `:myotis-engines`, and the same jniLibs (arm64-v8a, x86_64; 16 KB
  page-size alignment inherited from `rust/.cargo/config.toml` +
  `build-android.sh`). Build those `.so`s from source via `cargoNdkAndroid`
  at package-assembly time and bundle them into the AAR / npm tarball —
  `:android-app` builds them from source (no committed `.so`, no self-skip
  fallback) and this package should do the same, shipping the binaries in the
  published artifact rather than committing them.
- **iOS**: the podspec vendors a prebuilt `libmyotis_engine.a` per slice
  (device + simulator — an xcframework assembly step over the existing
  `cargoBuildIosDevice`/`cargoBuildIosSim` outputs) plus
  `myotis_engine.h`. Mirror the jniLibs strategy: **commit the prebuilt
  binaries** (or a checked-in zip + checksum) so non-Mac contributors and
  CI build without Rust/Xcode; the `myotis_init` ABI handshake is the
  stale-binary guard, exactly like `RustEngineNative.EXPECTED_ABI_VERSION`.
  On repository size: committed binaries do grow history on every engine
  update — this is the repo's deliberate, existing trade-off (the Android
  `.so`s are committed today for the same no-toolchain reason), and RN
  *consumers* are unaffected either way, since the published npm tarball
  ships the binaries and never touches git history. If growth becomes a
  problem, the named escalation path is prebuilt archives on GitHub
  Releases fetched by a checksum-pinned `prepare_command`/Gradle task (or
  Git LFS); the `myotis_init` handshake stays the staleness guard in every
  variant.

## Gaps to close

| Gap | Where | Action |
|---|---|---|
| C ABI is at engine ABI 13, `main` at 14 | `feat/ios-target` | Rebase/merge onto `main`; add `myotis_get_transaction_receipt_json` to `capi.rs` + header; bump the handshake expectation. Land the branch — it is the foundation of everything iOS. |
| CCIP-Read unsupported off-JVM | `IosNodeController.resolveEns` returns "doesn't support yet" for `status:"offchain"` | Port `CcipDriver.java` (round cap, `{sender}`/`{data}` URL templates, GET/POST, re-entry via `method:"ccipCallback"`) to the RN Swift layer using URLSession. `:app-ios` can adopt the same later (Ktor-Darwin is the Kotlin option per the CLAUDE.md HTTP policy). |
| `getHeaders` / `getBlockVerified` / `dialPeer` throw | `RustChainHandle.java` | Parallel track in the Rust engine (ABI bump, both shims + C header in lockstep). TS API marks them experimental until landed. |
| `eth_getLogs` / subscriptions | both engines | Out of scope for this roadmap; document in the RN README. |
| C ABI untested on Linux CI | `capi.rs` | Add extern-"C" round-trip `cargo test`s (callable on any host target) so the RN-critical seam is CI-covered without a Mac. |
| Pause latency bound | engine | Timing assertion that `nativePause`/`myotis_pause` fits the iOS ~30 s background grace window. |
| `NodeService` logic locked inside `android-app` | `NodeService.java` | Optional extraction of `:myotis-host-android` when P1 starts, so the service logic isn't copy-pasted. |

## Phases

Effort assumes the `feat/ios-target` groundwork lands first; the critical
path is P0 → P2 → P3, with P1 parallel.

- **P0 — land `feat/ios-target` refreshed to ABI 14** (~days).
  Validation: golden tests green on both shims; C-ABI round-trip tests on
  Linux; `:app-ios` simulator build.
- **P1 — RN package skeleton + Android module** (~2 weeks). TS spec +
  codegen, Kotlin Turbo Module over `RustMyotisEngine`, foreground service,
  poll→emitter, AAR packaging. Validation: `examples/rn-demo` on Android
  showing live status events, a verified `getBalance`, an ENS resolve.
- **P2 — RN iOS binding** (~1–2 weeks, needs a Mac). Swift marshalling over
  `myotis_engine.h`, podspec/xcframework with committed binaries.
  Validation: the same demo on an iOS simulator and device; sepolia sync
  end-to-end.
- **P3 — iOS lifecycle + CCIP** (~1–2 weeks). Scene-phase pause/resume,
  BGTaskScheduler refresh/processing tasks, Swift CCIP driver. Validation:
  warm-resume assertion (no re-bootstrap after backgrounding), a CCIP name
  resolving, an overnight BG-refresh soak showing periodic head advances.
- **P4 — hardening & release** (~1 week). One TS test suite run against
  both platforms (behavior diff), AAR/pod size audit, stale-binary guard
  tests, npm packaging dry-run, docs.
- **Parallel** (any time after P0): implement the three missing
  `RustChainHandle` methods in the Rust engine.

## Reference files

- `rust/myotis-engine/src/lib.rs` (`ABI_VERSION`, `jni_shim`),
  `src/host.rs` (the binding-neutral surface both shims share),
  `src/capi.rs` + `rust/include/myotis_engine.h` *(feat/ios-target)*
- `myotis-engines/src/main/java/io/myotis/engines/` —
  `RustEngineNative.java`, `RustChainHandle.java` (the wrapper contract the
  Swift layer ports), `CcipDriver.java`
- `app-ios/src/iosMain/kotlin/io/myotis/ios/RustEngine.kt`,
  `IosNodeController.kt` *(feat/ios-target)*
- `android-app/src/main/java/com/jaeckel/ethp2p/android/NodeService.java`
  (lifecycle playbook), `android-app/build.gradle.kts` (jniLibs fallback)
- `docs/reimplementation/05-engine-api-bindings.md` (binding decisions,
  lockstep rule), `docs/myotis-rust-engine-guidelines.md` (target matrix —
  explicitly lists a React Native app as an intended consumer)
