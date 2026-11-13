# Architecture and the host boundary

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read before adding or moving a module, or touching the host ↔ engine wiring. The last section is the full `:myotis-api` host-boundary rule with its documented exemptions.

## Architecture

Key Gradle modules:

- **myotis-engine** — THE ENGINE LIBRARY: a Kotlin Multiplatform module (jvm +
  android targets, no UI) that packages the Rust engine for the hosts — the
  Android AAR (the Myotis app and a separate wallet product) and the desktop jar.
  Published as `eth.myotis:myotis-engine` with its upstream modules (`myotis-api`,
  `myotis-engine-rust`, `myotis-engine-common`, `myotis-engine-ports`,
  `myotis-rpc-policy`; not `:core`, whose Tuweni + BouncyCastle would ride into
  every consumer
  — the root build's `Publishing` section): GitHub Packages and the token-free
  `maven-repo` branch on every `v*` tag plus the AAR and a Maven-repository zip
  as release assets
  (`engine-library.yml`; `publishAllPublicationsToStagingRepository` +
  `scripts/check_engine_library.sh` verify the set; `publishToMavenLocal` for a
  consumer under development). docs/guides/android-library.md is the consumer page.
  `io.myotis.engine.Myotis` is the entry point (`newEngine()`: the Rust engine
  with no loopback listener, for an in-process consumer); it re-exports
  `:myotis-api`, keeping `:myotis-engine-rust` implementation-only (host
  seams re-exported on `Myotis`). Its androidMain owns the jniLibs
  (`cargoNdkAndroid` builds them there from source) and JNA's Android dispatcher,
  so a consumer's APK is complete with the AAR alone. The Myotis apps consume the
  Rust engine through it and keep the Java engine via the selector.
- **myotis-engine-natives** — the desktop half the jar lacks: the Rust engine's
  host library as `eth.myotis:myotis-engine-natives-<platform>`, one plain jar
  per line of its `platforms.txt` (macOS arm64/x64, Linux x64/arm64; Windows
  later), the library at JNA's classpath path. Built by `engine-library.yml`'s
  `host-natives` matrix, one runner per platform, staged with
  `-PengineNativesDir`; without it, this host's own from `cargoBuildHost`.
- **myotis-engine-ios** — the engine library's iOS module
  (`eth.myotis:myotis-engine-ios`; iosArm64 + iosSimulatorArm64): the cinterop of
  the RUST engine's plain C ABI (`rust/include/myotis_engine.h`), with
  libmyotis_engine.a absorbed into each target's cinterop klib,
  `io.myotis.engine.ios.RustEngine` over it — the only code that imports
  `io.myotis.engine.capi` — and, in commonMain over a `NativeEngine` seam, the
  typed API with `io.myotis.api`'s names (`Myotis.newEngine()` → `MyotisEngine` /
  `ChainHandle` / `VerifiedReads` / `EnsApi`), its JSON decoding pinned by the
  JVM side's golden shapes and tested on the simulator (`ios-framework.yml`).
  macOS only (disabled elsewhere), so
  `engine-library.yml` stages it on a macOS runner and merges it into the set.
- **myotis-engines** — the engine SELECTOR (`Engines`/`SelectorEngine`): hosts'
  composition roots call `Engines.engine()`; `myotis.engine=java|rust|auto` routes
  each network (re)start to the Java engine (node-core) or the Rust one.
- **myotis-engine-rust** — the RUST engine behind the contract on its own
  (`RustMyotisEngine`/`RustChainHandle`/`RustVerifiedReads`/`RustEnsApi`, the Tor
  seam): `rust/myotis-engine` over UniFFI-generated Kotlin bindings + JNA (committed
  in this module, regenerated via `uniffiGenerateKotlin`; compound values as JSON
  pinned by golden tests both sides). Java 17, and it depends on nothing from the
  Java engine and carries no HTTP server: the loopback JSON-RPC listener is a PORT
  (`LoopbackRpc`). The selector fills it with the Ktor server (`KtorLoopbackRpc` in
  `:myotis-engines`), so the daemon, the desktop app and the Android app keep the
  listener they always had; an in-process consumer of the engine library (the
  Android AAR's wallet) constructs the engine with no factory and gets a handle that
  answers `reads()` in-process with nothing listening.
- **myotis-engine-common** — the lifecycle primitives both engines' handles wire
  (`WakeGate`, `SleepMetrics`); Java 17 over `:myotis-api` and slf4j.
- **myotis-engine-ports** — the engine library's DEFAULT port actuals
  (`io.myotis.engine.ports`): the node-key file, the file-backed EL and CL peer
  caches, the `HttpURLConnection` CCIP-Read gateway and the per-network file
  layout (`NetworkFiles`), assembled by `DefaultEnginePorts.forNetwork` /
  `Myotis.defaultPorts`. The Android app's former `NodeService` actuals, moved
  here so a consumer of the AAR gets a working engine from two directories; the
  daemon and desktop keep their twins in `:app` for now. Java 17, minSdk-29-safe,
  over `:myotis-api` and slf4j; re-exported (`api`) by `:myotis-engine`.
- **myotis-rpc-policy** — the JSON-RPC serving policy with no server attached
  (`RpcBlockWindow`, the block-selector window of #366; `WebAccessPolicy` /
  `WebOrigins`, the web-page policy's pure half of #502): a dependency-free Kotlin
  Multiplatform module, one definition for the Rust engine, the router in
  `:jsonrpc-server`, the iOS backend and the UI's normalizer parity test.
- **myotis-logindex-presets** — the log index's PREDEFINED CONTRACTS
  (`io.myotis.logindex`: `LogIndexPresets` — RAILGUN, Swarm, Privacy Pools,
  Tornado Cash per network, each from its creation block — and
  `LogIndexDownloads`: download/disk estimates, "cheaper together", the config
  push): dependency-free Kotlin Multiplatform like `:myotis-rpc-policy`, one
  catalog for the Index tab (`:ui`) and for embedding apps (`api` of
  `:myotis-engine` and `:myotis-engine-ios`; `Myotis.LogIndex` is the JVM
  trigger). docs/how-it-works/log-index-presets.md.
- **myotis-api** — THE ENGINE CONTRACT: zero-dependency Java-17 interfaces
  (`io.myotis.api` + `io.myotis.api.ports`) every host consumes exclusively.
  FFI-portable types only (byte[], String, long, double[], enums, flat records;
  blocking methods). Implemented by **node-core**'s `io.myotis.node.api` adapters
  (`JavaMyotisEngine`/`JavaChainHandle` over `ChainStack`/`NodeRegistry`). Designed so a Rust engine can replace the Java one behind the same
  surface — see docs/spec/05-engine-api-bindings.md.
- **core** — Cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** — Three protocol layers, all Netty-based:
  - `discv4` — UDP peer discovery using Kademlia DHT (ping/pong/findnode/neighbors)
  - `rlpx` — TCP transport: EIP-8 ECIES handshake → AES-256-CTR framed channel
  - `eth` — eth/66-69 sub-protocol on top of RLPx (hello → status → ready)
- **consensus** — Sync-committee light client (libp2p, BLS, SSZ)
- **app** — Daemon/CLI entry point, Unix domain socket IPC server, peer caching
- **myotis-evm** — Local EVM execution (Besu) against SNAP-verified state for view calls and gas estimation
- **ui** — Shared Compose Multiplatform screens + the pure-Kotlin seams
  (`NodeController`/`Settings`/`LogSource`/`NetworkStatus`/`QueryHistory`);
  targets Android + Desktop JVM + iOS. Hosts supply the seam actuals.
- **app-ios** — The iOS host: Kotlin/Native framework (`MyotisKit`) bundling `:ui`
  with iOS seam actuals over the Rust engine, through `:myotis-engine-ios` (whose
  libmyotis_engine.a the framework links). The JVM engine never runs on iOS. The Xcode shell lives in
  `ios-app/` (regenerate with `xcodegen generate`).

**Protocol flow**: `DiscV4Service` discovers peers → `Main` dials them via `RLPxConnector.connect()` → `RLPxHandler` performs ECIES handshake (state machine: HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED) → fires `RLPX_READY` event → `EthHandler` runs eth handshake (AWAITING_HELLO → AWAITING_STATUS → READY) → block header requests available.

**Daemon vs Client mode**: `Main` checks if the Unix socket (`/tmp/ethp2p.sock`) is already listening. No args = daemon mode (discovery + RLPx + IPC server). With args = client mode (send JSON command and exit).

## Conventions

- All protocol messages use Tuweni `RLP.encode()`/`RLP.decode()` for serialization
- State machines are explicit enums in handler classes (not generic FSM framework)
- Concurrent collections (`ConcurrentHashMap.newKeySet()`) for shared mutable state
- IPC uses JSON-Lines over Unix domain sockets with Java 21 virtual threads
- Network configs (genesis hash, fork ID, bootnodes) live in `NetworkConfig`
- **Hosts talk ONLY to `:myotis-api`** (`MyotisEngine`/`ChainHandle`): host runtime
  paths in the daemon, desktop, and Android don't import engine internals
  (node-core/networking/consensus types). Composition roots use the `:myotis-engines`
  selector (`Engines.engine()`; `myotis.engine=java|rust|auto`, default auto —
  `-Pengine=…` on run tasks), which routes to the Java engine (node-core) or the
  Rust engine (rust/myotis-engine via UniFFI + JSON). The engine library's default
  port actuals (`io.myotis.engine.ports`, `:myotis-engine-ports` — `Myotis.defaultPorts`)
  are part of the library's public surface, not engine internals: a host may build its
  `EnginePorts` from them, as the Android app does. Documented exemptions: the
  single `Engines.engine()` line at each composition root; the TrueBlocks
  transaction-history scan in `:tx-history` (`TxHistoryService` wraps the raw
  `RLPxConnector`; UNVERIFIED, Java-engine + mainnet only), consumed by the daemon's
  `get-transactions` debug stream (`DebugCommands`), the desktop Query tab
  (`DesktopNodeController.transactionHistory`), and the Android Query tab
  (`NodeService.txHistoryService`) — all reach the connector via
  `SelectorEngine.javaDelegate().debugStack` at their composition roots;
  the Settings toggles for the BLS backend (`BlsBackends`), the
  engine (`Engines`), and Tor routing of account reads and of the wallet's
  own transaction broadcast (`Tor` —
  docs/how-it-works/privacy-and-tor.md; Rust-engine-only, gated behind the Rust-engine
  toggle, and behind the `-PtorEngine` build flag that links Arti into the host
  dylib and the Android jniLibs), the Rust log drain (`Engines.drainRustLogs` —
  hosts pump the engine's tracing ring into their log pipeline), and the Status
  screen's per-network engine badge (`Engines.engineKindFor`) — internal
  seams, deliberately not on the API; and `:app`'s
  `testing/MainnetPeerBootstrap` (an integration-test fixture).
  The iOS host (`:app-ios`) is the JVM-free analogue: it consumes the same
  engine contract over the Rust engine's plain C ABI (`RustEngine.kt` mirrors
  `RustEngineNative`; same JSON shapes, pinned by the same golden tests) and
  never touches engine internals either.
