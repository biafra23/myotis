# 05 — The Engine API: Binding Strategy for a Rust (or Go) Engine

> Companion to the [re-implementation spec](README.md). The engine contract is the
> **`:myotis-api`** module (`io.myotis.api` + `io.myotis.api.ports`) — this document maps
> every interface in it to a concrete Rust/UniFFI (or JNI) binding strategy, so a Rust
> engine can slot in behind the exact surface the JVM hosts already consume.

## 1. Why the API is shaped the way it is

`:myotis-api` was designed binding-first (see the module's `package-info`):

- **Blocking methods everywhere.** UniFFI translates a blocking Rust fn to a blocking
  Kotlin/Swift call 1:1, or lifts it to `async` in the generated bindings. The hosts
  already call the API from worker threads (`Dispatchers.IO`, a query pool, virtual
  threads), so nothing about the JVM side changes when the implementation becomes Rust.
  Callbacks exist only in the ports (engine → host), which UniFFI models as *foreign
  traits* / callback interfaces.
- **Only FFI-trivial types cross**: `byte[]` ⇄ `Vec<u8>`, `String` ⇄ `String`,
  `long` ⇄ `i64`/`u64`, enums ⇄ enums, flat records ⇄ UniFFI *dictionaries* (Rust
  structs), `List<record>` ⇄ `Vec<struct>`. No `BigInteger` (wei = decimal strings),
  no `CompletableFuture`, no `InetSocketAddress`/`Path` (host:port pairs / path strings).
- **Three-tier error model** that needs no exception marshalling:
  1. `VerifiedReads` returns `null` (`Option::None`) = "cannot answer verified";
  2. verification queries return flat records with `failReason`/`error` strings;
  3. only programmer/state errors throw — one type, `EngineException`, which UniFFI
     models as a single flat `Error` enum.

## 2. Interface → binding map

| `io.myotis.api` | UniFFI construct | Rust shape |
|---|---|---|
| `MyotisEngine` | `interface` (object) | `struct RustEngine` behind `Arc`, constructor exported as the factory the host names once |
| `ChainHandle` | `interface` (object) | per-network handle owning the tokio runtime pieces |
| `EngineConfig`, `NetworkInfo`, `StatusSnapshot`, `BeaconStatus`, `PeerInfo`, `ConnectedPeer`, `DiscoveredPeer`, `ClPeerInfo`, `AccountProofResult`, `StorageProofResult`, `HeaderInfo`, `HeadersResult`, `BlockResult`, `DialResult`, `EnsResolutionResult` + the `Ens*Result` family, `ports.CachedPeerInfo`, `ports.ServedRange`, `ports.BootstrapPeer` | `dictionary` | plain `struct`s (all fields by value) |
| `SyncState`, `BeaconState`, `EnsRoot`, `ports.SnapQuality`, `ports.HttpGateway.Method` | `enum` | fieldless enums |
| `VerifiedReads`, `EnsApi` | `interface` (object returned by the handle) | sub-objects borrowing the handle's internals |
| `ports.NodeKeyStore`, `ports.EnginePeerCache`, `ports.EngineClPeerCache`, `ports.DnsServers`, `ports.HttpGateway`, `ports.EngineLogger`, `ports.EngineClock` | **callback interface** (foreign trait) | `Box<dyn Trait + Send + Sync>` handed into the engine at `create()` |
| `EngineException` | `[Error]` enum (single `Message(String)` variant) | `thiserror` enum |
| `EnginePorts` (the bundle record) | `dictionary` of callback-interface handles | struct of trait objects |

Threading contract carried over: the engine invokes port callbacks from its own worker
threads (tokio blocking pool for `HttpGateway`, never an I/O driver thread); port
implementations must be thread-safe. `HttpGateway` stays deliberately blocking — the
Rust side wraps it in `spawn_blocking`, exactly mirroring today's
`PortBridges.toCcipGateway` bridge.

## 3. Packaging (proven pattern)

`rust/myotis-bls` already proves the one-crate → desktop `.so` + Android ABIs pipeline
(cargo-ndk, `rust/build-android.sh`, loaded through the `BlsBackend` JNI seam — see
[bls-rust-acceleration.md](../bls-rust-acceleration.md)). A full engine generalizes it:

- **Android**: cdylib (`arm64-v8a`, `armeabi-v7a`, `x86_64`) + UniFFI-generated Kotlin
  in an `.aar`. The Kotlin bindings implement... nothing: they ARE the engine; a thin
  adapter maps them onto `io.myotis.api` so `NodeService` keeps compiling unchanged —
  or, once the JVM engine retires, hosts consume the UniFFI Kotlin types directly.
- **iOS**: staticlib + UniFFI Swift bindings as an `.xcframework`. The shared Compose
  UI (`:ui` commonMain — already pure Kotlin, no JVM types) gains `iosArm64`/
  `iosSimulatorArm64` targets; an iOS actual of the `NodeController`/`Settings`/
  `LogSource`/`QueryHistory` seams, mapping UniFFI types → the ui models (template:
  `AndroidNodeBridge.kt`, ~200 lines). iOS-native ports: `NodeKeyStore` → Keychain,
  `HttpGateway` → URLSession/Ktor-Darwin, `DnsServers` → resolver config.
- **Desktop**: use the crate directly from the JVM via JNI/UniFFI-Kotlin, or ship the
  Rust daemon binary with the same UDS JSON-lines IPC.

**No Java→Kotlin conversion debt exists**: everything currently Java is either the
engine (replaced by Rust), a platform-specific host shell (stays on its platform), or a
port implementation (rewritten natively per platform by design).

## 4. Recommended API simplification for the Rust port

The two peer-cache ports (`EnginePeerCache`, `EngineClPeerCache`) exist because the JVM
hosts historically owned the cache **files**. They are pure persistence with no
platform semantics beyond a directory. A Rust engine should **own peer-cache
persistence internally** (sled/flat files under a data dir) and replace both ports with
a single `dataDir` string in `EngineConfig`:

- Hosts shrink to three small native ports: `NodeKeyStore`, `HttpGateway`, `DnsServers`
  (+ optional logger/clock).
- The "Clear caches" host feature becomes an engine method (e.g.
  `ChainHandle.clearPeerCaches()`), removing today's host-side live-instance juggling.
- Keep the on-disk formats readable (documented in [README §9](README.md#9-persistence--storage))
  or migrate once at first run — they are reconstructible caches, not trust anchors.

`NodeKeyStore` should stay a port (key custody is a genuine platform concern —
Keychain/keystore vs files), as should `HttpGateway` (TLS stacks are platform-owned)
and `DnsServers` (mobile resolver quirk).

## 5. Conformance checklist for a replacement engine

1. Implement every `io.myotis.api` signature with the exact null/`failReason`
   semantics (the JVM hosts' behavior is pinned by: the daemon's golden JSON tests over
   the operator queries, `RpcRouterTest` over `VerifiedReads` wire shapes, and the
   `verify()`-ladder unit tests over `failReason` tokens).
2. Honor the threading contract: blocking API, thread-safe reentrant handles, port
   callbacks off I/O threads.
3. Preserve the security invariants of [README §11](README.md#11-security-critical-invariants-consolidated-checklist)
   — the API cannot express an unverified answer, and a port must not be able to inject
   one (ports carry availability data only: peers, DNS, HTTP bytes that are re-verified
   on-chain).
4. Match the stable `failReason`/`verifyMethod` tokens (`stateRootMatch`,
   `headerChain`, `beaconNotSynced`, `headerChainGapTooLarge`, `preMergeBlock`, …) —
   operator tooling and the integration tests grep them.
5. Wire the integration gate: with a SYNCED node, `ChainHandle.requestAccount` must
   yield `beaconChainVerified=true` with `verifyMethod` `stateRootMatch` or
   `headerChain`, and the CLAUDE.md `get-storage` contract must hold end-to-end.
