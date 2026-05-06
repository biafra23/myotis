# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build all modules
./gradlew build

# Compile only (no tests)
./gradlew compileJava

# Run tests (all modules)
./gradlew test

# Run a single test class
./gradlew :networking:test --tests "com.jaeckel.ethp2p.networking.rlpx.HandshakeRoundTripTest"

# Start daemon (mainnet, blocks until stopped)
./gradlew :app:run

# Start daemon on a testnet
./gradlew :app:run -Pnetwork=sepolia
./gradlew :app:run -Pnetwork=holesky

# Send IPC commands to running daemon
./gradlew :app:run -Pargs=status
./gradlew :app:run -Pargs=peers
./gradlew :app:run -Pargs="get-headers 21000000 3"
./gradlew :app:run -Pargs=stop
./gradlew :app:run -Pargs=purge-cache
```

## Architecture

Five Gradle modules:

- **core** — Cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** — Three protocol layers, all Netty-based:
  - `discv4` — UDP peer discovery using Kademlia DHT (ping/pong/findnode/neighbors)
  - `rlpx` — TCP transport: EIP-8 ECIES handshake → AES-256-CTR framed channel
  - `eth` — eth/67-68 sub-protocol on top of RLPx (hello → status → ready)
- **consensus** — Sync-committee light client (libp2p, BLS, SSZ)
- **app** — Daemon/CLI entry point, Unix domain socket IPC server, peer caching
- **myotis-evm** — Local EVM execution (Besu) against SNAP-verified state for view calls and gas estimation

**Protocol flow**: `DiscV4Service` discovers peers → `Main` dials them via `RLPxConnector.connect()` → `RLPxHandler` performs ECIES handshake (state machine: HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED) → fires `RLPX_READY` event → `EthHandler` runs eth handshake (AWAITING_HELLO → AWAITING_STATUS → READY) → block header requests available.

**Daemon vs Client mode**: `Main` checks if the Unix socket (`/tmp/ethp2p.sock`) is already listening. No args = daemon mode (discovery + RLPx + IPC server). With args = client mode (send JSON command and exit).

## Key Dependencies

- **Tuweni 2.7.2** (ConsenSys) — RLP encoding, SECP256K1, byte utilities. Fetched from ConsenSys Maven repo.
- **Netty 4.2.x** — NIO-only (no epoll/kqueue). 4-thread `NioEventLoopGroup` for RLPx.
- **BouncyCastle** — SECP256K1 crypto provider

## Conventions

- All protocol messages use Tuweni `RLP.encode()`/`RLP.decode()` for serialization
- State machines are explicit enums in handler classes (not generic FSM framework)
- Concurrent collections (`ConcurrentHashMap.newKeySet()`) for shared mutable state
- IPC uses JSON-Lines over Unix domain sockets with Java 21 virtual threads
- Network configs (genesis hash, fork ID, bootnodes) live in `NetworkConfig`

## Platform & language direction

- **Android compatibility is a first-class concern.** This is ultimately a wallet
  library that has to run inside an Android app (`:android-app`, minSdk 29).
  Every change needs to keep the consumer working: avoid JVM-only APIs that
  the Android runtime / `coreLibraryDesugaring` can't cover, mind APK / DEX
  size, and prefer libraries with known Android support. `java.net.http` is
  not desugared and is not available below API 33 — do not use it.
- **JVM 17 is the default source/target.** New modules should compile to
  Java 17 class files (`sourceCompatibility = JavaVersion.VERSION_17`,
  `targetCompatibility = JavaVersion.VERSION_17`) so they're consumable from
  the Android module. The toolchain may run on Java 21, and existing modules
  ship 21 class files only for transitive reasons (`:networking` because of
  ConsenSys discv5 26.4.0; `:myotis-evm` because of Besu's `evm` module both
  publishing Gradle module metadata declaring a JVM-21 floor). Only diverge
  when a transitive forces it, and document the reason in the module's
  build file.
- **Long-term direction is Kotlin + Compose Multiplatform.** New code can
  still land in Java where it lowers risk, but expect a migration to Kotlin
  to enable Compose Multiplatform consumers (Android + desktop + iOS). Public
  APIs should not depend on Java-only types that block Kotlin/Native or JS
  targets later. Avoid leaking `CompletableFuture` into shared APIs designed
  for multiplatform; expose suspending or library-neutral shapes instead.
- **HTTP client: Ktor.** When a feature needs HTTP (e.g. CCIP-Read gateways
  in `myotis-evm`), use Ktor — not OkHttp, not `java.net.http`. Ktor has
  Multiplatform-ready engines and runs on Android.

## Trust

- Peer trusted is never an option everything has to be cryptographically verified
- The only trust anchors are sync committee signatures and  the embedded pre-Merge historical hashes accumulator and the Bellatrix-era historical roots accumulator

## Data sources
- the only sources for data are devp2p and libp2p calling a local client via http may only be used for debugging purposes it is not an option for production

## Integration-Test
- When './gradlew :app:run -Pargs=beacon-status' returns "state":"SYNCED" then './gradlew :app:run -Pargs="get-storage 0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4 1 0x308686553a1EAC2fE721Ac8B814De638975a276e"'  and './gradlew  :app:run -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"' should return "verifyMethod":"headerChain"
