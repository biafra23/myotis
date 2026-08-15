# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build all modules. NOTE: :android-app builds the Rust engine from source by
# default, so a full build needs the Android Rust toolchain (cargo + cargo-ndk +
# NDK r28+ + the aarch64/x86_64-linux-android rustup targets). Without it, add
# -PskipRustEngine to build the app on the Java engine (see the Rust section below).
./gradlew build                  # add -PskipRustEngine without the Android Rust toolchain

# Compile only (no tests)
./gradlew compileJava

# Run tests (all modules) — same toolchain note as `build`; :android-app's test
# tasks also go through its preBuild gate.
./gradlew test                   # add -PskipRustEngine without the Android Rust toolchain

# Run a single test class
./gradlew :networking:test --tests "com.jaeckel.ethp2p.networking.rlpx.HandshakeRoundTripTest"

# Start daemon (mainnet, blocks until stopped)
./gradlew :app:run

# Start daemon on another network
./gradlew :app:run -Pnetwork=gnosis     # Gnosis Chain (chainId 100, its own beacon chain)
./gradlew :app:run -Pnetwork=sepolia    # Ethereum testnet
# (holesky was retired — the EF shut it down in Oct 2025: no peers, no checkpoint servers)

# Run a second network alongside mainnet (separate daemon, separate port + socket)
./gradlew :app:run -Pnetwork=gnosis -Pport=30304

# Send IPC commands to running daemon
./gradlew :app:run -Pargs=status
./gradlew :app:run -Pargs=peers
./gradlew :app:run -Pargs="get-headers 21000000 3"
./gradlew :app:run -Pargs=stop
./gradlew :app:run -Pargs=purge-cache

# Rust workspace (rust/ — native BLS + the growing Rust engine). OPTIONAL for the
# JVM hosts (daemon/desktop): without cargo these self-skip with one note and the
# pure-Java build is unaffected. The ANDROID app is the exception — it requires the
# toolchain by default (see below), or -PskipRustEngine to opt out.
./gradlew cargoBuildHost   # cargo build --release (auto-runs before :app:run / :consensus:test)
./gradlew cargoTest        # cargo test --workspace (part of `check`)
./gradlew cargoNdkAndroid  # Android jniLibs, built from source (needs cargo-ndk + NDK + Android rustup targets)

# The Android app builds the Rust engine FROM SOURCE by default — cargo + cargo-ndk
# + NDK r28+ + `rustup target add aarch64-linux-android x86_64-linux-android` are
# REQUIRED to build :android-app. There is no committed .so (so nothing can drift);
# an Android build also regenerates the committed UniFFI bindings (:myotis-engines)
# from source — other workflows do NOT, so regenerate them explicitly with
# `./gradlew uniffiGenerateKotlin` after changing the Rust FFI. Opt out when you
# lack the toolchain — the build tells you about the switch — with:
./gradlew :android-app:assembleDebug -PskipRustEngine  # Java engine only (no Rust engine / native BLS)

# iOS (macOS only; needs Xcode 26+ and the rustup targets on the toolchain the
# workspace's rust-toolchain.toml selects — i.e.
# `rustup target add --toolchain stable aarch64-apple-ios aarch64-apple-ios-sim`).
# Cargo stays optional here too: without the toolchain (and with no previously
# built libmyotis_engine.a) :app-ios disables its framework tasks with a warning
# instead of failing the build — the full toolchain is required only to actually
# build the iOS app.
./gradlew cargoBuildIosSim                              # libmyotis_engine.a for the arm64 simulator
./gradlew cargoBuildIosDevice                           # libmyotis_engine.a for arm64 devices
./gradlew :app-ios:linkDebugFrameworkIosSimulatorArm64  # MyotisKit.framework (runs cargo first)
# The app itself builds from ios-app/ (Xcode project, regenerable with `xcodegen generate`):
#   cd ios-app && xcodebuild -project Myotis.xcodeproj -scheme Myotis \
#     -destination 'platform=iOS Simulator,name=<device>' build
```

## Architecture

Key Gradle modules:

- **myotis-engines** — the engine SELECTOR (`Engines`/`SelectorEngine`/`RustMyotisEngine`):
  hosts' composition roots call `Engines.engine()`; `myotis.engine=java|rust|auto` routes
  each network (re)start to the Java engine or the Rust one (`rust/myotis-engine`,
  UniFFI-generated Kotlin bindings over JNA — committed in this module, regenerated
  via `uniffiGenerateKotlin`; compound values as JSON pinned by golden tests both sides).
- **myotis-api** — THE ENGINE CONTRACT: zero-dependency Java-17 interfaces
  (`io.myotis.api` + `io.myotis.api.ports`) every host consumes exclusively.
  FFI-portable types only (byte[], String, long, double[], enums, flat records;
  blocking methods). Implemented by **node-core**'s `io.myotis.node.api` adapters
  (`JavaMyotisEngine`/`JavaChainHandle` over `ChainStack`/`NodeRegistry`). Designed so a Rust engine can replace the Java one behind the same
  surface — see docs/reimplementation/05-engine-api-bindings.md.
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
  with iOS seam actuals over the RUST engine's plain C ABI
  (`rust/include/myotis_engine.h`, cinterop; libmyotis_engine.a is absorbed into
  the framework). The JVM engine never runs on iOS. The Xcode shell lives in
  `ios-app/` (regenerate with `xcodegen generate`).

**Protocol flow**: `DiscV4Service` discovers peers → `Main` dials them via `RLPxConnector.connect()` → `RLPxHandler` performs ECIES handshake (state machine: HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED) → fires `RLPX_READY` event → `EthHandler` runs eth handshake (AWAITING_HELLO → AWAITING_STATUS → READY) → block header requests available.

**Daemon vs Client mode**: `Main` checks if the Unix socket (`/tmp/ethp2p.sock`) is already listening. No args = daemon mode (discovery + RLPx + IPC server). With args = client mode (send JSON command and exit).

## Key Dependencies

- **Tuweni 2.7.2** (upstream `io.consensys.tuweni`, Maven Central; original `org.apache.tuweni` packages) — RLP encoding, SECP256K1, byte utilities.
- **Netty 4.2.x** — NIO-only (no epoll/kqueue). 4-thread `NioEventLoopGroup` for RLPx.
- **BouncyCastle** — SECP256K1 crypto provider

## Conventions

- All protocol messages use Tuweni `RLP.encode()`/`RLP.decode()` for serialization
- State machines are explicit enums in handler classes (not generic FSM framework)
- Concurrent collections (`ConcurrentHashMap.newKeySet()`) for shared mutable state
- IPC uses JSON-Lines over Unix domain sockets with Java 21 virtual threads
- Network configs (genesis hash, fork ID, bootnodes) live in `NetworkConfig`
- **Hosts talk ONLY to `:myotis-api`** (`MyotisEngine`/`ChainHandle`): host runtime
  paths in the daemon, desktop, and Android don't import engine internals
  (node-core/networking/consensus types). Composition roots use the `:myotis-engines`
  selector (`Engines.engine()`; `myotis.engine=java|rust|auto`, default java —
  `-Pengine=…` on run tasks), which routes to the Java engine (node-core) or the
  Rust engine (rust/myotis-engine via UniFFI + JSON). Documented exemptions: the
  single `Engines.engine()` line at each composition root; the TrueBlocks
  transaction-history scan in `:tx-history` (`TxHistoryService` wraps the raw
  `RLPxConnector`; UNVERIFIED, Java-engine + mainnet only), consumed by the daemon's
  `get-transactions` debug stream (`DebugCommands`), the desktop Query tab
  (`DesktopNodeController.transactionHistory`), and the Android Query tab
  (`NodeService.txHistoryService`) — all reach the connector via
  `SelectorEngine.javaDelegate().debugStack` at their composition roots;
  the Settings toggles for the BLS backend (`BlsBackends`), the
  engine (`Engines`), and Tor verified-read routing (`Tor` —
  docs/privacy-and-tor.md; Rust-engine-only, gated behind the Rust-engine
  toggle, and behind the `-PtorEngine` build flag that links Arti into the host
  dylib), the Rust log drain (`Engines.drainRustLogs` —
  hosts pump the engine's tracing ring into their log pipeline), and the Status
  screen's per-network engine badge (`Engines.engineKindFor`) — internal
  seams, deliberately not on the API; and `:app`'s
  `testing/MainnetPeerBootstrap` (an integration-test fixture).
  The iOS host (`:app-ios`) is the JVM-free analogue: it consumes the same
  engine contract over the Rust engine's plain C ABI (`RustEngine.kt` mirrors
  `RustEngineNative`; same JSON shapes, pinned by the same golden tests) and
  never touches engine internals either.

## Pull requests and code review

These rules are for the **PR author** answering a review. The reviewer's own
instructions live in `.github/claude-review-prompt.md` and
`.github/workflows/claude-review.yml`; a reviewer agent reads this file too
(its prompt opens "Read CLAUDE.md first"), so note that the mechanism below is
not addressed to it — and it could not follow it anyway, since `gh api` is not
on its allowlist.

**External / fork PRs are reviewed MANUALLY, never by the CI reviewer (owner's
decision, 2026-08-15).** The `claude-review` workflow deliberately skips forks
(`head.repo.full_name == github.repository` in its `if:`) because a `pull_request`
run from a fork gets no secrets — but the deeper reason is trust: a fork PR's
tree is attacker-controlled, and an automated reviewer that reads it can be
prompt-injected. Two inputs make that acute here — the reviewer reads
`CLAUDE.md` and `.github/claude-review-prompt.md` from the checkout, so a fork
could *rewrite the reviewer's own rules and prompt* in the same PR (the
"workflow must match the default branch" guard protects only the workflow YAML,
not these files). So do NOT wire fork PRs into the automated reviewer. Instead:
the owner reads the diff first — watching for injection in `CLAUDE.md` /
`.github/**` / build scripts / postinstall hooks / comments / encoded blobs —
then, if wanted, a review is run manually from a trusted session. Nothing
auto-merges, so an injected reviewer could at worst post a comment a human still
acts on. If automating fork review is ever reconsidered, pin the prompt and
CLAUDE.md to the base ref, never execute fork code, keep reviews `COMMENT`-only,
and lock down runner egress — see the discussion that produced this note.

- **ALWAYS respond to every review comment, individually, on its own thread.**
  One comment, one reply. A single bulk PR-level summary is not a substitute —
  it may be posted *in addition*, but a reviewer must be able to see the
  disposition of each point where they raised it. Silently fixing a comment in
  a follow-up commit does not count as responding, and neither does silently
  ignoring one.
- **Only *inline* review comments have a thread.** A submitted review's summary
  body and a top-level PR comment have no reply endpoint at all. Answer those
  in a single top-level reply that quotes each point it addresses — that is the
  one legitimate use of `gh pr comment`.
- **Verify every claim against the source before replying.** Reviewers —
  human, Copilot, or `claude[bot]` — are frequently right and occasionally
  wrong. Treat a review comment as information to check, not an instruction to
  obey. Quote the file and symbol you checked.
- **State a plain verdict** in each reply, one of:
  - *Accepted* — say what changed and name the commit.
  - *Disputed* — say why, with the evidence that settles it. Disagreeing is
    correct when the code supports it; do not change working code to satisfy a
    review that is mistaken.
  - *Deferred* — say who decides and what the options are. Use this for
    anything that amends a project rule (this file included) or changes
    architecture; those are the owner's call, not the PR author's.
- **Do not mark a thread resolved on the author's own say-so.** Leave that to
  the reviewer or the owner.
- Reply with
  `gh api repos/<owner>/<repo>/pulls/<n>/comments/<comment_id>/replies -f body='…'`
  so the response threads under the original comment, rather than
  `gh pr comment`, which starts a detached top-level discussion. **The `-f body`
  is not optional**: `body` is required by the endpoint, and `gh api` switches
  from `GET` to `POST` only when a parameter is present — without it the call is
  a `GET` against a `POST`-only path. List the ids with
  `gh api repos/<owner>/<repo>/pulls/<n>/comments --jq '.[].id'`. For bodies
  containing backticks or quotes, prefer `--raw-field body="$(cat <<'EOF' … EOF)"`
  over `-f`.
- **Drive CI to green.** Do not leave a PR on a red or pending check without
  either pushing a fix or stating the blocker explicitly.

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
- **A parameter that can change the answer must be APPLIED or REFUSED — never
  accepted and silently ignored.** A well-formed result computed against
  something other than what the caller asked for is indistinguishable from a
  correct one, so the caller cannot detect it, retry it, or work around it. This
  is the same rule the log index applies to an out-of-coverage range (an error,
  never a misleading `[]`). It was learned the hard way: `eth_call` accepted the
  state-override parameter and dropped it, which silently broke a wallet's
  account-state reads and cost hours to trace back (#314). When refusing, use a
  PERMANENT error code (`-32602`) — `-32000` is documented as retryable and a
  client will spin on it.

## Data sources
- the only sources for data are devp2p and libp2p calling a local client via http may only be used for debugging purposes it is not an option for production
- **Carve-out for myotis-operated serving infrastructure (owner's decision,
  2026-08-08).** The rule above governs the **wallet**. `roost`, the dedicated
  light-client server (`rust/roost`, docs/lc-server-design.md), MAY source
  *self-verifying* consensus objects — LC bootstrap, updates, finality and
  optimistic updates — from a local beacon node over loopback REST, and does
  NOT verify them itself. The verification happens in myotis: a bootstrap is
  anchored to the checkpoint root the wallet already pins, and every update is
  checked against sync-committee BLS signatures by the wallet receiving it. A
  relay can withhold, but it cannot forge.
  Two boundaries this carve-out does **not** cross:
  - **"Self-verifying" is load-bearing.** It does not widen into "roost may
    serve anything it read over REST". Any path relaying something a wallet
    cannot check against sync-committee signatures — proxying
    `beacon_blocks_by_range` is the live example — needs its own decision.
  - **Withholding is a liveness attack and this concentrates it.** It is
    *detected*, not silently wrong: `BeaconSyncState` regresses out of SYNCED
    and queries fail with `beaconNotSynced`, so a stalled relay surfaces as
    "not ready" rather than as a confidently wrong balance.
- **TrueBlocks Unchained Index mainnet publishing appears stalled.** The designated
  publisher (`publisher.unchainedindex.eth`) last published a mainnet manifest indexed
  to ~block 23.0M (mid-2025); as of mid-2026 that is ~a year behind the head, and the
  only newer on-chain entry is from an undesignated wallet whose content is not
  retrievable from IPFS. The `:tx-history` scan (debug-only) therefore misses all
  recent history — both its surfaces warn loudly about the gap. PLAN: the user intends
  to run their own index (TrueBlocks scraper) and add its IPFS peer address to Myotis;
  if you find evidence upstream publishing has resumed (a fresh manifest under the
  ENS-designated publisher), flag it to the user.
- **Portal Network is effectively dead.** Its reference clients are abandoned:
  the EF's own Trin client README states "THIS PROJECT IS NO LONGER ACTIVELY
  MAINTAINED" (https://github.com/ethereum/trin), and no one is actively
  continuing the network. (Note: ethereum.org docs may still list Trin/Fluffy as
  active — that is stale and not reliable.) Do NOT treat Portal as available
  infrastructure — anything Portal would have solved (deep historical
  state/blocks, a distributed state network as a SNAP fallback, etc.) must be
  solved another way. If you ever come across credible evidence that Portal has
  been revived or that someone is actively continuing it, FLAG IT TO THE USER
  IMMEDIATELY and prominently — the user wants to know right away because it would
  cover a lot of wallet needs.

## Integration-Test
- When './gradlew :app:run -Pargs=beacon-status' returns "state":"SYNCED" then './gradlew :app:run -Pargs="get-storage 0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4 1 0x308686553a1EAC2fE721Ac8B814De638975a276e"'  and './gradlew  :app:run -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"' should return "verifyMethod":"headerChain"
- Gnosis variant: with a gnosis daemon running (`./gradlew :app:run -Pnetwork=gnosis`), once `-Pnetwork=gnosis -Pargs=beacon-status` returns "state":"SYNCED", `-Pnetwork=gnosis -Pargs="get-account <addr>"` should return "verifyMethod":"headerChain". Refresh the trust anchor first with `./gradlew refreshCheckpoint -Pnetwork=gnosis` (one task for every network, writing both engines from one fetch; it refuses to write a root fewer than two operators agree on — see README §Trust model).
