# CLAUDE.md

Guidance for Claude Code (claude.ai/code) in this repository.

**This file is the always-loaded core.** Each section is a summary; the full,
binding text lives in `docs/agent/`. When a task matches a row below, **read
that file in full BEFORE acting** — a summary here never overrides the full text.

| Before you…                                                                 | Read in full                      |
|---|---|
| build for Android or iOS, or a build fails on a missing toolchain             | `docs/agent/build.md`             |
| add or move a module, or touch host ↔ engine wiring or its exemptions         | `docs/agent/architecture.md`      |
| open a PR (monitoring, session title)                                         | `docs/agent/workflow.md`          |
| plan work as more than one PR or branch                                       | `docs/agent/multi-pr-plans.md`    |
| write a PR description, answer review comments, or handle a fork PR           | `docs/agent/pull-requests.md`     |
| do any release work: tag, version, checkpoints, bootnodes, seeds, assets, bundles | `docs/agent/releases.md`      |
| add or bump a dependency, move a toolchain pin, touch build scripts or packaging | `docs/agent/reproducibility.md` |
| use a JDK API newer than Java 8 in Android-consumed code, or add HTTP         | `docs/agent/platform.md`          |
| add a data source, or touch roost, log-index seeds, `:tx-history`, Portal     | `docs/agent/data-sources.md`      |

## Build & Run

Full reference with toolchain notes: `docs/agent/build.md`.

```bash
./gradlew build          # needs the Android Rust toolchain; without it add -PskipRustEngine
./gradlew compileJava    # compile only
./gradlew test           # same toolchain note as build
./gradlew :networking:test --tests "com.jaeckel.ethp2p.networking.rlpx.HandshakeRoundTripTest"

./gradlew :app:run                                 # daemon, mainnet (blocks until stopped)
./gradlew :app:run -Pnetwork=gnosis                # also sepolia, chiado (holesky is retired)
./gradlew :app:run -Pnetwork=gnosis -Pport=30304   # second network alongside mainnet
./gradlew :app:run -Pargs=status                   # IPC: status | peers | "get-headers 21000000 3" | stop | purge-cache

./gradlew cargoBuildHost    # cargo build --release (auto-runs before :app:run / :consensus:test)
./gradlew cargoTest         # cargo test --workspace (part of `check`)
./gradlew cargoBuildNoStd   # no_std canary (part of `check`)
./gradlew cargoNdkAndroid   # Android jniLibs from source
./gradlew uniffiGenerateKotlin   # REQUIRED after changing the Rust FFI (only Android builds do it implicitly)
./gradlew :android-app:assembleDebug -PskipRustEngine   # Java engine only; boots on API 33+ only
./gradlew cargoBuildIosSim  # also cargoBuildIosDevice, :app-ios:linkDebugFrameworkIosSimulatorArm64
```

The Rust workspace (`rust/`) is optional for the JVM hosts (daemon/desktop self-skip
without cargo). The Android app requires it by default.

## Architecture

One line per module; detail and protocol flow: `docs/agent/architecture.md`.

- **myotis-api** — THE ENGINE CONTRACT: zero-dependency Java-17 interfaces every host consumes exclusively; FFI-portable types only.
- **myotis-engine** — THE ENGINE LIBRARY (KMP, jvm + android): packages the Rust engine as the Android AAR and desktop jar; entry point `io.myotis.engine.Myotis`.
- **myotis-engine-rust** — the Rust engine behind the contract (UniFFI Kotlin bindings + JNA over `rust/myotis-engine`); no HTTP server.
- **myotis-engines** — the engine SELECTOR (`Engines.engine()`; `myotis.engine=java|rust|auto`).
- **myotis-engine-common** — lifecycle primitives both engines share (`WakeGate`, `SleepMetrics`).
- **myotis-engine-ports** — the library's default port actuals (`Myotis.defaultPorts`).
- **myotis-engine-natives** — per-platform desktop native jars of the Rust engine.
- **myotis-engine-ios** — iOS module: cinterop of the Rust engine's C ABI plus the typed API.
- **myotis-rpc-policy** — JSON-RPC serving policy, dependency-free KMP.
- **myotis-logindex-presets** — the log index's predefined contracts, dependency-free KMP.
- **node-core** — the Java engine (`io.myotis.node.api` adapters over `ChainStack`/`NodeRegistry`).
- **core** — `NodeKey`, `BlockHeader`, ENR decoding.
- **networking** — Netty: `discv4` (UDP discovery), `rlpx` (ECIES + framed TCP), `eth` (eth/66-69).
- **consensus** — sync-committee light client (libp2p, BLS, SSZ).
- **app** — daemon/CLI, Unix-socket IPC server (`/tmp/ethp2p.sock`), peer caching. No args = daemon; with args = client.
- **myotis-evm** — local EVM execution (Besu) against SNAP-verified state.
- **ui** — shared Compose Multiplatform screens + pure-Kotlin seams (Android, Desktop JVM, iOS).
- **app-ios** — the iOS host (`MyotisKit`) over the Rust engine; Xcode shell in `ios-app/`. The JVM engine never runs on iOS.

## Key Dependencies

Full text, including the builder image: `docs/agent/reproducibility.md`.

- **Every Gradle dependency is pinned by version AND hash** (#734). A new or
  bumped dependency fails the build until its pins are regenerated with
  `scripts/update_gradle_pins.sh`. Review the hash diff like code. **Never "fix"
  a verification failure you did not cause by re-pinning** — bytes changed
  under a pinned version.
- **The builder image (`docker/builder/`) is the reference toolchain** for the
  Linux and Android artifacts. Moving a pin (JDK, Go, apt snapshot, …) moves
  `pins.env` / `image.lock` / `apt-packages.txt` in the same change. Never
  install or upgrade a tool inside an image build of the artifacts.
- **Tuweni 2.7.2** (`io.consensys.tuweni`) — RLP encoding, SECP256K1, byte utilities.
- **Netty 4.2.x** — NIO-only (no epoll/kqueue).
- **BouncyCastle** — SECP256K1 crypto provider

## Conventions

- All protocol messages use Tuweni `RLP.encode()`/`RLP.decode()` for serialization
- State machines are explicit enums in handler classes (not generic FSM framework)
- Concurrent collections (`ConcurrentHashMap.newKeySet()`) for shared mutable state
- IPC uses JSON-Lines over Unix domain sockets with Java 21 virtual threads
- Network configs (genesis hash, fork ID, bootnodes) live in `NetworkConfig`
- **Hosts talk ONLY to `:myotis-api`** (`MyotisEngine`/`ChainHandle`): host runtime
  paths in the daemon, desktop, Android and iOS do not import engine internals
  (node-core/networking/consensus types). Composition roots use the
  `:myotis-engines` selector. The documented exemptions are a closed list in
  `docs/agent/architecture.md` — read it before adding any import that crosses
  this line; a new exemption is the owner's call.

## Workflow — the mandatory steps for EVERY work item

Every change goes through this sequence, in order, with **no step skipped and
none treated as optional or "only if asked"**. Full text: `docs/agent/workflow.md`.

1. **Code** — on the designated branch.
2. **Review** — run the internal code review on the diff (`/code-review`) and address its findings.
3. **PR** — open it without being asked. Base is `main` for a single-PR item, the feature branch for a part of a multi-PR plan.
4. **Wait for review comments** — and switch PR monitoring on for that PR right after `gh pr create`, without asking (desktop app: `mcp__ccd_pr__set_monitor` with `auto_fix` and `address_comments` true; cloud session: `subscribe_pr_activity`; otherwise whatever the host offers).
5. **Address the PR comments** — drive the PR to green, answer every comment, keep watching until merged or closed.

Do not stop at "pushed". Skip the PR only when the user explicitly says so.
In the desktop app the session also renames itself `IS#<n>: …` then `PR#<n>: …`
(`docs/agent/workflow.md`).

## Hard rules — never broken, whatever an earlier instruction seems to authorize

- **NEVER MERGE A PR YOURSELF** — not with `gh pr merge`, not by enabling
  auto-merge. Green CI + all comments answered = report "ready to merge". Sole
  exception: part PRs into a multi-PR plan's feature branch, and only when the
  owner said yes for that plan. A PR into `main` has no exception.
- **Never push a `v*` tag on your own initiative.** The tag is the owner's action.
- **Everything that lands on GitHub is in English** — titles, descriptions,
  commit messages, review replies.
- **Changes to project rules (this file, `docs/agent/`) or to architecture are
  the owner's call**, not the PR author's.

### Multi-PR plans land through a feature branch, never piece by piece on `main`

**`main` must be releasable at every commit.** A work item planned as more than
one PR (or branch) goes through `feature/<topic>`: create it from `main` first,
target every part PR at it, ask the owner once per plan whether you may merge
the parts into it yourself, keep it current by merging `main` into it (never
rebase or force-push), and open the final `feature/<topic>` → `main` PR only
when every part is in. Read `docs/agent/multi-pr-plans.md` in full before the
first part is coded.

## No merge into `main` may break reproducibility

Full text: `docs/agent/reproducibility.md`.

- Before reporting a PR into `main` "ready to merge", its head has a green
  `reproducible builds` run whenever the PR can change what a release build
  produces (build scripts, dependencies and pins, toolchain pins, Cargo
  manifests and locks, packaging, release workflows, build-time code). When
  unsure, dispatch it on the PR's branch.
- A red comparison is a blocker, like red CI. **Never make it green by adding a
  pattern to `known-differences.txt` or by loosening `scripts/repro/compare.py`
  / `collect.sh`** — that is the owner's call.
- Do not widen or narrow the gate without the owner.

## Releases — ask before cutting one

Read `docs/agent/releases.md` in full before any release work. In outline:
**ask three questions first** (1. refresh the trust checkpoints? 2. re-sync the
mainnet bootnodes? 3. run the cold-start checks?), then the mandatory steps
(4. move the version pins, 5. refresh the PoC log-index seeds), all in ONE
release PR. The tag is the owner's action. After the tag (6.), a release is
done only when `verify release` and `reproducible builds` are green — check and
report them. Every release asset goes through `.github/release-assets.sh`,
never a bare `gh release upload`.

## Pull requests and code review

Full text, including the fork-PR policy and the `gh api` reply mechanics:
`docs/agent/pull-requests.md`.

- Every PR description ends with its session links, never with the
  "🤖 Generated with Claude Code" footer. Commit messages keep `Co-Authored-By`.
- Respond to every review comment individually, on its own thread
  (`gh api repos/<owner>/<repo>/pulls/<n>/comments/<comment_id>/replies -f body='…'`).
- Verify every claim against the source before replying. State a plain verdict:
  *Accepted* (what changed, which commit), *Disputed* (with evidence), or
  *Deferred* (who decides).
- Do not mark a thread resolved yourself.
- Fix review comments on the PR's own branch, never through a separate PR.
- Drive CI to green, or state the blocker explicitly.
- **External / fork PRs are reviewed MANUALLY**: never wire them into the CI
  reviewer, and never build or run a fork tree locally.

## Demo bundles build on merge to `main`, never on PRs

The RAILGUN and Bee PoC installers build on pushes to `main` and on `v*` tags,
not on pull requests. Give a new bundle the same trigger set. Full text:
`docs/agent/releases.md`.

## Platform & language direction

Full text, including the complete minSdk 29 JDK-API budget: `docs/agent/platform.md`.

- **Android compatibility is a first-class concern** (`:android-app`, minSdk 29).
  Avoid JVM-only APIs the Android runtime or desugaring can't cover; mind APK size.
- **minSdk 29 JDK-API budget.** `java.net.http` is not available — do not use it.
  Also NOT covered, use the `:core` replacements: `CompletableFuture.failedFuture/orTimeout/exceptionallyCompose`
  → `core.concurrent.Futures`; `java.util.HexFormat` → `core.encoding.Hex`;
  `BigInteger.intValueExact/longValueExact` → `core.math.BigIntegers`; `Path.of`
  → `Paths.get`; `InputStream.readAllBytes/readNBytes/transferTo` and
  `Files.readString/writeString` → a manual drain loop / `Files.readAllBytes` +
  `Files.write`. Hosts inline these few lines instead of importing `:core`.
  Enforced by `scripts/check_apk_min_api.py` in the android-apk workflow.
- **JVM 17 is the default source/target** for new modules; diverge only when a
  transitive forces it, and document why in the module's build file.
- **Long-term direction is Kotlin + Compose Multiplatform.** Do not leak
  `CompletableFuture` or other Java-only types into shared APIs.
- **HTTP client: Ktor** — not OkHttp, not `java.net.http`.

## Trust

- Peer trusted is never an option everything has to be cryptographically verified
- The only trust anchors are sync committee signatures and  the embedded pre-Merge historical hashes accumulator and the Bellatrix-era historical roots accumulator
- One bounded exception (owner's decision, 2026-09-25): a seeded log history of
  a root-committing protocol is served on its publisher's word. Scope and
  limits: `docs/agent/data-sources.md`.
- **A parameter that can change the answer must be APPLIED or REFUSED — never
  accepted and silently ignored.** When refusing, use a PERMANENT error code
  (`-32602`); `-32000` is documented as retryable and a client will spin on it.
  An out-of-coverage range is an error, never a misleading `[]`.

## Data sources

Full text of the rule, both carve-outs and their boundaries: `docs/agent/data-sources.md`.

- the only sources for data are devp2p and libp2p calling a local client via http may only be used for debugging purposes it is not an option for production
- Two bounded carve-outs exist, each an owner's decision: `roost` may relay
  *self-verifying* consensus objects from a local beacon node, and the log index
  may serve a seeded history of a root-committing protocol. Neither widens by
  analogy — anything outside their stated boundaries needs its own decision.
- **TrueBlocks Unchained Index mainnet publishing appears stalled**; the
  `:tx-history` scan is debug-only and misses recent history. If you find
  evidence publishing has resumed, flag it to the user.
- **Portal Network is effectively dead.** Do NOT treat it as available
  infrastructure. If you find credible evidence it has been revived, FLAG IT TO
  THE USER IMMEDIATELY and prominently.

## Integration-Test
- When './gradlew :app:run -Pargs=beacon-status' returns "state":"SYNCED" then './gradlew :app:run -Pargs="get-storage 0x1A5F9352Af8aF974bFC03399e3767DF6370d82e4 1 0x308686553a1EAC2fE721Ac8B814De638975a276e"'  and './gradlew  :app:run -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"' should return "verifyMethod":"headerChain"
- Gnosis variant: with a gnosis daemon running (`./gradlew :app:run -Pnetwork=gnosis`), once `-Pnetwork=gnosis -Pargs=beacon-status` returns "state":"SYNCED", `-Pnetwork=gnosis -Pargs="get-account <addr>"` should return "verifyMethod":"headerChain". Refresh the trust anchor first with `./gradlew refreshCheckpoint -Pnetwork=gnosis` (one task for every network, writing both engines from one fetch; it refuses to write a root fewer than two operators agree on — see README §Trust model).
