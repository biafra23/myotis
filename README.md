<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/myotis_logo_dark.svg">
    <img src="assets/myotis_logo.svg" alt="Myotis logo" width="200">
  </picture>
</p>

# myotis

Myotis is a **trustless Ethereum wallet engine** — a full participant in Ethereum's peer-to-peer networks that answers a wallet's requests with cryptographically verified data, with **no trusted RPC provider in the loop**. It speaks devp2p on the execution layer (discv4 discovery, RLPx encrypted transport, eth/66-69, and snap/1 or snap/2 state proofs) and libp2p on the consensus layer (a beacon-chain light client), and verifies every byte against sync-committee BLS signatures back to beacon-chain finality.

Myotis runs **on mobile, on desktop, and as a library embedded in other apps**. The apps: an **Android app** (minSdk 29), an **iOS app**, a **desktop GUI app**, and a **desktop daemon/CLI** for development. The embeddings: a **Node.js native addon** that Electron and Node hosts load to run the node invisibly in-process, the way they run other embedded nodes — the [Freedom browser](https://github.com/solardev-xyz/freedom-browser) is integrating Myotis this way as an experimental tier for fully-P2P verified `.eth` resolution ([PR #181](https://github.com/solardev-xyz/freedom-browser/pull/181)) — and, on iOS, the **`MyotisKit` framework** over the engine's C ABI: iOS suspends backgrounded apps, so an iOS wallet embeds Myotis as a library and runs the node in its own process rather than talking to a separate node app. Prebuilt addon binaries for macOS/Linux/Windows ship with every [release](https://github.com/biafra23/myotis/releases) since v0.1.3; see [Embedding: Node.js / Electron](#embedding-nodejs--electron).

A built-in **JSON-RPC server** exposes a verified subset of the Ethereum API over HTTP, so an **unmodified MetaMask** — pointed at the phone — can read balances, simulate calls, estimate gas, suggest fees, and **broadcast a real transaction**, all served from locally verified state. Nothing is taken on a peer's word: account and storage reads carry Merkle-Patricia proofs against a beacon-anchored `stateRoot`; blocks, transactions, and receipts are verified against the header's `transactionsRoot`/`receiptsRoot`; `eth_call`/`eth_estimateGas` run in a local EVM over proof-served state. When a request can't be answered from verified data, it returns an error rather than falling back to a trusted source.

> **Status:** End-to-end verified `send` works on a real device — MetaMask renders the confirm screen from verified balances, fees, and a local gas estimate, then broadcasts the signed transaction over devp2p, with no proxy and no permissioned service. The remaining gaps are listed in [Implementation Status](docs/implementation-status.md).

There are **two interchangeable engines** behind the same zero-dependency API (`:myotis-api`). The original **Java engine** is built on Java 21 with the [Tuweni](https://github.com/consensys/tuweni) libraries (RLP, SECP256K1, byte utilities), in-house SSZ and Merkle-Patricia verification, a BLS verifier (pure-Java Milagro, or native blst from `rust/myotis-bls` behind the `BlsBackends` seam), and an embedded Hyperledger Besu EVM; it ships JVM 17 bytecode where the Android consumer needs it. The **Rust engine** (`rust/` Cargo workspace) reimplements the whole stack natively — discv4/discv5, RLPx, eth/66-69, snap/1 + snap/2, the beacon light client on blst, a revm-based EVM, ENS + CCIP-Read, multichain — and is the primary engine: the default selection, and ahead of the Java engine on features (the `eth_getLogs` log index, Tor routing, EIP-7702/state overrides in the EVM, the `finalized` tag on state reads). Hosts pick one per network via the `:myotis-engines` selector (`myotis.engine=java|rust|auto`, default `auto` — the Rust engine where it can serve, Java fallback; `-Pengine=…` on run tasks, a Settings toggle in the apps). Behavioral parity is pinned by shared conformance vectors and golden tests on both sides — see [Engines](#engines-java-and-rust). The shared UI is Kotlin + Compose Multiplatform (Android, desktop, iOS).

## Documentation

- [Architecture](docs/architecture-doc.md) — Describes the target design for how the library will obtain and cryptographically verify all Ethereum data without relying on JSON-RPC providers; not all parts are implemented yet.
- [Benefits](docs/benefits-doc.md) — Explains why a trustless wallet matters and what risks centralized RPC providers pose to users.
- [Implementation Status](docs/implementation-status.md) — Current implementation progress and what remains to be done.
- [Readiness & Verified Head Age](docs/readiness-and-verified-head-age.md) — When the node counts as synced and ready to answer queries, and what the "verified head age" on the Status screen means.
- [Status Screen](docs/status-screen.md) — Field-by-field guide to the Status screen: the readiness strip, banners, sync bar, every status row, and the actions below them.
- [Read Statistics](docs/read-stats.md) — The `read-stats` shadow cache: what a state-read cache (per-block, storage-root-keyed, or stale-serve) would have saved on a real session, measured without serving anything from it.
- [Disk & Network Usage](docs/disk-and-network-usage.md) — Storage footprint of a fully synced client (peer caches, light-client snapshot — there is no on-disk block/header database) and bandwidth: initial sync, the daily cost of staying synced, and what sending a transaction costs.
- [Re-Implementation Specification](docs/reimplementation/README.md) — The language-agnostic spec the Rust engine was built from: the trust model, wire protocols, verification ladder, engine API and the Rust-phase notes and plan (`06`, `07`).
- [eth_getLogs: the log index](docs/eth-getlogs-design.md) — Design of the opt-in, verified log index behind `eth_getLogs` (Rust engine); companions: [verified bundles](docs/logindex-verified-bundle-design.md) (proposed) and [seeded histories](docs/seeded-log-histories.md) (the one bounded trust carve-out).
- [Privacy & Tor](docs/privacy-and-tor.md) — What the node leaks to peers today and the (feature-gated, experimental) Tor routing of account reads on the Rust engine.
- [Glamsterdam readiness](docs/glamsterdam-plan.md) — How the Gloas light client and the Amsterdam EVM are handled (live on Sepolia since the 2026-10-06 fork; mainnet and Gnosis have no date yet).
- [Dedicated light-client server](docs/lc-server-design.md) — The design behind [`rust/roost`](rust/roost/README.md), the light-client server that keeps a free slot for wallets.
- [Base (L2) evaluation](docs/base-l2-evaluation.md) — Whether and how Base could be supported under the trust model: no sync committee, so the only anchor is Base's proposals on mainnet (TEE-attested, 32–52 min old, no ZK proofs posted in practice), the weaker evidence available before one lands, the RPC landscape, and the cost of proving sequencing from L1 blob data.
- Integrations and proofs of concept: [Bee (Swarm) on Myotis](docs/bee-rpc-service.md) ([short version](docs/bee-node-from-source.md)), the [RAILGUN PoC build](docs/railgun-poc.md) (and [its seed on Android](docs/railgun-android.md)), [React Native](docs/react-native.md) (design), [inbound connections](docs/inbound-connections.md) (design), [multichain](docs/multichain-design.md).
- Historical: [Optimisations & Limitations](OPTIMISATIONS_AND_LIMITATIONS.md) (the Java engine's Android tuning record), the [SOLID](SOLID_REVIEW.md) and [Clean Architecture](CLEAN_ARCHITECTURE_REVIEW.md) reviews of the original modules, and the review follow-ups in [docs/TODO.md](docs/TODO.md).

## Wallet API — verified JSON-RPC over HTTP

The Android and desktop apps and the desktop daemon run an embedded JSON-RPC server (**loopback-only `127.0.0.1`** — mainnet on **8545**, Gnosis on 8546, Sepolia on 8547 by default; the apps let you change the port per network) that a same-device wallet talks to like any other Ethereum endpoint. (The iOS app carries the same listener for development, but iOS suspends backgrounded apps, so a separate wallet app cannot rely on it — on iOS a wallet embeds Myotis as a library instead.) Every method is answered **only** from cryptographically verified data; there is no trusted-RPC fallback in production (a dev-only upstream proxy exists purely to map what a wallet needs and is off in strict mode). When a request can't be served verified, the server returns a JSON-RPC error:

- `-32601` — the method isn't served verified at all (the wallet can stop asking).
- `-32000` — the method is implemented but can't be answered right now (not synced, no snap peer, the head isn't beacon-anchored yet, or an uncovered log-index range — retryable). One exception, kept for geth compatibility: an `eth_estimateGas` or `eth_call` whose transaction cannot succeed within the caller's own `gas`, fee cap or funds answers `-32000` with geth's message verbatim (`gas required exceeds allowance (N)`, `insufficient funds for transfer`, `out of gas`; a call that fails a check before it runs as geth's eth_call words it, `err: intrinsic gas too low: have N, want M (supplied gas N)` and likewise for the floor, `insufficient funds for gas * price + value: …` and `max fee per gas less than block base fee: …`) — an answer about that transaction, which a retry only repeats. Likewise an `eth_sendRawTransaction` the Rust engine refuses before broadcasting it, because the sender cannot pay for it or its nonce is used (geth's txpool words: `insufficient funds for gas * price + value: balance B, tx cost C, overshot D`, `nonce too low: next nonce N, tx nonce M`).
- `3` — `eth_call` / `eth_estimateGas` executed over verified state and the contract (or the transaction being estimated) REVERTED: the standard `execution reverted` error, with the raw revert payload in `error.data` and the decoded `Error(string)` reason in the message when present. This is a verified chain answer (not retryable) — wallets rely on it, e.g. MetaMask's ERC-165 token-standard probe expects a revert on plain ERC-20s, and a doomed transaction's estimate shows its actual revert reason instead of "node not synced".
- `-32602` — the request's parameters are malformed, or valid but unsupported by this node, and no retry will change that: answering without them would return a well-formed result to a different question than you asked. Every parameter of every verified method is applied or refused this way (#366):
  - **malformed or out-of-spec values** — more arguments than the method takes or `params` that is not an array (geth's `too many arguments` / `non-array args`), an address that is not 20 bytes, a transaction or block hash that is not 32, non-hex data, an empty raw transaction, a non-boolean `fullTransactions` flag, an index or `eth_feeHistory` count that is not a quantity, a count below 1, reward percentiles that are not numbers in [0, 100], non-decreasing, at most 100, or a missing `eth_feeHistory` newest block (an empty percentile list asks for no `reward` column, as in geth, and a count above 1024 is clamped as geth clamps it), and an `eth_getLogs` filter that is malformed, names `safe` or a block hash, has no address, or puts an explicit `fromBlock` above an explicit `toBlock` (refused even while the node is paused or syncing);
  - **block selectors** this node cannot apply (see *Block selectors* below) — `safe`, `earliest`, block 0, an empty string, bare decimal digits or a JSON number, a block hash or an EIP-1898 object where the method takes only a number (`eth_getBlockByNumber`, `eth_feeHistory`, the by-number compat reads), a block hash on the state reads and `eth_call` / `eth_estimateGas` (no historical state is held), `finalized` on the Java engine (which would answer it from the head), and a number pinned more than 64 blocks behind the verified head on the state reads, `eth_call` and `eth_estimateGas` (unless it is at or above a head this node itself reported in the last 15 minutes — a head that went back and forth is the node's glitch, answered with the retryable `-32000`);
  - **`eth_call` / `eth_estimateGas` fields** — a block override (`params[3]`: any value but `null` or `{}`), a state override (`params[2]`) on an engine that cannot apply it (the Rust engine applies state overrides; the Java engine does not); a transaction object that is contradictory (a type-4 request without an `authorizationList`, a tip above its fee cap, `data` and `input` that differ), names another chain in `chainId`, or is a blob transaction; an `authorizationList` / `accessList` or contract creation on the Java engine; an `eth_call` whose `gas`, above the node's 30 M call budget, was capped to it and ran out there;
  - **an engine's permanent refusal** — a block past a fork the engine cannot execute (Amsterdam on Sepolia on the Java engine, whose Besu 26.4 cannot price it; the Rust engine's revm does), and any read the engine itself marks permanent.

  Fall back to a request without the field, or use an upstream that applies it.
- `-32600` — the request object itself is invalid: `jsonrpc` is not `"2.0"`, `method` is not a string, the `id` is not a string, number or null (answered with a `null` id), or a batch carries more than 1000 requests (refused whole, as geth refuses it). A request without an `id` is a notification: it is served but never answered, and a batch of notifications gets an empty body.

> **Security:** the server binds **loopback only** by default — the wallet is a same-device client, and the endpoint is unauthenticated with no TLS or rate limiting (and `eth_sendRawTransaction` relays whatever signed bytes it's handed), so it is deliberately not reachable from other devices. Exposing it on a routable interface would require an explicit, opt-in change.

**Connecting MetaMask:** MetaMask runs on the same device as the node. Add a custom network pointing at `http://localhost:8545` (chain id 1 for mainnet). The desktop daemon serves the same verified JSON-RPC (mainnet on `127.0.0.1:8545`) and additionally exposes the verified operations over its CLI/IPC socket (see *Query commands* below).

### Implemented (verified) methods

The authoritative list is `VERIFIED_METHODS` in `jsonrpc-server`'s `RpcRouter.kt`; this
table mirrors it. `myotis_rpcCoverage` on a running node reports what has
actually been asked and answered.

| Method | How it's verified |
|---|---|
| `eth_chainId`, `net_version` | from config |
| `eth_blockNumber` | beacon optimistic-head execution block number |
| `eth_syncing` | straight from the beacon light client: `false` once `SYNCED`, otherwise a syncing object with zero bounds (the verified surface has no block-download notion and serves no chain-state reads before `SYNCED`; config and utility methods answer regardless) |
| `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | snap (snap/1 or snap/2) Merkle-Patricia proof against a beacon-anchored `stateRoot` (absent accounts/slots proven via exclusion proof — a verified zero, not a guess) |
| `eth_call` | local EVM over proof-served state — revm on the Rust engine, Besu on the Java engine — with a multi-hop speculative prefetch loop batching the SLOAD round-trips on both, and hedged state fetches across peers on the Rust engine. The whole transaction object is applied as geth applies it: `from`, `to`, `data`/`input`, `value` and the block selector; `gas` is the call's limit (running out of it is geth's `out of gas`); a fee must reach the base fee, is charged before the call runs and is what `GASPRICE` reads, and — fee or not — the sender must hold `gas × fee cap + value`. The Rust engine also applies `accessList`, `authorizationList`, a state override (`params[2]`) and contract creation (an absent `to` runs the init code); the Java engine refuses them (`-32602`), as both engines refuse blob fields and block overrides. A revert is error `3` with the payload |
| `eth_estimateGas` | local EVM: geth's search for the lowest gas limit at which the transaction succeeds, plus a 15% buffer (and at least the EIP-7623 calldata floor), over the whole transaction object: EIP-7702 `authorizationList` (applied as a mined transaction applies it — an invalid tuple is skipped), `accessList`, the `gas` cap, the fee fields (what `GASPRICE` reads, and geth's cap of what the sender can pay for), `nonce`, `type`, the block selector and a state override — the Rust engine applies all of them; the Java engine applies `gas`, fees and the block and refuses the rest (`-32602`). The answer never exceeds the caller's `gas` (without one, the block's gas limit), and never falls below what the transaction draws when run as simulated; a plain transfer to an EOA short-circuits to 21000; a reverting tx returns an error, never a number |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` | base fee from verified headers; priority-fee tips from block bodies verified against `transactionsRoot` (+ receipts vs `receiptsRoot` for the gas-weighted percentile reward walk) |
| `eth_getBlockByNumber`, `eth_getBlockByHash` | verified header window anchored to the beacon head; tx hashes checked against `transactionsRoot` (no snap peer required); an unknown or non-canonical hash answers `null` |
| `eth_getBlockTransactionCountByNumber`, `eth_getBlockTransactionCountByHash`, `eth_getTransactionByBlockNumberAndIndex`, `eth_getTransactionByBlockHashAndIndex`, `eth_getUncleCountByBlockNumber`, `eth_getUncleCountByBlockHash`, `eth_getUncleByBlockNumberAndIndex`, `eth_getUncleByBlockHashAndIndex` | derived from the same verified block serve (count or element read out of the verified block); post-Merge blocks have no uncles, so the uncle reads answer `0` / `null` from a verified block, not a stub |
| `eth_getTransactionReceipt`, `eth_getBlockReceipts` | scans the recent verified block window; receipts verified against `receiptsRoot` (handles eth/69 bloomless receipts by recomputing the bloom) |
| `eth_getTransactionByHash` | mined txs from the verified block window; locally-broadcast txs served as *pending* from a sent-tx cache; sender recovered from the signature (legacy + EIP-2930/1559/4844/7702) |
| `eth_getLogs` | served **only from the [log index](#log-index-verified-eth_getlogs)**: an opt-in, per-network index of the contracts you choose, every log verified against `receiptsRoot` over devp2p. A range the index has not covered is refused with `-32000` (the message says how far coverage reaches), never answered with a misleading `[]`. Historical coverage has to be built — a backfill to the contract's deployment block — and can be **bundled**: build once on an always-on daemon, `export-logindex` the portable chain-tagged `.db`, import it in the app. Rust engine only, and served by the JVM hosts (Android, desktop app, daemon) — the iOS app's RPC backend does not wire `eth_getLogs` yet, so it answers `-32000` there. |
| `eth_sendRawTransaction` | gossips the user-signed bytes to devp2p peers and returns the hash (Myotis never signs — the wallet does). The Rust engine first checks what geth's txpool checks: a transaction whose sender cannot pay `value + gas × fee`, or whose nonce is already used, is refused with geth's `-32000` message and never broadcast — but only when the sender's balance and nonce were proven against a fresh head's own state root; otherwise it is sent as before. |
| `eth_accounts` | the node holds no keys: exactly `[]`, a verified-grade constant |
| `net_listening`, `net_peerCount` | `true` (the discovery listener is live whenever the node runs); the peer count comes from the node's own status snapshot, never a fabricated zero |
| `web3_clientVersion`, `web3_sha3` | static identifier `Myotis/verified-light-client`; local keccak-256 — no chain data involved |

Any other method returns `-32601` (not served verified); a method from the table that
cannot be answered *right now* returns the retryable `-32000` instead — the full
error-code contract is the list at the top of this section.

**Node introspection (`myotis_*`).** Answered locally, bypassing the verified backend, so a
myotis-aware client can poll them before the node is synced or has peers:
`myotis_status` and `myotis_beaconStatus` (the JSON-RPC twins of the daemon's `status` /
`beacon-status` commands), `myotis_rpcCoverage` (which methods have been requested and how
they were answered), and `myotis_pause` / `myotis_wakeup` (the host's background/foreground
hooks).

**Block selectors.** One reading for every method that takes a selector (#366): a tag, a `0x`-prefixed hex number, and — where geth takes a `BlockNumberOrHash` (the state reads, `eth_call`, `eth_estimateGas`, `eth_getBlockReceipts`) — a 32-byte block hash or EIP-1898's object form (`{"blockNumber": …}` is that number; `{"blockHash": …}` that hash). Anything else is refused with `-32602`, never guessed: an empty string (only an absent or `null` selector means `latest`), bare decimal digits (one engine reads them as decimal, the other as hex), JSON numbers, unknown or mixed-case tags. `latest` and `pending` resolve to the verified (optimistic) head — `pending` with this node's own unmined broadcasts in `eth_getTransactionCount`, as it has no view of the public mempool. `safe` is **refused**: neither engine tracks the safe (justified) head, and both used to answer it from the head — another block. `earliest` and block 0 are refused (no genesis state or blocks are held). `finalized` is **applied** on the Rust engine: `eth_call`, the block and receipt reads and `eth_feeHistory` run against the beacon-finalized block (ABI 30), and the state reads prove against the finalized state root (ABI 32; best effort, since execution clients keep only on the order of 128 recent states and finality trails the head by two epochs — a finality delay makes such a read the retryable `-32000` until finality catches up). The Java engine would resolve `finalized` to its head, so the router refuses the tag there (`-32602`) on every method. A number-pinned read (wallets pin every read to the block they just saw) is served from the head's state when the number is within a small window of it (64 blocks below to 16 above) — the near-head trade-off; exact-block execution is #382. A number further behind is refused with the permanent `-32602` before any engine is asked, on both engines — unless it is at or above a head this node itself answered `eth_blockNumber` with in the last 15 minutes, which stays the retryable `-32000` (a wallet pins the number it was given, and a node head that swung back is not the wallet's invalid params); a number ahead of the window answers the retryable `-32000` (the head may yet reach it). A block hash is refused on the state reads, `eth_call` and `eth_estimateGas` (no historical state is held), and served by `eth_getBlockByHash` and `eth_getBlockReceipts`. Block reads (`eth_getBlockByNumber`, the receipt scans) look back up to 512 blocks below the head. Details: [Readiness & Verified Head Age → Block tags](docs/readiness-and-verified-head-age.md#block-tags).

## Requirements

- Java 21+
- Gradle (wrapper included)
- For the Rust engine: rustc/cargo stable (at least the workspace `rust-version` in `rust/Cargo.toml`) — optional for the JVM hosts, **required** for the Android app and the packaged desktop installers; see [Engines](#engines-java-and-rust) for the per-target toolchains.

## Build

```bash
# Build all modules (includes tests)
./gradlew build

# Compile only (skip tests)
./gradlew compileJava

# Run tests
./gradlew test
```

## Run

Myotis runs in four app forms: the **Android app**, the **iOS app**, and the **desktop app** (Compose GUIs over the shared `:ui`, running the wallet node with the verified JSON-RPC server), and the **desktop daemon/CLI** (the same engine for development, with a CLI/IPC command surface). All of them run the full devp2p + libp2p stack, the beacon light client, and the local EVM; on iOS the node runs on the Rust engine (the JVM engine never runs there). A fifth form is an embedding rather than an app: the engine as a **Node.js addon** for Electron/Node hosts — and on iOS as the embeddable `MyotisKit` framework — see [Embedding: Node.js / Electron](#embedding-nodejs--electron).

### Android

```bash
# Build + install the debug app on a connected device
./gradlew :android-app:installDebug
```

The app runs the node as a foreground `NodeService` (Start/Stop in the UI). Once it reaches `SYNCED`, the JSON-RPC server is live on `127.0.0.1:8545`; point an on-device MetaMask at `http://localhost:8545` (custom network, chain id 1). The app persists the sync snapshot, the known-state-root window, and light-client-capable peers, so warm restarts reach `SYNCED` in ~10 s. minSdk 29.

### iOS

The iOS app builds on macOS only (Xcode 26+, plus the Rust iOS targets: `rustup target add --toolchain stable aarch64-apple-ios aarch64-apple-ios-sim`). On iOS the node always runs the **Rust engine** over its plain C ABI — the JVM engine never runs there. `:app-ios` bundles the shared `:ui` and the engine into a Kotlin/Native framework (`MyotisKit`); the app shell is the Xcode project in `ios-app/` (regenerable with `xcodegen generate`).

```bash
# Kotlin/Native framework for the arm64 simulator (builds the Rust engine first)
./gradlew :app-ios:linkDebugFrameworkIosSimulatorArm64

# Build the app from the Xcode shell
cd ios-app && xcodebuild -project Myotis.xcodeproj -scheme Myotis \
  -destination 'platform=iOS Simulator,name=<device>' build
```

On iOS the app form is a development host more than an integration point: iOS suspends backgrounded apps, so the app's loopback JSON-RPC listener (foreground-only) can't serve a separate wallet app the way the Android and desktop nodes can. The supported iOS integration is **embedding** — a wallet links the `MyotisKit` framework (or the engine's C ABI directly) and runs the node in its own process. Releases ship a prebuilt **`MyotisKit.xcframework.zip`** (device arm64 + arm64 simulator, `+ .sha256`) so a host can drop it in without a local Kotlin/Native build.

### Desktop app (GUI)

`:app-desktop` is the Compose-Multiplatform desktop GUI — the same `:ui` NodeScreen the Android app hosts, running the engine in-process (the Rust engine by default, the Java engine as fallback or by choice). It shows the Status, Query and Settings tabs — plus Logs and Index under Settings → Expert mode — and serves the same verified JSON-RPC.

```bash
# Run from source (dev loop) — starts the GUI, compiling the Rust engine first
./gradlew :app-desktop:run

# Pick the engine explicitly: auto (default) | rust | java
./gradlew :app-desktop:run -Pengine=java
```

Build a native installer for the host OS with jpackage. **jpackage is host-OS-bound**: the `.dmg` can only be produced on macOS and the `.deb` only on Linux (CI builds each on its matching runner — `desktop-dmg.yml` / `desktop-linux-deb.yml`); locally you get the format for your OS. Only macOS and Linux formats are configured today — Windows packaging (`.msi`) isn't enabled yet, so these tasks fail on a Windows host.

```bash
# macOS → build a .dmg  (output under app-desktop/build/compose/binaries/main/dmg/)
./gradlew :app-desktop:packageDmg

# Linux → build a .deb  (output under app-desktop/build/compose/binaries/main/deb/)
./gradlew :app-desktop:packageDeb

# Or just the right format for whatever OS you're on
./gradlew :app-desktop:packageDistributionForCurrentOS

# Run the packaged app straight out of the build dir (no installer step)
./gradlew :app-desktop:runDistributable
```

The bundle embeds a full Java 21 runtime (the `:networking`/`:myotis-evm` backend ships Java-21 classes and reaches JDK modules reflectively, so the whole module graph is included). Packaged builds (dmg/deb/`runDistributable`) **bundle the Rust engine** as an app resource — packaging fails loudly if cargo isn't available, so an installed app can always switch engines. Logs roll under `~/.myotis/logs`; the app's log level comes from the `myotis.log.level` JVM system property (default `INFO`). Each JSON-RPC call gets a one-line summary at `INFO`; the request/response bodies (size-capped, **unredacted: they include addresses and signed transactions**) are logged only at `DEBUG` — pick DEBUG on the Logs-tab chip, or launch with `myotis.log.rpc.level=DEBUG`. Note that a `-D` flag on a `./gradlew :app-desktop:run` command line reaches the Gradle JVM, not the app — for a packaged app, edit the `java-options` in the bundle's generated `Myotis.cfg`.

### Embedding: Node.js / Electron

Myotis also runs **inside other applications** as a Node.js native addon: [`rust/myotis-node`](rust/myotis-node/README.md) is a [napi-rs](https://napi.rs) binding over the engine's C ABI (the same seam the iOS host consumes). A Node or Electron host loads `myotis-node.node`, starts the node in-process, and gets verified reads back as ordinary Promises — the engine's blocking calls run on the libuv thread pool. Every [release](https://github.com/biafra23/myotis/releases) since v0.1.3 ships prebuilt addon binaries (macOS arm64/x64, Linux arm64/x64, Windows x64) plus a `SHA256SUMS` manifest.

```js
const myotis = require('./myotis-node.node');   // ESM: createRequire(import.meta.url)
myotis.init();                                  // ABI handshake
const h = myotis.create('mainnet', '/path/to/data-dir');
// or, to recover a STALE_ANCHOR install from a checkpoint the host authenticated itself
// (ABI >= 26): myotis.createWithCheckpoint('mainnet', freshDir, blockRoot, headerSlot)
myotis.start(h);
// once statusJson(h) reports beaconState === 'SYNCED', elReaderAvailable, and
// snapServingPeers > 0 (ABI >= 31: a pooled peer that can answer at the anchored
// head — a pool of still-syncing peers keeps snapPeers > 0 while every read fails):
const ens = JSON.parse(await myotis.resolveEnsJson(h, 'vitalik.eth'));
```

This is how the [Freedom browser](https://github.com/solardev-xyz/freedom-browser) is integrating Myotis ([PR #181](https://github.com/solardev-xyz/freedom-browser/pull/181)): an invisible background node — alongside the browser's Swarm and IPFS nodes — behind an experimental tier that serves fully-P2P verified `.eth` resolution with no prover service and no RPC provider in the loop.

### Embedding: iOS / Swift

For Swift hosts that embed the engine **without** the Kotlin/Native `MyotisKit` framework, [`rust/build-xcframework.sh`](rust/build-xcframework.sh) packages the engine's plain C ABI as a static **`MyotisEngine.xcframework`** (device arm64 + fat simulator slice, header + Clang modulemap included — `import MyotisEngine` from Swift). Releases ship the zip + SHA256 alongside the napi addons, and CI builds the iOS targets on every `rust/` change so they stay green.

The host contract is the same as everywhere else: gate on `myotis_init()` returning the header's `MYOTIS_ABI_VERSION`, run the blocking verified reads off the main thread, free every returned string with `myotis_string_free`, and treat `myotis_pause`/`myotis_resume` as the scenePhase background/foreground hooks (warm resume is ~10 s back to `SYNCED`). Wait for `statusJson` to report `beaconState == "SYNCED"` **and** `snapServingPeers > 0` before attempting reads — right after sync the pool can hold only peers that are still syncing themselves (`snapPeers > 0`, yet every read fails until one of them covers the anchored head, #465). A host that knows a serving execution node can hand it to the engine with `myotis_set_boot_enodes` (ABI ≥ 31, a JSON array of `enode://` URLs, applied or refused as a whole) to shortcut a cold start; the engine ships no mainnet seed list of its own.

One caveat: an app that already links **another** Rust staticlib (another embedded node) must not add this xcframework next to it — two Rust staticlibs in one binary collide on the runtime/allocator. Build a single aggregator staticlib crate that depends on both engines as rlibs and re-exports their C symbols instead (one std/allocator/tokio/libp2p). That is how the Freedom iOS browser embeds Myotis alongside its Swarm and IPFS nodes: [freedom-mobile-ffi](https://github.com/solardev-xyz/freedom-mobile-ffi).

### Desktop daemon

The daemon discovers peers, maintains connections, and listens for CLI commands on a Unix domain socket (`/tmp/ethp2p.sock`); it exposes the verified operations as CLI commands (`get-account`, `get-storage`, `resolve-ens`, …) alongside the same verified JSON-RPC server the apps run (mainnet on `127.0.0.1:8545`). A **client** invocation sends a single command to the running daemon and exits.

### Start the daemon

```bash
# Mainnet
./gradlew :app:run

# Custom port (default: 30303)
./gradlew :app:run -Pport=30304
```

The daemon runs in the foreground. It discovers peers via discv4 (Kademlia DHT), establishes RLPx encrypted connections, and performs eth protocol handshakes. A beacon chain light client syncs finalized state roots from the consensus layer.

### Run the Gnosis Chain daemon

Gnosis Chain (chainId 100) is a supported network with its **own** consensus
layer (Gnosis Beacon Chain — 5s slots, 16 slots/epoch). Select it with
`-Pnetwork=gnosis`:

```bash
# 1. Refresh the trusted checkpoint (weak-subjectivity anchor) for Gnosis.
#    Do this before the first sync so the light client bootstraps from a recent
#    finalized root that peers still serve.
./gradlew refreshCheckpoint -Pnetwork=gnosis

# 2. Start the Gnosis daemon.
./gradlew :app:run -Pnetwork=gnosis
```

Each network is fully isolated: the Gnosis daemon uses its own IPC socket
(`/tmp/ethp2p-gnosis.sock`), lock file, and peer/sync caches (suffixed
`-gnosis`). Because of that, **every client command must also carry
`-Pnetwork=gnosis`** so it talks to the right daemon:

```bash
./gradlew :app:run -Pnetwork=gnosis -Pargs=status
./gradlew :app:run -Pnetwork=gnosis -Pargs=beacon-status      # SYNCING → CATCHING_UP → SYNCED
./gradlew :app:run -Pnetwork=gnosis -Pargs=peers
./gradlew :app:run -Pnetwork=gnosis -Pargs="get-account 0x<address>"
./gradlew :app:run -Pnetwork=gnosis -Pargs=stop
```

To run Gnosis **alongside** mainnet, host both in **one** daemon process — each
network gets its own ports, lock file and IPC socket, and client commands still
pick the network with `-Pnetwork`:

```bash
./gradlew :app:run -Pnetwork=mainnet,gnosis
```

Two separate daemons also work, as long as the second one gets a different EL
port (mainnet keeps 30303): `./gradlew :app:run -Pnetwork=gnosis -Pport=30304`.
One caveat for that form: a single-network daemon binds discv5 to UDP 9000
whatever the network, so a second **Java-engine** daemon beside mainnet fails
that bind and carries on without CL discovery (pinned CL peers and the cache
only); the default `auto`/Rust engine picks its own discv5 port and is
unaffected. The one-process form avoids the collision entirely.

> Note: verified-state queries (`get-account`/`get-storage`) require an active
> EL peer that serves `snap` (snap/1 or snap/2). Public Gnosis nodes are fewer and busier than
> mainnet's, so the light client may reach `SYNCED` (beacon trust anchor ready)
> before a snap-serving peer is held — retry once `peers` shows snap-capable
> connections, or let the peer cache warm over runs.

### Stop the daemon

```bash
# Mainnet
./gradlew :app:run -Pargs=stop

# A specific network (e.g. Gnosis)
./gradlew :app:run -Pnetwork=gnosis -Pargs=stop
```

## Query commands

All commands are sent to the running daemon via IPC. Responses are JSON.

### When is the daemon ready to answer?

Most commands depend on different parts of the stack being up. After
starting the daemon, wait for the sub-system you need before issuing
queries. The table is also the command reference — the daemon hosts either
engine, and a few commands exist on one engine only:

| Command | Engine | Requires |
|---------|--------|----------|
| `status`, `beacon-status`, `pause`, `resume`, `accept-stale-anchor`, `read-stats`, `stop` | both | daemon running (`beacon-status` progresses `SYNCING` → `CATCHING_UP` → `SYNCED`) |
| `peers` | both — the Rust engine returns empty peer lists; use the counts in `status` | daemon running |
| `dial <enode>` | Java | daemon running |
| `get-headers`, `get-block` | Java | at least one peer in `READY` state (check with `peers`) |
| `get-account`, `get-storage` | both | at least one snap-serving peer (`snapServingPeers > 0` in `status`) |
| `get-account`, `get-storage`, `get-block` (full beacon verification — `verifyMethod` populated, `beaconChainVerified=true`) | — | `beacon-status` returns `"state":"SYNCED"` |
| `resolve-ens`, `reverse-ens`, `resolve-ens-*` | both (mainnet and Sepolia — Gnosis has no ENS) | at least one snap-serving peer |
| `build-logindex`, `logindex-backfill on\|off`, `import-logindex <file…>`, `export-logindex <file>` | Rust (the Java engine answers an error) | daemon running (see [Log index](#log-index-verified-eth_getlogs)) |
| `logindex-status` | both — on the Java engine a stable `{"enabled":false,"logCount":0,"entries":[]}` | daemon running |
| `get-transactions <address>` | Java, mainnet only (debug) | at least one peer in `READY` state |
| `purge-cache` | — | runs in the client with the daemon **stopped**: deletes the first network's peer caches and sync snapshot |

Account and storage queries return data with a Merkle proof against
the peer's `stateRoot` even before the beacon light client reaches
`SYNCED`. Until its first finalized root lands (`SYNCING`) the
response reports `beaconChainVerified=false` with
`failReason: "beaconNotSynced"`; after that (`CATCHING_UP`) it can
verify, but against a finalized root that may not be current. Wait
for `SYNCED` if you need the full beacon-anchored trust chain.

How long `SYNCED` takes depends on what's cached: a warm restart
(persisted sync snapshot + state-root window + known light-client
peers) reaches `SYNCED` in roughly 10 seconds; a cold start has to
bootstrap from the embedded checkpoint and catch the sync committee
up period by period (visible as `CATCHING_UP` with
`currentPeriod`/`targetPeriod` progressing), which takes minutes
when the checkpoint is old. Watch progress with:

```bash
./beacon-status.sh
# or
watch -n 2 ./beacon-status.sh
```

### Status

```bash
./gradlew :app:run -Pargs=status
```

Returns daemon operational metrics.

| Field | Type | Description |
|-------|------|-------------|
| `state` | string | Always `"RUNNING"` for an active daemon |
| `uptimeSeconds` | long | Daemon uptime in seconds |
| `discoveredPeers` | int | Total peers in the Kademlia DHT |
| `connectedPeers` | int | Total active TCP (RLPx) connections |
| `readyPeers` | long | Peers that completed the eth handshake |
| `snapPeers` | long | Ready peers that also negotiated snap (snap/1 or snap/2) |
| `snapServingPeers` | int | Snap peers in the serving pool right now — gate reads on this, not on `snapPeers` (#465). Rust engine: peers whose announced or served head is at or near the anchored head; Java engine: active snap sessions |
| `snap2ServingPeers` | int | The part of `snapServingPeers` whose connection runs snap/2 (EIP-8189). Informational — reads are the same on snap/1 and snap/2, so never gate on it. The Status screen shows it in parentheses after the serving count (`serving 8 (3)`), and omits them at 0 |
| `backedOffPeers` | long | Peers in temporary backoff (connect failure, busy, incompatible; the Rust engine also lagging). Rust engine: entries still blocking a dial at the pool's current shortfall — below target, a window shrinks in proportion to it, never under geth's 30 s inbound throttle (#539) |
| `blacklistedPeers` | long | Peers permanently blacklisted (incompatible network) |

### Peers

```bash
./gradlew :app:run -Pargs=peers
```

Returns discovered peers (from the Kademlia table) and connected peers with their state, snap support, and client ID. Java engine only — on the Rust engine the lists come back empty and the peer counts (`snapPeers`, `snapServingPeers`, …) in `status` are the surface.

### Beacon status

```bash
./gradlew :app:run -Pargs=beacon-status
```

Returns beacon chain light client sync state.

| Field | Type | Description |
|-------|------|-------------|
| `state` | string | `"SYNCING"` (no trust anchor yet), `"CATCHING_UP"` (anchor present, but the state-root window is still sparse or the held sync committee lags wall clock), `"SYNCED"` (verification-ready; can regress to `CATCHING_UP` if the node falls behind), or `"STALE_ANCHOR"` (syncing refused: the best available anchor is older than the weak-subjectivity bound — see §Weak-subjectivity age bound; the response carries `anchorPeriod`, `anchorAgePeriods`, `wsBoundPeriods`, and a `warning`) |
| `currentPeriod` | long | Sync-committee period the store currently holds (0 before bootstrap) |
| `targetPeriod` | long | Wall-clock sync-committee period being caught up to |
| `uptimeSeconds` | long | Daemon uptime |
| `discoveredPeers` | int | Live discv5 nodes |
| `connectedPeers` | int | Connected libp2p beacon peers |
| `lightClientPeers` | long | Connected peers advertising the light-client protocols |
| `finalizedSlot` | long | Latest finalized beacon slot (0 while `SYNCING`) |
| `optimisticSlot` | long | Latest optimistic (attested but not finalized) slot (0 while `SYNCING`) |
| `finalizedPeriod` | long | `finalizedSlot / 8192` (absent while `SYNCING`) |
| `syncCommitteePeriod` | long | Same as `currentPeriod` — the committee period the store verifies against, **not** `finalizedSlot / 8192` (absent while `SYNCING`) |
| `wallClockPeriod` | long | Same as `targetPeriod` (absent while `SYNCING`) |
| `executionStateRoot` | string/null | Verified execution state root (null while `SYNCING`) |
| `executionBlockNumber` | long | Finalized execution block number (absent while `SYNCING`) |
| `knownStateRoots` | int | State roots in the rolling window cache |
| `fillThreshold` | int | Window size required for `SYNCED` (absent while `SYNCING`) |
| `peers` | array | Connected beacon peers (see below) |

**Peer fields** (in the `peers` array):

| Field | Type | Description |
|-------|------|-------------|
| `peerId` | string | Truncated libp2p peer ID |
| `remoteAddress` | string | Peer's network address |
| `clientId` | string | Client identification string (if available) |
| `lightClient` | boolean | Whether peer supports the light client protocol |
| `protocols` | int | Number of advertised protocols |

### Accept a stale anchor

```bash
./gradlew :app:run -Pargs=accept-stale-anchor
```

One-shot consent to sync forward from a trust anchor older than the weak-subjectivity
bound (see README §Weak-subjectivity age bound). Applies **only** while `beacon-status`
reports `"state":"STALE_ANCHOR"` — sent at any other time it answers
`"applied":false` without arming anything. Consent lasts for the current run only and
is never persisted; a restart with a still-stale anchor parks again. Prefer refreshing
the checkpoint (`./gradlew refreshCheckpoint`) over accepting.

### Get block headers

```bash
# Get 3 headers starting at block 21000000
./gradlew :app:run -Pargs="get-headers 21000000 3"
```

### Get block (header + body)

```bash
./gradlew :app:run -Pargs="get-block 21000000"
```

Returns block header and body data with beacon chain verification.

**Block fields:**

| Field | Type | Description |
|-------|------|-------------|
| `number` | long | Block number |
| `hash` | string | Block hash (keccak256 of RLP-encoded header) |
| `parentHash` | string | Parent block hash |
| `stateRoot` | string | State trie root after executing this block |
| `transactionsRoot` | string | Transactions trie root |
| `receiptsRoot` | string | Receipts trie root |
| `timestamp` | long | Block timestamp (Unix seconds) |
| `gasUsed` | long | Total gas used by all transactions |
| `gasLimit` | long | Block gas limit |
| `baseFeePerGas` | string | EIP-1559 base fee (post-London only) |
| `transactionCount` | int | Number of transactions in the block |
| `uncleCount` | int | Number of uncle blocks (always 0 post-Merge) |
| `withdrawalCount` | int | Number of validator withdrawals (post-Shanghai) |

**Verification fields** (in the `verification` object):

| Field | Type | Description |
|-------|------|-------------|
| `beaconSynced` | boolean | Whether the beacon light client has synced |
| `beaconChainVerified` | boolean | Whether the block is verified against the beacon chain |
| `verifyMethod` | string | `"stateRootMatch"` or `"headerChain"` (only when `beaconChainVerified=true`) |
| `matchedBeaconSlot` | long | Beacon slot trust anchor (only when `beaconChainVerified=true`) |
| `blsVerified` | boolean | Whether the trust anchor has BLS verification (only when `beaconChainVerified=true`) |
| `failReason` | string | Why verification failed (only when `beaconChainVerified=false`, see below) |

**`failReason` values:**

| Value | Description |
|-------|-------------|
| `preMergeBlock` | Block is before The Merge (block 15,537,394). Pre-merge blocks cannot be verified via the beacon chain. |
| `headerChainGapTooLarge` | The block is more than 8,192 blocks away from the beacon-finalized block. |
| `beaconNotSynced` | The beacon light client has not synced yet. |
| `beaconBlockHashUnavailable` | The beacon state does not have a finalized block hash to anchor against. |
| `headerChainInvalid` | A header chain was fetched but failed validation (hash mismatch or discontinuity). |
| `headerChainError` | An error occurred while fetching or verifying the header chain. |

**Block verification model:**

Block verification works differently from account/storage verification. Account and storage queries have two layers of protection: a Merkle-Patricia proof (binding data to a state root) and beacon chain linkage (proving the state root is canonical). Block verification has only the beacon chain linkage layer -- there is no Merkle proof for block inclusion.

The verification anchors to the beacon chain's `ExecutionPayloadHeader.block_hash`, which is verified by sync committee BLS signatures. The finalized block header is fetched from a peer, and its locally-computed `keccak256(RLP)` is compared against this beacon-attested hash. From that anchor, a parent-hash chain is walked to or from the requested block. Each link is pinned by the previous header's keccak256 hash, making forgery require a preimage attack.

### Get account

```bash
./gradlew :app:run -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
```

Returns account data with a Merkle-Patricia proof and cryptographic verification.

**Account fields:**

| Field | Type | Description |
|-------|------|-------------|
| `exists` | boolean | Whether the account was found in the state trie |
| `address` | string | The queried address (0x-prefixed) |
| `accountHash` | string | keccak256 of the address |
| `nonce` | long | Account transaction count (only if `exists=true`) |
| `balance` | string | Account balance in wei (only if `exists=true`) |
| `storageRoot` | string | Storage trie root hash (only if `exists=true`) |
| `codeHash` | string | Contract code hash (only if `exists=true`) |
| `proof` | array | Merkle-Patricia trie proof nodes (RLP-encoded, hex) |

**Verification fields** (in the `verification` object):

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `peerProofValid` | boolean | `true` / `false` | Whether the Merkle proof is cryptographically valid against the peer's state root. Proves the data is authentic relative to the peer's claimed state, but does not prove the state root itself is canonical. |
| `peerStateRoot` | string | 0x-prefixed hex | The state root the peer provided, against which the proof was verified. |
| `beaconSynced` | boolean | `true` / `false` | Whether the beacon chain light client has synced (has a finalized state root). |
| `beaconChainVerified` | boolean | `true` / `false` | Whether the peer's state root is verified against the beacon chain. This is the critical trust anchor: `true` means the data is cryptographically backed by sync committee signatures. |
| `verifyMethod` | string | `"stateRootMatch"` / `"headerChain"` | How the beacon chain verification was achieved (only present when `beaconChainVerified=true`). See below. |
| `matchedBeaconSlot` | long | slot number | The beacon slot used as the trust anchor (only present when `beaconChainVerified=true`). Beacon slots increment every 12 seconds. |
| `blsVerified` | boolean | `true` / `false` | Whether the trust anchor slot was validated via BLS sync committee signatures (only present when `beaconChainVerified=true`). `true` means at least 2/3 of the sync committee signed off on the data. |

**`verifyMethod` values:**

- **`stateRootMatch`** -- The peer's state root exactly matches a state root from a recent beacon block header stored in the rolling window cache. This is the most direct verification path.
- **`headerChain`** -- The peer's block is ahead of the finalized beacon block, so a chain of consecutive block headers was fetched and verified from the beacon-finalized block to the peer's block. Verification checks: (1) the first header's state root matches the beacon-attested root, (2) each header's parent hash matches the previous header's hash, (3) the last header's state root matches the peer's root.

**`failReason` values** (when `beaconChainVerified=false`; applies to both `get-account` and `get-storage`):

| Value | Description |
|-------|-------------|
| `noPeerStateRoot` | The peer did not provide a state root to verify against. |
| `peerProofInvalid` | The Merkle proof failed against the peer's claimed state root. |
| `beaconNotSynced` | The beacon light client has not synced yet. |
| `noPeerBlockNumber` | The peer's block number is unknown, so a header chain can't be anchored. |
| `beaconBlockUnavailable` | The beacon state has no finalized execution block to anchor against. |
| `peerBlockBehindFinalized` | The peer's block is older than the beacon-finalized block. |
| `headerChainGapTooLarge` | The peer's block is more than 8,192 blocks from the beacon-finalized block. |
| `headerChainInvalid` | A header chain was fetched but failed validation (hash mismatch or discontinuity). |
| `headerChainError` | An error occurred while fetching or verifying the header chain. |

### Get storage

```bash
# Direct slot access
./gradlew :app:run -Pargs="get-storage 0x<contract> <slot>"

# ERC-20 balance lookup (mapping slot with holder address)
./gradlew :app:run -Pargs="get-storage 0x<token> <slot> 0x<holder>"
```

Returns storage slot data for a contract with Merkle-Patricia proof verification. For ERC-20 tokens, pass the mapping slot number and holder address to compute `keccak256(abi.encode(holder, slot))`.

**Storage fields:**

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Contract address queried |
| `slot` | long | Slot number |
| `holder` | string | Holder address (only for ERC-20 mapping lookups) |
| `storageKey` | string | Computed storage key (0x-prefixed hex) |
| `storageKeyHash` | string | keccak256 of the storage key |
| `exists` | boolean | Whether the slot has a value |
| `value` | string | Storage value in hex (only if `exists=true`) |
| `valueDecimal` | string | Storage value as decimal (only if `exists=true`) |
| `slotsReturned` | int | Number of slots returned by peer (only if `exists=false`) |
| `storageRoot` | string | Account's storage trie root |
| `proof` | array | Merkle-Patricia proof nodes (RLP-encoded, hex) |

**Verification fields** (in the `verification` object):

| Field | Type | Description |
|-------|------|-------------|
| `storageProofValid` | boolean | Whether the storage proof is valid against the account's storage root |
| `beaconSynced` | boolean | Whether the beacon light client has synced |
| `beaconChainVerified` | boolean | Whether the state is verified against the beacon chain (same logic as `get-account`) |
| `verifyMethod` | string | `"stateRootMatch"` or `"headerChain"` (same as `get-account`, only present when `beaconChainVerified=true`) |
| `matchedBeaconSlot` | long | Beacon slot trust anchor (only present when `beaconChainVerified=true`) |
| `blsVerified` | boolean | Whether the trust anchor has BLS verification (only present when `beaconChainVerified=true`) |

### Read statistics

```bash
./gradlew :app:run -Pargs=read-stats
```

The read-fetch **shadow cache**: counters over every verified account /
storage / bytecode fetch this daemon made (the wallet's JSON-RPC reads, the
`eth_call` oracle, and the operator queries above), classifying each repeat by
which cache keying would have made it unnecessary and how much wall-clock it
cost — `sameStateRoot` (a per-block cache), `sameStorageRoot` (the sound
cross-block scheme, keyed by the account's storage root), `sameValue` /
`unchanged` (the ceiling no proof-based cache reaches), and `byAge` buckets
(how often a value up to 12 s / 60 s / 5 min old would have been correct).
Nothing is served from it; it exists to decide the next caching step on
measured traffic. Field-by-field guide: [docs/read-stats.md](docs/read-stats.md).

### Resolve ENS name

```bash
./gradlew :app:run -Pargs="resolve-ens vitalik.eth"
```

Resolves an ENS name to an Ethereum address by running the ENS contracts in a local EVM with state served from SNAP proofs. Supports vanilla `*.eth` names, ENSIP-10 wildcard resolution, and ERC-3668 off-chain (CCIP-Read) lookups.

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | `true` if the resolution attempt completed without protocol errors |
| `resolved` | boolean | `true` if a non-zero address was returned, `false` if the name has no record set |
| `name` | string | The queried name |
| `address` | string | Resolved address (0x-prefixed, only if `resolved=true`) |
| `beaconVerified` | boolean | `true` when resolution ran against the beacon-verified finalized state (the default), so the name→address mapping is anchored to a beacon-attested root |
| `blockNumber` | long | Execution block at which the resolution was performed |

**How it works:**

1. By default (AUTO) the daemon resolves against the light client's **beacon-verified finalized** execution state root first — no peer-head probe. Only if that yields no address (the record didn't exist at the finalized block) or can't be served does it fall back to a peer's head. (See *Resolution root* below.) A snap-capable peer serves the state; the proofs descend from the chosen `stateRoot`.
2. The local EVM (revm on the Rust engine, Hyperledger Besu's standalone EVM module on the Java engine) discovers the name's resolver through the ENS Registry — an ENSIP-10 walk: the exact node, then each parent — and calls it **directly**: `resolve(bytes name, bytes data)` on an ENSIP-10 (wildcard / off-chain) resolver, or the record method itself on a legacy resolver. No Universal Resolver and no shared CCIP batch gateway sit in the path. Every account field, storage slot, and contract bytecode the EVM reads is fetched on demand via snap and verified by Merkle-Patricia proof against that `stateRoot`.
3. If the call reverts with `OffchainLookup` (ERC-3668), the daemon fetches the gateway response over HTTPS from the resolver's **own** gateway (Coinbase's for `cb.id`, for example — no third-party relay) and re-enters the EVM with the resolver's callback. The callback validates the gateway's response on-chain — typically by checking a signer's signature against a list of trusted signers embedded in the resolver — so a malicious gateway cannot inject a wrong answer.
4. The resolver's return value is decoded as the resolved address.

**Resolution root (trust vs freshness):**

The state ENS executes against is configurable via `io.myotis.ens.EnsResolutionRoot`:

- **`AUTO` (default)** — resolve against the beacon-verified finalized state first; if that yields no address (the record didn't exist at the finalized block — e.g. a name registered or an `addr()` first set in the last ~12 min) or errors (a snap peer doesn't retain that block's state), fall back to the peer head. You get a beacon-verified mapping (`beaconVerified=true`) whenever one exists, and brand-new names still resolve (`beaconVerified=false`, peer-claimed). A record that *changed* in the last ~12 min resolves to its verified-but-stale finalized value (staleness, not a failure) — AUTO only falls back when finalized returns *no* address.
- **`FINALIZED`** — finalized state only; no fallback. Always `beaconVerified=true`, but brand-new names return "does not resolve."
- **`PEER_HEAD`** — resolve against a snap peer's latest head state. Freshest possible data, but the head root is the peer's *claim*, not beacon-attested, so the mapping is peer-claimed (`beaconVerified=false`). Choose this when you need the very latest ENS state and accept the weaker trust. (On Android, set via `NodeService.setEnsResolutionRoot(...)`.)

On the **Rust engine** the same choice is the `root` parameter of `ens_record_json` — the call the JVM hosts issue every ENS query through: `auto` (default), `finalized`, or `optimistic` — the beacon-anchored optimistic head, which stands in for `PEER_HEAD`. The bare forward lookup `resolve_ens_json` (Node addon `resolveEnsJson`) takes no root and resolves against the optimistic head in one attempt — no finalized-first preference; a host that wants `auto` or `finalized` goes through `ens_record_json`. The Rust engine has no peer-claimed mode: every ENS answer it gives is anchored to a beacon-attested root, finalized or optimistic.

**Trust model:**

- **State**: every read backed by a Merkle proof against the `stateRoot` — beacon-verified in `FINALIZED` mode.
- **Bytecode**: verified by `keccak256(code) == codeHash` from the proof-verified account.
- **CCIP-Read gateways**: trusted only for *availability* — the resolver's callback validates the response cryptographically. A lying gateway causes the call to revert, surfacing as a clean failure.

The same trust model and resolution root apply to every other `resolve-ens-*` command.

**Networks:** mainnet and Sepolia have the canonical ENS contract addresses pinned. Gnosis has no ENS, and the `resolve-ens*` commands answer `ENS is not available` there. (Holesky's addresses are still in `EnsResolver`, dead code since the network was retired in October 2025.)

**Validated names** (mainnet):

```bash
# Vanilla ENS (Public Resolver)
./gradlew :app:run -Pargs="resolve-ens vitalik.eth"
# → 0xd8da6bf26964af9d7eed9e03e53415d37aa96045

# CCIP-Read demo (EIP-3668 reference gateway)
./gradlew :app:run -Pargs="resolve-ens 1.offchainexample.eth"
# → 0x41563129cdbbd0c5d3e1c86cf9563926b243834d

# Coinbase ID (CCIP-Read via Coinbase's gateway)
./gradlew :app:run -Pargs="resolve-ens jesse.cb.id"
# → 0x849151d7d0bf1f34b70d5cad5149d28cc2308bf1
```

### Resolve ENS text record

```bash
./gradlew :app:run -Pargs="resolve-ens-text vitalik.eth avatar"
./gradlew :app:run -Pargs="resolve-ens-text vitalik.eth com.twitter"
```

Reads a text record (ENSIP-5) for a name. Common keys: `avatar`, `url`, `description`, `email`, `notice`, `keywords`, `com.twitter`, `com.github`, `org.telegram`.

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | The queried name |
| `key` | string | The text-record key |
| `resolved` | boolean | `true` if a non-empty value was returned |
| `value` | string | The record value (only if `resolved=true`) |
| `blockNumber` | long | Execution block at which the resolution was performed |

### Resolve ENS contenthash

```bash
./gradlew :app:run -Pargs="resolve-ens-contenthash vitalik.eth"
```

Reads the contenthash (ENSIP-7) — a multicodec-encoded pointer to IPFS, Swarm, IPNS, or Arweave content. Used to attach a decentralized website to an ENS name.

**Response fields:** `name`, `resolved`, `contenthash` (0x-prefixed multicodec bytes; decoder is the caller's responsibility), `blockNumber`.

### Resolve ENS multi-coin address

```bash
# Bitcoin (SLIP-44 coinType 0)
./gradlew :app:run -Pargs="resolve-ens-addr-coin some-name.eth 0"

# Litecoin (SLIP-44 coinType 2)
./gradlew :app:run -Pargs="resolve-ens-addr-coin some-name.eth 2"

# Solana (SLIP-44 coinType 501)
./gradlew :app:run -Pargs="resolve-ens-addr-coin some-name.eth 501"
```

Reads an `addr(node, coinType)` record (ENSIP-9 / SLIP-44). The default `addr` command returns the ETH-mainnet address (`coinType=60`); this two-arg form returns the chain-specific address bytes for any coinType the resolver has set.

**Response fields:** `name`, `coinType`, `resolved`, `address` (0x-prefixed raw chain-specific bytes — for Bitcoin this is the script payload, not a base58 address; the caller is responsible for decoding for that chain), `blockNumber`.

### Resolve ENS pubkey

```bash
./gradlew :app:run -Pargs="resolve-ens-pubkey some-name.eth"
```

Reads the secp256k1 public-key record (EIP-619). Niche — used for end-to-end-encrypted DM flows.

**Response fields:** `name`, `resolved`, `pubkeyX`, `pubkeyY` (each 0x-prefixed 32-byte hex), `blockNumber`. Returns `resolved:false` when both coordinates are zero.

### Resolve ENS ABI record

```bash
# Default contentTypes mask = 0xF (any encoding)
./gradlew :app:run -Pargs="resolve-ens-abi some-name.eth"

# Explicit mask: 1 = Solidity ABI JSON only
./gradlew :app:run -Pargs="resolve-ens-abi some-name.eth 1"
```

Reads an ABI record (EIP-205) — ABI metadata for a contract owned by the name. `contentTypes` is a bitmask: `1` = Solidity ABI JSON, `2` = zlib-compressed JSON, `4` = CBOR, `8` = URI. Default is `15` (all).

**Response fields:** `name`, `contentTypes`, `resolved`, `contentType` (which encoding the resolver chose), `data` (0x-prefixed bytes in that encoding), `blockNumber`.

### Resolve ENS DNS record

Reads a DNS record (ENSIP-8) stored under the name. The DNS record returned can include DNSSEC RRSIG bytes; the caller is responsible for parsing and (if desired) DNSSEC-verifying the bytes.

```bash
./gradlew :app:run -Pargs="resolve-ens-dns some-name.eth www.example.com 1"
```

Positional args are `<name.eth> <dnsName> <resource>`. `resource` is a DNS resource type (1 = A, 28 = AAAA, 16 = TXT, 33 = SRV, …).

**Response fields:** `name`, `dnsName`, `resource`, `resolved`, `data` (raw RDATA bytes), `blockNumber`.

### Resolve ENS interface implementer

```bash
# 0x5b5e139f is the EIP-165 selector for ERC-721 Metadata
./gradlew :app:run -Pargs="resolve-ens-interface some-name.eth 0x5b5e139f"
```

Reads `interfaceImplementer(node, interfaceId)` (EIP-1820 over ENS) — the address of a contract implementing the given EIP-165 interface for this name's owner. Positional args are `<name.eth> <0xInterfaceId>`.

**Response fields:** `name`, `interfaceId`, `resolved`, `implementer` (0x-prefixed 20-byte address), `blockNumber`.

### Get transactions

```bash
./gradlew :app:run -Pargs="get-transactions 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
```

Returns all transactions for an address (mainnet only, **Java engine only** — the scan wraps the Java engine's raw connector and is a debug feature, not a verified read) by looking them up in the [TrueBlocks Unchained Index](https://trueblocks.io/). Results are streamed as JSON-Lines, newest first, followed by a summary object. The same scan powers the **desktop and Android apps' Query tab** ("Find transactions" under an address lookup): hits appear as block-number placeholders and upgrade in place to parsed rows, with a progress bar and a Stop button. (On Android the bloom/index cache lives under `filesDir/trueblocks` and can grow to multi-GB after a deep scan.)

**How it works:**

1. Resolves the **latest** manifest CID from the UnchainedIndex_V2 contract on mainnet (`manifestHashMap(publisher, "mainnet")` at [`0x0c316B70…183d`](https://etherscan.io/address/0x0c316b7042b419d07d343f2f4f5bd54ff731183d)) using myotis' own **verified eth_call** — no external RPC. The publisher is `publisher.unchainedindex.eth` (chifra's preferred publisher, resolved via myotis' verified ENS; the manifest map is permissionless, so only the ENS-designated publisher's slot is trusted — even trueblocks.eth's own slot holds a junk placeholder). The result is cached for 24h; when the node isn't synced the cached (or, as a last resort, a hardcoded known-good) CID is used and the output says so via `cidSource`.
2. For each chunk in the manifest (scanned from newest to oldest blocks):
   - Downloads the Bloom filter (disk-cached under `trueblocks/`, content-addressed, immutable) and checks if the address appears
   - On a Bloom hit, downloads the index chunk (also cached) and extracts appearance records (block number + transaction index)
3. For each appearance, fetches the block header and body from devp2p peers and extracts the raw transaction
4. Decodes the transaction (legacy, EIP-2930, EIP-1559, EIP-4844, EIP-7702; sender recovered from the signature) and classifies it: plain ETH transfer, ERC-20 `transfer`/`transferFrom` of a well-known token (USDC, USDT, DAI, WETH, WBTC, …), generic contract call, or contract creation

**Stream shape** (succinct — one line per transaction, no raw tx hex):

```
{"ok":true,"manifestCid":"Qm…","cidSource":"contract","chunks":8123,"latestIndexedBlock":22841000,"headBlock":22843511}
{"ok":true,"blockNumber":22812345,"transactionIndex":41,"hash":"0x…","from":"0x…","to":"0xa0b86991…","kind":"erc20","token":"USDC","amount":"1250.50","recipient":"0x…","verified":false}
{"ok":true,"blockNumber":22711000,"transactionIndex":3,"hash":"0x…","from":"0x…","to":"0x…","kind":"eth","eth":"1.25","wei":"1250000000000000000","verified":false}
{"ok":true,"blockNumber":22600000,"transactionIndex":97,"hash":"0x…","from":"0x…","to":"0x…","kind":"call","calldataBytes":132,"selector":"0x38ed1739","verified":false}
{"ok":true,"progress":{"chunksScanned":250,"totalChunks":8123,"range":"022300000-022310000","hits":3,"bytesDownloaded":31457280}}
{"ok":true,"done":true,"totalTransactions":3}
```

`kind` is one of `eth` (plain transfer; `eth` = amount in ETH, `wei` = exact), `erc20` (well-known-token transfer; decimals-adjusted `amount` + decoded `recipient`), `call` (generic call; `calldataBytes` + 4-byte `selector`, plus `eth` when value is attached), or `create` (contract creation). Failed resolutions stream as `{"ok":false,"blockNumber":…,"error":"…"}` and the scan continues. A progress heartbeat line appears every 250 chunks.

**Limitations:**

- **Blocks are not verified.** Individual transactions are not yet verified against the block's `transactionsRoot`. The `verified` field is always `false`. This means a malicious peer could serve tampered transaction data. Verification against the transactions trie is planned but not implemented.
- **Index freshness depends on the publisher — and upstream publishing appears stalled.** The manifest CID tracks the on-chain publication, so the index is only as fresh as the designated publisher's latest publish. As of mid-2026 that is ~block 23.0M (**roughly a year behind the head**): `publisher.unchainedindex.eth` has not published a newer mainnet manifest, and the only newer-looking on-chain entry comes from an undesignated wallet whose content isn't retrievable from IPFS at all. Transactions above `latestIndexedBlock` will not be found. Both surfaces now make this loud: the `Started` IPC line carries `indexLagBlocks`/`indexAgeDays` plus `stale:true` + a `warning` beyond ~14 days of lag, and the desktop Query tab shows a warning banner with the approximate age and cutoff block. The planned remedy is a self-published index (running the TrueBlocks scraper and pinning/serving the chunks ourselves).
- **First full-history scan is heavy.** Every chunk's bloom filter is downloaded once (multi-GB across the whole chain history, kept forever in the `trueblocks/` cache); subsequent scans read blooms from disk. Newest chunks stream first, so recent history appears long before the scan completes — and the scan can be stopped at any point.
- **Completeness is not guaranteed.** IPFS content-addressing guarantees the index data has not been tampered with, but it does not guarantee all appearances for an address are present. If the TrueBlocks index has missing entries (due to indexing gaps or incomplete coverage), transactions will be silently missed. A future mitigation is balance reconciliation -- computing the expected balance from fetched transactions and comparing it against the on-chain balance via snap proofs.
- **Signature and access list data not returned.** The succinct JSON omits signature fields (v, r, s), access lists, blob hashes, and the raw transaction bytes; use `eth_getTransactionByHash` (verified JSON-RPC) with the returned `hash` for full detail on recent transactions.

### Dial a specific peer

```bash
./gradlew :app:run -Pargs="dial enode://..."
```

## Helper scripts

Convenience scripts that wrap the Gradle commands and format the output with `jq`:

### `peers.sh`

Lists connected peers in READY state, sorted by snap support and client ID:

```bash
./peers.sh
# Output:
# 1.2.3.4:30303 snap=true Geth/v1.15.0/linux-amd64/go1.23.4
# 5.6.7.8:30303 snap=true Nethermind/v1.30.0/...
```

### `status.sh`

Prints daemon status as JSON:

```bash
./status.sh
# {"ok":true,"state":"RUNNING","uptimeSeconds":120,"discoveredPeers":214,...}
```

### `beacon-status.sh`

Prints beacon light client sync status:

```bash
./beacon-status.sh
```

### `status-gnosis.sh` / `beacon-status-gnosis.sh`

The same two commands sent to the Gnosis daemon (`-Pnetwork=gnosis`).

## Beacon chain light client

The daemon includes a consensus-layer light client that tracks finalized state roots from the beacon chain. This enables trustless verification of account and storage proofs against the canonical chain state.

### Trust model

The only trust anchors are **sync committee BLS signatures** (chained from the embedded checkpoint) and, by design, the embedded historical hash accumulators — the accumulators are not built yet (see [Implementation Status §2](docs/implementation-status.md)), so today every verified answer rests on the sync-committee chain alone. All data from devp2p and libp2p peers is cryptographically verified -- no trusted third-party RPCs or HTTP APIs are used in production (one bounded, documented exception: a seeded log history served on its publisher's word, [docs/seeded-log-histories.md](docs/seeded-log-histories.md)).

The bootstrap trust anchor is a 32-byte mainnet block root hardcoded in `NetworkConfig.MAINNET.checkpointRoot`. Every `LightClientBootstrap` response is rejected unless `hash_tree_root(response.header)` equals this committed value, so the pin is cryptographic: no peer (libp2p or HTTP checkpoint endpoint) can substitute a different anchor, even an internally-consistent one, without finding a SHA-256 preimage.

Ethereum's weak-subjectivity period — how old a trust anchor may be before validators who have since exited could sign a competing "finalized" history (a long-range attack) that a light client cannot distinguish from the real one — is roughly **two weeks** on mainnet at current stake levels (the consensus-spec formula with `SAFETY_DECAY=10` plateaus at 3532 epochs ≈ 15.7 days; Electra's exit-churn cap only lengthens it). It is *not* the ~27-hour sync-committee period, though the two are easy to conflate because `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` happens to be 256 epochs too. What a fresh anchor buys is **attribution, not a slashing penalty**: sync-committee signatures are *not* a slashable offense on any Ethereum chain (bonded or not — the beacon chain slashes only proposer and attester equivocation), so the real protection is that a recent anchor's committee is still held by identifiable, staked validators who would be publicly implicated by a forged signature, and the exit-churn limit caps how fast those keys turn into freely-acquirable, consequence-free ones. So the committed root needs to be refreshed periodically or binaries eventually age past the safety envelope — and refreshing every sync-committee period, as the tasks below encourage, keeps the anchor ~13× fresher than the strict bound requires. The repo ships with a Gradle task that fetches a current finalized root, cross-validates it against multiple independent providers, and rewrites the `@checkpoint:mainnet` region of `NetworkConfig.java`:

```bash
# Preview the diff without writing
./gradlew refreshCheckpoint -Pnetwork=mainnet -Pdry

# Fetch + write (commit the resulting diff — BOTH engines move together)
./gradlew refreshCheckpoint -Pnetwork=mainnet

# All three networks in one run
./gradlew refreshCheckpoint
```

The task queries `/eth/v2/beacon/blocks/finalized` on four independent mainnet endpoints (ethereum-beacon-api.publicnode.com, beaconstate.info, sync-mainnet.beaconcha.in, mainnet-checkpoint-sync.attestant.io) to discover the finalized slot, normalizes to the oldest observed, then asks every responder `/eth/v1/beacon/blocks/{slot}/root` for the canonical block root at that slot and requires byte-for-byte agreement before writing. Agreement is counted per operator (registrable domain), not per URL, so two hostnames of one provider are one voice. Any disagreement aborts without modifying the source.

The same task serves every network — `-Pnetwork=sepolia` and `-Pnetwork=gnosis` refresh the `@checkpoint:sepolia` and `@checkpoint:gnosis` regions, and a bare `./gradlew refreshCheckpoint` does all three. It refuses to write a root fewer than two operators agree on; `-PallowSingleSource` is the explicit opt-out, which Gnosis sometimes needs and the other two do not.

Each run rewrites **both engines** from one fetch — `NetworkConfig.java` and the Rust `ChainConfig` in `rust/myotis-net/src/sync.rs` — because a hand-mirrored anchor is a split anchor waiting to happen. The `java_and_rust_checkpoints_agree` test fails if they ever diverge.

### Weak-subjectivity age bound

Both engines enforce the window above at every **sync start** — cold, and on a warm resume from idle-pause (a pause longer than the bound ages the held committee exactly like a cold snapshot) — re-face it at **every bootstrap attempt** (the poll loop's retry and the fallback after a failed snapshot resume judge the embedded checkpoint, which can be older than the anchor the start-time gate approved), and re-check it **continuously while running**: a node that stays awake but peer-starved (or eclipsed) past the bound parks the same way before catching up, so restart-vs-stay-running never decides whether the gate applies. Before resuming or bootstrapping, the client judges the age of the **best anchor it has** — the embedded checkpoint or the persisted sync snapshot, whichever is newer (when the checkpoint is the newer of the two, the snapshot is discarded and the sync restarts from the checkpoint's period, as it always has). If that anchor is older than the network's bound — **mainnet 13 periods (~14.7 days), sepolia 13, gnosis 3** — the client **refuses to sync** and parks in `STALE_ANCHOR`, failing closed: no bootstrap, no verification, verified queries keep erroring. Nothing is deleted; the client is waiting for a decision:

- **Update the binary / refresh the checkpoint** (`./gradlew refreshCheckpoint`) — the recommended fix; the wallet cannot fetch a fresh anchor itself (devp2p/libp2p only, no trusted RPCs).
- **Raise the bound** — Settings → "Weak-subjectivity bound" in the apps (0 = network default; applied live, a parked chain re-evaluates within a second), or `-Dmyotis.beacon.wsBoundPeriods=N` on the daemon. Raising it weakens the long-range-attack guarantee, knowingly.
- **Accept the risk for this run** — the apps show a dialog explaining the age and the risk ("Sync anyway"); the daemon takes `./gradlew :app:run -Pargs=accept-stale-anchor` (only applies while actually parked), or `-Dmyotis.beacon.acceptStaleAnchor=true` at start for deliberate pre-consent (e.g. re-syncing an archived data dir). Consent is never persisted — a restart with a still-stale anchor parks, and asks, again.
- **Supply a fresher checkpoint yourself** (embedding hosts, Node addon / plain C ABI, ABI ≥ 26) — `createWithCheckpoint(network, freshDir, blockRoot, headerSlot)` bootstraps a fresh directory from a beacon block root the **host** obtained and authenticated through its own channels. This does not add a trust anchor to Myotis: the engine treats the root exactly like the embedded checkpoint — bootstrap pinned to it, every update BLS-verified against the committee chain that follows, snapshot probation, and the same weak-subjectivity gate on the supplied slot's age — and it does not vouch for the root's honesty; the host does, and must say so to its users. The directory is bound to that anchor (`sync-anchor[-net].json`) and resumes only with the same root and slot; the Java engine and plain `create()` refuse it rather than silently swapping anchors. See [rust/myotis-node/README.md](rust/myotis-node/README.md).

Why this exists: the forward walk is only as trustworthy as the anchor it starts from. Past the weak-subjectivity period, an attacker who acquired keys of since-exited committee members could serve a validly-signed forged continuation, and BLS verification alone cannot tell it from the honest chain — so an over-age anchor must be an explicit, informed user decision, never a silent default. Per-network derivations are documented at `NetworkConfig.wsBoundPeriods()`; the Rust mirror lives in the `ChainConfig` constructors and is covered by tests on both sides. The default anchor is head, and that is the one to ship: the gate above refuses an anchor older than the bound, so a release anchored further back parks every fresh install on day one (gnosis's 3-period bound means its anchor stays fresh for only ~34 h after the refresh, so tag promptly — and any gnosis install more than ~2 days after the refresh still starts at the `STALE_ANCHOR` consent dialog; that is the expected gnosis first run, not a broken release). Use `-Pperiod=<n>` to anchor at a chosen sync-committee period instead, or `-Pslot=<n>` to pin an exact slot — for testing a specific retained state on the serving node, such as the oldest bootstrap it can still answer; both require naming the chain with `-Pnetwork` and refuse otherwise, and a pin below the serving node's archive floor is unreachable forever (the archive only grows forward). Historical slots may need a full node, named with `-PextraEndpoint=<url>` and checked against the pinned `genesis_validators_root` before it counts. To test from the oldest anchors roost's serving nodes can still bootstrap, without waiting on (or depending on) any endpoint, `-PanchorFile=rust/testdata/anchors/oldest-servable.properties` writes their recorded roots into both engines with no network access; that file carries the provenance and the caveat that every entry opens on the stale-anchor dialog.

### Verification flow

1. The beacon light client obtains a finalized execution state root (BLS-verified via sync committee signatures)
2. When a snap query returns account/storage data with a Merkle proof, the proof is first verified against the peer's state root
3. The peer's state root is then linked to the beacon-finalized state root via one of:
   - **Direct match** -- the peer's state root matches a known beacon-attested root
   - **Header chain verification** -- block headers are fetched in batches from the beacon-finalized block to the peer's block, verifying: (a) the first header's state root matches the beacon root, (b) consecutive parent hash chain integrity, (c) the last header's state root matches the peer's root

### Verification limitations

Block verification (`get-block`) currently has the following limitations:

- **Pre-merge blocks (before block 15,537,394)** cannot be verified. The beacon chain only exists post-Merge, so there is no sync committee anchor for proof-of-work era blocks.
- **Post-merge blocks more than 8,192 blocks from the finalized block** cannot be verified via header chain. This covers roughly 27 hours of blocks at 12-second slots.
- **Account and storage queries** (`get-account`, `get-storage`) share the 8,192-block header chain limit but are less affected in practice because they query the peer's current state (usually close to head).
**Roadmap:**

- **Pre-merge blocks**: Implement the [pre-merge historical hashes accumulator](https://github.com/ethereum/portal-network-specs/blob/master/history/history-network.md#the-header-accumulator) (EIP-2935). This is a Merkle tree over all ~15.5M pre-merge block hashes, with the root embedded as a static trust anchor. Any pre-merge block hash can be verified with an inclusion proof against this accumulator.
- **Post-merge historical blocks**: Implement the [Bellatrix-era historical roots accumulator](https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md#historical-roots). The beacon chain stores `historical_roots` (batches of 8,192 slots) and `historical_summaries` (post-Capella) that cover all post-merge execution payloads. By walking the beacon state's historical records, any post-merge block hash can be verified without an 8,192-block proximity constraint.

### Sync modes

The light client syncs from the **beacon chain P2P network** (libp2p) -- fully decentralized, using BLS-verified bootstrap and finality updates.

> **Debug only (not for production):** During development, the light client can also seed initial state from a local beacon node's HTTP API (e.g. Lighthouse on `http://localhost:5052`). This is a convenience fallback for debugging and will not be part of a future release. Helper scripts: `scripts/lighthouse.sh`, `scripts/lodestar.sh`.

## Engines: Java and Rust

Myotis ships **two engines** behind one contract: the original **Java engine** and the **Rust engine**, which reimplements the whole verification stack natively and is the primary engine — the default selection, and ahead of the Java engine on features (the eth_getLogs **log index** and Tor verified-read routing run on the Rust engine only). Both are interchangeable per network at (re)start:

- **The contract** is `:myotis-api` — zero-dependency Java-17 interfaces (`MyotisEngine`/`ChainHandle`, FFI-portable types only). Hosts (Android app, desktop app, daemon) consume *only* this API and never import engine internals.
- **The Java engine** is the original implementation (`node-core` adapters over the `networking`/`consensus`/`myotis-evm` modules).
- **The Rust engine** is the `rust/` Cargo workspace (`myotis-core`, `myotis-wire`, `myotis-net`, `myotis-consensus`, `myotis-bls`, `myotis-evm`, `myotis-engine`): discv4 + discv5 discovery, RLPx/eth/snap, the beacon light client with BLS via blst, a revm-based EVM with the same snap-proof state oracle, ENS incl. CCIP-Read, and multichain (mainnet, Sepolia, Gnosis). It reaches the JVM through UniFFI-generated Kotlin bindings over JNA (the generated bindings are committed in `:myotis-engines`, regenerated via `uniffiGenerateKotlin`); compound values cross as JSON, pinned by golden tests on both sides. The same engine's plain C ABI also serves the two non-JVM hosts: the iOS app (Kotlin/Native cinterop) and the Node.js addon (`rust/myotis-node`, napi-rs) — identical JSON shapes, pinned by the same golden tests.
- **Selection**: the `:myotis-engines` selector (`Engines.engine()`) routes each network to an engine via the `myotis.engine` property — `auto` (default: the Rust engine where it can serve, Java fallback otherwise), `java`, or `rust` (hard — error when unavailable). On run tasks use `-Pengine=java` to opt out; in the apps it's the "Prefer Java engine" Settings toggle (applies on network restart). **Android below API 33 (Android 13) is Rust-only**: the Java engine's EVM (Besu's `UInt256`) and its discv5 (Guava futures) use `VarHandle` APIs that Android 10–12 keep hidden, so the app forces `rust` there with no Java fallback, and Settings explains this instead of offering the toggle. The Status screen shows which engine hosts each network — "Mainnet (r)" vs "(j)".
- **Parity** is enforced by shared conformance vectors (BLS fixtures, a captured mainnet light-client corpus, the EL verification-ladder vectors) run against both implementations, plus a benchmark gate for the JNI path.

**rustc/cargo are NOT required to build or run the JVM hosts (daemon + desktop).**
That build is pure Java/Kotlin end to end: the UniFFI-generated Kotlin bindings are
committed source (no bindgen step for a JVM-host build), JNA comes from Maven Central
like any other dependency, and every `cargo*` Gradle task self-skips with a single
note when cargo is missing. On a cargo-less machine the JVM hosts' engine selector
simply reports the Rust engine as unavailable and the default `auto` selection
falls back to the Java engine — there is nothing to configure or disable. The
**Android app** is the exception: it builds the Rust engine from source by default
(cargo + cargo-ndk + NDK + the Android rustup targets; its `preBuild` runs
`cargoNdkAndroid` and regenerates the bindings). There is no committed `.so`, so
nothing can drift; a missing toolchain fails the build with a message pointing at
`-PskipRustEngine`, which builds the app without the Rust engine (Java engine at
runtime, so such a build can only start networks on Android 13 / API 33 and newer). The packaged **desktop installers** also need cargo
(`packageDmg`/`packageDeb`/`runDistributable` fail loudly without it, so an
installed app can always switch engines).
Release artifacts don't rely on committed binaries — CI builds the Rust engine
from source for the APK and the packaged desktop apps.

To actually build the Rust engine and bundle it, per target:

| Target | Requirements |
|---|---|
| Desktop dev loop + packaged installers (`packageDmg`/`packageDeb`) | rustc/cargo **stable**, at least the workspace `rust-version` in `rust/Cargo.toml` (the dependency graph sets it; `rust-toolchain.toml` tracks stable, and the Gradle probe reads that line and skips anything older). Builds the host triple; the x64 dmg CI leg additionally passes `-PrustTarget=x86_64-apple-darwin` under Rosetta. |
| Android jniLibs (`cargoNdkAndroid`) | The same rustc/cargo, plus `rustup target add aarch64-linux-android x86_64-linux-android`, `cargo install cargo-ndk`, and an Android **NDK r28+** (16 KB-aligned LOAD segments for Android 15+; older NDKs work because `.cargo/config.toml` forces the alignment, and the build fails loudly if it slips). Found via `$ANDROID_NDK_HOME` or the newest `<sdk>/ndk/<version>`. |
| iOS framework (`:app-ios`) | macOS with **Xcode 26+** and `rustup target add --toolchain stable aarch64-apple-ios aarch64-apple-ios-sim`. Without them the framework tasks disable themselves with a warning (a previously built `libmyotis_engine.a` also satisfies them). |
| Regenerating the committed Kotlin bindings (`uniffiGenerateKotlin`) | Just rustc/cargo — the pinned `rust/uniffi-bindgen` CLI builds from the workspace. Re-run after any `ffi.rs` shape change. |

```bash
./gradlew cargoBuildHost       # cargo build --release (auto-runs before :app:run / :consensus:test)
./gradlew cargoTest            # cargo test --workspace (part of `check`)
./gradlew cargoNdkAndroid      # Android jniLibs (needs cargo-ndk + NDK)
./gradlew uniffiGenerateKotlin # regenerate the committed Kotlin bindings after ffi.rs changes
./gradlew :app:run -Pengine=rust          # daemon on the Rust engine (hard; default auto)
./gradlew :app-desktop:run -Pengine=java  # desktop GUI forced onto the Java engine
```

## Log index: verified eth_getLogs

The **log index** is an opt-in, per-network index of the event logs of contracts *you choose*
— every log verified against receipt roots on the devp2p network (no RPC provider), backfilled
to each contract's deployment block, then kept current at the head. Queries outside what the
index has covered are refused with an error, never answered with a misleading `[]`.
**Rust engine only** (the default `auto` selection serves it; forcing the Java engine gives it up).

### Create an index in the app

Open the **Index** tab (desktop, Android, iOS), enter each contract's address and the block
to index back to — its deployment block; when unsure, choose an *earlier* block: later
silently hides the earlier events, earlier merely walks further — then flip **Collect logs**
on. The backfill runs in the background ("Max download speed" trades battery/bandwidth for
speed) and the tab shows per-contract progress. Display names resolve automatically via
verified reverse-ENS where a name exists.

### Create a portable index with the daemon

For a big backfill (months of history), build the index once on a machine that can run
around the clock, then hand the file to the apps:

```bash
# 1. Start the daemon on the target network (the Rust engine serves the index).
./gradlew :app:run -Pnetwork=gnosis

# 2. Tell it what to index: one or more addresses, and how far back.
./gradlew :app:run -Pnetwork=gnosis -Pargs="build-logindex 0x45a1502382541cd610cc9068e88727426b696293 --from 31305656"

# 3. Watch the backfill (cursor walks DOWN to the target; maxSpeed is on for build-logindex).
./gradlew :app:run -Pnetwork=gnosis -Pargs=logindex-status

# 4. When blocksRemaining reads 0 (equivalently: every watched entry's
#    coverage has reached its own from_block — backfillCursor itself can stop
#    short of the target once one entry finishes before another): export a
#    portable snapshot.
./gradlew :app:run -Pnetwork=gnosis -Pargs="export-logindex /tmp/my-index.db"
```

The exported `.db` is **self-describing and chain-tagged** (network id + genesis hash), so it
can only be imported into a node on the same chain. Import it via the Index tab's (Settings → Expert mode shows the tab)
"Import log-index snapshot…" button — the receiving node merges it with whatever it already
holds and immediately starts catch-up for every imported address, so the file does not need
to be fresh. One bound: the head-gap bridge spans at most **500,000 blocks** (~29 days on
Gnosis, ~10 weeks on mainnet), so import a snapshot within that window of its export — or
re-export a fresh one, which costs seconds on a node whose index is current.

Display names are deliberately NOT part of the file: the importing wallet resolves them
itself (verified reverse-ENS), so a generated file cannot lie about who a contract is.


## Architecture

Key Gradle modules (plus the `rust/` Cargo workspace):

- **myotis-api** -- the engine contract: zero-dependency interfaces every host consumes exclusively
- **myotis-engines** -- the engine selector (`Engines.engine()`; `myotis.engine=java|rust|auto`) routing to the Java engine or the Rust one over UniFFI + JNA
- **node-core** -- the Java engine's adapters (`JavaMyotisEngine`/`JavaChainHandle`) plus the verification ladder over the modules below
- **core** -- cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** -- protocol layers, all Netty-based:
  - `discv4` -- UDP peer discovery (ping/pong/findnode/neighbors)
  - `discv5` -- UDP CL peer discovery (wraps ConsenSys' `io.consensys.protocols:discovery`, consumed as the `com.github.biafra23:discovery` Android fork so it runs at minSdk 29 -- see `gradle/libs.versions.toml`)
  - `rlpx` -- TCP transport with EIP-8 ECIES handshake and AES-256-CTR framed channel
  - `eth` -- eth/66-69 sub-protocol (hello, status, block headers/bodies, receipts, transaction gossip)
  - `snap` -- snap sub-protocol, snap/1 and snap/2 / EIP-8189 (account range, storage range, bytecode, with Merkle proofs; the two versions share those messages, and a connection runs the highest one both sides offer)
- **consensus** -- beacon chain light client (sync committee BLS verification), Merkle-Patricia proof verification
- **myotis-evm** -- Hyperledger Besu EVM running against a SNAP-backed `StateOracle`. Powers ENS resolution, `eth_call`, and local gas estimation (`DefaultEvmExecutor.estimateGas` — geth's search for the lowest gas limit that succeeds, + 15% safety buffer). Includes `CcipReadEvmExecutor` for ERC-3668 off-chain lookups and `PrefetchingEvmExecutor` (multi-hop speculative prefetch) to amortize SNAP round-trips.
- **myotis-ens** -- the Java engine's ENS resolver (`EnsResolver`, `ReverseLookup`): discovers each name's resolver through the Registry (ENSIP-10 walk) and calls it directly in the local EVM. Forward and reverse resolution, every record type, ENSIP-10 wildcards, ERC-3668 off-chain records. (The Rust engine has its own equivalent in `rust/myotis-net/src/el`.)
- **jsonrpc-server** -- host-agnostic verified JSON-RPC router (Kotlin Multiplatform/Ktor). `RpcRouter` maps the Ethereum API onto this module's `RpcBackend` seam — implemented on the JVM by `VerifiedReadsBackend` over the `io.myotis.api.VerifiedReads` contract, and on iOS by `:app-ios`'s `IosRpcBackend`. Strict permissionless mode by default; binds loopback only. (Consumed by the Android, iOS, and desktop apps and the daemon — which additionally has its CLI/IPC command surface.)
- **rpc-backend** -- the verified RPC backend (`VerifiedRpcBackend`): anchored-head building, serve-stale policy, and the readiness probe (`verifiedHeadAgeMs`) shared by the JSON-RPC server and the hosts
- **ui** -- shared Compose Multiplatform `NodeScreen` (the readiness strip, the Status, Query and Settings tabs, and the Logs and Index tabs of Expert mode) used by the Android, desktop, and iOS apps
- **app** -- daemon/CLI entry point, Unix domain socket IPC server, peer caching
- **app-desktop** -- the Compose desktop GUI over `:ui`, packaged with jpackage (dmg/deb), bundling the Rust engine
- **app-ios** -- the iOS host: a Kotlin/Native framework (`MyotisKit`) bundling `:ui` with iOS seam actuals over the Rust engine's plain C ABI; the Xcode shell lives in `ios-app/` (the JVM engine never runs on iOS)
- **android-app** -- the Android wallet node (`NodeService` foreground service). Runs the full devp2p + libp2p stack, the local EVM, and the JSON-RPC server on-device, with Android-native peer/snapshot caching and a Compose UI; persists the sync snapshot, the known-state-root window, and light-client-capable peers for fast warm restarts (~10 s vs. a cold checkpoint bootstrap).
- **rust/myotis-node** (Cargo, not Gradle) -- the Node.js (napi-rs) addon over the engine's C ABI, for Electron/Node hosts — the embedding the Freedom browser's experimental Myotis tier consumes
- **rust/myotis-wire** (Cargo, not Gradle) -- the execution-layer wire protocols (discv4 codec, RLPx, eth/snap messages, snap proof verification) and, behind its `eth2` feature, the consensus req/resp codec, without an async runtime: `no_std` + `alloc` without the `std` feature, for hosts with their own event loop (UEFI firmware, wasm). `myotis-net` re-exports it at the old paths
- **rust/myotis-rpcd** (Cargo, not Gradle) -- a standalone JSON-RPC daemon over the Rust engine's verified reads, for hosts that can't or won't run the JVM (servers, containers, a Bee node's RPC endpoint) — see [rust/myotis-rpcd/README.md](rust/myotis-rpcd/README.md)

### Protocol flow

```
DiscV4Service (UDP)
  discovers peers
    --> RLPxConnector.connect() (TCP)
      --> ECIES handshake (HANDSHAKE_WRITE -> HANDSHAKE_READ -> FRAMED)
        --> EthHandler (AWAITING_HELLO -> AWAITING_STATUS -> READY)
          --> block headers, account/storage queries available
```

### Peer seeding

On the **Java engine**, both discv4 (EL) and libp2p (CL) get their initial peer lists from three sources, merged at startup:

1. **Hardcoded fallback** in `NetworkConfig` — a handful of IPv4 bootnodes and CL multiaddrs that ship with the binary.
2. **On-disk cache** (`PeerCache`, `CLPeerCache`) — peers that responded successfully on a prior run. The daemon writes `peers[-<network>].cache` / `cl-peers[-<network>].cache` (plus `sync-state[-<network>].snapshot`) into its working directory; the Android app keeps the same files in the app's cache dir (`getCacheDir()`).
3. **EIP-1459 DNS-based ENR trees** — each network can list `enrtree://<base32-pubkey>@<domain>` URLs in `NetworkConfig.elEnrTreeUrls` / `clEnrTreeUrls`. At startup the daemon walks each tree over DNS TXT records, verifies the root record's secp256k1 signature against the embedded pubkey, and decodes the leaf ENRs. Results are merged into the EL bootnode list and the CL peer list. Mainnet currently pins the Ethereum Foundation canonical tree (`all.mainnet.ethdisco.net`); the resolver is implemented in `networking/dns/DnsEnrResolver`.

DNS resolution is best-effort: on timeout, missing TXT records, or signature mismatch the daemon logs a warning and starts up with whatever the hardcoded + cached sources provide. Per-tree deadline defaults to 10 s.

The **Rust engine** seeds from the same hardcoded bootnodes / CL pins and the same on-disk caches (byte-identical formats, so switching engines keeps them), plus discv4/discv5 and, for the EL, any `enode://` seed pins a host hands it (`myotis_set_boot_enodes`, ABI ≥ 31). Since #539 it walks the same EIP-1459 EL trees too (`rust/myotis-net/src/el/dnsdisco.rs`) — but only on hosts that allow DNS (`myotis_set_dns_discovery`, ABI ≥ 39: the desktop app, the daemon and `myotis-rpcd`, through the system resolver; not Android or iOS, until the engine takes a host's DNS servers, and not yet the Node addon) and never while Tor is enabled. Its walk also checks that every record hashes to its DNS label and verifies each leaf's signature, and the leaves pass the same fork-id filter as discv4's candidates before the pool dials them. Where DNS is off — mobile, Tor — a stale bootnode list still never seeds EL discovery on a fresh mainnet profile (no pinned enodes), which is why the release checklist re-syncs the bootnodes from go-ethereum (CLAUDE.md §Releases).

### Key dependencies

- **Tuweni 2.7.2** (upstream, `io.consensys.tuweni` on Maven Central) -- RLP encoding, SECP256K1, byte utilities
- **Netty 4.2.x** (upstream) -- NIO transport. (The earlier Kotlin-transpiled tuweni/netty forks existed to explore a Kotlin-Multiplatform engine; multiplatform now comes from the Rust engine, so the forks were retired.)
- **BouncyCastle** -- SECP256K1 crypto provider
- **jvm-libp2p** -- beacon chain P2P networking (consensus module)
- **dnsjava 3.6** -- TXT-record resolution for EIP-1459 ENR tree walks (Java engine; the Rust engine uses `hickory-resolver`, already part of its libp2p stack)

## License

Myotis is licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Dirk Jäckel.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in Myotis shall be licensed under Apache 2.0 as
above, without any additional terms or conditions.
