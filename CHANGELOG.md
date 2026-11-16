# Changelog

Every release of Myotis, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Each release's installers, engine
libraries and checksums are on its
[GitHub release](https://github.com/biafra23/myotis/releases); every release so
far is a pre-release. The release PR adds its entry here
(`.claude/agent/releases.md`, step 6); numbers in parentheses are pull requests
and issues of this repository.

A release candidate's entry lists what it adds over the release before it; the
final release lists only what came after its last candidate. The **engine ABI**
is the number an embedder gates on (`init()` in the Node addon,
`myotis_init()` over the C ABI): from 0.1.3 on, each entry names the one it
ships when it moved. The entries up to 0.1.20 were written after the fact from the GitHub
release notes; those notes stay the full record of each release, including
its trust anchors and release checks.

## [Unreleased]

### Added

- Docs: verifying deep blocks, an analysis of reads beyond the 512-block
  window with a measured survey of which peers still serve old blocks
  (#882).

### Fixed

- `scripts/verify_release.sh` resolves the commit of a release tag again.
  Its copy in v0.1.21-rc1 stops at the attestation step with HTTP 422
  ("No commit found for SHA: tags/…"); use the one on `main` (#878).

## [0.1.21-rc1] - 2026-11-15

### Added

- Stale anchor: at a `STALE_ANCHOR` park, the user can re-anchor on a fresh
  checkpoint that every answering checkpoint-sync server names and a
  long-known peer confirms; the choice can be remembered and is applied
  headless. New in `:myotis-api` and on the iOS `ChainHandle`:
  `refreshAnchorFromCheckpointz`, `setStaleAnchorPolicy`, `AnchorRefresh`,
  `StaleAnchorPolicy` (#761).
- The Go engine: a minimal Myotis engine in Go with discovery, RLPx + eth, the
  light client and snap reads (#773), on go-ethereum v1.16.9, where a crafted
  discovery reply can no longer panic the host process (#838). No release
  carried the Go engine before this one.
- Log index: predefined contracts (RAILGUN, Swarm, Privacy Pools, Tornado
  Cash) with download and disk estimates, downloaded on unmetered networks
  only by default (#753).
- `myotis-rpcd`: a command-line switch for every P2P port (#775).
- Reproducible builds: every Gradle dependency pinned by version and hash, a
  pinned builder image, and the `reproducible builds`, `verify release` and
  `release rehearsal` workflows (#734, #771); the Go engine joins the Linux
  gate (#813).
- `eez_probe`, a compatibility probe for a foreign-chain snap peer (#768).
- Docs: Scaffold-ETH 2 dApps on Myotis (#735); the Myotis Rust Tour (#738);
  `SECURITY.md`, how to report a vulnerability privately (#870).
- This changelog.

### Changed

- Rust engine: each address gets its own snap peers. Account, storage,
  `eth_getProof` and address-keyed `eth_call` / `eth_estimateGas` reads rank
  the peers in each health tier by a salted per-address hash, so a wallet's
  addresses are spread over its peers instead of all leading with the same
  one (#863, biafra23/punicus#253; limits, such as a cold start, in
  docs/how-it-works/privacy-and-tor.md).
- Log index: backfill batches are fetched from several peers at once (#743).
- Build: AGP 9.5.1, Kotlin 2.4.21, Compose Multiplatform 1.12.2 and
  compileSdk 37 (#837, #808); Gradle 9.9.0 (#814).
- Rust: the minimum version is 1.92 (#860). Tor runs on Arti 0.48 (#860,
  #867).
- One netty, one BouncyCastle and Ktor 3.6 across the build (#864).
- Engine ABI 59 (0.1.20 shipped 55).

### Fixed

- `myotis-node`: a use-after-free at teardown (#455, #852).
- The loopback JSON-RPC server of the Android app, the desktop app and the
  daemon read a request body whole, so one oversized request could exhaust
  the memory of the app hosting the node. A body is now capped at 5 MiB (413)
  and must arrive within 10 s (408), the limits `myotis-rpcd` already had.
  Any local process (on Android, any app with network access) or a web origin
  the user allowed could send it (#667, #852).
- The light client could rotate its sync committee twice after a catch-up
  force-rotation and then refuse updates signed in the real period; fixed in
  the Java, Rust and Go engines (#737, #852).
- `myotis-rpcd` exits non-zero when its listener thread dies, so a supervisor
  restarts it (#737, #852).
- A result that arrives on the same poll as a late cancellation is returned,
  not reported as a failure (#737, #852).
- myotis-evm: a verified account is banked before its read completes, so a
  read right after it no longer re-proves it from a peer (#849).
- A missing entropy source fails the RLPx dial, not the process (#826).

### Security

- Tor mode on a host without OS entropy (early boot, a seccomp sandbox): the
  Tor reserve's fill salt and per-read seed fell back to zeros, which made the
  order of Tor peers computable. The Tor path now fails closed instead (#823,
  #829).
- hickory-resolver 0.26.3, for its 0.26.2 security release (DNS response
  parsing panics, UDP spoofing, resource exhaustion). It is used by the
  EIP-1459 DNS walk on desktop, the daemon and `myotis-rpcd`, not on Android
  or iOS. Also rustls 0.23.46, and libp2p is built without its DNS transport
  (#806).

## [0.1.20] - 2026-11-07

Everything in 0.1.20-rc1, and:

### Added

- Chiado, the Gnosis testnet (chain id 10200), on both engines (#724).
- `eth_simulateV1`: blocks of calls over proof-served state, as geth
  simulates them (#716, #723).
- `snap_probe`, a snap/1 census example for Bor, Scroll and Mantle peers
  (#729).

### Changed

- CL transport: QUIC first, in the spec's order, and QUIC-only peers are
  dialable (#731).
- Rust engine: the EL reconnects faster after an idle-pause wake (#728).
- Engine ABI 55.

## [0.1.20-rc1] - 2026-11-04

### Added

- Rust engine: watched accounts are answered from verified block-access-list
  post-values (#685, #711).
- JSON-RPC: the polled filter family over the log index (#714, #718);
  `eth_blobBaseFee`, `eth_getAccount` and `eth_getRawTransaction*` (#715,
  #719); `debug_traceCall` with geth's callTracer and prestateTracer (#716,
  #721).
- Docs: Myotis headless on Linux as Swarm Bee's RPC node (#709).

### Changed

- Engine ABI 54.

## [0.1.19] - 2026-11-01

Everything in 0.1.19-rc1 and 0.1.19-rc2, with fresh trust checkpoints and
PoC seeds (#706).

## [0.1.19-rc2] - 2026-10-22

### Changed

- A proof names its block's hash (#701). Engine ABI 52.

## [0.1.19-rc1] - 2026-10-22

### Added

- Address activity: which watched addresses each verified block touched, from
  the logs bloom and from block access lists over snap/2 (#691, #692, #693,
  #695).
- eth/70 and eth/71 on the Rust engine, with block access lists from every
  geth peer and a BAL server kept in the pool (#694).

### Changed

- The cold-start checks run the EL reader, so they can pass on Gloas chains
  (#690).
- Engine ABI 51.

## [0.1.18] - 2026-10-20

### Added

- Each network's data usage is counted and reported on the status call
  (#686).
- iOS engine library: the log index in the typed API (#687).

### Changed

- One source for the release notes, with a self-repairing section append
  (#684).
- Engine ABI 50.

## [0.1.17] - 2026-10-20

### Added

- The iOS engine library, `eth.myotis:myotis-engine-ios`, with a typed Kotlin
  API over the Rust engine's C ABI (#678, #680, #681).
- The engine's desktop host library as per-platform natives jars (#674).
- Log index: watch a topic value from any emitter (#673, #675).
- ENSv2, part 1: reverse resolution finds primary names without their own
  resolver, and refuses ownership where ENSv2 decides (#671, #672). A reverse
  claim whose address record is off chain is verified over CCIP (#677).

### Changed

- Engine ABI 49.

### Fixed

- `optimisticSlot` reports the head block's own slot, not the signature slot
  (#658, #660).
- `eth_call` / `eth_estimateGas` serve `BLOCKHASH` from verified data (#664,
  #669).
- `eth_sendRawTransaction` refuses a transaction signed for another chain
  (#665, #668).

## [0.1.16] - 2026-10-15

### Added

- Myotis as an engine library: the Android AAR and the desktop jar of the
  Rust engine, published as `io.myotis` Maven artifacts with default ports
  (#644 to #648, #654).
- `eth_getProof` (EIP-1186) on the Rust engine, pinned to attested roots
  (#637, #651).
- ERC-20 token balances in the query result, with a token list in Settings
  (#639).
- The Watch tab: a verified native and ERC-20 balance watch with change
  notifications (#640).
- Genome `.gno` names on Gnosis Chain, on both engines (#650).
- State reads and `eth_call` accept a block hash inside the verified window
  (#643, #649).
- A Windows `.msi` of the desktop app, built and smoke-tested in CI (not yet
  published) (#630, #633).
- `scripts/refresh_poc_seeds.py`: the PoC seeds are refreshed incrementally
  for every release (#634).

### Changed

- Engine ABI 47.

## [0.1.15] - 2026-10-12

### Security

- A single malicious peer could forge verified account and storage reads. The
  `headerChain` check walked the header chain upward from the finalized block,
  which pins nothing above it; both engines now walk down from an attested
  block (#611). Affected: the Java engine in every earlier release; the Rust
  engine in every earlier release that carried it, on every read up to 0.1.6
  and, since 0.1.7, when a peer claimed it could not serve the attested root;
  Rust Tor account reads since 0.1.3.
- The Java engine's `get-storage` / `get-account` report only what the proof
  proves (#626).

### Added

- A release-signed Android app, `Myotis-v<version>-android.apk`, next to a
  separate debug app (#618, #627). An earlier, debug-signed install has to be
  uninstalled first.
- A new home screen: normal mode (Status, Query, Settings) and Expert mode
  (Logs, Index, node tuning) (#593 to #597); peer rows grouped by layer
  (#586).
- Query tab: decoded ENS contenthash and profile records (#603), ENS ownership
  (#607), the chain's native currency (#601), block numbers with their
  verified age (#602).
- Tor on Android behind `-PtorEngine` (#609); in Tor mode the wallet's
  transactions are broadcast over Tor and every Tor read and send is logged
  (#612); a persisted Tor reserve (#615).
- An operator policy gates which web pages may use the JSON-RPC, and sites can
  be allowed from the app (#502, #605); a refused page is announced on
  Android, desktop and macOS (#608, #610, #613).
- `eth_createAccessList` on the Rust engine (#599).
- EL discovery: re-dialing when peers are scarce, the ENR fork-id filter and
  EIP-1459 DNS trees on desktop and the daemon (#539, #567).
- The Rust engine speaks mplex and QUIC, and both engines answer what a
  post-Fulu Nimbus asks of a peer (#588).
- `myotis-rpcd --boot-enodes` (#575); Logs tab Copy and Save… (#600); a
  user-facing website (#614, #620); a verification walkthrough (#624).

### Changed

- `eth_sendRawTransaction` relays only a transaction and refuses anything else
  with `-32602`, on both engines and every host (#616, #621).
- The light client polls finality a third of the way into each slot (#617).
- Android: the log index catches up while charging on an unmetered network
  (#574), and the node sleeps while charging otherwise (#619).
- Sepolia pins are roost-led with zbox's Nimbus second (#573, #581).
- Engine ABI 45.

### Fixed

- Rust `eth_feeHistory` accepts Amsterdam gas accounting (#578).
- A burst past the EVM slot cap waits for a slot instead of failing (#577).

## [0.1.14] - 2026-10-06

### Added

- Fork watch on every network from consensus-layer signals: discv5 ENR `eth2`
  fields and peers' Status fork digests (#561).
- snap/2 (EIP-8189) next to snap/1 on both engines (#554).
- `myotis-rpcd`, a standalone JSON-RPC daemon over the Rust engine (#542).
- Log index: Remove on the Index tab unsubscribes the contract (#550).

### Changed

- Log index: receipts are fetched first, and the body only for a block with a
  watched log (#549).
- The mainnet and Sepolia discv4 bootnodes follow go-ethereum's NodeOps fleet
  (#555).
- Engine ABI 38.

### Fixed

- Sepolia kept syncing only until Glamsterdam: a verified update that moves
  nothing no longer wins a finality round over a current one, on both engines
  (#562). A fresh Sepolia install depends on roost alone until a second
  Gloas-capable light-client server exists (#566).

## [0.1.13] - 2026-10-03

### Added

- Sepolia Glamsterdam on both engines: the fork schedule, the Gloas light
  client (EIP-7732) and, on the Rust engine, the Amsterdam EVM. The Java
  engine refuses post-fork calls with `-32602` instead of guessing (#491,
  #501).
- The Status screen guide, with in-app help (#507, #508).
- The RAILGUN PoC bundles a Sepolia seed beside mainnet's (#530).
- `myotis-core` builds `no_std` + `alloc` for firmware targets (#487).
- Node/Electron hosts get the remaining verified reads (#503, #538).

### Changed

- `eth_call` applies the whole transaction object, and `eth_estimateGas`
  searches for the lowest gas limit that works (#509, #514, #523, #524).
- Every JSON-RPC parameter is applied or refused, never silently ignored
  (#316, #366, #533).
- Sending refuses a transaction that can never be mined (#531, #537).
- Log index: completeness is tracked per watched entry (#506); catching up to
  the head shows in the top bar (#529).
- The Java engine's SYNCED requires a finality from the last five epochs
  (#490).
- The minimum Rust version is 1.91 (#511).
- Engine ABI 36.

### Fixed

- Fee reads no longer stall a polling wallet (#532, #512, #535), reads stop
  waiting out a silent peer (#320, #534), and `eth_call` and
  `eth_estimateGas` read their state in parallel (#536).
- CCIP-Read gateways get one deadline per request (#528).

### Security

- devp2p frames and responses are read in place and bounded by what was asked
  for; a crafted 10 MiB frame used to cost hundreds of MB (#454, #495, #515,
  #517).

## [0.1.12] - 2026-09-24

### Added

- A RAILGUN PoC desktop flavour beside the Bee one (#477).
- The EL knows each peer's head and admits, ranks and strikes by it (#465,
  #480); hosts see the serving snap peers, readiness is gated on them, and
  hosts can supply EL seed pins (#482, #483).

### Changed

- By-number windows are anchored at the finalized block, and the `finalized`
  tag is honoured (#481, #483).
- Every dmg and deb release asset carries the version in its name (#476).
- Engine ABI 32.

## [0.1.11] - 2026-09-21

### Added

- Hedged verified reads: block, receipt and `eth_call` state reads race a
  second peer after 3 s near the head, and peers that keep losing are evicted
  (#457).
- `read-stats`, a shadow cache that measures what a state-read cache would
  save (#466).
- An off switch for the log-index backfill in the daemon and the apps, off by
  default in the Bee PoC (#468, #471).

### Changed

- `eth_call` enforces its `block` argument: outside the head window it is
  refused, never answered from the head (#452, #456).
- The Status tab's maintenance actions are offered only while the network is
  stopped (#451).
- Engine ABI 29.

### Fixed

- Log index: a stalled appender hands its gap to the bridge, the backfill
  yields to head-follow, and checkpointed coverage survives a restart (#450,
  #458, #460, #469, #474).

### Security

- `myotis_eth_call_json` refuses a NULL `to`, which a plain-C host could pass
  to have its calldata run as init code (#470).

## [0.1.10] - 2026-09-16

### Added

- The Bee PoC desktop flavour: a separate app that a Swarm Bee full node can
  use as its Gnosis RPC from the first minute, with a bundled PostageStamp
  log-index seed and warm peer caches (#443, #444, #445).
- `myotis-node`: a caller-supplied checkpoint bootstrap (#441, #442).

### Changed

- `refreshCheckpoint` records the oldest-servable test anchors (#439).
- Engine ABI 26.

### Fixed

- The desktop app opts out of macOS App Nap, which had made the localhost RPC
  accept connections seconds late (#445).

## [0.1.9] - 2026-09-13

### Fixed

- Cold starts catch up again (#422): both engines speak gossipsub so
  Lighthouse stops banning the wallet (#425), Lighthouse is asked for one
  period per request (#424), discovery feeds the sync pool from every peer it
  hears about (#427), and catch-up is pipelined across peers (#431).
- A next-period signature is verified with the next sync committee (#423,
  #429), and each update under the fork active at its signature slot (#295,
  #430).
- Concurrent light-client requests can no longer complete the wrong caller
  (#438).
- Verified reads are held only while a node is waking up (#312, #432).

### Changed

- Android 10 to 12 (API 29 to 32) runs the Rust engine only (#433).
- The Sepolia, mainnet and Gnosis light-client pins follow a two-vantage
  census (#426, #437).
- Cold-start regression checks run before every release (#434).

## [0.1.8] - 2026-09-10

### Added

- The weak-subjectivity anchor-age gate on every engine (#383).
- `myotis_pause` / `myotis_wakeup` JSON-RPC lifecycle methods (#381).
- `MyotisEngine.xcframework` and `MyotisKit.xcframework` as release assets
  (#373, #377).
- Log index: generic builds, portable snapshots and import everywhere (#369).

### Changed

- The Rust engine is primary, and the log index is generic (#384).
- The app runs at minSdk 29, gated by a post-desugaring dex check and a
  minSdk-29 emulator boot in CI (#397, #398, #403).
- A reverting `eth_call` or `eth_estimateGas` answers code 3 with the revert
  data (#363, #364).
- Verified-read failure reasons reach the caller (#412); read-failing snap
  peers are rotated away and evicted (#413, #417).
- The mainnet discv4 bootnodes match go-ethereum (#414).
- Engine ABI 25.

## [0.1.7] - 2026-08-12

### Added

- Targeted discv5 lookups toward the pinned servers on the Java engine (#351).
- An on-demand log-index tail fill for head-edge `eth_getLogs` (#354).

### Fixed

- Snap queries take their roots from the beacon anchor, not stale handshake
  heads (#355, #356).
- RLPx: every Nethermind peer rejected the first frame (#291, #361).

## [0.1.6] - 2026-08-10

### Added

- roost, a dedicated light-client server for all three networks, pinned as
  Sepolia's first CL peer (#327 to #337, #345, #348).
- One `refreshCheckpoint` task for all three networks, writing both engines
  (#340, #341, #343).
- The release is refused when the pushed `v*` tag disagrees with the tree's
  version (#308).

### Changed

- Android builds the Rust engine from source by default (#324).

### Fixed

- The EL pool always re-dials pinned boot enodes (#321).

## [0.1.5] - 2026-08-08

### Added

- `eth_call` state overrides and the contract-creation form (#315, #318,
  #319).
- The build's version under the app name (#309).

### Fixed

- Android: the Rust engine was missing JNA from the APK (#307).
- The log index bridges the head gap and follows the optimistic tail (#306).
- CL sync: the no-light-client verdict is reversible, and pinned peers are
  never evicted (#291, #322).

## [0.1.4] - 2026-08-07

### Added

- Header backfill on both engines, and Rust genesis seeding, so serving
  blocks to peers is real (#285).
- Log index: a backfill speed setting with progress and ETA (#293).

### Changed

- Gnosis catch-up: 23 LC-serving peers pinned (#302).
- Engine ABI 22.

### Fixed

- eth/69 `BlockRangeUpdate` is sent at wire code 0x21 (#287).

## [0.1.3] - 2026-08-03

### Added

- `eth_getLogs` over a verified watch-list log index on the Rust engine
  (#269 to #272, #275).
- Rust engine: verified `eth_getTransactionReceipt`, `eth_getTransactionByHash`,
  `eth_getBlockByHash`, `eth_feeHistory`, `eth_getBlockReceipts` and full
  transaction blocks (#234, #237, #242, #247, #248), with 12 more JSON-RPC
  methods at the router (#249).
- The iOS target, the shared Compose UI over the Rust engine (#235, #244).
- `myotis-node`, the napi-rs Node.js binding over the C ABI, with prebuilt
  release assets (#261, #262, #282).
- Privacy & Tor: a PoC with a desktop opt-in on the Rust engine (#268).
- Rust engine: real idle sleep on Android (#231); LC and EL hunt modes when
  starved of peers (#230, #233).
- TrueBlocks transaction history (debug only) (#258, #259).
- The Apache 2.0 license (#263).

### Changed

- The Rust engine moved from hand-written JNI to UniFFI bindings (#264).
- Engine ABI 21.
- Back to upstream Tuweni 2.7.2 and Netty 4.2.10 (#227).

## [0.1.2] - 2026-07-12

### Fixed

- Desktop settings persist across restarts (#220).
- eth/69 advertises an honest served-block range (#221).

## [0.1.1] - 2026-07-11

### Added

- The Rust engine behind the `:myotis-engines` selector: CL light client,
  discv4/discv5, RLPx, eth/66-69, snap/1, verified reads, the revm EVM, ENS
  and CCIP-Read, on mainnet, Sepolia and Gnosis (#124 to #206).
- Sepolia (#192, #197) and Gnosis Chain (#198) on the Rust engine.
- Idle sleep with wake-on-RPC (#161, #177).
- A Linux `.deb` of the desktop app (#126), and the Rust engine bundled in the
  packaged desktop apps (#212).
- The Osaka (Fusaka) EVM on both engines, with Besu 26.4.0 (#208, #209).

## [0.1.0] - 2026-07-05

The first public build of the Myotis apps: the Java engine with snap sync,
the beacon light client and a Besu EVM; a verified JSON-RPC endpoint for
MetaMask; ENS with CCIP-Read; mainnet and Gnosis Chain; the Android app, the
shared Compose Multiplatform UI and the macOS dmg; and `:myotis-api`, the
engine contract (#1 to #123).

[Unreleased]: https://github.com/biafra23/myotis/compare/v0.1.21-rc1...HEAD
[0.1.21-rc1]: https://github.com/biafra23/myotis/compare/v0.1.20...v0.1.21-rc1
[0.1.20]: https://github.com/biafra23/myotis/compare/v0.1.20-rc1...v0.1.20
[0.1.20-rc1]: https://github.com/biafra23/myotis/compare/v0.1.19...v0.1.20-rc1
[0.1.19]: https://github.com/biafra23/myotis/compare/v0.1.19-rc2...v0.1.19
[0.1.19-rc2]: https://github.com/biafra23/myotis/compare/v0.1.19-rc1...v0.1.19-rc2
[0.1.19-rc1]: https://github.com/biafra23/myotis/compare/v0.1.18...v0.1.19-rc1
[0.1.18]: https://github.com/biafra23/myotis/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/biafra23/myotis/compare/v0.1.16...v0.1.17
[0.1.16]: https://github.com/biafra23/myotis/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/biafra23/myotis/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/biafra23/myotis/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/biafra23/myotis/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/biafra23/myotis/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/biafra23/myotis/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/biafra23/myotis/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/biafra23/myotis/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/biafra23/myotis/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/biafra23/myotis/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/biafra23/myotis/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/biafra23/myotis/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/biafra23/myotis/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/biafra23/myotis/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/biafra23/myotis/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/biafra23/myotis/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/biafra23/myotis/releases/tag/v0.1.0
