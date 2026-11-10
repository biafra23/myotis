# Myotis documentation

The documents are grouped by **what kind of statement they make**. The folder tells you whether a
document describes the code as it is now, tells you how to do something, records why a built
thing looks the way it does, or explores something that does not exist yet.

| Folder | What it contains | Can you rely on it for today's behaviour? |
|---|---|---|
| [`how-it-works/`](how-it-works/) | How Myotis behaves **now**: verification, readiness, the Status screen, data usage, Tor, the website | Yes, for what is shipped; a page's status note marks any part that is still a sketch |
| [`guides/`](guides/) | Step-by-step instructions: using the engine library, release signing, running Myotis for Swarm Bee, the RAILGUN PoC, a dedicated Sepolia node | Yes, for the procedure; re-check versions in long-lived runbooks |
| [`spec/`](spec/) | The language-agnostic specification of Myotis (01–05), plus the Rust port's working notes (06) and plan (07) | 01–05 yes; 06–07 are a record of how the port was done |
| [`design-history/`](design-history/) | Designs and plans that **were built**, kept as the record of why: the log index, roost, multichain, Glamsterdam, native BLS, the Java engine's EVM and ENS phases | Partly: the design was built, but later changes are not always folded back. Check `how-it-works/` or the code |
| [`ideas/`](ideas/) | Proposals, evaluations and research that are **not built** (or only a first slice): Base, a dApp browser, inbound connections, snap servers, state on Swarm, onion services | No. Nothing here describes shipped behaviour unless its status line says so |
| [`reviews/`](reviews/) | Code reviews and the backlog of review follow-ups | They describe the code at the commit they name |
| [`tour/`](tour/) | The Myotis Rust Tour: a guided reading of every Rust file, as a book (Markdown, HTML, EPUB) with its sources | It quotes the code at one pinned commit; see its README |

Each document's first lines carry a status note where its state is not obvious. When you add a
document, put it in the folder that matches what it claims, and move it when that changes (an idea
that gets built moves to `design-history/`, and its user-facing behaviour gets a page in
`how-it-works/`).

## how-it-works/

- [architecture-doc.md](how-it-works/architecture-doc.md): the data-acquisition and verification architecture, with where it meets the implementation.
- [implementation-status.md](how-it-works/implementation-status.md): the architecture compared with what is implemented, engine by engine.
- [benefits-doc.md](how-it-works/benefits-doc.md): why a trustless wallet matters, for readers new to the project.
- [verification.md](how-it-works/verification.md): how every answer is verified, from sync-committee signatures to Merkle proofs.
- [readiness-and-verified-head-age.md](how-it-works/readiness-and-verified-head-age.md): when a node counts as synced and ready, and what "verified head age" means.
- [status-screen.md](how-it-works/status-screen.md): every item on the Status screen explained.
- [data-usage.md](how-it-works/data-usage.md): the per-network data meter and the metered/unmetered split.
- [disk-and-network-usage.md](how-it-works/disk-and-network-usage.md): expected disk and network use (preliminary numbers).
- [read-stats.md](how-it-works/read-stats.md): read statistics, measuring what a state-read cache would save.
- [web-page-access.md](how-it-works/web-page-access.md): which browser origins may use the JSON-RPC listener.
- [address-activity.md](how-it-works/address-activity.md): address activity from block access lists (#691).
- [balance-watch.md](how-it-works/balance-watch.md): the Watch tab.
- [privacy-and-tor.md](how-it-works/privacy-and-tor.md): privacy and Tor routing; the production path and what is still sketched.
- [seeded-log-histories.md](how-it-works/seeded-log-histories.md): the bounded trust exception for seeded log histories.
- [log-index-presets.md](how-it-works/log-index-presets.md): the log index's predefined contracts (RAILGUN, Swarm, Privacy Pools, Tornado Cash), what they cost to download and store, and the metered-network hold.
- [website.md](how-it-works/website.md): the website in `site/`, where it is served and how it is published.

## guides/

- [android-library.md](guides/android-library.md): using the engine library `eth.myotis:myotis-engine` in an app.
- [android-release-signing.md](guides/android-release-signing.md): release-signing the Android APK.
- [bee-rpc-service.md](guides/bee-rpc-service.md): running Myotis as the RPC service for a Swarm Bee node.
- [bee-node-from-source.md](guides/bee-node-from-source.md): building the Bee setup from source, and what it adds.
- [bee-daemon-linux.md](guides/bee-daemon-linux.md): headless Myotis on Linux as Bee's RPC node (demo and test only).
- [railgun-poc.md](guides/railgun-poc.md): the RAILGUN PoC desktop build and refreshing its seed.
- [railgun-android.md](guides/railgun-android.md): importing the RAILGUN seed on Android.
- [dedicated-sepolia-node.md](guides/dedicated-sepolia-node.md): a runbook for a Sepolia EL+CL node that always serves Myotis clients.
- [gradle-dependency-pins.md](guides/gradle-dependency-pins.md): the Gradle dependency pins (lockfiles + verification hashes) and regenerating them after a dependency change.
- [reproducible-builds.md](guides/reproducible-builds.md): checking a release: its checksums and build attestations, and rebuilding the Android artifacts bit for bit in the pinned builder image.

## spec/

- [README.md](spec/README.md): the language-agnostic re-implementation specification, start here.
- [01-consensus-light-client.md](spec/01-consensus-light-client.md) to [05-engine-api-bindings.md](spec/05-engine-api-bindings.md): the light client, devp2p, state verification and the EVM, the engine and its hosts, the engine API bindings.
- [06-rust-phase-notes.md](spec/06-rust-phase-notes.md) and [07-el-implementation-plan.md](spec/07-el-implementation-plan.md): the Rust port's working notes and execution-layer plan.
- [benchmarks.md](spec/benchmarks.md): the Rust engine against the JVM engine, phase-1 gate.

## design-history/

- [eth-getlogs-design.md](design-history/eth-getlogs-design.md): the scoped, verified log index behind `eth_getLogs`.
- [lc-server-design.md](design-history/lc-server-design.md): the dedicated light-client server, built as `rust/roost`.
- [multichain-design.md](design-history/multichain-design.md) and [multichain-android-phase-b.md](design-history/multichain-android-phase-b.md): several chains in one process, and the Android registry.
- [glamsterdam-plan.md](design-history/glamsterdam-plan.md): readiness for Gloas and Amsterdam.
- [bls-rust-acceleration.md](design-history/bls-rust-acceleration.md): native blst behind the `BlsBackend` seam.
- [myotis-rust-engine-guidelines.md](design-history/myotis-rust-engine-guidelines.md): the embeddability guidelines the Rust engine was written to (followed in part).
- [evm/](design-history/evm/): the Java engine's EVM phases, decisions and benchmarks.
- [ens/](design-history/ens/): the Java engine's ENS phases, and a script explaining ENS resolution.

## ideas/

- [base-l2-evaluation.md](ideas/base-l2-evaluation.md): Base (Coinbase's L2) on Myotis, an evaluation.
- [dapp-browser-design.md](ideas/dapp-browser-design.md): a dApp browser and RPC interception (phase 0 built as #502).
- [inbound-connections.md](ideas/inbound-connections.md): accepting inbound devp2p connections.
- [logindex-verified-bundle-design.md](ideas/logindex-verified-bundle-design.md): downloadable log-index bundles the walker verifies (#472).
- [react-native.md](ideas/react-native.md): a React Native bridge for Android and iOS.
- [snap-server-design.md](ideas/snap-server-design.md): a dedicated snap server for verified state reads.
- [state-on-swarm.md](ideas/state-on-swarm.md): serving what SNAP serves from Swarm, verifiably.
- [swarm-read-economics.md](ideas/swarm-read-economics.md): what reading from Swarm costs.
- [wallet-onion-services.md](ideas/wallet-onion-services.md): wallets serving each other as onion services.

## reviews/

- [rust-idioms-review.md](reviews/rust-idioms-review.md): how idiomatic the Rust in `rust/` is (2026-11-01).
- [review-follow-ups.md](reviews/review-follow-ups.md): follow-ups from PR reviews, each fixed or consciously dropped.
