# Architecture vs Implementation Status

Comparison of the [architecture document](architecture-doc.md) against what is actually implemented in the codebase, as of 2026-09-30 (v0.1.12 + the `main` commits since).

**Two engines.** Everything below exists twice unless a line says otherwise: the original **Java engine** (`node-core` over `networking`/`consensus`/`myotis-evm`/`myotis-ens`, Besu EVM, Milagro or native-blst BLS) and the **Rust engine** (`rust/` — `myotis-core`, `myotis-consensus`, `myotis-net`, `myotis-evm`, `myotis-engine`; blst, revm), both behind the same engine contract (`:myotis-api`) and selected per network by `:myotis-engines` (`myotis.engine=auto|rust|java`, default `auto` = the Rust engine wherever it can serve). The Rust engine is the primary one: it is the default selection, the only engine on iOS and on Android below API 33, the engine the Node.js addon embeds, and ahead of the Java engine on features (the log index behind `eth_getLogs`, Tor routing, state overrides / EIP-7702 / contract creation in the EVM, the `finalized` tag on state reads, Amsterdam). "Rust only" / "Java only" below name the exceptions. Parity is pinned by shared conformance vectors (BLS fixtures, a captured mainnet light-client corpus, the EL verification-ladder vectors) and by golden JSON tests on both sides; the remaining behavioural differences are tracked in [TODO.md](TODO.md) (#342 parity entries).

## 1. Establishing a Trusted Chain Head — Sync Committees
**Implemented (both engines)**

- Beacon light client with bootstrap, finality updates, and sync-committee rotation — Java `BeaconLightClient`/`LightClientProcessor`, Rust `rust/myotis-net/src/sync.rs` over the sans-I/O verification core `rust/myotis-consensus`.
- Bootstrap pinned to a hardcoded beacon block root per network — the `@checkpoint:mainnet|sepolia|gnosis` marker regions of `NetworkConfig.java`, mirrored in `rust/myotis-net/src/sync.rs` (deliberately not duplicated here: a copy in prose goes stale on every refresh). `./gradlew refreshCheckpoint [-Pnetwork=…]` rewrites both engines from one multi-operator fetch; `java_and_rust_checkpoints_agree` fails if they diverge. Embedding hosts can supply a fresher root themselves (`createWithCheckpoint`, C ABI / Node addon, ABI ≥ 26; the Java engine refuses to resume such a directory).
- BLS12-381 with the ≥2/3 participation gate. Java: pure-Java Milagro AMCL or the native blst backend (`rust/myotis-bls` over JNI) behind the `BlsBackends` seam — `myotis.bls.backend=auto|milagro|native|compare`, default `auto` (native when the library loaded: the daemon and Android ship it, the desktop app bundles no blst library and runs Milagro). Rust: blst directly. Non-canonical encodings, non-subgroup points and identity points are rejected on both sides.
- Light-client req/resp over libp2p (Noise, yamux/mplex; jvm-libp2p on the JVM, rust-libp2p in Rust). Both engines register all four light-client protocols but request only three — `bootstrap`, `updates_by_range` and `finality_update` (the Java `requestOptimisticUpdate` has no callers; the Rust sync loop never asks for it) — so on both the optimistic head is the attested header of the finality updates they poll. Both engines run a **gossipsub** router with nothing subscribed or published (#425) — enough to stop Lighthouse from banning a peer that fails gossipsub negotiation, the 12-hour ban that stalled cold starts up to v0.1.8 (#422); subscribing to the light-client topics is still not built ([plan](../plan-gossipsub-subscription.md)).
- Every update is verified under the fork active at its signature slot, from the per-network fork schedule in `NetworkConfig` / `ChainConfig` (#430); a signature from the next period is checked against the next committee (#429). **Gloas** (Glamsterdam's CL half) is scheduled on Sepolia (epoch 353,024) and both light clients decode and verify the Gloas shapes — fork-keyed decoding, the shape gate before BLS, the execution anchor resolved by block hash (#501, [glamsterdam-plan.md](glamsterdam-plan.md)); mainnet and Gnosis have no Gloas date yet.
- `SYNCED` requires the held committee period to equal the wall clock's **and** the finalized slot to be within 5 epochs of it (`SYNCED_SLOT_SLACK_EPOCHS`, both engines), so a stalled or withheld feed drops the node to `CATCHING_UP` — the signal for a withholding relay ([readiness doc](readiness-and-verified-head-age.md)).
- **Weak-subjectivity gate** (both engines): an anchor older than the network's bound — 13 periods on mainnet and Sepolia, 3 on Gnosis — parks the client in `STALE_ANCHOR` instead of syncing; consent is per run (`accept-stale-anchor`, the apps' dialog, `-Dmyotis.beacon.acceptStaleAnchor`) or the bound is raised live (Settings, `-Dmyotis.beacon.wsBoundPeriods`). Re-checked at every bootstrap attempt and continuously while running.
- Persistence: the verified store snapshot (`sync-state[-net].snapshot`, "LCSS" v1/v2, byte-identical between engines, bound to the chain's genesis-validators-root) plus the state-root sidecar and the CL peer cache, so a warm restart reaches `SYNCED` in ~10 s.
- Catch-up: one period per request from the first contact (Lighthouse's rate limit), pipelined across peers, hunting for batch-capable servers when throughput-bound (Rust, #424/#431); the Java client polls finality before walking peers on resume.
- CL peers are seeded from the persistent `CLPeerCache`, the pinned multiaddrs in `NetworkConfig` (census-pruned to servers that answered from two vantage points — 5 on mainnet, 4 on Sepolia, 8 on Gnosis at the last census, with [roost](../rust/roost/README.md), the project's own light-client server, the first entry of each list) and **discv5** (Java: the ConsenSys library as the `com.github.biafra23:discovery` Android fork; Rust: the `discv5` crate), filtered by `eth2` fork digest; both engines run targeted lookups toward the pinned servers (#348, #351). EIP-1459 DNS remains wired on the Java side with an empty CL tree.
- Extraction of the execution payload header (state root, block hash, number, base fee) through the execution branch; SSZ types for every light-client container in both engines.

## 2. Verifying Historical Blocks — Trusted Accumulator Snapshots
**Partially implemented (unchanged)**

- Header-chain verification up to 8,192 blocks from the beacon-attested block (walk parent hashes) — both engines (`verify.rs`, `VerifiedAccountQuery`).
- Block verification against the beacon `ExecutionPayloadHeader.block_hash` works.
- The Rust log index walks parent hashes **without** a depth limit for its own purposes — the backfill descends from a beacon-anchored trust cursor to a contract's deployment block, and its head-gap bridge spans up to 500,000 blocks — but that anchors logs, not arbitrary block reads (§11).

**Not implemented:**
- `historical_summaries` / `historical_roots` lookup from beacon state (would remove the 8,192-block header-chain bound; note the JSON-RPC block reads are capped at 512 blocks below the head before that bound is ever reached).
- The pre-Merge epoch-hash accumulator — the README's trust-model section still lists it as a designed anchor; no code uses it.
- Pre-merge blocks return `failReason: "preMergeBlock"` with no verification path.

## 3. Transaction History — TrueBlocks via IPFS
**Implemented as a debug-only scan (Java engine, mainnet only)**

- Scan/parse service in `:tx-history` (`TxHistoryService`), shared by the daemon's `get-transactions` IPC stream and the desktop **and Android** Query tabs (streaming UI: block-number placeholders upgrade in place to parsed rows, progress + Stop). It wraps the Java engine's raw `RLPxConnector` (the documented exemption in `CLAUDE.md`), so it is unavailable on the Rust engine and on iOS.
- **Dynamic manifest CID discovery**: the latest mainnet manifest is read from the UnchainedIndex_V2 contract (`manifestHashMap(publisher, "mainnet")`, `0x0c316B70…183d`) via myotis' own verified `eth_call`; the publisher address comes from verified ENS (`publisher.unchainedindex.eth`, chifra's preferred publisher — the map is permissionless, so only that slot is trusted). Fallbacks when the node isn't synced: 24h-cached CID, then a hardcoded known-good manifest.
- Blooms + index chunks are fetched from an IPFS **HTTP gateway** (content-addressed, CID-checked; the doc's "IPFS bitswap" was never built) and disk-cached under `trueblocks/` (immutable, no TTL; truncated responses rejected against manifest sizes).
- Block bodies fetched from devp2p peers; txs decoded via `EthTxDecoder` (legacy, EIP-2930, EIP-1559, EIP-4844, EIP-7702; sender recovered from the signature) and classified (ETH transfer / ERC-20 transfer of well-known tokens / call / creation).

**Not implemented:**
- Transaction verification against `transactionsRoot` on this path (`verified` is hard-coded `false`). Per-tx verification exists on the JSON-RPC path (`eth_getTransactionByHash`, `eth_getTransactionReceipt`, §10); wiring it into the scan is still pending.
- Balance reconciliation for completeness checking.
- Non-mainnet indexes.
- **A fresh index.** Upstream publishing appears stalled: the designated publisher's newest mainnet manifest is indexed to ~block 23.0M (~a year behind head as of mid-2026), so recent history is absent. Both surfaces warn loudly (UI banner; `stale`/`indexAgeDays`/`warning` on the IPC `Started` line beyond 100,000 blocks of lag). Planned remedy: a self-published index (run the TrueBlocks scraper, pin the chunks, add the IPFS peer address to Myotis).

## 4. Fetching and Verifying Block Data — devp2p
**Implemented (both engines)**

- Full devp2p stack in both engines: discv4 discovery, RLPx ECIES handshake and AES-CTR framing, eth/66–69 (eth/69 `BlockRangeUpdate` and bloomless receipts included). The Rust stack is hand-rolled on small primitive crates (no reth); its RLP decoding of unsolicited peer frames is allocation-bounded (#454).
- `GetBlockHeaders`, `GetBlockBodies`, `GetReceipts`; bodies verified by rebuilding the transactions trie, receipts against `receiptsRoot` (eth/69's omitted `logsBloom` is recomputed first). Powers the block/receipt reads, `eth_feeHistory`'s reward percentiles and the log index.
- Block header verification against the beacon chain (direct state-root match or header chain).
- **Rust engine**: block, receipt and `eth_call` state reads are **hedged** — a second peer is raced after 3 s near the head (6 s for bulk reads), and peers that keep losing are evicted (#457); peers are admitted, ranked and struck by their announced head (`BlockRangeUpdate`, or a probe on eth/68), and readiness is gated on `snapServingPeers` — pooled peers that can answer at the anchored head *now* (#465); the by-number header window is anchored at the finalized block, honouring the `finalized` tag (ABI 30). The Java engine rotates `GetBlockBodies`/`GetReceipts` requests across peers instead of one-shot (#387) and evicts snap peers on repeated verified-read failures (#417), but has no hedging or serving count.
- EIP-1459 DNS-based bootnode discovery (`DnsEnrResolver`, `EnrTreeUrl`) — **Java engine only**, on startup and on the snap-peer maintainer's refresh; mainnet and Sepolia trees pinned, Gnosis dials pinned enodes instead. The Rust engine has no DNS walk: it seeds from the bootnodes, the cache, discv4, Sepolia's pinned enode and host-supplied seed pins (`myotis_set_boot_enodes`, ABI 31).
- **Fork watch** (#491): an EIP-2124 upgrade advisory on both engines — peers' fork ids are judged against the pinned schedule and a network that has forked past this build surfaces `upgradeAdvisory` on `status`. Enabled on Sepolia first.
- Peer caching across sessions, byte-identical between engines: the EL cache (`peers[-net].cache` — snap quality flags `snapok`/`snapbad`; a peer is evicted after 50 consecutive connect failures on both engines, and the Rust engine persists a `snapbad` verdict only when another live peer witnessed the failure, where the Java engine records verdicts unconditionally) and the CL cache (`cl-peers[-net].cache`, evicts after 3 consecutive failures).
- Inbound: neither engine accepts inbound RLPx (outbound dialer only; [design](inbound-connections.md)). Both answer peers' `GetBlockHeaders` from a small served-header window (default 32, Settings-adjustable) so eth/69 peers keep them; the Rust libp2p host accepts inbound CL connections but serves no light-client protocols (roost does).

**Not implemented:**
- EIP-4444 fallback strategies; inbound EL connections; eth/70–71 (Amsterdam's partial receipts and BAL exchange — tracked in the Glamsterdam plan, B.5).

## 5. State Data — SNAP Protocol
**Implemented (both engines)**

- snap/1 negotiated alongside eth; `GetAccountRange` and `GetStorageRanges` with Merkle-Patricia proof verification (Java `MerklePatriciaVerifier`, Rust `myotis-core`'s hand-ported verifier), `GetByteCodes` verified by `keccak256(code) == codeHash`. Both engines route every state read through the **range** messages, never `GetTrieNodes` — only the range responses carry the root-to-leaf proof (the Java `SnapPeer.getTrieNodes` API name is a misnomer: `EthHandlerSnapPeer` translates each path set into `GetAccountRange`/`GetStorageRanges`). `GetTrieNodes` is wired at the wire layer only.
- ERC-20 balance lookup via `keccak256(abi.encode(holder, slot))` mapping; full beacon cross-verification (proof → state root → beacon root).
- The snap query root comes from the beacon anchor, not a peer's stale handshake head (#356); `latest` reads retry briefly while peers trail the anchored head (#416).
- **`finalized`** on the state reads: the Rust engine proves against the finalized state root with no fallback and labels the result `anchor: "finalized"` (ABI 32); the Java engine still resolves `finalized` to the head (#366). A state read pinned to `earliest`, a block hash or a number too far behind the head is refused by the hosts before the engine runs, but reaches the wallet as the retryable `-32000` on both engines — a permanent refusal flattened, recorded in [TODO.md](TODO.md).
- Caches: the Java `StateProofCache` keys accounts by state root and **storage slots by the account's storage root**, so unchanged contracts replay across head advances; the Rust twin still keys storage by world state root (a parity gap recorded in `06-rust-phase-notes.md`). Both engines run the **read-stats shadow cache** (`read-stats` IPC, the Status tab's "Reads"/"Cacheable" rows) that measures what a further cache would save without serving anything ([read-stats.md](read-stats.md)).

**Not implemented:**
- NFT ownership queries (same mechanism, not exposed).
- Vyper storage slot layout support.

## 6. ENS Resolution — Via Local EVM over SNAP-Verified State
**Implemented (both engines; full record-type coverage)**

Resolution runs the ENS contracts in the local EVM (§9) with state served from SNAP proofs — ENSIP-10 wildcard resolution and CCIP-Read (ERC-3668) work for every record type. The Java resolver walks the Registry directly (ENSIP-10), the Rust engine likewise over its own verified `eth_call`s.

| Record | Spec | IPC command |
|---|---|---|
| Forward address | ENSIP-1 | `resolve-ens` |
| Reverse (address → name, with the mandatory ENSIP-3 forward check) | ENSIP-3 | `reverse-ens` |
| Multi-coin address | ENSIP-9 / SLIP-44 | `resolve-ens-addr-coin` |
| Text records | ENSIP-5 | `resolve-ens-text` |
| Content hash | ENSIP-7 | `resolve-ens-contenthash` |
| Public key | EIP-619 | `resolve-ens-pubkey` |
| ABI metadata | EIP-205 | `resolve-ens-abi` |
| DNS records | ENSIP-8 | `resolve-ens-dns` |
| Interface implementer | EIP-1820 over ENS | `resolve-ens-interface` |

Every query takes a **resolution root**: Java `AUTO` (finalized first, peer head as fallback) / `FINALIZED` / `PEER_HEAD`; Rust `auto` / `finalized` / `optimistic` — the Rust engine has no peer-claimed mode, every answer is beacon-anchored. All hosts use `AUTO` (Android's `NodeService.setEnsResolutionRoot(...)` exists for an embedding host; no UI exposes the choice).

CCIP-Read end-to-end: `OffchainLookup` reverts caught by `CcipReadEvmExecutor` (Java) or returned to the host as the gateway tuple and re-entered via `ccipCallback` (Rust, driven by `CcipDriver` on the JVM hosts); the HTTP transport is the injectable `HttpGateway` port — `java.net.http` on the daemon and desktop (`JavaHttpCcipGateway`), `HttpURLConnection` on Android (`AndroidCcipGateway`, 1 MiB response cap). Validated against the EIP-3668 demo gateway and Coinbase IDs (`*.cb.id`). The Java engine can chain two CCIP rounds (an off-chain reverse then an off-chain forward); the Rust path allows one. **iOS has no CCIP-Read yet** — off-chain names report "resolves off-chain (CCIP-Read), which this app doesn't support yet".

Network coverage: mainnet and Sepolia (`NetworkConfig.hasEns`); Gnosis has no ENS. (`EnsResolver.forChainId` still carries holesky's addresses, dead code since the network was retired.)

Reverse resolution also names the log index's imported entries (verified reverse-ENS, Rust engine), so a generated index file cannot lie about who a contract is.

**Not implemented:**
- ENS over JSON-RPC (there are no `ens_*`/`myotis_ens*` methods; wallets resolve through `eth_call` themselves) and a UI surface for reverse lookup or the resolution root.
- L2 / cross-chain name handling (ENSIP-19 L2 primary names) beyond what an ENSIP-10 resolver serves through CCIP-Read.

## 7. Submitting Signed Transactions — devp2p Transaction Gossip
**Implemented (both engines)**

- `eth_sendRawTransaction` broadcasts the user-signed raw bytes to connected peers via the `Transactions` message (the Rust engine to every snap peer, re-pushing a not-yet-seen transaction on the wallet's receipt / `eth_getTransactionByHash` polls at most every 20 s until gossip echoes its hash — the Java engine runs the same 20 s gate on a timer), returns `keccak256(rawTx)`, and caches the bytes so `eth_getTransactionByHash` reports the tx as *pending* before it's mined. Myotis never signs — it only relays.
- Propagation is confirmed by watching our own hash return over `Transactions` / `NewPooledTransactionHashes` gossip (decoded only while a send is unconfirmed); the pending-nonce overlay lets back-to-back sends from one account not collide (the one deliberately unproven value — it only raises the verified mined count, only for our own broadcasts, TTL-bounded).
- Confirmation tracking: `eth_getTransactionByHash` / `eth_getTransactionReceipt` scan the recent beacon-verified block window (initial lookback 8 blocks, then forward); once the tx appears (verified vs `transactionsRoot`) the wallet sees `blockNumber` populate and the receipt is verified against `receiptsRoot`.
- Validated end-to-end on a real device: MetaMask builds and signs, Myotis broadcasts over devp2p, the receipt confirms on-chain — no proxy.

**Not implemented:**
- `GetPooledTransactions` / mempool serving (announce-then-fetch) — outbound broadcast uses the direct `Transactions` message only.
- EIP-4844 blob-sidecar gossip (out of scope; L2-sequencer territory).

## 8. Gas Estimation
**Implemented (both engines) — `eth_estimateGas` over JSON-RPC**

Geth's search for the lowest gas limit at which the transaction succeeds, plus a 15% buffer, at least the EIP-7623 calldata floor (Prague+), capped at the caller's `gas` (without one, the block's gas limit) and at the fork's transaction gas cap (EIP-7825's 2^24 from Osaka). A plain value transfer to a code-less, non-precompile account short-circuits to exactly 21000 with no EVM run (pre-Amsterdam — EIP-2780 reprices transfers there). Revert and out-of-gas halts are errors, never a number: a revert reaches the wallet as JSON-RPC error `3` with the revert payload (engine ABI 23 added the estimate's revert payload); an estimate that does not fit the caller's `gas` or funds answers geth's `-32000` messages verbatim (`gas required exceeds allowance (N)`, `insufficient funds for transfer`), and a fee cap below the block's base fee — or, without a fee, a value the sender cannot cover — geth's "failed with N gas: …".

**The search (#509 stage 2, both engines).** A first probe at what the run at the ceiling drew plus the call stipend, with the 63/64 a nested call withholds, is usually the answer, and bisection stops within 1.5% of the lowest limit that works; the 15% buffer goes on top. One run's draw plus 15% was not a limit that works for a deep call chain or a contract that checks `gasleft()`. Unlike geth the search never goes below that draw (geth starts from the post-refund charge): a lower limit only "works" by running a different transaction, such as one whose inner call fails and is caught. Without a caller `gas` the ceiling is also bounded by the block's gas limit, where geth's search starts. A real mainnet RelayAdapt7702 shield — #509's transaction, recorded from the engine's verified reads with throwaway keys (`rust/testdata/evm/relayadapt7702-shield.json`) — replays in both engines and pins the answer.

**The whole transaction object (#509, ABI 34).** Every field is applied or the request is refused with the permanent `-32602`, never dropped. The Rust engine (`myotis_evm::tx::TxRequest`, `EvmExecutor::estimate_tx`) applies EIP-7702 `authorizationList` (revm installs the delegations exactly as a mined transaction does, skipping an invalid tuple), `accessList`, the `gas` cap (below 21000 it is no cap, as in geth), the fee fields (`GASPRICE` reads the effective price; a non-zero fee cap bounds the ceiling by `(balance − value) / feeCap`), `nonce`, `type`, `chainId`, the block selector (including `finalized`), a state override, and contract creation (init code bounded by EIP-3860). The Java engine applies `gas`, the fee fields and the block; it refuses the two lists, state overrides, contract creation and `finalized` (it would answer from the head). Contradictory objects (a type-4 request without a list, a tip above the fee cap, `data` and `input` that differ, blob fields, another chain's `chainId`) are refused on both.

Acceptance corpus (`MainnetGasEstimationIT`, env-gated): ETH→EOA, ETH→contract (WETH deposit), ERC-20 transfer (USDC), ERC-721 transfer (ENS BaseRegistrar), Uniswap V3 exact-input swap, each cross-checked against a reference `eth_estimateGas` within 5%. `AnvilForkedBroadcastIT` broadcasts a transaction with the locally-estimated gas to an Anvil mainnet fork and asserts `gasUsed <= localEstimate` — the 15% buffer is sufficient on the wire. Verified on-device against MetaMask's send flow (`0x5208` in ~0.16 s for a plain send).

Fee suggestions are served verified — `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` — base fee from verified headers, priority-fee tips from bodies verified against `transactionsRoot`, reward percentiles from a gas-used-weighted walk over receipts verified against `receiptsRoot`. The Rust engine memoizes the fee reads per anchored head and refreshes them in the background (#510), so the confirm screen's fee poll is instant.

## 9. Local EVM Execution
**Implemented (both engines) — `eth_call` and `eth_estimateGas`, ENS**

- **Rust engine**: `rust/myotis-evm` — **revm 43** (pinned exactly) behind a `SnapStateOracle` trait, sans-I/O; the network side (`rust/myotis-net/src/el/evm.rs`) serves it from the snap pool with hedged, batched proof fetches (chunks of 64, bounded in-flight requests). Per-chain fork tables for mainnet, Sepolia and Gnosis (London and later); **Amsterdam** (Glamsterdam's EL half) is served on Sepolia from its scheduled time.
- **Java engine**: `myotis-evm` embeds Hyperledger Besu's standalone EVM (`org.hyperledger.besu:besu-evm` 26.4.0; the `com.github.biafra23.besu` fork on Android). `DefaultEvmExecutor` runs one Besu pass over the snap-backed `StateOracle`; `PrefetchingEvmExecutor` wraps it; `CcipReadEvmExecutor` handles ERC-3668. Same three chains, London and later; Besu 26.4 stops at Osaka, so a Sepolia block from Amsterdam on is **refused** with a permanent `-32602` ("the Rust engine serves it") rather than mis-priced.
- Both engines run a **multi-hop speculative prefetch loop** (sentinel passes that record accesses without blocking, then parallel batch fetches, the last two of four iterations always real; the cap fails closed) — the round-trip-per-SLOAD latency does not dominate. Bytecode verified via `keccak256(code) == codeHash`; block context (`number`, `timestamp`, `coinbase`, `prevRandao`, `baseFeePerGas`, `gasLimit`, `chainId`, and Amsterdam's slot number) from the verified header only. EIP-7702 delegation designators are followed one hop, with the delegate warm from the start, as geth and revm start it.
- **`eth_call` fields** — the whole transaction object, applied as geth applies it or refused (#509 stage 2; `EvmExecutor::call_tx`, the Java `EvmExecutor.callTx`, engine ABI 35):
  - **Block selector.** `latest`/`safe`/`pending` = the head; `finalized` = the beacon-finalized block on the Rust engine — on the Java engine the head for a plain call (#366), refused (`-32602`) for one carrying gas, fees or lists; a number within 64 below / 16 above the head runs against head state, as does EIP-1898's `{"blockNumber":…}`; a `{"blockHash":…}` object is refused by the router (`-32602`). Anything else is refused before the engine runs: for a plain call, through the JVM and iOS hosts as the retryable `-32000` on both engines, because their shared block-window pre-check answers "not servable" and so flattens the Rust engine's permanent `-32602` (only the Node addon, with no host adapter in front, surfaces it); a call carrying gas, fees or lists skips that pre-check, so the Rust engine's `-32602` reaches the wallet.
  - **Gas and fees.** `gas` is the call's limit — capped at the engine's 30 M budget, as geth caps it at its RPC gas cap — so a limit below the intrinsic cost or the EIP-7623 floor is refused ("intrinsic gas too low: have N, want M" / "insufficient gas for floor data gas cost: …") and running out of it answers "out of gas"; a `gas` above the budget is capped to it, and a call that runs out there is refused (`-32602`: the answer would be for a smaller limit than the caller set). A non-zero fee must reach the base fee ("max fee per gas less than block base fee: …") and is debited from the sender before the call runs, with `GASPRICE` reading the effective price; fee or not, the sender must hold `gas × fee cap + value` ("insufficient funds for gas * price + value: …", geth's `buyGas`). A check failed before the run is worded as geth's `eth_call` words it, "err: <reason> (supplied gas N)" — each of these is `-32000` with geth's message, never return data.
  - **Rust engine only:** a **state override** (`code`, `balance`, `nonce`, `state`, `stateDiff`), **contract creation** (an absent or `null` `to` runs the init code; an empty-string `to` is a malformed address and is refused, not creation), `accessList` (charged and pre-warmed) and `authorizationList`; the Java engine refuses all four (`-32602`). Refused on both: blob fields, block overrides, contradictory `data`/`input`.
  - **Known differences from geth:** a fee-less call reads the block's real `BASEFEE` (geth zeroes it), and a plain call (no `gas`, fee or list) is not held to the sender's balance. Between the engines, the Java engine's plain call charges no intrinsic gas (calldata of any size runs with the full 30 M), where the Rust engine answers a plain call whose calldata alone outweighs the budget with geth's intrinsic/floor refusal.
- A reverting call answers error `3` with the revert payload and decoded `Error(string)` reason — MetaMask's ERC-165 probes depend on it. `BLOCKHASH` is not served by either EVM (it halts).
- Exposed over JSON-RPC as `eth_call` and `eth_estimateGas` (§8), and driving ENS (§6). `:myotis-evm:test` and the Rust crate's tests cover the executor stacks with deterministic fixtures; the EL verification-ladder vectors are shared.

**Not implemented / rough edges:**
- `BLOCKHASH`; `BLOBBASEFEE` reads revm's floor because no excess-blob-gas is passed; an EIP-1898 block object on the state reads is read as `latest` (`eth_call` and `eth_estimateGas` apply `{"blockNumber":…}` and refuse a hash).
- A dedicated "simulate" surface that decodes revert reasons for a UI — `eth_call`/`eth_estimateGas` cover the mechanism.
- Java engine: a cold head-context build (header-chain anchor + first snap fetch on a fresh peer) can take ~15 s; warm calls ~1 s.

## 10. Wallet Integration — Verified JSON-RPC on every host
**Implemented (MetaMask end-to-end; Bee and RAILGUN clients as PoCs)**

The `jsonrpc-server` module (Kotlin Multiplatform/Ktor) exposes the verification pipeline as a standard Ethereum JSON-RPC endpoint. `RpcRouter` maps the API onto the module's `RpcBackend` seam — `VerifiedReadsBackend` over the engine contract's `VerifiedReads` on the JVM hosts, `IosRpcBackend` on iOS — so **every host serves it**: the Android app, the iOS app, the desktop app and the desktop daemon (which additionally exposes the verified operations over its CLI/IPC socket). Loopback only (`127.0.0.1`; mainnet 8545, Gnosis 8546, Sepolia 8547 by default, user-settable in the apps), unauthenticated, no TLS, no rate limiting — a same-device wallet's endpoint, deliberately unreachable from other devices. **Strict permissionless mode** is the default and the only production mode: an unservable request returns `-32601` (not served verified) or `-32000` (can't answer right now), never proxied data. (A dev-only upstream proxy exists solely to discover what a wallet calls.)

Verified methods (`VERIFIED_METHODS` in `RpcRouter.kt`; per-method verification basis and the full error-code contract in the README's *Wallet API*): `eth_chainId`, `net_version`, `eth_blockNumber`, `eth_syncing`, `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_call`, `eth_estimateGas`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`, `eth_getBlockByNumber`, `eth_getBlockByHash`, the block-derived reads (`eth_getBlockTransactionCountBy*`, `eth_getTransactionByBlock*AndIndex`, `eth_getUncleCountBy*`, `eth_getUncleBy*AndIndex`), `eth_getTransactionReceipt`, `eth_getBlockReceipts`, `eth_getTransactionByHash`, `eth_getLogs` (log index, Rust engine), `eth_sendRawTransaction`, `eth_accounts`, `net_listening`, `net_peerCount`, `web3_clientVersion`, `web3_sha3`. Plus the node-introspection `myotis_status`, `myotis_beaconStatus`, `myotis_rpcCoverage`, `myotis_pause` / `myotis_wakeup` (the out-of-process wallet's background/foreground hooks). JSON-RPC 2.0 batches are handled element by element. Wallet quirks handled: reads pinned to a near-head block number are served from the head's state (a stale pin is refused, not answered with newer state); verified reads are held only while the node is actually waking up, at most 90 s (#432); a slow-call watchdog; the HTTP layer heartbeats whitespace so a long `eth_call` survives the wallet's read timeout.

**Hosts.**
- **Android** (`android-app`, minSdk 29) runs the whole stack as a foreground `NodeService` with a Compose UI (Status / Query / Logs / Index / Settings), every enabled network in one process, idle sleep with a daily catch-up pass, and warm-restart persistence. Below Android 13 (API 33) the Rust engine is the only engine — Besu's `UInt256` and Guava's futures need hidden `VarHandle` APIs — and Settings says so instead of offering the toggle (#433). The APK's dex is gated against the minSdk-29 API budget by `scripts/check_apk_min_api.py`, and CI boots the app on a minSdk-29 emulator.
- **iOS** (`app-ios` + `ios-app/`): the shared UI in a Kotlin/Native framework (`MyotisKit`) over the Rust engine's C ABI — the JVM engine never runs there. A development host more than an integration point: iOS suspends backgrounded apps (the node keeps running ~30 s after backgrounding), so a wallet embeds the engine instead; releases ship `MyotisKit.xcframework` and the raw-engine `MyotisEngine.xcframework` for Swift hosts. Its RPC backend does not wire `eth_getLogs` yet (`IosRpcBackend` has no `getLogs`, so the method answers `-32000` although the engine underneath holds the index).
- **Desktop app** (`app-desktop`): the same UI, jpackage `.dmg`/`.deb` bundling the Rust engine, opted out of macOS App Nap (it serves RPC to other processes), rolling logs under `~/.myotis/logs` with `myotis.log.level` / `myotis.log.rpc.level`. Two PoC build flavours (`-PbeePoc`, `-PrailgunPoc`) pre-seed a log index for a Swarm Bee node on Gnosis and for the RAILGUN wallet on mainnet — demo/debug artefacts, not production paths (§11).
- **Desktop daemon/CLI** (`app`): IPC over a Unix socket per network (`/tmp/ethp2p[-net].sock`), hosting one or several networks per process (`-Pnetwork=mainnet,gnosis`), each with its own EL/discv5/RPC ports; the command reference is in the README.
- **Node.js addon** (`rust/myotis-node`, napi-rs, ABI 35): the engine in-process for Electron/Node hosts (the Freedom browser's experimental Myotis tier), prebuilt for five platforms per release; wraps lifecycle, status, `requestAccountJson`, `ethCallJson`/`ethCallTxJson`, `estimateGasJson`/`estimateGasTxJson`, ENS, `feeEstimateJson` and `sendRawTransactionJson` — not yet the block/receipt reads, `feeHistory`, the other state reads, `eth_call` overrides, the log index or read-stats.

**Validated:** MetaMask pointed at the device renders its confirm screen from verified balances, fees, and a local gas estimate, then broadcasts a real signed transaction — fully permissionless, no proxy. A Swarm Bee 2.8.2 full node ran against the Bee PoC build's `eth_getLogs`/state reads as its Gnosis RPC (postage events to the chain tip, chequebook exercised — [bee-rpc-service.md](bee-rpc-service.md)).

**Not implemented / rough edges:**
- `eth_subscribe`/WebSocket, `eth_getProof`, ENS over JSON-RPC, and other less-common wallet methods (`-32601`).
- **Endpoint security:** loopback only, no auth/rate limiting/TLS — sufficient for the same-device model; no opt-in path yet for a routable interface (would need auth/TLS first).
- A permanent engine refusal on the hosts' *state* reads still flattens to the retryable `-32000` (TODO.md).

## 11. Log index — verified `eth_getLogs`
**Implemented (Rust engine only)**

An opt-in, per-network index of the logs of contracts the user chooses (the Index tab; `build-logindex` on the daemon), kept in `logindex[-net].db` under the data dir. Every stored log passed the anchored-header and `receiptsRoot` checks; a query outside the indexed coverage is an error, never a misleading `[]`. Per-entry `fromBlock` (walk back to each contract's deployment), a downward backfill that yields to head-follow, a head-gap bridge of up to 500,000 blocks, an optimistic tail above finality with reorg rewind, checkpointed final coverage that survives restarts, a pause switch and a "max download speed" mode, peers ranked by throughput. Portable, chain-tagged snapshots (`export-logindex` / `import-logindex`, the apps' import picker; format "MLIX" v2, names stripped on export and re-derived by verified reverse-ENS on import). Design: [eth-getlogs-design.md](eth-getlogs-design.md).

**Bounded trust carve-out (owner ruling 2026-09-25):** a *seeded* history of a root-committing protocol may be served on its publisher's word, because the client's on-chain root check keeps forged leaves out — [seeded-log-histories.md](seeded-log-histories.md). The engine has no dedicated seed path yet: a seed goes through the generic import and is served indistinguishably from walked logs, which is why the Bee and RAILGUN seeds stay demo-only. The verified alternative — downloadable bundles the walker re-verifies — is designed, not built ([logindex-verified-bundle-design.md](logindex-verified-bundle-design.md), #472).

**Not implemented:** the log index on the Java engine (`eth_getLogs` answers `-32000` there; the Index tab hides when the Java engine is forced); `eth_getLogs` on the iOS host (its RPC backend has no `getLogs`, so the method answers `-32000` there too — only the JVM hosts wire it); the Node addon's log-index surface; provenance marking of seeded ranges.

## 12. Privacy — Tor routing
**Implemented, feature-gated and experimental (Rust engine, desktop host)**

`-PtorEngine` links Arti into the Rust engine; a Settings toggle (desktop only today) routes **account reads** (`get_account` — balance/nonce, and the account half of a code read) over per-address isolated Tor circuits with ephemeral RLPx keys, failing closed with no clearnet fallback. Storage, `eth_call`, blocks, broadcast, the CL fetch and discovery stay on the real IP, and the Tor reads reuse the clearnet-validated peer pool (a timing-correlation limitation the code documents). A finalized read over Tor is refused. Design, threat model and the validated proof of concept (`rust/tor-poc`): [privacy-and-tor.md](privacy-and-tor.md).

## Summary

| Architecture Section                 | Status          | Key Gap                                        |
|--------------------------------------|-----------------|------------------------------------------------|
| 1. Sync Committees (CL light client) | **Implemented** (both engines) | Light-client gossipsub topics not subscribed (poll instead) |
| 2. Historical Block Verification     | **Partial**     | No accumulator snapshots, 8192-block limit     |
| 3. TrueBlocks Transaction History    | **Debug-only** (Java engine, mainnet) | Unverified on that path; upstream index stalled ~1 year behind |
| 4. Block Data via devp2p             | **Implemented** (both engines) | No EIP-4444 fallback; no inbound EL connections; DNS discovery Java only |
| 5. State Data via SNAP               | **Implemented** (both engines) | `finalized` on the Java engine's state reads; Rust storage cache keyed by world root; no NFT/Vyper helpers |
| 6. ENS Resolution                    | **Implemented** (both engines) | No JSON-RPC/UI surface for reverse lookup; no CCIP-Read on iOS |
| 7. Transaction Submission            | **Implemented** (both engines) | Direct `Transactions` broadcast only; no pooled-tx serving |
| 8. Gas Estimation                    | **Implemented** (both engines) | Java engine refuses lists / overrides / creation / `finalized` |
| 9. Local EVM Execution               | **Implemented** (both engines) | `BLOCKHASH` not served; Java engine refuses `eth_call` lists / overrides / creation and stops at Osaka |
| 10. Wallet Integration (JSON-RPC, all hosts) | **Implemented** | No WebSocket/`eth_subscribe`; loopback-only, no auth |
| 11. Log index (`eth_getLogs`)        | **Implemented** (Rust only) | Seeds unmarked; verified bundles not built; no Java engine support |
| 12. Tor routing                      | **Experimental** (Rust, desktop) | Account reads only; shared clearnet pool |

The core verification pipeline (sync committees → state root → Merkle proofs → local EVM) is functional end-to-end in both engines, exposed as a verified JSON-RPC endpoint on every host, and used by a stock MetaMask to read, estimate and **send a real transaction** on a phone, by a Swarm Bee node as its chain RPC, and by embedders through the Node.js addon and the iOS frameworks. The biggest remaining work: historical-block verification (accumulators), the seeded-history provenance / verified-bundle path for deep log histories, and the Java engine's feature lag behind the Rust engine (or its retirement).
