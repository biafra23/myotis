# Architecture vs Implementation Status

Comparison of the [architecture document](architecture-doc.md) against what is actually implemented in the codebase.

## 1. Establishing a Trusted Chain Head — Sync Committees
**POC: Implemented**

- Beacon light client with bootstrap, finality updates, and sync committee rotation (`BeaconLightClient`, `LightClientProcessor`)
- Bootstrap response is pinned to a hardcoded beacon block root (`checkpointRoot`) in `NetworkConfig` (mainnet: slot 14158720, root `611c852c…ff5d`). `verifyCheckpointPin` enforces the pin on every bootstrap response, whether fetched over libp2p or HTTP. The pin is refreshed via the `./gradlew refreshMainnetCheckpoint` Gradle task.
- BLS12-381 signature verification with 2/3 supermajority check (`SyncCommitteeVerifier`, `BlsVerifier`). Implementation is pure-Java Milagro AMCL — the jblst JNI dependency has been removed, which unblocks the Android port. Validation rejects non-canonical point encodings, non-subgroup points, and identity pubkeys/signatures to prevent trivial forgeries.
- libp2p networking with Noise XX, Yamux/Mplex (`BeaconP2PService`)
- All four light client req/resp protocols implemented (bootstrap, updates_by_range, finality_update, optimistic_update)
- Execution state root extraction from beacon blocks
- SSZ types for all beacon structures (47 files in `consensus/`)

CL peers are seeded from four sources (in priority order): the persistent `CLPeerCache`, hardcoded multiaddrs in `NetworkConfig.clPeerMultiaddrs()`, EIP-1459 DNS resolution of `clEnrTreeUrls`, and **discv5** (`DiscV5Service`, wraps `io.consensys.protocols:discovery` — the ConsenSys library Teku also uses). Discv5 seeds from `NetworkConfig.clDiscv5Bootnodes()` (the canonical Lighthouse mainnet CL bootstrap ENRs: Teku, Prylabs, Sigma Prime, EF, Nimbus, Lodestar) and runs on UDP 9000 alongside EL's discv4 on 30303. Discovered ENRs are filtered by `eth2.forkDigest` matching the current network's digest before being written to `CLPeerCache`, so dead-fork and non-CL discv5 participants don't pollute the cache. DNS remains wired but `clEnrTreeUrls` stays empty — no canonical CL tree exists (each CL client team publishes their own) and discv5 supersedes it. Matching ENRs are also pushed live into `BeaconLightClient` via `addPeer()`, so newly discovered CL peers become usable in the current run (no daemon restart required); the cache write keeps them across restarts. (EL peer DNS discovery is separate and fully populated — see Section 4.)

## 2. Verifying Historical Blocks — Trusted Accumulator Snapshots
**POC: Partially implemented**

- Header chain verification up to 8,192 blocks from the finalized block is implemented (walk parent hashes)
- Block verification against beacon `ExecutionPayloadHeader.block_hash` works

**Not implemented:**
- `historical_summaries` / `historical_roots` lookup from beacon state (would remove the 8,192-block limit)
- Pre-merge epoch hash accumulator (`premergeacc.bin`) — the README mentions it as a trust anchor but the code doesn't use it for block verification yet
- Pre-merge blocks return `failReason: "preMergeBlock"` with no verification path

## 3. Transaction History — TrueBlocks via IPFS
**POC: Implemented**

- TrueBlocks manifest fetched from IPFS (hardcoded CID)
- Bloom filter + index chunk download per address
- Block bodies fetched from devp2p peers, transactions extracted and RLP-parsed
- Supports legacy, EIP-2930, EIP-1559, EIP-4844 tx types

**Not implemented:**
- Transaction verification against `transactionsRoot` **on the TrueBlocks `get-transactions` path** (the `verified` field is always `false` there). Per-tx verification against `transactionsRoot` *does* now exist on the JSON-RPC path (`eth_getTransactionByHash`, Section 10) and for receipts (`eth_getTransactionReceipt`); wiring it into the TrueBlocks history scan is still pending.
- Dynamic manifest CID discovery (hardcoded, stale)
- Balance reconciliation for completeness checking

## 4. Fetching and Verifying Block Data — devp2p
**POC: Implemented**

- Full devp2p stack: discv4 discovery, RLPx ECIES handshake, eth/67-69 protocol
- `GetBlockHeaders`, `GetBlockBodies`, and `GetReceipts` implemented
- `GetReceipts` with receipt verification against the header's `receiptsRoot` (rebuild the receipts trie and compare). Handles **eth/69 (EIP-7642) bloomless receipts** — the wire receipt omits `logsBloom`, so it's recomputed from the logs and the canonical encoding rebuilt before the root check, identical verification across eth/66-69. Powers `eth_getTransactionReceipt` and the `eth_feeHistory` reward percentiles.
- Block header verification against beacon chain (direct state root match or header chain)
- EIP-1459 DNS-based bootnode discovery (`DnsEnrResolver`, `EnrTreeUrl`) runs on startup and is merged with the hardcoded bootnode list. Mainnet EL tree is `enrtree://…@all.mainnet.ethdisco.net`; CL tree is intentionally empty pending a canonical tree. EL DNS discovery doubles as a discv4-independent dial path on mobile/CGNAT networks where unsolicited inbound UDP is dropped.
- Peer caching across sessions: the devp2p cache (`PeerCache`) is append-only with deduplication; the CL peer cache (`CLPeerCache`) evicts peers after 3 consecutive failures and resets the counter on success. Cache writes are synchronized so parallel appends and rewrites can't interleave.

**Not implemented:**
- EIP-4444 fallback strategies

## 5. State Data — SNAP Protocol
**POC: Implemented**

- snap/1 protocol negotiated alongside eth
- `GetAccountRange` with Merkle-Patricia proof verification (`MerklePatriciaVerifier`)
- `GetStorageRanges` with storage proof verification
- ERC-20 balance lookup via `keccak256(abi.encode(holder, slot))` mapping
- Full beacon chain cross-verification (proof -> state root -> beacon finalized root)

**Not implemented:**
- `GetTrieNodes` (alternative trie path approach)
- NFT ownership queries (same mechanism but not exposed via IPC)
- Vyper storage slot layout support

## 6. ENS Resolution — Via Local EVM over SNAP-Verified State
**POC: Implemented (full record-type coverage)**

Resolution runs the ENS contracts in a local EVM (`myotis-evm`, see Section 9) with state served from SNAP proofs. Every record type goes through the Universal Resolver's `resolve(bytes,bytes)` so wildcard (ENSIP-10) and CCIP-Read (ERC-3668) work transparently for all of them.

| Record | Spec | IPC command |
|---|---|---|
| Forward address | ENSIP-1 | `resolve-ens` |
| Multi-coin address | ENSIP-9 / SLIP-44 | `resolve-ens-addr-coin` |
| Text records | ENSIP-5 | `resolve-ens-text` |
| Content hash | ENSIP-7 | `resolve-ens-contenthash` |
| Public key | EIP-619 | `resolve-ens-pubkey` |
| ABI metadata | EIP-205 | `resolve-ens-abi` |
| DNS records | ENSIP-8 | `resolve-ens-dns` |
| Interface implementer | EIP-1820 over ENS | `resolve-ens-interface` |

Reverse resolution (`address → name`) is implemented in the resolver with mandatory ENSIP-3 forward-verification round-trip — no IPC command surfaces it yet.

CCIP-Read end-to-end: `OffchainLookup` reverts caught by `CcipReadEvmExecutor`, gateway HTTP fetch via injectable `CcipGateway` (daemon supplies a `java.net.http`-backed impl; Android consumer supplies a Ktor-backed one), callback re-entry into the EVM. Validated against the EIP-3668 demo gateway and Coinbase IDs (`*.cb.id`).

Network coverage: mainnet, sepolia, holesky have canonical Registry + Universal Resolver addresses pinned (sourced from `ensdomains/ens-contracts` deployment manifests). `EnsResolver.forChainId(chainId)` picks the right pair.

**Not implemented:**
- IPC command for reverse lookup (the resolver method exists, just no surface)
- L2 / cross-chain name handling beyond the Universal Resolver path

## 7. Submitting Signed Transactions — devp2p Transaction Gossip
**POC: Implemented**

- `eth_sendRawTransaction` broadcasts the user-signed raw bytes to connected `eth` peers via the `Transactions` message (`RLPxConnector.broadcastTransaction`), returns `keccak256(rawTx)`, and caches the bytes so `eth_getTransactionByHash` can report the tx as *pending* before it's mined. Myotis never signs — it only relays.
- Confirmation tracking: `eth_getTransactionByHash` and `eth_getTransactionReceipt` scan the recent beacon-verified block window; once the tx appears in a block (verified vs `transactionsRoot`) the wallet sees `blockNumber` populate, and the receipt is verified against `receiptsRoot`.
- Validated end-to-end on a real device: MetaMask builds and signs a transaction, Myotis broadcasts it over devp2p, and the receipt confirms on-chain — no proxy.

**Not implemented:**
- `NewPooledTransactionHashes` / `GetPooledTransactions` (announce-then-fetch gossip and mempool serving) — outbound broadcast uses the direct `Transactions` message only.
- EIP-4844 blob-sidecar gossip (out of scope; L2-sequencer territory).

## 8. Gas Estimation
**POC: Implemented**

`DefaultEvmExecutor.estimateGas(UnsignedTransaction, BlockContext)` returns a Yellow-Paper-correct intrinsic + Besu-EVM-metered + 15%-buffer estimate. Revert and OOG halts throw rather than return a number (callers must not broadcast a doomed transaction). Out of scope for v1: contract creation, EIP-2930 access lists, EIP-3860 init-code, binary-search refinement.

Acceptance corpus (`MainnetGasEstimationIT`, env-gated): ETH→EOA, ETH→contract (WETH deposit), ERC-20 transfer (USDC), ERC-721 transfer (ENS BaseRegistrar), Uniswap V3 exact-input swap. Each cross-checks against `eth_estimateGas` from a reference RPC within 5% when the operator supplies `MYOTIS_INTEGRATION_<NAME>_REFERENCE_GAS`.

The headline end-to-end acceptance (`AnvilForkedBroadcastIT`) builds a transaction with the locally-estimated gas, broadcasts it to an Anvil fork of mainnet (via `anvil_impersonateAccount`), and asserts the receipt succeeds without OOG and `gasUsed <= localEstimate`. This proves the 15% safety buffer is actually sufficient on the wire — a property the 5%-of-reference cross-check alone can't guarantee.

Now exposed over JSON-RPC as **`eth_estimateGas`** (Section 10): a plain value transfer to a code-less account short-circuits to 21000 (no EVM run, exact — no buffer), and anything with calldata or a contract/7702 recipient runs the full metered estimate. Verified on-device against MetaMask's send flow (`0x5208` in ~0.16 s for a plain send).

Fee suggestions are also served verified: **`eth_gasPrice`**, **`eth_maxPriorityFeePerGas`**, and **`eth_feeHistory`** derive base fee from verified headers and priority-fee tips from block bodies (verified vs `transactionsRoot`), with `eth_feeHistory`'s reward percentiles using a gas-used-weighted walk over receipts (verified vs `receiptsRoot`). `baseFeePerGas` remains available via `get-block` and `eth_getBlockByNumber`.

## 9. Local EVM Execution
**POC: Implemented**

`myotis-evm` embeds Hyperledger Besu's standalone `org.hyperledger.besu:evm` artifact and runs it against a SNAP-backed `StateOracle`.

- `DefaultEvmExecutor` runs a transaction-shaped call against state served from snap/1; every read verified by Merkle-Patricia proof against a verified `stateRoot`. Resolves EIP-7702 delegation designators (`0xef0100‖address`) one hop so calls against delegated EOAs execute the delegate's code.
- `PrefetchingEvmExecutor` runs a multi-hop speculative discovery loop (sentinel runs that record accesses without blocking), batch-fetches each hop's misses in parallel (semaphore-bounded so a 1000-token balance sweep doesn't flood one peer), then runs for real against a warm cache — eliminates the round-trip-per-SLOAD latency that would otherwise dominate. A result is only returned from a run where every read hit the verified cache.
- `CcipReadEvmExecutor` handles ERC-3668 off-chain lookups (see Section 6).
- Bytecode verified via `keccak256(code) == codeHash` against the proof-verified account. Block context (`block.number`, `coinbase`, `prevRandao`, `baseFeePerGas`, `gasLimit`, `chainId`) supplied from a verified header.
- Exposed over JSON-RPC as **`eth_call`** (arbitrary view calls — ERC-20 metadata, balances, multicall) and **`eth_estimateGas`** (Section 8); also drives ENS resolution. `:myotis-evm:test` covers the executor stack with deterministic fixtures.

**Not implemented:**
- Pre-flight transaction simulation as a distinct surface (catch reverts before broadcast) — `eth_call`/`eth_estimateGas` cover the mechanism; no dedicated "simulate" command.
- Snap-peer reliability: a cold head-context build (header-chain anchor + first snap fetch on a fresh peer) can take ~15 s; warm calls are ~1 s.

## 10. Wallet Integration — Verified JSON-RPC + Android
**POC: Implemented (MetaMask end-to-end)**

The `jsonrpc-server` module exposes the verification pipeline as a standard Ethereum JSON-RPC endpoint (Kotlin/Ktor) so an **unmodified wallet** can use a Myotis node directly. `RpcRouter` maps the API onto a host-agnostic `MyotisRpcBackend` interface; the Android `NodeService` and the CLI daemon each implement it against their own connector + beacon state. **Strict permissionless mode** is the default — there is no trusted-RPC fallback; an unservable request returns `-32601` (not served verified) or `-32000` (can't answer right now), never proxied data. (A dev-only upstream proxy exists solely to discover what a wallet calls and is disabled in strict mode.)

Verified methods served: `eth_chainId`, `net_version`, `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_call`, `eth_estimateGas`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`, `eth_getBlockByNumber`, `eth_getTransactionReceipt`, `eth_getTransactionByHash`, `eth_sendRawTransaction`. (See README → *Wallet API* for the per-method verification basis.) Wallet-specific quirks handled: reads pinned to a near-head block number are served from the verified head's state (a stale historical pin is rejected); `eth_getBlockByNumber`/receipts work without a snap peer via the beacon optimistic anchor.

**Android** (`android-app`, minSdk 29) runs the entire stack on-device — devp2p, libp2p, the light client, the local EVM, and the JSON-RPC server — as a foreground `NodeService`. Mobile-specific work that made this real:

- Pure-Java Milagro BLS replaces the jblst JNI dep (ART has no JNI for it); sync-committee verification is sped up with subgroup-skip, parallel + cached pubkey decompression, and a period gate so a finality verify is ~1 pairing rather than ~512 decompressions.
- discv4 on ART needed a fixed receive-buffer allocator (large `NEIGHBORS` packets were truncated); EL DNS-ENR discovery provides a discv4-independent dial path on CGNAT networks.
- Crypto-provider ordering for discv5 AES; Besu-on-Android compatibility (tuweni dedup, Guava JRE variant, Caffeine pin).
- Warm-restart persistence: the verified sync snapshot, the known-state-root window (sidecar), and light-client-capable CL peers are all cached, so a restart reaches `SYNCED` in ~10 s instead of re-bootstrapping from the embedded checkpoint.

**Validated:** MetaMask pointed at the device renders its confirm screen from verified balances, fees, and a local gas estimate, then broadcasts a real signed transaction — fully permissionless, no proxy.

**Not implemented / rough edges:**
- Cold head-context build latency (~15 s first call after a rebuild; warm ~1 s) — a snap-peer warm-context reliability problem.
- `eth_getLogs`, `eth_subscribe`/WebSocket, batch nuances beyond the basics, and other less-common wallet methods.

## Summary

| Architecture Section                 | Status          | Key Gap                                        |
|--------------------------------------|-----------------|------------------------------------------------|
| 1. Sync Committees (CL light client) | **Implemented** | —                                              |
| 2. Historical Block Verification     | **Partial**     | No accumulator snapshots, 8192-block limit     |
| 3. TrueBlocks Transaction History    | **Implemented** | TrueBlocks index unverified/stale; per-tx verification now exists via `eth_getTransactionByHash` |
| 4. Block Data via devp2p             | **Implemented** | No EIP-4444 fallback                            |
| 5. State Data via SNAP               | **Implemented** | No `GetTrieNodes`, no NFT/Vyper support        |
| 6. ENS Resolution                    | **Implemented** | Reverse lookup has no IPC command surface yet  |
| 7. Transaction Submission            | **Implemented** | Direct `Transactions` broadcast only; no pooled-tx gossip |
| 8. Gas Estimation                    | **Implemented** | —                                              |
| 9. Local EVM Execution               | **Implemented** | Snap cold-context latency                       |
| 10. Wallet Integration (JSON-RPC + Android) | **Implemented** | Cold-call latency; fewer-used RPC methods, no WS/`eth_getLogs` |

The core verification pipeline (sync committees → state root → Merkle proofs → local EVM) is functional end-to-end, and is now exposed as a verified JSON-RPC endpoint that a stock MetaMask uses to read, estimate, and **send a real transaction** — running entirely on an Android phone, with no trusted RPC provider. The biggest remaining work is hardening: snap-peer/warm-context reliability (cold-call latency), historical-block verification (accumulators), and broader RPC-method coverage.
