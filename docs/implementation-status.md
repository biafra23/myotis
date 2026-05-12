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
- Transaction verification against `transactionsRoot` (the `verified` field is always `false`)
- Dynamic manifest CID discovery (hardcoded, stale)
- Balance reconciliation for completeness checking

## 4. Fetching and Verifying Block Data — devp2p
**POC: Implemented**

- Full devp2p stack: discv4 discovery, RLPx ECIES handshake, eth/67-69 protocol
- `GetBlockHeaders` and `GetBlockBodies` implemented
- Block header verification against beacon chain (direct state root match or header chain)
- EIP-1459 DNS-based bootnode discovery (`DnsEnrResolver`, `EnrTreeUrl`) runs on startup and is merged with the hardcoded bootnode list. Mainnet EL tree is `enrtree://…@all.mainnet.ethdisco.net`; CL tree is intentionally empty pending a canonical tree.
- Peer caching across sessions: the devp2p cache (`PeerCache`) is append-only with deduplication; the CL peer cache (`CLPeerCache`) evicts peers after 3 consecutive failures and resets the counter on success. Cache writes are synchronized so parallel appends and rewrites can't interleave.

**Not implemented:**
- `GetReceipts` — receipt fetching and verification against `receiptsRoot`
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
**POC: Implemented**

Resolution runs the ENS contracts in a local EVM (`myotis-evm`, see Section 9) with state served from SNAP proofs.

- Forward resolution via the **Universal Resolver** (`resolve(bytes,bytes)`) — handles wildcard names (ENSIP-10) and surfaces ERC-3668 reverts. Implementation in `myotis-ens/EnsResolver`.
- **CCIP-Read (ERC-3668)** end-to-end: `OffchainLookup` reverts caught by `CcipReadEvmExecutor`, gateway HTTP fetch via injectable `CcipGateway` (daemon supplies a `java.net.http`-backed impl; Android consumer supplies a Ktor-backed one), callback re-entry into the EVM. Validated against the EIP-3668 demo gateway and Coinbase IDs (`*.cb.id`).
- **Reverse resolution** (`address → name`) with mandatory ENSIP-3 forward-verification round-trip — the resolver's claim is rejected if a forward lookup of the claimed name doesn't return the original address.
- IPC command: `resolve-ens <name>` returns `{"resolved":bool, "address":"0x...", "blockNumber":N}`.

Validated against mainnet: `vitalik.eth`, `1.offchainexample.eth` (CCIP-Read demo), `jesse.cb.id` (Coinbase gateway).

**Not implemented:**
- Forward resolution of L2 / cross-chain names that depend on resolver behaviour beyond the Universal Resolver path
- Profile fields beyond `addr(bytes32)` (text records, content hash, multi-coin addresses)

## 7. Submitting Signed Transactions — devp2p Transaction Gossip
**Not implemented**

No `Transactions`, `NewPooledTransactionHashes`, or `GetPooledTransactions` message handling. The eth handler only covers handshake + block header/body + snap queries.

## 8. Gas Estimation
**POC: Implemented**

`DefaultEvmExecutor.estimateGas(UnsignedTransaction, BlockContext)` returns a Yellow-Paper-correct intrinsic + Besu-EVM-metered + 15%-buffer estimate. Revert and OOG halts throw rather than return a number (callers must not broadcast a doomed transaction). Out of scope for v1: contract creation, EIP-2930 access lists, EIP-3860 init-code, binary-search refinement.

Acceptance corpus (`MainnetGasEstimationIT`, env-gated): ETH→EOA, ETH→contract (WETH deposit), ERC-20 transfer (USDC), ERC-721 transfer (ENS BaseRegistrar), Uniswap V3 exact-input swap. Each cross-checks against `eth_estimateGas` from a reference RPC within 5% when the operator supplies `MYOTIS_INTEGRATION_<NAME>_REFERENCE_GAS`.

The headline end-to-end acceptance (`AnvilForkedBroadcastIT`) builds a transaction with the locally-estimated gas, broadcasts it to an Anvil fork of mainnet (via `anvil_impersonateAccount`), and asserts the receipt succeeds without OOG and `gasUsed <= localEstimate`. This proves the 15% safety buffer is actually sufficient on the wire — a property the 5%-of-reference cross-check alone can't guarantee.

`baseFeePerGas` is exposed via `get-block`. The plan's wallet integration (switching the tx-builder from fixed limits to `estimateGas`) is deferred to whenever `myotis-tx-builder` lands; the API is ready. The local EVM (Section 9) gives us the simulation path natively — wiring it through to a `gas-estimate` IPC command is straightforward, just not done yet.

## 9. Local EVM Execution
**POC: Implemented**

`myotis-evm` embeds Hyperledger Besu's standalone `org.hyperledger.besu:evm` artifact and runs it against a SNAP-backed `StateOracle`.

- `DefaultEvmExecutor` runs a transaction-shaped call against state served from snap/1; every read verified by Merkle-Patricia proof against a verified `stateRoot`.
- `PrefetchingEvmExecutor` does a speculative dry-run to record accessed paths, then warm-loads them before the real run — eliminates the round-trip-per-SLOAD latency that would otherwise dominate.
- `CcipReadEvmExecutor` handles ERC-3668 off-chain lookups (see Section 6).
- Bytecode verified via `keccak256(code) == codeHash` against the proof-verified account. Block context (`block.number`, `coinbase`, `prevRandao`, `baseFeePerGas`, `gasLimit`, `chainId`) supplied from a verified header.
- Currently used for ENS resolution; `:myotis-evm:test` covers the executor stack with deterministic fixtures.

**Not implemented:**
- `eth_call`-equivalent IPC command for arbitrary view calls (ERC-20 metadata, NFT `tokenURI`, multicall)
- Gas-estimate IPC command (the executor's `estimateGas` works; Section 8 covers the implementation, just no daemon surface yet)
- Pre-flight transaction simulation (catch reverts before broadcast)

## Summary

| Architecture Section                 | Status          | Key Gap                                        |
|--------------------------------------|-----------------|------------------------------------------------|
| 1. Sync Committees (CL light client) | **Implemented** | —                                              |
| 2. Historical Block Verification     | **Partial**     | No accumulator snapshots, 8192-block limit     |
| 3. TrueBlocks Transaction History    | **Implemented** | No tx verification against `transactionsRoot`  |
| 4. Block Data via devp2p             | **Implemented** | No `GetReceipts`, no EIP-4444                  |
| 5. State Data via SNAP               | **Implemented** | No `GetTrieNodes`, no NFT/Vyper support        |
| 6. ENS Resolution                    | **Implemented** | No text records / multi-coin addrs             |
| 7. Transaction Submission            | **Not started** | No tx gossip messages                          |
| 8. Gas Estimation                    | **Implemented** | No IPC surface yet (executor API ready)        |
| 9. Local EVM Execution               | **Implemented** | No generic view-call / gas-estimate IPC yet    |

The core verification pipeline (sync committees → state root → Merkle proofs → local EVM) is functional end-to-end. ENS resolution including CCIP-Read is validated on mainnet. The biggest remaining gaps are on the "wallet action" side: submitting transactions and exposing the EVM as a generic view-call / gas-estimate surface.
