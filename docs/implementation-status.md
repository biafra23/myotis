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

## 6. ENS Resolution — Via SNAP Storage Proofs
**Not implemented**

The primitives exist (storage proofs work), but there is no ENS-specific command or logic to do the multi-step registry -> resolver lookup.

## 7. Submitting Signed Transactions — devp2p Transaction Gossip
**Not implemented**

No `Transactions`, `NewPooledTransactionHashes`, or `GetPooledTransactions` message handling. The eth handler only covers handshake + block header/body + snap queries.

## 8. Gas Estimation
**Not implemented**

`baseFeePerGas` is available in `BlockHeader` and returned in `get-block`, but there is no dedicated gas estimation command or priority fee calculation logic.

## Summary

| Architecture Section                 | Status          | Key Gap                                        |
|--------------------------------------|-----------------|------------------------------------------------|
| 1. Sync Committees (CL light client) | **Implemented** | No discv5, hardcoded CL peers                  |
| 2. Historical Block Verification     | **Partial**     | No accumulator snapshots, 8192-block limit     |
| 3. TrueBlocks Transaction History    | **Implemented** | No tx verification against `transactionsRoot`  |
| 4. Block Data via devp2p             | **Implemented** | No `GetReceipts`, no EIP-4444                  |
| 5. State Data via SNAP               | **Implemented** | No `GetTrieNodes`, no NFT/Vyper support        |
| 6. ENS Resolution                    | **Not started** | Primitives exist, no ENS logic                 |
| 7. Transaction Submission            | **Not started** | No tx gossip messages                          |
| 8. Gas Estimation                    | **Not started** | `baseFeePerGas` available but no command       |

The core verification pipeline (sync committees -> state root -> Merkle proofs) is fully functional end-to-end. The biggest gaps are on the "wallet action" side: submitting transactions, ENS, and gas estimation.
