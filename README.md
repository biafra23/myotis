<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/myotis_logo_dark.svg">
    <img src="assets/myotis_logo.svg" alt="Myotis logo" width="200">
  </picture>
</p>

# devp2p Playground

An Ethereum devp2p implementation in Java 21 based on tuweni libraries meant to run on Android devices eventually. Connects to the Ethereum mainnet (or testnets) using the devp2p protocol stack: discv4 peer discovery, RLPx encrypted transport, and eth/67-69 sub-protocol. Includes a beacon chain light client for consensus-layer state root verification and snap/1 support for account and storage lookups with Merkle proofs and cryptographic verification back to beacon chain finality.

## Documentation

- [Architecture](docs/architecture-doc.md) — Describes the target design for how the library will obtain and cryptographically verify all Ethereum data without relying on JSON-RPC providers; not all parts are implemented yet.
- [Benefits](docs/benefits-doc.md) — Explains why a trustless wallet matters and what risks centralized RPC providers pose to users.
- [Implementation Status](docs/implementation-status.md) — Current implementation progress and what remains to be done.

## Requirements

- Java 21+
- Gradle (wrapper included)

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

The application operates in two modes: **daemon** and **client**. The daemon discovers peers, maintains connections, and listens for commands on a Unix domain socket (`/tmp/ethp2p.sock`). The client sends a single command to the running daemon and exits.

### Start the daemon

```bash
# Mainnet (default)
./gradlew :app:run

# Testnet
./gradlew :app:run -Pnetwork=sepolia
./gradlew :app:run -Pnetwork=holesky

# Custom port (default: 30303)
./gradlew :app:run -Pport=30304
```

The daemon runs in the foreground. It discovers peers via discv4 (Kademlia DHT), establishes RLPx encrypted connections, and performs eth protocol handshakes. A beacon chain light client syncs finalized state roots from the consensus layer.

### Stop the daemon

```bash
./gradlew :app:run -Pargs=stop
```

## Query commands

All commands are sent to the running daemon via IPC. Responses are JSON.

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
| `snapPeers` | long | Ready peers that also support snap/1 |
| `backedOffPeers` | long | Peers in temporary exponential backoff |
| `blacklistedPeers` | long | Peers permanently blacklisted (incompatible network) |

### Peers

```bash
./gradlew :app:run -Pargs=peers
```

Returns discovered peers (from the Kademlia table) and connected peers with their state, snap support, and client ID.

### Beacon status

```bash
./gradlew :app:run -Pargs=beacon-status
```

Returns beacon chain light client sync state.

| Field | Type | Description |
|-------|------|-------------|
| `state` | string | `"SYNCING"` or `"SYNCED"` |
| `finalizedSlot` | long | Latest finalized beacon slot (0 if not synced) |
| `optimisticSlot` | long | Latest optimistic (attested but not finalized) slot |
| `syncCommitteePeriod` | long | Current sync committee period (finalizedSlot / 8192, only when `SYNCED`) |
| `executionStateRoot` | string/null | Verified execution state root (null if not synced) |
| `executionBlockNumber` | long | Finalized execution block number (only when `SYNCED`) |
| `knownStateRoots` | int | State roots in the rolling window cache (only when `SYNCED`) |
| `peers` | array | Connected beacon peers (see below) |

**Peer fields** (in the `peers` array):

| Field | Type | Description |
|-------|------|-------------|
| `peerId` | string | Truncated libp2p peer ID |
| `remoteAddress` | string | Peer's network address |
| `clientId` | string | Client identification string (if available) |
| `lightClient` | boolean | Whether peer supports the light client protocol |
| `protocols` | int | Number of advertised protocols |

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

### Get transactions

```bash
./gradlew :app:run -Pargs="get-transactions 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
```

Returns all transactions for an address by looking them up in the [TrueBlocks Unchained Index](https://trueblocks.io/). Results are streamed as JSON-Lines (one JSON object per transaction), followed by a summary object.

**How it works:**

1. Fetches the TrueBlocks manifest from IPFS (hardcoded CID: "[QmUBS83qjRmXmSgEvZADVv2ch47137jkgNbqfVVxQep5Y1](https://ipfs.unchainedindex.io/ipfs/QmUBS83qjRmXmSgEvZADVv2ch47137jkgNbqfVVxQep5Y1)")
2. For each chunk in the manifest (scanned from newest to oldest blocks):
   - Downloads the Bloom filter and checks if the address appears
   - On a Bloom hit, downloads the index chunk and extracts appearance records (block number + transaction index)
3. For each appearance, fetches the block header and body from devp2p peers and extracts the raw transaction
4. Parses the transaction RLP into human-readable fields (supports legacy, EIP-2930, EIP-1559, and EIP-4844 transaction types)

**Transaction fields:**

| Field | Type | Description |
|-------|------|-------------|
| `blockNumber` | long | Block containing the transaction |
| `transactionIndex` | int | Position within the block |
| `type` | int | Transaction type (0=legacy, 1=EIP-2930, 2=EIP-1559, 3=EIP-4844) |
| `nonce` | long | Sender's transaction count |
| `to` | string | Recipient address (absent for contract creation) |
| `value` | string | Value transferred in wei (hex) |
| `gasLimit` | long | Gas limit |
| `gasPrice` | string | Gas price in wei (type 0-1, hex) |
| `maxPriorityFeePerGas` | string | Priority fee (type 2-3, hex) |
| `maxFeePerGas` | string | Max fee (type 2-3, hex) |
| `maxFeePerBlobGas` | string | Max blob fee (type 3, hex) |
| `chainId` | long | Chain ID (type 1-3) |
| `data` | string | Input data (hex, absent if empty) |
| `rawTx` | string | Full raw transaction bytes (hex) |
| `verified` | boolean | Always `false` (see limitations below) |

The stream ends with `{"ok":true,"done":true,"totalTransactions":N}`.

**Limitations:**

- **Blocks are not verified.** Individual transactions are not yet verified against the block's `transactionsRoot`. The `verified` field is always `false`. This means a malicious peer could serve tampered transaction data. Verification against the transactions trie is planned but not implemented.
- **The Unchained Index is stale.** The manifest CID is hardcoded and points to a snapshot of the TrueBlocks index that is not kept up to date. Transactions in recent blocks will not be found. There is currently no mechanism to dynamically update the manifest CID.
- **Completeness is not guaranteed.** IPFS content-addressing guarantees the index data has not been tampered with, but it does not guarantee all appearances for an address are present. If the TrueBlocks index has missing entries (due to indexing gaps or incomplete coverage), transactions will be silently missed. A future mitigation is balance reconciliation -- computing the expected balance from fetched transactions and comparing it against the on-chain balance via snap proofs.
- **Signature and access list data not returned.** The parsed JSON omits signature fields (v, r, s), access list details (type 1-2), and blob versioned hashes (type 3).

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

## Beacon chain light client

The daemon includes a consensus-layer light client that tracks finalized state roots from the beacon chain. This enables trustless verification of account and storage proofs against the canonical chain state.

### Trust model

The only trust anchors are **sync committee BLS signatures** and the embedded historical hash accumulators. All data from devp2p and libp2p peers is cryptographically verified -- no trusted third-party RPCs or HTTP APIs are used in production.

The bootstrap trust anchor is a 32-byte mainnet block root hardcoded in `NetworkConfig.MAINNET.checkpointRoot`. Every `LightClientBootstrap` response is rejected unless `hash_tree_root(response.header)` equals this committed value, so the pin is cryptographic: no peer (libp2p or HTTP checkpoint endpoint) can substitute a different anchor, even an internally-consistent one, without finding a SHA-256 preimage.

Ethereum's weak-subjectivity window is only ~28 hours of stake-weighted safety, so the committed root needs to be refreshed periodically or binaries eventually age past the safety envelope. The repo ships with a Gradle task that fetches a current finalized root, cross-validates it against multiple independent providers, and rewrites the `@checkpoint:mainnet` region of `NetworkConfig.java`:

```bash
# Preview the diff without writing
./gradlew refreshMainnetCheckpoint -Pdry

# Fetch + write (commit the resulting NetworkConfig.java diff)
./gradlew refreshMainnetCheckpoint
```

The task queries `/eth/v2/beacon/blocks/finalized` on three independent mainnet checkpoint providers (beaconstate.info, sync-mainnet.beaconcha.in, mainnet-checkpoint-sync.attestant.io), normalizes to the oldest observed finalized slot, re-queries each provider for the canonical block root at that slot, and requires byte-for-byte agreement before writing. Any disagreement aborts without modifying the source.

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

## Architecture

Three Gradle modules:

- **core** -- cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** -- protocol layers, all Netty-based:
  - `discv4` -- UDP peer discovery (ping/pong/findnode/neighbors)
  - `rlpx` -- TCP transport with EIP-8 ECIES handshake and AES-256-CTR framed channel
  - `eth` -- eth/67-69 sub-protocol (hello, status, block headers/bodies)
  - `snap` -- snap/1 sub-protocol (account range, storage range queries with Merkle proofs)
- **consensus** -- beacon chain light client (sync committee BLS verification), Merkle-Patricia proof verification
- **app** -- daemon/CLI entry point, Unix domain socket IPC server, peer caching

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

Both discv4 (EL) and libp2p (CL) get their initial peer lists from three sources, merged at startup:

1. **Hardcoded fallback** in `NetworkConfig` — a handful of IPv4 bootnodes and CL multiaddrs that ship with the binary.
2. **On-disk cache** (`PeerCache`, `CLPeerCache`) — peers that responded successfully on a prior run, loaded from `~/.ethp2p/*-peers.cache`.
3. **EIP-1459 DNS-based ENR trees** — each network can list `enrtree://<base32-pubkey>@<domain>` URLs in `NetworkConfig.elEnrTreeUrls` / `clEnrTreeUrls`. At startup the daemon walks each tree over DNS TXT records, verifies the root record's secp256k1 signature against the embedded pubkey, and decodes the leaf ENRs. Results are merged into the EL bootnode list and the CL peer list. Mainnet currently pins the Ethereum Foundation canonical tree (`all.mainnet.ethdisco.net`); the resolver is implemented in `networking/dns/DnsEnrResolver`.

DNS resolution is best-effort: on timeout, missing TXT records, or signature mismatch the daemon logs a warning and starts up with whatever the hardcoded + cached sources provide. Per-tree deadline defaults to 10 s.

### Key dependencies

- **Tuweni 2.7.2** -- RLP encoding, SECP256K1, byte utilities
- **Netty 4.2.x (modified)** -- NIO transport. Uses a modified Netty archive based on 4.2 that has been rewritten in Kotlin. This is a proof-of-concept for migrating the Java codebase to Kotlin to enable use in a Compose Multiplatform project
- **BouncyCastle** -- SECP256K1 crypto provider
- **jvm-libp2p** -- beacon chain P2P networking (consensus module)
- **dnsjava 3.6** -- TXT-record resolution for EIP-1459 ENR tree walks
