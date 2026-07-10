<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/myotis_logo_dark.svg">
    <img src="assets/myotis_logo.svg" alt="Myotis logo" width="200">
  </picture>
</p>

# myotis

Myotis is a **trustless Ethereum wallet engine** — a full participant in Ethereum's peer-to-peer networks that runs **on an Android phone** (minSdk 29) and answers a wallet's requests with cryptographically verified data, with **no trusted RPC provider in the loop**. It speaks devp2p on the execution layer (discv4 discovery, RLPx encrypted transport, eth/66-69, and snap/1 state proofs) and libp2p on the consensus layer (a beacon-chain light client), and verifies every byte against sync-committee BLS signatures back to beacon-chain finality. The same engine runs as a desktop daemon/CLI for development.

A built-in **JSON-RPC server** exposes a verified subset of the Ethereum API over HTTP, so an **unmodified MetaMask** — pointed at the phone — can read balances, simulate calls, estimate gas, suggest fees, and **broadcast a real transaction**, all served from locally verified state. Nothing is taken on a peer's word: account and storage reads carry Merkle-Patricia proofs against a beacon-anchored `stateRoot`; blocks, transactions, and receipts are verified against the header's `transactionsRoot`/`receiptsRoot`; `eth_call`/`eth_estimateGas` run in a local EVM over proof-served state. When a request can't be answered from verified data, it returns an error rather than falling back to a trusted source.

> **Status:** End-to-end verified `send` works on a real device — MetaMask renders the confirm screen from verified balances, fees, and a local gas estimate, then broadcasts the signed transaction over devp2p, with no proxy and no permissioned service. The remaining gaps are listed in [Implementation Status](docs/implementation-status.md).

Built in Java 21 on the [tuweni](https://github.com/apache/incubator-tuweni) libraries (RLP, SECP256K1, byte utilities; via a Kotlin-rewrite fork), with in-house SSZ and Merkle-Patricia verification, a pure-Java BLS verifier, and an embedded Hyperledger Besu EVM. JVM 17 bytecode where the Android consumer needs it; long-term direction is Kotlin + Compose Multiplatform.

## Documentation

- [Architecture](docs/architecture-doc.md) — Describes the target design for how the library will obtain and cryptographically verify all Ethereum data without relying on JSON-RPC providers; not all parts are implemented yet.
- [Benefits](docs/benefits-doc.md) — Explains why a trustless wallet matters and what risks centralized RPC providers pose to users.
- [Implementation Status](docs/implementation-status.md) — Current implementation progress and what remains to be done.
- [Re-Implementation Specification](docs/reimplementation/README.md) — A language-agnostic spec for rebuilding Myotis (everything except the Android-specific host) as a cross-platform engine in Go or Rust, consumable from Desktop, Android, and iOS apps.

## Wallet API — verified JSON-RPC over HTTP

The Android app runs an embedded JSON-RPC server (Ktor, **loopback-only `127.0.0.1:8545`**) that an on-device wallet talks to like any other Ethereum endpoint. Every method is answered **only** from cryptographically verified data; there is no trusted-RPC fallback in production (a dev-only upstream proxy exists purely to map what a wallet needs and is off in strict mode). When a request can't be served verified, the server returns a JSON-RPC error:

- `-32601` — the method isn't served verified at all (the wallet can stop asking).
- `-32000` — the method is implemented but can't be answered right now (not synced, no snap peer, or the head isn't beacon-anchored yet — retryable).

> **Security:** the server binds **loopback only** by default — the wallet is a same-device client, and the endpoint is unauthenticated with no TLS or rate limiting (and `eth_sendRawTransaction` relays whatever signed bytes it's handed), so it is deliberately not reachable from other devices. Exposing it on a routable interface would require an explicit, opt-in change.

**Connecting MetaMask:** MetaMask runs on the same device as the node. Add a custom network pointing at `http://localhost:8545` (chain id 1 for mainnet). The desktop daemon does **not** serve JSON-RPC — it exposes the same verified operations over its CLI/IPC socket (see *Query commands* below).

### Implemented (verified) methods

| Method | How it's verified |
|---|---|
| `eth_chainId`, `net_version` | from config |
| `eth_blockNumber` | beacon optimistic-head execution block number |
| `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | snap/1 Merkle-Patricia proof against a beacon-anchored `stateRoot` (absent accounts/slots proven via exclusion proof — a verified zero, not a guess) |
| `eth_call` | local Besu EVM over proof-served state; multi-hop speculative prefetch batches the SLOAD round-trips |
| `eth_estimateGas` | local EVM gas metering (intrinsic + EVM + 15% buffer); a plain transfer to an EOA short-circuits to 21000; a reverting tx returns an error, never a number |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` | base fee from verified headers; priority-fee tips from block bodies verified against `transactionsRoot` (+ receipts vs `receiptsRoot` for the gas-weighted percentile reward walk) |
| `eth_getBlockByNumber` | verified header window anchored to the beacon head; tx hashes checked against `transactionsRoot` (no snap peer required) |
| `eth_getTransactionReceipt` | scans the recent verified block window; receipts verified against `receiptsRoot` (handles eth/69 bloomless receipts by recomputing the bloom) |
| `eth_getTransactionByHash` | mined txs from the verified block window; locally-broadcast txs served as *pending* from a sent-tx cache; sender recovered from the signature (legacy + EIP-2930/1559/4844/7702) |
| `eth_sendRawTransaction` | gossips the user-signed bytes to devp2p peers and returns the hash (Myotis never signs — the wallet does) |

A number-pinned read (wallets pin every read to the block they just saw) is served from the verified head's state when the pinned block is at/near the head; a genuinely historical pin is rejected rather than answered with newer state.

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

Myotis runs in three forms: the **Android app** and the **desktop app** (both Compose GUIs over the shared `:ui`, running the wallet node with the verified JSON-RPC server), and the **desktop daemon/CLI** (the same engine for development, with a CLI/IPC command surface). All three run the full devp2p + libp2p stack, the beacon light client, and the local EVM.

### Android

```bash
# Build + install the debug app on a connected device
./gradlew :android-app:installDebug
```

The app runs the node as a foreground `NodeService` (Start/Stop in the UI). Once it reaches `SYNCED`, the JSON-RPC server is live on `127.0.0.1:8545`; point an on-device MetaMask at `http://localhost:8545` (custom network, chain id 1). The app persists the sync snapshot, the known-state-root window, and light-client-capable peers, so warm restarts reach `SYNCED` in ~10 s. minSdk 29.

### Desktop app (GUI)

`:app-desktop` is the Compose-Multiplatform desktop GUI — the same `:ui` NodeScreen the Android app hosts, driving the Java backend in-process. It shows sync status, peers, and the Logs tab, and serves the same verified JSON-RPC.

```bash
# Run from source (dev loop) — starts the GUI, compiling the Rust engine first
./gradlew :app-desktop:run

# Pick the engine: java (default) | rust | auto
./gradlew :app-desktop:run -Pengine=rust
```

Build a native installer for the host OS with jpackage. **jpackage is host-OS-bound**: the `.dmg` can only be produced on macOS and the `.deb` only on Linux (CI builds each on its matching runner — `desktop-dmg.yml` / `desktop-linux-deb.yml`); locally you get the format for your platform.

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

The bundle embeds a full Java 21 runtime (the `:networking`/`:myotis-evm` backend ships Java-21 classes and reaches JDK modules reflectively, so the whole module graph is included). Packaged builds currently ship the Java engine; the Rust engine is loaded only on the `run`/`syncSmoke` dev tasks until the packaging PR bundles the native lib. Logs roll under `~/.myotis/logs`; adjust the app log level with `-Dmyotis.log.level`.

### Desktop daemon

The daemon discovers peers, maintains connections, and listens for CLI commands on a Unix domain socket (`/tmp/ethp2p.sock`); it exposes the verified operations as CLI commands (`get-account`, `get-storage`, `resolve-ens`, …), not JSON-RPC. A **client** invocation sends a single command to the running daemon and exits.

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
./gradlew refreshGnosisCheckpoint

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

To run Gnosis **alongside** mainnet on the same host, give it a separate port
(mainnet keeps 30303) — the daemons are otherwise independent processes:

```bash
./gradlew :app:run -Pnetwork=gnosis -Pport=30304
```

> Note: verified-state queries (`get-account`/`get-storage`) require an active
> EL peer that serves `snap/1`. Public Gnosis nodes are fewer and busier than
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
queries:

| Command | Requires |
|---------|----------|
| `status`, `peers`, `dial` | daemon running |
| `beacon-status` | daemon running (state progresses `SYNCING` → `CATCHING_UP` → `SYNCED`) |
| `get-headers`, `get-block`, `get-transactions` | at least one peer in `READY` state (check with `peers`) |
| `get-account`, `get-storage` | at least one peer with `snap=true` in `READY` state |
| `get-account`, `get-storage`, `get-block` (full beacon verification — `verifyMethod` populated, `beaconChainVerified=true`) | `beacon-status` returns `"state":"SYNCED"` |
| `resolve-ens` | at least one peer with `snap=true` in `READY` state |

Account and storage queries return data with a Merkle proof against
the peer's `stateRoot` even before the beacon light client reaches
`SYNCED` — but the response will report `beaconChainVerified=false`
with `failReason: "beaconNotSynced"`. Wait for `SYNCED` if you need
the full beacon-anchored trust chain.

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
| `state` | string | `"SYNCING"` (no trust anchor yet), `"CATCHING_UP"` (anchor present, but the state-root window is still sparse or the held sync committee lags wall clock), or `"SYNCED"` (verification-ready; can regress to `CATCHING_UP` if the node falls behind) |
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
2. A local EVM (Hyperledger Besu's standalone EVM module) executes a single `resolve(bytes name, bytes data)` call to the ENS Universal Resolver. Every account field, storage slot, and contract bytecode the EVM reads is fetched on demand via snap/1 and verified by Merkle-Patricia proof against that `stateRoot`.
3. If the call reverts with `OffchainLookup` (ERC-3668), the daemon fetches the gateway response over HTTPS and re-enters the EVM with the resolver's callback. The callback validates the gateway's response on-chain — typically by checking a signer's signature against a list of trusted signers embedded in the resolver — so a malicious gateway cannot inject a wrong answer.
4. The Universal Resolver's return value is decoded as the resolved address.

**Resolution root (trust vs freshness):**

The state ENS executes against is configurable via `io.myotis.ens.EnsResolutionRoot`:

- **`AUTO` (default)** — resolve against the beacon-verified finalized state first; if that yields no address (the record didn't exist at the finalized block — e.g. a name registered or an `addr()` first set in the last ~12 min) or errors (a snap peer doesn't retain that block's state), fall back to the peer head. You get a beacon-verified mapping (`beaconVerified=true`) whenever one exists, and brand-new names still resolve (`beaconVerified=false`, peer-claimed). A record that *changed* in the last ~12 min resolves to its verified-but-stale finalized value (staleness, not a failure) — AUTO only falls back when finalized returns *no* address.
- **`FINALIZED`** — finalized state only; no fallback. Always `beaconVerified=true`, but brand-new names return "does not resolve."
- **`PEER_HEAD`** — resolve against a snap peer's latest head state. Freshest possible data, but the head root is the peer's *claim*, not beacon-attested, so the mapping is peer-claimed (`beaconVerified=false`). Choose this when you need the very latest ENS state and accept the weaker trust. (On Android, set via `NodeService.setEnsResolutionRoot(...)`.)

**Trust model:**

- **State**: every read backed by a Merkle proof against the `stateRoot` — beacon-verified in `FINALIZED` mode.
- **Bytecode**: verified by `keccak256(code) == codeHash` from the proof-verified account.
- **CCIP-Read gateways**: trusted only for *availability* — the resolver's callback validates the response cryptographically. A lying gateway causes the call to revert, surfacing as a clean failure.

The same trust model and resolution root apply to every other `resolve-ens-*` command.

**Networks:** mainnet, sepolia, and holesky have canonical Registry + Universal Resolver addresses pinned. Other networks fail with `ENS not pinned for chain id …`.

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

The same machinery serves the other networks: `./gradlew refreshSepoliaCheckpoint` refreshes the `@checkpoint:sepolia` region from the eth-clients sepolia checkpoint providers, and `./gradlew refreshGnosisCheckpoint` refreshes `@checkpoint:gnosis` (its own task — Gnosis exposes a different API slice and fewer providers).

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

Eight Gradle modules:

- **core** -- cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** -- protocol layers, all Netty-based:
  - `discv4` -- UDP peer discovery (ping/pong/findnode/neighbors)
  - `discv5` -- UDP CL peer discovery (wraps ConsenSys' `io.consensys.protocols:discovery`)
  - `rlpx` -- TCP transport with EIP-8 ECIES handshake and AES-256-CTR framed channel
  - `eth` -- eth/66-69 sub-protocol (hello, status, block headers/bodies, receipts, transaction gossip)
  - `snap` -- snap/1 sub-protocol (account range, storage range, bytecode, with Merkle proofs)
- **consensus** -- beacon chain light client (sync committee BLS verification), Merkle-Patricia proof verification
- **myotis-evm** -- Hyperledger Besu EVM running against a SNAP-backed `StateOracle`. Powers ENS resolution, `eth_call`, and local gas estimation (`DefaultEvmExecutor.estimateGas` — intrinsic + EVM-metered + 15% safety buffer). Includes `CcipReadEvmExecutor` for ERC-3668 off-chain lookups and `PrefetchingEvmExecutor` (multi-hop speculative prefetch) to amortize SNAP round-trips.
- **myotis-ens** -- ENS resolver (`EnsResolver`, `ReverseLookup`) using the Universal Resolver via the local EVM. Forward and reverse resolution, ENSIP-10 wildcards, ERC-3668 off-chain records.
- **jsonrpc-server** -- host-agnostic verified JSON-RPC router (Kotlin/Ktor). `RpcRouter` maps the Ethereum API onto a `MyotisRpcBackend` interface that the Android `NodeService` implements against its connector + beacon state. Strict permissionless mode by default; binds loopback only. (Consumed by `android-app`; the daemon uses its own CLI/IPC surface instead.)
- **app** -- daemon/CLI entry point, Unix domain socket IPC server, peer caching
- **android-app** -- the Android wallet node (`NodeService` foreground service). Runs the full devp2p + libp2p stack, the local EVM, and the JSON-RPC server on-device, with Android-native peer/snapshot caching and a Compose UI; persists the sync snapshot, the known-state-root window, and light-client-capable peers for fast warm restarts (~10 s vs. a cold checkpoint bootstrap).

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
2. **On-disk cache** (`PeerCache`, `CLPeerCache`) — peers that responded successfully on a prior run. The daemon writes `peers[-<network>].cache` / `cl-peers[-<network>].cache` (plus `sync-state[-<network>].snapshot`) into its working directory; the Android app keeps the same files in the app's cache dir (`getCacheDir()`).
3. **EIP-1459 DNS-based ENR trees** — each network can list `enrtree://<base32-pubkey>@<domain>` URLs in `NetworkConfig.elEnrTreeUrls` / `clEnrTreeUrls`. At startup the daemon walks each tree over DNS TXT records, verifies the root record's secp256k1 signature against the embedded pubkey, and decodes the leaf ENRs. Results are merged into the EL bootnode list and the CL peer list. Mainnet currently pins the Ethereum Foundation canonical tree (`all.mainnet.ethdisco.net`); the resolver is implemented in `networking/dns/DnsEnrResolver`.

DNS resolution is best-effort: on timeout, missing TXT records, or signature mismatch the daemon logs a warning and starts up with whatever the hardcoded + cached sources provide. Per-tree deadline defaults to 10 s.

### Key dependencies

- **Tuweni 2.7.2** (`tuweni-kotlin` fork, `2.7.2-jvm17.1`) -- RLP encoding, SECP256K1, byte utilities
- **Netty 4.2.x (modified)** -- NIO transport. Uses a modified Netty archive based on 4.2 that has been rewritten in Kotlin. This is a proof-of-concept for migrating the Java codebase to Kotlin to enable use in a Compose Multiplatform project
- **BouncyCastle** -- SECP256K1 crypto provider
- **jvm-libp2p** -- beacon chain P2P networking (consensus module)
- **dnsjava 3.6** -- TXT-record resolution for EIP-1459 ENR tree walks
