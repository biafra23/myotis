# Trustless Ethereum Wallet Library - Data Acquisition & Verification

## Overview

This document describes how a trustless Ethereum wallet library obtains and verifies all data necessary to display account balances, transaction history, and token holdings — without relying on JSON-RPC providers for correctness. The library participates directly in Ethereum's peer-to-peer networks and verifies all data cryptographically against trusted roots.

The trust model: the only external trust assumption is the sync committee mechanism (≥2/3 of a 512-validator subset is honest). Everything else is verified locally via Merkle proofs, signatures, or accumulator commitments.

> **Implementation status (where the design meets reality):** The verification pipeline below is realized end-to-end and surfaced to wallets as a **verified JSON-RPC endpoint** (Section 10) running **on an Android phone**. An unmodified MetaMask pointed at the node reads balances, simulates calls, estimates gas, suggests fees, and **broadcasts a real transaction**, all from locally verified data — no trusted RPC provider. The parts of this document that are still aspirational (historical accumulators, TrueBlocks completeness proofs, background-sync scheduling) are called out in [Implementation Status](implementation-status.md); the data-acquisition and verification core is built.

### Data the Wallet Needs

For each user-controlled address, the wallet must provide:

- **ETH balance** and **nonce** (for constructing transactions)
- **ERC-20 token balances** (for display and transfers)
- **NFT ownership** (ERC-721 and ERC-1155 balances, verified the same way as ERC-20 tokens via contract storage proofs)
- **Transaction history** (which transactions affected this address and in which blocks)
- **Current gas parameters** (base fee, priority fee estimates)
- A way to **submit signed transactions** to the network

---

## 1. Establishing a Trusted Chain Head — Sync Committees

### What We Get

A cryptographically verified recent block header, containing a trusted `stateRoot` (for state verification) and `blockHash`/`blockRoot` (for block data verification).

### How It Works

The Ethereum beacon chain designates a randomly selected subset of 512 validators as the *sync committee*, rotating every ~27 hours (256 epochs). Sync committee members sign every beacon block header they see. A light client can follow the chain by:

1. **Bootstrapping** from a known trusted checkpoint (a finalized beacon block root). This can be hardcoded at build time or obtained from a trusted source. The bootstrap response includes the current sync committee's public keys.
2. **Syncing forward** by requesting `LightClientUpdate` messages from beacon chain peers via libp2p (the consensus layer's p2p protocol). Each update contains:
   - An attested beacon block header
   - The aggregate BLS signature from the sync committee
   - A bitfield showing which committee members signed
   - The next sync committee (for committee rotation)
   - A finality proof (Merkle branch to the finalized checkpoint)
3. **Verifying** each update by checking the aggregate BLS signature against the known sync committee public keys, and verifying that a supermajority (≥2/3 of 512) signed.

### What We Extract

From the verified beacon block header, we obtain the `ExecutionPayloadHeader` via a Merkle proof against the beacon state root. This gives us:

- `stateRoot` — commitment to the entire Ethereum state at this block
- `blockHash` — the execution block hash
- `blockNumber` — the block height
- `baseFeePerGas` — current base fee (needed for gas estimation)
- `receiptsRoot` — commitment to all transaction receipts
- `transactionsRoot` — commitment to all transactions in the block

### Networking

Sync committee data is obtained via **libp2p** (the consensus layer p2p network), using the light client sync protocol defined in the Altair consensus spec. The relevant request/response protocols are:

- `LightClientBootstrap` — initial sync from a checkpoint
- `LightClientUpdatesByRange` — batch updates for catching up
- `LightClientFinalityUpdate` — finality notifications
- `LightClientOptimisticUpdate` — latest head tracking

Peer discovery uses **discv5** (the consensus layer's discovery protocol), which operates over UDP and uses a Kademlia DHT. ENRs (Ethereum Node Records) advertise the node's capabilities, so we can find peers that serve light client data.

---

## 2. Verifying Historical Blocks — Trusted Accumulator Snapshots

### The Problem

Sync committees only provide trust for recent blocks (post-Altair, post-Merge). To verify historical block headers — for example, when displaying old transaction history — we need a different mechanism.

### How It Works

The beacon chain state contains `historical_summaries` (introduced in Capella, replacing the earlier `historical_roots`). These are an append-only list of `HistoricalSummary` records, each committing to 8192 slots (256 epochs, roughly 27 hours) worth of beacon block roots and state roots via Merkle trees.

Given a trusted recent beacon state root (from sync committees), we can:

1. Obtain the `historical_summaries` list via a Merkle proof against the beacon state root.
2. For any past epoch, look up the corresponding `HistoricalSummary` which contains `block_summary_root` — a Merkle root over 8192 beacon block roots.
3. Prove that a specific beacon block root belongs to that epoch via a Merkle proof against the `block_summary_root`.
4. From the proven historical beacon block, extract the execution payload header (which contains the execution block hash, state root, etc.) via another Merkle proof.

### Accumulator Snapshots

To avoid downloading the full historical chain data at runtime, we use **pre-computed accumulator snapshots** bundled with the app. This approach was adopted from Portal Network client implementations, where a similar accumulator snapshot mechanism is used to verify execution layer block headers — allowing them to be trusted without replaying the full chain from genesis.

A snapshot is a serialized list of roots (epoch hashes for pre-Merge, historical roots for post-Merge) bundled as a binary resource. On launch, the app loads the snapshot directly and uses it as the root of trust for Merkle proof verification. The snapshot itself is trusted implicitly by virtue of being bundled with the application binary — there is no runtime cryptographic verification of the accumulator.

This allows the app to verify any historical execution block header by chaining: **bundled accumulator → historical beacon block root → execution block header**.

### Pre-Merge Blocks

Blocks before the Merge (September 2022) are not committed to by the beacon chain. For these, the app uses a pre-computed epoch hash accumulator (`premergeacc.bin`) distributed with the app — a one-time trust assumption made at build time.

---

## 3. Transaction History — TrueBlocks via IPFS

### The Problem

To show a user their transaction history, the wallet needs to know *which blocks contain transactions relevant to a given address*. Scanning every block is infeasible on a mobile device.

### How TrueBlocks Works

TrueBlocks maintains an address-appearance index — a mapping from Ethereum addresses to the list of (block number, transaction index) pairs where that address appears. This index is called the "Unchained Index" and is published as chunks on IPFS.

### Data Flow

1. **Discover index chunks**: TrueBlocks publishes a manifest (also on IPFS) that describes the available index chunks and their IPFS CIDs (content identifiers). The manifest's CID is published to a smart contract on-chain (the Unchained Index contract).
2. **Fetch relevant chunks via IPFS**: Given a user's address, determine which chunk(s) cover the address's hash range. Fetch those chunks by CID from the IPFS network. Since chunks are content-addressed, they are tamper-evident — if the data doesn't hash to the expected CID, it's rejected.
3. **Fallback to HTTP gateway**: If direct IPFS p2p retrieval is unavailable or too slow (especially on mobile), fall back to an IPFS HTTP gateway (e.g., `dweb.link`, `ipfs.io`, or a self-hosted gateway). The content-addressing property means the gateway cannot tamper with the data without detection — the CID acts as a checksum. However, note that using public HTTP gateways leaks the user's IP address and queried CIDs to the gateway operator, which is a privacy tradeoff compared to direct IPFS p2p retrieval.
4. **Extract appearances**: Parse the index chunk to get the list of `(blockNumber, txIndex)` pairs for the user's address.

### Verification

- IPFS content is verified by its CID (a cryptographic hash of the content). Tampered data will not match the expected CID.
- The TrueBlocks manifest itself should be verified against a known source (ENS name resolution or hardcoded/signed manifest hash).
- Individual transaction data fetched from blocks is verified against the block's `transactionsRoot` (see next section).

### Completeness Caveat

IPFS content-addressing guarantees *integrity* (the data has not been tampered with) but not *completeness* (that all appearances are present). If the TrueBlocks index has missing entries — whether due to indexing bugs, incomplete data, or a maliciously curated index — the wallet would silently miss transactions. There is no cryptographic proof that the index contains every appearance for a given address.

A possible mitigation is **balance reconciliation**: after fetching all known transactions from the index and computing the expected balance by summing all incoming and outgoing value transfers (both native ETH and ERC-20 token transfers), compare the result against the verified on-chain balance obtained via SNAP. If there is a discrepancy, the wallet can warn the user that the transaction history may be incomplete. This does not identify which transactions are missing, but it detects that something is missing.

This completeness limitation would be resolved by EIP-7919 (Pureth Meta), which enables verifiable completion proofs for address-relevant data at the protocol level (see Alternative Solutions below).

---

## 4. Fetching and Verifying Block Data — devp2p

### The Problem

After TrueBlocks tells us which blocks contain relevant transactions, we need to fetch the actual block data (headers, transaction bodies, receipts) and verify it.

### How It Works

We participate in the **execution layer p2p network (devp2p)** using the `eth` protocol. The relevant messages are:

- `GetBlockHeaders` — request block headers by number or hash
- `GetBlockBodies` — request transaction lists and uncle headers for blocks
- `GetReceipts` — request transaction receipts for blocks

### Verification

Each piece of data is verified against commitments in the block header (which we've already verified via sync committees or the historical accumulator):

1. **Block header**: The header hash must match the `blockHash` from the verified beacon block execution payload.
2. **Transactions**: The transaction list is Merkleized into a trie. The root of this trie must match the `transactionsRoot` in the verified header. Each individual transaction can be proven via a Merkle proof against this root.
3. **Receipts**: Similarly, receipts form a trie whose root must match the `receiptsRoot` in the verified header. This is needed to confirm whether a transaction succeeded or reverted, and to extract event logs (e.g., ERC-20 Transfer events).

### Peer Discovery

Execution layer peer discovery uses **discv4** (UDP-based Kademlia DHT). Nodes publish ENRs that advertise their capabilities, including which sub-protocols they support (`eth`, `snap`, etc.). Additionally, **DNS discovery** provides curated node lists — the Ethereum Foundation maintains DNS trees (e.g., `all.mainnet.ethdisco.net`) that can be used for initial bootstrapping.

The wallet maintains a local database of known peers, caching nodes that have responded well in previous sessions to avoid cold-start latency.

### History Expiry (EIP-4444)

EIP-4444 (History Expiry) means execution clients will stop serving historical block data older than approximately one year over the `eth` devp2p protocol. As this is progressively adopted, the `eth` protocol will become unreliable for fetching older block bodies, transactions, and receipts.

For historical data beyond the retention window, several fallback options exist:

- **Portal History Network**: The Portal Network has pivoted from a standalone network to being integrated into execution layer clients. While this integration no longer supports verifying arbitrary blocks without being a full node, the Portal History Network (the sub-network specifically responsible for historical block data) is likely usable for retrieving unverified historical block data. The extent of this implementation is still evolving and worth tracking.
- **Alternative data sources**: As noted in the Alternative Solutions section, block data verification is transport-agnostic. Historical blocks could be served from IPFS, a dedicated server, or any other data store — the wallet verifies them independently against trusted header roots regardless of the source.
- **Near-term assumption**: In practice, it is reasonable to assume that a sufficient number of `eth` peers (particularly archive nodes and long-running geth instances) will continue serving historical data for some time before widespread pruning occurs. If this assumption breaks before a decentralized alternative matures, a fallback to a centralized data server would be necessary — with no loss of trust, since the data is verified locally regardless of its source.

---

## 5. State Data — SNAP Protocol

### The Problem

To display ETH balances, nonces, and ERC-20 token balances, the wallet needs current state data for the user's accounts. This state lives in Ethereum's Merkle-Patricia Trie, committed to by the `stateRoot` in each block header.

### How It Works

The wallet participates in the execution layer p2p network and negotiates the **`snap` sub-protocol** alongside `eth`. The SNAP protocol (specified at `ethereum/devp2p/caps/snap.md`) provides several relevant message types:

#### For ETH Balance and Nonce

Use `GetAccountRange` to request accounts from the state trie:

- **Parameters**: `rootHash` (the verified `stateRoot`), `startingHash` (set to `keccak256(address)` or slightly before), `limitHash` (set to just after `keccak256(address)`), `responseBytes` (byte cap).
- **Response**: A list of accounts in the requested range, plus **Merkle proofs** for the range boundaries.
- Each account record contains: `nonce`, `balance`, `storageRoot`, `codeHash`.

Alternatively, use `GetTrieNodes` to request specific trie nodes by path:

- Compute the path as the nibbles of `keccak256(address)`.
- Request the trie nodes along that path from root to leaf.
- Assemble the Merkle proof locally from the returned nodes.

`GetTrieNodes` may be preferable for single-account lookups as it avoids returning unnecessary neighboring accounts and resembles normal trie healing traffic.

#### For ERC-20 Token Balances

ERC-20 balances are stored in the **storage trie** of the token contract. This requires two levels of proof:

1. **Account proof**: Prove the token contract's account exists in the state trie (as above). This gives us the contract's `storageRoot`.
2. **Storage proof**: Use `GetStorageRanges` to request storage slots from the contract's storage trie:
   - **Parameters**: `rootHash` (the `stateRoot`), `accounts` (the contract address hash), `origin`/`limit` (narrow range around the target storage slot hash), `responseBytes`.
   - **Response**: Storage slot data plus Merkle proofs.
   - For standard ERC-20 contracts, the balance of address `A` is stored at slot `keccak256(abi.encode(A, uint256(slot)))`, where `slot` is typically 0 or 1 (the position of the `balanceOf` mapping in the contract's storage layout). The exact slot depends on the contract — it must be determined per token contract (known for major tokens, discoverable via storage layout metadata for verified contracts). Note that contracts written in Vyper (used by protocols like Curve Finance) use a different hashing formulation for storage mappings than Solidity. A robust implementation will need to distinguish between Solidity and Vyper contracts to compute storage slots correctly.

Alternatively, `GetTrieNodes` can be used here as well, requesting specific paths within the storage trie.

**NFTs (ERC-721 / ERC-1155)** work identically — ownership and balance data are stored in contract storage mappings with different slot layouts but the same proof mechanism. NFT metadata (images, names) is typically fetched from IPFS or HTTP URLs referenced in the contract's `tokenURI` storage; this is untrusted display data that does not affect verified ownership.

### Verification

All SNAP responses include Merkle proofs that are verified locally against the trusted `stateRoot`:

1. The Merkle-Patricia proof links the returned account/storage data back to the `stateRoot` we obtained from the verified block header (via sync committees).
2. If the proof does not verify, the data is rejected and the peer is deprioritized.
3. **Key property**: the serving peer cannot forge data. They can only withhold it (refuse to respond or return empty results). This means we trust SNAP peers only for *data availability*, never for *completeness*.

### Peer Discovery for SNAP

SNAP-capable peers are discovered through the same mechanisms as `eth` peers (discv4, DNS discovery). Nodes advertise SNAP support in their ENR records (the `"snap"` key). The wallet filters discovered peers for those advertising SNAP capability and maintains a local cache of responsive SNAP peers.

For a wallet with a handful of addresses, the total SNAP traffic per session is minimal — perhaps 5-20 requests at app launch. This is negligible load on serving peers.

---

## 6. ENS Resolution — Via Local EVM over SNAP-Verified State

### The Problem

When a user wants to send to a human-readable name like `vitalik.eth` instead of a raw address, the wallet needs to resolve that name. Beyond plain forward resolution, modern wallet UIs also need text records (`avatar`, `description`, `com.twitter`, …), content hashes (for ENS-pointed websites), multi-coin addresses (BTC/LTC/SOL alongside ETH), and several niche record types (pubkey, ABI, DNS, interface implementer). Every modern resolver also relies on ENSIP-10 wildcard dispatch and ERC-3668 (CCIP-Read) off-chain lookups.

Direct storage reads against the registry and resolver contracts work for vanilla `*.eth` names but break on wildcard names, custom resolvers with non-standard storage layouts, and off-chain records — those would need either contract execution or a minimal RPC concession. We avoid that concession by **executing the resolver contracts in our own local EVM**, with all state reads served from SNAP proofs.

### How It Works

The wallet's `EnsResolver` issues a single call to the **Universal Resolver** — `resolve(bytes name, bytes data)` — for every record type. The Universal Resolver internally walks the registry/resolver chain, handles wildcard names (ENSIP-10), and surfaces ERC-3668 `OffchainLookup` reverts at the call boundary so a higher-level decorator can fetch the off-chain response transparently.

The call runs entirely inside the local EVM. State reads (account fields, storage slots, contract bytecode) are served by a `StateOracle` that fetches them on demand via the snap/1 protocol and verifies every response with a Merkle-Patricia proof against the `stateRoot` from a verified block header.

Supported record types — every one goes through the same Universal Resolver dispatch path, so wildcard + CCIP-Read work identically for all of them:

| Record | Spec | Selector |
|---|---|---|
| Forward address | ENSIP-1 | `addr(bytes32)` |
| Multi-coin address | ENSIP-9 / SLIP-44 | `addr(bytes32, uint256 coinType)` |
| Text records | ENSIP-5 | `text(bytes32, string key)` |
| Content hash | ENSIP-7 | `contenthash(bytes32)` |
| Public key | EIP-619 | `pubkey(bytes32)` |
| ABI metadata | EIP-205 | `ABI(bytes32, uint256 contentTypes)` |
| DNS records | ENSIP-8 | `dnsRecord(bytes32, bytes name, uint16 resource)` |
| Interface implementer | EIP-1820 over ENS | `interfaceImplementer(bytes32, bytes4 interfaceId)` |

Reverse resolution (`address → name`) uses the step-by-step Registry → reverse-resolver path, with a mandatory ENSIP-3 forward-verification round-trip — the resolver's claim is only accepted if a forward lookup of the claimed name returns the original address.

### Off-Chain Resolution (CCIP-Read / ERC-3668)

Modern ENS surfaces — Coinbase IDs (`*.cb.id`), Uniswap names, Base subdomains, and many wildcard resolvers — store records off-chain and require a CCIP-Read round-trip. The flow:

1. The Universal Resolver call reverts with `OffchainLookup(sender, urls, callData, callbackFunction, extraData)`.
2. The wallet POSTs `callData` to one of the gateway `urls` (HTTPS), receiving a signed off-chain response.
3. The wallet re-enters the EVM via `callbackFunction(response, extraData)`, which validates the response on-chain (typically by verifying a signer's signature against a list of trusted gateways the resolver embeds).
4. The callback's return value is the resolved record — and because the callback runs in the same proof-verified EVM, the signature check itself is anchored to the `stateRoot`.

The CCIP-Read flow is implemented as an executor decorator (`CcipReadEvmExecutor`) that wraps the base EVM executor: it catches `OffchainLookup` reverts, performs the gateway HTTP fetch, and re-enters the EVM with the callback. The HTTP transport is an injectable interface (`CcipGateway`) — the daemon supplies a `java.net.http.HttpClient`-backed implementation; the Android consumer supplies a Ktor-backed one.

### Trust Model — Identical Across Record Types

Verifiability is a property of the dispatch path (Universal Resolver call via local EVM over SNAP-verified state, with CCIP-Read callbacks re-entering the same proof-verified EVM), not of the record's selector or return type. Every record type listed above gets the same chain:

- **State reads**: every account field and storage slot accessed during execution is verified by a Merkle-Patricia proof against the `stateRoot` of a verified block header. A peer cannot lie about state without producing a forged proof.
- **Contract bytecode**: bytecode fetched via `GetByteCodes` is verified by checking that its keccak256 matches the `codeHash` field of the (proof-verified) account record.
- **CCIP-Read gateways**: trusted only for *availability*. The resolver's callback validates the gateway's response on-chain — typically by checking a signer's signature against trusted-signers stored on-chain. If the gateway lies, the callback reverts and resolution fails cleanly.
- **Block header**: as elsewhere, anchored to the beacon chain via sync committee BLS signatures and the historical accumulator.

The "interpretation" of returned bytes is a separate concern from verification: we verify that a `contenthash` value is the exact bytes the resolver returned, not that the IPFS hash inside resolves to live content; we verify a multi-coin BTC address is what the resolver stored, not that the bytes form a valid Bitcoin script. Sanity-decoding the value is the caller's responsibility.

### Network Coverage

Canonical Registry + Universal Resolver addresses are pinned for mainnet, sepolia, and holesky (sourced from the `ensdomains/ens-contracts` deployment manifests). `EnsResolver.forChainId(chainId)` picks the right pair; other networks fail fast with a clear error.

---

## 7. Submitting Signed Transactions — devp2p Transaction Gossip

### How It Works

Signed transactions are broadcast to the network using the `eth` protocol's transaction gossip mechanism. The relevant messages are:

- `Transactions` — announce full transactions to connected peers
- `NewPooledTransactionHashes` — announce transaction hashes (peers request full txs if interested)
- `GetPooledTransactions` / `PooledTransactions` — request/response for full transaction bodies

### Process

1. The wallet constructs and signs the transaction locally (standard ECDSA signing over the transaction envelope).
2. The wallet sends the signed transaction to connected `eth` peers using the `Transactions` message.
3. Connected peers validate the transaction (signature, nonce, gas, balance) and propagate it further through the gossip network.
4. The transaction eventually reaches block builders / validators for inclusion.

### Considerations

- The wallet should connect to multiple `eth` peers and broadcast to several of them to reduce the risk of transaction censorship by any single peer.
- Transaction confirmation is detected by monitoring new blocks (via sync committees) for the inclusion of the transaction hash. The receipt can be verified against the block's `receiptsRoot`.
- **Nonce management**: The confirmed nonce is known from the SNAP state query. For pending transactions (submitted but not yet included), the wallet tracks nonces locally and increments for subsequent transactions.
- **Scope limitation**: This transaction gossip mechanism covers standard transactions (ETH transfers, ERC-20/NFT interactions). EIP-4844 blob transactions (used primarily by Layer 2 sequencers) require a separate gossip mechanism for blob sidecars and are out of scope for this wallet.

---

## 8. Gas Estimation

### Base Fee

The `baseFeePerGas` is available directly from the execution payload header obtained via sync committees. No additional RPC call needed.

### Priority Fee

The wallet can estimate priority fees by examining recent blocks it has already fetched. By looking at the priority fees paid by transactions in the last N blocks, a reasonable median or percentile-based estimate can be computed locally.

### Gas Limit

- **Simple ETH transfers to EOAs**: Fixed at 21,000 gas. However, the wallet must first verify that the destination is an Externally Owned Account (EOA) by checking its `codeHash` via a SNAP proof. Sending ETH to a contract address can trigger fallback or receive functions that consume significantly more gas. If the destination is a contract, a conservative higher gas limit should be used.
- **ERC-20 transfers**: Typically 45,000–65,000 gas. A conservative fixed limit (e.g., 100,000) can be used, or a small set of known gas costs for standard contract interaction patterns can be maintained.
- **Complex contract interactions**: Accurate gas estimation for arbitrary contract calls requires EVM simulation with the relevant state. The wallet's local EVM (Section 9) gives us this path natively: `DefaultEvmExecutor.estimateGas` runs the call against SNAP-verified state and returns the Yellow-Paper-correct intrinsic-plus-EVM-metered gas with a 15% safety buffer; revert / OOG halts throw instead of returning a number (callers must not broadcast a doomed transaction). Validated end-to-end against an Anvil fork — the broadcast acceptance test confirms `gasUsed <= localEstimate`. No daemon IPC surface for it yet; the `myotis-tx-builder` wallet integration is the next consumer.

---

## 9. Local EVM Execution — View Calls and Gas Estimation

### The Problem

Some wallet operations cannot be answered by simple state lookups. ENS resolution (Section 6) needs to run resolver bytecode. Gas estimation for arbitrary contract interactions needs to actually execute the call to count consumed gas. ERC-20 metadata reads (`name()`, `symbol()`, `decimals()`) are view calls. Without a local EVM these are all forced through an RPC provider.

### How It Works

The wallet embeds a stripped-down EVM (`myotis-evm`) built around Hyperledger Besu's standalone `org.hyperledger.besu:evm` module. The EVM runs against a `StateOracle` that fetches account fields, storage slots, and contract bytecode on demand from snap/1 peers, verifying every response with a Merkle-Patricia proof against a verified `stateRoot`.

Execution is structured as a stack of decorators around a base `EvmExecutor`:

1. **`DefaultEvmExecutor`** — runs a transaction-shaped call against the SNAP-backed state and returns the execution result (return data, gas used, revert reason, accessed storage paths).
2. **`PrefetchingEvmExecutor`** — wraps the base executor to do a speculative dry-run that records every account/storage access, then warm-loads those into the cache before the real run. Eliminates the round-trip-per-SLOAD latency that would otherwise dominate.
3. **`CcipReadEvmExecutor`** — catches ERC-3668 `OffchainLookup` reverts, fetches the gateway response over HTTPS, and re-enters the EVM with the resolver's callback (Section 6).

### Trust Model

Identical to the SNAP / state-data trust model:

- **State**: every read backed by a Merkle proof against a verified `stateRoot`.
- **Bytecode**: verified by `keccak256(code) == codeHash` against the (proof-verified) account.
- **Block context** (`block.number`, `block.timestamp`, `coinbase`, `prevRandao`, `baseFeePerGas`, `gasLimit`, `chainId`): supplied from a verified block header.
- **No peer trust**: a peer cannot influence execution outcomes by lying about state — they can only refuse to serve, which surfaces as a clean failure rather than a wrong answer.

### Current Use Cases

- **ENS resolution** (`resolve-ens` and the seven `resolve-ens-*` variants): full forward resolution, including ENSIP-10 wildcard names and ERC-3668 off-chain records.
- **Reverse ENS lookup**: address → name with mandatory forward-verification round-trip.
- **Gas estimation** (`DefaultEvmExecutor.estimateGas`): Yellow-Paper-correct intrinsic + Besu-EVM-metered + 15% safety buffer. Acceptance corpus (ETH→EOA / ETH→contract / ERC-20 / ERC-721 / Uniswap V3) cross-checks against `eth_estimateGas` within 5%; an Anvil-fork broadcast test additionally confirms the estimate is sufficient on the wire (`gasUsed <= localEstimate`). No IPC surface yet — the API is ready for `myotis-tx-builder`.

### Current Use Cases (continued)

- **`eth_call`-equivalent view calls**: arbitrary contract reads (ERC-20 metadata, balances, multicall aggregations) are served via `eth_call` (Section 10). A multi-hop speculative-prefetch loop (`PrefetchingEvmExecutor`) batches the SLOAD round-trips so a many-token balance sweep resolves in a couple of network waves instead of one round-trip per slot.

### Future Use Cases

- **Pre-flight checks as a distinct surface**: `eth_call`/`eth_estimateGas` already run a transaction locally and surface reverts (insufficient balance, stale approvals, slippage) as errors; a dedicated "simulate" affordance that decodes the revert reason for the UI is the next step.

---

## 10. Wallet Integration — Verified JSON-RPC Endpoint

### The Problem

Sections 1–9 produce verified data; a wallet needs a way to *ask for it*. Rather than invent a bespoke API and require a custom wallet, Myotis speaks the language wallets already speak: **Ethereum JSON-RPC**. An unmodified wallet (MetaMask) points at the node as if it were any other RPC endpoint.

### How It Works

A host-agnostic router (`jsonrpc-server`, Kotlin/Ktor) maps the Ethereum JSON-RPC API onto a `MyotisRpcBackend` interface. Each host implements the backend against its own stack: the Android `NodeService` and the desktop daemon both delegate to the same `RLPxConnector` / beacon light client / local EVM described above. Every method is answered **only** from the verified pipeline:

| Method(s) | Verification basis |
|---|---|
| `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | snap/1 Merkle-Patricia proof against a beacon-anchored `stateRoot` (Section 5) |
| `eth_call`, `eth_estimateGas` | local EVM over proof-served state (Sections 8–9) |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` | base fee from verified headers; tips from bodies/receipts verified against `transactionsRoot`/`receiptsRoot` (Section 8) |
| `eth_getBlockByNumber`, `eth_getTransactionReceipt`, `eth_getTransactionByHash` | header window anchored to the beacon head; bodies/receipts verified against `transactionsRoot`/`receiptsRoot` (Sections 4, 7) |
| `eth_sendRawTransaction` | devp2p transaction gossip (Section 7) |

### Strict Permissionless Mode

The defining property: **there is no trusted-RPC fallback**. When a request cannot be answered from verified data, the server returns a JSON-RPC error — `-32601` (not served verified at all) or `-32000` (implemented but not answerable right now: not synced, no snap peer, head not yet beacon-anchored) — rather than silently proxying an unverified answer. A wallet thus only ever displays data the node could prove. (A dev-only upstream proxy exists purely to map what a given wallet calls during development and is disabled in strict mode.)

### Running on a Phone

The entire stack — devp2p, libp2p, light client, local EVM, and this JSON-RPC server — runs on-device as an Android foreground service (`android-app`, minSdk 29), addressing the *Resource Constraints* and *Feasibility* sections below in practice: a pure-Java BLS verifier (no JNI), ART-compatible discovery buffers, and persistence of the sync snapshot + known-state-root window + light-client-capable peers for ~10 s warm restarts. MetaMask on the same device, pointed at `localhost:8545`, completes a verified read-simulate-estimate-send flow with no permissioned service in the loop.

---

## Summary: Data Flow on App Launch

```
1. SYNC COMMITTEES (libp2p)
   └─→ Verified recent beacon block header
       └─→ Execution payload: stateRoot, blockHash, baseFeePerGas

2. TRUEBLOCKS INDEX (IPFS, HTTP gateway fallback)
   └─→ List of (blockNumber, txIndex) for user's addresses

3. HISTORICAL VERIFICATION (accumulator snapshot + sync committees)
   └─→ Verified block headers for all historical blocks of interest

4. BLOCK DATA (devp2p eth protocol)
   └─→ Block bodies, transactions, receipts
       └─→ Verified against transactionsRoot, receiptsRoot

5. STATE DATA (devp2p snap protocol)
   └─→ ETH balance, nonce per address
   └─→ ERC-20 balances (storage proofs)
       └─→ Verified against stateRoot

6. LOCAL EVM (Besu evm + SNAP-backed StateOracle)
   └─→ ENS resolution (Universal Resolver + CCIP-Read)
   └─→ Gas estimation (DefaultEvmExecutor.estimateGas)
   └─→ View calls (future)
       └─→ All reads verified against stateRoot

7. TRANSACTION SUBMISSION (devp2p eth protocol)
   └─→ Broadcast signed transactions via gossip

8. WALLET API (JSON-RPC over HTTP, strict permissionless)
   └─→ MetaMask reads balance/nonce/code/storage, eth_call, estimateGas,
       fees, blocks, receipts, getTransactionByHash, sendRawTransaction
       └─→ Every method answered only from the verified pipeline above;
           unservable → JSON-RPC error, never a proxied answer
```

### Network Participation Summary

| Network   | Protocol | Purpose                                     |
|-----------|----------|---------------------------------------------|
| libp2p    | CL light client sync | Sync committees, beacon block headers |
| devp2p    | eth      | Block headers/bodies, tx gossip, receipts   |
| devp2p    | snap     | Account state, storage proofs, bytecode     |
| HTTPS     | CCIP-Read gateway | Off-chain ENS records (ERC-3668)   |
| IPFS      | bitswap  | TrueBlocks index chunks                     |
| discv5    | UDP DHT  | Consensus layer peer discovery              |
| discv4    | UDP DHT  | Execution layer peer discovery              |
| DNS       | TXT      | Bootstrap peer lists                        |
| HTTP      | JSON-RPC | Verified wallet API served to MetaMask (strict, no proxy) |

### Trust Assumptions

| Component           | Trust Assumption                                                  |
|---------------------|-------------------------------------------------------------------|
| Sync committees     | ≥2/3 of 512 randomly selected validators are honest               |
| SNAP peers          | Completeness only — correctness verified via Merkle proofs    |
| devp2p peers        | Completeness only — block data verified against header roots  |
| TrueBlocks / IPFS   | Integrity verified via CID — but completeness is unverifiable; mitigated by balance reconciliation |
| Accumulator snapshot | One-time trust at build/distribution time                        |
| Transaction gossip   | Availability only — need multiple peers to mitigate censorship   |
| Local EVM           | Same as SNAP peers — every state read backed by Merkle proof; bytecode verified by `codeHash`     |
| CCIP-Read gateways  | Availability only — responses validated on-chain by the resolver's callback                       |

---

## Alternative Solutions

Some components described above could be replaced by alternative approaches:

- **TrueBlocks → Verifiable RPC (future)**: Once the changes proposed in EIP-7919 (Pureth Meta) are incorporated into the protocol, TrueBlocks could be replaced by standard RPC calls with attached correctness and completion proofs. Pureth Meta bundles a suite of underlying protocol changes (such as introducing SSZ transaction and receipt roots) that make RPC data mathematically verifiable — making it possible to query for address-relevant transactions from any untrusted RPC provider and verify the response locally. This would eliminate the dependency on TrueBlocks' off-chain index and IPFS distribution. However, EIP-7919 is not yet scheduled for inclusion in a specific hard fork (it is proposed for Glamsterdam), so TrueBlocks remains necessary for the foreseeable future.

- **TrueBlocks index updates via Swarm**: The existing TrueBlocks Unchained Index is published on IPFS and will remain the source for historical index chunks. However, for incremental index updates published by the wallet operator to close the gap between the current TrueBlocks head and the chain head, Swarm is a viable alternative to IPFS. Swarm's postage stamp mechanism provides economic guarantees of data availability without requiring the operator to maintain a pinning node, which would otherwise reintroduce a centralised dependency. This would require the client to speak to a second P2P network (Swarm in addition to IPFS) and adds complexity, so it is better suited as a future optimisation than a v1 requirement.

- **Block data via IPFS or other storage**: Block data (headers, bodies, receipts) does not need to come from devp2p peers specifically. Since all block data is verified independently against the trusted block header roots (from sync committees or the historical accumulator), the data can be sourced from any storage layer — IPFS, Bittorrent, a CDN, a centralized API, or even a USB stick. The verification is transport-agnostic. devp2p is the default because the peer network is large and readily available, but any data source that can provide the raw block bytes is equally valid.

---

## Resource Constraints — Mobile Mitigation

Maintaining p2p connections, syncing headers, and fetching state data has non-trivial battery and bandwidth costs on mobile devices. The following strategy mitigates this:

- **Background sync on favorable conditions**: The app registers a periodic background task (e.g., Android WorkManager) that wakes every few hours. If it detects unmetered internet (Wi-Fi) and the device is charging, it performs background sync: advancing the sync committee chain, refreshing the peer database, pre-fetching state for known addresses, and caching any new TrueBlocks index chunks. This keeps the wallet's data reasonably fresh without draining battery during normal use. As part of this background sync, the app also scans the **gap between the most recently indexed TrueBlocks chunk and the current chain head** — the window during which new transactions may not yet be covered by the index. This is done efficiently by first fetching block headers only and checking the bloom filter for relevant ERC-20 activity; full block bodies are only fetched for blocks that produce a bloom filter hit, or when a balance reconciliation mismatch suggests a plain ETH transfer may have occurred in the gap. In most sessions the reconciliation will pass and no gap scanning is needed at all.
- **Session-based foreground connectivity**: When the user actively opens the app, it establishes p2p connections, performs any remaining sync, fetches current state, and displays up-to-date data. Connections are torn down when the app goes to background.
- **Aggressive caching**: Peer lists, accumulator snapshots, TrueBlocks index chunks, and recent sync committee data are all persisted locally so that cold starts are fast and require minimal network activity.

---

## Feasibility of Implementation

The implementation does not start from zero. Key components are already available or have been proven feasible:

- **Consensus and execution layer base libraries**: The required cryptographic and networking primitives (BLS signature verification, SSZ serialization, RLP encoding, Merkle-Patricia trie operations, devp2p/RLPx, libp2p) exist in Java/Kotlin within **Teku** (ConsenSys' consensus layer client) and **Besu** (Hyperledger's execution layer client). Creating a proof-of-concept by extracting and using these libraries is fairly straightforward and avoids implementing wire protocols and cryptographic verification from scratch. However, both are heavy, enterprise-grade JVM applications not designed for mobile. Making the extracted components resource-efficient and performant on Android (adapting the networking layer, reducing memory footprint, optimizing for the Android Runtime) would require significant refactoring effort beyond the initial PoC.

- **TrueBlocks integration**: TrueBlocks is already available and was part of a previous project by the author. The index format, IPFS retrieval, and address lookup logic are proven and understood.

- **Portal Network client on Android**: The same previous project included running the Portal Network client **Samba** on Android to retrieve verified historical block data. This demonstrated that a Portal Network client can be made to run on Android with minimal modifications to the codebase. While modifications were necessary (and will be necessary again when upstream updates are available), the overall approach is validated. This experience also confirms that the libp2p/discv5 networking stack is viable on Android hardware.

---

## Open Questions

1. **SNAP peer behavior**: Will SNAP-capable peers reliably serve small account range requests or individual trie node requests from a non-syncing client? Initial testing needed.
2. **ERC-20 storage slot discovery**: How to reliably determine the storage slot for `balanceOf` mappings across arbitrary ERC-20 contracts without RPC access to call `eth_getStorageAt` or read verified contract metadata.
3. **Mobile networking constraints**: Battery and bandwidth impact of maintaining devp2p and libp2p connections on Android. May require aggressive connection pooling and session-based connectivity (connect on app open, disconnect on close).
4. **Transaction inclusion monitoring**: Efficient polling strategy for detecting transaction confirmation without maintaining persistent p2p connections.
5. **Pre-Merge history**: Whether to support verified display of pre-Merge transactions, and if so, what trust assumption for the pre-Merge block hash chain.
6. **Annual address rotation as an EIP-4444 mitigation**: For users who are comfortable creating a new EOA, the wallet could rotate to a fresh address annually and sweep all funds across. This keeps the oldest relevant block for any active address within the ~1 year EIP-4444 retention window, making historical block pruning a non-issue. Old addresses would remain monitored for incoming transactions, but only for new activity — no historical block data would be needed for them. This is only viable as an opt-in flow for users who accept the UX tradeoff; it should not be forced on all users.
