# Myotis — Language-Agnostic Re-Implementation Specification

> A complete description of **Myotis** sufficient to re-implement it from scratch in
> another language (e.g. **Go** or **Rust**) as a **cross-platform engine/framework**
> consumable from Desktop, Android, and iOS apps.

This is the **master document**. It gives the whole picture: what Myotis is, its trust
model, its architecture, the engine API surface to expose, the dependency mapping from
the JVM reference implementation to Go/Rust, and how to package the result as a
multi-platform library. Wire-level protocol detail lives in four companion documents:

| Companion | Covers |
|---|---|
| [`01-consensus-light-client.md`](01-consensus-light-client.md) | The trust root: beacon sync-committee light client — BLS12-381, SSZ, the light-client protocol, libp2p req/resp, fork digests |
| [`02-execution-networking.md`](02-execution-networking.md) | devp2p: discv4, discv5, EIP-1459 DNS discovery, RLPx (ECIES + framing), the `eth` and `snap` sub-protocols |
| [`03-state-verification-and-evm.md`](03-state-verification-and-evm.md) | Merkle-Patricia proof verification, the SNAP state oracle, the local EVM stack, gas estimation, ABI, CCIP-Read, ENS |
| [`04-engine-and-hosts.md`](04-engine-and-hosts.md) | The reusable engine (`ChainStack`/`NodeRegistry`), platform ports, the verified backend, IPC + JSON-RPC host surfaces, persistence, concurrency |

> **Scope note.** The request is to re-implement *everything except the Android-specific
> parts*. Concretely: re-implement the **engine** (all protocols + verification + the
> verified-read backend) and at least one **desktop host** (CLI/daemon). The Android and
> iOS *host* shells (foreground service, platform UI, platform cache files) are **out of
> scope**, but the engine must stay **consumable from Android and iOS** — so its public
> API must use FFI-friendly, library-neutral types and inject everything
> platform-specific through ports (see §5, §8). This is exactly how the reference
> codebase is already factored: a small `node-core` engine that both a JVM daemon and an
> Android service host identically.

---

## 1. What Myotis Is

Myotis is a **trust-minimized Ethereum light client** that doubles as a **wallet
backend engine**. It connects directly to Ethereum's peer-to-peer networks and
**cryptographically verifies every piece of data it returns** — balances, nonces,
contract storage, code, `eth_call` results, gas estimates, blocks, transactions,
receipts, and ENS names — **without trusting any JSON-RPC provider for correctness**.

The reference implementation runs the entire stack (devp2p, libp2p, the beacon light
client, a local EVM, and a verified JSON-RPC endpoint) on-device, including on an
Android phone, and an unmodified MetaMask pointed at it can read balances, estimate
gas, and broadcast a real transaction — all from locally verified data, with no
trusted RPC in the loop.

### Why it exists

Every mainstream wallet (MetaMask, Rainbow, Trust, Coinbase Wallet) ultimately asks a
**centralized JSON-RPC server** ("what is my balance?") and displays the answer with no
verification. A small number of providers (Infura, Alchemy) serve the majority of wallet
traffic; they can be pressured/censored, can go down, can surveil, and — for most data —
**cannot be checked**. `eth_getProof` helps for state but covers a narrow slice and is
worthless if the provider feeds you a false block hash to begin with. Transaction history
carries no completeness proof at all.

Myotis closes this: **balances are proven, not reported**; the chain head is established
through **sync-committee mathematics, not authority**; transactions are **broadcast
peer-to-peer**; and queries are spread across random peers to reduce surveillance. It is,
in effect, Ethereum's missing **SPV-grade light client** for the full account/token/smart-
contract model.

### What it delivers to a wallet (the product surface)

- **ETH balance & nonce** (for building transactions) — SNAP state proofs.
- **ERC-20 / NFT balances** — contract storage proofs (same mechanism).
- **`eth_call` view calls & gas estimation** — a local EVM over proof-served state.
- **ENS resolution** — forward/reverse, all record types, wildcard (ENSIP-10), and
  off-chain (CCIP-Read / ERC-3668), by executing resolver bytecode in the local EVM.
- **Blocks / transactions / receipts** — verified against `transactionsRoot` /
  `receiptsRoot` of beacon-anchored headers.
- **Fee suggestions** — base fee from verified headers, tips from verified bodies.
- **Transaction submission** — gossiped directly to peers over devp2p.
- **A stock Ethereum JSON-RPC endpoint** — so unmodified wallets "just work."

---

## 2. Trust Model — the crux of the whole system

Re-implementers must internalize this before writing any code. **Get the trust model
wrong and the project is pointless** — it becomes just another unverified client.

### The only trust anchors

1. **Sync-committee BLS signatures.** The beacon chain designates 512 validators as a
   *sync committee*, rotating every period (8192 slots, ~27 h on mainnet). They sign
   every beacon block header. The assumption — the *same one Ethereum itself rests on* —
   is that **≥2/3 of those 512 are honest**.
2. **An embedded weak-subjectivity checkpoint** — a 32-byte finalized beacon block root
   (+ its slot), hardcoded per network. Bootstrap is pinned to this root; without the pin
   an adversary could serve an internally consistent bootstrap for a chain they control.
3. *(Designed, not yet built in the reference)* **embedded historical accumulators** —
   a pre-Merge epoch-hash accumulator and a post-Merge historical-roots accumulator — for
   verifying deep historical headers. See §10.

**Everything else is derived by verification, never trusted:**

- **EL state** (accounts, storage, code): Merkle-Patricia proofs verified against a
  `stateRoot` that is itself beacon-anchored.
- **Block bodies / transactions / receipts**: rebuilt into their tries and checked
  against the header's `transactionsRoot` / `receiptsRoot`.
- **Bytecode**: accepted only if `keccak256(code) == codeHash` from a proven account leaf.
- **The execution payload** (EL state root, block hash, number, base fee): bound to the
  BLS-signed *beacon* header by a Merkle "execution branch" — the signature covers only
  the beacon header, so this branch is what extends trust to the EL.
- **CCIP-Read gateway responses**: untrusted data carriers; trust comes from re-executing
  the resolver's callback against proof-verified state (the contract validates the
  gateway's signature on-chain).

### Peers are trusted for *availability*, never *correctness*

A peer **cannot forge** data — a bad proof is rejected and the peer is deprioritized.
A peer **can only withhold** (refuse / return empty), which surfaces as a clean failure,
never a wrong answer. This holds for SNAP peers, devp2p block peers, libp2p CL peers, and
CCIP gateways alike.

### Strict permissionless mode

The production posture is **no trusted-RPC fallback**. When a request can't be answered
from verified data, the engine returns an **error** (`-32601` not served verified, or
`-32000` can't answer right now: not synced / no peer / head not anchored) — it **never**
proxies an unverified answer. A wallet therefore only ever displays data the node could
prove. (A dev-only upstream proxy exists purely to discover what a wallet calls and is
disabled in strict mode.)

### Data sources are P2P only

- **devp2p** (`eth`, `snap`) and **libp2p** (CL light-client req/resp) are the *only*
  production data sources. Calling a local full client over HTTP is permitted **for
  debugging only**, never for production.
- **The Portal Network is effectively dead** — its reference clients (Trin, Fluffy) are
  abandoned. Do **not** design around Portal as available infrastructure. Anything Portal
  would have solved (deep historical state/blocks) must be solved another way. *(If you
  ever find credible evidence Portal has been revived, flag it loudly — it would cover a
  lot of wallet needs.)*

### One deliberate, bounded exception

The **pending-nonce overlay**: for transactions *this node itself broadcast and signed*,
the next nonce is tracked locally and may *only raise* the verified mined nonce, TTL-bounded.
This is the single value not backed by a proof — and it is bounded by the node's own
ECDSA-authenticated broadcast, not peer data.

---

## 3. End-to-End Data Flow & the Verification Chain

### Launch sequence (per network)

```
1. CONSENSUS (libp2p)        Bootstrap from the embedded checkpoint → verify sync-committee
                             BLS signatures forward → a verified recent beacon block header.
                             Extract the ExecutionPayloadHeader (Merkle "execution branch"):
                                stateRoot, blockHash, blockNumber, baseFeePerGas.

2. EXECUTION DISCOVERY       discv4 (UDP Kademlia) + EIP-1459 DNS + direct enode dials find
                             eth/snap peers; RLPx (ECIES handshake → AES-CTR framed channel)
                             connects; eth handshake (Hello → Status) reaches READY.

3. STATE (devp2p snap)       GetAccountRange / GetStorageRanges return data + Merkle proofs,
                             verified against the beacon-anchored stateRoot.

4. BLOCK DATA (devp2p eth)   GetBlockHeaders / GetBlockBodies / GetReceipts; bodies & receipts
                             verified by rebuilding their tries vs transactionsRoot/receiptsRoot.

5. LOCAL EVM (over SNAP)     eth_call / estimateGas / ENS run resolver & contract bytecode
                             against proof-served state; CCIP-Read callbacks re-enter the EVM.

6. TX SUBMISSION (devp2p)    Signed raw tx gossiped to peers via the Transactions message.

7. WALLET API (JSON-RPC)     Stock eth_* served on loopback, strictly from verified data.
```

### The verification chain (what anchors every answer)

```
embedded checkpoint root
   └─(checkpoint pin: hash_tree_root(bootstrap header) == checkpoint)
beacon sync committee (512 BLS pubkeys, Merkle-proven into the pinned header's state)
   └─(≥2/3 aggregate BLS signature over each attested beacon header)
verified beacon block header  ── finality branch ──> finalized header
   └─(execution branch: Merkle proof of ExecutionPayloadHeader into the beacon body)
EL execution payload header (stateRoot, blockHash, number, baseFee)
   ├─(direct stateRootMatch)  OR  (header-chain walk: parent-hash chain from the
   │                               beacon-attested block hash, ≤ 8192 blocks)
   └──> trusted EL stateRoot / blockHash
          ├─ MPT account proof  → nonce, balance, storageRoot, codeHash
          ├─ MPT storage proof (anchored at the account's storageRoot) → slot value
          ├─ bytecode: keccak256(code) == codeHash
          ├─ bodies/txs:  rebuilt trie root == transactionsRoot
          └─ receipts:    rebuilt trie root == receiptsRoot
```

Two strategies tie a peer-served header to the beacon chain:
**`stateRootMatch`** (the header's `stateRoot` equals a beacon-attested root directly) and,
as a fallback, **`headerChain`** (walk parent hashes from the beacon-attested block hash
down to the target header, each link pinned by the previous header's `keccak256(RLP)`;
bounded by `MAX_HEADER_CHAIN_GAP = 8192`). The integration tests assert results carry
`"verifyMethod":"headerChain"` once the beacon client is `SYNCED`.

> **SSZ vs MPT — never mix them.** Consensus-layer hashing is **SHA-256 + little-endian
> SSZ merkleization**. Execution-layer hashing is **keccak-256 + big-endian RLP + Merkle-
> Patricia tries**. Two different hash functions, two different encodings, two different
> trie shapes. Mixing them is a classic re-implementation bug.

---

## 4. System Architecture

### Module map (reference JVM layout → re-implementation guidance)

The reference is an 11-module Gradle build. For a Go/Rust port, collapse to crates/packages
along these lines (the engine boundary matters far more than the exact split):

| Reference module | Responsibility | Re-impl crate/pkg | Notes |
|---|---|---|---|
| `core` | secp256k1 identity, `BlockHeader`, ENR, **MPT proof verifier**, hex-prefix | `myotis-core` | The MPT verifier is security-critical; port it carefully (companion 03). |
| `networking` | discv4, discv5 (wrapped lib), DNS, RLPx, `eth`, `snap`, `NetworkConfig` | `myotis-p2p-el` | Companion 02. discv5 is a wrapped library, not hand-rolled. |
| `consensus` | beacon light client, BLS, SSZ, proofs, libp2p req/resp | `myotis-consensus` | The trust root. Companion 01. |
| `myotis-evm` | local EVM over SNAP-verified state, ABI, CCIP-Read, state oracle | `myotis-evm` | Swap Besu for revm/geth-vm. Companion 03. |
| `myotis-ens` | ENS forward/reverse/all-records via the EVM | `myotis-ens` | Pure logic on top of the EVM. Companion 03. |
| `node-core` | **the engine**: `ChainStack` (one network) + `NodeRegistry` (many) + ports | `myotis-engine` | The reusable cross-platform core. Companion 04. |
| `rpc-backend` | `VerifiedRpcBackend`: the verified-read pipeline behind the eth_* API | (part of `myotis-engine`) | Companion 04. |
| `jsonrpc-server` | Ethereum JSON-RPC HTTP endpoint + the backend interface (SPI) | `myotis-jsonrpc` | Optional host surface. Companion 04. |
| `app` | desktop daemon/CLI host: IPC over UDS, file caches, locks | `myotis-cli` | The desktop host (in scope). Companion 04. |
| `android-app` | Android host (foreground service, Compose UI, Android caches) | — | **Out of scope** (consumer of the engine). |
| `besu-android-fork` | Android-compat fork of Besu | — | N/A once Besu is replaced. |

### The engine boundary (what is engine vs host)

The single most important architectural idea: **`node-core` is the reusable engine**, and
both the desktop daemon and the Android service are thin **hosts** that construct the *same*
engine and inject platform-specific adapters through small interfaces ("ports"):

```
            ┌──────────────────────────── host (per platform) ─────────────────────────────┐
            │  Desktop CLI/daemon        Android NodeService          iOS app (future)        │
            │  - UDS IPC server          - foreground service         - SwiftUI               │
            │  - file caches             - Android file caches        - iOS file caches       │
            │  - JVM HTTP CCIP gateway   - Ktor/OkHttp CCIP gateway   - URLSession CCIP gw     │
            └───────────────┬───────────────────────┬───────────────────────┬────────────────┘
                            │ inject ports           │                       │
            ┌───────────────▼───────────────────────▼───────────────────────▼────────────────┐
            │                         ENGINE  (node-core + rpc-backend)                        │
            │  NodeRegistry → Map<network, ChainStack>                                         │
            │  ChainStack = RLPx + discv4 + discv5 + BeaconLightClient + VerifiedRpcBackend    │
            │  Ports (injected): PeerCache, ClPeerCache, DnsServerProvider, CcipGateway,       │
            │                    SnapQualitySink, RpcLogger, RpcClock, key storage             │
            └───────────────┬───────────────────────┬───────────────────────┬────────────────┘
                            │                        │                       │
                  myotis-consensus           myotis-p2p-el              myotis-evm / -ens
                  (libp2p + BLS + SSZ)   (devp2p eth/snap + disc)   (EVM + ABI + CCIP + ENS)
```

A host supplies: where to store caches/keys, how to do HTTP (CCIP-Read), DNS servers, a
clock, a logger, and a user-facing surface (CLI/IPC, JSON-RPC, or direct FFI calls). The
engine supplies: discovery, transport, handshakes, the light client, verification, the EVM,
and the verified-read API. **Re-create this boundary** — it is what makes one codebase serve
desktop + Android + iOS.

### Concurrency model (summary; detail in companions)

- **devp2p / RLPx**: an async event-loop model (reference uses Netty NIO, 4 threads shared
  across connections). Per-connection framing state is single-threaded; requests are
  correlated by an `AtomicLong` request-id into per-type maps of futures. Rust → tokio; Go →
  goroutines + channels.
- **discv4**: one event-loop thread + a refresh timer (15 s). Kademlia table behind a lock.
- **libp2p (CL)**: the library's own I/O threads; **BLS verification must never run on an
  I/O thread** — offload to a dedicated worker (a single BLS verify can cost 17–30 s on a
  phone). The light-client store is fully synchronized.
- **EVM**: a small worker pool with a "small-calldata" fast lane and a gate capping heavy
  SNAP fan-out to ~half the live snap peers (token-sweep fairness) — see
  [companion 04 §3](04-engine-and-hosts.md#3-resource-dispatch-for-large-queries-the-metamask-all-balances-at-once-case)
  for how a jumbo balance query (MetaMask fetching all balances at once) is dispatched. The EVM is synchronous;
  a sync↔async bridge blocks on cache misses (so it must run on a worker, never an I/O thread).
- **Hosts**: the desktop IPC server uses one lightweight thread per connection (reference:
  Java virtual threads); the JSON-RPC server uses async handlers that dispatch blocking
  backend calls to an IO pool, with a whitespace "heartbeat" to keep slow calls alive.

---

## 5. The Engine API — the framework surface (the deliverable)

This is what apps consume. Keep it **library-neutral and FFI-friendly**: bytes, strings,
integers, enums, and simple records — **no framework-specific async types leaking across
the boundary** (the reference explicitly forbids leaking `CompletableFuture` into shared
APIs; for Rust expose `async fn` or blocking + callbacks, for Go expose blocking methods +
goroutine-safe handles).

### 5.1 Lifecycle: `NodeRegistry` + `ChainStack`

- **`ChainStack`** — one network's full node on its own ports & identity. Constructed with:
  `(NetworkConfig, ChainPorts, NodeKey, PeerCache, ClPeerCache, CcipGateway,
  syncSnapshotPath, gossipsubEnabled)`. Lifecycle: `start() -> bool` (fault-isolated: any
  failure tears down only this stack and returns false), `shutdown()`. Optional:
  `configureSnapMaintainer(targetSnapPeers, dnsServerProvider)` (call before `start()`).
  Accessors expose the live connector, discovery services, beacon sync state/light client,
  and the verified backend.
- **`NodeRegistry`** — `Map<networkName, ChainStack>`; `add/get/all/remove/shutdownAll`.
  One process hosts mainnet + Gnosis + Sepolia simultaneously, each on its own ports.
- **`ChainPorts`** — `(elPort, discv5Port, rpcPort)`, defaulted per network so several
  stacks never collide (see §6).

### 5.2 Platform ports (the injection seams — implement per host)

| Port | Purpose | Desktop impl | Mobile impl |
|---|---|---|---|
| `PeerCache` | EL peer cache: `add(addr, pubkeyHex, snap)`, `recordSnapServed/Failure`, `load() -> [CachedPeer]`, `close()` | file (`peers-<net>.cache`) | app-private file |
| `ClPeerCache` | CL libp2p peer cache: load/add/markFailure + served-period ranges, bootstrap peers, light-client confirmed/denied verdicts | file (`cl-peers-<net>.cache`) | app-private file |
| `DnsServerProvider` | DNS server IPs for EIP-1459 TXT lookups (mobile DNS has no system resolver config) | null → system DNS | active-network DNS IPs |
| `CcipGateway` | CCIP-Read HTTP transport: `request(method, url, body) -> bytes` (GET+POST, ~10–15 s timeouts, bounded response size) | native HTTP client | platform HTTP client |
| `SnapQualitySink` | persist EL peer snap-serving quality across restarts | file-backed | file-backed |
| `RpcLogger`, `RpcClock` | logging seam + monotonic clock | stdlib | platform clock/log |
| key storage | where `NodeKey` (secp256k1) is stored | `nodekey-<net>.hex` | secure storage/keystore |

`CachedPeer = (address, publicKeyHex, snap: bool, snapQuality: CONFIRMED|UNKNOWN|DENIED)`;
quality drives dial priority (CONFIRMED first).

### 5.3 The verified-read backend (the eth_* contract)

The engine's verified surface mirrors the Ethereum JSON-RPC API. This is the single most
useful API to expose to apps (every method answered **only** from verified data; a method
returns "absent/unanswerable" rather than guessing — the host maps that to an error):

| Method | Returns | Verification basis |
|---|---|---|
| `chainId()` | chain id | config |
| `headBlockNumber()` | beacon optimistic head, or none | beacon light client |
| `syncState()` | `SYNCING` \| `CATCHING_UP` \| `SYNCED` | beacon light client |
| `getBalance(addr, block)` | wei | MPT account proof vs anchored stateRoot |
| `getTransactionCount(addr, block)` | nonce | MPT account proof (+pending overlay for own txs) |
| `getCode(addr, block)` | bytecode | bytecode vs proven `codeHash` |
| `getStorageAt(addr, slot, block)` | 32 bytes | MPT storage proof vs proven `storageRoot` |
| `call(to, data, block)` | ABI return bytes | local EVM over proof-served state |
| `estimateGas(from, to, data, value)` | gas | local EVM, intrinsic + metered + 15% buffer |
| `gasPrice()` / `maxPriorityFeePerGas()` / `feeHistory(...)` | fees | base fee from headers, tips from verified bodies |
| `getBlockByNumber/Hash(...)` | block JSON | beacon-anchored header (no snap needed) |
| `getTransactionByHash(hash)` | tx JSON | beacon-anchored block vs `transactionsRoot` (+ own sent-tx cache) |
| `getTransactionReceipt(hash)` | receipt JSON | vs `receiptsRoot` (handles eth/69 bloomless receipts) |
| `sendRawTransaction(rawTx)` | keccak256(rawTx) | devp2p gossip (engine never signs — relays only) |

Plus **ENS**: `resolve(name)` / `resolveText/Contenthash/MultiCoinAddr/Pubkey/Abi/DnsRecord/
InterfaceImplementer` and reverse `resolveName(addr)` (with mandatory forward-verification).

### 5.4 Host surfaces (pick per platform)

- **Desktop**: a CLI that talks to a long-running daemon over a **Unix-domain socket** with
  a line-delimited JSON protocol (operator/debug commands incl. proof/verification metadata).
- **Wallet integration**: an **Ethereum JSON-RPC HTTP server bound to loopback**
  (`127.0.0.1`), strict mode, so stock wallets work unmodified.
- **Mobile**: **direct FFI calls** into the engine's verified-read API (no socket needed),
  or an in-process loopback JSON-RPC server the platform WebView/wallet points at.

---

## 6. Network Configuration

All per-network constants live in one `NetworkConfig` record. Three networks are supported:
**mainnet (chainId 1)**, **Gnosis (100)**, **Sepolia (11155111)** (Holesky was retired). The
fields a re-implementation needs:

**EL:** `name, networkId, genesisHash, forkIdHash (4 bytes, EIP-2124), forkNext, bootnodes
(ip:port), elEnrTreeUrls (EIP-1459 trees), elBootEnodes (full enode:// for direct dial — used
by chains with no DNS tree, e.g. Gnosis)`.

**CL:** `genesisValidatorsRoot (32B), checkpointRoot (32B), checkpointSlot, currentForkVersion
(4B), priorForkVersion (4B, nullable), activeBlobParamsEpoch/MaxBlobs (EIP-7892 BPO),
clPeerMultiaddrs, clGenesisTime, clEnrTreeUrls, clDiscv5Bootnodes (ENR strings)`.

| | Mainnet | Gnosis | Sepolia |
|---|---|---|---|
| chainId | 1 | 100 | 11155111 |
| genesis hash | `d4e56740…cb8fa3` | `4f1dd231…da79756` | `25a5cc10…93e6dd9` |
| EL forkIdHash | `07c9462e` | `cfca387c` | `268956b6` |
| genesisValidatorsRoot | `4b363db9…fe95` | `f5dcb556…9d47` | `d8ea171f…8078` |
| currentForkVersion | `06000000` (Fulu) | `06000064` (Fulu) | `90000073` (Electra) |
| priorForkVersion | — | `05000064` | — |
| BPO (epoch, maxBlobs) | (419072, 21) | (1337856, 2) | (0, 0) |
| clGenesisTime | 1606824023 | 1638993340 | 1655733600 |
| secondsPerSlot / slotsPerEpoch | 12 / 32 | **5 / 16** | 12 / 32 |
| EL/discv5/RPC ports | 30303/9000/8545 | 30304/9001/8546 | 30305/9002/8547 |
| ENS available | yes | no | yes |

Important: **`SLOTS_PER_SYNC_COMMITTEE_PERIOD = 8192` on both presets** (32×256 = 16×512), so
period math is shared; only wall-clock→slot conversion is per-network. Sync committee size is
**512** and the participation rule is **≥2/3** on every network.

**Fork digest** (filters discv5 ENRs to same-fork peers; EIP-7892 form):
`base = SHA256(forkVersion ‖ 28 zero bytes ‖ gvr)`; if a BPO is active,
`digest = (base XOR SHA256(LE64(epoch) ‖ LE64(maxBlobs)))[:4]`, else `base[:4]`.
Accept the current digest plus the prior-fork digest (eases fork-transition windows).

**EL fork id** (EIP-2124): the reference *pins* the 4-byte hash per network and refreshes it
out-of-band. A faithful port should implement the real `CRC32(genesisHash ‖ forkBlocks/Times…)`
with `forkNext` for forward-compatibility (remote peers validate *our* fork id and disconnect
on mismatch).

**Checkpoint refresh** is a build-time tool: query ≥3 independent checkpoint endpoints,
normalize to the oldest finalized slot all can serve, re-query the root there, **require
cross-agreement** (mainnet) or tolerate a single responder with a loud warning (Gnosis, where
public endpoints are scarce), then rewrite the pinned `checkpointRoot`/`checkpointSlot`. The
checkpoint is deliberately kept ~1 period stale so the catch-up path is always exercised.

---

## 7. Dependency & Library Mapping (JVM → Go / Rust)

The reference leans on the JVM ecosystem (Tuweni, BouncyCastle, Netty, Besu, jvm-libp2p,
Milagro, ConsenSys discv5). Map each concern as follows. **Rust generally has the most
mature, batteries-included crates for every layer and is the recommended target**; Go is
viable and benefits from go-ethereum covering most of the EL stack in one place.

| Concern | JVM reference | Rust | Go |
|---|---|---|---|
| keccak-256 | Tuweni `Hash` / BouncyCastle | `tiny-keccak` / `sha3` | `golang.org/x/crypto/sha3` / go-ethereum `crypto` |
| SHA-256 | JDK | `sha2` | stdlib `crypto/sha256` |
| secp256k1 (sign/recover/ECDH) | Tuweni `SECP256K1` / BouncyCastle | `k256` / `secp256k1` | go-ethereum `crypto`, `secp256k1` |
| RLP | Tuweni `RLP` | `alloy-rlp` | go-ethereum `rlp` |
| uint256 / bytes | Tuweni `UInt256`/`Bytes` | `ruint`/`alloy-primitives` | `holiman/uint256`, `[]byte` |
| MPT proof verify | **hand-rolled** (`core/trie`) | port by hand, or `alloy-trie` (re-validate semantics) | port by hand, or go-ethereum `trie` |
| AES-CTR / HMAC (RLPx) | BouncyCastle | `aes`,`ctr`,`hmac` | stdlib `crypto/aes`,`crypto/hmac` |
| Snappy (RLPx + SSZ wire) | iq80 snappy | `snap` | `golang/snappy` |
| **EVM** | **Besu `evm`** | **`revm`** | **go-ethereum `core/vm`** |
| BLS12-381 (verify/aggregate, hash-to-G2) | **Milagro AMCL (pure-Java) + hand-rolled RFC 9380** | **`blst`** (or `bls12_381`) | **`supranational/blst` Go bindings** (or `gnark-crypto`) |
| SSZ + merkleization | **hand-rolled** (`consensus/ssz`) | `ethereum_ssz` + `ssz_types` (re-validate light-client types) | `prysmaticlabs/go-ssz` / fastssz (re-validate) |
| libp2p (TCP, Noise, yamux/mplex, gossipsub) | jvm-libp2p | `rust-libp2p` | `go-libp2p` |
| discv5 | ConsenSys `discovery` (wrapped) | `discv5` crate (sigp) | go-ethereum `p2p/discover` (v5) |
| discv4 / RLPx / eth / snap | **hand-rolled** (`networking`) | port by hand (or reuse `reth`/`ethp2p` crates) | go-ethereum `p2p` (covers all) |
| DNS (EIP-1459 TXT) | dnsjava | `hickory-dns` | `miekg/dns` |
| async event loop | Netty NIO | tokio | goroutines |
| HTTP (CCIP-Read, checkpoint refresh) | java.net.http / Ktor | `reqwest` | `net/http` |
| JSON-RPC server | Ktor CIO + kotlinx.serialization | `axum`/`hyper` + `serde_json` | `net/http` + `encoding/json` |
| logging | slf4j/logback | `tracing` | `log`/`slog` |

**The four heavy ports** (budget accordingly):
1. **EVM** (Besu → revm/geth-vm): the biggest single piece. The reference's `world` package
   is an adapter to Besu's `WorldUpdater` SPI; re-target it to revm's `Database`/`DatabaseRef`
   trait or geth's `vm.StateDB`. Replicate the mainnet fork schedule and view-call frame setup
   (companion 03).
2. **BLS + hash-to-curve**: the reference hand-rolls everything on Milagro (no JNI, for
   Android). With `blst`/`gnark` you get `FastAggregateVerify` and RFC-9380 hash-to-G2 directly
   — **but you must use the exact DST** `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` and
   minimal-pubkey-size (companion 01). For mobile FFI, prefer a Rust/`blst` static lib.
3. **libp2p + discv5**: large surface; use the language's libp2p/discv5 libraries rather than
   re-implementing the wire.
4. **SSZ light-client types + MPT verifier**: small but security-critical; re-validate the
   exact field orders, generalized indices, and Found/Absent/Invalid semantics by hand even if
   a library exists.

---

## 8. Cross-Platform Packaging (the engine as a Desktop/Android/iOS framework)

The goal is **one engine, three consumers**. Two viable strategies:

### Rust (recommended)

- Build the engine as a Rust crate; expose a small FFI surface with **UniFFI** (generates
  idiomatic **Kotlin** for Android and **Swift** for iOS from one interface definition) or a
  plain `extern "C"` ABI.
- **Android**: package the `cdylib` (`.so` for arm64-v8a/armeabi-v7a/x86_64) plus the
  UniFFI-generated Kotlin into an `.aar`; the Android host implements the ports (caches, HTTP,
  DNS, key storage) in Kotlin and calls the engine.
- **iOS**: build a static lib + the UniFFI Swift bindings as an `.xcframework`; the iOS host
  implements ports in Swift.
- **Desktop**: use the crate directly, or ship a thin CLI binary that embeds it.
- Async: expose `async fn` (UniFFI supports async) or blocking calls + callback handles.
  tokio runs fine on Android/iOS.

### Go

- Use **gomobile bind** to produce an Android `.aar` and an iOS `.xcframework` from the engine
  package; desktop imports the package or ships a CLI binary.
- Caveats: gomobile's exported type surface is restricted (no generics, limited slices/maps at
  the boundary), the Go runtime/GC adds binary size, and goroutine/JNI interaction needs care.
  Keep the FFI surface to bytes/strings/ints (which the verified backend already is).

### FFI boundary design rules (both languages)

- **Only simple types cross the boundary**: byte arrays, strings, integers, booleans, enums,
  and flat records. This is already how the verified backend is shaped (`bytes`, big-integer-
  as-string, `i64`, JSON-string results) — mirror it.
- **Inject all platform concerns as ports** (callbacks/traits/interfaces): storage, HTTP, DNS,
  clock, logger, key access. The engine must contain **zero** desktop- or mobile-specific I/O.
- **Avoid host-runtime-only APIs in the engine.** (The JVM reference, for example, avoids
  `java.net.http` and Java-21 runtime APIs because Android can't desugar them; the general rule
  for any language is: the engine targets the lowest common denominator of all three platforms.)
- Surface **one verified-read API** (§5.3) and **one ENS API** as the primary product surface;
  the JSON-RPC server and the desktop IPC are *optional hosts* layered on top of the same API.

---

## 9. Persistence & Storage

The engine persists only **performance caches and identity** — never trust anchors (those are
embedded constants). All of it is reconstructible; nothing is fsync-critical. Abstract each
behind a port so hosts choose the location (file on desktop, app-private storage on mobile).

| Artifact | Reference file | Format | Purpose |
|---|---|---|---|
| Node identity | `nodekey-<net>.hex` | 32-byte secp256k1 secret as hex | stable enode/PeerId across restarts |
| EL peer cache | `peers-<net>.cache` | TSV: `ip⇥port⇥pubkeyHex⇥snap(1/0)[⇥snapok/snapbad]` | re-dial known (snap-quality-ordered) peers on startup |
| CL peer cache | `cl-peers-<net>.cache` | multiaddrs + failure counts + served period ranges + bootstrap periods + light-client verdicts | seed the beacon light client; front-load proven LC servers |
| Sync snapshot | `sync-state-<net>.snapshot` (+ `.roots` sidecar) | custom binary, magic `LCSS`, **bound to genesisValidatorsRoot** | resume the verified light-client store (warm restart ~10 s vs re-bootstrap) |

The sync snapshot is a **private cache, not a trust anchor**: it's bound to the network's gvr,
rejected if foreign/corrupt/older-than-checkpoint, and self-correcting (a bad snapshot fails the
next BLS verify and falls back to the embedded checkpoint).

---

## 10. Implementation Status & Recommended Build Order

The reference is a working proof-of-concept; some architecture pieces are designed but not yet
built. A re-implementation should know what's load-bearing vs aspirational.

**Implemented & load-bearing (build these first, in order):**

1. **Consensus light client** (companion 01) — bootstrap + checkpoint pin, BLS aggregate verify,
   the four Merkle branches, committee rotation, catch-up, snapshot persistence. *Nothing works
   without a verified head.* discv5 + libp2p req/resp for CL peers.
2. **devp2p stack** (companion 02) — discv4 + DNS + direct dials, RLPx handshake + framing, the
   `eth` handshake (Hello/Status → READY), `GetBlockHeaders/Bodies/Receipts`.
3. **State verification** (companion 03) — the MPT proof verifier + the `snap` sub-protocol
   (`GetAccountRange`/`GetStorageRanges`, **not** `GetTrieNodes` — only the range responses carry
   full root-to-leaf proofs), header-chain anchoring.
4. **Local EVM** (companion 03) — the SNAP-backed state oracle, the executor stack
   (default + prefetch + CCIP-Read), gas estimation.
5. **ENS** (companion 03) — resolver discovery, all record types, reverse + forward-verify.
6. **The verified backend + host surfaces** (companion 04) — the eth_* pipeline, JSON-RPC,
   desktop IPC, tx gossip + confirmation tracking, fee derivation.

**Partial in the reference (carry the limitation or improve):**

- **Historical verification** is limited to a **header-chain walk ≤ 8192 blocks** from the
  finalized block. The designed-but-unbuilt pieces are: `historical_summaries`/`historical_roots`
  lookups from beacon state (to remove the 8192 limit) and the **pre-Merge epoch-hash
  accumulator** (`premergeacc.bin`). Pre-Merge blocks currently return `failReason:"preMergeBlock"`.
- **Transaction history** via a TrueBlocks/IPFS address-appearance index exists as a
  debug/explorer path and is **unverified on that path** (per-tx verification exists on the
  JSON-RPC path). Treat as optional; verification + balance-reconciliation for completeness is
  future work.

**Not implemented (out of scope for a first port):**

- EIP-4444 history-expiry fallbacks; NFT/Vyper-specific storage helpers; pooled-tx gossip
  (announce-then-fetch) and EIP-4844 blob sidecars; `eth_getLogs`, WebSocket `eth_subscribe`;
  multi-chain *cross-verification* (e.g. bridge proofs between two in-process light clients —
  a designed long-term payoff of hosting multiple `ChainStack`s in one process).

**EVM fork schedule caveat:** the reference hardcodes **mainnet** fork boundaries (London by
block, Paris/Shanghai/Cancun/Prague by timestamp) and throws below London. A port must replicate
this table and pick the matching EVM spec id (revm `SpecId` / geth fork config), and parameterize
it per chain if Gnosis EVM execution is needed.

---

## 11. Security-Critical Invariants (consolidated checklist)

Re-implementers: treat each of these as a test case. Getting any one wrong silently breaks the
trust model.

1. **Checkpoint pin** — `hash_tree_root(bootstrap beacon header) == embedded checkpointRoot`
   *before* trusting anything from the bootstrap.
2. **BLS**: DST = `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (the `_POP_` suffix is
   load-bearing); minimal-pubkey-size (pubkeys in G1, signatures in G2); G2 is imaginary-part-
   first on the wire; reject identity points; the **signature is always subgroup-checked**,
   trusted committee pubkeys may skip the per-key check; verify `e(aggPk, H(m)) == e(G1, sig)`.
3. **≥2/3 participation** gate (`participants*3 ≥ 512*2`) *before* the BLS verify.
4. **Four Merkle branches** on every forward step: sync-aggregate-over-attested-header (the BLS
   check), finality branch, **execution branch for both attested and finalized headers**, and the
   next-sync-committee branch when present. Generalized indices are **fork-dependent**, inferred
   from SSZ branch length (companion 01).
5. **Signing root** = `htr(SigningData{ attestedHeader.htr(), compute_domain(0x07000000,
   forkVersion, gvr) })`.
6. **SSZ = SHA-256 + little-endian; MPT = keccak-256 + RLP + big-endian.** Never mix.
7. **`ExecutionPayloadHeader` merkleizes exactly 17 fields** and **excludes** the three EIP-7685
   request roots (they live elsewhere; including them breaks bootstrap).
8. **MPT `storageRoot` and `codeHash` come only from the proof-verified account leaf**, never a
   peer's "slim" account body (a peer can keep nonce/balance honest while forging those two).
9. **Storage proofs anchor at the account's `storageRoot`**, not the world `stateRoot`.
10. **Bytecode** accepted iff `keccak256(code) == codeHash`.
11. **Bodies/receipts** verified by rebuilding the ordered trie (`key = RLP(index)`, un-hashed)
    and comparing to `transactionsRoot`/`receiptsRoot`. eth/69 receipts are bloomless — recompute
    the logs bloom before the root check.
12. **SNAP uses `GetAccountRange`/`GetStorageRanges`** (full boundary proofs), **not**
    `GetTrieNodes` (returns only the node at a path, no descend-able proof). Use a fresh,
    per-peer state root (peers prune beyond ~128 blocks).
13. **Strict mode**: unservable → error, **never** a proxied/unverified answer.
14. **The only un-proven value** is the pending-nonce overlay for the node's *own* signed
    broadcasts (only-raises, TTL-bounded).
15. **RLPx ECIES KDF is NIST concat-KDF `SHA256(counter ‖ Z)`** (not BouncyCastle's `KDF2`),
    auth `sig` signs the token directly, the EIP-8 size prefix is ECIES AAD and seeds the MAC
    keccak chains (companion 02).

---

*Continue to the companion documents for wire-level detail. Start with
[`01-consensus-light-client.md`](01-consensus-light-client.md) — it is the trust root and the
hardest part to get right.*
