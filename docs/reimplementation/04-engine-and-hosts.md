# 04 — The Engine and Its Hosts

> Companion to the [re-implementation spec](README.md). Covers the **reusable engine**
> (`ChainStack` / `NodeRegistry` + platform ports), the **verified-read backend** (the eth_*
> pipeline), and the two **host surfaces** — the desktop daemon (Unix-domain-socket IPC) and the
> loopback **JSON-RPC** server — plus persistence and concurrency.

Reference modules: `node-core/` (`io.myotis.node`), `rpc-backend/` (`io.myotis.rpc`),
`jsonrpc-server/` (`io.myotis.jsonrpc`, Kotlin), `app/` (`com.jaeckel.ethp2p.app`, desktop host).

> **This is the layer the user most wants re-created cross-platform.** The clean engine boundary is
> `node-core` + `rpc-backend`: re-create those (plus the injected ports), and a desktop CLI, an
> Android service, and an iOS app become thin hosts that all construct the same engine.

---

## 1. The engine: `ChainStack` + `NodeRegistry`

### 1.1 `ChainStack` — one network's full node

Constructed with everything platform-specific **injected**:

```
ChainStack(NetworkConfig network, ChainPorts ports, NodeKey nodeKey,
           PeerCache peerCache, ClPeerCache clPeerCache, CcipGateway ccipGateway,
           Path syncSnapshotFile, bool gossipsubEnabled)
```

Owns, on its own ports & identity: the RLPx connector, discv4, discv5, the beacon light client +
sync state, and (best-effort) the verified JSON-RPC server. Plus per-stack dial bookkeeping (an
`attempted` set, a `backoff` map of expiry timestamps, a `blacklistedNodeIds` set) and an optional
snap-peer maintainer.

**Lifecycle:**
- `start() -> bool` — **fault-isolated**: on any failure it tears down only this stack's resources
  and returns `false`, never affecting sibling stacks or the host. `start()`/`shutdown()` share one
  monitor so they never interleave.
- `shutdown()` — reverse-order teardown (maintainer → rpc → beacon → connector → discv5 → discv4 →
  caches).
- `configureSnapMaintainer(targetSnapPeers, dnsServerProvider)` — must precede `start()`;
  `setTargetSnapPeers(n)` live-updates.

**The canonical start sequence** (re-create this order exactly):

```
1. EIP-1459 DNS discovery (EL + CL trees), concurrent, 10s deadline; seed the maintainer's pool.
2. RLPx connector; then immediate dials: cached peers (snap-quality-ordered),
   DNS-direct enodes (≤50), static enodes (chains with no DNS tree, e.g. Gnosis).
3. discv4.start(elPort)  — EL is ESSENTIAL: a bind failure throws and fails the stack.
4. BeaconSyncState; then discv5 (CL discovery — NON-essential: a failure logs and continues)
   + BeaconLightClient (checkpoint root/slot, fork version, gvr, CL-peer-cache wiring via
   method refs, sync snapshot file, gossipsub flag); blc.start().
5. Verified JSON-RPC (best-effort — a bind failure does NOT fail the stack): up-front loopback
   bind probe, build VerifiedRpcBackend, start MyotisRpcServer on 127.0.0.1:rpcPort.
6. Snap-peer maintainer (optional; daemon/mobile enable it): a 10s loop keeping
   activeSnapHandlers >= targetSnapPeers by re-dialing cached snap peers + a rate-capped,
   periodically-refreshed DNS ENR pool (the discv4-independent path NAT'd hosts need).
```

Maintainer tunables (reference): backoff 10 min (wrong-chain) / 30 s (transient); DNS direct-dial
limit 50; max attempted 200; DNS batch 15/cycle; 60 dials/min; pool cap 600; refresh every 4 min.

### 1.2 `NodeRegistry` — many stacks in one process

`Map<networkName, ChainStack>` with `add / get / all / networkNames / remove / shutdownAll`. One
process hosts mainnet + Gnosis + Sepolia at once, each on its own ports. A failure in one stack is
isolated. (The *long-term* payoff of co-resident verified heads — trustless cross-chain bridge
verification — is designed but not built.)

### 1.3 `ChainPorts`

`(elPort, discv5Port, rpcPort)`; `defaultsFor(network)` uses the per-network pinned defaults so a
wallet pointed at a given RPC port always reaches the same chain regardless of which others are
enabled. `withRpcPort(n)` overrides just the RPC port (hosts may let users pick it).

### 1.4 Platform ports (the injection seams)

See [README §5.2](README.md#52-platform-ports-the-injection-seams--implement-per-host) for the
table. The shapes (re-create as traits/interfaces):

- `PeerCache`: `add(addr, pubkeyHex, snap)`, `recordSnapServed(addr)`, `recordSnapFailure(addr)`,
  `load() -> [CachedPeer]`, `close()`.
- `ClPeerCache`: `load() -> [multiaddr]`, `add`, `markFailure`, `servedRanges() ->
  map<multiaddr,[low,high]>`, `recordServed`, `bootstrapPeers() -> map<multiaddr,period>`,
  `recordBootstrap`, `lightClientConfirmed()`, `lightClientDenied()`, `markLightClientBatch`,
  `close()`. (Method shapes mirror the light client's seed/listener setters so they wire as direct
  callbacks.)
- `DnsServerProvider`: `get() -> [dnsServerIp]` (null/empty → resolver's default).
- `CcipGateway`: `request(method, url, body) -> bytes`.
- `SnapQualitySink`: `recordSnapServed/Failure(addr)` (persist EL peer quality).
- `RpcLogger`: `info/warn`. `RpcClock`: `elapsedMillis()` (monotonic).
- `CachedPeer = (address, publicKeyHex, snap, snapQuality ∈ {CONFIRMED, UNKNOWN, DENIED})`.

---

## 2. The verified-read backend (`rpc-backend` / `VerifiedRpcBackend`)

The single verified implementation of the eth_* contract, shared by every host. Constructed from
the live `(connector, beaconLightClient, beaconSyncState, ccipGateway, logger, clock,
snapQualitySink)`; it never closes the injected components. `start()` spins a head-warmer and
registers as a tx-gossip observer; `close()` stops its own pools.

### 2.1 The verified-read pipeline (the engine's core algorithm)

It builds an **anchored head context** (reused for ~12 s) and constructs the EVM executor stack per
call:

```
PrefetchingEvmExecutor
  → DefaultEvmExecutor(oracle, bytecodeCache, evmPool)
      → SnapBackedStateOracle(peerSupplier, bytecodeCache, maxAttempts=8, stateProofCache)
          → EthHandlerSnapPeer (rotates across the connector's active snap handlers)
              → EthHandler (devp2p snap/1: GetAccountRange / GetStorageRanges)
```

**Head anchoring** ties a peer-served header to the beacon chain via `stateRootMatch` or the
`headerChain` walk (parent-hash chain from the beacon-attested block hash, ≤ 8192 blocks); bodies
/receipts are checked against `transactionsRoot`/`receiptsRoot`; accounts/storage against the
anchored `stateRoot`. The peer supplier prefers proven `rootServed` peers, falls back to the probed
peer then round-robin, skipping `rootDenied`; each served/denied event feeds the `SnapQualitySink`.

**Staleness gates** (sample): call timeout 120 s; state-head max-stale 120 s; **nonce serve-stale is
tighter** (it's what the wallet signs against); block-number tolerances for "near-head" pins.

### 2.2 Method catalog

The full list is in [README §5.3](README.md#53-the-verified-read-backend-the-eth_-contract). Notable
behaviors to replicate:

- **Null-return contract** (central): a method returns "no verified answer" (host maps to a JSON-RPC
  error in strict mode) vs a literal `null` JSON result (a *verified* "not found" — e.g. an unknown
  tx on a synced chain). Distinguish these.
- `getBlockByNumber/Hash`, `getTransactionByHash`, `getTransactionReceipt` verify from a
  beacon-anchored header — **no snap peer needed**. Receipt/tx-by-hash scan the recent
  beacon-anchored block window incrementally.
- `sendRawTransaction` gossips the raw bytes over devp2p, returns `keccak256(rawTx)`, caches the
  bytes so the tx shows as *pending* until mined, and re-broadcasts periodically until it sees the
  gossip echo. **The engine never signs.**
- Fees: base fee from verified headers; tips from verified bodies (vs `transactionsRoot`);
  `feeHistory` reward percentiles from a gas-used-weighted walk over verified receipts.
- **The one un-proven value**: a pending-nonce overlay for the node's own broadcast txs (only-raises,
  TTL-bounded) — bounded by the node's own ECDSA-authenticated broadcast, not peer data.

### 2.3 EVM concurrency controls

A heavy worker pool + a reserved "small-calldata" fast lane (routed by a thread-local + a calldata
size threshold), and a gate capping heavy SNAP fan-out to ~half the live snap peers (token-sweep
fairness). The EVM is synchronous and blocks on cache misses, so it must run on these workers, never
an I/O thread.

---

## 3. Resource dispatch for large queries (the MetaMask "all balances at once" case)

When a wallet loads it issues a **burst of state reads**. MetaMask in particular fetches many
token balances at once — either as **one multicall `eth_call`** (a balance-checker / Multicall3
contract doing N `balanceOf` SLOADs across N token contracts in a single call) or as **many
parallel `eth_call`/`eth_getBalance` requests** (often a JSON-RPC 2.0 batch array). The naive path
— one network round-trip per SLOAD against a thin set of snap peers — would take seconds to minutes
and could starve the interactive calls a confirm screen blocks on. The engine handles this at **two
levels**: *intra-call* (one big multicall) and *inter-call* (many requests at once).

### 3.1 Intra-call: the speculative-prefetch convergence loop (`PrefetchingEvmExecutor`)

A single multicall may touch hundreds of accounts and storage slots; the synchronous EVM would
block on each miss serially. The prefetch executor turns that into a few **parallel waves** with a
*sentinel-return* loop (cap `DEFAULT_ITERATION_CAP = 4`):

```
prime:  fetch the target (multicall) contract's account + bytecode synchronously         (~2 RTT)
loop:
  - run the EVM "sentinel-on-miss": every uncached read returns a zero/empty PLACEHOLDER
    without blocking, and the access is RECORDED (not cached).
  - discard the sentinel run's RESULT (placeholders make it bogus); keep its access list.
  - batch-fetch all newly-discovered misses IN PARALLEL (prefetchInParallel), warming the cache.
  - sentinel mode stays ON while an iteration still DISCOVERS new accesses → one parallel wave
    per "hop"; the last two iterations run for REAL.
  - converge when a run reads only cached values; return THAT run's result.
    (A result is ONLY returned from a fully cache-hit — i.e. fully verified — run.)
```

For the 1000-token multicall this is exactly: **iteration 0** (sentinel) discovers the 1000 token
*accounts* (their code isn't loaded yet, so no `balanceOf` runs); **iteration 1** (sentinel) loads
that code and records all 1000 *storage slots*, batch-fetched in one wave; the final real run reads
everything from cache. `balanceOf` is *data-independent* (slot = `keccak256(holder ‖ mappingSlot)`,
computed from inputs), so it converges in ≤3 iterations; a call that doesn't converge within the
cap **fails closed** rather than returning unverified data. Chained-dependency reads (deep proxy
chains where one read's value is the next read's slot) can't be prefetched and fall back to serial
blocking — same latency as baseline, never wrong.

### 3.2 Batch coalescing + per-item verification (`SnapBackedStateOracle.fetchBatch`)

Each prefetch wave is **coalesced**, not issued slot-by-slot:

- An `account → {slots}` map is split into chunks of **`BATCH_PATHSET_CHUNK = 64` path-sets per
  request**, issued **in parallel** (`allOf`).
- Every item is **verified independently** from the one combined node set the peer returns (the MPT
  verifier builds a `keccak256(node) → node` map, so each account/slot descends from the root on its
  own). A forged/incomplete proof for *any* item fails that item's verify and **rotates the whole
  chunk to another peer**; best-effort overall (an unverifiable chunk is left uncached and the
  per-item path re-fetches it).
- Net effect: a ~1000-account sweep collapses from ~1000 round-trips to **~16**.

### 3.3 Peer fan-out bounding

The thin snap-peer set — not threads — is the contended resource. Fetches **rotate across the
connector's `activeSnapHandlers()`** (preferring proven `rootServed` peers, skipping `rootDenied`),
and the parallel waves are **semaphore-bounded** so a 1000-token sweep doesn't flood one peer. On
the dial side, a **"snap-heavy" gate pauses *new* peer dials** while a long snap round-trip chain
runs, so discovery churn doesn't contend with the event loop mid-sweep.

### 3.4 Inter-call: lanes, the lane gate, and caches (`VerifiedRpcBackend` + JSON-RPC router)

When the burst arrives as **many separate requests** (or a batch array), three mechanisms keep a
jumbo multicall from starving the small interactive calls a wallet blocks on (nonce, balance, fee):

- **Two EVM lanes on separate pools.** Small-calldata calls (`calldata ≤ EVM_SMALL_CALLDATA_MAX =
  4096` — plain `eth_getBalance`/nonce/fee/simple `eth_call`) run on a **reserved `evmPoolSmall` (1
  thread)**; big multicalls run on **`evmPoolHeavy` (`EVM_POOL_THREADS − 1 = 2` threads)**. The lane
  is chosen per request from a thread-local hint set by calldata size.
- **`SnapLaneGate`.** A *heavy*-lane snap request must hold a permit, and the permit count is **half
  the live snap peers** (recomputed on each acquire, min 1). The other half is always free for the
  small/interactive lane (which never acquires). A jumbo multicall thus runs to genuine completion /
  OOG / timeout — **just never using more than its share of peers at once** — so a concurrent
  balance/nonce/fee read still gets through.
- **Caches make repeats free.** A verified `(stateRoot, addr, slot) → value` is a *cryptographic
  fact*, so the cross-call **`StateProofCache`** (LRU, `STATE_PROOF_CACHE_MAX = 65536`) and the
  forever-valid **`BytecodeCache`** let MetaMask's repeated/retried sweeps converge instead of
  re-proving. The anchored **head context is built once and reused for `RPC_HEAD_TTL_MS = 12 s`**, so
  a burst shares one beacon-anchoring instead of re-walking the header chain per call.

### 3.5 What a re-implementation must replicate

1. A speculative **sentinel/prefetch loop** so a multicall resolves in a few parallel waves, not one
   round-trip per SLOAD; **return a result only from a fully cache-hit (fully verified) run**; cap
   iterations and fail closed.
2. **Batch coalescing with independent per-item proof verification** and whole-chunk peer rotation
   on any bad item.
3. **Peer-fan-out bounding** (rotate across snap peers, semaphore per wave; pause new dials during a
   sweep).
4. **Lane separation + a fan-out gate** so heavy multicalls can't starve the small interactive reads.
5. **Cross-call verified-state + bytecode caches and a short head-context TTL** so bursts and retries
   converge.

> Latency shape (design target, not yet measured end-to-end in the reference — its benchmark IT is
> scaffolding): a data-independent multicall settles in ≤3 convergence iterations ≈ a small constant
> number of RTTs regardless of token count, versus one-RTT-per-SLOAD for the naive path.

---

## 4. Host surface A — the loopback JSON-RPC server (`jsonrpc-server`)

A standard Ethereum JSON-RPC HTTP endpoint so **unmodified wallets work**. Reference is Kotlin/Ktor
(CIO), chosen to be Android-safe; a port can use any async HTTP framework.

- **Transport**: HTTP server bound to **`127.0.0.1`** (loopback only — the wallet is a same-device
  client; the endpoint is unauthenticated and TLS-less, so it must not be on a routable interface).
  `GET /health`, `POST /`. CORS for browser wallets.
- **Backend SPI**: the server depends only on a `MyotisRpcBackend` interface (the verified backend
  implements it) — clean inversion so the server stays host-agnostic.
- **Routing**: handle single requests and JSON-RPC 2.0 **batch arrays** (each element gets its own
  result/error). For each method, call the backend; if it returns non-null → return it; else in
  **strict mode** (production) return `-32000` (known method, can't serve verified now) or `-32601`
  (method not served verified) — **never** proxy. (A dev-only upstream proxy exists to discover what
  a wallet calls; disabled in strict mode.)
- **Heartbeat streaming** (nice-to-have): compute the response in a child task and, while pending,
  trickle a whitespace byte every ~5 s. JSON ignores leading whitespace, so clients parse unchanged,
  but the trickle resets wallet socket read-timeouts so slow verified calls (>30 s) survive.
- **Encoding**: minimal hex quantities (`0x0`), allocation-light hex data (some results, e.g.
  `eth_getCode`, are large). Blocking backend calls dispatched to an IO pool.

Methods served (the verified set): `eth_chainId`, `net_version`, `web3_clientVersion`,
`eth_blockNumber`, `eth_call`, `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`,
`eth_getStorageAt`, `eth_sendRawTransaction`, `eth_getTransactionReceipt`,
`eth_getTransactionByHash`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_gasPrice`,
`eth_maxPriorityFeePerGas`, `eth_feeHistory`, `eth_estimateGas`.

---

## 5. Host surface B — the desktop daemon + IPC (`app`)

The desktop host: a long-running daemon plus a CLI that sends it commands. **In scope** for the
re-implementation as the reference desktop host (mobile hosts replace this with direct FFI calls).

### 4.1 Daemon vs client mode

- Parse `--network <csv>` (host several networks in one process), `--port`, `--gossipsub`, and a
  remaining command.
- A command token + a *running* daemon → **client mode**: connect to the network's socket, send one
  JSON line, print responses, exit.
- No command → **daemon mode**: build & start a `ChainStack` per `--network` into a `NodeRegistry`,
  start an IPC server per network, block on a shared stop-latch.
- "Is a daemon running?" = try to connect the socket; else try to take the lock file.

### 4.2 IPC transport & protocol

- **Unix-domain socket** per network (`/tmp/ethp2p[-<net>].sock`, override via env). Accept loop +
  per-connection handler on lightweight threads (reference: Java virtual threads). **Line-delimited
  JSON** ("JSON-Lines"): one request object per line, one (or, for streaming, many) response lines.
- This is a **distinct surface from JSON-RPC** — an operator/debug protocol whose responses include
  rich **proof/verification metadata** (the `verification` object with `verifyMethod`,
  `beaconChainVerified`, `blsVerified`, `failReason`, the raw `proof` nodes, etc.).
- The reference hand-rolls flat-JSON extraction (no JSON lib) — a port should just use a JSON
  library.

### 4.3 IPC command catalog (abridged)

| Command | Args | Response (key fields) |
|---|---|---|
| `status` | — | `state, uptimeSeconds, discoveredPeers, connectedPeers, readyPeers, snapPeers, …` |
| `peers` | — | discovered + connected peer lists (ip, ports, nodeId, clientId, snap) |
| `get-headers` | blockNumber, count | `[{number, hash, parentHash, stateRoot, transactionsRoot, …}]` |
| `get-block` | blockNumber | block summary + `verification{…}` |
| `get-account` | address | `nonce, balance, storageRoot, codeHash, proof[], verification{…}` |
| `get-storage` | address, slot, holder? | `value, storageRoot, proof[], verification{…}` (holder ⇒ ERC-20 mapping slot) |
| `get-transactions` | address | **streaming**: one line per appearance + a terminal `done` line (TrueBlocks/IPFS; debug/explorer; unverified on this path) |
| `resolve-ens[...]` | name (+ key/coin/etc.) | resolved record + `beaconVerified, blockNumber` |
| `dial` | enode | ack |
| `beacon-status` | — | `state, currentPeriod, targetPeriod, finalizedSlot, optimisticSlot, executionStateRoot, executionBlockNumber, peers[…]` |
| `stop` | — | trips the stop-latch (whole process) |

The integration tests key off `beacon-status` → `"state":"SYNCED"`, then `get-account` /
`get-storage` returning `"verifyMethod":"headerChain"`.

### 4.4 Verification metadata (the trust model, surfaced)

`get-account`/`get-storage`/`get-block` compute and return how the answer was anchored:
**`stateRootMatch`** (the header's `stateRoot` equals a beacon-attested root) or **`headerChain`**
(walk parent hashes from the beacon-attested block hash to the target, bounded by 8192 blocks;
pre-Merge blocks below 15,537,394 are unverifiable → `failReason:"preMergeBlock"`). Account/storage
proofs are MPT-verified against the peer's state root, and `storageRoot`/`codeHash` are taken from
the **proof-verified leaf**, never the peer's slim body.

---

## 6. Persistence

See [README §9](README.md#9-persistence--storage) for the table. The reference uses flat files
relative to the working directory (no database); each is reconstructible and abstracted behind a
port:

- **EL peer cache** (`peers-<net>.cache`): TSV `ip⇥port⇥pubkeyHex⇥snap(1/0)[⇥snapok/snapbad]`;
  insertion-ordered, in-memory authoritative + async single-thread disk writer; `add` appends a
  line, quality changes trigger a rewrite; 3 consecutive snap failures → DENIED (deprioritized,
  never evicted).
- **CL peer cache** (`cl-peers-<net>.cache`): multiaddrs + failure counts (threshold 3) + served
  period ranges + bootstrap periods + light-client confirmed/denied verdicts.
- **Sync snapshot** (`sync-state-<net>.snapshot` + `.roots` sidecar): the verified light-client
  store, bound to gvr (a cache, not a trust anchor — see companion 01 §9.7).
- **Node key** (`nodekey-<net>.hex`): 32-byte secp256k1 secret.

---

## 7. Concurrency model (consolidated)

- **devp2p/RLPx**: a shared async event-loop group; per-connection framing is single-threaded;
  requests correlated by an atomic id into per-type future maps.
- **discv4**: one event-loop thread + a 15 s refresh timer; Kademlia table behind a lock.
- **libp2p (CL)**: the library's I/O threads; **BLS verification offloaded to a dedicated worker**
  (never on an I/O thread); the light-client store fully synchronized.
- **EVM**: heavy pool + small-lane + SNAP fan-out gate; synchronous, blocks on misses → workers only.
- **JSON-RPC**: async handlers dispatch blocking backend calls to an IO pool, with heartbeat
  streaming.
- **IPC (desktop)**: one lightweight thread per connection.
- **Background loops (per stack)**: snap-peer maintainer (10 s), RPC head warmer (5 s), DNS pool
  refresh (on-demand, rate-capped, one-at-a-time). All daemon threads.
- **Shared mutable state**: concurrent maps/sets for dial bookkeeping; peer caches synchronized +
  single-thread disk writer; `start()`/`shutdown()` mutually synchronized; a single shared stop-latch
  trips the whole process; cleanup guarded to run exactly once.

---

## 8. Putting it together for a new host

To add a host (desktop, Android, iOS) on top of a re-implemented engine:

1. Implement the **ports**: peer cache, CL peer cache, DNS server provider, CCIP gateway, snap
   quality sink, logger, clock, and key storage — using the platform's filesystem/HTTP/keystore.
2. Build a `NodeRegistry`; for each enabled network, construct a `ChainStack` with those ports and
   `start()` it.
3. Pick a surface:
   - **Desktop** — a UDS IPC server + CLI (debug/operator), optionally the loopback JSON-RPC server.
   - **Mobile** — call the verified-read backend **directly over FFI** (no socket), or run the
     in-process loopback JSON-RPC server and point the platform wallet/WebView at it.
4. Drive lifecycle from the platform (foreground service on Android, app lifecycle on iOS, a
   stop-latch/daemon on desktop), scheduling sync into shared wake windows on mobile to save battery.

The engine code (`node-core` + `rpc-backend` + the protocol modules) is **identical across all three
hosts** — that is the whole point of the boundary.
