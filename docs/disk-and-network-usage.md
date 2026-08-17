# Disk & Network Usage

What a fully synced, response-ready Myotis client costs in **disk** and **bandwidth** —
on Android, desktop, and iOS — including the peer caches, header/block storage (spoiler:
there is none on disk), the daily traffic needed to stay synced, and the data cost of
creating and sending a transaction.

> **All numbers here are preliminary.** They are derived from today's code, and the
> tuning is still moving: it may well be necessary to cause *more* network traffic —
> more peers, wider fan-outs, speculative prefetching — to answer wallet queries in a
> reasonable time (see [Optimisations & Limitations](../OPTIMISATIONS_AND_LIMITATIONS.md):
> round-trip latency, not bandwidth, is the binding constraint). Revisit before quoting.

**How these numbers were derived.** Every constant (cache formats, poll intervals,
fan-outs, response caps) is taken from the code, with file references. Wire-volume
figures are arithmetic on top of those constants plus a few **chain-level assumptions**
(marked below) — average mainnet transaction rate, block body size, etc. Treat the
byte totals as sizing estimates, not measurements.

**Scope: only what a synced, wallet-serving client actually uses today.** Two features
are deliberately **not** counted in the budget below: the **historical accumulators**
(pre-Merge historical hashes, Bellatrix historical roots — today only roadmap items),
and the **TrueBlocks Unchained Index** transaction-history scan (the daemon's
`get-transactions` stream and the desktop Query tab) — an opt-in, per-request debug
feature, not part of steady-state operation. Its profile, for sizing: an on-demand
content-addressed cache under `trueblocks/` (daemon: working-dir-relative; desktop:
`<dataDir>/trueblocks/`; Android: `filesDir/trueblocks/` — mind that a deep scan can
grow it to multi-GB on a phone; delete the directory to reclaim) holding the manifest
TSV, every bloom filter the scan has
tested (~8k chunks × O(100 KB) = **multi-GB after a full-history scan**, immutable, no
TTL — delete the directory to reclaim), and one index chunk per bloom hit (O(1–25 MB)
each). First scan downloads what it tests; subsequent scans are disk-only for blooms.
The manifest CID itself refreshes via one verified eth_call per day (on-chain
UnchainedIndex_V2 lookup) when the node is synced.

Chain-level assumptions used throughout (2025/26 ballparks):

| Assumption | Value used |
|---|---|
| Mainnet transaction rate | ~15 tx/s (~1.3 M tx/day) |
| Average signed tx size (RLP) | ~400 B |
| Average mainnet block body | ~100 KB |
| Average mainnet block receipts | ~80 KB |
| Mainnet slot time / Gnosis slot time | 12 s / 5 s |
| Sync-committee period (8192 slots) | ~27.3 h mainnet / ~11.4 h Gnosis |

---

## TL;DR

| Dimension | Cost |
|---|---|
| **Disk, fully synced** | **≲ 1 MB per network** (typically ~100–500 KB). Dominated by the ~50 KB light-client snapshot. No block/header database exists. |
| **Cold first sync** | ~1–10 MB (bootstrap ~25 KB + one ~25 KB update per committee period behind + peer discovery/handshakes). Minutes. |
| **Warm restart** | Tens of KB (snapshot resume + one finality poll). ~10 s to `SYNCED`. |
| **Staying synced, protocol minimum** | **< 1 MB/day** (~1.6 KB finality update per epoch + ~25 KB committee update per ~27 h). |
| **While awake, defaults (wallet-serving)** | **~2–6 MB/min**, dominated by inbound mempool gossip (peers push it; Myotis drops it) and fee/head warming (block bodies). Both are tunable — see [Knobs](#6-knobs-that-change-the-numbers). A never-sleeping daemon/desktop therefore lands at ~3–8 GB/day. |
| **Android in practice** | Near zero while idle (idle-pause after 5 min, default) + a few MB for the daily catch-up pass; awake minutes cost the per-minute rate above (thinner phone peer pools trend toward its low end). |
| **Creating + sending a tx** | Signing costs nothing (the wallet signs). Gating reads ~10–50 KB; the broadcast itself **~5 KB**; confirmation tracking ~1–2 MB (block bodies). |

---

## 1. Disk footprint

Myotis is a light client in the strictest sense: **no chain data is persisted**. There
is no header database, no block store, no state database — no LevelDB/RocksDB/SQLite
anywhere in the tree. Headers live in a small in-memory window (§1.3); state is fetched
as snap/1 proofs on demand and cached only in bounded in-memory LRUs
(`myotis-evm/.../StateProofCache.java`, `rpc-backend/.../VerifiedResultCache.java`).

Everything persisted is a handful of flat files, one set **per network** (mainnet uses
the bare name; other networks get a `-<network>` suffix, e.g. `peers-gnosis.cache`).
Both engines (Java and Rust) read and write the **same files in byte-identical formats**,
so switching engines keeps the caches.

Where the files live:

| Host | Location |
|---|---|
| Daemon (`app`) | working directory (`Main.java`) |
| Desktop app | `~/.myotis/` (`app-desktop/.../Main.kt`) |
| Android | `getFilesDir()` (`NodeService.java`) |
| iOS | app sandbox for the Rust engine's cache files; settings & query history in `NSUserDefaults` (`IosSettings.kt`, `IosQueryHistory.kt`) |

### 1.1 The files, per network

| File | Contents | Size |
|---|---|---|
| `sync-state<suffix>.snapshot` | Beacon light-client store: finalized + optimistic headers, current **and** next sync committee (2 × 512 BLS pubkeys ≈ 48 KB), period/slots. Binary "LCSS" v1 (`consensus/.../lightclient/LightClientStoreSnapshot.java`, Rust twin `rust/myotis-consensus/src/snapshot.rs`). Overwritten in place; bound to the chain by genesis-validators-root. | **~50 KB** (~26 KB when the next committee isn't held yet) |
| `sync-state<suffix>.snapshot.roots` | Recent state-root window sidecar, ≤ 64 entries × 41 B — lets a resume skip re-accumulating roots. | ≤ ~2.6 KB |
| `peers<suffix>.cache` | EL peer cache: one TSV line per peer — `ip⇥port⇥pubkey(0x+128 hex)⇥snapFlag[⇥snapok\|snapbad]` (`app/.../PeerCache.java`, `rust/myotis-net/src/el/peercache.rs`). **No entry cap**; failed snap-servers are deprioritized (`snapbad`), never evicted. | ~150 B/peer → tens–hundreds of KB after weeks |
| `cl-peers<suffix>.cache` | CL peer cache: `multiaddr[⇥periodRange][⇥b<period>][⇥lc\|nolc]` (`app/.../CLPeerCache.java`, `rust/myotis-net/src/clcache.rs`). Self-pruning: 3 consecutive failures evict the peer. | ~100 B/peer → a few–tens of KB |
| `nodekey<suffix>.hex` | secp256k1 node identity, `0x` + 64 hex chars. | 66 B |

Global (not per network):

| File | Contents | Size |
|---|---|---|
| `settings.properties` (desktop) / SharedPreferences (Android) / NSUserDefaults (iOS) | UI + node tuning settings | ~200 B |
| `query-history.tsv` (desktop, Android) / NSUserDefaults (iOS) | Query-tab history, capped at **50 entries** | a few KB |
| `~/.myotis/logs/` (desktop only) | Rolling logs, size-capped (`logback-desktop.xml`) | bounded by the rolling policy |

**Total per enabled network: well under 1 MB.** The only unbounded file is the EL peer
cache (~150 B per distinct peer ever seen READY); `purge-cache` (IPC) or the apps'
cache-purge action deletes the caches and the snapshot.

### 1.2 What is deliberately *not* on disk

- **Headers/blocks**: nothing. The trust anchor is the beacon light client, so the EL
  side re-fetches and re-verifies headers on demand.
- **State/proofs/bytecode**: in-memory bounded LRUs only, keyed by state root — the
  root changes every slot, so persisting them would buy almost nothing.
  Nothing beyond logging config ships in `src/main/resources` — no data blobs.
  (The historical accumulators will add embedded data here once implemented — out of
  scope for now, see the scope note at the top.)

### 1.3 RAM, for completeness

The eth/69 **served-header window** (`networking/.../eth/ServedHeaderWindow.java`) holds the
most recent headers in RAM to answer peers' `GetBlockHeaders`: default **32** headers ×
~500 B ≈ 16 KB, configurable up to 4096 (≈ 2 MB) (`EthHandler.DEFAULT_SERVED_BLOCK_WINDOW`,
`ChainStack.setServedBlockWindow`). It does not survive restart — by design.

---

## 2. Network: getting synced

### 2.1 Cold start (first run, or stale checkpoint)

1. **Discovery warm-up** — discv4/discv5 bootnodes plus an EIP-1459 DNS ENR-tree walk
   (mainnet): tens of KB of UDP + DNS TXT.
2. **EL dial wave** — RLPx ECIES handshake + Hello + Status is ~1.5–2 KB per peer;
   the stack dials aggressively (up to hundreds of attempts) until it holds its
   snap-peer target (default 32): a few hundred KB.
3. **CL bootstrap** — `LightClientBootstrap` ≈ **25 KB** (SSZ; it carries a full
   512-pubkey sync committee), verified against the embedded checkpoint root.
4. **Committee catch-up** — one `LightClientUpdate` ≈ **25 KB per sync-committee period**
   between the checkpoint and now (`light_client_updates_by_range`, up to 128
   periods/request; `BeaconLightClient.catchUpSyncCommittee`). A month-old checkpoint
   ≈ 26 periods ≈ ~700 KB; even a year is ~8 MB. The catch-up fans out to multiple
   peers per batch, so worst-case bytes are a small multiple of that.

**Total: single-digit MB**, typically dominated by BLS verification time, not bandwidth.

### 2.2 Warm restart

The persisted snapshot (§1.1) + `.roots` sidecar + proven-peer caches let a restart skip
bootstrap and re-identification entirely: resume the store, one finality poll, re-dial
cached peers. **Tens of KB**, `SYNCED` in ~10 s.

---

## 3. Network: staying synced (the daily budget)

Two very different questions hide here: what the **protocol** requires, and what the
**implementation** spends with default settings.

### 3.1 Protocol minimum (what keeping trust actually needs)

- One verified **finality update** per epoch (6.4 min): ~1.6 KB × 225/day ≈ **360 KB/day**.
- One **committee rotation** (~25 KB) per ~27.3 h period ≈ **22 KB/day**.

So the trust anchor itself costs **well under 1 MB/day**. Everything above that is
peer management, redundancy, and wallet-serving freshness.

### 3.2 What the default configuration spends per minute (while awake, mainnet)

Rates below apply **only while the node is awake** — Android's idle-pause (§3.3) drops
all of them to zero. Multiply by awake minutes to get a real daily figure; a host that
never sleeps (daemon, desktop) runs them 1440×/day.

| Term | Mechanism | Estimate/min awake |
|---|---|---|
| **Inbound mempool gossip** (received and dropped) | Full nodes push `Transactions` (0x12) / `NewPooledTransactionHashes` (0x18) to every peer; Myotis never asks for them and discards them on the event loop unless watching its own send (`EthHandler.java`, `TxGossipObserver`). Cost is unavoidable per open eth connection: ~38 B announcement/tx/peer + full bodies from the subset of peers that picked us for full forwarding. | **~1–3.5 MB** at the default 32-peer target (≈ 35–110 KB per peer) |
| **Fee/head warming** (hosts serving the wallet API) | The head warmer rebuilds the verified head (~1 header / 5 s) and keeps the fee snapshot fresh: **3 block bodies every ~12 s** for the tip median (`VerifiedRpcBackend`: `FEE_SNAPSHOT_REFRESH_MS`/`TIP_CACHE_TTL_MS` = 12 s, `TIP_SUGGEST_BLOCKS` = 3, bodies not cached across refreshes) — ~15 bodies/min | **~1–1.7 MB** |
| **CL finality polling** | Parallel fan-out of `light_client_finality_update` req/resp to **16 peers every slot** (12 s → 5 rounds/min), first verified win; losers' responses still arrive (~1.5–2 KB each) (`BeaconLightClient.pollFinalityUpdate`) | **~20–140 KB** (depends on how many of the 16 respond) |
| **Discovery upkeep** | discv4 refresh every 15 s (ping/pong/findnode ~150–170 B, inbound `NEIGHBORS` ≤ 1.3 KB) + discv5 poll every 15 s + inbound DHT traffic from other nodes | **~35–175 KB** |
| **libp2p keepalive** | Ping (8 B payload) every 15 s per CL connection, a few dozen connections | ~10 KB |
| **Committee rotation** | ~25 KB per ~27.3 h period | negligible |

**Ballpark: ~2–6 MB per awake minute for a wallet-serving mainnet node at defaults**
(≈ 3–8 GB/day if never asleep). The two big terms scale directly with knobs (§6):
mempool gossip with the eth peer count, fee warming with whether a wallet-API host is
running. And per the note at the top: these rates may deliberately *grow* where more
peers or more parallel fetching is what makes query latency acceptable. §3.4 explains
why always-on hosts currently have to pay this at all — and the plans to stop it.

**Gnosis:** 5 s slots make the CL poll fire 2.4× as often, and periods rotate every
~11.4 h — CL terms scale ×2.4; EL terms are smaller (smaller blocks, fewer peers).

### 3.3 Android in practice: mostly asleep

The Android host **idle-pauses** each network stack after **5 minutes** (default,
configurable 0–240 min) without a wallet request once `SYNCED` — `ChainStack.pause()`
quiesces every socket and timer, so traffic drops to **zero** while backgrounded. A
network-constrained WorkManager job (`CatchUpWorker`, ~daily, 8-min budget) resumes each
stack, catches up the missed committee periods (~25 KB each + a finality poll), persists
the snapshot, and pauses again.

So a phone wallet's realistic daily profile is:

- **idle day**: a few MB (daily catch-up + the wake/resync around any notification-driven use);
- **awake minutes** (app foregrounded, wallet polling): the §3.2 per-minute rate — a
  phone's thinner peer pool trends toward its low end, call it **~1–4 MB/min**;
- a **cold day-after-vacation open**: §2.1 catch-up — still only a few MB.

### 3.4 Why the desktop/daemon stays expensive — and how that goes away

The desktop/daemon's large steady-state traffic is not inherent to the protocol; it's
a **knowledge problem**. A standalone RPC daemon serving an *unmodified* wallet has no
idea when the next query will arrive, so to honor its latency promises (instant fees,
a fresh verified head) it must keep everything warm **all the time** — that's the
mempool-gossip and fee/head-warming terms of §3.2 running 1440 minutes a day. Android
only escapes this because its host *does* know when the wallet is active and idle-pauses
the stack.

Two planned paths give other hosts the same escape:

- **Bundling.** Once Myotis is embedded as a library inside the application that uses
  it (rather than running as a free-standing daemon), the host application knows exactly
  when queries can occur and can pause/resume the engine around its own lifecycle —
  the Android idle-pause model generalized. The engine API already supports this
  (`ChainStack.pause()` quiesces every socket and timer; a read wakes it).
- **A pause/wake JSON-RPC surface.** The server exposes `myotis_pause` and
  `myotis_wakeup` (alongside the existing `myotis_status`/`myotis_beaconStatus`), so a
  Myotis-aware wallet — even an out-of-process one — can put the node to sleep when its
  UI goes to the background and wake it (and poll status until ready) before the next burst
  of queries. See [§4.1](#41-lifecycle-control-myotis_pause--myotis_wakeup) for the exact
  semantics. Unaware wallets keep today's always-warm behavior — the methods are opt-in and
  nothing calls them on the wallet's behalf.

With either in place, the desktop profile converges on the Android one in §3.3:
per-minute rates only while a wallet is actually active, near-zero otherwise.

iOS runs the same engine (Rust) with the same idle semantics available to the host;
the desktop app and daemon are always-on (§3.2) unless paused.

---

## 4. Per-read costs (once synced)

| Operation | Wire cost |
|---|---|
| Verified account read (`get-account`, `eth_getBalance`, nonce) | 1 fresh header (~700 B) + `GetAccountRange` (~110 B) → response capped at **~4 KB** (`SNAP_RESPONSE_BYTES`, proof always complete) ≈ **~5 KB** |
| Verified storage slot (`get-storage`, `eth_getStorageAt`) | same shape ≈ **~5 KB** |
| `eth_call` / `eth_estimateGas` (EVM over snap proofs) | ~5 KB per cold account/slot touched + contract bytecode (tens of KB, up to 128 KB/response); repeated calls hit the state-root-keyed cache |
| `eth_getBlockByNumber` | headers only, ~700 B each |
| `eth_feeHistory` (cold, with percentiles) | up to 10 blocks × (body ~100 KB + receipts ~80 KB) ≈ **~1–2 MB**; normally served from the warm fee snapshot (§3.2) |

### 4.1 Lifecycle control (`myotis_pause` / `myotis_wakeup`)

Two Myotis-namespaced JSON-RPC methods let an **out-of-process** wallet drive the
node's lifecycle over the same loopback endpoint it already uses for reads — the
JSON-RPC counterpart of the daemon's `pause` / `resume` IPC commands, and of what
the Android `NodeService` does in-process from its own idle/foreground callbacks.
Like `myotis_status` / `myotis_beaconStatus`, they are **local control that bypasses
the verified backend**, so they answer even when the node is not synced / has no
peers.

| Method | Params | Effect | Result |
|---|---|---|---|
| `myotis_pause` | `[]` | **Idle-pause**: tear down all P2P — every socket and periodic timer, so the radio can sleep — while the JSON-RPC listener keeps listening and the warm verified state (light-client store, sync-committee roots, peer caches) stays in memory. Exactly the transition the Android idle controller performs. Blocking (~a few seconds); idempotent. | `{"ok":true,"lifecycle":"PAUSED"}` |
| `myotis_wakeup` | `[]` | Rebuild P2P after a pause (tagged the `ipc` wake reason on the JVM hosts; the iOS native resume takes no reason), skipping the cold DNS walk. Blocking (seconds). A no-op success when already `RUNNING`; on a failed rebuild returns `ok:false` and stays `PAUSED` (retryable). | `{"ok":true,"lifecycle":"RUNNING"}` |

`lifecycle` is the coarse state reached (`RUNNING` | `PAUSED` | `STOPPED`), and `ok`
is whether the requested target state was reached — so a caller can tell a real
transition from a well-formed refusal rather than being handed a misleading success.

**Intended use — pair `myotis_wakeup` with the status methods, never fire-and-forget.**
`myotis_wakeup` only *starts* the rebuild; it returns as soon as the stack is
`RUNNING`, which is **before** the beacon light client has re-anchored and a snap peer
is in the serving pool. A wallet resuming from background should therefore:

1. call `myotis_wakeup` as its UI comes to the foreground (overlapping the rebuild
   with the user's unlock), then
2. poll `myotis_status` until `state == "RUNNING"` **and** `snapPeers > 0`, and
   `myotis_beaconStatus` until `state == "SYNCED"`, **before** issuing verified reads —
   the same readiness gate the hosts apply (see
   [readiness-and-verified-head-age.md](readiness-and-verified-head-age.md)).

Skipping the wake entirely still works — the first verified read on a paused stack
wakes it on its own and is held (bounded, ~90 s) until the node can answer — but an
explicit `myotis_wakeup` + status poll overlaps the multi-second rebuild with the UI
transition instead of stalling the first read. When the seam isn't wired (a host that
didn't provide a lifecycle source) both methods return `-32601`.

Availability: every host that serves the JSON-RPC endpoint wires these — the daemon,
the desktop, the iOS listener, **and the Android node service**. The Myotis Android
app doesn't call them for its own UI (it drives pause/resume in-process from its own
lifecycle callbacks — §3.3), but the node it hosts serves them on `127.0.0.1` so a
**separate** same-device wallet app (e.g. Walleth) that points at the endpoint can
pause/wake the shared node tied to *its* foreground/background. The Android idle
controller cooperates: a wake it did not itself initiate (an out-of-process
`myotis_wakeup`, or the engine's own wake on a verified read) is granted a full idle
window, so the controller won't re-pause a node a client just woke out from under it
(`NodeService.idleTick`). Loopback-only and unauthenticated like the rest of the
endpoint.

**Multi-client caveat — `myotis_pause` is unconditional (last-writer-wins).** The
pause verb does **not** consult the engine's in-flight-request counter (only the host
idle timer does, via `lastActivityEpochMillis()` reporting "now" while a request is in
flight). So on a node shared by more than one client:

- A background client's `myotis_pause` tears the connector down **under another
  client's in-flight read** — say a foreground wallet's multi-second confirm-screen
  sweep. Integrity is unaffected (the read fails transiently or re-enters the wake gate
  and is held ~90 s until the node can answer), but a background client can degrade a
  foreground one.
- Two Myotis-aware wallets both following the guidance above will pause the node out
  from under each other on every background transition. The idle-controller cooperation
  above protects external *wakes*; nothing arbitrates competing *pauses*.

`myotis_pause` is therefore only polite when the caller is the node's **sole active
consumer** (the embedded-library case: one app hosts the engine and is its only
client). A wallet that can't assume that should prefer letting the node idle-pause
itself (skip `myotis_pause`, keep `myotis_wakeup`) — a wake is always one verified read
away regardless. (Making `pause` refuse while requests are in flight — returning
`{ok:false, lifecycle:"RUNNING"}`, which the result shape already expresses — would
also change the IPC `pause` command's semantics, so that is an owner decision, tracked
separately.)

---

## 5. Creating and sending a transaction

Myotis never signs — the wallet does. The node's costs are the verified reads the
wallet's confirm screen needs, the broadcast, and confirmation tracking.

| Phase | What happens | Wire cost |
|---|---|---|
| **Gating reads** | nonce (`eth_getTransactionCount`) + balance: one snap proof each; fees: warm snapshot (≈ 0 marginal); gas estimate: plain ETH transfer short-circuits to 21000 (0 bytes); an ERC-20 transfer runs the EVM — token account + bytecode + 1–3 slots | **~10 KB** (ETH transfer) / **~50–150 KB** (ERC-20, first time at a given state root) |
| **Broadcast** | The signed raw tx (~110–200 B) is sent as a full `Transactions` (0x12) message to **every READY peer** (~32), fire-and-forget (`RLPxConnector.broadcastTransaction`) | **~5 KB** out |
| **Re-broadcast** | Still-pending own txs re-pushed every **20 s** (`TX_REBROADCAST_INTERVAL_MS`) until gossip echoes the hash back (propagation confirmed) — typically 1–3 rounds | ~5 KB/round |
| **Confirmation tracking** | `eth_getTransactionReceipt` polling scans beacon-anchored blocks for the tx: first poll looks back **8 blocks** (bodies verified against `transactionsRoot`), then ~1 new body per block (12 s) until mined; receipts fetched **only for the matched block** and verified against `receiptsRoot` (`VerifiedRpcBackend.locateMinedTx`, `RECEIPT_INITIAL_LOOKBACK_BLOCKS` = 8, per-poll cap 128) | ~8–12 bodies × ~100 KB + ~80 KB receipts ≈ **~1–2 MB** |

**Total for one ETH transfer end-to-end: ~1–2 MB**, almost all of it confirmation
tracking (block bodies). The send itself — nonce, fees, estimate, broadcast — is
**~15–20 KB**. On Gnosis the bodies are far smaller, so the total drops roughly an
order of magnitude.

---

## 6. Knobs that change the numbers

| Knob | Default | Effect |
|---|---|---|
| Target snap peers (`ChainStack.setTargetSnapPeers`, Settings) | 32 | Mempool-gossip inbound scales ~linearly with connected eth peers — the #1 lever. |
| Served-block window (`setServedBlockWindow`) | 32 (max 4096) | RAM (~500 B/header) and what we serve peers; not a big wire term. |
| Idle pause (Android Settings) | 5 min | Everything → 0 while asleep. |
| CL finality fan-out | 16 (32 hunting) | Multiplies per-slot CL response bytes. Compile-time today (`BeaconLightClient`). |
| Gossipsub observation (`setGossipsubEnabled`) | **off** | When on, adds inbound finality/optimistic gossip per slot (observation-only). |
| Fee snapshot refresh / tip window | 12 s / 3 blocks | The body-warming term (§3.2) scales with refresh rate × window. |
| Deep-pool threshold, dial budgets (`DNS_DIALS_PER_MIN` etc.) | see `ChainStack` | Discovery/dial churn traffic. |

---

## Code pointers

- Peer caches: `app/.../PeerCache.java`, `app/.../CLPeerCache.java`,
  `rust/myotis-net/src/el/peercache.rs`, `rust/myotis-net/src/clcache.rs`
- Snapshot format: `consensus/.../lightclient/LightClientStoreSnapshot.java`,
  `rust/myotis-consensus/src/snapshot.rs`
- Header window: `networking/.../eth/ServedHeaderWindow.java`
- Snap request caps: `networking/.../eth/EthHandler.java` (`SNAP_RESPONSE_BYTES`)
- CL sync loop, fan-outs, intervals: `consensus/.../BeaconLightClient.java`
- Gossip drop-path & tx broadcast: `networking/.../eth/EthHandler.java`,
  `networking/.../rlpx/RLPxConnector.java`
- Fee/head warmers, receipt scan, re-broadcast: `rpc-backend/.../VerifiedRpcBackend.java`
- Android idle-pause & daily catch-up: `android-app/.../NodeService.java`,
  `android-app/.../CatchUpWorker.java`
