# Optimisations & Limitations — verified RPC on a phone

This document records how the node serves cryptographically-verified JSON-RPC to an
**unmodified** wallet (MetaMask, rotki) fast enough to be usable on a phone, and where
the hard limits are. Every optimisation below exists to work around a specific
phone-performance or network-latency limitation; the two halves are meant to be read
together.

**Non-negotiable invariant.** Nothing here trades away verification. The only trust
anchors are sync-committee signatures, the embedded pre-Merge historical-hash
accumulator, and the Bellatrix-era historical-roots accumulator. A peer is never
trusted. Every value the wallet receives is either proven against a beacon-anchored
state root (SNAP proof / header chain) or is an honest *error* — never fabricated data,
never a proxied answer. The optimisations change *scheduling, caching, freshness, and
which verified anchor we use* — never *what we trust*.

---

## Part 1 — Why this is hard (the limitations)

A normal RPC provider runs a full node with all state on local disk: every
`eth_call`, `eth_getBalance`, `eth_getTransactionCount` is a microsecond memory read.
We have neither the state nor a trusted upstream. We reconstruct and *prove* each read
on demand over peer-to-peer networks, on a battery-powered device. That gap is the
source of every limitation.

### 1.1 Network latency is the dominant cost

- **Every state read is a round-trip.** To answer one `eth_getBalance` we fetch a SNAP
  proof for the account and verify it against the head's state root. An `eth_call` that
  touches N accounts/slots needs **N proof round-trips** (account record + storage slots
  + contract bytecode per contract touched). The bottleneck is **network round-trip
  time, not CPU** — keccak/proof verification is well under 1% of wall-clock. This was
  confirmed repeatedly (VPN-exit and Starlink-vs-cellular experiments): what changes the
  outcome is the path, not the processor.

- **The 1000-token balance sweep is the worst case.** MetaMask's account tracker calls a
  batch `BalanceChecker` contract — `balances(address[] users, address[] tokens)` at
  `0xb1f8e55c…adf39` — passing its **entire ~1000-token list** in one ~32 KB `eth_call`.
  Executing it trustlessly means fetching+proving **~3000 reads** (account + code + one
  storage slot per token). Its cost is **independent of how many tokens you actually
  hold**: proving a balance is *zero* still requires the exclusion proof, so a brand-new
  empty address triggers the same ~3000 fetches as a whale. On a phone's peer set this
  does not complete inside any reasonable budget.

- **Thin, volatile mobile peer pools.** A phone holds far fewer, lower-quality eth/snap
  peers than a desktop daemon, and the set churns. During a dip the node has **no
  servable head for a few seconds to tens of seconds**, and verified reads must honestly
  error (`-32000 no verified head / not synced`) rather than guess.

- **CGNAT / Starlink / cellular path instability — HYPOTHESIS, under verification.** A
  proposed (not yet proven) factor: behind carrier-grade NAT the public endpoint is
  shared and the NAT mapping churns, inbound reachability for discovery fails, and
  long-lived snap connections may drop or stall — so *successful*-request latency can look
  fine (~40–260 ms observed on both a VPN and a no-VPN path) while a *fraction* of a large
  fetch wave silently stalls, which would be enough to push a 3000-fetch sweep past
  budget. A network switch (e.g. to a clean VPN exit) appearing to "fix" it would then be
  stable connections + a fresh peer set, not peer-reputation blacklisting (peers served us
  identically before and after the switch).
  **Caveat:** this is inferred, not measured — the logs show successful round-trips, not
  the stall/loss tail that would confirm it, and the device-class factor (§1.2) is a
  confounder. The decisive test is to hold the device constant (a flagship, removing the
  CPU variable) and compare networks, measuring the **snap-request stall rate**
  (requests sent that get *no* response, vs. answered): a high stall rate on the
  suspect path vs. a clean one would confirm it; comparable stall rates would refute it.
  Until that data exists, treat CGNAT as a *suspected* contributor, not an established one.

- **Cross-block state-root churn defeats naive caching.** The proof cache is keyed by
  world state root. The wallet re-pins its polls to the *newest* block each time, so the
  root changes every ~12 s slot and a heavy call that didn't finish in one block's window
  restarts cold against a new root.

- **Gas meters reads too — and on a light node it meters *fetches*.** An `eth_call` is
  "free" only in that it pays no ETH and persists nothing; it still runs the **same metered
  EVM** as a real transaction. Gas is the EVM's *halting / metering* mechanism, not just a
  fee: a Turing-complete call needs a ceiling or it could loop forever, and gas is also
  *semantically visible* (`gasleft()`, CALL stipends, EIP-150's 63/64 rule), so the limit
  can change what a call returns. So every `eth_call` runs under a gas limit (myotis uses a
  30 M default when the caller gives none). On a **light node this doubles as a network
  bound**: every gas-consuming state op (`SLOAD`, cold account access, a `CALL` into a
  contract) is a snap **fetch — a round-trip**. So the gas ceiling caps how many peer
  fetches one call can trigger — which is exactly why the 662-token BalanceChecker sweep
  ends in `OutOfGas` rather than fetching forever. The gas limit is the per-call *total
  work* bound; the §2.7 lane gate is the *concurrency* bound — complementary.

### 1.2 Phone CPU / runtime limits

- **Device class drives the *experience*, not just correctness.** It functions across
  device classes — but the latency, not whether it works, is what makes it acceptable or
  not. Every cost in this section compounds with CPU speed. Measured directly with the
  **same code, same account, same network** on two devices:
  - **Pixel 10 Pro Fold** (Tensor G5, 2025): comfortable — confirm screen renders, the
    Confirm button activates, and back-to-back ETH and ERC-20 sends confirm.
  - **Pixel 7** (Tensor G2, 2022; `GS201`, 8 GB): **works, but users won't like it.** The
    send flow does complete — sends confirm — but slowly. Measured on one send: **~3–5 min**
    from opening the confirm sheet to an *active* Confirm button, and on the order of
    **~15 min** to a fully-settled screen (fee value rendered), during which MetaMask ran
    a **continuous storm of ~9–18 `eth_call` errors every 30 s** (the declined sweep it
    keeps retrying, plus transient no-head errors) — a **~32 %** session error rate
    overall. Correct and functional, but far past the patience of a real user.

  The weaker CPU slows BLS verification, EVM execution, and head builds *simultaneously*,
  so the head lags further behind the chain tip, each rebuild takes longer, and the
  no-verified-head windows widen — which the wallet experiences as a burst of `-32000`
  errors and retries before the screen settles. This is a hardware floor we can't
  optimise past: it stays *correct* on older silicon, but the wait grows, so treat
  current-flagship class as the bar for an experience users will actually accept, and
  expect noticeably worse responsiveness on older/cheaper devices.

- **ART is much slower than a JIT JVM for crypto.** Pure-Java BLS (Milagro) verification
  runs ~**76× slower** on Android ART than on the desktop JVM, which made beacon
  catch-up appear to "hang". Mitigated (subgroup-skip, parallel decompression,
  period-gating) but inherent to the runtime.

- **Head builds are slow on-device.** Anchoring a fresh head (beacon-finalized root →
  header-chain → snap-built state head) takes **~20–60 s on a phone** versus seconds on
  the daemon. Consequence: the snap-built head **lags the consensus-layer optimistic
  block number by several blocks** at all times. Wallets that pin reads to the
  just-advertised latest number then ask for a block the lagging head "doesn't have yet"
  (see §2.10).

- **EVM-on-ART and APK/DEX budget.** Running Besu's EVM on ART is slower than on a
  server, and Android constrains method count / APK size, bounding how much we can throw
  at the problem locally.

### 1.3 Structural limits of a light node

- **No mempool.** A light node sees no pending pool, so it cannot natively report a
  *pending* nonce or surface a just-broadcast tx — addressed by an overlay/mini-mempool
  (§2.11), but inherent.

- **State is only retained by snap peers for a window.** Roots older than ~128 blocks are
  pruned by serving peers, so deep historical state is not generally fetchable. (Portal
  Network, which would have covered this, is effectively dead and is **not** treated as
  available infrastructure.)

---

## Part 2 — What we did about it (the optimisations)

Roughly in the order a confirm-screen request flows. Each entry notes the limitation it
attacks and the PR(s) where it landed.

### 2.1 Bounded-stale serving for head-tracking reads — #55
`eth_getBlockByNumber` / `eth_feeHistory` serve **verified-but-slightly-stale** data
(within `RPC_STATE_HEAD_MAX_STALE_MS` = 120 s) on a transient fetch failure instead of
erroring. The wallet re-polls, so old-but-proven is harmless — and a `-32000` here
empties the asset list / loops the fee step and hangs the send screen. *Attacks:* peer
dips (§1.1).

### 2.2 Nonce freshness gate — #55
`eth_getTransactionCount` is gated on a **fresh** head (`RPC_NONCE_SERVE_STALE_MAX_MS`
= 120 s): a stale nonce is what the wallet *signs against*, so when the head is too old
we error and let the wallet retry rather than hand back an outdated nonce. Tuned to
120 s specifically because on-device head builds routinely push head age past the old
30 s bound on a healthy node. *Attacks:* slow head builds (§1.2).

### 2.3 Stop re-serving pruned roots — #59
When a read fails because **no peer serves that state root** (`StateUnavailable`), evict
the doomed head context (CAS the last-good head, clear the pinned context) instead of
hammering a dead root. *Attacks:* peer churn (§1.1).

### 2.4 Fast-fail servability probe — #60 / #63
Before serving stale, run a short, **serialised** `anyPeerServesRoot` probe (no
thundering herd) so we don't spend the whole budget discovering a root is dead.
*Attacks:* peer churn / latency (§1.1).

### 2.5 Single-flight identical `eth_call`s — #62
MetaMask fires the *same* call 4–6× concurrently (its BalanceChecker sweep, the
Multicall3 confirm simulation). We dedupe by `(stateRoot, to, keccak(calldata))` so
duplicates **share one EVM execution + one snap fetch wave** instead of multiplying
hundreds of round-trips by N and starving the gating calls. *Attacks:* latency
amplification (§1.1).

### 2.6 Heartbeat-streamed responses + 120 s budget — #64
The HTTP layer trickles RFC-8259-legal leading whitespace while we compute, keeping the
wallet's socket alive so a genuinely long call gets a **120 s** budget
(`RPC_CALL_TIMEOUT_SEC`) instead of tripping the wallet's ~30 s read timeout and being
retried from scratch. *Attacks:* latency (§1.1) — lets bottleneck calls converge in one
attempt.

### 2.7 EVM lane separation — threads *and* peers *(this PR)*
Two complementary limits keep a heavy call (token sweep / big multicall) from holding up
the gating calls a send needs:
- **Thread lane:** calls with calldata ≤ `EVM_SMALL_CALLDATA_MAX` (4 KB) run on a
  **reserved small lane** (a dedicated EVM thread), so a confirm screen's tiny
  probes/simulations never queue behind a sweep's CPU.
- **Peer lane (`SnapLaneGate`):** threads aren't the contended resource — the thin snap
  *peer* pool is. Both lanes fetch from the same `activeSnapHandlers()` with no
  reservation, so a sweep firing dozens of concurrent `GetTrieNodes` requests would queue
  the gating fetches behind it at the *network* level. The gate caps a **heavy-lane**
  execution to **half the live snap peers** per concurrent snap request (dynamic, min 1),
  leaving the other half free for small/interactive calls (which never acquire a permit).
  The heavy call still runs to genuine completion / `OutOfGas` / timeout — it's bounded,
  **not rejected**. (This replaced an earlier `DECLINE_HEAVY_SWEEP` experiment that
  fast-failed the sweep by calldata size — a fake rejection that also blocked names from
  ever rendering; the lane is the honest version.)
*Attacks:* heavy-call starvation of gating calls, at both the CPU and peer level (§1.1).

### 2.8 Deeper, quality-biased snap pool — #46 #47 #60 #63 #66
- Target snap-peer count raised toward daemon parity (`TARGET_SNAP_PEERS` = 32 on
  Android).
- Per-head **denial of hanging/dropped/empty-proof peers** (#45 #46) so a flaky peer
  can't repeatedly stall a head.
- **rootServed peer preference + probe-gated eviction** (#66): prefer peers proven to
  serve the current head's root, and don't evict a head that's still servable.
- Persist snap-serving **quality** so good peers are dialled first (#47).
*Attacks:* thin/volatile pool (§1.1).

### 2.9 Caching that survives retries
- **Node-level `StateProofCache`** keyed by state root: verified account/storage reads
  are reused across calls so a wallet's repeated retries don't re-prove the same slots.
- **Pin-by-number context reuse**: a number-pinned read reuses a *frozen* head context
  so its (fixed) state root lets the cache accumulate across the wallet's minutes-long
  retries instead of resetting on every head rebuild.
- **Batched snap fetches** (#67): the prefetch wave is coalesced into a few
  `GetTrieNodes` requests (one path-set per account, chunked at `BATCH_PATHSET_CHUNK` =
  64) and verified from the combined response — turning a 1000-item sweep's ~1000
  sequential proofs into a handful of round-trips. Each item is still independently
  proven; only the *requests* coalesce.
- **Fee snapshot warming**: `eth_gasPrice` / `eth_maxPriorityFeePerGas` serve from a
  warm snapshot refreshed off the RPC path, so the confirm screen's fee poll is
  effectively instant.
*Attacks:* latency × retries, cross-block churn (§1.1).

### 2.10 Coherent block serving — re-anchor on the optimistic head *(this PR)*
**The big one for "works a few times then sticks."** `eth_blockNumber` advertises the
**CL optimistic** head (advances every slot), but block serving anchored on the
**snap-built** head, which lags by several blocks on a phone. A pin *ahead* of that
lagging anchor hit a `return "null"` — telling MetaMask the head block "doesn't exist".
Since MM's block tracker, tx-confirmation tracking, and confirm-screen refresh all gate
on fetching the head block, this **wedged the wallet** — observed as
`eth_getBlockByNumber` returning the `null` literal for **96 % of polls (778/806)**.

Fix: when the pinned number is ahead of the lagging anchor but at/under the optimistic
number, **re-anchor on the beacon optimistic exec payload** (its block hash is
light-client-verified) and verify the fetched header window hash-links to it via the
existing `windowAnchoredToHash` path. Only a pin beyond even the optimistic tip is
genuinely future/unknown → `null`. No trust change: same verification, correct anchor.
Measured effect on-device: block-null rate **96 % → ~50 %**, and multiple sends per
session succeed. *Attacks:* slow head builds (§1.2).

### 2.11 No-mempool sends — #69
- **Pending-nonce overlay**: `eth_getTransactionCount("pending")` reports
  `max(minedCount, ourBroadcastNonce + 1)` so two back-to-back sends from one account
  don't collide on a nonce. Only ever *raises* the value, only for txs we relayed
  ourselves (sender recovered by ECDSA from the signed bytes), never below the verified
  mined count; self-heals on mining or a 90 s TTL. (`"latest"`/numbered tags stay the
  proof-backed mined count — this is the one documented, deliberately-bounded
  exception; see the trust note in `getTransactionCount`.)
- **Gossip-confirmed mini-mempool**: after broadcasting, watch for our own tx hash
  returning over `Transactions` (0x12) / `NewPooledTransactionHashes` (0x18) gossip as
  propagation confirmation — decoded only while we hold an unconfirmed send, so the
  firehose stays free otherwise.
*Attacks:* no mempool (§1.3).

### 2.12 The heavy balance sweep — bounded, not rejected
The ~32 KB BalanceChecker token sweep (§1.1) is a **non-gating balance *display* poll** —
the *send* needs only nonce/fee/estimateGas/sendRawTransaction. An earlier experiment
(`DECLINE_HEAVY_SWEEP`) fast-failed it up front by calldata size, which kept the confirm
screen responsive but was a **fake rejection** — and it meant balances could *never*
render. That's been replaced by the peer-lane gate (§2.7): the sweep now **runs**, capped
to half the snap peers so it can't starve the gating calls, and ends in genuine
completion / `OutOfGas` / timeout.

Notes from measuring the unbounded version on-device:
- With MetaMask sending **no gas limit**, myotis applies its `DEFAULT_GAS_LIMIT`
  (30 M); the ~662-token sweep exceeds it and returns `OutOfGas` in ~700 ms **on a healthy
  pool** — a natural fast-fail, but only because batched prefetch gathered the state
  quickly. The work isn't skipped, so on a thin pool that same call is slow; the lane gate
  is what keeps it from dragging the gating calls down with it. (The `OutOfGas` isn't a
  payment thing — it's the gas *meter* hitting its ceiling, which on a light node also caps
  the fetch count; see §1.1 "Gas meters reads too".)
- **Token balances still may not render** (the sweep can't complete on a light node within
  any sane gas/time budget). The durable path to actually *display* them is a convergent,
  cached balance flow (pin one stable root so the proof cache accumulates across polls, or
  a background warmer for the active address) — never a fabricated zero.

### 2.13 Android runtime mitigations
- **BLS on ART** (#48 and follow-ups): bound + deprioritise G1 decompression, subgroup-
  skip, parallel decompress, period-gate — stops UI-starvation ANRs and the
  catch-up "hang".
- **discv4 UDP**: `FixedRecvByteBufAllocator(4096)` + `SO_RCVBUF` so large `NEIGHBORS`
  packets aren't truncated (discovery was dead on ART without it).
- **Sync-committee snapshot persist/resume**: persist the verified store to the cache
  dir and resume on restart, catching up only the delta instead of re-bootstrapping.
- **discv5 free-port fallback**: avoid the emulator's OpenThread squatting on UDP 9000.
*Attacks:* ART/runtime limits (§1.2).

---

## Part 3 — Where it stands

- **Sends work**, including back-to-back, on a real device once the node is warm — the
  combination of coherent block serving (§2.10), the pending-nonce overlay (§2.11), and
  declining the heavy sweep (§2.12) unblocks the confirm + send flow.
- **Token balances are the open rough edge**: the heavy sweep is declined, so balances
  may not render; the convergent successor in §2.12 is the planned durable fix.
- **A cold-start / peer-dip window still errors honestly** for a few seconds after
  launch or during a snap-peer dip — by design (we error rather than guess), but it is
  why "let it reach the green readiness strip first" matters before transacting.
- **Device class sets the experience bar.** It works on a 2022 mid-tier phone (Pixel 7)
  — sends confirm — but only after a wait users won't accept; it's comfortable on a
  current flagship (Pixel 10 Pro Fold). Correctness is constant across the range; only
  responsiveness changes, and below flagship class the wait is the product problem (see
  §1.2).
- **Path quality still dominates outcomes.** On a clean, low-latency, non-CGNAT path the
  node is comfortably usable; on a degraded path (CGNAT/Starlink with stalls) heavy work
  suffers. We cannot fix the uplink, so the durable direction is to make the node *less
  sensitive* to it: bound/converge heavy calls, bias toward fast/stable peers, and keep
  the gating path cheap and lane-isolated.

*Trust posture, restated: every optimisation here changes performance, freshness, or
which verified anchor is used — never what is trusted. Unverifiable answers error; they
are never proxied or faked.*
