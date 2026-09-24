# Readiness: when is the node synced and ready for queries?

This document explains when a Myotis node considers itself **synced**, when it is
actually **ready to answer queries with verified data**, and what the
**"verified head age"** shown on the Status screen means. It applies to all three
hosts (Android app, desktop app, daemon) and both engines (Java and Rust), with
engine differences called out where they exist.

## TL;DR — how to tell it's ready

- **In the apps**: the readiness strip under a network's status card is **green**
  ("ready for simple reads") or **bright green** ("fully ready — deep peer pool").
- **On the daemon**: `./gradlew :app:run -Pargs=beacon-status` returns
  `"state":"SYNCED"`, and a query such as `get-account` returns
  `"verifyMethod":"headerChain"` (or `"stateRootMatch"`) instead of a `failReason`.
- **Over JSON-RPC** (Android's loopback `127.0.0.1:8545`): requests return data
  instead of error `-32000` (method cannot be served verified right now —
  retryable).

Being *synced* is necessary but not sufficient: a node can be beacon-SYNCED and
still unable to serve reads (e.g. no snap-serving peers yet). Readiness is the
conjunction of three gates, described next.

## The three readiness gates

A verified read (balance, nonce, code, storage, `eth_call`, …) can only be served
when all three of these hold:

1. **Beacon light client is SYNCED** — the node holds a current sync-committee
   and a recent *finalized* execution state root attested by ≥ 2/3 of the sync
   committee. This is the trust anchor: every answer is ultimately verified
   against it. Until the first finalized root lands, queries fail with
   `failReason: "beaconNotSynced"`; a node that later falls out of SYNCED keeps
   answering against its last anchor, so that shows in its beacon state, not
   as a read error.

2. **At least one snap-serving EL peer is connected** — account/storage data is
   fetched as snap/1 Merkle-Patricia proofs from execution-layer peers. Two
   counts describe this: `snapPeers` is every snap-capable peer in the pool,
   and `snapServingPeers` (Rust engine, ABI ≥ 31) is the subset that can answer
   a read at the anchored head *now* — their announced or served head is at or
   near ours and they are not benched after a failed read. The Rust hosts gate
   on `snapServingPeers`: right after SYNCED a cold pool can be full of peers
   that are still syncing themselves, which keep `snapPeers` positive for hours
   while every read fails with `peer returned 0 headers` (#465). The UI shows
   both on the EL peers line ("snap N · serving M").

3. **A verified head context has been built** — the node has recently anchored a
   peer-reported head block to the beacon-finalized block via a contiguous,
   parent-hash-verified header chain. "Verified head age" (below) measures how
   fresh this gate is; `readyForReads` requires it to be finite.

The engine-internal check is gates 1 + 3, plus the stack actually running
(`ChainStack.readyForReads()`: stack `RUNNING`, state == `SYNCED`, **and**
`verifiedHeadAgeMs != Long.MAX_VALUE`); gate 2 is implied because a head context
cannot be built or refreshed without snap peers. On the Rust engine there is no
separate head context (see the age measurement below), so the check is gates
1 + 2 with `snapServingPeers > 0` standing in for gate 3: a pooled peer whose
head is behind ours satisfies neither.

## Beacon sync states

The state reported by `beacon-status`, `myotis_beaconStatus`, and the UI:

| State | Meaning |
|---|---|
| `STARTING` | The network handle exists but hasn't started syncing yet. |
| `SYNCING` | No trust anchor yet: bootstrapping from the checkpoint, no finalized execution state root landed. Verified queries fail (`beaconNotSynced`). |
| `CATCHING_UP` | Trust anchor present but not dependable: the light client is replaying sync-committee periods, hasn't accumulated enough recent finalized roots, or its finalized head is more than 5 epochs behind the wall clock (a stalled or withheld light-client feed, or a warm start whose finality is still the snapshot's). |
| `SYNCED` | Verification-ready: the sync committee is current and the finalized head is recent. **Not latched** — a node can regress to `CATCHING_UP` (e.g. after sleeping across a committee-period boundary, or when finality stops arriving) and come back. |
| `STALE_ANCHOR` | Syncing **refused**: at sync start (cold, or a warm resume from idle-pause — a pause longer than the bound ages the held committee the same way) the best available trust anchor (embedded checkpoint or persisted snapshot, whichever is newer; on warm resume the store's held committee) was older than the network's weak-subjectivity bound — every later bootstrap attempt re-faces the gate against the embedded checkpoint, and every steady-state poll cycle re-checks the HELD committee's age, so a node that stays awake but starved past the bound parks too (restart-vs-stay-running never decides whether the gate applies) (README §Weak-subjectivity age bound; mainnet 13 periods ≈ two weeks). Past that window a forged continuation signed by since-exited committee members would BLS-verify, so the engine parks fail-closed and waits for a decision: update the binary / refresh the checkpoint, raise the bound (Settings / `-Dmyotis.beacon.wsBoundPeriods` / `ChainHandle.setWsBoundPeriods` — applied live), or accept the risk for this run (the apps' dialog / `accept-stale-anchor` / `ChainHandle.acceptStaleAnchor`). While parked, `currentPeriod` is the refused anchor's period, `targetPeriod` the wall clock, and `wsBoundPeriods` the enforced bound. The check trusts the device wall clock (a backwards clock reads as fresh) — clock integrity is outside this threat model, consistent with `SYNCED`'s wall-clock criteria. |

Both engines require the held sync-committee period to be the wall clock's
**and** the finalized slot to be within **5 epochs** of the wall-clock slot
(`SYNCED_SLOT_SLACK_EPOCHS`, counted in the network's own epochs: 32 min on
mainnet and sepolia, ~7 min on gnosis; finality itself trails ~2 epochs), so a
stalled light-client feed drops either engine out of SYNCED once its last
finality is that old. Beyond that:

- **Java engine** (`BeaconSyncState.getSyncState`): SYNCED also requires a
  finalized execution state root and **≥ 4 known state roots** in the attested
  window (i.e. at least two successful finality polls).
- **Rust engine** (`sync.rs::sync_state_at`): the Rust engine also has an
  internal `BOOTSTRAPPING` state, reported to hosts as `SYNCING`.

## What "verified head age" means

Shown on the Status screen as **"Verified head age: N ms"** (or `—` when there is
none yet), and carried in the engine API as `StatusSnapshot.verifiedHeadAgeMs`.

It answers: *how stale is the head context that verified reads are currently
served against?* A small value means answers reflect the chain as of a few
seconds ago; `Long.MAX_VALUE` (displayed `—`) means no verified head has been
built yet, so no state read can be served.

The measurement differs per engine:

- **Java engine**: milliseconds since the anchored RPC head context was last
  successfully **rebuilt**. A background warmer rebuilds it every ~5 s while
  peers cooperate, so a healthy node hovers in the low seconds. The clock is
  monotonic (`System.nanoTime` / `SystemClock.elapsedRealtime`), so device sleep
  or clock changes don't corrupt it.
- **Rust engine**: milliseconds since the optimistic head **block number last
  advanced** — a new block roughly every 12 s (mainnet) resets it to 0. If the
  engine is not currently serveable (not SYNCED, no head, or no *serving* snap
  peer — `snapServingPeers == 0`) it reports `Long.MAX_VALUE`, and the timer
  restarts from 0 when serving resumes.

In both cases: **fresh = ready, stale = warming up or wedged**. The shared UI
draws the line at **45 s** (`READY_HEAD_WARM_MS`): beyond that the strip turns
amber ("warming up, not ready to transact") even though the beacon side is
SYNCED, because reads would be served from an aging head or refused.

Note that head age is *not* the age of the latest block — it's the age of the
node's last successful verification of a head. The chain keeps moving regardless;
this number tells you whether the node is keeping up with it.

### How stale is too stale? (serve behavior as the head ages)

The Java RPC backend reuses and, within limits, serves a last-good head rather
than failing while a refresh is in flight:

- **≤ 12 s** — a built head is reused as-is across a burst of requests.
- **≤ 30 s** — the last-good head is served while a rebuild runs in the background.
- **≤ 120 s** — hard cap for *state* reads (balances, code, storage, `eth_call`,
  gas estimates) in the default **strict** mode, and always the cap for nonces
  (`eth_getTransactionCount`), since a stale nonce breaks transaction signing.
- **≤ ~12.8 min** — header-only last resort (e.g. `eth_blockNumber`,
  `eth_getBlockByNumber`), and the cap for state reads only if strict state
  freshness is explicitly disabled (`-Dmyotis.rpc.strictStateFreshness=false`;
  Android exposes this as a Settings toggle, off by default).

Beyond the applicable cap the node **refuses** (JSON-RPC `-32000`, IPC
`failReason`) rather than serving an unverifiable or misleading answer.

## Where to observe readiness, per host

### Android + desktop apps (shared UI)

Each network card has a readiness strip, evaluated top-down:

| Strip | Meaning |
|---|---|
| grey | sleeping (idle-paused) — an incoming request wakes it |
| red | not running, or beacon not SYNCED |
| amber | SYNCED but verified head age > 45 s — warming up, not ready to transact |
| green | ready for simple reads |
| bright green (thicker) | fully ready — deep snap-peer pool (≥ 16 serving peers by default) |

The Android foreground notification condenses the same tiers into words:
`sleeping` → `syncing` → `warming up` (SYNCED but no verified head yet) →
`ready`, per network (e.g. "mainnet ready · gnosis syncing"). The Status screen
additionally shows the raw "Verified head age" row, and a banner warns when the
beacon side is unsynced (any values shown then are peer-claimed, not verified).

### Daemon (IPC / CLI)

```bash
./gradlew :app:run -Pargs=beacon-status   # "state": "SYNCING" | "CATCHING_UP" | "SYNCED"
./gradlew :app:run -Pargs=status          # lifecycle, peer counts incl. snapPeers
./gradlew :app:run -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
```

`beacon-status` shows the sync state plus progress (`currentPeriod` /
`targetPeriod` while catching up; `finalizedSlot`, `executionBlockNumber`,
`knownStateRoots` once synced). A query response's `verification` object gives
the definitive answer: `verifyMethod` (`headerChain` or `stateRootMatch`) on
success, an ordered `failReason` token (`beaconNotSynced`, `noPeerStateRoot`,
`headerChainGapTooLarge`, …) otherwise.

### JSON-RPC (wallet-facing)

`myotis_status` and `myotis_beaconStatus` mirror the IPC fields. Verified
`eth_*` methods return `-32000` while any readiness gate is unmet — wallets
should treat it as retryable.

An out-of-process wallet that idle-pauses the node with `myotis_pause` should
call `myotis_wakeup` and then poll these two status methods back through the
readiness gate (`myotis_status.state == "RUNNING"` with `snapServingPeers > 0`,
and `myotis_beaconStatus.state == "SYNCED"`) **before** its first `eth_*` read —
`myotis_wakeup` returns when the rebuild *starts*, not when the node is ready
again (see disk-and-network-usage.md §4.1). Gate on `snapServingPeers`, not on
`snapPeers`: right after SYNCED a cold pool of still-syncing peers keeps
`snapPeers` positive for hours while every read fails (#465). Even so a read
can still come back as the retryable `-32000` — the in-process hosts hold such
a read only around a start or resume warm-up, and for at most 90 s
(`WAKE_WAIT_CAP_MS`); on a stack that has been running, the read proceeds at
once and fails in-band (#312) — so keep polling and retry.

## Block tags

Readiness is judged at the optimistic head, and so are `latest`, `safe` and
`pending` (the light client has no justified anchor to apply, so `safe` and
`pending` resolve to the head — documented, not silent; #366). The `finalized`
tag is **applied** since engine ABI 30 (#465): `eth_call`, `eth_getBlockByNumber`,
`eth_getBlockReceipts` and `eth_feeHistory` run against, or serve, the
beacon-finalized block, whose header window needs no path to the optimistic
head — so a finalized read can succeed while a `latest` read still fails on a
pool that lacks the head. Since ABI 32 the state reads (`eth_getBalance`,
`eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`) apply it too on
the Rust engine: the snap proof is verified against the finalized state root,
and a peer that has pruned that state fails the attempt rather than answer
from another block — a miss that is not held against the peer. Best effort by
nature: execution clients keep on the order of a hundred recent states (geth:
~128 blocks) and finality trails the head by two epochs (64–96 blocks), so a
finality delay puts the finalized state out of every peer's reach and the read
comes back as the retryable `-32000` until finality catches up. The converse
also holds: while the beacon status has regressed out of SYNCED (a CL-side
stall), a `finalized` state read keeps answering at the last-known finalized
root for as long as a deep-state peer still proves it — verified and labeled
as such (`anchor: "finalized"`, `matchedBeaconSlot` = that finality's slot),
but stale. `latest` does not refuse either: `beaconNotSynced`, like
`beaconSynced: false` on a result, only means no finalized root has ever
landed. So keep honoring the SYNCED gate for `finalized` reads too;
staleness does not always surface as `-32000`. On the JVM host the
start/resume warm-up hold applies to `finalized` reads too (it waits for a
head-serving peer that a finalized read does not need — at most 90 s).
The Java engine still resolves `finalized` to the head (#366).

## Code pointers

- Java sync states + criteria: `consensus/.../BeaconSyncState.java`
- Rust sync states + criteria: `rust/myotis-net/src/sync.rs` (`sync_state_at`, `publish_status`)
- Head age (Java): `rpc-backend/.../VerifiedRpcBackend.java`
  (`verifiedHeadAgeMs`, staleness constants `RPC_*_MS`)
- Head age (Rust mapping): `myotis-engines/.../RustChainHandle.java` (`status()`)
- Readiness gate: `node-core/.../ChainStack.java` (`readyForReads`)
- UI strip + 45 s threshold: `ui/.../NodeScreen.kt` (`ReadinessStrip`, `READY_HEAD_WARM_MS`)
- Verification ladder (verifyMethod/failReason): `node-core/.../VerifiedAccountQuery.java`,
  `rust/myotis-net/src/el/verify.rs`
