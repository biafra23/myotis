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
   against it. Without it, queries fail with `failReason: "beaconNotSynced"`.

2. **At least one snap-serving EL peer is connected** — account/storage data is
   fetched as snap/1 Merkle-Patricia proofs from execution-layer peers. The
   `snapPeers` count in `status` output shows this; the UI shows it as the
   EL peers line.

3. **A verified head context has been built** — the node has recently anchored a
   peer-reported head block to the beacon-finalized block via a contiguous,
   parent-hash-verified header chain. "Verified head age" (below) measures how
   fresh this gate is; `readyForReads` requires it to be finite.

The engine-internal check is gates 1 + 3, plus the stack actually running
(`ChainStack.readyForReads()`: stack `RUNNING`, state == `SYNCED`, **and**
`verifiedHeadAgeMs != Long.MAX_VALUE`); gate 2 is implied because a head context
cannot be built or refreshed without snap peers.

## Beacon sync states

The state reported by `beacon-status`, `myotis_beaconStatus`, and the UI:

| State | Meaning |
|---|---|
| `STARTING` | The network handle exists but hasn't started syncing yet. |
| `SYNCING` | No trust anchor yet: bootstrapping from the checkpoint, no finalized execution state root landed. Verified queries fail (`beaconNotSynced`). |
| `CATCHING_UP` | Trust anchor present but not yet dependable: the light client is replaying sync-committee periods or hasn't accumulated enough recent finalized roots. |
| `SYNCED` | Verification-ready: the sync committee is current and the finalized head is recent. **Not latched** — a node can regress to `CATCHING_UP` (e.g. after sleeping across a committee-period boundary) and come back. |
| `STALE_ANCHOR` | Syncing **refused**: at cold sync start, the best available trust anchor (embedded checkpoint or persisted snapshot, whichever is newer) was older than the network's weak-subjectivity bound (README §Weak-subjectivity age bound; mainnet 13 periods ≈ two weeks). Past that window a forged continuation signed by since-exited committee members would BLS-verify, so the engine parks fail-closed and waits for a decision: update the binary / refresh the checkpoint, raise the bound (Settings / `-Dmyotis.beacon.wsBoundPeriods` / `ChainHandle.setWsBoundPeriods` — applied live), or accept the risk for this run (the apps' dialog / `accept-stale-anchor` / `ChainHandle.acceptStaleAnchor`). While parked, `currentPeriod` is the refused anchor's period, `targetPeriod` the wall clock, and `wsBoundPeriods` the enforced bound. The check trusts the device wall clock (a backwards clock reads as fresh) — clock integrity is outside this threat model, consistent with `SYNCED`'s wall-clock criteria. |

The two engines use slightly different criteria for `SYNCED` (same contract,
different heuristics):

- **Java engine** (`BeaconSyncState.getSyncState`): SYNCED requires a finalized
  execution state root, **≥ 4 known state roots** in the attested window (i.e. at
  least two successful finality polls), and the tracked sync-committee period to
  match the wall-clock period.
- **Rust engine** (`sync.rs::publish_status`): SYNCED requires the store's
  committee period to match the wall-clock period **and** the finalized slot to
  be within **5 epochs** of the wall-clock slot (finality itself trails ~2
  epochs). The Rust engine also has an internal `BOOTSTRAPPING` state, reported
  to hosts as `SYNCING`.

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
  engine is not currently serveable (not SYNCED, no head, or no snap peers) it
  reports `Long.MAX_VALUE`, and the timer restarts from 0 when serving resumes.

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

## Code pointers

- Java sync states + criteria: `consensus/.../BeaconSyncState.java`
- Rust sync states + criteria: `rust/myotis-net/src/sync.rs` (`publish_status`)
- Head age (Java): `rpc-backend/.../VerifiedRpcBackend.java`
  (`verifiedHeadAgeMs`, staleness constants `RPC_*_MS`)
- Head age (Rust mapping): `myotis-engines/.../RustChainHandle.java` (`status()`)
- Readiness gate: `node-core/.../ChainStack.java` (`readyForReads`)
- UI strip + 45 s threshold: `ui/.../NodeScreen.kt` (`ReadinessStrip`, `READY_HEAD_WARM_MS`)
- Verification ladder (verifyMethod/failReason): `node-core/.../VerifiedAccountQuery.java`,
  `rust/myotis-net/src/el/verify.rs`
