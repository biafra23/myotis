# The Status screen — every item explained

This documents everything shown for a network on the shared Compose UI (Android +
desktop; iOS shares the same `NodeScreen.kt` composables) once a chain is
selected: the readiness strip and banners above the tabs, and every row of the
**Status** tab itself. Source: `ui/src/commonMain/kotlin/io/myotis/ui/NodeScreen.kt`
(`NodeScreen`, `ReadinessStrip`, `StatusTab`, `StatusView`), fed by
`NodeController.NodeSnapshot`.

Every value here reflects the *selected* network — the chips above the strip
switch which chain's snapshot is shown.

## Readiness strip

A thin colored bar above the tabs — the wallet's "safe to transact" signal for
the selected chain. Full semantics (including the 45 s "warming up" threshold
and the deep-pool default) are in `docs/readiness-and-verified-head-age.md`;
summary:

| Color / height | Meaning |
|---|---|
| grey | sleeping (idle-paused) — an incoming request wakes it |
| red — not running | the network isn't started |
| red — not verifying | peers report a network upgrade this build doesn't support, and the node's own state (unsynced or stale head) corroborates it — update the app |
| red — sync anchor too old | parked in `STALE_ANCHOR`, waiting on the consent dialog below |
| red — not synced | beacon light client isn't `SYNCED` yet |
| amber | `SYNCED`, but verified head age is over 45 s — warming up, wallet calls would still error |
| green (thin) | ready for simple reads |
| green (thick) | fully ready — snap-serving peer pool at or above the deep-pool threshold (Settings), so heavy confirm screens load too |

## Stale-anchor consent dialog

Appears only while the selected (or any) network is parked in `STALE_ANCHOR`:
the engine refuses to sync from a trust anchor older than the network's
weak-subjectivity bound until you decide. Three ways out, all described in
`docs/readiness-and-verified-head-age.md` under `STALE_ANCHOR`: update the app
(ships a fresher checkpoint), raise the bound in Settings, or "Sync anyway" —
accepts the risk for this run only, never persisted. Dismissing without a
choice just hides the dialog; it reappears if the network parks again later.

## Banners (above the sync bar, inside the Status tab)

- **Offline banner** — shown when the device has no connectivity at all
  ("No internet connection… Open network settings").
- **Network upgrade banner** — peers announce (`SCHEDULED`) or report already
  active (`ACTIVE`) a fork this build doesn't support. It is advisory only
  (unverified peer data) and never itself claims the node stopped verifying;
  it turns into an alarm ("Update required") only once the node's *own*
  verified state agrees — unsynced, or verified head gone stale. Shows the
  activation time, how many distinct peer networks reported it, and the fork
  id.
- **Hunt banner** ("Hunting for light-client servers and/or snap peers…") —
  the light client and/or the EL pool are starved of usable servers and
  running boosted discovery/probing to find more. Tracks `lcHunting` /
  `elHunting`.

## Sync progress bar

Shown while the beacon side is not yet `SYNCED` (hidden once it is, or if the
network is stopped):

- **`STALE_ANCHOR`** — no bar (nothing is progressing): text states the anchor
  age in periods against the enforced bound, and that it's waiting on your
  decision.
- **Bootstrapping** (state not yet `CATCHING_UP`) — indeterminate bar,
  "Bootstrapping light client…".
- **`CATCHING_UP`**, start period known — determinate bar, "Catching up sync
  committees — period *current* / *target*" (or "Finishing sync…" once
  current reaches target).
- **`CATCHING_UP`**, start period unknown — indeterminate bar, "Catching up
  sync committees…".

## Status rows

In on-screen order. "Row label" is the literal left-hand text.

| Row | Meaning |
|---|---|
| **Network** | The chain name (mainnet / sepolia / gnosis / …). |
| **State** | Stack lifecycle: `Sleeping (wakes on request)` (idle-paused — networking off, RPC still listening), `Running`, or `Stopped`. |
| **Beacon** | The beacon light client's sync state: `STARTING`, `SYNCING`, `CATCHING_UP`, `SYNCED`, or `STALE_ANCHOR`. Full definitions in `docs/readiness-and-verified-head-age.md` §Beacon sync states. This is the trust-anchor side of readiness — a node can be here `SYNCED` yet still not `readyForReads` (see Head age below). |
| **EL block** | The execution-layer block number the node currently tracks as its (optimistic) head. |
| **Log index** | Only shown when the log index feature applies. A short progress string, e.g. `12,041 logs · 5,594,611–8,461,900`, or `backfilling`. See `docs/eth-getlogs-design.md` / `docs/logindex-verified-bundle-design.md`; the Index tab has the full detail view for this feature. |
| **Tor** | Only shown when applicable (Rust engine + a Tor-capable build; see `docs/privacy-and-tor.md`). `off` = supported but disabled; `on — circuit bootstrapping…` = enabled, circuit not ready yet; `routing reads (circuit ready)` = enabled and verified reads are actually routing over Tor (highlighted in the theme's primary color). |
| **CL peers** | Consensus-layer (libp2p) peer activity: `served N/min` = distinct peers that answered a light-client request in the last 60 s; `con N` = currently-connected libp2p peers (usually near 0 — CL connections are short-lived, made just long enough to fetch a bootstrap/update and dropped). |
| **EL peers** | Execution-layer pool: `N` ready peers total, of which `snap M` negotiated the snap/1 capability, and `serving K` are in the pool actually able to answer a read right now (near the current head, not benched after a failed read). Reads gate on `serving`, not `snap` — right after reaching `SYNCED` a cold pool can be full of peers that are themselves still syncing (#465), which keeps `snap` positive for hours while every read fails. |
| **CL cache** | Peers remembered in the on-disk CL peer cache, parsed live from the cache file (cross-engine — both engines read/write the same file). Format `total · ✓proven ✕nolc ?untried`: `✓` = proven light-client servers (served a catch-up range or bootstrap, or Identify-confirmed), `✕` = confirmed *not* a light-client server (skipped when dialing for updates), `?` = untried. Predicts how fast the *next* cold start finds servers. |
| **EL cache** | Same idea for the on-disk EL (snap) peer cache: `total · ✓snapOk ✕snapBad ?untried` — confirmed snap-serving, confirmed snap-denied, or untried. |
| **Hdr asks** | Inbound demand from other peers for headers we serve: `N asked · served M` — how many `GetBlockHeaders` requests arrived and how many got a non-empty reply. |
| **Blk asks** | Same for `GetBlockBodies` requests. Served count is always 0 by design — this is a light client that holds no bodies, so it replies with a prompt empty response rather than not answering. |
| **Reads** / **Cacheable** / **Stale ≤60s ok** | The read-fetch shadow-cache counters — appear only once at least one verified state fetch has been observed. Fully documented in `docs/read-stats.md`; short version: **Reads** is the raw count of verified account/storage/code fetches since start; **Cacheable** is the share of each kind a *sound* cache keying (storage-root for slots, per-block for accounts, content-addressing for code) would have served for free, with the time it would have saved; **Stale ≤60s ok** is the *ceiling* for an unsound "just serve a value up to a minute old" strategy — how often that would have happened to be correct, with no proof backing it. |
| **Discovered** | Total peers discovered via discv4/discv5 this session. |
| **Discv5 peers** | Live nodes currently in the discv5 (CL-side) routing table. |
| **In backoff** | Peers currently in dial backoff (a recent connection attempt failed; won't be redialed until the backoff expires). |
| **Blacklisted** | Peers permanently blacklisted this session (protocol violations, etc.) — never dialed again until restart. |
| **RPC** | The local JSON-RPC listener for this network. Hidden entirely when the host doesn't report a port (`rpcPort == 0`). Otherwise `127.0.0.1:<port>` if serving, or `port <port> unavailable` (shown in the error color) if the bind failed — typically another process already holds that port. |
| **Sync period** | Sync-committee period progress: `current / target`. While parked in `STALE_ANCHOR`, `current` is the *refused* anchor's period and `target` is the period the wall clock is in — their difference is the anchor's age in periods, shown in the stale-anchor banner/dialog. |
| **Head age** | `Long.MAX_VALUE` displays as `—` ("no verified head yet — no state read can be served"); otherwise the freshness in ms of the head context verified reads are currently served against. Meaning differs by engine (rebuild-timer on Java, block-advance timer on Rust) — full explanation in `docs/readiness-and-verified-head-age.md` §What "verified head age" means. The UI's own amber/green threshold is 45 s. |
| **Uptime** | Seconds since this network's stack started running. |
| **Sleep** | Idle-sleep (pseudo-sleep) summary: `always on` if the host has no idle controller at all (e.g. desktop); `never slept` if it supports sleep but hasn't paused yet; otherwise `<duration> over N pause(s)` — cumulative time spent idle-paused and how many times. |
| **Last woke** | Only shown once there has been at least one demand wake. `<time> (<reason>) · slept <time>` — when the node last woke on a real request (foreground/app-open wakes are excluded so this keeps showing the last *meaningful* wake), why, and when it had gone to sleep before that. |

## Actions below the rows

- **Start `<network>` / Stop** — runtime-only start/stop, independent of the
  network's enabled switch in Settings (stopping from here doesn't disable
  it). Start is disabled while offline (discovery has nothing to reach).
- **Clear peer caches** — wipes the on-disk peer caches through the engine
  (so a live stack can't write the old peers back) — gives discovery a fresh
  slate. Only enabled while the network is stopped, to make the accidental
  click on a running node impossible.
- **Reset sync state** — deletes the persisted sync-committee snapshot so the
  next start re-bootstraps from the embedded checkpoint. Also gated to
  "stopped only"; unlike the cache clear this only ever takes effect at the
  *next* start (stop → reset → start is the reliable sequence).

## READY peers list

Shown at the bottom once there is at least one ready peer: one row per peer —
its remote address and whether it negotiated `snap`, with its reported client
identifier (e.g. `Geth/v1.…`) beneath, or `(no clientId)` if the peer didn't
send one.

## See also

- `docs/readiness-and-verified-head-age.md` — the full readiness model behind
  the strip, the Beacon row, and the Head age row.
- `docs/read-stats.md` — the Reads/Cacheable/Stale rows in depth, including
  the exact JSON schema and how to read the numbers.
- `docs/privacy-and-tor.md` — what the Tor row's three states mean and why.
- `docs/eth-getlogs-design.md`, `docs/logindex-verified-bundle-design.md` —
  the Log index row and the Index tab it summarizes.
