# The Status screen — every item explained

This documents everything shown for a network on the shared Compose UI (Android +
desktop; iOS shares the same `NodeScreen.kt` composables) once a chain is
selected: the readiness strip and banners above the tabs, and every row of the
**Status** tab itself. Source: `ui/src/commonMain/kotlin/io/myotis/ui/NodeScreen.kt`
(`NodeScreen`, `ReadinessStrip`, `StatusTab`, `StatusView`), fed by the
top-level `NodeSnapshot` data class (`ui/.../NodeController.kt`).

Every value here reflects the *selected* network — the chips above the strip
switch which chain's snapshot is shown — with one exception: the stale-anchor
dialog (below) can pop up for *any* parked network, selected or not.

Host coverage isn't uniform: iOS never fills the READY peers list or the
Sleep/Last woke fields (idle-sleep metrics aren't wired there yet), and the
Tor row is desktop-only (see that row below).

The app shows a condensed version of this explanation in place: rows marked
"ⓘ" open it in a dialog on a single tap anywhere on the row, and each of the
three actions — Start / Stop (one "ⓘ" for the pair), Clear peer caches, Reset
sync state — has an "ⓘ" beside it (the buttons' own tap stays the action). The
dialog is titled with the row or action's name and stays open until dismissed
(Close, tap outside, or back). The text lives in the `StatusHelp` object in
`NodeScreen.kt`. **The two are meant to stay in sync**: a behavior change that
changes what a row or action means must update both `StatusHelp` and this doc.

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
| amber | `SYNCED`, but verified head age is over 45 s (or there is no verified head yet) — warming up or wedged: reads are refused, or served from a head that has stopped advancing |
| green (thin) | ready for simple reads |
| green (thick) | fully ready — snap-serving peer pool at or above the deep-pool threshold (Settings), so heavy confirm screens load too |

## Stale-anchor consent dialog

Appears while any network is parked in `STALE_ANCHOR` — not only the selected
one; the dialog names the affected network in its title ("Sync anchor too
old — Gnosis"). The engine refuses to sync from a trust anchor older than the
network's weak-subjectivity bound until you decide. Three ways out, all described in
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
  "Bootstrapping light client…". Desktop/iOS only: Android maps `STARTING` to
  `STOPPED` (see the Beacon row above), and the bar's own early-return on
  `STOPPED` means it never shows this phase there.
- **`CATCHING_UP`**, start period known — determinate bar, "Catching up sync
  committees — period *current* / *target*" (or "Finishing sync…" once
  current reaches target).
- **`CATCHING_UP`**, start period unknown — indeterminate bar, "Catching up
  sync committees…".

## Status rows

In on-screen order. "Row" is the literal left-hand text label.

| Row | Meaning |
|---|---|
| **Network** | The chain name (mainnet / sepolia / gnosis / …). |
| **State** | Stack lifecycle: `Sleeping (wakes on request)` (idle-paused — networking off, RPC still listening), `Running`, or `Stopped`. |
| **Beacon** | The beacon light client's sync state: `STARTING` (shown as `STOPPED` on Android, where the sync bar is then hidden too — see below), `SYNCING`, `CATCHING_UP`, `SYNCED`, or `STALE_ANCHOR`. Full definitions in `docs/readiness-and-verified-head-age.md` §Beacon sync states. This is the trust-anchor side of readiness — a node can be here `SYNCED` yet still not `readyForReads` (see Head age below). |
| **EL block** | The execution-layer block number of the latest beacon-*finalized* payload (`StatusSnapshot.executionBlockNumber`) — not the optimistic head that `eth_blockNumber` reports. On a healthy node it trails the chain head by about two epochs (~64–96 blocks on mainnet). |
| **Log index** | Only shown when the log index feature applies. A short progress string, e.g. `12,041 logs · 5,594,611–8,461,900`, or `backfilling`. See `docs/eth-getlogs-design.md` / `docs/logindex-verified-bundle-design.md`; the Index tab has the full detail view for this feature. |
| **Tor** | Desktop only, and only when applicable (Rust engine + a `-PtorEngine` build; see `docs/privacy-and-tor.md`) — Android and iOS never populate this row. `off` = supported but disabled; `on — circuit bootstrapping…` = enabled, circuit not ready yet; `routing reads (circuit ready)` = enabled and a Tor circuit is ready (highlighted in the theme's primary color). **Scope: only account (balance/nonce) reads route over Tor today** — token/storage reads, `eth_call`/gas estimation, tx broadcast, the CL fetch, and discovery still leave from your real IP; full coverage is a follow-up. |
| **CL peers** | Consensus-layer (libp2p) peer activity: `served N/min` = distinct peers that answered a light-client request in the last 60 s; `con N` = currently-connected libp2p peers (usually near 0 — CL connections are short-lived, made just long enough to fetch a bootstrap/update and dropped). |
| **EL peers** | Execution-layer pool: `N` ready peers total, of which `snap M` negotiated the snap/1 capability, and `serving K` are in the pool actually able to answer a read right now (near the current head, not benched after a failed read). Reads gate on `serving`, not `snap` — right after reaching `SYNCED` a cold pool can be full of peers that are themselves still syncing (#465), which keeps `snap` positive for hours while every read fails. |
| **CL cache** | Peers remembered in the on-disk CL peer cache, parsed live from the cache file (cross-engine — both engines read/write the same file). Format `total · ✓proven ✕nolc ?untried`: `✓` = proven light-client servers (served a catch-up range or bootstrap, or Identify-confirmed), `✕` = confirmed *not* a light-client server (skipped when dialing for updates), `?` = untried. Predicts how fast the *next* cold start finds servers. |
| **EL cache** | Same idea for the on-disk EL (snap) peer cache: `total · ✓snapOk ✕snapBad ?untried` — confirmed snap-serving, confirmed snap-denied, or untried. |
| **Hdr asks** | Inbound demand from other peers for headers we serve: `N · served M` — how many `GetBlockHeaders` requests arrived and how many got a non-empty reply. |
| **Blk asks** | Same for `GetBlockBodies` requests. Served count is always 0 by design — this is a light client that holds no bodies, so it replies with a prompt empty response rather than not answering. |
| **Reads** / **Cacheable** / **Stale ≤60s ok** | The read-fetch shadow-cache counters — appear only once at least one verified state fetch has been observed. Fully documented in `docs/read-stats.md`; short version: **Reads** is the raw count of verified account/storage/code fetches since start; **Cacheable** is the share of each kind a *sound* cache keying (storage-root for slots, per-block for accounts, content-addressing for code) would have served for free, with the time it would have saved; **Stale ≤60s ok** is the *ceiling* for an unsound "just serve a value up to a minute old" strategy — how often that would have happened to be correct, with no proof backing it. |
| **Discovered** | EL peers currently in the discv4 (Kademlia) routing table — a live table size, not a running total: it shrinks as buckets evict, and it's 0 while the stack sleeps. discv5 has its own row below. |
| **Discv5 peers** | Live nodes currently in the discv5 (CL-side) routing table. |
| **In backoff** | Peers currently in dial backoff (a recent connection attempt failed; won't be redialed until the backoff expires). |
| **Blacklisted** | Peers blacklisted as wrong-chain (network-id/genesis mismatch, or an undecodable `Status` from a foreign-chain client) — not re-dialed until the stack restarts. Same-chain misbehavior gets backoff/strikes instead, never a blacklist entry. On the Rust engine a sleep/wake also clears this set (resume builds a fresh pool); the Java engine keeps it across a pause. |
| **RPC** | The local JSON-RPC listener for this network. Hidden entirely when the host doesn't report a port (`rpcPort == 0`). Otherwise `127.0.0.1:<port>` if serving, or `port <port> unavailable` (shown in the error color) if the bind failed — typically another process already holds that port. |
| **Sync period** | Sync-committee period progress: `current / target`. While parked in `STALE_ANCHOR`, `current` is the *refused* anchor's period and `target` is the period the wall clock is in — their difference is the anchor's age in periods, shown in the stale-anchor banner/dialog. |
| **Head age** | `Long.MAX_VALUE` displays as `—` ("no verified head yet — no state read can be served"); otherwise the freshness in ms of the head context verified reads are currently served against. Meaning differs by engine (rebuild-timer on Java, block-advance timer on Rust) — full explanation in `docs/readiness-and-verified-head-age.md` §What "verified head age" means. The UI's own amber/green threshold is 45 s. |
| **Uptime** | Seconds since this network's stack started running. |
| **Sleep** | Idle-sleep (pseudo-sleep) summary: `always on` if the host has no idle controller at all (e.g. desktop); `never slept` if it supports sleep but hasn't paused yet; otherwise `<duration> over N pause(s)` — cumulative time spent idle-paused and how many times. |
| **Last woke** | Only shown once there has been at least one demand wake. `<time> (<reason>) · slept <time>` — when the node last woke on a real request (foreground/app-open wakes are excluded so this keeps showing the last *meaningful* wake) and why; `slept` is the most recent time it went to sleep, which can be *after* that wake (e.g. it's asleep again now) — it does not necessarily describe the pause right before the shown wake. |

## Actions below the rows

- **Start `<network>` / Stop** — runtime-only start/stop, decoupled from the
  network's enabled switch in Settings: Stop never flips that switch off. The
  one exception is Start on a chain that isn't enabled at all (e.g. a fresh
  install) — that goes through `enableNetwork`, which *does* flip it on, so a
  cold host ends up with an enabled set to boot from. Start is also disabled
  while offline (discovery has nothing to reach).
- **Clear peer caches** — wipes the on-disk peer caches through the engine
  (so a live stack can't write the old peers back) — gives discovery a fresh
  slate. Only enabled while the network is stopped, making an accidental
  click on a running node unlikely — the gate follows a 2 s snapshot poll, so
  it's a guard rail, not a hard lock (and briefly stale on Android just after
  a foreground rebind).
- **Reset sync state** — deletes the persisted sync-committee snapshot so the
  next start re-bootstraps from the embedded checkpoint alone (the persisted
  snapshot is usually the *freshest* anchor the node has). Also gated to
  "stopped only"; unlike the cache clear this only ever takes effect at the
  *next* start (stop → reset → start is the sequence — reliably so on
  desktop; Android's reset is still an unlocked, best-effort delete of just
  the main snapshot file). **Consequence to know before pressing it:** if this
  app build is older than the network's weak-subjectivity bound (roughly two
  days on gnosis, two weeks on mainnet — see CLAUDE.md §Releases), the next
  start parks in `STALE_ANCHOR` and shows the stale-anchor consent dialog
  above. Updating the app first (a fresh checkpoint ships with it) avoids that.

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
