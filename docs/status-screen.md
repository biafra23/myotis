# The Status screen — every item explained

This documents everything shown for a network on the shared Compose UI (Android +
desktop; iOS shares the same `NodeScreen.kt` composables) once a chain is
selected: the readiness strip above the tabs, the status card and vitals the
**Status** tab opens with, and every row the tab shows in Expert mode. Source:
`ui/src/commonMain/kotlin/io/myotis/ui/NodeScreen.kt` (`NodeScreen`,
`ReadinessStrip`, `StatusTab`, `StatusView`), `ui/.../HomeStatus.kt` (the card
and the tiles) and `ui/.../Readiness.kt` (the ladder and the tile rules they all
draw), fed by the top-level `NodeSnapshot` data class (`ui/.../NodeController.kt`).

**Normal and Expert mode.** Out of the box the app shows the three screens a
wallet user needs — Status, Query, Settings — and the Status tab is the card and
the four tiles below. Settings → *Expert mode* adds the Logs and Index tabs, the
node-tuning settings, and on this tab everything from "Banners" on: the sync
bar, every row, the maintenance actions and the READY peers list. The card stays
at the top in both modes.

Every value here reflects the *selected* network — the chips above the strip
switch which chain's snapshot is shown — with one exception: the stale-anchor
dialog (below) can pop up for *any* parked network, selected or not.

Host coverage isn't uniform: iOS never fills the READY peers list or the
Sleep/Last woke fields (idle-sleep metrics aren't wired there yet), and the
Tor row is desktop-only (see that row below).

The app shows a condensed version of this explanation in place: the card has an
"ⓘ" ("Readiness") in both modes; in Expert mode rows marked "ⓘ" open it in a
dialog on a single tap anywhere on the row, and each of the three actions —
Start / Stop (one "ⓘ" for the pair), Clear peer caches, Reset sync state — has
an "ⓘ" beside it (the buttons' own tap stays the action). The dialog is titled
with the row or action's name and stays open until dismissed (Close, tap
outside, or back). The text lives in the `StatusHelp` object in `NodeScreen.kt`.
**The two are meant to stay in sync**: a behavior change that changes what a
row, tile or action means must update both `StatusHelp` and this doc.

## Status card (both modes)

The first thing on the Status tab: a colored dot, a headline, one line of
detail, a progress bar while something measurable is in progress, and the
action the state calls for. It paints the same ladder as the strip
(`readinessOf` in `Readiness.kt`), worst rung first:

| Headline | When | Detail / action |
|---|---|---|
| **Sleeping** (grey) | idle-paused (`lifecycle == PAUSED`) | networking is off to save battery; a wallet request wakes it. Names a reported network upgrade if peers announced one. Outranks "No internet connection": nothing is failing while asleep. |
| **No internet connection** (red) | the host reports no connectivity | *Open network settings* button; Start is refused meanwhile. |
| **Not running** (red) | no stack registered | *Start `<network>`* button. |
| **Update required** (red) | an ACTIVE upgrade advisory the node's own state corroborates (not SYNCED, or stale head) | update the app. |
| **Needs your decision** (red) | parked in `STALE_ANCHOR` | how many periods old the anchor is (and the bound, where the host reports it); a *Review* button re-opens the consent dialog after it was dismissed. |
| **Syncing** (red) | beacon not `SYNCED` | the sync bar's wording: "Starting the light client…" (Android's `STARTING`-as-`STOPPED`), "Bootstrapping the light client…", "Catching up sync committees — period *c* of *t*." with a determinate bar, or "Finishing sync…"; "Looking for light-client servers…" while hunting. |
| **Almost ready** (amber) | `SYNCED` but no verified head, or one older than 45 s | waiting for the first / a fresh verified head; "Looking for snap peers…" while hunting. |
| **Ready — log index catching up** / **too far behind** (amber) | ready, but an enabled log index trails the head past the serving slack | the catch-up line and, unless stalled, its bar — `eth_getLogs` near the head is refused until it has caught up. |
| **Ready** (green, bright green when the pool is deep) | verified reads are served | the verified head's age, and whether the peer pool is deep enough for heavy wallet screens (the deep-pool threshold in Settings). |

Below the headline sit *Stop* (while the stack is up) or *Start `<network>`*
(while it is down) — see "Actions" below for their exact semantics — plus the
rung's own button where it has one.

## Vitals (normal mode)

Four tiles under the card, each a label, a value with a tone dot (red = bad,
amber = wait, green = ok, bright green = great; a tile that does not apply
shows `—` and no dot) and one line of detail. All come from `vitalsOf` in
`Readiness.kt`:

| Tile | Value | Detail | Tone |
|---|---|---|---|
| **Execution peers** | `N usable` — `snapServingPeers`, the peers that can answer a read right now | `of M connected` (`readyPeers`); "· looking for more" while hunting | red at 0, green below the deep-pool threshold, bright green at or above it |
| **Consensus** | `Synced` / `Catching up` / `Starting` / `Paused` (`STALE_ANCHOR`) | `N servers answering` — distinct light-client servers in the last minute; "· looking for more" while hunting | green when `SYNCED`, red when parked, amber otherwise |
| **Verified head** | the verified head's age (`4 s`, `2 min`), `None yet`, or `—` | `fresh` (≤ 45 s), `stale — waiting for a fresh head`, `waiting for a peer that can answer`, `waiting for sync`, or `paused — needs your decision` | green when fresh, amber when stale or missing on a synced node, no dot while not synced |
| **Log index** (only when the engine reports an enabled index) | `Up to date` (within the serving slack), `Behind head`, `Too far behind` (past the bridge limit), `Starting` (no block covered yet), `Nothing watched` | the head gap, then the history: `history complete`, `history paused · N blocks unindexed`, or `history incomplete · <ETA or blocks left>` | follows the HEAD side only — an incomplete or paused history is said in the detail and never changes the tone, because it does not affect what the node can answer at the head |

While the stack is down every tile reads `—`; while it sleeps, `—` with
"sleeping". The index tile also disappears whenever the status probe answers an
error envelope (a paused or still-starting handle).

## Readiness strip

A thin colored bar under the header (above the tab row on desktop; a phone's
tabs sit in a bar at the bottom) — the wallet's "safe to transact" signal for
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
| amber (thick, a progress bar) | ready, but the log index trails the head past the serving slack — head-reaching `eth_getLogs` is refused until it has caught up; a gap past the bridge limit is a flat amber bar (nothing is closing it) |
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

## Banners (under the card, inside the Status tab)

- **Offline** — the card's "No internet connection" rung with its *Open
  network settings* button, in both modes (the former offline banner).
- **Network upgrade banner** (both modes) — peers announce (`SCHEDULED`) or report already
  active (`ACTIVE`) a fork this build doesn't support. It is advisory only
  (unverified peer data) and never itself claims the node stopped verifying;
  it turns into an alarm ("Update required") only once the node's *own*
  verified state agrees — unsynced, or verified head gone stale. Shows the
  activation time, how many distinct peer networks reported it, and the fork
  id.
- **Hunt banner** (Expert mode; the card's detail says the same in both) ("Hunting for light-client servers and/or snap peers…") —
  the light client and/or the EL pool are starved of usable servers and
  running boosted discovery/probing to find more. Tracks `lcHunting` /
  `elHunting`.

## Sync progress bar (Expert mode)

Shown while the beacon side is not yet `SYNCED` (hidden once it is, or if the
network is stopped). The card carries the same progress in both modes:

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

## Status rows (Expert mode)

In on-screen order. "Row" is the literal left-hand text label.

| Row | Meaning |
|---|---|
| **Network** | The chain name (mainnet / sepolia / gnosis / …). |
| **State** | Stack lifecycle: `Sleeping (wakes on request)` (idle-paused — networking off, RPC still listening), `Running`, or `Stopped`. |
| **Beacon** | The beacon light client's sync state: `STARTING` (shown as `STOPPED` on Android, where the sync bar is then hidden too — see below), `SYNCING`, `CATCHING_UP`, `SYNCED`, or `STALE_ANCHOR`. Full definitions in `docs/readiness-and-verified-head-age.md` §Beacon sync states. This is the trust-anchor side of readiness — a node can be here `SYNCED` yet still not `readyForReads` (see Head age below). |
| **EL block** | The execution-layer block number of the latest beacon-*finalized* payload (`StatusSnapshot.executionBlockNumber`) — not the optimistic head that `eth_blockNumber` reports. On a healthy node it trails the chain head by about two epochs (~64–96 blocks on mainnet). |
| **Log index** | Only shown when the log index feature applies. A short progress string, e.g. `12,041 logs · 5,594,611–8,461,900`, or `backfilling`. See `docs/eth-getlogs-design.md` / `docs/logindex-verified-bundle-design.md`; the Index tab has the full detail view for this feature. |
| **Tor** | Desktop only, and only when applicable (Rust engine + a `-PtorEngine` build; see `docs/privacy-and-tor.md`) — Android and iOS never populate this row. `off` = supported but disabled; `on — circuit bootstrapping…` = enabled, circuit not ready yet; `routing reads (circuit ready)` = enabled and a Tor circuit is ready (highlighted in the theme's primary color). **Scope: only account (balance/nonce) reads route over Tor today** — token/storage reads, `eth_call`/gas estimation, tx broadcast, the CL fetch, and discovery still leave from your real IP; full coverage is a follow-up. |
| **EL · N peers · M cache** | *Group header, not a row:* the execution-layer (devp2p) peer rows follow it. `N` = ready peers in the snap pool (the first number of the Peers row below), `M` = the on-disk EL peer-cache total (the first number of the Cache row below). |
| **Peers** (EL) | Execution-layer pool: `N` ready peers total, of which `snap M` negotiated the snap capability (snap/1 or snap/2), and `serving K` are in the pool actually able to answer a read right now (near the current head, not benched after a failed read). A number in parentheses after it — `serving 8 (3)` — is how many of those serving peers are connected over snap/2; no parentheses means all of them are on snap/1. Reads work the same on both versions. Reads gate on `serving`, not `snap` — right after reaching `SYNCED` a cold pool can be full of peers that are themselves still syncing (#465), which keeps `snap` positive for hours while every read fails. The help dialog is titled "EL peers". |
| **Cache** (EL) | Peers remembered in the on-disk EL (snap) peer cache, parsed live from the cache file (cross-engine — both engines read/write the same file): `total · ✓snapOk ✕snapBad ?untried` — confirmed snap-serving, confirmed snap-denied, or untried. Predicts how fast the *next* cold start finds servers. Help dialog title "EL cache". |
| **Hdr asks** | Inbound demand from other peers for headers we serve: `N · served M` — how many `GetBlockHeaders` requests arrived and how many got a non-empty reply. |
| **Blk asks** | Same for `GetBlockBodies` requests. Served count is always 0 by design — this is a light client that holds no bodies, so it replies with a prompt empty response rather than not answering. |
| **Discovered** | EL peers currently in the discv4 (Kademlia) routing table — a live table size, not a running total: it shrinks as buckets evict, and it's 0 while the stack sleeps. discv5 has its own row in the CL group. |
| **In backoff** | EL peers currently in dial backoff (a recent connection attempt failed; won't be redialed until the backoff expires). |
| **Blacklisted** | EL peers blacklisted as wrong-chain (network-id/genesis mismatch, or an undecodable `Status` from a foreign-chain client) — not re-dialed until the stack restarts. Same-chain misbehavior gets backoff/strikes instead, never a blacklist entry. On the Rust engine a sleep/wake also clears this set (resume builds a fresh pool); the Java engine keeps it across a pause. |
| **CL · served N/min · M cache** | *Group header:* the consensus-layer (libp2p) rows follow it. `served N/min` = distinct light-client servers that answered in the last 60 s (the same number the Peers row below starts with — a connection count would read 0 almost always, since CL connections are short-lived), `M` = the on-disk CL peer-cache total. |
| **Peers** (CL) | Consensus-layer (libp2p) peer activity: `served N/min` = distinct peers that answered a light-client request in the last 60 s; `con N` = currently-connected libp2p peers (usually near 0 — CL connections are short-lived, made just long enough to fetch a bootstrap/update and dropped). Help dialog title "CL peers". |
| **Cache** (CL) | Peers remembered in the on-disk CL peer cache, parsed live from the cache file. Format `total · ✓proven ✕nolc ?untried`: `✓` = proven light-client servers (served a catch-up range or bootstrap, or Identify-confirmed), `✕` = confirmed *not* a light-client server (skipped when dialing for updates), `?` = untried. Help dialog title "CL cache". |
| **Discv5 peers** | Live nodes currently in the discv5 (CL-side) routing table. |
| **Reads** / **Cacheable** / **Stale ≤60s ok** | After both peer groups (they are about *our* reads, not a peer group). The read-fetch shadow-cache counters — appear only once at least one verified state fetch has been observed. Fully documented in `docs/read-stats.md`; short version: **Reads** is the raw count of verified account/storage/code fetches since start; **Cacheable** is the share of each kind a *sound* cache keying (storage-root for slots, per-block for accounts, content-addressing for code) would have served for free, with the time it would have saved; **Stale ≤60s ok** is the *ceiling* for an unsound "just serve a value up to a minute old" strategy — how often that would have happened to be correct, with no proof backing it. |
| **RPC** | The local JSON-RPC listener for this network. Hidden entirely when the host doesn't report a port (`rpcPort == 0`). Otherwise `127.0.0.1:<port>` if serving, or `port <port> unavailable` (shown in the error color) if the bind failed — typically another process already holds that port. |
| **Sync period** | Sync-committee period progress: `current / target`. While parked in `STALE_ANCHOR`, `current` is the *refused* anchor's period and `target` is the period the wall clock is in — their difference is the anchor's age in periods, shown in the stale-anchor banner/dialog. |
| **Head age** | `Long.MAX_VALUE` displays as `—` ("no verified head yet — no state read can be served"); otherwise the freshness in ms of the head context verified reads are currently served against. Meaning differs by engine (rebuild-timer on Java, block-advance timer on Rust) — full explanation in `docs/readiness-and-verified-head-age.md` §What "verified head age" means. The UI's own amber/green threshold is 45 s. |
| **Uptime** | Seconds since this network's stack started running. |
| **Sleep** | Idle-sleep (pseudo-sleep) summary: `always on` if the host has no idle controller at all (e.g. desktop); `never slept` if it supports sleep but hasn't paused yet; otherwise `<duration> over N pause(s)` — cumulative time spent idle-paused and how many times. |
| **Last woke** | Only shown once there has been at least one demand wake. `<time> (<reason>) · slept <time>` — when the node last woke on a real request (foreground/app-open wakes are excluded so this keeps showing the last *meaningful* wake) and why; `slept` is the most recent time it went to sleep, which can be *after* that wake (e.g. it's asleep again now) — it does not necessarily describe the pause right before the shown wake. |

## Actions

- **Start `<network>` / Stop** (on the card, both modes; one of the two shows,
  depending on whether the stack is up) — runtime-only start/stop, decoupled from the
  network's enabled switch in Settings: Stop never flips that switch off. The
  one exception is Start on a chain that isn't enabled at all (e.g. a fresh
  install) — that goes through `enableNetwork`, which *does* flip it on, so a
  cold host ends up with an enabled set to boot from. Start is also disabled
  while offline (discovery has nothing to reach).
- **Clear peer caches** (Expert mode, below the rows) — wipes the on-disk peer caches through the engine
  (so a live stack can't write the old peers back) — gives discovery a fresh
  slate. Only enabled while the network is stopped, making an accidental
  click on a running node unlikely — the gate follows a 2 s snapshot poll, so
  it's a guard rail, not a hard lock (and briefly stale on Android just after
  a foreground rebind).
- **Reset sync state** (Expert mode, below the rows) — deletes the persisted sync-committee snapshot so the
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

## READY peers list (Expert mode)

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
