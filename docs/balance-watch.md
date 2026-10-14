# Balance watch (the Watch tab)

The user lists addresses per network on the **Watch** tab. The app checks their
balances now and then: the chain's native currency (ETH, xDAI), and every ERC-20 token
the network lists in **Settings → Tokens** (the built-in tokens and the user's own, #639).
When a balance has changed, the app posts a notification and adds the change to the tab's
list. A short scan of the blocks in between names the transaction, or the token `Transfer`,
behind the change when it finds one.

## Where it runs

| host | Watch tab | checks on its own | notification |
|---|---|---|---|
| Android | yes | foreground; around sleep and wake on the charger (below) | yes, one per address and asset (a later change replaces it); a tap opens the Watch tab |
| desktop | yes | every 5 min while the app runs and the network is synced | yes, one per check: Notification Center on a packaged macOS app, the tray elsewhere; none on a desktop with neither (the tab then says so) |
| iOS | no | — | — |

The tab is shown only where the host persists the list **and** checks it
(`Settings.supportsBalanceWatch`). A list the host never checks would be
accepted and then ignored. iOS is a follow-up: its foreground-only lifetime fits the
desktop schedule, but the C-ABI reader and the notification permission still have to
be written.

### When Android checks (`WatchPolicy`)

- **App in the foreground:** every 5 minutes. Opening the app asks for a fresh check: the first one after a foreground needs only a minute since the last check. A stack that the idle controller paused is not checked, but bringing the app forward wakes it.
- **Plugged in on an unmetered network** (Wi-Fi, Ethernet; not mobile data, not a metered hotspot):
  - **before sleeping:** once, right before the idle controller pauses a stack;
  - **on waking up:** once, when a catch-up pass (the hourly charging job, the daily job) has woken a stack and brought it to the head.

  This rule does not depend on the "Stay awake while charging" setting. That setting decides whether the node sleeps, not whether a sleep is preceded by a check.
- **Kept awake on the charger** (the stay-awake rule holds, so the node never sleeps and the two moments above never come): every 10 minutes.

A check counts as engine activity. That is why no check is scheduled in the background
outside the stay-awake rule: on battery, or with the setting off, it would keep awake a
node the user lets sleep. In the foreground the 5-minute check does tend to keep the
node awake while the app is visible.

The idle controller never pauses a stack while a check of it is queued or running. A
before-sleep check that finds another check running skips that pause. A before-sleep
check that sees the user come back meanwhile (a foreground or a query moves the UI
clock) cancels that pause. A wallet request does not cancel it, because it looks the same
as the check's own reads. That request simply wakes the stack again.

Every check is bounded:

- 3 minutes for a scheduled or before-sleep check;
- for an after-wake check, at most a minute of what is left of the stack's catch-up slice, ending 2 minutes before the pass's deadline (one read's own bound), so a read in flight cannot carry the pass past it.

Past the bound, balances not read yet keep their stored state, and a cause search stops
where it is. Each check reads the least recently attempted addresses first (by their least
recently attempted balance), and an address's tokens in the same order. What one check left
out leads the next, and a balance whose read keeps failing goes to the back after each
attempt.

Check now runs in the host's own scope, off the main thread, with the same 3-minute bound.
Leaving the tab mid-check ends the tab's wait, not the check, so the check's results are
still stored.

### Notification permission

On Android 13+, the auto-started service never asks for `POST_NOTIFICATIONS`.
Watching an address is the moment the app asks, because the notification is what the
user just asked for. With notifications off, the tab says that changes show only there.

## Trust

Only a **verified** read moves the stored balance. That is the Query tab's green badge:
the account proof verifies against a beacon-attested state root
(`beaconChainVerified && peerProofValid && failReason == null`). An unverified answer
is stored as the address's current error and changes nothing. So a lying peer can
neither invent a change nor hide one from the next verified read.

A verified read that is anchored at an **older** block than the stored one is ignored.
The engine's finalized fallback can serve state a few epochs behind the head, and
comparing against it would announce a change and then its reversal.

The first verified read of a balance is its baseline. A later one that differs is a change.

A token balance is a verified `eth_call` to the token's `balanceOf`, run by the engine's
local EVM against the verified head's state — the Query tab's read (#639). An empty reply
is an error, never a zero balance: an address without contract code answers any call with
nothing.

A change at the optimistic head can, in principle, be reorged away. The watch does not
wait for finality.

## Finding the transaction

The engines serve state only at the anchored head, and they refuse older block numbers.
So a change cannot be bisected through historical balances. Instead, the check scans the
blocks between the two observations **newest first**, at most 64 blocks on an unmetered
network and 16 on a metered one. A mainnet block with its transactions is ~100–200 KB.
Each block is `eth_getBlockByNumber(n, true)`, verified like any block read: the header
window up to the anchor, plus the body against `transactionsRoot`.

In each block, the scan attributes these to the address:

- a transaction **from** it (sent; its value excludes the fee) or **to** it (received);
- one from it **to itself** (only the fee moves);
- the block's **fee recipient** credit (priority fees; `miner`, a header field).

Validator **withdrawals** are not attributed. Neither engine's block JSON carries the
`withdrawals` list, only `withdrawalsRoot`. An engine that adds the list must verify it
against that root before the scan may read it.

A block the scan cannot read verified stops the scan: what it found is kept. A block it
could not see is never read as "nothing found".

The result is one of these:

- **complete:** every block in between was scanned;
- **partial:** only the newest blocks were scanned, because the gap was wider than the window or the time budget ran out;
- **unavailable:** a block had no verified answer;
- **none:** no scan was attempted.

When a complete scan finds nothing, the balance moved without a transaction of the
address's own. The texts name what can do that:

- a contract (an internal transfer, such as a WETH unwrap, a DEX payout, or a multisig execution);
- a validator withdrawal;
- a bridge credit, such as Gnosis minting bridged xDAI.

Telling these apart would need traces, which no engine serves, or the verified
withdrawals list.

With a foreground check every 5 minutes, the gap is ~25 blocks on mainnet and ~60 on
Gnosis, so the scan usually covers it. An hourly background gap (~300 / ~720 blocks)
usually does not. Then the notification reports the balance change and the block range,
as asked.

## Tokens

Each check reads, for every watched address, its balance of every token the network lists
(`listedTokens`: `PopularTokens` and the user's `CustomTokens`). A custom entry for a
contract that a later release pinned as built-in reads once, as built-in. That is one
`eth_call` per token per address per check, four in flight per address, under the check's
time bound.

**The anchor.** The engine API's `CallResult` does not say which block an `eth_call` ran
against. The Rust engine's call JSON has the number, but the API drops it. Both engines
also run a pinned block number against head state, so pinning the call cannot fix that.

So a token observation is anchored to the block of the same address's verified account read
in the same check, seconds earlier. On the Rust engine both reads run against the verified
head. Tokens are read only after that account read verified, and never on an anchor older
than the stored one, so the native rule against stepping back holds for them as well.

The residual case is the Java engine: its `eth_call` can fall back to finalized state while
its account read did not. In that case a transfer in the last few minutes can show as a
change and then its reversal. Closing it takes the anchor block on `CallResult` (follow-up).

**The cause.** A token change is searched in the token's `Transfer` logs. The search reads
each block's receipts (`eth_getBlockReceipts`, verified against `receiptsRoot`), newest
first, in a quarter of the native window: 16 blocks on an unmetered network, 4 on a metered
one. Receipts weigh more than block bodies.

A log counts when it comes from this token's contract and has `Transfer`'s topic and exactly
three topics. An ERC-721 `Transfer` indexes the id as a fourth and moves no balance. Such a
log names a transfer **from** the address (sent), **to** it (received) or both, with the
amount and the transaction hash.

When a complete search finds no `Transfer`, the contract changed the balance itself. A
rebasing token does that daily (stETH), and so does one that takes a fee or adjusts balances
directly. The texts say so.

## Storage

- **List:** `Settings.watchListJson(network)`, `[{"address":"0x…","label":"…"}]`. Addresses are stored lowercase; a mixed-case one must pass its EIP-55 checksum first (#639's Keccak-256), which catches most typos. Labels are cleaned of control characters and cut to 32 characters. At most 20 addresses per network, because each check reads every one's proof and its token balances.
- **State:** `Settings.watchStateJson(network)`. It holds the last verified balance, block and time per (address, asset) — the native balance under the address, a token's under `address/erc20:<contract>` — with the nonce for the native one, the last error, the last check and attempt times, and up to 50 changes, newest first. A change names its asset, symbol and decimals. It is written only by the host's one `BalanceWatcher`. The watcher's per-network guard keeps two triggers, such as Check now and a scheduled check, from checking a network at once. The second trigger returns nothing rather than read every proof twice.
  - Android keeps both in the app's preferences, under `watch.list.<net>` and `watch.state.<net>`.
  - The desktop keeps the list in `settings.properties` (`watch.list.<net>`, normalized on load). The state goes in `watch-state-<net>.json` beside it, because it is rewritten on every check.
- Removing an address, or a token in Settings → Tokens, drops its stored state: at once (`BalanceWatcher.prune`, through `onWatchListChanged`), or at the end of a check already running. Without this, removing the last address would leave its old balance as the baseline of a later re-add. Its past changes stay in the list.

## Code

- `ui/…/BalanceWatch.kt`: the models, the store formats, the comparison, the cause searches (block bodies for the native currency, receipts for tokens), the decimal arithmetic (commonMain has no BigInteger), the texts, and `BalanceWatcher`.
- `ui/…/Tokens.kt` (#639): the token list (`listedTokens`), the `balanceOf` read (`readTokenRaw`, shared with the Query tab), EIP-55.
- `ui/…/WatchScreens.kt`: the Watch tab.
- Seams: `Settings.supportsBalanceWatch`/`watchListJson`/`watchStateJson`, and `NodeController.checkWatched`/`watchSchedule`/`onWatchListChanged`/`watchNotificationsNote`. `NodeScreen(watchRequests = …)` brings the tab forward.
- Android: `WatchPolicy` (when), `BalanceWatchRunner` (the watcher, the reader over `ChainHandle` — account, blocks, `eth_call`, receipts — and the notifications), and the hooks in `NodeService` (the idle tick, the pause thread, the catch-up pass).
- Desktop: `DesktopNodeController.scheduledWatchChecks`/`checkWatched`, `watchBalances` in `DesktopAlerts.kt`, and the persistence in `DesktopSettings`.
- Tests: `BalanceWatchTest`, `WatchTabTest`, `WatchPolicyTest`, `DesktopSettingsPersistenceTest`.

## Limits and follow-ups

- **The `eth_call` anchor block.** `CallResult` carries no block number (above). Adding it to the engine API — the Rust engine already reports it in its call JSON — would anchor each token observation to its own block and close the Java engine's finalized-fallback case.
- **A ranged block read.** Each block read of a cause search fetches its own header window up to the anchor, ~11% on top of the bodies, and only after a detected change.
- **iOS.** No Watch tab yet (above).
- **Cost.** Every check reads every listed token of every address: 14 built-in tokens on mainnet, so 15 reads per address. The time bound and the least-recently-attempted order keep a long list from starving anything. A watched address that holds none of the tokens still pays for reading them, because an incoming transfer to a zero balance is exactly what the watch is for.
