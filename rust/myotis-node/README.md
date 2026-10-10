# myotis-node

Node.js binding over the myotis-engine **C ABI** (`capi.rs` /
`rust/include/myotis_engine.h`) via [napi-rs](https://napi.rs) — the seam for
Electron/desktop hosts that want to run Myotis invisibly in-process, the way
they run other embedded nodes.

This is the third consumer of the same engine, next to the UniFFI surface
(JVM hosts, `ffi.rs`) and the Kotlin/Native cinterop over this same C ABI
(iOS): identical JSON shapes (pinned
by the cross-engine golden tests), identical in-band error sentinels (negative
handle ids, `false`, `{"error": ...}` objects — no JS exceptions for
engine-level failures).

## Build

```bash
cargo build -p myotis-node --release
cp ../target/release/libmyotis_node.so myotis-node.node   # .dylib on macOS, .dll on Windows
```

## Use

```js
const myotis = require('./myotis-node.node');

myotis.init();   // ABI handshake — returns the engine ABI version; gate on
                 // the value pinned in the notes of the release you built or
                 // downloaded against
const h = myotis.create('mainnet', '/path/to/data-dir');  // dir is created if missing
myotis.start(h);

// Optional (ABI >= 31): seed the EL pool with execution nodes the host knows to
// be serving — a changed list is dialed at once, and again while the pool is
// below its target or no pooled peer can answer at the anchored head. Applied
// or refused AS A WHOLE (see Notes); before or after start(), kept across
// pause/resume:
// myotis.setBootEnodes(h, JSON.stringify(['enode://<128-hex pubkey>@1.2.3.4:30303']));

// Recovery from STALE_ANCHOR with a checkpoint the HOST authenticated (ABI >= 26):
// bootstraps a fresh dir from that root/slot instead of the embedded checkpoint.
// const h = myotis.createWithCheckpoint('mainnet', '/path/to/fresh-dir',
//   '0x<32-byte beacon block root>', 15208352 /* that block header's slot */);

// Lifecycle and status are synchronous (stop/pause can wait for native work):
JSON.parse(myotis.statusJson(h));   // { beaconState, peerCount, snapPeers, snapServingPeers, ... }

// Verified reads run on bounded Myotis workers, with a 90 s operation budget
// including queue wait. Cancellation drains native work before completion:
const acct = JSON.parse(await myotis.requestAccountJson(h, '0xd8dA…6045'));
// acct.blockTimestamp (ABI >= 41): blockNumber's own timestamp, unix seconds,
// when the engine proved it (the read ran against the beacon-attested block),
// else null. resolveEnsJson / ensRecordJson results carry it too.
// ...or at the beacon-finalized block (ABI >= 32; a number near the head also works):
const fin = JSON.parse(await myotis.requestAccountJson(h, '0xd8dA…6045', 'finalized'));
const ens = JSON.parse(await myotis.resolveEnsJson(h, 'vitalik.eth'));
const ch = JSON.parse(await myotis.ensRecordJson(h, JSON.stringify({
  method: 'contenthash', name: 'vitalik.eth',
})));

myotis.pause(h);   // idle-sleep: tear down networking, keep warm state
myotis.resume(h);  // warm restart
myotis.stop(h);
```

### A dApp provider's methods

Every verified read the other hosts serve is exported (#503), so a host can
route a page's `window.ethereum` requests here rather than to a proxy RPC.
Each resolves to the engine's JSON **unchanged**: the result object or array,
the literal `"null"` for a verified not-found, or an `{"error": …}` object.
`"code":-32602` marks a refusal no retry changes: answer it as JSON-RPC
invalid params. A plain `{"error"}` is retryable: answer it as -32000. An
unknown handle gets the usual
`{"error":"handle does not belong to this environment"}`.

| JSON-RPC method | call |
|---|---|
| `eth_blockNumber` | no call: `statusJson().optimisticBlockNumber`, the verified head (`0` = none yet: do not serve it) |
| `eth_getBalance`, `eth_getTransactionCount` | `requestAccountJson(h, address, block?)` |
| `eth_getTransactionCount` at `pending` | the mined nonce above through `pendingNonceOverlay(h, address, minedNonce)` — synchronous; raises it past this node's own unmined broadcast, -1 = serve the mined nonce |
| `eth_getCode` | `getCodeJson(h, address, block?)` |
| `eth_getStorageAt` | `getStorageAtJson(h, address, position, block?)` |
| `eth_call` | `ethCallJson(h, from, to, data, value, block)`, `ethCallTxJson(h, txJson, block, overrides)` |
| `eth_call` with a state override | `ethCallOverridesJson(h, from, to, data, value, block, overridesJson)`, or `ethCallTxJson` |
| `eth_estimateGas` | `estimateGasJson(h, from, to, data, value)`, `estimateGasTxJson(h, txJson, block, overrides)` |
| `eth_createAccessList` | `createAccessListJson(h, txJson, block, overrides)`: serve `{accessList, gasUsed: '0x…'}` from `status: "ok"`, and its `vmError` as geth's `error` next to them when present |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas` | `feeEstimateJson(h)` |
| `eth_feeHistory` | `feeHistoryJson(h, blockCount, newestBlock, percentilesJson?)` |
| `eth_getBlockByNumber` | `getBlockByNumberJson(h, blockTag, fullTransactions?)` |
| `eth_getBlockByHash` | `getBlockByHashJson(h, blockHash, fullTransactions?)` |
| `eth_getTransactionByHash` | `getTransactionByHashJson(h, txHash)` |
| `eth_getTransactionReceipt` | `getTransactionReceiptJson(h, txHash)` |
| `eth_getBlockReceipts` | `getBlockReceiptsJson(h, selector)` (a tag, a 0x-number or a 0x-hash) |
| `eth_getLogs` | `getLogsJson(h, filterJson)`: only for contracts in the log index, below |
| `eth_sendRawTransaction` | `sendRawTransactionJson(h, rawTxHex)` |

**Serve a state read only with its verdict.** `requestAccountJson`,
`getCodeJson` and `getStorageAtJson` answer with a full object even when
nothing could be verified: `verifyMethod` is then `null` and `failReason`
says why. Their data keys are an answer **only when `verifyMethod` is set**;
otherwise there is no answer yet (retryable, as a plain `{"error"}`). With a
verdict:

- `eth_getBalance`: `balanceWei` is a **decimal** string; serve it as a
  quantity (`'0x' + BigInt(balanceWei).toString(16)`). An account proven
  absent (`exists: false`) has `balanceWei: null`: serve `0x0`.
- `eth_getTransactionCount`: `nonce`, `-1` for an account proven absent:
  serve `0x0`.
- `eth_getCode`: `codeHex` (`0x` for an account without code).
- `eth_getStorageAt`: `valueHex` is the value without leading zeros (`null`
  for an empty slot): left-pad it to the 32-byte word a JSON-RPC answer
  carries.

**Arguments.** The addon makes the checks the JSON-RPC routers make on the
other hosts before they call the engine, and refuses what fails them as
`-32602`, before the handle is consulted: a NUL byte in a string argument
(`{"error":"argument contains NUL","code":-32602}`); a malformed address,
hash, call data, `value` (decimal wei) or raw transaction; reward percentiles
that are not JSON numbers in [0, 100] in non-decreasing order (at most 100;
`''`, `null` or `[]` ask for no reward column); an empty import list; and a
`blockCount` that is not a safe integer. Each check is the engine's own parse
or a JSON-RPC router's rule, so what the addon refuses, the other hosts refuse
too. A short storage `position` such
as `0x0` is padded to its 32-byte word. The older `requestAccountJson`,
`estimateGasJson` and `sendRawTransactionJson` are checked the same way since
#503; the engine's own refusals of their arguments carry no `code`.
`ethCallJson`, `ethCallTxJson`, `ethCallOverridesJson` and `estimateGasTxJson`
get theirs from the engine. Block numbers:

- `getBlockByNumberJson` and `feeHistoryJson` take a tag or a `0x`-number.
  Bare digits are refused: the engine would read them as hex there.
  `getBlockReceiptsJson` refuses them too, up front; the engine would refuse
  them only once the handle runs.
- The state reads and the calls (`ethCallJson`, `ethCallTxJson`,
  `ethCallOverridesJson`, `estimateGasTxJson`) also take bare decimal digits,
  as `ethCallJson` always has (below).

Convert a JSON-RPC quantity to a JS number before passing `blockCount` or
`minedNonce`.

**The log index.** `eth_getLogs` is served only from an opt-in index of the
contracts a host chooses (docs/eth-getlogs-design.md), and only inside its
verified coverage — anything else is an `{"error"}` that says how far coverage
reaches, never an empty array:

```js
// Watch a contract from its deployment block (a JSON number); the index then
// catches up. `enabled` defaults to false. Optional per entry: name, topic0s;
// at the top level: maxSpeed, backfillPaused.
await myotis.setLogIndexConfig(h, JSON.stringify({
  enabled: true, watch: [{ address: '0x…', fromBlock: 14737691 }],
}));     // '{"ok":true}', or '{"ok":false}': an invalid config (the engine logs
         // why; drainLogs) or no running EL reader
// `watch` only ever ADDS: an address left out of a later push stays indexed.
// To stop indexing one, name it under `unwatch` (ABI 37) — its entry, its
// coverage and its stored logs go, the other entries keep theirs:
await myotis.setLogIndexConfig(h, JSON.stringify({
  enabled: true, watch: [], unwatch: ['0x…'],
}));     // an address the index does not watch is ignored; one listed under
         // both `watch` and `unwatch` refuses the push. '{"ok":true}' means the
         // unwatch is durable; '{"ok":false}' can also mean its checkpoint
         // could not be written (dropped in memory only — send it again)
JSON.parse(await myotis.logIndexStatusJson(h));
// { enabled, logCount, maxSpeed?, backfillPaused?, headGap?, …,
//   entries: [{ address, fromBlock, name?, coveredLow?, coveredHigh?,
//               restricted? }] }   (restricted: indexed under topic0s; ABI 37)
// (an index never configured: { enabled: false, logCount: 0, entries: [] })
```

`importLogIndexFiles(h, pathsJson)` merges snapshot files into the index, as
the desktop, Android and iOS apps do with a file **the user picked**. Treat it
as that same deliberate act, never as something fetched: a snapshot is the
claim of whoever produced it, served as covered without being re-verified,
and served logs do not say which coverage was imported
(docs/eth-getlogs-design.md §Import, docs/seeded-log-histories.md).
A later config is merged with what is there, so an imported address stays in
the index until a config names it under `unwatch`.

**The request queue.** These calls go through the same scheduler as the other
reads (§Request ownership and cancellation): at most four requests per handle
queued or running, one running at a time, and a 90 s budget that starts at
submission. So:

- A `logIndexStatusJson` poll waits behind a slow read. Poll the synchronous
  `statusJson` for liveness.
- Once it runs, an import observes neither the budget nor a cancellation. It
  holds its handle's slot until it finishes, and `stop` or `pause`,
  synchronous on the JS thread, wait for it. (Queued, it expires and is
  cancelled like any request.)
- `getLogsJson`'s result is not capped. A host serving untrusted pages bounds
  the block range itself.

These calls need no newer engine: the C functions are in the ABI this addon
targets. A host detects them by the export
(`typeof myotis.getBlockByNumberJson === 'function'`).

`smoke.mjs` is the end-to-end check: syncs mainnet from plain Node, then runs
`resolve-ens` + `contenthash` + `get-account` with verification fields and
cold/warm timing, a fee estimate, the latest block, a fee history, and the
finalized block with the receipt of its first transaction:

```bash
node smoke.mjs ./data-dir ../target/debug/myotis-node.node
```

It begins the reads only once the peer set is worth judging — `snapServingPeers >= 1`
(a pooled peer that can answer at the anchored head; #465) and `snapPeers >= 2`
(the reader rotates, so one peer means one dud peer looks like a broken
engine) and discovery has produced candidates. Exit codes distinguish the two
verdicts that used to be one: **0** all checks passed, **1** the engine
answered and a check failed (or it never became ready), **2** the environment
never produced a usable peer set. Knobs for constrained runners:
`MYOTIS_SMOKE_MIN_SNAP_PEERS`, `MYOTIS_SMOKE_REQUIRE_DISCOVERY`,
`MYOTIS_SMOKE_GATE_TIMEOUT_MIN` (how long before a PEER-STARVED gate gives up
early — engine-side shortfalls always get the full budget, because a cold
checkpoint catch-up legitimately takes 30-40 min) and `MYOTIS_SMOKE_TIMEOUT_MIN`
(the overall budget). A set-but-nonsense value for any of them is refused at
startup rather than silently ignored. The gate itself is
unit-tested in `smoke-gate.test.mjs` (`node --test smoke-gate.test.mjs`).

## Notes

- **Readiness**: serve verified reads only when `statusJson` shows
  `beaconState === 'SYNCED'`, `elReaderAvailable`, and `snapServingPeers >= 1`;
  before that, reads answer with an error or without a verdict, never with a
  guess. `snapServingPeers`
  (ABI >= 31) counts the pooled peers that can answer a read at the anchored
  head *now*; `snapPeers` counts every pooled snap peer, and right after SYNCED
  a cold pool can be full of peers still syncing themselves — `snapPeers > 0`
  for hours while every read fails with `peer returned 0 headers` (#465). On
  an addon older than ABI 31 the key is absent: fall back to `snapPeers`. A
  host that wants a read to SURVIVE one silent peer should additionally wait
  for `snapPeers >= 2` — the reader rotates over the snap set, and with a
  single peer there is nowhere to rotate to (this is what `smoke.mjs` gates
  on; see #372).
- **Seed pins** (`setBootEnodes`, ABI >= 31): the engine ships no mainnet seed
  list; a host that knows serving execution nodes can pin them per handle
  (`myotis_set_boot_enodes` in `myotis_engine.h` is the contract). The push is
  applied or refused as a whole (`false`: invalid JSON, a non-array, a
  malformed or DNS-named entry, a duplicate address, more than the header's
  cap, or an unknown handle — nothing applied), an empty array clears, and an
  identical re-push is a no-op. The engine never persists it. A changed list
  is dialed at once; from then on the pins are pins like the network's own —
  never seeded into the peer cache, re-dialed while the pool is below its
  target or, once the beacon anchor has a head, no pooled peer can answer at
  it, and above that once proven to serve. On an address the network also
  pins, the host's key wins. An unspecified IP (`0.0.0.0`, geth's own enode
  before it learns its external address) or port 0 is refused.
- **Weak-subjectivity gate**: `statusJson().beaconState` can be `STALE_ANCHOR`
  — the engine refused to walk forward from an anchor (embedded checkpoint or
  persisted snapshot) older than the network's WS bound, because from that far
  back a forged continuation is BLS-indistinguishable from the honest chain
  (a long-range attack). While parked, verified reads fail closed and
  `statusJson().wsBoundPeriods` reports the effective bound. The bound is small
  on some networks (~34 h on gnosis, vs. ~2 weeks on mainnet), so an embedding
  must decide how a parked node behaves. Two host-owned controls (neither is
  persisted by the engine): `setWsBoundPeriods(h, periods)` raises the accepted
  anchor age (`0` restores the network default), applied live; and
  `acceptStaleAnchor(h)` gives run-sticky consent to sync past the park for the
  rest of this run. Put them behind your own UI or set a policy on your users'
  behalf — the durable alternative on short-window chains is a fresher anchor
  (ship/refresh the checkpoint), not a wider gate.
- **Caller-supplied checkpoint** (`createWithCheckpoint(network, dataDir,
  checkpointRoot, checkpointSlot)`, ABI ≥ 26, #441): for a host that is parked
  in `STALE_ANCHOR` and has obtained a fresher checkpoint through its own
  channels, this bootstraps from that beacon block root instead of the embedded
  one. The trust boundary is explicit: **the engine does not authenticate the
  root** — the caller does — and it treats it exactly like the embedded
  checkpoint afterwards: the bootstrap is pinned to it, every update is
  BLS-verified against the committee chain that follows, a persisted snapshot
  stays on probation until an update verifies against it, and the
  weak-subjectivity gate judges the supplied slot's age like any anchor (a root
  that is itself past the bound still parks). Supplying a checkpoint never
  marks the node synced or unlocks verified reads early. `checkpointRoot` is
  32-byte hex (`0x` optional); `checkpointSlot` is the checkpoint block
  **header's** slot as a plain JS number (safe integer, not the epoch boundary
  it finalizes — with skipped slots they differ, and the period derived from
  it selects the committee the bootstrap is checked against). Generations: the
  first call on a directory records the anchor in `sync-anchor[-net].json`
  next to the snapshot; a later call with the **same root and slot resumes**
  that generation under the normal rules (a snapshot strictly newer than the
  checkpoint is restored and re-verified, otherwise it bootstraps again), so a
  restart never reverts to the embedded anchor and needs no extra flag. Any
  other root/slot, a directory that already holds a snapshot from the embedded
  anchor, or a plain `create()` on a marked directory returns **-3**
  (`ANCHOR_MISMATCH`) — nothing is deleted or rewritten; pick a fresh
  directory or the matching anchor. Invalid input (unknown network, malformed
  or all-zero root, slot 0 / non-integer / above `Number.MAX_SAFE_INTEGER` /
  in the future, empty dataDir) returns **-1**, and a canonical network this
  engine does not host returns **-2** (`UNSUPPORTED_NETWORK`, the same
  sentinel `create()` uses), both before the directory is created or touched; so does a directory another live
  handle of the process is already using. Directory identity is canonical:
  symlinks, `..` and relative spellings of one directory are one directory for
  the in-use guard and the marker alike, and a dangling symlink (or any
  unreadable entry) at the marker path counts as a marker, never as absence —
  both constructors refuse it and leave it untouched. Detect support with `init() >= 26`
  (or `typeof myotis.createWithCheckpoint === 'function'`). Two practical
  notes: only the sync-committee **period** derived from the slot is
  load-bearing (the bootstrap warns when the verified header's slot differs; a
  slot in a later period than the header delays persistence until the store
  passes it), and a fresh directory starts without the proven-LC-server cache
  — copying `cl-peers[-net].cache` from the old directory into the new one is
  safe (it holds peers, not trust) and shortens the cold start.
- **`ethCallJson`'s `block`** (checked by the engine since ABI 27, #452): a
  head tag (`latest`/`pending`) or `''` runs against the **verified head's**
  state. `safe` is refused as invalid params (`code: -32602`; before #366 it
  ran against the head — another block, as nothing here tracks the safe head). `finalized` (since ABI 30, #465) runs against the
  **beacon-finalized block** — older and never reorged, but a state peers may
  already have pruned, so it can fail retryably while `latest` serves (engines
  before ABI 30 ran it against the head). Every result carries `blockNumber`
  (the block the call ran against) and `verified` (`true` = an `ok`/`revert`
  that ran against the finalized block; always `false` on `unavailable`). A
  block number
  (`0x`-hex, or bare decimal digits) runs only within `[head-64, head+16]` of
  the verified head (`statusJson().optimisticBlockNumber`), and even then it
  is answered from head state, not from that block (exact-block execution is
  #382). Anything else is refused rather than answered from the head:
  - `{"error": "…", "code": -32602}` is **permanent**: a number behind the
    window, `earliest`, a block hash, a malformed selector, a malformed
    `from`/`to`/`data`/`value`, or a NUL byte in any argument. Answer it as
    JSON-RPC invalid params, and do not retry.
  - A plain `{"error": "…"}` is retryable: a number ahead of the window, or no
    verified head yet.

  Engines before ABI 27 ignore `block` and always answer from the head, so a
  host that forwards a block number must gate on `init() >= 27`.
- **Executor refusals** (ABI 33): `ethCallJson` and `estimateGasJson` (and
  `estimateGasTxJson` since ABI 34, `ethCallTxJson` since ABI 35, and
  `ethCallOverridesJson`) answer `{"error": "…", "code": -32602}` — **permanent**,
  like the refusals above — when the verified head's header and this engine
  build's fork table disagree about Amsterdam: an Amsterdam block without
  EIP-7843's slot number, or a slot number on a block the table puts before
  Amsterdam (the fork was scheduled or moved after this build shipped). It ran
  nowhere, so it carries no `blockNumber`. Before ABI 33, `estimateGasJson`
  never carried a `code`.
- **Full transaction objects** (ABI 34, #509): `estimateGasTxJson(h, tx,
  block, stateOverrides)` takes the JSON-RPC transaction object as JSON — the
  EIP-7702 `authorizationList`, `accessList`, `gas`, fee fields, `nonce` and
  `type` are all applied (`estimateGasJson` carries only from/to/data/value, so
  a type-4 estimate through it is too low). A malformed or contradictory
  object (a type-4 request without authorizations, a tip above its fee cap, a
  `chainId` for another chain, a blob transaction) is `{"error": "…", "code":
  -32602}`, permanent. `{"status": "infeasible", "reason": "…"}` means the
  transaction does not fit the caller's `gas` or funds — answer it as geth
  does, JSON-RPC -32000 with `reason` verbatim ("gas required exceeds
  allowance (N)", "insufficient funds for transfer"); `estimateGasJson` can
  return it too, for an estimate that runs out of gas at its 30 M ceiling.
- **Full transaction objects for calls** (ABI 35, #509): `ethCallTxJson(h, tx,
  block, stateOverrides)` takes the same arguments and applies every field as
  the estimate does: `gas` is the call's limit (capped at the 30 M call
  budget, as geth caps at its RPC gas cap), a fee must reach the block's base
  fee and is charged to the sender before the call runs, and both lists are
  applied (`ethCallJson` carries only from/to/data/value). Refusals are the
  same permanent `-32602`. `{"status": "infeasible", "reason": "…"}` means
  the call cannot succeed within the caller's gas, fee cap or funds — answer
  it as geth does, JSON-RPC -32000 with `reason` verbatim: "out of gas" for a
  run that exhausted the caller's `gas`, and for a check failed before the
  run geth's eth_call wording, "err: <why> (supplied gas N)" with <why> one of
  "intrinsic gas too low: have N, want M", "insufficient gas for floor data
  gas cost: …", "insufficient funds for gas * price + value: address … have N
  want M" or "max fee per gas less than block base fee: …". Fee or not, the
  sender must hold `gas × fee cap + value`, as geth requires. `ethCallJson`
  can return `infeasible` too, but only for calldata that alone costs more
  than the 30 M budget. From ABI 35 `estimateGasTxJson` answers a fee cap below the
  base fee too, where it used to estimate — as geth's estimator words it,
  "failed with N gas: max fee per gas less than block base fee: …", N being
  the ceiling of the refused run.
- **Upgrade advisory**: `statusJson` carries `upgradeAdvisory` — `null`, or
  `{ phase, activationTime, forkId, observedPeers }` when peers announce
  (`"SCHEDULED"`, `activationTime` ahead) or have already activated
  (`"ACTIVE"`) a network upgrade this engine build does not support. Two
  detectors feed it: EIP-2124 stale-software detection over the peers' eth
  Status (enabled on Sepolia for now), and its consensus-layer twin over
  discv5 ENR `eth2` fields and peers' libp2p Status fork digests (every
  network) — `forkId` is the EL fork hash or the CL fork digest accordingly
  (`"0x00000000"` when unknown: a blob-parameter-only fork rotates the digest
  to a value the build cannot compute), and `activationTime` is `0` when
  unknown (peers seen on the fork, its epoch never announced: say "at an
  unknown time", not 1970). Tell the user an
  update is required, with the date while it is
  SCHEDULED. It is advisory only: derived from what peers announce
  (unverified; `observedPeers` counts distinct peer networks, and a minority
  can't outvote the peers it contradicts), never from anything verification
  reads — so it can raise a false alarm but never make an unverified answer
  look verified. Hence: say "this version can no longer verify" only when the
  engine's own status agrees (`beaconState` not SYNCED, or a stale verified
  head); while it still verifies, an ACTIVE advisory means "update soon". Its
  evidence survives `pause()`, but ages out a day after its peers were last
  seen connected (a long sleep re-derives it from the peers dialed on wake).
- **data_dir**: the engine creates it on `create()` (an uncreatable path
  yields a negative handle) as of the data_dir fix; on engine versions
  without it, create the directory yourself first — otherwise sync works but
  snapshot writes fail with ENOENT and every restart is a cold start.
- **CCIP-Read (`status: "offchain"`)**: the engine returns the gateway tuple;
  driving the HTTP round and re-entering via `method: "ccipCallback"` is the
  host's job (not yet wrapped here).
- The addon is loadable from Electron main/utility processes as-is (N-API is
  ABI-stable across Node and Electron).

## Request ownership and cancellation

This implementation targets the current engine's **ABI 42** and existing JS
argument/result shapes. Every signature up to ABI 31 is unchanged since ABI 25,
ABI 32's one change is additive (an optional trailing argument), ABI 33 changes
no signature (the executor refusals above), ABI 34 adds `estimateGasTxJson`
(the whole transaction object; `estimateGasJson` is unchanged), and ABI 35 adds
`ethCallTxJson` (the same for calls; `ethCallJson` is unchanged): ABI 26 added
`createWithCheckpoint`, and ABI 27 makes `ethCallJson` check its `block`
argument (see Notes), so a call an older engine answered from the head can now
be refused; ABI 28 added `read_stats_json` (the read-fetch shadow-cache
counters, docs/read-stats.md — not yet wrapped here); ABI 29 makes the
engine's plain-C `eth_call` refuse a NULL `to` instead of reading it as the
empty `to` that means contract creation (this binding always passes a string,
so nothing changes for Node callers); and ABI 30 makes `finalized` run
against the beacon-finalized block and adds `blockNumber` / `verified` to the
call result (the block string passes through unchanged; a host that relied on
`finalized` answering from the head must now pass `latest`); ABI 31 adds
`setBootEnodes` and the `snapServingPeers` status key (a key addition — older
readers ignore it); ABI 32 gives `requestAccountJson` an optional `block`
selector (`finalized` proves at the beacon-finalized block; a number only near
the head; the result carries `anchor`); ABI 36 lets `sendRawTransactionJson`
answer `{"status":"rejected","reason"}` for a transaction the engine refuses
before broadcasting it, because its sender cannot pay for it or its nonce is
used (#531): nothing was sent, and the reason is geth's txpool verdict — a
caller that reads only `txHash` and `error` must handle it; ABI 37 gives
`setLogIndexConfig`'s JSON an `unwatch` list (the unsubscribe — see the
log-index example above; a config without the key behaves as before); and
ABI 38 adds the `snap2ServingPeers` status key — the part of
`snapServingPeers` connected over snap/2 (EIP-8189), informational only (a
key addition — older readers ignore it, and nothing should gate on it); ABI 39
adds the engine's DNS-discovery switch (not wrapped here); ABI 40 adds
`createAccessListJson`; and ABI 41 adds `blockTimestamp` to the
`requestAccountJson`, `resolveEnsJson` and `ensRecordJson` results (a key
addition). It is not a drop-in artifact for a host pinned to ABI 22.
Engine failures, admission refusal, cancellation, and deadline expiry remain
in-band JSON errors. Node-API infrastructure failures may throw/reject.

Each Node environment owns two native workers, with a process-wide ceiling of
eight workers. Admission is capped at 32 requests including completions awaiting
JS delivery, with at most four queued/executing requests per handle and one
executing request per handle. Two chains can execute concurrently. Saturation
fails immediately with `{"error":"native scheduler busy"}`; there is no unbounded
thread creation or libuv work item. A fifth concurrent environment fails to initialize at the process worker cap.
Handles belong to the environment that created them and cannot be transferred to another Node worker environment.

A 90-second budget starts at submission, before scheduler setup and queue wait.
Expired or cancelled queued jobs never call the engine. The same deadline and
cancellation bit cross the C seam into async reader setup/network waits, EVM
oracle waits (including writer locks and sends), and EVM instruction checks.
ENS attempts use a shorter child budget and drain before AUTO changes roots.
Proof validation and cache trust rules are unchanged. An indivisible proof,
precompile, filesystem call, or OS operation can overrun the cooperative budget.

`stop` and `pause` remain **synchronous**. They cancel and drain native jobs before
teardown or a new reader generation; Promise delivery follows when JS can run.
The shared engine signals readers even while other `Arc`s own them and drains
registered read/execution work. Started EVM closures retain their global permits
(maximum eight) and accounting until they actually return. Pool shutdown joins
owned parent loops and spawned dial/backfill/send work before closing peers.
Pause/resume/start/stop on a handle must be serialized by C/JNI/UniFFI callers.

Environment cleanup closes admission and the completion producer, cancels queued
and active work, joins native workers without waiting for JS callbacks, and stops
owned handles. It never drops the shared Tokio runtime. The completion TSFN is
referenced while requests await delivery and unreferenced when idle. Cleanup
cannot preempt indivisible work: **this is not a hard-stop or crash-isolation
contract**. Hosts needing a hard shutdown deadline still need a supervised
process boundary. Cancelled/timed-out transaction gossip does not prove that a
transaction was not broadcast; do not blindly retry a signed submission.

Qualification of Node/Electron cleanup, forced environment teardown, parent DNS
liveness, queue cancellation, cross-chain fairness, and native overruns belongs
on disposable hosts. Exact-lock Node build/runtime qualification is required
before releasing a new artifact; a type-check with cached dependency patch
versions does not qualify that artifact.

The completion bridge makes exactly one resolve/reject attempt per deferred.
A result-string allocation failure selects rejection before settlement. If
Node's settlement itself fails, deferred ownership is consumed/unknown: the
addon releases its admission/keepalive accounting, marks the scheduler poisoned,
cancels remaining native work, and reports an uncaught exception plus a stderr
diagnostic, without retrying that pointer. New reads resolve with
`{"error":"native scheduler poisoned"}`; lifecycle cleanup remains available. A host
`uncaughtException` handler can suppress termination, so this is not a guarantee
that the failed Promise settles. If even the preallocated error reference cannot be obtained, no settlement is
attempted: the scheduler is poisoned and the pending exception or stderr
reports the loss. JS-side allocation and pending-exception errors never use
`napi_fatal_error`. A proven live worker-side TSFN enqueue invariant
failure is process-fatal (including in standalone Node); ordinary engine errors
and environment closing do not use that path.

Queued stop/pause cancellations are removed immediately under the queue lock
and delivered through the TSFN; they do not wait for workers occupied by other
chains, and they never release the slot of an actually executing sibling.
Stop/pause wait only for the target handle's active native job. Poisoning also
cancels queued jobs directly. An impossible owner-thread TSFN enqueue failure
retains the completion for one JS-thread settlement after native lifecycle
returns; ordinary lifecycle cancellation does not run synchronous Promise hooks.

Initialization/read calls from a Node `async_hooks` init hook during scheduler
creation are unsupported and throw. An uncaught exception inside that hook can
terminate Node; the initialization guard prevents a second scheduler from
replacing the first owner's state. Ownership-gated status/lifecycle calls in
that window return their unavailable sentinels. Synchronous `create`, `pause`
and `stop` may also throw scheduler/Node-API infrastructure errors; engine-level
read failures still use JSON error results.

ENS queries use one registered 90-second whole-query scope. A finalized root
attempt may use up to 60 seconds; AUTO's optimistic attempt receives only the
remaining budget (about 30 seconds after a full first attempt). CCIP callbacks
use a 60-second operation scope, and appender name lookups use an 8-second scope.
All retain the indivisible-work overrun limitation. Stop first aborts/joins the
appender, then drains its retained actual execution along with other requests.

Once a wrapped operation returns a ready success or error, cancellation does
not replace that committed result. Cancellation or connection loss after a
partial transaction broadcast but before the operation returns still has an
uncertain outcome; there is no exactly-once broadcast guarantee. Outer
fee-history cancellation/expiry follows the existing stale-cache policy: only
the same request signature within the cache age limit may be served, and an
explicit invalid-request rejection never uses stale data.

The global EVM cap admits eight native executions at once. A call that finds
every slot taken waits its turn — FIFO, for at most 5 s, and only while its
own operation is live — and is refused with `native execution busy` when the
wait runs out, or at once when 32 calls are already waiting; this applies to
C/JNI/UniFFI callers and appender ENS lookups alike. The blocking pool itself
never queues: a job reaches it only with a slot in hand. Hosts should still
bound their own queue and retry busy verified reads within their own request
deadline. Node's one
executing request per handle is intentional: a slow ENS call delays queued
calls on the same chain, while another chain can execute concurrently. The
ABI 25+ migration must account for the four queued/executing requests per
handle and treat `native scheduler busy` as admission refusal.

A cancelled partial RLPx frame cannot be resumed safely. The torn-write marker
prevents further writes on that stream; the next attempted send fails the peer,
and lifecycle cleanup closes it. Under write backpressure this can require
re-dialing an otherwise healthy peer. Cancellation does not grant an unbounded
write grace or delay stop to preserve the connection. Cancellation-check
frequency and polling performance remain unmeasured optimization follow-ups.
