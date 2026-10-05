# myotis-rpcd

Standard Ethereum JSON-RPC over HTTP, answered by the Rust engine
(`myotis_engine::ffi`) in-process: one binary, no JVM, and nothing behind it to
fall back on.

The wallet API the README describes is the Kotlin `jsonrpc-server`, so serving
it has meant running one of the JVM hosts. myotis-rpcd is for hosts that can't
or won't: a server, a container, a Raspberry Pi, or a service such as a Swarm
Bee node ([docs/bee-rpc-service.md](../../docs/bee-rpc-service.md)) that only
needs an RPC endpoint on localhost. It links the engine as a library and puts a
thin HTTP layer in front of it.

Every answer is one the engine verified: a beacon-anchored head, snap proofs for
state, root-verified bodies and receipts. Anything it cannot verify is an error.
There is no proxy mode.

## Build

```bash
cargo build -p myotis-rpcd --release   # ../target/release/myotis-rpcd
cargo test -p myotis-rpcd
```

It is an ordinary workspace member, so it inherits the workspace release profile
— including `panic = "abort"`, the engine's own contract (the engine is
panic-free by construction; a panic in the daemon ends the process, and the
data dir resumes on restart).

## Run

```bash
myotis-rpcd [--network gnosis|mainnet|sepolia]     # default gnosis
            [--data-dir DIR]                       # default ~/.local/share/myotis-rpcd/<network>
            [--listen ADDR]                        # default 127.0.0.1:8545 / 8546 / 8547 by network
            [--http-vhosts HOST,...|*]             # Host-header allowlist (geth's --http.vhosts)
            [--log-index-config FILE]              # enables eth_getLogs for a watch-list
            [--import-log-index FILE]...           # snapshot(s) imported after the config
            [--checkpoint-root 0x… --checkpoint-slot N]
            [--accept-stale-anchor] [--ws-bound-periods N]
            [--log-calls FILE] [--access-log]
            [--ready-wait 90] [--workers 16]
            [--http-queue N]                       # default 2 × --workers
            [--http-body-timeout 10]               # seconds to receive a body
```

- `POST /` takes a JSON-RPC request or a batch (up to 1000 requests, geth's
  limit; bodies up to 5 MiB, geth's `--http` limit). As in geth, the body must
  be sent as `Content-Type: application/json` (`curl -H 'Content-Type:
  application/json' -d …`); anything else, or no type, is `415`.
- Every request's `Host` header must name an allowed host (`403` otherwise),
  as geth's `--http.vhosts`: by default `localhost`, `127.0.0.1`, `[::1]` and
  the `--listen` address. `--http-vhosts a,b` replaces that list, and `*` turns
  the check off. Together with the Content-Type rule this keeps a web page in
  the operator's browser from reaching the node (DNS rebinding, cross-origin
  form posts).
- `GET /` returns one status line:
  `synced=true ready=true beacon=SYNCED head=… finalized=… peers=… snapServing=… network=gnosis`.
- `GET /logindex` returns the engine's log-index status JSON (coverage per watch
  entry, backfill cursor, head gap).
- Engine logs go to stderr. SIGINT and SIGTERM stop the engine handle cleanly,
  and its sync state persists in the data dir.

The HTTP side is deliberately synchronous: every engine read blocks (it may hold
for a verified head), so a fixed pool of `--workers` threads each takes a
request and blocks in the engine for as long as it must. A read is held up to
`--ready-wait` seconds for the node to become ready (SYNCED, an anchored head,
and a peer that can serve at it — `snapServingPeers`, #465), then asked anyway,
so the error carries the engine's own reason. The hold is taken once per
request, and a batch shares one: it waits at most `--ready-wait` in total, after
which its remaining reads fail fast with `-32000` while the node is still not
ready. Requests that never need the engine to be ready — `GET /`,
`GET /logindex`, `eth_chainId`, `net_version`, `web3_clientVersion`,
`eth_accounts`, `net_listening`, `eth_syncing`, `myotis_status`, or a batch of
only those — are answered by a separate small intake pool, so a health check
answers even while every read worker is held.

What waits is bounded. At most `--http-queue` gated requests (default twice
`--workers`) wait for a busy worker; past that a request is refused at once
with HTTP `503` and a `-32000` "server busy" error for each request in it, so
a flood of reads cannot grow memory without limit. A body larger than 1 KiB
(or chunked) is received on a thread of its own, never on the intake pool, and
must arrive within `--http-body-timeout` seconds (default 10) or the request is
answered `408`; at most 32 such bodies are received at once, and past that the
request is refused `503` unread. tiny_http exposes no socket timeout, so a
client that stops sending entirely holds its body thread until it closes the
connection or sends again — but never an intake thread, so `GET /` and the
status methods keep answering.

### The trust anchor

The engine bootstraps from the checkpoint embedded in the build. Once that is
older than the network's weak-subjectivity bound (13 periods on mainnet, 3 on
gnosis — about 34 h), the node parks in `STALE_ANCHOR` and refuses every read
with `-32000` and an explanation. Two ways forward, both explicit:

- **`--checkpoint-root 0x… --checkpoint-slot N`** bootstraps from a root you
  already trust, through the engine's create-with-checkpoint path (the one the
  Node addon exposes as `createWithCheckpoint`, #441). The daemon never fetches
  a root itself (its only data sources are devp2p and libp2p); where the root
  comes from is your decision. It is trusted for the anchor only: the engine
  fetches a light-client bootstrap for the root from peers, checks it against
  the root, and verifies every later header with sync-committee signatures, as
  from the embedded checkpoint. The data dir is bound to the anchor (the engine
  writes `sync-anchor[-net].json`); later starts on that dir resume it without
  the flags, and a different anchor needs a fresh `--data-dir`. Measured on
  gnosis: bootstrap verified 3 s after start, `SYNCED` within 9 s, ready for
  reads at 45 s.
- **`--accept-stale-anchor`** consents to sync forward from the stale embedded
  anchor, for this run only. It is a flag rather than a default because it is a
  trust decision the operator has to make, not the daemon: past the bound, a
  chain signed by sync-committee members who have since exited would look
  exactly like the real one, and BLS verification alone cannot tell them apart.
  It is the CLI form of the apps' `STALE_ANCHOR` consent dialog. Once a run has
  synced, the data dir resumes from its own fresh snapshot and the flag is no
  longer needed. `--ws-bound-periods` overrides the bound itself, with the same
  trade-off.

### eth_getLogs

`eth_getLogs` needs the opt-in log index
([docs/eth-getlogs-design.md](../../docs/eth-getlogs-design.md)).
`--log-index-config` takes the engine's watch-list JSON, installed as soon as
the engine's EL reader is up:

```json
{"enabled": true, "watch": [{"address": "0x…", "fromBlock": 12345678, "name": "BZZ"}]}
```

`fromBlock` must be the contract's **deployment block**: the engine reads it as
a claim that the contract has no logs below it, so a query reaching below is
answered `[]` from the config. Set it to something "recent" and older ranges
that do have logs come back empty. To avoid a long backfill, keep the
deployment block and add `"backfillPaused": true`; queries below the covered
range are then refused. Ranges the index has not covered yet are `-32000` with
the engine's reason.

`--import-log-index FILE` (repeatable) imports portable log-index snapshots once
the config is installed — e.g. a seed from `scripts/synth_logindex.py`. The
import is all-or-nothing, and its logs are served as the snapshot claims them,
so a seed is only as good as its source
([docs/seeded-log-histories.md](../../docs/seeded-log-histories.md)).

### --log-calls

`--log-calls FILE` appends one JSON line per request (each batch element on its
own line): `ts`, `method`, `params` with long strings shortened, `outcome`
(`ok`, `null`, or `error` with `code` and `message`), the result (or its size
and an FNV-64 hash when long), and `ms`. It is the record to read when a client
misbehaves against the node: what it asked, in what order, and what it got.
`--access-log` is the one-line-per-request stderr version.

## Error codes

| code | meaning |
|---|---|
| `-32000` | Implemented, but not answerable verified right now (not synced, no serving peer, range not indexed). Retryable. |
| `-32602` | Can never be answered as asked: malformed input, or state this node does not hold (a block more than 64 behind head, `safe`, `earliest`, a block hash on a state read). Do not retry (#366). |
| `-32601` | Method not implemented. |
| `3` | The call reverted. A verified answer; `data` is the revert payload. |

## Methods

| method | source | notes |
|---|---|---|
| `eth_chainId`, `net_version` | config | From the engine's network catalog. |
| `web3_clientVersion` | config | `myotis-rpcd/<version>` |
| `eth_accounts` | config | Always `[]`: the node holds no keys. |
| `net_listening` | config | `true` |
| `eth_syncing` | verified | `false` once the beacon light client is SYNCED, else a zeros object. |
| `eth_blockNumber` | verified | The beacon-anchored optimistic execution head. |
| `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | verified | Snap proof at the head or at `finalized`. A number pin is served from head state only within [head-64, head+16]. `pending` nonce adds the node's own broadcasts. |
| `eth_call` | verified | revm over proven state. State overrides applied; `blockOverrides` refused. A tx object with an explicit `type` or gas/fee/list fields goes through the engine's transaction-object call, which applies or refuses them. |
| `eth_estimateGas` | verified | Full transaction object, state overrides. |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas` | verified | The engine's fee suggestion (see gaps). |
| `eth_feeHistory` | verified | Newest block required. At most 1024 blocks and 100 percentiles. |
| `eth_getBlockByNumber`, `eth_getBlockByHash` | verified | Hashes or full txs; recent/anchored blocks only. Unknown blocks are `null`. |
| `eth_getBlockReceipts` | verified | Body and receipts root-verified. |
| `eth_getTransactionReceipt`, `eth_getTransactionByHash` | verified | Short lookback; see gaps. |
| `eth_getLogs` | verified | Needs `--log-index-config`. Watched addresses, covered ranges only. |
| `eth_sendRawTransaction` | engine | Gossiped to peers, unless the engine's txpool-style check refuses it first (`-32000`, geth's wording). |
| `myotis_status` | — | The engine's raw status object. |
| anything else | — | `-32601` |

## Known gaps

- **Receipt and tx-by-hash lookback.** The engine's first lookup for a hash
  scans the last 8 blocks; a per-hash cursor then grows forward while the caller
  keeps polling. That fits a client confirming its own send (Bee polls straight
  after sending), but an older transaction comes back `null` ("verified not
  seen") where geth would return it.
- **No historical state.** State reads more than 64 blocks behind head are
  `-32602`.
- **Fee suggestions are not a full node's.** On gnosis `eth_gasPrice` answers
  about base fee + 0.01 gwei where Nethermind answers about base fee, and
  `eth_maxPriorityFeePerGas` was seen to answer 0.001, 0.01, 0.1 and 1 gwei
  within minutes while Nethermind answered 3 wei throughout. Both are safe (they
  overpay), but the second is not stable.
- **`eth_estimateGas` is higher than a full node's** (an ERC-20 transfer: 49407
  vs Nethermind's 42962). Safe, but not tight.
- Blocks and logs lack some newer fields: `blockTimestamp` on logs;
  `withdrawals`, `requestsHash`, `size` and `totalDifficulty` on blocks.
  Everything the engine does emit matched a full node byte for byte.
- No `eth_subscribe`, filters or websocket; no `net_peerCount`, `web3_sha3`,
  `eth_getUncle*` or `eth_getTransactionByBlock*AndIndex` (the Kotlin router
  has these; they port directly).

## Provenance

The method semantics are a port of the strict (no-proxy) path of the Kotlin
`RpcRouter` (`jsonrpc-server`), and the engine-JSON reading follows
`IosRpcBackend` and `RustVerifiedReads`: selector parsing, the 64/16-block
window, `ReportedHeads`, tri-state results, the permanent
`{"error", "code": -32602}` envelope, revert-reason decoding, and the readiness
hold before reads (`RustChainHandle.readyForReads`). One deliberate difference:
an engine `{"error": …}` on a state read is surfaced with its reason (`-32000`,
or `-32602` when the engine marks it permanent) instead of the generic "no peer
/ not synced" text.
