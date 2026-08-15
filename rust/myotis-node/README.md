# myotis-node

Node.js binding over the myotis-engine **C ABI** (`capi.rs` /
`rust/include/myotis_engine.h`) via [napi-rs](https://napi.rs) — the seam for
Electron/desktop hosts that want to run Myotis invisibly in-process, the way
they run other embedded nodes.

This is the third consumer of the same ABI seam, next to the hand-JNI surface
(JVM hosts) and the Kotlin/Native cinterop (iOS): identical JSON shapes (pinned
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

// Lifecycle + status are cheap and synchronous:
JSON.parse(myotis.statusJson(h));   // { beaconState, peerCount, snapPeers, ... }

// Verified reads BLOCK up to ~90 s in the engine — the binding runs them on
// the libuv thread pool, so they surface as ordinary Promises:
const acct = JSON.parse(await myotis.requestAccountJson(h, '0xd8dA…6045'));
const ens = JSON.parse(await myotis.resolveEnsJson(h, 'vitalik.eth'));
const ch = JSON.parse(await myotis.ensRecordJson(h, JSON.stringify({
  method: 'contenthash', name: 'vitalik.eth',
})));

myotis.pause(h);   // idle-sleep: tear down networking, keep warm state
myotis.resume(h);  // warm restart
myotis.stop(h);
```

`smoke.mjs` is the end-to-end check: syncs mainnet from plain Node, then runs
`resolve-ens` + `contenthash` + `get-account` with verification fields and
cold/warm timing:

```bash
node smoke.mjs ./data-dir ../target/debug/myotis-node.node
```

It begins the reads only once the peer set is worth judging — `snapPeers >= 2`
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
  `beaconState === 'SYNCED'` and `elReaderAvailable`; before that, reads
  honestly error rather than guess. `snapPeers > 0` is the minimum to answer
  at all, but a host that wants a read to SURVIVE one silent peer should wait
  for `snapPeers >= 2` — the reader rotates over the snap set, and with a
  single peer there is nowhere to rotate to (this is what `smoke.mjs` gates
  on; see #372).
- **data_dir**: the engine creates it on `create()` (an uncreatable path
  yields a negative handle) as of the data_dir fix; on engine versions
  without it, create the directory yourself first — otherwise sync works but
  snapshot writes fail with ENOENT and every restart is a cold start.
- **CCIP-Read (`status: "offchain"`)**: the engine returns the gateway tuple;
  driving the HTTP round and re-entering via `method: "ccipCallback"` is the
  host's job (not yet wrapped here).
- The addon is loadable from Electron main/utility processes as-is (N-API is
  ABI-stable across Node and Electron).
