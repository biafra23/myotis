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

myotis.init();                                   // must return 19 (ABI handshake)
const h = myotis.create('mainnet', '/path/to/data-dir');  // dir must exist
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

## Notes

- **Readiness**: serve verified reads only when `statusJson` shows
  `beaconState === 'SYNCED'`, `elReaderAvailable`, and `snapPeers > 0`;
  before that, reads honestly error rather than guess.
- **data_dir**: the engine creates it on `create()` (an uncreatable path
  yields a negative handle) as of the data_dir fix; on engine versions
  without it, create the directory yourself first — otherwise sync works but
  snapshot writes fail with ENOENT and every restart is a cold start.
- **CCIP-Read (`status: "offchain"`)**: the engine returns the gateway tuple;
  driving the HTTP round and re-entering via `method: "ccipCallback"` is the
  host's job (not yet wrapped here).
- The addon is loadable from Electron main/utility processes as-is (N-API is
  ABI-stable across Node and Electron).
