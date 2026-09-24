# Review follow-ups (TODO)

Concerns raised while reviewing PR #261 (myotis-node napi-rs binding) and
PR #262 (create data_dir in `host::create`), collected 2026-07-31. None are
merge blockers; each should either be fixed or consciously dropped.

## From PR #261 — Node.js binding

- [ ] **libuv thread-pool starvation.** Every verified read runs on Node's
  shared libuv pool (default `UV_THREADPOOL_SIZE=4`). Four concurrent ~90 s
  worst-case reads block ALL of the host's `fs`/`dns`/`zlib`/`crypto` work —
  a real hazard in an Electron host that also runs IPFS/Swarm nodes.
  - Short term: warn in `rust/myotis-node/README.md` (raise
    `UV_THREADPOOL_SIZE`, or serialize long reads host-side).
  - Longer term: dispatch reads onto the engine's own tokio runtime and
    complete via a napi threadsafe function, taking the libuv pool out of
    the picture entirely.

- [x] **`node-binding.yml` goes dead on merge.** Done: push trigger retargeted
  to `main` + `v*` tags, keeping the `rust/**` paths filter for branch pushes
  (GitHub doesn't evaluate paths filters on tag pushes, so release runs
  always fire), and a release job now publishes the five addons plus
  `myotis-node.SHA256SUMS` to the tag's GitHub Release with the engine ABI
  version pinned in the notes.

- [ ] **`panic = "abort"` now aborts a browser.** Workspace-wide release
  profile choice (`rust/Cargo.toml`), same exposure as the JNI seam — but the
  blast radius is new: a Rust panic takes down the user's entire Electron
  process, not a daemon. Add an explicit note to the binding README; the
  "panic-free by construction" discipline in `host.rs` is carrying more
  weight now.

- [x] **`smoke-windows` is network-flaky by construction.** Resolved as
  predicted: `cargo test --workspace` is green on Windows (after the
  `.gitattributes` LF pin for the golden vectors), but the smoke discovers
  peers over UDP yet holds no TCP/libp2p connections — possibly Windows,
  possibly Ethereum peers deprioritizing Azure datacenter IPs (a Linux
  control job disambiguates; real-Windows-box validation pending downstream).
  Both smoke jobs are now manual-only (`workflow_dispatch`) and releases
  never gate on them.

- [ ] **Pin the flat-vs-nested verification-field divergence.** The Rust
  engine's account JSON carries `beaconChainVerified`/`blsVerified`/
  `failReason` flat, where the Java daemon's IPC nests them under
  `verification` (PR #261 field finding #4). If the surfaces are meant to
  converge, pin the discrepancy in the cross-engine golden tests now — before
  a fourth ABI consumer discovers it the hard way.

## Interplay #261 ↔ #262

- [x] **Sweep the stale "data_dir must exist" notes** once PR #262 (engine
  creates `data_dir` in `host::create`) lands. Done: the README usage comment
  and the workflow's "Ensure data dir exists" steps are gone (the README
  Notes bullet had already been dropped at merge time).

## From PR #262 — data_dir creation

Asked of the author in review; tracked here in case they don't land there.

- [x] **Stale `create()` doc contract.** Landed with #262: the doc comment now
  lists "an unknown name, an unavailable runtime, or an uncreatable dataDir".

- [x] **Misleading Java-side error message.** Landed with #262:
  `RustMyotisEngine.java` now throws "could not initialize the runtime or
  create the dataDir for <network>".

## From PRs #480, #481, #482 — issue #465 (verified reads fail after SYNCED)

Open questions and deferrals collected from the three PRs' "Decisions for the
owner" sections and their review threads, 2026-09-24. The decisions the owner
took while the work was in flight are listed at the end so this section is
complete on its own.

### Still open

- [x] **`snapServingPeers` on the wallet-facing status surfaces.** Done in
  the #465 follow-ups PR (owner's decision 2026-09-24): JSON-RPC, iOS RPC
  and daemon IPC status, and the wake-up guidance gates on it.
- [x] **`finalized` on the state reads — Rust engine.** Done in the same PR
  (owner's decision 2026-09-24: Rust now, Java stays on #366): ABI 32, the
  three state reads take the selector, a finalized proof is verified at the
  finalized state root with no fallback, results carry `anchor`.
  - [ ] **Java engine**: `VerifiedRpcBackend` still maps `finalized` to the
    head for the state reads, `eth_call` and the block reads — #366 item 5.
- [x] **`Behind` peers in a race another peer won** — dropped consciously
  (owner's decision 2026-09-24): the ladder ranks such a peer last, the
  maintainer evicts it within a tick, and an unwitnessed strike never
  persists. (The `RaceOutcome` reasons are index-aligned since the same PR,
  so the excuse is cheap if it is ever wanted.)
- [x] **Live cold-start checks** — run 2026-09-24 on the dev Mac: mainnet,
  Rust engine (`./gradlew :app:run -Pengine=rust`; the daemon's data dir is
  its working dir, `app/`, so `app/peers.cache` was moved aside; the CL
  snapshot was warm), polled every 5 s over JSON-RPC.
  - `SYNCED` 90 s after the gradle start, and the FIRST poll after the RPC
    came up already read `snapPeers 1, snapServingPeers 1` with
    `eth_getBalance(latest)` answering in 0.37 s: the first pooled peer
    proved the head at once. Three dials were refused for announcing a head
    far behind; the cache ended with 3 `snapok` and 0 `snapbad` entries.
  - At `finalized`: `eth_getBalance`, `eth_getTransactionCount` and
    `eth_getCode` answered in ≤ 0.2 s, `eth_call` in 1.5 s,
    `eth_getBlockByNumber` matched the beacon status's finalized block,
    `eth_feeHistory` served. `latest` reads succeeded on the same pool, so
    "finalized serves while latest fails" had no occasion to show.
  - Weak spot seen: the pool held only 1–2 peers for 15 minutes (few
    snap-capable peers discovered, 150+ addresses in backoff), and one peer
    that went silent after serving cost 4–5 s reads and two retryable
    `-32000`s over four minutes until the EL hunt engaged and evicted it —
    the #320 latency class, on a thin pool.
  - Seed pin through the Node addon on a fresh data dir: a DNS-named entry
    refused (`false`), a `snapok` peer pushed (`true`), dialed on the first
    tick (`EL pool host seed pins replaced count=1`, `snap peer connected`);
    `snapPeers 1 / snapServingPeers 1` after 5 s in one run and after 60 s
    in another, where the peer dropped the session five times first.
- [x] **A seed-pin surface for the JVM hosts** — dropped until a JVM host
  asks: `myotis_set_boot_enodes` exists on the C ABI, the Node addon and the
  iOS wrapper.
- [x] **Smoke-gate classification** — accepted: `smoke-gate.mjs` files a
  full but non-serving pool under peer starvation (an environment result,
  like the other peer conditions); an engine-side regression in the head
  probe would carry the same label, and the job still fails either way.
- [ ] **A permanent engine refusal flattens to a retryable `-32000` on the
  hosts' state reads.** `RustChainHandle.parseResultOrThrow` and the iOS
  `resultOrNull` drop the engine's `code`, so a `-32602` from
  `request_account_json` / `get_code_json` / `get_storage_at_json` reaches
  the wallet as the retryable `-32000` a client is documented to spin on.
  Reachable today only in the one-block race between the hosts' window
  pre-check and the engine's head; a real loop the moment the state reads
  accept a selector the hosts do not pre-filter. Decide deliberately (a typed
  refusal the router maps to `-32602`, as `eth_call`'s `CallResult` does)
  rather than inherit (review of #483).
- [ ] **Parity entries for #342.** Rust-only behaviour introduced by the
  three PRs, to be listed there as differs-fixed or differs-accepted:
  admission by announced head and lag eviction (the Java `EthHandler`
  decodes `BlockRangeUpdate` but does not route by it); the witness rule for
  persisted `snapbad` verdicts; `finalized` honoured on `eth_call` and the
  block reads; pins served up to 511 blocks below FINALITY (Java measures
  its lookback from the head, so pins in `[fin − 511, head − 512)` serve on
  the Rust engine only); `snapServingPeers` as a real count (Java has no
  serving count); host seed pins.
- [ ] **`verified` in the call envelope** means "ran against the finalized
  block", not "unverified data" — it follows `ens_record_json`'s vocabulary.
  If the key ever graduates into `io.myotis.api.CallResult`, land it as an
  anchor enum (head / finalized), not a boolean named `verified`.

### Accepted as tuning, revisit on live data

- `HEAD_LAG_TOLERANCE = 32` blocks (judged at the moment the peer spoke),
  `HEAD_SIGNAL_FRESH = 300 s`, `BACKOFF_LAGGING = 10 min` (not cleared by the
  hunt's backoff bypass), `PROBE_MISSES_EVICT = 3`, `MAX_HOST_ENODES = 64`.
- A warm resume's first read can cost up to one maintainer tick (~10 s) on
  an eth/68-only pool, since proving a peer now needs a probe round-trip;
  eth/69 peers prove at the handshake.
- A dead pin costs one SYN per backoff window while the pool is below target
  or, once the anchor has a head, nobody serves at it.

### Decided while the work was in flight (for the record)

- `safe` and `pending` resolve to the optimistic head (2026-09-23): the
  light client has no justified anchor to apply, and substituting the
  finalized block for `safe` would answer a third question.
- No shipped mainnet seed list; hosts supply pins through the ABI.
- No head-minus-k fallback for `latest`; the tip-lag retry constants stay.
- Nothing persists a `snapbad` verdict without a witness; a probe hit
  persists `Confirmed`.
- On an address the network also pins, the host's key wins; DNS names and
  unspecified addresses are refused, not resolved or dropped.
- A missing `snapServingPeers` key reads as 0 on the JVM and iOS hosts.
