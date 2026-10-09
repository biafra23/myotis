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
    the #320 latency class, on a thin pool. (#539 shortens backoffs and
    re-dials discovery's table while the pool is below target, and logs why
    each pooled peer closed.)
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
  Reachable today only in the one-block race between the router's window
  check and the engine's head: since #366 the router refuses every selector it
  can judge (`safe`, `earliest`, a hash, a malformed one, a pin behind the
  window) with `-32602` before the engine runs. Still a real loop the moment
  the state reads accept a selector the router does not pre-filter. Decide
  deliberately (a typed refusal the router maps to `-32602`, as `eth_call`'s
  `CallResult` does) rather than inherit (review of #483).
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
  `HEAD_SIGNAL_FRESH = 300 s`, `BACKOFF_LAGGING = 10 min` (below target it
  shrinks with the shortfall, to 60 s at an empty pool —
  `LAGGING_RECHECK_FLOOR`; transient and busy never go under geth's 30 s
  inbound throttle, `PEER_INBOUND_THROTTLE`, which is also why the EL hunt no
  longer clears a confirmed server's transient backoff outright; #539),
  `PROBE_MISSES_EVICT = 3`, `MAX_HOST_ENODES = 64`.
- Engine divergence (#539): the Rust EL hunt no longer clears a cache-confirmed
  server's transient backoff outright — against geth's 30 s inbound throttle
  that re-dial is a refusal and a cache strike — while the Java
  `ChainStack.maintainSnapPeers` still does. Aligning the Java twin is the
  owner's call.
- EIP-1459 in the Rust engine (#539 part 3, `el/dnsdisco.rs`) is desktop-first:
  the walk runs over the system resolver where a host switched it on
  (`myotis_set_dns_discovery`: the JVM desktop and daemon, `myotis-rpcd`) and
  never under Tor. Open: a `DnsServers`-style port taking explicit server IPs
  would bring it to Android (hickory's `builder_with_config`), and whether a
  phone should spend the lookups at all; the Node addon exposes no
  `setDnsDiscovery` yet (nor a Tor switch), so Electron/Node hosts stay off; the walk's lookups are sequential (~330 records per 15 s
  walk on the dev host, of trees with far more — random order spreads the
  walks); the seeder restarts with the reader on resume, where the Java twin
  keeps its DNS pool across pause; the Java twin's public DNS fallbacks
  (`1.1.1.1`/`8.8.8.8`) are left out on purpose (a third party learning the
  network).
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

## From the v0.1.14 release (2026-10-06, Glamsterdam day)

- [ ] **Sepolia has one light-client server either engine can sync
  Gloas-era data from (roost).** The release's cold-start pin check stopped
  at 1 of 4 — both Lighthouse pins stopped serving light-client data at the
  fork and a 91-peer census found no other Gloas-era server, from a host
  that could not reach Nimbus or Lodestar nodes (#576) — and the owner
  released anyway. Tracked in
  #566: until a second server exists, every Sepolia `cold-start regression`
  dispatch stops red at the pin check and 3b/3c never run there. Whether
  CLAUDE.md's release step 3 ("release-blocking") gets a carve-out for a
  floor unmet for an upstream reason is the owner's decision.
  - 2026-10-07: both Lighthouse pins dropped (both engines), roost is the
    only Sepolia pin. Cause upstream: Lighthouse's light-client server
    produces nothing for a Gloas block (sigp/lighthouse#9587; fix PRs #9732
    and #9790 unmerged, no release), and its store keys updates by the
    signature slot's period, so the update under 1379 is a Fulu one that
    fails as Gloas ("Database error") — expect 1379 to stay broken on nodes
    that ran v8.3.0-rc.0 across the fork even after a fixed release.
    Period-1379 censuses (zbox 170 peers, runner 218) found every Lighthouse
    answer an error or empty, Prysm and Grandine without the protocol, and
    100+ peers closing before Identify — most likely many of them Nimbus and
    Lodestar nodes the yamux-only census host could not reach (#576), so
    those censuses do not show roost to be the only server. zbox's own
    Nimbus serves Gloas light-client data and is #566's option 3 once #576
    is in — re-pinned second, after roost, on 2026-10-09 (both engines), with
    its two caveats in the pin comment: the `--max-peers=25` unit resets the
    handshake while it is full, and its peer loop scores our empty by-root
    answers down, so a connection lasts minutes between reconnects.
  **Part of the cause was ours (2026-10-08):** the Rust engine's libp2p host
  offered only yamux on TCP, while Nimbus (since 2024) and Lodestar speak
  only mplex there — so the two client families that DO serve Gloas
  light-client data were unreachable from the Rust engine by construction,
  and zbox's own Nimbus had been dropped as a "dead" pin in September for
  the same reason. mplex is in (`reqresp::build_swarm`), and so is the spec's
  primary transport, QUIC (2026-10-09): the host listens on an ephemeral
  `/udp/0/quic-v1` beside TCP, discovery turns an ENR `quic`/`quic6` field
  into a second dial address, and a peer is dialed at TCP first, QUIC only
  when the TCP dial fails. **Not QUIC first, measured:** pinned to zbox's
  Nimbus over `udp/9001/quic-v1` alone, the handshake, identify, status and
  the first four finality polls worked (`SYNCED`), then every further
  stream open hung (`Timeout while waiting for a response`) until Nimbus
  aborted the connection after ~70 s with lsquic's
  `connection timed out due to lack of progress` — its `es_noprogress_timeout`,
  which fires when the APPLICATION (nim-libp2p's QUIC muxer) stops servicing
  streams, so the stall is on Nimbus's side; over TCP the same node served
  for as long as it was asked. Upstream candidate (status-im/nim-libp2p,
  QUIC is new in Nimbus 26.9). Flip the order once a Nimbus release holds a
  QUIC connection open across many streams. Still open: roost listens on TCP
  only (its relay forwards no spare UDP port and its ENR carries no `quic`
  field), and the shipped Sepolia / mainnet / gnosis pins are all `/tcp/`
  multiaddrs.
  **And a second, independent cause behind it:** once a connection to zbox's
  Nimbus came up over mplex, Nimbus admitted us and then dropped us ~100 ms
  later, before our bootstrap request was served — its post-Fulu sync
  overseer asks every new peer for `metadata/3` and nothing else
  (`doPeerUpdateMetadata` → "Peer loop stopped"), and both engines served
  only `metadata/2`. Lighthouse and Teku hid this by negotiating v3→v2→v1 in
  one multistream offer. `metadata/3` is in on both engines
  (`status::metadata_v3_light_client`, `BeaconP2PService.METADATA_V3`),
  advertising `CUSTODY_REQUIREMENT` — not 0, which Lighthouse bans.
  **And a third:** with metadata answered, Nimbus admitted us, served the
  bootstrap, and then its root sync asked us for the head block we had just
  advertised in Status (the checkpoint block — not in its sync DAG, which
  only holds what it saw since its start), could not negotiate
  `beacon_blocks_by_root` at all, and ended the peer loop ~1 ms later, under
  our first `updates_by_range`. Both engines now answer `beacon_blocks_by_root/2`
  inbound with zero chunks — the spec's "none of these" — which passes
  Nimbus's response check and costs no score. With that in, the Rust engine
  applied finality updates from zbox's Nimbus alone, every 12 s — the first
  time ever — and the fourth and last drop showed itself:
  `data_column_sidecars_by_root/1`, asked every ~45 s because the
  `custody_group_count` we advertise (Lighthouse's minimum) gives us a column
  map. Same zero-chunk answer on both engines; Nimbus scores that
  `PeerScoreNoValues` but keeps the loop (a refused negotiation ends it), so
  a Nimbus that keeps missing sidecars still cycles us every few minutes,
  with updates flowing in between. The fifth and last step of that loop,
  Gloas `execution_payload_envelopes_by_root/1`, behaves like the sidecars
  (zbox's Nimbus asks on every connection, its missing-envelope set is never
  empty) and gets the same answer. A refused protocol ends Nimbus's loop with
  `CommunicationTimeout`, a sunk score with `PeerScoreLow`; neither blocks
  our reconnect, because its seen-table only gates ITS outbound dials
  (`checkPeer`). Re-run the Sepolia census from a build with all of this
  before concluding anything about who serves.
  **Upstream (owner's call to file, status-im/nimbus-eth2):** the three
  zero-chunk responders placate `sync_overseer2`, which (a) requests a peer's
  advertised head by root even when its own DAG holds the block (the sync DAG
  only covers what it saw since start, and `getMissingBlocksRequest` never
  consults the DAG), and (b) ends the peer loop on a protocol the peer does
  not offer, which disconnects every light client — its own
  `nimbus_light_client` included, whose Status is the genesis head. Every
  further overseer step that asks for data a light client cannot hold would
  need another responder here until that is fixed upstream.
  **Follow-ups from the final PR's review (2026-10-09):** the
  `custody_group_count` both engines advertise in `metadata/3` is a
  per-network parameter (`CUSTODY_REQUIREMENT`) hardcoded as 4
  (`status::CUSTODY_GROUP_COUNT`, `MetadataMessage.CUSTODY_GROUP_COUNT`); it
  belongs in the network configs with a parity test before any network with
  a different value is added, since Lighthouse bans a peer below its own
  requirement. And the Java engine's `metadata/3` and zero-chunk responders
  have not been run against a live Nimbus — only the Rust engine's have; one
  `-Pengine=java` run pinned to zbox's Nimbus is owed.
