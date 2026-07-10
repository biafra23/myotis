# 07 — EL phase: Rust execution-layer implementation plan

> Companion to the [re-implementation spec](README.md). Docs [02](02-execution-networking.md)
> and [03](03-state-verification-and-evm.md) are the *wire-level specification* of the EL;
> [06](06-rust-phase-notes.md) is the *state of the Rust effort*; this file is the **execution
> plan** for building the EL in Rust — crate layout, dependency decisions, the conformance-corpus
> strategy, and the PR-by-PR breakdown with exit criteria. Update it as PRs land (mark each
> PR's status inline), the same way 06 is updated.

## Status (2026-07-06)

Plan written; no EL Rust code exists yet. The workspace (`rust/`) is CL-only: `myotis-bls`
(blst verify), `myotis-consensus` (sans-I/O SSZ/light-client verification), `myotis-net`
(tokio + libp2p + discv5, the CL sync loop), `myotis-engine` (hand-JNI shell, `ABI_VERSION 2`,
mainnet-only). There is **no** RLP codec (beyond a 10-line ENR field helper in
`myotis-net/src/discovery.rs`), no keccak-256, no raw secp256k1, no ECIES, no Kademlia, no
devp2p of any kind. Everything below is greenfield Rust with a golden-tested Java twin
(`networking/`, `node-core/`) to conform against.

## Scope

**In scope (three milestones):**

- **A — devp2p + verified state queries.** discv4, RLPx, eth/66–69, snap/1, the MPT proof
  verifier, the CL→EL anchor, and the verified account/storage/header operator queries behind
  the existing JNI seam. Exit: the CLAUDE.md integration gate passes with `-Pengine=rust`
  (delivered by EL-A7; EL-A8 is post-gate hardening inside A — DNS discovery, peer-cache
  persistence, maintainer, packaging — and milestone B may start in parallel with it).
- **B — the full `VerifiedReads` surface.** Blocks/txs/receipts, fees, `sendRawTransaction`
  + pending-nonce overlay, behind one generic JNI dispatch native.
- **C — local EVM + ENS.** revm over a SNAP state oracle, `call`/`estimateGas`, ABI subset,
  CCIP-Read via the `HttpGateway` port, ENS resolution.

**Out of scope** (same posture as the Java reference — doc 02 scope note, README §10):
serving/responder halves beyond empty snap/eth responses; `eth_getLogs` / `eth_subscribe`;
pooled-tx gossip and blob sidecars; EIP-4444 history fallbacks; Portal (dead); pre-Merge /
deep-historical accumulators (post-A follow-up, tracked in README §10). The JSON-RPC HTTP
server and IPC daemon remain **host** surfaces consuming `VerifiedReads` — they are not
reimplemented in Rust in this phase.

**Client/dialer-only** stays the rule: we dial, we never listen; inbound eth/snap requests get
empty responses so peers don't disconnect (doc 02 §9.11).

## Entry criteria & carried items

1. **CL persistence first (or in parallel).** Gap #1 of doc 06 — the sync-state snapshot +
   CL peer cache under `dataDir` — is in flight on the `rust/persistence` branch. It should
   merge before the first *live-network* EL exit criteria are exercised (EL-A3+), because
   catch-up variance from cold bootstraps makes live testing miserable. EL-A1/A2 (pure
   codecs + verifier) have no dependency on it and can start immediately.
2. **Re-surface the extraData-offset leniency decision** (doc 06, carried findings): if
   tightened, change the Java and Rust `ExecutionPayloadHeader` decoders in ONE PR with a
   malformed-offset corpus vector. The EL phase touches neither decoder, but any EL-phase
   security review should re-raise it.
3. Process conventions from doc 06 apply to every PR below: branch from up-to-date
   `rust-engine`, PR targets `rust-engine`, independent no-context review before opening,
   inline replies to every review comment, periodic merges of main INTO `rust-engine`.

## Recorded design decisions

1. **Hand-roll the devp2p protocol logic on small primitive crates** — not reth's protocol
   crates (`reth-ecies`/`reth-eth-wire`/`reth-discv4`). Rationale: the CL phase's pattern
   (hand-rolled SSZ + cross-language golden vectors) is proven; the Java twin plus doc 02 pin
   every load-bearing constant; reth's alloy dependency tree is heavy, fast-moving, and a
   binary-size / cargo-ndk risk for the mobile targets (README §7 mobile constraint,
   guidelines §9 — "guidelines" throughout this doc =
   [myotis-rust-engine-guidelines.md](../myotis-rust-engine-guidelines.md)). Small
   building-block crates ARE used (see dependency table).
2. **Hand-port the MPT proof verifier** from `core/trie` — not `alloy-trie`. Doc 03 §2:
   replicate Found/Absent/Invalid, embedded-node, and exclusion-proof semantics verbatim and
   pin them with a shared corpus. It is ~3 small files; the validation burden of a library
   would equal the port.
3. **EL networking lives in `myotis-net`** as an `el/` module tree, not a new crate. This
   mirrors the CL precedent (pure `codec.rs` beside tokio `reqresp.rs`): codecs and protocol
   state machines are pure functions/structs unit-testable without I/O; only the
   dialer/UDP-service layers touch tokio. Primitives + verification go in a NEW sans-I/O
   **`myotis-core`** crate (guidelines §2 layout).
4. **JNI stays hand-rolled + JSON** (doc 05 status note). Milestone A adds a handful of
   operator-query natives; milestone B deliberately routes the whole `VerifiedReads` surface
   through **one generic dispatch native** (`nativeVerifiedReadJson(handle, method,
   paramsJson)`) per guidelines §5 ("one RPC dispatch layer, many fronts") so the native
   surface stops growing per-method.
5. **Fork id stays pinned per network** (as Java does; README §6). Implementing real EIP-2124
   CRC32 with `forkNext` is a forward-compat TODO noted for the phase that adds the rewrite
   tooling (doc 06 gap #3 covers the same "pinned constant needs tooling" family).

## Crate layout after the EL phase

```
myotis-bls         (unchanged)
myotis-core   NEW  sans-I/O primitives + EL verification:
                   keccak256, RLP, NodeKey (k256), BlockHeader, Enr, fork-id,
                   hex-prefix, MPT proof verifier, ordered trie root, logs bloom
myotis-consensus   (unchanged; stays permanently sans-I/O; gains nothing EL)
myotis-net         + el/ module tree (discv4, dns, ecies, handshake, frame, eth, snap, peers)
                   + exec_anchor (CL→EL bridge fed by sync.rs)
myotis-engine      + EL wiring: operator-query natives (A), generic reads dispatch (B)
myotis-evm    NEW  (milestone C) revm behind a StateOracle trait, sans-I/O
```

Dependency direction stays one-way: `engine → net → {consensus → bls, core}` (core depends on
nothing in-workspace). `myotis-core` joins the wasm32 canary (`cargoCheckWasm`) — it must never
grow a tokio/socket/fs/clock dependency; entropy via `getrandom` only (guidelines §1).

### New dependencies (exact-pinned like the rest of the workspace)

| Crate | For | Notes (mobile gate) |
|---|---|---|
| `sha3` (RustCrypto) | keccak-256 | pure Rust, wasm/ndk-clean |
| `k256` | secp256k1 sign-prehashed / recover / ECDH | pure Rust; replaces nothing (libp2p/discv5 keep their own wrappers) |
| `alloy-rlp` | RLP encode/decode | small, no alloy tree; if its strictness fights the tolerant decodes doc 02 requires (unknown trailing header fields, raw-item capture for re-encoding), fall back to a thin hand codec — decide inside EL-A1, corpus stays identical either way |
| `aes`, `ctr`, `cipher`, `hmac` | ECIES + RLPx framing | RustCrypto, pure Rust |
| `getrandom` / `rand_core` | nonces, ephemeral keys | already the workspace entropy rule |
| `hickory-resolver` | EIP-1459 DNS TXT (EL-A8) | supports explicit server IPs + TCP (the Android/SLIRP fallback path doc 02 §4 needs) |
| `revm` | milestone C EVM | the one big dep; gated to `myotis-evm`, never in core/net |

Banned as before: `ring`, full `alloy`, anything with mandatory platform asm or a C build that
breaks cargo-ndk/wasm32. `snap` (snappy) and `sha2` are already in-tree.

## Conformance corpus strategy

Same discipline as `rust/testdata/lc/`: **one set of vector files on disk, replayed by a test
on BOTH sides** (Java generates + asserts; Rust asserts). New tree: `rust/testdata/el/…`.

| Corpus | Contents | Java twin that pins it |
|---|---|---|
| `el/rlp/` | header vectors (pre-1559, 1559, 4895, 4844, 4788, 7685 read-and-discard; unknown-trailing-field tolerance; canonical re-encode → hash), typed-tx passthrough | `BlockHeader` tests |
| `el/discv4/` | ping/pong/findnode/neighbors wire bytes with fixed keys (encode match + sig recover + hash check), truncation/short-packet negatives | `Packet` tests |
| `el/rlpx/` | fixed static+ephemeral keys+nonces → auth/ack wire bytes, derived `aes/mac` secrets, first frames each direction; EIP-8 padding tolerance | seeded from `HandshakeRoundTripTest` |
| `el/eth/` | Hello, Status 67/68 + 69 shapes, forkid/genesis gate negatives, GetBlockHeaders/Bodies/Receipts round-trips, eth/69 bloomless receipt → recomputed bloom → canonical receipt bytes | `StatusMessage`/message tests |
| `el/mpt/` | account + storage proofs: Found / Absent (exclusion) / Invalid (missing node, wrong arity, size mismatch) / embedded sub-32-byte nodes; ordered-trie roots for tx/receipt lists | `MerklePatriciaProofVerifier` tests + a new Java conformance test replaying the same files |
| `el/snap/` | GetAccountRange/AccountRange, GetStorageRanges/StorageRanges, GetByteCodes/ByteCodes wire vectors incl. slim-body defaults and double-RLP-wrapped slot values | snap message tests |

Live capture tooling: a `-Peldump=<dir>` daemon flag (analogous to `-Plcdump`) capturing real
mainnet proofs/messages for the mpt/snap corpora. Carried caveat from the LC corpus applies
here too: negatives don't yet pin the *rejection reason*, only the verdict — same open item.

## The CL→EL anchor (`ExecAnchor`)

Rust twin of Java's `BeaconSyncState` (the single hand-off object, consensus → execution):

- Fed by the existing `myotis-net/src/sync.rs` loop, which already decodes
  `ExecutionPayloadHeader` on every verified update: on finality → set finalized
  `{block_number, block_hash, state_root, finalized_slot}`; on optimistic/attested → the
  optimistic triple; every BLS-verified attested header additionally appends to a bounded
  **known-state-roots window** (cap 8192, matching `MAX_HEADER_CHAIN_GAP`).
- Exposed as shared state + `tokio::sync::watch` so EL queries can (a) fast-path
  `stateRootMatch` against the window, (b) anchor `headerChain` walks at the attested block
  hash, exactly like `BeaconSyncState.findStateRoot()` / `getExecutionBlockHash()`.
- Lives in `myotis-net` (it is I/O-adjacent state, not verification logic); `myotis-consensus`
  stays untouched.

## JNI surface growth

All natives remain `Java_io_myotis_engines_RustEngineNative_*`, panic-free by construction
(workspace `panic="abort"`), compound values as JSON golden-pinned on both sides, `ABI_VERSION`
bumped on every surface change.

- **Milestone A** (flat operator queries, mirroring `ChainHandle`):
  `nativeRequestAccountJson(handle, addressHex)`, `nativeGetStorageProofJson(handle, addrHex,
  slot, holderHex?)`, `nativeGetHeadersJson(handle, start, count)`, `nativeDialPeer(handle,
  host, port, pubkeyHex)`, `nativeSetTargetSnapPeers(handle, n)`, `nativeClearPeerState(handle)`,
  and `nativeStatusJson` extended with EL fields (discovered/connected/ready/snap peer counts,
  per-peer rows). JSON schemas pinned by golden files under `rust/testdata/` + Java golden tests
  (the `networks_catalog.json` pattern).
- **Milestone B**: `nativeVerifiedReadJson(handle, method, paramsJson)` — one dispatch native
  for the whole `VerifiedReads` contract, preserving the tri-state convention (JSON / literal
  `"null"` = verified not-found / `null` = no verified answer).
- **Token conformance** (doc 05 §5): the exact `verifyMethod`/`failReason` strings —
  `stateRootMatch`, `headerChain`, `beaconNotSynced`, `headerChainGapTooLarge`,
  `preMergeBlock`, … — must match; the daemon's golden JSON tests and the integration greps
  key on them.
- **Validate every native's inputs at the JNI boundary** before any allocation or
  arithmetic: numeric parameters are clamped to protocol-sane maxima (e.g.
  `nativeGetHeadersJson`'s `count` capped at the 1024-headers-per-request batch limit the
  Java side already uses; negative/overflowing values → error JSON, never
  `Vec::with_capacity` from raw input — `usize` is 32-bit on some Android targets), and
  string parameters length/format-checked. Same family as the panic-free rule: a hostile or
  buggy host argument must produce an `error` field, not an abort.

## Milestone A — devp2p + verified state queries (PR-by-PR)

Every PR: cut from up-to-date `rust-engine`, no-context review before opening, target
`rust-engine`. "Live" tests are `#[ignore]` (never CI-gating — peer availability is weather).

### EL-A1 — `myotis-core`: primitives

- Crate skeleton + workspace/Gradle/wasm-canary wiring. keccak256; RLP layer (decide
  `alloy-rlp` vs thin hand codec here — the requirement is tolerant list-remainder decoding
  plus raw-item capture for canonical re-encode); `NodeKey` (load-or-generate 32-byte secret,
  64-byte uncompressed pubkey sans `0x04`, `nodeId = keccak256(pubkey)`, sign-prehashed with
  recid, recover, ECDH x-coordinate); `BlockHeader` (doc 02 §1.2 field set, optional trailing
  fields by list remainder, `hash = keccak256(rlp)`); `Enr` (EIP-778 decode, base64url,
  compressed→uncompressed key, `eth`/`eth2` field re-parse, libp2p-multiaddr/PeerId helpers can
  wait for need); pinned fork-id constants per network.
- Tests: `el/rlp/` + ENR vectors, key/signing vectors (fixed secrets → sigs → recover).
- Exit: corpus green on both languages; `cargoCheckWasm` includes `myotis-core`.

### EL-A2 — MPT verifier + trie roots + bloom

- Hand-port `MerklePatriciaProofVerifier` + `HexPrefix` (+ the RLP-item walker it needs):
  node map by `keccak256(node)`, branch/leaf/extension descent, embedded sub-32-byte nodes,
  `Found(value) | Absent | Invalid(reason)`; `EMPTY_TRIE_ROOT`; account-leaf and storage-leaf
  decoding (leaf-only `storageRoot`/`codeHash` — README §11.8). `OrderedTrieRoot`
  (`key = RLP(index)` un-hashed) for tx/receipt/withdrawal lists. Logs-bloom recompute
  (M3:2048) for eth/69 receipt re-canonicalization.
- `-Peldump` capture tooling on the Java side + the `el/mpt/` corpus + a Java conformance test
  replaying the same files.
- Exit: corpus (incl. all negative classes) replays identically Java↔Rust.

### EL-A3 — discv4

- Pure: packet codec (`hash ‖ sig ‖ type ‖ data`, doc 02 §2.1 — sign `keccak256(type‖data)`
  directly, no double hash), Kademlia table (256 buckets, K=16, XOR distance, single lock),
  per-IP rate limiter (5 pings/10 s), pending-pings bond tracking.
- I/O (`myotis-net`): tokio UDP service — **fixed 4096-byte receive buffer + 1 MB SO_RCVBUF**
  (doc 02 §9.10, the Android NEIGHBORS-truncation trap), 15 s refresh loop (empty table →
  re-ping bootnodes; else FindNode-self to bootnodes + random-target to ≤10 peers), Ping
  responder + tcpPort recording, discovered-peer callback.
- Exit: `el/discv4/` vectors green both sides; live `#[ignore]`: bond with a mainnet bootnode
  and receive non-empty NEIGHBORS.

### EL-A4 — RLPx transport

- Pure: `EciesCodec` (**NIST concat-KDF `SHA256(counter‖Z)`** — doc 02 §9.2 — AES-128-CTR,
  `HMAC-SHA256(SHA256(macKey), IV‖ct‖aad)` with AAD always fed); `AuthHandshake` (EIP-8:
  sign the token `staticShared XOR nonce` **directly**, random tail padding, the 2-byte size
  prefix is the ECIES AAD and the full wire bytes seed the MAC chains); `SessionSecrets`
  (keccak ladder); `FrameCodec` (AES-256-CTR zero-IV continuous keystream per direction,
  separate AES-ECB MAC cipher keyed `macSecret`, keccak MAC chains with non-destructive
  digest, snappy-except-Hello with raw fallback, 10 MB body cap). All pure byte-in/byte-out —
  unit-testable without sockets.
- I/O: TCP dialer + per-connection state machine `HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED`,
  p2p control messages (Hello/Disconnect/Ping/Pong), ready event upward.
- Exit: `el/rlpx/` vectors green both sides; Rust↔Rust in-memory round-trip; live
  `#[ignore]`: dial a mainnet peer to FRAMED + receive its Hello.

### EL-A5 — eth/66–69 handshake + block-data requests

- Hello capability negotiation (advertise eth/66–69 + snap/1, highest-common, floor 66);
  Status both shapes (67/68 with TD-empty; 69 with earliest/latest/latestHash) and the
  compatibility gate (networkId + genesisHash; our forkid must be correct — peers validate
  it); 30 s handshake timeout; `AWAITING_HELLO → AWAITING_STATUS → READY`.
- Request/response correlation (atomic req-id, per-type pending maps, per-request timeout,
  fail-all on disconnect); `GetBlockHeaders/Bodies/Receipts` with canonical re-encode →
  hash on headers, raw consensus receipt byte capture, eth/69 bloomless → recompute + 
  re-canonicalize; empty responders for all inbound eth requests; NewPooledTransactionHashes
  observed (gossip echo hook for milestone B), other gossip ignored.
- Exit: `el/eth/` vectors green both sides; live `#[ignore]`: negotiate with a mainnet peer,
  fetch a 1024-header batch, verify the parent-hash chain and per-header keccak.

### EL-A6 — snap/1

- Message codecs with the **dynamic base offset** (0x10 + eth-length: 17→0x21 for eth/67-68,
  18→0x22 for eth/69); `GetAccountRange`/`GetStorageRanges`/`GetByteCodes` requests with the
  **full `[origin, 0xff…ff]` range + small responseBytes** pattern (complete boundary proof,
  tiny discarded page — doc 02 §7.3); slim-body defaults; double-RLP-wrapped slot values;
  `GetTrieNodes` wired at the codec layer but unused by the oracle (doc 02 §7).
- Fresh per-peer root flow: the caller supplies the `stateRoot`; verify-on-fetch through the
  EL-A2 verifier (account vs state root; storage vs the proven `storageRoot`; bytecode by
  `keccak256 == codeHash`).
- Exit: `el/snap/` vectors green both sides; live `#[ignore]`: verified account fetch for a
  known mainnet account against a fresh root.
- **DEFERRED to EL-A7** (the managed-peer connection layer — the single-shot request model in
  A6 has no place for them): the stale-head floor (`minSensibleHeadBlock`); peer rotation on
  `Invalid`/timeout + root-unavailable marking; and answering inbound snap `Get*` (and eth
  `Get*`) with empty responses (needs a background read loop). The empty-response ENCODERS
  ship in A6; A7 wires them.

> **STATUS (delivered by EL-A6, PR #NNN):** the pure codecs, verify-on-fetch, and the
> single-shot `EthSession::snap_get_account/storage/bytecode` are done and cross-language
> conformance-pinned; a live run fetched a verified mainnet account. The deferred items above
> move to EL-A7.

### EL-A7 — orchestration, verified queries, JNI (the gate PR)

- Dial manager in `myotis-net/el/peers.rs`: attempted set, backoff map (10 min incompatible /
  30 s transient), session nodeId blacklist, snap-first dial rank (proven → snap-capable →
  denied → plain), static-enode dials (Gnosis-style) and cached-peer dials wired for when the
  cache lands (EL-A8).
- **Carried from EL-A6** (the managed-peer connection layer): a background per-connection read
  loop that answers inbound eth/snap `Get*` with empty responses (encoders shipped in A5/A6),
  the stale-head floor (`minSensibleHeadBlock`) before a snap query, and peer rotation on
  `Invalid`/timeout + root-unavailable marking across the connector's active peers.
- `ExecAnchor` (above) fed from `sync.rs`; verified query ladders ported from
  `VerifiedAccountQuery`/`VerifiedStorageQuery`/`HeaderQuery`: proof-vs-peer-root →
  `stateRootMatch` (window lookup) → `headerChain` (walk `[finalized … peer head]`, every
  link `keccak256(RLP)`-pinned, ends matched to the beacon anchor, gap ≤ 8192,
  `headerChainGapTooLarge`/`preMergeBlock`/`beaconNotSynced` tokens exact).
- JNI natives (list above) + `RustChainHandle`/`RustEngineNative` plumbing on the Java side +
  status JSON extension; goldens for every new JSON shape; `ABI_VERSION` bump.
- Exit — **the integration gate, on mainnet with `-Pengine=rust`**:
  `./gradlew :app:run -Pargs=beacon-status` → `"state":"SYNCED"`, then the CLAUDE.md
  `get-account` / `get-storage` commands return `"verifyMethod":"headerChain"` (and
  `stateRootMatch` when the fast path hits).

### EL-A8 — DNS discovery, peer-cache persistence, maintainer, packaging

- EIP-1459: `enrtree://` root TXT **signature verification against the URL key** (the trust
  step), branch walk with caps (512 nodes / depth 16 / per-lookup + overall deadlines),
  `hickory-resolver` with explicit server IPs (the `DnsServers` port semantics) and TCP
  fallback path; fork-filter the pool; rate-capped refresh.
- **Engine-owned EL peer-cache persistence under `dataDir`** (doc 05 §4 simplification — the
  Rust engine does NOT get an `EnginePeerCache` port): host/port/pubkey/snap + snap-quality
  CONFIRMED/UNKNOWN/DENIED (3 strikes → DENIED, never evicted), loaded into the dial rank at
  start. Write path mirrors the Java cache's discipline (doc 04 §6): in-memory map is
  authoritative, disk writes are batched/coalesced through a single async writer task —
  never a synchronous per-item file rewrite on the dial/serve path. Coordinate the on-disk
  layout with the `rust/persistence` branch's dataDir conventions.
- Snap-peer maintainer loop (10 s, `activeSnapPeers >= target`, doc 04 §1.1 tunables) wired
  to `nativeSetTargetSnapPeers`; DNS pool as its discv4-independent dial source.
- `build-android.sh` / jniLibs refresh; `sync_bench.sh` re-run now that `-Pengine=rust`
  carries an EL (updates [benchmarks.md](benchmarks.md) — the footprint scope-caveat from the
  v1 numbers finally closes).
- Exit: with an empty discv4 table and DNS as the only discovery source, the daemon still
  reaches the A7 gate (the NAT'd/mobile dial path works); a restart re-dials cached snap
  peers before any discovery round-trip; refreshed benchmark numbers recorded in
  [benchmarks.md](benchmarks.md).

## Milestone B — full `VerifiedReads` (coarser; ~3–4 PRs)

Spec: README §5.3, doc 04 §2. Highlights per PR-sized chunk:

1. **Anchored head context + blocks.** Head context built once, reused ~12 s;
   `getBlockByNumber/Hash` JSON from beacon-anchored headers (+bodies where needed);
   `headBlockNumber` = beacon optimistic head; `syncState` mapping.
2. **Tx/receipt lookup + fees.** Incremental scan over the recent beacon-anchored window vs
   `transactionsRoot`/`receiptsRoot` (eth/69 bloomless handled by EL-A2's recompute);
   `gasPrice`/`maxPriorityFeePerGas`/`feeHistory` from verified headers + bodies + receipts
   (gas-used-weighted percentiles).
3. **`sendRawTransaction` + pending overlay.** Gossip raw bytes to all READY peers, return
   `keccak256(rawTx)`, cache own-tx bytes (shows pending until mined), rebroadcast until the
   gossip echo (the EL-A5 hash-observation hook); pending-nonce overlay — only-raises,
   TTL-bounded, the single un-proven value (README §2).
4. **The generic dispatch native** + tri-state null convention end-to-end + conformance vs the
   Java `RpcRouterTest` wire shapes, so the JSON-RPC host serves identically from either engine.

Milestone-B gate: the JSON-RPC server backed by the Rust engine returns wire-identical
responses to the Java engine for the full verified method set (`RpcRouterTest`-shape
conformance run against both), and a MetaMask-style read burst (blocks + balances + fees)
completes from verified data on `-Pengine=rust`.

## Milestone C — EVM + ENS (coarser; ~4–5 PRs)

Spec: doc 03 §§3–7, doc 04 §3. New crate `myotis-evm` (sans-I/O; revm gated here).

1. **Oracle + revm adapter.** `SnapStateOracle` trait over the EL-A6 fetch path; revm
   `Database` adapter; three cache tiers (per-call view / in-flight dedup / cross-call
   `StateProofCache` keyed by stateRoot — cryptographic facts, safe to share); `BytecodeCache`
   forever-valid; sync↔async bridge off I/O threads.
   - **Landed (EL-C-1).** `myotis-evm` crate: sync `SnapStateOracle` trait (`fetch_account`/
     `fetch_storage`/`fetch_bytecode`) + `OracleAccount` + closed `OracleError`
     (`StateUnavailable`/`BytecodeUnavailable`/`InvalidProof`/`BlockHashUnsupported`) +
     `FixtureSnapStateOracle`; `OracleDatabase` implementing revm `DatabaseRef` (three-tier
     read: per-call view → cross-call `StateProofCache` → oracle); `StateProofCache`
     (Noop + bounded-LRU `InMemory`) and `BytecodeCache` (Noop + forever `InMemory`), both
     SPIs. Validated by a real revm `transact` of an SLOAD-return contract through the adapter.
     Decisions: **revm `=41.0.0`, `default-features=false, features=["std"]`** — drops the
     C precompile backends (c-kzg/libsecp256k1/blst) for revm's pure-Rust fallbacks, so
     `cargo tree -p myotis-evm` COMPILES only k256 for crypto (`cargo tree -i c-kzg` /
     `-i secp256k1-sys` print "nothing to print" — no C toolchain invoked, cargo-ndk/
     mobile-clean). `c-kzg`/`secp256k1-sys` remain as unbuilt *entries* in the workspace
     `Cargo.lock` (optional deps of `revm-precompile` that Cargo pins but our features never
     enable). revm's 1.91 MSRV is met by the workspace `stable` toolchain. The oracle trait is **synchronous** (the
     async→sync bridge belongs in the I/O impl that wraps `ElReader`, not this sans-I/O
     crate); the **in-flight-dedup** tier is deferred to the async prefetch slice (a single
     synchronous `transact` reads serially, so the per-call view cache already dedups). Not
     on the wasm32 canary (revm pulls `std`). *Carried to EL-C-2:* the latest spec caps per-tx
     gas at 2²⁴ (EIP-7825), so the 30 M `eth_call` ceiling needs the fork/`CfgEnv` selection
     that C-2 owns; and precompile completeness under the pure-Rust backends (ecrecover via
     k256, KZG via kzg-rs) must be verified when the EVM actually executes.
2. **View calls + fork table.** Frame setup verbatim (zero-sender anonymous vs sender/value
   `eth_call` overload, `isStatic`, 30 M gas, EIP-7702 one-hop, BLOCKHASH unsupported →
   fail fast); mainnet fork schedule (throws below London; Shanghai keeps Istanbul
   precompiles) mapped to revm `SpecId`.
   - **Landed (EL-C-2).** `fork::spec_for(block_number, timestamp) -> SpecId` — the
     mainnet cascade verbatim (LONDON_BLOCK/PARIS_BLOCK/SHANGHAI_TIME/CANCUN_TIME/
     PRAGUE_TIME; timestamp checked before block number; `EvmError::ForkTooOld` below
     London). revm applies the correct precompile set per `SpecId`, so the "Shanghai keeps
     Istanbul precompiles" nuance needs no special handling (revm's `SHANGHAI` predates the
     Cancun KZG precompile). `BlockContext` (all fields from the verified header) →
     `BlockEnv` (post-merge `DIFFICULTY` reads `prevrandao`, so `difficulty` is 0 — its
     true post-merge value; pre-merge difficulty and Cancun+ blob base fee aren't modelled,
     as those blocks aren't servable). `EvmExecutor`
     with `call_view` (from-less zero sender) / `call_view_from` (explicit sender+value for
     `msg.sender`-gated contracts), a fresh per-call `OracleDatabase` over the shared
     caches, and `EvmError` (Reverted{data} / OutOfGas / Halted / ForkTooOld / Oracle /
     Transaction). Resolves the C-1 carry: **30 M gas** works via `CfgEnv.tx_gas_limit_cap =
     Some(30M)` (overrides the EIP-7825 2²⁴ spec cap); the eth_call relaxations use revm's
     pure-config `optional_*` features (`optional_balance_check`/`optional_block_gas_limit`/
     `optional_eip3607`/`optional_no_base_fee` — still zero C crates, `cargo tree -i c-kzg`
     prints nothing). EIP-7702 one-hop is handled by revm (the oracle serves the designator
     as code). Tested with a fixture-backed `eth_call`: Cancun SLOAD-return uint256 (mirrors
     the Java `EvmFactoryTest`), `msg.sender`/`msg.value` pass-through, revert-data surfacing,
     out-of-gas, pre-London rejection; plus fork-boundary unit tests. *Not yet wired to the
     host* — the production `SnapStateOracle` over `ElReader` (the async→sync bridge) and the
     JNI/Java `eth_call` routing land in a following slice, which lights the live MetaMask path.
3. **Prefetch + dispatch fairness.** Sentinel-on-miss convergence loop (cap 4, result only
   from a fully cache-hit run, fail closed); batch coalescing (64 path-sets/request,
   independent per-item verification, whole-chunk rotation); semaphore-bounded waves; lanes +
   snap fan-out gate (half the live snap peers for the heavy lane).
4. **estimateGas** (intrinsic + metered, `ceil(total·1.15)`, no number for reverts, plain
   transfer short-circuit to 21000) + the ABI subset (hand-rolled, doc 03 §5 hardening).
5. **CCIP-Read + ENS.** `OffchainLookup` parse/serial gateway iteration/HttpError detection
   via the `HttpGateway` port (blocking, wrapped `spawn_blocking`); callback re-entry capped
   at 1; ENS namehash/DNS-encode/ENSIP-10 discovery + record calls + reverse with mandatory
   forward-verification. Mainnet+sepolia only (`hasEns` gate).
   - **Landed (EL-C-5-1): ENS forward resolution core** (`myotis-evm::ens`, sans-I/O). `namehash`
     (ENSIP-1, lowercase-only — the same UTS-46 gap as Java) + `dns_encode` (ENSIP-10); a
     hand-rolled ABI subset (`selector`, `bytes32`/`bytes4`/`address`/`bool`/dynamic-`bytes`
     encode+decode, all bounds-checked, `MAX_INDEX = 64 MiB`); `resolve_address` — the registry
     resolver-walk (registry `0x0000…2e1e`, up to the root), `supportsInterface(0x9061b923)`
     wildcard detection, and `addr(bytes32)` directly (legacy exact) or wrapped in
     `resolve(bytes,bytes)` (ENSIP-10) — every step an `eth_call` through the existing executor,
     abstracted behind an `EthCaller` trait (`ExecutorCaller` for the real path; mocked in tests).
     `Ok(None)` = no record (absent / zero-address / non-wildcard ancestor / — for now — offchain);
     an `OffchainLookup` revert reads as "no record" until CCIP lands. Unit-tested with a scripted
     mock (legacy, wildcard, no-resolver, ancestor-can't-answer-subname, zero-address) + canonical
     namehash/DNS vectors. *Deferred:* reverse + forward-verify (C-5-2), CCIP-Read offchain
     (C-5-3, HTTP via an injected `CcipGateway` port — no Rust HTTP dep), and the JNI/Java `EnsApi`
     wiring (C-5-1b, replacing `RustChainHandle.ens() { return null; }`).

Milestone-C gate: on a SYNCED mainnet daemon with `-Pengine=rust`, a real ERC-20
`balanceOf` `eth_call`, an `estimateGas` for a token transfer, and a `resolve-ens` of a
known name (including one CCIP-Read/offchain name) all return verified results matching the
Java engine's.

## Multichain (post-Milestone-C)

- **MC-1 (landed): sepolia hosted by the Rust engine.** `ChainConfig::sepolia()` /
  `ElConfig::sepolia()` mirror the Java `NetworkConfig.SEPOLIA` (PR #192's corrected
  values: Fulu `0x90000075`, BPO2 epoch 275712/21, checkpoint slot 10657440; EL fork-id
  `0x268956b6`, 5 bootnodes, port 30305). `ChainConfig` gained `chain_id`, threaded
  through eth_call/estimateGas/resolve-ens (no hardcoded network downstream). The EVM
  fork table is chain-aware (`spec_for(chain_id, block, ts)` — mainnet + sepolia tables;
  unknown chain fails closed with `UnsupportedChain`); the executor's mainnet-only guard
  is gone. Host `config_for`/`create` route sepolia; the EL peer cache is per-network
  (`peers-sepolia.cache`); the Java `RustMyotisEngine` "mainnet only" gate is replaced by
  the native `UNSUPPORTED_NETWORK` contract + catalog-driven rpc port/chain id. Parity
  tests pin the sepolia CL config incl. the cross-language fork digest (`0x74d01459`,
  computed identically by `NetworkConfig.SEPOLIA.currentForkDigest()` and Rust
  `fork_digest_bpo`). Sepolia checkpoint refreshes (`refreshSepoliaCheckpoint`) must be
  hand-mirrored into `ChainConfig::sepolia()` like mainnet's, until the plan-PR7 task
  rewrite covers the Rust constants.
- **MC-2 (landed): gnosis hosted by the Rust engine.** `ChainConfig::gnosis()` /
  `ElConfig::gnosis()` mirror the Java `NetworkConfig.GNOSIS` (own beacon chain: 5s slots,
  16-slot epochs, gvr `f5dcb556…`, Fulu fork `0x06000064` / prior Electra `0x05000064`,
  blob params 1337856/2, checkpoint slot 28516336; EL network_id 100, genesis `4f1dd231…`,
  fork-id `0xcfca387c`, 6 bootnodes, port 30304). The sync-committee period stays 8192
  slots — gnosis uses `EPOCHS_PER_SYNC_COMMITTEE_PERIOD=512`, so 512×16 = 8192, numerically
  identical to mainnet's 256×32 (checkpoint slot 28516336 → period 3480). The per-network
  `min_suggested_tip_wei` floor became an `ElConfig`/`ElReader` field (gnosis 0.001 gwei =
  1_000_000; mainnet/sepolia keep 0.1 gwei). EVM fork table gained the gnosis cascade
  (Shanghai `0x64c8edbc` / Cancun `0x65ef4dbc` / Prague `0x68122dbc`, all timestamp-gated,
  fail-closed below Shanghai) pinned to the nethermind `gnosis.json` hex. Gnosis has no ENS:
  catalog `has_ens=false` threads through `RustMyotisEngine.create` → `RustChainHandle` so
  `ens()` returns null. Parity tests pin the CL config incl. both fork digests (current Fulu+BPO
  `0x3237dab6`, prior Electra `0x7d5aab40`). Validated live: the gnosis checkpoint bootstrap
  discovered a CL peer (fork-digest correct) and verified against the genesis validators root
  (`period=3480`, state `CATCHING_UP`); full SYNCED is peer-supply-bound on the dev host, as with
  mainnet. `refreshGnosisCheckpoint` is hand-mirrored into `ChainConfig::gnosis()` like the others.
- **Known gap (both engines, deliberately mirrored): fork tables cap at PRAGUE** even
  though mainnet + sepolia have activated Osaka/Fusaka (sepolia `osakaTime` 1760427360,
  go-ethereum `SepoliaChainConfig`). Adding OSAKA is a cross-engine follow-up so the two
  engines never diverge on spec selection.

## Cross-cutting rules & risks

- **Panic-free natives** (workspace `panic="abort"` makes `catch_unwind` a no-op) — checked
  reads and `Err` returns everywhere untrusted bytes are parsed; the EL parses nothing BUT
  untrusted bytes.
- **Exact-pin every new dependency**; run `cargo ndk` + wasm canary in the same PR that adds
  one. CI `rust.yml` (doc 06 polish item #5) becomes worth doing at EL-A1 — the EL phase
  multiplies the places a regression can hide.
- **Mainnet-only until the A-gate passes**, then wire gnosis/sepolia in `catalog.rs` /
  `config_for` (doc 06 gap #3 — includes the checkpoint-constant duplication and static
  Gnosis enodes; Gnosis has no DNS tree, direct enode dials only).
- **Live-test discipline**: everything touching real peers is `#[ignore]`; exit criteria are
  run manually under fresh peer conditions (the benchmark lesson — peer starvation looks like
  engine slowness).
- **eth/69 heterogeneity**: a growing share of mainnet peers negotiate 69 — both Status
  shapes, the shifted snap base, and bloomless receipts are first-class from EL-A5/A6, not
  retrofits.
- **Security invariants**: README §11 is the checklist; items 8–12 and 15 are the EL-phase
  ones to turn into corpus vectors, not just code.

## Doc upkeep

Mark PR status inline here as things land (the way 06 tracks phase 1), and close the loop in
[06-rust-phase-notes.md](06-rust-phase-notes.md) when the milestone-A gate passes: that file's
"EL-phase entry" section defers to this plan.
