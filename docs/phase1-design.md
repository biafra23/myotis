# Phase 1 — SNAP-backed state oracle

Phase 0 proved that Besu's EVM runs end-to-end against a `SnapStateOracle`.
Phase 1 replaces the fixture oracle with a real one that fetches state on
demand from devp2p `snap/1` peers and verifies every response against the
trusted `stateRoot`.

> **Scope:** correctness, not speed. One synchronous round trip per SLOAD
> is acceptable in Phase 1 (1–5 s per call). Phase 2 adds prefetching.

## Acceptance criteria (from the original plan)

- `DefaultEvmExecutor.callView` works end-to-end against mainnet.
- Three integration tests passing against a known-good `stateRoot` from a
  recent block:
  - USDC `balanceOf(vitalik.eth)`
  - DAI `balanceOf(vitalik.eth)`
  - ENS Public Resolver `addr(namehash("vitalik.eth"))`
- Latency measurement recorded.

## Work breakdown

The work spans `:networking` (protocol), `:core` or a new utility (proof
verifier), and `:myotis-evm` (oracle wiring + integration tests). Sequencing
is bottom-up so each piece is testable on its own before the network round
trip is involved.

### 1 — SNAP wire types (this commit)

Phase 0 of the SNAP work shipped `GetAccountRange` / `AccountRange` /
`GetStorageRanges` / `StorageRanges` because that's what range-style sync
needs. For per-account lookups Phase 1 needs the lower-bandwidth pair:

| Code | Name             | Purpose |
|------|------------------|---------|
| 0x26 | `GetTrieNodes`   | Request specific trie nodes by `(account, path)` pairs. |
| 0x27 | `TrieNodes`      | Response with the requested nodes. |
| 0x24 | `GetByteCodes`   | Request bytecode by code hash. |
| 0x25 | `ByteCodes`      | Response with concatenated bytecodes. |

Encoders / decoders + RLP roundtrip tests. No protocol wiring yet.

### 2 — Proof verifier (done)

Goal: given a `stateRoot`, a key (account hash or storage slot hash), an
expected value, and a Merkle-Patricia-Trie proof, decide whether the proof
verifies.

Decision: **hand-rolled** in `:core` at
`com.jaeckel.ethp2p.core.trie.MerklePatriciaProofVerifier`. The catalog
entry for `io.consensys.tuweni:tuweni-merkle-trie:2.7.2` was aspirational
— that artifact does not exist in any version of ConsenSys Tuweni we can
resolve, and the alternative would be downgrading to Apache Tuweni 2.4.x
(unmaintained) or pulling in a heavier MPT library. The verifier is ~150
lines of straightforward Yellow-Paper-Appendix-D code.

Components:
- `HexPrefix.java` — compact path codec (4-flag header + nibble pack).
- `RlpItems.java` — splits an RLP list into raw child item bytes (Tuweni's
  `RLPReader` is callback-based and doesn't expose embedded children as
  raw RLP, which we need for in-line trie nodes).
- `MerklePatriciaProofVerifier.java` — descend from a trusted root through
  branch / extension / leaf nodes, supporting both 32-byte hashed and
  embedded children, returning `Found(value)` / `Absent` / `Invalid(reason)`.

Tests cover single-leaf inclusion, exclusion via different key, empty trie,
extension+branch+two-leaf inclusion, exclusion at the branch level, exclusion
above the extension, embedded sub-32-byte children, tampered-node detection,
and missing-node detection. Hand-built tries (programmatic RLP + keccak256)
rather than external fixtures so the tests are reproducible and the
correctness pattern is visible in the test source.

### 3 — SNAP protocol client (done)

`:networking` already negotiated `snap/1` in HELLO and had request/response
plumbing for `GetAccountRange` / `GetStorageRanges` (range-style sync).
Phase 1 commit 3 extends `EthHandler` with the lower-bandwidth pair:

- `requestByteCodesAsync(hashes)` — issues `GetByteCodes`, returns a
  `CompletableFuture<ByteCodesMessage.DecodeResult>` keyed by request id;
  10-second timeout.
- `requestTrieNodesAsync(stateRoot, paths)` — issues `GetTrieNodes`,
  returns a `CompletableFuture<TrieNodesMessage.DecodeResult>`; 10-second
  timeout.
- Inbound dispatch in `channelRead` routes the four new message codes
  (0x25 GetByteCodes / 0x26 ByteCodes / 0x27 GetTrieNodes / 0x28 TrieNodes
  under eth/68's offset; auto-shifted for eth/69) to handlers that either
  complete the matching pending future or respond with empty when serving.
- Wallet-side serving is intentionally empty — we ship `encodeEmpty(reqId)`
  responses to incoming `GetByteCodes` / `GetTrieNodes` so peers don't time
  out, mirroring the existing `GetAccountRange` / `GetStorageRanges`
  policy.

A dedicated `SnapHandler` class is intentionally not extracted: snap/1
shares the same RLPx connection and `ChannelHandlerContext` as eth/68, and
splitting them now would require a parallel multiplexer with no immediate
benefit. A future commit may extract it once the surface is large enough
to justify the restructure.

Out of scope for commit 3 (deferred to integration testing in commit 5):
- Per-peer rate limiting (the existing eth/snap path doesn't have it
  either; defer until we observe a peer that needs it).
- Proof-verification-failure handling. The verifier lives in `:core`
  (commit 2); the oracle in `:myotis-evm` (commit 4) is what owns the
  peer-score-decrement / retry logic since that's an EVM-execution
  concern, not a wire concern.

### 4 — `SnapBackedStateOracle` (done)

Implements `io.myotis.evm.world.SnapStateOracle` against a `SnapPeer`
abstraction defined in the same package. The peer interface is intentionally
minimal — `getTrieNodes(stateRoot, paths)` and `getByteCodes(hashes)`,
returning raw bytes — so `:myotis-evm` can stay decoupled from
`:networking`. The wallet integration plugs in an `EthHandler`-backed
implementation when constructing the oracle.

For each call:

1. `fetchAccount` — keccak256(address) → account-only path set →
   `getTrieNodes` → MPT verifier against the world stateRoot → decode
   `[nonce, balance, storageRoot, codeHash]` from the leaf value. The
   internal helper also captures `storageRoot` for downstream storage
   fetches.
2. `fetchStorage` — chain on `fetchAccountWithRoot` to pick up the
   storageRoot, then issue a path set carrying the account hash + slot
   hash, verify against the storageRoot, decode the RLP integer.
   Empty storage root short-circuits to zero without a network round trip.
3. `fetchBytecode` — bytecode cache check first; on miss, `getByteCodes`,
   keccak256 the response, match against the requested codeHash; surface
   `EvmExecutionError.InvalidProof` on mismatch.

Retry policy: a `Supplier<SnapPeer>` is consulted at the start of every
attempt. On any failure (proof invalid, IO timeout, hash mismatch) we
rotate to the next peer, up to `maxAttempts` (default 3). The supplier is
free to track peer scores externally — the oracle doesn't dictate that.

Tests build hand-crafted single-leaf tries, encode the proofs by hand,
register them with an in-memory `FixturePeer`, then run the oracle through
its three entry points. Eight tests cover: account hit, account absent,
account retry-on-bad-proof + retry budget exhaustion, storage hit, storage
on empty trie, bytecode hit + cache hit, bytecode hash mismatch, empty-code
short-circuit. 29/29 `:myotis-evm` tests now pass (Phase 0's 21 + the new 8).

`DefaultEvmExecutor` and `SyncStateView` from Phase 0 already consume
`SnapStateOracle`, so the executor needs no changes — wallet integration
is "construct `SnapBackedStateOracle` instead of `FixtureSnapStateOracle`."

What's still missing for the public-API "wallet integration" piece: an
`EthHandler`-backed `SnapPeer`. That's a thin adapter (translate
`SnapPeer.PathSet` to `GetTrieNodesMessage.PathSet`, call
`requestTrieNodesAsync`, project the response). It belongs in `:app` (or
wherever the daemon wires things up) since `:myotis-evm` doesn't depend on
`:networking`. Adapter + mainnet integration tests come together in commit 5.

### 5 — Mainnet integration tests (scaffolding done; bootstrap pending)

Two pieces shipped in commit 5:

**EthHandlerSnapPeer adapter (`:app/snap`).** Translates between
`io.myotis.evm.world.SnapPeer.PathSet` and
`com.jaeckel.ethp2p.networking.snap.messages.GetTrieNodesMessage.PathSet`,
and wraps `EthHandler.requestTrieNodesAsync` /
`EthHandler.requestByteCodesAsync` for the `:myotis-evm` consumer. Lives
in `:app` rather than `:myotis-evm` because the latter is intentionally
decoupled from `:networking`. The adapter is mechanical type translation —
its real coverage comes from the integration test below.

**Integration test source set (`:myotis-evm/src/integrationTest`).** A
separate Gradle source set + task (`./gradlew :myotis-evm:integrationTest`)
that's not bound to `check`. Tests are gated with
`@EnabledIfEnvironmentVariable(MYOTIS_MAINNET=1)` so the unit suite stays
offline. `MainnetCallViewIT` defines three tests covering the original
Phase 1 acceptance corpus:

- USDC `balanceOf(vitalik.eth)` (ERC-20 storage proof end-to-end)
- DAI `balanceOf(vitalik.eth)` (different storage layout, validates the
  oracle isn't accidentally USDC-shaped)
- ENS Public Resolver `addr(namehash("vitalik.eth"))` (multi-call walk:
  read account → read storage slot → return address)

Each test reads `MYOTIS_INTEGRATION_*` env vars (peer enode, state root,
block number/timestamp, base fee), constructs `DefaultEvmExecutor` against
`SnapBackedStateOracle`, calls `callView`, and decodes the result. For
USDC the test optionally cross-checks the value against an externally-
provided `eth_call` result via `MYOTIS_INTEGRATION_VITALIK_USDC_BALANCE`.

**What's not done in this commit:** the `connectToMainnetPeer()` helper
inside the test currently throws `UnsupportedOperationException`. Standing
up an `EthHandler` from inside a JUnit fixture means reproducing
`:app:Main`'s bootstrap (NodeKey, NetworkConfig, RLPxConnector,
ChainHead). The simpler path is to extract that wiring into a reusable
`MainnetSnapClient` helper in `:app` — that's a non-trivial refactor of
the daemon code and is intentionally out of scope here. The test compiles,
the gating works (`./gradlew :myotis-evm:integrationTest` without
`MYOTIS_MAINNET=1` reports 3 ignored / 0 failures), and the acceptance
criterion is reachable as soon as the bootstrap helper exists.

## Open decisions

- **Proof verifier source.** ~~Tuweni vs. hand-rolled — settle in commit 2.~~
  Settled: hand-rolled in `:core`. See section 2 above.
- **Where the verifier lives.** ~~`:core` vs `:networking` vs `:myotis-evm`.~~
  Settled: `:core`. Generic utility shared across modules.
- **`GetTrieNodes` vs `GetAccountRange` for single-account fetches.** The
  plan specifies `GetTrieNodes` because it returns just the proof path, not
  a 128 KB range. We may discover that mainnet peers serve `GetTrieNodes`
  inconsistently and need to fall back to `GetAccountRange` with a tight
  hash window. Decide when commit 3 hits real peers.
- **Threading model.** Phase 0 uses `Runnable::run` in the no-arg ctor and
  documents that production callers must pass a worker pool. Phase 1's
  oracle blocks on real network IO; the executor must run on a non-UI
  thread. Concrete recommendation lands in commit 4.

## What this branch has shipped so far

- Commit 1 (`be8331f`): four SNAP wire types + roundtrip tests.
- Commit 2 (`5e430d2`): MPT proof verifier in `:core` + hex-prefix codec
  + RLP-item splitter, all unit-tested.
- Commit 3 (`0a21c47`): `EthHandler` outbound + inbound wiring for the
  four new snap/1 message codes.
- Commit 4 (`2adb2dd`): `SnapBackedStateOracle` in `:myotis-evm` — combines
  the verifier + the SnapPeer abstraction with proof-verification + retry
  semantics.
- Commit 5 (this one): `EthHandlerSnapPeer` adapter in `:app/snap` +
  `MainnetCallViewIT` integration-test scaffolding (env-gated, three target
  contracts). Final piece pending: a reusable `EthHandler` bootstrap
  helper so the `connectToMainnetPeer()` stub becomes runnable.

Phase 1 status: structurally complete (every component compiles, every
unit test passes, every layer has the integration shape it needs). The
`connectToMainnetPeer` bootstrap is the last gate before the acceptance
criterion ("integration tests pass against a real SNAP peer") can be
declared met.
