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

### 4 — `SnapBackedStateOracle`

Implements `io.myotis.evm.world.SnapStateOracle`. For each call:

1. Issue the SNAP request via the client.
2. Verify the proof against the trusted `stateRoot` (or the `codeHash` for
   bytecode).
3. On verification failure: deprioritise the peer, retry with another peer
   (cap retries; fail with `EvmExecutionError.InvalidProof` after).
4. Cache `(stateRoot, address, slot) → value` in-memory for the duration
   of the call.

This lives in `:myotis-evm/world/SnapBackedStateOracle.java` (alongside
`FixtureSnapStateOracle`). The `DefaultEvmExecutor` doesn't change — only
the oracle the wallet hands it does.

### 5 — Mainnet integration tests

Separate Gradle source set (`src/integrationTest/java`) so they don't run
on every `:test` invocation. Each test:

1. Connects to a real SNAP peer (or runs against a local Geth/Besu).
2. Picks a recent finalised `stateRoot` (could be sourced via `:consensus`
   light client or hard-coded with the corresponding block number for the
   test).
3. Runs `callView` for the three target contracts.
4. Compares the result with `eth_call` from a public RPC at the same block.

Acceptable for these tests to be `@EnabledIfEnvironmentVariable(MAINNET=1)`
so CI can skip them when no peer is available.

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
- Commit 3 (this one): `EthHandler` outbound + inbound wiring for the four
  new snap/1 message codes. 37/37 `:networking` tests still pass.

Next: commit 4 wires `SnapBackedStateOracle` in `:myotis-evm` — combines
the wire client (commit 1+3), the verifier (commit 2), and the oracle
contract from Phase 0. After that, commit 5 adds the mainnet integration
tests.
