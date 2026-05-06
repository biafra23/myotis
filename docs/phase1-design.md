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

### 2 — Proof verifier

Goal: given a `stateRoot`, a key (account hash or storage slot hash), an
expected value, and a Merkle-Patricia-Trie proof, decide whether the proof
verifies.

Decision (open): use Tuweni's `tuweni-merkle-trie` (already in the version
catalog) or roll our own. A small spike will tell us whether Tuweni's API
covers the path of "verify a proof for a given root + key" cleanly. If yes,
this is a thin wrapper. If not, we hand-roll — the algorithm is
well-specified and not large.

The verifier is the Phase 1 trust anchor. Test vectors come from a hand-
crafted trie + Geth-generated proofs.

### 3 — SNAP protocol client

The Phase 0 `:networking` work has the eth/67-68 sub-protocol but no `snap/1`
client wiring beyond message types. Tasks:

- Announce `snap/1` capability in the eth handshake.
- `SnapHandler` (NioInboundHandler) that routes incoming `TrieNodes` /
  `ByteCodes` responses to pending request futures keyed by request id.
- Outbound API: `client.getTrieNodes(stateRoot, paths) -> CompletableFuture<List<Bytes>>`
  and `client.getByteCodes(hashes) -> CompletableFuture<List<Bytes>>`.
- Per-peer rate limiting and timeout handling.
- Peer disconnection on protocol violation (proof verification failure
  surfaces as a peer score decrement; not the wire layer's concern).

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

- **Proof verifier source.** Tuweni vs. hand-rolled — settle in commit 2.
- **`GetTrieNodes` vs `GetAccountRange` for single-account fetches.** The
  plan specifies `GetTrieNodes` because it returns just the proof path, not
  a 128 KB range. We may discover that mainnet peers serve `GetTrieNodes`
  inconsistently and need to fall back to `GetAccountRange` with a tight
  hash window.
- **Where the verifier lives.** `:core` adds it as a generic utility;
  `:networking` keeps it next to the wire types; `:myotis-evm` owns it as a
  private dependency. `:core` is the most natural home (the consensus
  module also benefits from MPT verification).
- **Threading model.** Phase 0 uses `Runnable::run` in the no-arg ctor and
  documents that production callers must pass a worker pool. Phase 1's
  oracle blocks on real network IO; the executor must run on a non-UI
  thread. Concrete recommendation lands in commit 4.

## What this commit ships

Just step 1 — the four new SNAP wire types and their roundtrip tests.
Nothing changes for callers of Phase 0; the new types are not wired
anywhere yet.
