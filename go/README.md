# Go engine

A Go re-implementation of the Myotis engine. Same contract as the Rust engine's
minimal core, same trust model: **all data over devp2p/libp2p, everything
verified against the pinned sync-committee / genesis anchors**
(README §Trust, docs/spec/).

Scope, deliberately small (owner's brief, 2026-11-10):

- **one network: mainnet** — pins in `internal/chain`, mirroring the Rust
  `ElConfig::mainnet` and geth's `params/bootnodes.go` (the pin test fails on a
  partial re-sync);
- **no EVM** — snap state + verification only, no local execution;
- **client/dialer only** for TCP — the engine dials, never accepts. One
  deliberate exception on the UDP side: reusing geth's discv4 node means we
  *do* answer FINDNODE from bonded peers (the references deliberately
  don't — `docs/spec/02-execution-networking.md` §2.3); `ListenV4` has no
  switch for the responder half, and being a good DHT citizen makes our own
  lookups return better sets. Decision, not accident — see the
  `internal/discovery` package doc.

Build blocks: much of the heavy, settled plumbing comes from go-ethereum
(RLP, discv4, EIP-1459, secp256k1, and the range-proof verifier for the snap
part). The **RLPx wire layer is the deliberate exception** (hand-ported,
PR #767): ECIES, the EIP-8 handshake and the frame codec are this module's
own code, ported from `myotis-wire` and pinned byte-for-byte to the shared
cross-language corpus in `rust/testdata/el/rlpx/` — which needs injectable
entropy and exercises the raw-snappy fallback and the frame caps the
library's `p2p/rlpx` does not expose. Whether to keep the port or wrap
`go-ethereum/p2p/rlpx` instead is an open owner decision. Everything that
makes it *Myotis* — the message handling, verification policy, anchoring —
is this module's own code, guided by `docs/spec/` and `rust/` as the
reference.

## Parts (feature/go-engine)

1. discovery — discv4 + EIP-1459 DNS tree, candidate reporting (PR #757)
2. RLPx + eth handshake (PR #767) — ECIES, framed channel, Status/fork-id, and the
   first verified read: a genesis header fetched from READY peers and hashed
   against the pinned genesis hash (`internal/rlpx`, `internal/ethwire`,
   `internal/transport`; the codec replays the shared conformance corpus in
   `rust/testdata/el/rlpx` byte-for-byte)
3. consensus light client (PR #769) — embedded checkpoint → BLS-verified
   finality anchors: the SSZ containers, merkleization, sync-committee BLS
   (blst) and the update processor, ported from `rust/myotis-consensus` and
   replayed byte-for-byte against the shared corpus `rust/testdata/lc/mainnet`
3b. CL fetch (this PR) — the beacon peer path over libp2p: the eth2 req/resp
   wire (`internal/clwire`: ssz_snappy framing pinned to the Java golden
   vectors, Status v1/v2, the Fulu/EIP-7892 fork digest incl. the BPO fold),
   discv5 CL discovery with the eth2 ENR filter (`internal/clsync`), and a
   bootstrap → catch-up → finality-poll loop (`cmd/myotis-lc`) whose every
   answer goes through the part-3 processor — checkpoint pin, period gate,
   BLS, Merkle branches. Live-smoke verified against roost + Lighthouse pins.
   Deliberate 3b cuts, all documented: TCP+Noise+yamux only (no QUIC, no
   mplex → Nimbus), identify disabled (eth2 servers answer it under
   `eth2/1.0.0`; re-enabling it feeds the LC-server peer tier), no LCSS
   snapshot persistence yet (cold start re-bootstraps).
4. snap reads — GetAccountRange/GetStorageRanges/GetByteCodes verified against
   the anchor's state root; a `get-account`-style read
5. final integration PR to `main`

## Run

```bash
cd go
go run ./cmd/myotis-go -datadir ./data          # discover + dial until Ctrl-C
go run ./cmd/myotis-go -run-for 90s              # smoke: report after 90s
go run ./cmd/myotis-go -dial=false               # discovery only
go run ./cmd/myotis-go -loglevel debug           # per-dial failure detail
```

## Test

```bash
go test ./...
```
