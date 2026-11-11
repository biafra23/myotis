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

Build blocks: the heavy, settled plumbing comes from go-ethereum (RLP, RLPx,
discv4, EIP-1459, secp256k1, and the range-proof verifier for the snap part);
everything that makes it *Myotis* — the message handling, verification
policy, anchoring — is this module's own code, guided by `docs/spec/` and
`rust/` as the reference.

## Parts (feature/go-engine)

1. discovery — discv4 + EIP-1459 DNS tree, candidate reporting (PR #757)
2. RLPx + eth handshake — ECIES, framed channel, Status/fork-id, and the
   first verified read: a genesis header fetched from READY peers and hashed
   against the pinned genesis hash (`internal/rlpx`, `internal/ethwire`,
   `internal/transport`; the codec replays the shared conformance corpus in
   `rust/testdata/el/rlpx` byte-for-byte)
3. consensus light client — embedded checkpoint → BLS-verified finality anchors
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
