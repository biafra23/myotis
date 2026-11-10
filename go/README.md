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
- **client/dialer only** — discovery dials and reads, never serves
  (docs/spec/02-execution-networking.md §Scope note).

Build blocks: the heavy, settled plumbing comes from go-ethereum (RLP, RLPx,
discv4, EIP-1459, secp256k1, and the range-proof verifier for the snap part);
everything that makes it *Myotis* — the message handling, verification
policy, anchoring — is this module's own code, guided by `docs/spec/` and
`rust/` as the reference.

## Parts (feature/go-engine)

1. discovery — discv4 + EIP-1459 DNS tree, candidate reporting (`this`)
2. RLPx + eth handshake — ECIES, framed channel, Status/fork-id
3. consensus light client — embedded checkpoint → BLS-verified finality anchors
4. snap reads — GetAccountRange/GetStorageRanges/GetByteCodes verified against
   the anchor's state root; a `get-account`-style read
5. final integration PR to `main`

## Run

```bash
cd go
go run ./cmd/myotis-go -datadir ./data          # discover until Ctrl-C
go run ./cmd/myotis-go -run-for 90s              # smoke: report after 90s
```

## Test

```bash
go test ./...
```
