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

Build blocks — where each piece comes from, honestly (PR #773 review):

- **From go-ethereum**: the RLP *encoder/list-splitter* (`rlp` — encoding and
  `Split` only; every *validation* of a decoded item is this module's),
  discv4 and discv5 (the DHT/UDP engines), EIP-1459 DNS trees, secp256k1,
  enode/ENR records, and libp2p (transport + host for the CL side).
- **Hand-ported from the Rust twins, deliberately** — the parts whose
  verification policy the library either lacks or implements with different
  rules: the **RLPx wire layer** (ECIES, the EIP-8 handshake, the frame
  codec — PR #767, pinned byte-for-byte to `rust/testdata/el/rlpx/`, which
  needs injectable entropy and exercises the raw-snappy fallback and the
  frame caps `p2p/rlpx` does not expose; keep-vs-wrap stays an open owner
  decision), the **strict RLP validator** (`internal/rlpcode` — the
  canonical-form refusals geth's decoder does not make, e.g. leading-zero
  integers), the **MPT range-proof verifier** for the snap part
  (`internal/mpt` — geth's `triangle` verifier serves its *own* full-node
  proofs and is not wired here; this is the ported Rust verifier, replaying
  `rust/testdata/el/mpt/`), the **SSZ containers + light-client processor**
  (`internal/lc`/`internal/ssz`, replaying `rust/testdata/lc/mainnet`), and
  the **eth2 req/resp codec** (`internal/clwire`, pinned to the Java golden
  vectors).

Everything that makes it *Myotis* — the message handling, verification
policy, anchoring — is this module's own code, guided by `docs/spec/` and
`rust/` as the reference.

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
3b. CL fetch (PR #770) — the beacon peer path over libp2p: the eth2 req/resp
   wire (`internal/clwire`: ssz_snappy framing pinned to the Java golden
   vectors, Status v1/v2, the Fulu/EIP-7892 fork digest incl. the BPO fold),
   discv5 CL discovery with the eth2 ENR filter (`internal/clsync`), and a
   bootstrap → catch-up → finality-poll loop (`cmd/myotis-lc`) whose every
   answer goes through the part-3 processor — checkpoint pin, period gate,
   BLS, Merkle branches. Live-smoke verified against roost + Lighthouse pins.
   Deliberate 3b cuts, all documented: TCP+Noise+yamux only (no QUIC, no
   mplex → Nimbus), identify's observed-address discovery off (the
   identify service itself runs and answers, with the eth2 twin's
   `eth2/1.0.0` protocol-version field; 3c builds the LC-server peer
   tier from the protocol lists it already collects), no LCSS
   snapshot persistence yet (cold start re-bootstraps), and no Gloas
   geometry — the decoders carry the Deneb and Electra/Fulu branch
   families only, and an unknown family (a Gloas update above all) is
   REFUSED by name at `DecodeUpdate`, never misparsed into the Deneb
   shape; mainnet pins no Gloas epoch, so this is unreachable today
   and honest the day one is (the normalized-branch verifier the Gloas
   proofs need is already ported and fuzz-pinned, waiting for that
   increment). LC responses carry their fork digest in the context
   bytes and the reader APPLIES it: an answer whose digest matches no
   digest this build's fork schedule can produce is refused, not
   silently decoded in the wrong-shape parser.
4. snap reads (PR #772) — the state trust anchor and the read path:
   the MPT proof verifier (`internal/mpt`, replaying the shared
   `rust/testdata/el/mpt/` corpus), the snap wire + verify-on-fetch
   (`internal/snapwire`: dynamic codes per negotiated eth version, both
   slim-body forms, "proof invalid" / "empty proof for non-empty root"
   as load-bearing classification channels; replays
   `rust/testdata/el/snap/` against Java's goldens), the range requests
   on a READY session (`internal/transport`: a GetAccountRange on 0x21
   answered on 0x22 proven in-process end-to-end), and the reader
   (`internal/snapread`: sequential attempts capped at 3 — the
   address-disclosure bound — storage anchored at the PROVEN
   storageRoot, code keccak-checked against the PROVEN codeHash,
   transport / pruned-root / bad-proof taxonomy; every peer-controlled
   list is streamed, never materialized, so a hostile multi-MiB list
   of one-byte items decodes in bounded memory — the #454 lesson,
   pinned by test). `myotis-go
   -get-account <addr> [-slot <n>]` runs the light client in parallel
   with EL dialing and prints the account only once the proof verifies
   against the LC-anchored finalized exec state root. Two CLI policy
   points: anchors are published only after a VERIFYING finality poll
   (never the bootstrap/catch-up root, which is routinely outside
   every peer's ~128-block state window — reading on it would
   disclose the key to peers that cannot answer), and the 2 s retry
   tick re-asks only peers not yet contacted **at that anchor**, so a
   failed read walks the ready set instead of redrawing a random
   three, and the address reaches each peer at most once per anchor.
   Read mode (`-get-account`) also gates the EL ready set on capability:
   a READY peer without snap can never serve the read and a READY
   session has no other way out of the set, so it is closed at the door
   and the backlog dials in its place. Residual cut, documented: a peer
   that answers with a pruned state stays in the set (it *can* serve
   snap, just not at this root) — the reader rotates past it per attempt
   rather than evicting it.
   Deliberate cuts, documented in the code: FINALIZED-anchor reads only
   (the Rust twin's optimistic-head read — `ProcessOptimisticUpdate` +
   the optimistic-update poll — is the next increment; a peer on a
   pruned state scheme answers a finalized-root read with an EMPTY
   proof, and that is precisely the `pruned-root` case the reader
   rotates past — observed live), and no hedged reads (sequential
   only; HEDGE_DELAY 3 s racing is 3c).
   Live-smoke verified 2026-11-11 from this machine: the LC finality
   poll advanced the anchor in real time (slot 15633728 → 15633856
   during the run), the first READY Geth answered the read with an
   empty proof (`pruned-root`, rotated past), the second — a snap/2
   peer on eth/71, exercising the 0x24 base codes for real — served
   it, and the account came back proven: nonce and balance from the
   MPT leaf at the anchored finalized exec state root
   (verifyMethod=snapProof→lcAnchor), its empty storageRoot then
   short-circuiting the `-slot 0` read to a provable zero anchored at
   the PROVEN storageRoot, with no JSON-RPC anywhere in sight.
   Re-smoked on the post-review head (2026-11-12): the restructured
   CLI path proved BOTH halves live — a first window ended in the
   honest failure shape (poll-verified publishing, per-anchor
   disclosure memory, taxonomy rotating past pruned-roots,
   cause-carrying window expiry with exit 1) when the peer set was
   exclusively state-pruned nodes, and a longer window then served
   the read: `verifiedAt=0xe04f511b… lcFinalizedSlot=15634912`,
   nonce/balance from the MPT leaf and the storage read anchored at
   the PROVEN empty storageRoot.
5. final integration PR to `main` (PR #773 — once it merges and the
   feature branch is deleted, this section is history, and the
   `feature/go-engine` entry in `go-engine.yml`'s push trigger can go
   with it)

## Run

```bash
cd go
go run ./cmd/myotis-go -datadir ./data          # discover + dial until Ctrl-C
go run ./cmd/myotis-go -run-for 90s              # smoke: report after 90s
go run ./cmd/myotis-go -dial=false               # discovery only
go run ./cmd/myotis-go -loglevel debug           # per-dial failure detail
go run ./cmd/myotis-go -get-account 0xd8dA…045   # light client + snap peer → VERIFIED account
go run ./cmd/myotis-go -get-account 0xd8dA…045 -slot 0   # …and a two-hop storage read
go run ./cmd/myotis-lc -once                     # LC alone: bootstrap → catch-up → one finality advance
```

## Test

```bash
go test ./...
```
