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
   against the LC-anchored finalized exec state root. (Since the
   desktop-embed step-1 refactor this orchestration — dialer, LC loop,
   anchor publishing, and the read with its per-anchor disclosure
   memory — lives in `internal/engine`, the engine as a library; the
   CLI is a thin driver over it, and `myotis-go -json` prints the same
   verified read in the pinned engine-API result shape
   (`internal/engine/eljson.go`: the eljson.rs key set and value
   encodings, goldens included).) Two policy points: anchors are published only after a VERIFYING finality poll
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
go run ./cmd/myotis-go -get-account 0xd8dA…045 -json     # …in the pinned engine-API JSON shape on stdout
go run ./cmd/myotis-lc -once                     # LC alone: bootstrap → catch-up → one finality advance
```

## C ABI (desktop embed)

`cmd/myotis-capi` builds the engine as a c-shared library exporting the
full `rust/include/myotis_engine.h` surface: the read-engine functions
(lifecycle, verified account/storage reads, status, log drain) are
functional, every other export answers an honest refusal (permanent
`-32602` JSON / `false` / the contract's own "not in build" codes),
and `myotis_go_capabilities_json` answers the split at runtime.

```bash
# CGO_CFLAGS as goBuildCShared and go-engine.yml set them (portable blst —
# see the build note at the bottom of this document)
CGO_CFLAGS="-O2 -D__BLST_PORTABLE__" \
  go build -buildmode=c-shared -o build/libmyotis_engine_go.so ./cmd/myotis-capi
scripts/check_capi_symbols.sh   # every header symbol must be exported (CI runs both)
```

The handle contract matches the header: `myotis_create` allocates a
NOT-YET-STARTED engine (the CLI starts its network right away; a C-ABI
host starts it at `myotis_start`), an empty `data_dir` is refused with
`-1` rather than defaulting to the process cwd, and the discv4 UDP
port is OS-assigned (the header's own default) unless the
undocumented-until-now override `MYOTIS_GO_LISTEN_PORT` says otherwise
(`0` = the network's `30303`, `-1` = ephemeral — the default). The block
selector is applied-or-refused: only `"finalized"` runs; the head tags
are refused with the way forward named. `myotis_status_json` answers
with the Rust engine's KEY SET (`host.rs` `status_object`: same names,
same types — the string `networkMetering`, the 0x-less
`finalizedRootHex`) plus three Go-only keys (`engine`, `myotisAbi`,
`capabilities`); keys whose machinery this engine lacks carry honest
zeros, marked in the struct. `myotis_set_ws_bound_periods` and
`myotis_accept_stale_anchor` are APPLIED live — the LC loop reads
them at every weak-subjectivity gate and a parked bootstrap
restarts — while `myotis_set_served_block_window` records its value
(a dial-only engine serves no blocks, so no answer depends on it;
`capabilities` makes that explicit).

## Desktop embed (`:myotis-engine-go`, feature/go-desktop-embed part 1c)

The JVM side is the `:myotis-engine-go` Gradle module: `GoEngineNative`
(plain JNA interface mapping over this same header, lazy symbol resolution — the Go twin of
`RustEngineNative`, same `java.library.path`→`jna.library.path` mirroring,
same ABI-57 handshake, `myotis_string_free` after every returned string),
and `GoMyotisEngine`/`GoChainHandle`/`GoVerifiedReads` behind the
`:myotis-api` contract. The selector routes it via `myotis.engine=go`
(`-Pengine=go` on the daemon/desktop run tasks only — the Settings engine
toggle is a java/rust switch and cannot select it) —
`auto` never picks it: the Go engine is desktop-only and explicit until the
engine-parity step (owner's brief, 2026-11). The library is built by the
root `goBuildCShared` task (without the go toolchain it skips and DELETES any
previously built library — the run tasks and native-backed tests gate on the
file's existence alone, and old bytes must not keep serving new sources;
PR #832 round-4) into
`go/build/libmyotis_engine_go.{so,dylib,dll}`; the desktop run task injects
it via `-Dmyotis.engine.go.lib`, the daemon via `java.library.path`.

Honest gaps the wrapper surfaces rather than fakes (all engine-parity
items): no idle sleep (`pause()` refuses, lifecycle is RUNNING/STOPPED),
reads ONLY at the finalized anchor (`latest`/numbers are refused, never
answered from finalized state — and the hosts' 45 s readiness dot
therefore reads amber, because the read state really is finality-old;
`eth_blockNumber` answers the FINALIZED block, not a head, while the
engine has no optimistic anchor — an open owner decision, PR #832),
storage reads reach positions below 2^64 only (the ABI names the slot as
an `int64_t`; positions ≥ 2^63 cross as their two's-complement pattern,
pinned by the slot-echo test, while positions beyond 8 significant bytes
cannot be named by the ABI at all and are refused before the FFI — as the
engine's generic retryable null, which is why every hashed mapping slot
gets a retryable code for a request no retry can serve; the fix is the
ABI slot width, not the reader — the Go reader itself takes the full
32-byte key), no EVM/block/tx/code reads,
no ENS (the `EnsApi` throws one named refusal), no broadcast path,
no Tor (account reads leave from the host's real IP; the desktop logs
the mismatch instead of pretending the switch applies). The JSON-string
reads (block/tx/receipt/fee-history) answer the `{"error":…,
"code":-32602}` envelope so the wallet gets a permanent refusal, not a
retryable one. `myotis_drain_logs` lines are drained by
`Engines.drainRustLogs` next to the Rust engine's ring, so the hosts'
log pipeline is engine-agnostic (Go's slog lines are normalized to the
level-first shape the pumps classify by, carrying a `go` marker). The
catalog lists only the runnable network (mainnet, its entry
golden-pinned), while the canonical-name table matches Rust's for all
four. A `-Pengine=go` desktop launch runs on its own `~/.myotis-go`
profile — the shrunken catalog would otherwise prune the shared
settings' other networks (and it keeps this engine's `nodekey`/`nodedb`
off the regular profile too).

`goBuildCShared` builds with `CGO_CFLAGS="-O2 -D__BLST_PORTABLE__"`
(portable blst, like the Rust workspace and — since this PR's review —
`go-engine.yml`, which built bare before: the ADX build's load-time
constructor answers SIGILL with `_exit(128+4)` and kills whatever process
dlopens the library on a pre-Broadwell/pre-Zen CPU, past every
`UnsatisfiedLinkError` handler) and `GOTOOLCHAIN=local`
(it skips with a note when the local toolchain is older than `go.mod`'s
line rather than downloading one mid-build; CI installs it via
`setup-go`). A skip — missing `go` (resolved like `cargo`, incl.
`/usr/local/go/bin` for PATH-blind IDE daemons) or an old toolchain — also
deletes a previously built library, since consumers gate on existence alone
(PR #832 round-4).

## Test

```bash
go test ./...
```
