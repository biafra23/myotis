# Glamsterdam readiness plan (Gloas + Amsterdam)

Status: IN PROGRESS — written 2026-08-19; updated 2026-09-25. Sepolia's date
and parameters are decided; A.2's EL detector shipped (#491). On the branch
after it: A.1 (Sepolia schedule + time-gated fork id, both engines), B.0 (the
pinned delta below), B.4 (Amsterdam EVM: served by revm 43, refused by Besu
26.4), and B.1–B.3 in progress — the Gloas light client, fork-keyed decoding,
and the execution anchor resolved by block hash (see "The EL anchor after
Gloas"). Dates without a decision are projections and move whenever testing
finds something.
Sources of truth to re-check while executing: `ethereum/consensus-specs`
(`specs/gloas/light-client/`), the EF fork announcement blog posts (they carry
the final epochs, timestamps and fork versions per network), and a fork
tracker (eipsinsight.com/upgrade/schedule, forkcast.org).

## Why this fork is unusually invasive for Myotis

Glamsterdam = **Gloas** (CL) + **Amsterdam** (EL). The CL headliner,
**EIP-7732 (ePBS)**, removes `execution_payload` from `BeaconBlockBody` and
replaces it with a builder bid (`signed_execution_payload_bid`); the payload is
revealed separately as an `ExecutionPayloadEnvelope`. That restructures exactly
the containers our light client proves:

- `BeaconChainSpec.EXECUTION_PAYLOAD_GINDEX = 25` / `DEPTH = 4` (the
  "Capella+" constants) stop being valid — the payload is no longer at that
  position under `body_root`.
- `LightClientHeader`'s fixed 244-byte layout with its hardcoded 4-node
  `executionBranch` no longer matches the wire format.
- `LightClientProcessor.verifyExecutionBranch()` — the ONLY binding between
  the sync-committee-signed beacon header and the EL block hash / state root,
  i.e. the wallet's entire EL trust path — must be re-derived against the new
  proof location.
- The size-inference decoders (`ExecutionPayloadHeader` 584/680 sniffing,
  `BeaconBlockBody` 392/396, `LightClientUpdate`/`Bootstrap` branch-length
  derivation) don't know the Gloas shapes.

Fulu rode through for free because it changed no LC container shapes; the
implicit decoder ceiling is **Electra**. Gloas is the first fork since we
shipped that breaks the shapes, in **both** engines (`consensus/` and
`rust/myotis-consensus/`).

What survives: the trust model itself. Sync-committee BLS signatures stay the
anchor (Altair machinery is not modified), and a withholding builder is a
liveness problem, not a safety one — same class as roost withholding: nothing
verifies wrong. What does NOT survive (B.0 finding, correcting this plan's
first draft): the EL state root is no longer committed anywhere on the
consensus side. Gloas removes `latest_execution_payload_header` from the state
and the payload from the body; a light-client header proves only an EL BLOCK
HASH. The chain of custody gains a hop — signature → beacon header → body root
→ block hash → keccak of a devp2p header → its state root — still trustless,
but every reader of the LC's state root / block number, and both engines'
SYNCED derivations, had to change (see "The EL anchor after Gloas").
(Caveat found while building A.2: detection is slower than CLAUDE.md suggests.
Both engines drop out of SYNCED ~5 epochs after finality stalls — the Java
gate landed in #490, `BeaconSyncState.SYNCED_SLOT_SLACK_EPOCHS`. But
`beaconNotSynced` only fires on a store that never finalized, in both engines;
a stalled one keeps serving the last finalized head until
`headerChainGapTooLarge`.) Bandwidth/storage on mobile are unaffected: BALs
(~70 KB/block) are a full-node artifact never fetched by the LC path, and
PeerDAS-style data is not in this fork.

## Schedule (as of 2026-09-24)

| Stage | Date | Status |
|---|---|---|
| Platåberget (public test network) | 2026-08-20 | forked — first public Gloas network |
| **Sepolia** | **2026-10-06 13:53:36 UTC** | **decided** (ethereum/pm#2205, ACD 2026-09-17): epoch 353024, slot 11296768, EL timestamp 1791294816, `GLOAS_FORK_VERSION 0x90000076`, EIP-2124 fork id → `0x6c1d9423` |
| Hoodi | ~2026-10-27 | tentative |
| **Mainnet** | TBD | was targeted 2026-11-04; Sepolia slipped two weeks from its 2026-09-21 projection, expect mainnet to move too |
| Gnosis | TBD | own beacon chain, own schedule — track separately |

**Sepolia is our real deadline**: Myotis supports `-Pnetwork=sepolia`, so
that is the first day Myotis meets Gloas blocks in a network we run.
Package A must be live for Sepolia by then; Package B wants Sepolia (or
Platåberget) as its integration bench.

---

## Package A — fork-day survival (small, per network, deadline-bound)

**Goal:** on a Gloas/Amsterdam network, Myotis keeps its devp2p connectivity
and EL header path working, and the beacon side degrades **explicitly**
instead of hanging mysteriously. No wrong answers (the verify-everything
architecture already guarantees that — a misparsed Gloas update produces a
wrong root, fails BLS/Merkle verification, and is rejected; the failure mode
is a stall, never corruption).

**Non-goal:** verified reads past the fork. Without Package B, reads on a
forked network stop succeeding once the finalized head can no longer advance
(eventually `headerChainGapTooLarge` — not `beaconNotSynced`, see the caveat
above); the A.2 advisory is what tells the user why.

### A.1 Fork-schedule entries in network config (both engines)

Extend `NetworkConfig` (Java) and the Rust twin with the Glamsterdam
transition data per network, taken from the official fork announcement when
it lands (do NOT guess them):

- Amsterdam EL activation timestamp + post-fork EIP-2124 `forkIdHash`.
- Gloas epoch + `GLOAS_FORK_VERSION` (per network) for digest/domain use.
- Updated BPO params if the announcement changes them.

Sepolia's values are now decided (see Schedule): Amsterdam 1791294816, fork id
`0x268956b6` → `0x6c1d9423` (verified: it is exactly `ForkIds.successor` of our
pin at that timestamp), Gloas epoch 353024, version `0x90000076`. No BPO change
was announced with it.

Today the fork ID is a single static pin (`NetworkConfig.forkIdHash`,
`rust/myotis-core/src/forkid.rs`), which cannot straddle a boundary: before
activation the old hash is right, after it the new one, and a shipped wallet
can't flip at the instant. Recommended shape: a **time-gated pair**
(`hashBefore`, `hashAfter`, `activationTime`) selected by wall clock /
observed head, plus announcing `forkNext = activationTime` pre-fork so
upgraded peers keep us through the announcement window. Same pattern for the
CL side (`forkVersionBefore/After` + epoch). This is deliberately the seed of
B.3's fork schedule — build it once, in config, and let B consume it.

Re-pin the cross-engine golden conformance bytes for the fork-ID values.

**Status: IMPLEMENTED for Sepolia (both engines).** The shape landed simpler
than the pair above: the build's one known next fork is its `forkNext`, so
the effective id is `ForkIds.effective(pin, forkNext, now)` /
`forkid::fork_id_at` — the pin with `forkNext` announced before `T`, and
`successor(pin, T)` with `next = 0` from `T` on. The eth `Status`, the DNS-pool
filter and the fork watch all read the effective id; the conformance corpus
pins `forkid.afterNext.<net>` so both engines' CRC32 must agree on
`0x6c1d9423`. The CL side is the Gloas entry `(353024, 0x90000076)` in each
engine's Sepolia schedule, read by epoch (`forkDigestAtEpoch` /
`fork_digest_at_epoch`), plus the schedule's Gloas epoch for B's format.

### A.2 Fork detection & upgrade advisory

**Status: IMPLEMENTED for the EL signal, in both engines, enabled on Sepolia
(2026-09-24).**

Without it, an un-updated client past the fork is a wallet that looks "stuck
syncing" — indistinguishable from a network outage. Safety already holds
(misparsed post-fork objects produce wrong roots and fail BLS/Merkle
verification), but the liveness failure is mute.

**What shipped**

- *Detector:* `networking/.../eth/ForkWatch` + `ForkIds` (Java) ↔
  `rust/myotis-net/src/el/fork_watch.rs` + `rust/myotis-core/src/forkid.rs`
  (Rust). Same constants, same rules, same Sepolia vectors in both suites.
- *Evidence* — EIP-2124 fork ids from the eth `Status` of peers that already
  passed the network-id + genesis gate:
  - announced: our hash with an unknown `forkNext = T` (upgraded clients
    announce it from the day their release carries the fork);
  - placed: a foreign hash that places as `successor(ourHash, T)`. CRC32
    resumes from its checksum and also runs backwards, so
    `ForkIds.activationOf` / `forkid::activation_of` recovers the one
    `T < 2^32` for ANY hash in O(1); a real `T` was announced or sits on the
    epoch grid within the last 400 days, so a wallet that was offline for the
    whole announcement window still recognises the fork (upgraded peers send
    their Status before dropping our stale one). Placing separates a
    successor from another chain's hash; it is **not proof** — anyone can mint
    a "successor" for any date (`0x47e12c82` places on Sepolia's grid at
    2026-09-23T23:55:12Z). The first version called it proof and searched
    ~9·10⁴ grid points per foreign hash behind a cache that a random-hash
    flood could thrash on the network thread; review caught both.
- *Vote* — built to be expensive to fake:
  - one vote per source network (IPv4 /24, IPv6 /48), not per node id — ids
    are free, and one host can present hundreds;
  - an advisory needs ≥3 sources behind one activation AND more of them than
    sources on our hash announcing no unknown fork: a minority can't outvote
    the peers it contradicts. Most-backed activation wins; ties → placed,
    then earliest. ACTIVE = passed on the wall clock, or placed by ≥3.
- *Freshness* — a source counts while one of its peers stays connected (both
  engines' peer maintainers touch live sessions every 10 s) and for 24 h
  after. A passed announcement counts 6 h past `T` (bridges the rollover,
  ages out a moved date) — unless it was made before `T` by a source still
  seen connected after it: that peer passed `T` with the fork configured. A
  fork the build knows (its own `forkNext`) never raises one; peers on it
  count as dissent. Advisory only — nothing in verification reads it.
- *Vectors:* the full mainnet chain Frontier → BPO2 reproduces our pinned
  `0x07c9462e`; Sepolia `0x268956b6` → `0x6c1d9423` at 1791294816 (the
  published Glamsterdam fork id), recovered exactly by `activationOf`.
- *Ownership:* Java ChainStack-owned (survives pause/resume connector
  rebuilds); Rust handle-owned (`EngineState.fork_watches`, attached to every
  rebuilt pool). Both report the advisory in every lifecycle state, PAUSED
  included — but its evidence ages out a day after its sources were last seen
  connected, so a long sleep re-derives it from the peers dialed on wake.
- *Gate:* `ENABLED_NETWORKS = {sepolia}` in both engines (staged rollout).
- *Surfacing:* `myotis-api` `UpgradeAdvisory`/`UpgradePhase` as nullable
  `StatusSnapshot.upgradeAdvisory`; Rust status-JSON key `upgradeAdvisory`
  (null | object — older wrappers ignore it, the JVM and iOS parsers treat
  absent/null/unknown-phase as "none" rather than failing the status read);
  daemon `status` + `beacon-status` (with a human-readable `message`) and a
  WARN log on transitions; UI `NodeSnapshot.upgrade` → Status + Query banner
  (desktop, Android and iOS producers). An ACTIVE advisory turns the
  readiness strip red and the banner into an alarm only when the node's OWN
  verified state agrees (`beaconState` not SYNCED, or a stale verified head):
  peers alone never make the wallet claim it stopped verifying. The Node.js
  module gets it through the same status JSON (README documents it). No
  JSON-RPC surface (owner decision; `StatusJson` records the IPC-only key).

**Still open**

- CL signals (would additionally catch a CL-only fork; Ethereum forks are
  coordinated EL+CL, BPO forks included, so the EL signal covers today's
  cases): pre-fork, the discv5 ENR `eth2.next_fork_version/next_fork_epoch`
  (decoded by Java `Enr.eth2()` but unused; Rust parses only the digest) plus
  `nfd`; post-fork, the peers' libp2p Status `fork_digest` (decoded and
  logged, never compared). The req/resp context bytes are extracted in
  `ReqRespCodec` but dropped at every call site, so they need plumbing first.
- Schedule-known mode (an explicit `unsupportedFork` once a configured epoch
  is crossed) — depends on A.1. Done with A.1: the watch measures from the
  effective fork id, so after `T` peers on its successor are dissent and a
  further fork announced on top of it is still detected. A build that carries
  a fork in its `forkNext` stays silent about it — correct only because that
  build also carries B; a release with A.1 but without B would not warn its
  Sepolia users (the owner decides what ships).
- Two or more forks ahead: placement is one step from our pin, so a stale
  build loses its placed evidence once a further fork (e.g. a BPO soon after
  Glamsterdam) moves upgraded peers two steps away; only announced/connected
  evidence remains. Cheap to chain: take the `forkNext` announced by peers
  placed on `successor(local, T)` as the next step.
- Before the mainnet/Gnosis flip: re-validate on Sepolia's real fork (churn,
  announcement timing — the majority rule holds SCHEDULED back until most
  observed sources announce), and consider a threshold relative to recent
  handshakes on top of the absolute three.
- Dropped: sharpening the verified-read error to `upgradeRequired`. The RPC
  surface is out of scope (owner), and `beaconNotSynced` doesn't fire on an
  already-synced node in either engine, so there was nothing to sharpen — the
  status advisory is the signal.
- Rollout: flip `ENABLED_NETWORKS` for mainnet/Gnosis in both engines once the
  Sepolia fork (2026-10-06) has validated it, ahead of their activations.

Correction to the original plan: the UI seam is `NodeController.snapshots()` →
`NodeSnapshot`; `NetworkStatus` is device connectivity only.

### A.3 Confirm the EL path is genuinely inert

`BlockHeader` decode is forward-tolerant (post-London fields behind
`isComplete()`, hash over raw RLP), so Amsterdam's new header fields — EIP-7928
`block_access_list_hash` and EIP-7843 `slot_number`, both trailing — are carried
through hashing untouched, same treatment as `requestsHash` today. Pinned by
decode/hash round-trip tests over a synthetic Amsterdam header with both
fields (Rust `header.rs`, Java `BlockHeaderAmsterdamTest`); the Rust decoder
also exposes the pair (SLOTNUM, B.4). This matters more after Gloas than
before: the header fetched by hash IS the EL anchor now.

**Definition of done (per network):** daemon on the forked network keeps
peers past the boundary (fork-ID accepted both sides), EL header fetch works
on post-fork headers, `beacon-status` shows the explicit unsupported-fork
reason (until B lands), and no verified-read path returns data it cannot
verify. Rollout: Sepolia by 2026-10-06, mainnet once its date is set, Gnosis when its date
is announced.

**Effort:** small — config plumbing ×2 engines + surfacing + tests; the only
design work is the time-gated pin.

---

## Package B — Gloas-verifying light client + Amsterdam EVM (the real work)

**Goal:** full verified reads on Gloas networks — `beacon-status` reaches
SYNCED past the fork and `get-account`/`get-storage` return
`verifyMethod: "headerChain"` again (the CLAUDE.md integration test, run on
post-fork Sepolia).

### B.0 Pin the spec delta (blocks everything; start now)

Against `specs/gloas/light-client/` in consensus-specs (pin the exact spec
release/devnet tag used), enumerate:

1. The Gloas `LightClientHeader` shape — what replaces the embedded
   Deneb/Electra `ExecutionPayloadHeader` (bid container? state-rooted
   `latest_block_hash` proof?) and the new execution-proof gindex + depth.
2. Gloas `BeaconState` field count — whether the sync-committee /
   finalized-root gindices shift again (Electra precedent: 37 fields →
   depth 6). ePBS adds several state fields; if the count stays ≤ 64 the
   existing Electra branch depths likely hold — verify, don't assume.
3. `LightClientBootstrap`/`Update`/`FinalityUpdate` branch lengths per fork,
   and the cross-fork normalization rule (Electra precedent: prepend a zero
   hash to shorter pre-fork proofs).
4. Fork digest computation — whether the EIP-7892 BPO XOR scheme carries
   into Gloas unchanged.
5. Whether any live-path consumer of `BeaconBlockBody` (gossip block parsing)
   needs the Gloas body (`execution_payload` out;
   `signed_execution_payload_bid` + `payload_attestations` in).

Deliverable: a short addendum to this file with the pinned constants, plus
the chosen consensus-spec-tests version for vectors.

#### B.0 result — pinned Gloas light-client delta (researched 2026-09-25)

- **Spec pin:** consensus-specs `v1.7.0-beta.2` (`5afdff62`). The LC wire
  format has not changed since `v1.7.0-alpha.12` (EIP-7688 landed then); on
  every new tag, re-diff `specs/gloas/light-client/` and the field order of
  Gloas `BeaconState`, `BeaconBlockBody` and `ExecutionPayloadBid`. Client dev
  branches: Lighthouse, Teku, Lodestar and Nimbus pin beta.2; Prysm beta.0
  (LC-identical).
- **Vectors:** consensus-specs release assets `v1.7.0-beta.2/{mainnet,minimal}.tar.gz`
  (`consensus-spec-tests` is archived). The subset both engines pin lives in
  `rust/testdata/lc/gloas-spec/` (README there): mainnet `ssz_static` for the
  layouts and roots; minimal `light_client/sync` and the Fulu→Gloas
  `gloas_fork` transition, sliced by hand (32-member committee).
- **Header:** `LightClientHeader{beacon, execution_block_hash: Hash32,
  execution_branch: Vector[Bytes32, 11]}`, 496 B, fixed size.
  `execution_block_hash = body.signed_execution_payload_bid.message.parent_block_hash`.
- **Containers (mainnet, fixed size, no offsets):** Bootstrap 25472, Update
  26424, FinalityUpdate 1448, OptimisticUpdate 664.
- **Gindex / depth (Gloas):** finalized root 735/9; current sync committee
  2945/11; next 2946/11; execution block hash 2856/11 (pre-Gloas headers in the
  Gloas shape: 812/9, normalized to 11). Electra/Fulu keep 169/7, 86/6, 87/6,
  25/4. Selected by the fork of the ATTESTED slot (a bootstrap: its header's)
  and checked with `is_valid_normalized_merkle_branch` — never derived from the
  branch length (Gloas `BeaconState` is a 46-field ProgressiveContainer; the
  depth formulas give 553/2070/2071).
- **Unchanged:** BeaconBlockHeader, SyncCommittee, SyncAggregate, Checkpoint,
  ForkData, the signing domain. The LC path needs no progressive merkleization.
- **EL anchor:** the LC proves only an EL block hash — the parent payload's,
  which for the finalized header is the EL finalized hash
  (`finalized_block_bid.parent_block_hash`). No EL state root is committed on
  the consensus side; number and state root come from the devp2p header whose
  keccak matches.
- **Cross-fork:** each object keeps its own fork's format on the wire (context
  bytes = digest of the attested slot's fork). A Gloas update can carry a
  pre-Gloas finalized header (812 branch, 2 zero nodes) for the first epochs
  after the fork. The Sepolia fork epoch 353024 is exactly the period-1379
  boundary.
- **Digest:** the Fulu rule is unchanged (Gloas redefines only
  `compute_fork_version`). Sepolia: Gloas `0x669e6c11` (derived; the Fulu
  digest `0x74d01459` matches live). `BLOB_SCHEDULE` unchanged; EL
  `amsterdamTime 1791294816`.
- **Who serves Gloas LC data over p2p:** only Nimbus (on by default, v26.8.0+)
  and Lodestar (on by default, v1.48.0+). Lighthouse unstable: not implemented
  (prerequisite sigp/lighthouse#9790, progressive Merkle proofs, open). Prysm:
  not implemented and off by default. Teku and Grandine: no p2p LC serving at
  all. roost relays whatever its upstream serves — a Nimbus upstream serves
  Gloas.
- **Settled:** B.1 decodes by fork. Beyond the LC objects, the Gloas
  `BeaconBlockBody`'s fixed part is 396 B — the same as Electra's — so size
  sniffing would misread a body outright.

### B.1 Java engine (`consensus/`)

- `BeaconChainSpec`: the Gloas gindices as constants (B.0) — the
  derive-from-branch-length helpers stay for pre-Gloas objects only.
- `types/`: `LightClientHeader` in both shapes (payload header + 4-node
  branch, or block hash + 11-node branch); fixed-size Gloas decoders for
  `LightClientBootstrap`/`Update`/`FinalityUpdate` behind `decodeFor(LcFork)`.
- `LightClientProcessor`: a shape gate before BLS (every header of an update
  is in its ATTESTED slot's fork's shape), finality / next-committee gindices
  by that fork, and `verifyExecutionBranchAt(header, fork of its own slot)` —
  2856 for a Gloas header, 812 normalized for a pre-Gloas one in the Gloas
  shape, 25 for the payload shape. Keeps the doc discipline: this function IS
  the EL trust path.
- `ForkSchedule` (`:core`) knows its Gloas epoch (`withGloasEpoch`, checked
  against the version list) and answers `lcForkAtSlot`.
- **Decided: decode by fork.** Context bytes (the digest of the object's
  attested epoch) pick the decoder; the processor's shape gate cross-checks
  the decoded object against its attested slot. Gloas-vs-pre-Gloas sizes do
  not collide for LC objects, but they do for `BeaconBlockBody` (B.0), and
  gindices cannot be derived from lengths at all, so sniffing is at its limit.
- `BeaconP2PService` drops the context bytes today; plumbing them to the
  decode sites is part of B.3.

### B.2 Rust twin (`rust/myotis-consensus/`) + golden corpus

Mirrors B.1 (`types.rs` `HeaderExecution`, `decode_for`; `store.rs`
`verify_execution_branch_at`, `verify_bootstrap`; `fork.rs` `LcFork`). Pinned
in both engines: the spec vectors (`rust/testdata/lc/gloas-spec`), a signed
Fulu→Gloas walk over synthetic trees (`gloas_boundary.rs` ↔
`GloasBoundaryTest`), and the snapshot format below. **LCSS v2**: one shape
tag per header, written only once a Gloas-shaped header is held — a
payload-shaped store still writes v1 byte-for-byte, so an older build can
resume it. Cross-engine golden `rust/testdata/snapshot/lcss-v2-golden.bin`.
`rust/roost` needed one change: `participation_of` reads Gloas updates (by
their fixed size) so a better copy of a Gloas period can replace a weaker one;
it already stamps each object's context bytes from the fork schedule.

### B.3 Runtime fork awareness

Consume A.1's schedule everywhere a fork constant is used at runtime: BLS
signing domain by epoch (done in #295's `version_for_signature_slot`), the
decoder by the chunk's context bytes (`ChainConfig::lc_fork_of_chunk`;
`codec::decode_multi_chunk_response_with_digests` keeps the per-chunk digest,
since one range response can span the fork) — or by its exact Gloas size, which
no pre-Gloas object has, so a later blob-parameter fork's digest (one the
single-BPO config does not compute) still reads as Gloas; Java twin
`BeaconLightClient.lcForkOf`. Gossip topic re-subscription at
the boundary (Java; the Rust engine consumes no LC gossip), req/resp context
handling. `rust/roost/src/forks.rs` is the in-repo model for the shape of this.
The Java chain fill (`fillChainStateRoots`, the one `BeaconBlockBody`
consumer) must stop at Gloas slots: a Gloas body carries no payload and no
state root, and its 396-byte fixed part is read as Electra.

### The EL anchor after Gloas (both engines)

Before Gloas the light client handed the EL `{number, block_hash, state_root}`
straight from the proven payload header. After it, only the block hash:

1. The CL loop records a Gloas header's hash as PENDING (Rust
   `ExecAnchor::note_finalized_hash` / `note_optimistic_hash`; Java
   `BeaconSyncState` twin).
2. The EL peer pool fetches `GetBlockHeaders(origin = hash, 1)` from any peer
   (Rust `PeerPool::start_anchor_resolver`) and offers the result.
3. The anchor adopts it only if the keccak of the header's OWN raw RLP is the
   pending hash — recomputed at the anchor, not taken from the decoder — and
   then takes number and state root from that header. The root joins the
   `stateRootMatch` window as verified.
4. Until then it keeps serving the last resolved finality (final, only older)
   and reports it NOT current, so the log index's restart claim never weighs a
   superseded finality as current. The published state is SYNCED only while
   the resolved finality is within the finality gate's own slack — a resolver
   that no peer serves drops out of SYNCED instead of reading as
   verification-ready.
5. After empty or withheld payloads, consecutive beacon headers name the same
   parent payload: the same hash only moves the anchor's slot, no fetch.

Before Gloas the anchor's finality IS the store's, so none of this changes
behaviour on mainnet or gnosis today.

### B.4 EVM: Amsterdam rung

- **revm (Rust): served.** revm `=43.0.3` (reth main's pin; 41 → 43 needed no
  API change) maps `SEPOLIA_AMSTERDAM_TIME` to `SpecId::AMSTERDAM`, with
  EIP-8037 state gas and EIP-2780 intrinsic gas on exactly for Amsterdam specs
  (what reth's `CfgEnv::new_with_spec` does; revm's EIP-7708/EIP-8246 opt-outs
  stay at their defaults, i.e. active). The flat-21000 estimate shortcut stops
  at Amsterdam (EIP-2780 reprices transfers; a value transfer to an empty
  account pays new-account state gas). SLOTNUM (EIP-7843) reads the verified
  header's `slot_number`; an Amsterdam-spec context without one is refused
  permanently (`EvmError::MissingSlotNumber`, -32602), never run with 0, and
  so is a slot number on a block the fork table puts before Amsterdam
  (`EvmError::UnexpectedSlotNumber`). Engine ABI 33. Decided: the JVM and iOS
  hosts map the Rust engine's `{"error","code":-32602}` on call and estimate
  to `REFUSED` (`RustChainHandle` / `IosRpcBackend` `permanentRefusalOrNull`),
  so EVERY Rust-engine -32602 there is permanent at the wallet — executor
  refusals, malformed arguments, and a block behind the window
  (`CallBlockRefusal::Behind`) alike, the last one reaching the engine only
  when the head moves between the host's window check and the engine's. The
  hosts no longer shortcut a plain transfer to 21000 either: the engine
  decides, and its EVM setup reads the verified head's header alone (no
  body), so the estimate costs what the shortcut's recipient read did.
- **Besu (Java): refused.** Besu 26.4 ships an early `MainnetEVMs.amsterdam`
  without EIP-2780, so it cannot price Sepolia's schedule. `EvmFactory`
  refuses Sepolia blocks at/after the activation with
  `EvmExecutionError.UnsupportedFork` (also ahead of the estimate's
  plain-transfer shortcut and before any prefetch), and the engine contract
  gained `CallResult`/`EstimateResult` status `REFUSED`, served as the
  permanent -32602 (never the retryable -32000). The Besu bump turns the
  refusal into an `amsterdam()` builder.
- **Android:** the Besu fork is on `26.4.0-android.1` (`besuForkVersion`,
  `android-app/build.gradle.kts`); Amsterdam is one rebase away once Besu
  releases an EIP-2780-capable EVM.
- Revisit `estimateGas` ceilings once the 200M gas-limit floor is real
  (current 30M ceiling; Osaka already left the EIP-7825 2^24 per-tx cap as a
  known residual).

### B.5 Networking follow-ups (not fork-day-critical)

Amsterdam also ships eth/70 (EIP-7975 partial receipts) and eth/71
(EIP-8159 BAL exchange). eth/66–69 keep negotiating for a transition window,
so nothing breaks on day one, but track deprecation — the receipts path (log
index) eventually needs eth/70. Separate ticket, not part of A or B DoD.

### Known limitations after review (tracked, not fork-day-critical)

- **One BPO in the digest model.** Both engines fold a single blob-parameter
  entry into the fork digest. A BPO fork scheduled after Gloas changes the
  network's digest without changing the fork version: light-client decoding
  survives it (a Gloas object is recognised by its exact size, which no
  pre-Gloas object has), but the Status digest and the Java engine's LC gossip
  topics would follow the wrong digest until the schedule model holds the full
  BPO list. Extend it when Sepolia or mainnet schedule a post-Gloas BPO.
- **Finalized slot in the Rust status.** Read results report the EL anchor's
  resolved finalized slot (the finality they proved against) in both engines.
  The Rust status object keeps the light client's finalized slot, paired with
  its `finalizedRootHex`; the Java status reports the resolved slot. The two
  differ only while a Gloas finality waits for its execution header.
- **ENS at `FINALIZED` right after the fork (Java).** Once the store's
  finalized header is Gloas-shaped, `prepareEnsCall(FINALIZED)` builds its
  block context from the resolved EL header, so until the first Gloas finality
  resolves (seconds; longer if no EL peer serves that header, or after a
  restart from a Gloas-shaped snapshot) it fails with "not resolved yet"
  instead of serving the older resolved finality as the Rust engine does. An
  error, never a wrong answer — and about two epochs after the fork the
  finalized block is an Amsterdam block, which the Java EVM refuses anyway.
  Revisit with the Besu upgrade.
- **Too-old blocks: host and engine disagree.** Both hosts pre-check the block
  window and answer UNAVAILABLE (-32000) for a block the Rust engine would
  refuse permanently (-32602), so that refusal rarely reaches a wallet. The
  engine's executor refusals (ABI 33) and malformed arguments do arrive as
  -32602. Which classification a block behind the window deserves is a
  separate decision.

### Test strategy

1. Spec vectors: consensus-spec-tests Gloas LC suite through both engines
   (decode, hashTreeRoot, verify), pinned as goldens.
2. Boundary: an Electra→Gloas update sequence across the fork epoch,
   including the normalization rule from B.0(3).
3. Live: **Platåberget forks 2026-08-20** — the only public Gloas network
   for the next month. Optionally add it as a fourth (dev-only)
   `NetworkConfig` to buy ~4 weeks of integration time before Sepolia;
   needs its bootnodes/genesis/checkpoint. Owner's call whether that's worth
   the config churn vs waiting for Sepolia.
4. Acceptance: the CLAUDE.md integration test on post-fork Sepolia —
   `beacon-status` SYNCED, then `get-account` →
   `verifyMethod: "headerChain"`.

---

## Dependencies, risks, ordering

| Risk | Exposure | Mitigation |
|---|---|---|
| Spec churn until Gloas LC spec is final | B.0/B.1 rework | pinned to v1.7.0-beta.2 (LC format unchanged since alpha.12); re-diff on bumps |
| Besu Amsterdam release timing | B.4 Java only | Java refuses Amsterdam blocks with a permanent -32602 until a Besu with EIP-2780 ships; the Rust engine serves them |
| Android Besu-fork rebase capacity | B.4 Android | fork is on 26.4.0-android.1; Amsterdam is one rebase |
| Size-sniffing shape collision | B.1 correctness of *rejection reasons* (not of results) | decided: fork-keyed decoding by context bytes, shape gate against the attested slot |
| Few Gloas LC servers | liveness after the fork | Sepolia: Nimbus and Lodestar only (+ roost on a Nimbus upstream) — upgrade the dedicated node's Nimbus before 10-06. Mainnet: Lighthouse, likely the largest LC-serving population, has no Gloas LC yet (sigp/lighthouse#9790) — track before the mainnet date |
| No EL peer serves the anchor's header | Gloas liveness (never safety) | any peer can serve it, none can forge it; the anchor falls back to the last resolved finality and SYNCED drops after the finality gate's slack |
| Dates slip | deadline planning | Sepolia date is the tripwire; A is small enough to hold ready |

Suggested order: **A.1–A.3 + B.0 now** (A is shippable independently and its
config schema feeds B); B.1→B.2 against spec vectors while Platåberget is the
live bench; B.4's Android 26.4 rebase in parallel; Sepolia fork day runs A in
anger and starts B's real-network soak; mainnet config refresh + B shipped
before mainnet's activation (date TBD — see Schedule; the earlier ~Nov 4
target predates Sepolia's two-week slip).
