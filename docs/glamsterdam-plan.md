# Glamsterdam readiness plan (Gloas + Amsterdam)

Status: PLANNING — written 2026-08-19, before the Sepolia fork. All dates below
except mainnet are projections and move whenever testing finds something.
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

What survives untouched: the trust model itself. Sync-committee BLS signatures
stay the anchor (Altair machinery is not modified), the EL state remains
committed under the signed header (the proof path moves, the chain of custody
does not), and a withholding builder is a liveness problem, not a safety one —
same class as roost withholding (`BeaconSyncState` regresses, queries fail
with `beaconNotSynced`; nothing verifies wrong). Bandwidth/storage on mobile
are unaffected: BALs (~70 KB/block) are a full-node artifact never fetched by
the LC path, and PeerDAS-style data is not in this fork.

## Schedule (as of 2026-08-19)

| Stage | Date | Status |
|---|---|---|
| Platåberget (public test network) | 2026-08-20 | forking now — first public Gloas network |
| **Sepolia** | **2026-09-21** | projected |
| Hoodi | 2026-10-05 | projected |
| **Mainnet** | **2026-11-04** | target (ACD-anchored; already slipped once from H1) |
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

**Non-goal:** verified reads past the fork. Without Package B, `get-account`
etc. on a forked network correctly fail with `beaconNotSynced` once the
finalized head can no longer advance.

### A.1 Fork-schedule entries in network config (both engines)

Extend `NetworkConfig` (Java) and the Rust twin with the Glamsterdam
transition data per network, taken from the official fork announcement when
it lands (do NOT guess them):

- Amsterdam EL activation timestamp + post-fork EIP-2124 `forkIdHash`.
- Gloas epoch + `GLOAS_FORK_VERSION` (per network) for digest/domain use.
- Updated BPO params if the announcement changes them.

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

### A.2 Explicit "unsupported fork" surfacing

`BeaconLightClient` knows only one fork version (`acceptedForkVersions()`
returns the configured singleton). Once the chain crosses the Gloas epoch,
every new update fails and the node sits in a permanent stale/OPTIMISTIC
limbo that is indistinguishable from a network problem. Add: when the head
slot crosses a configured Gloas epoch that the client does not support,
`beacon-status` reports it (e.g. a `reason: "unsupportedFork(gloas)"` next to
the state) and verified-read errors say so too. This is the trust rule from
CLAUDE.md applied to time: refuse loudly, never degrade silently.

### A.3 Confirm the EL path is genuinely inert

`BlockHeader` decode is forward-tolerant (post-London fields behind
`isComplete()`, hash over raw RLP), so Amsterdam's new header field
(EIP-7928 `block_access_list_hash`) is carried through hashing untouched —
same treatment as `requestsHash` today. Add a decode/hash round-trip test
with a synthetic Amsterdam header (extra trailing field) to pin that.

**Definition of done (per network):** daemon on the forked network keeps
peers past the boundary (fork-ID accepted both sides), EL header fetch works
on post-fork headers, `beacon-status` shows the explicit unsupported-fork
reason (until B lands), and no verified-read path returns data it cannot
verify. Rollout: Sepolia by ~Sep 21, mainnet by ~Nov 4, Gnosis when its date
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

### B.1 Java engine (`consensus/`)

- `BeaconChainSpec`: Gloas execution-proof gindex/depth (per B.0), keeping
  the existing derive-from-branch-length helpers where they still apply.
- `types/`: Gloas variants of `LightClientHeader`, the execution
  header/bid container, `LightClientBootstrap`/`Update`/`FinalityUpdate`;
  `BeaconBlockBody`/`BeaconBlockParser` if B.0(5) says the live path needs
  them.
- `LightClientProcessor.verifyExecutionBranch()`: new proof path; keep the
  existing doc discipline (this function IS the EL trust path).
- `BeaconLightClient`: accept the fork-schedule from A.1 — per-epoch fork
  version for the BLS domain, per-slot digest for topics/req-resp,
  `acceptedForkVersions()` spanning {Electra/Fulu, Gloas} through the
  transition, and boundary handling for updates whose attested/finalized
  headers straddle the fork.
- **Decision point (owner):** the size-sniffing decoder idiom is at its
  limit — Gloas shapes may collide by size with Electra ones. Recommended:
  key decoding on the fork at the object's slot (known from A.1's schedule)
  and keep sniffing only as a cross-check. That is an architecture change to
  a deliberate convention, so it is the owner's call; the alternative is
  adding Gloas size thresholds and accepting the brittleness.

### B.2 Rust twin (`rust/myotis-consensus/`) + golden corpus

Mirror every B.1 decoder change in `types.rs` (same runtime behavior,
including whatever B.1's sniffing decision is). Source fixtures from
`ethereum/consensus-spec-tests` Gloas light-client vectors and captured
Platåberget/Sepolia wire objects; pin them as cross-engine goldens in both
directions, per the established corpus pattern. `rust/roost` is already
Gloas-tolerant on scheduling (`forks.rs` parks unknown forks at
`u64::MAX`) — verify it relays Gloas LC objects as opaque bytes and only
needs digest awareness, not shape awareness.

### B.3 Runtime fork awareness

Consume A.1's schedule everywhere a fork constant is used at runtime: BLS
signing domain by epoch, fork digest by slot, gossip topic re-subscription at
the boundary, req/resp context handling. `rust/roost/src/forks.rs` is the
in-repo model for the shape of this.

### B.4 EVM: Amsterdam rung (upstream-gated, then mechanical)

- **Besu (Java):** needs a release past 26.4.0 with
  `MainnetEVMs.amsterdam` / `AmsterdamGasCalculator` /
  `EvmSpecVersion.AMSTERDAM`. Besu is active on the Glamsterdam devnets, so
  this lands before mainnet; bump `gradle/libs.versions.toml` when it ships
  (and fix the stale `24.12.2` comment in `myotis-evm/build.gradle.kts`).
- **revm (Rust):** already there — revm v114 aligns with Glamsterdam
  devnet-7 fixtures. Bump and add the rung.
- Add the rung in ONE coordinated change across both fork tables
  (`EvmFactory.java` cascade + `AMSTERDAM_TIME` ×3 chains;
  `rust/myotis-evm/src/fork.rs` `SpecId::AMSTERDAM`), twinned boundary tests
  like the Osaka pair (`OsakaBoundaryTest` ↔
  `osaka_boundaries_map_on_every_chain`).
- **Guard against the silent-Osaka fallback:** the timestamp cascade would
  otherwise price Amsterdam blocks with Osaka rules (wrong, undetectable —
  exactly the CLAUDE.md "applied or refused" violation). Until the rung
  exists, `buildForBlock()` past a configured Amsterdam timestamp must
  refuse (permanent error), not silently compute.
- **Android long pole:** `biafra23/besu` (`24.12.2-android.2`) must be
  rebased to an Amsterdam-capable Besu. De-risk by doing the pending 26.4
  rebase NOW, so Amsterdam is one hop instead of a double jump under time
  pressure.
- Revisit `estimateGas` ceilings once the 200M gas-limit floor is real
  (current 30M ceiling; Osaka already left the EIP-7825 2^24 per-tx cap as a
  known residual).

### B.5 Networking follow-ups (not fork-day-critical)

Amsterdam also ships eth/70 (EIP-7975 partial receipts) and eth/71
(EIP-8159 BAL exchange). eth/66–69 keep negotiating for a transition window,
so nothing breaks on day one, but track deprecation — the receipts path (log
index) eventually needs eth/70. Separate ticket, not part of A or B DoD.

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
| Spec churn until Gloas LC spec is final | B.0/B.1 rework | pin a spec tag per devnet; re-diff on bumps |
| Besu Amsterdam release timing | B.4 Java only | revm path is done; EVM lag is estimation-accuracy only, never a verification gap — with the refuse-guard in place |
| Android Besu-fork rebase capacity | B.4 Android | start the 26.4 rebase now |
| Size-sniffing shape collision | B.1 correctness of *rejection reasons* (not of results) | fork-keyed decoding decision (owner) |
| Dates slip | deadline planning | Sepolia date is the tripwire; A is small enough to hold ready |

Suggested order: **A.1–A.3 + B.0 now** (A is shippable independently and its
config schema feeds B); B.1→B.2 against spec vectors while Platåberget is the
live bench; B.4's Android 26.4 rebase in parallel; Sepolia fork day runs A in
anger and starts B's real-network soak; mainnet config refresh + B shipped
before ~Nov 4.
