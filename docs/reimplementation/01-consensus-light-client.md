# 01 — Consensus Light Client (the trust root)

> Companion to the [re-implementation spec](README.md). This is the **security-critical core**:
> the beacon sync-committee light client that establishes a cryptographically verified chain
> head. If this is wrong, every downstream "verified" answer is worthless. Re-implement it
> first and test it hardest.

Reference package: `consensus/` (`com.jaeckel.ethp2p.consensus`), compiled to Java 17.

---

## 1. What this layer produces

A continuously advancing, **BLS-verified beacon block header**, from which it extracts an
**`ExecutionPayloadHeader`** (via a Merkle "execution branch"). That gives the rest of the
system its trust anchor: `stateRoot`, `blockHash`, `blockNumber`, `baseFeePerGas`,
`transactionsRoot`, `receiptsRoot`. Two states are tracked: a **finalized** header (lags ~2
epochs) and an **optimistic** head.

---

## 2. Dependencies and what each provides

| Concern | Reference library | Notes for a port |
|---|---|---|
| BLS12-381 | **Pluggable `BlsBackend` seam** — `MilagroBlsBackend` (pure-Java AMCL, default/fallback) or `NativeBlsBackend` (Rust **`blst`** via JNI, `rust/myotis-bls`), selected by `BlsBackends.active()` | A port should use **`blst`** (Rust/Go) or `gnark-crypto` (Go) and call their `FastAggregateVerify` + RFC-9380 hash-to-G2 directly. See §8.0 and [`docs/bls-rust-acceleration.md`](../bls-rust-acceleration.md): native blst is **4–15× faster** than Milagro on real verifies (far more on ART), so a port should make it the primary backend, not the fallback. |
| hash-to-curve | **hand-rolled RFC 9380** (`bls/HashToCurve.java`) | Not needed if you use `blst`/`gnark` (they implement it) — but you must pass the exact DST. |
| libp2p | `io.libp2p:jvm-libp2p` (TCP, Noise-XX, yamux/mplex, gossip) | `rust-libp2p` / `go-libp2p`. |
| discv5 | ConsenSys `io.consensys.protocols:discovery` (in the `networking` module, not here) | `discv5` crate / go-ethereum v5. |
| Snappy | iq80 snappy (framed) | `snap` / `golang/snappy`. |
| SHA-256 | JDK `MessageDigest` | All SSZ hashing + fork digest. |
| keccak + RLP | Tuweni | **Only** for the execution-layer MPT bridge (`proof/`), never for SSZ. |

There is **no Teku dependency and no external SSZ library** — all beacon SSZ types and
merkleization are hand-rolled. A port may use an SSZ library but **must re-validate** the exact
light-client field orders and generalized indices below.

---

## 3. Constants (`lightclient/BeaconChainSpec.java`)

```
SLOTS_PER_EPOCH                    = 32        (Gnosis: 16)
EPOCHS_PER_SYNC_COMMITTEE_PERIOD   = 256       (Gnosis: 512)
SLOTS_PER_SYNC_COMMITTEE_PERIOD    = 8192      (32×256 == 16×512 — SAME on both presets)
SYNC_COMMITTEE_SIZE                = 512
MIN_SYNC_COMMITTEE_PARTICIPANTS    = 1
SECONDS_PER_SLOT                   = 12        (Gnosis: 5)
DOMAIN_SYNC_COMMITTEE              = 0x07000000
```

`computeSyncCommitteePeriod(slot) = slot / 8192`. Period math is shared across presets; only
the wall-clock→slot conversion (`(now - clGenesisTime) / secondsPerSlot`) is per-network. A
period is ~27 h on mainnet, ~11.4 h on Gnosis.

---

## 4. Beacon data types (SSZ; all little-endian)

Field order **is** the merkleization order; get it exact. Selected types (`types/`):

| Type | Fields (order · type · size) |
|---|---|
| **BeaconBlockHeader** (112 B) | `slot` u64 · `proposerIndex` u64 · `parentRoot` B32 · `stateRoot` B32 · `bodyRoot` B32 |
| **SyncCommittee** (24624 B) | `pubkeys` Vector[BLSPubkey×48, 512] · `aggregatePubkey` B48 |
| **SyncAggregate** (160 B) | `syncCommitteeBits` Bitvector[512] = 64 B · `syncCommitteeSignature` B96 |
| **LightClientHeader** | `beacon` (112 inline) · `execution` (ExecutionPayloadHeader, variable) · `executionBranch` Vector[B32, **4**]. **Hardcoded Capella+** (always 4 branch nodes + a payload header; no pre-Capella Altair variant). |
| **LightClientBootstrap** | `header` · `currentSyncCommittee` (24624) · `currentSyncCommitteeBranch` (5 **or** 6 × B32) |
| **LightClientUpdate** | `attestedHeader` · `nextSyncCommittee` (24624) · `nextSyncCommitteeBranch` (5/6) · `finalizedHeader` · `finalityBranch` (6/7) · `syncAggregate` (160) · `signatureSlot` u64 |
| **LightClientFinalityUpdate** | `attestedHeader` · `finalizedHeader` · `finalityBranch` (6/7) · `syncAggregate` (160) · `signatureSlot` u64 |
| **ExecutionPayloadHeader** | **exactly 17 merkleized fields** incl. `withdrawalsRoot` (Capella), `blobGasUsed`/`excessBlobGas` (Deneb). The 3 EIP-7685 request roots are **decoded for tolerance but EXCLUDED from merkleization** (they live in `BeaconBlockBody.execution_requests`; including them breaks bootstrap). `stateRoot`/`blockHash`/`blockNumber`/`baseFeePerGas` are the EL anchor. |
| **ForkData** | `currentVersion` B4 · `genesisValidatorsRoot` B32 |
| **Checkpoint** (40 B) | `epoch` u64 · `root` B32 |

> **Fork inference rule:** the fork is inferred from **SSZ branch length at decode time**, never
> from a version tag. A `currentSyncCommitteeBranch` of length 5 = pre-Electra, 6 = Electra+.
> A `finalityBranch` of length 6 = pre-Electra, 7 = Electra+. This is why the types carry no
> explicit fork field.

---

## 5. SSZ merkleization kernel (`ssz/SszUtil.java`)

Pure functions; **hash is always SHA-256**, and the only primitive is `sha256(a,b) =
SHA256(a‖b)` over two 32-byte chunks. All integers **little-endian**.

- `merkleize(chunks[, limit])`: pad chunk count up to `max(nextPow2(n), limit)` with 32 zero
  bytes, then hash pairwise bottom-up. For large limits use the sparse variant that prunes
  all-zero subtrees via a precomputed zero-hash table `ZERO_HASHES[d] = SHA256(ZERO_HASHES[d-1] ‖
  ZERO_HASHES[d-1])` (`ZERO_HASHES[0]` = 32 zero bytes).
- `hashTreeRootContainer(roots…) = merkleize(roots)` — **containers and vectors never mix in a
  length**; only Lists / ByteLists / Bitlists `mixInLength`.
- `mixInLength(root, len) = SHA256(root ‖ LE64(len) padded to 32)` (element/bit **count**;
  ByteList uses byte length).
- Primitive leaves: uint64 → 8 LE bytes in a 32-byte chunk; uint256 → 32 LE bytes; bytes32/20/4
  → right-padded to 32; bytes256 (logs bloom) → 8 chunks → tree of 8.

**The proof primitive — `verifyMerkleBranch(leaf, branch, depth, index, root)`:**

```
require branch.length == depth
value = leaf
for i in 0..depth-1:
    if bit i of index is set:  value = SHA256(branch[i] ‖ value)   // our node is the right child
    else:                      value = SHA256(value ‖ branch[i])   // our node is the left child
return value == root
```

`index` is the **subtree index = generalized index with the leading 1 bit stripped**. There are
no gindex-computation helpers in the kernel — the caller supplies `(depth, index)` from the table
in §6.

**Notable hash-tree-roots to replicate exactly:**
- `SyncCommittee`: each 48-byte pubkey is zero-padded to 64, split into 2 chunks, merkleized
  (`pubkeyHashTreeRoot`); the 512 pubkey roots are merkleized (9 levels, no length mix); then
  `container(pubkeysRoot, aggregatePubkeyRoot)`.
- `ExecutionPayloadHeader`: merkleize the 17 field roots padded to 32 leaves (request roots
  excluded — see §4).

---

## 6. Generalized indices (fork-dependent)

Computed at runtime from the branch length. `depth` = branch length; `index` = gindex with the
leading 1 stripped (what `verifyMerkleBranch` consumes).

| Branch | gindex formula | Pre-Electra (depth · gindex) | Electra+ (depth · gindex) | leaf → root |
|---|---|---|---|---|
| execution_payload | constant | 4 · 25 | 4 · 25 | `execution.htr()` → `beacon.bodyRoot` |
| current_sync_committee | `(1<<depth) + 22` | 5 · 54 | 6 · 86 | `committee.htr()` → `beacon.stateRoot` |
| next_sync_committee | `(1<<depth) + 23` | 5 · 55 | 6 · 87 | `nextCommittee.htr()` → `beacon.stateRoot` |
| finalized_root | `((1<<(depth-1)) + 20)*2 + 1` | 6 · 105 | 7 · 169 | `finalizedHeader.beacon.htr()` → `attestedHeader.beacon.stateRoot` |

The finalized-root gindex is `…*2 + 1` because `root` is child index 1 inside the
`Checkpoint{epoch, root}` container at beacon-state field 20.

---

## 7. The signing domain & signing root

The sync committee signs `compute_signing_root(attestedHeader)`:

```
domain        = compute_domain(DOMAIN_SYNC_COMMITTEE=0x07000000, forkVersion, gvr)
              = domainType[0:4]  ‖  hash_tree_root(ForkData{forkVersion, gvr})[0:28]      // 32 bytes
object_root   = hash_tree_root(attestedHeader.beacon)                                     // BeaconBlockHeader htr
signing_root  = hash_tree_root(SigningData{ object_root, domain })
              = sha256(object_root ‖ domain)                                              // 2-leaf container
```

`forkVersion` is the network's **current** fork version (not the attested header's epoch — the
client is forward-only from a recent checkpoint, so the current version always applies).

---

## 8. BLS verification (`bls/`)

Ethereum **minimal-pubkey-size**: pubkeys in **G1** (48-byte compressed), signatures in **G2**
(96-byte compressed).

### 8.0 Backend seam (Milagro vs native blst)

BLS is the light client's heaviest regular operation (a `fastAggregateVerify` on every
finality/optimistic update, ×N during catch-up). The reference puts it behind a `BlsBackend` seam
(`fastAggregateVerify(pubkeys, message, signature)`) selected at runtime by `BlsBackends.active()`
(`-Dmyotis.bls.backend=auto|milagro|native|compare`), wrapped in a `TimingBlsBackend`:

- **`MilagroBlsBackend`** — the portable pure-Java AMCL verifier described in §8.1–§8.5. Default
  fallback; needs an elaborate decompressed-pubkey cache + a bounded `ForkJoinPool` to survive on
  ART (a *cold* sync-aggregate verify is cited at 30–55 s on Android).
- **`NativeBlsBackend`** — a Rust **`blst`** cdylib (`rust/myotis-bls`, one crate → desktop `.so`
  + Android ABIs via `cargo-ndk`), the whole committee flattened into one JNI crossing. **Measured
  4–15× faster** on real ~500-pubkey verifies (desktop), and far more on ART — and it lets you
  delete the cache/pool/warm-up machinery. blst is also more audited than Milagro.

For a **Go/Rust re-implementation this seam mostly disappears**: use `blst`/`gnark` as the single
backend and skip the pure-Java path entirely. The algorithm details in §8.1–§8.5 still matter for
*correctness verification* (DST, point handling, the verify equation) even when a library does the
math. Full evaluation + benchmarks: [`docs/bls-rust-acceleration.md`](../bls-rust-acceleration.md).

### 8.1 The only entry point: `fastAggregateVerify(pubkeys, message, signature)`

```
1. decompress each 48-byte pubkey → G1 point
      - parallelizable; results cached
      - SUBGROUP CHECK SKIPPED for trusted committee pubkeys (see 8.3)
2. aggregate by sequential point-add into infinity; REJECT if any pubkey or the aggregate is infinity
3. decompress 96-byte signature → G2 point, WITH MANDATORY subgroup check; REJECT if infinity
4. hm   = hash_to_G2(message, DST)
5. g1neg = -G1_generator
6. return  fexp( ate2( hm, aggPk, signature, g1neg) ).is_one()
        // i.e.  e(H(m), aggPk) · e(sig, -G1) == 1   ⇔   e(aggPk, H(m)) == e(G1, sig)
```

One shared final exponentiation over a two-pairing product (`ate2`). There is **no** single
`Verify` and **no** distinct-message `AggregateVerify` — only `FastAggregateVerify` (all signers
sign the same message).

### 8.2 DST (load-bearing)

```
DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
```

The `_POP_` suffix is mandatory. A historical bug used `_NUL_` and silently failed **every**
sync-aggregate verify — the system "ran" but verified nothing. Make this an explicit test.

### 8.3 The trusted-pubkey / untrusted-signature asymmetry (security-critical)

- **Committee pubkeys** are already Merkle-proven into a verified header's state, so the per-key
  subgroup check (`r·P == O`) is **skipped** for speed (matches Lighthouse/Teku/Prysm/Lodestar,
  which validate at deposit time).
- The **signature is attacker-controlled** and is **always** subgroup-checked.

Preserve this asymmetry. Skipping the signature subgroup check is a forgery vector; skipping it
on trusted pubkeys is a safe, standard optimization.

### 8.4 Compressed wire format pitfalls

- Top byte bits: bit 7 = compression (required), bit 6 = infinity, bit 5 = y-sign/sort;
  remaining bits are the big-endian x-coordinate. Reject non-compressed and non-canonical
  infinity encodings.
- **G2 is imaginary-part-first**: the first 48 bytes are `c1`, the last 48 are `c0`. A very
  common port bug is reading them in the wrong order.
- y-root selection compares against `HALF_P = (p-1)/2`.

### 8.5 hash-to-G2 (`HashToCurve.java`, RFC 9380)

Implemented from scratch on Milagro field ops: `expand_message_xmd` over SHA-256 (count = 2
field elements, `L = 64`); `hash_to_field` → `FP2` pairs; `map_to_curve` = Simplified SWU on the
3-isogenous curve E′ (`ISO_A = 240i`, `ISO_B = 1012(1+i)`, `Z = -(2+i)`); 3-isogeny E′→E via
the RFC coefficient tables; cofactor clear by scalar-mult with a hardcoded `h_eff` (~636-bit).
**A `blst`/`gnark` port doesn't need any of this** — call their `hash_to_G2`/`HashToG2` with the
DST above. (CMOV is implemented as data-dependent branches — not constant-time, acceptable since
the input is public.)

---

## 9. The light-client protocol (the verifier)

### 9.1 Bootstrap (`BeaconLightClient.bootstrap` → `LightClientProcessor`)

On a received `LightClientBootstrap` (over libp2p; HTTP only for debug):

```
1. CHECKPOINT PIN:  require hash_tree_root(bootstrap.header.beacon) == embedded checkpointRoot
                    — the single root of trust. Reject otherwise.
2. current_sync_committee branch:
       verifyMerkleBranch(committee.htr(), branch, depth, syncCommitteeGindex(depth),
                          header.beacon.stateRoot)            // depth 5 or 6
3. execution branch:
       verifyExecutionBranch(header)                          // depth 4, gindex 25, vs beacon.bodyRoot
4. store.initialize(header, currentSyncCommittee)
       finalized = optimistic = header;  period = computeSyncCommitteePeriod(header.slot)
```

Bootstrap does **not** BLS-verify — the committee is proven by Merkle inclusion in the *pinned*
header's state; the signature anchor starts on the first forward update. The checkpoint is kept
deliberately ~1 period stale so the catch-up path is always exercised.

### 9.2 Forward step — finality update (`processFinalityUpdate`)

```
1. dedup: if syncAggregate.signature == lastAppliedFinalitySig, skip
          (avoids re-running an ~18s BLS verify every 12s poll)
2. participation gate + BLS verify (SyncCommitteeVerifier):
       require popcount(syncCommitteeBits)*3 >= 512*2
       require fastAggregateVerify(participating committee pubkeys,
                                   compute_signing_root(attestedHeader),
                                   syncCommitteeSignature)
3. finality branch:
       verifyMerkleBranch(finalizedHeader.beacon.htr(), finalityBranch, depth,
                          finalizedRootGindex(depth), attestedHeader.beacon.stateRoot)
4. EXECUTION BRANCH FOR BOTH headers (attested AND finalized) — verifyExecutionBranch(each)
       CRITICAL: the BLS signature covers only the BEACON header. The execution payload
       (EL stateRoot/blockHash) is bound to it SOLELY by this branch. Skipping it lets a peer
       pair a genuine signed beacon header with a forged execution payload.
5. store.updateFinalized(finalizedHeader); store.updateOptimistic(attestedHeader)
6. store.applyNextSyncCommitteeWhenPeriodChanges(oldFinalizedSlot, finalizedSlot)
```

`SyncCommitteeVerifier.verify` selects the participating pubkeys from the bitvector, runs the
2/3 gate, computes the signing root, and calls `fastAggregateVerify`.

### 9.3 Forward step — full update (`processUpdate`, for catch-up)

Adds, **before** the expensive BLS verify, the spec's `validate_light_client_update` period gate:

```
sigPeriod = computeSyncCommitteePeriod(update.signatureSlot)
applicable iff  sigPeriod == storePeriod
            or (sigPeriod == storePeriod + 1  AND  the store already holds a next committee)
```

This is essential: a catch-up `updates_by_range` response routinely contains far-future periods,
and an unguarded BLS verify costs 17–30 s **each** on a phone. Then it verifies the
`next_sync_committee` branch (depth 5/6) when the update carries a next committee the store
doesn't yet hold, and stores it.

### 9.4 Sync-committee rotation (`LightClientStore`)

The store tracks `currentSyncCommitteePeriod` **separately** from the finalized slot's period
(finality lags ~2 epochs, and wall-clock can cross a period boundary before finality catches up).

- `applyNextSyncCommitteeWhenPeriodChanges(old, new)`: if `period(new) > period(old)` and a next
  committee is held → `current = next; next = null; period++`.
- `forceRotateIfPastPeriod(wallClockSlot)` (catch-up): rotate when wall-clock period exceeds the
  held committee period, even before finality crosses — so the next finality update (signed by the
  new committee) verifies.

> **Re-implementation trap:** `light_client_finality_update` does **not** carry a next committee —
> only `LightClientUpdate` (via `updates_by_range`) does. So the steady-state poll loop must
> re-fetch a `LightClientUpdate` whenever wall-clock crosses a period boundary, or finality verifies
> fail indefinitely.

### 9.5 Sync state machine (`BeaconSyncState`)

`SYNCING → CATCHING_UP → SYNCED` (not latched; can regress):

- `SYNCING` — no verified EL state root yet (not bootstrapped).
- `CATCHING_UP` — verified-state-root window has fewer than `FILL_THRESHOLD = 4` entries, **or**
  `currentSyncCommitteePeriod < wallClockPeriod`.
- `SYNCED` — otherwise.

`BeaconSyncState` is lock-free for reads (an `AtomicReference` to an immutable state record) plus
a rolling deque (cap 8192) of `(slot, executionStateRoot, blsVerified)` — the window the rest of
the app uses to check a peer-claimed EL state root against a beacon-attested one.

### 9.6 Full lifecycle (`syncLoop`)

```
Phase 0   discover CL peers (HTTP debug only) — production seeds from discv5 + cache + multiaddrs
Phase 1   tryResumeFromSnapshot()  →  preConnectAndIdentify()  →  bootstrap() if not resumed
Phase 1b  catchUpSyncCommittee()   +  fill the chain-state-root window from any peer
Phase 2   steady-state: every secondsPerSlot, pollFinalityUpdate()
          (re-fetch a LightClientUpdate on each period boundary; see 9.4)
```

`catchUpSyncCommittee` fetches `LightClientUpdate`s by period range from wall-clock target
downward, up to `MAX_CATCHUP_BATCHES = 8` batches of ≤128 periods, fanning out to up to
`CATCHUP_FANOUT_MAX = 48` peers (proven light-client peers first, in 3 tiers); first applied
success wins (applies hold a lock on the store).

### 9.7 Snapshot persistence (`LightClientStoreSnapshot`)

Custom binary format (magic `LCSS`, version 1) persisting the verified store so a restart resumes
from the last verified period instead of re-bootstrapping (~10 s vs minutes). **It is bound to
`genesisValidatorsRoot`** and is a private cache, **not a trust anchor**: a corrupt / foreign /
older-than-checkpoint snapshot is rejected, and any bad snapshot self-corrects (the next BLS
verify fails and falls back to the embedded checkpoint). A `.roots` sidecar persists the
state-root window.

---

## 10. libp2p layer (`libp2p/BeaconP2PService`, `ReqRespCodec`)

A hand-rolled **eth2 req/resp** client (plus partial responders). **This is the only real CL
data path — gossip is inert (see below).**

### 10.1 Transport

TCP only (`/ip4/0.0.0.0/tcp/0`), **Noise-XX** secure channel, muxers **yamux then mplex**,
**random secp256k1 identity each start** (ephemeral PeerId). No QUIC / WebSocket / relay / DHT.

### 10.2 Req/resp protocol IDs (all `…/ssz_snappy`)

`status/2`, `status/1`, `ping/1`, `metadata/2`, `goodbye/1`, `light_client_bootstrap/1`,
`light_client_updates_by_range/1`, `light_client_finality_update/1`,
`light_client_optimistic_update/1`, `beacon_blocks_by_range/2`.

The `light_client_*` and `blocks_by_range` responses carry a 4-byte **fork_digest context byte**;
`status`/`ping`/`metadata`/`goodbye` do not.

### 10.3 Wire framing (`ReqRespCodec`)

```
Request:   varint(uncompressedSszLen)  ‖  snappy_framed(ssz)
Response:  result_byte(1)  ‖  [context_bytes(4)]  ‖  varint(uncompressedSszLen)  ‖  snappy_framed(ssz)
```

- The varint encodes the **uncompressed** SSZ length.
- `result_byte != 0` is an error: `1` InvalidRequest, `2` ServerError, `3` ResourceUnavailable.
- Snappy is the **framed** format. Multi-chunk responses are parsed by manually scanning snappy
  frame headers — because a compressed-frame type byte `0x00` is indistinguishable from a
  next-chunk success result code `0x00` without it.

### 10.4 Discovery (external to this module)

discv5 (the ConsenSys library in the `networking` module) discovers CL peers; the engine filters
ENRs by `eth2` `fork_digest` and calls `addPeer(multiaddr)` to push them into the light client
live. The `Status` finalized-epoch field is populated from the checkpoint slot before bootstrap so
Lighthouse doesn't `goodbye` the client with `IrrelevantNetwork`.

### 10.5 Fork digest (EIP-7892)

```
base = SHA256( forkVersion ‖ 28 zero bytes ‖ gvr )            // = compute_fork_data_root
digest = (base XOR SHA256(LE64(bpoEpoch) ‖ LE64(maxBlobs)))[0:4]   if a BPO is active
       =  base[0:4]                                                otherwise
```

Accept the current digest plus the prior-fork digest (eases fork-transition windows).

### 10.6 What is stubbed (flag for any port)

- **Gossipsub is OFF by default and observation-only**: it subscribes to the
  `light_client_finality_update` / `light_client_optimistic_update` topics, but the handler just
  logs and returns `Ignore` — **no snappy decode, no SSZ decode, no validation, no message-id, no
  mesh forwarding**. A real implementation that relied on gossip for liveness would need all of
  that, plus fork-change resubscribe. The reference relies on req/resp polling instead.
- `light_client_updates_by_range` / `beacon_blocks_by_range` **responders are absent** (the client
  can initiate, not serve; deliberately not advertised in Identify).
- Metadata responder is hardcoded (seq 0, all-zero attnets/syncnets); finality/optimistic/bootstrap
  responders are relay-cache echoes (TTL 90 s) of the last received payload; status responder
  echoes local status without validating the peer's.

The libp2p layer never touches the verifier — it returns raw SSZ `byte[]`; `BeaconLightClient`
decodes and verifies one layer up.

---

## 11. Execution-layer bridge inside `consensus` (`proof/`)

`proof/MerklePatriciaVerifier` and `proof/OrderedTrieRoot` live here too (keccak + RLP, big-endian
— **not** SSZ), but they're the same MPT machinery described in companion 03. They link the
beacon-verified EL state root (from the execution payload header, proven by the execution branch)
down to individual accounts/storage, and rebuild tx/receipt/withdrawals trie roots from ordered
lists. See companion 03 §2 for the algorithm; the security invariant — **`storageRoot` and
`codeHash` come only from the proof-verified account leaf** — applies identically here.

---

## 12. Concurrency

- A `beacon-sync` daemon thread runs `syncLoop`.
- A dedicated `beacon-catchup-apply` single-thread executor runs BLS-heavy applies **off** the
  libp2p I/O threads (a BLS verify must never block a Netty event loop).
- A `bls-cache-warmer` pre-decompresses committee pubkeys on resume.
- `LightClientStore` is fully synchronized; catch-up applies hold the store lock so first-success
  wins.
- libp2p I/O runs on the library's event-loop group; results surface as futures.

---

## 13. Test checklist (port these as explicit tests)

1. Checkpoint pin rejects a bootstrap whose header htr ≠ checkpoint root.
2. BLS DST is exactly `…_RO_POP_`; a `_NUL_` DST fails a known-good fixture.
3. G2 signature decompression reads imaginary-part-first; identity points rejected; signature
   subgroup-checked.
4. `fastAggregateVerify` accepts a known-good sync-aggregate and rejects a 1-bit-flipped signature.
5. 2/3 participation gate rejects a sub-threshold bitvector before BLS runs.
6. All four branches verify with the correct fork-dependent gindices (test both pre-Electra depth
   5/6 and Electra+ 6/7 fixtures).
7. `ExecutionPayloadHeader` htr matches a known value with the 3 request roots **excluded**.
8. Period rotation: finality across a period boundary rotates current←next; a finality update with
   no held next committee after a boundary fails until a `LightClientUpdate` is fetched.
9. Snapshot round-trips and is rejected when the gvr doesn't match.
10. SSZ uses SHA-256/little-endian; the `proof/` MPT uses keccak/big-endian — cross-checked against
    known roots.
