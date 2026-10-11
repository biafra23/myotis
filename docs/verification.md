# How Verification Works in Myotis

Myotis answers a wallet's questions — a balance, a token balance, a contract call, a
receipt — only from data it has checked itself. The peers it talks to (devp2p for the
execution layer, libp2p for the consensus layer) are **transport, never authority**: a
peer can refuse to answer, but anything it sends that does not verify is thrown away.

This document follows one answer from the single thing Myotis trusts — a checkpoint
compiled into the binary — down to an account balance proven by a SNAP peer. It
describes the **Rust engine** (`rust/`), which is the default engine on every host, and
notes where the **Java engine** differs. For the language-agnostic specification see
[reimplementation/](reimplementation/README.md); for what each JSON-RPC method serves, the
[README](../README.md#implemented-verified-methods).

## The chain at a glance

```
embedded checkpoint (a beacon block root)            ← the trust anchor, shipped in the binary
  │  hash_tree_root(bootstrap header) == checkpoint
  ▼
current sync committee (512 BLS public keys)         ← SSZ branch into that header's state_root
  │  ≥ 2/3 aggregate BLS signature on every update
  ▼
attested beacon header ──finality branch──► finalized beacon header
  │  execution branch (SSZ, into the header's body_root)
  ▼
execution payload header: state_root, block_hash, block_number, timestamp
  │
  ├─ state reads: stateRootMatch — the peer proves against exactly this state_root, or
  │               headerChain    — a parent-hash walk down from this block_hash
  │     ▼
  │   trusted state_root
  │     ├─ MPT account proof → nonce, balance, storageRoot, codeHash
  │     ├─ MPT storage proof → slot value (against the account's PROVEN storageRoot)
  │     └─ keccak256(code)   == codeHash
  │
  └─ block reads: a header window whose top hashes to this block_hash (or the
        │         finalized one), linked by parentHash — the header itself, not its root
        ▼
      trusted header
        ├─ rebuilt tx trie      == transactionsRoot
        └─ rebuilt receipt trie == receiptsRoot → logs
```

Every arrow is a hash or signature check. The only assumption beyond hash functions and
BLS is the standard light-client one: **at least 2/3 of the current sync committee does
not sign a fake beacon header.** That is weaker than a full node, which re-executes every
block, and far stronger than trusting an RPC provider.

---

## 1. Why a proof does not need the whole tree

A Merkle tree commits to a large data set with one hash, the **root**. Each inner node is
the hash of its children, so the root depends on every leaf. To check a single leaf you
need only the nodes along the path from the root to that leaf (and, for a binary tree,
the sibling hash at each level). You recompute the hashes along that path; if you arrive
at the trusted root, the leaf is in the tree. A peer that wants to fake a value has to
produce a different path that hashes to the same root — a hash collision.

Ethereum uses two different kinds of Merkle structure, and Myotis checks both:

| | Consensus layer (beacon chain) | Execution layer (accounts, storage, txs) |
|---|---|---|
| Structure | SSZ binary Merkle tree | Merkle-Patricia trie (MPT) |
| Hash | SHA-256 | keccak-256 |
| Encoding | SSZ, little-endian | RLP, big-endian |
| Branching | 2 children | up to 16 children (+ extension / leaf nodes) |
| A proof is | a fixed-length list of sibling hashes, addressed by a *generalized index* (gindex) | the trie nodes on the path to `keccak256(key)` |
| Proof size | depth × 32 bytes (4 to 11 nodes here) | a handful of nodes, typically a few KB |
| Used for | sync committee, finality, execution payload header | account, storage, transactions, receipts |

A **generalized index** names a node of an SSZ tree by its position: the root is 1, the
children of node *n* are 2*n* and 2*n*+1. It fixes both the depth of the proof and which
side each sibling sits on, so "the execution payload header is at gindex 25 of the block
body" is a complete description of that proof.

An MPT is a trie: the path to a value *is* its key (the nibbles of `keccak256(address)` or
`keccak256(slot)`). That gives it a property a list-shaped Merkle tree lacks — it can prove
**absence**. If the path from the root ends at a node that does not continue toward the key
(an empty branch slot, or a leaf/extension whose path diverges), the key is provably not in
the trie. Myotis reports such an account as empty and such a slot as zero — a verified
zero, not a guess.

Never mix the two: the consensus side and the execution side hash, encode and shape their
trees differently. Two separate verifiers implement them (`rust/myotis-consensus/src/ssz.rs`
and `rust/myotis-core/src/trie.rs`).

---

## 2. The trust anchor: an embedded checkpoint

Each network ships one **beacon block root** (plus its slot) in the `@checkpoint:<network>`
regions of `ChainConfig` in `rust/myotis-net/src/sync.rs`, mirrored in
`networking/.../NetworkConfig.java`; the test `java_and_rust_checkpoints_agree` keeps the
two engines identical. The genesis validators root and the fork schedule are embedded the
same way and never fetched at runtime.

- **Refreshing it.** `./gradlew refreshCheckpoint -Pnetwork=<net>` reads the finalized
  block root from several public beacon endpoints and writes both engines from one fetch.
  It refuses to write a root fewer than two distinct operators agree on (`-PallowSingleSource`
  overrides that), and checks each endpoint's genesis validators root before counting it.
- **Weak subjectivity.** A light client is only safe from an anchor that is not too old: once
  enough validators have exited, an old committee could sign a fork nobody else follows. The
  gate counts sync-committee periods (8192 slots each) between the anchor and the wall clock;
  past the bound — **13 periods on mainnet and Sepolia, 3 on Gnosis** — the client parks in
  `STALE_ANCHOR` instead of syncing, until the user consents (`accept-stale-anchor`, the
  apps' dialog) or raises the bound. The check runs on entry, before every re-bootstrap and
  continuously while running.
- **A host-supplied anchor.** An embedder can start the Rust engine from its own root
  (`myotis_create_with_checkpoint` in the C ABI, also exposed by the Node addon). That root
  *replaces* the trust anchor — the engine does not authenticate it — and everything after it is
  verified exactly as from the embedded one; the data directory is bound to it.
- **Restarts.** The verified store is persisted as an `LCSS` snapshot that both engines read
  and write. A snapshot is used only if it is newer than the checkpoint, and it is *not*
  re-verified on load: it is on probation until one update verifies against its committee,
  and is deleted (falling back to the checkpoint) after repeated rejections
  (`ResumeGuard` in `sync.rs`).

## 3. Bootstrap: from a block root to the sync committee

The client asks consensus peers for `light_client_bootstrap` by the checkpoint root and
accepts the first answer that passes (`verify_bootstrap` in
`rust/myotis-consensus/src/store.rs`):

1. **Checkpoint pin** — `hash_tree_root(bootstrap.header.beacon) == checkpoint`. This is the
   one root of trust; any other header is rejected.
2. **Current sync committee** — its hash tree root is proven by an SSZ branch against
   `header.beacon.state_root` (gindex 54 before Electra, 86 from Electra, 2945 from Gloas).
3. **Execution branch** — the execution payload header is proven into the block body (§5).

The bootstrap carries no signature and needs none: the committee's 512 public keys are
trusted because they are Merkle-proven into the state of the pinned block. BLS starts with
the first update.

## 4. Following the chain: sync-committee signatures

From then on the client follows the chain with two light-client messages over libp2p:
`light_client_updates_by_range` to catch up period by period, and
`light_client_finality_update` once per slot in steady state.
(`light_client_optimistic_update` is never requested; the optimistic head is the attested
header of the finality updates.) Every update goes through these checks, in this order
(`LightClientProcessor` in `store.rs`, `verify_sync_aggregate` in `verify.rs`):

1. **Period gate** — the signature slot must fall in the store's current period (checked
   against the current committee) or the next one (checked against the next committee, if
   the store already holds it). Anything else is not applicable and is dropped before any
   expensive work.
2. **Shape gate** — both headers must have the wire shape of the attested slot's fork.
3. **Participation** — at least 2/3 of the committee must have signed:
   `participants × 3 ≥ 512 × 2`, i.e. **342 of 512**.
4. **BLS** — `fast_aggregate_verify` (blst) of the participating public keys over the
   signing root of the **attested** beacon header. The signing root binds the header to the
   chain: domain `DOMAIN_SYNC_COMMITTEE` (`0x07000000`) with the fork version at the epoch
   of `signature_slot − 1` and the network's genesis validators root. The signature must be
   a canonical, subgroup-checked G2 point.
5. **Finality branch** — the finalized header's root is proven against the attested
   header's `state_root` (gindex 105 before Electra, 169 from Electra, 735 from Gloas).
6. **Execution branches** — for **both** the attested and the finalized header (§5).
7. **Next sync committee** — when the store does not hold the next committee yet, it is
   proven against the attested `state_root` (gindex 55 / 87 / 2946) and adopted. This is how
   trust is handed from one 27-hour committee to the next.

The store then moves forward: the finalized header is replaced only by a later one, the
optimistic (attested) header likewise, and the committee rotates when the finalized
period advances. The Java engine runs the same sequence in `LightClientProcessor` and
`SyncCommitteeVerifier`, with BLS from blst over JNI or pure-Java Milagro.

## 5. From the beacon header to the execution layer

The sync committee signs the **beacon** block header, which says nothing directly about
accounts. The execution data is reached through one more SSZ proof: the hash tree root of
the `ExecutionPayloadHeader` sits at **gindex 25 (depth 4) of the beacon block body**, and
the branch is checked against the header's `body_root` (`verify_execution_branch_at` in
`store.rs`). This check is load-bearing — without it a peer could pair a genuinely signed
beacon header with a made-up execution payload.

From the proven payload header the engine keeps `state_root`, `block_hash`, `block_number`
and `timestamp` of the finalized and the attested block in its **execution anchor**
(`ExecAnchor`, `rust/myotis-net/src/el/anchor.rs`; Java: `BeaconSyncState`). Every later
check on the execution side compares against these values.

**Gloas** (the consensus half of Glamsterdam, live on Sepolia since 2026-10-06; no date yet
on mainnet or Gnosis) changes this step. A Gloas block body carries a payload *bid* instead
of the payload, so a light-client header proves only an execution **block hash** (gindex
2856, the bid's `parent_block_hash` — the payload the block builds on). The engine then
fetches that header from execution peers by hash and adopts its number, state root and
timestamp only if `keccak256(RLP(header))` equals the proven hash. Until that resolution
lands, the anchor's finality counts as not current. Details:
[glamsterdam-plan.md](glamsterdam-plan.md).

### When the node counts as synced

`SYNCED` needs both: the store's committee period equals the wall clock's, **and** the
finalized slot is within 5 epochs of the wall clock (`SYNCED_SLOT_SLACK_EPOCHS`: 32 minutes
on mainnet, under 7 on Gnosis). A peer or relay that withholds updates therefore cannot keep
the node looking fresh — it drops to `CATCHING_UP`. See
[readiness-and-verified-head-age.md](readiness-and-verified-head-age.md).

---

## 6. Tying a peer's answer to the anchor

Execution peers answer against a state root. Before any value is accepted, that root must be
tied to the beacon chain. The decision logic lives in `rust/myotis-net/src/el/verify.rs`
(Java: `VerifiedAccountQuery`), and every result carries how it was tied in
`verifyMethod`:

- **`stateRootMatch`** — the root the peer proved against is one the beacon chain attested
  (it is in the execution anchor's window). The Rust engine asks peers for state **at the
  attested head's root** in the first place, so an ordinary read verifies this way.
- **`headerChain`** — the fallback when a peer cannot prove at that root (it pruned it, or
  trails the head) and the engine falls back to the peer's own head. The engine then
  fetches the headers from the peer's block up to the attested head in one request and
  requires:
  - the **last** header's hash (`keccak256` of its RLP) equals the attested `block_hash`;
  - the **first** header's `state_root` equals the root the peer proved against;
  - every header's hash equals the next header's `parentHash`.

  Trust only flows *down* this chain: a block hash pins its parent, never its children. So
  the walk is anchored at the attested head and must end below it; the peer's block must
  also be above the finalized block, and the gap must stay under `MAX_HEADER_CHAIN_GAP` =
  **8192** blocks. The Rust engine fetches the range in a single request, so in practice the
  walk also has to fit in one peer response (geth serves at most 1024 headers per request); a
  longer gap comes back short and fails closed as `headerChainInvalid`.

When neither works, the result carries a `failReason` instead (`beaconNotSynced`,
`peerProofInvalid`, `peerBlockBehindFinalized`, `peerBlockAheadOfAnchor`,
`headerChainGapTooLarge`, `headerChainInvalid`, …) and nothing is served as verified.

Which state a read uses: `latest`/`pending` read at the attested head; `finalized` (Rust
engine only) reads at the finalized root, with no fallback. Myotis holds no historical state:
a block-number pin is answered from head state only when it is within 64 blocks below
(or 16 above) the head, and refused otherwise (`RpcBlockWindow`).

**Java engine:** its account query asks the peer at the peer's own head, so `headerChain` is
its usual path rather than the fallback; the walk is fetched in batches.

## 7. SNAP: proving accounts, storage and code

State comes from ordinary execution clients over the **snap** protocol (snap/1 or snap/2,
negotiated in the RLPx Hello). Myotis sends three requests
(`rust/myotis-wire/src/snap/`):

| Request | Asked for | Checked against |
|---|---|---|
| `GetAccountRange` | the range starting at `keccak256(address)` | the trusted state root |
| `GetStorageRanges` | the range starting at `keccak256(slot)` in one account | that account's **proven** `storageRoot` |
| `GetByteCodes` | one code hash | `keccak256(code) == codeHash` |

(`GetTrieNodes` is never sent — snap/2 removed it.)

A range response that starts at `keccak256(address)` comes with a proof of its left
boundary, and that boundary proof *is* the Merkle-Patricia proof for exactly that key.
Myotis verifies it as a single-key proof (`verify_proof` in `rust/myotis-core/src/trie.rs`)
and ignores the range entries the peer lists next to it:

- **Found** — the proof reaches a leaf for the key. Nonce, balance, `storageRoot` and
  `codeHash` are decoded strictly from **that leaf**, never from the peer's own listing.
- **Absent** — a valid exclusion proof: the account is reported empty, the slot as zero.
- **Invalid** — a missing node, malformed RLP, a cycle, or an empty proof for a non-empty
  root. Nothing from that answer is used: on a head read the same peer gets one more try at its
  own head (verified by `headerChain`, §6) before it is struck, and the hedged race moves on.

Storage proofs are anchored at the account's proven `storageRoot`, so a peer cannot
substitute another contract's storage. An empty storage root answers zero and an empty code
hash answers empty code without asking anyone. Execution clients keep only recent state
(about the last 128 blocks), so a peer answering with an empty proof "does not hold that
root" — a head read then takes the `headerChain` fallback above. Reads race up to 3 peers,
starting a new one every 3 seconds (`HEDGE_DELAY`). The Java engine uses the same three
messages (its `SnapPeer.getTrieNodes()` is an adapter over them, despite the name). Its
wallet-facing reads verify with `core`'s `MerklePatriciaProofVerifier` (through
`SnapBackedStateOracle`); the operator `get-account` query uses `MerklePatriciaVerifier`.

## 8. Blocks, transactions and receipts

- **Headers** are served from a window fetched in one request and pinned to an attested
  hash: the window's last header must hash to the attested (or finalized) block hash, and
  every link must match its `parentHash`. Blocks are served at most 512 back from the head.
- **Transactions** — the block body's transactions are rebuilt into their ordered trie
  (key = `RLP(index)`) and the root must equal the header's `transactionsRoot`.
- **Receipts** — rebuilt the same way against `receiptsRoot`; their count must match the
  verified body. eth/69 peers send receipts without a bloom, so Myotis recomputes it.
- **Logs** (`eth_getLogs`, Rust engine) come from the opt-in log index. Every log the node walked
  itself was checked against `receiptsRoot`; a span imported from a seed was not, and
  `eth_getLogs` cannot yet tell the two apart (§11). Ranges outside its coverage are refused. See
  [eth-getlogs-design.md](eth-getlogs-design.md).

## 9. Contract calls and gas estimation

`eth_call` and `eth_estimateGas` (and, on the Rust engine only, `eth_createAccessList`) run a
local EVM (revm in the Rust engine, Besu in the Java engine) whose database is the
proof-verified state above: every account, storage slot and bytecode the execution touches is
fetched over snap and verified against the block's state root before the EVM sees it
(`rust/myotis-evm/src/database.rs`, `PoolOracle` in `rust/myotis-net/src/el/evm.rs`). A
prefetch loop batches those reads. If
some value cannot be proven, the call fails as retryable — it never runs on a guessed value.
The proof cache is keyed by the root a value was proven against, so a value is never
reused under a root it was not proven for.

## 10. Sending a transaction

Myotis never holds keys: the wallet signs, Myotis gossips the bytes to devp2p peers. Before
it does, it checks what geth's transaction pool checks — the sender can pay, the nonce is
not used — but only against a balance and nonce **proven at the attested head**, and only
when that head is fresh. When it cannot judge, it sends anyway rather than block a valid
transaction (`rust/myotis-net/src/el/send_check.rs`; Java: `SendCheck`).

---

## 11. What is not verified

- **Withholding.** A peer can refuse to answer or answer slowly. That is a liveness problem,
  not a correctness one: the node reports `CATCHING_UP` (beacon side) or a retryable error
  (execution side), never a wrong value.
- **Completeness of history.** A proof shows that a value is in a tree; nothing in the
  protocol proves that a list of *your* transactions is complete. The transaction-history
  scan (TrueBlocks, `:tx-history`) is debug-only and unverified.
- **Old data.** State is served at the head and the finalized block only; blocks up to 512
  back; the header walk under 8192 blocks. The historical accumulators that would extend
  this (pre-Merge epoch accumulator, `historical_summaries`) are designed but **not built**
  ([implementation-status.md](implementation-status.md)), so today every answer rests on the
  sync-committee chain alone.
- **The clock.** The weak-subjectivity gate and the `SYNCED` check read the device clock.
- **Simplifications against the light-client spec.** Neither engine implements the spec's
  `best_valid_update` / forced update after `UPDATE_TIMEOUT`; during catch-up both stores also
  rotate to the already-proven next committee when the wall clock has passed the period
  (`force_rotate_if_past_period` / `LightClientStore.forceRotateIfPastPeriod`), and both adopt a
  next committee from the attested state without requiring finality in the store's period.
- **Documented carve-outs.** The light-client server [roost](lc-server-design.md) relays
  self-verifying objects from a local beacon node (wallets verify them exactly as above; a
  relay can withhold but not forge). A [seeded log history](seeded-log-histories.md) is
  served on its publisher's word, bounded by the protocol client's own on-chain root check.
  CCIP-Read gateways are trusted for availability only; the resolver contract verifies their
  answer inside the EVM.
- **Java engine fallback.** If the checkpoint bootstrap fails, the Java engine seeds its sync
  state from an *unverified* finality update (`seedFromFinalityUpdate`, or a local beacon API
  in `seedFromBeaconApi`). Those roots are recorded with `blsVerified=false`, and the account
  query's `stateRootMatch` path does not check that flag. The Rust engine has no such path.
- **Java engine: `stateRootMatch` skips the proof flag.** `VerifiedAccountQuery` and
  `VerifiedStorageQuery` take the fast path before they look at `peerProofValid` /
  `storageProofValid`, and the root they match is the state root of a header the peer picked
  (its own best block). A peer whose header names a state root in the window is therefore
  reported `beaconChainVerified` even when its Merkle proof failed — on any Java run, not only
  after a seed — and the apps' Query card shows such a result as verified. The Rust engine
  verifies every proof before its ladder runs.
- **Java engine: `get-storage` prints the peer's listed value.** The operator storage query
  (daemon `get-storage`, the apps' Query tab) verifies the storage proof but reports the slot
  value the peer *listed* next to it, not the value the proof proves — a peer that sends a
  genuine proof and a different listed value has its own value printed as verified. The Java
  JSON-RPC reads and the Rust engine use the proven leaf.

## 12. Where to look in the code

| Step | Rust engine | Java engine |
|---|---|---|
| Checkpoint, WS gate, sync loop | `rust/myotis-net/src/sync.rs` | `consensus/.../BeaconLightClient.java` |
| Bootstrap and update checks | `rust/myotis-consensus/src/store.rs`, `verify.rs`, `spec.rs` | `consensus/.../lightclient/LightClientProcessor.java`, `SyncCommitteeVerifier.java` |
| SSZ Merkle branches | `rust/myotis-consensus/src/ssz.rs` | `consensus/.../ssz/SszUtil.java` |
| Execution anchor | `rust/myotis-net/src/el/anchor.rs` | `consensus/.../BeaconSyncState.java` |
| stateRootMatch / headerChain | `rust/myotis-net/src/el/verify.rs` | `node-core/.../VerifiedAccountQuery.java`, `VerifiedStorageQuery.java` |
| MPT proofs | `rust/myotis-core/src/trie.rs` | `core/.../trie/MerklePatriciaProofVerifier.java` (wallet reads), `consensus/.../proof/MerklePatriciaVerifier.java` (operator queries) |
| SNAP requests and checks | `rust/myotis-wire/src/snap/` | `rpc-backend/.../snap/EthHandlerSnapPeer.java`, `myotis-evm/.../world/SnapBackedStateOracle.java` |
| Tx / receipt trie roots | `rust/myotis-core/src/triehash.rs` | `consensus/.../proof/OrderedTrieRoot.java` |
| EVM over verified state | `rust/myotis-evm/`, `rust/myotis-net/src/el/evm.rs` | `myotis-evm/.../world/SnapBackedStateOracle.java` |

### Constants

| What | Value |
|---|---|
| Sync committee | 512 members, one period = 8192 slots (~27 h on mainnet) |
| Signature threshold | ≥ 342 of 512 (`participants × 3 ≥ 1024`) |
| Execution payload header | gindex 25, depth 4, in the block body |
| Current / next sync committee | gindex 54 / 55 (pre-Electra), 86 / 87 (Electra, Fulu), 2945 / 2946 (Gloas) |
| Finalized root | gindex 105 (pre-Electra), 169 (Electra, Fulu), 735 (Gloas) |
| Gloas execution block hash | gindex 2856 (812 for a pre-Gloas header in the Gloas shape) |
| Weak-subjectivity bound | 13 periods (mainnet, Sepolia), 3 (Gnosis) |
| SYNCED finality slack | 5 epochs |
| Header-chain walk | < 8192 blocks (Rust: also one peer response, ≤ 1024 headers on geth) |
| Block-number pin served from head state | head − 64 … head + 16 |
