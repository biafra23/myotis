# Base (Coinbase's L2) on Myotis — evaluation

Status: **evaluation, nothing built.** Written 2026-10-06 from the public specs,
on-chain observation of Base's L1 contracts on 2026-10-05/06, and this repo's
trust rules. Numbers quoted here were measured on those two days and will drift;
re-measure before acting on them.

**Updated 2026-11-06 for Denim** (200 ms blocks, live on mainnet since
2026-11-05 18:00 UTC): §1.1 is new, and §3.1.1 re-measures the proposal cadence
on 21 games after activation. The consequence that matters most is in §3.3:
the 8192-block header-chain bound now covers 27 minutes, less than the
shortest measured proposal lag, so no L1 anchor of any kind reaches the
head without changing that bound. Everything not marked as re-measured is
still the 2026-10 observation.

**Short answer: Base can be supported, but not as a fourth network next to
mainnet, Sepolia and Gnosis.** Base has no sync committee, so it has no trust
anchor in the sense of [CLAUDE.md §Trust](../CLAUDE.md). The only anchor that
fits the trust model is the state of Base's own contracts on mainnet, which
Myotis already reads verified today. Everything below follows from that: what
such an anchor proves, how old it is, what is possible before it lands, what the
RPC landscape offers (nothing verifiable), and what building it would cost.

## 1. Base from Myotis's point of view

- **Stack.** Base left the OP Stack in February 2026 for its own Reth-based
  "unified codebase" ([base/base](https://github.com/base/base)): sequencer,
  consensus layer, batcher and proof system in one repository. Execution
  semantics are still OP-Stack-derived (deposit transactions of type `0x7E`,
  the L1 fee component, the OP fork sequence up to and including Base's own
  forks — Azul since 2026-05-28, Beryl since 2026-06-25, Cobalt since
  2026-09-30, Denim with 200 ms native blocks since 2026-11-05 (§1.1);
  Everest is announced, without dates).
- **Data availability.** Transactions are posted to mainnet as EIP-4844 blobs
  by the batcher (`0x5050F69a9786F081509234F1a7F4684b5E5b76C9`, address
  pinned in the L1 `SystemConfig`) into the batch inbox
  `0xff00…8453`. The encoding is the OP derivation format: batcher
  transaction → channel frames → Brotli-compressed channel (quality 9) → span
  batches → typed transactions.
- **Proof system (Azul, live on mainnet since 2026-05-28).** Every 20
  minutes of L2 time — 600 blocks before Denim, 6000 since (§3.1.1) — the
  Base proposer turns a checkpoint into an `AggregateVerifier` dispute game
  (game type 621, 0.05 ETH bond) on mainnet; the game's L2 block number is
  its `l2SequenceNumber()` (an `l2BlockNumber()` call reverts). The game
  carries one or two proofs over the
  same claimed output root: a **TEE** proof (AWS Nitro enclave re-executes
  the checkpoint's blocks and signs the root; the TEE signer allowlist is managed by
  the Base Coordinator multisig, without the Security Council) and
  optionally a **ZK** proof (SP1 Hypercube, verified on L1 through the
  `SP1VerifierGateway`; posting one is permissionless and a ZK proof
  overrides a contradicting TEE proof). Finalization: 5 days for a
  one-proof game (the docs say 7; L2BEAT and the contracts say 5, and 5 is
  what we measured), 1 day when TEE and ZK agree.
- **Peers.** Base nodes (op-geth, Reth) speak discv4/discv5, RLPx, eth/68
  and snap/1 — the same wire protocols Myotis already implements, so the
  data-sources rule (devp2p and libp2p only) is satisfiable. Base's state is
  larger than mainnet's; a proof client never downloads it.
- **Governance.** Base is L2BEAT Stage 1. The Base Governance Multisig
  (2/2 of Base Coordinator 3/6 and Security Council 8/11) can pause
  withdrawals and blacklist dispute games without delay; contracts are
  instantly upgradable. A light client cannot be more secure than that.

### 1.1 Denim (mainnet 2026-11-05)

Measured 2026-11-06 against `mainnet.base.org` (blocks, receipts) and a public
mainnet RPC (the L1 games of §3.1.1). That is observation for this document
only, through trusted endpoints, not a data path for the wallet. Spec:
[Denim overview](https://docs.base.org/upgrades/denim/overview.md),
[200 ms blocks](https://docs.base.org/base-chain/specs/upgrades/denim/200ms-blocks.md).

- **Activation.** Base Sepolia on 2026-10-21 18:00 UTC; Base mainnet at
  block **53,556,127**, the first block with timestamp `1793901601`
  (2026-11-05 18:00:01 UTC). Block 53,556,126 is the last 2 s block.
- **200 ms blocks.** Five complete canonical blocks per second, each with
  its own number, hash, state root, receipts and unsafe/safe/finalized
  lifecycle. Measured: block 53,676,360 (`timestampMs` 1793925647600) is
  exactly 120,233 × 200 ms after the activation block (1793901601000).
- **Timestamps stay whole seconds in the header.** `header.timestamp` and
  EVM `block.timestamp` are Unix seconds, so five consecutive blocks share
  one header timestamp. The sub-second part
  travels in a new **BaseTime deposit** at `tx[1]` of every block: type
  `0x7E`, from `0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001` to the BaseTime
  predeploy `0x4200000000000000000000000000000000000030`, calldata
  `setTimestampMillisPart(uint16)` (`0x86bdf394`) with 0, 200, 400, 600 or
  800, source-hash domain 3, gas limit 1,000,000, not a system
  transaction. Full time: `T_ms = 1000 · header.timestamp +
  timestamp_millis_part`, and consecutive blocks are exactly 200 ms apart
  (no skipped slots). So every Base block now opens with **two** deposits
  (L1 attributes at `tx[0]`, BaseTime at `tx[1]`; measured on 53,556,127,
  53,556,128 and 53,676,360), and the BaseTime deposit has an ordinary deposit
  receipt (`depositNonce`, `depositReceiptVersion` 1).
- **No header-format change.** The `timestampMs` field that Base's RPC now
  returns for blocks and headers, and `blockTimestampMs` for transactions,
  logs and receipts, are RPC additions computed from the body. They are not
  header fields and do not enter the block hash.
- **EIP-1559 parameters moved with it.** `extraData` (Holocene's EIP-1559
  parameters in the version-1 layout that Jovian extended with a minimum base
  fee: 1 + 4 + 4 + 8 bytes) changed at
  activation from `0x01 00000064 00000005 00000000004c4b40` to
  `0x01 000003e8 00000005 00000000004c4b40`: base-fee-change denominator 100
  → 1000, elasticity still 5, minimum base fee still 5,000,000 wei. That is
  the observed value, not a spec statement. Anything that recomputes the
  base fee must read these parameters per block, never pin them.
- **Derivation.** Since activation, block timestamps come from the Denim
  activation schedule and the absolute L2 block number, not from batch data
  or a wall clock.
- **Flashblocks are gone.** Base stopped producing them at activation, and
  their streams ended. The canonical 200 ms block replaces them.
- **Contract time.** Block-count durations (timelocks, voting periods,
  vesting, TWAP lookbacks counted in blocks) shrank to a tenth of their
  wall-clock length; `block.timestamp` logic is unaffected. That is Base's
  problem, not ours, except where a Myotis bound is a block count (§3.3).
- **Also in Denim:** tighter B20 precompile transfer rules and a NOT flag
  in its PolicyRegistry, which an OP-aware EVM (§7) has to implement for
  Denim blocks.

## 2. Why a direct Base light client is out

The three shipped networks each hang off a beacon light client:
`ChainConfig` in `rust/myotis-net/src/sync.rs` and `NetworkConfig` need a
checkpoint root, a fork schedule and a `genesis_validators_root`. Base has
none. What it offers instead:

| source of truth | what it is | trust |
|---|---|---|
| sequencer signature on each block ("unsafe head") | one key, Coinbase's | "peer trusted" — excluded by CLAUDE.md |
| derivation from L1 data ("safe head") | re-run the derivation pipeline and execute every L2 block | correct, but a full node, not a wallet; blobs retrievable for ~18 days only |
| proposals on L1 | TEE/ZK-backed output roots in Base's mainnet contracts | readable through Myotis's existing verified mainnet state — the only fit |

## 3. The viable anchor: L1 proposals read through the mainnet light client

An `AggregateVerifier` game commits to an output root
(`keccak256(version ‖ state_root ‖ withdrawal_storage_root ‖ latest_block_hash)`)
for an L2 block number. Myotis reads the game's storage through the path it
already has — sync-committee signatures → beacon-attested mainnet state root →
snap proof into the contract — and gets a Base block hash plus state root. From
there the existing machinery applies against Base peers — `headerChain` walk,
snap/1 account and storage proofs, receipts against `receiptsRoot`, the log
index, the EVM — once the decoders tolerate Base's shapes (§7: header layout,
deposit transactions and their receipt fields). This is item 5 of
[multichain-design.md](multichain-design.md) (cross-chain verification between
two in-process light clients), planned and never built.

### 3.1 What is actually on L1 (measured 2026-10-05/06)

Six games sampled: two from 2026-10-05, two from 2026-10-02, two from
2026-08-25/26.

| quantity | value |
|---|---|
| checkpoint interval | 600 Base blocks = 20 min |
| proposal lands on L1 after the checkpoint's last block | ~32 min (21:07:47 → 21:40:11; 21:27:47 → 21:59:59) |
| age of the newest L1-anchored Base state | 32–52 min |
| proposer of every sampled game | Base Output Proposer `0xc1366F…`, TEE proof |
| second (ZK) proof attached | **none, in any sampled game** |
| resolution | after 5 days, by the Base Challenger `0x819501…` (08-25 23:41 → 08-30 23:44; 08-26 00:58 → 08-31 01:03) |
| 1-day (TEE + ZK) path used | never, in the sample |
| `ZkVerifier` / `SP1VerifierGateway` activity | deployed ~2026-06-02 (Etherscan: "126 days ago" on 2026-10-06), i.e. a few days after Azul's mainnet activation — the ZK arm was wired in after launch; no transactions since, per Etherscan. Etherscan does not reliably list value-less internal calls, but a ZK proof would be an external `verifyProposalProof` call on the game, and none of the sampled games has one |

An Immunefi report from April 2026 describes an intermediate-root interval
mismatch between the ZK prover and the contract that blocked the dual-proof
path on Sepolia; whatever the reason, **the ZK arm is a dispute backstop today,
not part of normal operation.** The question "how old is the L1-verified ZK
proof?" has the answer: there is none.

#### 3.1.1 Since Denim (measured 2026-11-06)

Games 25,795–25,818 of the `DisputeGameFactory` (the 24 newest, all type 621),
read on 2026-11-06 ~01:20 UTC: `l2SequenceNumber()` on each game, with the
L2 block's timestamp from Base.

| quantity | value |
|---|---|
| checkpoint interval before activation | 600 blocks (53,554,560 → 53,555,160 → 53,555,760) |
| the game spanning activation | 53,555,760 → 53,556,360: still 600 blocks, but 366 of them at 2 s and 234 at 200 ms, i.e. 13 min of L2 time |
| checkpoint interval since | **6000 blocks** = 20 min, 20 consecutive games (53,556,360 → … → 53,676,360) |
| proposal lands on L1 after the checkpoint (21 post-activation games) | **29.2–54.8 min**, median 37.6 min; all but one within 29–45 min |
| age of the newest L1-anchored Base state | 29–75 min (lowest just after a game lands; highest just before a game lands: that landing game's own lag + the 20 min since the previous checkpoint, i.e. 54.8 + 20 for the slowest game) |
| status of all 24 games | `IN_PROGRESS` (none older than 5 days, so none resolvable yet) |

Not re-measured here: proposer and challenger identity, which proofs each
game carries (in particular whether any game has a ZK proof since §3.1),
and the 5-day resolution. The ZK question is still what decides §3.2.

### 3.2 Trust quality by proof type

| anchor | trusts | fits CLAUDE.md §Trust? |
|---|---|---|
| ZK proof verified on L1 | the SP1 verifier and its trusted setup, plus the root the proof starts from (§3.3) | yes — cryptographic, but **not posted in practice** |
| TEE proposal | AWS Nitro attestation + Base's TEE allowlist (Coordinator multisig) | no — a new, documented exception at best, like the seeded log histories |
| resolved game (5 days, unchallenged) | 1-of-N honest challenger; today the only challenger is Base's own, and nobody posts ZK proofs | no — "unchallenged" means Base did not dispute itself |
| sequencer signature | Coinbase's sequencer key | no — peer trusted |

Consequence: **today Base cannot be anchored to this repo's standard.** The
first anchor that would qualify appears when Base actually runs the ZK arm.
Until then any Base support rests on a TEE anchor, which is an owner decision
to accept or refuse, never the author's.

### 3.3 Header-chain reach

The header-chain bound is 8192 blocks, pinned in several places that move
together (`MAX_HEADER_CHAIN_GAP` in `rust/myotis-net/src/el/verify.rs` and
`rust/myotis-engine/src/eljson.rs`, which also echoes it to hosts as
`maxHeaderChainGap`, pinned by golden tests on both FFI shapes; the Java
engine's `VerifiedAccountQuery` and `VerifiedRpcBackend`). On 2 s Base blocks
that was 4.5 h. **Since Denim it is 8192 × 200 ms = 27.3 min — shorter than
the shortest proposal lag measured (29.2 min, §3.1.1).** At the moment a game
lands, the head is already ≥ 8,760 blocks past its checkpoint, and up to
~22,440 just before the next one lands (74.8 min × 300 blocks/min). So with the
bound as it is, **no L1 anchor reaches the Base head at any time**; Base needs
its own bound, either time-based or a per-network block count of at least
~22,500 (better with margin: a delayed proposer pushes the lag up, and one of
21 games already took 55 min). The cost is a walk ten times as long per
minute of lag as on 2 s blocks. Because the bound is on the FFI surface
(above), a per-network value is an API change, not a constant edit.

Which anchor sits at the start of the walk decides whether the walk exists at
all. Today there is no rule-conforming anchor (§3.2), so the cases are:

- **Unresolved TEE proposal** (rated no): 29–75 min old. The head is within
  reach **only with a raised bound** (above). This is what the "anchor →
  `headerChain` → head" design of this section runs on, and it presupposes
  accepting TEE trust.
- **Resolved game** (rated no): ≥ 5 days old (1 day on the dual-proof path),
  ~2,160,000 Base blocks (~432,000 on the 1-day path). No header chain
  reaches the head, and reads would be served at the anchor's height only.
- **Posted ZK proof** (rated yes, hypothetical today): L1-verified the moment
  the `verifyProposalProof` call lands, so proposal-aged, and within
  header-chain reach once the bound is raised as above. This is the payoff
  behind open decision 1 in §8. One
  caveat belongs on §3.2's "yes": a game's proof covers the checkpoint's
  transition (600 blocks before Denim, 6000 since) from the **parent claim's** root to its own, so a lone ZK proof
  on an otherwise TEE-only chain of games still inherits TEE trust for its
  starting root. Rule-conforming all the way down needs an unbroken run of
  ZK-backed games back to a root the client already holds (a previously
  accepted ZK anchor, or a resolved one — which, with ZK on every game, is
  the 1-day path and a cryptographic chain rather than "unchallenged").

## 4. Weaker evidence inside the proposal window (29–75 min since Denim)

Four rungs, strongest first. They do not contradict each other; they stack,
and a read could carry its rung and climb as later evidence lands — the same
shape as mainnet's finalized anchor extended to the head by `headerChain`.

1. **Batch data on L1 ("safe head").** Once the blob carrying a Base block's
   transactions sits in a beacon-attested L1 block, the *inputs* of that
   block are covered by Myotis's existing anchor. This proves inclusion and
   ordering of a transaction, not its outcome (no state root without
   execution). It is the **only rung that fully satisfies the trust rule**,
   and it needs no Base peer at all. Cost: §5.
2. **L1 deposits.** An L1→L2 deposit is a mainnet event, verifiable against
   `receiptsRoot`; the protocol forces the sequencer to include it within the
   sequencing window (12 h). "Your deposit will arrive" is provable without
   asking Base anything.
3. **Sequencer signature ("unsafe head").** Base's consensus layer gossips
   every block signed by the unsafe-block signer, whose address Myotis can
   read from the L1 `SystemConfig` by storage proof. This is what Helios does
   (`opstack/src/consensus.rs`: `UNSAFE_SIGNER_SLOT`, `SequencerCommitment::verify`).
   It proves Coinbase committed to the block and makes equivocation
   provable; it does not prove the state root is right. Combined with rung 1
   the only remaining gap is execution correctness, which the TEE proposal
   confirms or refutes 29–75 min later. Since Denim the gossip carries five
   signed blocks a second. Still "peer trusted" under the rule.
4. **Peer quorum.** Asking
   several Base full nodes over devp2p for the same header is a sanity check
   against one lying peer, sybil-able and not a proof. (Base full nodes do
   not trust the sequencer either: they derive from L1 and re-execute, so
   their safe head is independently recomputed — by someone else.) This
   rung used to include Flashblocks, builder-signed 200 ms partial blocks
   ahead of the sequencer signature. Base stopped producing them at Denim
   (§1.1); the canonical 200 ms block is now the earliest signed object.

Not possible in the window: recomputing ourselves. Re-executing one Base block
over snap proofs is conceivable with the Myotis EVM, but its parent state root
would have to be anchored, which means every block since the anchor —
~9,000 Base blocks per half hour since Denim (~900 before).

A read served on a weaker rung must say so (`verifyMethod` carrying the rung;
callers able to demand a minimum) — "applied or refused", never a verified
look for a provisional answer. Whether rung 3 may be shown at all, even
labelled, touches the trust rule and is the owner's call.

## 5. Rung 1 in detail: proving sequencing from L1 blob data

What has to happen to prove "transaction T is in Base's canonical sequence",
and what Myotis already has for it.

### 5.1 The chain of checks

1. **L1 block.** A beacon-attested mainnet header (have: the mainnet light
   client; use the finalized one to rule out L1 reorgs, or the attested head
   with reorg risk).
2. **Batcher transaction.** The body of that block, verified against
   `transactionsRoot` (have: the fee reads do exactly this), filtered to
   `to == batch inbox` and `from == SystemConfig.batcherHash` (have: storage
   proof on L1). Take its `blob_versioned_hashes`.
3. **Blob bytes.** Mainnet has been on Fulu/PeerDAS since 2025-12-03
   (`NetworkConfig`), so blobs are no longer served whole:
   `blob_sidecars_by_range` is gone, blobs travel as 128 **data columns**
   (`/eth2/beacon_chain/req/data_column_sidecars_by_range/1/` and
   `…_by_root/1/`). A cell is 64 field elements, 2048 B; any 64 of the
   128 columns reconstruct a blob by Reed–Solomon recovery over the
   BLS12-381 scalar field, and the code is systematic: under the spec's
   bit-reversed evaluation order the **first 64 columns (indices 0–63)**
   are the original blob, so when peers serve those no decoding is needed.
   Each column sidecar carries that column's cell of **every** blob in the
   block, so 64 columns are 64 × 2048 B = 128 KiB per blob — the full
   original volume of every blob in that L1 block, other rollups included
   ("half" holds only against the 2× extended data). With ~6.7 blobs per
   block on average (September 2026) that is ~858 KiB of cell data per L1
   block touched, plus each sidecar's KZG cell proofs (48 B per blob per
   column), the block's commitments and the inclusion proof — a few percent
   on top.
   Have: libp2p, req/resp framing, snappy, SSZ. Missing: the two protocols,
   the `DataColumnSidecar` SSZ type, column→blob assembly, optional RS
   recovery (field arithmetic + FFT; `blst` has the field, not the FFT).
4. **Blob ↔ commitment.** Recompute the KZG commitment of the reconstructed
   blob (one 4096-point G1 multi-scalar multiplication in the Lagrange
   basis; `blst` has Pippenger; the trusted setup's G1 points are ~192 KiB
   to embed) and check `sha256(commitment)` with the `0x01` version byte
   against the batcher transaction's versioned hash. This avoids KZG proof
   verification entirely — the recomputed commitment is self-verifying.
   Missing: all of it; there is no KZG code in the tree (revm's c-kzg
   backend is deliberately off).
5. **Frames → channel → batches.** Parse frames out of the blob (the OP
   blob encoding packs 127 bytes into every 4 field elements, using the 6
   spare high bits of each element's first byte — 130,044 bytes per blob,
   not a plain 31-of-32), assemble the channel
   (frames may span several batcher transactions and L1 blocks),
   Brotli-decompress (pure-Rust `brotli` crate), decode span batches
   (prefix: relative timestamp, L1 origin, parent/origin checks; payload:
   block count, origin bits, per-block tx counts, then the columnar
   transaction fields — contract-creation bits, y-parity bits, signatures,
   `to`s, data, nonces, gas, protected bits) and rebuild the typed
   transactions; hash them to find T. Map the batch to Base block
   numbers: before Denim by 2 s timestamps; since Denim, derivation takes
   block timestamps from the activation schedule and the absolute block
   number, not from batch data (§1.1). Five blocks share each whole-second
   timestamp, so a block's number presumably follows from its position
   counted from the activation block (53,556,127 at `T_ms`
   1793901601000, +200 ms per block) rather than from a timestamp lookup.
   That is an inference: the Denim spec pages do not say whether the
   span-batch encoding itself changed (a per-block or millisecond field, a
   parent-number reference), so take the mapping from base/base's
   derivation code before writing the decoder. The BaseTime deposit's value
   is fixed by the schedule and the spec places it in the Engine API
   payload attributes (`transactions[1]`), so like the L1-attributes
   deposit it is expected to be derived rather than batched; confirm that
   in the same code, or the decoder looks for it among the batch's
   transactions. Missing: all of it,
   ~1.5–2 k lines; reference implementation `kona-derive` (Rust, OP Labs,
   what Base's own stack builds on) is the source of conformance vectors,
   but too heavy (alloy) to depend on under this repo's dependency policy.
6. **Derivation validity.** A batch in a blob is not automatically
   canonical: derivation drops batches with a bad timestamp, a failed
   parent/origin check, or past the sequencing window. The decoder must
   apply at least those rules, or a posted-but-dropped batch is reported as
   sequenced — the misleading-answer failure CLAUDE.md forbids.

### 5.2 Cost per proven transaction

| | estimate |
|---|---|
| download | ~0.9–2.6 MiB (64 columns ≈ 858 KiB × the 1–3 L1 blocks a channel spans) |
| compute | one 4096-point MSM per blob (hundreds of ms on a phone with `blst`), Brotli of ≤ ~750 KiB, span-batch decode; RS recovery only when columns 0–63 are unavailable |
| latency after the Base block | the batcher's posting cadence — minutes typically, up to the 12 h sequencing window |
| new code | two CL req/resp protocols + SSZ; column assembly; KZG commitment; frames/channel/Brotli/span-batch decoder with derivation rules; Base chain parameters; a new `ChainHandle` read (e.g. `sequencingStatus(txHash)`) on both FFI shapes with golden tests |
| engines | Rust only (like Tor); the Java engine never gets it |
| size | 4–5 PRs — a multi-PR plan, so a `feature/<topic>` branch per CLAUDE.md |

Note the boundary: [implementation-status.md](implementation-status.md) §7 and
[architecture-doc.md](architecture-doc.md) list "EIP-4844 blob-sidecar gossip"
as out of scope (L2-sequencer territory). This is req/resp retrieval of
specific columns, not gossip, but it is the same neighbourhood and the owner
should say so explicitly before it is built. Blob retention (~18 days) bounds how far back a sequencing proof can
reach; that is fine for "did my transaction land", useless for history.

## 6. RPC servers on Base

Free, permissionless endpoints exist; verifiable ones do not.

- **Public endpoints.** `mainnet.base.org` is run by Coinbase, rate-limited,
  without SLA and explicitly "not for production" per Base. Free tiers:
  Coinbase CDP Node, PublicNode, Ankr, dRPC and others. All are trusted
  servers.
- **Decentralized RPC markets** (Lava, POKT) spread the trust over several
  operators; they do not remove it.
- **Helios `opstack` mode** is the only light client for Base. It verifies
  that Coinbase's sequencer signed a block (signer address read from L1 by
  storage proof), not that the block is correct — rung 3 above.
- **Proof-shaped answers** (`eth_getProof`) from any RPC are checkable
  against a state root; Myotis already does this over snap/1. The bottleneck
  is the trusted root, i.e. the anchor question of §3, not the transport.

An RPC cannot create verifiability the chain itself does not offer. For
Myotis, Base nodes over devp2p are the same free, permissionless data source
they are on mainnet; whether the data is *verified* is decided by the anchor
alone, and on Base today that anchor is TEE-attested and 29–75 minutes old
(§3.1.1).

## 7. What Base would change in Myotis (if built)

- **Rust engine only.** Besu has no OP-Stack semantics; the Java engine
  drops out as it does for Tor. In Rust: `op-revm` instead of plain `revm`,
  Base's fork schedule in `rust/myotis-evm/src/fork.rs` (through Denim:
  the BaseTime predeploy and the tightened B20 rules), the L1 data fee
  from the `GasPriceOracle` predeploy for gas estimation.
- **Decoders.** Base's wire shapes differ from mainnet's and every verifier
  that rebuilds a canonical form has to know it, or the anchor →
  `headerChain` → snap path of §3 fails before it starts: the header
  (Holocene packs the EIP-1559 parameters into `extraData`, Jovian extends
  that to a 17-byte version 1 with a minimum base fee — what Base carries
  today, §1.1 — Isthmus
  repurposes `withdrawalsRoot` as the L2-to-L1 message passer's storage root
  and fixes `requestsHash` to the empty hash — `rust/myotis-core/src/header.rs`
  decodes by field count and must accept Base's layout per fork), bodies
  (deposit transactions, type `0x7E`, in every block, and since Denim two
  of them, the L1-attributes deposit at `tx[0]` and the BaseTime deposit at
  `tx[1]` (§1.1) — fee reads, log index, `transactionsRoot` rebuilds) and
  receipts (deposit receipts carry
  `depositNonce` and `depositReceiptVersion`, which enter `receiptsRoot`).
  §5.2's cost estimate is for rung 1 only; these are on top. Denim adds
  no header field (`timestampMs` is RPC-only), but anything that shows a
  Base block's time below the second has to read the BaseTime deposit, and a
  base-fee check has to read `extraData`'s EIP-1559 parameters, which
  changed at Denim (§1.1).
- **Header-chain bound per network.** Since Denim the 8192-block bound
  cannot reach the Base head from any L1 anchor (§3.3). Base needs its own
  bound before the anchor → `headerChain` path exists at all, and the bound
  is part of the FFI surface (`maxHeaderChainGap`).
- **Network.** An `ElConfig` for chain id 8453 with bootnodes and fork id.
- **Architecture.** A dependency between `ChainStack`s: Base is only as
  synced as mainnet, and its status (`SYNCED`, `verifyMethod`) needs a Base
  flavour on `:myotis-api`, with the rung of §4 visible to callers.
- **Moving target.** Base V1 is a young, independent stack; Kona replaces
  Cannon, Denim changed block time, timestamps and the checkpoint interval
  in blocks (§1.1, §3.1.1), Everest is announced without dates, and
  contract addresses and proposal layout move. Pins would need the same care as the checkpoints.

## 8. Open decisions (owner's)

1. Is a ZK proof verified on L1 an acceptable trust anchor (a new kind next
   to sync-committee signatures and the accumulators)? Moot until Base posts
   any; worth deciding now so the first one can be used.
2. Is a TEE anchor acceptable as a documented exception, and if so, how is
   it labelled to the wallet?
3. May a sequencer-signed (rung 3) answer be shown at all, labelled as such?
4. Is retrieving data columns from the CL (rung 1) inside the "blob
   sidecars out of scope" line or outside it?
5. Is Base worth 4–5 Rust-only PRs before any of 1–3 resolves in its
   favour? Rung 1 and 2 stand on their own under the current rules; the
   state reads do not.

## Sources

Base: [Azul proof system](https://docs.base.org/base-chain/specs/upgrades/azul/proofs),
[Introducing Base Azul](https://blog.base.dev/introducing-base-azul),
[Base adds ZK proofs with SP1](https://blog.succinct.xyz/base-sp1/),
[Denim overview](https://docs.base.org/upgrades/denim/overview.md),
[Denim 200 ms blocks](https://docs.base.org/base-chain/specs/upgrades/denim/200ms-blocks.md),
[upgrades overview](https://docs.base.org/upgrades/overview),
[Denim overview (basehub)](https://basehub.org/specifications/denim-overview/),
[base/base](https://github.com/base/base) (PRs
[#5034](https://github.com/base/base/pull/5034),
[#5343](https://github.com/base/base/pull/5343),
[#5353](https://github.com/base/base/pull/5353)),
[Base migration off the OP Stack](https://chainstack.com/base-migration-op-stack/),
[L2BEAT: Base](https://l2beat.com/scaling/projects/base),
[Immunefi: ZK interval mismatch prevents dual-proof fast finality](https://reports.immunefi.com/base/75249-sc-medium-rc-28-zk-interval-mismatch-prevents-dual-proof-fast-finality).
On-chain, 2026-11-06 (§1.1, §3.1.1): Base blocks and receipts from
`mainnet.base.org`, the `DisputeGameFactory`'s games 25,795–25,818
(`gameAtIndex`, then `l2SequenceNumber()` / `status()` on each game) from a
public mainnet RPC — observation for this document, not a wallet data path.
On-chain (Etherscan, 2026-10-05/06):
[DisputeGameFactory](https://etherscan.io/address/0x43edB88C4B80fDD2AdFF2412A7BebF9dF42cB40e),
[AggregateVerifier](https://etherscan.io/address/0xeF9eCeA15265321753047EBF7D54C858D53cB94f),
[ZkVerifier](https://etherscan.io/address/0xB88D95bDf6972508942d184866890c1834219B75),
[SP1VerifierGateway](https://etherscan.io/address/0xdc32E228636273285Befa5F001dBB5142517C106),
games [2026-08-26](https://etherscan.io/address/0x79E3DbB82883630ef6ADE886Cd05Cea8ab3EDAFb),
[2026-08-25](https://etherscan.io/address/0x93c3288e7a3b71c77147b92674a6547399752d8c),
[2026-10-02](https://etherscan.io/address/0xBE35d9a0D2105ff963B729Fc38b255aa6d110872),
[2026-10-05](https://etherscan.io/address/0x1fbB80AA30b64CcA6FbA5C5D38D93F2519fc2003).
Ethereum: [Fulu p2p interface](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/p2p-interface.md),
[OP Stack derivation spec](https://specs.optimism.io/protocol/derivation.html),
[blob usage, September 2026](https://www.bankless.com/read/news/ethereum-blob-usage-new-record.md).
RPC: [Base public RPC limits](https://onfinality.io/en/learn/base-rpc-rate-limits-and-reliability),
[Coinbase CDP Node](https://docs.cdp.coinbase.com/data/node/overview),
[Helios `opstack/src/consensus.rs`](https://github.com/a16z/helios/blob/master/opstack/src/consensus.rs).
