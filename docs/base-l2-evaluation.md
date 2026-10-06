# Base (Coinbase's L2) on Myotis — evaluation

Status: **evaluation, nothing built.** Written 2026-10-06 from the public specs,
on-chain observation of Base's L1 contracts on 2026-10-05/06, and this repo's
trust rules. Numbers quoted here were measured on those two days and will drift;
re-measure before acting on them.

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
  forks — Azul since 2026-05-28, Cobalt since 2026-09-30, Denim planned for
  October 2026 with 200 ms native blocks).
- **Data availability.** Transactions are posted to mainnet as EIP-4844 blobs
  by the batcher (`0x5050F69a9786F081509234F1a7F4684b5E5b76C9`, address
  pinned in the L1 `SystemConfig`) into the batch inbox
  `0xff00…8453`. The encoding is the OP derivation format: batcher
  transaction → channel frames → Brotli-compressed channel (quality 9) → span
  batches → typed transactions.
- **Proof system (Azul, live on mainnet since 2026-05-28).** Every 600 L2
  blocks (20 minutes; 6000 blocks of 200 ms after Denim) the Base proposer
  turns a checkpoint into an `AggregateVerifier` dispute game (game type 621,
  0.05 ETH bond) on mainnet. The game carries one or two proofs over the
  same claimed output root: a **TEE** proof (AWS Nitro enclave re-executes
  the 600 blocks and signs the root; the TEE signer allowlist is managed by
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
engine's `VerifiedAccountQuery` and `VerifiedRpcBackend`). On today's Base
that is 4.5 h, after Denim's 200 ms blocks 27 minutes — the bound would have
to become time-based, per network.

Which anchor sits at the start of the walk decides whether the walk exists at
all. Today there is no rule-conforming anchor (§3.2), so the cases are:

- **Unresolved TEE proposal** (rated no): 32–52 min old, head within reach.
  This is what the "anchor → `headerChain` → head" design of this section
  runs on today, and it presupposes accepting TEE trust.
- **Resolved game** (rated no): ≥ 5 days old (1 day on the dual-proof path),
  ~216,000 Base blocks — no header chain reaches the head; reads would be
  served at the anchor's height only.
- **Posted ZK proof** (rated yes, hypothetical today): L1-verified the moment
  the `verifyProposalProof` call lands, so proposal-aged and within
  header-chain reach. This is the payoff behind open decision 1 in §8. One
  caveat belongs on §3.2's "yes": a game's proof covers the 600-block
  transition from the **parent claim's** root to its own, so a lone ZK proof
  on an otherwise TEE-only chain of games still inherits TEE trust for its
  starting root. Rule-conforming all the way down needs an unbroken run of
  ZK-backed games back to a root the client already holds (a previously
  accepted ZK anchor, or a resolved one — which, with ZK on every game, is
  the 1-day path and a cryptographic chain rather than "unchallenged").

## 4. Weaker evidence inside the 32–52 minute window

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
   confirms or refutes 32–52 min later. Still "peer trusted" under the rule.
4. **Flashblocks and peer quorum.** Flashblocks are builder-signed 200 ms
   partial blocks ahead of the sequencer signature — UX preview only. Asking
   several Base full nodes over devp2p for the same header is a sanity check
   against one lying peer, sybil-able and not a proof. (Base full nodes do
   not trust the sequencer either: they derive from L1 and re-execute, so
   their safe head is independently recomputed — by someone else.)

Not possible in the window: recomputing ourselves. Re-executing one Base block
over snap proofs is conceivable with the Myotis EVM, but its parent state root
would have to be anchored, which means every block since the anchor — ~1000
Base blocks per half hour.

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
   transactions; hash them to find T. Map the span batch's relative
   timestamp to a Base block number (2 s blocks today; Denim's 200 ms
   blocks and BaseTime change this — pin per fork). Missing: all of it,
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
alone, and on Base today that anchor is TEE-attested and 32–52 minutes old.

## 7. What Base would change in Myotis (if built)

- **Rust engine only.** Besu has no OP-Stack semantics; the Java engine
  drops out as it does for Tor. In Rust: `op-revm` instead of plain `revm`,
  Base's fork schedule in `rust/myotis-evm/src/fork.rs`, the L1 data fee
  from the `GasPriceOracle` predeploy for gas estimation.
- **Decoders.** Base's wire shapes differ from mainnet's and every verifier
  that rebuilds a canonical form has to know it, or the anchor →
  `headerChain` → snap path of §3 fails before it starts: the header
  (Holocene packs the EIP-1559 parameters into `extraData`, Isthmus
  repurposes `withdrawalsRoot` as the L2-to-L1 message passer's storage root
  and fixes `requestsHash` to the empty hash — `rust/myotis-core/src/header.rs`
  decodes by field count and must accept Base's layout per fork), bodies
  (deposit transactions, type `0x7E`, in every block — fee reads, log index,
  `transactionsRoot` rebuilds) and receipts (deposit receipts carry
  `depositNonce` and `depositReceiptVersion`, which enter `receiptsRoot`).
  §5.2's cost estimate is for rung 1 only; these are on top.
- **Network.** An `ElConfig` for chain id 8453 with bootnodes and fork id.
- **Architecture.** A dependency between `ChainStack`s: Base is only as
  synced as mainnet, and its status (`SYNCED`, `verifyMethod`) needs a Base
  flavour on `:myotis-api`, with the rung of §4 visible to callers.
- **Moving target.** Base V1 is a young, independent stack; Kona replaces
  Cannon, Denim changes block time and timestamps, contract addresses and
  proposal layout move. Pins would need the same care as the checkpoints.

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
[Denim overview](https://basehub.org/specifications/denim-overview/),
[base/base](https://github.com/base/base) (PRs
[#5034](https://github.com/base/base/pull/5034),
[#5343](https://github.com/base/base/pull/5343),
[#5353](https://github.com/base/base/pull/5353)),
[Base migration off the OP Stack](https://chainstack.com/base-migration-op-stack/),
[L2BEAT: Base](https://l2beat.com/scaling/projects/base),
[Immunefi: ZK interval mismatch prevents dual-proof fast finality](https://reports.immunefi.com/base/75249-sc-medium-rc-28-zk-interval-mismatch-prevents-dual-proof-fast-finality).
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
