# State on Swarm: serving what SNAP serves, verifiably

Research note (2026-11-05). Question: how could the state Myotis fetches over
SNAP today be put on Swarm, so that it reads efficiently, verifies the same
way, and costs what someone can pay?

Status: research only. Nothing in Myotis reads from or writes to Swarm. This
note builds on [swarm-read-economics.md](swarm-read-economics.md), which
priced reads and the free bandwidth tier.

Sources: the Myotis code cited inline; Bee `master` at `a0042546`
(2026-11-04); live reads of the Gnosis PostageStamp contract and Swarmscan;
ethPandaOps' state tables; and our own churn measurements
(`scripts/state_churn.py`, §3). Figures marked **estimate** are derived, not
measured.

## In plain words

Ethereum's state is a huge tree of index cards. Every account and every
contract variable is a card. Each card carries a fingerprint (its hash), and
every card above it lists the fingerprints of the cards below. The top
fingerprint, the *state root*, is the one value Myotis trusts, because the
beacon light client proves it.

Over SNAP, Myotis asks a full node: "show me Alice's card, and the chain of
cards from the top down to it." The node looks it up and answers in one reply,
about nine cards. Myotis checks each card against the fingerprint on the card
above it, up to the trusted root. A peer can refuse to answer, but it cannot
lie.

Swarm is a warehouse of 4 KB boxes, and it differs from a full node in three
ways:

- **Nobody looks things up for you.** You can only ask for "box #X". To find
  Alice's card, Myotis opens the top box, reads which box holds the next card,
  and opens that one. That is about nine trips one after another for an
  account, and fifteen for a token balance.
- **Rent is paid per box, full or not.** A card averages 360 bytes, so a box
  holding one card wastes about 90% of the rent.
- **The tree changes every block.** Every mainnet block rewrites about 7,400
  cards. Someone has to upload them and pay their rent.

The checking does not change. A card from Swarm is checked exactly like a card
from SNAP. Swarm can lose cards, and then Myotis asks SNAP instead, but it
cannot fake one.

## Short answer

- **Verification is solved by construction.** Every node fetched from Swarm
  is checked by keccak against the same verified state root SNAP proofs use,
  and the nodes Myotis collects form an ordinary proof for
  `myotis_core::trie::verify_proof`. The publisher, its signatures and its
  postage stamps add no trust. A hostile publisher can withhold or delay
  data; it cannot forge it.
- **Efficiency is the hard part, and it is a layout problem.** Swarm cannot
  answer queries, so the client walks the trie. A plain walk is about 9
  sequential chunk fetches for a mainnet account and about 15 for an ERC-20
  balance, against SNAP's 1–2 round trips.
- **Recommended layout:**
  - *Pages:* each trie node is a single-owner chunk whose id is the node's
    own keccak hash. A page also carries the node's leaf children, so its
    content never changes.
  - *Jump tables:* each published root gets a table keyed by root and key
    prefix, so the first fetch returns the top four levels at once.
  - *Code store:* contract code is published once per code hash.

  Together these bring a balance read down to about 8 sequential fetches, and
  an account read to about 5.
- **Publish per finalized checkpoint, not per block.** That is one root per
  epoch: 6.4 min on mainnet, 80 s on Gnosis. It is the root Myotis's
  `finalized` reads use. Once Amsterdam is live, the block access lists
  Myotis already follows carry those reads up to the head (§7.3).
- **Volumes (measured):**
  - Mainnet rewrites about 7,400 trie nodes per block, 2.5 MiB.
  - Gnosis rewrites about 570 nodes per block.
  - Publishing once per epoch instead of every block merges repeated writes:
    to 41–44% on Gnosis (three epochs) and to 57% on mainnet (two
    epochs).
- **Capacity is the binding constraint, not money.**
  - Swarm currently holds about 4.3 billion chunks (about 16 TiB) of unique
    data.
  - Mainnet's full state is 2.9 billion trie nodes, about 0.76 billion chunks
    with leaves folded into their parents. That is 18% of the network, for
    about 97,000 BZZ a year of postage (≈$3,900).
  - Contract code is cheap: about 7 million chunks, about 900 BZZ a year.
- **What Swarm is good for here, in order:**
  1. Contract code.
  2. State at finalized checkpoints, which is a SNAP fallback when no snap
     peer is reachable.
  3. Historical state, which SNAP never serves (peers keep 128 blocks).

  Swarm does not replace SNAP for head reads. From Amsterdam on, it can
  supply their starting proof (§7.3).
- **What Swarm itself could change (§9):**
  - Keccak-addressed chunks.
  - Chunks priced by size.
  - A recursive "walk this path" retrieval.

  With those, the layout reduces to about two round trips per read and
  roughly a quarter to an eighth of the cost.

## 1. What SNAP gives Myotis today

Myotis uses three snap messages, all verified on fetch against a state root
from the verified header chain (`rust/myotis-wire/src/snap/fetch.rs`):

| Read | Request | Verified by |
|---|---|---|
| Account | `GetAccountRange` from `keccak(address)` with a small byte budget; the response's left boundary proof is the account's Merkle path | `verify_account` → `verify_proof(stateRoot, keccak(address), proof)` |
| Storage slot | `GetStorageRanges` for one slot | `verify_storage` against the account's proven `storageRoot` |
| Code | `GetByteCodes` | `keccak(code) == codeHash` |

The EVM reaches state only through the `SnapStateOracle` trait
(`rust/myotis-evm/src/oracle.rs`): `fetch_account` and `fetch_storage`, each
pinned to one state root, `fetch_bytecode` by code hash, and
`prefetch_batch`. `PoolOracle` (`rust/myotis-net/src/el/evm.rs`) implements
it over the snap peer pool. A
Swarm-backed oracle would implement the same trait.

What SNAP does well, and Swarm will not: **the server computes**. The peer
walks its own database and returns the whole proof, about 5 KB
(docs/disk-and-network-usage.md §4), in one round trip.

What SNAP does badly:

- **Recent roots only.** Snap peers serve the last 128 blocks (snap spec;
  geth's pathdb keeps 128 diff layers, Nethermind's `SnapServingMaxDepth` is
  128).
  - Myotis's `finalized` root is 64–96 blocks old on mainnet, near that edge
    (`ReadAnchor::Finalized` in `evm.rs` says so).
  - Myotis refuses state reads pinned more than 64 blocks below its head
    (`RpcBlockWindow.BLOCK_NUM_LAG_TOLERANCE`), because no peer could prove
    them.
- **Few servers.** Of 14,103 EL nodes counted, 7,014 of the 7,756 geth nodes
  advertise snap (devp2p issue #286, 2026-10-12). Reth and Erigon releases
  serve none, and Besu's server is off by default; Nethermind's is on. Until one answers at the
  anchored root, state reads wait (the `snapServingPeers > 0` gate in
  docs/disk-and-network-usage.md §4).
- **Privacy.** A snap request names `keccak(address)` to the serving peer. That
  is why the BAL follower exists (docs/address-activity.md, *Answering from
  block access lists*).

## 2. What Swarm gives, and what it does not

Facts from Bee `master`. `B/` stands for
`https://github.com/ethersphere/bee/blob/a00425464a1d733732ea9123db703130c722bead/`.

- **Chunks are at most 4,096 bytes of payload.** Two kinds:
  - A *content-addressed chunk* (CAC) is addressed by its BMT hash,
    `keccak256(span ‖ BMT-root)`, where the BMT is a binary keccak tree over
    128 segments of 32 bytes (`B/pkg/bmt/doc.go`, `B/pkg/cac/cac.go`). That is
    **not** `keccak256(payload)`, so a CAC cannot be found from an Ethereum
    hash.
  - A *single-owner chunk* (SOC) is `id(32) ‖ signature(65) ‖ span(8) ‖
    payload`, addressed by `keccak256(id ‖ owner)` (`B/pkg/soc/soc.go`). Whoever
    knows the owner and the id can compute the address.
- **Only the owner can write a SOC.** Storers check the signature. If the same
  address gets a different payload under another stamp, the last arrival wins;
  under the same stamp, the newer stamp timestamp wins
  (`B/pkg/storer/internal/reserve/reserve.go`). Nothing guarantees that
  neighbours converge on one version. **A layout must never rely on
  overwriting.**
- **There are no queries.** A retrieval names one address. Each lookup is one
  routed request through forwarding Kademlia.
- **A missing chunk is slow to give up on.** The origin retries every 1 s and
  tolerates 32 errors; one attempt per peer has a 30 s timeout
  (`B/pkg/retrieval/retrieval.go`). A client needs its own deadline to fall
  back to SNAP quickly.
- **Reads need no stamp and no chequebook.** An ultra-light node reads within
  the free tier (`B/pkg/node/node.go`). Each peer forgives a light node
  450,000 accounting units a second. A light client holding ~100 peers
  measured about 0.5–0.6 MiB/s, ~140 chunks/s, without paying
  (swarm-read-economics.md, *Total free throughput*). Past that a chunk
  costs about 2.7 · 10⁻⁶ BZZ, typically.
- **Writes need postage, paid per chunk, not per byte.**
  - The price, read live on 2026-11-05: `lastPrice()` on PostageStamp
    `0x45a1502382541Cd610CC9068e88727426b696293` (Gnosis) returns **201,656 PLUR
    per chunk per block**. Gnosis blocks are 5 s, and 1 BZZ = 10¹⁶ PLUR, so:
    - **3.48 · 10⁻⁷ BZZ per chunk-day**;
    - **1.27 · 10⁻⁴ BZZ per chunk-year**;
    - **33.3 BZZ per GiB-year** of nominal capacity.
  - An immutable batch of depth 24 is usable to about 68% of its nominal
    capacity (docs.ethswarm.org, *postage stamps*), so real costs run about
    1.2–1.5× higher.
  - Pushing a chunk costs the uploader the same first-hop price as reading it
    (`B/pkg/pushsync/pushsync.go` uses `PeerPrice`).
- **Postage is moving to Ethereum.** Swarm calls this its "homecoming".
  - The September 2026 development update sets "the firm goal to have all
    stamp handling on Ethereum".
  - The October update adds that "postage batches belong on Ethereum without
    compromise", by way of the Ethereum Economic Zone first. The
    redistribution game may follow (community call, 24 September).
  - Gnosis Chain is changing too. GIP-153 turns it into a ZK-proven rollup
    settling on Ethereum, with genesis around the turn of 2026/27 and, per
    wasp issue #540, 2 s blocks. Per that issue, Swarm's contracts count in
    blocks, so an unchanged per-block price would drain stamps 2.5× faster.
  - So every postage figure here is **today's Gnosis contract**, and the
    per-day and per-year values are the ones to compare. The layout does not
    depend on which chain the batches live on. A publisher will buy and top
    up batches on Ethereum.
- **Network capacity.**
  - Each storer keeps a reserve of 2²² chunks, about 16 GiB, and may double it
    once (`B/pkg/storer/storer.go`).
  - Swarmscan lists 4,328 nodes. Of the 995 that return a status, 868
    report storage radius 10 (984 committed depth 10), i.e. 2¹⁰
    neighbourhoods. Unique capacity is therefore about 2³² chunks:
    **4.3 billion chunks, about 16 TiB** (estimate, 2026-11-05).
  - Paid batches add up to about 8.0 billion chunk slots
    (`validChunkCount()`), most of them unused.
- **Latency is not well measured.** The Swarm dashboard shows a 9 ms average
  chunk retrieval and a 57% large-file success rate over 24 h, with no
  published methodology. A phone pays at least one WAN round trip to its first
  hop per chunk. This note uses 100 ms and 300 ms per sequential fetch as two
  illustrations. The real number has to be measured (§10).
- **Rust clients.**
  - [`ant`](https://github.com/freedom-hq/ant) is a Swarm light node in Rust,
    Apache-2.0. Its README says the ultra-light read path and most of the
    upload path are live on mainnet; the mobile artefact is still open.
  - [`vertex`](https://github.com/nxm-rs/vertex) is AGPL-3.0 and
    pre-release.
  - `nectar` provides `no_std` chunk-verification primitives.

## 3. Measurements: what a block rewrites

`scripts/state_churn.py` finds every account and slot a block changed. It uses
`debug_traceBlockByNumber` with the prestate tracer in diff mode, plus
withdrawals and the EIP-4788/2935 system slots. It then proves every changed
key at the block with `eth_getProof`. Every node on a path to a changed leaf
has a new hash, so the union of those proofs is the set of nodes the block
wrote, which is what a publisher must upload. `--window N` merges N blocks into
one delta: what publishing every N-th root costs. Measured 2026-11-05 against
eth.drpc.org and rpc.gnosischain.com, near the head. Two biases, both small
and both upward:
- The mainnet runs predate the script's filter for slots a block left at
  their starting value, so their storage side may run slightly high.
- The filter works per block, so a merged window still counts a slot that
  changes in one of its blocks and reverts in a later one.

| | Mainnet | Gnosis |
|---|---|---|
| Blocks sampled | 9 (26,346,923–26,347,044) | 9 (49,118,809–49,118,850) |
| Transactions / block | 279 | 24 |
| Accounts changed / block | 494 | 49 |
| Slots changed / block | 913 | 76 |
| **New trie nodes / block** | **7,397** (account 3,122, storage 4,275) | **567** (account 283, storage 285) |
| New node bytes / block | 2,594 KiB | 182 KiB |
| Mean node size | 359 B | 329 B |
| Leaf or extension share of new nodes | 19% | 22% |
| Account proof length (nodes) | 8–12, mean 8.9 | 7–9, mean 7.6 |
| Storage proof length (nodes) | 1–11, mean 6.3 | 2–8, mean 4.6 |
| Per day, one node per chunk | 53.3 M chunks | 9.8 M chunks |
| **One epoch merged** | 2 epochs of 32 blocks: 134,304 and 137,581 nodes, **57%** of their blocks summed | 3 epochs of 16 blocks: 3,731–3,964 nodes, **41–44%** of their blocks summed |

What the numbers say:

- **Every changed leaf drags its whole path with it.** On mainnet, levels 4–7
  of the account trie are rewritten once per changed account: nearly every
  changed account has its own nodes there. Levels 0–2 (1 + 16 + ~220 nodes)
  are rewritten almost entirely in every block.
- **Most of the upload is internal nodes, not values.** Leaves are only
  19% of the new nodes. A changed 32-byte slot costs about six new nodes
  of ~360 bytes each.
- **Merging blocks helps where writes repeat.** On Gnosis the same accounts
  recur from block to block. 16 blocks of ~49 changed accounts each touched
  only 279–302 distinct accounts per epoch, and an epoch costs 41–44% of its
  blocks summed.
  Mainnet repeats less. An epoch touched 8,207 and 8,361 distinct accounts
  against ~15,800 account changes summed over its blocks, and costs 57%.

For scale (ethPandaOps, 2026-11-04):

- Mainnet holds 430 M accounts and 1.69 B storage slots.
- Those take 597 M account-trie nodes (73 GB) and 2.29 B storage-trie nodes
  (247 GB).
- Contract code is 3.2 M distinct contracts, 16.4 GB.
- Storage is concentrated: XEN alone has 176 M slots, and the top 100
  contracts hold about 37% of all slots.
- Gnosis has no published counts. Nethermind's flat database is 189 GB on
  Gnosis against 304 GB on mainnet.

## 4. Verification: what changes, and what does not

Nothing new is trusted.

- **The root.** Head and finalized roots come from the beacon light client, as
  today: a BLS-signed sync-committee update, then the execution payload header
  through its Merkle branch. A historical root needs that block's verified
  header: the header chain reaches 8,192 blocks back today
  (`headerChainGapTooLarge`), and older blocks would need proofs against the
  accumulators CLAUDE.md names as trust anchors.
- **Trie nodes.** A node is accepted only if `keccak256(node)` equals the hash
  the reader expected: the root, or the child reference in an already-accepted
  parent. The nodes collected along a path form exactly the proof
  `eth_getProof` returns, so `verify_proof(root, keccak(key), nodes)` checks a
  Swarm read unchanged. Exclusion proofs work the same way: the path ends at an
  empty branch slot or a diverging leaf.
- **Code.** Accepted only if `keccak256(code) == codeHash`, the hash from the
  proven account.
- **Not trusted:** the SOC signature, the postage stamp, the publisher's
  identity. These are Swarm's own spam and payment controls. A chunk that fails
  the keccak check is a miss, and the read falls back to SNAP.
- **What a bad or absent publisher can do:**
  - withhold data;
  - publish late;
  - publish garbage, which is detected.

  This is the liveness-only exposure CLAUDE.md already accepts for `roost`.
  Unlike SNAP, Swarm data has no "peer is behind" case: a page for a node hash
  is either right or missing.

## 5. Layout options

Three questions decide a layout: how a reader turns (root, key) into chunk
addresses, what a chunk holds, and which roots get published. Five
candidates, all verified the same way (§4):

| | Layout | Reader: sequential fetches (mainnet balance read) | Publisher writes | Problem |
|---|---|---|---|---|
| A | **Node per chunk by hash**: SOC with `id = keccak(node)`, the reader follows child hashes (Portal's design) | ~15 (8.9 + 6.3) | the new nodes, about 7,400 per block | slow; postage wasted on ~360-byte chunks |
| B | **Path-addressed, latest version**: `id = H(trie, path)`, overwritten when the node changes; the reader fetches all levels in parallel | 1 parallel wave | about the same as A | every overwrite of a hot path races, and readers at an older root get the wrong version. SOC overwrite is not convergent (§2), so it fails exactly where it matters |
| C | **Per-root, per-key proof bundles** | 1 | every key, every root | impossible: 430 M accounts × every root |
| D | **Node + its children's paths** (`id = H(nodeHash ‖ next nibbles)`) | fewer | 16ʲ chunks per new node for j nibbles | write amplification of 16–256× |
| E | **Checkpoint proof plus BAL replay to the head** | as for the checkpoint | per checkpoint only | needs Amsterdam BALs; downloads ~92 KiB per block to follow |

The hexary MPT forces a trade-off. A full branch node is ~530 bytes, and a
path needs every node on it, because each parent's hash commits to all 16
child references.

- **Content addressing (A)** shares every unchanged subtree, so writes are
  proportional to churn. But the reader learns each address only from the node
  above it, so the walk is sequential.
- **Location addressing (B, C)** lets the reader compute every address up
  front. But each published root then needs writes proportional to the trie's
  width, or relies on overwrites that do not converge.

The recommended layout keeps A's immutability and buys back most of the
latency in two places where it is cheap: the top of the trie (jump tables)
and the bottom (pages).

## 6. Recommended layout

Everything is immutable. A chunk's id determines its content, so re-uploads
are byte-identical and overwrite semantics never matter.

### 6.1 Pages (hash-addressed)

- **Address:** a SOC under the publisher's key `P`, with
  `id = keccak256(node)`, the MPT node hash itself, so
  `address = keccak256(nodeHash ‖ P)`. The reader computes it from the child
  reference in the parent.
- **Content:** the node, plus all of its children that are leaves; or, when
  the node's whole subtree fits in 4,096 bytes, the whole subtree. Leaves
  therefore never get a chunk of their own. A child small enough to be
  embedded (under 32 bytes) is already inside its parent.
- **Why this rule:** a page changes only when its node changes, and a node
  changes whenever anything below it does. So carrying children costs no
  extra writes: the page is rewritten anyway. It saves one fetch at the bottom
  of every path, and its chunk count is the number of non-leaf nodes:
  - **Full state:** 2.88 B nodes − 2.12 B leaves = **0.76 B chunks** for
    mainnet (estimate, from ethPandaOps' totals). Packing 320 GB perfectly
    would take 78 M chunks, the floor.
  - **Churn:** about 20% fewer chunks than one node per chunk (the leaf
    share in §3).
- **Small storage tries.** About 23 M contracts have storage (May 2025). A
  storage trie of up to a few dozen slots fits in one page, so its reads cost
  one fetch.

### 6.2 Jump tables (root-addressed)

- **Address:** for each published root `R`, one SOC per k-nibble key prefix
  `p`, with `id = keccak256("myotis/jump/v1" ‖ R ‖ p)`.
- **Content:** the k + 1 nodes from `R` down along `p`; with k = 3, about
  2.1 KB.
- **How the reader uses it:** it knows `R` and `keccak(address)` before
  fetching anything, so the first fetch returns levels 0–3 at once. Then it
  continues by hash through pages.
- **Cost:** 16ᵏ chunks per published root.

  | Network | k | Per root | Published roots / day | Chunks / day |
  |---|---|---|---|---|
  | Mainnet, per epoch | 3 | 4,096 | 225 | 0.92 M (4% of the epoch's pages) |
  | Gnosis, per epoch | 3 | 4,096 | 1,080 | 4.4 M, more than its 3.1 M pages |

  Gnosis therefore takes k = 2 per epoch (0.28 M a day), or k = 3 every
  fourth epoch.
- **Storage tries:** the same scheme, keyed by a storage root, pays off only
  for the few dozen deep, hot storage tries (USDT, USDC, WETH and the like),
  where a mainnet slot proof is 7–9 nodes.
- **Not every block:** at 7,200 roots a day, mainnet jump tables would cost
  29 M chunks a day, more than half the churn they serve. That is why they belong
  to a sparse set of published roots (§6.4).

### 6.3 Code store

- **Address:** `id = keccak256("myotis/code/v1" ‖ codeHash)`.
- **Content:** the code itself if it fits in 4,096 bytes; otherwise the Swarm
  reference of the code as an ordinary Swarm file (the reader fetches its data
  chunks in parallel).
- **Never changes:** it is shared across every root, and across networks
  under the same publisher.
- **Size:** mainnet's 3.2 M distinct codes, 16.4 GB, come to about 7 M chunks:
  0.17% of the network, about 900 BZZ a year (≈$37).
- **Why first:** code is the largest item in an `eth_call` (tens of KB per
  contract, docs/disk-and-network-usage.md §4), it caches forever, and it
  needs no per-block work.

### 6.4 What to publish, and when

- **Cadence: one root per epoch,** the epoch-boundary block. That is exactly
  the `finalized` root Myotis reads at, and SNAP serves it worst. The publisher
  can start uploading as soon as the block exists and has two epochs (12.8 min
  on mainnet, 2.7 min on Gnosis) before readers see that root as finalized.
  The Gnosis figures describe today's chain. As a GIP-153 rollup it will have
  no beacon epochs of its own, and both the cadence and how Myotis verifies a
  Gnosis root will change. Myotis reads state only over SNAP. On a rollup
  whose execution clients do not serve snap yet, state published to Swarm
  would be the only state source it has.
- **Scope, in three tiers:**

  | Tier | Content | Mainnet | Gnosis |
  |---|---|---|---|
  | 0 | Code | ~7 M chunks once | smaller (no count published) |
  | 1 | Epoch churn: the pages of every node a published root added, plus its jump table | 23.8 M pages + 0.92 M jump / day | 3.1 M pages + 0.28 M jump / day |
  | 2 | Base: every page of one root, so cold keys are walkable too | 0.76 B chunks (estimate), 18% of the network | unknown; Nethermind's flat DB is 62% of mainnet's |

  Without a base, tier 1 serves only keys that changed since publishing
  began. Every node on such a key's path was published either when the key
  last changed or when the node changed later. A wallet's own account
  qualifies once it has transacted; a token balance untouched for months does
  not. Those misses fall back to SNAP.
- **Retention.** Stored chunks = base + churn per day × days kept.
  Structurally shared pages of old roots stay valid while any kept root
  references them, so retention is a property of the set of roots, not of
  single chunks.

### 6.5 Cost

Postage only, at the 2026-11-05 price, nominal capacity (§2); BZZ at about
$0.04.

| Scenario | Chunks stored | Share of Swarm | Postage |
|---|---|---|---|
| Code (tier 0), mainnet | 7 M | 0.2% | ~900 BZZ/yr |
| Mainnet, every block (one node per chunk), kept 1 day | 53 M | 1.2% | 19 BZZ/day |
| Mainnet, every block (one node per chunk), kept 30 days | 1.6 B | 37% | 560 BZZ/day |
| Mainnet, every epoch (pages + jump tables), kept 30 days | 743 M | 17% | 260 BZZ/day |
| Mainnet base snapshot (tier 2) | 0.76 B | 18% | ~97,000 BZZ/yr (~$3,900) |
| Gnosis, every epoch (pages + jump tables), kept 30 days | 102 M | 2.4% | 36 BZZ/day |

- **The money is small.**
- **The capacity is not.**
  - A mainnet base snapshot would be almost a fifth of today's Swarm.
  - A month of per-block mainnet history would be more than a third; a month
    of per-epoch history, about a sixth.
  - Putting Ethereum-scale state on Swarm needs the network to grow, or the
    larger reserves of §9.
- **Push bandwidth matters for short retention.** Uploading every block costs
  about 53 M chunks × 2.7 · 10⁻⁶ BZZ ≈ 140 BZZ a day at full first-hop prices.
  That is more than the postage for keeping it a day, and before the free
  allowance a full node gets.
- **Throughput.** Per block, mainnet means ~620 chunks a second sustained. The
  one public number for a Rust uploader is 77,407 chunks in 225–270 s, about
  300 chunks a second (ant PR #138), so per-block publishing needs a faster
  push path or several uploaders. Per-epoch publishing pushes ~110,000
  chunks within an epoch's 12.8 min, about 140 chunks a second.

## 7. Reading it from Myotis

### 7.1 A Swarm oracle

- **A `SwarmStateOracle` behind `SnapStateOracle`.** For one account:
  1. Fetch the jump chunk for `(R, keccak(address)[0..3])`.
  2. Walk pages by hash.
  3. Check with `verify_proof`.

  A storage slot does the same from the proven `storageRoot`, and code comes
  from the code store.
- **Cache by node hash, not by root.** Today's caches are keyed by state root
  (docs/disk-and-network-usage.md §1.2). A node-hash cache reuses the deep,
  unchanged levels across roots. For repeat reads (the wallet's own accounts,
  popular tokens) that is most of every walk.
- **Fail fast.** Each fetch gets a client deadline (§2: Bee itself retries for
  a long time). A miss falls back to SNAP for that key.

### 7.2 Which reads go to Swarm

| Read | Today | With Swarm |
|---|---|---|
| `latest` | SNAP | SNAP; Swarm only as the BAL replay's starting proof (§7.3) |
| `finalized` | SNAP, at the edge of the peers' window | Swarm first, SNAP as fallback |
| Block pin more than 64 below the head | refused | Swarm, if a published root covers that block |
| Code | `GetByteCodes` | code store, SNAP as fallback |
| No snap peer yet (cold start) | waits | `finalized` and code from Swarm |

A `latest` read must never be answered from the finalized root: CLAUDE.md's
*applied or refused* rule forbids silently downgrading what the caller asked
for. Swarm serves the reads that asked for an older root, and §7.3 bridges to
the head where that is verifiable.

### 7.3 Up to the head with block access lists

From Amsterdam on, every header commits to its block access list
(`block_access_list_hash`, EIP-7928). The BAL carries the post-values of
every balance, nonce, code and storage write. The Rust engine already uses
this on Amsterdam chains. It carries a watched account's state from a proof
through each verified BAL and answers reads with `verifyMethod`
`"blockAccessList"` (docs/address-activity.md, *Answering from block access
lists*).

Starting that replay from a Swarm proof at the finalized root, instead of a
snap proof at the head, gives a verified head read in which no snap peer ever
sees the address:

- **What it needs.** BALs from the finalized block to the head: 64–96 blocks
  at about 92 KiB each, compressed (EIP-7928 analysis, October 2026), so 6–9
  MiB once. After that, one BAL per block, which the follower already fetches.
- **What changes in Myotis.** The follower starts today only from a head proof
  whose block the anchor vouches for by hash. It would have to accept a
  finalized-root proof plus the BALs above it.
- **Limits.**
  - Storage writes still need a new proof, because a BAL carries slot values
    but not the new storage root. Following token slots is #685.
  - Gnosis has no Amsterdam date yet.

### 7.4 Cost and privacy for the reader

- **Cost.** A balance read is about 8 chunks, about 2 · 10⁻⁵ BZZ, well inside
  the free tier (swarm-read-economics.md). A cold `eth_call` touching 200
  nodes needs about 1.5 s of free allowance at ~140 chunks/s. That is less
  than its sequential fetches take, so bandwidth is not what limits a read.
- **Privacy.** Each chunk goes to the peer closest to its address, so no
  single peer sees a whole path. But the leaf page's address narrows the
  account down to that page's few keys, and a light node announces itself as
  one, so its peers know that a request it sends is its own. That is better than a snap request, which names the exact key
  to one peer, and worse than a BAL read, which names nothing.

### 7.5 Latency (estimate)

Sequential fetches × per-fetch latency. The per-fetch latency is unmeasured,
so two values are shown.

| Read | Plain walk (A) | Recommended | At 100 ms | At 300 ms | SNAP |
|---|---|---|---|---|---|
| Mainnet account | 8.9 | ~5 | 0.5 s | 1.5 s | 1 round trip |
| Mainnet ERC-20 balance | 15.2 | ~8 (~10 without a storage jump table) | 0.8 s | 2.4 s | 1–2 |
| Gnosis ERC-20 balance | 12.2 | ~8 (jump tables with k = 2) | 0.8 s | 2.4 s | 1–2 |

An `eth_call` walks many keys in parallel, and they share their upper levels,
so a wave costs about one path's depth, not the sum. For comparison, the
Portal state network made one recursive DHT lookup per node. Portal's own
measurements (on its history network) put a lookup at about 5 s at p95, with
~10% of recursive lookups timing out (implementer calls, February–March
2025). Swarm's single routed retrieval per chunk and the
shorter paths here are the two differences that matter.

## 8. The publisher

The publisher needs the new nodes of each published root. Its output is
self-verifying (§4), so how it gets them affects liveness, not safety.

1. **A local execution node over JSON-RPC.** `debug_traceBlockByNumber` (or
   the BAL) gives the changed keys, and `eth_getProof` for each at the new
   root gives exactly the new nodes. `scripts/state_churn.py` does this, so it
   is the publisher's read half. This is the `roost` pattern: a
   Myotis-operated service reading a local node. Like `roost`'s carve-out for
   self-verifying consensus objects, it needs the owner's decision.
2. **devp2p only.** The BAL (eth/71 or snap/2) gives the changed keys, and
   snap proofs at the new root give the nodes. That fits the data-source rule
   as written, but costs a full proof (~5 KB) per changed key: about 1,400
   proofs and ~7 MB per mainnet block.
3. **Replay BALs over a local copy of the trie.** Apply each BAL's
   post-values to the previous root's nodes and recompute the hashes. Then
   check the result against the header's state root: equality proves the
   publisher computed it right. This needs no EVM and no trusted node, only a
   full trie copy (hundreds of GB) bootstrapped once. EIP-7928 names
   "executionless state updates" as one of its motivations.

The publisher's key `P` is pinned in Myotis next to the other network
constants. Several publishers can coexist, and a reader tries them in order.
Each uploads its own copy, because SOC addresses include the owner.

## 9. What Swarm could change for this

Ranked by what it would save:

1. **Chunks addressed by `keccak256(payload)`.** A third chunk type, valid
   when its address is the keccak of its payload, would make every Ethereum
   object retrievable by the hash Ethereum already uses: trie nodes, small
   code, and block headers, whose address would be the block hash.
   - No publisher key, no 97-byte SOC header, no signature check per chunk.
   - Anyone can upload, and identical uploads deduplicate.
   - Cost to Swarm: the storage game's inclusion proofs assume the BMT, so
     this type needs its own proof path, e.g. hashing the whole ≤4 KiB
     payload on-chain. If the game moves to Ethereum with the stamps, that
     gas is mainnet gas.
2. **Price by size.** Smaller chunk classes (512 B, 1 KiB) with
   proportionally cheaper stamps and retrieval prices. Trie nodes average
   ~360 bytes, so this cuts the cost of publishing state about 4–8× and makes
   the page packing of §6.1 unnecessary.
3. **Recursive retrieval: "walk this path".** One request says: start at
   chunk A, follow key K through this trie format, return every node on the
   way. Each storer adds its node and forwards the rest of the request.
   - Pair it with locality: address bits that place a subtree in one
     neighbourhood, e.g. the first 10 bits of the key, then the content hash.
     Then one routed request reaches the neighbourhood that holds the whole
     lower path, and the walk runs inside the data centre.
   - That is a Swarm-native SNAP: about two phone round trips per read, and
     no jump tables.
   - Swarm's own manifests (Mantaray, also a trie of chunks) would resolve
     paths faster the same way.
   - It needs per-hop accounting so a single request cannot make a node fetch
     an unbounded number of chunks.
4. **A fast, definite "not here".** A storer inside the radius that lacks a
   chunk could say so, so the origin stops instead of retrying for many
   seconds. Clients fall back sooner, and feed lookups get faster too.
5. **Re-stamping without re-uploading.** Long-lived shared pages outlive the
   batch that first stamped them. A stamp-only message (address + new stamp)
   would renew them without pushing 4 KiB again. Rolling churn already fits
   mutable batches, which overwrite their oldest slot per bucket like a ring
   buffer (`B/pkg/postage/stampissuer.go`).
6. **Larger reserves.** 2²² chunks (16 GiB) per node, doubled at most once,
   caps today's network at about 16 TiB. Larger reserves would fit
   Ethereum-scale data on the same ~4,300 nodes. The limit is how long a node
   takes to sample its reserve for the storage game.
7. **Batched push-sync.** One message per neighbourhood instead of per chunk,
   for publishers pushing thousands of chunks per block.

With 1–3, the layout of §6 reduces to keccak-addressed nodes plus one
recursive request per key, at a quarter to an eighth of the postage.

## 10. Fit with the project rules, and open questions

- **Trust:** unchanged (§4). Swarm is a transport, and withholding is a
  liveness problem, as with `roost`.
- **Data sources:**
  - *Reader.* Bee's HTTP API from Myotis is the "local client over HTTP"
    pattern that is debug-only. A production reader needs an embedded Swarm
    client (`ant` is the candidate: Rust, Apache-2.0, read path live) and the
    owner's decision that Swarm, a libp2p network but not Ethereum's, counts
    as an allowed source.
  - *Publisher.* Options 1 and 3 in §8 need a carve-out like `roost`'s;
    option 2 needs none.
- **Measure before building:**
  1. Per-chunk SOC retrieval latency and miss rate from a phone and a
     desktop, through `ant` and Bee. Everything in §7.5 scales with it.
  2. Push throughput of one publisher, and how quickly a pushed chunk becomes
     retrievable.
  3. Mainnet's churn per epoch over more windows, and the size of the
     "active" state (keys read or written in the last 7 or 30 days, from
     BALs), which decides whether tier 2 can be partial.
  4. Gnosis state size, which decides whether a Gnosis base snapshot fits,
     once its post-GIP-153 verification path is settled.
- **Smallest useful proof of concept: on Sepolia.** A code store, per-epoch
  pages and jump tables for a handful of busy contracts, and a
  `SwarmStateOracle` used for `finalized` reads only. Why Sepolia:
  - Amsterdam is live there, so the BAL replay of §7.3 can be tried end to
    end.
  - Swarm's own testnet already keeps its contracts there (chain id 11155111
    in `go-storage-incentives-abi`).
  - Gnosis, the earlier choice, is about to change its block time and its
    consensus.

  It exercises every piece of the layout at a few thousand chunks a day.
- **The Bee synergy moves to mainnet.** A Bee node that pays by cheque needs
  a chain backend. Today that is Gnosis, which Myotis already serves in the
  Bee PoC (docs/bee-rpc-service.md). After the homecoming it is Ethereum,
  which Myotis's mainnet engine serves.
- **Binary trie (EIP-7864, draft).**
  - Binary nodes are 64 bytes, so a 4 KiB page holds a six-level subtree. A
    path of about 30 levels then costs about 5 fetches without jump tables.
  - The draft's hash (BLAKE3, "not final") does not matter to the client,
    which verifies whatever the spec fixes.
  - It does not change the core trade-off: the top of the tree still changes
    every block.

## Sources

- Myotis: `rust/myotis-wire/src/snap/fetch.rs`, `rust/myotis-evm/src/oracle.rs`,
  `rust/myotis-net/src/el/evm.rs` (`ReadAnchor`, `PoolOracle`),
  `myotis-rpc-policy/.../RpcBlockWindow.kt`, docs/address-activity.md,
  docs/disk-and-network-usage.md, docs/glamsterdam-plan.md,
  docs/swarm-read-economics.md.
- Bee at `a00425464a1d733732ea9123db703130c722bead`: `pkg/soc/soc.go`,
  `pkg/cac/cac.go`, `pkg/bmt/doc.go`, `pkg/storer/internal/reserve/reserve.go`,
  `pkg/storer/storer.go`, `pkg/retrieval/retrieval.go`,
  `pkg/pushsync/pushsync.go`, `pkg/postage/stampissuer.go`,
  `pkg/config/chain.go` — https://github.com/ethersphere/bee
- Live reads, 2026-11-05: PostageStamp `lastPrice()` (selector `0x053f14da`),
  `validChunkCount()`; https://api.swarmscan.io/v1/network/stats;
  https://network.ethswarm.org.
- Postage-batch effective volumes:
  https://docs.ethswarm.org/docs/concepts/incentives/postage-stamps
- ethPandaOps state tables, 2026-11-04 and 2026-11-05:
  https://lab.ethpandaops.io/api/v1/mainnet/fct_execution_state_size_daily,
  https://lab.ethpandaops.io/api/v1/mainnet/fct_storage_slot_top_100_by_slots
- Nethermind flat-DB sizes: https://github.com/NethermindEth/docs/pull/370
- EIP-7928 and its October 2026 BAL size analysis:
  https://eips.ethereum.org/EIPS/eip-7928,
  https://github.com/ethereum/EIPs/blob/master/assets/eip-7928/bal_size_analysis_60m_2026_10.md
- Snap spec and serving clients: https://github.com/ethereum/devp2p/blob/master/caps/snap.md,
  https://github.com/ethereum/devp2p/issues/286
- EIP-7864: https://eips.ethereum.org/EIPS/eip-7864
- Portal state network (legacy spec, implementer-call notes):
  https://github.com/ethereum/portal-network-specs/blob/master/legacy/state/state-network.md,
  https://hackmd.io/@chloezhux/H1x36pYIJg
- Rust Swarm clients: https://github.com/freedom-hq/ant (and PR #138 for
  the upload figure), https://github.com/nxm-rs/vertex
- Swarm's move to Ethereum: https://www.ethswarm.org/blog/2026/monthly-development-update-september-2026/,
  https://www.ethswarm.org/blog/2026/monthly-development-update-october-2026/,
  https://www.ethswarm.org/blog/2026/swarm-community-call-24-september-recap/
- Gnosis Chain as an Ethereum rollup: GIP-153,
  https://forum.gnosis.io/t/gip-153-should-gnosis-chain-transition-into-the-ethereum-economic-zone/12397;
  its effect on Swarm's block-based contracts: https://github.com/crtahlin/wasp/issues/540
