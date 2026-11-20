# Past transactions for any address: what is missing

Status: **planning basis; the tracer bullet is being built** (`feature/swarm-addr1`: the
Swarm carve-out, an embedded `ant` node, the addr1 reader and `myotis_getAddressHistory`).
D1 is decided (owner, 2026-11-20): the bundled checkpoint table is a trust anchor, so a
table-verified header verifies an entry. It lists everything needed for
[Punicus](https://github.com/biafra23/punicus) to show the past transactions of any
address with Myotis as its data access layer. The work is split into workstreams, and
each is meant to become an implementation plan of its own. It builds on two designs:
the addr1 address index on Swarm
([eth2swarm `docs/address-index.md`](https://github.com/biafra23/eth2swarm/blob/main/docs/address-index.md))
and [deep-block-verification.md](deep-block-verification.md) (the checkpoint table and the
header walk). The decisions marked *owner* change the trust model or the data-source
rules and are not the plan author's to make.

## The goal

Punicus lists an address's history, newest first, and picks up new transactions as they
come. Myotis finds the candidate entries, checks every one it can against verified chain
data, and says which ones it could not check.

```text
 importer ──▶ Swarm (addr1 slices, head feed)
                │
                ▼  ant, embedded in Myotis
 Myotis: head → cover → one bucket per slice → entries (block, slot, role)
                │
                ├─▶ header: checkpoint table + header walk (devp2p)
                ├─▶ body / receipts (devp2p, peer chosen by eth/69 earliestBlock)
                ├─▶ per-role check of each entry
                └─▶ recent blocks the index has not reached: Myotis scans them itself
                │
                ▼  :myotis-api / JSON-RPC
 Punicus: list, details, verified / unverified / loading
```

## What is verified and what is taken on trust

| Part | How it is held |
|---|---|
| An entry's block header | verified: hash-linked to the checkpoint table or to the beacon-attested head |
| FROM, TO, input WORD, AUTH | verified against the transaction (signature recovery, created-contract address) |
| EMITTER, TOPIC, log WORD | verified against the receipt (`receiptsRoot`) |
| BLOCK (beneficiary, withdrawals, uncles) | verified against the header and the body |
| TRACE (internal calls) | **on the importer's word** before Amsterdam: internal calls are in neither the transaction nor the receipt. From Amsterdam on, a header commits to its block access list (`blockAccessListHash`), which the engine already fetches and checks (`address-activity.md`); a TRACE entry that changes the address's balance, nonce or code is then checkable, as long as a peer still serves that block's BAL. Sepolia has BALs today; mainnet and Gnosis do not yet |
| Completeness (nothing left out) | **on the importer's word**: the index cannot prove an absence; a second importer narrows it |
| The checkpoint table | **a new trust anchor** (decision D1) |
| Swarm | transport only; everything read is checked, except TRACE and completeness (the two rows held on the importer's word) |

## Checklist

Items 1–9 are the owner's list; 10–24 are what it was missing. Each workstream below
collects its items.

| # | Item | Workstream |
|---|---|---|
| 1 | An importer that produces the addr1 index (a modified TrueBlocks or our own) | W1 |
| 2 | A fully synced node behind the importer | W1 |
| 3 | A script that generates the table of every k-th block hash | W3 |
| 4 | Publishing the addr1 index to Swarm | W1 |
| 5 | ant embedded in Myotis | W5 |
| 6 | Myotis code to query the index | W6 |
| 7 | Myotis code to bridge the header gap | W3 |
| 8 | Punicus code to query and show the history | W8 |
| 9 | The header hashes as an additional trust anchor | W2 |
| 10 | Receipts for deep blocks over devp2p (measured: as available as bodies) | W4 |
| 11 | Per-role verification of each entry | W6 |
| 12 | Pre-Merge bodies and receipts | W4 |
| 13 | TRACE entries are not verifiable | W2, W8 |
| 14 | A data-source carve-out for Swarm | W2 |
| 15 | Completeness on the publisher's word, or a second importer | W1, W2 |
| 16 | The importer's signing key as a trust input | W2 |
| 17 | The head gap: the newest 13–32 minutes | W6 |
| 18 | Who pays for Swarm reads (not the index: it reads within the free rate) | W5 |
| 19 | ant on mobile, and the privacy of bucket requests and of block fetches | W5, W6 |
| 20 | Postage and running the importer continuously | W1 |
| 21 | The engine contract and a JSON-RPC method | W7 |
| 22 | Golden vectors shared by the importer and Myotis | W6 |
| 23 | A release step that extends the checkpoint table | W3 |
| 24 | Showing amounts, tokens and verification state in Punicus | W8 |

## Owner decisions

These gate the workstreams that depend on them; they are listed first because nothing
built on an undecided rule can ship.

- **D1. The checkpoint table as a trust anchor** (item 9). **Decided (owner, 2026-11-20):
  bundle every 1024th block hash, instead of a walk back at run time; the rule is in
  `.claude/agent/data-sources.md` (Trust).** For the first mainnet table the owner ruled
  that the build's own checks suffice: every header hashed and linked by `parentHash` down
  to the genesis hash, its top (Erigon's finalized block) cross-checked against a second
  client; the running node's gap walk still checks the top entry. A generator that starts
  from a Myotis beacon-attested block (item 3 below) stays the target for later tables.
  The considerations: a third embedded anchor next to the sync-committee checkpoint and the
  historical accumulators, only as good as the walk that produced it
  ([deep-block-verification.md §Open decisions](deep-block-verification.md#open-decisions)).
- **D2. Swarm as a data source** (item 14). **Decided (owner, 2026-11-19): an embedded
  client, `ant` linked into the Rust engine; the carve-out is in
  `.claude/agent/data-sources.md`, which supersedes the sketch below in both halves: what is
  read (the index's SOCs and its spill and pages files), and how entries are shown (as
  verified, contradicted or unverified, labelled, rather than only once checked).** The considerations it settled: `CLAUDE.md` allows devp2p and libp2p only. A
  carve-out in the shape of the existing ones (`.claude/agent/data-sources.md`): what may be
  read from Swarm (addr1 records and spill files only), and that every entry read is
  checked before it is shown. It must also name **the form of the reader**, because the
  forms fall under different rules:
  - *An embedded client linked into the engine*, with no local HTTP API — the form this plan
    assumes. Swarm runs over libp2p, so D2 covers it.
  - *A separate Swarm process* (`antd`, or a Bee node) whose local API the engine calls.
    That is the "local client over HTTP" pattern `CLAUDE.md` allows only for debugging
    (`swarm-read-economics.md`, *Fit with the project rules*; `state-on-swarm.md` §10), so
    it needs a carve-out of its own. It also cannot exist on iOS, where an app cannot start
    a second process.
  - *A Swarm HTTP gateway* is one operator's server, not the Swarm network: neither devp2p
    nor libp2p. Its chunks stay checkable (content address, SOC signature), so it could
    withhold but not forge, but it sees every bucket request together with the user's IP —
    item 19 in concentrated form. It needs its own line in D2, as the checkpoint servers
    needed their own carve-out, or it is ruled out.
- **D3. Completeness and TRACE on the importer's word** (items 13, 15). **For the first
  version (owner, 2026-11-19): accepted with one importer, labelled, entries unverified
  until checked; whether a second importer is required stays open.** Like the seeded-log
  carve-out (2026-09-25), the displayed history then rests on the publisher for what it
  leaves out. Whether that is acceptable with one importer, or only with two that agree,
  and what Punicus must say about it. Before Amsterdam this is permanent for TRACE; from
  Amsterdam on, block access lists make most TRACE entries checkable (see the table above),
  which shrinks D3 over time and bears on whether the first version needs a tracing archive
  node at all.
- **D4. Which importer keys Myotis trusts** (item 16). **For the first version (owner,
  2026-11-19): a key the user configures at runtime, an experimental setting labelled as
  trusting that importer; pinning, rotation and the reaction to a contradicted entry stay
  open.** SOC addresses are derived from the
  identifier and the owner, so Myotis pins the importer's address or addresses; rotating a
  key needs a release or a signed handover. D3 and D4 also have to say **what follows when a
  pinned key is caught publishing a false entry** — an entry whose address is not where its
  role says. That is not a row to skip but evidence against the party completeness and TRACE
  rest on: the checkpoint-server rule treats one differing answer as an alarm, and this
  needs a decision of the same kind (stop trusting the key, warn, report).
- **D5. This plan against the one in `data-sources.md`.** Still open: the Swarm carve-out
  (2026-11-19) does not decide it. That file records the plan to run
  our own TrueBlocks scraper and add its IPFS peer to Myotis for `:tx-history`. addr1 on
  Swarm would replace it; `:tx-history` stays debug-only either way.

## Workstreams

### W1. Producing the index (items 1, 2, 4, 15, 20)

Lives outside this repository (eth2swarm), but Myotis depends on its output.

- **Importer.** The addr1 detection rules are normative and differ from TrueBlocks'
  heuristics. TrueBlocks can be a starting point for extracting appearances, but the
  output must follow addr1 byte for byte, or importers cannot be compared.
- **Node.** A full-history node (no archive state) covers every role except TRACE; the addr1
  measurements were taken on one. TRACE needs a tracing archive client (Erigon or Reth).
  Without it the index has no internal ETH transfers (W8 shows that).
- **Publishing.** Slices, buckets, spill files, the head feed and the origin record, as
  specified. Deferred merges in the background. Parallel upload: the block-store importer
  uploads one chunk per request, and a top-level merge takes about a day even at 200 chunks
  per second.
- **Operations.** It is a service that runs indefinitely: one slice and one head update
  every 64 blocks. Postage batches grouped by lifetime, about $72–96 a month at
  2026-11-16 prices (69 GB, 32 M chunks for one copy, growing ~0.8 M chunks a month).
  Monitoring, top-ups, key custody.
- **A second importer** (item 15), under its own key, for the comparison addr1 describes.

### W2. Trust and rules (items 9, 13, 14, 15, 16)

The rule changes behind D1–D5, written into `CLAUDE.md` and `.claude/agent/` in the same
commit, as the rules require. No code.

### W3. Verifying deep headers (items 3, 7, 23)

Fully specified in [deep-block-verification.md](deep-block-verification.md); worth building
first, because deep `eth_getBlockByNumber` and receipt reads are useful on their own.

- **Generator (item 3).** A verified walk from a beacon-attested block down to the genesis
  hash, not hashes read from a node's RPC: otherwise D1 anchors on an RPC's word. Output: the
  hash of every 1024th block, per network (mainnet 0.83 MB, Gnosis 1.54 MB, Sepolia 0.38 MB).
- **Bridging the gap (item 7).** A lookup walks at most 1024 headers up to the next table
  entry (one request, ~0.66 MB at most). Entries the node records itself as finality passes
  them; the gap since the release and over downtime closed lazily, held on metered networks.
- **Release step (item 23).** Extend the table every release, commit it as a pinned asset,
  keep release builds reproducible, add the step to `.claude/agent/releases.md`.
- Body checks gain `withdrawalsRoot` and `ommersHash`; the below-window refusal becomes the
  permanent `-32602` (both engines).

### W4. Deep block data over devp2p (items 10, 12)

- **Receipts (item 10).** EMITTER, TOPIC and log-WORD entries are checked against receipts.
  History expiry drops receipts with bodies, and Myotis's receipt READ path
  (`block_receipts_at_inner`) refuses below the same 512-block window as its block reads.
  But the engine already fetches and verifies receipts far below that window: the log-index
  backfill walks headers down from the anchored head, 1024 a request, and for each candidate
  calls `get_receipts` and `verify_block_receipts` (`fetch_candidate_logs` in `reader.rs`;
  `eth-getlogs-design.md` §3), ranks peers by throughput (`rank_backfill_peers`), and stalls,
  not fails, when no peer holds the range. W4 reuses that fetch-and-verify step; what it adds
  is the entry point (a header verified through the checkpoint table) and the
  `earliestBlock` peer choice.
- **Measured (2026-11-16, mainnet).** A local, never-committed probe asked six pooled snap
  peers in parallel for the header by number, then body and receipts, checked against that
  header's own roots, at 20 random pre-Merge and 20 random post-Merge heights. All 40 were
  served (median 144 ms pre-Merge, 232 ms post-Merge, first full answer). Per peer: the four
  that announce full history served receipts at all 40 heights; a Nethermind announcing
  `earliestBlock` 24,600,000 served them exactly from its announced block up (3 of the 13
  heights it was asked), and below it returned headers but no bodies; a Geth v1.17.4 that
  announces `earliestBlock` 0 and a current head answered every deep header request with an
  empty list. **No peer served a body and then withheld its receipts.** So receipts are as
  available as bodies, and what limits deep checks is the number of full-history peers (7
  of 18 in the survey, 4 of 6 here; one host, one evening). For the live mainnet log-index
  download (`log-index-presets.md` says it has not been run end to end) the backfill is the
  tool to take the larger measurement with; the Bee backfill already ran the same walk on
  Gnosis.
- **Peer choice.** Ask for a body or receipts only peers whose eth/69 `earliestBlock` is at
  or below the block; today the engine does not keep that value. The announcement is not
  enough on its own (the Geth peer above): an empty answer moves on to the next peer.
- **Pre-Merge (item 12).** Archive peers serve pre-Merge bodies and receipts alike (above).
  Either accept them as the source, or put pre-Merge blocks and receipts on Swarm (a block
  store of its own, a project of its own, D2 again, and the one part of this plan where Swarm
  reads become bulk reads that cost money, see W5).

### W5. Swarm access in Myotis (items 5, 18, 19)

- **ant (item 5)**, its crates linked into the engine (the form D2 names; not the `antd`
  daemon), in the desktop app, the
  daemon, `myotis-rpcd`, Android and iOS. Besides APK and app size, background execution,
  battery and iOS suspending the app, linking it costs this repository:
  - **The panic contract.** The workspace builds `panic = "abort"` (`rust/Cargo.toml`,
    `[profile.release]`): a panic anywhere in the Swarm client ends the host app, and that
    code was not written under the engine's panic-free contract.
  - **The libp2p pin.** `myotis-net` pins `libp2p = "=0.56.0"`; the client shares that exact
    version, or the binary carries two libp2p stacks.
  - **Reproducibility.** Its dependency tree joins `Cargo.lock`, the hash pins and the
    `reproducible builds` gate.
  - **A mobile artefact**, which `state-on-swarm.md` §2 lists as still open for ant.
- **Paying for reads (item 18): not a cost of the first version.** Swarm has no free quota
  that runs out: a light node reads free below a rate limit
  ([swarm-read-economics.md](swarm-read-economics.md): about 0.5–0.6 MiB/s with ~100 peers,
  ~0.2 MiB/s modelled with 30). A cold full-history lookup is 40–65 KB and an incremental one
  less, well under a second of the free rate, so no chequebook (xDAI for gas and a BZZ deposit
  per user) is needed for the index. Paying becomes a question only for bulk reads, such as a
  pre-Merge block store on Swarm (W4).
- **Privacy (item 19), the Swarm half.** A bucket request tells the serving neighbourhood
  which addresses it is about (about 127–180 per bucket); whoever sees a whole lookup can
  narrow it down further across slices. Decoy buckets and Tor are the options. The devp2p
  half is in W6.

### W6. Querying the index and checking entries (items 6, 11, 17, 22)

- **Query (item 6).** Head discovery without probing for missing chunks (from the
  light client's finalized block), the cover, pending merges, buckets, paged buckets,
  spill files, incremental sync. Cold full-history lookup: 13–22 buckets, about 40–65 KB.
- **Per-role verification (item 11).** For each entry, fetch the header (W3), the body or
  the receipts (W4), and check that the address is where the role says it is. Lazily,
  when the user opens an entry or scrolls to it: a deep entry costs a header walk and a
  body, about 0.5–1.5 s.
- **The head gap (item 17)** — the most expensive part of a lookup. The index runs 13–32
  minutes behind, and Myotis scans the blocks it has not reached:
  - **Cost.** Finding an arbitrary address in a block needs the whole body (FROM, TO, input
    WORD and AUTH are in the transactions) and, for log WORD, the whole block's receipts: an
    address in a log's data sets no bloom bit (`address-activity.md`: the bloom answers for
    emitter and indexed topics only). At ~100 KB of body and ~80 KB of receipts per mainnet
    block (`disk-and-network-usage.md`), 13–32 minutes are 65–160 blocks: about 12–29 MB for
    the first scan, then about 0.9 MB a minute while the screen follows the head — against
    40–65 KB for the index lookup beside it. Like W3's gap walk, it is held on a metered
    network.
  - **The overlap holds only while the importer is on time.** The window is 512 blocks below
    finality: about 1.7–1.9 hours on mainnet, about 43 minutes on Gnosis. A stalled importer
    leaves blocks neither side covers; with W3 the scan can reach deeper, at the cost above
    per block. Either way the answer names that range as a gap (W7), never a shorter list.
  - **Above finality.** At least the newest two epochs of the gap are above finality, verified
    against the optimistic head, and can be reorganized away. Merging by block number is not
    enough: such an entry carries its block hash and a "not final" state, as the activity
    report already does ("above finality a block can come back with a new `blockHash`").
  - **Build on the activity follower.** `rust/myotis-net/src/el/activity.rs` (#691) keeps the
    last 256 verified headers with their blooms, fetches and verifies block access lists where
    blocks commit to one, and reports every block as covered or as a gap. The head-gap scan
    extends it with bodies and receipts; it is not a second follower.
  - **TRACE.** Before Amsterdam the scan cannot see TRACE roles at all; internal transfers of
    the newest minutes appear only once the index reaches them.
- **Privacy, the devp2p half (item 19).** Per-entry verification asks devp2p peers for the
  bodies and receipts of exactly the blocks the address appears in, and the header walk
  names the block (`origin = N`). A set of block numbers identifies an address at least as
  well as a bucket does: anyone holding an address index — and addr1 is published — can
  intersect a handful of blocks down to one address. Deep bodies come only from the peers
  that keep history (7 of 18 in the survey), so the same few peers see most of the set,
  together with the user's IP. `privacy-and-tor.md` rates "which blocks' bodies we fetch" as
  low for a single send; a whole history is a different quantity, these fetches are not
  Tor-routed today, and decoy buckets do nothing for them. Options: decoy blocks, always
  requesting the whole 1024-header window to the next table entry instead of
  `origin = N`, or Tor for these fetches.
- **Golden vectors (item 22).** The addr1 encoding is canonical; the importer and the Myotis
  decoder check against the same files.

### W7. The engine contract and the API (item 21)

- A new interface in `:myotis-api` (hosts talk only to it), FFI-portable types, the Rust
  implementation, and the Java engine refusing it with `-32602`.
- A JSON-RPC method (e.g. `myotis_getAddressHistory`) with an entry in `myotis-rpc-policy`.
  Every parameter (role filter, block range, page cursor) is applied or refused, never
  ignored; an uncovered range is an error, never a misleading empty list.
- **A range-level answer.** Completeness is a property of the list, not of an entry. The
  answer says up to which block the list rests on which importer key, from which block
  Myotis scanned itself, and which ranges nobody covered — the precedent is
  `addressActivityJson`, with `from`, `to` and `gaps` ("a block the engine did not check is
  a gap, never a silence"). That is the field D3's caveat travels in, and what the
  "uncovered range is an error" rule checks against when the importer is behind.
- **Each entry's state**: verified; not final (above finality, with its block hash); not
  verifiable (TRACE before Amsterdam); not yet checked; **unavailable** (no peer served the
  body or receipts — a liveness state, expected for a pre-Merge entry without an archive
  peer, worth a retry); or **contradicted** (the address is not where the role says — proof
  that a pinned importer key published a false entry, which goes to D3/D4's alarm, not just
  into a row).

### W8. Punicus (items 8, 13, 24)

- List and details, newest first, with paging and incremental refresh.
- Amounts and tokens: symbols and decimals by `eth_call` at the head. Historical state is
  not available, so no "balance after" column.
- The verification state of every entry, and the caveats: TRACE and completeness are on
  the importer's word; without TRACE internal transfers are missing and balances will not
  add up.
- Privacy settings that W5 offers (decoys, Tor).

## Order and dependencies

| Workstream | Depends on | Can start |
|---|---|---|
| W2 trust and rules | — | now (owner) |
| W3 deep headers | D1 to ship; the code can be built behind it | now |
| W4 deep block data | W3 for verification; the measurement needs nothing | now |
| W1 importer and publishing | D2–D4 to be used by Myotis | now (long lead: node sync, postage) |
| W5 Swarm access | D2 | after D2 |
| W6 query and checks | W3, W4, W5, W1's format (golden vectors) | after W5 |
| W7 engine contract | W6 | with W6 |
| W8 Punicus | W7 | after W7 |

Suggested plans, each a multi-PR plan through its own `feature/<topic>` branch where it
spans several PRs (`.claude/agent/multi-pr-plans.md`):

1. **Deep block reads** (W3 + W4 post-Merge): the checkpoint table, the generator, the
   gap walk, deep block and receipt reads. Useful without the index.
2. **The addr1 importer and publisher** (W1), in eth2swarm.
3. **Swarm reads in Myotis** (W5), once D2 is decided.
4. **Address history in the engine** (W6 + W7).
5. **The history screen in Punicus** (W8).
6. **Pre-Merge history** (W4's pre-Merge part), if archive peers turn out not to be enough.

## Open questions

- How many full-history peers there are over days, not one evening: the 2026-11-16 samples
  (7 of 18, 4 of 6) come from one host (W4).
- Whether TRACE is worth an archive node for the first version, or whether the first
  version ships without internal transfers and says so — and how much block access lists
  cover once mainnet and Gnosis reach Amsterdam, and how long peers keep them.
- Whether the mobile apps carry the checkpoint tables (about 2.7 MB for mainnet, Gnosis and
  Sepolia) or only the desktop hosts do.
- Gnosis and the testnets: every piece (index, tables, postage) is per network.
