# Past transactions for any address: what is missing

Status: **planning basis — nothing here is built.** It lists everything needed for
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
                ▼  antd, inside Myotis
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
| TRACE (internal calls) | **on the importer's word**: internal calls are in neither the transaction nor the receipt |
| Completeness (nothing left out) | **on the importer's word**: the index cannot prove an absence; a second importer narrows it |
| The checkpoint table | **a new trust anchor** (decision D1) |
| Swarm | transport only; everything read is checked, except what the two rows above leave open |

## Checklist

Items 1–9 are the owner's list; 10–24 are what it was missing. Each workstream below
collects its items.

| # | Item | Workstream |
|---|---|---|
| 1 | An importer that produces the addr1 index (a modified TrueBlocks or our own) | W1 |
| 2 | A fully synced node behind the importer | W1 |
| 3 | A script that generates the table of every k-th block hash | W3 |
| 4 | Publishing the addr1 index to Swarm | W1 |
| 5 | antd bundled with Myotis | W5 |
| 6 | Myotis code to query the index | W6 |
| 7 | Myotis code to bridge the header gap | W3 |
| 8 | Punicus code to query and show the history | W8 |
| 9 | The header hashes as an additional trust anchor | W2 |
| 10 | Receipts for deep blocks over devp2p | W4 |
| 11 | Per-role verification of each entry | W6 |
| 12 | Pre-Merge bodies and receipts | W4 |
| 13 | TRACE entries are not verifiable | W2, W8 |
| 14 | A data-source carve-out for Swarm | W2 |
| 15 | Completeness on the publisher's word, or a second importer | W1, W2 |
| 16 | The importer's signing key as a trust input | W2 |
| 17 | The head gap: the newest 13–32 minutes | W6 |
| 18 | Who pays for Swarm reads | W5 |
| 19 | antd on mobile, and the privacy of bucket requests | W5 |
| 20 | Postage and running the importer continuously | W1 |
| 21 | The engine contract and a JSON-RPC method | W7 |
| 22 | Golden vectors shared by the importer and Myotis | W6 |
| 23 | A release step that extends the checkpoint table | W3 |
| 24 | Showing amounts, tokens and verification state in Punicus | W8 |

## Owner decisions

These gate the workstreams that depend on them; they are listed first because nothing
built on an undecided rule can ship.

- **D1. The checkpoint table as a trust anchor** (item 9). A third embedded anchor next to
  the sync-committee checkpoint and the historical accumulators, only as good as the walk
  that produced it. Covered in
  [deep-block-verification.md §Open decisions](deep-block-verification.md#open-decisions).
- **D2. Swarm as a data source** (item 14). `CLAUDE.md` allows devp2p and libp2p only. A
  carve-out in the shape of the existing ones (`.claude/agent/data-sources.md`): what may be
  read from Swarm (addr1 records and spill files only), and that every entry read is
  checked before it is shown.
- **D3. Completeness and TRACE on the importer's word** (items 13, 15). Like the seeded-log
  carve-out (2026-09-25), the displayed history then rests on the publisher for what it
  leaves out. Whether that is acceptable with one importer, or only with two that agree,
  and what Punicus must say about it.
- **D4. Which importer keys Myotis trusts** (item 16). SOC addresses are derived from the
  identifier and the owner, so Myotis pins the importer's address or addresses; rotating a
  key needs a release or a signed handover.
- **D5. This plan against the one in `data-sources.md`.** That file records the plan to run
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
  History expiry drops receipts with bodies, and Myotis's receipt reads have the same
  512-block window as its block reads. Measure first: how many peers serve deep receipts
  (the 2026-11-16 survey measured bodies and headers only).
- **Peer choice.** Ask for a body or receipts only peers whose eth/69 `earliestBlock` is at
  or below the block; today the engine does not keep that value.
- **Pre-Merge (item 12).** 7 of 18 surveyed peers hold pre-Merge bodies; pre-Merge receipts
  are probably rarer. Either accept archive peers as the source, or put pre-Merge blocks and
  receipts on Swarm (a block store of its own, a project of its own, and D2 again).

### W5. Swarm access in Myotis (items 5, 18, 19)

- **antd (item 5)** in the desktop app, the daemon, `myotis-rpcd`, Android and iOS: APK and
  app size, background execution, battery, iOS suspending the app.
- **Paying for reads (item 18).** A light node pays for retrievals beyond its free
  allowance ([swarm-read-economics.md](swarm-read-economics.md)). Per user, or through a
  gateway, and who funds it.
- **Privacy (item 19).** A bucket request tells the serving neighbourhood which addresses
  it is about (about 127–180 per bucket); whoever sees a whole lookup can narrow it down
  further across slices. Decoy buckets and Tor are the options.

### W6. Querying the index and checking entries (items 6, 11, 17, 22)

- **Query (item 6).** Head discovery without probing for missing chunks (from the
  light client's finalized block), the cover, pending merges, buckets, paged buckets,
  spill files, incremental sync. Cold full-history lookup: 13–22 buckets, about 40–65 KB.
- **Per-role verification (item 11).** For each entry, fetch the header (W3), the body or
  the receipts (W4), and check that the address is where the role says it is. Lazily,
  when the user opens an entry or scrolls to it: a deep entry costs a header walk and a
  body, about 0.5–1.5 s.
- **The head gap (item 17).** The index runs 13–32 minutes behind. Myotis scans the
  blocks the index has not reached itself; its verified window (512 blocks below
  finality, about 2 hours) covers that, so the two overlap. Merge and deduplicate.
- **Golden vectors (item 22).** The addr1 encoding is canonical; the importer and the Myotis
  decoder check against the same files.

### W7. The engine contract and the API (item 21)

- A new interface in `:myotis-api` (hosts talk only to it), FFI-portable types, the Rust
  implementation, and the Java engine refusing it with `-32602`.
- A JSON-RPC method (e.g. `myotis_getAddressHistory`) with an entry in `myotis-rpc-policy`.
  Every parameter (role filter, block range, page cursor) is applied or refused, never
  ignored; an uncovered range is an error, never a misleading empty list.
- Each entry carries its verification state: verified, not verifiable (TRACE), not yet
  checked, or failed.

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

- How many peers serve deep receipts, pre-Merge and post-Merge (W4).
- Whether TRACE is worth an archive node for the first version, or whether the first
  version ships without internal transfers and says so.
- Whether the mobile apps carry the checkpoint tables (about 2.7 MB for mainnet, Gnosis and
  Sepolia) or only the desktop hosts do.
- Gnosis and the testnets: every piece (index, tables, postage) is per network.
