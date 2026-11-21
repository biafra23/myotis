# The address history: an address's transactions from the addr1 index on Swarm

Myotis can list the blocks and transactions an address appears in, newest first, from an
**addr1 address index** published on Swarm, and check each entry against verified chain data.
It is a development feature: the Swarm reader (the embedded `ant` light node) is linked only
into builds that ask for it, and every shipped artifact refuses the history.

The rule this rests on is the carve-out for Swarm reads of the address index in
`.claude/agent/data-sources.md`. The plan is `docs/ideas/address-history-plan.md` (#899).

## What you get, and what it rests on

- **A page of candidates.** `myotis_getAddressHistory` reads the importer's index: its head,
  the slices of its cover, the address's bucket in each, and its spill files. Every chunk is
  checked before use: a SOC against its address and the importer's signature, a
  content-addressed chunk against its reference, every record by the decoder's canonical
  checks. Swarm is transport only. Each entry is still a *candidate*, `"unverified"`.
- **Each entry verified on request.** `myotis_verifyAddressHistoryEntries` checks the entries a
  host shows, by role, against a verified block and its verified receipts, fetched over devp2p.
  Deep blocks verify through the bundled checkpoint table (the D1 rule). The answer per entry
  is `verified`, `contradicted`, `unverified` or `unavailable`. A verified transaction entry
  carries its hash, sender, recipient and value. A final verdict is kept, and later pages show
  it.
- **What stays on the importer's word.** The list's *completeness* (an entry left out) and its
  `TRACE` entries. The answer names the importer key it rests on, and every block range the
  index does not cover (`headGap`, `tailGap`, `gaps`), never a shorter list.

## Building with the reader

```bash
# The daemon and the desktop app: link ant into the host library.
./gradlew :app:run -PswarmEngine -Pengine=rust -PaddressHistoryConfig=<settings file>

# The Rust JSON-RPC daemon.
cargo build --release -p myotis-rpcd --features swarm   # in rust/
myotis-rpcd --network mainnet --address-history-config <settings file>
```

Without the reader (no `-PswarmEngine`, no `--features swarm`, Android, iOS, the Java and Go
engines), every call is refused with the permanent `-32602`, and so are the settings: a daemon
told to use the history does not start without it.

## The settings

One JSON object, applied whole or refused:

```json
{
  "importer": "0x<the importer's address>",
  "swarm": { "network": "mainnet" }
}
```

- **`importer`**: the key the index is signed with. An *experimental* setting: you trust that
  importer for the list's completeness. `null` refuses every read. The daemon and `myotis-rpcd`
  log at start which importer they trust.
- **`swarm`**: `{"network": "mainnet"}` (Swarm mainnet's bootnodes, the default), or for a
  local network `{"network": "dev", "networkId": <id>, "bootnodes": ["<multiaddr>", …]}`.

The history is also refused while Tor routing is on: neither the Swarm reader nor the block
reads of the verify call go through Tor, and together they name the address.

## The calls

### `myotis_getAddressHistory(address, options)`

`options`, each field optional and each applied:

| Field | Meaning |
|---|---|
| `cursor` | the `next` of an earlier page: continue below it |
| `limit` | 1 to 500 entries, 50 by default |
| `roles` | only entries with one of these roles: `from`, `to`, `emitter`, `topic`, `word`, `trace`, `block`, `auth` |
| `fromBlock`, `toBlock` | the block range, as numbers or `0x` quantities |

The page:

```json
{
  "importer": "0x…", "headUpdate": <n>,
  "coveredFrom": <first block>, "coveredTo": <last block>,
  "headGap": {"fromBlock": …, "toBlock": <verified head or toBlock> | null} | null,
  "tailGap": {"fromBlock": …, "toBlock": …} | null,
  "gaps": [{"fromBlock": …, "toBlock": …}],
  "fromBlock": …, "toBlock": … | null, "roles": [ … ],
  "entries": [{"block": …, "slot": …, "roles": ["from", …], "state": "unverified"}],
  "next": "<head update>:<block>:<slot>" | null
}
```

`slot` is `0` for the block itself (fee recipient, withdrawal, uncle), else the transaction's
index plus one. A page is never read at an older head than its cursor's.

### `myotis_verifyAddressHistoryEntries(address, entries)`

Up to 50 entries, as a page returned them. Each comes back with its `state`, `final`, the block
hash it was checked in, the roles `confirmed` / `contradicted` / `unchecked`, and for a
transaction its `txHash`, `from`, `to`, `value` and the first ERC-20/721 `transfer` the
address is a party of. `unavailable` comes with a `reason`: ask again. A call takes at most
90 s, newest blocks first.

### The daemon's IPC

```bash
./gradlew :app:run -Pargs='get-address-history 0x<address> {"limit":5}'
./gradlew :app:run -Pargs='verify-address-history 0x<address> [{"block":…,"slot":…,"roles":["from"]}]'
```

## Checking it end to end

With an index on a Swarm network the node can reach (a local bee-factory holding an export, or
Swarm mainnet):

1. Start a reader build with the settings: `myotis-rpcd … --address-history-config <file>`, or
   the daemon with `-PswarmEngine -PaddressHistoryConfig=<file>`.
2. Wait for `beacon-status` `"SYNCED"` (the head gap and the verify call need a verified head).
3. Read a busy address's newest page, and one with a `toBlock` deep below the head.
4. Pass each page's `entries` to the verify call. Entries of finalized blocks should come back
   `verified` and `final`, each with its `txHash`. Deep ones verify through the checkpoint
   table, which takes about a second or a few per block.
