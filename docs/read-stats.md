# Read statistics — measuring what a state-read cache would have saved

`read-stats` is a **shadow cache**: it caches nothing and serves nothing. It
watches every verified state fetch that actually crossed the network (an
account proof, a storage-slot proof, a bytecode blob), remembers the last
verified fact per key, and classifies each repeat by *which cache keying would
have made the fetch unnecessary* and *how much wall-clock that fetch cost*.
It exists so the question "is caching worth it, and which kind?" gets answered
with numbers from a real wallet session before any serving behaviour changes.

Both engines implement it with the identical JSON shape (schema 1):

| Surface | Java engine | Rust engine |
|---|---|---|
| `ChainHandle.readStatsJson()` | `ChainStack.readStats()` | `read_stats_json` (UniFFI, C ABI `myotis_read_stats_json`) |
| daemon IPC | `./gradlew :app:run -Pargs=read-stats` | same |
| log line | — | `[read-stats] …` every 5 min while reads flow (the tracing ring hosts drain) |

Reset on process start; survives pause/resume on both engines (the Java
stack owns it like `ServeStats`; the Rust engine parks it in the paused
handle and hands it to the reader that resume builds, and `read-stats`
answers from it while paused).

## What is observed

| Path | Java engine | Rust engine |
|---|---|---|
| `eth_call` / `eth_estimateGas` state fetches (the EVM oracle, prefetch waves included) | `SnapBackedStateOracle` | `PoolOracle` |
| `eth_getBalance` / `eth_getTransactionCount` / `eth_getCode` / `eth_getStorageAt` | via the same oracle | `ElReader::get_account` / `get_storage_at` / `get_code` |
| operator queries `get-account` / `get-storage` | `VerifiedAccountQuery` / `VerifiedStorageQuery` | the same reader paths |
| Tor-routed account reads (docs/privacy-and-tor.md; Rust engine, `tor` feature only) | — | `ElReader::get_account_over_tor`, costed at the snap round-trip over the circuit (never the circuit build) |

Only **verified** answers are observed (an unverified fallback is not a fact a
cache could ever have served). Existing cache hits never reach the observer:
the counters describe the fetches that *did* happen, so every "avoidable"
number is a genuine missed opportunity, not a hit the engine already took.

Three notes on what the numbers mean:

- Every path counts the account proof and the slot proof as separate facts,
  including a direct storage read (which fetches the account proof to learn
  the storage root, then the slot proof) — so `account.fetches` includes the
  account proofs paid for storage reads.
- `fetchMs` is the **snap round-trip** only. The beacon-anchoring ladder that
  follows a direct read (a header-chain walk on the fallback path) is never
  included: it is not something a state cache would have saved.
- The batched Java prefetch wave verifies many facts from one round-trip; the
  round-trip's time (end to end across peer retries, like the per-item paths —
  on the Rust EVM oracle that span is the hedged race, so a hedge delay spent
  on a silent first peer counts as cost the read paid) is shared out equally across the facts it verified, so a per-fact figure
  from that path is an estimate — removing one slot from a batch does not save
  1/N of the trip. A chunk that partially verifies and then retries on
  another peer flushes the first attempt's facts with the first attempt's
  time and the rest with the whole span, so the first window is counted
  twice in that (rare) case. The Rust prefetch issues one request per fact
  and times each.
- A verified **absence** (exclusion proof) is observed as the empty account on
  the Rust direct reads and on both EVM oracles, but not by the Java operator
  `get-account` query, whose proof check does not extract exclusions — so
  `account.fetches` for absent addresses compares across engines only on the
  wallet paths.

## The JSON

```json
{"schema":1,"windowSeconds":1834,
 "account":{"fetches":412,"repeats":380,"sameStateRoot":9,"unchanged":301,
            "fetchMs":61234,"sameStateRootFetchMs":900,
            "byAge":{"le12s":{"reads":12,"unchanged":12},"le60s":{"reads":300,"unchanged":250},
                     "le5m":{"reads":60,"unchanged":35},"gt5m":{"reads":8,"unchanged":4}}},
 "storage":{"fetches":2210,"repeats":2100,"sameStateRoot":40,"sameStorageRoot":1800,"sameValue":210,
            "fetchMs":401000,"sameStorageRootFetchMs":330000,
            "byAge":{ … }},
 "code":{"fetches":31,"repeats":24,"fetchMs":5100,"repeatFetchMs":3900},
 "tracked":{"accounts":57,"slots":410,"codes":7}}
```

| Field | Meaning |
|---|---|
| `fetches` | verified fetches of this kind that crossed the network |
| `repeats` | of those, the key had been fetched before (and was still tracked — see `tracked`) |
| `sameStateRoot` | repeats where the **world state root** was unchanged — the read was within the same block. A per-root cache (what the EVM path already has, and what the Rust direct-read path does NOT consult) would have served it with zero round-trips. |
| `sameStorageRoot` (storage) | repeats where the contract's **storage trie root** was unchanged, so the slot value is provably the same. A cache keyed `(storageRoot, slot)` would have served it for the price of the account proof alone — the SOUND cross-block scheme: the account proof *is* the freshness check. Includes the `sameStateRoot` cases. |
| `unchanged` (account) / `sameValue` (storage) | repeats where the value was identical although the root moved. No sound cache can exploit this without a proof — it is the **ceiling**, there to judge "serve a minute-old value" against how often that value would have been right. Counted only when the root-based classes above did not apply. |
| `fetchMs` | wall-clock of all fetches of this kind |
| `sameStateRootFetchMs` / `sameStorageRootFetchMs` / `repeatFetchMs` | wall-clock of the fetches the named keying would have avoided — the "was it worth it" number |
| `byAge` | repeats bucketed by how long ago the key was last fetched (≤12 s, ≤60 s, ≤5 min, longer), each with how many were value-unchanged. `unchanged / reads` per bucket is the hit rate a stale-serve of that age would have had. |
| `tracked` | keys currently remembered (bounded LRU: 4096 accounts, 16384 slots, 4096 code hashes). A repeat of a key evicted from here counts as a first fetch. |

Bytecode is content-addressed (`keccak(code) == codeHash`), so every code
`repeat` is avoidable by construction.

## How to read it

- **`storage.sameStorageRoot / storage.repeats` high** → a storage-root-keyed
  cache pays. The Java engine has one (`StateProofCache`); the Rust engine's
  twin (`rust/myotis-evm/src/cache.rs`) still keys by world root and is reset
  every slot — the known parity gap in
  `docs/reimplementation/06-rust-phase-notes.md`. A high number on a Rust
  session is that gap, measured.
- **`sameStateRoot` non-zero on the Rust engine** → the direct read path
  (`eth_getStorageAt`, `eth_getBalance`, …) re-fetched inside one block; it
  does not consult the EVM cross-call cache at all.
- **`code.repeats` non-zero on the Rust engine** → `get_code` re-fetches
  bytecode it already verified (the direct path does not consult the bytecode
  cache).
- **`byAge.le60s.unchanged / reads`** is how often a value up to a minute old
  would have been correct. Note what it does NOT say: serving it would still
  be serving a value verified against an OLDER root than the one asked for.
  That is a freshness decision (see `OPTIMISATIONS_AND_LIMITATIONS.md` §2.1 /
  §2.14), and the `sameStorageRoot` scheme above needs no such trade: it
  re-proves the account every block and reuses only what that proof shows
  unchanged.

## Trust posture

Nothing here changes what is trusted or served. The observer sees a fetch
only after it verified, and its output is counters. The point is to decide the
next step — a storage-root-keyed cache in the Rust engine, consulting the
existing caches on the direct read path, a bytecode cache on `get_code` — on
measured traffic rather than on a hunch.
