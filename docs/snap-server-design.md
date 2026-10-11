# A dedicated snap server? Serving verified state reads at roost scale

Status: **analysis and proposal — nothing here is built.** Companion to
[`lc-server-design.md`](lc-server-design.md), the design behind
[`rust/roost`](../rust/roost/README.md). Roost serves the light client to
thousands of wallets from a commodity box; this document asks whether the
execution-layer half of a wallet's traffic — the snap state reads behind
`eth_getBalance`, `eth_getStorageAt`, `eth_call` and `eth_estimateGas` — can be
served the same way, what that means for the proofs, and what it costs in
privacy. The open decisions are listed at the end; they are the owner's.

## TL;DR

- **The connection side carries over; the cache side does not.** Holding
  thousands of wallet sessions is as cheap as it is for roost. But roost is a
  byte cache of a tiny, immutable, identical-for-everyone data set, and snap
  data is none of those: every wallet reads its own keys, out of the whole
  state, and every proof expires with the block it was made for.
- **So a snap server is a front for a full execution node, not a cache.** Its
  capacity is set by *reads per second × proof size* — uplink first, disk
  second — not by the number of connected wallets. Thousands of wallets per
  server is realistic; the estimate is in [§Capacity](#capacity).
- **Trust is unchanged.** A proof verifies against the sync-committee-signed
  state root the wallet already holds. The server can withhold, not forge, and
  verifies nothing itself — the same posture as roost.
- **Privacy is the real new cost.** Roost sends everyone the same bytes and
  learns nothing about a wallet's addresses. A snap server learns which
  addresses each wallet holds and, by timing, which belong together. Tor (an
  onion service is the right shape) hides the wallet's IP from it; nothing
  hides the clustering from a single operator.

## Why roost is cheap

`lc-server-design.md` §Capacity rests on three properties, and says so:

1. **Every client receives identical bytes.** There is no per-peer
   computation.
2. **The data set is tiny and immutable.** ~27 KB per sync-committee period,
   ~36 MB for sepolia's whole archive; a period below the head never changes,
   so it is collected once and kept forever.
3. **Responses are pre-encoded**, so serving is a memcpy and a write.

The rest of this document is about which of these survive for snap data.

## What a wallet asks for

Both engines read state with three snap messages (`docs/reimplementation/02`
§7), one key per request:

| Read | Request | Verified by |
|---|---|---|
| account | `GetAccountRange(root, keccak(address), 0xff…ff, 4096)` (`rust/myotis-net/src/el/peer.rs:778`) | the Merkle path for `keccak(address)` against `root` |
| storage slot | `GetStorageRanges(root, [accountHash], keccak(slot), 0xff…ff, 4096)` (`peer.rs:804`) | the path for `keccak(slot)` against the account's **proven** `storageRoot` |
| bytecode | `GetByteCodes([codeHash], 256 KiB)` (`peer.rs:821`) | `keccak(code) == codeHash` |

The state root is the beacon anchor's **optimistic** execution state root
(`rust/myotis-net/src/el/reader.rs:10-13`), taken from the light-client header's
`execution` field and proven against the block body root through
`execution_branch`. A proof against it verifies as `stateRootMatch` with no
header walk. That head read is the normal case. Its fallback is the serving
peer's own head, anchored by a `headerChain` walk. A caller can also ask for a
`finalized` read (ABI ≥ 32), which proves against the beacon-finalized root
instead — a separate mode, not a fallback.

Two consequences that shape everything below:

- **All synced wallets ask for the same root in the same slot.** They follow
  the same optimistic updates. (`finalized` reads share one root for a whole
  epoch — 6.4 min on mainnet, 80 s on Gnosis — while the node still holds it.)
- **The verifiers consume the proof, not the range.** The Rust engine's
  `verify_account` / `verify_storage` (`rust/myotis-wire/src/snap/fetch.rs:77-112`)
  and the Java EVM oracle (`SnapBackedStateOracle.java:599,625`) read only the
  proof nodes. The Java operator queries additionally read the requested
  account's slim entry from the list (`VerifiedAccountQuery.java:160`,
  `VerifiedStorageQuery.java:93`, which throws when it is missing), so any
  response must still carry that one entry.

## Measured: what a proof weighs and how long it lives

Measured 2026-10-11 on mainnet blocks 26,171,433–26,171,436 with `eth_getProof`
against a public RPC endpoint — a one-off measurement for this document, not a
data path. `eth_getProof` returns the same Merkle path a single-key snap proof
carries (both are `trie.Prove` of the same key against the same root). Byte
counts are the RLP node encodings, before snappy; proof nodes are mostly
hashes and barely compress.

**Size:**

| Account | Account proof | Holder's balance-slot proof |
|---|---|---|
| an EOA (`0xd8dA…6045`) | 9 nodes, 3,761 B | — |
| USDC (proxy) | 9 nodes, 3,847 B | 7 nodes, 3,070 B |
| USDT | 8 nodes, 3,732 B | 10 nodes, 3,363 B |
| WETH | 9 nodes, 3,794 B | 7 nodes, 2,945 B |
| an absent address (exclusion proof) | 10 nodes, 3,839 B | — |

So **~3.8 KB per account and ~3–3.4 KB per slot**: a token balance is ~7 KB of
proof, before anything else on the wire.

**Lifetime** — the same keys at three consecutive block transitions, which
nodes of the path changed (`X`) and which stayed (`=`), root first:

| Key | N→N+1 | N+1→N+2 | N+2→N+3 | Changed bytes per block |
|---|---|---|---|---|
| the EOA (not touched in these blocks) | `XXXX=====` | `XXX======` | `XXXX=====` | 1,596–2,128 of 3,761 |
| the absent address | `XXX=======` | `XX========` | `XX========` | 1,064–1,596 of 3,839 |
| USDC's account (touched every block) | `XXXXXXXXX` | `XXXXXXXXX` | `XXXXXXXXX` | all 3,847 |
| the holder's USDC balance slot (unchanged) | `XX=====` | `XX=====` | `XXX====` | the top 2–3 storage nodes |

What this means:

- **A proof is valid for exactly one block.** Even for state that did not
  change, the top two to four levels of the account trie are rewritten every
  block — other accounts changed under them. So roost's "collect once, keep
  forever" has no snap equivalent: a head-read proof cache is a one-slot cache
  (12 s on mainnet, 5 s on Gnosis); only `finalized` reads hold one root for
  an epoch.
- **Popular contracts churn completely.** USDC's own account proof was new in
  every one of the three blocks.
- **Roughly a quarter to a half of a repeat proof is new** for state that did
  not change (28–57 % of the bytes in the table). A client that kept the
  previous block's nodes would need only the top levels again. That is a
  protocol extension snap does not have
  ([§Later](#later-a-proof-delta-protocol)).

## Roost and snap side by side

| | roost (light client) | snap server |
|---|---|---|
| Bytes per client | identical for all | per address and slot |
| Data set | ~27 KB per period, ~36 MB archive | the whole state — hundreds of GB on mainnet, held by a full EL node |
| Lifetime of a served object | a past period: forever | one block (12 s / 5 s) |
| Serving work | memcpy + write of a pre-encoded response | a trie walk of ~8–10 nodes per key, partly from disk, then encode |
| Load pattern | per-slot polling, ~1 KB/slot/client; cold-start bursts | idle until the user acts; then bursts (refresh, dapp `eth_call`s) |
| Trust | self-verifying against the sync committee | self-verifying against the beacon-signed state root |
| What the operator learns | that an IP runs a myotis wallet | which addresses an IP holds, and which belong together |

## What carries over

### Connections are cheap; being an ordinary eth peer is not

A wallet connection is an RLPx session — tens of KB of state, like roost's
Noise + yamux session — and a wallet keeps it open (the Rust pool targets 8
snap peers, `PoolConfig::default`). Ten thousand idle sessions is a memory and
`LimitNOFILE` question, not a CPU one.

What does *not* scale is the way wallets are served today. The dedicated
sepolia node (`dedicated-sepolia-node.md` §3) is a patched geth that admits
wallets past `MaxPeers` by their RLPx Hello client id. That has the two flaws
roost was built to escape on the CL side:

- **Every wallet is a full eth peer to geth**, so geth announces every pooled
  transaction to it (and pushes full bodies to √n peers). Estimate for mainnet:
  ~17 tx/s × ~38 B per announcement entry ≈ 0.65 KB/s per wallet — ~5 Mbit/s
  of uplink at 1,000 wallets, for a stream the wallet uses only to spot its own
  sent transactions (`peer.rs:956`, the sent-tx watch, #531).
- **Admission rests on a self-reported, trivially spoofable string** — the
  objection that sank the Nimbus patch (`lc-server-design.md` §Rejected
  alternative).

So the split is the same as roost's: the node goes back to being an ordinary
node, and a **front** faces wallets. The front speaks Hello, eth Status
(eth/69, with an honest block range), and snap; it gossips nothing, sets its
own connection cap, and reaches the node over a small fixed pool of upstream
connections (geth serves snap requests sequentially per peer, so parallelism
comes from several upstream sessions, each with its own node key). Those
sessions are ordinary eth peers of the node, so they must be configured as
trusted peers (exempt from `MaxPeers` and trimming) and they still receive the
node's transaction gossip — a fixed cost for a handful of sessions, not one
per wallet.

**Strangers stop being a cost by construction.** If the front answers every
snap request in the single-key shape below — one entry and its path, whatever
range was asked — a snap-*syncing* full node that finds it gets one entry per
request: useless for a sync, and as cheap to serve as a wallet's read. That
makes admission by identity unnecessary: the front serves exactly what a
wallet needs, to anyone. It does **not** make the request rate free — reads
per second are the binding cost ([§Capacity](#capacity)), and a peer that asks
nonstop sets it. So, as roost bounds its work per request
(`lc-server-design.md` item 5), the front needs a per-connection request-rate
cap and a global upstream budget, with misses refused rather than queued.

What else the front must answer, or decline cleanly so the wallet asks another
peer: `GetBlockHeaders` (the fresh-head fetch and the `headerChain` walk),
bodies and receipts (fee history, receipt polling). The recent ones are the
same for every wallet and hash-chained to the beacon-anchored block, so they
are the one part besides bytecode that *does* behave like roost data — a
small, shared, verifiable cache. The eth/69 range the front advertises must be
one it can serve (`el/served.rs` holds the same rule for the wallet's own
window).

### Bytecode is a genuine roost-style cache

Code is content-addressed (`keccak(code) == codeHash`) and never changes for a
given hash. A front can pre-encode the bytecode of popular contracts once and
serve it forever, exactly as roost serves a past period. This is the single
snap object with all three of roost's properties.

### One root per slot: a coalescing response cache

Because every synced wallet reads at the same optimistic root, identical
requests from different wallets in the same slot produce identical answers. A
front keyed by `(root, key)` — normalised: the request id and the caller's
`responseBytes` are not part of the key, or no two wallets' requests ever
match — that merges concurrent misses into one upstream fetch serves the
shared part of the load once per slot.

How much is shared depends on what wallets read. A token balance through
`eth_call` on a proxied token (USDC) reads the proxy's account, its EIP-1967
implementation slot, the implementation's account, the two bytecodes, and the
holder's balance slot. Only the last is per-wallet. With the measured sizes,
that is ~10.6 KB of shared proof against ~3 KB of personal proof — **about
three quarters of the bytes for a proxied token are the same for every wallet
in that slot.** A front can also pre-compute the top-N contract accounts on
every new head (1,000 accounts × ~3.8 KB ≈ 4 MB per block).

Two limits on that win:

- **It saves the node's work, not the uplink.** Every wallet still downloads
  its own copy of the shared proof; the cache saves the trie walk.
- **"Pre-encoded" is approximate here.** The request id sits inside the RLP
  payload, and RLPx compresses and encrypts per message, so each answer is
  re-framed: cheap, but not roost's bare memcpy.

### Lean responses

Geth answers a single-key read with a full page: `ServiceGetAccountRangeQuery`
keeps adding neighbouring accounts until `size > req.Bytes` (4 KiB), then
proves both the first and the last key (`eth/protocols/snap/handlers.go`); the
storage path does the same. The wallet discards the page. The front can drop
it, and needs no proof surgery to do so: asking its own geth with
`responseBytes = 1` returns exactly one entry, because both loops admit the
first entry before the cap can stop them. For an **existing** key the "last"
key is then the requested one, so the second boundary path disappears too: the
response is the one entry the Java operator queries need plus the ~3.8 KB path
every verifier reads. For an **absent** key — a new address, a zero token
balance — the one entry is the next neighbouring key, and geth proves both the
origin (the exclusion the wallet checks) and that neighbour. The two paths
share their upper nodes, so the extra is a few nodes, not a second full proof
(not measured). `eth_getProof` would send the exclusion path alone.

(The wallet could make the same change against public peers without any
server. That is a separate experiment: geth's behaviour is read from source
above, but how Nethermind, Besu and reth treat a tiny cap is untested.)

## Capacity

An estimate from the measurements above, not a load test:

- **A wallet refresh** — ETH balance and nonce plus ten token balances, half of
  them proxied — is about 31 verified reads and ~110 KB of lean proof
  (one account proof, five plain tokens at ~7 KB, five proxied at ~14 KB;
  bytecode cached after the first time). A zero balance is an absent slot and
  adds a few nodes for the neighbour's path ([§Lean responses](#lean-responses)).
- **1,000 wallets refreshing once a minute** is ~520 reads/s and ~1.8 MB/s —
  **about 15 Mbit/s of uplink.** Of those reads, only the ~180/s personal ones
  (each wallet's own account and balance slots) are new per slot; the shared
  ones are generated once per slot.
- **Proof generation at that rate is not the limit.** A proof is ~8–10 node
  lookups with the top levels hot in memory; a few hundred per second sits far
  inside one NVMe-backed node (estimate; measure before sizing on it).

So the binding resources, in order, are **uplink bandwidth**, then **disk
IOPS** on the node under a cold cache, then file descriptors. Connection count
is not one of them. The load is the opposite of roost's: idle wallets cost
almost nothing, an active one costs ~100 KB per refresh, and a dapp-heavy
session (an `eth_call` can touch dozens of slots) costs more.

The hardware is a full execution node per chain — 2 TB NVMe and 32 GB RAM
(`dedicated-sepolia-node.md` §2) — plus the front. Commodity, but not roost's
small box. On Gnosis the upstream cannot be geth (it does not run the chain);
Nethermind serves snap with its FlatDb / halfpath layouts
(`dedicated-sepolia-node.md` §1), and the 5 s slot shortens every cache
window above.

## The proofs: trust

The posture is roost's, and so is the argument for it:

- **The server can withhold but cannot forge.** The root a proof is checked
  against arrives in a sync-committee-signed light-client header; the wallet
  holds it before it asks. A wrong value fails the Merkle check; a proof for a
  different root fails it too; an exclusion proof is checked the same way as an
  inclusion proof.
- **The server verifies nothing.** It relays what its node produced; the
  wallet is the verifier, as for roost.
- **Withholding is a liveness attack, and this design concentrates it** — the
  same trade CLAUDE.md records for roost. It is never silently wrong: a read
  that gets no valid proof fails with an error, and the read ladder benches the
  peer for 30 s and tries the others (`READ_FAIL_BENCH`, `pool.rs`). How much a
  stalled front costs depends on what else serves the wallet. Where public
  peers still answer, it is one peer of eight. Where the front is the reason
  reads work at all — the case it is built for — a stalled front stops reads,
  and the wallet is back to whatever public peers will take it.

On the data-source rule (CLAUDE.md, *Data sources*): the wallet talks devp2p to
the front, and a front sourcing from its node over devp2p is devp2p end to end,
so neither needs a new decision. Sourcing over the node's JSON-RPC
`eth_getProof` instead would be simpler — it returns exactly the lean
single-key path and is not serialized per peer — but the 2026-08-08 carve-out
names light-client consensus objects, not state proofs. The substance is the
same (self-verifying against a beacon-signed root), the wording is not, so
that path is the owner's call ([§Open decisions](#open-decisions)).

## The proofs: privacy

This is where a snap server differs from roost in kind, not degree.

- **Roost learns nothing about a wallet's holdings.** Everyone gets the same
  bytes; the server learns that an IP runs a myotis wallet.
- **A snap server learns the portfolio.** Account reads name the address;
  storage reads name the slot's key — for a balance mapping
  `keccak(keccak(pad(holder) ‖ pad(index)))` — which anyone can match against a
  precomputed table of known holders. The server sees which addresses an IP
  holds, which tokens, and when it looks.
- **Today that linkage is spread out.** Reads go to whichever of the wallet's
  eight pool peers the read ladder picks, run by unrelated operators, and Tor
  mode spreads account reads over a reserve of up to 24 nodes that is
  "never a pin" (`privacy-and-tor.md`). A server that wallets pin and that
  serves them well concentrates it at one operator — which is also what makes
  it attractive to rank first.
- **Transaction broadcast concentrates the same way.** If the front relays the
  wallet's own transactions to its node, it sees transaction ↔ IP as well.

### Reaching it over Tor: an onion service, not an exit

Tor-mode reads today leave through an exit to the peer's public IP:port (Arti
is built without its onion-service client: `rust/myotis-net/Cargo.toml`,
`arti-client` with `tokio` + TLS only). For a server myotis operates, an onion
service is the better shape:

| | Through a Tor exit (what ships) | Onion service |
|---|---|---|
| Exit problems the PoC measured (`privacy-and-tor.md` §2) | Present: reduced-policy exits refuse :30303, the rest are lossy. Listening on 443 would avoid most of it. | None — no exit at all. |
| Full nodes refusing Tor exits (§8.9) | Not an issue: the front sets its own limits. | Same. |
| What the path reveals | The exit sees the server's IP and timing, not the content (RLPx is end-to-end encrypted). | No relay knows both ends. |
| Hosting | Needs a public IP and port; zbox sits behind mobile CGNAT and relies on the netcup relay's DNAT. | Publishes outbound-only, from behind CGNAT, no relay needed. |
| Latency | 3 hops; the PoC measured 0.75 s on a good circuit, up to 18 s on a bad one. | 6 hops plus rendezvous setup, per isolated circuit. Unmeasured. |
| Wallet side | Nothing new. | Arti's `onion-service-client` feature (APK and dylib size to measure), and a pinned `.onion` address — discv4 and ENR records cannot carry one. |

On the server side this is stock C tor (`HiddenServiceDir` /
`HiddenServicePort` to the front's loopback port); whether Arti's client
solves the onion-service PoW defence puzzles is to be checked before relying
on that defence.

### What Tor does not fix

Tor hides the wallet's IP from the server. It does not hide which addresses
belong together: a refresh sends the reads for all of a wallet's addresses
within about a second, and one operator receiving them all can group them by
timing even when each address rides its own isolated circuit. That is address
clustering for every user, held by one party — exactly what the per-address
isolation and the 24-node spread exist to prevent.

Rules that follow, if the server is built:

- **One route per wallet per operator.** A wallet in Tor mode must not also
  reach the same server directly — not for account reads, and not for storage
  or `eth_call` reads either, since slot keys identify holders. Otherwise the
  operator links its Tor reads to its IP by the keys both carry.
- **A peer in the pool, not the place all reads go.** The front should be one
  of the wallet's snap peers that keeps reads working when public nodes refuse
  it — never ranked so that it takes every read by default.
- **Blunting the timing link costs latency or bandwidth.** Route each address's
  read to the server or a reserve peer at random; spread reads with random
  delays; add cover reads for popular contracts. None is free, and none
  removes the linkage.

## Suggested path

Each step stands alone; stop where the measurements say it stops paying.

1. **A front on sepolia, without caches.** Replaces the geth client-id patch:
   own connection cap, no gossip, upstream pool to the existing node,
   single-key answers via `responseBytes = 1`. Measure reads per wallet and the
   share of reads that repeat across wallets within a slot.
2. **Caches.** Bytecode (permanent), the per-root coalescing cache, pre-computed
   top-N accounts per head. Measure the hit rate against step 1's numbers.
3. **Mainnet and Gnosis**, sized from steps 1–2: one full node per chain (geth
   on mainnet, Nethermind on Gnosis) behind the same front.
4. **An onion endpoint**, only after the privacy rules above are decided.

Independent of all of it: the wallet-side `responseBytes` experiment against
public peers (§Lean responses), which would shrink every read without a server.

### Later: a proof-delta protocol

The lifetime measurement says a repeat read needs only the top two to four
nodes again. A wallet-specific protocol — "here are the node hashes I hold for
this key, send the rest", or a multiproof for all of a refresh's keys at one
root — would cut a repeat read of unchanged state by roughly half to three
quarters (popular contracts, which change every block, gain nothing). It is a
new protocol rather than snap, so it would only ever be served by our own
fronts; worth it only if step 1 shows uplink is the binding cost.

## Open decisions

All are the owner's, not the author's:

- **Build at all?** The privacy concentration in §The proofs: privacy is the
  price of the capacity. A front that keeps snap reads alive for wallets
  public nodes turn away is worth more on mainnet than on sepolia, where the
  patched geth already does that job.
- **Upstream: devp2p or `eth_getProof`?** devp2p needs no new decision;
  `eth_getProof` is simpler and leaner but sits outside the roost carve-out's
  wording.
- **Tor-mode routing to an operated server:** onion-only, exit, or not at all
  — and the "one route per wallet per operator" rule.
- **Transactions through the front:** whether it relays the wallet's own
  broadcasts (transaction ↔ IP at one operator), and whether it forwards any
  gossip at all (the sent-tx watch's signal).
