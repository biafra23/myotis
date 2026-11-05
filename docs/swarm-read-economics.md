# Reading from Swarm: what is free, and what paying buys

Research note (2026-11-02). Question: how much can a client read from Swarm
before it has to pay for reads, and how much does it pay per amount read? The
idea behind it is to let Myotis users pay so that state data and
sync-committee data come from Swarm faster and more reliably.

Status: research only. Nothing in Myotis reads from Swarm today. The Bee PoC
(docs/bee-rpc-service.md) runs in the other direction: Myotis serves Bee's
Gnosis RPC.

Sources: Bee's current `master` (constants and code cited below) and a live
`eth_call` against the SWAP price oracle on Gnosis. The throughput figures are
**estimates** derived from those constants, except where a measurement is
named.

Updated 2026-11-05. *Total free throughput* now uses the throughput `ant` (a
Rust light node) measured on mainnet. The first version estimated
100–200 KiB/s, which was 3–5× too low for a client holding ~100 peers.

## Short answer

Swarm has no free quota that runs out. Each peer forgives a fixed amount of
debt every second (time-based settlement, *pseudosettle*). As long as a node
reads slower than that, reading is free indefinitely. A light client holding
about 100 peers measured **0.5–0.6 MiB/s** this way. Paying (SWAP cheques)
lifts that speed limit. It costs roughly **0.7–0.85 BZZ per GiB**, about
**$0.03–0.04 per GiB** at a BZZ price of about $0.04, which is approximate and
varies a lot between price sites.

## How Bee charges for reads

### Price per chunk

A retrieval is paid per chunk (4 KiB payload), and the requester pays only the
**first hop**, i.e. the peer it asks. Forwarding nodes settle among themselves.
`pkg/pricer/pricer.go`:

```go
func (pricer *FixedPricer) PeerPrice(peer, chunk swarm.Address) uint64 {
	return uint64(swarm.MaxPO-swarm.Proximity(peer.Bytes(), chunk.Bytes())+1) * pricer.poPrice
}
```

with `swarm.MaxPO = 31` (`pkg/swarm/swarm.go`) and `poPrice = basePrice = 10_000`
(`pkg/node/node.go`). A chunk therefore costs between 10,000 accounting units
(the peer is at maximal proximity to the chunk) and 320,000 units (proximity 0).

A light node picks the closest connected peer. For a chunk in bin *p* of its
own address, that peer shares at least *p + 1* bits with the chunk, plus about
log₂(peers in the bin). Bin 0 carries half of all chunks, so the typical first
hop sits at proximity about 2–8: **about 240k–300k units per chunk**. The rest
of this note uses 270k as the typical value.

Price depends on the chunk count, not on bytes. A 500-byte trie node stored as
its own chunk costs the same as a full 4 KiB chunk.

### Accounting units to BZZ

SWAP cheques are paid in PLUR (1 BZZ = 10¹⁶ PLUR). The conversion comes from
the price oracle, which Bee polls through `getPrice()`. That returns
`(exchangeRate, deduction)` (`pkg/settlement/swap/priceoracle/priceoracle.go`).
The mainnet oracle address is hard-coded in `pkg/config/chain.go`
(`SwapPriceOracleAddress`).

Read live on 2026-11-02:

```bash
curl -s -X POST -H 'content-type: application/json' https://rpc.gnosischain.com --data \
 '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xA57A50a831B31c904A770edBCb706E03afCdbd94","data":"0x98d5fdca"},"latest"]}'
# → exchangeRate = 0x186a0 = 100000, deduction = 0x64 = 100
```

So **1 accounting unit = 100,000 PLUR = 10⁻¹¹ BZZ**, and the typical chunk at
270k units costs about **2.7 · 10⁻⁶ BZZ**. The oracle's owner can change the
rate, so re-read it before relying on these numbers.

| | units/chunk | BZZ/chunk | BZZ/GiB (262,144 chunks + ~0.8% intermediate chunks) |
|---|---|---|---|
| best case (proximity 31) | 10,000 | 1 · 10⁻⁷ | ~0.026 |
| typical (proximity ~5) | ~270,000 | ~2.7 · 10⁻⁶ | **~0.71** |
| worst case (proximity 0) | 320,000 | 3.2 · 10⁻⁶ | ~0.85 |

### The free allowance (pseudosettle)

`pkg/node/node.go`:

```go
refreshRate         = int64(4_500_000) // accounting units refreshed per second
lightFactor         = 10               // downscale payment thresholds and their change rate, and refresh rates by this for light nodes
lightRefreshRate    = refreshRate / lightFactor
basePrice           = 10_000
```

CLI defaults (`cmd/bee/cmd/cmd.go`): `payment-threshold = 13500000`,
`payment-tolerance-percent = 25`, `payment-early-percent = 50`.
`pkg/accounting/accounting.go` derives the light-node values:
`lightPaymentThreshold = paymentThreshold / lightFactor` and
`lightDisconnectLimit = (100 + tolerance)% of lightPaymentThreshold`.

Each peer applies these limits to your node independently:

| Your node type | Forgiven per peer | Free throughput per peer (at 270k units/chunk) | Debt allowed before you must settle |
|---|---|---|---|
| Full node | 4,500,000 units/s | ~16.7 chunks/s, about **65 KiB/s** | 13.5M units, about 50 chunks |
| Light or ultra-light node | 450,000 units/s | ~1.7 chunks/s, about **6.5 KiB/s** | 1.35M units, about 5 chunks; the peer disconnects you above 1.69M (25% tolerance) |

Mechanics, from `accounting.go`:

- A credit that would exceed `paymentThreshold + refreshDue` fails with
  `ErrOverdraft`. The elapsed time in `refreshDue` is capped at one second, so
  at most one second of refresh can be borrowed in advance.
- A refresh (pseudosettle) is triggered at most once per second, and only for
  at least one second's worth of refresh rate.
- With a chequebook (`payFunction` set), the node settles **monetarily** once
  the expected debt reaches `(100 − earlyPayment)% = 50%` of the threshold. The
  minimum cheque is `refreshRate / 5`, and a failed settlement is retried after
  10 s.
- An **ultra-light** node (`swap-enable: false`, `full-node: false`) has no
  pay function, so it can only wait for the next refresh.

### Total free throughput

A node spreads its reads over every connected peer, and every peer forgives
its own share. So total free throughput scales with the number of peers the
node holds.

**Model.** At ~250k units per chunk, one peer gives a light node about 1.8
chunks/s, roughly 7 KiB/s. More peers also make each chunk cheaper, because
the closest connected peer is closer to the chunk.

| Peers held | Free ceiling (light node) |
|---|---|
| 30 | ~0.2 MiB/s |
| 100 | ~0.7 MiB/s |
| 400 | ~2.8 MiB/s |

**Measured.** [`ant`](https://github.com/freedom-hq/ant), a Rust light node
that announces `full_node: false`, ran on mainnet:

- **Download:** a 55 MiB file three times in 92–108 s, holding 99–138 peers,
  with its debt cleared by pseudosettle alone. That is **0.5–0.6 MiB/s**,
  about 140 chunks/s: 1.8–2.1 GiB per hour, or 40–50 GiB per day of
  nonstop reading. Source: `ant` PLAN.md, Appendix F.6.
- **Upload with SWAP off:** 300 MiB in 225–270 s with 99 peers, about
  1.1–1.3 MiB/s (`ant` PR #138). That is more than the model allows. The
  model does not explain it.

**What the first version got wrong.** It estimated 100–200 KiB/s, assuming
about 8 bin-0 peers carry half of all chunks. A client holding ~100 peers has
far more than that.

**On a phone.** It may keep fewer peers to save battery and connections, so
it would land between the two figures.

**A full node** gets ten times the allowance per peer, but it is not an option
for a wallet:

- it has to accept inbound connections and hold a reserve (its share of the
  network's storage);
- announcing full-node status in the handshake without doing that work is not
  legitimate.

### What paying changes

A light node with a chequebook (`swap-enable: true`, `full-node: false`)
settles by cheque. Cheques go to the peer off-chain, and the peer cashes them
later, so there is **no transaction per read**. The one-time cost is deploying
the chequebook through the factory (`CurrentFactoryAddress` in `chain.go`),
which needs xDAI for gas plus a BZZ deposit. After that, the limit is the
peers' bandwidth and the network's latency, not the forgiveness rate.

Paying does **not**:

- **reduce per-chunk latency:** a retrieval still crosses several peers;
- **make data available:** a chunk stays on Swarm only while its uploader's
  postage batch is funded, and that is the uploader's cost, not the reader's.

## What this means for Myotis's data

### Sync-committee data: does not need payment

One `LightClientUpdate` per sync-committee period is about 25 KiB (the 512
committee public keys alone are 512 × 48 B = 24.0 KiB, 24.05 KiB with the
aggregate key). Periods last 27.3 h on mainnet and 11.4 h on Gnosis. A full
year of mainnet periods is about 320 × 25 KiB ≈ 8 MiB, about 2,000 chunks.
Since Capella each light-client header embeds the execution payload header
plus its branch, so a finality update (two headers, finality branch, sync
aggregate) is about 2 KiB and an optimistic update about 1 KiB. All of this
fits easily inside the free rate, and paying for all of it would cost about
0.005 BZZ, a fraction of a cent. Payment would buy nothing here.

### State data: payment helps throughput, not latency

- **Cost per read.** Store one trie node per chunk, and an account proof of
  8–10 nodes is 8–10 retrievals, about 2.7 · 10⁻⁵ BZZ, which is negligible. An
  `eth_call` touching about 500 nodes costs about 0.0014 BZZ.
- **Throughput.** On the free tier, 500 chunks take about 4 s at the
  ~140 chunks/s measured with ~100 peers, and 10–20 s with a few dozen
  peers. Paying removes that throttle.
- **Latency dominates.** Each trie level depends on the one above it, so a
  proof is a chain of sequential Swarm lookups, each crossing several peers.
  Payment does not shorten that chain. The publisher's data layout has to:
  per-account proof bundles of one or a few chunks, or a hash-to-chunk index,
  so that one read round-trip yields a whole proof.
- **Keeping it current is the dominant cost, and it is the writer's.** State on
  Swarm is useful only if someone uploads the changed trie nodes every block
  and keeps the postage batches funded. That cost is far larger than any read
  cost, so the business model sits with the publisher.

### Fit with the project rules (CLAUDE.md)

- **Trust:** nothing would be taken on trust. Trie nodes are checked by keccak
  against the state root of the verified header chain, and committee updates
  against BLS signatures. Swarm would be a transport only, and a stalled or
  hostile publisher could withhold data but not forge it. Withholding is a
  liveness problem, the same as for `roost`.
- **Data sources:** Bee runs over libp2p. However, Myotis calling a local Bee
  node's HTTP API is the "local client over HTTP" pattern that CLAUDE.md allows
  only for debugging. A production path needs either an embedded Swarm client
  (no mature Rust implementation is known to us) or an explicit owner
  carve-out like the one for `roost`'s self-verifying consensus objects. That
  decision is the owner's.
- **Synergy:** a Bee light node with a chequebook needs a Gnosis chain backend
  to verify chequebooks and read the price oracle. Myotis's Gnosis engine
  already serves that role in the Bee PoC (docs/bee-rpc-service.md).

## Open questions

- Measure the free throughput of a phone, which may hold far fewer than
  `ant`'s ~100 peers, and of Bee's own light and ultra-light modes. `ant`'s
  figures come from a server.
- Measure per-chunk retrieval latency from a phone, which bounds sequential
  trie walks whether or not the node pays.
- Who publishes state and sync-committee data to Swarm, in which layout, and
  who funds the postage batches.
- Whether Bee's retrieval actually falls back to the next-closest peer on
  `ErrOverdraft` under load, which the total-throughput estimate assumes.

## Sources

- bee `pkg/node/node.go`: `refreshRate`, `lightFactor`, `basePrice`, threshold limits —
  https://github.com/ethersphere/bee/blob/master/pkg/node/node.go
- bee `cmd/bee/cmd/cmd.go`: CLI defaults —
  https://github.com/ethersphere/bee/blob/master/cmd/bee/cmd/cmd.go
- bee `pkg/pricer/pricer.go`: per-chunk price —
  https://github.com/ethersphere/bee/blob/master/pkg/pricer/pricer.go
- bee `pkg/swarm/swarm.go`: `MaxPO = 31` —
  https://github.com/ethersphere/bee/blob/master/pkg/swarm/swarm.go
- bee `pkg/accounting/accounting.go`: overdraft, light limits, refresh timing —
  https://github.com/ethersphere/bee/blob/master/pkg/accounting/accounting.go
- bee `pkg/settlement/swap/priceoracle/priceoracle.go` and `pkg/config/chain.go`:
  oracle polling and address —
  https://github.com/ethersphere/bee/blob/master/pkg/settlement/swap/priceoracle/priceoracle.go,
  https://github.com/ethersphere/bee/blob/master/pkg/config/chain.go
- BZZ price, approximate and inconsistent across sites (about $0.04–0.05 in
  late 2026): https://www.coingecko.com/en/coins/swarm/usd,
  https://cryptorank.io/price/swarm/usd
- Measured free throughput of a Rust light node: `ant` PLAN.md, Appendix F
  (https://github.com/freedom-hq/ant/blob/main/PLAN.md), and the
  measurements in https://github.com/freedom-hq/ant/pull/138
