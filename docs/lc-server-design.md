# A dedicated light-client server (Rust)

Status: **design**, not built. Supersedes the CL half of
`dedicated-sepolia-node.md` §8.

## Why

A myotis wallet needs a beacon node that will (a) still have a free slot when
the wallet dials it, and (b) be findable without the wallet hard-coding its
address. A general-purpose beacon node is bad at both, and the reason is
structural rather than a matter of tuning.

Nimbus sizes **one** libp2p connection semaphore at `maxPeers`
(`eth2_network.nim`: `.withMaxConnections(config.maxPeers)`), shared between
inbound and outbound, and `peerTrimmerHeartbeat` trims at `wantedPeers` — the
*same* number. At the cap, `Switch.accept()` awaits `getIncomingSlot()` **before**
`transport.accept()`, so inbound connections are never accepted at all: they
complete the TCP handshake in the kernel and rot in the backlog. From the
wallet's side, connect succeeds and then nothing — indistinguishable from a dead
listener.

Worse, even below the cap a light client is the **first** peer trimmed:
`trimConnections` scores on stability-subnet count and gossip-mesh membership,
and a light client has neither, so it sits at 0 — the bottom of an ascending
sort.

Every previous attempt to fix this from the outside was a workaround on a
workaround: raise the cap (refills), turn off discv5 to stop random inflow
(node becomes undiscoverable, so wallets must hard-code it — and it then needs
hand-fed `--direct-peer` anchors, a candidate pool, and a top-up timer whose only
actuator is restarting the beacon node). Measured on zbox: 1 of 8 anchors
connected while the node ran perfectly on 86 peers it got by other means. The
scaffold was not load-bearing; it was decorative, and it caused 35 restarts in
two days.

The right split is to stop asking one process to do two unrelated jobs:

- **Nimbus** goes back to being an ordinary beacon node — discv5 on, stock peer
  limits, no anchors, no supervisor. It follows the chain.
- **The LC server** serves wallets. It is the only component facing them, and
  it sets its own limits.

## What a wallet actually needs

The complete surface is nine protocols. Verified against
`rust/myotis-net/src/protocols.rs` and the Java constants in `BeaconP2PService`:

| Protocol | Role |
|---|---|
| `status/1`, `status/2` | mandatory handshake — peers drop you without it |
| `ping/1`, `metadata/2`, `goodbye/1` | housekeeping |
| `light_client_bootstrap/1` | one-shot trust anchor |
| `light_client_updates_by_range/1` | per-period sync-committee updates |
| `light_client_finality_update/1` | per-slot |
| `light_client_optimistic_update/1` | per-slot |

One asymmetry between our own engines: the **Java** CL also calls
`beacon_blocks_by_range/2`, but only over a bounded recent window
(`finalizedSlot+1 .. attestedSlot`, at most a couple of epochs) in
`BeaconLightClient.fillChainStateRoots`, purely to extract execution state
roots. The **Rust** engine never requests blocks — it takes the execution state
root from the LC header's `execution` field, verified against the block body
root via `execution_branch` (`myotis-consensus/src/store.rs:157`). So this is a
Java-engine wart to fix on our side, not a requirement on the server. Until it
is fixed, either proxy a bounded block window or accept that Java-engine hosts
still need a full CL for that one call.

## Where the data comes from: Nimbus REST over loopback

The LC server does **not** peer with Nimbus over libp2p. A libp2p connection
over 127.0.0.1 is still a libp2p connection — `getIncomingSlot()` does not care
about the source address — so loopback buys nothing against the cap.

Nimbus's REST API is a genuinely different door, outside the peer table
entirely: no semaphore, no trimmer, no peer scoring. Requires `--rest`
(off by default; binds 127.0.0.1) plus the already-set
`--light-client-data-serve=true`.

```
/eth/v1/beacon/light_client/bootstrap/{block_root}
/eth/v1/beacon/light_client/updates?start_period=&count=
/eth/v1/beacon/light_client/finality_update
/eth/v1/beacon/light_client/optimistic_update
```

This satisfies the hard requirement that the LC server can **always** reach the
newest update regardless of how Nimbus's 500 p2p slots are being used.

### This does not breach the no-HTTP rule

CLAUDE.md forbids sourcing production data from a local client over HTTP. That
rule governs how a **wallet** obtains data. Here the consumer is our own
infrastructure, and the payload is self-verifying end to end: a bootstrap is
anchored to the checkpoint root the wallet already pins, and every update is
verified against sync-committee BLS signatures by the wallet that receives it.
A relay can withhold data; it cannot forge it. The wallet's trust anchors are
unchanged.

## What already exists

Most of the server is written. In `rust/myotis-net`:

- Full libp2p host — Noise, yamux, SSZ+snappy req/resp codecs.
- **Inbound already works for 5 of 9 protocols** with real answers:
  `respond_inbound` (`reqresp.rs`) serves `status/1`, `status/2`, `ping`,
  `metadata/2`, `goodbye`. The four LC protocols currently fall through to
  `ResourceUnavailable` — "no relay cache yet".
- **Multi-chunk responses already round-trip.** `decode_multi_chunk_response`
  exists and its test builds the wire by concatenating `encode_success_response`,
  which is exactly how `updates_by_range` must answer. No new protocol work.
- **A real discv5 instance** (`discovery.rs`, sigp `discv5` 0.11). Its local
  record is built as `Enr::builder().build(&enr_key)` — no endpoint, hence
  unlistable. This is client-mode-by-omission, not a missing capability.

## The work

1. **An LC store** — bootstraps keyed by block root, updates keyed by period,
   plus the latest finality and optimistic update. Small and fully shareable:
   every client gets identical bytes. Dominated by the 512×48-byte sync
   committee, so ~25 KB per update.
2. **Ingestion** — poll Nimbus REST per slot for finality/optimistic; fetch
   updates by period on demand and cache; fetch bootstraps on demand by root.
   Prefer the SSE stream (`/eth/v1/events`) over polling if Nimbus exposes the
   light-client topics.
3. **Serve the four LC protocols** in `respond_inbound`, replacing the
   `ResourceUnavailable` fallthrough. `updates_by_range` additionally needs
   `ProtocolSupport::Outbound` → `Full` and removal from the responder's
   excluded arm.
4. **Publish an ENR** — build the discv5 record with ip/tcp/udp and the `eth2`
   fork-digest field so wallets discover the server without hard-coding it.
   This is the point of the whole exercise.
5. **Daemon + limits** — a binary, a systemd unit, and a connection cap we
   choose.

## Library policy

This is a **server-side daemon**, so the constraints that shape `myotis-net` —
iOS/Android targets, binary size, dependency minimalism — do not apply. Prefer
libraries; the question is only which.

**Not Lighthouse's networking or REST crates.** `lighthouse_network` (its
libp2p req/resp + discv5 + ENR machinery) and `eth2` (its beacon REST client)
are **not published on crates.io** — verified; both return "does not exist".
They are internal to the Lighthouse monorepo and consumable only as a git
dependency pinned to a commit, dragging in a very large workspace and its
`EthSpec` generics. They would also sit *alongside* `myotis-net`'s existing
implementation of the same protocols rather than replacing it, since our own
wallets are already proven against that stack. Two protocol stacks to keep in
step is a worse position than one.

**Yes to the published, standalone pieces.** `ethereum_ssz` (0.10.4) and
`tree_hash` (0.12.1) are Lighthouse-authored and generally useful; take them if
LC objects need modelling. An async HTTP client is a genuine gap — the Rust
workspace has none today (only `serde_json`) — so add `reqwest` with rustls,
which fits the existing tokio runtime.

**Settled: SSZ works, so this is a byte cache.** Verified against the live
Nimbus v26.7.0 on zbox (REST enabled 2026-08-08, `127.0.0.1:5052`). All four LC
endpoints honour `Accept: application/octet-stream` and answer 200, and the
response carries an `Eth-Consensus-Version` header (`fulu`) naming the object's
fork — which is exactly what the libp2p context bytes need.

| Endpoint | SSZ bytes | JSON bytes |
|---|---|---|
| `optimistic_update` | 1 000 | 2 529 |
| `finality_update` | 2 081 | 5 096 |
| `updates?count=1` | 26 927 | 57 384 |
| `bootstrap/{root}` | 25 673 | — |

No LC type modelling is required: fetch SSZ, wrap, serve.

### The one framing detail

The `updates` endpoint returns a list, framed per chunk as:

```
u64 little-endian length | 4-byte fork digest | LightClientUpdate SSZ
```

where the length covers *digest + update* (observed: `2e69000000000000` =
26 926, then digest `74d01459`). Chunks vary in size by a few bytes because
`ExecutionPayloadHeader.extra_data` is variable-length, so they must be walked
by the length prefix, not assumed uniform.

Converting to a libp2p `light_client_updates_by_range` response is therefore:
split on the length prefix, and for each chunk call the existing
`encode_success_response(update_ssz, Some(fork_digest))` and concatenate. That
is precisely the shape `decode_multi_chunk_response`'s own round-trip test
builds, so both directions are already covered by code we have.

The single-object endpoints need a fork-name → fork-digest mapping for the
context bytes (from `Eth-Consensus-Version`); myotis already computes fork
digests for `status`, so this is a lookup, not new machinery.

## Historical depth: the server archives, Nimbus does not

Measured on zbox (2026-08-08): Nimbus serves LC updates only from **period 1323**
(1321/1322 return 0 bytes), while its *block* floor is far deeper — slot
~9,824,218, **period 1199**. A 124-period gap where blocks exist but LC data does
not.

The cause is state, not blocks. A `LightClientUpdate` carries
`next_sync_committee` and its Merkle branch, which come from the beacon **state**
at the attested block. Backfilled blocks are stored without states, and
`--history` defaults to `prune`, so historical states are gone.
`--light-client-data-import-mode=full` (already set) derives what it can; it
cannot conjure states the node does not have. `--light-client-data-max-periods`
is a retention *cap* — it can only shorten the window, never extend it.

Extending it on Nimbus would mean `--history=archive` plus state history
reaching back that far: a full sync from genesis, or a trustedNodeSync with
`--reindex`. Long, disk-hungry, and it buys a permanently slower startup.

**Don't. Archive in the LC server instead.** The full set from period 0 to now
is ~1327 × ~27 KB ≈ **36 MB** — trivial to hold. Every period below the current
one is **immutable**, so each is collected exactly once and kept forever. And the
server needs no trust in whoever supplied them: a wallet verifies each update
against the sync committee established by the previous period, chaining from its
own anchor, so a bad archive entry is detected by the client, not relied upon.

This is what makes the LC server strictly better than any single beacon node
rather than merely a proxy for one.

Sourcing the back-archive is a one-time job: an archive-mode node, or a public
beacon API that exposes the endpoint. Note the checkpoint provider we already use
(`checkpoint-sync.sepolia.ethpandaops.io`) returns 404 on
`/eth/v1/beacon/light_client/updates` — including for periods our own node serves
— so that is an endpoint-availability limitation there, not missing data.

Near-term this is not urgent: a wallet only needs updates from *its pinned
checkpoint* forward, and the shipped sepolia pin is period 1324, inside the live
window. The archive matters for wallets with stale pins, and for decoupling the
shipped pin from the node's sync point so the two no longer have to move together.

### Nimbus does not prune LC data (so its window grows)

From source: `maxPeriods = config.maxPeriods.get(SyncCommitteePeriod.high)` —
unset means effectively unlimited — and `targetLightClientTailSlot` then reduces
to the Altair fork slot, i.e. "retain everything". LC data is also **persisted**,
in a `LightClientDataDB` keyed by period/root/slot
(`beacon_chain_db_light_client.nim`), not merely an in-memory cache rebuilt at
startup.

So the 1323 floor means "never had the states to derive anything older", not
"derived it and threw it away". The window only widens: the floor stays, the head
advances. The one way to break this is to set
`--light-client-data-max-periods`, which can only prune — so don't.

### The archive must be durable; the live window need not be

The two halves of the store have opposite recovery properties, and this is the
main reason the archive lives on disk rather than in memory:

- **Live window (1323 → head): disposable.** Refetchable from Nimbus in seconds.
- **Back-archive (below Nimbus's floor): irreplaceable.** Nothing we operate can
  regenerate it. Lose it and it is gone.

Requirements that follow:

1. **Persist the archive; treat memory as an accelerator in front of it.**
2. **Append-only.** Periods below the head never change, so a written record is
   never rewritten — a crash can only tear the tail record, never corrupt
   history.
3. **Checksum and self-validate on load, refetch what fails** — the same
   discipline as the MLIX log index (magic, version, checksum, coverage spans).
4. **Back it up.** At ~36 MB and immutable, a copy on another disk *is* the
   answer to "what if it forgets", and restoring from an untrusted copy is safe
   because clients verify every update anyway.

Note the failure mode is bounded: with an empty archive the server's range simply
equals Nimbus's. Losing the archive is a **degradation to as-good-as-Nimbus**,
never an outage. The same immutability makes the archive shippable with the app
later, exactly like the log-index seed.

## Capacity

Comfortably past 1000 connections. Per-connection state is a Noise session and
a yamux stream — tens of KB — and there is no per-peer computation: every client
receives the same cached bytes. It is a broadcast cache with a request
interface. What makes a beacon node expensive per peer (gossipsub mesh, peer
scoring, attnet/syncnet tracking, full chain state) is absent by construction.

Expect stranger traffic anyway: once the ENR is published, every CL on the
network will discover it, dial, complete `status`, find no blocks and no gossip,
and drop — then rediscover it later. That churn is cheap here, and crucially the
cap is ours to set rather than one inherited from a beacon node's sizing.

## Rollout

Ordered so nothing regresses:

1. ~~Enable `--rest` on Nimbus.~~ **Done 2026-08-08** — purely additive,
   `127.0.0.1:5052`, verified serving all four LC endpoints in SSZ.
2. Build the server. Verify a wallet can bootstrap and stay synced from it
   alone, with Nimbus's pinned multiaddr removed from the client config.
3. Only then: flip Nimbus to `--discv5=true`, drop the direct-peer anchors, the
   candidate pool, the top-up timer and its unit, and restore stock peer limits.
4. Replace the pinned CL multiaddr in `NetworkConfig` with discovery.

## Rejected alternative: patching Nimbus

A patch was written (not built, not installed) adding an `Eth2Agent.Myotis`
classification, switching `withMaxConnections` to `withMaxInOut` so the inbound
semaphore no longer collides with the trim threshold, and exempting myotis peers
from `trimConnections` up to a bound. It works in principle, but it means
carrying a fork of a beacon node — including its vendored `nim-libp2p` in the
more invasive variants — across every upgrade, and it makes admission depend on
a self-reported, trivially spoofable agent string. The split above removes the
problem instead of managing it.
