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

### OPEN DECISION: this needs a CLAUDE.md amendment, not an exception

CLAUDE.md's rule is unqualified: "the only sources for data are devp2p and
libp2p calling a local client via http may only be used for debugging purposes
it is not an option for production". Nothing in it scopes to the wallet, so
reading it as wallet-only would be a narrowing invented here, in a document
CLAUDE.md does not reference — leaving two texts that disagree and the next
reader to guess which wins. **This is the owner's call and is not settled by
this document.**

The substantive argument, for what it is worth: the payload is self-verifying
end to end. A bootstrap is anchored to the checkpoint root the wallet already
pins, every update is verified against sync-committee BLS signatures by the
wallet receiving it, and a relay can withhold but not forge. That is a genuinely
different situation from an EL RPC fallback, which is what the rule was written
against.

If accepted, the amendment belongs in CLAUDE.md's **Data sources** section, e.g.:

> …for a wallet; myotis-operated relay infrastructure may source *self-verifying*
> consensus objects (LC bootstrap/updates) from a local beacon node over loopback
> REST, because the wallet still verifies every byte against its own anchor.

Two boundaries the carve-out must keep, and they are the reason to write it down
rather than leave it implicit:

- **"Self-verifying" is doing all the work.** This must not widen into "the relay
  may serve anything it read over REST". Any path relaying something a wallet
  cannot check against sync-committee signatures — the `beacon_blocks_by_range`
  proxy floated above is the live example — needs its own justification, not this
  one.
- **Withholding is a liveness attack, and this design concentrates it.** After
  rollout, a wallet's LC data comes from one relay fed by one Nimbus. That
  failure is *detected*, not silently wrong: `BeaconSyncState` regresses out of
  SYNCED and queries fail with `beaconNotSynced` (gate 1 in
  `docs/readiness-and-verified-head-age.md`), so a stalled relay surfaces as "not
  ready" rather than as a confidently wrong balance, and the wallet falls back to
  discv5-discovered CL peers.

The alternative that needs no amendment: have the LC server peer with Nimbus over
**libp2p** as a `--direct-peer` (outbound from Nimbus, trim-exempt) instead of
using REST. It stays on-policy, but it is weaker — direct peers still take a slot
from the shared semaphore, so it reintroduces exactly the "can we always reach
the newest update" question that REST answers unconditionally.

## What already exists

Most of the server is written. In `rust/myotis-net`:

- Full libp2p host — Noise, yamux, SSZ+snappy req/resp codecs.
- **Inbound is already wired for 5 of 9 protocols**, though two of those are not
  yet spec-correct. `respond_inbound` (`reqresp.rs`) answers `status/1`,
  `status/2`, `ping`, `metadata/2`, `goodbye`. Of these, `status` and `metadata`
  are real answers; **`ping` echoes the caller's value instead of returning this
  node's metadata sequence number, and `goodbye` replies without disconnecting**
  even though Goodbye is a one-way notification. Both are acceptable in a client
  that dials out and closes; both must be fixed before shipping a public
  responder, or the daemon retains peers that asked to leave. Count them as
  remaining work. The four LC protocols currently fall through to
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
   committee, so ~27 KB per update (measured). Store the **fully encoded response** (result
   byte, context bytes, snappy frames), not the raw SSZ — serving then costs a
   memcpy and a write, which is what the capacity claim below rests on.

2. **Ingestion, entirely in background tasks.** Poll Nimbus REST for
   finality/optimistic; fetch and cache update periods; pre-populate bootstraps.
   Never fetch from the request path — see item 4.

   `/eth/v1/events` may be used as a **notification only, never as a data
   source**: it is `text/event-stream` with JSON payloads and offers no SSZ
   negotiation, so consuming its bodies would reintroduce the LC type modelling
   this design exists to avoid, and would make what we serve a re-encode rather
   than a verbatim relay of what Nimbus produced. Let an event trigger a refetch
   of the SSZ endpoint: same latency benefit, byte-cache property intact.

3. **A chain-view poller for `status`.** Easy to miss, and the daemon is dead
   without it: `respond_inbound` answers `status` from `LocalStatus`, which today
   stays current only because `refresh_local_status` (`sync.rs`) derives
   finalized/head roots and slots from decoded light-client headers as the sync
   loop runs. A byte-only cache that skips this keeps serving its **initial
   checkpoint status forever**, and peers judge us on it. Feed `LocalStatus`
   from REST (head + finality checkpoints) or by decoding the LC headers we
   already ingest, and handle fork transitions.

4. **Serve the four LC protocols as a pure cache read.** This is *not* a
   one-line replacement of the `ResourceUnavailable` fallthrough.
   `respond_inbound` is **synchronous**, called inline from `on_rr_event` on the
   single swarm task — there is no `await` point. An on-demand REST fetch there
   would either stall every other connection's handshakes and responses for an
   HTTP round trip, or `block_on` inside a tokio worker and panic.

   So: the handler stays a pure read of a shared cache, and **`ResourceUnavailable`
   remains the miss path**, with a background task filling on miss. That is
   correct behaviour today — a wallet retries against another peer and the second
   attempt hits — and it preserves the broadcast-cache property. (The alternative,
   parking the `ResponseChannel` and answering from a spawned task, is permitted
   by libp2p but a much larger change.)

   `updates_by_range` additionally needs `ProtocolSupport::Outbound` → `Full` and
   removal from the responder's excluded arm.

5. **Bound the work per request.** A connection cap alone does not do this: this
   is a public responder and `updates_by_range` carries caller-controlled `u64`
   start and count. Enforce the spec's `MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128`,
   cap total response bytes, refuse ranges outside the servable window rather
   than scanning, and coalesce plus rate-limit upstream cache misses so one
   caller cannot fan out into a burst of Nimbus fetches. Bootstraps are the
   awkward case — keyed by arbitrary block root, so unbounded and genuinely
   miss-prone — which argues for pre-populating only checkpoint-aligned roots and
   refusing the rest.

6. **Fix `ping` and `goodbye`** (see above): return our own metadata sequence
   number rather than echoing, and actually disconnect on Goodbye.

7. **Publish an ENR** — the discv5 record with ip/tcp/udp and an **`eth2`** field
   carrying the complete 16-byte SSZ `ENRForkID`
   (`fork_digest || next_fork_version || next_fork_epoch`), not merely the
   4-byte digest; a truncated field is malformed and standard clients reject it.
   This is the point of the whole exercise, and it needs three things the
   client-side code deliberately does not do:

   - **Persist both keys.** Today the discv5 key (`discovery.rs`:
     `CombinedKey::generate_secp256k1()`) and the libp2p host key (`reqresp.rs`:
     `Keypair::generate_secp256k1()`) are generated fresh on every start. Right
     for a wallet; fatal for a published server — each restart becomes a new node
     ID, so the ENR is a fresh DHT entry with no accumulated reachability, and
     every wallet's cached `/p2p/<peer-id>` entry points at an identity that no
     longer exists. Those then burn the three strikes to eviction
     (`clcache.rs`, `FAILURE_THRESHOLD = 3`), taking the `lc` and period-range
     tokens that made the peer worth keeping. A routine deploy would repeatedly
     un-learn the server from every wallet that had proven it. This is the same
     lesson `--netkey-file` taught us on the Nimbus side, and it cost a day.
   - **Persist the ENR sequence number** too, so it stays monotonic across
     restarts; otherwise updated records lose to cached ones in the DHT.
   - **Re-publish at fork *and* BPO boundaries.** Wallets filter discovered peers
     on `accepted_fork_digests` (`discovery.rs`), so a stale digest makes the
     server invisible to precisely the clients it exists for.

8. **Daemon + limits** — a binary, a systemd unit with an explicit
   `LimitNOFILE` (the shell default here is 2048; Nimbus's unit sets 524288),
   and a connection cap we choose.

## Library policy

This is a **server-side daemon**, so the constraints that shape `myotis-net` —
iOS/Android targets, binary size, dependency minimalism — do not apply. Prefer
libraries; the question is only which.

### Where the crate lives — decide this first, it gates the rest

That "constraints do not apply" claim is only true if the crate sits **outside**
the workspace. As a member of `rust/` it would inherit two things it must not:

- **Everyone's build cost.** `cargoBuildHost` is `cargo build --release
  --workspace` and runs before `:app:run` and `:consensus:test`; `cargoTest` is
  `cargo test --workspace`, wired into root `check`. Every Android, iOS and JVM
  developer would compile an HTTP stack they never link.
- **`panic = "abort"`**, set workspace-wide in `rust/Cargo.toml`, which a member
  cannot override (crate-level `[profile.*]` is ignored in a workspace). That is
  the correct FFI rule for the engine. In a daemon holding 1000+ connections it
  means one panic anywhere kills the process for every connected wallet, with
  none of tokio's per-task isolation — and the framing parser above walks an
  attacker-influenced `u64` length prefix and slices on it.

**Resolution: a standalone excluded crate**, following the existing `tor-poc`
precedent (`exclude = ["tor-poc"]` — "pulls the whole Arti dependency tree, which
must never burden the pure-engine build or CI"). That fixes both at once, since
an excluded crate carries its own profile and can set `panic = "unwind"`, so a
malformed chunk kills one connection rather than the daemon.

If it is ever made a member instead, the design must additionally commit to
checked slicing at the framing parser (`get(..)`, `checked_add`,
`usize::try_from` on the prefix) and `Restart=always` in the unit — because
"prefer libraries" plus `panic = "abort"` plus untrusted framing is exactly the
combination that turns a parse bug into an outage. Do the checked slicing
regardless; it is cheap.

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

Note the two byte counts above come from **separate fetches** (period 1327 alone
is 26 927 = 8 + 26 919; the hexdump is period 1326 at 8 + 26 926). They differ
because `extra_data` is variable-length, so **the length prefix is the only
authority for chunk boundaries** — do not derive one number from the other when
checking a parser.

### Context bytes: prefer re-emission, compute only as a fallback

`Eth-Consensus-Version` gives a fork *name*, and since EIP-7892 the fork digest
is **not a function of the name**: it folds in the active blob parameters.
`status.rs`'s `fork_digest_bpo(fork_version, gvr, blob_params_epoch,
blob_params_max_blobs)` computes
`(fork_data_root XOR sha256(epoch_le || max_blobs_le))[0..4]`, and its own test
pins mainnet Fulu at `0x82FAE541` *base* versus `0x8C9F62FE` *with BPO2* — the
same fork name, two digests. A name→digest table built today would silently emit
a stale digest after the next blob-parameter-only fork, indefinitely, while
Nimbus keeps returning 200s.

So: **re-emit the digest the source already framed** wherever one exists — which
`updates_by_range` does, per chunk, making it the robust path. Compute only where
the source supplies none (the single-object endpoints), and compute it for the
*object's slot* via `fork_digest_bpo` against the network's blob schedule, not
from the fork name.

The blast radius of getting this wrong is asymmetric and worth knowing: myotis'
own decoder skips the context bytes (`codec.rs`: "the payload's own fork sniffing
governs decode"), so our wallets tolerate a stale digest. Every other CL — which
§Capacity expects to dial us once the ENR is published — dispatches
deserialization on it and does not.

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

Comfortably past 1000 connections, and the binding constraint is **not** this
machine. Per-connection state is a Noise session and a yamux stream — tens of KB
— and there is no per-peer computation: every client receives the same cached
bytes, pre-encoded per item 1, so serving is a memcpy and a write. What makes a
beacon node expensive per peer (gossipsub mesh, peer scoring, attnet/syncnet
tracking, full chain state) is absent by construction.

This claim depends on items 1, 2 and 4 holding: pre-encoded responses, ingestion
strictly off the request path, and a synchronous handler that only reads cache.
An on-demand fetch inside `respond_inbound` would invalidate it outright.

Measured headroom on zbox (2026-08-08): 31 GB RAM with 14 GB available, 8 cores,
Nimbus at 0.4 GB RSS. At ~100–200 KB per idle connection including kernel socket
buffers, 1000 connections is ~100–200 MB — not the limit.

The real limits, in order:

1. **Residential upload bandwidth.** A cold client pulls a bootstrap (~26 KB)
   plus its missing periods (~27 KB each); three periods behind is ~107 KB.
   A thousand cold clients arriving together is ~100 MB of uplink. Steady state
   is trivial by comparison — an optimistic update is 1 KB, so 1000 clients
   polling once per 12-second slot is well under 1 Mbit/s. **The cost is the
   cold-start burst, not the resting load.**
2. **File descriptors.** The unit must set `LimitNOFILE` explicitly; the shell
   default here is 2048, while Nimbus's unit sets 524288.
3. **CPU** — Noise handshakes only, and pre-encoded responses keep the serving
   path free of snappy work. Not expected to bind.

**Capping Nimbus helps, for the right reason.** `--max-peers=100` is ample for
chain-following (gossipsub needs a mesh degree of 8; Nimbus's own default is
160). It frees little RAM — a beacon node's memory is dominated by state and DB
caches, not peers — but it meaningfully cuts *gossip uplink*, since Nimbus
forwards attestations and blocks to its mesh. That is exactly the resource the
LC server is short of. Note `--max-peers` sets both `wantedPeers` and the single
shared in+out semaphore, so 100 means 100 total — fine for a node that no longer
serves wallets.

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
   **Validate on both engines and say which is which** — `myotis.engine`
   defaults to *java*, so "a wallet" is ambiguous exactly where it matters.

3. **Settle the Java `beacon_blocks_by_range` gap explicitly.** Without this step
   the choice gets made by omission: step 2 can pass on the Rust engine while
   steps 4–5 remove the pinned full-CL path from under the default one.

   The earlier framing ("Java-engine hosts still need a full CL") overstates it.
   `BeaconSyncState.FILL_THRESHOLD = 4` is deliberately sized for a fill path
   that often never lands — "in practice many peers reject
   `beacon_blocks_by_range/2` with protocol negotiation failures and the window
   only grows via `updateSyncState` (2 roots per finality poll)". So a
   Java-engine wallet on this server alone still reaches SYNCED; what it loses is
   the *dense* recent state-root window (40–80 roots per invocation versus 2 per
   poll). Real degradation for reads at slots between finality and head, but
   characterizable rather than fatal.

   Pick one, with a measurement behind it:
   - **Measure and accept** the sparse-window degradation — this deletes the
     "proxy blocks" option entirely; or
   - **Fix `fillChainStateRoots`** to take the execution state root from the LC
     header's `execution` field, as the Rust engine already does
     (`myotis-consensus/src/store.rs:157`). Removes the asymmetry permanently and
     is where this document's own analysis points.

   Note what proxying blocks would cost, if it is ever revisited: §Capacity rests
   on "every client receives the same cached bytes". A block range is per-wallet
   (each asks a different `finalizedSlot..attestedSlot`) and a post-Deneb 2-epoch
   window is ~64 blocks at orders of magnitude more than an LC update. That is a
   different service with different sizing, not an extra endpoint.

4. Only then: flip Nimbus to `--discv5=true`, drop the direct-peer anchors, the
   candidate pool, the top-up timer and its unit, and restore stock peer limits.
5. Replace the pinned CL multiaddr in `NetworkConfig` with discovery.

## Rejected alternative: patching Nimbus

A patch was written (not built, not installed) adding an `Eth2Agent.Myotis`
classification, switching `withMaxConnections` to `withMaxInOut` so the inbound
semaphore no longer collides with the trim threshold, and exempting myotis peers
from `trimConnections` up to a bound. It works in principle, but it means
carrying a fork of a beacon node — including its vendored `nim-libp2p` in the
more invasive variants — across every upgrade, and it makes admission depend on
a self-reported, trivially spoofable agent string. The split above removes the
problem instead of managing it.
