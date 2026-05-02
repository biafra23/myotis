# Plan: Gossipsub subscription for light-client topics

Goal: become a spec-compliant mesh peer on the two light-client gossipsub topics, so
CL peers (Lighthouse / Teku / Prysm / Nimbus / Lodestar) recognize us as useful and
stop pruning us from their peer set. Secondary goal: replace our 12 s finality-update
poll with real-time push.

## Scope

In scope:
- `/eth2/<fork_digest>/light_client_finality_update/ssz_snappy`
- `/eth2/<fork_digest>/light_client_optimistic_update/ssz_snappy`

Out of scope (would require validating full blocks / aggregating 500 k-validator BLS
signatures):
- `beacon_block`
- `beacon_aggregate_and_proof`
- attestation subnets (`beacon_attestation_<subnet_id>`)
- sync committee subnets (`sync_committee_<subnet_id>`)
- `voluntary_exit`, `proposer_slashing`, `attester_slashing`, `bls_to_execution_change`
- `blob_sidecar_<subnet_id>`

## What has to happen in code

### 1. Wire jvm-libp2p's `Gossip` into the host

`io.libp2p.pubsub.gossip.Gossip` is already on our classpath (comes with
jvm-libp2p 1.2.2). Add it alongside our existing Identify / req-resp bindings
in `BeaconP2PService.start()`:

```java
Gossip gossip = new Gossip();
hostBuilder.protocol(gossip);
// keep a reference; we subscribe after start()
```

Estimate: ~20 LOC.

### 2. Subscribe once fork_digest is known

`BeaconGossip.subscribeLightClientTopics(byte[] forkDigest)` subscribes to both
topics and wires their `MessageApi` handler into our existing
`BeaconP2PService.cacheFinalityUpdate(byte[])` / `cacheOptimisticUpdate(byte[])`
so the relay cache is populated by push instead of by poll.

```java
Topic finality = new Topic(
    "/eth2/" + hex(forkDigest) + "/light_client_finality_update/ssz_snappy");
gossip.subscribe(msgApi -> handleFinalityUpdate(msgApi), finality);
```

Estimate: ~50 LOC.

### 3. Message validation (the hard part)

Gossipsub is mesh-based: if we forward invalid messages we get scored down and
kicked out. For every incoming message the subscriber must synchronously return
`ValidationResult.{Valid, Ignore, Reject}`.

`Valid`   = message is good, propagate it to our mesh peers.
`Ignore`  = message is fine but we don't want to judge (no penalty for sender).
`Reject`  = message is malformed / invalid, score the sender down.

For `light_client_finality_update` the required checks are:
- snappy-decode, SSZ-decode → trivial, we already do this for req/resp.
- `fork_digest` in context matches our current fork → trivial, we already
  compute `currentForkDigest()` in `BeaconLightClient`.
- `signature_slot` is in `[current_slot - SLOTS_PER_EPOCH, current_slot + 3]` —
  wall-clock math, same as our existing `clGenesisTime` logic.
- **BLS-verify the sync-committee signature over the attested header.** This is
  the expensive bit. We already do this in
  `LightClientProcessor.processFinalityUpdate`, but it mutates the store. We
  need to split out a pure `validateFinalityUpdate(update)` that doesn't touch
  the store and can be called from the gossipsub thread.

Same pattern for `light_client_optimistic_update` (a subset: no
finalized-checkpoint / Merkle-branch check, just the sync-committee signature
on the attested header).

Edge case: **before bootstrap completes we have no sync committee**, so we
can't validate. Cleanest handling: delay `subscribeLightClientTopics()` until
`store.isInitialized() == true`. Ignores the message cascade entirely rather
than forwarding garbage.

Estimate: ~100 LOC plus a minor refactor of `LightClientProcessor` to expose
`validateFinalityUpdate` / `validateOptimisticUpdate` as pure predicates.

### 4. Lifecycle

- Subscribe after bootstrap completes. Before bootstrap we can't validate.
- On fork activation, unsubscribe from the old `fork_digest` topic and
  subscribe to the new one. Not urgent — fork cadence is months — but record
  a TODO.
- On `close()`, unsubscribe and shut down the gossipsub router cleanly.

Estimate: ~30 LOC.

### 5. Remove the polling loop (only after push is proven reliable)

`BeaconLightClient.pollFinalityUpdate()` becomes redundant once gossipsub is
delivering. Gate this on empirical data: leave both running for ~24 h, confirm
push delivery rate > 99 % per slot, then delete the poll.

## Total scope

| Component | LOC estimate |
|---|---|
| `BeaconGossip` new class (subscribe, handler plumbing) | 150 |
| `BeaconP2PService` / `BeaconLightClient` wiring | 30 |
| `LightClientProcessor.validateFinalityUpdate` refactor | 100 |
| Shutdown / fork-rotation lifecycle | 30 |
| Removal of polling loop (gated) | -40 (net) |
| **Total** | ~270 LOC (net ~230) |

## Risks

- **Peer-scoring miscalibration.** Return `Valid` too eagerly → forward bad
  messages → crash our mesh score → peers prune us. Mitigation: start with
  `Ignore` for everything, graduate to `Valid`/`Reject` only when the
  validator has been observed matching `LightClientProcessor.processUpdate`'s
  accept/reject on a non-trivial sample.
- **BLS-verify latency.** Sync-committee BLS aggregate is ~3-5 ms on modern
  hardware but jvm-libp2p runs validation on the gossipsub thread. If we
  block too long, the router backs up. Mitigation: offload validation to a
  small bounded executor (size 2) and return `Ignore` if the queue is full.
- **Topic-digest rotation at fork.** Handled in lifecycle (4); needs testing
  near an actual fork.
- **Test story is painful.** Gossipsub is emergent across N peers; unit tests
  can only check validation logic in isolation. The real test is running the
  daemon for a day and comparing push delivery count to wall-clock slot count.

## Rollout plan

Three PRs, each independently revertable:

**PR 1 — Observe only.**
Subscribe to both topics, log every incoming message (sender peer-id, slot,
size), return `Ignore` for all. Goal: prove the wiring works and we actually
get messages. No behavior change.

**PR 2 — Full validation + relay.**
Wire `validateFinalityUpdate` / `validateOptimisticUpdate` into the subscriber,
return `Valid` / `Reject`. Populate relay cache from push.

**PR 3 — Drop the poll.**
Delete `pollFinalityUpdate`. Gated on 24-hour observation of PR 2 delivering
on every slot.

## Non-goals for this work

- Subscribing to `beacon_block` or any attestation/sync topic.
- Participating in GRAFT/PRUNE mesh management beyond what jvm-libp2p's
  default router does. (Default is spec-compliant.)
- ENR attnets/syncnets bitfields — light clients leave these empty.
- Peer-exchange (PX). Default router advertises/accepts PX; we don't need
  custom handling.
