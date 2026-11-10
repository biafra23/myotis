# ZK sync and fresh checkpoints

Two ways for the Rust engine to reach the chain's current sync committee
without walking every light-client update from its anchor. **ZK sync** is
automatic and replaces the walk. The **fresh checkpoint** is an explicit user
choice at the weak-subjectivity (`STALE_ANCHOR`) prompt and replaces the anchor
itself. Both come from [Colibri](https://github.com/corpus-core/colibri-stateless)
(corpus.core's stateless client). Myotis uses Colibri's proofs with the Colibri
team's permission.

## Why

A light client walks the chain one sync-committee handoff at a time: a
bootstrap at its anchor, then one `LightClientUpdate` per period
(~27 h on mainnet and sepolia, ~11.4 h on gnosis). A fresh install whose
checkpoint is two weeks old needs ~13 updates on mainnet and a peer that still
serves a bootstrap for that root. A gnosis install needs a dozen updates within
days. Few peers answer these historical requests (#422 and #441 were exactly
that), and the walk is the slowest part of a cold start. The *latest* finality
update, by contrast, is answered by every light-client server.

## ZK sync

Colibri runs an [SP1](https://docs.succinct.xyz/) zkVM guest program
(`src/chains/eth/zk_proof/program`) that verifies one sync-committee handoff:
the old committee's ≥ 2/3 BLS signature over an attested header, and the Merkle
path from that header's state root to the next committee's pubkeys. It also
verifies the proof of the previous handoff (recursion). So the proof for
period *N* attests the whole chain of handoffs from a fixed per-network
**anchor committee** to committee *N*. The STARK is wrapped in a 356-byte
Groth16 proof over BN254, which Myotis checks with a few pairings
(`rust/myotis-consensus/src/zk.rs`, about 10 ms).

### What the engine does

When the sync loop would otherwise bootstrap at an anchor, or walk updates
from its held committee, and the wall-clock period is at least
`min_gap_periods` (2) ahead:

1. Fetch `https://<net>.colibri-proof.tech/period_store/<wall period>/zk_proof.ssz`.
   If that fails it tries `https://<net>1.colibri-proof.tech/…` (`rust/myotis-net/src/zksync.rs`).
2. Verify it. Every public value is recomputed locally, never taken from the
   file:
   - the pinned SP1 program and verifying key;
   - the pinned anchor committee root;
   - the requested period (checked against the attested header's slot);
   - the root of the 512 pubkeys the file carries;
   - the attested header root;
   - the signing domain, computed from this chain's own fork schedule and
     genesis validators root.

   A proof made for another network, another period, another committee or
   another program fails.
3. Ask light-client peers for their latest finality update, and initialize a
   **fresh** store from the first update this committee signed with ≥ 2/3
   participation whose finalized header is in that period. The update must also
   carry a valid finality branch and execution branches
   (`LightClientProcessor::initialize_from_proven_committee`). The store is
   then exactly what a bootstrap at that finalized header would have produced.
   The committee's aggregate key is recomputed from the pubkeys, so the
   persisted snapshot and later updates see the spec's `SyncCommittee`.
4. Swap the fresh store in, persist it, and carry on as usual: finality
   polling, and the next period's handoff through a normal `updates_by_range`.

Any failure at any step leaves the held store untouched and the loop walks
updates exactly as it did before. The cases are: unreachable servers, the
period's proof not published yet (proving lags the period start), a proof that
does not verify, or no peer with a usable finality update (for example in the
first epochs of a period, before finality crosses the boundary). Retries back
off for 60 s when the cause is transient by nature, 15 minutes otherwise. A
single-period gap always walks: one update costs the same as the proof plus a
finality update, and stays on the wallet's own anchor.

ZK sync runs only **after** the weak-subjectivity gate. An install whose own
anchor is past the bound still parks in `STALE_ANCHOR`, and a proof never
releases a park.

Networks: mainnet, sepolia and gnosis (Colibri has no proof chain for chiado).
The fetch goes out in the clear, even with Tor routing on. It carries no
address, but tells the prover which network this IP runs and when
([privacy-and-tor.md](privacy-and-tor.md) §2).
`MYOTIS_ZK_SYNC=0` turns it off. The cold-start release checks
(`live_cold_start`) always turn it off, because they exist to prove the walk
still works. The Java engine has no ZK path and always walks.

### Trust: what changes

A ZK start trusts, in addition to the sync-committee signatures it trusts
anyway:

- **The anchor committee** (`zk::anchors`, copied from Colibri's
  `chain_spec.c`). The proof chain starts there, not at Myotis's own checkpoint.
- **SP1's soundness and its Groth16 setup**, under the verifying key and
  recursion-VK root pinned in `zk.rs`.
- **Colibri's guest program** (`PROGRAM_VKEY_HASH`), doing what its source says:
  it checks ≥ 2/3 participation and binds the leaf to `next_sync_committee`.

It does **not** trust the servers. They can withhold a proof, which means a
walk instead, but they cannot make a wrong one verify.

**The weak-subjectivity caveat.** The walk Myotis does itself passes only
through committees inside the weak-subjectivity window of its own anchor. The
proof chain passes through every committee since Colibri's anchor, which is
older than the bound: mainnet period 1844 and gnosis period 3642, against a
bound of 13 and 3 periods. A long-range attacker who obtained ≥ 2/3 of the keys
of any one of those older committees, from validators who have since exited,
could sign a forked handoff that the guest program would prove like any other.
Myotis's own walk does not have this exposure. Colibri bounds it with a
checkpointz cross-check when its client crosses the bound. Myotis bounds it
only by the weak-subjectivity gate on its *own* anchor, and that gate does not
cover the committees between Colibri's anchor and Myotis's. Myotis accepts this
exposure for the faster, peer-light cold start (the owner's request,
2026-11-10; CLAUDE.md *Trust*). `MYOTIS_ZK_SYNC=0` restores the walk-only
model.

### Anchor provenance

The anchors and the verifying key were cross-checked on 2026-11-10:

| | value | checked against |
|---|---|---|
| mainnet anchor | `c610d3cf…a2213c`, committee of period 1844 | `next_sync_committee` of period 1843's update, `ethereum-beacon-api.publicnode.com` |
| sepolia anchor | `ee5c880d…ba9725`, committee of period 1347 | same, `lodestar-sepolia.chainsafe.io` |
| gnosis anchor | `1997249f…07b8e0`, committee of period 3642 | same, `gnosis-beacon-api.publicnode.com` |
| Groth16 key, `VK_ROOT`, selector | `zk.rs` `vk`, `SP1_VK_ROOT`, `SP1_VERIFIER_SELECTOR` | succinctlabs/sp1-contracts `contracts/src/v6.1.0` |

The committees proven by the committed fixtures (`rust/testdata/zk`) were
compared with the same APIs' `next_sync_committee` for the period before, and
matched. `rust/myotis-net/tests/zk_fixtures.rs` verifies them offline, refuses
every tampered variant, and initializes a store from each together with a
finality update that committee signed.

**When Colibri rotates its guest program**, the program hash, and with it the
anchors (a rotation restarts the recursion), must move in a reviewed release.
Until then the new proofs are refused (`UnknownProgram`) and every install
walks. Nothing breaks; it is just slower.

## Fresh checkpoint (the STALE_ANCHOR option)

When it has no state, Colibri asks one checkpointz server for
`/eth/v1/beacon/states/head/finality_checkpoints` and trusts the finalized root
it names. Myotis offers the same as a third answer to the `STALE_ANCHOR` dialog,
next to "Sync anyway" and raising the bound. The dialog button is "Fetch fresh
checkpoint". The daemon command is `./gradlew :app:run -Pargs=refresh-anchor`.
The engine call is `ChainHandle.refreshAnchorFromCheckpointz()` /
`myotis_refresh_anchor_from_checkpointz`.

It is stricter than Colibri's version (`rust/myotis-net/src/checkpointz.rs`):

- It asks **every** configured server: checkpointz instances and public beacon
  APIs, the union of Colibri's list and the one `./gradlew refreshCheckpoint`
  uses.
- It accepts a root only when servers of **at least two operators** name the
  same finalized epoch and root. Operators are counted by registrable domain,
  so two hostnames of one operator are one voice.
- It refuses the round outright if any two servers name **different** roots
  for the same epoch.
- It refuses a root that is itself past the bound or ahead of the device's
  clock.
- It applies only while the network is **parked**, so it never replaces a
  healthy store.

The parked loop then discards the stale state and bootstraps from the new root,
exactly as from the embedded checkpoint: Merkle-pinned to the root, then
BLS-verified forward. Its verified state is persisted, so a restart resumes it.

**Trust.** This one *is* a trust decision. No engine can verify an anchor, so
the root is the agreeing operators' word. That is the same standing as the
embedded checkpoint, which is the release's word, cross-checked the same way
when it was refreshed. The dialog says so and names the operators. It is opt-in
per park, never automatic.
