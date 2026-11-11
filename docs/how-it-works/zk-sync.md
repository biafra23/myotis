# ZK sync and fresh checkpoints

Two ways for the Rust engine to reach the chain's current sync committee
without walking every light-client update from its anchor. **ZK sync** is
automatic and replaces the walk. At the weak-subjectivity (`STALE_ANCHOR`)
prompt it is also one of three explicit user choices, next to the **fresh
checkpoint** (which replaces the anchor itself) and continuing anyway; any of
them can be remembered. Both come from [Colibri](https://github.com/corpus-core/colibri-stateless)
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
releases a park. That gate is a staleness check, not a bound on the proof: on
the ZK path the store does not descend from the anchor the gate judged, and
the embedded checkpoint root is **not applied at all** (see *Trust* below).

**When it does not run:**
- A **caller-supplied root** (`createWithCheckpoint`, `myotis-rpcd
  --checkpoint-root`) and the **fresh checkpoint** below each turn ZK sync off
  for that run. Whoever chose the root chose the trust root, so the store must
  descend from it, and a proof must not overtake a slow bootstrap from it.
- **Tor routing on.** The fetch resolves `<net>.colibri-proof.tech` through the
  system resolver and names it in clear SNI. That is the same disclosure #539
  keeps the EIP-1459 DNS walk from making under Tor, so the walk runs instead.
- `MYOTIS_ZK_SYNC=0`. This only affects a process whose environment someone
  controls (the daemon, a developer). No host offers a switch yet, and it does
  not undo a store already persisted from a proof: the next start resumes that
  snapshot, which carries no provenance mark.
- The cold-start release checks (`live_cold_start`) always turn it off,
  because they exist to prove the walk still works.

Networks: mainnet, sepolia and gnosis (Colibri has no proof chain for chiado).
Otherwise the fetch carries no address, but tells the prover which network this
IP runs and when ([privacy-and-tor.md](privacy-and-tor.md) §2). The Java engine
has no ZK path. It does, however, resume the same snapshot file, so after one ZK
start an engine switch resumes a store that descends from Colibri's anchor.

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
walk instead, but they cannot make a wrong one verify. (Neither can they crash
the engine: the HTTP and JSON parsers refuse hostile sizes and encodings, #761.)

Put plainly: on this path the roots of trust are `zk::anchors::*`, the SP1
Groth16 key with `VK_ROOT` and the selector, and `PROGRAM_VKEY_HASH`. The
embedded checkpoint is only the staleness clock the gate reads. This PR does not
record a reproducible build of Colibri's guest from source that yields
`PROGRAM_VKEY_HASH`; it is taken from Colibri v0.1.2's committed ELF and
constants. The wallet's verified reads still travel over devp2p, but every one
of them is checked against the store these sources initialize.

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
2026-11-10; CLAUDE.md *Trust*). `MYOTIS_ZK_SYNC=0` keeps a *fresh* start on the
walk; it does not demote a store a proof already initialized (above).

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

## At a stale-anchor park: three choices

When a network's own anchor is past the weak-subjectivity bound, it parks in
`STALE_ANCHOR`, and the app asks the user to pick one of three ways forward:

| choice | what happens | engine call / daemon command |
|---|---|---|
| **Fetch ZK proof** | Colibri's proof of the *current* period's committee is fetched and verified in the call. The parked loop then initializes a fresh store from it and the first finality update that committee signed, retrying every 15 s while peers are short, and leaves the park. The old anchor is neither walked from nor replaced; trust moves to Colibri's proof chain (*Trust* above). | `fetchZkProofForStaleAnchor()` / `myotis_fetch_zk_proof_for_stale_anchor` / `zk-anchor` |
| **Fetch fresh checkpoint** | A finalized root every answering checkpoint-sync server names (below). | `refreshAnchorFromCheckpointz()` / `refresh-anchor` |
| **Continue anyway** | Sync forward from the stale anchor, the long-range risk accepted (the existing consent). | `acceptStaleAnchor()` / `accept-stale-anchor` |

- **No ZK proof available.** The proof is verified before the call returns, so
  "not applied" means no usable proof right now: the period's proof is not
  published yet, a prover is unreachable, the network has none (chiado), or ZK
  is off for this run (`MYOTIS_ZK_SYNC=0`, a caller-supplied root). The dialog
  then asks again with the two remaining choices.
- **Remember my choice.** Every choice can be made permanent from the dialog
  ("Remember my choice and apply it automatically next time"). The choice is
  stored by the host (`Settings.staleAnchorChoice`) and can be changed under
  Settings → *When the sync anchor is too old* (Ask me / ZK proof / Fresh
  checkpoint / Continue anyway). At the next park:
  - a remembered **continue** consents without showing the dialog;
  - a remembered **ZK proof** or **checkpoint** is fetched at once. If it fails
    (no proof, or the checkpoint servers do not all agree), the dialog stays
    with the remaining choices, and any of those can be remembered in its place.
- **Headless: the engine applies it.** The host hands the remembered choice to
  the engine (`ChainHandle.setStaleAnchorPolicy` / `myotis_set_stale_anchor_policy`,
  ABI 59) before each network starts and whenever it changes, and the sync loop
  applies it at every park by itself — with no window or Activity open, as in
  the Android service or the desktop app minimized. A remembered fetch that
  fails is logged and retried every 10 minutes (the ZK proof's own retries are
  faster once one is queued) until it succeeds, the bound is raised, or the user
  answers otherwise. With the UI open, the dialog's own fetch may run alongside
  the engine's; both apply the same verified result. The daemon takes the same
  policy at start: `-PstaleAnchorPolicy=ask|zk_proof|checkpoint|continue`
  (`-Dmyotis.beacon.staleAnchorPolicy`), an unknown value — or a fetch the
  engine lacks (the Java engine) — refusing the start. Switching a remembered
  "continue" to another choice withdraws the consent it gave for the run.
- **Under Tor**, both fetches still run when the user picks them. They are
  explicit requests, unlike the automatic ZK start, which Tor turns off; both
  go out in the clear ([privacy-and-tor.md](privacy-and-tor.md) §2). A
  REMEMBERED fetch is not applied by the engine while Tor is on: the park waits
  and the dialog asks, so nothing leaves in the clear without a click.
- The **Java engine** has neither fetch: its dialog offers only "continue", and of
  the remembered choices it applies only "continue" (as a pre-consent for the run);
  `setStaleAnchorPolicy` returns false for the other two.

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
- It accepts a root only when the vote is **unanimous**. Every server that
  answers must name the same finalized epoch and root, and those servers must
  span at least two operators. Operators are counted by registrable domain, so
  two hostnames of one operator are one voice.
- **One differing answer refuses the fetch and names the outlier server**, with
  what it said and what the others said. Nothing is applied and nothing
  retries on its own; the user asks again. A differing answer is any of:
  - another root or another epoch, including a server one epoch behind;
  - an `execution_optimistic` answer;
  - an answer that does not parse.
- A different root for the same epoch is reported as an **alarm**: one side is
  serving another chain. A server that does not answer at all (unreachable, an
  HTTP error) names nothing and is only listed.
  (Owner's ruling on #761, 2026-11-11: a differing source is alarm-worthy,
  never something to outvote.)
- In practice: on 2026-11-11 mainnet (8 operators), sepolia (3) and gnosis (2)
  were unanimous. Chiado was refused, because `rpc-gbc.chiadochain.net` reported
  a finalized epoch about 200 epochs older than the other two. That server has
  been dropped from chiado's list, which keeps `checkpoint.chiadochain.net` and
  publicnode, two operators. (`./gradlew refreshCheckpoint` keeps its own list.)
- It refuses a root that is itself past the bound or ahead of the device's
  clock.
- It applies only while the network is **parked**, so it never replaces a
  healthy store.

The parked loop then discards the stale state and bootstraps from the new root,
exactly as from the embedded checkpoint: Merkle-pinned to the root, then
BLS-verified forward. ZK sync stays off for the rest of that run, so a proof
cannot overtake the bootstrap. Its verified state is persisted, so a restart
resumes it.

**Trust.** This one *is* a trust decision. No engine can verify an anchor, so
the root is the agreeing operators' word. That is the same standing as the
embedded checkpoint, which is the release's word, cross-checked the same way
when it was refreshed. The dialog says so and names the operators. It is opt-in
per park, never automatic.
