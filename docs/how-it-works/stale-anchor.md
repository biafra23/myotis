# A stale sync anchor: fresh checkpoint or continue

A light client trusts each sync committee because the previous one signed the
handoff, so everything rests on the anchor it starts from: the checkpoint
embedded in the release, or the last state it verified itself. Sync-committee
signatures are not slashable, and validators who have since exited have nothing
at stake: 2/3 of an old committee's keys can sign a fake continuation that
every signature check accepts. That is the weak-subjectivity problem, and no
cryptography solves it, because the forgery is valid cryptography. Only a
fresh anchor from outside the chain does.

So when a network's anchor is older than the weak-subjectivity bound (13
periods on mainnet and Sepolia, 3 on Gnosis), the Rust and Java engines park
it in `STALE_ANCHOR` and the app asks the user what to do.

## The two choices

| choice | what happens | engine call / daemon command |
|---|---|---|
| **Fetch fresh checkpoint** (recommended) | A finalized root every answering checkpoint-sync server names and a long-known peer confirms (below). The stale state is discarded and the node bootstraps from the new root. | `refreshAnchorFromCheckpointz()` / `myotis_refresh_anchor_from_checkpointz` / `refresh-anchor` (`refresh-anchor-unconfirmed` for "use it anyway") |
| **Continue anyway** | Sync forward from the stale anchor, the long-range risk accepted. | `acceptStaleAnchor()` / `accept-stale-anchor` |

The fresh checkpoint is the one that addresses the problem: it is a new anchor
from outside the chain. Continuing walks forward from the old one, which is
exactly what the bound exists to stop.

- **Remember my choice.** Either choice can be made permanent from the dialog
  ("Remember my choice and apply it automatically next time"). The choice is
  stored by the host (`Settings.staleAnchorChoice`) and can be changed under
  Settings → *When the sync anchor is too old* (Ask me / Fresh checkpoint /
  Continue anyway). At the next park:
  - a remembered **continue** consents without showing the dialog;
  - a remembered **checkpoint** is fetched at once. If it is refused (the
    servers do not all agree, or no long-known peer confirms it), the dialog
    stays with both choices, and the other can be remembered in its place. A
    remembered checkpoint never applies an UNCONFIRMED one: "use it anyway" is
    a click every time.
- **Headless: the engine applies it.** The host hands the remembered choice to
  the engine (`ChainHandle.setStaleAnchorPolicy` / `myotis_set_stale_anchor_policy`)
  before each network starts and whenever it changes, and the sync loop applies
  it at every park by itself — with no window or Activity open, as in the
  Android service or the desktop app minimized. A remembered checkpoint that is
  refused is logged and retried every 10 minutes until it succeeds, the bound is
  raised, or the user answers otherwise. With the UI open, the dialog's own
  fetch may run alongside the engine's; both apply the same agreed root. The
  daemon takes the same policy at start: `-PstaleAnchorPolicy=ask|checkpoint|continue`
  (`-Dmyotis.beacon.staleAnchorPolicy`); an unknown value, or a fetch the engine
  lacks (the Java engine), refuses the start. Switching a remembered "continue"
  to another choice withdraws the consent it gave for the run.
- **Under Tor**, the fetch still runs when the user picks it: it is an explicit
  request, and it goes out in the clear ([privacy-and-tor.md](privacy-and-tor.md)
  §2). A REMEMBERED checkpoint is not applied by the engine while Tor is on: the
  park waits and the dialog asks, so nothing leaves in the clear without a click.
- The **Java engine** has no fetch: its dialog offers only "continue", and of
  the remembered choices it applies only "continue" (as a pre-consent for the
  run); `setStaleAnchorPolicy` returns false for "checkpoint".

## Fresh checkpoint

Asked for at a park, the engine requests
`/eth/v1/beacon/states/head/finality_checkpoints` from **every** configured
checkpoint-sync server — checkpointz instances and public beacon APIs, the union
of [Colibri](https://github.com/corpus-core/colibri-stateless)'s list and the one
`./gradlew refreshCheckpoint` uses (`rust/myotis-net/src/checkpointz.rs`):

- It accepts a root only when the vote is **unanimous**. Every server that
  answers must name the same finalized epoch and root, and those servers must
  span at least two operators. Operators are counted by registrable domain, so
  two hostnames of one operator are one voice.
- **One differing answer refuses the fetch and names the outlier server**, with
  what it said and what the others said. Nothing is applied. A differing answer
  is any of:
  - another root or another epoch, including a server one epoch behind;
  - an `execution_optimistic` answer;
  - an answer that does not parse.
- A different root for the same epoch is reported as an **alarm**: one side is
  serving another chain. A server that does not answer at all (unreachable, an
  HTTP error) names nothing and is only listed.
  (Owner's ruling on #761, 2026-11-11: a differing source is alarm-worthy,
  never something to outvote.)
- In practice: on 2026-11-11 mainnet (8 operators), sepolia (3) and gnosis (2)
  were unanimous. Chiado's `rpc-gbc.chiadochain.net` reported a finalized epoch
  about 200 epochs older than the other two and has been dropped from chiado's
  list, which keeps `checkpoint.chiadochain.net` and publicnode, two operators.
  (`./gradlew refreshCheckpoint` keeps its own list.)
- It refuses a root that is itself past the bound or ahead of the device's
  clock.
- It applies only while the network is **parked**, so it never replaces a
  healthy store.

The parked loop then discards the stale state and bootstraps from the new root,
exactly as from the embedded checkpoint: Merkle-pinned to the root, then
BLS-verified forward. Its verified state is persisted, so a restart resumes it.

### Confirmed by long-known peers (the eclipse guard)

The servers are reached over HTTPS, and every libp2p peer this node meets
during a park is whoever answers: an attacker who controls this device's
network connection — an eclipse — can be all of them. What such an attacker
cannot do is answer as a peer whose identity this node already knew. A libp2p
peer ID is the hash of the node's public key, and the Noise handshake proves
possession of that key, so a known ID can only be spoken for by its owner.

So the checkpoint the servers agree on must also be confirmed by at least one
**long-known peer** (`rust/myotis-net/src/known_peers.rs`; owner's ruling on
#761, 2026-11-13):

- **Who is long-known.** The light-client peers this release **pins** by peer
  ID (reviewed, and known before the anchor was embedded; mainnet 5, Sepolia 2,
  Gnosis 8, Chiado none — the compiled-in list, not a `MYOTIS_CL_STATIC_PEERS`
  override), and the peers in this device's **CL peer cache** whose
  ID it first saw **at least a week ago**. The cache records that time as an
  `s<unix seconds>` token, kept by both engines; an entry written before the
  token existed is stamped when first loaded, so it ages from the upgrade on.
- **What is asked.** Each long-known peer's `Status` — asked fresh, right after
  the servers answered — carries its finalized epoch and root. A peer naming
  the **same epoch and root** confirms. A peer naming **another root for the
  same epoch** is an **alarm**: the round is refused, the peer named, and there
  is no override. A peer at another epoch (finality moved during the round, or
  it lags) does not confirm; when that is all there is, the round is asked once
  more after 20 seconds, and if the long-known peers that answered still name
  other epochs, the checkpoint is **refused with no override**: the servers and
  the peers this node trusts most disagree (an attacker answering the HTTPS
  round can name an epoch the honest peers never reach).
- **No long-known peer answered** — none known, none reachable — refuses the
  checkpoint as **UNCONFIRMED** and the app flags it: *an eclipse attack cannot
  be ruled out.* The user may still apply it with **"Use it
  anyway (eclipse not ruled out)"** (`allowUnconfirmed`, the daemon's
  `refresh-anchor-unconfirmed`) — an explicit choice each time, never
  remembered, never applied by the engine on its own. A remembered checkpoint
  asks the peers once per try (no 20-second re-ask, so the park is not held)
  and tries again every 10 minutes. A fresh Chiado install
  has no pins, so it is flagged until its cache has a week-old peer.
- **What it does not cover.** A long-known peer that has itself been
  compromised, or an attacker who has been answering as a light-client server
  in this device's cache for over a week. The pins are the release's word, as
  the embedded checkpoint is.

**Trust.** This *is* a trust decision. No engine can verify an anchor, so the
root is the agreeing operators' word, cross-checked against peers this node
already knew. That is the same standing as the
embedded checkpoint, which is the release's word, cross-checked the same way
when it was refreshed. The dialog says so and names the operators. It is opt-in
per park, or remembered by the user.

## Why not a ZK proof of the committee chain

An earlier revision of #761 also offered Colibri's SP1/Groth16 proofs of the
sync-committee chain, automatically and as a third choice here. It was removed
before merging (owner's decision, 2026-11-13). Such a proof attests that a
valid chain of committee handoffs leads from Colibri's pinned anchor committee
to today's, which is exactly the walk from that anchor, compressed. Colibri's
anchor is older than the weak-subjectivity bound and never moves, and anyone
holding old exited keys can run the same prover over a forged chain, so the
proof inherits the long-range exposure the bound exists to stop, and adds the
soundness of SP1, Groth16's trusted setup and an unreproduced program hash on
top. It is a speed-up, not an answer to a stale anchor.
