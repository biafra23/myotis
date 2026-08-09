# roost — dedicated light-client server

Design: [`docs/lc-server-design.md`](../../docs/lc-server-design.md).

A myotis wallet needs a beacon node that will still have a free slot when it
dials, and that it can find without hard-coding an address. A general-purpose
beacon node is structurally bad at both: Nimbus sizes one connection semaphore
at `maxPeers` shared between inbound and outbound, and its peer trimmer scores
on stability-subnet and gossip-mesh membership — where a light client sits at
zero, first to be trimmed.

roost is the split that removes the problem rather than managing it. Nimbus goes
back to being an ordinary beacon node; roost serves wallets, and sets its own
limits.

It is a **byte cache, not a beacon node**. It fetches light-client objects from
Nimbus over loopback REST and relays them verbatim, without decoding them. It
verifies nothing and does not need to: a wallet checks every update against
sync-committee signatures chained from its own anchor, so a relay can withhold
but cannot forge. That carve-out is recorded in
[`CLAUDE.md`](../../CLAUDE.md) under **Data sources**.

One thing roost relays is **not** self-verifying, and is worth naming so the
boundary is not widened by accident: the `status` handshake, built from REST
`head_header` + `finalized_checkpoint`. A wallet uses a peer's status only for
fork-digest relevance and `earliest_available_slot` peer selection, so a wrong
one costs peer choice and never correctness. Anything beyond that — relaying
something a wallet cannot check against sync-committee signatures — needs its
own decision, per the carve-out.

## What works

| | |
|---|---|
| `rest.rs` | Nimbus REST client, SSZ over loopback. Bodies streamed under a cap; failures classified transient vs definitive. |
| `framing.rs` | Splits the `updates` body's length-prefixed chunks and re-frames them as a libp2p multi-chunk response. |
| `store.rs` | Serving cache holding **pre-encoded** responses, so serving is a memcpy and a write. Bounded on update count, response bytes, cached bootstraps and queued bootstrap misses. (The global in-flight response budget lives in `myotis-net`, not here.) |
| `archive.rs` | Durable append-only archive (magic, version, per-record checksum), bound to a chain by `genesis_validators_root`. Repairs a torn tail; scans past a corrupt record instead of losing what follows. |
| `forks.rs` | Fork and blob schedule read from the upstream, and the fork digest for any slot. |
| `enr.rs` | Persisted, monotonic ENR sequence number. |
| `serve.rs` | The daemon: persisted identity, chain-view poller behind `status`, per-slot refresh, new-period archiving, background bootstrap filler, external-address tracking. |

A **Rust-engine** myotis wallet bootstraps and stays synced from roost alone —
verified on sepolia with discovery disabled, so it cannot have been another
peer. The **Java engine is untested against roost**, and `myotis.engine`
defaults to *java*, so that gap is the default path: `MYOTIS_CL_STATIC_PEERS`
exists only on the Rust side, and pointing a Java-engine wallet at roost means
editing `NetworkConfig` and rebuilding. `docs/lc-server-design.md` rollout step 2
asks for both engines and for saying which is which; this is the which.

**Context bytes are computed, not guessed.** Since EIP-7892 one fork name has as
many digests as it has BPO entries, so a name→digest table would go stale at the
next blob-parameter-only fork. `updates` re-emits the digest its source framed;
a bootstrap is stamped for the slot of the block it anchors to; the per-slot
objects use head. `roost probe` checks the computed value against the one the
upstream actually put on the wire.

**The external address comes from the UPSTREAM, and is not published.** roost
reads Nimbus's own discv5 view (`/eth/v1/node/identity`) every tick and warns
loudly when it changes; that is what drives IP-change detection. The libp2p
Identify quorum is a fallback, used only when the upstream cannot answer,
because dialing peers to harvest observations was measured here and does not
work: beacon nodes close a non-gossiping peer's connection before Identify
completes. Either way this is the input an ENR needs on a connection whose
public IP is not guaranteed stable.

## Not built yet

- **Publishing the ENR.** `roost enr --advertise <ip>` builds and prints the
  record — endpoint, the full 16-byte `eth2` ENRForkID, signed with the libp2p
  host key so the peer id wallets derive is the one roost authenticates as — and
  puts nothing in the DHT. Until that lands, **wallets cannot discover roost**;
  they have to be pointed at it (`MYOTIS_CL_STATIC_PEERS`, or a pinned
  multiaddr in `NetworkConfig`).
- **The back-archive** below the upstream's light-client floor. Nimbus serves
  updates only from the period its states reach; everything older is
  irreplaceable once collected.

## Run locally

```bash
cargo run  --manifest-path rust/roost/Cargo.toml -- probe
cargo run  --manifest-path rust/roost/Cargo.toml -- ingest --archive /tmp/sepolia.db
cargo run  --manifest-path rust/roost/Cargo.toml -- enr --archive /tmp/sepolia.db --advertise <ip>
cargo test --manifest-path rust/roost/Cargo.toml
```

Requires Nimbus started with `--rest` (off by default; binds 127.0.0.1:5052) and
`--light-client-data-serve=true`.

To point a wallet at a local roost, with discovery off so "synced from roost" is
an honest claim:

```bash
NET=sepolia \
MYOTIS_CL_STATIC_PEERS=/ip4/127.0.0.1/tcp/9105/p2p/<peer-id> \
MYOTIS_CL_DISABLE_DISCV5=1 \
cargo run --manifest-path rust/Cargo.toml -p myotis-net --example live_sync -- --once
```

## Deploy

Staging lives in `~/myotis-node/` alongside the geth and Nimbus units;
runtime data lives in `/data/roost/`, matching `/data/geth` and `/data/nimbus`.

**Prerequisite.** Nimbus must expose REST on loopback and serve light-client
data:

```
--rest --light-client-data-serve=true --light-client-data-import-mode=full
```

`--rest` is **off by default** and was added to the running sepolia node on
2026-08-08 (`docs/lc-server-design.md` §Rollout). Check your unit actually has
it before installing roost: without it roost fails on its first upstream call,
and under `Restart=on-failure` that is a restart loop rather than a clear error.

The unit and installer live in [`deploy/`](deploy/) — in the repo, so
`LimitNOFILE`, `Restart=on-failure` and "never overwrites the key" are
reviewable rather than assertions about a file on one machine.

```bash
cargo build --release --manifest-path rust/roost/Cargo.toml
# One instance per chain, from the systemd TEMPLATE (deploy/roost@.service):
sudo bash deploy/install-roost-instance.sh sepolia   # tcp 9105, upstream 5052
sudo bash deploy/install-roost-instance.sh mainnet   # tcp 9109, upstream 5054
sudo bash deploy/install-roost-instance.sh gnosis    # tcp 9108, upstream 5053
sudo systemctl start roost@sepolia roost@mainnet roost@gnosis
```

The older `rust/roost/deploy/install-roost.sh` + `roost-sepolia.service` pair
installs a **second, differently-named** sepolia unit and is superseded by the
template. Do not run both: two units on port 9105 means one restart-loops.

What that lays down:

| Path | |
|---|---|
| `/usr/local/bin/roost` | the binary |
| `/etc/systemd/system/roost-sepolia.service` | unit; `LimitNOFILE=65536`, `Restart=on-failure` |
| `/data/roost/sepolia.key` | **libp2p + discv5 identity.** Created `0600` on first start. |
| `/data/roost/sepolia.db` | light-client archive |
| `/data/roost/sepolia.enrseq` | ENR sequence number |

**Back up `sepolia.key`.** It is the one artifact here that cannot be
regenerated. Wallets derive the peer id they dial from it, so replacing it
re-mints the node identity: every wallet that had learned this server dials an
identity that no longer exists, fails, and spends its three strikes to eviction
on a node that is actually healthy. The installer never overwrites it.

**Back up `sepolia.enrseq` with it** — restoring one without the other is worse
than restoring neither, once publication is enabled. `EnrSeq::load` starts at 1
when the file is missing, so an identity restored without its sequence number
re-issues numbers the network has already seen, and the DHT ignores every record
until the count climbs back past the previously published high-water mark. The
node would look healthy and be undiscoverable. If the file is ever lost, set it
by hand to something comfortably above the last published value rather than
letting it restart.

Back up `sepolia.db` too, once it holds periods below Nimbus's floor — nothing
you run can regenerate those. While it only holds the live window it is
refetchable in seconds.

**Ports.** `9105/tcp` inbound, forwarded on the router. Add `9105/udp` only when
discv5 publication lands — nothing listens on it today.

**Verify:**

```bash
systemctl status roost-sepolia
journalctl -u roost-sepolia -f          # look for the startup banner and "digest … (computed)"
sudo -u roost /usr/local/bin/roost probe --rest http://127.0.0.1:5052
```

**Run `roost enr` as the service user too** — it *writes*. It consumes a
sequence number on every invocation and creates the identity key if one is
absent, so running it as root leaves both root-owned and the service unable to
read them:

```bash
sudo -u roost /usr/local/bin/roost enr \
    --archive /data/roost/sepolia.db --advertise <public-ip>
```

`probe` checks the **upstream** path only: it exercises the light-client REST
endpoints, round-trips a re-encoded update through myotis' own wire decoder, and
compares the computed fork digest against the one on the wire. It talks to
Nimbus directly and never connects to roost's libp2p listener, so a green
`probe` says nothing about whether the deployed service is reachable. It also
does not call three REST paths `serve` depends on — `head_header`,
`finalized_checkpoint` and `header_slot`, the two behind `status` and the one
that stamps a bootstrap's digest — so a green `probe` is consistent with `serve`
failing on them. Extending `probe` to cover them is a worthwhile follow-up.

**The end-to-end check is the wallet**, pointed at the deployed address as above
but with the public IP. That is the only step that exercises the listener, the
serving handlers and the archive together.

**Note what deploying does not yet do.** roost publishes no ENR, so wallets
cannot DISCOVER it (#335). It is nonetheless in the default wallet path: both
engines pin roost first on mainnet, gnosis and sepolia, by DynDNS name
(`/dns4/…`), resolved at dial time. So a deployed roost serves every wallet
that ships with those pins — it just cannot be found by one that does not.

## Why it is not a workspace member

Same reasoning as `tor-poc`, plus one more. As a member it would put an HTTP
stack into every Android, iOS and JVM developer's `cargo build --workspace`, and
— the one that matters — it would inherit the workspace's `panic = "abort"`,
which a member cannot override. In a daemon holding a thousand wallet
connections that turns one panic into an outage for all of them. Excluded, roost
carries its own profile with `panic = "unwind"`, so a panic is a recoverable,
observable failure rather than an instant process abort.

Be precise about what that does NOT buy: request handling runs inline on the
single swarm task, so a panic there takes the task down and with it every
connection. `serve` detects the dead task and exits non-zero for the
supervisor. The gain is a controlled, logged exit that systemd restarts —
not per-connection isolation.

That only holds because the daemon watches for it: the libp2p swarm task owns
the listener, so if it dies the process would otherwise keep running with no
listener at all. `serve` exits non-zero when that happens, and the unit restarts
it.

It still depends on `myotis-net` by path. The wire codec our wallets are proven
against is the one roost serves with — one protocol stack, not two.
