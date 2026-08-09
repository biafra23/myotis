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

## What works

| | |
|---|---|
| `rest.rs` | Nimbus REST client, SSZ over loopback. Bodies streamed under a cap; failures classified transient vs definitive. |
| `framing.rs` | Splits the `updates` body's length-prefixed chunks and re-frames them as a libp2p multi-chunk response. |
| `store.rs` | Serving cache holding **pre-encoded** responses, so serving is a memcpy and a write. Bounded on update count, response bytes, in-flight bytes and cached bootstraps. |
| `archive.rs` | Durable append-only archive (magic, version, per-record checksum), bound to a chain by `genesis_validators_root`. Repairs a torn tail; scans past a corrupt record instead of losing what follows. |
| `forks.rs` | Fork and blob schedule read from the upstream, and the fork digest for any slot. |
| `enr.rs` | Persisted, monotonic ENR sequence number. |
| `serve.rs` | The daemon: persisted identity, chain-view poller behind `status`, per-slot refresh, new-period archiving, background bootstrap filler, external-address tracking. |

A myotis wallet bootstraps and stays synced from roost alone — verified on
sepolia with discovery disabled, so it cannot have been another peer.

**Context bytes are computed, not guessed.** Since EIP-7892 one fork name has as
many digests as it has BPO entries, so a name→digest table would go stale at the
next blob-parameter-only fork. `updates` re-emits the digest its source framed;
a bootstrap is stamped for the slot of the block it anchors to; the per-slot
objects use head. `roost probe` checks the computed value against the one the
upstream actually put on the wire.

**The external address is tracked but not published.** roost takes a quorum of
libp2p Identify reports — deduped by connection source, so extra peer ids buy
nothing — and warns loudly when it changes. That is the input an ENR needs on a
connection whose public IP is not guaranteed stable.

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
cargo run -p myotis-net --example live_sync -- --once
```

## Deploy

Staging lives in `~/myotis-node/` alongside the geth and Nimbus units;
runtime data lives in `/data/roost/`, matching `/data/geth` and `/data/nimbus`.

**Prerequisite.** Nimbus must expose REST on loopback and serve light-client
data — the sepolia unit already does:

```
--rest --light-client-data-serve=true --light-client-data-import-mode=full
```

**Build, then install:**

```bash
cd ~/myotis && cargo build --release --manifest-path rust/roost/Cargo.toml
sudo bash ~/myotis-node/install-roost.sh      # idempotent; never touches an existing key
sudo systemctl start roost-sepolia
```

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

Back up `sepolia.db` too, once it holds periods below Nimbus's floor — nothing
you run can regenerate those. While it only holds the live window it is
refetchable in seconds.

`sepolia.enrseq` must only ever increase. The DHT keeps the highest-sequence
record it has seen, so a reset makes every later update silently ignored.

**Ports.** `9105/tcp` inbound, forwarded on the router. Add `9105/udp` only when
discv5 publication lands — nothing listens on it today.

**Verify:**

```bash
systemctl status roost-sepolia
journalctl -u roost-sepolia -f          # look for the startup banner and "digest … (computed)"
sudo -u roost /usr/local/bin/roost probe --rest http://127.0.0.1:5052
```

`probe` is the honest end-to-end check: it exercises every upstream endpoint,
round-trips a re-encoded update through myotis' own wire decoder, and compares
the computed fork digest against the one on the wire.

Then point a wallet at it, as above but with the public address.

**Note what deploying does not yet do.** roost publishes no ENR, and
`NetworkConfig`'s pinned sepolia multiaddr still points at Nimbus — so a
deployed roost serves only wallets explicitly told about it. Running it now is
worth doing to keep the archive warm and prove stability, not because it is in
the wallet path yet.

## Why it is not a workspace member

Same reasoning as `tor-poc`, plus one more. As a member it would put an HTTP
stack into every Android, iOS and JVM developer's `cargo build --workspace`, and
— the one that matters — it would inherit the workspace's `panic = "abort"`,
which a member cannot override. In a daemon holding a thousand wallet
connections that turns one panic into an outage for all of them. Excluded, roost
carries its own profile with `panic = "unwind"`, so a malformed chunk kills one
connection rather than the process.

That only holds because the daemon watches for it: the libp2p swarm task owns
the listener, so if it dies the process would otherwise keep running with no
listener at all. `serve` exits non-zero when that happens, and the unit restarts
it.

It still depends on `myotis-net` by path. The wire codec our wallets are proven
against is the one roost serves with — one protocol stack, not two.
