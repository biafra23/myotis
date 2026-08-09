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

## Status

**In progress.** What works today:

- `rest.rs` — the Nimbus REST client, SSZ over loopback, all four light-client
  endpoints plus the control endpoints a chain view needs.
- `framing.rs` — walks the `updates` body's length-prefixed chunks and re-frames
  them as a libp2p multi-chunk response, re-emitting each chunk's fork digest
  verbatim.
- `store.rs` — the in-memory serving cache, holding **pre-encoded** libp2p
  responses so serving is a memcpy and a write. Bounded: spec update count,
  total response bytes, and a hard cap on bootstraps.
- `forks.rs` — the chain's fork and blob schedule, read from the upstream's
  `/eth/v1/config/spec`, and the fork digest for any slot. Context bytes are
  **computed**, not guessed from a fork name — since EIP-7892 one fork name has
  as many digests as it has BPO entries.
- `archive.rs` — the durable, append-only archive (magic, version, per-record
  FNV-1a checksum), bound to a chain by its `genesis_validators_root`. Repairs a
  torn tail on open and scans past a corrupt record rather than losing every
  record behind it.
- `serve.rs` — the daemon: persisted secp256k1 identity, the chain-view poller
  behind `status`, per-slot refresh of the live objects, new-period archiving,
  and a coalesced background filler for bootstrap misses.
- The four light-client protocols are served, via the `LcResponder` seam in
  `myotis-net` — which also gained the `ping` and `goodbye` spec fixes a public
  responder needs.
- `roost probe` — runs the whole upstream path against a live node and
  round-trips the result through myotis' own wire decoder.
- `roost ingest` — loads the archive, fills it from Nimbus, and finishes with a
  serving self-check that reads back through the real serving API.
- `roost serve` — the server itself. A myotis wallet bootstraps and stays synced
  from it alone (verified on sepolia with discovery disabled).

roost tracks the address peers say they see it on, by quorum of libp2p Identify
reports, and logs a change loudly. Nothing is published from it yet — it is the
input the ENR will need, on a deployment whose public IP is not guaranteed
stable.

`roost enr --advertise <ip>` builds and prints the record roost would publish —
persisted discv5 identity (separate from the libp2p key), monotonic sequence
number, endpoint, and the full 16-byte `eth2` ENRForkID. It publishes nothing.

Not built yet: **putting that record in the DHT** (re-published at fork *and* BPO boundaries) and the **back-archive** below the
upstream node's light-client floor. Those are what stand between this and the
design's rollout steps 4-5.

Context bytes are now computed per object: `updates` re-emits the digest the
source framed (the robust path), a bootstrap is stamped for the slot of the
block it anchors to, and the per-slot objects for head. `roost probe` checks the
computed value against the one the upstream actually put on the wire.

## Run

```bash
cargo run --manifest-path rust/roost/Cargo.toml -- probe
cargo run --manifest-path rust/roost/Cargo.toml -- ingest --archive /var/lib/roost/sepolia.db
cargo test  --manifest-path rust/roost/Cargo.toml
```

Requires Nimbus started with `--rest` (off by default; binds 127.0.0.1) and
`--light-client-data-serve=true`.

## Why it is not a workspace member

Same reasoning as `tor-poc`, plus one more. As a member it would put an HTTP
stack into every Android, iOS and JVM developer's `cargo build --workspace`, and
— the one that matters — it would inherit the workspace's `panic = "abort"`,
which a member cannot override. In a daemon holding a thousand wallet
connections that turns one panic into an outage for all of them. Excluded, roost
carries its own profile with `panic = "unwind"`, so a malformed chunk kills one
connection.

It still depends on `myotis-net` by path. The wire codec our wallets are proven
against is the one roost serves with — one protocol stack, not two.
