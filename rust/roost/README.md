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
- `roost probe` — runs the whole upstream path against a live node and
  round-trips the result through myotis' own wire decoder.

Not built yet: the LC store, the ingestion tasks, the four serving handlers, the
chain-view poller behind `status`, ENR publication, and the daemon itself.

## Run

```bash
cargo run --manifest-path rust/roost/Cargo.toml -- probe
cargo run --manifest-path rust/roost/Cargo.toml -- probe --rest http://127.0.0.1:5052
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
