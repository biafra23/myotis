# Headless Myotis on Linux as the RPC node for Swarm Bee

This page shows how to run Myotis as a **headless daemon on a Linux server** and
use it as the Gnosis Chain RPC endpoint (`blockchain-rpc-endpoint`) of a Swarm
Bee full node. It needs no desktop app, no GUI and no hosted RPC.

It covers the two ways to give the daemon the postage-stamp history Bee needs,
what each one costs you, how to run the daemon under systemd, and how to point
Bee at it, whether Bee runs as a binary, in Docker or on another machine.

Related pages:
[bee-rpc-service.md](bee-rpc-service.md) is the long reference: every RPC
method Bee calls, the measured runs, the backfill internals.
[bee-node-from-source.md](bee-node-from-source.md) is the short version,
centred on the macOS PoC app. This page is the Linux-server path through both.

## What Bee needs before it starts

Bee reads almost everything with `eth_call`, `eth_getBalance` and similar
calls. Myotis serves those verified out of the box, against snap/1 proofs
anchored to sync-committee-signed beacon headers. The exception is
`eth_getLogs`.

Before it serves anything, Bee replays every event of the **PostageStamp**
contract (`0x45a1502382541Cd610CC9068e88727426b696293`, deployed at Gnosis block
**31,305,656**) in 5,000-block pages. Bee v2.8.2 has those events built in up to
block **47,061,407**, so a fresh Bee asks the RPC for logs from **47,061,408**
to the chain head. A Bee that has run before resumes from its own last synced
block, which is higher.

A light client keeps no chain history. So Myotis answers `eth_getLogs` from an
opt-in **log index** for a list of watched contracts
([eth-getlogs-design.md](eth-getlogs-design.md)). A range the index does not
cover is refused with the retryable `-32000` error. It is never answered with an
empty `[]` that only looks correct. Bee retries a refused page every 5 seconds,
but if 10 minutes pass with no successful page it shuts itself down
(`postage syncing stalled`).

So **the index has to cover the PostageStamp contract from Bee's first page to
the head before you start Bee.** There are two ways to get that coverage.

## Choosing a path: bundled seed or on-the-fly walk

| | **A. Bundled seed (unverified)** | **B. On-the-fly walk (verified)** |
|---|---|---|
| Where the logs come from | `data/bee/gnosis/`, committed in this repo: raw `eth_getLogs` output of one geth full node, from block 47,000,000 up, refreshed every release | Fetched by the daemon itself from devp2p peers, each block's receipts checked against its verified header's receipts root |
| Time until Bee can start | Minutes: beacon sync, then the head bridge closes the gap above the seed | Hours. About 2 million blocks lie between the head and 47,061,408 (Nov 2026, growing by 17,280 a day). The measured walk rate is 30–83 blocks/s (about 41 on average), so expect roughly 7–19 h and plan for a day |
| What you trust | The operator of the full node the seed came from, for every log in the seed's range. Above the seed's top, everything is verified | Nothing beyond Myotis's normal trust anchors (the embedded checkpoint and sync-committee signatures) |
| Failure if the source lied | A forged or withheld postage event is served to Bee as if it were verified. The index cannot tell seeded logs from walked ones | Not possible: a peer can withhold receipts (the walk stalls, and that is visible), but it cannot forge them |
| Load on the peer pool | Low: only head-follow runs | High while walking. The walk and head-follow share one snap-peer pool, so Bee must not run during the walk |
| Shelf life | The seed is usable up to 500,000 blocks (~29 days) above its top. After that the gap never closes. Re-synthesize from a newer checkout | None. Once built, the index follows the head for as long as the daemon runs, and it closes downtime gaps of up to ~29 days |
| Disk | ~20 MB | ~20 MB for Bee's range. The full PostageStamp history down to its deployment is larger |
| Status under the repo's rules | **Demo / test only.** RPC-sourced data is not a production data path (CLAUDE.md, *Data sources*) | The production path |

**Rule of thumb:** use **A** to get a Bee node running today, for a test, a demo
or an integration check. Use **B** for any node you intend to keep, or whenever
the postage data matters: who pays for what, and which batches are valid. You
can start on A and move to B later (see *Moving from A to B* below).

What path A's trust means in practice: Bee builds its batch store, which says
which chunks are paid for and how much, from these events. A seed whose source
invented a `BatchCreated` event, or left out a `BatchTopUp`, would make Bee
believe it. The walker cannot fully repair a seed later. If its downward walk is
switched on, it fills holes and overwrites a seeded log that has a verified twin
at the same (block, log index) position, but it **never deletes** a seeded log.
A seeded log with no real counterpart stays. The only fix for a bad seed is to
delete the index file.

## Prerequisites

- **Linux** on x86-64 or arm64. The daemon only dials out: it needs outbound
  TCP and UDP to devp2p and libp2p peers, and no inbound port forwarding
  ([inbound-connections.md](inbound-connections.md)).
- **JDK 21** (`java -version`). The Gradle wrapper is in the repo.
- **Rust**, through rustup. `rust/rust-toolchain.toml` selects stable, and the
  build enforces the minimum version. **This is required here, not optional.**
  Only the Rust engine has the log index. Without cargo the default engine
  selection falls back to the Java engine, which serves no `eth_getLogs` at all.
- **Python 3.9+**, for path A only (`scripts/synth_logindex.py`, standard
  library only).
- **Bee** v2.8.2 or later, set up as a full node with its own wallet and
  password.

```bash
git clone https://github.com/biafra23/myotis.git && cd myotis
./gradlew cargoBuildHost          # builds the Rust engine (rust/target/release)
```

## Common setup (both paths)

### The data directory is `app/`

There is no packaged headless distribution yet, so the daemon runs from the
checkout through `./gradlew :app:run`. The run task's working directory is the
`app/` module, and **that directory is the daemon's data directory**. For
Gnosis it holds:

| File | What it is |
|---|---|
| `app/peers-gnosis.cache`, `app/cl-peers-gnosis.cache` | EL and CL peer caches |
| `app/sync-state-gnosis.snapshot` | Beacon light-client state, so a restart resumes instead of re-bootstrapping |
| `app/logindex-gnosis.db` | The log index |
| `app/logindex-gnosis.db.final` | The block the index's own last checkpoint proved final |

The IPC socket is `/tmp/ethp2p-gnosis.sock`. Every client command needs
`-Pnetwork=gnosis` so it reaches the Gnosis daemon and not mainnet's.

### Install the warm peer caches

Public Gnosis snap peers are few and busy. A cold pool once starved the
daemon's head-follow for 10 minutes, which is exactly Bee's stall limit
([bee-rpc-service.md](bee-rpc-service.md), *Peer starvation*). The repo ships
caches of known public peers. Every peer is re-verified on dial, so a stale
entry costs a failed dial, not trust. Copy them in **only if the daemon has no
caches yet**:

```bash
cp -n data/bee/gnosis/peers-gnosis.cache    app/
cp -n data/bee/gnosis/cl-peers-gnosis.cache app/
```

### Refresh the trust anchor

```bash
./gradlew refreshCheckpoint -Pnetwork=gnosis
```

This writes a fresh Gnosis checkpoint into both engines' sources. It refuses a
root that fewer than two checkpoint operators agree on. It is a local change to
tracked files (`git diff` shows it). Keep it, or `git stash` it before you pull.

Why this is needed: Gnosis's weak-subjectivity bound is short. An anchor more
than ~34–45 hours old makes the light client park in `STALE_ANCHOR` until
someone consents ([README](../README.md), *Weak-subjectivity age bound*).
After the first sync, the daemon resumes from `app/sync-state-gnosis.snapshot`,
so this matters for the first start and after the daemon has been down for
more than about a day and a half. In those cases either refresh again or
consent once with `./gradlew :app:run -Pnetwork=gnosis -Pargs=accept-stale-anchor`.

### Flags used below

| Flag | Why |
|---|---|
| `-Pnetwork=gnosis` | Bee runs on Gnosis Chain (chain id 100). JSON-RPC is served on `127.0.0.1:8546` |
| `-Pengine=rust` | Forces the Rust engine. Under the default `auto`, a missing native library falls back to the Java engine, which has no log index. The fallback is only a log line (`rust available: false`). With `rust` the daemon fails at start instead |
| `-PbackfillPaused=true` | Turns off the log index's downward walk at boot (see the paths for when). It must be `-P`, not `-D`: `:app:run` is a forked JVM, so a bare `-D` stays in Gradle's own JVM |

## Path A: the bundled seed (unverified, minutes)

**1. Synthesize the seed straight into the data directory**, with the daemon
stopped. The engine activates a `logindex-gnosis.db` it finds at start, so no
import step is needed:

```bash
python3 scripts/synth_logindex.py \
  --meta data/bee/gnosis/postagestamp-logs-47000000-*.meta.json \
  --logs data/bee/gnosis/postagestamp-logs-47000000-*.jsonl.gz \
  --watch 0x45a1502382541Cd610CC9068e88727426b696293:31305656 \
  --out app/logindex-gnosis.db \
  --manifest app/bee-seed.properties
cat app/bee-seed.properties      # coveredLow / coveredHigh / usableUntilBlock
```

Keep the `--watch` value exactly as shown. `31305656` is the contract's real
deployment block, and the index answers `[]` below it without consulting
coverage. With the seed's low edge there instead, the unwalked band below the
seed would get a silent empty answer instead of an honest refusal. The script
refuses only a deployment block *above* the fetch's low edge, so this one is
on you. By default it drops the top 128 blocks of the fetch as a reorg margin,
and the daemon re-fetches them, verified.

The manifest's `usableUntilBlock` is the seed's expiry, about 29 days of Gnosis
blocks above its top. Past it the head bridge no longer closes the gap. Then
`git pull` (every release refreshes `data/bee/gnosis/`) and repeat this step
into a fresh file. The seed's low edge never moves, so a newer seed can also be
imported into the running daemon:
`-Pargs="import-logindex $PWD/app/new-seed.db"`.

(Any Gnosis full node you trust can be the seed source instead of the committed
one. The format is described in
[bee-node-from-source.md](bee-node-from-source.md), *Making your own data set*.
It is the same trust model, with your node in place of ours.)

**2. Start the daemon with the backfill paused.**

```bash
./gradlew :app:run -Pnetwork=gnosis -Pengine=rust -PbackfillPaused=true
```

The pause matters. The engine loads a dropped-in index with its walk paused,
but the daemon then pushes its own boot default, and that default is
*walking*. The walk starts at the head, so it first re-descends through the
seeded span and then continues down to block 31,305,656. That is about 18
million blocks, or around five days. During that time it competes with head-follow for the
snap-peer pool. On 2026-09-19 that contention left coverage behind the head
and Bee shut itself down. Bee never asks below 47,061,408, so the walk adds
nothing Bee uses. Its only benefit is partly re-verifying the seeded span, as
described above.

**3. Wait for readiness** (from a second shell):

```bash
./gradlew -q :app:run -Pnetwork=gnosis -Pargs=beacon-status     # "state":"SYNCED"
./gradlew -q :app:run -Pnetwork=gnosis -Pargs=logindex-status
```

In `logindex-status`, check:

- `"enabled":true` and `"backfillPaused":true`;
- the PostageStamp entry's `coveredLow` (47000000) is at or below Bee's first
  page;
- `headGap` (how far the top of coverage trails the head) is at most 4.
  Above that, queries reaching the head are refused. Right after start it is
  the distance from the seed's top to the head, and the head bridge closes it
  within minutes.

Then start Bee (*Pointing Bee at it*, below).

## Path B: walking it on the fly (verified, about a day)

**1. Start the daemon** with the walk on (the default), and wait for
`beacon-status` to say `SYNCED`:

```bash
./gradlew :app:run -Pnetwork=gnosis -Pengine=rust
```

**2. Subscribe the PostageStamp contract at its real deployment block:**

```bash
./gradlew -q :app:run -Pnetwork=gnosis \
  -Pargs="build-logindex 0x45a1502382541Cd610CC9068e88727426b696293 --from 31305656"
```

The index anchors at the head and walks down from there, at maximum speed. It
fetches the receipts of every block whose bloom filter matches, checks them
against the verified header chain and stores the contract's logs.

Do not pass a later `--from` to save time. `--from` claims that the contract
has no logs below that block. Set too high, it turns every query below it into
a confident `[]` instead of a refusal. Undershooting cannot lie; it only walks
further.

Bee reads the other Swarm contracts (staking, redistribution, price oracle)
with `eth_call`. Only PostageStamp needs an index entry.
[bee-rpc-service.md](bee-rpc-service.md) lists all four contracts if you want a
complete index anyway.

**3. Watch the walk come down.**

```bash
./gradlew -q :app:run -Pnetwork=gnosis -Pargs=logindex-status
```

The entry's `coveredLow` is the number that matters: Bee can start once it is
at or below **47,061,408**. For a Bee that has synced before, its own resume
block is enough. `blocksPerSec` is the current walk rate. `blocksRemaining` and
`etaSeconds` count to the deployment block (31,305,656), not to Bee's range, so
they overstate how long Bee has to wait by about 16 million blocks.

**4. Pause the walk, let the head catch up, then start Bee.**

```bash
./gradlew -q :app:run -Pnetwork=gnosis -Pargs="logindex-backfill off"
./gradlew -q :app:run -Pnetwork=gnosis -Pargs=logindex-status   # wait for headGap <= 4
```

While the walk runs, head-follow falls behind: a few blocks a minute against
the chain's 12. Pausing hands the peer pool back to head-follow, and the bridge
closes the gap. Pausing keeps everything: the coverage already walked and the
cursor. Below `coveredLow`, queries keep getting `-32000` with a message that
the walk is paused. The `--from 31305656` assertion stays honest.

Two ways to continue from here:

- **Keep it paused** (recommended while Bee is the only consumer): add
  `-PbackfillPaused=true` to the daemon's command line, so a restart does not
  resume the walk.
- **Finish the history** (4–5 days for the remaining ~16 M blocks) for a
  complete, exportable index (`-Pargs="export-logindex $PWD/bee-logindex.db"`;
  use an absolute path, because a relative one resolves against `app/`). Bee keeps
  working only if head-follow keeps up, which on Gnosis's thin peer set it
  often does not. So run the rest of the walk while Bee is stopped, or on a
  second machine.

### Moving from A to B

Seeded and walked logs cannot be told apart inside one index, and a walk never
deletes a seeded log. So a node that started on the seed only becomes verified
by starting a new index:

```bash
./gradlew -q :app:run -Pnetwork=gnosis -Pargs=stop
rm app/logindex-gnosis.db app/logindex-gnosis.db.final app/bee-seed.properties
# then Path B from step 1 (Bee stays stopped until step 4)
```

## Running it as a systemd service

The daemon runs in the foreground and logs to stdout, which suits systemd. As
an example, a user unit at `~/.config/systemd/user/myotis-gnosis.service`
(adjust the path, and drop `-PbackfillPaused=true` while a path-B walk is
still meant to run):

```ini
[Unit]
Description=Myotis verified light client (Gnosis) for Swarm Bee
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=%h/myotis
ExecStart=%h/myotis/gradlew --no-daemon --console=plain -q :app:run \
    -Pnetwork=gnosis -Pengine=rust -PbackfillPaused=true
Restart=on-failure
RestartSec=30
TimeoutStopSec=60

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now myotis-gnosis
loginctl enable-linger "$USER"          # keep it running after you log out
journalctl --user -u myotis-gnosis -f
```

`systemctl stop` sends SIGTERM to the Gradle wrapper and the forked daemon
JVM, and the daemon's shutdown hook stops the engine cleanly.
`./gradlew :app:run -Pnetwork=gnosis -Pargs=stop` does the same over IPC. A
restart keeps the index coverage that its last checkpoint proved final
(`logindex-gnosis.db.final`), and the bridge re-fetches only the downtime. A
start re-runs `cargoBuildHost`, which does nothing when the Rust sources have
not changed.

For Bee, a unit with `After=myotis-gnosis.service` is not enough, because "the
process started" is not "the index covers the head". The readiness checks below
are one-shot status reads: they do not wait, and they do not fail on a large
`headGap`. So start Bee by hand once they look right. If you automate it, your
script has to parse `logindex-status` and loop until the numbers are good.

## Pointing Bee at it

Myotis serves verified JSON-RPC on **`http://127.0.0.1:8546`** for Gnosis. In
`bee.yaml` (flat keys only, since Bee rejects unknown or nested ones):

```yaml
mainnet: true
full-node: true
swap-enable: true
chequebook-enable: true            # the Bee wallet needs xDAI for the chequebook deployment
blockchain-rpc-endpoint: http://127.0.0.1:8546
storage-incentives-enable: false   # true only once you stake
data-dir: /var/lib/bee
password-file: /etc/bee/password
```

You can also use the flag `--blockchain-rpc-endpoint http://127.0.0.1:8546`
or the environment variable `BEE_BLOCKCHAIN_RPC_ENDPOINT`.

**Start order:** Myotis first. Then wait for all three readiness checks:
`beacon-status` says `SYNCED`, `status` shows snap peers, and `logindex-status`
shows coverage from Bee's first page with `headGap` at most 4. Only then run
`bee start --config bee.yaml`. A quick check from the shell:

```bash
curl -s -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
  http://127.0.0.1:8546                       # → "result":"0x64"
```

A working Bee logs `connected to blockchain backend
version="Myotis/verified-light-client"`, syncs postage from its resume block to
the head (seconds to a few minutes) and then reports `starting in full mode`.

### Bee in Docker

The listener binds **127.0.0.1 only**, and that cannot be configured. So a
container on Docker's default bridge network cannot reach it. Run Bee's
container on the host network. With the `bee.yaml` above kept in `/etc/bee/`,
the same paths work inside the container:

```bash
docker run -d --name bee --network host \
  -e BEE_BLOCKCHAIN_RPC_ENDPOINT=http://127.0.0.1:8546 \
  -v /var/lib/bee:/var/lib/bee -v /etc/bee:/etc/bee:ro \
  ethersphere/bee:2.8.2 start --config /etc/bee/bee.yaml
```

### Bee on a different machine

Bridge the loopback port with an SSH tunnel from the Bee machine, and point Bee
at its own local end:

```bash
ssh -N -L 8546:127.0.0.1:8546 user@myotis-host     # Bee keeps http://127.0.0.1:8546
```

A plain TCP forwarder or a reverse proxy publishing the port under another name
does not work as-is. The listener checks the HTTP `Host` header against its
loopback names (`localhost`, `127.0.0.1`, `[::1]`), as protection against DNS
rebinding, so a request for `myotis-host:8546` gets `403`. A reverse proxy
would have to rewrite `Host` to `127.0.0.1`.

Think before exposing the port at all. The RPC has no authentication, and it
relays `eth_sendRawTransaction` to the network for anyone who can reach it.
The SSH tunnel keeps it private.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `logindex-status` shows `"enabled":false` with no entries after a seed was dropped in, `build-logindex` answers "not the Rust engine", the boot log says `rust available: false`, or the daemon fails at start under `-Pengine=rust` | The Java engine is running because the Rust library was not built or not found. Run `./gradlew cargoBuildHost` and check that `rust/target/release/` holds `libmyotis_engine.so` |
| Bee: `postage syncing stalled` | A page stayed refused for 10 minutes. Check `logindex-status`: is `coveredLow` above Bee's page (path B not deep enough yet), or is `headGap` large (a walk still running, which you pause with `logindex-backfill off`; or starved peers, so check `status` for snap peers)? Restart Bee once coverage is right |
| Bee refuses to start: header too old | Bee wants the latest header under 60 s old. Myotis is not `SYNCED`, or has lost its snap peers |
| `-32000 requested range is not indexed yet (covered: A-B)` | Honest refusal. The range is outside coverage. Wait for the walk or the bridge, or (path A) check the seed's `usableUntilBlock` |
| `headGap` never closes on path A | The seed is past its shelf life (more than 500,000 blocks behind the head). Re-synthesize from a current checkout |
| `beacon-status` says `STALE_ANCHOR` | The anchor is past Gnosis's ~34 h bound. Run `refreshCheckpoint -Pnetwork=gnosis` and restart, or consent once with `-Pargs=accept-stale-anchor` |
| `403` through a proxy or forwarder | The `Host` header is not a loopback name. Use the SSH tunnel |
| Port 8546 already in use | Another Myotis (for example the desktop app running Gnosis) holds it. Stop that one, or Bee may end up talking to an instance without the index |
