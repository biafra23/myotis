# myotis-net, part 3: execution-layer peers

*Stop 11 · crate `myotis-net`, `src/el/`* · 14 files · 9,668 lines · about 180 minutes

From an empty routing table to a verified snap peer that serves many requests at once: discv4 discovery with its ENR fork-id filter, EIP-1459 DNS node lists, the tokio side of RLPx and the eth handshake, the managed-peer actor, the peer cache, and the Tor reserve and transport. The pure wire codecs now live in `myotis-wire` ([stop 5](05-wire.md)); this stop is the I/O that drives them. It is where generics over `AsyncRead`, hand-written cancellation safety, and “split one value into two independently owned halves” come together.

## Rust you will practise

- **Splitting ownership** `split(self)` moves a connection's parts out: a reader owned by one task, a writer shared behind an async mutex.
- **Cancellation by drop** — the `torn` flag, `PendingGuard`, `WalkClaim` and `StorageHold`: guards whose `Drop` repairs state when a future is dropped mid-await.
- **Borrows that end early** — non-lexical lifetimes, disjoint fields and “copy out, then mutate” let a single-task actor change its own maps without locks.

## The path of one peer

Candidates reach the peer pool ([stop 12](12-el-pool.md)) from four sources. `discv4` walks the UDP DHT and, since #539, asks each node for its ENR first, so `enrfilter` can drop nodes of other chains before any TCP dial. `dnsdisco` walks a network's signed DNS node list on hosts that allow DNS. `peercache` replays peers that served snap before a restart. `torreserve` holds a share of those proven peers aside for Tor only.

The pool dials a candidate with `RlpxConnection::dial`: TCP, then the EIP-8 auth/ack handshake and a stateful frame codec (the codecs are `myotis-wire`'s, [stop 5](05-wire.md)). `EthSession::handshake` exchanges Hello and Status and checks network id and genesis. The pool turns a snap-capable session into a `ManagedPeer`, and the reader, the EVM and the log index then send concurrent requests through it. Nothing a peer says is trusted until `myotis-wire`'s `snap/fetch.rs` verifies it against a trusted root. The Tor path (`tor.rs`) runs the same RLPx and eth code over an Arti stream to a node from the reserve.

> [!TIP]
> **What changed since September**<br>
>
> The RLPx crypto (`ecies`, `handshake`, `frame`), the eth and snap message codecs, snap verification and the discv4 packet codec moved to `myotis-wire` (myotis#505). Their old files under `el/` are now 4-line re-export shims, covered in [stop 5](05-wire.md). New here: the ENR fork-id filter and DNS discovery (#539), the Tor reserve, eth/70–71 and snap/2 (receipt continuations, block access lists), per-peer head tracking, close reasons, and the hedged-read send marker.

<a id="f-myotis-net-src-el-mod-rs"></a>

### myotis-net/src/el/mod.rs

*module index · 40 lines · Java twin · networking package*

Declares the execution-layer submodules, twins of the Java `com.jaeckel.ethp2p.networking` package. Two children are private (`mod feecache;` and `mod tasks;`), and `torreserve` is `pub(crate)`: visible inside the crate, invisible to the engine and the hosts. `#[cfg(feature = "tor")] pub mod tor;` exists only in Tor builds: a compile-time switch, not a runtime `if`. The excerpt shows the second half of the list.

`rust/myotis-net/src/el/mod.rs` · lines 27–40

```rust
mod tasks;
pub mod receipt;
pub mod rlpx;
/// Tor transport for the verified-read path (docs/privacy-and-tor.md). Only
/// compiled with `--features tor`; a no-op absence otherwise.
#[cfg(feature = "tor")]
pub mod tor;
pub(crate) mod torreserve;
pub mod send_check;
pub mod sent_tx;
pub mod served;
pub mod snap;
pub mod tx;
pub mod verify;
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* Rust visibility is per module, not per package as in Java. `pub(crate)` is roughly Java's package-private stretched to the whole crate. Code outside the crate that names `el::torreserve` does not compile, while `el::pool` can use it freely.

<a id="f-myotis-net-src-el-tasks-rs"></a>

### myotis-net/src/el/tasks.rs

*library · 40 lines*

Owns the peer pool's background tasks. It offers a graceful shutdown (abort, then await), a hard one (abort only), and silently refuses new spawns after shutdown. `spawn` also drops handles of finished tasks (`retain(|task| !task.is_finished())`), so the list does not grow for the life of the pool. The primer shows the whole file; the notes below add the part that concerns the pool.

`rust/myotis-net/src/el/tasks.rs` · lines 18–40

```rust
    fn take(&self) -> Vec<JoinHandle<()>> {
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        tasks.0 = true;
        for task in &tasks.1 {
            task.abort();
        }
        std::mem::take(&mut tasks.1)
    }

    pub async fn stop(&self) {
        for task in self.take() {
            let _ = task.await;
        }
    }
    pub fn abort(&self) {
        drop(self.take());
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.abort();
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* The “stopped” flag and the handles share *one* lock. A concurrent `spawn` therefore either lands before `take` (and is aborted) or sees the flag (and drops its future unrun). It's Java's `shutdownNow()` + `awaitTermination()`.
- *[async/await & tokio](01-primer.md#primer-async) · [Interior mutability](01-primer.md#primer-interior-mutability)* The `std` guard lives only inside the synchronous `take()`, so `stop()` never holds it across `.await`. A held `std` guard would make the future non-`Send`.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* **A reference cycle.** The pool's loops own `Arc<PoolInner>`, and `PoolInner` owns this `Tasks`. While the loops run, the count never reaches zero, so `Tasks::drop` can't fire on its own. `PeerPool::drop` calls `abort()` explicitly to break the cycle.

<a id="f-myotis-net-src-el-discv4-rs"></a>

### myotis-net/src/el/discv4.rs

*library · 2,536 lines · Java twin · DiscV4Service / KademliaTable*

Execution-layer peer discovery over UDP: discv4, a Kademlia DHT. Like the Java reference it is client-only: it pings, sends FindNode, reads Neighbors and answers Ping with Pong, but never answers FindNode. Since #539 it departs from the Java twin twice: it pings back a node that pings it while no pong from that node is on file, and it answers ENRRequest (EIP-868) from bonded nodes. Both exist so that the fork-id filter ([enrfilter.rs](#f-myotis-net-src-el-enrfilter-rs)) can read a node's ENR before the pool dials it. The packet codec moved to `myotis-wire` and is re-exported here (`pub use myotis_wire::discv4::*;`, line 32). The table and the rate limiter are pure (time is a parameter); only `Discv4Service` owns a socket.

| Lines | What happens |
|---|---|
| 1–32 | Docs, imports, the re-exported packet codec. |
| 34–146 | `KademliaTable`: 256 buckets × 16, XOR distance over `keccak256(pubkey)`; `remove` and `get` are new (the filter forgets foreign nodes). |
| 148–195 | `PingRateLimiter`: 5 packets per IP per 10 s, at most 4,096 IPs remembered (fail open beyond that). |
| 197–375 | `Discv4Config`, the filter's `EnrCounts`, the `Discv4Service` handle: `start`, accessors, `stop`, `Drop`. |
| 377–425 | Socket binding: dual-stack v6 with v4 fallback, and a best-effort 1 MiB receive buffer. |
| 427–513 | `ServiceLoop` state, pending pings, and the “wide fan-out” budget (30 instead of 10 peers per refresh, 8 refreshes per below-target episode, at most once per 30 minutes). |
| 515–749 | The ENR exchange: constants, `Bond`, `PendingEnr`, `Judgement` (verdict plus a TCP port per address family), `Seen`, `EnrExchange`. |
| 751–806 | `ServiceLoop::run`: the `select!` loop. |
| 808–1067 | Handlers for Ping, Pong and Neighbors; `admit` and `consider` decide whether a node waits for its ENR. |
| 1069–1262 | ENRRequest out, ENRRequest in (bond check, rate limit), ENRResponse in (verdict), and the 1 s sweep that hands over nodes whose ENR never came. |
| 1264–1444 | `forget`, pending-ping helpers, `emit`, `probe`, `refresh`, the send helpers. |
| 1446–1513 | Clock, address and sampling helpers (partial Fisher–Yates). |
| 1515–2536 | Tests, including two real services over loopback UDP. |

#### The table

`rust/myotis-net/src/el/discv4.rs` · lines 68–77

```rust
/// Add or refresh a peer (dedup by nodeId; oldest dropped when full).
pub fn add(&mut self, entry: TableEntry) {
    let idx = self.bucket_index(&entry.node_id);
    let bucket = &mut self.buckets[idx];
    bucket.retain(|e| e.node_id != entry.node_id);
    if bucket.len() >= BUCKET_SIZE {
        bucket.remove(0);
    }
    bucket.push(entry);
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing)* `let bucket = &mut self.buckets[idx];` borrows one element of the vector mutably; until its last use, nothing else may touch `self.buckets`. The closure in `retain` reads `entry.node_id`, a different value, so the two borrows don't conflict. `bucket.push(entry)` then *moves* the entry into the bucket: the caller passed it by value and no longer has it. A full bucket drops its oldest entry, the same simplification the Java table makes (no ping-before-evict).

#### Start, stop and drop

`rust/myotis-net/src/el/discv4.rs` · lines 265–305

```rust
impl Discv4Service {
    /// Bind the socket and spawn the service loop. Discovered peers (from
    /// Pong bonds and Neighbors) are emitted on `events`.
    pub async fn start(
        key: Arc<NodeKey>,
        cfg: Discv4Config,
        events: tokio::sync::mpsc::Sender<TableEntry>,
    ) -> Result<Discv4Service, String> {
        let (socket, dual_stack) =
            bind_udp(cfg.bind_port).map_err(|e| format!("discv4 bind: {e}"))?;
        let local_port = socket
            .local_addr()
            .map_err(|e| format!("discv4 local_addr: {e}"))?
            .port();
        let table = Arc::new(Mutex::new(KademliaTable::new(key.node_id())));
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (probe_tx, probe_rx) = tokio::sync::mpsc::channel(64);
        let enr_counts = Arc::new(EnrCounts::default());
        let enr = match cfg.fork_filter {
            Some(filter) => Some(EnrExchange::new(&key, filter, Arc::clone(&enr_counts))?),
            None => None,
        };
        let loop_state = ServiceLoop {
            key,
            socket,
            dual_stack,
            local_port,
            bootnodes: cfg.bootnodes,
            table: Arc::clone(&table),
            events,
            pending_pings: HashMap::new(),
            limiter: PingRateLimiter::default(),
            enr_limiter: PingRateLimiter::default(),
            probe_rx,
            probed: HashMap::new(),
            enr,
            pool_below_target: cfg.pool_below_target,
            wide: WideState::default(),
            traffic: cfg.traffic.unwrap_or_default(),
        };
        let task = tokio::spawn(loop_state.run(stop_rx));
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async)* **Actor-style ownership.** Everything the loop needs is packed into `ServiceLoop` and moved into the task (`tokio::spawn(loop_state.run(stop_rx))`). The socket, the pending maps and the ENR exchange need no locks, because only that task can reach them. Two things are shared: the routing table, as `Arc<std::sync::Mutex<KademliaTable>>` (the pool reads it), and the tallies, as `Arc<EnrCounts>` of atomics.
- *[Ownership & moves](01-primer.md#primer-ownership)* `cfg` is taken by value, and its fields are moved out one by one: `cfg.fork_filter` in the `match`, `cfg.bootnodes` and `cfg.pool_below_target` into the struct literal. Moving fields out of a struct is allowed when the struct has no `Drop` impl; afterwards `cfg` as a whole can no longer be used.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The `?` inside the `Some(filter) =>` arm returns from `start` itself when our own ENR can't be signed; a `match` arm is not a function boundary.

`rust/myotis-net/src/el/discv4.rs` · lines 360–375

```rust
    pub async fn stop(&self) {
        let _ = self.stop_tx.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Discv4Service {
    fn drop(&mut self) {
        // Signal the loop to exit even if the owner forgot to `stop().await`
        // (EL-A4's restart flows drop-and-recreate). The task detaches; the
        // socket closes when it winds down.
        let _ = self.stop_tx.send(true);
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [async/await & tokio](01-primer.md#primer-async) · [Lifetimes](01-primer.md#primer-lifetimes)* In `stop()`, the guard created in the `if let` condition lives through the body (this crate is edition 2021), which means across `task.await`. That's only allowed with an async mutex, and the lock also guarantees the task is joined exactly once, even if two callers stop concurrently through `&self`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* A `watch` channel works as an awaitable stop flag. `Drop` sends `true` but can't wait, so the task detaches and winds down on its own; the socket closes when the task ends.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The doc on `Discv4Service` (lines 251–252) says “Dropping it does NOT stop the task; call `Discv4Service::stop`.” The `Drop` impl at lines 368–375 sends the stop signal, and even without it, dropping `stop_tx` would make `stop_rx.changed()` return an error, which the `_ =` branch in `run` also accepts. Dropping does stop the loop; it just doesn't wait for it.

#### The loop

`rust/myotis-net/src/el/discv4.rs` · lines 752–806

```rust
async fn run(mut self, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
    tracing::info!(port = self.local_port, "discv4 listening");
    // Bootstrap: ping all bootnodes; then refresh every 15 s (first at 10 s).
    let now = tokio::time::Instant::now();
    for bootnode in self.bootnodes.clone() {
        if !self.fresh_ping_pending(bootnode, now) {
            self.send_ping(bootnode).await;
        }
    }
    let mut refresh = tokio::time::interval_at(
        tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(15),
    );
    // After a stall/sleep, catch up with ONE tick, not a burst of them —
    // otherwise we'd flood peers with a storm of FindNodes on wakeup.
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The ENR exchange's timeout sweep (a no-op without a filter).
    let mut sweep = tokio::time::interval(std::time::Duration::from_secs(1));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                tracing::info!("discv4 stopped");
                return;
            }
            _ = refresh.tick() => self.refresh().await,
            _ = sweep.tick() => self.sweep_enr().await,
            // `Some(addr) =` disables this branch once all senders drop
            // (recv() → None fails the pattern) — no busy-loop at shutdown.
            Some(addr) = self.probe_rx.recv() => self.probe(addr).await,
            recv = self.socket.recv_from(&mut buf) => {
                let (n, sender) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        // ICMP port-unreachable surfaces here on some
                        // stacks (Windows WSAECONNRESET). Log and continue;
                        // the next recv proceeds normally.
                        tracing::debug!("discv4 recv error: {e}");
                        continue;
                    }
                };
                // Un-map v4-mapped v6 senders back to canonical v4 so the
                // pending-ping key and the recorded IP bytes match what we
                // sent to and what peers advertise.
                let sender = canonical_addr(sender);
                self.traffic.el.add_rx(n);
                match parse(&buf[..n]) {
                    Ok(parsed) => self.handle(parsed, sender).await,
                    Err(e) => tracing::debug!(bytes = n, %sender, "discv4 unparseable: {}", e.0),
                }
            }
        }
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Borrowing & slices](01-primer.md#primer-borrowing)* One `select!` over five cancel-safe sources: stop, the 15 s refresh tick, the 1 s ENR sweep, probe requests, and `recv_from`. When one branch wins, the losing futures and their borrows (of `self.socket`, `buf`, `self.probe_rx`) are dropped *before* its handler runs. That is why a handler may call `&mut self` methods.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [async/await & tokio](01-primer.md#primer-async)* `Some(addr) = self.probe_rx.recv()`: when all senders are gone, `recv()` yields `None`, the pattern fails, and `select!` disables that branch. There is no busy loop at shutdown.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `for bootnode in self.bootnodes.clone()` iterates a *clone*, so the loop doesn't hold `&self.bootnodes` while calling the `&mut self` method `send_ping`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Ownership & moves](01-primer.md#primer-ownership)* `buf` is allocated once and reused. `parse(&buf[..n])` borrows only the received bytes and returns an owned `Parsed` (its `data` is a `Vec<u8>`), so the next `recv_from` can overwrite the buffer.
- *[async/await & tokio](01-primer.md#primer-async)* `MissedTickBehavior::Skip`: after a laptop sleep, the interval fires once instead of replaying every missed tick as a burst of FindNodes.

#### The ENR exchange

Every sighted node (its Ping, its Pong, or an entry in someone's Neighbors) goes through `consider`. With no filter configured it is handed over at once. Otherwise the exchange looks up an earlier verdict by node id. With none on file, the node becomes a `PendingEnr`: if it holds our pong, an ENRRequest goes out now; if not, we ping first and ask once it answers. The ENRResponse is decoded and its identity checked against the packet's signer (`decode_enr`). `ForkFilter::verdict` then sorts the node: *Foreign* nodes are counted and removed from the table, *Compatible* and *Unknown* ones are emitted. Every second, `sweep_enr` hands over nodes that did not answer within 3 s: the filter fails open, and the eth Status check at the handshake stays the authority. While the pool is at its target it dials nothing, so second-hand Neighbors entries skip the exchange and are handed over unjudged.

A second thread runs through the code: the TCP port. A Neighbors entry is hearsay from a relayer. A Ping's FROM endpoint is the node's own signed claim, and its ENR is its own signed record. The exchange keeps the node's own word per address family (`Judgement::tcp_port: [Option<u32>; 2]`) and lets hearsay replace only a port that was itself hearsay or a guess. Port 0 means “takes no TCP connections on this family”, and the pool never dials it.

`rust/myotis-net/src/el/discv4.rs` · lines 965–1008

```rust
async fn consider(&mut self, entry: TableEntry, bonded: bool, claim: Option<u32>) {
    let Some(enr) = self.enr.as_mut() else {
        return self.emit(entry).await;
    };
    let now = tokio::time::Instant::now();
    let seen = match enr.verdicts.get(&entry.node_id) {
        Some(j) if j.verdict == Verdict::Foreign => Seen::Foreign,
        Some(j) if j.expired(now) => Seen::Stale,
        Some(j) => Seen::Judged(j.tcp_port[family(&entry.ip)]),
        None => Seen::New,
    };
    match seen {
        Seen::Foreign => {
            enr.skip_foreign();
            // It may have entered the table unjudged earlier (see the gate
            // below); the pool's below-target walk reads the table.
            return self.forget(&entry.node_id);
        }
        Seen::Judged(record_port) => {
            // The node's own word on its port for this family outlives the
            // sighting (see `Judgement::tcp_port`): a relayer's hearsay
            // yields to it, a Ping's own claim — fresher, and signed by
            // the node — updates it, so a node that moved its port is
            // followed and a relayer cannot move it.
            let mut entry = entry;
            match claim {
                Some(port) => {
                    if let Some(j) = enr.verdicts.get_mut(&entry.node_id) {
                        j.tcp_port[family(&entry.ip)] = Some(port);
                    }
                }
                None => {
                    if let Some(port) = record_port {
                        entry.tcp_port = port;
                    }
                }
            }
            return self.emit(entry).await;
        }
        Seen::Stale => {
            enr.verdicts.remove(&entry.node_id); // judged again below
        }
        Seen::New => {}
    }
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Copy out, then mutate.** `enr` is a `&mut` into `self.enr`. The first `match` turns the borrowed lookup `enr.verdicts.get(...)` into `Seen`, an enum that holds no references (`Judged` carries a copied `Option<u32>`). The borrow of the map ends there, and the second `match` is free to call `enr.verdicts.get_mut` or `remove`.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Non-lexical lifetimes.** `self.forget(...)` and `self.emit(...)` need all of `self`, while `enr` still borrows part of it. This compiles because a borrow lasts until its *last use*, not to the end of its scope: in each arm, `enr` is used for the last time before `self` is touched. In the `let … else` at the top, the `else` branch has no `enr` at all, so it may call `self.emit` directly.
- *[Ownership & moves](01-primer.md#primer-ownership)* `let mut entry = entry;` moves the parameter into a new, mutable binding. Parameters are immutable unless declared `mut`, and rebinding is the idiom for “mutable from here on”.

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* Two more variants of the same discipline sit nearby. `handle_enr_response` (lines 1117–1211) first borrows the pending entry (`let Some(pending) = enr.pending.get(&sender)`) only to check the request hash, and later *shadows* it with the owned value `let Some(mut pending) = enr.pending.remove(&sender)`. `sweep_enr` (lines 1215–1262) collects the expired keys into a `Vec` before removing them, because a map can't be mutated while it is being iterated, and collects the nodes to emit into another `Vec`, because `self.emit` needs `&mut self` while `enr` is still in use.

`rust/myotis-net/src/el/discv4.rs` · lines 1288–1302

```rust
async fn emit(&mut self, entry: TableEntry) {
    if let Ok(mut table) = self.table.lock() {
        table.add(entry.clone());
    }
    // NON-blocking: discovery events are advisory (the table is already
    // updated). Blocking here on a full channel would freeze the whole
    // select loop — recv AND refresh AND stop would all stall.
    match self.events.try_send(entry) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            tracing::trace!("discv4 events channel full, dropping peer event");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* The `std` guard (`table`) is released at the end of the `if let` body, before anything else happens. The event is then *offered* with `try_send`. Blocking on a full channel would freeze every branch of the single-task loop, including stop. Dropping an event is harmless, because the table already holds the entry.

*[Protocol & domain](01-primer.md#primer-domain)* An ENRRequest is answered only from a node whose pong we verified, keyed by address *and* checked against the signing key (`is_bonded`), and only within the Ping rate limit. Otherwise a spoofed source address could make us send a signed record to a victim, an amplification attack; geth applies the same `checkBond` rule. Expired requests are ignored so a captured one can't be replayed.

<a id="f-myotis-net-src-el-enrfilter-rs"></a>

### myotis-net/src/el/enrfilter.rs

*library · 528 lines*

The EIP-2124 fork-id pre-filter (#539). discv4 is one DHT for every Ethereum network, so a Neighbors reply mixes mainnet, testnets, Gnosis and others; before this file the pool learned a node's chain only after a full TCP, ECIES, Hello and Status exchange. A node's ENR carries its fork id in the `eth` entry, `[[fork-hash, fork-next]]`. `ForkFilter` accepts the pinned hash and its successor, and treats a hash that could be our chain one fork *ahead* of this build (a plausible activation time, on the beacon epoch grid) as Unknown rather than Foreign, so a stale build can still reach upgraded peers and learn of the fork. The file also decodes remote ENRs and signs our own minimal one. `dnsdisco.rs` uses the same filter for its leaves.

`rust/myotis-net/src/el/enrfilter.rs` · lines 102–139

```rust
/// Judge a node at `now` (unix seconds) by the raw RLP of its ENR `eth`
/// entry (`None` = no entry).
pub fn verdict(&self, eth_entry_rlp: Option<&[u8]>, now: u64) -> Verdict {
    match eth_entry_rlp.and_then(parse_eth_entry) {
        None => Verdict::Unknown,
        Some((hash, _next)) if self.accepted.contains(&hash) => Verdict::Compatible,
        Some((hash, _next)) if self.plausible_successor(hash, now) => Verdict::Unknown,
        Some(_) => Verdict::Foreign,
    }
}

/// Whether `hash` could be our chain a fork AHEAD of what we announce: the
/// one activation that turns one of our accepted hashes into it is a
/// plausible fork time — at or past EIP-2124's timestamp threshold, within
/// the fork watch's lookback and horizon, and on the beacon epoch grid when
/// one is configured. Placed from the pin AND its successor, as the fork
/// watch judges from both baselines: past the pinned time we announce the
/// successor, but a network that rescheduled that fork keeps its nodes on
/// the pin, and their next fork follows the pin.
pub fn plausible_successor(&self, hash: [u8; 4], now: u64) -> bool {
    let hash = u32::from_be_bytes(hash);
    self.accepted
        .iter()
        .map(|ours| forkid::activation_of(u32::from_be_bytes(*ours), hash))
        .any(|t| self.plausible_time(t, now))
}

fn plausible_time(&self, t: u64, now: u64) -> bool {
    if t < forkid::TIMESTAMP_THRESHOLD
        || t < now.saturating_sub(LOOKBACK_SECONDS)
        || t > now.saturating_add(MAX_HORIZON_SECONDS)
    {
        return false;
    }
    self.epoch_seconds == 0
        || (t >= self.genesis_time
            && (t - self.genesis_time).is_multiple_of(self.epoch_seconds))
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* Match arms are tried in order, and guards make that order part of the logic: a hash in `accepted` is Compatible before the plausibility guard is even evaluated. The last arm, `Some(_)`, catches every parsed hash that passed neither guard.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `.map(...).any(...)` is lazy: `any` stops at the first `true`, so at most one activation time is computed per accepted hash. Like Java streams, nothing runs until the terminal operation pulls.
- *[Protocol & domain](01-primer.md#primer-domain)* `forkid::activation_of` finds the one timestamp `T` that turns our hash into the observed one. Another chain's hash lands on an epoch boundary inside the window only by chance, which the module doc puts at about one in 25,000 per baseline.

`rust/myotis-net/src/el/enrfilter.rs` · lines 214–233

```rust
/// Decode a remote ENR from its RLP, check its signature (the `enr` crate
/// does, on decode), and require its identity key to be `signer` — the key
/// that signed the discv4 packet carrying it — so a node cannot answer with
/// someone else's record.
pub fn decode_enr(raw: &[u8], signer: &[u8; 64]) -> Result<RemoteEnr, String> {
    use alloy_rlp::Decodable;
    let enr = Enr::<CombinedKey>::decode(&mut &raw[..]).map_err(|e| format!("enr: {e}"))?;
    let signer = compress_public_key(signer).map_err(|e| format!("signer key: {}", e.0))?;
    if enr.public_key().encode() != signer.to_vec() {
        return Err("enr identity differs from the packet signer".to_string());
    }
    Ok(RemoteEnr {
        seq: enr.seq(),
        eth: enr.get_raw_rlp("eth").map(<[u8]>::to_vec),
        tcp4: enr.tcp4(),
        tcp6: enr.tcp6(),
        has_ip4: enr.ip4().is_some(),
        has_ip6: enr.ip6().is_some(),
    })
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Protocol & domain](01-primer.md#primer-domain)* `Enr::decode(&mut &raw[..])` passes a *mutable reference to a slice*: `alloy_rlp`'s decoder advances the slice past what it consumed, like a read cursor. The slice is a view into `raw`; no bytes are copied until `<[u8]>::to_vec` copies the `eth` entry out. The signer check matters: without it, a node could answer with someone else's validly signed record.

<a id="f-myotis-net-src-el-dnsdisco-rs"></a>

### myotis-net/src/el/dnsdisco.rs

*library · 1,461 lines · Java twin · networking.dns.DnsEnrResolver*

EIP-1459 DNS node lists for the EL pool (#539, part 3). A network publishes its node list as a Merkle tree of DNS TXT records under a domain: a signed root (`enrtree-root:v1 e=… l=… seq=… sig=…`), branch records listing child labels, and leaves that are signed ENRs. Each label is the base32 of the first 16 bytes of the keccak of its record, so a resolver can withhold records but can't add any. The walk is bounded (lookups, depth, deadline) and its order random. `DnsSeeder` walks once when first asked, then again every 4 minutes while the pool stays below target; it keeps up to 600 candidates, hands them to the dialer in batches of 10, and nudges up to 32 UDP endpoints into discv4. DNS discovery runs only where the host switched it on, and never under Tor: the query itself tells the local resolver which network this node is on.

| Lines | What happens |
|---|---|
| 1–50 | Docs (format, trust, where it runs), imports. |
| 52–92 | Policy: the process-wide host switch and the Tor check. |
| 94–149 | RFC 4648 base32 encode/decode, `label_of`. |
| 151–252 | `EnrTreeUrl::parse`, `parse_root` (signature recovered against the URL's key). |
| 254–343 | `Entry` (branch, node, link), `DnsNode`, `parse_leaf`. |
| 345–547 | The walk: `TxtLookup`, `WalkLimits`, `WalkReport`, `walk`, `judge`, `shuffle`. |
| 549–604 | `SystemResolver` over hickory. |
| 606–879 | `DnsSeeder`: schedule, walk, merge, round-robin batches; `WalkClaim`; `merge_candidates`. |
| 881–1461 | Tests against the EIP's example zone and an in-memory resolver. |

`rust/myotis-net/src/el/dnsdisco.rs` · lines 76–92

```rust
/// Whether a walk may run now: a host allowed DNS, and Tor is not on. Read when
/// a walk is claimed and again before each of its lookups: both switches are
/// live, and a walk in flight stops when they turn against it.
pub fn allowed() -> bool {
    is_enabled() && !tor_enabled()
}

fn tor_enabled() -> bool {
    #[cfg(feature = "tor")]
    {
        crate::el::tor::is_enabled()
    }
    #[cfg(not(feature = "tor"))]
    {
        false
    }
}
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* Exactly one of the two `#[cfg]` blocks survives compilation, and the survivor is the function body's value. Without the `tor` feature, `crate::el::tor` doesn't exist, and the first block is never type-checked, so its reference to the missing module is not an error. `allowed()` is read before every lookup, not only when a walk starts, so switching Tor on stops a walk in flight.

#### Parsing without copying

`parse_root` (lines 207–252) shows several `&str` tools at once. `rsplit_once(" sig=")` and `strip_prefix` return sub-slices of the input, never copies. `let (Some(enr_root), Some(link_root), Some(seq)) = (enr_root, link_root, seq) else { … };` destructures three `Option`s in one `let … else`. `sig.try_into()` converts a `Vec<u8>` into a `[u8; 65]` and, on a wrong length, hands the vector back as the error, which `map_err(|v: Vec<u8>| …)` uses to report its length. The comment at lines 215–217 explains why `strip_prefix` replaced slicing by index: a record like `enrtree-root:v1 sig=…` would make `&signed[PREFIX.len()..]` panic, and a DNS zone must not be able to crash the host.

#### An async trait you can put behind `dyn`

`rust/myotis-net/src/el/dnsdisco.rs` · lines 349–359

```rust
/// The TXT lookups a walk makes: one name → the texts of its TXT records
/// (empty when it has none). A name in a tree carries one tree record, but a
/// zone apex may carry others (SPF, a verification token), so the walk picks
/// the record it recognises rather than the first one served — as geth does.
/// Production: [`SystemResolver`]; tests: a map.
pub trait TxtLookup: Send + Sync {
    fn txt<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}
```

`rust/myotis-net/src/el/dnsdisco.rs` · lines 579–604

```rust
impl TxtLookup for SystemResolver {
    fn txt<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            // Fully qualified: no search-list suffixing, one query.
            let fqdn = format!("{name}.");
            match self.inner.txt_lookup(fqdn).await {
                // A record's segments concatenate (TXT strings are at most 255
                // bytes, a long ENR is split over several).
                Ok(lookup) => Ok(lookup
                    .iter()
                    .map(|txt| {
                        txt.txt_data()
                            .iter()
                            .map(|seg| String::from_utf8_lossy(seg))
                            .collect::<String>()
                    })
                    .collect()),
                Err(e) if e.is_no_records_found() || e.is_nx_domain() => Ok(Vec::new()),
                Err(e) => Err(e.to_string()),
            }
        })
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* The walk takes `resolver: &dyn TxtLookup`, so production and tests can pass different resolvers at run time. A trait with an `async fn` can't be used as `dyn`, because each implementation's future is a different, unnamed type. The fix is to return one concrete type for all of them: `Pin<Box<dyn Future<…> + Send + 'a>>`, a heap-allocated future behind a pointer. It's like a Java interface method returning `CompletableFuture<List<String>>`.
- *[Lifetimes](01-primer.md#primer-lifetimes)* `'a` ties the future to both borrows: it may use `self` and `name` until it completes, so neither may be dropped first. `Box::pin(async move { … })` moves those two references (not the resolver) into the future.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* TXT strings are at most 255 bytes, so a long ENR arrives in segments. The inner `collect::<String>()` concatenates one record's segments; `String::from_utf8_lossy` returns a `Cow` that borrows when the bytes are valid UTF-8 and allocates only when it must replace bad bytes.

#### The walk

`rust/myotis-net/src/el/dnsdisco.rs` · lines 451–496

```rust
let mut stack: Vec<(String, usize)> = vec![(root.enr_root, 0)];
let mut visited: HashSet<String> = HashSet::new();
while let Some((label, depth)) = stack.pop() {
    if started.elapsed() >= limits.deadline {
        report.timed_out = true;
        break;
    }
    if abort_if() {
        report.cut_short = true;
        break;
    }
    if report.lookups >= limits.max_lookups {
        break;
    }
    if depth > limits.max_depth {
        continue; // not resolved, so not visited: a shallower path may reach it
    }
    // Loop protection: a label resolved once is never fetched twice.
    if !visited.insert(label.to_ascii_uppercase()) {
        continue;
    }
    report.lookups += 1;
    let name = format!("{label}.{}", url.domain);
    let records = match resolver.txt(&name).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(%name, "dns tree: lookup failed: {e}");
            continue;
        }
    };
    if records.is_empty() {
        tracing::debug!(%name, "dns tree: no record");
        continue;
    }
    // The label is the record's hash: the record that hashes to it is the
    // tree's; a name serving only others was not published under this
    // root (or the zone was altered in flight).
    let Some(txt) = records
        .iter()
        .map(|r| r.trim())
        .find(|r| label_of(r).eq_ignore_ascii_case(&label))
    else {
        report.mismatched += 1;
        tracing::debug!(%name, "dns tree: no record hashes to the label");
        continue;
    };
```

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Protocol & domain](01-primer.md#primer-domain)* An explicit stack replaces recursion, which an `async fn` could not do without boxing. `visited` is the loop protection: a label resolved once is never fetched again, so a label listed by two branches costs one lookup. A label that fails the depth check is *not* marked visited, so a shorter path can still reach it. `find(|r| label_of(r).eq_ignore_ascii_case(&label))` picks the one record that hashes to its own name, which is the tree's integrity check. Just after the excerpt (lines 498–503), branch children are shuffled before being pushed, so a tree larger than one walk's budget is seen in a different part each time.

#### Claiming a walk

`rust/myotis-net/src/el/dnsdisco.rs` · lines 722–745

```rust
pub async fn walk_once(&self, probe: Option<&tokio::sync::mpsc::Sender<SocketAddr>>) -> usize {
    let _claim = WalkClaim(self);
    self.walk_all(probe).await
}

async fn walk_all(&self, probe: Option<&tokio::sync::mpsc::Sender<SocketAddr>>) -> usize {
    let system;
    let resolver: &dyn TxtLookup = match &self.source {
        ResolverSource::Fixed(r) => r.as_ref(),
        ResolverSource::System => match SystemResolver::new() {
            Ok(r) => {
                system = r;
                &system
            }
            Err(e) => {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if !st.resolver_unavailable {
                    st.resolver_unavailable = true;
                    tracing::warn!("dns discovery unavailable on this host: {e}");
                }
                return 0;
            }
        },
    };
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Borrowing from one of two owners.** `resolver` borrows either the caller's `Arc` (the `Fixed` arm) or a freshly built `SystemResolver`. `let system;` is declared *before* the `match`, and assigned inside the arm, so the value lives until the function returns. Declared inside the arm, it would be dropped at the arm's end while `resolver` still pointed at it, and the code would not compile.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `r.as_ref()` turns `&Arc<dyn TxtLookup>` into `&dyn TxtLookup` without touching the reference count.

`rust/myotis-net/src/el/dnsdisco.rs` · lines 844–855

```rust
/// Releases a walk's claim when the walk ends — by returning, by the task
/// being cancelled (the pool stopping) or by an unwind — so `walking` can
/// never stay set without a walk behind it.
struct WalkClaim<'a>(&'a DnsSeeder);

impl Drop for WalkClaim<'_> {
    fn drop(&mut self) {
        let mut st = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        st.walking = false;
        st.last_walk = Some(tokio::time::Instant::now());
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* **Cancellation by drop.** `begin_walk_if_due` sets `walking`; `WalkClaim`'s `Drop` clears it. Because `walk_once` binds the guard (`let _claim = WalkClaim(self);`), the flag is cleared whether the walk returns, its future is dropped by the pool stopping, or it unwinds. Rust has no `finally`; a value's destructor is the equivalent, and it also runs on cancellation, which Java's `finally` has no notion of.
- *[Ownership & moves](01-primer.md#primer-ownership)* The name matters. `let _claim = …` keeps the guard until the end of the scope. `let _ = …` would drop it immediately, releasing the claim before the walk even started.
- *[Lifetimes](01-primer.md#primer-lifetimes)* `WalkClaim<'a>(&'a DnsSeeder)` borrows the seeder, so the compiler proves the guard can't outlive it. `impl Drop for WalkClaim<'_>` uses the anonymous lifetime: “for any lifetime”.

*[Ownership & moves](01-primer.md#primer-ownership) · [Interior mutability](01-primer.md#primer-interior-mutability)* Elsewhere in the seeder: `merge` calls `std::mem::take(&mut st.pool)` to move the vector out of the mutex guard (leaving an empty one), passes it by value to the pure `merge_candidates`, and stores the result back. `take_batch` indexes `st.pool[(start + i) % len]` without `.clone()`, because an `Enode` is `(SocketAddr, [u8; 64])`, which is `Copy`. `forbidden = || !(self.policy)()` needs the parentheses: `policy` is a boxed closure stored in a field, and `self.policy()` would look for a method of that name.

<a id="f-myotis-net-src-el-rlpx-mod-rs"></a>

### myotis-net/src/el/rlpx/mod.rs

*module index · 17 lines · Java twin · networking.rlpx*

Index of the RLPx transport: `ecies`, `handshake`, `frame` and `transport`. Only the initiator side exists. The first three are now 4-line shims that re-export `myotis-wire`'s codecs at their old paths ([frame](05-wire.md#f-myotis-wire-src-rlpx-frame-rs), [handshake](05-wire.md#f-myotis-wire-src-rlpx-handshake-rs), [stop 5](05-wire.md)), so code in this crate still writes `crate::el::rlpx::frame::FrameCodec`. Only `transport` does I/O.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc (lines 4–12) still describes `ecies`, `handshake` and `frame` as this crate's pure codecs pinned by `rust/testdata/el/rlpx/`, and `transport.rs` (lines 5–7) says “the crypto lives in the pure `super::ecies`/`handshake`/`frame` modules”. Since myotis#505 those modules are re-exports; the code lives in `myotis-wire/src/rlpx/`.

<a id="f-myotis-net-src-el-rlpx-transport-rs"></a>

### myotis-net/src/el/rlpx/transport.rs

*library · 424 lines · Java twin · RLPxConnector / RLPxHandler*

The only RLPx code that does I/O and draws OS entropy: dial TCP, run the initiator handshake to FRAMED (10 s budget), and send or receive framed p2p messages with timeouts. Hello's codec moved to `myotis-wire` and is re-exported here (lines 25–28). `pub struct RlpxConnection<S = TcpStream>` (lines 55–63) holds the stream, the stateful `FrameCodec`, the peer's public key and an optional traffic meter. It is generic over its byte stream, so the same code runs over a Tor `DataStream`; a TCP connection can additionally be split into an independently owned reader and writer.

`rust/myotis-net/src/el/rlpx/transport.rs` · lines 104–116

```rust
/// Split into independent read/write halves for the managed-peer's separate
/// tasks (the frame codec's egress/ingress state are independent). TCP-only:
/// the managed-peer actor is a clearnet construct; the Tor PoC drives the
/// connection through `&mut self` [`send`](Self::send)/[`recv`](Self::recv).
pub fn split(self) -> (RlpxReader, RlpxWriter, [u8; 64]) {
    let (read_half, write_half) = self.stream.into_split();
    let (encoder, decoder) = self.codec.split();
    (
        RlpxReader { read_half, decoder, traffic: self.traffic.clone() },
        RlpxWriter { write_half, encoder, traffic: self.traffic },
        self.peer_pubkey,
    )
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `RlpxConnection<S = TcpStream>` has a **default type parameter**: a plain `RlpxConnection` means the TCP type, so no caller had to change when Tor arrived. Java generics have no defaults.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* This method sits in `impl RlpxConnection<TcpStream>`, together with `dial`, so it exists *only* for the TCP instantiation: only `TcpStream` has `into_split`. Erased Java generics can't express this; the closest analogue is a Kotlin extension function on `RlpxConnection<TcpStream>`.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `split(self)` consumes the connection and moves its fields out one by one, which is allowed because `RlpxConnection` has no `Drop` impl. The read half goes with the ingress decoder, the write half with the egress encoder. The traffic meter is cloned for the reader and moved into the writer; the 64-byte key is `Copy`. Each socket half holds an internal `Arc` of the socket, which closes when both halves are dropped.

`rust/myotis-net/src/el/rlpx/transport.rs` · lines 136–185

```rust
pub async fn handshake_metered(
    mut stream: S,
    local_key: Arc<NodeKey>,
    peer_pubkey: [u8; 64],
    traffic: Option<Arc<TrafficMeter>>,
) -> Result<RlpxConnection<S>, String> {
    // Fresh entropy for this handshake.
    let eph_secret = random32();
    let local_nonce = random32();
    let ecies_eph = random32();
    let ecies_iv = random16();
    let padding = random_padding();

    let mut initiator = Initiator::new(&local_key, peer_pubkey, &eph_secret, local_nonce)
        .map_err(|e| format!("rlpx init: {}", e.0))?;
    let auth_wire = initiator
        .build_auth(&ecies_eph, &ecies_iv, &padding)
        .map_err(|e| format!("rlpx auth: {}", e.0))?;
    stream
        .write_all(&auth_wire)
        .await
        .map_err(|e| format!("rlpx write auth: {e}"))?;
    if let Some(t) = &traffic {
        t.el.add_tx(auth_wire.len());
    }
    // Flush before blocking on the ack: a plain TcpStream sends immediately,
    // but a buffered stream (Arti's Tor `DataStream`) holds the auth in its
    // write buffer until flushed — without this the peer never sees our auth
    // and FINs, surfacing as an "early eof" reading the ack.
    stream
        .flush()
        .await
        .map_err(|e| format!("rlpx flush auth: {e}"))?;

    // Read the EIP-8 ack: 2-byte size prefix, then that many bytes.
    let ack_wire = read_ack(&mut stream).await?;
    if let Some(t) = &traffic {
        t.el.add_rx(ack_wire.len());
    }
    let secrets = initiator
        .process_ack(&ack_wire)
        .map_err(|e| format!("rlpx ack: {}", e.0))?;

    Ok(RlpxConnection {
        stream,
        codec: FrameCodec::new(&secrets),
        peer_pubkey,
        traffic,
    })
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* The surrounding `impl<S: AsyncReadExt + AsyncWriteExt + Unpin>`: tokio implements the `…Ext` traits for every async byte stream, so this bound means “any async stream” and brings `read_exact`, `write_all` and `flush` into scope. The code is compiled separately for each concrete `S` (monomorphization).
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* `Initiator::new(&local_key, …)`: `local_key` is an `Arc<NodeKey>`, and `&Arc<NodeKey>` deref-coerces to the `&'a NodeKey` that `Initiator<'a>` stores. The initiator's borrow lives across several `.await`s, which is fine because the `Arc` and the borrow live inside the same future.
- *[Ownership & moves](01-primer.md#primer-ownership)* `mut stream: S` is owned by the function. `read_ack(&mut stream)` lends it out for one call, and the final struct literal moves it into the returned connection.
- *[Protocol & domain](01-primer.md#primer-domain)* `flush()` before reading the ack is needed for Tor: Arti's `DataStream` buffers output, and without the flush the peer never sees the auth message.

*[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* `write_frame` (lines 278–291) bounds every frame write by 30 s, so a peer that stops reading can't block the shared writer forever. Its `timeout(…, async { … }).await` yields a nested `Result`: the first `map_err`/`?` handles the expired timer, the second the I/O error. A timed-out write leaves the egress MAC advanced mid-frame, so it is fatal for the connection, as the comment at lines 278–280 says. `recv` waits for a frame header without limit (an idle peer is normal) but gives the body 30 s once the header has arrived. The `#[cfg(test)] impl` at lines 239–256 adds `from_secrets`, a constructor that exists only in test builds and skips the ECIES handshake.

<a id="f-myotis-net-src-el-eth-mod-rs"></a>

### myotis-net/src/el/eth/mod.rs

*module index · 11 lines*

Index of eth/66–71: `messages` is a re-export shim of [myotis-wire's eth codecs](05-wire.md#f-myotis-wire-src-eth-rs) ([stop 5](05-wire.md)), and `session` is the handshake and one-request-at-a-time correlation, twin of the Java `EthHandler`.

<a id="f-myotis-net-src-el-eth-session-rs"></a>

### myotis-net/src/el/eth/session.rs

*library · 931 lines · Java twin · EthHandler*

An eth session on one `RlpxConnection<S>`. `handshake` (capped at 30 s) sends our Hello, reads the peer's, picks the highest common eth version (66–71) and snap version (1 or 2), sends our Status in that version's format with the fork id in effect now, reads the peer's Status while answering Pings, and rejects the peer unless network id and genesis match. Afterwards it serves requests one at a time: headers, bodies, proof-verified snap reads, header-chain verdicts, and a transaction push confirmed by a Ping/Pong round trip. `into_parts` hands the connection to the concurrent `ManagedPeer`; the Tor path keeps using the session directly.

| Lines | What happens |
|---|---|
| 1–67 | Docs, versions, `EthConfig` and `fork_id_at`. |
| 69–222 | `EthSession<S>`, `handshake`, `handshake_as` (the Tor path's client id). |
| 224–367 | Request ids, header and body requests, `await_response`, `send_transaction`, `await_pong`, `into_parts`. |
| 369–544 | snap reads and verdicts (single-shot twins of the `ManagedPeer` methods). |
| 546–618 | `negotiate`, `recv_answering_ping`, Disconnect formatting. |
| 620–931 | Tests against a scripted peer over an in-memory stream. |

The handshake body is `let fut = async { … };` (line 114) followed by `tokio::time::timeout(Duration::from_secs(30), fut)` (line 219). The first line only *creates* the future; it runs when `timeout` polls it. A `?` inside makes the *block*, not `handshake_as`, return `Err`, and the outer `.map_err(…)?` turns an expired timer into one more error. The block captures `conn` by value, because `conn` is moved into the `EthSession` it builds; `cfg` and `local_pubkey` are only read, so they are captured by reference.

`rust/myotis-net/src/el/eth/session.rs` · lines 188–222

```rust
        let frame = recv_answering_ping(&mut conn).await?;
        let peer_status = match frame.message_code {
            messages::STATUS => messages::decode_status(&frame.payload, eth_version)
                .map_err(|e| format!("peer Status decode: {}", e.0))?,
            P2P_DISCONNECT => {
                return Err(status_disconnect_error(
                    &peer_hello.client_id,
                    eth_version,
                    &frame.payload,
                ))
            }
            other => return Err(format!("expected Status, got code 0x{other:02x}")),
        };
        if !peer_status.is_compatible(cfg.network_id, &cfg.genesis_hash) {
            return Err(format!(
                "incompatible peer: networkId={} genesis={}",
                peer_status.network_id,
                hex4(&peer_status.genesis_hash)
            ));
        }

        Ok(EthSession {
            conn,
            eth_version,
            snap: snap_version.is_some(),
            snap_version,
            peer_status,
            peer_hello,
            next_request_id: 1,
        })
    };
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .map_err(|_| "eth handshake timed out".to_string())?
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* The `match` on the first non-Ping frame is the Status gate. A matched `STATUS` arm evaluates to the decoded status; the other two arms `return` early, so their type is `!` (“never”) and fits any arm type. Any other frame fails the handshake instead of being skipped, as geth's `readStatusMsg` does.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The error strings are load-bearing: the pool blacklists a peer on the prefixes `"peer Status decode"` and `"incompatible peer"` and classifies a busy peer by `status_disconnect_error`'s text. Tests in this file pin the prefixes so a rewording breaks a test rather than the classification.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Interior mutability](01-primer.md#primer-interior-mutability)* `next_request_id: u64` is a plain counter, because request methods take `&mut self`, which already guarantees exclusive access. `ManagedPeer`'s methods take `&self`, so it needs an `AtomicU64`.

`rust/myotis-net/src/el/eth/session.rs` · lines 546–578

```rust
/// Highest common eth version (floor 66) + the highest common snap version
/// (`None` when the peer offers neither snap/1 nor snap/2). RLPx runs one
/// version per capability name — the highest both sides advertise — so a peer
/// offering snap/1 and snap/2 is a snap/2 session, and a snap/2-only peer (reth
/// implements no snap/1) is no longer mistaken for one without snap.
fn negotiate(hello: &Hello) -> Option<(u64, Option<u64>)> {
    let mut best: Option<u64> = None;
    let mut snap: Option<u64> = None;
    for cap in &hello.capabilities {
        if cap.name == "eth" && OUR_ETH_VERSIONS.contains(&cap.version) && cap.version >= MIN_ETH_VERSION {
            best = Some(best.map_or(cap.version, |b| b.max(cap.version)));
        }
        if cap.name == "snap" && snap::OUR_SNAP_VERSIONS.contains(&cap.version) {
            snap = Some(snap.map_or(cap.version, |b| b.max(cap.version)));
        }
    }
    best.map(|v| (v, snap))
}

/// Receive the next frame, transparently answering a p2p Ping with a Pong.
async fn recv_answering_ping<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    conn: &mut RlpxConnection<S>,
) -> Result<crate::el::rlpx::frame::DecodedFrame, String> {
    loop {
        let frame = conn.recv().await?;
        if frame.message_code == P2P_PING {
            // Pong body is an empty RLP list.
            conn.send(P2P_PONG, &[0xc0]).await?;
            continue;
        }
        return Ok(frame);
    }
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `best.map_or(cap.version, |b| b.max(cap.version))`: “the version if nothing is set yet, otherwise the larger of the two”. A `Some` wrapped around it keeps the running maximum in an `Option`, so “no common version” stays `None`.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `recv_answering_ping` uses one `&mut` borrow for both `recv` and `send`, so reading and writing can never overlap. That's the one-request-at-a-time limitation `peer.rs` removes.

> [!WARNING]
> **Gotcha: a timeout in the middle of a frame**<br>
>
> `await_response` (lines 293–316) wraps `recv_answering_ping` in `timeout(remaining, …)`. A timeout can cancel `read_exact` in the middle of a frame, and tokio documents `read_exact` as not cancel-safe. `EthSession` has no torn-state marker, so after such a timeout the session is out of step with the stream and must not be reused. The Tor read builds a new session for each candidate attempt and drops it when the attempt ends (`reader.rs`, around line 6410).

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The eth/69 Status comment (lines 138–146) says “unlike Java we embed no genesis header RLP, so a genesis probe still gets an empty answer”. `EthConfig::genesis_header_rlp` (lines 53–55) now carries it, the reader sets it on mainnet, and the pool seeds its served-headers window with it (`pool.rs`, around line 1577). On mainnet a genesis probe is answered; on other networks the comment still holds.

#### Testing over an in-memory stream

`rust/myotis-net/src/el/eth/session.rs` · lines 718–759

```rust
/// Our side (the initiator) and the peer's side of one FRAMED connection
/// over an in-memory stream — no ECIES handshake.
fn framed_pair() -> (RlpxConnection<DuplexStream>, RlpxConnection<DuplexStream>) {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (initiator, responder) = SessionSecrets::test_pair();
    (
        RlpxConnection::from_secrets(ours, &initiator, [2; 64]),
        RlpxConnection::from_secrets(theirs, &responder, [1; 64]),
    )
}

/// Run our handshake against a peer that answers our Hello with its own
/// (eth/66-71 + snap/1-2, so eth/71 and snap/2 are negotiated) and sends `script` once our
/// Status arrives. Returns our outcome (negotiated eth and snap versions, the peer's
/// Status) and the codes of every frame we sent after our Status.
async fn handshake_against(
    script: Vec<(u64, Vec<u8>)>,
) -> (Result<(u64, Option<u64>, Status), String>, Vec<u64>) {
    let (ours, mut peer) = framed_pair();
    let peer_side = tokio::spawn(async move {
        assert_eq!(peer.recv().await.unwrap().message_code, P2P_HELLO);
        peer.send(P2P_HELLO, &encode_hello(&[2; 64], 30303)).await.unwrap();
        assert_eq!(peer.recv().await.unwrap().message_code, messages::STATUS);
        for (code, body) in script {
            peer.send(code, &body).await.unwrap();
        }
        // Whatever we answer, until our side hangs up.
        let mut answered = Vec::new();
        while let Ok(frame) = peer.recv().await {
            answered.push(frame.message_code);
        }
        answered
    });
    let outcome = EthSession::handshake(ours, &[1; 64], &test_config(), None)
        .await
        // Dropping the session's connection is what ends the peer's loop.
        .map(|session| {
            let (_conn, eth_version, snap, status, _hello) = session.into_parts();
            (eth_version, snap, status)
        });
    (outcome, peer_side.await.unwrap())
}
```

- *[Tests](01-primer.md#primer-testing) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `tokio::io::duplex` returns two connected in-memory streams. Because `RlpxConnection<S>` and `EthSession<S>` accept any async stream, the test runs the real handshake with `S = DuplexStream`: no sockets, no ECIES, but every frame really encrypted and MAC'd.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership) · [Tests](01-primer.md#primer-testing)* `tokio::spawn(async move { … })` moves `peer` and `script` into the scripted peer's task. The peer loops until our side hangs up, and the comment names the trigger: `into_parts` hands back `_conn`, which is dropped at the end of the closure, closing our end of the duplex.
- *[Tests](01-primer.md#primer-testing) · [async/await & tokio](01-primer.md#primer-async)* The tests run under `#[tokio::test(start_paused = true)]`: tokio's clock is virtual and jumps ahead whenever every task is idle, so a test that leaves the handshake waiting hits its 30 s timeout instantly instead of stalling the suite.

<a id="f-myotis-net-src-el-snap-mod-rs"></a>

### myotis-net/src/el/snap/mod.rs

*module index · 16 lines*

Index of snap/1 and snap/2: `messages` and `fetch` are re-export shims of [myotis-wire's snap codecs](05-wire.md#f-myotis-wire-src-snap-messages-rs) and [verification](05-wire.md#f-myotis-wire-src-snap-fetch-rs) ([stop 5](05-wire.md)). snap shares the eth peer's RLPx connection, and the two protocols are told apart by message code; the first snap code is `0x21`, `0x22` or `0x24` depending on the eth version. The request methods are on `EthSession` and `ManagedPeer`.

<a id="f-myotis-net-src-el-peer-rs"></a>

### myotis-net/src/el/peer.rs

*library · 1,695 lines · Java twin · EthHandler (always-listening channel)*

The managed-peer actor. A handshaken session is split into a reader, owned by a background task, and a writer shared behind a lock. Many requests can be in flight at once, each matched to its response by `(reqId, code)` through a map of oneshot channels. Besides delivering responses, the read loop answers Ping, serves GetBlockHeaders from the pool's shared window, answers other Get\* requests with empty responses, records the peer's announced head (eth/69 BlockRangeUpdate), reports gossip sightings of our own transactions, and fails every waiter on disconnect, recording why. Much of the file defends against async cancellation. Since September it gained eth/70 receipt continuations, eth/71 and snap/2 block access lists, the per-peer head judgement (`KnownHead`, `Coverage`), close reasons and the hedged-read send marker.

![Managed peer. split(self) turns an RlpxConnection into an RlpxReader, moved into the read-loop task as its sole owner, and an RlpxWriter placed inside an Arc tokio Mutex GuardedWriter with a torn flag, shared by request callers and by the read loop for Pong and serving. Request callers insert id and oneshot sender into the shared pending map; the read loop removes the entry for a matching response and sends the payload through the oneshot.](img/11-el-transport-1.svg)

*After `split`, reading has one owner and needs no lock, while writing is shared and serialized by an async mutex. Responses find their waiter through the shared pending map. Oxide arrows lock a shared structure; the green edge is the read loop delivering a response. Not drawn: three small `std::sync::Mutex` cells the loop and the callers share (the known head, the last-response time, the close reason) and the `closed` atomic.*

| Lines | What happens |
|---|---|
| 1–61 | Docs, imports, `REQUEST_TIMEOUT`, the pending map types. |
| 63–126 | `GuardedWriter`, the task-local send marker, `send_frame`. |
| 128–172 | `deliver`, `PendingGuard`. |
| 174–297 | Pure head policy: `HeadSource`, `KnownHead`, `Coverage`, `coverage`, `refusing_lag`, `AnchorSource`. |
| 299–345 | The `ManagedPeer` struct. |
| 347–515 | `close`, the spawn paths (`from_connection` splits and spawns the loop), accessors. |
| 517–628 | `request`, BlockRangeUpdate and transaction sends. |
| 630–870 | eth requests: headers (only requested headers enter the shared serve window), bodies, receipts with eth/70 continuations, block access lists. |
| 872–1015 | snap reads, verified against the trusted root by `myotis-wire`'s `fetch`. |
| 1017–1098 | Header-chain verdicts. |
| 1100–1265 | `Drop` and `read_loop`. |
| 1267–1422 | eth/70 and BAL helpers, `empty_answer`, `fail_all`, `set_close_reason`, `serve_headers`. |
| 1424–1695 | Tests. |

#### The writer and its torn marker

`rust/myotis-net/src/el/peer.rs` · lines 63–75

```rust
/// The egress writer plus a torn-write marker. A frame write whose future is
/// DROPPED mid-await (request futures are cancelled routinely — e.g. the
/// backfill pipeline dropping its in-flight stream on truncation) may have put
/// a partial frame on the wire with the egress MAC already advanced; nothing
/// runs afterwards to notice. `torn` is set before every send and cleared only
/// when the send completes, so the next lock holder observes the tear and
/// refuses the corrupt stream instead of writing MAC-garbage after it.
struct GuardedWriter {
    inner: Option<RlpxWriter>,
    torn: bool,
}

type SharedWriter = Arc<Mutex<GuardedWriter>>;
```

`rust/myotis-net/src/el/peer.rs` · lines 107–126

```rust
/// Send one frame under the writer lock, cancel-safely: a previous send that
/// was cancelled mid-frame leaves `torn` set, which this surfaces as a write
/// error — every call site already treats that as fatal (`fail_all` + close).
async fn send_frame(writer: &SharedWriter, code: u64, body: &[u8]) -> Result<(), String> {
    let mut w = writer.lock().await;
    if w.torn {
        return Err("egress stream torn by a cancelled frame write".to_string());
    }
    w.torn = true;
    let result = match w.inner.as_mut() {
        Some(writer) => writer.send(code, body).await,
        None => Err("peer writer closed".to_string()),
    };
    // A completed-Err send (write error / frame-write timeout) leaves the
    // stream just as mid-frame-corrupt as a cancelled one — keep the marker
    // set so a request already queued on the writer lock (racing `fail_all`'s
    // closed-store) can't write onto the corrupt stream.
    w.torn = result.is_err();
    result
}
```

- *[async/await & tokio](01-primer.md#primer-async)* **Cancellation safety by hand.** `torn` is set *before* the write's `.await`. If the caller's future is dropped mid-write (`write_all` is not cancel-safe), nothing after the `.await` runs, the flag stays set, and the next lock holder refuses the stream instead of writing after a partial frame with an already-advanced MAC.
- *[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* **New since September:** `w.torn = result.is_err();`. A send that *completed* with an error leaves the stream just as corrupt as a cancelled one, so the marker stays set for it too, and a request already queued on the lock can't write after it.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [async/await & tokio](01-primer.md#primer-async)* The guard `w` is a `tokio::sync::MutexGuard`, held across `writer.send(…).await`. That is the point of an async mutex: one frame at a time on the wire. A `std` guard held across an `.await` would block the executor thread and make the future non-`Send`.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `inner: Option<RlpxWriter>`: `close()` takes the writer out, which drops it and closes the write half; later sends see `None` and fail with “peer writer closed”.

#### A task-local mark for hedged reads

`rust/myotis-net/src/el/peer.rs` · lines 77–105

```rust
tokio::task_local! {
    /// When the enclosing hedged attempt's first request frame was written
    /// (see [`scope_send_marker`]). Unset outside a hedged read.
    static REQUEST_SENT: Arc<std::sync::OnceLock<tokio::time::Instant>>;
}

/// Wrap one hedged-read attempt so it records when its first request actually
/// reached the peer's socket, as opposed to when the attempt was created. The
/// two can differ by a lot: every request first waits for the connection's
/// shared writer, which another frame (a large response we are serving, or a
/// write stuck on a peer that stopped reading) can hold for up to the 30 s
/// frame-write timeout. The hedged race judges a loser only from this mark.
pub(crate) fn scope_send_marker<F: std::future::Future>(
    fut: F,
) -> (
    Arc<std::sync::OnceLock<tokio::time::Instant>>,
    impl std::future::Future<Output = F::Output>,
) {
    let sent = Arc::new(std::sync::OnceLock::new());
    (Arc::clone(&sent), REQUEST_SENT.scope(sent, fut))
}

/// Record, for the enclosing hedged attempt if there is one, that a request
/// frame was just written. Only the first call per attempt counts.
pub(crate) fn mark_request_sent() {
    let _ = REQUEST_SENT.try_with(|sent| {
        let _ = sent.set(tokio::time::Instant::now());
    });
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Macros & attributes](01-primer.md#primer-macros)* `tokio::task_local!` declares a value that is visible only to code polled inside a `scope`. `REQUEST_SENT.scope(sent, fut)` wraps `fut` so that anything it calls, however deep, can reach the value without it being passed as a parameter. Java's `ThreadLocal` is the closest analogue, but it would be wrong here: a tokio task can move between threads at every `.await`, and several tasks share a thread.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Interior mutability](01-primer.md#primer-interior-mutability)* The caller keeps one `Arc` clone, the scoped future gets the other. `std::sync::OnceLock` accepts only the first `set`, so the mark records the *first* request frame an attempt wrote. `try_with` returns an error outside a scope, which `let _ =` ignores: `mark_request_sent()` is a no-op for requests that are not part of a hedged read.
- *[Protocol & domain](01-primer.md#primer-domain)* Why it exists: every request first waits for the shared writer, which a large served response or a stuck write can hold for up to 30 s. The hedged race in `reader.rs` and `evm.rs` judges a slow peer from the moment its request actually left, not from when the attempt was created.

#### The guard that cleans up a cancelled request

`rust/myotis-net/src/el/peer.rs` · lines 145–172

```rust
/// Removes a request's pending-map entry if the owning [`ManagedPeer::request`]
/// future is DROPPED mid-flight (routine under the backfill pipeline, which
/// cancels in-flight fetches on truncation). Without this, a cancelled request
/// whose peer never answers would leave its entry until disconnect. Disarmed on
/// every completed path — there the entry is already removed (response
/// delivery, explicit timeout removal, or `fail_all`'s drain). The pending
/// mutex is async, so cleanup happens via a spawned task; at runtime shutdown
/// (no handle) the whole map is being dropped anyway.
struct PendingGuard {
    pending: PendingMap,
    id: u64,
    armed: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pending = Arc::clone(&self.pending);
            let id = self.id;
            handle.spawn(async move {
                pending.lock().await.remove(&id);
            });
        }
    }
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async)* `PendingGuard` lives on the stack of the `request` future. If that future is dropped at any `.await`, the guard is dropped with it, and its `Drop` removes the orphaned map entry. Every path that completes normally sets `armed = false` first, because there the entry is already gone.
- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `Drop::drop` is synchronous and can't `.await` the async mutex, so it spawns a tiny task that can. It clones the `Arc` and copies the id into an `async move` block, because the spawned task must own everything it uses (`'static`). `Handle::try_current()` fails during runtime shutdown, when the whole map is being dropped anyway.

*[Threads, Send & Sync](01-primer.md#primer-concurrency)* `deliver` (lines 128–143) is the other side: the read loop removes the entry only if it expects this `code`, sends the payload through the oneshot, and stamps `last_response` only when the send succeeded. A late answer to a cancelled request can beat its guard's spawned removal, and a frame nobody receives must not count as proof that the peer is responsive.

#### Splitting and spawning

`rust/myotis-net/src/el/peer.rs` · lines 411–444

```rust
let (reader, writer, peer_pubkey) = conn.split();
let snap_codes = snap_version.map(|v| snap::SnapCodes::negotiated(eth_version, v));
let writer = Arc::new(Mutex::new(GuardedWriter { inner: Some(writer), torn: false }));
let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
let closed = Arc::new(AtomicBool::new(false));
let close_reason: SharedCloseReason = Arc::new(std::sync::Mutex::new(None));
// eth/69 Status carries the peer's head, judged against our anchored
// head as of now; eth/68 carries none (only a best hash), so such a
// peer starts with no known head until it serves or the pool probes it.
let anchored_now = anchored_head_number(&anchor);
let head: SharedKnownHead = Arc::new(std::sync::Mutex::new(peer_status.latest_block.map(
    |number| KnownHead {
        number,
        anchored_then: anchored_now,
        source: HeadSource::Announced,
        seen_at: tokio::time::Instant::now(),
    },
)));

let last_response: SharedLastResponse = Arc::new(std::sync::Mutex::new(None));
let reader_task = tokio::spawn(read_loop(
    reader,
    Arc::clone(&writer),
    Arc::clone(&pending),
    Arc::clone(&last_response),
    Arc::clone(&closed),
    Arc::clone(&close_reason),
    snap_codes,
    serve.clone(),
    tx_watch,
    eth_version,
    Arc::clone(&head),
    anchor,
));
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* After `conn.split()`, the `RlpxReader` is *moved* into the task, so it has a sole owner and needs no lock. The `RlpxWriter` goes into `Arc<tokio::Mutex<…>>`, shared by callers and the loop. `Arc::clone` gives the task its own handle to the writer, the pending map, the closed flag and the three small cells. `snap_codes` is `Copy` (it is used again in the struct), `serve` is cloned because the struct keeps it too, and `tx_watch` and `anchor` simply move.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `peer_status.latest_block.map(|number| KnownHead { … })`: an eth/69 Status carries the peer's head, eth/68 doesn't, so the cell starts as `Some` or `None` without an `if`.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* Mutexes and atomics let an `Arc<ManagedPeer>` serve concurrent callers through `&self`. `Send` and `Sync` follow automatically from the field types; nothing in the file implements them by hand.

#### One request

`rust/myotis-net/src/el/peer.rs` · lines 520–558

```rust
async fn request(
    &self,
    send_code: u64,
    want_code: u64,
    encode: impl FnOnce(u64) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    let id = self.next_id.fetch_add(1, Ordering::Relaxed);
    let body = encode(id);
    let (tx, rx) = oneshot::channel();

    // Insert while holding the pending lock, checking `closed` inside it.
    // `fail_all` sets `closed` under the SAME lock, so we can't lose the
    // race where the read loop drains the map (on disconnect) between an
    // unlocked check and our insert — either we insert before the drain (and
    // it delivers our Err) or we observe `closed` and bail here.
    {
        let mut map = self.pending.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err("peer connection closed".to_string());
        }
        map.insert(id, Pending { want_code, tx });
    }
    let mut guard =
        PendingGuard { pending: Arc::clone(&self.pending), id, armed: true };

    // Send under the writer lock; a write failure leaves the egress frame
    // stream in an indeterminate state (a partial frame may be on the wire),
    // so fail EVERY in-flight request — not just this one, which would leave
    // the others hanging until their own timeouts on a dead connection.
    // (If THIS future is cancelled inside the send, the torn marker in
    // `send_frame` makes the next writer fail here instead; the pending
    // entry inserted above is then drained by that `fail_all`, or by the
    // discarded late response — either way it stays bounded.)
    if let Err(e) = send_frame(&self.writer, send_code, &body).await {
        fail_all(&self.pending, &self.closed, &self.close_reason, format!("peer write failure: {e}")).await;
        guard.armed = false; // fail_all drained the map
        return Err(e);
    }
    mark_request_sent();
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Check and insert under one lock.** `fail_all` sets `closed` while holding the *same* pending lock. So a request either inserts before the drain (and receives its `Err`) or sees `closed` and bails. It can never hang on a dead connection.
- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* No `.await` lies between the insert and arming `PendingGuard`: the block's guard is dropped at its `}`, and the next statement arms the guard. If the future is dropped at any later `.await`, the guard removes the entry.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `encode: impl FnOnce(u64) -> Vec<u8>` builds the body once the id is known: a `LongFunction<byte[]>` that runs exactly once. Callers pass closures that borrow their own arguments, such as `|id| messages::encode_get_block_bodies(id, hashes)`.

*[Result, ? and panics](01-primer.md#primer-error-handling) · [async/await & tokio](01-primer.md#primer-async)* The rest of `request` (lines 560–597) has three outcomes after `timeout(REQUEST_TIMEOUT, rx)`: `Ok(Ok(result))` means the response arrived; `Ok(Err(_))` means the sender was dropped because a disconnect drained the map; `Err(_)` means we gave up, so the stale entry is removed. It's Java's `future.get(15, SECONDS)`, with each outcome spelled out. A `timeout_streak` atomic makes only the first timeout of a silent streak a WARN line naming the peer.

#### The read loop

`read_loop` (line 1111) takes `mut reader: RlpxReader` by value: the task owns the reader outright. It loops on `reader.recv().await` and classifies each frame: transaction gossip, BlockRangeUpdate (only on eth/69 and later, where code `0x21` is free; on eth/68 it is the snap base), Ping, Disconnect, served headers, empty answers, and finally responses.

`rust/myotis-net/src/el/peer.rs` · lines 1143–1173

```rust
if code == messages::NEW_POOLED_TRANSACTION_HASHES || code == messages::TRANSACTIONS {
    if let Some(watch) = &tx_watch {
        let now = std::time::Instant::now();
        let (watching, unseen) = {
            let mut w = watch.lock().unwrap();
            let unseen = w.evict_expired(now);
            (w.watching_any(), unseen)
        };
        crate::el::sent_tx::log_unseen_expiries(&unseen);
        if watching {
            let hashes = if code == messages::TRANSACTIONS {
                messages::transactions_gossip_hashes(&frame.payload)
            } else {
                messages::decode_new_pooled_tx_hashes(&frame.payload)
            };
            let sighted: Vec<([u8; 32], std::time::Duration)> = {
                let mut w = watch.lock().unwrap();
                hashes.into_iter().filter_map(|hash| w.mark_seen(&hash, now).map(|after| (hash, after))).collect()
            };
            // The first sighting of one of ours, once each (#531).
            for (hash, after) in sighted {
                tracing::info!(
                    tx = %crate::el::sent_tx::hash_hex(&hash),
                    after_ms = after.as_millis(),
                    "sent transaction seen in gossip"
                );
            }
        }
    }
    continue;
}
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [async/await & tokio](01-primer.md#primer-async)* The sent-transaction watch is a `std` mutex (`SharedSentTxWatch`). Each guard lives inside its own block expression (`let (watching, unseen) = { let mut w = watch.lock().unwrap(); … };`) and dies at the block's `}`, so the hash decoding between the two blocks runs unlocked, and no guard spans an `.await`. Otherwise the future wouldn't be `Send`, and `tokio::spawn(read_loop(…))` wouldn't compile.

`rust/myotis-net/src/el/peer.rs` · lines 1241–1265

```rust
        // Get* requests and their responses both open with `[reqId, …]`. Read
        // it once per frame, by walking the list rather than building it (#454).
        let request_id = messages::leading_request_id(&frame.payload);

        // An inbound Get* request we answer with an empty response.
        if let Some((resp_code, empty)) = request_id.and_then(|id| empty_answer(code, &snap_codes, id, eth_version)) {
            if let Err(e) = send_frame(&writer, resp_code, &empty).await {
                fail_all(&pending, &closed, &close_reason, format!("peer write failure on empty response: {e}"))
                    .await;
                break;
            }
            continue;
        }

        // Otherwise try to correlate a response by (reqId, code). Anything that
        // doesn't match a waiting request is gossip/mempool — ignore it.
        if let Some(id) = request_id {
            deliver(&pending, &last_response, id, code, frame.payload).await;
        }
    }
    // Backstop: every break above already set `closed` via `fail_all`, but keep
    // this so any future exit path can't leave the peer looking open.
    set_close_reason(&close_reason, "peer read loop exited");
    closed.store(true, Ordering::SeqCst);
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `request_id.and_then(|id| empty_answer(code, &snap_codes, id, eth_version))` chains two `Option`s: no request id, or not a Get\* code, both end in `None`. The answer echoes the request's id, so the asking peer can match it.
- *[Ownership & moves](01-primer.md#primer-ownership)* `deliver(…, frame.payload)` moves the payload `Vec` out of the frame and on through the oneshot to the waiting request. The bytes are never copied between socket and caller.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* The lines after the loop are a backstop: every `break` already went through `fail_all`, but any future exit path still leaves the peer marked closed, with a reason.

#### Closing, from either side

`rust/myotis-net/src/el/peer.rs` · lines 1376–1398

```rust
async fn fail_all(
    pending: &PendingMap,
    closed: &Arc<AtomicBool>,
    close_reason: &SharedCloseReason,
    reason: String,
) {
    let mut map = pending.lock().await;
    // The reason before the flag (see `ManagedPeer::close`).
    set_close_reason(close_reason, &reason);
    closed.store(true, Ordering::SeqCst);
    for (_id, entry) in map.drain() {
        let _ = entry.tx.send(Err(reason.clone()));
    }
}

/// Record why the peer closed. The first reason wins: a write failure that
/// follows the remote's Disconnect must not overwrite the Disconnect.
fn set_close_reason(slot: &SharedCloseReason, reason: &str) {
    let mut r = slot.lock().unwrap_or_else(|e| e.into_inner());
    if r.is_none() {
        *r = Some(reason.to_string());
    }
}
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* The reason is written before the flag, so a caller that sees `closed` and then asks why always finds an answer. `set_close_reason` keeps the first reason: a write failure that follows the remote's Disconnect must not overwrite it (#539). `map.drain()` moves every `Pending` out of the map, and `entry.tx.send(…)` consumes each sender; `let _ =` ignores a requester who already gave up.

`rust/myotis-net/src/el/peer.rs` · lines 347–358

```rust
impl ManagedPeer {
    /// Invalidate snapshots too: active oracle Arcs must not keep reads alive.
    pub async fn close(&self) {
        // The reason before the flag: a reader that sees `closed` then asks
        // why must never find nothing.
        set_close_reason(&self.close_reason, "closed by this node");
        self.closed.store(true, Ordering::Release);
        let task = self.reader_task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task { task.abort(); let _ = task.await; }
        self.pending.lock().await.clear();
        self.writer.lock().await.inner.take();
    }
```

`rust/myotis-net/src/el/peer.rs` · lines 1100–1105

```rust
impl Drop for ManagedPeer {
    fn drop(&mut self) {
        // Stop the background read loop when the last handle goes away.
        if let Some(task) = self.reader_task.get_mut().unwrap_or_else(|e| e.into_inner()).take() { task.abort(); }
    }
}
```

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* In `close`, the `std` guard created in `let task = … .take();` dies at the `;`, before `task.await`. In `Drop`, `get_mut()` needs no locking at all: `&mut self` already proves exclusive access, and the mutex just hands out its contents. `close()` stores with `Ordering::Release` while the rest of the file uses `SeqCst`. That is valid, just inconsistent. `Drop` only aborts the task: when the last `Arc<ManagedPeer>` goes, the reader is dropped with the task and the writer with the struct.

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* `Coverage` (lines 216–231) derives `PartialOrd` and `Ord`. For an enum, the derived order is the declaration order, so `Covers < Near < Unknown < Behind`, and the pool sorts peers for its read ladder by that order. The judgement compares the peer's head with *our* anchored head as observed at the same moment (`KnownHead::anchored_then`), so it doesn't go stale as the observation ages; an observation older than five minutes simply counts as Unknown.

*[Protocol & domain](01-primer.md#primer-domain)* Two defenses in the eth requests are worth knowing. Headers a peer returns enter the pool's serve window only if they are the ones we asked for (by number range, or by hash): a hostile peer could otherwise pin the window at fabricated far-future numbers (lines 650–665). Block access lists are kept only when their keccak matches the commitment in the header, and a mismatch is reported as `forged` (`verified_bal_entries`, lines 1309–1320).

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc's frame list (lines 13–14) says an inbound Get\* request gets an empty response because “the wallet serves no chain data”. The read loop first serves GetBlockHeaders from the pool's shared window (lines 1223–1234), and only unservable requests get the empty answer. The field doc on `eth_version` (line 323) says “66-69”; the session negotiates up to eth/71.

<a id="f-myotis-net-src-el-peercache-rs"></a>

### myotis-net/src/el/peercache.rs

*library · 1,133 lines · Java twin · PeerCache / FilePeerCache*

Persists execution-layer peers that reached a READY session, so a restart dials proven snap servers first. It reads and writes the Java engine's `peers[-net].cache` file in the same tab-separated format. On top of the snap-capability flag it keeps learned verdicts: serving quality (3 failures in a row → DENIED, any serve → CONFIRMED), reachability (5 failed connects → reported DENIED, 50 → removed), and a Rust-only `bal` token for peers that served a verified block access list. Keys are canonical, so a node seen as `::ffff:a.b.c.d` and as `a.b.c.d` holds one entry. The Tor reserve takes peers out of this cache and gives them back (`remove`, `restore`).

| Lines | What happens |
|---|---|
| 1–50 | Docs: record format, canonical keys, capability versus quality, reachability. |
| 52–136 | Thresholds, `SnapQuality`, `CachedElPeer`, `Entry` and `absorb`. |
| 138–290 | `ElPeerCache`, `load`, the tab and legacy colon parsers, `insert_loaded`. |
| 292–404 | `peers` (dial order), BAL marks, the Tor-reserve hand-off, `quality_of`. |
| 406–600 | `add`, the `record_*` verdicts, `flush`. |
| 602–651 | Key and hex helpers. |
| 653–1133 | Tests, including Java-format compatibility. |

`rust/myotis-net/src/el/peercache.rs` · lines 126–135

```rust
fn absorb(&mut self, other: Entry) {
    self.snap |= other.snap;
    self.quality = match (self.quality, other.quality) {
        (SnapQuality::Confirmed, _) | (_, SnapQuality::Confirmed) => SnapQuality::Confirmed,
        (SnapQuality::Denied, _) | (_, SnapQuality::Denied) => SnapQuality::Denied,
        _ => SnapQuality::Unknown,
    };
    self.fails = self.fails.min(other.fails);
    self.bal |= other.bal;
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Ownership & moves](01-primer.md#primer-ownership)* A `match` on a tuple with or-patterns: `(Confirmed, _) | (_, Confirmed)` reads “either side is Confirmed”, and the arms are tried in order, so Confirmed beats Denied beats Unknown. `SnapQuality` is `Copy`, so building the tuple copies both values and borrows nothing. `other: Entry` is taken by value: the second line is consumed by the merge.

`rust/myotis-net/src/el/peercache.rs` · lines 296–321

```rust
pub fn peers(&self) -> Vec<CachedElPeer> {
    let mut out: Vec<(CachedElPeer, bool)> = self
        .entries
        .iter()
        .filter_map(|(k, e)| {
            let addr = parse_key(k)?;
            let pubkey = parse_pubkey(&e.pubkey_hex)?;
            // A peer past the connect-failure demote threshold reports
            // Denied regardless of its learned serve quality: a
            // currently-unreachable Confirmed peer must not outrank
            // reachable candidates in the dial order. The stored verdict
            // is kept — one successful connect clears the streak and
            // restores it (Java parity).
            let quality = if e.fails >= CONNECT_FAILURE_DEMOTE {
                SnapQuality::Denied
            } else {
                e.quality
            };
            Some((CachedElPeer { addr, pubkey, snap: e.snap, quality }, e.bal))
        })
        .collect();
    // Snap peers first (by quality), then non-snap; BAL servers first
    // within a rank. Stable otherwise.
    out.sort_by_key(|(p, bal)| (if p.snap { p.quality.dial_rank() } else { 3 }, !*bal));
    out.into_iter().map(|(p, _)| p).collect()
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* Inside the `filter_map` closure, `parse_key(k)?` returns `None` from the *closure*, not from `peers`: a corrupt entry is skipped. `?` always applies to the innermost function or closure.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `sort_by_key(|(p, bal)| (rank, !*bal))` sorts by a tuple, compared field by field. `false < true`, so `!bal` puts BAL servers first within a rank. `sort_by_key` is stable: equal keys keep their map order.

`rust/myotis-net/src/el/peercache.rs` · lines 477–501

```rust
pub fn record_connect_failure(&mut self, addr: SocketAddr) {
    if self.path.is_none() {
        return;
    }
    let k = addr_key(addr);
    let Some(e) = self.entries.get_mut(&k) else {
        return;
    };
    e.fails = e.fails.saturating_add(1);
    if e.fails >= CONNECT_FAILURE_EVICT {
        let fails = e.fails;
        self.entries.remove(&k);
        self.failures.remove(&k);
        self.dirty = true;
        tracing::info!(%addr, fails, "evicted unreachable peer from EL cache");
    } else if e.fails % CONNECT_FAILURE_DEMOTE == 0 {
        // Persist every 5th failure (not just the demote crossing) so a
        // restart resumes the streak with at most 4 counts lost — keeping
        // eviction genuinely cumulative across restarts (Java parity).
        self.dirty = true;
        if e.fails == CONNECT_FAILURE_DEMOTE {
            tracing::info!(%addr, fails = e.fails, "deprioritized unreachable EL cache peer");
        }
    }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Borrowing & slices](01-primer.md#primer-borrowing)* A single-owner type: every mutator takes `&mut self`, and there is no locking inside. The pool supplies the mutex, just as a caller would guard a non-thread-safe Java class.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `e` is a mutable borrow into `entries`. `let fails = e.fails;` copies the value out, so `e` is dead before `self.entries.remove(&k)` needs the map mutably. Logging `e.fails` in the `tracing::info!` instead would not compile. Writing `self.dirty` while `e` is alive (the `else if` branch) is fine, since those are disjoint fields.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `BTreeMap` (Java's `TreeMap`) makes every rewrite deterministic. `FAILURE_THRESHOLD` is `pub(crate)` so the pool can pin its own constant equal to it with a compile-time assertion.

*[Protocol & domain](01-primer.md#primer-domain) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* Connect failures are only recorded while the device is demonstrably online, so an offline phone can't wipe out its own cache. `flush` is a synchronous `std::fs::write` of the whole file, best-effort: a write error leaves `dirty` set for the next try. The one key derivation, `key()`, formats `ip.to_canonical()`, which turns a v4-mapped IPv6 address into its IPv4 form.

<a id="f-myotis-net-src-el-torreserve-rs"></a>

### myotis-net/src/el/torreserve.rs

*library · 442 lines*

The Tor reserve: verified snap servers set aside for Tor reads and sends, persisted beside the peer cache as `peers-tor[-net].cache`. A node moves in from the peer cache and from then on the pool never dials it directly, so no direct session of ours can be paired with a Tor session to it. Its last direct contact is stored with it, and Tor uses it only once `TOR_DIRECT_SEPARATION` has passed. Three Tor dials in a row that the node refuses send it back to the peer cache. The reserve holds about a third of the verified peers, at most 24, and none while fewer than two are known. The Java engine has no Tor mode and never reads this file.

`rust/myotis-net/src/el/torreserve.rs` · lines 174–197

```rust
/// The nodes Tor may use at `now_ms` (unix millis): those whose last direct
/// contact is [`TOR_DIRECT_SEPARATION`] behind, snap-serving quality first
/// (Confirmed → Unknown → Denied), then the fewest Tor failures, then in an
/// order `draw` picks — a fresh one per call, so successive reads spread
/// over the reserve rather than all going to the same first few nodes.
pub(crate) fn ready(&self, now_ms: u64, draw: impl Fn(&[u8; 64]) -> u64) -> Vec<CachedElPeer> {
    let window = TOR_DIRECT_SEPARATION.as_millis() as u64;
    let mut ready: Vec<(&[u8; 64], &Reserved)> = self
        .entries
        .iter()
        .filter(|(_, e)| now_ms >= e.last_direct_ms.saturating_add(window))
        .collect();
    ready.sort_by_cached_key(|(node, e)| (e.quality.dial_rank(), e.tor_fails, draw(node)));
    ready.into_iter().map(|(node, e)| e.as_peer(node)).collect()
}

/// The `n` nodes to hand back when the reserve holds more than its share
/// (the verified cache shrank): the most Tor failures first, then the
/// weakest quality.
pub(crate) fn surplus(&self, n: usize) -> Vec<[u8; 64]> {
    let mut nodes: Vec<(&[u8; 64], &Reserved)> = self.entries.iter().collect();
    nodes.sort_by_key(|(_, e)| (std::cmp::Reverse(e.tor_fails), std::cmp::Reverse(e.quality.dial_rank())));
    nodes.into_iter().take(n).map(|(node, _)| *node).collect()
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `sort_by_cached_key` computes each element's key exactly once, then sorts. That matters because the last key component, `draw(node)`, is meant to be random per call. `sort_by_key` calls the key function on every comparison; a random key would then contradict itself between comparisons, and since Rust 1.81 the sort may even panic when it detects an inconsistent order. Here the draw just shuffles peers of equal rank.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* `Vec<(&[u8; 64], &Reserved)>` holds borrows into `self.entries`; sorting them moves only pointers. `as_peer` builds owned `CachedElPeer`s at the end, so the returned vector borrows nothing. `BTreeMap<[u8; 64], Reserved>` works because fixed-size arrays implement `Ord`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* In `surplus`, `std::cmp::Reverse` flips a key component's order, so the most Tor failures come first without a hand-written comparator.

`rust/myotis-net/src/el/torreserve.rs` · lines 216–230

```rust
#[cfg(any(test, feature = "tor"))]
/// A Tor dial to `node` was refused on its side. The
/// [`TOR_RESERVE_EVICT_AT`]th in a row releases it, returned for the peer
/// cache, and this process does not take it again.
pub(crate) fn record_unreachable(&mut self, node: &[u8; 64]) -> Option<CachedElPeer> {
    let e = self.entries.get_mut(node)?;
    e.tor_fails += 1;
    self.dirty = true;
    if e.tor_fails >= TOR_RESERVE_EVICT_AT {
        self.released.insert(*node);
        self.remove(node)
    } else {
        None
    }
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `e` borrows `self.entries`; `self.dirty = true` writes a different field while `e` is alive, which the compiler allows for disjoint fields. `self.remove(node)` borrows all of `self`, after `e`'s last use in the condition. `#[cfg(any(test, feature = "tor"))]` compiles the method only where it is called, so builds without Tor don't warn about dead code.

<a id="f-myotis-net-src-el-tor-rs"></a>

### myotis-net/src/el/tor.rs

*feature: tor · 394 lines*

Routes the sensitive flows over Tor: account reads, and the broadcast of the wallet's own transactions. Compiled only with the `tor` feature (the desktop dylib and the Android jniLibs when built with `-PtorEngine`). It keeps a lazily bootstrapped, process-wide Arti client and an on/off switch. `open_snap_session` opens a Tor stream isolated per wallet address to a node from the Tor reserve, then runs the *unchanged* RLPx and eth handshakes over it with a fresh throwaway key, a Hello that names the software without its version, and no listen port. `push_transaction` takes the isolation token from its caller (one per broadcast) and counts the push as delivered only when the peer's Pong confirms it read the frame. On Android the host must name Arti's directories first (`set_storage_dirs`).

`rust/myotis-net/src/el/tor.rs` · lines 51–62

```rust
/// Process-wide Tor on/off, flipped by the host (JNI `myotis_set_tor_enabled`).
static ENABLED: AtomicBool = AtomicBool::new(false);

/// The one bootstrapped Tor client, shared across every read. Bootstrap (~11 s)
/// happens on first use, on whatever tokio runtime the reader call runs on.
/// `create_bootstrapped` hands back an `Arc<TorClient>`, which we keep as-is.
static CLIENT: OnceCell<Arc<TorClient<PreferredRuntime>>> = OnceCell::const_new();

/// Stable per-address isolation tokens: the SAME address reuses its circuit
/// (cheap), DIFFERENT addresses never share one (docs §3) — so any single exit
/// only ever sees queries for one of the user's addresses.
static ISOLATION: Mutex<Option<HashMap<[u8; 20], IsolationToken>>> = Mutex::new(None);
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Lifetimes](01-primer.md#primer-lifetimes)* **Global state.** `static` items must be `Sync` and built by a `const` expression. `ENABLED` is an atomic. `ISOLATION` is `Mutex<Option<HashMap>>` because `Mutex::new` is `const` but `HashMap::new` is not, so the map is created on first use with `get_or_insert_with` (`isolation_for`, lines 170–174). `STORAGE` (line 73) works directly, because a struct holding `None` and `false` is a constant.
- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `OnceCell::const_new()` is tokio's async lazy cell, usable in a `static`. The cell is `static`, so references into it are `&'static`.
- *[Ownership & moves](01-primer.md#primer-ownership)* In `isolation_for`, `*map.entry(*address).or_insert_with(IsolationToken::new)` copies the token out of the map, which is allowed because `IsolationToken` is `Copy`; the guard is released when the function returns.

`rust/myotis-net/src/el/tor.rs` · lines 176–231

```rust
/// The one bootstrap in flight, with its generation ([`client`]).
type Bootstrap = futures::future::Shared<futures::future::BoxFuture<'static, Result<(), String>>>;
static BOOTSTRAP: Mutex<(u64, Option<Bootstrap>)> = Mutex::new((0, None));

/// Bootstrap-once accessor for the shared Tor client. ONE bootstrap runs at a
/// time, in a task of its own: every caller waits on it under its own deadline
/// (a read's, a push's), so a deadline never cancels it halfway, and callers
/// that gave up leave nothing behind to retry it. A failed bootstrap is
/// cleared by the first caller that sees it fail, so the next CALL starts a
/// fresh one — never a queue of orphaned retries.
async fn client() -> Result<&'static Arc<TorClient<PreferredRuntime>>, String> {
    use futures::FutureExt;
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let (generation, bootstrap) = {
        let mut slot = BOOTSTRAP.lock().unwrap_or_else(|p| p.into_inner());
        let running = slot.1.clone();
        match running {
            Some(b) => (slot.0, b),
            None => {
                let task = tokio::spawn(async {
                    CLIENT
                        .get_or_try_init(|| async {
                            tracing::info!("tor: bootstrapping embedded Arti client (first use)…");
                            let config = take_config()?;
                            let mut hold = StorageHold { release: true };
                            ensure_crypto_provider();
                            let c = TorClient::create_bootstrapped(config)
                                .await
                                .map_err(|e| format!("tor bootstrap: {e}"))?;
                            hold.release = false; // bootstrapped: the directories are held for good
                            tracing::info!("tor: Arti client bootstrapped");
                            Ok::<_, String>(c)
                        })
                        .await
                        .map(|_| ())
                });
                let b: Bootstrap = async move { task.await.map_err(|e| format!("tor bootstrap task: {e}"))? }
                    .boxed()
                    .shared();
                slot.0 = slot.0.wrapping_add(1);
                slot.1 = Some(b.clone());
                (slot.0, b)
            }
        }
    };
    if let Err(e) = bootstrap.await {
        let mut slot = BOOTSTRAP.lock().unwrap_or_else(|p| p.into_inner());
        if slot.0 == generation {
            slot.1 = None;
        }
        return Err(e);
    }
    CLIENT.get().ok_or_else(|| "tor bootstrap: no client after bootstrap".to_string())
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **A bootstrap no caller can cancel.** The bootstrap runs in a task of its own (`tokio::spawn`). Callers await a `futures::future::Shared` wrapper around its `JoinHandle`: every clone of a `Shared` future resolves to the same output, which must therefore be `Clone` (here `Result<(), String>`). A caller whose own deadline expires drops only its clone; dropping a `JoinHandle` detaches the task rather than killing it. The previous design let a caller's timeout cancel Arti's bootstrap halfway, which the `StorageHold` comment still mentions.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [async/await & tokio](01-primer.md#primer-async)* The `std` guard `slot` lives only inside the block that computes `(generation, bootstrap)`, so it is released before `bootstrap.await`. The generation counter means a caller clears only the failed bootstrap it waited on, never a newer one another caller has started meanwhile.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [async/await & tokio](01-primer.md#primer-async)* `Ok::<_, String>(c)` names the inner async block's error type, which `?` alone can't infer. `get_or_try_init` initializes once, makes concurrent callers wait, and leaves the cell empty after a failure, so a later call can retry.
- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async)* `StorageHold` is another drop guard with a flag, like `PendingGuard`: it releases the claimed Arti directories unless the bootstrap succeeded and cleared `release`.

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Result, ? and panics](01-primer.md#primer-error-handling)* `open_session` (lines 300–343) returns `EthSession<arti_client::DataStream>`: the generic stack instantiated with a Tor stream. Only `split()` is TCP-specific, so the Tor path drives an unsplit session. Its error strings carry a prefix that `is_peer_unreachable` reads: `"tor connect "` and the handshake prefixes count as a strike against the reserved node, `"tor circuit for "` (no circuit, local network down, exit policy) does not. `EthConfig { listen_port: 0, ..eth_cfg.clone() }` is struct-update syntax: a copy with one field changed.

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-elt-q1"></a>

**Q1** · Written answer

Why can a `ManagedPeer` serve many requests concurrently, when an `EthSession` can only handle one at a time?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-elt-q1)

<a id="q-elt-q2"></a>

**Q2** · Multiple choice

`pub struct RlpxConnection<S = TcpStream>`, with `split` in `impl RlpxConnection<TcpStream>` and the handshake in `impl<S: AsyncReadExt + AsyncWriteExt + Unpin> RlpxConnection<S>`. What does this arrangement buy?

- **A.** Dynamic dispatch over streams, chosen at run time
- **B.** Faster TCP, because the default parameter inlines the socket
- **C.** Callers can keep writing `RlpxConnection` for TCP, the handshake and framing run unchanged over any async stream (Arti's `DataStream`, an in-memory `DuplexStream`), and `split` exists only where `into_split` does
- **D.** Automatic encryption of any stream passed in

[Answer →](answers.md#a-elt-q2)

<a id="q-elt-q3"></a>

**Q3** · Multiple choice

`send_frame` sets `w.torn = true` before `writer.send(…).await` and afterwards sets `w.torn = result.is_err()`. What does this protect against?

- **A.** Two request ids colliding in the pending map
- **B.** A frame write that was cancelled or failed may have left a partial frame on the wire with the egress MAC already advanced; the marker makes every later writer refuse the stream instead of appending MAC-garbage
- **C.** Peers that send frames faster than the read loop can decode them
- **D.** A poisoned mutex after a panic in another task

[Answer →](answers.md#a-elt-q3)

<a id="q-elt-q4"></a>

**Q4** · Multiple choice

In discv4's `emit`, why is the discovered entry offered with `try_send` instead of `send().await`?

- **A.** `send` doesn't exist on bounded channels
- **B.** `try_send` avoids cloning the entry
- **C.** The whole service is one `select!` loop in one task; waiting on a full channel would stall receiving, the refresh, the ENR sweep and even stop. The event is advisory because the table already holds the entry
- **D.** `try_send` retries automatically until the pool reads

[Answer →](answers.md#a-elt-q4)

<a id="q-elt-q5"></a>

**Q5** · Written answer

`DnsSeeder::walk_once` starts with `let _claim = WalkClaim(self);`. What does the guard do, in which situations does it do it, and what would change if the line were `let _ = WalkClaim(self);`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-elt-q5)

<a id="q-elt-q6"></a>

**Q6** · Multiple choice

In `walk_all`, `let system;` is declared before the `match` and assigned inside the `ResolverSource::System` arm, whose value is `&system`. Why not write `let system = r;` inside the arm?

- **A.** Style only; both compile
- **B.** Variables can't be declared inside match arms
- **C.** Declared inside the arm, `system` would be dropped at the arm's end while `resolver` still borrowed it, which is a compile error; declaring it outside makes it live until the function returns
- **D.** Because `SystemResolver` is not `Copy` and can't be moved into the arm

[Answer →](answers.md#a-elt-q6)

<a id="q-elt-q7"></a>

**Q7** · Written answer

In discv4's `consider`, `enr` is `self.enr.as_mut()`, a mutable borrow of part of `self`. Yet the function later calls `self.forget(…)` and `self.emit(…).await`, which need all of `self`. Why does this compile, and what role does the `Seen` enum play?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-elt-q7)

<a id="q-elt-q8"></a>

**Q8** · Multiple choice

`TxtLookup::txt` returns `Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>` instead of being an `async fn`. Why?

- **A.** Boxed futures run faster than async fns
- **B.** An `async fn` in a trait makes the trait unusable as `dyn TxtLookup`, because each implementation's future is a different unnamed type; one boxed future type lets `walk` take `&dyn TxtLookup` and the seeder hold `Arc<dyn TxtLookup>`
- **C.** hickory's resolver can only be called from a pinned box
- **D.** `'a` would otherwise make the future `'static`

[Answer →](answers.md#a-elt-q8)

<a id="q-elt-q9"></a>

**Q9** · Multiple choice

In `tor.rs`, `client()` runs the Arti bootstrap inside `tokio::spawn` and hands callers a `Shared` future over the task's `JoinHandle`. What does this achieve?

- **A.** It runs one bootstrap per caller, in parallel
- **B.** A caller whose deadline expires drops only its clone of the shared future; the task keeps running (dropping a `JoinHandle` detaches it), so a bootstrap is never cancelled halfway, and all waiting callers see the same result
- **C.** It makes the Tor client thread-local
- **D.** It lets the bootstrap run without a tokio runtime

[Answer →](answers.md#a-elt-q9)

<a id="q-elt-q10"></a>

**Q10** · Written answer

`ManagedPeer::request` inserts its pending entry while holding the pending lock and checks `closed` inside that lock, then arms a `PendingGuard`. Which two failure cases do these choices prevent?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-elt-q10)

<a id="q-elt-q11"></a>

**Q11** · Multiple choice

`TorReserve::ready` sorts with `sort_by_cached_key(|(node, e)| (e.quality.dial_rank(), e.tor_fails, draw(node)))`, where `draw` returns a random number. Why `sort_by_cached_key` and not `sort_by_key`?

- **A.** `sort_by_cached_key` is always faster
- **B.** `sort_by_key` can't sort tuples
- **C.** `sort_by_cached_key` computes each key once, so each node gets one random draw; `sort_by_key` recomputes keys during comparisons, which with a random key gives an inconsistent order (and recent Rust sorts may panic on that)
- **D.** `sort_by_key` requires the key to be `Copy`

[Answer →](answers.md#a-elt-q11)

<a id="q-elt-q12"></a>

**Q12** · Multiple choice

Why does discv4 answer an ENRRequest only from a node whose pong it verified, checked against the signing key, and within the Ping rate limit?

- **A.** To save CPU on signature checks
- **B.** Because ENR records are secret
- **C.** Without a bond, a spoofed source address could make us send signed records to a victim (amplification); the key check stops a spoofer from borrowing a bootnode's bond, and the rate limit stops a bonded node from asking at line rate
- **D.** Because geth never sends ENRRequests

[Answer →](answers.md#a-elt-q12)

<a id="q-elt-q13"></a>

**Q13** · Written answer

What does `scope_send_marker` record, how does a call deep inside `ManagedPeer::request` reach it without a parameter, and why is a `OnceLock` used?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-elt-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
