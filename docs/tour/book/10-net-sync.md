# myotis-net, part 2: the light-client sync loop

*Stop 10 · crate `myotis-net`* · 7 files · 8,380 lines · about 180 minutes

`sync.rs` conducts the consensus side. It defines each chain, starts the libp2p host and one long-lived task that bootstraps from the trusted checkpoint (or resumes a snapshot), walks the sync committee up to the present, then polls finality once per slot. It refuses to start from an anchor older than the weak-subjectivity bound. A new neighbour, `cl_fork_watch.rs`, listens to what consensus peers advertise and raises an "update required" advisory when the network has moved to a fork this build does not know. The five example binaries reuse these parts as operator tools.

## Rust you will practise

- **Owning a whole state machine in one task** — Fanning out requests as futures (`join_all`, `FuturesUnordered`, `select!`, `join!`) while one task lends its state as `&mut`, with no locks.
- **Shared knobs across clones** `Arc<WsPolicy>` of atomics and `Arc<ClForkWatch>` with a `Mutex` inside a `Clone` config, and a `watch` channel as a `StateFlow`.
- **Lifecycle and scopes** `stop(self)`, abort-then-await, a `Drop` guard that frees a UDP port, and a lock guard scoped so logging happens after the lock is released.

## How the pieces run

`SyncHandle::start` creates four kinds of concurrent work. The **swarm task** (started by `reqresp::start_host_with`, [Stop 9](09-net-cl.md)) owns the libp2p `Swarm`; everyone else talks to it through a cloneable `ReqRespClient`, which is just an `mpsc::Sender<Command>` plus a few shared maps, with a `oneshot` reply per request. The **discovery task** owns `Discv5` and pushes fork-matched peers into an `mpsc` channel. The **`run_sync` task** owns every piece of sync state. And the **request futures** that `run_sync` creates are not tasks at all: they are futures polled by `run_sync` itself.

State that more than one of them must see lives behind an `Arc`: the Status the host serves to peers (`Arc<LocalStatus>`, a `std::sync::Mutex`), the CL→EL bridge (`Arc<ExecAnchor>`), the weak-subjectivity knobs (`Arc<WsPolicy>`, two atomics), the hunt boost (`Arc<AtomicBool>`), the discv5 table size (`Arc<AtomicUsize>`), the byte counters (`Arc<TrafficMeter>`), and now the fork watch (`Arc<ClForkWatch>`). Everything else is owned by exactly one task.

![Ownership across tasks. The engine host owns the SyncHandle, writes the WsPolicy atomics that the run_sync task reads, and keeps one Arc ClForkWatch per handle whose advisory it reads at status time. SyncHandle holds a watch receiver, a ReqRespClient, the run_sync JoinHandle and an Arc ExecAnchor. The run_sync task exclusively owns the peer pool, the light-client processor, the CL peer cache, staged updates, hunt state and the resume guard, and sends SyncStatus over the watch channel. It talks to the swarm task through mpsc commands and a shared Arc LocalStatus, receives discovered peers from the discovery task over an mpsc channel, shares an Arc AtomicBool hunt boost with it and aborts it on drop, and feeds the EL reader through an Arc ExecAnchor. The swarm task feeds peer Status digests and the discovery task feeds ENR eth2 fields into the ClForkWatch.](img/10-net-sync-1.svg)

*Solid black arrows are channels or method calls, oxide arrows are writes to shared state behind an `Arc` (a `std` `Mutex` or an atomic), and dashed arrows are cancellations. Everything inside the oxide box is plain data that a single task owns. The fan-out requests are futures polled by that same task, not threads. The swarm task has no entry in `tasks`: its `JoinHandle` is dropped at start, and it ends when `stop` sends it `Command::Shutdown`.*

<a id="f-myotis-net-src-sync-rs"></a>

### myotis-net/src/sync.rs

*library · 6,124 lines · Java twin · BeaconLightClient + NetworkConfig*

The consensus-layer light-client driver. It defines each supported chain (`ChainConfig`: trust anchor, fork schedule, pinned LC servers, discv5 bootnodes, weak-subjectivity bound), now four of them with Chiado. `SyncHandle::start` launches the host and one long-lived `run_sync` task. That task bootstraps or resumes, walks the committee with `light_client_updates_by_range`, polls `light_client_finality_update` once per slot at a jittered point just past a third of the slot, publishes a `SyncStatus`, keeps the Status served to peers honest, and feeds the CL→EL `ExecAnchor`. It does not call the fork watch itself; it only threads the `Arc<ClForkWatch>` from its config into the host and discovery.

| Lines | What happens |
|---|---|
| 1–34 | Module doc (the clock policy) and imports. |
| 36–141 | `ws_anchor_stale`; the finality-poll schedule: constants, the pure `finality_poll_offset_ms` and `delay_to_next_poll`, and `now_unix_ms`, the one clock read. |
| 143–230 | `WsPolicy` and the `ChainConfig` struct. |
| 232–711 | `impl ChainConfig`: the geometry check, env overrides (`MYOTIS_CL_STATIC_PEERS`, `MYOTIS_CL_DISABLE_DISCV5`), `mainnet()` / `sepolia()` / `gnosis()` / `chiado()` with the `@checkpoint` blocks, `for_genesis`, fork-digest helpers, `lc_fork_of_chunk` (Gloas wire format), clock helpers. |
| 713–1260 | `hex32`, then pinned data: static LC peers and bootstrap ENRs per network, with census evidence and pruning history in comments. |
| 1262–1346 | `SyncState` and `SyncStatus`. |
| 1348–1460 | `SyncHandle`: start, exec\_anchor, status, watch, stop. |
| 1462–2165 | `Peer` (QUIC-then-TCP `dial_addrs`), the `PeerPool`: fields, tuning constants, credit and eviction, `add_inner`, candidate tiers, `explore_candidates`, `parse_static_peer`. |
| 2167–2613 | `run_sync`: setup, the entry weak-subjectivity gate, snapshot resume, the main loop. |
| 2615–2814 | `persist_snapshot`, `drain_discovered`, `try_bootstrap`. |
| 2816–3073 | `ResumeGuard`, `StagedChunk` / `stage_chunk`, catch-up limits, LC-hunt tuning and the pure `hunt_due`. |
| 3075–3661 | The `catch_up` pipeline. |
| 3663–3857 | `HuntState`, `throughput_bound_verdict`, `next_single_target`, `apply_staged_step`, `agent_serves_one_period`, `StepOutcome`. |
| 3859–4148 | `poll_finality` / `FinalityPoll`, `hunt_round`. |
| 4150–4386 | `refresh_local_status`, `update_exec_anchor`, the SYNCED gate (`light_client_current`, `sync_state_at`, `feed_exec_anchor`), `publish_stale_anchor`, `publish_status`. |
| 4388–6124 | 44 unit tests: agent classification, the WS gate, exec-anchor feeding (including Gloas), config parity with Java for all four networks, checkpoint markers, the poll schedule, hunt triggers, pool policy, staging. |

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc (lines 8–11) says this module "is the only place wall-clock time is read". That holds for the light-client path (it keeps `myotis-consensus` clock-free), but not for the crate: `cl_fork_watch.rs` reads the clock through `el::fork_watch::wall_clock_secs`, and several `el/` modules call `SystemTime::now` too. Also, the doc comment at lines 256–260 ("Mainnet — values duplicated verbatim from the Java `NetworkConfig.MAINNET`") is glued to `env_static_peers`, not to `mainnet()`, which has no doc comment of its own.

#### Configuration shared across clones

`rust/myotis-net/src/sync.rs` · lines 40–46

```rust
/// Whether an anchor is past the weak-subjectivity bound. Saturating: a wall
/// clock BEHIND the anchor (skew) reads as fresh — a backwards clock can only
/// make the check more permissive, and the device clock is outside this
/// threat model.
pub fn ws_anchor_stale(anchor_period: u64, wall_clock_period: u64, bound_periods: u64) -> bool {
    wall_clock_period.saturating_sub(anchor_period) > bound_periods
}
```

`rust/myotis-net/src/sync.rs` · lines 143–156

```rust
/// Live weak-subjectivity knobs, shared between the host FFI and the running
/// sync loop: `ChainConfig` is deep-cloned into the loop at start, but this
/// sits behind an `Arc`, so a host-side write reaches a loop already parked in
/// `StaleAnchor` (the park re-reads both every second). Mirrors the Java
/// engine's `BeaconLightClient` volatiles.
#[derive(Debug, Default)]
pub struct WsPolicy {
    /// Host override for the anchor-age bound (periods); 0 = use the network
    /// default (`ChainConfig::ws_bound_periods`).
    pub bound_override_periods: AtomicU64,
    /// One-shot consent to sync forward from a stale anchor. Per-run: never
    /// persisted, so a restart with a still-stale anchor parks again.
    pub accept_stale_anchor: AtomicBool,
}
```

`rust/myotis-net/src/sync.rs` · lines 211–230

```rust
    /// Default weak-subjectivity bound (sync-committee periods): how old the
    /// sync anchor (embedded checkpoint or persisted snapshot, whichever is
    /// newer) may be before the sync loop refuses it and parks in
    /// `SyncState::StaleAnchor` awaiting explicit consent. Keep in lockstep
    /// with the Java `NetworkConfig.wsBoundPeriods()` (the derivations are
    /// documented there).
    pub ws_bound_periods: u64,
    /// Live host overrides for the bound + the stale-anchor consent (see
    /// [`WsPolicy`]). Shared across config clones.
    pub ws_policy: Arc<WsPolicy>,
    /// The consensus-layer fork watch this loop feeds — every discv5 ENR's
    /// `eth2` field and every peer Status (`cl_fork_watch`). Handle-owned by
    /// the engine host so its evidence survives pause/resume; None (the
    /// network constructors' default) runs without the detector.
    pub cl_fork_watch: Option<Arc<crate::cl_fork_watch::ClForkWatch>>,
    /// This stack's byte counters ([`crate::traffic`]), shared across config
    /// clones like [`Self::ws_policy`]: the libp2p host and discv5 count into
    /// it, and the engine host hands it to the EL reader.
    pub traffic: Arc<crate::traffic::TrafficMeter>,
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Three fields are shared, the rest are copied.** `ChainConfig` derives `Clone`. Cloning deep-copies its `Vec<String>`s and arrays, but for `ws_policy: Arc<WsPolicy>`, `cl_fork_watch: Option<Arc<ClForkWatch>>` and `traffic: Arc<TrafficMeter>` it only bumps a reference count. The engine's copy and the loop's copy therefore point at the same atomics, the same watch and the same counters. A host click on "accept stale anchor" (`store(true, Relaxed)`) is seen by the parked loop, which re-reads the flag every second.
- *[Interior mutability](01-primer.md#primer-interior-mutability)* `AtomicU64` and `AtomicBool` are mutated through `&self`, with no `mut` and no lock: Java's `volatile` plus `AtomicLong`. `#[derive(Default)]` works because both atomics implement `Default` (zero and `false`). `Relaxed` ordering is enough: each flag is read on its own, and nothing else has to become visible together with it.
- *[Protocol & domain](01-primer.md#primer-domain)* `saturating_sub` in `ws_anchor_stale` makes a wall clock *behind* the anchor read as fresh, not as a huge unsigned age. The comparison is `>`: an age equal to the bound is still fresh.

`rust/myotis-net/src/sync.rs` · lines 337–357

```rust
    // Mirrors the @checkpoint:mainnet region of NetworkConfig.java;
    // `./gradlew refreshCheckpoint` rewrites both from one fetch, and
    // `java_and_rust_checkpoints_agree` fails if they ever diverge.
    // @checkpoint:mainnet:begin — managed by `./gradlew refreshCheckpoint`
    // trusted checkpoint: recent finalized mainnet block root (slot 15557088, 2026-11-01, period 1899)
    checkpoint_root: hex32(
        "9e10af227d7fc94fff81a4d9a559a2e2d5c028eba12435eab7eb256c6ad04ebb",
    ),
    checkpoint_slot: 15_557_088,
    // @checkpoint:mainnet:end
    static_peers: MAINNET_STATIC_PEERS.iter().map(|s| s.to_string()).collect(),
    bootstrap_enrs: MAINNET_BOOTSTRAP_ENRS.iter().map(|s| s.to_string()).collect(),
    discv5_port: 0,
    snapshot_path: None,
    cl_peer_cache_path: None,
    ws_bound_periods: 13, // spec WS plateau 3532 epochs / 256 = 13.8 -> floor 13 (~14.7 days)
    ws_policy: Arc::new(WsPolicy::default()),
    traffic: crate::traffic::TrafficMeter::new(),
    cl_fork_watch: None,
}
.with_env_overrides()
```

*[Protocol & domain](01-primer.md#primer-domain) · [Methods & self](01-primer.md#primer-methods)* The embedded trust anchor. `./gradlew refreshCheckpoint` rewrites the text between `@checkpoint:mainnet:begin` and `…:end` in this file *and* in `NetworkConfig.java` from one fetch, and the test `java_and_rust_checkpoints_agree` fails if the two ever drift (it even panics, rather than skipping, when it runs inside a checkout where the Java file has moved). `ws_bound_periods: 13` is the mainnet weak-subjectivity bound; Sepolia also uses 13, Gnosis 3 and Chiado 1. `.with_env_overrides()` is a consuming builder step: it takes the struct by value (`mut self`) and returns it, so every constructor applies the env overrides on its way out.

#### The finality-poll schedule

`rust/myotis-net/src/sync.rs` · lines 111–134

```rust
pub(crate) fn delay_to_next_poll(
    now_ms: u64,
    since_poll_ms: u64,
    genesis_time: u64,
    seconds_per_slot: u64,
    offset_ms: u64,
) -> Duration {
    let slot_ms = poll_slot_ms(seconds_per_slot);
    let rest = slot_ms * FINALITY_POLL_MIN_REST_BPS / 10_000;
    let quota = if slot_ms > FINALITY_POLL_QUOTA_PACE_MS {
        FINALITY_POLL_QUOTA_PACE_MS.saturating_sub(since_poll_ms)
    } else {
        0
    };
    let wait = rest.max(quota);
    let from = now_ms.saturating_add(wait);
    let first = genesis_time.saturating_mul(1000).saturating_add(offset_ms % slot_ms);
    let to_point = if from < first {
        (first - from).min(slot_ms)
    } else {
        slot_ms - (from - first) % slot_ms
    };
    Duration::from_millis(wait + to_point)
}
```

*[Protocol & domain](01-primer.md#primer-domain)* New since September. The old loop slept one fixed slot after each round, so its poll drifted through the slot. Now each process draws one point per run (a third of the slot, plus a 500 ms margin, plus random jitter of up to a quarter slot, capped at two thirds; `finality_poll_offset_ms`, fed by `getrandom`) and sleeps until that point in the next slot. A third of the way in is the attestation and sync-message deadline: the sync aggregate that attests the previous block is out by then, and servers rebuild their latest update as they import it. `delay_to_next_poll` is pure: it takes "now" as a parameter instead of reading the clock, so the tests can drive it with any time. The clamp in `poll_slot_ms` plus the saturating operations keep every sum in range for any input. On 12 s slots it also waits at least 11 s after the previous poll started, because Lighthouse serves each light-client protocol once per 10 s per peer.

#### Status and the handle

`rust/myotis-net/src/sync.rs` · lines 1266–1291

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Starting,
    Bootstrapping,
    CatchingUp,
    Synced,
    /// Syncing is REFUSED: the best available trust anchor (embedded checkpoint
    /// or persisted snapshot, whichever is newer) is older than the
    /// weak-subjectivity bound, so a forged continuation signed by since-exited
    /// committee members would verify. Parked awaiting a raised bound or
    /// explicit consent (`WsPolicy`); fail-closed meanwhile.
    StaleAnchor,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Starting => "STARTING",
            Self::Bootstrapping => "BOOTSTRAPPING",
            Self::CatchingUp => "CATCHING_UP",
            Self::Synced => "SYNCED",
            Self::StaleAnchor => "STALE_ANCHOR",
        };
        write!(f, "{s}")
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `SyncState` is `Copy`: a plain tag with no data, copied like an `int`. `Display` maps each variant to the API string the hosts show. `StaleAnchor` means "fail closed and wait for a raised bound or explicit consent". The `SyncStatus` struct below it carries the numbers: since #658 its `optimistic_slot` is the attested block's own slot, not the signature slot the store tracks.

`rust/myotis-net/src/sync.rs` · lines 1363–1390

```rust
impl SyncHandle {
    /// Start syncing. Must be called from within a tokio runtime.
    pub fn start(config: ChainConfig) -> Result<SyncHandle, String> {
        let (status_tx, status_rx) = watch::channel(SyncStatus::initial());

        // Local Status the responder serves pre-bootstrap: the trusted
        // checkpoint (a real block root — Lighthouse's relevance check
        // goodbyes zero roots; see the Java buildLocalStatusFor).
        let local_status = LocalStatus::new(StatusMessage {
            fork_digest: config.current_fork_digest(),
            finalized_root: config.checkpoint_root,
            finalized_epoch: config.checkpoint_slot / config.slots_per_epoch.max(1),
            head_root: config.checkpoint_root,
            head_slot: config.checkpoint_slot,
            earliest_available_slot: 0,
        });

        // The host feeds every peer Status to the CL fork watch (the same
        // instance discovery feeds ENRs to).
        let client = reqresp::start_host_with(
            Arc::clone(&local_status),
            reqresp::HostConfig {
                cl_fork_watch: config.cl_fork_watch.clone(),
                traffic: Some(Arc::clone(&config.traffic)),
                ..reqresp::HostConfig::default()
            },
        )
        .map(|(client, _, _)| client)?;
```

`rust/myotis-net/src/sync.rs` · lines 1392–1431

```rust
let discovery_cfg = DiscoveryConfig {
    bootstrap_enrs: config.bootstrap_enrs.clone(),
    // Re-read per candidate ENR so the filter follows the fork schedule
    // at the wall clock (a fork pinned ahead rotates it at its epoch
    // without a restart) — see `AcceptedForkDigests`.
    accepted_fork_digests: {
        let chain = config.clone();
        discovery::AcceptedForkDigests::Dynamic(Arc::new(move || chain.accepted_fork_digests()))
    },
    listen_port: config.discv5_port,
    // Shared with run_sync's hunt trigger; discovery re-spawns reuse
    // the same flag, so a boost survives a discv5 restart.
    hunt_boost: Arc::new(AtomicBool::new(false)),
    // Every ENR heard — accepted or not — is evidence for the CL fork
    // watch; it must see them BEFORE the digest filter drops them.
    cl_fork_watch: config.cl_fork_watch.clone(),
    traffic: Some(Arc::clone(&config.traffic)),
    // The pinned CL peers, for targeted lookups: discovery walks toward
    // their derived discv5 ids so a stale pinned address (roost behind
    // a rotated residential IP) heals from third-party tables in
    // seconds instead of waiting on random-walk luck.
    pinned_peer_ids: config
        .static_peers
        .iter()
        .filter_map(|s| parse_static_peer(s))
        .map(|p| p.id)
        .collect(),
};

let exec_anchor = Arc::new(ExecAnchor::new());
let sync_task = tokio::spawn(run_sync(
    config,
    client.clone(),
    local_status,
    status_tx,
    discovery_cfg,
    Arc::clone(&exec_anchor),
));

Ok(SyncHandle { status_rx, client, tasks: vec![sync_task], exec_anchor })
```

- *[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `watch::channel(SyncStatus::initial())` holds the *latest* value, like Kotlin's `StateFlow`. The sender goes into the task; the receiver stays in the handle.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `start_host_with` returns `Result<(ReqRespClient, PeerId, JoinHandle), String>`. `.map(|(client, _, _)| client)?` destructures the tuple in the closure's parameter, keeps the client and drops the other two. Dropping a `JoinHandle` does not stop the task, it only detaches it. `?` returns early with the `String` error, which matches `start`'s own error type.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `accepted_fork_digests` is built from a `move` closure that owns a *clone* of the whole config, wrapped as `AcceptedForkDigests::Dynamic(Arc<dyn Fn() -> …>)`. The discovery task calls it for every candidate ENR, so the filter follows the fork schedule at the wall clock without a restart. The inner block `{ let chain = …; … }` is an expression: its last line is the field's value.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* `tokio::spawn(run_sync(config, client.clone(), …))` *moves* the config, the `LocalStatus` `Arc`, the watch sender and the discovery config into the task, because a spawned future must own its data (`'static`). `config` cannot be used after that line, which is why the closure above had to take its own clone first.
- *[Protocol & domain](01-primer.md#primer-domain)* The same `config.cl_fork_watch.clone()` goes to two places: `HostConfig` (the swarm task records every peer's Status digest) and `DiscoveryConfig` (the discovery task records every routing-table ENR). That is the whole connection between this file and `cl_fork_watch.rs`.

`rust/myotis-net/src/sync.rs` · lines 1434–1460

```rust
    /// The EL execution anchor fed by this beacon sync loop — the CL→EL trust
    /// bridge the verified-read ladder anchors against (finalized/optimistic
    /// execution + the BLS-attested state-root window).
    pub fn exec_anchor(&self) -> Arc<ExecAnchor> {
        Arc::clone(&self.exec_anchor)
    }

    pub fn status(&self) -> SyncStatus {
        self.status_rx.borrow().clone()
    }

    /// A watch receiver for callers that want to await state changes.
    pub fn watch(&self) -> watch::Receiver<SyncStatus> {
        self.status_rx.clone()
    }

    /// Stop the sync loop, discovery, and the libp2p host.
    pub async fn stop(self) {
        self.client.shutdown().await;
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* `status()` calls `self.status_rx.borrow().clone()`. `borrow()` returns a guard that holds a read lock on the channel's value; the guard lives only until the end of that statement, and `.clone()` copies the value out first. Holding the guard longer would block the sender.
- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async)* **`stop(self)` consumes the handle**, so the compiler rejects any later use. It first tells the swarm task to shut down. The first loop then *borrows* the handles (`&self.tasks`) to abort them, and the second *moves* each `JoinHandle` out, because `.await` consumes it. Awaiting an aborted task yields `Err(JoinError::Cancelled)`, which `let _ =` discards.

> [!WARNING]
> **Gotcha**<br>
>
> Dropping a `SyncHandle` *without* calling `stop()` stops nothing. `SyncHandle` has no `Drop` impl, and a dropped `JoinHandle` merely detaches its task. `run_sync` has no exit path at all; `abort()` is the shutdown signal. That is why the engine host always calls `sync.stop().await`.

#### The loop: setup

`rust/myotis-net/src/sync.rs` · lines 2171–2230

```rust
async fn run_sync(
    config: ChainConfig,
    client: ReqRespClient,
    local_status: Arc<LocalStatus>,
    status_tx: watch::Sender<SyncStatus>,
    discovery_cfg: DiscoveryConfig,
    anchor: Arc<ExecAnchor>,
) {
    let mut pool = PeerPool::new();
    for s in &config.static_peers {
        match parse_static_peer(s) {
            Some(p) => pool.add_static(p.id, p.addr),
            None => tracing::warn!(peer = s, "skipping unparseable static peer multiaddr"),
        }
    }
    tracing::info!(chain = config.name, static_peers = pool.len(),
        fork_digest = %hex_str(&config.current_fork_digest()),
        "sync starting");

    // Discovery feeds the pool continuously; failure is non-fatal (Java treats
    // discv5 the same way). The guard aborts the discovery task the moment
    // run_sync's future is dropped (SyncHandle::stop): without it the lookup
    // loop only notices the closed channel at its next 15 s tick, keeping the
    // UDP port bound and failing a fast stop→start on a fixed discv5_port
    // (tokio cancellation drops the future's locals without unwinding, so the
    // guard is panic=abort-safe and Discv5's socket closes immediately).
    struct DiscoveryGuard(Option<tokio::task::JoinHandle<()>>);
    impl Drop for DiscoveryGuard {
        fn drop(&mut self) {
            if let Some(task) = self.0.as_ref() {
                task.abort();
            }
        }
    }
    let mut discovery_guard = DiscoveryGuard(None);

    let (peer_tx, mut peer_rx) = mpsc::channel::<discovery::DiscoveredPeer>(64);
    let mut discovery_up = match discovery::spawn(discovery_cfg.clone(), peer_tx.clone()).await {
        Ok((task, table_size)) => {
            pool.discv5_table_size = table_size;
            discovery_guard.0 = Some(task);
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "discv5 unavailable — will retry (static peers meanwhile)");
            false
        }
    };
    // Respawn countdown, in outer-loop iterations (~12 s each → retry ~1/min).
    // A failed spawn is often transient (the predecessor instance's port still
    // bound during a fast restart) — without the retry, discv5TableSize would
    // report 0 for the process lifetime, indistinguishable from an empty
    // table, and the empty-table re-seed could never run at all.
    let mut discovery_retry_in = 0u32;

    let mut processor = LightClientProcessor::new(
        LightClientStore::new(config.slots_per_period()),
        config.fork_schedule.clone(),
        config.genesis_validators_root,
    );
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [async/await & tokio](01-primer.md#primer-async)* **`DiscoveryGuard`** is a struct defined *inside* the function, whose `Drop` aborts the discovery task. When `SyncHandle::stop` aborts `run_sync`, tokio drops the future and every local in it, this guard included. The discovery task stops at once and its UDP port is released, so a fast stop→start on a fixed port works. `self.0.as_ref()` borrows the handle inside the `Option` instead of moving it out of `&mut self`.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `discovery_cfg.clone()` and `peer_tx.clone()` keep originals so a *respawned* discovery (retried about every sixth loop iteration after a failure) can reuse them. The `hunt_boost` `Arc` inside the config is shared, so a boost survives the restart. Because the loop keeps one `peer_tx`, `peer_rx` never reports "closed", even while discovery is down.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `LightClientStore::new(config.slots_per_period())` and `LightClientProcessor::new(…)`: the sans-I/O core from [Stop 6](06-consensus.md), owned by this task. `config.fork_schedule.clone()` gives the processor its own copy of the schedule, which it consults for every signature.

#### The weak-subjectivity gate

A light client trusts sync-committee signatures. Validators can leave, though, and once enough members of an old committee have exited, they can sign a forged chain at no cost to themselves. Their signatures would still verify against the old committee. So a light client must not walk forward from an anchor older than the network's weak-subjectivity bound. Here the bound is counted in sync-committee periods (8192 slots: about 27 hours on mainnet, about 11 hours on Gnosis).

`rust/myotis-net/src/sync.rs` · lines 2296–2341

```rust
// Weak-subjectivity gate (mirrors the Java BeaconLightClient.awaitAnchorFreshness).
// The forward walk is only as trustworthy as the anchor it starts from: past the
// bound, a forged continuation signed by since-exited committee members would
// BLS-verify. So judge the best anchor's age and, when it's past the bound, park
// in StaleAnchor — fail closed, publishing status once per second — until the
// bound covers it (host raised it live), consent arrives
// (WsPolicy::accept_stale_anchor), or the task is aborted (stop/pause).
{
    let snap_period = persisted_snap
        .as_ref()
        .map(|s| s.current_sync_committee_period)
        .unwrap_or(0);
    let anchor_period = checkpoint_period.max(snap_period);
    let mut parked = false;
    loop {
        let bound = config.effective_ws_bound_periods();
        let wall_period = config.wall_clock_period();
        let stale = ws_anchor_stale(anchor_period, wall_period, bound);
        if !stale || config.ws_policy.accept_stale_anchor.load(Ordering::Relaxed) {
            break;
        }
        if !parked {
            parked = true;
            tracing::warn!(anchor_period, wall_period, bound,
                age = wall_period - anchor_period,
                "STALE ANCHOR: best trust anchor is past the weak-subjectivity bound — \
                 refusing to sync (a forged chain signed by since-exited committee members \
                 would be indistinguishable) until the bound is raised or the risk is \
                 explicitly accepted");
        }
        publish_stale_anchor(&status_tx, &anchor, anchor_period, bound);
        // Parked across a fork activation, the served Status digest must
        // still follow the schedule (see refresh_local_status).
        refresh_local_status(&config, &processor, &local_status);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if parked {
        tracing::warn!(anchor_period,
            "stale anchor released (bound raised or risk accepted) — syncing forward");
        // Replace the lingering StaleAnchor on the status watch IMMEDIATELY:
        // bootstrap can take a while (or keep failing peer-starved), and until
        // the next publish the UI would keep saying "awaiting your consent"
        // about a consent that was just given.
        publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, false).await;
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Entry gate.** The anchor is the newer of the embedded checkpoint and the persisted snapshot. When it is past the bound, the loop parks in `StaleAnchor` and re-checks once per second, until the host raises the bound (`effective_ws_bound_periods` reads the override atomic), gives consent (`accept_stale_anchor.load(Relaxed)`), or aborts the task. Consent is per run and never persisted. While parked it still keeps the served Status's fork digest in step with the schedule.
- *[async/await & tokio](01-primer.md#primer-async)* `tokio::time::sleep(…).await` yields the worker thread, so a parked loop costs nothing. It is also a cancellation point: `abort()` takes effect at the next `.await`.
- *[Protocol & domain](01-primer.md#primer-domain)* `publish_stale_anchor` sends a status built from `SyncStatus::initial()` with only `state`, `period` (the refused anchor's) and `ws_bound_periods` filled in, and tells the `ExecAnchor` that its finality is no longer current.

`rust/myotis-net/src/sync.rs` · lines 2343–2362

```rust
if let Some(snap) = persisted_snap {
    if snap.current_sync_committee_period > checkpoint_period {
        last_persisted_period = snap.current_sync_committee_period;
        tracing::info!(period = snap.current_sync_committee_period,
            finalized_slot = snap.finalized_slot,
            "resumed from persisted snapshot — skipping bootstrap");
        processor.store.restore(snap);
        resume = ResumeGuard::resumed();
        // Publish the restored state IMMEDIATELY: without this the
        // status watch holds SyncStatus::initial() (period 0 —
        // indistinguishable from a fresh bootstrap) until the first
        // catch-up apply, hiding the resume from the UI and from
        // on-device forensics.
        refresh_local_status(&config, &processor, &local_status);
        publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, false).await;
    } else {
        tracing::info!(
            "persisted snapshot not newer than the configured checkpoint — bootstrapping fresh");
    }
}
```

*[Ownership & moves](01-primer.md#primer-ownership)* Note the two uses of `persisted_snap`. The gate above only *looked* at it: `persisted_snap.as_ref().map(|s| s.current_sync_committee_period)` turns `&Option<Snapshot>` into `Option<&Snapshot>` and copies one `u64` out. Here `if let Some(snap) = persisted_snap` *moves* the snapshot out of the `Option`, and `processor.store.restore(snap)` moves it again into the store. After this block `persisted_snap` is gone; the compiler would reject any later use. A restored store starts on probation (`ResumeGuard::resumed()`) until an update verifies against it.

`rust/myotis-net/src/sync.rs` · lines 2496–2514

```rust
if processor.store.is_initialized() {
    let held_period = processor.store.current_period();
    let ws_bound = config.effective_ws_bound_periods();
    let wall = config.wall_clock_period();
    if ws_anchor_stale(held_period, wall, ws_bound)
        && !config.ws_policy.accept_stale_anchor.load(Ordering::Relaxed)
    {
        if status_tx.borrow().state != SyncState::StaleAnchor {
            tracing::warn!(held_period, wall_period = wall, bound = ws_bound,
                age = wall - held_period,
                "STALE ANCHOR: held committee aged past the weak-subjectivity \
                 bound while running — refusing to sync forward until the bound \
                 is raised or the risk is explicitly accepted");
        }
        publish_stale_anchor(&status_tx, &anchor, held_period, ws_bound);
        tokio::time::sleep(Duration::from_secs(5)).await;
        continue;
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Borrowing & slices](01-primer.md#primer-borrowing)* **The gate runs in two more places.** Before a re-bootstrap (lines 2434–2448: reachable when a poisoned snapshot was discarded, so the older checkpoint becomes the anchor again), and here, while running: a committee held in memory ages exactly like a snapshot on disk, so a node that was peer-starved for longer than the bound must not walk forward when peers return. Both of these park in 5 s steps. `status_tx.borrow().state` reads the value the loop itself last sent, so the warning is logged only when the state changes.

#### The loop: one iteration

`rust/myotis-net/src/sync.rs` · lines 2516–2529

```rust
let wall_period = config.wall_clock_period();
if wall_period > processor.store.current_period() {
    // Baseline the progress bar at every catch-up ENTRY (not just
    // bootstrap/resume): a process that reached SYNCED and re-enters
    // catch-up after a doze must start its bar at 0%, not at the
    // fraction left over from the previous run's baseline.
    if !in_catchup {
        in_catchup = true;
        pool.sync_start_period = processor.store.current_period() as i64;
    }
    let poisoned = catch_up(&config, &client, &mut pool, &mut processor, &status_tx,
        &mut peer_rx, &mut staged_updates, &mut clcache, &mut resume,
        &mut last_persisted_period, &anchor, &mut hunt)
        .await;
```

`rust/myotis-net/src/sync.rs` · lines 2582–2613

```rust
        in_catchup = false; // reaching here means the committee is current
        let poll_started = Instant::now();
        let poll =
            poll_finality(&config, &client, &mut pool, &mut processor, &mut clcache, &hunt.confirmed)
                .await;
        if poll.verified {
            // A finality update verified against the (possibly restored)
            // committee — the snapshot is genuine. A stale one proves that
            // just as well as one that advanced.
            resume.confirm();
        }
        if !poll.advanced && hunt.hunting {
            // Starved and the proven/preferred tiers came up dry — burst-probe
            // the unproven pool tail for new LC servers.
            hunt_round(&config, &client, &mut pool, &mut processor, &mut clcache,
                &mut hunt.probed, &mut hunt.confirmed)
                .await;
        }
        clcache.flush(); // batch any finality-round evictions into one write
        // No-op unless the period advanced (force-rotate can move it here too).
        persist_snapshot(&config, &processor, &mut last_persisted_period);
        refresh_local_status(&config, &processor, &local_status);
        publish_status(&config, &client, &processor, &pool, &status_tx, &anchor, hunt.hunting).await;

        // The next poll at this process's point in the next slot (just past a
        // third of the way in), not a fixed slot after this round: the update a
        // server holds refreshes when a block lands, so a poll that drifts
        // through the slot answers up to a slot staler than it needs to.
        tokio::time::sleep(config.until_next_finality_poll(poll_started.elapsed(), poll_offset_ms)).await;
    }
    // No code after the loop: the task ends via SyncHandle::stop (abort).
}
```

| Each iteration | What happens |
|---|---|
| 1 · housekeeping | Drain discovered peers without waiting (`try_recv` in `drain_discovered`), track progress, decide whether to hunt for LC servers (`hunt_due`), retry discv5 about every sixth iteration while it is down. |
| 2 · bootstrap | If the store is not initialized: WS gate on the checkpoint, then `try_bootstrap` (8 peers, 16 when hunting). On failure: an optional hunt round, refresh the served Status, publish, sleep 5 s, `continue`. |
| 3 · in-run gate | If the held committee is past the bound: publish `StaleAnchor`, sleep 5 s, `continue`. |
| 4 · catch-up | If the wall-clock period is ahead of the store: the `catch_up` pipeline. A poisoned resume deletes the snapshot and resets the store. Still behind: sleep one slot and skip finality, since finality updates cannot verify against a stale committee. |
| 5 · finality | `poll_finality` (16 peers, first verified advance wins), confirm a resumed snapshot, maybe a hunt round, flush the peer cache, persist, refresh the served Status, publish, sleep until this process's poll point in the next slot. |

*[Borrowing & slices](01-primer.md#primer-borrowing)* `catch_up(&config, &client, &mut pool, &mut processor, …)` lends all the task-owned state at once, twelve arguments. Because *this task* owns it, the helpers can take `&mut` with no synchronization, and each borrow ends when the call returns. `let _ = std::fs::remove_file(path);` ignores the result deliberately. There is no optimistic-update poll: the optimistic head comes from each finality update's attested header.

#### Verification before trust: bootstrap

`rust/myotis-net/src/sync.rs` · lines 2688–2714

```rust
let wire = codec::encode_request(&config.checkpoint_root);
let mut futures = Vec::new();
for peer in &peers {
    let client = client.clone();
    let wire = wire.clone();
    let (id, addrs) = (peer.id, peer.dial_addrs());
    futures.push(async move {
        let res = client.request_raw_at(id, addrs, protocols::BOOTSTRAP, wire).await;
        (id, res)
    });
}
let results = futures::future::join_all(futures).await;

// Same round-scoped cache accounting as poll_finality: strikes are
// buffered and applied ONLY when the whole round fails — a round with a
// verified winner spares its speculative losers, while a fully-failed
// round strikes each failed peer once. Without any bootstrap-side strikes
// (the previous state), dead proven servers could accumulate in the shared
// cache unboundedly and — once they filled the 8-candidate proven tier —
// wedge a fresh bootstrap forever on the same dead dials every round.
let mut round_failures: Vec<String> = Vec::new();
let fail = |pool: &mut PeerPool, buf: &mut Vec<String>, id: PeerId| {
    pool.note_failure(id);
    if let Some(p) = peers.iter().find(|p| p.id == id) {
        buf.push(format!("{}/p2p/{}", p.addr, p.id));
    }
};
```

- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* One `async move` block per candidate, each owning its own client clone, wire bytes, peer id and dial addresses. `futures::future::join_all(futures).await` waits for *every* reply. Then the first valid one, in candidate order, wins.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `let fail = |pool: &mut PeerPool, buf: &mut Vec<String>, id| …` takes the pool as a *parameter* instead of capturing it. A captured `&mut pool` would stay borrowed for as long as the closure lives, and later code (`pool.mark_proven(peer)`) could not touch the pool. The closure does capture `peers`, but only by shared reference, which does not conflict with anything below.

`rust/myotis-net/src/sync.rs` · lines 2751–2758

```rust
// Checkpoint pin: the peer chose the payload, WE chose the root.
let header_root = bootstrap.header.beacon.hash_tree_root();
if header_root != config.checkpoint_root {
    fail(pool, &mut round_failures, peer);
    tracing::warn!(peer = %peer, client = ?client.client_of(&peer), got = %hex_str(&header_root),
        "bootstrap rejected: header root does not match checkpoint");
    continue;
}
```

`rust/myotis-net/src/sync.rs` · lines 2785–2808

```rust
// Shape vs its slot's fork, the committee in the header's state, and the
// execution branch — each at the gindex of the header's fork.
if let Err(reason) = processor.verify_bootstrap(&bootstrap) {
    fail(pool, &mut round_failures, peer);
    tracing::warn!(peer = %peer, client = ?client.client_of(&peer), %reason,
        slot = bootstrap.header.beacon.slot, "bootstrap rejected");
    continue;
}

processor
    .store
    .initialize(bootstrap.header.clone(), bootstrap.current_sync_committee.clone());
pool.mark_proven(peer);
pool.note_served(peer); // verified: checkpoint pin + both branches checked
if let Some(p) = peers.iter().find(|p| p.id == peer) {
    clcache.record_bootstrap(
        &format!("{}/p2p/{}", p.addr, p.id),
        processor.store.current_period(),
    );
}
tracing::info!(peer = %peer, client = ?client.client_of(&peer),
    slot = bootstrap.header.beacon.slot, period = processor.store.current_period(),
    "bootstrap verified and applied");
return true; // round has a winner — buffered strikes are discarded
```

*[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* "The peer chose the payload, WE chose the root." The bootstrap header must hash to the embedded checkpoint root. Then `processor.verify_bootstrap` (new since September; the branches used to be checked inline here) checks that the shape matches the header's fork, that the current sync committee is in the header's state, and that the execution branch binds the execution data to the body, each at the generalized index of the header's fork, so Gloas is covered. It returns `Result<(), BootstrapReject>`; `if let Err(reason) = …` handles only the failure. Only after all of that does the peer earn credit (`mark_proven`, `note_served`). Credit always follows verification, never mere delivery.

#### The catch-up pipeline

`rust/myotis-net/src/sync.rs` · lines 3141–3157

```rust
/// One outstanding ask: what was asked of a busy peer.
struct Ask {
    from: u64,
    /// count=1 ask to a quota-limited server (vs a batch ask) — decided
    /// at top-up, carried here so the response path never has to infer
    /// it from `count` (a batch ask with span 1 also has count 1).
    single: bool,
}
type Answer = (Peer, bool, u64, u64, Result<Vec<u8>, RequestError>);
// The pipeline: every outstanding ask, across top-ups. Boxed because each
// top-up's async block is its own anonymous type.
let mut in_flight: FuturesUnordered<futures::future::BoxFuture<'static, Answer>> =
    FuturesUnordered::new();
// Peers with an ask outstanding — never asked twice concurrently. The
// only bookkeeping: `in_flight` and the per-period coverage the top-up
// needs are both derived from it.
let mut outstanding: HashMap<PeerId, Ask> = HashMap::new();
```

`rust/myotis-net/src/sync.rs` · lines 3373–3380

```rust
let wire = codec::encode_updates_by_range_request(from, count);
let client = client.clone();
in_flight.push(Box::pin(async move {
    let res = client
        .request_raw_at(peer.id, peer.dial_addrs(), protocols::UPDATES_BY_RANGE, wire)
        .await;
    (peer, single, from, count, res)
}));
```

`rust/myotis-net/src/sync.rs` · lines 3446–3458

```rust
// ── One response — or a quota refill, which goes straight back to
// the top-up so the refilled server is asked while others stream.
let next = match refill {
    Some(until) => tokio::select! {
        answer = in_flight.next() => answer,
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(until)) => continue,
    },
    None => in_flight.next().await,
};
let Some((peer, single, sub_from, sub_count, res)) = next else {
    continue;
};
outstanding.remove(&peer.id);
```

- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Lifetimes](01-primer.md#primer-lifetimes)* `FuturesUnordered<BoxFuture<'static, Answer>>` is a set of futures that yields each result as soon as it finishes. `BoxFuture` is `Pin<Box<dyn Future<Output = Answer> + Send + 'static>>`: a heap-allocated future whose concrete type is erased, so the set's element type can be written down in the declaration, long before the first push. `'static` forces each future to *own* its client clone, peer and wire bytes; it may not borrow the pool. The pin gives the future a fixed heap address, which an async state machine that may borrow from itself needs once it has been polled.
- *[async/await & tokio](01-primer.md#primer-async)* `tokio::select!` races "next answer" against "the earliest per-peer quota refill". If the timer wins, the `next()` future is dropped, but the requests stay inside `in_flight`, so nothing is lost; `continue` goes back to the top-up. `let Some(…) = next else { continue };` destructures the 5-tuple answer.
- *[Protocol & domain](01-primer.md#primer-domain)* The pipeline keeps at most 32 asks outstanding, at most 4 of them batch asks of up to 128 periods. Lighthouse-class peers (one update per 10 s each) each get a different look-ahead period, while the prefix period is asked at least twice. Out-of-order answers are staged with up to 3 alternates per period, and the pipeline backs off 5→10→20→25 s after idle waves. A peer whose multi-period answer applies two or more periods is promoted to "batch server" and leads selection afterwards.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The comment on `in_flight` (lines 3150–3151) says it is "Boxed because each top-up's async block is its own anonymous type." That is not quite how the type system works. Each `async` block *in the source* has its own type, but every future one source location creates, however many loop iterations run it, has that same type. `catch_up` has a single push site (line 3375), so an inferred `FuturesUnordered<_>` would compile, as it does in `poll_finality`. The box is a choice (a nameable type, room for a second push site later), not a requirement.

`rust/myotis-net/src/sync.rs` · lines 3424–3431

```rust
let (_, _) = tokio::join!(
    tokio::time::sleep(wait),
    tokio::time::timeout(
        probe_budget,
        hunt_round(config, client, pool, processor, clcache, &mut hunt.probed,
            &mut hunt.confirmed),
    ),
);
```

*[async/await & tokio](01-primer.md#primer-async) · [Borrowing & slices](01-primer.md#primer-borrowing)* When every server is inside its quota window and the walk is slow, the wait itself is used to look for more servers. `tokio::join!` polls both futures on *this* task until both finish. `hunt_round` borrows `pool`, `processor` and `clcache` mutably; `sleep` borrows nothing, so there is no conflict. Two futures that both wanted `&mut pool` would not compile. `timeout` drops the hunt future at the deadline; results it already recorded stay recorded.

`rust/myotis-net/src/sync.rs` · lines 3584–3634

```rust
let mut applied_now_total = 0usize;
let mut from_this_response = 0usize;
loop {
    let before_period = processor.store.current_period();
    let step = apply_staged_step(processor, staged, slot_estimate);
    wave_rejects += step.verify_rejects;
    if let Some(p) = step.reject_participants {
        last_reject_participants = Some(p);
    }
    // Charge every peer whose chunk failed verification — by peer KEY,
    // so the strike lands on whoever actually served the bad copy
    // rather than on whoever happened to respond last.
    for bad in &step.rejected_from {
        if let Some(id) = pool.id_for_key(bad) {
            pool.note_verify_reject(id);
            clcache.mark_failure(bad);
            tracing::warn!(peer = %bad, client = ?client.client_of(&id), period = before_period,
                "catch-up: update failed verification — peer penalised, \
                 will try another next ask");
        }
    }
    if step.applied == 0 {
        // ORDER MATTERS: an apply BLS-verified against the restored
        // committee proves the snapshot genuine — confirm() (below, on
        // the first apply) resets the guard, so rejects only count
        // while nothing has verified yet. The verdict is read at wave
        // end (`resume.poisoned(0)`), so a slower HONEST response can
        // still confirm the snapshot — a fast bad peer must not win.
        let _ = resume.poisoned(step.verify_rejects as u32);
        break;
    }
    if applied_now_total == 0 {
        resume.confirm();
    }
    applied_now_total += step.applied;
    let Some(key) = step.applied_from.as_deref() else { break };
    if key == peer_key {
        from_this_response += 1;
    }
    if let Some(id) = pool.id_for_key(key) {
        pool.mark_proven(id);
        pool.note_served(id); // BLS-verified and applied
    }
    // Only VERIFIED periods reach the shared cross-engine cache (Java
    // applyCatchUpResponses records AFTER processUpdate the same way).
    clcache.record_served(key, before_period, before_period);
    persist_snapshot(config, processor, last_persisted_period);
    publish_status(config, client, processor, &*pool, status_tx, anchor, hunt.hunting)
        .await;
    tokio::task::yield_now().await;
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* `apply_staged_step` verifies at most one update, the one for the store's current period, trying the leader and then each alternate. Each applied period is credited to the peer whose response *staged* it (`applied_from`), and each rejected copy is charged to whoever served it, found by its cache key.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `publish_status(…, &*pool, …)`: `pool` is a `&mut PeerPool` here, and `publish_status` wants `&PeerPool`. `&*pool` reborrows it as shared for the duration of the call. (Writing `pool` would also work, through implicit coercion; the explicit form makes it visible.)
- *[async/await & tokio](01-primer.md#primer-async)* `tokio::task::yield_now().await` hands the worker thread back to the scheduler between BLS verifications, so a long drain does not starve the swarm task that shares the runtime.

`rust/myotis-net/src/sync.rs` · lines 3785–3805

```rust
let target_period = processor.store.current_period();
let Some(chunk) = staged.remove(&target_period) else {
    return StepOutcome::default();
};
let mut out = StepOutcome::default();
// The leader first, then every alternate: one bad copy of a period must not
// block the walk when another peer served a good one in the same round.
let candidates = std::iter::once((chunk.ssz, chunk.fork, chunk.from)).chain(chunk.alternates);
for (ssz, fork, from) in candidates {
    match LightClientUpdate::decode_for(fork, &ssz) {
        Ok(update) => {
            if processor.process_update(&update) {
                processor.store.force_rotate_if_past_period(slot_estimate);
                tracing::debug!(target_period,
                    finalized_slot = update.finalized_header.beacon.slot,
                    period = processor.store.current_period(),
                    "catch-up update applied");
                out.applied = 1;
                out.applied_from = Some(from);
                return out;
            }
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `staged.remove(&target_period)` returns the `StagedChunk` by value: the map no longer owns it. `std::iter::once((chunk.ssz, chunk.fork, chunk.from)).chain(chunk.alternates)` then moves the struct's fields out one by one (a *partial move*, allowed because `StagedChunk` has no `Drop` impl) and chains the leader in front of the alternates, so one `for` loop tries them in order. `let Some(chunk) = … else { return … };` is `let-else`: bind or leave.

#### Finality polling

`rust/myotis-net/src/sync.rs` · lines 3887–3917

```rust
let peers = pool.candidates(16, false, false, &lc_servers, &HashSet::new());
// Parallel fan-out; first update that verifies AND advances wins.
let mut in_flight: FuturesUnordered<_> = peers
    .into_iter()
    .map(|peer| {
        let client = client.clone();
        async move {
            // Finality/optimistic requests carry NO body: write nothing,
            // half-close (the empty Vec is the reqresp layer's "write
            // nothing" contract).
            let res = client
                .request_raw_at(peer.id, peer.dial_addrs(), protocols::FINALITY_UPDATE, Vec::new())
                .await;
            (peer, res)
        }
    })
    .collect();
// Round-scoped cache accounting (the Java poll now fans out with the same
// rule). Dialing 16 at once mints up to 15 speculative losses per 12 s
// round, and feeding each into the cache's 3-strike eviction emptied it of
// every proven server on-device (peers=209, catch_up_servers=0). So:
// failures are buffered per round; a round WITH a winner discards them
// (the losers raced a success); a fully-failed round strikes every failed
// peer once. Dead proven servers thus still evict in ~3 fully-failed
// encounters, and the cache can't accumulate them unboundedly.
// Session-pool note_failure stays per-dial: it exists precisely to rotate
// the live fan-out.
let mut round_failures: Vec<String> = Vec::new();
let mut applied = false;
let mut verified = false;
while let Some((peer, res)) = in_flight.next().await {
```

`rust/myotis-net/src/sync.rs` · lines 3947–3999

```rust
    match LightClientFinalityUpdate::decode_for(fork, &ssz_payload) {
        Ok(update) => match processor.apply_finality_update(&update) {
            FinalityOutcome::Advanced => {
                // Success is a VERIFIED apply that ADVANCED the store
                // (Java notifies its cache only after processUpdate
                // succeeds, never on mere decode — a peer serving
                // decodable-but-unverifiable updates must not earn
                // tier-1 status or cache streak resets).
                pool.mark_proven(peer.id);
                pool.note_served(peer.id);
                clcache.note_success(&format!("{}/p2p/{}", peer.addr, peer.id));
                tracing::info!(peer = %peer.id, client = ?client.client_of(&peer.id),
                    finalized_slot = processor.store.finalized_slot(),
                    optimistic_slot = optimistic_block_slot(&processor.store),
                    period = processor.store.current_period(),
                    "finality update applied");
                applied = true;
                verified = true;
                break; // stragglers are speculative losers — spare them
            }
            // Verified but behind what the store holds: not a win — the
            // round keeps reading, since a current server may still
            // answer — and not a strike. Returning "no advance" is what
            // lets a hunting loop burst-probe for new servers this cycle
            // (a stale win used to short-circuit that), and the store's
            // own age is what drops SYNCED and engages the hunt.
            FinalityOutcome::Stale => {
                verified = true;
                tracing::debug!(peer = %peer.id,
                    attested_slot = update.attested_header.beacon.slot,
                    finalized_slot = update.finalized_header.beacon.slot,
                    "finality update verified but did not advance state");
            }
            FinalityOutcome::Rejected => tracing::debug!(peer = %peer.id,
                finalized_slot = update.finalized_header.beacon.slot,
                "finality update rejected"),
        },
        Err(e) => {
            pool.note_failure(peer.id);
            round_failures.push(format!("{}/p2p/{}", peer.addr, peer.id));
            tracing::debug!(peer = %peer.id, error = %e, "finality update decode failed");
        }
    }
}
// Strikes are for a round that found NO server: a response that verified
// — stale or not — means the losers raced a real one (a stalled network
// would otherwise evict every proven-but-busy server in three rounds).
if !verified {
    for addr in &round_failures {
        clcache.mark_failure(addr);
    }
}
FinalityPoll { advanced: applied, verified }
```

- *[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* `while let Some((peer, res)) = in_flight.next().await` consumes answers in completion order. `break` on the first advance drops the remaining futures, so their replies are no longer awaited. Here the futures are not boxed: they all come from one `map` closure, so they share one anonymous type, and `FuturesUnordered<_>` lets the compiler infer it.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* `FinalityOutcome` is new: `Advanced` (verified and moved the store), `Stale` (verified but not newer), `Rejected`. A stale answer is not a win, so the round keeps reading and a hunting loop may still probe this cycle. It is not a strike either: it sets `verified`, which confirms a resumed snapshot and spares the round's losers.
- *[Protocol & domain](01-primer.md#primer-domain)* The round-scoped failure buffer is a lesson from a real device: striking all 15 speculative losers every slot emptied the peer cache of every proven server (`peers=209, catch_up_servers=0`). Now the shared cache strikes them only when nothing verified at all.

`rust/myotis-net/src/sync.rs` · lines 3663–3693

```rust
/// The LC hunt's state, owned by the sync loop and lent to `catch_up`: probe
/// bookkeeping for `hunt_round`, the engaged flag every status publish
/// carries, the discovery boost it mirrors, and the throughput-bound verdict
/// `catch_up` raises for `hunt_due`.
struct HuntState {
    probed: HashMap<PeerId, Instant>,
    confirmed: HashSet<PeerId>,
    hunting: bool,
    boost: Arc<AtomicBool>,
    /// Raised by `catch_up` when the walk is throughput-bound on a few
    /// quota-limited servers with a long span ahead; keeps `hunt_due` from
    /// disengaging the hunt that `catch_up` raised for it.
    throughput_bound: bool,
}

impl HuntState {
    fn new(boost: Arc<AtomicBool>) -> Self {
        Self {
            probed: HashMap::new(),
            confirmed: HashSet::new(),
            hunting: false,
            boost,
            throughput_bound: false,
        }
    }

    /// The one writer of the engaged flag and its discovery-boost mirror.
    fn set_hunting(&mut self, on: bool) {
        self.hunting = on;
        self.boost.store(on, Ordering::Relaxed);
    }
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `HuntState` is owned by the loop and lent to `catch_up`. Its `boost` is the same `Arc<AtomicBool>` the discovery task holds, so `set_hunting` is the single place where the loop's view and discovery's lookup cadence change together.

#### Publishing and the SYNCED gate

`rust/myotis-net/src/sync.rs` · lines 4209–4225

```rust
if let Some(finalized) = store.finalized_header() {
    match &finalized.execution {
        HeaderExecution::Payload(e) if e.block_hash != [0u8; 32] => {
            anchor.update_finalized(
                finalized.beacon.slot,
                e.state_root,
                e.block_number,
                e.block_hash,
                e.timestamp,
            );
        }
        HeaderExecution::BlockHash(hash) if *hash != [0u8; 32] => {
            anchor.note_finalized_hash(finalized.beacon.slot, *hash);
        }
        _ => {}
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* `update_exec_anchor` is the CL→EL trust bridge. A match guard (`Payload(e) if e.block_hash != [0u8; 32]`) tests the variant and a condition at once; a zero block hash (pre-Merge or absent) falls through to `_ => {}`. `e` is a `&Box<ExecutionPayloadHeader>`, and `e.block_hash` auto-dereferences through both. Gloas headers carry only the execution block hash (`HeaderExecution::BlockHash`), so the anchor records it as pending until the EL fetches the header whose hash it is. The optimistic header is fed the same way in lines 4226–4243.

`rust/myotis-net/src/sync.rs` · lines 4246–4268

```rust
/// SYNCED gate: committee period current AND the finalized header within ~5
/// epochs of wall clock (finality itself trails the head by ~2 epochs).
/// Crate-visible because the EL log index sizes a bound from it
/// (`RESTART_CLAIM_MAX_LEAD` in el/reader.rs, pinned by a test there).
pub(crate) const SYNCED_SLOT_SLACK_EPOCHS: u64 = 5;

/// The light client's half of the SYNCED gate, over the two numbers a
/// [`SyncStatus`] publishes for it (its `period` and `finalized_slot` are the
/// store's): the committee period is the wall clock's, and the finality is
/// within [`SYNCED_SLOT_SLACK_EPOCHS`] of `wall_slot`. Before Gloas that is the
/// whole gate; from Gloas, `feed_exec_anchor` also holds the execution
/// anchor's finality to the same slack. Public so the live cold-start test
/// tells the two halves apart by the gate's own definition, not a copy.
pub fn light_client_current(
    period: u64,
    finalized_slot: u64,
    wall_slot: u64,
    slots_per_epoch: u64,
    slots_per_period: u64,
) -> bool {
    period == spec::compute_sync_committee_period_with(wall_slot, slots_per_period)
        && finalized_slot + SYNCED_SLOT_SLACK_EPOCHS * slots_per_epoch >= wall_slot
}
```

`rust/myotis-net/src/sync.rs` · lines 4301–4321

```rust
fn feed_exec_anchor(
    store: &LightClientStore,
    anchor: &ExecAnchor,
    wall_slot: u64,
    slots_per_epoch: u64,
    slots_per_period: u64,
) -> SyncState {
    update_exec_anchor(store, anchor);
    let mut state = sync_state_at(store, wall_slot, slots_per_epoch, slots_per_period);
    // Gloas: a finality is usable only once its execution header is resolved.
    // A resolver left behind (no EL peer serves the header) must not read as
    // SYNCED — the same slack as the finality gate itself. Before Gloas the
    // anchor's finality IS the store's, so this never fires.
    if state == SyncState::Synced
        && anchor.finalized_slot() + SYNCED_SLOT_SLACK_EPOCHS * slots_per_epoch < wall_slot
    {
        state = SyncState::CatchingUp;
    }
    anchor.set_finality_current(state == SyncState::Synced);
    state
}
```

`rust/myotis-net/src/sync.rs` · lines 4349–4386

```rust
async fn publish_status(
    config: &ChainConfig,
    client: &ReqRespClient,
    processor: &LightClientProcessor,
    pool: &PeerPool,
    status_tx: &watch::Sender<SyncStatus>,
    anchor: &ExecAnchor,
    hunting: bool,
) {
    let store = &processor.store;
    let state = feed_exec_anchor(
        store,
        anchor,
        config.current_slot_estimate(),
        config.slots_per_epoch,
        config.slots_per_period(),
    );
    let finalized_root = store
        .finalized_header()
        .map(|h| h.beacon.hash_tree_root())
        .unwrap_or([0u8; 32]);
    let status = SyncStatus {
        state,
        finalized_slot: store.finalized_slot(),
        finalized_root,
        optimistic_slot: optimistic_block_slot(store),
        period: store.current_period(),
        peer_count: client.connected_peer_count().await,
        served_peers_last_min: pool.served_last_minute(),
        discv5_table_size: pool
            .discv5_table_size
            .load(std::sync::atomic::Ordering::Relaxed),
        sync_start_period: pool.sync_start_period,
        hunting,
        ws_bound_periods: config.effective_ws_bound_periods(),
    };
    let _ = status_tx.send(status);
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* SYNCED means the store is initialized, the wall-clock period equals the store period, and the finalized slot is within 5 epochs of the wall slot (32 minutes on mainnet, about 7 minutes on Gnosis). From Gloas on, `feed_exec_anchor` adds one more condition: the anchor's own finality, which needs the EL header resolved, must be within the same slack. The verdict is written into the anchor too (`set_finality_current`), so the EL log index can tell a restored finality from a current one.
- *[async/await & tokio](01-primer.md#primer-async)* `publish_status` is `async` only because it asks the swarm task for the peer count. `let _ = status_tx.send(status);` ignores the error that occurs when every receiver is gone.

#### Two borrow-checker details in the pool

`rust/myotis-net/src/sync.rs` · lines 1750–1761

```rust
fn note_failure(&mut self, id: PeerId) {
    let n = self.fail_counts.entry(id).or_insert(0);
    *n += 1;
    let threshold = if self.proven.contains(&id) {
        PROVEN_EVICT_AT
    } else {
        UNPROVEN_EVICT_AT
    };
    if *n >= threshold {
        self.evict(&id);
    }
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing)* **Non-lexical lifetimes and disjoint fields.** `n` is a `&mut u32` into `self.fail_counts`. Reading `self.proven` while `n` is alive is fine, because the borrow checker tracks fields separately. `self.evict(&id)` needs all of `self`, and it compiles because `n`'s borrow ended at its last use in the `if` condition. `PeerId` is `Copy`, so `id` survives being passed to `entry(id)`.

`rust/myotis-net/src/sync.rs` · lines 1512–1524

```rust
fn dial_addrs(&self) -> Vec<Multiaddr> {
    let mut addrs = Vec::with_capacity(2);
    if let Some(quic) = &self.quic {
        addrs.push(quic.clone());
    }
    // A peer pooled QUIC-only whose record later gained a TCP port keeps
    // its QUIC `addr` (the cache key never changes shape) and learns the
    // same QUIC address as `quic`: dial it once, not twice.
    if self.quic.as_ref() != Some(&self.addr) {
        addrs.push(self.addr.clone());
    }
    addrs
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* New since September: QUIC. A peer may advertise a QUIC address beside its TCP one, and the spec says to dial QUIC first. `if let Some(quic) = &self.quic` borrows the `Option`'s content instead of moving it out of `&self`; `quic.clone()` then makes the owned `Multiaddr` the `Vec` needs. `self.quic.as_ref() != Some(&self.addr)` compares `Option<&Multiaddr>` values without cloning, so a QUIC-only peer is not dialed twice.

#### A test

`rust/myotis-net/src/sync.rs` · lines 4443–4467

```rust
#[test]
fn ws_gate_staleness_and_bound_precedence() {
    // Fresh: age == bound is NOT stale (the bound is inclusive headroom).
    assert!(!ws_anchor_stale(1800, 1813, 13));
    // Stale: one period past the bound.
    assert!(ws_anchor_stale(1800, 1814, 13));
    // Clock skew (wall behind anchor) reads as fresh, never underflows.
    assert!(!ws_anchor_stale(1800, 1700, 13));

    // Effective bound: network default until the host override is set (> 0),
    // then the override wins; 0 restores the default. Judged through the
    // SHARED WsPolicy so a clone of the config sees the same live values.
    let config = ChainConfig::mainnet();
    assert_eq!(config.effective_ws_bound_periods(), 13);
    let clone = config.clone();
    config.ws_policy.bound_override_periods.store(40, Ordering::Relaxed);
    assert_eq!(config.effective_ws_bound_periods(), 40);
    assert_eq!(clone.effective_ws_bound_periods(), 40, "clones share the policy");
    config.ws_policy.bound_override_periods.store(0, Ordering::Relaxed);
    assert_eq!(config.effective_ws_bound_periods(), 13);

    // Per-network defaults stay in lockstep with NetworkConfig.wsBoundPeriods().
    assert_eq!(ChainConfig::sepolia().effective_ws_bound_periods(), 13);
    assert_eq!(ChainConfig::gnosis().effective_ws_bound_periods(), 3);
}
```

*[Tests](01-primer.md#primer-testing) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* The test proves the sharing claim from the top of this entry: it stores into `config.ws_policy` and reads the change through `clone`. `#[test]` functions inside `mod tests` (under `#[cfg(test)]`) can reach the module's private items, such as `PeerPool` or `hunt_due`, through `use super::*`.

<a id="f-myotis-net-src-cl-fork-watch-rs"></a>

### myotis-net/src/cl\_fork\_watch.rs

*library · 1,055 lines · Java twin · networking.discv5.ClForkWatch*

New since September. A stale-software detector for the consensus layer, the CL twin of `el/fork_watch.rs` (same vote rules and constants, shared test vectors). It watches what consensus peers advertise and raises an advisory when the network has scheduled, or already activated, a fork that this build's `ForkSchedule` does not carry. It is advisory only: nothing in verification reads it. A wrong advisory is a banner in the UI, never a wrong answer.

| Lines | What happens |
|---|---|
| 1–49 | Module doc: the two kinds of evidence (Announced, Placed), the vote, the time rules. |
| 51–88 | Imports, `FAR_FUTURE_EPOCH`, `source_of` (the EL watch's vote key), `merge_advisories`. |
| 90–135 | Observation types, `Inner` (the mutable state), `Vote`, the `ClForkWatch` struct and a hand-written `Debug`. |
| 137–305 | `new` (precomputes every digest the schedule can produce), `observe_enr` / `observe_status` and their `_at` twins, `advisory` / `evaluate`, and `update`, which mutates, re-evaluates and logs on change. |
| 307–338 | Clock helpers: wall epoch, activation time with a 400-day horizon, known transitions. |
| 340–527 | `evaluate_locked`: age out, pass 1 (ENR votes), pass 2 (place bare digests), tally, rank, decide phase and fork id. |
| 530–554 | `evict_oldest` (the 512-source bound), `same_fork`. |
| 556–1055 | 20 tests on Sepolia's real Fulu→Gloas transition, run against a "pre-Gloas build" schedule with Gloas removed; one test checks the constants against `testdata/lc/fork_watch/params.txt`, which the Java twin's test reads too. |

Some domain first. Each consensus client advertises an `eth2` field in its discv5 ENR: the 4-byte *fork digest* of its current fork (a truncated hash of the fork version, the genesis validators root and, since Fulu, the blob parameters), the version of the *next* fork it knows about, and that fork's activation epoch (or `FAR_FUTURE_EPOCH` for none). A Status message carries only the digest. From that, the watch collects two kinds of evidence. **Announced**: a peer on one of our digests names a next-fork epoch our schedule does not know. **Placed**: a peer on a digest we do not know, whose advertised version reproduces that digest under our genesis root and is newer than ours, so it is on a later fork of this chain. A bare digest (a Status) can also be placed against a version some other source announced.

#### Connected to the sync loop by two feeds and one reader

`rust/myotis-net/src/discovery.rs` · lines 599–611

```rust
/// Report one routing-table ENR to the CL fork watch (its `eth2` field, keyed
/// by the record's address). A record without an address has no source to
/// vote as.
fn note_enr(watch: &Option<Arc<crate::cl_fork_watch::ClForkWatch>>, enr: &Enr) {
    let Some(watch) = watch else { return };
    let Some((digest, next_version, next_epoch)) = enr_eth2_fork_id(enr) else { return };
    let ip: IpAddr = match (enr.ip4(), enr.ip6()) {
        (Some(ip4), _) => IpAddr::V4(ip4),
        (None, Some(ip6)) => IpAddr::V6(ip6),
        (None, None) => return,
    };
    watch.observe_enr(&crate::cl_fork_watch::source_of(ip), digest, next_version, next_epoch);
}
```

`rust/myotis-net/src/reqresp.rs` · lines 2002–2013

```rust
/// Record what a peer's auto-Status reply says: its `earliest_available_slot`
/// for request routing, and its `fork_digest` for the CL fork watch (keyed by
/// the connection's source address — one vote per source network).
fn note_peer_status(ctx: &mut SwarmCtx, version: &str, peer_id: PeerId, raw: &[u8]) {
    let Some((earliest, fork_digest)) = log_peer_status(version, peer_id, raw) else {
        return;
    };
    ctx.peer_earliest.insert(peer_id, earliest);
    if let (Some(watch), Some((ip, _))) = (&ctx.cl_fork_watch, ctx.peer_source_ips.get(&peer_id)) {
        watch.observe_status(&crate::cl_fork_watch::source_of(*ip), fork_digest);
    }
}
```

`rust/myotis-engine/src/host.rs` · lines 1196–1215

```rust
/// The handle's CL fork watch — created on its first spin-up from the chain's
/// fork schedule, genesis root, blob params and slot timing, then reused
/// across pause/resume. On every network (no staged rollout: the CL signal
/// needs no EL peer, and a false advisory is a banner, never a wrong answer).
/// None only if the registry mutex is poisoned.
fn cl_fork_watch_for(engine: &EngineState, handle: i64, config: &ChainConfig) -> Option<Arc<ClForkWatch>> {
    let mut map = engine.cl_fork_watches.lock().ok()?;
    let watch = map.entry(handle).or_insert_with(|| {
        Arc::new(ClForkWatch::new(
            config.name,
            config.fork_schedule.clone(),
            config.genesis_validators_root,
            config.blob_params_epoch,
            config.blob_params_max_blobs,
            config.genesis_time,
            config.seconds_per_slot,
        ))
    });
    Some(Arc::clone(watch))
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Protocol & domain](01-primer.md#primer-domain)* **Who owns it.** The engine host keeps one `Arc<ClForkWatch>` per handle in a `Mutex<HashMap<i64, Arc<ClForkWatch>>>` and puts a clone into the `ChainConfig` at every spin-up. `entry(handle).or_insert_with(…)` creates it only the first time, so a pause and resume keeps the evidence. `SyncHandle::start` hands clones to the swarm task and the discovery task. At status time the host calls `advisory()` and merges it with the EL watch's.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* Both feeds are short `let-else` chains. `let Some(watch) = watch else { return };` turns `&Option<Arc<…>>` into `&Arc<…>` through match ergonomics. In `note_peer_status`, `if let (Some(watch), Some((ip, _))) = (…, …)` matches two options at once. The discovery feed reads routing-table entries only, never records relayed in NODES responses: a table entry held a session with us at its address, while a relayed record costs its author nothing.
- *[Protocol & domain](01-primer.md#primer-domain)* The vote key is the source *network* (IPv4 /24, IPv6 /48), not the node id, because node ids are free to mint. One host's EL and CL records count as the same source in both detectors.

#### Interior mutability and a scoped lock

`rust/myotis-net/src/cl_fork_watch.rs` · lines 116–127

```rust
pub struct ClForkWatch {
    label: &'static str,
    schedule: ForkSchedule,
    genesis_validators_root: [u8; 32],
    blob_params_epoch: u64,
    blob_params_max_blobs: u64,
    genesis_time: u64,
    seconds_per_slot: u64,
    /// Every digest the schedule can produce — "ours" — computed once.
    known_digests: Vec<[u8; 4]>,
    inner: Mutex<Inner>,
}
```

`rust/myotis-net/src/cl_fork_watch.rs` · lines 274–305

```rust
fn update(&self, now: u64, mutation: impl FnOnce(&mut Inner)) {
    let current = {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        mutation(&mut inner);
        let current = self.evaluate_locked(&mut inner, now);
        if same_fork(inner.last_logged.as_ref(), current.as_ref()) {
            return;
        }
        inner.last_logged = current;
        current
    };
    match current {
        None => tracing::info!(
            network = self.label,
            "[cl-fork-watch] upgrade advisory cleared"
        ),
        Some(a) if a.phase == Phase::Scheduled => tracing::warn!(
            network = self.label, peers = a.peers, activation = a.activation_time,
            fork_digest = %a.fork_hash_hex(),
            "[cl-fork-watch] consensus peers announce a network upgrade this build does not \
             support — update before then"
        ),
        Some(a) => tracing::warn!(
            network = self.label, peers = a.peers, activation = a.activation_time,
            fork_digest = %a.fork_hash_hex(),
            "[cl-fork-watch] consensus peers are on a fork this build does not support — \
             update required"
        ),
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* Every method takes `&self`, because the watch is shared behind an `Arc` by three tasks and the host. The mutable part sits in `inner: Mutex<Inner>`; the configuration fields beside it are never written after `new`, so they need no lock. This is the Rust shape of a Java class whose mutable fields are all guarded by one `synchronized` lock.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Borrowing & slices](01-primer.md#primer-borrowing)* **The lock is held only inside the inner block.** `let Ok(mut inner) = self.inner.lock() else { return; };` takes the guard. It is dropped at the block's closing brace, before the `match current` that logs. Logging under the lock would make every other observer wait for the log sink. A poisoned lock (a panic while it was held) silently skips the update; `evaluate` returns `None` in that case through `.ok()?`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `mutation: impl FnOnce(&mut Inner)` lets `observe_enr_at` and `observe_status_at` pass in their own change as a closure, which is called exactly once. `mutation(&mut inner)` passes a `&mut MutexGuard<Inner>`, which deref coercion turns into the `&mut Inner` the closure expects.
- *[Ownership & moves](01-primer.md#primer-ownership)* `inner.last_logged = current;` followed by returning `current` would be a use after move for most types. It compiles because `Advisory` derives `Copy`, and so `Option<Advisory>` is `Copy` too.

#### The vote

`rust/myotis-net/src/cl_fork_watch.rs` · lines 340–363

```rust
fn evaluate_locked(&self, inner: &mut Inner, now: u64) -> Option<Advisory> {
    let fresh = now.saturating_sub(OBSERVATION_TTL_SECONDS);
    inner.enr_by_source.retain(|_, o| o.observed_at >= fresh);
    inner.status_by_source.retain(|_, o| o.observed_at >= fresh);

    // Every digest this schedule can produce is "ours": a peer on an older
    // scheduled fork is behind, not news.
    let known_digests = &self.known_digests;
    let current_version =
        u32::from_be_bytes(self.schedule.version_at_epoch(self.wall_epoch(now)));
    // A record whose `next_fork_version` is newer than ours AND reproduces
    // its own digest: a peer on a later fork of THIS chain (with nothing
    // further scheduled it publishes its current version there; with a
    // blob-parameter fork scheduled, still its current version).
    let newer_self_consistent = |o: &EnrObservation| {
        u32::from_be_bytes(o.next_version) > current_version
            && self.digest_of(o.next_version) == o.digest
    };

    // Pass 1: ENR evidence — the only kind that names the fork ahead.
    // Deterministic containers throughout (BTreeMap, sorted versions): a
    // tie must resolve the same way on every evaluate and in both engines.
    let mut votes: BTreeMap<&str, Vote> = BTreeMap::new();
    let mut versions_in_play: Vec<[u8; 4]> = Vec::new();
```

*[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `retain` needs `&mut` access to the maps, so it runs first. After that the function only reads. `votes: BTreeMap<&str, Vote>` borrows its keys from the `String`s in `inner.enr_by_source` and `inner.status_by_source`: no string is copied, and the compiler ensures `votes` does not outlive `inner`. Calling `retain` again while `votes` is alive would not compile. The closure `newer_self_consistent` captures `self` and `current_version` by reference. `BTreeMap` rather than `HashMap` gives a fixed iteration order, so a tie resolves the same way on every evaluation and in both engines.

`rust/myotis-net/src/cl_fork_watch.rs` · lines 480–512

```rust
// Most-backed fork; ties → more placed, a known epoch, the earliest
// epoch, then the lowest version. Must clear both the absolute floor
// and the dissent: a minority can't outvote the peers it contradicts.
let total = |c: &Claim| c.announced + c.placed;
let rank = |c: &Claim| {
    (
        total(c),
        c.placed,
        c.epoch.is_some(),
        std::cmp::Reverse(c.epoch.unwrap_or(u64::MAX)),
        std::cmp::Reverse(u32::from_be_bytes(c.version)),
    )
};
let mut best: Option<&Claim> = None;
for c in &claims {
    if total(c) < MIN_PEERS || total(c) <= dissent {
        continue;
    }
    if best.is_none_or(|b| rank(c) > rank(b)) {
        best = Some(c);
    }
}
let best = best?;
let activation_time = best
    .epoch
    .and_then(|e| self.activation_time(e, now))
    .unwrap_or(0);
let phase = if (activation_time != 0 && activation_time <= now) || best.placed >= MIN_PEERS
{
    Phase::Active
} else {
    Phase::Scheduled
};
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `rank` returns a tuple. Tuples implement `Ord` lexicographically when every element does, `false < true` for `bool`, and `std::cmp::Reverse` flips one element's order. One `>` therefore encodes the whole tie-break list from the comment: more support, then more placed peers, a known epoch, the earliest epoch, and the lowest version.
- *[Protocol & domain](01-primer.md#primer-domain)* An advisory needs at least `MIN_PEERS` (3) sources behind one fork *and* more of them than sources on our chain that announce nothing unknown. It is `Active` once its activation time has passed or three sources were placed on it, else `Scheduled`. `best.is_none_or(…)` (a recent `Option` method) reads "no best yet, or this one ranks higher".

`rust/myotis-net/src/cl_fork_watch.rs` · lines 75–88

```rust
pub fn merge_advisories(el: Option<Advisory>, cl: Option<Advisory>) -> Option<Advisory> {
    match (el, cl) {
        (None, cl) => cl,
        (el, None) => el,
        (Some(e), Some(c)) => {
            let rank = |a: &Advisory| (a.phase == Phase::Active, a.activation_time != 0, a.peers);
            if rank(&c) > rank(&e) {
                Some(c)
            } else {
                Some(e)
            }
        }
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `merge_advisories` matches a tuple of two options. `(None, cl) => cl` binds the second element whatever it is, so the first two arms cover every case where at least one side is `None`; only `(Some, Some)` reaches the ranking. The ranking reuses the tuple trick: active beats scheduled, a known time beats an unknown one, then more peers, and on a full tie the EL advisory wins.

## The examples

`examples/*.rs` are extra executables that Cargo discovers automatically; run one with `cargo run -p myotis-net --example live_sync`. Each is compiled as its own crate that links the library. It sees only `pub` items (which is why several re-implement the private `parse_static_peer`) and may use dev-dependencies such as `tracing-subscriber`. `cargo test` builds examples but does not run them. Every example now accepts `chiado` as a network.

<a id="f-myotis-net-examples-live-sync-rs"></a>

### myotis-net/examples/live\_sync.rs

*example binary · 81 lines*

The smallest complete user of the public API. It picks a chain from `NET`, starts a `SyncHandle`, and logs the status whenever it changes. With `--once` it exits 0 at SYNCED, or 1 after a 1500 s budget (`ONCE_BUDGET`). `roost`'s README uses it to test a candidate server.

`rust/myotis-net/examples/live_sync.rs` · lines 51–80

```rust
let handle = match SyncHandle::start(config) {
    Ok(h) => h,
    Err(e) => {
        tracing::error!(error = %e, "failed to start sync");
        std::process::exit(2);
    }
};

let deadline = tokio::time::Instant::now() + ONCE_BUDGET;
let mut last_status = None;
loop {
    tokio::time::sleep(Duration::from_secs(3)).await;
    let s = handle.status();
    if last_status.as_ref() != Some(&s) {
        tracing::info!(state = %s.state, finalized_slot = s.finalized_slot,
            optimistic_slot = s.optimistic_slot, period = s.period,
            peers = s.peer_count, "status");
        last_status = Some(s.clone());
    }
    if s.state == SyncState::Synced && once {
        tracing::info!("SYNCED — exiting (--once)");
        handle.stop().await;
        std::process::exit(0);
    }
    if once && tokio::time::Instant::now() > deadline {
        tracing::error!(budget_s = ONCE_BUDGET.as_secs(), "not SYNCED within the budget");
        handle.stop().await;
        std::process::exit(1);
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Macros & attributes](01-primer.md#primer-macros) · [Binaries, CLIs & signals](01-primer.md#primer-cli)* `#[tokio::main]` turns `async fn main` into a real `main` that builds a runtime, which `SyncHandle::start` requires. The *binary* installs the log subscriber; the library only emits events.
- *[Ownership & moves](01-primer.md#primer-ownership)* `last_status.as_ref() != Some(&s)` compares without moving, then `s.clone()` keeps a copy, because `s` is still needed below.
- *[Ownership & moves](01-primer.md#primer-ownership)* `handle.stop().await` *moves* the handle inside a `loop`. Normally that fails with "value moved here, in previous iteration of loop". It compiles because `std::process::exit` returns the never type `!`, so no later iteration can reach the moved handle.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The header (lines 9–14) says SYNCED means "finalized within a couple of epochs of wall clock"; the gate is 5 epochs (`SYNCED_SLOT_SLACK_EPOCHS`). It also says the sync "staggers disjoint sub-ranges across the fan-out", but `catch_up`'s own doc records that the disjoint-range experiment was dropped: the prefix period is asked redundantly and only look-ahead periods are spread.

<a id="f-myotis-net-examples-probe-updates-rs"></a>

### myotis-net/examples/probe\_updates.rs

*example binary · 84 lines*

A diagnostic: start a bare libp2p host with the same pre-bootstrap Status, and ask each pinned mainnet peer in turn for `updates_by_range(checkpoint period, 16)`, logging wire bytes, chunk count, chunk sizes and timing. It has no sync loop and no discovery. It still hard-codes `8192` slots per period instead of calling `slots_per_period()` (correct on mainnet, the only network it uses), and the old batch size of 16 where the loop now asks up to 128.

`rust/myotis-net/examples/probe_updates.rs` · lines 58–81

```rust
let Some(peer) = peer else { continue };
let t0 = Instant::now();
match tokio::time::timeout(
    Duration::from_secs(60),
    client.request_raw(peer, addr, protocols::UPDATES_BY_RANGE, wire.clone()),
)
.await
{
    Ok(Ok(raw)) => {
        let elapsed = t0.elapsed();
        match codec::decode_multi_chunk_response(&raw, span as usize) {
            Ok(chunks) => {
                let sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
                tracing::info!(peer = %peer, wire_bytes = raw.len(),
                    chunks = chunks.len(), ?sizes, ms = elapsed.as_millis() as u64,
                    "response");
            }
            Err(e) => tracing::warn!(peer = %peer, wire_bytes = raw.len(),
                ms = elapsed.as_millis() as u64, error = %e, "undecodable"),
        }
    }
    Ok(Err(e)) => tracing::warn!(peer = %peer, error = %e, "request failed"),
    Err(_) => tracing::warn!(peer = %peer, "timed out (60s)"),
}
```

*[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* Calling the `async fn request_raw` only *creates* a future. The single `.await` on `timeout(…)` drives both. If 60 s pass first, the inner future is dropped. The result is nested (`Result<Result<Vec<u8>, RequestError>, Elapsed>`), hence the three arms `Ok(Ok(raw))`, `Ok(Err(e))` and `Err(_)`. `let Some(peer) = peer else { continue };` skips pins without a `/p2p/` id.

<a id="f-myotis-net-examples-lc-crawl-rs"></a>

### myotis-net/examples/lc\_crawl.rs

*example binary · 270 lines*

A one-shot census of light-client *finality* servers. It crawls the discv5 DHT for 420 s (`CRAWL_SECS`), probes every fork-matched peer (pinned first) with a finality request, at most 24 (`PROBES`) at a time, and prints a verdict histogram plus each server's finalized-slot age and round-trip time. `NET` defaults to sepolia. Answers are now decoded in the right wire format for Gloas through `lc_fork_of_chunk`.

`rust/myotis-net/examples/lc_crawl.rs` · lines 118–145

```rust
// finality_update carries NO request content — send truly empty wire
// bytes, exactly like the production poll (sync.rs poll_finality). An
// encode_request(&[]) would prepend a stray length byte that strict
// servers reject, skewing the census toward responded-undecodable.
let finality_wire: Vec<u8> = Vec::new();

let mut results: Vec<(String, String, Verdict, f64)> = Vec::new();
let spawn_probe = |peer_id: libp2p::PeerId,
                       addr: libp2p::Multiaddr,
                       seen: &mut HashSet<String>,
                       spawned: &mut usize| {
    let key = peer_id.to_string();
    if !seen.insert(key) {
        return;
    }
    *spawned += 1;
    let client = client.clone();
    let sem = Arc::clone(&sem);
    let res_tx = res_tx.clone();
    let wire = finality_wire.clone();
    let config = config.clone();
    tokio::spawn(async move {
        let _permit = sem.acquire_owned().await.expect("semaphore");
        let started = Instant::now();
        let res = tokio::time::timeout(
            Duration::from_secs(25),
            client.request_raw(peer_id, addr.clone(), protocols::FINALITY_UPDATE, wire),
        )
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `sem.acquire_owned()` on an `Arc<Semaphore>` returns a permit that borrows nothing, so it can live inside a spawned task. `let _permit = …` keeps it until the task ends. `let _ = …` would drop it immediately and limit nothing.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* One clone per spawned task (client, semaphore, result sender, wire, config), moved in by `async move`: a `'static` task cannot borrow what the closure captured. Each task sends on its own `res_tx` clone into a single receiver.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `seen` and `spawned` are closure *parameters*, not captures, so the loop can still read them later. `seen.insert(key)` moves the `String` into the set and returns `false` for duplicates.
- *[Protocol & domain](01-primer.md#primer-domain)* Finality requests carry an *empty* body. `encode_request(&[])` would add a stray length byte that strict servers reject.

*[async/await & tokio](01-primer.md#primer-async)* In the crawl loop below the excerpt, the `select!` arm `Some(r) = res_rx.recv()` uses a pattern: if `recv()` yields `None`, that arm is disabled for the rest of that `select!` call instead of matching.

<a id="f-myotis-net-examples-period-census-rs"></a>

### myotis-net/examples/period\_census.rs

*example binary · 649 lines*

An operator tool: does anyone serve a plausible update for period N? Every peer gets `updates_by_range(PERIOD, 1)`. Each answer is read the way the catch-up reads it, up to but not including BLS: error answers are filed by result code, an update attested outside the period is `wrong-period`, one whose headers are in the wrong fork's shape is `wrong-fork-shape`, and the rest are compared with the 2/3 participation bar (342 of 512). Answers are also grouped by the client name Identify reported, which separates "one release refuses this fork" from "a few sick nodes". Pinned peers are asked first, one at a time, with a retry after 11 s. CLAUDE.md's release step 3a and `tests/live_pins_alive.rs` point here for a re-census. Grew from 422 to 649 lines since September, mostly for Sepolia's Gloas fork.

`rust/myotis-net/examples/period_census.rs` · lines 120–136

```rust
/// The histogram bucket a verdict lands in; `need` is the 2/3 participation bar.
fn bucket(verdict: &Verdict, need: u64) -> &'static str {
    match verdict {
        Verdict::Serves(bits, _) if *bits >= need => "claims-supermajority",
        Verdict::Serves(..) => "below-2/3-bar",
        Verdict::WrongPeriod(_) => "wrong-period",
        Verdict::WrongShape(_) => "wrong-fork-shape",
        Verdict::Error(code, _) => error_bucket(*code),
        Verdict::Empty => "answered-empty",
        Verdict::Undecodable => "undecodable",
        Verdict::Unsupported => "no-updates-protocol",
        Verdict::DialFail => "dial-fail",
        Verdict::Timeout => "timeout",
        Verdict::ConnectionClosed => "conn-closed",
        Verdict::Io => "io-error",
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* An exhaustive `match` on `&Verdict`, like Kotlin's `when` on a sealed class. Match ergonomics bind `bits` as `&u64`, hence `*bits`. The guarded arm must come first, since arms are tried in order. `Serves(..)` ignores all fields. Returning `&'static str` works because the literals live for the whole program; `error_bucket(*code)` returns one too.

`rust/myotis-net/examples/period_census.rs` · lines 404–429

```rust
let mut ask = probe(&config, &client, period, peer_id, addr.clone(), finality_wire.clone())
    .await;
let mut agent = None;
if ask.0 != Verdict::DialFail {
    agent = identify(&client, peer_id).await;
}
if matches!(ask.0, Verdict::Serves(..)) {
    println!("  pin {addr}: {}", describe(&ask.0, need, spp));
} else {
    tokio::time::sleep(PIN_RETRY_BACKOFF).await;
    let retry =
        probe(&config, &client, period, peer_id, addr.clone(), finality_wire.clone())
            .await;
    let first = std::mem::replace(&mut ask, retry);
    if ask.0 != Verdict::DialFail && agent.is_none() {
        agent = identify(&client, peer_id).await;
    }
    println!(
        "  pin {addr}: {}, then {}",
        describe(&first.0, need, spp),
        describe(&ask.0, need, spp)
    );
    pin_first_asks.insert(key.clone(), first.0);
}
let (verdict, secs) = ask;
results.push(Probed { peer: key, addr: addr.to_string(), verdict, secs, identify: agent });
```

*[Ownership & moves](01-primer.md#primer-ownership)* `std::mem::replace(&mut ask, retry)` stores the retry result and hands back the old value in one step. With a plain local, `let first = ask; ask = retry;` would work too. `mem::replace` is *required* when all you hold is a `&mut`, because you cannot move a value out through a reference without putting something back. `let (verdict, secs) = ask;` then destructures the tuple and moves both parts into the `Probed` record.

`rust/myotis-net/examples/period_census.rs` · lines 447–457

```rust
tokio::spawn(async move {
    let permit = sem.acquire_owned().await.expect("semaphore");
    let (verdict, secs) =
        probe(&config, &client, period, peer_id, addr.clone(), wire).await;
    // The probe slot is free again; Identify only needs the swarm.
    drop(permit);
    let agent = if verdict == Verdict::DialFail {
        None
    } else {
        identify(&client, peer_id).await
    };
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Ownership & moves](01-primer.md#primer-ownership)* Compare with `lc_crawl`'s `let _permit`. Here the permit is named `permit` and released early with `drop(permit)`, because the Identify poll that follows needs only the swarm, not a probe slot. `drop` is an ordinary function that takes ownership and lets the value go out of scope. Line 316 shows a related rule: in `match std::env::var("NET").unwrap_or_default().trim() { … }` the temporary `String` lives until the end of the `match`, so borrowing it with `trim()` is fine.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The header (lines 43–46) still says reqresp "keys its outbound bookkeeping by request id alone", which is why pins are probed one at a time and why the crawl's negative buckets should be read with care. `reqresp.rs` now keys pending requests by `(protocol, id)` (its lines 1364–1372), so that caveat no longer applies; sequential pin probing still gives each pin a clean line. Also, the variable `finality_wire` (line 382) holds an `updates_by_range` request; the name was copied from `lc_crawl`.

<a id="f-myotis-net-examples-enr-lookup-rs"></a>

### myotis-net/examples/enr\_lookup.rs

*example binary · 117 lines*

A `roost` operator tool that checks inbound UDP. A node only gets into third-party routing tables after those nodes complete an inbound endpoint proof, so if other nodes return the target's ENR, inbound UDP works. It seeds the chain's bootstrap ENRs (skipping the target itself, since a self-answer proves nothing), runs 5 `find_node` rounds 10 s apart, and prints `FOUND` (exit 0). On failure it runs a direct FINDNODE against the target's advertised endpoint as a diagnostic, deliberately last so it cannot affect the verdict, then prints `NOT FOUND` (exit 1). The only change since September is the `chiado` option.

`rust/myotis-net/examples/enr_lookup.rs` · lines 18–30

```rust
#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (net, target) = match (args.next(), args.next()) {
        (Some(n), Some(t)) => (n, t),
        _ => {
            eprintln!("usage: enr_lookup <mainnet|sepolia|gnosis|chiado> <target-enr>");
            std::process::exit(2);
        }
    };
    let target_enr: Enr<CombinedKey> = target.parse().expect("target is not a valid ENR");
    let target_id: NodeId = target_enr.node_id();
    let published_seq = target_enr.seq();
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Binaries, CLIs & signals](01-primer.md#primer-cli) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* A `match` on a tuple of two `Option<String>`s, where `n` and `t` take ownership of the strings. The fallback arm ends in `exit(2)`, whose type `!` fits any type. `Enr<CombinedKey>` is a generic type, and `target.parse()` infers what to parse into from the annotation. The verdict goes to stdout (`println!`) and progress to stderr (`eprintln!`).

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-sync-q1"></a>

**Q1** · Multiple choice

The host calls “accept stale anchor” *after* `run_sync` received its own clone of `ChainConfig`. How does the parked loop notice?

- **A.** It does not; the loop must be restarted
- **B.** Through `LocalStatus`
- **C.** `ws_policy` is an `Arc<WsPolicy>`; cloning the config only copied the pointer, so both copies share the same `AtomicBool`, which the loop re-reads every second
- **D.** The host sends a message on the watch channel

[Answer →](answers.md#a-sync-q1)

<a id="q-sync-q2"></a>

**Q2** · Written answer

Bootstrap, catch-up and finality polling all fire many network requests concurrently, yet `PeerPool` and `LightClientProcessor` are plain structs without any `Mutex`. Explain why this is safe.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sync-q2)

<a id="q-sync-q3"></a>

**Q3** · Multiple choice

`catch_up` declares `in_flight: FuturesUnordered<BoxFuture<'static, Answer>>` and pushes `Box::pin(async move { … })` blocks that each own a `client.clone()`, the peer and the wire bytes. What does the `'static` bound force, and why?

- **A.** Each future must live for the whole program
- **B.** Each future may not borrow anything from `catch_up`'s stack (such as `pool`); it must own what it uses, because the set outlives any single top-up and the pool is mutated while the requests are in flight
- **C.** The futures must be `Copy`
- **D.** The futures run on separate threads and need `Sync`

[Answer →](answers.md#a-sync-q3)

<a id="q-sync-q4"></a>

**Q4** · Multiple choice

`pub async fn stop(self)` runs `for task in &self.tasks { task.abort(); }` and then `for task in self.tasks { let _ = task.await; }`. Why two different loops?

- **A.** Style only
- **B.** Aborting twice is safer
- **C.** The first only needs to borrow the handles to signal abort; `.await` consumes a `JoinHandle`, so the second must move each handle out of `self`
- **D.** The first loop is for discovery tasks

[Answer →](answers.md#a-sync-q4)

<a id="q-sync-q5"></a>

**Q5** · Multiple choice

What does `DiscoveryGuard` achieve that simply storing the discovery `JoinHandle` in a local would not?

- **A.** Nothing
- **B.** It restarts discovery after a failure
- **C.** It makes discovery faster
- **D.** When `run_sync` is aborted, its locals are dropped and the guard's `Drop` aborts the discovery task immediately, freeing its UDP port. A dropped `JoinHandle` would only detach the task

[Answer →](answers.md#a-sync-q5)

<a id="q-sync-q6"></a>

**Q6** · Multiple choice

What must hold before `try_bootstrap` calls `store.initialize(…)` with a peer's bootstrap?

- **A.** The peer must be pinned
- **B.** The header's `hash_tree_root` must equal the embedded checkpoint root, and `processor.verify_bootstrap` must accept it: shape matching the header's fork, the sync-committee branch, and the execution branch
- **C.** At least two peers must return the same bootstrap
- **D.** The bootstrap must be the fastest reply

[Answer →](answers.md#a-sync-q6)

<a id="q-sync-q7"></a>

**Q7** · Multiple choice

`let fail = |pool: &mut PeerPool, buf: &mut Vec<String>, id: PeerId| { … }`. Why is the pool a parameter instead of being captured by the closure?

- **A.** A captured `&mut pool` would stay borrowed for the closure's whole lifetime, blocking later uses like `pool.mark_proven(peer)`; passing it per call keeps each borrow short
- **B.** Closures cannot capture mutable references
- **C.** Parameters are faster
- **D.** To make the closure `Send`

[Answer →](answers.md#a-sync-q7)

<a id="q-sync-q8"></a>

**Q8** · Written answer

Explain the weak-subjectivity (STALE\_ANCHOR) gate: what attack does it prevent, where in `run_sync` does it run, and how is it released?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sync-q8)

<a id="q-sync-q9"></a>

**Q9** · Written answer

In `run_sync`, the entry gate reads the snapshot with `persisted_snap.as_ref().map(|s| s.current_sync_committee_period)`, and a few lines later the code says `if let Some(snap) = persisted_snap { … processor.store.restore(snap); }`. Explain what each form does with ownership, and why the gate must use the first.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sync-q9)

<a id="q-sync-q10"></a>

**Q10** · Multiple choice

In `ClForkWatch::update`, the lock is taken inside an inner block `let current = { let Ok(mut inner) = self.inner.lock() else { return; }; … current };` and the `tracing::warn!` calls come after that block. What does that structure achieve?

- **A.** It makes the log messages appear in order
- **B.** The `MutexGuard` is dropped at the block's closing brace, so logging happens after the lock is released and other observers do not wait on the log sink
- **C.** It is required because `tracing` macros cannot be called while a lock is held
- **D.** It avoids a poisoned lock by unlocking twice

[Answer →](answers.md#a-sync-q10)

<a id="q-sync-q11"></a>

**Q11** · Written answer

Describe what `cl_fork_watch.rs` does and how it connects to `sync.rs`: who creates and owns the watch, who feeds it with what, who reads it, and what it can and cannot affect.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sync-q11)

<a id="q-sync-q12"></a>

**Q12** · Multiple choice

In `poll_finality`, a response comes back `FinalityOutcome::Stale`: it verified against the held committee but did not advance the store. What does the round do with it?

- **A.** Treats it as the round's winner and breaks
- **B.** Strikes the peer in the shared cache
- **C.** Sets `verified = true` and keeps reading: it is not a win (so `advanced` stays false and a hunt may still run) and not a strike, and it spares the round's losers from cache strikes
- **D.** Evicts the peer from the pool

[Answer →](answers.md#a-sync-q12)

<a id="q-sync-q13"></a>

**Q13** · Written answer

`lc_crawl` writes `let _permit = sem.acquire_owned().await…;` while `period_census` writes `let permit = …;` and later `drop(permit);`. Explain what each does, why `let _ = sem.acquire_owned().await…` would be a bug, and why `acquire_owned` rather than `acquire`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sync-q13)

<a id="q-sync-q14"></a>

**Q14** · Written answer

In `catch_up`'s quota wait, the code runs `tokio::join!(tokio::time::sleep(wait), tokio::time::timeout(probe_budget, hunt_round(config, client, pool, processor, clcache, …)))`. Explain how the two futures run, why the borrow checker accepts `hunt_round` borrowing `pool` mutably here, and what happens to the hunt when the budget runs out.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-sync-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
