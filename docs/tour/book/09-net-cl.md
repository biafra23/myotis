# myotis-net, part 1: libp2p, req/resp and discovery

*Stop 9 · crate `myotis-net`* · 5 files · 5,586 lines · about 150 minutes

From here on, everything is `async`. This stop covers the consensus-layer side of the crate that does all of Myotis's I/O: the libp2p host that speaks the eth2 req/resp protocols, discv5 discovery, the on-disk peer cache shared with the Java engine, and the new byte counters. The central idea is an **actor**: one tokio task owns all network state, and everyone else talks to it through channels. The byte-level framing (varints, snappy, Status SSZ, protocol IDs) moved to `myotis-wire`; it is covered in [stop 5](05-wire.md).

## Rust you will practise

- **Channels as an API** `mpsc` commands with a `oneshot` reply inside, and a cheap-to-clone client handle.
- **A task that owns its state** `tokio::spawn`, `select!`, cancellation by drop, and why the actor's maps need no locks while two shared sets do.
- **Wrapping a poll-based trait** `Pin<&mut Self>`, `Unpin`, `Weak` references and a `Drop` that unregisters, in the traffic counters.

## The crate: what myotis-net is for

`myotis-net` is the I/O crate of the workspace. Everything that touches a socket, a clock, the file system or the tokio runtime lives here, and the verification crates below it stay "sans-I/O": they take bytes and slot numbers and return verdicts. This stop and the six after it all read this one crate. It has two halves. The **consensus layer** (CL), in the crate root, finds beacon nodes over discv5, talks to them over libp2p and runs the light-client sync loop ([stop 10](10-net-sync.md)). The **execution layer** (EL), under `src/el/`, speaks devp2p to execution clients (stops 11 to 14).

The manifest makes the layering explicit. Path dependencies point one way only: down to the sans-I/O crates.

`rust/myotis-net/Cargo.toml` · lines 9–22

```toml
[dependencies]
# The sans-I/O verification core this crate drives. The dependency is strictly
# one-way: myotis-consensus must never grow a dependency on this crate (or on
# tokio/libp2p/discv5 through any other path) — that's the wasm32 canary's job
# to enforce (root build.gradle.kts `cargoCheckWasm`).
myotis-consensus = { path = "../myotis-consensus" }
# EL primitives (keccak, RLP, NodeKey, ENR) — sans-I/O, same one-way rule.
myotis-core = { path = "../myotis-core" }
# The tokio-free wire protocols (discv4 codec, RLPx, eth/snap messages), split
# out for hosts without an async runtime (myotis#505); re-exported at the old paths.
myotis-wire = { path = "../myotis-wire" }
# The EVM (revm-backed) for eth_call over verified state — the I/O crate implements
# myotis-evm's sync SnapStateOracle trait and bridges it to the async snap fetch path.
myotis-evm = { path = "../myotis-evm" }
```

Then come the external dependencies, pinned with `=`. A plain `"0.56.0"` in Cargo means "0.56.0 or any semver-compatible later version"; `"=0.56.0"` means exactly that version. The lockfile pins anyway; the `=` documents that interop with live peers depends on the exact wire behaviour of these releases.

`rust/myotis-net/Cargo.toml` · lines 24–33

```toml
# Exact pins: this crate owns the I/O surface and interop with live CL peers
# depends on wire-level behavior of these exact versions (noise/yamux framing,
# discv5 packet format). Cargo.lock would pin them anyway; the `=` makes the
# intent explicit and survives lockfile regeneration.
tokio = { version = "=1.52.3", features = ["rt-multi-thread", "macros", "time", "sync", "signal", "net", "io-util"] }
# `quic`: the consensus p2p spec's PRIMARY transport (QUIC MUST be supported;
# TCP is the fallback, consensus-specs#5330). QUIC carries its own TLS 1.3
# handshake and stream multiplexing, so neither noise nor a muxer is negotiated
# on it — see `reqresp::build_swarm`.
libp2p = { version = "=0.56.0", features = ["tokio", "tcp", "quic", "dns", "noise", "yamux", "identify", "request-response", "gossipsub", "secp256k1", "macros"] }
```

The rest of the list, in short: `libp2p-mplex` (the second TCP stream multiplexer, more below), `discv5` (sigp's discovery), `alloy-rlp` and `hickory-resolver` (both used by the EL discovery code), `snap`, `tracing`, `futures`, `async-trait`, and `socket2` plus `getrandom` for the EL's UDP socket.

The crate has two features:

`rust/myotis-net/Cargo.toml` · lines 92–97

```toml
[features]
tor = ["dep:arti-client", "dep:tor-rtcompat", "dep:rustls"]
# The EVM fixture recorder's seam (`ElReader::head_evm_oracle`) and
# myotis-evm's recorded-world files, for examples/record_shield_fixture.rs.
# Test tooling: on only through this crate's own dev-dependency below.
fixture-recorder = ["myotis-evm/fixture"]
```

- **`tor`** is off by default. It turns on three optional dependencies (`dep:arti-client` and friends), and the manifest picks Arti's TLS backend per target with two `[target.'cfg(…)'.dependencies]` tables: native-tls off Android, rustls on Android, where the NDK has no OpenSSL. Every `#[cfg(feature = "tor")]` in the crate sits under `src/el/`. None of the five files in this stop changes with it.
- **`fixture-recorder`** is test tooling. It is switched on by a small Cargo trick: the crate lists *itself* as a dev-dependency with the feature on, so tests and examples see it while the shipped library never does.

`rust/myotis-net/Cargo.toml` · lines 103–106

```toml
# Tests and examples build this crate with `fixture-recorder`, so the fixture
# recorder example compiles in every `cargo test`/clippy run while the engine
# library and the shipped .so never carry its seam.
myotis-net = { path = ".", features = ["fixture-recorder"] }
```

> [!NOTE]
> **JVM lens**<br>
>
> A Cargo feature is closer to a Gradle source set switched by a build flag than to a runtime flag. Code under `#[cfg(feature = "tor")]` does not exist in a build without it: no class to load, no dead branch, no dependency on the classpath.

<a id="f-myotis-net-src-lib-rs"></a>

### myotis-net/src/lib.rs

*crate root · 45 lines*

The crate root and its rules: all consensus-layer I/O lives here, the dependency on `myotis_consensus` runs one way only, every clock read happens in this crate, and logging goes through `tracing`. Below the doc comment are four narrow libp2p re-exports, the module list, and a re-export of the sync loop's public types. `traffic` is new since September, as is `cl_fork_watch`, the consensus-layer fork detector that this stop's files feed (it is read with the sync loop).

`rust/myotis-net/src/lib.rs` · lines 24–45

```rust
// Re-exported so downstream crates (rust/roost) can build a `HostConfig`
// without pinning their own libp2p version — the types in that config are
// libp2p's, so version skew would be a confusing type error. Narrowed to the
// items a downstream actually needs — building a `HostConfig` (`identity`,
// `Multiaddr`) and handling what `start_host_with` returns (`PeerId`), plus
// `multiaddr` for constructing an address from its protocols. Deliberately not
// `pub use libp2p;`, which would put the whole crate in this one's public
// surface.
pub use libp2p::{identity, multiaddr, Multiaddr, PeerId};

pub mod cl_fork_watch;
pub mod clcache;
pub mod codec;
pub mod discovery;
pub mod el;
pub mod protocols;
pub mod reqresp;
pub mod status;
pub mod sync;
pub mod traffic;

pub use sync::{ChainConfig, SyncHandle, SyncState, SyncStatus};
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* Why re-export four libp2p items instead of the whole crate? `roost` needs exactly these to build a `HostConfig`. If it took them from its own libp2p dependency, a version mismatch would make them *different types*, because two versions of a crate never share types. The narrow list keeps the rest of libp2p out of this crate's public API. `pub mod codec;`, `protocols` and `status` are now four-line shims, each a single `pub use myotis_wire::eth2::…::*;`, so older `crate::codec::…` paths keep compiling. The real code is in [stop 5](05-wire.md).

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc (lines 1–22) is out of date in three ways. Its module list omits `cl_fork_watch`, `clcache`, `el` and `traffic`, and it still lists `codec`, `protocols` and `status` as if their code lived here. It describes `reqresp` as "TCP + noise + yamux", but the host now also speaks mplex and QUIC. And "no global mutable state" (line 21) is no longer true: `traffic.rs` has a `static DISCV5: Mutex<…>`, and `el::tor`, `el::dnsdisco` and `el::request` have `static` switches and semaphores. The `ReqRespClient` doc in `reqresp.rs` repeats the claim ("no globals anywhere in this crate").

<a id="f-myotis-net-src-reqresp-rs"></a>

### myotis-net/src/reqresp.rs

*library · 3,506 lines · Java twin · BeaconP2PService (behaviour, not structure)*

The libp2p host. It runs TCP (with Noise and either yamux or mplex) and QUIC side by side, with a secp256k1 identity, Identify, a gossipsub with *no* subscriptions, and one `request_response` behaviour per eth2 protocol. A single tokio task, the **swarm task**, owns all network state. Callers hold a cloneable `ReqRespClient` that sends commands over a channel and awaits one-shot replies. For outbound requests the host only moves raw bytes; `sync.rs` parses them. For inbound requests it answers status, ping, metadata, goodbye and three "by root" protocols itself, and delegates light-client requests to an optional `LcResponder`, which is how `roost` reuses this host as a server.

| Lines | What happens |
|---|---|
| 1–109 | Module doc, imports, timeouts (10 s, 60 s for updates), quiet windows, size caps, the in-flight response budget. |
| 111–279 | Stream codec: `Eth2Protocol`, `Eth2Codec`, `read_capped`, `drain_capped`, `read_until_quiet`, the `#[async_trait]` `Codec` impl. |
| 281–418 | `#[derive(NetworkBehaviour)] Behaviour` (16 sub-behaviours, 13 of them request/response) and its constructor: connection limits, Identify agent string, anonymous gossipsub, which protocols are advertised in which direction. |
| 420–490 | `RequestError` and `Command`, the swarm task's inbox messages. |
| 492–567 | Two sets shared outside the task: `AgentMap` (Identify agent per peer, for `client=` log labels) and `TcpFirst` (peers dialled at TCP before QUIC), with `dial_order`, `is_quic`, `is_nimbus_agent`. |
| 569–829 | `ReqRespClient`: `request_raw_at` (the address walk and the one retry), `request_in_order`, `request_raw_once`, the small query commands; `CatchupPeerMeta`; `LocalStatus`. |
| 831–1095 | External-address types and quorum, `is_routable`, multiaddr helpers, `resolve_dial_addrs` (DNS in the client, not the swarm), `Observation`. |
| 1097–1162 | The `LcResponder` trait and `HostConfig` (now with `listen_quic`, `cl_fork_watch`, `traffic`). |
| 1164–1343 | `start_host`, `build_swarm` (the hand-built TCP+QUIC transport with byte counting; a DNS and a no-DNS variant), `start_host_with`, which spawns the task. |
| 1345–1459 | Task state: `Pending`, `QueuedRequest`, `SwarmCtx`. |
| 1461–1535 | `run_swarm`: the `select!` event loop. |
| 1537–1648 | Dispatch: `submit_request`, `behaviour_for`, `send_tracked`, `fail_queued`, `mark_status_done`. |
| 1650–1831 | Connection lifecycle (auto-Status on connect, clean-up on close, the "dropped without goodbye" line), Identify handling including the Nimbus rule. |
| 1833–2056 | `on_rr_event` (inbound budget, outbound failures), `demote_stalled_quic`, `complete` (reply delivery and the auto-Status state machine), peer-Status logging. |
| 2058–2265 | `respond_inbound` (the responder), the external-address tally, budget release. |
| 2267–3506 | Tests: address quorum; the `/meshsub/` regression; mplex, yamux and QUIC reachability; zero-chunk answers; QUIC-to-TCP fall-through; DNS handling; TCP-first and Nimbus rules; request-id collisions; a late auto-Status failure. |

![Request round trip. On the caller's side, request_raw_at walks the peer's addresses one at a time and resolves DNS names. Each attempt sends Command::Request carrying a oneshot sender over the mpsc channel to the swarm task. If the peer has no completed Status exchange, the task parks the request and dials. The task sends an automatic Status request; the peer answers; the parked request is released. The task sends the request on the protocol's behaviour and stores the reply sender under the protocol and request id. The peer's response chunks arrive and complete() removes the sender and sends the bytes back through the oneshot to the waiting caller.](img/09-net-cl-1.svg)

*One owner for all network state. The caller never touches the `Swarm`; it hands over a `oneshot::Sender` and awaits the matching receiver. If the swarm task dies, every sender it held is dropped, and each waiting caller sees `RequestError::Shutdown` instead of hanging. The address walk (QUIC first, TCP on a dial failure) runs on the caller's side, one `Command::Request` per attempt.*

#### The caller's side

`rust/myotis-net/src/reqresp.rs` · lines 705–727

```rust
async fn request_raw_once(
    &self,
    peer: PeerId,
    addr: Multiaddr,
    protocol: &'static str,
    wire: Vec<u8>,
) -> Result<Vec<u8>, RequestError> {
    // Resolve HERE, per request, in async context. The swarm task's dial
    // path is synchronous, so it cannot await a lookup — and libp2p's own
    // DNS transport is not always present (Android has no /etc/resolv.conf,
    // so `build_swarm` falls back to plain TCP and a /dns4/ address is
    // rejected outright with "Multiaddr is not supported").
    let dns_name = multiaddr_dns_name(&addr);
    // Never empty: a resolver failure yields the original address, so an
    // already-connected peer is unaffected by a transient DNS blip.
    let addrs = resolve_dial_addrs(&addr, &self.last_resolved).await;
    let (reply, rx) = oneshot::channel();
    self.tx
        .send(Command::Request { peer, dns_name, addrs, protocol, wire, reply })
        .await
        .map_err(|_| RequestError::Shutdown)?;
    rx.await.map_err(|_| RequestError::Shutdown)?
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `#[derive(Clone)] ReqRespClient` is cheap to clone: an `mpsc::Sender` (itself a handle) plus three `Arc`s (the agent map, the TCP-first set and a DNS memo). Every clone talks to the same task.
- *[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* `let (reply, rx) = oneshot::channel();` then `reply` is *moved* into the command, so the task now owns the right to answer. `self.tx.send(…).await` suspends while the 256-slot inbox is full, like `BlockingQueue.put` but without blocking a thread.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `rx.await` yields `Result<Result<Vec<u8>, RequestError>, RecvError>`. `.map_err(|_| RequestError::Shutdown)?` unwraps the outer layer, and the inner `Result` is the function's return value as it is.
- *[async/await & tokio](01-primer.md#primer-async) · [Interior mutability](01-primer.md#primer-interior-mutability)* DNS is resolved here, in async context, because the swarm task's dial path is synchronous and Android lacks `/etc/resolv.conf`. Inside `resolve_dial_addrs` the memo is a `std` mutex that is only locked *after* `lookup_host(…).await` has returned. A `std` guard is not `Send`, so holding one across an `.await` would make this future unusable in `tokio::spawn`.

#### The address walk: QUIC first, TCP as the fallback

The consensus p2p spec now makes QUIC the primary transport and TCP the fallback, so a discovered peer can come with two addresses (`sync::Peer::dial_addrs` orders them QUIC first). `request_raw_at` tries them one at a time, and moves on only when the *dial* failed. A request that reached a connection and then failed is the peer's answer.

`rust/myotis-net/src/reqresp.rs` · lines 672–700

```rust
async fn request_in_order(
    &self,
    peer: PeerId,
    mut addrs: Vec<Multiaddr>,
    protocol: &'static str,
    wire: Vec<u8>,
) -> (Result<Vec<u8>, RequestError>, bool) {
    dial_order(&self.tcp_first, &peer, &mut addrs);
    let count = addrs.len();
    let mut quic_dial_failed = false;
    let mut demoted = false;
    for (i, addr) in addrs.into_iter().enumerate() {
        let is_last = i + 1 == count;
        let quic = is_quic(&addr);
        let outcome = self.request_raw_once(peer, addr, protocol, wire.clone()).await;
        let dial_failed = outcome == Err(RequestError::DialFailure);
        if quic_dial_failed && !quic && !dial_failed && prefer_tcp(&self.tcp_first, peer) {
            demoted = true;
            tracing::debug!(peer = %peer,
                "QUIC dial failed where TCP reached the peer — dialing it at TCP first from now on");
        }
        if dial_failed && !is_last {
            quic_dial_failed |= quic;
            continue;
        }
        return (outcome, demoted);
    }
    (Err(RequestError::DialFailure), demoted)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `addrs.into_iter()` consumes the `Vec`: each `addr` is moved into `request_raw_once`, so no address is copied. `wire` is needed by every attempt, so each call gets `wire.clone()` and the original stays here. The `mut addrs` parameter means "I own this vector and may reorder it", which `dial_order` does in place through `&mut addrs`.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `outcome == Err(RequestError::DialFailure)` compares a whole `Result`. That works because `RequestError` derives `PartialEq`, and `Result<T, E>` is `PartialEq` when both `T` and `E` are.
- *[Protocol & domain](01-primer.md#primer-domain)* A peer is put on `TcpFirst` only when QUIC failed *and* TCP then reached it. A blip that fails every dial (no network) does not demote a healthy QUIC peer for good.

`rust/myotis-net/src/reqresp.rs` · lines 536–567

```rust
pub type TcpFirst = Arc<std::sync::RwLock<HashSet<PeerId>>>;

/// Bound on [`TcpFirst`]: the pool holds far fewer peers than this, so the cap
/// only matters to a long-running process that has seen thousands.
const TCP_FIRST_CAP: usize = 4096;

/// Put `peer` on TCP first (see [`TcpFirst`]); `true` when it was not there.
fn prefer_tcp(set: &TcpFirst, peer: PeerId) -> bool {
    let mut set = set.write().unwrap_or_else(|e| e.into_inner());
    set.len() < TCP_FIRST_CAP && set.insert(peer)
}

/// The caller's address order for `peer`, with its TCP addresses moved to the
/// front when it is on [`TcpFirst`]. Stable: the order within each transport
/// (resolver candidates, IPv4 before IPv6) stays the caller's.
fn dial_order(set: &TcpFirst, peer: &PeerId, addrs: &mut [Multiaddr]) {
    if set.read().unwrap_or_else(|e| e.into_inner()).contains(peer) {
        addrs.sort_by_key(is_quic);
    }
}

/// Whether a dial address is QUIC (`/udp/<port>/quic-v1`).
fn is_quic(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    addr.iter().any(|p| matches!(p, Protocol::QuicV1 | Protocol::Quic))
}

/// Whether an Identify agent is Nimbus's (`nimbus-eth2/v…`, or plain `nimbus`
/// from older builds) — the client [`TcpFirst`] keeps on TCP first.
fn is_nimbus_agent(agent: &str) -> bool {
    agent.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("nimbus"))
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `addrs.sort_by_key(is_quic)` passes a *function item* where a closure is expected. The key is a `bool`, and `false < true`, so TCP addresses (key `false`) move to the front. `sort_by_key` is a stable sort, so the order within each transport stays the caller's.
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Result, ? and panics](01-primer.md#primer-error-handling)* `TcpFirst` is an `Arc<std::sync::RwLock<HashSet<PeerId>>>`, shared by the client (which writes on a QUIC dial failure) and the swarm task (which writes on a QUIC timeout or a Nimbus agent). A `std` lock is fine because no critical section awaits. `.unwrap_or_else(|e| e.into_inner())` handles *poisoning*: if a thread panicked while holding the lock, `lock()`/`read()` return `Err(PoisonError)`, and `into_inner()` takes the guard anyway. For a dial-order hint that is the right call; Java has no equivalent because its locks don't track panics.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `agent.get(..6)` returns `Option<&str>`: `None` if the string is shorter than six bytes or byte 6 is not a character boundary. Slicing with `&agent[..6]` would panic in both cases. The agent string is chosen by the remote peer, so it must never be able to panic this host.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* In `prefer_tcp`, `let mut set = set.write()…;` shadows the parameter: the first `set` is the `&TcpFirst`, the new one is the write guard. The guard drops at the closing brace, after the `&&` expression is evaluated.

`rust/myotis-net/src/reqresp.rs` · lines 630–659

```rust
pub async fn request_raw_at(
    &self,
    peer: PeerId,
    addrs: Vec<Multiaddr>,
    protocol: &'static str,
    wire: Vec<u8>,
) -> Result<Vec<u8>, RequestError> {
    // An empty list would work exactly as long as the peer happens to be
    // connected and fail the moment it is not — a contract violation that
    // must not depend on connection state to show itself.
    debug_assert!(!addrs.is_empty(), "request_raw_at needs at least one address");
    let demoted_before = self.is_tcp_first(&peer);
    let (outcome, demoted_here) =
        self.request_in_order(peer, addrs.clone(), protocol, wire.clone()).await;
    match outcome {
        // The swarm put the peer on TCP first while this request was out —
        // a QUIC connection it closed (a request timed out on it, or it
        // turned out to be Nimbus's). This request was lost to that close,
        // not answered: retry it ONCE, now TCP first, rather than charge
        // the peer a failure for a connection this node took down.
        Err(RequestError::Timeout | RequestError::ConnectionClosed)
            if !demoted_before && !demoted_here && self.is_tcp_first(&peer) =>
        {
            tracing::debug!(peer = %peer, protocol,
                "request lost to a QUIC connection this node closed — retrying, TCP first");
            self.request_in_order(peer, addrs, protocol, wire).await.0
        }
        outcome => outcome,
    }
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Clone because you might need it again.** `request_in_order` takes `addrs` and `wire` by value. To be able to retry, the first call gets `addrs.clone()` and `wire.clone()`, and the retry consumes the originals. The match arm `Err(RequestError::Timeout | RequestError::ConnectionClosed) if …` is an or-pattern nested inside `Err`, followed by a guard. The retry happens only when the swarm demoted the peer *while this request was out*: the request was lost to a connection this node closed (see `demote_stalled_quic` below), not refused by the peer.

#### The owner's side

`rust/myotis-net/src/reqresp.rs` · lines 1330–1343

```rust
    let (tx, rx) = mpsc::channel(256);
    let agents: AgentMap = Arc::default();
    let tcp_first: TcpFirst = Arc::default();
    let task = tokio::spawn(run_swarm(
        swarm,
        rx,
        local_status,
        config.lc_responder,
        config.cl_fork_watch,
        agents.clone(),
        tcp_first.clone(),
    ));
    Ok((ReqRespClient { tx, agents, tcp_first, last_resolved: Arc::default() }, peer_id, task))
}
```

`rust/myotis-net/src/reqresp.rs` · lines 1461–1492

```rust
async fn run_swarm(
    mut swarm: Swarm<Behaviour>,
    mut rx: mpsc::Receiver<Command>,
    local_status: Arc<LocalStatus>,
    lc: Option<Arc<dyn LcResponder>>,
    cl_fork_watch: Option<Arc<crate::cl_fork_watch::ClForkWatch>>,
    agents: AgentMap,
    tcp_first: TcpFirst,
) {
    let mut ctx = SwarmCtx::new(local_status, lc, cl_fork_watch, agents, tcp_first);
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None | Some(Command::Shutdown) => {
                    for (_, p) in ctx.pending.drain() {
                        if let Pending::External(reply) = p {
                            let _ = reply.send(Err(RequestError::Shutdown));
                        }
                    }
                    for (_, queue) in ctx.queued.drain() {
                        for q in queue {
                            let _ = q.reply.send(Err(RequestError::Shutdown));
                        }
                    }
                    tracing::info!("libp2p host stopping");
                    return;
                }
                Some(Command::Request { peer, dns_name, addrs, protocol, wire, reply }) => {
                    submit_request(
                        &mut swarm, &mut ctx, peer, dns_name, addrs, protocol, wire, reply,
                    );
                }
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `tokio::spawn(run_swarm(swarm, rx, …))` *moves* the `Swarm` and the receiver into the task. `SwarmCtx`'s plain `HashMap`s need no locks because only this task can reach them. The Java analogue is a Netty `EventLoop` fed from a `BlockingQueue<Command>`. The two exceptions, `agents` and `tcp_first`, are created here as `Arc::default()` and cloned: one copy goes into the task, one into the client.
- *[async/await & tokio](01-primer.md#primer-async)* `tokio::select!` waits for whichever is ready first, the next command or the next swarm event (the `event = swarm.select_next_some()` arm at line 1532, after the remaining command arms), and drops the other future. Both are cancellation-safe, so nothing is lost. Because the futures are dropped before the handler body runs, the handler may take `&mut swarm`. The handlers never `.await`, which keeps the loop responsive.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `ctx.pending.drain()` hands each stored `Pending` back by value. `if let Pending::External(reply) = p` takes the sender out, and `let _ = reply.send(…)` ignores a caller who has already gone away. `rx.recv()` returns `None` once every client clone is dropped, so the task also ends when nobody can reach it.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `enum Pending` works like a sealed interface. An outcome completes either an external caller's oneshot or one of the two automatic Status exchanges.

#### The request-id collision fix

`rust/myotis-net/src/reqresp.rs` · lines 1585–1631

```rust
fn behaviour_for<'a>(swarm: &'a mut Swarm<Behaviour>, protocol: &str) -> Option<&'a mut RR> {
    let behaviour = swarm.behaviour_mut();
    Some(match protocol {
        protocols::STATUS_V2 => &mut behaviour.status_v2,
        protocols::STATUS_V1 => &mut behaviour.status_v1,
        protocols::PING => &mut behaviour.ping,
        protocols::METADATA_V2 => &mut behaviour.metadata,
        protocols::METADATA_V3 => &mut behaviour.metadata_v3,
        protocols::GOODBYE => &mut behaviour.goodbye,
        protocols::BOOTSTRAP => &mut behaviour.bootstrap,
        protocols::UPDATES_BY_RANGE => &mut behaviour.updates,
        protocols::FINALITY_UPDATE => &mut behaviour.finality,
        protocols::OPTIMISTIC_UPDATE => &mut behaviour.optimistic,
        protocols::BLOCKS_BY_ROOT => &mut behaviour.blocks_by_root,
        protocols::DATA_COLUMN_SIDECARS_BY_ROOT => &mut behaviour.data_column_sidecars_by_root,
        protocols::EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT => {
            &mut behaviour.execution_payload_envelopes_by_root
        }
        _ => return None,
    })
}

/// Send `wire` on `protocol`'s behaviour and record what its outcome completes.
///
/// The only place a `pending` entry is created: the protocol that picks the
/// behaviour is the protocol in the key, so a key can never name a behaviour
/// other than the one that issued its id (see `SwarmCtx::pending`).
fn send_tracked(
    swarm: &mut Swarm<Behaviour>,
    ctx: &mut SwarmCtx,
    peer: PeerId,
    protocol: &'static str,
    wire: Vec<u8>,
    addrs: Vec<Multiaddr>,
    on_outcome: Pending,
) {
    let Some(rr) = behaviour_for(swarm, protocol) else {
        // Only an external caller can name a protocol this host lacks; the
        // auto-Status ones are this module's own constants.
        if let Pending::External(reply) = on_outcome {
            let _ = reply.send(Err(RequestError::Io(format!("unknown protocol {protocol}"))));
        }
        return;
    };
    let id = rr.send_request_with_addresses(&peer, wire, addrs);
    ctx.pending.insert((protocol, id), on_outcome);
}
```

> [!WARNING]
> **A real bug, and its fix in the types**<br>
>
> libp2p numbers outbound requests *per behaviour*, starting at 1, and this host has thirteen request/response behaviours. When `pending` was keyed by the id alone, a new peer's auto-Status and a bootstrap request to another peer could share id 1. The second insert evicted the first, so one caller saw "service shut down", and a bootstrap caller could receive *Status bytes*. Keying by `(&'static str, OutboundRequestId)`, with `send_tracked` as the only inserter, makes a mismatched key impossible: the protocol that picks the behaviour is the protocol in the key. The fix landed in `aa123758`; the tests in `pending_request_tests` mint ids the way the behaviours do and assert that they collide. The inbound budget map `in_flight` is keyed the same way for the same reason.

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* `behaviour_for<'a>(swarm: &'a mut Swarm<…>, …) -> Option<&'a mut RR>` returns a mutable borrow *into* the swarm, tied to the input by `'a`. In `send_tracked` that borrow (`rr`) is last used on the `send_request_with_addresses` line, so the next line may use `ctx` freely. `Some(match … { …, _ => return None })` shows `return` inside an expression.
- *[Ownership & moves](01-primer.md#primer-ownership)* `on_outcome` is either moved into the map or consumed on the error path, never copied. A reply sender therefore has exactly one owner at every moment.

`rust/myotis-net/src/reqresp.rs` · lines 1944–2000

```rust
fn complete(
    ctx: &mut SwarmCtx,
    swarm: &mut Swarm<Behaviour>,
    protocol: &'static str,
    request_id: OutboundRequestId,
    peer: PeerId,
    result: Result<Vec<u8>, RequestError>,
) {
    match ctx.pending.remove(&(protocol, request_id)) {
        Some(Pending::External(reply)) => {
            let _ = reply.send(result);
        }
        // Stale: the peer's LAST connection closed before this outcome arrived.
        // libp2p yields `SwarmEvent::ConnectionClosed` first and the request's
        // `OutboundFailure` on a later poll, so the close handler has already
        // reset the peer and failed its parked requests. Settling it now would
        // mark a disconnected peer Status-done, sending its next requests ahead
        // of the next connection's own auto-Status. Nothing can reconnect the
        // peer in between: queued behaviour events drain before the pool is
        // polled again.
        Some(Pending::AutoStatusV2(peer_id) | Pending::AutoStatusV1(peer_id))
            if !ctx.connected.contains(&peer_id) =>
        {
            tracing::debug!(peer = %peer_id, protocol, "auto-status outcome after disconnect — ignored");
        }
        Some(Pending::AutoStatusV2(peer_id)) => match result {
            Ok(raw) => {
                note_peer_status(ctx, "v2", peer_id, &raw);
                mark_status_done(swarm, ctx, peer_id);
            }
            Err(RequestError::UnsupportedProtocol) => {
                // v1-only peer (Nimbus bucket in the Java notes) — fall back.
                let local = ctx.local_status.get();
                let wire = codec::encode_request(&local.encode_v1());
                send_tracked(swarm, ctx, peer_id, protocols::STATUS_V1, wire, Vec::new(),
                    Pending::AutoStatusV1(peer_id));
            }
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "auto-status v2 failed");
                // Settled (failed) — release parked requests rather than
                // starving them; the peer may still serve other protocols.
                mark_status_done(swarm, ctx, peer_id);
            }
        },
        Some(Pending::AutoStatusV1(peer_id)) => {
            match result {
                Ok(raw) => note_peer_status(ctx, "v1", peer_id, &raw),
                Err(e) => tracing::debug!(peer = %peer_id, error = %e, "auto-status v1 failed"),
            }
            mark_status_done(swarm, ctx, peer_id);
        }
        None => {
            tracing::debug!(peer = %peer, protocol, %request_id,
                "outcome for an untracked outbound request — dropped");
        }
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Some(Pending::AutoStatusV2(peer_id) | Pending::AutoStatusV1(peer_id)) if !ctx.connected.contains(&peer_id)` is an **or-pattern that binds the same name in both alternatives**, plus a guard. Arms are tried in order, so this "stale outcome" arm catches both kinds before the specific arms below it. A v1-only peer answers v2 with `UnsupportedProtocol`, and the host falls back to v1. Any other failure still settles the peer, so its parked requests are released rather than starved.

#### A stalled QUIC connection is closed, not just avoided

`rust/myotis-net/src/reqresp.rs` · lines 1925–1942

```rust
fn demote_stalled_quic(
    swarm: &mut Swarm<Behaviour>,
    ctx: &mut SwarmCtx,
    peer: PeerId,
    connection: ConnectionId,
    protocol: &'static str,
) {
    // Removed here, not only on the close event, so the requests still in
    // flight on this connection — whose timeouts may follow in the same
    // poll — do not close it, or log, a second time.
    if !ctx.quic_conns.remove(&connection) {
        return;
    }
    prefer_tcp(&ctx.tcp_first, peer);
    tracing::info!(peer = %peer, client = ?client_label(&ctx.peer_agents, &peer), protocol,
        "request timed out over QUIC — closing that connection; this peer is dialed at TCP first from now on");
    swarm.close_connection(connection);
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* libp2p's request-response hands a request to any established connection to the peer and cannot steer it by transport. So when a request times out on a QUIC connection (the doc comment above the function records the stall measured against Nimbus), the only cure is to close that connection; the next request dials afresh, TCP first. `quic_conns.remove` returns whether the id was there, which makes the function idempotent: other requests timing out on the same connection in the same poll do nothing. The Identify handler applies the same rule up front to any peer whose agent is Nimbus.

#### Reading a response until the peer goes quiet

`rust/myotis-net/src/reqresp.rs` · lines 164–218

```rust
async fn read_until_quiet<T>(
    io: &mut T,
    cap: usize,
    quiet: Duration,
    budget: Option<Duration>,
) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let deadline = budget.map(|b| tokio::time::Instant::now() + b);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        // The quiet window only means anything once bytes are buffered (it
        // detects "peer finished a paced response without closing"). Before the
        // first byte, await the read with NO per-iteration timer — the
        // behaviour-level request timeout is the deadline — instead of respawning
        // a `quiet`-length timer every window while a slow peer spins up.
        let read = if buf.is_empty() {
            io.read(&mut chunk).await.map(Some)
        } else {
            let mut wake_at = tokio::time::Instant::now() + quiet;
            if let Some(d) = deadline {
                wake_at = wake_at.min(d);
            }
            match tokio::time::timeout_at(wake_at, io.read(&mut chunk)).await {
                Ok(r) => r.map(Some),
                // Quiet with data buffered — or total budget spent — → complete.
                Err(_elapsed) => Ok(None),
            }
        };
        match read {
            Ok(Some(0)) => break,
            Ok(Some(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "response exceeds size cap",
                    ));
                }
            }
            Ok(None) => break, // quiet window elapsed with data buffered
            Err(e) => {
                if buf.is_empty() {
                    return Err(e);
                }
                tracing::debug!(buffered = buf.len(), error = %e,
                    "stream errored after data — salvaging buffered response");
                break;
            }
        }
    }
    Ok(buf)
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* `T: AsyncRead + Unpin + Send`: any async byte stream that can be polled through `&mut` (`Unpin`) and moved between threads (`Send`). The whole function compiles to a state machine; its 16 KiB `chunk` buffer lives inside the future, not on a thread stack.
- *[async/await & tokio](01-primer.md#primer-async)* `tokio::time::timeout_at(wake_at, io.read(&mut chunk))`: if the timer wins, the unfinished `read` future is *dropped*, which is cancellation, and no data is lost because a pending read hasn't consumed anything. Before the first byte there is no timer at all. The behaviour-level request timeout (10 s, or 60 s for updates) is the deadline then, which keeps slow, rate-limited servers usable.
- *[Protocol & domain](01-primer.md#primer-domain)* `budget` is set only for `updates_by_range` (55 s, under the 60 s behaviour timeout). When it runs out with data buffered, the read completes with the whole chunks that arrived instead of letting the behaviour timeout discard them and charge the peer a failure.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* An error *after* data arrived keeps the buffered response instead of discarding it. The codec in `myotis-wire` validates it later.

The request side has a newer twin, `drain_capped`. The three "by root" protocols (blocks, data-column sidecars, payload envelopes) are inbound only and always answered with zero chunks, so their request body is never read: `futures::io::copy(io.take(cap + 1), &mut sink())` reads it to EOF and throws it away, up to 256 KiB, without buffering. A light client serves these at all because Nimbus asks every new peer for blocks (and later columns and envelopes) by root, and ends its peer loop, disconnecting, when the protocol cannot be negotiated. The answer is zero chunks rather than `ResourceUnavailable` because, per the comment in `respond_inbound`, Nimbus treats an error chunk as a failed request too (the protocol docs are in [myotis-wire's protocols.rs](05-wire.md#f-myotis-wire-src-eth2-protocols-rs)).

#### The behaviour, gossipsub and the Lighthouse ban

`rust/myotis-net/src/reqresp.rs` · lines 308–344

```rust
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    // Defense-in-depth: this client dials but also accepts inbound, and each
    // protocol behaviour independently permits concurrent streams. Cap total
    // established connections so a peer flood can't exhaust fds/memory.
    pub limits: connection_limits::Behaviour,
    pub identify: identify::Behaviour,
    /// Gossipsub with NO subscriptions. It exists so the `/meshsub/` protocol
    /// negotiates on every connection: Lighthouse (v8.1.3–v8.2.2 verified in
    /// `lighthouse_network/src/service/mod.rs`) reports a peer whose gossipsub
    /// upgrade fails with `PeerAction::Fatal` ("does_not_support_gossipsub"),
    /// which bans the peer id for 12 h after ONE goodbye (reason 0) and bans
    /// the whole IP once more than five of its peer ids are banned. A wallet
    /// therefore got exactly one first-contact connection per Lighthouse
    /// node per start, and the IP ban after a handful of restarts. Negotiating
    /// the protocol is all the check needs; the mesh is never joined.
    pub gossipsub: gossipsub::Behaviour,
    pub status_v2: RR,
    pub status_v1: RR,
    pub ping: RR,
    pub metadata: RR,
    /// Fulu metadata. Post-Fulu peers ask for v3 — Nimbus for nothing else,
    /// and it drops a peer that cannot answer (see `protocols::METADATA_V3`).
    pub metadata_v3: RR,
    pub goodbye: RR,
    pub bootstrap: RR,
    pub updates: RR,
    pub finality: RR,
    pub optimistic: RR,
    /// Inbound only, always answered with zero chunks — see
    /// `protocols::BLOCKS_BY_ROOT` for the Nimbus behaviour this placates.
    pub blocks_by_root: RR,
    /// Likewise — `protocols::DATA_COLUMN_SIDECARS_BY_ROOT`.
    pub data_column_sidecars_by_root: RR,
    /// Likewise — `protocols::EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT`.
    pub execution_payload_envelopes_by_root: RR,
}
```

- *[Macros & attributes](01-primer.md#primer-macros)* `#[derive(NetworkBehaviour)]` generates the combined behaviour impl plus a `BehaviourEvent` enum with one variant per field (`BehaviourEvent::StatusV2`, `…::Gossipsub`, …). `handle_behaviour_event` matches on exactly those variants.
- *[Protocol & domain](01-primer.md#primer-domain)* **The gossipsub with no subscriptions is still there**, and still only so that `/meshsub/` negotiates. Lighthouse reports a peer whose gossipsub upgrade fails as `PeerAction::Fatal`: the peer id is banned for 12 h, and the whole IP once more than five of its peer ids are banned. That was #422. The test `meshsub_negotiates_without_any_subscription` plays Lighthouse (a subscribed swarm) against this host and fails on `GossipsubNotSupported`. If you test from a machine that ran a pre-gossipsub build, the bans can outlive the fix by 12 hours, and a banned host sees healthy nodes as "dial failed" (the repo's `CLAUDE.md` records this caveat for the cold-start checks).
- *[Protocol & domain](01-primer.md#primer-domain)* `metadata_v3` is new: post-Fulu peers ask for v3, and Nimbus drops a peer that cannot answer. `updates` is advertised outbound-only for a wallet (advertising a protocol you cannot serve gets you sent Goodbye) and `Full` for a serving host.

#### TCP with two muxers, QUIC beside it, and every byte counted

`rust/myotis-net/src/reqresp.rs` · lines 1231–1254

```rust
let transport = |key: &libp2p::identity::Keypair| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::upgrade::{SelectUpgrade, Version};
    use libp2p::Transport as _;
    let tcp_meter = Arc::clone(&traffic);
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
        .map(move |stream, _| {
            crate::traffic::CountingStream::new(stream, Arc::clone(&tcp_meter), crate::traffic::cl)
        })
        .upgrade(Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(key)?)
        .multiplex(SelectUpgrade::new(
            libp2p::yamux::Config::default(),
            libp2p_mplex::Config::default(),
        ))
        .map(|(p, c), _| (p, StreamMuxerBox::new(c)));
    let quic_meter = Arc::clone(&traffic);
    let quic = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(key)).map(
        move |(p, c), _| {
            (p, StreamMuxerBox::new(crate::traffic::CountingMuxer::new(c, Arc::clone(&quic_meter))))
        },
    );
    Ok(tcp.or_transport(quic).map(|either, _| either.into_inner()))
};
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Why mplex.** The spec says a TCP client MUST support mplex and MAY support yamux, with yamux preferred where both exist. Nimbus and Lodestar speak only mplex on TCP. A yamux-only host (this one, until recently) completed Noise with every Nimbus node and then died on the muxer proposal, which made Nimbus nodes look dead. `SelectUpgrade::new(yamux, mplex)` offers both, and its argument order is the preference order. The test pair `a_yamux_only_host_cannot_connect_to_an_mplex_only_peer` / `the_host_connects_to_an_mplex_only_peer_like_nimbus` pins both sides.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **A `move` closure that clones on every call.** `.map(move |stream, _| …)` moves `tcp_meter` (an `Arc`) into the closure. The closure runs once per connection, so it cannot give its captured `Arc` away; it calls `Arc::clone(&tcp_meter)` each time, and each `CountingStream` owns one strong reference.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* The TCP stack and the QUIC stack produce different output types. `StreamMuxerBox::new(c)` erases each muxer to one boxed type, and `or_transport` combines the two into a transport that tries TCP or QUIC by address; its output is an `Either`, flattened by `into_inner()`. The return type `Result<_, Box<dyn Error + Send + Sync>>` lets `?` convert the Noise config error. QUIC brings its own TLS 1.3 and its own streams, so neither Noise nor a muxer applies there.

The two `if dns` branches after this closure build the same swarm with and without `.with_dns()`. They are separate chains because each builder step consumes the builder and changes its type, so a failed DNS step cannot hand the builder back. `start_host_with` tries with DNS first and falls back with a warning; Android has no `/etc/resolv.conf`.

#### The responder: synchronous by design

`rust/myotis-net/src/reqresp.rs` · lines 1097–1117

```rust
/// A source of pre-encoded light-client responses.
///
/// This is the seam that lets a SERVER (`rust/roost`) reuse this host verbatim
/// instead of standing up a second libp2p stack — the design's "one protocol
/// stack, not two". The wallet passes `None` and keeps behaving exactly as
/// before: the four light-client protocols fall through to
/// `ResourceUnavailable`.
///
/// Every method returns the **fully encoded response body** (`result byte ||
/// fork digest || varint || snappy frames`), because these are called from
/// [`respond_inbound`], which is **synchronous** and runs inline on the swarm
/// task. There is no await point here: an implementation must be a pure cache
/// read, never an I/O fetch. `None` means miss, and the caller answers
/// `ResourceUnavailable` — correct behaviour, since a wallet simply retries
/// against another peer.
pub trait LcResponder: Send + Sync {
    fn bootstrap(&self, block_root: &[u8; 32]) -> Option<Vec<u8>>;
    fn updates_by_range(&self, start_period: u64, count: u64) -> Option<Vec<u8>>;
    fn finality_update(&self) -> Option<Vec<u8>>;
    fn optimistic_update(&self) -> Option<Vec<u8>>;
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `HostConfig` holds `Option<Arc<dyn LcResponder>>`: a shared, thread-safe trait object, like an injected Java interface. `Send + Sync` as supertraits make every implementation safe to call from the swarm task. The methods are plain `fn`, not `async fn`, because `respond_inbound` runs inline in the event loop; an I/O fetch there would stall every connection. A miss returns `None`, answered as `ResourceUnavailable`.
- *[Protocol & domain](01-primer.md#primer-domain)* Two responder details changed. Ping now answers with *our* metadata sequence number instead of echoing the caller's, so peers re-fetch our real metadata. A Goodbye is answered and then the peer is disconnected, so a public responder does not collect dead connections.
- *[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* A serving host also caps response bytes queued but not yet written at 64 MiB across all connections (`MAX_IN_FLIGHT_RESPONSE_BYTES`). In `on_rr_event`, a response that would overflow is swapped for `ResourceUnavailable`; both terminal events, `ResponseSent` and `InboundFailure`, release the bytes. Missing either would leak budget until the responder refused everything.

#### Shared status

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `LocalStatus` (lines 812–829) is shared between the sync loop (writer) and the swarm task (reader) through an `Arc`, so it needs a `Mutex`. `*self.inner.lock().expect(…) = s;` assigns through the guard, and the guard lives only for that statement. `get` returns a `clone()`, so the caller never holds the lock.

> [!NOTE]
> **JVM lens**<br>
>
> `SwarmCtx` needs no lock and `LocalStatus` does, for the same reason a Java object confined to one Netty event loop needs no synchronisation while a field shared with another thread does. The difference is that Rust *checks* the confinement. Moving the `SwarmCtx` into the task makes it unreachable from anywhere else, and anything the task shares (`LocalStatus`, `AgentMap`, `TcpFirst`) has to be an `Arc` around a lock, or it will not compile.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc (lines 1–15) still lists "TCP + noise XX + yamux or mplex" without QUIC, and says the `light_client_*` protocols answer `ResourceUnavailable`, which is true only without an `LcResponder`. The `RESP_TIMEOUT` doc (line 37) says updates get "the Java catch-up deadline (15 s)", but `UPDATES_TIMEOUT` is 60 s. The `respond_inbound` doc (lines 2058–2060) says "ping/goodbye → echo" and "no relay cache in this stage"; ping now returns our own sequence number, and the light-client branches serve from the responder. Lines 715, 985 and 1301 say the no-DNS fallback is "plain TCP"; it is TCP plus QUIC. Two doc comments are attached to the wrong item: the `start_host_with` doc (lines 1173–1182) sits directly above `build_swarm`'s doc, so rustdoc merges both onto `build_swarm`, and the doc for `external_address` (lines 729–735) is merged into `observe_via`'s, leaving `external_address` undocumented.

<a id="f-myotis-net-src-discovery-rs"></a>

### myotis-net/src/discovery.rs

*library · 1,215 lines · Java twin · DiscV5Service (as wired by ChainStack)*

discv5 discovery for the consensus layer, in two modes. **Client mode** (`spawn`) runs two tasks: a lookup loop (FINDNODE every 15 s, or every 2 s while the sync loop hunts for light-client servers) and a consumer of every ENR heard in NODES responses. Both emit fork-matched dial candidates on an `mpsc` channel, now with a QUIC address where the record has one. **Server mode** (`spawn_server`, `publish`) lets `roost` join the DHT and publish a signed record under a persisted sequence number.

| Lines | What happens |
|---|---|
| 1–26 | Module doc, imports, `RESEED_EMPTY_ROUNDS`. |
| 27–98 | `DiscoveredPeer` (now with `quic`), `AcceptedForkDigests`, `rotate_seen_if_changed`. |
| 99–202 | `DiscoveryConfig` (now with `cl_fork_watch` and `traffic`), `spawn`. |
| 204–241 | `node_id_for_peer`, `seed_bootnodes`. |
| 243–395 | `run_lookups`: pinned targets first, the seq gate for pinned records, fork-watch evidence from the routing table, the empty-table re-seed, the hunt cadence. |
| 397–437 | `reseed`, `reseed_due`. |
| 439–527 | `consume_discovered`, `Heard`, `classify_heard`. |
| 529–637 | `filter_candidate` (TCP and/or QUIC), the `eth2` field readers, `note_enr`, RLP short-string decode, `enr_to_peer_id`. |
| 639–740 | Client tests. |
| 741–971 | Server ENR: `discv5_key_from_libp2p`, `build_server_enr`; tests, including the QUIC-field and QUIC-only record tests. |
| 972–1215 | Server discv5: `ServerDiscovery` + `Drop`, `spawn_server`, maintenance, `publish`, lifecycle test. |

`rust/myotis-net/src/discovery.rs` · lines 54–74

```rust
#[derive(Clone)]
pub enum AcceptedForkDigests {
    Fixed(Vec<[u8; 4]>),
    Dynamic(Arc<dyn Fn() -> Vec<[u8; 4]> + Send + Sync>),
}

impl AcceptedForkDigests {
    /// The list to filter the NEXT candidate with.
    pub fn current(&self) -> Vec<[u8; 4]> {
        match self {
            AcceptedForkDigests::Fixed(v) => v.clone(),
            AcceptedForkDigests::Dynamic(f) => f(),
        }
    }
}

impl From<Vec<[u8; 4]>> for AcceptedForkDigests {
    fn from(v: Vec<[u8; 4]>) -> Self {
        AcceptedForkDigests::Fixed(v)
    }
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `Dynamic(Arc<dyn Fn() -> Vec<[u8; 4]> + Send + Sync>)` is a thread-safe `Supplier` stored in an enum variant. It is re-read for every candidate, so a fork that activates at a future epoch switches the filter without a restart. `Arc` rather than `Box` keeps the enum `Clone`able.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `match self` on `&self` binds `v` and `f` by reference, so `v.clone()` is needed to return an owned `Vec`. `f()` calls through the reference. `impl From<Vec<[u8; 4]>>` lets callers write `vec.into()`.

`rust/myotis-net/src/discovery.rs` · lines 156–201

```rust
let bootnodes = seed_bootnodes(&discv5, &config.bootstrap_enrs);

// Joined before the socket opens so the bootstrap pings are counted;
// held by the lookup task, so it leaves the share when the task ends.
let share = config.traffic.as_ref().map(crate::traffic::Discv5Share::join);
discv5
    .start()
    .await
    .map_err(|e| format!("discv5 start failed: {e}"))?;
// Pinned ids whose discv5 node id is derivable get TARGETED lookups; the
// rest (non-secp256k1 ids, if any ever appear) silently fall back to being
// findable only by the random walk, which is what they were before.
let pinned_targets: Vec<NodeId> = config
    .pinned_peer_ids
    .iter()
    .filter_map(node_id_for_peer)
    .collect();
tracing::info!(
    bootnodes = bootnodes.len(),
    pinned_targets = pinned_targets.len(),
    port = config.listen_port,
    "discv5 started"
);

// Every ENR that comes back in a NODES response during a query, live or
// not — see the consumer in run_lookups for why this, and not the lookup
// results, is where a small network's peers surface.
let events = discv5
    .event_stream()
    .await
    .map_err(|e| format!("discv5 event stream failed: {e}"))?;

let table_size = Arc::new(AtomicUsize::new(0));
let task = tokio::spawn(run_lookups(
    discv5,
    events,
    config.accepted_fork_digests,
    bootnodes,
    pinned_targets,
    Arc::clone(&table_size),
    config.hunt_boost,
    tx,
    config.cl_fork_watch,
    share,
));
Ok((task, table_size))
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* One owner means a move; two owners means an `Arc`. The `Discv5` instance is moved into `run_lookups`, while the routing-table size counter is shared: `Arc::clone(&table_size)` goes to the task and the original is returned to the caller for the UI. `AtomicUsize` is Java's `AtomicLong`; `Relaxed` ordering is fine for a metric.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `config.traffic.as_ref().map(crate::traffic::Discv5Share::join)`: `as_ref()` turns `&Option<Arc<_>>` into `Option<&Arc<_>>`, which is exactly what `join(meter: &Arc<TrafficMeter>)` takes, so the function path can be passed directly. The resulting share is moved into the lookup task as `_traffic_share`: it lives as long as the task, and its `Drop` unregisters the meter when the task ends (see [traffic.rs](#f-myotis-net-src-traffic-rs)).
- *[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* Every start-up step is fallible and mapped to a `String` error. Discovery failing is reported, not panicked, just as the Java engine treats discv5 as non-essential.

`rust/myotis-net/src/discovery.rs` · lines 316–344

```rust
let mut emitted = 0usize;
let digests = accepted_digests.current();
rotate_seen_if_changed(&mut seen.lock().expect("seen lock"), &mut last_digests, &digests);
match discv5.find_node(target).await {
    Ok(enrs) => {
        for enr in enrs {
            if pinned_targets.contains(&enr.node_id()) {
                // Pinned ids bypass the once-ever dedup, but only on a
                // record NEWER than the last one emitted.
                match pinned_seq.get(&enr.node_id()) {
                    Some(&last) if enr.seq() <= last => continue,
                    _ => {
                        pinned_seq.insert(enr.node_id(), enr.seq());
                        seen.lock().expect("seen lock").insert(enr.node_id());
                    }
                }
            } else if !seen.lock().expect("seen lock").insert(enr.node_id()) {
                continue;
            }
            if let Some(peer) = filter_candidate(&enr, &digests) {
                emitted += 1;
                if tx.send(peer).await.is_err() {
                    return; // receiver gone — sync loop shut down
                }
            }
        }
    }
    Err(e) => tracing::debug!(error = %e, "discv5 lookup failed"),
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [async/await & tokio](01-primer.md#primer-async) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Where each guard dies.** Every `seen.lock()` here is a *temporary*. On line 318 the guard lives until the end of the statement; on line 332 it lives until the end of the `if` condition. So no guard is alive at `find_node(target).await` or at `tx.send(peer).await`. If one were, the future would hold a non-`Send` `std::sync::MutexGuard` across an `.await`, and `tokio::spawn(run_lookups(…))` would not compile.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match pinned_seq.get(&id)` borrows the map, yet the `_` arm calls `pinned_seq.insert`. This compiles because `Some(&last)` *copies* the `u64` out of the reference, and the `_` arm uses no reference at all, so the borrow is already over (non-lexical lifetimes).
- *[Protocol & domain](01-primer.md#primer-domain)* A pinned server (roost) is re-emitted only on a strictly newer ENR sequence number. That heals a stale pinned address when roost republishes, and a table serving an *older* record cannot move the pool's address backwards.

`rust/myotis-net/src/discovery.rs` · lines 451–495

```rust
async fn consume_discovered(
    mut events: mpsc::Receiver<Event>,
    accepted_digests: AcceptedForkDigests,
    pinned_targets: Vec<NodeId>,
    seen: Arc<std::sync::Mutex<HashSet<NodeId>>>,
    tx: mpsc::Sender<DiscoveredPeer>,
) {
    let mut last_digests: Vec<[u8; 4]> = accepted_digests.current();
    while let Some(event) = events.recv().await {
        let Event::Discovered(enr) = event else { continue };
        // A full channel drops the node unmarked (see below), so deciding
        // anything about it now — the key decode behind filter_candidate and
        // its debug line — would only be repeated on the next hearing. On
        // mainnet, where nearly every ENR matches, a full channel is the
        // steady state between sync-loop drains.
        if tx.capacity() == 0 {
            continue;
        }
        let id = enr.node_id();
        // One critical section from check to claim: the lookup loop claims
        // its own emissions under the same lock, so neither path can slip a
        // duplicate into the pool channel between the other's check and
        // insert. try_send never blocks, so holding a std mutex across it is
        // fine; nothing awaits while it is held.
        let digests = accepted_digests.current();
        let mut guard = seen.lock().expect("seen lock");
        // Either task may notice the rotation first; clearing twice is harmless.
        rotate_seen_if_changed(&mut guard, &mut last_digests, &digests);
        match classify_heard(&enr, &guard, &pinned_targets, &digests) {
            Heard::Skip => {}
            Heard::NeverCandidate => {
                guard.insert(id);
            }
            Heard::Emit(peer) => match tx.try_send(peer) {
                // Marked seen only once the pool has it: a node dropped on a
                // full channel is heard again later and emitted then.
                Ok(()) => {
                    guard.insert(id);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            },
        }
    }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* `seen: Arc<std::sync::Mutex<HashSet<NodeId>>>` is shared by the two tasks to avoid duplicate emits. The critical section runs from check to `try_send` to insert: Java's `synchronized (seen) { check; offer; add }`. A `std` mutex is fine because nothing inside `.await`s. `try_send` never blocks, and the guard is dropped at the end of the loop body.
- *[async/await & tokio](01-primer.md#primer-async)* `send().await` waits like `put`; `try_send` fails immediately like `offer`. A node dropped on a full channel is deliberately *not* marked seen, so it is emitted the next time it is heard. The `tx.capacity() == 0` shortcut skips even the key decode while the channel is full.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Tests](01-primer.md#primer-testing)* The decision itself moved into a pure function, `classify_heard`, which returns `Heard::Skip`, `NeverCandidate` or `Emit(peer)`. It only *reads* `seen`; the caller writes it, because only the caller knows whether the send landed. Pure decisions are easy to test (`a_heard_node_is_emitted_once_and_pins_are_left_to_the_lookup_path`).
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let Event::Discovered(enr) = event else { continue };` works in loops too: the `else` branch may `continue`. `&guard` is accepted where `&HashSet` is expected, because of deref coercion.

`rust/myotis-net/src/discovery.rs` · lines 531–568

```rust
fn filter_candidate(enr: &Enr, accepted_digests: &[[u8; 4]]) -> Option<DiscoveredPeer> {
    use libp2p::multiaddr::Protocol;
    let digest = enr_eth2_fork_digest(enr)?;
    let match_idx = accepted_digests.iter().position(|d| *d == digest)?;

    // An endpoint is an IP plus at least one transport: TCP (`tcp`/`tcp6`),
    // the spec's QUIC port (`quic` for IPv4, `quic6` for IPv6 —
    // fulu/p2p-interface.md), or both. QUIC has been the spec's primary
    // transport since consensus-specs#5330 (merged 2026-07-06: QUIC MUST, TCP
    // only SHOULD), so a record with QUIC and no TCP is a valid peer — a
    // QUIC-only one, whose QUIC address becomes its `addr`. IPv4 wins whenever
    // it carries either transport; IPv6 is the fallback, as before.
    //
    // Port 0 means "no QUIC listener" the way an absent field does; and a
    // field that does not decode as a port is ignored, not a reason to drop
    // the peer — its TCP endpoint is still good.
    let quic_port = |key: &[u8]| {
        enr.get_decodable::<u16>(key).and_then(|r| r.ok()).filter(|port| *port != 0)
    };
    let endpoint = |ip: Option<IpAddr>, tcp: Option<u16>, quic: Option<u16>| {
        ip.filter(|_| tcp.is_some() || quic.is_some()).map(|ip| (ip, tcp, quic))
    };
    let (ip, tcp_port, quic_port) =
        endpoint(enr.ip4().map(IpAddr::V4), enr.tcp4(), quic_port(b"quic"))
            .or_else(|| endpoint(enr.ip6().map(IpAddr::V6), enr.tcp6(), quic_port(b"quic6")))?;

    let peer_id = enr_to_peer_id(enr)?;
    let tcp = tcp_port.map(|port| Multiaddr::empty().with(ip.into()).with(Protocol::Tcp(port)));
    let quic = quic_port
        .map(|port| Multiaddr::empty().with(ip.into()).with(Protocol::Udp(port)).with(Protocol::QuicV1));
    let (addr, quic) = match (tcp, quic) {
        (Some(tcp), quic) => (tcp, quic),
        (None, Some(quic)) => (quic, None),
        (None, None) => return None, // `endpoint` admits neither
    };
    tracing::debug!(peer = %peer_id, %addr, ?quic, prior_fork = match_idx > 0, "CL peer discovered");
    Some(DiscoveredPeer { peer_id, addr, quic })
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* Two small closures keep the endpoint logic flat. `quic_port` reads a field, ignores one that does not decode (`.and_then(|r| r.ok())`) and treats port 0 as absent. `endpoint` accepts an IP only if it has at least one transport. `endpoint(v4…).or_else(|| endpoint(v6…))?` prefers IPv4 and evaluates the IPv6 side only if needed.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* The final `match (tcp, quic)` on a tuple of options states the rule directly: TCP present means TCP is the cache identity `addr` and QUIC rides along; QUIC alone means the QUIC address *is* `addr`. The `(None, None)` arm cannot happen after `endpoint`, but the compiler requires every case to be handled.

`rust/myotis-net/src/discovery.rs` · lines 1021–1027

```rust
impl Drop for ServerDiscovery {
    fn drop(&mut self) {
        // The maintenance task holds an Arc<Discv5>; aborting it releases the
        // last clone so the service (and its UDP socket) shuts down promptly.
        self.maintenance.abort();
    }
}
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [async/await & tokio](01-primer.md#primer-async)* **A tokio task is not tied to its handle.** Dropping a `JoinHandle` only *detaches* the task. So `Drop` aborts it explicitly. That drops the task's `Arc<Discv5>`, the last clone goes away, and discv5's own `Drop` shuts the service and its UDP socket down. In client mode, `sync.rs` wraps the handle in a `DiscoveryGuard` that does the same.

*[Protocol & domain](01-primer.md#primer-domain)* Design notes from the file: "hearsay" ENRs (heard in NODES responses) are used on purpose; this found the first sepolia peer in 4 s instead of 2 min 12 s, and they are trusted only after a successful Noise handshake. `add_enr` alone is passive and fails on a bucket full of dead entries, so the re-seed also pings. The CL fork watch gets its evidence from the *routing table* once per round, not from hearsay, because a relayed record is self-declared and keys are free.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The module doc (line 6) still says candidates are a "TCP multiaddr + PeerId"; they can now be QUIC. The doc comment for `seed_bootnodes` (lines 204–207) sits above `node_id_for_peer`'s doc, so rustdoc attaches both paragraphs to `node_id_for_peer` and `seed_bootnodes` has none. The QUIC record tests live in `server_enr_tests`, although they test the client-side `filter_candidate`.

<a id="f-myotis-net-src-clcache-rs"></a>

### myotis-net/src/clcache.rs

*library · 477 lines · Java twin · FileClPeerCache / CLPeerCache*

Reads and writes the *same* `cl-peers[-net].cache` file the Java hosts keep, so proven light-client servers survive restarts and engine switches. On disk: one tab-separated line per peer with tokens for served period ranges, deepest bootstrap, and `lc`/`nolc`. In memory: a plain struct where ranges only widen, three failures evict a peer, and changes only set `dirty`, so `flush` writes once per sync round. The only change since September is the Java twin's name in line 2.

`rust/myotis-net/src/clcache.rs` · lines 1–40

````rust
//! CL peer cache — the Rust reader/writer of the SAME `cl-peers[-net].cache`
//! file the Java hosts maintain (the engine library's `FileClPeerCache` / `app CLPeerCache`), so
//! proven light-client servers survive restarts AND engine switches.
//!
//! Format (tab-separated UTF-8 lines, one peer per line, only lines starting
//! with `/` are peers):
//!
//! ```text
//! multiaddr[\t<token>]...
//! ```
//!
//! Tokens (order-independent):
//!   - `<low>-<high>`  proven catch-up served sync-committee period range
//!   - `b<period>`     LightClientBootstrap period served (deepest kept)
//!   - `lc` / `nolc`   light-client protocol support confirmed / denied
//!   - bare integer    legacy floor — loaded as the degenerate range `[p, p]`
//!
//! Ranges WIDEN on merge (union), never overwrite — matching the Java parser.
//! Peers are evicted after 3 consecutive failures (Java FAILURE_THRESHOLD).
//! Writes are full rewrites of sorted lines via temp-file + rename; best-effort
//! (a lost cache costs a slower next catch-up, never correctness).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const FAILURE_THRESHOLD: u32 = 3;

#[derive(Default)]
pub struct ClPeerCache {
    path: Option<PathBuf>,
    peers: Vec<String>, // insertion order; rewrite sorts (Java parity)
    served: HashMap<String, (u64, u64)>,
    bootstrap: HashMap<String, u64>,
    lc: HashSet<String>,
    nolc: HashSet<String>,
    failures: HashMap<String, u32>,
    /// Unflushed changes. Mutators only mark; [`Self::flush`] writes — so the
    /// sync loop batches one write per round instead of one per peer event.
    dirty: bool,
}
````

`rust/myotis-net/src/clcache.rs` · lines 142–159

```rust
/// A peer served VERIFIED catch-up updates for `[low, high]` (callers must
/// only invoke this after the updates BLS/Merkle-verified and applied —
/// the cache is shared cross-engine, so an unverified entry would poison
/// the Java engine's peer selection too): widen its range, confirm lc,
/// clear failures. Persists only when something actually changed, so the
/// steady drip of repeat serves doesn't rewrite the file every round.
pub fn record_served(&mut self, addr: &str, low: u64, high: u64) {
    let mut changed = self.ensure(addr);
    let before = self.served.get(addr).copied();
    self.widen(addr, low, high);
    changed |= self.served.get(addr).copied() != before;
    changed |= self.lc.insert(addr.to_string());
    changed |= self.nolc.remove(addr);
    self.failures.remove(addr); // in-memory streak only — not persisted
    if changed {
        self.dirty = true;
    }
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* `let before = self.served.get(addr).copied();`. Without `.copied()`, `before` would be an `Option<&(u64, u64)>` still borrowing `self.served`, and the `&mut self` call on the next line would not compile. Copying the pair out ends the borrow.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `HashSet::insert` and `remove` return whether something changed, like Java's `Set.add`, and `changed |=` accumulates the result. `self.served.get(addr)` accepts a `&str` for a `String` key, because `String: Borrow<str>`. `Vec::contains` has no such flexibility, which is why `ensure` and `mark_failure` write `self.peers.contains(&addr.to_string())` and allocate a `String` just to compare.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Borrowing & slices](01-primer.md#primer-borrowing)* **No synchronisation at all.** The mutators take `&mut self`, and `run_sync` owns the cache as a local variable, so the compiler guarantees a single writer. It's a non-thread-safe Java object confined to one thread, except the confinement is proven. `run_sync` builds it with `.map(ClPeerCache::load).unwrap_or_else(ClPeerCache::disabled)`, passing both associated functions as values.

`rust/myotis-net/src/clcache.rs` · lines 276–308

```rust
/// Full sorted rewrite via pid-suffixed temp + rename (atomic publish; an
/// overlapping writer from another process can't tear the temp file).
/// Reached only through [`Self::flush`]. Best-effort: failures are logged
/// at debug and ignored (performance cache).
fn save(&self) {
    let Some(path) = &self.path else { return };
    let mut peers = self.peers.clone();
    peers.sort();
    let mut out = String::new();
    for p in &peers {
        out.push_str(p);
        if let Some((lo, hi)) = self.served.get(p) {
            out.push('\t');
            out.push_str(&format!("{lo}-{hi}"));
        }
        if let Some(bp) = self.bootstrap.get(p) {
            out.push('\t');
            out.push_str(&format!("b{bp}"));
        }
        if self.lc.contains(p) {
            out.push_str("\tlc");
        } else if self.nolc.contains(p) {
            out.push_str("\tnolc");
        }
        out.push('\n');
    }
    let tmp = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    let ok = std::fs::write(&tmp, out.as_bytes())
        .and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = ok {
        tracing::debug!(error = %e, "CL peer cache write failed (ignored)");
    }
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling)* An atomic write via temp file plus rename. `and_then` chains two fallible steps without `?`. The error is deliberately swallowed, because the file is only a performance cache. There is no file lock, so across processes (for example the Java engine) the last writer wins. `let Some(path) = &self.path else { return };` binds a *reference* into `self`.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The test `ordering_prefers_proven_then_bootstrap` (lines 420–421) says the widest range leads because it is "the generous multi-chunk server", which is exactly what the `peers()` doc (lines 107–109) says width does *not* show.

<a id="f-myotis-net-src-traffic-rs"></a>

### myotis-net/src/traffic.rs

*library · 343 lines*

New since September. Byte counters per network stack, split into an execution-layer and a consensus-layer pair, so a host running several networks can show each one's data usage (the engine's `usage.rs` turns the totals into a ledger). A `TrafficMeter` lives in `ChainConfig` and is handed to every socket the stack opens. For this stop's half: libp2p TCP is counted on the raw socket, below Noise and the muxer; QUIC is counted per substream above QUIC, because libp2p does not expose its socket; and discv5, which only counts process-wide, has its growth shared out among the meters whose discovery is running.

`rust/myotis-net/src/traffic.rs` · lines 31–53

```rust
/// One direction pair of byte counters. Monotonic; never reset.
#[derive(Debug, Default)]
pub struct ByteCounter {
    rx: AtomicU64,
    tx: AtomicU64,
}

impl ByteCounter {
    /// Count `n` received bytes.
    pub fn add_rx(&self, n: usize) {
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Count `n` sent bytes.
    pub fn add_tx(&self, n: usize) {
        self.tx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// `(received, sent)` so far.
    pub fn snapshot(&self) -> (u64, u64) {
        (self.rx.load(Ordering::Relaxed), self.tx.load(Ordering::Relaxed))
    }
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* `add_rx` takes `&self`, not `&mut self`, and still changes the count: `AtomicU64` is interior mutability without a lock, like Java's `AtomicLong`. That is what lets many connections share one meter through an `Arc` (which only ever hands out `&T`). `Relaxed` ordering guarantees each counter's own updates are not lost, and nothing more, which is all a statistic needs.

#### discv5: one global counter, shared out with weak references

`rust/myotis-net/src/traffic.rs` · lines 100–146

```rust
struct Discv5Ledger {
    /// discv5's global `(recv, sent)` at the last flush.
    seen: (u64, u64),
    /// Meters whose discv5 is running right now.
    live: Vec<Weak<TrafficMeter>>,
}

static DISCV5: Mutex<Discv5Ledger> = Mutex::new(Discv5Ledger { seen: (0, 0), live: Vec::new() });

fn discv5_totals() -> (u64, u64) {
    let m = discv5::Discv5::metrics();
    (m.bytes_recv as u64, m.bytes_sent as u64)
}

/// Hand discv5's growth since the last flush to the live meters, evenly (the
/// remainder to the first). Growth with no live meter — a discv5 the engine
/// did not start (tools, roost) — is dropped.
fn flush_discv5_locked(ledger: &mut Discv5Ledger) {
    share_growth(ledger, discv5_totals());
}

/// [`flush_discv5_locked`] against given totals (`(recv, sent)`).
fn share_growth(ledger: &mut Discv5Ledger, now: (u64, u64)) {
    let d_rx = now.0.saturating_sub(ledger.seen.0);
    let d_tx = now.1.saturating_sub(ledger.seen.1);
    ledger.seen = now;
    ledger.live.retain(|w| w.strong_count() > 0);
    let live: Vec<Arc<TrafficMeter>> = ledger.live.iter().filter_map(Weak::upgrade).collect();
    if live.is_empty() || (d_rx == 0 && d_tx == 0) {
        return;
    }
    let n = live.len() as u64;
    for (i, m) in live.iter().enumerate() {
        let (mut rx, mut tx) = (d_rx / n, d_tx / n);
        if i == 0 {
            rx += d_rx % n;
            tx += d_tx % n;
        }
        m.cl.rx.fetch_add(rx, Ordering::Relaxed);
        m.cl.tx.fetch_add(tx, Ordering::Relaxed);
    }
}

fn flush_discv5() {
    let mut ledger = DISCV5.lock().unwrap_or_else(|e| e.into_inner());
    flush_discv5_locked(&mut ledger);
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Interior mutability](01-primer.md#primer-interior-mutability)* `static DISCV5: Mutex<Discv5Ledger> = Mutex::new(…)` is a global initialised at compile time. That is allowed because `Mutex::new` and `Vec::new` are `const fn`. A `static` must be `Sync`, and the `Mutex` is what makes the ledger so. This is the crate's answer to an external global: the `discv5` crate's own metrics are process-wide.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **`Weak` is Java's `WeakReference`, with explicit counting.** The ledger keeps `Weak<TrafficMeter>`, so being registered does not keep a meter alive. `retain(|w| w.strong_count() > 0)` prunes dead entries, and `filter_map(Weak::upgrade)` turns each live one into a temporary `Arc` for the duration of the update. The `live` vector drops those `Arc`s at the end of the function.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `saturating_sub` clamps at 0. A plain `-` that underflows panics in debug and test builds, where overflow checks are on, and wraps silently in release. The split is even, with the remainder to the first meter; the test `discv5_growth_is_shared_by_the_live_meters_only` checks the arithmetic, including a dropped meter and nobody live.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `DISCV5.lock().unwrap_or_else(|e| e.into_inner())` again takes the guard even if a panicking thread poisoned the lock. A wrong byte count is better than a panic in a status read.

`rust/myotis-net/src/traffic.rs` · lines 148–172

```rust
/// Held for as long as one meter's discv5 runs: on creation the meter joins
/// the share of discv5's process-wide traffic, on drop it leaves. Both flush
/// first, so bytes from before the change go to the meters live then.
pub struct Discv5Share {
    meter: Weak<TrafficMeter>,
}

impl Discv5Share {
    pub fn join(meter: &Arc<TrafficMeter>) -> Discv5Share {
        let mut ledger = DISCV5.lock().unwrap_or_else(|e| e.into_inner());
        flush_discv5_locked(&mut ledger);
        ledger.live.push(Arc::downgrade(meter));
        Discv5Share { meter: Arc::downgrade(meter) }
    }
}

impl Drop for Discv5Share {
    fn drop(&mut self) {
        let mut ledger = DISCV5.lock().unwrap_or_else(|e| e.into_inner());
        flush_discv5_locked(&mut ledger);
        if let Some(i) = ledger.live.iter().position(|w| w.ptr_eq(&self.meter)) {
            ledger.live.swap_remove(i);
        }
    }
}
```

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* **Registration as a value.** `Discv5Share::join` registers the meter and returns a token; dropping the token unregisters it. It is the RAII shape of Java's try-with-resources, except no `try` block is needed: the owner (the lookup task) simply holds the token, and when the task ends or is aborted, Rust drops it. `Arc::downgrade(meter)` is called twice, once for the ledger and once for the token, and `w.ptr_eq(&self.meter)` finds the token's own entry by pointer identity, like `==` on Java references. `swap_remove` is O(1) because order does not matter. Both paths flush first, so bytes from before the change go to the meters that were live then.

#### libp2p: wrapping a poll-based stream

`rust/myotis-net/src/traffic.rs` · lines 176–215

```rust
/// A `futures` byte stream that counts what passes through it into one
/// [`ByteCounter`] of a meter. Wraps libp2p's raw TCP socket (below noise) and
/// each QUIC substream.
pub struct CountingStream<S> {
    inner: S,
    meter: Arc<TrafficMeter>,
    layer: fn(&TrafficMeter) -> &ByteCounter,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, meter: Arc<TrafficMeter>, layer: fn(&TrafficMeter) -> &ByteCounter) -> Self {
        CountingStream { inner, meter, layer }
    }

    fn counter(&self) -> &ByteCounter {
        (self.layer)(&self.meter)
    }
}

impl<S: futures::AsyncRead + Unpin> futures::AsyncRead for CountingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.counter().add_rx(n);
        }
        poll
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_read_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = poll {
            self.counter().add_rx(n);
        }
        poll
    }
}
```

- *[async/await & tokio](01-primer.md#primer-async) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **What `poll_read` is.** Under every `.await` on a byte stream there is a `poll_read` that returns at once with `Poll::Ready(result)` or `Poll::Pending` (after registering the waker in `cx`). A wrapper implements the same trait and forwards each call; here it adds the byte count when the inner call is `Ready(Ok(n))`. It is the decorator pattern, as with a Java `FilterInputStream`.
- *[async/await & tokio](01-primer.md#primer-async) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **`Pin<&mut Self>` and `Unpin`.** Poll methods take the receiver pinned, a promise that the value will not move in memory, which self-referential futures need. To call the inner stream's `poll_read`, the wrapper needs a `Pin<&mut S>`. `Pin::new(&mut self.inner)` builds one, and it is only allowed because the impl requires `S: Unpin` ("safe to move even when pinned"). With that bound no `unsafe` pin projection is needed.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `layer: fn(&TrafficMeter) -> &ByteCounter` is a plain function pointer (no closure, no allocation) that picks which counter to use. The elided lifetimes mean "the returned reference borrows from the argument". `(self.layer)(&self.meter)` needs the parentheses so Rust calls the field instead of looking for a method named `layer`. Line 295 defines `cl`, which `build_swarm` passes.

`rust/myotis-net/src/traffic.rs` · lines 260–292

```rust
impl<M> libp2p::core::muxing::StreamMuxer for CountingMuxer<M>
where
    M: libp2p::core::muxing::StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    type Substream = CountingStream<M::Substream>;
    type Error = M::Error;

    fn poll_inbound(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Self::Substream, Self::Error>> {
        let meter = Arc::clone(&self.meter);
        Pin::new(&mut self.inner)
            .poll_inbound(cx)
            .map_ok(|s| CountingStream::new(s, meter, cl))
    }

    fn poll_outbound(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Self::Substream, Self::Error>> {
        let meter = Arc::clone(&self.meter);
        Pin::new(&mut self.inner)
            .poll_outbound(cx)
            .map_ok(|s| CountingStream::new(s, meter, cl))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<libp2p::core::muxing::StreamMuxerEvent, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* `CountingMuxer` implements libp2p's `StreamMuxer` with an **associated type**: `type Substream = CountingStream<M::Substream>`, so every substream it hands out is a counting one. `Poll<Result<T, E>>::map_ok` transforms a ready success and passes `Pending` and errors through. The `Arc::clone(&self.meter)` comes first because the closure needs its own handle while `self.inner` is borrowed mutably through the pin. It costs one atomic increment per poll, including polls that return `Pending`.

> [!WARNING]
> **Not counted**<br>
>
> The module doc lists what the meters miss: IP/TCP/UDP headers, QUIC's own packet overhead and TLS handshake, EIP-1459 DNS lookups, and Tor. With several networks running, discv5's share is an even split, not a measurement.

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-netcl-q1"></a>

**Q1** · Written answer

Describe how a response gets from the network back to the code that called `ReqRespClient::request_raw_at`. Which task owns what at each step?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-netcl-q1)

<a id="q-netcl-q2"></a>

**Q2** · Multiple choice

Why does `SwarmCtx` hold plain `HashMap`s, while `LocalStatus`, `AgentMap` and `TcpFirst` wrap their data in a lock?

- **A.** `SwarmCtx` only holds `Copy` types
- **B.** tokio synchronises all task state automatically
- **C.** `SwarmCtx` is moved into the one swarm task and only used there through `&mut`; the other three are shared with the client or the sync loop through an `Arc`, which only gives out `&T`, so mutation needs interior mutability
- **D.** The locked types are larger than 4 KiB

[Answer →](answers.md#a-netcl-q2)

<a id="q-netcl-q3"></a>

**Q3** · Multiple choice

What went wrong when `pending` was keyed by `OutboundRequestId` alone?

- **A.** Each request/response behaviour numbers its requests from 1, so ids from different protocols collided; a second insert evicted the first entry and a reply could reach the wrong caller
- **B.** Ids overflowed after 2^64 requests
- **C.** The map grew without bound
- **D.** Requests were sent twice

[Answer →](answers.md#a-netcl-q3)

<a id="q-netcl-q4"></a>

**Q4** · Multiple choice

In `resolve_dial_addrs`, the DNS memo (a `std::sync::Mutex`) is locked only after `lookup_host(…).await` has returned. What would go wrong if the guard were held across that `.await`?

- **A.** The lookup would be slower
- **B.** Nothing
- **C.** A `std` `MutexGuard` is not `Send`, so the future would not be `Send` and could not run inside `tokio::spawn`; it would also block other users for the whole lookup
- **D.** The mutex would be poisoned

[Answer →](answers.md#a-netcl-q4)

<a id="q-netcl-q5"></a>

**Q5** · Multiple choice

What does dropping the `JoinHandle` returned by `tokio::spawn` do to the task?

- **A.** It cancels the task
- **B.** It blocks until the task finishes
- **C.** It panics
- **D.** It detaches the task, which keeps running; stopping it needs `abort()`, which is why `ServerDiscovery` and `DiscoveryGuard` abort in `Drop`

[Answer →](answers.md#a-netcl-q5)

<a id="q-netcl-q6"></a>

**Q6** · Multiple choice

The host runs a gossipsub behaviour but never subscribes to a topic. Why is it there?

- **A.** To receive finality updates by gossip
- **B.** So that the `/meshsub/` protocol negotiates: Lighthouse treats a failed gossipsub upgrade as fatal and bans the peer id for 12 h, and the whole IP after more than five banned ids
- **C.** Because libp2p requires at least one pub/sub behaviour
- **D.** To publish the wallet's own Status

[Answer →](answers.md#a-netcl-q6)

<a id="q-netcl-q7"></a>

**Q7** · Multiple choice

`ClPeerCache` has no lock inside. What prevents two writers from corrupting it?

- **A.** Its mutators take `&mut self`, and the sync loop owns it as a local variable, so the compiler guarantees one writer; sharing it would require something like `Arc<Mutex<_>>`
- **B.** Nothing; it's a bug
- **C.** A file lock
- **D.** tokio serialises all tasks

[Answer →](answers.md#a-netcl-q7)

<a id="q-netcl-q8"></a>

**Q8** · Written answer

In `consume_discovered`, a `std::sync::Mutex` guard is held while calling `tx.try_send(peer)`. Explain why that is acceptable, and why `tx.send(peer).await` would not be.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-netcl-q8)

<a id="q-netcl-q9"></a>

**Q9** · Multiple choice

`dial_order` runs `addrs.sort_by_key(is_quic)` for a peer on `TcpFirst`. What is the result?

- **A.** QUIC addresses first, because `true` sorts before `false`
- **B.** TCP addresses first, because `false < true`; the sort is stable, so the order within each transport is kept
- **C.** A random order, because `sort_by_key` is unstable
- **D.** It does not compile: `sort_by_key` needs a closure, not a function name

[Answer →](answers.md#a-netcl-q9)

<a id="q-netcl-q10"></a>

**Q10** · Written answer

`Discv5Ledger::live` stores `Weak<TrafficMeter>`, not `Arc<TrafficMeter>`, and `Discv5Share` implements `Drop`. Explain what each choice buys, and what happens to discv5 bytes when a meter's network stops.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-netcl-q10)

<a id="q-netcl-q11"></a>

**Q11** · Multiple choice

Why are the `LcResponder` methods plain `fn` returning `Option<Vec<u8>>`, not `async fn`?

- **A.** Traits cannot contain async methods
- **B.** They are called from `respond_inbound`, which runs inline on the swarm task; an implementation that did I/O there would stall every connection, so it must be a cache read, and a miss is answered with `ResourceUnavailable`
- **C.** Because `roost` has no tokio runtime
- **D.** To avoid the `Send` bound

[Answer →](answers.md#a-netcl-q11)

<a id="q-netcl-q12"></a>

**Q12** · Multiple choice

Before mplex was added, the Rust host could not reach Nimbus nodes. Why does the test helper `dial_outcome` wait for an Identify answer instead of `ConnectionEstablished`?

- **A.** Identify arrives earlier
- **B.** `ConnectionEstablished` is never emitted for TCP
- **C.** The dialer negotiates the muxer optimistically and reports the connection established even with no muxer in common; only a completed stream (the Identify exchange) proves a muxer was agreed
- **D.** Identify carries the fork digest

[Answer →](answers.md#a-netcl-q12)

<a id="q-netcl-q13"></a>

**Q13** · Written answer

`request_raw_at` calls `self.request_in_order(peer, addrs.clone(), protocol, wire.clone())` and may call it a second time. Why the clones, and exactly when does the retry happen?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-netcl-q13)

<a id="q-netcl-q14"></a>

**Q14** · Multiple choice

Several locks in this stop are taken with `.lock().unwrap_or_else(|e| e.into_inner())` or `.read().unwrap_or_else(|e| e.into_inner())`. What does that do?

- **A.** It retries until the lock is free
- **B.** It returns a default value when the lock is busy
- **C.** It converts the lock into a tokio lock
- **D.** If another thread panicked while holding the lock, the lock is poisoned and returns `Err(PoisonError)`; `into_inner()` takes the guard anyway, accepting data that a panic may have left half-updated

[Answer →](answers.md#a-netcl-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
