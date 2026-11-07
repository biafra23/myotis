# tor-poc: the same stack over Tor

*Stop 21 · standalone crate `tor-poc`* · 1 file · 544 lines · about 60 minutes

A proof of concept for `docs/privacy-and-tor.md`, run by hand against live mainnet. It boots an embedded Arti Tor client and runs the *unmodified* RLPx + eth + snap stack from `myotis-net` over a Tor stream. Each wallet address gets its own circuit and a fresh throwaway node key, followed by one proof-verified account read. The production change it needed is the most instructive idea in this stop: making the connection types **generic over the byte stream**.

## Rust you will practise

- **Generics with defaults** — `RlpxConnection<S = TcpStream>`, trait bounds, and monomorphisation compared with Java's erased generics.
- **Ownership down the layers** — Stream → RLPx connection → eth session, each owning the one below.
- **Explicit lifetimes** — Why `fn f<'a>(…, peers: &'a [Peer], …) -> Option<&'a Peer>` needs the annotation.

### The production change *Traits, generics & dyn · async/await & tokio*

The clearnet code was written against `tokio::net::TcpStream`. To run it over Arti's `DataStream`, the two connection types became generic over the stream, with a *default type parameter* so that every existing clearnet caller compiles unchanged. The code lives in `myotis-net/src/el/rlpx/transport.rs` ([Stop 11](11-el-transport.md) covers it in full):

**myotis-net/src/el/rlpx/transport.rs** · `rust/myotis-net/src/el/rlpx/transport.rs` · lines 45–63

```rust
/// A live framed RLPx connection: the byte stream plus the session's stateful
/// [`FrameCodec`]. Read/write are serialized through `&mut self` (the codec is
/// position-dependent), matching the Java single-event-loop contract.
///
/// Generic over the underlying stream `S`, defaulting to [`TcpStream`] so every
/// clearnet caller is unchanged. The bound is any tokio byte stream, which lets
/// the same handshake + framed channel run over a Tor `DataStream` (Arti) — see
/// [`RlpxConnection::handshake_over`] and `docs/privacy-and-tor.md` §3. The
/// crypto (`Initiator`/`FrameCodec`) never touched the socket type; only this
/// dialer did.
pub struct RlpxConnection<S = TcpStream> {
    stream: S,
    codec: FrameCodec,
    /// The peer's static public key (its enode id).
    peer_pubkey: [u8; 64],
    /// Where the connection's bytes are counted (the EL layer), from the
    /// handshake on; carried into the split halves. None = not counted.
    traffic: Option<Arc<TrafficMeter>>,
}
```

**myotis-net/src/el/rlpx/transport.rs** · `rust/myotis-net/src/el/rlpx/transport.rs` · lines 119–132

```rust
impl<S: AsyncReadExt + AsyncWriteExt + Unpin> RlpxConnection<S> {
    /// Run the initiator handshake over an ALREADY-CONNECTED stream, returning a
    /// FRAMED connection. The caller owns transport setup (TCP connect + nodelay
    /// for [`dial`](RlpxConnection::dial); opening a Tor `DataStream` for the
    /// privacy path). Not bounded by [`HANDSHAKE_TIMEOUT`] — the caller wraps it
    /// (Tor's multi-hop build wants a larger budget). Entropy is drawn from the
    /// OS here.
    pub async fn handshake_over(
        stream: S,
        local_key: Arc<NodeKey>,
        peer_pubkey: [u8; 64],
    ) -> Result<RlpxConnection<S>, String> {
        Self::handshake_metered(stream, local_key, peer_pubkey, None).await
    }
```

`impl<S: AsyncReadExt + AsyncWriteExt + Unpin>` reads as "for any tokio byte stream that may be moved between polls". The extension traits are implemented for every `AsyncRead`/`AsyncWrite` type, and Arti's `DataStream` implements those when its `tokio` feature is enabled. `dial` stays in a separate `impl RlpxConnection<TcpStream>` block (line 65), because only TCP can be dialled that way. Since the September tour the struct also carries `traffic: Option<Arc<TrafficMeter>>`, the data-usage counter; `handshake_over` passes `None` to the new `handshake_metered`, so tor-poc counts nothing.

> [!NOTE]
> **JVM lens**
>
> It is like a protocol class written against `InputStream`/`OutputStream` that you hand a Tor socket's streams, with one difference. Java erases generics to one implementation that dispatches at run time; Rust *monomorphises*, compiling a specialised copy of the handshake for `S = DataStream` next to the `TcpStream` one, with no virtual calls. The default parameter (`S = TcpStream`) is something Java generics cannot express.

Generic code is not automatically behaviour-neutral. A `TcpStream` sends each write at once; a `DataStream` buffers until it is flushed. The handshake therefore flushes before it waits for the peer's answer:

**myotis-net/src/el/rlpx/transport.rs** · `rust/myotis-net/src/el/rlpx/transport.rs` · lines 154–168

```rust
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
```

*[async/await & tokio](01-primer.md#primer-async) · [Result, ? and panics](01-primer.md#primer-error-handling)* `write_all` and `flush` come from `AsyncWriteExt`, the bound on `S`. Each returns a future of `io::Result<()>`; `.await` drives it, `.map_err(…)` turns the `io::Error` into the function's `String` error, and `?` returns early. On TCP the flush is a no-op. The tor-poc README records what happened without it: the peer never saw the auth message, and every Tor attempt ended with "early eof" while reading the ack.

<a id="f-tor-poc-src-main-rs"></a>

### tor-poc/src/main.rs

*binary · proof of concept · 544 lines*

It boots Arti, measures a clearnet baseline over the same stack (so a later Tor failure can be blamed on the Tor path), probes peers over Tor, and then performs per-address isolated, proof-verified snap reads. It is *not* production code: there is no quarantined peer pool, and the state root is the peer's *claimed* head, not a beacon-anchored one. It is fully sequential, with no `tokio::spawn` anywhere. `#[tokio::main]` is still required, because Arti uses the current runtime.

| Lines | What happens |
|---|---|
| 1–44 | Crate docs (the design claims it tests) and imports. |
| 46–64 | `mainnet_eth_config`: an inline copy of the mainnet EL parameters. |
| 66–132 | `Peer`, its `TorAddr`, the peers from the clearnet daemon's `peers.cache`, and the four legacy geth bootnodes as a fallback. |
| 134–164 | Demo addresses and `ephemeral_key`. |
| 166–264 | `query_over_tor`: one isolated circuit, RLPx, eth, head header, one verified `GetAccountRange`. |
| 266–367 | `eth_handshake_over_tor`, `head_number` and `pick_working_peer`. |
| 369–401 | `probe_clearnet`: the same stack over `TcpStream`. |
| 403–520 | `main`: boot Arti, baseline, Tor probe, per-address reads. |
| 522–544 | Hex helpers. |

`rust/tor-poc/src/main.rs` · lines 1–31

```rust
//! Tor integration PROOF OF CONCEPT for `docs/privacy-and-tor.md`.
//!
//! It exercises, against the LIVE Ethereum mainnet p2p network, the load-bearing
//! technical claims of that design doc — the ones worth de-risking before any
//! production work:
//!
//!   §3  Arti (the Tor Project's embeddable Rust client) boots inside the Rust
//!       process and opens a TCP stream to an Ethereum peer's `:30303`.
//!   §3  Per-address *stream isolation* — one `IsolationToken` per wallet
//!       address — so any single Tor exit only ever sees queries for ONE
//!       address, never the user's whole portfolio.
//!   §4  The EXISTING RLPx + eth/snap stack (`myotis-net`) runs UNMODIFIED over
//!       a Tor `DataStream`: the only production change this PoC required was
//!       making `RlpxConnection`/`EthSession` generic over the byte stream
//!       (default `TcpStream`, so every clearnet caller is untouched).
//!   §6.1 Each Tor-side connection presents an EPHEMERAL RLPx node key, never
//!       the persistent `nodekey.hex`, so a peer can't pair a clearnet probe
//!       with a Tor-side query by node identity.
//!
//! It then issues a REAL, proof-verified `GetAccountRange` for a wallet address
//! over Tor — the exact flow §1 calls "the core leak" (address ↔ IP at snap
//! peers) — and prints the MPT-verified account, demonstrating the query works
//! end-to-end with the user's IP hidden behind three Tor hops.
//!
//! NOT production: no quarantined peer pool (§5), no multi-source promotion
//! (§6.2), and the snap proof here anchors to the peer's *claimed* fresh head
//! rather than the beacon-verified anchor — the wallet's real trust root. This
//! is a networking-plumbing proof, not a trust-model change.
//!
//!   cargo run --manifest-path rust/tor-poc/Cargo.toml -- [ADDRESS ...]

```

**tor-poc/Cargo.toml** · `rust/tor-poc/Cargo.toml` · lines 22–38

```toml
[dependencies]
# The real Myotis EL stack — the whole point is to reuse it verbatim.
myotis-net = { path = "../myotis-net" }
myotis-core = { path = "../myotis-core" }

# Arti — the Tor Project's official embeddable Rust client (docs §3). native-tls
# (macOS Security.framework / system trust store) sidesteps the rustls 0.23
# process-wide CryptoProvider selection; tokio matches the engine's runtime.
arti-client = { version = "0.44", default-features = false, features = ["tokio", "native-tls"] }
tor-rtcompat = { version = "0.44", default-features = false, features = ["tokio", "native-tls"] }

tokio = { version = "1", features = ["rt-multi-thread", "macros", "io-util", "time"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
hex = "0.4"
getrandom = "0.2"
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* Its own `[workspace]` root (like roost, [Stop 2](02-workspace.md)), so Arti's large dependency tree never enters the engine build or CI. `default-features = false, features = ["tokio", "native-tls"]`: Arti's `tokio` feature is what compiles the tokio `AsyncRead`/`AsyncWrite` implementations for `DataStream`, the hinge of this whole proof. `native-tls` avoids rustls's process-wide crypto-provider choice. The engine's optional `tor` feature in `myotis-net` now takes the same Arti crates into production builds, with rustls on Android.

#### The core flow

`rust/tor-poc/src/main.rs` · lines 168–216

```rust
async fn query_over_tor(
    tor: &TorClient<tor_rtcompat::PreferredRuntime>,
    peer: &Peer,
    address: &[u8; 20],
    isolation: IsolationToken,
    eth_cfg: &EthConfig,
) -> Result<AccountOutcome> {
    // Per-address stream isolation (docs §3): this token pins the circuit; a
    // different address uses a different token → a different middle+exit path,
    // so no exit ever correlates two of the user's addresses.
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(isolation);

    let t0 = Instant::now();
    let stream = tor
        .connect_with_prefs(peer.tor_addr()?, &prefs)
        .await
        .with_context(|| format!("Tor connect to {}", peer.addr))?;
    // Per-phase deltas (each `since` measures only its own phase, not cumulative).
    // `mark` starts at t0 so the first delta captures the Tor connect/circuit build.
    let mut mark = t0;
    let mut since = || {
        let d = mark.elapsed().as_millis();
        mark = Instant::now();
        d
    };
    let dial_ms = since();

    // Fresh ephemeral RLPx identity for this circuit (docs §6.1).
    let key = ephemeral_key()?;

    // The EXISTING handshake, over a Tor DataStream instead of a TcpStream.
    // Bounded here (Tor's multi-hop path wants more than the clearnet budget).
    let conn = tokio::time::timeout(
        Duration::from_secs(45),
        RlpxConnection::handshake_over(stream, Arc::clone(&key), peer.pubkey),
    )
    .await
    .map_err(|_| anyhow!("RLPx handshake timed out over Tor"))?
    .map_err(|e| anyhow!("RLPx handshake: {e}"))?;
    let rlpx_ms = since();

    let mut session = EthSession::handshake(conn, &key.public_key_bytes(), eth_cfg, None)
        .await
        .map_err(|e| anyhow!("eth handshake: {e}"))?;
    if !session.snap {
        bail!("peer negotiated eth/{} but no snap", session.eth_version);
    }
    let eth_ms = since();
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [async/await & tokio](01-primer.md#primer-async)* **Inference picks the type.** `stream` is an Arti `DataStream`, so `handshake_over(stream, …)` is instantiated with `S = DataStream`, and `conn` is a `RlpxConnection<DataStream>`. No type is written anywhere.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **Ownership down the layers.** `stream` moves into the RLPx connection, and `conn` moves into the eth session. Each layer owns the one below, like wrapping Java streams, except that the old variable becomes unusable. `Arc::clone(&key)` hands one reference-counted handle to `handshake_over`, and the original `key` stays usable for `key.public_key_bytes()`, which auto-derefs through the `Arc`. `peer.pubkey`, a `[u8; 64]`, is copied.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [async/await & tokio](01-primer.md#primer-async)* **Two error layers.** `timeout(…)` wraps the handshake, so the result is `Result<Result<…, String>, Elapsed>`. The first `map_err(…)?` handles the timeout, and the second handles the handshake's `String` error. On timeout, the inner future and the stream it owns are dropped, which closes the circuit.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* **An `FnMut` closure.** `since` updates its captured `mark`, so calling it needs `&mut since`, hence `let mut since`. While `since` is still going to be called, `mark` is mutably borrowed by it and cannot be used elsewhere. `Instant` is `Copy`, so `mark = t0` copies.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **A conversion into a trait object.** `prefs.set_isolation(isolation)` is declared as `fn set_isolation<T: Into<Box<dyn Isolation>>>(…)`, so the `Copy` `IsolationToken` is converted into a boxed trait object inside Arti. One token per address means one circuit per address.
- *[Protocol & domain](01-primer.md#primer-domain)* **The fourth argument.** `EthSession::handshake(conn, &…, eth_cfg, None)`: the `None` is `served_range`, the block range a serving node would advertise. tor-poc is outbound-only and serves nothing.

`rust/tor-poc/src/main.rs` · lines 270–304

```rust
async fn eth_handshake_over_tor(
    tor: &TorClient<tor_rtcompat::PreferredRuntime>,
    peer: &Peer,
    eth_cfg: &EthConfig,
) -> Result<EthSession<arti_client::DataStream>> {
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(IsolationToken::new());
    let stream = tor.connect_with_prefs(peer.tor_addr()?, &prefs).await?;
    let key = ephemeral_key()?;
    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        RlpxConnection::handshake_over(stream, Arc::clone(&key), peer.pubkey),
    )
    .await
    .map_err(|_| anyhow!("rlpx timeout"))?
    .map_err(|e| anyhow!("{e}"))?;
    EthSession::handshake(conn, &key.public_key_bytes(), eth_cfg, None)
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// Ask a session for its head block number (its eth/69 advertised head, or a
/// best_hash header fetch on eth/67-68). 0 ⇒ effectively unsynced.
async fn head_number<S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin>(
    session: &mut EthSession<S>,
) -> u64 {
    if let Some(n) = session.peer_status.latest_block {
        return n;
    }
    let best_hash = session.peer_status.best_hash;
    match session.get_block_headers_by_hash(&best_hash, 1).await {
        Ok(hs) => hs.first().map(|h| h.header.number).unwrap_or(0),
        Err(_) => 0,
    }
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Borrowing & slices](01-primer.md#primer-borrowing)* `EthSession<arti_client::DataStream>` names the generic type explicitly in a return position. `head_number<S: …>` repeats the `impl`'s bounds so it can call `EthSession<S>`'s methods, and takes `&mut` because requests change the session's state (the request id and the frame codec). `.map_err(|e| anyhow!("{e}"))` turns `myotis-net`'s `String` errors into `anyhow::Error`, because `String` does not implement `std::error::Error`.

#### Choosing a peer: an explicit lifetime

`rust/tor-poc/src/main.rs` · lines 311–367

```rust
async fn pick_working_peer<'a>(
    tor: &TorClient<tor_rtcompat::PreferredRuntime>,
    peers: &'a [Peer],
    eth_cfg: &EthConfig,
    attempts_per_peer: usize,
) -> Option<&'a Peer> {
    use std::io::Write;
    const SYNCED_HEAD: u64 = 1_000_000; // any real mainnet head dwarfs this
    let mut best: Option<(&Peer, u64)> = None;
    for peer in peers {
        for attempt in 1..=attempts_per_peer {
            print!(
                "  probing {} ({}) over Tor [try {attempt}/{attempts_per_peer}] ... ",
                peer.name, peer.addr
            );
            let _ = std::io::stdout().flush();
            let t0 = Instant::now();
            match tokio::time::timeout(
                Duration::from_secs(60),
                eth_handshake_over_tor(tor, peer, eth_cfg),
            )
            .await
            {
                Ok(Ok(mut session)) => {
                    if !session.snap {
                        println!("OK but no snap — skipping");
                        break; // capability won't change on retry
                    }
                    let head = head_number(&mut session).await;
                    println!(
                        "OK in {}ms — eth/{}, snap, head=#{head} — {:?}",
                        t0.elapsed().as_millis(),
                        session.eth_version,
                        session.peer_hello.client_id
                    );
                    if head >= SYNCED_HEAD {
                        return Some(peer); // synced + Tor-reachable: ideal
                    }
                    if best.map_or(true, |(_, h)| head > h) {
                        best = Some((peer, head));
                    }
                    break; // this peer answered; try the next peer for a synced one
                }
                Ok(Err(e)) => println!("failed: {e}"),
                Err(_) => println!("timed out (>60s)"),
            }
        }
    }
    if let Some((peer, head)) = best {
        println!(
            "  (no synced peer accepted Tor; falling back to best found: {} head=#{head})",
            peer.name
        );
        return Some(peer);
    }
    None
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Why `'a`.** The function returns a reference but takes *several* reference parameters (`tor`, `peers`, `eth_cfg`), so the elision rules cannot guess which one the result borrows from. `'a` says: from `peers`. The caller must then keep the slice's owner alive while it uses the result.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Nested results in one `match`.** `Ok(Ok(mut session))` / `Ok(Err(e))` / `Err(_)` peels the nested timeout result; the `mut` inside the pattern makes the binding mutable. `best.map_or(true, |(_, h)| head > h)` means "no best yet, or better than the best". `best` is an `Option<(&Peer, u64)>`, which is `Copy`, so `map_or` consumes a copy and `best` stays usable.
- *[Ownership & moves](01-primer.md#primer-ownership) · [async/await & tokio](01-primer.md#primer-async)* **Where the session goes.** `session` is owned by the match arm. When the arm ends, it is dropped, and with it the RLPx connection and the Tor stream. The function returns only the `&Peer`; `query_over_tor` later opens a new circuit to it.

`rust/tor-poc/src/main.rs` · lines 446–458

```rust
// ---- §4: prove the identical RLPx+eth+snap stack runs over Tor --------
// Probe the clearnet-live peers first (most likely to answer), then the rest.
let mut ordered: Vec<&Peer> = live.clone();
ordered.extend(targets.iter().filter(|p| !live.iter().any(|l| l.addr == p.addr)));
let ordered_owned: Vec<Peer> = ordered
    .iter()
    .map(|p| Peer { name: p.name.clone(), pubkey: p.pubkey, addr: p.addr })
    .collect();
println!("[2/3b] Probing those peers over Tor (RLPx handshake unmodified, fresh circuit per try):");
// Live peers get several tries (worth retrying a known-good node through a
// different exit); the rest get one.
let attempts = if live.is_empty() { 2 } else { 4 };
let peer = match pick_working_peer(&tor, &ordered_owned, &eth_cfg, attempts).await {
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* **`&[&Peer]` is not `&[Peer]`.** `ordered` is a `Vec<&Peer>`, but `pick_working_peer` wants a slice of *owned* `Peer`s. `Peer` is not `Clone`, so `ordered_owned` rebuilds them field by field (`name.clone()`, plus copies of the `Copy` fields), and the `&Peer` that comes back borrows from `ordered_owned`. That is the `'a` above in action. `live.clone()` copies only the vector of references, not the peers.

#### The configuration copy

`rust/tor-poc/src/main.rs` · lines 46–64

```rust
/// Mainnet EL parameters, mirroring `myotis_net::el::reader::ElConfig::mainnet()`
/// (kept inline so the PoC needs nothing beyond the public handshake types).
fn mainnet_eth_config() -> EthConfig {
    let genesis =
        hex32("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
    EthConfig {
        network_id: 1,
        genesis_hash: genesis,
        fork_id_hash: [0x07, 0xc9, 0x46, 0x2e],
        fork_next: 0,
        // A light client advertises genesis as its head; peers gate on fork-id,
        // not on our claimed head (docs §-parity with the Java handshake).
        head_hash: genesis,
        head_number: 0,
        listen_port: 30303,
        // Outbound-only: no PeerPool, so no serve window to seed with genesis.
        genesis_header_rlp: None,
    }
}
```

*[Methods & self](01-primer.md#primer-methods) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* A struct literal must name every field unless it ends with `..base`. When `EthConfig` gained `genesis_header_rlp`, this function stopped compiling, and because tor-poc is excluded from the workspace, CI did not notice. The September tour reported exactly that error. The field is now set to `None` (the comment says why: no peer pool, so no serve window to seed), and `EthConfig`'s own doc comment now warns the next person who adds a field:

**myotis-net/src/el/eth/session.rs** · `rust/myotis-net/src/el/eth/session.rs` · lines 35–56

```rust
/// Parameters for our side of the eth handshake.
///
/// Adding a field? `rust/tor-poc/src/main.rs` also builds this with a struct
/// literal, and tor-poc sits outside the workspace, so CI never compiles it —
/// update it too, then run `cargo check --manifest-path tor-poc/Cargo.toml`
/// from `rust/`.
#[derive(Clone)]
pub struct EthConfig {
    pub network_id: u64,
    pub genesis_hash: [u8; 32],
    /// The pinned fork id; what goes on the wire is [`EthConfig::fork_id_at`].
    pub fork_id_hash: [u8; 4],
    pub fork_next: u64,
    /// The block hash/number we advertise as our head (a light client can send
    /// genesis; peers don't gate on it beyond fork-id).
    pub head_hash: [u8; 32],
    pub head_number: u64,
    pub listen_port: u16,
    /// Raw genesis header RLP for serve-window seeding (mainnet only today);
    /// verified against `genesis_hash` before use. None → no genesis serving.
    pub genesis_header_rlp: Option<Vec<u8>>,
}
```

> [!WARNING]
> **Status at this snapshot**
>
> It compiles again. A `cargo check --offline --locked --manifest-path rust/tor-poc/Cargo.toml` of this snapshot (rustc 1.99.0, run while writing this stop) finished without errors or warnings. It was not run against the network. The values in `mainnet_eth_config` still match `ElConfig::mainnet()` in `reader.rs` (network id 1, the genesis hash, fork id `07c9462e` with no next fork), but nothing checks that they stay in step. Also: `let _ = advertised;` near the end of `query_over_tor` (line 256) is a leftover that does nothing; `advertised` is an `Option<u64>` that was already used.

*[Protocol & domain](01-primer.md#primer-domain)* The fallback bootnodes (lines 111–132) are the four "legacy" geth mainnet bootnodes, with pubkeys. Since geth moved to EF NodeOps nodes given as ENRs without a `tcp` key, tor-poc has nothing newer to dial over TCP; the doc comment notes that once geth drops the legacy four, the fallback has no upstream list left to mirror.

## Checkpoint

10 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-tor-q1"></a>

**Q1** · Multiple choice

What change let the existing RLPx and eth code run over a Tor stream?

- **A.** A new Tor-specific handshake
- **B.** `RlpxConnection` and `EthSession` became generic over the stream type `S` (default `TcpStream`, bounded by tokio's async read/write traits plus `Unpin`), and `handshake_over` accepts an already-connected stream. Arti's `DataStream` meets those bounds
- **C.** Arti converts Tor streams into `TcpStream`s
- **D.** The code uses `dyn Any` casts

[Answer →](answers.md#a-tor-q1)

<a id="q-tor-q2"></a>

**Q2** · Multiple choice

How does Rust compile `RlpxConnection::handshake_over` for both `TcpStream` and `DataStream`, compared with Java generics?

- **A.** Same as Java: one erased implementation
- **B.** Monomorphisation: the compiler generates a specialised copy per concrete `S`, with static calls and no boxing. Java erases generics to a single implementation that dispatches at run time
- **C.** Rust picks one type at link time
- **D.** It uses reflection

[Answer →](answers.md#a-tor-q2)

<a id="q-tor-q3"></a>

**Q3** · Multiple choice

Why does `pick_working_peer` need the explicit lifetime `'a`?

- **A.** All async functions need lifetimes
- **B.** It returns a reference but has several reference parameters, so elision cannot tell which input the result borrows from. `'a` ties the returned `&Peer` to `peers`
- **C.** `'a` makes the result `'static`
- **D.** To allow mutation of `peers`

[Answer →](answers.md#a-tor-q3)

<a id="q-tor-q4"></a>

**Q4** · Multiple choice

`RlpxConnection::handshake_over(stream, Arc::clone(&key), peer.pubkey)`: what happens to each argument?

- **A.** All three are borrowed
- **B.** `stream` is moved into the connection. The `Arc` handle is cloned (a reference-count bump), so `key` stays usable afterwards. `peer.pubkey`, a `[u8; 64]`, is copied
- **C.** All three are deep-copied
- **D.** `key` is moved and cannot be used any more

[Answer →](answers.md#a-tor-q4)

<a id="q-tor-q5"></a>

**Q5** · Multiple choice

In September, tor-poc failed to compile because `EthConfig` had gained a field that `mainnet_eth_config()` did not set. Why did CI not catch it?

- **A.** CI ignores compile errors
- **B.** `tor-poc` is its own workspace root, excluded from the main workspace, so `cargo build/test --workspace` (and the Gradle tasks built on it) never compile it
- **C.** The field was optional, so it compiled
- **D.** Rust only checks struct literals at run time

[Answer →](answers.md#a-tor-q5)

<a id="q-tor-q6"></a>

**Q6** · Written answer

The handshake works over `TcpStream` without the `flush()` after writing the auth message, but over Arti's `DataStream` it failed with "early eof" until the flush was added. Explain why, and what this says about writing code generic over a stream type.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-tor-q6)

<a id="q-tor-q7"></a>

**Q7** · Multiple choice

`let mut since = || { let d = mark.elapsed().as_millis(); mark = Instant::now(); d };` Why must `since` be declared `mut`?

- **A.** Closures are always mutable
- **B.** The closure assigns to its captured `mark`, so it is `FnMut`; calling an `FnMut` needs a mutable borrow of the closure itself
- **C.** Because `Instant` is not `Copy`
- **D.** So that it can be passed to another thread

[Answer →](answers.md#a-tor-q7)

<a id="q-tor-q8"></a>

**Q8** · Written answer

In `pick_working_peer`, a peer that completes the handshake is matched as `Ok(Ok(mut session))`. Follow the `session` value: who owns it, what happens to the Tor circuit when the arm ends, and what the function returns instead. Why can `best` be read with `map_or` and still be used afterwards?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-tor-q8)

<a id="q-tor-q9"></a>

**Q9** · Multiple choice

`main` builds `ordered_owned: Vec<Peer>` from `ordered: Vec<&Peer>` before calling `pick_working_peer`. Why?

- **A.** To sort the peers
- **B.** `pick_working_peer` takes `&[Peer]`, and a `Vec<&Peer>` derefs to `&[&Peer]`, a different type. `Peer` is not `Clone`, so the code rebuilds each one field by field
- **C.** Because references cannot be stored in a `Vec`
- **D.** To move the peers onto another thread

[Answer →](answers.md#a-tor-q9)

<a id="q-tor-q10"></a>

**Q10** · Multiple choice

Which trust shortcut makes tor-poc a networking proof rather than a production read path?

- **A.** It skips the Merkle proof of the account
- **B.** It verifies the snap proof against the state root of the peer's own claimed head header, not against a beacon-verified anchor
- **C.** It trusts the Tor exit node
- **D.** It uses a fixed, hard-coded state root

[Answer →](answers.md#a-tor-q10)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
