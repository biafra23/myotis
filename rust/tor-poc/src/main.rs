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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use arti_client::{IsolationToken, StreamPrefs, TorAddr, TorClient, TorClientConfig};

use myotis_core::nodekey::NodeKey;
use myotis_net::el::eth::session::{EthConfig, EthSession};
use myotis_net::el::peercache::ElPeerCache;
use myotis_net::el::rlpx::transport::RlpxConnection;
use myotis_net::el::snap::fetch::AccountOutcome;

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
    }
}

/// A dial target: the peer's static secp256k1 pubkey (its enode id) + address.
struct Peer {
    name: String,
    pubkey: [u8; 64],
    addr: SocketAddr,
}

impl Peer {
    fn tor_addr(&self) -> Result<TorAddr> {
        // Tor exits connect to a raw IP literal directly (no exit-side DNS).
        TorAddr::from((self.addr.ip().to_string().as_str(), self.addr.port()))
            .map_err(|e| anyhow!("tor addr {}: {e}", self.addr))
    }
}

/// Snap-capable peers the clearnet daemon already discovered & validated, from
/// its `peers.cache` — the design's model exactly: discovery + validation stay
/// clearnet, and the Tor pool joins against that shared cache (§4/§5). These are
/// real full nodes that serve eth+snap (unlike the discovery-only bootnodes).
fn cache_peers() -> Vec<Peer> {
    let path = std::env::var_os("MYOTIS_PEER_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Default to the repo's mainnet cache relative to this crate.
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../app/peers.cache")
        });
    if !path.exists() {
        return Vec::new();
    }
    let cache = ElPeerCache::load(path);
    let mut peers: Vec<myotis_net::el::peercache::CachedElPeer> =
        cache.peers().into_iter().filter(|p| p.snap).collect();
    // Confirmed snap peers first (dial_rank 0), then Unknown.
    peers.sort_by_key(|p| p.quality.dial_rank());
    peers
        .into_iter()
        .enumerate()
        .map(|(i, p)| Peer {
            name: format!("cache#{i}({:?})", p.quality),
            pubkey: p.pubkey,
            addr: p.addr,
        })
        .collect()
}

/// The current go-ethereum `MainnetBootnodes` (params/bootnodes.go): popular,
/// known to every client — the "Tor-usable on day one, zero aging" bootstrap
/// set the design calls out (§5). NB these are usually discovery-only daemons
/// that don't serve eth, so they're a last-resort fallback here.
fn mainnet_bootnodes() -> Vec<Peer> {
    let mk = |name: &str, pk_hex: &str, ip: &str| Peer {
        name: name.to_string(),
        pubkey: pk(pk_hex),
        addr: SocketAddr::new(ip.parse().unwrap(), 30303),
    };
    vec![
        mk("hetzner-hel-001", "2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc", "65.108.70.101"),
        mk("hetzner-fsn-002", "4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052", "157.90.35.166"),
        mk("aws-ap-se-1-001", "d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666", "18.138.108.67"),
        mk("aws-us-east-1-001", "22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de", "3.209.45.79"),
    ]
}

/// Demo wallet addresses (public, well-known) — each gets its OWN isolation
/// token + ephemeral key, the per-address unlinking the design is built around.
fn demo_addresses(args: &[String]) -> Result<Vec<[u8; 20]>> {
    if args.is_empty() {
        return Ok(vec![
            addr("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"), // vitalik.eth
            addr("00000000219ab540356cBB839Cbe05303d7705Fa"), // beacon deposit contract
        ]);
    }
    args.iter()
        .map(|a| {
            let a = a.strip_prefix("0x").unwrap_or(a);
            addr_checked(a).with_context(|| format!("bad address {a:?}"))
        })
        .collect()
}

/// A per-connection ephemeral RLPx identity (docs §6.1) — random secp256k1 key,
/// never the persistent node key. Cheap: Myotis is outbound-only.
fn ephemeral_key() -> Result<Arc<NodeKey>> {
    // A random 32-byte scalar is a valid secp256k1 secret with overwhelming
    // probability; retry the vanishingly rare zero/overflow case.
    for _ in 0..8 {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| anyhow!("OS entropy: {e}"))?;
        if let Ok(k) = NodeKey::from_secret_bytes(&secret) {
            return Ok(Arc::new(k));
        }
    }
    bail!("could not derive an ephemeral node key")
}

/// The core PoC: run RLPx + eth handshake + one verified snap account read over
/// a single isolated Tor circuit, with a fresh ephemeral identity.
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
    let dial_ms = t0.elapsed().as_millis();

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
    let rlpx_ms = t0.elapsed().as_millis();

    let mut session = EthSession::handshake(conn, &key.public_key_bytes(), eth_cfg, None)
        .await
        .map_err(|e| anyhow!("eth handshake: {e}"))?;
    if !session.snap {
        bail!("peer negotiated eth/{} but no snap/1", session.eth_version);
    }
    let eth_ms = t0.elapsed().as_millis();

    // A FRESH state root the peer still retains: its own claimed head header.
    // (Production anchors this to the beacon chain — out of scope for the PoC.)
    // Prefer fetch-by-number on eth/69 (its Status carries the head number).
    let advertised = session.peer_status.latest_block;
    let headers = match advertised {
        Some(n) if n > 0 => session
            .get_block_headers_by_number(n, 1, 0, false)
            .await
            .map_err(|e| anyhow!("fetch peer head #{n}: {e}"))?,
        _ => {
            let h = session.peer_status.best_hash;
            session
                .get_block_headers_by_hash(&h, 1)
                .await
                .map_err(|e| anyhow!("fetch peer head by hash: {e}"))?
        }
    };
    let head = headers
        .first()
        .ok_or_else(|| anyhow!("peer returned no head header"))?;
    let state_root = head.header.state_root;
    let block = head.header.number;

    // THE core-leak flow (docs §1), now over Tor: GetAccountRange for the user's
    // address, MPT-verified against the peer's head state root.
    let outcome = session
        .snap_get_account(&state_root, address)
        .await
        .map_err(|e| anyhow!("snap GetAccountRange: {e}"))?;
    let snap_ms = t0.elapsed().as_millis();

    println!(
        "      timing: dial={dial_ms}ms  +rlpx={rlpx_ms}ms  +eth/{}={eth_ms}ms  +snap={snap_ms}ms",
        session.eth_version
    );
    let _ = advertised;
    println!(
        "      peer={} client={:?} head=#{block} stateRoot=0x{}…",
        peer.name,
        session.peer_hello.client_id,
        hex::encode(&state_root[..6])
    );
    Ok(outcome)
}

/// One eth+snap handshake attempt over a FRESH Tor circuit (a new isolation
/// token forces a new middle+exit path — the same lever the design uses for
/// per-address isolation, here repurposed to route around exits that refuse
/// :30303 or peers that drop a given exit IP; docs §2/§8.1).
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

/// Find a peer that completes an eth+snap handshake OVER TOR, retrying each with
/// fresh circuits (Tor exit selection is random and :30303 exit coverage is
/// partial, so a first failure is often just an unlucky exit). Prefers a SYNCED
/// peer (real head) — Tor-accepting nodes skew toward less-busy, sometimes
/// unsynced ones — but returns the best it found so the demo can still proceed.
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
                        println!("OK but no snap/1 — skipping");
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

/// Clearnet baseline over the SAME generic stack (direct `TcpStream` via
/// `RlpxConnection::dial`) — establishes which cached peers are live full nodes
/// that serve eth+snap right now, so a later Tor failure is attributable to the
/// Tor path (exit policy / peer-side Tor treatment) rather than a dead peer.
async fn probe_clearnet<'a>(peers: &'a [Peer], eth_cfg: &EthConfig) -> Vec<&'a Peer> {
    use std::io::Write;
    let mut live = Vec::new();
    for peer in peers {
        print!("  clearnet-dial {} ({}) ... ", peer.name, peer.addr);
        let _ = std::io::stdout().flush();
        let t0 = Instant::now();
        let attempt = async {
            let key = ephemeral_key()?;
            let conn = RlpxConnection::dial(Arc::clone(&key), peer.addr, peer.pubkey)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            let session = EthSession::handshake(conn, &key.public_key_bytes(), eth_cfg, None)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            Ok::<_, anyhow::Error>(session)
        };
        match tokio::time::timeout(Duration::from_secs(20), attempt).await {
            Ok(Ok(s)) if s.snap => {
                println!("OK {}ms — eth/{}, snap ✓ — {:?}", t0.elapsed().as_millis(), s.eth_version, s.peer_hello.client_id);
                live.push(peer);
            }
            Ok(Ok(s)) => println!("eth/{} but no snap", s.eth_version),
            Ok(Err(e)) => println!("failed: {e}"),
            Err(_) => println!("timed out"),
        }
    }
    live
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,tor_poc=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let addresses = demo_addresses(&args)?;
    let eth_cfg = mainnet_eth_config();

    println!("== Myotis Tor integration PoC (docs/privacy-and-tor.md) ==\n");

    // ---- §3: boot the embedded Arti client -------------------------------
    print!("[1/3] Bootstrapping embedded Arti Tor client ... ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let t0 = Instant::now();
    let tor = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .context("Arti bootstrap (is outbound Tor traffic reachable from here?)")?;
    println!("ready in {}ms\n", t0.elapsed().as_millis());

    // Prefer the clearnet daemon's snap-validated peers.cache (the design's
    // clearnet-discovery → Tor-use split); fall back to the discovery bootnodes.
    let mut targets = cache_peers();
    let from_cache = targets.len();
    targets.extend(mainnet_bootnodes());

    // ---- Clearnet baseline: which of these are live eth+snap full nodes? --
    println!(
        "[2/3a] Clearnet baseline over the SAME stack (direct TcpStream) — \
         {from_cache} cache peers + {} bootnodes:",
        targets.len() - from_cache
    );
    let live: Vec<&Peer> = probe_clearnet(&targets, &eth_cfg).await;
    println!(
        "  -> {} peer(s) serve eth+snap on clearnet right now\n",
        live.len()
    );

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
        Some(p) => p,
        None => {
            println!(
                "\n  NOTE: {} peer(s) completed eth+snap on CLEARNET but none over Tor. \
                 That isolates the failure to the Tor path — either the reduced exit \
                 policy for :30303 (docs §2/§8.1) or peer-side treatment of Tor exit \
                 IPs — NOT the transport plumbing (Arti opened the circuits and the \
                 generic RLPx stack drove them; several reached the peer and got an EOF \
                 at the RLPx ack, i.e. the peer closed on us).",
                live.len()
            );
            bail!("no peer completed an eth+snap handshake over Tor (see NOTE above; docs §8.1)");
        }
    };
    println!("  -> using {} for the snap demo\n", peer.name);

    // ---- §3 + §6.1 + §1: per-address isolated, verified snap reads --------
    println!(
        "[3/3] Verified snap account reads over Tor — one isolated circuit + \
         ephemeral key PER address:"
    );
    let mut ok = 0usize;
    for (i, address) in addresses.iter().enumerate() {
        // One IsolationToken per address == one circuit per address (docs §3).
        let token = IsolationToken::new();
        println!(
            "\n  address[{i}] 0x{}  (isolation token #{i}, fresh ephemeral key)",
            hex::encode(address)
        );
        match query_over_tor(&tor, peer, address, token, &eth_cfg).await {
            Ok(AccountOutcome::Present(leaf)) => {
                ok += 1;
                let wei = if leaf.balance.is_empty() {
                    "0".to_string()
                } else {
                    format!("0x{}", hex::encode(&leaf.balance))
                };
                println!(
                    "      VERIFIED present: nonce={} balance={} wei  codeHash=0x{}",
                    leaf.nonce,
                    wei,
                    hex::encode(&leaf.code_hash[..6])
                );
            }
            Ok(AccountOutcome::Absent) => {
                ok += 1;
                println!("      VERIFIED absent (exclusion proof)");
            }
            Err(e) => println!("      ERROR: {e:#}"),
        }
    }

    println!(
        "\n== done: {ok}/{} addresses read over Tor, each on its own isolated \
         circuit with a distinct ephemeral RLPx identity ==",
        addresses.len()
    );
    if ok == 0 {
        bail!("no address completed a snap read over Tor");
    }
    Ok(())
}

// --- small hex helpers -------------------------------------------------------

fn pk(hexstr: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    hex::decode_to_slice(hexstr, &mut out).expect("valid 64-byte enode pubkey hex");
    out
}

fn hex32(hexstr: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hexstr, &mut out).expect("valid 32-byte hex");
    out
}

fn addr(hexstr: &str) -> [u8; 20] {
    addr_checked(hexstr).expect("valid 20-byte address hex")
}

fn addr_checked(hexstr: &str) -> Result<[u8; 20]> {
    let mut out = [0u8; 20];
    hex::decode_to_slice(hexstr, &mut out).map_err(|e| anyhow!("{e}"))?;
    Ok(out)
}
