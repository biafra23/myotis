//! M3 / Phase 7 / Rung B — emit a 1-PLUR cheque to a connected mainnet
//! bee peer and observe the stream close behaviour.
//!
//! Stands up a one-shot libp2p host that mirrors `antd`'s transport
//! stack (TCP + DNS + Noise + Yamux + identify + ping + libp2p-stream),
//! resolves `/dnsaddr/mainnet.ethswarm.org` through `ant_p2p::dnsaddr`,
//! dials peers in parallel until one establishes, runs the BZZ
//! handshake to recover the peer's Ethereum EOA, then opens
//! `/swarm/swap/1.0.0/swap` and emits a single
//! `cumulative_payout = 1` PLUR cheque signed against
//! `CHEQUEBOOK_ADDRESS` with the chequebook issuer key in
//! `STORAGE_STAMP_PRIVATE_KEY`.
//!
//! The smoke is *deliberately* tiny: 1 PLUR ≈ 1e-16 BZZ. Cashing it
//! costs the peer ~1e6× the cheque value in gas, so they'd accept
//! the wire transfer (which is what we want to test) and silently
//! drop it instead of cashing — were it not for the result below.
//!
//! ## Observed outcome (2026-05-05 against `mainnet.ethswarm.org` bootnodes)
//!
//! - **TCP / Noise / Yamux**: ✅ connect.
//! - **identify**: ✅ exchanged.
//! - **BZZ handshake `/swarm/handshake/14.0.0/handshake`**: ✅
//!   completes, recovers the peer's overlay + EOA + welcome banner.
//! - **`/swarm/swap/1.0.0/swap` open**: ✅ libp2p substream opens
//!   (we get a `Stream` back).
//! - **Headers exchange**: ❌ bee Reset()s the substream *immediately*
//!   after we write our empty `Headers{}` preamble — zero bytes back,
//!   in 0 ms. A clean `FullClose()` would have flushed bee's empty
//!   response headers first; the immediate-EOF signature matches
//!   bee's `defer { _ = stream.Reset() }` on `Service.handler` error.
//! - **Result**: bee never reads our `EmitCheque`. The cheque does
//!   not land in the peer's chequestore.
//!
//! Independent of `full_node = true | false` in our handshake `Ack`,
//! and independent of post-BZZ settle delay (0 s, 5 s, 30 s).
//!
//! ## Diagnosis (2026-05-05)
//!
//! Original hypothesis was that bee's swap Addressbook only arms a
//! peer for incoming cheques after that peer has *served bee chunks
//! at non-trivial debt* — i.e. bee was rejecting an unsolicited
//! cheque from a "cold" peer.
//!
//! **That diagnosis is now in question.** Tier-1 of the SWAP
//! end-to-end confirmation (block `46019699`, tx
//! `0x643bb08e4485042024604a8ac223a7ea89c594d1a22a27cbba01b4bc9982e308`,
//! see `antctl chequebook cash-self --submit`) caught a real bug in
//! our EIP-712 implementation: bee's chequebook domain is
//! `EIP712Domain(string name,string version,uint256 chainId)` — three
//! fields, *no* `verifyingContract` (per
//! `pkg/crypto/eip712/EIP712DomainType` upstream). Our
//! `eip712_domain_separator` was hashing the four-field
//! OpenZeppelin-default shape and stuffing the chequebook address
//! into the domain. Every cheque this binary previously sent was
//! signed against a digest that bee's chequebook contract would have
//! rejected with `invalid issuer signature` — exactly the kind of
//! failure that would also justify bee's stream-side `Service.handler`
//! erroring and `defer { stream.Reset() }`-ing.
//!
//! Re-running this smoke with the corrected digest is the obvious
//! next step. If bee accepts the cheque this time, the cold-peer
//! hypothesis was wrong and Phase 7 is essentially closed; if the
//! `Reset()` is still immediate, the cold-peer / Addressbook story
//! probably stands and we proceed to wire the auto-settlement trigger
//! into `ant-retrieval::accounting` (PLAN.md §9.0 M3 Phase 7
//! outstanding item).
//!
//! Required env:
//!   `STORAGE_STAMP_PRIVATE_KEY`  - 32-byte secp256k1 secret (chequebook issuer)
//!   `CHEQUEBOOK_ADDRESS`         - 20-byte address (0x… hex)
//! Optional env:
//!   `ANT_NETWORK_ID`             - default 1 (mainnet)
//!   `ANT_CHAIN_ID`               - default 100 (gnosis mainnet)
//!   `ANT_FULL_NODE`              - default true; set to "false" to
//!                                advertise as light node
//!   `RUST_LOG`                   - tracing filter; default "`ant_p2p=info`"

use ant_crypto::HandshakeWireVersion;
use ant_p2p::swap::{emit_cheque, issue_cheque};
use ant_p2p::{handshake_outbound_with_role, PROTOCOL_HANDSHAKE};
use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{dns, identify, identity, noise, ping, tcp, yamux};
use libp2p::{Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use libp2p_stream::Behaviour as StreamBehaviour;
use primitive_types::U256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

#[derive(NetworkBehaviour)]
struct B {
    stream: StreamBehaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

const HANDSHAKE_IDENTIFY_WAIT: Duration = Duration::from_secs(5);
const DIAL_DEADLINE: Duration = Duration::from_secs(45);
const POST_EMIT_OBSERVE: Duration = Duration::from_secs(10);
/// Bee runs `swap.Handshake(peer, beneficiary)` from its swap
/// service's `ConnectIn`/`ConnectOut` callback after the BZZ
/// handshake completes. Until that finishes our peer isn't in
/// bee's swap accounting and the `headler` will error
/// (returning empty headers, which still works) — but bee's
/// `EmitCheque` handler also looks the peer up and rejects if
/// missing. Sleep long enough that the registration completes.
const POST_BZZ_SETTLE: Duration = Duration::from_secs(5);

fn parse_hex_secret(name: &str) -> [u8; 32] {
    let s = std::env::var(name).unwrap_or_else(|_| panic!("env {name} missing"));
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("decode {name}: {e}"));
    out
}

fn parse_hex_addr(name: &str) -> [u8; 20] {
    let s = std::env::var(name).unwrap_or_else(|_| panic!("env {name} missing"));
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let mut out = [0u8; 20];
    hex::decode_to_slice(s, &mut out).unwrap_or_else(|e| panic!("decode {name}: {e}"));
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,ant_p2p=info")),
        )
        .try_init();

    let secret = parse_hex_secret("STORAGE_STAMP_PRIVATE_KEY");
    let chequebook = parse_hex_addr("CHEQUEBOOK_ADDRESS");
    let network_id: u64 = std::env::var("ANT_NETWORK_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let chain_id: u64 = std::env::var("ANT_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut sk_copy = secret;
    let sk = identity::secp256k1::SecretKey::try_from_bytes(&mut sk_copy)?;
    let kp_secp = identity::secp256k1::Keypair::from(sk);
    let kp = identity::Keypair::from(kp_secp);
    let local_peer_id = kp.public().to_peer_id();

    let our_eth = {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_bytes((&secret).into())?;
        let vk = k256::ecdsa::VerifyingKey::from(&sk);
        ant_crypto::ethereum_address_from_public_key(&vk)
    };

    println!("== M3 Phase 7 Rung B — outbound cheque smoke ==");
    println!("  local libp2p peer:   {local_peer_id}");
    println!("  our eth (issuer):    0x{}", hex::encode(our_eth));
    println!("  chequebook:          0x{}", hex::encode(chequebook));
    println!("  network_id:          {network_id}");
    println!("  chain_id:            {chain_id}");

    let id_cfg = identify::Config::new("bee/2.7.0".into(), kp.public())
        .with_agent_version("ant-cheque-smoke/0.1.0".into());
    let behaviour = B {
        stream: StreamBehaviour::default(),
        identify: identify::Behaviour::new(id_cfg),
        ping: ping::Behaviour::new(ping::Config::new()),
    };

    let mut swarm = SwarmBuilder::with_existing_identity(kp)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns_config(
            dns::ResolverConfig::cloudflare(),
            dns::ResolverOpts::default(),
        )
        .with_behaviour(|_| behaviour)
        .expect("infallible behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_mins(2)))
        .build();

    let mut control = swarm.behaviour().stream.new_control();

    let bootnodes = ant_p2p::default_mainnet_bootnodes();
    println!(
        "\n[1/4] resolving {} dnsaddr bootnode roots",
        bootnodes.len()
    );
    let resolved = ant_p2p::dnsaddr::resolve_all(bootnodes).await;
    println!("       resolved {} concrete multiaddrs", resolved.len());
    if resolved.is_empty() {
        return Err("no bootnodes resolved".into());
    }

    println!("\n[2/4] dialing bootnodes in parallel");
    for addr in &resolved {
        match swarm.dial(addr.clone()) {
            Ok(()) => {}
            Err(e) => eprintln!("       dial init failed for {addr}: {e}"),
        }
    }

    let mut identify_signals: HashMap<PeerId, oneshot::Sender<()>> = HashMap::new();
    let (peer_id, peer_addr) = {
        let (peer_idnt_tx, peer_idnt_rx) = oneshot::channel::<(PeerId, Multiaddr)>();
        let mut peer_idnt_tx = Some(peer_idnt_tx);
        let dial_deadline = Instant::now() + DIAL_DEADLINE;
        let drive = async {
            loop {
                let evt = swarm.next().await;
                match evt {
                    Some(SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    }) => {
                        let addr = match &endpoint {
                            ConnectedPoint::Dialer { address, .. } => address.clone(),
                            ConnectedPoint::Listener { send_back_addr, .. } => {
                                send_back_addr.clone()
                            }
                        };
                        println!("       connected: peer={peer_id} addr={addr}");
                        let (tx, rx) = oneshot::channel();
                        identify_signals.insert(peer_id, tx);
                        // Wait until we've seen identify so the BZZ handshake has
                        // a chance — start a side task that on the FIRST identify
                        // for this peer fires the channel sent up to the smoke.
                        std::mem::drop(rx);
                        if let Some(tx) = peer_idnt_tx.take() {
                            let _ = tx.send((peer_id, addr));
                        }
                    }
                    Some(SwarmEvent::OutgoingConnectionError { peer_id, error, .. }) => {
                        eprintln!("       dial error peer={peer_id:?}: {error}");
                    }
                    Some(SwarmEvent::Behaviour(BEvent::Identify(identify::Event::Received {
                        peer_id,
                        ..
                    }))) => {
                        println!("       identify received: peer={peer_id}");
                        if let Some(tx) = identify_signals.remove(&peer_id) {
                            let _ = tx.send(());
                        }
                    }
                    _ => {}
                }
                if Instant::now() > dial_deadline {
                    return Err::<(PeerId, Multiaddr), Box<dyn std::error::Error>>(
                        "dial deadline reached, no peer connected".into(),
                    );
                }
            }
        };
        let pick = async {
            peer_idnt_rx
                .await
                .map_err(|_| -> Box<dyn std::error::Error> { "peer pick channel dropped".into() })
        };
        tokio::select! {
            r = drive => return Err(r.err().unwrap_or_else(|| "drive ended".into())),
            r = pick => r?,
        }
    };

    // Hand the swarm off to a background task for ongoing event drain
    // (identify, ping, libp2p-stream substream notifications).
    tokio::spawn(async move {
        loop {
            if swarm.next().await.is_none() {
                break;
            }
        }
    });

    println!("\n[3/4] running BZZ handshake against {peer_id}");
    // Brief settle: give identify a chance to round-trip so bee's
    // peerstore has our advertised addresses before we open BZZ.
    tokio::time::sleep(HANDSHAKE_IDENTIFY_WAIT).await;

    let proto = StreamProtocol::new(PROTOCOL_HANDSHAKE);
    let stream = control.open_stream(peer_id, proto).await?;
    let overlay_nonce = [0u8; 32]; // smoke-only; real antd persists this
                                   // Advertise full_node = true so bee's swap handler accepts our
                                   // cheques. Bee rejects emit_cheque from peers it knows as light
                                   // nodes (`if !p.FullNode { return errNotFullNode }`). We'll
                                   // confirm the rejection vs acceptance directly by comparing the
                                   // two runs; flip ANT_FULL_NODE=false to reproduce the rejection.
    let advertise_full_node: bool = std::env::var("ANT_FULL_NODE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(true);
    let info = handshake_outbound_with_role(
        stream,
        local_peer_id,
        peer_id,
        &secret,
        &overlay_nonce,
        network_id,
        std::slice::from_ref(&peer_addr),
        Vec::new(),
        advertise_full_node,
        HandshakeWireVersion::V15,
    )
    .await?;

    println!("       handshake ok:");
    println!(
        "         remote_overlay:     0x{}",
        hex::encode(info.remote_overlay)
    );
    println!(
        "         remote_eth_address: 0x{}",
        hex::encode(info.remote_eth_address)
    );
    println!("         remote_full_node:   {}", info.remote_full_node);
    println!("         remote_welcome:     {:?}", info.remote_welcome);

    println!(
        "\n[settle] sleeping {} s so bee's swap.Handshake() runs before we open the swap stream",
        POST_BZZ_SETTLE.as_secs(),
    );
    tokio::time::sleep(POST_BZZ_SETTLE).await;

    // [4a] Diagnostic FIRST — open a swap stream, write empty headers,
    // dump whatever bytes bee responds with (or report EOF). We do this
    // before the full emit_cheque so the connection is fresh.
    println!("\n[4a/diag] opening swap stream, writing empty headers, dumping bee's response");
    use futures::AsyncReadExt as _;
    use futures::AsyncWriteExt as _;
    let proto = StreamProtocol::new(ant_p2p::swap::PROTOCOL_SWAP);
    match control.open_stream(peer_id, proto).await {
        Ok(mut stream) => {
            let t = Instant::now();
            let _ = stream.write_all(&[0x00]).await;
            let _ = stream.flush().await;
            println!(
                "       wrote 1 byte (varint length 0 = empty Headers) in {} ms",
                t.elapsed().as_millis()
            );
            let mut buf = [0u8; 1024];
            let read_t = Instant::now();
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    println!(
                        "       bee sent {n} bytes in {} ms: {}",
                        read_t.elapsed().as_millis(),
                        if n == 0 {
                            "[EOF, peer closed write side]".to_string()
                        } else {
                            format!("hex={}", hex::encode(&buf[..n]))
                        }
                    );
                    if n > 0 {
                        // Try a second read in case bee sends more
                        let mut buf2 = [0u8; 1024];
                        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf2))
                            .await
                        {
                            Ok(Ok(m)) if m > 0 => {
                                println!(
                                    "       bee sent {m} more bytes: hex={}",
                                    hex::encode(&buf2[..m])
                                );
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Err(e)) => println!("       read err: {e}"),
                Err(_) => println!("       timeout, bee sent no bytes in 5 s"),
            }
            let _ = stream.close().await;
        }
        Err(e) => println!("       diag open_stream err: {e}"),
    }

    println!(
        "\n[4b] signing + emitting 1-PLUR cheque (chequebook=0x{}, beneficiary=0x{})",
        hex::encode(chequebook),
        hex::encode(info.remote_eth_address)
    );
    let signed = issue_cheque(
        &secret,
        chequebook,
        info.remote_eth_address,
        U256::from(1u64),
        chain_id,
    )?;
    println!(
        "       cheque signature: 0x{}",
        hex::encode(signed.signature)
    );

    let t0 = Instant::now();
    match emit_cheque(&mut control, peer_id, &signed).await {
        Ok(()) => {
            println!(
                "       OK — emit_cheque returned in {} ms (stream closed cleanly from our side)",
                t0.elapsed().as_millis()
            );
        }
        Err(e) => {
            println!(
                "       ERR — emit_cheque failed in {} ms: {e}",
                t0.elapsed().as_millis()
            );
        }
    }

    // Hold the connection open briefly so we can observe whether bee
    // resets it post-emit (rejection signal), keeps it alive (cheque
    // accepted, reply absent), or just lets it idle.
    println!(
        "\n[obs] holding connection for {} s to observe peer-side behaviour…",
        POST_EMIT_OBSERVE.as_secs()
    );
    tokio::time::sleep(POST_EMIT_OBSERVE).await;
    println!("done.");
    Ok(())
}
