//! Tor transport for the verified-read path (`docs/privacy-and-tor.md`).
//!
//! Feature-gated (`tor`): only a host that builds `myotis-net` with
//! `--features tor` pulls Arti; every other build (Android/iOS/daemon) never
//! sees this module. It owns a process-wide, lazily-bootstrapped Arti
//! [`TorClient`] and hands the reader a per-address ISOLATED [`EthSession`] over
//! a Tor `DataStream`, with a FRESH ephemeral RLPx identity per connection.
//!
//! Scope (matches the design's §4 split): only the sensitive verified reads are
//! routed here. Discovery and clearnet snap-peer validation stay on the real IP.
//! What is NOT here yet: the quarantined peer pool + aging window (§5) and
//! multi-source popularity promotion (§6.2) — this reuses whatever the clearnet
//! pool already validated. Enabling Tor is therefore a network-privacy win
//! (peer/exit see a Tor exit IP, never the user's) but not yet the full
//! unlinkability the design targets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arti_client::{IsolationToken, StreamPrefs, TorAddr, TorClient, TorClientConfig};
use tokio::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

use crate::el::eth::session::{EthConfig, EthSession};
use crate::el::rlpx::transport::RlpxConnection;

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

/// Enable/disable Tor for subsequent verified reads. Idempotent; cheap.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::SeqCst);
    if on {
        tracing::info!("tor: verified-read routing ENABLED");
    } else {
        tracing::info!("tor: verified-read routing disabled");
    }
}

/// Whether verified reads should route over Tor.
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// Whether the shared Tor client has finished bootstrapping (for host status).
pub fn is_bootstrapped() -> bool {
    CLIENT.get().is_some()
}

fn isolation_for(address: &[u8; 20]) -> IsolationToken {
    let mut guard = ISOLATION.lock().expect("tor isolation map");
    let map = guard.get_or_insert_with(HashMap::new);
    *map.entry(*address).or_insert_with(IsolationToken::new)
}

/// Bootstrap-once accessor for the shared Tor client.
async fn client() -> Result<&'static Arc<TorClient<PreferredRuntime>>, String> {
    CLIENT
        .get_or_try_init(|| async {
            tracing::info!("tor: bootstrapping embedded Arti client (first use)…");
            let c = TorClient::create_bootstrapped(TorClientConfig::default())
                .await
                .map_err(|e| format!("tor bootstrap: {e}"))?;
            tracing::info!("tor: Arti client bootstrapped");
            Ok::<_, String>(c)
        })
        .await
}

/// Open a per-address ISOLATED Tor circuit to `addr` (identity `pubkey`, already
/// clearnet-validated) and run the RLPx + eth/snap handshake with a fresh
/// ephemeral key, returning a READY snap-capable session. The whole dial is
/// bounded (Tor's multi-hop path can hang on a bad exit).
pub async fn open_snap_session(
    address: &[u8; 20],
    addr: SocketAddr,
    pubkey: [u8; 64],
    eth_cfg: &EthConfig,
) -> Result<EthSession<arti_client::DataStream>, String> {
    let tor = client().await?;

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(isolation_for(address));
    let target = TorAddr::from((addr.ip().to_string().as_str(), addr.port()))
        .map_err(|e| format!("tor addr {addr}: {e}"))?;
    let stream = tor
        .connect_with_prefs(target, &prefs)
        .await
        .map_err(|e| format!("tor connect {addr}: {e}"))?;

    // Fresh ephemeral RLPx identity per connection (docs §6.1) — never the
    // persistent node key. Reuses the reader's key generator (one source of truth).
    let key = crate::el::reader::generate_node_key()?;
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        RlpxConnection::handshake_over(stream, Arc::clone(&key), pubkey),
    )
    .await
    .map_err(|_| format!("tor rlpx handshake timed out to {addr}"))?
    .map_err(|e| format!("tor rlpx handshake to {addr}: {e}"))?;

    let session = EthSession::handshake(conn, &key.public_key_bytes(), eth_cfg, None)
        .await
        .map_err(|e| format!("tor eth handshake to {addr}: {e}"))?;
    if !session.snap {
        return Err(format!("tor: peer {addr} did not negotiate snap/1"));
    }
    Ok(session)
}
