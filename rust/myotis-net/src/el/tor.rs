//! Tor transport for the verified-read path (`docs/privacy-and-tor.md`).
//!
//! Feature-gated (`tor`): only a host that builds `myotis-net` with
//! `--features tor` (`-PtorEngine`: the desktop dylib, the Android jniLibs)
//! pulls Arti; every other build (iOS/daemon, and any build without the flag)
//! never sees this module. It owns a process-wide, lazily-bootstrapped Arti
//! [`TorClient`] and hands the reader a per-address ISOLATED [`EthSession`] over
//! a Tor `DataStream`, with a FRESH ephemeral RLPx identity per connection.
//!
//! Android differs in two ways (see the TLS note in this crate's Cargo.toml):
//! Arti runs on rustls there, whose process-default `CryptoProvider` this
//! module installs before the first bootstrap, and Arti's default directories
//! derive from `$HOME`, which an app process has no usable value for — so on
//! Android the host MUST name them first ([`set_storage_dirs`]) or the
//! bootstrap is refused.
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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arti_client::config::TorClientConfigBuilder;
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

/// Where Arti keeps its state (guard selection, …) and its directory cache, as
/// set by the host ([`set_storage_dirs`]). `in_use` is set while a bootstrap
/// holds them (from the moment it reads its config until it fails or for good
/// once it succeeds), and from then on the directories cannot move.
struct Storage {
    dirs: Option<(PathBuf, PathBuf)>,
    in_use: bool,
}

static STORAGE: Mutex<Storage> = Mutex::new(Storage { dirs: None, in_use: false });

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

/// Name the directories Arti keeps its state and its directory cache in (both
/// absolute; Arti creates them on first use). Answers whether the client will
/// use exactly these: before the first bootstrap any pair is taken, while a
/// bootstrap holds its directories only the same pair answers `true` — a
/// different one is REFUSED (`false`), never recorded and silently ignored. A
/// relative or empty path is refused too: it would resolve against whatever
/// the process's working directory happens to be.
pub fn set_storage_dirs(state_dir: &str, cache_dir: &str) -> bool {
    let (state, cache) = (Path::new(state_dir), Path::new(cache_dir));
    if !state.is_absolute() || !cache.is_absolute() {
        tracing::warn!("tor: storage dirs must be absolute (state {state_dir:?}, cache {cache_dir:?})");
        return false;
    }
    let mut s = STORAGE.lock().expect("tor storage");
    let asked = (state.to_path_buf(), cache.to_path_buf());
    if s.in_use {
        return s.dirs.as_ref() == Some(&asked);
    }
    tracing::info!("tor: Arti state in {}, cache in {}", asked.0.display(), asked.1.display());
    s.dirs = Some(asked);
    true
}

/// The config the bootstrap runs with, marking the storage as in use. Off
/// Android an unset pair means Arti's platform defaults; on Android it is an
/// error, since those defaults derive from `$HOME` (module docs).
fn take_config() -> Result<TorClientConfig, String> {
    let mut s = STORAGE.lock().expect("tor storage");
    let config = match &s.dirs {
        Some((state, cache)) => TorClientConfigBuilder::from_directories(state, cache)
            .build()
            .map_err(|e| format!("tor config: {e}"))?,
        None if cfg!(target_os = "android") => {
            return Err("tor: no storage directory configured — the host must call \
                        set_tor_storage_dirs before the first Tor read"
                .to_string())
        }
        None => TorClientConfig::default(),
    };
    s.in_use = true;
    Ok(config)
}

/// Releases the storage [`take_config`] marked as in use when dropped with
/// `release` still set — cleared once the bootstrap succeeds. A bootstrap that
/// fails, or whose future a caller's read timeout drops part-way, holds
/// nothing, so the next attempt may run from other directories.
struct StorageHold {
    release: bool,
}

impl Drop for StorageHold {
    fn drop(&mut self) {
        // Never panic in drop: a poisoned lock just keeps the directories pinned.
        if self.release {
            if let Ok(mut s) = STORAGE.lock() {
                s.in_use = false;
            }
        }
    }
}

/// Arti's rustls backend needs a process-default `CryptoProvider` and panics
/// without one (tor-rtcompat's `RustlsProvider::new`). ring is the provider
/// libp2p-quic already links on this target. An `Err` here means a provider is
/// already installed, which serves Arti just as well.
#[cfg(target_os = "android")]
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(not(target_os = "android"))]
fn ensure_crypto_provider() {}

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
        return Err(format!("tor: peer {addr} did not negotiate snap"));
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test, because STORAGE is process-global: separate tests would race
    // on it under the default parallel test runner.
    #[test]
    fn storage_dirs_are_applied_or_refused() {
        // Relative and empty paths are refused before anything is recorded.
        assert!(!set_storage_dirs("state", "/abs/cache"));
        assert!(!set_storage_dirs("/abs/state", ""));
        assert!(STORAGE.lock().unwrap().dirs.is_none());

        // Before a bootstrap holds them, the last pair wins.
        assert!(set_storage_dirs("/a/state", "/a/cache"));
        assert!(set_storage_dirs("/b/state", "/b/cache"));
        take_config().expect("configured dirs build a config");

        // Held: the same pair is still answered true, any other is refused
        // and leaves the held pair alone.
        assert!(set_storage_dirs("/b/state", "/b/cache"));
        assert!(!set_storage_dirs("/c/state", "/c/cache"));
        assert_eq!(
            STORAGE.lock().unwrap().dirs,
            Some((PathBuf::from("/b/state"), PathBuf::from("/b/cache")))
        );

        // A bootstrap that succeeded keeps them; one that failed or was
        // dropped part-way releases them: movable again.
        drop(StorageHold { release: false });
        assert!(!set_storage_dirs("/c/state", "/c/cache"));
        drop(StorageHold { release: true });
        assert!(set_storage_dirs("/c/state", "/c/cache"));
    }
}
