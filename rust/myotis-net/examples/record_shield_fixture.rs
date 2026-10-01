//! Record the mainnet RelayAdapt7702 shield fixture (#509 stage 2, part 3).
//!
//! RAILGUN's wallet shields ETH through a fresh EIP-7702 account: a type-4
//! transaction delegates the account to RelayAdapt7702 and calls it, and the
//! account wraps the ETH and shields it into RAILGUN. This builds that
//! transaction with throwaway keys and runs it through this engine's VERIFIED
//! mainnet state (snap proofs against the beacon-anchored execution header).
//! It records every account, slot and bytecode the runs read, into the
//! fixture the replay tests run:
//!
//! ```bash
//! cargo run --release -p myotis-net --example record_shield_fixture
//! # → rust/testdata/evm/relayadapt7702-shield.json, then:
//! cargo test -p myotis-evm relay_adapt_7702_shield
//! ./gradlew :myotis-evm:test --tests '*RelayAdapt7702ShieldFixtureTest' -PskipRustEngine
//! ```
//!
//! Options:
//! - `--out <path>`: where to write the fixture (default: the committed path).
//! - `--delegate current`: delegate to the RelayAdapt7702 that
//!   `@railgun-community/shared-models` names for mainnet today, instead of
//!   #509's (`0x05ae73…`, which Terminal Wallet 2.0.2 used).
//! - `--peer-cache <path>`: the EL peer cache to start discovery from and to
//!   keep the peers it finds in. Default: the recorder's own,
//!   `rust/target/record_shield_fixture/peers.cache`. Never point it at the
//!   cache of a Myotis that is running.
//!
//! It syncs the light client first (minutes, from the embedded checkpoint),
//! then waits until the EL reader has snap peers and a verified head it can
//! serve. Finding snap peers from scratch is slow on mainnet (no pinned
//! enodes, #414), so on its first run the recorder seeds its own peer cache
//! with a copy of the newest one an installed Myotis keeps (`~/.myotis`, the
//! RAILGUN PoC build's `~/.myotis-railgun-poc`, or the daemon's `app/`), and
//! it keeps every snap peer it proves there for the next run. If a recording
//! fails (a peer vanishes, the head moves past what peers serve), it retries
//! at a fresh head with fresh keys.
//!
//! Privacy: the keys come from OS randomness for this run only and are never
//! written anywhere. The fixture holds two fresh addresses, the signed
//! request, and public contract state. No wallet's data is involved.

use std::path::{Path, PathBuf};
use std::time::Duration;

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_evm::fixture::relay_adapt_7702::{self as railgun, ShieldParams};
use myotis_evm::fixture::{hex0x, EvmFixture};
use myotis_evm::U256;
use myotis_net::el::reader::ElReader;
use myotis_net::{ChainConfig, SyncHandle, SyncState};

/// How long the light client gets to reach SYNCED.
const SYNC_BUDGET: Duration = Duration::from_secs(1500);
/// How long the EL reader gets, over all attempts, to find snap peers and
/// verify a head it can serve state for.
const READY_BUDGET: Duration = Duration::from_secs(1800);
/// How often the wait for a servable head reports progress.
const PROGRESS_EVERY: Duration = Duration::from_secs(60);
/// Recordings tried before giving up, each at a fresh head with fresh keys.
const ATTEMPTS: usize = 5;
const MAINNET: u64 = 1;
/// 0.01 ETH, a small shield like #509's.
const SHIELD_WEI: u128 = 10_000_000_000_000_000;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,myotis_net=warn".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let out = arg("--out").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/evm/relayadapt7702-shield.json")
    });
    let delegate = match arg("--delegate").as_deref() {
        None => railgun::RELAY_ADAPT_7702_OF_509,
        Some("current") => railgun::MAINNET_RELAY_ADAPT_7702,
        Some(other) => fail(&format!("--delegate takes `current` (got {other})")),
    };

    let peer_cache = arg("--peer-cache").map(PathBuf::from).unwrap_or_else(|| {
        let own = own_peer_cache();
        seed_peer_cache(&own);
        own
    });

    tracing::info!("syncing the mainnet light client");
    let sync = SyncHandle::start(ChainConfig::mainnet()).unwrap_or_else(|e| fail(&format!("light client: {e}")));
    let deadline = tokio::time::Instant::now() + SYNC_BUDGET;
    loop {
        let s = sync.status();
        if s.state == SyncState::Synced {
            tracing::info!(finalized_slot = s.finalized_slot, "light client SYNCED");
            break;
        }
        if s.state == SyncState::StaleAnchor {
            fail(
                "the embedded mainnet checkpoint is past its weak-subjectivity bound; refresh it \
                 (./gradlew refreshCheckpoint -Pnetwork=mainnet) and run again",
            );
        }
        if tokio::time::Instant::now() > deadline {
            fail(&format!("the light client did not reach SYNCED within {} s ({})", SYNC_BUDGET.as_secs(), s.state));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let reader = ElReader::start_mainnet(sync.exec_anchor(), Some(peer_cache.clone()))
        .await
        .unwrap_or_else(|e| fail(&format!("EL reader: {e}")));
    let recorded = record_with_retries(&reader, delegate, &peer_cache).await;
    reader.stop().await;
    sync.stop().await;
    let fixture = recorded.unwrap_or_else(|e| fail(&e));

    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| fail(&format!("{}: {e}", dir.display())));
    }
    std::fs::write(&out, fixture.to_json()).unwrap_or_else(|e| fail(&format!("{}: {e}", out.display())));
    let w = &fixture.world;
    println!("block {} ({})", fixture.block.block_number, hex0x(&fixture.block_hash));
    println!("measured {}", fixture.measured);
    println!(
        "world: {} accounts, {} slots, {} bytecodes",
        w.accounts.len(),
        w.storage.values().map(|s| s.len()).sum::<usize>(),
        w.code.len()
    );
    println!("wrote {}", out.display());
}

/// Record, retrying at a fresh head when a recording fails, within one
/// [`READY_BUDGET`] for finding a servable head.
async fn record_with_retries(reader: &ElReader, delegate: [u8; 20], peer_cache: &Path) -> Result<EvmFixture, String> {
    let deadline = tokio::time::Instant::now() + READY_BUDGET;
    let mut last_error = String::new();
    for attempt in 1..=ATTEMPTS {
        let head = ready_head(reader, deadline, peer_cache).await?;
        match record(head, delegate).await {
            Ok(fixture) => return Ok(fixture),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "recording failed; retrying at a fresh head");
                last_error = e;
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        }
    }
    Err(format!("no recording succeeded in {ATTEMPTS} attempts; the last failed with: {last_error}"))
}

/// The verified head and an oracle over it, once the reader can serve one:
/// discovery has found snap peers and one of them serves the head's block.
async fn ready_head(reader: &ElReader, deadline: tokio::time::Instant, peer_cache: &Path) -> Result<Head, String> {
    let mut reported = tokio::time::Instant::now();
    let mut last_error = String::from("no snap peer yet");
    loop {
        let snap_peers = reader.snap_peer_count().await;
        if snap_peers > 0 {
            match reader.head_evm_oracle(MAINNET).await {
                Ok(head) => return Ok(head),
                Err(e) => last_error = e,
            }
        }
        let now = tokio::time::Instant::now();
        if now > deadline {
            return Err(format!(
                "no servable verified head within {} min ({snap_peers} snap peer(s); the last attempt: {last_error}). \
                 The snap peers found so far are kept in {} for the next run; a warm Myotis peers.cache \
                 (--peer-cache) starts faster",
                READY_BUDGET.as_secs() / 60,
                peer_cache.display()
            ));
        }
        if now.duration_since(reported) >= PROGRESS_EVERY {
            tracing::info!(snap_peers, last_error = %last_error, "waiting for a servable verified head");
            reported = now;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// The recorder's own EL peer cache, kept between runs.
fn own_peer_cache() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/record_shield_fixture/peers.cache")
}

/// Seed the recorder's own peer cache, once, with a copy of the newest mainnet
/// EL peer cache an installed Myotis keeps. A copy: the recorder never writes
/// another program's file.
fn seed_peer_cache(own: &Path) {
    if own.exists() {
        tracing::info!(cache = %own.display(), "starting EL discovery from the recorder's peer cache");
        return;
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let candidates = [
        home.as_ref().map(|h| h.join(".myotis/peers.cache")),
        home.as_ref().map(|h| h.join(".myotis-railgun-poc/peers.cache")),
        Some(repo.join("app/peers.cache")),
    ];
    let newest = candidates
        .into_iter()
        .flatten()
        .filter_map(|path| std::fs::metadata(&path).and_then(|m| m.modified()).ok().map(|at| (at, path)))
        .max();
    let Some((_, source)) = newest else {
        tracing::info!("no Myotis peer cache found; discovering EL peers from scratch (slow on mainnet)");
        return;
    };
    let copied = own.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::copy(&source, own));
    match copied {
        Ok(_) => tracing::info!(from = %source.display(), "starting EL discovery from a copy of this Myotis peer cache"),
        Err(e) => tracing::warn!(from = %source.display(), error = %e, "could not copy the peer cache; discovering from scratch"),
    }
}

type Head = ([u8; 32], myotis_evm::BlockContext, std::sync::Arc<dyn myotis_evm::SnapStateOracle>);

/// One recording at `head`, with fresh keys.
async fn record((block_hash, block, oracle): Head, delegate: [u8; 20]) -> Result<EvmFixture, String> {
    tracing::info!(block = block.block_number, "recording the shield");
    let ephemeral_key = fresh_key()?;
    let sender = railgun::address_of(&fresh_key()?);
    let note = random_bytes()?;
    let field = |label: &[u8]| keccak256(&[&note[..], label].concat());
    let mut npk = field(b"npk");
    npk[0] &= 0x0f; // below the SNARK scalar field (0x3064…)
    let params = ShieldParams {
        chain_id: MAINNET,
        delegate,
        wrapped_base: railgun::MAINNET_WETH,
        value: SHIELD_WEI,
        require_success: true,
        authorization_nonce: 0,
        execute_nonce: U256::ZERO,
        npk,
        encrypted_bundle: [field(b"bundle0"), field(b"bundle1"), field(b"bundle2")],
        shield_key: field(b"shieldKey"),
    };
    let meta = serde_json::json!({
        "description": "RAILGUN shield ETH through a fresh EIP-7702 account (RelayAdapt7702), #509",
        "recordedBy": "rust/myotis-net/examples/record_shield_fixture.rs",
        "engine": concat!("myotis-net ", env!("CARGO_PKG_VERSION")),
        "network": "mainnet",
        "verification": "every account and slot passed the engine's snap-proof checks against the verified head's state root",
        "synthetic": "the sender and the ephemeral account are throwaway keys drawn for this recording; the sender's funds are the stateOverride",
    });
    tokio::task::spawn_blocking(move || {
        railgun::record_shield(
            oracle,
            block,
            block_hash,
            sender,
            &ephemeral_key,
            &params,
            railgun::MAINNET_RAILGUN_PROXY,
            meta,
        )
    })
    .await
    .map_err(|e| format!("the recording thread failed: {e}"))?
}

fn fresh_key() -> Result<NodeKey, String> {
    for _ in 0..8 {
        if let Ok(key) = NodeKey::from_secret_bytes(&random_bytes()?) {
            return Ok(key);
        }
    }
    Err("no valid key from OS entropy".to_string())
}

fn random_bytes() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("OS entropy: {e}"))?;
    Ok(bytes)
}

fn fail(message: &str) -> ! {
    tracing::error!("{message}");
    eprintln!("record_shield_fixture: {message}");
    std::process::exit(1)
}
