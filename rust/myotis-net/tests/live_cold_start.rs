//! The two cold-start regressions issue #422 asked us to keep.
//!
//! Both are live-network tests, ignored by default. `SyncHandle::start` is
//! already a cold start — the `ChainConfig` constructors set `snapshot_path:
//! None`, so there is no sync snapshot and no CL peer cache — which is exactly
//! the profile a fresh install has and the one a warm dispatched smoke run
//! hides. Each test then removes ONE crutch and asserts the wallet still
//! reaches SYNCED:
//!
//! * `cold_start_with_every_pinned_peer_unreachable_syncs_through_discovery` —
//!   the pins are still CONFIGURED but every address is a black hole, which is
//!   the shape #422 reported: stale pins plus roost down. Keeping the peer ids
//!   matters and is why this does not simply clear the list — a pinned peer is
//!   exempt from eviction (`PeerPool::evict` returns early for `static_ids`),
//!   so a dead pin stays in the pool for the life of the process, keeps being
//!   handed to every catch-up fan-out, and keeps steering targeted discovery
//!   lookups at a server that will never answer. Discovery has to win anyway.
//!
//! * `cold_start_from_an_old_anchor_walks_periods_to_head` — the trust anchor
//!   is several periods behind, so bootstrap is not enough and catch-up must
//!   actually walk. A release-fresh anchor makes the walk 0–2 periods and
//!   proves almost nothing, which is why this test never uses the embedded one.
//!
//! ```bash
//! # dead pins (default network: gnosis — where #422 bit hardest)
//! cargo test -p myotis-net --test live_cold_start -- --ignored --nocapture \
//!     cold_start_with_every_pinned_peer_unreachable
//!
//! # Old anchor: by default this network's entry in
//! # rust/testdata/anchors/oldest-servable.properties, the oldest checkpoint
//! # the serving nodes behind roost still bootstrap, far past every network's
//! # weak-subjectivity bound (gnosis 3 periods, mainnet/sepolia 13). The test
//! # asserts the anchor is further behind than the bound, because a shallower
//! # one walks a period or two and would have survived the bug this guards.
//! # Measured 2026-09-11: gnosis's entry, 70 periods behind, walked to head in
//! # 170 s.
//! NET=gnosis cargo test -p myotis-net --test live_cold_start -- --ignored --nocapture \
//!     cold_start_from_an_old_anchor
//!
//! # Override the anchor, both variables or neither:
//! NET=gnosis MYOTIS_TEST_ANCHOR_ROOT=<64 hex> MYOTIS_TEST_ANCHOR_SLOT=<slot> \
//! cargo test -p myotis-net --test live_cold_start -- --ignored --nocapture \
//!     cold_start_from_an_old_anchor
//! ```
//!
//! If the old-anchor run never bootstraps, first suspect that the anchor file's
//! entry has aged out of what roost still serves (bootstrap retention is a
//! moving horizon): re-probe on zbox and update the file before hunting for a
//! regression.
//!
//! NOTE both tests are peer-quota-bound, not CPU-bound: light-client servers
//! serve roughly one update per 10 s each, so a deep walk takes minutes. The
//! budgets below are generous for that reason, and a failure means "no peer
//! would serve us in N minutes", which is the condition #422 reported.

use std::sync::atomic::Ordering;
use std::time::Duration;

use myotis_net::{ChainConfig, SyncHandle, SyncState};

/// Network under test. Gnosis when unset: its light-client servers are almost
/// all Lighthouse, which is the population that stopped answering in #422.
/// An unrecognised value REFUSES rather than falling back — a cold-start run
/// against a network the operator did not ask for is a green result that means
/// something else (CLAUDE.md: a parameter that can change the answer must be
/// applied or refused, never accepted and silently ignored).
fn config_for_env() -> ChainConfig {
    match net_from_env().as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "sepolia" => ChainConfig::sepolia(),
        "gnosis" => ChainConfig::gnosis(),
        other => panic!("unknown NET {other:?} (want mainnet, sepolia or gnosis)"),
    }
}

/// `NET`, defaulting to gnosis. [`config_for_env`] refuses an unknown value.
fn net_from_env() -> String {
    std::env::var("NET").unwrap_or_else(|_| "gnosis".into())
}

/// The committed test-anchor file, as it is named in failure messages.
const ANCHOR_FILE: &str = "rust/testdata/anchors/oldest-servable.properties";

/// `<net>.root` and `<net>.slot` from [`ANCHOR_FILE`], the oldest checkpoint
/// per network the serving nodes behind roost still bootstrap. Panics when the
/// file or the entry is missing: the old-anchor test must never pass having
/// walked nothing.
fn recorded_test_anchor(net: &str) -> (String, String) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/anchors/oldest-servable.properties");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {ANCHOR_FILE} ({}): {e}", path.display()));
    let value = |key: &str| {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            // Last duplicate wins, as in java.util.Properties, which is what
            // refreshCheckpoint -PanchorFile reads the same file with.
            .filter(|(k, _)| k.trim() == key)
            .last()
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "{ANCHOR_FILE} has no {key}: add this network's entry, or set \
                     MYOTIS_TEST_ANCHOR_ROOT + MYOTIS_TEST_ANCHOR_SLOT"
                )
            })
    };
    (value(&format!("{net}.root")), value(&format!("{net}.slot")))
}

/// How long the dead-pins cold start may take. Named, with the prose
/// derived from it, so the budget and the message reporting it cannot drift
/// apart — the bug this PR fixes in `examples/live_sync.rs`.
const NO_PINS_BUDGET: Duration = Duration::from_secs(900);

/// How long the deep catch-up may take. Peer-quota-bound: a serving peer
/// answers roughly one update per 10 s, so a 70-period walk is minutes.
const OLD_ANCHOR_BUDGET: Duration = Duration::from_secs(1800);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,myotis_net=debug".into()),
        )
        .try_init();
}

/// Drive the handle to SYNCED or the deadline.
async fn run_to_synced(
    handle: &SyncHandle,
    label: &str,
    budget: Duration,
) -> Option<myotis_net::SyncStatus> {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = handle.status();
        eprintln!(
            "[{label}] state={} period={} start_period={} finalized_slot={} peers={} served/min={}",
            s.state, s.period, s.sync_start_period, s.finalized_slot, s.peer_count,
            s.served_peers_last_min
        );
        if s.state == SyncState::Synced {
            return Some(s);
        }
    }
    None
}

/// The CL source-selection overrides are applied in the `ChainConfig`
/// constructors, so a stray one silently changes what a test dials — setting
/// `MYOTIS_CL_STATIC_PEERS` to a known-good server is exactly how #422's
/// reporter built their *control*, which is the opposite of what these
/// regressions measure.
fn assert_no_cl_env_overrides() {
    for var in ["MYOTIS_CL_STATIC_PEERS", "MYOTIS_CL_DISABLE_DISCV5"] {
        assert!(
            std::env::var_os(var).is_none(),
            "{var} is set — it changes which peers this test dials, so the result \
             would not mean what the test claims. Unset it."
        );
    }
}

/// RFC 5737 TEST-NET-3, reserved for documentation: nothing routes there, so a
/// dial fails the way a decommissioned or firewalled server's does.
const BLACKHOLE_PREFIX: &str = "203.0.113.";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: cold start with every pin DEAD, takes minutes"]
async fn cold_start_with_every_pinned_peer_unreachable_syncs_through_discovery() {
    init_tracing();
    assert_no_cl_env_overrides();
    let mut config = config_for_env();

    // Keep every pinned peer ID, point it at a black hole. NOT a cleared list:
    // pinned peers are exempt from eviction, so these stay in the pool, keep
    // taking fan-out slots in every catch-up round, and keep aiming targeted
    // discovery lookups at servers that will never answer. That is the #422
    // shape, and it is strictly harder than having no pins at all.
    let pinned = config.static_peers.len();
    assert!(pinned > 0, "this network pins no CL peers, so there is nothing to kill");
    config.static_peers = config
        .static_peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let id = p.rsplit("/p2p/").next().expect("pinned multiaddr carries a peer id");
            // A distinct address each, so none can collide with a live host.
            format!("/ip4/{BLACKHOLE_PREFIX}{}/tcp/9000/p2p/{id}", i % 254 + 1)
        })
        .collect();
    assert!(
        config.static_peers.iter().all(|p| p.contains(BLACKHOLE_PREFIX)),
        "every pin must be blackholed, or this measures a live server"
    );
    // Discovery keeps its bootnodes — removing those would test nothing but
    // "a node with no way in cannot get in".
    assert!(!config.bootstrap_enrs.is_empty(), "discovery needs its bootnodes");

    let handle = SyncHandle::start(config).expect("sync start");
    let synced = run_to_synced(&handle, "dead-pins", NO_PINS_BUDGET).await;
    handle.stop().await;

    assert!(
        synced.is_some(),
        "cold start with all {pinned} pinned peers unreachable did not reach SYNCED in {} min — \
         discovery could not find a light-client server while the dead pins held their \
         un-evictable pool slots, which is the #422 condition",
        NO_PINS_BUDGET.as_secs() / 60
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network test: cold start from an OLD anchor, takes many minutes"]
async fn cold_start_from_an_old_anchor_walks_periods_to_head() {
    init_tracing();
    assert_no_cl_env_overrides();
    let mut config = config_for_env();

    // The anchor comes from MYOTIS_TEST_ANCHOR_ROOT + MYOTIS_TEST_ANCHOR_SLOT
    // when both are set, else from this network's entry in the committed
    // test-anchor file. Empty values count as unset (the workflow passes blank
    // inputs through). A missing or half-supplied anchor FAILS rather than
    // returning: this test only runs when someone asked for it by name (it is
    // #[ignore]d), and a green "1 passed" for a run that did nothing is how a
    // regression quietly stops being one.
    let env_non_empty = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let (root_hex, slot, source) = match (
        env_non_empty("MYOTIS_TEST_ANCHOR_ROOT"),
        env_non_empty("MYOTIS_TEST_ANCHOR_SLOT"),
    ) {
        (Some(root), Some(slot)) => (root, slot, "MYOTIS_TEST_ANCHOR_ROOT/SLOT".to_string()),
        (None, None) => {
            let (root, slot) = recorded_test_anchor(&net_from_env());
            (root, slot, ANCHOR_FILE.to_string())
        }
        _ => panic!(
            "MYOTIS_TEST_ANCHOR_ROOT and MYOTIS_TEST_ANCHOR_SLOT override the anchor together: \
             set both, or neither to use {ANCHOR_FILE}"
        ),
    };
    let slot: u64 = slot.trim().parse().expect("anchor slot must be a number");
    let root_hex = root_hex.trim().trim_start_matches("0x");
    assert_eq!(root_hex.len(), 64, "anchor root must be 32 bytes of hex");
    let mut root = [0u8; 32];
    for (i, b) in root.iter_mut().enumerate() {
        *b = u8::from_str_radix(&root_hex[i * 2..i * 2 + 2], 16).expect("anchor root hex");
    }

    let anchor_period = slot / config.slots_per_period();
    let wall_period = config.wall_clock_period();
    let bound = config.effective_ws_bound_periods();
    assert!(
        wall_period > anchor_period && wall_period - anchor_period > bound,
        "anchor period {anchor_period} is only {} behind the wall clock ({wall_period}), \
         which is within this network's weak-subjectivity bound of {bound} periods — a walk \
         that short would have survived the #422 bug, so the test would prove nothing",
        wall_period.saturating_sub(anchor_period)
    );
    let behind = wall_period - anchor_period;
    eprintln!("[old-anchor] anchor period {anchor_period} from {source}, wall {wall_period} \
               ({behind} behind, ws bound {bound})");

    config.checkpoint_root = root;
    config.checkpoint_slot = slot;
    // An anchor this old is past the weak-subjectivity bound, so the engine
    // parks in STALE_ANCHOR until a host consents. Consent here: the point of
    // the test is the catch-up walk behind that gate, and the gate itself has
    // its own coverage.
    config.ws_policy.accept_stale_anchor.store(true, Ordering::Relaxed);

    let handle = SyncHandle::start(config).expect("sync start");
    let synced = run_to_synced(&handle, "old-anchor", OLD_ANCHOR_BUDGET).await;
    handle.stop().await;

    let synced = synced.unwrap_or_else(|| {
        panic!(
            "cold start {behind} periods behind did not reach SYNCED in {} min — \
             the bootstrap may have landed but catch-up made no progress, which is \
             exactly the #422 stall. If it never bootstrapped, first suspect that the \
             anchor ({source}) has aged out of what roost still serves: re-probe on zbox \
             and update {ANCHOR_FILE} before hunting for a regression",
            OLD_ANCHOR_BUDGET.as_secs() / 60
        )
    });
    // `sync_start_period` is the period this run's catch-up started from (-1
    // until bootstrap), so this is exact rather than sampled: the walk has to
    // have covered the whole gap, not merely moved.
    assert!(synced.sync_start_period >= 0, "a synced store must have bootstrapped");
    assert_eq!(
        synced.sync_start_period as u64, anchor_period,
        "catch-up started from a different period than the anchor we pinned"
    );
    assert!(
        synced.period > synced.sync_start_period as u64,
        "reached SYNCED without advancing a period, so the catch-up walk went untested"
    );
}
